// Package hub connects Keelwatch instances: agents on remote hosts push
// their scan results to one hub dashboard, and the hub replies with the
// suppressions and alert acknowledgements made there.
package hub

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/keelwatch/keelwatch/internal/model"
	"github.com/keelwatch/keelwatch/internal/scan"
	"github.com/keelwatch/keelwatch/internal/store"
)

// MaxReport bounds an agent report body (snapshot with CVE lists).
const MaxReport = 32 << 20

const (
	maxHistory = 240
	maxAlerts  = 300
)

// Report is what an agent POSTs to /api/agent/report after each scan.
type Report struct {
	Version     string               `json:"version"`
	IntervalSec int                  `json:"intervalSec"`
	CVEEnabled  bool                 `json:"cveEnabled"`
	Snapshot    *model.Snapshot      `json:"snapshot"`
	History     []model.HistoryPoint `json:"history"`
	Alerts      []model.Alert        `json:"alerts"`
	Suppressed  map[string]string    `json:"suppressed"`
}

// Reply carries the hub's decisions back. The hub is authoritative for both.
type Reply struct {
	Suppressed map[string]string `json:"suppressed"`
	Acked      []string          `json:"acked"`
}

var nameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)

// ParseAgents reads "name=token" pairs separated by commas or newlines.
// Names become directory names on the hub, so they are strictly validated.
func ParseAgents(s string) (map[string]string, error) {
	out := map[string]string{}
	seen := map[string]bool{}
	for _, part := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' }) {
		if part = strings.TrimSpace(part); part == "" || strings.HasPrefix(part, "#") {
			continue
		}
		name, tok, ok := strings.Cut(part, "=")
		name, tok = strings.TrimSpace(name), strings.TrimSpace(tok)
		switch {
		case !ok || !nameRe.MatchString(name):
			return nil, fmt.Errorf("agent entry %q: want name=token, name of letters, digits, . _ -", name)
		case len(tok) < 24:
			return nil, fmt.Errorf("agent %q: token must be at least 24 characters (openssl rand -hex 24)", name)
		case out[name] != "":
			return nil, fmt.Errorf("agent %q listed twice", name)
		case seen[tok]:
			return nil, fmt.Errorf("agent %q reuses another agent's token", name)
		}
		out[name], seen[tok] = tok, true
	}
	return out, nil
}

// Rescore re-applies suppressions, drops findings for acknowledged alerts
// and recomputes scores and debt on the stored snapshot.
func Rescore(st *store.State) {
	if st.Snapshot == nil {
		return
	}
	acked := map[string]bool{}
	for _, a := range st.Alerts {
		if a.Acked {
			acked[model.MakeID("alert", a.ID, "")] = true
		}
	}
	fs := make([]model.Finding, 0, len(st.Snapshot.Findings))
	for _, f := range st.Snapshot.Findings {
		if f.Rule == "runtime-alert" && acked[f.ID] {
			continue
		}
		_, f.Suppressed = st.Suppressed[f.ID]
		fs = append(fs, f)
	}
	st.Snapshot.Findings = fs
	scan.Score(st.Snapshot)
}

// Client pushes this host's state to a hub.
type Client struct {
	URL      string // hub base URL, e.g. https://apps.example.com/keelwatch
	Token    string
	Version  string
	Interval time.Duration
	CVE      func() bool
	HTTP     *http.Client
}

// Push sends the latest snapshot and applies the hub's reply to st.
func (c *Client) Push(ctx context.Context, st *store.Store) error {
	var body []byte
	var err error
	st.View(func(s *store.State) {
		if s.Snapshot == nil {
			return
		}
		rep := Report{Version: c.Version, IntervalSec: int(c.Interval.Seconds()), Snapshot: s.Snapshot, Suppressed: s.Suppressed}
		if c.CVE != nil {
			rep.CVEEnabled = c.CVE()
		}
		rep.History = s.History
		if len(rep.History) > maxHistory {
			rep.History = rep.History[len(rep.History)-maxHistory:]
		}
		alerts := append([]model.Alert(nil), s.Alerts...)
		sort.Slice(alerts, func(i, j int) bool { return alerts[i].Time.After(alerts[j].Time) })
		if len(alerts) > maxAlerts {
			alerts = alerts[:maxAlerts]
		}
		rep.Alerts = alerts
		body, err = json.Marshal(rep) // inside View: the snapshot must not escape the lock
	})
	if err != nil || body == nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.URL, "/")+"/api/agent/report", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.Token)
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 60 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("hub returned %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	var r Reply
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&r); err != nil {
		return fmt.Errorf("hub reply: %w", err)
	}
	return st.Update(func(s *store.State) { Apply(s, r) })
}

// Apply adopts the hub's suppressions and acknowledgements on the agent.
func Apply(s *store.State, r Reply) {
	if r.Suppressed != nil { // nil = old hub that doesn't send them; keep local state
		s.Suppressed = r.Suppressed
	}
	acked := map[string]bool{}
	for _, id := range r.Acked {
		acked[id] = true
	}
	for i := range s.Alerts {
		if acked[s.Alerts[i].ID] {
			s.Alerts[i].Acked = true
		}
	}
	Rescore(s)
}

// Receive stores an agent report on the hub and builds the reply.
// The first report seeds the hub with the agent's existing suppressions.
func Receive(s *store.State, rep Report, now time.Time) Reply {
	if s.Snapshot == nil && len(s.Suppressed) == 0 {
		for k, v := range rep.Suppressed {
			s.Suppressed[k] = v
		}
	}
	acked := map[string]bool{}
	for _, a := range s.Alerts {
		if a.Acked {
			acked[a.ID] = true
		}
	}
	s.Alerts = rep.Alerts
	for i := range s.Alerts {
		if acked[s.Alerts[i].ID] {
			s.Alerts[i].Acked = true
		}
	}
	s.ImageScans = map[string]*model.ImageScan{} // CVE details for the image modal
	for _, im := range rep.Snapshot.Images {
		if im.Scan != nil {
			s.ImageScans[im.ID] = im.Scan
		}
	}
	s.Snapshot = rep.Snapshot
	s.History = rep.History
	s.Agent = &store.AgentInfo{ReceivedAt: now, IntervalSec: rep.IntervalSec, Version: rep.Version, CVEEnabled: rep.CVEEnabled}
	Rescore(s)
	out := Reply{Suppressed: map[string]string{}, Acked: []string{}}
	for k, v := range s.Suppressed {
		out.Suppressed[k] = v
	}
	for _, a := range s.Alerts {
		if a.Acked {
			out.Acked = append(out.Acked, a.ID)
		}
	}
	return out
}
