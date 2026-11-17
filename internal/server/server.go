// Package server exposes the JSON API and the embedded dashboard.
package server

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/keelwatch/keelwatch/internal/engine"
	"github.com/keelwatch/keelwatch/internal/hub"
	"github.com/keelwatch/keelwatch/internal/model"
	"github.com/keelwatch/keelwatch/internal/notify"
	"github.com/keelwatch/keelwatch/internal/scan"
	"github.com/keelwatch/keelwatch/internal/store"
)

//go:embed web
var webFS embed.FS

type Options struct {
	Version      string
	Password     string
	AuthDisabled bool
	FalcoToken   string
	Settings     map[string]any // read-only settings shown in the UI
	Demo         bool
	BasePath     string            // e.g. "/keelwatch" when served under a sub-path
	Agents       map[string]string // remote host name -> agent token (hub mode)
	DataDir      string            // remote host state lives in DataDir/hosts/<name>
}

type Server struct {
	opt   Options
	eng   *engine.Engine
	st    *store.Store
	notif *notify.Notifier
	auth  *auth
	log   *slog.Logger
	hosts map[string]*store.Store // remote hosts reporting through agents
}

func New(opt Options, eng *engine.Engine, st *store.Store, n *notify.Notifier, log *slog.Logger) (*Server, error) {
	a, generated, err := initAuth(st, opt.Password, opt.AuthDisabled)
	if err != nil {
		return nil, err
	}
	if generated != "" {
		log.Warn("no KEELWATCH_PASSWORD set; generated an admin password (shown once, set KEELWATCH_PASSWORD to choose your own)", "password", generated)
	}
	if opt.AuthDisabled {
		log.Warn("authentication is DISABLED (KEELWATCH_AUTH=off). Only do this behind an authenticating proxy such as Cloudflare Access.")
	}
	hosts := map[string]*store.Store{}
	for name := range opt.Agents {
		if filepath.Base(name) != name || name == "." || name == ".." {
			return nil, errors.New("invalid agent name " + name)
		}
		hs, err := store.Open(filepath.Join(opt.DataDir, "hosts", name))
		if err != nil {
			return nil, err
		}
		hosts[name] = hs
	}
	return &Server{opt: opt, eng: eng, st: st, notif: n, auth: a, log: log, hosts: hosts}, nil
}

// storeFor picks the host named by ?host= (empty = this host). Writes a 404 and returns nil if unknown.
func (s *Server) storeFor(w http.ResponseWriter, r *http.Request) *store.Store {
	h := r.URL.Query().Get("host")
	if h == "" {
		return s.st
	}
	if st := s.hosts[h]; st != nil {
		return st
	}
	writeErr(w, http.StatusNotFound, "unknown host")
	return nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	sub, _ := fs.Sub(webFS, "web")
	static := http.FileServer(http.FS(sub))
	mux.Handle("GET /assets/", static)
	mux.Handle("GET /favicon.svg", static)
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		b, _ := fs.ReadFile(sub, "index.html")
		if base := s.base(); base != "" {
			b = []byte(strings.Replace(string(b), "<head>", "<head>\n<base href=\""+base+"/\">", 1))
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(b)
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") })

	mux.HandleFunc("GET /api/session", s.session)
	mux.HandleFunc("POST /api/login", s.login)
	mux.HandleFunc("POST /api/logout", s.logout)
	mux.HandleFunc("POST /api/falco", s.falco)
	mux.HandleFunc("POST /api/agent/report", s.agentReport)

	mux.Handle("GET /api/state", s.protect(s.state))
	mux.Handle("GET /api/hosts", s.protect(s.hostList))
	mux.Handle("DELETE /api/hosts/{name}", s.protect(s.removeHost))
	mux.Handle("POST /api/hosts/{name}/restore", s.protect(s.restoreHost))
	mux.Handle("GET /api/alerts", s.protect(s.alerts))
	mux.Handle("GET /api/images/{id}/cves", s.protect(s.imageCVEs))
	mux.Handle("GET /api/settings", s.protect(s.settings))
	mux.Handle("GET /api/export", s.protect(s.export))
	mux.Handle("POST /api/scan", s.protect(s.triggerScan))
	mux.Handle("POST /api/findings/{id}/suppress", s.protect(s.suppress))
	mux.Handle("DELETE /api/findings/{id}/suppress", s.protect(s.unsuppress))
	mux.Handle("POST /api/alerts/{id}/ack", s.protect(s.ack))
	mux.Handle("POST /api/alerts/ack-all", s.protect(s.ackAll))
	mux.Handle("POST /api/notify/test", s.protect(s.testNotify))
	h := securityHeaders(mux)
	base := s.base()
	if base == "" {
		return h
	}
	// Served under a sub-path. Works whether the reverse proxy keeps the
	// prefix (/keelwatch/api/...) or strips it (/api/...).
	outer := http.NewServeMux()
	outer.Handle(base+"/", http.StripPrefix(base, h))
	outer.HandleFunc(base, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, base+"/", http.StatusMovedPermanently)
	})
	outer.Handle("/", h)
	return outer
}

func (s *Server) base() string { return strings.TrimRight(s.opt.BasePath, "/") }

func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("Referrer-Policy", "no-referrer")
		hd.Set("X-Frame-Options", "DENY")
		h.ServeHTTP(w, r)
	})
}

// protect requires a session and, for state-changing calls, the custom
// X-Keelwatch header (a CSRF guard on top of SameSite=Strict cookies).
func (s *Server) protect(fn http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.auth.valid(r) {
			writeErr(w, http.StatusUnauthorized, "login required")
			return
		}
		if r.Method != http.MethodGet && r.Header.Get("X-Keelwatch") != "1" {
			writeErr(w, http.StatusForbidden, "missing X-Keelwatch header")
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		fn(w, r)
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func (s *Server) session(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"authenticated": s.auth.valid(r), "authRequired": !s.auth.disabled, "version": s.opt.Version, "demo": s.opt.Demo})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !s.auth.allow(ip, false) {
		writeErr(w, http.StatusTooManyRequests, "too many attempts, try again in 15 minutes")
		return
	}
	var body struct{ Password string }
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}
	if !s.auth.check(body.Password) {
		s.auth.allow(ip, true)
		s.log.Warn("failed login", "ip", ip)
		time.Sleep(400 * time.Millisecond)
		writeErr(w, http.StatusUnauthorized, "wrong password")
		return
	}
	s.auth.issue(w, r)
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) state(w http.ResponseWriter, r *http.Request) {
	var out struct {
		Snapshot     *model.Snapshot      `json:"snapshot"`
		History      []model.HistoryPoint `json:"history"`
		OpenAlerts   int                  `json:"openAlerts"`
		RecentAlerts []model.Alert        `json:"recentAlerts"`
		Scanning     bool                 `json:"scanning"`
		CVEEnabled   bool                 `json:"cveEnabled"`
		Version      string               `json:"version"`
		Demo         bool                 `json:"demo"`
		Agent        *store.AgentInfo     `json:"agent,omitempty"` // set for a remote host
	}
	hs := s.storeFor(w, r)
	if hs == nil {
		return
	}
	hs.View(func(st *store.State) {
		if st.Agent != nil {
			cp := *st.Agent
			out.Agent = &cp
		}
		if st.Snapshot != nil {
			cp := *st.Snapshot
			cp.Images = make([]model.ImageView, len(st.Snapshot.Images))
			for i, im := range st.Snapshot.Images {
				if im.Scan != nil {
					sc := *im.Scan
					sc.CVEs = nil // fetched per image on demand
					im.Scan = &sc
				}
				cp.Images[i] = im
			}
			out.Snapshot = &cp
		}
		h := st.History
		if len(h) > 240 {
			h = h[len(h)-240:]
		}
		out.History = append([]model.HistoryPoint(nil), h...)
		alerts := append([]model.Alert(nil), st.Alerts...)
		sort.Slice(alerts, func(i, j int) bool { return alerts[i].Time.After(alerts[j].Time) })
		for _, a := range alerts {
			if !a.Acked {
				out.OpenAlerts++
			}
		}
		if len(alerts) > 5 {
			alerts = alerts[:5]
		}
		out.RecentAlerts = append([]model.Alert{}, alerts...)
	})
	if out.Agent != nil {
		out.CVEEnabled = out.Agent.CVEEnabled
	} else if hs == s.st {
		out.Scanning = s.eng.Busy()
		out.CVEEnabled = s.eng.CVEEnabled()
	}
	out.Version = s.opt.Version
	out.Demo = s.opt.Demo
	writeJSON(w, out)
}

func (s *Server) alerts(w http.ResponseWriter, r *http.Request) {
	hs := s.storeFor(w, r)
	if hs == nil {
		return
	}
	var out []model.Alert
	hs.View(func(st *store.State) { out = append(out, st.Alerts...) })
	sort.Slice(out, func(i, j int) bool { return out[i].Time.After(out[j].Time) })
	if out == nil {
		out = []model.Alert{}
	}
	writeJSON(w, out)
}

func (s *Server) imageCVEs(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	hs := s.storeFor(w, r)
	if hs == nil {
		return
	}
	var res *model.ImageScan
	hs.View(func(st *store.State) {
		if sc, ok := st.ImageScans[id]; ok {
			cp := *sc
			cp.CVEs = append([]model.CVE(nil), sc.CVEs...)
			res = &cp
		}
	})
	if res == nil {
		writeErr(w, http.StatusNotFound, "no CVE scan for this image yet")
		return
	}
	writeJSON(w, res)
}

func (s *Server) settings(w http.ResponseWriter, r *http.Request) {
	type sup struct {
		ID, Note, Title, Target string
	}
	hs := s.storeFor(w, r)
	if hs == nil {
		return
	}
	settings := s.opt.Settings
	removedHosts := []string{}
	var sups []sup
	hs.View(func(st *store.State) {
		if hs == s.st {
			for n := range st.RemovedHosts {
				removedHosts = append(removedHosts, n)
			}
			sort.Strings(removedHosts)
		} else {
			settings = map[string]any{"Reported by": "Keelwatch agent", "Agent version": "—", "Last report": "never"}
			if a := st.Agent; a != nil {
				settings["Agent version"] = a.Version
				settings["Last report"] = a.ReceivedAt.Format(time.RFC3339)
				settings["Scan interval"] = (time.Duration(a.IntervalSec) * time.Second).String()
				settings["CVE scanner"] = map[bool]string{true: "on", false: "off"}[a.CVEEnabled]
			}
		}
		titles := map[string]model.Finding{}
		if st.Snapshot != nil {
			for _, f := range st.Snapshot.Findings {
				titles[f.ID] = f
			}
		}
		for id, note := range st.Suppressed {
			f := titles[id]
			sups = append(sups, sup{ID: id, Note: note, Title: f.Title, Target: f.Target})
		}
	})
	sort.Slice(sups, func(i, j int) bool { return sups[i].Title < sups[j].Title })
	writeJSON(w, map[string]any{
		"settings":     settings,
		"channels":     append([]string{}, s.notif.Channels()...),
		"suppressed":   sups,
		"falcoReady":   s.opt.FalcoToken != "",
		"cveEnabled":   s.eng.CVEEnabled(),
		"removedHosts": removedHosts,
	})
}

func (s *Server) export(w http.ResponseWriter, r *http.Request) {
	hs := s.storeFor(w, r)
	if hs == nil {
		return
	}
	var snap *model.Snapshot
	hs.View(func(st *store.State) { snap = st.Snapshot })
	w.Header().Set("Content-Disposition", `attachment; filename="keelwatch-report-`+time.Now().UTC().Format("20060102-1504")+`.json"`)
	writeJSON(w, snap)
}

func (s *Server) triggerScan(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("host") != "" {
		writeErr(w, http.StatusConflict, "remote hosts scan on their agent's own schedule")
		return
	}
	if !s.eng.Busy() {
		go s.eng.ScanNow(context.Background())
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) suppress(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var body struct{ Note string }
	_ = json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body)
	if body.Note == "" {
		body.Note = "Accepted risk"
	}
	hs := s.storeFor(w, r)
	if hs == nil {
		return
	}
	_ = hs.Update(func(st *store.State) {
		st.Suppressed[id] = truncate(body.Note, 200)
		hub.Rescore(st)
	})
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) unsuppress(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	hs := s.storeFor(w, r)
	if hs == nil {
		return
	}
	_ = hs.Update(func(st *store.State) {
		delete(st.Suppressed, id)
		hub.Rescore(st)
	})
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) ack(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	hs := s.storeFor(w, r)
	if hs == nil {
		return
	}
	_ = hs.Update(func(st *store.State) {
		for i := range st.Alerts {
			if st.Alerts[i].ID == id {
				st.Alerts[i].Acked = true
			}
		}
		hub.Rescore(st)
	})
	if hs == s.st {
		s.eng.Trigger()
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) ackAll(w http.ResponseWriter, r *http.Request) {
	hs := s.storeFor(w, r)
	if hs == nil {
		return
	}
	_ = hs.Update(func(st *store.State) {
		for i := range st.Alerts {
			st.Alerts[i].Acked = true
		}
		hub.Rescore(st)
	})
	if hs == s.st {
		s.eng.Trigger()
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) testNotify(w http.ResponseWriter, r *http.Request) {
	if !s.notif.Enabled() {
		writeErr(w, http.StatusBadRequest, "no notification channel configured")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	err := s.notif.Send(ctx, notify.Message{Title: "Keelwatch test notification", Body: "If you can read this, notifications work.", Severity: "info"})
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

// falco receives Falcosidekick webhook events.
func (s *Server) falco(w http.ResponseWriter, r *http.Request) {
	if s.opt.FalcoToken == "" {
		writeErr(w, http.StatusNotFound, "Falco integration disabled (set KEELWATCH_FALCO_TOKEN)")
		return
	}
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if tok == "" {
		tok = r.URL.Query().Get("token")
	}
	if subtle.ConstantTimeCompare([]byte(tok), []byte(s.opt.FalcoToken)) != 1 {
		writeErr(w, http.StatusUnauthorized, "bad token")
		return
	}
	var ev scan.FalcoEvent
	if err := json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&ev); err != nil {
		writeErr(w, http.StatusBadRequest, "bad payload")
		return
	}
	s.eng.AddAlert(context.Background(), scan.FalcoAlert(ev))
	writeJSON(w, map[string]bool{"ok": true})
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// agentReport receives a remote host's scan from a Keelwatch agent.
// The token, not the payload, decides which host the report belongs to.
func (s *Server) agentReport(w http.ResponseWriter, r *http.Request) {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	name := ""
	for n, t := range s.opt.Agents {
		if subtle.ConstantTimeCompare([]byte(tok), []byte(t)) == 1 {
			name = n
		}
	}
	if tok == "" || name == "" {
		writeErr(w, http.StatusUnauthorized, "bad agent token")
		return
	}
	if s.removed(name) {
		writeErr(w, http.StatusGone, "host "+name+" was removed on the hub; restore it in Settings or stop this agent")
		return
	}
	var rep hub.Report
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, hub.MaxReport)).Decode(&rep); err != nil || rep.Snapshot == nil {
		writeErr(w, http.StatusBadRequest, "bad report")
		return
	}
	var reply hub.Reply
	if err := s.hosts[name].Update(func(st *store.State) { reply = hub.Receive(st, rep, time.Now().UTC()) }); err != nil {
		writeErr(w, http.StatusInternalServerError, "store: "+err.Error())
		return
	}
	s.log.Info("agent report", "host", name, "score", rep.Snapshot.Score, "findings", len(rep.Snapshot.Findings))
	writeJSON(w, reply)
}

type hostRow struct {
	ID         string                 `json:"id"` // "" = this host; else the agent name used in ?host=
	Name       string                 `json:"name"`
	Remote     bool                   `json:"remote"`
	Reported   bool                   `json:"reported"`
	Stale      bool                   `json:"stale"`
	ScannedAt  time.Time              `json:"scannedAt"`
	Score      int                    `json:"score"`
	Grade      string                 `json:"grade"`
	Containers int                    `json:"containers"`
	Counts     map[model.Severity]int `json:"counts"`
	Debt       model.Debt             `json:"debt"`
}

func hostSummary(id string, st *store.State, now time.Time) hostRow {
	h := hostRow{ID: id, Name: id, Remote: id != "", Counts: map[model.Severity]int{}}
	if st.Snapshot == nil {
		return h
	}
	snap := st.Snapshot
	h.Reported, h.ScannedAt, h.Score, h.Grade, h.Containers, h.Debt = true, snap.ScannedAt, snap.Score, snap.Grade, len(snap.Containers), snap.Debt
	if snap.Host.Name != "" && !h.Remote {
		h.Name = snap.Host.Name
	}
	for _, f := range snap.Findings {
		if !f.Suppressed {
			h.Counts[f.Severity]++
		}
	}
	if a := st.Agent; a != nil {
		every := time.Duration(a.IntervalSec) * time.Second
		h.Stale = now.Sub(a.ReceivedAt) > 2*every+10*time.Minute
	}
	return h
}

// hostList summarises every host for the fleet view and host picker.
func (s *Server) hostList(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	var out []hostRow
	s.st.View(func(st *store.State) { out = append(out, hostSummary("", st, now)) })
	if out[0].Name == "" {
		out[0].Name = "this host"
	}
	names := make([]string, 0, len(s.hosts))
	for n := range s.hosts {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if !s.removed(n) {
			s.hosts[n].View(func(st *store.State) { out = append(out, hostSummary(n, st, now)) })
		}
	}
	writeJSON(w, out)
}

func (s *Server) removed(name string) bool {
	var ok bool
	s.st.View(func(st *store.State) { _, ok = st.RemovedHosts[name] })
	return ok
}

// removeHost forgets a remote host's data and refuses its agent's reports until restored.
// The agent token stays in KEELWATCH_AGENT_TOKENS; delete it there to revoke it for good.
func (s *Server) removeHost(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	hs := s.hosts[name]
	if hs == nil {
		writeErr(w, http.StatusNotFound, "unknown host")
		return
	}
	if err := s.st.Update(func(st *store.State) { st.RemovedHosts[name] = time.Now().UTC() }); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := hs.Reset(); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.log.Info("remote host removed", "host", name)
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) restoreHost(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if s.hosts[name] == nil {
		writeErr(w, http.StatusNotFound, "unknown host")
		return
	}
	_ = s.st.Update(func(st *store.State) { delete(st.RemovedHosts, name) })
	writeJSON(w, map[string]bool{"ok": true})
}
