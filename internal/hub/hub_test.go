package hub

import (
	"strings"
	"testing"
	"time"

	"github.com/keelwatch/keelwatch/internal/model"
	"github.com/keelwatch/keelwatch/internal/store"
)

func TestParseAgents(t *testing.T) {
	tok, tok2 := strings.Repeat("a", 24), strings.Repeat("b", 24)
	got, err := ParseAgents("pi-b=" + tok + ",\n# comment\n vps.1 = " + tok2 + "\n")
	if err != nil || got["pi-b"] != tok || got["vps.1"] != tok2 || len(got) != 2 {
		t.Fatalf("got %v %v", got, err)
	}
	for _, bad := range []string{"../etc=" + tok, "a/b=" + tok, "pi=short", "pi", "pi=" + tok + ",pi=" + tok2, "a=" + tok + ",b=" + tok, ".hidden=" + tok} {
		if _, err := ParseAgents(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if m, err := ParseAgents(""); err != nil || len(m) != 0 {
		t.Errorf("empty: %v %v", m, err)
	}
}

// An alert acked on the hub survives the next report and is acked on the agent.
func TestAckSync(t *testing.T) {
	alert := model.Alert{ID: "a1", Severity: model.SevHigh, Title: "exec"}
	snap := func() *model.Snapshot {
		return &model.Snapshot{ScannedAt: time.Now(), Findings: []model.Finding{
			{ID: model.MakeID("alert", "a1", ""), Rule: "runtime-alert", Severity: model.SevHigh, FirstSeen: time.Now()},
		}}
	}
	hubSt := &store.State{Suppressed: map[string]string{}}
	agentSt := &store.State{Suppressed: map[string]string{"x": "agent note"}, Alerts: []model.Alert{alert}, Snapshot: snap()}

	r := Receive(hubSt, Report{Snapshot: snap(), Alerts: []model.Alert{alert}, Suppressed: agentSt.Suppressed}, time.Now())
	if hubSt.Suppressed["x"] != "agent note" || len(r.Acked) != 0 {
		t.Fatalf("first report should seed suppressions: %+v %+v", hubSt.Suppressed, r)
	}
	hubSt.Alerts[0].Acked = true // admin acks on the hub
	r = Receive(hubSt, Report{Snapshot: snap(), Alerts: []model.Alert{alert}}, time.Now())
	if len(r.Acked) != 1 || len(hubSt.Snapshot.Findings) != 0 {
		t.Fatalf("ack lost or alert finding kept: %+v findings=%d", r, len(hubSt.Snapshot.Findings))
	}
	Apply(agentSt, r)
	if !agentSt.Alerts[0].Acked || len(agentSt.Snapshot.Findings) != 0 || agentSt.Suppressed["x"] != "agent note" {
		t.Fatalf("agent did not apply reply: %+v", agentSt)
	}
}
