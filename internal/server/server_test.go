package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keelwatch/keelwatch/internal/demo"
	"github.com/keelwatch/keelwatch/internal/docker"
	"github.com/keelwatch/keelwatch/internal/engine"
	"github.com/keelwatch/keelwatch/internal/hub"
	"github.com/keelwatch/keelwatch/internal/notify"
	"github.com/keelwatch/keelwatch/internal/store"
)

// End-to-end: demo Docker API → engine scan → authenticated HTTP API.
func TestEndToEnd(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dir := t.TempDir()
	host, err := demo.Start(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	dc, _ := docker.New(host)
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	n := notify.New(notify.Config{})
	eng := engine.New(engine.Config{CheckUpdates: true}, dc, demo.Checker{}, demo.Scanner{}, st, n, log)
	if _, err := eng.ScanOnce(ctx); err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{Version: "test", Password: "correct horse", FalcoToken: "ftok"}, eng, st, n, log)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, Timeout: 10 * time.Second}

	if r, _ := c.Get(ts.URL + "/api/state"); r.StatusCode != 401 {
		t.Fatalf("state without login: %d", r.StatusCode)
	}
	if r, _ := c.Post(ts.URL+"/api/login", "application/json", strings.NewReader(`{"password":"nope"}`)); r.StatusCode != 401 {
		t.Fatalf("bad password accepted: %d", r.StatusCode)
	}
	r, _ := c.Post(ts.URL+"/api/login", "application/json", strings.NewReader(`{"password":"correct horse"}`))
	if r.StatusCode != 200 {
		t.Fatalf("login: %d", r.StatusCode)
	}
	r, err = c.Get(ts.URL + "/api/state")
	if err != nil || r.StatusCode != 200 {
		t.Fatalf("state: %v %d", err, r.StatusCode)
	}
	var state struct {
		Snapshot struct {
			Score    int
			Findings []struct{ ID, Rule, Category, Severity, Evidence string }
			Images   []struct{ Scan *struct{ CVEs []any } }
			Networks []struct {
				Name     string
				Internal bool
			}
			Containers []struct {
				Name, NetworkMode string
				Networks          []string
				DockerSocket      bool
			}
		}
	}
	_ = json.NewDecoder(r.Body).Decode(&state)
	// Connectivity map data.
	internal := map[string]bool{}
	for _, n := range state.Snapshot.Networks {
		internal[n.Name] = n.Internal
	}
	if !internal["expense_db"] || internal["proxy"] {
		t.Errorf("network list wrong: %+v", state.Snapshot.Networks)
	}
	for _, ct := range state.Snapshot.Containers {
		switch ct.Name {
		case "uptime-kuma":
			if !ct.DockerSocket || strings.Join(ct.Networks, ",") != "monitoring,proxy" {
				t.Errorf("uptime-kuma: %+v", ct)
			}
		case "pihole":
			if ct.NetworkMode != "host" {
				t.Errorf("pihole network mode: %+v", ct)
			}
		case "vaultwarden":
			if ct.DockerSocket {
				t.Error("vaultwarden flagged for docker socket")
			}
		}
	}
	if state.Snapshot.Score <= 0 || state.Snapshot.Score >= 70 {
		t.Errorf("demo score should be poor but positive, got %d", state.Snapshot.Score)
	}
	cats := map[string]int{}
	for _, f := range state.Snapshot.Findings {
		cats[f.Category]++
		if strings.Contains(f.Evidence, "Sup3rS3cret") || strings.Contains(f.Evidence, "wJalrXUtnFEMI/K7MDENG") {
			t.Errorf("secret leaked through API evidence: %s", f.Evidence)
		}
	}
	for _, want := range []string{"outdated", "credentials", "config", "practices", "errors", "runtime"} {
		if cats[want] == 0 {
			t.Errorf("no findings in category %s", want)
		}
	}
	for _, im := range state.Snapshot.Images {
		if im.Scan != nil && len(im.Scan.CVEs) > 0 {
			t.Error("state should not inline CVE lists")
		}
	}

	// CSRF guard: POST without header is refused.
	if r, _ := c.Post(ts.URL+"/api/scan", "application/json", nil); r.StatusCode != 403 {
		t.Errorf("POST without X-Keelwatch: %d", r.StatusCode)
	}
	// Suppress a finding and confirm the score improves.
	id := state.Snapshot.Findings[0].ID
	req, _ := http.NewRequest("POST", ts.URL+"/api/findings/"+id+"/suppress", strings.NewReader(`{"note":"test"}`))
	req.Header.Set("X-Keelwatch", "1")
	if r, _ := c.Do(req); r.StatusCode != 200 {
		t.Fatalf("suppress: %d", r.StatusCode)
	}
	r, _ = c.Get(ts.URL + "/api/state")
	var after struct{ Snapshot struct{ Score int } }
	_ = json.NewDecoder(r.Body).Decode(&after)
	if after.Snapshot.Score < state.Snapshot.Score {
		t.Errorf("score dropped after suppressing: %d -> %d", state.Snapshot.Score, after.Snapshot.Score)
	}

	// Falco webhook needs the token and creates an alert.
	body := `{"rule":"Terminal shell in container","priority":"Warning","output":"A shell was spawned","output_fields":{"container.name":"jellyfin"}}`
	if r, _ := http.Post(ts.URL+"/api/falco", "application/json", strings.NewReader(body)); r.StatusCode != 401 {
		t.Errorf("falco without token: %d", r.StatusCode)
	}
	req, _ = http.NewRequest("POST", ts.URL+"/api/falco", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer ftok")
	if r, _ := http.DefaultClient.Do(req); r.StatusCode != 200 {
		t.Errorf("falco with token: %d", r.StatusCode)
	}
	r, _ = c.Get(ts.URL + "/api/alerts")
	var alerts []struct{ Source, Container string }
	_ = json.NewDecoder(r.Body).Decode(&alerts)
	if len(alerts) == 0 || alerts[0].Source != "falco" {
		t.Errorf("falco alert missing: %+v", alerts)
	}
	// Security headers present.
	r, _ = c.Get(ts.URL + "/")
	if !strings.Contains(r.Header.Get("Content-Security-Policy"), "script-src 'self'") {
		t.Error("CSP missing")
	}
}

func TestBasePath(t *testing.T) {
	dir := t.TempDir()
	st, _ := store.Open(dir)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	dc, _ := docker.New("unix://" + dir + "/none.sock")
	n := notify.New(notify.Config{})
	eng := engine.New(engine.Config{}, dc, nil, nil, st, n, log)
	srv, err := New(Options{Version: "t", Password: "p", BasePath: "/keelwatch/"}, eng, st, n, log)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	get := func(p string) (*http.Response, string) {
		r, err := c.Get(ts.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(r.Body)
		return r, string(b)
	}
	if r, _ := get("/keelwatch"); r.StatusCode != 301 || r.Header.Get("Location") != "/keelwatch/" {
		t.Errorf("no trailing-slash redirect: %d %s", r.StatusCode, r.Header.Get("Location"))
	}
	r, body := get("/keelwatch/")
	if r.StatusCode != 200 || !strings.Contains(body, `<base href="/keelwatch/">`) {
		t.Errorf("index under base path: %d, base tag present=%v", r.StatusCode, strings.Contains(body, "<base"))
	}
	for _, p := range []string{"/keelwatch/assets/app.js", "/keelwatch/api/session", "/api/session", "/assets/app.js"} {
		if r, _ := get(p); r.StatusCode != 200 {
			t.Errorf("%s: %d", p, r.StatusCode)
		}
	}
	if _, body := get("/keelwatch/assets/app.js"); strings.Contains(body, `fetch("/api`) {
		t.Error("frontend still uses root-absolute API paths")
	}
}

// Multi-host: an agent pushes to a hub; suppressions made on the hub flow back.
func TestAgentHub(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	n := notify.New(notify.Config{})

	// Agent: a real scan of the demo host.
	adir := t.TempDir()
	host, err := demo.Start(ctx, adir)
	if err != nil {
		t.Fatal(err)
	}
	adc, _ := docker.New(host)
	ast, _ := store.Open(adir)
	aeng := engine.New(engine.Config{}, adc, demo.Checker{}, nil, ast, n, log)
	snap, err := aeng.ScanOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Hub: its own (unreachable) Docker plus one registered agent.
	hdir := t.TempDir()
	hst, _ := store.Open(hdir)
	hdc, _ := docker.New("unix://" + hdir + "/none.sock")
	heng := engine.New(engine.Config{}, hdc, nil, nil, hst, n, log)
	tok := strings.Repeat("k", 32)
	srv, err := New(Options{Version: "t", Password: "p", Agents: map[string]string{"pi-b": tok}, DataDir: hdir}, heng, hst, n, log)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	bad := &hub.Client{URL: ts.URL, Token: strings.Repeat("x", 32)}
	if err := bad.Push(ctx, ast); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("wrong token accepted: %v", err)
	}
	agent := &hub.Client{URL: ts.URL + "/", Token: tok, Version: "t", Interval: 30 * time.Minute}
	if err := agent.Push(ctx, ast); err != nil {
		t.Fatal(err)
	}

	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, Timeout: 10 * time.Second}
	if r, _ := c.Post(ts.URL+"/api/login", "application/json", strings.NewReader(`{"password":"p"}`)); r.StatusCode != 200 {
		t.Fatalf("login: %d", r.StatusCode)
	}
	r, _ := c.Get(ts.URL + "/api/hosts")
	var hosts []struct {
		ID       string
		Reported bool
		Stale    bool
		Score    int
		Debt     struct{ Open int }
	}
	_ = json.NewDecoder(r.Body).Decode(&hosts)
	if len(hosts) != 2 || hosts[0].ID != "" || hosts[1].ID != "pi-b" || !hosts[1].Reported || hosts[1].Stale ||
		hosts[1].Score != snap.Score || hosts[1].Debt.Open == 0 {
		t.Fatalf("hosts: %+v (agent score %d)", hosts, snap.Score)
	}
	if r, _ := c.Get(ts.URL + "/api/state?host=../pi-b"); r.StatusCode != 404 {
		t.Errorf("unknown host: %d", r.StatusCode)
	}

	// Suppress on the hub, push again, and the agent adopts it.
	id := snap.Findings[0].ID
	req, _ := http.NewRequest("POST", ts.URL+"/api/findings/"+id+"/suppress?host=pi-b", strings.NewReader(`{"note":"ok on hub"}`))
	req.Header.Set("X-Keelwatch", "1")
	if r, _ := c.Do(req); r.StatusCode != 200 {
		t.Fatalf("suppress on remote: %d", r.StatusCode)
	}
	if err := agent.Push(ctx, ast); err != nil {
		t.Fatal(err)
	}
	ast.View(func(s *store.State) {
		if s.Suppressed[id] != "ok on hub" {
			t.Errorf("agent did not adopt hub suppression: %v", s.Suppressed)
		}
	})
	r, _ = c.Get(ts.URL + "/api/state?host=pi-b")
	var st struct {
		Snapshot struct {
			Findings []struct {
				ID         string
				Suppressed bool
			}
		}
		Agent *struct{ Version string }
	}
	_ = json.NewDecoder(r.Body).Decode(&st)
	if st.Agent == nil || st.Agent.Version != "t" {
		t.Errorf("remote state lacks agent info: %+v", st.Agent)
	}
	for _, f := range st.Snapshot.Findings {
		if f.ID == id && !f.Suppressed {
			t.Error("hub lost the suppression after the next report")
		}
	}
	req, _ = http.NewRequest("POST", ts.URL+"/api/scan?host=pi-b", nil)
	req.Header.Set("X-Keelwatch", "1")
	if r, _ := c.Do(req); r.StatusCode != 409 {
		t.Errorf("scan on remote host: %d", r.StatusCode)
	}

	// Remove: data wiped, hidden from the fleet, reports refused; restore re-admits it.
	do := func(method, path string) int {
		req, _ := http.NewRequest(method, ts.URL+path, nil)
		req.Header.Set("X-Keelwatch", "1")
		r, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return r.StatusCode
	}
	if code := do("DELETE", "/api/hosts/nope"); code != 404 {
		t.Errorf("remove unknown host: %d", code)
	}
	if code := do("DELETE", "/api/hosts/pi-b"); code != 200 {
		t.Fatalf("remove host: %d", code)
	}
	hosts = nil
	r, _ = c.Get(ts.URL + "/api/hosts")
	_ = json.NewDecoder(r.Body).Decode(&hosts)
	if len(hosts) != 1 {
		t.Errorf("removed host still listed: %+v", hosts)
	}
	if _, err := os.Stat(filepath.Join(hdir, "hosts", "pi-b", "keelwatch.json")); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(hdir, "hosts", "pi-b", "keelwatch.json"))
	if strings.Contains(string(b), `"snapshot"`) {
		t.Error("removed host data not wiped")
	}
	if err := agent.Push(ctx, ast); err == nil || !strings.Contains(err.Error(), "410") {
		t.Errorf("removed agent's report accepted: %v", err)
	}
	r, _ = c.Get(ts.URL + "/api/settings")
	var set struct{ RemovedHosts []string }
	_ = json.NewDecoder(r.Body).Decode(&set)
	if len(set.RemovedHosts) != 1 || set.RemovedHosts[0] != "pi-b" {
		t.Errorf("settings removedHosts: %v", set.RemovedHosts)
	}
	if code := do("POST", "/api/hosts/pi-b/restore"); code != 200 {
		t.Fatalf("restore: %d", code)
	}
	if err := agent.Push(ctx, ast); err != nil {
		t.Errorf("restored agent refused: %v", err)
	}
}
