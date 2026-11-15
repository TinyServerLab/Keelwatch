package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/keelwatch/keelwatch/internal/demo"
	"github.com/keelwatch/keelwatch/internal/docker"
	"github.com/keelwatch/keelwatch/internal/engine"
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
		}
	}
	_ = json.NewDecoder(r.Body).Decode(&state)
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
