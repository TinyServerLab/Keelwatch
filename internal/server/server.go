// Package server exposes the JSON API and the embedded dashboard.
package server

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/keelwatch/keelwatch/internal/engine"
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
}

type Server struct {
	opt   Options
	eng   *engine.Engine
	st    *store.Store
	notif *notify.Notifier
	auth  *auth
	log   *slog.Logger
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
	return &Server{opt: opt, eng: eng, st: st, notif: n, auth: a, log: log}, nil
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
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(b)
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") })

	mux.HandleFunc("GET /api/session", s.session)
	mux.HandleFunc("POST /api/login", s.login)
	mux.HandleFunc("POST /api/logout", s.logout)
	mux.HandleFunc("POST /api/falco", s.falco)

	mux.Handle("GET /api/state", s.protect(s.state))
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
	return securityHeaders(mux)
}

func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
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
	}
	s.st.View(func(st *store.State) {
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
	out.Scanning = s.eng.Busy()
	out.CVEEnabled = s.eng.CVEEnabled()
	out.Version = s.opt.Version
	out.Demo = s.opt.Demo
	writeJSON(w, out)
}

func (s *Server) alerts(w http.ResponseWriter, r *http.Request) {
	var out []model.Alert
	s.st.View(func(st *store.State) { out = append(out, st.Alerts...) })
	sort.Slice(out, func(i, j int) bool { return out[i].Time.After(out[j].Time) })
	if out == nil {
		out = []model.Alert{}
	}
	writeJSON(w, out)
}

func (s *Server) imageCVEs(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var res *model.ImageScan
	s.st.View(func(st *store.State) {
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
	var sups []sup
	s.st.View(func(st *store.State) {
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
		"settings":   s.opt.Settings,
		"channels":   append([]string{}, s.notif.Channels()...),
		"suppressed": sups,
		"falcoReady": s.opt.FalcoToken != "",
		"cveEnabled": s.eng.CVEEnabled(),
	})
}

func (s *Server) export(w http.ResponseWriter, r *http.Request) {
	var snap *model.Snapshot
	s.st.View(func(st *store.State) { snap = st.Snapshot })
	w.Header().Set("Content-Disposition", `attachment; filename="keelwatch-report-`+time.Now().UTC().Format("20060102-1504")+`.json"`)
	writeJSON(w, snap)
}

func (s *Server) triggerScan(w http.ResponseWriter, r *http.Request) {
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
	_ = s.st.Update(func(st *store.State) {
		st.Suppressed[id] = truncate(body.Note, 200)
		s.rescore(st)
	})
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) unsuppress(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	_ = s.st.Update(func(st *store.State) {
		delete(st.Suppressed, id)
		s.rescore(st)
	})
	writeJSON(w, map[string]bool{"ok": true})
}

// rescore updates the current snapshot immediately after a suppression change.
func (s *Server) rescore(st *store.State) {
	if st.Snapshot == nil {
		return
	}
	for i := range st.Snapshot.Findings {
		_, st.Snapshot.Findings[i].Suppressed = st.Suppressed[st.Snapshot.Findings[i].ID]
	}
	scan.Score(st.Snapshot)
}

func (s *Server) ack(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	_ = s.st.Update(func(st *store.State) {
		for i := range st.Alerts {
			if st.Alerts[i].ID == id {
				st.Alerts[i].Acked = true
			}
		}
	})
	s.eng.Trigger()
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) ackAll(w http.ResponseWriter, r *http.Request) {
	_ = s.st.Update(func(st *store.State) {
		for i := range st.Alerts {
			st.Alerts[i].Acked = true
		}
	})
	s.eng.Trigger()
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
