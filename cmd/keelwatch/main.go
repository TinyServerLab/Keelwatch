// Command keelwatch is a self-hosted Docker security posture dashboard.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/keelwatch/keelwatch/internal/demo"
	"github.com/keelwatch/keelwatch/internal/docker"
	"github.com/keelwatch/keelwatch/internal/engine"
	"github.com/keelwatch/keelwatch/internal/model"
	"github.com/keelwatch/keelwatch/internal/notify"
	"github.com/keelwatch/keelwatch/internal/registry"
	"github.com/keelwatch/keelwatch/internal/scan"
	"github.com/keelwatch/keelwatch/internal/server"
	"github.com/keelwatch/keelwatch/internal/store"
)

var version = "0.1.1"

var basePathRe = regexp.MustCompile(`^(/[A-Za-z0-9._~-]+)+$`)

func env(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

// secret reads K, or the file named by K_FILE (Docker secrets).
func secret(k string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	if f := os.Getenv(k + "_FILE"); f != "" {
		b, err := os.ReadFile(f)
		if err == nil {
			return strings.TrimSpace(string(b))
		}
		slog.Error("cannot read secret file", "var", k+"_FILE", "err", err)
	}
	return ""
}

func dur(k string, def time.Duration) time.Duration {
	if v := os.Getenv(k); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
		slog.Warn("invalid duration, using default", "var", k, "value", v)
	}
	return def
}

func boolEnv(k string, def bool) bool {
	v := strings.ToLower(os.Getenv(k))
	switch v {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	return def
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "healthcheck":
			os.Exit(healthcheck())
		case "scan":
			os.Exit(cliScan(os.Args[2:]))
		case "version", "--version", "-v":
			fmt.Println("keelwatch", version)
			return
		case "help", "--help", "-h":
			fmt.Println("usage: keelwatch [serve|scan [--json] [--fail-on critical|high]|healthcheck|version]")
			return
		case "serve":
		default:
			fmt.Fprintln(os.Stderr, "unknown command:", os.Args[1])
			os.Exit(2)
		}
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)
	if err := serve(log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

type setup struct {
	eng     *engine.Engine
	st      *store.Store
	notif   *notify.Notifier
	cfg     engine.Config
	demo    bool
	trivy   string
	dockerH string
}

func build(ctx context.Context, log *slog.Logger) (*setup, error) {
	dataDir := env("KEELWATCH_DATA", "/data")
	demoMode := boolEnv("KEELWATCH_DEMO", false)
	dockerHost := env("DOCKER_HOST", "unix:///var/run/docker.sock")
	if demoMode {
		dataDir = env("KEELWATCH_DATA", filepath.Join(os.TempDir(), "keelwatch-demo"))
		if err := os.MkdirAll(dataDir, 0o700); err != nil {
			return nil, err
		}
		h, err := demo.Start(ctx, dataDir)
		if err != nil {
			return nil, fmt.Errorf("demo docker: %w", err)
		}
		dockerHost = h
		log.Info("DEMO MODE: using a simulated Docker host; no real containers are scanned")
	}
	st, err := store.Open(dataDir)
	if err != nil {
		return nil, fmt.Errorf("open data dir %s: %w", dataDir, err)
	}
	dc, err := docker.New(dockerHost)
	if err != nil {
		return nil, err
	}
	var reg registry.Checker = registry.NewHTTPChecker()
	var cve scan.CVEScanner
	trivyBin := env("KEELWATCH_TRIVY", "trivy")
	if demoMode {
		reg, cve = demo.Checker{}, demo.Scanner{}
	} else if trivyBin != "off" {
		if _, err := exec.LookPath(trivyBin); err == nil {
			th := ""
			if strings.HasPrefix(dockerHost, "tcp://") || strings.HasPrefix(dockerHost, "unix://") {
				th = dockerHost
			}
			cve = &scan.TrivyScanner{Bin: trivyBin, DockerHost: th, CacheDir: env("KEELWATCH_TRIVY_CACHE", filepath.Join(dataDir, "trivy-cache"))}
		} else {
			log.Info("Trivy not found; CVE scanning disabled", "binary", trivyBin)
			trivyBin = "off"
		}
	}
	var composeDirs []string
	for _, d := range strings.Split(env("KEELWATCH_COMPOSE_DIRS", ""), ",") {
		if d = strings.TrimSpace(d); d != "" {
			composeDirs = append(composeDirs, d)
		}
	}
	minSev := model.Severity(strings.ToLower(env("KEELWATCH_NOTIFY_MIN_SEVERITY", "high")))
	if minSev.Rank() == 0 && minSev != model.SevInfo {
		minSev = model.SevHigh
	}
	cfg := engine.Config{
		ScanInterval:   dur("KEELWATCH_SCAN_INTERVAL", 30*time.Minute),
		RegistryTTL:    dur("KEELWATCH_REGISTRY_TTL", 6*time.Hour),
		CVETTL:         dur("KEELWATCH_CVE_TTL", 24*time.Hour),
		ComposeDirs:    composeDirs,
		DaemonJSONPath: env("KEELWATCH_DAEMON_JSON", "/host/etc/docker/daemon.json"),
		CheckUpdates:   boolEnv("KEELWATCH_CHECK_UPDATES", true),
		NotifyMinSev:   minSev,
		BaseURL:        env("KEELWATCH_BASE_URL", ""),
	}
	n := notify.New(notify.Config{
		NtfyURL: secret("KEELWATCH_NTFY_URL"), NtfyToken: secret("KEELWATCH_NTFY_TOKEN"),
		DiscordWebhook: secret("KEELWATCH_DISCORD_WEBHOOK"), SlackWebhook: secret("KEELWATCH_SLACK_WEBHOOK"),
		TelegramToken: secret("KEELWATCH_TELEGRAM_TOKEN"), TelegramChat: env("KEELWATCH_TELEGRAM_CHAT_ID", ""),
		WebhookURL: secret("KEELWATCH_WEBHOOK_URL"),
	})
	eng := engine.New(cfg, dc, reg, cve, st, n, log)
	return &setup{eng: eng, st: st, notif: n, cfg: cfg, demo: demoMode, trivy: trivyBin, dockerH: dockerHost}, nil
}

func serve(log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	s, err := build(ctx, log)
	if err != nil {
		return err
	}
	addr := env("KEELWATCH_ADDR", ":8080")
	falcoTok := secret("KEELWATCH_FALCO_TOKEN")
	basePath := strings.TrimRight(env("KEELWATCH_BASE_PATH", ""), "/")
	if basePath != "" && !basePathRe.MatchString(basePath) {
		return fmt.Errorf("KEELWATCH_BASE_PATH %q must look like /keelwatch (letters, digits, - _ . ~ only)", basePath)
	}
	srv, err := server.New(server.Options{
		Version: version, Password: secret("KEELWATCH_PASSWORD"), AuthDisabled: !boolEnv("KEELWATCH_AUTH", true) && !s.demo,
		FalcoToken: falcoTok, Demo: s.demo, BasePath: basePath,
		Settings: map[string]any{
			"Docker API":            s.dockerH,
			"Base path":             basePath,
			"Scan interval":         s.cfg.ScanInterval.String(),
			"Registry update check": strconv.FormatBool(s.cfg.CheckUpdates) + " (cache " + s.cfg.RegistryTTL.String() + ")",
			"CVE scanner":           map[bool]string{true: s.trivy + " (rescan every " + s.cfg.CVETTL.String() + ")", false: "off"}[s.eng.CVEEnabled()],
			"Compose directories":   s.cfg.ComposeDirs,
			"daemon.json":           s.cfg.DaemonJSONPath,
			"Notify at severity ≥":  string(s.cfg.NotifyMinSev),
		},
	}, s.eng, s.st, s.notif, log)
	if err != nil {
		return err
	}
	hs := &http.Server{Addr: addr, Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second}
	go s.eng.Run(ctx)
	go func() {
		<-ctx.Done()
		sh, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = hs.Shutdown(sh)
	}()
	log.Info("Keelwatch listening", "addr", addr, "version", version, "basePath", basePath)
	if err := hs.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func healthcheck() int {
	addr := env("KEELWATCH_ADDR", ":8080")
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://" + addr + "/healthz")
	if err != nil || resp.StatusCode != 200 {
		return 1
	}
	return 0
}

func cliScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "print the full report as JSON")
	failOn := fs.String("fail-on", "", "exit 3 if a finding at this severity or above exists (critical|high|medium)")
	_ = fs.Parse(args)
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	s, err := build(ctx, log)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	snap, err := s.eng.ScanOnce(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(snap)
	} else {
		fmt.Printf("Keelwatch %s — %s (Docker %s)\nScore %d/100, grade %s, %d containers\n\n", version, snap.Host.Name, snap.Host.EngineVersion, snap.Score, snap.Grade, len(snap.Containers))
		for _, c := range snap.Categories {
			fmt.Printf("  %-22s %3d  (%d issues)\n", c.Label, c.Score, c.Count)
		}
		fmt.Println()
		for _, f := range snap.Findings {
			if f.Suppressed || f.Severity == model.SevInfo {
				continue
			}
			fmt.Printf("%-9s %-24s %s\n", strings.ToUpper(string(f.Severity)), truncate(f.Target, 24), f.Title)
		}
	}
	if *failOn != "" {
		min := model.Severity(strings.ToLower(*failOn)).Rank()
		for _, f := range snap.Findings {
			if !f.Suppressed && min > 0 && f.Severity.Rank() >= min {
				return 3
			}
		}
	}
	return 0
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
