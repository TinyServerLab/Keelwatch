package scan

import (
	"fmt"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/keelwatch/keelwatch/internal/docker"
	"github.com/keelwatch/keelwatch/internal/model"
)

var (
	minerRe   = regexp.MustCompile(`(?i)(\b(xmrig|xmr-stak|minerd|cpuminer|ccminer|nbminer|t-rex|lolminer|kdevtmpfsi|kinsing|phoenixminer|ethminer|cgminer|bfgminer|srbminer|teamredminer)\b|stratum\+(tcp|ssl)://)`)
	revShell  = regexp.MustCompile(`(?i)(/dev/(tcp|udp)/\d|\bnc(at)?\b.*\s-[a-z]*e\s|\bsocat\b.*exec:|python[0-9.]*\s+-c\s+.*socket.*connect|perl\s+-e\s+.*socket|mkfifo\s+\S+.*\bnc\b|\bsh\s+-i\b.*[<>]&)`)
	dlExec    = regexp.MustCompile(`(?i)\b(curl|wget)\b[^|;]*\|\s*(ba|da|z)?sh\b`)
	attackTls = regexp.MustCompile(`(?i)(^|/)(nmap|masscan|zmap|hydra|sqlmap|linpeas\.sh|pspy\d*|chisel|frpc|ngrok)(\s|$)`)
)

var shells = map[string]bool{"sh": true, "bash": true, "ash": true, "zsh": true, "dash": true, "busybox": true, "fish": true}

// LearningScans is how many scans build a container's process baseline
// before new processes are reported.
const LearningScans = 3

// ProcessRules flags malicious-looking processes and drift from baseline.
// It returns findings, and the set of process names to merge into baseline.
func ProcessRules(c docker.ContainerJSON, cmds []string, baseline map[string]bool, learning bool) ([]model.Finding, map[string]bool) {
	name := c.DisplayName()
	b := &fb{tt: model.TargetContainer, target: name, id: c.ID}
	seen := map[string]bool{}
	for _, cmd := range cmds {
		exe := procName(cmd)
		seen[exe] = true
		switch {
		case minerRe.MatchString(cmd):
			b.addD("proc-miner", exe, model.CatRuntime, model.SevCritical, "",
				"Crypto-miner process running",
				"A process matching known mining software is running. This almost always means the container (or the image) is compromised.",
				"Stop the container now (`docker stop "+name+"`), keep it for forensics (`docker commit`), rotate any secrets it had, and rebuild from a trusted image. Check how it got in: exposed ports, docker.sock, outdated image.", truncate(cmd, 200))
		case revShell.MatchString(cmd):
			b.addD("proc-revshell", exe, model.CatRuntime, model.SevCritical, "",
				"Reverse-shell pattern in a running process",
				"The command line looks like an attacker's remote shell.",
				"Isolate the container (`docker network disconnect`), capture `docker top` and `docker diff`, then rebuild and rotate credentials.", truncate(cmd, 200))
		case dlExec.MatchString(cmd):
			b.addD("proc-dlexec", exe, model.CatRuntime, model.SevHigh, "",
				"Download-and-execute command running",
				"A process is piping a download straight into a shell, a common payload-delivery step.",
				"Confirm whether this is expected (some install scripts do it). If not, treat the container as compromised.", truncate(cmd, 200))
		case attackTls.MatchString(cmd):
			b.addD("proc-attacktool", exe, model.CatRuntime, model.SevHigh, "",
				"Offensive/tunnelling tool running: "+exe,
				"Scanners and tunnelling tools are rarely part of a normal app.",
				"Verify who started it (`docker logs`, exec history in Runtime alerts).", truncate(cmd, 200))
		}
	}
	if !learning && baseline != nil {
		for exe := range seen {
			if exe == "" || baseline[exe] {
				continue
			}
			sev := model.SevMedium
			if shells[exe] {
				sev = model.SevHigh
			}
			b.addD("proc-drift", exe, model.CatRuntime, sev, "",
				"New process not in baseline: "+exe,
				fmt.Sprintf("`%s` was not running during the first %d scans of this container.", exe, LearningScans),
				"If this is expected (an update, a cron job), suppress the finding. Otherwise check Runtime alerts for a recent `docker exec`.", exe)
		}
	}
	return b.out, seen
}

func procName(cmd string) string {
	f := strings.Fields(cmd)
	if len(f) == 0 {
		return ""
	}
	exe := strings.Trim(f[0], "[]")
	if strings.HasSuffix(exe, ":") { // "nginx: worker process"
		exe = strings.TrimSuffix(exe, ":")
	}
	return path.Base(exe)
}

// ResourceRules flags containers saturating CPU or memory at scan time.
func ResourceRules(c docker.ContainerJSON, s docker.Stats) []model.Finding {
	b := &fb{tt: model.TargetContainer, target: c.DisplayName(), id: c.ID}
	cpu := s.CPUPercent()
	if cpu >= 90 {
		b.add("high-cpu", model.CatErrors, model.SevMedium, "",
			fmt.Sprintf("High CPU: %.0f%% at scan time", cpu),
			"Sustained high CPU can be a busy app, a bug, or an unwanted miner. Compare with Runtime findings.",
			"Check `docker top "+c.DisplayName()+"` and set a CPU limit.", fmt.Sprintf("%.0f%% (100%% = one core)", cpu))
	}
	if c.HostConfig.Memory > 0 {
		if m := s.MemPercent(); m >= 90 {
			b.add("near-mem-limit", model.CatErrors, model.SevMedium, "",
				fmt.Sprintf("Memory at %.0f%% of its limit", m),
				"The container is about to be OOM-killed.",
				"Raise `mem_limit` or investigate the memory growth.", fmt.Sprintf("%.0f%%", m))
		}
	}
	return b.out
}

// EventAlert turns a Docker event into a runtime alert, or nil.
// healthCmds maps container name → health-check command so routine health
// probes (which also appear as exec events) are ignored.
func EventAlert(ev docker.Event, healthCmds map[string]string) *model.Alert {
	if ev.Type != "container" {
		return nil
	}
	name := ev.Actor.Attributes["name"]
	action, arg, _ := strings.Cut(ev.Action, ": ")
	t := time.Unix(ev.Time, 0).UTC()
	if ev.Time == 0 {
		t = time.Now().UTC()
	}
	mk := func(sev model.Severity, title, detail string) *model.Alert {
		return &model.Alert{
			ID: model.MakeID("event", name, fmt.Sprint(ev.Time, ev.Action)), Time: t, Severity: sev,
			Source: "docker-events", Container: name, Title: title, Detail: detail,
		}
	}
	switch action {
	case "exec_start":
		cmd := strings.TrimSpace(arg)
		if hc := healthCmds[name]; hc != "" && (strings.Contains(cmd, hc) || strings.Contains(hc, cmd)) {
			return nil
		}
		exe := procName(cmd)
		if shells[exe] && !strings.Contains(cmd, " -c ") {
			return mk(model.SevHigh, "Interactive shell opened in "+name, "docker exec: "+truncate(cmd, 200))
		}
		if minerRe.MatchString(cmd) || revShell.MatchString(cmd) || dlExec.MatchString(cmd) {
			return mk(model.SevCritical, "Malicious-looking command executed in "+name, "docker exec: "+truncate(cmd, 200))
		}
		return mk(model.SevMedium, "Command executed in "+name, "docker exec: "+truncate(cmd, 200))
	case "oom":
		return mk(model.SevHigh, name+" was OOM-killed", "The kernel killed the container for exceeding its memory.")
	case "die":
		if code := ev.Actor.Attributes["exitCode"]; code != "" && code != "0" && code != "143" && code != "130" {
			return mk(model.SevMedium, name+" crashed (exit "+code+")", "Container stopped unexpectedly.")
		}
	case "health_status":
		if strings.TrimSpace(arg) == "unhealthy" {
			return mk(model.SevHigh, name+" became unhealthy", "Its health check started failing.")
		}
	}
	return nil
}

// FalcoEvent is the Falcosidekick webhook payload.
type FalcoEvent struct {
	Output       string         `json:"output"`
	Priority     string         `json:"priority"`
	Rule         string         `json:"rule"`
	Time         time.Time      `json:"time"`
	Hostname     string         `json:"hostname"`
	OutputFields map[string]any `json:"output_fields"`
}

func FalcoAlert(e FalcoEvent) model.Alert {
	sev := model.SevInfo
	switch strings.ToLower(e.Priority) {
	case "emergency", "alert", "critical":
		sev = model.SevCritical
	case "error":
		sev = model.SevHigh
	case "warning":
		sev = model.SevMedium
	case "notice":
		sev = model.SevLow
	}
	cname, _ := e.OutputFields["container.name"].(string)
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	return model.Alert{
		ID: model.MakeID("falco", cname, e.Rule+e.Time.String()), Time: e.Time.UTC(), Severity: sev,
		Source: "falco", Container: cname, Title: e.Rule, Detail: truncate(e.Output, 500),
	}
}

// HealthCmd returns the health-check command as it appears in exec events.
func HealthCmd(c docker.ContainerJSON) string {
	if c.Config.Healthcheck == nil || len(c.Config.Healthcheck.Test) < 2 {
		return ""
	}
	t := c.Config.Healthcheck.Test
	return strings.Join(t[1:], " ")
}
