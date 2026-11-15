package scan

import (
	"fmt"
	"strings"

	"github.com/keelwatch/keelwatch/internal/docker"
	"github.com/keelwatch/keelwatch/internal/model"
)

// fb collects findings for one target.
type fb struct {
	tt     model.TargetType
	target string
	id     string
	where  string // e.g. "compose service `web` in /opt/app/compose.yml"
	out    []model.Finding
}

func (b *fb) add(rule string, cat model.Category, sev model.Severity, cis, title, detail, fix, evidence string) {
	b.addD(rule, "", cat, sev, cis, title, detail, fix, evidence)
}

// addD adds a finding with an extra discriminator so one rule can fire
// several times for the same target (e.g. two leaked env vars).
func (b *fb) addD(rule, disc string, cat model.Category, sev model.Severity, cis, title, detail, fix, evidence string) {
	if b.where != "" && fix != "" {
		fix = fix + "\n\nWhere: " + b.where
	}
	b.out = append(b.out, model.Finding{
		ID: model.MakeID(rule, b.target, disc), Rule: rule, Category: cat, Severity: sev, CIS: cis,
		Title: title, Detail: detail, Remediation: fix, Evidence: evidence,
		TargetType: b.tt, Target: b.target, TargetID: b.id,
	})
}

var dangerousCaps = map[string]string{
	"ALL":             "every Linux capability",
	"SYS_ADMIN":       "mount filesystems and escape the container in many ways",
	"SYS_PTRACE":      "inspect and inject into other processes",
	"SYS_MODULE":      "load kernel modules on the host",
	"DAC_READ_SEARCH": "read any file on mounted filesystems (open_by_handle_at escape)",
	"NET_ADMIN":       "reconfigure networking and sniff traffic",
	"SYS_RAWIO":       "raw access to host I/O ports and memory",
	"SYS_BOOT":        "reboot the host",
	"SYS_TIME":        "change the host clock",
	"BPF":             "load eBPF programs into the host kernel",
	"PERFMON":         "observe host performance data",
}

var sensitiveHostPaths = []string{"/", "/boot", "/dev", "/etc", "/lib", "/proc", "/sys", "/usr", "/root", "/var/lib/docker"}

var credentialMounts = []struct{ sub, what string }{
	{"/.ssh", "SSH keys"},
	{"/.docker/config.json", "registry credentials"},
	{"/.aws", "AWS credentials"},
	{"/.kube", "Kubernetes credentials"},
	{"/etc/shadow", "host password hashes"},
	{"/.gnupg", "GPG keys"},
	{"/.config/gcloud", "Google Cloud credentials"},
}

func composeWhere(labels map[string]string) string {
	svc := labels["com.docker.compose.service"]
	if svc == "" {
		return ""
	}
	if f := labels["com.docker.compose.project.config_files"]; f != "" {
		return fmt.Sprintf("compose service `%s` in %s", svc, f)
	}
	return fmt.Sprintf("compose service `%s` (project %s)", svc, labels["com.docker.compose.project"])
}

// ContainerRules evaluates configuration, credential, best-practice and
// error rules for one container. img may be nil.
func ContainerRules(c docker.ContainerJSON, img *docker.ImageInspect) []model.Finding {
	name := c.DisplayName()
	b := &fb{tt: model.TargetContainer, target: name, id: c.ID, where: composeWhere(c.Config.Labels)}
	hc := c.HostConfig

	// ---------- Configuration flaws ----------
	if hc.Privileged {
		b.add("privileged", model.CatConfig, model.SevCritical, "5.5",
			"Runs in privileged mode",
			"Privileged containers get every capability and all host devices. A compromise here is a compromise of the host.",
			"Remove `privileged: true`. Grant only the specific capability or device the app needs (`cap_add`, `devices`).", "")
	}
	for _, cap := range hc.CapAdd {
		k := strings.ToUpper(strings.TrimPrefix(strings.ToUpper(cap), "CAP_"))
		if why, ok := dangerousCaps[k]; ok {
			sev := model.SevHigh
			if k == "ALL" || k == "SYS_ADMIN" || k == "SYS_MODULE" {
				sev = model.SevCritical
			}
			b.addD("dangerous-cap", k, model.CatConfig, sev, "5.4",
				"Dangerous capability added: "+k,
				"CAP_"+k+" lets the container "+why+".",
				"Remove `"+k+"` from `cap_add`. If it is required, isolate this container on its own network and document why.", "cap_add: "+k)
		}
	}
	if hc.NetworkMode == "host" {
		b.add("host-network", model.CatConfig, model.SevHigh, "5.10",
			"Shares the host network namespace",
			"With host networking the container can bind any host port and see all host traffic; Docker's port isolation does not apply.",
			"Use a bridge network and publish only the needed ports (`ports:`). Keep `network_mode: host` only for apps that truly need it (DHCP, mDNS).", "network_mode: host")
	}
	if hc.PidMode == "host" {
		b.add("host-pid", model.CatConfig, model.SevHigh, "5.16",
			"Shares the host PID namespace",
			"The container can see and signal every process on the host.",
			"Remove `pid: host`.", "pid: host")
	}
	if hc.IpcMode == "host" {
		b.add("host-ipc", model.CatConfig, model.SevHigh, "5.17",
			"Shares the host IPC namespace",
			"Shared memory of host processes is reachable from the container.",
			"Remove `ipc: host`.", "ipc: host")
	}
	if hc.UsernsMode == "host" {
		b.add("host-userns", model.CatConfig, model.SevMedium, "5.31",
			"Opts out of user-namespace remapping",
			"`userns_mode: host` disables the daemon's user-namespace protection for this container.",
			"Remove `userns_mode: host`.", "")
	}
	for _, so := range hc.SecurityOpt {
		l := strings.ToLower(so)
		if strings.Contains(l, "seccomp") && strings.Contains(l, "unconfined") {
			b.add("seccomp-unconfined", model.CatConfig, model.SevHigh, "5.22",
				"Seccomp profile disabled",
				"Without seccomp the container can call ~300 syscalls that Docker normally blocks.",
				"Remove `seccomp:unconfined` from `security_opt`.", so)
		}
		if strings.Contains(l, "apparmor") && strings.Contains(l, "unconfined") {
			b.add("apparmor-unconfined", model.CatConfig, model.SevHigh, "5.2",
				"AppArmor profile disabled",
				"The default AppArmor profile is switched off for this container.",
				"Remove `apparmor:unconfined` from `security_opt`.", so)
		}
	}
	if len(hc.Devices) > 0 {
		var ds []string
		for _, d := range hc.Devices {
			ds = append(ds, d.PathOnHost)
		}
		b.add("host-devices", model.CatConfig, model.SevMedium, "5.18",
			"Host devices passed through",
			"Direct device access widens the attack surface on the host kernel.",
			"Keep only devices the app needs (e.g. /dev/dri for transcoding) and avoid block devices.", strings.Join(ds, ", "))
	}
	for _, m := range c.Mounts {
		src := strings.TrimRight(m.Source, "/")
		if src == "" {
			src = "/"
		}
		if strings.HasSuffix(src, "docker.sock") || strings.HasSuffix(m.Destination, "docker.sock") {
			sev := model.SevCritical
			mode := "read-write"
			if !m.RW {
				mode = "read-only"
			}
			if isSocketProxy(c.Config.Image) {
				psev := model.SevLow
				if m.RW {
					psev = model.SevMedium
				}
				b.addD("docker-socket-proxy", src, model.CatConfig, psev, "5.32",
					"Socket proxy holds the Docker socket",
					"This is expected: the proxy is the one container allowed to talk to Docker, and it filters what others can do.",
					"Keep `POST=0` (read-only API), mount the socket `:ro`, put the proxy on an `internal: true` network and never publish its port.", src+" → "+m.Destination)
				continue
			}
			b.addD("docker-socket", src, model.CatConfig, sev, "5.32",
				"Docker socket mounted ("+mode+")",
				"Access to the Docker socket equals root on the host, even when mounted read-only: the API itself can start a privileged container.",
				"Remove the socket mount. If the app needs Docker data, put a read-only docker-socket-proxy in front (e.g. tecnativa/docker-socket-proxy with POST=0) and point the app at it.", src+" → "+m.Destination)
			continue
		}
		if m.Type == "bind" {
			for _, p := range sensitiveHostPaths {
				if src == p {
					sev := model.SevHigh
					if !m.RW {
						sev = model.SevMedium
					}
					b.addD("sensitive-mount", src, model.CatConfig, sev, "5.6",
						"Sensitive host path mounted: "+src,
						"Mounting system directories lets the container read or change host configuration.",
						"Mount only the specific file or sub-directory needed, read-only (`:ro`).", fmt.Sprintf("%s → %s (rw=%v)", src, m.Destination, m.RW))
				}
			}
			for _, cm := range credentialMounts {
				if strings.Contains(src, cm.sub) {
					b.addD("credential-mount", src, model.CatCredentials, model.SevHigh, "",
						"Host "+cm.what+" mounted into container",
						"The container can read "+cm.what+" from the host. If the app is compromised, these credentials leak.",
						"Use Docker secrets or a scoped, dedicated credential instead of mounting your personal "+cm.what+".", src+" → "+m.Destination)
				}
			}
		}
	}
	for port, binds := range hc.PortBindings {
		for _, bd := range binds {
			if bd.HostIP == "" || bd.HostIP == "0.0.0.0" || bd.HostIP == "::" {
				b.addD("exposed-port", port+bd.HostPort, model.CatConfig, model.SevMedium, "5.14",
					"Port "+bd.HostPort+" published on all interfaces",
					"Published ports bypass UFW/firewalld rules because Docker writes its own iptables rules. Anyone on the network (or internet, on a VPS) can reach "+port+".",
					"Bind to localhost and use a reverse proxy or tunnel: `ports: [\"127.0.0.1:"+bd.HostPort+":"+strings.Split(port, "/")[0]+"\"]`.", "0.0.0.0:"+bd.HostPort+" → "+port)
			}
		}
	}

	// ---------- Credential leakage (environment) ----------
	imgEnv := map[string]bool{}
	if img != nil {
		for _, e := range img.Config.Env {
			imgEnv[e] = true
		}
	}
	for _, h := range scanEnv(c.Config.Env) {
		sev := model.SevHigh
		title := "Plaintext secret in environment: " + h.Key
		detail := "Anyone who can run `docker inspect` (or read /proc inside the container) can read this value. It also ends up in logs and crash reports."
		fix := "Move it to a Docker secret or a file mounted read-only, and use the app's `" + h.Key + "_FILE` variant if it supports one."
		if h.Known {
			sev = model.SevCritical
			title = h.Kind + " exposed in environment: " + h.Key
			fix = "Rotate this credential now, then load it from a Docker secret instead of an environment variable."
		}
		if h.Weak {
			sev = model.SevCritical
			title = "Default/weak credential in " + h.Key
			detail = "The value is a well-known default that attackers try first."
			fix = "Set a strong random value (e.g. `openssl rand -base64 32`) and store it as a Docker secret."
		}
		b.addD("env-secret", h.Key, model.CatCredentials, sev, "", title, detail, fix, h.Key+"="+h.Redacted)
	}

	// ---------- Best practices ----------
	user := c.Config.User
	if user == "" && img != nil {
		user = img.Config.User
	}
	if user == "" || user == "0" || user == "root" || strings.HasPrefix(user, "0:") || strings.HasPrefix(user, "root:") {
		b.add("runs-as-root", model.CatPractices, model.SevMedium, "4.1",
			"Runs as root",
			"If the app is compromised the attacker is root inside the container, which makes kernel escapes far easier.",
			"Set `user: \"1000:1000\"` (or the app's documented UID) and fix volume ownership. Many linuxserver.io images support PUID/PGID instead.", "user: "+orDash(user))
	}
	if !hasNoNewPrivs(hc.SecurityOpt) {
		b.add("no-new-privileges", model.CatPractices, model.SevLow, "5.26",
			"`no-new-privileges` not set",
			"Processes can still gain privileges through setuid binaries.",
			"Add `security_opt: [\"no-new-privileges:true\"]`.", "")
	}
	if !hc.ReadonlyRootfs {
		b.add("writable-rootfs", model.CatPractices, model.SevLow, "5.13",
			"Root filesystem is writable",
			"Attackers can drop tools and persist changes inside the container.",
			"Add `read_only: true` and mount `tmpfs` for paths the app writes to (e.g. /tmp).", "")
	}
	if hc.Memory == 0 {
		b.add("no-memory-limit", model.CatPractices, model.SevMedium, "5.11",
			"No memory limit",
			"A leak or attack in this container can exhaust host RAM and take every other service down (OOM killer).",
			"Add `mem_limit: 512m` (or `deploy.resources.limits.memory`) sized to the app.", "")
	}
	if hc.NanoCpus == 0 && hc.CPUQuota == 0 {
		b.add("no-cpu-limit", model.CatPractices, model.SevLow, "5.12",
			"No CPU limit",
			"A runaway process (or a crypto-miner) can starve the host.",
			"Add `cpus: 1.0` (or `deploy.resources.limits.cpus`).", "")
	}
	if hc.PidsLimit == nil || *hc.PidsLimit <= 0 {
		b.add("no-pids-limit", model.CatPractices, model.SevLow, "5.29",
			"No PIDs limit",
			"A fork bomb inside the container can exhaust host process slots.",
			"Add `pids_limit: 200`.", "")
	}
	hasHC := c.Config.Healthcheck != nil && len(c.Config.Healthcheck.Test) > 0 && c.Config.Healthcheck.Test[0] != "NONE"
	if !hasHC && img != nil && img.Config.Healthcheck != nil && len(img.Config.Healthcheck.Test) > 0 && img.Config.Healthcheck.Test[0] != "NONE" {
		hasHC = true
	}
	if !hasHC {
		b.add("no-healthcheck", model.CatPractices, model.SevLow, "4.6",
			"No health check",
			"Docker cannot tell a hung app from a healthy one, so failures go unnoticed.",
			"Add a `healthcheck:` that probes the app (e.g. `curl -f http://localhost:PORT/health`).", "")
	}
	ref := c.Config.Image
	if !strings.Contains(ref, "@sha256:") {
		r := ref
		if i := strings.LastIndex(r, "/"); i >= 0 {
			r = r[i:]
		}
		if !strings.Contains(r, ":") || strings.HasSuffix(ref, ":latest") {
			b.add("latest-tag", model.CatPractices, model.SevMedium, "",
				"Uses the `latest` (unpinned) tag",
				"Unpinned images change under you on the next pull, which breaks rollbacks and hides what version is running.",
				"Pin a version tag (e.g. `image: "+strings.TrimSuffix(ref, ":latest")+":1.2.3`) and update deliberately.", "image: "+ref)
		}
	}
	lc := hc.LogConfig
	if (lc.Type == "json-file" || lc.Type == "") && lc.Config["max-size"] == "" {
		b.add("unbounded-logs", model.CatPractices, model.SevMedium, "",
			"Container logs are not rotated",
			"json-file logs without `max-size` grow forever and can fill the disk (common on SD cards).",
			"Add `logging: {driver: json-file, options: {max-size: \"10m\", max-file: \"3\"}}` or set it daemon-wide in daemon.json.", "log driver: "+orDash(lc.Type))
	}
	if hc.RestartPolicy.Name == "" || hc.RestartPolicy.Name == "no" {
		b.add("no-restart-policy", model.CatPractices, model.SevInfo, "",
			"No restart policy",
			"The service will stay down after a crash or reboot.",
			"Add `restart: unless-stopped`.", "")
	}
	if hc.RestartPolicy.Name == "on-failure" && hc.RestartPolicy.MaximumRetryCount == 0 {
		b.add("unbounded-restarts", model.CatPractices, model.SevLow, "5.15",
			"Unlimited on-failure restarts",
			"A crashing container restarts forever, hiding the failure.",
			"Use `on-failure:5`.", "")
	}

	// ---------- Critical errors ----------
	st := c.State
	switch {
	case st.Dead || st.Status == "dead":
		b.add("dead", model.CatErrors, model.SevCritical, "", "Container is dead",
			"Docker could not remove or stop this container cleanly; this often means a storage-driver problem.",
			"Check `journalctl -u docker` for errors, then `docker rm -f "+name+"`.", "state: dead")
	case st.Restarting || c.RestartCount >= 5:
		b.add("restart-loop", model.CatErrors, model.SevHigh, "", "Restart loop",
			fmt.Sprintf("The container has restarted %d times and keeps crashing.", c.RestartCount),
			"Run `docker logs --tail 100 "+name+"` to find the crash reason (bad config, missing env, port in use).", fmt.Sprintf("restarts: %d, state: %s", c.RestartCount, st.Status))
	}
	if st.OOMKilled {
		b.add("oom-killed", model.CatErrors, model.SevHigh, "", "Killed: out of memory",
			"The kernel OOM killer stopped this container.",
			"Raise its memory limit or find the leak. Check `docker stats` for usage trends.", "OOMKilled: true")
	}
	if st.Status == "exited" && st.ExitCode != 0 && !st.OOMKilled {
		sev := model.SevMedium
		detail := fmt.Sprintf("The container exited with code %d.", st.ExitCode)
		if p := hc.RestartPolicy.Name; p == "always" || p == "unless-stopped" {
			sev = model.SevHigh
			detail += " Its restart policy says it should be running."
		}
		if st.ExitCode == 143 || st.ExitCode == 130 {
			sev = model.SevInfo
			detail = "Stopped by a signal (manual stop)."
		}
		b.add("exited-error", model.CatErrors, sev, "", fmt.Sprintf("Exited with error code %d", st.ExitCode),
			detail, "Check `docker logs --tail 100 "+name+"`.", "exit code "+fmt.Sprint(st.ExitCode))
	}
	if st.Health != nil && st.Health.Status == "unhealthy" {
		ev := ""
		if n := len(st.Health.Log); n > 0 {
			ev = truncate(strings.TrimSpace(st.Health.Log[n-1].Output), 200)
		}
		b.add("unhealthy", model.CatErrors, model.SevHigh, "", "Health check failing",
			fmt.Sprintf("Health check has failed %d times in a row.", st.Health.FailingStreak),
			"Inspect the health log with `docker inspect --format '{{json .State.Health}}' "+name+"`.", ev)
	}
	if st.Error != "" {
		b.add("runtime-error", model.CatErrors, model.SevHigh, "", "Docker reported an error",
			"The engine recorded an error for this container.", "Read the error and `journalctl -u docker`.", truncate(st.Error, 200))
	}
	return b.out
}

func isSocketProxy(image string) bool {
	i := strings.ToLower(image)
	return strings.Contains(i, "docker-socket-proxy") || strings.Contains(i, "socket-proxy:") || strings.HasSuffix(i, "socket-proxy")
}

func hasNoNewPrivs(opts []string) bool {
	for _, o := range opts {
		l := strings.ToLower(strings.ReplaceAll(o, "=", ":"))
		if l == "no-new-privileges" || l == "no-new-privileges:true" {
			return true
		}
	}
	return false
}

func orDash(s string) string {
	if s == "" {
		return "(not set)"
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
