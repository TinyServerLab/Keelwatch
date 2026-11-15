package scan

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/keelwatch/keelwatch/internal/docker"
	"github.com/keelwatch/keelwatch/internal/model"
)

// DaemonJSON is the subset of /etc/docker/daemon.json Keelwatch checks.
type DaemonJSON struct {
	Hosts           []string          `json:"hosts"`
	TLSVerify       bool              `json:"tlsverify"`
	ICC             *bool             `json:"icc"`
	UsernsRemap     string            `json:"userns-remap"`
	LiveRestore     bool              `json:"live-restore"`
	NoNewPrivileges bool              `json:"no-new-privileges"`
	LogDriver       string            `json:"log-driver"`
	LogOpts         map[string]string `json:"log-opts"`
	InsecureRegs    []string          `json:"insecure-registries"`
	Experimental    bool              `json:"experimental"`
}

func ReadDaemonJSON(path string) (*DaemonJSON, error) {
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var d DaemonJSON
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, fmt.Errorf("daemon.json: %w", err)
	}
	return &d, nil
}

const minEngineMajor = 26 // older majors no longer receive security fixes

// HostRules evaluates daemon/host level posture (CIS sections 2 and 3).
func HostRules(info docker.Info, ver docker.Version, bridge *docker.Network, df *docker.DiskUsage, dj *DaemonJSON) []model.Finding {
	b := &fb{tt: model.TargetHost, target: "host:" + orDash(info.Name)}
	secOpts := strings.Join(info.SecurityOptions, " ")

	for _, w := range info.Warnings {
		lw := strings.ToLower(w)
		switch {
		case strings.Contains(lw, "without encryption") || strings.Contains(lw, "0.0.0.0:2375"):
			b.addD("daemon-tcp-plain", w, model.CatConfig, model.SevCritical, "2.7",
				"Docker API exposed over TCP without TLS",
				"Anyone who can reach this port has full root on the host. This is how most cryptojacking botnets get in.",
				"Remove the tcp:// listener from daemon.json/systemd, or enable TLS with client certificates (`tlsverify`). Use SSH (`DOCKER_HOST=ssh://`) for remote access.", w)
		default:
			b.addD("daemon-warning", w, model.CatErrors, model.SevMedium, "",
				"Docker engine warning", "The engine reported a warning about its own configuration.",
				"Investigate the warning shown below.", w)
		}
	}
	if dj != nil {
		for _, h := range dj.Hosts {
			if strings.HasPrefix(h, "tcp://") && !dj.TLSVerify {
				b.addD("daemon-tcp-plain", h, model.CatConfig, model.SevCritical, "2.7",
					"Docker API listens on TCP without TLS verification",
					"daemon.json opens "+h+" without `tlsverify`. Anyone who reaches it controls the host.",
					"Remove the tcp:// host or set `tlsverify: true` with tlscacert/tlscert/tlskey.", h)
			}
		}
		if len(dj.InsecureRegs) > 0 {
			b.add("insecure-registry", model.CatConfig, model.SevMedium, "2.5",
				"Insecure registries allowed",
				"Images from these registries are pulled over plain HTTP and can be tampered with in transit.",
				"Remove `insecure-registries` and give the registry a TLS certificate.", strings.Join(dj.InsecureRegs, ", "))
		}
	}
	if !strings.Contains(secOpts, "name=userns") {
		b.add("no-userns", model.CatPractices, model.SevMedium, "2.10",
			"User-namespace remapping is off",
			"Root inside a container is root on the host. With userns-remap it maps to an unprivileged host user.",
			"Add `\"userns-remap\": \"default\"` to /etc/docker/daemon.json and restart Docker (test first: volume permissions change).", "")
	}
	if !strings.Contains(secOpts, "name=seccomp") {
		b.add("no-seccomp", model.CatConfig, model.SevHigh, "5.22",
			"Seccomp is not available to the engine",
			"Containers run without the default syscall filter.",
			"Use a kernel with CONFIG_SECCOMP and a Docker build with seccomp support.", "")
	}
	if !strings.Contains(secOpts, "name=apparmor") && !strings.Contains(secOpts, "name=selinux") {
		b.add("no-lsm", model.CatPractices, model.SevLow, "5.2",
			"No AppArmor/SELinux confinement",
			"No mandatory access-control profile protects containers on this host.",
			"Install and enable AppArmor (Debian/Ubuntu/Raspberry Pi OS: `apt install apparmor`).", "")
	}
	if !strings.Contains(secOpts, "rootless") && !info.LiveRestoreEnabled {
		b.add("no-live-restore", model.CatPractices, model.SevLow, "2.15",
			"Live restore is disabled",
			"Restarting or upgrading the Docker daemon stops every container.",
			"Add `\"live-restore\": true` to daemon.json.", "")
	}
	if bridge != nil {
		if v, ok := bridge.Options["com.docker.network.bridge.enable_icc"]; !ok || v == "true" {
			b.add("icc-enabled", model.CatPractices, model.SevMedium, "2.2",
				"Containers on the default bridge can talk to each other",
				"Inter-container communication on docker0 is unrestricted, so one compromised container can probe the rest.",
				"Set `\"icc\": false` in daemon.json and give each compose stack its own network.", "")
		}
	}
	if info.LoggingDriver == "json-file" && (dj == nil || dj.LogOpts["max-size"] == "") {
		b.add("daemon-log-rotation", model.CatPractices, model.SevMedium, "",
			"No default log rotation",
			"Every container without its own logging options can fill the disk.",
			"Add `\"log-opts\": {\"max-size\": \"10m\", \"max-file\": \"3\"}` to daemon.json (applies to new containers).", "logging driver: json-file")
	}
	if dj != nil && !dj.NoNewPrivileges {
		b.add("daemon-no-new-privs", model.CatPractices, model.SevLow, "2.18",
			"`no-new-privileges` not enforced daemon-wide", "", "Add `\"no-new-privileges\": true` to daemon.json.", "")
	}
	if maj := majorOf(info.ServerVersion); maj > 0 && maj < minEngineMajor {
		b.add("old-engine", model.CatOutdated, model.SevHigh, "1.1.2",
			"Docker Engine "+info.ServerVersion+" is out of support",
			"Old engine releases no longer get security fixes (runc/containerd escapes such as Leaky Vessels were fixed in newer versions).",
			"Upgrade Docker Engine from the official repository: https://docs.docker.com/engine/install/", "engine "+info.ServerVersion)
	}
	if df != nil {
		var reclaim int64
		var dangling int
		for _, im := range df.Images {
			if im.Containers == 0 {
				reclaim += im.Size - im.SharedSize
				if len(im.RepoTags) == 0 || (len(im.RepoTags) == 1 && im.RepoTags[0] == "<none>:<none>") {
					dangling++
				}
			}
		}
		var orphan int
		for _, v := range df.Volumes {
			if v.UsageData.RefCount == 0 {
				orphan++
			}
		}
		var cache int64
		for _, bc := range df.BuildCache {
			if !bc.InUse {
				cache += bc.Size
			}
		}
		if total := reclaim + cache; total > 2<<30 {
			sev := model.SevLow
			if total > 10<<30 {
				sev = model.SevMedium
			}
			b.add("disk-reclaimable", model.CatErrors, sev, "",
				"Unused images and build cache use "+humanBytes(total),
				fmt.Sprintf("%d dangling images, %d unused volumes. Disk-full is the most common cause of Docker outages on small hosts.", dangling, orphan),
				"Review, then run `docker image prune -a` and `docker builder prune`. Prune volumes only after confirming they hold no data.", humanBytes(total)+" reclaimable")
		}
	}
	_ = ver
	return b.out
}

func majorOf(v string) int {
	maj, _, _ := strings.Cut(v, ".")
	n, _ := strconv.Atoi(maj)
	return n
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
