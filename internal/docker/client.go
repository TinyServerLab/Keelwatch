// Package docker is a tiny, read-only Docker Engine API client built on the
// standard library. It only issues GET requests, so it works behind a
// read-only docker-socket-proxy.
package docker

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	http *http.Client
	base string // e.g. http://docker
}

// New builds a client from a DOCKER_HOST style address:
// unix:///var/run/docker.sock (default) or tcp://host:2375.
func New(host string) (*Client, error) {
	if host == "" {
		host = "unix:///var/run/docker.sock"
	}
	u, err := url.Parse(host)
	if err != nil {
		return nil, fmt.Errorf("parse docker host: %w", err)
	}
	tr := &http.Transport{MaxIdleConns: 8, IdleConnTimeout: 60 * time.Second}
	base := ""
	switch u.Scheme {
	case "unix":
		path := u.Path
		tr.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", path)
		}
		base = "http://docker"
	case "tcp", "http":
		base = "http://" + u.Host
	case "https":
		base = "https://" + u.Host
	default:
		return nil, fmt.Errorf("unsupported docker host scheme %q", u.Scheme)
	}
	return &Client{http: &http.Client{Transport: tr}, base: base}, nil
}

func (c *Client) get(ctx context.Context, path string, out any) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("docker GET %s: %s: %s", path, resp.Status, strings.TrimSpace(string(b)))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *Client) Info(ctx context.Context) (Info, error) {
	var v Info
	return v, c.get(ctx, "/info", &v)
}

func (c *Client) Version(ctx context.Context) (Version, error) {
	var v Version
	return v, c.get(ctx, "/version", &v)
}

func (c *Client) Containers(ctx context.Context) ([]ContainerSummary, error) {
	var v []ContainerSummary
	return v, c.get(ctx, "/containers/json?all=1", &v)
}

func (c *Client) InspectContainer(ctx context.Context, id string) (ContainerJSON, error) {
	var v ContainerJSON
	return v, c.get(ctx, "/containers/"+url.PathEscape(id)+"/json", &v)
}

func (c *Client) Images(ctx context.Context) ([]ImageSummary, error) {
	var v []ImageSummary
	return v, c.get(ctx, "/images/json", &v)
}

func (c *Client) InspectImage(ctx context.Context, id string) (ImageInspect, error) {
	var v ImageInspect
	return v, c.get(ctx, "/images/"+url.PathEscape(id)+"/json", &v)
}

func (c *Client) Network(ctx context.Context, name string) (Network, error) {
	var v Network
	return v, c.get(ctx, "/networks/"+url.PathEscape(name), &v)
}

func (c *Client) DiskUsage(ctx context.Context) (DiskUsage, error) {
	var v DiskUsage
	return v, c.get(ctx, "/system/df", &v)
}

func (c *Client) Top(ctx context.Context, id string) (Top, error) {
	var v Top
	return v, c.get(ctx, "/containers/"+url.PathEscape(id)+"/top", &v)
}

func (c *Client) Stats(ctx context.Context, id string) (Stats, error) {
	var v Stats
	return v, c.get(ctx, "/containers/"+url.PathEscape(id)+"/stats?stream=false", &v)
}

// Events streams container events until ctx is cancelled. It returns when the
// stream ends; callers should reconnect.
func (c *Client) Events(ctx context.Context, fn func(Event)) error {
	q := url.QueryEscape(`{"type":["container"]}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/events?filters="+q, nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("docker events: %s", resp.Status)
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		var ev Event
		if err := json.Unmarshal(sc.Bytes(), &ev); err == nil {
			fn(ev)
		}
	}
	return sc.Err()
}

// ---- API types (only the fields Keelwatch reads) ----

type Info struct {
	Name               string
	ServerVersion      string
	OperatingSystem    string
	KernelVersion      string
	Architecture       string
	Driver             string
	LoggingDriver      string
	DockerRootDir      string
	SecurityOptions    []string
	LiveRestoreEnabled bool
	NCPU               int
	MemTotal           int64
	Containers         int
	ContainersRunning  int
	Images             int
	Warnings           []string
}

type Version struct {
	Version    string
	APIVersion string `json:"ApiVersion"`
}

type ContainerSummary struct {
	ID      string `json:"Id"`
	Names   []string
	Image   string
	ImageID string
	State   string
	Status  string
}

type ContainerJSON struct {
	ID              string `json:"Id"`
	Name            string
	Image           string
	RestartCount    int
	AppArmorProfile string
	State           struct {
		Status     string
		Running    bool
		Restarting bool
		OOMKilled  bool
		Dead       bool
		ExitCode   int
		Error      string
		StartedAt  string
		FinishedAt string
		Health     *struct {
			Status        string
			FailingStreak int
			Log           []struct {
				ExitCode int
				Output   string
			}
		}
	}
	Config struct {
		User        string
		Env         []string
		Image       string
		Labels      map[string]string
		Healthcheck *struct{ Test []string }
	}
	HostConfig struct {
		Privileged     bool
		CapAdd         []string
		CapDrop        []string
		NetworkMode    string
		PidMode        string
		IpcMode        string
		UsernsMode     string
		ReadonlyRootfs bool
		Memory         int64
		NanoCpus       int64
		CPUQuota       int64 `json:"CpuQuota"`
		PidsLimit      *int64
		SecurityOpt    []string
		Devices        []struct{ PathOnHost, PathInContainer string }
		PortBindings   map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string
		}
		RestartPolicy struct {
			Name              string
			MaximumRetryCount int
		}
		LogConfig struct {
			Type   string
			Config map[string]string
		}
	}
	Mounts []struct {
		Type        string
		Source      string
		Destination string
		RW          bool
	}
}

func (c ContainerJSON) DisplayName() string { return strings.TrimPrefix(c.Name, "/") }

type ImageSummary struct {
	ID          string `json:"Id"`
	RepoTags    []string
	RepoDigests []string
	Created     int64
	Size        int64
	Containers  int64
}

type ImageInspect struct {
	ID           string `json:"Id"`
	RepoTags     []string
	RepoDigests  []string
	Created      string
	Size         int64
	Os           string
	Architecture string
	Config       struct {
		User        string
		Env         []string
		Healthcheck *struct{ Test []string }
		Labels      map[string]string
	}
}

type Network struct {
	Name    string
	Options map[string]string
}

type DiskUsage struct {
	LayersSize int64
	Images     []struct {
		ID         string `json:"Id"`
		Size       int64
		SharedSize int64
		Containers int64
		RepoTags   []string
	}
	Volumes []struct {
		Name      string
		UsageData struct {
			Size     int64
			RefCount int64
		}
	}
	BuildCache []struct {
		Size  int64
		InUse bool
	}
}

type Top struct {
	Titles    []string
	Processes [][]string
}

// Commands returns the command column (CMD/COMMAND) of each process.
func (t Top) Commands() []string {
	col := -1
	for i, ti := range t.Titles {
		if ti == "CMD" || ti == "COMMAND" {
			col = i
		}
	}
	var out []string
	for _, p := range t.Processes {
		if col >= 0 && col < len(p) {
			out = append(out, p[col])
		} else if len(p) > 0 {
			out = append(out, p[len(p)-1])
		}
	}
	return out
}

type Stats struct {
	CPUStats    cpuStats `json:"cpu_stats"`
	PreCPUStats cpuStats `json:"precpu_stats"`
	MemoryStats struct {
		Usage uint64 `json:"usage"`
		Limit uint64 `json:"limit"`
		Stats struct {
			Cache        uint64 `json:"cache"`
			InactiveFile uint64 `json:"inactive_file"`
		} `json:"stats"`
	} `json:"memory_stats"`
}

type cpuStats struct {
	CPUUsage struct {
		TotalUsage uint64 `json:"total_usage"`
	} `json:"cpu_usage"`
	SystemUsage uint64 `json:"system_cpu_usage"`
	OnlineCPUs  uint32 `json:"online_cpus"`
}

// CPUPercent mirrors `docker stats`: 100% == one full core.
func (s Stats) CPUPercent() float64 {
	cpuDelta := float64(s.CPUStats.CPUUsage.TotalUsage) - float64(s.PreCPUStats.CPUUsage.TotalUsage)
	sysDelta := float64(s.CPUStats.SystemUsage) - float64(s.PreCPUStats.SystemUsage)
	n := float64(s.CPUStats.OnlineCPUs)
	if n == 0 {
		n = 1
	}
	if cpuDelta <= 0 || sysDelta <= 0 {
		return 0
	}
	return cpuDelta / sysDelta * n * 100
}

// MemPercent of the container's limit (host RAM when unlimited).
func (s Stats) MemPercent() float64 {
	used := s.MemoryStats.Usage
	if c := s.MemoryStats.Stats.InactiveFile; c > 0 && c < used {
		used -= c
	}
	if s.MemoryStats.Limit == 0 {
		return 0
	}
	return float64(used) / float64(s.MemoryStats.Limit) * 100
}

type Event struct {
	Type   string
	Action string
	Actor  struct {
		ID         string
		Attributes map[string]string
	}
	Time int64 `json:"time"`
}
