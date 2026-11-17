// Package engine orchestrates scans, the Docker event watcher, background
// CVE scans and notifications.
package engine

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/keelwatch/keelwatch/internal/docker"
	"github.com/keelwatch/keelwatch/internal/model"
	"github.com/keelwatch/keelwatch/internal/notify"
	"github.com/keelwatch/keelwatch/internal/registry"
	"github.com/keelwatch/keelwatch/internal/scan"
	"github.com/keelwatch/keelwatch/internal/store"
)

type Config struct {
	ScanInterval   time.Duration
	RegistryTTL    time.Duration
	CVETTL         time.Duration
	ComposeDirs    []string
	DaemonJSONPath string
	CheckUpdates   bool
	NotifyMinSev   model.Severity
	BaseURL        string
	// AfterCommit runs (in its own goroutine) after each saved scan; agent mode pushes to the hub here.
	AfterCommit func(context.Context)
}

type Engine struct {
	cfg    Config
	dc     *docker.Client
	reg    registry.Checker
	cve    scan.CVEScanner
	st     *store.Store
	notif  *notify.Notifier
	log    *slog.Logger
	now    func() time.Time
	mu     sync.Mutex
	busy   bool
	trig   chan struct{}
	cveQ   chan cveJob
	queued sync.Map // image id -> bool

	hmu        sync.RWMutex
	healthCmds map[string]string
	lastAlert  map[string]time.Time
}

type cveJob struct{ ref, id string }

func New(cfg Config, dc *docker.Client, reg registry.Checker, cve scan.CVEScanner, st *store.Store, n *notify.Notifier, log *slog.Logger) *Engine {
	if cfg.ScanInterval == 0 {
		cfg.ScanInterval = 30 * time.Minute
	}
	if cfg.RegistryTTL == 0 {
		cfg.RegistryTTL = 6 * time.Hour
	}
	if cfg.CVETTL == 0 {
		cfg.CVETTL = 24 * time.Hour
	}
	if cfg.NotifyMinSev == "" {
		cfg.NotifyMinSev = model.SevHigh
	}
	return &Engine{cfg: cfg, dc: dc, reg: reg, cve: cve, st: st, notif: n, log: log, now: func() time.Time { return time.Now().UTC() },
		trig: make(chan struct{}, 1), cveQ: make(chan cveJob, 256), healthCmds: map[string]string{}, lastAlert: map[string]time.Time{}}
}

// SetAfterCommit installs the post-scan hook (agent mode). Call before Run.
func (e *Engine) SetAfterCommit(fn func(context.Context)) { e.cfg.AfterCommit = fn }

func (e *Engine) Busy() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.busy
}

func (e *Engine) CVEEnabled() bool { return e.cve != nil && e.cve.Available() }

// Trigger requests a scan soon (coalesced).
func (e *Engine) Trigger() {
	select {
	case e.trig <- struct{}{}:
	default:
	}
}

// Run starts the scheduler, event watcher and CVE worker. Blocks until ctx ends.
func (e *Engine) Run(ctx context.Context) {
	go e.watchEvents(ctx)
	if e.CVEEnabled() {
		go e.cveWorker(ctx)
	}
	e.ScanNow(ctx)
	t := time.NewTicker(e.cfg.ScanInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			e.ScanNow(ctx)
		case <-e.trig:
			// debounce bursts of events (compose up starts many containers)
			select {
			case <-time.After(15 * time.Second):
			case <-ctx.Done():
				return
			}
			e.ScanNow(ctx)
		}
	}
}

func (e *Engine) ScanNow(ctx context.Context) {
	e.mu.Lock()
	if e.busy {
		e.mu.Unlock()
		return
	}
	e.busy = true
	e.mu.Unlock()
	defer func() { e.mu.Lock(); e.busy = false; e.mu.Unlock() }()
	start := time.Now()
	snap, err := e.scan(ctx)
	if err != nil {
		e.log.Error("scan failed", "err", err)
		return
	}
	snap.DurationMs = time.Since(start).Milliseconds()
	e.commit(ctx, snap)
	e.log.Info("scan complete", "score", snap.Score, "findings", len(snap.Findings), "containers", len(snap.Containers), "ms", snap.DurationMs)
}

// ScanOnce runs a single synchronous scan (used by the CLI `scan` command).
func (e *Engine) ScanOnce(ctx context.Context) (*model.Snapshot, error) {
	start := time.Now()
	snap, err := e.scan(ctx)
	if err != nil {
		return nil, err
	}
	// Run queued CVE scans inline so the one-shot report includes them.
	if e.CVEEnabled() {
		for len(e.cveQ) > 0 {
			j := <-e.cveQ
			res := e.cve.Scan(ctx, j.ref, j.id)
			_ = e.st.Update(func(s *store.State) { s.ImageScans[j.id] = res })
			e.queued.Delete(j.id)
		}
		if snap, err = e.scan(ctx); err != nil {
			return nil, err
		}
	}
	snap.DurationMs = time.Since(start).Milliseconds()
	e.commit(ctx, snap)
	return snap, nil
}

type inspected struct {
	c   docker.ContainerJSON
	img *docker.ImageInspect
}

func (e *Engine) scan(ctx context.Context) (*model.Snapshot, error) {
	now := e.now()
	snap := &model.Snapshot{ScannedAt: now}
	info, err := e.dc.Info(ctx)
	if err != nil {
		return nil, fmt.Errorf("cannot reach Docker: %w", err)
	}
	ver, err := e.dc.Version(ctx)
	if err != nil {
		snap.Errors = append(snap.Errors, "version: "+err.Error())
	}
	var bridge *docker.Network
	if n, err := e.dc.Network(ctx, "bridge"); err == nil {
		bridge = &n
	}
	var df *docker.DiskUsage
	if d, err := e.dc.DiskUsage(ctx); err == nil {
		df = &d
	} else {
		snap.Errors = append(snap.Errors, "disk usage: "+err.Error())
	}
	dj, err := scan.ReadDaemonJSON(e.cfg.DaemonJSONPath)
	if err != nil {
		snap.Errors = append(snap.Errors, err.Error())
	}
	list, err := e.dc.Containers(ctx)
	if err != nil {
		return nil, fmt.Errorf("list containers: %w", err)
	}
	images, err := e.dc.Images(ctx)
	if err != nil {
		snap.Errors = append(snap.Errors, "list images: "+err.Error())
	}

	// Inspect containers and the images they use.
	imgCache := map[string]*docker.ImageInspect{}
	var imu sync.Mutex
	getImg := func(id string) *docker.ImageInspect {
		imu.Lock()
		if im, ok := imgCache[id]; ok {
			imu.Unlock()
			return im
		}
		imu.Unlock()
		im, err := e.dc.InspectImage(ctx, id)
		imu.Lock()
		defer imu.Unlock()
		if err != nil {
			imgCache[id] = nil
			return nil
		}
		imgCache[id] = &im
		return &im
	}
	ins := make([]inspected, len(list))
	parallel(len(list), 4, func(i int) {
		c, err := e.dc.InspectContainer(ctx, list[i].ID)
		if err != nil {
			return
		}
		ins[i] = inspected{c: c, img: getImg(c.Image)}
	})
	var all []inspected
	for _, x := range ins {
		if x.c.ID != "" {
			all = append(all, x)
		}
	}

	var findings []model.Finding
	findings = append(findings, scan.HostRules(info, ver, bridge, df, dj)...)
	findings = append(findings, scan.ComposeRules(e.cfg.ComposeDirs)...)

	health := map[string]string{}
	for _, x := range all {
		findings = append(findings, scan.ContainerRules(x.c, x.img)...)
		if hc := scan.HealthCmd(x.c); hc != "" {
			health[x.c.DisplayName()] = hc
		}
	}
	e.hmu.Lock()
	e.healthCmds = health
	e.hmu.Unlock()

	// Runtime: processes + resources of running containers.
	type rt struct {
		f    []model.Finding
		seen map[string]bool
		cpu  float64
		mem  float64
	}
	rts := make([]rt, len(all))
	var baselines map[string]store.Baseline
	e.st.View(func(s *store.State) {
		baselines = map[string]store.Baseline{}
		for k, v := range s.Baselines {
			cp := store.Baseline{Image: v.Image, Scans: v.Scans, Processes: map[string]bool{}}
			for p := range v.Processes {
				cp.Processes[p] = true
			}
			baselines[k] = cp
		}
	})
	parallel(len(all), 4, func(i int) {
		c := all[i].c
		if !c.State.Running {
			return
		}
		name := c.DisplayName()
		if top, err := e.dc.Top(ctx, c.ID); err == nil {
			bl, ok := baselines[name]
			learning := !ok || bl.Image != c.Image || bl.Scans < scan.LearningScans
			var base map[string]bool
			if ok && bl.Image == c.Image {
				base = bl.Processes
			}
			f, seen := scan.ProcessRules(c, top.Commands(), base, learning)
			rts[i].f, rts[i].seen = append(rts[i].f, f...), seen
		}
		if s, err := e.dc.Stats(ctx, c.ID); err == nil {
			rts[i].cpu, rts[i].mem = s.CPUPercent(), s.MemPercent()
			rts[i].f = append(rts[i].f, scan.ResourceRules(c, s)...)
		}
	})
	for _, r := range rts {
		findings = append(findings, r.f...)
	}

	// Outdated images: registry checks (cached) + CVE results (cached).
	imgByID := map[string]docker.ImageSummary{}
	for _, im := range images {
		imgByID[im.ID] = im
	}
	type refKey struct{ ref, id string }
	var refs []refKey
	seenRef := map[refKey]bool{}
	for _, x := range all {
		k := refKey{x.c.Config.Image, x.c.Image}
		if !seenRef[k] {
			seenRef[k] = true
			refs = append(refs, k)
		}
	}
	updates := map[string]*model.UpdateStatus{}
	var scans map[string]*model.ImageScan
	e.st.View(func(s *store.State) {
		for k, v := range s.Updates {
			cp := *v
			updates[k] = &cp
		}
		scans = map[string]*model.ImageScan{}
		for k, v := range s.ImageScans {
			scans[k] = v
		}
	})
	if e.cfg.CheckUpdates && e.reg != nil {
		var umu sync.Mutex
		parallel(len(refs), 4, func(i int) {
			r := refs[i]
			umu.Lock()
			cur := updates[r.ref]
			umu.Unlock()
			if cur != nil && now.Sub(cur.CheckedAt) < e.cfg.RegistryTTL {
				return
			}
			st := e.reg.Check(ctx, r.ref, imgByID[r.id].RepoDigests)
			umu.Lock()
			updates[r.ref] = st
			umu.Unlock()
		})
	}
	for _, r := range refs {
		var created time.Time
		if im, ok := imgByID[r.id]; ok {
			created = time.Unix(im.Created, 0).UTC()
		}
		findings = append(findings, scan.UpdateRules(r.ref, r.id, updates[r.ref], created, now)...)
		if s := scans[r.id]; s != nil {
			findings = append(findings, scan.ImageScanRules(s)...)
		}
		if e.CVEEnabled() {
			if s := scans[r.id]; s == nil || now.Sub(s.ScannedAt) > e.cfg.CVETTL {
				e.enqueueCVE(r.ref, r.id)
			}
		}
	}

	// Unacknowledged runtime alerts from the last 24h count against posture.
	e.st.View(func(s *store.State) {
		for _, a := range s.Alerts {
			if a.Acked || now.Sub(a.Time) > 24*time.Hour || a.Severity.Rank() < model.SevMedium.Rank() {
				continue
			}
			tt, target := model.TargetContainer, a.Container
			cid := ""
			for _, x := range all {
				if x.c.DisplayName() == a.Container {
					cid = x.c.ID
				}
			}
			if cid == "" {
				tt, target = model.TargetHost, "host:"+orHost(info.Name)
				if a.Container != "" {
					target = a.Container
				}
			}
			findings = append(findings, model.Finding{
				ID: model.MakeID("alert", a.ID, ""), Rule: "runtime-alert", Category: model.CatRuntime, Severity: a.Severity,
				Title: "Unreviewed alert: " + a.Title, Detail: a.Detail + " (" + a.Source + ", " + a.Time.Format(time.RFC3339) + ")",
				Remediation: "Review it on the Runtime page and acknowledge it once explained.",
				TargetType:  tt, Target: target, TargetID: cid,
			})
		}
	})

	// Views.
	for i, x := range all {
		c := x.c
		v := model.ContainerView{ID: c.ID, Name: c.DisplayName(), Image: c.Config.Image, ImageID: c.Image, State: c.State.Status,
			Restarts: c.RestartCount, CPU: round1(rts[i].cpu), Mem: round1(rts[i].mem)}
		if c.State.Health != nil {
			v.Health = c.State.Health.Status
		}
		for port, bs := range c.HostConfig.PortBindings {
			for _, b := range bs {
				ip := b.HostIP
				if ip == "" {
					ip = "0.0.0.0"
				}
				v.Ports = append(v.Ports, ip+":"+b.HostPort+"→"+port)
			}
		}
		sort.Strings(v.Ports)
		v.NetworkMode = c.HostConfig.NetworkMode
		for n := range c.NetworkSettings.Networks {
			v.Networks = append(v.Networks, n)
		}
		sort.Strings(v.Networks)
		for _, m := range c.Mounts {
			if strings.HasSuffix(m.Source, "docker.sock") || strings.HasSuffix(m.Destination, "docker.sock") {
				v.DockerSocket = true
			}
		}
		snap.Containers = append(snap.Containers, v)
	}
	if nets, err := e.dc.Networks(ctx); err == nil {
		for _, n := range nets {
			snap.Networks = append(snap.Networks, model.NetworkView{Name: n.Name, Driver: n.Driver, Internal: n.Internal})
		}
		sort.Slice(snap.Networks, func(i, j int) bool { return snap.Networks[i].Name < snap.Networks[j].Name })
	} else {
		snap.Errors = append(snap.Errors, "list networks: "+err.Error())
	}
	used := map[string][]string{}
	refOf := map[string]string{}
	for _, x := range all {
		used[x.c.Image] = append(used[x.c.Image], x.c.DisplayName())
		refOf[x.c.Image] = x.c.Config.Image
	}
	var reclaim, total int64
	for _, im := range images {
		total += im.Size
		iv := model.ImageView{ID: im.ID, Tags: im.RepoTags, Created: time.Unix(im.Created, 0).UTC(), Size: im.Size, InUseBy: used[im.ID]}
		iv.Ref = refOf[im.ID]
		if iv.Ref == "" && len(im.RepoTags) > 0 {
			iv.Ref = im.RepoTags[0]
		}
		iv.Dangling = len(im.RepoTags) == 0 || im.RepoTags[0] == "<none>:<none>"
		if iv.Ref != "" {
			iv.Update = updates[iv.Ref]
		}
		iv.Scan = scans[im.ID]
		if ii := imgCache[im.ID]; ii != nil {
			u := ii.Config.User
			iv.RunsAsRoot = u == "" || u == "0" || u == "root"
		}
		if len(iv.InUseBy) == 0 {
			reclaim += im.Size
		}
		snap.Images = append(snap.Images, iv)
	}
	sort.SliceStable(snap.Images, func(i, j int) bool {
		if (len(snap.Images[i].InUseBy) > 0) != (len(snap.Images[j].InUseBy) > 0) {
			return len(snap.Images[i].InUseBy) > 0
		}
		return snap.Images[i].Ref < snap.Images[j].Ref
	})
	snap.Host = model.HostView{Name: info.Name, EngineVersion: info.ServerVersion, APIVersion: ver.APIVersion, OS: info.OperatingSystem,
		Kernel: info.KernelVersion, Arch: info.Architecture, CPUs: info.NCPU, MemTotal: info.MemTotal, Containers: info.Containers,
		Running: info.ContainersRunning, Images: info.Images, StorageDriver: info.Driver, SecurityOpts: info.SecurityOptions,
		Reclaimable: reclaim, ImagesSize: total}

	// Persist caches and baselines.
	err = e.st.Update(func(s *store.State) {
		for k, v := range updates {
			s.Updates[k] = v
		}
		for i, x := range all {
			if rts[i].seen == nil {
				continue
			}
			name := x.c.DisplayName()
			bl := s.Baselines[name]
			if bl == nil || bl.Image != x.c.Image {
				bl = &store.Baseline{Image: x.c.Image, Processes: map[string]bool{}}
				s.Baselines[name] = bl
			}
			if bl.Scans < scan.LearningScans {
				for p := range rts[i].seen {
					bl.Processes[p] = true
				}
			}
			bl.Scans++
		}
	})
	if err != nil {
		snap.Errors = append(snap.Errors, "store: "+err.Error())
	}
	snap.Findings = dedupe(findings)
	return snap, nil
}

// commit merges first-seen/suppression state, scores, notifies and saves.
func (e *Engine) commit(ctx context.Context, snap *model.Snapshot) {
	var toNotify []model.Finding
	_ = e.st.Update(func(s *store.State) {
		live := map[string]bool{}
		for i := range snap.Findings {
			f := &snap.Findings[i]
			live[f.ID] = true
			if t, ok := s.FirstSeen[f.ID]; ok {
				f.FirstSeen = t
			} else {
				f.FirstSeen = snap.ScannedAt
				s.FirstSeen[f.ID] = snap.ScannedAt
			}
			f.LastSeen = snap.ScannedAt
			if _, ok := s.Suppressed[f.ID]; ok {
				f.Suppressed = true
			}
			if !f.Suppressed && f.Severity.Rank() >= e.cfg.NotifyMinSev.Rank() && f.Rule != "runtime-alert" {
				if _, done := s.NotifiedIDs[f.ID]; !done {
					toNotify = append(toNotify, *f)
					s.NotifiedIDs[f.ID] = snap.ScannedAt
				}
			}
		}
		for id := range s.FirstSeen {
			if !live[id] {
				delete(s.FirstSeen, id)
				delete(s.NotifiedIDs, id) // re-notify if it comes back
			}
		}
		scan.Score(snap)
		counts := map[model.Severity]int{}
		for _, f := range snap.Findings {
			if !f.Suppressed {
				counts[f.Severity]++
			}
		}
		s.History = append(s.History, model.HistoryPoint{Time: snap.ScannedAt, Score: snap.Score, Counts: counts,
			Overdue: snap.Debt.Overdue, DebtDays: snap.Debt.DebtDays})
		s.Snapshot = snap
	})
	if len(toNotify) > 0 && e.notif != nil && e.notif.Enabled() {
		go e.sendFindings(ctx, snap, toNotify)
	}
	if e.cfg.AfterCommit != nil {
		go e.cfg.AfterCommit(ctx)
	}
}

func (e *Engine) sendFindings(ctx context.Context, snap *model.Snapshot, fs []model.Finding) {
	scan.SortFindings(fs)
	var b strings.Builder
	max := 8
	for i, f := range fs {
		if i == max {
			fmt.Fprintf(&b, "…and %d more\n", len(fs)-max)
			break
		}
		fmt.Fprintf(&b, "• [%s] %s — %s\n", strings.ToUpper(string(f.Severity)), f.Title, f.Target)
	}
	title := fmt.Sprintf("Keelwatch [%s]: %d new issue(s), score %d (%s)", orHost(snap.Host.Name), len(fs), snap.Score, snap.Grade)
	if err := e.notif.Send(ctx, notify.Message{Title: title, Body: b.String(), Severity: string(fs[0].Severity), URL: e.cfg.BaseURL}); err != nil {
		e.log.Warn("notify failed", "err", err)
	}
}

// AddAlert stores a runtime alert (deduplicated) and notifies if severe.
func (e *Engine) AddAlert(ctx context.Context, a model.Alert) {
	key := a.Container + "|" + a.Title
	e.hmu.Lock()
	if t, ok := e.lastAlert[key]; ok && time.Since(t) < 10*time.Minute {
		e.hmu.Unlock()
		return
	}
	e.lastAlert[key] = time.Now()
	e.hmu.Unlock()
	_ = e.st.Update(func(s *store.State) { s.Alerts = append(s.Alerts, a) })
	if a.Severity.Rank() >= e.cfg.NotifyMinSev.Rank() && e.notif != nil && e.notif.Enabled() {
		go func() {
			msg := notify.Message{Title: "Keelwatch runtime alert: " + a.Title, Body: a.Detail + "\nContainer: " + a.Container + "\nSource: " + a.Source,
				Severity: string(a.Severity), URL: e.cfg.BaseURL}
			if err := e.notif.Send(ctx, msg); err != nil {
				e.log.Warn("notify failed", "err", err)
			}
		}()
	}
}

func (e *Engine) watchEvents(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		err := e.dc.Events(ctx, func(ev docker.Event) {
			backoff = time.Second
			e.hmu.RLock()
			hc := e.healthCmds
			e.hmu.RUnlock()
			if a := scan.EventAlert(ev, hc); a != nil {
				e.AddAlert(ctx, *a)
			}
			act, _, _ := strings.Cut(ev.Action, ":")
			switch act {
			case "start", "die", "destroy", "oom", "health_status", "create":
				e.Trigger()
			}
		})
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			e.log.Warn("event stream ended", "err", err)
		}
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return
		}
		if backoff < time.Minute {
			backoff *= 2
		}
	}
}

func (e *Engine) enqueueCVE(ref, id string) {
	if _, loaded := e.queued.LoadOrStore(id, true); loaded {
		return
	}
	select {
	case e.cveQ <- cveJob{ref, id}:
	default:
		e.queued.Delete(id)
	}
}

func (e *Engine) cveWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case j := <-e.cveQ:
			e.log.Info("CVE scan", "image", j.ref)
			res := e.cve.Scan(ctx, j.ref, j.id)
			if res.Error != "" {
				e.log.Warn("CVE scan failed", "image", j.ref, "err", res.Error)
			}
			_ = e.st.Update(func(s *store.State) { s.ImageScans[j.id] = res })
			e.queued.Delete(j.id)
			if len(e.cveQ) == 0 {
				e.Trigger()
			}
		}
	}
}

func dedupe(fs []model.Finding) []model.Finding {
	seen := map[string]bool{}
	out := fs[:0]
	for _, f := range fs {
		if seen[f.ID] {
			continue
		}
		seen[f.ID] = true
		out = append(out, f)
	}
	return out
}

func parallel(n, workers int, fn func(i int)) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, workers)
	for i := 0; i < n; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			fn(i)
		}(i)
	}
	wg.Wait()
}

func round1(f float64) float64 { return float64(int(f*10+0.5)) / 10 }

func orHost(s string) string {
	if s == "" {
		return "docker"
	}
	return s
}
