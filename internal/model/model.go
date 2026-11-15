// Package model holds the types shared by the scanner, store and API.
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

type Category string

const (
	CatOutdated    Category = "outdated"
	CatCredentials Category = "credentials"
	CatConfig      Category = "config"
	CatPractices   Category = "practices"
	CatErrors      Category = "errors"
	CatRuntime     Category = "runtime"
)

var Categories = []Category{CatOutdated, CatCredentials, CatConfig, CatPractices, CatErrors, CatRuntime}

var CategoryLabels = map[Category]string{
	CatOutdated:    "Outdated images",
	CatCredentials: "Credential leakage",
	CatConfig:      "Configuration flaws",
	CatPractices:   "Best practices",
	CatErrors:      "Critical errors",
	CatRuntime:     "Security breaches",
}

type Severity string

const (
	SevCritical Severity = "critical"
	SevHigh     Severity = "high"
	SevMedium   Severity = "medium"
	SevLow      Severity = "low"
	SevInfo     Severity = "info"
)

// Weight is the penalty a finding contributes to the posture score.
func (s Severity) Weight() float64 {
	switch s {
	case SevCritical:
		return 25
	case SevHigh:
		return 10
	case SevMedium:
		return 4
	case SevLow:
		return 1
	}
	return 0
}

func (s Severity) Rank() int {
	switch s {
	case SevCritical:
		return 4
	case SevHigh:
		return 3
	case SevMedium:
		return 2
	case SevLow:
		return 1
	}
	return 0
}

type TargetType string

const (
	TargetHost      TargetType = "host"
	TargetContainer TargetType = "container"
	TargetImage     TargetType = "image"
	TargetFile      TargetType = "file"
)

type Finding struct {
	ID          string     `json:"id"`
	Rule        string     `json:"rule"`
	Category    Category   `json:"category"`
	Severity    Severity   `json:"severity"`
	Title       string     `json:"title"`
	Detail      string     `json:"detail"`
	Remediation string     `json:"remediation"`
	Evidence    string     `json:"evidence,omitempty"`
	CIS         string     `json:"cis,omitempty"`
	TargetType  TargetType `json:"targetType"`
	Target      string     `json:"target"`             // display name
	TargetID    string     `json:"targetId,omitempty"` // container/image id
	FirstSeen   time.Time  `json:"firstSeen"`
	LastSeen    time.Time  `json:"lastSeen"`
	Suppressed  bool       `json:"suppressed,omitempty"`
}

// MakeID gives a stable identifier so a finding keeps its FirstSeen and
// suppression across scans. Keyed on rule + target name + discriminator.
func MakeID(rule, target, discriminator string) string {
	h := sha256.Sum256([]byte(rule + "\x00" + target + "\x00" + discriminator))
	return hex.EncodeToString(h[:8])
}

// Alert is a point-in-time runtime event (exec into a container, Falco
// rule hit, miner process seen, OOM kill...).
type Alert struct {
	ID        string    `json:"id"`
	Time      time.Time `json:"time"`
	Severity  Severity  `json:"severity"`
	Source    string    `json:"source"` // events | process | falco
	Container string    `json:"container"`
	Title     string    `json:"title"`
	Detail    string    `json:"detail"`
	Acked     bool      `json:"acked"`
}

type CVE struct {
	ID        string   `json:"id"`
	Pkg       string   `json:"pkg"`
	Installed string   `json:"installed"`
	Fixed     string   `json:"fixed,omitempty"`
	Severity  Severity `json:"severity"`
	Title     string   `json:"title,omitempty"`
}

type ImageScan struct {
	ImageID   string         `json:"imageId"`
	Ref       string         `json:"ref"`
	ScannedAt time.Time      `json:"scannedAt"`
	Error     string         `json:"error,omitempty"`
	Counts    map[string]int `json:"counts"`
	Fixable   int            `json:"fixable"`
	CVEs      []CVE          `json:"cves"`    // top N, sorted
	Secrets   []string       `json:"secrets"` // redacted descriptions
}

type UpdateStatus struct {
	Ref        string    `json:"ref"`
	CheckedAt  time.Time `json:"checkedAt"`
	Error      string    `json:"error,omitempty"`
	DigestNew  bool      `json:"digestNew"` // same tag, newer image pushed
	NewestTag  string    `json:"newestTag,omitempty"`
	Bump       string    `json:"bump,omitempty"` // patch|minor|major
	RemoteDigs string    `json:"remoteDigest,omitempty"`
}

type ContainerView struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Image    string            `json:"image"`
	ImageID  string            `json:"imageId"`
	State    string            `json:"state"`
	Health   string            `json:"health,omitempty"`
	Restarts int               `json:"restarts"`
	CPU      float64           `json:"cpu"`
	Mem      float64           `json:"mem"`
	Score    int               `json:"score"`
	Counts   map[Severity]int  `json:"counts"`
	ByCat    map[Category]int  `json:"byCategory"`
	Ports    []string          `json:"ports"`
	Labels   map[string]string `json:"-"`
}

type ImageView struct {
	ID         string        `json:"id"`
	Ref        string        `json:"ref"`
	Tags       []string      `json:"tags"`
	Created    time.Time     `json:"created"`
	Size       int64         `json:"size"`
	InUseBy    []string      `json:"inUseBy"`
	Update     *UpdateStatus `json:"update,omitempty"`
	Scan       *ImageScan    `json:"scan,omitempty"`
	Dangling   bool          `json:"dangling"`
	RunsAsRoot bool          `json:"runsAsRoot"`
}

type HostView struct {
	Name          string   `json:"name"`
	EngineVersion string   `json:"engineVersion"`
	APIVersion    string   `json:"apiVersion"`
	OS            string   `json:"os"`
	Kernel        string   `json:"kernel"`
	Arch          string   `json:"arch"`
	CPUs          int      `json:"cpus"`
	MemTotal      int64    `json:"memTotal"`
	Containers    int      `json:"containers"`
	Running       int      `json:"running"`
	Images        int      `json:"images"`
	StorageDriver string   `json:"storageDriver"`
	SecurityOpts  []string `json:"securityOptions"`
	Reclaimable   int64    `json:"reclaimable"`
	ImagesSize    int64    `json:"imagesSize"`
}

type CategoryScore struct {
	Category Category         `json:"category"`
	Label    string           `json:"label"`
	Score    int              `json:"score"`
	Count    int              `json:"count"`
	Counts   map[Severity]int `json:"counts"`
	Top      string           `json:"top,omitempty"`
}

type HistoryPoint struct {
	Time   time.Time        `json:"time"`
	Score  int              `json:"score"`
	Counts map[Severity]int `json:"counts"`
}

// Snapshot is the result of one full scan.
type Snapshot struct {
	ScannedAt  time.Time       `json:"scannedAt"`
	DurationMs int64           `json:"durationMs"`
	Score      int             `json:"score"`
	Grade      string          `json:"grade"`
	Categories []CategoryScore `json:"categories"`
	Findings   []Finding       `json:"findings"`
	Containers []ContainerView `json:"containers"`
	Images     []ImageView     `json:"images"`
	Host       HostView        `json:"host"`
	Errors     []string        `json:"errors,omitempty"`
}
