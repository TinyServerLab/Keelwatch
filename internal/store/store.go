// Package store persists Keelwatch state as a single JSON file with atomic
// writes. Small, dependency-free and easy to back up.
package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/keelwatch/keelwatch/internal/model"
)

const (
	maxHistory = 720 // ~15 days at 30 min
	maxAlerts  = 1000
)

type State struct {
	Snapshot    *model.Snapshot                `json:"snapshot,omitempty"`
	History     []model.HistoryPoint           `json:"history"`
	Alerts      []model.Alert                  `json:"alerts"`
	FirstSeen   map[string]time.Time           `json:"firstSeen"`
	Suppressed  map[string]string              `json:"suppressed"` // id -> note
	Baselines   map[string]*Baseline           `json:"baselines"`  // container name -> processes
	Updates     map[string]*model.UpdateStatus `json:"updates"`    // image ref -> status
	ImageScans  map[string]*model.ImageScan    `json:"imageScans"` // image id -> CVE scan
	AuthSecret  string                         `json:"authSecret,omitempty"`
	PassHash    string                         `json:"passHash,omitempty"`
	PassSalt    string                         `json:"passSalt,omitempty"`
	CreatedAt   time.Time                      `json:"createdAt"`
	SchemaVer   int                            `json:"schemaVersion"`
	NotifiedIDs map[string]time.Time           `json:"notifiedIds"`
	Agent       *AgentInfo                     `json:"agent,omitempty"` // set on the hub for a remote host
	// RemovedHosts (hub only): agents removed in the UI; their reports are refused until restored.
	RemovedHosts map[string]time.Time `json:"removedHosts,omitempty"`
}

// AgentInfo describes the last report a hub received from a remote agent.
type AgentInfo struct {
	ReceivedAt  time.Time `json:"receivedAt"`
	IntervalSec int       `json:"intervalSec"`
	Version     string    `json:"version"`
	CVEEnabled  bool      `json:"cveEnabled"`
}

type Baseline struct {
	Image     string          `json:"image"`
	Processes map[string]bool `json:"processes"`
	Scans     int             `json:"scans"`
}

type Store struct {
	mu   sync.RWMutex
	path string
	st   State
}

func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Store{path: filepath.Join(dir, "keelwatch.json")}
	b, err := os.ReadFile(s.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		s.st.CreatedAt = time.Now().UTC()
	case err != nil:
		return nil, err
	default:
		if err := json.Unmarshal(b, &s.st); err != nil {
			return nil, err
		}
	}
	s.st.init()
	return s, nil
}

func (st *State) init() {
	st.SchemaVer = 1
	if st.RemovedHosts == nil {
		st.RemovedHosts = map[string]time.Time{}
	}
	if st.FirstSeen == nil {
		st.FirstSeen = map[string]time.Time{}
	}
	if st.Suppressed == nil {
		st.Suppressed = map[string]string{}
	}
	if st.Baselines == nil {
		st.Baselines = map[string]*Baseline{}
	}
	if st.Updates == nil {
		st.Updates = map[string]*model.UpdateStatus{}
	}
	if st.ImageScans == nil {
		st.ImageScans = map[string]*model.ImageScan{}
	}
	if st.NotifiedIDs == nil {
		st.NotifiedIDs = map[string]time.Time{}
	}
}

// Reset wipes all state (used when a remote host is removed) and saves.
func (s *Store) Reset() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.st = State{CreatedAt: time.Now().UTC()}
	s.st.init()
	return s.saveLocked()
}

// Update runs fn with exclusive access and saves the result.
func (s *Store) Update(fn func(*State)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.st)
	if len(s.st.History) > maxHistory {
		s.st.History = s.st.History[len(s.st.History)-maxHistory:]
	}
	if len(s.st.Alerts) > maxAlerts {
		sort.Slice(s.st.Alerts, func(i, j int) bool { return s.st.Alerts[i].Time.After(s.st.Alerts[j].Time) })
		s.st.Alerts = s.st.Alerts[:maxAlerts]
	}
	return s.saveLocked()
}

// View runs fn with shared access. fn must not retain pointers.
func (s *Store) View(fn func(*State)) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	fn(&s.st)
}

func (s *Store) saveLocked() error {
	b, err := json.Marshal(&s.st)
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
