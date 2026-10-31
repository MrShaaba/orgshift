package web

import (
	"fmt"
	"sync"

	"github.com/MrShaaba/orgshift/internal/fixtures"
	"github.com/MrShaaba/orgshift/internal/snapshot"
)

// Store keeps the snapshots loaded into the UI, in memory only.
type Store struct {
	mu    sync.RWMutex
	snaps map[string]*snapshot.Snapshot
	order []string
}

// NewStore creates an empty store.
func NewStore() *Store { return &Store{snaps: map[string]*snapshot.Snapshot{}} }

// Add stores a snapshot under a name, de-duplicating names. It returns the
// name actually used.
func (s *Store) Add(name string, snap *snapshot.Snapshot) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if name == "" {
		name = snap.Organization.Name
	}
	if name == "" {
		name = snap.Organization.ID
	}
	base, n := name, 2
	for {
		if existing, ok := s.snaps[name]; !ok || existing.Organization.ID == snap.Organization.ID {
			break
		}
		name = fmt.Sprintf("%s (%d)", base, n)
		n++
	}
	if _, ok := s.snaps[name]; !ok {
		s.order = append(s.order, name)
	}
	s.snaps[name] = snap
	return name
}

// Get returns a snapshot by name.
func (s *Store) Get(name string) (*snapshot.Snapshot, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	snap, ok := s.snaps[name]
	return snap, ok
}

// Names lists the loaded snapshot names in load order.
func (s *Store) Names() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]string(nil), s.order...)
}

// LoadFixtures adds the two fixture organizations, source first.
func (s *Store) LoadFixtures() {
	s.Add(fixtures.LarkspurName, fixtures.Larkspur())
	s.Add(fixtures.FernhillName, fixtures.Fernhill())
}
