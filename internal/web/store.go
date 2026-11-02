package web

import (
	"fmt"
	"sync"

	"github.com/MrShaaba/orgshift/internal/fixtures"
	"github.com/MrShaaba/orgshift/internal/scenario"
	"github.com/MrShaaba/orgshift/internal/snapshot"
)

// Store keeps the snapshots and scenarios loaded into the UI, in memory only.
type Store struct {
	mu    sync.RWMutex
	snaps map[string]*snapshot.Snapshot
	order []string
	// scenarios are the staged migration overlays, by name.
	scenarios     map[string]*scenario.Scenario
	scenarioOrder []string
}

// NewStore creates an empty store.
func NewStore() *Store {
	return &Store{snaps: map[string]*snapshot.Snapshot{}, scenarios: map[string]*scenario.Scenario{}}
}

// AddScenario stores a scenario overlay under its name (or the given one).
func (s *Store) AddScenario(name string, sc *scenario.Scenario) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if name == "" {
		name = sc.Name
	}
	if _, ok := s.scenarios[name]; !ok {
		s.scenarioOrder = append(s.scenarioOrder, name)
	}
	s.scenarios[name] = sc
	return name
}

// Scenario returns a scenario by name.
func (s *Store) Scenario(name string) (*scenario.Scenario, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sc, ok := s.scenarios[name]
	return sc, ok
}

// ScenarioNames lists the loaded scenarios in load order.
func (s *Store) ScenarioNames() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]string(nil), s.scenarioOrder...)
}

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

// LoadFixtures adds the fixture organizations, source first, then the
// partially collected copy of the source, and the two staged scenarios.
func (s *Store) LoadFixtures() {
	s.Add(fixtures.LarkspurName, fixtures.Larkspur())
	s.Add(fixtures.FernhillName, fixtures.Fernhill())
	s.Add(fixtures.LarkspurPartialName, fixtures.LarkspurPartial())
	for _, doc := range []string{fixtures.PaymentsToFernhillStaged, fixtures.SandboxToBusinessUnitsStaged} {
		if sc, err := scenario.Parse([]byte(doc)); err == nil {
			s.AddScenario(sc.Name, sc)
		}
	}
}
