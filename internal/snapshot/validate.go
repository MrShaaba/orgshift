package snapshot

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
)

var accountIDRe = regexp.MustCompile(`^\d{12}$`)

// Validate checks referential integrity. It is deliberately strict so that
// hand-edited snapshots fail early with a precise message.
func (s *Snapshot) Validate() error {
	var errs []error
	fail := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	if s.SchemaVersion != SchemaVersion {
		fail("schema_version must be %d, got %d", SchemaVersion, s.SchemaVersion)
	}
	if s.Organization.ID == "" {
		fail("organization.id is required")
	}
	if s.Root.ID == "" {
		fail("root.id is required")
	}
	seen := map[string]string{s.Root.ID: "root"}
	for _, ou := range s.OUs {
		if ou.ID == "" {
			fail("organizational unit %q has no id", ou.Name)
			continue
		}
		if k, dup := seen[ou.ID]; dup {
			fail("id %s is used by both a %s and an ou", ou.ID, k)
		}
		seen[ou.ID] = "ou"
	}
	for _, a := range s.Accounts {
		if !accountIDRe.MatchString(a.ID) {
			fail("account %q: id %q is not a 12 digit account id", a.Name, a.ID)
			continue
		}
		if k, dup := seen[a.ID]; dup {
			fail("id %s is used by both a %s and an account", a.ID, k)
		}
		seen[a.ID] = "account"
	}
	for _, ou := range s.OUs {
		if k, ok := seen[ou.ParentID]; !ok || k == "account" {
			fail("ou %s (%s): parent %q is not a root or ou", ou.ID, ou.Name, ou.ParentID)
		}
	}
	for _, a := range s.Accounts {
		if k, ok := seen[a.ParentID]; !ok || k == "account" {
			fail("account %s (%s): parent %q is not a root or ou", a.ID, a.Name, a.ParentID)
		}
	}
	policyIDs := map[string]bool{}
	for _, p := range s.Policies {
		if p.ID == "" {
			fail("policy %q has no id", p.Name)
			continue
		}
		if policyIDs[p.ID] {
			fail("policy id %s is duplicated", p.ID)
		}
		policyIDs[p.ID] = true
		switch p.Type {
		case PolicyTypeSCP, PolicyTypeRCP, PolicyTypeTag, PolicyTypeBackup:
		default:
			fail("policy %s (%s): unknown type %q", p.ID, p.Name, p.Type)
		}
		if len(p.Document) == 0 || !json.Valid(p.Document) {
			fail("policy %s (%s): document is not valid JSON", p.ID, p.Name)
		}
		for _, t := range p.Targets {
			if _, ok := seen[t]; !ok {
				fail("policy %s (%s): target %q does not exist", p.ID, p.Name, t)
			}
		}
	}
	for id := range s.Usage {
		if seen[id] != "account" {
			fail("usage: %q is not an account in this snapshot", id)
		}
	}
	// Cycles: every OU must reach the root.
	ix := s.Index()
	for _, ou := range s.OUs {
		if ix.PathTo(ou.ID) == nil {
			fail("ou %s (%s) does not reach the root", ou.ID, ou.Name)
		}
	}
	return errors.Join(errs...)
}
