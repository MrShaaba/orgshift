package snapshot

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/MrShaaba/orgshift/internal/policy"
)

var accountIDRe = regexp.MustCompile(`^\d{12}$`)

// Validate checks referential integrity and the structure of every policy
// document. It is deliberately strict so that hand-edited snapshots fail
// early with a precise message instead of surfacing as an unevaluable
// policy or a wrong verdict later.
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
		if a.JoinedAt != "" {
			if _, err := time.Parse(time.RFC3339, a.JoinedAt); err != nil {
				fail("account %s (%s): joined_at %q is not an RFC 3339 timestamp", a.ID, a.Name, a.JoinedAt)
			}
		}
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
			if len(p.Document) == 0 || !json.Valid(p.Document) {
				fail("policy %s (%s): document is not valid JSON", p.ID, p.Name)
			} else if err := ValidatePolicyDocument(p.Type, p.Document); err != nil {
				fail("policy %s (%s): %v", p.ID, p.Name, err)
			}
		default:
			fail("policy %s (%s): unknown type %q", p.ID, p.Name, p.Type)
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
	s.validateControlTower(seen, fail)
	s.validateIdentityCenter(seen, fail)
	s.validateWorkloads(seen, fail)
	s.validateCoverage(seen, fail)
	// Cycles: every OU must reach the root.
	ix := s.Index()
	for _, ou := range s.OUs {
		if ix.PathTo(ou.ID) == nil {
			fail("ou %s (%s) does not reach the root", ou.ID, ou.Name)
		}
	}
	return errors.Join(errs...)
}

// ValidatePolicyDocument checks that a document has the structure its policy
// type requires, so that malformed input is reported with the statement and
// element at fault. SCPs and RCPs must parse as IAM policy documents; an RCP
// statement must carry Principal "*" and an SCP statement none; tag and
// backup policies must be objects with their top-level map.
func ValidatePolicyDocument(t PolicyType, doc json.RawMessage) error {
	switch t {
	case PolicyTypeSCP, PolicyTypeRCP:
		d, err := policy.Parse(doc)
		if err != nil {
			return err
		}
		for i := range d.Statements {
			st := &d.Statements[i]
			switch t {
			case PolicyTypeSCP:
				if st.Principals != nil || st.NotPrincipals != nil {
					return fmt.Errorf("%s: service control policies cannot carry a Principal or NotPrincipal element", st.Label())
				}
			case PolicyTypeRCP:
				if st.NotPrincipals != nil {
					return fmt.Errorf("%s: resource control policies do not support NotPrincipal", st.Label())
				}
				if st.Principals == nil {
					return fmt.Errorf("%s: resource control policies require a Principal element", st.Label())
				}
				if !st.Principals.All {
					return fmt.Errorf("%s: the Principal of a resource control policy must be \"*\"", st.Label())
				}
			}
		}
	case PolicyTypeTag:
		var d struct {
			Tags map[string]json.RawMessage `json:"tags"`
		}
		if err := json.Unmarshal(doc, &d); err != nil {
			return fmt.Errorf("tag policy must be an object with a tags map: %v", err)
		}
		if d.Tags == nil {
			return fmt.Errorf("tag policy has no tags element")
		}
		for k, v := range d.Tags {
			var spec map[string]json.RawMessage
			if err := json.Unmarshal(v, &spec); err != nil {
				return fmt.Errorf("tag policy: tags.%s must be an object: %v", k, err)
			}
		}
	case PolicyTypeBackup:
		var d struct {
			Plans map[string]json.RawMessage `json:"plans"`
		}
		if err := json.Unmarshal(doc, &d); err != nil {
			return fmt.Errorf("backup policy must be an object with a plans map: %v", err)
		}
		if d.Plans == nil {
			return fmt.Errorf("backup policy has no plans element")
		}
	}
	return nil
}

// validateControlTower checks that every Control Tower reference points at a
// node of the right kind.
func (s *Snapshot) validateControlTower(seen map[string]string, fail func(string, ...any)) {
	ct := s.ControlTower
	if ct == nil {
		return
	}
	for _, id := range []string{ct.AuditAccountID, ct.LogArchiveAccountID} {
		if id != "" && seen[id] != "account" {
			fail("control_tower: shared account %q is not an account in this snapshot", id)
		}
	}
	switch ct.AutoEnrollment {
	case "", AutoEnrollmentEnabled, AutoEnrollmentDisabled:
	default:
		fail("control_tower: auto_enrollment must be enabled, disabled or empty, got %q", ct.AutoEnrollment)
	}
	registered := map[string]bool{}
	for _, ou := range ct.RegisteredOUs {
		if seen[ou.OUID] != "ou" {
			fail("control_tower.registered_ous: %q is not an ou", ou.OUID)
		}
		if registered[ou.OUID] {
			fail("control_tower.registered_ous: %s is listed twice", ou.OUID)
		}
		registered[ou.OUID] = true
	}
	enrolled := map[string]bool{}
	for _, a := range ct.EnrolledAccounts {
		if seen[a.AccountID] != "account" {
			fail("control_tower.enrolled_accounts: %q is not an account", a.AccountID)
		}
		if enrolled[a.AccountID] {
			fail("control_tower.enrolled_accounts: %s is listed twice", a.AccountID)
		}
		enrolled[a.AccountID] = true
		if a.ParentOUID != "" && seen[a.ParentOUID] != "ou" {
			fail("control_tower.enrolled_accounts: parent_ou_id %q of %s is not an ou", a.ParentOUID, a.AccountID)
		}
		switch a.Source {
		case "", EnrolledFromBaseline, EnrolledManual:
		default:
			fail("control_tower.enrolled_accounts: %s has unknown source %q", a.AccountID, a.Source)
		}
	}
	for _, c := range ct.EnabledControls {
		if c.ControlIdentifier == "" {
			fail("control_tower.enabled_controls: a control on %q has no control_identifier", c.TargetOUID)
		}
		if seen[c.TargetOUID] != "ou" {
			fail("control_tower.enabled_controls: target %q of %s is not an ou", c.TargetOUID, c.ControlIdentifier)
		}
		switch c.Behavior {
		case "", ControlPreventive, ControlDetective, ControlProactive:
		default:
			fail("control_tower.enabled_controls: %s has unknown behavior %q", c.ControlIdentifier, c.Behavior)
		}
	}
}

// validateIdentityCenter checks that permission sets are unique and that
// every assignment points at a known permission set and account.
func (s *Snapshot) validateIdentityCenter(seen map[string]string, fail func(string, ...any)) {
	ic := s.IdentityCenter
	if ic == nil {
		return
	}
	if ic.InstanceARN == "" {
		fail("identity_center: instance_arn is required")
	}
	if ic.OwnerAccountID != "" && seen[ic.OwnerAccountID] != "account" {
		fail("identity_center: owner account %q is not an account in this snapshot", ic.OwnerAccountID)
	}
	arns, names := map[string]bool{}, map[string]bool{}
	for _, ps := range ic.PermissionSets {
		if ps.ARN == "" || ps.Name == "" {
			fail("identity_center.permission_sets: %q needs both arn and name", ps.ARN+ps.Name)
			continue
		}
		if arns[ps.ARN] {
			fail("identity_center.permission_sets: arn %s is listed twice", ps.ARN)
		}
		if names[ps.Name] {
			fail("identity_center.permission_sets: name %s is used twice", ps.Name)
		}
		arns[ps.ARN], names[ps.Name] = true, true
		if len(ps.InlinePolicy) > 0 && !json.Valid(ps.InlinePolicy) {
			fail("identity_center.permission_sets: %s has an inline policy that is not valid JSON", ps.Name)
		}
		for _, id := range ps.ProvisionedAccounts {
			if seen[id] != "account" {
				fail("identity_center.permission_sets: %s is provisioned in %q, which is not an account", ps.Name, id)
			}
		}
	}
	for _, a := range ic.Assignments {
		if seen[a.AccountID] != "account" {
			fail("identity_center.account_assignments: %q is not an account", a.AccountID)
		}
		if !arns[a.PermissionSetARN] {
			fail("identity_center.account_assignments: permission set %q on %s is not in permission_sets", a.PermissionSetARN, a.AccountID)
		}
		switch a.PrincipalType {
		case PrincipalUser, PrincipalGroup:
		default:
			fail("identity_center.account_assignments: principal %q on %s has unknown type %q", a.PrincipalID, a.AccountID, a.PrincipalType)
		}
		if a.PrincipalID == "" {
			fail("identity_center.account_assignments: an assignment on %s has no principal_id", a.AccountID)
		}
	}
}

// validateWorkloads checks the workload inventory: every key is an account
// of the snapshot, stacks are named and unique per Region, resources carry
// an ARN, kept policies are JSON and carry at least one organization
// condition, and StackSet instances point at 12-digit accounts.
func (s *Snapshot) validateWorkloads(seen map[string]string, fail func(string, ...any)) {
	for id, w := range s.Workloads {
		if seen[id] != "account" {
			fail("workloads: %q is not an account in this snapshot", id)
			continue
		}
		if w == nil {
			fail("workloads.%s is null", id)
			continue
		}
		switch w.ResourceSource {
		case "", ResourceSourceTaggingAPI, ResourceSourceResourceExplorer, ResourceSourceManual:
		default:
			fail("workloads.%s: resource_source %q is not tagging-api, resource-explorer or manual", id, w.ResourceSource)
		}
		stacks := map[string]bool{}
		for i, st := range w.Stacks {
			if st.Name == "" || st.Region == "" {
				fail("workloads.%s.stacks[%d]: name and region are required", id, i)
				continue
			}
			key := st.Region + "/" + st.Name
			if stacks[key] {
				fail("workloads.%s.stacks: %s is listed twice in %s", id, st.Name, st.Region)
			}
			stacks[key] = true
			for t, n := range st.ResourceTypes {
				if t == "" || n < 0 {
					fail("workloads.%s stack %s: resource type %q has count %d", id, st.Name, t, n)
				}
			}
			for _, o := range st.Outputs {
				if o.Key == "" {
					fail("workloads.%s stack %s: an output has no key", id, st.Name)
				}
			}
			for _, im := range st.Imports {
				if im.ExportName == "" {
					fail("workloads.%s stack %s: an import has no export_name", id, st.Name)
				}
			}
			for _, ex := range st.ExternalOutputs {
				if ex.StackName == "" || ex.OutputName == "" {
					fail("workloads.%s stack %s: an external output needs stack_name and output_name", id, st.Name)
				}
				if ex.AccountID != "" && !accountIDRe.MatchString(ex.AccountID) {
					fail("workloads.%s stack %s: external output account_id %q is not a 12 digit account id", id, st.Name, ex.AccountID)
				}
			}
			for _, ref := range st.References {
				if ref.Kind == "" || ref.ID == "" {
					fail("workloads.%s stack %s: a reference needs kind and id", id, st.Name)
				}
			}
			if ss := st.StackSet; ss != nil {
				if ss.Evidence != StackSetEvidenceInstance && ss.Evidence != StackSetEvidenceName {
					fail("workloads.%s stack %s: stack_set.evidence %q is not stack-instance or stack-name", id, st.Name, ss.Evidence)
				}
			}
		}
		for i, r := range w.Resources {
			if r.ARN == "" {
				fail("workloads.%s.resources[%d]: arn is required", id, i)
			}
		}
		for i, p := range w.ResourcePolicies {
			switch p.Kind {
			case PolicyKindBucket, PolicyKindRoleTrust, PolicyKindTemplate:
			default:
				fail("workloads.%s.resource_policies[%d]: kind %q is not one of %s, %s, %s", id, i, p.Kind, PolicyKindBucket, PolicyKindRoleTrust, PolicyKindTemplate)
			}
			if p.ResourceARN == "" && p.Resource == "" {
				fail("workloads.%s.resource_policies[%d]: resource_arn or resource is required", id, i)
			}
			if len(p.Document) > 0 {
				if !json.Valid(p.Document) {
					fail("workloads.%s.resource_policies[%d] (%s%s): document is not valid JSON", id, i, p.ResourceARN, p.Resource)
				} else if _, err := policy.Parse(p.Document); err != nil {
					fail("workloads.%s.resource_policies[%d] (%s%s): %v", id, i, p.ResourceARN, p.Resource, err)
				}
			}
			if len(p.Document) == 0 && len(p.Conditions) == 0 {
				fail("workloads.%s.resource_policies[%d] (%s%s): a kept policy needs a document or at least one organization condition", id, i, p.ResourceARN, p.Resource)
			}
			for _, c := range p.Conditions {
				if !IsOrgConditionKey(c.Key) {
					fail("workloads.%s.resource_policies[%d]: condition key %q is not an organization key", id, i, c.Key)
				}
			}
		}
	}
	for _, ss := range s.StackSets {
		for i, inst := range ss.Instances {
			if !accountIDRe.MatchString(inst.AccountID) {
				fail("stack_sets %s: instances[%d].account_id %q is not a 12 digit account id", ss.Name, i, inst.AccountID)
			}
			if inst.Region == "" {
				fail("stack_sets %s: instances[%d] has no region", ss.Name, i)
			}
		}
	}
}
