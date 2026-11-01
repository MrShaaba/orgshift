package snapshot

import "strings"

// GuardrailPolicyPrefix is the name prefix AWS Control Tower gives the
// service control policies that implement its preventive controls.
const GuardrailPolicyPrefix = "aws-guardrails-"

// Control behaviors, as reported by the Control Catalog.
const (
	ControlPreventive = "PREVENTIVE"
	ControlDetective  = "DETECTIVE"
	ControlProactive  = "PROACTIVE"
)

// Auto-enrollment settings of a landing zone. Control Tower exposes the
// setting as the INHERITANCE_DRIFT remediation type on the landing zone
// (landing zone 3.1 and later). An empty value means the snapshot does not
// say.
const (
	AutoEnrollmentEnabled  = "enabled"
	AutoEnrollmentDisabled = "disabled"
)

// Sources of an enrolled-account record.
const (
	// EnrolledFromBaseline: read from ListEnabledBaselines as a child
	// enabled baseline whose target is the account. Whether Account Factory
	// vended the account is not visible this way.
	EnrolledFromBaseline = "baseline"
	// EnrolledManual: written by hand.
	EnrolledManual = "manual"
)

// ControlTower describes the AWS Control Tower landing zone that governs an
// organization. It is absent when Control Tower is not set up.
type ControlTower struct {
	LandingZoneARN string `json:"landing_zone_arn,omitempty"`
	Version        string `json:"version,omitempty"`
	// LatestAvailableVersion is the newest landing zone version offered.
	LatestAvailableVersion string `json:"latest_available_version,omitempty"`
	// Status is ACTIVE, PROCESSING or FAILED; DriftStatus is IN_SYNC or DRIFTED.
	Status      string `json:"status,omitempty"`
	DriftStatus string `json:"drift_status,omitempty"`
	// AutoEnrollment is "enabled" when the landing zone remediates
	// inheritance drift (accounts moved into a registered OU are enrolled
	// and accounts moved out are unenrolled automatically), "disabled" when
	// the landing zone was read and the setting is off, empty when unknown.
	AutoEnrollment string `json:"auto_enrollment,omitempty"`
	// HomeRegion is where the landing zone was set up and where its APIs
	// answer; GovernedRegions are the regions the controls are deployed to.
	HomeRegion      string   `json:"home_region,omitempty"`
	GovernedRegions []string `json:"governed_regions,omitempty"`
	// AuditAccountID and LogArchiveAccountID are the shared accounts the
	// landing zone created. They cannot be moved or unenrolled.
	AuditAccountID      string `json:"audit_account_id,omitempty"`
	LogArchiveAccountID string `json:"log_archive_account_id,omitempty"`
	// RegisteredOUs are the OUs Control Tower governs. Accounts are
	// enrolled when the OU baseline has been applied to them, which the
	// collector reads as child enabled baselines.
	RegisteredOUs []RegisteredOU `json:"registered_ous"`
	// EnrolledAccounts lists the accounts that are enrolled. The collector
	// fills it from ListEnabledBaselines (child enabled baselines whose
	// target is an account) and records the control_tower.enrolled_accounts
	// coverage domain. When that domain is complete, an account that is not
	// listed is not enrolled, whatever its OU. When the list is empty and the
	// domain was not collected, the evaluator falls back to assuming that
	// accounts in registered OUs are enrolled and says so.
	EnrolledAccounts []EnrolledAccount `json:"enrolled_accounts,omitempty"`
	// EnabledControls lists the controls enabled on each registered OU.
	// Controls on an OU also apply to the OUs nested under it.
	EnabledControls []EnabledControl `json:"enabled_controls"`
}

// RegisteredOU is an OU with the Control Tower baseline enabled.
type RegisteredOU struct {
	OUID            string `json:"ou_id"`
	BaselineVersion string `json:"baseline_version,omitempty"`
	// Status is SUCCEEDED, UNDER_CHANGE or FAILED.
	Status      string `json:"status,omitempty"`
	DriftStatus string `json:"drift_status,omitempty"`
}

// EnrolledAccount is an account governed by Control Tower.
type EnrolledAccount struct {
	AccountID string `json:"account_id"`
	// VendedByAccountFactory is true when Account Factory created the
	// account; a Service Catalog provisioned product then tracks it. The
	// collector cannot see this (Service Catalog is not read), so records
	// with source "baseline" leave it false and the evaluator treats the
	// provenance as unknown.
	VendedByAccountFactory bool   `json:"vended_by_account_factory"`
	ProvisionedProduct     string `json:"provisioned_product,omitempty"`
	// Status is the enablement status of the child baseline (SUCCEEDED,
	// UNDER_CHANGE, FAILED) or a hand-written label such as ENROLLED.
	Status string `json:"status,omitempty"`
	// DriftStatus is the inheritance drift of the child baseline, when known.
	DriftStatus string `json:"drift_status,omitempty"`
	// ParentOUID is the registered OU whose baseline governs the account,
	// when the collector could resolve it.
	ParentOUID string `json:"parent_ou_id,omitempty"`
	// Source is "baseline" or "manual"; empty means manual.
	Source string `json:"source,omitempty"`
}

// ProvenanceKnown reports whether the record says anything about Account
// Factory: hand-written records do, collected ones only when they name a
// provisioned product.
func (e *EnrolledAccount) ProvenanceKnown() bool {
	return e != nil && (e.Source != EnrolledFromBaseline || e.ProvisionedProduct != "" || e.VendedByAccountFactory)
}

// EnabledControl is one control enabled on one OU.
type EnabledControl struct {
	// ControlIdentifier is the control ARN, for example
	// arn:aws:controltower:eu-west-1::control/AWS-GR_ENCRYPTED_VOLUMES.
	ControlIdentifier string `json:"control_identifier"`
	Name              string `json:"name,omitempty"`
	// Behavior is PREVENTIVE, DETECTIVE or PROACTIVE; empty when unknown.
	Behavior   string `json:"behavior,omitempty"`
	TargetOUID string `json:"target_ou_id"`
	// Status is SUCCEEDED, UNDER_CHANGE or FAILED; DriftStatus is IN_SYNC,
	// DRIFTED, NOT_CHECKING or UNKNOWN.
	Status      string `json:"status,omitempty"`
	DriftStatus string `json:"drift_status,omitempty"`
	// Implementation names what enforces the control, for example
	// AWS::Organizations::Policy, AWS::Config::ConfigRule or
	// AWS::CloudFormation::Hook.
	Implementation string `json:"implementation,omitempty"`
}

// ControlTowerManaged reports whether a policy is a Control Tower guardrail,
// which the collector recognises by its name.
func (p *Policy) ControlTowerManaged() bool {
	return p.Type == PolicyTypeSCP && strings.HasPrefix(p.Name, GuardrailPolicyPrefix)
}

// RegisteredOU returns the registration of an OU, or nil. It is safe to call
// on a nil receiver.
func (ct *ControlTower) RegisteredOU(ouID string) *RegisteredOU {
	if ct == nil {
		return nil
	}
	for i := range ct.RegisteredOUs {
		if ct.RegisteredOUs[i].OUID == ouID {
			return &ct.RegisteredOUs[i]
		}
	}
	return nil
}

// Enrolled returns the enrolment record of an account, or nil. It is safe to
// call on a nil receiver.
func (ct *ControlTower) Enrolled(accountID string) *EnrolledAccount {
	if ct == nil {
		return nil
	}
	for i := range ct.EnrolledAccounts {
		if ct.EnrolledAccounts[i].AccountID == accountID {
			return &ct.EnrolledAccounts[i]
		}
	}
	return nil
}

// ControlsOn returns the controls enabled directly on an OU, in snapshot
// order. It is safe to call on a nil receiver.
func (ct *ControlTower) ControlsOn(ouID string) []EnabledControl {
	if ct == nil {
		return nil
	}
	var out []EnabledControl
	for _, c := range ct.EnabledControls {
		if c.TargetOUID == ouID {
			out = append(out, c)
		}
	}
	return out
}

// ControlsAlong returns the controls that reach a node at the end of the
// given path: those enabled on any OU in the path, nearest the root first.
func (ct *ControlTower) ControlsAlong(path []Node) []EnabledControl {
	if ct == nil {
		return nil
	}
	var out []EnabledControl
	for _, n := range path {
		if n.Kind == KindOU {
			out = append(out, ct.ControlsOn(n.ID)...)
		}
	}
	return out
}

// ControlShortID returns the readable part of a control identifier, for
// example AWS-GR_ENCRYPTED_VOLUMES from its ARN. It is the same for the same
// control in different regions and organizations.
func ControlShortID(identifier string) string {
	if i := strings.LastIndex(identifier, "/"); i >= 0 {
		return identifier[i+1:]
	}
	return identifier
}

// Label is the short name of a control: the readable identifier
// (AWS-GR_ENCRYPTED_VOLUMES) when there is one, otherwise the alias at the
// start of the catalog name (CT.S3.PR.1) or the whole name.
func (c EnabledControl) Label() string {
	id := ControlShortID(c.ControlIdentifier)
	if !opaqueID(id) || c.Name == "" {
		return id
	}
	if i := strings.Index(c.Name, ": "); i > 0 && i <= 24 {
		return c.Name[:i]
	}
	return c.Name
}

// opaqueID reports whether a control identifier is a Control Catalog opaque
// ID (a long run of lower-case letters and digits) rather than a name.
func opaqueID(id string) bool {
	if len(id) < 16 {
		return false
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}
