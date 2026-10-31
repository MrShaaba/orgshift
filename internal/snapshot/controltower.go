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

// ControlTower describes the AWS Control Tower landing zone that governs an
// organization. It is absent when Control Tower is not set up.
type ControlTower struct {
	LandingZoneARN string `json:"landing_zone_arn,omitempty"`
	Version        string `json:"version,omitempty"`
	// Status is ACTIVE, PROCESSING or FAILED; DriftStatus is IN_SYNC or DRIFTED.
	Status      string `json:"status,omitempty"`
	DriftStatus string `json:"drift_status,omitempty"`
	// HomeRegion is where the landing zone was set up and where its APIs
	// answer; GovernedRegions are the regions the controls are deployed to.
	HomeRegion      string   `json:"home_region,omitempty"`
	GovernedRegions []string `json:"governed_regions,omitempty"`
	// AuditAccountID and LogArchiveAccountID are the shared accounts the
	// landing zone created. They cannot be moved or unenrolled.
	AuditAccountID      string `json:"audit_account_id,omitempty"`
	LogArchiveAccountID string `json:"log_archive_account_id,omitempty"`
	// RegisteredOUs are the OUs Control Tower governs. Accounts become
	// enrolled by living in one of them.
	RegisteredOUs []RegisteredOU `json:"registered_ous"`
	// EnrolledAccounts is optional. When it is empty, every account whose
	// parent OU is registered is assumed to be enrolled.
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
	// account; a Service Catalog provisioned product then tracks it.
	VendedByAccountFactory bool   `json:"vended_by_account_factory"`
	ProvisionedProduct     string `json:"provisioned_product,omitempty"`
	Status                 string `json:"status,omitempty"`
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
