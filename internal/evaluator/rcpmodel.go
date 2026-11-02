package evaluator

import (
	"fmt"
	"sort"
	"strings"
)

// The RCP applicability model: which services resource control policies
// apply to, and what they never restrict. It is versioned by the date it
// was checked against the AWS Organizations user guide, and the result
// records that version, because AWS adds services to the list without a
// fixed schedule. An action on a service outside the list is reported as
// not evaluated, never as allowed.
const (
	RCPModelVersion   = "2026-11-01"
	RCPModelReference = "https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html#rcp-supported-services"
)

// rcpServices are the service prefixes RCPs apply to, as listed on the
// reference page on the model date (62 services).
var rcpServices = map[string]bool{
	"appstream": true, "dsql": true, "clouddirectory": true, "cloudfront": true, "cloudsearch": true,
	"logs": true, "networkmonitor": true, "cognito-identity": true, "cognito-idp": true, "comprehend": true,
	"comprehendmedical": true, "firehose": true, "dynamodb": true, "dax": true, "autoscaling": true,
	"ecr": true, "ecr-public": true, "gamelift": true, "inspector-scan": true, "kendra": true,
	"kinesisvideo": true, "memorydb": true, "aoss": true, "personalize": true, "polly": true,
	"s3": true, "swf": true, "sqs": true, "textract": true, "timestream-influxdb": true,
	"transcribe": true, "translate": true, "workspaces": true, "appconfig": true, "autoscaling-plans": true,
	"budgets": true, "servicediscovery": true, "cloudtrail-data": true, "codeartifact": true, "codebuild": true,
	"codecommit": true, "codepipeline": true, "compute-optimizer": true, "cost-optimization-hub": true, "events": true,
	"fms": true, "fis": true, "health": true, "rolesanywhere": true, "kms": true,
	"opensearch": true, "pricing": true, "pca-connector-ad": true, "resource-groups": true, "secretsmanager": true,
	"sts": true, "signin": true, "support": true, "transfer": true, "notifications": true,
	"wafv2": true, "xray": true,
}

// rcpExemptActions are actions on governed services that RCPs do not
// impact, per the reference page.
var rcpExemptActions = map[string]bool{"kms:retiregrant": true}

const rcpExemptReason = "exempt"

// RCPModel describes the model for the result's model list.
func RCPModel() ModelRef {
	return ModelRef{ID: "rcp-applicability", Version: RCPModelVersion, Reference: RCPModelReference,
		Note: fmt.Sprintf("%d services; RCPs never restrict resources in the management account, calls by service-linked roles, AWS managed KMS keys or kms:RetireGrant", len(rcpServices))}
}

// rcpApplies reports whether an action is governed by RCPs. The second
// value is rcpExemptReason for an exempt action, or a note for a service
// outside the model. A bare "*" or "service:*" over a governed service is
// evaluated (the matcher reports partial overlaps as unknown).
func rcpApplies(action string) (bool, string) {
	if rcpExemptActions[strings.ToLower(action)] {
		return false, rcpExemptReason
	}
	svc := serviceOf(action)
	if svc == "*" {
		return true, ""
	}
	if rcpServices[svc] {
		return true, ""
	}
	return false, fmt.Sprintf("service %s is not in the RCP applicability model %s", svc, RCPModelVersion)
}

// rcpModelFindings adds the informational findings that make the model's
// limits visible: the actions that were not evaluated because their service
// is outside the model, and the exempt ones.
func (e *evaluation) rcpModelFindings(c *Check, notGoverned, exempt []string) {
	if len(notGoverned) > 0 {
		sort.Strings(notGoverned)
		c.add(Finding{Status: StatusInfo, Category: CategoryUnsupported, Title: fmt.Sprintf("%d action(s) use services RCPs do not govern and were not evaluated against RCPs", len(notGoverned)),
			Detail: "RCPs apply to a fixed list of services (applicability model " + RCPModelVersion + ", " + fmt.Sprint(len(rcpServices)) + " services). These actions are not restricted by RCPs at either position, so nothing changes for them: " +
				strings.Join(notGoverned, ", ") + ". Services added to RCPs after the model date are not covered; the model is updated with the tool.",
			References: []string{RCPModelReference}})
	}
	if len(exempt) > 0 {
		sort.Strings(exempt)
		c.add(Finding{Status: StatusInfo, Category: CategoryUnsupported, Title: fmt.Sprintf("%d action(s) are exempt from RCPs: %s", len(exempt), strings.Join(exempt, ", ")),
			Detail:     "The reference page lists these permissions as not impacted by RCPs, so they were not evaluated.",
			References: []string{RCPModelReference}})
	}
}
