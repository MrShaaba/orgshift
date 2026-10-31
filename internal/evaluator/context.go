package evaluator

import (
	"sort"
	"strings"

	"github.com/MrShaaba/orgshift/internal/policy"
	"github.com/MrShaaba/orgshift/internal/snapshot"
)

// globalServices are evaluated in us-east-1 for aws:RequestedRegion.
var globalServices = map[string]bool{
	"iam": true, "sts": true, "organizations": true, "support": true, "budgets": true, "cloudfront": true,
	"route53": true, "route53domains": true, "waf": true, "health": true, "account": true, "ce": true, "cur": true,
	"shield": true, "globalaccelerator": true, "savingsplans": true, "tax": true, "billing": true, "pricing": true,
	"trustedadvisor": true, "importexport": true, "networkmanager": true, "iq": true, "artifact": true,
}

// rcpServices are the services resource control policies apply to.
var rcpServices = map[string]bool{"s3": true, "sts": true, "kms": true, "sqs": true, "secretsmanager": true}

func serviceOf(action string) string {
	if i := strings.Index(action, ":"); i > 0 {
		return strings.ToLower(action[:i])
	}
	return strings.ToLower(action)
}

// regionsFor returns the regions an action is evaluated in.
func regionsFor(action string, explicit, enabled []string) []string {
	if globalServices[serviceOf(action)] {
		return []string{"us-east-1"}
	}
	src := explicit
	if len(src) == 0 {
		src = enabled
	}
	if len(src) == 0 {
		return []string{""} // unknown region
	}
	out := append([]string(nil), src...)
	sort.Strings(out)
	return out
}

func regionFromARN(arn string) string {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) == 6 && parts[0] == "arn" {
		return parts[3]
	}
	return ""
}

// side is one end of the move: an organization and the account's position.
type side struct {
	name  string // "source" or "target"
	snap  *snapshot.Snapshot
	ix    *snapshot.Index
	orgID string
	path  []snapshot.Node
	// fresh lists the node IDs on the path that join this organization new
	// (an account changing organization, or an OU that has to be recreated).
	// They carry only the AWS managed defaults instead of their attachments.
	fresh map[string]bool
}

// orgOfAccount finds the organization an account belongs to on either side.
func (e *evaluation) orgOfAccount(accountID string) (string, bool) {
	return snapshot.AccountOrg(accountID, e.from, e.to)
}

// ownRequest builds the request for an action performed by the account's
// own principals.
func (e *evaluation) ownRequest(s *side, a snapshot.ActionInUse, region string) policy.Request {
	ctx := policy.Context{}
	if region != "" {
		ctx.Set("aws:RequestedRegion", policy.Known(region))
	}
	ctx.Set("aws:PrincipalOrgID", policy.Known(s.orgID))
	ctx.Set("aws:PrincipalAccount", policy.Known(e.accountID))
	ctx.Set("aws:PrincipalIsAWSService", policy.Known("false"))
	principal := a.PrincipalArn
	if principal == "" {
		// Assumption, documented in docs/snapshot.md: actions in use are
		// performed by IAM roles of the account unless principal_arn says
		// otherwise. This lets root-user denies be evaluated instead of
		// turning every action into a REVIEW.
		principal = "arn:aws:iam::" + e.accountID + ":role/*"
	}
	ctx.Set("aws:PrincipalArn", policy.Known(principal))
	if a.PrincipalTags != nil {
		ctx.Set("aws:PrincipalTag/*", policy.Absent())
		for k, v := range a.PrincipalTags {
			ctx.Set("aws:PrincipalTag/"+k, policy.Known(v))
		}
	}
	if acct := policy.AccountFromPrincipal(a.Resource); acct != "" {
		ctx.Set("aws:ResourceAccount", policy.Known(acct))
		if acct == e.accountID {
			ctx.Set("aws:ResourceOrgID", policy.Known(s.orgID))
		} else if org, ok := e.orgOfAccount(acct); ok {
			ctx.Set("aws:ResourceOrgID", policy.Known(org))
		}
	}
	return policy.Request{Action: a.Action, Resource: a.Resource, Principal: principal, Context: ctx}
}

// inboundRequest builds the request for an outside principal calling into
// the account.
func (e *evaluation) inboundRequest(s *side, in snapshot.InboundAccess, action, region string) policy.Request {
	ctx := policy.Context{}
	if region != "" {
		ctx.Set("aws:RequestedRegion", policy.Known(region))
	}
	ctx.Set("aws:ResourceAccount", policy.Known(e.accountID))
	ctx.Set("aws:ResourceOrgID", policy.Known(s.orgID))
	isService := strings.HasSuffix(in.Principal, ".amazonaws.com")
	switch {
	case isService:
		ctx.Set("aws:PrincipalIsAWSService", policy.Known("true"))
		ctx.Set("aws:PrincipalOrgID", policy.Absent())
		ctx.Set("aws:PrincipalAccount", policy.Absent())
		ctx.Set("aws:PrincipalArn", policy.Absent())
		ctx.Set("aws:PrincipalServiceName", policy.Known(in.Principal))
	default:
		ctx.Set("aws:PrincipalIsAWSService", policy.Known("false"))
		acct := policy.AccountFromPrincipal(in.Principal)
		if acct != "" {
			ctx.Set("aws:PrincipalAccount", policy.Known(acct))
		}
		switch {
		case in.PrincipalOrgID != "":
			ctx.Set("aws:PrincipalOrgID", policy.Known(in.PrincipalOrgID))
		case acct == e.accountID:
			ctx.Set("aws:PrincipalOrgID", policy.Known(s.orgID))
		default:
			if org, ok := e.orgOfAccount(acct); ok {
				ctx.Set("aws:PrincipalOrgID", policy.Known(org))
			}
		}
		if strings.HasPrefix(in.Principal, "arn:") {
			ctx.Set("aws:PrincipalArn", policy.Known(in.Principal))
		} else if acct != "" {
			ctx.Set("aws:PrincipalArn", policy.Known("arn:aws:iam::"+acct+":*"))
		}
	}
	return policy.Request{Action: action, Resource: in.Resource, Principal: in.Principal, Context: ctx}
}
