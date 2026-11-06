package evaluator

import (
	"fmt"
	"sort"
	"strings"

	"github.com/MrShaaba/orgshift/internal/policy"
	"github.com/MrShaaba/orgshift/internal/snapshot"
)

// globalServices have a single endpoint and are evaluated in us-east-1 for
// aws:RequestedRegion. AWS STS is not one of them: it has Regional
// endpoints next to its global one (see regionsFor).
var globalServices = map[string]bool{
	"iam": true, "organizations": true, "support": true, "budgets": true, "cloudfront": true,
	"route53": true, "route53domains": true, "waf": true, "health": true, "account": true, "ce": true, "cur": true,
	"shield": true, "globalaccelerator": true, "savingsplans": true, "tax": true, "billing": true, "pricing": true,
	"trustedadvisor": true, "importexport": true, "networkmanager": true, "iq": true, "artifact": true,
}

func serviceOf(action string) string {
	if i := strings.Index(action, ":"); i > 0 {
		return strings.ToLower(action[:i])
	}
	return strings.ToLower(action)
}

// GlobalEndpoint is the value a usage entry gives in regions for a call to
// a service's global endpoint (sts.amazonaws.com). "aws-global", the name
// the SDKs use, is accepted too.
const GlobalEndpoint = "global"

// refSTSRegions is the page the STS endpoint rule was checked against
// (2026-11-05): "Requests made to the AWS STS global endpoint have a value
// of us-east-1 for the aws:RequestedRegion condition key, regardless of
// which Region served the request."
const refSTSRegions = "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_region-endpoints.html"

// endpointServices have a global endpoint and Regional ones, so the Region
// of a request depends on the endpoint the caller uses and cannot be
// taken from the account's enabled Regions.
var endpointServices = map[string]bool{"sts": true}

// regionSet is where an action is evaluated.
type regionSet struct {
	// regions are the aws:RequestedRegion values to evaluate; "" stands
	// for a Region that is not known.
	regions []string
	// endpointUnknown is set for a service with Regional and global
	// endpoints when the usage entry names neither.
	endpointUnknown bool
	// viaGlobal is set when the entry names the global endpoint, which is
	// evaluated as us-east-1.
	viaGlobal bool
}

// known reports whether findings can name the Regions.
func (r regionSet) known() bool { return !(len(r.regions) == 1 && r.regions[0] == "") }

// note explains the Region of a finding where it is not self-evident.
func (r regionSet) note(action string) string {
	switch {
	case r.endpointUnknown:
		return fmt.Sprintf(" The endpoint %s is called through is not known, so aws:RequestedRegion was left unknown rather than guessed: a request to the global endpoint sts.amazonaws.com carries us-east-1 whichever Region serves it, a request to a Regional endpoint carries that Region. Add regions to the usage entry: the Region of the endpoint, or %q for the global one.", action, GlobalEndpoint)
	case r.viaGlobal:
		return " The usage entry names the global endpoint, which carries us-east-1 as aws:RequestedRegion whichever Region serves the request."
	}
	return ""
}

// regionsFor returns the Regions an action is evaluated in: us-east-1 for
// a service with a single global endpoint; for AWS STS the Regions the
// usage entry names, with the global endpoint counted as us-east-1, and
// unknown when it names none; for everything else the entry's Regions or,
// without any, the account's enabled Regions.
func regionsFor(action string, explicit, enabled []string) regionSet {
	svc := serviceOf(action)
	if globalServices[svc] {
		return regionSet{regions: []string{"us-east-1"}}
	}
	if endpointServices[svc] {
		if len(explicit) == 0 {
			return regionSet{regions: []string{""}, endpointUnknown: true}
		}
		set := regionSet{}
		seen := map[string]bool{}
		for _, r := range explicit {
			if r == GlobalEndpoint || r == "aws-global" {
				r, set.viaGlobal = "us-east-1", true
			}
			if !seen[r] {
				seen[r] = true
				set.regions = append(set.regions, r)
			}
		}
		sort.Strings(set.regions)
		return set
	}
	src := explicit
	if len(src) == 0 {
		src = enabled
	}
	if len(src) == 0 {
		return regionSet{regions: []string{""}} // unknown region
	}
	out := append([]string(nil), src...)
	sort.Strings(out)
	return regionSet{regions: out}
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
	ctx.Set("aws:PrincipalOrgPaths", policy.Known(orgPath(s.orgID, s.path)))
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
			ctx.Set("aws:ResourceOrgPaths", policy.Known(orgPath(s.orgID, s.path)))
		} else if owner := e.sideOfAccount(acct); owner != nil {
			ctx.Set("aws:ResourceOrgID", policy.Known(owner.orgID))
			ctx.Set("aws:ResourceOrgPaths", policy.Known(orgPath(owner.orgID, owner.path)))
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
	ctx.Set("aws:ResourceOrgPaths", policy.Known(orgPath(s.orgID, s.path)))
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
			ctx.Set("aws:PrincipalOrgPaths", policy.Known(orgPath(s.orgID, s.path)))
		default:
			if owner := e.sideOfAccount(acct); owner != nil {
				ctx.Set("aws:PrincipalOrgID", policy.Known(owner.orgID))
				ctx.Set("aws:PrincipalOrgPaths", policy.Known(orgPath(owner.orgID, owner.path)))
			} else if org, ok := e.orgOfAccount(acct); ok {
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
