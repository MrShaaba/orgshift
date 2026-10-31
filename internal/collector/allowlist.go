// Package collector reads an AWS organization through read-only API calls
// and produces a snapshot. Every operation it may call is listed in
// Allowlist; a test fails the build if the package references anything
// else, and the IAM policy in docs/permissions.md is derived from the same
// list.
package collector

import (
	"sort"
	"strings"
)

// Allowlist maps a service to the read-only operations the collector uses.
var Allowlist = map[string][]string{
	"organizations": {
		"DescribeOrganization",
		"ListRoots",
		"ListOrganizationalUnitsForParent",
		"ListAccountsForParent",
		"ListPolicies",
		"DescribePolicy",
		"ListTargetsForPolicy",
		"ListTagsForResource",
		"ListDelegatedAdministrators",
		"ListDelegatedServicesForAccount",
		"ListAWSServiceAccessForOrganization",
	},
	"ram": {
		"GetResourceShares",
		"ListPrincipals",
		"ListResources",
	},
	"account": {
		"ListRegions",
	},
	"controltower": {
		"ListLandingZones",
		"GetLandingZone",
		"ListEnabledBaselines",
		"ListEnabledControls",
	},
	"controlcatalog": {
		"GetControl",
	},
}

// readOnlyPrefixes are the only verbs an allowlisted operation may start with.
var readOnlyPrefixes = []string{"List", "Describe", "Get"}

// IsReadOnly reports whether an operation name uses a read-only verb.
func IsReadOnly(op string) bool {
	for _, p := range readOnlyPrefixes {
		if strings.HasPrefix(op, p) {
			return true
		}
	}
	return false
}

// Allowed reports whether an operation is in the allowlist for any service.
func Allowed(op string) bool {
	for _, ops := range Allowlist {
		for _, o := range ops {
			if o == op {
				return true
			}
		}
	}
	return false
}

// IAMActions renders the allowlist as IAM action strings, sorted.
func IAMActions() []string {
	var out []string
	for svc, ops := range Allowlist {
		for _, o := range ops {
			out = append(out, svc+":"+o)
		}
	}
	sort.Strings(out)
	return out
}
