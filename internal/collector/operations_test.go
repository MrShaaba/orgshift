package collector

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// awsCall matches method calls that look like AWS API operations: any
// verb-prefixed CamelCase method call on a value. It is deliberately broad
// so that a new call shows up here before it shows up in production.
var awsCall = regexp.MustCompile(`\.((?:Describe|List|Get|Search|Lookup|Select|Query|Scan|Batch|Start|Generate|Assume|Create|Delete|Update|Put|Attach|Detach|Move|Tag|Untag|Enable|Disable|Invite|Remove|Accept|Reject|Register|Deregister|Close|Leave|Associate|Disassociate|Promote|Cancel|Decline|Stop|Modify|Set|Add|Replace|Reset|Provision|Import|Deploy|Run|Invoke|Send|Terminate|Reboot|Restore|Rotate|Revoke|Grant|Authorize|Allocate|Release|Purchase|Publish|Submit|Upload)[A-Z][A-Za-z]*)\(`)

// paginatorCall matches the SDK's paginator constructors, which call the
// operation without the operation's name appearing as a method call.
var paginatorCall = regexp.MustCompile(`\.New([A-Z][A-Za-z]*)Paginator\(`)

// notAWS are verb-shaped calls in the scanned packages that are not API
// operations (standard library and orgshift helpers).
var notAWS = map[string]bool{"CreateTemp": true, "DescribeDomains": true, "SetEscapeHTML": true, "SetIndent": true}

// scannedDirs are the packages that may call AWS: the collector, the
// preflight, the credential builder and the CLI.
var scannedDirs = []string{".", "../preflight", "../awsaccess", "../../cmd/orgshift"}

// referencedOperations scans the non-test sources of scannedDirs and
// returns the operation names called, with the file of the first call.
func referencedOperations(t *testing.T) map[string]string {
	t.Helper()
	found := map[string]string{}
	checked := 0
	for _, dir := range scannedDirs {
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			src, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			for _, re := range []*regexp.Regexp{awsCall, paginatorCall} {
				for _, m := range re.FindAllStringSubmatch(string(src), -1) {
					if notAWS[m[1]] {
						continue
					}
					checked++
					if _, ok := found[m[1]]; !ok {
						found[m[1]] = f
					}
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("the scan found no API calls at all; the regexp is broken")
	}
	return found
}

// TestEveryReferencedOperationIsInTheCatalog fails if any scanned source
// calls an operation that the catalog does not list as used by this build.
func TestEveryReferencedOperationIsInTheCatalog(t *testing.T) {
	for op, file := range referencedOperations(t) {
		if !Allowed(op) {
			t.Errorf("%s calls %s, which the catalog does not list as a used read-only operation", file, op)
		}
	}
}

// TestEveryUsedOperationIsReferenced keeps the catalog honest the other way
// round: an operation marked used must be called somewhere, otherwise the
// IAM templates grant a permission nothing needs.
func TestEveryUsedOperationIsReferenced(t *testing.T) {
	found := referencedOperations(t)
	for _, o := range Catalog {
		if o.Used {
			if _, ok := found[o.Name]; !ok {
				t.Errorf("%s is marked used but nothing calls it; mark it planned or call it", o.Action())
			}
		} else if _, ok := found[o.Name]; ok {
			t.Errorf("%s is called by %s but marked planned", o.Action(), found[o.Name])
		}
	}
}

// TestCatalogSemantics enforces the rules of the catalog: no write ever, a
// write verb is refused whatever kind it declares, a billable read sits
// behind an opt-in, and a kind the verb does not make obvious carries a
// note.
func TestCatalogSemantics(t *testing.T) {
	seen := map[string]bool{}
	for _, o := range Catalog {
		action := o.Action()
		if seen[action] {
			t.Errorf("%s is listed twice", action)
		}
		seen[action] = true
		if o.Kind == KindWrite {
			t.Errorf("%s is a write operation; the collector never writes", action)
		}
		if WriteVerb(o.Name) {
			t.Errorf("%s starts with a write verb and is refused whatever kind it declares (%s)", action, o.Kind)
		}
		switch o.Kind {
		case KindRead, KindReadBillable, KindSession:
		default:
			t.Errorf("%s has unknown kind %q", action, o.Kind)
		}
		if o.Kind == KindReadBillable && o.OptIn == "" {
			t.Errorf("%s is billable but has no opt-in flag", action)
		}
		if o.Kind != KindReadBillable && o.OptIn != "" {
			t.Errorf("%s has an opt-in flag but is not billable", action)
		}
		if !ReadVerb(o.Name) && o.Note == "" {
			t.Errorf("%s does not start with a read verb and carries no note justifying its kind", action)
		}
		if len(o.Responsibilities) == 0 {
			t.Errorf("%s belongs to no responsibility", action)
		}
		if o.Purpose == "" {
			t.Errorf("%s has no purpose", action)
		}
		if o.Kind != KindSession && o.Domain == "" {
			t.Errorf("%s fills no domain", action)
		}
	}
}

// gatedBillable are the billable reads this build can call. Each one is
// behind an opt-in that is off by default, and a test proves the call is
// not made without it: TestBucketPoliciesAreReadOnlyWithTheOptIn for the
// S3 reads. A billable operation marked used that is not listed here fails
// the build.
var gatedBillable = map[string]string{
	"s3:ListBuckets":     OptInBucketPolicies,
	"s3:GetBucketPolicy": OptInBucketPolicies,
}

// TestBillableReadsAreOffByDefault checks that every billable operation
// names its opt-in, that the only ones this build calls are the gated ones,
// and that the others stay planned.
func TestBillableReadsAreOffByDefault(t *testing.T) {
	n := 0
	for _, o := range Catalog {
		if o.Kind != KindReadBillable {
			continue
		}
		n++
		if !strings.Contains(o.OptIn, "billable.") || !strings.Contains(o.OptIn, "--with-") {
			t.Errorf("%s opt-in %q should name the configuration key and the flag", o.Action(), o.OptIn)
		}
		want, gated := gatedBillable[o.Action()]
		switch {
		case o.Used && !gated:
			t.Errorf("%s is billable and marked used, but no test proves it is off without its opt-in; add it to gatedBillable with that test", o.Action())
		case o.Used && o.OptIn != want:
			t.Errorf("%s is gated by %q, expected %q", o.Action(), o.OptIn, want)
		case !o.Used && gated:
			t.Errorf("%s is listed as gated but marked planned", o.Action())
		}
	}
	if n < 6 {
		t.Errorf("the catalog should classify the S3 policy reads and the planned CloudTrail Lake and Config queries as billable reads, found %d", n)
	}
	if got := Billable(); len(got) != len(gatedBillable) {
		t.Errorf("Billable() should list the %d gated reads, got %d", len(gatedBillable), len(got))
	}
	// A zero-value workload configuration has the opt-in off.
	var w WorkloadOptions
	if w.BucketPolicies || w.withDefaults().BucketPolicies {
		t.Error("bucket policies must be off unless asked for")
	}
}

func TestVerbsAndSemantics(t *testing.T) {
	for _, op := range []string{"MoveAccount", "AttachPolicy", "CreateOrganizationalUnit", "DeletePolicy", "UpdatePolicy", "LeaveOrganization", "InviteAccountToOrganization",
		"EnableControl", "DisableControl", "EnableBaseline", "ResetEnabledBaseline", "UpdateLandingZone", "ResetLandingZone", "DeleteLandingZone",
		"CreateAccountAssignment", "DeleteAccountAssignment", "ProvisionPermissionSet", "PutInlinePolicyToPermissionSet", "AttachManagedPolicyToPermissionSet", "DeletePermissionSet", "CreateUser", "DeleteGroup",
		"PutResourcePolicy", "TagResource", "CreateResourceShare", "AssociateResourceShare"} {
		if Allowed(op) || IsReadOnly(op) || !WriteVerb(op) || Semantics(op) != KindWrite {
			t.Errorf("%s must never be allowed", op)
		}
	}
	for _, op := range []string{"SearchProvisionedProducts", "LookupEvents", "SelectAggregateResourceConfig", "ListRoots", "DescribePolicy", "GetControl"} {
		if !ReadVerb(op) {
			t.Errorf("%s is a read verb", op)
		}
	}
	if ReadVerb("Listen") || ReadVerb("Getenv") || WriteVerb("Settings") {
		t.Error("a verb needs an upper-case letter after it")
	}
	if Semantics("AssumeRole") != KindSession || Semantics("GetCallerIdentity") != KindSession || !IsReadOnly("AssumeRole") {
		t.Error("the STS operations are sessions, which a read-only collector may call")
	}
	if Semantics("StartQuery") != KindReadBillable || Allowed("StartQuery") {
		t.Error("StartQuery is a planned billable read and not allowed in this build")
	}
	if Semantics("GetBucketPolicy") != KindReadBillable || IsReadOnly("GetBucketPolicy") || Semantics("ListBuckets") != KindReadBillable {
		t.Error("the S3 policy reads are billable reads: callable, but only behind their opt-in")
	}
	for _, op := range []string{"DescribeStacks", "ListStackResources", "ListExports", "ListImports", "GetTemplate", "GetResources", "ListIndexes", "Search", "ListRoles", "ListStackSets", "DescribeStackSet", "ListStackInstances"} {
		if !Allowed(op) || !IsReadOnly(op) || WriteVerb(op) {
			t.Errorf("%s is a free read of the workload inventory", op)
		}
	}
	for _, op := range []string{"CreateStack", "UpdateStack", "DeleteStack", "UpdateStackSet", "DeleteStackInstances", "CreateStackInstances", "PutBucketPolicy", "DeleteBucketPolicy", "UpdateAssumeRolePolicy", "TagResources", "UntagResources", "CreateIndex", "DeleteIndex", "CreateView"} {
		if Allowed(op) || !WriteVerb(op) || Semantics(op) != KindWrite {
			t.Errorf("%s must never be allowed", op)
		}
	}
}

func TestIAMActionsAndResponsibilities(t *testing.T) {
	actions := IAMActions()
	if len(actions) != 47 || actions[0] != "account:ListRegions" || actions[1] != "cloudformation:DescribeStackSet" || actions[len(actions)-1] != "tag:GetResources" {
		t.Errorf("unexpected IAM action list (%d): %v", len(actions), actions)
	}
	// An operation authorized under another name is listed by that name.
	if !containsString(actions, "s3:ListAllMyBuckets") || containsString(actions, "s3:ListBuckets") || !containsString(actions, "cloudformation:ListStacks") {
		t.Errorf("IAM actions should use the names IAM authorizes: %v", actions)
	}
	if o, ok := Lookup("s3:ListAllMyBuckets"); !ok || o.Name != "ListBuckets" {
		t.Errorf("Lookup by the IAM name: %+v", o)
	}
	if !sort.StringsAreSorted(actions) {
		t.Error("actions should be sorted")
	}
	for _, a := range actions {
		if _, ok := Lookup(a); !ok {
			t.Errorf("%s not found by Lookup", a)
		}
	}
	org := ActionsFor(RoleOrgManagement, false)
	if !containsString(org, "organizations:ListRoots") || !containsString(org, "ram:GetResourceShares") || !containsString(org, "sts:AssumeRole") || containsString(org, "sso:ListInstances") || containsString(org, "sts:GetCallerIdentity") {
		t.Errorf("org-management actions: %v", org)
	}
	if !containsString(org, "cloudformation:ListStackSets") || !containsString(org, "cloudformation:ListStackInstances") || containsString(org, "cloudformation:DescribeStacks") {
		t.Errorf("org-management reads the StackSets, not the stacks of member accounts: %v", org)
	}
	if planned := ActionsFor(RoleOrgManagement, true); !containsString(planned, "cloudtrail:DescribeTrails") || containsString(planned, "organizations:ListRoots") || containsString(planned, "cloudformation:ListStackSets") {
		t.Errorf("planned org-management actions: %v", planned)
	}
	if net := ActionsFor(RoleNetwork, false); strings.Join(net, ",") != "ram:GetResourceShares,ram:ListPrincipals,ram:ListResources" {
		t.Errorf("network actions: %v", net)
	}
	if m := ActionsFor(RoleMemberInspection, false); strings.Join(m, ",") != "cloudformation:DescribeStacks,cloudformation:GetTemplate,cloudformation:ListExports,cloudformation:ListImports,cloudformation:ListStackResources,cloudformation:ListStacks,iam:ListRoles,resource-explorer-2:ListIndexes,resource-explorer-2:Search,s3:GetBucketPolicy,s3:ListAllMyBuckets,tag:GetResources" {
		t.Errorf("member inspection actions: %v", m)
	}
	if m := ActionsFor(RoleMemberInspection, true); !containsString(m, "iam:GetServiceLastAccessedDetails") || !containsString(m, "config:SelectAggregateResourceConfig") {
		t.Errorf("planned member actions: %v", m)
	}
	if ct := ActionsFor(RoleControlTower, false); len(ct) != 5 || ct[0] != "controlcatalog:GetControl" {
		t.Errorf("control tower actions: %v", ct)
	}
	if idc := ActionsFor(RoleIdentityCenter, false); len(idc) != 11 {
		t.Errorf("identity center actions: %v", idc)
	}
	for _, o := range OperationsFor(RoleControlTower, false) {
		if !o.Used || !o.For(RoleControlTower) {
			t.Errorf("OperationsFor returned %+v", o)
		}
	}
}

// TestPermissionsDocListsEveryUsedAction keeps docs/permissions.md in step
// with the catalog.
func TestPermissionsDocListsEveryUsedAction(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("..", "..", "docs", "permissions.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range IAMActions() {
		if !strings.Contains(string(doc), "`"+a+"`") {
			t.Errorf("docs/permissions.md does not list %s", a)
		}
	}
	for _, o := range Catalog {
		if !o.Used && !strings.Contains(string(doc), o.Name) {
			t.Errorf("docs/permissions.md does not mention the planned operation %s", o.Action())
		}
	}
}
