package collector

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// awsCall matches method calls that look like AWS API operations. It is
// deliberately broad: any verb-prefixed CamelCase method call on a value.
var awsCall = regexp.MustCompile(`\.((?:Describe|List|Get|Create|Delete|Update|Put|Attach|Detach|Move|Tag|Untag|Enable|Disable|Invite|Remove|Accept|Reject|Register|Deregister|Close|Leave|Associate|Disassociate|Promote|Cancel|Decline|Start|Stop|Modify|Set|Add|Replace|Reset|Provision)[A-Z][A-Za-z]*)\(`)

// TestOnlyAllowlistedOperationsAreReferenced fails if any source file in the
// collector package calls an operation that is not in the allowlist. The
// allowlist itself may only contain read-only verbs.
func TestOnlyAllowlistedOperationsAreReferenced(t *testing.T) {
	for svc, ops := range Allowlist {
		for _, op := range ops {
			if !IsReadOnly(op) {
				t.Errorf("allowlist entry %s:%s is not a read-only operation", svc, op)
			}
		}
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range awsCall.FindAllStringSubmatch(string(src), -1) {
			checked++
			op := m[1]
			if !Allowed(op) {
				t.Errorf("%s calls %s, which is not in the read-only allowlist", f, op)
			}
		}
	}
	if checked == 0 {
		t.Fatal("the scan found no API calls at all; the regexp is broken")
	}
}

func TestAllowlistRejectsWriteVerbs(t *testing.T) {
	for _, op := range []string{"MoveAccount", "AttachPolicy", "CreateOrganizationalUnit", "DeletePolicy", "UpdatePolicy", "LeaveOrganization", "InviteAccountToOrganization",
		"EnableControl", "DisableControl", "EnableBaseline", "ResetEnabledBaseline", "UpdateLandingZone", "ResetLandingZone", "DeleteLandingZone",
		"CreateAccountAssignment", "DeleteAccountAssignment", "ProvisionPermissionSet", "PutInlinePolicyToPermissionSet", "AttachManagedPolicyToPermissionSet", "DeletePermissionSet", "CreateUser", "DeleteGroup"} {
		if Allowed(op) || IsReadOnly(op) {
			t.Errorf("%s must never be allowed", op)
		}
	}
	if len(IAMActions()) != 31 || IAMActions()[0] != "account:ListRegions" || IAMActions()[1] != "controlcatalog:GetControl" {
		t.Errorf("unexpected IAM action list: %v", IAMActions())
	}
}
