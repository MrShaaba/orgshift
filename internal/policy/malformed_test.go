package policy

import (
	"fmt"
	"strings"
	"testing"
)

// M5 defect 3. A statement has one action element and one resource
// element: the IAM policy grammar writes them as ("Action" | "NotAction")
// and ("Resource" | "NotResource"). A statement with both is malformed, and
// reading it as if only one were there gives a definite answer to a
// question the document does not answer.
func TestStatementWithBothElementsIsMalformed(t *testing.T) {
	for name, c := range map[string]struct{ doc, want string }{
		"action and notaction":     {`{"Statement":[{"Sid":"Both","Effect":"Deny","Action":"ec2:*","NotAction":"s3:*","Resource":"*"}]}`, "both Action and NotAction"},
		"resource and notresource": {`{"Statement":[{"Effect":"Deny","Action":"s3:*","Resource":"*","NotResource":"arn:aws:s3:::keep/*"}]}`, "both Resource and NotResource"},
	} {
		_, err := Parse([]byte(c.doc))
		if err == nil || !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), "statement #1") {
			t.Errorf("%s: expected a malformed-statement error naming the statement and %q, got %v", name, c.want, err)
		}
	}
	// A statement without a resource element parses: a role trust policy
	// has none. The parser does not invent a "*" for it; whether the
	// element is required is a rule of the policy type.
	d, err := Parse([]byte(`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	st := &d.Statements[0]
	if len(st.Resources) != 0 || len(st.NotResources) != 0 || st.HasResourceElement() {
		t.Errorf("no Resource element means none, not an invented \"*\": %+v", st.Resources)
	}
	// Such a statement is about the resource the policy is attached to.
	if m := st.Applies(Request{Action: "sts:AssumeRole", Resource: "arn:aws:iam::111111111112:role/Reader", Principal: "arn:aws:iam::111111111113:role/x"}); m.Outcome != Yes {
		t.Errorf("a statement of a resource policy without a Resource element applies to its resource: %+v", m)
	}
}

// An unresolved policy variable in Resource or NotResource is unknown,
// never a definite non-match: a Deny behind it may apply, an Allow behind
// it may not.
func TestPolicyVariableInResourceIsUnknownNotANonMatch(t *testing.T) {
	const pattern = "arn:aws:s3:::example/${aws:PrincipalTag/team}/*"
	stmt := func(effect, element string) *Statement {
		t.Helper()
		d, err := Parse([]byte(fmt.Sprintf(`{"Statement":[{"Sid":"V","Effect":%q,"Action":"s3:GetObject",%q:[%q]}]}`, effect, element, pattern)))
		if err != nil {
			t.Fatal(err)
		}
		return &d.Statements[0]
	}
	inside := "arn:aws:s3:::example/platform/report.csv"
	elsewhere := "arn:aws:s3:::other-bucket/report.csv"
	req := func(resource string, ctx Context) Request {
		if ctx == nil {
			ctx = Context{}
		}
		return Request{Action: "s3:GetObject", Resource: resource, Context: ctx}
	}
	for _, effect := range []string{"Deny", "Allow"} {
		for _, element := range []string{"Resource", "NotResource"} {
			st := stmt(effect, element)
			// The tag is not known: the statement may or may not apply.
			m := st.Applies(req(inside, nil))
			if m.Outcome != Unknown || !strings.Contains(m.Reason, "policy variable") || !strings.Contains(m.Reason, "aws:PrincipalTag/team") {
				t.Errorf("%s %s, tag unknown: got %v (%s), want unknown naming the variable", effect, element, m.Outcome, m.Reason)
			}
			// A resource the pattern cannot reach whatever the variable holds
			// is decided: outside Resource, not excluded by NotResource.
			want := No
			if element == "NotResource" {
				want = Yes
			}
			if m := st.Applies(req(elsewhere, nil)); m.Outcome != want {
				t.Errorf("%s %s, resource out of reach of the pattern: got %v, want %v", effect, element, m.Outcome, want)
			}
			// The tag is known: the variable resolves and the answer is definite.
			platform, data := Context{}, Context{}
			platform.Set("aws:PrincipalTag/team", Known("platform"))
			data.Set("aws:PrincipalTag/team", Known("data"))
			matchWant, missWant := Yes, No
			if element == "NotResource" {
				matchWant, missWant = No, Yes
			}
			if m := st.Applies(req(inside, platform)); m.Outcome != matchWant {
				t.Errorf("%s %s, team=platform: got %v, want %v", effect, element, m.Outcome, matchWant)
			}
			if m := st.Applies(req(inside, data)); m.Outcome != missWant {
				t.Errorf("%s %s, team=data: got %v, want %v", effect, element, m.Outcome, missWant)
			}
			// The principal is known to carry no such tag: "the resource that
			// includes a policy variable with no value will not match any
			// resource" (IAM policy variables).
			none := Context{}
			none.Set("aws:PrincipalTag/*", Absent())
			if m := st.Applies(req(inside, none)); m.Outcome != missWant {
				t.Errorf("%s %s, no tag: got %v, want %v", effect, element, m.Outcome, missWant)
			}
		}
	}
	// A default value stands in for a variable without a value.
	d, err := Parse([]byte(`{"Statement":[{"Effect":"Deny","Action":"s3:GetObject","Resource":"arn:aws:s3:::example/${aws:PrincipalTag/team, 'shared'}/*"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	none := Context{}
	none.Set("aws:PrincipalTag/*", Absent())
	if m := d.Statements[0].Applies(req("arn:aws:s3:::example/shared/x", none)); m.Outcome != Yes {
		t.Errorf("the default value is used when the tag is absent: %+v", m)
	}
	if m := d.Statements[0].Applies(req("arn:aws:s3:::example/platform/x", none)); m.Outcome != No {
		t.Errorf("with the default in place another prefix does not match: %+v", m)
	}
	// A literal resource next to the variable one still decides on its own.
	d, err = Parse([]byte(`{"Statement":[{"Effect":"Deny","Action":"s3:GetObject","Resource":["arn:aws:s3:::example/${aws:PrincipalTag/team}/*","arn:aws:s3:::example/platform/*"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if m := d.Statements[0].Applies(req(inside, nil)); m.Outcome != Yes {
		t.Errorf("a literal pattern that matches settles it: %+v", m)
	}
}
