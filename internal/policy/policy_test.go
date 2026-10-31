package policy

import (
	"testing"
)

func mustParse(t *testing.T, doc string) *Document {
	t.Helper()
	d, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestParseShapes(t *testing.T) {
	d := mustParse(t, `{"Version":"2012-10-17","Statement":{"Sid":"One","Effect":"Deny","Action":"ec2:CreateVpc","Resource":"*"}}`)
	if len(d.Statements) != 1 || d.Statements[0].Sid != "One" || d.Statements[0].Actions[0] != "ec2:CreateVpc" {
		t.Fatalf("single statement object not parsed: %+v", d.Statements)
	}
	d = mustParse(t, `{"Statement":[{"Effect":"Allow","Action":["s3:*","ec2:Describe*"],"Resource":["*"],
		"Condition":{"StringEquals":{"aws:RequestedRegion":["eu-west-1","eu-central-1"]},"Bool":{"aws:SecureTransport":true}}}]}`)
	st := d.Statements[0]
	if len(st.Actions) != 2 || len(st.Conditions) != 2 {
		t.Fatalf("array forms not parsed: %+v", st)
	}
	if st.Conditions[0].Operator != "Bool" || st.Conditions[0].Values[0] != "true" {
		t.Fatalf("conditions should be sorted and stringified: %+v", st.Conditions)
	}
	if _, err := Parse([]byte(`{"Statement":[{"Effect":"Maybe","Action":"*"}]}`)); err == nil {
		t.Fatal("bad effect should fail")
	}
	if _, err := Parse([]byte(`{"Statement":[{"Effect":"Allow","Resource":"*"}]}`)); err == nil {
		t.Fatal("missing action should fail")
	}
}

func TestGlob(t *testing.T) {
	cases := []struct {
		p, s string
		want bool
	}{
		{"*", "anything", true},
		{"ec2:*", "ec2:RunInstances", true},
		{"ec2:Describe*", "ec2:RunInstances", false},
		{"ec2:Run?nstances", "ec2:RunInstances", true},
		{"arn:aws:s3:::bucket/*", "arn:aws:s3:::bucket/key/deep", true},
		{"arn:aws:s3:::bucket/*", "arn:aws:s3:::other/key", false},
	}
	for _, c := range cases {
		if got := globMatch(c.p, c.s, true); got != c.want {
			t.Errorf("globMatch(%q,%q)=%v want %v", c.p, c.s, got, c.want)
		}
	}
	if !covers("ec2:*", "ec2:Describe*", true) || covers("ec2:Describe*", "ec2:*", true) || !covers("*", "s3:*", true) {
		t.Fatal("covers is wrong")
	}
	if !overlaps("ec2:Describe*", "ec2:*", true) || overlaps("ec2:Describe*", "s3:*", true) || !overlaps("*", "x", true) {
		t.Fatal("overlaps is wrong")
	}
}

func TestMatchAction(t *testing.T) {
	if MatchAction([]string{"ec2:*"}, "ec2:runinstances") != Yes {
		t.Fatal("case-insensitive match expected")
	}
	if MatchAction([]string{"ec2:Delete*"}, "ec2:*") != Unknown {
		t.Fatal("partial overlap with wildcard action should be unknown")
	}
	if MatchAction([]string{"s3:*"}, "ec2:*") != No {
		t.Fatal("disjoint should be no")
	}
}

func ctxWith(kv map[string]Value) Context {
	c := Context{}
	for k, v := range kv {
		c.Set(k, v)
	}
	return c
}

func TestRegionDeny(t *testing.T) {
	d := mustParse(t, `{"Statement":[{"Sid":"DenyOutsideEU","Effect":"Deny","NotAction":["iam:*","sts:*","organizations:*","support:*"],"Resource":"*",
		"Condition":{"StringNotEquals":{"aws:RequestedRegion":["eu-west-1","eu-central-1"]}}}]}`)
	st := d.Statements[0]
	req := Request{Action: "ec2:RunInstances", Context: ctxWith(map[string]Value{"aws:RequestedRegion": Known("us-east-1")})}
	if m := st.Applies(req); m.Outcome != Yes {
		t.Fatalf("us-east-1 should be denied, got %v %s", m.Outcome, m.Reason)
	}
	req.Context.Set("aws:RequestedRegion", Known("eu-west-1"))
	if m := st.Applies(req); m.Outcome != No {
		t.Fatalf("eu-west-1 should not match, got %v", m.Outcome)
	}
	req.Action = "iam:CreateRole"
	req.Context.Set("aws:RequestedRegion", Known("us-east-1"))
	if m := st.Applies(req); m.Outcome != No {
		t.Fatalf("NotAction should exclude iam, got %v", m.Outcome)
	}
	req.Action = "ec2:RunInstances"
	req.Context = Context{}
	if m := st.Applies(req); m.Outcome != Unknown {
		t.Fatalf("unknown region should be unknown, got %v", m.Outcome)
	}
}

func TestConditionSemantics(t *testing.T) {
	type tc struct {
		name string
		cond Condition
		ctx  Context
		want Outcome
	}
	cases := []tc{
		{"equals", Condition{"StringEquals", "aws:PrincipalOrgID", []string{"o-abc"}}, ctxWith(map[string]Value{"aws:PrincipalOrgID": Known("o-abc")}), Yes},
		{"not equals", Condition{"StringNotEquals", "aws:PrincipalOrgID", []string{"o-abc"}}, ctxWith(map[string]Value{"aws:PrincipalOrgID": Known("o-xyz")}), Yes},
		{"not equals same", Condition{"StringNotEquals", "aws:PrincipalOrgID", []string{"o-abc"}}, ctxWith(map[string]Value{"aws:PrincipalOrgID": Known("o-abc")}), No},
		{"negated missing is true", Condition{"StringNotEquals", "aws:PrincipalOrgID", []string{"o-abc"}}, ctxWith(map[string]Value{"aws:PrincipalOrgID": Absent()}), Yes},
		{"positive missing is false", Condition{"StringEquals", "aws:PrincipalOrgID", []string{"o-abc"}}, ctxWith(map[string]Value{"aws:PrincipalOrgID": Absent()}), No},
		{"ifexists missing", Condition{"StringEqualsIfExists", "aws:PrincipalOrgID", []string{"o-abc"}}, ctxWith(map[string]Value{"aws:PrincipalOrgID": Absent()}), Yes},
		{"unknown", Condition{"StringEquals", "aws:PrincipalOrgID", []string{"o-abc"}}, Context{}, Unknown},
		{"null absent", Condition{"Null", "aws:PrincipalTag/team", []string{"true"}}, ctxWith(map[string]Value{"aws:principaltag/*": Absent()}), Yes},
		{"null present", Condition{"Null", "aws:PrincipalTag/team", []string{"true"}}, ctxWith(map[string]Value{"aws:PrincipalTag/team": Known("x")}), No},
		{"tag family absent", Condition{"StringEquals", "aws:PrincipalTag/team", []string{"platform"}}, ctxWith(map[string]Value{"aws:principaltag/*": Absent()}), No},
		{"tag unknown", Condition{"StringEquals", "aws:PrincipalTag/team", []string{"platform"}}, Context{}, Unknown},
		{"like", Condition{"StringLike", "aws:PrincipalArn", []string{"arn:aws:iam::*:role/Admin*"}}, ctxWith(map[string]Value{"aws:PrincipalArn": Known("arn:aws:iam::111111111111:role/AdminRole")}), Yes},
		{"arnlike no", Condition{"ArnLike", "aws:PrincipalArn", []string{"arn:aws:iam::*:role/Admin*"}}, ctxWith(map[string]Value{"aws:PrincipalArn": Known("arn:aws:iam::111111111111:role/Dev")}), No},
		{"bool", Condition{"Bool", "aws:PrincipalIsAWSService", []string{"false"}}, ctxWith(map[string]Value{"aws:PrincipalIsAWSService": Known("false")}), Yes},
		{"boolifexists missing", Condition{"BoolIfExists", "aws:PrincipalIsAWSService", []string{"false"}}, ctxWith(map[string]Value{"aws:PrincipalIsAWSService": Absent()}), Yes},
		{"unsupported op", Condition{"IpAddress", "aws:SourceIp", []string{"10.0.0.0/8"}}, ctxWith(map[string]Value{"aws:SourceIp": Known("10.1.1.1")}), Unknown},
		{"policy variable", Condition{"StringEquals", "aws:ResourceTag/owner", []string{"${aws:username}"}}, ctxWith(map[string]Value{"aws:ResourceTag/owner": Known("bob")}), Unknown},
		{"forallvalues", Condition{"ForAllValues:StringEquals", "aws:TagKeys", []string{"a", "b"}}, ctxWith(map[string]Value{"aws:TagKeys": Known("a", "b")}), Yes},
		{"forallvalues fail", Condition{"ForAllValues:StringEquals", "aws:TagKeys", []string{"a"}}, ctxWith(map[string]Value{"aws:TagKeys": Known("a", "b")}), No},
		{"foranyvalue", Condition{"ForAnyValue:StringEquals", "aws:TagKeys", []string{"b"}}, ctxWith(map[string]Value{"aws:TagKeys": Known("a", "b")}), Yes},
	}
	for _, c := range cases {
		got, _ := evalCondition(c.cond, c.ctx)
		if got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func TestResourceAndPrincipal(t *testing.T) {
	d := mustParse(t, `{"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::secret-*/*",
		"Condition":{"StringNotEqualsIfExists":{"aws:PrincipalOrgID":"o-home"}}}]}`)
	st := d.Statements[0]
	base := Context{}
	base.Set("aws:PrincipalOrgID", Known("o-other"))
	if m := st.Applies(Request{Action: "s3:GetObject", Context: base}); m.Outcome != Unknown {
		t.Fatalf("unknown resource against scoped statement should be unknown, got %v", m.Outcome)
	}
	if m := st.Applies(Request{Action: "s3:GetObject", Resource: "arn:aws:s3:::secret-files/a", Principal: "999999999999", Context: base}); m.Outcome != Yes {
		t.Fatalf("expected deny match, got %v %s", m.Outcome, m.Reason)
	}
	if m := st.Applies(Request{Action: "s3:GetObject", Resource: "arn:aws:s3:::public/a", Principal: "999999999999", Context: base}); m.Outcome != No {
		t.Fatalf("other bucket should not match, got %v", m.Outcome)
	}
	d = mustParse(t, `{"Statement":[{"Effect":"Deny","Principal":{"AWS":["arn:aws:iam::222222222222:root"]},"Action":"sts:AssumeRole","Resource":"*"}]}`)
	st = d.Statements[0]
	if m := st.Applies(Request{Action: "sts:AssumeRole", Principal: "arn:aws:iam::222222222222:role/x"}); m.Outcome != Yes {
		t.Fatalf("account root principal should match roles in the account, got %v", m.Outcome)
	}
	if m := st.Applies(Request{Action: "sts:AssumeRole", Principal: "333333333333"}); m.Outcome != No {
		t.Fatalf("other account should not match, got %v", m.Outcome)
	}
	if m := st.Applies(Request{Action: "sts:AssumeRole"}); m.Outcome != Unknown {
		t.Fatalf("unknown principal should be unknown, got %v", m.Outcome)
	}
	if AccountFromPrincipal("arn:aws:iam::123456789012:role/x") != "123456789012" || AccountFromPrincipal("nope") != "" {
		t.Fatal("AccountFromPrincipal")
	}
}
