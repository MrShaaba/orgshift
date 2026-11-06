package policy

import (
	"strings"
	"testing"
)

// Seed documents for the parser fuzzer: the shapes the fixtures use plus the
// malformed ones the audit found.
var seedDocuments = []string{
	`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`,
	`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*"}]}`,
	`{"Version":"2012-10-17","Statement":{"Sid":"One","Effect":"Deny","Action":"ec2:CreateVpc","Resource":"*"}}`,
	`{"Version":"2012-10-17","Statement":[{"Sid":"DenyOutsideEU","Effect":"Deny","NotAction":["iam:*","sts:*"],"Resource":"*","Condition":{"StringNotEquals":{"aws:RequestedRegion":["eu-west-1","eu-central-1"]}}}]}`,
	`{"Version":"2012-10-17","Statement":[{"Sid":"EnforceOrgIdentities","Effect":"Deny","Principal":"*","Action":["s3:*","sts:AssumeRole"],"Resource":"*","Condition":{"StringNotEqualsIfExists":{"aws:PrincipalOrgID":"o-fernhill0001"},"BoolIfExists":{"aws:PrincipalIsAWSService":"false"}}}]}`,
	`{"Statement":[{"Effect":"Deny","Principal":{"AWS":["arn:aws:iam::222222222222:root"]},"Action":"sts:AssumeRole","Resource":"*"}]}`,
	`{"Statement":[{"Effect":"Deny","Action":"ec2:RunInstances","Resource":"arn:aws:ec2:*:*:instance/*","Condition":{"StringNotLike":{"ec2:InstanceType":["t3.*","t4g.*"]}}}]}`,
	`{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"Null":{"aws:PrincipalTag/team":"true"},"Bool":{"aws:SecureTransport":false},"NumericLessThan":{"s3:max-keys":10}}}]}`,
	`{"Version":"2012-10-17","Statement":[{"Sid":"Broken","Effect":"Deny","Resource":"*"}]}`,
	`{"Version":"2012-10-17","Statement":[{"Effect":"Maybe","Action":"*","Resource":"*"}]}`,
	`{"Version":"2012-10-17"}`,
	`{"Statement": 5}`,
	`{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":"nope"}]}`,
	`{"Statement":[{"Effect":"Deny","Action":null,"Principal":{"AWS":null},"Resource":[null]}]}`,
	`{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"StringEquals":{"a":[[["deep"]]]}}}]}`,
	`[]`, `"string"`, `null`, `123`, `{`, ``,
}

// FuzzParseAndApply checks that no policy document, however malformed, can
// make the parser or the matcher panic, and that every parsed statement
// answers a request with one of the three outcomes.
func FuzzParseAndApply(f *testing.F) {
	for _, d := range seedDocuments {
		f.Add([]byte(d), "ec2:RunInstances", "arn:aws:ec2:us-east-1:111111111111:instance/*", "arn:aws:iam::111111111111:role/*", "us-east-1")
	}
	f.Add([]byte(seedDocuments[4]), "s3:GetObject", "", "999999999999", "")
	f.Fuzz(func(t *testing.T, doc []byte, action, resource, principal, region string) {
		d, err := Parse(doc)
		if err != nil {
			if d != nil {
				t.Fatal("a parse error must not come with a document")
			}
			return
		}
		ctx := Context{}
		if region != "" {
			ctx.Set("aws:RequestedRegion", Known(region))
		}
		ctx.Set("aws:PrincipalOrgID", Known("o-fuzz00000001"))
		ctx.Set("aws:PrincipalArn", Known(principal))
		ctx.Set("aws:PrincipalTag/*", Absent())
		req := Request{Action: action, Resource: resource, Principal: principal, Context: ctx}
		for i := range d.Statements {
			st := &d.Statements[i]
			if !strings.EqualFold(st.Effect, "Allow") && !strings.EqualFold(st.Effect, "Deny") {
				t.Fatalf("parsed statement with effect %q", st.Effect)
			}
			if len(st.Actions) == 0 && len(st.NotActions) == 0 {
				t.Fatal("parsed statement without actions")
			}
			m := st.Applies(req)
			if m.Outcome != Yes && m.Outcome != No && m.Outcome != Unknown {
				t.Fatalf("outcome out of range: %v", m.Outcome)
			}
			if m.Outcome == Unknown && m.Reason == "" {
				t.Fatal("an unknown outcome must carry a reason")
			}
			_ = st.Label()
		}
	})
}

// FuzzGlob checks the pattern algorithms against each other: they must not
// panic, coverage must imply overlap, on a plain string coverage of the
// whole string must agree with matching, coverage component by component
// must imply coverage of the whole string, and the three matching modes
// must stay consistent with them. The case that separates the modes is an
// ARN-shaped pattern whose wildcard would have to stand for a colon
// ("Arn:*::::" against "Arn::::::", which the fuzzer found): a string
// operator matches it, an ARN operator does not, and the Resource element
// matches it only because the '*' ends its component.
func FuzzGlob(f *testing.F) {
	for _, c := range [][2]string{
		{"*", "anything"}, {"ec2:*", "ec2:Describe*"}, {"ec2:Describe*", "ec2:*"}, {"a*b*c", "a?b*c*"}, {"***", ""},
		{"arn:aws:s3:::bucket/*", "arn:aws:s3:::bucket/key"}, {"arn:aws:iam::*:role/Admin*", "arn:aws:iam::111111111111:role/*"},
		{strings.Repeat("*a", 40), strings.Repeat("a", 60)}, {strings.Repeat("a*", 40) + "b", strings.Repeat("a", 80)},
		{"Arn:*::::", "Arn::::::"}, {"arn:aws:s3:*:x:y", "arn:aws:s3:a:b:x:y"}, {"arn:aws:s3:a*b:x:y", "arn:aws:s3:a:b:x:y"}, {"arn:aws:s3:?:x:y:z", "arn:aws:s3:::x:y:z"},
	} {
		f.Add(c[0], c[1])
	}
	f.Fuzz(func(t *testing.T, p, v string) {
		if len(p) > maxPatternLen || len(v) > maxPatternLen {
			return
		}
		for _, fold := range []bool{false, true} {
			fp, fv := p, v
			if fold {
				fp, fv = strings.ToLower(p), strings.ToLower(v)
			}
			matched := globMatch(p, v, fold)
			cov := covers(p, v, fold)
			ov := overlaps(p, v, fold)
			flat, flatOverlap := coverDP(fp, fv), overlapsFlat(fp, fv)
			if cov && !ov {
				t.Fatalf("covers(%q,%q) but not overlaps", p, v)
			}
			if !hasWildcard(v) && flat != matched {
				t.Fatalf("on a plain string coverage of the whole string (%v) must agree with match (%v): %q %q", flat, matched, p, v)
			}
			if cov && !flat {
				t.Fatalf("coverage component by component without coverage of the whole string: %q %q", p, v)
			}
			if matched && !flatOverlap {
				t.Fatalf("match without overlap: %q %q", p, v)
			}
			// The three modes.
			str, arn, res := compare(p, v, fold, modeString), compare(p, v, fold, modeARN), compare(p, v, fold, modeResource)
			if (arn == Yes) != cov {
				t.Fatalf("ARN mode is coverage component by component: %v vs %v for %q %q", arn, cov, p, v)
			}
			if cov && (str != Yes || res != Yes) {
				t.Fatalf("what matches component by component matches in every mode: %v %v for %q %q", str, res, p, v)
			}
			if (str == Yes) != flat {
				t.Fatalf("string mode is coverage of the whole string: %v vs %v for %q %q", str, flat, p, v)
			}
			if flat && res == No {
				t.Fatalf("the Resource element must not rule out a pattern that matches the whole string: %q %q", p, v)
			}
			if res == Yes && !flat {
				t.Fatalf("the Resource element cannot match what does not match the whole string: %q %q", p, v)
			}
			if ov && (str == No || arn == No || res == No) {
				t.Fatalf("patterns that overlap component by component are never a No: %v %v %v for %q %q", str, arn, res, p, v)
			}
			if !hasWildcard(v) {
				// A concrete string is decided, except where the Resource
				// element leaves a colon crossing undocumented.
				if str == Unknown || arn == Unknown {
					t.Fatalf("a concrete string is a yes or a no for the operators: %v %v for %q %q", str, arn, p, v)
				}
				if !flat && res != No {
					t.Fatalf("a concrete string the pattern does not match is a No: %v for %q %q", res, p, v)
				}
			}
			if overlapNames(fp, fv) && !flatOverlap {
				t.Fatalf("an overlap with names for wildcards is an overlap: %q %q", p, v)
			}
		}
	})
}

// TestWildcardModes pins the documented differences between the places a
// pattern can stand in: an ARN operator checks the six components one by
// one, a string operator matches anywhere in the string, and in the
// Resource element a '*' that ends a component can expand beyond the colon.
func TestWildcardModes(t *testing.T) {
	cases := []struct {
		p, v          string
		str, arn, res Outcome
	}{
		// Components line up: every mode agrees.
		{"arn:aws:s3:::bucket/*", "arn:aws:s3:::bucket/key", Yes, Yes, Yes},
		{"arn:aws:iam::*:role/Admin*", "arn:aws:iam::111111111111:role/AdminOps", Yes, Yes, Yes},
		{"arn:aws:iam::*:role/Admin*", "arn:aws:iam::111111111111:role/Reader", No, No, No},
		{"arn:aws:logs:*:*:*", "arn:aws:logs:us-east-1:111111111111:log-group:app:*", Yes, Yes, Yes},
		// A '*' that ends its component has to stand for a colon: a string
		// operator and the Resource element match, an ARN operator does not.
		{"arn:aws:s3:*:x:y", "arn:aws:s3:a:b:x:y", Yes, No, Yes},
		{"arn:*::::", "arn::::::", Yes, No, Yes},
		// A wildcard in the middle of a component, or a '?', would have to
		// stand for a colon: the documentation does not say, so the
		// Resource element is unknown rather than a silent no.
		{"arn:aws:s3:a*b:x:y", "arn:aws:s3:a:b:x:y", Yes, No, Unknown},
		{"arn:aws:s3:?:x:y:z", "arn:aws:s3:::x:y:z", Yes, No, Unknown},
		// A value that is itself a pattern: covered, overlapping or disjoint.
		{"arn:aws:iam::*:role/*", "arn:aws:iam::111111111111:role/Admin*", Yes, Yes, Yes},
		{"arn:aws:iam::111111111111:role/Admin", "arn:aws:iam::111111111111:role/*", Unknown, Unknown, Unknown},
		{"arn:aws:iam::111111111111:role/Admin", "arn:aws:iam::222222222222:role/*", No, No, No},
		// "Any role of the account" against the root-user pattern: the '*' of
		// the value stands for a role name, which holds no colon, so the
		// pattern for the root user cannot match it in any mode.
		{"arn:aws:iam::*:root", "arn:aws:iam::111111111111:role/*", No, No, No},
		// A pattern that leaves a component out reaches a wildcard value by
		// letting its '*' stand for a colon: possible, so never a No outside
		// the ARN operators.
		{"arn:aws:logs:*:log-group:prod", "arn:aws:logs:us-east-1:111111111111:log-group:*", Unknown, No, Unknown},
		{"arn:aws:logs:*:log-group:prod", "arn:aws:logs:us-east-1:111111111111:log-group:prod", Yes, No, Yes},
		// Inside the last component colons are ordinary characters.
		{"arn:aws:logs:*:*:log-group:*:log-stream:*", "arn:aws:logs:us-east-1:111111111111:log-group:*", Unknown, Unknown, Unknown},
		// Not two ARNs of six components: one flat comparison in every mode.
		{"ec2:Describe*", "ec2:DescribeInstances", Yes, Yes, Yes},
		{"arn:aws:s3:*", "arn:aws:s3:::bucket/key", Yes, Yes, Yes},
	}
	for _, c := range cases {
		if got := compare(c.p, c.v, false, modeString); got != c.str {
			t.Errorf("string mode %q vs %q: got %v, want %v", c.p, c.v, got, c.str)
		}
		if got := compare(c.p, c.v, false, modeARN); got != c.arn {
			t.Errorf("ARN mode %q vs %q: got %v, want %v", c.p, c.v, got, c.arn)
		}
		if got := compare(c.p, c.v, false, modeResource); got != c.res {
			t.Errorf("resource mode %q vs %q: got %v, want %v", c.p, c.v, got, c.res)
		}
	}
	// Through the statement matcher: a Deny whose Resource pattern reaches
	// the resource only across a colon is not missed.
	d, err := Parse([]byte(`{"Statement":[{"Effect":"Deny","Action":"s3:GetObject","Resource":["arn:aws:s3:*:x:y"]},{"Effect":"Deny","Action":"s3:GetObject","Resource":["arn:aws:s3:a*b:x:y"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	req := Request{Action: "s3:GetObject", Resource: "arn:aws:s3:a:b:x:y"}
	if m := d.Statements[0].Applies(req); m.Outcome != Yes {
		t.Errorf("a trailing '*' crosses the colon in the Resource element: %+v", m)
	}
	if m := d.Statements[1].Applies(req); m.Outcome != Unknown || m.Reason == "" {
		t.Errorf("an undocumented crossing is unknown, with a reason: %+v", m)
	}
	// And through the condition operators.
	ctx := Context{}
	ctx.Set("aws:PrincipalArn", Known("arn:aws:s3:a:b:x:y"))
	like := Condition{Operator: "StringLike", Key: "aws:PrincipalArn", Values: []string{"arn:aws:s3:*:x:y"}}
	arnLike := Condition{Operator: "ArnLike", Key: "aws:PrincipalArn", Values: []string{"arn:aws:s3:*:x:y"}}
	if o, _ := evalCondition(like, ctx); o != Yes {
		t.Errorf("StringLike matches anywhere in the string: %v", o)
	}
	if o, _ := evalCondition(arnLike, ctx); o != No {
		t.Errorf("ArnLike checks the six components separately: %v", o)
	}
}

// TestGlobAgainstReference compares the iterative matcher with a plain
// recursive one on a grid of small patterns, so a slip in the loop logic
// shows up without the fuzzer.
func TestGlobAgainstReference(t *testing.T) {
	var ref func(p, s string) bool
	ref = func(p, s string) bool {
		if p == "" {
			return s == ""
		}
		switch p[0] {
		case '*':
			for i := 0; i <= len(s); i++ {
				if ref(p[1:], s[i:]) {
					return true
				}
			}
			return false
		case '?':
			return s != "" && ref(p[1:], s[1:])
		}
		return s != "" && s[0] == p[0] && ref(p[1:], s[1:])
	}
	alphabet := []string{"a", "b", "*", "?"}
	var gen func(prefix string, n int, out *[]string)
	gen = func(prefix string, n int, out *[]string) {
		*out = append(*out, prefix)
		if n == 0 {
			return
		}
		for _, c := range alphabet {
			gen(prefix+c, n-1, out)
		}
	}
	var pats, strs []string
	gen("", 4, &pats)
	for _, s := range pats {
		if !hasWildcard(s) {
			strs = append(strs, s)
		}
	}
	for _, p := range pats {
		for _, s := range strs {
			if got, want := glob(p, s), ref(p, s); got != want {
				t.Fatalf("glob(%q,%q)=%v want %v", p, s, got, want)
			}
			// Coverage of a plain string is exactly matching.
			if got, want := coverDP(p, s), ref(p, s); got != want {
				t.Fatalf("coverDP(%q,%q)=%v want %v", p, s, got, want)
			}
		}
	}
	// Coverage between two patterns: p covers v when every string v matches, p matches too.
	for _, p := range pats {
		for _, v := range pats {
			if coverDP(p, v) {
				for _, s := range strs {
					if ref(v, s) && !ref(p, s) {
						t.Fatalf("coverDP(%q,%q) claims coverage but %q is matched by v only", p, v, s)
					}
				}
			}
			// Overlap: a common string inside the small universe proves
			// overlap; the converse does not hold, because the witness may
			// be longer than the universe allows (aaa* and a*ba share aaaba).
			for _, s := range strs {
				if ref(p, s) && ref(v, s) && !overlapsFlat(p, v) {
					t.Fatalf("overlapsFlat(%q,%q) is false but both match %q", p, v, s)
				}
			}
		}
	}
}

func TestOversizedPatternsAnswerConservatively(t *testing.T) {
	big := strings.Repeat("a", maxPatternLen+1)
	if glob(big, big) || coverDP(big, big) {
		t.Fatal("oversized inputs must not be reported as matched or covered")
	}
	if !overlapsFlat(big, big) {
		t.Fatal("oversized inputs must be reported as possibly overlapping")
	}
	// Patterns that made the recursive matcher backtrack exponentially.
	p := strings.Repeat("a*", 30) + "b"
	s := strings.Repeat("a", 2000)
	if glob(p, s) || coverDP(p, s) {
		t.Fatal("should not match")
	}
	if !overlapsFlat(p, "*") {
		t.Fatal("everything overlaps with *")
	}
}
