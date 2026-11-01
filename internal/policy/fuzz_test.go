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
// panic, coverage must imply overlap, and on a plain string coverage must
// agree with matching.
func FuzzGlob(f *testing.F) {
	for _, c := range [][2]string{
		{"*", "anything"}, {"ec2:*", "ec2:Describe*"}, {"ec2:Describe*", "ec2:*"}, {"a*b*c", "a?b*c*"}, {"***", ""},
		{"arn:aws:s3:::bucket/*", "arn:aws:s3:::bucket/key"}, {"arn:aws:iam::*:role/Admin*", "arn:aws:iam::111111111111:role/*"},
		{strings.Repeat("*a", 40), strings.Repeat("a", 60)}, {strings.Repeat("a*", 40) + "b", strings.Repeat("a", 80)},
	} {
		f.Add(c[0], c[1])
	}
	f.Fuzz(func(t *testing.T, p, v string) {
		for _, fold := range []bool{false, true} {
			matched := globMatch(p, v, fold)
			cov := covers(p, v, fold)
			ov := overlaps(p, v, fold)
			if cov && !ov && len(p) <= maxPatternLen && len(v) <= maxPatternLen {
				t.Fatalf("covers(%q,%q) but not overlaps", p, v)
			}
			if !hasWildcard(v) && len(p) <= maxPatternLen && len(v) <= maxPatternLen && cov != matched {
				t.Fatalf("on a plain string covers (%v) must agree with match (%v): %q %q", cov, matched, p, v)
			}
			if matched && !ov && len(p) <= maxPatternLen && len(v) <= maxPatternLen {
				t.Fatalf("match without overlap: %q %q", p, v)
			}
		}
	})
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
