package policy

import "strings"

// maxPatternLen bounds the inputs of the pattern algorithms. AWS limits a
// policy document to a few kilobytes and an ARN to 2048 characters, so
// anything larger is not a real policy value; the matchers then answer
// conservatively (not matched, not covered, possibly overlapping) instead
// of spending time on it.
const maxPatternLen = 16 * 1024

// globMatch reports whether pattern (with * and ? wildcards) matches s.
// The comparison is case-insensitive when fold is true.
func globMatch(pattern, s string, fold bool) bool {
	if fold {
		pattern = strings.ToLower(pattern)
		s = strings.ToLower(s)
	}
	return glob(pattern, s)
}

// glob is the classic linear-space wildcard matcher: it walks both strings
// once and backtracks to the most recent '*' when a literal stops matching.
// It never recurses, so hostile patterns cannot exhaust the stack or take
// exponential time.
func glob(p, s string) bool {
	if len(p) > maxPatternLen || len(s) > maxPatternLen {
		return false
	}
	pi, si := 0, 0
	star, match := -1, 0
	for si < len(s) {
		switch {
		case pi < len(p) && (p[pi] == '?' || p[pi] == s[si]):
			pi++
			si++
		case pi < len(p) && p[pi] == '*':
			star, match = pi, si
			pi++
		case star >= 0:
			pi = star + 1
			match++
			si = match
		default:
			return false
		}
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}

// matchMode says where a pattern stands in a policy, because IAM matches
// wildcards differently there (checked against the IAM User Guide on
// 2026-11-05):
//
//   - the ARN condition operators check "each of the six colon-delimited
//     components of the ARN" separately;
//   - the string condition operators match wildcards "anywhere in the
//     string", with no format;
//   - in the Resource element wildcards belong inside the segments of an
//     ARN, but "if the * wildcard is the last character of a resource ARN
//     segment, it can expand to match beyond the colon boundaries".
type matchMode int

const (
	// modeString matches the whole string: a wildcard can stand for a colon.
	modeString matchMode = iota
	// modeARN matches the six ARN components one by one.
	modeARN
	// modeResource matches the components one by one, lets a '*' that ends
	// a component cross the colon as documented, and answers Unknown when a
	// match needs any other wildcard to cross one, which the documentation
	// does not describe.
	modeResource
)

// compare matches a value against a pattern: Yes when the pattern matches
// it, No when it does not, Unknown when that cannot be decided.
//
// A value without wildcards is a concrete string, and the documented rules
// of the mode apply to it literally. A value with wildcards stands for a
// set of strings (the evaluator writes "any role of the account" as
// role/*): the answer is Yes when the pattern covers all of them and
// Unknown when it can match some. There a wildcard of the value stands for
// a name, never for further colon-separated parts of an ARN, so a pattern
// such as arn:aws:iam::*:root does not match arn:aws:iam::111111111111:role/*.
// Answering Unknown rather than No where the documentation is silent keeps
// a Deny from being missed.
func compare(p, v string, fold bool, mode matchMode) Outcome {
	if fold {
		p, v = strings.ToLower(p), strings.ToLower(v)
	}
	ps, vs, shaped := arnSegments(p, v)
	if !shaped {
		switch {
		case coverDP(p, v):
			return Yes
		case hasWildcard(v) && overlapsFlat(p, v):
			return Unknown
		}
		return No
	}
	segmented := coverSegments(ps, vs)
	if segmented {
		return Yes
	}
	if mode == modeARN {
		if hasWildcard(v) && overlapSegments(ps, vs) {
			return Unknown
		}
		return No
	}
	// The components do not line up: the pattern can only match by letting
	// one of its wildcards stand for a colon. A string operator allows that
	// anywhere; the Resource element documents it for a '*' that ends a
	// component and is silent about the rest.
	if coverDP(p, v) {
		if mode == modeResource && !onlyTrailingStars(ps) {
			return Unknown
		}
		return Yes
	}
	if hasWildcard(v) && (overlapSegments(ps, vs) || overlapNames(p, v)) {
		return Unknown
	}
	return No
}

// overlapNames reports whether a pattern and a value pattern can match a
// common string when the wildcards of the pattern may stand for anything,
// colons included, and the wildcards of the value only for text without a
// colon (a name). It is the product of the two patterns walked as a dynamic
// program, in O(len(p)*len(v)) time and O(len(v)) memory.
func overlapNames(p, v string) bool {
	n, m := len(p), len(v)
	if n > maxPatternLen || m > maxPatternLen {
		return true
	}
	wild := func(c byte) bool { return c == '*' || c == '?' }
	prev := make([]bool, m+1) // row i+1
	cur := make([]bool, m+1)  // row i
	prev[m] = true
	for j := m - 1; j >= 0; j-- {
		prev[j] = v[j] == '*' && prev[j+1]
	}
	for i := n - 1; i >= 0; i-- {
		cur[m] = p[i] == '*' && prev[m]
		for j := m - 1; j >= 0; j-- {
			pStar, vStar := p[i] == '*', v[j] == '*'
			ok := (pStar && prev[j]) || (vStar && cur[j+1])
			// Consume one character that both sides accept.
			var compatible bool
			switch {
			case !wild(p[i]) && !wild(v[j]):
				compatible = p[i] == v[j]
			case !wild(p[i]):
				compatible = p[i] != ':' // the value's wildcard is a name
			default:
				compatible = true // the pattern's wildcard takes anything the value offers
			}
			if compatible && !ok && !(pStar && vStar) {
				switch {
				case pStar:
					ok = cur[j+1]
				case vStar:
					ok = prev[j]
				default:
					ok = prev[j+1]
				}
			}
			cur[j] = ok
		}
		prev, cur = cur, prev
	}
	return prev[0]
}

// onlyTrailingStars reports whether every wildcard in the first five
// components of a pattern is a '*' that ends its component, the one case
// in which the documentation lets a wildcard cross a colon.
func onlyTrailingStars(segments []string) bool {
	for _, s := range segments[:len(segments)-1] {
		if strings.Contains(s, "?") {
			return false
		}
		if i := strings.Index(s, "*"); i >= 0 && strings.TrimRight(s[i:], "*") != "" {
			return false
		}
	}
	return true
}

// covers reports whether every string matched by the value pattern v is also
// matched by p, component by component for two ARNs. Wildcards in v can only
// be absorbed by a '*' in p, which makes the check sound (never claims
// coverage that does not hold) though not complete for exotic patterns.
func covers(p, v string, fold bool) bool {
	if fold {
		p, v = strings.ToLower(p), strings.ToLower(v)
	}
	if ps, vs, ok := arnSegments(p, v); ok {
		return coverSegments(ps, vs)
	}
	return coverDP(p, v)
}

// coverSegments reports whether every component of a pattern covers the
// same component of the value.
func coverSegments(ps, vs []string) bool {
	for i := range ps {
		if !coverDP(ps[i], vs[i]) {
			return false
		}
	}
	return true
}

// overlapSegments reports whether every pair of components can match a
// common string.
func overlapSegments(as, bs []string) bool {
	for i := range as {
		if !overlapsFlat(as[i], bs[i]) {
			return false
		}
	}
	return true
}

// arnSegments splits two ARN-shaped values into their six colon-separated
// segments so wildcards are matched per segment, as IAM does for ARNs.
func arnSegments(a, b string) ([]string, []string, bool) {
	if !strings.HasPrefix(a, "arn:") || !strings.HasPrefix(b, "arn:") {
		return nil, nil, false
	}
	as, bs := strings.SplitN(a, ":", 6), strings.SplitN(b, ":", 6)
	if len(as) != 6 || len(bs) != 6 {
		return nil, nil, false
	}
	return as, bs, true
}

// coverDP decides coverage with a dynamic program over the two patterns:
// row i holds, for every j, whether p[i:] covers v[j:]. It runs in
// O(len(p)*len(v)) time and O(len(v)) memory, with no recursion.
func coverDP(p, v string) bool {
	n, m := len(p), len(v)
	if n > maxPatternLen || m > maxPatternLen {
		return false
	}
	prev := make([]bool, m+1)
	cur := make([]bool, m+1)
	prev[m] = true // an exhausted pattern covers only the exhausted value
	for i := n - 1; i >= 0; i-- {
		switch p[i] {
		case '*':
			// '*' covers v[j:] when the rest of the pattern covers some
			// suffix of it; a trailing run of '*' covers everything.
			acc := false
			for j := m; j >= 0; j-- {
				acc = acc || prev[j]
				cur[j] = acc
			}
		case '?':
			for j := 0; j < m; j++ {
				cur[j] = v[j] != '*' && v[j] != '?' && prev[j+1]
			}
			cur[m] = false
		default:
			for j := 0; j < m; j++ {
				cur[j] = v[j] == p[i] && prev[j+1]
			}
			cur[m] = false
		}
		prev, cur = cur, prev
	}
	return prev[0]
}

// overlaps reports whether two glob patterns can match a common string,
// component by component for two ARNs.
func overlaps(a, b string, fold bool) bool {
	if fold {
		a, b = strings.ToLower(a), strings.ToLower(b)
	}
	if as, bs, ok := arnSegments(a, b); ok {
		return overlapSegments(as, bs)
	}
	return overlapsFlat(a, b)
}

// overlapsFlat is the same dynamic program for the symmetric question: row
// i holds whether a[i:] and b[j:] can match a common string. Oversized
// inputs are reported as possibly overlapping, which callers treat as
// "unknown" rather than as a match.
func overlapsFlat(a, b string) bool {
	n, m := len(a), len(b)
	if n > maxPatternLen || m > maxPatternLen {
		return true
	}
	prev := make([]bool, m+1)
	cur := make([]bool, m+1)
	prev[m] = true
	for j := m - 1; j >= 0; j-- {
		prev[j] = b[j] == '*' && prev[j+1]
	}
	for i := n - 1; i >= 0; i-- {
		cur[m] = a[i] == '*' && prev[m]
		for j := m - 1; j >= 0; j-- {
			switch {
			case a[i] == '*':
				cur[j] = prev[j] || cur[j+1]
			case b[j] == '*':
				cur[j] = cur[j+1] || prev[j]
			case a[i] == b[j] || a[i] == '?' || b[j] == '?':
				cur[j] = prev[j+1]
			default:
				cur[j] = false
			}
		}
		prev, cur = cur, prev
	}
	return prev[0]
}

// hasWildcard reports whether s contains glob wildcards.
func hasWildcard(s string) bool { return strings.ContainsAny(s, "*?") }
