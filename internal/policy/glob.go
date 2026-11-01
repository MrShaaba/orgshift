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

// covers reports whether every string matched by the value pattern v is also
// matched by p. Wildcards in v can only be absorbed by a '*' in p, which makes
// the check sound (never claims coverage that does not hold) though not
// complete for exotic patterns.
func covers(p, v string, fold bool) bool {
	if fold {
		p, v = strings.ToLower(p), strings.ToLower(v)
	}
	if ps, vs, ok := arnSegments(p, v); ok {
		for i := range ps {
			if !coverDP(ps[i], vs[i]) {
				return false
			}
		}
		return true
	}
	return coverDP(p, v)
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

// overlaps reports whether two glob patterns can match a common string.
func overlaps(a, b string, fold bool) bool {
	if fold {
		a, b = strings.ToLower(a), strings.ToLower(b)
	}
	if as, bs, ok := arnSegments(a, b); ok {
		for i := range as {
			if !overlapsFlat(as[i], bs[i]) {
				return false
			}
		}
		return true
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
