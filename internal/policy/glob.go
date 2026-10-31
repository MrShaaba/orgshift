package policy

import "strings"

// globMatch reports whether pattern (with * and ? wildcards) matches s.
// The comparison is case-insensitive when fold is true.
func globMatch(pattern, s string, fold bool) bool {
	if fold {
		pattern = strings.ToLower(pattern)
		s = strings.ToLower(s)
	}
	return glob(pattern, s)
}

func glob(p, s string) bool {
	for len(p) > 0 {
		switch p[0] {
		case '*':
			p = strings.TrimLeft(p, "*")
			if p == "" {
				return true
			}
			for i := 0; i <= len(s); i++ {
				if glob(p, s[i:]) {
					return true
				}
			}
			return false
		case '?':
			if s == "" {
				return false
			}
		default:
			if s == "" || p[0] != s[0] {
				return false
			}
		}
		p, s = p[1:], s[1:]
	}
	return s == ""
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
			if !coverRec(ps[i], vs[i]) {
				return false
			}
		}
		return true
	}
	return coverRec(p, v)
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

func coverRec(p, v string) bool {
	for len(p) > 0 {
		switch p[0] {
		case '*':
			p = strings.TrimLeft(p, "*")
			if p == "" {
				return true
			}
			for i := 0; i <= len(v); i++ {
				if coverRec(p, v[i:]) {
					return true
				}
			}
			return false
		case '?':
			if v == "" || v[0] == '*' || v[0] == '?' {
				return false
			}
		default:
			if v == "" || v[0] != p[0] {
				return false
			}
		}
		p, v = p[1:], v[1:]
	}
	return v == ""
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

func overlapsFlat(a, b string) bool {
	memo := map[[2]int]bool{}
	var rec func(i, j int) bool
	rec = func(i, j int) bool {
		key := [2]int{i, j}
		if r, ok := memo[key]; ok {
			return r
		}
		var r bool
		switch {
		case i == len(a) && j == len(b):
			r = true
		case i < len(a) && a[i] == '*':
			r = rec(i+1, j) || (j < len(b) && rec(i, j+1))
		case j < len(b) && b[j] == '*':
			r = rec(i, j+1) || (i < len(a) && rec(i+1, j))
		case i < len(a) && j < len(b) && (a[i] == b[j] || a[i] == '?' || b[j] == '?'):
			r = rec(i+1, j+1)
		default:
			r = false
		}
		memo[key] = r
		return r
	}
	return rec(0, 0)
}

// hasWildcard reports whether s contains glob wildcards.
func hasWildcard(s string) bool { return strings.ContainsAny(s, "*?") }
