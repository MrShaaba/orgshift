package policy

import "strings"

// Policy variables (${aws:PrincipalTag/team}) in the Resource and
// NotResource elements. Checked against the IAM User Guide page on policy
// variables on 2026-11-05.

type variableState int

const (
	// variableNone: the pattern has no variable.
	variableNone variableState = iota
	// variableResolved: every variable was replaced by its value.
	variableResolved
	// variableNoValue: a variable is known to have no value and no default,
	// so the pattern matches no resource.
	variableNoValue
	// variableUnresolved: the value of a variable is not known offline. The
	// returned pattern has a wildcard in its place.
	variableUnresolved
)

// resolveVariables replaces the policy variables of a resource pattern with
// their values from the request context. It returns the pattern to match
// with, how far the variables could be resolved, and the variables that
// could not be.
func resolveVariables(pattern string, ctx Context) (string, variableState, []string) {
	if !strings.Contains(pattern, "${") {
		return pattern, variableNone, nil
	}
	var out strings.Builder
	state := variableResolved
	var unresolved []string
	rest := pattern
	for {
		i := strings.Index(rest, "${")
		if i < 0 {
			out.WriteString(rest)
			break
		}
		end := strings.Index(rest[i:], "}")
		if end < 0 {
			// An unterminated "${" is text the grammar does not define;
			// nothing can be said about what it matches.
			out.WriteString(rest[:i])
			out.WriteString("*")
			return out.String(), variableUnresolved, []string{rest[i:]}
		}
		out.WriteString(rest[:i])
		inner := rest[i+2 : i+end]
		whole := rest[i : i+end+1]
		rest = rest[i+end+1:]
		name, def, hasDefault := splitDefault(inner)
		switch name {
		case "*", "?", "$":
			// ${*}, ${?} and ${$} stand for the literal character. The
			// matcher has no way to escape a wildcard, so the pattern is
			// treated as undecided rather than matched wrongly.
			out.WriteString("*")
			state = variableUnresolved
			unresolved = append(unresolved, whole)
			continue
		}
		val := ctx.Lookup(name)
		switch {
		case !val.Known:
			out.WriteString("*")
			state = variableUnresolved
			unresolved = append(unresolved, whole)
		case len(val.Values) == 0:
			if !hasDefault {
				return pattern, variableNoValue, nil
			}
			out.WriteString(def)
		case len(val.Values) == 1 && !hasWildcard(val.Values[0]):
			out.WriteString(val.Values[0])
		default:
			// Several values, or a value that is itself a pattern standing
			// for a set of strings: not one string to put in its place.
			out.WriteString("*")
			state = variableUnresolved
			unresolved = append(unresolved, whole)
		}
	}
	return out.String(), state, unresolved
}

// splitDefault splits "aws:PrincipalTag/team, 'shared'" into the key and
// its default value.
func splitDefault(inner string) (name, def string, hasDefault bool) {
	i := strings.Index(inner, ",")
	if i < 0 {
		return strings.TrimSpace(inner), "", false
	}
	name = strings.TrimSpace(inner[:i])
	d := strings.TrimSpace(inner[i+1:])
	if len(d) >= 2 && strings.HasPrefix(d, "'") && strings.HasSuffix(d, "'") {
		return name, d[1 : len(d)-1], true
	}
	return name, "", false
}
