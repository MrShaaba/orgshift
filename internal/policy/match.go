package policy

import (
	"fmt"
	"strings"
)

// Outcome is a tri-state match result.
type Outcome int

// Outcome values.
const (
	No Outcome = iota
	Yes
	Unknown
)

func (o Outcome) String() string {
	switch o {
	case Yes:
		return "yes"
	case No:
		return "no"
	}
	return "unknown"
}

// Value is the value of a request context key. Known with no values means
// the key is known to be absent from the request.
type Value struct {
	Known  bool
	Values []string
}

// Known builds a known context value.
func Known(values ...string) Value { return Value{Known: true, Values: values} }

// Absent builds a context value that is known to be missing.
func Absent() Value { return Value{Known: true} }

// UnknownValue builds a context value the evaluator cannot determine.
func UnknownValue() Value { return Value{} }

// Context maps lower-cased condition keys to values. A family entry such as
// "aws:principaltag/*" set to Absent() declares that every key in that
// family is known, so keys without an explicit entry are absent.
type Context map[string]Value

// Set stores a value under a key (case-insensitive).
func (c Context) Set(key string, v Value) { c[strings.ToLower(key)] = v }

// Lookup finds a key, falling back to its family entry.
func (c Context) Lookup(key string) Value {
	k := strings.ToLower(key)
	if v, ok := c[k]; ok {
		return v
	}
	if i := strings.Index(k, "/"); i > 0 {
		if fam, ok := c[k[:i+1]+"*"]; ok && fam.Known {
			return Absent()
		}
	}
	return UnknownValue()
}

// Request is what a statement is matched against.
type Request struct {
	Action string
	// Resource is an ARN or ARN pattern; empty means unknown.
	Resource string
	// Principal is the caller's ARN or account ID; empty means unknown. Only
	// used for statements that carry a Principal element (RCPs).
	Principal string
	Context   Context
}

// Match is the result of matching a statement.
type Match struct {
	Outcome Outcome
	// Reason explains an Unknown outcome, or names the matched element.
	Reason string
}

// Applies decides whether a statement applies to a request.
func (s *Statement) Applies(req Request) Match {
	parts := []Match{
		s.matchAction(req.Action),
		s.matchResource(req.Resource, req.Context),
		s.matchPrincipal(req.Principal),
		s.matchConditions(req.Context),
	}
	var unknown []string
	for _, m := range parts {
		switch m.Outcome {
		case No:
			return Match{Outcome: No, Reason: m.Reason}
		case Unknown:
			unknown = append(unknown, m.Reason)
		}
	}
	if len(unknown) > 0 {
		return Match{Outcome: Unknown, Reason: strings.Join(unknown, "; ")}
	}
	return Match{Outcome: Yes}
}

// matchPatterns matches a value (which may itself be a pattern) against a
// list of patterns, with the wildcard semantics of the place the patterns
// stand in.
func matchPatterns(patterns []string, value string, fold bool, mode matchMode) Outcome {
	out := No
	for _, p := range patterns {
		switch compare(p, value, fold, mode) {
		case Yes:
			return Yes
		case Unknown:
			out = Unknown
		}
	}
	return out
}

// MatchAction matches an action (possibly a wildcard) against patterns.
func MatchAction(patterns []string, action string) Outcome {
	return matchPatterns(patterns, action, true, modeString)
}

func (s *Statement) matchAction(action string) Match {
	if len(s.NotActions) > 0 {
		switch MatchAction(s.NotActions, action) {
		case Yes:
			return Match{Outcome: No, Reason: "action is excluded by NotAction"}
		case Unknown:
			return Match{Outcome: Unknown, Reason: fmt.Sprintf("%s only partly overlaps the NotAction list", action)}
		}
		return Match{Outcome: Yes}
	}
	switch MatchAction(s.Actions, action) {
	case Yes:
		return Match{Outcome: Yes}
	case Unknown:
		return Match{Outcome: Unknown, Reason: fmt.Sprintf("%s only partly overlaps the Action list", action)}
	}
	return Match{Outcome: No, Reason: "action not listed"}
}

func (s *Statement) matchResource(resource string, ctx Context) Match {
	if !s.HasResourceElement() {
		// No Resource element: a statement of a policy attached to a
		// resource (a role trust policy) is about that resource.
		return Match{Outcome: Yes}
	}
	patterns, negate := s.Resources, false
	if len(s.NotResources) > 0 {
		patterns, negate = s.NotResources, true
	}
	allStar := len(patterns) == 1 && patterns[0] == "*"
	if allStar {
		if negate {
			return Match{Outcome: No, Reason: "NotResource * excludes everything"}
		}
		return Match{Outcome: Yes}
	}
	if resource == "" {
		return Match{Outcome: Unknown, Reason: "statement is scoped to specific resources and the resource in use is unknown"}
	}
	o, unresolved := matchResourcePatterns(patterns, resource, ctx)
	element := "Resource"
	if negate {
		element = "NotResource"
	}
	variableReason := ""
	if len(unresolved) > 0 {
		variableReason = fmt.Sprintf("%s names a policy variable (%s) whose value is not known for this request, so the statement may or may not apply; give the principal's tags or attributes in the usage entry to decide it", element, strings.Join(unresolved, ", "))
	}
	if negate {
		switch o {
		case Yes:
			return Match{Outcome: No, Reason: "resource excluded by NotResource"}
		case No:
			return Match{Outcome: Yes}
		}
		if variableReason != "" {
			return Match{Outcome: Unknown, Reason: variableReason}
		}
		return Match{Outcome: Unknown, Reason: "resource only partly overlaps the NotResource list"}
	}
	switch o {
	case Yes:
		return Match{Outcome: Yes}
	case No:
		return Match{Outcome: No, Reason: "resource not listed"}
	}
	if variableReason != "" {
		return Match{Outcome: Unknown, Reason: variableReason}
	}
	return Match{Outcome: Unknown, Reason: "resource only partly overlaps the Resource list"}
}

// matchResourcePatterns matches a resource against the patterns of a
// Resource or NotResource element, resolving policy variables from the
// request context. It returns the variables that could not be resolved and
// on which the outcome depends.
//
// A variable whose value is known is substituted. A variable that is known
// to have no value makes its pattern match no resource, as IAM documents:
// "the resource that includes a policy variable with no value will not
// match any resource". A variable whose value is not known is neither: the
// pattern is tried with a wildcard in its place, and where that could match
// the outcome is unknown, never a definite non-match.
func matchResourcePatterns(patterns []string, resource string, ctx Context) (Outcome, []string) {
	out := No
	var unresolved []string
	for _, p := range patterns {
		rp, state, names := resolveVariables(p, ctx)
		switch state {
		case variableNoValue:
			continue
		case variableUnresolved:
			if compare(rp, resource, false, modeResource) != No {
				out = Unknown
				for _, n := range names {
					if !containsString(unresolved, n) {
						unresolved = append(unresolved, n)
					}
				}
			}
			continue
		}
		switch compare(rp, resource, false, modeResource) {
		case Yes:
			return Yes, nil
		case Unknown:
			out = Unknown
		}
	}
	if out != Unknown {
		unresolved = nil
	}
	return out, unresolved
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func (s *Statement) matchPrincipal(principal string) Match {
	if s.Principals == nil && s.NotPrincipals == nil {
		return Match{Outcome: Yes}
	}
	p, negate := s.Principals, false
	if p == nil {
		p, negate = s.NotPrincipals, true
	}
	o := principalMatches(p, principal)
	if negate {
		switch o {
		case Yes:
			return Match{Outcome: No, Reason: "principal excluded by NotPrincipal"}
		case No:
			return Match{Outcome: Yes}
		}
		return Match{Outcome: Unknown, Reason: "cannot tell whether the caller is excluded by NotPrincipal"}
	}
	switch o {
	case Yes:
		return Match{Outcome: Yes}
	case No:
		return Match{Outcome: No, Reason: "principal not listed"}
	}
	return Match{Outcome: Unknown, Reason: "cannot tell whether the caller matches the Principal element"}
}

func principalMatches(p *Principal, principal string) Outcome {
	if p.All {
		return Yes
	}
	if principal == "" {
		return Unknown
	}
	acct := AccountFromPrincipal(principal)
	isService := strings.HasSuffix(principal, ".amazonaws.com")
	for _, v := range p.Service {
		if isService && strings.EqualFold(v, principal) {
			return Yes
		}
	}
	for _, v := range p.AWS {
		switch {
		case v == "*":
			return Yes
		case v == principal:
			return Yes
		case len(v) == 12 && v == acct:
			return Yes
		case strings.HasSuffix(v, ":root") && AccountFromPrincipal(v) == acct && acct != "":
			return Yes
		case hasWildcard(v) && globMatch(v, principal, false):
			return Yes
		}
	}
	if len(p.Other) > 0 {
		return Unknown
	}
	return No
}

// AccountFromPrincipal extracts the account ID from an ARN or returns the
// value itself when it already is an account ID.
func AccountFromPrincipal(p string) string {
	if len(p) == 12 && strings.Trim(p, "0123456789") == "" {
		return p
	}
	parts := strings.Split(p, ":")
	if len(parts) >= 5 && parts[0] == "arn" && len(parts[4]) == 12 {
		return parts[4]
	}
	return ""
}

func (s *Statement) matchConditions(ctx Context) Match {
	var unknown []string
	for _, c := range s.Conditions {
		o, reason := evalCondition(c, ctx)
		switch o {
		case No:
			return Match{Outcome: No, Reason: fmt.Sprintf("condition %s %s not met", c.Operator, c.Key)}
		case Unknown:
			unknown = append(unknown, reason)
		}
	}
	if len(unknown) > 0 {
		return Match{Outcome: Unknown, Reason: strings.Join(unknown, "; ")}
	}
	return Match{Outcome: Yes}
}
