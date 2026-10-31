package policy

import (
	"fmt"
	"strings"
)

// evalCondition evaluates one condition triple against the context.
func evalCondition(c Condition, ctx Context) (Outcome, string) {
	op := c.Operator
	setOp := ""
	for _, prefix := range []string{"ForAnyValue:", "ForAllValues:"} {
		if strings.HasPrefix(op, prefix) {
			setOp = strings.TrimSuffix(prefix, ":")
			op = strings.TrimPrefix(op, prefix)
		}
	}
	ifExists := strings.HasSuffix(op, "IfExists")
	op = strings.TrimSuffix(op, "IfExists")

	for _, v := range c.Values {
		if strings.Contains(v, "${") {
			return Unknown, fmt.Sprintf("%s %s uses a policy variable (%s) that cannot be resolved offline", c.Operator, c.Key, v)
		}
	}

	val := ctx.Lookup(c.Key)
	if !val.Known {
		return Unknown, fmt.Sprintf("%s %s cannot be evaluated: the value of %s is not known for this account", c.Operator, c.Key, c.Key)
	}
	present := len(val.Values) > 0

	if op == "Null" {
		// "true" means the key must be absent.
		wantAbsent := len(c.Values) > 0 && strings.EqualFold(c.Values[0], "true")
		if present != wantAbsent {
			return Yes, ""
		}
		return No, ""
	}

	negated := strings.Contains(op, "Not")
	if !present {
		// Missing keys satisfy ...IfExists and negated operators; every other
		// operator fails.
		if ifExists || negated || setOp == "ForAllValues" {
			return Yes, ""
		}
		return No, ""
	}

	cmp, ok := comparator(op)
	if !ok {
		return Unknown, fmt.Sprintf("condition operator %s is not supported by the offline evaluator", c.Operator)
	}

	matches := make([]bool, 0, len(val.Values))
	for _, have := range val.Values {
		m := false
		for _, want := range c.Values {
			if cmp(want, have) {
				m = true
				break
			}
		}
		if negated {
			m = !m
		}
		matches = append(matches, m)
	}
	switch setOp {
	case "ForAllValues":
		for _, m := range matches {
			if !m {
				return No, ""
			}
		}
		return Yes, ""
	default: // ForAnyValue and single-valued keys
		for _, m := range matches {
			if m {
				return Yes, ""
			}
		}
		return No, ""
	}
}

// comparator returns the positive comparison for an operator (the "Not" is
// handled by the caller).
func comparator(op string) (func(want, have string) bool, bool) {
	switch strings.ReplaceAll(op, "Not", "") {
	case "StringEquals":
		return func(w, h string) bool { return w == h }, true
	case "StringEqualsIgnoreCase":
		return strings.EqualFold, true
	case "StringLike":
		return func(w, h string) bool { return globMatch(w, h, false) }, true
	case "ArnEquals", "ArnLike":
		return func(w, h string) bool { return globMatch(w, h, false) }, true
	case "Bool":
		return strings.EqualFold, true
	}
	return nil, false
}
