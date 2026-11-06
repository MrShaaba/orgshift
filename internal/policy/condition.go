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

	// Each context value yields Yes, No or Unknown (a wildcard context value
	// that only partly overlaps the policy value). Negation flips Yes and No.
	results := make([]Outcome, 0, len(val.Values))
	for _, have := range val.Values {
		r := No
		for _, want := range c.Values {
			o := cmp(want, have)
			if o == Yes {
				r = Yes
				break
			}
			if o == Unknown {
				r = Unknown
			}
		}
		if negated {
			switch r {
			case Yes:
				r = No
			case No:
				r = Yes
			}
		}
		results = append(results, r)
	}
	if setOp == "ForAllValues" {
		unknown := false
		for _, r := range results {
			if r == No {
				return No, ""
			}
			if r == Unknown {
				unknown = true
			}
		}
		if unknown {
			return Unknown, fmt.Sprintf("%s %s: the value of %s is only partly known", c.Operator, c.Key, c.Key)
		}
		return Yes, ""
	}
	unknown := false
	for _, r := range results {
		if r == Yes {
			return Yes, ""
		}
		if r == Unknown {
			unknown = true
		}
	}
	if unknown {
		return Unknown, fmt.Sprintf("%s %s: the value of %s is only partly known (%s)", c.Operator, c.Key, c.Key, strings.Join(val.Values, ", "))
	}
	return No, ""
}

// comparator returns the positive comparison for an operator (the "Not" is
// handled by the caller). The context value may itself contain wildcards,
// in which case the result is Yes only when the policy value covers every
// possible context value, Unknown when they merely overlap.
func comparator(op string) (func(want, have string) Outcome, bool) {
	// The string operators match anywhere in the string; the ARN operators
	// check the six components of the ARN one by one.
	like := func(fold bool, mode matchMode) func(w, h string) Outcome {
		return func(w, h string) Outcome { return compare(w, h, fold, mode) }
	}
	exact := func(fold bool) func(w, h string) Outcome {
		return func(w, h string) Outcome {
			eq := w == h
			if fold {
				eq = strings.EqualFold(w, h)
			}
			if eq {
				return Yes
			}
			if hasWildcard(h) && globMatch(h, w, fold) {
				return Unknown
			}
			return No
		}
	}
	switch strings.ReplaceAll(op, "Not", "") {
	case "StringEquals":
		return exact(false), true
	case "StringEqualsIgnoreCase":
		return exact(true), true
	case "StringLike":
		return like(false, modeString), true
	case "ArnEquals", "ArnLike":
		return like(false, modeARN), true
	case "Bool":
		return exact(true), true
	}
	return nil, false
}
