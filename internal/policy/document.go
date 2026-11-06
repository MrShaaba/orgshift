// Package policy parses IAM-style policy documents (service control policies
// and resource control policies) and matches requests against their
// statements. Every match returns a tri-state outcome so that conditions the
// evaluator cannot decide surface as "unknown" instead of a guess.
package policy

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Document is a parsed policy document.
type Document struct {
	Version    string
	Statements []Statement
}

// Statement is one parsed statement. Raw keeps the original JSON for evidence.
type Statement struct {
	Index         int
	Sid           string
	Effect        string
	Actions       []string
	NotActions    []string
	Resources     []string
	NotResources  []string
	Principals    *Principal
	NotPrincipals *Principal
	Conditions    []Condition
	Raw           json.RawMessage
}

// Principal is a parsed Principal or NotPrincipal element.
type Principal struct {
	All     bool
	AWS     []string
	Service []string
	Other   map[string][]string
}

// Condition is one (operator, key, values) triple.
type Condition struct {
	Operator string
	Key      string
	Values   []string
}

// Label returns "Sid" or "statement #n" for messages.
func (s *Statement) Label() string {
	if s.Sid != "" {
		return s.Sid
	}
	return fmt.Sprintf("statement #%d", s.Index+1)
}

// IsAllow reports whether the statement effect is Allow.
func (s *Statement) IsAllow() bool { return strings.EqualFold(s.Effect, "Allow") }

// HasResourceElement reports whether the statement carries a Resource or a
// NotResource element. A statement of a role trust policy has neither and
// is about the role it is attached to; whether the element is required is a
// rule of the policy type (service and resource control policies require
// it), not of the parser, which never invents a "*" for a missing one.
func (s *Statement) HasResourceElement() bool {
	return len(s.Resources) > 0 || len(s.NotResources) > 0
}

// Parse parses a policy document.
func Parse(data []byte) (*Document, error) {
	var raw struct {
		Version   string          `json:"Version"`
		Statement json.RawMessage `json:"Statement"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("policy is not valid JSON: %w", err)
	}
	if len(raw.Statement) == 0 {
		return nil, fmt.Errorf("policy has no Statement element")
	}
	var rawStatements []json.RawMessage
	if strings.HasPrefix(strings.TrimSpace(string(raw.Statement)), "[") {
		if err := json.Unmarshal(raw.Statement, &rawStatements); err != nil {
			return nil, fmt.Errorf("Statement: %w", err)
		}
	} else {
		rawStatements = []json.RawMessage{raw.Statement}
	}
	doc := &Document{Version: raw.Version}
	for i, rs := range rawStatements {
		st, err := parseStatement(i, rs)
		if err != nil {
			return nil, fmt.Errorf("statement #%d: %w", i+1, err)
		}
		doc.Statements = append(doc.Statements, st)
	}
	return doc, nil
}

type rawStatement struct {
	Sid          string                    `json:"Sid"`
	Effect       string                    `json:"Effect"`
	Action       stringList                `json:"Action"`
	NotAction    stringList                `json:"NotAction"`
	Resource     stringList                `json:"Resource"`
	NotResource  stringList                `json:"NotResource"`
	Principal    json.RawMessage           `json:"Principal"`
	NotPrincipal json.RawMessage           `json:"NotPrincipal"`
	Condition    map[string]map[string]any `json:"Condition"`
}

func parseStatement(i int, data json.RawMessage) (Statement, error) {
	var r rawStatement
	if err := json.Unmarshal(data, &r); err != nil {
		return Statement{}, err
	}
	if !strings.EqualFold(r.Effect, "Allow") && !strings.EqualFold(r.Effect, "Deny") {
		return Statement{}, fmt.Errorf("effect must be Allow or Deny, got %q", r.Effect)
	}
	if len(r.Action) == 0 && len(r.NotAction) == 0 {
		return Statement{}, fmt.Errorf("statement has neither Action nor NotAction")
	}
	// The policy grammar gives a statement one action element and one
	// resource element, each written as an alternative: ("Action" |
	// "NotAction") and ("Resource" | "NotResource"). A statement with both
	// does not say which one holds, so it is malformed rather than read as
	// if one of them were absent.
	if len(r.Action) > 0 && len(r.NotAction) > 0 {
		return Statement{}, fmt.Errorf("statement has both Action and NotAction; a statement carries one or the other")
	}
	if len(r.Resource) > 0 && len(r.NotResource) > 0 {
		return Statement{}, fmt.Errorf("statement has both Resource and NotResource; a statement carries one or the other")
	}
	st := Statement{
		Index:        i,
		Sid:          r.Sid,
		Effect:       r.Effect,
		Actions:      r.Action,
		NotActions:   r.NotAction,
		Resources:    r.Resource,
		NotResources: r.NotResource,
		Raw:          data,
	}
	var err error
	if st.Principals, err = parsePrincipal(r.Principal); err != nil {
		return Statement{}, fmt.Errorf("Principal: %w", err)
	}
	if st.NotPrincipals, err = parsePrincipal(r.NotPrincipal); err != nil {
		return Statement{}, fmt.Errorf("NotPrincipal: %w", err)
	}
	ops := make([]string, 0, len(r.Condition))
	for op := range r.Condition {
		ops = append(ops, op)
	}
	sort.Strings(ops)
	for _, op := range ops {
		keys := make([]string, 0, len(r.Condition[op]))
		for k := range r.Condition[op] {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			vals, err := anyToStrings(r.Condition[op][k])
			if err != nil {
				return Statement{}, fmt.Errorf("Condition %s %s: %w", op, k, err)
			}
			st.Conditions = append(st.Conditions, Condition{Operator: op, Key: k, Values: vals})
		}
	}
	return st, nil
}

func parsePrincipal(data json.RawMessage) (*Principal, error) {
	if len(data) == 0 {
		return nil, nil
	}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == `"*"` {
		return &Principal{All: true}, nil
	}
	var m map[string]stringList
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("must be \"*\" or an object: %w", err)
	}
	p := &Principal{Other: map[string][]string{}}
	for k, v := range m {
		switch k {
		case "AWS":
			p.AWS = v
		case "Service":
			p.Service = v
		default:
			p.Other[k] = v
		}
	}
	if len(p.AWS) == 1 && p.AWS[0] == "*" {
		p.All = true
	}
	return p, nil
}

// stringList accepts a JSON string or array of strings.
type stringList []string

func (l *stringList) UnmarshalJSON(data []byte) error {
	if strings.TrimSpace(string(data)) == "null" {
		// A JSON null is "absent", not the empty string.
		*l = nil
		return nil
	}
	var one string
	if err := json.Unmarshal(data, &one); err == nil {
		*l = []string{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return fmt.Errorf("expected a string or array of strings")
	}
	*l = many
	return nil
}

func anyToStrings(v any) ([]string, error) {
	switch t := v.(type) {
	case nil:
		return nil, fmt.Errorf("condition value is null")
	case string:
		return []string{t}, nil
	case bool:
		return []string{fmt.Sprint(t)}, nil
	case float64:
		return []string{strings.TrimSuffix(fmt.Sprintf("%v", t), ".0")}, nil
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			s, err := anyToStrings(e)
			if err != nil {
				return nil, err
			}
			out = append(out, s...)
		}
		return out, nil
	}
	return nil, fmt.Errorf("unsupported condition value %T", v)
}
