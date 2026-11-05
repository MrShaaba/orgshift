package collector

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/MrShaaba/orgshift/internal/snapshot"
)

// Templates are read to derive facts and are never stored: a template can
// carry anything its author put in it. What is kept is which other stacks
// and accounts the stack reads from, which identifiers of shared
// infrastructure it names, and the conditions on organization identity in
// the policies it declares.

// parseTemplate decodes a CloudFormation template body, JSON or YAML with
// the short forms of the intrinsic functions (!Ref, !Sub, !ImportValue),
// into generic maps and slices with the long forms.
func parseTemplate(body string) (map[string]any, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(body), &doc); err != nil {
		return nil, fmt.Errorf("template does not parse: %w", err)
	}
	if doc.Kind == 0 || len(doc.Content) == 0 {
		return nil, fmt.Errorf("template is empty")
	}
	v, err := templateValue(doc.Content[0], 0)
	if err != nil {
		return nil, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("template is not a mapping")
	}
	return m, nil
}

// templateValue converts a YAML node, turning a short-form intrinsic tag
// into the long-form mapping.
func templateValue(n *yaml.Node, depth int) (any, error) {
	if depth > 200 {
		return nil, fmt.Errorf("template nests too deeply")
	}
	var v any
	switch n.Kind {
	case yaml.AliasNode:
		return templateValue(n.Alias, depth+1)
	case yaml.MappingNode:
		m := make(map[string]any, len(n.Content)/2)
		for i := 0; i+1 < len(n.Content); i += 2 {
			val, err := templateValue(n.Content[i+1], depth+1)
			if err != nil {
				return nil, err
			}
			m[n.Content[i].Value] = val
		}
		v = m
	case yaml.SequenceNode:
		list := make([]any, 0, len(n.Content))
		for _, c := range n.Content {
			val, err := templateValue(c, depth+1)
			if err != nil {
				return nil, err
			}
			list = append(list, val)
		}
		v = list
	default:
		if strings.HasPrefix(n.Tag, "!!") && n.Tag != "!!str" {
			var scalar any
			if err := n.Decode(&scalar); err == nil {
				v = scalar
				break
			}
		}
		v = n.Value
	}
	if strings.HasPrefix(n.Tag, "!") && !strings.HasPrefix(n.Tag, "!!") {
		name := strings.TrimPrefix(n.Tag, "!")
		switch name {
		case "Ref", "Condition":
		default:
			name = "Fn::" + name
		}
		return map[string]any{name: v}, nil
	}
	return v, nil
}

// Identifier patterns of infrastructure a stack can take from outside its
// own template.
var referencePatterns = []struct {
	kind string
	re   *regexp.Regexp
}{
	{snapshot.RefSubnet, regexp.MustCompile(`\bsubnet-[0-9a-f]{8,17}\b`)},
	{snapshot.RefTransitGateway, regexp.MustCompile(`\btgw-[0-9a-f]{8,17}\b`)},
	{snapshot.RefVPC, regexp.MustCompile(`\bvpc-[0-9a-f]{8,17}\b`)},
	{snapshot.RefResolverRule, regexp.MustCompile(`\brslvr-rr-[0-9a-f]{8,32}\b`)},
	{snapshot.RefPrefixList, regexp.MustCompile(`\bpl-[0-9a-f]{8,17}\b`)},
}

// referencesIn finds infrastructure identifiers in a string.
func referencesIn(s, via string) []snapshot.ResourceReference {
	var out []snapshot.ResourceReference
	for _, p := range referencePatterns {
		for _, id := range p.re.FindAllString(s, -1) {
			out = append(out, snapshot.ResourceReference{Kind: p.kind, ID: id, Via: via})
		}
	}
	return out
}

// templateFacts is what the collector keeps of a template.
type templateFacts struct {
	externalOutputs []snapshot.ExternalOutput
	references      []snapshot.ResourceReference
	policies        []snapshot.ResourcePolicy
}

// factsOfTemplate derives the kept facts. params are the stack's parameter
// values, used to resolve a Ref to a parameter; a value that stays an
// intrinsic function is computed at deployment and reported as dynamic.
func factsOfTemplate(tmpl map[string]any, stack string, params map[string]string) templateFacts {
	var f templateFacts
	w := &templateWalker{params: params, defined: map[string]bool{}}
	if res, ok := tmpl["Resources"].(map[string]any); ok {
		for id := range res {
			w.defined[id] = true
		}
	}
	seenRef := map[string]bool{}
	seenOut := map[string]bool{}
	w.visit(tmpl, func(v any) {
		switch x := v.(type) {
		case string:
			for _, ref := range referencesIn(x, "template") {
				if !seenRef[ref.ID] {
					seenRef[ref.ID] = true
					f.references = append(f.references, ref)
				}
			}
		case map[string]any:
			arg, ok := x["Fn::GetStackOutput"].(map[string]any)
			if !ok {
				return
			}
			ex := snapshot.ExternalOutput{}
			ex.StackName, _ = w.literal(arg["StackName"])
			ex.OutputName, _ = w.literal(arg["OutputName"])
			ex.Region, _ = w.literal(arg["Region"])
			ex.RoleARN, _ = w.literal(arg["RoleArn"])
			ex.AccountID = snapshot.AccountFromARN(ex.RoleARN)
			key := ex.StackName + "|" + ex.OutputName + "|" + ex.Region + "|" + ex.RoleARN
			if !seenOut[key] {
				seenOut[key] = true
				f.externalOutputs = append(f.externalOutputs, ex)
			}
		}
	})
	res, _ := tmpl["Resources"].(map[string]any)
	ids := make([]string, 0, len(res))
	for id := range res {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		body, ok := res[id].(map[string]any)
		if !ok {
			continue
		}
		var conds []snapshot.OrgCondition
		w.visit(body["Properties"], func(v any) {
			doc, ok := v.(map[string]any)
			if !ok {
				return
			}
			st, ok := doc["Statement"]
			if !ok {
				return
			}
			conds = append(conds, w.orgConditions(st)...)
		})
		if len(conds) > 0 {
			f.policies = append(f.policies, snapshot.ResourcePolicy{Kind: snapshot.PolicyKindTemplate, Resource: id, Stack: stack, Source: "cloudformation:GetTemplate", Conditions: conds})
		}
	}
	return f
}

type templateWalker struct {
	params  map[string]string
	defined map[string]bool
}

// visit calls fn for every value of the template, depth first.
func (w *templateWalker) visit(v any, fn func(any)) {
	fn(v)
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			w.visit(x[k], fn)
		}
	case []any:
		for _, e := range x {
			w.visit(e, fn)
		}
	}
}

// literal returns the string a template value stands for and whether it is
// known offline: a plain string, or a Ref to a stack parameter whose value
// was read. Anything else is computed at deployment.
func (w *templateWalker) literal(v any) (string, bool) {
	switch x := v.(type) {
	case nil:
		return "", true
	case string:
		return x, true
	case map[string]any:
		if name, ok := x["Ref"].(string); ok {
			if val, ok := w.params[name]; ok && !w.defined[name] {
				return val, true
			}
		}
	}
	return "", false
}

// orgConditions extracts the conditions on organization identity from the
// statements of a policy declared in a template.
func (w *templateWalker) orgConditions(statements any) []snapshot.OrgCondition {
	var list []any
	switch x := statements.(type) {
	case []any:
		list = x
	case map[string]any:
		list = []any{x}
	}
	var out []snapshot.OrgCondition
	for _, s := range list {
		st, ok := s.(map[string]any)
		if !ok {
			continue
		}
		cond, ok := st["Condition"].(map[string]any)
		if !ok {
			continue
		}
		sid, _ := st["Sid"].(string)
		effect, _ := st["Effect"].(string)
		ops := make([]string, 0, len(cond))
		for op := range cond {
			ops = append(ops, op)
		}
		sort.Strings(ops)
		for _, op := range ops {
			keys, ok := cond[op].(map[string]any)
			if !ok {
				continue
			}
			names := make([]string, 0, len(keys))
			for k := range keys {
				names = append(names, k)
			}
			sort.Strings(names)
			for _, key := range names {
				if !snapshot.IsOrgConditionKey(key) {
					continue
				}
				c := snapshot.OrgCondition{Sid: sid, Effect: effect, Operator: op, Key: key}
				values := []any{keys[key]}
				if l, ok := keys[key].([]any); ok {
					values = l
				}
				for _, v := range values {
					if s, ok := w.literal(v); ok {
						c.Values = append(c.Values, s)
						continue
					}
					c.Dynamic = true
					c.Values = append(c.Values, describeIntrinsic(v))
				}
				out = append(out, c)
			}
		}
	}
	return out
}

// describeIntrinsic renders a value computed at deployment so a reader can
// find it in the template: the function and its argument, shortened.
func describeIntrinsic(v any) string {
	data, err := json.Marshal(v)
	if err != nil {
		return "(computed in the template)"
	}
	s := string(data)
	if len(s) > 120 {
		s = s[:117] + "..."
	}
	return s
}
