package evaluator

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/MrShaaba/orgshift/internal/snapshot"
)

// tagRule is the effective rule for one tag key after inheritance.
type tagRule struct {
	Key         string   `json:"key"`
	KeyEnforced bool     `json:"key_case_enforced"`
	Values      []string `json:"values,omitempty"`
	EnforcedFor []string `json:"enforced_for,omitempty"`
	Sources     []string `json:"sources"`
}

// effectiveTagPolicy merges the tag policies along a chain, root first,
// applying the @@assign, @@append and @@remove inheritance operators.
func (e *evaluation) effectiveTagPolicy(ch []link) ([]*tagRule, []string) {
	rules := map[string]*tagRule{}
	var order []string
	var problems []string
	for _, lvl := range ch {
		for _, p := range lvl.policies {
			var doc struct {
				Tags map[string]map[string]any `json:"tags"`
			}
			if err := json.Unmarshal(p.Document, &doc); err != nil {
				problems = append(problems, fmt.Sprintf("tag policy %s (%s) could not be parsed: %v", p.Name, p.ID, err))
				continue
			}
			keys := make([]string, 0, len(doc.Tags))
			for k := range doc.Tags {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				spec := doc.Tags[k]
				id := strings.ToLower(k)
				r, ok := rules[id]
				if !ok {
					r = &tagRule{Key: k}
					rules[id] = r
					order = append(order, id)
				}
				r.Sources = appendUnique(r.Sources, p.Name)
				if tk, ok := spec["tag_key"].(map[string]any); ok {
					if v, ok := tk["@@assign"].(string); ok {
						r.Key = v
						r.KeyEnforced = true
					}
				}
				if tv, ok := spec["tag_value"].(map[string]any); ok {
					r.Values = applyListOps(r.Values, tv)
				}
				if ef, ok := spec["enforced_for"].(map[string]any); ok {
					r.EnforcedFor = applyListOps(r.EnforcedFor, ef)
				}
			}
		}
	}
	out := make([]*tagRule, 0, len(order))
	for _, id := range order {
		out = append(out, rules[id])
	}
	return out, problems
}

func applyListOps(cur []string, spec map[string]any) []string {
	if v, ok := spec["@@assign"]; ok {
		cur = toStrings(v)
	}
	if v, ok := spec["@@append"]; ok {
		for _, s := range toStrings(v) {
			cur = appendUnique(cur, s)
		}
	}
	if v, ok := spec["@@remove"]; ok {
		drop := map[string]bool{}
		for _, s := range toStrings(v) {
			drop[s] = true
		}
		var kept []string
		for _, s := range cur {
			if !drop[s] {
				kept = append(kept, s)
			}
		}
		cur = kept
	}
	return cur
}

func toStrings(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func appendUnique(list []string, s string) []string {
	for _, e := range list {
		if e == s {
			return list
		}
	}
	return append(list, s)
}

func enforcedFor(r *tagRule, resourceType string) bool {
	for _, pat := range r.EnforcedFor {
		if strings.EqualFold(pat, resourceType) {
			return true
		}
		if strings.HasSuffix(pat, ":*") && strings.HasPrefix(strings.ToLower(resourceType), strings.ToLower(strings.TrimSuffix(pat, "*"))) {
			return true
		}
	}
	return false
}

// evaluateTags fills the tag policy check from the target's effective policy.
func (e *evaluation) evaluateTags(c *Check) {
	t := snapshot.PolicyTypeTag
	if !e.to.PolicyTypeEnabled(t) {
		c.Summary = "Tag policies are not enabled in the target organization."
		return
	}
	rules, problems := e.effectiveTagPolicy(e.chain(&e.dst, t))
	for _, p := range problems {
		c.add(Finding{Status: StatusReview, Title: "Tag policy could not be parsed", Detail: p})
	}
	if len(rules) == 0 {
		c.Summary = "No tag policy applies at the target."
		return
	}
	usage := e.from.UsageFor(e.accountID)
	rulesJSON, _ := json.MarshalIndent(rules, "", "  ")
	if e.from.PolicyTypeEnabled(t) {
		srcRules, _ := e.effectiveTagPolicy(e.chain(&e.src, t))
		if srcJSON, _ := json.Marshal(srcRules); string(srcJSON) == string(mustCompact(rulesJSON)) {
			c.add(Finding{Status: StatusInfo, Title: "The effective tag policy is the same before and after the move",
				Detail:   "The merged tag rules on the source path and on the target path are identical, so the move changes no tag compliance.",
				Evidence: []Evidence{{Kind: "effective-tag-policy", Side: "target", PolicyType: "TAG", StatementJSON: rulesJSON}}})
			c.Summary = fmt.Sprintf("%d tag keys governed; unchanged by the move.", len(rules))
			return
		}
	}
	keys := make([]string, 0, len(rules))
	for _, r := range rules {
		keys = append(keys, r.Key)
	}
	c.add(Finding{Status: StatusInfo, Title: "Effective tag policy at the target defines " + strings.Join(keys, ", "),
		Detail:   "Rules below are the merged result of every tag policy on the target path.",
		Evidence: []Evidence{{Kind: "effective-tag-policy", Side: "target", PolicyType: "TAG", StatementJSON: rulesJSON}}})
	if len(usage.TaggedResources) == 0 {
		c.add(Finding{Status: StatusReview, Title: "No tagged resources were provided for this account",
			Detail: "Add usage.tagged_resources to the source snapshot (for example from the Resource Groups Tagging API) to check compliance against the target tag policy."})
		c.Summary = fmt.Sprintf("%d tag keys governed at the target; no resource sample to check.", len(rules))
		return
	}
	type bucket struct {
		status Status
		title  string
		detail string
		arns   []string
	}
	buckets := map[string]*bucket{}
	var order []string
	record := func(key, title, detail string, status Status, arn string) {
		b, ok := buckets[key]
		if !ok {
			b = &bucket{status: status, title: title, detail: detail}
			buckets[key] = b
			order = append(order, key)
		}
		b.arns = append(b.arns, arn)
	}
	nonCompliant := 0
	for _, r := range rules {
		src := strings.Join(r.Sources, ", ")
		for _, res := range usage.TaggedResources {
			enforced := enforcedFor(r, res.Type)
			sev := StatusInfo
			suffix := " The policy only reports this (the resource type is not in enforced_for), so tagging operations are not blocked."
			if enforced {
				sev = StatusReview
				suffix = " The policy enforces this for " + res.Type + ": non-compliant tag operations on such resources are rejected after the move."
			}
			actualKey, value, found := lookupTag(res.Tags, r.Key)
			switch {
			case !found:
				record(r.Key+"|missing|"+res.Type, fmt.Sprintf("%s: %s resources carry no %s tag", r.Key, res.Type, r.Key),
					"Tag policies do not require a tag to be present, so this does not block the move, but these resources fall outside the target standard ("+src+").", StatusInfo, res.ARN)
			case r.KeyEnforced && actualKey != r.Key:
				nonCompliant++
				record(r.Key+"|case|"+res.Type+"|"+actualKey, fmt.Sprintf("%s: %s resources use the key %q instead of %q", r.Key, res.Type, actualKey, r.Key),
					"The target tag policy ("+src+") fixes the key capitalization."+suffix, sev, res.ARN)
			case len(r.Values) > 0 && !contains(r.Values, value):
				nonCompliant++
				record(r.Key+"|value|"+res.Type+"|"+value, fmt.Sprintf("%s: %s resources use the value %q which is not allowed", r.Key, res.Type, value),
					"Allowed values ("+src+"): "+strings.Join(r.Values, ", ")+"."+suffix, sev, res.ARN)
			}
		}
	}
	for _, k := range order {
		b := buckets[k]
		detail := b.detail + fmt.Sprintf(" Affected: %d resource(s), for example %s.", len(b.arns), strings.Join(firstN(b.arns, 3), ", "))
		c.add(Finding{Status: b.status, Title: b.title, Detail: detail,
			Evidence: []Evidence{{Kind: "tag-compliance", Side: "target", PolicyType: "TAG", Note: strings.Join(b.arns, "\n")}}})
	}
	sortFindings(c.Findings)
	c.Summary = fmt.Sprintf("%d tag keys governed at the target; %d non-compliant tag(s) across %d sampled resources.", len(rules), nonCompliant, len(usage.TaggedResources))
}

func mustCompact(data []byte) []byte {
	var buf bytes.Buffer
	if err := json.Compact(&buf, data); err != nil {
		return data
	}
	return buf.Bytes()
}

func lookupTag(tags map[string]string, key string) (actualKey, value string, found bool) {
	if v, ok := tags[key]; ok {
		return key, v, true
	}
	keys := make([]string, 0, len(tags))
	for k := range tags {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if strings.EqualFold(k, key) {
			return k, tags[k], true
		}
	}
	return "", "", false
}

func contains(list []string, s string) bool {
	for _, e := range list {
		if e == s {
			return true
		}
	}
	return false
}

func firstN(list []string, n int) []string {
	if len(list) <= n {
		return list
	}
	return list[:n]
}
