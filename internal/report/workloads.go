package report

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/MrShaaba/orgshift/internal/snapshot"
	"github.com/MrShaaba/orgshift/internal/workload"
)

// WorkloadsJSON renders an inventory as indented JSON.
func WorkloadsJSON(inv *workload.Inventory) ([]byte, error) {
	data, err := json.MarshalIndent(inv, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func coverageLine(inv *workload.Inventory) string {
	var parts []string
	for _, c := range inv.Coverage {
		parts = append(parts, c.Domain+" "+string(c.Status))
	}
	return strings.Join(parts, "; ")
}

func typeCounts(types map[string]int) string {
	keys := make([]string, 0, len(types))
	for k := range types {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s x%d", k, types[k]))
	}
	return strings.Join(parts, ", ")
}

func tagList(tags map[string]string) string {
	if len(tags) == 0 {
		return "no tags"
	}
	keys := make([]string, 0, len(tags))
	for k := range tags {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		parts = append(parts, k+"="+tags[k])
	}
	return strings.Join(parts, ", ")
}

// stackNotes lists what a stack depends on or offers, one item per line.
func stackNotes(st workload.StackView) []string {
	var out []string
	if st.StackSetSettings != nil {
		ss := st.StackSetSettings
		how := "matched by stack name"
		if ss.MatchedByInstance {
			how = "matched by instance ID"
		}
		out = append(out, fmt.Sprintf("StackSet %s: %s, auto-deployment %t, retain stacks on account removal %t, targets %s (%s)",
			ss.Name, orNone(ss.PermissionModel), ss.AutoDeployment, ss.RetainStacksOnAccountRemoval, orNone(strings.Join(ss.TargetOUs, ", ")), how))
	}
	var exports []string
	for _, o := range st.Outputs {
		if o.ExportName != "" {
			exports = append(exports, o.ExportName)
		}
	}
	if len(exports) > 0 {
		out = append(out, "exports "+strings.Join(exports, ", "))
	}
	for _, im := range st.Imports {
		from := "a stack outside the inventory"
		if im.ExportingStack != "" {
			from = "stack " + im.ExportingStack
		}
		out = append(out, fmt.Sprintf("imports %s from %s (Fn::ImportValue, same account and Region)", im.ExportName, from))
	}
	for _, ex := range st.ExternalOutputs {
		where := "this account"
		if ex.AccountID != "" {
			where = "account " + ex.AccountID + " through role " + ex.RoleARN
		}
		out = append(out, fmt.Sprintf("reads output %s of stack %s in %s (Fn::GetStackOutput, resolved at deploy time)", ex.OutputName, ex.StackName, where))
	}
	for _, ref := range st.References {
		owner := ""
		if ref.AccountID != "" {
			owner = " of account " + ref.AccountID
		}
		out = append(out, fmt.Sprintf("references %s %s%s (%s)", ref.Kind, ref.ID, owner, orNone(ref.Via)))
	}
	if st.TerminationProtection {
		out = append(out, "termination protection on")
	}
	return out
}

func conditionLine(c snapshot.OrgCondition) string {
	sid := c.Sid
	if sid == "" {
		sid = "(no Sid)"
	}
	dyn := ""
	if c.Dynamic {
		dyn = " (a value is computed in the template)"
	}
	return fmt.Sprintf("%s %s: %s %s %s%s", orNone(c.Effect), sid, c.Operator, c.Key, strings.Join(c.Values, ", "), dyn)
}

func policyTarget(p snapshot.ResourcePolicy) string {
	switch {
	case p.ResourceARN != "":
		return p.ResourceARN
	case p.Stack != "":
		return "resource " + p.Resource + " of stack " + p.Stack
	}
	return p.Resource
}

// WorkloadsText renders an inventory for a terminal.
func WorkloadsText(inv *workload.Inventory) string {
	var b strings.Builder
	fmt.Fprintf(&b, "WORKLOADS %s (%s)\n\n", orNone(inv.AccountName), inv.AccountID)
	fmt.Fprintf(&b, "workload layer: %s\ncoverage: %s\n", inv.Evaluation(), coverageLine(inv))
	for _, c := range inv.Coverage {
		if c.Detail != "" {
			fmt.Fprintf(&b, "  %s: %s\n", c.Domain, c.Detail)
		}
	}
	for _, n := range inv.Notes {
		fmt.Fprintf(&b, "note: %s\n", n)
	}
	if !inv.Collected {
		return b.String()
	}
	stackResources := 0
	for _, st := range inv.Stacks {
		stackResources += st.Resources
	}
	fmt.Fprintf(&b, "regions: %s\nstacks: %d with %d resources; sampled resources: %d (source %s); policies that reference organization identity: %d of %d read\n",
		orNone(strings.Join(inv.Regions, ", ")), len(inv.Stacks), stackResources, len(inv.Resources), orNone(inv.ResourceSource), len(inv.Policies), inv.PoliciesInspected)
	b.WriteString("\nHow it would be redeployed\n")
	for _, g := range inv.Groups {
		fmt.Fprintf(&b, "  %-42s %d stack(s) with %d resource(s), %d sampled resource(s) outside any stack\n", g.Title, g.Stacks, g.StackResources, g.SampledResources)
	}
	b.WriteString("\nStacks\n")
	for _, st := range inv.Stacks {
		fmt.Fprintf(&b, "  %s  %s  [%s, %s confidence]  %d resource(s), %s\n", st.Region, st.Name, st.Provenance.Kind.Label(), st.Provenance.Confidence, st.Resources, orNone(st.Status))
		fmt.Fprintf(&b, "      types: %s\n", orNone(typeCounts(st.ResourceTypes)))
		for _, e := range st.Provenance.Evidence {
			fmt.Fprintf(&b, "      evidence: %s\n", e)
		}
		for _, n := range stackNotes(st) {
			fmt.Fprintf(&b, "      %s\n", n)
		}
	}
	b.WriteString("\nSampled resources\n")
	for _, r := range inv.Resources {
		fmt.Fprintf(&b, "  %-32s %s  [%s, %s confidence]\n", orNone(r.Type), r.ARN, r.Provenance.Kind.Label(), r.Provenance.Confidence)
		fmt.Fprintf(&b, "      tags: %s\n", tagList(r.Tags))
		for _, e := range r.Provenance.Evidence[:1] {
			fmt.Fprintf(&b, "      evidence: %s\n", e)
		}
	}
	b.WriteString("\nPolicies that reference organization identity\n")
	if len(inv.Policies) == 0 {
		b.WriteString("  none among the policies read\n")
	}
	for _, p := range inv.Policies {
		fmt.Fprintf(&b, "  %s  %s  (%s)\n", p.Kind, policyTarget(p), orNone(p.Source))
		for _, c := range p.Conditions {
			fmt.Fprintf(&b, "      %s\n", conditionLine(c))
		}
	}
	return b.String()
}

// WorkloadsMarkdown renders an inventory as Markdown.
func WorkloadsMarkdown(inv *workload.Inventory) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Workloads of %s (`%s`)\n\n", md(orNone(inv.AccountName)), inv.AccountID)
	writeWorkloadsBody(&b, inv, 2)
	return b.String()
}

// writeWorkloadsBody writes the inventory below a title, with headings at
// the given level, so it can nest in other reports.
func writeWorkloadsBody(b *strings.Builder, inv *workload.Inventory, level int) {
	h := strings.Repeat("#", level)
	fmt.Fprintf(b, "Workload layer: **%s**.\n\n| Domain | Status | Detail |\n|---|---|---|\n", inv.Evaluation())
	for _, c := range inv.Coverage {
		fmt.Fprintf(b, "| `%s` | %s | %s |\n", c.Domain, c.Status, md(c.Detail))
	}
	b.WriteString("\n")
	for _, n := range inv.Notes {
		fmt.Fprintf(b, "> %s\n\n", n)
	}
	if !inv.Collected {
		return
	}
	fmt.Fprintf(b, "Regions inspected: %s. Resource sample from %s. %d of %d policies read reference organization identity.\n\n",
		orNone(strings.Join(inv.Regions, ", ")), orNone(inv.ResourceSource), len(inv.Policies), inv.PoliciesInspected)
	fmt.Fprintf(b, "%s How it would be redeployed\n\n| Group | Stacks | Resources in them | Sampled resources outside any stack |\n|---|---|---|---|\n", h)
	for _, g := range inv.Groups {
		fmt.Fprintf(b, "| %s | %d | %d | %d |\n", g.Title, g.Stacks, g.StackResources, g.SampledResources)
	}
	fmt.Fprintf(b, "\n%s Stacks\n\n| Region | Stack | Provenance | Confidence | Resources | Evidence |\n|---|---|---|---|---|---|\n", h)
	for _, st := range inv.Stacks {
		fmt.Fprintf(b, "| %s | `%s` | %s | %s | %d | %s |\n", st.Region, st.Name, st.Provenance.Kind.Label(), st.Provenance.Confidence, st.Resources, md(strings.Join(st.Provenance.Evidence, "; ")))
	}
	b.WriteString("\n")
	for _, st := range inv.Stacks {
		notes := stackNotes(st)
		if len(notes) == 0 {
			continue
		}
		fmt.Fprintf(b, "`%s` (%s): %s.\n\n", st.Name, md(typeCounts(st.ResourceTypes)), md(strings.Join(notes, "; ")))
	}
	fmt.Fprintf(b, "%s Sampled resources\n\n| Type | Resource | Provenance | Confidence | Tags | Evidence |\n|---|---|---|---|---|---|\n", h)
	for _, r := range inv.Resources {
		fmt.Fprintf(b, "| %s | `%s` | %s | %s | %s | %s |\n", orNone(r.Type), r.ARN, r.Provenance.Kind.Label(), r.Provenance.Confidence, md(tagList(r.Tags)), md(r.Provenance.Evidence[0]))
	}
	fmt.Fprintf(b, "\n%s Policies that reference organization identity\n\n", h)
	if len(inv.Policies) == 0 {
		b.WriteString("None among the policies read.\n\n")
		return
	}
	b.WriteString("| Kind | Resource | Read with | Conditions |\n|---|---|---|---|\n")
	for _, p := range inv.Policies {
		var conds []string
		for _, c := range p.Conditions {
			conds = append(conds, conditionLine(c))
		}
		fmt.Fprintf(b, "| %s | `%s` | %s | %s |\n", p.Kind, policyTarget(p), orNone(p.Source), md(strings.Join(conds, "; ")))
	}
	b.WriteString("\n")
}

// WorkloadsIndexText lists the accounts of a snapshot that have a workload
// inventory, one line each.
func WorkloadsIndexText(s *snapshot.Snapshot) string {
	var b strings.Builder
	ids := workload.Accounts(s)
	fmt.Fprintf(&b, "%s (%s): %d account(s) with a workload inventory\n", orNone(s.Organization.Name), s.Organization.ID, len(ids))
	for _, id := range ids {
		inv := workload.Build(s, id)
		fmt.Fprintf(&b, "  %s  %-28s %s: %d stack(s), %d sampled resource(s), %d policy(ies) on organization identity\n", id, inv.AccountName, inv.Evaluation(), len(inv.Stacks), len(inv.Resources), len(inv.Policies))
	}
	if len(ids) == 0 {
		b.WriteString("  none: name accounts under member_inspection.accounts in the onboarding configuration and collect again\n")
	}
	b.WriteString("Use --account ID for the inventory and provenance of one account.\n")
	return b.String()
}
