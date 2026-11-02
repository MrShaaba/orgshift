package report

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/MrShaaba/orgshift/internal/evaluator"
	"github.com/MrShaaba/orgshift/internal/scenario"
	"github.com/MrShaaba/orgshift/internal/snapshot"
)

// StagesJSON renders a staged report as indented JSON.
func StagesJSON(r *scenario.Report) ([]byte, error) {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// StagesText renders a staged report for a terminal: one block per stage
// with the layer changes, the stage findings and the transition's verdict
// board.
func StagesText(r *scenario.Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n\n%s\n\n", banner(r.Verdict), r.Summary)
	fmt.Fprintf(&b, "scenario: %s (%s)\naccount: %s (%s)\nfrom: %s %s\nto:   %s %s\n", r.Name, r.Strategy, r.Subject.AccountName, r.Subject.AccountID,
		orgLabel(r.Subject.SourceOrg), snapshot.PathString(r.Subject.CurrentPath), orgLabel(r.Subject.DestinationOrg), snapshot.PathString(r.Subject.FinalPath))
	if len(r.CriticalOperations) > 0 {
		b.WriteString("critical operations declared:")
		for _, op := range r.CriticalOperations {
			fmt.Fprintf(&b, " %s", op.Action)
		}
		b.WriteString("\n")
	}
	if len(r.Proposed.OUs)+len(r.Proposed.Policies)+len(r.Proposed.ResourceShares) > 0 {
		fmt.Fprintf(&b, "proposed: %d OU(s), %d policy(ies), %d share(s) (do not exist in the snapshots)\n", len(r.Proposed.OUs), len(r.Proposed.Policies), len(r.Proposed.ResourceShares))
	}
	for _, n := range r.Notes {
		fmt.Fprintf(&b, "note: %s\n", n)
	}
	for _, st := range r.Stages {
		fmt.Fprintf(&b, "\n== Stage %d: %s [%s]\n", st.Index, st.Title, st.Verdict)
		if st.Description != "" {
			fmt.Fprintf(&b, "   %s\n", st.Description)
		}
		fmt.Fprintf(&b, "   state: %s at %s", orgLabel(st.State.Organization), snapshot.PathString(st.State.Path))
		if st.State.Enrolled {
			b.WriteString(", enrolled")
		}
		if st.State.Governed {
			b.WriteString(", registered OU")
		}
		if len(st.State.ProposedOnPath) > 0 {
			fmt.Fprintf(&b, ", proposed on path: %s", strings.Join(st.State.ProposedOnPath, ", "))
		}
		b.WriteString("\n   layers:")
		for _, l := range st.Layers {
			mark := "-"
			if l.Changed {
				mark = "*"
			}
			fmt.Fprintf(&b, " %s %s: %s;", mark, l.Layer, l.Summary)
		}
		b.WriteString("\n")
		for _, f := range st.Findings {
			fmt.Fprintf(&b, "   %-6s [%s] %s\n", f.Status, f.Category, f.Title)
		}
		if st.Transition != nil {
			fmt.Fprintf(&b, "   transition: %s; coverage %s\n", st.Transition.Verdict, st.Transition.Coverage.Line())
			for _, c := range st.Transition.Checks {
				if c.Status == evaluator.StatusGo && len(c.Findings) == 0 {
					continue
				}
				fmt.Fprintf(&b, "     [%-6s] %s", c.Status, c.Title)
				if c.Summary != "" {
					fmt.Fprintf(&b, " - %s", c.Summary)
				}
				b.WriteString("\n")
				for _, f := range c.Findings {
					if f.Status == evaluator.StatusInfo {
						continue
					}
					fmt.Fprintf(&b, "         %-6s [%s] %s", f.Status, f.Category, f.Title)
					if f.Source == evaluator.SourceDeclared {
						b.WriteString(" (declared)")
					}
					b.WriteString("\n")
				}
			}
		}
		if len(st.Verify) > 0 {
			b.WriteString("   verify (operator): " + strings.Join(st.Verify, "; ") + "\n")
		}
	}
	b.WriteString("\n== Strategies\n")
	for _, s := range r.Strategies {
		sel := ""
		if s.Selected {
			sel = " (selected)"
		}
		fmt.Fprintf(&b, "%s%s\n", s.Title, sel)
		writeList(&b, "  prerequisites", s.Prerequisites)
		writeList(&b, "  risks", s.Risks)
		writeList(&b, "  unknowns", s.Unknowns)
		writeList(&b, "  reversal", s.Reversal)
	}
	b.WriteString("\n== Limitations\n")
	for _, l := range r.Limitations {
		fmt.Fprintf(&b, "- %s\n", l)
	}
	return b.String()
}

func writeList(b *strings.Builder, title string, items []string) {
	fmt.Fprintf(b, "%s:\n", title)
	for _, it := range items {
		fmt.Fprintf(b, "    - %s\n", it)
	}
}

// StagesMarkdown renders the staged report as Markdown: the stage table,
// then one section per stage with the layer changes, the stage findings and
// the full transition report, then the strategy comparison.
func StagesMarkdown(r *scenario.Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# orgshift staged verdict: %s\n\n%s\n\n", r.Verdict, r.Summary)
	fmt.Fprintf(&b, "Scenario **%s** (strategy %s). Account `%s` (%s), from %s at %s to %s at %s.\n\n", md(r.Name), r.Strategy, r.Subject.AccountID, md(r.Subject.AccountName),
		orgLabel(r.Subject.SourceOrg), snapshot.PathString(r.Subject.CurrentPath), orgLabel(r.Subject.DestinationOrg), snapshot.PathString(r.Subject.FinalPath))
	if r.Description != "" {
		fmt.Fprintf(&b, "%s\n\n", r.Description)
	}
	for _, n := range r.Notes {
		fmt.Fprintf(&b, "> %s\n\n", n)
	}
	b.WriteString("## Stages\n\n| # | Stage | Verdict | Membership | Placement | Governance | Network | Workload |\n|---|---|---|---|---|---|---|---|\n")
	for _, st := range r.Stages {
		fmt.Fprintf(&b, "| %d | %s | %s |", st.Index, md(st.Title), st.Verdict)
		for _, l := range st.Layers {
			if l.Changed {
				fmt.Fprintf(&b, " %s |", md(l.Summary))
			} else {
				b.WriteString(" - |")
			}
		}
		b.WriteString("\n")
	}
	b.WriteString("\n")
	if len(r.CriticalOperations) > 0 {
		b.WriteString("## Declared critical operations\n\n| Action | Regions | Reason |\n|---|---|---|\n")
		for _, op := range r.CriticalOperations {
			fmt.Fprintf(&b, "| `%s` | %s | %s |\n", op.Action, orNone(strings.Join(op.Regions, ", ")), md(op.Reason))
		}
		b.WriteString("\n")
	}
	b.WriteString("## Proposed objects\n\n")
	if len(r.Proposed.OUs)+len(r.Proposed.Policies)+len(r.Proposed.ResourceShares) == 0 {
		b.WriteString("None: every object the stages use exists in the snapshots.\n\n")
	} else {
		b.WriteString("These do not exist in the snapshots; they are created before the stage that uses them.\n\n")
		for _, ou := range r.Proposed.OUs {
			fmt.Fprintf(&b, "- OU **%s** (`%s`) under `%s`", md(ou.Name), ou.ID, ou.ParentID)
			if len(ou.Policies) > 0 {
				fmt.Fprintf(&b, ", policies %s", strings.Join(ou.Policies, ", "))
			}
			if ou.Register {
				b.WriteString(", registered with Control Tower")
			}
			b.WriteString("\n")
		}
		for _, p := range r.Proposed.Policies {
			fmt.Fprintf(&b, "- %s **%s** (`%s`)\n", p.Type.Short(), md(p.Name), p.ID)
		}
		for _, sh := range r.Proposed.ResourceShares {
			fmt.Fprintf(&b, "- resource share **%s**\n", md(sh))
		}
		b.WriteString("\n")
	}
	for _, st := range r.Stages {
		fmt.Fprintf(&b, "## Stage %d: %s: %s\n\n", st.Index, md(st.Title), st.Verdict)
		if st.Description != "" {
			fmt.Fprintf(&b, "%s\n\n", st.Description)
		}
		fmt.Fprintf(&b, "State: %s at %s", orgLabel(st.State.Organization), snapshot.PathString(st.State.Path))
		if st.State.Enrolled {
			b.WriteString(", enrolled in Control Tower")
		}
		if st.State.Governed {
			b.WriteString(", in a registered OU")
		}
		if len(st.State.ProposedOnPath) > 0 {
			fmt.Fprintf(&b, "; proposed on the path: %s", strings.Join(st.State.ProposedOnPath, ", "))
		}
		if len(st.State.Shares) > 0 {
			fmt.Fprintf(&b, "; proposed shares present: %s", strings.Join(st.State.Shares, ", "))
		}
		b.WriteString(".\n\n| Layer | Change |\n|---|---|\n")
		for _, l := range st.Layers {
			fmt.Fprintf(&b, "| %s | %s |\n", l.Layer, md(l.Summary))
		}
		b.WriteString("\n")
		if len(st.Findings) > 0 {
			b.WriteString("### Stage findings\n\n")
			for _, f := range st.Findings {
				fmt.Fprintf(&b, "#### %s: %s\n\n", f.Status, md(f.Title))
				fmt.Fprintf(&b, "Category %s, confidence %s.\n\n", f.Category, f.Confidence)
				writeFinding(&b, f)
			}
		}
		if len(st.Verify) > 0 {
			b.WriteString("### Operator verification at this stage\n\n")
			for _, v := range st.Verify {
				fmt.Fprintf(&b, "- [ ] %s\n", md(v))
			}
			b.WriteString("\n")
		}
		if st.Transition != nil {
			fmt.Fprintf(&b, "### Transition into this stage: %s\n\n", st.Transition.Verdict)
			writeMarkdownBody(&b, st.Transition, 4)
		}
	}
	b.WriteString("## Strategies compared\n\n")
	for _, s := range r.Strategies {
		sel := ""
		if s.Selected {
			sel = " (selected)"
		}
		fmt.Fprintf(&b, "### %s%s\n\n", md(s.Title), sel)
		for _, part := range []struct {
			title string
			items []string
		}{{"Prerequisites", s.Prerequisites}, {"Risks", s.Risks}, {"Remaining unknowns", s.Unknowns}, {"Reversal limitations", s.Reversal}} {
			fmt.Fprintf(&b, "**%s**\n\n", part.title)
			for _, it := range part.items {
				fmt.Fprintf(&b, "- %s\n", md(it))
			}
			b.WriteString("\n")
		}
	}
	b.WriteString("## Limitations of the offline evaluation\n\n")
	for _, l := range r.Limitations {
		fmt.Fprintf(&b, "- %s\n", md(l))
	}
	b.WriteString("\nModels used: ")
	var parts []string
	for _, m := range r.Models {
		parts = append(parts, fmt.Sprintf("%s %s ([reference](%s))", m.ID, m.Version, m.Reference))
	}
	b.WriteString(strings.Join(parts, "; ") + ".\n")
	return b.String()
}
