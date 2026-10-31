// Package report renders evaluation results as JSON, Markdown and plain text.
package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/MrShaaba/orgshift/internal/evaluator"
	"github.com/MrShaaba/orgshift/internal/snapshot"
)

// JSON renders the result as indented JSON.
func JSON(r *evaluator.Result) ([]byte, error) {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// Markdown renders the result as a Markdown document.
func Markdown(r *evaluator.Result) string {
	var b strings.Builder
	s := r.Subject
	fmt.Fprintf(&b, "# orgshift verdict: %s\n\n", r.Verdict)
	fmt.Fprintf(&b, "%s\n\n", r.Summary)
	fmt.Fprintf(&b, "| | Source | Target |\n|---|---|---|\n")
	fmt.Fprintf(&b, "| Organization | %s | %s |\n", orgLabel(s.SourceOrg), orgLabel(s.TargetOrg))
	fmt.Fprintf(&b, "| Path | %s | %s |\n\n", snapshot.PathString(s.SourcePath), snapshot.PathString(s.TargetPath))
	fmt.Fprintf(&b, "Account `%s` (%s). Evaluated %d actions in use, %d inbound access entries and %d tagged resources. Regions assumed when an action has none: %s.\n\n",
		s.AccountID, s.AccountName, s.ActionsInUse, s.InboundAccess, s.TaggedResources, orNone(strings.Join(s.RegionsAssumed, ", ")))
	for _, n := range r.Notes {
		fmt.Fprintf(&b, "> %s\n\n", n)
	}

	b.WriteString("## Checks\n\n| Check | Status | Summary |\n|---|---|---|\n")
	for _, c := range r.Checks {
		fmt.Fprintf(&b, "| %s | %s | %s |\n", c.Title, c.Status, c.Summary)
	}
	b.WriteString("\n")

	for _, c := range r.Checks {
		fmt.Fprintf(&b, "## %s: %s\n\n", c.Title, c.Status)
		if c.Summary != "" {
			fmt.Fprintf(&b, "%s\n\n", c.Summary)
		}
		if len(c.Findings) == 0 {
			b.WriteString("No findings.\n\n")
			continue
		}
		for _, f := range c.Findings {
			fmt.Fprintf(&b, "### %s: %s\n\n", f.Status, f.Title)
			fmt.Fprintf(&b, "%s\n\n", f.Detail)
			var meta []string
			if f.Action != "" {
				meta = append(meta, "action `"+f.Action+"`")
			}
			if f.Principal != "" {
				meta = append(meta, "principal `"+f.Principal+"`")
			}
			if f.Resource != "" {
				meta = append(meta, "resource `"+f.Resource+"`")
			}
			if len(f.Regions) > 0 {
				meta = append(meta, "regions "+strings.Join(f.Regions, ", "))
			}
			if len(meta) > 0 {
				fmt.Fprintf(&b, "%s\n\n", strings.Join(meta, "; "))
			}
			for _, ev := range f.Evidence {
				writeEvidence(&b, ev)
			}
		}
	}

	b.WriteString("## What changes: effective policies\n\n")
	for _, d := range r.Diff {
		fmt.Fprintf(&b, "### %s\n\n", d.TypeShort)
		if !d.EnabledTarget && !d.EnabledSource {
			b.WriteString("Not enabled in either organization.\n\n")
			continue
		}
		b.WriteString("| | Source chain | Target chain |\n|---|---|---|\n")
		rows := len(d.SourceChain)
		if len(d.TargetChain) > rows {
			rows = len(d.TargetChain)
		}
		for i := 0; i < rows; i++ {
			fmt.Fprintf(&b, "| %d | %s | %s |\n", i+1, chainCell(d.SourceChain, i), chainCell(d.TargetChain, i))
		}
		b.WriteString("\n")
		writeRefs(&b, "Added", d.Added)
		writeRefs(&b, "Removed", d.Removed)
		writeRefs(&b, "Changed (same name, different document)", d.Changed)
		writeRefs(&b, "Unchanged", d.Unchanged)
	}
	return b.String()
}

func chainCell(ch []evaluator.ChainLink, i int) string {
	if i >= len(ch) {
		return ""
	}
	l := ch[i]
	names := make([]string, 0, len(l.Policies))
	for _, p := range l.Policies {
		names = append(names, "`"+p.Name+"`")
	}
	if len(names) == 0 {
		names = append(names, "(none)")
	}
	return fmt.Sprintf("**%s** %s", l.Node.Name, strings.Join(names, ", "))
}

func writeRefs(b *strings.Builder, title string, refs []evaluator.PolicyRef) {
	if len(refs) == 0 {
		return
	}
	fmt.Fprintf(b, "**%s**\n\n", title)
	for _, p := range refs {
		fmt.Fprintf(b, "- `%s` (%s) at %s", p.Name, p.ID, p.Level)
		if p.Description != "" {
			fmt.Fprintf(b, ": %s", p.Description)
		}
		b.WriteString("\n")
		for _, st := range p.Statements {
			acts := st.Actions
			prefix := ""
			if len(st.NotActions) > 0 {
				acts = st.NotActions
				prefix = "NotAction "
			}
			cond := ""
			if st.HasCondition {
				cond = " when " + strings.Join(st.Conditions, " and ")
			}
			fmt.Fprintf(b, "  - %s %s%s%s\n", st.Effect, prefix, strings.Join(acts, ", "), cond)
		}
	}
	b.WriteString("\n")
}

func writeEvidence(b *strings.Builder, ev evaluator.Evidence) {
	var head []string
	if ev.Side != "" {
		head = append(head, ev.Side)
	}
	if ev.PolicyName != "" {
		head = append(head, fmt.Sprintf("%s `%s` (%s)", ev.PolicyType, ev.PolicyName, ev.PolicyID))
	}
	if ev.Statement != "" {
		head = append(head, "statement "+ev.Statement)
	}
	if ev.Level != "" {
		head = append(head, "at "+ev.Level)
	}
	if ev.Reference != "" {
		head = append(head, "`"+ev.Reference+"`")
	}
	fmt.Fprintf(b, "- Evidence (%s): %s", ev.Kind, strings.Join(head, ", "))
	if ev.Note != "" {
		fmt.Fprintf(b, "\n  %s", strings.ReplaceAll(ev.Note, "\n", "\n  "))
	}
	b.WriteString("\n")
	if len(ev.StatementJSON) > 0 {
		var buf bytes.Buffer
		if err := json.Indent(&buf, ev.StatementJSON, "  ", "  "); err == nil {
			fmt.Fprintf(b, "\n  ```json\n  %s\n  ```\n", buf.String())
		}
	}
	b.WriteString("\n")
}

// Text renders a compact terminal summary.
func Text(r *evaluator.Result) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n\n%s\n\n", banner(r.Verdict), r.Summary)
	for _, n := range r.Notes {
		fmt.Fprintf(&b, "note: %s\n", n)
	}
	for _, c := range r.Checks {
		fmt.Fprintf(&b, "[%-6s] %s", c.Status, c.Title)
		if c.Summary != "" {
			fmt.Fprintf(&b, " - %s", c.Summary)
		}
		b.WriteString("\n")
		for _, f := range c.Findings {
			if f.Status == evaluator.StatusInfo {
				continue
			}
			fmt.Fprintf(&b, "    %-6s %s", f.Status, f.Title)
			if len(f.Regions) > 0 {
				fmt.Fprintf(&b, " [%s]", strings.Join(f.Regions, ", "))
			}
			b.WriteString("\n")
			for _, ev := range f.Evidence {
				if ev.PolicyName != "" {
					fmt.Fprintf(&b, "           %s %s / %s at %s\n", ev.PolicyType, ev.PolicyName, ev.Statement, ev.Level)
				}
			}
		}
		info := c.Counts()[evaluator.StatusInfo]
		if info > 0 {
			fmt.Fprintf(&b, "    (%d informational finding(s) omitted; use --format markdown or json for everything)\n", info)
		}
	}
	return b.String()
}

func banner(s evaluator.Status) string {
	line := strings.Repeat("=", len(s)+12)
	return fmt.Sprintf("%s\n   VERDICT: %s\n%s", line, s, line)
}

func orgLabel(o evaluator.OrgRef) string {
	if o.Name != "" {
		return fmt.Sprintf("%s (`%s`)", o.Name, o.ID)
	}
	return "`" + o.ID + "`"
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}
