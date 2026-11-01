package report

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/MrShaaba/orgshift/internal/evaluator"
	"github.com/MrShaaba/orgshift/internal/runbook"
	"github.com/MrShaaba/orgshift/internal/snapshot"
)

// RunbookJSON renders a runbook as indented JSON.
func RunbookJSON(rb *runbook.Runbook) ([]byte, error) {
	data, err := json.MarshalIndent(rb, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// OURunbookJSON renders an OU runbook as indented JSON.
func OURunbookJSON(rb *runbook.OURunbook) ([]byte, error) {
	data, err := json.MarshalIndent(rb, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// RunbookMarkdown renders a runbook as a Markdown checklist, one task list
// item per step with its commands and evidence.
func RunbookMarkdown(rb *runbook.Runbook) string {
	var b strings.Builder
	s := rb.Subject
	fmt.Fprintf(&b, "# orgshift runbook: %s (%s)\n\n", s.AccountName, s.AccountID)
	fmt.Fprintf(&b, "Move from **%s** (`%s`) %s to **%s** (`%s`) %s.\n\n", orNone(s.SourceOrg.Name), s.SourceOrg.ID, snapshot.PathString(s.SourcePath[:len(s.SourcePath)-1]),
		orNone(s.TargetOrg.Name), s.TargetOrg.ID, snapshot.PathString(s.TargetPath[:len(s.TargetPath)-1]))
	fmt.Fprintf(&b, "**Verdict %s.** %s\n\n", rb.Verdict, rb.Summary)
	for _, n := range rb.Notes {
		fmt.Fprintf(&b, "> %s\n\n", n)
	}
	writeRunbookPhases(&b, rb.Phases, 2)
	return b.String()
}

// OURunbookMarkdown renders an OU runbook: the OU-level phases, then one
// section per account with its own checklist.
func OURunbookMarkdown(rb *runbook.OURunbook) string {
	var b strings.Builder
	s := rb.Subject
	fmt.Fprintf(&b, "# orgshift runbook: OU %s (%s)\n\n", s.OUName, s.OUID)
	fmt.Fprintf(&b, "Move from **%s** (`%s`) %s to **%s** (`%s`) %s, with %d nested OU(s) and %d account(s).\n\n", orNone(s.SourceOrg.Name), s.SourceOrg.ID, snapshot.PathString(s.SourcePath[:len(s.SourcePath)-1]),
		orNone(s.TargetOrg.Name), s.TargetOrg.ID, snapshot.PathString(s.TargetPath[:len(s.TargetPath)-1]), s.NestedOUs, s.Accounts)
	fmt.Fprintf(&b, "**Verdict %s.** %s\n\n", rb.Verdict, rb.Summary)
	for _, n := range rb.Notes {
		fmt.Fprintf(&b, "> %s\n\n", n)
	}
	b.WriteString("## Accounts\n\n| Verdict | Account | Steps | Blocking |\n|---|---|---|---|\n")
	for _, a := range rb.Accounts {
		blocking := 0
		for _, st := range a.Phase(runbook.PhaseBefore).Steps {
			if st.Status == evaluator.StatusNoGo {
				blocking++
			}
		}
		fmt.Fprintf(&b, "| %s | %s (`%s`) | %d | %d |\n", a.Verdict, a.Subject.AccountName, a.Subject.AccountID, len(a.Steps()), blocking)
	}
	b.WriteString("\n")
	writeRunbookPhases(&b, rb.Phases, 2)
	for _, a := range rb.Accounts {
		fmt.Fprintf(&b, "## Account %s (`%s`): %s\n\n%s\n\n", a.Subject.AccountName, a.Subject.AccountID, a.Verdict, a.Summary)
		writeRunbookPhases(&b, a.Phases, 3)
	}
	return b.String()
}

func writeRunbookPhases(b *strings.Builder, phases []runbook.Phase, level int) {
	h := strings.Repeat("#", level)
	for i, p := range phases {
		fmt.Fprintf(b, "%s %d. %s\n\n", h, i+1, p.Title)
		if p.Intro != "" {
			fmt.Fprintf(b, "%s\n\n", p.Intro)
		}
		if len(p.Steps) == 0 {
			b.WriteString("Nothing to do in this phase.\n\n")
			continue
		}
		for j, st := range p.Steps {
			writeStep(b, fmt.Sprintf("%d.%d", i+1, j+1), st)
		}
	}
}

func writeStep(b *strings.Builder, number string, st runbook.Step) {
	fmt.Fprintf(b, "- [ ] **%s** ", number)
	if st.Status != "" {
		fmt.Fprintf(b, "`%s` ", st.Status)
	}
	fmt.Fprintf(b, "%s\n", st.Title)
	var body strings.Builder
	if st.Where != "" {
		fmt.Fprintf(&body, "_Where:_ %s\n\n", st.Where)
	}
	if st.Detail != "" {
		fmt.Fprintf(&body, "%s\n\n", st.Detail)
	}
	var meta []string
	if len(st.Actions) > 0 {
		meta = append(meta, "actions `"+strings.Join(st.Actions, "`, `")+"`")
	}
	if st.Principal != "" {
		meta = append(meta, "principal `"+st.Principal+"`")
	}
	if st.Resource != "" {
		meta = append(meta, "resource `"+st.Resource+"`")
	}
	if len(st.Regions) > 0 {
		meta = append(meta, "regions "+strings.Join(st.Regions, ", "))
	}
	if len(meta) > 0 {
		fmt.Fprintf(&body, "%s\n\n", strings.Join(meta, "; "))
	}
	if st.Check != "" {
		ref := "From the " + st.Check + " check"
		if st.Finding != "" {
			ref += ": " + st.Finding
		}
		fmt.Fprintf(&body, "_%s._\n\n", strings.ReplaceAll(ref, "_", "\\_"))
	}
	if len(st.Commands) > 0 {
		fmt.Fprintf(&body, "```sh\n%s\n```\n\n", strings.Join(st.Commands, "\n"))
	}
	for _, ev := range st.Evidence {
		writeEvidence(&body, ev)
	}
	for _, line := range strings.Split(strings.TrimRight(body.String(), "\n"), "\n") {
		if line == "" {
			b.WriteString("\n")
		} else {
			b.WriteString("  " + line + "\n")
		}
	}
	b.WriteString("\n")
}
