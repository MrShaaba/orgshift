package report

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/MrShaaba/orgshift/internal/preflight"
)

// PreflightJSON renders the preflight result as indented JSON.
func PreflightJSON(r *preflight.Result) ([]byte, error) {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// PreflightText renders the preflight for a terminal, in the coverage
// matrix layout: one line per domain, one column per side.
func PreflightText(r *preflight.Result) string {
	var b strings.Builder
	verdict := "READY"
	if !r.Ready {
		verdict = "NOT READY"
	}
	fmt.Fprintf(&b, "PREFLIGHT: %s\n\n%s\n\n", verdict, r.Line())
	b.WriteString("Identities\n")
	for _, s := range r.Sides {
		for _, id := range s.Identities {
			actual := id.Actual.ARN
			if actual == "" {
				actual = "-"
			}
			fmt.Fprintf(&b, "  %-12s %-18s expected %s  %-9s %s", s.Name, id.Access, id.Expected, id.Status, actual)
			if id.Via != "" {
				fmt.Fprintf(&b, "  (via %s)", id.Via)
			}
			b.WriteString("\n")
		}
	}
	b.WriteString("\nCapabilities (coverage matrix format)\n")
	target := "destination"
	if r.Matrix.SingleSide {
		target = "destination (none)"
	}
	fmt.Fprintf(&b, "  %-34s %-12s %-12s %s\n", "domain", "source", target, "decides")
	for _, row := range r.Matrix.Rows {
		fmt.Fprintf(&b, "  %-34s %-12s %-12s %s\n", row.Domain, cellText(row.Source), cellText(row.Target), row.Why)
	}
	b.WriteString("\nDetails\n")
	for _, s := range r.Sides {
		for _, d := range s.Domains {
			if d.Status == preflight.Available {
				continue
			}
			fmt.Fprintf(&b, "  %s %s: %s %s\n", s.Name, d.Domain, d.Status, d.Detail)
		}
	}
	if len(r.Blocking) > 0 {
		b.WriteString("\nBlocking\n")
		for _, x := range r.Blocking {
			fmt.Fprintf(&b, "  - %s\n", x)
		}
	}
	notes := append([]string(nil), r.Notes...)
	for _, s := range r.Sides {
		for _, n := range s.Notes {
			notes = append(notes, s.Name+": "+n)
		}
	}
	if len(notes) > 0 {
		b.WriteString("\nNotes\n")
		for _, n := range notes {
			fmt.Fprintf(&b, "  - %s\n", n)
		}
	}
	return b.String()
}

func cellText(c preflight.Cell) string {
	s := string(c.Status)
	if !c.Required && c.Status != preflight.Available {
		s += "*"
	}
	return s
}

// PreflightMarkdown renders the preflight as Markdown with the same table
// as the evaluation's coverage section.
func PreflightMarkdown(r *preflight.Result) string {
	var b strings.Builder
	verdict := "READY"
	if !r.Ready {
		verdict = "NOT READY"
	}
	fmt.Fprintf(&b, "# Preflight: %s\n\n%s. Generated %s by %s.\n\n", verdict, r.Line(), r.GeneratedAt, r.Tool)
	b.WriteString("## Identities\n\n| Side | Access | Expected account | Status | Identity | Via |\n|---|---|---|---|---|---|\n")
	for _, s := range r.Sides {
		for _, id := range s.Identities {
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s |\n", s.Name, id.Access, id.Expected, id.Status, md(id.Actual.ARN), md(id.Via))
		}
	}
	b.WriteString("\n## Capabilities\n\nThe rows are the collection domains of the coverage matrix; a cell is the worst outcome of that domain's probes on that side. An asterisk marks a domain that is not required (skipped in the configuration or not collected by this build).\n\n")
	b.WriteString("| Domain | Decides | Check | Source | Target |\n|---|---|---|---|---|\n")
	for _, row := range r.Matrix.Rows {
		fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %s |\n", row.Domain, row.Why, row.Check, mdCell(row.Source), mdCell(row.Target))
	}
	if len(r.Blocking) > 0 {
		b.WriteString("\n## Blocking\n\n")
		for _, x := range r.Blocking {
			fmt.Fprintf(&b, "- %s\n", md(x))
		}
	}
	b.WriteString("\n## Probes\n\n| Side | Access | Domain | Operation | Status | ms | Detail |\n|---|---|---|---|---|---|---|\n")
	for _, s := range r.Sides {
		for _, p := range s.Probes {
			fmt.Fprintf(&b, "| %s | %s | `%s` | `%s` | %s | %d | %s |\n", s.Name, md(p.Access), p.Domain, p.Operation, p.Status, p.Millis, md(p.Detail))
		}
	}
	notes := append([]string(nil), r.Notes...)
	for _, s := range r.Sides {
		for _, n := range s.Notes {
			notes = append(notes, s.Name+": "+n)
		}
	}
	if len(notes) > 0 {
		b.WriteString("\n## Notes\n\n")
		for _, n := range notes {
			fmt.Fprintf(&b, "- %s\n", md(n))
		}
	}
	return b.String()
}

func mdCell(c preflight.Cell) string {
	s := string(c.Status)
	if !c.Required && c.Status != preflight.Available {
		s += " (not required)"
	}
	if c.Detail != "" && c.Status != preflight.Available {
		s += ": " + md(c.Detail)
	}
	return s
}

func md(s string) string { return strings.ReplaceAll(s, "|", "\\|") }
