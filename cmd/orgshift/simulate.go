package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/MrShaaba/orgshift/internal/evaluator"
	"github.com/MrShaaba/orgshift/internal/report"
	"github.com/MrShaaba/orgshift/internal/runbook"
	"github.com/MrShaaba/orgshift/internal/snapshot"
	"github.com/MrShaaba/orgshift/internal/usage"
)

// errVerdict carries the verdict out of runSimulate so main can map it to
// an exit code (0 GO, 2 REVIEW, 3 NO-GO) without printing an error.
type errVerdict struct{ code int }

func (e errVerdict) Error() string { return fmt.Sprintf("verdict exit code %d", e.code) }

func runSimulate(args []string) error {
	fs := flag.NewFlagSet("simulate", flag.ContinueOnError)
	from := fs.String("from", "", "source snapshot (required)")
	to := fs.String("to", "", "destination snapshot; omit for a move inside the same organization")
	account := fs.String("account", "", "ID of the account to move (this or --ou is required)")
	ou := fs.String("ou", "", "ID of the OU to move with everything under it (this or --account is required)")
	targetOU := fs.String("target-ou", "", "ID of the destination OU or root; for --ou, the new parent (required)")
	format := fs.String("format", "text", "output format: text, json, markdown, runbook (the migration runbook as Markdown) or runbook-json")
	out := fs.String("out", "", "write the report to this file instead of stdout")
	actions := fs.String("actions", "", "JSON file with actions in use; merged into the snapshot's list for the account")
	lastAccessed := fs.String("last-accessed", "", "IAM last-accessed export (get-service-last-accessed-details JSON) to import as actions in use")
	replace := fs.Bool("replace-actions", false, "replace the snapshot's actions in use instead of merging")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: orgshift simulate --from A.json [--to B.json] (--account ID | --ou OU) --target-ou OU [flags]")
		fs.PrintDefaults()
		fmt.Fprintln(os.Stderr, "\nExit codes: 0 GO, 2 REVIEW, 3 NO-GO, 1 error.")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *from == "" || *targetOU == "" || (*account == "") == (*ou == "") {
		fs.Usage()
		return errors.New("--from, --target-ou and exactly one of --account or --ou are required")
	}
	if *ou != "" && (*actions != "" || *lastAccessed != "") {
		return errors.New("--actions and --last-accessed apply to a single account; use --account")
	}
	src, err := snapshot.Load(*from)
	if err != nil {
		return err
	}
	var dst *snapshot.Snapshot
	if *to != "" {
		if dst, err = snapshot.Load(*to); err != nil {
			return err
		}
	}
	if err := applyUsageFlags(src, *account, *actions, *lastAccessed, *replace); err != nil {
		return err
	}
	var (
		verdict evaluator.Status
		body    []byte
	)
	f := strings.ToLower(*format)
	if f == "md" {
		f = "markdown"
	}
	if *ou != "" {
		res, err := evaluator.EvaluateOU(evaluator.OUInput{From: src, To: dst, OUID: *ou, TargetParentID: *targetOU})
		if err != nil {
			return err
		}
		verdict = res.Verdict
		switch f {
		case "text":
			body = []byte(report.OUText(res))
		case "json":
			if body, err = report.OUJSON(res); err != nil {
				return err
			}
		case "markdown":
			body = []byte(report.OUMarkdown(res))
		case "runbook":
			body = []byte(report.OURunbookMarkdown(runbook.BuildOU(res, src, dst)))
		case "runbook-json":
			if body, err = report.OURunbookJSON(runbook.BuildOU(res, src, dst)); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown format %q", *format)
		}
	} else {
		res, err := evaluator.Evaluate(evaluator.Input{From: src, To: dst, AccountID: *account, TargetOUID: *targetOU})
		if err != nil {
			return err
		}
		verdict = res.Verdict
		switch f {
		case "text":
			body = []byte(report.Text(res))
		case "json":
			if body, err = report.JSON(res); err != nil {
				return err
			}
		case "markdown":
			body = []byte(report.Markdown(res))
		case "runbook":
			body = []byte(report.RunbookMarkdown(runbook.Build(res, src, dst)))
		case "runbook-json":
			if body, err = report.RunbookJSON(runbook.Build(res, src, dst)); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown format %q", *format)
		}
	}
	if *out != "" {
		if err := os.WriteFile(*out, body, 0o644); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "wrote %s (%s)\n", *out, verdict)
	} else {
		os.Stdout.Write(body)
	}
	switch verdict {
	case evaluator.StatusReview:
		return errVerdict{2}
	case evaluator.StatusNoGo:
		return errVerdict{3}
	}
	return nil
}

// applyUsageFlags merges --actions and --last-accessed into the snapshot.
func applyUsageFlags(s *snapshot.Snapshot, account, actionsPath, lastAccessedPath string, replace bool) error {
	if actionsPath == "" && lastAccessedPath == "" {
		return nil
	}
	var added []snapshot.ActionInUse
	if actionsPath != "" {
		a, err := usage.LoadActionsFile(actionsPath)
		if err != nil {
			return err
		}
		added = append(added, a...)
	}
	if lastAccessedPath != "" {
		a, err := usage.LoadLastAccessed(lastAccessedPath)
		if err != nil {
			return err
		}
		added = append(added, a...)
	}
	if s.Usage == nil {
		s.Usage = map[string]*snapshot.AccountUsage{}
	}
	u := s.Usage[account]
	if u == nil {
		u = &snapshot.AccountUsage{}
		s.Usage[account] = u
	}
	if replace {
		u.Actions = added
	} else {
		u.Actions = usage.Merge(u.Actions, added)
	}
	return nil
}
