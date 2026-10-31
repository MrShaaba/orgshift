package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/MrShaaba/orgshift/internal/evaluator"
	"github.com/MrShaaba/orgshift/internal/report"
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
	account := fs.String("account", "", "ID of the account to move (required)")
	targetOU := fs.String("target-ou", "", "ID of the destination OU or root (required)")
	format := fs.String("format", "text", "output format: text, json or markdown")
	out := fs.String("out", "", "write the report to this file instead of stdout")
	actions := fs.String("actions", "", "JSON file with actions in use; merged into the snapshot's list for the account")
	lastAccessed := fs.String("last-accessed", "", "IAM last-accessed export (get-service-last-accessed-details JSON) to import as actions in use")
	replace := fs.Bool("replace-actions", false, "replace the snapshot's actions in use instead of merging")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: orgshift simulate --from A.json [--to B.json] --account ID --target-ou OU [flags]")
		fs.PrintDefaults()
		fmt.Fprintln(os.Stderr, "\nExit codes: 0 GO, 2 REVIEW, 3 NO-GO, 1 error.")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *from == "" || *account == "" || *targetOU == "" {
		fs.Usage()
		return errors.New("--from, --account and --target-ou are required")
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
	res, err := evaluator.Evaluate(evaluator.Input{From: src, To: dst, AccountID: *account, TargetOUID: *targetOU})
	if err != nil {
		return err
	}
	var body []byte
	switch strings.ToLower(*format) {
	case "text":
		body = []byte(report.Text(res))
	case "json":
		if body, err = report.JSON(res); err != nil {
			return err
		}
	case "markdown", "md":
		body = []byte(report.Markdown(res))
	default:
		return fmt.Errorf("unknown format %q", *format)
	}
	if *out != "" {
		if err := os.WriteFile(*out, body, 0o644); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "wrote %s (%s)\n", *out, res.Verdict)
	} else {
		os.Stdout.Write(body)
	}
	switch res.Verdict {
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
