package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/MrShaaba/orgshift/internal/report"
	"github.com/MrShaaba/orgshift/internal/snapshot"
	"github.com/MrShaaba/orgshift/internal/workload"
)

func runWorkloads(args []string) error {
	fs := flag.NewFlagSet("workloads", flag.ContinueOnError)
	path := fs.String("snapshot", "", "snapshot file (required)")
	account := fs.String("account", "", "account ID; without it the accounts that have an inventory are listed")
	format := fs.String("format", "text", "output format: text, json or markdown")
	out := fs.String("out", "", "write the report to this file instead of stdout")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: orgshift workloads --snapshot FILE [--account ID] [--format text|json|markdown] [--out FILE]")
		fs.PrintDefaults()
		fmt.Fprintln(os.Stderr, "\nPrints the workload inventory of an account as the snapshot recorded it (CloudFormation stacks, the resource sample, the policies that reference organization identity) with the deployment provenance of every stack and resource and the evidence each classification rests on. Offline: nothing is called.")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *path == "" {
		fs.Usage()
		return errors.New("--snapshot is required")
	}
	snap, err := snapshot.Load(*path)
	if err != nil {
		return err
	}
	var body []byte
	if *account == "" {
		body = []byte(report.WorkloadsIndexText(snap))
	} else {
		if _, ok := snap.Index().AccountByID[*account]; !ok {
			return fmt.Errorf("account %s is not in the snapshot (%s)", *account, snap.Organization.ID)
		}
		inv := workload.Build(snap, *account)
		switch strings.ToLower(*format) {
		case "text":
			body = []byte(report.WorkloadsText(inv))
		case "json":
			if body, err = report.WorkloadsJSON(inv); err != nil {
				return err
			}
		case "markdown", "md":
			body = []byte(report.WorkloadsMarkdown(inv))
		default:
			return fmt.Errorf("unknown format %q", *format)
		}
	}
	if *out != "" {
		if err := os.WriteFile(*out, body, 0o644); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "wrote %s\n", *out)
		return nil
	}
	os.Stdout.Write(body)
	return nil
}
