package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/MrShaaba/orgshift/internal/report"
	"github.com/MrShaaba/orgshift/internal/scenario"
	"github.com/MrShaaba/orgshift/internal/snapshot"
)

func runStages(args []string) error {
	fs := flag.NewFlagSet("stages", flag.ContinueOnError)
	scPath := fs.String("scenario", "", "scenario overlay file (YAML or JSON); see `orgshift scenario example` (required)")
	from := fs.String("from", "", "source snapshot (default: the scenario's source, relative to the scenario file)")
	to := fs.String("to", "", "destination snapshot (default: the scenario's destination; omit for a move inside one organization)")
	format := fs.String("format", "text", "output format: text, json or markdown")
	out := fs.String("out", "", "write the report to this file instead of stdout")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: orgshift stages --scenario plan.yaml [--from A.json] [--to B.json] [--format text|json|markdown] [--out FILE]")
		fs.PrintDefaults()
		fmt.Fprintln(os.Stderr, "\nEvery stage of the scenario is derived as a state (membership, placement, governance, network, workload) and evaluated as a move from the previous state. Snapshots are never modified; proposed OUs, policies and shares exist only in the derived states and are listed apart.")
		fmt.Fprintln(os.Stderr, "Exit codes: 0 GO, 2 REVIEW, 3 NO-GO, 1 error.")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *scPath == "" {
		fs.Usage()
		return errors.New("--scenario is required")
	}
	sc, err := scenario.Load(*scPath)
	if err != nil {
		return err
	}
	dir := filepath.Dir(*scPath)
	resolve := func(flagValue, fromScenario string) string {
		if flagValue != "" {
			return flagValue
		}
		if fromScenario == "" {
			return ""
		}
		if filepath.IsAbs(fromScenario) {
			return fromScenario
		}
		return filepath.Join(dir, fromScenario)
	}
	srcPath, dstPath := resolve(*from, sc.Source), resolve(*to, sc.Destination)
	if srcPath == "" {
		return errors.New("--from is required when the scenario names no source snapshot")
	}
	src, err := snapshot.Load(srcPath)
	if err != nil {
		return err
	}
	var dst *snapshot.Snapshot
	if dstPath != "" {
		if dst, err = snapshot.Load(dstPath); err != nil {
			return err
		}
	}
	rep, err := scenario.Run(scenario.Input{Scenario: sc, Source: src, Destination: dst, Version: version})
	if err != nil {
		return err
	}
	var body []byte
	switch strings.ToLower(*format) {
	case "text":
		body = []byte(report.StagesText(rep))
	case "json":
		if body, err = report.StagesJSON(rep); err != nil {
			return err
		}
	case "markdown", "md":
		body = []byte(report.StagesMarkdown(rep))
	default:
		return fmt.Errorf("unknown format %q", *format)
	}
	if *out != "" {
		if err := os.WriteFile(*out, body, 0o644); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "wrote %s (%s)\n", *out, rep.Verdict)
	} else {
		os.Stdout.Write(body)
	}
	return verdictExit(rep.Verdict)
}

func runScenario(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: orgshift scenario example | orgshift scenario check --scenario FILE")
	}
	switch args[0] {
	case "example":
		os.Stdout.WriteString(scenario.Example)
		return nil
	case "check":
		fs := flag.NewFlagSet("scenario check", flag.ContinueOnError)
		scPath := fs.String("scenario", "", "scenario file to validate (required)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *scPath == "" {
			return errors.New("--scenario is required")
		}
		sc, err := scenario.Load(*scPath)
		if err != nil {
			return err
		}
		fmt.Printf("%s is valid: %q, account %s, strategy %s, %d stage(s), %d critical operation(s), %d proposed OU(s), %d proposed policy(ies), %d proposed share(s)\n",
			*scPath, sc.Name, sc.AccountID, sc.Strategy, len(sc.Stages), len(sc.CriticalOperations), len(sc.Proposed.OUs), len(sc.Proposed.Policies), len(sc.Proposed.ResourceShares))
		for i, st := range sc.Stages {
			var layers []string
			if st.Membership != nil {
				layers = append(layers, "membership")
			}
			if st.Placement != nil {
				layers = append(layers, "placement")
			}
			if st.Governance != nil {
				layers = append(layers, "governance")
			}
			if st.Network != nil {
				layers = append(layers, "network")
			}
			if st.Workload != nil {
				layers = append(layers, "workload")
			}
			if st.Policies != nil {
				layers = append(layers, "policies")
			}
			fmt.Printf("  %d. %s (%s): %s\n", i+1, st.Title, st.ID, orDefault(strings.Join(layers, ", "), "verification only"))
		}
		fmt.Println("References to snapshot objects are checked when the scenario runs: orgshift stages --scenario", *scPath)
		return nil
	default:
		return fmt.Errorf("unknown scenario subcommand %q (example or check)", args[0])
	}
}
