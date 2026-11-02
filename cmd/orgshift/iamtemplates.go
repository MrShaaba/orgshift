package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/MrShaaba/orgshift/internal/config"
	"github.com/MrShaaba/orgshift/internal/iamtemplates"
)

func runIAMTemplates(args []string) error {
	fs := flag.NewFlagSet("iam-templates", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "onboarding configuration; without it the templates carry placeholders")
	sideName := fs.String("side", "source", "which side of the configuration the roles are for: source or destination")
	out := fs.String("out", "", "directory to write the trust and permissions policies and a README into (default: print the README to stdout)")
	format := fs.String("format", "markdown", "stdout format when --out is not given: markdown or json")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: orgshift iam-templates [--config orgshift.yaml] [--side source|destination] [--out DIR] [--format markdown|json]")
		fs.PrintDefaults()
		fmt.Fprintln(os.Stderr, "\nOne read-only role per collector responsibility (org-management, control-tower, identity-center, member-inspection, network), each with a trust policy, the account it goes in, the delegated-administrator alternative and a justification for every Resource \"*\". Generated locally from the operation catalog; nothing is called.")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	in := iamtemplates.Input{Side: *sideName}
	if *cfgPath != "" {
		cfg, err := config.Load(*cfgPath)
		if err != nil {
			return err
		}
		in.Config = cfg
	}
	ts, err := iamtemplates.Generate(in)
	if err != nil {
		return err
	}
	if *out != "" {
		paths, err := iamtemplates.Write(*out, ts, in)
		if err != nil {
			return err
		}
		fmt.Printf("wrote %d files to %s:\n  %s\n", len(paths), *out, strings.Join(paths, "\n  "))
		fmt.Println("Create the roles with the commands in README.md, then run: orgshift preflight --config", orDefault(*cfgPath, "orgshift.yaml"))
		return nil
	}
	switch strings.ToLower(*format) {
	case "markdown", "md":
		os.Stdout.WriteString(iamtemplates.Markdown(ts, in))
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if err := enc.Encode(ts); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown format %q", *format)
	}
	return nil
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
