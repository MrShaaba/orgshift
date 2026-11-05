package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/MrShaaba/orgshift/internal/config"
	"github.com/MrShaaba/orgshift/internal/preflight"
	"github.com/MrShaaba/orgshift/internal/report"
)

func runPreflight(args []string) error {
	fs := flag.NewFlagSet("preflight", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "onboarding configuration (YAML or JSON); see `orgshift config example` (required)")
	sideName := fs.String("side", "both", "which side to probe: source, destination or both")
	format := fs.String("format", "text", "output format: text, json or markdown")
	out := fs.String("out", "", "write the report to this file instead of stdout")
	timeout := fs.Duration("timeout", 5*time.Minute, "overall timeout")
	bucketPolicies := fs.Bool("with-bucket-policies", false, "OPT-IN, COSTS MONEY: also probe the bucket policy reads (S3 bills one LIST request and one request for the first bucket, per inspected account)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: orgshift preflight --config orgshift.yaml [--side source|destination|both] [--format text|json|markdown] [--out FILE]")
		fs.PrintDefaults()
		fmt.Fprintln(os.Stderr, "\nFor every collection domain the cheapest read call is tried (one page, one item) and reported as available, denied, error or unknown, in the coverage matrix layout. Nothing is written to AWS.")
		fmt.Fprintln(os.Stderr, "Exit codes: 0 ready, 2 not ready (a denied, failed or mismatched credential), 1 error.")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgPath == "" {
		fs.Usage()
		return errors.New("--config is required")
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if *bucketPolicies {
		cfg.Billable.BucketPolicies = true
	}
	var names []string
	switch *sideName {
	case "both":
		for _, s := range cfg.Sides() {
			names = append(names, s.Name)
		}
	case "source", "destination":
		if _, err := cfg.Side(*sideName); err != nil {
			return err
		}
		names = []string{*sideName}
	default:
		return fmt.Errorf("--side must be source, destination or both, got %q", *sideName)
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	logger := log.New(os.Stderr, "preflight ", log.LstdFlags)
	in := preflight.Input{Version: version, Logger: logger}
	for _, name := range names {
		sc, err := buildSide(ctx, cfg, name, false, version, logger)
		if err != nil {
			return err
		}
		in.Sides = append(in.Sides, sc.preflight)
	}
	res := preflight.Run(ctx, in)
	var body []byte
	switch strings.ToLower(*format) {
	case "text":
		body = []byte(report.PreflightText(res))
	case "json":
		if body, err = report.PreflightJSON(res); err != nil {
			return err
		}
	case "markdown", "md":
		body = []byte(report.PreflightMarkdown(res))
	default:
		return fmt.Errorf("unknown format %q", *format)
	}
	if *out != "" {
		if err := os.WriteFile(*out, body, 0o644); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "wrote %s (%s)\n", *out, res.Line())
	} else {
		os.Stdout.Write(body)
	}
	if !res.Ready {
		return errVerdict{2}
	}
	return nil
}
