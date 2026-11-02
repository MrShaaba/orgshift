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

	"github.com/MrShaaba/orgshift/internal/collector"
	"github.com/MrShaaba/orgshift/internal/config"
	"github.com/MrShaaba/orgshift/internal/snapshot"
)

func runCollect(args []string) error {
	fs := flag.NewFlagSet("collect", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "onboarding configuration (YAML or JSON); see `orgshift config example`")
	sideName := fs.String("side", "source", "which side of the configuration to collect: source or destination")
	out := fs.String("out", "", "snapshot file to write (required)")
	checkpoint := fs.String("checkpoint", "", "checkpoint file (default <out>.checkpoint.json); a rerun restores the completed steps from it")
	noCheckpoint := fs.Bool("no-checkpoint", false, "do not write or read a checkpoint")
	fresh := fs.Bool("fresh", false, "ignore and remove an existing checkpoint")
	keep := fs.Bool("keep-checkpoint", false, "keep the checkpoint after a complete run")
	concurrency := fs.Int("concurrency", 0, "parallel per-item calls (default from the configuration, 4)")
	timeout := fs.Duration("timeout", 0, "overall timeout (default from the configuration, 10m)")
	// Legacy flags, for a quick collection without a configuration file.
	profile := fs.String("profile", "", "without --config: AWS profile for the management account")
	expectAccount := fs.String("expect-account", "", "without --config: the account ID the credentials must belong to (required with --profile)")
	region := fs.String("region", "us-east-1", "without --config: region for the API endpoints, the Control Tower home region and the Identity Center region")
	name := fs.String("name", "", "without --config: friendly organization name to store in the snapshot")
	skipRAM := fs.Bool("skip-ram", false, "without --config: do not list resource shares")
	skipRegions := fs.Bool("skip-regions", false, "without --config: do not call account:ListRegions for every account")
	skipControlTower := fs.Bool("skip-control-tower", false, "without --config: do not read the Control Tower landing zone")
	skipIdentityCenter := fs.Bool("skip-identity-center", false, "without --config: do not read IAM Identity Center")
	retries := fs.Int("retry-attempts", 0, "SDK attempts per call, adaptive retry mode (default from the configuration, 8)")
	// Optional data sources that can cost money. Off by default, and in this
	// version they only print the cost warning; see ROADMAP.md.
	cloudTrailLake := fs.Bool("with-cloudtrail-lake", false, "OPT-IN, COSTS MONEY: query CloudTrail Lake for actions in use (not implemented yet)")
	configQueries := fs.Bool("with-config-queries", false, "OPT-IN, COSTS MONEY: run Config aggregator advanced queries for resource inventories (not implemented yet)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: orgshift collect --config orgshift.yaml [--side source|destination] --out FILE [flags]")
		fmt.Fprintln(os.Stderr, "       orgshift collect --profile NAME --expect-account ID --out FILE [--region R] [flags]")
		fs.PrintDefaults()
		fmt.Fprintln(os.Stderr, "\nOnly the read operations in the catalog (docs/permissions.md) are called. Nothing is ever written to AWS.")
		fmt.Fprintln(os.Stderr, "Every credential is checked with sts:GetCallerIdentity against the account the configuration names before anything is read.")
		fmt.Fprintln(os.Stderr, "Every domain the collector could not read is recorded in the snapshot's coverage block instead of being left as an empty list.")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		fs.Usage()
		return errors.New("--out is required")
	}
	if *cloudTrailLake {
		return errors.New("--with-cloudtrail-lake: CloudTrail Lake queries are billed per TB scanned; this data source is listed in ROADMAP.md and not implemented in this version, so the flag is refused rather than silently ignored")
	}
	if *configQueries {
		return errors.New("--with-config-queries: Config advanced queries against an aggregator are billed per query; this data source is listed in ROADMAP.md and not implemented in this version, so the flag is refused rather than silently ignored")
	}
	var cfg *config.Config
	if *cfgPath != "" {
		c, err := config.Load(*cfgPath)
		if err != nil {
			return err
		}
		cfg = c
	} else {
		c, err := legacyConfig(*profile, *expectAccount, *region, *name, *skipRAM, *skipRegions, *skipControlTower, *skipIdentityCenter)
		if err != nil {
			fs.Usage()
			return err
		}
		cfg = c
		*sideName = "source"
	}
	if cfg.Billable.CloudTrailLake || cfg.Billable.ConfigQueries {
		return errors.New("billable.cloudtrail_lake and billable.config_queries are not implemented in this version; set them to false (ROADMAP.md)")
	}
	if *retries > 0 {
		cfg.Collection.RetryAttempts = *retries
	}
	if *concurrency > 0 {
		cfg.Collection.Concurrency = *concurrency
	}
	if *timeout > 0 {
		cfg.Collection.Timeout = config.Duration(*timeout)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.Collection.Timeout))
	defer cancel()
	logger := log.New(os.Stderr, "collect ", log.LstdFlags)

	sc, err := buildSide(ctx, cfg, *sideName, true, version, logger)
	if err != nil {
		return err
	}
	for _, id := range sc.identities {
		fmt.Fprintln(os.Stderr, "identity verified:", id)
	}
	opts := sc.collect
	if !*noCheckpoint && cfg.Collection.Checkpointing() {
		opts.Checkpoint = *checkpoint
		if opts.Checkpoint == "" {
			opts.Checkpoint = strings.TrimSuffix(*out, ".json") + ".checkpoint.json"
		}
		opts.KeepCheckpoint = *keep
		if *fresh {
			if err := os.Remove(opts.Checkpoint); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
	}
	snap, err := collector.Collect(ctx, opts)
	if err != nil {
		return err
	}
	if err := snapshot.Save(*out, snap); err != nil {
		return err
	}
	fmt.Printf("wrote %s\n%s\n", *out, collector.Summary(snap))
	fmt.Println("Next: add usage.actions (or use --last-accessed at simulate time) for the account you plan to move.")
	if snap.ControlTower != nil {
		fmt.Println("Control Tower: enrolled accounts were read from ListEnabledBaselines; whether Account Factory vended an account is not visible that way, so add provisioned_product by hand where it matters.")
	}
	if snap.IdentityCenter != nil {
		fmt.Println("Identity Center: assignments were listed for the accounts each permission set is provisioned in; principal names come from the identity store when identitystore:DescribeUser/DescribeGroup are allowed.")
	}
	if gaps := snap.CoverageGaps(); len(gaps) > 0 {
		fmt.Printf("Coverage: %d domain(s) could not be read completely; simulations against this snapshot report them as REVIEW until they are collected.\n", len(gaps))
		if opts.Checkpoint != "" {
			fmt.Printf("Checkpoint: %s is kept; fix the cause and run the same command again to collect only what is missing.\n", opts.Checkpoint)
		}
	}
	return nil
}

// legacyConfig turns the pre-configuration flags into a one-sided
// configuration so collection always goes through the same identity check.
func legacyConfig(profile, expectAccount, region, name string, skipRAM, skipRegions, skipCT, skipIdC bool) (*config.Config, error) {
	if expectAccount == "" {
		return nil, errors.New("--config, or --expect-account with the legacy flags, is required: the collector refuses to run without knowing which account the credentials must belong to")
	}
	if name == "" {
		name = "organization " + expectAccount
	}
	off := false
	side := config.Side{Name: name, Management: config.Access{AccountID: expectAccount, Region: region, Profile: profile}}
	if skipRAM {
		side.Skip = append(side.Skip, snapshot.DomainResourceShares)
	}
	if skipRegions {
		side.Skip = append(side.Skip, snapshot.DomainEnabledRegions)
	}
	if skipCT {
		side.ControlTower = &config.ControlTower{Enabled: &off}
	}
	if skipIdC {
		side.IdentityCenter = &config.IdentityCenter{Enabled: &off}
	}
	c := &config.Config{SchemaVersion: config.SchemaVersion, Source: side}
	data, err := c.JSON()
	if err != nil {
		return nil, err
	}
	// Parse applies the defaults and the validation.
	return config.Parse(data)
}
