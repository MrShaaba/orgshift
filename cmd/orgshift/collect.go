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

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/account"
	"github.com/aws/aws-sdk-go-v2/service/controlcatalog"
	"github.com/aws/aws-sdk-go-v2/service/controltower"
	"github.com/aws/aws-sdk-go-v2/service/identitystore"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/ram"
	"github.com/aws/aws-sdk-go-v2/service/ssoadmin"

	"github.com/MrShaaba/orgshift/internal/collector"
	"github.com/MrShaaba/orgshift/internal/snapshot"
)

func runCollect(args []string) error {
	fs := flag.NewFlagSet("collect", flag.ContinueOnError)
	profile := fs.String("profile", "", "AWS profile for the management or delegated-administrator account (default: the standard credential chain)")
	region := fs.String("region", "us-east-1", "region used for the API endpoints")
	name := fs.String("name", "", "friendly organization name to store in the snapshot")
	out := fs.String("out", "", "snapshot file to write (required)")
	ramProfiles := fs.String("ram-profiles", "", "comma-separated extra profiles whose owned RAM shares should be included (for example the network account)")
	skipRAM := fs.Bool("skip-ram", false, "do not list resource shares owned by the main profile")
	skipRegions := fs.Bool("skip-regions", false, "do not call account:ListRegions for every account")
	skipControlTower := fs.Bool("skip-control-tower", false, "do not read the Control Tower landing zone (its APIs answer only in the home region, so set --region to it)")
	skipIdentityCenter := fs.Bool("skip-identity-center", false, "do not read the IAM Identity Center instance, permission sets and account assignments (its APIs answer only in the instance's region)")
	timeout := fs.Duration("timeout", 10*time.Minute, "overall timeout")
	// Optional data sources that can cost money. Off by default, and in this
	// version they only print the cost warning; see ROADMAP.md.
	cloudTrailLake := fs.Bool("with-cloudtrail-lake", false, "OPT-IN, COSTS MONEY: query CloudTrail Lake for actions in use (not implemented yet)")
	configQueries := fs.Bool("with-config-queries", false, "OPT-IN, COSTS MONEY: run Config aggregator advanced queries for resource inventories (not implemented yet)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: orgshift collect --out FILE [--profile NAME] [--name LABEL] [--ram-profiles a,b] [flags]")
		fs.PrintDefaults()
		fmt.Fprintln(os.Stderr, "\nOnly the read-only operations listed in docs/permissions.md are called. Nothing is ever written to AWS.")
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

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	logger := log.New(os.Stderr, "collect ", log.LstdFlags)

	load := func(p string) (aws.Config, error) {
		opts := []func(*config.LoadOptions) error{config.WithRegion(*region)}
		if p != "" {
			opts = append(opts, config.WithSharedConfigProfile(p))
		}
		return config.LoadDefaultConfig(ctx, opts...)
	}
	cfg, err := load(*profile)
	if err != nil {
		return fmt.Errorf("load AWS configuration: %w", err)
	}
	opts := collector.Options{Name: *name, Region: *region, Organizations: organizations.NewFromConfig(cfg), Logger: logger}
	if !*skipRAM {
		opts.RAM = append(opts.RAM, ram.NewFromConfig(cfg))
	}
	for _, p := range strings.Split(*ramProfiles, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		c, err := load(p)
		if err != nil {
			return fmt.Errorf("load AWS profile %s: %w", p, err)
		}
		opts.RAM = append(opts.RAM, ram.NewFromConfig(c))
	}
	if !*skipRegions {
		opts.Account = account.NewFromConfig(cfg)
	}
	if !*skipControlTower {
		opts.ControlTower = controltower.NewFromConfig(cfg)
		opts.ControlCatalog = controlcatalog.NewFromConfig(cfg)
	}
	if !*skipIdentityCenter {
		opts.SSOAdmin = ssoadmin.NewFromConfig(cfg)
		opts.IdentityStore = identitystore.NewFromConfig(cfg)
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
		fmt.Println("Control Tower: list control_tower.enrolled_accounts by hand if you want Account Factory provenance; otherwise accounts in registered OUs are assumed enrolled.")
	}
	if snap.IdentityCenter != nil {
		fmt.Println("Identity Center: assignments were listed for the accounts each permission set is provisioned in; principal names come from the identity store when identitystore:DescribeUser/DescribeGroup are allowed.")
	}
	return nil
}
