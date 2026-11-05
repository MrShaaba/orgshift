package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/MrShaaba/orgshift/internal/config"
)

func runConfig(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: orgshift config example | orgshift config check --config FILE [--format json]")
	}
	switch args[0] {
	case "example":
		os.Stdout.WriteString(config.Example)
		return nil
	case "check":
		fs := flag.NewFlagSet("config check", flag.ContinueOnError)
		cfgPath := fs.String("config", "", "configuration file to validate (required)")
		format := fs.String("format", "summary", "summary or json (the configuration with defaults applied)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *cfgPath == "" {
			return errors.New("--config is required")
		}
		cfg, err := config.Load(*cfgPath)
		if err != nil {
			return err
		}
		if *format == "json" {
			data, err := cfg.JSON()
			if err != nil {
				return err
			}
			os.Stdout.Write(append(data, '\n'))
			return nil
		}
		fmt.Printf("%s is valid (schema_version %d)\n", *cfgPath, cfg.SchemaVersion)
		for _, s := range cfg.Sides() {
			side := s.Side
			fmt.Printf("%s: %s\n", s.Name, side.Name)
			fmt.Printf("  management: account %s, region %s, via %s\n", side.Management.AccountID, side.Management.Region, side.Management.Describe())
			ct := "disabled"
			if side.ControlTowerEnabled() {
				ct = "home region " + side.ControlTowerRegion()
			}
			ic := "disabled"
			if side.IdentityCenterEnabled() {
				ic = "region " + side.IdentityCenterRegion() + ", via " + side.IdentityCenterAccess().Describe()
			}
			fmt.Printf("  control tower: %s\n  identity center: %s\n", ct, ic)
			for _, n := range side.Network {
				fmt.Printf("  network: %s, account %s, via %s\n", n.Label, n.AccountID, n.Describe())
			}
			for _, sec := range side.Security {
				fmt.Printf("  security: %s, account %s, via %s\n", sec.Label, sec.AccountID, sec.Describe())
			}
			if m := side.MemberInspection; m != nil {
				fmt.Printf("  member inspection: role %s, %d configured account(s), sample %d\n", m.RoleName, len(m.Accounts), m.MemberSample())
				switch {
				case side.Skipped("workloads"):
					fmt.Println("  workload inventory: skipped")
				case len(m.Accounts) == 0:
					fmt.Println("  workload inventory: no account named under member_inspection.accounts, so none is inspected")
				default:
					regions := side.WorkloadRegions
					if len(regions) == 0 {
						regions = []string{side.Management.Region}
					}
					source := "auto"
					if w := side.Workloads; w != nil && w.ResourceSource != "" {
						source = w.ResourceSource
					}
					fmt.Printf("  workload inventory: accounts %s in %s, resource sample from %s\n", strings.Join(m.Accounts, ", "), strings.Join(regions, ", "), source)
				}
			}
			if len(side.Skip) > 0 {
				fmt.Printf("  skipped domains: %v\n", side.Skip)
			}
		}
		fmt.Printf("collection: concurrency %d, retry attempts %d, timeout %s, checkpoint %t\n", cfg.Collection.Concurrency, cfg.Collection.RetryAttempts, cfg.Collection.Timeout, cfg.Collection.Checkpointing())
		if cfg.Billable.BucketPolicies {
			fmt.Println("billable: bucket policies are read (S3 bills one LIST request per inspected account and one request per bucket in the workload regions)")
		} else {
			fmt.Println("billable: nothing billed is read; bucket policies stay unread and the workload layer reads partially evaluated (billable.bucket_policies or --with-bucket-policies)")
		}
		if cfg.Billable.CloudTrailLake || cfg.Billable.ConfigQueries {
			fmt.Println("billable: an opt-in is on; these data sources are not implemented in this version and collect refuses to run with them")
		}
		return nil
	default:
		return fmt.Errorf("unknown config subcommand %q (example or check)", args[0])
	}
}
