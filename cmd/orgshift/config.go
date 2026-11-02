package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

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
			}
			if len(side.Skip) > 0 {
				fmt.Printf("  skipped domains: %v\n", side.Skip)
			}
		}
		fmt.Printf("collection: concurrency %d, retry attempts %d, timeout %s, checkpoint %t\n", cfg.Collection.Concurrency, cfg.Collection.RetryAttempts, cfg.Collection.Timeout, cfg.Collection.Checkpointing())
		if cfg.Billable.CloudTrailLake || cfg.Billable.ConfigQueries {
			fmt.Println("billable: an opt-in is on; these data sources are not implemented in this version and collect refuses to run with them")
		}
		return nil
	default:
		return fmt.Errorf("unknown config subcommand %q (example or check)", args[0])
	}
}
