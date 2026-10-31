package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/MrShaaba/orgshift/internal/fixtures"
	"github.com/MrShaaba/orgshift/internal/snapshot"
)

// FixtureFiles maps the fixture organization names to their file names.
var fixtureFiles = map[string]string{
	fixtures.LarkspurName: "larkspur-holdings.json",
	fixtures.FernhillName: "fernhill-group.json",
}

func runFixtures(args []string) error {
	fs := flag.NewFlagSet("fixtures", flag.ContinueOnError)
	out := fs.String("out", "fixtures", "directory to write the fixture snapshots into")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		return err
	}
	for name, s := range fixtures.All() {
		path := filepath.Join(*out, fixtureFiles[name])
		if err := snapshot.Save(path, s); err != nil {
			return err
		}
		fmt.Printf("wrote %s (%s, %d accounts, %d policies)\n", path, name, len(s.Accounts), len(s.Policies))
	}
	fmt.Printf("\nTry:\n  orgshift simulate --from %s --to %s --account %s --target-ou %s\n",
		filepath.Join(*out, fixtureFiles[fixtures.LarkspurName]), filepath.Join(*out, fixtureFiles[fixtures.FernhillName]),
		fixtures.LarkspurPaymentsProd, fixtures.FernhillPaymentsOU)
	return nil
}
