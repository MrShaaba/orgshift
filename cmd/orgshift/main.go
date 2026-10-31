// Command orgshift simulates moving an AWS account between organizational
// units or organizations and gives a GO / REVIEW / NO-GO verdict.
package main

import (
	"fmt"
	"os"
)

var version = "dev"

func usage() {
	fmt.Fprintf(os.Stderr, `orgshift %s - go/no-go simulator for moving AWS accounts and OUs

Usage:
  orgshift fixtures --out DIR               write the fictional fixture organizations
  orgshift simulate --from A.json [--to B.json] --account ID --target-ou OU [flags]
  orgshift serve [--from A.json --to B.json] [--listen :8080]
  orgshift collect --profile NAME --out FILE [flags]
  orgshift version

Run "orgshift <command> -h" for the flags of each command.
`, version)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "version":
		fmt.Println("orgshift", version)
	case "fixtures":
		err = runFixtures(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		usage()
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "orgshift:", err)
		os.Exit(1)
	}
}
