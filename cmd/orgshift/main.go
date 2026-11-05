// Command orgshift simulates moving an AWS account between organizational
// units or organizations and gives a GO / REVIEW / NO-GO verdict.
package main

import (
	"errors"
	"fmt"
	"os"
)

var version = "dev"

func printUsage() {
	fmt.Fprintf(os.Stderr, `orgshift %s - go/no-go simulator for moving AWS accounts and OUs

Usage:
  orgshift fixtures --out DIR               write the fictional fixture organizations
  orgshift simulate --from A.json [--to B.json] --account ID --target-ou OU [flags]
  orgshift simulate --from A.json [--to B.json] --ou OU --target-ou PARENT [flags]
  orgshift stages --scenario plan.yaml [--from A.json --to B.json] [--format text|json|markdown]
  orgshift scenario example | scenario check --scenario plan.yaml
  orgshift workloads --snapshot A.json [--account ID] [--format text|json|markdown]
  orgshift serve [--from A.json --to B.json] [--fixtures] [--listen 127.0.0.1:8080]
  orgshift config example | config check --config orgshift.yaml
  orgshift iam-templates [--config orgshift.yaml] [--out docs/iam]
  orgshift preflight --config orgshift.yaml [--side both] [--format text|json|markdown]
  orgshift collect --config orgshift.yaml [--side source] --out FILE [flags]
  orgshift version

Run "orgshift <command> -h" for the flags of each command.
`, version)
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "version":
		fmt.Println("orgshift", version)
	case "fixtures":
		err = runFixtures(os.Args[2:])
	case "simulate":
		err = runSimulate(os.Args[2:])
	case "stages":
		err = runStages(os.Args[2:])
	case "scenario":
		err = runScenario(os.Args[2:])
	case "workloads":
		err = runWorkloads(os.Args[2:])
	case "serve":
		err = runServe(os.Args[2:])
	case "collect":
		err = runCollect(os.Args[2:])
	case "preflight":
		err = runPreflight(os.Args[2:])
	case "iam-templates":
		err = runIAMTemplates(os.Args[2:])
	case "config":
		err = runConfig(os.Args[2:])
	case "-h", "--help", "help":
		printUsage()
	default:
		printUsage()
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		var v errVerdict
		if errors.As(err, &v) {
			os.Exit(v.code)
		}
		fmt.Fprintln(os.Stderr, "orgshift:", err)
		os.Exit(1)
	}
}
