// truthsayer — find and classify quantum-vulnerable cryptography in Go codebases.
//
// Usage:
//
//	truthsayer scan <path> [--resolve] [--json out.json] [--cbom cbom.json] [--sarif out.sarif]
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/ramnbt/truthsayer/internal/cbom"
	"github.com/ramnbt/truthsayer/internal/classify"
	"github.com/ramnbt/truthsayer/internal/report"
	"github.com/ramnbt/truthsayer/internal/resolver"
	"github.com/ramnbt/truthsayer/internal/sarif"
	"github.com/ramnbt/truthsayer/internal/scanner"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "scan":
		runScan(os.Args[2:])
	case "version":
		fmt.Println("truthsayer v" + scanner.Version)
	default:
		usage()
		os.Exit(2)
	}
}

func runScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	jsonOut := fs.String("json", "", "write full inventory JSON (rewrite-plan IR) to this path")
	cbomOut := fs.String("cbom", "", "write CycloneDX 1.6 CBOM to this path")
	sarifOut := fs.String("sarif", "", "write SARIF 2.1.0 to this path (GitHub code scanning)")
	resolve := fs.Bool("resolve", false, "run the go/ssa resolver: upgrade findings to dataflow facts (needs a compilable module)")
	fs.Parse(args)

	root := "."
	if fs.NArg() > 0 {
		root = fs.Arg(0)
	}
	// flag.Parse stops at the first positional arg; anything after it would be
	// silently ignored — refuse instead (hard rule: never silently drop intent).
	if fs.NArg() > 1 {
		fmt.Fprintf(os.Stderr, "unexpected arguments after path: %v\nflags must come before the path: truthsayer scan --cbom out.json <path>\n", fs.Args()[1:])
		os.Exit(2)
	}

	inv, err := scanner.Scan(root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "scan failed:", err)
		os.Exit(1)
	}

	if *resolve {
		for _, note := range resolver.Enrich(root, inv) {
			fmt.Fprintln(os.Stderr, note)
		}
		// Re-classify: priorities must follow resolver facts (egress-proven
		// lifetimes can escalate to P0-HNDL).
		classify.Apply(inv)
		scanner.FinalizeStats(inv)
	}

	report.WriteTable(inv, os.Stdout)

	if *jsonOut != "" {
		if err := report.WriteJSON(inv, *jsonOut); err != nil {
			fatal("writing json", err)
		}
		fmt.Printf("\ninventory written to %s\n", *jsonOut)
	}
	if *cbomOut != "" {
		b, err := cbom.Export(inv)
		if err != nil {
			fatal("cbom export", err)
		}
		if err := os.WriteFile(*cbomOut, append(b, '\n'), 0o644); err != nil {
			fatal("writing cbom", err)
		}
		fmt.Printf("CBOM written to %s\n", *cbomOut)
	}
	if *sarifOut != "" {
		b, err := sarif.Export(inv)
		if err != nil {
			fatal("sarif export", err)
		}
		if err := os.WriteFile(*sarifOut, append(b, '\n'), 0o644); err != nil {
			fatal("writing sarif", err)
		}
		fmt.Printf("SARIF written to %s\n", *sarifOut)
	}
}

func fatal(what string, err error) {
	fmt.Fprintf(os.Stderr, "%s: %v\n", what, err)
	os.Exit(1)
}

func usage() {
	fmt.Fprintln(os.Stderr, `truthsayer — find and classify quantum-vulnerable crypto in Go codebases

usage:
  truthsayer scan <path> [--resolve] [--json out.json] [--cbom cbom.json] [--sarif out.sarif]
  truthsayer version

The verified-rewrite layer (gated migration PRs with machine-checked evidence
bundles, CI posture gate, signed attestations) is a separate commercial
product: see the README.`)
}
