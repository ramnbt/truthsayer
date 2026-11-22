// Package report renders an inventory for humans (console table) and
// machines (JSON).
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"text/tabwriter"

	"github.com/ramnbt/truthsayer/internal/ir"
)

// WriteJSON writes the full inventory to path.
func WriteJSON(inv *ir.Inventory, path string) error {
	b, err := json.MarshalIndent(inv, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

// WriteTable renders the human triage view.
func WriteTable(inv *ir.Inventory, w io.Writer) {
	s := inv.Stats
	fmt.Fprintf(w, "\ntruthsayer v%s — %s\n", inv.Version, inv.Root)
	fmt.Fprintf(w, "files scanned: %d (skipped: %d) · sites: %d (prod %d / test %d / gen %d) · quantum-vulnerable: %d · misuse: %d · UNRESOLVED: %d\n\n",
		s.FilesScanned, s.FilesSkipped, s.TotalSites, s.ProdSites, s.TestSites, s.GeneratedSites, s.QuantumVuln, s.MisuseSites, s.UnresolvedSites)

	if len(inv.Sites) == 0 {
		fmt.Fprintln(w, "no crypto sinks found")
		return
	}

	tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "LOCATION\tALGORITHM\tFAMILY\tPRIO\tVERDICT\tMIGRATION TARGET")
	for _, c := range inv.Sites {
		loc := fmt.Sprintf("%s:%d", c.Site.File, c.Site.Line)
		if c.Site.InTest {
			loc += " (test)"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			loc, c.Primitive.Algorithm, c.Primitive.Family, c.Priority, c.Verdict, c.Primitive.MigrationTarget)
	}
	tw.Flush()

	if len(inv.Deps) > 0 {
		fmt.Fprintln(w, "\ncrypto-relevant dependencies:")
		dw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
		for _, d := range inv.Deps {
			tag := ""
			if d.PQC {
				tag = " [PQC]"
			}
			fmt.Fprintf(dw, "  %s %s%s\t%s\n", d.Module, d.Version, tag, d.Note)
		}
		dw.Flush()
	}
	if len(inv.SkippedFiles) > 0 {
		fmt.Fprintf(w, "\nWARNING — %d file(s) could not be parsed (possible silent misses):\n", len(inv.SkippedFiles))
		for _, f := range inv.SkippedFiles {
			fmt.Fprintf(w, "  %s\n", f)
		}
	}

	fmt.Fprintln(w)
	keys := make([]string, 0, len(s.ByVerdict))
	for k := range s.ByVerdict {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Fprint(w, "verdicts: ")
	for i, k := range keys {
		if i > 0 {
			fmt.Fprint(w, " · ")
		}
		fmt.Fprintf(w, "%s=%d", k, s.ByVerdict[k])
	}
	fmt.Fprintln(w)
}
