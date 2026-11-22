// evalrecall measures the scanner's file-level sink-hit recall against a
// deliberately dumb oracle: any .go file whose text contains a quoted catalog
// import path counts as oracle-positive. The oracle over-approximates
// (comments, strings), so disagreements are inspected, not auto-failed —
// but a file the oracle flags and the scanner misses is a candidate silent
// miss, which is the one defect class this product cannot tolerate.
//
// Usage: evalrecall <repo-dir> [<repo-dir>...]
package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ramnbt/truthsayer/internal/rules"
	"github.com/ramnbt/truthsayer/internal/scanner"
)

var skipDirs = map[string]bool{
	".git": true, "vendor": true, "node_modules": true, ".idea": true,
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: evalrecall <repo-dir> [...]")
		os.Exit(2)
	}
	exit := 0
	for _, root := range os.Args[1:] {
		if err := evalRepo(root); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", root, err)
			exit = 1
		}
	}
	os.Exit(exit)
}

func evalRepo(root string) error {
	needles := make([]string, 0)
	for _, s := range rules.Catalog() {
		needles = append(needles, `"`+s.ImportPath+`"`)
	}

	oracle := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDirs[d.Name()] || (strings.HasPrefix(d.Name(), ".") && d.Name() != ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		text := string(data)
		for _, n := range needles {
			if strings.Contains(text, n) {
				rel, _ := filepath.Rel(root, path)
				oracle[rel] = true
				break
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	inv, err := scanner.Scan(root)
	if err != nil {
		return err
	}
	scanned := map[string]bool{}
	for _, s := range inv.Sites {
		scanned[s.Site.File] = true
	}

	hit := 0
	var missed []string
	for f := range oracle {
		if scanned[f] {
			hit++
		} else {
			missed = append(missed, f)
		}
	}
	sort.Strings(missed)

	recall := 100.0
	if len(oracle) > 0 {
		recall = 100 * float64(hit) / float64(len(oracle))
	}
	fmt.Printf("%s: oracle-files=%d scanner-hit=%d recall=%.1f%% (sites=%d, skipped-parse=%d)\n",
		root, len(oracle), hit, recall, inv.Stats.TotalSites, inv.Stats.FilesSkipped)
	for _, m := range missed {
		fmt.Printf("  MISSED: %s\n", m)
	}
	return nil
}
