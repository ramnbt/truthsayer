// Package scanner implements the find stage v0: walk a repo, parse Go files
// with the stdlib AST, and match imports + qualified uses against the sink
// catalog. Precision work (go/ssa resolution) lands in M3; v0 optimizes for
// recall and honesty — anything matched but not understood stays UNRESOLVED.
package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ramnbt/truthsayer/internal/classify"
	"github.com/ramnbt/truthsayer/internal/ir"
	"github.com/ramnbt/truthsayer/internal/rules"
)

// Version is the tool version stamped into every inventory, evidence
// bundle, and PR body. Overridden at release time via
// -ldflags "-X github.com/ramnbt/truthsayer/internal/scanner.Version=vX.Y.Z".
var Version = "0.0.1-dev"

var skipDirs = map[string]bool{
	".git": true, "vendor": true, "node_modules": true, ".idea": true,
}

// Scan walks root and returns the inventory of crypto call sites.
func Scan(root string) (*ir.Inventory, error) {
	catalog := rules.ByImportPath()
	inv := &ir.Inventory{
		Tool:        "truthsayer",
		Version:     Version,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Root:        root,
		Stats: ir.Stats{
			ByFamily:  map[string]int{},
			ByVerdict: map[string]int{},
		},
	}

	fset := token.NewFileSet()
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
		if d.Name() == "go.mod" {
			scanGoMod(path, root, inv)
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		file, perr := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if perr != nil {
			// Unparseable file = potential silent miss; count AND list it, never drop it.
			inv.Stats.FilesSkipped++
			rel, _ := filepath.Rel(root, path)
			inv.SkippedFiles = append(inv.SkippedFiles, rel)
			return nil
		}
		inv.Stats.FilesScanned++
		scanFile(fset, file, path, root, catalog, inv)
		return nil
	})
	if err != nil {
		return nil, err
	}

	classify.Apply(inv)
	FinalizeStats(inv)
	return inv, nil
}

func scanFile(fset *token.FileSet, file *ast.File, path, root string, catalog map[string][]rules.Sink, inv *ir.Inventory) {
	// Map local import names -> import paths for matched packages.
	imported := map[string]string{} // local name -> import path
	for _, imp := range file.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		if _, ok := catalog[p]; !ok {
			continue
		}
		name := defaultPkgName(p)
		if imp.Name != nil {
			name = imp.Name.Name
		}
		if name == "_" || name == "." {
			// Blank/dot imports still count as usage we cannot attribute per-symbol.
			name = "\x00" + p
		}
		imported[name] = p
	}
	if len(imported) == 0 {
		return
	}

	rel, _ := filepath.Rel(root, path)
	inTest := strings.HasSuffix(path, "_test.go")
	generated := isGenerated(file)

	// Track which (importPath, symbol) pairs we emitted per enclosing function,
	// so a loop of calls is one finding per site, not thousands.
	type key struct{ pth, sym, fn string }
	seen := map[key]bool{}

	// Pre-pass: collect rendered arguments for calls whose Fun is a selector,
	// keyed by the selector's position, so the selector walk can attach them.
	callArgs := map[token.Pos][]string{}
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		callArgs[sel.Pos()] = renderArgs(fset, call.Args)
		return true
	})

	// Pre-pass: field-level facts for tls.Config composite literals (I59/I60),
	// keyed by enclosing function — the main walk dedups per function, and the
	// first tls.Config mention in a function (often a *tls.Config return type)
	// may precede the literal.
	tlsFacts := map[string]*ir.TLSConf{}
	{
		var fn string
		ast.Inspect(file, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.FuncDecl:
				fn = x.Name.Name
			case *ast.CompositeLit:
				sel, ok := x.Type.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "Config" {
					return true
				}
				id, ok := sel.X.(*ast.Ident)
				if !ok || imported[id.Name] != "crypto/tls" {
					return true
				}
				if _, dup := tlsFacts[fn]; dup {
					return true // keep first literal's facts per function
				}
				tlsFacts[fn] = tlsConfFacts(x)
			}
			return true
		})
	}

	// Walk with enclosing-function context.
	var currentFn string
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncDecl:
			currentFn = node.Name.Name
		case *ast.SelectorExpr:
			id, ok := node.X.(*ast.Ident)
			if !ok {
				return true
			}
			impPath, ok := imported[id.Name]
			if !ok {
				return true
			}
			sym := node.Sel.Name
			k := key{impPath, sym, currentFn}
			if seen[k] {
				return true
			}
			seen[k] = true
			var tc *ir.TLSConf
			if impPath == "crypto/tls" && sym == "Config" {
				tc = tlsFacts[currentFn]
			}
			emit(inv, catalog, impPath, sym, callArgs[node.Pos()], tc, ir.Site{
				File: rel, Line: fset.Position(node.Pos()).Line,
				Package: file.Name.Name, Function: currentFn,
				InTest: inTest, Generated: generated,
			})
		}
		return true
	})

	// Blank/dot imports of catalog packages: emit a package-level finding.
	for name, p := range imported {
		if strings.HasPrefix(name, "\x00") {
			emit(inv, catalog, p, "", nil, nil, ir.Site{
				File: rel, Line: 1, Package: file.Name.Name,
				InTest: inTest, Generated: generated,
			})
		}
	}
}

// hybridGroups are the ML-KEM hybrid KEX groups in Go's crypto/tls
// (X25519MLKEM768 since 1.24; SecP256r1/SecP384r1 variants since 1.26).
var hybridGroups = map[string]bool{
	"X25519MLKEM768":     true,
	"SecP256r1MLKEM768":  true,
	"SecP384r1MLKEM1024": true,
}

// tlsConfFacts extracts field-level facts from a tls.Config composite literal.
func tlsConfFacts(cl *ast.CompositeLit) *ir.TLSConf {
	tc := &ir.TLSConf{}
	for _, el := range cl.Elts {
		kv, ok := el.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok {
			continue
		}
		switch key.Name {
		case "CurvePreferences":
			tc.HasCurvePrefs = true
			if lit, ok := kv.Value.(*ast.CompositeLit); ok {
				tc.PrefsLiteral = true
				for _, e := range lit.Elts {
					if s, ok := e.(*ast.SelectorExpr); ok && hybridGroups[s.Sel.Name] {
						tc.PrefsHybrid = true
					}
				}
			}
		case "MinVersion":
			tc.MinVersion = "nonliteral"
			if s, ok := kv.Value.(*ast.SelectorExpr); ok {
				switch s.Sel.Name {
				case "VersionTLS13":
					tc.MinVersion = "TLS13"
				case "VersionTLS12":
					tc.MinVersion = "TLS12"
				case "VersionTLS11":
					tc.MinVersion = "TLS11"
				case "VersionTLS10":
					tc.MinVersion = "TLS10"
				}
			}
		case "CipherSuites":
			tc.HasCipherSuites = true
		}
	}
	return tc
}

// generatedRe is the conventional marker per https://go.dev/s/generatedcode.
var generatedRe = regexp.MustCompile(`^// Code generated .* DO NOT EDIT\.$`)

func isGenerated(file *ast.File) bool {
	for _, cg := range file.Comments {
		if cg.Pos() > file.Package {
			break
		}
		for _, c := range cg.List {
			if generatedRe.MatchString(c.Text) {
				return true
			}
		}
	}
	return false
}

// renderArgs renders up to 4 call arguments, truncated, for the classifier
// (e.g. rsa.GenerateKey(rand.Reader, 2048) -> ["rand.Reader", "2048"]).
func renderArgs(fset *token.FileSet, args []ast.Expr) []string {
	const maxArgs, maxLen = 4, 48
	var out []string
	for i, a := range args {
		if i == maxArgs {
			out = append(out, "…")
			break
		}
		var buf strings.Builder
		if err := printer.Fprint(&buf, fset, a); err != nil {
			out = append(out, "?")
			continue
		}
		s := buf.String()
		if len(s) > maxLen {
			s = s[:maxLen] + "…"
		}
		out = append(out, s)
	}
	return out
}

// emit matches a use against the catalog and appends a CallSite.
func emit(inv *ir.Inventory, catalog map[string][]rules.Sink, impPath, sym string, args []string, tc *ir.TLSConf, site ir.Site) {
	sinks := catalog[impPath]
	var chosen *rules.Sink
	for i := range sinks {
		if sinks[i].Symbol != "" && sinks[i].Symbol == sym {
			chosen = &sinks[i]
			break
		}
	}
	if chosen == nil {
		for i := range sinks {
			if sinks[i].Symbol == "" {
				chosen = &sinks[i]
				break
			}
		}
	}
	if chosen == nil {
		return
	}

	prim := chosen.Primitive
	prim.Symbol = impPath + "." + sym
	if sym == "" {
		prim.Symbol = impPath + " (package use)"
	}

	cs := ir.CallSite{
		ID:         siteID(site, prim.Symbol),
		Site:       site,
		Primitive:  prim,
		Args:       args,
		TLSConf:    tc,
		Resolution: ir.ResolutionLiteral, // import+symbol match is literal; dataflow cases come in M3
		KeyProv:    ir.KeyUnknown,
		Verdict:    chosen.VerdictHint,
		VerdictWhy: chosen.VerdictWhy,
	}
	if sym == "" {
		cs.Resolution = ir.ResolutionUnresolved
		cs.VerdictWhy = "package imported but symbol-level attribution unavailable; " + cs.VerdictWhy
	}
	inv.Sites = append(inv.Sites, cs)
}

// FinalizeStats (re)computes inventory stats from sites. Idempotent, so
// enrichment passes (resolver) can mutate sites and call it again.
func FinalizeStats(inv *ir.Inventory) {
	sort.Slice(inv.Sites, func(i, j int) bool {
		a, b := inv.Sites[i].Site, inv.Sites[j].Site
		if a.File != b.File {
			return a.File < b.File
		}
		return a.Line < b.Line
	})
	s := &inv.Stats
	s.TotalSites = len(inv.Sites)
	s.ByFamily = map[string]int{}
	s.ByVerdict = map[string]int{}
	s.ByPriority = map[string]int{}
	s.ProdSites, s.TestSites, s.GeneratedSites = 0, 0, 0
	s.QuantumVuln, s.MisuseSites, s.UnresolvedSites = 0, 0, 0
	clusters := map[string]bool{}
	for _, c := range inv.Sites {
		s.ByFamily[string(c.Primitive.Family)]++
		s.ByVerdict[string(c.Verdict)]++
		s.ByPriority[c.Priority]++
		if c.Site.InTest {
			s.TestSites++
		} else {
			s.ProdSites++
		}
		if c.Site.Generated {
			s.GeneratedSites++
		}
		if c.Primitive.QuantumVulnerable {
			s.QuantumVuln++
		}
		if c.Primitive.Misuse {
			s.MisuseSites++
		}
		if c.Resolution == ir.ResolutionUnresolved {
			s.UnresolvedSites++
		}
		if c.Cluster != "" {
			clusters[c.Cluster] = true
		}
	}
	s.KeyClusters = len(clusters)
}

func siteID(site ir.Site, symbol string) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s:%d:%s", site.File, site.Line, symbol)))
	return hex.EncodeToString(h[:8])
}

// scanGoMod flags dependencies with crypto relevance. v0 parses require
// lines directly (single-line and block form) to stay dependency-free.
func scanGoMod(path, root string, inv *ir.Inventory) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	rel, _ := filepath.Rel(root, path)
	known := rules.CryptoModules()

	inBlock := false
	for _, line := range strings.Split(string(data), "\n") {
		l := strings.TrimSpace(line)
		if f := strings.Fields(l); len(f) == 2 && f[0] == "go" && !inBlock {
			inv.GoMods = append(inv.GoMods, ir.GoMod{Dir: filepath.ToSlash(filepath.Dir(rel)), Version: f[1]})
			continue
		}
		switch {
		case l == "require (":
			inBlock = true
			continue
		case inBlock && l == ")":
			inBlock = false
			continue
		}
		var spec string
		if inBlock {
			spec = l
		} else if strings.HasPrefix(l, "require ") {
			spec = strings.TrimPrefix(l, "require ")
		} else {
			continue
		}
		fields := strings.Fields(spec)
		if len(fields) < 2 {
			continue
		}
		mod, ver := fields[0], fields[1]
		note, ok := known[mod]
		if !ok {
			// prefix match for module major-version suffixes (…/v4, …/v2)
			for k, v := range known {
				if strings.HasPrefix(mod, k+"/") {
					note, ok = v, true
					break
				}
			}
		}
		if !ok {
			continue
		}
		inv.Deps = append(inv.Deps, ir.DepFinding{
			Module: mod, Version: ver, Manifest: rel,
			Note: note.Note, PQC: note.PQC,
			Indirect: strings.Contains(spec, "// indirect"),
		})
	}
}

// defaultPkgName derives the package identifier from an import path.
func defaultPkgName(importPath string) string {
	base := importPath
	if i := strings.LastIndex(importPath, "/"); i >= 0 {
		base = importPath[i+1:]
	}
	return base
}
