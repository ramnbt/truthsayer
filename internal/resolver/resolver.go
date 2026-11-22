// Package resolver is the M3 precision stage: it loads the target module
// with go/packages, builds SSA, and upgrades scanner findings from
// parse-level guesses to dataflow facts — per-site Resolution
// (LITERAL/DERIVED/CONFIG/UNRESOLVED), concrete key sizes and curves, and
// key provenance.
//
// The resolver is an enrichment pass, never a gate on the scan: a target
// that does not compile keeps its parse-level inventory, with the load
// failure surfaced as a note (hard rule #1: degrade loudly, not silently).
package resolver

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"path/filepath"
	"strings"

	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/callgraph/vta"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"

	"github.com/ramnbt/truthsayer/internal/ir"
)

// argKind says what an algorithm-bearing argument means.
type argKind int

const (
	argKeySize argKind = iota // integer key size (bits)
	argCurve                  // elliptic.Curve choice
	argKey                    // key material — resolve provenance
)

// argSpec marks one argument of a catalog sink as algorithm-bearing.
type argSpec struct {
	idx  int
	kind argKind
}

// argSpecs keys on the scanner's Primitive.Symbol ("importpath.Name").
var argSpecs = map[string]argSpec{
	"crypto/rsa.GenerateKey":             {1, argKeySize},
	"crypto/rsa.GenerateMultiPrimeKey":   {2, argKeySize},
	"crypto/ecdsa.GenerateKey":           {0, argCurve},
	"crypto/rsa.SignPKCS1v15":            {1, argKey},
	"crypto/rsa.SignPSS":                 {1, argKey},
	"crypto/rsa.DecryptPKCS1v15":         {1, argKey},
	"crypto/rsa.DecryptOAEP":             {2, argKey},
	"crypto/rsa.EncryptPKCS1v15":         {1, argKey},
	"crypto/rsa.EncryptOAEP":             {2, argKey},
	"crypto/ecdsa.SignASN1":              {1, argKey},
	"crypto/ed25519.Sign":                {0, argKey},
	"crypto/x509.MarshalPKCS1PrivateKey": {0, argKey},
	"crypto/x509.MarshalECPrivateKey":    {0, argKey},
	"crypto/x509.MarshalPKCS8PrivateKey": {0, argKey},
}

// Enrich resolves inv's sites in place and returns human-readable notes
// (load errors, resolution counts). It never fails the scan.
func Enrich(root string, inv *ir.Inventory) []string {
	r, notes := loadTarget(root)
	if r == nil {
		return notes
	}

	resolved, attempted, egressed := 0, 0, 0
	for i := range inv.Sites {
		site := &inv.Sites[i]
		if spec, ok := argSpecs[site.Primitive.Symbol]; ok {
			attempted++
			if r.resolveArgSite(site, spec) {
				resolved++
			}
		}
		if site.Primitive.Symbol == "crypto/tls.Config" {
			attempted++
			if r.resolveCurvePreferences(site) {
				resolved++
			}
		}
		if kind, ok := resultSpecs[site.Primitive.Symbol]; ok {
			if r.resolveEgress(site, kind) {
				egressed++
			}
		}
	}
	notes = append(notes, fmt.Sprintf("resolver: egress boundary proven for %d site(s)", egressed))
	if n := r.clusterKeys(inv); n > 0 {
		notes = append(notes, fmt.Sprintf("resolver: %d key lifecycle cluster(s)", n))
	}
	notes = append(notes, fmt.Sprintf("resolver: %d/%d algorithm-bearing sites resolved", resolved, attempted))
	return notes
}

// loadTarget loads the module, builds SSA + VTA, and returns the analysis
// state (nil when the target cannot be loaded; notes say why).
func loadTarget(root string) (*resolution, []string) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, []string{"resolver skipped: " + err.Error()}
	}
	// go/packages reports symlink-resolved filenames (macOS /tmp →
	// /private/tmp); resolve the root the same way or every position
	// lookup silently misses.
	if resolved, rerr := filepath.EvalSymlinks(absRoot); rerr == nil {
		absRoot = resolved
	}
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
			packages.NeedImports | packages.NeedDeps | packages.NeedTypes |
			packages.NeedSyntax | packages.NeedTypesInfo | packages.NeedModule,
		Dir: absRoot,
		// Tests included: the scanner flags test sites separately, but a
		// test-only crypto use still deserves dataflow facts.
		Tests: true,
	}
	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		return nil, []string{"resolver skipped (module does not load): " + err.Error()}
	}
	var notes []string
	broken := 0
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		if len(p.Errors) > 0 && p.Module != nil {
			broken++
			notes = append(notes, fmt.Sprintf("resolver: package %s has errors: %v", p.PkgPath, p.Errors[0]))
		}
	})
	if len(pkgs) == 0 {
		return nil, append(notes, "resolver skipped: no packages loaded (no go.mod?)")
	}
	notes = append(notes, fmt.Sprintf("resolver: %d module packages loaded, %d with errors", countPkgs(pkgs), broken))

	prog, _ := ssautil.AllPackages(pkgs, ssa.InstantiateGenerics)
	prog.Build()

	// Module-local function set: VTA runs over these (precision where it
	// matters, bounded cost), and value tracing follows calls into them.
	modulePkgs := map[*types.Package]bool{}
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		if p.Module != nil && p.Types != nil {
			modulePkgs[p.Types] = true
		}
	})
	moduleFns := map[*ssa.Function]bool{}
	for fn := range ssautil.AllFunctions(prog) {
		if fn.Pkg != nil && modulePkgs[fn.Pkg.Pkg] {
			moduleFns[fn] = true
		}
	}
	cg := vta.CallGraph(moduleFns, cha.CallGraph(prog))

	return &resolution{
		root:  absRoot,
		fset:  prog.Fset,
		calls: indexSSACalls(prog),
		ast:   indexAST(pkgs),
		trc:   &tracer{cg: cg, inModule: moduleFns},
	}, notes
}

func countPkgs(pkgs []*packages.Package) int {
	n := 0
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		if p.Module != nil {
			n++
		}
	})
	return n
}

// resolution carries the per-target indexes.
type resolution struct {
	root  string
	fset  *token.FileSet
	calls map[callKey][]ssa.CallInstruction
	ast   *astIndex
	trc   *tracer
}

type callKey struct {
	file   string // absolute, cleaned
	line   int
	callee string // "importpath.Name"
}

// resolveArgSite upgrades one call site using AST constants first (cheap,
// distinguishes literal vs named const), then SSA value tracing.
// Returns true when it produced a definite fact (incl. a definite CONFIG).
func (r *resolution) resolveArgSite(site *ir.CallSite, spec argSpec) bool {
	abs := filepath.Join(r.root, site.Site.File)

	// AST pass: constant known to go/types?
	if call, info := r.ast.callAt(abs, site.Site.Line, site.Primitive.Symbol); call != nil && spec.idx < len(call.Args) {
		arg := call.Args[spec.idx]
		switch spec.kind {
		case argKeySize:
			if tv, ok := info.Types[arg]; ok && tv.Value != nil {
				bits := tv.Value.ExactString()
				if _, isLit := arg.(*ast.BasicLit); isLit {
					site.Resolution = ir.ResolutionLiteral
					site.Evidence = append(site.Evidence, "keysize="+bits+" (literal at call site)")
				} else {
					site.Resolution = ir.ResolutionDerived
					site.Evidence = append(site.Evidence, "keysize="+bits+" (constant, resolved via go/types)")
				}
				applyKeySize(site, bits)
				return true
			}
		case argCurve:
			if name := curveName(arg, info); name != "" {
				site.Resolution = ir.ResolutionLiteral
				site.Primitive.Algorithm = "ECDSA-" + name
				site.Evidence = append(site.Evidence, "curve="+name+" (literal at call site)")
				return true
			}
		}
	}

	// SSA pass: trace the argument value.
	for _, ci := range r.calls[callKey{abs, site.Site.Line, site.Primitive.Symbol}] {
		args := ci.Common().Args
		if spec.idx >= len(args) {
			continue
		}
		f := r.trc.value(args[spec.idx], 0)
		switch spec.kind {
		case argKeySize:
			switch f.kind {
			case factConst:
				site.Resolution = ir.ResolutionDerived
				site.Evidence = append(site.Evidence, "keysize="+f.detail+" (resolved via SSA)")
				applyKeySize(site, f.detail)
				return true
			case factConfig:
				site.Resolution = ir.ResolutionConfig
				site.Evidence = append(site.Evidence, "keysize from "+f.detail+" — value not provable at rest")
				return true
			default:
				site.Resolution = ir.ResolutionUnresolved
				site.Evidence = append(site.Evidence, "keysize not resolved: "+f.detail)
				return false
			}
		case argCurve:
			switch f.kind {
			case factCurve:
				site.Resolution = ir.ResolutionDerived
				site.Primitive.Algorithm = "ECDSA-" + f.detail
				site.Evidence = append(site.Evidence, "curve="+f.detail+" (resolved via SSA)")
				return true
			case factConfig:
				site.Resolution = ir.ResolutionConfig
				site.Evidence = append(site.Evidence, "curve from "+f.detail)
				return true
			default:
				site.Resolution = ir.ResolutionUnresolved
				site.Evidence = append(site.Evidence, "curve not resolved: "+f.detail)
				return false
			}
		case argKey:
			switch f.kind {
			case factKeyGenerated:
				site.KeyProv = ir.KeyGenerated
			case factKeyLoaded:
				site.KeyProv = ir.KeyLoaded
			case factKeyExternal:
				site.KeyProv = ir.KeyExternal
			case factConst:
				site.KeyProv = ir.KeyHardcoded
			case factConfig:
				// For key MATERIAL a config source is still provenance:
				// bytes from a file are a loaded key; env/flag-provided
				// key material is external.
				if strings.Contains(f.detail, "file read") {
					site.KeyProv = ir.KeyLoaded
				} else {
					site.KeyProv = ir.KeyExternal
				}
			default:
				site.Evidence = append(site.Evidence, "key provenance unknown: "+f.detail)
				return false
			}
			site.Evidence = append(site.Evidence, "key provenance: "+f.detail)
			return true
		}
	}
	// Site known to carry an algorithm-bearing arg but no SSA call matched
	// (build-excluded file, or SSA withheld because a dependency failed to
	// type-check) — honesty over optimism, never silent (hard rule #1).
	if spec.kind != argKey {
		site.Resolution = ir.ResolutionUnresolved
	}
	site.Evidence = append(site.Evidence, "call not found in SSA (build-excluded file or ill-typed dependency)")
	return false
}

// applyKeySize rewrites the algorithm with the proven size (e.g. RSA-1024).
func applyKeySize(site *ir.CallSite, bits string) {
	base, _, _ := strings.Cut(site.Primitive.Algorithm, "-")
	site.Primitive.Algorithm = base + "-" + bits
}

// curveName recognizes elliptic.P224/P256/P384/P521() call expressions.
func curveName(arg ast.Expr, info *types.Info) string {
	call, ok := arg.(*ast.CallExpr)
	if !ok {
		return ""
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	if fn, ok := info.Uses[sel.Sel].(*types.Func); ok &&
		fn.Pkg() != nil && fn.Pkg().Path() == "crypto/elliptic" {
		switch fn.Name() {
		case "P224", "P256", "P384", "P521":
			return fn.Name()
		}
	}
	return ""
}

// resolveCurvePreferences resolves tls.Config composite literals: are the
// curve preferences explicit, and do they include the hybrid group?
func (r *resolution) resolveCurvePreferences(site *ir.CallSite) bool {
	abs := filepath.Join(r.root, site.Site.File)
	lits, info, ambiguous := r.ast.tlsConfigLitsInFunc(abs, site.Site.Function)
	if ambiguous {
		site.Resolution = ir.ResolutionUnresolved
		site.Evidence = append(site.Evidence, "multiple functions named "+site.Site.Function+" in file — cannot attribute tls.Config literal safely")
		return false
	}
	if len(lits) == 0 {
		site.Evidence = append(site.Evidence, "tls.Config referenced but not constructed here (type reference only)")
		return false
	}
	if len(lits) > 1 {
		site.Evidence = append(site.Evidence, fmt.Sprintf("%d tls.Config literals in function; resolving the first (per-literal sites: M3)", len(lits)))
	}
	lit := lits[0]
	for _, el := range lit.Elts {
		kv, ok := el.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		if id, ok := kv.Key.(*ast.Ident); !ok || id.Name != "CurvePreferences" {
			continue
		}
		cl, ok := kv.Value.(*ast.CompositeLit)
		if !ok {
			site.Resolution = ir.ResolutionUnresolved
			site.Evidence = append(site.Evidence, "CurvePreferences set from non-literal value")
			return false
		}
		var groups []string
		hasMLKEM := false
		for _, g := range cl.Elts {
			name := exprIdentName(g, info)
			groups = append(groups, name)
			if name == "X25519MLKEM768" {
				hasMLKEM = true
			}
		}
		site.Resolution = ir.ResolutionLiteral
		ev := "curve_preferences=[" + strings.Join(groups, " ") + "]"
		if !hasMLKEM {
			ev += " — X25519MLKEM768 ABSENT: explicit list disables PQ KEX (go>=1.24)"
		}
		site.Evidence = append(site.Evidence, ev)
		return true
	}
	// No CurvePreferences field: Go defaults apply (hybrid on, go>=1.24).
	site.Resolution = ir.ResolutionLiteral
	site.Evidence = append(site.Evidence, "no explicit CurvePreferences: go>=1.24 defaults negotiate X25519MLKEM768")
	return true
}

func exprIdentName(e ast.Expr, info *types.Info) string {
	switch x := e.(type) {
	case *ast.SelectorExpr:
		return x.Sel.Name
	case *ast.Ident:
		return x.Name
	default:
		if tv, ok := info.Types[e]; ok && tv.Value != nil {
			return tv.Value.ExactString()
		}
		return "?"
	}
}
