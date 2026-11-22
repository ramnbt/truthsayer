package resolver

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"path/filepath"
	"strings"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// factKind classifies where a traced SSA value came from.
type factKind int

const (
	factUnknown factKind = iota
	factConst
	factConfig       // env var, flag, file read — value exists but not in source
	factCurve        // elliptic.PXXX()
	factKeyGenerated // rsa/ecdsa/ed25519 GenerateKey
	factKeyLoaded    // pem.Decode / x509.Parse* / ssh.ParsePrivateKey
	factKeyExternal  // KMS/HSM/secret-manager SDK
	factParam        // function parameter with no visible caller
)

type fact struct {
	kind   factKind
	detail string
}

const (
	maxTraceDepth = 16
	maxFanIn      = 16 // callers examined per parameter/return hop
)

// tracer walks the SSA value graph. With a callgraph it crosses function
// boundaries: backward through callers for parameters, into in-module
// callees for returned values. Without one (cg == nil) it degrades to the
// intraprocedural walk, stopping honestly at boundaries.
type tracer struct {
	cg       *callgraph.Graph
	inModule map[*ssa.Function]bool
	// globalStores caches every store to each package-level var across the
	// module (lazily built): soundness over speed — a global's value is the
	// merge of everything ever stored to it.
	globalStores map[*ssa.Global][]ssa.Value
	// originSink, when set, receives the terminal call producing key
	// material each time a trace reaches one (clustering hook).
	originSink func(ssa.Value)
}

func (t *tracer) noteOrigin(v ssa.Value) {
	if t.originSink != nil {
		t.originSink(v)
	}
}

// value walks backward to find the origin of v.
func (t *tracer) value(v ssa.Value, depth int) fact {
	if depth > maxTraceDepth {
		return fact{factUnknown, "trace depth exceeded"}
	}
	switch x := v.(type) {
	case *ssa.Const:
		if x.Value == nil {
			// nil is not an origin fact: a nil key/curve says nothing
			// about where real values come from on other paths.
			return fact{factUnknown, "nil literal"}
		}
		return fact{factConst, x.Value.ExactString()}
	case *ssa.Convert:
		return t.value(x.X, depth+1)
	case *ssa.ChangeType:
		return t.value(x.X, depth+1)
	case *ssa.MakeInterface:
		return t.value(x.X, depth+1)
	case *ssa.TypeAssert:
		return t.value(x.X, depth+1)
	case *ssa.Slice:
		return t.value(x.X, depth+1)
	case *ssa.Extract:
		if call, ok := x.Tuple.(*ssa.Call); ok {
			return t.callResult(call, x.Index, depth)
		}
		return t.value(x.Tuple, depth+1)
	case *ssa.Phi:
		return t.phi(x, depth)
	case *ssa.Call:
		return t.callResult(x, 0, depth)
	case *ssa.UnOp:
		if x.Op == token.MUL { // load through a pointer
			return t.load(x, depth)
		}
		return t.value(x.X, depth+1)
	case *ssa.Parameter:
		return t.parameter(x, depth)
	case *ssa.Global:
		return t.global(x, depth)
	case *ssa.FreeVar:
		return t.freeVar(x, depth)
	case *ssa.Alloc:
		return t.alloc(x, depth)
	case *ssa.Lookup:
		return t.mapLookup(x, depth)
	case *ssa.FieldAddr:
		return t.addrStores(x.X, x, depth)
	case *ssa.Field:
		return fact{factUnknown, "struct field of register value"}
	default:
		return fact{factUnknown, fmt.Sprintf("unhandled ssa value (%T)", v)}
	}
}

// freeVar resolves a closure capture to what the enclosing function bound.
func (t *tracer) freeVar(fv *ssa.FreeVar, depth int) fact {
	parent := fv.Parent()
	idx := -1
	for i, f := range parent.FreeVars {
		if f == fv {
			idx = i
			break
		}
	}
	refs := parent.Referrers()
	if idx < 0 || refs == nil {
		return fact{factUnknown, "closure capture " + fv.Name()}
	}
	var facts []fact
	for _, instr := range *refs {
		if mc, ok := instr.(*ssa.MakeClosure); ok && idx < len(mc.Bindings) {
			facts = append(facts, t.value(mc.Bindings[idx], depth+1))
		}
	}
	if len(facts) == 0 {
		return fact{factUnknown, "closure capture " + fv.Name() + " (no binding site)"}
	}
	return mergeFacts(facts, "closure capture "+fv.Name())
}

// global merges every store to a package-level var across the module —
// including the init store for `var x = ...`.
func (t *tracer) global(g *ssa.Global, depth int) fact {
	if t.globalStores == nil {
		t.globalStores = map[*ssa.Global][]ssa.Value{}
		for fn := range t.inModule {
			for _, b := range fn.Blocks {
				for _, instr := range b.Instrs {
					if st, ok := instr.(*ssa.Store); ok {
						if dst, ok := st.Addr.(*ssa.Global); ok {
							t.globalStores[dst] = append(t.globalStores[dst], st.Val)
						}
					}
				}
			}
		}
	}
	stores := t.globalStores[g]
	if len(stores) == 0 {
		return fact{factUnknown, "package-level var " + g.Name() + " (no store found in module)"}
	}
	facts := make([]fact, 0, len(stores))
	for _, v := range stores {
		facts = append(facts, t.value(v, depth+1))
	}
	return mergeFacts(facts, "package-level var "+g.Name())
}

// mapLookup resolves m[k] against the MapUpdates that built m.
func (t *tracer) mapLookup(l *ssa.Lookup, depth int) fact {
	refs := l.X.Referrers()
	if refs == nil {
		return fact{factUnknown, "map lookup on non-local map"}
	}
	wantKey, keyIsConst := l.Index.(*ssa.Const)
	var facts []fact
	for _, instr := range *refs {
		up, ok := instr.(*ssa.MapUpdate)
		if !ok {
			continue
		}
		if keyIsConst {
			if k, ok := up.Key.(*ssa.Const); ok && k.Value != nil && wantKey.Value != nil &&
				k.Value.ExactString() != wantKey.Value.ExactString() {
				continue // different constant key cannot flow to this lookup
			}
		}
		facts = append(facts, t.value(up.Value, depth+1))
	}
	if len(facts) == 0 {
		return fact{factUnknown, "map lookup: no matching update found"}
	}
	return mergeFacts(facts, "map lookup")
}

// addrStores merges the values stored through a specific field/index of a
// local base: sibling FieldAddr/IndexAddr of the same base selecting the
// same element, plus whole-base copies (`*dst = *src` — how go/ssa builds
// composite literals since x/tools v0.52) projected through to the source.
func (t *tracer) addrStores(base ssa.Value, sel ssa.Value, depth int) fact {
	if depth > maxTraceDepth {
		return fact{factUnknown, "trace depth exceeded"}
	}
	// A slice literal stores through the backing array's alloc, while the
	// load indexes the Slice value — unwrap to the shared base.
	base = unwrapSlice(base)
	refs := base.Referrers()
	if refs == nil {
		return fact{factUnknown, "field/index of non-local value"}
	}
	var facts []fact
	for _, instr := range *refs {
		// Whole-struct/array copy into base: project the selection into
		// whatever the copied value was loaded from.
		if st, ok := instr.(*ssa.Store); ok && st.Addr == base {
			if u, ok := st.Val.(*ssa.UnOp); ok && u.Op == token.MUL {
				facts = append(facts, t.addrStores(u.X, sel, depth+1))
			} else {
				facts = append(facts, fact{factUnknown, "whole value copied from untraceable source"})
			}
			continue
		}
		addr, ok := instr.(ssa.Value)
		if !ok || !selectsSameElem(sel, addr, base) {
			continue
		}
		aRefs := addr.Referrers()
		if aRefs == nil {
			continue
		}
		for _, use := range *aRefs {
			if st, ok := use.(*ssa.Store); ok && st.Addr == addr {
				facts = append(facts, t.value(st.Val, depth+1))
			}
		}
	}
	if len(facts) == 0 {
		return fact{factUnknown, "field/index never stored (or stored through an alias)"}
	}
	return mergeFacts(facts, "field/index stores")
}

func unwrapSlice(v ssa.Value) ssa.Value {
	for {
		s, ok := v.(*ssa.Slice)
		if !ok {
			return v
		}
		v = s.X
	}
}

// selectsSameElem reports whether candidate addresses the same element that
// sel does, within base. sel's own base may differ (whole-value copies are
// projected across allocs), so only the element — field number or index —
// is compared against sel; the base is compared against candidate.
func selectsSameElem(sel, candidate, base ssa.Value) bool {
	switch s := sel.(type) {
	case *ssa.FieldAddr:
		c, ok := candidate.(*ssa.FieldAddr)
		return ok && unwrapSlice(c.X) == base && c.Field == s.Field
	case *ssa.IndexAddr:
		c, ok := candidate.(*ssa.IndexAddr)
		if !ok || unwrapSlice(c.X) != base {
			return false
		}
		si, so := s.Index.(*ssa.Const)
		ci, co := c.Index.(*ssa.Const)
		if so && co && si.Value != nil && ci.Value != nil {
			return si.Value.ExactString() == ci.Value.ExactString()
		}
		return true // any non-constant index may alias
	}
	return false
}

// parameter crosses backward into callers via the callgraph.
func (t *tracer) parameter(p *ssa.Parameter, depth int) fact {
	stop := fact{factParam, "function parameter " + p.Name() + " (no caller visible)"}
	if t.cg == nil {
		return stop
	}
	fn := p.Parent()
	node := t.cg.Nodes[fn]
	if node == nil || len(node.In) == 0 {
		return stop
	}
	if len(node.In) > maxFanIn {
		return fact{factUnknown, fmt.Sprintf("parameter %s: %d callers (fan-in cap %d)", p.Name(), len(node.In), maxFanIn)}
	}
	idx := -1
	for i, q := range fn.Params {
		if q == p {
			idx = i
			break
		}
	}
	if idx < 0 {
		return stop
	}
	var facts []fact
	for _, edge := range node.In {
		if edge.Site == nil {
			return fact{factUnknown, "parameter " + p.Name() + ": synthetic call edge"}
		}
		cc := edge.Site.Common()
		var arg ssa.Value
		if cc.IsInvoke() {
			// Invoke mode: receiver is cc.Value, Args hold the rest.
			if idx == 0 {
				arg = cc.Value
			} else if idx-1 < len(cc.Args) {
				arg = cc.Args[idx-1]
			}
		} else if idx < len(cc.Args) {
			arg = cc.Args[idx]
		}
		if arg == nil {
			return fact{factUnknown, "parameter " + p.Name() + ": argument shape mismatch at call site"}
		}
		facts = append(facts, t.value(arg, depth+1))
	}
	return mergeFacts(facts, "parameter "+p.Name()+" across callers")
}

// callResult resolves the idx-th result of a call: known crypto/config
// producers first, then into in-module callees' return statements.
func (t *tracer) callResult(c *ssa.Call, idx int, depth int) fact {
	cc := c.Common()
	callee := cc.StaticCallee()
	if callee == nil {
		return t.dynamicCallResult(c, idx, depth)
	}
	path := ""
	if callee.Pkg != nil {
		path = callee.Pkg.Pkg.Path()
	}
	sym := path + "." + callee.Name()

	switch sym {
	case "os.Getenv", "os.LookupEnv":
		return fact{factConfig, "environment variable (" + renderConstArg(c, 0) + ")"}
	case "os.ReadFile":
		return fact{factConfig, "file read (" + renderConstArg(c, 0) + ")"}
	case "strconv.Atoi", "strconv.ParseInt", "strconv.ParseUint":
		inner := t.value(cc.Args[0], depth+1)
		if inner.kind == factConfig {
			return inner
		}
		return fact{factUnknown, "parsed from " + inner.detail}
	case "crypto/elliptic.P224", "crypto/elliptic.P256", "crypto/elliptic.P384", "crypto/elliptic.P521":
		return fact{factCurve, callee.Name()}
	case "crypto/rsa.GenerateKey", "crypto/rsa.GenerateMultiPrimeKey",
		"crypto/ecdsa.GenerateKey", "crypto/ed25519.GenerateKey",
		"crypto/ecdh.GenerateKey":
		t.noteOrigin(c)
		return fact{factKeyGenerated, "generated in-process (" + sym + ")"}
	case "encoding/pem.Decode",
		"crypto/x509.ParsePKCS1PrivateKey", "crypto/x509.ParsePKCS8PrivateKey",
		"crypto/x509.ParseECPrivateKey", "crypto/x509.ParseCertificate",
		"crypto/tls.LoadX509KeyPair", "crypto/tls.X509KeyPair",
		"golang.org/x/crypto/ssh.ParsePrivateKey", "golang.org/x/crypto/ssh.ParseRawPrivateKey":
		t.noteOrigin(c)
		return fact{factKeyLoaded, "parsed from serialized form (" + sym + ")"}
	}
	if strings.HasPrefix(sym, "flag.") {
		return fact{factConfig, "command-line flag"}
	}
	for _, marker := range []string{"kms", "secretsmanager", "secretmanager", "vault", "hsm", "pkcs11"} {
		if strings.Contains(strings.ToLower(path), marker) {
			t.noteOrigin(c)
			return fact{factKeyExternal, "external key store (" + path + ")"}
		}
	}
	// In-module callee: trace what it returns.
	if t.inModule[callee] && len(callee.Blocks) > 0 {
		var facts []fact
		for _, b := range callee.Blocks {
			for _, instr := range b.Instrs {
				ret, ok := instr.(*ssa.Return)
				if !ok || idx >= len(ret.Results) {
					continue
				}
				facts = append(facts, t.value(ret.Results[idx], depth+1))
				if len(facts) > maxFanIn {
					return fact{factUnknown, "too many return paths in " + sym}
				}
			}
		}
		if len(facts) > 0 {
			return mergeFacts(facts, "returned by "+sym)
		}
	}
	return fact{factUnknown, "returned by " + sym}
}

// dynamicCallResult resolves an interface-dispatch result through the VTA
// callgraph: the concrete callees reachable from this call site.
func (t *tracer) dynamicCallResult(c *ssa.Call, idx int, depth int) fact {
	if t.cg == nil || c.Parent() == nil {
		return fact{factUnknown, "dynamic call"}
	}
	node := t.cg.Nodes[c.Parent()]
	if node == nil {
		return fact{factUnknown, "dynamic call (caller not in callgraph)"}
	}
	var facts []fact
	callees := 0
	for _, edge := range node.Out {
		if edge.Site != ssa.CallInstruction(c) || edge.Callee == nil {
			continue
		}
		callees++
		if callees > maxFanIn {
			return fact{factUnknown, fmt.Sprintf("dynamic call: >%d possible callees", maxFanIn)}
		}
		fn := edge.Callee.Func
		for _, b := range fn.Blocks {
			for _, instr := range b.Instrs {
				if ret, ok := instr.(*ssa.Return); ok && idx < len(ret.Results) {
					facts = append(facts, t.value(ret.Results[idx], depth+1))
				}
			}
		}
	}
	if len(facts) == 0 {
		return fact{factUnknown, "dynamic call (no resolvable callee)"}
	}
	return mergeFacts(facts, "dynamic dispatch")
}

// phi merges facts across control-flow joins.
func (t *tracer) phi(p *ssa.Phi, depth int) fact {
	facts := make([]fact, 0, len(p.Edges))
	for _, e := range p.Edges {
		facts = append(facts, t.value(e, depth+1))
	}
	return mergeFacts(facts, "control-flow join")
}

// mergeFacts combines facts from multiple paths (phi edges, callers,
// return statements): unanimous facts survive; config taints; a single
// provenance kind survives unknown siblings (one proven PEM-load path is
// actionable even when other paths are opaque); conflicting definite facts
// degrade to honest unknown.
func mergeFacts(facts []fact, where string) fact {
	if len(facts) == 0 {
		return fact{factUnknown, where + ": no paths"}
	}
	first := facts[0]
	allSame := true
	for _, f := range facts[1:] {
		if f.kind != first.kind || f.detail != first.detail {
			allSame = false
			break
		}
	}
	if allSame {
		return first
	}

	var consts []string
	uniqConst := map[string]bool{}
	provKinds := map[factKind]fact{}
	unknowns := 0
	for _, f := range facts {
		switch f.kind {
		case factConfig:
			return fact{factConfig, f.detail + " (one of several paths: " + where + ")"}
		case factConst:
			if !uniqConst[f.detail] {
				uniqConst[f.detail] = true
				consts = append(consts, f.detail)
			}
		case factKeyGenerated, factKeyLoaded, factKeyExternal, factCurve:
			provKinds[f.kind] = f
		default:
			unknowns++
		}
	}
	if len(provKinds) == 1 && len(consts) == 0 {
		for _, f := range provKinds {
			if unknowns > 0 {
				f.detail += " (some paths unresolved: " + where + ")"
			}
			return f
		}
	}
	if len(provKinds) > 1 {
		return fact{factUnknown, where + ": conflicting origins across paths"}
	}
	if len(consts) == 1 && unknowns == 0 {
		return fact{factConst, consts[0]}
	}
	if len(consts) > 0 {
		return fact{factUnknown, where + ": varies {" + strings.Join(consts, ", ") + "}"}
	}
	return fact{factUnknown, where + ": no path resolved"}
}

func renderConstArg(c *ssa.Call, idx int) string {
	if idx < len(c.Common().Args) {
		if k, ok := c.Common().Args[idx].(*ssa.Const); ok && k.Value != nil {
			return k.Value.ExactString()
		}
	}
	return "dynamic name"
}

// load resolves a load through a pointer: locals, globals, closure
// captures, struct fields, and indexed elements each have a store-finding
// strategy.
func (t *tracer) load(u *ssa.UnOp, depth int) fact {
	switch x := u.X.(type) {
	case *ssa.Alloc:
		return t.alloc(x, depth)
	case *ssa.Global:
		return t.global(x, depth)
	case *ssa.FreeVar:
		// The binding is the captured variable's address; loading it means
		// resolving what that address holds.
		f := t.freeVar(x, depth)
		return f
	case *ssa.FieldAddr:
		return t.addrStores(x.X, x, depth)
	case *ssa.IndexAddr:
		return t.addrStores(x.X, x, depth)
	default:
		return fact{factUnknown, fmt.Sprintf("load through %T", u.X)}
	}
}

func (t *tracer) alloc(alloc *ssa.Alloc, depth int) fact {
	var stores []*ssa.Store
	for _, ref := range *alloc.Referrers() {
		if st, ok := ref.(*ssa.Store); ok && st.Addr == alloc {
			stores = append(stores, st)
		}
	}
	switch len(stores) {
	case 0:
		return fact{factUnknown, "local never stored (zero value)"}
	case 1:
		return t.value(stores[0].Val, depth+1)
	default:
		facts := make([]fact, 0, len(stores))
		for _, st := range stores {
			facts = append(facts, t.value(st.Val, depth+1))
		}
		return mergeFacts(facts, "multiple stores")
	}
}

// --- indexes ---

// indexSSACalls maps (file, line, callee-symbol) to call sites across the
// whole program, restricted to functions with source positions.
func indexSSACalls(prog *ssa.Program) map[callKey][]ssa.CallInstruction {
	idx := map[callKey][]ssa.CallInstruction{}
	for fn := range ssautil.AllFunctions(prog) {
		for _, b := range fn.Blocks {
			for _, instr := range b.Instrs {
				call, ok := instr.(ssa.CallInstruction)
				if !ok {
					continue
				}
				cc := call.Common()
				callee := cc.StaticCallee()
				if callee == nil || callee.Pkg == nil {
					continue
				}
				pos := prog.Fset.Position(call.Pos())
				if !pos.IsValid() {
					continue
				}
				k := callKey{
					file:   filepath.Clean(pos.Filename),
					line:   pos.Line,
					callee: callee.Pkg.Pkg.Path() + "." + callee.Name(),
				}
				idx[k] = append(idx[k], call)
			}
		}
	}
	return idx
}

// astIndex finds AST nodes (with their types.Info) by file position.
type astIndex struct {
	files map[string]astFile // abs path -> file
}

type astFile struct {
	file *ast.File
	info *types.Info
	fset *token.FileSet
}

func indexAST(pkgs []*packages.Package) *astIndex {
	idx := &astIndex{files: map[string]astFile{}}
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		if p.Module == nil || p.TypesInfo == nil {
			return
		}
		for _, f := range p.Syntax {
			pos := p.Fset.Position(f.Pos())
			if pos.IsValid() {
				idx.files[filepath.Clean(pos.Filename)] = astFile{f, p.TypesInfo, p.Fset}
			}
		}
	})
	return idx
}

// callAt finds the call expression for symbol ("importpath.Name") whose
// selector sits on the given line.
func (a *astIndex) callAt(absFile string, line int, symbol string) (*ast.CallExpr, *types.Info) {
	af, ok := a.files[filepath.Clean(absFile)]
	if !ok {
		return nil, nil
	}
	wantName := symbol[strings.LastIndex(symbol, ".")+1:]
	var found *ast.CallExpr
	ast.Inspect(af.file, func(n ast.Node) bool {
		if found != nil {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != wantName {
			return true
		}
		if af.fset.Position(sel.Pos()).Line != line {
			return true
		}
		// Confirm the selector resolves to the expected package.
		if fn, ok := af.info.Uses[sel.Sel].(*types.Func); ok && fn.Pkg() != nil {
			if fn.Pkg().Path()+"."+fn.Name() == symbol {
				found = call
				return false
			}
		}
		return true
	})
	if found == nil {
		return nil, nil
	}
	return found, af.info
}

// tlsConfigLitsInFunc finds every tls.Config composite literal inside the
// named function. The scanner anchors a tls.Config site to the symbol's
// first use in the function (often the signature), so the literal must be
// searched for function-wide, not by line.
// The scanner records bare function names, so two methods sharing a name in
// one file are ambiguous — reported as such rather than resolved against the
// wrong body (a wrong definite fact is worse than UNRESOLVED).
func (a *astIndex) tlsConfigLitsInFunc(absFile, funcName string) (lits []*ast.CompositeLit, info *types.Info, ambiguous bool) {
	af, ok := a.files[filepath.Clean(absFile)]
	if !ok {
		return nil, nil, false
	}
	var scope ast.Node = af.file
	if funcName != "" {
		var matches []*ast.FuncDecl
		for _, d := range af.file.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Name.Name == funcName {
				matches = append(matches, fd)
			}
		}
		if len(matches) > 1 {
			return nil, af.info, true
		}
		if len(matches) == 1 {
			scope = matches[0]
		}
	}
	ast.Inspect(scope, func(n ast.Node) bool {
		cl, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		tv, ok := af.info.Types[cl]
		if !ok {
			return true
		}
		named, ok := tv.Type.(*types.Named)
		if !ok {
			return true
		}
		if obj := named.Obj(); obj.Name() == "Config" && obj.Pkg() != nil && obj.Pkg().Path() == "crypto/tls" {
			lits = append(lits, cl)
		}
		return true
	})
	return lits, af.info, false
}
