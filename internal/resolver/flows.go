package resolver

import (
	"fmt"
	"go/token"
	"go/types"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/tools/go/ssa"
)

// Config-default flows (M6, T5): mature codebases rarely write the curve
// list at the tls.Config site — they keep a default slice somewhere and map
// config onto it (the caddy/etcd pattern). This pass finds every store to a
// CurvePreferences field and traces the stored value backward to the
// []tls.CurveID composite literals it came from. Those literal positions
// are deterministic rewrite targets: adding X25519MLKEM768 to a default
// that provably feeds CurvePreferences is the same operation as T1, one
// dataflow hop (or several) removed.

// PrefLiteral is one []tls.CurveID composite literal that flows into a
// CurvePreferences field.
type PrefLiteral struct {
	File string // relative to root
	Line int
	// Sites lists the CurvePreferences stores this literal reaches
	// ("file:line", relative), for evidence.
	Sites []string
}

// CurvePreferenceFlows loads the module and returns the literal targets.
// Literals outside the module root (library defaults) are reported in notes
// and never rewritten.
func CurvePreferenceFlows(root string) ([]PrefLiteral, []string) {
	r, notes := loadTarget(root)
	if r == nil {
		return nil, notes
	}
	byLit := map[string]*PrefLiteral{}
	outside := map[string]bool{}

	for fn := range r.trc.inModule {
		for _, b := range fn.Blocks {
			for _, instr := range b.Instrs {
				st, ok := instr.(*ssa.Store)
				if !ok {
					continue
				}
				fa, ok := st.Addr.(*ssa.FieldAddr)
				if !ok || !isTLSConfigCurvePrefs(fa) {
					continue
				}
				sitePos := r.fset.Position(st.Pos())
				if !sitePos.IsValid() {
					sitePos = r.fset.Position(fa.Pos())
				}
				site := r.relPos(sitePos)
				seen := map[ssa.Value]bool{}
				for _, alloc := range r.trc.sliceOrigins(st.Val, 0, seen) {
					pos := r.fset.Position(alloc.Pos())
					if !pos.IsValid() {
						continue
					}
					file := filepath.Clean(pos.Filename)
					rel, err := filepath.Rel(r.root, file)
					if err != nil || strings.HasPrefix(rel, "..") {
						outside[fmt.Sprintf("%s:%d", file, pos.Line)] = true
						continue
					}
					key := fmt.Sprintf("%s:%d", rel, pos.Line)
					lit := byLit[key]
					if lit == nil {
						lit = &PrefLiteral{File: rel, Line: pos.Line}
						byLit[key] = lit
					}
					if site != "" && !contains(lit.Sites, site) {
						lit.Sites = append(lit.Sites, site)
					}
				}
			}
		}
	}

	lits := make([]PrefLiteral, 0, len(byLit))
	for _, l := range byLit {
		sort.Strings(l.Sites)
		lits = append(lits, *l)
	}
	sort.Slice(lits, func(i, j int) bool {
		if lits[i].File != lits[j].File {
			return lits[i].File < lits[j].File
		}
		return lits[i].Line < lits[j].Line
	})
	if len(outside) > 0 {
		keys := make([]string, 0, len(outside))
		for k := range outside {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		notes = append(notes, fmt.Sprintf("flows: %d CurvePreferences default(s) live outside the module (library code) — not rewritable here: %s",
			len(outside), strings.Join(keys, ", ")))
	}
	notes = append(notes, fmt.Sprintf("flows: %d in-module []tls.CurveID literal(s) feed CurvePreferences", len(lits)))
	return lits, notes
}

func (r *resolution) relPos(p token.Position) string {
	rel, err := filepath.Rel(r.root, filepath.Clean(p.Filename))
	if err != nil || strings.HasPrefix(rel, "..") {
		return ""
	}
	return fmt.Sprintf("%s:%d", rel, p.Line)
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// isTLSConfigCurvePrefs reports whether fa addresses tls.Config.CurvePreferences.
func isTLSConfigCurvePrefs(fa *ssa.FieldAddr) bool {
	ptr, ok := fa.X.Type().Underlying().(*types.Pointer)
	if !ok {
		return false
	}
	named, ok := ptr.Elem().(*types.Named)
	if !ok {
		return false
	}
	obj := named.Obj()
	if obj.Name() != "Config" || obj.Pkg() == nil || obj.Pkg().Path() != "crypto/tls" {
		return false
	}
	st, ok := named.Underlying().(*types.Struct)
	return ok && fa.Field < st.NumFields() && st.Field(fa.Field).Name() == "CurvePreferences"
}

// sliceOrigins walks backward from v collecting the array allocs backing
// []tls.CurveID composite literals. It mirrors tracer.value's traversal,
// bounded the same way; anything it cannot see through is simply not a
// rewrite target (under-rewriting is safe, the site stays UNRESOLVED).
func (t *tracer) sliceOrigins(v ssa.Value, depth int, seen map[ssa.Value]bool) []*ssa.Alloc {
	if depth > maxTraceDepth || seen[v] {
		return nil
	}
	seen[v] = true
	switch x := v.(type) {
	case *ssa.Alloc:
		if isCurveIDArrayPtr(x.Type()) {
			return []*ssa.Alloc{x}
		}
		var out []*ssa.Alloc
		for _, ref := range *x.Referrers() {
			if st, ok := ref.(*ssa.Store); ok && st.Addr == x {
				out = append(out, t.sliceOrigins(st.Val, depth+1, seen)...)
			}
		}
		return out
	case *ssa.Slice:
		return t.sliceOrigins(x.X, depth+1, seen)
	case *ssa.Convert:
		return t.sliceOrigins(x.X, depth+1, seen)
	case *ssa.ChangeType:
		return t.sliceOrigins(x.X, depth+1, seen)
	case *ssa.Phi:
		var out []*ssa.Alloc
		for _, e := range x.Edges {
			out = append(out, t.sliceOrigins(e, depth+1, seen)...)
		}
		return out
	case *ssa.UnOp:
		if x.Op != token.MUL {
			return nil
		}
		switch addr := x.X.(type) {
		case *ssa.Alloc:
			var out []*ssa.Alloc
			for _, ref := range *addr.Referrers() {
				if st, ok := ref.(*ssa.Store); ok && st.Addr == addr {
					out = append(out, t.sliceOrigins(st.Val, depth+1, seen)...)
				}
			}
			return out
		case *ssa.Global:
			if t.globalStores == nil {
				t.global(addr, depth) // populate the lazy store index
			}
			var out []*ssa.Alloc
			for _, val := range t.globalStores[addr] {
				out = append(out, t.sliceOrigins(val, depth+1, seen)...)
			}
			return out
		case *ssa.FreeVar:
			parent := addr.Parent()
			idx := -1
			for i, f := range parent.FreeVars {
				if f == addr {
					idx = i
				}
			}
			refs := parent.Referrers()
			if idx < 0 || refs == nil {
				return nil
			}
			var out []*ssa.Alloc
			for _, ref := range *refs {
				if mc, ok := ref.(*ssa.MakeClosure); ok && idx < len(mc.Bindings) {
					out = append(out, t.sliceOrigins(mc.Bindings[idx], depth+1, seen)...)
				}
			}
			return out
		}
		return nil
	case *ssa.Extract:
		return t.sliceOrigins(x.Tuple, depth+1, seen)
	case *ssa.Call:
		callee := x.Common().StaticCallee()
		if callee == nil || !t.inModule[callee] {
			return nil
		}
		var out []*ssa.Alloc
		for _, b := range callee.Blocks {
			for _, instr := range b.Instrs {
				if ret, ok := instr.(*ssa.Return); ok && len(ret.Results) > 0 {
					out = append(out, t.sliceOrigins(ret.Results[0], depth+1, seen)...)
				}
			}
		}
		return out
	case *ssa.Parameter:
		if t.cg == nil {
			return nil
		}
		fn := x.Parent()
		node := t.cg.Nodes[fn]
		if node == nil || len(node.In) == 0 || len(node.In) > maxFanIn {
			return nil
		}
		idx := -1
		for i, q := range fn.Params {
			if q == x {
				idx = i
			}
		}
		if idx < 0 {
			return nil
		}
		var out []*ssa.Alloc
		for _, edge := range node.In {
			if edge.Site == nil {
				continue
			}
			cc := edge.Site.Common()
			var arg ssa.Value
			if cc.IsInvoke() {
				if idx == 0 {
					arg = cc.Value
				} else if idx-1 < len(cc.Args) {
					arg = cc.Args[idx-1]
				}
			} else if idx < len(cc.Args) {
				arg = cc.Args[idx]
			}
			if arg != nil {
				out = append(out, t.sliceOrigins(arg, depth+1, seen)...)
			}
		}
		return out
	}
	return nil
}

// isCurveIDArrayPtr matches *[N]tls.CurveID — the backing array a
// []tls.CurveID composite literal allocates.
func isCurveIDArrayPtr(t types.Type) bool {
	ptr, ok := t.Underlying().(*types.Pointer)
	if !ok {
		return false
	}
	arr, ok := ptr.Elem().Underlying().(*types.Array)
	if !ok {
		return false
	}
	named, ok := arr.Elem().(*types.Named)
	if !ok {
		return false
	}
	obj := named.Obj()
	return obj.Name() == "CurveID" && obj.Pkg() != nil && obj.Pkg().Path() == "crypto/tls"
}
