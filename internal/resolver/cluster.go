package resolver

import (
	"fmt"
	"path/filepath"
	"sort"

	"golang.org/x/tools/go/ssa"

	"github.com/ramnbt/truthsayer/internal/ir"
)

// Key-lifecycle clustering: sites touching the same key object — the call
// that generated or loaded it — belong to one migration unit (gameplan: one
// PR per cluster; a signature swap must cover every signer/verifier of that
// key together).
//
// Origins are keyed by source position, not SSA value identity: with test
// variants loaded, the same source call appears as distinct ssa.Values in
// the package and package.test programs.

// clusterKeys assigns Cluster ids and returns the number of clusters.
func (r *resolution) clusterKeys(inv *ir.Inventory) int {
	siteOrigins := map[*ir.CallSite][]string{}
	originPos := map[string]struct {
		file string
		line int
	}{}

	record := func(site *ir.CallSite, v ssa.Value) {
		pos := r.fset.Position(v.Pos())
		if !pos.IsValid() {
			return
		}
		key := fmt.Sprintf("%s:%d:%d", filepath.Clean(pos.Filename), pos.Line, pos.Column)
		siteOrigins[site] = append(siteOrigins[site], key)
		originPos[key] = struct {
			file string
			line int
		}{filepath.Clean(pos.Filename), pos.Line}
	}

	for i := range inv.Sites {
		site := &inv.Sites[i]
		abs := filepath.Join(r.root, site.Site.File)
		cis := r.calls[callKey{abs, site.Site.Line, site.Primitive.Symbol}]
		if len(cis) == 0 {
			continue
		}
		// A key-producing call is itself an origin.
		if kind, ok := resultSpecs[site.Primitive.Symbol]; ok && kind == resultKey {
			for _, ci := range cis {
				if c, ok := ci.(*ssa.Call); ok {
					record(site, c)
				}
			}
		}
		// A key-consuming call joins the origins its key argument traces to.
		if spec, ok := argSpecs[site.Primitive.Symbol]; ok && spec.kind == argKey {
			r.trc.originSink = func(v ssa.Value) { record(site, v) }
			for _, ci := range cis {
				if args := ci.Common().Args; spec.idx < len(args) {
					r.trc.value(args[spec.idx], 0)
				}
			}
			r.trc.originSink = nil
		}
	}

	// Union-find over origin keys; a site with several origins bridges them.
	parent := map[string]string{}
	var find func(string) string
	find = func(x string) string {
		if parent[x] == "" || parent[x] == x {
			parent[x] = x
			return x
		}
		root := find(parent[x])
		parent[x] = root
		return root
	}
	union := func(a, b string) { parent[find(a)] = find(b) }
	for _, origins := range siteOrigins {
		for i := 1; i < len(origins); i++ {
			union(origins[0], origins[i])
		}
	}

	// Deterministic ids: clusters ordered by their earliest origin position.
	rootMembers := map[string][]*ir.CallSite{}
	rootRep := map[string]string{} // root -> representative origin key
	for site, origins := range siteOrigins {
		root := find(origins[0])
		rootMembers[root] = append(rootMembers[root], site)
		for _, o := range origins {
			if rep, ok := rootRep[root]; !ok || less(originPos[o].file, originPos[o].line, originPos[rep].file, originPos[rep].line) {
				rootRep[root] = o
			}
		}
	}
	roots := make([]string, 0, len(rootMembers))
	for root := range rootMembers {
		roots = append(roots, root)
	}
	sort.Slice(roots, func(i, j int) bool {
		a, b := originPos[rootRep[roots[i]]], originPos[rootRep[roots[j]]]
		return less(a.file, a.line, b.file, b.line)
	})
	for n, root := range roots {
		id := fmt.Sprintf("K%d", n+1)
		members := rootMembers[root]
		rep := originPos[rootRep[root]]
		repRel, err := filepath.Rel(r.root, rep.file)
		if err != nil {
			repRel = rep.file
		}
		for _, site := range members {
			site.Cluster = id
			site.Evidence = append(site.Evidence,
				fmt.Sprintf("key lifecycle %s: %d site(s) share the key from %s:%d", id, len(members), repRel, rep.line))
		}
	}
	return len(roots)
}

func less(f1 string, l1 int, f2 string, l2 int) bool {
	if f1 != f2 {
		return f1 < f2
	}
	return l1 < l2
}
