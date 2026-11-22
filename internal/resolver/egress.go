package resolver

import (
	"fmt"
	"go/token"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/tools/go/ssa"

	"github.com/ramnbt/truthsayer/internal/ir"
)

// Egress detection: forward dataflow from a crypto value (key, ciphertext,
// signature, serialized form) to the boundary it crosses — file, network,
// database, or an io.Writer we cannot see past. Egress facts replace the
// classifier's family-based lifetime guesses (I20): HNDL priority should
// follow where ciphertext actually goes, not what family produced it.
//
// With the callgraph, tracing crosses function boundaries (returns followed
// into callers, arguments followed into in-module callees, closure captures
// followed into the closure body). Anything it cannot see past is recorded
// honestly — "no egress observed" is only claimed when the walk completed.

// resultKind says what crypto material a sink call produces.
type resultKind int

const (
	resultKey resultKind = iota
	resultCiphertext
	resultSignature
	resultSerialized
)

func (k resultKind) String() string {
	switch k {
	case resultKey:
		return "private key"
	case resultCiphertext:
		return "ciphertext"
	case resultSignature:
		return "signature"
	default:
		return "serialized key material"
	}
}

// resultSpecs marks sinks whose results deserve forward egress tracing.
var resultSpecs = map[string]resultKind{
	"crypto/rsa.GenerateKey":             resultKey,
	"crypto/rsa.GenerateMultiPrimeKey":   resultKey,
	"crypto/ecdsa.GenerateKey":           resultKey,
	"crypto/ed25519.GenerateKey":         resultKey,
	"crypto/rsa.EncryptOAEP":             resultCiphertext,
	"crypto/rsa.EncryptPKCS1v15":         resultCiphertext,
	"crypto/rsa.SignPKCS1v15":            resultSignature,
	"crypto/rsa.SignPSS":                 resultSignature,
	"crypto/ecdsa.SignASN1":              resultSignature,
	"crypto/ed25519.Sign":                resultSignature,
	"crypto/x509.MarshalPKCS1PrivateKey": resultSerialized,
	"crypto/x509.MarshalECPrivateKey":    resultSerialized,
	"crypto/x509.MarshalPKCS8PrivateKey": resultSerialized,
	"crypto/x509.CreateCertificate":      resultSerialized,
}

// transforms re-encode crypto material: tracing continues from their result.
// Keyed by "pkgpath.FuncName"; methods are matched by receiver in egressCall.
var transforms = map[string]string{
	"crypto/x509.MarshalPKCS1PrivateKey": "x509-marshaled",
	"crypto/x509.MarshalECPrivateKey":    "x509-marshaled",
	"crypto/x509.MarshalPKCS8PrivateKey": "x509-marshaled",
	"encoding/pem.EncodeToMemory":        "pem-encoded",
	"encoding/hex.EncodeToString":        "hex-encoded",
	"encoding/hex.Encode":                "hex-encoded",
	"encoding/base64.EncodeToString":     "base64-encoded", // method, pkg-qualified name after receiver strip
	"fmt.Sprintf":                        "formatted",
	"fmt.Sprint":                         "formatted",
	"fmt.Appendf":                        "formatted",
}

// egressFact is one observed boundary crossing.
type egressFact struct {
	what     string // e.g. "file write (os.WriteFile)"
	lifetime string // persistent | in-transit | "" (unknown destination)
}

const maxEgressDepth = 16

// resolveEgress forward-traces the site's call results and records where
// the material goes. Returns true when a definite boundary was found.
func (r *resolution) resolveEgress(site *ir.CallSite, kind resultKind) bool {
	abs := filepath.Join(r.root, site.Site.File)
	cis := r.calls[callKey{abs, site.Site.Line, site.Primitive.Symbol}]
	if len(cis) == 0 {
		// Never silently skip (hard rule #1) — this is "not analyzed",
		// which must look different from "analyzed and clean".
		site.Egress = append(site.Egress, "egress not analyzed: call not found in SSA (build-excluded file or ill-typed dependency)")
		return false
	}
	seen := map[ssa.Value]bool{}
	var facts []egressFact
	analyzed := false
	for _, ci := range cis {
		if call, ok := ci.(*ssa.Call); ok {
			analyzed = true
			facts = append(facts, r.trc.egress(call, seen, 0)...)
		} else {
			facts = append(facts, egressFact{what: "invoked via go/defer: result discarded, not traced"})
		}
	}
	if len(facts) == 0 {
		if analyzed {
			site.Egress = append(site.Egress, "no egress observed (result stays within analyzed functions)")
		}
		return false
	}
	// Dedup, record, and derive lifetime from the strongest fact:
	// persistent > in-transit > unknown destination.
	uniq := map[string]bool{}
	lifetime := ""
	for _, f := range facts {
		if !uniq[f.what] {
			uniq[f.what] = true
			site.Egress = append(site.Egress, f.what)
		}
		switch f.lifetime {
		case "persistent":
			lifetime = "persistent"
		case "in-transit":
			if lifetime != "persistent" {
				lifetime = "in-transit"
			}
		}
	}
	sort.Strings(site.Egress)
	if lifetime != "" {
		site.Lifetime = lifetime
		site.Evidence = append(site.Evidence,
			fmt.Sprintf("lifetime=%s (%s egress proven, not heuristic)", lifetime, kind))
		return true
	}
	return false
}

// egress walks forward through referrers of v.
func (t *tracer) egress(v ssa.Value, seen map[ssa.Value]bool, depth int) []egressFact {
	if depth > maxEgressDepth || seen[v] {
		return nil
	}
	seen[v] = true
	refs := v.Referrers()
	if refs == nil {
		return nil
	}
	var facts []egressFact
	for _, instr := range *refs {
		switch x := instr.(type) {
		case ssa.CallInstruction:
			facts = append(facts, t.egressCall(x, v, seen, depth)...)
		case *ssa.Store:
			if x.Val == v {
				facts = append(facts, t.egressStore(x, seen, depth)...)
			}
		case *ssa.MakeClosure:
			facts = append(facts, t.egressClosure(x, v, seen, depth)...)
		case *ssa.Extract:
			facts = append(facts, t.egress(x, seen, depth+1)...)
		case *ssa.Phi, *ssa.MakeInterface, *ssa.Convert, *ssa.ChangeType, *ssa.Slice, *ssa.UnOp,
			*ssa.FieldAddr, *ssa.IndexAddr:
			if val, ok := instr.(ssa.Value); ok {
				facts = append(facts, t.egress(val, seen, depth+1)...)
			}
		case *ssa.Return:
			facts = append(facts, t.egressReturn(x, v, seen, depth)...)
		}
	}
	return facts
}

// egressReturn follows a returned value into the callers' use of the result.
func (t *tracer) egressReturn(ret *ssa.Return, v ssa.Value, seen map[ssa.Value]bool, depth int) []egressFact {
	stop := []egressFact{{what: "returned to caller (no caller visible)"}}
	if t.cg == nil {
		return stop
	}
	fn := ret.Parent()
	node := t.cg.Nodes[fn]
	if node == nil || len(node.In) == 0 {
		return stop
	}
	if len(node.In) > maxFanIn {
		return []egressFact{{what: fmt.Sprintf("returned to %d callers (fan-in cap %d)", len(node.In), maxFanIn)}}
	}
	idx := -1
	for i, res := range ret.Results {
		if res == v {
			idx = i
			break
		}
	}
	if idx < 0 {
		return stop
	}
	var facts []egressFact
	for _, edge := range node.In {
		call, ok := edge.Site.(*ssa.Call)
		if !ok {
			continue // go/defer discard results
		}
		if len(ret.Results) == 1 {
			facts = append(facts, t.egress(call, seen, depth+1)...)
			continue
		}
		// Tuple result: follow only the matching Extract.
		if refs := call.Referrers(); refs != nil {
			for _, r := range *refs {
				if ex, ok := r.(*ssa.Extract); ok && ex.Index == idx {
					facts = append(facts, t.egress(ex, seen, depth+1)...)
				}
			}
		}
	}
	if len(facts) == 0 {
		return []egressFact{{what: "returned to caller (result unused or untraceable there)"}}
	}
	return facts
}

// egressClosure follows a value captured by a closure into the closure body.
func (t *tracer) egressClosure(mc *ssa.MakeClosure, v ssa.Value, seen map[ssa.Value]bool, depth int) []egressFact {
	closureFn, ok := mc.Fn.(*ssa.Function)
	if !ok {
		return []egressFact{{what: "captured by closure (body not traceable)"}}
	}
	var facts []egressFact
	for i, b := range mc.Bindings {
		if b == v && i < len(closureFn.FreeVars) {
			facts = append(facts, t.egress(closureFn.FreeVars[i], seen, depth+1)...)
		}
	}
	if len(facts) == 0 {
		return []egressFact{{what: "captured by closure " + closureFn.Name() + " (no boundary seen inside)"}}
	}
	return facts
}

// egressStore follows a stored value to the loads of its destination —
// covers `block := &pem.Block{Bytes: der}; pem.Encode(w, block)`.
func (t *tracer) egressStore(st *ssa.Store, seen map[ssa.Value]bool, depth int) []egressFact {
	addr := st.Addr
	// Through field/index addressing to the underlying alloc.
	for {
		switch a := addr.(type) {
		case *ssa.FieldAddr:
			addr = a.X
			continue
		case *ssa.IndexAddr:
			addr = a.X
			continue
		}
		break
	}
	refs := addr.Referrers()
	if refs == nil {
		return nil
	}
	var facts []egressFact
	for _, instr := range *refs {
		switch x := instr.(type) {
		case *ssa.UnOp:
			if x.Op == token.MUL {
				facts = append(facts, t.egress(x, seen, depth+1)...)
			}
		case ssa.CallInstruction:
			// The pointer itself passed somewhere (pem.Encode(w, &block)).
			facts = append(facts, t.egressCall(x, addr, seen, depth)...)
		case *ssa.MakeClosure:
			// Heap-promoted local captured by a closure: follow the
			// pointer into the closure body.
			facts = append(facts, t.egressClosure(x, addr, seen, depth)...)
		}
	}
	return facts
}

// egressCall decides what passing v into this call means.
func (t *tracer) egressCall(call ssa.CallInstruction, v ssa.Value, seen map[ssa.Value]bool, depth int) []egressFact {
	cc := call.Common()
	argIdx := -1
	for i, a := range cc.Args {
		if a == v {
			argIdx = i
			break
		}
	}
	if argIdx < 0 && cc.Value != v {
		return nil
	}

	// Dynamic (interface) calls: writes to net.Conn / io.Writer / sql.
	if cc.IsInvoke() {
		recv := cc.Value.Type().String()
		switch cc.Method.Name() {
		case "Write", "WriteString":
			if strings.Contains(recv, "net.Conn") {
				return []egressFact{{what: "network write (net.Conn)", lifetime: "in-transit"}}
			}
			return []egressFact{{what: "write to " + recv + " (destination unresolved)"}}
		case "Exec", "ExecContext", "Query", "QueryContext":
			return []egressFact{{what: "database write (" + recv + ")", lifetime: "persistent"}}
		}
		return []egressFact{{what: "passed to interface method " + recv + "." + cc.Method.Name()}}
	}

	callee := cc.StaticCallee()
	if callee == nil {
		if b, ok := cc.Value.(*ssa.Builtin); ok {
			switch b.Name() {
			case "append", "copy":
				return t.throughTransform(call, b.Name(), seen, depth)
			default: // len, cap, print, ... — not a boundary
				return nil
			}
		}
		return []egressFact{{what: "passed to dynamic call (destination unresolved)"}}
	}
	pkg := ""
	if callee.Pkg != nil {
		pkg = callee.Pkg.Pkg.Path()
	} else if callee.Object() != nil && callee.Object().Pkg() != nil {
		pkg = callee.Object().Pkg().Path()
	}
	sym := pkg + "." + callee.Name()

	// Method callees carry their receiver in the signature.
	if recv := callee.Signature.Recv(); recv != nil {
		recvType := recv.Type().String()
		switch {
		case strings.HasPrefix(recvType, "*os.File") && (callee.Name() == "Write" || callee.Name() == "WriteString"):
			return []egressFact{{what: "file write (*os.File)", lifetime: "persistent"}}
		case strings.Contains(recvType, "sql.DB") || strings.Contains(recvType, "sql.Tx") || strings.Contains(recvType, "sql.Stmt"):
			return []egressFact{{what: "database write (" + recvType + ")", lifetime: "persistent"}}
		case strings.HasPrefix(recvType, "*encoding/base64.Encoding") || strings.HasPrefix(recvType, "*base64.Encoding"):
			return t.throughTransform(call, "base64-encoded", seen, depth)
		case strings.HasPrefix(recvType, "*bufio.Writer"):
			return []egressFact{{what: "write to *bufio.Writer (underlying destination unresolved)"}}
		}
	}

	switch sym {
	case "os.WriteFile":
		return []egressFact{{what: "file write (os.WriteFile)", lifetime: "persistent"}}
	case "encoding/pem.Encode":
		return []egressFact{{what: "pem.Encode to io.Writer (destination unresolved)"}}
	case "fmt.Fprintf", "fmt.Fprint", "fmt.Fprintln":
		return []egressFact{{what: "fmt.Fprint* to io.Writer (destination unresolved)"}}
	}
	if label, ok := transforms[sym]; ok {
		return t.throughTransform(call, label, seen, depth)
	}
	switch {
	case strings.HasPrefix(pkg, "net/http"):
		return []egressFact{{what: "HTTP egress (" + sym + ")", lifetime: "in-transit"}}
	case pkg == "net" || strings.HasPrefix(pkg, "net/"):
		return []egressFact{{what: "network egress (" + sym + ")", lifetime: "in-transit"}}
	case t.inModule[callee] && argIdx >= 0 && argIdx < len(callee.Params):
		// Follow the argument into the in-module callee.
		if inner := t.egress(callee.Params[argIdx], seen, depth+1); len(inner) > 0 {
			return inner
		}
		return []egressFact{{what: "passed into " + sym + " (no boundary seen inside)"}}
	case pkg != "" && isStdlib(pkg):
		return nil // stdlib plumbing (errors, bytes.Equal, copy helpers) — not a boundary
	default:
		return []egressFact{{what: fmt.Sprintf("escapes to %s (outside analyzed module)", sym)}}
	}
}

// throughTransform keeps following a re-encoded value from the call result.
func (t *tracer) throughTransform(call ssa.CallInstruction, label string, seen map[ssa.Value]bool, depth int) []egressFact {
	var facts []egressFact
	if res, ok := call.(*ssa.Call); ok {
		facts = append(facts, t.egress(res, seen, depth+1)...)
	}
	if len(facts) == 0 {
		return []egressFact{{what: label + " (destination unresolved)"}}
	}
	for i := range facts {
		facts[i].what = label + " → " + facts[i].what
	}
	return facts
}

func isStdlib(pkg string) bool {
	if pkg == "" {
		return false
	}
	root, _, _ := strings.Cut(pkg, "/")
	return !strings.Contains(root, ".")
}
