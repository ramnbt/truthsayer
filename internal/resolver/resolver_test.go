package resolver

import (
	"strings"
	"sync"
	"testing"

	"github.com/ramnbt/truthsayer/internal/classify"
	"github.com/ramnbt/truthsayer/internal/ir"
	"github.com/ramnbt/truthsayer/internal/scanner"
)

var (
	enrichOnce sync.Once
	enrichInv  *ir.Inventory
	enrichErr  error
)

// scanAndEnrich runs the real scanner then the resolver over the fixture
// module — the exact production pipeline. Computed once: whole-program SSA
// analysis is expensive and the tests only read the result.
func scanAndEnrich(t *testing.T) *ir.Inventory {
	t.Helper()
	enrichOnce.Do(func() {
		inv, err := scanner.Scan("testdata/resolvemod")
		if err != nil {
			enrichErr = err
			return
		}
		for _, n := range Enrich("testdata/resolvemod", inv) {
			t.Log(n)
		}
		// Production pipeline re-classifies after enrichment (cmd/truthsayer).
		classify.Apply(inv)
		scanner.FinalizeStats(inv)
		enrichInv = inv
	})
	if enrichErr != nil {
		t.Fatal(enrichErr)
	}
	return enrichInv
}

// siteIn finds the unique site for symbol within function fn.
func siteIn(t *testing.T, inv *ir.Inventory, symbol, fn string) *ir.CallSite {
	t.Helper()
	for i := range inv.Sites {
		s := &inv.Sites[i]
		if s.Primitive.Symbol == symbol && s.Site.Function == fn {
			return s
		}
	}
	t.Fatalf("no site %s in func %s", symbol, fn)
	return nil
}

func hasEvidence(s *ir.CallSite, substr string) bool {
	for _, e := range s.Evidence {
		if strings.Contains(e, substr) {
			return true
		}
	}
	return false
}

func TestResolveKeySizes(t *testing.T) {
	inv := scanAndEnrich(t)

	cases := []struct {
		fn      string
		res     ir.Resolution
		alg     string // expected algorithm after enrichment ("" = don't check)
		evidice string
	}{
		{"litBits", ir.ResolutionLiteral, "RSA-1024", "keysize=1024"},
		{"namedConstBits", ir.ResolutionDerived, "RSA-2048", "keysize=2048"},
		{"varBits", ir.ResolutionDerived, "RSA-3072", "keysize=3072"},
		{"envBits", ir.ResolutionConfig, "", "environment variable"},
		// Interprocedural: the only caller passes 4096.
		{"paramBits", ir.ResolutionDerived, "RSA-4096", "keysize=4096"},
		// Interprocedural: callee return value traced.
		{"bitsViaHelper", ir.ResolutionDerived, "RSA-2048", "keysize=2048"},
		// No caller exists — must stay honestly unresolved.
		{"UncalledGen", ir.ResolutionUnresolved, "", "parameter"},
	}
	for _, c := range cases {
		s := siteIn(t, inv, "crypto/rsa.GenerateKey", c.fn)
		if s.Resolution != c.res {
			t.Errorf("%s: resolution %s, want %s (evidence: %v)", c.fn, s.Resolution, c.res, s.Evidence)
		}
		if c.alg != "" && s.Primitive.Algorithm != c.alg {
			t.Errorf("%s: algorithm %q, want %q", c.fn, s.Primitive.Algorithm, c.alg)
		}
		if !hasEvidence(s, c.evidice) {
			t.Errorf("%s: evidence %v missing %q", c.fn, s.Evidence, c.evidice)
		}
	}
}

func TestResolveCurve(t *testing.T) {
	inv := scanAndEnrich(t)
	s := siteIn(t, inv, "crypto/ecdsa.GenerateKey", "curveLit")
	if s.Resolution != ir.ResolutionLiteral || s.Primitive.Algorithm != "ECDSA-P256" {
		t.Errorf("curveLit: %s / %s, want LITERAL / ECDSA-P256 (%v)", s.Resolution, s.Primitive.Algorithm, s.Evidence)
	}
}

func TestResolveKeyProvenance(t *testing.T) {
	inv := scanAndEnrich(t)
	gen := siteIn(t, inv, "crypto/rsa.SignPKCS1v15", "signGenerated")
	if gen.KeyProv != ir.KeyGenerated {
		t.Errorf("signGenerated: provenance %s, want GENERATED (%v)", gen.KeyProv, gen.Evidence)
	}
	loaded := siteIn(t, inv, "crypto/rsa.SignPKCS1v15", "signLoaded")
	if loaded.KeyProv != ir.KeyLoaded {
		t.Errorf("signLoaded: provenance %s, want LOADED (%v)", loaded.KeyProv, loaded.Evidence)
	}
}

func TestResolveTLSConfig(t *testing.T) {
	inv := scanAndEnrich(t)
	noPQC := siteIn(t, inv, "crypto/tls.Config", "tlsExplicitNoPQC")
	if noPQC.Resolution != ir.ResolutionLiteral || !hasEvidence(noPQC, "X25519MLKEM768 ABSENT") {
		t.Errorf("tlsExplicitNoPQC: %s %v", noPQC.Resolution, noPQC.Evidence)
	}
	defaults := siteIn(t, inv, "crypto/tls.Config", "tlsDefaults")
	if defaults.Resolution != ir.ResolutionLiteral || !hasEvidence(defaults, "defaults negotiate") {
		t.Errorf("tlsDefaults: %s %v", defaults.Resolution, defaults.Evidence)
	}
}

func hasEgress(s *ir.CallSite, substr string) bool {
	for _, e := range s.Egress {
		if strings.Contains(e, substr) {
			return true
		}
	}
	return false
}

func TestEgressKeyToDisk(t *testing.T) {
	inv := scanAndEnrich(t)
	s := siteIn(t, inv, "crypto/rsa.GenerateKey", "keyToDisk")
	if s.Lifetime != "persistent" {
		t.Errorf("keyToDisk: lifetime %q, want persistent (egress: %v)", s.Lifetime, s.Egress)
	}
	if !hasEgress(s, "os.WriteFile") {
		t.Errorf("keyToDisk: egress %v missing file write", s.Egress)
	}
	if s.Priority != "P0-HNDL" {
		t.Errorf("keyToDisk: priority %q, want P0-HNDL (persistent quantum-vulnerable material)", s.Priority)
	}
}

func TestEgressCiphertextToNet(t *testing.T) {
	inv := scanAndEnrich(t)
	s := siteIn(t, inv, "crypto/rsa.EncryptPKCS1v15", "ciphertextToNet")
	if s.Lifetime != "in-transit" {
		t.Errorf("ciphertextToNet: lifetime %q, want in-transit (egress: %v)", s.Lifetime, s.Egress)
	}
	if !hasEgress(s, "net.Conn") {
		t.Errorf("ciphertextToNet: egress %v missing network write", s.Egress)
	}
}

func TestEgressNoneObserved(t *testing.T) {
	inv := scanAndEnrich(t)
	s := siteIn(t, inv, "crypto/rsa.SignPKCS1v15", "signatureLocal")
	if s.Lifetime == "persistent" || s.Lifetime == "in-transit" {
		t.Errorf("signatureLocal: lifetime %q, want no proven boundary (egress: %v)", s.Lifetime, s.Egress)
	}
	if !hasEgress(s, "no egress observed") {
		t.Errorf("signatureLocal: egress %v missing honest no-egress note", s.Egress)
	}
}

func TestEgressInterprocedural(t *testing.T) {
	inv := scanAndEnrich(t)

	// Ciphertext returned by a helper, persisted by the caller.
	ct := siteIn(t, inv, "crypto/rsa.EncryptOAEP", "makeCiphertext")
	if ct.Lifetime != "persistent" || ct.Priority != "P0-HNDL" {
		t.Errorf("makeCiphertext: lifetime %q priority %q, want persistent/P0-HNDL (egress: %v)", ct.Lifetime, ct.Priority, ct.Egress)
	}

	// Key marshaled, base64-encoded via stdlib method, then written.
	b64 := siteIn(t, inv, "crypto/rsa.GenerateKey", "b64KeyToDisk")
	if b64.Lifetime != "persistent" {
		t.Errorf("b64KeyToDisk: lifetime %q, want persistent (egress: %v)", b64.Lifetime, b64.Egress)
	}

	// Key written inside a closure that captures it.
	cl := siteIn(t, inv, "crypto/rsa.GenerateKey", "closureKeyToDisk")
	if cl.Lifetime != "persistent" {
		t.Errorf("closureKeyToDisk: lifetime %q, want persistent (egress: %v)", cl.Lifetime, cl.Egress)
	}
}

func TestKeyClustering(t *testing.T) {
	inv := scanAndEnrich(t)
	gen := siteIn(t, inv, "crypto/rsa.GenerateKey", "sharedKeyLifecycle")
	sign := siteIn(t, inv, "crypto/rsa.SignPKCS1v15", "sharedKeyLifecycle")
	marshal := siteIn(t, inv, "crypto/x509.MarshalPKCS1PrivateKey", "sharedKeyLifecycle")
	if gen.Cluster == "" || gen.Cluster != sign.Cluster || sign.Cluster != marshal.Cluster {
		t.Errorf("shared lifecycle not clustered: gen=%q sign=%q marshal=%q", gen.Cluster, sign.Cluster, marshal.Cluster)
	}
	// A different key's lifecycle must be a different cluster.
	other := siteIn(t, inv, "crypto/rsa.SignPKCS1v15", "signGenerated")
	if other.Cluster == "" || other.Cluster == gen.Cluster {
		t.Errorf("distinct lifecycles share cluster: %q vs %q", other.Cluster, gen.Cluster)
	}
	if inv.Stats.KeyClusters < 2 {
		t.Errorf("KeyClusters=%d, want ≥2", inv.Stats.KeyClusters)
	}
}

func TestCurvePreferenceFlows(t *testing.T) {
	flows, notes := CurvePreferenceFlows("testdata/resolvemod")
	for _, n := range notes {
		t.Log(n)
	}
	var hit *PrefLiteral
	for i := range flows {
		if flows[i].File == "main.go" {
			// defaultPrefs literal line.
			hit = &flows[i]
		}
	}
	if hit == nil {
		t.Fatalf("defaultPrefs flow not found: %+v", flows)
	}
	if len(hit.Sites) == 0 {
		t.Fatalf("flow has no CurvePreferences sites: %+v", hit)
	}
}

func TestEnrichSurvivesBrokenTarget(t *testing.T) {
	inv := &ir.Inventory{}
	notes := Enrich(t.TempDir(), inv)
	if len(notes) == 0 {
		t.Fatal("want a skip note for non-module target")
	}
}
