package scanner

import (
	"strings"
	"testing"

	"github.com/ramnbt/truthsayer/internal/ir"
)

func TestScanVulnApp(t *testing.T) {
	inv, err := Scan("testdata/vulnapp")
	if err != nil {
		t.Fatal(err)
	}
	if inv.Stats.FilesScanned != 1 {
		t.Fatalf("files scanned = %d, want 1", inv.Stats.FilesScanned)
	}

	// RSA-2048: the classifier enriches RSA with the captured key-size arg.
	wantAlgos := map[string]bool{
		"RSA-2048": false, "ECDSA": false, "EC curves": false, "TLS config": false, "MD5": false,
	}
	for _, s := range inv.Sites {
		if _, ok := wantAlgos[s.Primitive.Algorithm]; ok {
			wantAlgos[s.Primitive.Algorithm] = true
		}
	}
	for alg, found := range wantAlgos {
		if !found {
			t.Errorf("expected to find %s, did not", alg)
		}
	}

	if inv.Stats.QuantumVuln == 0 {
		t.Error("expected quantum-vulnerable sites")
	}
	if inv.Stats.MisuseSites == 0 {
		t.Error("expected misuse site (md5)")
	}
	for _, s := range inv.Sites {
		if s.Verdict == "" {
			t.Errorf("site %s has empty verdict", s.ID)
		}
		if s.Resolution == "" {
			t.Errorf("site %s has empty resolution", s.ID)
		}
	}
	// Dependency manifest scan: jwt (sig-relevant), x/crypto, circl (PQC, indirect).
	if len(inv.Deps) != 3 {
		t.Fatalf("deps = %d, want 3: %+v", len(inv.Deps), inv.Deps)
	}
	var sawPQC, sawIndirect, sawVersionedPath bool
	for _, d := range inv.Deps {
		if d.PQC {
			sawPQC = true
		}
		if d.Indirect {
			sawIndirect = true
		}
		if d.Module == "github.com/golang-jwt/jwt/v5" {
			sawVersionedPath = true
		}
	}
	if !sawPQC || !sawIndirect || !sawVersionedPath {
		t.Errorf("dep flags: pqc=%v indirect=%v versioned-path=%v", sawPQC, sawIndirect, sawVersionedPath)
	}

	// TLS-CONF verdicts (I59/I60, go>=1.24 module):
	//  - tlsSetup: pin w/o hybrid + TLS12 floor -> AUTO remove-pin + raise floor
	//  - tlsReady: no pin + TLS13 floor -> OK, not quantum-vulnerable
	//  - tlsNoFloor: no pin, no floor, CipherSuites -> AUTO set floor + dead-config note
	var removePin, pqReady, setFloor bool
	for _, s := range inv.Sites {
		if s.Primitive.Family != ir.FamilyTLSConfig {
			continue
		}
		switch s.Site.Function {
		case "tlsSetup":
			removePin = removePin || s.Verdict == ir.VerdictAuto &&
				strings.Contains(s.Primitive.MigrationTarget, "remove CurvePreferences") &&
				strings.Contains(s.Primitive.MigrationTarget, "VersionTLS13")
		case "tlsReady":
			pqReady = pqReady || (s.Verdict == ir.VerdictOK && !s.Primitive.QuantumVulnerable)
		case "tlsNoFloor":
			setFloor = setFloor || s.Verdict == ir.VerdictAuto &&
				strings.Contains(s.Primitive.MigrationTarget, "set MinVersion") &&
				strings.Contains(s.Primitive.MigrationTarget, "CipherSuites")
		}
	}
	if !removePin || !pqReady || !setFloor {
		t.Errorf("TLS-CONF verdicts: removePin=%v pqReady=%v setFloor=%v", removePin, pqReady, setFloor)
	}

	// go directive must be captured for the root module.
	var sawGoMod bool
	for _, m := range inv.GoMods {
		if m.Dir == "." && m.Version == "1.25" {
			sawGoMod = true
		}
	}
	if !sawGoMod {
		t.Errorf("expected root go.mod directive 1.25 captured, got %+v", inv.GoMods)
	}

	// Arg capture: rsa.GenerateKey(rand.Reader, 2048) must record "2048".
	var sawKeySize bool
	for _, s := range inv.Sites {
		for _, a := range s.Args {
			if a == "2048" {
				sawKeySize = true
			}
		}
	}
	if !sawKeySize {
		t.Error("expected captured arg 2048 on rsa.GenerateKey")
	}
}
