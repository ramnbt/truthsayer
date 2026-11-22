package cbom

import (
	"encoding/json"
	"testing"

	"github.com/ramnbt/truthsayer/internal/scanner"
)

func TestExport(t *testing.T) {
	inv, err := scanner.Scan("../scanner/testdata/vulnapp")
	if err != nil {
		t.Fatal(err)
	}
	b, err := Export(inv)
	if err != nil {
		t.Fatal(err)
	}

	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if doc["bomFormat"] != "CycloneDX" || doc["specVersion"] != "1.6" {
		t.Errorf("bad header: %v %v", doc["bomFormat"], doc["specVersion"])
	}
	comps := doc["components"].([]any)
	if len(comps) == 0 {
		t.Fatal("no components")
	}
	// RSA key size must have been enriched by the classifier (RSA-2048).
	var sawRSA2048 bool
	for _, c := range comps {
		m := c.(map[string]any)
		if m["type"] != "cryptographic-asset" {
			t.Errorf("component type = %v", m["type"])
		}
		if m["name"] == "RSA-2048" {
			sawRSA2048 = true
			props := m["cryptoProperties"].(map[string]any)
			ap := props["algorithmProperties"].(map[string]any)
			if ap["nistQuantumSecurityLevel"].(float64) != 0 {
				t.Error("RSA-2048 quantum security level should be 0")
			}
		}
	}
	if !sawRSA2048 {
		t.Error("expected RSA-2048 component (classifier enrichment)")
	}
}
