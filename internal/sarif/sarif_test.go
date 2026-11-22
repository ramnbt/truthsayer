package sarif

import (
	"encoding/json"
	"strings"
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
	if doc["version"] != "2.1.0" {
		t.Errorf("version = %v", doc["version"])
	}
	runs := doc["runs"].([]any)
	r := runs[0].(map[string]any)
	results := r["results"].([]any)
	if len(results) != inv.Stats.TotalSites {
		t.Errorf("results = %d, want %d", len(results), inv.Stats.TotalSites)
	}
	first := results[0].(map[string]any)
	if !strings.HasPrefix(first["ruleId"].(string), "truthsayer/") {
		t.Errorf("ruleId = %v", first["ruleId"])
	}
	loc := first["locations"].([]any)[0].(map[string]any)
	pl := loc["physicalLocation"].(map[string]any)
	if pl["artifactLocation"].(map[string]any)["uri"] == "" {
		t.Error("empty artifact uri")
	}
}
