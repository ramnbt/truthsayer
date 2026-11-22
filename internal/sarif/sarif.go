// Package sarif exports an inventory as SARIF 2.1.0 for GitHub code scanning
// and similar consumers. Severity policy: broken-classical misuse and
// quantum-vulnerable primitives surface as warnings (they are migration work,
// not build-breakers); everything else is a note.
package sarif

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/ramnbt/truthsayer/internal/ir"
)

type log struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []run  `json:"runs"`
}

type run struct {
	Tool    toolWrap `json:"tool"`
	Results []result `json:"results"`
}

type toolWrap struct {
	Driver driver `json:"driver"`
}

type driver struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Rules   []rule `json:"rules"`
}

type rule struct {
	ID               string `json:"id"`
	ShortDescription text   `json:"shortDescription"`
	Help             *text  `json:"help,omitempty"`
}

type text struct {
	Text string `json:"text"`
}

type result struct {
	RuleID    string     `json:"ruleId"`
	Level     string     `json:"level"`
	Message   text       `json:"message"`
	Locations []location `json:"locations"`
}

type location struct {
	PhysicalLocation physicalLocation `json:"physicalLocation"`
}

type physicalLocation struct {
	ArtifactLocation artifactLocation `json:"artifactLocation"`
	Region           region           `json:"region"`
}

type artifactLocation struct {
	URI string `json:"uri"`
}

type region struct {
	StartLine int `json:"startLine"`
}

// Export renders the inventory as SARIF 2.1.0 JSON.
func Export(inv *ir.Inventory) ([]byte, error) {
	rulesSeen := map[string]rule{}
	results := make([]result, 0, len(inv.Sites))

	for _, s := range inv.Sites {
		id := ruleID(s)
		if _, ok := rulesSeen[id]; !ok {
			help := s.Primitive.MigrationTarget
			r := rule{ID: id, ShortDescription: text{Text: s.Primitive.Algorithm + " (" + string(s.Primitive.Family) + ")"}}
			if help != "" {
				r.Help = &text{Text: "Migration target: " + help}
			}
			rulesSeen[id] = r
		}

		msg := fmt.Sprintf("%s [%s, verdict %s, priority %s]", s.Primitive.Symbol, s.Primitive.Algorithm, s.Verdict, s.Priority)
		if s.Primitive.MigrationTarget != "" {
			msg += " — migrate to: " + s.Primitive.MigrationTarget
		}
		results = append(results, result{
			RuleID:  id,
			Level:   levelFor(s),
			Message: text{Text: msg},
			Locations: []location{{PhysicalLocation: physicalLocation{
				ArtifactLocation: artifactLocation{URI: s.Site.File},
				Region:           region{StartLine: s.Site.Line},
			}}},
		})
	}

	ruleList := make([]rule, 0, len(rulesSeen))
	for _, r := range rulesSeen {
		ruleList = append(ruleList, r)
	}
	sort.Slice(ruleList, func(i, j int) bool { return ruleList[i].ID < ruleList[j].ID })

	l := log{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []run{{
			Tool:    toolWrap{Driver: driver{Name: inv.Tool, Version: inv.Version, Rules: ruleList}},
			Results: results,
		}},
	}
	return json.MarshalIndent(l, "", "  ")
}

func ruleID(s ir.CallSite) string {
	slug := strings.ToLower(strings.NewReplacer(" ", "-", "/", "-", "(", "", ")", "", "#", "").Replace(s.Primitive.Algorithm))
	return "truthsayer/" + strings.ToLower(string(s.Primitive.Family)) + "/" + slug
}

func levelFor(s ir.CallSite) string {
	if s.Site.InTest {
		return "note"
	}
	if s.Primitive.Misuse || s.Primitive.QuantumVulnerable {
		return "warning"
	}
	return "note"
}
