// Package cbom exports an inventory as a CycloneDX 1.6 CBOM (ECMA-424):
// one cryptographic-asset component per distinct algorithm, with file/line
// occurrences as evidence. The CBOM is a lossy projection of the IR —
// compliance tools consume this; the rewrite pipeline consumes the IR.
package cbom

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/ramnbt/truthsayer/internal/ir"
)

type bom struct {
	BOMFormat    string      `json:"bomFormat"`
	SpecVersion  string      `json:"specVersion"`
	SerialNumber string      `json:"serialNumber,omitempty"`
	Version      int         `json:"version"`
	Metadata     metadata    `json:"metadata"`
	Components   []component `json:"components"`
}

type metadata struct {
	Timestamp string `json:"timestamp,omitempty"`
	Tools     []tool `json:"tools"`
}

type tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type component struct {
	Type        string       `json:"type"`
	BOMRef      string       `json:"bom-ref"`
	Name        string       `json:"name"`
	Evidence    *evidence    `json:"evidence,omitempty"`
	CryptoProps *cryptoProps `json:"cryptoProperties,omitempty"`
}

type evidence struct {
	Occurrences []occurrence `json:"occurrences"`
}

type occurrence struct {
	Location string `json:"location"`
	Line     int    `json:"line,omitempty"`
}

type cryptoProps struct {
	AssetType      string     `json:"assetType"`
	AlgorithmProps *algoProps `json:"algorithmProperties,omitempty"`
	ProtocolProps  *protProps `json:"protocolProperties,omitempty"`
}

type algoProps struct {
	Primitive                string `json:"primitive,omitempty"`
	NISTQuantumSecurityLevel int    `json:"nistQuantumSecurityLevel"`
}

type protProps struct {
	Type string `json:"type"`
}

// Export renders the inventory as CycloneDX 1.6 JSON.
func Export(inv *ir.Inventory) ([]byte, error) {
	return export(inv, false)
}

// ExportStable renders the CBOM without the per-run serial number and
// timestamp: the same tree always produces the same bytes. This is the form
// for committed gate baselines (docs/V2-ATTEST.md) — a random serial would
// make every baseline refresh a spurious git diff. Both fields are optional
// in CycloneDX 1.6.
func ExportStable(inv *ir.Inventory) ([]byte, error) {
	return export(inv, true)
}

func export(inv *ir.Inventory, stable bool) ([]byte, error) {
	type agg struct {
		prim ir.Primitive
		occ  []occurrence
	}
	byAlgo := map[string]*agg{}
	for _, s := range inv.Sites {
		a, ok := byAlgo[s.Primitive.Algorithm]
		if !ok {
			a = &agg{prim: s.Primitive}
			byAlgo[s.Primitive.Algorithm] = a
		}
		a.occ = append(a.occ, occurrence{Location: s.Site.File, Line: s.Site.Line})
	}

	names := make([]string, 0, len(byAlgo))
	for n := range byAlgo {
		names = append(names, n)
	}
	sort.Strings(names)

	comps := make([]component, 0, len(names))
	for i, n := range names {
		a := byAlgo[n]
		comps = append(comps, component{
			Type:        "cryptographic-asset",
			BOMRef:      fmt.Sprintf("crypto-asset-%d", i+1),
			Name:        n,
			Evidence:    &evidence{Occurrences: a.occ},
			CryptoProps: propsFor(a.prim),
		})
	}

	b := bom{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.6",
		Version:     1,
		Metadata: metadata{
			Tools: []tool{{Name: inv.Tool, Version: inv.Version}},
		},
		Components: comps,
	}
	if !stable {
		b.SerialNumber = "urn:uuid:" + pseudoUUID()
		b.Metadata.Timestamp = inv.GeneratedAt
	}
	return json.MarshalIndent(b, "", "  ")
}

func propsFor(p ir.Primitive) *cryptoProps {
	switch p.Family {
	case ir.FamilyTLSConfig:
		return &cryptoProps{AssetType: "protocol", ProtocolProps: &protProps{Type: "tls"}}
	case ir.FamilyCert, ir.FamilyKeyMgmt:
		return &cryptoProps{AssetType: "related-crypto-material"}
	}
	return &cryptoProps{
		AssetType: "algorithm",
		AlgorithmProps: &algoProps{
			Primitive: primitiveFor(p),
			// Classical public-key and broken primitives provide no
			// post-quantum security: level 0.
			NISTQuantumSecurityLevel: 0,
		},
	}
}

func primitiveFor(p ir.Primitive) string {
	switch p.Family {
	case ir.FamilyKEX:
		return "key-agree"
	case ir.FamilySignature:
		return "signature"
	case ir.FamilyPKE:
		return "pke"
	case ir.FamilyHash:
		return "hash"
	case ir.FamilySymmetric:
		if p.Algorithm == "RC4" {
			return "stream-cipher"
		}
		return "block-cipher"
	}
	return "other"
}

func pseudoUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "00000000-0000-4000-8000-000000000000"
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
