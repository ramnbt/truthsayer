// Package ir defines the rewrite-plan intermediate representation: the
// per-call-site record that carries everything a safe rewrite needs and
// that a CBOM cannot express. CBOM export is a lossy projection of this.
package ir

// Family classifies the cryptographic role of a sink.
type Family string

const (
	FamilyKEX       Family = "KEX"      // key exchange / agreement
	FamilySignature Family = "SIG"      // digital signature
	FamilyPKE       Family = "PKE"      // public-key encryption
	FamilySymmetric Family = "SYM"      // symmetric cipher
	FamilyHash      Family = "HASH"     // hash / MAC
	FamilyTLSConfig Family = "TLS-CONF" // TLS configuration surface
	FamilyCert      Family = "CERT"     // certificate / PKI handling
	FamilyKeyMgmt   Family = "KEY-MGMT" // key generation / parsing / storage
)

// Resolution says how confidently the algorithm at a site was determined.
type Resolution string

const (
	ResolutionLiteral    Resolution = "LITERAL"    // algorithm explicit at the call site
	ResolutionDerived    Resolution = "DERIVED"    // recovered via constant/dataflow analysis
	ResolutionConfig     Resolution = "CONFIG"     // flows from config/env; value not proven
	ResolutionUnresolved Resolution = "UNRESOLVED" // could not determine — must be surfaced, never dropped
)

// Verdict is the rewritability decision for a site.
type Verdict string

const (
	VerdictAuto       Verdict = "AUTO"
	VerdictAutoReview Verdict = "AUTO-REVIEW"
	VerdictManual     Verdict = "MANUAL"
	VerdictBlocked    Verdict = "BLOCKED"
	// VerdictOK marks a site whose posture is already post-quantum — listed
	// (recall-maximalist), but no action needed.
	VerdictOK Verdict = "OK"
)

// KeyProvenance says where the key material at a site comes from.
type KeyProvenance string

const (
	KeyGenerated KeyProvenance = "GENERATED" // created in-process (GenerateKey etc.)
	KeyLoaded    KeyProvenance = "LOADED"    // parsed from file/DB/keystore
	KeyHardcoded KeyProvenance = "HARDCODED" // literal in source — co-located misuse
	KeyExternal  KeyProvenance = "EXTERNAL"  // HSM/KMS/env — not source-rewritable
	KeyUnknown   KeyProvenance = "UNKNOWN"
)

// Site pins a finding to a location.
type Site struct {
	File      string `json:"file"`
	Line      int    `json:"line"`
	Package   string `json:"package"`
	Function  string `json:"function,omitempty"`
	InTest    bool   `json:"in_test,omitempty"`
	Generated bool   `json:"generated,omitempty"` // file carries a "Code generated" marker
}

// Primitive describes the crypto semantics found (CBOM-aligned).
type Primitive struct {
	Family            Family `json:"family"`
	Algorithm         string `json:"algorithm"` // e.g. "RSA", "ECDSA-P256", "Ed25519"
	Symbol            string `json:"symbol"`    // matched API symbol, e.g. "rsa.GenerateKey"
	QuantumVulnerable bool   `json:"quantum_vulnerable"`
	Misuse            bool   `json:"misuse,omitempty"` // broken-classical (MD5, DES, RC4...)
	MigrationTarget   string `json:"migration_target,omitempty"`
}

// TLSConf records field-level facts for a tls.Config composite literal, set
// by the scanner. The classifier needs these for go>=1.24-correct advice
// (I59/I60, decred/vspd#536 review): remove CurvePreferences pins rather than
// extend them, and require a TLS 1.3 floor (TLS<=1.2 has no PQ KEX).
type TLSConf struct {
	HasCurvePrefs   bool   `json:"has_curve_prefs"`
	PrefsLiteral    bool   `json:"prefs_literal,omitempty"` // pin is a []tls.CurveID composite literal
	PrefsHybrid     bool   `json:"prefs_hybrid,omitempty"`  // pin already lists an ML-KEM hybrid group
	MinVersion      string `json:"min_version,omitempty"`   // TLS10..TLS13, "nonliteral", or "" (unset)
	HasCipherSuites bool   `json:"has_cipher_suites,omitempty"`
}

// CallSite is one record of the rewrite-plan IR. Fields that later pipeline
// stages fill in (resolver, classifier) hold honest zero values until then —
// UNKNOWN/UNRESOLVED are first-class, never omitted-and-assumed.
type CallSite struct {
	ID         string        `json:"id"` // stable hash of site+symbol
	Site       Site          `json:"site"`
	Primitive  Primitive     `json:"primitive"`
	Args       []string      `json:"args,omitempty"` // rendered call arguments (truncated)
	Resolution Resolution    `json:"resolution"`
	Evidence   []string      `json:"evidence,omitempty"`  // def-use chain notes from resolver
	APIIdiom   string        `json:"api_idiom,omitempty"` // one-shot | streaming | config
	KeyProv    KeyProvenance `json:"key_provenance"`
	Egress     []string      `json:"egress,omitempty"`        // serialization/boundary points
	Peer       string        `json:"peer,omitempty"`          // internal | external | unknown
	Lifetime   string        `json:"data_lifetime,omitempty"` // ephemeral | persistent | unknown
	CoMisuses  []string      `json:"co_misuses,omitempty"`
	TLSConf    *TLSConf      `json:"tls_conf,omitempty"` // only on tls.Config literal sites
	Verdict    Verdict       `json:"verdict"`
	VerdictWhy string        `json:"verdict_why,omitempty"`
	// Cluster groups sites sharing one key lifecycle (dataflow-connected
	// through the same generated/loaded key object). Set by the resolver;
	// rewrites should land one PR per cluster.
	Cluster string `json:"cluster,omitempty"`
	// Priority ranks migration urgency (HNDL-aware):
	// P0-HNDL > P1 > P2 > P3. Set by the classifier.
	Priority string `json:"priority,omitempty"`
}

// GoMod records a module's go directive, keyed by the go.mod's directory
// relative to the scan root ("." for the root module). The classifier uses
// the longest-prefix match to decide which directive governs a site.
type GoMod struct {
	Dir     string `json:"dir"`
	Version string `json:"version"`
}

// DepFinding flags a dependency whose crypto posture matters, from manifest
// scanning (go.mod). Transitive source analysis of deps lands in M3.
type DepFinding struct {
	Module   string `json:"module"`
	Version  string `json:"version"`
	Manifest string `json:"manifest"` // which go.mod declared it
	Note     string `json:"note"`
	PQC      bool   `json:"pqc"` // module already provides PQC primitives
	Indirect bool   `json:"indirect,omitempty"`
}

// Inventory is the top-level scan output.
type Inventory struct {
	Tool        string       `json:"tool"`
	Version     string       `json:"version"`
	GeneratedAt string       `json:"generated_at"`
	Root        string       `json:"root"`
	Stats       Stats        `json:"stats"`
	Sites       []CallSite   `json:"sites"`
	GoMods      []GoMod      `json:"go_mods,omitempty"`
	Deps        []DepFinding `json:"deps,omitempty"`
	// SkippedFiles lists files the scanner could not parse — surfaced, not
	// silently dropped (hard rule #1).
	SkippedFiles []string `json:"skipped_files,omitempty"`
}

// Stats summarizes an inventory; UnresolvedRate is a product KPI.
type Stats struct {
	FilesScanned    int            `json:"files_scanned"`
	FilesSkipped    int            `json:"files_skipped"`
	TotalSites      int            `json:"total_sites"`
	ProdSites       int            `json:"prod_sites"`
	TestSites       int            `json:"test_sites"`
	GeneratedSites  int            `json:"generated_sites"`
	QuantumVuln     int            `json:"quantum_vulnerable"`
	MisuseSites     int            `json:"misuse_sites"`
	ByFamily        map[string]int `json:"by_family"`
	ByVerdict       map[string]int `json:"by_verdict"`
	ByPriority      map[string]int `json:"by_priority"`
	UnresolvedSites int            `json:"unresolved_sites"`
	KeyClusters     int            `json:"key_clusters,omitempty"`
}
