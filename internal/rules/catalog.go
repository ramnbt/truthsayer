// Package rules holds the sink catalog: which import paths and symbols
// constitute crypto usage, with the metadata the classifier needs.
// v0 covers Go stdlib + golang.org/x/crypto; completeness target is M1.
package rules

import "github.com/ramnbt/truthsayer/internal/ir"

// Sink describes one API symbol (or whole package) to flag.
type Sink struct {
	ImportPath string // package that must be imported
	Symbol     string // exported name; "" matches any use of the package
	Primitive  ir.Primitive
	// VerdictHint is the classifier's starting point before resolver data.
	VerdictHint ir.Verdict
	VerdictWhy  string
}

// Catalog returns the v0 sink catalog. Order matters only for readability.
func Catalog() []Sink {
	qv := func(fam ir.Family, alg, target string) ir.Primitive {
		return ir.Primitive{Family: fam, Algorithm: alg, QuantumVulnerable: true, MigrationTarget: target}
	}
	misuse := func(fam ir.Family, alg, target string) ir.Primitive {
		return ir.Primitive{Family: fam, Algorithm: alg, Misuse: true, MigrationTarget: target}
	}

	return []Sink{
		// ---- quantum-vulnerable public-key: stdlib ----
		{ImportPath: "crypto/rsa", Symbol: "", Primitive: qv(ir.FamilyPKE, "RSA", "ML-KEM-768 hybrid (KEM) / ML-DSA-65 (sig)"), VerdictHint: ir.VerdictManual, VerdictWhy: "RSA role (encrypt vs sign) decides target; needs classification"},
		{ImportPath: "crypto/ecdsa", Symbol: "", Primitive: qv(ir.FamilySignature, "ECDSA", "ML-DSA-65 (consider dual-sign during migration)"), VerdictHint: ir.VerdictAutoReview, VerdictWhy: "signature swap is template-able once egress known"},
		{ImportPath: "crypto/ecdh", Symbol: "", Primitive: qv(ir.FamilyKEX, "ECDH", "X25519MLKEM768 hybrid"), VerdictHint: ir.VerdictAutoReview, VerdictWhy: "KEX→KEM reshapes both peers; cluster first"},
		{ImportPath: "crypto/elliptic", Symbol: "", Primitive: qv(ir.FamilyKeyMgmt, "EC curves", "ML-KEM/ML-DSA parameter sets"), VerdictHint: ir.VerdictManual, VerdictWhy: "curve plumbing; usually rides along a rsa/ecdsa finding"},
		{ImportPath: "crypto/ed25519", Symbol: "", Primitive: qv(ir.FamilySignature, "Ed25519", "ML-DSA-65 (dual-sign option)"), VerdictHint: ir.VerdictAutoReview, VerdictWhy: "one-shot sign/verify; good template case"},
		{ImportPath: "crypto/dsa", Symbol: "", Primitive: qv(ir.FamilySignature, "DSA", "ML-DSA-65"), VerdictHint: ir.VerdictAutoReview, VerdictWhy: "deprecated since go1.16; flag loudly"},

		// ---- quantum-vulnerable: x/crypto ----
		{ImportPath: "golang.org/x/crypto/curve25519", Symbol: "", Primitive: qv(ir.FamilyKEX, "X25519", "X25519MLKEM768 hybrid"), VerdictHint: ir.VerdictAutoReview, VerdictWhy: "raw DH; cluster peers before KEM reshape"},
		{ImportPath: "golang.org/x/crypto/nacl/box", Symbol: "", Primitive: qv(ir.FamilyPKE, "NaCl box (X25519)", "hybrid KEM envelope"), VerdictHint: ir.VerdictAutoReview, VerdictWhy: "sealed-box pattern maps well to KEM envelope"},
		{ImportPath: "golang.org/x/crypto/ssh", Symbol: "", Primitive: qv(ir.FamilyKEX, "SSH (classical KEX/hostkeys)", "sntrup761x25519 / mlkem768x25519 KEX"), VerdictHint: ir.VerdictManual, VerdictWhy: "protocol-level; config-driven"},
		{ImportPath: "golang.org/x/crypto/openpgp", Symbol: "", Primitive: qv(ir.FamilyPKE, "OpenPGP (classical)", "deprecated pkg; migrate off first"), VerdictHint: ir.VerdictManual, VerdictWhy: "package frozen/deprecated upstream"},

		// ---- TLS configuration surface ----
		{ImportPath: "crypto/tls", Symbol: "Config", Primitive: ir.Primitive{Family: ir.FamilyTLSConfig, Algorithm: "TLS config", QuantumVulnerable: true, MigrationTarget: "ride go>=1.24 hybrid KEX defaults: remove CurvePreferences pins, set MinVersion TLS1.3"}, VerdictHint: ir.VerdictAuto, VerdictWhy: "TLS config controls KEX posture; pins freeze it, TLS<=1.2 floor is a classical downgrade path"},
		{ImportPath: "crypto/tls", Symbol: "", Primitive: ir.Primitive{Family: ir.FamilyTLSConfig, Algorithm: "TLS usage", QuantumVulnerable: true, MigrationTarget: "verify hybrid KEX negotiated end-to-end (go>=1.24 default)"}, VerdictHint: ir.VerdictManual, VerdictWhy: "TLS API surface (certs, keypairs, dialers); Config sites get AUTO"},
		{ImportPath: "crypto/x509", Symbol: "", Primitive: ir.Primitive{Family: ir.FamilyCert, Algorithm: "X.509 handling", QuantumVulnerable: true, MigrationTarget: "cert chain inventory; ML-DSA certs when CA-ready"}, VerdictHint: ir.VerdictManual, VerdictWhy: "cert migration is ecosystem-gated"},

		// ---- key management / serialization (egress markers) ----
		{ImportPath: "encoding/pem", Symbol: "", Primitive: ir.Primitive{Family: ir.FamilyKeyMgmt, Algorithm: "PEM serialization"}, VerdictHint: ir.VerdictManual, VerdictWhy: "egress point: key/cert crosses a boundary here"},

		// ---- quantum-vulnerable: x/crypto continued ----
		{ImportPath: "golang.org/x/crypto/ed25519", Symbol: "", Primitive: qv(ir.FamilySignature, "Ed25519 (deprecated pkg)", "ML-DSA-65; also move to crypto/ed25519"), VerdictHint: ir.VerdictAutoReview, VerdictWhy: "deprecated alias of stdlib"},
		{ImportPath: "golang.org/x/crypto/nacl/sign", Symbol: "", Primitive: qv(ir.FamilySignature, "NaCl sign (Ed25519)", "ML-DSA-65 (dual-sign option)"), VerdictHint: ir.VerdictAutoReview, VerdictWhy: "one-shot sign/verify"},
		{ImportPath: "golang.org/x/crypto/pkcs12", Symbol: "", Primitive: qv(ir.FamilyKeyMgmt, "PKCS#12 (RSA/EC keystores)", "inventory keystore contents; PQ certs when CA-ready"), VerdictHint: ir.VerdictManual, VerdictWhy: "keystore egress point"},
		{ImportPath: "golang.org/x/crypto/ocsp", Symbol: "", Primitive: qv(ir.FamilyCert, "OCSP (classical sigs)", "ecosystem-gated"), VerdictHint: ir.VerdictManual, VerdictWhy: "PKI protocol surface"},

		// ---- broken-classical misuse (rides along; CNSA/NIST also retire these) ----
		{ImportPath: "crypto/md5", Symbol: "", Primitive: misuse(ir.FamilyHash, "MD5", "SHA-256/SHA-3"), VerdictHint: ir.VerdictAutoReview, VerdictWhy: "broken hash; verify no interop pin before swap"},
		{ImportPath: "crypto/sha1", Symbol: "", Primitive: misuse(ir.FamilyHash, "SHA-1", "SHA-256/SHA-3"), VerdictHint: ir.VerdictAutoReview, VerdictWhy: "broken for signatures; check usage context"},
		{ImportPath: "crypto/des", Symbol: "", Primitive: misuse(ir.FamilySymmetric, "DES/3DES", "AES-256-GCM"), VerdictHint: ir.VerdictAutoReview, VerdictWhy: "retired cipher"},
		{ImportPath: "crypto/rc4", Symbol: "", Primitive: misuse(ir.FamilySymmetric, "RC4", "AES-256-GCM / ChaCha20-Poly1305"), VerdictHint: ir.VerdictAutoReview, VerdictWhy: "broken stream cipher"},
		{ImportPath: "golang.org/x/crypto/md4", Symbol: "", Primitive: misuse(ir.FamilyHash, "MD4", "SHA-256/SHA-3"), VerdictHint: ir.VerdictAutoReview, VerdictWhy: "broken hash"},
		{ImportPath: "golang.org/x/crypto/ripemd160", Symbol: "", Primitive: misuse(ir.FamilyHash, "RIPEMD-160", "SHA-256/SHA-3"), VerdictHint: ir.VerdictAutoReview, VerdictWhy: "legacy hash (common in btc code — check context)"},
		{ImportPath: "golang.org/x/crypto/blowfish", Symbol: "", Primitive: misuse(ir.FamilySymmetric, "Blowfish", "AES-256-GCM"), VerdictHint: ir.VerdictAutoReview, VerdictWhy: "legacy cipher (bcrypt dep is fine; direct use is not)"},
		{ImportPath: "golang.org/x/crypto/cast5", Symbol: "", Primitive: misuse(ir.FamilySymmetric, "CAST5", "AES-256-GCM"), VerdictHint: ir.VerdictAutoReview, VerdictWhy: "legacy cipher"},
		{ImportPath: "golang.org/x/crypto/tea", Symbol: "", Primitive: misuse(ir.FamilySymmetric, "TEA", "AES-256-GCM"), VerdictHint: ir.VerdictAutoReview, VerdictWhy: "legacy cipher"},
		{ImportPath: "golang.org/x/crypto/xtea", Symbol: "", Primitive: misuse(ir.FamilySymmetric, "XTEA", "AES-256-GCM"), VerdictHint: ir.VerdictAutoReview, VerdictWhy: "legacy cipher"},
		{ImportPath: "golang.org/x/crypto/twofish", Symbol: "", Primitive: misuse(ir.FamilySymmetric, "Twofish", "AES-256-GCM"), VerdictHint: ir.VerdictAutoReview, VerdictWhy: "non-standard cipher"},
	}
}

// ModuleNote describes a dependency module with crypto relevance.
type ModuleNote struct {
	Note string
	PQC  bool // module already provides PQC primitives
}

// CryptoModules maps module paths (as they appear in go.mod) to notes.
// Matching is by exact path or path prefix (module path then "/...").
func CryptoModules() map[string]ModuleNote {
	return map[string]ModuleNote{
		"golang.org/x/crypto":                    {Note: "extended crypto lib — see source findings for specifics"},
		"github.com/cloudflare/circl":            {Note: "CIRCL: PQC (ML-KEM/ML-DSA) AND classical primitives — check which are used", PQC: true},
		"github.com/open-quantum-safe/liboqs-go": {Note: "liboqs bindings — PQC already in use", PQC: true},
		"filippo.io/age":                         {Note: "age file encryption: X25519 KEX (quantum-vulnerable at rest = HNDL exposure)"},
		"filippo.io/edwards25519":                {Note: "Ed25519 arithmetic (quantum-vulnerable signatures)"},
		"github.com/ProtonMail/go-crypto":        {Note: "OpenPGP fork — classical public-key throughout"},
		"go.dedis.ch/kyber":                      {Note: "DH-based protocol toolkit (classical despite the name)"},
		"github.com/golang-jwt/jwt":              {Note: "JWT: RSA/ECDSA signatures typical — token sig migration + size limits"},
		"github.com/lestrrat-go/jwx":             {Note: "JOSE/JWT: classical sig/enc algorithms typical"},
		"github.com/minio/sio":                   {Note: "encryption-at-rest streams (symmetric OK, check key wrap)"},
	}
}

// ByImportPath indexes the catalog for the scanner.
func ByImportPath() map[string][]Sink {
	m := make(map[string][]Sink)
	for _, s := range Catalog() {
		m[s.ImportPath] = append(m[s.ImportPath], s)
	}
	return m
}
