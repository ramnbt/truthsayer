// TLS-CONF verdict refinement (I59/I60), encoding the decred/vspd#536 review
// lessons from jrick and davecgh:
//   - on go>=1.24 the defaults already negotiate hybrid KEX and auto-upgrade
//     with the toolchain, so an explicit CurvePreferences pin should be
//     REMOVED, never extended — pins freeze PQ posture;
//   - pin removal (or riding defaults) requires MinVersion TLS 1.3: TLS<=1.2
//     has no PQ key exchange, so a lower floor is a silent classical
//     downgrade path;
//   - under a TLS 1.3 floor an explicit CipherSuites list is dead config.
package classify

import (
	"strconv"
	"strings"

	"github.com/ramnbt/truthsayer/internal/ir"
)

// refineTLSConf rewrites verdict/target for tls.Config literal sites using
// field-level facts. Must run before setPriority (it may clear
// QuantumVulnerable, which demotes priority).
func refineTLSConf(inv *ir.Inventory, s *ir.CallSite) {
	tc := s.TLSConf
	if s.Primitive.Family != ir.FamilyTLSConfig || tc == nil {
		return
	}

	ge124, known := goAtLeast(inv, s.Site.File, 1, 24)
	floorClause := ""
	if tc.MinVersion != "TLS13" {
		floorClause = " and set MinVersion tls.VersionTLS13 (TLS<=1.2 has no PQ KEX)"
	}
	cipherClause := ""
	if tc.HasCipherSuites {
		cipherClause = "; remove CipherSuites (dead config under TLS 1.3)"
	}

	switch {
	case !known:
		s.Verdict = ir.VerdictAutoReview
		s.Primitive.MigrationTarget = "confirm go>=1.24, then ride default hybrid KEX: remove any CurvePreferences pin" + floorClause + cipherClause
		s.VerdictWhy = "module go version unknown — toolchain gate unverified"
	case !ge124:
		s.Verdict = ir.VerdictAutoReview
		s.Primitive.MigrationTarget = "upgrade module to go>=1.24 (hybrid KEX in defaults), then remove any CurvePreferences pin" + floorClause + cipherClause
		s.VerdictWhy = "go<1.24: X25519MLKEM768 unavailable — toolchain upgrade first"
	case tc.HasCurvePrefs && !tc.PrefsLiteral:
		s.Verdict = ir.VerdictAutoReview
		s.Primitive.MigrationTarget = "CurvePreferences set from non-literal value — resolve, then remove pin" + floorClause + cipherClause
		s.VerdictWhy = "pin value not provable at site; resolver required"
	case tc.HasCurvePrefs && !tc.PrefsHybrid:
		s.Verdict = ir.VerdictAuto
		s.Primitive.MigrationTarget = "remove CurvePreferences (go>=1.24 defaults negotiate hybrid KEX and auto-upgrade)" + floorClause + cipherClause
		s.VerdictWhy = "explicit pin predates secure defaults and silently disables PQ KEX; removal preferred over extension"
	case tc.HasCurvePrefs && tc.PrefsHybrid:
		s.Verdict = ir.VerdictAutoReview
		s.Primitive.MigrationTarget = "pin includes a hybrid group but freezes future defaults — prefer removing CurvePreferences" + floorClause + cipherClause
		s.VerdictWhy = "works today; pin will not pick up new default groups"
	case tc.MinVersion == "TLS13":
		s.Verdict = ir.VerdictOK
		s.Primitive.QuantumVulnerable = false
		s.Primitive.MigrationTarget = "none — PQ-ready: hybrid KEX by default (go>=1.24) + TLS 1.3 floor" + cipherClause
		s.VerdictWhy = "riding maintained defaults"
	case tc.MinVersion == "nonliteral":
		s.Verdict = ir.VerdictAutoReview
		s.Primitive.MigrationTarget = "verify MinVersion >= TLS 1.3 — hybrid KEX is default on go>=1.24, but a TLS<=1.2 floor is a silent classical downgrade path" + cipherClause
		s.VerdictWhy = "MinVersion non-literal; floor not provable at site"
	default: // no pin, floor unset or < TLS 1.3
		s.Verdict = ir.VerdictAuto
		s.Primitive.MigrationTarget = "set MinVersion tls.VersionTLS13 — hybrid KEX already default on go>=1.24, but TLS<=1.2 fallback has no PQ KEX" + cipherClause
		s.VerdictWhy = "presence of PQ defaults != absence of classical downgrade path"
	}
}

// goAtLeast reports whether the go directive governing file (longest-prefix
// go.mod match) is at least major.minor, and whether any directive was found.
func goAtLeast(inv *ir.Inventory, file string, major, minor int) (ok, known bool) {
	best, bestLen := "", -1
	for _, m := range inv.GoMods {
		switch {
		case m.Dir == ".":
			if bestLen < 0 {
				best, bestLen = m.Version, 0
			}
		case strings.HasPrefix(file, m.Dir+"/") && len(m.Dir) > bestLen:
			best, bestLen = m.Version, len(m.Dir)
		}
	}
	if best == "" {
		return false, false
	}
	parts := strings.SplitN(best, ".", 3)
	if len(parts) < 2 {
		return false, false
	}
	maj, err1 := strconv.Atoi(parts[0])
	min, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return false, false
	}
	return maj > major || (maj == major && min >= minor), true
}
