// Package classify is the verdict/priority engine v0: a rule-based pass over
// scanned sites that refines verdicts and assigns HNDL-aware migration
// priority. Dataflow-backed classification (key provenance, egress) lands in
// M3; v0 uses only facts the scanner already established.
package classify

import (
	"regexp"

	"github.com/ramnbt/truthsayer/internal/ir"
)

var intArg = regexp.MustCompile(`^\d{3,5}$`)

// Apply mutates sites in place. It must run before stats are finalized.
func Apply(inv *ir.Inventory) {
	for i := range inv.Sites {
		s := &inv.Sites[i]
		enrichAlgorithm(s)
		refineTLSConf(inv, s) // before setPriority: may clear QuantumVulnerable
		setLifetime(s)
		setPriority(s)

		// Generated code must not be edited directly; the rewrite target is
		// the generator (or its template), which v0 cannot locate.
		if s.Site.Generated {
			s.Verdict = ir.VerdictBlocked
			s.VerdictWhy = "generated file — rewrite the generator, not the output"
		}
	}
}

// enrichAlgorithm folds captured args into the algorithm name where the
// parameter changes migration urgency (RSA-1024 vs RSA-4096).
func enrichAlgorithm(s *ir.CallSite) {
	if s.Primitive.Algorithm != "RSA" {
		return
	}
	for _, a := range s.Args {
		if intArg.MatchString(a) {
			s.Primitive.Algorithm = "RSA-" + a
			return
		}
	}
}

// setLifetime guesses data lifetime from family. v0 heuristic only; the M3
// resolver replaces this with egress-based facts.
func setLifetime(s *ir.CallSite) {
	if s.Lifetime != "" {
		return
	}
	switch s.Primitive.Family {
	case ir.FamilyTLSConfig:
		s.Lifetime = "in-transit"
	case ir.FamilyKeyMgmt, ir.FamilyCert:
		s.Lifetime = "persistent"
	default:
		s.Lifetime = "unknown"
	}
}

// setPriority ranks urgency. Harvest-now-decrypt-later makes confidentiality
// (KEX/PKE) urgent today; signatures can't be retro-forged, so they rank
// below — except where persistent artifacts outlive the 2030/2035 deadlines.
func setPriority(s *ir.CallSite) {
	if s.Site.InTest {
		s.Priority = "P3"
		return
	}
	qv := s.Primitive.QuantumVulnerable
	switch {
	case qv && (s.Primitive.Family == ir.FamilyPKE || s.Primitive.Family == ir.FamilyKEX):
		if s.Lifetime == "persistent" {
			s.Priority = "P0-HNDL"
		} else {
			s.Priority = "P1"
		}
	case qv && s.Primitive.Family == ir.FamilyTLSConfig:
		s.Priority = "P1" // in-transit confidentiality is harvestable now
	case s.Primitive.Misuse:
		s.Priority = "P1" // broken today, not just quantum-later
	case qv && s.Primitive.Family == ir.FamilySignature:
		s.Priority = "P2"
	case qv:
		s.Priority = "P2"
	default:
		s.Priority = "P3"
	}
}
