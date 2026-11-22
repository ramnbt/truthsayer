# truthsayer

Find and classify quantum-vulnerable cryptography in Go codebases — with a
recall guarantee instead of a vibe.

A Truthsayer, in Dune, is one who can detect truth from falsehood. This one
reads your crypto posture: every call site found, classified, and prioritized,
exported as CycloneDX 1.6 CBOM and SARIF, with anything the scanner could not
resolve **surfaced and counted, never silently dropped**.

```console
$ truthsayer scan ./myrepo

truthsayer v0.1.0 — ./myrepo
files scanned: 68 (skipped: 0) · sites: 19 (prod 13 / test 6) · quantum-vulnerable: 18 · UNRESOLVED: 0

LOCATION             ALGORITHM    FAMILY    PRIO  VERDICT  MIGRATION TARGET
rpc/client.go:47     TLS config   TLS-CONF  P3    OK       none — PQ-ready: hybrid KEX by default (go>=1.24) + TLS 1.3 floor
database/db.go:119   Ed25519      SIG       P2    AUTO-REVIEW  ML-DSA-65 (dual-sign option)
cmd/tool/x.go:32     TLS config   TLS-CONF  P1    AUTO     set MinVersion tls.VersionTLS13 — hybrid KEX already default on go>=1.24, but TLS<=1.2 fallback has no PQ KEX
...
```

## Why now

Traffic recorded today is decrypted when a cryptographically relevant quantum
computer arrives ("harvest now, decrypt later"). The compliance clocks are
already running: CNSA 2.0 reaches new US national-security acquisitions in
2027; NIST IR 8547 deprecates RSA/ECC in 2030 and disallows them in 2035.

## Quick start

```console
go install github.com/ramnbt/truthsayer/cmd/truthsayer@latest

# inventory: every crypto call site, classified and prioritized
truthsayer scan ./myrepo --json inventory.json --cbom cbom.json --sarif scan.sarif

# deep mode: go/ssa dataflow facts (key sizes, key provenance, egress, lifecycle clusters)
truthsayer scan ./myrepo --resolve
```

## What it does

**Find** — AST scan of every crypto call site (stdlib + `x/crypto`), go.mod
dependency scan, generated/test flagging. Measured recall: **100% on a 10-repo
OSS corpus** (vault, caddy, etcd, grpc-go, …; 4,762 sites) against an
import-level oracle — the eval harness ships in this repo (`cmd/evalrecall`),
so you can check the claim instead of trusting it.

**Classify** — verdicts (OK / AUTO / AUTO-REVIEW / MANUAL / BLOCKED) and
harvest-now-decrypt-later priority (P0-HNDL → P3). TLS configs get
field-level analysis informed by real maintainer review (decred/vspd#536):
on go ≥ 1.24 an explicit `CurvePreferences` pin should be **removed**, not
extended; riding defaults requires a TLS 1.3 floor (TLS ≤ 1.2 has no
post-quantum key exchange); dead TLS 1.2 cipher lists are flagged; configs
already riding defaults with a 1.3 floor read **OK — PQ-ready**. With
`--resolve`, go/ssa dataflow replaces heuristics: proven key sizes and
curves, key provenance, egress boundaries, key-lifecycle clusters — and the
resolver says UNRESOLVED rather than guess.

## Design rules

1. Nothing is silently skipped — unparseable files and unresolved sites are
   counted and listed. False positives are triage cost; false negatives are
   failure.
2. The scanner is recall-maximalist and its recall is measured, not asserted.
3. Stdlib-first: the scan path has one external dependency class
   (`golang.org/x/tools`, for the optional `--resolve` SSA mode).

## Limits — read this

- Source-level scan: cgo, assembly, and vendored binaries are not inventoried.
- Config-driven TLS (values flowing from config files at runtime) is surfaced
  as CONFIG/UNRESOLVED, not guessed at.
- **A clean scan is an inventory, not a security proof.** Findings and
  verdicts describe code posture against known rules; they do not prove the
  absence of vulnerable cryptography beyond the scanner's catalog, and they
  are not a compliance determination. The rule set grows through expert
  review and is versioned in this repo.

## The verified-rewrite layer (commercial)

This scanner is the free, open core. The migration layer on top of it —
deterministic rewrite templates, enforced verification gates (NIST ACVP +
Wycheproof vectors run in your build, live OpenSSL interop, diff-isolation
proof), machine-checked evidence bundles attached to PRs, a CI gate that
fails builds on crypto-posture regression, and signed attestations — is a
commercial product built on the same inventory format. Verified PRs produced
by it have been merged by real OSS projects (first:
[ibnaleem/gosearch#137](https://github.com/ibnaleem/gosearch/pull/137);
review history: [decred/vspd#536](https://github.com/decred/vspd/pull/536),
[haproxytech/dataplaneapi#421](https://github.com/haproxytech/dataplaneapi/pull/421)).
Contact: ramvakk@gmail.com.

Evidence bundles attest that **enumerated functional gates passed** — they
are explicitly not a formal proof of security preservation, and the claim
language is scoped accordingly (see the soundness notes; reviewed critique
welcome).

## License

Apache-2.0. The commercial layer is separate and separately licensed.
