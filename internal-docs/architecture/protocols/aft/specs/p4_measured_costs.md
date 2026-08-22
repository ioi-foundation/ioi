# AFT-CB P4.3 — Measured Costs

Gate: every number reproduces within its stated variance on re-run. The
figures split into three reproduction classes, and each row says which
class it is — a number without a reproduction path is not in this table.

## Class A — exact, zero variance (structural wire costs)

Pinned by the test `measured_wire_costs_are_pinned`
(`crates/types/src/app/consensus/tests_parts/measured_wire_costs.rs`):
these are SCALE-encoded byte sizes of the canonical objects, so they
reproduce exactly and any wire-format change updates the pinned number in
review.

| Quantity | Bytes | What it is |
|---|---|---|
| Validate-and-hold binding | **72** | `BulletinAvailabilityCertificate` — the per-slot custody standing whose signature MEANS validate-and-hold (T3). Paid once per sealed slot. |
| Canonical bulletin close | **180** | `CanonicalBulletinClose` — the sealed-slot commitment (height, cutoff, five surface hashes, entry count). |
| Optional audit record | **106** | `AvailabilityAuditRecord` — the ADDITIVE per-probe audit cost (R2). A close verifies with ZERO of these, so 106 B is the MARGINAL cost of the audit lane, paid only when a probe is recorded; the at-rest audit cost is zero. |

Reproduce: `cargo test --locked -p ioi-types --lib measured_wire_costs_are_pinned`.

Reading: the audit lane's cost is strictly marginal — the zero-audit
close gate (R2) proves no verification path reads an audit record, so a
deployment that never probes pays 0 bytes for audit, and each probe it
DOES record costs 106 B. Validate-and-hold is 72 B per slot regardless
of ring size, because the binding is over the committed surface, not
per-holder.

## Class B — measured once, reproduces within CPU variance (proving time)

The P2.5 SP1 continuity proof, measured locally during P2.5 de-risking:

| Quantity | Value | Variance class |
|---|---|---|
| CORE continuity proof, one step | **~27 s CPU** | ±CPU scheduling; single-thread bound |
| 3-step chain (harness `chain` e2e) | **~84 s wall, CPU backend** | ±CPU scheduling |

Reproduce: the P2.5 recipe (`crates/aft-proofs`, sp1up + cargo-prove
f66b4bf, CPU backend) documented in the program record; the nightly lane
`aft-proofs-nightly.yml` runs it. These are CPU-backend figures; a GPU
or the Succinct prover network would change them by an order of
magnitude and is out of scope for an in-repo measurement.

## Class C — box-variable, deferred to a pinned bench runner (throughput / close latency)

Boundary-close LATENCY and sustained TPS at n ∈ {4, 7} are produced by
the existing paper-benchmark harness
(`crates/cli/tests/benchmark_throughput/aft*`, `PaperBenchmarkResult`
with p50/p95/p99/max commit latency + injection/sustained TPS + churn).
The harness EXISTS and is the reproduction instrument; committed numbers
are deliberately NOT pinned in this repo because:

- the figures are runner-dependent (the program's own history notes the
  verifier is env-flaky on the slow development box), so a number
  committed from an ad-hoc local run would fail its own
  reproduce-within-variance gate on a different box;
- reproducible throughput numbers require a PINNED bench-CI runner — the
  same discipline the estate already applies to its deterministic gates.

**Honest residual (RES-P4.3-throughput):** the close-latency / TPS table
at n ∈ {4, 7} lands when a pinned bench runner exists. The instrument is
built; only the stable execution environment is missing. Reproduce the
shape today with:
`cargo test -p ioi-cli --features consensus-aft,vm-wasm,state-jellyfish -- --ignored <aft paper-benchmark scenario>`
(runner-dependent absolute values; use for relative comparison only until
the pinned lane lands).

Bandwidth at payload sizes rides the same harness (bytes per committed
block are derivable from the Class A per-object costs times the block's
object count) and is deferred with it.

## Summary

Class A (the wire costs — the numbers a protocol reviewer needs to reason
about custody and audit overhead) are exact and gate-pinned now. Class B
(proving) reproduces within CPU variance via the nightly lane. Class C
(throughput/latency) is instrument-ready but honestly deferred to a
pinned runner rather than committed from a variable box — recording the
residual instead of a number that could not survive its own gate.

## Measured-results registry contract

Class C promotion is a relying-party state transition, not a manual table
edit. `AftMeasuredResultRow` binds one accepted campaign result to its C8 v3
certificate, environment, immutable image, provider, honesty class, and
verdict. `AftMeasuredResultsRegistry` is the compare-and-set target: every
accepted transition increments its revision, names the prior state hash, and
commits the complete ordered row set. Rejection leaves the registry bytes
unchanged and is represented only by a `CertificateAcceptanceReceipt`.
