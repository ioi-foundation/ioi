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

## Class C — measured-container, variance-caveated (throughput / close latency)

Two separately authorized campaigns ran the complete `res-p4.3.v2` matrix on
the same exact Akash provider and immutable image. Each campaign discarded one
full-matrix warmup and retained five measured passes with ten unique
scenario/lane rows per pass. The environment manifests match: AMD EPYC 7352
24-Core Processor, 48 online CPUs, 131753256 KiB memory, Linux
6.8.0-124-generic, `x86_64`, `schedutil`, source
`14d249076477e97ec0dce5cdbea069b205df7cad`, and image
`sha256:3ddf68303685720610c6f3ff60ee300a884d9afb08101773f8d74d872eb1211d`.
The exact provider was
`akash1ggfvyhr9sar4uxjs4hth3p4kzrwk7lysnenj3g`.

Values are campaign-N / campaign-O medians. TPS columns are transactions per
second; commit columns are milliseconds.

| Scenario / lane | Injection TPS | Sustained TPS | p50 | p95 | p99 | max | Cross-campaign verdict |
|---|---:|---:|---:|---:|---:|---:|---|
| `paper_asymptote_4v / base_final` | 23112.38 / 20072.61 | 321.83 / 322.81 | 1583.16 / 1556.07 | 1589.41 / 1583.42 | 1589.94 / 1585.05 | 1590.11 / 1585.07 | variance-caveated |
| `paper_asymptote_4v / canonical_ordering` | 22156.16 / 17828.87 | 324.38 / 326.17 | 1555.21 / 1548.14 | 1576.13 / 1567.84 | 1577.47 / 1568.48 | 1577.70 / 1568.82 | variance-caveated |
| `paper_asymptote_4v / durable_collapse` | 18596.36 / 21552.59 | 322.01 / 322.63 | 1540.99 / 1581.05 | 1583.51 / 1585.45 | 1589.04 / 1586.13 | 1589.50 / 1586.26 | variance-caveated |
| `paper_asymptote_4v / sealed_final` | 20248.78 / 19319.42 | 325.75 / 315.97 | 1556.70 / 1561.24 | 1570.01 / 1618.40 | 1570.42 / 1619.53 | 1570.92 / 1619.82 | within threshold |
| `paper_asymptote_7v / base_final` | 11799.95 / 26761.25 | 338.23 / 344.18 | 2241.47 / 2185.40 | 2266.60 / 2214.95 | 2268.63 / 2229.23 | 2269.23 / 2229.58 | variance-caveated |
| `paper_asymptote_7v / canonical_ordering` | 11387.74 / 31215.72 | 342.15 / 341.02 | 2224.57 / 2238.23 | 2240.87 / 2248.16 | 2242.20 / 2249.77 | 2243.71 / 2250.00 | variance-caveated |
| `paper_asymptote_7v / durable_collapse` | 25359.49 / 32596.58 | 343.97 / 342.35 | 2221.34 / 2211.22 | 2229.33 / 2239.72 | 2231.37 / 2241.34 | 2231.53 / 2241.73 | variance-caveated |
| `paper_asymptote_7v / sealed_final` | 28148.01 / 32207.55 | 337.85 / 342.19 | 2212.87 / 2232.53 | 2269.57 / 2241.25 | 2271.57 / 2242.89 | 2272.29 / 2243.35 | variance-caveated |
| `paper_guardian_majority_4v / base_final` | 9119.25 / 9421.75 | 332.00 / 329.50 | 1536.53 / 1549.81 | 1540.12 / 1552.24 | 1541.05 / 1552.85 | 1541.35 / 1553.08 | within threshold |
| `paper_guardian_majority_7v / base_final` | 29314.23 / 30175.52 | 342.84 / 339.08 | 2194.89 / 2213.13 | 2201.76 / 2262.40 | 2238.58 / 2263.98 | 2239.15 / 2264.00 | within threshold |

The predeclared cross-campaign thresholds were 10% for injection TPS,
sustained TPS, p50, and p95, and 15% for p99 and max. Environments were
compatible. Every sustained-TPS and commit-latency comparison passed; injection
TPS exceeded 10% in seven rows, so the aggregate is **variance-caveated**. No
row was removed and no threshold was changed after measurement. The complete
per-pass values, min/median/max, median absolute deviation, sample coefficient
of variation, and deterministic exact-bootstrap median interval remain bound in
the campaign certificates.

Campaign N certificate:
`sha256:47af5c12270a44b6c7f5eb5d5a3114f24e03fdf09a4163efdb934aae2df43434`.
Campaign O certificate:
`sha256:875e9386be7fb7d95739748905d1ce6e8ae67b57773c53d56d72657759229348`.
Both leases closed with zero campaign-scoped open or unknown exposure. N debited
$0.080610 and refunded $0.919390; O debited $0.077146 and refunded $0.922854.

**Honesty class:** measured container on one exact audited provider allocation;
physical-host placement is unproven. The workload runtime supplied no provider
host attestation, so this is not a bare-metal measurement. RES-P4.3's live
measurement loop is closed by the retained variance-caveated observation; a
promoted reproduced-within-threshold row and any bare-metal label remain
separate stronger claims.

## Summary

Class A (the wire costs — the numbers a protocol reviewer needs to reason
about custody and audit overhead) is exact and gate-pinned. Class B (proving)
reproduces within CPU variance via the nightly lane. Class C now contains two
same-provider, same-image campaigns and is explicitly variance-caveated because
injection TPS missed the predeclared cross-campaign threshold; sustained TPS and
all commit-latency metrics reproduced within their thresholds.

## Measured-results registry contract

Class C promotion remains a relying-party state transition, not a manual table
edit. The table above records the completed U1 variance-caveated observation;
it is not represented as a registry-promoted reproduced claim.
`AftMeasuredResultRow` binds an accepted candidate to its C8 v3 certificate,
environment, immutable image, provider, honesty class, and verdict.
`AftMeasuredResultsRegistry` is the compare-and-set target: every accepted
transition increments its revision, names the prior state hash, and commits the
complete ordered row set. Rejection leaves the registry bytes unchanged and is
represented only by a `CertificateAcceptanceReceipt`.

The owner-local registry of record now contains both measured campaigns. Campaign
O was accepted at revision 1 (`sha256:8a133ada…`); Campaign N was then accepted by
compare-and-set at revision 2 (`sha256:483c7211…`). Campaign N retained the same
`measured_container`, `same_provider_container_unknown_host`, and
`variance_caveated` boundaries. The second transition used an explicitly
re-derived first-party verifier build profile; policy drift outside that build
lineage was forbidden. This is a second variance-caveated row, not a promotion to
`reproduced_within_threshold`, bare metal, provider neutrality, or third-party
verification.
