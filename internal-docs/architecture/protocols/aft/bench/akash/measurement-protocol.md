# RES-P4.3 measurement protocol

This protocol is fixed before observing the certified-provider measurements. It prevents a favorable single run from becoming the reported result.

## Campaign shape

- Run the canonical four-scenario matrix: `paper_guardian_majority_4v`, `paper_guardian_majority_7v`, `paper_asymptote_4v`, and `paper_asymptote_7v`.
- Each measured pass must contain exactly 14 unique scenario/lane rows: three lanes for each guardian-majority scenario and four lanes for each asymptote scenario.
- Each campaign performs one discarded full-matrix warmup followed by five measured full-matrix passes.
- Run two campaigns through separately admitted, separately authorized provider operations against the same exact provider and the same immutable image digest.
- Never retry a failed or partial pass inside a paid campaign. Retain the failed evidence, close and reconcile the lease, diagnose offline, and admit a fresh campaign.

## Recorded metrics

For every scenario/lane row, retain injection TPS, sustained TPS, and commit-latency p50, p95, p99, and max. For each metric report count, minimum, median, maximum, median absolute deviation, sample coefficient of variation, and a deterministic exact 95% bootstrap interval for the median when five measured passes are present. Retain raw output, normalized pass JSON, the environment manifest, aggregate JSON/Markdown, a machine-readable artifact manifest, and its SHA-256 companion.

## Reproduction thresholds

The aggregate uses `(maximum - minimum) / median` across measured passes. Injection TPS, sustained TPS, p50, and p95 must be within 10%. P99 and max must be within 15%. Every row and metric must clear its threshold for `reproduced_within_threshold`; otherwise the only permitted verdict is `variance_caveated`.

The `compare` operation applies the same thresholds to each campaign median, requires both environment manifests, and emits a separate `ioi.aft.benchmark-campaign-comparison.v1` artifact. Source commit, image digest, protocol version, CPU model/count, kernel, machine, memory, and governor must match for `reproduced_within_threshold`; drift forces an explicit `variance_caveated` verdict. A within-campaign verdict cannot substitute for the required second campaign.

## Honesty class

Provider address pinning proves stable provider identity, not physical bare-metal allocation. A result is `Class C — measured on attested pinned bare metal` only when evidence satisfying [provider-placement-attestation-request.md](provider-placement-attestation-request.md) independently establishes the reserved host and its hardware identity. Without that evidence, publish the more limited measured-container class and keep RES-P4.3 open or variance-caveated as the Common-Boundary ledger requires.

Zero ready replicas, missing result artifacts, an unverified manifest, a mutable image tag, a provider mismatch, or unreconciled exposure invalidates the campaign. Endpoint discovery alone is not workload readiness.
