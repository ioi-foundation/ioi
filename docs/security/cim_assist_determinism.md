# CIM Assist Determinism Contract

## Scope
This document defines the consensus-bound Stage A -> A' assist contract for the local-only PII pipeline.

`CimAssistV0Provider` is always-on for the default PII routing path.

## Runtime Model
- `inspect_and_route_with_for_target(...)` always uses `CimAssistV0Provider`.
- `route_pii_decision_for_target(...)` applies `CimAssistV0Provider` before routing.
- `NoopCimAssistProvider` remains available only for explicit baseline/test paths.

Consensus caveat: all environments must run the same CIM identity for desktop/service and validator/ingestion parity.

## Deterministic Requirements
`CimAssistV0Provider` must remain deterministic:
- no wall clock reads
- no RNG
- no external I/O
- no locale-dependent behavior
- no floating-point or thread scheduling dependence

Routing remains pure over:
`(graph, policy, target, risk_surface, supports_transform, assist_receipt)`.

## Allowed vs Forbidden Transformations
Allowed (v0):
- drop existing spans that are deterministically classified as ambiguity false positives
- downgrade confidence bucket
- set `ambiguous=false` when ambiguity is deterministically resolved

Forbidden (v0):
- creating new spans
- mutating `source_hash`
- increasing severity
- reclassifying to a more severe class

## v0 Rule Scope
`CimAssistV0Provider` is intentionally narrow:
- `card_pan` ambiguity refinement for tracking/invoice/order-id-like contexts
- `phone` ambiguity refinement for non-contact numeric-id contexts
- `custom` ambiguity drop only for explicitly ambiguous low-confidence spans

## Identity Commitments
For v0:
- `assist_kind = "cim_v0"`
- `assist_version = "cim-v0.1"`
- `assist_config_hash` is computed from canonical config bytes
- `assist_module_hash` is a fixed zero hash in native v0 (no external module bytes)

`assist_identity_hash` remains derived from:
`assist_kind`, `assist_version`, `assist_config_hash`, `assist_module_hash`.

Decision hash material binds:
- `supports_transform`
- assist invocation/application flags
- assist identity fields
- assist input/output graph hashes

Different assist identities are not decision-hash-equivalent.

## Scoped Exception Usage Semantics
Usage counters follow a single-writer model:
- validator/ingestion are verify-only (preflight check via `check_exception_usage_increment_ok(...)`, no mutation)
- desktop service resume path is the sole writer and persists `next_uses`
