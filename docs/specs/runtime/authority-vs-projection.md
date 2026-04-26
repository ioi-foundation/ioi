# Authority vs Projection

Status: implementation scaffold active

Runtime UX has two layers:

- **Projection:** fast UI/event mirrors that help users see current activity.
- **Authority:** persisted policy decisions, approval grants, commitments,
  observations, postconditions, settlement bundles, and artifact promotion
  receipts.

Projection is useful, but it is not settlement. UI copy, exports, and debug
views must not call projection-only events "canonical" unless persisted
settlement records are included.

## Evidence Tiers

- **Projection:** event stream or UI state only.
- **Runtime event receipt:** event-level receipt emitted by the runtime, not a settlement bundle.
- **Settlement receipt:** persisted, verifier-checkable settlement record.
- **External approval:** signed or externally attestable approval authority.
- **Artifact promotion:** validated artifact promotion receipt.
- **Missing settlement:** projection exists but settlement refs are absent.
- **Simulation-only:** explicitly non-authoritative execution.

## Trace Export Rule

Trace bundles expose:

- `projectionReceipts`: event-derived receipt projections.
- `settlementReceipts`: settlement-backed records when available.
- `missingSettlementRefs`: evidence gaps that prevent settlement authority.
- `receipts`: legacy alias for projection receipts during migration.

Consumers should prefer `settlementReceipts` for verification and treat `receipts`
as a compatibility field only.

## Workflow Projection Rule

Workflow run receipts that have not yet settled through the runtime kernel must
set `projectionOnly` and carry empty `settlementRefs`. Remote workflow triggers
must include an idempotency key so retries can be reconciled instead of creating
ambiguous duplicate side effects.
