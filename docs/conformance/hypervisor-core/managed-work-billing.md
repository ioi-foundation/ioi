# Managed-work billing conformance

Status: target conformance contract with a registered bundle schema,
invariants, fixtures, and generated projections. No current accounting kernel,
durable billing ledger, public billing, or supplier reconciliation is claimed.
Canonical inputs:
[`economic-flywheel-and-pricing-boundaries.md`](../../architecture/foundations/economic-flywheel-and-pricing-boundaries.md),
[`common-objects-and-envelopes.md`](../../architecture/foundations/common-objects-and-envelopes.md),
[`identity-access-and-metering.md`](../../architecture/components/hypervisor/identity-access-and-metering.md),
and
[`events-receipts-delivery-bundles.md`](../../architecture/components/daemon-runtime/events-receipts-delivery-bundles.md).
Last audited: 2026-07-16.

## Scope and honest implementation posture

This profile specifies the target semantics of the registered managed-work
ledger-bundle schema. The machine-contract substrate validates its closed
shape, cross-field invariants, positive and negative fixtures, and generated
Rust/TypeScript projections. Current master has no shared accounting kernel or
fsync-backed managed-work billing ledger.

A future implementation must authenticate its owner rather than trusting
schema-valid caller-supplied commands. Current master does not resolve runtime
receipts or supplier statements, reconcile provider invoices, collect payment,
purchase or top up credits, hold cash or escrow, pay a
supplier/participant/verifier, post Agentgres truth, emit checkpointed receipts,
or operate a cross-process transactional ledger. No public daemon route exposes
`RecordUsage`.

## Required behavior

### MWB-1 — Fixed-point values only

Money uses integer ISO-currency minor units and Work Credits use integer
`micro_work_credit` units. Floating-point contract values are rejected.
Addition and multiplication fail on overflow and never wrap, round, or
saturate. The v1 interoperability ceiling is the maximum exact JSON integer,
`9,007,199,254,740,991`.

### MWB-2 — Frozen inputs and finite validity

A versioned RateCard precedes and is body-hash-bound by one versioned Plan.
One immutable WorkQuote freezes both refs and hashes, the initial hold,
attempt cap, commercial postures, and overrun policy. A Plan cannot outlive
its RateCard; a quote cannot outlive either input; holds are finite and cannot
outlive the quote. Expired or not-yet-valid objects fail closed.

### MWB-3 — Exact idempotency and append heads

The same idempotency key and canonically identical command bytes replay the
prior result. Reuse with changed bytes conflicts. Usage binds the current
usage-body head; adjustments bind the current adjustment-body head; ledger
entries bind the prior entry hash. Reordering, deletion, stale-head append, or
record/entry body mutation is rejected.

### MWB-4 — Owner-derived usage only

Every command binds one billing-account/work ledger identity, an authority ref,
and non-empty owner-evidence refs. Every UsageRecord binds non-empty runtime
receipt refs. This is necessary but not sufficient evidence validation: the
owning runtime and billing planes must resolve those refs before invoking the
internal kernel. A public caller-authored supplier-usage mint is forbidden.

### MWB-5 — Exact holds and overrun

The initial hold equals the quote's required hold. Usage cannot exceed holds
active at occurrence time. An overrun decision binds the current usage head
and projected total. `block` carries no additional amount.
`exact_additional_hold` is admitted only when the quote permits it and its
amount equals projected usage minus active held Work Credits. The corresponding
additional hold must bind that exact decision and amount.

### MWB-6 — One debit and downward-only correction

Exactly one FinalDebit binds the complete usage head and exact checked usage
sum and cannot exceed holds active at finalization. No usage follows it.
Refunds and writeoffs append after FinalDebit, carry evidence and a reason,
and cumulatively cannot exceed the debited amount. They never rewrite usage or
mint an upward charge.

### MWB-7 — Cost and posture separation

Provider cost, broker fee, participant cost, verifier cost, IOI fee, and
excluded customer-borne provider cost remain distinct integer fields.
BYOK/BYOA/customer-cloud/self-hosted/local posture cannot carry managed provider
cost. Supplier-reconciled state requires statement refs. Coarse OCU may only
use a zero-rate non-billable telemetry meter and cannot carry a supplier-cost
claim.

### MWB-8 — Assurance remains bounded

An exported bundle reports `internal_event_log`,
`supplier_partially_reconciled`, or `supplier_reconciled` from its exact bound
usage evidence. An internal debit with estimated cost is not invoice truth.
Neither schema validity nor a canonical hash proves that a supplier statement
is authentic, that money moved, or that a payout settled.

## Current machine-contract evidence

Run:

```bash
npm run check:architecture-contracts
npm run test:architecture-contract-projections
```

Those checks validate the positive complete bundle, floating-credit-unit
rejection, declared validity/hold/head invariants, and generated projection
parity. They do not execute fixed-point arithmetic, idempotency, append heads,
overrun policy, debit/adjustment limits, durable replay, or owner evidence
resolution.

## Open live gates

- a shared fixed-point accounting kernel implementing MWB-1 through MWB-8;
- same-body replay, changed-body conflict, stale-head, expiry, overflow,
  overrun, debit, and downward-adjustment adversarial tests;
- a durable append store with crash, restore, and cross-process concurrency
  evidence;
- owner-plane resolution of runtime receipt identities and measured quantities;
- signed/versioned provider price schedules and supplier-statement ingestion;
- invoice-line reconciliation for every billed route attempt and fallback;
- Agentgres-owned append/transaction authority and cross-process concurrency;
- public product entitlement, purchase, top-up, processor, tax, and cash-ledger
  integration;
- participant, verifier, broker, and supplier payout/settlement execution;
- refund payment execution and chargeback/dispute integration;
- daemon event emission, receipt checkpoints, and offline audit export; and
- fault injection across crash-before-fsync, crash-after-fsync, compaction,
  backup/restore, mixed-version rollout, and reconciliation outage.

Until those gates land, this is a registered target contract and fixture
corpus, not an internal accounting mechanism, production billing service, or
invoice-grade multi-provider allowance.
