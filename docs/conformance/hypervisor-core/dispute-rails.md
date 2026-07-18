# Dispute-rail conformance

Status: target conformance contract with a registered portable schema,
invariants, fixtures, and generated projections. No current dispute admission,
allocation, adjudication, or settlement kernel is claimed.
Canonical inputs:
[`common-objects-and-envelopes.md`](../../architecture/foundations/common-objects-and-envelopes.md),
[`economic-flywheel-and-pricing-boundaries.md`](../../architecture/foundations/economic-flywheel-and-pricing-boundaries.md),
[`marketplace-neutrality.md`](../../architecture/domains/marketplace-neutrality.md),
[`ecosystem-assurance-certification-liability.md`](../../architecture/foundations/ecosystem-assurance-certification-liability.md),
and
[`events-receipts-delivery-bundles.md`](../../architecture/components/daemon-runtime/events-receipts-delivery-bundles.md).
Last audited: 2026-07-16.

## Scope and honest implementation posture

This profile specifies the target semantics of the registered dispute-rail
bundle contract. The machine-contract substrate validates the closed schema,
cross-field invariants, positive and negative fixtures, and deterministic
Rust/TypeScript projections. It does not implement a dispute case owner,
admission or allocation kernel, idempotent transition store, adjudicator, or
remedy executor.

A future implementation must not infer that schema-valid caller-supplied case
or resolution fields are authentic. Evidence availability, adjudicator
authority, exact case heads, escrow or bond custody, money or Work Credit
movement, public settlement, and required receipt emission remain duties of
their marketplace, AIIP, wallet/settlement, Agentgres, and receipt owners.

## Required behavior

### CDR-1 — Rail separation

`internal_review`, `marketplace_escrow`, `aiip_dispute`, and
`public_settlement` remain distinct profiles. Marketplace cases bind their
escrow, AIIP cases bind exact CollaborationTerms plus ordinary verification
funding, and public cases bind settlement profile plus network enrollment.
Internal review cannot silently acquire bonded/slashing semantics.

### CDR-2 — Evidence and appeal retention

Evidence retention must cover the evidence, response, and actual resolution
appeal windows. An unavailable-evidence or respondent-timeout default cannot
run before its declared deadline.

### CDR-3 — Exact bond holds and conservation

Case holds must exactly match the admitted challenger/respondent bond sizes.
Every outcome distribution totals 10,000 basis points. Allocation uses integer
units, assigns rounding residue to the profile-declared recipient, and proves
that returns, awards, verifier funding, treasury, and burn sum to the held pool.
Zero-bond profiles carry no hold refs.

### CDR-4 — Declared defaults only

Unavailable evidence and missing response select only their profile-declared
default outcome. Unavailable evidence takes precedence because the response
cannot cure an unavailable adjudication record. Each default must name an
outcome rule.

### CDR-5 — Profile-selected remedy

The caller cannot choose a refund, payout, slash, retry, revision, escalation,
or no-fault result independently of the outcome rule. Remedy units cannot
exceed the rule's fixed-point cap over disputed value.

### CDR-6 — Exact idempotency

The same idempotency key and canonically identical resolution request returns
the prior decision. Reuse with changed bytes is a conflict. The request binds
the exact current case head and adjudicator.

### CDR-7 — Receipt duties survive resolution

Every decision names dispute-resolution and bond-distribution receipt duties.
Non-empty remedies and escalation add their own receipt duties; a computed
decision alone never proves value moved or the dispute became final.

### CDR-8 — One exact asset-unit binding

The profile, dispute, request, and resolution bind the same asset ref, unit ref,
unit version/body hash, atomic-unit code, and decimal scale. Disputed value,
remedy, both bond holds, bond pool, and every allocation leg are integer atomic
units of that one binding. V1 has no conversion. Substituting another asset,
deployment, denomination, decimal scale, display code, token, or Work Credit
fails closed. Values above the portable exact-integer ceiling and all floating
point amounts are invalid.

## Current machine-contract evidence

Run:

```bash
npm run check:architecture-contracts
npm run test:architecture-contract-projections
```

Those checks cover the registered positive marketplace-resolution fixture, the
adversarial value-unit substitution fixture, the declared cross-field
invariants, and byte-current generated projections. They do not execute
allocation, replay, timing, retention, adjudication, or settlement behavior.

## Open live gates

- a deterministic admission/allocation kernel implementing CDR-1 through CDR-8;
- object-scoped idempotency, exact-head conflict, timing/default, retention,
  fixed-point conservation, and foreign-prior adversarial tests;
- Agentgres-owned append-only dispute case and resolution heads;
- independent evidence-availability verification;
- real challenger/respondent bond holds and release/slash execution;
- marketplace escrow refund/payout and supplier/customer reconciliation;
- AIIP bilateral/exported dispute receipt exchange;
- public-settlement inclusion/finality where explicitly enrolled;
- appeal transition and supersession of prior resolution;
- adversarial concurrent adjudication and stale-head tests at the storage PEP;
- evidence deletion/crypto-shredding only after every applicable dispute,
  appeal, legal-hold, and retention window; and
- required receipt emission plus offline proof export.

Until those gates land, this is a registered target contract and fixture
corpus, not an admission mechanism, deterministic arbitration claim, or live
escrow settlement.
