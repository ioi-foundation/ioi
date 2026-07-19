# Dispute-rail conformance

Status: active conformance target; registered portable contract plus
deterministic admission/allocation core.
Canonical inputs:
[`common-objects-and-envelopes.md`](../../architecture/foundations/common-objects-and-envelopes.md),
[`economic-flywheel-and-pricing-boundaries.md`](../../architecture/foundations/economic-flywheel-and-pricing-boundaries.md),
[`marketplace-neutrality.md`](../../architecture/domains/marketplace-neutrality.md),
[`ecosystem-assurance-certification-liability.md`](../../architecture/foundations/ecosystem-assurance-certification-liability.md),
and
[`events-receipts-delivery-bundles.md`](../../architecture/components/daemon-runtime/events-receipts-delivery-bundles.md).
Last audited: 2026-07-16.

## Scope and honest implementation posture

This profile tests the registered dispute-rail bundle contract, generated
Rust/TypeScript projections, and pure Rust dispute-rail kernel. The kernel
validates one versioned profile and owner-produced case snapshot, applies
evidence and response-window defaults, binds the exact profile/case/unit and
idempotency bytes, selects the profile-owned remedy, and conserves the held
bond pool through fixed-point integer allocation.

It does not adjudicate whether evidence is substantively correct, hold escrow,
move money or Work Credits, publish a public settlement, independently verify
evidence availability, or emit the required receipts. Those remain duties of
the marketplace, AIIP, wallet/settlement, Agentgres, and receipt owners.

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

## Focused proof

Run:

```bash
npm run hypervisor-conformance:disputes
```

The suite covers contract and generated-projection fixtures plus exact
allocation conservation, bundle export, asset/unit substitution, foreign prior
replay, zero-bond hold-ref smuggling, portable-integer overflow, non-value
remedy caps, same-body replay/changed-body conflict, unavailable-evidence
timing/defaults, retention failure, and public-settlement binding refusal.

## Open live gates

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

Until those gates land, the mechanism is an admission and allocation reference,
not a claim of deterministic arbitration or live escrow settlement.
