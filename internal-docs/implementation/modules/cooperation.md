---
module_id: cooperation
module_class: method
title: Conditional sovereign cooperation
sequencer: program/sequence.v1.json
status_owner: work-item records
stage_ids: [M12, M13, M14]
legacy_id: WP-COOP
canon_owners:
  - docs/architecture/foundations/aiip.md
  - docs/architecture/foundations/governed-autonomous-systems.md
  - docs/architecture/foundations/economic-flywheel-and-pricing-boundaries.md
  - docs/architecture/foundations/common-objects-and-envelopes.md
  - docs/architecture/foundations/invariants.md
  - docs/architecture/foundations/domain-ontologies-and-data-recipes.md
  - docs/architecture/foundations/security-privacy-policy-invariants.md
  - docs/architecture/foundations/ecosystem-assurance-certification-liability.md
  - docs/architecture/components/agentgres/doctrine.md
  - docs/architecture/components/wallet-network/api-authority-scopes.md
  - docs/architecture/domains/ioi-ai/collaborative-outcome-pattern.md
  - docs/architecture/domains/marketplace-neutrality.md
  - docs/conformance/hypervisor-core/sovereign-local-completeness.md
  - docs/conformance/hypervisor-core/dispute-rails.md
---

# Conditional Sovereign Cooperation

## What this module owns

This module owns the reusable method for deciding whether cross-sovereign cooperation may
begin at all, binding it to exact accepted terms when it may, and treating refusal as a
first-class result when it may not. It supplies a test and an evidence shape a stage
delegates to; it never orders work, never carries stage or cut status, and is never a
sequencer — order and exit gates belong to [`sequence.v1.json`](../program/sequence.v1.json),
durable status to the owning work-item record.

## Pulled by

`modules[].applies_to_stages` for `cooperation` binds it to `M12`, `M13`, and `M14`: at M12
its terms, acceptance, decline, and non-retroactive-amendment obligations become
contractible objects; at M13 its participant-surplus and safe-decline obligations become
falsifiable trial evidence; at M14 the same participation test is reapplied to public
service families, enrollment, and any optional L1 commitment. No other binding is valid
unless the sequencer declares it.

## Canon owners

| Canon owner | What it governs here |
| --- | --- |
| [`foundations/aiip.md`](../../../docs/architecture/foundations/aiip.md) | AIIP as an option to interoperate; conditional cooperation thesis; participant-level admission; semantic-profile negotiation; the receipt → evidence → verification → acceptance → adjudication → settlement ladder |
| [`foundations/governed-autonomous-systems.md`](../../../docs/architecture/foundations/governed-autonomous-systems.md) | Sovereign completeness without federation; OutcomeRoom / CollaborativeWorkGraph as a conditional profile, not a runtime; conditional cooperation surplus as the optimization target |
| [`foundations/economic-flywheel-and-pricing-boundaries.md`](../../../docs/architecture/foundations/economic-flywheel-and-pricing-boundaries.md) | The expected-cooperation-surplus expression, incremental cooperation costs, attribution-is-not-allocation, and direct local operation as the correct fallback |
| [`foundations/objects/interop-and-collaboration-terms.md`](../../../docs/architecture/foundations/objects/interop-and-collaboration-terms.md) | `CollaborationTermsEnvelope`, its body root and activation rule, `MultiPartyCollaborationEnvelope`, `CollaborationTermsAcceptanceReceipt`, and the accept / counteroffer / decline response shape |
| [`foundations/invariants.md`](../../../docs/architecture/foundations/invariants.md) | `INV-30` (cooperation is explicitly conditional) and `INV-31` (attribution is not allocation) |
| [`foundations/domain-ontologies-and-data-recipes.md`](../../../docs/architecture/foundations/domain-ontologies-and-data-recipes.md) | Semantic assertions, mappings, negotiated ontology/semantic profiles crossing the sovereignty boundary, and mapping risk |
| [`foundations/security-privacy-policy-invariants.md`](../../../docs/architecture/foundations/security-privacy-policy-invariants.md) | Keeping private valuations and outside options private through negotiation; disclosure and restricted-view limits |
| [`foundations/ecosystem-assurance-certification-liability.md`](../../../docs/architecture/foundations/ecosystem-assurance-certification-liability.md) | Assurance profiles, certification posture, and liability/claims routing carried across the boundary |
| [`components/agentgres/doctrine.md`](../../../docs/architecture/components/agentgres/doctrine.md) | Each domain's separately admitted operational truth and ordering; no shared operational database |
| [`components/wallet-network/api-authority-scopes.md`](../../../docs/architecture/components/wallet-network/api-authority-scopes.md) | Authority scopes, grants, and revocation for delegated or high-risk cross-system effects |
| [`domains/ioi-ai/collaborative-outcome-pattern.md`](../../../docs/architecture/domains/ioi-ai/collaborative-outcome-pattern.md) | OutcomeRoom product behavior, room materialization as conditional rather than default, shared evidence projections |
| [`domains/marketplace-neutrality.md`](../../../docs/architecture/domains/marketplace-neutrality.md) | Neutrality, contribution and derivation accounting, and assurance-state attribution for domain participants |
| [`conformance/hypervisor-core/sovereign-local-completeness.md`](../../../docs/conformance/hypervisor-core/sovereign-local-completeness.md) | The local-completeness contract a party still satisfies after it declines or disconnects |
| [`conformance/hypervisor-core/dispute-rails.md`](../../../docs/conformance/hypervisor-core/dispute-rails.md) | Dispute, challenge, and remedy rails invoked when cooperation degrades |

## Retained obligations

**Participation precondition.** Work begins only when each required sovereign party may
rationally accept exact terms: its own governed decision path finds expected utility under
the accepted terms, minus its best permitted outside option and minus incremental
cooperation costs, positive under its own constitution and policy. Coalition value never
substitutes for a required party's positive result. Valuations and outside options may stay
private; what binds is governed acceptance of one exact terms root, not a disclosed price.

**Contact creates no duty.** Compatibility, discovery, room visibility, channel enrollment,
messaging, a task offer, a terms proposal, or a shared goal creates no duty to cooperate and
no obligation, authority, membership, access right, executable award, contribution eligibility,
reputation, or payout. Solicitation, response, selection, and bounded award are distinct steps;
contribution, verification, acceptance or adjudication, and settlement are later distinct steps.

**Safe decline is a success.** When surplus is absent for any required party, declining is a
successful result of this method — not a failure, a stall, or a gap to close. A decline
leaves the declining party locally complete and leaves the counterparty unable to mutate its
truth, widen its authority, or retain access it did not accept. Direct local operation is
correct whenever external participation creates no positive participant-level value.

**Terms are exact and non-retroactive.** Cooperation binds to one exact terms root accepted
by every required party or role. A new root requires new acceptance and never rewrites an
already admitted contribution or reward basis; amendment is forward-only.

**Owner split is preserved.** This method spans, and must not merge, the AIIP protocol owner,
the OutcomeRoom owner, the semantic-mapping owner, the authority owner, the Agentgres
operational-truth owner, the assurance owner, and the applicable domain owners. A cooperation
object never silently relocates a subject between owners.

**Protocol completion is not value.** Successful negotiation, admission, or packet exchange
proves neither verification, acceptance, correctness, surplus, nor settlement. Attribution
supplies evidence for allocation; it is not allocation.

## Applying it in a work item

- `falsifiable_claim` states the participation test so it can fail: which required parties,
  which terms root, and what result counts as rational decline.
- `canon_owners` lists every owner crossed from the table above, including the applicable
  domain owner, with no owner represented by a proxy document.
- `evidence_refs` cite repo paths for the terms body root and its per-party acceptance
  receipts, the negotiated semantic/ontology profile with its mapping-risk record, and the
  authority grant plus revocation path for every cross-boundary effect.
- `adversarial_or_fault_proof` carries the decline battery: a required party refusing and
  staying locally complete, a counteroffer that does not bind, an expired or superseded
  root, a rejected retroactive-amendment attempt, and a peer attempting to mutate foreign
  truth or widen its own authority.
- `remaining_nonclaims` state that protocol completion alone carries no positive-economic-
  value, network-effect, marketplace-economics, or Internet-of-Intelligence claim.
- Where a valuation or outside option is frozen before a trial, the record names the
  freezing artifact and its non-disclosing binding, never the valuation itself.

## Terminal evidence

This method contributes to a stage exit only through: one exact terms root with
per-required-party acceptance receipts bound to it; a retained decline or negative-surplus
control in which a party safely refuses and continues locally; proof that neither peer
mutated the other's truth, widened its authority, or kept access after exit; and a
portable-exit artifact showing the departing party retains permitted state without continued
dependence on the counterparty. The stage's aggregate exit record in `sequence.v1.json`
alone closes the stage; passing this method for one instance bounds that instance only.

## Canon gaps

- No conformance contract defines the negative-surplus / safe-decline scenario as a testable
  matrix row; local completeness covers the post-decline state but not the decline decision.
  Owner to resolve:
  [`sovereign-local-completeness.md`](../../../docs/conformance/hypervisor-core/sovereign-local-completeness.md).
- Canon permits valuations and outside options to stay private but names no durable, non-
  disclosing artifact for freezing one before a trial and checking a later surplus claim
  against it. Owner to resolve:
  [`security-privacy-policy-invariants.md`](../../../docs/architecture/foundations/security-privacy-policy-invariants.md),
  object form in [`common-objects-and-envelopes.md`](../../../docs/architecture/foundations/common-objects-and-envelopes.md).
- The "domain owners" party in the owner split is not enumerated per cooperation instance,
  so a work item must resolve which domain files bind before naming them. Owner to resolve:
  [`source-of-truth-map.md`](../../../docs/architecture/_meta/source-of-truth-map.md).
