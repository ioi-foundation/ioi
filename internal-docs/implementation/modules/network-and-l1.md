---
module_id: network-and-l1
module_class: method
title: Network services and optional L1
sequencer: program/sequence.v1.json
status_owner: work-item records
stage_ids: [M14, FUTURE]
legacy_id: WP-NET
canon_owners:
  - docs/architecture/foundations/ioi-l1-mainnet.md
  - docs/architecture/foundations/ioi-l1-contract-interfaces.md
  - docs/architecture/foundations/economic-flywheel-and-pricing-boundaries.md
  - docs/architecture/foundations/ecosystem-assurance-certification-liability.md
  - docs/architecture/foundations/common-objects-and-envelopes.md
  - docs/architecture/domains/marketplace-neutrality.md
  - docs/architecture/domains/sas/service-marketplace.md
  - docs/architecture/components/wallet-network/doctrine.md
  - docs/conformance/hypervisor-core/dispute-rails.md
  - docs/decisions/0015-bounded-distributed-autonomous-systems-and-network-enrollment.md
  - docs/decisions/0012-ioi-autonomous-system-settlement-and-aiip.md
---

# Network Services And Optional-L1 Method

## What this module owns

One reusable method: how a work item binds public network-service and optional-L1
work to its separate canonical owners, and keeps real demand, rights, security,
dispute, and economic proof distinct from the technical satellites surrounding an
L1 question. It supplies classification and non-substitution discipline only — it
never orders work, never carries stage or cut status, never closes a stage exit,
and is never a sequencer.

## Pulled by

Per `modules[network-and-l1].applies_to_stages` in [`sequence.v1.json`](../program/sequence.v1.json): **M14** and **FUTURE**. The retiring source scoped this method to M14 alone; the conditional `FUTURE` binding has no stage predecessor of its own. No stage ordered before M14 pulls it, and no earlier stage may borrow it to justify enrollment, public service-family, settlement, or L1 work ahead of these owners.

## Canon owners

| Canon owner | What it governs here |
| --- | --- |
| [`foundations/ioi-l1-mainnet.md`](../../../docs/architecture/foundations/ioi-l1-mainnet.md) | The L1 owner: optional-utility character, `ioi_compatible`/`ioi_connected`/`ioi_secured` posture separation, explicit network enrollment, shared-trust services, root contracts, gas boundaries, public commitments |
| [`foundations/ioi-l1-contract-interfaces.md`](../../../docs/architecture/foundations/ioi-l1-contract-interfaces.md) | Contract-interface shapes a devnet exercise binds to, including `NetworkEnrollmentRegistry`, `LicenseRightRegistry`, `SharedSecurityServiceRegistry`, `ServiceBondRegistry`, `DisputeRegistry`, `ServiceOrderEscrow`, `SettlementIntentRegistry`, `BenchmarkProfileRegistry` |
| [`foundations/economic-flywheel-and-pricing-boundaries.md`](../../../docs/architecture/foundations/economic-flywheel-and-pricing-boundaries.md) | The economics owner: distinct ledgers, declared fee bases, and the boundary a network fee or bond may not cross |
| [`foundations/ecosystem-assurance-certification-liability.md`](../../../docs/architecture/foundations/ecosystem-assurance-certification-liability.md) | The assurance owner: assurance and conformance profiles, certification, jurisdiction, quarantine, and liability behind any public service claim |
| [`foundations/common-objects-and-envelopes.md`](../../../docs/architecture/foundations/common-objects-and-envelopes.md) | Shape ownership for `IOINetworkEnrollment`, `NetworkServiceInvocationEnvelope`, `SettlementIntentEnvelope`, `SettlementEnvelope`, `SharedSecurityAgreement`, `DisputeRailBundle`, `ReceiptEnvelope` |
| [`domains/marketplace-neutrality.md`](../../../docs/architecture/domains/marketplace-neutrality.md), [`domains/sas/service-marketplace.md`](../../../docs/architecture/domains/sas/service-marketplace.md), [`domains/sas/service-endpoints.md`](../../../docs/architecture/domains/sas/service-endpoints.md) | The marketplace/service owner: neutral routing and contribution accounting; registry, order, delivery, acceptance, payment, suspension, exit, and endpoint posture |
| [`components/wallet-network/doctrine.md`](../../../docs/architecture/components/wallet-network/doctrine.md), [`api-authority-scopes.md`](../../../docs/architecture/components/wallet-network/api-authority-scopes.md), [`product-exchange-risk.md`](../../../docs/architecture/components/wallet-network/product-exchange-risk.md) | Authority scoping for enrollment and service invocation, the settlement boundary, and exchange/risk posture behind risk-bearing participation |
| [`conformance/hypervisor-core/dispute-rails.md`](../../../docs/conformance/hypervisor-core/dispute-rails.md), [`attestation-assurance.md`](../../../docs/conformance/hypervisor-core/attestation-assurance.md) | The dispute owner: rail separation, bond conservation, remedy, idempotency, asset-unit binding; attestation evidence expectations |
| ADR [`0015-…-network-enrollment.md`](../../../docs/decisions/0015-bounded-distributed-autonomous-systems-and-network-enrollment.md) | The enrollment owner: bounded-DAS enrollment doctrine and the optional, non-mandatory character of an L1 |
| ADR [`0012-…-settlement-and-aiip.md`](../../../docs/decisions/0012-ioi-autonomous-system-settlement-and-aiip.md), ADR [`0011-…-system-chains.md`](../../../docs/decisions/0011-hypervisor-nodes-and-governed-autonomous-system-chains.md) | The settlement owner: settlement semantics at the AIIP boundary and governed autonomous-system chain posture |
| [`whitepaper.tex`](../../../docs/architecture/whitepaper.tex) §5.3 | Records the AFT challenge-dominant settlement-finality design as a research candidate rather than architecture canon, and names what promotion would require |
| [`_meta/execution-horizons.md`](../../../docs/architecture/_meta/execution-horizons.md), [`_meta/source-of-truth-map.md`](../../../docs/architecture/_meta/source-of-truth-map.md) | Horizon 6 placement of public economic commitments; single-owner resolution across the families above |

## Retained obligations

**Separate the seven owners; never collapse them.** Work pulling this method
answers to the IOI Network enrollment owner, the economics owner, the L1 owner,
the assurance owner, the marketplace/service owner, the dispute owner, and the
settlement owner. Each is named individually in the record. One "network" or
"chain" owner standing in for the set is a stop condition under
[`rules.md` §9](../program/rules.md), since at least one contract would then carry
no clear canonical owner.

**Technical satellites stay conditional and stay satellites.** Throughput
experiments, AFT benchmarks, and chain engineering are conditional technical
satellites of this method. They are legitimate work and their results are
retained; what they are not is stage-advancing. They do not pull M14 forward, do
not activate a `FUTURE` record, and do not shorten, soften, or pre-satisfy any
owner's obligation. A satellite changes character only through the promotion path
its own owner names — for the AFT candidate, canon states this as a canonical L1
owner update, formal specification, executable conformance, independent review, and
explicit synchrony, adversary, data-availability, committee-selection, governance,
and challenge-window assumptions.

**Five proof classes are non-substitutable.** External demand, rights, security,
dispute, and economic proof are separate obligations bound to separate owners. No
satellite result substitutes for any of them, and none of the five substitutes for
another: a passing benchmark is not demand; a throughput figure is not security
economics; an exercised rights contract is not a dispute outcome; a working
settlement path is not willingness to pay or bear risk.

**An L1 remains optional, and the method proves nothing by itself.** A record
pulling this method carries the no-L1 branch as a live, valid outcome and keeps
every L1-conditional obligation explicitly conditional; nothing here authorizes
public commitment, native-asset issuance, or mainnet. Correct classification is a
precondition for admissible network/L1 work, not evidence of it — proof remains
what [`rules.md` §6](../program/rules.md) defines, produced against the owners
above.

## Applying it in a work item

- Map all seven owner families explicitly, each to a path in the table above with
  the exact obligation it governs for this cut; leave no family implied by another.
- Declare which of the five proof classes the record claims, which it explicitly
  does not, and the owner plus pre-frozen threshold each claimed class is measured
  against.
- List every throughput experiment, AFT benchmark, and chain-engineering artifact
  the record touches under a satellite heading, with its retention path under
  `evidence/` and an explicit statement that it closes no proof class and advances
  no stage.
- Carry the no-L1 branch and the selected posture (`ioi_compatible`,
  `ioi_connected`, `ioi_secured`) as declared record fields, marking every
  L1-conditional obligation conditional rather than pending.
- Bind each exercised contract interface, envelope, and dispute rail to its
  registered shape and owner; record any family lacking a registered shape as an
  `R-CONTRACT` blocker, never as an implicit local definition.
- Retain the nonclaims this method forces: no demand from internal traffic or
  affiliates, no L1 authorization from service availability, no public or mainnet
  claim from a devnet or a satellite, and no legal-conformity assertion without a
  separately authorized accountable issuer.

## Terminal evidence

This method's contribution closes when the pulling record's retained evidence
shows, bound to exact artifact bytes: seven owner families mapped and separately
satisfied for the cut's scope; each claimed proof class evidenced against its own
owner and pre-frozen threshold, with unclaimed classes carried as nonclaims; every
satellite artifact retained and explicitly excluded from proof-class credit; the
no-L1 branch preserved as valid; and the adversarial, denial, recovery, replay, and
fault evidence the pulling stage requires. The stage's aggregate literal exit
belongs to its `aggregate_exit` record; this method never closes one.

## Canon gaps

- **Satellite classification rule.** [`whitepaper.tex`](../../../docs/architecture/whitepaper.tex) §5.3 marks the AFT candidate non-canonical and names its promotion prerequisites, but no canon file defines a general rule for network/L1 technical satellites: which artifacts qualify, where results are retained, or the prohibition on citing them as demand, rights, security, dispute, or economic proof. Resolution owners: [`foundations/ioi-l1-mainnet.md`](../../../docs/architecture/foundations/ioi-l1-mainnet.md) with [`_meta/source-of-truth-map.md`](../../../docs/architecture/_meta/source-of-truth-map.md).
- **Proof-class boundaries.** Canon names demand, rights, security, dispute, and economic obligations across several owners but states no rule for when evidence produced under one owner may count toward another, which the non-substitution obligation depends on. Resolution owners: [`_meta/source-of-truth-map.md`](../../../docs/architecture/_meta/source-of-truth-map.md), [`foundations/economic-flywheel-and-pricing-boundaries.md`](../../../docs/architecture/foundations/economic-flywheel-and-pricing-boundaries.md), and [`foundations/ecosystem-assurance-certification-liability.md`](../../../docs/architecture/foundations/ecosystem-assurance-certification-liability.md).
- **Method reuse at the `FUTURE` binding.** The source scoped this method to M14 alone while the sequencer also binds it to `FUTURE`; canon states no doctrine for which network/L1 obligations survive into conditional post-M14 work or how the satellite rule applies there. Resolution owner: [`_meta/execution-horizons.md`](../../../docs/architecture/_meta/execution-horizons.md).
