# ADR 0021: Select Sovereign-Local Completeness As The First Flagship Proof

- Status: Accepted
- Date: 2026-07-25
- Owners: execution horizons / conformance / Hypervisor Core / daemon runtime
- Refines: ADR 0008, ADR 0015
- Confidence: working_ruling — this orders work; the owner can reorder from
  this record alone without unwinding any contract.

## Context

Four flagship proofs were declared targets — sovereign-local completeness, one
logical DAS across two failure domains, two sovereign DASs over AIIP, and the
north-star external-Worker proof — with a contract-first build sequence but no
answer to which proof, landed first, most changes what everything else can
claim. Separately, ADR 0008 named the Authority Gateway attach lane "the
stronger adoption wedge" while `execution-horizons.md`, the sequencing owner,
did not sequence the gateway at all; the wedge was asserted beside the plan
rather than inside it.

## Conflicting Readings

1. **Network-first.** The two-sovereign-DAS AIIP proof is the
   category-defining demonstration; land it first even at higher cost.
2. **Distribution-first.** The two-failure-domain continuity proof is the L0
   differentiation ("distributable institution"); land it first.
3. **Local-first.** Sovereign-local completeness is the root of the dependency
   graph and the adoption argument; land it first.

## Decision

Reading 3. **Sovereign-local completeness — the
`embedded_single_operator_offline` fixture plus undeniable-product profile 1
on the bounded software-change OutcomeRoom institution — is the first
flagship proof.** The reasons that actually drove it:

- Dependency structure: readings 1 and 2 both presuppose at least one operable
  sovereign node; there is no ordering in which they land first.
- Claim leverage: "the current estate has not yet passed the end-to-end
  standalone contract" is the canon's most-repeated honesty caveat; this proof
  flips the largest set of target claims to evidenced at once.
- Adoption: local-first, credible exit, and adopt-rather-than-fork (the
  adoption calculus in `web4-and-ioi-stack.md`) are positioning claims until
  this proof exists and demonstrable properties after it.
- Cost: it is the cheapest flagship — single node, no consensus, no
  federation, no payments — and its conformance matrix already exists as
  fixture data.

Sub-ruling: **the Authority Gateway attach lane is sequenced in Horizon 0**,
not gated behind the first proof. Its contracts (`ActionRequestEnvelope`,
registered gateway receipt types, `AuthorityGatewayProfile`, graduation
through `GoalRunActivation`) are additive contract work that meets adopters
where their agents already run; making the wedge wait on the flagship would
starve adoption for no dependency reason, and leaving it unsequenced would
keep ADR 0008 and the horizon plan in contradiction.

## Consequences

- `execution-horizons.md` carries "The first proof — a ruling" and the
  Horizon 0 attach-lane and admission-contract bullets; the proof order is
  SLC → Horizon 2A continuity → Horizon 2B distributed work → Horizon 3
  two-sovereign AIIP (unchanged as the minimum credible
  Internet-of-Intelligence demonstration).
- The conformance claim coverage index marks SLC as the selected first proof;
  its runner and isolated-egress harness become the highest-leverage missing
  evaluators in the tree.
- Nothing is deleted or descoped; this ADR orders existing targets.

## Rejected Alternatives

- Network-first and distribution-first, per the dependency argument above.
- Declaring the gateway wedge the first proof: the attach lane is contract
  work and an adoption channel, not a flagship institutional proof; treating
  it as one would substitute reach for evidence.

## Cost Of Being Wrong And Reversal

If commercial reality demands re-prioritizing (for example, a customer-funded
two-node engagement), reorder by editing the ruling section and this ADR's
status; no contract, schema, or identifier depends on the order. The cost of
this ruling being wrong is schedule, not architecture.

## Canonical References

- [`../architecture/_meta/execution-horizons.md`](../architecture/_meta/execution-horizons.md)
- [`../conformance/hypervisor-core/sovereign-local-completeness.md`](../conformance/hypervisor-core/sovereign-local-completeness.md)
- [`../conformance/README.md`](../conformance/README.md)
- [`../architecture/foundations/web4-and-ioi-stack.md`](../architecture/foundations/web4-and-ioi-stack.md)
- [`../architecture/components/daemon-runtime/doctrine.md`](../architecture/components/daemon-runtime/doctrine.md)
