# Protocol Governance Neutrality

Status: canonical architecture authority.
Canonical owner: this file for IOI's neutrality as protocol specification owner and network operator — the change process, capture resistance, and versioning rights over the protocol surface.
Supersedes: the implicit assumption that routing/marketplace neutrality covers specification neutrality.
Superseded by: none.
Last alignment pass: 2026-08-05.
Doctrine status: canonical
Implementation status: planned (a governance contract; no change-process tooling, registry of designations, or objection mechanism exists on current master)
Last implementation audit: 2026-08-05

## Purpose And Boundary

[`../domains/marketplace-neutrality.md`](../domains/marketplace-neutrality.md)
owns neutrality **inside** the network: routing, matching, ranking, marketplace
placement, anti-cannibalization, and contribution accounting. It answers "does
IOI favor its own workers and services when routing work?"

It does not answer the prior question: **does IOI favor itself when deciding
what the protocol is?** IOI writes the specification, operates a network on it,
and ships the reference implementation. Those are three roles, and an adopter's
rational move to adopt rather than fork depends on the third role not silently
serving the first two. This file owns that question and nothing else.

The distinction matters because routing neutrality is defeasible by
specification capture. A router that treats every worker identically is not
neutral if the contract the workers implement was shaped so that only one of
them can implement it well.

## The Three Roles, Held Apart

| Role | What it controls | Held by |
| --- | --- | --- |
| **Specification owner** | what the protocol surface is: contracts, invariants, versioning | canon owners under `_meta/source-of-truth-map.md`, amended through the change process below |
| **Reference implementer** | one designated release implementing a named surface | the contract in [`web4-and-ioi-stack.md`](./web4-and-ioi-stack.md) § The Reference-Implementation Contract |
| **Certifier and marks holder** | who may claim conformance, and who may use the names | [`ecosystem-assurance-certification-liability.md`](./ecosystem-assurance-certification-liability.md) and the licensing ADR |

**The separation rule.** No single act may exercise more than one of these roles
at once. Shipping code is not amending the specification (that rule is stated at
its owner); certifying an implementation is not designating it the reference;
and holding the marks confers no vote over what the specification says. Where
one organization currently performs all three — as IOI does today — the
separation is procedural rather than structural, and this file says so plainly
rather than implying an independence that does not yet exist.

## The Change Process

A change to the protocol surface is admissible only through this path. The path
is deliberately boring; capture happens in the exceptions.

1. **Proposal names its surface and its blast radius.** Which registered
   contract ids and owner docs change, which existing implementations the change
   would break, and whether it is additive, narrowing, or breaking.
2. **Public before accepted.** A change to the protocol surface is published in
   its proposed form before acceptance, with enough time for an adopter to
   evaluate it. A change accepted and published simultaneously has been imposed,
   not proposed — however good it is.
3. **Objection is answered on the record, not resolved by fiat.** An adopter's
   substantive objection receives a recorded answer. The answer may be "we are
   proceeding anyway"; what is not admissible is silence, because silence is
   indistinguishable from capture and makes the process unverifiable from
   outside.
4. **Breaking changes carry migration and a deprecation window.** A breaking
   change to a surface with known implementers publishes the migration path and
   the window before it lands. Compatibility aliases and successor contracts are
   the existing mechanism (`evolution` in the contract registry); this is the
   process rule that requires using them.
5. **The record is durable.** Proposal, objections, answers, and the accepted
   change are retained. A change process whose history can be edited is not a
   change process.

**Emergency exception, bounded.** A security fix may land ahead of the process
and is then published retroactively with the same record. The exception covers
*timing*, never *scope*: an emergency may not carry an unrelated surface change,
and an emergency change that turns out to have been convenient rather than
urgent is a process violation to be recorded as one.

## Capture Resistance

The failure this file exists to prevent is not a dramatic one. It is the slow
version: each individual change is defensible, and the accumulated surface fits
exactly one implementation.

Four resistances, each falsifiable rather than aspirational:

- **Specification sufficiency is testable.** A surface an outsider cannot
  implement from the specification alone is captured in effect, whatever the
  intent. The test is `separate_codegen` + `separate_transport`
  ([ADR 0032](../../decisions/0032-independently-implemented-client-definition.md));
  if the answer is "read our source", the surface is under-specified and the
  gap is a defect with an owner, not a documentation preference.
- **The reference implementation cannot legislate.** A divergence between a
  designated release and its named surface is a defect in the release until the
  surface is amended through the process above. Behavior does not become
  specification by shipping.
- **Compatibility is untaxed, and stays untaxed.** `ioi_compatible` owes no fee,
  token, enrollment, or hosted dependency. Introducing any of those to
  compatibility is a category change, not a pricing decision, and would need to
  be argued as one.
- **Exit stays typed.** Portable exit contracts are what make adoption a
  reversible decision. Degrading exit — making export lossy, gating it behind a
  service, or letting it rot untested — removes the adopter's leverage and is
  therefore a neutrality question, not only an engineering one.

## Versioning Rights

- **Contract versions are owned by their canon owner**, not by the reference
  implementation's release cadence. A release may not bump a contract version to
  match its own shipping schedule.
- **Successor contracts are additive by default.** Narrowing an existing
  contract is a breaking change and takes the breaking-change path, even when
  the narrowing is a correction.
- **A third party may implement any published version**, including a superseded
  one, and say so accurately. Nothing in this canon requires an implementer to
  track the newest surface to remain honest about which one it implements.
- **Version designations are not marketing.** `provisional`, `stable`, and
  `deprecated` in the contract registry mean what the registry says they mean;
  they may not be used to discourage implementation of a competitor-favourable
  version.

## What This File Does Not Own

- Routing, matching, ranking, and marketplace neutrality —
  [`../domains/marketplace-neutrality.md`](../domains/marketplace-neutrality.md).
- Certification, issuer accreditation, and liability —
  [`ecosystem-assurance-certification-liability.md`](./ecosystem-assurance-certification-liability.md).
- What makes a release the reference implementation, and how parity is proven —
  [`web4-and-ioi-stack.md`](./web4-and-ioi-stack.md) § The
  Reference-Implementation Contract.
- Licensing terms, the marks licence, and the open-surface boundary — the
  licensing ADR under [`../../decisions/`](../../decisions/).
- Pricing, fees, and the open-L0 covenant —
  [`economic-flywheel-and-pricing-boundaries.md`](./economic-flywheel-and-pricing-boundaries.md).

## Non-Claims

- This file does not claim IOI is currently structurally neutral. One
  organization holds all three roles; the separation is procedural, and saying
  otherwise would be the exact theater the adoption calculus forbids.
- It does not claim a change process exists in tooling. No proposal registry,
  objection mechanism, or designation record is implemented on current master;
  this is the contract they would have to satisfy.
- It does not claim neutrality is proven by intent. Every resistance above is
  written to be falsifiable from outside, because a neutrality claim only an
  insider can check is not a neutrality claim.

## Related Canon

- [`web4-and-ioi-stack.md`](./web4-and-ioi-stack.md) — the adoption calculus and
  the reference-implementation contract.
- [`internet-of-intelligence.md`](./internet-of-intelligence.md) — the category
  whose portability this neutrality serves.
- [`../domains/marketplace-neutrality.md`](../domains/marketplace-neutrality.md)
  — in-network routing neutrality.
- [`ecosystem-assurance-certification-liability.md`](./ecosystem-assurance-certification-liability.md)
  — certification, issuers, and liability.
- [`../../conformance/README.md`](../../conformance/README.md) — the claim
  coverage index and the public conformance profile.
