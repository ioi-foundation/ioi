# 00 — Why IOI Exists

Status: architecture guide chapter (non-owning synthesis).
Canonical owner: this file for the reading order and narrative sequencing of
the category problem and founding move only; every subject is owned by the
linked owner doc, which wins on any point of substance.
Supersedes: none (originates no doctrine).
Superseded by: none.
Last alignment pass: 2026-08-16.
Doctrine status: canonical
Implementation status: mixed (narrative over built, partial, planned, and
speculative subjects; status truth lives in
[`canon-to-code-delta.md`](../_meta/canon-to-code-delta.md) and the
[`work-items/`](../_meta/work-items/) records)
Last implementation audit: 2026-08-16

## The Problem

Intelligence can now reason, plan, and propose anywhere — in a model API, an
editor, a harness, a robot, a browser. What it cannot be allowed to do is carry
**ambient consequential power**: the standing ability to touch money, data,
infrastructure, other people's systems, or the physical world merely because it
is running.

Most agent systems respond with supervision: prompt rules, allowlists,
confirmation dialogs, review after the fact. Supervision matters, but it
preserves the dangerous shape — *the model has broad access, and the system
tries to persuade it not to misuse that access*. IOI rests on a different
premise, stated by its alignment-security owner,
[`verifiable-bounded-agency.md`](../foundations/verifiable-bounded-agency.md):

> **Intelligence may be probabilistic. Authority must be bounded, explicit, and
> verifiable.**

Authority is reduced by architecture, not merely moderated by supervision. The
actor never had the power in the first place, except under explicit, bounded,
receipted, and revocable conditions. This is an execution-boundary claim, not a
claim to have solved model-internal alignment — IOI constrains what autonomous
actors can *do*, and is honest that it does not prove what they privately
*want*.

## The Founding Move

IOI places one governed **effect boundary** between probabilistic cognition and
real-world consequence. Everything else in the architecture is entailed by
taking that boundary seriously:

- **Authority** must exist as explicit artifacts — scoped, expiring, revocable
  leases and grants rather than possessed secrets — because delegation that
  cannot be bounded or withdrawn is ambient power with paperwork. Owner:
  [`doctrine.md`](../components/wallet-network/doctrine.md) (wallet.network),
  with local/domain policy providers where canon permits.
- **Admission** must be deterministic — a daemon that checks contract, policy,
  authority, and evidence before an effect crosses, and fails closed — because
  a probabilistic gate is not a gate. Owner:
  [`doctrine.md`](../components/daemon-runtime/doctrine.md) (Hypervisor
  Daemon).
- **Evidence** must be attributable and challengeable — receipts that bind
  declared boundary facts, with assurance staged rather than assumed — because
  among self-interested parties, adversarial contribution cannot be averaged
  away; it must be attributed, verified, and made accountable. Owner:
  [`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md).
- **Operational truth** must be admitted, not accumulated — a state substrate
  that records what a domain accepted, under which policy, replayably — because
  a log is not memory an institution can stand on. Owner:
  [`doctrine.md`](../components/agentgres/doctrine.md) (Agentgres).
- **Sovereign interop** must be contractible — independently governed systems
  exchanging bounded work under accepted terms — because institutions with real
  liability will not pool their cognition, and should not have to. Owner:
  [`aiip.md`](../foundations/aiip.md).
- **Shared settlement** must be sparse and optional — public commitments only
  where shared trust actually creates value. Owner:
  [`ioi-l1-mainnet.md`](../foundations/ioi-l1-mainnet.md).

## The Category

Two definitional owners name what this architecture claims to be.

[`web4-and-ioi-stack.md`](../foundations/web4-and-ioi-stack.md) owns the Web4
category:

> **Web4 = Read + Write + Own + Act, under machine authority.**

Machine authority is the protocolized ability for a non-human actor to receive
limited power and use it across real systems — bounded by identity, scope,
policy, purpose, time, budget, approval, revocation, receipts, and settlement.

[`internet-of-intelligence.md`](../foundations/internet-of-intelligence.md)
owns the Internet of Intelligence category: the network condition in which
independently governed intelligent institutions exchange bounded, verifiable
work under machine authority — an economy of accountable intelligent labor
across sovereign boundaries, **not** a commons of pooled cognition, parameters,
or gradients. That owner also states why the pooling alternative fails
structurally (wrong adversary, silence at the effect boundary, weights launder
rights, no incentive layer) and names the category-defining inversion:

```text
academic pooling model    assumes cooperation, engineers privacy
canonical IoI             assumes sovereignty, engineers cooperation
```

Humanity already built an internet of intelligence once, for human
intelligences, and its substrate was not shared brains: it was identity,
contracts, bounded agency, attribution, courts, and money. IOI recapitulates
those institutional primitives at machine speed — leases for agency law,
receipts for attribution, challenges for courts, sparse settlement for money.

## The Thesis, In One Statement

The strongest formulation is stated by the owners above and carried across the
corpus; it is reproduced here as navigation only:

> **IOI turns intelligence into bounded autonomous institutions. L0 makes one
> institution safely distributable across governed compute, state,
> verification, human, and embodied nodes; AIIP makes selective,
> positive-surplus interoperation between separately sovereign institutions
> contractible; IOI L1 supplies optional shared trust and economic finality.**

The rest of this guide unpacks that sentence in order: the effect boundary
(chapter 02), the institution (chapter 03), distribution (chapter 04),
sovereign interop and settlement (chapter 05), the products (chapter 06), and
learning under bounds (chapter 07).

## Owners For This Chapter

- [`verifiable-bounded-agency.md`](../foundations/verifiable-bounded-agency.md)
  — the alignment-security thesis and execution-boundary claim.
- [`internet-of-intelligence.md`](../foundations/internet-of-intelligence.md)
  — the IoI category, its necessity argument, and the north-star network proof.
- [`web4-and-ioi-stack.md`](../foundations/web4-and-ioi-stack.md) — the Web4
  category and the IOI reference stack.
- [`term-boundaries.md`](../foundations/term-boundaries.md) — what every
  protected term means and must not mean.
