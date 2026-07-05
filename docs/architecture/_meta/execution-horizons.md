# Execution Horizons

Status: canonical architecture note.
Canonical owner: this file for the horizon framing that separates the launch wedge from long-horizon breadth without narrowing canon.
Supersedes: readings of the canon that mistake speculative breadth for current shipped surface, or that treat horizon labels as scope deletion.
Superseded by: none.
Last alignment pass: 2026-07-05.
Doctrine status: canonical
Implementation status: mixed (this note classifies; subject owners carry per-file status)
Last implementation audit: 2026-07-05

## Why this note exists

The canon deliberately specifies more than is built. That breadth is an asset
— it keeps the object model coherent as lanes land — but only if readers can
tell what is shipping from what is designed. This note gives the horizon
frame; the per-file `Implementation status` axis (see
[`doc-classes.md`](./doc-classes.md)) gives the per-subject truth.

**Horizon does not equal deletion.** Nothing here narrows the architecture.
A `speculative` label is a maturity statement, not a scope cut.

## Horizon 1 — the launch wedge (build and sell now)

Governed multi-provider compute plus authority custody plus receipts:

- The BYO/managed provider plane and adapter ladder (SSH, Vast, RunPod,
  Lambda, Akash, AWS, GCP; clusters and Azure next) —
  [`../components/hypervisor/byo-provider-plane.md`](../components/hypervisor/byo-provider-plane.md).
- The decentralized.cloud candidate plane filling `hypervisor_choose` —
  [`../domains/decentralized/cloud.md`](../domains/decentralized/cloud.md).
- Wallet-gated capability leases, sealed credentials, budget-before-mutation,
  spend reconciliation, and receipts on every crossing —
  [`../components/wallet-network/doctrine.md`](../components/wallet-network/doctrine.md).
- Storage-plane archive custody with state-root restore truth —
  [`../components/storage-backends/doctrine.md`](../components/storage-backends/doctrine.md).
- The Hypervisor estate that operates all of it (sessions, environments,
  operations, work ledger) —
  [`../components/hypervisor/core-clients-surfaces.md`](../components/hypervisor/core-clients-surfaces.md).

Doc-detail budget: this horizon deserves endpoint-level and semantics-level
detail, kept current with code.

## Horizon 2 — network effects on the wedge

Lands as the wedge produces volume and evidence:

- Marketplaces over the draft object planes (aiagent.xyz hire/install,
  sas.xyz outcomes) and the Verified Work Graph they accrete.
- Exchange/trade candidate intelligence going live behind wallet authority.
- Foundry training/eval execution over the inert object plane; MoW routing
  with routing receipts.
- Multi-user/org distribution (IdP plane is already built; org adoption is
  the horizon-2 work).

Doc-detail budget: object models and boundaries stay canonical; endpoint
walls stay reference-class until implementation starts pulling them.

## Horizon 3 — the full stack

Category-defining surface that waits on horizons 1–2 or on external
maturity: IOI L1 settlement and token/BME, AIIP interop, cTEE private
workspaces, HypervisorOS bare-metal, embodied/robot runtimes, ecosystem
assurance/certification.

Doc-detail budget: crisp boundaries, invariants, and object sketches —
enough that horizon-1/2 decisions never paint these out — without
endpoint-level elaboration that would drift for years.

## The rule that keeps this honest

**Doc detail follows implementation maturity.** When a subject moves up a
horizon, its docs earn more detail; until then, elaborate detail on unbuilt
subjects is a maintenance liability and a credibility risk (readers mistake
spec for shipped). The per-file axis is the enforcement point: `speculative`
files should stay lean; `built` files should carry the detail.

## Related Canon

- [`doc-classes.md`](./doc-classes.md) — the status-axis vocabulary.
- [`implementation-matrix.md`](./implementation-matrix.md) — per-concept durable-form status.
- [`../foundations/economic-flywheel-and-pricing-boundaries.md`](../foundations/economic-flywheel-and-pricing-boundaries.md) — what monetizes at each layer.
