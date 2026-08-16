# 01 — The System In One Page

Status: architecture guide chapter (non-owning synthesis).
Canonical owner: this file for the reading order and narrative sequencing of
the system's strata and first full-stack picture only; every subject is owned
by the linked owner doc, which wins on any point of substance.
Supersedes: none (originates no doctrine).
Superseded by: none.
Last alignment pass: 2026-08-16.
Doctrine status: canonical
Implementation status: mixed (narrative over built, partial, planned, and
speculative subjects; status truth lives in
[`canon-to-code-delta.md`](../_meta/canon-to-code-delta.md) and the
[`work-items/`](../_meta/work-items/) records)
Last implementation audit: 2026-08-16

## Two Complementary Directions

IOI combines two directions that answer different questions and replace
nothing in each other:

1. a Hypervisor substrate that mounts models, workers, tools, services,
   runtimes, infrastructure, memory, and embodied systems behind one governed
   effect boundary; and
2. a local-first semantic and coordination fabric in which member nodes,
   workers, people, services, and embodied units can pursue one system's goals,
   while separately sovereign domains may optionally collaborate without
   surrendering local truth or authority to one global database.

The first direction makes intelligence executable and governable. The second
makes independently owned intelligence composable. Owners:
[`governed-autonomous-systems.md`](../foundations/governed-autonomous-systems.md)
and
[`domain-ontologies-and-data-recipes.md`](../foundations/domain-ontologies-and-data-recipes.md).

Local-first is a target operating contract, not only a semantic preference:
within a declared standalone capability, durability, custody, and assurance
envelope, a conforming local or customer-controlled deployment must remain
independently operable without an `ioi.ai` account or another first-party
managed dependency. Managed attachment adds separately admitted capabilities
and never silently transfers truth, authority, custody, or writer ownership.
The current estate has not yet passed the end-to-end standalone conformance
profile. Owner:
[`core-clients-surfaces.md`](../components/hypervisor/core-clients-surfaces.md)
§ Standalone Local Completeness.

## The Strata

Every named thing in this architecture belongs to a stratum, and confusing the
strata is the corpus's most common reading error. Stated once, reused by every
later chapter:

```text
PRODUCTS            what someone buys, installs, or opens
  Hypervisor        the governed autonomy substrate and product family
  ioi.ai            Goal Space — the intent-to-outcome managed product
  wallet.network    the authority wallet and control plane product
  aiagent.xyz       the worker marketplace
  sas.xyz           the service/outcome marketplace
  IOI Network / L1  not an install — an explicit, optional enrollment

APPLICATIONS        surfaces WITHIN a product, never sibling products
  Hypervisor's owner applications (Studio, Automations, Ontology, Data,
  Governance, Provenance, Evaluations, Improvement, Foundry, Packages,
  Developer Workspace, Developer Console) and substrate applications
  (Environments, Operations) — authoritative list and semantics owned by
  core-clients-surfaces.md. Foundry is "the capability factory" INSIDE
  Hypervisor (foundry.md), not a peer product. ODK is a developer kit
  beneath Ontology and Data, not an application.

CLIENTS             ways to operate one product core, never runtime truth
  Hypervisor App, Hypervisor Web, CLI/headless (TUI is an optional
  presentation of it), SDK/ADK/ODK clients — all over one Hypervisor Core.

SUBSTRATES & PROTOCOLS   what operates the fabric and what crosses boundaries
  Hypervisor Daemon   admits, enforces, executes or mediates, receipts,
                      fails closed
  Agentgres           admitted domain-local operational truth
  MemorySpace         portable governed memory truth (distinct from Agentgres)
  storage backends    payload bytes, never meaning
  machine authority   wallet.network plus local/domain policy and authority
                      providers
  AIIP                the protocol across independently governed systems
  receipts/evidence   the accountability fabric, staged not assumed
```

The ontological categories behind these strata — substrate, product, protocol,
definition, durable object, authority, evidence, projection, faculty — are
owned by [`term-boundaries.md`](../foundations/term-boundaries.md). One rule
from that owner matters constantly: Hypervisor is both a product family and a
substrate, and prose must say which.

## The Whole Stack, Top To Bottom

```text
Goal Space (ioi.ai)
  durable goals, subscriptions, budgets, collaboration, replay, outcome UX
  -> OutcomeRoom / CollaborativeWorkGraph when shared pursuit is useful
     -> one or more bounded GoalRuns
        -> one immutable GoalRunProfile resolution per GoalRun
        -> Goal Kernel interprets it through GoalGroundingLoop and RoleTopology
           -> ContextCells, claims, leases, typed handoffs, attempts
              -> HarnessInvocations, Workers, tools, and services

Hypervisor
  one control plane across hosted, attached-estate, and node-root deployments,
  with conventional compute and governed-autonomy capabilities selected independently
  -> Hypervisor Daemon admits and mediates effects
  -> Agentgres records admitted operational truth
  -> artifact/storage planes hold governed payloads
  -> wallet.network and local/domain policy supply authority

One bounded DAS across admitted nodes
  one system_id / constitution / operational truth
  -> RuntimeAssignments bind GoalRuns and roles to governed node memberships
  -> execution, state, verification, gateway, and embodied roles coordinate
  -> partitions, reassignment, failover, replay, and duplicate effects follow policy

Local semantic world planes with optional federation
  local Domain Ontologies, assertions, overlays, and action contracts
  <-> explicit crosswalks and challengeable mapping decisions after accepted terms
  <-> optional AIIP signed handoffs between bounded execution domains

Sparse public coordination
  local work stays local by default
  -> explicit ioi_compatible / ioi_connected / ioi_secured enrollment
  -> IOI L1 only for selected rights, registry, assurance, security, economic,
     dispute, governance, or cross-domain commitments
```

This is not a choice between a “hypervisor app” and a decentralized enterprise
ontology. Hypervisor is the execution and operating substrate; Goal Space and
the semantic/collaboration planes are how many intelligences and domains use
that substrate to converge on open or private outcomes.

Do not try to memorize the middle of this diagram yet. Chapter 02 walks one
action through it; chapters 03–05 then zoom out one layer at a time, and each
name above is introduced where its reason to exist becomes visible.

## Owners For This Chapter

- [`core-clients-surfaces.md`](../components/hypervisor/core-clients-surfaces.md)
  — Hypervisor product taxonomy, clients, workspaces, and application surfaces.
- [`foundry.md`](../components/hypervisor/foundry.md) — Foundry, the capability
  factory owner application.
- [`term-boundaries.md`](../foundations/term-boundaries.md) — ontological
  categories and protected terms.
- [`web4-and-ioi-stack.md`](../foundations/web4-and-ioi-stack.md) — the full
  reference stack and system boundary.
- [`README.md`](../README.md) — the canonical stack block and the complete
  ownership index.
