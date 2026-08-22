# 06 — The Products, Mapped Onto The Architecture

Status: architecture guide chapter (non-owning synthesis).
Canonical owner: this file for the reading order and narrative sequencing of
the product-to-architecture mapping only; every subject is owned by the linked
owner doc, which wins on any point of substance.
Supersedes: none (originates no doctrine).
Superseded by: none.
Last alignment pass: 2026-08-16.
Doctrine status: canonical
Implementation status: mixed (narrative over built, partial, planned, and
speculative subjects; status truth lives in
[`canon-to-code-delta.md`](../_meta/canon-to-code-delta.md) and the
[`work-items/`](../_meta/work-items/) records)
Last implementation audit: 2026-08-16

By this point every product can be introduced as a projection over machinery
you already understand, rather than as a list to memorize. The strata from
chapter 01 apply throughout: products contain applications; clients operate
cores; substrates and protocols sit beneath everything.

## Hypervisor

Hypervisor is the governed autonomy substrate where work becomes reusable
capability — and, per
[`term-boundaries.md`](../foundations/term-boundaries.md), it is both a
product family and a substrate, so prose must always say which. Its owner,
[`core-clients-surfaces.md`](../components/hypervisor/core-clients-surfaces.md),
states the boundary this guide's hierarchy hangs on:

> Hypervisor runs governed autonomous work. Foundry builds models, workers,
> evals, datasets, ontology-bound packages, deployment candidates, and admitted
> experimental runs. ioi.ai asks and conducts subscribed Goal Spaces.

Three structural facts to hold onto:

- **One Core, many clients.** Hypervisor App, Hypervisor Web, and CLI/headless
  are first-class clients over one Hypervisor Core; a TUI is an optional
  presentation of the CLI/headless client. Clients never own runtime truth —
  the daemon remains the execution owner inside Core.
- **Applications live inside the product.** The owner applications (the
  authoritative list, including Studio, Foundry, Governance, Provenance, and
  Developer Workspace, is owned by
  [`core-clients-surfaces.md`](../components/hypervisor/core-clients-surfaces.md))
  and the Environments and Operations substrate applications are projections
  over Core. Conceptually the suite divides into running work, operating
  substrate, and **building capability** — and the builder seat is
  [`foundry.md`](../components/hypervisor/foundry.md), "the capability factory
  for governed autonomous systems," where observed work becomes reusable
  models, workers, evals, datasets, routes, and packages. Foundry is an owner
  application within Hypervisor, never a sibling product; Evaluations owns
  judgment and Governance owns release decisions.
- **Posture is declared, not implied.** Every released profile declares
  controller deployment, resource relationship, and enabled autonomy
  capabilities as separate nonexclusive facets. Type 1 and Type 2 are external
  market mappings earned only by exact profile evidence; “Type 3” is qualified
  IOI shorthand for the autonomy plane, not a standardized successor VMM
  category.

Project and environment convenience stays proposal-mediated: discovery
produces a non-authoritative proposal and executes no source, installs
nothing, grants no authority, and starts no environment; explicit acceptance
creates Project and recipe lineage; admission may then produce a startup plan.
Owner:
[`providers-and-environments.md`](../components/hypervisor/providers-and-environments.md).

The standalone contract from chapter 01 compresses into one product journey.
The local product target makes that contract visible as one shared, non-object
zero-to-operable journey across App and CLI/headless: verify and preview the
selected release; install; bootstrap deployment-local identity and authority;
start the client, daemon, and declared Agentgres posture; pass bounded
readiness; inspect status, doctor findings, and logs; update or roll back
through an admitted change plan; stop or uninstall without implicit wipe; and
back up, export, or restore through the owning contracts. It is distinct from
zero-to-idle and from one environment StartupPlan. The current estate has not
yet passed this end-to-end product proof.

## ioi.ai — Goal Space

ioi.ai enters the story last among the first-party surfaces, deliberately: per
[ADR 0022](../../decisions/0022-goal-orchestration-application-layer-and-clean-slate.md)
there are three layers here, not one. The substrate executes and records; the
**orchestration application** — the goal/room domain of chapters 03–04 — is
openly packaged and deployable on any Hypervisor with no ioi.ai account; and
**ioi.ai the managed product** is the hosted offering of that same
application: accounts, subscription, Goal Space UX, pre-admission drafts, read
projections, and synthesis. It holds no privileged substrate semantics and its
projections never become a competing source of truth.

As a product, ioi.ai should sell one coherent Goal Space subscription rather
than a bundle of pooled model seats. The subscription includes persistent
conductor state, portable memory, private and organization goals, governance,
collaboration, receipts, replay, and a bounded grant of non-transferable Work
Credits.

Managed model and runtime supply is a portfolio:

- direct provider APIs, dedicated capacity, and negotiated inference;
- replaceable aggregators such as OpenRouter for breadth and discovery;
- customer BYOK or provider-approved user-scoped BYOA;
- open-weight, local, customer-boundary, and self-hosted routes.

Every route resolves a versioned commercial and technical rights contract.
Named-human ChatGPT, Claude, or similar subscriptions are not pooled
production worker capacity. Missing automation, downstream, OEM/reseller,
data, region, credential-principal, provider-use, retention, or
customer-output-use rights fail closed.

The user controls independent axes:

- execution/custody: `Standard` or `Private`;
- goal routing: `Auto`, `Pinned`, or `Compare`;
- contributors: `My workers`, `Organization`, or `Network / Open`;
- placement: local, customer infrastructure, selected cloud, or Hypervisor
  choice.

Network/Open contribution uses a separate funded goal budget, bounty,
procurement cap, or sas.xyz service order. It must not silently burn an
ordinary seat allowance. Owners:
[`collaborative-outcome-pattern.md`](../domains/ioi-ai/collaborative-outcome-pattern.md),
[`control-plane.md`](../domains/ioi-ai/control-plane.md),
[`economic-flywheel-and-pricing-boundaries.md`](../foundations/economic-flywheel-and-pricing-boundaries.md).

## wallet.network

wallet.network is the authority layer met at chapter 02's fourth step, as a
product: identity, secrets, authority-scope grants, approvals, payments,
exchange authority, and revocation for delegated machine power. Its product
doctrine is one line — **agents do not get secrets; they get authority leases**
— and it usually appears to users as SSO, permissions, connected access, and
approval review embedded in the product they already use, with the
wallet.network name reserved for advanced, high-trust, and protocol contexts.
It authorizes power; it does not do the work, store the app, or become the
chain. Owner: [`doctrine.md`](../components/wallet-network/doctrine.md).

## Agentgres — And Why MemorySpace Is Not It

Agentgres is chapter 02's admitted-truth substrate as a named component:
operation-backed, head-addressed, replayable domain truth with a Postgres
bridge — "Git versions code; Agentgres versions autonomous work." Keep it
distinct from **MemorySpace / Agent Wiki**, the portable governed memory plane:
what an agent can know and retrieve is memory-plane state, while what became
canonical, authorized, and replayable is Agentgres admission. Adapter-local
memory is cache, never the durable brain. Owners:
[`doctrine.md`](../components/agentgres/doctrine.md),
[`portable-memory-vault.md`](../components/daemon-runtime/portable-memory-vault.md).

## aiagent.xyz And sas.xyz

The two marketplaces sit on the network edge of chapter 05, as first-party
applications of AIIP and selected settlement — never the protocol itself.
aiagent.xyz is the worker marketplace: discovery, procurement, installation,
benchmarks, managed instances, and routing eligibility for ontology-bound
digital and embodied workers. sas.xyz is the service/outcome marketplace:
orders, escrow, milestones, acceptance, disputes, and provider reputation.
The canonical line is owned by [`aiip.md`](../foundations/aiip.md): the
marketplace is a first-party application of the protocol. Owners:
[`worker-marketplace.md`](../domains/aiagent/worker-marketplace.md),
[`service-marketplace.md`](../domains/sas/service-marketplace.md),
[`marketplace-neutrality.md`](../domains/marketplace-neutrality.md).

## IOI Network And L1

Not an install but an enrollment, exactly as chapter 05 left it: compatible
systems owe nothing; connected systems pay for selected services; secured
systems buy named shared-security coverage under explicit terms and bonds.
Owner: [`ioi-l1-mainnet.md`](../foundations/ioi-l1-mainnet.md).

## Owners For This Chapter

- [`core-clients-surfaces.md`](../components/hypervisor/core-clients-surfaces.md)
  — Hypervisor's product taxonomy, clients, and application surfaces.
- [`foundry.md`](../components/hypervisor/foundry.md) — the capability factory.
- [`doctrine.md`](../components/wallet-network/doctrine.md) — wallet.network.
- [`doctrine.md`](../components/agentgres/doctrine.md) — Agentgres.
- [`collaborative-outcome-pattern.md`](../domains/ioi-ai/collaborative-outcome-pattern.md)
  and [`control-plane.md`](../domains/ioi-ai/control-plane.md) — ioi.ai.
- [`worker-marketplace.md`](../domains/aiagent/worker-marketplace.md) and
  [`service-marketplace.md`](../domains/sas/service-marketplace.md) — the
  marketplaces.
- [`economic-flywheel-and-pricing-boundaries.md`](../foundations/economic-flywheel-and-pricing-boundaries.md)
  — Work Credits and pricing boundaries.
