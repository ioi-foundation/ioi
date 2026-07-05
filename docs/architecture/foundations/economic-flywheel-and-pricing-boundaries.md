# Economic Flywheel and Pricing Boundaries

Status: canonical architecture authority.
Canonical owner: this file for stack-wide monetization boundaries, open
substrate / paid network doctrine, verified work graph economics, Work Credit
usage abstraction, marketplace fee legitimacy, substrate bundling, wallet.network
value-flow revenue boundaries, Agentgres pricing non-boundaries, and token/BME
timing.
Supersedes: product or plan prose that turns every protocol surface, authority
check, receipt, state write, or builder surface into a separate toll booth.
Superseded by: none.
Last alignment pass: 2026-06-28.
Doctrine status: canonical
Implementation status: mixed (fee-basis declarations and OCU metering built; Work Credits, marketplace fees, and token/BME planned or deferred)
Last implementation audit: 2026-07-05

## Canonical Thesis

**Product surfaces monetize. Substrate layers meter, prove, authorize, record,
or settle only where they naturally carry value.**

IOI should capture value when the user receives a product outcome, managed
execution, marketplace distribution, commercial trust, or financial value flow.
It should not invent separate pricing models merely because an internal
primitive exists.

The primary alpha is **network effects plus governed trust**. The code may be
open source and user execution may be BYOM, BYOA, self-hosted, customer-cloud,
or local-first. The durable asset is the **Verified Work Graph**: the
receipt-backed record of who did what, under which authority, with which
worker/harness/model/tool stack, at what cost, with what eval result, for whom,
and whether that evidence is reusable for routing, reputation, settlement,
promotion, or dispute resolution.

Short form:

> Charge for useful autonomous work, managed capability, distribution, trust,
> and value movement. Bundle the substrate that makes those safe.

Category form:

```text
Open substrate. Paid network.
Your model, your cloud, your tools, your authority.
IOI monetizes coordination, governed trust, distribution, verified outcomes,
managed convenience, and value movement.
```

## Verified Work Graph

The Verified Work Graph is the economic memory of the network. It is assembled
from:

- WorkRuns, sessions, attempts, branches, automations, service orders, and
  delivery bundles;
- worker, harness, model, tool, connector, MCP, provider, route, and runtime
  identities;
- authority grants, policy decisions, approval state, revocation state, and
  privacy posture;
- receipts, ContributionReceipts, RoutingDecisionReceipts, BenchmarkReceipts,
  EvaluationReceipts, payout records, dispute records, and state-root refs;
- cost, latency, quality, verifier, SLA, failure, retry, promotion, rollback,
  and recall evidence;
- marketplace listing, install, invocation, managed-instance, procurement, and
  service-delivery history.

The graph is not a single database, chain, or UI. Agentgres-backed domains keep
operational truth; product surfaces render projections; marketplaces consume
attribution and reputation; wallet.network supplies authority and value-flow
receipts; IOI L1 anchors selected public/economic commitments when portability,
settlement, reputation, rights, or disputes require it.

The graph is the moat because it improves:

- route calibration;
- worker and service reputation;
- benchmark and eval credibility;
- marketplace trust;
- enterprise auditability;
- dispute resolution;
- capability promotion;
- user confidence that autonomous work is attributable, replayable, revocable,
  and economically settleable.

## Stack Economic Roles

| Layer | Economic role | Boundary |
| --- | --- | --- |
| Hypervisor | Main product shell, managed runtime, application surfaces, Foundry, Workbench, Automations, Environments, ODK, Governance, Operations, Work Ledger, Developer & Integrations, and related managed compute | Monetizes subscriptions, managed execution, enterprise/private deployment, and Work Credit usage. Foundry is a Hypervisor surface and usage lane, not a separate top-level business by default. |
| ioi.ai | Intent-to-outcome conductor over Hypervisor, marketplace workers, connectors, sessions, and verifier lanes | Monetizes subscription and conductor usage. It spends Work Credits through Hypervisor and markets rather than owning a separate runtime pricing model. |
| aiagent.xyz | Capability marketplace for benchmarked, installable, attributable workers and managed worker instances | Monetizes admission, benchmarks, certification, managed instances, invocation, distribution, licensing, procurement, and take-rate only where it supplies real demand, trust, hosting, or settlement. |
| sas.xyz | Outcome marketplace for delivered autonomous services and Worker Training as Service-as-Software | Monetizes escrow, orders, milestones, SLAs, disputes, procurement, delivery acceptance, and take-rate where it provides commercial trust and demand. |
| wallet.network | Authority wallet, credential broker, approvals, recovery, exchange/trade/provider authority, payments, swaps, and value movement | Ordinary authority, connector approval, provider credential custody, resource-spend approval, and IAM-style grants are infrastructure bundled into products. Revenue capture belongs mainly to swaps, trades, payments, exchange, settlement assistance, protection, or other value-flow actions. |
| Agentgres | Per-domain operational truth substrate, receipt/state/projection substrate, and Postgres-like compatibility layer | Not a separate pricing surface in the first-party stack. It records economics and may support optional managed infrastructure offerings, but routine Agentgres writes, refs, and projections are bundled substrate. |
| IOI L1 | Public registry, rights, reputation, settlement, dispute, sparse commitments, and governance layer | Protocol fees apply only at public coordination, settlement, registry, dispute, reputation, rights, bond, or economic-finality boundaries. It is not charged per model thought, local workflow node, routine receipt, or Agentgres write. |

## Work Credits

`WorkCredit` is the broad product usage and budget abstraction for managed
autonomous work across Hypervisor, ioi.ai, aiagent.xyz, sas.xyz, and related
first-party product flows.

Work Credits may meter or budget:

- model calls and model-route usage;
- managed runtime, VM, microVM, container, GPU, browser, terminal, and
  environment time;
- connector, MCP, external API, and provider calls;
- Private Workspace, cTEE, TEE, customer-boundary, confidential, or
  no-provider-trust managed runtime posture;
- storage, replay, archive, restore, proof, and audit export usage when those
  create managed cost;
- Foundry training, eval, dataset, experiment, conversion, endpoint, and
  package jobs;
- Hypervisor Automations and background missions;
- ioi.ai conductor runs, multi-path attempts, verifier lanes, and synthesis;
- aiagent worker invocation, managed worker instance runtime, benchmark, and
  certification jobs;
- sas service execution, verifier work, delivery bundles, and dispute evidence
  processing.

Work Credits are not necessarily the final settlement asset. Worker, service,
provider, and verifier payouts may settle through fiat, stablecoins, IOI, or
other approved rails depending on jurisdiction, product posture, and settlement
readiness.

BYOK, BYOA, customer-VPC, customer-cloud, self-hosted, or local execution should
not be double-charged for provider costs already borne by the customer.
Hypervisor may still charge for orchestration, governance, managed control
plane, support, audit, marketplace distribution, or enterprise features.
Self-hosted and local-first execution remain first-class. Managed execution is
convenience, not captivity.

## Legitimate Revenue Surfaces

Revenue is legitimate when it attaches to at least one of these:

1. Managed execution cost or reserved capacity.
2. User-visible product value or labor saved.
3. Marketplace distribution, demand aggregation, trust, procurement, licensing,
   or settlement.
4. Benchmarks, certification, conformance, or assurance that prevent spam,
   improve routing, or create commercial trust.
5. Escrow, SLA, dispute, insurance-routing, audit export, procurement, invoice,
   or customer-facing commercial operations.
6. Financial value movement such as swaps, trades, payments, exchange,
   settlement, protection, or treasury operations.
7. Enterprise/private deployment, cTEE/TEE/customer-boundary runtime,
   no-provider-trust execution posture, compliance posture, managed support,
   retention, data residency, or administrative control.
8. Public coordination that requires IOI L1 registry, rights, reputation,
   dispute, bond, or settlement commitments.
9. Verified route selection, calibrated worker/harness/model matching, verifier
   routing, or marketplace/service matching that uses network evidence and
   produces a challengeable receipt.

If none of those applies, the feature should usually be bundled into the
product surface that depends on it.

## Product Surface Guidance

### Hypervisor

Hypervisor is the main paid operating environment. Its clean pricing axis is:

- subscription or seat for the product shell and collaboration;
- included Work Credits for ordinary managed work;
- pay-as-you-go or committed Work Credits for heavy model, compute, training,
  connector, GPU, storage, replay, and automation usage;
- enterprise/private deployment for customer-boundary runtime, compliance,
  support, retention, and administrative control;
- BYOK/BYOA/provider-pass-through posture where customer provider spend is
  transparent and platform fees attach to orchestration and governance, not
  hidden provider markup.

Runtime placement should be productized as four user-facing choices:

```text
Run local
Use my infrastructure
Pick a cloud
Let Hypervisor choose
```

Those choices map onto three economic placement sources underneath:

```text
connected infrastructure
  local or user-owned provider accounts

managed infrastructure
  IOI or partner provider-of-record capacity

optimized placement
  Hypervisor compares, routes, procures, fails over, reconciles, or aggregates
  providers, optionally using decentralized.cloud as the resource-candidate
  engine
```

The pricing boundary follows what Hypervisor actually does:

```text
Run local
  user's machine, local sandbox, local KVM, or HypervisorOS node
  no external provider spend exists
  paid value may attach to the control plane, collaboration, memory, Work
  Ledger, governance, receipts, support, and enterprise features

Use my infrastructure
  user's provider, user's bill
  no percentage fee on direct self-managed provider spend
  paid value may attach to the control plane, setup, credential binding,
  preflight, templates, snapshot custody, restore, monitoring, governance,
  audit, support, and collaboration
  if Hypervisor brokers credentials, provisions, manages leases, snapshots,
  restores, tracks cost, emits receipts, or tears down resources, a visible
  adapter/orchestration fee is legitimate

Pick a cloud
  user selects a specific venue or provider
  if Hypervisor executes provider lifecycle on the user's behalf, a visible
  orchestration/platform fee is legitimate
  if the user directly connects outside Hypervisor and Hypervisor only observes,
  percentage-of-spend fees are not legitimate

Hypervisor managed infrastructure
  IOI or a partner is provider-of-record
  Work Credits, reserved capacity, managed runtime margin, and support margin
  are legitimate because IOI bears procurement, operation, support, or capacity risk

Optimized placement
  Hypervisor may use decentralized.cloud or other candidate sources to compare,
  route, procure, fail over, reconcile, or aggregate provider billing
  a visible routing/procurement fee is legitimate only when it creates routing
  value and produces challengeable placement/routing evidence
```

Do not charge because "a VM exists." Charge because Hypervisor provides the
governed operating environment around that VM: policy, identity, memory,
Work Ledger, release controls, rollback, restore, audit, routing evidence,
team collaboration, private custody, and the Verified Work Graph.

Canonical fee doctrine:

```text
Choice is the trust layer.
Optimization is the paid convenience layer.
Receipts make the economics challengeable.

Direct local / direct BYO:
  subscription or control-plane value

Pinned provider through Hypervisor:
  adapter, orchestration, custody, lifecycle, support, or audit fee

Optimized placement:
  routing, procurement, comparison, failover, or aggregation fee

Managed infrastructure:
  Work Credits, margin, support, reserved capacity, or provider-of-record fee
```

Foundry is priced as Hypervisor usage and capability-building work. Do not turn
Foundry into a separate top-level business by default unless the product is
later intentionally sold as a standalone hosted capability factory.

### ioi.ai

ioi.ai monetizes the conductor experience:

- subscription for persistent goal orchestration and account experience;
- included Work Credits for routine tasks;
- additional Work Credits for multi-session, multi-model, marketplace-worker,
  connector-heavy, verifier-heavy, or long-running work;
- enterprise plans for managed organizational conductors, policy, audit,
  retention, connector governance, and private runtime boundaries.

ioi.ai should use Hypervisor as the execution/control substrate and marketplaces
as supply/delivery layers. It should not create a private runtime pricing model
that bypasses Hypervisor, Agentgres, wallet.network, aiagent.xyz, sas.xyz, or
IOI L1 boundaries.

ioi.ai may charge for orchestration when it coordinates across the network:
multi-worker pursuit, marketplace sourcing, verifier routing, connector
escalation, settlement handoff, evidence synthesis, or managed execution. It
should not tax a user for a direct local run that uses only the user's own
model, cloud, tools, and authority envelope without IOI network selection or
managed service.

The user-facing managed execution selector has only two modes: `Standard` and
`Private`. `Standard` is still private-native at the operating-substrate layer
for IOI-managed execution: cTEE / Plaintext-Free Runtime Mounting, scoped
authority, connector vaulting, and receipts are baseline discipline, while
provider-trust model routes may be allowed with disclosure. `Private` adds the
stronger promise: no-provider-trust model routing for protected data through
open-weight or user-controlled models inside local, BYO private node,
customer-boundary/customer-cloud, cTEE, TEE, or another custody-proven route.

Private ioi.ai is a paid managed execution posture when IOI provisions or
brokers confidential/customer-boundary compute, TEE/private workspace custody,
protected connector processing, stricter no-provider-trust model routing,
encrypted storage, attestation/custody proof, audit/replay, or background
private work. The paid product is the managed private runtime, model-route
constraint, and proof obligations, not the abstract right to privacy.

Selecting `Private`, requesting protected connected-app processing, starting a
background connector automation, requiring no-provider-trust routing, or
exceeding included private/runtime budgets may trigger a product handoff for a
private workspace, BYO private node, customer-boundary deployment, enterprise
plan, or Work Credits. Merely connecting an app, granting ordinary connector
authority, or running local/BYOM/BYOA without IOI-managed private compute should
not trigger a generic connector tax.

### aiagent.xyz

aiagent.xyz may charge where it supplies market trust or operational value:

- listing admission when it pays for benchmark/eval compute and discourages
  spam;
- benchmark, certification, and conformance execution;
- managed worker instance hosting and persistence;
- worker invocation, licensing, and metered usage;
- marketplace take-rate on paid worker usage, installs, subscriptions,
  procurement, or managed instance revenue;
- optional promotion only when clearly separated from benchmark/routing
  quality and not pay-to-win.

Routing eligibility must remain based on declared policy, benchmark evidence,
receipt completeness, quality, cost, privacy, runtime posture, reputation, and
user preference. Fees must not silently buy ranking, router preference, or
worker appropriation.

aiagent.xyz should make benchmark/eval posture and verified work history default
listing metadata. Listings without evidence may exist as drafts or unverified
packages, but routing, reputation, and managed-instance trust must be earned
through receipts, evals, and successful work.

### sas.xyz

sas.xyz may charge where it provides outcome-market operations:

- order fees, escrow, milestone processing, or take-rate;
- SLA, dispute, acceptance, procurement, invoice, and customer-facing audit
  surfaces;
- provider subscriptions for managed service operations;
- verifier, delivery-bundle, or claims/evidence processing when material;
- Worker Training as Service-as-Software when the buyer purchases a trained,
  benchmarked, policy-bound worker outcome rather than raw compute.

sas.xyz owns service monetization, tenant operations, order lifecycle, billing
posture, and commercial delivery state for productized services. Hypervisor may
author, promote, or run capabilities, but sas.xyz is the service marketplace
where autonomous outcomes are sold.

### wallet.network

wallet.network should not become a fee layer on every permission, approval,
connector binding, key shard, credential lease, or authority grant. Those are
core safety infrastructure.

wallet.network revenue capture should concentrate on:

- swaps and exchange;
- trades, prediction/event-market exposure, and advanced financial actions;
- payments and settlement assistance;
- protection actions, recovery, insurance-adjacent routing, or treasury
  services where value movement or risk management is the product;
- enterprise authority cockpit packaging where the product is the managed
  authority experience, not a per-approval tax.

### Agentgres

Agentgres is analogous to Postgres in the first-party stack: it is essential
infrastructure and may be exposed through managed offerings, but it should not
be modeled as a separate pricing product for routine first-party use.

Agentgres may record:

- usage receipts;
- ContributionReceipts;
- payout, royalty, and dispute state;
- billing and entitlement projections;
- cost-center refs and commercial assurance exports;
- settlement evidence and state roots.

Recording economic truth does not make Agentgres the monetization surface.

## Routing Fee Covenant

Routing fees are legitimate only when the platform creates visible routing
value beyond direct local execution. Acceptable cases include:

- marketplace discovery and matching;
- cross-worker, cross-service, or cross-harness selection;
- verifier routing and challengeable route evidence;
- managed connector brokerage;
- one-click provider execution or runtime placement;
- pinned-provider execution where Hypervisor brokers credentials, provisions,
  manages leases, snapshots, restores, tracks cost, emits receipts, tears down,
  or otherwise performs provider lifecycle work on behalf of the user;
- escrow, settlement, payout splitting, licensing, or dispute support;
- service procurement, SLA enforcement, or customer-facing delivery operations.

Provider adapter/orchestration fees are allowed for pinned or BYO venues when
Hypervisor performs lifecycle work. They should be labelled as orchestration or
platform fees, not hidden inside provider spend and not misrepresented as
optimized routing unless Hypervisor actually compares, routes, procures, fails
over, reconciles, or aggregates providers.

Routing fees are not legitimate for:

- a purely local BYOM/BYOA run that does not use IOI network matching;
- a self-hosted user invoking their own worker directly without marketplace
  distribution, managed hosting, or settlement;
- basic authority checks, local receipts, Agentgres writes, or local policy
  decisions;
- hidden platform preference for first-party workers;
- pay-to-route behavior that overrides benchmark, receipt, privacy, cost, or
  user-preference signals.

Every paid routing decision that affects payment, reputation, settlement,
dispute posture, or marketplace rank should produce a challengeable
RoutingDecisionReceipt or equivalent evidence.

### IOI L1, Token, and BME

IOI L1 fees, token mechanics, and BME-like mechanisms should follow verified
work demand, marketplace liquidity, and real settlement needs.

Do not lead with a token before:

- Hypervisor produces meaningful verified work volume;
- ioi.ai spends credits into useful orchestrated work;
- aiagent.xyz and sas.xyz have real worker/service liquidity;
- ContributionReceipts, dispute flows, reputation, and settlement triggers have
  real demand;
- public commitments are valuable enough to justify L1 coordination.

Token or BME design should be treated as protocol-economics work after product
usage proves the demand curve. Until then, Work Credits are the cleaner product
abstraction.

## Anti-Patterns

Do not model:

- Agentgres as a priced product surface for every state write or projection;
- wallet.network as a per-approval, per-connector, or per-authority toll booth;
- Private mode as a cosmetic upsell without local, BYO private node,
  customer-boundary/customer-cloud, cTEE, TEE, or otherwise declared custody
  proof and no-provider-trust model routing;
- Foundry as a separate top-level business when it is functioning as a
  Hypervisor surface;
- IOI L1 gas on every model thought, workflow node, routine receipt, or local
  Agentgres operation;
- Work Credits as mandatory protocol tokens;
- marketplace routing as pay-to-win;
- generic routing fees on direct local/self-hosted execution that does not use
  IOI network matching, managed hosting, settlement, or marketplace
  distribution;
- BYOK/BYOA usage as hidden provider markup;
- aiagent.xyz listings as generic chatbot cards without benchmarks, receipts,
  runtime posture, authority requirements, or managed-instance clarity;
- sas.xyz take-rate without escrow, SLA, procurement, billing, dispute,
  delivery, or commercial trust value;
- separate SKUs for every internal primitive merely because it can be metered.

## Conformance Questions

Before adding a fee, subscription gate, credit meter, token mechanic, or
marketplace take-rate, ask:

1. What product outcome or commercial trust does the user receive?
2. Which surface owns the customer relationship?
3. Is this real managed cost, distribution, value movement, settlement, or
   enterprise assurance?
4. Is the fee attached to a product surface rather than a substrate primitive?
5. Does it preserve BYOK/BYOA/customer-infra transparency?
6. Does it avoid pay-to-win routing or benchmark corruption?
7. Does it preserve wallet.network as authority infrastructure and value-flow
   cockpit, not an IAM toll booth?
8. Does it preserve Agentgres as truth substrate, not a separate app business?
9. Does it delay token/BME design until verified work demand exists?
10. If this is a private upsell, does the product actually provide a declared
    custody posture, private workspace, local/BYO/customer-boundary/cTEE/TEE
    route, and no-provider-trust model routing rather than just a label?
11. Can the billing, receipt, payout, audit, and dispute trail be reconstructed
    from Agentgres refs, Work Credit ledgers, ContributionReceipts, wallet
    receipts, marketplace records, and IOI L1 commitments where applicable?

If the answer is unclear, bundle the primitive into the nearest product surface
and revisit after real usage evidence exists.

## Related Canon

- [`web4-and-ioi-stack.md`](./web4-and-ioi-stack.md): Web4 category and stack
  map.
- [`ioi-l1-mainnet.md`](./ioi-l1-mainnet.md): public settlement and gas
  boundaries.
- [`marketplace-neutrality.md`](../domains/marketplace-neutrality.md):
  contribution accounting and anti-cannibalization doctrine.
- [`aiagent/worker-marketplace.md`](../domains/aiagent/worker-marketplace.md):
  worker marketplace and managed worker instance doctrine.
- [`sas/service-marketplace.md`](../domains/sas/service-marketplace.md):
  service/outcome marketplace doctrine.
- [`wallet-network/product-exchange-risk.md`](../components/wallet-network/product-exchange-risk.md):
  wallet exchange/trade/provider authority and value-flow cockpit.
- [`agentgres/doctrine.md`](../components/agentgres/doctrine.md): Agentgres
  operational truth substrate.
