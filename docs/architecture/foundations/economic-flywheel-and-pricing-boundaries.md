# Economic Flywheel and Pricing Boundaries

Status: canonical architecture authority.
Canonical owner: this file for stack-wide monetization boundaries, Work Credit
usage abstraction, marketplace fee legitimacy, substrate bundling, wallet.network
value-flow revenue boundaries, Agentgres pricing non-boundaries, and token/BME
timing.
Supersedes: product or plan prose that turns every protocol surface, authority
check, receipt, state write, or builder surface into a separate toll booth.
Superseded by: none.
Last alignment pass: 2026-06-27.

## Canonical Thesis

**Product surfaces monetize. Substrate layers meter, prove, authorize, record,
or settle only where they naturally carry value.**

IOI should capture value when the user receives a product outcome, managed
execution, marketplace distribution, commercial trust, or financial value flow.
It should not invent separate pricing models merely because an internal
primitive exists.

Short form:

> Charge for useful autonomous work, managed capability, distribution, trust,
> and value movement. Bundle the substrate that makes those safe.

## Stack Economic Roles

| Layer | Economic role | Boundary |
| --- | --- | --- |
| Hypervisor | Main product shell, managed runtime, application surfaces, Foundry, Workbench, Automations, Environments, ODK, Governance, Operations, Work Ledger, Developer & Integrations, and related managed compute | Monetizes subscriptions, managed execution, enterprise/private deployment, and Work Credit usage. Foundry is a Hypervisor surface and usage lane, not a separate top-level business by default. |
| ioi.ai | Intent-to-outcome conductor over Hypervisor, marketplace workers, connectors, sessions, and verifier lanes | Monetizes subscription and conductor usage. It spends Work Credits through Hypervisor and markets rather than owning a separate runtime pricing model. |
| aiagent.xyz | Capability marketplace for benchmarked, installable, attributable workers and managed worker instances | Monetizes admission, benchmarks, certification, managed instances, invocation, distribution, licensing, procurement, and take-rate only where it supplies real demand, trust, hosting, or settlement. |
| sas.xyz | Outcome marketplace for delivered autonomous services and Worker Training as Service-as-Software | Monetizes escrow, orders, milestones, SLAs, disputes, procurement, delivery acceptance, and take-rate where it provides commercial trust and demand. |
| wallet.network | Authority wallet, credential broker, approvals, recovery, exchange/trade authority, payments, swaps, and value movement | Ordinary authority, connector approval, credential custody, and IAM-style grants are infrastructure bundled into products. Revenue capture belongs mainly to swaps, trades, payments, exchange, settlement assistance, protection, or other value-flow actions. |
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
7. Enterprise/private deployment, compliance posture, customer-boundary
   runtime, managed support, retention, data residency, or administrative
   control.
8. Public coordination that requires IOI L1 registry, rights, reputation,
   dispute, bond, or settlement commitments.

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
- Foundry as a separate top-level business when it is functioning as a
  Hypervisor surface;
- IOI L1 gas on every model thought, workflow node, routine receipt, or local
  Agentgres operation;
- Work Credits as mandatory protocol tokens;
- marketplace routing as pay-to-win;
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
10. Can the billing, receipt, payout, audit, and dispute trail be reconstructed
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
  wallet exchange/trade authority and value-flow cockpit.
- [`agentgres/doctrine.md`](../components/agentgres/doctrine.md): Agentgres
  operational truth substrate.
