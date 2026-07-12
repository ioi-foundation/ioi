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
Last alignment pass: 2026-07-11.
Doctrine status: canonical
Implementation status: mixed (fee-basis declarations and flat OCU receipt metering built; invoice-grade multi-provider reconciliation, Work Credits, Goal Space allowances, marketplace fees, and token/BME planned or deferred)
Last implementation audit: 2026-07-11

## Canonical Thesis

**Product surfaces monetize. Substrate layers meter, attest, authorize, record,
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

Product thesis:

> **ioi.ai sells one seat-like Goal Space subscription: persistent conductor,
> policy, memory, receipts, replay, and same-domain 1-N worker orchestration,
> plus a bounded managed-work allowance. Genuine independent network labor is
> opt-in and separately funded.**

This is a seat-like outcome product, not a resale bundle of named-user
foundation-model subscriptions and not a separate SKU for every runtime node,
worker, verifier, or protocol primitive.

The margin thesis is not “buy tokens wholesale and resell them opaquely.”
Durable margin comes from the conductor, verified cascade and route savings,
governed runtime, memory/context continuity, private deployment and reserved
capacity, evidence and assurance, worker/service discovery, settlement support,
and successful outcome coordination. Inference remains a disclosed cost of
delivered work and may carry a visible managed-service margin; it is not the
defensible product by itself.

## Open Verification / Protected Network Covenant

The open/closed split is a trust boundary, not only a business preference.
Anything required to verify IOI's honesty must be inspectable and implementable
outside the hosted service. Anything whose value comes from network scale,
managed operations, distribution, routing intelligence, marketplace liquidity,
or provider risk may be protected and monetized.

Architecture doctrine, not legal license advice:

```text
open verification layer
  protocol contracts
  receipt schemas
  authority envelopes
  RoutingDecisionReceipt and fee-transparency covenant
  portable memory vault format
  Agentgres ref and object model
  provider / connector / harness adapter contracts
  SDK interfaces
  conformance tests

protected local runtime layer
  local Hypervisor core
  Agentgres runtime implementation
  wallet authority daemon
  provider adapter runtime
  self-host single-node stack

proprietary network / operations layer
  hosted ioi.ai
  managed Hypervisor compute
  private managed runtime
  routing and placement intelligence
  provider reliability scores
  cross-party Verified Work Graph aggregation
  marketplace ranking and reputation
  settlement, billing, procurement, and support rails
  enterprise / compliance control plane
```

The open verification layer should use permissive or standards-compatible
terms wherever adoption, third-party implementation, offline verification, or
challengeability is load-bearing. The protected local runtime layer may use
source-available or anti-rehosting terms when needed to keep large hosted
providers from reselling IOI's control plane as a commodity service. The
network/operations layer is the business: it compounds data, distribution,
managed execution, commercial trust, and routing value.

This covenant has two hard requirements:

1. A party must be able to verify its own receipts, authority envelopes,
   routing decisions, fee disclosures, state roots, and portable memory exports
   offline against open schemas and conformance fixtures. If verification
   requires hosted IOI, the claim is not truly verified.
2. The local/self-hosted core must be complete enough for one operator to run
   governed work on their own substrate. A crippled demo core is trust theater;
   managed IOI should win through convenience, routing intelligence,
   compliance, support, private runtime posture, and network effects.

Conformance is therefore a product pillar. Open adapter contracts without an
executable conformance suite invite fake integrations, hidden provider
semantics, and unverifiable receipts. IOI should treat conformance as the
certification surface for providers, workers, connectors, harnesses,
marketplaces, and managed runtime claims.

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

“Verified” is an assurance path, not a claim that every signed receipt is true
or valuable:

```text
receipt / attestation
  authenticated statement about one declared boundary fact
-> evidence bundle
  support for a claim
-> verification
  a named verifier applied a named rule/version
-> acceptance
  the user, customer, domain, or counterparty accepted the outcome
-> adjudication
  a challenge or dispute was resolved
-> settlement
  rights or value moved under the accepted/adjudicated claim
```

The graph preserves these states independently. A receipt may establish that a
request was admitted, a policy hash was evaluated, a tool reported an effect,
or a signer made an observation. It does not alone establish external-world
change, correctness, causality, customer value, or settlement eligibility.

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

## One Goal Space, Two Supply Lanes

The canonical commercial shape is one product experience with explicit supply
and owner boundaries:

```text
ioi.ai Goal Space subscription
  = conductor, persistent goal state, portable memory, policy, receipts,
    replay, collaboration, and ordinary support entitlement
  + bounded monthly grant of non-transferable Work Credits
  + provider-neutral Auto routing and disclosed route controls

additional managed work
  = Work Credit top-up, opt-in overage, or committed-spend drawdown

Network / Open participation
  = separately bounded goal budget, bounty, procurement limit, or sas.xyz
    service order for independent workers, verifiers, services, challenge,
    and settlement

Enterprise / Private
  = seats plus committed managed-work spend, customer-boundary/private
    runtime, reserved capacity, administration, governance, audit, SLA,
    retention, residency, and support
```

### Subscription-Backed Lane

The base Goal Space includes persistent conductor/account state, private and
organization goals, direct and same-domain 1-N worker execution, receipts,
replay, memory, collaboration, budgets, governance, a modest managed-work
allowance, BYOM/BYOK/BYOA/local/customer-infrastructure routes, and the
`Standard` / `Private` policy semantics.

`Private` availability does not promise that IOI-provisioned confidential
compute, customer-boundary custody, attestation, or reserved capacity is free
inside every seat. Where IOI supplies those resources or proof obligations,
they consume Work Credits or require Private Workspace, committed capacity, or
an enterprise entitlement. Heavy multi-session, multi-model, connector,
training, storage, verifier, and background work consumes additional credits.
Unlimited managed multi-worker burn is not canonical because it creates
adverse selection, opaque subsidy, and unstable margin.

This lane may use GoalRun and OutcomeRoom coordination but remains one party
when one principal controls authority, truth, verification, and settlement.
Multi-model, multi-worker, and multi-node execution do not manufacture
multi-party federation.

### Network / Open Lane

Opening contributor scope to independent parties must:

- use a separate goal budget, bounty, procurement cap, or service order rather
  than silently spend the ordinary seat allowance;
- admit worker-provider and verifier domains through explicit room membership
  and bind `MultiPartyCollaborationEnvelope` when principals are actually
  independent;
- disclose worker affiliation, model/runtime dependencies, price, privacy,
  license/export, verification, assurance, and settlement posture;
- preserve each domain's local operational truth and use AIIP for signed,
  permitted handoffs and refs;
- separate execution, verification, acceptance, challenge/adjudication, and
  payout;
- emit routing and contribution receipts and preserve the product owners below.

ioi.ai may charge for real cross-worker selection, evidence synthesis, verifier
routing, and settlement handoff. aiagent.xyz retains worker-market fees;
sas.xyz retains service procurement, acceptance, SLA, and dispute economics;
Hypervisor retains managed execution charges. A single user-visible quote may
aggregate these records, but the underlying ledgers may not erase ownership.

### Orthogonal Product Controls

Privacy, participation, and placement are independent axes:

| Axis | Choices | Meaning |
| --- | --- | --- |
| Execution/custody | `Standard` or `Private` | Provider-trust disclosure, model-route, custody, and proof posture |
| Contributor scope | `My workers`, `Organization`, or `Network / Open` | Which accountable worker/provider domains may participate |
| Placement | `Run local`, `Use my infrastructure`, `Pick a cloud`, or `Let Hypervisor choose` | Where eligible work executes |

Contributor scope never declassifies data or weakens retention, authority,
provider-trust, custody, or privacy policy. Every candidate must satisfy the
intersection of Goal Space policy and its home-domain policy or remain
ineligible. Sell the governed goal, not physical node count: one logical domain
may schedule many workers across machines, providers, and failure domains.

## Work Credits

`WorkCredit` is the broad product usage and budget abstraction for managed
autonomous work across Hypervisor, ioi.ai, aiagent.xyz, sas.xyz, and related
first-party product flows.

Work Credits are non-transferable product credits, not cash, a speculative
token, a worker payout rail, or a claim on provider tokens. Monthly grants may
expire or reset by disclosed plan policy. Their job is to normalize
heterogeneous input, output, cached, reasoning, image, audio, tool, accelerator,
environment, storage, worker, and verifier costs into one budget while keeping
the underlying execution auditable.

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

The accountable charge is:

```text
Work Credits charged
  = model / accelerator / compute supplier cost
  + sandbox, storage, connector, environment, and replay cost
  + external worker, verifier, or service cost
  + declared IOI managed-work and orchestration charge
```

The rate card may simplify this for users, but the receipt ledger preserves at
least the actual Worker composition, model/provider/endpoint and route, price
schedule, token/compute categories where available, attempted and billed
fallbacks, verifier/escalation reason, supplier/broker cost class, IOI fee basis
and amount, adjustments/refunds, and total Work Credits. Direct BYOK normally
removes the provider-cost component while retaining explicit conductor,
runtime, governance, or support charges.

`Auto` / `1-of-N`, `Pinned`, and `Compare` / `N-of-N` are routing policies, not
plan tiers. Auto may use a verified cheap-first cascade and escalate only on
failure. Pinned fails closed on an unavailable or commercially/privacy-
ineligible route unless fallback was authorized. Compare visibly accounts for
all admitted attempts, verifier work, and synthesis. Quotes and caps should be
available before expensive or externally procured work.

## Open Supply And Foundation-Model Procurement

IOI must reproduce the simplicity of broad seat access without pooling,
sharing, browser-automating, or reselling named-user chat/workspace subscription
limits as production worker capacity. Public provider contracts separate
interactive subscriptions from API capacity and commonly prohibit account
credential sharing or resale. A negotiated order form may grant broader rights;
the signed commercial posture, not an assumed public default, controls.

The canonical procurement hierarchy is:

1. open/self-hosted weights where operationally and legally suitable;
2. provider APIs or managed cloud endpoints;
3. dedicated capacity or negotiated inference agreements for volume, SLA,
   retention, residency, or data posture;
4. explicit OEM/reseller authorization when IOI exposes near-raw provider
   capability;
5. named-human workspace seats only for internal operators or expressly
   provider-approved user-scoped interactive harnesses.

The durable portfolio is intentionally plural:

| Supply source | Preferred role | Economic and trust posture |
| --- | --- | --- |
| Direct provider API, managed endpoint, or negotiated inference agreement | Core/high-volume routes, feature fidelity, negotiated economics, regional/privacy commitments, dedicated capacity, high assurance | First-class adapter and direct receipt; graduate proven volume here |
| Aggregator such as OpenRouter | Bootstrap breadth, long-tail models, price/availability discovery, policy-qualified fallback, overflow, experimentation | Replaceable procurement/routing adapter, never the product moat or sole inference authority; obtain enterprise/OEM interpretation where IOI's provider-neutral routing could approach prohibited raw resale/competition |
| Customer BYOK/BYOA | Customer cost ownership, existing commitments, user-selected interactive harnesses, enterprise control | Customer-owned credential binding; explicit IOI conductor/runtime/governance charges instead of hidden spend markup |
| Open/self-hosted weights | No-provider-trust execution, sovereignty, customization, training/distillation rights, concentration and COGS hedge | Hypervisor-managed or customer-boundary execution with explicit model license, custody, and attestation posture |

An aggregator does not erase model/provider terms, commercial rights, data
handling, availability risk, or semantic differences. Default provider or model
fallbacks are too fail-open for governed sensitive work. Eligible routes pin or
allowlist providers, required parameters, data-collection/ZDR and region policy,
maximum price, fallback classes, and verifier obligations. An aggregator ZDR
flag may qualify a disclosed `Standard` route; it does not satisfy strict
`Private` / no-provider-trust posture without a custody-proven direct,
dedicated, local, or customer-boundary route.

Every candidate route resolves the versioned
[`ModelRouteRightsContract`](../components/model-router/doctrine.md#supply-portfolio-and-route-rights)
before unattended or customer-facing admission. The model-router owner defines
the schema and enums. Economic admission requires its `commercial_posture`,
`contract_version`, `contract_hash`, `admitted_policy_hash`, validity window,
`status`, `access_mode`, `customer_facing_allowed`, `reseller_oem_authorized`,
`automation_right`, `downstream_right`, `credential_principal`,
`provider_terms_version_ref`, `model_terms_version_ref`, `endpoint_ref`,
`model_version_ref`, `provider_allowlist`, `data_collection`, `zdr_required`,
`retention_policy_ref`, `region_ref`, `fallback_classes`, `max_price_ref`,
`required_parameters`, and `output_training_right` fields; pricing code must not
invent a reduced parallel contract.

Missing rights fail closed. A provider/model fallback is a semantic substitution
and must remain within this contract, emit routing evidence, and re-run the
applicable verifier/acceptance path. Inference rights and training/distillation
rights are separate; Foundry uses open weights or expressly licensed teacher
agreements rather than inferring training rights from ordinary inference spend.

Primary current provider boundaries informing this doctrine include the
[OpenAI Services Agreement](https://openai.com/policies/services-agreement/),
[OpenAI subscription/API separation](https://help.openai.com/en/articles/8156019),
[Anthropic paid-plan/API separation](https://support.claude.com/en/articles/9876003-i-have-a-paid-claude-subscription-pro-max-team-or-enterprise-plans-why-do-i-have-to-pay-separately-to-use-the-claude-api-and-console),
and OpenRouter's [pricing](https://openrouter.ai/pricing),
[BYOK](https://openrouter.ai/docs/guides/overview/auth/byok),
[routing](https://openrouter.ai/docs/guides/routing/provider-selection),
[fallback](https://openrouter.ai/docs/guides/routing/model-fallbacks),
[ZDR](https://openrouter.ai/docs/guides/features/zdr), and
[terms](https://openrouter.ai/terms/) documentation. Public fees and defaults
are procurement inputs that can change, never customer-plan promises.

## Commercial Activation Gates

The target product is not a claim that current metering safely supports a paid
multi-provider allowance. As of the implementation audit for this alignment
pass, the live OCU slice charges `0.1` OCU for every model-backed receipt
without reconciling provider, input/output/cache/reasoning classes, retries, or
supplier invoice. The model-route overview declares sealed BYOK unimplemented
and only Ollama-transport routes bindable for session execution. Work Credits,
marketplace fees, and the Goal Space allowance remain planned.

Before attaching a fixed managed-work allowance, IOI needs invoice-grade
reconciliation for:

- endpoint, provider, model, route, and price-schedule version;
- uncached input, cache write/read, visible output, reasoning, image, audio,
  tool, accelerator, environment, storage, and other billed categories exposed
  by the supplier;
- every attempted route, outcome/failure class, fallback, escalation, and which
  attempts the supplier billed;
- estimated cost, reserved budget, finalized supplier cost, external broker
  fee, IOI fee basis and amount, refund/adjustment, and receipt refs;
- organization and goal caps, concurrency/child-agent/runtime limits,
  background-work policy, and explicit overage/top-up consent.

The commercial sequence is:

1. reconcile internal route-attempt telemetry against supplier statements;
2. run a prepaid, capped beta without upstream model-quality or availability
   promises;
3. introduce a seat plus expiring/resetting monthly Work Credit grant and
   opt-in top-ups only after P50/P90 cost and fallback amplification are bounded;
4. add pooled organization budgets and route-policy administration;
5. add enterprise commitments, reserved capacity, private deployment, support,
   and decomposed control-plane/runtime/route-class SLAs.

Progression gates are supplier-invoice reconciliation, positive cohort
contribution margin, bounded p95 COGS, abuse and chargeback behavior, fallback
cost amplification, accepted outcomes per dollar, and support burden—not gross
token volume. The included allowance must be based on observed workload cohorts
and managed-work COGS, never the sum of retail ChatGPT, Claude, or aggregator
plan prices.

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

ioi.ai monetizes one Goal Space conductor experience rather than separate
single-node and network-node products:

- recurring entitlement for persistent goal/account state, memory, policy,
  collaboration, receipts, replay, and support;
- bounded monthly Work Credit grant for routine managed work, sized from
  observed cohorts rather than retail chat-plan prices;
- top-up, opt-in overage, or committed-spend drawdown for heavy work;
- separately funded Network/Open goal budgets for independent workers,
  verifiers, services, challenges, and settlement;
- enterprise plans for organization policy, pooled budgets, private/customer-
  boundary deployment, reserved capacity, audit, retention, connector
  governance, SLA, administration, and support.

Same-domain 1-N worker orchestration is built into the Goal Space. Genuine
multi-party participation is an opt-in supply scope with explicit admission,
affiliation, evidence, and settlement terms. Node count is not the SKU.

ioi.ai uses Hypervisor as execution/control and Work Credit owner, MoW and
aiagent.xyz as worker supply/routing-attribution owners, sas.xyz as service
procurement/delivery owner, wallet.network and local/domain governance as
authority owners, and Agentgres domains as operational-truth owners. It must
not invent private bypasses around them.

ioi.ai may charge for cross-worker selection, multi-worker pursuit,
marketplace sourcing, verifier routing, connector escalation, evidence
synthesis, settlement handoff, or managed execution. It should not tax a direct
local run using only customer models, infrastructure, tools, and authority when
no managed service or network matching occurs.

IOI may operate a disclosed seed fleet to create initial planner, builder,
verifier, critic, synthesizer, benchmark, and challenge capacity. Those are
ordinary first-party Worker compositions, use the same contracts as external
supply, receive no hidden preference, disclose subsidy and dependencies, and
remain one party until an independent principal joins. The fleet is anchor
liquidity, not a permanent sole counterparty.

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

The recursive trust topology is:

```text
attempt / execution branch
-> local governed autonomous-system state
-> organization or project Hypervisor Node / Agentgres domain
-> AIIP cross-domain evidence and work exchange
-> sparse public commitment only when independent trust or economic finality needs it
```

This is not one chain per worker, agent, GoalRun, OutcomeRoom, or node. Local
signatures, deterministic admission, receipts, and replay handle ordinary work;
consensus is reserved for independent ordering, rights, bonds, disputes,
portable reputation, or economic finality.

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
- separate SKUs for every internal primitive merely because it can be metered;
- pooled, shared, browser-automated, or resold named-user foundation-model
  workspace seats treated as unattended production capacity;
- a Goal Space allowance priced by adding retail chat subscriptions rather
  than measured workload COGS;
- unlimited managed multi-model or multi-worker burn hidden inside a flat seat;
- raw token resale or opaque provider markup as IOI's margin thesis;
- an aggregator as the sole inference authority or a ZDR flag presented as a
  no-provider-trust `Private` guarantee;
- ordinary seat credits silently funding independent Network/Open labor;
- separate single-node and network-node subscriptions when contributor scope
  and goal budget express the difference;
- Work Credits made transferable, cash-redeemable, or conflated with worker
  settlement assets;
- a chain or L1 commitment for every worker, GoalRun, attempt, receipt, or room
  update.

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
12. Is a Goal Space allowance bounded by observed COGS, quotes/caps, and
    explicit overage rather than implied unlimited work?
13. Is external Network/Open labor funded separately and attributed to the
    worker, service, and verifier owners rather than silently subsidized by the
    seat?
14. Does every managed route have current unattended/downstream, privacy,
    fallback, model-license, and training-right posture, with missing rights
    failing closed?
15. Is Work Credit billing reconciled to supplier attempts and invoices rather
    than inferred from one flat per-receipt constant?
16. Does each economic claim preserve the distinction between attestation,
    evidence, verification, acceptance, adjudication, and settlement?

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
