# Economic Flywheel and Pricing Boundaries

Status: canonical architecture authority.
Canonical owner: this file for stack-wide monetization boundaries, open
substrate / paid network doctrine, verified work graph economics, Work Credit
usage abstraction, marketplace fee legitimacy, substrate bundling, wallet.network
value-flow revenue boundaries, dispute-rail economics, Agentgres pricing
non-boundaries, and token/BME timing.
Supersedes: product or plan prose that turns every protocol surface, authority
check, receipt, state write, or builder surface into a separate toll booth.
Superseded by: none.
Last alignment pass: 2026-07-16.
Doctrine status: canonical
Implementation status: mixed (fee-basis declarations and flat OCU receipt metering exist; the registered managed-work billing and dispute-rail schemas, invariants, fixtures, and generated projections are contract substrate only; quote/hold/usage/debit/adjustment persistence, dispute admission/allocation, public Work Credit purchase/debit APIs, supplier-statement reconciliation, live evidence adjudication, escrow/bond/remedy execution, payment rails, Goal Space allowances, marketplace fees, and token/BME remain planned or deferred)
Last implementation audit: 2026-07-18

## Canonical Thesis

**Product surfaces monetize. Substrate layers meter, attest, authorize, record,
or settle only where they naturally carry value.**

IOI should capture value when the user receives a product outcome, managed
execution, marketplace distribution, commercial trust, or financial value flow.
It should not invent separate pricing models merely because an internal
primitive exists.

IOI has three distinct value loops. They may reinforce one another, but none
accrues to another automatically:

1. **L0 product alpha** — Goal Space/Hypervisor subscriptions, Work Credits,
   managed clusters and execution, enterprise/private deployment, support,
   compliance, and procurement convenience.
2. **Network alpha** — worker/service/verifier/ontology discovery, routing,
   marketplaces, certification, assurance operations, shared evidence,
   dispute, rights, and settlement liquidity.
3. **L1 value** — paid scarce neutral trust and bonded risk: public capacity,
   registries, shared security, finality, bonds/stake, slashing/claims,
   arbitration, and governance.

The **Verified Work Graph** becomes a durable compounding asset across the first
two loops only when repeated evidenced, verified, accepted, or adjudicated
outcomes measurably improve routing, trust, audit, promotion, or dispute
decisions. It is the receipt-backed record of who did what, under which
authority, with which worker/harness/model/tool stack, at what cost, with what
eval result, for whom, and whether that evidence is reusable. Raw graph size,
receipt count, or participation creates no moat by itself.

## Conditional Cooperation And Participant Rationality

Sovereignty does not motivate cooperation; it limits its downside. A system
uses external workers, services, verifiers, data-derived evidence, authority,
resources, or shared trust only when its expected cooperation surplus is
positive under its own constitution and policy.

```text
expected cooperation surplus_i
  = expected utility under accepted collaboration terms_i
  - expected utility of best permitted outside option_i
  - incremental cooperation costs_i

incremental cooperation costs_i include execution, opportunity, search,
  semantic-mapping, coordination, verification, privacy, IP, counterparty,
  dispute, settlement, switching, and dependency costs and risks

participate only when expected cooperation surplus_i > 0
```

Participation is rational only when the surplus is positive for every required
party under its own constitution and policy. Total coalition value is
insufficient if one required party is made worse off. Raw valuations and
outside options may remain private; the protocol binds each party's governed
acceptance of one exact `CollaborationTermsEnvelope` root.

The network earns value by reducing search, contracting, semantic-translation,
verification, counterparty-risk, and settlement costs or by unlocking a scarce
complement that a participant cannot obtain as efficiently alone. AIIP
compatibility, system count, room activity, message volume, receipts, or L0
adoption create no network alpha by themselves. The correct fallback when no
positive-surplus case exists is direct local operation.

Attribution supplies evidence for allocation; it is not allocation. Payment,
reputation, licensing, reciprocal access, or other consideration follows only
the terms and contribution policy in force when work was awarded plus the
declared verification, acceptance or adjudication, and settlement path.

Short form:

> Charge for useful autonomous work, managed capability, distribution, trust,
> and value movement. Bundle the substrate that makes those safe.

Category form:

```text
Open, independently operable L0. Paid managed products and network services.
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

## Open L0 / Protected Commercial Network Covenant

The open/closed split is a trust boundary, not only a business preference.
Anything required to verify IOI's honesty must be inspectable and implementable
outside the hosted service. Anything whose value comes from network scale,
managed operations, distribution, routing intelligence, marketplace liquidity,
or provider risk may be protected and monetized.

Architecture doctrine, not legal license advice:

```text
open, independently operable L0
  constitution, deployment, membership, ordering/finality, oracle, lifecycle,
    and enrollment contracts
  protocol contracts
  receipt schemas
  authority envelopes
  RoutingDecisionReceipt and fee-transparency covenant
  portable memory vault format
  Agentgres ref and object model
  provider / connector / harness adapter contracts
  SDK / ADK / ODK interfaces and portable package formats
  complete self-hostable reference stack
  conformance tests

protected commercial implementations (allowed, never required for compatibility)
  differentiated Hypervisor clients and enterprise distributions
  optimized Agentgres/runtime implementations and managed control planes
  proprietary provider adapters, operations automation, and support tooling

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

The open L0 must be implementable and independently operable, not merely
inspectable. It should use permissive or standards-compatible terms wherever
adoption, third-party implementation, offline verification, portability, or
challengeability is load-bearing. Commercial implementations may remain
protected when a complete compatible reference path exists. The
network/operations layer becomes a defensible business only where voluntary
participation creates distribution, routing, managed-execution, or commercial-
trust value greater than the coordination, disclosure, and switching costs
borne by its users.

This is architecture doctrine, not a license grant. Any change to an existing
repository's licensing or previously adopted open/protected covenant requires a
separate legal review and ADR; documentation cannot silently relicense code.

This covenant has two hard requirements:

1. A party must be able to verify its own receipts, authority envelopes,
   routing decisions, fee disclosures, state roots, and portable memory exports
   offline against open schemas and conformance fixtures. If verification
   requires hosted IOI, the claim is not truly verified.
2. The local/self-hosted core must be complete enough for one operator to run
   governed work on their own substrate. A crippled demo core is trust theater;
   managed IOI should win through convenience, routing intelligence,
   compliance, support, private runtime posture, and demonstrated routing and
   distribution advantages.

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
receipts; IOI L1 anchors selected public/economic commitments only when a
system's enrollment and settlement profiles choose it for portability,
settlement, reputation, rights, or disputes.

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

The graph can become a moat only when its staged evidence measurably improves:

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
| Hypervisor | Main product shell, managed runtime, the core Systems and Work workspaces, the application suite (Studio, Automations, Ontology, Data, Governance, Provenance, Evaluations, Improvement, Foundry, Packages with optional Marketplace mode, Developer Workspace, Developer Console), the Environments and Operations substrate lane, and related managed compute | Monetizes subscriptions, managed execution, enterprise/private deployment, and Work Credit usage. Foundry is a Hypervisor surface and usage lane, not a separate top-level business by default. Local package build, install, version, recall, and impact workflows do not depend on marketplace commerce. |
| ioi.ai | Intent-to-outcome conductor over Hypervisor, marketplace workers, connectors, sessions, and verifier lanes | Monetizes subscription and conductor usage. It spends Work Credits through Hypervisor and markets rather than owning a separate runtime pricing model. |
| aiagent.xyz | Capability marketplace for benchmarked, installable, attributable workers and managed worker instances | Monetizes admission, benchmarks, certification, managed instances, invocation, distribution, licensing, procurement, and take-rate only where it supplies real demand, trust, hosting, or settlement. |
| sas.xyz | Outcome marketplace for delivered autonomous services and Worker Training as Service-as-Software | Monetizes escrow, orders, milestones, SLAs, disputes, procurement, delivery acceptance, and take-rate where it provides commercial trust and demand. |
| wallet.network | Authority wallet, credential broker, approvals, recovery, exchange/trade/provider authority, payments, swaps, and value movement | Ordinary authority, connector approval, provider credential custody, resource-spend approval, and IAM-style grants are infrastructure bundled into products. Revenue capture belongs mainly to swaps, trades, payments, exchange, settlement assistance, protection, or other value-flow actions. |
| Agentgres | Per-domain operational truth substrate, receipt/state/projection substrate, and Postgres-like compatibility layer | Not a separate pricing surface in the first-party stack. It records economics and may support optional managed infrastructure offerings, but routine Agentgres writes, refs, and projections are bundled substrate. |
| IOI L1 | Public registry, rights, reputation, settlement, dispute, sparse commitments, and governance layer | Protocol fees apply only at public coordination, settlement, registry, dispute, reputation, rights, bond, or economic-finality boundaries. It is not charged per model thought, local workflow node, routine receipt, or Agentgres write. |

## Enrollment Economics And Value Accrual

The system-level enrollment profiles make the economic boundary explicit:

| Enrollment | What the network supplies | Economic rule |
| --- | --- | --- |
| `ioi_compatible` | Open L0 contracts, formats, reference implementation, and local conformance. No IOI Network assurance. | No mandatory fee, token, L1 use, or network contribution. Adoption may improve tooling and ecosystem reach but creates no automatic L1 demand. |
| `ioi_connected` | Selected registry, rights, reputation, escrow, dispute, settlement, or endpoint services. | Pay only for the selected service under its fee basis; connection alone does not imply shared security or certification. |
| `ioi_secured` | Standard DAS conformance plus named verifier, guardian, availability, ordering, finality, arbitration, or related shared-security coverage. | Explicit service fees, bonds/stake, slashing/claim terms, or a declared network-contribution covenant pay for scarce neutral trust. |

This is the required adoption/value-capture separation. A popular open L0 can
create product leads and ecosystem reach while producing no L1 transactions.
AIIP message volume can grow without IOI settlement. Marketplace GMV can grow
without a native asset if fiat or stable settlement is superior. L1 value
exists only when users choose scarce neutral trust, public capacity, bonded
security, disputes, rights, finality, or governance that the L1 supplies better
than alternatives.

The design intentionally combines lessons from modular sovereign ecosystems:
compatibility remains open; connected networks declare explicit alignment and
services; scarce shared security is paid; and additional assurance is opt-in.
IOI L1 is not a toll on sovereignty.

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
- Hypervisor AutomationRuns and background Session/WorkRun execution;
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

### Managed-work billing chain

One managed-work ledger is scoped to a billing account and one admitted work
identity. Its v1 chain is:

```text
versioned RateCard + versioned Plan
  -> immutable WorkQuote
  -> finite idempotent CreditHold
  -> append-only UsageRecord chain
  -> typed OverrunDecision
       -> exact additional CreditHold
       -> or block
  -> one exact FinalDebit
  -> append-only downward Adjustment / Refund / Writeoff
```

All money and Work Credit arithmetic uses fixed-point integers: ISO-currency
minor units and `micro_work_credit` units. Floating-point amounts are invalid
at contract and kernel boundaries. Every RateCard, Plan, quote, hold, usage
entry, decision, debit, and adjustment has a canonical exact-body hash. A quote
freezes the exact RateCard and Plan refs and hashes, expiry, estimated Work
Credits, required initial hold, maximum attempt count, admitted commercial
postures, and overrun policy. Expired RateCards, Plans, quotes, or holds cannot
be silently reused.

A `CreditHold` is a finite budget reservation, not a payment or machine
authority grant. Same idempotency key plus the same canonical command bytes
replays the prior result; the same key with changed bytes conflicts. A
`UsageRecord` can only append against the current usage head, derives its
quantity from owner-resolved runtime receipts, applies the frozen rate, and
cannot exceed active holds. If projected use exceeds the active held amount,
the quote's exact overrun policy either blocks or permits one additional hold
equal to the precise overage. It never permits an unbounded or approximate
top-up.

The cost breakdown keeps these dimensions separate:

- managed provider or compute supplier cost;
- external broker cost;
- participant cost;
- verifier cost;
- IOI managed-service fee;
- customer-borne provider cost excluded under BYOK, BYOA, customer-cloud,
  self-hosted, or local posture;
- supplier-reconciliation state and exact statement refs.

`FinalDebit` equals the checked sum of the complete bound UsageRecord chain and
cannot exceed then-active holds. Exactly one FinalDebit is allowed. A later
refund or writeoff is an append-only downward adjustment bound to that debit
and the prior adjustment head; cumulative adjustments cannot exceed the debit.
No record rewrites prior usage, changes the frozen quote, turns Work Credits
into cash, or authorizes execution.

The registered ledger-bundle contract, invariants, fixtures, and generated
projections specify this internal product-accounting chain. Current master does
not contain the quote/hold/usage/debit/adjustment kernel or its durable store,
and exposes no public caller-authored supplier-usage endpoint. A future
implementation must accept only owner-resolved authority/evidence context.
Its internal-event-log assurance cannot become invoice-grade merely because a
debit exists: a managed supplier-cost claim becomes reconciled only when the
applicable supplier statement is bound. Coarse OCU remains a separate,
zero-rate telemetry projection and cannot mint billable usage.

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
| Provider aggregator or broker | Bootstrap breadth, long-tail models, price/availability discovery, policy-qualified fallback, overflow, experimentation | Replaceable procurement/routing adapter, never the product moat or sole inference authority; obtain enterprise/OEM interpretation where IOI's provider-neutral routing could approach prohibited raw resale/competition |
| Customer BYOK/BYOA | Customer cost ownership, existing commitments, user-selected interactive harnesses, enterprise control | Customer-owned credential binding; explicit IOI conductor/runtime/governance charges instead of hidden spend markup |
| Open/self-hosted weights | No-provider-trust execution, sovereignty, customization, training/distillation rights, concentration and COGS hedge | Hypervisor-managed or customer-boundary execution with explicit model license, custody, and attestation posture |

An aggregator does not erase model/provider terms, commercial rights, data
handling, availability risk, or semantic differences. Default provider or model
fallbacks are too fail-open for governed sensitive work. Eligible routes pin or
allowlist providers, required parameters, provider-use and retention/ZDR policy,
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
`model_version_ref`, `provider_allowlist`, `zdr_required`, the full
`provider_use_of_customer_material` matrix and retention posture, the full
`customer_use_of_outputs` matrix, `rights_basis_refs`, `region_ref`,
`fallback_classes`, `max_price_ref`, and `required_parameters`; pricing code
must not invent a reduced parallel contract.

Missing rights fail closed. Compare or synthesized multi-route output uses the
intersection of every contributing route's customer output rights, while
provider exposure remains attributed per recipient. A provider/model fallback is a semantic substitution
and must remain within this contract, emit routing evidence, and re-run the
applicable verifier/acceptance path. Inference rights and training/distillation
rights are separate; Foundry uses open weights or expressly licensed teacher
agreements rather than inferring training rights from ordinary inference spend.
Enterprise pricing may cover managed learning-boundary governance, confidential
compute, custody evidence, compliance packs, capability export, and provider-exit
testing; it must not condition the customer's right to retain eligible
institutional state on a platform toll.

Supplier agreements; separation between named-human workspace plans and
API/OEM access; and aggregator pricing, BYOK, routing, fallback, data-use,
retention, and commercial terms are time-sensitive procurement evidence, not
canonical architecture. Reviewed versions belong in non-canonical discovery
and implementation evidence. Public fees and defaults can change and never
become customer-plan promises.

## Commercial Activation Gates

The target product is not a claim that current metering safely supports a paid
multi-provider allowance. As of the implementation audit for this alignment
pass, the live OCU slice still charges `0.1` OCU for every model-backed receipt
without reconciling provider, input/output/cache/reasoning classes, retries, or
supplier invoice. The registered managed-work contract now supplies the exact
machine shape and adversarial fixtures for
RateCard/Plan/quote/hold/usage/overrun/debit/adjustment, but the runtime kernel,
durable ledger, public billing API, payment rail, and supplier-statement
reconciler remain planned. The
model-route overview declares sealed BYOK unimplemented and only
Ollama-transport routes bindable for session execution. Commercial Work Credit
allowances and top-ups, marketplace fees, and the Goal Space allowance remain
planned.

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
and managed-work COGS, never the sum of retail named-human workspace or
aggregator plan prices.

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

## Dispute Rail Economics

Dispute handling is not one global court or one automatic token-slashing
system. The selected `DisputeRailProfileEnvelope` fixes one of four economic
postures:

| Rail | Economic boundary |
|---|---|
| `internal_review` | Domain-local review. No challenger/respondent bond and no claim of escrow or public finality. |
| `marketplace_escrow` | The marketplace case binds the exact order escrow; the marketplace/settlement owner later executes any admitted refund, payout, or bond distribution. |
| `aiip_dispute` | The cross-domain case binds the exact accepted CollaborationTerms root and an ordinary verification-funding source. AIIP carries the case and receipts; it does not create settlement by message delivery. |
| `public_settlement` | Optional enrolled neutral dispute/finality service. The case binds the selected settlement profile and active network enrollment; compatibility alone creates no fee, bond, or public adjudication. |

V1 uses one exact `DisputeValueUnitBinding` across disputed value, remedy,
challenger and respondent bonds, bond pool, and every allocation leg. This is a
deliberate no-conversion rule. A USD-cent claim cannot be remedied in a token,
a Work Credit bond cannot be treated as cash, and one chain deployment or
decimal scale cannot substitute for another because their display labels look
similar. A later multi-asset rail must bind an explicit conversion contract,
rate source, freshness, rounding, slippage, and conversion authority.

Dispute revenue is legitimate only for real escrow operation, independent
verification/adjudication, evidence custody/export, insurance routing,
settlement execution, public finality, or support work. Opening a local review,
hashing a case, or computing a deterministic allocation does not by itself
justify a network toll. The registered contract requires a profile-selected
resolution and conserved allocation plan. Current master does not contain the
dispute admission or allocation kernel; schema validation also cannot hold a
bond, decide evidence truth, move value, execute a remedy, emit the required
receipts, or make an appeal or public settlement final.

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
Provenance receipts, release controls, rollback, restore, audit, routing evidence,
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

Same-domain 1-N worker orchestration is included in the target Goal Space
product contract. Genuine
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

If a native asset is eventually justified, its defensible role is risk-bearing
network capital and access to scarce public capacity:

- gas for selected public commitments;
- validator or consensus security;
- verifier, guardian, availability-witness, relayer, and arbitrator bonds;
- claims, slashing, and performance/security penalties;
- governance of IOI Network contracts, conformance profiles, services, and
  treasury/security parameters.

It is not the default user billing unit, generic inference currency, a
replacement for stable-value Work Credits, or a mandatory token for every DAS.
Architecture cannot promise market capitalization. Token value requires real
fee demand, credible neutral security, capital at risk, and durable governance
rights; product revenue, network usage, and token value are three different
ledgers until evidence proves their coupling.

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
- architecture adoption, AIIP traffic, product revenue, or marketplace volume
  presented as automatic native-asset demand or market capitalization;
- mandatory connected/secured enrollment or L1 fees for compatible local use;
- one token per autonomous system by default;
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
17. Is IOI Network enrollment explicit, service-specific, and unnecessary for
    a compatible local system?
18. What scarce neutral trust, public capacity, bonded risk, or governance right
    creates L1 demand, independently of L0 product revenue or AIIP adoption?

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
