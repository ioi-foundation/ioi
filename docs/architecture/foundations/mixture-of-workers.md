# Mixture of Workers

Status: canonical architecture authority.
Canonical owner: this file for Mixture of Workers, worker composition and plurality distinctions, worker routing and execution policies, sparse worker categories, seed-supply posture, and MoW neutrality doctrine.
Supersedes: product, marketplace, or model-routing prose when it treats models as the protocol actor or treats routing as platform fiat.
Superseded by: none.
Last alignment pass: 2026-07-11.
Doctrine status: canonical
Implementation status: planned (routing doctrine; MoW routing receipts, general collaborative-frontier routing, independent-party supply, and contribution settlement are not implemented)
Last implementation audit: 2026-07-05

## Canonical Definition

**Mixture of Workers (MoW) is IOI's labor-routing architecture for decomposing intent into bounded work, selecting accountable workers, verifying their contributions, and settling value through receipts.**

MoW is not a fifth Web primitive. Web4 remains:

```text
Read + Write + Own + Act, with proof
```

MoW is the routing architecture made possible once Act is bounded by identity,
policy, receipts, authority scopes, and settlement.

## Worker, Agent, Model

IOI uses these terms precisely:

- **Worker** is the canonical protocol actor: a bounded executable actor with a
  manifest, policy envelope, capability surface, receipt obligations, runtime
  requirements, contribution terms, and settlement identity.
- **Agent** is product-facing or colloquial language. It may describe UX,
  personality, delegation, or operator experience, but it is not the normative
  protocol actor.
- **Model** is a cognition backend used by a worker. A model may be local,
  hosted, fine-tuned, provider-routed, MoE-backed, retrieval-augmented, or
  verifier-only, but it is not the economic actor by itself.

Protocol doctrine:

```text
Models are mounted.
Workers are installed.
Services are hired.
MoW is routed.
Receipts attribute contributions; accepted or adjudicated claims may settle.
```

The accountable routing unit is normally a versioned **Worker Composition**:

```text
Worker Composition
  = manifest and publisher
  + model route or model requirements
  + harness/runtime entrypoint
  + tools, connectors, and MCP contracts
  + policy and authority requirements
  + memory and persistence posture
  + verifier and receipt obligations
  + version, benchmark, cost, license, and contribution identity
```

Foundation models are mounted cognition, not labor-market identities. This
keeps a worker portable across provider APIs, dedicated capacity, aggregators,
open weights, customer endpoints, and future routes while preserving the
publisher, policy, tool, verifier, and contribution boundary.

MoW also distinguishes four kinds of plurality:

| Shape | Distinct unit | Establishes | Does not establish |
| --- | --- | --- | --- |
| Multi-model | Model routes or model families | Cognitive diversity and route choice | Accountable worker identity or independent parties |
| Multi-worker | Worker compositions, roles, manifests, policies, and outputs | Division of labor and comparable contribution | Independent authority, truth, or settlement roots |
| Multi-node | Runtime nodes, providers, or failure domains | Scale, isolation, locality, custody, and resilience | Governance or economic independence |
| Multi-party | Separate principals controlling authority, revocation, truth, risk, challenge, and settlement | Actual federation and a reason for `MultiPartyCollaborationEnvelope` | Independence when affiliations or dependencies are hidden |

Ten IOI-owned workers on ten nodes and several foundation-model providers are
still one party if IOI controls authority, operational truth, verification, and
settlement. Model/cloud providers remain disclosed dependencies unless their
principals accept participant-level rights and obligations.

## MoE vs MoW

Mixture of Experts routes inference across specialized model components.

Mixture of Workers routes consequential labor across bounded workers.

```text
MoE asks: which expert should help predict the next token?
MoW asks: which worker or worker set should perform this job safely, cheaply,
          privately, and verifiably?
```

A worker may use any cognition backend:

- single LLM;
- hosted API model;
- local open-weight model;
- fine-tuned domain model;
- Mixture-of-Experts system;
- retrieval-augmented system;
- deterministic toolchain;
- verifier ensemble;
- TEE-hosted proprietary model.

IOI treats those as worker internals. The model supplies cognition; the worker
supplies bounded agency.

For benchmark, routing, and marketplace purposes, the tested unit should usually
be a **Worker Composition**: worker manifest, model route or model requirements,
harness adapter, tools/connectors/MCP contracts, runtime placement, privacy
posture, verifier path, and receipt obligations. Naked model scores may inform
model routing, but they are not sufficient evidence for autonomous-labor
routing eligibility.

## Routed Labor Graph

A MoW flow turns intent into a receipt-backed labor graph:

```text
intent
-> direct bounded task or OutcomeRoom frontier item
-> candidate worker and capability/resource discovery
-> eligibility, affiliation, semantic, policy, privacy, authority, and budget checks
-> 1-of-N selection, N-of-N comparison, or claimed work lease
-> isolated attempt with explicit model/provider/runtime dependencies
-> evidence, negative or positive result, verification, and acceptance
-> ContributionReceipts and derivation lineage
-> local accounting and sparse settlement only where required
```

The canonical economic graph often has planner, executor, verifier, and merge
roles. The planner scopes work; executor workers perform bounded tasks;
verifier workers or deterministic gates validate outputs; the merge gate turns
provisional work into canonical state, delivery, or settlement.

Each routed worker remains independently accountable. It has its own manifest,
policy envelope, contribution terms, receipt obligations, quality record, and
dispute surface.

For persistent collective pursuit, MoW supplies eligible Worker compositions
to an `OutcomeRoom` / CollaborativeWorkGraph. The room owns neither the Worker
manifest nor MoW ranking. It may advertise `CapabilityOffer` / `ResourceOffer`
refs, create `WorkFrontierItem`s, grant bounded `WorkClaimLease`s, compare
attempts, request replication or verification, and update routing priors from
admitted evidence. Pull-based claims and conductor assignments are both policy
options; a hard-coded planner/executor/verifier graph is not the protocol.

Participant inputs are untrusted until admitted. Worker messages, artifacts,
findings, ontology mappings, and evaluator suggestions must preserve provenance,
taint, license/export, and trust labels and must not automatically change
durable memory, ontology, routing, authority, or production capability.

## Execution Policies

The product may expose three route policies over the same MoW substrate:

| Policy | Behavior | Accounting |
| --- | --- | --- |
| `Auto` / `1-of-N` | Select the least-cost eligible Worker composition expected to satisfy quality, privacy, authority, latency, semantic, and context requirements; a cheap-first cascade may escalate after verifier failure | Charge admitted attempts, verification, runtime, and escalation under the declared cap or quote |
| `Pinned` | Use a named eligible Worker/model/provider route selected by the user or policy | Charge route-specific admitted work; fail closed on ineligibility or unapproved fallback |
| `Compare` / `N-of-N` | Execute several independent routes and apply a declared comparison, verifier, or synthesis rule | Account for all admitted attempts, verifier work, and synthesis visibly |

`1-of-N` is a routing policy, not a separate product plan. A verified cascade
is often the economically best route: inexpensive worker first, deterministic
or model verifier second, and frontier escalation only when evidence fails.
Every fallback that changes the Worker composition, model/provider, privacy
posture, or semantic behavior is a visible routing decision and must re-run the
applicable verifier/acceptance path.

## Sparse Worker Categories

MoW should not collapse into one global leaderboard. IOI supports **Sparse
Worker Categories**: narrow labor markets with explicit evaluation profiles.

Examples:

- Rust security audit worker;
- legal intake worker;
- construction quote worker;
- grant research worker;
- sales follow-up worker;
- insurance claim review worker;
- scientific literature worker;
- React refactor worker;
- local SEO worker;
- government RFP worker.

A Sparse Worker Category may define:

- task class;
- input and output schemas;
- benchmark suite;
- evaluation rubric;
- runtime requirements;
- policy and trust posture requirements;
- receipt obligations;
- submission fee or stake;
- routing eligibility criteria;
- contribution policy.

Submitting a worker to a category pays for benchmark execution and leaderboard
admission. Submission does not guarantee routing. Routing eligibility is earned
through benchmark performance, receipt completeness, policy compatibility,
price, runtime posture, and reputation.

## First-Party Seed Supply

IOI may operate an initial mesh of named planner/researcher,
builder/implementer, deterministic verifier, model critic, synthesizer,
benchmark, challenge, and evaluation Worker compositions to solve cold start.
That mesh is anchor liquidity: baseline quality, conformance fixtures,
last-resort capacity, and a credible first-run experience. It is not evidence of
independent multi-party collaboration.

Every first-party composition must:

- disclose IOI ownership, publisher, affiliation, model/provider/runtime
  dependencies, subsidy, and real cost class;
- use the same authority, isolation, route receipt, replay, benchmark,
  contribution, challenge, and dispute contracts as external workers;
- receive no hidden MoW, marketplace, or verifier preference;
- avoid simultaneously serving as coordinator, paid worker, sole verifier,
  ranking authority, and settlement judge for the same consequential outcome;
- remain replaceable or outperformable by a third-party Worker composition
  without changing the pursuit contract.

IOI may be the initial market maker. It must not become the permanent only
counterparty or disguise one controlled fleet as decentralized supply.

## Routing Decision Receipts

A MoW routing decision is protocol-visible. A router must be able to explain and
receipt why a worker was selected.

Routing inputs may include:

- intent class;
- required capabilities and authority scopes;
- privacy class;
- execution target;
- trust posture;
- cost ceiling;
- latency requirement;
- benchmark profile;
- sparse worker category;
- reputation root;
- contribution terms;
- user preference.

Routing outputs must include:

- selected worker;
- candidate-set commitment;
- candidate ownership/affiliation commitment;
- routing policy hash;
- selection reason;
- selected Worker composition and disclosed model/provider/runtime refs;
- attempted routes, fallbacks, verifier-triggered escalations, and actual
  admitted attempt refs;
- contribution policy reference;
- receipt obligations.

The router must not silently substitute a first-party or default worker when a
third-party worker is materially better under the declared routing policy. If a
default worker is selected, the routing receipt must make the basis legible:
cost, privacy, locality, installed status, policy compatibility, user
preference, benchmark result, or reputation superiority.

This is the MoW neutrality invariant:

> **The platform routes intelligence; it does not absorb it.**

## Contribution, Assurance, And Settlement

`ContributionReceipt` is the attribution unit of MoW economics, not automatic
proof of quality or a payout instruction. It binds a contributor, role, method,
inputs/outputs, derivation, evidence, cost, routing decision, license, and
downstream outcome. Economic or reputation effects follow only through the
declared assurance path:

```text
attributed contribution
-> evidence
-> verification under a named rule/version
-> customer/domain acceptance
-> challenge or adjudication when invoked
-> payout, royalty, reputation, or routing update
```

Useful contributions include planning, execution, data, review, debugging,
independent replication, negative or inconclusive results, integrity reports,
resource provision, semantic mapping, verifier hardening, curation, and
synthesis. Credit follows accepted marginal information and derivation, not
only the winning run.

When ioi.ai or another Hypervisor-built coordinator routes through marketplace
workers, the outcome graph should carry routing and ContributionReceipt refs.
The coordinator may synthesize the final answer, but MoW remains the worker
supply, routing-eligibility, and attribution layer. Subscription attribution
belongs to MoW, aiagent.xyz, and settlement rails, not to ioi.ai chat state.

The ioi.ai subscription may fund managed work through prepaid, non-transferable
Work Credits, but Work Credits are product budget units rather than contributor
payout assets:

```text
user subscription
-> Work Credits and separately bounded network/open goal budget
-> worker invocation / benchmark / outcome delivery / verifier work
-> ContributionReceipt plus evidence and acceptance state
-> quality and reputation update when admitted
-> payout through an approved fiat, stablecoin, token, or other settlement rail
```

Reference payout components may include:

```text
worker_payout =
  invocation_fee
+ metered_compute
+ success_bonus
+ quality_delta_bonus
+ royalty_share
- dispute_or_failure_penalties
```

IOI L1 may anchor sparse roots for registry, contribution, reward, reputation,
license, rights, bond, and dispute commitments only when shared public or
economic finality adds value. Agentgres domains own detailed attempts, routing,
quality, assurance, and contribution ledgers. One receipt, worker, GoalRun, or
room participant does not require its own chain.

## Benchmark And Routing Non-Claims

Benchmark receipts attest performance observations under a declared benchmark
profile, evaluation environment, rubric, worker manifest, and policy hash. They
do not prove universal intelligence, universal optimality, or permanent
superiority.

Routing receipts attest that a worker was selected under a declared policy and
candidate set. They do not establish that the selected worker is globally best
or that its outcome is correct. They make the decision legible,
policy-evaluable, and challengeable.

Sparse Worker Categories are relative labor markets, not universal intelligence
rankings.

## One-Line Doctrine

> **MoW routes accountable Worker compositions—not naked models—by declared
> policy, semantic fit, authority, privacy, cost, verified evidence, and
> contribution quality; it preserves party identity, attribution, challenge,
> and sparse settlement rather than routing by platform fiat.**
