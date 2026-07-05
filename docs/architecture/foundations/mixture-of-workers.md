# Mixture of Workers

Status: canonical architecture authority.
Canonical owner: this file for Mixture of Workers, worker routing, sparse worker categories, and MoW neutrality doctrine.
Supersedes: product, marketplace, or model-routing prose when it treats models as the protocol actor or treats routing as platform fiat.
Superseded by: none.
Last alignment pass: 2026-05-14.
Doctrine status: canonical
Implementation status: planned (routing doctrine; MoW routing receipts not implemented)
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
Receipts pay contributors.
```

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
→ task decomposition
→ candidate worker discovery
→ worker selection
→ capability and policy check
→ execution
→ verification
→ ContributionReceipts
→ settlement
```

The canonical economic graph often has planner, executor, verifier, and merge
roles. The planner scopes work; executor workers perform bounded tasks;
verifier workers or deterministic gates validate outputs; the merge gate turns
provisional work into canonical state, delivery, or settlement.

Each routed worker remains independently accountable. It has its own manifest,
policy envelope, contribution terms, receipt obligations, quality record, and
dispute surface.

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
- routing policy hash;
- selection reason;
- contribution policy reference;
- receipt obligations.

The router must not silently substitute a first-party or default worker when a
third-party worker is materially better under the declared routing policy. If a
default worker is selected, the routing receipt must make the basis legible:
cost, privacy, locality, installed status, policy compatibility, user
preference, benchmark result, or reputation superiority.

This is the MoW neutrality invariant:

> **The platform routes intelligence; it does not absorb it.**

## Contribution And Settlement

ContributionReceipts are the unit of MoW economics. Payouts, royalties,
reputation updates, routing weight, and subscription-credit distribution should
be based on verified contribution rather than raw token usage, attention time,
popularity, or platform fiat.

When ioi.ai or another Hypervisor-built coordinator routes through marketplace
workers, the outcome graph should carry routing and ContributionReceipt refs.
The coordinator may synthesize the final answer, but MoW remains the worker
supply, routing-eligibility, and attribution layer. Subscription attribution
belongs to MoW, aiagent.xyz, and settlement rails, not to ioi.ai chat state.

Subscription credits should behave as prepaid work credits:

```text
user subscription
→ work credits
→ worker invocation / benchmark / outcome delivery
→ ContributionReceipt
→ quality and reputation update
→ receipt-weighted payout
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
license, and dispute commitments. Agentgres owns detailed routing, quality, and
contribution ledgers.

## Benchmark And Routing Non-Claims

Benchmark receipts prove performance under a declared benchmark profile,
evaluation environment, rubric, worker manifest, and policy hash. They do not
prove universal intelligence, universal optimality, or permanent superiority.

Routing receipts prove that a worker was selected under a declared policy and
candidate set. They do not prove the selected worker is globally best in an
absolute sense. They prove the decision was legible, receipt-backed,
policy-compatible, and challengeable.

Sparse Worker Categories are relative labor markets, not universal intelligence
rankings.

## One-Line Doctrine

> **MoW routes bounded workers by receipts, benchmarks, policy compatibility, cost, trust, and contribution quality rather than by model size or platform fiat.**
