# ioi.ai Collaborative Outcome Pattern

Status: canonical architecture authority.
Canonical owner: this file for ioi.ai's intent-to-outcome coordination pattern,
goal-appropriate multi-model/multi-harness pursuit, shared evidence projections,
attempt comparison, and final ownership synthesis.
Supersedes: product prose that treats multi-model goal pursuit as a separate
Hypervisor product, room UI, fixed swarm, public leaderboard, or benchmark-only
workflow.
Superseded by: none.
Last alignment pass: 2026-06-17.

## Canonical Definition

**ioi.ai is the intent-to-outcome surface.**

When a goal is simple, ioi.ai may route it to one model, one worker, one
automation, one service, or one Hypervisor session.

When a goal benefits from multiple models, harnesses, tools, verifier paths, or
attempt strategies, ioi.ai may materialize a collaborative outcome pattern over
Hypervisor. The pattern is the way ioi.ai coordinates goal-appropriate pursuit
while Hypervisor executes, wallet.network authorizes, Agentgres records, and
Foundry supplies eval/build capability.

The useful analogy is not "copy a search-answer app." The useful analogy is:

```text
multiple models and strategies may be routed toward one objective
the evidence and attempts stay comparable
the final answer or delivery owns what was learned
```

## Owns

ioi.ai owns the user-facing coordination of:

- goal intake, constraints, preferences, and account context;
- deciding whether the goal is single-path or multi-path;
- selecting a goal-appropriate coordination shape;
- requesting Hypervisor sessions, automations, workers, services, harnesses, or
  model routes;
- showing authorized progress, evidence summaries, citations, receipts,
  screenshots, traces, run state, and unresolved uncertainty;
- comparing attempts when multiple paths are used;
- asking for human clarification, approval, or step-up when required;
- final answer/delivery synthesis after evidence, observations, receipts, and
  verifier state have returned.

## Does Not Own

ioi.ai does not own:

- Hypervisor Daemon execution semantics;
- Hypervisor Automations durable workflow/service/mission specs;
- wallet.network authority, credentials, declassification, or spend;
- Agentgres admitted operational truth, state roots, artifact refs, archive
  refs, or restore validity;
- Foundry training, tuning, eval suites, model registry, endpoint deployment,
  simulation training, or package promotion;
- physical-action safety semantics;
- IOI L1 settlement by default.

## Goal-Appropriate Materialization

The collaborative outcome pattern materializes differently by goal. It is not
always a benchmark, leaderboard, coding race, or public challenge.

```text
General question / research
  multi-model answer attempts, source retrieval, citation comparison,
  contradiction tracking, confidence and uncertainty summaries

Coding / software repair
  multi-path code search, tests, static analysis, runtime traces,
  rollback/snapshot branches, visual verification, failure mining

Computer use
  browser/app sessions, screenshots, action traces, task-completion evidence,
  connector receipts, policy-gated external actions

Operations / data work
  connector queries, data recipes, ontology projections, validation checks,
  report artifacts, approval gates

Finance or trading research
  simulations, backtests, risk labels, policy checks, paper/live separation,
  wallet.network approval before any funds-moving action

Model / worker improvement
  Foundry job drafts, eval suites, dataset curation, scorecards, promotion
  proposals

Public challenge / benchmark
  shared objective, scorecard, guardrail metric, attempt registry, optional
  message-board projection, optional leaderboard, prize/dispute settlement only
  when triggered
```

Embodied robotics model-building is not primarily an ioi.ai collaborative
outcome flow. ioi.ai may request or summarize it, but the build surface belongs
to Foundry: simulation worlds, LiDAR maps, Gaussian splats, perception/action
datasets, policy training, eval worlds, and safety cases. Live actuator
execution belongs to Hypervisor Daemon admission plus Physical Action Safety.

## Canonical Flow

```text
1. User states goal in ioi.ai.
2. ioi.ai classifies the goal shape:
     single path | multi-model answer | multi-harness attempt |
     software search | computer-use task | Foundry build job |
     automation/service handoff | wallet/action handoff
3. ioi.ai drafts the required Hypervisor, Foundry, wallet, or marketplace
   handoff.
4. Hypervisor opens governed sessions or Automations when execution is needed.
5. wallet.network grants scoped capability, spend, connector, credential, or
   declassification leases when required.
6. Agents, models, harnesses, workers, tools, services, or connectors propose
   and execute through daemon gates.
7. Agentgres records admitted operations, artifacts, receipts, traces, and
   replay refs.
8. Foundry/eval lanes score, verify, mine failures, or draft improvement
   proposals when applicable.
9. ioi.ai performs the final ownership synthesis for the user-facing answer,
   report, delivery, or next approval request.
```

## Minimal Implementation Objects

```yaml
IoiAiGoal:
  goal_id: goal:...
  user_ref: account:...
  project_ref: project:... | null
  goal_text: string
  constraints:
    - string
  privacy_posture_ref: policy://... | null
  authority_context_ref: authority://... | null
  status:
    draft | active | waiting_for_user | handed_off |
    completed | blocked | archived

IoiAiOutcomePlan:
  plan_id: outcome_plan:...
  goal_ref: goal:...
  materialization:
    single_path | multi_model_answer | multi_harness_attempt |
    software_search | computer_use | automation_handoff |
    foundry_job | wallet_action | marketplace_handoff
  selected_model_routes:
    - model_route:...
  selected_harnesses:
    - harness_profile:... | agent_harness_adapter:...
  hypervisor_refs:
    - automation:... | session:... | mission:...
  foundry_job_refs:
    - foundry_job:...
  wallet_request_refs:
    - capability_request:... | approval_request:...
  evidence_policy_ref: policy://...
  final_ownership_policy_ref: policy://...

IoiAiAttemptSummary:
  attempt_summary_id: attempt_summary:...
  plan_ref: outcome_plan:...
  source_ref:
    model_route:... | harness_profile:... | worker:... | service:...
  session_ref: hypervisor_session:... | null
  observation_refs:
    - observation:...
  artifact_refs:
    - artifact://...
  receipt_refs:
    - receipt://...
  verifier_refs:
    - eval_gate:...
  summary: string
  status:
    proposed | running | blocked | rejected | selected | archived
```

## Conformance Checks

- ioi.ai may coordinate multiple models and strategies, but it must not execute
  consequential actions outside Hypervisor/daemon gates.
- Multi-path goal pursuit must be goal-appropriate. Do not require benchmark
  scorecards or leaderboards for ordinary research, chat, or operations work.
- Shared message boards, progress feeds, leaderboards, and attempt summaries are
  projections. Agentgres-admitted operations and receipts define truth.
- Final answers must identify grounded evidence, unresolved uncertainty, and
  authorization state when those affect the user outcome.
- Connector and generalized-computer-use actions require wallet.network scopes,
  leases, and receipts when they touch private data, credentials, money,
  external systems, or policy-sensitive resources.
- Robotics simulation/training belongs to Foundry; physical actuator execution
  belongs to Physical Action Safety and daemon admission.

## Anti-Patterns

Avoid:

```text
ioi.ai = chat-only wrapper
ioi.ai = daemon runtime
collaborative outcome = fixed swarm
collaborative outcome = benchmark only
collaborative outcome = public leaderboard by default
multi-model answer = authority
connector access = credential ownership
robotics training = ordinary chat task
physical action = generic tool call
```

Correct:

```text
ioi.ai asks, coordinates, compares, and synthesizes
Hypervisor executes governed sessions
Automations owns durable workflow/service/mission specs
Foundry builds and evaluates reusable capability
wallet.network authorizes connectors, credentials, money, and declassification
Agentgres records admitted truth
IOI L1 settles only selected public/economic commitments
```

## Related Canon

- [`control-plane.md`](./control-plane.md)
- [`../../components/hypervisor/core-clients-surfaces.md`](../../components/hypervisor/core-clients-surfaces.md)
- [`../../components/hypervisor/foundry.md`](../../components/hypervisor/foundry.md)
- [`../../components/daemon-runtime/default-harness-profile.md`](../../components/daemon-runtime/default-harness-profile.md)
- [`../../components/daemon-runtime/events-receipts-delivery-bundles.md`](../../components/daemon-runtime/events-receipts-delivery-bundles.md)
- [`../../components/wallet-network/doctrine.md`](../../components/wallet-network/doctrine.md)
- [`../../foundations/physical-action-safety.md`](../../foundations/physical-action-safety.md)
