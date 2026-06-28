# ioi.ai Collaborative Outcome Pattern

Status: canonical architecture authority.
Canonical owner: this file for ioi.ai's intent-to-outcome coordination pattern,
goal-appropriate multi-model/multi-harness pursuit, shared evidence projections,
attempt comparison, and final ownership synthesis.
Supersedes: product prose that treats multi-model goal pursuit as a separate
Hypervisor product, room UI, fixed swarm, public leaderboard, or benchmark-only
workflow.
Superseded by: none.
Last alignment pass: 2026-06-22.

## Canonical Definition

**ioi.ai is the outcome conductor built on Hypervisor.**

ioi.ai is the first-party proof that Hypervisor can produce high-level
autonomous products. It turns user goals into governed Hypervisor work,
cross-session outcome graphs, connector/auth handoffs, Foundry proposals, and
final ownership synthesis. It is not the main runtime, not the authority layer,
not marketplace truth, and not the only coordinator that should be possible on
the substrate.

When a goal is simple, ioi.ai may route it to one model, one worker, one
automation, one service, or one Hypervisor session.

When a goal benefits from multiple models, harnesses, tools, verifier paths, or
attempt strategies, ioi.ai may materialize a collaborative outcome pattern over
Hypervisor. The pattern is the way ioi.ai coordinates goal-appropriate pursuit
while Hypervisor executes, authority providers and local/domain governance
authorize as required, wallet.network supplies portable delegated/high-risk
authority, Agentgres records, and Foundry supplies eval/build capability.

Doctrine sentence:

```text
ioi.ai conducts goals across sessions, agents/workers, connectors, and attempts;
Hypervisor executes; authority providers and local/domain governance authorize
as required, with wallet.network mandatory for portable delegated authority and
high-risk external effects; Agentgres records; Foundry builds/evaluates;
aiagent.xyz supplies and attributes workers.
```

ioi.ai dogfoods Hypervisor. It is a first-party intent-to-outcome product built
from Hypervisor application surfaces, WorkRuns, Automations, Foundry,
operator-plane contracts, wallet authority, Agentgres truth, and receipts. It is
not privileged substrate. A user or organization should be able to build an
ioi.ai-like coordinator through Hypervisor without receiving host authority or a
separate runtime bypass.

Conceptually:

```text
Hypervisor is the substrate.
ioi.ai is one first-party conductor product.
Other conductors should be buildable from the same surfaces and contracts.
```

Dogfooding means ioi.ai uses the same Hypervisor application-surface pipeline as
other coordinators. It may use App, Web, SDK, or CLI/headless-equivalent client
projections over declared surface contracts, but it must not own a custom
headless Hypervisor instance, direct connector path, or private operator loop.
Headless is a client projection; Hypervisor Core, the Operator Plane, daemon
admission, wallet.network, Agentgres, and receipts remain the substrate.

The useful analogy is not "copy a search-answer app." The useful analogy is:

```text
multiple models and strategies may be routed toward one objective
the evidence and attempts stay comparable
the final answer or delivery owns what was learned
```

Canon should avoid turning this into a separate "meta-harness" runtime. The
product-facing term remains **outcome conductor**. The lower-level contracts are
`OrchestrationPolicy`, `OrchestrationConstraintEnvelope`, `VerifierPath`, and
`OrchestrationDecisionReceipt`: they describe how a coordinator chooses,
explains, verifies, and later improves a multi-harness plan. They do not execute
work, own authority, or become a hidden swarm.

## Owns

ioi.ai owns the user-facing coordination of:

- goal intake, constraints, preferences, and account context;
- deciding whether the goal is single-path or multi-path;
- selecting a goal-appropriate coordination shape;
- selecting or applying an `OrchestrationPolicy` subject to an explicit
  `OrchestrationConstraintEnvelope`;
- selecting verifier paths that match the goal's risk, evidence, and
  acceptance posture;
- emitting orchestration decision refs when a material plan, model route,
  harness, worker set, verifier path, or session topology is selected;
- creating cross-session outcome graph projections when several sessions,
  workers, verifier paths, or attempts are useful;
- requesting Hypervisor sessions, automations, workers, services, harnesses, or
  model routes;
- detecting missing connectors, expired scopes, insufficient authority, or
  required approvals and drafting connector/auth escalation handoffs;
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
- Hypervisor Operator Plane semantics or private operator loops;
- wallet.network authority, credentials, declassification, or spend;
- connector secrets, direct provider API calls, or connector execution truth;
- Agentgres admitted operational truth, state roots, artifact refs, archive
  refs, or restore validity;
- Foundry training, tuning, eval suites, model registry, endpoint deployment,
  simulation training, or package promotion;
- conductor-training consent, raw training data, or model-route promotion truth;
- aiagent.xyz worker listings, marketplace routing truth, or contribution
  accounting;
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
  multi-path code search, isolated child environments, Git branch/worktree
  backing, Agentgres patch branches, tests, static analysis, runtime traces,
  visual verification, failure mining, review/merge proposals

Computer use
  browser/app sessions, screenshots, action traces, task-completion evidence,
  connector receipts, policy-gated external actions

External account or connector action
  missing-connector detection, scope/authority explanation, wallet.network
  scope request, dry-run or preview, policy-gated execution through daemon
  connector calls, action receipts, skipped/blocked summary

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
     automation/service handoff | connector/auth escalation |
     wallet/action handoff | marketplace handoff
3. ioi.ai creates a plan or cross-session outcome graph projection when several
   sessions, workers, attempts, verifier paths, connectors, or strategies are
   useful.
4. The plan carries an orchestration constraint envelope and selected verifier
   paths when privacy, authority, budget, latency, quality, or safety posture
   matters.
5. ioi.ai drafts the required Hypervisor, Foundry, wallet, connector, or
   marketplace handoff.
6. Hypervisor opens governed sessions, WorkRuns, or Automations when execution
   is needed.
7. Auto/MoW routing or explicit user selection chooses the participating
   workers, harnesses, model routes, verifier paths, and managed agents.
8. Hypervisor supplies the selected participants a scoped brokered tool/MCP
   capability manifest for the goal, session, project, privacy posture, and
   authority posture.
9. Connectors / Tools / MCP registry and surface contracts expose readiness,
   risk, scopes, policy, previews, and receipt obligations.
10. wallet.network grants scoped capability, spend, connector, credential,
   declassification, or training-data leases when required.
11. Agents, models, harnesses, workers, tools, services, or connectors propose
   and execute through daemon gates.
12. Agentgres records admitted operations, artifacts, receipts, traces, and
   replay refs.
13. Foundry/eval lanes score, verify, mine failures, or draft improvement
    proposals when applicable.
14. aiagent.xyz and MoW contribution paths receive routing/contribution refs
    when marketplace workers materially contribute.
15. ioi.ai emits an `OrchestrationDecisionReceipt` for material plan choices,
    including candidate-set, constraint, policy, selected plan, verifier-path,
    and evidence refs.
16. ioi.ai performs the final ownership synthesis for the user-facing answer,
    report, delivery, or next approval request.
```

## Dogfood And Handoff Pipeline

ioi.ai should be implemented as the first excellent coordinator built on
Hypervisor, not as a privileged sibling runtime.

The canonical connector/auth escalation path is:

```text
ioi.ai Goal Chat or Intake Worker
  -> classify goal, privacy, authority, connector, and budget needs
  -> create ioi.ai plan / cross-session outcome graph / escalation projection
  -> read Hypervisor application-surface registry and connector/tool readiness
  -> use Connectors / Tools / MCP RuntimeToolContract and MCP contracts
  -> request wallet.network authority review or scoped lease
  -> route execution through Hypervisor Operator Plane when host/platform state
     changes, or through governed session/daemon calls for ordinary work
  -> daemon admission
  -> Agentgres operation, receipt, artifact, trace, projection, and replay refs
  -> ioi.ai final synthesis
```

App, Web, SDK, embedded, and CLI/headless clients are equivalent projections
over these contracts. A backend ioi.ai conductor may run headlessly, but only as
a Hypervisor client over declared application-surface and daemon/Core contracts.
It cannot hold connector secrets, bypass wallet.network, mutate host/platform
state directly, or admit its own truth.

## Orchestration Policy And Verification

The outcome conductor should make orchestration decisions explicit enough to
audit and improve. This applies when ioi.ai materially chooses among single-path
execution, multi-model synthesis, multi-harness attempts, marketplace workers,
private/local routes, verifier branches, or cross-session graphs.

`OrchestrationPolicy` is a versioned decision policy over candidate plans. It
may use deterministic rules, benchmark priors, online quality evidence,
contextual bandit updates, user/org preferences, or Foundry-produced conductor
advisors. It is not authority, runtime truth, or a substitute for daemon gates.

`OrchestrationConstraintEnvelope` is the plan-selection input that captures:

```text
goal class
privacy posture
authority posture
provider-trust posture
budget and quota limits
latency tolerance
quality target
verification strength
data-use and trace eligibility
user/org preferences
```

The envelope constrains plan selection before a model, harness, or worker sees
raw tools, private context, connector payloads, or sensitive data. It is not a
wallet grant and not a replacement for local/domain governance.

`VerifierPath` is the selected verification shape for a plan. It may include
deterministic checks, tests, static analysis, browser/computer-use evidence,
LLM-as-judge steps, trained verifier workers, human review, benchmark gates, or
Foundry eval jobs. Model judges are permitted as evidence, but they are not
truth by themselves.

`OrchestrationDecisionReceipt` records why the conductor chose the plan it
chose. It should preserve candidate-set commitment, orchestration policy hash,
constraint envelope ref, selected plan, selected model routes, selected
harnesses, selected workers, selected verifier paths, expected cost/latency,
evidence refs, and fallback policy.

This separates four decisions that must not be collapsed:

```text
orchestration decision: which plan shape should pursue the goal?
model-routing decision: which cognition backend should a leg use?
worker-routing decision: which accountable worker should perform work?
authority decision: which effects, data, spend, or credentials are allowed?
```

Learned conductor advisors may score, rank, or propose orchestration plans, but
production decisions remain challengeable, policy-bound, and receipt-backed.
They cannot widen privacy, authority, budget, connector, tool, or session scope
without the normal governance and daemon gates.

## Learned Conductor Boundary

ioi.ai may eventually consume a learned conductor as a planning and routing
advisor, but the conductor is not hidden authority.

The training and promotion path is:

```text
Hypervisor sessions, WorkRuns, Automations, connector runs, and worker calls
  -> opted-in receipts, redacted traces, artifacts, corrections, and outcomes
  -> Foundry datasets, eval suites, scorecards, and simulations
  -> conductor or worker training/distillation job
  -> offline and shadow-mode eval gates
  -> model-route or worker promotion proposal
  -> wallet.network, Agentgres, daemon, policy, receipt, and marketplace gates
  -> ioi.ai consumes the promoted advisor as one bounded planning input
```

ioi.ai may draft Foundry jobs or conductor-improvement proposals. Foundry owns
training, evaluation, datasets, scorecards, model-route candidates, and
promotion proposals. Hypervisor/Foundry/Data governance surfaces propose
training evidence eligibility; Agentgres records admitted eligibility,
lineage, refs, and receipts; wallet.network supplies authority refs when
training-data use requires delegated power such as decryption, connector
access, provider-trust acceptance, model-provider keys, spend, publication, or
cross-domain reuse.

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
  orchestration_policy_ref: orchestration_policy://...
  constraint_envelope_ref: constraint://...
  coordination_mode:
    auto_mow | user_directed | hybrid
  materialization:
    single_path | multi_model_answer | multi_harness_attempt |
    software_search | computer_use | automation_handoff |
    connector_auth_escalation | foundry_job | wallet_action |
    marketplace_handoff
  selected_model_routes:
    - model_route:...
  selected_harnesses:
    - harness_profile:... | agent_harness_adapter:...
  selected_workers:
    - worker://... | managed_worker://...
  selected_verifier_paths:
    - verifier_path://...
  candidate_plan_refs:
    - orchestration_plan://...
  orchestration_decision_receipt_refs:
    - receipt://...
  brokered_capability_manifest_refs:
    - ai://... | mcp_gateway://...
  connector_refs:
    - connector://...
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
    - verifier_path://... | eval_gate:... | gate://...
  summary: string
  status:
    proposed | running | blocked | rejected | selected | archived

IoiAiCrossSessionOutcomeGraph:
  graph_id: ioi_outcome_graph:...
  goal_ref: goal:...
  plan_ref: outcome_plan:...
  session_refs:
    - hypervisor_session:...
  work_run_refs:
    - hypervisor_work_run:...
  attempt_refs:
    - attempt_summary:...
  connector_escalation_refs:
    - connector_escalation:...
  collaboration_context_refs:
    - collaboration://...
  authority_refs:
    - capability_request:... | approval_request:... | grant://...
  evidence_refs:
    - receipt://... | artifact://... | evidence://...
  allowed_shared_refs:
    - receipt://... | artifact://... | restricted_view://... |
      redacted_summary://... | collaboration://...
  blocked_context_classes:
    - raw_secret
    - protected_plaintext
    - unauthorized_connector_payload
    - unrelated_private_memory
    - non_opted_in_training_trace
  marketplace_contribution_refs:
    - contribution_receipt://...
  training_consent_refs:
    - authority://training_consent/... | foundry_job:...
  training_evidence_eligibility_refs:
    - eligibility://...
  training_posture:
    never_train | synthetic_only | redacted_opt_in | full_private_opt_in | org_policy
  status:
    proposed | active | blocked | completed | archived

IoiAiConnectorAuthEscalation:
  escalation_id: connector_escalation:...
  goal_ref: goal:...
  plan_ref: outcome_plan:...
  required_connector:
    namespace: string
    required_tools:
      - runtime_tool_contract:...
  missing_state:
    not_connected | expired | scope_insufficient | revoked |
    approval_required | policy_blocked
  requested_scopes:
    - scope:...
  preview_required: boolean
  approval_required: boolean
  wallet_request_refs:
    - capability_request:... | approval_request:...
  hypervisor_surface_refs:
    - surface://connectors-tools-mcp
  status:
    waiting_for_auth | waiting_for_approval | approved |
    denied | completed | revoked
```

## Conformance Checks

- ioi.ai may coordinate multiple models and strategies, but it must not execute
  consequential actions outside Hypervisor/daemon gates.
- ioi.ai may offer Auto/MoW selection or user-directed agent/harness/model
  selection, but both modes must consume Hypervisor-brokered connector/tool/MCP
  capability manifests instead of granting raw connector credentials or ambient
  tool access to the selected participant.
- ioi.ai must not be conflated with the Hypervisor Operator Plane. ioi.ai can
  ask, coordinate, inspect, summarize, and draft operator-plane requests, but
  effectful host/platform changes still flow through declared Hypervisor
  application-surface contracts, daemon admission, wallet authority, Agentgres,
  and receipts.
- ioi.ai-like coordination should be buildable from Hypervisor surfaces; ioi.ai
  is first-party dogfood, not a privileged product-only capability.
- ioi.ai connector/auth escalation must use Connectors / Tools / MCP
  `RuntimeToolContract` or MCP contracts, wallet.network authority, daemon
  admission, Agentgres refs, and receipts. It must not call provider APIs
  directly or hold connector secrets.
- ioi.ai may run backend/headless conductors only as Hypervisor clients over
  declared application-surface, Operator Plane, daemon/Core, wallet, Agentgres,
  and receipt contracts.
- Multi-path goal pursuit must be goal-appropriate. Do not require benchmark
  scorecards or leaderboards for ordinary research, chat, or operations work.
- Shared message boards, progress feeds, leaderboards, and attempt summaries are
  projections. Agentgres-admitted operations and receipts define truth.
- Cross-session graphs that coordinate multiple organizations or domains must
  reference `MultiPartyCollaborationEnvelope` / collaboration context refs and
  share only allowed refs, restricted views, redacted summaries, receipts, or
  explicit private slices admitted by policy.
- Final answers must identify grounded evidence, unresolved uncertainty, and
  authorization state when those affect the user outcome.
- Connector and generalized-computer-use actions require wallet.network scopes,
  leases, and receipts when they touch private data, credentials, money,
  external systems, or policy-sensitive resources.
- Learned conductors are Foundry-produced planning/routing advisors, not
  ioi.ai-owned runtime authority or automatic self-modification paths.
- Material orchestration decisions should carry an orchestration constraint
  envelope, selected verifier path refs, and an orchestration decision receipt.
- Orchestration policy, model routing, worker routing, and authority decisions
  must remain distinct. A good model score, benchmark result, or learned
  conductor recommendation is not an authority grant.
- Multi-model or multi-agent patterns such as aggregation, debate, critique, or
  branch-and-merge should be selected only when the expected value justifies the
  extra latency, cost, privacy exposure, and verification burden.
- Marketplace workers used by ioi.ai outcomes must preserve explainable routing
  and contribution refs; ioi.ai must not silently clone worker internals into a
  default harness.
- Robotics simulation/training belongs to Foundry; physical actuator execution
  belongs to Physical Action Safety and daemon admission.

## Anti-Patterns

Avoid:

```text
ioi.ai = chat-only wrapper
ioi.ai = daemon runtime
ioi.ai = Hypervisor Operator Plane
ioi.ai = privileged Hypervisor substrate
ioi.ai = private headless Hypervisor instance
collaborative outcome = fixed swarm
collaborative outcome = benchmark only
collaborative outcome = public leaderboard by default
collaborative outcome = child sessions with host admin power
connector/auth escalation = direct provider API call
selected harness/model = direct connector credential holder
Auto/MoW conductor = secret or tool authority owner
outcome conductor = hidden meta-harness runtime
orchestration policy = authority grant
verifier path = one model judge
benchmark receipt = universal worker truth
learned conductor = hidden authority
multi-model answer = authority
connector access = credential ownership
robotics training = ordinary chat task
physical action = generic tool call
```

Correct:

```text
ioi.ai asks, coordinates, compares, and synthesizes
ioi.ai dogfoods Hypervisor through declared application-surface contracts
Hypervisor Operator Plane operates Hypervisor through declared surface contracts
Hypervisor executes governed sessions
Automations owns durable workflow/service/mission specs
Foundry builds and evaluates reusable capability
authority providers and local/domain governance authorize as required
wallet.network supplies portable delegated authority for connectors,
credentials, money, declassification, and high-risk external effects
aiagent.xyz/MoW supplies workers and preserves attribution
Agentgres records admitted truth
IOI L1 settles only selected public/economic commitments
```

## Related Canon

- [`control-plane.md`](./control-plane.md)
- [`../../components/hypervisor/core-clients-surfaces.md`](../../components/hypervisor/core-clients-surfaces.md)
- [`../../components/hypervisor/foundry.md`](../../components/hypervisor/foundry.md)
- [`../../components/connectors-tools/doctrine.md`](../../components/connectors-tools/doctrine.md)
- [`../../components/daemon-runtime/default-harness-profile.md`](../../components/daemon-runtime/default-harness-profile.md)
- [`../../components/daemon-runtime/events-receipts-delivery-bundles.md`](../../components/daemon-runtime/events-receipts-delivery-bundles.md)
- [`../../components/wallet-network/doctrine.md`](../../components/wallet-network/doctrine.md)
- [`../../components/wallet-network/api-authority-scopes.md`](../../components/wallet-network/api-authority-scopes.md)
- [`../aiagent/worker-marketplace.md`](../aiagent/worker-marketplace.md)
- [`../../foundations/mixture-of-workers.md`](../../foundations/mixture-of-workers.md)
- [`../../foundations/physical-action-safety.md`](../../foundations/physical-action-safety.md)
