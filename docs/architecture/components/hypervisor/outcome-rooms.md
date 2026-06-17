# Outcome Rooms And Collaborative Missions Over Hypervisor

Status: canonical architecture authority.
Canonical owner: this file for the Outcome Room pattern, ioi.ai/chat.ioi.ai
Outcome Rooms, Collaborative Missions over Hypervisor, multi-agent/multi-session
search, benchmark-gated outcome races, shared message/leaderboard/evidence
rooms, and Stockfish-style coding/computer-use search patterns.
Supersedes: product prose that treats collaborative agents as a group chat,
unbounded swarm, separate runtime, or leaderboard without authority, receipts,
and replay.
Superseded by: none.
Last alignment pass: 2026-06-17.

## Canonical Definition

**An Outcome Room is ioi.ai/chat.ioi.ai's first-party use of Hypervisor
Core, CLI/headless operation, Automations, sessions, harness adapters, and
Foundry/eval lanes to turn one user intent into one measurable outcome through
governed multi-agent and multi-session search.**

It is not a new Hypervisor runtime or a required Hypervisor product surface.
It is the canonical ioi.ai product implementation of a general pattern that
any Hypervisor client, SDK, enterprise console, or third-party system may build:
a durable Collaborative Mission that coordinates many agents, harnesses,
models, humans, sessions, and verifier paths under explicit authority, budget,
privacy, and quality guardrails.

Product line:

```text
State the goal in chat.ioi.ai.
ioi.ai opens an Outcome Room over Hypervisor.
Agents explore in isolated sessions.
Evals score attempts.
Receipts prove why the winner won.
Foundry turns lessons into reusable capability.
```

It is not:

```text
a chatbot room
a fixed swarm
a separate runtime beside the daemon
a replacement for Hypervisor Automations
a replacement for Foundry
a mandatory Hypervisor UI for all users
a marketplace by itself
a leaderboard without receipts
a direct self-improvement path
an excuse to bypass wallet.network authority
```

## Owns

Outcome Rooms own ioi.ai-level coordination and projections for:

- the outcome objective and acceptance criteria;
- participant roster across humans, workers, models, and harness adapters;
- search policy and attempt allocation;
- isolated sessions, branches, snapshots, or workspace attempts;
- shared message board and coordination log projections;
- attempt submissions and result packages;
- benchmark, eval, visual-verification, static-analysis, runtime-trace, and
  quality-guardrail scorecards;
- leaderboard and promotion state;
- failure mining and reusable lesson extraction proposals;
- run history, receipts, replay links, artifacts, and evidence projections.

## Does Not Own

Outcome Rooms do not own:

- daemon execution semantics;
- wallet.network authority, secrets, payment scopes, capability leases, or
  declassification;
- Agentgres admitted truth, state roots, artifact refs, archive refs, or
  restore validity;
- Foundry training, distillation, or package publication;
- the selected harness's internal loop;
- participant model private reasoning;
- marketplace settlement;
- IOI L1 settlement by default.

## Stack Relationship

```text
chat.ioi.ai / ioi.ai Goal Chat
  creates, inspects, and coordinates the first-party Outcome Room experience

Hypervisor Automations
  owns the durable CollaborativeMission / AutomationSpec and trigger policy

Hypervisor CLI / Headless Client
  provides the programmable operation lane ioi.ai can use to start, inspect,
  pause, resume, and govern sessions without becoming the runtime itself

Hypervisor Sessions
  isolate attempts across branches, sandboxes, VMs, browsers, shells,
  editors, workers, and provider nodes

Agent Harness Adapters
  bring Codex, Claude Code, Grok Build, DeepSeek TUI, OpenHands, Aider,
  local models, hosted agents, and custom harnesses in as proposal sources

Workbench
  inspects attempts, diffs, traces, failures, screenshots, and promoted patches

Foundry
  owns model/worker building surfaces, eval suites, benchmark gates,
  scorecards, failure mining, skill extraction, worker/package improvement,
  ontology-bound datasets, and promotion proposals

Hypervisor Daemon
  gates and executes consequential actions

wallet.network
  authorizes budgets, credentials, provider spend, secrets, and declassification

Agentgres
  records attempts, messages, artifacts, receipts, scorecards, state roots,
  replay refs, and promotion evidence

AIIP
  moves bounded work across runtimes or external autonomous systems

IOI L1
  anchors public prizes, bounties, disputes, rights, or settlement commitments
  only when triggered
```

## Stockfish-Style Coding And Computer Use

Outcome Rooms are the natural place for Stockfish-style coding and generalized
computer-use search.

```text
chess board state
  -> workspace, browser, terminal, VM, OS, app, or environment state

legal move
  -> ActionProposal, ToolIntent, patch, shell command, browser action,
     ModelPass, request_context, or scoped CapabilityExit

search tree
  -> branches, snapshots, sandbox sessions, candidate attempts, and rollbacks

evaluation function
  -> tests, benchmarks, static analysis, visual verification, runtime traces,
     policy checks, risk labels, and human review

principal variation
  -> promoted attempt path and replayable receipt chain

opening book / transposition table
  -> persistent workspace intelligence, skills, Agent Wiki / ioi-memory,
     known fixes, route preferences, and reusable recipes
```

Canonical search tools:

```text
multi-path code search
test/eval playouts
static analysis
visual verification
runtime traces
rollback/snapshot branching
skill reuse
failure mining
benchmark-gated improvement
```

This is not "more agents talking." It is a governed search/evaluation machine
where attempts become comparable, replayable, promotable, and teachable.

## Lifecycle

```text
1. User states a desired outcome in chat.ioi.ai, ioi.ai, Hypervisor, Wallet,
   or an API.
2. ioi.ai or another client creates an OutcomeRoom draft with objective,
   constraints,
   authority requirements, privacy posture, budget, and quality guardrails.
3. Hypervisor Automations turns the draft into a CollaborativeMission spec.
4. wallet.network grants scoped budgets, credentials, provider access, or
   declassification leases when required.
5. Hypervisor allocates sessions, branches, snapshots, sandboxes, providers,
   harness adapters, models, workers, and verifier lanes.
6. Participants propose and execute attempts through daemon gates.
7. Each attempt emits observations, artifacts, logs, traces, receipts, and
   Agentgres operation refs.
8. Foundry/eval lanes run tests, benchmarks, static analysis, visual checks,
   runtime tracing, quality guardrails, and regression checks.
9. The room ranks attempts by objective score, quality guardrails, cost,
   risk, reproducibility, privacy posture, and receipt completeness.
10. A promoted attempt enters review, merge/deploy/package, or delivery flow.
11. Failures and wins produce governed skill, memory, workflow, verifier,
    harness-profile, worker-package, or Foundry-job improvement proposals.
12. IOI L1 settlement occurs only when a bounty, prize, dispute, rights,
    public registry, or cross-domain commitment requires it.
```

## Minimal Implementation Objects

```yaml
OutcomeRoom:
  outcome_room_id: outcome_room:...
  owner_surface:
    ioi_ai | hypervisor_client | sdk_client | enterprise_console | third_party
  project_ref: project:...
  automation_ref: automation:...
  mission_ref: mission:...
  objective:
    summary: string
    metric_refs:
      - metric:...
    acceptance_criteria:
      - string
  quality_guardrails:
    - eval_gate:...
  privacy_posture_ref: ctee_posture:... | policy://... | null
  budget_policy_ref: policy://...
  authority_refs:
    - grant://... | lease://...
  participant_refs:
    - outcome_participant:...
  search_policy_ref: outcome_search_policy:...
  message_board_ref: outcome_message_board:...
  leaderboard_ref: outcome_leaderboard:...
  scorecard_refs:
    - outcome_scorecard:...
  attempt_refs:
    - outcome_attempt:...
  agentgres_refs:
    - agentgres://operation/...
  receipt_refs:
    - receipt://...
  status:
    draft | active | paused | waiting_for_review |
    promoted | completed | failed | archived

OutcomeParticipant:
  participant_id: outcome_participant:...
  participant_kind:
    human | worker | agent_harness_adapter | model_route |
    service_module | verifier | external_aiip_domain
  display_name: string
  harness_ref: harness_profile:... | agent_harness_adapter:... | null
  model_route_ref: model_route:... | null
  session_refs:
    - hypervisor_session:...
  authority_refs:
    - grant://... | lease://...
  contribution_receipt_refs:
    - receipt://...

OutcomeSearchPolicy:
  search_policy_id: outcome_search_policy:...
  strategy:
    multi_path_code_search | benchmark_race | eval_playout |
    verifier_tournament | human_agent_mix | custom
  max_parallel_attempts: integer
  max_depth: integer | null
  branch_policy_ref: policy://...
  rollback_policy_ref: policy://...
  allowed_harnesses:
    - harness_profile:... | agent_harness_adapter:...
  verifier_refs:
    - verifier:...
  required_checks:
    - tests
    - static_analysis
    - visual_verification
    - runtime_trace
    - benchmark
    - policy
  promotion_policy_ref: policy://...

OutcomeAttempt:
  attempt_id: outcome_attempt:...
  outcome_room_ref: outcome_room:...
  participant_ref: outcome_participant:...
  session_ref: hypervisor_session:...
  branch_ref: branch://... | null
  snapshot_ref: artifact://... | null
  proposed_action_refs:
    - action:...
  execution_refs:
    - result://...
  artifact_refs:
    - artifact://...
  trace_refs:
    - trace://...
  receipt_refs:
    - receipt://...
  scorecard_ref: outcome_scorecard:... | null
  status:
    proposed | running | blocked | failed_checks |
    scored | promoted | rejected | archived

OutcomeScorecard:
  scorecard_id: outcome_scorecard:...
  outcome_room_ref: outcome_room:...
  attempt_ref: outcome_attempt:...
  objective_scores:
    - metric:...
  quality_guardrail_results:
    - eval_gate:...
  cost_summary_ref: cost://... | null
  risk_labels:
    - risk:...
  reproducibility:
    replayable: true
    receipt_complete: true
    state_root_ref: state_root://...
  promotion_verdict:
    promote | hold | reject | needs_human_review
```

## Conformance Checks

- ioi.ai Outcome Rooms must run through Hypervisor Automations,
  CLI/headless/Core contracts, and daemon gates, not through an ungoverned chat
  process.
- Third-party Outcome Room-like products may use their own UI, but they must
  still bind to Hypervisor contracts before claiming IOI-grade authority,
  receipts, replay, or settlement.
- Every consequential attempt must produce receipts, Agentgres operation refs,
  and enough replay/evidence material to justify its leaderboard position.
- Leaderboards must rank by declared objective and guardrails, not raw model
  confidence or unverified claims.
- A promoted attempt must pass promotion policy, required eval gates, and
  authority checks before merge, deploy, delivery, or package publication.
- Shared message boards, reports, and leaderboards are projections. They do not
  become canonical truth without Agentgres admission.
- External harnesses remain proposal sources or adapter targets. They do not
  become Hypervisor clients, runtime truth, wallet authority, or Agentgres.
- Failure mining may propose skills, memory, workflow patches, verifier
  candidates, or Foundry jobs, but cannot self-mutate the runtime directly.
- Public bounty/prize/dispute settlement goes to IOI L1 only by trigger.

## Anti-Patterns

Avoid:

```text
Outcome Room = group chat
Outcome Room = unbounded swarm
Outcome Room = separate runtime
leaderboard = truth
message board = Agentgres
winning attempt = accepted without receipts
benchmark score = permission to deploy
external harness = Hypervisor authority
many agents = better result by default
failure mining = direct self-modification
shared workspace = private workspace by default
```

Correct:

```text
Outcome Room = ioi.ai implementation of governed multi-session search/eval
Collaborative Mission = durable automation class
Hypervisor Core / CLI-headless = programmable substrate for the room
participants propose
daemon gates and executes
wallet.network authorizes
Agentgres records
Foundry evaluates and mines lessons
Workbench inspects
Automations owns durable mission shape
IOI settles public commitments by trigger
```

## Related Canon

- [`core-clients-surfaces.md`](./core-clients-surfaces.md)
- [`providers-and-environments.md`](./providers-and-environments.md)
- [`../daemon-runtime/default-harness-profile.md`](../daemon-runtime/default-harness-profile.md)
- [`../daemon-runtime/events-receipts-delivery-bundles.md`](../daemon-runtime/events-receipts-delivery-bundles.md)
- [`../wallet-network/doctrine.md`](../wallet-network/doctrine.md)
- [`../agentgres/doctrine.md`](../agentgres/doctrine.md)
- [`../../_meta/source-of-truth-map.md`](../../_meta/source-of-truth-map.md)
- [`../../_meta/implementation-matrix.md`](../../_meta/implementation-matrix.md)
