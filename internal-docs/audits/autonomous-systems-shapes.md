# Autonomous Systems Shape Audit Before Phase 5

Status: living architecture audit
Created: 2026-05-17
Reviewed sources through: 2026-05-17
Owner: Autopilot / daemon-runtime / workflow-compositor / wallet.network / connectors-tools / Agentgres

## 1. Purpose

This audit exists to answer one question before Phase 5 connector expansion:

> Is Autopilot iterating toward the right foundational shape for building,
> deploying, governing, and improving autonomous systems, or should its core
> topology be corrected before more connector and integration surface hardens
> the wrong abstractions?

This is not a feature-comparison exercise against Google Gemini Enterprise
Agent Platform or Google ADK. Those systems are reference points for enterprise
agent lifecycle, SDK ergonomics, deployment, evaluation, samples, and governance.
The target is the correct shape for Autopilot specifically: sovereign, local
first where possible, daemon/runtime backed, wallet-authorized, receipt-rich,
workflow-composable, marketplace-compatible, and future Foundry-compatible.

The audit treats the current canonical IOI docs as the source of truth for
Autopilot doctrine:

- no second runtime;
- daemon/runtime contracts first;
- React Flow is a projection/authoring surface, not canonical state;
- wallet.network authorizes power;
- Agentgres remembers operational truth;
- events expose observation and receipts expose proof;
- models propose, runtime settles;
- tools/connectors expose typed, permissioned, receipted capabilities;
- workflows are bounded autonomous work composition, not hidden product state.

The intended outcome is a decision about Phase 5 readiness and a staged set of
shape corrections that prevents connector expansion from turning Autopilot into
only a connector hub, only a local daemon, only a workflow tool, or only a chat
shell.

## 2. Executive Findings

### Decision

Recommended Phase 5 decision:

> Split Phase 5 into a short P0 shape-hardening pass followed by connector
> expansion. Workstream 1, filesystem/Git proposal-first mutation, may proceed
> as the hardening proof. Broader connector expansion should wait until the P0
> shape corrections below are complete.

This is closest to option 3 from the prompt: split Phase 5 into shape-hardening
and connector expansion. It does not require pausing all implementation. It
means the first Phase 5 slice should prove the autonomous-system package shape,
authority binding, eval/replay hooks, and developer examples before adding many
production connectors.

### Broad Conclusion

Autopilot is broadly on the right path. Its strongest architectural choices are
stronger than the surveyed Google/ADK references for IOI's intended category:

- runtime truth is not owned by the UI;
- authority is separated from primitive runtime feasibility;
- secrets and BYOK keys belong to wallet.network-shaped brokerage;
- tools have contracts, risk classes, grants, approvals, and receipts;
- workflow composition is intended to compile into deterministic manifests;
- computer/browser use is shaped around leases, observations, proposals,
  actions, verification, trajectories, and cleanup;
- marketplace and Foundry implications are already present in the canonical
  architecture, not bolted on later.

The key weakness is not doctrine. The weakness is product/developer shape:
Autopilot has many strong primitives, but the "one package I build, test, run,
deploy, observe, and improve" concept is still implicit across worker,
workflow, harness, capability, policy, memory, evaluation, and deployment docs.
Google ADK and Agents CLI are much clearer about the developer lifecycle and
sample topology even though they are less sovereign and less receipt-oriented.

### What Google/ADK Reveal As Missing

Google's platform reveals lifecycle expectations Autopilot should not ignore:

- clear agent construction path;
- serialization and initialization/execution separation for deployable units;
- managed deployment modes;
- sessions and memory as named lifecycle resources;
- registry, identity, gateway, policies, observability, and evaluation as
  enterprise lifecycle surfaces;
- evals as a continuous quality loop using traces, simulated users, metrics,
  and optimization.

ADK reveals developer-ergonomic primitives Autopilot should expose cleanly:

- Agent, Tool, Session, State, Memory, Artifact, Event, Runner;
- callbacks/hooks at lifecycle points;
- tools from function signatures and schemas;
- action confirmation as a first-class pattern;
- visual builder that can produce editable project code;
- sample projects with README, env, agent code, tools, eval, tests, deployment,
  and diagrams.

The local example repos reveal the biggest practical gap: examples are treated
as canonical developer workflow, not just demos. Autopilot needs a canonical
autonomous-system sample kit with workflow manifest, tool contracts, authority
policy, evals, trace/replay, and promotion guidance.

### True Gaps Versus Deliberate Divergences

True gaps:

- no single explicit `AutonomousSystemManifest` or equivalent developer-facing
  package shape binding worker, workflow, harness, tools, models, authority,
  memory/session/artifacts, evals, deployment profile, and promotion metadata;
- examples/tutorials are not yet canonical enough to teach the intended shape;
- sessions, memory, artifacts, and evaluations exist in doctrine, runtime, or
  product surfaces, but are not yet presented as a simple developer lifecycle;
- enterprise lifecycle surfaces such as deployment profiles, revisions,
  promotion gates, quality monitors, and runbooks are scattered across docs;
- workflow compositor and Authority Center are stronger now, but they still
  need an "autonomous system package readiness" lens before connector sprawl.

Deliberate divergences:

- do not copy a hosted-first platform assumption;
- do not treat callbacks/hooks as ungoverned code snippets;
- do not let visual-builder code generation become canonical truth;
- do not collapse policy into tracing/observability;
- do not make IAM/Gateway semantics the root authority model; IOI's root is
  wallet.network plus daemon/Agentgres receipts.

### Strategic Dangers

Dangerous to copy from Google/ADK:

- framework-owned action runtime loops;
- loose callbacks with side effects outside authority receipts;
- cloud deployment as the default mental model;
- prompt/tool examples without persistent authority and receipt binding;
- visual builder project files as the source of execution truth.

Dangerous to ignore:

- developer lifecycle clarity;
- sample agents as onboarding infrastructure;
- session/memory/artifact/event primitives as named concepts;
- evals and traces as continuous quality loops;
- deployable agent object constraints such as serialization and lifecycle
  separation;
- enterprise registry, identity, gateway, and policy visibility.

## 3. Autopilot Current Shape

### Runtime Model

Status: partially implemented, with strong canonical doctrine.

Autopilot Desktop is the local product shell over a local IOI daemon/runtime
profile. The daemon is the universal execution endpoint for canonical Web4
work. It launches workflows, agents, workers, tools, models, connectors,
training jobs, benchmark jobs, evaluation jobs, routing decisions, and
artifact-producing jobs across local, hosted, provider, DePIN, TEE, and
enterprise environments.

Current runtime doctrine is strong:

- the daemon executes work and emits events/receipts;
- `ioi-cli`, TUI, SDK, Autopilot, and agent-ide are clients/projections;
- `RuntimeApiBridge` bridges public thread/turn APIs into the lower runtime
  service rather than replacing it;
- runs are compatibility aliases over durable thread/turn/event records;
- fixture profiles must be explicit when synthetic paths are used.

Implementation status from the current source tree:

- `packages/runtime-daemon/` is the daemon-local v0 public runtime surface;
- `crates/services/src/agentic/runtime/` is the canonical lower runtime home;
- `crates/node/src/bin/ioi-runtime-bridge.rs` is the bridge command path;
- `packages/agent-sdk/` is a client over the daemon/substrate;
- `crates/cli/` owns CLI/TUI client controls;
- `packages/agent-ide/` owns workflow/compositor projection;
- `apps/autopilot/` owns the product shell.

Shape implication: the runtime bones are correct. The missing piece is a
developer-facing autonomous-system package/lifecycle that makes the relationships
obvious without requiring maintainers to read many internal docs.

### Workflow Model

Status: partially implemented and recently hardened.

The workflow canvas is the construction language for bounded autonomous work.
The canonical Autopilot canvas doc names triggers, model nodes, tool nodes,
connector nodes, parser nodes, adapter nodes, decision nodes, loop/barrier
nodes, human gates, output/materialization nodes, subgraphs, tests, fixtures,
proposals, activation checklist, and replay/debug panes.

The compositor has recently moved toward canonical primitive taxonomy:

- model/tool capability binding instead of provider-flavored branches;
- readiness, grants, policy decisions, receipt behavior, and run history
  projection;
- default/advanced palette separation;
- terminal coding loop and harness teaching surfaces;
- compatibility helpers for old workflows.

Important boundary: React Flow can author and project workflow manifests, but
must not own runtime state or become a shadow truth store.

Shape implication: the workflow model is a strong foundation. Before Phase 5
sprawl, the compositor should gain an "autonomous system readiness" view that
answers: what worker/workflow/harness/capability/eval/deployment package would
this graph become?

### Node and Compositor Topology

Status: improved, still needs package-lifecycle clarity.

Current intended palette shape:

- Input / Trigger;
- Context;
- Agent Step / Model Capability;
- Tool Capability / Connector;
- Memory;
- Skills;
- Policy / Approval;
- Worker / Subagent;
- State;
- Control Flow;
- Verification;
- Artifact / Output;
- Recovery;
- Runtime / Harness.

Recent doctrine says complexity should live in configuration, ports, policies,
inspectors, emitted events, and receipts unless it represents a distinct
execution boundary. This is right. The next layer should not add many
Google-style framework nodes; it should add package/readiness affordances around
the existing canonical primitives.

### Agent, Worker, Skill, Tool Model

Status: partially implemented; terminology still overloaded in some product
and roadmap surfaces.

Current doctrine:

- Worker is the protocol actor that exposes responsibilities.
- Agent is a product-facing alias or instance compatibility surface.
- Model is a cognition backend.
- Tool is a typed runtime capability with schemas, risk, authority, and
  receipts.
- Connector exposes external systems as permissioned tools.
- Skill is guidance/instruction/procedure, not authority and not execution.
- Workflow is executable composition.
- Harness is reusable runtime topology around planning, model calls, tools,
  policy, approvals, memory, verification, artifacts, repair, and receipts.

Risk: "agent" can still mean product assistant, ADK-style agent object,
compatibility worker instance, or runtime session depending on context. Before
Phase 5, the developer-facing package shape should lock these distinctions.

### Deterministic Execution Boundary

Status: strong doctrine, partially implemented.

The core invariant is clear: models propose actions; the runtime settles them.
Consequential actions require policy decisions, authority leases, approvals when
required, receipts, and postcondition evidence. Tool outputs are schema
validated. External side effects require preconditions and postconditions.

Current implementation includes model capabilities, coding tool contracts,
authority evidence summaries, workflow capability preflight, runtime event
projection, and computer-use/action receipt shapes.

Risk: developer ergonomics can still make deterministic settlement feel like
debug internals. The product should elevate it as "system readiness and proof,"
not bury it in raw trace tabs.

### Authority Model

Status: strong and ahead of the references.

wallet.network is the canonical authority layer. It owns identity, secrets,
API keys, OAuth refresh tokens, connector credentials, BYOK model provider
keys, authority grants, approvals, revocation, payment authorization, data-use
permissions, and decryption leases. It does not execute work or store workflow
truth.

Primitive capability and authority scope are intentionally distinct:

- primitive capabilities: `prim:fs.read`, `prim:fs.write`, `prim:sys.exec`,
  `prim:ui.interact`, `prim:model.invoke`, `prim:connector.invoke`;
- authority scopes: `scope:gmail.read`, `scope:gmail.send`,
  `scope:repo.write`, `scope:commerce.order_submit`.

This is a deliberate IOI advantage. It should remain more explicit than
Google/ADK's tool/callback examples.

### Events, Receipts, Artifacts

Status: strong doctrine, partially implemented.

Canonical event kinds include thread, turn, context, model, tool, policy,
authority, approval, artifact, memory, MCP, delegation, workspace trust,
diagnostics, training, evaluation, benchmark, routing, receipt, and run
terminal events.

Receipts include policy, approval, model invocation, tool execution, artifact,
validation, merge, settlement, quality, routing, training, evaluation, benchmark,
workspace, diagnostics, and job receipts.

Important distinction:

- projection events are useful UI state;
- settlement receipts are verifier-checkable proof.

Risk: as Phase 5 adds connectors, product UI must not call traces "policy" or
receipt projections "settlement." Policy UI should show authority decisions and
constraints; trace UI should show chronological execution.

### Connector Model

Status: Phase 5 ready for local/proposal-first lanes.

Connector/tool doctrine is clear:

- no effectful tool without a `RuntimeToolContract`;
- every effectful tool binds to authority;
- high-risk tools require wallet approval;
- tools do not inherit ambient connector secrets;
- output must validate against schema and carry receipt-ready evidence;
- connector payloads become domain truth only through ConnectorMapping,
  DataRecipe, policy-bound views, and receipts.

The registry is now expected to expose typed tool name, input/output schemas,
risk class, auth scopes, credential readiness, approval requirement, rate
limits, idempotency, receipt behavior, workflow availability, agent availability,
and marketplace exposure eligibility.

Shape implication: the Phase 5 connector expansion can proceed, but only if
developer surfaces bind to the same contract model and examples teach this
pattern.

### Local vs Cloud Execution

Status: strong architecture, provider implementation pending.

Autopilot is local-first and private by default, but IOI daemon/runtime-node
profiles can run local, hosted, provider, DePIN, TEE, customer VPC, cloud
container, cloud VM, local container, local VM, mobile emulator, or task-scoped
browser profile sessions.

Recent isolated computer provider doctrine correctly reframes hosted providers:
they are any leased environment that is not the current application/browser/
desktop instance. Local or cloud is deployment topology; the runtime contract is
lease, observe, target, propose, act, verify, retain, clean up.

### Persistence Model

Status: partially implemented.

Current doctrine:

- Agentgres owns canonical operational truth, runs, tasks, artifacts, receipts,
  policy decisions, training lineage, benchmark state, routing decisions,
  projections, and ledgers.
- Local files, browser storage, SDK checkpoints, workbench state, GUI captures,
  and fixtures are projections/test material unless written through
  daemon/Agentgres-compatible APIs with receipts.
- Filecoin/CAS handles large payloads, evidence, archives, and packages by CID.
- wallet.network owns secret and authority state, not rich app state.

Gap: developer-facing persistence profiles should be simpler. ADK's session,
state, memory, artifact naming is useful as an ergonomic layer, even though IOI
must back it with Agentgres/wallet/Filecoin semantics.

### Policy and Governance

Status: strong architecture, product surface recently repaired.

IOI policy is not just observability. It gates authority. The recent Authority
Center refresh and workflow capability binding reduce drift from old Settings
and Policy panels. Before Phase 5, this should be tied to autonomous-system
readiness so each package can answer:

- what authority scopes can this system request?
- which scopes are standing, single-use, or forbidden?
- where are approval gates?
- what receipts are required?
- what risk classes are reachable?
- what data retention modes are used?

### Foundry Implications

Status: planned and doctrine-level, but well-aligned.

Autopilot Foundry is the future product surface for turning repeated work,
examples, corrections, source documents, quality gates, verifier feedback, and
benchmarks into deployable workers. Foundry should not be a generic fine-tuning
form. It is a worker creation and improvement studio over the same workflow,
data recipe, evaluation, receipt, and authority substrate.

Current architecture already names Domain Ontologies, Data Recipes,
ConnectorMappings, PolicyBoundDataViews, DistilledOntologyDatasets,
EvaluationDatasets, TrainingBatchPlans, QualityGateReports, ModelCapacityProfile,
TrainingCostLedger, and PromotionDecision receipts. That is a strong future
shape. The missing piece is a small manifest slot today that lets Phase 5 work
remain Foundry-compatible later without implementing Foundry now.

### Marketplace and Service Implications

Status: planned.

The architecture is correct:

- Autopilot stabilizes private work;
- `aiagent.xyz` discovers, compares, installs, and routes workers;
- `sas.xyz` productizes repeatable worker services;
- IOI CLI instantiates sovereign domains;
- wallet.network authorizes installs, scopes, payments, escrows, and revocation;
- Agentgres records delivery, usage, quality, contribution, and settlement
  state.

Gap: Phase 5 connectors need marketplace exposure eligibility metadata from the
start, but should not attempt marketplace monetization yet.

### Overloaded or Ambiguous Terms

Terms currently doing too much work:

- **Agent**: product assistant, runtime session, ADK-style object, compatibility
  worker instance.
- **Capability**: primitive feasibility, model capability, tool capability,
  authority scope, marketplace ability. Canon says separate `prim:*` and
  `scope:*`; product copy must match.
- **Policy**: authority decision versus trace decoration. Keep policy separate
  from tracing.
- **Harness**: default agent loop, workflow template, validation proof surface.
- **Workflow**: graph authoring projection, manifest, executable runtime
  topology, package candidate.
- **Skill**: instruction bundle, marketplace item, imported source, prompt
  context. It must not imply authority or execution.
- **Runtime**: daemon substrate, hosted provider, local bridge, model runtime.

These should be clarified in a P0 terminology/manifest pass.

## 4. Google Gemini Enterprise Agent Platform Findings

### Agent Construction

Gemini Enterprise Agent Platform supports deploying agents built with multiple
frameworks: ADK, A2A, LangChain, LangGraph, AG2, LlamaIndex, or custom agents.
Its create-agent docs emphasize framework templates that handle common
development concerns such as object serialization and separating initialization
logic from execution logic.

Implied architecture:

- an agent is a deployable object or source package;
- deployability depends on serialization boundaries;
- long-lived handles, sockets, and non-serializable state are incompatible with
  managed runtime;
- initialization and request handling are separate lifecycle phases.

Autopilot implication:

- IOI should keep its daemon/workflow truth, but the package shape should also
  declare lifecycle separation: setup, readiness, run, resume, cleanup, deploy.
- Phase 5 connectors should not smuggle open handles or local-only assumptions
  into worker manifests.

Deliberate divergence:

- Autopilot should not make framework templates the architecture. Frameworks
  and providers are adapters into IOI contracts.

### Runtime and Scale

Gemini Enterprise's scale docs organize production under four lifecycle areas:
serverless runtime, context management through Sessions and Memory Bank,
continuous quality improvement through Example Store/Evaluation/Tracing, and
secure sandbox execution through Code Execution and Computer Use.

Implied architecture:

- production agents need managed runtime;
- runtime includes observability, release, access, and performance controls;
- sessions and memory are first-class context services;
- eval and example storage are not optional extras;
- code/computer use are governed sandbox capabilities.

Autopilot implication:

- IOI's architecture already has stronger local-sovereign primitives, but the
  product should expose the same lifecycle cluster: Run, Context, Quality,
  Sandbox, Govern.
- Phase 5 should not be "connectors only." It should prove connector actions as
  part of this lifecycle.

### Deployment

Gemini Enterprise supports deployment from an agent object, source files,
Dockerfile, container image, or connected Git repository. This reveals a useful
deployment shape:

- interactive/in-memory deployment for development;
- source-based deployment for IaC/CI;
- Dockerfile/container image for build control;
- Git-linked deployment for team workflows and CI/CD.

Autopilot implication:

- IOI should define deployment profiles even before hosted deployment is
  complete: local daemon, task-scoped container, hosted daemon, provider
  runtime, customer VPC, TEE, DePIN.
- Workflow/worker packages should record which profiles they support and which
  are blocked.

Deliberate divergence:

- Google deploys to managed Google infrastructure. IOI must keep local and
  sovereign domain deployment as first-class, not as development-only.

### Sessions, State, Memory

Gemini Enterprise Sessions maintain chronological interactions between users
and agents. Core concepts are Session, Event, State, and Memory. Memory Bank
generates and consolidates long-term memories from conversations, supports
continuous event ingestion, asynchronous generation, customizable extraction,
and multimodal understanding.

Autopilot implication:

- IOI has the lower-level Agentgres/event/receipt substrate, but the developer
  and product UX should still use simple terms: session, state, memory, artifact.
- Memory should be policy-bound and receipted, not only convenience context.
- Phase 5 connectors should state whether connector outputs can enter session
  state, long-term memory, eval datasets, or training data.

### Governance and Agent Gateway

Gemini Enterprise Govern centers around visibility, identity/access, security,
compliance, and operational oversight. Agent Registry stores approved agents,
tools, and MCP servers. Agent Gateway secures and governs user-agent,
agent-tool, and agent-agent interactions. Policies can be IAM allow/deny and
semantic governance policies, with dry-run and enforce modes.

Interesting policy metadata:

- source agent identity;
- registered services/tools;
- tool names and MCP operations;
- read-only/destructive/idempotent/open-world flags;
- dry-run before enforce.

Autopilot implication:

- IOI already has wallet/network authority and runtime receipts, which are
  stronger for sovereign/local autonomy.
- IOI should still expose registry/gateway-like visibility in product:
  installed tools, reachable connectors, authority posture, policy decisions,
  dry-run/proposal mode, and enforcement mode.
- Tool metadata such as read-only/destructive/idempotent/open-world should be
  included or mapped in RuntimeToolContract/search/readiness surfaces.

Deliberate divergence:

- IAM/Gateway is not the root authority model for IOI. wallet.network grants
  and revocation epochs are.

### Observability

Gemini Enterprise traces are described as a sequential timeline for
non-deterministic agent reasoning loops. They help explain why an agent chose
tools and paths.

Autopilot implication:

- IOI should continue separating trace from authority. Traces help understand;
  receipts prove.
- Product UI should label raw execution timeline, authority decisions, policy
  gates, and settlement receipts distinctly.

### Evaluation

Gemini Enterprise's evaluation workflow is:

```text
define eval cases
-> run inferences
-> generate traces
-> compute metrics
-> analyze failures
-> optimize agent
```

Capabilities include scenario generation, user simulation, environment
simulation, multi-turn evaluation, automated raters, failure analysis, and
prompt optimization.

Autopilot implication:

- IOI should not wait for Foundry to make evals first-class. Every Phase 5
  connector should ship with fixture evals, failure taxonomy, replay, and
  scorecard hooks.
- Environment simulation maps well to IOI's fixture/sandbox/provider doctrine.

### Enterprise Lifecycle Assumptions

Gemini Enterprise treats agents as:

- standalone deployable units;
- framework-built applications;
- registry/governance resources;
- endpoint/runtime resources;
- session and memory consumers;
- eval/trace quality targets;
- identity-bearing actors.

Autopilot should learn from this lifecycle clarity while keeping a different
root ontology: workers and workflows under IOI daemon/Agentgres/wallet
contracts.

## 5. Google ADK Findings

### Core Concepts

ADK names a small set of primitives:

- Agent;
- Tool;
- Callbacks;
- Session and State;
- Memory;
- Artifact;
- Code Execution;
- Planning;
- Models;
- Event;
- Runner.

This is developer-friendly. It gives people a grammar for building before they
learn platform details.

Autopilot equivalent:

- Worker/Agent Step/Model Capability for cognition;
- RuntimeToolContract and Tool Capability for tools;
- Hook/Hook Policy for governed callbacks;
- thread/turn/session state through daemon/Agentgres;
- memory-manager and memory receipts;
- artifacts and receipt refs;
- computer/code/shell/sandbox lanes;
- workflow/harness for planning and orchestration;
- model router for models;
- runtime events and receipts;
- daemon runtime as runner.

Gap: Autopilot has the pieces but not the same single beginner-facing grammar.

### Agents and Workflow Agents

ADK supports LLM agents and deterministic workflow agents such as Sequential,
Parallel, and Loop agents. ADK 2.0 introduces graph-based workflows, routes,
data handling, human input, collaborative agents, and dynamic workflows.

Autopilot stance:

- IOI should not copy ADK class names into the compositor.
- Keep generic canonical primitives: Control Flow, Worker, Agent Step,
  Verification, Approval, Tool Capability.
- ADK-style workflow patterns can become starter templates or compatibility
  imports.

### Tools

ADK function tools derive schema from function signatures, docstrings, type
hints, and defaults. It also supports long-running function tools and
agent-as-tool.

Autopilot equivalent:

- RuntimeToolContract is richer: schema, risk, primitive capability,
  authority scope, approval, evidence, receipt behavior, workflow/agent
  availability, and marketplace eligibility.

Gap:

- IOI should offer developer ergonomics that feel as easy as "write a typed
  function and docstring," but compile into RuntimeToolContract rather than
  bypassing it.

### Action Confirmations

ADK exposes tool confirmation patterns. Python can mark a FunctionTool as
requiring confirmation; TypeScript can request confirmation through tool
context.

Autopilot equivalent:

- ApprovalReceipt and wallet approval grants bound to request hash, policy
  hash, scope, and expiry.

IOI is stronger here, but the UX should be just as obvious:

- "This tool requires approval";
- "This draft is safe";
- "This send is blocked";
- "This authority grant is missing";
- "This action is waiting for human decision."

### Sessions, State, Memory

ADK Sessions contain app name, user id, event history, session state, and update
time. State is serializable key-value data with scope prefixes such as session,
user, app, and temp. Memory is long-term searchable knowledge across sessions.

Autopilot equivalent:

- Agentgres operation log and projections;
- daemon thread/turn/item records;
- memory manager and MemoryMutationReceipt;
- wallet authority for data-use and retention.

Gap:

- Use ADK's simple state/memory vocabulary as a UX layer, but bind it to IOI
  privacy, retention, authority, and receipt semantics.

### Callbacks

ADK callbacks include before/after agent, before/after model, before/after tool.
Examples use callbacks for validation, rate limiting, state mutation, and
guardrails.

Autopilot equivalent:

- governed hook types: pre-model, post-model, pre-tool, post-tool, approval,
  event subscriber, workflow activation;
- hook side-effect contracts, authority scopes, failure policy, visibility.

Deliberate divergence:

- Autopilot should not allow arbitrary callback side effects without authority,
  failure policy, and receipts.

### Artifacts

ADK artifacts are versioned binary data associated with session/user scope,
represented with MIME type and bytes.

Autopilot equivalent:

- ArtifactEnvelope, ArtifactReceipt, Filecoin/CAS refs, redaction status,
  promotion receipts.

Gap:

- Product UX should make artifacts visible as first-class deliverables and
  evidence, not only files in logs.

### Events

ADK Events are immutable records of execution: user messages, agent replies,
tool calls, tool results, state changes, control signals, and errors. They carry
author, invocation id, event id, timestamp, actions, and branch metadata.

Autopilot equivalent:

- RuntimeEventEnvelope and richer receipt/event taxonomy.

IOI is stronger, but should keep event ergonomics simple for SDK/CLI users.

### Runner and Runtime

ADK supports `adk web`, `adk run`, `adk api_server`, deployment, observability,
evaluation, and safety/security. This is a clean development loop.

Autopilot equivalent:

- Autopilot GUI, IOI CLI/TUI, daemon API, SDK, runtime profiles.

Gap:

- IOI should document and test a similarly crisp loop:

```text
define system
-> bind capabilities
-> run locally
-> inspect trace/receipts
-> evaluate
-> package worker/workflow
-> deploy/promote when ready
```

### Visual Builder

ADK Visual Builder provides a drag-and-drop UI with left config panel, central
component canvas, right assistant, save/test loop, and project code output in
YAML/Python.

Autopilot equivalent:

- Workflow Composer and harness teaching view.

IOI advantage:

- React Flow compiles to runtime/workflow manifests and remains a projection,
  rather than project files becoming hidden runtime truth.

Gap:

- ADK's builder makes "edit, save, test" obvious. Autopilot should keep its
  stronger runtime doctrine but improve package/readiness affordances.

### Skills

ADK skills use progressive disclosure through `SkillToolset`: list skills,
load skill, load skill resource. Local examples show inline skills, file-based
skills, external repo skills, and meta skill creation.

Autopilot equivalent:

- skill discovery/import, frontmatter validation, active skill hash, prompt
  audit provenance, Skill Context workflow projection, skills as guidance not
  authority.

IOI is aligned. The remaining risk is UX and marketplace-grade discoverability.

## 6. Example Repository Findings

### `examples/agents-cli-main`

Key observations:

- The repo positions `agents-cli` as a tool and skills package for coding agents
  to build, evaluate, deploy, publish, and observe agents on Google Cloud.
- It is explicitly not a coding agent. It is a CLI and skill toolkit that
  coding agents consume.
- It installs skills for Gemini CLI, Claude Code, Codex, Antigravity, and
  other agents.
- Commands cover setup, login, scaffold, run, install, lint, eval, deploy,
  publish, infra, data ingestion, info, update.
- Docs teach a lifecycle: understand, scaffold, build, evaluate, deploy,
  publish, observe.
- Generated project structure includes:
  - `app/agent.py`;
  - `app/app_utils/*`;
  - `tests/eval/evalsets/basic.evalset.json`;
  - `tests/eval/eval_config.json`;
  - integration/unit tests;
  - `pyproject.toml`;
  - guidance file such as `GEMINI.md`;
  - `Makefile`;
  - `.env`;
  - deployment Terraform/CI/CD when selected.
- Project scaffolding supports prototype-first, Agent Runtime, Cloud Run, GKE,
  A2A, RAG, session storage, datastore, CI/CD, and upgrade/enhance flows.
- The workflow skill makes requirements clarification mandatory before
  scaffolding and makes evaluation mandatory before deployment.

Implications for Autopilot:

- IOI needs a comparable "autonomous system project" scaffold or sample shape,
  even if implementation starts in Autopilot GUI rather than CLI.
- A guidance file pattern is useful, but IOI should bind guidance to skills,
  policies, and authority. Guidance must not become authority.
- Prototype-first is exactly right for IOI, but "prototype" should mean local
  daemon + fixture/mock/live readiness explicitly, not hidden dev bypasses.
- Evaluation must be part of default workflow, not an advanced option.

### `examples/adk-samples-main`

Key observations:

- Samples span Python, TypeScript, Go, Java.
- Python agents are organized as vertical examples with README, `.env.example`,
  `pyproject.toml`, agent code, tools, prompts, sub_agents, eval, tests,
  deployment scripts, diagrams, and often Makefiles.
- The root Python README categorizes samples by use case, tags, interaction
  type, complexity, agent type, and vertical.
- Samples include single-agent and multi-agent patterns, RAG, BigQuery, MCP,
  human-in-the-loop, custom tools, external API integrations, code execution,
  safety plugins, memory, data science, workflows, and commerce-adjacent demos.
- Many samples are marked demonstration/not production, but they are still
  strong teaching artifacts.

Implications for Autopilot:

- IOI should create fewer but more canonical examples. Each should prove IOI
  doctrine: authority, receipts, replay, proposal-first mutation, eval,
  workflow manifest, and cleanup.
- Samples should be tagged by capability lane, risk tier, authority scopes,
  runtime profile, workflow primitives, and eval coverage.
- The example README should teach the system shape, not only how to run it.

### Customer Service Sample

Files reviewed:

- `python/agents/customer-service/README.md`;
- `customer_service/agent.py`;
- `customer_service/tools/tools.py`;
- `customer_service/shared_libraries/callbacks.py`;
- `eval/test_eval.py`;
- eval session/test JSON files.

Concrete patterns:

- A single root agent binds model, global instruction, instruction, tools, and
  callbacks.
- Tools model CRM/cart/product/recommendation/service operations.
- Callbacks validate customer id, lowercase inputs, enforce business rules,
  perform approval-like logic, and apply deterministic behavior after tools.
- Eval uses ADK `AgentEvaluator` against session/test files.
- README explicitly says mocked tools do not persist all changes and points to
  tool files for real backend integration.

Autopilot implications:

- The pattern is useful, but IOI should not let callbacks perform side effects
  silently. These become Hook/Policy/Tool contract surfaces with authority.
- Mock behavior must be visible as fixture/simulation readiness, not mistaken
  for live connector state.
- For Phase 5, this maps to proposal-first connector tools and draft/read-only
  external actions.

### Agent Skills Tutorial

Files reviewed:

- `python/agents/agent-skills-tutorial/README.md`;
- `app/agent.py`;
- local `SKILL.md` examples.

Concrete patterns:

- Skills use progressive disclosure: L1 metadata, L2 instructions, L3 resources.
- `SkillToolset` auto-registers `list_skills`, `load_skill`, and
  `load_skill_resource`.
- The tutorial includes inline, file-based, external, and meta skill patterns.

Autopilot implications:

- IOI's skill doctrine is aligned: skills are prompt/context guidance, not
  authority.
- Autopilot should expose skill provenance, active hash, trust/pin/version,
  import source, and prompt audit at runtime.

### HITL Workflow Sample

File reviewed:

- `python/agents/workflows-HITL_concierge/agent.py`.

Concrete patterns:

- Uses `WorkflowAgent` edges with explicit functions and an `LlmAgent`.
- Uses `RequestInput` to pause and request human input.
- `rerun_on_resume=True` shows resume behavior as part of the workflow.

Autopilot implications:

- Human gates should remain distinct execution boundaries when they pause
  execution.
- IOI should keep approvals/handoffs as runtime receipts, not just UI prompts.

### Repository Structure Lessons

The practical ADK/Agents CLI lesson is simple: every serious sample should have:

- one sentence purpose;
- architecture diagram or topology summary;
- setup and auth;
- local run;
- eval;
- unit/integration tests;
- deployment or explicit non-deployment posture;
- tool list;
- safety/authority constraints;
- known limitations;
- mock/live distinction.

Autopilot examples should add:

- workflow manifest;
- capability bindings;
- policy/authority scope file;
- receipt and replay expectations;
- computer/browser/sandbox profile if used;
- Agentgres/artifact retention profile;
- promotion/marketplace eligibility metadata when applicable.

## 7. Comparative Shape Matrix

| Dimension | Autopilot Current Shape | Gemini Enterprise | ADK | Example Repos | Gap / Implication |
| --- | --- | --- | --- | --- | --- |
| Agent abstraction | Product-facing agent alias over worker/runtime sessions; partially overloaded | Deployable framework/custom agent | `Agent`, `LlmAgent`, workflow agents | `app/agent.py`, root agents | Clarify agent vs worker vs workflow vs harness. |
| Worker abstraction | Protocol actor with responsibilities; marketplace/foundry target | Not primary term | Agent is worker unit | Samples are agent-centric | IOI should keep Worker as durable actor, but map agent UX clearly. |
| Tool abstraction | RuntimeToolContract with schema/risk/authority/receipts | Tools/MCP via registry/gateway | Function tools, MCP, OpenAPI, confirmations | Python functions, MCP tools | IOI stronger, needs simpler authoring ergonomics. |
| Skill abstraction | Guidance with provenance/hash/prompt audit; not authority | Not central in Agent Platform docs | ADK Skills and SkillToolset | Skill tutorial | Good direction; needs marketplace-grade UX. |
| Workflow graph | React Flow projection compiling to manifests; no shadow truth | LangGraph/framework options; Agent Builder/Studio | Workflow agents and graph workflows | Workflow samples | IOI stronger if package lifecycle is explicit. |
| Runtime/session model | Daemon thread/turn/event bridge; Agentgres target | Managed Agent Runtime and Sessions | Runner, Session, State | `adk run`, `adk web`, eval sessions | Add beginner-facing session/state/memory/artifact lifecycle. |
| Event stream | Rich event envelope and receipt taxonomy | Traces and session events | Immutable Events | Eval traces/session JSON | Strong, but keep trace vs receipt labels clear. |
| Artifact model | ArtifactEnvelope, receipts, CAS/Filecoin refs | Not central in pages reviewed | Artifacts with MIME/version scope | Media/sample outputs | Make artifacts visible in product and examples. |
| Memory model | Memory manager, memory receipts, Agentgres/wallet doctrine | Memory Bank | MemoryService | memory-bank sample | Strong doctrine; needs ergonomic profiles. |
| State persistence | Agentgres canonical operation log; UI projections | Sessions/Memory Bank managed | Session State prefixes | session files/eval data | Add simple state scopes over Agentgres. |
| Deterministic execution | Runtime settles, model proposes, receipts prove | Managed runtime, less explicit receipts | Runner executes agent loop | Tool/callback code | IOI stronger; package it for developers. |
| Authority/delegation | wallet.network grants, scopes, approvals, revocation | IAM, agent identity, gateway | Tool confirmations/callbacks | env/API keys, mocks | IOI stronger; keep UX clear. |
| Policy/governance | Authority Center, policies, receipts | Govern, Registry, Gateway, IAM, semantic policies | Safety callbacks/plugins | safety plugins | Add dry-run/enforce and registry visibility language. |
| Approvals | Wallet approvals, ApprovalReceipt | confirmation/gateway policy | FunctionTool confirmation, HITL | approval callbacks/workflows | IOI stronger; keep human gates first-class. |
| Receipts | First-class proof objects | Traces/logs/evals | Events/actions, not receipts | eval outputs | Key IOI differentiator. |
| Evaluation | Benchmark/eval doctrine and receipts; Phase 5 validation net | End-to-end eval, user/env simulation, optimization | Eval CLI | eval dirs/tests | Need default eval scaffolds per autonomous-system sample. |
| Deployment | Runtime profiles local/hosted/provider/etc.; partial | Five deploy modes | Agent Runtime, Cloud Run, GKE | deployment docs/Terraform | Need deployment profile manifest slots. |
| Local execution | Primary Autopilot mode | Dev/local secondary | `adk run`, `adk web` | local commands | IOI differentiator; preserve. |
| Cloud execution | Planned hosted/runtime nodes | Primary managed target | Deploy docs | CI/CD/deploy examples | Define profiles without blocking local work. |
| Connector model | Authority-scoped tools, mappings, data recipes | Integration connectors, registry/gateway | Prebuilt/custom/MCP/OpenAPI tools | many vertical integrations | Start Phase 5 with package/eval pattern. |
| Marketplace readiness | aiagent/sas doctrine, eligibility metadata | Agent registry, sharing | integrations catalog | sample catalog | IOI needs worker card/package examples. |
| Foundry readiness | Strong doctrine, not implemented | Eval/optimization loops | eval/fix loop | eval samples | Add lineage slots now, implementation later. |
| UI/compositor | Strong React Flow direction | Visual Builder/Studio | Visual Builder | diagrams | Add autonomous-system readiness lens. |
| CLI/TUI | IOI CLI/TUI over daemon | agents-cli and gcloud | adk CLI | agents-cli workflows | IOI CLI should offer simple build/run/eval/package loop. |
| Debugging/replay | Events, receipts, replay, traces | Cloud Trace | events/evals | eval session JSON | Strong; product should simplify. |
| Enterprise adoption | Sovereign/local plus future domains | Enterprise managed platform | framework/dev centric | scaffold/deploy guides | Need crisp lifecycle docs and examples. |
| Autonomous governance | wallet/Agentgres/receipts/policy | IAM/Gateway/Registry | callbacks/safety | limited | IOI stronger; avoid overcomplex UX. |

## 8. Shape Tensions and Design Questions

### Workflow-First vs Agent-First

Tension: Google/ADK is agent-first. Autopilot has been moving workflow-first
because workflows are the authoring language for bounded work.

Why it matters: connector expansion can sprawl if every integration becomes an
agent or a bespoke node instead of a capability in a workflow.

Google/ADK stance: agents are the primary build/deploy unit; workflows are
agent patterns or visual builder components.

Autopilot stance: workflows are executable composition and workers are durable
actors.

Recommendation: keep workflow-first for authoring, but package it as an
Autonomous System: worker identity + workflow/harness + capability bindings +
eval/deployment profiles.

### Agent vs Worker vs Skill vs Tool

Tension: user-facing "agent" is easy, but IOI protocol needs Worker as the
durable actor, Skill as guidance, Tool as capability, Connector as external
system adapter.

Recommendation: keep all four, but lock a public glossary and manifest mapping
before Phase 5 broad connectors. Do not let "agent" absorb everything.

### Deterministic Runtime vs Flexible Agent Framework

Tension: ADK callback/function ergonomics are fast, but can blur authority and
side effects. IOI's deterministic boundary is safer but heavier.

Recommendation: build ergonomic wrappers that generate contracts and hooks,
not bypasses. A Python/TS helper can feel like function tools while still
emitting RuntimeToolContract.

### Local Sovereign Execution vs Cloud Persistence

Tension: Google assumes managed cloud value. IOI starts at the local trust
boundary but needs hosted/team/cloud paths.

Recommendation: model local/cloud as runtime profiles under the same manifest.
Do not use cloud readiness as a blocker for local Phase 5 lanes.

### Connector Expansion vs Correct Topology

Tension: connectors create product value quickly, but can harden ad hoc
provider branches.

Recommendation: Phase 5 starts with filesystem/Git and browser/computer-use as
topology proofs. Google Workspace and mail follow after package/eval/readiness
shape is locked.

### GUI Canvas Simplicity vs Expressive Composition

Tension: canonical runtime has many primitives. A user needs a small intuitive
palette.

Recommendation: keep canonical primitives, expose package/readiness concepts in
inspector tabs and helper views, not dozens of new nodes.

### Policy-Bound Workflow Governance vs Agent-by-Agent Governance

Tension: Google Gateway policies govern agents and services. IOI can govern at
workflow node, tool, worker, run, and authority grant levels.

Recommendation: workflow governance should compile to policy targets and
wallet grants, then render as authority readiness. Do not put trace-only data
in policy UI.

### Autopilot as App vs Runtime vs Protocol Surface

Tension: Autopilot is a product shell, but it is also where users experience
the runtime.

Recommendation: keep Autopilot as product/workbench and daemon as substrate.
Add explicit labels for projection, runtime event receipt, and settlement
receipt.

### Foundry Later vs Foundry-Compatible Now

Tension: Foundry is not in Phase 5, but connector choices will shape training
data later.

Recommendation: every connector/tool output contract should include optional
semantic data refs, retention mode, data-use authority, eval/training
eligibility, and redaction posture now.

### Marketplace/Service Composition

Tension: Phase 5 local tools can become worker packages and services later, but
marketplace monetization is not in scope.

Recommendation: include marketplace exposure eligibility metadata, but defer
publication/monetization. Worker Cards can be generated later from the same
manifest slots.

### Examples As Demos vs Examples As Canonical Patterns

Tension: sample repos can drift into toy demos.

Recommendation: IOI examples should be small, production-shaped, and
contract-checked. They should teach how to build safely, not just show features.

## 9. Recommended Autopilot Shape Corrections Before Phase 5

### P0-1: Lock An Autonomous System Manifest Shape

Problem: The durable package concept is implicit across worker, workflow,
harness, model/tool capability, authority, memory, eval, deployment, and
promotion docs.

Evidence: Google deploys agent objects/source/images/Git repos. ADK and
Agents CLI scaffold a concrete project with agent code, eval, tests, deployment,
and guidance. IOI currently has stronger primitives but scattered lifecycle
packaging.

Implication: Connector expansion may produce isolated tool integrations rather
than packageable autonomous systems.

Proposed correction: Define `AutonomousSystemManifest` or equivalent as a
developer-facing envelope. It can be an extension/profile of `ManifestEnvelope`
rather than a new runtime substrate.

Minimum fields:

```text
system_id
display_name
worker_ref
workflow_manifest_ref
harness_ref
model_capability_refs
tool_capability_refs
connector_mapping_refs
authority_scope_requirements
policy_profile_ref
approval_profile_ref
session_profile
memory_profile
artifact_retention_profile
eval_profile_refs
deployment_profiles
runtime_profiles
promotion_profile
marketplace_exposure_eligibility
foundry_lineage_refs
```

Expected benefit: Phase 5 work becomes package-shaped, not integration-shaped.

Risk if ignored: broad connector work may need expensive migration into worker,
marketplace, Foundry, and deployment package shapes later.

### P0-2: Publish A Terminology Boundary Table

Problem: Agent, worker, skill, tool, connector, workflow, harness, capability,
policy, trace, receipt, runtime are overloaded.

Evidence: ADK uses "Agent" as the core worker unit. IOI uses Worker as the
protocol actor and Agent as product-facing alias/instance in several contexts.

Proposed correction: Add a concise canonical glossary/table to the architecture
docs and reference it from Phase 5 and workflow compositor docs.

Expected benefit: Prevents new connectors, docs, and GUI labels from drifting.

Risk if ignored: Phase 5 surfaces will reintroduce provider/framework language
and blur authority scopes with capabilities.

### P0-3: Create One Canonical Phase 5 Proof Sample

Problem: IOI lacks a sample equivalent to Agents CLI generated projects or ADK
sample agents.

Proposed correction: Create a canonical "repo maintenance autonomous system"
sample around filesystem/Git proposal-first mutation.

It should include:

- README with purpose, topology, and safety posture;
- workflow manifest;
- tool contracts for fs/git/test;
- model capability binding;
- authority policy;
- approval profile;
- fixture eval cases;
- trace/receipt expectations;
- local run command;
- GUI run checklist;
- known limitations;
- package/readiness status.

Expected benefit: Workstream 1 becomes a teaching and regression target.

Risk if ignored: developers will learn IOI from scattered internals instead of
a correct pattern.

### P0-4: Add Package Readiness To Workflow Composer

Problem: Workflow readiness currently validates many runtime/capability pieces,
but the product does not yet present "this graph is or is not a packageable
autonomous system" as a first-class frame.

Proposed correction: Add a readiness summary for:

- manifest completeness;
- model/tool capability readiness;
- authority grants/scopes;
- approvals;
- eval fixtures;
- artifact retention;
- deployment profile;
- mock/live posture;
- receipt requirements.

Expected benefit: Users see why a graph can run, why it can package, and why it
cannot yet become a worker/service.

Risk if ignored: connector graphs will feel runnable but not productizable.

### P1-1: Make Session, State, Memory, Artifact UX Simpler

Problem: IOI has powerful event/receipt/memory/artifact doctrine, but ADK's
developer vocabulary is easier.

Proposed correction: Expose simple lifecycle concepts in SDK/CLI/Autopilot,
while keeping Agentgres/wallet/CAS implementation hidden behind receipts and
policy.

### P1-2: Add ADK-like Tool Authoring Ergonomics Over RuntimeToolContract

Problem: Function tools are easy in ADK. IOI contracts are safer but heavier.

Proposed correction: Add or document a helper path that derives initial
RuntimeToolContract from a typed function/spec, then requires risk/authority/
receipt fields before live exposure.

### P1-3: Evaluation-As-Default For Phase 5 Lanes

Problem: Evaluation exists in plans, but examples and connector lanes need a
default eval loop.

Proposed correction: Every Phase 5 lane has fixture evals and scorecard rows
from day one.

### P1-4: Deployment Profile Slots

Problem: hosted/container/VM/cloud is planned, but package manifests need slots
now so local work can migrate.

Proposed correction: Include local daemon, task-scoped browser, local container,
hosted daemon, customer VPC, TEE, and DePIN profile fields with readiness.

### P2: Foundry Compatibility Metadata

Problem: Foundry is later but connector data-use choices begin now.

Proposed correction: Include optional data recipe, connector mapping,
evaluation dataset, training eligibility, and retention slots in tool/workflow
outputs.

### P3: Full Enterprise Lifecycle Surface

Problem: Google has a mature enterprise Build/Scale/Govern/Optimize product
taxonomy.

Proposed correction: Later, make Autopilot/IOI show a similarly clear lifecycle
without copying hosted-first assumptions.

## 10. Proposed Target Shape

Autopilot should be shaped as:

> A sovereign autonomous systems workbench where users compose workers,
> workflows, capabilities, memory, policy, evaluations, and deployment profiles
> into packageable systems that run through IOI daemon/runtime contracts,
> receive authority from wallet.network, settle operational truth into
> Agentgres, and emit replayable events, artifacts, and receipts.

### Conceptual Model

```text
Autonomous System
  Worker identity / responsibility
  Workflow or harness topology
  Model capabilities
  Tool and connector capabilities
  Skills and instructions
  Policy and authority scopes
  Session/state/memory/artifact profiles
  Evaluations and verification gates
  Deployment/runtime profiles
  Receipts, traces, and replay
  Promotion/marketplace/foundry metadata
```

### Runtime Model

```text
user intent
-> workflow/harness manifest
-> capability readiness
-> authority scope request
-> policy decision
-> action proposal
-> approval if required
-> runtime execution
-> schema validation
-> verification
-> artifact/receipt emission
-> Agentgres operation/projection
-> replay/eval/promotion feedback
```

### Workflow/Compositor Model

The compositor should expose a small palette of canonical primitives and a
package readiness lens. Low-level runtime nodes remain in advanced/debug mode.
Every config field compiles into deterministic workflow/runtime manifests.

### Node Taxonomy

Default palette:

- Trigger / Input;
- Agent Step / Model Capability;
- Tool Capability;
- Connector;
- Memory;
- Skills;
- Policy Gate;
- Approval;
- Worker / Subagent;
- Control Flow;
- Verification;
- Artifact Output;
- Browser / Computer;
- Sandboxed Computer;
- Repository / Pull Request;
- Runtime / Harness.

Advanced palette:

- raw runtime event/control nodes;
- hook/policy internals;
- telemetry budget chains;
- low-level computer-use adapters;
- compatibility nodes for old workflows.

### Agent, Worker, Skill, Tool Distinctions

- Worker: durable actor/responsibility/package.
- Agent: product-facing instance or compatibility alias.
- Skill: instructions/resources/procedure; no authority.
- Tool: executable capability with contract, schema, risk, authority, receipts.
- Connector: external system adapter exposing tools.
- Workflow: executable composition graph/manifest.
- Harness: reusable workflow topology for autonomous behavior.
- Model: cognition backend/capability.

### Authority and Policy Model

Every live system has:

- primitive capability requirements;
- authority scope requirements;
- grant readiness;
- approval profile;
- policy target;
- revocation posture;
- receipt obligations;
- retention mode.

### Session, Memory, State, Artifact Model

Developer-facing terms:

- Session: current interaction/run context.
- State: serializable scoped scratch data.
- Memory: governed long-term recall.
- Artifact: materialized output/evidence.

Implementation truth:

- daemon thread/turn/item records;
- Agentgres operations/projections;
- wallet authority/data-use grants;
- Filecoin/CAS refs where appropriate;
- receipts for mutation/promotion.

### Deployment Model

Deployment profiles should be manifest-level:

- local daemon;
- task-scoped browser profile;
- local container;
- local VM;
- hosted daemon;
- cloud container;
- cloud VM;
- TEE;
- DePIN;
- customer VPC;
- mobile/device provider.

Each profile has readiness, authority, retention, cleanup, and eval support.

### Connector Model

Connectors expose RuntimeToolContracts, not ambient APIs. Connector outputs map
through ConnectorMapping and DataRecipe before becoming domain, eval, training,
or service truth.

### Evaluation Model

Every package can bind:

- eval cases;
- simulated users/environments;
- expected outcomes;
- fixture/live provider posture;
- failure taxonomy;
- scorecard rows;
- promotion gates.

### Future Foundry Compatibility

Do not implement Foundry in Phase 5, but keep these refs available:

- domain ontology;
- canonical object model;
- connector mapping;
- data recipe;
- policy-bound data view;
- evaluation dataset;
- distilled ontology dataset;
- quality gate;
- model capacity profile;
- training lineage;
- promotion decision.

### Marketplace and Service Compatibility

Each package should later be able to produce a Worker Card:

- task class;
- authority scopes;
- runtime profiles;
- evaluation scores;
- known limitations;
- artifact/receipt behavior;
- marketplace exposure eligibility;
- service promotion posture.

## 11. Phase 5 Decision

Decision:

> Split Phase 5 into a P0 shape-hardening pass followed by connector expansion.
> Start with filesystem/Git proposal-first mutation as the first hardening proof.

Specific ruling:

1. Proceed with Phase 5 Workstream 1 now, because it is local, reversible,
   inspectable, and exercises the correct runtime/tool/authority/receipt path.
2. Before broad production connector expansion, complete P0-1 through P0-4:
   autonomous-system manifest shape, terminology boundary, canonical proof
   sample, workflow package readiness.
3. Browser/computer-use hardening can proceed in parallel because it already
   shares the same lease/action/receipt doctrine and is required for GUI
   validation.
4. Google Workspace/mail live connectors should wait until the P0 package shape
   and eval sample pattern are present.
5. Blender/FreeCAD can begin after Workstream 1 if they use the same tool
   contract and artifact/receipt sample pattern.

This reduces integration debt without stopping forward motion.

## 12. Implementation Plan

### Step 1: Add Autonomous System Manifest Contract

Affected files:

- `docs/architecture/foundations/common-objects-and-envelopes.md`;
- `docs/architecture/_meta/source-of-truth-map.md`;
- possibly `internal-docs/implementation/runtime-module-map.md`;
- workflow schema/types in `packages/agent-ide/src/runtime/*`;
- daemon API docs if endpoint shapes are added.

Acceptance criteria:

- manifest fields are documented;
- worker/workflow/harness/capability/eval/deployment relationships are clear;
- no second runtime introduced;
- older workflow/package manifests can project into the new shape.

### Step 2: Lock Glossary and UX Language

Affected files:

- source-of-truth map;
- Autopilot local app/workflow canvas doc;
- Phase 5 guide;
- workflow node taxonomy/search strings.

Acceptance criteria:

- Agent/Worker/Skill/Tool/Connector/Workflow/Harness/Capability/Policy/Trace/
  Receipt definitions are explicit;
- product-facing names map to canonical contracts.

### Step 3: Build Canonical Workstream 1 Proof Sample

Affected areas:

- sample docs or internal sample directory;
- workflow manifest/test fixture;
- fs/git RuntimeToolContracts;
- authority policy fixture;
- eval fixture and scorecard;
- GUI workflow composer readiness probe.

Acceptance criteria:

- user can run local repo inspection/proposal flow;
- patch mutation is proposal-first;
- approval and receipt evidence are visible;
- failed readiness is clear;
- docs explain mock vs live posture.

### Step 4: Add Package Readiness Projection To Workflow Composer

Affected areas:

- `packages/agent-ide/src/runtime/workflow-capability-preflight*`;
- `packages/agent-ide/src/WorkflowComposer/*`;
- `WorkflowRailPanel` / readiness summaries;
- tests for old workflow compatibility.

Acceptance criteria:

- graph can show run readiness and package readiness separately;
- missing eval/deployment/profile data blocks package promotion, not local dry
  run;
- advanced runtime receipts remain inspectable.

### Step 5: Phase 5 Workstream 1 Implementation

Proceed with filesystem/Git proposal-first mutation only after or during the
sample proof, using the sample as the regression target.

Acceptance criteria:

- read/diff/proposal/apply tools exposed through registry;
- authority and preview gates enforced;
- receipts and rollback/restore artifacts emitted;
- CLI/TUI/GUI projections agree.

### Step 6: Resume Connector Expansion

Order:

1. browser/computer-use hardening and Playwright adapter;
2. local shell/sandbox hardening;
3. Blender connector;
4. FreeCAD/CAD connector;
5. Google Workspace/mail read-only;
6. draft-only email/calendar/docs.

What not to change yet:

- do not implement high-risk commerce;
- do not implement Foundry;
- do not expose broad standing grants;
- do not make cloud provider availability a local-lane blocker.

## 13. Open Questions

### Architectural Questions

- Should `AutonomousSystemManifest` be a new top-level envelope or a profile of
  `ManifestEnvelope`?
- Is Worker always required for a package, or can a workflow-only package be a
  first-class autonomous system candidate?
- What is the exact migration path from old workflow package manifests?
- How much Agentgres v0 state is needed before package readiness can be called
  canonical rather than projection-only?

### UX Questions

- Where should package readiness live: right rail, top activation banner,
  deploy/publish modal, or all three?
- Should default users see Worker terminology immediately, or should product UX
  say Agent while advanced docs map to Worker?
- How much advanced runtime receipt detail should be visible by default?
- What is the smallest default sample that feels real but not overwhelming?

### Runtime Questions

- Which runtime endpoint owns package readiness evaluation?
- Should eval fixtures run through workflow runtime or a separate benchmark
  command that consumes the same manifest?
- How should session/state/memory/artifact profiles be represented in the
  daemon API before full Agentgres?

### Marketplace Questions

- What minimum metadata makes a local package marketplace-eligible?
- When should Worker Card generation begin?
- Should marketplace exposure eligibility live on tool contracts, system
  manifests, or both?

### Foundry Questions

- Which Foundry lineage refs should exist now as empty/optional manifest slots?
- How should connector data-use authority be captured so future training is not
  blocked?
- What failure/eval data from Phase 5 should be retained for future worker
  improvement?

### Governance Questions

- What is the product boundary between policy UI, authority UI, and trace UI?
- Should every Phase 5 local write require explicit user approval, or can
  workspace trust plus proposal-first grant allow scoped mutation?
- What approval receipts are sufficient for reversible local writes versus
  external drafts versus sends?

## 14. Source Notes

### Official Google Sources

Reviewed on 2026-05-17.

- `https://docs.cloud.google.com/gemini-enterprise-agent-platform/build/runtime/create-an-agent`
  - Relevant concepts: framework-specific templates, ADK/A2A/LangChain/
    LangGraph/AG2/LlamaIndex/custom agents, deployable agent object, object
    serialization, lifecycle separation.
  - Autopilot relevance: define setup/run lifecycle and serializable package
    constraints without making frameworks runtime truth.

- `https://docs.cloud.google.com/gemini-enterprise-agent-platform/scale`
  - Relevant concepts: managed Agent Runtime, Sessions, Memory Bank, Example
    Store, Evaluation Service, tracing, secure sandbox execution, Code
    Execution, Computer Use.
  - Autopilot relevance: lifecycle categories are useful: runtime, context,
    quality, sandbox, govern.

- `https://docs.cloud.google.com/gemini-enterprise-agent-platform/scale/runtime/deploy-an-agent`
  - Relevant concepts: deploy from object, source files, Dockerfile, container
    image, connected Git repository.
  - Autopilot relevance: deployment profiles should be manifest slots even
    before all provider implementations exist.

- `https://docs.cloud.google.com/gemini-enterprise-agent-platform/scale/sessions`
  - Relevant concepts: Session, Event, State, Memory; create/resume/save/list/
    cleanup conversations.
  - Autopilot relevance: use simple lifecycle vocabulary over IOI's stronger
    event/receipt/Agentgres substrate.

- `https://docs.cloud.google.com/gemini-enterprise-agent-platform/scale/memory-bank`
  - Relevant concepts: generated long-term memories, memory extraction,
    consolidation, asynchronous generation, continuous event ingestion,
    customizable extraction, multimodal understanding.
  - Autopilot relevance: memory requires retention, policy, data-use, and
    receipt posture.

- `https://docs.cloud.google.com/gemini-enterprise-agent-platform/govern`
  - Relevant concepts: Agent Registry, safety, sharing, identity/access,
    security/compliance, audit trail, policies, Agent Gateway.
  - Autopilot relevance: Authority Center should expose registry/gateway-like
    clarity while keeping wallet.network as root authority.

- `https://docs.cloud.google.com/gemini-enterprise-agent-platform/govern/policies/overview`
  - Relevant concepts: IAM allow/deny, Semantic Governance, dry-run/enforce,
    agent identity, Agent Registry resource, CEL conditions, MCP tool metadata.
  - Autopilot relevance: read-only/destructive/idempotent/open-world flags are
    useful tool contract metadata.

- `https://docs.cloud.google.com/gemini-enterprise-agent-platform/govern/gateways/agent-gateway-overview`
  - Relevant concepts: gateway as network entry/exit for user-agent,
    agent-tool, agent-agent interactions; agent identity; registry;
    framework-agnostic protocol mediation; telemetry.
  - Autopilot relevance: useful governance topology; do not copy as authority
    root.

- `https://docs.cloud.google.com/gemini-enterprise-agent-platform/optimize/evaluation/agent-evaluation`
  - Relevant concepts: eval cases, inference, traces, metrics, failure
    analysis, optimization, user simulation, environment simulation,
    multi-turn autoraters.
  - Autopilot relevance: Phase 5 connector lanes should have fixture evals and
    scorecards from the start.

- `https://docs.cloud.google.com/gemini-enterprise-agent-platform/optimize/observability/traces`
  - Relevant concepts: traces as sequential timeline for non-deterministic
    agent reasoning/tool paths.
  - Autopilot relevance: trace is observability, not settlement; keep receipts
    separate.

### Official ADK Sources

Reviewed on 2026-05-17.

- `https://adk.dev/get-started/about/`
  - Relevant concepts: Agent, Tool, Callbacks, Session/State, Memory, Artifact,
    Code Execution, Planning, Models, Event, Runner.
  - Autopilot relevance: IOI needs a similarly simple public grammar.

- `https://adk.dev/runtime/`
  - Relevant concepts: `adk web`, `adk run`, `adk api_server`, deployment,
    observability, evaluation, safety/security.
  - Autopilot relevance: define an equivalent build/run/eval/package/deploy
    loop.

- `https://adk.dev/tools-custom/function-tools/`
  - Relevant concepts: function signature/docstring/type hints generate tool
    schema; long-running tools; agent-as-tool.
  - Autopilot relevance: add ergonomic wrappers over RuntimeToolContract.

- `https://adk.dev/tools-custom/confirmation/`
  - Relevant concepts: boolean confirmation for tools, manual TypeScript
    confirmation through tool context.
  - Autopilot relevance: IOI approvals are stronger but should be as obvious.

- `https://adk.dev/sessions/session/`
  - Relevant concepts: session id, app name, user id, events, state, update
    time.
  - Autopilot relevance: map to daemon thread/turn/session projections.

- `https://adk.dev/sessions/state/`
  - Relevant concepts: serializable key-value state, session/user/app/temp
    scopes.
  - Autopilot relevance: useful UX layer over Agentgres state and policy.

- `https://adk.dev/sessions/memory/`
  - Relevant concepts: MemoryService, session ingestion, event ingestion,
    direct memory writes, search, in-memory and managed memory options.
  - Autopilot relevance: memory profiles should declare persistence, retention,
    and authority.

- `https://adk.dev/callbacks/types-of-callbacks/`
  - Relevant concepts: before/after agent, model, tool callbacks; validation,
    logging, state changes.
  - Autopilot relevance: use governed hooks with side-effect contracts.

- `https://adk.dev/artifacts/`
  - Relevant concepts: versioned binary artifacts with filename, scope, MIME
    type, bytes.
  - Autopilot relevance: artifact UX should be first-class and receipt-bound.

- `https://adk.dev/events/`
  - Relevant concepts: immutable events, author, invocation id, event id,
    timestamp, actions, branch, content.
  - Autopilot relevance: IOI event model is stronger; keep SDK ergonomics.

- `https://adk.dev/visual-builder/`
  - Relevant concepts: web visual workflow design, left config panel, central
    add components, right assistant, save/test, generated YAML/Python project
    code.
  - Autopilot relevance: preserve manifest truth while improving edit/test UX.

- `https://adk.dev/tutorials/agent-team/`
  - Relevant concepts: multi-model agents, delegation, session state, safety
    callbacks.
  - Autopilot relevance: good examples for worker delegation, but callbacks
    need IOI authority.

### Local Example Sources

Reviewed on 2026-05-17.

- `examples/agents-cli-main/README.md`
  - CLI/skills package for building, evaluating, deploying, publishing, and
    observing agents. Key lesson: developer lifecycle is explicit and skills
    are used as coding-agent guidance.

- `examples/agents-cli-main/docs/src/guide/project-structure.md`
  - Generated project includes `app/agent.py`, evalsets, eval config,
    tests, pyproject, guidance file, Makefile, env, and deployment infra.

- `examples/agents-cli-main/docs/src/guide/development.md`
  - Lifecycle: understand, scaffold, build, eval, deploy, publish, observe.

- `examples/agents-cli-main/docs/src/guide/evaluation.md`
  - Eval-fix loop and metric selection; validates agent behavior rather than
    brittle pytest assertions on LLM text.

- `examples/agents-cli-main/docs/src/guide/deployment.md`
  - Agent Runtime, Cloud Run, GKE deployment targets and dry-run/status flows.

- `examples/agents-cli-main/docs/src/guide/cicd.md`
  - Staging/prod pipeline, manual production approval.

- `examples/agents-cli-main/skills/google-agents-cli-workflow/SKILL.md`
  - Mandatory requirements clarification, sample study, scaffold, build,
    evaluate, deploy, publish, observe workflow.

- `examples/agents-cli-main/skills/google-agents-cli-scaffold/SKILL.md`
  - Prototype-first scaffold, RAG/A2A/deployment/session flags, strict
    programmatic mode, preservation rules.

- `examples/adk-samples-main/adk-samples-main/README.md`
  - Multi-language sample repository. Demonstration-focused but rich pattern
    catalog.

- `examples/adk-samples-main/adk-samples-main/python/agents/README.md`
  - Sample taxonomy by use case, tag, interaction type, complexity, agent type,
    vertical. Standard agent directory with core code, sub_agents, tools,
    prompts, deployment, eval, tests, diagrams, env, pyproject.

- `examples/adk-samples-main/adk-samples-main/python/agents/customer-service/README.md`
  - Customer-service agent with mocked tools, session state, evals, unit tests,
    Agent Runtime deployment instructions.

- `examples/adk-samples-main/adk-samples-main/python/agents/customer-service/customer_service/agent.py`
  - Root ADK agent binding model, global instruction, instruction, tools, and
    callbacks.

- `examples/adk-samples-main/adk-samples-main/python/agents/customer-service/customer_service/shared_libraries/callbacks.py`
  - Callback guardrails for customer id, rate limit, approval-like discount
    logic, and deterministic post-tool behavior. IOI should convert this class
    of logic into governed hooks/policy/tool contracts.

- `examples/adk-samples-main/adk-samples-main/python/agents/customer-service/eval/test_eval.py`
  - AgentEvaluator over eval case files.

- `examples/adk-samples-main/adk-samples-main/python/agents/agent-skills-tutorial/README.md`
  - Skills with progressive disclosure and four skill patterns.

- `examples/adk-samples-main/adk-samples-main/python/agents/agent-skills-tutorial/app/agent.py`
  - `SkillToolset` wiring for inline, file-based, external, and meta skills.

- `examples/adk-samples-main/adk-samples-main/python/agents/workflows-HITL_concierge/agent.py`
  - WorkflowAgent with explicit edges and RequestInput human-in-the-loop nodes.

### Local IOI Sources

Reviewed on 2026-05-17.

- `docs/architecture/_meta/source-of-truth-map.md`
  - Canonical source ownership and conflict rules. Important current defaults:
    daemon/public APIs own execution semantics; Worker is protocol actor; Model
    is cognition backend; clients are projections/operators.

- `docs/architecture/foundations/common-objects-and-envelopes.md`
  - Shared envelope types, ID namespaces, capability/authority tier split,
    WorkerInstanceEnvelope, authority scope envelope.

- `docs/architecture/foundations/domain-kernels.md`
  - IOI kernel/L0 substrate, domain kernels, edge-in topology, Agentgres
    operational truth, runtime assignment.

- `docs/architecture/components/daemon-runtime/doctrine.md`
  - Daemon as universal execution endpoint; CLI/TUI/SDK/Autopilot as clients;
    runtime APIs; command families.

- `docs/architecture/components/daemon-runtime/events-receipts-delivery-bundles.md`
  - Runtime event kinds, receipt types, tool receipt shape, training/eval/
    benchmark/routing receipts.

- `docs/architecture/components/connectors-tools/doctrine.md`
  - Connectors expose external systems as typed, permissioned, receipted tools.
    No effectful tool without contract. Connector output maps through
    ConnectorMapping/DataRecipe before becoming domain truth.

- `docs/architecture/components/connectors-tools/contracts.md`
  - RuntimeToolContract, connector API, tool API, risk classes, approval rules.

- `docs/architecture/components/wallet-network/doctrine.md`
  - wallet.network owns identity, secrets, grants, approvals, data-use,
    revocation, payments, and decryption leases. It does not execute work.

- `docs/architecture/components/wallet-network/api-authority-scopes.md`
  - Authority scope request/grant APIs, secret/BYOK APIs, approval API,
    revocation/emergency stop.

- `internal-docs/architecture/products/autopilot/internal-product-spec.md`
  - Autopilot as private/local operator shell and autonomous action workbench;
    local-first, sovereign, verifiable; Foundry and marketplace implications.

- `internal-docs/architecture/products/autopilot/local-app-workflow-canvas.md`
  - Autopilot Desktop as local canonical workbench; workflow canvas; harness as
    workflow; Foundry as product lens over shared builder substrate.

- `internal-docs/plans/phase-5-early-connector-expansion-master-guide.md`
  - Phase 5 entry gate open; connector/tool registry, model capabilities,
    wallet-core-lite, Authority Center, workflow capability binding,
    Playwright/browser harness readiness, workstreams.

- `internal-docs/plans/isolated-computer-providers-master-guide.md`
  - Isolated computer provider taxonomy, task-scoped browser profiles,
    Playwright context adapter, local container provider, lease/observe/act/
    verify/cleanup contract.

- `internal-docs/plans/computer-use-external-eval-ingestion-master-guide.md`
  - External eval suite ingestion into IOI benchmark cases, workflow manifests,
    trajectories, scorecards, failure taxonomy.

- `internal-docs/implementation/runtime-module-map.md`
  - Source tree canonical homes for runtime kernel, daemon, bridge, SDK, CLI,
    agent-ide, Autopilot, validation surfaces.

- `internal-docs/implementation/runtime-package-boundaries.md`
  - Package/runtime/client ownership boundaries and primitive-vs-authority tier
    guardrail.

- `internal-docs/specs/runtime/authority-vs-projection.md`
  - Projection vs authority, evidence tiers, trace export rule, workflow
    projection rule.

- `internal-docs/specs/runtime/agent-runtime-live-bridge-tti-event-contract.md`
  - Live bridge contract, runtime source of truth, stable thread/turn/item
    records, fixture visibility, RuntimeApiBridge boundary.

- `packages/runtime-daemon/src/model-mounting/model-capability.mjs`
  - Implemented model capability projection with route id, primitive model
    capability, authority scope requirements, privacy tier, provider priority,
    fallback policy/evidence, cost estimate visibility, credential/vault
    readiness, receipt behavior, workflow/agent availability.

- `packages/runtime-daemon/src/coding-tools.mjs`
  - Coding tool contracts for workspace status, git diff, file inspect, patch
    apply, tests, diagnostics, artifacts, tool result retrieval, computer-use
    lease request; includes primitive capabilities, authority scopes, schemas,
    evidence, workflow node types, config fields.

- `packages/agent-ide/src/WorkflowComposer/controller.tsx`
  - Workflow Composer consumes node registry, composition helpers, capability
    preflight, readiness, grant requests, terminal coding loop, computer-use
    options, live telemetry, run history, runtime subflows.

- `packages/agent-ide/src/runtime/workflow-tool-connector-capability-binding.test.ts`
  - Evidence that workflow tool/connector bindings now use capability refs,
    authority scopes, readiness, and receipt behavior, with fail-closed tests.

