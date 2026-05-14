# Runtime Vocabulary

Status: canonical vocabulary reference.
Canonical owner: this file for runtime, audit, substrate, projection, and legacy naming vocabulary.
Supersedes: overlapping runtime vocabulary in plans/specs when names conflict.
Superseded by: none.
Last alignment pass: 2026-05-14.

The agent harness uses behavior-first names in runtime code and reserves
compliance acronyms for hidden audit material.

## Runtime Terms

- `IOIDaemon`: the deployable execution endpoint for Web4 work. It exposes the
  public runtime API, hosts daemon-local execution services, writes through
  Agentgres-compatible envelopes, and requests wallet.network authority.
- `IOIKernelL0` or `L0Substrate`: the reusable IOI kernel substrate for
  instantiating application domains, sovereign execution domains,
  non-intelligent chains/state machines, and intelligent blockchains. It is not
  one live global chain and it is not the CLI.
- `IOIL1`: the public registry, rights, settlement, dispute, sparse-commitment,
  and governance layer. It may approve canonical L0/kernel release roots, but
  it does not execute the L0 substrate or own ordinary repository management.
- `EdgeInTopology`: IOI's topology inversion in which work starts at the local
  or remote runtime edge, becomes operational truth in a domain kernel +
  Agentgres, and settles upward to IOI L1 only when public trust is required.
- `RuntimeNode`: a machine, container, TEE, DePIN node, local process, or
  customer environment running an IOI daemon profile. Runtime nodes execute
  workers and task capsules; they are not application domains by default.
- `ComputeSession`: a bounded runtime allocation selected by a router for one
  run, order, task, or service outcome. It may be backed by a VM, container,
  browser sandbox, GPU job, hosted node, DePIN node, TEE, customer VPC, or local
  daemon. For managed worker instances, the session may be warm, persistent, or
  zero-to-idle under a subscription or entitlement policy.
- `RuntimeAssignment`: the domain-kernel/router decision that binds a run or
  task capsule to a runtime node, daemon profile, authority posture, payment
  quote, and verification requirements.
- `Worker`: the canonical protocol actor for bounded executable labor. A
  worker has a manifest, policy envelope, capability surface, receipt
  obligations, runtime requirements, contribution terms, and settlement
  identity.
- `Agent`: product-facing or colloquial language for an autonomous assistant,
  delegated actor, or user-facing worker experience. New protocol prose should
  use `Worker` when referring to the accountable execution actor.
- `ManagedWorkerInstance`: a user-, org-, or project-bound initialization of a
  worker package. Product UX may call this an agent instance, but canonical
  state should bind it to a worker manifest, install/license right, runtime
  assignment, persistence profile, authority policy, memory/archive policy, and
  subscription or entitlement.
- `RuntimeSubscription`: an entitlement or billing object that keeps a managed
  worker instance available by per-invocation use, warm runtime allocation, or
  zero-to-idle restore policy. It does not make aiagent.xyz or ioi.ai the
  execution runtime.
- `Model`: a cognition backend mounted or invoked by a worker. Models are not
  the economic actor by themselves.
- `MixtureOfWorkers` or `MoW`: protocol-level labor routing across bounded
  workers. MoW selects accountable workers, not merely cognition providers.
- `MixtureOfExperts` or `MoE`: model-internal or provider-side expert routing.
  MoE may be used inside a worker, but it is not the protocol-visible labor
  routing layer.
- `SparseWorkerCategory`: a narrow benchmarked labor category with declared
  schemas, rubric, benchmark profile, runtime requirements, policy posture,
  receipt obligations, and routing eligibility criteria.
- `WorkerTraining`: the supply-creation lifecycle for turning workflows,
  examples, corrections, data, tools, policies, and evaluation gates into
  deployable, benchmarked workers.
- `TrainingProfile`: descriptive worker-training metadata for the cognition or
  configuration pattern being trained, such as dense transformer, MoE-backed,
  subquadratic, hybrid attention/state, retrieval-augmented, mutable-context,
  adapter-trained, distillation-trained, perpetually post-trained, or
  deterministic verifier/toolchain. A training profile is not a protocol actor.
- `DomainOntology`: the semantic model for a domain's entities,
  relationships, events, actions, states, roles, and invariants.
- `CanonicalObjectModel`: the typed object contract that grounds a domain
  ontology in IDs, schemas, constraints, lifecycle states, privacy classes,
  authority needs, and projection hints.
- `DataRecipe`: a repeatable, receipted pipeline that turns raw sources,
  traces, connector outputs, and documents into ontology-bound objects,
  training datasets, evaluation datasets, or projections.
- `ConnectorMapping`: the mapping from provider fields, files, events, and
  actions into canonical object models and authority scopes.
- `PolicyBoundDataView`: a governed data lens that defines who or what may
  read, transform, train on, evaluate with, export, publish, or route over a
  subset of domain data.
- `EvaluationDataset`: ontology-bound golden cases, holdouts, adversarial
  cases, regressions, rubric refs, benchmark refs, and provenance commitments.
- `TransformationReceipt`: a receipt proving what source material was
  transformed by which recipe, under which policy, into which object, dataset,
  or projection.
- `OntologyProjection`: an Agentgres projection generated from ontology
  relationships, canonical object models, data recipes, and policy-bound views.
- `OntologyToWorkerPlan`: a plan that turns ontology, recipes, workflow
  schemas, tools, policies, evals, and benchmarks into a WorkerManifest or
  Worker Training spec.
- `AutopilotFoundry`: the Autopilot product surface for capturing, training,
  evaluating, and deploying workers through the Worker Training lifecycle.
- `TaskCapsule`: a minimized, policy-bound execution packet given to a runtime
  node. It carries visible context, hidden context classes, allowed/forbidden
  actions, output contract, TTL, and authority bindings.
- `AutopilotDesktop`: the local product shell/workbench. It may launch, manage,
  or project a local IOI daemon/runtime profile, but it does not define a
  separate canonical runtime path.
- `IOICliTui`: the terminal/TUI operator client over daemon/public runtime APIs.
  It can render plans, controls, traces, approvals, and receipts, but it does
  not own execution semantics.
- `IOISdk`: a developer client facade over daemon/substrate contracts. It may
  provide typed helpers and explicit test mocks; it is not the execution
  substrate initialized on compute nodes.
- `AgentIde`: the GUI/workbench/workflow-composer projection over shared
  contracts. It authors and inspects workflows, but canonical run/session/task
  truth remains in daemon/Agentgres state.
- `SealedStateArchive`: an encrypted content-addressed state artifact for
  inactive, idle, terminal, portable, migrated, or restorable runtime/domain
  state. It is a first-class Agentgres format, but not canonical live state by
  itself. Agentgres keeps canonical operation refs, state roots, object heads,
  lifecycle metadata, archive refs, authority metadata, and receipts;
  Filecoin/CAS or another blob store keeps bytes.
- `AgentgresPostgresBridge`: a Postgres-compatible read/query surface over
  named Agentgres projections. Canonical writes still go through Agentgres
  operations unless a bridge write explicitly compiles into an operation with
  schema, policy, authority, and constraint checks.
- `AgentgresConsistencyLevel`: one of `cached_projection`,
  `projection_consistent`, `snapshot_consistent`, `state_root_consistent`,
  `linearized_domain`, or `serializable_domain`.
- `AgentgresInvariant`: a Web4 validity rule for consequential action, such as
  authority, receipt, settlement, policy, temporal, projection, state-root,
  artifact-integrity, or policy-monotonicity requirements.
- `AgentgresConstraint`: an object validity rule such as required field, schema
  type, unique key, foreign ref, check, exclusion rule, cardinality, or temporal
  range.
- `DomainSequence`: the ordered accepted-operation sequence for an Agentgres
  domain. Recovery is sequence-first: restore to sequence N, verify roots
  through N, then rebuild projections from verified checkpoints.
- `TrainingReceipt`: a receipt binding a training trace, dataset curation step,
  training/configuration run, or worker-training output to canonical inputs,
  policy, worker identity, artifact refs, and signatures.
- `ContextMutationReceipt`: a receipt binding a versioned context update,
  contradiction, supersession, or deprecation to evidence, policy, authority,
  and worker/project refs.
- `PromotionDecisionReceipt`: a receipt binding a context, adapter,
  route-policy, evaluation, or package promotion decision to baseline/candidate
  versions, regression checks, gates, rollback refs, and policy.
- `BenchmarkReceipt`: a receipt binding a benchmark execution to its worker
  manifest, benchmark profile, evaluation environment, policy hash, score
  commitment, and evaluator identity.
- `EvaluationReceipt`: a receipt binding an evaluation verdict to its rubric,
  input set, worker output, verifier identity, score/decision commitment, and
  policy hash.
- `RoutingDecisionReceipt`: a receipt binding a MoW routing decision to the
  candidate set, routing policy, selected worker, selection reason,
  contribution policy, and receipt obligations.
- `ioiAiControlPlane`: the lightweight account, device, publishing, restore
  routing, sync metadata, billing/entitlement, and remote-runtime coordination
  domain for `ioi.ai`.
- `intent`: the semantic operation the user is asking the harness to perform.
- `lane`: a durable runtime capability family such as weather, sports, places,
  recipes, messaging, user input, visualizer, artifact, or inline answer.
- `source`: the origin of information used to answer or act.
- `adapter`: the concrete runtime implementation that executes an action.
- `connector`: a user- or workspace-connected service that may supply private
  context or perform authenticated work.
- `policy`: versioned decision logic for permission, risk, priority, or
  feasibility.
- `constraint`: a typed requirement that must hold before a decision or action
  is valid.
- `evidence`: typed proof that a runtime stage happened or a requirement was
  satisfied.
- `observation`: measured runtime state collected during execution.
- `decision_record`: hidden structured evidence describing a selected lane,
  source, adapter, or outcome.
- `ledger`: authoritative append-only execution attempt state.
- `completion_gate`: the shared API that decides whether a terminal path may
  complete.
- `verification`: typed checks or observations proving the requested outcome.
- `RuntimeSubstrate`: the shared runtime contract. It is not a daemon client,
  UI cache, canonical store, or proof harness.
- `RuntimeDaemonClient`: a client that talks to daemon/public runtime APIs.
- `AgentgresRuntimeStateStore`: daemon-owned canonical runtime state for local
  v0 proof runs.
- `RuntimeProjection`: UI/cache/read-model state derived from canonical events,
  receipts, traces, or Agentgres state.
- `adaptive_work_graph`: the durable public name for parallel/delegated work
  graph execution. `adaptive work graph` is legacy or historical vocabulary only.

## Audit Terms

- `receipt`: an immutable audit event emitted for hidden traces or bundles.
- `contract`: a spec-level requirement set, not product UI copy.
- `CIRC`: the intent-resolution compliance specification label.
- `CEC`: the execution-completion compliance specification label.

`CIRC` and `CEC` may appear in specs, trace schema values, evidence bundle
paths, and architecture guard tests. They should not appear in ordinary runtime
type names, helper names, Chat/Spotlight UI copy, or product-facing summaries.
