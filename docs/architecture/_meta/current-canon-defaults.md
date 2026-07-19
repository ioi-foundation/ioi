# Current Canon Defaults

Status: canonical cross-owner digest.
Canonical owner: this file for the current high-level defaults that span
multiple architecture owners. Subject-specific doctrine remains owned by the
files named in [source-of-truth-map.md](./source-of-truth-map.md).
Supersedes: the inline "Current canonical defaults" digest formerly embedded in
[source-of-truth-map.md](./source-of-truth-map.md).
Superseded by: none.
Last alignment pass: 2026-07-19.
Doctrine status: canonical
Implementation status: mixed (cross-owner digest)
Last implementation audit: 2026-07-19

## Purpose

This digest keeps the current architecture defaults easy to scan without turning
the source-of-truth map into a long doctrine file. Use it when you need the
latest cross-owner mental model before editing a specific owner doc.

This file does not replace the owner docs. When a detail needs
implementation-grade precision, edit the canonical owner named in
[source-of-truth-map.md](./source-of-truth-map.md) first and keep this digest
synchronized.

## Reading Order

1. Start with [start-here.md](./start-here.md) for the five-minute stack model.
2. Use this digest for the current cross-owner defaults.
3. Use [source-of-truth-map.md](./source-of-truth-map.md) to find the edit-first owner.
4. Use [implementation-matrix.md](./implementation-matrix.md) to map a concept to durable forms, code anchors, and conformance hooks.

## Current Defaults

### Capability, authority, and runtime ownership

- `prim:*` means primitive execution capability;
- `scope:*` means wallet/provider authority scope;
- daemon/public runtime APIs own execution semantics;
- Hypervisor Daemon runtime nodes are the hypervisor/control plane for
  autonomous execution;
- Platform Operability evaluates exact operation readiness across owner-produced
  plane observations. Temporal requirements bind an immutable
  `TemporalVerificationProfile` and recomputable
  `TemporalValidityEvaluation`; absolute interval, challenge freshness,
  same-boot elapsed duration, owner epochs, status-as-of, continuity floors,
  and final resource fencing remain distinct. The evaluation does not create
  authority or permission. Rollback resistance requires an owner-scoped floor
  outside the declared rollback domain or fresh independent re-anchoring;
  software-only deployments remain valid with correspondingly narrower claims;
- Workflow Compositor owns high-level directed workflow/service shape:
  graph, dependencies, step contracts, review points, delivery contracts,
  and immutable versioned WorkflowTemplates;
- HarnessProfiles are daemon-executed or daemon-mediated step-resolution
  profiles/adapters; they must produce common boundary objects and cannot
  own execution truth;
- the Default Harness Profile is IOI's reference scaffold/fallback
  HarnessProfile for loop-native scoped step resolution; it is not a peer
  runtime, not the only admissible harness, not a meta-harness, and not the
  owner of high-level workflow composition;
### Goal Kernel and collective pursuit

- every newly admitted GoalRun binds exactly one immutable GoalRunProfile
  revision, including the versioned generic-adaptive profile for ad hoc work;
  daemon admission freezes the permitted override set, resolved component
  snapshot/hash, and resolution receipt before activation;
- ioi.ai and Hypervisor use the Goal Kernel shape for one bounded goal or
  claimed subgoal: the Goal Kernel interprets that admitted pursuit profile,
  while the GoalRun owns durable pursuit state and references the live
  GoalGroundingLoop, RoleTopology, independent Context Cells, scoped Context
  Leases, typed Context Handoffs, selected HarnessProfiles, generic
  `WorkResult` / `OutcomeDelta`, VerifierPath evidence, and continuation state;
- a GoalRun owns durable bounded outcome pursuit across zero or more Sessions.
  A Session is one bounded interactive, headless, or supervisory execution and
  control context; closing, replacing, or restoring a Session cannot silently
  close, fork, accept, or rewrite its GoalRun. A direct Session may exist without
  a GoalRun or System;
- the GoalGroundingLoop receives intent, classifies risk, gathers grounding,
  inspects current state, derives constraints and acceptance, selects or adapts
  topology, leases context/resources/authority, executes or delegates, monitors,
  verifies, repairs or escalates, reconciles receipts/memory/skills, and
  continues or closes. It optimizes useful progress per token, not model calls;
- a GoalRunProfile composes existing OrchestrationPolicy, optional
  WorkflowTemplate, topology, SkillManifest, HarnessProfile, tool/capability,
  output, verifier, budget, stop, recovery, and learning-boundary requirements;
  it is not executable, authority, a workflow graph, live run state, campaign
  state, or domain state;
- WorkflowTemplate is immutable reusable directed-work shape. AutomationSpec
  adds standing activation, triggers, schedules, and service lifecycle;
  AutomationInstallationBinding is the successor-versioned scope enablement
  and narrowing overlay; AutomationRun freezes the exact template, spec, and binding for
  one activation; GoalRunProfile adds adaptive convergence. Selected
  HarnessProfiles resolve scoped steps and own none of those higher layers;
- SkillManifest is the immutable procedural/context definition; SkillEntry is
  an immutable successor-versioned owner-scoped admission binding to one exact
  manifest revision/hash; ActiveSkillSetSnapshot is the exact daemon-admitted
  run selection. Registry lifecycle is a mutable projection. Runtime tools,
  hooks, and marketplace listing metadata remain separately owned;
- Recipe is only product/package language over an owner-qualified DataRecipe,
  HypervisorDevelopmentEnvironmentRecipe, HypervisorSessionLaunchRecipe,
  WorkflowTemplate, AutomationSpec, or GoalRunProfile. No generic
  RecipeEnvelope executes or owns live state;
- persistent collective pursuit instantiates the reusable `OutcomeRoom` package
  through genesis as one bounded-DAS room system with a
  `CollaborativeWorkGraph` above one or more GoalRuns. The room owns the shared
  objective, participant leases, work frontier, claim leases, resource and
  capability offers, attempts, findings, verifier challenges, contribution
  lineage, admission policy, discussion projections, and replay. It is not a
  peer runtime or a globally mutable Agentgres graph. Every consequential room
  child uses `RoomAdmittedObjectBase` with exact participant lease or room-
  system issuer, predecessor/revision, decision, sequence, commitments, proof,
  state root, and receipt root;
- the minimum Internet-of-Intelligence network proof is an independently
  operated external Worker discovering eligible work through a versioned,
  policy-bound `OutcomeRoomDiscovery`, negotiating semantic/action profiles,
  submitting a typed `RoomParticipationRequest`, receiving bounded leases,
  returning a verifiable contribution, preserving credit/dispute lineage, and
  exiting with a portable `ParticipantStateBundle`. It must not require one
  runtime, operational database, administrator, or continued IOI-host trust;
- an already-running user-owned agent may reach that path through a
  `LocalAgentPairingSessionEnvelope`: a one-time, short-lived, key/origin-bound
  bootstrap whose target is `room_guest`, `private_worker`, or
  `organization_worker`. Pairing may expose discovery and accept a
  `WorkerComposition` draft or `RoomParticipationRequest`; it never grants room
  membership, context, authority, tools, budget, direct room-database access,
  reputation, payout, or marketplace exposure. Admission and leases remain
  separate, and prompt-only output remains an untrusted proposal with no more
  than `attested` assurance from pairing alone;
- `WorkResult` / `OutcomeDelta` is the general cross-harness result seam.
  `ImplementationResultPayload` remains the software profile with file, patch,
  diff, and test fields; research, ontology, incident, service, review,
  evaluation, and physical-mission results do not inherit software fields. An
  executable result freezes the exact producer-component snapshot/hash/receipt
  and resolver revision/hash; HarnessInvocation binds the underlying work
  subject but never becomes a second work subject;
- cross-harness coordination uses typed ContextHandoffs, ContextLeases,
  TaskBriefPayloads, HarnessInvocations, HarnessAdapterEvents, generic results,
  VerifierPaths, and receipts. Adapter-private prompts or commands and raw chat
  are not the durable contract;
- ordinary direct work collapses to one GoalRun, worker, model route,
  AutomationRun, service, or Session. OutcomeRoom machinery appears only when a
  durable shared frontier, multiple attempts, dynamic participants, independent
  verification, or cross-domain contribution justifies its cost;
- ordinary verification may use deterministic checks, receipts, diffs, tests,
  browser/runtime evidence, and acceptance reconciliation. Independent verifier
  harnesses are policy-triggered for publish, mount, external connectors, spend,
  secrets, unsafe plaintext, marketplace admission, production mutation,
  physical action, compliance, challenge, or cross-party acceptance;

### Bounded improvement campaigns

- every Campaign binds one immutable `ImprovementGovernanceProfile` revision.
  A System constitution protects the selected System-scoped profile; a user,
  project, or organization Campaign uses an explicit owner-governance binding
  and does not thereby become a bounded DAS or inherit System authority;
- direct `UpgradeProposal` remains the simplest improvement path. An optional
  `ImprovementCampaign` materializes only for adaptive or repeated search,
  sealed evaluation, multiple evaluation epochs, durable candidate/archive
  lineage, or a recursive-improvement claim;
- `GoalRunProfile` is the reusable pursuit method, GoalRun owns one admitted
  pursue/verify/course-correct loop, `ImprovementAgenda` owns an immutable
  governed portfolio of questions, and `ImprovementCampaign` owns the
  multi-epoch candidate, evaluation, cutoff, claim, and promotion-handoff
  lifecycle. None is another runtime, truth store, authority plane, or product
  application;
- Search proposes and executes candidates; Evaluations/Judgment freezes epochs,
  meters sealed exposure, evaluates, challenges, and tracks evaluator validity;
  Governance/Authority admits campaigns and decides target-owner activation or
  recovery. These are logical duties, not mandatory services. Lower-assurance
  role collapse must be disclosed and never collapses evidence into authority;
- every campaign freezes finite target/order, active-depth, resource,
  statistical-risk, exposure, learning-rights, authority, deadline, and
  recovery ceilings. Child campaigns and higher claimed order inherit those
  bounds; siblings reserve disjoint allocations;
- `EvaluationEpoch` separates visible development, sealed survival, transfer,
  and production signals. Search strategy, archive strategy, statistical test,
  and causal design remain versioned policy choices. Candidate/evaluator/
  controller successors cannot mutually validate and activate at one cutoff;
- `ImprovementOrderCutoffReceipt` records eligible evidence at one adjacent
  target-order edge without becoming a sync state machine or predicting later
  promotion. `ImprovementEvidenceClaim` is a qualified evidence artifact, not
  authority; bounded optimization, self-targeted improvement, net-positive
  recursive improvement, ignition evidence, and inflection evidence require
  progressively stronger declared proof;
- `LearningEvidenceEligibility` governs whether Findings, corrections,
  production observations, or other evidence may enter later improvement.
  `LearningEgressReceipt` is additionally required only for an attempted or
  completed institutional-boundary crossing. Sealed material and
  tenant-ineligible exhaust remain denied;
- Hypervisor Improvement is the campaign cockpit; Evaluations owns judgment
  contracts; Foundry builds candidate and evaluator assets and executes admitted
  experiments; Work shows GoalRuns; Provenance joins lineage; Governance owns
  promotion, rollback, recall, containment, compensation, and protected paths.
  No new application or rail item is created;

### Enterprise learning boundary and persistent intelligence

- persistent workspace intelligence such as skills, Agent Wiki /
  `ioi-memory`, wiki facts, learned tool affordances, and durable
  behavior-affecting context is workspace/project/domain state that should
  survive model/harness swaps when workspace identity, compatibility,
  provenance, policy, and authority allow;
- the enterprise-facing composition is: models are replaceable cognition;
  ontology, admitted memory, corrections, evals, policies, workflows, datasets,
  lineage, and rights-eligible derived capability are the institution's durable
  learning state. `InstitutionalLearningBoundaryProfile` is the versioned,
  hash-bound compiler contract for that promise. **Enterprise Learning
  Boundary** is its product projection, not another application, authority
  plane, truth store, runtime, scaling plane, or `Standard`/`Private` tier;
- boundary inheritance narrows from organization defaults through project build
  policy into an admitted system revision and then a session, GoalRun, model
  invocation, transformation, or Foundry-job snapshot. A changed organization
  default proposes a system upgrade; it does not silently rewrite a sovereign
  live system. A narrower child scope cannot widen its parent without explicit
  authority and a new admitted decision;
- effective learning permission is the most restrictive intersection of source
  rights, consent, policy-bound views, institutional boundary, custody posture,
  model-route rights, training eligibility, retention/export policy, and
  jurisdictional obligations. Missing or ambiguous rights fail closed.
  Enterprise operation does not manufacture rights over employee, contractor,
  customer, partner, public, licensed, provider-output, or collaborative-room
  material;
- provider secondary use and cross-customer aggregation are denied by default.
  Standard may use disclosed policy-qualified provider-trust routes; Private
  requires a custody-proven no-provider-trust route for protected plaintext.
  A contract or receipt proves the route and terms IOI admitted, not hidden
  provider behavior;
- `TrainingEvidenceEligibility` remains the per-subject admission decision.
  Agentgres records admitted profiles, decisions, derivative lineage, and
  revocation impact without granting data-use rights or becoming payload
  storage. Foundry transforms only eligible evidence into reusable capability;
  every derived dataset, adapter, checkpoint, worker, package, or route policy
  carries transitive source-rights, boundary, route-rights, eligibility, and
  impact refs;
- `LearningEgressReceipt` records an admitted crossing or an attempt blocked
  before egress without carrying protected plaintext. `InstitutionalIntelligenceExportBundle`
  provides policy-filtered audit, migration, or selected-capability portability;
  import re-runs admission and possession never manufactures rights. A
  model-independence test hard-disables the incumbent provider and evaluates a
  replacement using only institution-controlled, rights-eligible state against
  declared thresholds; it proves bounded continuity, not universal model
  equivalence;
- the Hypervisor Daemon is the deterministic execution substrate for
  portable, verifiable autonomous systems;

### Bounded DAS, deployment, interop, and enrollment

- strongest formulation: **IOI is the open operating stack that turns
  intelligence into bounded autonomous institutions. L0 makes one institution
  safely distributable across governed compute, state, verification, human, and
  embodied nodes; AIIP makes selective, positive-surplus interoperation between
  separately sovereign institutions contractible; IOI L1 supplies optional
  shared trust and economic finality**;
- lead product/category language with bounded distributed autonomous systems;
  use intelligent blockchain as the technical classification for their ordered
  state-machine substrate. A single-authority/PoA-1 or no-public-consensus
  system remains an intelligent blockchain when constitution, authority,
  operation log, receipts, replay, lifecycle, and proposal-mediated improvement
  are real; consensus changes the trust model, not the classification;
- every durable system binds a constitution, manifest, deployment profile,
  observed node memberships, ordering/admission/finality profile,
  oracle/evidence profile, lifecycle continuity profile, and optional IOI
  Network enrollment. Ordinary improvement cannot amend protected purpose,
  ceilings, amendment gates, oracle, finality, shutdown, or dissolution;
- external-world evidence can support useful system decisions without being
  mislabeled as certainty. A versioned `OracleEvidenceProfile` composes
  attributed observations, boundary receipts, correlation-aware independent
  sources, verifier paths, freshness, uncertainty, contradiction, challenge,
  and adjudication policy into a defeasible determination whose fact class,
  consequence scope, validity interval, dependencies, and supersession path
  are explicit. `OracleEvidenceAdmissionReceipt` proves the evaluator decision;
  `OntologyAssertionAdmissionReceipt` separately proves matching
  Agentgres/domain operational admission. Neither proves the external fact.
  Correlated sources do not stack as independent evidence, and acceptance,
  adjudication, or settlement changes disposition rather than automatically
  increasing factual accuracy. Oracle and assertion admissions form
  Agentgres exact-head chains; a consequential effect binds and revalidates
  both the current oracle receipt/head and the current domain
  assertion-admission receipt/resulting assertion head. The oracle decision
  must remain active and unexpired, the domain decision must remain `admitted`,
  and their oracle receipt, assertion commitment, fact class, active profile,
  source/verifier posture, applicability, and consequence scopes must match
  immediately before invocation. A rejected or superseded domain-admission
  head blocks the effect even if the oracle decision remains active;
- one stable `system_id` may span several Hypervisor Nodes. Node addition is a
  governed membership transition and never silently widens authority, changes
  quorum/finality, or proves independence. Desired topology and observed
  membership/readiness remain distinct;
- same-system distributed work is a primary L0 capability, not merely a
  replication posture. `GoalRun`, `RoleTopology`, `RuntimeAssignment`, member-
  node roles and leases, Agentgres ordering, and domain or fleet policy bind
  useful work across admitted execution, state, verification, gateway, and
  embodied nodes under one constitution and truth root;
- the first distributed proof is one logical DAS across two failure domains and
  contains both continuity and useful-work proofs: join, role assignment,
  checkpoint/log catch-up, root verification, writer epoch and fencing,
  controlled failover, replay, drain/removal, concurrent work placement,
  reassignment, partition behavior, duplicate-effect prevention, distributed
  verification, and unchanged authority. Only then does the roadmap prove two
  sovereign DASs over AIIP;
- the reusable `OutcomeRoom` package is the flagship/reference DAS profile
  because selected deployments can exercise bounded external-agent ingress,
  workgraphs, verification, contribution, and course correction. Its durable
  room-system instances are
  not the definition of L0, which must also support enterprise, marketplace,
  treasury/asset, research, public-interest, and embodied ontologies;
- AIIP assumes neither consensus nor IOI L1. It composes with versioned A2A
  remote-task, MCP tool/context, OASF/directory, HTTP/RPC, and settlement
  bindings while preserving IOI authority, ontology/action, evidence,
  acceptance, dispute, recovery, and lifecycle semantics;
- a sovereign system remains complete without AIIP use, marketplace
  participation, external contribution, or IOI Network enrollment. Cooperation
  is conditional on every required party accepting one exact
  `CollaborationTermsEnvelope` root and attesting positive expected cooperation
  surplus: expected utility under the accepted terms minus its best permitted
  outside option and incremental cooperation costs;
- discovery, compatibility, a shared goal, invitation, message, task offer, or
  terms proposal creates no obligation, authority, participant lease,
  executable award, contribution eligibility, reputation, or payout. Terms
  acceptance, room participation, work claim, contribution, verification,
  acceptance/adjudication, and settlement are distinct stages (`INV-30`);
- contribution attribution is not economic or non-economic allocation. Terms
  and contribution policy in force when work was awarded govern eligibility
  and reward basis; later amendments are non-retroactive (`INV-31`);
- IOI Network enrollment is explicit: `ioi_compatible` has no mandatory L1,
  fee, token, or assurance; `ioi_connected` pays only for selected registry,
  rights, reputation, escrow, dispute, or settlement services; `ioi_secured`
  additionally adopts a Standard DAS profile and named bonded/shared-security
  services. Enrollment never taxes local work;

### Native embodied systems target

- Embodied Runtime is a native IOI execution target for drones, humanoids,
  manipulators, mobile robots, vehicles, facilities, sensor/actuator groups,
  fleets, and swarms. ROS, flight stacks, vendor controllers, DDS, Zenoh,
  fieldbuses, and physics engines are replaceable adapters or backends beneath
  IOI contracts; the product center is not a partner-runtime bridge;
- the existing two-speed rule remains the system invariant: Goal Kernel, fleet
  policy, governance, and portable authority operate at mission/course-
  correction timescales, while high-frequency physical control and safety stay
  local. The local fast side is explicitly mixed-criticality: an autonomy
  stratum proposes, a deterministic-motion stratum controls, and an independent
  runtime-assurance/safety stratum monitors, arbitrates, switches to bounded
  recovery, and holds the final veto. Failure of AI, GPU, network, remote
  operator, wallet, or chain cannot disable that final local boundary;
- `EmbodiedRuntimeGraphManifest` is the immutable native graph definition.
  `NativeEmbodiedRuntimeProfile` supplies composable `micro`, `edge`, and `site`
  deployment footprints rather than three products or assurance grades:
  `micro` targets bounded MCU/RTOS control and safety, `edge` targets on-unit
  perception/planning/motion/local coordination, and `site` targets multi-unit
  world state, fleet coordination, evidence, and operations;
- graph ports bind `PhysicalStreamContract`, including schema/frame, endpoint
  identity, authentication, integrity/anti-replay, confidentiality, clock and
  uncertainty, rate/deadline/jitter, freshness, reliability/ordering/history,
  liveliness, priority/backpressure, criticality, allowed transports, and
  declared failure action. Backend mappings must fail admission when endpoints
  cannot jointly satisfy the semantic contract;
- `EmbodimentAdapter` maps an external device/runtime/protocol into native
  identity, frame, stream, lifecycle, health, action, and receipt semantics. It
  grants no authority or assurance equivalence. `EmbodiedActionPolicyContract`
  maps permitted ontology-level actions into bounded target schemas;
  `EmbodiedActionChunk` is a finite, fresh, uncertainty-bearing proposal, never
  an actuator command or authority grant;
- `LocalControlSupervisor` is the native deterministic graph executor and
  runtime-assurance root: it owns exclusive active-writer fencing, local
  scheduling, stream/time-health enforcement, command arbitration, safety
  monitor/switch/recovery, watchdogs, and final veto inside the already-admitted
  authority and safety envelope. `LocalControlBridge` remains a compatibility
  projection for an existing controller and may not imply the native guarantees
  or certification posture;
- `EmbodiedGraphActivationTransaction` prepares and validates the exact graph,
  components, streams, clocks, resources, scheduling, supervisor/safety, and
  assurance prerequisites before local commit. Activation does not arm or mint
  authority; restart returns inactive and unarmed. Atomic activation is
  claimable only inside one admitted supervisor/hardware boundary, while
  distributed launch uses fenced coordination epochs and explicit readiness;
- same-system fleet/swarm work remains native L0. Mission allocations and
  `SpacetimeReservationLease` coordinate units, volumes, paths, workcells,
  capacity, time, uncertainty, priority, expiry, and fencing, but never replace
  local collision avoidance or physical safety. Coordinator failover may use
  replicated state and epochs; motion control retains one active writer, and
  takeover requires safe handoff and a new fence. AIIP begins only when a
  separately governed system accepts cross-system terms;
- physical effects are not presumed exactly once. Partition, failover, rejoin,
  reassignment, and retry preserve effect IDs, causal/world-state watermarks,
  bounded disconnected-operation envelopes, and observation-based ambiguity
  reconciliation before further physical work;
- Foundry owns the backend-neutral development loop—scenario and graph
  candidates, simulation, software-in-the-loop, hardware-in-the-loop, shadow,
  limited-live evidence, scorecards, and promotion-bundle proposals—without
  owning live runtime, actuator authority, evaluator truth, or promotion. A
  backend binding is replaceable and never defines the canonical graph;
- `EmbodiedDeploymentAssuranceCase` binds the exact admitted graph, binaries,
  hardware, operational design domain, hazards, timing/fault assumptions,
  monitors/recovery controls, applicable standards, tests, fault injection,
  residual risk, and existing `AssuranceEvidenceBundle`/receipt refs. It is not
  generic certification. The required proof matrix spans graph compilation and
  transactional activation; stream/time/QoS failure; deterministic scheduling;
  supervisor veto/recovery/e-stop; one-writer fencing and safe takeover;
  fleet partition/rejoin/effect reconciliation; adapter equivalence; and
  assurance lineage across simulation, SIL, HIL, shadow, limited-live, and
  deployment-specific assessment;
- this native object family and its APIs, executor, compiler, adapters,
  conformance suite, and Embodied Systems surface remain **planned**. Existing
  physical-safety doctrine, runtime-node substrate, ROS/controller bridges,
  telemetry concepts, and Foundry simulation objects are adjacent ingredients,
  not evidence that the native embodied runtime has shipped;

### Hypervisor substrate and product structure

- Hypervisor includes Type 1, Type 2, and Type 3 substrate modes as deployment
  and control postures of one product. Type 1 is HypervisorOS / appliance /
  cluster control where the Hypervisor Daemon is node root. Type 2 is Hypervisor
  Desktop / Workstation hosted on a normal OS for local VMs, sandboxes, models,
  tools, agents, connectors, and environments. Type 3 is autonomy virtualization
  across sessions, WorkRuns, workers, model routes, tools, authority, receipts,
  replay, outcomes, and promotion. Type 3 is the differentiator; Type 1 and Type
  2 are the trustable substrate beneath it. HypervisorOS improves control,
  integrity, containment, measurement, reproducibility, and policy enforcement,
  but it does not replace cTEE no-plaintext-custody;
- Hypervisor must expose real substrate-control grammar, not only agent
  orchestration. Substrate, inventory, create/import, console, operations,
  governance, and ledger expectations resolve through Systems context, Work,
  Operations, Environments, Developer Workspace, Provenance, Governance,
  Developer Console, Hypervisor Desktop / Workstation, and HypervisorOS/provider
  detail views. Systems explains logical identity and desired-versus-observed
  topology; Operations performs admitted infrastructure and member operations;
- Hypervisor manages sessions, environments, providers, and cross-session
  infrastructure posture directly through the Applications catalog, the
  singular Open Application slot, session detail, project settings, provider
  settings, org/admin views, and operator console panels; provider posture
  is not a separate product or truth layer;
- BYO provider integration is a provider-neutral object plane with a priority
  adapter ladder, not a vendor taxonomy. SSH/bare-metal is the conformance
  adapter; simple GPU VMs, GPU runtimes, GPU marketplaces, enterprise
  hyperscalers, customer clusters, DePIN compute, and decentralized storage
  custody follow as adapters under the same `ProviderAccount`,
  `RuntimeNode`, `PlacementDecision`, `SnapshotRef`, `RestoreRef`,
  `SpendReceipt`, and `ProviderOperationReceipt` contract. BYO provider spend
  is customer-borne and transparent; direct local/self-managed BYO carries no
  percentage-of-provider-spend fee, while BYO or pinned cloud venues run through
  Hypervisor may carry a visible adapter/orchestration fee when Hypervisor
  brokers credentials, provisions, manages leases, snapshots, restores, tracks
  cost, emits receipts, or tears down resources. Hypervisor monetizes
  orchestration, governance, custody, receipts, restore, support, private
  posture, and managed convenience rather than hiding provider markup;
- runtime placement presents four user choices: run local, use my
  infrastructure, pick a cloud, or let Hypervisor choose. Underneath those
  choices are three placement sources: `connected`, `managed`, and
  `optimized`. `Connected` means the user owns the provider bill, with no
  percentage fee on direct self-managed spend and visible orchestration fees
  only when Hypervisor performs provider lifecycle work. `Managed` means IOI or
  a partner is provider-of-record and Work Credits or margin are legitimate.
  `Optimized` means Hypervisor creates visible routing/procurement/failover or
  billing-aggregation value and may charge only with challengeable placement or
  routing evidence;
- Hypervisor Core is the shared runtime/control substrate whose execution
  owner is the Hypervisor Daemon; it is not a peer runtime beside the daemon,
  not a replacement for wallet.network, and not a replacement for Agentgres;
- Hypervisor App, Hypervisor Web, and Hypervisor CLI/headless are
  first-class clients over Hypervisor Core; TUI is an optional presentation
  of the CLI/headless client, not a separate first-class client lane;
- Hypervisor's five core workspaces are Home, Systems, Projects, Applications,
  and Work. Automations is an owner application with a shell placement, not a
  sixth core-workspace registration. The New menu offers System, Session, Goal,
  Project, and Automation while preserving New Session as a one-click and
  keyboard-first action. `Open Application` remains one singular active surface
  slot;
- Systems is the stable inventory, context router, and coherent read model for
  one admitted `system_id` across package releases, nodes, models, upgrades,
  recovery, migration, succession, and dissolution. It projects Overview,
  Design, Operate, Govern, Evidence, Improve, and Interfaces through the owning
  applications and contracts; it does not mint identity, own operational truth,
  or replace daemon/Agentgres admission. A direct Session, Project,
  AutomationSpec, or stand-alone GoalRun never requires premature System
  genesis;
- Work is the unified, policy-filtered workspace for Active, Goals, Sessions,
  Rooms, Queues, Reviews, Incidents, and History. Each row declares a typed
  `subject_kind` and canonical `subject_ref` and deep-links to its type-specific
  detail. Work aggregates GoalRun, AutomationRun, OutcomeRoom, WorkQueue,
  WorkItem, WorkRun, and Session subjects plus RuntimeAssignment placement,
  authority, Agentgres, and receipt facets; it owns no universal lifecycle,
  authority, budget, evidence, or
  truth and filters before counting, caching, search, or recents;
- the work spine remains typed: `GoalRunProfile` is reusable adaptive pursuit
  definition; `WorkflowTemplate` is reusable directed-work shape;
  `SkillManifest` is reusable procedural context; `AutomationSpec` is reusable
  standing behavior;
  `AutomationRun` is one activation and may finish directly, explicitly create
  or join a GoalRun, contribute to an OutcomeRoom, or request bounded execution;
  `GoalRun` is durable bounded outcome pursuit and freezes one admitted
  GoalRunProfile resolution; `OutcomeRoom` is persistent
  collective pursuit above accepted participant GoalRuns; `Session` is one
  bounded interactive, headless, or supervisory execution/control context; and
  `WorkRun` is one execution attempt. Project, System, organization, and room
  scope are orthogonal to those kinds. Background is an execution mode, not an
  object class;
- shared lifecycle mechanics do not flatten that typed work spine. Each
  GoalRun, GoalGroundingLoop, WorkRun, AutomationRun, HarnessInvocation,
  ContextCell, and external handle keeps its own legal phase and authority
  table. `WorkLifecycleRecord` supplies exact-head append/replay and typed child
  refs; `CancellationFanoutPlan` supplies drain/fence/timeout/compensation/
  reconciliation obligations; archive-bound snapshots remain rebuildable
  checkpoints. Domain owners still issue the effects and completion receipts
  (`INV-35`);
- generic `HypervisorMission` is retired as a canonical catch-all. Mission may
  remain optional product copy or a creation/filter profile backed by exactly
  one GoalRun or OutcomeRoom, whose kind and ref remain visible. It creates no
  independent ID, authority, budget, lifecycle, state, evidence, or receipts.
  Typed physical mission/action and fleet-coordination contracts remain valid
  in Physical Action Safety and Embodied Runtime;
- IOI is one open, edge-sovereign operating stack for bounded autonomous
  institutions. Locally canonical ontologies make a domain legible and map
  across domains only when selected; GoalRuns create bounded purposeful work;
  OutcomeRooms add collective pursuit only when cooperation surplus justifies
  it; Hypervisor is the reference
  execution/control environment; local/domain governance and authority
  providers authorize; Agentgres admits each domain's operational truth; AIIP
  makes accepted positive-surplus interoperation between sovereign systems
  contractible; and explicitly enrolled systems may use IOI L1
  for selected shared-trust commitments. The semantic world plane and
  Hypervisor are complementary halves of one architecture, not peer product
  theses;
- Hypervisor is the governed autonomy substrate where work becomes reusable
  capability. Lowercase work is governed activity such as a Session, WorkRun,
  connector action, code change, research path, training job, workflow step,
  or service delivery; capitalized Work is its cross-object product projection.
  Capability is reusable autonomous capacity such as a worker, AutomationSpec,
  model route, data recipe, eval, tool, package, conductor advisor, service
  module, or marketplace listing;
- Hypervisor product direction is an open autonomy control plane and
  operating environment for autonomous systems, organized by a simple
  lifecycle lens of Build, Run, Govern, Observe, and Improve behind the
  stable shell. Packages owns mandatory local package, release, dependency,
  installation, recall, and impact projections. Marketplace is an optional
  discovery, publication, and commerce mode over eligible packages and external
  listing owners; neither becomes settlement or live-System truth;
- the twelve enduring first-party owner-application jobs are Studio,
  Automations, Ontology, Data, Governance, Provenance, Evaluations, Improvement,
  Foundry, Packages, Developer Workspace, and Developer Console. Environments
  and Operations are substrate applications. Embodied Systems is a conditional
  `owner_application` registration with `surface_availability: planned`,
  contextually shown or recommended only for embodied Systems or fleet roles,
  and nonlaunchable until its route and implementation exist; it projects
  Embodied Runtime truth and never requires HypervisorOS. Systems, Home,
  Projects, Applications, and Work are core
  workspaces, not application registrations;
- Studio composes package and blueprint candidates, agents, topology and
  generated-interface descriptors without owning observed membership;
  Automations owns triggers, schedules, monitors, workflows, services and
  process graphs; Ontology owns semantic versions, types, actions, overlays and
  mappings; Data owns sources, syncs, recipes, datasets, media, rights and
  consent; Governance owns constitution, admission, authority, approvals,
  budgets, protected change, learning-boundary, AIIP, lifecycle and enrollment
  decisions; Provenance owns receipts, lineage, replay, roots, custody and
  qualified assertions; Evaluations owns released suites, epoch judgment and
  judgment scorecards, exposure, consent-aware feedback, verifier challenges,
  and validity; Improvement owns change
  discovery, authoring, simulation, canary recommendations and remediation while
  Governance admits promotion, rollback, recall or kill decisions; Foundry owns
  models/routes, training, tuning, datasets and capability candidates; Packages
  owns local package lifecycle; Developer Workspace owns environment-bound code,
  files, terminals, ports and debugging; Developer Console owns connectors, MCP,
  API/client/SDK/extension registration and conformance, while Environments and
  Operations retain provider lifecycle and health;
- one `HypervisorApplicationSurfaceRegistration` family classifies
  `owner_application`, `substrate_application`, `tool_surface`, and
  `extension_application` while owning only stable definition identity,
  accountable publisher/origin, creation method, availability, routes,
  contexts, contracts, and obligations. `HypervisorSurfaceReleaseRecord` owns
  release distribution, admission, disposition, capability depth, versioned
  descriptor, and exact object/action/operator contracts beneath the
  definition's declared ceilings;
  `HypervisorSurfaceInstallationBinding` owns installation and
  deployment-level enablement plus organization/Project visibility, audience,
  object/action bounds, and authority preview;
  `HypervisorSystemInterfaceBinding` owns System-specific enablement and may
  only narrow those audience, object/action, and authority bounds; and
  `HypervisorSurfaceServingBinding` owns operational health. The independent
  canonical axes remain defined in `canonical-enums.md`, but the compiler joins
  their owning records rather than copying mutable state onto the stable
  registration. Installation is not a class, Marketplace is not an origin,
  and a developer kit is not a publisher;
- one policy-filtered product-surface compiler joins static core/application
  registrations, typed route aliases, registered tool contract metadata, and
  normalized daemon-admitted release, installation, System-interface, and
  serving records with authenticated user/organization preferences and
  Organization/Project/System/GoalRun/OutcomeRoom/AutomationRun/Session/
  WorkQueue/WorkItem/WorkRun context. Shell, Applications, command palette,
  contextual launch, and APIs
  consume appropriate projections of this compiler. Static first-party
  inventory remains safely visible during partial dynamic-service failure;
  drafts never launch; recalls/revocations remove launch eligibility; tenant and
  System caches never cross boundaries;
- compatibility routes are typed `HypervisorRouteAliasRegistration` records
  with exactly one owning workspace/application and either one static target
  route or one fail-closed typed resolver. Alias/canonical-route collisions,
  orphan targets, and context-dropping redirects are invalid;
- tools remain searchable and directly launchable but have exactly one primary
  owner and an owner breadcrumb. Generated or installed interfaces bind admitted
  package, surface descriptor, installation, audience/visibility, allowed
  actions, authority preview, and—when effectful for a live System—an admitted
  System/context ref. One interface package may bind independently to many
  Systems and serve through many UI replicas without changing System identity.
  Reference captures, screenshots, pixel certificates, and parity matrices are
  implementation evidence only and never grant product membership;
- Product surfaces should use layered language. Users and buyers see agents,
  jobs, sessions, permissions, connected apps, delivery channels, evidence,
  payments, and revoke controls. Admins and builders see policies, scopes,
  work ledgers, evals, worker packages, runtime profiles, data recipes, ontology
  kits, surface descriptors, and authority clients. Protocol, audit, and
  implementation views may name
  wallet.network, Agentgres, Hypervisor Daemon, authority grants, IOI L1
  commitments, and ContributionReceipts. Subsystem names support trust; they
  should not carry the default product pitch;
- Hypervisor's compounding loop is: governed work happens; receipts,
  artifacts, traces, corrections, and evals accumulate; failures and wins are
  mined; Foundry proposes or builds reusable capability; aiagent.xyz/MoW
  attributes external supply when marketplace workers contribute; future
  work routes better under policy, authority, receipts, and replay;
### Goal Space product and economics

- ioi.ai presents one Goal Space subscription, not separate single-node and
  network-node products. The subscription covers conductor/account experience,
  persistent goal state, portable memory, policy, receipts, replay,
  collaboration, ordinary support, and a bounded monthly grant of
  non-transferable Work Credits. Additional managed work uses opt-in top-ups,
  overage, or committed spend; independent Network/Open workers, verifiers, and
  services use a separately bounded goal budget, bounty, procurement limit, or
  service order;
- IOI reproduces the simplicity of a foundation-model seat without pooling,
  sharing, browser-automating, or reselling named-user chat/workspace limits as
  production worker capacity. Managed supply uses open/self-hosted weights,
  provider APIs, managed/dedicated endpoints, negotiated inference capacity,
  customer BYOK/BYOA, and explicitly authorized OEM/reseller paths. Aggregators
  are replaceable procurement/routing adapters, not the product moat or sole
  inference authority;
- every provider/model candidate resolves a versioned route contract covering
  commercial posture, access mode, customer-facing and automation/downstream
  rights, credential principal, provider/model terms, endpoint/model versions,
  provider allowlists, the full provider-use-of-customer-material and
  customer-use-of-output matrices, retention/ZDR, region, fallback, price,
  parameters, and rights-basis refs. Missing rights fail closed; provider
  service-delivery permission does not imply secondary use, customer receipt of
  output does not imply retention/training/distillation rights, and
  model/provider fallback is a semantic substitution that emits route evidence
  and re-runs applicable verification/acceptance;
- `Auto` / 1-of-N, `Pinned`, and `Compare` / N-of-N are routing policies, not
  subscription tiers. Auto may use a verified cheap-first cascade; Pinned fails
  closed unless fallback was authorized; Compare accounts for every admitted
  attempt, verifier, and synthesis step;
- execution/custody (`Standard` or `Private`), contributor scope (`My workers`,
  `Organization`, or `Network / Open`), and placement (local, customer
  infrastructure, selected cloud, or Hypervisor-selected) are orthogonal.
  Contributor scope never declassifies data or widens authority. Multi-model,
  multi-worker, and multi-node work does not become multi-party unless separate
  principals control authority, truth, challenge, risk, and settlement;
- local-agent intake has three explicit product elevations rather than one
  forced marketplace funnel: ioi.ai may connect an agent as a proposal-only
  guest for one Goal Space; aiagent.xyz may save an admitted composition as a
  reusable private `My workers` or organization worker; marketplace discovery,
  monetization, reputation, and Network/Open eligibility require a later,
  explicit publication and qualification decision. A guest can contribute
  useful work without becoming public, and pairing never auto-elevates it;
- `Standard` permits disclosed, policy-qualified provider-trust model routes
  over the private-native substrate. `Private` adds no-provider-trust model
  routing through local, BYO, customer-boundary, cTEE, TEE, or another
  custody-proven route. Managed private compute/proof may consume Work Credits
  or require enterprise capacity; merely connecting an app or using local/BYO
  execution is not a connector tax;
- IOI's economic posture is open independently operable L0, paid managed
  products and network services. L0 product alpha, network alpha, and L1/token
  value are separate ledgers that never accrue automatically. The Verified Work
  Graph is receipt-backed economic memory across accountable worker, harness,
  model, tool, provider, authority, cost, evaluation, acceptance, contribution,
  and dispute state. Work Credits normalize managed product costs but remain
  non-transferable product credits, not cash, a speculative token, or a labor
  payout rail. Direct BYOK removes the provider-cost component and retains only
  explicit conductor/runtime/governance/support charges;
- the registered managed-work billing schema, invariants, fixtures, and
  generated projections define exact versioned RateCard/Plan/quote bindings,
  finite credit holds, owner-evidence-bound usage, explicit overrun decisions,
  one final debit, and downward-only refund/writeoff adjustments using
  fixed-point units. The accounting kernel and durable ledger remain planned;
  the contract substrate is not public entitlement, invoice truth, cash
  movement, escrow, payout, or cross-process Agentgres ledger authority;
- the sellable allowance is still planned. Current flat OCU receipt metering is
  not supplier-invoice reconciliation, and the registered contract substrate
  does not make it so. Commercial activation
  requires route-attempt and billed-token/compute telemetry, supplier/broker
  cost, IOI fee basis, adjustments, caps, explicit overage consent, positive
  cohort margin, bounded p95 COGS, and accepted outcomes per dollar;
- Agentgres remains bundled operational truth infrastructure; ordinary
  wallet.network authority remains bundled safety infrastructure; marketplace
  and service owners retain their fees; IOI L1/token/BME economics attach only
  after real demand for scarce neutral trust, public capacity, bonded security,
  disputes, rights, finality, or governance. Any native asset is conditional
  risk-bearing capital, not Work Credits, generic inference currency, or one
  token per DAS;

### Governed autonomous systems and sparse settlement

- Intelligent blockchains are self-driving bounded actors: stateful
  autonomous-system domains that can monitor state, route work, request
  authority, recover, improve future behavior, and settle what matters only
  inside explicit authority, policy, budget, safety, receipt, replay,
  rollback, recall, and proof envelopes. Bounded recursive improvement is
  proposal-mediated improvement, not direct self-mutation or
  self-escalation;
- Hypervisor's core workspaces, twelve enduring baseline owner applications,
  conditional planned Embodied Systems owner registration, two substrate
  applications, extension applications, and tool surfaces are projections over
  Hypervisor Core, never runtime-truth owners.
  Agent Studio is Studio's agent lens, not a separate application; ODK is a
  developer kit whose artifacts surface through Ontology, Data, Studio, and
  Developer Console; Work Ledger is a Provenance compatibility alias;
  Workbench is a Developer Workspace compatibility alias; Sessions is a Work
  view and route alias; Missions is a typed Work filter/profile alias;
- Hypervisor surface registrations carry stable identity, owner doc, primary
  object families, class, accountable publisher/origin, creation method,
  availability, canonical route and typed route-alias refs, allowed placements
  and launch modes, supported roles,
  Organization/Project/System/GoalRun/OutcomeRoom/AutomationRun/Session/
  WorkQueue/WorkItem/WorkRun compatibility, daemon/API/Agentgres dependencies,
  authority/privacy and mutation boundary, declared operator-plane contract
  ceilings, composition pattern, and receipt/replay/eval obligations. Release
  records, installation bindings,
  System-interface bindings, and serving bindings carry their respective
  distribution/admission/disposition/capability, installation/enablement,
  System authorization, and operational-health state. The request-scoped
  `HypervisorProductSurfaceProjection` joins those typed records and emits
  launchability, disabled reasons, groups, and a discriminated launch binding.
  Favorite, recent and recommendation state are user or organization
  projections over stable entries, not new entries or shell categories;
- Autonomous-system domain manifests and ODK blueprints must be concrete
enough to instantiate real domains, not only diagrams. They should name
source/project bindings, runtime placement, authority scopes, connector
requirements, exposed operator/API/MCP/AIIP interfaces, generated domain
app refs, release targets, rollback/recall/kill-switch posture, receipt
schemas, replay obligations, and settlement/dispute posture when
applicable;
- Hypervisor application composition primitives include catalog/search
  launcher, Open Application frame, list/detail workspace, command composer,
  modal or step wizard, canvas/editor projection, object view, object-view
  editor, graph view, review/approval inbox, monitoring/resource console,
  lineage/replay/evidence view, artifact/build/job view,
  package/install/publish/recall flow, generated domain surface, governed
  creation/genesis wizard, typed resource/object picker, lifecycle strip,
  authority preview, desired-versus-observed topology view, incident queue,
  proposal/diff/simulation/canary/rollback drawer, and persistent
  Organization/Project/System/Application/Tool/Object breadcrumb. These are UX
  composition patterns over shared Core contracts, not new truth owners;
- the canonical builder journey is
  `blank or template -> describe institution/resources/actions/success ->
  compile one package/genesis proposal -> validate -> preview authority,
  policy, cost, topology, evidence, and lifecycle -> simulate -> propose and
  approve -> instantiate one stable System -> operate and inspect -> upgrade,
  recover, migrate, recall, or dissolve`. Studio, declarative files, ADK, SDK,
  and CLI edit or project one source-neutral representation. Product language
  and progressive disclosure keep the common path compact, while every resolved
  ref, hash, default, policy source, and receipt remains inspectable. A template
  never pre-authorizes an effect or fabricates evidence;
- Hypervisor capability lifecycle control is a cross-surface projection, not
  a separate runtime, authority owner, or permanent shell category. Governance
  owns the release/change facet for promote, deploy, roll out, pause, rollback,
  recall, kill-switch, remote-config, release-target, gate, and cohort
  coordination across reusable capability; local surfaces still own their local
  evidence and work state. Systems projects live-System identity and contextual
  lifecycle/topology; Work projects typed pursuit, execution, review, queue and
  logical-work incidents; Environments owns environment runtime lifecycle;
  Operations owns provider infrastructure, capacity, placement, provisioning,
  member operation, fencing, failover, queue/spend and RPO/RTO posture;
  Foundry owns candidate/evaluator-asset building, training, experiment
  execution, and promotion-bundle candidates; Evaluations owns released suites,
  frozen epoch judgment, exposure, challenges, and validity; Automations owns
  trigger/workflow/service lifecycle; Packages owns local install/publish/recall
  projections while Marketplace is optional discovery/commerce; Provenance owns
  artifact/contribution handoffs; Governance owns human approval, policy, and
  protected incident/lifecycle gates;
  Ontology and Provenance own dependency, provenance, and impact views, and
  Provenance owns trace/proof inspection (the legacy Work Ledger views
  converge there);
- agent-ready development environments are stateful, interactive, and
  potentially adversarial. For untrusted or cross-tenant autonomous work,
  Hypervisor should use VM, microVM, HypervisorOS, customer-boundary, TEE, or
  cTEE profiles as the isolation claim; devcontainers and containers are setup
  or inner-sandbox lanes unless admitted inside an appropriate boundary.
  Readiness means the daemon admitted recipe, tasks, services, resources,
  connectivity, ports, caches, authority, receipts, and restore posture, not
  merely that a shell or container started;
- application surface modes such as solution planners, walkthrough builders,
  typed tool/function builders, object views, value-type managers,
  graph/object explorers, schedulers, object/state monitors, authority
  clients, client applications, granular permissions, resource queues,
  retention/declassification views, restricted views, checkpoints,
  issues/action queues, artifact registries, build/job trackers, workflow
  lineage, code templates, branch/change views, developer consoles,
  diagnostics, widget builders, source/sync/listener managers, data health,
  dataset/time-series explorers, model libraries, model rules/guardrails,
  inference readiness, and domain consoles are Applications catalog or
  contextual surface inventory, not permanent shell categories;
- Learning / Patterns / Examples / Training is the role-guided recipe facet for
  turning learning
  tracks, solution diagrams, example apps, starter automations, data recipes,
  ontology packs, eval packs, and package templates into governed sessions,
  automations, Foundry jobs, domain apps, receipts, replay, promotion
  proposals, and optional marketplace paths. It appears through Home,
  Applications, Packages/Marketplace, Foundry, Ontology, Data, generated domain
  apps, and onboarding rather than as a separate final product app;
- Agents are configurable, buildable product objects over Hypervisor Core;
  Workers remain the accountable protocol package/manifest boundary.
  Product controls such as Agent, Mode, Model, Reasoning, Speed, Resolver,
  Tools / Integrations, Memory, Authority, Budget, Evals, and Provenance
  posture compile into daemon records, wallet authority, model routing,
  HarnessProfile selection, Agentgres operations, and receipts;
- Model is the product-facing control label inside New Session, Studio's
  agent lens, Foundry, and related surfaces; ModelRoute remains the implementation/runtime
  object for provider, custody, fallback, spend, privacy, eligibility, and
  invocation policy;
- Hypervisor's Agent Operating Plane is daemon-owned: configured agent
  records, agent/session admission, work queues, work items, work runs,
  turn control, conversation streams, subagent delegation, runner
  reconciliation, usage accounting, and exec/security telemetry are
  runtime contracts, not client-local state;
- Hypervisor's Operator Plane is the governed control-plane surface and lane for
  operating Hypervisor itself. It uses the same `AgentRecord`,
  `ModelConfiguration`, `ReasoningEffort`, `ServiceTier`, `HarnessProfile`,
  tool/MCP contract, authority, and receipt substrate as sessions, but it is
  not ioi.ai, not a child Session or HarnessInvocation, and not an ambient host
  administrator. Backend/headless conductors are client projections over
  this same substrate, not custom privileged Hypervisor instances;
- Hypervisor Automations is the durable workflow, trigger, schedule, monitor,
  API/service, approval-flow, and queue definition surface over the Workflow
  Compositor. WorkflowTemplate owns immutable directed graph shape;
  AutomationSpec binds one exact template revision plus standing activation,
  triggers, schedules, service/queue contracts, concurrency/idempotency,
  authority requirements, and allowed overrides; AutomationRun freezes the
  exact spec/template revisions, parameters, resolution receipt, and live
  authority leases. Automations owns AutomationSpec authoring and
  AutomationRun history, not
  GoalRun, OutcomeRoom, Session/WorkRun execution truth, wallet.network
  authority, or Agentgres truth. Long duration, System binding, or headless
  execution never changes an automation into a Mission or GoalRun;
- ioi.ai is the outcome conductor and Goal Space product. It may coordinate
  multiple models, HarnessProfiles/AgentHarnessAdapters, workers, connectors,
  sessions, verifier paths,
  attempt strategies, and independent contributors over Hypervisor when a goal
  calls for it. Its durable projection is a cross-session outcome graph and,
  for persistent collective goals, an OutcomeRoom workstream graph over
  authorized participants, claims, attempts, findings, receipts, artifacts,
  spend, authority blockers, challenges, replay, and contribution refs;
- ioi.ai dogfoods Hypervisor as a first-party coordinator. Similar
  coordinators should be buildable from Hypervisor application surfaces,
  operator-plane contracts, WorkRuns, Automations, Foundry, wallet.network,
  Agentgres, aiagent.xyz/MoW contribution refs, and receipts without
  privileged substrate access;
- Hypervisor Foundry is the capability factory: the surface where observed
  work, datasets, executable eval worlds, interactive worlds, gameplay
  trajectory datasets, scenario curricula, traces, failures, and proposals
  become reusable models, workers, world-model candidates, spatial-temporal
  policies, data recipes, evals, model routes, packages, endpoints,
  conductor-advisor candidates, certification-run candidates, transfer gates,
  or promotion proposals. ioi.ai may draft or consume Foundry refs, but Foundry
  owns training/eval lineage;
- Domain Ontologies and Data Recipes are IOI's locally canonical semantic world
  plane. Domains interoperate only when expected benefit justifies it, through versions,
  overlays, crosswalks, challengeable semantic mapping decisions, and policy-
  bound projections rather than one global ontology or database. Admitted
  assertions preserve provenance, valid/transaction time, uncertainty,
  supporting and contradicting evidence, applicability, supersession, and
  dispute; admission does not make a proposition universally true;
- `OntologyActionContract` is the semantic/action bridge: target object and
  typed IO, pre/postconditions, invariants, capability/runtime binding, risk,
  authority, dry-run, idempotency, retry, ambiguous-effect reconciliation,
  compensation, verification, evidence, receipts, and physical-safety posture;
- Ontology and Data are the first-party Hypervisor applications over the
  semantic world plane; ODK is the developer kit beneath them (CLI, templates,
  scaffolds, generated SDKs, conformance), not an application. Foundry
  consumes ontology/data artifacts governed through that plane for training,
  evaluation, simulation, worker/package generation, and capability
  improvement, but does not own semantic truth. `Data / Knowledge`,
  `Data Studio`, `Ontology Studio`, `Workshop`, and `Domain Blueprints` are
  legacy aliases that resolve to the Ontology and Data applications, not
  separate final product apps;
- the Ontology Development Kit is the source-neutral builder kit over Domain
  Ontologies, Canonical Object Models, Data Recipes, Connector Mappings,
  PolicyBoundDataViews, OntologyProjections, evals, and workflow schemas. It may
  scaffold or validate object-aware surfaces, domain apps, operator consoles,
  eval packs, worker/package skeletons, and marketplace-ready ontology packs,
  but it is not a runtime, truth store, authority layer, data warehouse,
  training-consent owner, marketplace, or settlement layer;
- Connectors / Tools / MCP is Developer Console's facet over the
  authority-aware registry (a legacy family label, not a separate
  application); reusable packages carry immutable `MCPGatewayRequirement`
  refs while live work receives separately admitted subject-scoped gateway
  profiles. MCP tools normalize to `RuntimeToolContract`; resources to
  policy-bound views, artifacts, or memory projections under ContextLease;
  prompts to untrusted import inputs; elicitation to typed user input with
  separate authority approval; tasks to external HarnessInvocation handles;
  and Apps to sandboxed extension surfaces. MCP servers, external agent tools,
  and workflow-as-tool subgraphs must still compile to primitive capabilities,
  authority scopes, policy decisions, and receipt obligations;
  the Hypervisor Operator Plane may consume those contracts, while child
  sessions may request or propose but must not directly mutate host/platform
  state. ioi.ai connector/auth escalation is a handoff through these
  contracts, wallet.network authority, daemon admission, and Agentgres
  receipts, not a direct provider path;
- wallet.network is the autonomous-work authority wallet and gateway for
  identity, auth factors, guardian surfaces, key shards, provider credential
  bindings, delegated authority, leases, approvals, secrets, spend, data-use
  permission, declassification, revocation, policy simulation inputs,
  gateway decisions, risk labels, portable authority refs for training-data
  use, and authority receipts. Hypervisor/Foundry/Data/Agentgres own local
  governance and eligibility state; wallet.network supplies delegated
  authority when that state needs secrets, spend, decryption,
  declassification, provider trust, publication/export, cross-domain reuse,
  or autonomous-agent-executable power. Agents and workers do not receive
  raw secrets as product doctrine; they receive scoped, revocable authority
  leases mediated by wallet.network and daemon policy;
- the default managed-product authority experience is:
  `continue with an eligible federated identity or passkey -> native wallet
  identity -> low-risk product session with no effect authority ->
  consequential-action proposal -> canonical exact-action, batch, or standing
  review -> qualified presentation plus separately inspectable authenticator
  ceremony -> scoped, expiring, revocable grant/lease -> daemon-computed actual
  effect and equality/membership/constraint verification -> effect or refusal
  -> WalletReceipt plus Agentgres evidence`. Apple, Google, Microsoft, GitHub,
  enterprise SSO, and future providers are UI choices over a provider-neutral
  `federated_identity` factor contract. The calling product/deployment identity
  plane owns the product session; wallet.network binds its ref and origin into
  the exact request/review without taking over its lifecycle. The immutable
  request, canonical reviewed representation, single-use ceremony context, and
  typed authorization subject are distinct commitments. Presentation evidence
  records independent properties through a versioned evidence profile; a
  generic passkey, hardware key, user-verification flag, or attestation is not
  proof that the application-defined representation was displayed or
  understood. Portable v3 grants must sign that complete context together with
  the exact root-signed principal-authority resolution coordinates and snapshot
  whenever portable-principal authority is claimed before this journey is
  claimable end to end. The target ceremony context is a closed,
  domain-separated object with a fresh random nonce; the target review receipt
  is a portable wrapper over the exact common receipt base and carries one
  hash-bound satisfaction evaluation per required factor or guardian; and final
  equality/membership/constraint admission, the exact temporal profile/
  evaluation, revocation evidence, and required continuity-floor evidence are
  recorded by a distinct `AuthorityEffectAdmissionReceipt` before
  invocation. These successor contracts are not claims
  about current v1/v2 schemas. Face ID, Touch ID, Windows Hello, or a device PIN
  unlocks the authenticator locally; biometric material is not an IOI
  credential and does not leave the device. Account linking, sign-in, session
  restoration, recovery, and device replacement never reconstruct, preserve,
  or widen authority. High-risk recovery requires policy-selected proof,
  revocation or quarantine of affected sessions/factors, re-enrollment, and
  receipts;
- Developer Workspace is the live code, files, terminal, ports, debugging, and
  environment-bound hands-on surface; `Workbench` is its compatibility alias;
- editor integrations such as VS Code, Cursor, Windsurf, JetBrains, browser
  IDEs, terminals, VMs, local OS surfaces, and HypervisorOS nodes are
  adapter targets, not Hypervisor's product identity;
- external CLI or hosted agent harnesses such as Codex, Claude Code, Grok
  Build, OpenHands, Aider, shell/tmux agents, CI agents, and hosted coding
  agents are Agent Harness Adapters; they submit proposed work through
  Hypervisor Core and the daemon and do not become Hypervisor clients or
  runtime truth;
- host-terminal harness sessions become daemon-admitted only after recipe
  admission, harness binding admission, launch, spawn, readiness, terminal
  attach, and transcript projection refs are all bound; a Hypervisor client
  PTY is transport, not runtime truth;
- code WorkRuns should bind isolated child environments to a materialized Git
  branch/worktree and an Agentgres patch branch: Git/worktree backs file
  review, tests, IDE use, and PR export; Agentgres owns coordination,
  attribution, authority, validation, receipts, and admitted merge truth;
- Hypervisor is the flagship product substrate for building, deploying, and
  governing autonomous systems through daemon/runtime contracts;
- Hypervisor product UX direction belongs in the canonical owner docs; any
  private sprint, research, or product-reference scaffold must be translated
  into ownership, authority, state, receipt, privacy, and adapter contracts
  before it becomes doctrine;
- ioi.ai Goal Chat is an intent and coordination surface: it may ask,
  invoke, inspect, summarize, and draft Hypervisor work, but durable
  workflows/services must hand off to Hypervisor Automations and execution
  must pass through the Hypervisor Daemon;
- IOI Authority Gateway is the daemon sidecar/compatibility profile for
  existing IDE, CLI, browser, hosted-agent, and MCP/tool ecosystems; it is
  not a separate runtime;
- Agentgres is operation-backed domain truth with a Postgres bridge;
- Agent Wiki / `ioi-memory` is the adjacent context-memory plane for what
  agents can know, retrieve, and remember; Agentgres admits and proves
  durable memory mutations when they become canonical, shared, portable,
  replayable, policy-relevant, routing-relevant, training-relevant, or
  restore-relevant; worker packages may declare memory compatibility, managed
  instances own concrete memory profiles/archives, and harnesses consume
  policy-filtered memory projections rather than owning durable memory by
  themselves;
- Agentgres artifact refs own payload meaning, lifecycle,
  policy/authority linkage, receipts, replay/import metadata,
  archive/restore validity, and state-root validity;
- private user/app state follows the same split as private agent state:
  Agentgres owns canonical refs and meaning, storage backends hold encrypted
  bytes, authority providers and local/domain policy control
  viewing/decryption/mutation authority, wallet.network is mandatory for
  portable delegated authority, secrets, decryption leases, external effects,
  or high-risk approval, and IOI L1 receives public/economic/cross-domain
  commitments only for explicitly enrolled systems under their selected
  settlement profiles;
- wallet.network is the authority wallet/gateway for autonomous agents and
  autonomous finance. It may render as a Wallet cockpit in high-trust or
  advanced contexts, but ordinary product flows should usually present it as
  SSO, permissions, connected access, approvals, recovery, and revoke controls
  embedded inside the current product. It owns auth-factor posture, guardian
  and key-shard posture, provider credential binding posture, agent/session
  authority, exchange authority, trade authority, risk disclosure, approval,
  signing/denial, revocation, protection actions, and wallet receipts, while
  agents, routes, venues, connectors, and provider adapters only produce
  requests or candidates;
- `decentralized.exchange` is a preferred first-party route-intelligence
  engine for asset conversion, not a mandatory exchange UI, exchange
  backend, authority layer, liquidity owner, execution owner, or trust root;
- `decentralized.trade` is a preferred first-party venue, market, and
  exposure-intelligence engine, not a mandatory trading UI, broker,
  custodian, user position owner, authority layer, venue execution owner, or
  trust root;
- `decentralized.cloud` is a preferred first-party resource-intelligence
  engine for infrastructure capacity, not a mandatory cloud UI, cloud control
  plane, provider account owner, VM lifecycle owner, authority layer, restore
  truth layer, storage custody owner, or trust root;
- Hypervisor has direct provider integrations for cloud compute, storage,
  GPUs, DePIN, local machines, customer cloud, enterprise infrastructure,
  decentralized storage, and user-specified provider routes; confidential
  compute / cTEE lanes remain speculative design, not a shipped provider
  kind;
- aiagent.xyz is the capability market for benchmarked, installable,
  attributable autonomous capability. It is the discovery, procurement,
  installation, initialization, and routing layer for ontology-bound digital
  and embodied workers; it
  indexes workers through `DigitalWorkerOntology`, `VerticalOntologyPack`,
  `IntegrationSurface`, `ManagedWorkerOnboardingPlan`,
  `ManagedWorkerInstance`, managed-instance lifecycle,
  `ManagedWorkerInstanceConfigRevision`, `ManagedWorkerInstanceChangePlan`,
  `RuntimeManagementChannel`, `ContactDeliveryChannel`,
  receipts, benchmarks, authority, runtime posture, and safety posture instead
  of hardcoded vertical directories;
- decentralized.exchange/trade/cloud produce route, venue, exposure, and
  infrastructure-capacity candidates; wallet.network authorizes; Hypervisor
  deploys or executes; venues and providers perform; Agentgres records; the
  system settles locally or invokes a selected settlement service by trigger;
- storage backends such as Filecoin/CAS, S3, local disk, and object stores
  hold payload bytes only; missing, invalid, stale, or unavailable payloads
  become Agentgres `ArtifactAvailabilityIncident` records plus repair
  receipts when they affect admitted work;
- Private Workspace backed by cTEE is the daemon-owned workspace/execution
  profile for persistent rented GPU Hypervisor Nodes that must keep protected
  plaintext off provider-controlled nodes by default;
- Candidate-Lattice Private Decoding is the default protected-agency strategy
  for Private Workspace backed by cTEE: rented nodes generate candidates,
  sealed/private heads select or deny;
- IOI kernel is the L0 substrate;
- IOI L1 is the optional shared public settlement, registry, dispute, and
  governance root for systems that enroll in those services;
- autonomous systems can execute anywhere and settle locally; external
  settlement is explicit and service-selective;
- AIIP moves delegated autonomous work, collaborative-pursuit updates,
  negotiated semantic profiles, authority leases, receipts, settlement intents,
  disputes, reputation queries, and handoffs across independently governed
  bounded execution domains;
- local member nodes and workers may reuse the same typed work, handoff,
  evidence, and receipt vocabulary, but ordinary intra-system placement is not
  AIIP federation and does not require cross-party collaboration terms. It binds
  through the system's constitution, membership, role, resource, work, and
  authority leases instead;
- governed autonomous-system chains are system-local execution chains with
  policy, modules, proposals, receipts, state roots, and governed upgrades;
- a Hypervisor Node is a local operational-finality, orchestration, authority-integration
  and enforcement, state,
  replay, routing, and interop domain for many governed autonomous-system
  chains;
- Hypervisor App, Hypervisor Web, CLI/headless, Systems, Work, Developer
  Workspace, Automations, Foundry, other application surfaces, and Environments
  views
  are not the Hypervisor Node; they are clients, application surfaces, or
  projections, while the node is the local operational-finality domain composed around
  Hypervisor Daemon, Agentgres, wallet.network authority paths, local
  registries, receipts, and replay;
- Hypervisor Nodes settle autonomous work locally; selected external services,
  including IOI L1 for enrolled systems, settle only declared shared
  commitments;
- IOI topology is edge-in and fractal;
- verifiable bounded agency is IOI's execution-boundary alignment thesis:
  workers may reason or propose probabilistically, but consequential effects
  cross reality only through bounded authority, policy, receipts, and
  verification;
- Smarter-agent runtime loop is the bounded cognition discipline for
  model pass, action proposal, gate, execution, observation, receipt, and
  re-entry; it is mediated by Hypervisor Daemon/Core and never owns
  execution authority by itself;
- `physical_action` is a high-risk effect class, not a generic tool-call
  variant; actuator-affecting work must bind to Physical Action Safety
  objects such as `PhysicalActionPolicy`, `SafetyEnvelope`,
  `EmergencyStopAuthority`, `SensorEvidenceReceipt`, and
  `ActuatorCommandReceipt` before execution;
- Embodied Runtime is the runtime companion to Physical Action Safety. It
  owns robot/fleet identity, controller bindings, sensor and actuator
  registries, versioned `EmbodiedResourceGroup` definitions, local control
  bridges, heartbeat/failsafe posture, world models, maps, zones, calibration,
  environment state, physical command queues, telemetry streams, physical
  replay, sim-to-real gates, incidents, recovery, operator handoff, and
  fleet-level policy for live physical domains. Resource groups freeze their
  transitive resolved closure to exact unit, controller, sensor, actuator, zone,
  and emergency-stop-authority refs plus a membership hash at admission. Sensor
  and actuator refs remain the terminal physical-I/O membership leaves; the
  wider closure binds the units, controllers, zones, and stop authorities that
  constrain them. Resource groups create no node, unit, fleet, DAS, or actuator authority,
  and atomic execution is claimable only within one admitted controller or
  hardware boundary. Embodied execution is explicitly two-speed: the slow
  governance plane authorizes bounded mission/action envelopes; a certified
  local control-and-safety plane executes high-frequency control, retains local
  emergency stop, and emits segment commitments plus exception receipts;
- an embodied unit is not automatically a Hypervisor Node. A robot or drone may
  host an admitted runtime-node membership or may remain a governed physical unit
  attached through an admitted edge gateway/controller. Fleet missions bind the
  owning `system_id`, deployment and membership refs, allocation leases,
  coordination epoch and state watermark, partition/rejoin policy, and
  resulting receipts; independently governed fleets cross through AIIP instead;
- workers, models, tools, connectors, browsers, shells, and computer-use
  providers are guest workloads/capabilities executed through daemon
  enforcement under local/domain policy and applicable authority grants;
- policy, receipts, replay, approvals, authority scopes, and settlement hooks
  are the shared trust/audit substrate. A receipt binds only its declared
  boundary fact; evidence, verification, acceptance, adjudication, and
  settlement are distinct assurance stages;
- clients are projections or operators, not private runtime truth;
- Environments views in Hypervisor App, Hypervisor Web,
  CLI/headless projections, and console.ioi.ai are projections and control
  lenses over daemon, Agentgres, wallet.network, cTEE, AIIP, and provider
  substrate; they are not separate apps with separate runtime truth;
- CLI/headless, SDK, ADK, and ODK are separate surfaces: CLI/headless is the
  operator/scripting/CI client, TUI is an optional presentation of it, SDK is
  the low-level protocol/client library, ADK is the autonomous-system builder
  framework, and ODK is the ontology-aware surface/domain-app/data-recipe builder
  kit over semantic data-plane contracts;
- IDE/CLI/browser/hosted-agent adapters mediate through available control
  points only and must not claim total interception of opaque tools;
- models and agents may reason or propose; local/domain policy and the
  applicable authority provider authorize consequential power, while the daemon
  admits, enforces, executes, receipts, and fails closed at the deterministic
  execution boundary;
- Hypervisor's primary build artifact is an Autonomous System Package;
- Autonomous System Package identity and live-system identity are separate.
  Package lifecycle is compose -> bind requirements -> simulate/evaluate ->
  package -> sign -> release -> promote -> deprecate/revoke;
- `AutonomousSystemGenesisEnvelope` alone binds a selected package release to a
  new stable `system_id`, constitution, initial profiles, governing
  decision/authority, and cryptographic origin. Its
  `initial_profile_bundle_root` commits the exact closed candidate constitution,
  ordered oracle profiles, ordering and lifecycle profiles, and explicit
  nullable network enrollment before the genesis operation commitment.
  Activation, operation, improvement, recovery, migration, succession,
  dissolution, and decommission are live-system lifecycle, not package
  lifecycle;
- Worker is the protocol actor;
- Model is a cognition backend;
- MoW is labor routing;
- Worker Training is the supply-creation lifecycle;
- TrainingBatchPlan, RawBatchArchive, QualityGateReport,
  ModelCapacityProfile, and TrainingCostLedger are first-class Foundry and
  Agentgres objects when batch-level training mechanics matter;
- Domain Ontologies and Data Recipes are the semantic data plane, surfaced
  in Hypervisor through ODK facets, Domain Apps, or contextual views;
- DistilledOntologyDataset is the compact high-signal data substrate for
  efficient specialist training and evaluation when useful;
- participant messages, artifacts, findings, semantic mappings, and verifier
  suggestions remain hostile/untrusted input until admitted. They cannot
  automatically promote into durable memory, ontology, routing, authority, or
  production capability; risk may require independent verification,
  separation of duty, affiliation disclosure, anti-Sybil/collusion controls,
  quarantine, and reversible promotion;
- external-effect work declares `replayable`, `checkpointable`,
  `compensatable`, `reconciliation_required`, or `non_retryable` posture.
  Environment restoration never establishes outcome restoration;
- governed autonomous-system chains are system-local state machines, not a
  mandatory public chain per agent, GoalRun, tool call, or receipt. Public
  consensus remains sparse and trust-driven;
- `adaptive_work_graph` is a local execution strategy only;
  `CollaborativeWorkGraph` is the shared-frontier collaboration profile above
  GoalRuns. Neither is a peer runtime.
