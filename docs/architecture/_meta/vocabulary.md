# Runtime Vocabulary

Status: canonical vocabulary reference.
Canonical owner: this file for runtime, audit, substrate, projection, and naming vocabulary.
Supersedes: overlapping runtime vocabulary in plans/specs when names conflict.
Superseded by: none.
Last alignment pass: 2026-07-11.
Doctrine status: reference
Implementation status: mixed (naming reference across all maturity levels)
Last implementation audit: 2026-07-05

The agent harness uses behavior-first names in runtime code and reserves
compliance acronyms for hidden audit material.

## Language Layers

Architecture terms should not automatically become product copy. Use the
smallest visible vocabulary that matches the audience:

| Layer | Use For | Default Language |
| --- | --- | --- |
| Product | users, buyers, first-run flows, marketplace listings | Goal Spaces, agents, contributors, jobs, workstreams, projects, sessions, permissions, connected apps, budgets, evidence, run history, payments, renew, revoke |
| Admin / Builder | org admins, builders, operators, advanced settings | policies, scopes, work frontier, claims, attempts, findings, verifier challenges, work ledger, evals, worker packages, runtime profiles, data recipes, ontology kits, surface descriptors, integration surfaces, authority clients |
| Protocol / Architecture | implementers, auditors, conformance, proof drilldowns | wallet.network, Agentgres, Hypervisor Daemon, authority grants, Agentgres operations, ContributionReceipts, IOI L1 commitments |

Default presentation map:

| Owner Term | Default Product Term |
| --- | --- |
| wallet.network | SSO, permissions, connected access, authority, recovery |
| Agentgres | Provenance (legacy family name: Work Ledger), evidence, run history, receipts |
| Hypervisor Daemon | secure runtime, execution environment, worker runtime |
| IOI L1 / mainnet | proof network, settlement, public commitment |
| aiagent.xyz | agent marketplace, worker marketplace, agent supply |
| ContributionReceipt | contribution record, payout evidence, attribution |
| OutcomeRoom / CollaborativeWorkGraph | Goal Space or Mission workstream |
| RoomParticipantLease | contributor or background participant status |
| WorkCredit | managed-work credit or included/top-up allowance |
| NetworkGoalBudget | Network/Open budget, bounty, or external-contributor budget |

Subsystem names should be visible in advanced security, audit, proof,
developer, protocol, and conformance contexts. They should not carry the default
product pitch or routine onboarding flow.

## Builder Kit Terms

- `SDK`: the low-level protocol/client library over daemon/domain APIs. It may
  submit, inspect, stream, or control work through admitted APIs; it is not the
  execution substrate or a truth store.
- `ADK`: the autonomous-system builder framework. It scaffolds workers, service
  modules, harness adapters, evals, manifests, receipts, and deployment profiles
  over daemon/domain contracts; it is not a peer runtime.
- `ODK` / `OntologyDevelopmentKit`: the ontology-aware builder kit over Domain
  Ontologies, Canonical Object Models, Data Recipes, Connector Mappings,
  PolicyBoundDataViews, OntologyProjections, workflow schemas, evals, and
  conformance profiles. It scaffolds object-aware surfaces, domain apps,
  operator consoles, dashboards, data-recipe builders, connector-mapping
  editors, eval packs, worker/package skeletons, and marketplace-ready ontology
  packs. It is not a runtime, authority layer, semantic truth store, data
  warehouse, training-consent owner, marketplace, or settlement layer.
- `OntologyDevelopmentKitManifest`: a builder/conformance manifest that packages
  ontology refs, object-model refs, recipe refs, connector mappings,
  policy-bound views, surface descriptors, workflow schemas, eval refs,
  operator/MCP contract refs, package refs, and conformance expectations.
- `OntologySurfaceDescriptor`: an object-aware surface descriptor for generated
  or authored list/detail views, object views, object editors, graphs, forms,
  review queues, monitoring consoles, dashboards, data-recipe builders,
  connector-mapping editors, and domain apps. It declares binding and
  obligations; it does not own execution, authority, semantic truth, or
  marketplace status.

## Runtime Terms

- `HypervisorDaemon`: the hypervisor/control plane for autonomous execution. It
  exposes the public runtime API, hosts daemon-local execution services,
  schedules and supervises workflows/workers/tools/models/connectors/computer-use
  leases, writes through Agentgres-compatible envelopes, emits receipts/replay
  records, requests wallet.network authority, and owns effect semantics for
  autonomous work. IOI remains the protocol, settlement, routing, and
  public-trust layer around that runtime.
- `HypervisorOS`: the bare-metal Hypervisor node profile where the Hypervisor
  Daemon is the node root. It owns measured node boot posture, daemon-rooted
  workload launch, node integrity receipts, denied-by-default egress, and
  bare-metal conformance. It improves integrity/control/measurement; it does
  not make consumer GPUs confidential compute and does not replace cTEE
  no-plaintext-custody.
- `HypervisorSubstrateMode`: the deployment/control posture by which the same
  Hypervisor control plane governs substrate and autonomy. Values are
  `type1_hypervisoros`, `type2_desktop_workstation`, and
  `type3_autonomy_plane`. Type 1 governs bare-metal/appliance/cluster substrate;
  Type 2 governs hosted local/workstation substrate on a normal OS; Type 3
  virtualizes autonomous work across sessions, WorkRuns, workers, model routes,
  tools, authority, receipts, replay, outcomes, and promotion. These are not
  three products.
- `HypervisorOSNode`: a runtime node running the HypervisorOS bare-metal
  profile. It may expose microVM, container, WASM, model-server, and tool-runner
  substrates, but all autonomous workloads remain subordinate to Hypervisor
  Daemon policy, receipts, and capability exits.
- `HypervisorOSBootProfile`: a measured boot profile binding image, kernel,
  initrd, daemon binary, package manifest, driver manifest, GPU class, secure
  boot/TPM posture, and update/rollback policy for a HypervisorOS node.
- `HypervisorOSBootReceipt`: the integrity receipt emitted for HypervisorOS boot
  state. It can support accounting, reproducibility, disputes, and provider
  reputation, but it is not by itself a plaintext privacy guarantee.
- `NodeMeasurementReceipt`: a receipt for measured node state, runtime
  compatibility, or attestation posture. It proves what was supposed to run; it
  does not prove protected plaintext was safe unless paired with cTEE, TEE, or
  another approved confidential profile.
- `EcosystemAssuranceProfile`: a source-neutral trust profile that declares the
  evidence, policy, conformance, revocation, and anchor requirements for a
  worker, runtime, wallet authority client, MCP gateway, service outcome,
  embodied domain, storage backend, or marketplace listing. It does not grant
  authority, execute work, store truth, rank listings, decide insurance
  coverage, or settle disputes.
- `ConformanceProfile`: a compatibility profile for an interface or runtime
  family such as worker endpoints, harness adapters, runtime nodes, wallet
  authority clients, MCP gateways, cTEE private workspaces, HypervisorOS nodes,
  embodied runtime, service endpoints, storage backends, or Agentgres domains.
  It defines expected behavior and negative tests; it is not by itself a legal
  or safety certification.
- `CertificationClaim`: a claim that a subject satisfies an
  `EcosystemAssuranceProfile` for a bounded version, issuer, evidence set,
  expiry, and revocation policy. It must bind to evidence refs and may anchor
  publicly when marketplace, dispute, bond, registry, or governance trust
  requires it.
- `JurisdictionPolicyPack`: a declarative policy pack for jurisdiction,
  eligibility, identity, KYC/business verification, regulated actions,
  retention, deletion, residency, tax, invoice, disclosure, and audit-export
  requirements. It is a policy input to wallet.network, Hypervisor, Agentgres,
  marketplaces, services, and settlement triggers, not legal advice.
- `AssuranceEvidenceBundle`: an evidence package composed of Agentgres refs,
  receipts, artifact refs, scorecards, wallet authority refs, policy refs,
  redaction policy, and optional L1 anchors. It packages evidence without
  becoming raw payload storage or operational truth.
- `AssurancePostureProjection`: a rebuildable view over current certification,
  jurisdiction, abuse, liability, and commercial status for a subject. It is
  derived from owner-domain truth, evidence, policy packs, and public anchors.
- `QuarantineAdvisory`: a scoped restriction or warning over a worker, package,
  runtime node, wallet client, MCP gateway, service package, embodied domain, or
  ecosystem class. It must be reasoned, receipted, and routed through owner
  domains; it is not an unbounded global kill switch.
- `LiabilityClaimRoute`: a claims-routing object that binds an incident,
  evidence bundle, parties, policy refs, optional external claim refs, and
  dispute or settlement refs. It routes evidence for coverage or dispute
  processes; it does not adjudicate insurance coverage by itself.
- `CommercialAssuranceExport`: a customer or organization export over billing,
  invoices, cost centers, SLA evidence, audit evidence, service delivery,
  marketplace usage, and tax refs. It is generated from owner-domain truth and
  redacted by policy; it is not the source of runtime truth.
- `HypervisorProvidersAndEnvironments`: the default Hypervisor capability set
  for cross-session provider integrations, environment lifecycle, managed
  runtime resources, services, tasks, ports, logs, SCM auth, archive/restore
  posture, cost, health, placement, and provider evidence. It is part of
  Hypervisor's default session/project/provider views, not a separate product.
- `HypervisorProviderNode`: the Hypervisor projection/object for a local, cloud, GPU, DePIN,
  customer, HypervisorOS, TEE, or bare-metal runtime node. It binds node
  identity, daemon refs, provider metadata, Agentgres domain refs, authority
  refs, status, cTEE posture, storage posture, receipt refs, and projection
  watermarks.
- `HypervisorWorkloadPrimitive`: the Hypervisor projection/object for VM, container,
  microVM, WASM, image, volume, network, snapshot, backup, restore point,
  GPU-pool, node-pool, migration-plan, or provider-connector lifecycle state.
  It is governed infrastructure state and must still link to authority refs,
  Agentgres operation refs, and receipts when consequential.
- `HypervisorRuntimeAssignmentView`: the Hypervisor projection over runtime
  assignments, placement reasons, workspace/run refs, authority refs,
  Agentgres operation refs, receipt refs, and status. It is observability and
  control-plane state, not execution ownership.
- `HypervisorStoragePosture`: the Hypervisor projection over storage-backend availability,
  retention, replication, privacy class, and Agentgres artifact refs. It does
  not make storage backends the authority over payload meaning or restore
  validity.
- `WorkspacePersistenceProfile`: Hypervisor policy object for ephemeral,
  session, zero-to-idle, persistent, or archive-only workspaces. It declares
  idle behavior, compute shutdown, provider lease closure, archive/checkpoint
  requirements, allowed storage backends, retrieval checks, restore policy, and
  receipts.
- `EnvironmentWarmupProfile`: Hypervisor policy object for prebuilds,
  dependency caches, model caches, index warmup, image pulls, and provider warm
  pools. It is a performance projection, not canonical workspace truth.
- `NodeEnforcementProfile`: HypervisorOS profile declaring daemon gates,
  sandboxing, executable policy, egress policy, datawall/leakage detection,
  log/export redaction, cTEE checks, and optional hardware attestation hooks.
  It is evidence/control posture, not a substitute for cTEE privacy.
- `ClassicalInfraPrimitive`: any traditional infrastructure object Hypervisor may
  manage or project, including a VM, container, microVM, WASM workload, image,
  volume, network, firewall/egress policy, snapshot, backup, restore point,
  node pool, GPU pool, quota, lease, health check, log stream, metric stream,
  cost record, provider connector, or migration plan.
- `VirtualMachineWorkload`: a VM managed as a Hypervisor workload primitive. It is
  not automatically a Hypervisor runtime node unless a Hypervisor Daemon profile
  is installed, enrolled, and receipted.
- `ContainerWorkload`: a container managed as a Hypervisor workload primitive under
  daemon/provider policy. Containers do not bypass wallet.network authority,
  Agentgres receipt admission, or cTEE mount rules.
- `MicroVMWorkload`: a microVM managed as a Hypervisor workload primitive for
  stronger workload isolation or reproducibility under daemon/provider policy.
- `WASMWorkload`: a WASM module or workload managed as a Hypervisor workload
  primitive, commonly used for portable step/module execution under daemon
  routing.
- `ImageRef`: Hypervisor-visible image identity or image artifact ref for VM,
  container, microVM, WASM, HypervisorOS, or model-server deployment.
- `VolumeRef`: Hypervisor-visible volume identity or volume artifact/storage ref.
  Volume availability is not payload meaning; Agentgres artifact refs and
  receipts govern meaning and restore validity.
- `NetworkPolicy`: Hypervisor-visible ingress, egress, firewall, routing, and
  private-network posture. Network policy does not grant authority by itself.
- `SnapshotRef`: Hypervisor-visible snapshot identity for infrastructure restore
  flows. It is not restore validity without Agentgres archive refs, state roots,
  and receipts where the snapshot affects canonical state.
- `MigrationPlan`: Hypervisor-visible plan for moving workloads, nodes, volumes,
  images, private workspaces, model servers, or provider posture between
  VMware, Proxmox, KubeVirt, Nutanix, Kubernetes, HypervisorOS, cloud, DePIN,
  and customer targets.
- `GpuPool`: Hypervisor-visible accelerator pool with provider, node, utilization,
  model-route, placement, cost, lease, authority, and cTEE posture.
- `ProviderConnector`: a declared connector for cloud, DePIN, storage,
  Kubernetes, KubeVirt, VMware, Proxmox, Nutanix, HypervisorOS, or customer
  environments. It may execute provider API actions only through approved daemon
  or provider-connector boundaries with authority and receipts.
- `HypervisorPlacementDecision`: a Hypervisor projection or canonical object, depending
  on risk, that records why a workload, private workspace, model mount, worker,
  service, or runtime assignment should land on a node/provider. It cannot
  bypass wallet.network, daemon execution, cTEE custody, or Agentgres admission.
- `HypervisorProviderIntegration`: a direct Hypervisor integration with a
  provider or inventory source that can run, store, network, attest, or host
  autonomous work. Examples include local machines, customer clouds,
  hyperscalers, DePIN compute markets, decentralized storage networks,
  confidential-compute providers, enterprise clusters, cloud GPU providers,
  provider-specific markets, and user-specified routes.
- `CloudRoute`: the Hypervisor object for routing a workload to compute,
  storage, GPU, network, confidential compute, DePIN, customer cloud, local, or
  provider infrastructure. It binds resource requirements, privacy posture,
  storage requirements, budget, jurisdiction, selected candidate, provider trust
  model, attestation requirements, secret-release policy, wallet policy hash,
  authority refs, cost, risk labels, and receipts.
- `CloudCandidate`: a resource route candidate from direct provider connector,
  local inventory, customer cloud, DePIN market, decentralized storage network,
  cloud GPU provider, hyperscaler, enterprise cluster, or user route. It is not
  authority, execution, storage truth, or privacy proof until selected into an
  approved CloudRoute and executed through the daemon/provider boundary with
  receipts.
- `CloudResourceIntent`: a decentralized.cloud resource request describing the
  desired infrastructure capacity, user placement choice (`run local`, `use my
  infrastructure`, `pick a cloud`, or `let Hypervisor choose`), placement
  source, selection mode, runtime class, resource classes, custody posture,
  privacy requirements, region preferences, budget policy, failover policy,
  support boundary, and evidence refs. It is not authority and cannot execute.
- `CloudResourceCandidate`: a decentralized.cloud resource candidate from a
  resource-intelligence source, direct provider adapter, customer inventory,
  DePIN market, storage network, managed capacity, or user route. It may carry
  provider quote, spend estimate, custody plan, failover plan, reliability,
  region, availability, and interruption-risk evidence. It cannot provision,
  spend, release credentials, expose ingress, claim custody, or restore until
  selected into a Hypervisor-admitted placement and authorized as required.
- `ProviderQuote`: quoted resource capacity, price, availability, expiry,
  provider semantics, and evidence for placement comparison. It is not spend
  authority.
- `CustodyPlan`: a placement-supporting plan for snapshot/archive bytes,
  state-root checks, cTEE/TEE posture, provider trust, encrypted storage, and
  restore evidence. Storage availability does not equal restore validity.
- `FailoverPlan`: candidate alternatives, health thresholds, re-placement
  policy, data movement assumptions, restore material requirements, expected
  downtime, and authority refs required before failover.
- `SpendEstimate`: estimated provider cost, Hypervisor cost, routing-fee
  eligibility, cost owner, billing path, and uncertainty. It is not spend
  authority.
- `HarnessProfile`: a daemon-executed or daemon-mediated step-resolution
  profile/adapter. A selected harness profile resolves a scoped step under
  daemon gates and must produce common boundary objects such as
  `ActionProposal`, `GateResult`, `ExecutionResult`, `NormalizedObservation`,
  receipts, artifact refs, Agentgres refs, and terminal/blocker state. It is
  not a peer runtime, not high-level workflow composition, and not the owner of
  persistent workspace memory.
- `DefaultHarnessProfile`: IOI's reference scaffold/fallback
  `HarnessProfile` for loop-native scoped step resolution. It is useful as a
  template for custom profiles and as the ordinary fallback, but it is not the
  only admissible harness, not a meta-harness above external harnesses, and not
  the Workflow Compositor.
- `GoalKernel` / `GoalMicroharness`: goal-shaped orchestration kernel used by
  ioi.ai and Hypervisor Sessions for one bounded goal or claimed subgoal. It
  turns intent into a durable GoalRun, grounds context, selects or adapts a role
  topology, leases context/resources/authority, delegates bounded work when
  useful, returns generic `WorkResult` / `OutcomeDelta`, verifies through the
  selected VerifierPath, reconciles receipts, and carries continuation state
  across compaction or session boundaries. It is not a super-agent, an
  OutcomeRoom, or a swarm-control UI.
- `GoalRun`: durable coordination record for a goal-shaped unit of work:
  normalized intent, constraints, role topology, context cells, context leases,
  optional room/participant/claim refs, handoffs, orchestration plans, generic
  results, verifier path, receipts, and continuation state. It owns one bounded
  pursue/verify/course-correct loop and may stand alone or participate in an
  OutcomeRoom. It is not a chat transcript or a harness-local memory file.
- `GoalGroundingLoop`: low-level conductor-orientation loop for goal-shaped
  work: receive intent, classify risk, gather grounding, inspect current state,
  derive constraints and acceptance, select topology, lease context, open
  Context Cells only when useful, delegate or execute, monitor, verify, repair
  or escalate, reconcile receipts/memory/skills, and continue or close. It
  optimizes progress per token rather than maximizing agent calls.
- `RoleTopology`: provider-neutral role shape for a GoalRun, such as direct,
  goal-conductor, delegated-build, governed-release, multi-context-review, or
  specialist-mesh. Roles may resolve to any compatible HarnessProfile,
  AgentHarnessAdapter, worker, local model, hosted agent, or future harness.
  Topology may change under policy when evidence, capacity, risk, or the room
  frontier changes; the initial roster is not permanent architecture.
- `LoopNativeExecution`: the execution discipline in which scoped work advances
  by model pass, action proposal, authority/policy gate, execution, result
  normalization, receipt/Agentgres/context update, and model re-entry until
  completion, blocker, budget, verification, or delivery state resolves the
  task. It is the reference behavior of the Default Harness Profile and may be
  adopted by other HarnessProfiles.
- `ContextTopology`: the planning and repair surface that partitions a run into
  context-resolution boundaries such as semantic domain, authority, privacy,
  verification, service step, loop depth, artifact locality, or Agentgres
  domain boundary. It may start as a projection and should become canonical
  only when replay, repartition, or cross-actor routing needs object identity.
- `ContextCell`: durable role context for conductor, implementer, reviewer,
  verifier, operator, specialist, task, service step, or memory-curation work
  under a GoalRun or run. It carries local goal, constraints, authority,
  evidence refs, receipt refs, observations, uncertainty, loop policy, and
  output policy without dumping global context into every actor. It protects
  long-horizon intent from implementation-token churn and receives only scoped
  memory, tool, model, and authority leases.
- `ContextHandoff`: typed packet between Context Cells, such as task brief,
  generic work result, outcome delta, finding, implementation result, blocker,
  diff/test summary, review or verification request, decision request, or
  continuation summary. Agent-to-agent exchange should become a
  ContextHandoff, not unbounded chatter.
- `ContextLease`: scoped context/tool/memory/authority/budget lease issued to a
  Context Cell or HarnessInvocation. It limits which files, docs, memory
  projections, tools, connectors, receipts, and authority scopes a harness may
  use.
- `TaskBriefPayload`: normalized bounded-work payload attached to a
  ContextHandoff. It carries objective, scope, canon refs, constraints,
  do-not-touch rules, acceptance, verification plan, context leases, and output
  contract. Software-specific changed-file/diff/test expectations are a profile,
  not required fields for every kind of work.
- `HarnessInvocation`: daemon-mediated invocation of a selected HarnessProfile
  or AgentHarnessAdapter. The adapter may render prompts or commands internally,
  but the durable contract remains the task brief, context leases, adapter
  events, implementation result, and receipts.
- `HarnessAdapterEvent`: normalized event emitted during a HarnessInvocation,
  such as progress, observation, finding, artifact_created, file_changed,
  patch_created, test_completed, blocker, decision_request, receipt_emitted,
  completed, or failed.
- `ImplementationResultPayload`: normalized result returned from a harness
  invocation for the software-implementation profile. It contains changed
  files, patch refs, test results, blockers, artifacts, receipts, summary, and
  recommended next handoff. It is a profile of generic `WorkResult`, not the
  universal result contract.
- `WorkResult`: generic bounded result returned by a GoalRun, work claim,
  worker, harness, service, research attempt, ontology operation, incident
  response, review, evaluation, or physical mission. It binds result profile,
  outcome class, findings, outcome deltas, artifacts/evidence/receipts,
  blockers, verification, and next action.
- `OutcomeDelta`: proposed change to outcome, frontier, finding, ontology,
  capability, policy, routing prior, service, or domain state. It binds
  preconditions/invariants, expected effect, verifier/acceptance refs, and
  admission state; it is a proposal until the owning domain admits it.
- `OutcomeRoom`: durable shared collaborative-pursuit profile above one or more
  GoalRuns. It binds objective, constraints, acceptance and stop policy, room
  mode, participation/visibility/privacy/contribution policy, hosted or
  federated admission topology, ontology profiles, budget/resources,
  participants, frontier, attempts, findings, verifier challenges, discussion
  projections, contribution lineage, and replay. It is not a runtime,
  marketplace, authority system, or global Agentgres database.
- `OutcomeRoomDiscovery`: policy-bound `room-discovery://...` projection that
  exposes only the objective/category, semantic profiles, eligibility,
  privacy/visibility posture, budget/quote, verifier/settlement posture,
  publication version, and typed join path needed to discover eligible work.
  It never publishes private room context or grants participation.
- `RoomParticipationRequest`: signed `participation-request://...` request from
  a disclosed external party to join a discoverable room with a declared role,
  capability, affiliation, home domain, eligibility evidence, requested
  leases, and accepted policies. Admission or rejection is a separate
  receipted decision; a request carries no ambient authority.
- `ParticipantStateBundle`: policy-filtered `participant-state://...` portable
  bundle for active handoff or exit. It preserves permitted claim,
  contribution, result, finding, evidence, receipt, dispute, and acknowledgement
  refs while recording exclusions/redactions and released claims. It remains
  usable without continued access to the hosted room database.
- `CollaborativeWorkGraph`: the admitted participant/frontier/claim/attempt/
  finding/evaluation graph of an OutcomeRoom. In ioi.ai it renders as a Goal
  Space workstream; in Hypervisor it renders as Mission detail. Boards, chats,
  digests, leaderboards, and replay are projections over this graph. It is not
  an unbounded swarm and not a separate runtime: every participant acts under
  a leased admission, every attempt runs as a bounded GoalRun (whose internal
  parallelism is that run's `adaptive_work_graph`), and shared state changes
  only through admitted, receipted transitions.
- `RoomParticipantLease`: bounded room participation record binding actor,
  operator, home domain, Worker/harness/model/runtime refs, affiliation,
  eligibility evidence, visibility, context/authority/resource/budget leases,
  current claim, heartbeat or wake condition, TTL, and lifecycle state.
  Participation is leased rather than ambient.
- `ResourceOffer`: typed offer of compute, runtime capacity, data access,
  verification capacity, or another resource to a room, with locality, custody,
  trust, price, availability, allocation, fairness, spend, and contribution
  refs. It is a profile over existing resource inventory, not a second market.
- `CapabilityOffer`: typed room advertisement of a Worker, service, specialist,
  tool, connector, or other capability, including semantic eligibility,
  authority/context needs, privacy, cost, quality, latency, and availability.
- `WorkFrontierItem`: claimable question, problem, hypothesis, task, review,
  verification need, synthesis need, or resource need in a room. It binds
  dependencies, required capabilities/context/resources/authority/evidence,
  expected value, uncertainty, priority, duplication/replication policy,
  concurrency, expiry, and stop conditions.
- `WorkClaimLease`: TTL- and heartbeat-bound claim over one frontier item. It
  binds claimant, bounded scope, context/authority/resource/compute/data/budget/
  tool leases, duplicate-work policy, renewal, release, reassignment,
  quarantine, and revocation.
- `Attempt`: durable declared method and hypothesis plus lineage, environment,
  Worker/model/harness/tool/runtime versions, authority, resources/cost,
  positive/negative/inconclusive/invalid/exploit/superseded outcome class,
  result/delta, evidence, reproduction, license/export, verifier, and
  contribution refs. Non-winning attempts may still add accepted information.
- `Finding`: provenance-bearing hypothesis, observation, claim, negative result,
  integrity incident, semantic-mapping claim, causal claim, counterexample, or
  synthesis. It preserves uncertainty, valid and transaction time, supporting
  and contradicting evidence, applicability, supersession, and dispute. Domain
  admission records the assertion; it does not make it universally true.
- `VerifierChallenge`: typed challenge to a metric, rule, verifier, evidence,
  eligibility decision, result, independence claim, collusion posture, exploit,
  or semantic mapping. It binds challenge evidence, adjudication policy,
  affected attempts, rule versions, and re-verification requirements.
- `OutputOwnershipPass`: the final cognitive ownership step in which the
  accountable worker, service engine, or runtime synthesizes output after
  evidence, normalized observations, receipts, artifact refs, verification
  state, blockers, and unresolved uncertainty have been ingested. It may begin
  as completion receipts and terminal events, and promote to an Agentgres object
  when delivery, dispute, replay, or settlement needs require it.
- `PrivateWorkspaceCtee`: IOI's daemon-owned binding of the generic cTEE
  systems pattern for persistent rented GPU Hypervisor Nodes and other
  untrusted remote compute where protected files, folders, PII, credentials,
  strategy logic, and action authority must not be present on the
  provider-controlled node as plaintext by default. Candidate-Lattice Private
  Decoding is the default protected-agency strategy: the rented node generates
  candidates at speed while AlphaSeal, wallet.network policy,
  guardian/client evaluation, or private operators select, deny, declassify, or
  sign. It uses encrypted workspace objects, encrypted patches, redaction,
  secret-sharing, masks, sealed strategy capsules, wallet-controlled
  declassification, and capability exits rather than trusting consumer GPU
  memory.
- `cTEE`: Cryptographic Trusted Execution Envelope. A portable systems pattern
  for private agency on untrusted compute. It is not a hardware TEE claim and
  is not IOI-specific; it is an execution and workspace contract in which
  sensitive state is represented as ciphertext, secret shares, masked tensors,
  committed witnesses, encrypted refs, sealed capsules, or guardian-gated
  outputs. IOI binds this generic pattern through the daemon, wallet.network,
  Agentgres, the Agentgres Artifact Plane, and optional IOI L1 settlement.
- `CandidateLatticePrivateDecoding`: the default cTEE protected-agency
  strategy. The untrusted node expands public/redacted candidate continuations,
  plans, simulations, reports, patches, or trade intents; private state then
  selects, filters, reranks, denies, or declassifies without entering node
  plaintext custody.
- `PlaintextFreeRuntimeMounting`: the daemon/cTEE runtime mount discipline that
  presents private workspaces to untrusted tools, shells, filesystems, model
  servers, and model calls as public content, redacted projections, encrypted
  refs, commitments, private-function handles, declassification requests, and
  capability handles rather than provider-readable plaintext.
- `PlaintextFreeModelMount`: the daemon/cTEE model mount contract that presents
  private workspaces to untrusted model runtimes as public content, redacted
  projections, encrypted refs, commitments, candidate lattices,
  private-function handles, declassification requests, and capability handles.
  It is the model-facing specialization of Plaintext-Free Runtime Mounting.
- `CustodyType`: the cTEE type discipline that declares whether a value may be
  public, redacted, sealed, guardian-only, crypto-operator-only,
  capability-only, or never-remote-plaintext.
- `CustodyProof`: a verifier-facing cTEE object that binds sensitivity labels,
  custody derivation, mount graph, lattice commitments, private-operator
  receipts, declassification receipts, leakage receipts, and state roots.
- `PrivateAgencyTransform`: the cTEE compiler strategy that rewrites a
  protected agent step into public proposal generation plus private selection,
  verification, declassification, or authorization when the task is
  candidate-selection-reducible.
- `CandidateCoverageProfile`: the cTEE scheduler profile that estimates
  proposal redundancy mass, redundancy phase, coverage target, candidate trace
  budget, public token budget, schedule, and fallback route for CLPD/CLE. It
  expresses the coverage frontier: `coverage(m, r) >= 1 - (1-r)^m`. Constant
  redundancy mass means bounded/depth-independent public overgeneration;
  exponential redundancy decay means the runtime should route away from CLPD/CLE.
- `CounterfactualLatticeExecution`: the high-assurance CLPD schedule where a
  rented node expands a committed public candidate lattice before private
  selection feedback. It reduces online branch-selection leakage by spending
  additional public token volume.
- `CounterfactualLatticeReceipt`: the receipt emitted for Counterfactual
  Lattice Execution. It binds lattice commitment, width/depth/token budgets,
  generation rules, padding/dedupe policy, node ref, policy hash, and state
  root.
- `ManagedExecutionMode`: the user-facing execution/privacy selector. Values are
  `Standard` and `Private`. `Standard` means the IOI-managed runtime uses the
  private-native operating substrate by default, including cTEE /
  Plaintext-Free Runtime Mounting, scoped authority, connector vaulting, and
  receipts, while provider-trust model routes may still be allowed with
  disclosure. `Private` means the same private-native substrate plus a
  no-provider-trust model route, using open-weight or user-controlled models
  inside local, BYO private node, customer-boundary/customer-cloud, cTEE, TEE, or
  another custody-proven route. Technical states such as `redacted_api`,
  `provider_trust`, and `unsafe` are execution/admission evidence, not separate
  product modes.
- `GoalExecutionPolicy`: user/policy choice for one leg of Goal Space work:
  `auto`, `pinned`, or `compare`. Auto is eligible 1-of-N routing and may use a
  verified cheap-first cascade; Pinned uses one selected eligible route and
  fails closed unless fallback was authorized; Compare is N-of-N execution
  under a declared verifier/synthesis rule. These are not subscription tiers.
- `ContributorScope`: Goal Space participation selector: `my_workers`,
  `organization`, or `network_open`. It chooses which accountable worker/
  provider domains may participate and never widens data, privacy, retention,
  custody, authority, export, or route-rights policy.
- `ExecutionPrivacyPosture`: the cTEE posture label for a worker, service,
  outcome engine, or harness path. Values include `private_native`,
  `redacted_api`, `provider_trust`, and `unsafe`.
- `PrivateManagedExecutionPosture`: the product/entitlement posture for
  managed private execution where Hypervisor, ioi.ai, aiagent.xyz, or sas.xyz
  provisions or brokers a Private Workspace backed by cTEE, hardware TEE,
  local-only execution, BYO private node, customer-boundary/customer-cloud
  execution, or another approved no-provider-trust route. It may be plan-,
  Work Credit-, enterprise-, or BYO-node-gated when managed compute, protected
  connector processing, encrypted storage, proof, audit/replay, or persistent
  background private work is provided. It is not a connector tax and is not
  proof of privacy without an `ExecutionPrivacyPosture`, custody proof,
  model/API boundary, and receipts.
- `EffectRecoveryClass`: external-effect recovery posture: `replayable`,
  `checkpointable`, `compensatable`, `reconciliation_required`, or
  `non_retryable`. It governs retry after timeout/provider failure and keeps
  environment restore separate from outcome reconciliation.
- `ProviderTrustBoundary`: the boundary crossed when sensitive plaintext is sent
  to a third-party model API or provider service. Contractual no-training,
  retention, or enterprise privacy controls may be valuable, but they are not
  base cTEE no-plaintext-custody unless the provider receives no sensitive
  plaintext or exposes a separately verifiable private-compute interface.
- `CryptographicOperatorPlane`: the internal cTEE routing plane for protected
  subcomputations that must not become node plaintext. It routes private
  scoring, selection, retrieval, and policy checks through FHE, MPC, garbled
  circuits, ORAM, local guardian, or threshold guardian paths. The default
  second logical party is the authenticated authority surface, not a managed
  non-colluding committee.
- `CryptographicOperatorPolicy`: the policy object that declares allowed
  private operator families, fallback order, second-party refs, latency and
  leakage budgets, and receipt requirements for a Private Workspace backed by
  cTEE.
- `PrivateOperatorReceipt`: the receipt emitted for a cTEE private operator
  execution. It binds the operator family, protected input commitments,
  second-party ref, output commitment, leakage profile, policy hash, and the
  claim that no protected plaintext class was materialized on the untrusted
  node.
- `DeterrenceDetectionProfile`: the cTEE attribution and abuse-detection layer
  for high-value private workspaces. It uses synthetic canaries, honeytokens,
  provider-bound watermarks, leak scans, replay detection, and receipts to make
  theft or leakage more attributable. It is not a privacy primitive and does
  not justify mounting protected plaintext on a node.
- `PrivateWorkspaceNode`: a rented or hosted runtime node that runs a
  Hypervisor Daemon and Hypervisor Node shell persistently while protected workspace state
  is stored and processed only through private workspace representations unless
  explicitly declassified.
- `PrivateWorkspaceCapsule`: the task/workspace capsule sent to an untrusted
  rented node. It carries visible public/redacted context, encrypted refs,
  sealed private heads, allowed remote ops, forbidden plaintext classes, leakage
  profile, and required receipts.
- `AlphaSeal`: a sealed private strategy capsule for quantitative strategies or
  similar high-value logic. It binds a public compute trunk, private strategy
  head, leakage profile, policy, wallet authority, and receipts.
- `AutonomyLease`: a wallet.network authority lease that allows a persistent
  node to act while the user is away within bounded policy, without receiving
  durable raw secrets or unrestricted authority.
- `WalletAuthorityCore`: the reusable wallet.network authority pipeline behind
  Wallet, embedded dapp approvals, agents, Hypervisor, CLI prompts, and advanced
  consoles. It evaluates intent, simulation, risk, eligibility, policy,
  approval mode, execution handoff, receipt, and revocation. It is not the full
  Wallet application UI.
- `WalletAuthorityCockpit`: the high-trust wallet.network product shape for
  autonomous agents and autonomous finance. It lets users and organizations see
  agents, active authority, provider credential bindings, budgets, approval
  modes, auth-factor posture, guardian surfaces, key shards, receipts, and
  revocation controls without making the agent a raw credential holder. Routine
  product flows may render the same authority contract as SSO, permissions,
  connected access, approval review, or recovery inside the product being used.
- `WalletPresentationProfile`: a UI profile over the same `WalletAuthorityCore`
  review contract. Canonical profiles are `lite_approval_card`,
  `standard_wallet_review`, `advanced_authority_console`, `cli_prompt`, and
  `mobile_approval_sheet`.
- `AuthFactor`: a wallet.network account credential or factor such as Google,
  GitHub, email/OIDC, enterprise SSO, Web3 wallet, passkey, or TOTP. It can help
  authenticate account access or step-up posture, but it is not an authority
  grant and does not by itself convey agent power.
- `GuardianSurface`: a high-assurance wallet.network surface such as an enrolled
  mobile approver, passkey device, hardware key, local CLI signer, trusted
  wallet/Hypervisor app, or enterprise approval surface. It must render exact
  action details and bind the request hash before approving high-risk authority.
- `KeyShard`: actual MPC, threshold, hardware-backed, recovery, or organization
  quorum key material. The term "shard" is reserved for cryptographic or
  threshold authority, not ordinary provider login.
- `ProviderCredentialBinding`: a wallet.network-managed OAuth refresh token, API
  key, wallet credential, model-provider key, cloud role, or connector
  credential. It is brokered through policy and grants; agents do not receive the
  raw binding by default.
- `WalletAuthorityClient`: a CLI, MCP, SDK, mobile, web, embedded Hypervisor, or
  enterprise authority service session over wallet.network. It can request,
  inspect, approve, deny, revoke, or receipt authority only through the same
  policy pipeline and cannot bypass step-up or export secrets.
- `WalletMCP`: an agent-facing wallet.network authority request and receipt
  surface. It may expose authority-request, capability-check, approval-request,
  payment-request, receipt-list, and revoke-request tools, but must not expose
  raw secrets, provider tokens, raw signing, limit widening, guardian enrollment,
  or step-up bypass.
- `WalletCLI`: a local wallet.network operator and signer surface for sign-in,
  factor linking, guardian enrollment, approval/denial, grant inspection,
  revocation, secret-brokerage requests, and receipt export. It is a client of
  wallet.network authority, not a separate authority source.
- `ApprovalMode`: the policy-derived execution approval posture for an
  authority review. Values include `one_shot_review`, `session_envelope`,
  `batch_review`, `silent_within_policy`, `after_the_fact_receipt`,
  `step_up_review`, and `denied`.
- `RiskCoverageState`: the assessment coverage state attached to a risk or
  eligibility label. Values include `Assessed`, `Unknown`, `Unassessed`,
  `Stale`, `Partially Covered`, and `Conflicting Sources`. Absence of a risk
  label is never safety.
- `CandidateEvidence`: evidence metadata attached to route, venue, market,
  provider, connector, app, or workload candidates. It binds candidate id,
  source, adapter id, observed time, expiry, coverage state, evidence refs,
  risk labels, eligibility labels, and claims. It is not authority; it makes
  candidate provenance inspectable before Wallet, Hypervisor, or policy can
  approve a consequential action.
- `CapabilityLease`: a scoped, expiring wallet.network lease that lets an app,
  agent, service, or runtime exercise a capability such as `scope:gmail.send`,
  `scope:broker.place_order`, or `scope:cloud.deploy` without receiving
  long-lived credentials or root authority by default.
- `WalletExchange`: the source-agnostic Wallet product surface for exchanges.
  wallet.network owns exchange authority, risk disclosure, policy evaluation,
  signing or denial, revocation, and receipts; the Wallet product is the
  high-trust cockpit, while embedded products may present narrower approval
  cards over the same contract. Route sources only produce candidates.
- `WalletTrade`: the advanced Wallet product surface for exposure management,
  including spot orders, perps, prediction markets, event contracts, leverage,
  collateral, margin, liquidation, funding, resolution, and position lifecycle.
  wallet.network owns trade authority, risk disclosure, policy evaluation,
  signing or denial, revocation, and receipts; the Wallet product is the
  high-trust cockpit, while embedded products may present narrower approval
  cards over the same contract. Trading route sources and venues only produce
  candidates or execute approved intents.
- `ExchangeIntent`: the semantic wallet object above raw transaction calldata.
  It binds route, calldata commitments, slippage, simulation hash, policy hash,
  grant/lease, revocation epoch, economics, risk labels, and exact `TxIntent`
  records before any exchange can be approved or signed.
- `IOI / ioi.ai`: the primary public umbrella and account/control-plane front
  door for the IOI product family. This is a brand/distribution boundary, not a
  runtime ownership boundary: Hypervisor still executes, wallet.network still
  authorizes, Agentgres still records truth, and `decentralized.*` remains the
  protocol namespace for candidate intelligence.
- `RouteCandidate`: a proposed route from decentralized.exchange, direct pool
  adapters, DEX routers, bridge routers, solvers, quote APIs, RFQ systems, or
  user-specified paths. It is not authority and cannot execute until selected
  into an approved `ExchangeIntent`.
- `decentralized.exchange`: a preferred first-party route-intelligence engine
  for asset conversion. Wallet and other clients consume it through API/RPC/SDK
  boundaries for route candidates, adapter registry data, route-candidate
  receipts, and comparison views; it does not own Wallet exchange authority,
  liquidity, execution, exchange truth, or settlement.
- `decentralized.trade`: a preferred first-party venue, market, and
  exposure-intelligence engine. Wallet and other clients consume it through
  API/RPC/SDK boundaries for venue adapters, order-ticket normalization, market
  discovery, prediction-market discovery, event-market and resolution-rule
  display, position/risk display, margin calculations, strategy templates,
  paper venues, venue comparison, and trade-candidate receipts; it does not own
  user authority, custody, final approval, venue execution, market resolution,
  user positions, policy, or settlement truth.
- `decentralized.cloud`: a preferred first-party resource-intelligence engine
  for infrastructure capacity. Hypervisor, wallet.network, ioi.ai, agents, and
  clients may consume it through API/RPC/SDK boundaries for cloud resource
  candidates, provider quotes, resource-liquidity discovery, custody plans,
  failover plans, spend estimates, adapter registry metadata, reliability
  evidence, cloud-picker comparison, and optimized-placement suggestions; it
  does not own provider accounts, credentials, spend authority, VM lifecycle,
  restore truth, storage custody, Hypervisor execution, or settlement.
- `TradeIntent`: the semantic wallet object above raw venue order or calldata.
  It binds venue, market, side, collateral, leverage, margin mode, order type,
  liquidation/funding assumptions, max-loss policy, simulation, risk labels,
  grants/leases, revocation epoch, and exact venue/order/TxIntent records
  before advanced trading can be approved or signed.
- `PositionReceipt`: the wallet receipt that records position state, risk, and
  policy status at meaningful transitions or checkpoints, including venue,
  market, side, size, collateral, leverage, margin mode, entry/mark/liquidation
  prices, funding, PnL, close conditions, and policy status.
- `PredictionIntent`: the semantic wallet object for prediction markets and
  event contracts. It binds venue, market question, outcome, side, price limit,
  shares, max loss, max payout, resolution source, market rules, liquidity,
  policy hash, grants/leases, revocation epoch, and risk labels before event
  exposure can be approved or signed.
- `PredictionReceipt`: the wallet receipt that records event-market order,
  risk, policy, resolution source, market rules, max loss/payout, execution,
  settlement, dispute, or resolution transitions.
- `AssetExposureRecord`: a wallet.network risk record over an account or asset,
  including cryptographic regime, public-key exposure, bridge/admin/oracle
  dependencies, approval exposure, agent-access exposure, protection level,
  risk labels, and recommended protection actions.
- `ProtectionAction`: a wallet action that turns risk into a receipted change,
  such as revoking approval, reducing allowance, moving assets to a fresh or
  policy-stronger account, isolating agent execution funds, freezing grants, or
  requiring step-up for exposed routes.
- `ApprovalInboxItem`: a pending wallet authority decision. It must show
  initiator, action, authority risk class, risk labels, eligibility labels,
  coverage states, affected assets/secrets/data/workloads, destination, policy
  diff, policy explanation, simulation result, candidate evidence, expiry,
  allowed approval modes, presentation profile, and deny/edit/approve actions.
- `WalletReceipt`: a user-facing and machine-verifiable receipt for wallet
  actions such as sends, receives, exchanges, approvals, delegations,
  revocations, agent actions, step-up, secret execution, risk events,
  protection actions, and policy changes.
- `AccessPointBinding`: a wallet.network binding for low-assurance access
  points such as SMS, email, chat apps, voice bridges, or webhooks. These
  channels may notify, wake, pause, steer, or initiate preapproved low-risk
  work, but they are not guardian surfaces and cannot decrypt, declassify, hold
  grants, release secrets, or authorize high-risk actions without step-up.
- `StepUpChallenge`: a short-lived, single-use challenge pointer sent through a
  low-assurance access point. It routes the user into wallet.network,
  Hypervisor, an enrolled guardian device, passkey, enterprise IdP, local app,
  CLI signer, or another high-assurance authority surface. It is not a grant.
- `DeclassificationGate`: the policy and authority boundary where protected
  outputs become visible or actionable. It emits a receipt and routes external
  effects through wallet.network capability exits.
- `PrivateUserAppStateRef`: an Agentgres-governed private user/app state ref
  for encrypted profile metadata, preferences, service intake payloads,
  workspace snapshots, non-public app outputs, managed-instance metadata, or
  meaningful local app checkpoints. Storage backends hold encrypted bytes;
  authority providers and local/domain policy control
  viewing/decryption/mutation authority, with wallet.network mandatory for
  portable delegated authority, secrets, decryption leases, external effects,
  or high-risk approval; IOI L1 stores only selected
  public/economic/cross-domain commitments.
- `AgentgresArtifactRefPlane`: the Agentgres-governed reference, lifecycle,
  policy/authority linkage, receipt, replay/import, archive/restore, and
  state-root validity layer for payload bytes. It owns `ArtifactRef`,
  `PayloadRef`, `EvidenceBundle`, `DeliveryBundle` artifact linkage, and
  `AgentStateArchive` refs; storage backends hold the bytes.
- `ArtifactAvailabilityIncident`: the Agentgres-admitted incident object for
  missing, unavailable, corrupt, stale, undecryptable, expired, or
  policy-incompatible artifact payloads. It binds the affected refs, expected
  and observed commitments, backend evidence, lifecycle state, repair policy,
  repair receipts, replacement payload refs, and Agentgres operations.
- `ArtifactRepairReceipt`: the receipt proving an attempted or completed repair
  for an artifact availability incident. It records the repair action,
  verified commitments, decryptability or restore-validity checks, replacement
  refs, policy hash, and Agentgres operation refs. It does not make storage
  backends authoritative.
- `ServiceCompositionReceiptBundle`: the receipt-bundle profile for composed
  service deliveries. It binds composition graph refs, routing receipts,
  contribution receipts, verifier refs, policy receipts, private-data posture,
  dispute evidence refs, Agentgres operation refs, and state roots so nested
  workers, providers, verifiers, and private workspace posture are attributable
  without making sas.xyz a runtime, wallet, storage backend, or hidden
  contribution oracle.
- `StorageBackend`: a payload byte store below Agentgres-governed artifact refs,
  such as local disk, S3/object stores, Filecoin, CAS/IPFS, provider blob
  stores, customer VPC blob stores, or storage engines used as payload engines.
  A storage backend is not an authority layer; availability failures become
  `ArtifactAvailabilityIncident` records when admitted work depends on them.
- `FilecoinCASBackend`: a content-addressed storage backend profile for payload
  availability. It may hold packages, evidence, traces, checkpoints, delivery
  payloads, datasets, and sealed archive bytes, but Agentgres owns their
  meaning/validity and authority providers control authority/decryption, with
  wallet.network mandatory when portable delegated authority, secret custody,
  or decryption leases are required.
- `CanonImplementationMatrix`: the meta index that maps architecture concepts
  to canonical owner docs, current durable forms, object/event/receipt/projection
  status, code anchors, and conformance hooks. It is a build map, not a
  competing source of doctrine.
- `CanonReadabilityAudit`: the meta workplan for keeping architecture docs
  enterable, terminology-clean, and implementation-oriented without weakening
  precision.
- `GovernedAutonomousSystemChain`: a system-local execution chain with state,
  policy, service modules, proposals, receipts, state roots, and governed
  upgrades. It is "L1-like" in the local state-machine sense, but it is not
  necessarily a public blockchain, global validator network, or IOI L1.
- `IntelligentExecutionNode`: a product-facing agent or worker-backed node
  inside a governed autonomous-system chain. It may reason, plan, diagnose,
  route work, and propose upgrades, but consequential transitions must pass the
  deterministic authority boundary.
- `HypervisorCore`: the shared Hypervisor runtime/control substrate used by
  first-class clients and application surfaces. Its execution owner is the
  Hypervisor Daemon. It coordinates sessions, adapter targets, daemon APIs,
  receipts/replay projections, policy admission hooks, wallet.network
  authority gateway integration, Agentgres admission/projection bridges, cTEE
  posture, and provider integration surfaces. It is not a peer runtime beside
  the daemon and not a replacement for wallet.network or Agentgres.
- `HypervisorClient`: a first-class client over Hypervisor Core, such as
  Hypervisor App, Hypervisor Web, Hypervisor CLI/headless, SDK, ADK, or embedded
  clients. Clients request, inspect, steer, approve, and render; they do not
  own runtime truth.
- `HypervisorApp`: the native desktop client over Hypervisor Core. It may host
  the application suite — Studio (whose agent lens absorbs the former Agent
  Studio), Automations, Ontology, Data, Governance, Missions, Provenance
  (the former Work Ledger card), Evaluations, Improvement, Foundry,
  Marketplace, Workbench, Developer Console — plus the Environments and
  Operations substrate lane, generated domain apps, the named HypervisorOS horizon entry (embodied systems lane; named only),
  and other application surfaces.
- `HypervisorWeb`: the browser/team/remote client over Hypervisor Core. It may
  host web/operator/team versions of the same application surfaces while using
  the same daemon, authority, Agentgres, session, receipt, and adapter
  contracts.
- `HypervisorCliHeadless`: the terminal, scripting, CI, node-ops, and headless
  operator client over Hypervisor Core. It can render plans, controls, traces,
  approvals, receipts, Environments projections, and node operations,
  but it does not own execution semantics.
- `HypervisorTui`: an optional interactive presentation of the
  HypervisorCliHeadless client. It is not a separate first-class client lane and
  must not maintain hidden runtime controls outside daemon/domain APIs.
- `HypervisorHome`: the default command and resume surface in the Hypervisor
  shell. It can start a New Session, resume recent work, surface approvals,
  route into Projects, Automations, Applications, Sessions, receipts, and
  replay, or draft a reviewed handoff. It is not a durable automation owner,
  ioi.ai replacement, or default deploy-as-service funnel.
- `HypervisorApplications`: the catalog, launcher, and vertical surface layer
  inside Hypervisor. Applications can expose first-party, organization-built,
  generated, marketplace, or domain-specific surfaces over Hypervisor Core.
  Applications may create, inspect, modify, or govern Projects, Automations,
  Sessions, agents, workers, models, environments, ODK descriptors, Domain
  Apps, developer integrations, governance, operations, evidence, artifacts,
  or other domain objects, but they are not separate runtimes, authority
  owners, or Agentgres truth sources.
- `HypervisorApplicationSurface`: a major product surface over Hypervisor Core,
  such as Studio, Automations, Ontology, Data, Governance, Missions,
  Provenance, Evaluations, Improvement, Foundry, Marketplace, Workbench,
  Developer Console, the Environments and Operations substrate lane, or
  the named HypervisorOS horizon entry (embodied systems lane; named only). Provider/environment posture may appear
  through the Applications catalog, Open Application, session, project,
  provider, org/admin, or operator-console views, not through a standalone
  provider-management product. Application surfaces are not separate apps with
  separate runtime truth.
- `HypervisorSurfaceAlias`: a legacy or architectural-family label that maps to
  a preferred product surface name. `Providers / Environments` maps to
  Environments; `Data / Knowledge`, `Data Studio`, `Ontology Studio`,
  `Workshop`, and `Domain Blueprints` map to the Ontology and Data
  applications (ODK remains the developer kit beneath them, not a surface
  name); `Agent Studio` maps to Studio's agent lens; `Analyst` maps to
  generated domain apps; `Connections`, `Connectors / Tools / MCP`, and
  `Developer & Integrations` map to Developer Console;
  `Authority / Govern`, `Governance Center`, `Change Plane`, and
  `Release Controls` map to Governance; `Operate / Monitoring`,
  `Operations Center`, and `Resource Management` map to Operations;
  `Receipts / Replay`, `Proof Explorer`, and `Work Ledger` map to Provenance;
  `Patterns / Examples / Training` and `Learning Center` map to enablement
  facets in Home, Applications, Marketplace, Foundry, Ontology, Data, and
  onboarding;
  `Outcome Services / Delivery` maps to the Marketplace declared outcome
  service facet. Aliases are not separate final product apps.
- `HypervisorPatternsExamplesTraining`: the role-guided recipe and enablement
  facet inside Hypervisor. It turns role tracks, speedruns,
  solution diagrams, examples, starter automations, data recipes, ontology
  packs, eval packs, and package templates into governed sessions,
  automations, Foundry jobs, domain apps, receipts, replay, improvement, and
  marketplace paths. It is not passive documentation, a runtime owner, an
  authority layer, or proof of production readiness by itself.
- `HypervisorWorkbench`: the code, systems, workspace, editor, terminal,
  browser, workflow, and debugging surface over Hypervisor Core. It replaces
  one editor shell as the live product term for the code-oriented Hypervisor
  experience.
- `HypervisorAutomations`: the durable workflow, trigger, schedule, webhook,
  approval-flow, queue-worker, service/API, and background-mission surface over
  Hypervisor Core and the Workflow Compositor. It owns product-level
  AutomationSpec projections and run views, but not execution semantics,
  wallet.network authority, Agentgres truth, or the selected harness loop.
- `HypervisorCanvas`: the visual builder/editor for graph-shaped work inside
  Automations, Workbench, or Foundry. It may edit and display nodes, edges,
  typed step contracts, approvals, privacy posture, and receipt projections,
  but it is not a runtime owner, automation truth source, or authority plane.
- `HypervisorSession`: a live governed workspace, run, or control context
  managed through Hypervisor Core. Examples include local workspaces, remote VM
  workspaces, browser sandboxes, hosted workers, HypervisorOS nodes, terminal
  sessions, editor sessions, computer-use sessions, Foundry/eval/training
  sessions, provider management sessions, and environment management sessions.
- `HypervisorProject`: stable project/workspace identity under Hypervisor
  Core. It binds repository/context roots, default policies, persistence
  defaults, adapter preferences, and Agentgres domain links. It is not a
  product UI and not canonical runtime truth by itself.
- `HypervisorMission`: background/manual/scheduled/webhook/event-triggered
  autonomous work with trigger policy, review contract, output contract,
  authority requirements, and receipts. It is not a hidden interactive editor
  session.
- `HypervisorAutomationSpec`: durable product object for saved workflows,
  service recipes, schedules, triggers, approval flows, and background work. It
  binds a Workflow Compositor graph contract, trigger/review/output contracts,
  harness selection hints, authority refs, receipt policy, Agentgres refs, and
  version state. It is not a chat transcript or Canvas layout.
- `HypervisorAutomationRun`: run/session projection for one execution of an
  AutomationSpec. It binds session refs, trigger refs, daemon refs, Agentgres
  operation refs, receipt refs, artifact refs, and terminal status.
- `HypervisorWorkQueue`: intake and ordering object for delegated agent work
  inside Hypervisor. It may represent one-off handoffs, automation runs,
  review queues, background missions, service requests, or custom queues. It
  is product/work routing state, not an agent brain.
- `HypervisorWorkItem`: normalized work request queued for governed execution.
  It binds source kind, original request, project/code context, desired
  delivery, review contract, authority scopes, and status. It is distinct from
  a chat message and distinct from an AutomationSpec.
- `HypervisorWorkRun`: one execution attempt of a `HypervisorWorkItem` inside
  a governed session/environment. It binds selected harness or agent adapter,
  model and reasoning configuration, desired/current phase, activity,
  conversation, transcript, logs, support bundle, connector/MCP status, usage,
  outputs, review state, receipts, and Agentgres operation refs.
- `HypervisorWorkRunConversationProjection`: read model for a WorkRun's
  conversation history, live stream, blobs, and human/reviewer comments. It is
  a projection over daemon/admitted work input, not the private state of an
  agent service.
- `HypervisorWorkRunIntegrationStatus`: per-run connector, tool, or MCP status
  such as connected, degraded, failed, auth required, policy blocked, or
  revoked. It prevents missing credentials from being hidden inside the agent
  loop.
- `HypervisorWorkRunReviewState`: review status for a WorkRun, including
  waiting-for-review, changes-requested, approved, rejected, superseded, and
  delivery refs such as pull requests, artifacts, or deployments.
- `GoalSpace`: ioi.ai's durable product container for one pursued outcome. It
  binds goal/conductor state, policy, memory, budget, receipts, replay,
  collaboration, contributor scope, and user-facing ownership. A simple request
  may remain one direct GoalRun; persistent collective pursuit projects an
  OutcomeRoom/CollaborativeWorkGraph through this same product container.
- `GoalSpaceSubscription`: account/entitlement projection for the conductor,
  ordinary support, and a bounded grant of non-transferable Work Credits.
  Managed-work overage/top-up is explicit; independent Network/Open labor uses
  a separate `NetworkGoalBudget`. It is not pooled resale of provider seat
  limits.
- `NetworkGoalBudget`: separately funded, visible `goal-budget://...` spend
  boundary for independent Network/Open workers, verifiers, services, resource
  providers, challenges, and settlement. It may be funded as a prepaid cap,
  bounty, procurement cap, or service-order budget. It is not ordinary Goal
  Space Work Credits, a transferable token, or pooled resale of provider seat
  limits.
- `IoiAiGoal`: user-facing goal object for chat.ioi.ai / ioi.ai. It carries
  goal text, constraints, privacy posture, authority context, project refs, and
  terminal state.
- `IoiAiOutcomePlan`: ioi.ai coordination plan for a goal. It selects the
  materialization shape, such as single path, multi-model answer, multi-harness
  attempt, software search, computer-use task, automation handoff, Foundry job,
  wallet action, or marketplace handoff. Material plans should bind an
  orchestration policy, constraint envelope, verifier path, and decision
  receipt refs when the choice affects privacy, authority, cost, latency,
  quality, or attribution.
- `OrchestrationPolicy`: versioned outcome-conductor plan-selection policy. It
  may use rules, benchmark priors, online quality evidence, user/org
  preferences, contextual bandit updates, or Foundry conductor advisors, but it
  is not authority and does not execute work.
- `OrchestrationConstraintEnvelope`: explicit plan-selection envelope for goal
  class, privacy posture, provider-trust posture, authority posture, budget,
  latency, verification strength, data-use eligibility, and user/org
  preferences. It is not a wallet grant.
- `VerifierPath`: configured verification shape for a plan, run, worker, route,
  or package. It may include deterministic checks, tests, verifier workers,
  model judges, human review, benchmark gates, or regulated review. For ordinary
  goal work, the conductor may satisfy the VerifierPath through deterministic
  checks; independent verifier harnesses are policy-triggered escalation paths.
- `OrchestrationDecisionReceipt`: receipt recording the candidate plans,
  constraint envelope, orchestration policy, selected plan, selected model
  routes, harnesses, workers, verifier paths, evidence basis, and reason codes.
  It is distinct from a MoW `RoutingDecisionReceipt`.
- `IoiAiAttemptSummary`: comparable evidence projection for one model, worker,
  harness, connector, service, or session attempt. It binds observations,
  artifacts, receipts, verifier refs, summary text, and terminal status.
- `GoalAppropriateSearchPolicy`: policy used by ioi.ai to decide whether a goal
  should stay lightweight or materialize multiple models, harnesses, workers,
  connectors, sessions, branches, or verifier lanes.
- `CollaborativeMission`: a durable Hypervisor Automations mission class that
  may be created from an ioi.ai Goal Space/OutcomeRoom handoff. Mission detail
  and Goal Space render the same underlying participant/frontier/claim/attempt/
  finding/evaluation graph through different product lenses. It is not a group
  chat, separate swarm runtime, or unbounded process tree.
- `StockfishStyleCodingSearch`: product shorthand for code and computer-use
  search over branches, snapshots, and sessions. Tests, static analysis, visual
  verification, runtime traces, benchmarks, and policy checks score attempts
  before promotion when the goal calls for that shape.
- `HypervisorAdapterTarget`: an editor, terminal, browser, VM, container, local
  OS surface, hosted worker, HypervisorOS node, or external tool that a
  Hypervisor Session can project into or mediate. VS Code, Cursor, Windsurf,
  JetBrains, browser IDEs, Git, terminal/tmux, browser automation, local apps,
  cloud VMs, and HypervisorOS nodes are adapter targets, not Hypervisor's
  product identity.
- `AdapterConnectionProfile`: implementable contract for connecting a
  Hypervisor Session to an adapter target. It declares connection mode, launch
  mode, required local/remote components, supported features, policy coverage,
  and known limitations.
- `AgentHarnessAdapter`: a Hypervisor adapter family for external CLI or hosted
  agent harnesses such as Codex, Claude Code, Grok Build, OpenHands, Aider,
  Cursor/Windsurf agent loops, shell/tmux agent loops, CI agents, and hosted
  coding agents. These harnesses may propose work through Hypervisor Core and
  the Hypervisor Daemon, but they are not Hypervisor clients and not runtime
  truth.
- `HypervisorHarnessSelectionOption`: New Session selection object for either
  a selected `HarnessProfile` or a selected `AgentHarnessAdapter`. It is the
  app/API-facing object that keeps Default Harness Profile as IOI's reference
  scaffold/fallback while exposing external harnesses as daemon-mediated
  proposal sources.
- `HypervisorSessionModelConfiguration`: model configuration selected for a
  Hypervisor Session. It may point at a local OpenAI-compatible model mount,
  an adapter/provider-trust path, or a deterministic no-model path. The default
  first-session local route can be used by Codex OSS, example Claude Code
  harness bring-up, and DeepSeek TUI without requiring provider API auth.
- `HarnessSessionBinding`: launch-time object that binds the selected harness,
  model configuration, model route policy, workspace mount policy, privacy
  posture, authority scopes, receipt policy, example root when applicable, and
  daemon-gate requirement to a `HypervisorSession`. A launched session without
  this binding is an invalid loose UI projection.
- `HarnessSessionBindingAdmission`: daemon-admitted launch gate for a
  `HarnessSessionBinding`. It makes a local-first harness/model binding
  eligible for daemon launch planning, blocks external harness cTEE custody and
  provider-trust shortcuts until explicit leases exist, and prevents
  Codex/Claude/DeepSeek-style adapters from claiming runtime truth.
- `HarnessSessionLaunch`: daemon-authored launch-ready contract for an admitted
  `HarnessSessionBinding`. The first host-dev contract is Codex OSS over local
  Ollama/Qwen, using `codex --oss --local-provider ollama` with workspace-write
  sandboxing, on-request approvals, no durable secret release, and the
  Hypervisor local OpenAI-compatible model mount. Example Claude Code and
  DeepSeek TUI may bind to the same local model configuration, but are not
  launch-ready until their own daemon-owned launch contracts exist.
- `HarnessSessionSpawn`: daemon-authored spawn-ready contract for an admitted
  `HarnessSessionLaunch`. It resolves argv, model name, workspace root,
  terminal attach contract, PTY transport, process custody posture, receipt
  refs, and Agentgres operation refs before a client terminal may attach. The
  first spawn lane is Codex OSS over the local Ollama/Qwen mount through the
  Hypervisor client terminal adapter; the client supplies PTY transport but
  does not become runtime truth.
- `HarnessAdapterReceipt`: receipt envelope for an external harness run. It
  binds selection ref, execution lane, model route ref when present, workspace
  mount policy, authority scope refs, privacy posture ref, Agentgres operation
  refs, artifact refs, and daemon-runtime truth source.
- `HarnessContainerLanePlan`: daemon-planned Docker/Podman execution contract
  for a containerized `AgentHarnessAdapter`. It binds the selected adapter,
  runtime, container image ref, command argv hash, public/redacted mounts,
  network policy, env policy ref, authority scope refs, and privacy posture.
  It is a lane plan, not execution proof and not a privacy primitive.
- `HarnessContainerLaneReceipt`: receipt envelope for a container harness lane.
  It copies the planned image, argv hash, mounts, network policy, env policy,
  authority scope refs, and privacy posture, then adds explicit exit status,
  Agentgres operation refs, artifact refs, and daemon-runtime truth source.
  By default it must not represent plaintext workspace, cTEE private workspace,
  raw host paths, host container sockets, plaintext env maps, or secret argv as
  safe.
- `AgentHarnessEnvironmentOpsProfile`: stable environment-operations contract
  for external harnesses. It extends `HypervisorEnvironmentOpsProfile` for
  harness-specific proposal-source behavior and keeps external harnesses out of
  runtime truth.
- `HypervisorEnvironmentClass`: selectable managed environment shape behind a
  Hypervisor Session, such as local workspace, remote VM, container, microVM,
  browser sandbox, hosted worker, HypervisorOS node, provider workspace,
  customer cloud, or enterprise cluster. It declares resource shape, provider
  posture, persistence modes, privacy posture, attestation policy, and cost
  policy.
- `HypervisorEnvironmentOpsProfile`: daemon/Core lifecycle and operations
  contract for a managed Hypervisor environment. It covers discovery,
  create/start/stop/mark-active/archive/unarchive/restore/delete, command
  execution, logs, service/task/port operations, SCM auth, cleanup, and receipt
  obligations.
- `HypervisorEnvironmentLifecycleState`: Agentgres/daemon-backed lifecycle
  state for a managed Hypervisor Session environment, including provider state
  evidence, activity refs, archive refs, restore refs, state-root refs, and
  receipts.
- `HypervisorEnvironmentActivitySignal`: observable environment signal such as
  user activity, agent activity, task running, service running, port open, log
  write, file change, network activity, work run active, waiting review, idle
  candidate, idle confirmed, restore required, or policy blocked. It is
  evidence/projection data, not authority.
- `HypervisorSessionAccessLease`: durable authority object for short-lived
  editor, SSH, browser, log, support, port-share, SCM-auth, task-exec, or
  environment-ops access to a Hypervisor Session. `SessionAccessToken` is
  derived token material under this lease, not durable authority.
- `HypervisorEnvironmentService`: daemon-visible service inside a Hypervisor
  environment, such as model server, dev server, database, queue, browser,
  worker, agent service, evaluator, or custom service, with service refs,
  health refs, logs, support posture, and receipts. An agent service is runtime
  posture behind a WorkRun, not durable work truth.
- `HypervisorEnvironmentTask`: daemon-visible task inside a Hypervisor
  environment, such as shell, build, test, eval, benchmark, migration, provider
  action, package install, git operation, pull request, code-review response,
  agent run, archive, restore, or custom task, with WorkRun refs when relevant,
  authority refs, execution results, and receipts.
- `HypervisorEnvironmentPort`: daemon-visible port and exposure posture for a
  Hypervisor environment. Port sharing is a policy and lease event, not a
  harmless preview toggle.
- `HypervisorScmAuthRequirement`: brokered source-control authentication or
  credential requirement for clone, fetch, push, pull request, issue, or
  release actions. Satisfaction may require wallet.network step-up, scoped
  secret release, a lease, and a receipt.
- `SessionAccessToken`: short-lived, audience-bound token for editor, SSH,
  browser, log, support, or environment-ops access to a Hypervisor Session. It
  is derived token material under a `HypervisorSessionAccessLease`, bound to
  expiry and revocation epoch, and receipted.
- `PortExposurePolicy`: policy object declaring which session ports may be
  opened, forwarded, shared, previewed, or externally exposed.
- `BrowserOpenPolicy`: policy object declaring whether browser URLs in a
  session can be auto-opened, proxied, externally shared, recorded, or blocked.
- `SupportBundlePolicy`: policy object declaring what logs, traces, screenshots,
  redacted diffs, environment metadata, and diagnostic files may leave a
  session.
- `HypervisorNode`: the local autonomous-system settlement domain for a user,
  organization, project, or deployment. It composes Hypervisor Core clients and
  application surfaces, Hypervisor Daemon, Agentgres, wallet.network authority
  paths, local registries, receipts, replay, and runtime profiles. It is not
  the Hypervisor App, Hypervisor Web, CLI/headless client, optional TUI view,
  Workbench, Automations, Foundry, or Environments view by itself.
- `LocalSettlementDomain`: a Hypervisor Node domain that locally accepts work,
  proposals, authority outcomes, receipts, interop messages, and state
  transitions for many governed autonomous-system chains. Public economic
  finality still belongs to IOI L1 when required.
- `AIIP`: IOI's RPC-shaped, receipt-native interop protocol for bounded
  autonomous work. It carries task offers, handoffs, authority leases, receipt
  commitments, settlement intents, disputes, reputation queries, and
  cross-system handoff finality across bounded execution domains.
- `BoundedExecutionDomain`: a local, hosted, enterprise, marketplace, robot,
  worker, service, microharness, third-party, or AS-L1 domain that performs
  scoped autonomous work under declared capabilities, policy, authority
  requirements, receipt schemas, runtime boundaries, and settlement behavior.
- `EmbodiedRuntimeDomain`: the live physical-domain runtime record for robot
  fleets, facility systems, drones, vehicle-adjacent systems, IoT actuators, or
  other embodied domains. It binds fleet identity, controller bridges, sensors,
  actuators, world state, telemetry, command queues, policy, and emergency stop
  to the Hypervisor Daemon boundary.
- `RobotControllerBinding`: the binding between an embodied unit and a local or
  edge controller bridge. It declares command endpoints, telemetry streams,
  heartbeat/failsafe policy, authority scopes, sensor/actuator registries, and
  where receipts are emitted.
- `PhysicalCommandQueue`: the daemon-governed queue for movement,
  manipulation, facility-control, and other physical commands. It carries
  preflight, interrupt, concurrency, conflict, stop, and result semantics that a
  generic tool call cannot express.
- `PhysicalReplayBundle`: the synchronized replay bundle for embodied work,
  binding commands, telemetry streams, sensor evidence, actuator receipts,
  incident refs, timeline segments, and proof links.
- `SimToRealPromotionGate`: the promotion gate that separates simulation
  success, hardware/shadow validation, limited live operation, review, rollback,
  and full embodied deployment.
- `PhysicalActionIntent`: the proposed action object for embodied work that can
  affect actuators, physical systems, facilities, vehicles, drones, robots, or
  safety-relevant devices. It must carry `risk_class = physical_action`,
  authority refs, safety policy refs, and expected receipt schemas before the
  daemon can consider execution.
- `PhysicalActionPolicy`: the policy object that declares which physical action
  kinds, scopes, supervision modes, sensor evidence, and emergency-stop
  requirements apply to an embodied worker or domain.
- `SafetyEnvelope`: the bounded physical operating envelope for an actuator or
  embodied worker. It declares allowed and forbidden actions, physical zones,
  limits, preflight checks, stop conditions, sensor requirements, and operator
  contact refs.
- `EmergencyStopAuthority`: the authority object that names who or what can
  halt a physical-action domain, through which trigger channels, with what
  latency expectation, and under which revocation epoch.
- `HumanSupervisionPolicy`: the supervision policy for physical action,
  ranging from autonomous to monitored, human-on-loop, human-in-loop, or manual
  confirmation for each action.
- `SensorEvidenceReceipt`: the receipt that binds the sensor snapshot,
  observation hashes, artifacts, capture time, confidence, and redaction policy
  used to justify or audit a physical action.
- `ActuatorCommandReceipt`: the receipt that binds a physical command hash,
  actuator ref, issuing daemon, authority ref, safety envelope ref, sensor
  evidence receipt refs, and command result.
- `PhysicalActionIncident`: the admitted incident object for safety-envelope
  violations, emergency stops, sensor disagreement, actuator failure,
  supervision failure, policy violation, disputed outcome, or remediation.
- `AIIPEnvelope`: the signed, sequenced packet envelope for AIIP messages. It
  binds sender/receiver systems, channel, profile, policy hash, authority ref,
  payload hash, receipt obligations, settlement terms, and signature.
- `AIIPProfile`: a standard AIIP mode such as local, installed worker,
  marketplace worker, outcome service, autonomous system, or enterprise. The
  profile changes trust boundary, transport, privacy, and settlement depth
  without changing the semantic protocol.
- `AIIPChannel`: a registered or local channel binding two bounded execution
  domains to an AIIP profile, schema/version set, relay/router policy,
  authority posture, privacy posture, and settlement mode.
- `ServiceModule`: a reusable governed capability, code unit, contract,
  workflow component, worker service, adapter, verifier, policy module, or
  economic module that can be invoked by an autonomous-system harness.
- `ModuleInvocation`: one execution of a service module under specific input,
  state root, module version, policy, authority, and receipt obligations.
- `DeterminismBoundary`: the trust boundary where a model, worker, agent,
  adapter, or operator proposal becomes an admitted effect. Models and agents
  may reason or propose; policy and authority providers authorize, and the
  Hypervisor Daemon admits, enforces, executes or mediates, receipts, and fails
  closed at this boundary.
- `IOIAuthorityGateway`: the Hypervisor Daemon sidecar/compatibility profile for
  existing IDEs, CLI agents, hosted agents, browser tools, MCP ecosystems,
  shell wrappers, Git hooks, API proxies, credential brokers, and CI/CD gates.
  It routes proposed actions through daemon policy, authority scopes,
  approvals, receipts, and replay. It is not a separate runtime, not merely a
  VS Code plugin identity, and it must be honest about the mediation limits of
  opaque third-party runtimes.
- `IOIKernelL0` or `L0Substrate`: the reusable IOI kernel substrate for
  instantiating application domains, sovereign execution domains,
  non-intelligent chains/state machines, and intelligent blockchains. It is not
  one live global chain and it is not the CLI.
- `IOIL1`: the public registry, rights, settlement, dispute, sparse-commitment,
  autonomous-system settlement, and governance layer. It may approve canonical
  L0/kernel release roots, but it does not execute the L0 substrate or own
  ordinary repository management.
- `EdgeInTopology`: IOI's topology inversion in which work starts at the local
  or remote runtime edge, becomes operational truth in a domain kernel +
  Agentgres, and settles upward to IOI L1 only when public trust is required.
- `VerifiableBoundedAgency`: IOI's alignment-security thesis that autonomous
  workers may reason, propose, and improve probabilistically, but consequential
  effects cross into reality only through bounded authority, policy, receipts,
  and verification.
- `ExecutionBoundaryAlignment`: the precise claim that IOI aligns autonomous
  action at the effect boundary. It is not a claim that IOI proves every model's
  private cognition, latent goals, or future reasoning are safe.
- `RuntimeNode`: a machine, container, TEE, DePIN node, local process, or
  customer environment running a Hypervisor Daemon profile. Runtime nodes execute
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
  worker has a manifest, accountable operator or owner, policy envelope,
  capability surface, receipt obligations, runtime requirements, contribution
  terms, and settlement identity. A Worker may compose one or more models,
  harnesses, tools, services, and runtime placements without making any of
  those components the accountable labor actor.
- `DigitalWorkerOntology`: the aiagent.xyz base ontology for broad autonomous
  labor. It defines shared worker/package/instance/capability/task/action/
  integration/policy/receipt/evidence/runtime/memory/persistence primitives for
  software workers and becomes embodied work when a vertical pack binds
  physical-action safety objects.
- `VerticalOntologyPack`: a versioned domain extension over
  `DigitalWorkerOntology`. It can define domain objects, action vocabulary,
  integration mappings, risks, policy profiles, receipt schemas, evidence
  requirements, benchmarks, UI projections, forbidden actions, and physical
  safety bindings without forking the daemon, wallet, Agentgres, or settlement
  model.
- `IntegrationSurface`: the class of external environment a worker can observe
  or act within, such as chat/community, game/platform, browser/SaaS,
  developer/code, commerce, finance/trading, local computer-use, enterprise
  VPC, webhook/API, voice/SMS, robotics/physical, embodied humanoid,
  vehicle-adjacent, field service, education, creative/media, or support/ops.
  It is a policy/evidence profile, not an authority grant.
- `Agent`: configurable, buildable product object for an autonomous assistant,
  delegated actor, or user-facing worker experience. Agent records may bind
  mode, model, reasoning effort, speed/service tier, harness, tools/connectors,
  memory, authority, budgets, evals, receipts, runtime compatibility, and
  marketplace/install status. New protocol prose should still use `Worker` when
  referring to the accountable execution actor. When an agent is treated as
  durable system architecture, prefer `IntelligentExecutionNode` or
  `GovernedAutonomousSystemChain` to avoid implying a stateless chatbot.
- `AgentOperatingPlane`: the daemon-owned control plane for configured agents,
  agent/session admission, agent executions, work queues, work items, work
  runs, thread/turn controls, conversation streams, subagents, runner
  reconciliation, usage accounting, and exec/security telemetry. It is not a
  client-local loop and not a second runtime beside the daemon.
- `AgentRecord`: daemon/Agentgres-facing configuration record for a product
  agent. It binds metadata, owner, package/install refs, project/environment
  context, mode defaults, model configuration, HarnessProfile or adapter
  selection, tools/connectors, memory policy, authority posture, budgets,
  evals, receipts, and runtime compatibility.
- `AgentExecution`: one admitted execution of an `AgentRecord` inside a
  session, environment, work run, thread, or automation. It records phase,
  desired phase, current activity, current operation, mode, model
  configuration, usage, waiting interests, outputs, conversation refs,
  transcript refs, support bundle refs, receipts, and Agentgres refs.
- `ModelConfiguration`: product/runtime selection object for model, reasoning
  effort, speed/service tier, fallback policy, custody posture, and route
  eligibility. It may point to one or more `ModelRoute` objects; it is the
  user-facing configuration layer, not the model router itself.
- `ModelRouteRightsContract`: versioned admission contract for one candidate
  model route. It binds commercial posture, access mode, customer-facing and
  OEM/reseller rights, automation and downstream rights, credential principal,
  provider/model terms, endpoint/model versions, provider allowlist, data and
  ZDR posture, region, fallback classes, price limits, required parameters, and
  output-training rights. Missing rights fail closed. A fallback is a semantic
  substitution that must remain eligible and re-enter verification; an
  aggregator such as OpenRouter is only one replaceable procurement adapter.
- `ReasoningEffort`: model/harness control value such as low, medium, high, or
  extra high. Product surfaces should usually show the value under a simple
  `Reasoning` control rather than exposing provider-specific internals.
- `ServiceTier`: latency/throughput posture such as standard or fast. Product
  surfaces may call this `Speed`; runtime receipts and usage records should
  preserve the exact tier that was used.
- `TurnControlInput`: daemon-admitted control input for compact, goal pause,
  goal resume, goal complete, goal clear, goal set, queued-message deletion,
  interrupt, or steer. It is a runtime control, not hidden client state.
- `ManagedWorkerInstance`: a user-, org-, or project-bound initialization of a
  worker package. Product UX may call this an agent instance, but canonical
  state should bind it to a worker manifest, install/license right, runtime
  assignment, persistence profile, authority policy, Agent Wiki / `ioi-memory`
  refs, memory profile, projection policy, archive policy, and subscription or
  entitlement.
- `ManagedWorkerInstanceLifecycle`: the admitted lifecycle for a managed worker
  instance, including install, initialize, grant authority, assign runtime,
  active, idle, zero-to-idle, suspend, payment past due, archive, restore,
  migrate, export, delete, and forget. Payment lapse may remove compute
  entitlement, but it must not silently delete user-owned context.
- `ManagedAgentConsole`: a web projection over a managed worker instance. It
  can show chat, sessions, approvals, receipts, usage, memory summaries,
  runtime status, and archive/restore controls, but it does not execute work,
  hold wallet authority, or own Agentgres truth.
- `AgentWiki`: the user-facing and agent-facing semantic memory surface for
  preferences, procedures, doctrine, route notes, failure lessons, source-backed
  claims, and project knowledge. It may hold draft or local memory, but durable
  behavior-affecting wiki changes become canonical only when admitted through
  Agentgres operations such as `ContextMutation` with policy, authority,
  provenance, and receipts.
- `ioi-memory`: the live product-memory implementation boundary for runtime
  memory, thread checkpoints, core and archival memory, local evidence blobs,
  and enrichment jobs. It is a context-memory plane, not Agentgres and not IOI
  L1.
- `MemoryProfile`: the declared retention, privacy, portability, projection,
  archive, restore, export, and forget posture for Agent Wiki / `ioi-memory`.
  Worker packages may declare supported profiles, but the managed instance owns
  the concrete profile binding.
- `MemoryArchive`: an encrypted restorable memory payload bundle. Agentgres owns
  archive refs, receipts, restore/import truth, and policy linkage; storage
  backends hold bytes; authority providers gate restore/decryption/export when
  required.
- `MemoryProjection`: a policy-filtered view of Agent Wiki / `ioi-memory` for a
  target harness, model route, worker, surface, API, or MCP endpoint. It is the
  portability layer that keeps harness-local memory as cache rather than the
  durable brain.
- `ContextMemoryPlane`: the adjacent memory/retrieval plane that governs what
  agents can know, remember, and retrieve. Agentgres governs which context
  changes are canonical, replayable, portable, shared, policy-relevant, or
  settlement-relevant.
- `PersistentWorkspaceIntelligence`: workspace-, project-, org-, or
  domain-bound skills, Agent Wiki / `ioi-memory` facts, learned tool
  affordances, route preferences, failure lessons, and durable
  behavior-affecting context. It should survive model and harness swaps when
  workspace identity, compatibility, provenance, policy, and authority remain
  valid. It is not owned by the selected model or harness.
- `RuntimeSubscription`: an entitlement or billing object that keeps a managed
  worker instance available by per-invocation use, warm runtime allocation, or
  zero-to-idle restore policy. It does not make aiagent.xyz or ioi.ai the
  execution runtime.
- `WorkCredit`: the broad product usage and budget abstraction for managed
  autonomous work across Hypervisor, ioi.ai, aiagent.xyz, sas.xyz, and related
  first-party product flows. It may meter model, runtime, GPU, connector, MCP,
  storage, replay, Foundry, automation, conductor, worker, verifier, service,
  and audit usage. Work Credits are bounded, non-transferable product budget;
  they are not pooled provider seats, raw model tokens, a tradeable asset, or
  the protocol settlement token. Network/Open contribution budgets remain a
  separate funded lane even when the same Goal Space surface exposes them.
- `VerifiedWorkGraph`: the network-level economic memory assembled from
  WorkRuns, receipts, ContributionReceipts, RoutingDecisionReceipts, benchmark
  and eval outcomes, authority refs, worker/harness/model/tool/provider
  identities, cost/quality evidence, marketplace installs, managed instances,
  service orders, disputes, and selected settlement roots. It is a graph of
  provenance and staged assurance across owner domains, not a single database,
  chain, UI, or assertion that every recorded contribution is verified.
- `AssuranceState`: the ordered evidence/admission posture attached to a
  contribution or interop result: `attested`, `evidenced`, `verified`,
  `accepted`, `adjudicated`, or `settled`. A receipt can support attestation;
  stronger stages require the applicable evidence, verifier, acceptance,
  dispute, or settlement path. Stages must not be collapsed in UI or economics.
- `Model`: a cognition backend mounted or invoked by a worker. Models are not
  the economic actor by themselves. Model routing belongs to the runtime/node
  contract; model weights or provider endpoints are mounted by deployment
  profile and are not part of the Hypervisor Node binary by default.
- `MultiModelExecution`: one accountable Worker or GoalRun invokes or compares
  multiple cognition routes. It increases cognition plurality but does not by
  itself create independent workers, nodes, operators, or economic parties.
- `MultiWorkerExecution`: multiple accountable Workers contribute bounded work
  under typed claims, handoffs, evidence, and contribution lineage. The workers
  may still share one node, operator, or model provider.
- `MultiNodeExecution`: work is placed across multiple runtime nodes or
  settlement domains. It changes placement, custody, availability, and trust
  boundaries, but does not by itself establish independent contributors.
- `MultiPartyCollaboration`: multiple independently governed people,
  organizations, providers, or autonomous-system domains contribute under
  explicit participation, privacy, authority, attribution, dispute, and
  economic terms. It may use multiple models, workers, and nodes, but those
  lower-level pluralities are not substitutes for party independence.
- `ModelDeploymentProfile`: the deployment-specific choice for how a model is
  supplied to a node or runtime: bundled weights, local file, local server,
  BYOK external API, hosted pool, TEE session, DePIN session, or customer VPC.
  Bundled weights are allowed only when declared by profile; they are not the
  architecture default.
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
- `TrainingOrchestrator`: the accountable coordination role for a training run.
  It owns goals, case specs, batch plans, prompt sets, executor mix, gate policy,
  rejects, reports, and worklog while delegating to planner, generator,
  verifier, reviewer, trainer, and evaluator workers.
- `ModelCapacityProfile`: training metadata that describes target worker/model
  size, prompt budget, context budget, tool batch limits, row structure, serving
  posture, cost/latency targets, and recommendations for making a smaller or
  more efficient worker succeed.
- `TrainingBatchPlan`: a bounded plan for one generation, capture, curation, or
  distillation batch. It defines target scope or family, label boundaries, hard
  eval pattern, quota, split policy, executor mix, and acceptance thresholds.
- `RawBatchArchive`: the pre-curation archive of generated or captured rows,
  prompts, caches, provider metadata, token/cost telemetry, and rejected material.
  It is evidence, not accepted training signal.
- `QualityGateReport`: a report binding gate policy, pass/fail decisions,
  rejection reasons, accepted dataset refs, and receipts for a training batch.
- `TrainingCostLedger`: the training-run ledger for provider calls, tokens,
  runtime, spend, accepted/rejected row counts, cost per accepted row, dataset
  yield, and quality lift.
- `DomainOntology`: the semantic model for a domain's entities,
  relationships, events, actions, states, roles, and invariants.
- `OntologyVersion`: immutable version plus compatibility, migration,
  deprecation, and namespace lineage for one ontology or overlay. Canonicality
  is scoped to the owning domain rather than presumed global.
- `OntologyOverlay`: local extension or policy-specific view that preserves its
  base ontology, namespace, version, and provenance lineage.
- `OntologyCrosswalk`: explicit versioned mapping between ontology, object,
  relationship, event, or action versions. It records exactness, loss,
  ambiguity, adapter requirements, policy-bound views, validation, challenge,
  and migration posture rather than silently flattening schemas.
- `SemanticMappingDecision`: challengeable, receipted application of an
  OntologyCrosswalk or adapter to a concrete handoff, query, object, event, or
  action. It preserves source and target versions and does not manufacture
  universal semantic truth.
- `ProvenanceAssertion`: time-, source-, uncertainty-, scope-, evidence-,
  contradiction-, supersession-, and dispute-bearing claim about an
  ontology-bound property or relationship. Agentgres admission proves that a
  domain recorded the assertion; it does not prove the proposition universally.
- `OntologyActionContract`: executable semantic-action contract binding target
  objects and typed input/output to preconditions, postconditions, state
  transition, capabilities, runtime/tool refs, policy and authority scopes,
  risk, preview, idempotency, retry, ambiguous-effect reconciliation,
  compensation, verification, evidence, receipts, and physical-safety posture.
  Ontology semantics never grant execution power on their own.
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
- `SharedBuilderSubstrate`: the shared graph model, typed node contracts,
  schemas, recipe model, daemon execution path, and Agentgres receipt model
  used by Hypervisor application surfaces. It is a UI/workflow substrate, not
  canonical runtime truth by itself.
- `HypervisorFoundry`: the Hypervisor application surface for model catalog,
  model registry, model routes/mounts, tuning, training, evaluation, datasets,
  feature views, experiments, pipelines, endpoints, batch inference, metadata,
  monitoring, executable eval worlds, tool-call audits, trajectory scorecards,
  interactive worlds, gameplay trajectory datasets, scenario curricula,
  world-model candidates, spatial-temporal policy candidates, transfer gates,
  simulation training, robotics worlds, worker/package creation,
  ontology-aware package building, certification-run candidates, and promotion
  proposals. It can project recipes into the standard Workflow Compositor, but
  it is not a separate canvas environment, ioi.ai coordination surface,
  transfer-gate admission owner, physical actuator authority, or runtime.
- `HypervisorProviderEnvironmentView`: default Hypervisor App, Hypervisor Web,
  CLI/headless, optional TUI, or console view for hands-on management of
  attached nodes, providers, persistent workspaces, active
  agents/workers/services, model mounts, cTEE posture, receipts, approvals,
  trace summaries, replay availability, and start/stop/resume/archive/restore
  actions. It requests and displays; it does not own execution, authority,
  Agentgres truth, or storage bytes.
- `ConsoleIoiAiProviderEnvironmentView`: the console.ioi.ai web/org/admin lens
  for accounts, devices, entitlements, node registry, provider integrations,
  provider status, billing, remote access, restore routing, and org policy
  visibility. It is an ioi.ai control-plane view over Hypervisor provider and
  environment posture, not the daemon.
- `WorkflowCompositor`: the high-level directed-work surface over Hypervisor
  Core and the SharedBuilderSubstrate. It owns workflow/service graph shape,
  typed step contracts, dependencies, acceptance criteria, review points,
  delivery contracts, reusable templates, and harness/model/provider/verifier
  selection hints. It does not own execution semantics, wallet authority,
  Agentgres truth, persistent workspace memory, Foundry training, or the
  selected harness's internal loop.
- `ImprovementProposalPlane`: the governed proposal path for runtime
  improvement. It turns traces, failures, corrections, evals, and receipts into
  proposed `SkillCandidate`, `MemoryCandidate`, `ToolCallRefinement`,
  `WorkflowPatch`, `HarnessProfilePatch`, `RoutingPolicyPatch`,
  `VerifierCandidate`, or `FoundryJobRequest` objects. It is not a
  self-modifying meta-harness and does not make improvements canonical without
  evaluation, policy, authority, receipts, and Agentgres admission.
- `WorkspaceBootstrapRecipe`: a compositor-executed setup recipe for
  downloading models, configuring provider integrations, setting local/remote
  compute preferences, creating capability leases, initializing cTEE/private
  workspace posture, and selecting defaults. It is not the Default Harness
  Profile.
- `IoiAiGoalChat`: the ioi.ai intent and coordination surface where users ask,
  invoke existing work, inspect state, and draft Hypervisor runs, Automations,
  Foundry jobs, restore flows, or marketplace publish flows. It is not the
  durable automation builder, execution runtime, wallet authority, or
  Agentgres truth source.
- `IoiAiGoalChatHandoff`: explicit proposal from ioi.ai Goal Chat into
  Hypervisor App/Web, Hypervisor Automations, Foundry, wallet.network,
  aiagent.xyz, sas.xyz, or provider/restore flows. It can carry draft refs and
  review requirements, but it does not make an automation durable without
  explicit user action and daemon/Agentgres/wallet paths.
- `TaskCapsule`: a minimized, policy-bound execution packet given to a runtime
  node. It carries visible context, hidden context classes, allowed/forbidden
  actions, output contract, TTL, and authority bindings.
- `HypervisorAppShell`: implementation-level native shell for Hypervisor App.
  It owns shell affordances such as windows, deep links, tray, shortcuts,
  updater, auth handoff, and daemon supervision. Shell framework selection is an
  implementation choice, not Hypervisor's product identity.
- `HypervisorDesktop`: the local/private device automation mode within the
  Hypervisor product. It may launch, manage, or project a local Hypervisor Daemon runtime
  profile, but it does not define a separate canonical runtime path.
- `IOICli`: the terminal/headless operator client over daemon/public runtime
  APIs. It can render plans, controls, traces, approvals, and receipts, but it
  does not own execution semantics.
- `IOITui`: an optional interactive presentation of IOI CLI controls. It is
  useful when a terminal operator wants a dashboard-like flow, but it must map
  to daemon/domain APIs and must not create hidden runtime truth.
- `IOISdk`: a low-level protocol/client library over daemon, Agentgres,
  wallet.network, AIIP, and IOI L1 contracts. It may provide typed helpers,
  transports, generated clients, and explicit test mocks; it is not the
  execution substrate initialized on compute nodes and not the full autonomous
  development kit.
- `IOIAdk`: the autonomous development kit for building governed autonomous
  systems, workers, service modules, harnesses, evals, manifests, receipts, and
  deployment profiles. It may be built on top of SDK clients, but it is a
  builder framework, not an operator shell and not the daemon/runtime owner.
- `CompatibilityAdapter`: an IDE extension, CLI wrapper, MCP gateway, shell
  shim, Git hook, workspace watcher, API proxy, browser/cloud connector, or
  CI/CD gate that observes or submits proposed actions to the daemon. It is a
  request and mediation surface, not the authority owner for policy, effects,
  secrets, receipts, replay, or durable runtime state.
- `GuestWorkload` or `GuestCapability`: a worker, model, tool, connector,
  browser, shell, computer-use provider, or external execution venue supervised
  by the Hypervisor Daemon under policy and authority. Guest workloads/capabilities do
  not own policy, secrets, receipts, replay, or durable run truth.
- `TrustAuditSubstrate`: the shared policy, authority, approval, receipt, replay,
  verification, and settlement evidence layer that makes autonomous execution
  inspectable and accountable.
- `SealedStateArchive`: an encrypted content-addressed state artifact for
  inactive, idle, terminal, portable, migrated, or restorable runtime/domain
  state. It is a first-class Agentgres format, but not canonical live state by
  itself. Agentgres keeps canonical operation refs, state roots, object heads,
  lifecycle metadata, archive refs, authority metadata, and receipts;
  storage backends such as Filecoin/CAS, S3, local disk, or another blob store
  keep bytes.
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
  routing, sync metadata, billing/entitlement, console/org
  provider-environment view, and remote-runtime coordination domain for
  `ioi.ai`.
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
- `adaptive_work_graph`: the durable runtime name for parallel/delegated work
  graph execution inside a bounded GoalRun. It is not the
  `CollaborativeWorkGraph` of an OutcomeRoom; a room may contain many GoalRuns,
  each with its own adaptive work graph. Neither is an unbounded swarm or a
  separate runtime: the adaptive work graph stays inside one GoalRun's budget,
  policy, and receipt envelope, and the room's shared graph is an admitted,
  leased coordination structure over those bounded runs. `adaptive work graph`
  is legacy or historical vocabulary only.

## Audit Terms

- `receipt`: an immutable or content-addressed evidence record that a declared
  operation, observation, decision, authority transition, delivery, or effect
  occurred under identified inputs, versions, policy, and actors. A receipt is
  not automatically proof of correctness, truth, acceptance, or settlement.
- `contract`: a spec-level requirement set, not product UI copy.
- `CIRC`: stable label for the Hypervisor Core Intent Resolution Contract.
- `CEC`: stable label for the Hypervisor Core Effect Execution Contract.

`CIRC` and `CEC` may appear in specs, trace schema values, evidence bundle
paths, and architecture guard tests. They should not appear in ordinary runtime
type names, helper names, Chat/Spotlight UI copy, or product-facing summaries.
