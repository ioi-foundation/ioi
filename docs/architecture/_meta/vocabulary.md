# Runtime Vocabulary

Status: canonical vocabulary reference.
Canonical owner: this file for runtime, audit, substrate, projection, and legacy naming vocabulary.
Supersedes: overlapping runtime vocabulary in plans/specs when names conflict.
Superseded by: none.
Last alignment pass: 2026-06-12.

The agent harness uses behavior-first names in runtime code and reserves
compliance acronyms for hidden audit material.

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
- `HypervisorFleet`: the general infrastructure manager whose first-class
  workload is autonomous systems. It coordinates machines, VMs, containers,
  microVMs, WASM workloads, images, volumes, networks, GPU pools, node
  registry, provider integrations, placement, health, cost, storage posture,
  cTEE posture, receipts, replay projections, and policy visibility. It appears
  through Hypervisor IDE and console.ioi.ai surfaces, but it does not execute
  work, authorize power, admit Agentgres truth, or own payload bytes.
- `FleetNode`: the Fleet projection/object for a local, cloud, GPU, DePIN,
  customer, HypervisorOS, TEE, or bare-metal runtime node. It binds node
  identity, daemon refs, provider metadata, Agentgres domain refs, authority
  refs, status, cTEE posture, storage posture, receipt refs, and projection
  watermarks.
- `FleetWorkloadPrimitive`: the Fleet projection/object for VM, container,
  microVM, WASM, image, volume, network, snapshot, backup, restore point,
  GPU-pool, node-pool, migration-plan, or provider-connector lifecycle state.
  It is governed infrastructure state and must still link to authority refs,
  Agentgres operation refs, and receipts when consequential.
- `FleetRuntimeAssignmentView`: the Fleet projection over runtime assignments,
  placement reasons, workspace/run refs, authority refs, Agentgres operation
  refs, receipt refs, and status. It is observability/control-plane state, not
  execution ownership.
- `FleetStoragePosture`: the Fleet projection over storage-backend availability,
  retention, replication, privacy class, and Agentgres artifact refs. It does
  not make storage backends the authority over payload meaning or restore
  validity.
- `ClassicalInfraPrimitive`: any traditional infrastructure object Fleet may
  manage or project, including a VM, container, microVM, WASM workload, image,
  volume, network, firewall/egress policy, snapshot, backup, restore point,
  node pool, GPU pool, quota, lease, health check, log stream, metric stream,
  cost record, provider connector, or migration plan.
- `VirtualMachineWorkload`: a VM managed as a Fleet workload primitive. It is
  not automatically a Hypervisor runtime node unless a Hypervisor Daemon profile
  is installed, enrolled, and receipted.
- `ContainerWorkload`: a container managed as a Fleet workload primitive under
  daemon/provider policy. Containers do not bypass wallet.network authority,
  Agentgres receipt admission, or cTEE mount rules.
- `MicroVMWorkload`: a microVM managed as a Fleet workload primitive for
  stronger workload isolation or reproducibility under daemon/provider policy.
- `WASMWorkload`: a WASM module or workload managed as a Fleet workload
  primitive, commonly used for portable step/module execution under daemon
  routing.
- `ImageRef`: Fleet-visible image identity or image artifact ref for VM,
  container, microVM, WASM, HypervisorOS, or model-server deployment.
- `VolumeRef`: Fleet-visible volume identity or volume artifact/storage ref.
  Volume availability is not payload meaning; Agentgres artifact refs and
  receipts govern meaning and restore validity.
- `NetworkPolicy`: Fleet-visible ingress, egress, firewall, routing, and
  private-network posture. Network policy does not grant authority by itself.
- `SnapshotRef`: Fleet-visible snapshot identity for infrastructure restore
  flows. It is not restore validity without Agentgres archive refs, state roots,
  and receipts where the snapshot affects canonical state.
- `MigrationPlan`: Fleet-visible plan for moving workloads, nodes, volumes,
  images, private workspaces, model servers, or provider posture between
  VMware, Proxmox, KubeVirt, Nutanix, Kubernetes, HypervisorOS, cloud, DePIN,
  and customer targets.
- `GpuPool`: Fleet-visible accelerator pool with provider, node, utilization,
  model-route, placement, cost, lease, authority, and cTEE posture.
- `ProviderConnector`: a declared connector for cloud, DePIN, storage,
  Kubernetes, KubeVirt, VMware, Proxmox, Nutanix, HypervisorOS, or customer
  environments. It may execute provider API actions only through approved daemon
  or provider-connector boundaries with authority and receipts.
- `FleetPlacementDecision`: a Fleet projection or canonical object, depending
  on risk, that records why a workload, private workspace, model mount, worker,
  service, or runtime assignment should land on a node/provider. It cannot
  bypass wallet.network, daemon execution, cTEE custody, or Agentgres admission.
- `HypervisorProviderIntegration`: a direct Hypervisor/Fleet integration with a
  provider or inventory source that can run, store, network, attest, or host
  autonomous work. Examples include local machines, customer clouds,
  hyperscalers, DePIN compute markets, decentralized storage networks,
  confidential-compute providers, enterprise clusters, cloud GPU providers,
  provider-specific markets, and user-specified routes.
- `CloudRoute`: the Hypervisor/Fleet object for routing a workload to compute,
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
- `DefaultHarnessProfile`: the standard daemon-executed, wallet-authorized,
  Agentgres-backed, loop-native orchestration profile for bounded autonomous
  work. It is not a peer runtime beside the daemon; it configures how daemon
  runs move through intent contracts, context topology, action proposals,
  policy/authority gates, execution, normalization, receipts, Agentgres state,
  artifact refs, verification, and output ownership.
- `LoopNativeExecution`: the Default Harness Profile execution discipline in which
  scoped work advances by model pass, action proposal, authority/policy gate,
  execution, result normalization, receipt/Agentgres/context update, and model
  re-entry until completion, blocker, budget, verification, or delivery state
  resolves the task.
- `ContextTopology`: the planning and repair surface that partitions a run into
  context-resolution boundaries such as semantic domain, authority, privacy,
  verification, service step, loop depth, artifact locality, or Agentgres
  domain boundary. It may start as a projection and should become canonical
  only when replay, repartition, or cross-actor routing needs object identity.
- `ContextChamber`: a bounded context scope for one task, actor, service step,
  or verifier. It carries local goal, constraints, authority, evidence refs,
  receipt refs, observations, uncertainty, loop policy, and output policy
  without dumping global context into every actor.
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
- `ExecutionPrivacyPosture`: the cTEE posture label for a worker, service,
  outcome engine, or harness path. Values include `private_native`,
  `redacted_api`, `provider_trust`, and `unsafe`.
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
  explicitly declassified. `PersistentShieldedHypervisorNode` is a deprecated
  compatibility alias.
- `PrivateWorkspaceCapsule`: the task/workspace capsule sent to an untrusted
  rented node. It carries visible public/redacted context, encrypted refs,
  sealed private heads, allowed remote ops, forbidden plaintext classes, leakage
  profile, and required receipts. `ShieldedTaskCapsule` is a deprecated
  compatibility alias.
- `AlphaSeal`: a sealed private strategy capsule for quantitative strategies or
  similar high-value logic. It binds a public compute trunk, private strategy
  head, leakage profile, policy, wallet authority, and receipts.
- `AutonomyLease`: a wallet.network authority lease that allows a persistent
  node to act while the user is away within bounded policy, without receiving
  durable raw secrets or unrestricted authority.
- `WalletExchange`: the source-agnostic Wallet product surface for exchanges.
  wallet.network is the user-facing cockpit and owns exchange authority, risk
  disclosure, policy evaluation, signing or denial, revocation, and receipts;
  route sources only produce candidates.
- `WalletTrade`: the advanced Wallet product surface for exposure management,
  including spot orders, perps, prediction markets, event contracts, leverage,
  collateral, margin, liquidation, funding, resolution, and position lifecycle.
  wallet.network is the user-facing cockpit and owns trade authority, risk
  disclosure, policy evaluation, signing or denial, revocation, and receipts;
  trading route sources and venues only produce candidates or execute approved
  intents.
- `ExchangeIntent`: the semantic wallet object above raw transaction calldata.
  It binds route, calldata commitments, slippage, simulation hash, policy hash,
  grant/lease, revocation epoch, economics, risk labels, and exact `TxIntent`
  records before any exchange can be approved or signed.
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
- `FutureDecentralizedCloud`: parked future product space for a possible public
  provider catalog, P2P/PQ-aware cloud routing layer, compute/storage receipt
  explorer, provider reputation surface, or infrastructure marketplace. It is
  not part of the present canon spine and must not be required for Hypervisor
  provider integrations.
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
  initiator, action, authority risk class, asset/route/security risk labels,
  affected assets/secrets/data, destination, policy diff, simulation result,
  expiry, and deny/edit/approve actions.
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
  wallet.network controls viewing/decryption/mutation authority; IOI L1 stores
  only selected public/economic/cross-domain commitments.
- `AgentgresArtifactRefPlane`: the Agentgres-governed reference, lifecycle,
  policy, authority, receipt, replay/import, archive/restore, and state-root
  validity layer for payload bytes. It owns `ArtifactRef`, `PayloadRef`,
  `EvidenceBundle`, `DeliveryBundle` artifact linkage, and `AgentStateArchive`
  refs; storage backends hold the bytes.
- `StorageBackend`: a payload byte store below Agentgres-governed artifact refs,
  such as local disk, S3/object stores, Filecoin, CAS/IPFS, provider blob
  stores, customer VPC blob stores, or storage engines used as payload engines.
  A storage backend is not an authority layer.
- `FilecoinCASBackend`: a content-addressed storage backend profile for payload
  availability. It may hold packages, evidence, traces, checkpoints, delivery
  payloads, datasets, and sealed archive bytes, but Agentgres owns their
  meaning and wallet.network owns authority/decryption.
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
- `HypervisorNode`: the local autonomous-system settlement domain for a user,
  organization, project, or deployment. It composes Hypervisor IDE,
  Hypervisor Daemon, Agentgres, wallet.network authority paths, local registries,
  receipts, replay, and runtime profiles. It is not the Hypervisor IDE UI by itself.
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
  adapter, or operator proposal becomes a daemon-authorized effect. Models and
  agents may reason or propose; the daemon decides what crosses this boundary.
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
  worker has a manifest, policy envelope, capability surface, receipt
  obligations, runtime requirements, contribution terms, and settlement
  identity.
- `Agent`: product-facing or colloquial language for an autonomous assistant,
  delegated actor, or user-facing worker experience. New protocol prose should
  use `Worker` when referring to the accountable execution actor. When an agent
  is treated as durable system architecture, prefer `IntelligentExecutionNode`
  or `GovernedAutonomousSystemChain` to avoid implying a stateless chatbot.
- `ManagedWorkerInstance`: a user-, org-, or project-bound initialization of a
  worker package. Product UX may call this an agent instance, but canonical
  state should bind it to a worker manifest, install/license right, runtime
  assignment, persistence profile, authority policy, memory/archive policy, and
  subscription or entitlement.
- `AgentWiki`: the user-facing and agent-facing semantic memory surface for
  preferences, procedures, doctrine, route notes, failure lessons, source-backed
  claims, and project knowledge. It may hold draft or local memory, but durable
  behavior-affecting wiki changes become canonical only when admitted through
  Agentgres operations such as `ContextMutation` with policy, authority,
  provenance, and receipts.
- `ioi-memory`: the live product-memory implementation boundary for runtime
  memory, thread checkpoints, core and archival memory, local evidence blobs,
  and enrichment jobs. It is a context-memory plane, not Agentgres and not IOI
  L1. `SCS` is legacy terminology removed as the product-memory architecture by
  ADR 0001.
- `ContextMemoryPlane`: the adjacent memory/retrieval plane that governs what
  agents can know, remember, and retrieve. Agentgres governs which context
  changes are canonical, replayable, portable, shared, policy-relevant, or
  settlement-relevant.
- `RuntimeSubscription`: an entitlement or billing object that keeps a managed
  worker instance available by per-invocation use, warm runtime allocation, or
  zero-to-idle restore policy. It does not make aiagent.xyz or ioi.ai the
  execution runtime.
- `Model`: a cognition backend mounted or invoked by a worker. Models are not
  the economic actor by themselves. Model routing belongs to the runtime/node
  contract; model weights or provider endpoints are mounted by deployment
  profile and are not part of the Hypervisor Node binary by default.
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
  used by Hypervisor builder lenses. It is a UI/workflow substrate, not
  canonical runtime truth by itself.
- `HypervisorFoundry`: the Hypervisor product lens for creating, training,
  configuring, evaluating, packaging, deploying, and improving workers through
  the Worker Training lifecycle. It can project recipes into the standard
  workflow compositor, but it is not a separate canvas environment.
- `HypervisorIDEFleetSurface`: the Hypervisor IDE lens for hands-on management
  of attached nodes, persistent workspaces, active agents/workers/services,
  model mounts, cTEE posture, receipts, approvals, trace summaries, replay
  availability, and start/stop/resume/archive/restore actions. It requests and
  displays; it does not own Fleet truth, execution, or authority.
- `ConsoleIoiAiFleetSurface`: the console.ioi.ai web/org/admin lens for
  accounts, devices, entitlements, node registry, provider integrations, fleet
  status, billing, remote access, restore routing, and org policy visibility.
  It is an ioi.ai control-plane surface over Hypervisor Fleet, not the daemon.
- `WorkflowCompositor`: the standard graph authoring projection over the
  SharedBuilderSubstrate. It may render outcome workflows, data recipes,
  training recipes, evaluation recipes, benchmark recipes, or deployment
  recipes with lens-specific palettes and inspectors.
- `TaskCapsule`: a minimized, policy-bound execution packet given to a runtime
  node. It carries visible context, hidden context classes, allowed/forbidden
  actions, output contract, TTL, and authority bindings.
- `HypervisorIDE`: the IDE-grade operator console for autonomous systems. It
  observes, requests, approves, interrupts, debugs, explains, and replays
  daemon-governed work. It is not an execution authority and it must not become a
  second runtime inside the VS Code extension host. It is also not the full
  Hypervisor Node; the node includes daemon, Agentgres, wallet.network authority
  paths, local registries, receipts, replay, and runtime profiles.
- `HypervisorGuard`: developer-facing packaging for IOI Authority Gateway
  adapters. It can describe "bring IOI alignment security to Cursor, VS Code,
  Codex, Claude Code, JetBrains, OpenHands, hosted agents, and similar tools,"
  but canonical runtime authority still belongs to the Hypervisor Daemon.
- `HypervisorAppShell`: the Electron/VS Code fork that hosts Hypervisor IDE and
  local runtime surfaces. It owns shell affordances such as windows, deep links,
  tray, shortcuts, updater, auth handoff, and daemon supervision.
  Tauri/OpenVSCode embedding is legacy extraction inventory, not the target
  shell.
- `HypervisorDesktop`: the local/private device automation mode within the
  Hypervisor product. It may launch, manage, or project a local Hypervisor Daemon runtime
  profile, but it does not define a separate canonical runtime path.
- `IOICliTui`: the terminal/TUI operator client over daemon/public runtime APIs.
  It can render plans, controls, traces, approvals, and receipts, but it does
  not own execution semantics.
- `IOISdk`: a low-level protocol/client library over daemon, Agentgres,
  wallet.network, AIIP, and IOI L1 contracts. It may provide typed helpers,
  transports, generated clients, and explicit test mocks; it is not the
  execution substrate initialized on compute nodes and not the full autonomous
  development kit.
- `IOIAdk`: the autonomous development kit for building governed autonomous
  systems, workers, service modules, harnesses, evals, manifests, receipts, and
  deployment profiles. It may be built on top of SDK clients, but it is a
  builder framework, not an operator shell and not the daemon/runtime owner.
- `AgentIde`: the GUI/workflow-composer projection over shared
  contracts. It authors and inspects workflows, but canonical run/session/task
  truth remains in daemon/Agentgres state.
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
  routing, sync metadata, billing/entitlement, console/org Fleet surface, and
  remote-runtime coordination domain for `ioi.ai`.
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
