# ADR 0015: Define IOI As The Open Operating Stack For Bounded Distributed Autonomous Systems

- Status: Accepted
- Date: 2026-07-12
- Owners: IOI architecture / Hypervisor / daemon runtime / Agentgres / wallet.network / AIIP / IOI Network / IOI L1
- Supersedes: ADR 0011 and ADR 0012

## Context

ADR 0011 correctly separated local operational settlement from sparse public
settlement, but it conflated a logical autonomous system with one Hypervisor
Node and described IOI L1 as the global settlement layer for the machine
economy. ADR 0012 correctly established AIIP as receipt-native work interop,
but made shared IOI settlement sound like the inevitable center of sovereign
autonomous systems.

The architecture now has a stronger and more general category. A useful IOI
system may be single-node or multi-node, single-authority or threshold/BFT,
local-only or network-connected, finite-lived or successor-governed. It remains
one bounded distributed autonomous system when its constitution, admitted
state transitions, authority boundaries, evidence, replay, improvement, and
lifecycle are real. Public consensus, a token, and IOI L1 are deployment and
enrollment choices, not category requirements.

Distribution is not exhausted by replication and failover. One sovereign DAS
may also place useful work across many admitted compute, verifier, sensor,
gateway, human, or embodied members while retaining one `system_id`, one
constitution, and one operational-truth boundary. A drone swarm, robot fleet,
distributed facility, or multi-site service can therefore be one internally
distributed autonomous institution. AIIP is needed when work crosses into a
separately governed system, not merely because work crosses a process, machine,
provider, or physical unit.

## Decision

The canonical thesis is:

> **IOI is the open operating stack that turns intelligence into bounded
> autonomous institutions. L0 makes each institution safely distributable
> across its governed compute, state, verification, human, and embodied members;
> AIIP makes selective, positive-surplus interoperation between separately
> sovereign institutions contractible; IOI L1 supplies optional shared trust and
> economic finality.**

### Product And Protocol Category

IOI leads with **bounded distributed autonomous systems (bounded DAS)**.
`Intelligent blockchain` is the technical classification for a bounded DAS
implemented as a constitution-bound, ordered, receipted, replayable, and
cryptographically continuous state machine. Every admitted operation or batch
binds a monotonic sequence, expected predecessor commitment, operation/batch
commitment, admission proof, resulting state root, and receipt root. A bounded
autonomous application without that chain is not classified as a blockchain.
“Cosmos for bounded DAS” is a useful L0 builder analogy, not the full product
category and not a claim that consensus is always present.

A no-public-consensus, one-authority deployment can still be an intelligent
blockchain. Replication, threshold authority, BFT consensus, and external-chain
finality are independent declared profiles. Node count never upgrades the
system's authority, consensus, independence, or finality claims implicitly.

### Package Release, Genesis, And Live Identity

An Autonomous System Package is a reusable `package://` release artifact. It
versions and distributes typed GoalRunProfile, WorkflowTemplate, HarnessProfile,
SkillManifest, RuntimeToolContract, worker, authority-requirement,
constitution/profile-template, evaluation, and receipt components without
changing their canonical owners; it has no live system identity, membership,
enrollment, or lifecycle continuity. Package lifecycle ends in release,
promotion, deprecation, or revocation.

`AutonomousSystemGenesisEnvelope` is the one-time binding of a selected release
to a new stable `system_id`, active constitution, initial profiles, governing
decision/authority, sequence-zero commitment, and initial state/receipt roots.
Activation, operation, upgrade, recovery, migration, succession, dissolution,
and decommission are live-system lifecycle. An upgrade adopts a later release
without minting another genesis or changing system identity.

### Logical System And Node Topology

The durable identity is the logical `system_id`, not a process, app, machine,
or Hypervisor Node. One logical system can span one or many governed node
memberships. Desired topology belongs to a deployment profile; observed node
membership, role, readiness, catch-up root, lease, writer epoch, and fencing
state remain explicit operational records.

Adding a node is a governed membership transition. It may add availability,
durability, read capacity, execution capacity, or a standby writer, but it
cannot silently widen authority or finality. Promoting or replacing a
single-authority writer requires verified catch-up, a new epoch, and prior-
writer fencing. A deliberately single-node profile may fail closed or perform a
receipted checkpoint/log restore. Threshold, BFT, and external-finality systems
use their declared profile-native view/round, membership, or external-finality
recovery proof. Ambiguous partition fails closed.

The same governed membership also supports productive distribution. Admitted
members may receive bounded role, work-claim, runtime, context, resource,
budget, and authority leases; perform specialized or parallel work; publish
evidence and results; and reconcile through the system's declared ordering and
admission path. Node membership establishes eligibility and topology, not a
work award or an authority grant. The existing GoalRun, RoleTopology,
RuntimeAssignment, lease, receipt, and domain-state contracts compose this
plane; IOI does not add a second swarm runtime.

### Three Coordination Planes

The architecture distinguishes three composable planes:

1. **Continuity coordination** keeps one logical system available and
   recoverable through replication, catch-up, fencing, failover, replay, and
   profile-native recovery.
2. **Same-system distributed work** assigns useful cognitive, digital, human,
   verification, and embodied work across admitted members under one
   constitution and one system-local admission boundary.
3. **Cross-system federation** uses AIIP only when work crosses between
   independently governed systems with separate authority, truth, risk, exit,
   and settlement boundaries; exact collaboration terms and the required
   participant and work leases apply.

One deployment may use all three planes. They are trust and coordination
profiles over the same L0 substrate, not three products or three competing
runtimes. Replicas need not become workers, workers need not become writers,
and independently governed AIIP peers must not be disguised as member nodes.

### Constitution, Evidence, Improvement, And Lifecycle

The constitution sits above ontology, ordinary work, and ordinary upgrades. It
binds purpose and action contracts, authority ceilings, protected amendment
classes, ordering/admission/finality, oracle evidence, continuity, emergency
stop, revocation, and decommission paths. Ordinary recursive improvement may
propose changes but cannot self-commit protected constitutional changes.

External observations remain attributed, freshness-bounded, challengeable
evidence. Consensus or signatures can prove agreement over an assertion; they
do not make the assertion external-world truth. Durable systems require
explicit migration, succession, dissolution, residual-asset, archive,
revocation, and terminal-decommission semantics. Bounded does not mean
benevolent; it means consequential power and persistence remain enforceably
limited.

### L0, AIIP, And Optional Shared Trust

- **IOI L0** supplies the independently operable contracts, schemas,
  conformance, reference runtime path, authority/evidence boundaries, and
  tooling used to build and run bounded DAS, including continuity and useful
  distributed work across admitted members of one logical system.
- **AIIP** moves bounded work across sovereign systems and binds semantic,
  authority, evidence, recovery, dispute, and settlement intent. It assumes
  neither consensus nor IOI L1. A2A, MCP, AGNTCY/OASF, HTTP/RPC, and external
  chain standards are versioned bindings, not protocol identities that AIIP
  replaces.
- **IOI L1** is an optional neutral public-trust utility for selected registry,
  rights, reputation, escrow, dispute, verification, guardian, availability,
  ordering, finality, bond, and settlement services. It never owns per-call
  reasoning, operational state, or local transitions.

Each system settles locally by default. External settlement must be declared
and service-selective.

### Conditional Cooperation And Exact Terms

IOI assumes no ambient motive, duty, or inevitable progression from sovereign
operation to federation. A bounded DAS remains complete without AIIP use,
marketplace participation, external contribution, or IOI Network enrollment.
Sovereignty protects local truth, policy, assets, bargaining power, and exit;
complementary value supplies the motive to interoperate.

Cross-system work proceeds only when every required party's governed decision
finds its expected cooperation surplus positive:

```text
expected cooperation surplus_i
  = expected utility under accepted collaboration terms_i
  - expected utility of best permitted outside option_i
  - incremental cooperation costs_i

participate only when expected cooperation surplus_i > 0
```

Incremental cooperation costs include execution, opportunity, search,
semantic-mapping, coordination, verification, privacy, IP, counterparty,
dispute, settlement, switching, and dependency costs and risks. Raw valuations
and outside options may remain private.

One `CollaborationTermsEnvelope` root binds scope, parties, roles, rights,
obligations, disclosure, contribution and reward basis, risk, exit, and
settlement. Discovery, compatibility, a shared objective, invitation, message,
task offer, or terms proposal creates no obligation, authority, executable
award, access right, reputation, or payout. Exact-root acceptance enables
admission; `RoomParticipantLease` admits participation; `WorkClaimLease` awards
bounded work; contribution, verification, acceptance or adjudication, and
settlement remain distinct. Amendments require new acceptance and are
non-retroactive (`INV-30`, `INV-31`).

### Explicit IOI Network Enrollment

The network relationship has three profiles:

- `ioi_compatible`: independently operable open L0; no mandatory L1, network
  fee, token, assurance claim, or contribution.
- `ioi_connected`: selects named IOI Network services and pays only for what it
  consumes; it may claim only those service guarantees.
- `ioi_secured`: additionally adopts a current Standard DAS profile and named
  shared-security or assurance services, including explicit terms, fault
  model, evidence, duration, and bonds or claims where applicable.

Enrollment cannot tax local transitions or mutate constitution, authority,
ordering, or finality. Exit preserves outstanding obligations and disputes.

### Product, Network, And L1 Value

Three value loops may reinforce one another but never automatically accrue:

1. L0 product/company value from subscriptions, managed execution and
   clusters, enterprise deployments, Work Credits, and support.
2. Network value from routing, marketplaces, assurance, certification,
   procurement, disputes, and selected settlement operations.
3. L1/native-asset value only from demonstrated demand for scarce neutral
   public capacity and bonded risk.

Work Credits are product budget units, not protocol tokens. A native asset is
justified only if gas/public capacity, bonds, slashing/claims, or governance
cannot be served more cleanly otherwise. Architecture alone makes no market-
capitalization claim and does not justify one token per DAS.

### Open Reference Path And Commercial Boundary

The architecture requires an open, complete, independently operable L0
reference path. Protected commercial implementations, managed routing,
aggregation, assurance operations, enterprise services, and IOI Network
operations remain allowed. This ADR defines the architectural boundary; it
does not silently relicense existing code. Any source-license or contribution-
covenant change requires a separate legal review and accepted licensing ADR.

## Consequences

- OutcomeRoom/Goal Space is the flagship reusable bounded-DAS package and launch
  wedge, not the definition of L0. Every durable room genesis creates its own
  system identity and cryptographic admission spine; the hosted service may
  operate many room systems. React and generated applications remain first-
  class UI projections over each governed system.
- The distributed L0 proof has two same-system gates. The continuity gate is one
  logical DAS across two failure domains with governed join, checkpoint/log
  catch-up, root verification, writer fencing, controlled failover, replay,
  drain, and unchanged authority. The useful-work gate assigns and reconciles a
  real multi-member workload across admitted nodes or embodied units under one
  constitution, including partition/degraded-mode behavior and duplicate-effect
  prevention. Two sovereign systems over AIIP follows as the federation proof
  and must demonstrate a non-subsidized or transparently subsidized
  participant-rational exchange, not connectivity alone.
- Canonical schemas include package release, system genesis, constitution,
  deployment, membership, failover, profile-native ordering/finality recovery,
  ordering/admission/finality, oracle evidence, lifecycle continuity and
  transition, network enrollment, network-service invocation, settlement, and
  external-protocol binding objects.
- IOI Network and token value must be measured independently from L0 adoption.
  Mainnet follows demonstrated contract/service demand; it is not a prerequisite
  for proving L0 utility.
- Hypervisor is both the reference hybrid hypervisor/control environment and
  the operator surface for the wider autonomous-system operating stack. Those
  roles are complementary, not competing product theses.

## Non-Goals

- Do not equate node count, replication, or failover with consensus.
- Do not treat all distributed work as AIIP. Member-to-member work inside one
  `system_id` remains same-system coordination; AIIP begins at an independently
  governed system boundary.
- Do not require every DAS, AIIP peer, action, receipt, or local transition to
  enroll in or settle on IOI L1.
- Do not market oracle assertions, signatures, receipts, or consensus as
  universal external truth.
- Do not allow recursive improvement, self-preservation, propagation, resource
  acquisition, succession, or recovery to bypass constitutional ceilings and
  external revocation.
- Do not claim generic discovery, tool invocation, agent tasks, registry,
  escrow, or container orchestration as IOI's novelty. The differentiator is
  the constitution-to-effect lifecycle and its operational evidence.
- Do not treat sovereign-system count, AIIP traffic, room activity, receipts,
  compatibility, or shared goals as cooperation demand or network value.

## Canonical References

- `docs/architecture/foundations/governed-autonomous-systems.md`
- `docs/architecture/foundations/domain-kernels.md`
- `docs/architecture/foundations/common-objects-and-envelopes.md`
- `docs/architecture/foundations/aiip.md`
- `docs/architecture/foundations/ioi-l1-mainnet.md`
- `docs/architecture/foundations/economic-flywheel-and-pricing-boundaries.md`
- `docs/architecture/foundations/ecosystem-assurance-certification-liability.md`
- `docs/architecture/_meta/execution-horizons.md`
- `docs/architecture/_meta/implementation-matrix.md`
