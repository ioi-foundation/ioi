# AIIP: Inter-Autonomous-System Protocol

Status: canonical architecture authority.
Canonical owner: this file for AIIP, bounded-execution-domain interop, work and collaborative-pursuit packets, semantic-profile negotiation, AIIP profiles, and cross-system handoff/admission semantics.
Supersedes: product prose that treats Hypervisor, aiagent.xyz, sas.xyz, or third-party autonomous systems as separate bespoke interop protocols.
Superseded by: none.
Last alignment pass: 2026-07-11.
Doctrine status: canonical
Implementation status: planned (protocol design only; no AIIP transport, channel, semantic-negotiation, collaborative-pursuit, or two-sovereign-node implementation)
Last implementation audit: 2026-07-05

## Canonical Definition

**AIIP is IOI's RPC-shaped, receipt-native interoperability protocol for
bounded autonomous work.**

AIIP moves delegated work, collaborative-pursuit updates, negotiated semantic
profiles, authority leases, receipt commitments, settlement intents, reputation
queries, dispute notices, and handoff finality across bounded execution domains.
Each domain keeps its own runtime, private context, and operational truth. IOI
mainnet settles only the selected consequential record when public trust,
economic finality, portable reputation or rights, dispute resolution, or
cross-system interoperability requires it.

Short form:

> **AIIP moves autonomous work across systems. IOI settles what happened.**

The broader IOI thesis is:

> **Autonomous systems can execute anywhere. IOI settles what matters.**

## Layer Boundary

Autonomous work should usually execute off chain and close to its authority,
data, tools, models, users, or physical environment.

```text
Autonomous systems execute anywhere.
AIIP routes delegated work across systems.
Receipts attest declared boundary facts.
IOI mainnet settles the consequential record.
```

The chain does not execute most model inference, browser activity, API calls,
file edits, workflow steps, robot actions, human review, VM jobs, or artifact
generation. The chain may settle accepted or adjudicated claims under known
rules; it does not turn a signed statement into a correct outcome.

Canonical distinction:

```text
Execution = local runtimes, microharnesses, workers, APIs, robots, VMs, enterprise systems
Interop   = AIIP packets, profiles, channels, authority, receipts, settlement intents
Settlement = IOI mainnet roots, rights, escrows, disputes, reputation, handoff finality
```

AIIP preserves this assurance ladder across domains:

```text
receipt / attestation
  authenticated statement about a declared boundary fact
-> evidence bundle
  support for a claim
-> verification
  named verifier and rule/version evaluated the claim
-> acceptance
  user, customer, domain, or counterparty accepted the outcome
-> adjudication
  challenge or dispute was resolved
-> settlement
  rights or value moved under the accepted or adjudicated claim
```

Cryptography makes claims attributable, ordered, portable, and challengeable.
Correctness and economic value additionally require evaluation, acceptance,
causality, demand, and dispute resolution.

## Bounded Execution Domains

A **bounded execution domain** is any domain that can perform scoped autonomous
work under declared capabilities, policies, authority requirements, receipt
schemas, runtime boundaries, and settlement behavior.

Examples:

- local coding, browser, terminal, design, finance, or research microharnesses;
- installed workers from aiagent.xyz;
- marketplace workers;
- outcome providers from sas.xyz;
- robot fleets;
- DAO-owned operators;
- enterprise private runtimes;
- third-party autonomous systems;
- independent autonomous-system L1s or sovereign domains.

AIIP lets bounded execution domains talk. IOI mainnet lets their consequential
records settle.

Robot fleets, robot controllers, drones, vehicles, facility systems, and other
embodied domains are valid AIIP participants, but actuator-affecting work is
not ordinary AIIP traffic. Any handoff or command envelope that can produce a
`physical_action` must bind `PhysicalActionPolicy`, `SafetyEnvelope`,
`EmergencyStopAuthority`, required supervision policy, sensor evidence
obligations, and `ActuatorCommandReceipt` obligations before execution. The
canonical owner for those objects is
[`physical-action-safety.md`](./physical-action-safety.md).

## Same Semantic Protocol, Different Modes

Hypervisor internal routing and external autonomous-system handoffs should use
the same exposed AIIP semantics. The difference is transport, trust boundary,
privacy posture, and settlement depth.

Internal local routing may use in-process calls, daemon IPC, Unix sockets,
local HTTP, gRPC, JSON-RPC, NATS, or a daemon bus. It may emit local receipts
only and require no public settlement unless the action is consequential.

External routing should use signed envelopes, authority leases, receipt
obligations, payment or escrow terms, reputation updates, dispute windows, and
mainnet commitments when consequential.

Canonical rule:

> **Same semantic protocol, different transport and settlement mode.**

## Core Call Shape

AIIP should feel like RPC to developers while behaving like interchain
communication at the trust and settlement layer.

```text
system.discover()
system.quote(task)
system.invoke(task, authority)
system.handoff(task)
system.deliver(update)
system.accept(delivery)
room.join(policy, capabilities)
room.claim(frontier_item, leases)
room.publish(attempt_or_finding_ref)
room.challenge(verifier_or_rule_ref)
room.admit(outcome_delta_ref)
system.commitReceipt()
system.settle()
system.dispute()
system.resolveDispute()
```

Underneath, these calls compile into signed, sequenced, idempotent,
receipt-aware packets. Room calls carry refs and permitted projections; they do
not expose a shared raw context bus.

Canonical analogy:

> **RPC is the call shape. IBC is the trust model. IOI is the settlement layer.**

Category role:

> **AIIP is the work-interop layer for the Web4 domain economy: it lets
> autonomous-system domains exchange delegated work, authority, receipts,
> reputation, disputes, and settlement claims without sharing one runtime or one
> operational database.**

## Packet Classes

AIIP carries typed work packets, not arbitrary undifferentiated bytes.

```text
CapabilityDiscoveryPacket
  What can this system, domain, worker, or module do?

TaskOfferPacket
  Can you perform this bounded task under these constraints?

TaskAcceptancePacket
  Yes, under this price, policy, SLA, receipt obligation, and authority requirement.

HandoffPacket
  Transfer this task or subtask to another bounded execution domain.

SemanticProfileNegotiationPacket
  Declare input/output ontology and action-schema profiles, compatible versions,
  crosswalk or adapter refs, policy-bound views, mapping loss/ambiguity, and
  verifier obligations for the handoff.

OutcomeRoomDiscoveryPacket
  Query or publish a signed, policy-bound OutcomeRoom discovery projection:
  public objective/category, semantic and capability requirements, eligibility,
  visibility/privacy, budget/quote, verifier, settlement, and admission endpoint,
  with no raw private room context.

RoomParticipationPacket
  Request, admit, update, suspend, retire, or revoke a participant lease under
  the room's declared membership and visibility policy; on exit, release claims
  and carry the permitted portable participant-state bundle or its signed ref.

FrontierUpdatePacket
  Propose or admit a question, hypothesis, task, review need, dependency,
  priority, stop condition, or resource need in a CollaborativeWorkGraph.

WorkClaimPacket
  Claim, renew, release, expire, reassign, or quarantine bounded frontier work
  together with context, authority, data, compute, tool, and budget lease refs.

AttemptFindingPacket
  Publish positive, negative, inconclusive, invalid, exploit-found, or
  superseded attempt/finding refs, derivation, evidence, cost, reproduction,
  license, and disclosure posture.

VerifierChallengePacket
  Challenge a metric, rule version, verifier, evidence bundle, mapping,
  eligibility decision, or claimed result and identify affected work requiring
  re-evaluation.

RoomAdmissionPacket
  Propose, accept, reject, supersede, or reconcile a WorkResult / OutcomeDelta
  under the declared hosted or federated room ordering policy.

AuthorityQueryPacket
  Does this worker, system, or domain have authority to perform this action?

AuthorityGrantPacket
  This authority lease is valid for this scope, time, budget, subject, and policy.

ReceiptCommitmentPacket
  This signer attests declared work boundary facts; here is the receipt root or
  inclusion proof for later evidence, verification, acceptance, or dispute.

DeliveryUpdatePacket
  This milestone, partial delivery, final delivery, revision, or cancellation
  changed the outcome state; here are the artifact, evidence, and receipt refs.

AcceptanceDecisionPacket
  Accept, accept partially, reject, request revision, or open dispute against a
  delivery under the declared acceptance criteria.

SettlementIntentPacket
  Release payment or update reputation if these receipt conditions are satisfied.

DisputePacket
  Challenge this outcome, receipt, authority use, payment, routing choice, or settlement claim.

DisputeResolutionPacket
  Resolve a dispute with refund, partial refund, payout, partial payout, slash,
  retry, revision, escalation, or no-fault outcome.

ReputationQueryPacket
  Return reputation under this context, rubric, worker class, or dispute history.
```

## AIIP Envelope

AIIP owns packet semantics, processing rules, profiles, conformance, and
evolution. The single canonical field-level `AIIPChannelEnvelope` and
`AIIPEnvelope` schemas are owned by
[`common-objects-and-envelopes.md`](./common-objects-and-envelopes.md#aiip-and-bounded-execution-domain-envelopes).
That shared schema is the normative superset. It retains packet and payload
identity while binding:

- message type, sender, recipient, channel, sequence/nonce, timestamp, and
  signature;
- idempotency, causation, and correlation;
- local, installed-worker, marketplace-worker, outcome-service,
  autonomous-system, collaborative-pursuit, and enterprise profiles;
- policy and authority, collaboration and OutcomeRoom, ontology/action
  profiles, restricted views, and verifier challenges;
- payload hash/ref, receipt obligations, verifier/acceptor refs, settlement
  terms, and the canonical `assurance_stage` ladder;
- external-effect recovery as `replayable`, `checkpointable`, `compensatable`,
  `reconciliation_required`, or `non_retryable`.

No profile or application may publish a reduced competing `AIIPEnvelope`.
Profile-specific bodies travel through `payload_ref` or the typed packet
objects below while preserving the shared envelope.

AIIP payload bodies may remain private, encrypted, redacted, or available only
to dispute participants. Public settlement should anchor commitments and roots,
not sensitive operational payloads. Sequence, idempotency, and causation fields
must make retry, duplicate delivery, cancellation, ambiguous-effect
reconciliation, and recovery explicit rather than relying on transport luck.

Every task/action profile that can create an external effect declares an effect
recovery class: `replayable`, `checkpointable`, `compensatable`,
`reconciliation_required`, or `non_retryable`. Restoring a transport, VM,
worker, or environment is not proof that the business or physical outcome was
restored. A timeout after dispatch enters the declared reconciliation path;
unknown effects are not blindly replayed, and compensation is a separately
authorized action with its own receipts.

## Protocol Profiles

AIIP uses standard profiles so implementers do not invent one-off integration
patterns.

```text
Local Profile
  Same-node microharness routing, local receipts, optional settlement.

Installed Worker Profile
  User-installed worker/module, signed package identity, scoped authority leases,
  local receipts, optional mainnet anchoring.

Marketplace Worker Profile
  Third-party worker invocation, signed offers, worker staking, quote/invoke/receipt,
  payment, reputation update, and dispute path.

Outcome Service Profile
  Escrow, milestones, acceptance criteria, receipt commitments, challenge window,
  refund/payout rules, provider reputation.

Autonomous-System Profile
  Peer system handoff, mutual receipts, settlement intents, cross-system reputation,
  handoff finality.

Collaborative Pursuit Profile
  OutcomeRoom membership, capability/resource offers, frontier and claim refs,
  attempts and findings, verifier challenges, WorkResult / OutcomeDelta admission,
  contribution lineage, and declared hosted or federated ordering.

Enterprise Profile
  Private execution, redacted receipts, encrypted artifacts, selective disclosure,
  permissioned evidence, optional public roots.
```

Profiles preserve one semantic protocol while allowing local, marketplace,
enterprise, and inter-system variants.

## Multi-Party Collaboration

AIIP channels are usually bilateral at the packet boundary, but an autonomous
outcome may involve a data owner, worker provider, compute provider, customer,
verifier, auditor, regulator, insurer, and settlement counterparty. A party is
an accountable principal with independent control over some combination of
authority, revocation, operational truth, risk, challenge, acceptance, or
settlement. A model endpoint or cloud dependency is normally a disclosed
subprocessor, not a party, unless its principal accepts room-level rights and
obligations.

Do not conflate:

```text
multi-model = distinct cognition routes
multi-worker = distinct versioned worker compositions or roles
multi-node = distinct execution or failure domains
multi-party = distinct accountable principals and governed domains
```

Multiple IOI-owned workers, clouds, keys, and model providers remain one party
when IOI controls their authority, truth, verifier, and settlement. Conversely,
an organization-labelled room spanning independently governed domains is
multi-party even if its UI is private and permissioned.

Multi-party collaboration is represented by a
`MultiPartyCollaborationEnvelope`, not by turning AIIP into a shared raw
context bus. The envelope binds:

- participating principals, affiliations, roles, home domains, authority
  providers, join/eligibility evidence, revocation refs, and separation-of-duty
  constraints;
- allowed artifacts, receipts, restricted views, redacted summaries, AIIP
  channels, delivery bundles, semantic profiles, and audit exports;
- blocked context classes including raw secrets, protected plaintext,
  unauthorized connector payloads, unrelated private memory, and non-opted-in
  training traces;
- per-party authority refs; one party's grant cannot authorize another party's
  connector, worker, data, or physical system;
- policy-bound views, evidence and delivery bundles, contribution refs,
  challenge/adjudication, settlement, artifact license, retention, disclosure,
  and export profiles;
- history policy for party removal, live-view revocation, immutable historical
  roots, and downstream recall or access rotation.

The user may see one outcome, but the protocol remains explicit about which
domain did what, under whose authority, which semantic mapping and evidence were
used, what was withheld, and which contribution, acceptance, dispute, or
settlement claims resulted. Party removal revokes or rotates future access; it
does not rewrite receipt roots, contribution lineage, delivery state, or
required dispute/audit history.

### OutcomeRoom And CollaborativeWorkGraph Handoffs

An `OutcomeRoom` is a collaboration profile above bounded GoalRuns. AIIP moves
discovery projections, participation requests and exits, portable participant-
state bundles, room membership, capability/resource offers, frontier items,
work claims, attempt and finding refs, verifier challenges, and proposed/
admitted outcome deltas between domains. It does not own those objects, execute
attempts, or become a global room database.

Every persistent room declares one ordering and admission topology:

1. **Hosted admission:** one named governed domain sequences and admits
   room-level frontier, attempt, finding, evaluation, and decision updates.
   This is the first conformance target.
2. **Federated admission:** a versioned profile names member domains, sequence
   or merge rules, quorum or adjudicator requirements, conflicts, failover,
   recovery, and policy-version transitions. It is opt-in and planned, not an
   implicit property of every AIIP channel.

Both modes preserve local operational truth. The host or declared federation
policy admits the shared-room projection; each participant separately admits
its private work and outbound claims. AIIP packets are signed, sequenced,
idempotent refs and permitted updates. Raw private context moves only through
an authorized policy-bound view. A board, digest, inbox, leaderboard, and replay
are projections over this state, not protocol authority.

Cross-domain/open discovery and admission use the shared
[`OutcomeRoomDiscoveryEnvelope`](./common-objects-and-envelopes.md#outcomeroomdiscoveryenvelope-and-roomparticipationrequestenvelope)
and `RoomParticipationRequestEnvelope`. An external independently operated
Worker can discover a signed public/permissioned objective and category,
semantic/capability requirements, eligibility, visibility/privacy,
budget/quote, verifier, settlement, and contribution posture, then request
admission through the declared AIIP channel. Discovery contains no private room
context and grants no membership, authority, budget, or data access. Admission
creates a `RoomParticipantLeaseEnvelope` only after the named host domain or
federation policy accepts the same typed request and evidence.

Retire, expiry, quarantine, and revoke transitions release or reassign live
claims and terminate future access. They preserve policy-allowed contribution,
receipt, acceptance, settlement, and dispute refs and may carry a signed
[`ParticipantStateBundleEnvelope`](./common-objects-and-envelopes.md#participantstatebundleenvelope).
The participant's home domain can retain that portable state without continued
access to or trust in a hosted room database. Hosted and federated rooms use the
same discovery, request, lease, exit, and export contracts; they differ only in
the declared ordering/admission owner and watermark.

Open participation remains hostile-input territory. Membership and work packets
must preserve provenance, taint, license/export, and trust labels; apply rate,
resource, spend, context, and authority bounds; support quarantine; and prevent
participant messages, artifacts, mappings, or evaluator suggestions from
automatically entering durable memory, ontology, routing policy, authority, or
production state. Sybil signals, affiliation disclosure, reviewer independence,
anti-collusion policy, backpressure, and fair resource allocation are room
admission concerns rather than optional UI moderation.

## Hypervisor As Coordination Substrate

Hypervisor is the reference coordination substrate, router, governance surface,
local control plane, and receipt aggregator for AIIP-powered autonomous work.
It is not a global meta-harness above every agent runtime. Hypervisor Core,
the Workflow Compositor, selected HarnessProfiles, agent harness adapters, and
daemon gates let heterogeneous harnesses interoperate without becoming runtime
truth.

Canonical formulation:

```text
Hypervisor routes.
Selected harnesses, workers, services, and modules execute under daemon gates.
AIIP hands off.
Receipts attest boundary facts.
Verifiers and acceptors evaluate outcomes.
IOI settles selected accepted or adjudicated commitments.
```

Hypervisor should use AIIP internally for local microharness routing and
externally for worker, service, and peer autonomous-system handoffs. Hypervisor
clients and application surfaces remain operator views over Hypervisor Core;
they are not the protocol and not IOI L1.

## Routing Decisions And Receipts

Meaningful routing decisions should emit routing receipts, especially when they
affect payment, reputation, trust, settlement, or dispute posture.

The canonical decision object is
[`RoutingDecisionEnvelope`](./common-objects-and-envelopes.md#routingdecisionenvelope).
It owns the candidate and affiliation commitments, selected Worker composition,
mounted model/provider/runtime dependencies, attempted and actual route refs,
fallback and verifier escalation, contributor policy, and first-party seed-
supply/independence evidence. AIIP carries the decision or its permitted refs;
it does not define a parallel receipt schema.

The canonical `RoutingDecisionReceipt` field schema is owned by
[`events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md).
That receipt must bind the `routing-decision://...` identity and decision hash,
policy/version, selected route, actual attempts, and declared evidence refs. It
attests those bound routing facts; it does not prove optimality, quality,
independence, or fairness by receipt existence alone.

Routing receipts answer:

- why a harness, worker, service, or peer autonomous system was selected;
- whether the selected worker or domain was eligible;
- which Worker composition and model/provider/runtime dependencies were mounted;
- which candidates were affiliated, first-party, subsidized seed supply, or
  independently operated and what evidence supported that posture;
- whether authority and budget were respected;
- whether a cheaper, safer, more private, or more capable option was ignored;
- whether a first-party service was silently favored;
- which routes were attempted in fact, what fallback/escalation occurred, and
  whether independent verification was triggered.

## IOI Mainnet Relationship

IOI mainnet is the generic settlement layer for autonomous systems. AIIP
handoffs may anchor to IOI mainnet when the handoff needs:

- autonomous-system identity roots;
- worker or provider identity roots;
- authority lease commitments;
- receipt root commitments;
- global reputation events;
- payment, escrow, payout, refund, or slashing;
- dispute bond and finality records;
- AIIP channel, profile, schema, endpoint, or capability registration;
- routing receipt roots;
- cross-system handoff finality.

Local receipts and room updates stay local unless another trust boundary needs
them. Mainnet is for sparse shared trust and economics, not an autonomous-system
chain per worker, a transaction per attempt, or a publication rail for raw room
context.

## First-Party Applications

aiagent.xyz and sas.xyz are first-party applications of AIIP and IOI
settlement. They are not the whole protocol.

```text
IOI mainnet
  generic settlement layer for autonomous systems

AIIP
  generic interop protocol for bounded autonomous work

aiagent.xyz
  first-party marketplace for workers, agents, modules, benchmarks, and invocations

sas.xyz
  first-party marketplace for outcomes, services, acceptance, escrow, and disputes

Hypervisor
  first-party Hypervisor Core clients, application surfaces, workflow
  compositor, harness-profile mediation, router, and governance substrate

Third-party systems
  any custom autonomous system that wants to settle receipts, authority, payments,
  reputation, disputes, or handoffs through IOI
```

Canonical line:

> **The marketplace is not the protocol. The marketplace is a first-party
> application of the protocol.**

## Independent AS-L1s

Independent autonomous-system L1s, appchains, sovereign domains, enterprise
runtimes, marketplaces, DAOs, and robot fleets are allowed and encouraged when
they specialize locally and settle globally.

Doctrine:

> **Sovereignty at the edge. Settlement at the center.**

These systems may own local state, governance, matching logic, service
categories, worker modules, UX state, and private receipts. They should rely on
IOI mainnet for shared trust primitives such as identity, authority, receipt
formats, reputation commitments, dispute finality, AIIP channel registration,
settlement accounts, and routing receipt schemas.

The intended builder promise is not "deploy everything on IOI." It is "build an
autonomous system where it belongs, speak AIIP at the boundary, and settle the
consequential record through IOI when shared trust is required."

## Lessons From IBC

IBC moved tokens and messages between sovereign chains. AIIP moves delegated
work, authority, receipts, and settlement claims between bounded autonomous
systems.

AIIP should improve on IBC-style friction by making interop:

- intent-native rather than path/channel-native for users;
- receipt-native rather than message-delivery-only;
- work-native rather than token-transfer-led;
- economically native for relay/router fees, bonds, SLAs, and reliability
  receipts;
- observable through route trace, packet status, receipt status, authority
  status, escrow status, dispute status, and recovery recommendations;
- privacy-aware through public roots, private receipt bodies, selective
  disclosure, encrypted artifacts, and permissioned evidence;
- conformance-driven through profiles, schemas, replay harnesses, and
  compatibility tests.

Canonical line:

> **IBC moved tokens and messages. AIIP moves delegated work, authority,
> receipts, and settlement claims.**

## Anti-Patterns

Do not model AIIP as:

```text
a separate bespoke interop API per app
a raw message bus with no authority or receipts
a requirement that every handoff settles on L1
a way to bypass daemon policy or wallet.network authority
a marketplace-only protocol
a public-disclosure default for private execution data
a shared mutable room database or universal conductor
an implicit federated-consensus layer with no declared ordering/admission owner
an untyped semantic mapping or actuator-command bypass
```

Correct model:

```text
same semantic protocol across local and external handoffs
different transport and settlement mode by profile
authority leases travel with work
receipts attest declared boundary facts
semantic profiles and mappings stay explicit
verifiers, acceptors, and adjudicators remain distinct
settlement intents promote only what needs public trust
```

## Related Canon

- [`common-objects-and-envelopes.md`](./common-objects-and-envelopes.md):
  shared AIIP envelope and ID vocabulary.
- [`ioi-l1-mainnet.md`](./ioi-l1-mainnet.md): public settlement layer for
  consequential records.
- [`../components/wallet-network/doctrine.md`](../components/wallet-network/doctrine.md):
  authority leases and approval scopes.
- [`../components/daemon-runtime/default-harness-profile.md`](../components/daemon-runtime/default-harness-profile.md):
  local daemon profile that can route work through AIIP.
- [`../components/daemon-runtime/events-receipts-delivery-bundles.md`](../components/daemon-runtime/events-receipts-delivery-bundles.md):
  receipt and event shapes used by handoffs.

## Non-Negotiables

1. Do not require every autonomous action to settle on mainnet.
2. Do not turn IOI into an execution chain for model inference or workflow
   execution.
3. Do not create separate bespoke interop APIs for Hypervisor, aiagent.xyz,
   sas.xyz, and third-party autonomous systems when AIIP semantics apply.
4. Do not let every appchain create isolated authority, reputation, and receipt
   standards.
5. Do not depend on unpaid relayers as public-good infrastructure for
   consequential handoffs.
6. Do not expose low-level path or channel complexity to end users.
7. Do not let first-party marketplaces silently bias routing without routing
   receipts.
8. Do not make public disclosure the default for sensitive enterprise execution
   data.
9. Do not treat a model, worker, runtime node, or provider dependency as an
   independent party unless an accountable principal accepts distinct rights,
   obligations, challenge, and settlement roles.
10. Do not create a CollaborativeWorkGraph with implicit global truth. Every
    room must name hosted or federated ordering and admission semantics.
11. Do not promote participant packets into memory, ontology, routing,
    production, or settlement merely because they are signed or popular.
12. Do not transport a physical actuator command as ordinary AIIP work. The
    physical-action safety envelope and certified local-control path remain
    mandatory.
13. Do not equate environment or channel recovery with outcome recovery, and do
    not retry an ambiguous external effect without its declared recovery and
    reconciliation policy.

## Open Protocol Workstreams

The canonical doctrine is settled, but protocol specs still need to define:

- mandatory receipt schemas by AIIP profile;
- minimum roots required for global interoperability;
- context-aware reputation models;
- dispute models and evidence disclosure rules;
- wallet.network authority lease types;
- settlement assets and account abstraction;
- relay/router fee, bond, SLA, and penalty mechanics;
- AIIP version, schema, and profile governance;
- conformance tests for third-party autonomous systems and AS-L1s;
- privacy limits for receipt bodies, artifacts, and execution traces.
- collaboration-profile membership, lease, frontier, attempt, finding,
  challenge, and admission packet schemas;
- hosted-admission failure/recovery semantics and later federated ordering,
  quorum/adjudication, conflict, and failover profiles;
- ontology/action-profile compatibility negotiation, mapping receipts, and
  challenge/replay fixtures;
- retry, cancellation, ambiguous-effect reconciliation, compensation, and
  idempotency conformance across transports;
- an end-to-end demonstration across two independently operated
  Hypervisor/Agentgres domains with no shared raw operational database and no
  mandatory L1 dependency.

## One-Line Doctrine

> **AIIP is the signed, semantic, receipt-native work and collaboration interop
> fabric for bounded autonomous systems; each domain keeps local truth, and IOI
> mainnet settles only the selected consequential record that needs shared
> rights, reputation, dispute, or economic finality.**
