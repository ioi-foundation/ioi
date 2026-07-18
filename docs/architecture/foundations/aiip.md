# AIIP: Inter-Autonomous-System Protocol

Status: canonical architecture authority.
Canonical owner: this file for AIIP, the boundary from pre-AIIP local-agent pairing into participation, bounded-execution-domain interop, work, collaborative-pursuit, and dispute packets, semantic-profile negotiation, AIIP profiles, and cross-system handoff/admission semantics.
Supersedes: product prose that treats Hypervisor, aiagent.xyz, sas.xyz, or third-party autonomous systems as separate bespoke interop protocols.
Superseded by: none.
Last alignment pass: 2026-07-16.
Doctrine status: canonical
Implementation status: planned for AIIP transport (the shared registered dispute schema, invariants, fixtures, and generated projections are contract substrate; dispute admission/allocation, local-agent pairing ingress, AIIP transport/binding, channel, collaboration-terms or semantic negotiation, collaborative-pursuit, cross-domain dispute exchange, and two-sovereign-system implementation remain planned)
Last implementation audit: 2026-07-18

## Canonical Definition

**AIIP is IOI's RPC-shaped, receipt-native interoperability protocol for
selective, positive-surplus bounded autonomous work.**

AIIP moves delegated work, collaborative-pursuit updates, negotiated semantic
profiles, authority leases, receipt commitments, settlement intents, reputation
queries, dispute notices, and handoff finality across independently governed
bounded execution domains.
Each domain keeps its own runtime, private context, operational truth,
governance, and ordering/finality. AIIP assumes neither consensus nor IOI L1.
Explicitly enrolled systems may use IOI L1 for selected accepted or adjudicated
commitments when public trust, economic finality, portable reputation or
rights, dispute resolution, or shared security creates value.

Short form:

> **AIIP moves bounded work across systems. Each system admits its own truth.
> Explicitly enrolled systems may use IOI L1 for selected shared-trust
> commitments.**

The broader IOI thesis is:

> **IOI turns intelligence into bounded autonomous institutions. L0 creates
> and operates them through native same-system distribution; AIIP makes
> selective, positive-surplus interoperation between separately sovereign
> institutions contractible; IOI L1 optionally supplies shared trust and
> economic finality.**

## Conditional Cooperation Thesis

AIIP creates an option to interoperate, not a reason or duty to do so. A
sovereign system remains complete without federation, marketplace
participation, external contribution, or IOI Network enrollment. It uses AIIP
only when another independently governed domain controls a complement whose
expected value exceeds the best permitted local or bilateral alternative after
coordination and risk costs.

Relevant complements include specialized intelligence, protected data-derived
evidence, local authority or jurisdiction, physical access, compute or capital,
demand, independent verification, insurance, dispute resolution, and neutral
settlement. Relevant costs include execution, latency, semantic translation,
verification, disclosure and IP exposure, opportunity cost, counterparty risk,
dispute, settlement, switching, and dependency risk.

Participant-level admission is therefore conditional:

```text
expected cooperation surplus_i
  = expected utility under accepted collaboration terms_i
  - expected utility of best permitted outside option_i
  - incremental cooperation costs_i

incremental cooperation costs_i include execution, opportunity, search,
  semantic-mapping, coordination, verification, privacy, IP, counterparty,
  dispute, settlement, switching, and dependency costs and risks

participate only when expected cooperation surplus_i > 0
  and the constitution, policy, authority, privacy, and terms gates admit it
```

The valuation may remain private. The protocol proves only that each required
party accepted one exact `CollaborationTermsEnvelope` root through its governed
decision path. Discovery, compatibility, room visibility, task offers, and
terms proposals create no obligation, access, award, contribution eligibility,
or payout. `TaskOffer` solicits; `TaskAcceptance` accepts, rejects, or
counteroffers; `RoutingDecision` selects; `WorkClaimLease` awards bounded work;
`Contribution`, verification, `AcceptanceDecision`, adjudication, and
`SettlementIntent` remain later distinct stages.

Short form:

> **Sovereignty protects the downside; complementary value supplies the motive;
> accepted terms make cooperation contractible.**

## Layer Boundary

Autonomous work should usually execute off chain and close to its authority,
data, tools, models, users, or physical environment.

```text
Autonomous systems execute anywhere.
Native L0 contracts coordinate continuity and useful work inside one system.
AIIP exchanges delegated work across systems.
Receipts attest declared boundary facts.
Each system admits its own truth.
Selected enrolled commitments may use IOI L1.
```

The chain does not execute most model inference, browser activity, API calls,
file edits, workflow steps, robot actions, human review, VM jobs, or artifact
generation. The chain may settle accepted or adjudicated claims under known
rules; it does not turn a signed statement into a correct outcome.

Canonical distinction:

```text
Execution = local runtimes, HarnessInvocations, workers, APIs, robots, VMs, enterprise systems
Interop   = AIIP packets, profiles, channels, authority, receipts, settlement intents
Settlement = local-domain by default; a declared external profile only when
             selected; IOI L1 only under explicit enrollment
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

- local agent runtimes executing coding, browser, terminal, design, finance,
  or research steps through admitted HarnessProfiles or AgentHarnessAdapters;
- installed workers from aiagent.xyz;
- marketplace workers;
- outcome providers from sas.xyz;
- robot fleets;
- DAO-owned operators;
- enterprise private runtimes;
- third-party autonomous systems;
- independent autonomous-system L1s or sovereign domains.

AIIP lets independently governed bounded execution domains interoperate. Their
settlement system is a declared profile, not an AIIP assumption. A bounded
execution domain may itself span many runtime nodes, people, robots, drones,
sensors, controllers, or facilities. Their internal replication, failover,
mission allocation, runtime assignment, work leases, shared state/evidence,
fleet policy, and local safety are native L0 and Embodied Runtime coordination,
not AIIP. AIIP begins only when one such domain crosses into another domain's
separate governance, authority, truth, risk, and exit boundary.

Robot fleets, robot controllers, drones, vehicles, facility systems, and other
embodied domains are valid AIIP participants, but actuator-affecting work is
not ordinary AIIP traffic. Any handoff or command envelope that can produce a
`physical_action` must bind `PhysicalActionPolicy`, `SafetyEnvelope`,
`EmergencyStopAuthority`, required supervision policy, sensor evidence
obligations, and `ActuatorCommandReceipt` obligations before execution. The
canonical owner for those objects is
[`physical-action-safety.md`](./physical-action-safety.md).

An inbound AIIP packet remains candidate intent or work at the receiving
sovereignty boundary. The receiver must re-admit it into local work-subject,
mission, allocation, resource-fence, authority, and safety state before any
physical effect. It may eventually produce a proposal-only
`EmbodiedActionChunk`, but the packet cannot install or activate an
`EmbodiedRuntimeGraphManifest`, arm a controller, acquire a
`SpacetimeReservationLease`, bypass the `LocalControlSupervisor`, or command an
actuator. Cross-system agreement and local physical admission are separate
decisions with separate receipts.

## First-Mile Local Agent Pairing Is Pre-AIIP

ioi.ai and aiagent.xyz may accept an already-running, user-owned local agent or
harness without claiming to verify its hidden cognition or taking over its
runtime. The first-mile boundary is the shared
[`LocalAgentPairingSessionEnvelope`](./common-objects-and-envelopes.md#localagentpairingsessionenvelope).
It is a short-lived authentication and bootstrap contract, not an AIIP channel,
an authority grant, a participant lease, a Worker installation, or proof of
model, harness, tool, environment, or operator claims.

The product targets are exact:

```text
ioi.ai / Goal Space / Add local contributor
  -> target_kind: room_guest
  -> propose one room-scoped WorkerComposition
  -> submit one RoomParticipationRequest

aiagent.xyz / My workers / Connect local worker
  -> target_kind: private_worker
  -> propose one user-private reusable WorkerComposition

aiagent.xyz / Organization workers / Connect local worker
  -> target_kind: organization_worker
  -> propose one organization-scoped WorkerComposition for separate org admission
```

Hypervisor or another conforming local adapter may provide the loopback helper,
device-code client, or copyable bootstrap command. An ioi.ai or aiagent.xyz
modal may render those choices. The surface and transport are projections over
the same pairing object; neither becomes protocol authority. Any authentication
material carried by the copy-command path must be one-time and short-lived,
never a durable account token, broad organization credential, private room
context, connector secret, or authority lease.

The product-to-protocol flow is:

```text
authenticated product user creates LocalAgentPairingSessionEnvelope
  -> product issues one short-lived, single-use challenge
  -> already-running local client proves the challenge
  -> session binds the client public key and declared origin
  -> bootstrap_bound permits only:
       read_discovery
       submit_worker_composition
       submit_room_participation_request
  -> submitted WorkerComposition remains a tainted proposal
  -> for room_guest, the bound client submits RoomParticipationRequestEnvelope
  -> the first room_participation AIIP packet begins AIIP
  -> room host or federation policy evaluates the request
  -> admission may create RoomParticipantLeaseEnvelope and restricted views
  -> only then may the participant claim work or publish typed proposals
```

The pairing state vocabulary is exact and reflects observed lifecycle rather
than optimistic UI copy:

| Status | Meaning |
| --- | --- |
| `created` | A product-side session exists; no challenge has been issued. |
| `challenge_issued` | A short-lived, single-use challenge is outstanding. |
| `agent_proof_received` | Candidate proof arrived but is not yet a usable bootstrap binding. |
| `bootstrap_bound` | Challenge, client key, origin, target, and closed bootstrap scope matched. No participation or authority exists. |
| `composition_submitted` | A typed WorkerComposition proposal was recorded for admission evaluation, not admitted, installed, or invoked. |
| `participation_submitted` | A typed RoomParticipationRequest was sent in the first AIIP participation packet, not admitted. |
| `completed` | The target-specific bootstrap submissions exist. This does not mean Worker, room, authority, budget, or outcome acceptance. |
| `expired` | The pairing window elapsed before completion. |
| `rejected` | Pairing/bootstrap policy rejected the session before completion; downstream Worker or room rejection remains on its own object. |
| `cancelled` | The initiating user or product cancelled the session. |
| `revoked` | Future bootstrap use was terminated after a binding existed. |
| `failed_closed` | Replay, invalid proof, key/origin drift, scope escalation, malformed input, or another invariant violation prevented partial use. |

Changing target, key, origin, discovery scope, or requested bootstrap actions
requires a new pairing session. The one-time authentication factor is consumed
atomically on successful binding and cannot become a reusable bearer token.
The bootstrap action list is closed: it grants no room database access, private
context, connector or secret access, budget, spend, authority, effect execution,
membership, claim lease, marketplace publication, or organization
representation.

A `prompt_only` agent is confined to the proposal lane. Pairing can attribute
its submissions to the bound client key and origin, but its unverified claims
have an `attested` assurance ceiling. Independent evidence, reproduction, a
named verifier, and an acceptor may advance a specific WorkResult or
OutcomeDelta later. They do not retroactively verify the hidden agent identity,
model, reasoning, runtime, tools, independence, or originality.

Pairing introduces no new receipt type. Existing Worker-composition,
participation, runtime-event, evidence, verification, acceptance, dispute, and
settlement owners remain authoritative for their own facts and lifecycle.

## Shared Conventions, Different Sovereignty Boundaries

Hypervisor should reuse compatible work, authority, idempotency, evidence, and
receipt conventions across internal and external routes so implementations do
not require needless adapters. Reuse does not make an internal handoff AIIP.

Same-system routing uses native L0 membership, `RoleTopology`,
`RuntimeAssignment`, GoalRun/work leases, domain state and evidence, and—where
physical—Embodied Runtime, controller, fleet-policy, and local-safety contracts.
It may use in-process calls, daemon IPC, Unix sockets, local HTTP, gRPC,
JSON-RPC, NATS, or a daemon bus and may emit local receipts only.
Consequentiality may require stronger local authority and evidence, but it does
not create a cross-system protocol or public-settlement requirement.

AIIP routing begins only at an independently governed system boundary. It uses
signed AIIP envelopes, exact collaboration terms, separately admitted
participant/work/resource/authority leases, receipt obligations, recovery and
dispute semantics, and only the public commitments selected by the parties'
enrollment and settlement profiles.

Canonical rule:

> **Share semantic conventions where useful; reserve AIIP for independently
> governed system boundaries.**

## Standards Bindings, Not Replacements

AIIP should compose with the emerging agent ecosystem instead of competing for
generic discovery, tool invocation, remote-task transport, or EVM escrow. A
versioned `AIIPExternalProtocolBindingEnvelope` maps an external protocol's
identities, messages, lifecycle states, artifacts, errors, and receipts into
AIIP semantics without weakening IOI authority or assurance.

### A2A Binding

[A2A](https://a2a-protocol.org/latest/specification/) is an optional remote-
agent task and artifact transport. Its Agent Card, Task, context, Message,
status, and Artifact identities map into AIIP capability, correlation, task,
payload, delivery, and result refs. An A2A task reaching `completed` proves only
that the remote participant reported completion under A2A. It does not imply
IOI evidence verification, acceptance, authority, adjudication, or settlement.
AIIP-specific fields should use the standard's extension mechanism rather than
forking its transport.

### MCP Binding

[MCP](https://modelcontextprotocol.io/specification/latest) remains the
model/application-to-context, tools, prompts, and resources boundary. An MCP
`tools/call` entering consequential IOI work compiles through
`RuntimeToolContract`, `ActionRequest`, daemon admission, policy/authority, and
receipts. MCP does not establish peer-system trust, grant wallet authority, or
replace AIIP task/evidence/dispute semantics. MCP and AIIP therefore compose at
different layers.

### Directory And Schema Bindings

AGNTCY/OASF-compatible identity, directory, and capability-schema records may
populate discovery adapters. They remain identity and capability evidence—not
wallet authority, a canonical IOI Domain Ontology, competence, independence,
quality, or operational truth. Likewise, `ai://` is an optional IOI-connected
resolver/registry binding. A compatible system may use DNS, A2A Agent Cards,
OASF, another registry, or direct configuration and still speak AIIP.

### EVM Registry And Escrow Bindings

Draft ERC-8004 may bind EVM agent identity and reputation registry records, and
draft ERC-8183 may bind a job-escrow/evaluator lifecycle. Both are optional
adapters. Registration cannot prove advertised capability or non-maliciousness;
an escrow evaluator decision cannot collapse IOI's evidence, verification,
acceptance, adjudication, appeal, and settlement ladder. Draft status and exact
versions remain explicit on the binding object.

Canonical rule:

> **Reuse standards for the boundary they own; preserve IOI's differentiated
> constitution, machine-authority, semantic-action, operational-evidence,
> lifecycle, and assurance contracts above them.**

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

> **RPC is the call shape. IBC is a useful sovereign-interop analogy. AIIP binds
> work, authority, evidence, and recovery without prescribing one transport,
> consensus system, registry, or settlement layer.**

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

CollaborationTermsProposalPacket
  Propose or amend the exact objective, roles, obligations, rights, disclosure,
  contribution, consideration, risk, exit, and settlement terms root.

CollaborationTermsResponsePacket
  Accept the exact terms root, counteroffer with a new terms ref/root, or decline.
  Response alone creates no membership, authority, work award, or payout.

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

The collaboration-terms packet payloads are typed profiles of the signed
`AIIPEnvelope`; they are not additional durable envelope families:

```yaml
CollaborationTermsProposalPacketPayload:
  schema_version: ioi.aiip.collaboration-terms-proposal.v1
  collaboration_terms_ref: terms://...
  collaboration_terms_root: hash
  predecessor_terms_ref: terms://... | null
  scope_ref:
    collaboration://... | outcome-room://... | task://... |
    frontier://... | order://... | service://... | aiip://channel/...
  proposed_by_ref: system://... | domain://... | org://... | service://...
  proposer_decision_ref: decision://... | null
  proposer_signature: required

CollaborationTermsResponsePacketPayload:
  schema_version: ioi.aiip.collaboration-terms-response.v1
  proposal_packet_ref: packet://...
  responding_party_ref:
    system://... | domain://... | org://... | wallet://... |
    service://... | provider://...
  collaboration_terms_ref: terms://...
  collaboration_terms_root: hash
  response: accept | counteroffer | decline
  counterterms_ref: terms://... | null
  counterterms_root: hash | null
  participation_decision_ref: decision://... | null
  terms_acceptance_receipt_ref: receipt://... | null
  response_hash: hash
  signature: required
```

For `accept`, counterterms fields are null and the responding domain may issue
`terms_acceptance_receipt_ref` only after its governed decision admits the
response. For `counteroffer`, both counterterms fields are required, the
original root remains the root being declined, and the counterterms become a
new proposal requiring acceptance. For `decline`, counterterms and acceptance-
receipt fields are null. `response_hash` binds every response field except the
signature; the signed `AIIPEnvelope.payload_hash` binds the complete payload.
No response grants membership, authority, work, reputation, or payout.

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
  Same-node HarnessInvocation and Worker routing, local receipts, optional settlement.

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
multi-node = distinct execution or failure domains, possibly inside one system
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
local control plane, and receipt aggregator for autonomous work, including
native same-system distribution and AIIP federation.
It is not a global meta-harness above every agent runtime. Hypervisor Core,
the Workflow Compositor, selected HarnessProfiles, agent harness adapters, and
daemon gates let heterogeneous harnesses interoperate without becoming runtime
truth.

Canonical formulation:

```text
Hypervisor routes.
Selected harnesses, workers, services, and modules execute under daemon gates.
Native L0 assignments and leases coordinate members inside one system.
AIIP hands off across independently governed systems.
Receipts attest boundary facts.
Verifiers and acceptors evaluate outcomes.
The declared settlement profile handles selected accepted or adjudicated commitments.
```

Hypervisor should use native L0 assignment, lease, domain-state/evidence, and
Embodied Runtime contracts for local HarnessInvocation and same-system member
routing. It should use AIIP for external worker, service, and peer-system
handoffs only when the counterparty is independently governed. Hypervisor
clients and application surfaces remain operator views over Hypervisor Core;
they are not the protocol and not IOI L1.

## AIIP Dispute Rail

AIIP transports dispute proposals, case-head updates, evidence refs, responses,
resolution decisions, and permitted receipts between independently governed
domains. It does not become either domain's adjudicator, escrow, balance ledger,
or settlement authority.

An `aiip_dispute` case uses the shared `DisputeRailProfileEnvelope`,
`DisputeEnvelope`, and `DisputeResolutionEnvelope`. It must bind the exact
accepted `CollaborationTermsEnvelope` ref and body root, the current case head,
the selected profile ref/version/body hash, and ordinary verification funding
that is separate from ordinary Work Credits. The counterparties may select a
local, bilateral, external escrow/chain, or explicitly enrolled IOI settlement
path; AIIP compatibility alone selects none of them.

V1 carries one exact `DisputeValueUnitBinding` for disputed value, remedy,
party bonds, and bond allocation. It allows no cross-domain asset, deployment,
denomination, decimal, Work Credit, or display-code substitution and performs
no conversion. If counterparties need different bond and remedy assets, their
terms must select a future explicit conversion-capable rail rather than
mislabeling v1 units.

An admitted resolution is a deterministic, challengeable decision and
allocation plan. The receiving domain still verifies provenance and authority,
records its local truth, executes any remedy through its selected settlement
owner, emits receipts, and applies appeal/finality rules. Packet delivery or
matching receipt hashes do not prove evidence truth, value movement, bilateral
acceptance, or public finality.

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

IOI mainnet is an optional neutral trust and economic-finality service for
`ioi_connected` and `ioi_secured` systems. AIIP works without it. An enrolled
handoff may anchor to IOI mainnet when the participants explicitly select:

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
  optional shared-trust and economic-finality services for enrolled systems

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
  any compatible custom autonomous system; connection or secured enrollment is optional
```

Canonical line:

> **The marketplace is not the protocol. The marketplace is a first-party
> application of the protocol.**

## Independent AS-L1s

Independent autonomous-system L1s, appchains, sovereign domains, enterprise
runtimes, marketplaces, DAOs, and robot fleets are allowed and encouraged when
they specialize locally and choose their own trust and settlement profile.

Doctrine:

> **Sovereignty at the edge. Interoperability by AIIP. Shared trust by explicit
> enrollment.**

These systems may own local state, governance, matching logic, service
categories, worker modules, UX state, and private receipts. They may use local,
external-chain, bilateral, or IOI Network trust. `ioi_compatible` requires no
registration or fee; `ioi_connected` selects specific registry, rights,
reputation, escrow, dispute, or settlement services; `ioi_secured` additionally
selects Standard DAS assurance and named shared-security services, terms, and
bonds. Receipt formats and AIIP conformance do not require IOI settlement.

The intended builder promise is not "deploy everything on IOI." It is "build an
autonomous system where it belongs, speak AIIP at the boundary, settle locally
by default, and select IOI Network services only where neutral shared trust adds
enough value to justify enrollment."

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
an assumption that local-agent pairing is an AIIP channel or authority grant
a same-system node, worker, robot, drone, or controller route mislabeled as AIIP
a presumption that compatibility, discovery, a shared goal, or message volume creates cooperation demand
a terms proposal, contribution receipt, or routing decision treated as obligation, award, allocation, or payout
a durable bearer token, broad organization credential, or room context in a bootstrap command
```

Correct model:

```text
common work, authority, evidence, idempotency, and receipt conventions where useful
native L0 and Embodied Runtime coordination inside one system_id
AIIP only across independently governed system_ids
exact-root terms acceptance precedes participant admission and work award
each required party may decline when its governed participation case is not positive
authority leases travel with work
receipts attest declared boundary facts
semantic profiles and mappings stay explicit
verifiers, acceptors, and adjudicators remain distinct
settlement intents promote only commitments explicitly selected for shared trust
```

## Related Canon

- [`common-objects-and-envelopes.md`](./common-objects-and-envelopes.md):
  shared AIIP envelope and ID vocabulary.
- [`ioi-l1-mainnet.md`](./ioi-l1-mainnet.md): optional IOI Network shared-trust
  and economic-finality service for explicitly enrolled commitments.
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
    physical-action safety envelope and native `LocalControlSupervisor` or
    separately assured local-control path remain mandatory.
13. Do not equate environment or channel recovery with outcome recovery, and do
    not retry an ambiguous external effect without its declared recovery and
    reconciliation policy.
14. Do not let a local-agent pairing factor, bound client key, prompt, persona,
    claimed harness, or completed bootstrap session imply Worker admission,
    room membership, authority, budget, runtime provenance, or verified work.
15. Do not infer cooperation demand or network value from compatibility,
    discovery, shared goals, system count, packets, receipts, or room activity.
    External work requires exact-root terms acceptance and separately admitted
    participation, claim, resource, budget, and authority leases (`INV-30`).
16. Do not call replication, failover, RuntimeAssignment, mission allocation,
    fleet coordination, or work leases among members of one `system_id` AIIP.
    Shared envelope conventions are allowed; AIIP starts only at an
    independently governed system boundary (`INV-32`).

## Open Protocol Workstreams

The canonical doctrine is settled, but protocol specs still need to define:

- mandatory receipt schemas by AIIP profile;
- minimum roots required by each conformance and enrollment profile;
- context-aware reputation models;
- dispute models and evidence disclosure rules;
- wallet.network authority lease types;
- settlement-adapter profiles and, where selected, assets/account abstraction;
- relay/router fee, bond, SLA, and penalty mechanics;
- AIIP version, schema, and profile governance;
- conformance tests for third-party autonomous systems and AS-L1s;
- privacy limits for receipt bodies, artifacts, and execution traces;
- local-agent pairing conformance for single-use challenge consumption,
  key/origin binding, closed bootstrap scopes, target-specific completion,
  prompt-only assurance ceilings, revocation, replay, and fail-closed behavior;
- collaboration-profile membership, lease, frontier, attempt, finding,
  challenge, and admission packet schemas;
- conformance fixtures for `CollaborationTermsEnvelope` proposal/response,
  exact-root acceptance, counteroffer/decline, private-valuation,
  non-retroactive amendment, and terms-acceptance receipts;
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

> **AIIP is the signed, semantic, receipt-native interop fabric for voluntarily
> accepted, terms-bound work between bounded autonomous systems. Each domain
> keeps local truth and may decline when no positive participation case exists;
> explicitly enrolled systems may use IOI L1 for selected rights, reputation,
> assurance, dispute, security, or economic commitments.**
