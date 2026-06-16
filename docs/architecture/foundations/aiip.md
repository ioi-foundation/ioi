# AIIP: Inter-Autonomous-System Protocol

Status: canonical architecture authority.
Canonical owner: this file for AIIP, bounded-execution-domain interop, work packets, AIIP profiles, and cross-system handoff semantics.
Supersedes: product prose that treats Hypervisor, aiagent.xyz, sas.xyz, or third-party autonomous systems as separate bespoke interop protocols.
Superseded by: none.
Last alignment pass: 2026-05-30.

## Canonical Definition

**AIIP is IOI's RPC-shaped, receipt-native interoperability protocol for
bounded autonomous work.**

AIIP moves delegated work, authority leases, receipt commitments, settlement
intents, reputation queries, dispute notices, and handoff finality across
bounded execution domains. IOI mainnet settles the consequential record when
public trust, economic finality, reputation portability, dispute resolution, or
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
Receipts prove what happened.
IOI mainnet settles the consequential record.
```

The chain does not execute most model inference, browser activity, API calls,
file edits, workflow steps, robot actions, human review, VM jobs, or artifact
generation. The chain settles claims that work happened under known rules.

Canonical distinction:

```text
Execution = local runtimes, microharnesses, workers, APIs, robots, VMs, enterprise systems
Interop   = AIIP packets, profiles, channels, authority, receipts, settlement intents
Settlement = IOI mainnet roots, rights, escrows, disputes, reputation, handoff finality
```

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
system.commitReceipt()
system.settle()
system.dispute()
```

Underneath, these calls compile into signed, sequenced, receipt-aware packets.

Canonical analogy:

> **RPC is the call shape. IBC is the trust model. IOI is the settlement layer.**

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

AuthorityQueryPacket
  Does this worker, system, or domain have authority to perform this action?

AuthorityGrantPacket
  This authority lease is valid for this scope, time, budget, subject, and policy.

ReceiptCommitmentPacket
  This work was performed; here is the receipt root or inclusion proof.

SettlementIntentPacket
  Release payment or update reputation if these receipt conditions are satisfied.

DisputePacket
  Challenge this outcome, receipt, authority use, payment, routing choice, or settlement claim.

ReputationQueryPacket
  Return reputation under this context, rubric, worker class, or dispute history.
```

## AIIP Envelope

The canonical packet envelope should include:

```yaml
AIIPEnvelope:
  message_type: capability_discovery | task_offer | task_acceptance | handoff | authority_query | authority_grant | receipt_commitment | settlement_intent | dispute | reputation_query
  system_id_from: system://...
  system_id_to: system://...
  channel_id: aiip://channel/...
  sequence_or_nonce: string
  timestamp_or_slot: string
  profile: local | installed_worker | marketplace_worker | outcome_service | autonomous_system | enterprise
  policy_hash: hash
  authority_ref: optional grant://...
  payload_hash: hash
  receipt_obligations: []
  settlement_terms:
    mode: local_only | optional_anchor | mainnet_required | dispute_only | reputation_only
    settlement_account_ref: optional
    escrow_ref: optional
    dispute_window: optional
  signature:
    scheme: ed25519 | secp256k1 | ml-dsa | hybrid
    public_key_ref: string
    signature: base64
```

AIIP payload bodies may remain private, encrypted, redacted, or available only
to dispute participants. Public settlement should anchor commitments and roots,
not sensitive operational payloads.

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

Enterprise Profile
  Private execution, redacted receipts, encrypted artifacts, selective disclosure,
  permissioned evidence, optional public roots.
```

Profiles preserve one semantic protocol while allowing local, marketplace,
enterprise, and inter-system variants.

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
Receipts prove.
IOI settles.
```

Hypervisor should use AIIP internally for local microharness routing and
externally for worker, service, and peer autonomous-system handoffs. Hypervisor
IDE remains an operator console; it is not the protocol and not IOI L1.

## Routing Receipts

Meaningful routing decisions should emit routing receipts, especially when they
affect payment, reputation, trust, settlement, or dispute posture.

```yaml
RoutingDecisionReceipt:
  intent_hash: hash
  candidate_set_commitment: hash
  selected_domain_or_worker: system://... | worker://... | service://... | runtime://...
  routing_policy_hash: hash
  authority_scope: []
  cost_bound: optional
  receipt_obligations: []
  reason_code: string
  fallback_policy: optional
```

Routing receipts answer:

- why a harness, worker, service, or peer autonomous system was selected;
- whether the selected worker or domain was eligible;
- whether authority and budget were respected;
- whether a cheaper, safer, more private, or more capable option was ignored;
- whether a first-party service was silently favored;
- what fallback path was available.

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

Local receipts can stay local. Mainnet is for shared trust and economics.

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
```

Correct model:

```text
same semantic protocol across local and external handoffs
different transport and settlement mode by profile
authority leases travel with work
receipts prove what happened
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

## One-Line Doctrine

> **AIIP is the work interop fabric for bounded autonomous systems; IOI mainnet
> is the settlement layer for the consequential record.**
