# ioi.ai Collaborative Outcome Pattern

Status: canonical architecture authority.
Canonical owner: this file for ioi.ai's Goal Space and intent-to-outcome
coordination pattern, goal-appropriate single-path and collaborative pursuit,
OutcomeRoom/CollaborativeWorkGraph product behavior, shared evidence
projections, attempt comparison, and final ownership synthesis.
Supersedes: product prose that treats multi-model goal pursuit as a separate
Hypervisor product, room UI, fixed swarm, public leaderboard, or benchmark-only
workflow.
Superseded by: none.
Last alignment pass: 2026-07-12.
Doctrine status: canonical
Implementation status: partial (bounded GoalRun multi-harness orchestration
built; collaboration-terms negotiation, general OutcomeRoom participation,
shared-frontier, cross-domain, local-agent pairing/admission, and attempt-
comparison behavior remain planned)
Last implementation audit: 2026-07-05

## Canonical Definition

**ioi.ai is the outcome conductor built on Hypervisor, and a Goal Space is its
durable product container for pursuing one outcome.**

ioi.ai is the first-party proof that Hypervisor can produce high-level
autonomous products. It turns user goals into governed Hypervisor work,
cross-session outcome graphs, connector/auth handoffs, Foundry proposals, and
final ownership synthesis. It is not the main runtime, not the authority layer,
not marketplace truth, and not the only coordinator that should be possible on
the substrate.

When a goal is simple, ioi.ai may route it to one model, one worker, one
automation, one service, or one Hypervisor session.

When a goal benefits from multiple models, harnesses, tools, verifier paths,
attempt strategies, or independent contributors, ioi.ai may materialize an
`OutcomeRoom` bounded-DAS instance from the reusable OutcomeRoom package, with a
`CollaborativeWorkGraph` over Hypervisor. Genesis binds that durable room's
stable `system_id`, constitution, active profiles, and cryptographic origin. The room is the
shared objective, participation, frontier, claim, attempt, finding, challenge,
admission, and replay profile. It is not a new runtime or a globally mutable
database. Hypervisor executes bounded work; authority providers and
local/domain governance authorize as required; wallet.network supplies portable
delegated/high-risk authority; each Agentgres domain retains admitted
operational truth; and a declared room admission topology governs shared-room
state.

Collective pursuit is conditional, not the default. A room should materialize
only when specialization, parallel exploration, independent verification,
reusable negative information, shared fixed costs, or access to
non-centralizable data, authority, locality, or resources creates expected
value greater than its additional latency, spend, disclosure, semantic-mapping,
verification, counterparty, dispute, and settlement burden.

A cross-party room forms under one exact `CollaborationTermsEnvelope` root
covering sponsor, parties, roles, bounded work, rights, obligations, disclosure,
contribution eligibility, reward basis, acceptance, remedies, exit, and
settlement. Participants may seek payment, accepted-outcome rights, reciprocal
capability, licenses or royalties, portable reputation, reusable learning,
strategic value, or shared-risk reduction. Each required party accepts only
after its own governed decision finds participation constitutionally
permissible and better than its permitted outside option. Raw valuations may
remain private.

Discovery, invitation, a shared objective, or a terms proposal creates no
membership, context, authority, work, contribution eligibility, or payout.
Terms acceptance enables admission evaluation; `RoomParticipantLease` admits
participation; `WorkClaimLease` awards bounded work; contribution,
verification, acceptance or adjudication, and settlement remain distinct. A
counteroffer is only a proposal, and amendments never rewrite earlier admitted
work retroactively (`INV-30`, `INV-31`).

Doctrine sentence:

```text
ioi.ai conducts Goal Spaces across sessions, agents/workers, connectors,
claims, attempts, and verifier paths;
Hypervisor executes; authority providers and local/domain governance authorize
as required, with wallet.network mandatory for portable delegated authority and
high-risk external effects; Agentgres records; Foundry builds/evaluates;
aiagent.xyz supplies and attributes workers.
```

ioi.ai dogfoods Hypervisor. It is a first-party intent-to-outcome product built
from Hypervisor application surfaces, WorkRuns, Automations, Foundry,
operator-plane contracts, wallet authority, Agentgres truth, and receipts. It is
not privileged substrate. A user or organization should be able to build an
ioi.ai-like coordinator through Hypervisor without receiving host authority or a
separate runtime bypass.

The reusable OutcomeRoom package is the first flagship/reference bounded-DAS
profile because it pressure-tests local-agent ingress, typed workgraphs,
verification, contribution lineage, course correction, and network supply in
one observable product. Each durable room genesis creates a distinct bounded
DAS; the hosted ioi.ai service/domain operates many such systems and is not a
substitute for their logical identity. A direct GoalRun or temporary
collaboration aggregate that does not justify genesis remains non-room
application work. OutcomeRoom is not the definition of all autonomous systems
or L0: the same constitution, deployment, lifecycle, authority, and evidence
substrate must support systems with no room, chat, leaderboard, or swarm
behavior.

Conceptually:

```text
Hypervisor is the substrate.
ioi.ai is one first-party conductor product.
Other conductors should be buildable from the same surfaces and contracts.
```

Dogfooding means ioi.ai uses the same Hypervisor application-surface pipeline as
other coordinators. It may use App, Web, SDK, or CLI/headless-equivalent client
projections over declared surface contracts, but it must not own a custom
headless Hypervisor instance, direct connector path, or private operator loop.
Headless is a client projection; Hypervisor Core, the Operator Plane, daemon
admission, wallet.network, Agentgres, and receipts remain the substrate.

The useful analogy is not "copy a search-answer app" or "add a swarm chat."
The useful analogy is:

```text
multiple models and strategies may be routed toward one objective
the evidence and attempts stay comparable
the final answer or delivery owns what was learned
```

Canon should avoid turning this into a separate "meta-harness" runtime. The
product-facing terms are **Goal Space** and **outcome conductor**. Two
coordination scales compose:

```text
OutcomeRoom / CollaborativeWorkGraph
  shared objective, participants, work frontier, claims, attempts, findings,
  resources, evaluation, contribution lineage, admission, discussion
  projections, and replay

  -> GoalRun A -> bounded Goal Kernel loop -> harnesses / workers
  -> GoalRun B -> bounded Goal Kernel loop -> harnesses / workers
  -> GoalRun C -> bounded Goal Kernel loop -> harnesses / workers
```

`GoalRun` answers how one bounded intelligence or subteam grounds, pursues,
verifies, and course-corrects. `OutcomeRoom` answers how many intelligences
discover work, join or retire, claim it, exchange artifacts, publish positive
and negative attempts, challenge evaluation, and update the shared frontier.
AIIP carries that participation across independently governed domains.

The lower-level orchestration contracts remain `OrchestrationPolicy`,
`OrchestrationConstraintEnvelope`, `VerifierPath`, and
`OrchestrationDecisionReceipt`. They describe how a coordinator chooses,
explains, verifies, and later improves a plan. They do not execute work, own
authority, or become a hidden swarm.

## Owns

ioi.ai owns the user-facing coordination of:

- goal intake, constraints, preferences, and account context;
- Goal Space status, contributor-scope choice, budget projection, and final
  user-facing ownership;
- deciding whether the goal is single-path or multi-path;
- selecting a goal-appropriate coordination shape;
- selecting or applying an `OrchestrationPolicy` subject to an explicit
  `OrchestrationConstraintEnvelope`;
- selecting verifier paths that match the goal's risk, evidence, and
  acceptance posture;
- emitting orchestration decision refs when a material plan, model route,
  harness, worker set, verifier path, or session topology is selected;
- creating cross-session outcome graph projections when several sessions,
  workers, verifier paths, or attempts are useful;
- materializing an OutcomeRoom only when persistent collective pursuit is
  useful, then projecting its participant leases, work frontier, claims,
  attempts, findings, challenges, spend, authority blockers, and replay;
- presenting room-scoped **Connect local agent** intake, pairing progress,
  proposal-only preflight, admission status, revoke controls, and the choice to
  keep that participant room-only, save it privately, or explicitly promote it;
- selecting `Auto`, `Pinned`, or `Compare` execution policy for a leg without
  confusing model routes, accountable workers, runtime nodes, or independent
  parties;
- requesting Hypervisor sessions, automations, workers, services, harnesses, or
  model routes;
- detecting missing connectors, expired scopes, insufficient authority, or
  required approvals and drafting connector/auth escalation handoffs;
- showing authorized progress, evidence summaries, citations, receipts,
  screenshots, traces, run state, and unresolved uncertainty;
- comparing attempts when multiple paths are used;
- asking for human clarification, approval, or step-up when required;
- final answer/delivery synthesis after evidence, observations, receipts, and
  verifier state have returned.

## Does Not Own

ioi.ai does not own:

- Hypervisor Daemon execution semantics;
- Hypervisor Automations durable workflow/service specs;
- Hypervisor Operator Plane semantics or private operator loops;
- wallet.network authority, credentials, declassification, or spend;
- connector secrets, direct provider API calls, or connector execution truth;
- Agentgres admitted operational truth, state roots, artifact refs, archive
  refs, or restore validity;
- Foundry training, tuning, eval suites, model registry, endpoint deployment,
  simulation training, or package promotion;
- conductor-training consent, raw training data, or model-route promotion truth;
- aiagent.xyz worker listings, marketplace routing truth, or contribution
  accounting;
- aiagent.xyz reusable private-worker registration, benchmark admission,
  publication, or marketplace promotion truth;
- local Hypervisor pairing, harness-adapter, MCP-gateway, credential, or
  execution truth merely because ioi.ai presents the pairing flow;
- Hypervisor Work Credit metering truth, provider invoices, route-rights
  eligibility, or supplier-cost reconciliation;
- the operational truth of an OutcomeRoom participant's home domain or an
  implicitly global Agentgres graph;
- physical-action safety semantics;
- IOI L1 settlement by default.

## Goal Space Product Contract

ioi.ai presents one Goal Space subscription rather than separate single-node
and network-node products:

```text
Goal Space subscription
  conductor, persistent goal state, memory, policy, receipts, replay,
  collaboration, and ordinary support entitlement
  + bounded monthly grant of non-transferable Hypervisor Work Credits

additional managed work
  Work Credit top-up, overage, or committed-spend drawdown

Network / Open participation
  separately bounded goal budget, bounty, service order, or procurement limit

Enterprise / Private
  seats plus committed managed-work spend, private/customer-boundary runtime,
  reserved capacity, governance, audit, SLA, and support
```

The subscription is a seat-like outcome product, not resale of named-user
foundation-model plan limits. Same-domain 1-N worker orchestration may consume
the included or topped-up Work Credit budget. Independent worker, verifier, or
service participation uses a separately visible Network/Open goal budget. The
economic owner defines charge legitimacy and settlement; this file owns how the
choice appears in goal coordination.

Three orthogonal controls must remain distinct:

| Axis | Product choices | Meaning |
| --- | --- | --- |
| Execution/custody | `Standard` or `Private` | provider-trust disclosure and custody/proof posture |
| Contributor scope | `My workers`, `Organization`, or `Network / Open` | which accountable worker/provider domains may participate |
| Placement | local, customer infrastructure, selected provider, or Hypervisor-selected | where eligible work executes |

Contributor scope never declassifies data or widens authority. A candidate is
eligible only when its policy intersects safely with the Goal Space privacy,
retention, license, export, authority, budget, and route-rights constraints.
Making the `Private` selector available does not imply free IOI-provisioned
private compute, attestation, reserved capacity, or customer-boundary custody;
those obligations may require Work Credits, Private Workspace entitlement,
customer infrastructure, committed capacity, or an enterprise plan.

Keep four kinds of plurality visible in receipts and advanced UI:

| Shape | Distinct unit | Does not imply |
| --- | --- | --- |
| Multi-model | model routes or families | accountable worker or independent party |
| Multi-worker | versioned Worker compositions | independent authority or settlement |
| Multi-node | runtime/compute/provider failure domains | independent governance |
| Multi-party | separate principals controlling authority, truth, challenge, risk, and settlement | independence when ownership or dependencies are hidden |

Foundation models are mounted cognition, not protocol actors. The accountable
unit is a versioned Worker composition: publisher/manifest, model route,
harness/runtime entrypoint, tools/connectors, policy and authority requirements,
memory posture, verifier/receipt obligations, license, benchmark, cost, and
contribution identity.

An IOI-operated planner, builder, verifier, critic, and synthesizer fleet is
valuable seed supply, but it is one disclosed party while IOI controls its
authority, operational truth, and settlement. Seed workers use the same
versioned Worker, authority, receipt, replay, routing, and contribution
contracts as external workers and receive no hidden marketplace preference.
Each discloses IOI ownership, model/runtime/provider dependencies, subsidy, and
real cost. IOI must not circularly act as coordinator, paid worker, sole
verifier, ranking authority, and settlement judge for the same outcome. An
external worker must be able to replace or outperform a seed worker without
changing the pursuit contract. The fleet is anchor liquidity, baseline quality,
last-resort capacity, and conformance supply—not the permanent only
counterparty.

Sell the governed Goal Space, not physical node count. One logical Hypervisor
domain may place many workers across machines, clouds, model providers, and
failure domains while remaining one authority, truth, and settlement domain.
The UI label does not determine the protocol boundary: an `Organization` room
spanning sovereign domains requires `MultiPartyCollaborationEnvelope`, while a
`Network / Open` room served only by IOI-owned seed workers remains one party
until an independent principal joins.
A model or cloud provider is normally a disclosed dependency/subprocessor, not
a room party. It becomes a party only when its controlling principal accepts
room-level rights, obligations, evidence, challenge, or settlement roles.

## Bring An Existing Local Agent

**ioi.ai should let a user connect an existing local agent to one Goal Space
without requiring that agent to become a public marketplace listing.** The
product promise is not that IOI can prove the agent's hidden cognition or
runtime merely because it paired successfully. The promise is narrower and
useful: an untrusted local agent can receive bounded work, make typed
proposals, and accumulate attributable evidence without receiving ambient room
access or direct authority.

The three product elevations are explicit and independently reversible:

| Elevation | User-facing action | Canonical scope |
| --- | --- | --- |
| One-room guest | **Connect local agent** | ioi.ai binds a local agent to one Goal Space/OutcomeRoom through a bounded pairing and participation request. The guest is not reusable outside that room and has no aiagent.xyz listing. |
| Reusable private worker | **Save to My workers** | aiagent.xyz registers the exact Worker composition for the owner or organization as private reusable supply. This does not submit, benchmark, rank, route publicly, or disclose it. |
| Public marketplace candidate | **Publish on aiagent.xyz** | The owner explicitly creates a promotion/submission, accepts disclosure and license terms, completes applicable benchmark/admission gates, and separately publishes the resulting listing. |

No elevation is automatic. Room participation does not create a reusable
private worker; saving a private worker does not create a benchmark submission;
benchmarking does not publish a listing; and a public listing does not widen an
existing room lease. Promotion copies only the manifest fields, artifacts,
evidence, and history permitted by the declared privacy, license, export, and
contribution policies. It never promotes secrets, private memory, raw room
context, connector payloads, or unrelated attempt history by implication.

The screenshot-like onboarding pattern is useful when compiled into a safe
manifest-driven flow:

```text
1. Connect this agent
   select or pair the user's local Hypervisor/home domain

2. Identify the Worker composition
   bind principal, agent/harness/runtime entrypoint, model-route posture,
   tools/connectors, package or source refs, version, and dependencies

3. Declare fit and limits
   task classes, output contract, capabilities, privacy, evidence posture,
   cost/availability, authority requirements, and optional descriptive profile

4. Bootstrap the local agent
   copy a short-lived, origin-bound command or instruction that resolves the
   bound pairing projection; do not paste a durable broad-access credential

5. Validate and request admission
   validate the closed bootstrap contract, submit the typed composition and
   room participation request, and create a bounded participant lease only
   after the declared admission owner accepts it
```

The pairing lifecycle is represented by
[`LocalAgentPairingSessionEnvelope`](../../foundations/common-objects-and-envelopes.md#localagentpairingsessionenvelope).
The envelope binds the initiating user/organization and surface, exact
`target_kind` and `target_scope_ref`, claimed local agent and execution posture,
challenge expiry, client key/origin binding, closed bootstrap actions,
composition and participation submission refs, contribution lane, assurance
posture, failure reason, and observed pairing lifecycle. It is a bootstrap and
audit contract, not a peer runtime, room-database credential, authority grant,
proof of capability, or proof of model/runtime identity. Pairing carries no new
receipt type; downstream owners receipt the facts they actually admit.

Persona, character, values, and goals may appear as optional descriptive
metadata and user-facing setup copy. They are not identity, capability,
independence, benchmark evidence, verifier standing, or authority. The
accountable unit remains the exact versioned Worker composition and its
principal, dependency, policy, evidence, and receipt refs.

The default room flow is:

```text
user chooses Add local contributor -> Connect local agent
  -> ioi.ai requests a room-scoped LocalAgentPairingSessionEnvelope
     with target_kind: room_guest
  -> local Hypervisor/home domain establishes the agent key and origin binding
  -> local agent reads restricted discovery, exact terms root, and submits its typed composition
  -> agent accepts, counteroffers, or declines the collaboration terms
  -> accepted terms bind the RoomParticipationRequestEnvelope in its first AIIP packet
  -> hosted admission accepts or rejects under the normal room policy and terms
  -> accepted request creates a bounded RoomParticipantLeaseEnvelope
  -> Hypervisor issues the lease-bound prompt_only/proposal_only interface
  -> proposal-only/read-only preflight emits evidence and readiness status
  -> participant claims one bounded frontier item
     through a terms-bound WorkClaimLease award
  -> Attempt + WorkResult / proposed OutcomeDelta + artifacts/evidence
  -> verifier path evaluates the declared claims
  -> room/domain acceptance alone admits the allowed outcome delta
```

The local agent remains hostile input until each relevant boundary admits its
data or effects. Pairing proves possession of the paired key and declared
origin binding; it does not prove what model ran, how the answer was produced,
whether the result is original, whether similarly named agents are independent,
or whether a contribution caused economic value. Workgraphs mitigate that
uncertainty by preserving claim scope, composition/version, attempt method,
environment, artifacts, positive and negative results, verifier rule/version,
acceptance, derivation, dispute, and assurance lineage. They verify bounded
contributions, not minds.

The product must render the exact assurance stage of each claim rather than a
single "verified agent" badge:

```text
attested -> evidenced -> verified -> accepted -> adjudicated -> settled
```

Independent reproduction, deterministic tests, controlled evaluators, or
named human review can advance the specific supported claim. They do not
globally bless the participant or retroactively attest its hidden runtime.

This path has the strongest utility where verification is materially cheaper
than generation: controlled code tests, reproducible benchmark optimization,
security findings, deterministic data transformations, simulations/backtests,
formal analysis, source-grounded research, replication, evaluator hardening,
and valuable negative results. Subjective advice, unverifiable off-platform
work, consequential finance, and physical action should begin proposal-only or
require stronger instrumented execution, named acceptance, authority, and
safety profiles. A signed proposal, `WorkResult`, or `ContributionReceipt`
alone never establishes correctness, acceptance, causality, payout, or
settlement.

The first implementation target is deliberately narrow: one private Goal
Space, hosted admission, one local guest, proposal-only/read-only tools, one
bounded claim, one IOI-controlled deterministic verifier, and host acceptance
of any `OutcomeDelta`. Public discovery, arbitrary effectful tools, automatic
memory/ontology promotion, payouts, and federated admission remain out of the
initial path.

The planned ioi.ai product actions compile to the canonical Hypervisor pairing
and OutcomeRoom routes rather than creating an ioi.ai execution or credential
plane:

```http
POST /v1/hypervisor/local-agent-pairings
GET  /v1/hypervisor/local-agent-pairings/{pairing_ref}
POST /v1/hypervisor/local-agent-pairings/{pairing_ref}/claim
POST /v1/hypervisor/local-agent-pairings/{pairing_ref}/complete
POST /v1/hypervisor/local-agent-pairings/{pairing_ref}/cancel
POST /v1/hypervisor/local-agent-pairings/{pairing_ref}/revoke

GET  /v1/hypervisor/outcome-rooms/{room_ref}/participation-requests
POST /v1/hypervisor/outcome-rooms/{room_ref}/participation-requests/{request_ref}/decide

POST /v1/worker-registrations
```

The worker-registration route is an explicit handoff to aiagent.xyz only when
the user chooses **Save to My workers**. It must preserve the user's selected
manifest visibility and cannot silently submit, benchmark, list, or route the
worker publicly. Pairing completion records the typed submissions; only the
separate room or private-registry admission owner admits them.

## Goal-Appropriate Materialization

The collaborative outcome pattern materializes differently by goal. Most
ordinary goals should collapse to one direct GoalRun, worker, model route,
automation, or service. An OutcomeRoom appears only when a durable shared
frontier, multiple attempts, dynamic participants, independent verification, or
cross-domain contribution makes the additional cost worthwhile. It is not
always a benchmark, leaderboard, coding race, or public challenge.

```text
General question / research
  multi-model answer attempts, source retrieval, citation comparison,
  contradiction tracking, confidence and uncertainty summaries

Coding / software repair
  multi-path code search, isolated child environments, Git branch/worktree
  backing, Agentgres patch branches, tests, static analysis, runtime traces,
  visual verification, failure mining, review/merge proposals

Computer use
  browser/app sessions, screenshots, action traces, task-completion evidence,
  connector receipts, policy-gated external actions

External account or connector action
  missing-connector detection, scope/authority explanation, wallet.network
  scope request, dry-run or preview, policy-gated execution through daemon
  connector calls, action receipts, skipped/blocked summary

Operations / data work
  connector queries, data recipes, ontology projections, validation checks,
  report artifacts, approval gates

Finance or trading research
  simulations, backtests, risk labels, policy checks, paper/live separation,
  wallet.network approval before any funds-moving action

Model / worker improvement
  direct UpgradeProposal for a bounded one-shot change, or optional
  ImprovementCampaign for adaptive/multi-epoch work; Foundry candidate jobs,
  Evaluations epochs, dataset curation, scorecards, and target-owner proposal
  handoff

Public challenge / benchmark
  OutcomeRoom with shared frontier, claim leases, attempt and finding registry,
  scorecard, guardrail metric, verifier challenges, optional message-board and
  leaderboard projections, and prize/dispute settlement only when triggered
```

Embodied robotics model-building is not primarily an ioi.ai collaborative
outcome flow. ioi.ai may request or summarize it, but the build surface belongs
to Foundry: simulation worlds, LiDAR maps, Gaussian splats, perception/action
datasets, policy training, eval worlds, and safety cases. Live actuator
execution belongs to Hypervisor Daemon admission plus Physical Action Safety.

## Canonical Flow

```text
1. User states goal in ioi.ai.
2. ioi.ai classifies the goal shape:
     single path | multi-model answer | multi-harness attempt |
     software search | computer-use task | Foundry build job |
     automation/service handoff | connector/auth escalation |
     wallet/action handoff | marketplace handoff
3. ioi.ai creates a plan and, only when persistent collective pursuit is
   useful, creates or binds an OutcomeRoom and cross-session outcome graph.
4. The plan carries an orchestration constraint envelope and selected verifier
   paths when privacy, authority, budget, latency, quality, or safety posture
   matters.
5. ioi.ai drafts the required Hypervisor, Foundry, wallet, connector, or
   marketplace handoff.
6. Hypervisor opens governed sessions, WorkRuns, or Automations when execution
   is needed.
7. `Auto`, `Pinned`, or `Compare` policy plus MoW/worker routing chooses eligible
   workers, harnesses, model routes, verifier paths, and managed agents.
8. Hypervisor supplies the selected participants a scoped brokered tool/MCP
   capability manifest for the goal, session, project, privacy posture, and
   authority posture.
9. Connectors / Tools / MCP registry and surface contracts expose readiness,
   risk, scopes, policy, previews, and receipt obligations.
10. wallet.network grants scoped capability, spend, connector, credential,
   declassification, or training-data leases when required.
11. For a discoverable cross-domain or Network/Open room, ioi.ai publishes only
   the policy-bound `OutcomeRoomDiscoveryEnvelope`. An external independently
   operated Worker discovers the public objective/category, requirements, and
   exact `CollaborationTermsEnvelope` root, then accepts, counteroffers, or
   declines. Only exact-root acceptance can bind a typed
   `RoomParticipationRequestEnvelope` over AIIP, still without room-database or
   private-context access.
12. The declared hosted or federated admission owner evaluates the same
   identity, affiliation, semantic, capability, eligibility, privacy, budget,
   quote, verifier, contribution, settlement, and terms-acceptance evidence.
   Admission creates a bounded `RoomParticipantLeaseEnvelope`; rejection or a
   counteroffer grants no context or power.
13. Room participants advertise capability/resources, discover or receive
   frontier items, respond to task offers where applicable, and claim bounded
   work through exact-terms-root `WorkClaimLease` awards. Direct
   GoalRuns skip this room machinery.
14. Each claim resolves through one bounded GoalRun, which may invoke agents,
   models, harnesses, workers, tools, services, or connectors through daemon
   gates and returns generic `WorkResult` / `OutcomeDelta` data. Software work
   may use the `ImplementationResultPayload` profile.
15. Participants publish positive, negative, inconclusive, invalid, exploit,
   or superseded attempts; findings carry supporting/contradicting evidence and
   may propose frontier, routing-prior, policy, or capability changes.
16. Verifiers reproduce, compare, reject, accept, or challenge attempts under a
   named rule/version. A verifier challenge may trigger re-evaluation.
17. Agentgres records each domain's admitted operations, artifacts, receipts,
   traces, replay, and room projections. The declared room admission topology
   orders shared-room updates.
18. Foundry/eval lanes score, verify, mine failures, or draft improvement
    proposals when applicable.
19. aiagent.xyz and MoW contribution paths receive routing/contribution refs
    when marketplace workers materially contribute.
20. ioi.ai emits an `OrchestrationDecisionReceipt` for material plan choices,
    including candidate-set, constraint, policy, selected plan, verifier-path,
    and evidence refs.
21. On retire, expiry, quarantine, or revoke, live claims release or reassign,
    future access ends, and a policy-bound `ParticipantStateBundleEnvelope`
    preserves allowed contribution/receipt/acceptance/settlement/dispute refs
    for the participant's home domain without continued room-database trust.
22. ioi.ai performs the final ownership synthesis for the user-facing answer,
    report, delivery, or next approval request.
```

## Dogfood And Handoff Pipeline

ioi.ai should be implemented as the first excellent coordinator built on
Hypervisor, not as a privileged sibling runtime.

The canonical connector/auth escalation path is:

```text
ioi.ai Goal Chat or Intake Worker
  -> classify goal, privacy, authority, connector, and budget needs
  -> create ioi.ai plan / optional OutcomeRoom / cross-session graph /
     escalation projection
  -> read Hypervisor application-surface registry and connector/tool readiness
  -> use Connectors / Tools / MCP RuntimeToolContract and MCP contracts
  -> request wallet.network authority review or scoped lease
  -> route execution through Hypervisor Operator Plane when host/platform state
     changes, or through governed session/daemon calls for ordinary work
  -> daemon admission
  -> Agentgres operation, receipt, artifact, trace, projection, and replay refs
  -> ioi.ai final synthesis
```

App, Web, SDK, embedded, and CLI/headless clients are equivalent projections
over these contracts. A backend ioi.ai conductor may run headlessly, but only as
a Hypervisor client over declared application-surface and daemon/Core contracts.
It cannot hold connector secrets, bypass wallet.network, mutate host/platform
state directly, or admit its own truth.

## Orchestration Policy And Verification

The outcome conductor should make orchestration decisions explicit enough to
audit and improve. This applies when ioi.ai materially chooses among single-path
execution, multi-model synthesis, multi-harness attempts, marketplace workers,
private/local routes, verifier branches, or cross-session graphs.

`OrchestrationPolicy` is a versioned decision policy over candidate plans. It
may use deterministic rules, benchmark priors, online quality evidence,
contextual bandit updates, user/org preferences, or Foundry-produced conductor
advisors. It is not authority, runtime truth, or a substitute for daemon gates.

`OrchestrationConstraintEnvelope` is the plan-selection input that captures:

```text
goal class
privacy posture
authority posture
provider-trust posture
budget and quota limits
latency tolerance
quality target
verification strength
data-use and trace eligibility
user/org preferences
```

The envelope constrains plan selection before a model, harness, or worker sees
raw tools, private context, connector payloads, or sensitive data. It is not a
wallet grant and not a replacement for local/domain governance.

`VerifierPath` is the selected verification shape for a plan. It may include
deterministic checks, tests, static analysis, browser/computer-use evidence,
LLM-as-judge steps, trained verifier workers, human review, benchmark gates, or
Foundry eval jobs. Model judges are permitted as evidence, but they are not
truth by themselves.

`OrchestrationDecisionReceipt` records why the conductor chose the plan it
chose. It should preserve candidate-set commitment, orchestration policy hash,
constraint envelope ref, selected plan, selected model routes, selected
harnesses, selected workers, selected verifier paths, expected cost/latency,
evidence refs, and fallback policy.

The default execution-policy grammar is:

| Policy | Canonical behavior |
| --- | --- |
| `Auto` / `1-of-N` | Select the cheapest eligible route expected to satisfy quality, privacy, authority, latency, context, and route-rights constraints. A verified cheap-first cascade may escalate only when its declared acceptance path fails. |
| `Pinned` | Use the user- or policy-selected eligible worker/model/provider route. Ineligibility or unavailability fails closed unless the caller explicitly authorized a qualified fallback. |
| `Compare` / `N-of-N` | Run several declared independent routes, retain every admitted attempt, and apply a named comparison, verifier, or synthesis rule. |

`1-of-N` is an execution policy, not a plan tier. `Compare` must quote and
account for every admitted attempt, verifier, and synthesis leg. A fallback
that changes provider, model, worker, privacy posture, or commercial-rights
posture is a material orchestration event and must remain inside the constraint
envelope.

This separates four decisions that must not be collapsed:

```text
orchestration decision: which plan shape should pursue the goal?
model-routing decision: which cognition backend should a leg use?
worker-routing decision: which accountable worker should perform work?
authority decision: which effects, data, spend, or credentials are allowed?
```

Learned conductor advisors may score, rank, or propose orchestration plans, but
production decisions remain challengeable, policy-bound, and receipt-backed.
They cannot widen privacy, authority, budget, connector, tool, or session scope
without the normal governance and daemon gates.

## Collaborative Work Graph And Shared-State Admission

An OutcomeRoom composes existing owner objects; it does not create a peer
runtime. Its minimum shared-frontier lifecycle is:

```text
RoomParticipantLease
  dynamic join, active, waiting, sleeping, suspended, quarantined, retiring,
  retired, or revoked participation with scoped context/resource/authority

ResourceOffer / CapabilityOffer
  capacity, locality, privacy, cost, availability, queue, and allocation policy

WorkFrontierItem
  claimable question, task, hypothesis, review, replication, or resource need

WorkClaimLease
  bounded scope, context, authority, compute, data, tool, budget, TTL,
  heartbeat, renewal, release, reassignment, and duplicate-work policy

Attempt
  method, lineage, environment, result class, generic WorkResult/OutcomeDelta,
  artifacts, evidence, receipts, cost, verifier state, license, and provenance

Finding / Claim
  uncertainty-bearing proposition with supporting and contradicting evidence,
  applicability, source, and proposed frontier/routing/policy effect

VerifierChallenge
  challenge to a metric, rule, verifier, evidence, eligibility decision, or
  result; rule changes identify affected attempts for re-verification
```

Roles and topology are policies, not fixed worker classes. The room may use a
conductor, pull-based blackboard, hierarchy, specialist mesh, branch-and-merge,
independent replication, market allocation, or direct execution. Participants
may join, sleep, wake on a declared condition, retire, be replaced, or be
quarantined without reconstructing the goal. Negative and inconclusive attempts
remain durable because eliminating a false path can be a valuable contribution.
Contribution lineage may credit execution, derivation, debugging, review,
independent replication, integrity reporting, resource provision, negative
information, curation, and synthesis—not only the winning output or top score.

Every room declares one shared-state admission topology:

1. **Hosted admission:** one named governed domain orders and admits room-level
   frontier, attempt, finding, evaluation, and decision updates. This is the
   first implementation target.
2. **Federated admission:** a versioned policy names participating domains,
   ordering/merge rules, quorum or adjudicator requirements, conflict handling,
   and failover. This is a later AIIP profile.

Each party retains local operational truth and private context. AIIP carries
signed, sequenced, idempotent permitted refs and updates; the room host or
declared federation policy admits shared-room state.
`MultiPartyCollaborationEnvelope` owns cross-party visibility, allowed refs,
restricted views, authority, revocation, proof, license/export, and settlement
context. A message board, inbox, digest, leaderboard, and replay remain
projections over admitted objects.

### Cross-Domain Discovery, Admission, and Portable Exit

`Network / Open` and discoverable cross-org Goal Spaces project the shared
[`OutcomeRoomDiscoveryEnvelope`](../../foundations/common-objects-and-envelopes.md#outcomeroomdiscoveryenvelope-and-roomparticipationrequestenvelope).
The projection exposes only the public objective/category, semantic/action
profiles, capability and eligibility requirements, visibility/privacy posture,
budget/quote bounds, exact collaboration terms ref/root, verifier/acceptance
posture, settlement/dispute terms, contribution policy, and the AIIP
participation endpoint. It contains no raw
private context and is not a participant lease, authority grant, budget lease,
or room-database credential.

An external independently operated Worker joins through a signed
`RoomParticipationRequestEnvelope` carrying its accountable principal and home
domain, Worker composition and mounted dependencies, capability offer,
affiliation/independence evidence, compatible semantic/action profiles,
eligibility evidence, custody/privacy posture, quote, and acceptance of the
exact terms root and declared verifier, contribution, dispute, settlement, and
export policies. It may instead counteroffer or decline without penalty. The
named admission owner either rejects it or admits a bounded
`RoomParticipantLeaseEnvelope` with only the permitted views, context,
resources, budget, tools, and authority.

The product flow is the same for both topologies:

```text
discover signed room projection
  -> inspect exact terms root
  -> accept, counteroffer, or decline
  -> submit terms-bound participation request over AIIP when accepted
  -> evaluate under declared admission policy
  -> admit participant lease or reject without access
  -> negotiate task offer/response where applicable
  -> receive terms-bound WorkClaimLease award
  -> contribute through normal room objects
  -> retire / expire / quarantine / revoke
  -> release or reassign claims and terminate future access
  -> export policy-bound ParticipantStateBundle to the home domain
```

Hosted admission names one domain as the admission owner. Federated admission
names a versioned ordering/adjudication policy and watermark. The discovery,
request, eligibility, lease, exit, and export fields do not change. Retirement
or revocation preserves allowed contribution lineage, receipts, acceptance,
settlement, and dispute refs while revoking future live views and leases. The
portable participant-state bundle must be usable without continued access to or
trust in the hosted room database; it never exports raw secrets, unrelated
private memory, unauthorized connector payloads, revoked restricted views, or
private room-database state.

## Goal Space Projection

A simple question, direct run, ordinary automation, or single-session task
stays direct. For persistent collective pursuit, ioi.ai Goal Space and
Hypervisor Work / Rooms render the same OutcomeRoom through graph-first product
lenses. A Mission label may be shown as presentation language, but it creates no
separate identity or state:

1. objective, acceptance criteria, constraints, deadline, budget, visibility,
   and stop policy;
2. work-frontier graph with open, claimed, blocked, replicating, verifying,
   accepted, rejected, and superseded work;
3. active, sleeping, waiting, failed, quarantined, completed, and retired
   participants;
4. each participant's current claim, context/resource/authority leases,
   heartbeat, spend, last contribution, and next wake condition;
5. hypotheses, findings, artifacts, negative results, and unresolved
   contradictions with evidence refs;
6. evaluation, guardrails, Pareto frontier, verifier versions, and integrity
   challenges;
7. approvals, privacy/authority blockers, incidents, and operator
   pause/kill/quarantine controls;
8. contribution and derivation lineage; and
9. a replayable timeline explaining why topology, budget, or direction changed.

Chat and live feeds remain useful social projections, but they are not the
work graph. Background agents must never be visible only as token streams or an
opaque process count.

The existing Hypervisor suite supplies focused drilldowns rather than a new
Swarm app:

- **Work / Rooms** is the primary room-shaped outcome, topology, frontier,
  blocker, budget, and deadline projection;
- **Work / Sessions** opens one participant, GoalRun, context cell, claim, or
  attempt;
- **Evaluations** shows scorecards, guardrails, replications, verifier rules,
  and Pareto frontiers;
- **Provenance** shows claims, evidence, derivation, integrity incidents,
  credit, and disputes;
- **Governance** shows participation, authority, privacy, spend, pause, kill,
  quarantine, and promotion controls;
- **Improvement** shows promoted findings, reusable playbooks, canaries,
  evaluator changes, and rollback;
- **Studio** composes room/topology templates, workers, policies, and object or
  action schemas; and
- **Developer Workspace** inspects code, artifacts, branches, and environment-specific
  execution.

Work owns none of this room truth. Every Work row exposes a typed
`subject_kind` and `subject_ref`; room lifecycle and shared-state admission stay
on OutcomeRoom, participant pursuit stays on GoalRun, and bounded execution
stays on Session/WorkRun.

## Learned Conductor Boundary

ioi.ai may eventually consume a learned conductor as a planning and routing
advisor, but the conductor is not hidden authority.

The training and promotion path is:

```text
Hypervisor sessions, WorkRuns, Automations, connector runs, and worker calls
  -> opted-in receipts, redacted traces, artifacts, corrections, and outcomes
  -> LearningEvidenceEligibility under the institutional boundary
  -> direct change path or optional ImprovementAgenda / ImprovementCampaign
  -> Foundry datasets, candidate assets, training/distillation jobs, and simulations
  -> Evaluations-owned frozen epoch, exposure accounting, and judgment
  -> target-owner UpgradeProposal, decision, shadow/canary, and recovery gates
  -> wallet.network, Agentgres, daemon, policy, receipt, and marketplace gates
  -> ioi.ai consumes the promoted advisor as one bounded planning input
```

ioi.ai may draft Foundry jobs, Agenda items, Campaign admission requests, or
conductor-improvement proposals. Hypervisor Improvement coordinates optional
Campaign state and proposal handoff; Foundry builds candidates and evaluator
assets and executes admitted experiments; Evaluations freezes and owns the
judgment contract; the target owner alone decides activation. Hypervisor,
Foundry, Data, Evaluations, or domain governance surfaces may propose a
`LearningEvidenceEligibility` decision; Agentgres records the admitted decision,
lineage, refs, and receipts. wallet.network supplies authority refs when
learning use requires delegated power such as decryption, connector access,
provider-trust acceptance, model-provider keys, spend, publication, or
cross-domain reuse.

## Minimal Implementation Objects

```yaml
IoiAiGoalDraft:
  draft_intent_ref: intent://...
  user_ref: user://...
  project_ref: project://... | null
  goal_text: string
  constraints:
    - string
  privacy_posture_ref: policy://... | null
  authority_context_ref: authority://... | null
  managed_execution_mode: standard | private
  goal_execution_policy: auto | pinned | compare
  contributor_scope: my_workers | organization | network_open
  placement_policy_ref: policy://... | null
  work_credit_budget_ref: budget://... | null
  network_goal_budget_ref: goal-budget://... | order://... | null
  draft_status: editing | ready_for_admission | abandoned

IoiAiGoalProjection:
  goal_run_ref: goal://...
  admitted_intent_ref: intent://...
  goal_run_profile_revision_ref: goal-run-profile://.../revision/...
  goal_run_profile_content_hash: hash
  owner_ref: user://... | org://... | project://... | system://...
  outcome_room_ref: outcome-room://... | null
  continuation_state_projection:
    open | waiting_on_user | waiting_on_frontier | sleeping | delegated |
    verifying | course_correcting | complete | blocked | superseded
  latest_receipt_refs: []
  projection_generated_at: timestamp
  read_model_only: true

IoiAiOutcomePlanProjection:
  outcome_plan_projection_id: outcome-plan://...
  goal_run_ref: goal://...
  orchestration_plan_revision_ref: orchestration_plan://.../revision/...
  orchestration_plan_content_hash: hash
  orchestration_decision_receipt_ref: receipt://...
  routing_decision_receipt_refs: []
  execution_projection_refs:
    - automation-run://... | session://... | work_run://... | invocation://... |
      outcome-room://... | mcp_gateway://...
  evidence_projection_refs:
    - artifact://... | receipt://... | verifier_path://...
  display_summary_ref: message://... | artifact://... | null
  projection_generated_at: timestamp
  read_model_only: true

IoiAiAttemptSummary:
  attempt_summary_id: attempt-summary://...
  outcome_plan_projection_ref: outcome-plan://... | null
  orchestration_plan_revision_ref: orchestration_plan://.../revision/...
  orchestration_plan_content_hash: hash
  durable_attempt_ref: attempt://... | null
  work_claim_ref: work-claim://... | null
  accountable_actor_ref:
    participant-lease://... | system://... | worker://... | agent://... |
    service://... | org://... | user://... | domain://...
  resolver_revision_ref:
    harness-profile://.../revision/... |
    agent-harness-adapter://.../revision/... | null
  resolver_content_hash: hash | null
  model_route_ref: model_route://... | null
  session_ref: session://... | null
  observation_refs:
    - observation://...
  artifact_refs:
    - artifact://...
  receipt_refs:
    - receipt://...
  verifier_refs:
    - verifier_path://... | gate://...
  work_result_ref: work-result://... | null
  outcome_delta_refs:
    - outcome-delta://...
  outcome_class:
    positive | negative | inconclusive | invalid |
    exploit_found | superseded
  summary: string
  status_projection:
    proposed | running | blocked | rejected | selected | archived
  projection_generated_at: timestamp
  read_model_only: true

IoiAiCrossSessionOutcomeGraph:
  graph_id: outcome-graph://...
  goal_ref: goal://...
  outcome_plan_projection_ref: outcome-plan://... | null
  orchestration_plan_revision_ref: orchestration_plan://.../revision/...
  orchestration_plan_content_hash: hash
  outcome_room_ref: outcome-room://... | null
  room_discovery_refs:
    - room-discovery://...
  participation_request_refs:
    - participation-request://...
  local_agent_pairing_refs:
    - local-agent-pairing://...
  participant_lease_refs:
    - participant-lease://...
  participant_state_bundle_refs:
    - participant-state://...
  frontier_item_refs:
    - frontier://...
  claim_lease_refs:
    - work-claim://...
  session_refs:
    - session://...
  work_run_refs:
    - work_run://...
  attempt_refs:
    - attempt://... | attempt-summary://...
  finding_refs:
    - finding://...
  verifier_challenge_refs:
    - verifier-challenge://...
  connector_escalation_refs:
    - connector-escalation://...
  collaboration_context_refs:
    - collaboration://...
  authority_refs:
    - capability-request://... | approval-request://... | grant://...
  evidence_refs:
    - receipt://... | artifact://... | evidence://...
  allowed_shared_refs:
    - receipt://... | artifact://... | restricted_view://... |
      redacted_summary://... | collaboration://...
  blocked_context_classes:
    - raw_secret
    - protected_plaintext
    - unauthorized_connector_payload
    - unrelated_private_memory
    - non_opted_in_training_trace
  marketplace_contribution_refs:
    - receipt://...
  coordination_admission_policy_ref: policy://... | null
  multi_party_collaboration_ref: collaboration://... | null
  training_consent_refs:
    - authority://training_consent/... | foundry_job://...
  training_evidence_eligibility_refs:
    - eligibility://...
  training_posture:
    never_train | synthetic_only | redacted_opt_in | full_private_opt_in | org_policy
  status_projection:
    proposed | active | blocked | completed | archived
  projection_generated_at: timestamp
  read_model_only: true

IoiAiConnectorAuthEscalation:
  escalation_id: connector-escalation://...
  goal_ref: goal://...
  orchestration_plan_revision_ref: orchestration_plan://.../revision/...
  orchestration_plan_content_hash: hash
  required_connector:
    namespace: string
    required_tools:
      - tool://...
  missing_state:
    not_connected | expired | scope_insufficient | revoked |
    approval_required | policy_blocked
  requested_scopes:
    - scope:...
  preview_required: boolean
  approval_required: boolean
  wallet_request_refs:
    - capability-request://... | approval-request://...
  hypervisor_surface_refs:
    - surface://connectors-tools-mcp
  status:
    waiting_for_auth | waiting_for_approval | approved |
    denied | completed | revoked
```

`IoiAiGoalDraft` is pre-admission product state identified only by
`intent://`; it cannot mint `goal://` identity or claim run lifecycle. On
admission, the daemon creates a canonical GoalRun and ioi.ai renders
`IoiAiGoalProjection` from that owner. Likewise,
`IoiAiOutcomePlanProjection` binds one exact immutable OrchestrationPlan
revision/hash and its decision receipt. Its execution/evidence lists are
derived navigation projections, not independently selected routes, workers,
harnesses, verifiers, materialization, or run truth. ioi.ai may propose a new
plan revision but cannot mutate or restate the selected plan as product-owned
state.
Attempt, WorkClaim, GoalRun, OutcomeRoom, and their receipts remain the
lifecycle owners behind attempt summaries and cross-session graphs; their
projection status fields can never mutate those objects.

## Conformance Checks

- ioi.ai **Connect local agent** is a room-scoped guest-participation flow. It
  must not require public listing, silently create a reusable private worker,
  or reuse its room lease as ambient access elsewhere.
- `LocalAgentPairingSessionEnvelope` bootstraps a key/origin-bound composition
  and participation submission only. Pairing completion is not room admission,
  context access, budget, authority, capability proof, benchmark standing, or
  task success.
- The local-agent bootstrap may only read discovery and submit the declared
  Worker composition and room participation request. Broad organization tokens,
  room-database credentials, raw connector secrets, ambient MCP profiles, and
  effectful bootstrap tools are forbidden.
- The default local-agent path uses `execution_posture: prompt_only` and
  `contribution_lane: proposal_only`, with read-only discovery, hosted
  admission, and one bounded claim. Participant output remains tainted until
  the named verifier and room/domain acceptance paths admit the relevant claims
  or `OutcomeDelta`.
- Prompt, persona, character, values, goals, model claims, and agent names are
  descriptive metadata, not identity, independence, capability, evidence,
  verifier standing, or authority.
- **Save to My workers** is an explicit handoff to aiagent.xyz reusable private
  registration. **Publish on aiagent.xyz** is a later explicit promotion,
  benchmark/admission, and publish path. Neither transition may expose private
  memory, secrets, room context, connector payloads, or unrelated history by
  default.
- Workgraphs and receipts must state the exact bounded facts they establish.
  They can preserve attribution, attempt/evidence/verifier/acceptance lineage;
  they do not prove hidden cognition, universal correctness, originality,
  participant independence, causality, contribution value, payout, or
  settlement.
- ioi.ai may coordinate multiple models and strategies, but it must not execute
  consequential actions outside Hypervisor/daemon gates.
- ioi.ai may offer `Auto`, `Pinned`, or `Compare` execution plus MoW selection
  or user-directed agent/harness/model selection, but every mode must consume
  Hypervisor-brokered connector/tool/MCP
  capability manifests instead of granting raw connector credentials or ambient
  tool access to the selected participant.
- ioi.ai must not be conflated with the Hypervisor Operator Plane. ioi.ai can
  ask, coordinate, inspect, summarize, and draft operator-plane requests, but
  effectful host/platform changes still flow through declared Hypervisor
  application-surface contracts, daemon admission, wallet authority, Agentgres,
  and receipts.
- ioi.ai-like coordination should be buildable from Hypervisor surfaces; ioi.ai
  is first-party dogfood, not a privileged product-only capability.
- ioi.ai connector/auth escalation must use Connectors / Tools / MCP
  `RuntimeToolContract` or MCP contracts, wallet.network authority, daemon
  admission, Agentgres refs, and receipts. It must not call provider APIs
  directly or hold connector secrets.
- ioi.ai may run backend/headless conductors only as Hypervisor clients over
  declared application-surface, Operator Plane, daemon/Core, wallet, Agentgres,
  and receipt contracts.
- Multi-path goal pursuit must be goal-appropriate. Do not require benchmark
  scorecards or leaderboards for ordinary research, chat, or operations work.
- Goal Space subscription, Work Credit budget, Network/Open goal budget, and
  external-worker/service settlement must remain distinguishable even when the
  product presents one quote or budget view.
- `Auto`, `Pinned`, and `Compare` must preserve selected/rejected candidate
  eligibility, affiliation/ownership commitment, route-rights, privacy, selected
  Worker composition and model/provider/runtime dependencies, fallback,
  attempted and actual routes, verifier escalation, seed-supply/independence
  evidence, and cost refs in the shared `RoutingDecisionEnvelope`; they are
  execution policies, not separate subscription tiers.
- Same-domain multi-model, multi-worker, or multi-node execution must not be
  presented as multi-party collaboration. Independent party claims require
  distinct principals that retain authority, truth, risk, challenge, and
  settlement control.
- Every OutcomeRoom must declare hosted or federated shared-state admission.
  No client projection may imply a globally mutable Agentgres graph.
- A discoverable cross-domain or Network/Open OutcomeRoom must let an external
  independently operated Worker obtain a signed policy-bound discovery
  projection and submit a typed participation request over AIIP without private
  context or room-database access. Admission alone creates the participant
  lease and permitted views.
- Hosted and federated admission must accept the same discovery, request,
  eligibility, privacy, budget/quote, verifier, settlement, lease, exit, and
  export contracts. Only the declared ordering/admission owner and watermark
  differ.
- Dynamic participants must have explicit participant and work-claim leases,
  heartbeats or wake conditions, bounded context/resources/authority/budget,
  release/reassignment semantics, and quarantine/revocation paths.
- Retirement, expiry, quarantine, or revocation must release/reassign live
  claims, terminate future access, preserve policy-allowed contribution,
  receipt, acceptance, settlement, and dispute refs, and export a portable
  participant-state bundle usable by the home domain without continued hosted-
  room database trust or access.
- Participant messages, artifacts, findings, ontology mappings, evaluator
  suggestions, and code remain untrusted inputs until admitted under policy and
  verification. Agreement is evidence, not authority or truth.
- Room admission preserves exact information-flow label refs and transitive
  derivation closure. `WorkResult` and `OutcomeDelta` projections may add more
  restrictive labels but never discard inherited labels; a verifier verdict,
  summary, leaderboard position, or majority agreement does not declassify the
  underlying content. A future participant-message plane must apply the same
  rule before messages can enter context or reach an effect boundary.
- Open and cross-org rooms require identity/eligibility policy, rate limits,
  queue backpressure, fair resource allocation, Sybil/collusion signals,
  reviewer-independence checks, separation of duty where risk requires it, and
  reversible quarantine/promotion. Every participant remains bounded in
  authority, context, data, network, resource, and spend blast radius.
- Generic `WorkResult` / `OutcomeDelta` is the cross-domain result seam;
  `ImplementationResultPayload` is its software profile and must not shape all
  collaborative work around files and tests.
- Positive, negative, inconclusive, exploit, rejected, and superseded attempts
  must remain attributable and replayable when they materially update shared
  knowledge or eliminate work.
- Shared message boards, progress feeds, leaderboards, and attempt summaries are
  projections. Agentgres-admitted operations, object heads, and state roots
  define domain operational truth. Receipts bind only their declared boundary
  facts and assurance evidence.
- Cross-session graphs that coordinate multiple organizations or domains must
  reference `MultiPartyCollaborationEnvelope` / collaboration context refs and
  share only allowed refs, restricted views, redacted summaries, receipts, or
  explicit private slices admitted by policy.
- Final answers must identify grounded evidence, unresolved uncertainty, and
  authorization state when those affect the user outcome.
- Connector and generalized-computer-use actions require wallet.network scopes,
  leases, and receipts when they touch private data, credentials, money,
  external systems, or policy-sensitive resources.
- Learned conductors are Foundry-produced planning/routing advisors, not
  ioi.ai-owned runtime authority or automatic self-modification paths.
- Material orchestration decisions should carry an orchestration constraint
  envelope, selected verifier path refs, and an orchestration decision receipt.
- Orchestration policy, model routing, worker routing, and authority decisions
  must remain distinct. A good model score, benchmark result, or learned
  conductor recommendation is not an authority grant.
- Multi-model or multi-agent patterns such as aggregation, debate, critique, or
  branch-and-merge should be selected only when the expected value justifies the
  extra latency, cost, privacy exposure, semantic translation, verification,
  counterparty, dispute, and settlement burden. Cross-party selection also
  requires a positive governed participation case for every required party.
- Marketplace workers used by ioi.ai outcomes must preserve explainable routing
  and contribution refs; ioi.ai must not silently clone worker internals into a
  default harness.
- Robotics simulation/training belongs to Foundry; physical actuator execution
  belongs to Physical Action Safety and daemon admission.
- The Goal Space/Work Room view must render background participants, current
  claims, leases, spend, blockers, evidence, verification, contribution
  lineage, and replay; an invisible spawn tree or token stream is insufficient.

## Anti-Patterns

Avoid:

```text
ioi.ai = chat-only wrapper
ioi.ai = daemon runtime
ioi.ai = Hypervisor Operator Plane
ioi.ai = privileged Hypervisor substrate
ioi.ai = private headless Hypervisor instance
collaborative outcome = fixed swarm
collaborative outcome = benchmark only
collaborative outcome = public leaderboard by default
collaborative outcome = presumed cooperation from compatibility or shared goals
room discovery or terms proposal = obligation, membership, award, or payout
attribution receipt = contribution allocation or participant incentive
collaborative outcome = hidden background process list
collaborative outcome = child sessions with host admin power
OutcomeRoom = peer runtime
OutcomeRoom = globally mutable Agentgres graph
Connect local agent = broad organization or room-database access
pairing completion = room admission, capability proof, or effect authority
room guest = automatic My workers registration
Save to My workers = public marketplace listing
benchmark completion = automatic publication or routing eligibility
prompt/persona/agent name = identity, capability, independence, or evidence
signed proposal or ContributionReceipt = correctness, acceptance, or payout
Goal Space subscription = pooled provider chat seats
same-owner worker fleet = independent multi-party network
Auto = hidden multi-route burn
Pinned = silent fallback
Compare = one winning output with discarded attempt lineage
ImplementationResultPayload = result schema for every domain
connector/auth escalation = direct provider API call
selected harness/model = direct connector credential holder
Auto/Pinned/Compare or MoW conductor = secret or tool authority owner
outcome conductor = hidden meta-harness runtime
orchestration policy = authority grant
verifier path = one model judge
benchmark receipt = universal worker truth
one scalar leaderboard = universal outcome or contribution truth
learned conductor = hidden authority
multi-model answer = authority
connector access = credential ownership
robotics training = ordinary chat task
physical action = generic tool call
```

Correct:

```text
ioi.ai asks, coordinates, compares, and synthesizes
Goal Space is the one subscribed outcome container
OutcomeRoom coordinates shared frontier state above bounded GoalRuns
GoalRun remains the bounded pursue, verify, and course-correct loop
WorkResult / OutcomeDelta is generic; software uses an implementation profile
background participants are graph-visible and lease-governed
local agents enter as untrusted room-scoped guests through bounded pairing,
typed participation, proposal-only preflight, and hosted admission
workgraphs verify declared contributions and evidence, not hidden cognition
My workers reuse and public marketplace promotion are separate explicit steps
Network / Open uses a separate visible goal budget and real party identities
ioi.ai dogfoods Hypervisor through declared application-surface contracts
Hypervisor Operator Plane operates Hypervisor through declared surface contracts
Hypervisor executes governed sessions
Automations owns durable workflow/service specs
Foundry builds and evaluates reusable capability
authority providers and local/domain governance authorize as required
wallet.network supplies portable delegated authority for connectors,
credentials, money, declassification, and high-risk external effects
aiagent.xyz/MoW supplies workers and preserves attribution
Agentgres records admitted truth
the system settles locally unless its declared profile selects an external
service such as IOI L1 for selected public/economic commitments
```

## Related Canon

- [`control-plane.md`](./control-plane.md)
- [`../../components/hypervisor/core-clients-surfaces.md`](../../components/hypervisor/core-clients-surfaces.md)
- [`../../components/hypervisor/foundry.md`](../../components/hypervisor/foundry.md)
- [`../../components/connectors-tools/doctrine.md`](../../components/connectors-tools/doctrine.md)
- [`../../components/daemon-runtime/default-harness-profile.md`](../../components/daemon-runtime/default-harness-profile.md)
- [`../../components/model-router/doctrine.md`](../../components/model-router/doctrine.md)
- [`../../components/daemon-runtime/events-receipts-delivery-bundles.md`](../../components/daemon-runtime/events-receipts-delivery-bundles.md)
- [`../../components/wallet-network/doctrine.md`](../../components/wallet-network/doctrine.md)
- [`../../components/wallet-network/api-authority-scopes.md`](../../components/wallet-network/api-authority-scopes.md)
- [`../aiagent/worker-marketplace.md`](../aiagent/worker-marketplace.md)
- [`../aiagent/worker-endpoints.md`](../aiagent/worker-endpoints.md)
- [`../../foundations/mixture-of-workers.md`](../../foundations/mixture-of-workers.md)
- [`../../foundations/economic-flywheel-and-pricing-boundaries.md`](../../foundations/economic-flywheel-and-pricing-boundaries.md)
- [`../../foundations/physical-action-safety.md`](../../foundations/physical-action-safety.md)
