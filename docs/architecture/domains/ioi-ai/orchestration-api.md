# ioi.ai Orchestration Application APIs

Status: canonical low-level reference.
Canonical owner: this file for the OutcomeRoom, GoalRun, and step-resolution
API catalog of the openly packaged ioi.ai orchestration application — the
`/v1/goal-orchestration/*` namespace, the hosted-v2 OutcomeRoom routes, the
goal-run-profile routes, local-agent pairing and room admission, and the target
room and broker route walls.
Supersedes: the same catalog when it lived inside
[`api.md`](../../components/daemon-runtime/api.md) as if it were a daemon
core contract (moved 2026-09-07 under ADR 0052 Decision 4; the text is
unchanged apart from link paths).
Superseded by: none.
Last alignment pass: 2026-09-07.
Doctrine status: reference
Implementation status: partial (see the daemon API owner's status paragraph and
[`../../_meta/canon-to-code-delta.md`](../../_meta/canon-to-code-delta.md);
these routes are application handlers hosted in the daemon, admitted through the
same effect boundary as any other application — hosting is not ownership).
Implementation refs:
  - `crates/node/src/bin/hypervisor_daemon_routes/goalrun_routes.rs`
  - `packages/ioi-ai-orchestration/src/orchestrations.ts` (the orchestration composition that replaced the hosted-v2 room routes, deleted 2026-09-17 under R-187)
  - `crates/node/src/bin/hypervisor_daemon_routes/system_record_routes.rs`
Last implementation audit: 2026-07-30

## Scope

The generic session, thread, run, invocation, result, lifecycle, authority,
storage, evidence and recovery APIs stay with
[`api.md`](../../components/daemon-runtime/api.md). Everything below is
application vocabulary: it composes those daemon primitives
([ADR 0031](../../../decisions/0031-goalrun-execution-composes-thread-orchestration.md))
and is never a prerequisite for ordinary Hypervisor use
([ADR 0052](../../../decisions/0052-hypervisor-bounded-alpha-profile-and-base-platform-acceptance.md)).

## OutcomeRoom, GoalRun, And Step-Resolution APIs

Goal-shaped work should not be coordinated by copying prompts between harnesses.
Two API scales compose:

```text
OutcomeRoom / CollaborativeWorkGraph
  dynamic participants, shared frontier, claim/resource leases, attempts,
  findings, verifier challenges, admission, contribution lineage, and replay

GoalRun / step-resolution broker behavior
  one bounded grounding, execution, verification, repair, course-correction,
  and completion loop for a goal or claimed frontier item
```

The currently audited live slice exposes GoalRun activation/create/list/get,
`start`, `reconcile`, lifecycle recovery, result/delta admission, and event
projection, plus the selected hosted-v2 OutcomeRoom create/read, reciprocal
membership, replay, graph, discussion, and product-projection routes. It admits
`parallel_implement_reconcile` with one deterministic conductor and at most two
implementers. A successful adapter execution is retained as a non-canonical
result candidate on a `waiting_on_conductor` HarnessInvocation; only reciprocal
WorkResult admission materializes the canonical
`ImplementationResultPayloadEnvelope`, binds `work_result_ref` and
`profile_result_ref`, and advances the invocation to `completed`. The local-agent
pairing, current participant/frontier/claim/attempt/finding/challenge
lifecycles, federation, and remaining fine-grained routes below are target
contract; their presence here is not a live-route claim.

**Retired 2026-09-16 (R-178 slice S4a, R-179).** The daemon no longer mounts
the flat `/v1/goal-orchestration/*` families for attempts, findings,
work-frontier-items, work-claim-leases, resource-offers, capability-offers,
work-eligibility-matches, verifier-challenges, room-participation-requests,
room-participant-leases, collaboration-terms and local-agent-pairing-sessions
(43 routes deleted with their modules). Those objects are v4 application
records the ioi.ai composer (`packages/ioi-ai-orchestration`) admits through the
System-record seam, and participation is an `OrchestrationParticipationRequest`
or a delegation of the coordinating thread
([`collaborative-pursuit.md`](./collaborative-pursuit.md)). The room-nested
target routes listed below for the same lifecycles are retired as targets: the
composition mounts none of them. The hosted-v2 OutcomeRoom routes and the
GoalRun routes remain mounted until slices S4c and S4d retire them into the
same composition.

**Re-pointed 2026-09-17 (R-185, slice S4c-1).** The ioi.ai web application's
goal space — the one live consumer the hosted-v2 OutcomeRoom routes had — no
longer calls them. It consumes `OrchestrationEnvelope`
([`collaborative-pursuit.md`](./collaborative-pursuit.md)
§ *OrchestrationEnvelope*, the successor of `OutcomeRoomEnvelope`) through
`packages/ioi-ai-orchestration` over the S2 orchestration handle and the
System-record seam: composing creates the coordinating thread and admits the
record; listing, opening, the graph, replay and delegations are reads; GoalRun
attach and detach and the status are revisions on the exact head. The daemon
session the ioi.ai portal exchange mints is scoped to those primitives — the
thread routes, the Systems projection and the record seam — beside this
namespace. The hosted-v2 room routes below therefore have no consumer and are
deleted in slice S4c-2.

The `/v1/goal-orchestration/*` namespace is the ioi.ai orchestration
application's route namespace (ADR 0022): the daemon hosts, admits, and
receipts these routes exactly as it does any application domain's, and their
presence in this API reference documents the daemon's mounting of the
application, not Hypervisor-substrate ownership of the objects.

Live audited GoalRun routes:

```http
POST /v1/goal-orchestration/goal-run-activations
GET  /v1/goal-orchestration/goal-run-activations/{activation_ref}
POST /v1/goal-orchestration/goal-run-activations/{activation_ref}/submit
POST /v1/goal-orchestration/goal-runs
GET  /v1/goal-orchestration/goal-runs
GET  /v1/goal-orchestration/goal-runs/{goal_ref}
POST /v1/goal-orchestration/goal-runs/{goal_ref}/results
POST /v1/goal-orchestration/goal-runs/{goal_ref}/outcome-deltas
POST /v1/goal-orchestration/goal-runs/{goal_ref}/start
POST /v1/goal-orchestration/goal-runs/{goal_ref}/reconcile
POST /v1/goal-orchestration/goal-runs/{goal_ref}/lifecycle-recovery
GET  /v1/goal-orchestration/goal-runs/{goal_ref}/events
```

The hosted-v2 OutcomeRoom routes the audited M4 slice served — **deleted
2026-09-17 (R-178 slice S4c-2, R-187)** with `outcome_room_routes.rs`,
`outcome_room_system_routes.rs`, the startup convergence of their intent
families and the pending-intent fence (R-183); no registered route serves any
of them, and the ioi.ai composition (§ *OrchestrationEnvelope* in
[`collaborative-pursuit.md`](./collaborative-pursuit.md)) is their successor:

```http
GET  /v1/goal-orchestration/outcome-rooms                                          # no registered route — deleted 2026-09-17 (S4c-2)
POST /v1/goal-orchestration/outcome-rooms                                          # no registered route — deleted 2026-09-17 (S4c-2)
GET  /v1/goal-orchestration/outcome-rooms/overview                                 # no registered route — deleted 2026-09-17 (S4c-2)
GET  /v1/goal-orchestration/outcome-rooms/{room_ref}                               # no registered route — deleted 2026-09-17 (S4c-2)
POST /v1/goal-orchestration/outcome-rooms/{room_ref}/attach-goal-run               # no registered route — deleted 2026-09-17 (S4c-2)
POST /v1/goal-orchestration/outcome-rooms/{room_ref}/detach-goal-run               # no registered route — deleted 2026-09-17 (S4c-2)
GET  /v1/goal-orchestration/outcome-rooms/{room_ref}/replay                        # no registered route — deleted 2026-09-17 (S4c-2)
GET  /v1/goal-orchestration/outcome-rooms/{room_ref}/collaborative-work-graph      # no registered route — deleted 2026-09-17 (S4c-2)
GET  /v1/goal-orchestration/outcome-rooms/{room_ref}/discussion-projection         # no registered route — deleted 2026-09-17 (S4c-2)
GET  /v1/goal-orchestration/outcome-rooms/{room_ref}/product-projection            # no registered route — deleted 2026-09-17 (S4c-2)
```

The lifecycle-transition URIs that were mounted beside them (typed unavailable
or retired in that profile) were deleted in the same cut. A GoalRun record that
still names an `outcome_room_ref` admits no result or delta through
`/goal-runs/{goal_ref}/results` or `/outcome-deltas` — refused by name
(`goal_run_outcome_room_ref_retired`, 410) until the GoalRun composition over
the orchestration lands in slice S4d.

Target pursuit-profile discovery and nonbinding validation routes:

```http
GET  /v1/hypervisor/goal-run-profiles
GET  /v1/hypervisor/goal-run-profiles/{profile_id}/revisions/{revision_id}
POST /v1/hypervisor/goal-run-profiles/{profile_id}/revisions/{revision_id}/validate
```

Studio and Packages own profile authoring, successor-revision release, and
registry lifecycle. These daemon routes discover an exact eligible revision,
or return a nonbinding validation/compatibility preview. They do not create a
resolution identity, mutate the released profile, grant authority, or reserve
components. `POST /goal-runs` atomically revalidates, resolves, admits, creates
the resolved-component and active-skill snapshots, emits the
`GoalRunProfileResolutionReceipt`, and creates the GoalRun so no preview can be
replayed across registry, policy, revocation, or availability drift.

The target `POST /v1/goal-orchestration/goal-runs` request supplies the exact immutable
profile and requested inputs; its admitted response binds the atomic resolution
explicitly:

```json
{
  "goal_run_profile_revision_ref": "goal-run-profile://.../revision/...",
  "goal_run_profile_content_hash": "sha256:...",
  "requested_override_set_ref": "artifact://... | null",
  "requested_override_set_hash": "sha256:... | null",
  "owner_ref": "user://... | org://... | project://... | system://...",
  "user_intent_ref": "intent://... | prompt://...",
  "constraint_refs": ["constraint://..."],
  "outcome_room_ref": "outcome-room://... | null",
  "room_participant_lease_ref": "participant-lease://... | null"
}
```

```json
{
  "goal_run_id": "goal://...",
  "goal_run_profile_revision_ref": "goal-run-profile://.../revision/...",
  "goal_run_profile_content_hash": "sha256:...",
  "admitted_override_set_ref": "artifact://... | null",
  "admitted_override_set_hash": "sha256:... | null",
  "effective_constraint_envelope_ref": "constraint://...",
  "effective_constraint_envelope_hash": "sha256:...",
  "resolved_component_set_snapshot_ref": "artifact://...",
  "resolved_component_set_hash": "sha256:...",
  "active_skill_set_snapshot_ref": "active-skill-set://...",
  "active_skill_set_hash": "sha256:...",
  "initial_role_topology_revision_ref": "role_topology://.../revision/... | null",
  "initial_role_topology_content_hash": "sha256:... | null",
  "goal_run_profile_resolution_receipt_ref": "receipt://...",
  "admission_status": "admitted",
  "run_status": "draft"
}
```

Every newly admitted GoalRun binds exactly one profile revision. Simple or
ad-hoc UX resolves the built-in generic-adaptive profile instead of creating a
profileless exception. A later profile edit cannot rewrite the run; adopting a
successor or different profile requires an explicit receipted migration or
fork. The audited live create route predates generalized profile resolution and
remains partial until it emits these fields.

Target local-agent pairing routes:

```http
POST /v1/hypervisor/local-agent-pairings
GET  /v1/hypervisor/local-agent-pairings/{pairing_ref}
POST /v1/hypervisor/local-agent-pairings/{pairing_ref}/claim
POST /v1/hypervisor/local-agent-pairings/{pairing_ref}/complete
POST /v1/hypervisor/local-agent-pairings/{pairing_ref}/cancel
POST /v1/hypervisor/local-agent-pairings/{pairing_ref}/revoke
```

`POST /v1/hypervisor/local-agent-pairings` is an authenticated operator action that creates a
short-lived `LocalAgentPairingSessionEnvelope` with target `room_guest`,
`private_worker`, or `organization_worker`. It returns the one-time plaintext
challenge/device code and generated bootstrap instruction exactly once; the
server persists only its commitment/hash and must not log or re-display the
secret. The envelope binds expiry, claim-attempt limit and count, pairing
transport, room or registry target, allowed bootstrap operations, and creator
principal.

`POST .../claim` proves possession of the challenge and binds the candidate
public key, observed origin, and harness/agent descriptor. It does not
mint a bearer credential with general API access. `POST .../complete` accepts
only the signed `WorkerComposition` draft/ref and/or
`RoomParticipationRequestEnvelope` allowed by the session target. Completion
does not admit the worker, create a `RoomParticipantLease`, grant context,
tools, authority, resources, or budget, expose room state, publish a
marketplace listing, establish reputation, or authorize payment. Those remain
separate owner decisions and leases.

The creator may inspect status, cancel an incomplete session, or revoke future
bootstrap use after a binding exists. Candidate polling, if a
deployment permits it, is possession-bound and returns only pairing lifecycle
state and the next allowed bootstrap action. Expired, replayed,
origin-mismatched, key-mismatched, attempt-exhausted, completed, or revoked
sessions fail closed. Rate limits apply by creator, origin, network posture,
and target. Lifecycle and admission evidence reuse the existing
authentication, policy-decision, and room-admission event/receipt owners rather
than inventing a pairing receipt that claims competence.

A prompt-only bootstrap is proposal-only and remains tainted. Pairing evidence
alone cannot raise its result above `attested`; any stronger assurance must
come from the admitted claim's evidence, isolation, verifier, acceptance,
adjudication, and settlement path. Pairing is pre-AIIP first-mile
authentication. After admission, cross-domain work uses AIIP and the same
scoped Hypervisor MCP/tool gateway and lease contracts as any other participant.

**Retired (R-188, slice S4c-3, 2026-09-18).** The target room family below was never registered and no longer has an owner in the daemon: discovery, participation, budget, offers, frontier, claims, attempts, findings, verifier challenges and admission proposals are the ioi.ai composition's records (`OrchestrationDiscovery`, `OrchestrationParticipationRequest`, the six v4 work objects) admitted through the System-record seam, and the collaborative graph and discussion lenses are read models the composer derives from the thread and the seam (`Orchestrations.graph`). The block is kept as the history of the target; every route in it is annotated on its own line.

Target OutcomeRoom / CollaborativeWorkGraph routes:

```http
POST  /v1/goal-orchestration/outcome-rooms                                    # no registered route — deleted 2026-09-17 (S4c-2)
GET   /v1/goal-orchestration/outcome-rooms                                    # no registered route — deleted 2026-09-17 (S4c-2)
GET   /v1/goal-orchestration/outcome-rooms/{room_ref}                         # no registered route — deleted 2026-09-17 (S4c-2)
POST  /v1/goal-orchestration/outcome-rooms/{room_ref}/attach-goal-run         # no registered route — deleted 2026-09-17 (S4c-2)
POST  /v1/goal-orchestration/outcome-rooms/{room_ref}/detach-goal-run         # no registered route — deleted 2026-09-17 (S4c-2)
POST  /v1/goal-orchestration/outcome-rooms/{room_ref}/upgrade-proposals   # no registered route — retired target 2026-09-18 (S4c-3): the composition owns this
POST  /v1/goal-orchestration/outcome-rooms/{room_ref}/lifecycle/transitions   # no registered route — deleted 2026-09-17 (S4c-2)

POST /v1/goal-orchestration/outcome-rooms/{room_ref}/discovery   # no registered route — retired target 2026-09-18 (S4c-3): the composition owns this
POST /v1/goal-orchestration/outcome-rooms/{room_ref}/discovery/pause   # no registered route — retired target 2026-09-18 (S4c-3): the composition owns this
POST /v1/goal-orchestration/outcome-rooms/{room_ref}/discovery/withdraw   # no registered route — retired target 2026-09-18 (S4c-3): the composition owns this
GET  /v1/hypervisor/outcome-room-discoveries   # no registered route — retired target 2026-09-18 (S4c-3): the composition owns this
GET  /v1/hypervisor/outcome-room-discoveries/{discovery_ref}   # no registered route — retired target 2026-09-18 (S4c-3): the composition owns this
POST /v1/hypervisor/outcome-room-discoveries/{discovery_ref}/participation-requests   # no registered route — retired target 2026-09-18 (S4c-3): the composition owns this
GET  /v1/goal-orchestration/outcome-rooms/{room_ref}/participation-requests   # no registered route — retired target 2026-09-18 (S4c-3): the composition owns this
POST /v1/goal-orchestration/outcome-rooms/{room_ref}/participation-requests/{request_ref}/decide   # no registered route — retired target 2026-09-18 (S4c-3): the composition owns this

POST /v1/goal-orchestration/outcome-rooms/{room_ref}/participants/join   # no registered route — retired target 2026-09-18 (S4c-3): the composition owns this
GET  /v1/goal-orchestration/outcome-rooms/{room_ref}/participants   # no registered route — retired target 2026-09-18 (S4c-3): the composition owns this
POST /v1/goal-orchestration/outcome-rooms/{room_ref}/participants/{participant_ref}/heartbeat   # no registered route — retired target 2026-09-18 (S4c-3): the composition owns this
POST /v1/goal-orchestration/outcome-rooms/{room_ref}/participants/{participant_ref}/sleep   # no registered route — retired target 2026-09-18 (S4c-3): the composition owns this
POST /v1/goal-orchestration/outcome-rooms/{room_ref}/participants/{participant_ref}/retire   # no registered route — retired target 2026-09-18 (S4c-3): the composition owns this
POST /v1/goal-orchestration/outcome-rooms/{room_ref}/participants/{participant_ref}/quarantine   # no registered route — retired target 2026-09-18 (S4c-3): the composition owns this
POST /v1/goal-orchestration/outcome-rooms/{room_ref}/participants/{participant_ref}/state-exports   # no registered route — retired target 2026-09-18 (S4c-3): the composition owns this
GET  /v1/goal-orchestration/outcome-rooms/{room_ref}/participants/{participant_ref}/state-exports/{state_ref}   # no registered route — retired target 2026-09-18 (S4c-3): the composition owns this
POST /v1/goal-orchestration/outcome-rooms/{room_ref}/participants/{participant_ref}/state-exports/{state_ref}/acknowledge   # no registered route — retired target 2026-09-18 (S4c-3): the composition owns this
POST /v1/goal-orchestration/outcome-rooms/{room_ref}/participants/{participant_ref}/state-exports/{state_ref}/revoke   # no registered route — retired target 2026-09-18 (S4c-3): the composition owns this

POST /v1/goal-orchestration/outcome-rooms/{room_ref}/network-goal-budget   # no registered route — retired target 2026-09-18 (S4c-3): the composition owns this
GET  /v1/goal-orchestration/outcome-rooms/{room_ref}/network-goal-budget   # no registered route — retired target 2026-09-18 (S4c-3): the composition owns this
POST /v1/goal-orchestration/outcome-rooms/{room_ref}/network-goal-budget/quote   # no registered route — retired target 2026-09-18 (S4c-3): the composition owns this
POST /v1/goal-orchestration/outcome-rooms/{room_ref}/network-goal-budget/reserve   # no registered route — retired target 2026-09-18 (S4c-3): the composition owns this
POST /v1/goal-orchestration/outcome-rooms/{room_ref}/network-goal-budget/adjust   # no registered route — retired target 2026-09-18 (S4c-3): the composition owns this
POST /v1/goal-orchestration/outcome-rooms/{room_ref}/network-goal-budget/reconcile   # no registered route — retired target 2026-09-18 (S4c-3): the composition owns this

POST /v1/goal-orchestration/outcome-rooms/{room_ref}/offers   # no registered route — retired target 2026-09-18 (S4c-3): the composition owns this
GET  /v1/goal-orchestration/outcome-rooms/{room_ref}/offers   # no registered route — retired target 2026-09-18 (S4c-3): the composition owns this
GET  /v1/goal-orchestration/outcome-rooms/{room_ref}/offers/{offer_ref}   # no registered route — retired target 2026-09-18 (S4c-3): the composition owns this
POST /v1/goal-orchestration/outcome-rooms/{room_ref}/offers/{offer_ref}/allocate   # no registered route — retired target 2026-09-18 (S4c-3): the composition owns this
POST /v1/goal-orchestration/outcome-rooms/{room_ref}/offers/{offer_ref}/withdraw   # no registered route — retired target 2026-09-18 (S4c-3): the composition owns this
GET  /v1/goal-orchestration/outcome-rooms/{room_ref}/frontier   # no registered route — retired target 2026-09-18 (S4c-3): the composition owns this
POST /v1/goal-orchestration/outcome-rooms/{room_ref}/frontier   # no registered route — retired target 2026-09-18 (S4c-3): the composition owns this
POST /v1/goal-orchestration/outcome-rooms/{room_ref}/claims   # no registered route — retired target 2026-09-18 (S4c-3): the composition owns this
POST /v1/goal-orchestration/outcome-rooms/{room_ref}/claims/{claim_ref}/renew   # no registered route — retired target 2026-09-18 (S4c-3): the composition owns this
POST /v1/goal-orchestration/outcome-rooms/{room_ref}/claims/{claim_ref}/release   # no registered route — retired target 2026-09-18 (S4c-3): the composition owns this
POST /v1/goal-orchestration/outcome-rooms/{room_ref}/claims/{claim_ref}/reassign   # no registered route — retired target 2026-09-18 (S4c-3): the composition owns this

POST /v1/goal-orchestration/outcome-rooms/{room_ref}/attempts   # no registered route — retired target 2026-09-18 (S4c-3): the composition owns this
POST /v1/goal-orchestration/outcome-rooms/{room_ref}/findings   # no registered route — retired target 2026-09-18 (S4c-3): the composition owns this
POST /v1/goal-orchestration/outcome-rooms/{room_ref}/verifier-challenges   # no registered route — retired target 2026-09-18 (S4c-3): the composition owns this
POST /v1/goal-orchestration/outcome-rooms/{room_ref}/admission-proposals   # no registered route — retired target 2026-09-18 (S4c-3): the composition owns this
POST /v1/goal-orchestration/outcome-rooms/{room_ref}/admission-proposals/{proposal_ref}/decide   # no registered route — retired target 2026-09-18 (S4c-3): the composition owns this
GET  /v1/goal-orchestration/outcome-rooms/{room_ref}/replay                       # no registered route — deleted 2026-09-17 (S4c-2)
```

**History (retired 2026-09-18, R-188 S4c-3; the routes above are gone).** The paragraphs from here to the GoalRun routes describe the deleted hosted-v2 room plane and its target discovery/participation lanes; they bind nothing now. The living semantics are in `collaborative-pursuit.md` § *OrchestrationEnvelope* and § *OrchestrationDiscoveryEnvelope and OrchestrationParticipationRequestEnvelope*.

The canonical `outcome-rooms` family admits and projects the bounded-System
`OutcomeRoom` contract only. The predecessor v1 free-form aggregate is not a
fallback when a create body omits or substitutes the current schema/System
coordinates: its create, lifecycle, and membership writes return
`410 outcome_room_v1_write_retired`; a canonical lookup whose storage slot is
occupied only by a predecessor record returns
`410 outcome_room_v1_read_retired`; list and overview omit predecessor records.
M4 admits no public predecessor compatibility route. Historical v1 schemas and
fixtures may remain for source disposition and regression, but cannot create,
mutate, project, or prove current room truth.

The plural `/lifecycle/transitions` URI above is the canonical lifecycle-write
route. In the selected M4 profile it returns the typed
`outcome_room_v2_lifecycle_transition_unavailable` refusal for a current v2
room without mutating the room; implementing room lifecycle transitions is not
part of the hosted M4 cut. For a predecessor room it returns the typed
`outcome_room_v1_write_retired` refusal. The former singular `/transition` URI
is retired for both current and predecessor records and returns a distinct
typed route-retirement refusal with no compatibility dispatch. Attach and
detach are current reciprocal dual-head membership transitions: each compares
the exact room revision/predecessor commitment and GoalRun record root, then
commits both sides under one operation and receipt or writes neither side.

`POST /outcome-rooms` is the room-admission leg of the package-to-genesis
composition, not a hidden autonomous-System create path. Its current bounded-
System contract requires an exact `system_id` whose reusable OutcomeRoom
package, release, genesis, constitution, active profile set, cryptographic
origin, and activation already resolve through the canonical autonomous-System
owner routes. A product or client may present the explicit System admission and
room admission sequence as one guided workflow, but it may not collapse the
wallet-authorized System acts into this route, invent their coordinates, or
infer authority from room creation. Missing, inactive, wrong-package, or stale
System truth refuses before any room record, receipt, or transition is written.
The hosted service/domain may operate many such room systems; the service is not
their logical or authority owner.

The selected hosted successor profile admits no more than 50 current room
records. Each room objective is bounded to 4,096 characters, each repeated room
semantic ref set to 64 unique entries, the sequence-complete
`admission_and_replay_refs` set to 128 entries, and the admitted room sequence
to `0..127`.
Canonical room, replay, collaborative-graph, discussion, and product JSON bodies
are each capped at 1 MiB. Create refuses before its intent or Agentgres operation
when capacity is exhausted. Every mutation validates the complete candidate room
and serialized bound before its first durable effect. Every census and point read
validates the same limits; an over-cap or malformed record makes the read typed-
unavailable rather than truncated, omitted, or false-empty. General collection
cursor pagination remains the shared Hypervisor collection/application-surface
contract and is not claimed by this M4 route profile.

The selected profile is hosted-only. A create request whose
`coordination_topology` is `federated_admission` returns
`422 outcome_room_federated_admission_unavailable` before any room intent,
record, receipt, transition, or bounded-System mutation. This is the one typed
refusal for that current route condition; clients must not alias it to a
predecessor spelling or treat it as a compatibility dispatch. External,
federated, cross-sovereign, and AIIP admission remain later-stage contracts.

WorkResult and OutcomeDelta repeated ref sets and generated collaborative-graph
semantic ref/summary sets are capped at 64. Graph/discussion source-admission
receipt refs and replay operations are capped at 128. Discussion permitted
subjects are capped at 67 (System, owner, and host coordinates plus at most 64
participant leases, after set deduplication). The runtime bounds these source
censuses before projection use and returns typed unavailable on excess; it does
not allocate a successful partial projection.

The daemon-private WorkResult/OutcomeDelta room-scoped seam returns the typed
object plus a bounded owner-convergence summary, never duplicate full GoalRun,
HarnessInvocation, or parent-WorkResult bodies. The summary carries the exact
owner contract/ref, room ref, canonical Agentgres operation/head/receipt refs,
the enclosing bounded-System transition ref, and the applicable GoalRun,
invocation/run, or parent-WorkResult refs. It does not copy a room-owned
revision, transition, state root, or receipt root. Callers that need the
converged owner bodies re-read them from their canonical owner routes after
success. A successful WorkResult admission returns exactly `ok` and this
canonical admission projection; an OutcomeDelta admission also returns the explicit
`effect_executed: false` and `acceptance_granted: false` nonclaims. The daemon
serializes and checks this exact final HTTP response before
writing an intent, runtime dependency, Agentgres admission, room projection, or
owner backlink; an oversized response therefore refuses without side effects.

Room create/update routes never mint free-form mutable aggregates. Every
frontier item, offer, claim, attempt, finding, challenge, result, delta, lease,
budget transition, and state export compiles into a typed payload carrying a
`SystemScopedObjectBinding`. The daemon resolves issuer, current policy,
authority, expected Agentgres head or heads, and the enclosing room System's
predecessor condition. The accepted operation and bounded-System transition
own the canonical decision, sequence, resulting head/commitment, receipt refs,
state root, and receipt root. Object-specific routes are conveniences over
that one canonical admission path; they never mint a room-level spine.

Discovery list/query accepts policy-qualified filters such as
`category_ref`, `semantic_profile_ref`, `capability_ref`,
`eligibility_profile_ref`, `affiliation_posture`, `privacy_posture`, `region`,
`max_quote`, `verifier_profile_ref`, `settlement_posture`, and an opaque
`cursor`. It returns signed, versioned `OutcomeRoomDiscoveryEnvelope` objects
plus the next cursor. Eligibility filtering is advisory until the typed
participation admission decision; no query response grants access or authority.

Every room declares `hosted_admission` or `federated_admission` shared-state admission. Room APIs
carry refs and policy-bound projections; they do not imply a global mutable
Agentgres graph. Cross-domain participation binds
`MultiPartyCollaborationEnvelope` and AIIP sequencing while each participant
retains home-domain truth and private context.

Discovery routes expose only a versioned, policy-bound
`OutcomeRoomDiscoveryEnvelope`; they do not return private room state or grant
membership. Participation requests require a typed admission decision before a
lease exists. Retire/revoke releases or reassigns live claims, terminates future
access, and emits a policy-filtered `ParticipantStateBundleEnvelope` plus export
receipt. That bundle must remain usable without continued access to the hosted
room database.

`POST .../participants/join` is only a host-local or invitation convenience. It
must create or adopt a typed `RoomParticipationRequestEnvelope`, run the same
admission decision, and return the resulting lease/receipt refs; it may never
mint a participant lease as a bypass.

The Network/Open budget routes create or bind a separate
`NetworkGoalBudgetEnvelope`, price/quote eligible external work, reserve against
the declared cap, and reconcile allocation, contribution, dispute, refund, and
settlement refs. They may delegate procurement or settlement to marketplace or
service-order owners, but they may never draw silently from ordinary Goal Space
Work Credits.

Offer allocation composes the existing resource scheduler, quote/budget, queue,
preemption, fairness, custody/locality, and receipt paths. It admits a typed
`ResourceAllocationDecision`; the room route is not a second scheduler or an
unreceipted first-party allocation shortcut.

Target fine-grained GoalRun / broker routes:

```http
PATCH /v1/goal-orchestration/goal-runs/{goal_ref}
POST /v1/goal-orchestration/goal-runs/{goal_ref}/grounding-loop
POST /v1/goal-orchestration/goal-runs/{goal_ref}/context-cells
POST /v1/goal-orchestration/goal-runs/{goal_ref}/context-leases
POST /v1/goal-orchestration/goal-runs/{goal_ref}/handoffs
POST /v1/goal-orchestration/goal-runs/{goal_ref}/harness-invocations
GET  /v1/goal-orchestration/goal-runs/{goal_ref}/harness-invocations
GET  /v1/hypervisor/harness-invocations/{harness_invocation_id}
GET  /v1/hypervisor/harness-invocations/{harness_invocation_id}/events
POST /v1/goal-orchestration/goal-runs/{goal_ref}/verify
POST /v1/goal-orchestration/goal-runs/{goal_ref}/continue
POST /v1/goal-orchestration/goal-runs/{goal_ref}/close
```

An OutcomeRoom claim creates or binds a GoalRun with optional room,
participant, claim, attempt, and admission-policy refs. Context handoffs carry
`task_brief`, generic `work_result` / `outcome_delta`, `blocker`,
`decision_request`, `verification_result`, or `continuation_summary` packets.
`ImplementationResultPayload` is the software profile of `WorkResult`; files,
patches, diffs, and tests are not universal result fields.

The broker adapts a `TaskBriefPayload` to a selected HarnessProfile or Agent
Harness Adapter, records normalized HarnessAdapterEvents, returns a
`WorkResult` / `OutcomeDelta`, and applies a VerifierPath. Reconciliation uses
the normalized result, receipts, evidence, domain-profile fields, uncertainty,
and handoffs to choose repair, escalation, memory proposal, room-frontier
update, continuation, or completion.

Hard rules:

- harness adapters may render prompts, commands, terminal scripts, or
  provider-specific session input internally, but raw chat text is not the
  durable cross-harness contract;
- room participants cannot write shared frontier state directly; the declared
  hosted/federated admission policy orders and admits updates;
- participant/claim membership never widens context, authority, privacy,
  resource, or budget leases;
- participant messages, artifacts, mappings, findings, and evaluator changes
  remain untrusted until admitted;
- background workers expose participant/claim leases, heartbeat or wake
  condition, spend, blockers, evidence, verification, and control state.
