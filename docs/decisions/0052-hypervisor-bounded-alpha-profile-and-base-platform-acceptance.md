# ADR 0052: Adopt A Hypervisor Bounded-Alpha Profile And Separate Base-Platform Acceptance From Application And Flagship Proofs

- Status: Accepted
- Date: 2026-09-07
- Owners: Hypervisor core surfaces / daemon runtime / providers and
  environments / identity, access and metering / execution horizons
- Refines: ADR 0013, ADR 0016, ADR 0021, ADR 0022, ADR 0031, ADR 0035
- Confidence: working_ruling (owner-reversible; recorded by the 2026-09-07
  boundary and bounded-alpha program under the standing owner-authority rule
  that canon is ruled and then kept moving, never stalled)

## Context

ADR 0022 and ADR 0031 already allocate goal pursuit and collaborative rooms
to the openly packaged ioi.ai orchestration application and keep Session,
WorkRun, HarnessInvocation, environments, authority, receipts, Agentgres truth
and the generic result seam in Hypervisor. That allocation did not propagate
into three places that decide what a Hypervisor user actually meets:

1. **Proof sequencing.** The selected minimum-L0 first proof
   ([`execution-horizons.md`](../architecture/_meta/execution-horizons.md)
   § *Selected minimum-L0 proof profile* and § *The first proof — a ruling*)
   is an OutcomeRoom-backed bounded software-change institution, and the
   undeniable-product gate's twenty-two steps route every operator through a
   goal template, genesis and a GoalRun. Read as the only product proof, an
   ordinary Hypervisor session journey has no represented acceptance of its
   own and the platform's readiness appears to wait on the flagship
   application.
2. **Shared prose.** Core Hypervisor surface, daemon API, daemon doctrine and
   default-harness documents still specify room projections, goal queue
   discriminators, goal-specific work forms and a GoalRun admission-path
   decision as if they were platform contracts.
3. **The served front door.** Eleven canonical routes render a route-shell
   page that prints build waves, retirement notes and links to internal
   readouts instead of the owned surface, and session create carries no
   authority scope, so a session's runtime authority is the workspace's.

The 2026-09-05 boundary review recorded these findings as evidence to verify.
This program re-derived them from the current checkout
(`298b0b875` at start) and found them current, with one correction: the
private planning checker's two structural failures the review cited were
already repaired before this ruling.

## Decision

### 1. One Hypervisor bounded-alpha profile is adopted

The base-platform alpha is defined by
[`bounded-alpha-profile.md`](../architecture/components/hypervisor/bounded-alpha-profile.md),
which is the canonical owner of the profile, its journey, and its
journey-to-contract-to-implementation readiness matrix. In one paragraph:

> An invited technical operator on one supported Linux x86_64 host runs the
> Hypervisor daemon, the owned served App and the HTTP/headless client
> locally; bootstraps deployment-local identity from the one-boot bootstrap
> token; opens a project or scratch workspace; starts a session on the
> qualified `generic-cli-local` harness over one local OpenAI-compatible model
> route in the `host_spawn` lane of the local workspace provider; inspects
> progress, written artifacts, receipts, cost and approvals; stops or revokes;
> restarts the daemon and recovers; backs up and restores through the managed
> backup bundle; and obtains diagnostics — all without an ioi.ai account, a
> GoalRun, an OutcomeRoom, a bounded System, or pasted grant JSON.

The profile names exactly one execution venue and discloses its isolation
posture (a host process with a minimal secret-free environment, optionally
bwrap-confined for adapter drivers; **not** a microVM). Every other venue,
provider, harness or isolation posture is explicitly unqualified for the alpha
until its own evidence exists.

### 2. Base-platform acceptance is separate from optional and flagship proofs

Three acceptance classes are distinguished and may not be summed:

| Class | Gate owner | Alpha relationship |
| --- | --- | --- |
| **Base platform** | the alpha profile journey and its named checks | required for the alpha |
| **Optional applications and capabilities** — data, ontology, pipelines, models, evaluations, approvals, automation, packages, application building, bounded-System conformance, marketplace, decentralized cloud, AIIP/network | each capability's own owner and check | available under accurate availability labels; never an alpha gate |
| **Flagship ioi.ai proofs** — sovereign-local completeness on the OutcomeRoom-backed institution, continuity, two-sovereign, north-star | `execution-horizons.md` and the ioi.ai owners | strong application-plus-substrate evidence; never the definition of platform readiness |

The first-proof ruling in `execution-horizons.md` stands for the flagship
class. It is amended to say so, and the base-platform alpha is recorded beside
it as the platform's own front-door proof.

### 3. Sessions carry a closed authority profile

A Session records at create a closed set of connection scopes
(`authority_profile.connection_refs`, each an existing Connections-estate
connector the caller owns). The default is the empty set, not the workspace.
Daemon admission — not client filtering — refuses a connector invocation made
under a session whose profile does not name that connector. Widening is a new
binding on record (a new session, or an explicit Connections act), never an
in-run mutation. Revocation of the connector fences every session that named
it, and the fence survives daemon restart. This is a binding of the existing
Session object to the existing connector/lease objects; it mints no new
authority primitive. Canonical owner:
[`core-clients-surfaces.md`](../architecture/components/hypervisor/core-clients-surfaces.md)
§ *Hypervisor Sessions*, with the connectors doctrine cross-reference.

### 4. Application-specific contracts leave shared core prose by move, not rename

Room projections, goal-specific queue discriminators and work-form fields, the
GoalRun admission-path decision and the OutcomeRoom/GoalRun route catalog move
to their existing ioi.ai owners under `domains/ioi-ai/`. Shared core documents
keep the generic Session, WorkRun, HarnessInvocation, WorkResult/OutcomeDelta,
lifecycle, authority, storage, evidence and recovery contracts and reference
application work only through the typed `subject_attachments` seam. GoalRun is
not renamed to WorkRun and OutcomeRoom is not renamed to Project. Persisted
records and their attribution are preserved; no compatibility alias is minted.

### 5. Canonical routes serve their owned surfaces

A canonical route whose serving lane exists serves that lane's content at the
canonical route. Build waves, plane counts, retirement narratives and source
file names move to a developer diagnostics readout. A route with no serving
lane states its unavailability with a prerequisite and a next action. Advanced
inspection (route ledger, registration, build state) stays reachable through
diagnostics.

### 6. Release qualification includes update and rollback, and is not claimed early

The alpha is release-qualified only when the exact packaged build has evidence
for install, bootstrap, first useful work, orderly restart, interrupted-work
recovery, backup/restore, update/rollback and diagnostics, with App and
headless client agreeing on daemon-owned durable state. Until that evidence
exists the shipped-products register keeps its `development_only` posture and
the profile document records each step's actual status. Environment
restoration is recorded separately from reconciling an ambiguous external
effect; restore never authorizes repeating an effect.

## Non-Goals

- No new orchestration kernel, project-management primitive, or mandatory
  project authority. Projects organize work and grant nothing.
- No requirement that durable services, automations or pipelines live inside a
  session lifetime.
- No parallel container runtime and no OCI/Dockerfile ergonomics until an
  implemented environment-source contract pulls them.
- No change to the flagship proof contracts, ADR 0021's first-proof
  instantiation, or any M02 System-conformance requirement for capabilities
  that claim it.
- No claim that host-spawn execution is workload-bound isolation (ADR 0027).

## Consequences

- `execution-horizons.md` gains the base-platform alpha section and its
  first-proof ruling is scoped to the flagship class.
- `start-here.md` and the architecture README gain a Hypervisor operator
  reader path ahead of the stack-wide paths.
- `core-clients-surfaces.md` gains the session authority profile declaration
  and loses the application-owned sections named in Decision 4.
- The daemon session family gains `authority_profile` at create and the
  connector invoke path enforces it; the owned App forwards the profile.
- The private implementation program promotes the essential M13 session units
  and the M12 zero-to-operable work into the base-alpha critical path without
  moving any other priority.

## Cost Of Being Wrong And Reversal

Decisions 1, 2 and 6 are scoping rulings; reversing them re-widens the alpha
and costs re-qualification, not lost guarantees. Decision 3 adds a field with
an empty default and one admission check; reversal deletes both and every
session created meanwhile remains valid. Decisions 4 and 5 are re-homing and
presentation moves reversible from git history. None of them touch the frozen
AFT surfaces.

## Canonical References

- [`../architecture/components/hypervisor/bounded-alpha-profile.md`](../architecture/components/hypervisor/bounded-alpha-profile.md)
- [`../architecture/components/hypervisor/core-clients-surfaces.md`](../architecture/components/hypervisor/core-clients-surfaces.md)
- [`../architecture/components/daemon-runtime/api.md`](../architecture/components/daemon-runtime/api.md)
- [`../architecture/components/daemon-runtime/default-harness-profile.md`](../architecture/components/daemon-runtime/default-harness-profile.md)
- [`../architecture/_meta/execution-horizons.md`](../architecture/_meta/execution-horizons.md)
- [`./0022-goal-orchestration-application-layer-and-clean-slate.md`](./0022-goal-orchestration-application-layer-and-clean-slate.md)
- [`./0031-goalrun-execution-composes-thread-orchestration.md`](./0031-goalrun-execution-composes-thread-orchestration.md)
