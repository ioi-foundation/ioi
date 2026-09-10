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

### 7. The deployment-local operator key is a recognized custody tier for a standing envelope

> Refinement added 2026-09-09 (owner-reversible; private register R-14).

The consumer loop the alpha exists to prove (M13.3/M13.5) turns on a standing
envelope declared at attach. wallet.network records a standing grant only from
an interactive step-up ceremony whose authentication-factor receipt is
passkey-only, and the alpha's operator holds the approver key on the deployment
host itself — so the alpha could mint no standing envelope at all, and its
attach flow refused typed rather than fabricating a ceremony.

The refinement: **`deployment_local_operator` is a recognized custody tier
beside `passkey`**, under exactly the same rules — one ceremony, receipted
before the effect, creating no effect authority of its own, and widening
nothing. It is carried by a NEW registered contract
(`auth-factor-receipt/v2`), not by mutating v1, because widening is a new
binding on record. The v2 receipt attests **custody**: the host the key lives
on, the hash of its path, that it is readable by its owner alone, and when the
operator acknowledged the ceremony. It never attests a person, and the tier and
the verification mode are bound to each other so neither tier can borrow the
other's evidence. Recording is a control-plane act signed by the deployment's
control root; the capability account remains the grant's audience and the
signer of every later draw.

Two consequences the alpha must live with. A deployment that mints standing
envelopes runs its authority node on the **wall clock**, because an envelope's
expiry is a real-time promise the daemon checks against the host clock at every
bind and draw; the deterministic clock stays for lanes that make no such
promise. And the tier is a floor, not a ceiling: a deployment that enrols a
passkey keeps the stronger tier, and the recognized set stays closed — a third
tier is another binding on record, not a configuration flag.

### 8. Connector authority speaks one language: a registration binds its principal, and every connector authority route refuses an unresolved caller identically

> Refinement added 2026-09-10 (owner-reversible; private register R-20 and R-22).

The Connections estate is the only authority surface a session may name
(Decision 3). After the 2026-09-10 ruling that the routes minting and retiring
a standing envelope resolve their caller (R-17), the route that registers a
connector and the route that spends the envelope still did not. Two
consequences followed. A connector's id was derived from
`{service}:{name}:{base_url}` alone, so a second caller presenting the same
triple overwrote the first caller's record — `org_policy.principal_scoped`
included — and undid the scoping bind and revoke rely on. And an anonymous
caller, refused at bind and revoke, could still draw an existing envelope
through invoke; revoke is the safety act, and it was the one that died.

The refinement, in two rules:

- **A connector's identity binds the principal that registered it.** The
  register route resolves its caller before any record read, refuses an
  unresolved one, records the holder on the record (`owner_ref`,
  server-resolved, never taken from the request), and refuses a
  re-registration of an existing id with a typed `409
  connector_already_registered` rather than overwriting — for every caller,
  the holder included, because the holder's own re-register would rewrite its
  standing lease, admitted policy and credential posture in place, and
  widening is a new binding on record. The id derivation is unchanged on
  purpose: session profiles name `connector:<id>` as a closed set, and lease
  grants, standing leases and credentials join on the id, so re-keying by
  principal would orphan every existing record. Records registered before this
  ruling carry no holder; the daemon never backfills one (that would attribute
  a registration to a principal who did not perform it), refuses their
  re-registration like any other, and reads the holder for nothing — bind,
  revoke and invoke keep R-17's single ownership notion (`principal_scoped`
  plus per-principal lease grants).
- **Register, bind, revoke and invoke answer an unresolved caller
  identically:** `401 hypervisor.authentication_required`, before any record
  read, byte-identical across the four routes. Invoke no longer attributes an
  anonymous caller to a local-operator literal, and the act tool, which
  delegates to invoke under the caller's own headers, inherits the refusal.
  What an authenticated caller receives on any of the four routes is
  unchanged: on the session-scoped path `session_ref` still resolves the
  session's write owner after the caller resolves, and the App's run lane
  crosses under the operator's own session.

Posture, stated plainly. The daemon's auth middleware defaults to `auto`,
which enforces only for an exposed daemon or a forwarded request; the served
App marks a request forwarded only when the browser is not on loopback; the
bootstrap sets no policy. On the alpha's supported deployment — one host, a
loopback daemon, the browser on that host — neither the App lane nor the
headless lane is enforced, the shipped alpha turns enforcement on nowhere, and
every verifier boots its daemon the same way. **The in-handler resolution these
rules add is therefore the entire gate in the posture the bounded alpha
ships**, not a second line behind a middleware.

Recorded, not widened: the daemon's own internal dispatches (the per-boot
internal token) resolve no principal and never invoked a connector; after this
refinement such a call refuses typed instead of being attributed to the local
operator. A record read that precedes identity on any other connector route
(policy, credential, OAuth) stays with its owner; this refinement rules the
four authority routes only.

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
- The connector record gains `owner_ref` at register; the four connector
  authority routes share one unresolved-caller refusal; the admission-evidence
  gate's rule-H baseline loses `handle_connector_register` (Decision 8).

## Cost Of Being Wrong And Reversal

Decisions 1, 2 and 6 are scoping rulings; reversing them re-widens the alpha
and costs re-qualification, not lost guarantees. Decision 3 adds a field with
an empty default and one admission check; reversal deletes both and every
session created meanwhile remains valid. Decisions 4 and 5 are re-homing and
presentation moves reversible from git history. Decision 8 adds one
server-resolved field and two refusals; reversal deletes the refusals and the
field's use, and every connector registered meanwhile remains valid, because
nothing reads `owner_ref` for authority. None of them touch the frozen AFT
surfaces.

## Canonical References

- [`../architecture/components/hypervisor/bounded-alpha-profile.md`](../architecture/components/hypervisor/bounded-alpha-profile.md)
- [`../architecture/components/hypervisor/core-clients-surfaces.md`](../architecture/components/hypervisor/core-clients-surfaces.md)
- [`../architecture/components/daemon-runtime/api.md`](../architecture/components/daemon-runtime/api.md)
- [`../architecture/components/daemon-runtime/default-harness-profile.md`](../architecture/components/daemon-runtime/default-harness-profile.md)
- [`../architecture/_meta/execution-horizons.md`](../architecture/_meta/execution-horizons.md)
- [`./0022-goal-orchestration-application-layer-and-clean-slate.md`](./0022-goal-orchestration-application-layer-and-clean-slate.md)
- [`./0031-goalrun-execution-composes-thread-orchestration.md`](./0031-goalrun-execution-composes-thread-orchestration.md)
