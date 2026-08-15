# ADR 0035: An Environment Is Owned From Its First Durable Byte, By A Request That Could Have Refused

- Status: Proposed — DESIGN ONLY, REVISION 2. No code exists for this ADR and none
  may be written until this document has survived its adversarial review
  (next-legs XIV Leg 2d). Revision 1 was DEFEATED; see *Revision history*.
- Date: 2026-08-15
- Owners: daemon runtime / environment lifecycle / W1.5 disposition
- Refines: ADR 0031 and ADR 0024 (the one structural law — no second spine),
  ADR 0030, and the substrate scope pin
- Closes: defect 1a, open since next-legs XI, gate-asserted open since XIII
- Confidence: high on the defect and on why the five previous designs failed —
  all five are measured below. The ruling is agent-proposed under standing
  program authority and is owner-reversible (see Reversal).

## Why this is a document and not a branch

Four builds have tried to give an environment an owner. Each was demonstrated broken by a
merge-blocking review, and the fifth attempt without a ruled design is the demonstrated
failure mode. Next-legs XIV forbids it in as many words.

**Revision 1 of this document was itself defeated, which is the point.** A review found a
FIFTH failure mode in it, plus six further ship-blockers and five factual errors — at the
cost of a review round on a document rather than a fifth broken build. Every finding is
carried below by name.

## Context: what is actually true today, measured

Every claim in this section was read from the tree at `6cfdcb5be` and re-verified against
source after revision 1's review.

**Creation happens at THREE seams, and one of them is a GET.** `new_env` is called at
`environment_routes.rs:2564` (`handle_environment_create`), **`:2652`
(`handle_environment_get` — a GET that auto-vivifies on first reference and PERSISTS the
record at `:2666`)**, and `:2679` (`handle_environment_action`, when the id does not exist).
None of the three resolves a caller: `handle_environment_create` (`:2549`),
`handle_environment_get` (`:2614`) and `handle_environment_action` (`:2671`) take no
`HeaderMap`.

**CREATE MATERIALIZES NO WORKSPACE.** `new_env` sets `"workspace_root": Value::Null`
(`:257`). The only call to `provision_local_workspace` is in the `"start"` arm (`:2724`).
**The record and the workspace are born at two separate client requests** — the fact that
defeated revision 1 and the single most important line in this document.

**Provisioning is an idempotent mkdir of a deterministic path.**
`provision_local_workspace` (`:341`) is a `create_dir_all` of
`environments/safe_id(id)/workspace`. It cannot refuse and cannot tell a first call from a
thousandth.

**The lifecycle plane is not two routes.** The estate's own gate already censuses fifteen
of them — `NAMED_UNOWNED` in `verify-hypervisor-environment-custody.mjs:257-272`. Beyond
those, handlers that reach workspace bytes with no `HeaderMap` include
`POST /v1/hypervisor/exec` (`environment_routes.rs:4336`), `POST /v1/hypervisor/env-files`
(`binding_routes.rs:297`), terminals (`binding_routes.rs:404`, `:608`), logs
(`operability_routes.rs:901`), watch-state (`:960`), workruns (`:3309`, `:4677`), env-config
(`:4475`), `maintenance/idle-sweep` (`:3476`, which stops every environment in the estate),
and `start_preview_server` (`lifecycle_routes.rs:9348`), a separate axum server outside
`auth_gate` entirely.

**AND THERE IS AN ANONYMOUS TWO-REQUEST CHAIN TO WORKSPACE BYTES THAT NEVER TOUCHES `/v1/`.**
`handle_env_ops_lease` (`supervisor_routes.rs:31`) takes `State` and `AxumPath` and **no
`HeaderMap`**; it mints a 3600-second `environment.ops` lease bound to the named environment
and returns it as a bearer token. `handle_environment_ops` (`:305`) gates on `authed()`
(`:177`), which checks only that the lease is active and names this environment — **no
principal is resolved**. Its methods include `ReadFile`, `WriteFile` and `Exec` against
`status.workspace_root`. The path is outside `/v1/`, and `auth_gate_exempt_path` returns
true for every non-`/v1` path (`lifecycle_routes.rs:17226-17229`), so the global gate never
sees it.

**The scope pin is genesis-only, there is no unbind, and there is NO BIND-ON-BEHALF.**
`bind_request_resource_scope` (`substrate_store.rs:2899`) refuses with
`ResourceOwnerMismatch` when a non-matching scope exists, and writes
`principal_ref: identity.principal_ref` unconditionally (`:2932`). Every one of its call
sites passes the caller's own identity. **An administrator cannot bind a pin naming somebody
else.**

**But there is a non-binding read.** `read_request_scope` (`:2887`) is `pub(crate)` exactly
so that asking "who owns this?" is not itself a mutation.

**And the estate already ships administration WITHOUT pinning.**
`model_routes::authorize_route_owner` (`model_routes.rs:1497-1524`): the deployment
administrator administers every route; a record with **no** owner "predates the ownership
model … NO principal holds a legitimate ownership claim to it. It resolves to the
deployment, whose administrator is the only party that can dispose of it. Fail-closed to
every ordinary principal, and recoverable rather than stranded." Its authority is
`require_authenticated_org_admin` via `RouteCaller.is_deployment_admin` (`:1467`).

**The capture-custody fix binds BEFORE the bytes exist**, and says why in the code
(`environment_routes.rs:3588-3605`): "Binding first means a capture record can never exist
on disk without an owner." Bind at `:3592`, `create_dir_all` at `:3603`, `fs::write` at
`:3605`. **Capture ids are daemon-minted** (`:3585`).

**`environment_id` is CALLER-SUPPLIED** (`:2554-2559`), and `new_env` stores the RAW
spelling as `"id"` (`:235`).

**`safe_id` is many-to-one** (`:189`), and there are FOUR independent copies of the
normalizer: `environment_routes::safe_id`, `supervisor_routes::safe`
(`supervisor_routes.rs:61`), `operability_routes::safe`, and an inline copy in
`editor_host::env_workspace` (`:189-192`). `supervisor_routes::lease_binds_env` (`:141-147`)
compares **raw** `environment:<id>` strings.

**`org://local` is the only constructible organization and every principal holds it.**

**`delete` nulls `status.workspace_root`** (`:3172-3196`), is reachable anonymously, and
carries a standing commitment in its own carve-out comment (`:3172-3176`): "deletion of an
EXISTING environment REMAINS CALLABLE under every containment in this cut. **It never
refuses.**"

**`auth_enforced` defaults to `auto`** (`lifecycle_routes.rs:15802-15818`, "Default policy
is OFF").

## The five failures, by name

**F1 — pin at create.** Broken because two other routes also create, one of them a GET.
A pin minted only in `handle_environment_create` covers environments that arrived through
the door named "create"; every other one is born unowned.

**F2 — pin at first reference.** First-touch under a different name. Whoever gets there
first owns it permanently, because the pin is genesis-only with no unbind.

**F3 — pin at workspace materialization.** Reached from a route that resolves no caller and
never refuses, so the pin minted beside it is F2 with extra steps.

**F4 — adoption gated on `status.workspace_root`.** A mutable field an anonymous route
nulls. Two requests, one anonymous, defeated it.

**F5 — pin at workspace materialization WITH the lifecycle plane made identity-first
(revision 1 of this document).** Still broken, because create and start are two client
requests and only start materializes a workspace:

1. P1 → `POST /v1/hypervisor/environments {"environment_id":"proj-x"}` → 200, record on
   disk, **no pin**.
2. P2 — any principal, since `org://local` isolates nothing — → `POST
   /v1/hypervisor/environments/proj-x/start`. Authenticated, so revision 1's R1 passes. The
   record exists, so its R2 passes. Its R3 binds the pin naming **P2**.
3. P1 is refused on its own environment forever.

Revision 1 blessed this in as many words: "a principal that authenticates and materializes a
workspace IS the owner." That definition awards P1's environment to P2.

The pattern across all five: **a route that cannot refuse cannot mint ownership** — and
**ownership must attach to the FIRST durable byte, not to a later one**, because everything
between the first byte and the pin is a window in which somebody else can become the owner.

## The ruling

### R1 — The closed world is DERIVED FROM HANDLER REACH, not from a list of route names.

The set of routes that must resolve a caller is: **every route whose handler can reach
`environments/<id>/` on disk or `status.workspace_root`.** Derived from the router SOURCE
and asserted in both directions — nothing unclassified, no stale entry — never a hand list.
`verify-hypervisor-environment-custody.mjs:257-272` already censuses fifteen and is the
instrument to extend, not to replace.

The closed world explicitly includes:

- the three creating handlers and the wildcard `:action` route;
- `exec`, `env-files`, terminals, logs, watch-state, workruns, env-config,
  `maintenance/idle-sweep`;
- **the supervisor ops surface and its lease minter**, which are outside `/v1/` and
  therefore outside `auth_gate` entirely;
- `start_preview_server`, a second axum server serving workspace bytes.

**Every refusal is per-handler and unconditional.** None of them may be delegated to
`auth_gate`, whose `auth_enforced` policy defaults to OFF.

### R2 — Creation happens at exactly ONE seam. All three `new_env` arms outside it are deleted.

`handle_environment_get`'s auto-vivify (`:2652`) is deleted: a GET may not persist a record.
`handle_environment_action`'s (`:2679`) is deleted: an action on a non-existent environment
is a 404. Leaving the GET arm in place is worse than a missed seam — under R6 an anonymous
GET would mint unbounded records that no ordinary principal can ever delete.

### R3 — Environment ids are DAEMON-MINTED. A caller-supplied id is refused.

This is the ruling revision 1 did not make, and it is what makes the rest safe. Because the
pin is genesis-only with no unbind and its coordinate is the environment id:

- a caller-chosen id lets any principal permanently claim arbitrary coordinates, each
  burning a whole `safe_id` equivalence class, unrecoverable by anyone including the
  administrator;
- and after a delete, the pin outlives the bytes, so a caller-chosen id can never be
  re-created by anyone — a delete would permanently consume the name.

Daemon-minted ids are never reused, so neither hazard exists. **This is why the capture lane
is immune and it is the axis on which "same shape as the capture fix" actually holds:**
capture ids are daemon-minted (`:3585`).

Callers keep a `display_name`; the id is the daemon's.

### R4 — The pin binds BEFORE the first durable byte, at the one creation seam.

Revision 1 had this exactly inverted — it bound "as the LAST act before returning success",
while the capture fix it cited binds *before* `create_dir_all` and says why. The order
matters and only one direction is recoverable:

- **bind, then write** — a failed write leaves a pin with no bytes. The owner retries; the
  pin matches; nothing is stranded.
- **write, then bind** — a failed bind leaves bytes with no owner, indistinguishable from a
  legacy environment, refused to everyone and claimable by whichever *different* principal
  retries. That does not merely risk one stranding: it **refills at runtime** the very class
  R8 exists to close once, which makes "owned from this leg forward" unattainable.

So: the create handler resolves its caller, mints the id, binds the pin, and only then
writes the record. `start` and every other route AUTHORIZE against the existing pin through
`read_request_scope`. **No route other than create ever mints a pin.** The create→start gap
disappears because there is no gap: the pin precedes the record, and the record precedes the
workspace.

The bind's idempotency key is `environment-owner:<canonical-id>`, mirroring
`environment-capture-owner:{id}` (`:3598`), so a replay is a replay rather than a
`SameKeyDifferentBytes` refusal.

### R5 — One normalizer, canonical in the record, canonical in the lease plane.

The four independent copies of `safe_id` collapse to one function that RETURNS the canonical
coordinate. `new_env` stores the CANONICAL id, not the caller's spelling (`:235` today) —
without that, "the response returns the canonical coordinate" is not achieved. And
`supervisor_routes::lease_binds_env` (`:141-147`), which compares raw `environment:<id>`
strings, is re-keyed on the canonical coordinate: a lease plane keyed on a raw spelling
while the pin is canonical is two coordinate systems over one workspace, which is the
coordinate trap exactly.

### R6 — Ownership is read from the substrate pin, never from a record field.

Every authorization decision resolves through `read_request_scope`. `status.workspace_root`,
`owner_ref` and every other record field are DESCRIPTIVE. This kills F4 structurally.

Two specific consequences the design must state rather than imply:

- **`handle_snapshot_restore` (`:4092`) gains a destination check.** It says today: "NO
  DESTINATION AUTHORIZATION, because there is nothing to authorize against." There is now.
  Its subject derives from the canonical coordinate, not from the `snap["environment_ref"]`
  record field.
- **`delete`'s never-refuses carve-out is RE-RULED, explicitly.** R1 and R6 make it refuse,
  which overrides a standing commitment in its own comment (`:3172-3176`). A silent override
  is how a promise becomes a falsehood. The re-ruling: deletion never refuses **for the
  owner**, and the cleanup-obligation guarantee is unchanged; it refuses a non-owner, and it
  refuses an unadopted environment to every ordinary principal while remaining available to
  the deployment administrator under R7.

### R7 — Legacy environments are ADMINISTERED, not adopted. No pin is minted for them, ever.

Revision 1 ruled an "administrator-authorized adoption transition that binds a FIRST pin".
**That cannot be built**: there is no bind-on-behalf, so such a transition could only bind
*the administrator* as owner of every legacy environment — and with transfer out of scope
and no unbind, real users would be locked out permanently.

The estate already ships the right pattern and it needs no substrate change.
`authorize_route_owner` (`model_routes.rs:1497-1524`) resolves an unowned record to **the
deployment**, whose administrator is the only party that can dispose of it — fail-closed to
every ordinary principal and recoverable rather than stranded. The authority is
`require_authenticated_org_admin` via `RouteCaller.is_deployment_admin` (`:1467`).

So: an environment with no pin belongs to the deployment. Ordinary principals are refused
with a typed reason that says **unadopted**, not "not yours" — the truth is "nobody's", and
XIII paid for that distinction. The deployment administrator may read, stop and **delete**
it. Nothing binds a pin on its behalf.

**This is why the escape hatch does not fire.** The commission's file-and-stop trigger is
"no existing authority can carry it". The authority exists. Nothing in this design is
outside the estate's gift.

### R8 — The reach is not retroactive, and the gate says so.

The open-defect assertion in `check:environment-custody` flips in the LAST commit of a proven
fix, never the first. The honest claim is "owned from this leg forward"; legacy environments
are administered, not owned, and the residual names exactly that.

## What this design does NOT do

- It does not add an unbind. The substrate has none and inventing one is a second spine.
- It does not make ownership transferable. That is a separate governed act, named here so it
  cannot be smuggled in.
- It does not touch the capture custody lane, which already has an owner.
- It does not state whether an environment pin becomes a third retention subject kind
  (`retention_routes.rs:171`, `:492`, `:549`). **That is an open question this design does
  not answer** and it must be answered before the build closes.
- It does not cover `workrun-workspaces/<wr_id>` (`:3351-3353`), a second copy of workspace
  bytes written outside any environment coordinate. **Named open.**

## The verifier this design implies

Named here so the build cannot narrow it later. Revision 1's list is superseded: a review
demonstrated that all eight of its items could pass while the property was false.

1. **The closed world is every route whose handler can reach `environments/<id>/` or
   `status.workspace_root`** — derived from source, asserted in both directions. Not "the
   lifecycle plane", which is undefined and let an anonymous non-`/v1/` chain through.
2. Every route in that world refuses an anonymous request, PAIRED WITH A COUNT of the
   durable artifact it must not have produced — no workspace directory, no record, no lease.
3. **The anonymous ops-lease chain specifically**: minting a lease for another principal's
   environment is refused, and `WriteFile`/`Exec` are refused without a resolved principal.
4. A **GET** of a non-existent environment creates nothing on disk; an action on one is a
   404 and creates nothing.
5. **The create→start gap**: P1 creates, P2 starts — P2 is refused and P1 still owns it.
6. **Bind precedes bytes**: an induced write failure after a successful bind leaves no
   workspace directory and the pin still resolves to P1, who can retry.
7. A refused create leaves NO pin behind, proven by a subsequent successful create by a
   different principal.
8. A caller-supplied `environment_id` is refused, and two creates never produce the same id.
9. An alias spelling resolves to the SAME pin and is refused for the non-owner — including
   through the **lease** plane, which is keyed independently.
10. Delete: the owner is never refused; a non-owner is; a legacy environment is refused to
    an ordinary principal and available to the deployment administrator.
11. A legacy (unpinned) environment is refused with **unadopted**, not "not yours".
12. Mutations RED-ON-TARGET for each, floored in the same commit.

## Revision history

**Revision 1 (2026-08-15) — DEFEATED by adversarial review.** Seven ship-blockers and five
factual errors:

- **the fifth failure (F5)**: create and start are two requests and only start provisions, so
  binding at materialization awards P1's environment to whoever starts it;
- bind ordered AFTER the bytes, inverting the capture precedent it cited and refilling the
  unowned class at runtime;
- R1 scoped to two named routes when handler reach is fifteen-plus, including an anonymous
  non-`/v1/` chain to `WriteFile`/`Exec`;
- one `new_env` arm named when there are three, one of them a GET that persists;
- an adoption mechanism that cannot be built — no bind-on-behalf — while the authority it
  needed already ships as `authorize_route_owner`;
- caller-chosen ids plus no unbind, giving permanent squatting and a delete that consumes a
  name forever;
- one normalizer named when there are four, with the record and the lease plane both keyed
  raw.
- Factual errors corrected: the no-second-spine law is ADR 0031/0024, not "ADR 0034-branch";
  the ODK bind is not an authority crossing and is not the precedent for R7; "same shape as
  the capture fix" was false on bind ORDER and true only on daemon-minted ids; the lifecycle
  plane is not two routes; `new_env` is not one arm.

## Reversal

Owner-reversible. If the owner rules that the lifecycle plane must stay anonymous, this ADR
is superseded and defect 1a stays open with its gate assertion intact — which is the state
today, and is honest. The cost of that ruling is stated plainly: any authenticated principal
can capture any environment's workspace and restore its own capture back over it, **and an
entirely unauthenticated caller can mint an ops lease for any environment and read, write or
execute inside its workspace.**

## Status of the evidence

This ADR cites source locations at `6cfdcb5be`, re-verified after revision 1's review. It has
NOT been built and nothing here has been demonstrated live. It is a design, and the next act
is its review — not a branch.
