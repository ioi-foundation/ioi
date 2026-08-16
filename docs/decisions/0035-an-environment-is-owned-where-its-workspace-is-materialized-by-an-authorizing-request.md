# ADR 0035: An Environment Is Owned From Its First Durable Byte, And Every Handle To Its Bytes Authorizes

- Status: Proposed — DESIGN ONLY, REVISION 4. Revisions 1, 2 and 3 were each DEFEATED
  by their own review. No code exists and none may be written until this document
  survives. **Revision 3's "sound-conditional" status is WITHDRAWN: the dependency it
  filed does not exist.**
- Date: 2026-08-15
- Owners: daemon runtime / environment lifecycle / W1.5 disposition
- Refines: ADR 0031 and ADR 0024 (the one structural law — no second spine), ADR 0030
- Closes: defect 1a
- Confidence: high on the defect and on why seven designs failed; all seven are measured.
  Agent-proposed under standing program authority and owner-reversible.

## Why this is a document and not a branch

Four builds tried to give an environment an owner; a review demonstrated each broken. Three
revisions of this design were then each defeated in turn, finding a fifth, sixth and seventh
failure mode. Total cost: three review rounds on a document, against four broken builds before it.

## Two corrections this document owes, at source

**One.** Revision 2 stated that the ops-lease minter is "outside `/v1/`, so the global gate never
sees it". False: `POST /v1/hypervisor/environments/:id/ops-lease` is registered at
`hypervisor-daemon.rs:3348`. Only the consumer (`/supervisor/:env/…`, `:3355-3358`) is outside.

**Two, and it is the larger one.** Revision 3 FILED a dependency on
`ioi.hypervisor.authority-grant.v1`, claiming "the grant schema has no principal ref" and that
adding one is "the highest blast-radius change in the estate". **That is false, and the estate
already does exactly the opposite under a named invariant.** `issue_capability_lease` takes
`subject` as a parameter (`authority_routes.rs:195-240`) and writes it to the grant record at
`:232`. `handle_editor_access_lease_create` (`editor_routes.rs:724`) resolves it SERVER-SIDE to a
principal:

> **INV-37** — the lease SUBJECT is resolved SERVER-SIDE, never a caller-passed constant. A
> supplied session ref must resolve to a real session record; otherwise the authenticated
> principal is the subject; otherwise the request is refused. **The "operator" default is gone.**
> — `editor_routes.rs:730-732`

The ops-lease route simply passes the literal `"operator"` (`supervisor_routes.rs:37`), which is
the very default INV-37 removed everywhere else. So **there is nothing to file**: the row is
buildable today by following a pattern that already ships. Revision 3's supporting citation
(`authority_routes.rs:148`) pointed at `emit_receipt` on `authority-receipt.v1` — the wrong
schema. A dependency filed on a mis-read citation would have commissioned XV+ work that is not
needed, and the conditional status it produced is withdrawn.

## Context: what is true today, measured

Read at `6cfdcb5be`, re-verified after revision 3's review. Files named where not
`environment_routes.rs`.

**Creation happens at three seams and one is a GET.** `new_env` at `:2564`, `:2652`
(`handle_environment_get`, persisting at `:2661`), `:2679`. `:5199`/`:5208` are `#[cfg(test)]`.
None resolves a caller. **Create materializes no workspace** — `"workspace_root": Value::Null`
(`:257`); the only `provision_local_workspace` call is in the `"start"` arm (`:2724`).

**Bytes are reachable through SEVEN handles, and the environment id is only one of them.** Three
of the other six are served by modules with NO identity resolution anywhere in them:

| handle | reached by | resolves a caller? |
|---|---|---|
| environment id | create, get, `:action`, exec, env-files, logs, watch-state, env-config, idle-sweep, **ops-lease mint** (`supervisor_routes.rs:31`), snapshots, backups, scm/publish | mixed |
| terminal id | `binding_routes.rs:404`, `:608` | no |
| ops-lease id | `supervisor_routes.rs:305` (`ReadFile` `:349`, `WriteFile` `:410`, `Exec` `:556`) | bearer only |
| preview port | `lifecycle_routes.rs:9346-9351` | **no auth at all** |
| workrun id | `:3309`, `:4677` | no |
| **conversation id** | `agentops_routes.rs:98`, `:259` → `apply_turn` `:204` | **module contains ZERO `HeaderMap`** |
| **editor service id** | `editor_routes.rs:350`, `:412` → `editor_host::start_oss_runtime` `:197` | no |

`apply_turn` does `std::fs::write` into the workspace (`agentops_routes.rs:214`), then
`git add -A` (`:223`) and a commit — so it stages **every uncommitted byte of the owner's working
tree**. `start_oss_runtime` launches openvscode-server `--without-connection-token` (`editor_host.rs:247`)
rooted at the victim workspace (`:252-253`), and `editor_proxy.rs` fronts it with a raw
`TcpListener` (`:156`) whose gate allows a request carrying **no token at all** (`:106-109`).

**Two routes that resolve identity DO authorize, and revision 3 said they did not.**
`scm_publication_routes.rs:2765` calls `authorize_environment_owner` (`:2193-2243`) before
publishing. `managed_runtime_routes.rs:2598-2630` refuses an environment that is not the
authenticated principal's admitted managed instance. **The unauthorized pair is
`POST /v1/hypervisor/snapshots` (`:4040`) and `POST /v1/hypervisor/backups` (`:4048`)** — which
the estate's own verifier already names in prose at
`verify-hypervisor-environment-custody.mjs:226-229`.

**`POST /workruns` writes INTO the owned workspace** — `ensure_git_repo(&ws)` (`:3336`) and
`git worktree add -b` (`:3364-3375`) with `run_git` at `.current_dir(ws)` (`:356-360`), so a
branch and `.git/worktrees/<wr>` land in the owner's repo.

**The pin is genesis-only, has no unbind, and has no bind-on-behalf** (`substrate_store.rs:2899`;
`principal_ref` written at `:2938`). `read_request_scope` (`:2887`) is the non-binding read.
`authorize_request_resource_scope` (`:2970-2985`) requires an exact principal match **with no
administrator branch**, and `resolve_principal` requires `status == "active"` — while the estate
deprovisions principals (`lifecycle_routes.rs:17875`, SCIM at `:18394`+).

**Administration without pinning ships**: `authorize_route_owner` (`model_routes.rs:1497-1524`);
`require_authenticated_org_admin` (`lifecycle_routes.rs:16287-16294`) is `role == "admin"` AND
live `org://local` membership, and only the bootstrap operator is seeded admin (`:15707`).

**The capture fix binds before the bytes** — `:3592`, then `create_dir_all` `:3605`, `fs::write`
`:3607`. **Capture ids are daemon-minted** (`:3586`). **`gen_opaque`** (two v4 UUIDs) is at
`lifecycle_routes.rs:15663-15669` and is **private**.

**TEN normalizers touch the coordinate, and two of them are not like the others.** Eight fold
identically; `managed_runtime_routes::safe` (`:142-153`) preserves `'.'`, so it is STRICTER and
404s where the others silently alias; and `lifecycle_routes.rs:9613-9619` **refuses** a
non-canonical id rather than folding it — the shape `durable_fs::is_normalization_safe`
(`:725-730`) already names ("a caller must reject rather than collide"). A further copy lives
inside the shared writer: `hypervisor-daemon.rs:4448-4453` derives the FILE NAME, and
`"environments"` is not in `PROMOTED_DOMAINS` (`substrate_store.rs:42`), so that branch always
runs. Raw readings persist at `supervisor_routes.rs:146`, `authority_routes.rs:1019-1021`,
`managed_runtime_routes.rs:2618` and `:3790`, `lifecycle_routes.rs:9635`, `environment_routes.rs:588`, plus the
raw-keyed `st.live_vms` map (`hypervisor-daemon.rs:275`).

**`environment_id` is caller-supplied** (`:2554-2559`); `new_env` stores it RAW (`:235`).
**`org://local` isolates nothing.** **`delete` nulls `workspace_root`** (`:3172-3196`) under a
carve-out that says it "never refuses". **`auth_enforced` defaults to `auto`** (`:15802-15819`).
**`snap["environment_ref"]` is written once** (`:3616`), never updated.

## The seven failures, by name

**F1** pin at create — two other routes create, one a GET.
**F2** pin at first reference — first-touch renamed, permanent.
**F3** pin at workspace materialization — the route never refuses.
**F4** adoption gated on `status.workspace_root` — a field an anonymous route nulls.
**F5** F3 plus an identity-first lifecycle (rev 1) — create and start are two requests, so P1
creates and P2 starts and P2 owns it.
**F6** identity-first without AUTHORIZATION (rev 2) — a route that resolves a caller and never
authorizes cannot honour ownership. **Restated on measured evidence**: the live instances are
`POST /snapshots` and `POST /backups`, not `scm/publish`, which refuses today.
**F7** authorization ruled over a HAND-LISTED closed world (rev 3) — the list omitted the
conversation id, the editor service id, and the ops-lease MINT route, and the only derived
over-approximation available (`verify-hypervisor-environment-custody.mjs:210-225`) filters to
`environment_routes::`, so it cannot over-approximate the three modules the misses live in.
**A derived closed world is only as wide as what it derives over** — and revision 3 had
`agentops_routes::safe` and `editor_host`'s normalizer on its own page while omitting both
modules from its handle table.

## The ruling

### R1 — The closed world is DERIVED over handler reach, across every module, and the derivation is the deliverable.

Not a hand list. The census walks the router SOURCE for every registered route in every module,
and classifies each handler by whether it can reach `environments/<id>/` on disk or
`status.workspace_root` — transitively, through the module-local helpers that resolve a workspace
(`env_workspace` in `agentops_routes`, `editor_host`, `supervisor_routes`, `orchestration_routes.rs:109`).
Every route is classified or the census is RED; the classification is asserted in both directions.

This is the same instrument shape as the ontology admission census (Leg 3a): derived from source,
positive classification, no silent absence. Building it is part of this leg, not a precondition
borrowed from a verifier that cannot compute it.

**Every route in the derived world AUTHORIZES its caller against the pin**, per-handler and
unconditional — never delegated to `auth_gate`, whose policy defaults to OFF.

### R2 — Creation happens at exactly one seam; all three `new_env` arms outside it are deleted.

### R3 — Ids are minted by `gen_opaque`; the bind CAS-refuses a cross-principal repeat; the minter is made reachable.

`gen_env_id` is a wall clock whose `unwrap_or(0)` branch mints `env_0` for everyone.
`gen_opaque` (`lifecycle_routes.rs:15663-15669`) is the collision-free minter and is currently
private — making it reachable is part of this leg, and it is reconciled with `recipe_routes::gen_id`
(`:29`) rather than becoming a third minter.

The CAS is real and verified — `expected_head: None` → `expected_absent` → `ExpectedAbsentConflict`
→ `ResourceOwnerMismatch` — but it refuses only a DIFFERENT principal: the read-check at
`substrate_store.rs:2911-2921` returns `Ok(existing)` for the same principal. So a same-principal
collision is not caught by the bind, and the create path must detect it by the coordinate already
being occupied rather than by the refusal.

**Blast radius, budgeted**: `verify-hypervisor-environment-custody.mjs:309`,
`verify-hypervisor-backup-restore.mjs:260`, `verify-hypervisor-placement-venue-picker.mjs:135`,
`verify-hypervisor-cloud-candidate-plane.mjs:191`. The custody alias fixture survives, because
`gen_opaque("env")` still yields exactly one underscore. And three INTERNAL self-calls create
environments over HTTP — `orchestration_routes.rs:1556-1562`, `:2613-2619`,
`operability_routes.rs:1076-1082`, the first driven by the background scheduler
(`hypervisor-daemon.rs:3964`) under `internal_dispatch_authorized` — so each must resolve to a real
principal or the plane refuses them.

### R4 — The pin binds before the first durable byte AT THE ENVIRONMENT COORDINATE.

Bind, then write: a failed write leaves a pin with no bytes and the owner retries; a failed bind
leaves bytes with no owner, refilling at runtime the class R8 closes once. Qualified to the
coordinate because `detect_and_admit` (`recipe_routes.rs:358-368`) persists a recipe at `:366`
before `persist_env` at `:2608`. Idempotency key `environment-owner:<canonical-id>`.

### R5 — ONE canonicalizer, one REJECTOR, and the write-side copy named.

The eight folding copies collapse to one that RETURNS the canonical coordinate, and `new_env`
stores it. But R5 cannot be "one normalizer" as revision 3 ruled, because
`hypervisor-daemon.rs:4448-4453` derives the FILE NAME inside the shared `persist_record` and is
generic across families. So the ruling is: the coordinate is canonicalized ONCE at the edge, and
the shared writer's copy is left alone precisely because it is not environment-specific — it must
receive an already-canonical id.

**And the estate's own better shape is adopted**: `lifecycle_routes.rs:9613-9619` REFUSES a
non-canonical id rather than folding it, which is what `durable_fs::is_normalization_safe`
(`:725-730`) names. Under R3 ids are daemon-minted, so refusal costs nothing and removes the
many-to-one map at the source instead of papering it.

`managed_runtime_routes::safe` is stricter, not looser — it preserves `'.'` — so the hazard is a
404 against a different file, and `managed_runtime_routes.rs:2618` authorizes on the RAW id while
`:1936-1939` reads on the folded one: two coordinates in one request. `lease_binds_env`'s
kind-less disjunction (`supervisor_routes.rs:146`) is narrowed, and so is its duplicate at
`authority_routes.rs:1019-1021`.

### R6 — Ownership resolves through the pin. A derived subject needs immutability AND no alternative.

`snap["environment_ref"]` is written once (`:3616`) and never updated, and restore
(`:4092-4095`) has no other subject — both conditions hold, so the restore check is buildable.
Immutability ALONE is not the discriminator: `wr["environment_id"]` is also written once
(`:3387`) and never reassigned, so revision 3's clause readmitted the workrun subject it was
invoked to refuse. The workrun path DOES have an alternative — derive the environment from the
pin at create time and record it as a bound fact — so it takes that.

**`delete`'s carve-out is re-ruled**: never refuses the OWNER, cleanup guarantee unchanged;
refuses a non-owner; available to the deployment administrator for an unowned or stranded one.

### R7 — Legacy environments are ADMINISTERED, and the administrator's reach over OWNED ones is ruled, not inherited.

An environment with no pin belongs to the deployment; ordinary principals are refused with
**unadopted**, not "not yours". Adopt the ADMINISTRATOR half of `authorize_route_owner`
(`model_routes.rs:1506-1508`) and NOT the half that branches on `route["owner_ref"]`
(`:1509`, `:1515`), which R6 forbids and which environment records do not have.

Revision 3 left the bypass unconditional, which would silently grant the deployment administrator
full access to OWNED environments. It is ruled explicitly: the administrator may **dispose** of any
environment (stop, delete, place under retention) and may **not read or write** an owned
workspace. Disposal is receipted.

Note this widens two live checks that today refuse legacy environments to everyone except
`user://local-operator` in `single_user` posture — `scm_publication_routes::authorize_environment_owner`
(`:2193-2243`) and `lifecycle_routes::bind_env_workspace` (`:9639-9651`). That widening is
deliberate and is stated rather than absorbed.

### R8 — The reach is not retroactive; FIVE assertions flip, not one.

The no-binder source test, the capture-harm and restore-harm assertions, and two `NAMED_UNOWNED`
entries (`verify-hypervisor-environment-custody.mjs:258`, `:262`).

### R9 — `GET /environments` is scoped, on the `handle_snapshots_list` precedent (`:4066-4086`).

The SPA forwards caller identity per request (`ioi-api-adapter.mjs:61`, `:100`, `:467`), so
scoping does not break it; `serve-product-ui.mjs:9411` is a second consumer the build must check.

### R10 — A PIN MUST NOT OUTLIVE ITS PRINCIPAL. (New — the case no revision had ruled.)

The pin is genesis-only with no unbind, `authorize_request_resource_scope` has no administrator
branch, and `resolve_principal` requires `status == "active"` while the estate deprovisions
principals. Under R6/R7/R9 as previously written, a deprovisioned principal's environments become
invisible to everyone, unstartable, unstoppable and **undeletable by anyone including the
administrator**, with bytes on disk — the exact state `delete`'s carve-out promises never happens.

The ruling: **disposal authority resolves through the deployment administrator whenever the pinned
principal cannot be resolved as active.** This adds an administrator branch to the environment
plane's own authorization, never to `authorize_request_resource_scope`, so nothing widens for any
other subject kind. It is disposal only — never read, never write, never re-pin — because there is
no unbind and inventing one is a second spine.

### R11 — The three unauthenticated surfaces are BUILT, not filed.

Revision 3 filed these behind a schema change that does not exist:

- **the ops-lease mint route** (`supervisor_routes.rs:31`) becomes identity-first, authorizes
  against the pin, and passes the resolved `principal_ref` as `subject` — the INV-37 pattern
  (`editor_routes.rs:730-732`, `:762-785`, `:795-801`). `authed()` (`:177-183`) then compares
  `grant["subject"]` against the pin, so **no caller identity is needed at the `/supervisor/` seam
  at all** and the Workbench transport contract (`:164-166`, which drops the env PATH, not headers)
  is untouched;
- **the preview server** (`lifecycle_routes.rs:9339-9351`) receives `data_dir` and the environment
  id alongside `workspace_root` and authorizes — a `lifecycle_routes` change, not a kernel one;
- **the editor proxy** (`editor_proxy.rs:106-109`), which today allows a request carrying NO token,
  is closed. Revision 3 missed this surface entirely.

## The verifier this design implies

1. **The closed world is DERIVED over handler reach across every module**, positively classified,
   asserted in both directions — a route the census cannot classify is RED.
2. Every route in it refuses an ANONYMOUS request, paired with a count of the durable artifact it
   must not have produced.
3. **Every route in it refuses a NON-OWNER**, paired with the same count. The property.
4. The seven handles each, by name — environment id, terminal, ops-lease, preview port, workrun,
   **conversation, editor service** — driven end to end by a non-owner.
5. `POST /snapshots` and `POST /backups` specifically.
6. A GET of a non-existent environment creates nothing; an action on one is a 404.
7. The create→start gap: P1 creates, P2 starts — refused, P1 still owns it.
8. Bind precedes bytes: an induced write failure leaves no workspace directory and the pin intact.
9. A refused create leaves no pin.
10. A caller-supplied id is refused; a non-canonical id is REFUSED, not folded; a forced collision
    is re-minted, not awarded.
11. An alias spelling resolves to the same pin and is refused for a non-owner — through the lease
    plane and the managed-backup family, which key independently.
12. A workrun cannot be created or executed by a non-owner, and no branch or worktree metadata
    appears in the owner's `.git`.
13. **A deprovisioned owner's environment is disposable by the administrator and readable by
    nobody**, with a count proving no read occurred.
14. Delete: owner never refused; non-owner refused; unadopted available to the administrator.
15. An unadopted environment is refused with **unadopted**, not "not yours".
16. `GET /environments` returns only the caller's own.
17. The administrator can dispose of an owned environment and CANNOT read or write it.
18. Mutations RED-ON-TARGET for each, floored in the same commit.

## Revision history

**Revision 1 — DEFEATED.** F5; bind after the bytes; R1 at two routes; one `new_env` arm named of
three; an unbuildable adoption; caller-chosen ids; four normalizers named. Five factual errors.

**Revision 2 — DEFEATED.** F6; the workrun path filed out of scope while writing into the owner's
repo; a predicate its instrument could not compute; an unnamed schema requirement; R6 forbidding
its own consequence; a minter asserted not named; eight normalizers, the divergent one missed. Ten
factual errors including the `/v1/` claim.

**Revision 3 — DEFEATED.** F7; a hand-listed closed world missing three handles including the mint
route for the handle it declared unauthorizable; **a FILED dependency that does not exist**, on a
citation pointing at the wrong schema, which would have commissioned unnecessary XV+ work; F6's
evidence two-thirds false (`scm/publish` and managed backups both authorize today); ten
normalizers not eight, with the write-side and rejecting copies missed; the deprovisioned-owner
strand unruled; R7's administrator bypass left unconditional over owned environments; the editor
proxy's tokenless path missed.

**Revision 4 — CITATION-AUDITED before landing.** An independent audit of ~70 load-bearing
citations found the two headline reversals SOUND (the ops-lease minter is inside `/v1/` at
`hypervisor-daemon.rs:3348`; `issue_capability_lease` carries a `subject` and INV-37 resolves a
principal into it) and every behavioural claim reproducing, and four citation errors, all
corrected here: the INV-37 quote block is `editor_routes.rs:730-732` not `:733-735`; the
`POST /backups` handler is `:4048` not `:3583` (a line inside the shared `capture_workspace`
helper); the `host_ports_in_use` raw read is `environment_routes.rs:588` not `lifecycle_routes.rs`;
and the fourth workspace-resolving helper is `orchestration_routes.rs:109`, not an `env_workspace`
in `operability_routes` (which has none). None touched a load-bearing conclusion.

## Reversal

Owner-reversible. If the plane stays as it is, 1a stays open with its gate assertion intact. The
cost, counted correctly at last: any authenticated principal can capture any environment's
workspace and restore its own capture over it; **and an entirely unauthenticated caller can mint
an ops lease for any environment and read, write or execute inside its workspace, drive an
AgentOps conversation that writes a file and commits the owner's entire working tree, launch a
tokenless browser IDE rooted at the owner's workspace, and reach that IDE through a proxy that
admits a request carrying no token at all.**

## Status of the evidence

Citations re-verified against source after revision 3's review, including the two that reversed
this document's own claims. Nothing here has been built or demonstrated live.
