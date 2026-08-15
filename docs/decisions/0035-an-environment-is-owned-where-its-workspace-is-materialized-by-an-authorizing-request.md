# ADR 0035: An Environment Is Owned From Its First Durable Byte, And Every Handle To Its Bytes Authorizes

- Status: Proposed — DESIGN ONLY, REVISION 3, and **SOUND-CONDITIONAL**: one ruling
  (R1, at the ops surface) cannot be built without a change to
  `ioi.hypervisor.authority-grant.v1`, which is FILED below as a dependency and is
  NOT assumed by anything here. Revisions 1 and 2 were each DEFEATED by their own
  review; see *Revision history*. No code exists and none may be written until this
  document has survived its review.
- Date: 2026-08-15
- Owners: daemon runtime / environment lifecycle / W1.5 disposition
- Refines: ADR 0031 and ADR 0024 (the one structural law — no second spine), ADR 0030
- Closes: defect 1a **conditionally** — see *The filed dependency*
- Confidence: high on the defect and on why six designs failed; all six are measured.
  Agent-proposed under standing program authority and owner-reversible.

## Why this is a document and not a branch

Four builds tried to give an environment an owner and a review demonstrated each one broken. A
fifth attempt without a ruled design is the demonstrated failure mode, and next-legs XIV forbids
it.

**Revisions 1 and 2 of this document were then each defeated by their own review**, finding a
fifth and a sixth failure mode. Total cost: two review rounds on a document. That is the whole
argument, and it is why the failure list below is six long instead of four.

## A correction this document owes, at source

Revision 2 stated as measured fact that the ops-lease minter is "outside `/v1/`, and
`auth_gate_exempt_path` returns true for every non-`/v1` path, so the global gate never sees it."
**That is false.** `POST /v1/hypervisor/environments/:id/ops-lease` is registered at
`hypervisor-daemon.rs:3348` — inside `/v1/`, and inside exactly the environments family. Only the
CONSUMER (`/supervisor/:env/…`, `hypervisor-daemon.rs:3355-3358`) sits outside.

It was written on a reviewer's finding without fetching the ref, which is a scar this program has
already paid for once. The durable defect is not the path — it is that the lease record carries no
principal (R1 and *The filed dependency*), and that survives with the auth gate fully enforced.

## Context: what is true today, measured

Read at `6cfdcb5be`. Every citation below was re-verified against source after revision 2's review;
the file is named where it is not `environment_routes.rs`.

**Creation happens at three seams and one is a GET.** `new_env` is called at `:2564`
(`handle_environment_create`), `:2652` (`handle_environment_get`, which auto-vivifies and
**persists at `:2661`**), and `:2679` (`handle_environment_action`). `:5199`/`:5208` are
`#[cfg(test)]`. None of the three resolves a caller.

**Create materializes no workspace.** `new_env` sets `"workspace_root": Value::Null` (`:257`); the
only `provision_local_workspace` call is in the `"start"` arm (`:2724`). Record and workspace are
born at two separate client requests.

**Identity is resolved on some routes and authorizes nothing.** Three that reach owned bytes today:

| route | identity resolved | reaches the owner's bytes |
|---|---|---|
| `POST /environments/:id/scm/publish` | `scm_publication_routes.rs:2719` | reads `workspace_root` at `:2732`, publishes **outward** |
| `POST /snapshots` | `:4040` | tars the workspace at `:3565-3573` |
| `POST /environments/:id/backups` | `managed_runtime_routes.rs:2495` | `:1936-1944` |

**Bytes are reachable through handles that are not the environment id**: a terminal id
(`binding_routes.rs:608`), an ops-lease id (`supervisor_routes.rs:305`), an ephemeral preview port
(`lifecycle_routes.rs:9346-9351`, a second axum server whose state is the bare `workspace_root`
string), and a workrun id (`:4677`).

**`POST /workruns` writes INTO the owned workspace.** `handle_workrun_create` (`:3309`, no
`HeaderMap`) runs `ensure_git_repo(&ws)` (`:3336`) and
`git worktree add -b <branch>` (`:3364-3375`) with `run_git` executing `.current_dir(ws)`
(`:356-360`). A linked worktree shares the owner's object store: the call creates a branch in the
owner's repo and writes `.git/worktrees/<wr>` into the owner's `.git`, and every
`handle_workrun_execute` commit (`:4677`) lands in the owner's objects. `handle_workrun_execute`
derives its environment only from `wr["environment_id"]` (`:4689-4692`), a record field written at
`:3387` from a caller-supplied body value (`:3313-3316`).

**The scope pin is genesis-only, has no unbind, and has no bind-on-behalf.**
`substrate_store.rs:2899`; `principal_ref: identity.principal_ref` at **`:2938`**.
**`read_request_scope` (`:2887`) is the non-binding read.**

**Administration without pinning already ships.** `model_routes::authorize_route_owner`
(`model_routes.rs:1497-1524`) resolves an unowned record to the deployment, whose administrator is
the only party that can dispose of it. Authority: `require_authenticated_org_admin`
(`lifecycle_routes.rs:16287-16294`) = `role == "admin"` **and** live `org://local` membership. Only
the bootstrap operator is seeded `admin` (`:15707`); SSO auto-join (`:18349`), invite accept
(`:18684`, `:19181`) and SCIM all grant `member`. **It discriminates.**

**The capture fix binds before the bytes** — bind `:3592`, `create_dir_all` **`:3605`**,
`fs::write` **`:3607`** — "Binding first means a capture record can never exist on disk without an
owner." **Capture ids are daemon-minted (`:3586`).**

**A collision-free minter already ships**: `gen_opaque` (`lifecycle_routes.rs:15663-15669`), two v4
UUIDs. `gen_env_id` (`:196-202`) is `format!("env_{nanos:x}")` from a wall clock, with
`unwrap_or(0)`.

**`environment_id` is caller-supplied** (`:2554-2559`) and `new_env` stores the RAW spelling
(`:235`).

**EIGHT normalizers are applied to the `environments/` coordinate**, and one DISAGREES:
`environment_routes::safe_id` (`:189`), `supervisor_routes::safe` (**`:59`**),
`operability_routes::safe` (`:25`), `editor_host` inline (**`:184-187`**), `binding_routes::safe`
(`:40`), `agentops_routes::safe` (`:29`), `orchestration_routes::safe` (`:29`), and
`managed_runtime_routes::safe` (`:142-151`) — **which admits `'.'`**, so `a.b` stays `a.b` there and
becomes `a_b` everywhere else. `scm_publication_routes.rs:2723-2725` matches `record["id"]` raw,
through no normalizer at all.

**A lease carries no principal.** `issue_capability_lease` (`authority_routes.rs:195-240`) writes
`"subject": subject` (`:148`) from the literal `"operator"` passed at `supervisor_routes.rs:37`.
`authed()` (`:177-183`) can therefore only check that a lease is active and names this environment.

**`snap["environment_ref"]` is written once** (`:3616`) and no route updates it; `:3851` propagates
it and `:4110` reads it.

**`org://local` isolates nothing.** **`delete` nulls `workspace_root`** (`:3172-3196`) and carries a
carve-out: "deletion of an EXISTING environment REMAINS CALLABLE … **It never refuses.**"
**`auth_enforced` defaults to `auto`** (`:15802-15819`); "Default policy is OFF" is the `auth_gate`
doc comment at **`:17239`**.

## The six failures, by name

**F1 pin at create** — two other routes also create, one a GET.
**F2 pin at first reference** — first-touch renamed; permanent, since there is no unbind.
**F3 pin at workspace materialization** — reached from a route that never refuses.
**F4 adoption gated on `status.workspace_root`** — a mutable field an anonymous route nulls.
**F5 pin at materialization WITH an identity-first lifecycle (revision 1)** — create and start are
two requests and only start provisions, so P1 creates and P2 starts and P2 owns it forever.
**F6 identity-first WITHOUT authorization (revision 2)** — P1 creates and starts; P2, any
authenticated `org://local` member, calls `POST /environments/<id>/scm/publish`; identity resolves,
so revision 2's R1 is satisfied with **zero code change**, and P1's source is published to a remote
P2 controls. Revision 2's twelve verifier items all stay green.

F5 was *a route that cannot refuse cannot mint ownership*. **F6 is its dual: a route that resolves a
caller but never authorizes cannot honour ownership** — and revision 2's entire apparatus was about
anonymity.

## The ruling

### R1 — Every HANDLE to an environment's bytes AUTHORIZES its caller against the pin.

Not "resolves a caller" — that was F6. The obligation is authorization, and the closed world is
**every route whose handler can reach `environments/<id>/` on disk or `status.workspace_root`,
enumerated by the HANDLE it takes**, because a path-shaped derivation cannot see three of them:

| handle | reached by |
|---|---|
| environment id | create, get, the wildcard `:action`, exec, env-files, logs, watch-state, env-config, idle-sweep, snapshots, backups, scm/publish |
| **terminal id** | `binding_routes.rs:404`, `:608` |
| **ops-lease id** | `supervisor_routes.rs:305` — see *The filed dependency* |
| **preview port** | `lifecycle_routes.rs:9346-9351` — see *The filed dependency* |
| **workrun id** | `:3309`, `:4677` |

Every refusal is per-handler and unconditional; none may be delegated to `auth_gate`, whose policy
defaults to OFF.

**The instrument is a build obligation, not an extension of the existing regex.**
`verify-hypervisor-environment-custody.mjs:211-225` derives by regex over `.route(` chunks filtered
to `/v1/hypervisor/…` and `environment_routes::`, and is structurally blind to non-`/v1/` paths, to
the preview server, and to other modules. Its `NAMED_UNOWNED` list (`:257-273`) holds fifteen
entries, four of which are the projects plane and agent-run transcripts and explicitly not this leg.
The census this design needs is over handler reach, which that instrument cannot compute — so the
build must state the closed world it derives and assert it in both directions, and a hand list is
acceptable ONLY if every entry is justified against a derived over-approximation.

### R2 — Creation happens at exactly one seam; all three `new_env` arms outside it are deleted.

The GET's auto-vivify (`:2652`) and the action arm (`:2679`) both go. Leaving the GET would mint
unbounded records under R6 that no ordinary principal can delete.

### R3 — Environment ids are minted by `gen_opaque`, and the bind CAS-refuses a repeat.

Revision 2 asserted "daemon-minted ids are never reused" as a property. It is not one:
`gen_env_id` is a wall clock, so an NTP step-back, two creates inside one nanosecond bucket, or two
daemons on one `data_dir` reproduce an id — and `unwrap_or(0)` mints `env_0` for everyone, whose
first caller owns it forever. Under a genesis-only pin that is exactly the hazard daemon-minting was
supposed to remove.

So: mint with `gen_opaque` (`lifecycle_routes.rs:15663-15669`), and **require the bind to refuse a
repeat rather than trusting the minter** — the substrate already does this
(`expected_absent` → `ExpectedAbsentConflict` → `ResourceOwnerMismatch`), so the create path treats
that refusal as "mint again", not as an error. A caller-supplied id is refused; callers keep a
`display_name`.

**Blast radius, budgeted rather than discovered:** four verifiers pass a caller-chosen
`environment_id` and must change — `verify-hypervisor-environment-custody.mjs:309`,
`verify-hypervisor-backup-restore.mjs:260`, `verify-hypervisor-placement-venue-picker.mjs:135`,
`verify-hypervisor-cloud-candidate-plane.mjs:191`. The custody one is load-bearing: its alias
fixture (`:350-353`, `:412`) deliberately chooses an underscore id, and R3 removes the caller's
ability to choose it. That fixture must be rebuilt against a minted id whose canonical and raw forms
still differ, or the alias property loses its test.

### R4 — The pin binds before the first durable byte AT THE ENVIRONMENT COORDINATE.

Bind, then write. A failed write leaves a pin with no bytes and the owner retries; a failed bind
leaves bytes with no owner, which is indistinguishable from a legacy environment, claimable by
whichever different principal retries, and **refills at runtime** the class R8 closes once.

"First durable byte" is qualified deliberately: `detect_and_admit` (`recipe_routes.rs:358-368`)
persists a recipe at `:366` from `environment_routes.rs:2574` before `persist_env` at `:2608`. That
is a durable write the create path makes and it is not at the environment coordinate. The rule binds
to the coordinate, not to the first write of any kind.

`start` and every other handle AUTHORIZE against the existing pin through `read_request_scope`. **No
route other than create ever mints one.**

Idempotency key: `environment-owner:<canonical-id>`, mirroring `environment-capture-owner:{id}`
(`:3598`).

### R5 — One normalizer, canonical in the record, canonical in every plane that keys on the coordinate.

Eight copies collapse to one that RETURNS the canonical coordinate. `new_env` stores the canonical
id (`:235` today stores the raw one, which also fixes `scm_publication_routes.rs:2723-2725`, the
ninth reading, which uses no normalizer at all). **`managed_runtime_routes::safe` is the one that
DISAGREES** — it admits `'.'`, so the managed-backup family resolves a different file than the pin's
coordinate for any dotted id; collapsing "the four identical copies" would have left the single
divergence in place. `supervisor_routes::lease_binds_env` (`:141-147`) is re-keyed on the canonical
coordinate, and its bare-`env_id` disjunction (`:146`) is narrowed with it.

### R6 — Ownership resolves through the pin. A derived subject is legitimate only where the field it derives from is IMMUTABLE.

`status.workspace_root`, `owner_ref` and every other mutable record field are descriptive.

But two paths have no other subject, and revision 2 forbade its own named consequence by forgetting
why: `handle_snapshot_restore` (`:4092-4095`) receives only the CAPTURE id, so the destination is
knowable only from `snap["environment_ref"]` (`:4110-4113`). That is legitimate **because that field
is written once at `:3616` and no route updates it** — immutability, not canonicalization, is what
makes a derived subject safe. State the clause and the restore check is buildable.

The same clause refuses `handle_workrun_execute`'s subject: `wr["environment_id"]` is caller-supplied
(`:3313-3316` → `:3387`), so it is NOT immutable and may not carry authorization. The workrun path
must derive its environment from the pin at create time and record it as a bound fact.

**`delete`'s never-refuses carve-out is re-ruled explicitly** rather than silently overridden: it
never refuses the OWNER and its cleanup-obligation guarantee is unchanged; it refuses a non-owner;
and for an unadopted environment it is available to the deployment administrator under R7.

### R7 — Legacy environments are ADMINISTERED, not adopted.

There is no bind-on-behalf, so an "adoption" could only make the administrator the permanent owner of
every legacy environment. Instead: an environment with no pin belongs to the deployment.
Ordinary principals are refused with a typed reason that says **unadopted**, not "not yours" — the
truth is "nobody's". The deployment administrator may read, stop and delete it. Nothing binds a pin
on its behalf.

Adopt the half of `authorize_route_owner` that consults the ADMINISTRATOR, not the half that branches
on a record's `owner_ref` — environment records carry none, and R6 forbids it. The helper is private
to `model_routes` and keyed to that module's records; the build owes a SHARED helper rather than a
second copy, because the estate already rules there is "one answer to 'may this principal make this
crossing'" (`lifecycle_routes.rs:16282-16286`).

### R8 — The reach is not retroactive, and FIVE assertions flip, not one.

`check:environment-custody` carries the no-binder source test, the capture-harm assertion, the
restore-harm assertion, and two `NAMED_UNOWNED` entries (`:258`, `:262`) bound to this defect. They
flip in the LAST commit of a proven fix.

### R9 — `GET /environments` is scoped.

`handle_environments_list` (`:2274-2276`) takes only `State` and returns every environment in the
estate with absolute `workspace_root` paths. `handle_snapshots_list` (`:4066-4086`) is the estate's
own fixed shape for exactly this and is the precedent.

## The filed dependency — `ioi.hypervisor.authority-grant.v1` carries no principal

**R1 cannot be built at the ops surface or the preview server without a change this design does not
make and does not assume.** Both citations, per the two-sources discipline:

- **The requirement**: R1 obliges `handle_environment_ops` (`supervisor_routes.rs:305`) — whose
  methods are `ReadFile` (`:349`), `WriteFile` (`:410`) and `Exec` (`:556`) — to authorize its
  caller against the pin. `authed()` (`:177-183`) has no caller to authorize: the bearer it
  validates is principal-free.
- **The substrate location**: `issue_capability_lease` (`authority_routes.rs:195-240`) writes
  `"subject": subject` at `:148`, taking the literal `"operator"` from `supervisor_routes.rs:37`.
  The grant schema has no principal ref. The same holds for the preview server
  (`lifecycle_routes.rs:9346-9351`), whose state is the bare `workspace_root` string with no
  `data_dir` and no headers.

Requiring a session ALONGSIDE the lease is not an escape: the Workbench transport contract drops the
env path by design (`supervisor_routes.rs:164-166`).

**This is filed, not designed.** A principal ref on a kernel authority grant is the highest
blast-radius change in the estate — the editor lane and port-preview consume the same records — and
it does not ride into existence as a footnote in an environment-ownership ADR. It is commissioned as
XV+ work with its own adversarial cycle.

**Therefore this design is SOUND-CONDITIONAL and defect 1a closes CONDITIONALLY.** Every ruling
except R1's ops-lease and preview-port rows is buildable today. Those two rows, and the 1a gate
assertion, stay OPEN until the filed change lands. **No code in this run assumes it.** The honest
statement at merge is: the environment plane authorizes every handle it can, two handles remain
unauthorizable by construction, and they are named.

## The verifier this design implies

Revision 2's twelve are superseded — a review demonstrated all twelve passing while a non-owner
published the owner's source.

1. **The closed world is every route whose handler can reach `environments/<id>/` or
   `status.workspace_root`, enumerated by handle**, asserted in both directions.
2. Every route in it refuses an ANONYMOUS request, paired with a count of the durable artifact it
   must not have produced.
3. **Every route in it refuses a NON-OWNER**, paired with the same count. This is the item whose
   absence let F6 through, and it is the property.
4. `scm/publish`, `snapshots` and `backups` specifically — the three that resolve identity today and
   authorize nothing.
5. A GET of a non-existent environment creates nothing; an action on one is a 404.
6. **The create→start gap**: P1 creates, P2 starts — P2 refused, P1 still owns it.
7. **Bind precedes bytes**: an induced write failure after a successful bind leaves no workspace
   directory and the pin still resolves to P1.
8. A refused create leaves no pin, proven by a later successful create by a different principal.
9. A caller-supplied `environment_id` is refused; ids come from `gen_opaque`; a forced id collision
   is refused by the bind and re-minted, not awarded.
10. An alias spelling resolves to the same pin and is refused for the non-owner — **including
    through the lease plane and the managed-backup family**, which normalize independently.
11. A workrun cannot be created or executed against an environment the caller does not own, and no
    branch or worktree metadata appears in the owner's `.git`.
12. Delete: the owner is never refused; a non-owner is; a legacy environment is refused to an
    ordinary principal and available to the deployment administrator.
13. A legacy environment is refused with **unadopted**, not "not yours".
14. `GET /environments` returns only the caller's own.
15. **The two unauthorizable handles are asserted as such** — the ops-lease and preview-port rows
    are proven still open, so the residual cannot quietly close or quietly widen.
16. Mutations RED-ON-TARGET for each, floored in the same commit.

## Revision history

**Revision 1 — DEFEATED.** Seven ship-blockers: F5; bind ordered after the bytes; R1 scoped to two
routes; one `new_env` arm named when there are three; an adoption mechanism that cannot be built;
caller-chosen ids with no unbind; one normalizer named when there are four. Five factual errors.

**Revision 2 — DEFEATED.** Seven more: F6; the workrun path filed as out-of-scope when it writes
into the owner's repo; a closed-world predicate its named instrument cannot compute; the ops surface
needing an unnamed schema change; R6 forbidding its own named consequence; a minter asserted rather
than named; four normalizers named when there are eight, and the missed one is the only divergent
one. Ten factual errors, including the `/v1/` claim corrected at the top of this document — written
on a reviewer's finding without fetching the ref.

## Reversal

Owner-reversible. If the owner rules the plane must stay as it is, this ADR is superseded and 1a
stays open with its gate assertion intact. The cost, stated correctly this time — revision 2
undercounted it because R6 closes only the restore half: any authenticated principal can **capture**
any environment's workspace (`check:environment-custody` asserts this live) **and** restore its own
capture back over it, **and** publish its source outward, **and** an ops lease minted for any
environment grants `ReadFile`/`WriteFile`/`Exec` inside its workspace to whoever holds the bearer.

## Status of the evidence

Citations re-verified against source after revision 2's review. Nothing here has been built or
demonstrated live. The next act is this document's review.
