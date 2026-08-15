# ADR 0035: An Environment Is Owned Where Its Workspace Is Materialized By A Request That Could Have Refused

- Status: Proposed — DESIGN ONLY. No code exists for this ADR and none may be written
  until this document has survived its own adversarial review (next-legs XIV Leg 2d).
- Date: 2026-08-15
- Owners: daemon runtime / environment lifecycle / W1.5 disposition
- Refines: ADR 0030, ADR 0034-branch (the one structural law), the substrate scope pin
- Closes: defect 1a, open since next-legs XI, gate-asserted open since XIII
- Confidence: high on the defect and on why the four previous designs failed —
  both are measured below. The ruling is agent-proposed under standing program
  authority and is owner-reversible (see Reversal).

## Why this is a document and not a branch

Four builds have tried to give an environment an owner. Each was demonstrated broken by a
merge-blocking review, and the fifth attempt without a ruled design is the demonstrated
failure mode. Next-legs XIV forbids it in as many words. So this is the deliverable: a
design that answers each of the four failures BY NAME and rules the two load-bearing
questions, filed before any code exists.

If this design is wrong, the cost of finding out is a review round on a document.

## Context: what is actually true today, measured

Every claim in this section was read from the tree at `6cfdcb5be`.

**The lifecycle plane resolves no caller.** `handle_environment_create`
(`crates/node/src/bin/hypervisor_daemon_routes/environment_routes.rs:2549`) takes
`State` and `Json` and no `HeaderMap`. `handle_environment_action`
(`:2671`) takes `State` and `AxumPath` and no `HeaderMap`. Neither calls
`resolve_request_identity`. They are registered at:

```text
POST /v1/hypervisor/environments            -> handle_environment_create
POST /v1/hypervisor/environments/:id/:action -> handle_environment_action
```

**The action route is a create route wearing a different hat.** `handle_environment_action`
opens with:

```rust
let mut env = match load_env(&st.data_dir, &id) {
    Some(env) => env,
    None => new_env(&id, &json!({}))?,
};
```

So `POST /v1/hypervisor/environments/anything-at-all/start` MATERIALIZES an environment
that did not exist, anonymously, on a wildcard `:action` registration. This is the single
most important measured fact in this document and it is why "pin at create" could not work:
**`create` is not the creation seam.**

**Provisioning is an idempotent mkdir of a deterministic path.**

```rust
fn provision_local_workspace(data_dir: &str, id: &str) -> Result<String, AppError> {
    let ws = Path::new(data_dir).join("environments").join(safe_id(id)).join("workspace");
    std::fs::create_dir_all(&ws)...
}
```

It cannot refuse, it cannot tell a first call from a thousandth, and it is reached from
the anonymous action route (`:2724`).

**The scope pin is genesis-only and there is no unbind.**
`substrate_store::bind_request_resource_scope` (`substrate_store.rs:2899`) refuses with
`ResourceOwnerMismatch` whenever a scope already exists that does not match the caller
exactly. Nothing removes one. Whatever a pin lands on is pinned forever, for every
principal including the deployment administrator.

**But there is a non-binding read.** `read_request_scope` (`:2887`) exists and is already
`pub(crate)` for exactly this reason — so that asking "who owns this?" is not itself a
mutation. **This is the substrate affordance the four failed designs did not use**, and it
is what makes this design possible without a substrate change.

**`safe_id` is many-to-one.** `id.replace(|c| !c.is_ascii_alphanumeric() && c != '-' && c != '_', "_")`
(`environment_routes.rs:189`). `a.b` and `a_b` are one workspace and two spellings.

**`org://local` is the only constructible organization and every principal holds it**, so
no tenant check isolates anything. Ownership is per-PRINCIPAL.

**`delete` nulls `status.workspace_root`** (`:3172`–`:3196`) and is reachable anonymously.

## The four failures, by name

**F1 — pin at create.** Broken because the action route creates. A pin minted in
`handle_environment_create` covers only environments that happened to arrive through the
route named "create"; every other one is born unowned, and an attacker simply uses the
other door. *Also* broken because create resolves no caller, so the pin would name nobody.

**F2 — pin at first reference.** This is first-touch under a different name. Whoever gets
there first owns it, including an unauthenticated party, and — because the pin is
genesis-only with no unbind — owns it permanently.

**F3 — pin at workspace materialization.** The closest to right, and still broken as
built: `provision_local_workspace` is reached from a route that resolves no caller and
never refuses, so the pin minted beside it is F2 with extra steps. **The location was
correct; the authority was missing.** This design keeps the location and supplies the
authority.

**F4 — adoption gated on `status.workspace_root`.** Broken because that field is a
MUTABLE field an ANONYMOUS route nulls. Two requests, one of them anonymous, defeated it:
null the field, then adopt. An ownership decision may not depend on state an unauthorized
caller controls.

The pattern across all four: **a route that cannot refuse cannot mint ownership.** Every
design that put the pin somewhere without first making that place able to say no was
re-implementing first-touch.

## The ruling

### R1 — First touch must AUTHORIZE or REFUSE. The lifecycle plane becomes identity-first.

`handle_environment_create` and `handle_environment_action` resolve the caller BEFORE they
read or create any record (rule E: a 401 is owed before a 404 existence oracle). A request
with no resolvable principal is refused. This is the precondition for everything else in
this document and it is not optional: without it, every subsequent rule decorates
first-touch.

### R2 — An action on an environment that does not exist is a 404, not a creation.

The `None => new_env(...)` arm is DELETED. Creation happens at exactly one seam. This is
the structural change that makes R3 meaningful, and it is a behaviour change to a live
route — called out here because it is the part of this design most likely to break a
caller, and it must be verified against the surfaces and journeys that drive the plane
before it lands.

### R3 — The pin binds where the WORKSPACE is materialized, from the principal whose authorized request materialized it.

Ownership follows the thing being protected. A record is a name; a workspace is bytes. This
is the same shape as the capture-custody fix that WORKED in XIII, and it is the only one of
the four locations that survives, because R1 has now made that call site able to refuse.

Concretely: `provision_local_workspace` gains the caller's identity and the canonical
coordinate, and binds the scope pin as the LAST act before returning success — after every
refusal has already happened.

### R4 — Bind only on a request that has already been authorized and is about to succeed.

The pin is genesis-only with no unbind, so the two questions the checkpoint demands must be
answered before any `bind_request_resource_scope` call:

- *What if this request is refused?* It never reaches the bind. The bind is the last act,
  not the first.
- *What if the wrong principal gets there first?* There is no "wrong principal" that is not
  authenticated, because R1 refuses unauthenticated callers. A principal that authenticates
  and materializes a workspace IS the owner. That is not a compromise — it is the
  definition, and it is the one an unbindable pin can safely carry.

**No pin may be minted on a refused request, and no pin may name a principal that does not
exist.** A pin that could strand a coordinate is a permanent denial for every principal
including the administrator; XIII shipped three of those.

### R5 — Normalize the coordinate once, at the edge, through one function, and return it.

The pin's `resource_ref` is the CANONICAL environment id — `safe_id(id)` — computed once at
the route edge by one function that RETURNS the canonical value, so no downstream caller
carries the caller's spelling onward. `safe_id` is many-to-one; a pin keyed on the raw id
is a second coordinate over one workspace, which is exactly how XIII's alias defeat worked.

The canonical coordinate is also what the response returns, so a caller cannot later
address the same workspace under a spelling the pin does not cover.

### R6 — Ownership is read from the substrate pin, never from a record field.

`status.workspace_root`, `owner_ref` and every other record field are DESCRIPTIVE. Every
authorization decision resolves through `read_request_scope`. This kills F4 structurally
rather than by patching the specific field: there is no record field left for an anonymous
route to null that any decision depends on.

### R7 — Pre-existing environments need an administrator-authorized ADOPTION transition, and until it exists they are refused, not adopted.

Every environment that exists today carries no pin. Under R6 they resolve to no owner, so
every authorizing route refuses them. **Refusing at declaration is the correct fail-closed
shape** — it is what XIII ruled for pre-existing captures — but it strands real bytes, and
this design does not get to pretend otherwise.

Adoption is a typed, receipted, deployment-administrator-only transition that binds a
FIRST pin (never replaces one, because there is nothing to replace and no unbind if there
were). Its authority is the deployment administrator principal the estate already resolves
for the ODK materialization ladder.

**This is the part of the design most likely to require substrate or canon change, and it
is flagged rather than assumed.** If review finds that no existing authority can carry an
adoption transition, then per the commission's escape hatch this ADR files that as the
resolution path with both citations and the leg STOPS there — that is success, not failure.

### R8 — The reach is not retroactive, and the gate says so.

The open-defect assertion in `check:environment-custody` flips in the LAST commit of a
proven fix, never the first. Until R7 has landed AND pre-existing environments have been
adopted, the honest claim is "owned from this leg forward", and the residual names exactly
what is not covered — the same discipline XIII applied to captures.

## What this design does NOT do

- It does not add an unbind. The substrate has none and inventing one is a second spine.
- It does not make ownership transferable. That is a separate governed act and is out of
  scope; naming it here keeps it from being smuggled in.
- It does not touch the capture custody lane, which already has an owner.
- It does not claim the lifecycle plane is safe. It claims the plane can REFUSE, which is
  the precondition for that claim, not the claim itself.

## The verifier this design implies

Named here so the build cannot narrow it later:

1. Every route in the lifecycle plane resolves a caller — derived from the router SOURCE,
   asserted in both directions (nothing unclassified, no stale entry), not a hand list.
2. An anonymous request to each of them is refused, PAIRED WITH A COUNT of the durable
   artifact it must not have produced — no workspace directory, no record.
3. An action on a non-existent environment is a 404 and creates nothing on disk.
4. Two principals: the second cannot read, write, capture, restore over, or delete the
   first's environment.
5. An alias spelling of an owned environment resolves to the SAME pin and is refused for
   the non-owner — the coordinate rule, asserted.
6. A refused create leaves NO pin behind, proven by a subsequent successful create by a
   different principal on the same coordinate.
7. Pre-existing (unpinned) environments are refused with a typed reason that says
   "unadopted", not "not yours" — the truth is "nobody's", and XIII paid for that
   distinction.
8. Mutations RED-ON-TARGET for each, floored in the same commit.

## Reversal

Owner-reversible. If the owner rules that the lifecycle plane must stay anonymous, this ADR
is superseded and defect 1a stays open with the gate assertion intact — which is the state
today, and is honest. The cost of that ruling is stated plainly: any authenticated principal
can capture any environment's workspace and restore its own capture back over it.

## Status of the evidence

This ADR cites source locations at `6cfdcb5be`. It has NOT been built, and nothing here has
been demonstrated live. It is a design, and the next act is its adversarial review — not a
branch.
