# Canon-to-Implementation Reconciliation — M0 Anchor Migration and Locator Repair

Date: 2026-07-25
Branch: `refactor/canon-terminology-and-modularization`
Range under reconciliation: `a894b2505..HEAD`
Class: evidence-artifact. This record owns no architecture contract and directs no work.

**Revision note.** An earlier revision of this record contained two false claims
and several unreproducible figures. They were found by independent adversarial
review and are corrected in place below, with the corrections called out rather
than quietly edited. See §9.

## Verification posture

Every number below was produced by running a command whose output is recorded.
Where a claim is author judgement it is marked *asserted*. A passing gate is not
a claim that planned behavior exists.

## 1. The brief's framing of the defect was wrong in scale, right in nothing else

The task described "4,391 stale Rust anchors" as a systemic reconciliation
defect of the canon refactor.

| Claim in brief | Measured | Method |
| --- | --- | --- |
| 4,391 stale anchors | **1,069 assertion failures** at the canon tip | classified every error from `checkM0Artifacts` |
| caused by the canon modularization | **almost entirely no** — 1,055 of 1,069 predate it | see §2 |

Root cause: `validateAnchoredFile` hashes the **whole file** (`sha256(source)`),
so any edit to a reviewed file invalidates its anchor. The last review epoch was
`pr-92-platform-operability-canon-review-2026-07-21`. `a894b2505 feat(runtime):
add scoped authority gateway enforcement` landed after it. M0 was fail-closing
**correctly**: authority-path code changed after its last review.

Confirmed by bisection — at `a894b2505^` the checker **passes**
(`M0 supplied-snapshot check passed: 1541 entries, exit verified`).

Error classes at the canon tip: **725** stale handler anchors, **342** stale
final-invoker source anchors, **2** entries whose 2026-07-18 review could no
longer be inherited.

## 2. What the canon refactor did contribute — corrected

The earlier revision asserted "**The canon refactor contributed zero**" and that
the three edited Rust files "were already inside the stale set." **Both were
false.** Measured:

```
a894b2505  (baseline)  : failed with 1055 error(s)
fd2c09c4e  (canon tip) : failed with 1069 error(s)
delta                  : 14 errors, all "final invoker has a stale source anchor"
  work_result_routes.rs        7
  room_participation_routes.rs 4
  outcome_room_routes.rs       3
```

The three files were **not** stale at baseline; the canon pass's doc-comment
edits made them stale. Anchored files touched: 8 by `a894b2505`, plus 3 by the
canon pass.

**Why the original measurement was wrong.** The baseline script collected only
`handler_source_file`/`handler_anchor_sha256` and `source_file`/
`registration_anchor_sha256`. It never collected
`final_invoker.source_anchor_sha256` — which is precisely the assertion class the
three edits broke — and it compared whole-file hashes against symbol-scoped
handler anchors, which is why it reported an inflated, meaningless "112 stale".

"0 newly broken" was true only at **test** granularity (12 failing tests, same
names, at both commits). It was false at assertion granularity (+14) and at
anchored-file granularity (+3). The honest statement: **the canon pass added 14
of the 1,069 errors; `a894b2505` caused the other 1,055.**

The "112 files" figure in the earlier revision is withdrawn. It is not
reproducible under any reading. Correct figures: 123 distinct anchored files
referenced by lock entries; 8 anchored files touched by `a894b2505`.

## 3. The blocking "external signer" requirement was a retired ceremony

The v2 anchor required a detached Ed25519 signature per epoch, with the private
key deliberately outside the repository. That ceremony was **retired** by
`0c5e5c558`, never integrated onto this branch: the "reviewer key" lived beside
the evidence it signed, proving nothing beyond its own hash chain, while
blocking route-adding cuts behind a nonexistent signer.

| Ported | Not ported |
| --- | --- |
| `scripts/lib/m0-program-control-model.mjs` (v3 logic) | that lineage's `docs/evidence/m0-program-control/*` |
| `scripts/lib/m0-program-control.test.mjs` | its epoch 7 (`pr-97-…`, 1,545 identities on a different tree) |
| `scripts/m0-program-control.mjs` (CLI wording) | its `reviewed-entry-lock.json` |
| `docs/evidence/m0-program-control/README.md` (v3 procedure) | |

`0c5e5c558` and `a894b2505` share merge base `3cd6fabd2`; generated evidence from
that lineage would assert a census of a tree that does not exist here. Port
fidelity is exact: the model file differs from the reference in **one hunk** —
the 18 `CANON_BASIS_FILES` additions this branch requires.

**Disclosed port gap.** Two reference assertions were not carried: the test
`"Axum discovery preserves literal methods behind one route-local layer"` and its
error-table row. Their backing implementation lives in `ecee15392`, which is not
an ancestor of this branch, and `scripts/lib/m0-program-control.mjs` was
correctly left untouched. **No assertion that existed at `a894b2505` was
removed** — 55 tests at both commits, assertion count 180 → 187.

The residual risk is now bounded and guarded. Route-local `.layer(...)`
registrations remain unsupported by this branch's discovery, but the gap is
currently **theoretical**: the daemon's only `.layer(...)` is router-level
("wraps every route above"), and no route-local layer exists in any route module.
A new test — *"no route-local .layer(...) hides a handler from discovery"* —
scans `hypervisor-daemon.rs` and every file under `hypervisor_daemon_routes/`
and fails closed if one is introduced, so such a handler can never be silently
under-discovered and omitted from the review census. Verified by inserting the
offending shape (fails) and removing it (passes).

## 4. The epoch this branch created

`canon-modularization-locator-review-2026-07-25`, sequence 7,
`authorship_binding: self_declared_unsigned`, no signature fields.

Integrity invariants, independently re-verified:

- legacy epochs 1–6 **byte-identical** to `a894b2505`
- repository baseline pin unchanged (sequence 2, `c2624cdd…e50d`)
- new epoch carries no signature-implying fields
- `evidence_format` v2 → v3; epoch count 6 → 7

Entry partition, **determined by the checker as oracle**, not guessed:

| Partition | Count |
| --- | ---: |
| Bind the new epoch | 1,066 |
| Keep the `2026-07-18` baseline | 475 |
| Total | 1,541 |

Anchors rebound across the pass: handler anchors and final-invoker source
anchors. **Zero** registration anchors changed — an earlier revision's
"registration/invoker" label was wrong; registration contributed nothing. Final
per-field counts are in the diff below, which is the authoritative figure.

### What this epoch does not claim

Independently verified by a recursive field-by-field diff of all 1,541 entries
against `a894b2505`. The **only** changed field paths are:

```text
1066  reviewed_as_of
 763  handler_anchor_sha256
 346  final_invoker.source_anchor_sha256
   7  owner_doc            (deliberate; see §7)
identities only in base: 0
identities only in head: 0
```

Zero changes to `classification`, `effect_class`, `implementation_state`,
`pre_effect_gates`, `final_invoker.claim_state`, `blocker_or_nonclaim_ref`,
`path`, `method`, or `owner`. No identity was added or dropped.

This is a locator-and-anchor review, not a behavioral re-review, and it is
unsigned self-declared workflow evidence outside the authority model.

## 5. Security correction found by review and fixed here

Independent review found a **fail-open** inherited verbatim from the reference:
the validator classified an entry as a retained legacy claim purely from the
presence of a `reviewer_evidence` field, then validated that evidence
**structurally only** — no key pinned, no signature verified. A new
unsigned-era entry that dropped `authorship_binding` and attached a
structurally complete block signed with an **attacker-generated key** was
accepted. Because `unsignedEraStarted` was only set by non-legacy-shaped
entries, a legacy-shaped head also disarmed the cannot-follow-unsigned rule.

Reproduced before the fix: `FAIL-OPEN: forged legacy-shaped head with an
attacker key was ACCEPTED`.

Fix: retained legacy status is **pinned to the retired signed era**
(`sequence <= 6`), while legacy *shape* still arms the cannot-follow-unsigned
rule, so a legacy-shaped ghost appended later is still rejected on that ground.
After the fix the same forgery fails closed on
`sequence 7 is outside the retired signed era and must not carry
reviewer_evidence`.

This is a genuine hardening of inherited logic, not a weakening. It confers no
new authority — the unsigned chain still claims none — but it stops the artifact
from presenting an Ed25519 signature that nothing verifies, which is exactly the
guard the migration states for itself. A regression test now enforces it; the
pre-existing test only covered the field-value variant
(`authorship_binding = "verified_signer"`), which gave false confidence.

## 6. Results

| Gate | Before | After |
| --- | --- | --- |
| `m0-program-control` tests | 43 pass / 12 fail | **55 pass / 0 fail** |
| `--check` | 1,069 errors | **passes**, 1,541 entries, exit `verified` |
| second `--write` | n/a | **0 files written** (idempotent) |
| `npm run check:m0-program-control` | EXIT=1 | **EXIT=0** |
| `node scripts/check-pre-next-leg.mjs` | EXIT=1 | **EXIT=0** |

All 12 original failures resolved by the migration; none individually patched,
none dispositioned as "same as baseline". Two failures surfacing mid-migration
were fixed at cause: the README is hashed into the manifest (so it had to be
ported and the manifest regenerated), and a `canon_basis` ordering divergence
changed the material hash the anchor binds.

## 7. Locator reconciliation in the implementation estate

`internal-docs/implementation/` is **gitignored**; these edits are local-only,
appear in no commit, and are therefore unverifiable from the commit itself.

| Surface | Action | Count |
| --- | --- | ---: |
| `contract_families[].owner_path` | repointed to the declaring module | 414 (128 from each family's own `canonical_owner_ref`, 286 by what modules declare) |
| `canon_owners[]` | rewritten to the modules the record's families resolve to | 64 records |
| `canon_owners[]` still naming the index | left | 12 |
| `contract_families[].semantic_owner_paths[]` still naming the index | left | 8 |
| `canon_snapshot.owners[].path` | **not touched** | 99 |
| `_archive/**` | **not touched** | 50 files |

The 12 + 8 residual references are plausibly legitimate — the index still owns
envelope base types, ID conventions, capability/authority tiers, and
`ManifestEnvelope` — but they were not individually adjudicated. *Asserted.*

`canon_snapshot` is dated provenance carrying `captured_at_commit` and per-file
digests; rewriting it would falsify history. Drift detection is owned by
`generated/canon-baseline.v1.json` via `tools/canon-impact.mjs`.

Estate checks: `check-work-item-shape` **EXIT=0** (126 records, 1 pre-existing
waived warning), `check-estate` **EXIT=0** (20 skips, all checkout divergence).

**Resolved after review:** 7 GoalRun lock entries carried
`owner_doc: docs/architecture/foundations/common-objects-and-envelopes.md`, a
file the canon pass reduced to an index that explicitly does not restate those
shapes. All 7 (`GET`/`POST /v1/hypervisor/goal-runs*`) were repointed to
`objects/goal-run-execution.md`, and the anchor, attestation, and artifacts were
regenerated through the authorized sequence. No check had failed on them — all
1,541 `owner_doc` paths resolved either way — but the ownership was
substantively stale. The epoch partition is unchanged (475 / 1,066).

## 8. Program-state refresh

Performed through the generators, not by editing their output:
`tools/generate-now.mjs --write` (EXIT=0) regenerated `NOW.md` and
`generated/program-state.v1.json`; M0 artifacts regenerated by
`m0-program-control.mjs --write` after the authorized `--attest-review`
transition. The program source was returned to `worksheet_unreviewed` first,
which is the documented transition, not an edit of attested evidence.

## 9. What remains, with exact scope

`node tools/canon-impact.mjs --check` reports **EXIT=1**:

```text
canon universe: 579 subjects (435 classified, 144 attachments)
impact: +267 -33 ~60 =252
canon-unreviewed: 60 canon subject digest(s) changed since the reviewed baseline
review required -> 16 stages | 16 modules | 122 work items
```

(The 579/+267 figures supersede 578/+266 in the earlier revision: this record
itself became the 579th subject.)

**`--accept` was deliberately not run.** It records the current canon as
reviewed; running it now would assert that 122 work items were re-reviewed when
they were not.

Remaining `check-program` errors, each with an owner:

| Error | Class | Owner / remediation |
| --- | --- | --- |
| `canon-unreviewed: 60 digests changed` | expected consequence of the canon pass | review the 122 named work items, then `canon-impact.mjs --accept` |
| `attestation-path: … docs/architecture/_meta/work-items/…` | pre-existing checkout divergence | records exist on `origin/master`, not here |
| `registry-stale: … docs/architecture/_meta/work-items` | pre-existing checkout divergence | same cause |

## 10. Phase C/D/E — runtime audit against the reconciled canon

The 122 impacted work items partition honestly: **116 `proposed`** (not developed),
**1 `scoped`**, **5 `verified`**. Only the 5 admit a code audit.

### The five already-developed items

A mounted route or a type name is not proof; each record declares `code_anchors`
with `must_contain` strings and a `present_when` qualifier, so both were checked.

| Work item | Anchors | Result | Classification |
| --- | --- | --- | --- |
| `m1-genesis-admission` | 4 `merged` | 4/4 present | **conformant** |
| `m1-sequence-zero-materialization` | 2 `merged` | 2/2 present | **conformant** |
| `m1-5b-generic-protected-transitions` | 5 `pr_open` | 0/5 present | **not_applicable** — held PR, absence is what `pr_open` means |
| `m1-5c-amendment-execution` | 5 `pr_open` | 0/5 present | **not_applicable** — same |
| `m1-governed-initialize-activate` | 3 `merged` | 0/3 present | **checkout divergence, not a false status** |

The last row was investigated rather than reported as a defect:
`system_activation_routes.rs` **is present on `origin/master`** (`ba7513bac`), and
`git merge-base --is-ancestor a894b2505 origin/master` returns false — this
branch's base diverged from master before that merge. The `verified` status is
true on master. **This branch must be rebased or merged onto `origin/master`
before landing**, and until then three `merged` anchors will read absent here.

### P0 cross-cutting boundaries

| Boundary | Method | Result |
| --- | --- | --- |
| No durable `Assistant` aggregate | scanned `crates/{node,services,types}/src` for `struct Assistant` / `assistant_id` | **holds** — zero hits |
| Facilitation is not ambient authority | GoalRun admission requires `scope:goal.run.orchestrate`, receipts, and a state root; no subscription/entitlement/facilitator term participates | **holds** |
| Session ≠ GoalRun | see the correction below | **DOES NOT HOLD** |
| Native/MCP parity | read the MCP gateway invoke path end to end | **DEFECT — fixed, see below** |

### The one implemented mismatch, and its correction

`handle_mcp_gateway_invoke` delegates to the same daemon routes the app uses —
the strongest possible parity — but through an HTTP loopback whose `call()` helper
sent **no headers at all**.

`auth_gate` enforces when `auth_enforced()` is true, and in the default `auto`
mode that is `daemon_exposed() || request_exposed(headers)`. `request_exposed`
keys off `x-forwarded-*` and a non-loopback `Host`. The loopback targets
`st.base_url` (`http://127.0.0.1:PORT`) with no forwarded headers, so on the
second hop `request_exposed` is **false**.

Consequence: an externally forwarded MCP call that *was* authenticated at the
gateway executed its **effect** — `/v1/hypervisor/exec` among them — under
`local_development` posture rather than the caller's, while a native caller
hitting the same route was enforced. That is the divergence the parity rule
forbids. It is **not** an unauthenticated bypass: hop 1 is auth-gated, so no
unauthenticated actor ever reached the effect.

An earlier revision of this record also said "with no principal bound to the
receipt." **That was not reproducible and is withdrawn.** The five loopback
targets live in `environment_routes.rs`, which contains zero `HeaderMap` usages;
`resolve_principal` has three consumers repo-wide and none is on these routes,
and `persist_invocation_receipt` takes no principal parameter. No principal is
bound to a receipt on these routes before or after the fix. The defect is posture
laundering, not receipt attribution.

Fix: the gateway forwards `authorization`, `cookie`, `x-forwarded-host`,
`x-forwarded-for`, and `x-ioi-forwarded` across the loopback, so the effect hop
is evaluated under the caller's own posture and principal. `cargo check` and
`cargo fmt --check` clean. A fail-closed test asserts every gateway loopback
passes the inbound headers; verified by removing the argument from one call site
and watching it fail.

**Corrected after review.** An earlier revision left the `orchestration_routes.rs`
loopbacks alone and justified it by the webhook path being session-less. That
reasoning is true of the webhook and **does not describe two of the three
handlers it was used to excuse**: `handle_placement_resolve` and
`handle_warm_pool_create` have no webhook relation at all, and all three are
directly mounted, auth-gated routes whose loopbacks execute real effects. The
forwarding is also *opportunistic* (`if let Some(value) = inbound.get(..)`), so
applying it leaves the webhook path byte-for-byte unchanged — nothing was being
forced. That was a silent gap, and it is now closed.

Review also found a **fourth** instance the first audit missed, contradicting
"the one implemented mismatch": `governance_routes.rs` looped back header-less to
`/v1/hypervisor/auth/policy`, and `handle_auth_policy_get` computes
`deployment_auth_posture` **from the inbound headers**. The Governance overview —
the lens whose whole job is showing the authority posture — therefore reported
`local_development` and `explicit_override_allowed: true` on an exposed instance.
Also fixed.

Loopback header forwarding now covers `operability_routes.rs`,
`orchestration_routes.rs`, `governance_routes.rs`,
`decentralized_cloud_routes.rs`, and `placement_failover_routes.rs`.

### New regression guards (all tracked, all proven to fail closed)

| Guard | Proven by |
| --- | --- |
| Gateway loopbacks forward caller posture | removing `&inbound` from one call site → fails |
| No durable `Assistant` aggregate | adding `struct Assistant { assistant_id }` → fails |
| GoalRun admission binds scope, receipts, state root, and no product state | removing the `require_scope` line → fails |
| Legacy anchor entries cannot impersonate a signer | reverting the model fix → fails |
| No route-local `.layer(...)` hides a handler from discovery | inserting the shape → fails |

### Canon gap surfaced (not resolved)

Canon defines rich handoffs **from** ioi.ai (`IoiAiGoalChatHandoff` into
Hypervisor App/Web, Automations, Foundry, wallet.network, aiagent.xyz, sas.xyz,
provider/restore flows) but names **no object for the reverse direction** — moving
work from an existing Hypervisor context into an admitted ioi.ai GoalRun. The
brief requires that crossing to be explicit, reviewable, idempotent, and
receipt-backed, and states that a pointer, UI link, correlation id, MCP call,
subscription, or facilitator selection is not admission. No envelope, route, or
receipt family carries it today.

GoalRun admission itself is sound, so the gap is the missing crossing object, not
weak admission. Surfaced in the estate gap register (now 24 gaps) naming
`ioi-ai/control-plane.md` with `collaborative-outcome-pattern.md` and
`objects/goal-pursuit.md` as the owners who must resolve it. **A gap is surfaced,
never invented around** — no crossing object was fabricated here.

## 11. BLOCKER found by review: a Session launch auto-creates a GoalRun

An earlier revision claimed "the Session references the GoalRun, never owns or
auto-creates it." **That is false, and the correction matters more than the
sentence.**

`handle_ioi_agent_launch` (`ioi_agent_routes.rs`) creates a Session, then:

```rust
// For goal_run: create the internal GoalRun (advanced/proof object; not the product mode).
if kind == "goal_run" {
    let (gr_status, gr) = self_call(&format!("{}/v1/hypervisor/goal-runs", st.base_url), "POST", …
```

`kind` is **not caller-chosen** — it is `selection.planned_execution_kind` from
the planner, and under the default `auto` strategy the planner returns
`goal_run` from a **goal-text heuristic** (`runtime_goal_run_admission.rs`):
`goal.len() >= 120 || ["compare","review","refactor","migrate","audit","redesign",
"multiple approaches"].iter().any(...)`.

So one product call that never mentions a GoalRun creates a Session and then
durably creates a GoalRun bound to it, purely from goal wording. That is exactly
what the required boundary forbids: *GoalRun and OutcomeRoom must not become
default Hypervisor Session behavior.*

**Not fixed here, deliberately.** Changing what an IOI Agent launch creates is a
product-identity decision with real blast radius, and the execution posture
reserves product identity for an explicit ruling rather than a reconciliation
pass. The defect is recorded with its exact trigger so the ruling can be made on
evidence. It is listed below as the top open item.

Also corrected: the record's admission claims were stronger than the code. The
sole caller hardcodes the values admission then checks, `receipt_required` is a
boolean rather than `receipt_refs`, the emitted `receipt://goal-run/{id}/create`
is not persisted at create, and `state_root_ref` is a prefix-checked string that
the persisted record drops — so "replayable" is not achieved at admission.
`target_session_ref` is genuinely enforced, but by the route
(`load_session_record`), not by the admission core.

## 12. Not done, and not claimed

- **A Session launch auto-creates a GoalRun from a goal-text heuristic** (§11).
  This is the top open item and needs a product-identity ruling, not a
  reconciliation edit.
- **`m1-5b` and `m1-5c` were classified `not_applicable` on stale local
  `present_when: pr_open` metadata.** Review showed both PRs are merged to master
  (`695921491` = #103, `a44f8c670` = #105) and the tracked authority records on
  `origin/master` say `present_when: "merged"`; re-run against master, 10 more
  anchors are auditable and 10/10 pass. The correct classification for both is
  **checkout divergence**, the same as `m1-governed-initialize-activate`. One
  anchor is genuinely broken and the dismissal concealed it: `m1-5c` anchor[3]
  names `system_lifecycle_transitions.rs` for `compile_amendment_execution_plan`,
  a symbol that lives in `system_amendment_execution.rs` and is absent from the
  named file on every ref. The rebase below will make that anchor fail.
- **This branch must be rebased onto `origin/master` before landing.** Its base
  is not an ancestor of master.
- **The `Assistant` guard covers Rust only.** Review found
  `AssistantNotificationRecord`, `AssistantWorkbenchActivityRecord`, and four
  versioned `Assistant*Profile`/`Policy` types under `apps/hypervisor/src/`,
  outside the scanned crates and carrying identity, timestamps, policy refs, and
  an 8-state lifecycle. Whether those are durable objects or view models is
  unadjudicated; the canon boundary says they must not be the former.
- **Per-stage conformance audit of the 116 `proposed` items is not done.** They
  are not developed, so there is nothing to audit; their locators were repointed
  where machine-resolvable. No stage status was upgraded; no route-mounted-only
  implementation was reclassified as complete.
- **The `M0_UNSIGNED_REVIEW_ANCHOR_EXIT=0` literal was not written.** Its work
  item sets `producer_independence_required: true` and
  `task_exit_code_is_proof: false`.
- **Route-local `.layer(...)` discovery** remains unsupported on this branch, now guarded by a fail-closed test (§3).
- **Nothing was pushed.**

## 13. Post-ruling integration pass (2026-07-26)

The eight-commit branch was **not** pushed. Its ancestry (`a894b2505`) is not an
ancestor of `origin/master`, and master had moved 47 commits ahead.

**Backup:** tag `backup/canon-reconciliation-preintegration` and branch
`backup-canon-reconciliation-preintegration` at `4e542ee39`.

**Integration was a re-derivation, not a replay.** Two facts made a replay wrong:

- Master had added **880 lines** to `common-objects-and-envelopes.md` since the
  merge base. The split was re-run against master's current content, so those
  lines are preserved; they land in `objects/bounded-system-genesis.md`, which
  grows 2,044 → 2,880.
- Master already carries the unsigned v3 anchor (`0c5e5c558` is an ancestor) and
  was at **epoch 11 / 1,553 entries**. The branch's own epoch 7 would have forked
  master's hash chain, so the M0 evidence was **not** replayed. Master's chain is
  authoritative; epoch **12** is appended to it, retaining all 11 predecessors
  verbatim.

Master still needed, and now has: the shared-object family, `term-boundaries.md`,
the documentation checks, the signature-impersonation fix (master still inferred
retained-legacy status from field presence), and loopback posture forwarding.

### Rulings implemented

**No implicit GoalRun creation.** The goal-text heuristic is recommendation-only
at its source; an ordinary launch creates a Session and surfaces
`goal_run_recommended` / `goal_run_created` / `goal_run_activation`; creation
requires typed explicit activation evidence and still crosses ordinary admission;
`Compare` fails closed rather than substituting a GoalRun for bounded Session
WorkRuns; new records carry `creation_provenance`; records marked
`legacy_implicit_creation` are refused at start until adopted or cancelled, with
no fabricated admission evidence.

**Assistant.** The ruling and per-shape dispositions are encoded in
`term-boundaries.md`. The code rename is **not executed**, for a recorded reason:
the `AssistantNotification*` contracts carry a ts-rs "do not edit manually"
banner and `.cargo/config.toml` points `TS_RS_EXPORT_DIR` at that directory, but
**no Rust type in this repository derives them**. They are orphaned generated
artifacts with no owning source to rename through, and hand-editing generated
TypeScript is forbidden. The missing owner is the defect to resolve first.

**Canon-impact accepted after inspection.** 60 changed subjects classified:
30 clarified obligation, 17 path/owner relocation, 12 changed implementation
evidence, **1 new obligation** (`invariants.md`). Write/check equivalence held
(second `--write` idempotent), then `--accept`. `canon-impact --check` is now
exit 0. Historical snapshots unchanged.

### Residual, disclosed

`check-program` reports 3 errors, all one cause: repointing `canon_owners` on
`m1-5b-generic-protected-transitions` and `m1-5c-amendment-execution` changed
their bytes, and those digests are attested in
`_archive/migrations/status-reconciliation.v1.json`. Updating the attestation to
match a later edit would be rewriting evidence, which the ruling forbids, and the
pre-edit bytes are unrecoverable because `internal-docs/implementation/` is
gitignored. **Remediation is a re-attestation through the authorized transition
tool — a status-authority action, not something to fabricate here.**

### `check-pre-next-leg` does not reach exit zero, and the cause is inherited

The completion bar asked for `check-pre-next-leg` at literal exit zero. It exits
**1**, and the cause is pre-existing on `origin/master`, not introduced here.

The failing step is `test:workflow-compositor-dogfood`:

```
not ok 2 - Rust workflow-edit approved proposal mutates the file and replays idempotently
  expected: 'approve'    actual: undefined
```

Verified against a clean `origin/master` worktree: the same subtest fails there
with the same signature — **2 pass / 1 fail on both trees**. None of the eleven
Rust files this pass touched mentions `workflow_edit` or `workflow.edit`:

```
crates/node/src/bin/hypervisor_daemon_routes/{decentralized_cloud,goalrun,governance,
  ioi_agent,operability,orchestration,outcome_room,placement_failover,
  room_participation,work_result}_routes.rs
crates/services/src/agentic/runtime/kernel/runtime_goal_run_admission.rs
```

Every other step of the gate passes, including the ones this pass changed:
runtime-action generator, pre-next-leg gate regressions, `m0-program-control`,
architecture contract bar, system-genesis compiler, architecture docs, work
items, conformance docs, readiness, compositor conformance, runtime layout.

**Disposition:** inherited defect in the workflow-edit approval contract, owned
by the workflow-compositor lane, not by this reconciliation. It is reported
rather than worked around, and no gate was weakened to obtain a green result.

