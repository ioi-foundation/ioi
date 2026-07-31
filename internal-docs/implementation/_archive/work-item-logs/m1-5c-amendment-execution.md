# Work item m1-5c — protected constitutional amendment execution

Status: active · Branch: feat/system-amendment-execution (worktree ioi-m1-5b) · Forked from master 695921491 (post-#103).
User directive 2026-07-22: work until M1 exit then HARD PAUSE (user question pending before M2).

## Objective

An approved constitutional amendment executes on the live chain exactly once, swapping the active
constitution to its successor revision under the constitution's OWN declared amendment governance
(`governance.amendment_mode`, `amendment_decision_profile_ref`, `protected_clause_refs`,
`agent_may_commit_amendment`), with protected clauses unamendable and the predecessor constitution
retained as superseded evidence. Canon: governed-autonomous-systems.md ~L179 (distinct high-assurance
path: notice, approval, challenge, activation, rollback) + guide M1.5 "distinct protected amendment".

## Falsifiable claim

No protected or structural clause ever changes (declared changed_field_paths must equal the
canonically computed predecessor→successor JSON-pointer diff and must not touch protected_clause_refs
paths or structural lineage fields); amendment admits only from an `active | paused` predecessor with
exact state-root + chain-head pinning; `scope:autonomous_system.constitution.amend` is satisfiable by
no lifecycle scope; an approved amendment executes exactly once (race-linearized, crash-replay
convergent); rollback is forward-only (a new amendment), never in-place revert.

## Object plan

1. `autonomous-system-constitution-amendment.v1` — EXISTS (M1.1): declaration object. Verify fixtures/invariants still bar-green; extend invariants if diff rules are uncontracted.
2. NEW `autonomous-system-amendment-execution-proposal.v1` — binds amendment_ref+root, sequence ≥3,
   predecessor_status ∈ {active, paused}, predecessor_state_root, predecessor_chain_head_root,
   required_scope scope:autonomous_system.constitution.amend, op `amend_constitution`,
   irreversibility `one_way`, closed authority_effect (amendment variant: carries predecessor/successor
   constitution roots + changed-path commitment; six negative claims retained), operation_commitment.
3. NEW `autonomous-system-amendment-execution-decision.v1` — house decision mirror w/ wallet
   consumption evidence, restated one_way irreversibility.
4. Successor constitution = existing constitution.v1 contract (version+1, predecessor ref pinned,
   status active); predecessor flips to superseded (retained, content-addressed).
5. NEW `autonomous-system-active-profile-set.v2` (successor_of v1, predecessor_remains_valid true):
   generalizes admission carrier — `admitted_by_transition_ref` (any lifecycle transition, not just
   activation), `supersedes_profile_set_ref`; constitution entry swaps to successor revision; all
   other entries carried verbatim.
6. Chain revision swaps constitution_ref/root; operation-log v2 entry kind `constitution_amendment`
   (check log v2 entry-kind enum — may need widening = registry evolution note, NOT v3);
   lifecycle-state.v1 at sequence N with status UNCHANGED (amendment never alters operational status).

## Runtime plan

Route pair (2 census identities → census epoch 9):
`GET/POST /v1/hypervisor/autonomous-systems/:id/amendments` (GET = eligibility + retained amendment
evidence; POST = execute approved amendment). POST runs the m1-5b discipline via shared
`prepare_node_evidence_for`: closed-input validation; caller-pinned head/state roots; sealed intents
(`asamx_` prefix dir) with under-lock byte-exact plan rebinding; fail-closed wallet consumption
(scope:autonomous_system.constitution.amend); no-clobber persistence + Agentgres admission
(new families → REQUIRED_ADMISSION_DOMAINS + identity/prefix/material tables; profile-set root
recipe dispatches on schema_version v1/v2); background replay driver + pending-intent choke points
(bootstrap + protected + amendment intents mutually exclusive per key).

Server-side diff computation: canonical JSON-pointer diff over constitution bodies (flat, sorted,
deterministic); structural lineage fields (schema_version, constitution_id, system_id, version,
predecessor_constitution_ref, constitution_root, activation_receipt_ref, status) are
machine-protected regardless of declaration; `governance.protected_clause_refs` paths add the
constitution's own protected set; `agent_may_commit_amendment: false` refuses agent-principal
execution even with a grant.

## Journey plan (target checks, single new journey `constitutional-amendment`)

1. Bootstrap prefix (genesis→materialize→initialize→activate) reused verbatim.
2. Amend success: successor constitution active (version+1), predecessor superseded + retained,
   chain constitution_ref/root swapped, log gains `constitution_amendment` entry, lifecycle-state
   seq N status unchanged, profile-set v2 admitted w/ verbatim non-constitution entries.
3. Declared-diff mismatch (changed_field_paths ⊉ real diff and ⊋ real diff, both directions) refused, zero evidence.
4. Protected-clause change refused (path in protected_clause_refs); structural-field change refused.
5. Scope substitution refused: lifecycle.pause grant cannot amend; amend grant cannot pause.
6. Stale chain head / stale state root refused as conflict.
7. N-way race linearizes to exactly one execution (reproduce 3x).
8. Crash-after-consumption replay converges exactly one amendment via driver.
9. Post-amendment continuity: pause→resume under successor constitution still 25/25-style green.
10. Exact teardown.

## Increment log

- inc.0 (this file): design pinned. Next: inc.1 canon sections + schemas + fixtures + invariants → bar.

## inc.3 runtime — build/wiring notes (2026-07-22, opus)

- Subagent authored system_amendment_routes.rs (2071 lines) + shared-file edits (record_by_root pub, continue_log_with_entry shared refactor, load_previous_step receipt-family dispatch protected/amendment, system_id_for_key pub, amendment-pendency cross-check in protected POST). Cut off before daemon reg + substrate + wallet scope; I completed those.
- Substrate wiring (substrate_store.rs): +3 REQUIRED_ADMISSION_DOMAINS (amendment-receipts asamr_, constitution-amendments asca_, constitutions ascn_). Declaration = content-recompute via {domain, amendment: body} special-case (no self-root field). Constitution = content-recompute via 14-field minted recipe. Amendment-receipt = lifecycle-transition-receipt artifact recompute group. Proposal/decision dispatch += amendment-execution schema_versions. active-profile-sets dispatch v1/v2 (v2 adds supersedes, excludes admitted_by).
- DESIGN FACTS for the journey POST body (constitution.v1 contract is strict):
  - status "active" ⇒ activation_receipt_ref MUST be receipt://... string (allOf status conditional). Successor inherits the System's activation receipt (structural/diff-excluded field). Predecessor+successor share it.
  - agency_boundary has 11 required fields; governance 11; protected_profile_governance 12 — successor must be a COMPLETE valid body, not a stub. Journey derives successor from the genesis constitution body + one non-protected scalar/array change.
  - amendable change in tests = /normative_constraints/permitted_ontology_action_contract_refs ([] -> [one ref]); protected_field_paths declares /declared_purpose; neither machine-protected (/governance) nor structural.
  - receipt_ref is seed-derived (system_id+sequence+kind), NOT root-derived — no cycle with successor_constitution_root.
- ioi-node daemon builds clean (my new file warning-free; the two protected:1835 warnings are pre-existing m1-5b shadowed for-loop bindings). Wallet fixture: +1 scope scope:autonomous_system.constitution.amend (no wildcard widening).

## inc.4 journey run 1 — CONSTITUTION ROOT MODEL CORRECTION (2026-07-22)

Journey run 1 (AJ1_EXIT=1) refused with "no durable constitution body carries the chain's
constitution_root" — a REAL defect the live plane caught that no unit test could:

- The chain/active-profile-set name a constitution by its PROFILE-CANDIDATE root:
  `jcs_hash({domain:"ioi.autonomous-system-profile-candidate-jcs-sha256.v1", kind:"constitution",
  candidate:<whole body>})` — the recipe genesis+activation already use (system_activation::candidate_root).
- The constitution body's own `constitution_root` FIELD is a declared, NON-AUTHORITATIVE claim
  (the genesis fixture carries a placeholder sha256:bbbb...). It cannot hold the authoritative root
  without self-reference, since the candidate recipe hashes the whole body including that field.
- inc.2 had INVENTED a third recipe (flat 14-field `minted_constitution_root`). That would have
  made amended constitutions unnameable by the chain. REPLACED by `constitution_candidate_root`
  (one constitution = one root everywhere: chain, profile set, declaration, substrate key).
- Consequences applied: compiler verifies `constitution_candidate_root(predecessor)==chain root`
  (not the declared field) and computes the successor root the same way; successor MUST carry the
  predecessor's declared `constitution_root` field verbatim (structural/diff-excluded) so it never
  states a competing self-claim; added a byte-identical-successor refusal. Substrate moved the
  constitutions family from the root-field path to a KEY-RECOMPUTE special case under the candidate
  recipe. load_constitution_body recomputes instead of reading the field. Journey mirrors it.

LESSON (recurring): when a new family names an existing object, adopt that object's EXISTING root
recipe — never mint a parallel one. Three-way agreement must include the incumbent producer.

## inc.4 journey run 2 (23/24) — two further findings

1. CANON GUARANTEE (stronger than the machine floor): constitution.v1 pins
   `governance.agent_may_commit_amendment` to const **false**. An agent-committed amendment is
   refused by the CONTRACT before any runtime check — the compiler's floor is defence in depth,
   not the only barrier. The journey's machine-floor proof therefore uses a contract-LEGAL
   governance edit (`affected_party_policy_ref`) so it proves the floor itself, not schema validation.
2. DEFECT FIXED (status honesty): caller-supplied `amendment` / `successor_constitution` bodies that
   violate their registered contract were classified `system_lifecycle_artifact_invalid` -> HTTP 500,
   i.e. reported as a server fault for a bad request. Now remapped to
   `system_lifecycle_request_invalid` -> 422 at the caller-input boundary in
   compile_amendment_from_source. Server-BUILT artifacts keep artifact_invalid/500, which is correct.

## inc.4 runs 3-4 — AUTHORITY BINDING GAP CLOSED (the substantive finding)

Run 4 crashed with "wallet.network record_approval refused: request_hash already names a different
wallet approval decision" even after the two probes used DIFFERENT declarations. Root cause was not
the journey: the daemon derives request_hash from the server-built authority EFFECT, and the effect
bound the constitutional CHANGE (predecessor root -> successor root + changed-path commitment) but
NOT the declaration that authorizes it. Two different governance declarations proposing the same
change produced an identical authority request.

Why that mattered: canon requires constitution amendment to run a DISTINCT high-assurance governed-
decision path (notice/approval/challenge). An effect that omits the declaration means the wallet
grant approves a bare state transition, not that governance decision — and the receipt then names a
declaration the approval never saw.

FIX (tightening, not a workaround): `amendment_root` is now a required field of the amendment
authority effect AND of the operation-commitment material. One declaration = one effect = one
authority request = one commitment. Touched: compiler (effect + commitment recipe; field set after
the json! literal, which had hit the macro recursion limit at 42 fields), proposal schema
authorityEffect required set (42), commitment invariants (2 rules), all 8 fixtures re-solved.

Side effect: the journey's wrong-scope probe and the real amendment now naturally carry distinct
request hashes, because they carry distinct declarations. The collision was the symptom; the missing
binding was the defect.

## inc.4 run 5 — SCOPE NAMING DECISION (canon-affecting; flag for user)

Run 5: all refusal proofs green, but the real amendment got 403
`system_lifecycle_authority_resolution_refused`. Root cause was NOT the wallet fixture (its binary
did carry the new scope): the shared authority gateway DERIVES the required scope as
`{AUTHORITY.scope_prefix}.{op}` with prefix `scope:autonomous_system.lifecycle`. No op string can
produce the originally-declared `scope:autonomous_system.constitution.amend`, so the gateway asked
the wallet for a scope nothing had granted.

Options weighed:
(a) a second AuthorityContract with prefix `scope:autonomous_system.constitution`. Semantically
    purer, but `prepare_node_evidence_for` hardcodes AUTHORITY for decision_effect_hash, so the
    contract would have to be threaded through SHARED, MERGED, PROVEN code used by m1-5a/m1-5b —
    real blast radius on the authority seam for a naming gain.
(b) ADOPTED: the amendment scope is `scope:autonomous_system.lifecycle.amend_constitution`, which
    the gateway derives correctly from op `amend_constitution`.

Why (b) is honest: the property canon actually requires is DISJOINTNESS, and it holds exactly —
the amend scope satisfies none of the fourteen operational transition scopes and none satisfies it
(m1-5b's wrong-scope proof and this cut's both hold). The `lifecycle` segment names the daemon's
System-operation authority namespace shared by every governed chain operation; the OPERATION segment
is what separates authority. Canon prose updated to say exactly that instead of the looser
"satisfiable by no lifecycle scope". One authority gateway, one evidence-domain family, one
derivation rule — no parallel authority path.

USER DECISION 2026-07-22 (CONFIRMED, not a proposal): KEEP
`scope:autonomous_system.lifecycle.amend_constitution`. Rationale accepted: it satisfies canon's
disjointness requirement, fits the shared authority gateway, and avoids unnecessary changes to proven
M1 code. A dedicated `constitution.*` namespace may be considered AFTER M1 as a broader
authority-naming refactor; it must NOT block M1 exit. Do not reopen this in m1-5c/d.
