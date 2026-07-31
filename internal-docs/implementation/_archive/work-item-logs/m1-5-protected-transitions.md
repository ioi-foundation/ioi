# Work item — M1.5 protected lifecycle transitions (scoped)

> **Status routing (2026-07-22): preserved human cut log.** The sole live
> status owner is
> `docs/architecture/_meta/work-items/m1-5-protected-transitions.v1.json`,
> validated with `npm run check:work-items`. Status labels and increment notes
> below are retained provenance and must not be used as a current cut claim.

Planning record per master guide §4.1. Status: `scoped` — admission blocks on
PR #97 (M1 initialize/activate) reaching verified, because these transitions
extend the same `SystemLifecycleOperation` runtime family and chain sequence.

```text
work_item_id: m1-5-protected-transitions
stage_id: M1 (required work M1.5)
status: scoped
objective: Implement distinct protected amendment, migration/succession,
  suspension, dissolution, and enrollment transitions over the live System
  chain, each under its own authority path, so protected fields change only
  through their declared paths (M1 exit condition 2).
falsifiable_claim: A caller holding ordinary lifecycle authority (or replaying
  initialize/activate evidence) can never admit an amendment, suspension,
  dissolution, migration/succession, or enrollment transition; each transition
  admits exactly once, under its own scope, with exact predecessor roots, and
  reconstructs after restart.
selected_profile: single_authority local deployment (unchanged).
canon_owners:
  - docs/architecture/foundations/governed-autonomous-systems.md
    (constitution-before-recursion list; amendment = distinct high-assurance
    path with notice/approval/challenge/activation/rollback; recovery,
    migration, succession, dissolution, decommission belong only to the live
    system; enrollment never silently inherits identity/assurance)
  - docs/architecture/foundations/common-objects-and-envelopes.md
    (AutonomousSystemConstitutionAmendmentEnvelope: proposal/decision evidence
    only; "a separately verified constitutional transition must bind the same
    roots and decision under the active predecessor's external governance
    path"; proposal cannot satisfy its own authority requirements)
current_implementation_evidence:
  - Registered + fixtured: autonomous-system-constitution-amendment.v1
    (schema, invariants, positive-proposed / negative-committed-status
    fixtures) — proposal/decision evidence contract only.
  - NOT registered: suspension, dissolution, migration/succession, enrollment
    transition contracts; amendment TRANSITION (execution) contract.
  - Runtime seam: crates/node/src/bin/hypervisor_daemon_routes/
    system_activation_routes.rs — SystemLifecycleOperation {Initialize,
    Activate}, sealed intents, distinct scope:autonomous_system.lifecycle.*
    wallet scopes, fail-closed wallet consumption, persist_graph no-clobber
    chain 0 -> 1 -> 2. M1.5 extends this family and the operation log.
dependencies: PR #97 verified (chain sequences 1-2); unsigned M0 census epoch per slice.
in_scope:
  - Contract family: amendment-transition, suspension, resumption-or-explicit
    one-way rule, dissolution (with residual disposition refs), migration/
    succession, enrollment (optional profile) — registry + invariants +
    positive/negative fixtures + generated Rust/TS projections.
  - Daemon routes extending the lifecycle family with one distinct wallet
    scope per transition kind; sealed intent + durable replay identical to
    initialize/activate; exact predecessor commitment (chain head + roots).
  - Amendment transition must bind the approved
    AutonomousSystemConstitutionAmendmentEnvelope decision + exact
    predecessor/successor constitution roots; protected/unamendable clauses
    fail closed.
  - Agentgres domains per transition kind, no-clobber, restart reconstruction.
out_of_scope: membership/topology (M2), consensus, product Systems UX beyond
  the pulled read projections (M1.7), any room/GoalRun coupling (M3+),
  network enrollment effects beyond the local enrollment record.
consequential_effects_and_final_invokers: each new POST route names
  persist_graph-family leaves under with_source_locks; census will classify
  candidates with BLK-M0-FINAL-INVOKER-PROOF as with #97 (no terminality
  claim).
applicable_pg_ids: map at admission; no PG closure claimed here.
positive_proof: one journey per transition kind; amendment end-to-end from
  proposed envelope -> decision -> transition -> new active constitution root.
adversarial_or_fault_proof: wrong-scope substitution across all transition
  kinds; stale predecessor root; replayed initialize/activate evidence;
  protected-path amendment without required path; suspension of a dissolved
  system; enrollment self-inheritance; restart mid-intent convergence; forged
  decision refs; a proposal satisfying its own authority requirement.
product_journey_and_states: pulled M1 surfaces only (Governance preview,
  provisional System detail) — read projections of transition state; honest
  absent/degraded states.
metrics_and_frozen_thresholds: journey counts frozen at admission before
  observation.
compatibility_and_migration: additive contract family; existing sequence 0-2
  records immutable; each slice appends one unsigned census review epoch
  (v3 hash chain; no signing ceremony).
evidence_index: to be created at admission (docs/evidence or PR ledger).
remaining_nonclaims: no runtime/workload execution from any transition; no
  membership, writer/finality, distribution, or federation claim; enrollment
  record is local evidence, not IOI Network assurance.
rollback_or_stop_rule: stop if a transition cannot name its final invoker, if
  any transition is reachable under another transition's scope, or if
  amendment can bypass the envelope's separate-decision rule.
source_provenance: master guide M1.5 + §16; canon owners above; PR #97 code.
```

Sequencing note (updated 2026-07-22): the M0 census epoch is now an UNSIGNED
hash-chain entry (v3), so new-route cuts no longer queue behind a signing
ceremony, and the user removed the one-PR-at-a-time constraint. Phase M1.5 into
reviewable slices, each with its own unsigned census epoch:
- m1-5b: generic protected operational transitions (suspend/reinstate, pause/
  resume, dormancy, recovery, quarantine, retire/archive/revoke/decommission)
  over the existing LifecycleTransitionReceiptEnvelope at sequence >= 3, plus
  the new protected-transition proposal/decision contracts and the lifecycle
  state extension beyond initialized|active.
- m1-5c: constitution-amendment EXECUTION transition binding the approved
  AutonomousSystemConstitutionAmendmentEnvelope decision (named receipt owner).
- m1-5d: migration/succession, dissolution (residual disposition), and local
  network-enrollment records (named receipt owners; enrollment local_only).
Canon grounding confirmed: the activation proposal family is
activation-bootstrap-only by declaration; LifecycleTransitionReceiptEnvelope
already enumerates the generic op vocabulary; named owners are explicitly
reserved in canon ("Migration, succession, dissolution, constitutional
amendment, and network enrollment retain their named receipt owners").

## m1-5b design groundwork (2026-07-22)

Chain schema already canonizes all 18 lifecycle states. Generic-op legality
matrix for m1-5b (op: predecessor state(s) -> resulting state; everything else
fails closed; sequence >= 3; each op gets scope:autonomous_system.lifecycle.<op>):

- pause: active | degraded -> paused
- resume: paused -> active
- suspend: active | degraded | paused -> suspended
- reinstate: suspended -> active
- enter_dormancy: active | paused -> dormant
- wake: dormant -> active
- begin_recovery: degraded | suspended | quarantined -> recovering
- complete_recovery: recovering -> active
- quarantine: active | degraded | paused | recovering -> quarantined
- release_quarantine: quarantined -> active
- retire: active | paused | suspended | dormant -> retired
- archive: retired -> archived (one-way)
- revoke: any non-terminal -> revoked (one-way, protected)
- decommission: retired | archived | revoked -> decommissioned (terminal)

Reserved to named-owner slices: succession_pending, successor_governed
(m1-5d migration/succession); dissolution_pending, dissolving, dissolved
(m1-5d dissolution); draft/initialized/active bootstrap arcs stay owned by
genesis + m1-5a initialize/activate. degraded is an OBSERVED posture, not an
op target: no proposal may set it directly.

New contracts for m1-5b: protected-transition proposal + authority-decision
envelopes (op-discriminated, sequence >= 3, exact predecessor state root +
chain head commitment, per-op scope) + lifecycle-state envelope covering the
generic-op resulting states; transitions/receipts ride the existing
LifecycleTransitionReceiptEnvelope. One-way ops must declare irreversibility
in the proposal so a decision cannot silently approve a terminal effect.

## m1-5b progress checkpoint (2026-07-22, in worktree ioi-m1-5b @ 0c5e5c558)

DONE: canon sections inserted in common-objects-and-envelopes.md before
LifecycleTransitionReceiptEnvelope (ProtectedTransitionProposal/Decision +
LifecycleState envelopes, normative op-by-predecessor legality table);
check:architecture-docs green. Draft schemas written for proposal/decision/
lifecycle-state (data-driven from the legality table, 14 allOf op branches).

OPEN DESIGN ITEM before registration: `authority_effect:
exact_closed_server_derived_effect` in canon YAML is prose shorthand — the
wire contract models a CLOSED EFFECT OBJECT (see activation proposal schema's
authorityEffect $defs and its operation-commitment invariant material list:
op/sequence/scope/system/genesis + predecessor coordinates + resulting
coordinates). The protected-transition proposal/decision schemas must define
the per-op closed effect object to match what the runtime derives server-side
(sealed decision jcs domains like hypervisor.system-lifecycle.decision.*),
plus jcs_sha256_equals identity invariants (proposal_root recomputes;
operation_commitment recomputes). Then: registry entries, fixtures
(positive per op class + negatives: illegal predecessor, scope substitution,
irreversibility mismatch, succession/dissolution status smuggling), generator
run, and the runtime slice in the same PR.

Closed effect object design for m1-5b (mirrors
ioi.autonomous-system-lifecycle-authority-effect.v1, ~50-field closed shape):
`ioi.autonomous-system-protected-transition-authority-effect.v1` binds
op/required_scope/sequence(>=3) + identity continuity (system_id, genesis_ref,
home_domain_ref/commitment/binding refs+roots, policy_root,
module_registry_root) + predecessor coordinates (predecessor_status,
predecessor_state_ref/root, predecessor chain head root, predecessor
transition/receipt refs+roots) + resulting coordinates (resulting_status,
resulting_state_ref/root) + active_profile_set_ref/root carried UNCHANGED
(generic ops never touch the profile set) + irreversibility +
operation_commitment + explicit negative claims:
node_membership_created:false, runtime_effect_admitted:false,
network_effect_admitted:false, constitution_changed:false,
profile_set_changed:false. Build schema and runtime derivation together in
the implementation stretch so the derived object and contract cannot drift.

## m1-5b increment log

- Increment 1 COMMITTED (feat/system-lifecycle-transition-contracts): canon
  sections + draft schemas (f6beaa599) and
  crates/types/src/app/system_lifecycle_transitions.rs — ProtectedTransitionOp
  (14 ops) / ProtectedLifecycleStatus / TransitionIrreversibility with the
  canon-pinned legality matrix; 6/6 unit tests including row-by-row canon
  parity. Scopes disjoint from bootstrap.
- Increment 2 NEXT — effect derivation + compiled plan (types crate,
  system_activation.rs is the template): add
  compile_protected_transition_plan(...) producing a plan whose
  authority_effect is ioi.autonomous-system-protected-transition-authority-effect.v1
  (field list earlier in this file). Template functions: authority_effect()
  at crates/types/src/app/system_activation.rs:1249 (json! effect assembly,
  operation_commitment_from_effect last), CompiledSystemLifecyclePlan at :174,
  compile fns at :1000/:1204. Predecessor step at sequence n-1 may be the
  activation step (activation_state_ref) or a prior protected transition
  (lifecycle_state_ref) — read whichever ref key the predecessor state
  carries. Identity-continuity coordinates carry from the stored activation
  source records (revalidate, do not trust caller). Enforce
  admits_predecessor() from the new op family before any effect is built.
- Increment 3: rework draft proposal/decision schemas to embed the closed
  effect object; registry entries + invariants (jcs_sha256_equals identity
  rules) + fixtures (positive per irreversibility class + negatives: illegal
  predecessor, scope substitution, irreversibility mismatch, reserved-status
  smuggling); run the contract generator; contract gates.
- Increment 4: runtime route pair /v1/hypervisor/autonomous-systems/:id/
  transitions/:op (GET+POST, TWO census identities not 28) over the sealed
  intent machinery; per-op scope; chain/operation-log continuation at
  sequence >= 3; lifecycle-state persistence; fault-injection recovery
  convergence.
- Increment 5: journey verifier extension (protected-transition journey +
  illegal-matrix adversaries), unsigned census epoch 8, full pre-next-leg,
  PR with delegated review.
- Post-#102-merge follow-on: rebase m1-5b, wire check:work-items into
  check:pre-next-leg steps (after architecture-docs), add the m1-5b work-item
  record.

- Increment 4a COMMITTED (3f677d024): 27 spine symbols pub(crate) so the
  protected runtime CONTINUES the proven authority/evidence path (zero
  behavior change; the AuthorityContract at system_activation_routes.rs:101
  is already lifecycle-generic and covers the per-op scopes).
- AUTHORITY-PATH FINDING (fixed before any runtime built on it): the closed
  protected effect omitted source_governing_authority_ref — the governing
  principal continuity that decision policy/request hashes bind
  (prepare_node_evidence:481-499 derives both from it). Added to the Rust
  effect + commitment material, the schema effect $defs, the invariant
  commitment rules, and regenerated fixtures. Lesson: derive effect field
  sets from the authority path first, not from the state path alone.
- Increment 4b design notes: reuse prepare_node_evidence by genericizing over
  (effect, op_str, sequence, scope, governing_ref) with a bootstrap wrapper;
  serialize protected transitions against SYSTEM_ACTIVATION_GATE (export the
  async gate) because they mutate the same chain; head discovery reads the
  latest CHAIN_DIR revision as the authoritative pointer; body contract
  mirrors activation POST (caller wallet grant refs + expected predecessor
  roots; server derives everything else).

- CONTRACT-EVOLUTION FINDING (2026-07-22, template read complete): the
  operation-log v1 contract is deliberately CLOSED to the activation prefix
  (snapshot_kind const activation_prefix; entries exactly 3; latest_sequence
  const 2) — sequence >= 3 logging REQUIRES an
  autonomous-system-operation-log.v2 successor contract (general entries
  minItems 3 no max; latest_sequence >= 2; snapshot_kind lifecycle_log;
  activation_prefix retained as a required embedded sub-object so the
  bootstrap evidence stays closed inside the general log). Register with
  evolution.successor_of = v1 and predecessor_remains_valid = true (v1 stays
  the valid shape for the committed sequence-2 revision). The CHAIN contract
  is already general (latest_sequence >= 2, full status enum) and needs no
  evolution — new revisions simply continue.
- 4b sequencing (template read now COMPLETE through build_admitted_step,
  complete_live_graph, evidence intent round-trip): 4b-0 operation-log v2
  contract + fixtures + canon note; 4b-1 protected route module helper layer
  (dirs, tails, chain-head discovery from latest CHAIN_DIR revision,
  predecessor loading incl. activation-step fallback, protected artifact
  builders mirroring build_admitted_step but per-op refs
  proposal://{ns}/lifecycle/sequence/{n}, log-v2 continuation, chain
  revision continuation) + unit tests, no routes; 4b-2 genericized
  prepare_node_evidence (effect/op/sequence/scope/governing params +
  bootstrap wrapper) + POST/GET handlers + sealed intents + daemon
  registration (2 routes); 4b-3 fault hooks + 12-way race + restart
  backfill tests. Then inc.5 journeys + census epoch 8.

## inc.5b — final bars + PR (2026-07-22)

- Bar 1: full 11-journey suite 100/100, literal FULLJ_EXIT=0 (protected-transition first in journey census; teardown 37/37, zero descendants).
- Bar 2: check:pre-next-leg literal PNL3_EXIT=0 at tip 4c17d324d after two honest deliberate-change-pin refusals, both acknowledged without weakening: tier pin ← work-items tier (fda9064fa), m0 anchor pin ← census epoch 8 (4c17d324d). Note: BOTH background task notifications claimed exit 0 while the literal exits were 1 — the gate-on-literal-exit rule caught both.
- Work-item record → evidence_ready (932628b52): evidence_refs must be machine-checked repo paths (checker refuses prose); run literals live in adversarial_or_fault_proof.
- PR #103 OPEN with delegated review APPROVE (independent bar re-execution; red-flag sweep: fault hooks = crash-only forced_fault; 5 production expects = line-for-line m1-5a house pattern on infallible-by-construction values; zero bypasses). USER RUNS THE MERGE.
- On land: flip record to verified with merged anchor; refresh projection; next slice = m1-5c amendment execution.
