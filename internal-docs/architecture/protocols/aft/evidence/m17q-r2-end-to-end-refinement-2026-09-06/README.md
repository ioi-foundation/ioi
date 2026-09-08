# M17Q R2 — QUV end-to-end transition-level composition witness (2026-09-06)

Status: `LOCAL_FINITE_DESIGN_CHECK_PASS_NOT_PRODUCTION_REFINEMENT`.

Addresses independent review finding `QUV-M17Q-005` (`../m17q-r1-import-2026-09-04/review-output/M17Q-quv-independent-review-daybreak-2026-09-04.md`, section "QUV-M17Q-005"): `QueryUnanimityCompositionProof.tla` is a conditional accepted-set lifting lemma with no state or transition for configuration, policy, domain, predecessor, durable head/recovery, live handoff, process-local continuation, stable resource key, or external register. This slice adds one composed, finite, explicit-state TLC transition model that has all of those as state and transitions, checks the required invariants in the positive configurations, and demonstrates each named mutation as a named invariant violation. It does not close the implementation-refinement obligation; see "Assumes / does not establish".

Base commit at hand-back: `24a9888e3` (dirty worktree; only the files listed below are this slice's).

## Files

New (all under `internal-docs/architecture/protocols/aft/formal/maximal_visibility/`):

| File | Role |
|---|---|
| `QuvEndToEndRefinement.tla` | the composed transition model (one module; every mutation is a boolean `CONSTANT` flag) |
| `QuvEndToEndRefinement.cfg` | positive: owned mode, `Correct = {m1, m2}`, 2 slots |
| `QuvEndToEndRefinementUnowned.cfg` | positive: unowned (first-winner) mode, 2 correct, 2 slots |
| `QuvEndToEndRefinementSolo.cfg` | positive: sole correct member, 2 slots, two sequential operation windows |
| `QuvEndToEndRefinementHandoff.cfg` | positive: old root + successor root, certified boundary, live handoff, gate install, activation |
| `QuvEndToEndRefinementTwoDomain.cfg` | positive: two domains, sole correct member (cross-domain key isolation) |
| `QuvEndToEndRefinementReachable.cfg` | reachability probe (registered as a COUNTERMODEL, existing `*Reachable.cfg` pattern): `NoExecutedSecondSlot` MUST be violated |
| `QuvEndToEndRefinementPredecessorInKey.cfg` | countermodel: `PredecessorInKey = TRUE` |
| `QuvEndToEndRefinementLateReply.cfg` | countermodel: `LateReplyAdmitted = TRUE` |
| `QuvEndToEndRefinementSkipExecutorQuv.cfg` | countermodel: `SkipExecutorQuv = TRUE` |
| `QuvEndToEndRefinementClaimAfterExpiry.cfg` | countermodel: `ClaimAfterExpiry = TRUE` |
| `QuvEndToEndRefinementCallBeforeClaim.cfg` | countermodel: `CallBeforeClaim = TRUE` |
| `QuvEndToEndRefinementUnauthenticatedRecovery.cfg` | countermodel: `UnauthenticatedRecovery = TRUE` |
| `QuvEndToEndRefinementResourceIdSplitsKey.cfg` | countermodel: `ResourceIdSplitsKey = TRUE` |
| `QuvEndToEndRefinementActivateFromBytes.cfg` | countermodel: `ActivateFromBytes = TRUE` |

Edited: `.github/scripts/run_aft_formal_checks.sh` — five entries appended to `MODELS`, nine to `COUNTERMODELS` (append-only; no focused `--…-only` branch was added). `bash -n` passes; every registered cfg/tla pair resolves to an existing file. The module has no local imports, so `run_countermodel`'s copy-two-files temp-dir execution needs no special case.

This evidence directory: `README.md` (this file), `tlc-logs/` (full TLC output per cfg, plus superseded first-pass runs and one extra diagnostic run), `manifest.sha256`, `metadata.json`.

## What the model has as state and transitions

- **Members** (`Correct`, model values; Byzantine members are silent and hold no state — the same premise as `QuvHeadPreparation.tla`). Executors are the correct relying members themselves: `query_unanimity_head_state_design.md` advances a frontier only through that member's own live operation, so a separate executor identity would have no head to admit against.
- **Per-member durable conflict store** `anchor[c]` keyed by `(root, domain, slot, pred)` with `pred = "any"` in the correct model (configuration root and policy root are folded into `root`; `authority_mode` is one `CONSTANT` per instance). `PredecessorInKey` makes the request-supplied predecessor a key component instead of an admission check (the pre-schema-5 store).
- **Two-phase durability**: `Record(c, e)` stages generation `g+1` (authenticated, or *torn* — an unauthenticated write that rolls the touched key back and crashes the member); `Commit(c)` anchors and only then exposes the nonce-bound reply; `Recover(c)` completes the single authenticated `g+1` window and drops unauthenticated bytes. Ghost `authGen[c]` is the highest generation any authenticated write produced.
- **Expected-predecessor admission** `Admissible(c, o)`: exact active root; slot at most next slot (retained old slots stay answerable, as the head design requires); predecessor equals the head-derived expected predecessor (initial coordinate or last accepted hash); handoff pushes additionally require the member's certified boundary. A refusal writes nothing and replies with a typed refusal; any typed refusal aborts the executor's operation (the `QuvHeadPreparation` "all correct members admissible" premise, made explicit as a reply).
- **Executor operation**: `Begin` pushes one exact context to every configured member; replies are retained only if first observed at or before the rooted cutoff `start + Delta` (inclusive) and only when they bind the exact live request (nonce freshness is abstracted as exact context plus start time — a stale staged record for a superseded operation is dropped at `Commit`). `Decide` runs strictly after the cutoff instant on whatever was retained: owned = every retained snapshot is exactly `{s}`; unowned = every retained first winner is `s`; otherwise a typed abort (no grant).
- **Q-A3 as an assumption**: `Tick` cannot leave an operation's cutoff instant while a correct member has not replied. The executor never reads `Correct`.
- **Own head advancement** `Advance(e)` appends only at the next offset; a different hash at an occupied offset is the `ConflictingAcceptedHistory` refusal (no write). `NoConflictingOwnHead` checks that the refusal is never needed to hide a rewrite.
- **Process-local continuation** `grant[e]` with absolute `expires` and the execution `height` at acceptance; lost on crash and droppable at any time; consumed single-use by `Claim`. `Claim` requires unexpired, same height, own head holding the value, and the admitted manifest binding (domain, slot, predecessor, authority mode via the instance, manifest root = candidate) equal to the accepted candidate.
- **T10 externalization**: durable `claims[e]` keyed by the stable `(domain, slot)` key is written before `Call`; the external register is put-if-absent on the idempotency key the call carries (stable key in the correct model); crash between claim and call leaves the claim and no handle, so a later grant for the same key can only `Reconcile` (lookup-only, no call).
- **Handoff**: a member reaches its certified boundary; the successor is a candidate `"r1"` in the `handoff` domain under the old root, accepted only by the member's own live operation; `InstallGate` consumes that grant into a durable gate; `Activate` requires the gate; recovery reloads it; `ReceiveBytes` models a handoff transcript arriving from a member that installed the gate, and only the `ActivateFromBytes` mutation lets bytes synthesize a gate.

## Invariants (positive cfgs check all of these)

`TypeOK`, `NoConflictingAccepts`, `OneCanonicalConflictIdentity`, `AcceptedKnowledgeRetained`, `NoConflictingOwnHead`, `NoClaimWithoutOwnLiveAccept`, `NoClaimAfterExpiryOrFence`, `AtMostOneExternalMutationPerStableKey`, `NoBlindReplayAfterCrash`, `RecoveryNeverAdvancesBeyondAuthenticatedRecords`, `NoSuccessorAuthorityFromBytes`. `NoExecutedSecondSlot` is the reachability probe (must be violated).

## Results

TLC 1.8.0 (`tla2tools.jar` sha256 `ab323b79…6c05f`), OpenJDK 21, `-cleanup -deadlock`, 4–6 workers, `-XX:+UseParallelGC`. The committed harness runs the same cfgs single-worker; elapsed times below are for the worker counts stated and will be longer there. Under `SYMMETRY Symm` (permutations of `Correct`) with multiple workers, TLC's generated/distinct counts vary by a few hundred between runs (the main cfg reported 1,812,319 and 1,812,222 distinct in two runs); the verdicts do not.

| cfg | expected | observed | generated | distinct | depth | elapsed |
|---|---|---|---|---|---|---|
| `QuvEndToEndRefinement.cfg` | pass | pass | 8,938,002 | 1,812,222 | 31 | 30 s (6 w) |
| `QuvEndToEndRefinementUnowned.cfg` | pass | pass | 8,965,487 | 1,818,675 | 31 | 28 s (6 w) |
| `QuvEndToEndRefinementSolo.cfg` | pass | pass | 25,205 | 8,980 | 26 | 1 s |
| `QuvEndToEndRefinementHandoff.cfg` | pass | pass | 16,827,430 | 3,273,246 | 37 | 66 s (6 w) |
| `QuvEndToEndRefinementTwoDomain.cfg` | pass | pass | 89,961 | 31,472 | 26 | 2 s |
| `QuvEndToEndRefinementReachable.cfg` | `Invariant NoExecutedSecondSlot is violated` | as expected | 18,826 | 7,315 | 21 | 1 s |
| `QuvEndToEndRefinementPredecessorInKey.cfg` | `Invariant NoConflictingAccepts is violated` | as expected | 5,391,269 | 1,533,593 | 16 | 22 s (6 w) |
| `QuvEndToEndRefinementLateReply.cfg` | `Invariant NoConflictingAccepts is violated` | as expected | 115,170 | 37,814 | 11 | 2 s |
| `QuvEndToEndRefinementSkipExecutorQuv.cfg` | `Invariant NoClaimWithoutOwnLiveAccept is violated` | as expected | 132,779 | 39,654 | 12 | 2 s |
| `QuvEndToEndRefinementClaimAfterExpiry.cfg` | `Invariant NoClaimAfterExpiryOrFence is violated` | as expected | 2,242 | 945 | 14 | 1 s |
| `QuvEndToEndRefinementCallBeforeClaim.cfg` | `Invariant NoBlindReplayAfterCrash is violated` | as expected (see deviation 1) | 22,014 | 7,456 | 22 | 2 s |
| `QuvEndToEndRefinementUnauthenticatedRecovery.cfg` | `Invariant RecoveryNeverAdvancesBeyondAuthenticatedRecords is violated` | as expected | 278 | 136 | 7 | 1 s |
| `QuvEndToEndRefinementResourceIdSplitsKey.cfg` | `Invariant AtMostOneExternalMutationPerStableKey is violated` | as expected | 22,402 | 7,864 | 21 | 1 s |
| `QuvEndToEndRefinementActivateFromBytes.cfg` | `Invariant NoSuccessorAuthorityFromBytes is violated` | as expected | 1,488,974 | 370,848 | 15 | 11 s (4 w) |

Diagnostic run (not registered): `CallBeforeClaim` cfg with only `AtMostOneExternalMutationPerStableKey` — passes, 22,593 generated / 7,552 distinct, depth 25, complete (`tlc-logs/CallBeforeClaim-mutation-invariant-only.log`).

Superseded first-pass runs are kept in `tlc-logs/superseded-*.log`: the handoff cfg at `MaxTime = 3, MaxHeight = 1` passed at 25,073,844 distinct states (526 s, 6 w) and at `MaxTime = 2, MaxHeight = 1` at 6,572,826 distinct (151 s); the two-member `ResourceIdSplitsKey` instance found its violation after 4,485,672 distinct states (76 s); the `ActivateFromBytes` instance at `MaxHeight = 1` found its violation after 698,724 distinct (16 s). The registered instances were tightened as documented below; no invariant or transition was changed for tractability.

## State-space constraints and reductions (all documented, none weaken an invariant)

- Bounded constants per cfg: `MaxTime` (3, or 4 for two sequential operation windows, or 2 for the handoff family), `Delta = 1`, `Lifetime` (1; 0 in the expiry countermodel so expiry precedes `MaxTime`), `MaxHeight` (1; 0 in the handoff family — the height fence is witnessed by the main, solo and `ClaimAfterExpiry` cfgs), `MaxGen = 3` with `CONSTRAINT GenBound`, `MaxSlot` (2 where the second slot matters, else 1).
- `SYMMETRY Symm = Permutations(Correct)` on two-member cfgs only.
- `BeginPreds`: an executor tries its expected predecessor or exactly one wrong one (so typed refusal and, under `PredecessorInKey`, the split are exercised without the third value).
- `BeginRids`: delivery ids vary (`{ra, rb}`) only in cfgs whose mutation reads them (`ResourceIdSplitsKey`, `CallBeforeClaim`); elsewhere fixed.
- The admitted manifest chain is fixed to candidate `X` at every slot (`Admitted(dom, s) = "X"`); `Y` is the competing, never-admitted candidate. Accepting `Y` is reachable (owned mode when only `Y` is pushed) and is then refused at the claim binding, so the binding check is exercised; a nondeterministic admitted chain multiplied the initial states without adding a distinct claim.
- Heads are root-independent (the successor's initial coordinate equals the certified old head); retirement/garbage collection of old-root stores is not modeled.

## Deviations from the requested countermodel table (reported, not hidden)

1. **`CallBeforeClaim` violates `NoBlindReplayAfterCrash`, not `AtMostOneExternalMutationPerStableKey`.** With a faithful T10 register (put-if-absent on the stable idempotency key, Q-EA6) the crash-before-claim retry issues a *second call* carrying the *same* stable key, which the register deduplicates; the physical mutation count stays 1. The diagnostic run above confirms the mutation invariant holds under this mutation over the complete state space. The property claim-before-call actually protects is T10's `NoBlindReplayAfterAmbiguity` (invocations <= 1), lifted here per executor and stable key. Making the mutation count go to 2 would require the retry to carry a *different* idempotency key — which is exactly the `ResourceIdSplitsKey` mutation, witnessed separately. I did not distort the register to force the requested string.
2. **`LateReplyAdmitted` is modeled as an unfenced finalization.** Under Q-A3 no correct reply can be first observed after the cutoff, so "admit late replies" alone has no reachable effect on safety; correct snapshots are monotone and can only add conflicts. The flag therefore removes the cutoff fence from finalization as a whole (the executor no longer waits through the cutoff, and admits any reply present when it finalizes), which is the R4 `oneway` mutation in transition form and does produce the conflicting-accept trace (two executors each decide on their own member's early snapshot). The flag name is the requested one; its precise semantics are in the module comment.
3. **`PredecessorInKey` also drops the head-derived predecessor admission check** (the request-supplied predecessor becomes the key). Under strict head admission at every correct member the split is unreachable in this instance (all members derive the same expected predecessor); the normalization is defense in depth for the pre-schema-5 store the review describes, and that is what the countermodel models.

## Assumes / does not establish (proposed spec wording)

This is a finite explicit-state transition model over an abstraction of the production state machine, not a mechanized refinement of the Rust implementation. It assumes atomic durable writes at record, anchor, head, claim and gate granularity; MAC unforgeability (an unauthenticated record is exactly the torn-write case, never a forged one); ideal model time (the rooted cutoff is a single shared clock, and Q-A3 is a constraint on that clock rather than a measured envelope); static faults with silent Byzantine members; direct executor reachability of every configured member; and a faithful T10 register (atomic put-if-absent on the idempotency key the call carries). Executors are identified with correct relying members; nonce freshness is abstracted as exact-context-plus-start binding; the admitted manifest chain is fixed; heads are root-independent across handoff; retention, retirement, capacity, scheduling and the runtime-finality lock are outside the model. It establishes that, under those assumptions and within the bounded instances listed here, the composed transitions preserve the named invariants and that each named mutation is sufficient to break the named invariant. It does not establish Q-A3, Q-A9, portable authority, liveness beyond the single reachability witness, or that `crates/consensus/src/aft/query_unanimity*` or `crates/validator/.../quv.rs` refine these transitions.

## Proposed paragraph for `specs/query_unanimity_end_to_end_theorems.md` (section 4, after the "conditional lifting lemmas" paragraph)

`QueryUnanimityCompositionProof.tla` is a conditional accepted-set lifting lemma: it assumes accepted-value uniqueness, accepted histories and accepted mutation candidates as premises and lifts them pointwise; it has no state or transition for admission, heads, recovery, continuation, handoff or the external register. `formal/maximal_visibility/QuvEndToEndRefinement.tla` is the transition-level composition witness that R1 finding QUV-M17Q-005 required: a finite explicit-state TLC model whose transitions include expected-predecessor admission with typed refusal, two-phase authenticated record/anchor durability with crash recovery, timed executor operations with the rooted cutoff, own-head advancement, process-local continuation expiry and height fence, T10 claim-before-call externalization on the stable key, and successor activation only through the successor's own live operation. Its positive instances (owned, unowned, sole correct member, handoff, two domains) preserve `NoConflictingAccepts`, `OneCanonicalConflictIdentity`, `NoClaimWithoutOwnLiveAccept`, `NoClaimAfterExpiryOrFence`, `AtMostOneExternalMutationPerStableKey`, `NoBlindReplayAfterCrash`, `RecoveryNeverAdvancesBeyondAuthenticatedRecords` and `NoSuccessorAuthorityFromBytes`, and `QuvEndToEndRefinementReachable.cfg` exhibits an accepted-and-executed two-slot trace with one correct member. Its registered mutations each break the named invariant: `PredecessorInKey` and `LateReplyAdmitted` break `NoConflictingAccepts`; `SkipExecutorQuv` breaks `NoClaimWithoutOwnLiveAccept`; `ClaimAfterExpiry` breaks `NoClaimAfterExpiryOrFence`; `CallBeforeClaim` breaks `NoBlindReplayAfterCrash` (the physical mutation count is protected by the T10 register, not by claim order); `ResourceIdSplitsKey` breaks `AtMostOneExternalMutationPerStableKey`; `UnauthenticatedRecovery` breaks `RecoveryNeverAdvancesBeyondAuthenticatedRecords`; `ActivateFromBytes` breaks `NoSuccessorAuthorityFromBytes`. This is bounded design evidence under the assumptions recorded in `evidence/m17q-r2-end-to-end-refinement-2026-09-06/README.md`; it is not a mechanized refinement of the implementation, and the implementation-refinement half of QUV-M17Q-005 remains open.

## Reproduction

```text
cd internal-docs/architecture/protocols/aft/formal/maximal_visibility
java -cp ../../../../../../.internal/formal-cache/tools/tla/tla2tools.jar tlc2.TLC -cleanup -deadlock \
  -config QuvEndToEndRefinement.cfg QuvEndToEndRefinement.tla
# and likewise for every other QuvEndToEndRefinement*.cfg; the harness runs them all:
bash .github/scripts/run_aft_formal_checks.sh
```

## sha256

```text
18a3a3a16855ed11c7a3640622b6bd0c77e65ef206ccd2b70bf960b6553c4b83  formal/maximal_visibility/QuvEndToEndRefinement.tla
8a52f19245cfb4d0e122caeec8d35793fc969d4fde64c1c144fa332aa02ad175  formal/maximal_visibility/QuvEndToEndRefinement.cfg
90c17a7f38fb00a44a4d726dd2099a839495f1f25f10cb758a861d13b0be2570  formal/maximal_visibility/QuvEndToEndRefinementUnowned.cfg
885434bafc3b10729761bcf9a495f5734fbaf76f90c47650d1dcd540abe34a14  formal/maximal_visibility/QuvEndToEndRefinementSolo.cfg
2dc21278e8548d8a47c5e64af56547ddb65e035933a23de25488c2f02ea242b1  formal/maximal_visibility/QuvEndToEndRefinementHandoff.cfg
adf638505c5da9bdfcddda9ae577e7b99b09069028df034ad93fb2e96d7aedd0  formal/maximal_visibility/QuvEndToEndRefinementTwoDomain.cfg
63a64e2e58877d778c220d6914af88561e7f1d11a8b2794c9773c735dc07b2b1  formal/maximal_visibility/QuvEndToEndRefinementReachable.cfg
7a4281e09e04c79d41bdd782954a8f4027bd30647387927c5f5e53c9fc11c048  formal/maximal_visibility/QuvEndToEndRefinementPredecessorInKey.cfg
d4b68982e7d98e82d5e8cd239ade6407fb55d3ba6867c56c97a23cc1f1f46a91  formal/maximal_visibility/QuvEndToEndRefinementLateReply.cfg
bbbcdf84a210518b88d5fa7fe2baaa74509d411d44e0810f2811c7fe91fd8543  formal/maximal_visibility/QuvEndToEndRefinementSkipExecutorQuv.cfg
84e09a8ff7cb686e01d7148dcc90ee46218249efb161318b3b7c8c49fd3e2d04  formal/maximal_visibility/QuvEndToEndRefinementClaimAfterExpiry.cfg
db039d46d35010e2d1d5d984409ba8261540ab1d46219c7fbee60c19dbc5be71  formal/maximal_visibility/QuvEndToEndRefinementCallBeforeClaim.cfg
46a870eae496f1cdc4e7193ae898341f6ca8252035a40c6e234f120c4161661a  formal/maximal_visibility/QuvEndToEndRefinementUnauthenticatedRecovery.cfg
81c85cd2fa9edd7d67329f5433225edf36d19a34cbae70cf68102de6a4c08879  formal/maximal_visibility/QuvEndToEndRefinementResourceIdSplitsKey.cfg
7d86a9dec8a5bcaf1ef6fe99f7054d59d3e16c4d0345dc52a419412c332662d1  formal/maximal_visibility/QuvEndToEndRefinementActivateFromBytes.cfg
d017ac2f285e6eac61711dfb162434ea449ef8414868c9582ce36b461eb4cadb  .github/scripts/run_aft_formal_checks.sh (after the append; other agents also hold this file dirty)
ab323b79802aedc3203b3f9af37c6aca3ed43f4e0225b36f2aa77b26de46c05f  .internal/formal-cache/tools/tla/tla2tools.jar
```

`manifest.sha256` in this directory covers these files, this README and every log.
