# AFT M17Q independent QUV security and theorem review

Disposition: **REPAIR_REQUIRED**

Review subject: annotated tag
`aft-quv-v0-m17q-candidate-r1-2026-09-04`, tag object
`3dc63d9d802ac9a1c373a795a22161903692d2b6`, peeled commit
`24a9888e3b88383c18dfbfea0f2e7fa44b99fa64`.

Reviewer: fresh `gpt-daybreak-blue-latest` automated reviewer. Review began
`2026-09-04T21:49:28Z`; review ended `END_TIME_PENDING`. This is an automated
independent review, not human peer review, certification, or an external
institutional audit.

## 1. Executive result

The abstract online Query-Unanimity Verification argument remains a conditional
construction: if every correct member durably and monotonically records both
opposing candidates in one correctly scoped slot, and every executor receives
every correct reply by the rooted end-to-end deadline, two conflicting
candidates cannot both pass the stated union/first-winner predicate. My
independent bounded twin supports that narrow result and deliberately recovers
the expected failures when its assumptions are removed.

The candidate is nevertheless not admissible. I reproduced production
authorization/state defects and identified further exact production traces:

1. The candidate-controlled predecessor is part of the member-store map key,
   but neither the member nor the effect executor checks it against one durable
   expected predecessor. Two candidates for the same configured
   domain/numeric slot can therefore select different predecessor hashes,
   obtain singleton snapshots from every correct member, and both execute.
2. Both member and handoff stores authenticate only the old anchor. On restart,
   any structurally valid ordinary state one generation ahead that names the
   authenticated old head is blessed without a MAC or authenticated pending
   journal. This can erase conflict knowledge or mint a successor activation
   gate without the custody key or a live QUV operation.
3. The verifier admits replies observed after the rooted decision deadline and
   the audit verifier accepts the resulting timing record.
4. The whole grow-only store is cloned, canonically encoded, hashed, and
   atomically rewritten for every new candidate, with no lifetime/rate quota or
   safe compaction. A Byzantine rooted account can serially exhaust the
   qualified timing/byte envelope and ultimately make restart fail.
5. An unauthenticated status response can claim the sole correct member's
   account before the correct carrier arrives. The PQ manager permanently
   reserves that account for the attacker's carrier before any ML-DSA identity
   proof, so the genuine carrier is refused and the correct QUV reply is routed
   to the attacker.
6. Cached consequence state is not revalidated at the actual `Claimed`
   transition: protocol-height/authority fences and the process-local
   continuation deadline can expire before the irreversible claim.
7. Terminal-effect replay, finite durable QUV outboxes, and stale-record ACK
   semantics let Byzantine or leftover traffic exclude unrelated or current
   correct operations despite the nominal bounded lanes.
8. An existing consequence receipt suppresses reconstruction from the actual
   Agentgres admission. Because that receipt has only self-computed unkeyed
   hashes, substituted ordinary state can select an unadmitted manifest, then
   use a fresh QUV result for that manifest to reach the sole external mutation
   owner.

The first two defects reproduce as executable exact-candidate regressions, and
the third reproduces as an exact-candidate timing regression. The persistent
resource defect and authorizing-receipt substitution follow from complete
source traces and are represented by explicit independent-twin mutations.
These are remediable enforcement defects rather than a counterexample to the
abstract theorem under all of its ideal assumptions, so the correct disposition
is `REPAIR_REQUIRED`, not `REJECT`.

No part of this disposition changes the fixed boundaries: the M12a portable
byte-only impossibility remains; QUV is online and known-synchronous only;
`portable_final_receipt=false`; audit bytes never authorize; there is no
portable, offline, asynchronous, exact-decision Byzantine-agreement, or
classical-consensus result; and the original M13-M18 remain blocked.

## 2. Independence and immutable preflight

I had no implementation role, no prior candidate exposure, and no conflict to
disclose. The commissioning checkout was used only as a local Git object/source
for a no-hardlinks clone. I did not inspect uncommitted files from it.

Clean-room path:
`/tmp/ioi-m17q-daybreak.u6nAwg/review-clone`.

Preflight commands:

```sh
review_root="$(mktemp -d /tmp/ioi-m17q-daybreak.XXXXXX)"
git clone --no-hardlinks --no-checkout \
  /home/heathledger/Documents/ioi/repos/ioi \
  "$review_root/review-clone"
cd "$review_root/review-clone"
git fetch --force --tags origin
git cat-file -t refs/tags/aft-quv-v0-m17q-candidate-r1-2026-09-04
git rev-parse refs/tags/aft-quv-v0-m17q-candidate-r1-2026-09-04
git rev-parse refs/tags/aft-quv-v0-m17q-candidate-r1-2026-09-04^{}
git checkout --detach refs/tags/aft-quv-v0-m17q-candidate-r1-2026-09-04^{}
git status --short --branch
```

Observed before review:

```text
object type: tag
tag object: 3dc63d9d802ac9a1c373a795a22161903692d2b6
peeled commit: 24a9888e3b88383c18dfbfea0f2e7fa44b99fa64
status: ## HEAD (no branch)
```

The tag and commit exactly match the commission. The initial tree was clean.
The only later untracked tree entry was the mandatory runner's newly created
evidence directory.

## 3. Claim reviewed and method

I reviewed only the commission's separately named interactive claim: one
reachable correct configured member suffices for online conflict-qualified
accepted-value non-conflict and no-conflict singleton progress when every
relying executor performs a fresh push/write-before-reply operation against
every configured member inside the rooted full round-trip bound, and correct
conflict state is atomic, durable, monotone, correctly scoped, and non-rollback.
The implemented predecessor/order, reconfiguration/recovery, executor, and T10
composition were part of the subject.

I read the accepted ADRs 0048 and 0050, action plan, complete implementation
ledger, all three QUV specifications, theorem/local evidence, both QUV TLA+
proofs, T10 model, R4 model/results, production types/member/verifier/network/PQ
and scheduling paths, effect executor/register, handoff/recovery/ceremony paths,
process fixtures, full M16Q runner, and every retained M16Q command/log/hash. I
verified all 12 retained source hashes and all 36 retained artifact hashes by
content. I traced each authorizing input through the process-local continuation
into T10 and separately inspected audit/receipt/operator/boundary-QC paths for
authority laundering.

I then:

- ran the complete, non-quick M16Q runner from the immutable checkout;
- independently reran both QUV TLAPS proof modules and the T10 TLC kernel;
- wrote a Python spec-only twin from the prose algorithm and assumptions,
  without production imports or translation of the Rust decision code;
- exhaustively enumerated its documented finite bounds and negative witnesses;
- created two additional isolated exact-tag clones containing minimized Rust
  regressions for the implementation counterexamples; and
- compared new phase results, observations, environment, and hashes with the
  retained commissioning run.

## 4. Findings

### QUV-M17Q-001 — CRITICAL — candidate-selected predecessor forks the conflict namespace

Category: production implementation / theorem-assumption enforcement.

Affected evidence:

- `crates/types/src/app/query_unanimity.rs:32-50`: `QuvSlotV0` derives `Ord`
  and contains the predecessor.
- `crates/consensus/src/aft/query_unanimity.rs:410-417,791-820`: the member
  store is a `BTreeMap<QuvSlotV0, ...>` and indexes reads/writes by the entire
  candidate-selected slot.
- `crates/consensus/src/aft/query_unanimity.rs:353-381`: rooted candidate
  validation checks only that predecessor is nonzero; it does not derive or
  compare one expected durable predecessor.
- `crates/validator/src/standard/orchestration/mod.rs:438-449` and
  `crates/validator/src/standard/orchestration/grpc_public.rs:183-195`: both
  irreversible-effect entry points bind payload/configuration/policy/domain and
  numeric slot, but omit predecessor and authority mode.
- `crates/agentgres/src/consequence.rs:1212-1235`: the durable online
  authorization requirement has no predecessor.
- `crates/agentgres/src/consequence.rs:461-469` and
  `crates/types/src/app/consequence.rs:303-315`: QUV derives the same
  domain/slot idempotency string, but the actual register path additionally
  namespaces it by independently chosen `resource_id`, so two conflicting
  manifests can cause two physical mutations.
- `crates/cli/tests/aft_e2e.rs:180-208,1610-1629`: the M16 conflict fixture
  uses one hard-coded predecessor for both candidates and therefore misses the
  fork; its two resources are distinct.

Minimized trace:

```text
Given one configuration C, policy P, network N, conflict domain D, numeric
slot 7, and at least one correct member H:
1. Byzantine rooted authorizer A signs candidate X for (C,P,N,D,7,PX).
2. Byzantine rooted authorizer B signs conflicting candidate Y for
   (C,P,N,D,7,PY), PX != PY, both nonzero.
3. Every correct member durably inserts X under map key (...,PX), observes no Y
   there, and returns singleton [X].
4. Every correct member durably inserts Y under map key (...,PY), observes no X
   there, and returns singleton [Y].
5. EX and EY each receive every correct timely reply. Exact reply binding
   succeeds because each reply matches its own candidate-selected predecessor.
6. Both fresh operations return process-local authorization. With distinct
   resource IDs, T10 uses distinct physical register paths and both mutations
   can execute.
```

Exact reproduction:

```sh
cd /tmp/ioi-m17q-repro.Bitdwf/repro-clone
cargo test -p ioi-consensus --features aft \
  repro_distinct_predecessors_split_one_numeric_slot_and_both_accept \
  --lib -- --nocapture
```

Result: `REPRO_RESULT_PENDING`.

Violated claim/assumption: fixed claim's implemented predecessor/order
composition; Q-EA1, Q-EA2, Q-E2/Q-E3; the specification's statement that
cross-predecessor replay is load-bearing. This counterexample includes every
correct member's timely durable reply; it is not a timing or omission attack.

Required remediation: derive and enforce the one exact expected predecessor
from durable per-domain history before member insertion and before executor
authorization. The conflict-knowledge key must not let a candidate split one
logical configured domain/numeric slot: exclude predecessor from conflict
identity while retaining it in the signed candidate. Extend the Agentgres
requirement and both entry points to bind that signed predecessor and authority
mode to the exact durable manifest and expected per-domain head. Add
owned/unowned, all-correct-placement, opposite-order, process, restart, and
distinct-resource regressions in which different predecessor hashes cannot
both authorize or mutate.

### QUV-M17Q-002 — CRITICAL — unauthenticated generation+1 state is blessed as recovery authority

Category: production implementation / recovery / authority synthesis.

Affected evidence:

- `crates/consensus/src/aft/query_unanimity.rs:410-425,448-464`: ordinary
  member and handoff state carry generation/previous-head but no custody-key
  MAC or authenticated transition record.
- `crates/consensus/src/aft/query_unanimity.rs:518-530,746-760`: `open()`
  accepts any structurally valid state at `anchor.generation + 1` whose
  `previous_head` equals the old authenticated head, computes its unkeyed head,
  and advances the authenticated anchor to it.
- `crates/consensus/src/aft/query_unanimity.rs:1242-1286,1293-1309,1331-1383`:
  structural validation does not prove the transition was locally authorized;
  state heads are unkeyed, while the old anchor tag authenticates only the old
  generation/head.
- `crates/consensus/src/aft/query_unanimity.rs:667-699` and
  `crates/validator/src/standard/orchestration/lifecycle.rs:1136-1155`: a
  blessed forged handoff state satisfies the exact activation gate used to
  restore successor authority.
- `internal-docs/architecture/protocols/aft/evidence/m15q-quv-live-handoff-foundation-2026-09-04.md:28-35`
  says ordinary bytes cannot create the separately authenticated monotone gate;
  the implementation contradicts that claim.

Minimized member-state trace:

```text
1. Correct member at generation g durably records X and EX accepts X.
2. Its separately protected anchor authenticates (g,H).
3. An actor able to write/restore only the ordinary state file writes canonical
   generation g+1, previous_head=H, and an empty slot map. It never learns the
   custody key and never changes the old anchor.
4. Restart treats the file as the narrow crash window and writes a valid anchor
   for the attacker-chosen state.
5. The member records Y into the now-empty namespace and returns singleton
   [Y]; EY accepts Y. Correct conflict knowledge has rolled back.
```

Minimized handoff trace:

```text
1. A genuine generation-0 empty handoff store and authenticated anchor exist.
2. From public, structurally valid handoff/envelope fields, write an ordinary
   generation-1 state with previous_head equal to the protected generation-0
   head and `installed=Some(attacker_selected_valid_gate)`.
3. `open()` authenticates only the old anchor, computes the unkeyed new head,
   advances the anchor, and returns the forged installed state.
4. `permits_exact_activation` returns true; lifecycle recovery treats the local
   gate as authority without any live QUV operation or custody-key MAC over the
   transition.
```

Exact reproductions:

```sh
cd /tmp/ioi-m17q-repro.Bitdwf/repro-clone
cargo test -p ioi-consensus --features aft \
  repro_unauthenticated_one_generation_ahead_state_erases_conflict \
  --lib -- --nocapture
cargo test -p ioi-consensus --features aft \
  repro_unauthenticated_one_generation_ahead_handoff_mints_activation_gate \
  --lib -- --nocapture
```

Results: `REPRO_RESULTS_PENDING`.

Violated claim/assumption: Q-A5, Q-EA3, Q-EA7 and the no-authority-from-bytes
boundary. This is stronger than restoring an old clonable image: the protected
old anchor becomes an oracle that authenticates attacker-selected future state.
The baseline names crash-consistent local storage, not arbitrary host
compromise (`specs/maximal_consensus_task.md:159-168`). Severity is nevertheless
critical for this candidate's advertised separated-anchor boundary: the code
explicitly treats the ordinary state as clonable and says that it is
insufficient without the protected anchor. If ordinary-state integrity is
instead intended as a stronger external premise, it must be explicitly rooted,
charged, and reflected in the claims; it cannot coexist with the current
rollback-authentication wording.

Required remediation: authenticate the exact pending next-state bytes/head
before ordinary-state rename, for example with a domain-separated custody-key
MAC in an
independently durable pending-transition journal, and advance only that exact
record on recovery. Equivalently, MAC every state generation with the protected
key over store kind/schema/generation/previous-head/all contents and verify it
before blessing it. Reusing the existing anchor-tag construction closes this
logical forgery only under the same unforgeability assumption; a standard
HMAC/KMAC is preferable to an ad hoc keyed hash. Merely matching
`previous_head` is insufficient. Add mutations of every generation+1 field,
both stores, erased and invented contents, restart, and complete process
activation; all must fail without an authentic pending transition while the
genuine crash window passes.

### QUV-M17Q-003 — HIGH — replies observed after the decision deadline can mint authorization

Category: production implementation / timing boundary.

Affected evidence:

- `crates/consensus/src/aft/query_unanimity.rs:932-942`: `observe_reply`
  records elapsed time but never rejects a reply after `decision_interval`.
- `crates/consensus/src/aft/query_unanimity.rs:961-985`: `finish_at` requires
  only that finalization occurs after the interval; it validates every retained
  reply without `reply_elapsed <= decision_interval`.
- `crates/consensus/src/aft/query_unanimity.rs:1167-1186`: audit verification
  checks reply time only against observed finalization time, not the rooted
  decision interval.
- `crates/validator/src/standard/orchestration/quv.rs:1699-1703,1883-1887`:
  the asynchronous timer can wake and finalize late, leaving a scheduling
  window in which a post-deadline reply is admitted.
- `internal-docs/architecture/protocols/aft/specs/query_unanimity_verification.md:158-160,173-174,229-230`
  limits eligible replies to those received by the full rooted deadline.

Minimized trace:

```text
1. Start an operation with decision_interval=1 ms and receive no eligible
   reply by that deadline.
2. At more than 20 ms, call observe_reply with an otherwise valid signed
   singleton response.
3. Call finish_at with elapsed >= 20 ms.
4. The candidate returns a consumable QuvOnlineAuthorizationV0, and the audit
   verifier accepts evidence whose reply_elapsed exceeds decision_interval.
```

Exact reproduction:

```sh
cd /tmp/ioi-m17q-repro.Bitdwf/repro-clone
cargo test -p ioi-consensus --features aft \
  repro_reply_observed_after_deadline_still_mints_authorization \
  --lib -- --nocapture
```

Result: `REPRO_RESULT_PENDING`.

Violated claim/assumption: rooted decision-interval semantics and the exact
timing context in Q-A3/Q-A8. A late answer is not evidence that the required
online fact held at the rooted cutoff.

Required remediation: freeze or close reply admission at the exact monotonic
deadline and independently filter `reply_elapsed <= decision_interval` during
finalization. Audit verification must reject any admitted reply after the
decision interval. Add boundary tests just below/equal/above the cutoff and a
delayed-runtime timer test; above-deadline-only input must return
`NoValidReplies` and must never produce an authorization.

### QUV-M17Q-004 — HIGH — M16Q does not establish its stated Q-A3/Q-A9 and conflict campaign coverage

Category: test/evidence gap.

Affected evidence:

- `crates/cli/tests/aft_e2e.rs:211-254`: the receipt helper returns the maximum
  over whichever nonempty valid replies happen to exist; it never checks exact
  configured membership, count, member identity, or that every correct reply
  is present by the deadline.
- `crates/cli/tests/aft_e2e.rs:1745-1794`: saturation is four one-shot
  executor operations and again checks only an unspecified nonempty subset of
  member replies.
- `crates/cli/tests/aft_e2e.rs:1823-1850`: the conflict campaign counts only
  successful RPCs and accepts any errors. `accepts=0` therefore passes
  vacuously if both paths fail for infrastructure reasons; it does not require
  typed `ConflictDisclosed` or verify absence of resource records.
- `internal-docs/architecture/protocols/aft/AFT_M15Q_M18Q_COMPLETION_GOAL_PROMPT.md:70-80`
  requires deadline-edge, missing-reply, one-way, pre-durable, rollback,
  split-atomicity, replay, cross-context, stale-session, queue-flood and crash
  mutations. The 15-phase runner has no production/process phase that executes
  this complete matrix.
- `internal-docs/architecture/protocols/aft/evidence/m16q-quv-qualification-2026-09-04.md:56-72`
  nevertheless says the measurements qualify production timing,
  reachability, durability, configuration, and executor revalidation.

Reproduction/inspection:

```sh
sed -n '211,254p;1745,1850p' crates/cli/tests/aft_e2e.rs
sed -n '108,140p' .github/scripts/run_aft_m16q_qualification.sh
rg -n 'one-way|reply-before|split|stale|missing correct|rollback' \
  internal-docs/architecture/protocols/aft/evidence/m16q-runs/\
20260904T204403Z-ab8d2e58103a/*.command.txt
```

The first two commands expose the permissive assertions; the final search does
not identify the promised production/process mutation phases. The R4 abstract
model does contain several assumption-removal mutations, but is not a test of
the production scheduler, persistence, routing, or executor.

Violated claim/assumption: the M16Q acceptance criterion and evidentiary support
for Q-A3/Q-A9. This gap also allowed QUV-M17Q-001 through QUV-M17Q-003 to survive
the nominal full campaign.

Required remediation: make each process receipt assert the exact expected
configured correct-member set and per-member deadline, require explicit typed
conflict outcomes, and inspect both consequence stores/resources for zero
conflicting mutations. Implement and retain the complete requested mutation
matrix against production paths, including deadline edges and timer delay,
different predecessors, unauthenticated generation+1 state/handoff, sustained
serial flood, restart, and unrelated-domain progress.

### QUV-M17Q-005 — HIGH — the composition proof is a conditional set lift, not a mechanized runtime refinement

Category: proof/evidence wording.

Affected evidence:

- `internal-docs/architecture/protocols/aft/formal/maximal_visibility/QueryUnanimityCompositionProof.tla:14-25`
  assumes accepted-value uniqueness, assumes every history position is already
  accepted, and assumes every mutation is already accepted.
- The two conclusions at lines 27-56 are direct pointwise consequences of
  those assumptions. The module has no state or transition for configuration,
  policy, domain, predecessor, durable head/recovery, live handoff, process-local
  continuation, stable resource key, or external register.
- `.github/scripts/run_aft_m16q_qualification.sh:110` runs
  `run_aft_formal_checks.sh --quv-only`; that branch runs only the Python R4
  model and exits (`run_aft_formal_checks.sh:170-200`). The actual two-module
  TLAPS branch is `--quv-theorem-only` at lines 358-361, and the runner does not
  run T10 TLC.
- `internal-docs/architecture/protocols/aft/specs/query_unanimity_end_to_end_theorems.md:48-50,62,105-112`
  and the ledger describe the results as mechanized composition.

Independent reproduction:

```sh
bash .github/scripts/run_aft_formal_checks.sh --quv-theorem-only
# PASS: QueryUnanimityProof 75 obligations; composition proof 16 obligations

java -cp /tmp/tla2tools.jar tlc2.TLC -cleanup \
  -config AtMostOnceExternalization.cfg AtMostOnceExternalization.tla
# PASS: 66 generated / 42 distinct states, depth 8
```

The exact logs and hashes are retained with this report. The proofs pass; the
finding is their claim boundary, not a failed TLAPS obligation.

Violated claim/assumption: no abstract theorem is disproved. The defect is that
the claimed end-to-end mechanization does not itself validate Q-EA1 through
Q-EA8 or the implementation refinement, while the nominal M16 formal phase
does not execute even this narrow proof/T10 kernel.

Required remediation: describe this module precisely as a conditional
accepted-set lifting lemma, and add a transition/refinement model (or
equivalent machine-checked proof) that includes predecessor admission, durable
head/recovery, executor consumption, handoff, and stable-key externalization.
Make the qualification runner execute the TLAPS modules and T10 model whose
PASS it cites.

### QUV-M17Q-006 — HIGH — serial authenticated traffic exhausts the persistent whole-store timing envelope

Category: deployment assumption / production resource control / qualification.

Affected evidence:

- `crates/consensus/src/aft/query_unanimity.rs:25-29`: the only persistent
  ceilings are 512 MiB, one million slot keys, and 4096 candidates per slot.
- `crates/consensus/src/aft/query_unanimity.rs:353-381`: any nonzero numeric
  slot/domain/predecessor with a valid rooted signature is admitted; no expected
  next slot, lifetime, or request-rate bound is enforced.
- `crates/validator/src/standard/orchestration/quv.rs:1348-1367,1371-1468`:
  all domains share one store/mutex; the per-account control limits concurrent
  work only and is removed after each request, so a Byzantine rooted member can
  submit an unbounded serial sequence.
- `crates/consensus/src/aft/query_unanimity.rs:790-832,1386-1440`: every new
  candidate clones the complete map, canonical-encodes/hashes it, rewrites and
  fsyncs the complete state file, then rewrites/fsyncs the anchor. Work and
  bytes therefore grow with all historical traffic, with quadratic cumulative
  write amplification.
- `crates/consensus/src/aft/query_unanimity.rs:1391-1397`: the 512-MiB check is
  performed only while reopening; no pre-write encoded-size check prevents an
  oversized final write, after which restart deterministically refuses.
- `crates/types/src/config/mod.rs:1203-1223,1346-1390`: the rooted deployment
  policy can express timing, membership, and continuation limits, but no
  request rate, retained-slot lifetime, persistent-byte headroom, or safe
  compaction envelope.
- `crates/consensus/src/aft/query_unanimity.rs:1664-1733` benchmarks only 256
  growing entries; `aft_e2e.rs:1745-1794` sends four one-shot operations.

Minimized operational trace:

```text
1. A rooted Byzantine member/owner serially submits correctly signed,
   independently valid candidates at fresh nonzero domain/slot keys.
2. The one-inflight gate accepts the next request after each prior fsync.
3. The global store grows monotonically; each later request copies, hashes,
   encodes, writes and fsyncs the entire prefix under the one global mutex.
4. Before the nominal entry ceiling, processing exceeds the rooted delta_rt;
   a correct singleton request in an unrelated domain misses Q-A3.
5. Continued traffic crosses 512 MiB because no pre-write check exists. A
   restart then refuses the store with StoreCapacityExceeded, violating
   retained/reachable correct knowledge and all-domain availability.
```

This is a bounded-resource failure, not an arbitrary throughput claim. The
exact threshold depends on serialized candidate size, disk, and rooted
`delta_rt`, which is why it must be measured and rooted. The current schema
cannot state it and M16Q did not measure it.

Violated claim/assumption: Q-A3, Q-A5 retention/reachability and Q-A9 under
Byzantine authenticated query traffic; the M16Q deployment-envelope claim.

Required remediation: enforce durable expected-next-slot admission; add rooted
per-identity/domain and lifetime quotas; use an incremental authenticated
WAL/index rather than whole-store rewrites; reject before exceeding a rooted
persistent byte/headroom limit; and design root-bound safe retention/compaction
that preserves all authority-lifetime conflict knowledge. Qualify sustained
serial Byzantine flood concurrently with unrelated correct requests and
restart at high-water mark, not merely four simultaneous operations.

### QUV-M17Q-007 — HIGH — unauthenticated status identity squatting captures a correct member's PQ carrier

Category: production networking/admission / Q-A2, Q-A3 and Q-A9 enforcement.

Affected evidence:

- `crates/validator/src/standard/orchestration/sync.rs:529-568`: after checking
  only chain ID and genesis root, status handling trusts the response's
  `validator_account_id`, inserts `peer -> claimed account`, looks up that
  account's rooted ML-DSA key hash, and commands PQ enrollment. The carrier has
  not yet proved possession of that account's key.
- `crates/networking/src/libp2p/pq_channel.rs:455-485`: enrollment is committed
  before the PQ handshake. The first carrier for an account wins; a second
  carrier is refused. The existing unit test at lines 1406-1425 explicitly
  codifies this first-wins behavior.
- `crates/networking/src/libp2p/pq_channel.rs:769-773`: later QUV routing resolves
  an account through that enrollment map.
- `crates/networking/src/libp2p/pq_channel.rs:855-859` and
  `crates/networking/src/libp2p/swarm.rs:687-696,1027-1040`: connection or
  handshake failure clears only pending/session state; it does not remove the
  enrollment. Validator-side connection close removes a separate
  `peer_accounts_ref` entry only
  (`crates/validator/src/standard/orchestration/peer_management.rs:47-74`).
- `crates/networking/src/libp2p/swarm.rs:1457-1485`: when the genuine carrier's
  later enrollment is refused, the error is only logged; no proof-based
  replacement occurs.

Minimized trace:

```text
Given sole correct rooted account C and Byzantine rooted account B:
1. B connects first under its authenticated libp2p carrier PeerB, but sends a
   chain/genesis-correct status response whose account field claims C.
2. The validator commands enrollment (PeerB,C,key_hash_C). The manager stores
   it before a PQ handshake proves C's ML-DSA key.
3. B cannot finish that handshake. Failure/disconnect clears transient session
   state but leaves the enrollment.
4. Genuine PeerC connects, reports C, and is refused because C is already
   assigned to PeerB.
5. `peer_for_account(C)` continues to return PeerB. Fresh QUV requests for C
   never reach PeerC, excluding the only correct reply indefinitely.
```

Exact focused reproduction:

```sh
cd /tmp/ioi-m17q-network-repro.DMcOfy/repro-clone
cargo test -p ioi-networking \
  repro_status_claimed_account_carrier_squat_survives_disconnect \
  --lib -- --nocapture
```

Result: `REPRO_RESULT_PENDING`.

Violated claim/assumption: production enforcement of Q-A2/Q-A3 and Q-A9 and
no-conflict singleton progress at `f=n-1`. The attacker need not forge C's
ML-DSA signature; failure to do so is exactly what leaves the permanent
unproven reservation. Known synchrony between correct endpoints does not
authenticate this earlier account-to-carrier claim.

Required remediation: treat status account fields as provisional routing hints
only. Bind and commit `account <-> carrier` after the strict-PQ handshake proves
possession of the rooted ML-DSA key and the transcript binds the libp2p carrier,
configuration, and network. Expire/remove every failed unproven mapping and
allow a successfully proven carrier to replace an unproven claim. Add
attacker-first, disconnect, retry, simultaneous genuine carrier, handoff-only,
and sole-correct process regressions.

### QUV-M17Q-008 — HIGH — cached `Authorized` state bypasses the live execution-height fence

Category: production executor / authorization lifetime.

Affected evidence:

- `crates/validator/src/standard/orchestration/grpc_public.rs:144-182` and
  `crates/validator/src/standard/orchestration/mod.rs:405-437`: current height
  and manifest fence are checked through `authorize(...)` only when no receipt
  file exists. Any cached receipt makes `contains(effect_id)` true and skips
  the only live-height check.
- `crates/agentgres/src/consequence.rs:769-829,1120-1151`: `contains` is file
  existence; `validate_fence` is called only by `authorize`.
- `crates/agentgres/src/consequence.rs:867-940`: the requirement, fresh online
  authorization consumption, `Claimed`, `InFlight`, and external invocation
  paths have no current-height/configuration input and do not recheck the
  manifest fence.
- `crates/types/src/app/consequence.rs:143-164`: the fence is expressly the
  permitted height range / last height at which execution may be claimed.

Minimized trace:

```text
1. At height h inside [minimum,maximum], call the effect endpoint. It persists
   an Authorized receipt after validate_fence.
2. Let that attempt fail/abort before QUV returns and before Claimed.
3. Advance canonical height beyond maximum without changing the still usable
   QUV root/policy.
4. Retry the same effect. Receipt existence skips authorize/validate_fence.
5. The executor performs fresh QUV, consumes the live token, persists Claimed
   and InFlight, and calls the resource after the manifest expired.
```

Violated claim/assumption: Q-EA4's immediate correctly scoped authorization,
the manifest's authorization fence, and the executor-to-T10 claim boundary.
Fresh QUV does not extend a separately committed effect fence.

Required remediation: re-read live canonical height/configuration and re-run
the exact fence/manifest/root checks inside the same locked transition that
persists `Claimed`. A lingering `Authorized` receipt must become terminally
expired on a fence/configuration transition, not remain executable. Add
inside-bound, cached-then-expired, restart, and root-transition tests for both
production entry points.

### QUV-M17Q-009 — HIGH — continuation expiry is checked before, not at, the durable claim

Category: production executor / process-local token lifetime.

Affected evidence:

- `crates/consensus/src/aft/query_unanimity.rs:863-872,1067-1090`:
  `QuvOnlineAuthorizationV0` carries `expires_at`; `consume()` checks
  `Instant::now()` once and returns a consumed object that no longer carries
  the deadline.
- `crates/agentgres/src/consequence.rs:869-886`: after consumption, Agentgres
  validates and persists the potentially large audit/receipt.
- `crates/agentgres/src/consequence.rs:904-940`: only afterward does it persist
  `Claimed` and `InFlight`, with no remaining deadline check.
- `crates/types/src/config/mod.rs:1222-1223,1365-1375`: `continuation_millis` is
  the maximum delay from successful QUV to effect claim, but configuration
  permits any nonzero value, including one millisecond.

Minimized trace:

```text
1. QUV returns a token whose absolute continuation expiry is near.
2. `consume()` runs just before expiry and discards the deadline.
3. Receipt/audit validation, canonical serialization, fsync, scheduler delay,
   or process suspension crosses expiry.
4. Agentgres persists `Claimed` and invokes the resource after the rooted
   continuation interval, because no claim-time check remains.
```

Violated claim/assumption: Q-A6/Q-EA4 and the configured maximum
QUV-to-claim continuation. A pre-claim pause is not bounded merely because a
prior instruction sampled the clock.

Required remediation: carry the absolute monotonic deadline in the consumed
authorization and recheck it immediately within the transition that persists
`Claimed`; preferably combine consume/audit installation/claim under one
deadline-checked store lock. Add deterministic clock-injected tests for
before/equal/after expiry and delay between consumption and claim.

### QUV-M17Q-010 — HIGH — terminal receipt replay monopolizes the one global QUV operation

Category: production resource admission / cross-domain liveness.

Affected evidence:

- `crates/agentgres/src/consequence.rs:769-773,892-902`: receipt existence and
  `online_authorization_requirement` do not require a claimable receipt phase.
- `crates/validator/src/standard/orchestration/grpc_public.rs:167-212` and
  `crates/validator/src/standard/orchestration/mod.rs:405-468`: both entry
  points launch a fresh full-deadline QUV operation before asking Agentgres
  whether the receipt is `Authorized`, `Claimed`, `Executed`, or `Unknown`.
- `crates/agentgres/src/consequence.rs:904-940`: terminal/ambiguous phase is
  rejected only after QUV completes.
- `crates/validator/src/standard/orchestration/quv.rs:1596-1605,1699-1703`: one
  executor operation is allowed globally per process and occupies the slot
  through the full rooted interval.

Minimized trace:

```text
1. Keep a valid candidate for effect E after E's receipt reaches Executed (or
   another phase that cannot enter Claimed).
2. Repeatedly call the public E endpoint. Each request passes the loose receipt
   requirement and occupies the only global QUV operation for delta_rt.
3. Agentgres rejects WrongState only after that wait.
4. Legitimate operations in unrelated domains repeatedly encounter the global
   one-operation gate and fail or starve.
```

Violated claim/assumption: Q-A9 and unrelated-domain liveness/isolation. The
candidate can be replayed by any Byzantine rooted authorizer; no cached QUV
authorization is required.

Required remediation: atomically inspect and reserve an exactly claimable
receipt phase before starting QUV; reject terminal/ambiguous receipts
immediately. Add bounded fair per-principal/domain scheduling and rate control
so one caller/domain cannot monopolize the global verifier. Qualify terminal
replay concurrently with an unrelated singleton operation.

### QUV-M17Q-011 — HIGH — one silent recipient permanently fills the durable QUV outbox

Category: production network persistence / lifetime capacity.

Affected evidence:

- `crates/networking/src/libp2p/pq_channel.rs:27-39,263-320`: each recipient
  gets 1024 normal plus two reserved QUV entries; each nonce-bearing request
  hashes to a distinct message ID; enqueue permanently refuses after the cap.
- `crates/networking/src/libp2p/pq_channel.rs:337-383`: ACK removes a record,
  while the only explicit retirement API is for hash-asynchronous instances,
  not completed/aborted QUV operations.
- `crates/networking/src/libp2p/swarm.rs:438-441`: completing a QUV operation
  clears transient reply admission only; it does not retire durable request or
  reply records.
- `crates/validator/src/standard/orchestration/quv.rs:1712-1761`: the verifier
  durably queues each remote sequentially, aborts on any enqueue error, and
  performs local correct-member delivery only after remote admission.

Minimized trace:

```text
1. One configured Byzantine recipient is permanently silent and never ACKs.
2. Each otherwise valid operation adds a fresh nonce-bearing request to its
   durable outbox. Completion/abort does not retire the obsolete record.
3. After the finite per-recipient cap (or after two QUV entries if 1024 normal
   records already exist), enqueue for that Byzantine account returns full.
4. Every later operation aborts before local self-delivery or other progress;
   the sole correct member cannot enable singleton progress.
```

Violated claim/assumption: sustainable Q-A2/Q-A3/Q-A9 enforcement for allowed
Byzantine silence. A finite queue is necessary but is not a lifetime bound or
safe QUV message lifecycle.

Required remediation: introduce operation-aware, crash-safe expiry/retirement
for obsolete QUV request/reply records, or a send/admission design in which one
silent Byzantine recipient cannot prevent correct-member push. Root the
authority lifetime/capacity policy and qualify through saturation, abort,
restart, retirement, and later correct singleton progress.

### QUV-M17Q-012 — HIGH — stale QUV records consume and ACK-drop the current correct message

Category: production network replay/recovery / Q-A3 enforcement.

Affected evidence:

- `crates/networking/src/libp2p/swarm.rs:281-323`: after authenticated decryption
  and sequence advance, QUV admission inserts only the account into a current
  push/reply in-flight set before inspecting the operation nonce. A duplicate
  account record is dropped but returns `Ok(())`.
- `crates/networking/src/libp2p/swarm.rs:876-897,979-999` and
  `crates/networking/src/libp2p/pq_channel.rs:337-350`: `Ok(())` is transport
  ACKed; the sender then durably deletes that exact record and flushes the next.
- `crates/validator/src/standard/orchestration/quv.rs:1558-1565`: application
  semantic nonce lookup happens later; a stale reply is rejected only after it
  has consumed the member's current transport lane.
- There is no completed-operation QUV outbox retirement (011).

Minimized reply trace:

```text
1. A correct member's reply for old nonce N0 remains durable after a prior
   crash/no-ACK episode.
2. During a new operation N1, the stale N0 reply arrives first, occupies that
   member's reply lane, is ACKed, and is then rejected by the application
   because N0 is not live.
3. The queued current N1 reply arrives next. It is classified as a duplicate
   account, dropped with Ok, and ACKed/deleted at the correct sender.
4. The new operation lacks the sole correct member's reply. The symmetric stale
   request schedule can consume the requester lane before current work.
```

Violated claim/assumption: Q-A3, Q-A8's operation-scoped first response, and
crash/replay robustness. "First" must mean first authenticated response for the
exact live operation, not the first arbitrary durable record from an account.

Required remediation: perform operation/nonce semantic admission before
consuming the current lane and before positive ACK. Explicitly retire stale
operations without occupying live admission; NACK/retry rather than ACK-delete
current duplicates that were not durably/semantically accepted. Add
old-reply/current-reply and old-push/current-push crash/reconnect tests proving
the current correct message is retained and delivered.

### QUV-M17Q-013 — CRITICAL — unkeyed consequence receipt substitutes an unadmitted manifest

Category: production authorization / durable-state authenticity.

Affected evidence:

- `crates/validator/src/standard/orchestration/grpc_public.rs:144-166` resolves
  the actual committed Agentgres admission, current height, runtime root, and
  resource profile.
- `crates/validator/src/standard/orchestration/grpc_public.rs:167-182` derives
  `AcceptedEffectAuthorizationV1` from that committed admission and calls
  `ConsequenceStore::authorize` only when no file already exists for the
  caller-supplied effect ID.
- `crates/validator/src/standard/orchestration/grpc_public.rs:183-212` derives
  the QUV binding from the stored receipt and executes with its fresh result;
  it never compares the existing receipt's manifest, manifest root, achieved
  guarantee root, or authorization root with the committed admission.
- `crates/validator/src/standard/orchestration/mod.rs:405-468` has the same
  existence bypass on the internal entry point. When a receipt exists, it does
  not even resolve the committed admission or compare the live resource profile
  with that admission before using the receipt-derived requirement.
- `crates/agentgres/src/consequence.rs:770-772,1072-1080` defines existence as
  a path check and loads a receipt by checking only that its embedded effect ID
  matches the filename input and that the receipt is internally valid.
- `crates/agentgres/src/consequence.rs:312-340,1367-1442,1541-1600` validates
  only self-consistency and plain domain-separated SHA-256 commitments. There
  is no custody-key MAC, independent anchor, or Agentgres-admission lookup.
- `crates/agentgres/src/consequence.rs:780-851` performs the real manifest,
  guarantee, fence, and accepted-authorization comparisons only while creating
  a receipt. The existence fast path bypasses all of them.
- `crates/agentgres/src/consequence.rs:869-940,1212-1235` validates and consumes
  a fresh online token against the substituted receipt's own binding, then
  invokes the resource with that receipt's manifest.

Minimized trace:

```text
1. Agentgres has admitted effect ID E with manifest M and guarantee/authority
   roots, but E has not legitimately reached ConsequenceStore::authorize.
2. An attacker able to restore, clone, or replace ordinary consequence-state
   bytes writes effects/SHA256(E).json as a canonical, internally consistent
   Authorized receipt for M'. M' retains E and the admitted resource profile
   but selects attacker-chosen request, predecessor, outcome, conflict domain,
   slot, and other effect fields; its authorization and achieved roots need
   only be nonzero and self-consistent.
3. The public executor resolves the real admission for E and confirms only that
   the live endpoint's profile matches M. Because the forged file exists, it
   skips `from_committed...` and `authorize`.
4. The executor derives its requirement from M'. A rooted signer permitted by
   M''s selected provisioned QUV policy supplies a valid candidate; the fresh
   online operation can correctly accept that exact candidate.
5. `execute_with_online_authorization` consumes the M'-bound token and invokes
   the sole external mutation owner with M'. Agentgres admitted M, not M'.
```

The exploit does not turn an audit transcript into a token and does not forge a
QUV signature. It lets self-authenticating receipt bytes replace the source of
truth that selects what the otherwise genuine fresh QUV operation authorizes.
It is therefore inside the commission's authorizing-byte, recovery, cached
assertion, and source-substitution questions. If ordinary consequence storage
is intended to have stronger integrity than the separately anchored QUV stores,
that is an unstated deployment assumption contradicted by the production
authorization census's claim that committed evidence is reverified.

Violated claim/assumption: Q-EA4's requirement that the irreversible executor
perform fresh QUV for the exact Agentgres-admitted candidate, T10's exact
stable-key externalization premise, and the fixed rule that receipt/audit bytes
never authorize. Fresh QUV occurs, but its candidate is selected by substituted
receipt bytes rather than the committed admission.

Required remediation: on every call, reconstruct and reverify the accepted
effect authorization from the current committed Agentgres admission before
using any receipt. Require exact equality of effect ID, complete manifest and
manifest root, achieved-guarantee root, authorization-receipt root, resource
contract, and live fence with the existing receipt before QUV and again before
the atomic claim. Independently authenticate/anchor consequence-state records
if ordinary-state replacement or rollback remains in scope. Add exact tests for
canonical self-consistent Authorized, Claimed, and terminal receipt
substitution, including a receipt with the same effect ID and resource profile
but a different request/domain/slot/predecessor/outcome; all must fail before
QUV and before resource invocation.

## 5. Theorem-assumption enforcement matrix

| Assumption | Enforcement/evidence | Review result |
|---|---|---|
| Q-A1 rooted candidate validity | configuration/policy/network roots; ML-DSA candidate and reply verification | QUV cryptographic validity is enforced, but an unkeyed stored receipt can substitute the manifest that selects the rooted QUV context (013) |
| Q-A2 send to every member | verifier enumerates the rooted member set; queue failure aborts | Carrier squatting can route the correct account to a Byzantine peer (007); a silent recipient can fill its outbox and abort all later sends (011); M16 receipts do not prove exact coverage |
| Q-A3 every correct reply by full rooted deadline | rooted `delta_rt`, deployment envelope, reserved lanes | Failed/unevidenced through late admission (003), incomplete assertions (004), unbounded persistent work (006), carrier exclusion (007), outbox exhaustion (011), and stale-record lane capture (012) |
| Q-A4 atomic durable monotone scoped state | one mutex, write/fsync/rename/directory fsync before signing | Transition ordering is sound, but candidate predecessor splits the key (001) |
| Q-A5 restart/non-rollback/lifetime reachability | separate custody-key anchor | Failed for unauthenticated generation+1 QUV recovery (002); consequence receipts have no comparable authentication (013); lifetime/resource retention is unqualified (006) |
| Q-A6 operation-local authorization | private Rust type, nonce, expiry, move into executor | Nonserializable and fresh, but expiry is discarded before durable claim (009) |
| Q-A7 rooted authority mode/policy | policy root and configured owner/mode | Enforced generically; executor manifest comparison should also bind mode/predecessor (001) |
| Q-A8 first authenticated response | first member identity retained and signature/binding checked | Eligibility is not closed at deadline (003); transport counts a stale-nonce record as the first current response (012) |
| Q-A9 Byzantine-load reservation | bounded network lanes, one in-flight push/account | Serial storage amplification (006), carrier squat (007), terminal replay (010), finite outbox exhaustion (011), and stale-lane capture (012) remain |
| Q-A10 fault assignment | static deployment/theorem premise | Explicit premise, not inferred from bytes |
| Q-EA1 exact ordered-candidate context | signed `QuvSlotV0` and manifest hash | Bytes bind predecessor, but no unique expected predecessor exists (001), and an existing unkeyed receipt can replace the admitted manifest that chooses the context (013) |
| Q-EA2 unique next-slot durable append | prose/entry-point checks | Failed: neither effect nor member derives next predecessor (001) |
| Q-EA3 restart from same head | state plus external anchor | Failed in generation+1 crash-window recognition (002) |
| Q-EA4 every executor performs fresh QUV | both production effect entry points call QUV then directly consume token | Fresh QUV occurs, but an existing receipt can substitute its candidate for the Agentgres-admitted manifest (013), cached receipt fence is not rechecked (008), and continuation can expire before claim (009) |
| Q-EA5 stable domain/slot key | manifest derives idempotency string from domain+slot | String is stable; endpoint register additionally namespaces resource ID, so it relies critically on Q-E2, which 001 defeats |
| Q-EA6 T10 atomic register | claim-before-call and lookup-only ambiguity recovery; independent TLC PASS | Conditional atomicity holds, but exact admitted input can be replaced before the register by 013 |
| Q-EA7 live old-root handoff | typed source, fresh QUV, local durable gate | Normal install path present; forged generation+1 gate can recreate authority (002) |
| Q-EA8 independently trusted current root | explicit bootstrap premise | Accurately stated; no historical-byte currentness claim found |

## 6. Authority and no-laundering trace

For a newly created ordinary effect, the durable Agentgres manifest produces an
exact online requirement. The public/internal executor compares the supplied
candidate, creates a fresh random nonce, starts a new network QUV operation,
waits through the rooted interval, and directly moves the resulting
non-serializable `QuvOnlineAuthorizationV0` into the consequence store. The
store rechecks payload/configuration/policy/domain/numeric-slot and continuation
expiry against its receipt before entering T10's durable state. The resulting
audit is serializable but is not itself an input to the mutation method. I found
no route from an audit transcript, operator ceremony record, boundary QC,
terminal seal, classic BFT, fallback, BLS, VDF, legacy profile, or Hypervisor
component into this normal QUV token.

That positive trace does not cure findings 001-003: the live operation itself
can return the wrong authorization. Finding 002's handoff case is not ordinary
audit-byte laundering; it is unauthenticated durable-state synthesis at the
recovery seam, after which lifecycle treats the forged local gate as authority.
Finding 013 is the distinct receipt path: substituted receipt bytes select the
manifest against which a new genuine token is requested and consumed. The bytes
do not become the opaque token, but they do select the mutation that token
authorizes. All paths must remain fail closed.

All inspected QUV network authority uses the protected typed channel and rooted
ML-DSA identities. No BLS, VDF, classic-BFT, hash-asynchronous fallback,
non-PQ transport, legacy compatibility, or Hypervisor dependency entered the
QUV theorem-bearing authorization path.

## 7. Mandatory complete reproduction

Exact command, run from detached immutable commit:

```sh
bash .github/scripts/run_aft_m16q_qualification.sh
```

New run directory:
`internal-docs/architecture/protocols/aft/evidence/m16q-runs/20260904T215026Z-24a9888e3b88/`.

Environment recorded by the runner:

```text
commit=24a9888e3b88383c18dfbfea0f2e7fa44b99fa64
tree_dirty=false
quick=false
started_utc=2026-09-04T21:50:26Z
Linux pop-os 6.17.9-76061709-generic x86_64
rustc 1.93.1 (01f6ddf75 2026-02-11)
cargo 1.93.1 (083ac5135 2025-12-15)
Python 3.12.3; Node v22.22.0; npm 10.9.4; 24 logical CPUs
```

Final result: `MANDATORY_RUN_RESULT_PENDING`.

`PHASE_TABLE_PENDING`

The retained commissioning run at code commit
`ab8d2e58103a2eef3e39c1c6042ffefd7d3c86f4` passed all 15 phases. The reviewed
candidate changes only documentation/evidence after that code commit. The new
run comparison, process observations, source/artifact hash verification, and
any timing differences are recorded in `REPRO_COMPARISON_PENDING`.

The full retained and new logs must be interpreted as regression evidence, not
proof that untested assumptions hold. A green runner cannot override the
reproduced counterexamples in findings 001-003, the missing sustained
persistent-load envelope in 006, the carrier-squatting trace in 007, or the
receipt-selected unadmitted manifest in 013.

## 8. Independent spec-only executable twin

Artifacts:

- `m17q_spec_twin.py`
- `m17q_spec_twin_results.json`
- `m17q_spec_twin.log`

Exact command:

```sh
cd /tmp/ioi-m17q-daybreak.u6nAwg/review-output
set -o pipefail
/usr/bin/time -v python3 m17q_spec_twin.py \
  --output m17q_spec_twin_results.json 2>&1 | tee m17q_spec_twin.log
```

Result:

```text
families=33
states_explored=8348
sound_conflicting_accepts=0
sound_liveness_failures=0
negative_mutations_witnessed=25
```

The positive exploration covers every nonempty correct-member placement for
`n=2..5` with concurrent X/Y candidates; every product of correct-member XY/YX
serialization orders; Byzantine omission/support/valid-conflict injection;
owned and unowned predicates; singleton progress for `n=2..6`; discrete
deadline component/skew edges; write/reply/crash ordering; every exact context
binding; disjoint/overlapping reconfiguration for old/new `n=2..4`; unrelated
domains; and T10 crash points/duplicate attempts.

The negative witnesses cover absent correct reply, one-way-only timing, late
reply, reply-before-durable, rollback, unauthenticated generation+1 recovery,
split atomicity, missing domain/slot/root/configuration/candidate binding,
predecessor namespace split, cached/portable acceptance, skipped executor QUV,
stale handoff, domain coupling, persistent store growth, and call-before-claim.
The additional implementation-review mutations cover cached fence bypass,
consume-before-claim expiry, terminal-receipt verifier monopolization, silent
recipient outbox exhaustion, and stale-record lane capture. Every negative
family records a minimized conflict, liveness, binding, or physical-duplication
trace in the raw JSON. The final source-review mutation also demonstrates that
a self-consistent unkeyed consequence receipt can substitute an unadmitted
manifest before a genuine QUV operation (013).

This is finite exploration only. It is not an arbitrary-`n` proof, a network
implementation test, or evidence for unmodeled scheduling/storage bounds. The
arbitrary-set theorem remains the separate TLAPS artifact, with the
mechanization-scope limitation in finding 005.

## 9. Required adversarial-question answers

1. **Every correct timely reply?** The algorithm intends this, but the evidence
   does not assert exact membership (004), late replies enter (003), persistent
   work defeats the bound (006), a carrier can be squatted (007), a silent
   outbox can fill (011), and stale records can capture the live lane (012).
2. **Persistence before reply?** Normal transitions fsync state, rename, fsync
   parent, then similarly persist the anchor before signing. Generation+1
   recovery authenticates no pending transition and is exploitable (002).
3. **Opposite correct orders?** The abstract predicates remain safe when both
   replies share one exact slot. Candidate-selected predecessors split that
   slot before serialization (001).
4. **Exact binding?** Signatures bind all `QuvSlotV0` fields and nonce, but the
   executor lacks an independently derived predecessor/authority-mode
   requirement (001), and timing eligibility is not exact (003).
5. **Replay/source substitution?** Canonical encodings, signatures, nonce, and
   normal handoff source checks reject direct reply reinterpretation. An
   unauthenticated future state synthesizes durable authority (002), and an
   unkeyed consequence receipt substitutes an unadmitted manifest (013);
   terminal effect replay and stale transport records still consume live
   resources or current reply admission (010, 012).
6. **Byzantine starvation?** Concurrent lanes are bounded; authenticated serial
   storage is not (006), unproven carriers divert accounts (007), terminal
   effect replay monopolizes the verifier (010), and silent outboxes fill (011).
7. **Fresh executor QUV?** Yes on both inspected irreversible entry points;
   audit/receipt bytes are not tokens. Cached `Authorized` state nevertheless
   skips its live fence and token expiry is not checked at claim (008-009).
8. **Other bytes authorize?** Yes. An audit or serialized QUV result does not
   become the opaque token, but a self-consistent existing consequence receipt
   suppresses committed authorization and selects the manifest for a new
   genuine token (013). The forged recovery state in 002 is another distinct
   critical violation.
9. **Recovery authority/fork?** Yes: unauthenticated generation+1 state can
   erase member knowledge or mint a handoff gate (002).
10. **Reconfiguration roots?** Normal disjoint/overlap live paths and exact
    boundary checks are present; the durable gate's recovery authenticity is
    defeated by 002. Long-range bootstrap still requires independent trust.
11. **Domain isolation?** Logical keys isolate ordinary conflicts, but global
    store/verifier resources allow cross-domain starvation (006, 010-011).
12. **T10?** The modeled claim-before-call/lookup-only path passed independent
    TLC. Its same-conflict guarantee relies on Q-E2, defeated by 001; distinct
    resources yield distinct registers. Fence and continuation lifetime are not
    rechecked at `Claimed` (008-009), and substituted receipt state can replace
    the admitted manifest before T10 (013).
13. **Legacy/non-PQ dependency?** None found in the QUV authorization path.
14. **Agreement among code/proof/model/test/wording?** No: findings 001-013
    identify predecessor, recovery, timing, coverage, mechanization, and
    deployment-envelope disagreements.
15. **Overbroad words?** Public-facing boundaries largely preserve online-only
    and nonportable scope. The M16 qualification and mechanization wording are
    broader than their actual evidence (004-005).

## 10. Required repair and re-review gate

M17Q must remain open. Repair all CRITICAL/HIGH findings without weakening the
fixed claim or turning an assumption failure into a portable assertion. At
minimum, a new immutable candidate must include:

1. one independently derived durable predecessor for every configured
   domain/numeric slot and no candidate-selected namespace split;
2. authenticated exact pending transitions for both state stores, with all
   forged generation+1 mutations refused;
3. hard reply-admission closure and audit validation at the rooted deadline;
4. explicit, rooted lifetime/storage/rate/headroom limits and an incremental
   persistence design that remains within the measured envelope under sustained
   serial Byzantine traffic;
5. proof-after-handshake PQ carrier enrollment with eviction/replacement of
   failed unproven status claims;
6. live fence and continuation-expiry validation atomically at the durable
   `Claimed` transition;
7. unconditional rederivation of accepted effect authorization from current
   committed Agentgres admission, exact existing-receipt equality checks, and
   authenticated/anchored consequence state wherever ordinary-state mutation
   or rollback is in scope;
8. pre-QUV receipt-phase admission, fair cross-domain verifier scheduling, and
   crash-safe bounded QUV outbox/stale-record lifecycle whose ACK semantics
   cannot discard the current correct operation;
9. process assertions for exact correct-reply membership, typed conflict
   outcomes, zero conflicting resource records, all required negative
   mutations, restart, and unrelated-domain liveness;
10. precise proof wording and qualification execution of the cited TLAPS/T10
   artifacts; and
11. a complete non-quick rerun, a new annotated candidate tag, and fresh
   independent review with no unresolved CRITICAL/HIGH finding.

The original M13-M18 must remain blocked. No M18Q admission, push, publication,
deployment, spending, or external contact is authorized by this report.

## 11. Artifact inventory and integrity

Committed review bundle contents:

- this Markdown report;
- `immutable-preflight.txt` and `review-commands.txt`;
- independent twin source, raw JSON, and complete timed transcript;
- independent QUV TLAPS and T10 TLC transcripts;
- `core-four-reproductions.patch` and
  `carrier-squat-reproduction.patch`, each based on the exact peeled commit;
- complete new M16Q run directory (added after the runner finishes);
- focused regression transcripts (added after Cargo is released); and
- final `artifact-sha256.txt`.

The exact review-output Git commit is reported alongside the path at handoff;
it is intentionally not embedded into the content it hashes.
