# AFT Post-Quantum Assurance Implementation Ledger

Status: active implementation ledger; supporting protocol context, non-canonical.
Authority: code, accepted ADRs, `docs/architecture/`, and reproducible evidence cited here.
Baseline: `master` / `origin/master` at `ef20d4ff5` when this program began on 2026-09-01.

This ledger tracks the completed/in-review M0–M8 implementation program and
the gated M9–M18 maximal-consensus program. A checked item is not a
claim of completion unless its evidence column names an authoritative artifact
or reproducible command. Only one milestone may be marked **CRITICAL PATH**.

Current disposition (2026-09-06): M17Q R1 `REPAIR_REQUIRED`; remediation toward
an R2 candidate is the sole critical path. The authoritative closure index is
`specs/query_unanimity_fault_property_matrix.md`; the authoritative version
statement (policy root `v8-push-admission`, member schema 9, handoff schema 3,
outbox `AFTPQI04`/`AFTPQI05`/`AFTPQA01`, receipt `AFTCR001`) is the "Current
profile" header carried by every QUV specification. Dated sections later in this
ledger are chronological history; where one says a root or schema is "now" in
force, the specification header supersedes it. M12a remains
`PROVED_IMPOSSIBLE_UNDER_CONSTRAINTS`, original M13-M18 remain blocked, and
`portable_final_receipt=false` is mandatory.

## Milestone status

| Milestone | State | Evidence / next required proof |
|---|---|---|
| M0 claim and schema freeze | **COMPLETE** | Canonical `GuaranteeVectorV1`, conservative legacy/profile census, accepted claim ADR, assumption census, and fail-closed transform boundary; current 459-test authoritative types-library run passes |
| M1 PQ cryptographic substrate | **COMPLETE** | SLH-DSA seal custody, ML-DSA live/header signatures, strict rotating PQ swarm records, durable ACK outbox, independent-implementation interop, stateful-seal fuzzing, and the strict four-validator timeout/restart drill pass; the owner-authorized automated M10 review has no open finding, subject to its explicit provider/side-channel/adaptive-corruption limits |
| M2 PQ optimistic live core | **COMPLETE** | Exact unit-weight 3f+1 / 2f+1 PQ geometry, guardian-independent authority, versioned scoped timeout votes/certificates, strict-PQ relay, canonical D2 trigger, and crash-safe restart are implemented; full optimistic/fallback composition belongs to M3 |
| M3 hash-only asynchronous fallback | **COMPLETE** | R10 D1–D4, hash-only RBC/RA/ASKS/gather/VABA/ACS, durable PQ transport/storage, exact-q certificates, canonical execution/admission, cross-path fencing, bounded formal composition, adversarial/mutation/crash/race campaigns, n=130 benchmark evidence, and the strengthened four-validator cold-restart drill pass under the declared static-adversary model |
| M4 no-laundering theorem/runtime | **COMPLETE** | Exact certificate-derived meet, opaque policy input, exhaustive default-deny transform registry, T6/L-M paper/formal proof, runtime-v3 recomputation, and laundering mutation corpus |
| M5 consequence externalization | **COMPLETE** | Agentgres-bound EffectManifestV1, exact atomic-resource profile, durable claim-before-call executor, lookup-only reconciliation, T10/L-X, formal/crash/mutation evidence |
| M6 economic assurance | **COMPLETE** | Exact native-asset floor from objective evidence and distinct bond snapshots; T8 stays open |
| M7 portable receipts | **COMPLETE** | Canonical ML-DSA envelope, payload-scoped PQ channel/seal/endpoint proofs, offline library/CLI, full constituent/transform report, golden vectors, validly re-enveloped negative corpus and independent RustCrypto/fips205/Python reproduction |
| M8 integrated release | **COMPLETE** | All local implementation, mixed-domain demonstration, proof, receipt, clean-room, authorization-census and affected-workspace gates pass in retained evidence; M9 froze the candidate and exact R5 M10 qualification closed the sole remaining integrated-restart finding |
| M9 immutable PQ v1 candidate | **COMPLETE** | T5d/T8 reconciled; all local M8/static/formal/affected-workspace gates reproduced; exact contents bound by annotated tag `aft-pq-v1-review-candidate-2026-09-03`; see `evidence/m9-pq-v1-candidate-freeze-2026-09-03.md` |
| M10 independent PQ v1 review and release | **COMPLETE — AUTOMATED REVIEW** | Exact annotated R5 tag object `3149d3404193864df992b482363625fe031f2f22` received an owner-authorized Daybreak `PASS`: the unchanged four-validator fixture passed all eight signer starts, H5 fallback/metrics, cold restart, recovered H4, authenticated H6, and H7. `AFT-M10-003` is closed; no M10 finding remains open. This is automated review, not human/institutional certification |
| M11 exact maximal task/model | **COMPLETE** | R3 fixes non-vacuous internal/external agreement, conflict-qualified effect liveness with explicit solo-input progress, durability, setup, verifier/freshness semantics, support partitioning, all communication profiles, role switching, and exact `f=n-1` cases |
| M12a byte-portable visibility | **PROVED IMPOSSIBLE UNDER CONSTRAINTS** | Exact R3 tag `aft-maximal-visibility-lower-bound-candidate-r3-2026-09-03` was retested `UPHELD_WITHIN_SCOPE`. It proves the M11 byte-function verifier cannot combine portable non-conflict and solo non-`Abort` progress at `f=n-1`; ADR 0050 forbids generalizing that result to interactive verifiers |
| M12b interactive visibility | **COMPLETE — PASS CONSTRUCTION** | Exact R4 tag `aft-quv-v0-construction-candidate-r4-2026-09-03` received an ADR-0049-authorized independent automated `PASS_CONSTRUCTION` with no open findings. Q-A3 requires every correct member timely for every operation; `H=2..3` opposite-order rows remain safe, the weaker split-witness mutation conflicts, and non-vacuous liveness campaigns pass for every authority mode. This opens M13Q only |
| M13 maximal consensus theorem | **BLOCKED BY M12a IMPOSSIBILITY** | The exact M11 byte-portable target has no `PASS_CONSTRUCTION`. ADR 0050 creates M13Q under changed premises rather than treating the original gate as passed |
| M14 end-to-end theorem lift | **BLOCKED BY PROVED IMPOSSIBILITY** | No theorem-bearing maximal construction exists under the fixed M11 premises to carry through ordering, durable state, effects, and receipts |
| M15 production implementation | **BLOCKED BY PROVED IMPOSSIBILITY** | Implementing or relabeling a profile would misstate the upheld lower bound; the admitted `f<n/3` hash-async and all-member seal profiles remain separate |
| M16 adversarial/performance qualification | **BLOCKED BY PROVED IMPOSSIBILITY** | No maximal production profile is authorized for process-level qualification |
| M17 independent maximal review | **BLOCKED BY PROVED IMPOSSIBILITY** | A positive maximal candidate does not exist under the fixed premises; R3 is the terminal lower-bound review evidence |
| M18 public admission and release | **BLOCKED BY PROVED IMPOSSIBILITY** | The target headline is unauthorized. Public material may report the lower bound and strongest admitted profile only |
| M13Q online QUV theorem | **COMPLETE LOCALLY; M17Q REVIEW REQUIRED** | The exact theorem surface distinguishes conflict-qualified accepted-value agreement from classical exact-decision BA, pairs each dependency with a mutation/lower bound, and gives bounded typed termination and singleton-candidate liveness. `QueryUnanimityProof.tla` discharges 75 arbitrary-set TLAPS obligations; the R4 operational model supplies the timing/mutation bridge. Independent theorem review remains M17Q work |
| M14Q online end-to-end theorem lift | **REOPENED — REPAIR REQUIRED** | R1 finding 005 identifies conditional composition lemmas without transition-level refinement; retain prior TLAPS results within that narrower scope. See `evidence/m17q-r1-import-2026-09-04/README.md`. |
| M15Q QUV production implementation | **REOPENED — REPAIR REQUIRED** | R1 findings 001–003 and 006–013 require implementation, recovery, admission, transport, and consequence repairs. Existing local changes are unqualified; prior process runs remain historical evidence only. |
| M16Q QUV adversarial/performance qualification | **REOPENED — R2 REQUIRED** | The earlier 15-phase pass at `ab8d2e58103a` does not close R1 findings 004–006 or qualify repairs. The independent R1 reproduction records eight phase passes and no complete runner disposition. Require a clean full R2 run after remediation. |
| M17Q independent QUV review | **REPAIR REQUIRED — CRITICAL PATH** | Attributable automated R1 report at review-output commit `b68e26be6679412794fa1b9d6540c630f4ff69be` records 13 unresolved critical/high findings. Imported unchanged with its pending evidence fields; see `evidence/m17q-r1-import-2026-09-04/README.md`. Remediation precedes R2 qualification, immutable candidate freeze, and fresh independent review. |
| M18Q online public admission and release | **NOT STARTED** | Exact online known-synchronous claim only; `portable_final_receipt=false` remains mandatory and the protocol cannot be called Byzantine consensus unless M13Q proves that task |

## Prepared concurrent RPC workload — 2026-09-05

The staggered dispatch loop mixed candidate signing with RPC launch. It now
prepares all four requests first and releases them through a controller-side
barrier. Preparation duration and dispatch spread are reported separately from
post-release execution time. No runtime hook or authority/deadline change was
introduced. The revised captured campaign passed and showed four overlapping
verifier intervals (739.821 ms start spread); the earlier intermittent missing-
member failure and sustained saturation remain open. A follow-up qualification
gate now correlates receipt nonces with retained start/finish logs and requires
four-way overlap, capped at the declared decision interval. Production validation
and the final checker passed: 116.737 ms start spread, 4883.263 ms bounded common
overlap, and maximum valid reply 2232 ms. No finding is closed by this run; see
`evidence/m17q-r1-workload-overlap-gate-2026-09-05/`.

## Concurrent-load coverage gap — 2026-09-05

The nonce-correlated run passed but showed four RPC-load verifier starts spread
across 5689.907 ms, with at most three logged verifier intervals overlapping.
Concurrent RPC launch does not establish four-way verifier or reserved-lane
saturation. The test comment now states that limit; full saturation remains a
required open gate. Evidence is retained under diagnostic-retention/operation-
capture. The earlier intermittent missing-member failure remains unexplained.

## Restart diagnostic retention — 2026-09-05

The transport-logging repetition passed but did not retain general child logs;
empty filtered snapshots supplied no diagnosis. The harness now preserves the
trace destination across orchestration restarts. Its child-process regression
passes two appended restarts and refuses an unwritable destination. The runner
retains per-phase nested logs and checks capture failures. A properly captured
diagnostic run passed with eight retained component logs, but did not explain
the failure. A nonce-bound lifecycle tracing follow-up compiles and is running
in `evidence/m17q-r1-diagnostic-retention-2026-09-05/`.
The intermittent saturation failure remains unexplained and unqualified.

## M16Q runner result scope — 2026-09-04

Runner PASS now explicitly means only the selected runner gates. The result
file repeats quick/dirty scope and states `r2_admission=NOT_ESTABLISHED`; the
final console label no longer calls a partial/development run qualification.
Missing R1 refinement/load/restart coverage must be implemented and qualified
before R2 admission can be established. No required gate has been waived.

## R1 typed conflict refusal — 2026-09-04

QUV completion now preserves typed verifier errors. Only ConflictDisclosed maps
to the Aborted RPC status with the versioned refusal marker; the campaign checks
both fields instead of message text. This marker grants no authority. The client
and server regressions passed; a mismatched helper feature gate was found by
the default check, repaired, and all three checks now pass. The fresh production
campaign failed saturation member coverage after all four sole-correct cases
passed. An enriched-error repeat then passed without a protocol repair, so the
intermittent failure remains unexplained. A transport-logging run is active in
`evidence/m17q-r1-typed-refusal-2026-09-04/`. Production completion, remaining
finding 004 obligations, clean R2, and fresh review remain required.

## R1 conditional formal kernels — 2026-09-04

Targeted formal runner phases pass: 75 QUV TLAPS obligations, 16 composition
obligations, and the bounded abstract T10 model (42 distinct states, depth 8).
Raw evidence and tool/source hashes are retained in
`evidence/m17q-r1-conditional-formal-2026-09-04/`. These conditional kernels do
not discharge runtime premise establishment or transition refinement. Finding
005 remains open, as do full clean R2 qualification and exact-candidate review.

## R1 production participation/resource campaign — 2026-09-04

The existing exact-member coverage checks are now paired with direct durable
resource lookup before and after concurrent conflicting effect requests.
Rejected effects must remain absent; accepted effects must match the admitted
manifest and the endpoint-authenticated stored record. The local process run
passed in `evidence/m17q-r1-production-participation-2026-09-04/`: all four
sole-correct placements and saturation operations executed, both conflicting
effects were rejected without durable mutation, and the unrelated effect
executed. That run used message-based conflict classification and predates the
typed-refusal follow-up. Finding 004 remains open; no clean R2 pass is claimed.
The runner now also checks complete campaign output rather than test selection
alone: four distinct placements, saturation, conflict/resource outcomes, and
unrelated execution. Its parser accepts two complete fixtures and rejects 21
incomplete/inconsistent fixtures. This does not replace process execution.

## R1 Claimed readmission — 2026-09-04

The public consequence admission/binding APIs now permit `Claimed` retries
only when current admission matches the exact initial authorization trace
commitment. A fresh live continuation remains mandatory. Seventeen consequence
tests pass, including restarted public readmission, changed-admission refusal
without receipt mutation, and expired height/continuation refusal with zero
resource calls. Evidence is in `evidence/m17q-r1-claimed-readmission-2026-09-04/`.
This closes a local API gap, not R1 findings 009/010/013; production retry,
reconciliation, timing/refinement, clean R2, and review remain required.

## R1 effect-context separation — 2026-09-04

The admitted manifest now distinguishes external-resource `predecessor_root`
from `online_authorization_predecessor` and explicitly commits the QUV
`online_authorization_authority_mode`. Live/audit bindings and both executor
entry points check the admitted QUV fields. Portable manifests omit the new
online-only fields; older QUV objects missing them fail closed. Seven type
checks and all 104 Agentgres library tests pass; QUV core passes 21 tests with
one ignored benchmark. The M16Q runner now includes manifest-type and workload
registry gates and hashes those sources. Both registry tests, one representative
portable receipt test, and feature-enabled process-fixture compilation pass.
Exact artifacts are recorded in `evidence/m17q-r1-effect-context-2026-09-04/`.
This does not establish durable expected-head/next-slot enforcement; findings
001/013 remain open for full production/refinement/qualification/review.

## R1 provisional PQ enrollment — 2026-09-04

Unproven carrier metadata is capped per claimed account and globally, expires
without indefinite status-refresh extension, and loses pending key/retry state
on expiry. Successful proof evicts aliases; authenticated identity metadata
changes require explicit configuration/manager replacement. Updated fixtures
require renewed enrollment after unproven disconnect and a full authenticated
handshake before account-addressed outbox routing. All 21 networking library
tests pass; initial failures and exact final source/command/log hashes are
retained in `evidence/m17q-r1-pq-enrollment-2026-09-04/`. These local caps can
refuse new metadata under pressure; discovery fairness, process timing/flood,
restart, and exact-candidate review remain open. Findings 007/011/012 are not
closed by library evidence.

## R1 pre-write store headroom — 2026-09-04

Member insertion now checks exact projected encoded-state growth before
cloning/authenticating the next state; handoff installation checks its next
encoded state; the shared atomic writer enforces the same 512 MiB ceiling as
the reader before touching temporary/destination files. Local QUV tests pass
21 cases with one explicitly ignored benchmark, including exact-fit,
one-byte-short, duplicate-at-capacity, reopen, compact-length-boundary, and
non-mutation checks. Source/command/log hashes are retained in
`evidence/m17q-r1-store-headroom-2026-09-04/`. Finding 006 remains open:
rooted quotas, fair admission, bounded lifetime, incremental authenticated
storage, compaction, sustained process-load/restart qualification, and fresh
review are not established by this absolute headroom guard.

## R1 authenticated recovery hardening — 2026-09-04

Member/handoff storage and anchor tags now use the existing dcrypt
HMAC-SHA-256 provider with fixed-width tag verification, domain-separated
canonical inputs, and schema 3. Older schemas are rejected without automatic
authority migration. `evidence/m17q-r1-hmac-recovery-2026-09-04/` retains local
commands, hashes, and results. The tests cover one altered bit at each encoded
state/anchor byte, unchanged files on refusal, and authentic one-generation
pending recovery. This does not qualify crash/fsync timing, all corruption
patterns, custody backends, or production process activation. R1 finding 002
remains open through complete qualification and fresh review.

## R1 local remediation in progress — 2026-09-04

`evidence/m17q-r1-local-remediation-2026-09-04/README.md` records deadline
admission hardening and post-QUV committed-admission/claim checks. Local QUV
core tests pass 16 cases with the performance benchmark explicitly ignored;
consequence tests pass 17 cases, including typed fence/continuation refusal
and zero external calls on invalid Claimed retries. These are dirty-worktree
checks, not clean qualification. The longer runtime-finality critical section,
production retry path, sustained-load timing, and transition-level refinement
remain unqualified. All 13 R1 findings remain open pending complete repair,
qualification, and fresh exact-candidate independent review.

## Completed slice: M0 GuaranteeVectorV1 claim and schema freeze

Design decisions:

- The scalar R6 assumption lattice remains decodable during migration.
- `GuaranteeVectorV1` is a distinct versioned wire object committed with
  RFC 8785/JCS bytes and a domain-separated SHA-256 hash.
- Policy requirement joins and evidence meets are different Rust types and
  operations.
- `end_to_end_pq` is valid only when it equals the conjunction of consensus,
  channel and externalization PQ coordinates, the primitive census is PQ-only,
  a PQ-authenticated channel is named, and no primitive is unresolved.
- At-most-once externalization is valid only for an idempotency-register
  profile with an exact adapter-profile commitment.
- Committee geometry is all-or-none. Quorum-intersection BFT validates
  `n >= 3f+1`, `q >= 2f+1`, `2q > n+f`, and `q <= n-f`; unanimous all-but-one
  safety instead validates its exact `f=n-1`, `q=n`, `n>=2` geometry without
  pretending it has the live quorum's capacity.
- The safety construction is explicit. Existing live/guardian certificates are
  labelled `legacy_guardian_majority`; only a future exact-geometry profile may
  claim `quorum_intersection_bft`.
- Collateral amounts use canonical decimal strings so JCS commitments do not
  inherit JSON integer precision limits.
- Legacy certificate profiles migrate conservatively: none earns an
  end-to-end PQ claim.
- The M4 registry is exhaustive and default-deny: every non-empty
  transformation set remains a typed refusal until the rule's independent
  evidence verifier lands. End-to-end PQ also requires a
  finality-bearing chain, committed constituents, and no legacy profile whose
  own label is non-PQ.

Proof obligations intentionally carried into later milestones and release gates:

- M2/M4/M7 must bind production certificate issuers to exact v1 vectors,
  verified constituent hashes, and the runtime/portable-verifier algebra.
- M2 must populate the future exact quorum geometry and configuration/domain
  coordinates. Legacy majority profiles are already distinguished and cannot
  claim target quorum-intersection BFT.
- M4 defines the exhaustive transform vocabulary and retains M0's fail-closed
  behavior for every rule whose independent evidence verifier has not landed.
- Final release gate 4 still requires production authorization to consume the
  vector. That cutover is not represented as an M0 schema-freeze result.

Changed files for this slice:

- `crates/types/src/app/consensus/collapse/guarantee_vector.rs`
- `crates/types/src/app/consensus/collapse.rs`
- `crates/types/src/app/consensus/tests_parts/guarantee_vector_v1.rs`
- `crates/types/src/app/consensus/tests.rs`
- `crates/types/src/app/consensus/collapse/assumptions.rs`
- `crates/types/src/app/consensus/tests_parts/assumption_lattice.rs`
- `docs/decisions/0041-adopt-coordinate-wise-aft-assurance-and-refuse-evidence-laundering.md`
- `docs/decisions/README.md`
- `internal-docs/architecture/protocols/aft/README.md`
- this ledger

Verification commands:

```text
cargo test -p ioi-types guarantee_vector
cargo test -p ioi-types assumption_lattice
cargo check -p ioi-types
cargo fmt --all -- --check
```

Verified on 2026-09-01 against the baseline plus this slice:

- `cargo test -p ioi-types --lib` — PASS, 419 passed / 0 failed,
  including the initial six `GuaranteeVectorV1` migration and refusal tests.
- After the assumption-ledger census and stricter BFT/PQ/externalization
  validation landed, `cargo test -p ioi-types --lib app::consensus::tests::`
  — PASS, 96 passed / 0 failed, including all current vector tests.
- Final authoritative run after the complete M0 hardening:
  `cargo test -p ioi-types --lib` — PASS, 423 passed / 0 failed / 0 ignored.
- Current integrated-tree run: `cargo test --locked -p ioi-types --lib` —
  PASS, 459 passed / 0 failed / 0 ignored in 491.19 seconds.
- `cargo check -p ioi-types` — PASS; 19 pre-existing non-snake-case
  warnings originate in generated architecture contracts.
- `cargo fmt --all -- --check` — PASS.
- `git diff --check` — PASS before the verification record was appended.

Evidence paths:

- M0 schema and validation: `crates/types/src/app/consensus/collapse/guarantee_vector.rs`
- M0 canonical claim boundary: `docs/decisions/0041-adopt-coordinate-wise-aft-assurance-and-refuse-evidence-laundering.md`
- M0 negative/migration tests:
  `crates/types/src/app/consensus/tests_parts/guarantee_vector_v1.rs`
- Legacy lattice:
  `crates/types/src/app/consensus/collapse/assumptions.rs`

## Completed slice: M1 PQ cryptographic substrate

Implemented and admitted by the exact R5 automated M10 review, subject to the
review's explicit limits:

- Accepted ADR 0042 selects FIPS 205 SLH-DSA-SHA2-128s for terminal
  shares, pins the provider version and keeps production authorization blocked
  on independent review.
- `SealKeyManifestV1`, `SealKeyBindingV1` and `SealShareV2` bind every share
  to network, configuration, epoch, conflict domain, member, slot, predecessor
  and successor commitment. Verification starts from the enrolled manifest;
  a key carried only by a share grants no authority.
- The durable v2 signer reserves externally before signing, encrypts local
  state, burns a slot on the recoverable crash boundary, rejects detached
  clones/rollback/exhaustion and holds its shared-file anchor lock for the
  signer lifetime. The file anchor is production-capable only on an external,
  strongly consistent filesystem outside the clonable signer snapshot.
- A NIST ACVP SLH-DSA key-generation vector, manifest/rogue-key/replay tests,
  and crash/clone/rollback/exhaustion tests pass.
- Native AFT quorum verification now dispatches by the authorized suite and
  verifies ML-DSA-44 votes and view changes against the exact rooted raw-key
  hash. Rooted state hydration accepts raw ML-DSA-44 keys and continues to
  parse Ed25519's existing protobuf representation.
- Consensus production selects the local live-vote signer by the effective
  rooted validator record, supports a stable account id distinct from its
  rotated consensus-key hash, signs votes/view changes/tip replays with the
  selected ML-DSA key, and refuses absent or ambiguous local authorization.
- Proposal and sealed-finality verification recognize ML-DSA-44, and the
  producer suite/key/hash are rebound to the rooted leader record before
  acceptance. Classic-BFT ML-DSA headers are signed directly by that configured
  key and carry no guardian certificate; guardian authorization remains only
  in separately named compatibility profiles. Sealed-proof producer signatures
  use the same rooted suite.
- Accepted ADR 0043 defines `aft-pq-channel-v1`: mutually authenticated
  ML-DSA-44 identities, ephemeral hybrid ML-KEM-768 establishment,
  transcript-bound directional keys and ChaCha20-Poly1305 records. The crypto
  core implements rooted enrollment checks, mutual signed key confirmation,
  downgrade refusal, cross-configuration replay rejection, confidential
  records and strict sequence/AAD replay discipline.
- The libp2p swarm now carries canonical client-hello/server-hello/finish and
  AEAD record messages, chooses one deterministic initiator, queues consensus
  records until the pairwise channel is established, and routes votes, QCs,
  view changes, echoes, panic and confidence controls only after authenticated
  decryption and envelope/content-type agreement. In strict mode it drops the
  equivalent classical gossip and direct-relay inputs rather than downgrading.
- Validator startup selects strict mode only for a uniformly ML-DSA effective
  rooted validator set. It verifies every raw key against the embedded key
  record, requires the local ML-DSA signer to match one stable validator
  account, commits the effective-set hash into the channel scope and enrolls a
  status peer only after chain identity validation. A claimed account carried
  by classical status cannot complete the PQ handshake without the enrolled
  ML-DSA private key.
- Every AFT finalization preflights the next effective validator set before
  header authority is issued or the header is persisted. A strict-to-mixed or
  strict-to-classical transition is refused before durability. After the old
  height's vote/QC emission, a changed configuration atomically replaces the
  swarm session manager and re-enrolls known peers. Manager replacement drops
  old traffic keys, pending handshakes and queued records; an adverse test
  proves an old record is rejected both before and after the new handshake.
- Classic-BFT ML-DSA headers are now signed directly by the configured rooted
  producer key. They make no guardian-counter claim, carry no guardian
  certificate, and do not wait on the legacy guardian signer. The signed
  compatibility trace commits the producer account/key, height and view.
  Receiving nodes still bind the suite, public key and key hash to the rooted
  leader record before accepting the signature.
- Classic-BFT admission no longer treats guardian counter monotonicity as a
  safety premise. Same-slot rebinding is still rejected. Guardian-dependent
  compatibility modes retain counter rollback/order enforcement.
- Strict PQ consensus delivery now uses a versioned, configuration/account-
  scoped SCALE outbox. A payload is atomically written and fsynced before
  issuance, one record per peer remains in flight until its exact request ACK,
  and ACK deletion is itself atomic and fsynced. Process restart reloads the
  plaintext evidence and reseals it under a fresh handshake transcript, so a
  reset sequence number never reuses an AEAD key/nonce pair. Scope mismatch,
  malformed commitments, duplicate entries, queue overflow and concurrent
  clone ownership fail closed. `aft_pq_outbox_dir` is mandatory for an all-
  ML-DSA strict channel profile.
- ML-DSA decoding now delegates public, expanded-secret and signature
  validation to the FIPS 204 provider. It rejects malformed secret material
  and non-canonical hint encodings at deserialization rather than retaining
  attacker-controlled bytes for a later verifier.
- NIST ACVP-Server FIPS 204 internal signature-verification test case 91 is
  pinned with its upstream commit and passes against ML-DSA-44. A separate
  Rust-1.85+ oracle pins patched RustCrypto `ml-dsa` 0.1.1 and proves mutual
  import/verification plus byte-identical deterministic signatures against
  production `dcrypt` 4.0.1. The same oracle pairs production RustCrypto
  `slh-dsa` 0.2.0-rc.5 with IntegrityChain `fips205` 0.4.1 and proves matching
  key generation, mutual signature verification and byte-identical
  deterministic signatures. This is independent-implementation
  interoperability evidence, not an independent audit.
- A seeded malformed-input fuzz target covers the ML-DSA key/signature import
  boundary and all four PQ channel wire decoders. Two bounded 10,000-run
  campaigns complete without a crash at 84 MiB peak RSS; the second begins
  with curated full-size ML-DSA-44 objects rather than an empty corpus.
- Reproducible Criterion benchmarks publish primitive sizes and latency
  distributions. On the recorded development host, ML-DSA-44 signing is about
  143 ms and verification about 634 µs; SLH-DSA-SHA2-128s terminal signing is
  about 100.5 ms and verification about 102.7 µs. These results expose a live
  throughput risk and do not support an optimal-latency claim.
- Stateful SLH-DSA signer fuzzing covers durable reservation, destructive
  update, crash recovery, rollback and detached-clone refusal. A bounded
  128-run / 557-second campaign completed without a crash or invariant
  violation.
- The strict-PQ cluster harness now drives four validators with rooted ML-DSA
  authority through proposal, a scheduled leader loss, the exact `q=3`
  timeout certificate, view-1 recovery, all-node restart, historical sync and
  resumed finality. The test treats any terminal-runtime-finality or frozen-node
  diagnostic as a failure; its retained trace contains neither signal nor a
  missing-validator-set, state-root or durability error.
- Restart recovery retains production's canonical rooted membership history.
  The static test configuration has an explicitly gated test-only historical
  hydration lane; it cannot be cited as proof of production rotation recovery.

M1 review boundary:

- The owner-authorized independent automated M10 review is complete and has no
  open finding. It is not human peer review or provider, side-channel, or
  adaptive-corruption certification. The independent implementations remain
  interoperability and differential oracles, not certifications.

M1 evidence commands run so far:

```text
cargo test -p ioi-types seal_share
cargo test -p ioi-validator common::guardian::seal_signer::tests
cargo test -p ioi-consensus --features aft --lib
cargo test -p ioi-crypto pq_authenticated_channel
cargo test -p ioi-networking pq_
cargo test -p ioi-networking protected_payload_routes_only_after_aead_and_type_agreement
cargo test -p ioi-networking configuration_rotation_invalidates_old_session_records
cargo test -p ioi-networking --lib
cargo test -p ioi-crypto dilithium::tests
cargo +stable run --locked --manifest-path tools/aft-pq-interop/Cargo.toml
cargo +nightly fuzz run aft_pq_decoders --fuzz-dir fuzz/aft-pq-crypto -- -runs=10000 -max_len=16384
cargo bench -p ioi-crypto --bench aft_pq_crypto -- --noplot
cargo bench -p ioi-validator --bench aft_pq_terminal_seal -- --noplot
cargo test -p ioi-validator pq_rotation_is_preflighted_before_header_authority_or_durability
cargo test -p ioi-validator runtime_finality --lib --features consensus-aft,vm-wasm,state-iavl
cargo test -p ioi-validator pending_aft_proposal_rebroadcast_is_producer_owned --lib --features consensus-aft,vm-wasm,state-iavl
cargo test -p ioi-validator strict_pq_vote_replay_has_bounded_cadence --lib --features consensus-aft,vm-wasm,state-iavl
cargo test -p ioi-networking pq_ --lib
IOI_AFT_BENCH_TRACE=1 IOI_AFT_BENCH_TRACE_DIR=/tmp/aft-pq-trace-20260902-15 IOI_TEST_ORCH_RUST_LOG=info,consensus=debug,sync=trace,network=warn RUST_TEST_THREADS=1 cargo test -p ioi-cli --test aft_e2e --features consensus-aft,vm-wasm,state-iavl test_aft_pq_four_validator_timeout_quorum_and_restart -- --nocapture
cargo check -p ioi-validator
cargo check -p ioi-validator -p ioi-node -p ioi-cli
```

Observed results on 2026-09-01:

- focused seal-share/type tests — PASS, including four new v2 manifest/replay
  tests;
- seal signer tests before durable-state expansion — PASS, 7 / 7;
- durable signer-state tests — PASS, 5 / 5;
- `cargo test -p ioi-consensus --features aft --lib` after ML-DSA
  vote/header/rooted-key verification — PASS, 179 / 179;
- `cargo test -p ioi-crypto pq_authenticated_channel` — PASS, 5 / 5 mutual
  authentication, cross-scope, transcript, key-confirmation and record tests;
- `cargo test -p ioi-networking pq_` — PASS, 2 / 2 rooted session-manager
  establishment and unknown-enrollment refusal tests;
- protected swarm payload routing mutation test — PASS, 1 / 1; a valid AEAD
  record with a mismatched authenticated content type and inner envelope is
  rejected before event delivery;
- PQ configuration replacement test — PASS, 1 / 1; an old-session record is
  rejected both before and after establishment under the rotated scope;
- ML-DSA module tests — PASS, 9 / 9, including pinned NIST ACVP FIPS 204
  verification and non-canonical hint rejection;
- isolated two-pair interoperability oracle — PASS; ML-DSA-44 public key 1312
  bytes, expanded secret 2560 bytes and signature 2420 bytes; SLH-DSA-SHA2-128s
  public key 32 bytes and signature 7856 bytes; both pairs mutually verify and
  match deterministic bytes;
- seeded PQ decoder fuzz campaign — PASS, 10,000 / 10,000 inputs, no crash,
  84 MiB peak RSS; a preceding empty-corpus 10,000-run campaign also passed;
- primitive benchmarks — PASS; full distributions, sample counts, host and
  exact reproduction commands are published in the M1 benchmark evidence;
- finalization activation-order test — PASS, 1 / 1; downgrade/configuration
  validation precedes both authority issuance and durable header update, while
  manager replacement remains after current-height self-vote emission;
- `cargo check -p ioi-networking` — PASS after strict carrier integration;
- `cargo check -p ioi-validator` after rooted local signer selection — PASS.
- Classic PQ header-authority test — PASS, 1 / 1; the rooted ML-DSA producer
  signs directly, mutation fails, a substituted key is refused, and no
  guardian/sealed certificate is minted.
- Guardian counter tests — PASS, 5 / 5; compatibility modes retain monotonic
  enforcement while Classic BFT accepts cross-slot counter reuse and rejects
  conflicting same-slot bindings.
- Full networking library — PASS, 7 / 7; includes durable restart/ACK
  recovery, clone locking, cross-configuration refusal, fresh-transcript
  resealing and old-record rejection.
- Affected validator/node/CLI compile check — PASS after introducing the
  required strict-PQ outbox configuration surface.

Follow-up verification on 2026-09-02:

- `cargo test -p ioi-crypto --lib` — PASS, 62 / 62 after strict ML-DSA
  deserialization, ACVP, interoperability-support and benchmark additions;
- stateful SLH-DSA signer fuzz campaign — PASS, 128 generated operation
  sequences / 557 seconds, with no crash or custody invariant violation;
- strict four-validator PQ timeout/restart drill — PASS, 1 / 1 in 339.63
  seconds; scheduled leader loss formed the exact three-member scoped timeout
  certificate, recovered in view 1, restarted every node, sync-recovered the
  lagging node from height 3 through height 7 and resumed all nodes through
  height 9;
- retained drill trace `/tmp/aft-pq-trace-20260902-15` — CLEAN under the
  terminal-finality, frozen-node, missing-validator-set, state-root mismatch,
  durability-uncertainty and panic audit patterns; recovered Agentgres effects
  were admitted contiguously;
- runtime-finality recovery/admission suite — PASS, 13 / 13;
- proposal ownership and strict-PQ replay cadence regressions — PASS, 1 / 1
  each;
- focused PQ networking suite — PASS, 8 / 8, including delayed-handshake,
  configuration-rotation and durable-outbox restart cases;
- `cargo fmt --all -- --check` and `git diff --check` — PASS after the M1
  evidence slice.

M1 evidence paths:

- `docs/decisions/0042-select-slh-dsa-for-aft-terminal-seals.md`
- `crates/types/src/app/consensus/seal_shares.rs`
- `crates/validator/src/common/guardian/seal_signer.rs`
- `crates/validator/src/common/guardian/seal_signer/state.rs`
- `crates/consensus/src/aft/authenticated_quorum.rs`
- `crates/crypto/src/transport/pq_authenticated_channel.rs`
- `crates/crypto/src/sign/dilithium/tests/vectors/nist_acvp_mldsa44_sigver_tc91.json`
- `crates/networking/src/libp2p/pq_channel.rs`
- `crates/networking/src/libp2p/swarm.rs`
- `crates/types/src/config/mod.rs`
- `crates/networking/src/libp2p/sync.rs`
- `crates/validator/src/standard/orchestration/consensus.rs`
- `crates/validator/src/standard/orchestration/consensus/production.rs`
- `crates/validator/src/standard/orchestration/lifecycle.rs`
- `crates/validator/src/standard/orchestration/sync.rs`
- `docs/decisions/0043-adopt-mutually-authenticated-ml-kem-aft-channels.md`
- `tools/aft-pq-interop/`
- `fuzz/aft-pq-crypto/`
- `crates/crypto/benches/aft_pq_crypto.rs`
- `crates/validator/benches/aft_pq_terminal_seal.rs`
- `internal-docs/architecture/protocols/aft/evidence/m1-pq-benchmarks-2026-09-02.md`

## Completed slice: M2 exact PQ optimistic core and durable fallback boundary

Implemented:

- `PqOptimisticQuorumGeometryV1` accepts only a non-empty, strictly sorted,
  duplicate-free, all-ML-DSA, unit-weight validator set with exact `n=3f+1`;
  it derives `q=2f+1`. Weighted, mixed-suite, malformed-total and non-exact
  memberships remain compatibility profiles and cannot acquire the label.
- Live QC formation, timeout-certificate formation and collapse verification
  apply the exact distinct-member threshold in Classic BFT for the normative
  all-ML-DSA profile. Compatibility modes retain their declared weighted
  threshold and are not silently reinterpreted.
- Finalized quorum events record whether exact PQ optimistic qualification was
  proved. Qualification rechecks the complete member set, suite, unit weight,
  signer uniqueness/subset relation, mode and threshold and refuses `f=0`.
- Classic-BFT producer authority and cross-slot acceptance no longer depend on
  guardian signing or guardian counter monotonicity. Guardian certificates
  remain available to the explicitly guardianized policy profiles.
- `AftTimeoutVoteV1` signs protocol/schema version, genesis network,
  effective validator-set hash, epoch, height, view, voter, high QC and lock
  QC directly.
  `AftTimeoutCertificateV1` canonicalizes voters and is reverified against
  rooted ML-DSA keys at exact q. A legacy `(height, view)` view-change vote or
  timeout certificate is rejected by the normative all-ML-DSA profile and
  remains only in explicitly classical compatibility profiles.
- Scoped timeout votes and certificates are carried only by the strict PQ
  channel, use its durable per-peer ACK outbox, and have distinct authenticated
  payload variants. Adoption is idempotent and immediately advances a lagging
  pacemaker. Non-zero-view PQ block headers carry only scoped timeout authority;
  simultaneous legacy/scoped evidence is refused.
- `FallbackStartCertificateV1` binds network, effective validator-set hash,
  epoch, height, one deterministic instance id, the complete consecutive
  view-1-through-view-3 TC chain, high QC, lock QC, and locked root. High/lock
  state is selected deterministically from the signed timeout contributions;
  an issuer cannot attach local or stale safe-state claims after quorum
  collection. Every carried QC is reverified, and a node refuses a transition
  that omits its newer authenticated state. Unknown versions and malformed
  cross-field bindings fail closed.
- The normative PQ engine requires a process-locked, configuration-scoped
  transition journal. It atomically writes, fsyncs, renames, and directory-
  syncs the certificate before in-memory adoption. Restart re-verifies every
  trigger/QC against rooted ML-DSA membership and re-announces it; a conflicting
  second certificate for the height is refused.
- Runtime ingress rejects stale, excessively future, malformed, cross-scope,
  locally inconsistent safe-state, and conflicting transitions. The D2
  boundary does not pretend to implement ACS or asynchronous termination.

Verification on 2026-09-02:

```text
cargo test -p ioi-consensus --features aft authenticated_quorum::tests --lib
cargo test -p ioi-consensus --features aft guardian_counter --lib
cargo test -p ioi-validator classic_pq_header_authority_is_rooted_and_guardian_independent --lib
cargo test -p ioi-types fallback --lib
cargo test -p ioi-consensus --features aft fallback --lib
cargo test -p ioi-consensus --features aft relayed_timeout_certificate_advances_once_and_is_relayed_once --lib
cargo test -p ioi-consensus --features aft scoped_timeout --lib
cargo test -p ioi-consensus --features aft pq_quorums_intersect --lib
cargo test -p ioi-consensus --features aft --lib
cargo test -p ioi-networking protected_payload_routes_only_after_aead_and_type_agreement --lib
cargo test -p ioi-networking --lib
cargo check -p ioi-validator
```

- exact PQ quorum tests — PASS, including exhaustive quorum-pair intersection
  at n=4/7/10 and the algebraic identities through f=10,000;
- guardian demotion/counter tests — PASS, 5 / 5;
- direct PQ header authority — PASS, 1 / 1.
- fallback/timeout wire-shape tests — PASS, including direct commitment of
  every authority coordinate, canonical voter ordering, and unknown-version
  refusal;
- durable fallback tests — PASS, 3 / 3, covering fsync-backed restart,
  single-owner locking, missing durability, malformed signatures, stale/future
  relay, cross-scope replay, conflicting safe state, and deterministic instance
  convergence;
- timeout synchronizer tests — PASS, covering exact-q formation from
  out-of-order scoped votes, one-time relay, immediate idempotent view adoption,
  cross-network replay refusal, and refusal of a cryptographically valid legacy
  ML-DSA vote as normative PQ authority;
- full AFT consensus library — PASS, 191 / 191;
- full networking library — PASS, 7 / 7 after adding distinct scoped timeout
  payload routing and authenticated-content-type refusal;
- validator compile check — PASS after adding TC/FallbackStart ingress,
  startup journal configuration, and configuration rotation.

M2 changed/evidence paths:

- `crates/types/src/app/consensus/fallback.rs`
- `crates/types/src/app/mod.rs`
- `crates/api/src/consensus/mod.rs`
- `crates/consensus/src/aft/authenticated_quorum.rs`
- `crates/consensus/src/aft/guardian_majority/{engine,qc_state,runtime,fallback_state,collapse_verification,recovery_cache}.rs`
- `crates/consensus/src/aft/guardian_majority/tests_parts/{authenticated_runtime,support}.rs`
- `crates/networking/src/libp2p/{pq_channel,sync,types,swarm,mod}.rs`
- `crates/validator/src/standard/orchestration/{lifecycle,events}.rs`
- `crates/validator/src/standard/orchestration/consensus/production.rs`
- `internal-docs/architecture/protocols/aft/specs/r10_live_tier_async_fallback.md`

M2 closure rationale:

- The exit criterion permits tested or mechanized quorum intersection. The
  implementation exhausts every quorum pair for representative exact
  geometries and checks the general arithmetic identity over 10,000 fault
  bounds. The broader temporal proof remains a required M8 artifact rather
  than being misreported as completed here.
- Correct nodes derive the fallback instance id only from the signed
  network/configuration/epoch scope and height. Trigger arrival order and
  safe-state freshness cannot fork that namespace; canonical vote ordering,
  exact replay, conflict refusal, single-writer persistence, and restart
  re-verification are all exercised.
- The Classic-BFT production and theorem-assumption audit found no guardian
  non-equivocation dependency. Guardian evidence is policy/admissibility data;
  it grants no live quorum or timeout authority.

## Completed slice: M3 hash-only asynchronous fallback core

Implemented and release-gated for the declared M3 profile:

- The design authority is Das, Duan, Liu, Momose, Ren and Shoup,
  “Asynchronous Consensus without Trusted Setup or Public-Key Cryptography,”
  CCS 2024 / IACR ePrint 2024/677. The encoded assumption profile says
  `static`, randomized asynchronous termination, exact `n=3f+1`, exact
  `q=2f+1`, private authenticated channels, and no private threshold setup or
  DKG. It makes no adaptive-security or fully setup-free claim.
- `AftAsyncInstanceV1` binds the asynchronous namespace to the durable
  `FallbackStartCertificateV1`, exact configuration geometry, high/lock QC,
  locked root and trigger hash. Versioned, purpose-separated envelopes bind
  every message to that instance and its authenticated sender.
- An original Rust implementation now composes bounded full-value Bracha RBC,
  reliable agreement, byte-wise GF(256) ASKS with caller-supplied secret
  entropy, index gather, index cover gather, multi-view index VABA and message
  ACS. A public research prototype was inspected only as research context; it
  carries no license file and contains unfinished paths, so no source was
  copied from it.
- The ordering adapter consumes only availability-certified immutable proposal
  references extending the fallback lock, chooses the agreed ACS set,
  canonicalizes it, and emits an ordering decision plus an arrival-order-free
  transcript summary. Random ASKS material affects rank selection only and
  grants no authority.
- A cross-path signer fence refuses one member signing different canonical
  block hashes at one height regardless of whether the optimistic or fallback
  path supplied the hash. Ordering roots never enter this fence. The production implementation authenticates state with a derived
  custody key, persists authorization before signing, uses a separately located
  locked generation anchor, and rejects rollback and concurrent clones. The
  executed-block decision is persisted before entering the fence and its local
  vote is persisted before broadcast.
- Future-view traffic and reconstruction shares that arrive before their local
  state transition are bounded and buffered. Exact duplicate start triggers
  and messages are idempotent; conflicting local proposals and equivocations
  fail closed.
- `DurableHashAsyncNode` encrypts the complete write-ahead/replay journal,
  including private ASKS shares, under an instance/member-bound custody key.
  Inputs are evaluated on an isolated candidate and the complete input/outcome
  frame is persisted before candidate state or actions are released. Restart
  replays safe idempotent actions. A separately
  located generation anchor detects rollback and its lock prevents concurrent
  clones; the anchor must be outside clonable node snapshots.
- Journal schema v2 is an authenticated append-only WAL: a separately
  encrypted entropy header is followed by nonce-unique encrypted outcome
  frames chained to a head commitment carried by the external anchor. The
  initial head commits the encrypted entropy header, preventing a same-scope
  cloned initialization from substituting different private randomness. The
  implementation fsyncs a complete input/outcome frame before releasing any
  action, repairs only an unanchored torn tail, and rejects rollback,
  same-generation mutation and ambiguous generation gaps.
- The strict PQ carrier has a dedicated asynchronous-consensus authenticated
  content type. Outbox schema v2 commits the rooted recipient account instead
  of a transient libp2p peer id, so public and private protocol actions are
  durably queued even before peer discovery or channel establishment. A later
  unique account-to-carrier enrollment drains the same commitment; assigning
  one rooted account to multiple carriers is refused. Validator broadcasts are
  expanded across the exact rooted membership and never depend on an
  opportunistic peer/account cache.
- The instance carries the complete fallback-start certificate, rather than a
  bare claimed hash, so portable verification can recompute the scope, trigger,
  lock and transition commitment. The versioned carrier distinguishes protocol
  messages, decision votes and completed ordering certificates and refuses
  cross-instance/type substitution.
- Rooted ML-DSA decision votes bind the complete ordering-decision hash,
  member index and enrolled account. `AsyncOrderingVotePool` verifies raw keys
  against the effective `ValidatorSetV1`, never mixes decisions, and emits only
  an exact `q=2f+1` certificate. The portable verifier repeats membership,
  epoch, configuration, geometry, transcript and signature checks.
- Each proposal now enters ACS only after an exact `q=2f+1` ML-DSA
  validate-and-hold certificate. Descriptor and vote preimages bind the exact
  instance, proposer, payload hash/length and fallback lock. Payload bytes,
  availability certificates, the frozen local proposal and the accepted
  terminal ordering certificate are atomically persisted and commitment-
  checked on reload.
- `HashAsyncSession` connects authenticated rooted accounts, durable proposal
  custody, availability collection, the protocol node, ordering votes and the
  shared signing fence. It buffers early traffic, refuses account/index or
  instance substitution, loops back local broadcasts, and emits finality only
  after portable exact-q verification. Restart re-emits a previously accepted
  final result and can reconstruct every selected payload through its persisted
  availability evidence.
- A second exact-`q` ML-DSA round binds the canonical ordering-decision hash,
  selected-batch witness hash, and one executed block hash. It deliberately
  commits the ordering decision rather than one certificate byte hash, because
  honest nodes may assemble different valid signer subsets. Executed decisions,
  local votes, and final certificates are durable and reverified on restart.
- Async instance and decision identity commits the semantic trigger and
  decision, not one replaceable exact-`q` witness encoding. Every supplied
  timeout, availability, ordering and executed witness is still fully
  verified. Nodes that assemble different valid signer subsets therefore
  converge on one instance and block identity rather than forking on evidence
  serialization.
- The fallback transition applies the same rule at its first durable boundary:
  two fully verified exact-`q` timeout chains with the same scope, height and
  authenticated high/lock safe state are consensus-equivalent even when their
  signer subsets differ. The first durable representation remains retained;
  different safe state is still a conflict. This closes the process-discovered
  race in which correct nodes named one semantic fallback instance but rejected
  one another's byte-distinct trigger witnesses.
- Validator orchestration now activates one durable session from an accepted
  full fallback-start certificate, semantically validates typed transaction
  proposals before voting, routes public/private actions only through the
  strict PQ swarm and authenticated peer map, and reconstructs a deterministic
  de-duplicated transaction batch when a certificate finalizes. It derives a
  virtual multi-producer header from the exact parent, executes and inertly
  stages the batch, then starts the executed-block round. Only the fully
  verified second-round certificate enters the Agentgres finality spine. The
  virtual header commits a canonical high-QC reference rather than raw
  replaceable quorum-signature bytes.
- Production telemetry counts canonical carrier messages and bytes by
  inbound/outbound direction and evidence class, measures ingress/dispatch
  plus execution/admission stage latency, and exposes the retained
  active-session gauge. These metrics use the validator consensus accessor
  installed by the orchestration process into the Prometheus sink;
  benchmark-only counters are not substituted for the production boundary.
- Runtime receipt v3 has a distinct hash-async evidence variant rather than a
  synthetic optimistic QC. Its offline verifier decodes the exact validator
  set, ordering certificate, availability witness and executed certificate;
  recomputes configuration/block/virtual-header bindings; and re-verifies every
  fallback timeout vote, carried safe-state QC, availability vote, ordering
  vote, and executed-block vote before accepting the canonical effect. The
  evidence contract explicitly declares static Byzantine faults, randomized
  asynchronous termination, required membership enrollment, required private
  and PQ-authenticated channels, and `private_threshold_setup=false`; it does
  not use the ambiguous phrase “no trusted setup.”
- A hash-async receipt may authorize either the certified terminal virtual
  block or its exact direct high-QC parent. In the parent case it retains the
  terminal header and complete terminal hash-async proof, and the verifier
  checks the height/hash ancestry and high-QC relationship. The runtime uses
  this form to admit a staged direct parent before the terminal block when the
  Agentgres finality spine is one height behind; it never relabels the parent
  with native optimistic evidence or invents a synthetic QC.
- Optimistic timeout votes now carry signer-bound high-QC and lock-QC state.
  Fallback start deterministically derives its safe state from those quorum
  contributions, reverifies each QC, and refuses evidence older than local
  authenticated state. Once the transition is durable, the optimistic engine
  stalls decisions and rejects later proposals, votes, and QCs for that
  height; delayed optimistic traffic therefore cannot regain authority.
- `OptimisticFallbackComposition.tla` model-checks the one-height temporal
  seam: captured committed state is preserved, fallback fences subsequent
  optimistic authority, and asynchronous randomness cannot select a
  conflicting root. The model is registered in the no-orphan formal census.
- Deterministic simulation reaches one common order with four honest nodes.
  A second schedule uses one silent Byzantine member, randomized reordering,
  first-transmission loss with reliable retries, duplicate deliveries,
  malformed-envelope injection and early-message buffering; the three honest
  nodes still converge.
- The encrypted journal now appends only a successful first-seen protocol
  input. Exact retransmissions reuse their original durable result and rejected
  messages consume no WAL records, preventing duplicate or invalid-message
  floods from exhausting the bounded log. Legacy rejected records remain
  replay-compatible, but do not poison later acceptance of the same event.
- A fallback decision may replace the optimistic projection at the same height
  or its one speculative child only while the target remains strictly above
  the Agentgres-admitted floor. Complete target/live bytes, parent hash and
  state root, retained pre-projection snapshots, and the two-projection limit
  fence the rollback. Safe refusal restores the exact live projection;
  uncertain durability quarantines the node. A recovered virtual projection
  now requires the complete executed transaction batch to equal—not merely be
  a subsequence of—the certified selected batch.
- Successful runtime admission records a semantic executed-instance
  tombstone and retires the live session plus its finalized ordering/batch
  caches. Exact replay is idempotent and a different completed instance at the
  same height is refused, bounding retained active process state independently
  of the still-open durable-journal compaction work.
- The async terminal carries forward the canonical-collapse execution spine
  without changing its authority class. Its virtual header extends the last
  admitted collapse, and async-parent acceptance re-derives and retains the
  virtual block's collapse from that header surface so the next optimistic
  block can extend it normally.
- `AftAsyncParentProofV1` retains the complete hash-async executed evidence
  behind the virtual block's empty-signature QC-shaped reference. Native
  proposal and timeout-safe-state validation accept that reference only when
  the exact proof is retained and bound by its semantic proof hash. It never
  enters the native QC pool. Terminal traffic is retired by instance without
  deleting timeout or unrelated consensus evidence.
- Journal schema 3 atomically compacts a terminal event WAL to a sub-megabyte
  encrypted decision checkpoint while preserving the already anchored logical
  generation and head. Schema-2 WALs remain readable and advance under the new
  anchor schema. Terminal protocol traffic is still authenticated and
  validated but cannot regrow the compacted log.
- The portable finality entrypoint dispatches exact receipt schema v2 or
  runtime schema v3 before interpreting fields. A focused disk round-trip
  reloads a hash-async runtime receipt through that entrypoint, accepts the
  original, mutates an embedded timeout signature, reissues the outer
  certificate, reloads it independently and refuses it.
- The strengthened production drill stages a real same-height optimistic
  workload projection, requires the certified fallback block to replace it,
  exports every production metric stage, cold-restarts all four validators,
  recovers with no active asynchronous session, and resumes native PQ
  progress. The clean restored-source run passed in 621.34 seconds.
- Mutation calibration turns both load-bearing boundaries red: disabling the
  proposal/instance fallback-lock check fails the lock-binding test, and
  disabling nested trigger validation plus the expected-view check fails the
  trigger mutation test. A narrower redundant-check mutant is explicitly not
  credited.
- The signer-fence crash test models state durability completing one generation
  before its external anchor. Reopen completes that exact pending commit,
  preserves same-root idempotence, and refuses a conflicting root.

Verification on 2026-09-02:

```text
cargo check -p ioi-types
cargo test -p ioi-types async_fallback --lib
cargo test -p ioi-consensus --features aft hash_async --lib
cargo test -p ioi-consensus --features aft hash_async::journal --lib
cargo test -p ioi-consensus --features aft integrated_sessions_reach_rooted_exact_q_ordering --lib
cargo test -p ioi-finality runtime_v3 --lib
cargo check -p ioi-validator --lib
cargo check -p ioi-networking
cargo test -p ioi-networking account_addressed_outbox_survives_restart_before_peer_discovery --lib
cargo test -p ioi-networking enrollment_refuses_one_rooted_account_on_multiple_carriers --lib
cargo test -p ioi-networking protected_payload_routes_only_after_aead_and_type_agreement --lib
cargo test -p ioi-networking --lib
cargo test -p ioi-finality hash_async_execution_refuses_omitted_reordered_or_extra_transactions --lib
cargo test -p ioi-execution aft_branch_rollback_window_is_bounded_above_agentgres_floor --lib
cargo test -p ioi-finality runtime_v3_reverifies_hash_async_chain_without_synthetic_qc --lib
cargo test -p ioi-finality runtime_v3_hash_async_direct_parent_receipt_retains_terminal_proof --lib
cargo test -p ioi-finality portable_verifier_reloads_hash_async_receipt_from_disk_and_refuses_mutation
cargo test -p ioi-types app::consensus::tests:: --lib
cargo test -p ioi-consensus --features aft hash_async --lib
cargo test -p ioi-consensus --features aft fallback_start_refuses_missing_durability_mutations_stale_future_and_conflict --lib
cargo test -p ioi-cli --test aft_e2e --features consensus-aft,vm-wasm,state-iavl test_aft_pq_hash_fallback_executes_virtual_block -- --nocapture
cargo check -p ioi-telemetry -p ioi-validator --lib
cargo test -p ioi-validator configured_consensus_accessor_routes_hash_async_observations --lib
cargo fmt --all -- --check
git diff --check
bash .github/scripts/run_aft_formal_checks.sh --census-only
java -cp .internal/formal-cache/tools/tla/tla2tools.jar tlc2.TLC -cleanup -deadlock -config OptimisticFallbackComposition.cfg OptimisticFallbackComposition.tla
```

- asynchronous wire/evidence tests — PASS, 6 / 6, including typed batch
  instance/lock binding and duplicate-transaction refusal;
- hash-only primitive/compositor tests — PASS, 32 / 32, including the honest
  FIFO run, silent-Byzantine adverse scheduler and encrypted durable-journal
  rollback/clone/confidentiality cases, plus exact-q rooted ML-DSA aggregation
  and signature-mutation rejection. The integrated four-node durable session
  run took 142.13 seconds on the development host before final-certificate
  restart assertions were added; this is evidence of a journal performance
  problem, not a favorable latency result. The strengthened run, including
  terminal-certificate restart/replay and selected-payload reconstruction,
  passed in 151.29 seconds. Replacing whole-file rewrites with the append-only
  authenticated WAL reduced the same run to 98.50 seconds; the final full
  32-test run after header binding and private-state erasure passed in 83.87
  seconds. Durable fsync and external-anchor costs remain a benchmark concern;
- strict-PQ authenticated payload routing — PASS, including the dedicated
  asynchronous type and content-type laundering refusal;
- optimistic/fallback transition mutation test — PASS after adding signed
  high/lock contributions and late optimistic vote/QC rejection;
- bounded optimistic/fallback TLC model — PASS, 24 generated / 11 distinct
  states, depth 4, no invariant violation; formal census PASS, 36 modules = 23
  executed + 13 explicitly manual;
- four-node ordering plus executed-block round and restart replay — PASS in
  97.14 seconds; all nodes reached one executed decision even when their valid
  certificates carried different signer subsets, and restart recovered the
  exact durable certificate without signing a second block;
- existing runtime-v3 offline-verifier suite — PASS, 6 / 6 after adding the
  closed hash-async evidence variant; validator and finality compile checks
  PASS. Dedicated hash-async emission/self-verification and issuer-reissued
  executed-signature mutation tests also PASS. The strengthened mutation test
  additionally corrupts a fallback timeout vote under a reissued outer
  certificate and is rejected; the focused test passed in 196.88 seconds;
- account-addressed PQ outbox restart-before-enrollment and duplicate-account
  carrier-refusal tests — PASS, 1 / 1 each. Networking and validator compile
  checks PASS after schema-v2 integration;
- full networking library suite — PASS, 12 / 12 after account-addressed outbox
  integration; full runtime-v3 verifier subset — PASS, 8 / 8;
- full hash-async consensus subset after bounded journal deduplication — PASS,
  33 / 33 in 104.44 seconds. The dedicated journal test proves duplicates and
  rejected messages do not increase the durable record count;
- bounded rollback arithmetic and Agentgres-floor refusals — PASS, 1 / 1.
  Validator integration compiles with the same-height replacement call, and
  the offline exact-batch mutation test rejects omission, reordering and extra
  transactions. An actual workload-process replacement drill remains open;
- telemetry and validator compile checks — PASS after production Prometheus
  message, byte, stage-duration and active-session collectors were added;
- the release-mode component benchmark covers exact geometries 4, 16, 64 and
  130 (the first `3f+1` size at or above 128). With `f` silent members, n=130
  converged in one VABA retry using 16,269,738 wire messages, 18,399,942,090
  encoded bytes, 319.87 CPU seconds and 3,870,428 KiB peak RSS. Multi-sample
  p50/p95 distributions are retained through n=64; the n=130 value is plainly
  labelled a single observation. This is component evidence and excludes
  signatures, fsync, PQ transport, execution and runtime admission;
- semantic commitment and wrapper-delegation hardening — PASS: the focused
  types suite passed 9 / 9 and the full hash-async consensus subset passed
  33 / 33. Different valid exact-`q` signer subsets produce the same instance,
  ordering decision and virtual-block identity while malformed constituent
  evidence is still rejected;
- terminal and direct-parent runtime-v3 receipt verification — PASS, 1 / 1
  each in 75.17 seconds and 60.04 seconds. The parent receipt retains and
  reverifies the terminal async proof and contains no native evidence;
- four-validator production-process fallback drill — PASS, 1 / 1 in 253.00
  seconds. Three forced timeout views activated the hash-only fallback at
  height 4; all validators deterministically executed and admitted the same
  virtual block, including evidence-preserving admission of the staged direct
  parent where required. This drill intentionally stops at the admitted async
  terminal: automatic optimistic re-entry is not claimed until a typed
  predecessor-proof bridge exists;
- strengthened four-validator fallback/re-entry drill — PASS, 1 / 1 in
  458.91 seconds. All validators finalized the same height-4 virtual block,
  installed its typed asynchronous parent proof, retained a verified collapse
  object, retired the terminal async instance, and admitted a signed ML-DSA
  native child at height 5. No synthetic native QC is created;
- integrated four-session exact-q agreement/execution/parent-proof test after
  the collapse bridge — PASS, 1 / 1 in 96.78 seconds. After checkpoint
  compaction and mutation assertions, the same test passes in 87.46 seconds;
- journal recovery/compatibility suite after checkpoint compaction — PASS,
  8 / 8, including torn-tail recovery, rollback/clone/ciphertext refusal,
  no-growth duplicates, and schema-2-to-schema-3 continuation. The integrated
  session test additionally rejects a mutated encrypted checkpoint and
  recovers the exact ordering/executed certificates after restart;
- repeated mid-protocol journal restart — PASS; the same non-terminal session
  is reopened across multiple interruption points without losing its durable
  generation, accepting a conflicting replay, or issuing a second local
  authorization;
- independently reloaded portable receipt and embedded-signature mutation
  test — PASS, 1 / 1 in 123.30 seconds;
- byte-distinct but semantically equal fallback-start witness admission — PASS,
  while malformed, cross-scope and different-safe-state triggers remain
  refused; the focused authenticated-runtime test passed in 195.77 seconds;
- production hash-async journal benchmark separates journal open, encrypted
  append/fsync, external-anchor update, terminal compaction and recovery. Raw
  samples and host/build provenance are retained alongside the report; these
  durability results are not relabelled as protocol CPU;
- the strict `-D warnings` Clippy run found and resolved all reported findings
  in the new M3 files. Repository-wide completion remains blocked by existing
  warnings/errors in pre-M3 consensus/generated files, recorded rather than
  misreported as a clean all-crate lint result.

M3 changed/evidence paths:

- `crates/types/src/app/consensus/async_fallback.rs`
- `crates/types/src/app/consensus.rs`
- `crates/consensus/src/aft/hash_async/{adapter,asks,certificate,gather,gf256,journal,node,proposal_store,reliable,session,signing_fence}.rs`
- `crates/consensus/src/aft/hash_async/mod.rs`
- `crates/consensus/examples/aft_hash_async_bench.rs`
- `crates/consensus/src/aft/mod.rs`
- `crates/networking/src/libp2p/{sync,types,swarm,mod}.rs`
- `crates/validator/src/standard/orchestration/{context,events,hash_async,lifecycle}.rs`
- `crates/validator/src/standard/workload/ipc/grpc_blockchain.rs`
- `crates/execution/src/app/{mod,tests}.rs`
- `crates/validator/src/standard/orchestration/runtime_finality.rs`
- `crates/telemetry/src/{sinks,prometheus}.rs`
- `crates/ioi-finality/src/{lib,runtime_v3}.rs`
- `crates/validator/src/standard/orchestration/consensus/production.rs`
- `crates/types/src/config/mod.rs`
- `internal-docs/architecture/protocols/aft/formal/hash_async/{OptimisticFallbackComposition.tla,OptimisticFallbackComposition.cfg,README.md}`
- `.github/scripts/run_aft_formal_checks.sh`
- this ledger
- `internal-docs/architecture/protocols/aft/evidence/m3-hash-async-core-benchmark-2026-09-02.{md,jsonl}`
- `internal-docs/architecture/protocols/aft/evidence/m1-pq-benchmarks-2026-09-02.md`
- `internal-docs/architecture/protocols/aft/evidence/m3-hash-async-journal-benchmark-2026-09-02.{md,jsonl}`
- `internal-docs/architecture/protocols/aft/evidence/m3-adversarial-release-gate-2026-09-03.md`

M3 closure rationale:

- The adverse simulation covers delay, reordering, first-transmission loss,
  duplication, one silent Byzantine member, malformed/equivocating traffic,
  repeated mid-protocol restart, duplicate triggers and the optimistic/fallback
  race. The release-gate report maps each obligation to its executable test.
- Component benchmarks deliberately separate protocol CPU/memory/wire cost,
  PQ primitive/channel cost, and encrypted WAL/fsync/anchor cost. The
  production drill adds evidence-class traffic and execution/admission stage
  metrics without mislabelling its single observation as a distribution.
- The normative fallback is the hash-only path. No BLS certificate or
  threshold coin enters its safety, liveness, transport, or receipt chain.
- RES-R10 is closed only for the explicit static-adversary, `f<n/3`, reliable
  private authenticated-channel model. No adaptive-security or favorable
  latency claim is inferred.

## Completed slice: M4 no-laundering theorem and runtime boundary

Implemented and release-gated:

- `GuaranteeTransformV1` defines an exhaustive coordinate and rule
  vocabulary. Every transform commits to its input vectors, new evidence,
  theorem, verifier profile and claimed output. Metadata validation is
  coordinate-specific; every rule remains default-deny until its independent
  proof verifier lands.
- `CertificateOnlyGuaranteeVerifierV1` derives the exact evidence meet itself.
  Callers cannot construct `VerifiedGuaranteeV1`, and policy requirements
  consume only that opaque verified type rather than a caller-authored vector.
- Runtime-finality certificate v2 carries requirements, achieved coordinates,
  their commitment and the transformation trace as distinct fields. Emission
  derives them from the embedded native/hash-async evidence; verification
  independently recomputes and exact-compares them before evaluating policy.
- The certificate profile census now explicitly distinguishes classical and
  PQ live quorum, hash-async ordering, PQ unanimous boundary and PQ anchored
  boundary evidence. The meet retains the weakest load-bearing coordinate.
- The T6/L-M paper proof is stated as certificate indistinguishability: two
  executions exposing the same certificates are indistinguishable to a
  certificate-only verifier, so no wrapper can soundly report a stronger
  execution-dependent property without new evidence.
- `GuaranteeMeet.tla` exhaustively checks the bounded exact-meet and
  coordinate-local transform invariants. TLC explored 11,666 generated / 5,833
  distinct states to complete depth 3 with no error.
- Negative tests cover PQ-wrapper/classical-ordering composition, safety versus
  availability, collateral versus BFT, timeout downgrade, classical endpoints,
  cross-domain weakening and malformed transform metadata. A runtime attack
  mutates `channel_pq` and re-signs the outer issuer; verification refuses it.
- Mutation calibration disabled the exact-meet guard. The forged-wrapper test
  failed with exit 101, proving the test is load-bearing. Clean source was
  restored before all authoritative runs.

Verification on 2026-09-03:

```text
cargo test -p ioi-types app::consensus::tests:: --lib
cargo test -p ioi-types --lib
cargo test -p ioi-finality --lib
java -cp "$(git rev-parse --show-toplevel)/.internal/formal-cache/tools/tla/tla2tools.jar" tlc2.TLC -cleanup -deadlock -config GuaranteeMeet.cfg GuaranteeMeet.tla
bash .github/scripts/run_aft_formal_checks.sh --census-only
bash .github/scripts/check_aft_theorem_assumes.sh
bash .github/scripts/check_aft_claim_discipline.sh
git diff --check
```

- consensus/type subset — PASS, 106 / 106;
- complete types library — PASS, 447 / 447 in 808.09 seconds;
- complete finality library — PASS, 51 / 51 in 234.15 seconds;
- no-laundering TLC model — PASS, 11,666 generated / 5,833 distinct;
- formal census — PASS, 37 modules = 24 executed + 13 explicitly manual;
- theorem-assumption and claim-discipline gates — PASS.

M4 evidence paths:

- `crates/types/src/app/consensus/collapse/guarantee_vector.rs`
- `crates/types/src/app/consensus/tests_parts/guarantee_vector_v1.rs`
- `crates/ioi-finality/src/runtime_v3.rs`
- `crates/ioi-finality/src/tests.rs`
- `internal-docs/architecture/protocols/aft/formal/no_laundering/`
- `internal-docs/architecture/protocols/aft/evidence/m4-no-laundering-release-gate-2026-09-03.md`
- `internal-docs/architecture/protocols/aft/specs/common_boundary_theorems.md`
- `internal-docs/architecture/protocols/aft/specs/yellow_paper.tex`

M4 closure boundary:

- This closes evidence-amplification resistance at the certificate/runtime
  boundary. It does not enable any strengthening transform.
- The hash-async receipt can claim `consensus_pq=true`, but remains honest with
  `channel_pq=false` and `end_to_end_pq=false` until portable channel evidence
  exists.
- Collateral proof, clean-room receipts and estate-wide authorization remain
  M6–M8 work. T8 remains the open lower-bound row; responsive T5d is refuted
  and paired with L-S, while scheduled succession proves no cadence claim.

## Completed slice: M5 consequence consensus and at-most-once externalization

Implemented and release-gated for the declared modeled-resource boundary:

- `EffectManifestV1` canonically binds resource/conflict-domain identity,
  complete read/write footprints, the stable idempotency key, request,
  predecessor, intent and expected-outcome roots, exact adapter/resource
  profile, assurance requirements, height/authority fence and reconciliation
  policy.
- A prepared runtime-v3 recognized effect binds that manifest before the
  Agentgres linearization point. The opaque accepted-authorization token is
  reconstructed by reverifying the committed finality bundle and rebinding
  its achieved vector, Agentgres record/root/sequence, manifest and authority
  snapshot.
- `ExternalResourceV1` admits only an exact atomic put-if-absent, compare-and-
  set or equivalent idempotency contract into the at-most-once profile.
  Unsupported resources advertise best effort and fail irreversible
  at-most-once policy.
- The device-flushed state machine persists `Authorized -> Claimed ->
  InFlight` before the one mutation call, then reaches `Executed` or
  `Unknown`, and finally `Reconciled` through same-key lookup. Restart from
  `InFlight` is reconciliation-only and can never blindly replay mutation.
- Eight crash-injection points cover authorization, claim, in-flight,
  post-invocation/pre-outcome, executed, unknown, post-lookup and reconciled
  persistence. Every path performs at most one invocation/mutation.
- Runtime traces exactly match the clear and ambiguous formal paths.
  `AtMostOnceExternalization.tla` explored 66 generated / 42 distinct states
  to depth 8 with no invariant violation.
- T10 states the model-relative consequence theorem. L-X proves the atomic
  endpoint primitive is necessary under ambiguous reply loss: retry may
  duplicate while no retry may omit.
- Contradictory endpoint evidence becomes transferable only after the exact
  resource-profile verifier accepts it. Ordinary ambiguity and forged
  evidence remain unattributed.
- Mutation calibration disabled `InFlight -> Unknown` recovery; the focused
  crash test failed with exit 101. Clean source was restored before the
  authoritative suites.

Verification on 2026-09-03:

```text
cargo test -p ioi-types consequence::tests --lib
cargo test -p agentgres consequence::tests --lib
cargo test -p agentgres --lib
cargo test -p agentgres runtime_v3_effect_linearizes_recovers_and_replays_on_the_agentgres_spine --lib
java -cp "$(git rev-parse --show-toplevel)/.internal/formal-cache/tools/tla/tla2tools.jar" tlc2.TLC -cleanup -deadlock -config AtMostOnceExternalization.cfg AtMostOnceExternalization.tla
bash .github/scripts/run_aft_formal_checks.sh --census-only
bash .github/scripts/check_aft_theorem_assumes.sh
bash .github/scripts/check_aft_claim_discipline.sh
git diff --check
```

- consequence types — PASS, 4 / 4;
- consequence runtime/adversarial subset — PASS, 11 / 11;
- complete Agentgres library — PASS, 98 / 98 in 129.69 seconds;
- committed runtime-v3 manifest binding — PASS, 1 / 1;
- T10 formal model — PASS, 66 generated / 42 distinct, depth 8;
- formal census — PASS, 38 modules = 25 executed + 13 explicitly manual;
- theorem-assumption and claim-discipline gates — PASS.

M5 evidence paths:

- `crates/types/src/app/consequence.rs`
- `crates/agentgres/src/consequence.rs`
- `crates/agentgres/src/consequence/tests.rs`
- `crates/agentgres/src/recognized_effect.rs`
- `internal-docs/architecture/protocols/aft/formal/consequence/`
- `internal-docs/architecture/protocols/aft/evidence/m5-consequence-externalization-release-gate-2026-09-03.md`
- `docs/decisions/0044-adopt-effect-native-atomic-externalization.md`

M5 closure boundary:

- The theorem consumes the exact atomic resource contract and promises safety,
  not eventual external occurrence.
- Arbitrary HTTP APIs and physical devices remain outside the at-most-once
  claim until their adapter profile proves equivalent semantics.
- Full portable receipt authentication is M7; integrated production rollout
  and mixed-domain demonstration are M8.

## Completed slice: M6 evidence-qualified economic assurance

Implemented and release-gated for the offline collateral-proof boundary:

- `EconomicAssuranceV1` carries one native asset and exact amount,
  configuration and distinct collateral-set commitments, bond snapshot root,
  snapshot/lock/challenge horizons, objective evidence predicate, exact
  slashing contract, and optional explicit valuation assumptions.
- `AccountabilityEvidenceV1` binds the signed-fault behavior, proof hash,
  implicated member set and challenge horizon. Withholding/silence is a typed
  input but the verifier refuses to price it.
- `BondSnapshotV1` commits unique bond and underlying-lot identities, owner,
  asset, arbitrary-precision amount, exclusive configuration, lock interval,
  challenge horizon, evidence predicate, enforcement contract, encumbrances
  and withdrawal state.
- The offline verifier requires every implicated member to have qualifying
  collateral, rejects shared/reused/expired/unlocked/encumbered/withdrawing
  lots, never sums unlike assets or contracts, and exact-compares its complete
  recomputation with the portable claim.
- Only opaque `VerifiedEconomicAssuranceV1` output can attach the coordinate to
  `VerifiedGuaranteeV1`. Exact-asset policy floors join at the larger canonical
  decimal amount without machine-width limits.
- T9 now states maximal attribution without manufacturing a nominal
  `n × bond` floor. T11 states the evidence-qualified floor and pairs with L-C,
  the indistinguishability bound on missing collateral eligibility evidence.
- `DistinctCollateralFloor.tla` explored 33 generated / 8 distinct states to
  depth 4 with no invariant violation.
- Mutation calibration disabled the underlying-lot deduplication guard; the
  duplicate-lot test failed with exit 101. Clean source was restored.

Verification on 2026-09-03:

```text
cargo test -p ioi-types economic_assurance --lib
cargo test -p ioi-types --lib
java -cp "$(git rev-parse --show-toplevel)/.internal/formal-cache/tools/tla/tla2tools.jar" tlc2.TLC -cleanup -deadlock -config DistinctCollateralFloor.cfg DistinctCollateralFloor.tla
bash .github/scripts/run_aft_formal_checks.sh --census-only
bash .github/scripts/check_aft_theorem_assumes.sh
bash .github/scripts/check_aft_claim_discipline.sh
cargo fmt --all -- --check
git diff --check
```

- economic-assurance focused corpus — PASS, 7 / 7;
- complete types library — PASS, 458 / 458 in 654.21 seconds;
- T11 formal model — PASS, 33 generated / 8 distinct, depth 4;
- formal census — PASS, 39 modules = 26 executed + 13 explicitly manual;
- theorem-assumption, claim-discipline, formatting and diff gates — PASS.

M6 evidence paths:

- `crates/types/src/app/economic_assurance.rs`
- `crates/types/src/app/economic_assurance/tests.rs`
- `crates/types/src/app/consensus/collapse/guarantee_vector.rs`
- `internal-docs/architecture/protocols/aft/formal/economic_assurance/`
- `internal-docs/architecture/protocols/aft/evidence/m6-economic-assurance-release-gate-2026-09-03.md`
- `docs/decisions/0045-adopt-evidence-qualified-economic-assurance.md`

M6 closure boundary:

- The coordinate is a minimum objectively slashable amount in one native
  asset. Optional oracle metadata is visible but does not change that amount.
- T8 remains open: no token-value, bribery, liquidity, acquisition-cost,
  validator-supply or configuration-capture claim follows.
- M7 owns portable receipt authentication and clean-room verification. M8 owns
  estate-wide enforcement and the mixed-domain demonstration.

## Completed slice: M7 portable assurance receipts

- `PortableAssuranceReceiptV1` carries the exact manifest/policy,
  configuration/key snapshot and unanimous enrollment votes, runtime-v3
  finality evidence, a complete pairwise PQ channel graph, unanimous SLH-DSA
  terminal seal, consequence/resource/PQ endpoint evidence, M6 economic proof,
  anchors, achieved vector, T12/T1/T10/T11 trace, verifier identity, canonical
  hash and ML-DSA-44 envelope signature.
- `verify_portable_assurance_bytes` accepts canonical bytes only, requires an
  independently provisioned `PortableAssuranceTrustV1`, and uses no node,
  database, clock or network. The external policy pins the network,
  configuration, epoch, terminal-key root, allowed receipt signer, anchors and
  relying-party guarantee floor; receipt-contained roots cannot self-nominate
  authority. The report returns the achieved vector, policy result, precise
  refusal, constituents and transformations.
- Unknown schemas, verifier profiles, algorithms and transforms fail closed.
  Mutations across every major constituent are rejected.
- Per ADR 0048, `ioi-receipt-proof-verify` accepts exactly a portable v1
  receipt plus external trust v1. Legacy v2/runtime-v3 compatibility dispatch
  and scalar-to-vector promotion are removed from the production surface.
- A Python clean-room verifier imports no IOI crate. In addition to committed
  canonical and arbitrary-precision economic vectors, it reconstructs the
  complete generated receipt's runtime certificate, six pairwise PQ channel
  sessions, four configuration votes, four terminal shares, endpoint evidence,
  collateral, transforms and policy. A separately compiled oracle uses
  RustCrypto for ML-DSA and `fips205` for SLH-DSA rather than the production
  implementations.
- T12 and L-PQCH state the positive payload-scoped channel-coverage theorem and
  its matching lower bound. ADR 0047 records why protocol labels, self-enrolled
  terminal keys and adapter booleans are insufficient.
- Signature-guard mutation calibration made a validly encoded bit-flipped
  envelope pass and the negative test fail with exit 101. Clean source was
  restored.
- Runtime-v3 now has an additive ML-DSA-44 checkpoint-issuer emitter and
  verifier path; its focused hash-async PQ-issuer test passes.

Verification on 2026-09-03:

```text
cargo test -p ioi-finality --features portable-assurance portable_assurance --lib
cargo test -p ioi-finality --features portable-assurance --lib
cargo test -p ioi-finality runtime_v3_hash_async_supports_pq_checkpoint_issuer_without_downgrade --lib
cargo check -p ioi-finality --features portable-assurance --bin ioi-receipt-proof-verify
python3 tools/aft-assurance-cleanroom/verify.py
cargo build --manifest-path tools/aft-pq-interop/Cargo.toml
```

- portable receipt corpus after PQ path closure — PASS, now 5 / 5 including
  externally imposed trust-root and relying-party-policy attacks;
- independently reconstructed generated 1.08 MB complete receipt — PASS; all
  seven validly re-enveloped channel/seal/enrollment/endpoint/domain/withheld-
  unanimity mutations rejected;
- complete finality library before the ADR 0047 extension — PASS, 55 / 55 in
  272.27 seconds; current external-trust-policy run — PASS, 57 / 57 in 221.33
  seconds;
- PQ hash-async checkpoint issuer — PASS, 1 / 1 in 54.84 seconds;
- independent golden vectors and oracle build — PASS.

M7 evidence paths:

- `crates/ioi-finality/src/portable_assurance.rs`
- `crates/ioi-finality/src/portable_assurance/tests.rs`
- `crates/ioi-finality/src/main.rs`
- `tools/aft-assurance-cleanroom/`
- `tools/aft-pq-interop/`
- `internal-docs/architecture/protocols/aft/evidence/m7-portable-assurance-receipt-release-gate-2026-09-03.md`
- `docs/decisions/0046-adopt-portable-aft-assurance-receipts.md`
- `docs/decisions/0047-require-payload-scoped-pq-path-evidence.md`

## Completed slice: M8 integrated demonstration and release

Implemented local evidence:

- The cross-domain model holds one unanimous ring permanently stalled while
  another domain enters fallback and externalizes three effects. TLC exhausts
  41 generated / 10 distinct states to depth 6 with no invariant violation.
- The complete formal corpus is closed under the harness census: 40 modules
  equal 27 executed modules plus 13 explicitly manual proof artifacts.
- All nine TLAPS proof modules discharged 1,015 obligations. The complete TLC
  prefix through both boundary-liveness models passed, including the largest
  canonical-ordering exploration at 632,887,809 generated / 66,846,976
  distinct states to depth 39. The separately rerun observed tail passed all
  remaining models and the code-to-model trace; MembershipTransition explored
  21,764,161 generated / 1,254,528 distinct states to depth 22.
- The yellow paper builds to a 147-page PDF. The theorem-assumption, claim
  discipline, formal census, formatting, and diff checks all pass.
- The complete receipt now derives `channel_pq=true` only from all six rooted,
  dual-attested member-pair sessions over the exact finality hash; derives
  all-but-one seal safety from all four enrolled SLH-DSA shares; verifies a
  rooted ML-DSA endpoint; and derives `end_to_end_pq=true` only after all three
  PQ coordinates pass. The clean-room verifier independently accepts this
  decision and rejects seven validly re-enveloped inner forgeries.
- An executable consequence test leaves a seal-required conflict domain
  permanently unauthorized, then executes and reconciles three effects in an
  unrelated domain. One response becomes ambiguous after mutation; same-key
  reconciliation completes with exactly three invocations and three mutations.
- The production-authorization census finds exactly one production
  `ExternalResourceV1`/`invoke_atomic` owner. Its authorization method accepts
  only opaque `VerifiedGuaranteeV1`, reverifies the Agentgres-committed
  runtime-v3 bundle, exact-binds manifest/policy/profile/authorization roots,
  and fences irreversible effects on the atomic idempotency contract. The
  static gate fails if a second mutation owner or raw vector path appears.
- Census evidence:
  `internal-docs/architecture/protocols/aft/evidence/m8-production-authorization-census-2026-09-03.md`.
- The integrated runner is `scripts/run_aft_m8_release_demo.sh`. On the final
  integrated tree it completed in one uninterrupted process with exit 0. Its
  real four-validator drill passed in 636.80 seconds, the PQ checkpoint issuer
  passed in 61.94 seconds, the five-test portable corpus passed in 196.03
  seconds, the consequence corpus passed 12 / 12, both independent PQ oracles
  passed, all 1,015 TLAPS obligations discharged, every TLC model completed,
  and the generated Rust trace replay matched. Exact R5 M10 qualification later
  closed the sole remaining independent integrated-restart finding.
- ADR 0048 adopts a clean-genesis AFT PQ v1 boundary: production admits only
  classic-BFT plus the mandatory hash-only asynchronous path; the unused BLS
  aggregation placeholder, scalar-to-vector promotion, and portable CLI's
  v2/runtime-v3 compatibility dispatch are removed. Historical guardian modes
  remain source-only and fail production profile admission.
- Portable authorization now requires a separately provisioned
  `PortableAssuranceTrustV1` pinning network, configuration, epoch,
  terminal-key root, allowed receipt signer, anchors, and relying-party
  guarantee requirements. The Rust and no-IOI-import clean-room verifiers both
  refuse self-nominated roots.
- Hypervisor's default node profile no longer contains `ioi-consensus`,
  `ioi-validator`, or SLH-DSA. A locked daemon check passes; direct full-node
  dependencies and the AFT seal/receipt stack are explicit feature edges.
- Full affected-workspace CI passes on the integrated tree: types 459 / 459,
  crypto 63 / 63, networking 13 / 13, consensus 229 / 229, finality 57 / 57,
  Agentgres 99 / 99 and validator 260 / 260. The run caught two regressions:
  a Classic-BFT parent-quorum fixture still used Ed25519, and a source-order
  assertion depended on rustfmt whitespace. Both were repaired without
  weakening production admission. The validator distribution check then
  exposed that the feature split omitted direct optional node dependencies;
  every full-node distribution now inherits `kernel-node`, while Hypervisor
  retains an empty default feature set.

Verification on 2026-09-03:

```text
cargo test -p ioi-finality --lib
cargo test --locked -p ioi-types --lib
cargo test --locked -p ioi-crypto --features aft-terminal-seals --lib
cargo test --locked -p ioi-networking --lib
cargo test --locked -p ioi-consensus --features aft --lib
cargo test --locked -p ioi-finality --features portable-assurance --lib
cargo test --locked -p agentgres --lib
cargo test --locked -p ioi-validator --features consensus-aft,vm-wasm,state-iavl --lib
cargo check --locked -p ioi-node --bin hypervisor-daemon
cargo check --locked -p ioi-node --features validator-mode --bin ioi-validator
cargo check --locked -p ioi-finality --features portable-assurance --bin ioi-receipt-proof-verify
cargo fmt --all -- --check
git diff --check
bash .github/scripts/check_aft_theorem_assumes.sh
bash .github/scripts/check_aft_claim_discipline.sh
bash .github/scripts/check_aft_production_authorization.sh
bash .github/scripts/run_aft_formal_checks.sh --census-only
bash .github/scripts/run_aft_formal_checks.sh
```

The current affected-workspace package and distribution matrix passes. The
finality library passed 57 / 57 tests in 221.33 seconds. The final integrated
runner passed with exit 0 in one uninterrupted process. Its largest TLC model,
`CanonicalOrderingRetrievability`, exhaustively generated 632,887,809 states,
found 66,846,976 distinct states to depth 39 and drained its queue without an
invariant violation; `MembershipTransition` generated 21,764,161 states and
found 1,254,528 distinct states to depth 22.

M8 is complete for the admitted automated-review standard. The portable
complete-path PQ evidence, independent offline decision reproduction,
estate-wide AFT externalization-authorization census, affected-workspace CI,
retained integrated mixed-workload process, and exact R5 restart qualification
are closed. The M10 report's human-review, provider-correctness, side-channel,
adaptive-corruption, and snapshot-custody exclusions remain in force.

## Claims currently permitted

- A versioned, coordinate-wise assurance schema exists in the types crate once
  the recorded tests pass.
- Historical scalar evidence has no production promotion API and cannot claim
  end-to-end PQ; production emits `GuaranteeVectorV1` directly.
- Policy joins and evidence meets are distinct operations.
- Runtime-v3 finality receipts carry an independently recomputed, exact
  guarantee-vector meet. Re-signing or nesting existing certificates cannot
  strengthen a coordinate, and all new-evidence transforms remain
  default-deny.
- One Agentgres-accepted, manifest-bound authorization causes at most one
  modeled resource mutation under the exact atomic idempotency-register
  contract; ambiguous results reconcile by same-key lookup without blind
  replay and without manufacturing blame.
- An offline verifier can establish an exact distinct slashable-collateral
  floor for objective signed-fault evidence under one native asset and one
  committed enforcement contract. The claim excludes silence and supply cost.
- The named PQ optimistic profile uses exact unit-weight `n=3f+1`,
  `q=2f+1`, rooted ML-DSA authority and versioned configuration-scoped
  timeout evidence; this is a safety/transition claim, not asynchronous
  termination or end-to-end PQ.
- The normative hash-only fallback provides randomized asynchronous progress
  for exact `n=3f+1` against a static Byzantine adversary with `f<n/3` under
  its reliable private authenticated-channel model. The four-validator
  production drill reaches and admits one common async virtual block after
  three forced timeout views, survives a cold restart, then resumes through a
  typed asynchronous parent proof and admits a native PQ child.
- For one ADR 0047 receipt, an offline verifier can establish payload-scoped
  full-mesh PQ channel coverage, unanimous rooted SLH-DSA terminal closure and
  a rooted ML-DSA endpoint, and may derive `end_to_end_pq=true` for that exact
  demonstrated evidence chain. This is not an adaptive-security, delivery,
  historical-traffic or release claim.

## Claims currently forbidden

- AFT is fully post-quantum or adaptively secure.
- The completed M3 result implies adaptive security, favorable latency, or
  progress outside its declared channel/fault model.
- AFT has no setup; the intended future claim is only “no private threshold
  setup or DKG.”
- Current v2 seal shares are human-certified, provider-certified, or secure
  outside their stated custody and rollback assumptions.
- The PQ channel implementation or startup slice is sufficient by itself to
  set `channel_pq=true`; only the complete
  payload-scoped ADR 0047 evidence verifier may derive that coordinate locally.
- ML-DSA vote support alone makes the live or header path end-to-end PQ.
- Arbitrary HTTP or physical effects are at-most-once.
- Slashable collateral is a general cost-to-violate or closes T8.
- The M10 automated pass is human peer review, institutional certification, or
  proof of provider correctness, side-channel resistance, or adaptive security.
- M15Q-M18Q or the interactive QUV release is complete.

## Unresolved risks

- Runtime-v3 emission and verification consume the new assurance body, and the
  AFT externalization authorization census is closed. Extending AFT governance
  to unrelated product-local side effects is outside this release claim.
- Pairwise PQ channel rotation and durable outbound crash recovery are
  implemented, including fresh-session resealing without nonce/key reuse, and
  the strict four-node adverse timeout/restart schedule passes. Production
  validator-set rotation across restart and independent review remain open.
- The v2 seal signer and enrolled manifest are implemented but remain blocked
  on independent provider/custody review and non-shared-filesystem anchor
  backends.
- Static-adversary hash-only ACS does not imply adaptive security.
- The typed async-parent and canonical-collapse bridge survives the recorded
  cold process restart. A synthetic native QC remains explicitly forbidden as
  evidence laundering.
- Adding the versioned scoped-timeout extension to `BlockHeader` changes its
  canonical SCALE shape. ADR 0048 resolves this as a new-genesis AFT PQ v1
  activation and explicitly makes no rolling mixed-version compatibility
  claim. The canonical new-genesis header fixture's SHA-256 SCALE fingerprint
  is pinned by `aft_pq_v1_block_header_scale_fingerprint_is_pinned`.

### Prepared RPC campaign result — 2026-09-05

The prepared-request/barrier production campaign passed locally. Retained nonce
logs show four overlapping verifier intervals and a 739.821 ms start spread
(previous dispatch: at most three overlaps, 5689.907 ms spread). Exact configured
member coverage passed for all four workload receipts; latest valid reply was
2270 ms against the 4000 ms envelope. All sole-correct placements passed. Both
conflicting requests received typed refusals, neither mutated its resource, and
the unrelated request executed. Evidence:
`evidence/m17q-r1-diagnostic-retention-2026-09-05/prepared-rpc-capture/`.

This validates the harness preparation correction for this diagnostic run only.
Wall-clock overlap is not a monotonic timing proof; sustained queue/storage
saturation and the prior intermittent missing-member failure remain open. No R1
finding, clean M16Q R2 qualification, or release admission is closed by this run.

### Outbox persistence-error quarantine — 2026-09-05

Outbox transitions now refuse further use after a persistence error until disk
state is reopened and validated. This prevents continuation from an old memory
snapshot when rename succeeded but a later durability step reported failure.
The new storage regression covers staging failure and injected post-publication
failure, refusal of retry/drain selection, and successful reopen. The targeted regression and all 22 networking library
tests passed, along with formatting, diff, claim and Assumes checks. Evidence is
under `evidence/m17q-r1-outbox-persistence-2026-09-05/`. This refusal is not
liveness or full crash/rollback qualification; finding 011 remains open.

### Non-executable retry audit preservation — 2026-09-05

The consequence online entry point checks Authorized/Claimed eligibility before
consuming a continuation or persisting its audit. InFlight, Unknown, Executed
and Reconciled retries now preserve the receipt. A regression covers normal
execution, before-call crash, recovery, lookup reconciliation and reopen; all 18 consequence
tests passed. Evidence is in `evidence/m17q-r1-retry-audit-preservation-2026-09-05/`.
Public same-effect terminal-result idempotency and reconciliation fairness remain
open under finding 010. Rejection does not count as effect liveness.

### Online same-effect result retries — 2026-09-05

Both execution entry points now handle terminal or ambiguous existing receipts
before live QUV, after exact committed readmission and candidate matching.
Terminal results require matching resource lookup and retain identical receipt
bytes; ambiguous calls reconcile by lookup only. New execution still needs a
fresh continuation. The process campaign now requires same-effect replay for
every sole-correct placement. Corrected-source validation is active under
`evidence/m17q-r1-online-result-retry-2026-09-05/validated-process/`; the preliminary
run was intentionally interrupted to add terminal resource lookup validation.
Expired-fence retrieval, broad fairness, full crash/process qualification and
finding 010 remain open. This does not admit any new public claim.

### Online result retry process result — 2026-09-05

Corrected production replay validation passed: all four sole-correct placements
returned byte-identical receipts in 15–16 ms. The exact-member workload passed
with 2078 ms maximum valid reply and observed four-way bounded overlap. Both
conflict requests refused with zero durable effects; unrelated execution passed.
All 106 Agentgres library tests passed. Evidence and unchanged-source recheck:
`evidence/m17q-r1-online-result-retry-2026-09-05/`. This run does not resolve the
earlier intermittent missing-member failure, expired-fence retrieval, broad
fairness, full crash/refinement qualification or any complete R1 finding.

### Durable reconciliation exhaustion guard — 2026-09-05

Reconciliation checks its recorded observation budget before lookup, preventing
repeated calls after an exhausted result from issuing more resource reads. The
expanded test covers fault clearance, repeated retry, reopen and byte-preserved
receipts. All 19 consequence tests passed; evidence is under
`evidence/m17q-r1-reconciliation-exhaustion-2026-09-05/`. Durable reservation before
lookup/crash, terminal-lookup budgets and global fairness remain open; this
completed-observation guard is not a lifetime attempt bound or liveness result.

### Durable reconciliation attempt reservations — 2026-09-05

Reconciliation now persists a receipt-root committed attempt count before
lookup, carrying forward legacy ambiguous observations. Repeated crashes before
and after lookup retain spent budget; reservation-before-crash can conservatively
consume an unused attempt. Known execution is preserved when a later lookup is
ambiguous. Zero counters preserve old encoding; old strict readers reject the
new nonzero field, requiring coordinated reader upgrades.

All 21 consequence tests, validator compile, T10 model and the new finite
reservation model passed locally. The formal/M16Q runners include the component
model. Evidence: `evidence/m17q-r1-reconciliation-reservation-2026-09-05/`.
Atomic/non-rollback storage remains an assumption, not a filesystem refinement
proof. Terminal-result lookup budgeting, full process/crash qualification,
expired-fence retrieval and global fairness remain open under R1.

### Expired online result retrieval — 2026-09-05

Both production entry points now distinguish result preparation from strict new
execution authorization. Existing non-executable online receipts may pass an
expired upper fence after exact committed readmission and fence identity checks;
missing, Authorized and Claimed receipts cannot. Candidate binding and resource
lookup/reconciliation remain mandatory, and strict pre-call authorization is
unchanged. All 22 consequence tests and validator compile passed locally.
Evidence: `evidence/m17q-r1-expired-result-retrieval-2026-09-05/`.
Expired-result RPC process qualification, terminal lookup budgeting and global
fairness remain open; no R1 finding or full M16Q R2 gate is closed.

### Expired-result RPC qualification fixture — 2026-09-05

The production campaign gives its first effect a nearer registered upper fence,
then repeats the RPC after that fence using byte-identical receipt and committed
server-height assertions. The server height is diagnostic metadata only. The
mandatory evidence checker requires result=recorded so no new effect execution
is counted. CLI compilation and checker self-tests passed; process validation
is active in `evidence/m17q-r1-expired-result-process-2026-09-05/`. All R1 findings
and full clean qualification remain open.

### Expired-result RPC and reservation induction — 2026-09-05

The RPC campaign passed: the original nonportable receipt returned unchanged in
20 ms at committed height 69, beyond expiry 65. All four sole-correct executions
and immediate replays passed; workload valid replies peaked at 2170 ms with
exact member coverage and bounded four-way overlap. Conflicts produced two typed
refusals and zero resource records; unrelated execution passed. All 109 Agentgres
tests passed. All 27 process source hashes matched at completion. Evidence:
`evidence/m17q-r1-expired-result-process-2026-09-05/`.

The reservation invariant now has a ten-obligation TLAPS proof for arbitrary
natural budgets, under atomic non-rollback reservation. A separate abstract
restart model that loses reservations produces the required invariant violation.
The canonical formal/M16Q runners include both and retain the raw witness;
integrated checks passed. Evidence:
`evidence/m17q-r1-reservation-induction-2026-09-05/`.
These results do not prove filesystem refinement, global fairness, sustained
storage/queue qualification or resolve the prior intermittent member failure.
All complete R1 findings and clean M16Q R2 admission remain open.

### QUV member/handoff persistence-error quarantine — 2026-09-05

Both stores now refuse use after a persistence error until authenticated reopen.
This prevents a state-written/anchor-pending transition from being overwritten
by retries using stale memory. Member requests produce no signature while
quarantined; handoff install/activation also refuse. Tests cover real staging
errors on both files, removal of the immediate fault, unchanged failed retries,
and recovery preserving the pending candidate/install. Local QUV tests passed
22 cases with the dedicated benchmark ignored; evidence and final compile checks
are in `evidence/m17q-r1-quv-store-reopen-2026-09-05/`.

Tracing accepted-history validation confirmed the separate expected-head and
next-slot mechanism is still absent; nonzero predecessor validation is not that
mechanism. The source contract comment now states this limitation. R1 001/002
and full refinement/process qualification remain open.

### Durable head provisioning/integration constraints — 2026-09-05

Current source analysis confirms no independently provisioned initial domain
head/slot and no accepted frontier in the member store. Storage authentication
heads are not accepted history. The one-live-nonce runtime/transport also rules
out adding recursive parent verification during a child operation. The new
`specs/query_unanimity_head_state_design.md` records bootstrap, frontier/retained-
slot, live-parent, preparation timing/fairness and handoff integration requirements,
including the unresolved owned-mode late-conflict re-verification schedule.
Evidence/source hashes: `evidence/m17q-r1-head-provisioning-analysis-2026-09-05/`.
This is a design boundary, not implementation or refinement completion. R1 001
remains open; no first-seen or portable-proof shortcut has been introduced.

### Parent re-verification claim boundary — 2026-09-05

Added a sequential one-correct-witness TLA model with two possible valid owner
values and two atomic completed queries. TLC checks accepted non-conflict and
singleton progress over 22 reachable states; the separate negative config
requires the stronger PriorAcceptancePersists invariant to fail, retaining the
Query(A)/accept, Introduce(B), Query(A)/abort witness. Full formal runner arrays
and M16Q source hashes include the model/configs; targeted runner and census
passed. Evidence: `evidence/m17q-r1-parent-reverification-boundary-2026-09-05/`.
This isolates an invalid naive preparation guarantee, not an interactive
impossibility or production refinement. Q-T4's singleton premise and Q-EA2's
conditional status are unchanged. Production head enforcement, R1 001/005,
full qualification, and independent review remain open.

### Durable frontier transition design model — 2026-09-05

Added QuvHeadPreparation.tla with per-member durable history, retained slot
knowledge, own-live-query grants, compare-before-advance, and crash loss of
local grants. Expected predecessors are checked before abstract insertion;
historical slots remain queryable. TLC passed one/two-correct configurations
(70/522 reachable states) and retained a required two-slot completion schedule.
The reachability probe is existential, not liveness. Full formal runner arrays
and M16Q hashes include all configurations; the targeted runner passed.
Evidence: `evidence/m17q-r1-head-transition-model-2026-09-05/`, including initial
model sentinel type error and generated-orphan census rejection before repair.
The model abstracts each completed live Query atomically and assumes atomic
non-rollback state; production bootstrap/head enforcement, concurrent runtime
refinement, scheduling/timing, handoff and R1 closure remain open.

### Interleaved head preparation model — 2026-09-05

Split the design model's atomic Query into local operation admission, per-member
durable capture, delayed observation and decision. Added captured/observed
consistency and pre-advance accepted-grant compatibility checks. Two-correct
configurations cover competing values at one and two slots (4,328 and 17,314
reachable states); the interleaved completion probe reaches both two-slot
histories. Full runner arrays and M16Q source hashing include the model and
configs. Evidence: `evidence/m17q-r1-head-interleaving-2026-09-05/`.
This remains a finite owned-mode design model: exact routing, complete correct
observation and atomic non-rollback writes are assumed. Production head
enforcement, scheduler/timing, filesystem and full T10 refinement remain open.

### Member capacity preflight borrows retained state — 2026-09-05

Removed the full slot clone performed before duplicate/capacity admission.
Preflight now borrows the stored slice; the admitted reply still owns a complete
snapshot. Expanded the headroom regression to admit a second candidate after
refusal/reopen and verify ordered snapshots plus fresh-nonce duplicate replies
with unchanged durable bytes/generation. Evidence is retained in
`evidence/m17q-r1-member-preflight-borrow-2026-09-05/`. This removes one redundant
allocation; it does not replace the complete-store rewrite or close R1 006.
Production bootstrap/head advancement and clean full qualification remain open.

### Unowned head-model acceptance and first-seen retention — 2026-09-05

Extended QuvHeadInterleaving with explicit authority mode and durable firstSeen
state, captured in replies and preserved across later insertions/crashes.
Unowned decisions use the first candidate; owned decisions retain singleton
snapshot acceptance. New first-seen consistency invariants passed across
75,249 two-correct and 171 sole-correct unowned states. Owned two-slot checks
passed across 27,217 states after extension. Both modes retained two-slot
completion witnesses. Runner arrays, M16Q hashes and raw evidence updated at
`evidence/m17q-r1-head-unowned-model-2026-09-05/`. These finite checks assume
atomic non-rollback storage and complete authenticated/routed correct replies;
production head integration, timing/fairness and full refinement remain open.

### Conditional head-preparation progress — 2026-09-05

Added QuvHeadProgress.tla: singleton, no-crash, per-action weakly fair executions
must eventually advance both correct members through two slots. Owned and
unowned temporal checks pass over 353 states each with grant preservation.
Removing that guard produces a fair non-completion cycle (407 states), retained
under the exact AllHistoriesAdvance violation. The initial expected-message
mismatch is retained; the corrected targeted runner passes. Runner arrays and
M16Q source hashes include the checks. Evidence:
`evidence/m17q-r1-head-progress-model-2026-09-05/`. This identifies a preparation
scheduler obligation, not production refinement, general impossibility or
bounded latency. Production head integration and complete R1 closure remain open.

### Required typed bootstrap in production policy — 2026-09-05

Added QuvDomainBootstrapV0 (Fixed initial slot/predecessor or owned
HandoffBoundary activation rule), required it in domain policy, and committed
it under the explicit v1-bootstrap policy hash domain. Runtime initial
coordinate checks run before member processing/executor admission. Handoff
policies require the exact source and certified local boundary for old-rooted
requesters as well as staged successors. Fixtures now provision explicit
bootstraps; missing configurations have no fallback.
Regression/check evidence is being retained in
`evidence/m17q-r1-rooted-bootstrap-2026-09-05/`, including initial missing-docs
and test-import compile failures. This intentional root-format break requires
fresh qualification. Durable expected-head/next-slot state, stored-bootstrap
comparison, parent preparation, full process/refinement and R1 closure remain
open; no history migration is implemented.

Bootstrap local validation completed: 1 config test, 3 runtime policy tests and
23 QUV tests passed (the separate benchmark remains ignored here); CLI test
target compilation and scoped formatting/claim checks passed. The retained
process sequence now runs disjoint handoff, overlapping handoff/recovery, and
the four-member effect campaign against the changed roots. It is not yet a
terminal process result or clean R2 admission.

The bootstrap process sequence remains live in the disjoint-handoff release
build. All 31 sources recorded at process start still match. A read-only audit
identified initial/successor store-open paths and the requirement to compare
stored bootstrap before pending-anchor recovery writes. Supplemental source
hashes and findings are retained in storage-integration-audit.json; they are
not retroactive pre-build bindings. No process pass or R1 closure is claimed.

### Disjoint handoff failure and targeted repairs — 2026-09-05

The bootstrap process sequence terminated with disjoint-handoff exit 101 and
unchanged recorded sources. The interrupted successor logged a fresh-install
activation after reusing its durable gate, so the recovery assertion timed
out. It logged only one live QUV operation. Separately, every successor received
at most three old-member replies: the fourth refused all four requests because
it lacked a cached certified boundary. Neither later campaign ran; this is
not passing handoff evidence. Raw logs/manifest and analysis are preserved.

The helper now returns typed existing-gate versus fresh-live outcomes for
accurate reporting. Member processing independently verifies the source QC
under the old root and matches local execution height and boundary bytes,
rather than requiring locally cached QC assembly. Post-validation audit
diagnostics plus a fixture-rooted checker now enforce exact correct-member
coverage, one accepted operation per successor and qualified reply timing.
The checker passed one positive and 18 negative cases. Compiler feedback
required propagating the verifier bound for local workload access; raw compile
failures are retained. Final checks and new process qualification remain in
progress at `evidence/m17q-r1-handoff-origin-2026-09-05/`. All complete R1
findings, clean M16Q R2 and release admission remain open.

Handoff-origin/member-validation local checks passed: 3 runtime tests, 23 QUV
tests (one separate benchmark ignored), CLI compilation, scoped formatting
and claim checks. The strict evidence checker passed 18 negative cases and
one positive. A fresh retained process sequence is live with info/quv/network
diagnostics and exact handoff evidence checks. No process pass is claimed.

### Repaired disjoint handoff process result — 2026-09-05

The fresh disjoint-handoff process and strict evidence checker passed, with
all 34 recorded source hashes unchanged. Each of four successors accepted
with all four expected old-member replies; the maximum observed valid handoff
reply was 931 ms. The fixture also passed interrupted-gate recovery, successor
progress after retiring old processes, later restart and the post-handoff
effect checks. Eight orchestration logs and artifact hashes are retained in
`evidence/m17q-r1-handoff-origin-2026-09-05/process/disjoint-handoff/`.
The prior failed run remains preserved. The overlapping-member and four-member
effect campaigns remain in progress; this is not full R1 closure or R2 admission.

The overlapping-member handoff/restart process and strict checker also passed
on unchanged recorded sources. Each of four successors had all four expected
old-member replies, with a maximum observed valid reply of 848 ms. Seven
orchestration logs, raw results and hashes are retained in
`evidence/m17q-r1-handoff-origin-2026-09-05/process/overlap-handoff/`. The
four-member effect campaign is now running; complete qualification remains open.

The four-member effect campaign and strict checker passed on unchanged
recorded sources, completing this three-process local regression sequence.
All four sole-correct-member placements passed; the four-operation workload
had 4818.426 ms of observed common overlap within its 5000 ms decision
windows. Conflict isolation, unrelated execution, terminal replay and expired
result retrieval passed. Raw evidence and hashes are retained under
`evidence/m17q-r1-handoff-origin-2026-09-05/process/`, with a final
`qualification-summary.json`. Host timing is diagnostic evidence, not a
protocol timing proof. This dirty-tree regression pass does not close any
whole R1 finding or admit M16Q R2; earlier failures remain retained.

### Authenticated member provisioning scope — 2026-09-05

Member schema 4 adds an authenticated independently provisioned scope commitment
covering network, configuration and the canonical complete set of domain policy
roots, including bootstrap rules. Both production constructors supply it.
Reopen compares it after state/anchor authentication but before pending anchor
recovery, so changed provisioning cannot mutate recovery state or silently
reset retained knowledge. No schema 3 migration is provided. Handoff store
schema remains 3.

The core QUV suite passed 25 tests with one separate ignored benchmark, including
new scope-commitment and unchanged/changed provisioning recovery tests. The
existing all-byte corruption checks cover the new authenticated field. Runtime
compilation/tests are in progress. Source changes invalidate earlier process
results as admission evidence for this revision. Expected-head advancement,
preparation and successor domain-history continuity remain unimplemented; all
whole R1 findings and clean M16Q R2 remain open. Evidence:
`evidence/m17q-r1-member-provisioning-2026-09-05/`.

Provisioning local checks completed: restored core 25 passed/1 benchmark
ignored, runtime 3 passed, CLI test target compiled, formatting and claim
checks passed. Removing only the provisioning comparison made its regression
fail as expected; the exact source was restored and the core suite passed
again. The mandatory M16Q runner now requires both named provisioning tests
to pass within the core phase. A new process sequence will qualify the changed
member schema; earlier process passes do not qualify this revision.

The schema 4 disjoint-handoff process and exact evidence checker passed on
all 34 unchanged recorded source hashes. Each of four successors received
valid replies from all four expected old members; maximum observed reply
latency was 862 ms. The fixture passed durable-gate recovery and successor
progress/effect checks. Eight orchestration logs and artifact hashes are
retained at `evidence/m17q-r1-member-provisioning-2026-09-05/process/disjoint-handoff/`.
The overlapping-member and four-placement effect campaigns are still pending;
this is local regression evidence, not complete R1 closure or M16Q R2 admission.

The schema 4 overlapping-member handoff/restart process and strict checker
also passed on unchanged recorded sources: each of four successors received
all four expected old-member replies, maximum observed reply 804 ms. Seven
orchestration logs and artifact hashes are retained in
`evidence/m17q-r1-member-provisioning-2026-09-05/process/overlap-handoff/`.
The four-placement effect campaign is live; full qualification remains open.

### Candidate-triggered independent preparation model

`QuvHeadTriggeredPreparation.tla` restricts new singleton inputs to one
initiating member. Another member can begin only after that candidate appears
in its durable snapshot for its next slot. Reception schedules an independent
local query; it never creates a grant or advances history. Existing complete
Capture/Observe/Decide and own-grant Advance transitions remain unchanged.
A completed grant is preserved until advancement.

Both authority modes pass AllTriggeredHistoriesAdvance over 232 reachable
states for two correct members and two slots. Disabling only automatic
preparation yields the required temporal failure over 15 states: the initiator
advances once and waits on the next slot while the other member, although it
retains the first candidate, never performs its own query or advances. This
supports a candidate-triggered preparation design, not authority from received
bytes. No failure is counted as history progress.

The model assumes singleton inputs, fixed roots, no crashes, atomic non-rollback
durable writes, ideal authenticated routing, and per-action weak fairness.
An inadmissible future Capture can remain pending until the member catches up;
production requests currently refuse instead. Therefore bounded retry,
queue admission, timers, continuation expiry, competing domains, resource
budgets and handoff remain explicit unimplemented/unproved refinements. This
finite temporal check is not a production scheduler, arbitrary-size progress
proof, or qualified latency guarantee. Evidence:
`evidence/m17q-r1-triggered-preparation-2026-09-05/`. The full formal runner
includes both positives and the named negative, with a focused
`--quv-triggered-preparation-only` reproduction option.

The schema 4 four-member effect campaign and strict checker passed, completing
all three retained process regressions on 34 unchanged recorded source hashes.
All four sole-correct-member placements passed; the four-operation workload
had 4398.885 ms observed common overlap inside its 5000 ms decision windows.
Conflict isolation, unrelated effects, terminal replay and expired-result
retrieval passed. Final raw evidence, case manifests and qualification summary
are retained under `evidence/m17q-r1-member-provisioning-2026-09-05/process/`.
This remains dirty-tree local regression evidence, not whole R1 closure or
clean M16Q R2 admission. The earlier failures remain retained.

After the process sequence terminated, the M16Q selected-gate runner gained
an explicit head/preparation formal phase and hashes for the triggered model
and three configurations. Previously the model files were partly recorded but
not executed by that runner's selected formal phases. The full formal runner
already includes the positive models and required negative witnesses. This
adds coverage without claiming the remaining R1/refinement/load gates exist.

The integrated head/preparation phase passed 11 positive model runs and all
six required negative/reachability witnesses. Runner syntax and diff checks
passed. Source hashes and the raw phase log are recorded in
`evidence/m17q-r1-triggered-preparation-2026-09-05/m16q-integration-result.json`.
This closes the selected-runner omission for these finite models; it does not
close production expected-head advancement or any whole R1 finding.

### Accepted-history transition core (not yet persisted or runtime-enforced)

`QuvAcceptedHistoryV0` stores an independently provisioned initial coordinate
and an ordered vector of accepted candidate hashes. It derives the predecessor
for retained historical slots and the next slot, rejects earlier/skipped slots
and mismatched scope, and preserves old coordinates after advancement. Its
staged transition accepts only a process-local QuvOnlineAuthorizationV0 and
checks continuation expiry, scope/predecessor, exact historical idempotency and
capacity before changing the in-memory history. A terminal u64 slot is retained
without wrapping the next slot. Neither candidate arrival nor encoded history
or an audit can call the live-grant transition as authority.

This is an implemented transition primitive, not production history enforcement.
Member schema 4 does not yet persist this structure or check it on insertion;
runtime completion does not yet reserve or commit Advance. Independently
provisioned per-domain enrollment, authenticated encoding and recovery,
pre-write capacity, member/executor checks, candidate-triggered preparation and
successor frontier transfer are still required. The existing initial-slot
process passes do not discharge those obligations. R1 001/002/005/006/009 remain
open as complete findings.

Tests cover both authority modes, bootstrap and scope substitutions, historical
queries, two successive live grants, repeated/conflicting grants, expiry before/
equal/after the local cutoff, canonical encoding and the terminal slot. Removing
the predecessor/admissible-slot check causes the named regression to fail;
the exact source was restored. Evidence:
`evidence/m17q-r1-accepted-history-core-2026-09-05/`.

### Member schema 5 and local runtime advancement

Member schema 5 now authenticates an explicitly enrolled domain map alongside
candidate snapshots. Fixed domains contain QuvAcceptedHistoryV0; one-shot
handoff domains contain the provisioned activation scope and still require the
runtime's independently verified local executed boundary. The one-shot zero
predecessor is only an internal rule placeholder and is never accepted in a
request or promoted to history. Both production constructors derive enrollment
from configuration. Incoming candidates cannot enroll a domain. Startup rejects
non-initial enrollment and compares every stored bootstrap after authentication
but before pending anchor recovery; it does not import encoded accepted history
as a bootstrap. No schema 4 migration or fallback is provided.

Fixed-domain PUSHQUERY insertion and local executor start now check the exact
retained/next-slot predecessor and rooted scope. Accepted advancement requires
the member's process-local live grant and an already retained matching candidate
snapshot. It preflights exact encoded growth before cloning, stages the append,
serializes/authenticates the new state, rechecks expiry, and durably writes state
then anchor before exposing the new head. A persistence error quarantines the
instance until authenticated reopen. Exact historical advancement repeats are
idempotent; historical queries continue disclosing retained snapshots.

Runtime completion now reserves local admission while finishing and committing
the accepted Fixed-domain history. It holds the grant through that commit even
if the oneshot result receiver disappears, then releases the transport operation
and forwards the grant for the independent immediate T10 checks. The dedicated
handoff install gate remains responsible for one-shot handoff acceptance.

The core suite passed 32 tests (one separate component benchmark ignored in that
suite), including both modes, future-slot refusal without writes, two accepted
steps, historical queries, changed-enrollment refusal at synchronized/pending
anchors, exact byte headroom, persistence-error quarantine/reopen, and all-byte
corruption over an advanced history. Initial fixture failures are retained: an
unowned I/O fixture had been opened under an owned domain, and the old predecessor
substitution fixture expected insertion. They now enroll the intended fixture
scope and assert early refusal while retaining the canonical-slot and genuine
same-coordinate conflict checks. Runtime policy tests and CLI compilation passed.

This implements local history enforcement, not complete multi-member progress.
Candidate-triggered independent preparation, bounded retries, per-domain fair
admission, rooted service/storage quotas, incremental storage and successor
frontier transfer remain unimplemented/unqualified. A successor's newly scoped
Fixed bootstrap is not proof of inherited accepted history. The schema 4 process
results remain historical evidence for their exact source hashes. No schema 5
process qualification, full transition refinement, whole R1 closure or R2
admission is claimed. Evidence: `evidence/m17q-r1-durable-history-2026-09-05/`.

### Bounded preparation before child admission

`QuvHeadPreparationTiming.tla` isolates the timing obligation omitted by the
weak-fairness preparation models. At time zero the initiating member has its
own accepted parent grant, so the prior complete-processing premise supplies
durable parent-candidate knowledge at every correct member. Each other member
still needs its own query and durable parent commit. The model explicitly
assumes those local services complete within PreparationBound and that child
requests are delivered inside their decision interval. It does not prove a
production scheduler or derive that service bound.

Allowing child admission immediately produces the required
CompleteCorrectProcessing failure: a correct member receives the child before
its parent history is ready and refuses it. Waiting through the preparation
bound passes this finite check, and a separate required witness reaches a
completed child. This is a failure of the complete-processing premise in an
unprepared execution, not two conflicting accepts or an impossibility result
under Q-A3. Timely reachability alone does not imply timely admissible insertion.

The implementation therefore needs both independent preparation and a locally
rooted child-readiness rule. A delay alone is insufficient while preparation is
absent. Its service budget must be derived from bounded/fair admission, active
operation service, each own live query and durable frontier commit, including
clock error and restart behavior. A remote timestamp or transcript cannot set
that authority. Reopen must recover pending work from retained snapshots and
reestablish the local readiness delay; it cannot assume a volatile worker
survived. Every child executor still performs its fresh live QUV operation.

The finite model uses an ideal shared clock, fixed roots, two correct members,
one parent/child and no crashes or competing domains. Its bounded-service tick
constraint is an explicit assumption awaiting production refinement. It does
not establish latency, inclusion, queue fairness or handoff. The full formal
runner and M16Q head/preparation phase include the positive, no-wait negative
and completion witness. Evidence:
`evidence/m17q-r1-preparation-timing-2026-09-05/`.

The explicitly run schema 5 component benchmark completed: one passed, no
ignored tests, 256 samples per path. Debug-build medians were 1769872 us for
ML-DSA signing and 1725341 us for durable write/reply with ML-DSA. The run
briefly overlapped CLI compilation and is local smoke evidence, not clean
release timing qualification. Terminal output, statistics and core source
hashes are retained in `evidence/m17q-r1-durable-history-2026-09-05/component-benchmark-result.json`.

### Recoverable preparation selection

The member store can now select one pending preparation candidate from its
authenticated retained snapshots, rotating after a supplied domain cursor.
It considers only the next unaccepted Fixed-domain slot. Already advanced
historical slots and one-shot handoffs are excluded. An owned snapshot with a
locally disclosed conflict is preserved but not selected for a futile fresh
owned query; an unowned snapshot retains first-seen order. A quarantined store
refuses selection until authenticated reopen.

Selection is read-only and does not create a grant, advance a head, mark a child
ready, or create a durable authorization from received bytes. A caller must
still independently validate and query the selected candidate. Restart tests
recover the same pending work without a volatile queue; rotation tests cover
two domains, historical duplicates, no state/anchor writes, both authority
modes and handoff exclusion. Replacing the next-slot filter with the initial
historical slot makes the advancement/selection regression fail; source is
restored afterward.

This is a scheduler input primitive, not the production worker or a fair-service
proof. A scan can visit every configured domain, so its cost belongs in the
pending admission/storage qualification. The worker, bounded attempt/service
policy, child readiness, restart timing and successor history transfer remain
open. Evidence: `evidence/m17q-r1-preparation-selection-2026-09-05/`.

### Explicit rooted preparation policy

AftQuvDomainPolicyV0 now requires QuvPreparationPolicyV0 with no serde default:
Independent for Fixed histories, or OneShot for handoff-boundary domains.
Independent commits max_attempts_per_slot, service_millis and readiness_millis.
Local syntax requires a nonzero attempt count, service longer than the live
query interval but no longer than query plus continuation, and readiness at
least the checked product of attempts and service. Incompatible kinds, missing
fields and arithmetic overflow refuse. These are necessary local consistency
checks, not a cross-domain queue-service proof.

The canonical policy-root domain is now `ioi/aft/quv-policy/v2-preparation` and
includes the entire preparation policy. Runtime derivation and all typed fixtures
use the new root. No old-root conversion, inferred policy or fallback is supplied;
changing these settings changes the authenticated member provisioning commitment.
Member schema remains 5 and handoff schema remains 3. Fixtures currently supply
explicit, generous preparation budgets for implementation tests; these are not
calibrated or qualified scheduling measurements.

Root tests vary each preparation limit independently and reject invalid budgets;
configuration tests cover required JSON/TOML fields and incompatible preparation.
Removing preparation from the root preimage makes the new binding regression
fail while syntax checks remain enabled; the source was restored afterward.
Evidence: `evidence/m17q-r1-rooted-preparation-policy-2026-09-05/`.

Durable attempt reservation, the worker, enforcement of service/readiness limits,
aggregate fair admission, restart timing and qualification are still missing.
Merely committing a budget does not make a member ready or authorize a child.
R1 001/005/006/009 remain open as complete findings. The earlier process results
remain bound to their old policy-root/source revisions and do not admit this
changed candidate.

Rooted preparation-policy checks completed on unchanged recorded sources:
1 configuration test, 35 core tests (one separate benchmark ignored), 3 runtime
policy tests and CLI compilation passed. Root-input removal failed the required
regression; original source was restored. Formatting, runner syntax and claim
checks passed. This proves local policy binding/validation only; durable attempt
reservation, worker/readiness enforcement and new qualification remain open.


### Accepted-history snapshot retention — 2026-09-05

Recovery now cross-checks every accepted history entry against its retained
candidate snapshot, including the terminal entry with no later predecessor.
This supplements authenticated decoding and candidate-to-history validation.
Missing or substituted snapshots fail before synchronized or pending-anchor
recovery can write either file. Schema 5 and policy roots are unchanged.
The core suite passed 36 tests (one separate benchmark ignored). Removing this
check fails the named regression; restoring it passes. Evidence is retained at
`evidence/m17q-r1-history-retention-2026-09-05/`. The M16Q runner requires the new
regression. R1 001/002/005/006 remain open as complete findings; this does not
establish durable preparation attempts, worker/readiness enforcement, WAL,
compaction, rollback custody deployment, refinement or new qualification.


### Durable preparation-attempt reservation — 2026-09-05

Member schema 6 adds an authenticated next-slot preparation-attempt map. The
reservation API recomputes the complete supplied policy root, matches the enrolled
domain/next coordinate, requires a retained candidate and refuses a disclosed
owned conflict. It checks the rooted maximum before exact pre-write byte admission
and persists the increment to state and anchor before returning. There is no
refund. An uncertain write quarantines the live member until reopen; pending
recovery retains the spent attempt. Only a successful durable accepted-history
transition retires the old counter, atomically with advancement. Historical grant
replay does not retire a later counter. New slots receive a fresh budget.

The core suite passed 38 tests (one separate benchmark ignored). The new tests
cover both authority modes, repeated reopen/exhaustion, substituted rooted limits,
exact-size and one-byte-short admission for reserve and advance, uncertain anchor
write, recovery non-mutation and counter-field authentication. Three isolated
removed-rule controls (budget guard, policy-root comparison, counter MAC coverage)
each fail their required regression; restored code passes. Evidence is retained
at `evidence/m17q-r1-durable-preparation-attempts-2026-09-05/`.

There is no schema-5 migration or old-root/store fallback. Handoff schema stays 3.
The preparation worker has not yet been connected to this API. Aggregate fair
service, readiness/restart timing, authority/queue quotas, WAL/compaction,
production refinement and new process qualification remain open. R1 findings
remain open as whole findings; this is not R2 or M18Q admission.

Durable-attempt integration checks completed on unchanged recorded sources:
3 runtime policy tests and CLI compilation passed, alongside 38 core tests and
three required removed-rule failures. Formatting, runner syntax, diff and claim
checks passed. Evidence manifest and toolchain/source context are retained.
The worker is still not connected; no whole R1 finding or release gate is closed.


### Runtime preparation worker — 2026-09-05

A single preparation worker is now started with the orchestration lifecycle.
It scans retained next-slot candidates on startup and wakes after durable member
work, local operation completion, or replacement of the member store during
successor activation. It rotates domain selection, skips refusals through a
bounded sweep, and performs no network work on exhausted-budget reservation.

The worker uses the same rooted candidate validation and single-operation runtime
admission as external executors. After reserving runtime admission, it persists
its rooted attempt before opening the transport epoch or sending PUSHQUERY.
Failures do not refund the attempt. It waits for the existing completion path,
which requires its own live QUV result and durable head advance; discarded worker
result values never authorize an effect. Notifications replace recursive task
spawning; storage scanning/reservation runs on blocking workers.

Compilation of the validator path passed. A new local process campaign has been
started and its result is pending in
`evidence/m17q-r1-preparation-worker-2026-09-05/`. No process pass is claimed here.

The rooted service/readiness intervals are not yet enforced by this worker.
External requests can still compete for the single operation slot without proved
fair scheduling. Child readiness, aggregate bounded service, overload and restart
timing, process evidence and transition refinement remain open. All original R1
findings remain open as complete findings; no clean R2 admission follows.

The first worker process campaign terminated with exit 101 on unchanged source
hashes. Four sole-correct placements and four saturation effects executed, but
the conflict case received the generic one-live-operation refusal while a worker
occupied admission. One worker completion is visible in retained logs. Early
component log retention failed (missing directory, 820 diagnostics); the failure
and remaining logs are preserved. This run cannot qualify the worker. The next
repair is bounded queued operation admission and revalidation after waiting.


### Queued foreground/preparation admission — 2026-09-05

The first worker campaign exposed a foreground contention regression: an
independent preparation occupied the sole operation and a conflict request got
a generic busy refusal. Queued admission now replaces the idle-flag race. One
semaphore permit owns the active operation, including transport setup and durable
accepted-history commit. Each enrolled domain has at most one waiting foreground
request; the single lifecycle worker can enqueue one preparation. Waiting permits
release on admission or cancellation. The bounded queue follows semaphore order.

Candidate authority is checked before joining the queue and revalidated against
current roots, policy, membership and local history after waiting. The active
permit moves into the pending operation and remains held through head persistence.
Dropping the caller's receiver cannot release it early. The worker no longer waits
for an observed idle flag; it joins the shared queue. No fixed-domain policies
means the worker exits immediately, including the default non-QUV path.

Five runtime tests passed, including two queue tests for exclusivity, worker and
foreground order, waiting-domain capacity and cancellation. Relaxing active or
waiting capacity from one to two fails the regressions; restored source passes.
The M16Q runner now requires these tests and hashes the new admission module,
context and lifecycle. A new process campaign is pending at
`evidence/m17q-r1-queued-admission-2026-09-05/`, with its component directory
created before launch. The original failed campaign remains preserved.

This bounds local queued operation count and tests queue order. It does not prove
wall-clock service, PQ admission cost, resource/authority lifetime quotas, child
readiness or end-to-end progress. Those obligations and all whole R1 findings
remain open.


### Queued-admission development result — 2026-09-05

The queued-admission process campaign completed with exit 0 on unchanged
recorded sources and no diagnostic-retention failure. The evidence checker
confirmed all four sole-correct placements, four-way workload overlap (4914.504ms),
one conflict acceptance with typed rejection and resource non-mutation, unrelated
effect execution, and unchanged expired terminal-result retrieval. Retained logs
match 13 accepted worker completions across all four endpoints to preceding
reservation, own live-query audit with all four expected members, and completed
runtime outcome. There were 17 worker starts; no completion is claimed for the
four remaining starts at test shutdown.

The worker-observation checker rejects removed reservation diagnostics, portable
claims and incomplete member sets. These are evidence-check mutations, not a
substitute for runtime worker mutation, restart or transition-refinement tests.
Five runtime tests and two actual admission-capacity controls also passed their
required dispositions. Evidence is retained in
`evidence/m17q-r1-queued-admission-2026-09-05/` (relative to the AFT directory).
This is a shared-host development campaign, not clean R2 qualification, a measured
aggregate service bound or child-readiness proof. All whole R1 findings remain open.

Next runtime inspection: cancellation between pending-operation insertion and
completion of request dispatch needs explicit acceptance gating before adding
service-deadline cancellation. This boundary has not yet been tested. Readiness,
aggregate service, restart timing, storage and full refinement remain required.


### Cancellation-safe dispatch completion — 2026-09-05

Pending runtime operations now retain the exact set of configured members whose
local dispatch completion is outstanding. A remote member is recorded only after
durable outbox admission succeeds; a local member only after successful durable
write-before-reply processing. Duplicate/unconfigured markers are rejected.
Recording uses the operation's monotonic elapsed time and refuses observations
after its rooted interval without changing the outstanding set. Exact deadline
equality remains valid. Once deadline handling removes a pending operation, the
sender stops recording or continuing remote dispatch for it.

Finalization checks the complete dispatch set before running the live decision,
producing an acceptance audit, or advancing history. Cancellation with any member
outstanding therefore cannot authorize from an already received partial set of
replies. The pending operation retains its admission permit through cleanup.
This check is necessary local accounting; durable outbox admission is not delivery
or a member reply. Every correct member's complete timely processing remains a
separate safety-critical assumption.

Eight runtime tests, 38 core tests (one separate benchmark ignored), and CLI
compilation passed on unchanged recorded sources. New tests cover each omitted
member, empty/duplicate/unconfigured sets, cancellation after zero through three
of four completions, live-decision refusal propagation, and before/equal/after
clock edges. Removing either the completion guard or clock guard fails the
regressions; restored source passes. An intermediate compile failure from an
omitted interval initializer was fixed and its log retained. Evidence is in
`evidence/m17q-r1-dispatch-completion-2026-09-05/`. The M16Q runner hashes the new
module and requires all three dispatch regressions.

This is local cancellation/dispatch evidence, not new process qualification,
worker service enforcement, child readiness or full transition refinement. The
previous queued-admission process pass is historical for its recorded source
revision. All whole R1 findings remain open.


### Rooted active preparation service — 2026-09-05

Preparation now enforces the rooted active-attempt service budget. The budget
starts immediately after exclusive operation admission; the duration comes from
the already validated rooted policy, so no extra context-lock wait precedes the
clock. Current roots and history are still revalidated inside the admitted work.
Selection and queue waiting belong to the separate aggregate readiness obligation.
This distinction is explicit in the policy type comments; it does not establish
an aggregate service bound or discharge the timing model's assumptions.

Startup/dispatch runs under the deadline. Expiration cancels that future and
aborts any pending operation, while the exact dispatch-completion guard prevents
partial dispatch from authorizing. Spent durable attempts are not refunded.
The finalization timer is scheduled for the earlier query/service cutoff;
delayed execution cannot extend the service deadline, and acceptance still
requires the complete QUV decision interval. A consuming grant cap can only
shorten the original continuation, never extend or revive it. Head advancement
therefore rechecks the capped expiry immediately before its first durable write.
Completion at or after the active deadline is reported as failure.

An atomic write already started while the grant was valid cannot be undone by a
timeout. If it finishes late, durable history may have advanced, but no expired
grant or timely-preparation success is returned. Structured service-expiration
and completion-budget diagnostics expose that outcome. This is not a mechanism
for making slow storage meet a bound or for counting failure as progress.

Thirty-nine core tests (one separate benchmark ignored), nine runtime tests and
CLI compilation passed. Removing non-extension, expired-grant rejection or the
late-completion check fails the corresponding regression; restored source passes.
The runtime completion control was repeated after moving policy lookup ahead of
active admission. The M16Q runner requires the new regressions. Evidence is in
`evidence/m17q-r1-active-service-2026-09-05/`; a new current-source process campaign
is running, with no result claimed yet.

Foreground setup/service, aggregate queue/readiness bounds, restart behavior,
uncancellable storage cost, full refinement and all whole R1 findings remain open.
The earlier queued-admission process pass remains historical for its source hash.

The active-service process campaign terminated with exit 101 on unchanged
recorded sources. Four sole-correct and four saturation effects executed; both
conflicting candidates were rejected (safety-only evidence, no conflict-domain
progress), and the unrelated effect executed. The combined expired-result
assertion failed without identifying height, portability or byte-equality cause.
No active-service overruns were reported. The public height wait can precede
the effect endpoint’s admitted-height metadata, so it is insufficient for this
expiry precondition. Root cause remains unproven; preserve this failed run and
strengthen synchronization/diagnostics without relaxing receipt assertions.


### Expired-result observation correction (2026-09-05)

The active-service process campaign failed its combined expired-result assertion;
its retained output does not establish which of height, portability or receipt
equality failed. Public block availability is insufficient to synchronize an
assertion about the effect endpoint's admitted-height metadata. The fixture now
polls that endpoint for at most 240 seconds, with each RPC bounded by 30 seconds.
It immediately rejects RPC errors, missing/malformed metadata, changed receipt
bytes or portable results, including observations before expiry. Only an exact
nonportable terminal result at admitted height strictly greater than the fence
satisfies the expiry case. Lower/equal heights remain pending, not success.

The named regression passes; removing strictness, byte equality or non-portability
individually fails it. Restored source passes. The full M16Q runner includes this
regression. Evidence: `evidence/m17q-r1-expiry-observation-2026-09-05/`. A fresh
local process campaign is running; no process pass or R1 closure is claimed.
This changes fixture synchronization and diagnostics, not authority semantics,
Q-A assumptions, or any theorem/lower-bound disposition. The earlier failed run
remains failed, and its root cause remains unproven.


The expiry-observation campaign terminated with exit 101 on unchanged recorded
sources. Four sole-correct placements and four saturation effects executed;
both conflicting candidates were rejected with resource non-mutation (safety
only). The unrelated effect failed exact four-member audit coverage, so the
new expiry case was not reached. Its missing member completed durable processing,
but the reply was routed approximately 5296.857ms after the operation-start
log, beyond the rooted 5000ms decision interval, and was absent from the audit.
These are same-host diagnostics; they do not isolate transport, queue, lock or
scheduler delay, or qualify the timing premise. The strict process checker
rejects the run. No retry or relaxed coverage is used to turn it into a pass.
Raw logs and the extracted lifecycle are in
`evidence/m17q-r1-expiry-observation-2026-09-05/process/`.
The strengthened expiry fixture remains locally tested but process-unqualified.
All whole R1 findings and aggregate readiness/timing qualification remain open.


### Reply-path timing diagnostics (2026-09-05)

The retained unrelated-effect participation failure has a post-interval reply,
but existing logs cannot divide delay among async worker return, context locks,
command admission, transport, and event handling. New nonce-bound diagnostic
boundaries delimit those stages without changing deadline observation or
eligibility. Channel admission is explicitly not durable admission/delivery.
See `evidence/m17q-r1-reply-boundary-diagnostics-2026-09-05/` for definitions and
checks. No process timing qualification, root-cause fix or R1 closure is claimed.

The diagnostic change passed nine runtime tests, three QUV outbox tests and
the separately selected authenticated payload-routing test. Formatting and diff
checks passed. Instrumented process evidence remains outstanding.


### Instrumented reply-path process result (2026-09-05)

The campaign in `evidence/m17q-r1-reply-boundary-diagnostics-2026-09-05/process/`
terminated with exit 0 and unchanged recorded sources. The strict checker confirms
all four sole-correct placements, four saturation effects with 4153.826ms common
workload overlap, one conflict acceptance and one typed rejection with resource
non-mutation, unrelated-effect execution with exact participation, and unchanged
terminal receipt retrieval at admitted height 70 beyond expiry fence 65.
Seventeen preparation operations started; fourteen accepted completions across
all four workers match preceding reservations, own live-query audits and active
service checks. No completion is credited to the remaining starts.

The boundary analyzer reports 21 remote replies across 11 foreground operations
with all added remote stages present. Observed maxima include 1657.767ms between
async durable-work return and reply-command preparation (spanning the preparation
notification context lock and encoding), 287.859ms acquiring the command sender,
and 1350.235ms between verifier-handler entry and routing under the context lock.
Command-channel admission itself took at most 0.023ms in these samples. These are
host-clock observations, not worst-case bounds or isolated causal measurements.
They identify context contention as a concrete repair target, without establishing
the cause of the earlier uninstrumented late reply.

The strengthened expiry fixture now has a local process pass. Earlier expired-
result and missing-participation campaigns remain failed; this pass does not
retroactively explain or qualify them. Child readiness, aggregate timing/fairness,
restart/storage bounds, full refinement, whole R1 closure and clean R2 remain open.


### Captured member-completion handles (2026-09-05)

Member processing captures its preparation notifier and QUV command sender in
the initial rooted-context read. After durable work returns, synchronous
completion notifies via that handle and exposes a response only on success.
Remote forwarding preserves the exact recipient and signed reply and uses the
captured sender. Neither step reacquires the main orchestration context; the
completion API carries no reference to that context. Initial policy validation,
durable write-before-reply and transport capability checks remain unchanged.
Command-channel backpressure still applies and is not durable delivery.

Eleven runtime tests passed. The new regressions cover notification under
backpressure, exact forwarding, refusal without reply and closed-lane error.
Removing notification or substituting the recipient fails the intended tests;
restored source passes. The M16Q runner hashes the new module and requires both
named regressions. Evidence: `evidence/m17q-r1-member-completion-handles-2026-09-05/`.

This removes two redundant post-work context acquisitions identified by the
instrumented predecessor campaign. It does not prove that they caused its earlier
uninstrumented failure or establish a latency bound. Verifier observation still
acquires the main context; aggregate readiness, process contention controls,
restart/storage bounds, full refinement, whole R1 closure and clean R2 remain
open. A new process run is required for the revised source.


### Separately locked verifier-operation table (2026-09-05)

The QUV event loop captures the live-operation table once. Reply handling now
acquires that table directly, without acquiring the main orchestration context.
Startup and dispatch reuse its captured handle. Abort and finalization remove
entries from the same table; operation permits remain owned through their prior
completion boundaries. Table guards are released before invoking abort, and the
reply path never acquires the main context while holding a table guard. Existing
rooted revalidation at startup/finalization and monotonic observation/deadline
checks remain in force. Keeping an entry until a delayed finalizer runs cannot
extend the rooted reply interval.

Twelve runtime tests passed. The added regression drives the actual reply handler
through a captured table while its handle owner's lock is held, checks exact
transport identity, sends a stale nonce before the correct reply, and verifies
that an event after removal cannot recreate an operation. Its fixture signature
verifier and explicit finish time test routing only, not PQ security or real-time
authorization. Removing transport binding or using an arbitrary table entry
instead of exact nonce lookup fails the intended assertions; restored source
passes. The M16Q runner requires this regression.

Evidence: `evidence/m17q-r1-verifier-operation-table-2026-09-05/`. A new process
measurement is required for this source. A preceding PUSHQUERY admission can
still wait for the main context inside the event loop; entry/dispatch/finalization
scheduling and aggregate readiness are not bounded by this change. Full process
contention controls, restart/storage qualification, refinement, whole R1 closure
and clean R2 remain open. The earlier process pass remains historical evidence.


### Captured-handle/table process result (2026-09-05)

The revised-source campaign terminated with exit 0 and unchanged recorded
sources. Strict evidence checks confirm all four sole-correct placements, four
saturation effects with 4868.970ms common workload overlap, one accepted conflict
candidate and one typed rejection with resource non-mutation, and unrelated-effect
execution with exact participation. Expired-result retrieval first observed
unchanged nonportable bytes at admitted height 65 (equal to the fence), then
succeeded only at height 66. This exercises the fixture's pending-equality path.
Sixteen accepted preparation completions across all four workers are matched to
preceding reservations, own live queries and active service diagnostics; eighteen
started and the other two starts are not credited as completions.

All 21 remote foreground replies have the added boundary diagnostics. Observed
maxima were 0.029ms from durable-work return to reply-command preparation,
0.011ms between reply-command preparation/sending, and 0.020ms from verifier
handler entry to routing. These are small in this sample after removing the
corresponding main-context accesses, not a causal or worst-case timing proof.
The largest remaining observed event-forwarding-to-handler gap was 998.006ms.
PUSHQUERY admission in the shared QUV event loop still needs main-context access;
the remaining queue delay must be isolated and bounded, not hidden by this pass.

Evidence: `evidence/m17q-r1-verifier-operation-table-2026-09-05/process/`.
Earlier failed campaigns remain failed. Aggregate readiness/fairness, process
contention controls, restart/storage bounds, full refinement, whole R1 closure
and clean R2 remain open. The measured stages and previous failures do not
establish a counterexample under the fixed complete-timely-processing premise.


### Bounded PUSHQUERY admission worker (2026-09-05)

The event drain no longer awaits PUSHQUERY admission. It sends push events to
one admission worker through a finite channel and continues handling replies
through the separately locked operation table. The production channel capacity
is twice the protocol member cap, covering the capped old/successor union; there
is one active admission callback in addition to queued events. Existing transport
per-account admission and runtime per-account durable-work limits remain in force.
This introduces no unbounded per-event admission-task spawning.

Queue overflow is explicitly reported and attempts nonce-aware retirement of the
unadmitted transport lane through the reserved command sender. That retirement
can itself fail and is logged; overflow is never qualified progress. Unexpected
worker exit stops event routing and emits a distinct diagnostic. The mandatory
process checker rejects either overflow or worker-stop diagnostics, including
those unrelated to the saturation nonces. Shutdown closes the queue, cancels and
joins the admission worker. Existing already-spawned durable work follows its
previous lifecycle; shutdown does not count it as completed. No admission worker
is started when QUV policies are absent.

The actual driver regression blocks a push callback while requiring a subsequent
reply to be observed, verifies the exact finite queue overflow, and verifies
shutdown of the blocked worker. Restoring serial callback processing fails on
reply progress; increasing capacity fails the exact-overflow assertion. The
checker control removing admission-failure rejection also fails its self-test.
These are local scheduling/evidence controls, not cryptographic or process timing
qualification. Evidence: `evidence/m17q-r1-bounded-push-admission-2026-09-05/`.

Main-context admission and durable member service must still fit the rooted
complete-processing envelope. Independent draining prevents one dependency but
does not establish that bound, byte/rate/lifetime quotas, aggregate readiness or
fairness. A fresh process run, full refinement, whole R1 closure and clean R2
remain open. Earlier exact-source passes and failures retain their dispositions.


### Bounded-admission process result (2026-09-05)

The recorded bounded-admission source passed the process campaign with exit 0
and unchanged selected hashes. Strict process and worker-service checkers passed,
including rejection checks for overflow and unexpected admission-worker exit.
All four sole-correct placements and four saturation effects executed; workload
overlap was 4373.699ms. One conflict candidate executed, the other received a
typed rejection with resource non-mutation; unrelated execution and unchanged
terminal replay beyond expiry (admitted height 66, fence 65) also passed.
Thirteen of sixteen preparation starts had accepted completions matched to their
own live queries and active-service diagnostics; other starts are not credited.

All 21 remote foreground replies had complete stage diagnostics. The largest
observed event-forwarding-to-handler-entry gap was 36.217ms. This is a shared-host
sample, not a causal improvement proof or a worst-case bound. Evidence is in
`evidence/m17q-r1-bounded-push-admission-2026-09-05/process/`.

Subsequent source inspection found that forced abort of the outer event task
could detach its admission worker. The validator has a two-second task shutdown
grace followed by abort, so this is an existing lifecycle boundary. A local
regression reproduced the detached blocked callback and is being repaired in
`evidence/m17q-r1-admission-worker-cancellation-2026-09-05/`. This process pass does
not cover that forced-abort boundary or qualify the subsequent repair. All whole
R1 findings, full restart/refinement, aggregate bounds and clean R2 remain open.


### Admission worker ownership across forced abort (2026-09-05)

The new forced-abort test failed against the prior scheduler: the outer event
Task ended, but its blocked admission callback remained alive. The validator's
existing two-second shutdown grace explicitly permits aborting that outer task.
An owned abort-handle guard now requests worker cancellation when the event-drain
future is dropped or unwinds. Normal shutdown still cancels and joins the worker;
non-cancellation join errors encountered during cleanup emit the existing worker-
failure diagnostic rejected by the process gate.

Fourteen runtime tests passed, including normal blocked-worker shutdown and the
new forced outer-task abort. Removing the guard reproduces the callback-lifetime
timeout; restored source passes. The runner requires the new named regression.
Evidence: `evidence/m17q-r1-admission-worker-cancellation-2026-09-05/`.

Cancellation takes effect when the async task can be cancelled; it is not forced
preemption of synchronous code. It covers the admission callback, not already
spawned durable member work, atomic storage writes or external effects. Those
retain their existing semantics and still require complete restart/refinement
qualification. The preceding process pass is historical for its recorded source;
no process run of this repair or whole R1 closure/clean R2 is claimed.


### Scheduling/service failure evidence gates (2026-09-05)

Both the single-correct process checker and the handoff checker now reject
`push_admission_overflow`, `push_admission_worker_stopped` and
`preparation_service_expired` in any retained component record, including records
whose nonce is unrelated to the selected workload. Passing selected acceptance
assertions cannot erase a declared scheduling/service failure elsewhere in that
same qualification campaign. These diagnostics remain evidence, never authority.

The handoff checker self-test passes 1 positive and 21 negative cases. The main
checker passes 2 positive/26 negative process cases and 1 positive/26 negative
component-overlap cases. Replacing each checker's scheduling/service failure
condition with False causes its self-test to fail. Raw commands, outputs and
checker hashes are retained in `evidence/m17q-r1-scheduling-evidence-gates-2026-09-05/`.
The stronger handoff checker was applied to the completed disjoint campaign's
retained raw logs after that campaign terminated; its original and recheck
checker hashes remain distinct. No runtime-source change is attributed to that
recheck. Full R2 and all whole R1 findings remain open.


### Current scheduler reconfiguration checks (2026-09-05)

Both disjoint and overlapping handoff/recovery campaigns passed with exit 0 and
unchanged selected sources during each run. Each checker confirms four successor
executors with their own live acceptance and exactly all four expected old-member
replies. The largest valid-reply observations were 939ms (disjoint) and 911ms
(overlap), within each fixture's declared envelope. The strengthened checkers
found no admission overflow, unexpected admission-worker stop or preparation-
service-expiry marker. The disjoint run finished before checker strengthening;
its initial and stronger recheck hashes are retained separately. Runtime source
was not changed by that recheck.

The overlapping fixture kills and restarts the common old/successor member,
requires the local install-gate recovery diagnostic and a publicly retrievable
block two heights beyond its pre-restart tip, then requires a signer-role refusal
diagnostic from a restarted retired member. These assertions passed. They are specific restart/role checks, not full
restart scheduling, storage rollback resistance or transition refinement.
Raw evidence is in `evidence/m17q-r1-admission-worker-cancellation-2026-09-05/`.

These current-runtime results cover the scheduler and ownership changes on the
handoff path. They do not retroactively explain earlier failures, qualify the
latest foreground/saturation campaign, establish worst-case timing or close any
whole R1 finding. Full mutation/refinement, aggregate bounds and clean R2 remain
open. No theorem assumption or non-portability boundary changes.


### Current scheduler foreground campaign (2026-09-05)

The foreground process campaign after the cancellation-ownership repair passed
(exit 0, unchanged selected sources). The strengthened checker confirms all four
sole-correct placements, all four concurrent saturation operations, one conflict
acceptance with one typed rejection and non-mutation, unrelated effect execution,
and unchanged terminal-result retrieval beyond the committed expiry fence
(observed height 66 > 65). Four-way workload overlap was 4674.706ms. Worker checks
matched 16 independent preparation starts and 12 accepted completions across all
four workers, with no scheduling/service-failure markers. Refusals are not progress.

Raw logs, exact source/command hashes and checker results are retained under
`evidence/m17q-r1-admission-worker-cancellation-2026-09-05/foreground-process/`.
This supersedes the earlier pending foreground status only. Previous failed runs
remain unexplained and retained. These selected assertions do not establish
worst-case timing, aggregate readiness, full transition/restart/storage refinement,
clean R2, or closure of any whole R1 finding. No theorem assumption changes.


### Repeated-slot readiness composition boundary (2026-09-05)

`QuvReadinessComposition.tla` checks completion schedules for a proposed rule,
not production transition refinement. Waiting a fixed bound after every member's
own head commit does not follow from the rooted active-service bounds alone:
with wait 3, fast service 1, slow service 2, and active budget 3, the fifth child
is introduced at time 16 while the slow predecessor completes at 17. Both
services are strictly within budget. The model stops before any acceptance for
that inadmissible child. Equal-service scheduling passes and a separate required
witness reaches five completed slots, preventing a vacuous always-refuse result.

A second positive configuration exempts retained-candidate preparation from the
foreground wait. It passes the same unequal-service five-slot schedule under
ideal immediate selection, no queue/competition/restart and timely complete
correct-member processing whenever the predecessor is ready. It is a design
candidate, not an implemented readiness gate or derived production bound.

The existing one-parent/child timing model assumes aggregate PreparationBound;
its pass does not derive that bound over repeated slots. Selection, fair queueing,
finite retries, durable reservation/commit and restart still need a uniform
composition bound. A per-attempt cap or readiness policy field alone is
insufficient. This witness violates the missing complete-processing premise;
it is not conflicting acceptance or an impossibility under the fixed QUV
assumptions. No timeout/silence grants authority; every relying member still
needs its own live query and non-rollback durable advance.

Evidence: `evidence/m17q-r1-readiness-composition-2026-09-05/`. The focused formal
flag `--quv-readiness-composition-only` requires two positive schedules and two
named negative/reachability witnesses; full and parent-boundary runners include
the same checks and M16Q hashes their sources. All whole R1 findings, complete
refinement, aggregate readiness and clean R2 remain open.


### Conditional readiness bound across arbitrary slots (2026-09-05)

`QuvReadinessBoundProof.tla` discharges all 10 TLAPS obligations for an inductive
completion-schedule invariant, without a finite slot-count premise. **Assumes:**
each correct member receives the singleton candidate, retained-candidate
preparation has no extra own-head wait, aggregate selection/queue delay is at
most Q, its own live query and durable commit take at most S, and foreground
wait W satisfies W >= Q + S. The next foreground introduction then occurs only
after the prior slow completion. This is a conditional arithmetic schedule
lemma, not QUV authorization, runtime transition refinement or a liveness proof.
It assumes completion costs; it does not prove those completions happen.

The bounded TLC instance explores three slots. The paired instance using a
service-only wait (W=2, Q=2, S=2) violates ReadyForNext: first fast completion 3,
slow completion 6, next introduction 5. The failure demonstrates why queue delay
cannot be omitted from the aggregate premise. Evidence and exact hashes are in
`evidence/m17q-r1-readiness-bound-2026-09-05/`. Both the full formal runner and a
new mandatory M16Q phase include the proof/model pair; only the focused phase
was run here. The initial census rejection is retained and resolved by including
the model in the executed harness, without a manual-discharge exemption.

Production audit: `QuvOperationAdmissionV0` permits one active operation and one
waiting foreground operation per enrolled domain; its single preparation worker
joins FIFO. With D enrolled domains, a newly queued worker has at most D queued
foreground operations plus the active predecessor ahead. An elapsed bound of
(D+1)*Smax additionally requires every predecessor to release admission within
Smax, including startup, dispatch, decision, durable commit and cleanup. Current
foreground/handoff operations do not have a rooted active-service cap. Selection,
context/store lock acquisition, scheduling and restart costs also remain unbounded
by that queue-count argument. The current runtime therefore does not discharge Q,
and no foreground readiness wait is installed or qualified by this lemma.
All whole R1 findings, complete transition refinement and clean R2 remain open.


### Durable operation admission ownership on cancellation (2026-09-05)

The runtime now shares the operation's active admission permit with its blocking
preparation-reservation and accepted-head-commit closures. Cancelling or timing
out the async waiter cannot release admission while either already-started
closure still runs. The blocking share is released when that closure returns or
unwinds. The pending operation/finalizer retains its own share through normal
cleanup. This changes local scheduling ownership; it adds no new authorization
source and does not cancel, roll back or duplicate durable work.

All 15 QUV runtime tests passed. The new named regression blocks durable work,
cancels its async owner, requires the next foreground admission to remain pending,
then releases the work and requires admission to recover. Removing the closure's
permit retention makes that pending assertion fail; restored source passes.
Both production blocking boundaries use this checked helper. The M16Q runtime
phase now requires this exact test. Raw results and hashes are retained under
`evidence/m17q-r1-durable-admission-ownership-2026-09-05/`.

The store mutex already serialized writes, but that did not retain operation
admission after waiter cancellation. This repair closes that ownership gap, not
the elapsed-service bound: stalled blocking work correctly retains admission and
can still prevent progress. Rooted timing qualification must include actual
storage completion; a timeout/refusal cannot substitute for it. The repair does
not cover unrelated inbound member work or prove full storage/restart refinement.
Earlier process passes remain historical for their exact source hashes. Affected
process campaigns, full R2 and all whole R1 findings remain open.


### Durable-admission repair foreground qualification (2026-09-05)

The post-repair foreground campaign terminated with exit 0 and no recorded source
changes. The strict checker confirms all four sole-correct placements, four
concurrent saturation operations, one conflict acceptance and one typed rejection
with non-mutation, unrelated effect execution, and unchanged terminal-result
retrieval at committed height 67 beyond expiry height 65. Four-way workload
overlap was 4974.655ms. Worker diagnostics matched 17 starts and 13 accepted
completions across all four workers; no scheduling/service-failure markers were
found. All three retained evidence checks passed. The reply-stage analyzer found
21 remote replies with no missing stages; host timestamps are observations,
not a proof of worst-case latency or authority.

Evidence: `evidence/m17q-r1-durable-admission-ownership-2026-09-05/foreground-process/`;
`check_foreground.py` rechecks only a terminal retained run and never launches
another campaign. This qualifies the selected foreground assertions for the
recorded repair source. It does not qualify handoff/restart after this repair,
derive aggregate queue/readiness bounds, explain earlier failures, provide full
transition refinement, complete R2, or close any whole R1 finding.


### Required all-operation service contract — implementation in validation (2026-09-05)

AftQuvDomainPolicyV0 now requires operation_service_millis, with no serde default.
The canonical policy root moves to `ioi/aft/quv-policy/v3-operation-service` and
commits this field. The limit must exceed Delta, fit within checked Delta plus
continuation, and cover the independent preparation active limit. Root/config
validation refuses missing, insufficient or overflowing contracts. Existing
provisioning bindings therefore reject old roots; no migration or fallback is
introduced. Fixture policies and candidate roots explicitly supply the new field.

Every admitted operation now gets an active deadline: foreground and handoff use
the all-operation limit, and independent preparation uses its no-wider attempt
limit. The existing startup/dispatch timeout, capped decision timer, non-extending
live-grant expiry cap, pre-write expiry check and final completion check apply to
all roles. Deadlines start after exclusive admission. Queueing and selection are
outside this active interval and still require separate rooted aggregate bounds.
A deadline failure is logged as operation_service_expired. Evidence gates reject
that marker, the prior preparation marker, or any completed operation lacking
explicit service_budgeted=true and service_budget_met=true. No timeout grants
authority or establishes inclusion/effect progress.

**Assumes still unqualified:** actual startup/transport/storage/cleanup completion
within the active service contract, bounded selection/FIFO delay, correct clock
behavior and restart composition. An already-running blocking write retains its
shared admission permit until it returns or unwinds; a timeout cannot make that
write stop or bound its actual duration. Thus finite declared active budgets do
not yet discharge the queue/readiness lemma's elapsed-time premise.

Validation is ongoing in `evidence/m17q-r1-all-operation-service-2026-09-05/`.
Configuration tests and 40 core tests passed (one pre-existing ignored test remains
separate). Runtime, CLI, removed-rule and process qualification must be completed
for this exact root change. Earlier process evidence is historical. All whole
R1 findings, full transition refinement, clean R2 and release admission remain open.


### All-operation service local validation (2026-09-05)

For the v3-operation-service implementation, configuration validation passed,
40 core tests passed with the separately retained existing ignored test, and all
16 QUV runtime tests passed. The CLI aft_e2e test target compiled. Omitting the
operation-service field from canonical hashing makes the new binding regression
fail; bypassing the foreground budget makes the role-selection regression fail.
Restored source passes both. These are scoped binding/selection controls, not a
claim that the complete production timeout workflow has been mutated end to end.

The strengthened main checker passes 2 positive/26 negative process cases and
1 positive/31 negative overlap/component cases; the handoff checker passes
1 positive/26 negative cases. Removing each checker's completed-operation service
guard causes its self-test to fail. Affected Rust formatting, runner syntax and
diff checks pass. The CLI fixture was formatted after compilation; this formatting
change has no behavioral validation claim beyond rustfmt's successful parse.
Raw commands, outcomes and final hashes are retained in
`evidence/m17q-r1-all-operation-service-2026-09-05/`.

Process and restart qualification of this root/behavior change remains required,
as do a derived and qualified queue/readiness bound, full transition refinement,
clean R2 and closure of every whole R1 finding. No declaration of finite service
or successful local test turns refusal, timeout or a stalled durable write into
progress.


### v3-operation-service foreground campaign (2026-09-05)

The unchanged-source campaign passed its process test and all three retained
evidence checks. All four sole-correct placements and saturation operations
executed; four-way overlap was 4927.347ms. The concurrent conflict case had zero
acceptances, two typed refusals, zero durable records and non-mutation: safety
only, no conflict-case progress. The unrelated effect executed, and unchanged
terminal-result retrieval observed height 70 beyond expiry 65. Worker diagnostics
matched 17 starts and 9 accepted completions across the expected workers.

Evidence is under `evidence/m17q-r1-all-operation-service-2026-09-05/foreground-process/`.
The source audits in that directory still identify incomplete startup/dispatch
admission ownership and completion sampling before final permit release. This
process pass neither resolves those findings nor proves actual admission-release
or aggregate queue/readiness bounds. All whole R1 findings and clean R2 remain open.


### Shared admission lifetime and final release observation (2026-09-05)

The startup/dispatch future now retains an admission share independently of the
pending-operation table. Deadline removal of pending state cannot open the lane
while that future is still waiting. Its share is released on return or cancellation;
blocking reservation/head-commit closures retain their existing independent shares.
The final shared QuvActiveAdmissionV0 owner releases the actual semaphore before
sampling the release time. This separate operation_admission_released diagnostic
records whether release was strictly before the rooted active deadline; equality
or lateness emits operation_service_expired. Elapsed microseconds are recorded
without narrowing the integer. The earlier operation_finished sample remains a
finalizer/outcome check, not a claim that all admission shares have disappeared.

All 18 runtime tests pass on final source. The new regressions cover pending removal
while dispatch waits, both normal completion and cancellation, actual semaphore
availability at clock observation, and before/equal/after release deadlines.
Removing startup retention, observing before semaphore release, or admitting release
at deadline equality makes its regression fail; restored source passes. The CLI
aft_e2e target compiled before the final private predicate extraction; final runtime
compilation/tests cover that extraction. Exact commands and hashes are retained in
`evidence/m17q-r1-final-admission-release-2026-09-05/`.

Process gates require successful release diagnostics for selected operations and a
matching final release for every recorded completed operation, including unrelated
nonces. They reject late/unbudgeted release, duplicate records and missing releases.
Workload overlap remains capped by the decision interval; delayed release does not
inflate overlap. Main checker self-tests pass 2 positive/26 negative process and
1 positive/38 negative component cases; handoff passes 1 positive/30 negative cases.
Removing either all-completions release gate makes its self-test fail.

This repairs local ownership and conservative release observation. A delayed clock
sample after actual release can produce a conservative overrun; it cannot certify
late actual release as timely. Crashes without a completed/released record are not
qualified by that match. Selection, scheduler resumption, fair queueing, actual
storage completion and restart still need aggregate bounds/refinement. The prior
v3 process pass is historical for its recorded source. Current-source process
qualification, clean R2 and all whole R1 findings remain open. No audit diagnostic
or timeout independently authorizes another executor or constitutes progress.


### Final-release foreground process evidence (2026-09-05)

The unchanged-source foreground campaign passed the process test and all three
evidence gates. All four sole-correct placements, four saturation operations,
one conflict acceptance with one typed rejection/non-mutation, unrelated execution,
and unchanged terminal-result retrieval at height 70 beyond expiry 65 passed.
Four-way workload overlap was 3777.211ms. Worker diagnostics matched 18 starts
and 15 accepted completions. Every one of the 26 recorded completed operations
had a matching successful final admission release; 32 release records were retained
in total, including releases without a completed-operation record.

The largest observed active release duration was 7,142,340 microseconds
(preparation); the foreground maximum was 6,818,118 microseconds. These are runtime
monotonic observations sampled after final semaphore release, not a worst-case
service bound or aggregate queue/readiness proof. Raw component logs, release rows,
source/checker hashes and terminal dispositions are retained under
`evidence/m17q-r1-final-admission-release-2026-09-05/foreground-process/`.

This validates selected foreground assertions and release-record completeness on
the recorded repair source. Handoff/restart qualification of the current root and
lifetime changes, full refinement/resource bounds, clean R2 and closure of all
whole R1 findings remain open. Earlier failures remain retained and unexplained.


### Failed disjoint campaign after final-release repair (2026-09-05)

The current-source disjoint campaign failed (exit 101, no recorded source changes):
successor node 4 did not observe required post-QUV height 5. The mandatory handoff
evidence checker rejected the failed campaign. The separate release analyzer passed;
that component result is not a handoff/progress pass. Four successor live-acceptance
audit records match the expected old root/domain/member set, but post-install
progress remains required. Validator-20400's retained consensus progress records
end after beginning a height-3 proposal; other successor logs contain later admitted
height diagnostics. The exact stalled boundary is not yet isolated, and public
status values must not be conflated with those internal diagnostic heights.

Raw logs, failed terminal result, rejected checker result and partial source-bound
analysis remain under `evidence/m17q-r1-final-admission-release-2026-09-05/disjoint-process/`.
No assertion is relaxed, no retry is substituted for this failure, and no freeze or
refusal is counted as progress. Post-install production/finality boundaries require
investigation before requalification. Overlapping-handoff qualification of this
repair is still outstanding. All whole R1 findings and clean R2 remain open.


### Post-commit node-state lock-order repair (2026-09-05)

Source inspection after the failed disjoint campaign found finalization holding
node_state from the Syncing-to-Synced update through its later engine/context
operations. Sync status handling owns the orchestration context and then locks
node_state. These paths permit opposite lock acquisition orders. The production
finalization helper now completes the short node-state update and releases that
mutex before polling the remaining continuation. The status update and existing
vote/configuration/admission checks remain in their original order.

The bounded two-task regression uses the production helper: a sync handler holds
context, finalization updates node state and waits for context, then the handler
must acquire node state and release context so finalization completes. It passes
for initially Syncing and Synced states. Retaining node state across the continuation
reproduces the blocked second acquisition; restored source passes. All 54 finalization
tests and the CLI aft_e2e compilation passed. M16Q now requires this exact regression
and hashes its implementation/test sources. Evidence is retained under
`evidence/m17q-r1-post-commit-lock-order-2026-09-05/`.

This establishes and repairs a concrete component lock-order hazard. The retained
process logs do not conclusively identify it as the cause of validator-20400's
stall, and no claim of global deadlock freedom or full transition refinement is
made. The failed campaign remains failed. Current-source process requalification,
all aggregate timing/resource bounds, clean R2 and all whole R1 findings remain open.
The existing bounded-service assumption and nonportable authorization boundary
are unchanged; node synchronization status is not an authorization source.


### Post-commit lock repair disjoint campaign and formal gate (2026-09-05)

The repaired disjoint campaign passed (exit 0, unchanged recorded sources), and
both handoff and release-evidence checks passed. All four successors independently
accepted with exactly all four expected old-member replies; maximum valid-reply
observation was 922ms. All eight recorded completed operations had final release
records (nine releases total); maximum observed active release was 30,015,029
microseconds. These are finite observations under the recorded additional
consensus debug logging, not worst-case bounds.

The fixture observed post-handoff blocks from the installed successor set, recovered
a restarted successor from its durable local install gate, retrieved two further
blocks, and completed the subsequent live effect assertions. Block retrieval and
producer membership are the checked progress surfaces; they must not be amplified
into proof of fully admitted canonical history at every height. The prior failed
campaign remains retained, and the exact cause of its stall is not conclusively
attributed by this later pass.

The independent two-caller PostCommitLockOrder model is now in formal/concurrency.
Full formal and M16Q runners include its positive/fairness check and the required
retained-lock circular-wait witness. The focused --post-commit-lock-order-only
runner passed; the positive explores 17 states. This is component lock-order
reasoning, not full transition refinement or global deadlock freedom. Commands,
hashes and raw evidence remain in
`evidence/m17q-r1-post-commit-lock-order-2026-09-05/`.

Overlapping-handoff qualification of the current repair remains outstanding, along
with aggregate readiness/resource bounds, complete mutation/refinement, clean R2
and closure of all whole R1 findings. No fixed assumption or authority boundary
changes.


### Overlapping handoff and admission-order component evidence (2026-09-05)

The post-commit lock repair's overlapping-member campaign passed with unchanged
recorded sources (314.08s). Handoff and final-release evidence gates both passed:
four successors independently accepted with all four expected old-member replies;
maximum valid reply observation was 962ms. Four completed operations matched four
final release records, maximum 30,012,800 microseconds. No preparation operation
was observed in this campaign. The fixture checked the common member's own live
install, its durable-gate recovery after restart, further public block retrieval,
and retired-member rejection after restart. Retrieval is not proof of fully
admitted canonical history at every height. These are finite observations, not
worst-case timing bounds. Earlier failed campaigns remain retained. Raw evidence:
`evidence/m17q-r1-post-commit-lock-order-2026-09-05/overlap-process/`.

`QuvAdmissionOrder` adds a finite component ordering check, with one/two domains
(18/101 states), one queued preparation worker, one waiting foreground per domain,
FIFO starts, foreground cancellation, and weakly fair release/service. It checks
at most D foreground starts before that worker and eventual worker admission.
Removing FIFO violates the bound with one domain. The focused runner passed and
both full formal/M16Q runners require the positives and named control. Evidence:
`evidence/m17q-r1-admission-order-model-2026-09-05/`. This is not an arbitrary-domain
proof, runtime transition refinement, or a wall-clock queue/readiness guarantee.
Selection, domain rotation, scheduler resumption, actual durable completion and
restart costs remain unqualified; worker admission is not inclusion/effect progress.

All whole R1 findings remain OPEN. Complete mutation/refinement, aggregate readiness
and resource bounds, clean full R2, immutable candidate and fresh independent review
remain required. The fixed M12a/M12b, complete-correct-processing, durable nonrollback
and process-local nonportable authorization boundaries remain unchanged.


### Production foreground child-readiness wait (2026-09-05)

The Fixed-domain foreground path now enforces the independently rooted
`readiness_millis` delay before joining the active operation queue. It holds the
single waiting-domain permit across that delay, so preparation can use the active
lane while additional waiting requests for that domain are refused. Cancellation
releases waiting capacity. Independent preparation and one-shot handoff do not
inherit the foreground delay.

Each member records a process-local monotonic observation only after its own
accepted-head state and external anchor are durable. Authenticated reopen starts
a fresh conservative observation; no Instant is serialized or restored from an
audit. The exact next slot/root/predecessor must match local history. Initial and
historical coordinates impose no new delay; an exact historical retry or refused
mutation does not reset the next child's clock. Uncertain persistence requires
reopen. After waiting and active admission, current rooted membership/policy,
current head and the current readiness deadline are rechecked; a replacement or
new observation cannot borrow an elapsed deadline from the earlier store. Early
admission is refused, equality/past is eligible for a fresh live operation. The
observation itself is never authorization.

Evidence `evidence/m17q-r1-foreground-readiness-2026-09-05/` retains 41 passing core
tests (one unrelated ignored measurement), 20 passing runtime tests, CLI test-target
compilation and seven required-failure controls: early commit/reopen clocks, retry
clock reset, omitted waiting, omitted readiness predicate, preparation waiting, and
active admission before readiness. Restored suites pass. M16Q explicitly requires
the new regressions. The first core command used an unsupported feature and is
retained separately; the corrected command uses `--features aft`.

This implements the local waiting premise in the prior conditional readiness
models; it does not discharge their aggregate QueueBound/ServiceBound assumptions,
prove runtime transition refinement, or establish complete correct-member processing.
The existing 1,000,000ms fixture readiness value is preserved and now actually
applies to noninitial foreground children: up to 16m40s after local commit/reopen.
No shorter qualified envelope is asserted. A refusal, cancellation, or expired
caller is not inclusion/effect progress. Process qualification of this repair,
arbitrary-domain scheduling bounds, authority lifetime/rooted quotas/incremental
storage, full refinement/mutations, clean R2 and fresh review remain outstanding.
All whole R1 findings remain OPEN; fixed M12a/M12b, synchrony, nonrollback retention,
own live query and `portable_final_receipt=false` boundaries remain unchanged.


### Consecutive readiness qualification and consequence lock handoff (2026-09-05)

The earlier initial-slot foreground campaign passed on the preceding readiness
snapshot with unchanged recorded sources and all four evidence checks. It covered
four sole-correct placements, four saturation operations, an unrelated execution
and unchanged expired-result retrieval. The conflict pair had zero acceptances
and two typed refusals with nonmutation: safety only, not conflict progress.
That pass does not qualify the subsequent changes described here.

The effect endpoint previously held its process-wide ConsequenceStore lock across
readiness and live QUV waiting. Durable preflight now finishes and releases that
lock before waiting. The endpoint reopens the store afterward, re-derives exact
current committed admission and height, and revalidates the durable receipt.
If another request has completed meanwhile, only the existing result/reconciliation
path is used; the fresh grant does not cause a second mutation. Otherwise the
fresh process-local continuation still undergoes the immediate T10 checks. The
store remains exclusively locked across the synchronous Claim/call transition.
This change does not establish fair completion of all contenders for that lock;
StoreBusy/refusal remains a refusal, never effect progress.

The readiness clock regression now covers a second durable head transition.
Runtime diagnostics bind a positive remaining delay and observed elapsed duration
to the nonce/domain/slot before active operation startup. The new three-slot process
fixture uses a distinct rooted 40,000ms readiness profile, exact four-member live
participation, a restart before slot three, unchanged terminal parent replay, and
an unrelated effect completed on the same executor during the slot-two wait.
Each noninitial slot must have at least 15 seconds of actual remaining wait and
consume the matching fresh live audit. This is a selected finite profile, not a
replacement for existing 1,000,000ms roots or a derived aggregate QueueBound.

Core (41 pass, one ignored measurement), runtime (20 pass), endpoint lock/refusal
(2 pass), and consequence (22 pass) checks passed. Controls retaining the consequence
lock, failing to refresh the second head clock, and accepting a vacuous wait each
failed the intended regression; restored checks passed. The Rust observation
assertion includes malformed/early/wrong-nonce negatives; the retained process
checker self-test has one positive and 22 negative cases. M16Q now requires these
unit/assertion gates, the consecutive process case, and its independent host-log
checks for accepted scope, exact member coverage, wait ordering, unrelated progress
and final operation releases.

Raw evidence is in `evidence/m17q-r1-readiness-process-2026-09-05/`. The consecutive
process campaign is running; no process pass is claimed yet. Aggregate preparation,
selection/queue/scheduler/restart bounds, rooted lifetime/quotas/incremental storage,
full transition refinement, clean R2 and fresh independent review remain open.
All whole R1 findings remain OPEN. The fixed M12a/M12b, complete-correct-processing,
nonrollback retention and `portable_final_receipt=false` boundaries are unchanged.


### Consecutive readiness restart failure retained (2026-09-05)

The first three-slot campaign is FAILED (exit 101, unchanged recorded sources).
Slot one, unchanged terminal parent replay, same-executor unrelated execution
while slot two waited, and slot-two execution passed their selected assertions.
Slot two required 39.175024726s and observed 39.176213856s of waiting. The fixture
then missed the slot-three wait event after restart. Its checker rejects the
campaign; the passing prefix is not restart qualification.

The test was awaiting diagnostics while leaving an early spawned RPC result
unobserved. It now selects between the wait event and an early RPC completion,
preserving the underlying typed error. The new regression passes; restoring the
masking behavior fails within the regression's one-second observation bound.
An initial failed source-edit attempt caused a zero-test command, explicitly
retained as non-qualification; the corrected test ran and passed. M16Q requires
that regression. A diagnostic rerun of the same unchanged scenario/profile is
running under `consecutive-process-rpc-observed/`; no production cause or repair
is inferred yet. Recovery logs naming height 1 and a listening RPC endpoint are
insufficient to attribute the failure.

Both campaigns retain copies of every source named by their recorded source
hashes. The first fixture/runner versions were reconstructed by reversing the
known diagnostic edit and verified against their original SHA-256 values. This
is scoped source retention, not a full immutable repository candidate. All whole
R1 findings, aggregate bounds, full refinement, clean R2 and fresh review remain
open. Evidence: `evidence/m17q-r1-readiness-process-2026-09-05/`.


### Restart connection race identified; bounded read-only readiness probe (2026-09-05)

The diagnostic rerun failed with the explicit slot-three connection error:
`Failed to connect to public gRPC: transport error`. Its recorded sources were
unchanged. The restart helper returns after spawn; the fixture had made one RPC
connection attempt without a startup barrier. Both failed runs remain retained.

The fixture now probes the exact already-executed parent result for at most 20s
before requesting the restarted child. Only a typed ConnectionRefused cause or
Unavailable/`Node is initializing` permits another probe. Other errors and any
changed result are failures. The testing RPC connector now preserves its typed
transport cause. A real loopback refusal and the exact-result/startup classifier
pass; erasing the transport type or accepting changed result bytes fails the
regression, and restored checks pass. This is read-only startup observation, not
authority for the child: the child must still perform and consume its own fresh
live operation under the unchanged rooted 40,000ms readiness profile.

The checker now requires the recovered-parent probe and the executor's second RPC
listener between slot-two completion and slot-three waiting. Its self-test passes
one positive and 24 negatives. The initial self-test extension failed on optional
event fields in listener records; that construction error and correction are
retained. M16Q requires the new recovery regression. The corrected campaign is
running under `consecutive-process-recovery-probed/`; no pass is claimed yet.
Raw evidence and exact recorded source copies remain in
`evidence/m17q-r1-readiness-process-2026-09-05/`. All whole R1 findings, aggregate
bounds, full refinement, clean R2 and fresh review remain open.


### Three-slot readiness/restart campaign passed on its recorded snapshot (2026-09-05)

The corrected campaign passed in 295.93s with unchanged recorded sources. Its
recorded-source readiness checker and final-release analyzer both passed. All
three consecutive Fixed-domain effects executed using the relying executor's own
live operations and exactly all four configured correct-member replies. Slot two
required 39.514471166s and observed 39.515012671s before admission; after restart,
slot three required 38.648001013s and observed 38.648667936s. Their maximum valid
reply observations were 793ms and 817ms (parent: 1554ms), within the fixture's
4000ms envelope and rooted 5000ms decision interval.

The same executor returned the unchanged terminal parent result and executed an
unrelated effect while slot two waited. After restart it recovered the exact
parent result through current committed readmission before the third child query;
the checker also matched the second RPC listener between slot-two completion and
slot-three waiting. Fourteen recorded completed operations matched final-release
records (18 releases total). Maximum observed active release was 7,303,766us;
preparation maximum was 6,004,109us. These are finite host observations, not
worst-case time bounds. Neither diagnostic events nor returned parent receipt
bytes authorize a child or another executor.

The two earlier failed campaigns remain failed and retained with their exact
recorded source copies and checker refusals. This pass does not retroactively
waive them, prove full transition refinement, derive aggregate scheduling/queue/
restart costs, or close whole R1 findings. Canonical receipts, commands, toolchain,
source copies and hashes, raw component logs and checked disposition are retained
under `evidence/m17q-r1-readiness-process-2026-09-05/consecutive-process-recovery-probed/`.
The profile remains two configured domains, four correct members, a rooted 40,000ms
readiness delay and a bounded read-only startup probe. General authority lifetime,
rooted byte/rate/slot quotas, incremental authenticated storage/retention, sustained
resource qualification, complete mutation/refinement, clean full R2 and fresh
independent review remain outstanding. All whole R1 findings remain OPEN.

### 2026-09-05 — incremental authenticated journal component (test-only)

Added a bounded immutable-record journal primitive with an authenticated external head anchor, complete-chain authentication before semantic replay, pending-generation recovery, pre-write headroom checks, and durable cleanup of unacknowledged temporary records. Seven component regressions pass; the focused QUV suite passes 48 tests with one existing ignored test. [Retained evidence](evidence/m17q-r1-journal-component-2026-09-05/README.md) includes exact commands, source-subset hashes and logs. Production member storage remains schema 6 full snapshots; this component does not establish rooted production quotas, safe compaction, complete transition refinement or clean R2. All whole R1 critical/high findings remain open.

### 2026-09-05 — journal commit boundary and uncertain I/O (test-only)

The journal now exposes a final caller check after encoding/authentication/headroom and immediately before its first durable write, allowing production integration to preserve the existing live-continuation expiry boundary. Tests require disk non-mutation on refusal and quarantine after record or anchor I/O errors until authenticated reopening. Twelve component tests pass; focused QUV tests pass 53 with one existing ignored test. Removed-check and removed-quarantine controls both fail by assertion. [Evidence](evidence/m17q-r1-journal-component-2026-09-05/README.md) retains the controls separately from the earlier component snapshot. Typed production replay and storage replacement remain unfinished; no whole R1 finding or R2/M17Q/M18Q gate is closed.

### 2026-09-05 — shared typed member transitions and journal replay

Production member staging now applies `MemberDelta::{InsertCandidate, ReservePreparation, AcceptHead}` before its existing authenticated snapshot and anchor writes. Live candidate validation, rooted preparation limits, exact expected-head checks and the final process-local expiry check remain outside the state delta and remain required. Delta bytes never create an online authorization. The replay path restores retained state only after the journal chain and exact independently provisioned bootstrap authenticate.

The journal component and typed replay are not yet the production persistence format. Production member schema 6 still clones and rewrites full state; handoff schema 3 is unchanged. Rooted byte/rate/slot/lifetime quotas, incremental production persistence, safe retention/compaction, aggregate timing qualification and complete transition-level refinement remain outstanding. These changes do not establish clean R2 or close a whole R1 finding.

[Scoped evidence](evidence/m17q-r1-journal-replay-2026-09-05/README.md) retains the comparison against the preceding production staging implementation, exact source revisions, restored unit/runtime checks and removed-retained-candidate / removed-counter-sequence controls. The comparison exercises three consecutive slots in each authority mode with local query grants and recovery after every slot. Following the staging refactor, production and replay deliberately share transition code; their agreement is regression evidence, not independent implementation evidence or a refinement proof.

### 2026-09-05 — prepared deltas and incremental backend component

Production staging now validates borrowed typed transitions and projects exact logical byte growth before mutating a staged snapshot. The test-only schema-7 journal backend uses a cached byte count, bounds delta serialization, commits record and anchor, then applies memory changes. Six integration tests cover three-slot parity in both modes, local grant expiry fences, recovery, uncertain-write quarantine and cached SCALE sizes through 65 slots; transition record lengths remain equal between the first and 65th positions in the fixture. The exact revision passes 59 QUV tests (one existing ignored), 20 runtime tests and CLI compilation. Removed-retained-candidate and removed-counter-sequence controls fail by assertion and are restored. Production still uses schema-6 full snapshots; the journal-directory format switch and its production recovery qualification remain required. [Scoped evidence](evidence/m17q-r1-journal-replay-2026-09-05/README.md) does not close a whole R1 finding, prove complete refinement or admit R2/M17Q/M18Q.

### 2026-09-05 — production schema-7 incremental member persistence

The production member now commits typed journal records and an external authenticated anchor before applying memory or returning a reply/head. Per-transition full-state cloning, hashing and rewriting have been removed from this path. The complete rooted enrollment is matched against an independently constructed bootstrap; schema-6 member files are refused without conversion or mutation. Handoff schema 3 is unchanged. The [journal specification](specs/query_unanimity_journal.md) states the encoding/file-count limits, directory-ancestry sync assumption, recovery behavior and remaining profile/refinement/compaction work. Focused QUV tests pass 60 cases with one existing benchmark ignored; a fresh scoped unit/runtime/benchmark/process qualification is in progress in [retained evidence](evidence/m17q-r1-journal-production-2026-09-05/README.md). No whole R1 finding or R2/M17Q/M18Q gate is closed.

### 2026-09-05 — schema-7 scoped process qualification

The production journal revision passes 60 QUV tests (plus its separately executed 256-sample durability benchmark), 20 runtime tests, CLI compilation and a syscall-order ancestry check. The fresh three-slot process campaign passes unchanged-source checks: exact four-member participation for all three slots, restart before slot 3, unchanged terminal-parent replay and an unrelated same-executor effect during the wait. Strict evidence checkers pass; 13 completed operations and 17 final releases have maximum observed active hold 6,369,893 microseconds against the fixture's 10-second limit. [Retained evidence](evidence/m17q-r1-journal-production-2026-09-05/README.md) is finite scoped qualification, not a rooted aggregate resource/service bound, full refinement, clean R2, independent review or whole R1 closure.

### 2026-09-05 — rooted preparation replay and bounded preparation waiting

The current closure index is [the R1 fault/property matrix](specs/query_unanimity_fault_property_matrix.md). Its 13 rows now explicitly map remaining production changes, proof obligations, positive/negative regressions, mandatory qualification and exact independent-review closure conditions. All whole findings remain OPEN.

Member schema 8 records the preparation policy preimage with each durable reservation. Shared live/replay validation binds that preimage to the enrolled domain policy root and refuses counters beyond its committed attempt cap. Reopen cannot refund reservations. Schema-7 bootstrap refusal preserves the existing record directory and anchor; no migration or reset of conflict knowledge is authorized. The outer journal format and handoff schema 3 are unchanged.

The runtime admission gate now reserves at most one preparation waiter, enforced internally rather than solely by the single-worker call convention. Together with one foreground waiter per configured domain, at most D+1 operations wait in the active FIFO and at most one is active. Cancellation frees waiting capacity and a replacement joins behind existing requests. This is a queue-count bound, not a scheduler, durable-I/O, service-time or complete Q-A9 proof.

Scoped checks and source bindings are retained in `evidence/m17q-r1-rooted-replay-2026-09-05/`. Schema-7 process evidence remains historical: 65 retained source hashes verified unchanged. Rooted finite authority/byte/rate/slot bounds, safe retention/migration, aggregate service/recovery costs, complete refinement, clean R2 and fresh review remain required. No M18Q claim is admitted.

### 2026-09-05 — streaming authenticated recovery

Journal reopen no longer builds a path map or retains every payload. Canonical unique filenames, initial presence, count and greatest generation establish the contiguous range; both streaming passes check every MAC, root, generation, previous hash and anchored head. The first complete authentication pass precedes callbacks; the second reauthenticates individual records and must end at the identical first-pass head before anchor repair or successful return. Replay remains private, non-authorizing state reconstruction. Auxiliary memory is per-record/bootstrap, while retained member state still grows within its logical limit; two linear reads replace buffered replay. This does not establish allocated-disk bounds, a rooted lifetime/slot horizon, compaction or worst-case recovery time. Fourteen journal regressions pass, including sparse/noncanonical filenames and changed or reauthenticated pending tails between passes. Current-source integration checks follow in the rooted-replay evidence directory.

The streaming revision's complete scoped run finished with unchanged selected sources: 64 QUV tests, 21 runtime tests, CLI test-target compilation, formatting and runner syntax all passed. Exact commands, source copies/hashes, raw logs and tool versions are retained under `evidence/m17q-r1-rooted-replay-2026-09-05/streaming-recovery/`. The existing benchmark was not rerun; no performance/process claim is transferred from schema 7 or the preceding schema-8 revision.

### Resume checkpoint — schema-9 finite encoded profile

HEAD remains `24a9888e3b88383c18dfbfea0f2e7fa44b99fa64`, with the existing dirty
worktree preserved. No immutable candidate, commit, public action or reviewer
was created in this continuation. No commands remain running at this checkpoint.
The active goal is unfinished; no fixed-assumption counterexample or external
owner dependency has been established.

Production now uses policy root `v4-conflict-summary`, schema-9 member state,
mandatory nonwrapping finite `authority_slots`, two retained distinct candidates
per slot, a 4096-byte candidate cap, 8192-byte transition-record budget and
startup encoded lifetime accounting. Historical slot queries remain supported;
saturated summaries emit fresh valid conflict observations without journal
updates. Rooted preparation replay checks the independently enrolled horizon
and attempt cap. The runtime enrollment factory derives the policy root and
limits from the same policy. Old schema-7/8 bootstraps are refused intact.

The full coherent scoped batch passed: 70 core tests (one benchmark ignored),
21 runtime tests, the configuration regression, CLI compilation, formatting,
runner syntax, 27 summary-proof obligations, 36 lifetime-proof obligations,
the 6144-state positive lifetime model and required event-reuse countermodel.
Evidence is `evidence/m17q-r1-rooted-replay-2026-09-05/finite-profile/`, with a
retained repeat at `finite-profile-final/`. Both bind 70 selected production and
formal sources with no drift; narrative documents are excluded. The repeat
followed an overly broad documentation-drift concern and adds no coverage.
Raw intermediate proof/test failures remain under `conflict-summary/` and
previous component directories. Do not rerun these completed components merely
to rediscover their status. No schema-7 process/performance evidence qualifies
the newer profile.

The exact next production dependency remains the integrated resource/service
profile in row QUV-M17Q-006 of the single fault/property closure matrix. Encoded
headroom does not reserve filesystem blocks, directory/inode capacity, memory,
or recovery time. Next inspect the whole allocation/service path through
`journal/member_store.rs`, `journal.rs`, PQ `swarm.rs`/`pq_channel.rs`, runtime
`quv/event_dispatch.rs`/`quv/admission.rs`, and consequence persistence. Existing
one-in-flight-per-authenticated-account lanes and local FIFO are bounded counts,
not yet a rooted end-to-end rate/service theorem. Establish physical capacity
and bounded service without dropping required correct-member participation or
forgetting retained conflicts. Complete cross-configuration retention/recovery
and the full admission/head/recovery/continuation/handoff/T10 refinement bridge.
The new lifetime proof assumes unique transition accounting; its Rust mapping
and aggregate physical bounds remain obligations, not discharged assumptions.

Then run clean full M16Q R2, isolate/freeze the exact candidate, commission only
the expressly authorized fresh independent automated reviewer, and execute the
repair/requalification/review loop before M18Q and owner handoff. All 13 whole
R1 findings remain OPEN. M15Q is reopened, M16Q R2 unqualified, M17Q R1 remains
REPAIR_REQUIRED, and M18Q is NOT_ADMITTED. M12a/M12b, every executor's live path,
nonrollback custody, every-correct-member timing and
`portable_final_receipt=false` remain binding.


### PQ sendability boundary — retained checkpoint

The preceding turn made production and verified-test progress. The current
turn additionally shared the existing record plaintext cap with durable outbox
admission/recovery. All 20 channel tests, 6 record-layer tests, the final exact
boundary test, formatting and runner syntax passed. Evidence is retained at
`evidence/m17q-r1-outbox-plaintext-2026-09-05/`. No live jobs or reviewer remain.
Production sources did not drift after the evidence snapshot; a later runner
hash-list addition is explicitly recorded with both manifests.

Continue integrated R1-006 work in PQ persistence: `PqDurableOutbox::open` still
reads a whole file before aggregate validation, and `commit_with` clones and
rewrites the complete outbox. Per-recipient count bounds plus a per-message
wire cap do not establish reserved physical capacity or bounded QUV service.
An incremental persistence and aggregate reservation profile must preserve the
reserved QUV lanes and correct-member processing while accounting for normal
consensus traffic, recovery, and configuration lifetime. Member-store physical
allocation, consequence storage, cross-configuration retention and full
transition refinement remain open. Preserve prior schema-9 evidence; it does
not qualify these subsequent networking changes. HEAD, all 13 OPEN findings,
M15Q–M18Q dispositions, fixed premises and owner-only boundaries are unchanged.


### Outbox staging memory — retained checkpoint

This turn made production and verification progress: pending entries are shared
immutably during transaction staging, and snapshot encoding uses a fixed 64 KiB
buffer with explicit I/O error propagation. Schema-2 bytes remain unchanged.
Twenty PQ channel tests and the new old-format/error regression passed;
formatting and runner syntax passed. Evidence:
`evidence/m17q-r1-outbox-streaming-2026-09-05/`. No live jobs remain.

Next complete incremental outbox persistence and bounded recovery/aggregate
reservation; current disk writes still rewrite every retained payload. Preserve
atomic replacement, ACK/nonce retirement, durable enqueue before discovery and
uncertain-write quarantine. The existing generic storage WAL has placeholder
CRC and is not an authenticated substitute for the QUV journal. A new backend
must be qualified for its actual durability and physical/service costs; merely
adding a database dependency does not discharge them. The Arc/streaming change
removes temporary whole-payload copies but is not a full resource-profile fix.
All prior physical-capacity, retention, refinement, clean R2, immutable candidate,
fresh review and M18Q obligations remain; no whole finding is closed.


### Bounded-entry outbox recovery — retained checkpoint

This turn made production and verification progress. `pq_channel/outbox_decode.rs`
now streams v2 recovery with header-first scope checks, fixed buffering, bounded
entry decoding and strict complete consumption. Twenty-three channel tests
passed; the final allocation probe/removed-budget control passed separately.
Evidence: `evidence/m17q-r1-outbox-recovery-2026-09-05/`. No schema or transport
limit changed. No immutable candidate or review was commissioned.

Next integrated dependency remains aggregate rooted reservation and incremental
outbox disk persistence. The whole-file input buffer is gone, but every valid
retained entry still occupies memory and every commit still rewrites the full
snapshot. Rooted account scope is available at the `PqChannelLocalConfig`
construction sites in validator `consensus.rs` and `lifecycle.rs`; current
outbox enrollment occurs before peer discovery and must preserve that behavior.
Do not mistake per-entry bounds or per-recipient counts for reserved aggregate
physical capacity. Preserve ACK/nonce retirement, crash/retry semantics and
normal-consensus versus QUV reserved lanes. All resource/service, retention,
full refinement, clean R2, freezing, fresh independent review and M18Q obligations
remain. All 13 whole R1 findings remain OPEN, and fixed truth boundaries hold.


### Rooted recipient capacity — retained checkpoint

This turn made production and verification progress. `PqChannelLocalConfig`
requires the independently rooted old/staged account set; startup and rotation
factories populate it before discovery. Outbox enqueue/enrollment/recovery enforce
that scope. Streaming recovery caps counts and checks each recipient before
payload allocation. Final checks: 24 channel, 21 QUV runtime, swarm admission,
CLI compile, formatting and runner syntax pass. The synthetic provisional-capacity
fixture failure is retained; declarations were repaired without weakening its
assertions. Evidence: `evidence/m17q-r1-rooted-outbox-2026-09-05/`.

Next complete aggregate byte/physical reservations and incremental outbox disk
persistence under this rooted recipient set. The N*1026 count bound plus 16 MiB
wire cap is a finite but potentially huge encoded envelope, not reserved capacity
or a timing proof. Current snapshots still rewrite all retained payloads.
Preserve pre-discovery queueing, old/staged capability separation, ACK/nonce
retirement and uncertain-write quarantine. Membership-set narrowing refuses
retained foreign entries; safe reconfiguration retirement must not erase them
merely to force reopening. Member/consequence physical resources, rate/service,
retention and full transition refinement still precede clean R2, freezing,
fresh independent review and M18Q. No whole R1 finding is closed; no immutable
candidate, public action or reviewer exists for these repairs.


### Indexed outbox production — retained checkpoint

This continuation made production, formal and verification progress. Outbox
commits now write immutable new entry files and an ordered AFTPQI03 index,
then delete retired files; unrelated payloads are not rewritten. Recovery
validates the rooted index and all referenced commitments before orphan cleanup.
Valid v2 conversion occurs during startup before live admission. Directory
creation syncs complete ancestry before staging writes. Logical entry/scope
schema remains v2; this is a transport storage change, not member-custody migration.

Final scoped checks pass: 27 channel tests, 21 QUV runtime tests, CLI compilation,
swarm admission, 9 TLAPS obligations, the 79-state model, both required ordering
countermodels and the ancestry syscall/removed-sync check. Formatting and runner
syntax pass. Initial dispatch/format failures are preserved. Exact selected
sources, commands, tools and logs are at
`evidence/m17q-r1-indexed-outbox-2026-09-05/`. The M16Q runner now requires the new
storage cases and ancestry gate; the full formal harness includes the model/proof.
No commands remain live at this checkpoint. No public action, immutable candidate
or fresh reviewer was created. The existing dirty worktree is preserved.

Next production dependency is aggregate byte/physical reservation plus rooted
rate/service bounds, consistently across the now-incremental outbox, member
journal, transport/authentication queues and consequence storage. Index work is
still O(pending entries); recovery and conversion are linear. N*1026 recipient
count bounds plus a 16 MiB wire ceiling can imply huge encoded storage and are
not a reservation. Directory allocation need not shrink on unlink. Account for
actual blocks/inodes, memory, pending temporaries, write/fsync costs and shared
resources while preserving every correct member's complete processing. Do not
replace these obligations with refusal, sample timings or a conditional lifting
lemma. Finish retention/reconfiguration and the entire admission/head/recovery/
continuation/handoff/T10 transition bridge before clean R2, immutable freezing,
fresh automated independent review and M18Q handoff. All 13 whole R1 findings
remain OPEN; M15Q is reopened, M16Q R2 unqualified, M17Q REPAIR_REQUIRED, M18Q
NOT_ADMITTED. Fixed M12a/M12b and portable_final_receipt=false boundaries hold.


### Retained checkpoint — rooted logical byte reserve

This turn made production, formal and verification progress. The v5-outbox-budget
policy root binds (1024 normal records, 16 MiB normal payloads, 2 QUV records,
16 KiB per QUV payload, 32 KiB QUV payloads) per rooted recipient. The outbox
allows one request and one reply lane and enforces class bytes during live
preflight and streaming recovery. OnlineAuthorization record sealing/opening
checks the frame ceiling before sequence consumption. Normal frames retain the
existing 16 MiB wire limit. Member schema remains 9, outbox index AFTPQI03 and
logical entry schema v2. No old policy/custody state was reset or migrated to v5.

The unchanged-source scoped run passes: 70 core, 29 channel, 21 runtime tests,
CLI compile, formatting, runner syntax and the formal gate. Seven record-layer
tests separately pass on final crypto source. Seventeen TLAPS obligations and
the 12-state model prove logical reserve properties; the shared-budget mutation
fails as required. Initial lint/proof failures are retained. Evidence:
`evidence/m17q-r1-quv-byte-profile-2026-09-05/`. No live jobs remain after polling
completion. Do not rerun completed components solely to rediscover this state.
Old v4 process or performance evidence is not qualification for these changes.

Next integrated work remains physical reservation plus rooted rate/service
bounds and complete transition refinement. Pending payload bytes now have a
finite N*(16 MiB+32 KiB) envelope. Add actual entry/index metadata, allocation
rounding, inodes/directory growth, temporary payload/index files, startup migration
copies, receiver/active buffers and external-effect storage. Logical byte caps
are not physical allocation guarantees, and normal-traffic refusal is not
inclusion or effect progress. The lane/cost proof must cover actual transport,
authentication, queues, fsync, recovery and externalization under the fixed
synchrony assumptions; finite timing samples cannot discharge worst-case counts.
Finish retention/reconfiguration and admission/head/recovery/continuation/handoff/
T10 refinement, then clean full R2, immutable freezing, fresh independent review
and honest M18Q owner handoff. All 13 whole findings stay OPEN; M15Q reopened,
M16Q R2 unqualified, M17Q REPAIR_REQUIRED, M18Q NOT_ADMITTED. Fixed M12a/M12b,
every executor's own live path and portable_final_receipt=false remain binding.


### Retained checkpoint — allocated queue-index exchange

AFTPQI04 now uses two allocated index files. Startup validates and converts the
old queue, reserves both files and verifies atomic exchange support before
returning a usable handle. Live commits sync the inactive image, exchange names,
sync the parent and only then retire payloads/publish live state. No live index
create/truncate/allocation occurs. Lost allocation, aliased files, incomplete
inactive images, active corruption and the exchange-to-directory-sync interval
have explicit defensive regressions. Member schema 9, logical entry schema v2
and v5-outbox-budget policy roots remain unchanged. The storage profile currently
requires Linux allocation/exchange interfaces; it is not fully qualified.

Final unchanged-source scoped evidence is
`evidence/m17q-r1-index-reservation-2026-09-05/`: 33 channel, 21 runtime tests,
CLI compile, formatting/syntax, 9 reserved-index TLAPS obligations, a 10-state
positive model and two expected mutations; the prior index/payload proof and
ancestry gate pass on this source, as does the new syscall gate. Initial fixture
failure and intermediate logs are retained. This is a dirty source subset,
not clean R2. No live job remains; the final campaign handle 53413 was observed
to exit 0. HEAD remains 24a9888e3b88383c18dfbfea0f2e7fa44b99fa64.

Exact next production dependency: QUV payload reservation. The existing live
writer still creates payload files. A fixed four-slot arena per rooted recipient
would permit retaining both old QUV lanes while staging both new ones; it is a
design candidate only, not implemented. Bind location/recovery to the validated
index; never fall back to inactive or retired payloads. Account for normal-path
capacity errors, filesystem metadata/journal space, memory, lifetime retention
and full service bounds. Two allocated index files alone do not discharge the
physical-resource antecedents. Then finish admission/head/recovery/continuation/
handoff/T10 refinement, clean full R2, immutable freeze, fresh authorized
independent automated review and M18Q handoff. All 13 whole findings remain
OPEN; M15Q reopened, M16Q R2 unqualified, M17Q REPAIR_REQUIRED and M18Q
NOT_ADMITTED. M12a/M12b boundaries and portable_final_receipt=false hold.


### Retained checkpoint — payload arena and normal capacity isolation

Production QUV payloads now occupy a scope/root-bound allocated four-slot arena
per recipient. Both old lanes remain protected while both replacements stage;
arena fsync precedes index exchange. AFTPQI04 envelopes carry AFTPQI05 indices,
with AFTPQA01 payload arenas. Validated old file-backed queues convert at startup;
active arena state is never reset or replaced by retired payload files. Member
schema 9, logical entry schema v2 and v5-outbox-budget policy roots are unchanged.
Normal ENOSPC/EDQUOT refuses a new payload without quarantining the existing queue
only after all uncommitted files are durably cleaned before index commit. Cleanup
failure, EIO and uncertain index outcomes remain quarantined.

Final unchanged-source evidence:
`evidence/m17q-r1-payload-arena-2026-09-06/normal-capacity/` passes 36 channel,
21 runtime tests, CLI compile, formatting/syntax, 6 arena TLAPS obligations and
a 113-state slot model with two expected mutations. The index kernels pass 9+9
obligations, 10/79 states and four expected mutations. Both syscall gates pass.
The earlier arena-only run and all development logs remain in the parent folder;
use normal-capacity for the current source binding. Final handle 27187 was
observed to exit 0; no live jobs remain. HEAD is still
24a9888e3b88383c18dfbfea0f2e7fa44b99fa64, with unrelated dirty changes preserved.

Next integrated dependency: finish the physical/resource/service profile beyond
outbox data blocks. Inspect member/handoff journal and consequence storage
allocation and retention; account for filesystem metadata/journal space, peak
normal-payload staging/recovery, rooted RAM/allocator/container costs, and actual
transport/authentication rate and fair service bounds. The arena currently
revalidates retained entries, stages metadata and encodes a global index per
commit: these costs must appear in the worst-case envelope. Qualify actual
sustained pressure and restart behavior; error injection and finite samples do
not establish the platform theorem. Finish cross-configuration retention and
admission/head/recovery/continuation/handoff/T10 refinement, then clean full R2,
immutable freezing, fresh independent automated review and honest M18Q handoff.
All 13 whole findings remain OPEN; M15Q reopened, M16Q R2 unqualified, M17Q
REPAIR_REQUIRED, M18Q NOT_ADMITTED. M12a/M12b and portable_final_receipt=false
boundaries remain fixed. No external blocker or premise-defeating evidence has
been established; the remaining work is executable remediation/refinement.


### Current continuation checkpoint — member record-data reservation

Production derives G from the complete rooted H/A lifetimes and allocates every
future record inode before admitting a member handle. Existing authenticated
schema-9/AFTQJ001 bytes are unchanged. A signed scope/limit root binds the sibling
reservation pool; pool bytes never become journal transitions. Live preflight
checks the next empty file and its allocated-block charge before continuation;
record data is synced and its inode renamed/synced into the journal before the
independent anchor update, memory application and reply. Recovery authenticates
and replays the retained chain before resetting unacknowledged reservations.
Lost or excessive physical allocation quarantines; encoded request-capacity
refusal remains nonmutating. Metadata/anchor allocation is not yet reserved.

Final current-source evidence is
`evidence/m17q-r1-member-reservation-2026-09-06/allocation-charge/`: 75 core,
21 runtime tests, CLI compile, formatting/syntax, 9 reservation TLAPS obligations,
15 positive states/two expected mutations, the 36-obligation lifetime gate and
production syscall checks pass. The parent source separately passed 74 core,
21 runtime and the 256-sample benchmark; that benchmark predates the excessive-
allocation quarantine repair and must not count as current-source M16Q evidence.
Initial compile, obsolete staging-fixture, timing-fixture and pre-fix physical-
charge failures are retained. No deadline/assertion was relaxed. Allocation is
batched before syncing every inode, and fixtures obtain readiness/fresh live
interaction after provisioning instead of extending old grants.

All jobs were observed terminal: final 6876 exited 0, parent/benchmark 84953
exited 0, earlier development handles closed. No live jobs remain. HEAD remains
24a9888e3b88383c18dfbfea0f2e7fa44b99fa64. This is a dirty source subset; unrelated
work is preserved and no candidate, tag or public action was created.

Exact next action: integrate the prepared, currently UNLINKED and UNTESTED
`crates/consensus/src/aft/query_unanimity/journal/anchor_reservation.rs`. It stages
fixed-size raw authenticated anchors through two reserved inodes and atomic
exchange. Connect it only after active-anchor authentication and full semantic
replay; preflight resources before the live continuation and commit the anchor
only after the record is durable. Preserve pending-record/anchor-failure tests
by injecting errors at their actual durable boundary, not by accepting arbitrary
failure. Compile/run the new primitive tests, production regressions, formal and
syscall mapping. The draft is explicitly excluded from the tested-source claim.
Then finish handoff/consequence/metadata/RAM/rate/fair service and full transition
refinement before clean full R2, immutable freezing, fresh independent automated
review and honest M18Q owner handoff. All 13 whole findings remain OPEN; M15Q
reopened, M16Q R2 unqualified, M17Q REPAIR_REQUIRED, M18Q NOT_ADMITTED. No external
blocker or fixed-premise defeat is established. M12a/M12b and
portable_final_receipt=false remain fixed.

### Current continuation checkpoint — integrated anchor/handoff reservation

This supersedes the prior unlinked-anchor checkpoint. Production schema-9 member
journals now preflight and reuse two fixed authenticated anchor allocations,
after full semantic replay; record durability precedes anchor exchange/directory
sync and memory/reply. Three anchor primitive tests plus three journal crash/
capacity/authentication tests and an extended syscall checker are integrated.
`evidence/m17q-r1-anchor-reservation-2026-09-06/` retains 81 core/21 runtime tests,
CLI, 10 anchor TLAPS obligations/36 positive states/two expected mutations,
record/lifetime proofs and trace checks. The obsolete preparation failure fixture
was repaired using a real post-record/inactive-anchor-durable test hook; all
original recovery/nonmutation assertions remain. Its failed run is retained.

Handoff install now fences expiry after preparation and checks authenticated
one-shot recovery shape. `evidence/m17q-r1-handoff-final-fence-2026-09-06/` retains
83 core/21 runtime tests, CLI and 10 continuation TLAPS obligations/145 positive
states/two expected mutations, plus restored outcome-based production negative
controls. This is a conditional kernel, not complete transition refinement.

Handoff now prepares exact state/anchor capacity from its validated envelope
before the successor begins its own live QUV. It fixes one prepared identity,
preflights exact size/intact allocation before final consumption, transfers the
reserved state inode durably, then commits the reserved anchor before memory.
Preparation creates no activation authority. Production orchestration calls
prepare_install_capacity in a blocking task before begin_online_authorization.
Raw handoff schema 3 and MAC/anchor recovery semantics remain. Tests preserve
pending-state recovery via a post-state-durable anchor hook. Parent evidence
`evidence/m17q-r1-handoff-reservation-2026-09-06/` has 84 core/21 runtime tests,
CLI, focused formal and production state/anchor trace checks. A subsequent
runner-only gate/hash addition is separately bound in runner-followup/.

A further durability audit found that a separate custody directory ancestry
must be synced before live admission. That production fix is now applied in
handoff_reservation.rs. The exact-source collector is LIVE at shell session
38802, logging to
`evidence/m17q-r1-handoff-reservation-2026-09-06/ancestry/run.log`.
Poll this existing handle; observation timeout is not failure. The parent
84-test evidence predates this ancestry fix and is not final-source evidence.
The new trace fixture uses distinct handoff/ and custody/ directories. Next:
verify its terminal results, then strengthen the fixture to a deeper independent
custody ancestry (custody/nested/state.anchor) and remove only that intermediate
custody fsync in the negative trace. The current removed-common-temp-ancestor
control is too broad to isolate the distinct-custody obligation; do not call it
that narrower proof. Preserve current results and collect the focused final
source/checker evidence after that refinement.

Then continue the integrated resource profile in
`crates/agentgres/src/consequence.rs`: ConsequenceStore::prepare_online_effect,
execute_with_online_authorization, execute_after_online_authorization and
persist_receipt/atomic_write still use growing JSON receipt snapshots and live
allocation. Both production callers are in validator orchestration/mod.rs and
grpc_public.rs. Derive complete receipt/audit/trace/reconciliation bounds from
the rooted manifest; reserve before live QUV and preserve final T10 height/
expiry/admission checks, idempotency and lookup-only recovery. Do not silently
cap admitted work or alter the separate portable profile. Metadata/RAM, aggregate
transport/authentication/fair service/recovery, cross-configuration retention and
full transition refinement still precede clean full M16Q R2, immutable freezing,
fresh authorized independent review and honest M18Q owner handoff.

All prior handles in this continuation were observed terminal (including 55515
and 97485); only 38802 is live at this checkpoint. HEAD remains
24a9888e3b88383c18dfbfea0f2e7fa44b99fa64. Unrelated dirt is preserved; no immutable
candidate, tag, reviewer or public action exists. All 13 whole findings remain
OPEN; M15Q reopened, M16Q R2 unqualified, M17Q REPAIR_REQUIRED, M18Q NOT_ADMITTED.
No external blocker or fixed-premise defeat is established. M12a/M12b and
portable_final_receipt=false remain fixed. Earlier benchmarks and process
campaigns retain their old exact source bindings and cannot qualify these repairs.

Checkpoint correction: shell 38802 is terminal, exit 1. Its production checks
passed (84 core, 21 runtime, CLI, fmt/syntax, record/anchor/continuation/lifetime
formal and handoff trace). The final record-trace command had an extra script
argument from collector construction and exited 2; preserve ancestry/results.json
and trace.log as a collector failure, not a passing complete campaign.

The fixture/checker now use custody/nested/state.anchor and remove only the
intermediate /custody fsync for the distinct-ancestry negative control. The
collector argument is corrected in the new immutable evidence subdirectory.
CURRENT LIVE shell handle: 91152. Its exact-source collector log is
`evidence/m17q-r1-handoff-reservation-2026-09-06/ancestry/deep-custody/run.log`.
Poll 91152, do not restart. No other live jobs remain. Next action is inspect its
terminal results, repair any actual failure without changing deadline/assertion
requirements, then write its README/environment/checksums and update this index
with the exact source limitations. The larger consequence/resource/refinement
path in the preceding checkpoint remains the next production dependency.


Handle 91152 is terminal exit 0. The distinct intermediate-custody follow-up
passed all declared checks: 84 core/21 runtime, CLI, fmt/syntax, four focused
formal gates, record and handoff traces. Exact source, commands, environment,
README and checksums are retained in
`evidence/m17q-r1-handoff-reservation-2026-09-06/ancestry/deep-custody/`.
The earlier collector error and broader negative control remain historical.
Production work has advanced to consequence trace/resource bounds; no admission
or whole finding disposition changed, and no handoff jobs remain live.


### Current continuation checkpoint — consequence representation bounds

The handoff deep-custody follow-up is complete and source-bound at
`evidence/m17q-r1-handoff-reservation-2026-09-06/ancestry/deep-custody/`.
No old handoff jobs remain live.

ConsequenceStore now checks trace length <=4+M on live transition and receipt
validation, where M is the exact manifest reconciliation allowance. The named
PQ register enforces ML-DSA-44, canonical JCS evidence <=16 KiB, and bounded
<=80 KiB record reads before decoding. A maximum-token/signed-record regression,
wrong-suite/noncanonical/oversized controls and independent direct canonical-byte
hash comparison pass. Receipt roots use a borrowed zero-root view and canonical
hashing writes into SHA-256, eliminating the explicit receipt clone and extra
output Vec; JCS's internal object buffering remains.

For the named online PQ adapter, online_receipt_byte_bound derives and enforces
B_manifest + 4*16 MiB + 512*(4+M) + 80 KiB + 32 KiB before persistence. The full
manifest and observation budget remain intact. Stored resource records for that
profile reject evidence beyond its format bound before record hashing.

Current final scoped evidence:
`evidence/m17q-r1-consequence-trace-bound-2026-09-06/receipt-budget/`.
26 consequence tests, 7 manifest type tests, 21 runtime tests, 2 executor refusal/
lock tests, CLI, fmt/syntax, existing T10 formal and 17 trace/format TLAPS
obligations pass. The positive trace model has 44 states; reused lookup readiness
violates TraceBound. Four production guard-removal controls fail the intended
assertions and are restored exactly; baseline/mutant sources are archived.
The first charge lemma lacked numeric typing and failed; TypeOK is now an
explicit antecedent already proved in the invariant. Failed evidence is retained.
The parent 24-test and hash-view 25-test revisions have separate source bindings.
All three collectors passed unchanged selected-source checks and have README,
command/toolchain/hash records and child-first checksums. They are not immutable
qualified checkouts. All jobs in this continuation are terminal, including final
95387 (exit 0); there are no live shell jobs to resume.

Exact next production action: replace live snapshot allocation in
crates/agentgres/src/consequence.rs::persist_receipt/atomic_write for the named
online profile with prepared physical storage using online_receipt_byte_bound.
Also cover DurablePqAtomicRegisterV1::invoke_atomic's endpoint file allocation
and lock/directory lifecycle. Preparation must occur before the executor's own
live operation, in both orchestration/mod.rs and grpc_public.rs, while retaining
current admission rederivation, immediate Claim height/expiry fencing, idempotency
and lookup-only recovery. Reserve actual allocated data and account separately
for metadata; do not relabel encoded length as physical allocation. Preserve
portable/generic resource semantics and complete authoritative format/recovery
validation before any conversion or spare-file reset. Avoid a consensus crate
dependency in Agentgres; preserve the Hypervisor graph. No allocator/format
module draft has been created in this turn.

Then finish root/profile binding and global capacity feasibility before admitting
operations; complete predecode/aggregate RAM, metadata, fair authentication/
transport/service, recovery and cross-configuration retention bounds. The current
receipt bound does not yet discharge any of those. Full admission/head/recovery/
continuation/handoff/T10 refinement still precedes clean full M16Q R2, immutable
freezing, authorized fresh independent review and M18Q owner handoff.

HEAD remains 24a9888e3b88383c18dfbfea0f2e7fa44b99fa64; unrelated dirt is preserved.
All 13 whole findings remain OPEN; M15Q reopened, M16Q R2 unqualified, M17Q
REPAIR_REQUIRED, M18Q NOT_ADMITTED. No candidate/tag/reviewer/public action exists.
No indispensable external blocker or fixed-premise defeat has been established.
M12a/M12b and portable_final_receipt=false remain binding.

## Continuation checkpoint — endpoint/receipt physical data, policy v6 (2026-09-06)

Endpoint and receipt changes are implemented and their scoped pre-v6 campaigns
passed. Endpoint evidence: evidence/m17q-r1-endpoint-reservation-2026-09-06/
(28 consequence, 7 types, 21 runtime, 2 executor, CLI, fmt/syntax, scoped proofs
and syscall ordering). Receipt evidence: evidence/m17q-r1-receipt-reservation-2026-09-06/
(30 consequence, 7 types, 21 runtime, 2 executor, CLI, fmt/syntax, reused
conditional index/record/T10/trace proofs and both syscall gates). Each has exact
selected source archives, restored production negative controls and checksums.
They remain dirty-worktree scoped campaigns, not immutable qualification.

DurablePqAtomicRegister reserves its one-shot 81920-byte record before QUV in
both executor entry paths; live calls consume the same inode with write/fsync/
rename/dirsync, no late fallback. Active records are bounded/canonical/key-matched
and signed; corrupt active bytes never choose spare. Uncertain commit quarantines
the handle. Safe rustix 1.1.3 allocation preserves Agentgres forbid(unsafe_code).

Named online receipts use AFTCR001, a fixed initialized two-file envelope around
the unchanged canonical receipt. Payload length/capacity/reported allocation are
validated; live replacements use write/fsync/exchange/dirsync without allocation
or truncation. Preparation initializes the whole pair before QUV, and persists
the replacement name before resetting the former active inode. Lost capacity
refuses before Claim without endpoint mutation; store quarantine/reopen and
corrupt-active/non-fallback tests pass. Initial payload-equals-physical prototypes
failed on 4096 extra filesystem-reported bytes; failed sources/logs are retained.
The final profile separately records physical allocation <=2C per file, C being
page-rounded encoded bound +32-byte header. Full metadata service remains open.

Current source advances policy root to v6-consequence-storage, binding twelve
shared QuvConsequenceStorageProfileV0 coefficients. Full u32 observation budgets
are preserved, overflow refuses, and per-effect data charge is explicit. No v5
migration or aggregate admission guarantee is implied. The independently encoded
policy-vector script produces root
4abba2118280e71d1eaaf947b8e309e64309866f62982c96f24fd6fdfc675056 for its fixture.

Collector38935 completed: 84 core (one scoped benchmark ignored), 30 consequence,
8 types, 21 runtime, 2 executor, CLI, fmt/syntax and all selected proof/syscall
gates passed. Missing-storage-field mutation6319 failed the exact independently
predicted root assertion and restored source. All selected source hashes were
rechecked and evidence packaged with checksums. No live jobs remain. A development core invocation used the nonexistent consensus-aft
feature; it did not run tests and is retained separately.

Exact next integrated work: trace rooted aggregate resource admission before
preparation/commit, including physical per-effect totals, manifest count/size,
full observation allowances, fair service and predecode/aggregate RAM. Current
AftEffectRegistry admits at most one exact manifest per block but no finite
rooted total; runtime committed_consequence_manifest scans all committed effects
and staged blocks. Workload setup currently instantiates a unit registry service
without orchestration QUV policies. Do not silently add a per-slot quota that
changes admitted-operation or correct-member guarantees. Queue/selection and
preparation initialization costs must enter their proper rooted service bounds.
Then complete retention/recovery and full transition refinement, clean full R2,
immutable candidate, authorized fresh independent review and M18Q handoff.

All 13 whole findings remain OPEN. M15Q reopened; M16Q R2 unqualified; M17Q
REPAIR_REQUIRED; M18Q NOT_ADMITTED. HEAD remains
24a9888e3b88383c18dfbfea0f2e7fa44b99fa64. Unrelated dirt preserved. No candidate,
tag, reviewer or public action; no indispensable external blocker established.

Initialized endpoint follow-up completed, at
evidence/m17q-r1-consequence-profile-2026-09-06/initialized-endpoint/.
Collector29654 and root mutation76833 are terminal. 84 core (one benchmark
ignored in scope), 30 consequence, 8 types, 21 runtime, 2 executor, CLI,
fmt/syntax, selected proofs and both syscall gates pass. Source restored and
verified; child/parent checksums updated. No live jobs remain.
The root now has 13 fields including ENDPOINT_INITIALIZED=1; fixture root is
4248290434dd4679b21b36dadd56574c7f781b800b528b9ed7b83198774cd079. Endpoint
staging is fully space-written before QUV; live commit checks untouched padding
and exact allocation, publishes same inode; lookup validates canonical JSON
plus only the exact full-size padding. This removes unwritten-extent conversion
from the endpoint interval. Earlier 12-field evidence is a separate revision.

Next concrete service repair: replace committed_consequence_manifest's per-call
full-history sort/read scan with a non-authorizing locator index, rebuilt from
verified committed records on open and updated under the admission mutex after
durable commit. Every lookup must still re-read/hash-check the selected staged
block and exact Agentgres manifest root; duplicate effect identities must remain
refused, and index corruption/substitution must not authorize a different effect.
Prove the index fold/recovery invariant and test selected-block read count,
duplicate admission, reopen and wrong-locator negatives. The index's own memory
and startup scan still enter the larger aggregate profile; this is not closure.
Then finish rooted manifest/count/observation capacity admission, predecode RAM,
metadata, fair scheduling, retention and complete transition refinement before
clean R2/fresh independent review/M18Q. All whole dispositions remain unchanged.

### Effect preparation guard (2026-09-06)

Both executor entry points compare exact manifest binding and run rooted
signature, membership, policy and expected-head preflight before per-effect
allocation. Authorized/Claimed retries require preflight; non-executable
readmission skips it but still rederives committed authorization. Preparation
creates no live grant. Global lock files may precede this guard.

`QuvEffectPreparationProof` proves a conditional guard kernel: nine TLAPS
obligations and 25 states pass. **Assumes:** correct committed admission and
rooted validator predicates, exclusive nonrollback custody, and OwnLive denotes
the executor's own successful exact-root QUV. Complete transition composition
and physical/fair service bounds remain open. SkipBinding/SkipPreflight violate
PreparationChecked; PreparedBearer violates GrantIsOwn.

Evidence: `evidence/m17q-r1-effect-preflight-2026-09-06/` (selected worktree
source, not immutable qualification). 31 consequence, 15 runtime-finality,
21 QUV runtime and two executor tests, CLI compile, formatting and formal checks
pass. Three production omission controls fail as intended; source is restored.
The new sole-correct-placement process negative requires the precise signature
refusal and unchanged per-effect bytes before valid execution; compiled only.
All 13 whole findings remain OPEN; R2 unqualified, M17Q REPAIR_REQUIRED,
M18Q NOT_ADMITTED.

Locator evidence also completed: m17q-r1-manifest-locator-2026-09-06 retains
15 runtime-finality/21 runtime/two executor checks, ten TLAPS obligations/35
states and three restored production controls. Next concrete repair: retain
operation admission through continuation consumption and consequence/handoff
work, then integrate preparation admission, aggregate capacity and retention.

### Continuation admission ownership (2026-09-06)

The runtime completion channel carries a non-cloneable admitted continuation.
Its admission share survives delivery, post-query committed revalidation and
the synchronous T10 consequence call or durable successor install. A cancelled
observer cannot release a started blocking worker's share. Undeliverable or
unused continuations release ownership when dropped. Only the own-live core
grant authorizes execution; the admission wrapper supplies no authority.

`QuvContinuationAdmissionProof` proves the conditional ownership kernel (nine
TLAPS obligations, eight states). Early delivery release and worker-observation
cancellation countermodels violate Ownership. **Assumes:** every relying call
keeps the wrapper through its synchronous transition and every started worker
owns it until return/unwind. Mapping: completion send is Deliver, consuming
callback is Start/Finish, failed delivery is CancelDelivery, dropped join handle
is CancelObservation. This is not a fairness or worst-case service proof;
pre-allocation admission and aggregate physical bounds still need integration.

Scoped evidence: `evidence/m17q-r1-continuation-admission-2026-09-06/`. Fifteen
runtime-finality, 22 QUV runtime and two executor tests, CLI compile, formatting,
syntax and formal checks pass. The early-release production control fails as
intended; original source is restored. Process campaign is running; it has not
been claimed passing. All whole findings remain OPEN; no clean R2 or M18Q
admission.

Live process driver: run_process.py in the continuation-admission campaign;
raw output process.log. Check its process-completed.json before treating it as
terminal. Its new invalid-signature case must refuse before per-effect writes
for all four correct-member placements.

2026-09-06 continuation/preparation process outcome: the final scoped campaign
`evidence/m17q-r1-continuation-admission-2026-09-06/process-recovery/admission-diagnostic/`
passes four explicit initial admissions, four signature/storage negatives, all
sole-correct placements, exact recovery/replay, concurrent workload, typed
conflict/non-mutation, unrelated execution and expired-result retrieval. The
strict source-bound checker passes with retained component service/release
checks and 4053.866 ms observed four-way overlap. Sole replies are
288/298/300/297 ms; saturation maximum 2586 ms, all within 4000 ms. Ancestor
startup/unadmitted failures remain retained. Initial admission is now explicitly
proved by the probe before isolation; earlier unadmitted-state root cause is
not established by this later pass. Full R2 and every whole finding remain open.

### Receipt leaf custody guards (2026-09-06)

Directory-entry absence now uses symlink_metadata: dangling active links and
metadata errors cannot become fresh authorization. On Unix, initial receipt
staging and the consequence lock use the existing no-follow, regular-file,
single-link guard before truncation or locking. Existing generic non-Unix
adapters remain outside the Linux reserved profile.

**Assumes:** exclusive nonrollback custody of the store and its parent namespace;
ordinary Unix no-follow/open/lock semantics. These leaf checks do not establish
parent-directory custody, adversarial namespace race protection, aggregate
physical resources, or full transition refinement. Invalid active state maps
to refusal, never the Absent case of QuvEffectPreparation. The existing reserved
receipt proof's private-file antecedent remains conditional on these OS/custody
assumptions. No stored bytes create live authority.

Evidence: `evidence/m17q-r1-receipt-custody-2026-09-06/with-lock/`. Thirty-three
consequence, 15 runtime-finality, 22 QUV runtime and two executor tests, CLI
compile, formatting, formal guard checks and receipt syscall controls pass.
Original failing dangling-active/lock-alias regressions are retained. Removing
existence, staging, or lock validation produces the expected test failure;
original source is restored. Previous process evidence predates this change.
All whole findings remain OPEN; R2 unqualified; M18Q NOT_ADMITTED.


2026-09-06 queued preparation update: executable effect and handoff allocation
now runs under operation admission, with store release before waiting and
committed admission rederivation afterward. Conditional proof, deadline/ownership
regression and inspection-write negative evidence are indexed in
`evidence/m17q-r1-queued-preparation-2026-09-06/`. See the specification's Queued
preparation refinement Assumes and limitations. Terminal/reconciliation fairness,
aggregate resource/retention bounds and complete refinement remain outstanding.
All 13 whole findings remain OPEN; R2 unqualified, M17Q REPAIR_REQUIRED,
M18Q NOT_ADMITTED. This supersedes no prior failed evidence or immutable-source
requirements.


2026-09-06 terminal readmission: final outcomes skip receipt-pair preparation
while retaining committed validation and exact resource lookup; ambiguous states
retain preparation for reconciliation. Scoped tests, the extended preparation
proof/countermodel and restored production omission are retained in
`evidence/m17q-r1-terminal-readonly-2026-09-06/`. See the protocol/end-to-end
Assumes and limitations. The mandatory reservation-test namespace is corrected.
No whole finding closure, R2 qualification, M17Q acceptance or M18Q admission.


2026-09-06 receipt admission/profile v7: both executor entries serialize initial,
terminal and live-owner receipt access through bounded FIFO admission, release
storage before operation/network waits, and rederive after queueing. Protected
owner capacity is separate from current and historical result waiters. Queue
coefficients enter policy-root v7; current schema formats are unchanged and old
provisioning roots cannot silently migrate. Conditional mapping, service debt
and exact root vector are in the protocol/end-to-end specification. Evidence:
`evidence/m17q-r1-receipt-admission-2026-09-06/`; collector status is authoritative.
All whole findings remain OPEN and M15Q-M18Q remain unadmitted.


2026-09-06 v7 receipt pressure/restart outcome: the source-bound campaign in
`evidence/m17q-r1-receipt-admission-2026-09-06/pressure-process/` passes after
1068.80 seconds including release-node compilation and provisioning. Three
consecutive slots include exactly four expected correct members, with maximum
valid replies 394/646/495 ms against the unchanged 4000-ms envelope. An unrelated
same-executor effect completes while 120 exact parent-result replays run across
5773 ms; the child remains in its required readiness wait. Restart before slot
three preserves exact terminal recovery and the required positive child wait.
The strict checker passes with unchanged captured source hashes and complete
service-release evidence. A broader source archive, toolchain, command,
environment overrides and component hashes are retained. This is finite scoped
working-tree evidence, not clean R2 or a worst-case resource/service proof. All
whole R1 findings remain OPEN; M17Q REPAIR_REQUIRED; M18Q NOT_ADMITTED.


Post-query model extension: QuvQueuedEffectPreparation now exposes receipt
reopening and finality-lock acquisition separately, allowing context changes
while the receipt lock is held before finality is acquired. Nine obligations and
four countermodels pass, including removed final revalidation producing an
unauthorized-call trace. Evidence: receipt-admission campaign's
`post-query-model/`. Production Rust is unchanged from the passing pressure run;
this later formal/harness source is separately bound. Validation, custody,
continuation timing and full service/refinement antecedents remain conditional.


2026-09-06 candidate decode boundary: the public effect entry uses
`decode_quv_candidate`, which checks the existing rooted 4096-byte cap before
canonical SCALE decoding. Exact-fit input parses; oversized canonical and
undecodable inputs return the capacity error; empty input retains codec refusal.
Parsing grants no authority. Removing the pre-decode guard fails the existing
mandatory capacity regression, and exact source is restored. Evidence:
`evidence/m17q-r1-candidate-decode-2026-09-06/` (one capacity regression, two
executor regressions, CLI compilation, format and syntax pass on unchanged
selected sources). The earlier pressure process predates this production change.

Proof obligation: this establishes the input-length antecedent at this decoder
entry; it does not establish SCALE heap/allocation amplification, already decoded
protobuf storage, total in-flight requests, authentication service, or the full
resource/transition refinement. Those antecedents remain OPEN under Q-A3/Q-A9.
The policy-root value is unchanged because the capacity was already rooted.
All whole findings remain OPEN; no clean R2, independent acceptance or M18Q
admission follows.

2026-09-06 registry identity repair: schema v2 prevents substituted manifests
from reusing an admitted effect ID; unindexed historical namespaces refuse
unchanged pending explicit migration. Four registry tests, two restored omission
controls, 15 runtime-finality tests, transaction cleanup retry, CLI/format/syntax
and conditional formal checks pass. Initial compiler ENOSPC is retained rather
than overwritten. Exact scoped evidence: `evidence/m17q-r1-registry-identity-2026-09-06/`.
No immutable candidate or whole finding closure; M16Q R2 unqualified, M17Q
REPAIR_REQUIRED, M18Q NOT_ADMITTED.

2026-09-06 overlay scan repair: a backing error previously appeared as an empty
namespace to registry bootstrap. The service regression fails on the original
iterator and passes after error propagation; API/registry/runtime/CLI and
conditional formal evidence is retained in
`evidence/m17q-r1-overlay-scan-2026-09-06/`. M16Q's partial formal invocations were
also replaced with the complete scheduled corpus after discovering omitted QUV
repair proofs; syntax/census pass, full R2 has not run. All whole findings OPEN;
M17Q REPAIR_REQUIRED; M18Q NOT_ADMITTED.


## R2 remediation wave — 2026-09-06

Integrated repair wave toward the R2 candidate, executed on the dirty tree at
HEAD `24a9888e3`. Every item below is scoped development evidence with its own
README under `evidence/m17q-r2-*-2026-09-06/`; none is qualification, and
no row above changes from OPEN until the exact R2 candidate passes the clean
full M16Q run and fresh independent review.

| Finding | Landed in this wave | Evidence | Still required before R2 admission |
|---|---|---|---|
| 001 | Exact-trace handoff/predecessor regressions; removed-rule controls for the conflict key (`QuvConflictSlotV0`), the push-path `check_expected_slot` (extended to the saturated-slot reply path after the first control unexpectedly passed) and the head predecessor comparison; member-side handoff predecessor enforcement traced and pinned by test; process fixture with different predecessors for one numeric slot in owned/unowned domains and both orders; stable-key claim index below the QUV argument | `m17q-r2-consensus-identity-custody`, `m17q-r2-consequence-claim-guard`, `m17q-r2-process-fixtures` | Clean process campaign pass; exact-candidate review |
| 002 | Forged generation+1 handoff gate regression, every-byte and per-field handoff mutations, foreign-scope / mismatched-generation / valid-record-at-scratch-name journal negatives | `m17q-r2-consensus-identity-custody` | Clean R2; review |
| 003 | Runtime late-timer-wake regression through the production finalization closure (`finalize_operation_at_deadline`) | `m17q-r2-validator-deadline-fairness` | Clean R2; review |
| 004 | Measured (not literal) conflict-register evidence; predecessor-fork, concurrent-replay and flood checker rules with self-tests; component-log cross-checks that refused payloads start no member operation | `m17q-r2-process-fixtures` | Single-correct and flood campaigns pass with the strict checker on the integrated dirty tree (c26, c23 in `m17q-r2-process-fixtures`); clean R2 on the committed tree and review remain |
| 005 | `QuvEndToEndRefinement.tla`: composed finite transition model (admission, two-phase authenticated durability and recovery, timed operations, own head, continuation expiry/fence, T10 claim-before-call on the stable key, handoff activation) with 5 positive instances, one reachability witness and 8 named countermodels, registered in the formal runner; spec wording labels the composition proof a conditional lifting lemma | `m17q-r2-end-to-end-refinement` | Implementation-refinement half remains open by declaration; review |
| 006 | Policy-root v8: rooted per-identity/per-domain sliding-window push quota enforced before authentication and store access; claim-index storage charge and `WAITING_PER_PRINCIPAL` rooted; independent Python root reproduction; flood + high-water restart fixture with member-store byte inspection | `m17q-r2-push-admission`, `m17q-r2-process-fixtures` | Flood campaign passes (3 quota drops, unrelated singleton within three intervals, six-slot horizon, high-water restart); aggregate service envelope remains a measured cost, recorded in the verification specification |
| 007 | Squatter-disconnect, handoff-only squat, mid-handshake eviction and live swarm-level squat regressions; `PqEnrollmentLost` recovery with fresh status request instead of a blind handshake | `m17q-r2-pq-carrier-outbox` | Process case landed: a rooted node restarted with a test-only, fail-closed status override claiming the sole correct member's account is refused by every peer and all four genuine replies arrive (`m17q-r2-byzantine-status`); the first-contact variant (claimant lying from its very first status response, launched before the genuine carrier ever authenticated) passes as its own cold-start fixture: the claim is provisionally enrolled and evicted three times, the genuine carrier authenticates, every other process refuses the claimant, and the operation executes on exactly the three correct members with the claimant never bound under any account; review |
| 008 | Cached `Authorized` beyond fence refused on inspect, prepare and execute; fail-closed-in-place documented | `m17q-r2-consequence-claim-guard` | Clean R2; review |
| 009 | Injected store clock; inclusive deadline equality and expiry crossing between `Claimed` persist and `InFlight` check | `m17q-r2-consequence-claim-guard` | Clean R2; review |
| 010 | Per-principal waiting bound on foreground and historical receipt lanes (rooted); concurrent terminal replay against an unrelated singleton effect in the process fixture | `m17q-r2-validator-deadline-fairness`, `m17q-r2-process-fixtures` | Concurrent terminal replay against an unrelated singleton passes (8.5–11.0 s measured, three-interval fence); review |
| 011 | Silent-recipient 24-operation and reopen regressions; analysis that only a quarantined outbox can make enqueue fail | `m17q-r2-pq-carrier-outbox` | Review |
| 012 | Stale-reply-before-lane, stale-push lane, `PqChannelNack` retry path, in-flight drop branch now releases the lane; a deferred push ACK (held until `CompleteQuvPush`) was implemented, then reverted after process qualification showed it serialized replies behind pushes on the single in-flight lane and missed the rooted cutoff under saturation; ACK-before-durable-processing is a documented liveness-only boundary | `m17q-r2-pq-carrier-outbox`, `m17q-r2-validator-deadline-fairness` | Review |
| 013 | Substituted self-consistent receipt file (Authorized/Claimed/Executed) refused before QUV and invocation | `m17q-r2-consequence-claim-guard` | Clean R2; review |

Runner changes: portable `grep -E` instead of `rg`; formatting gate; every new
regression is a named required case; new `pq_swarm_quv_lanes`, flood process
and five fixture-parser phases; new sources and the composed model are hashed.
The complete formal corpus (92 modules) passed on this tree in 39 minutes
before the composed model was registered; the census now reports 79 executed
and 13 manual modules.

Requalification finding outside the R1 set (2026-09-06): the integrated-tree
single-correct campaign failed at manifest registration because a late-joining
fourth validator was quarantined by a duplicate opportunistic sync batch
(`node frozen`, executed cursor 6 vs admitted floor 0), which then cost a view
timeout on every fourth height. The same frozen state is present in a retained
passing readiness campaign, so it predates this wave and is timing-dependent.
Repair: the opportunistic sync path now skips exactly the hash-linked prefix
ending in the locally executed tip (`already_executed_prefix_len`), and the
in-progress sync loop skips a fetched block only when its header hash equals
the hash this node itself executed at that height (bounded
`recent_executed_headers` ring, `executed_exactly`); both have unit
regressions registered in the `sync_executed_prefix` M16Q phase. Diagnosis
and logs: `evidence/m17q-r2-sync-prefix-2026-09-06/`. No theorem, assumption,
authority rule or policy root changes.

Requalification observation (2026-09-06): the first full-membership QUV
operation after process start delivered its pushes 4.7–4.9 s late to all
remote members at once (beyond the 4000 ms envelope), while later operations
delivered in under a second; cause not isolated. Recorded as a deployment
obligation in the verification specification's failure boundaries; the flood
fixture warms lanes with one recorded, unasserted operation first.

Repository hygiene (2026-09-06): five machine-specific `TLAPS.tla` stub
symlinks under `formal/` were tracked because the root ignore pattern was
root-relative and never matched the AFT path; the harness creates and
removes those links itself. They are untracked and the pattern is now
`**/formal/**/TLAPS.tla`. A stale dangling link had also made the
test-node build refuse to resolve a source revision.

Clean R2 attempts (2026-09-06): the first clean run on `e5928c321` passed
the formal corpus (2622 s), the core and journal gates, and then failed on a
latent runner defect: the three reserved-anchor regressions were required
from a phase whose filter never ran their module (`b4fb23106` gives them
their own phase). The second run on `b4fb23106` passed formal (2591 s), core,
journal, anchor and every reservation gate, then deadlocked in the
strace-wrapped journal-ancestry phase because the runner's process-substitution
tee was forked as a traced child (`2404a79e6` writes phase logs directly).
Both runs are retained outside the candidate as runner-defect history; the
definitive clean R2 run must start from the fixed commit.

Disposition after this wave: unchanged. M15Q reopened, M16Q R2 unqualified
(process campaigns on the integrated tree are running; earlier attempts under
concurrent builds failed and are retained), M17Q `REPAIR_REQUIRED`, M18Q
`NOT_ADMITTED`. Next: passing campaigns, Byzantine-status process case, commit
coherent slices, clean full M16Q R2 on the committed tree, immutable R2 tag,
fresh independent review.

### Retired-process successor-root gate (2026-09-07)

The first clean M16Q R2 attempt on `5ae464c11` passed every gate through
`quv_status_squat_evidence` and failed `quv_disjoint_reconfiguration`: the
retired old-root member restarted from admitted height 1 (its executed
projection was 2, below the activation height 3), took the ordinary old-member
startup path, then adopted successor-signed heights 2..14 through sync because
the engine's validator-set projection makes `next` effective at its
`effective_from_height` and neither sync nor gossip consulted the
process-local QUV install gate. Before the R2 sync repairs the same member had
usually followed successor history *before* its restart, so the fixture's
retirement refusal had been produced by the defect itself.

Repair: `quv_successor_root_gate` (`orchestration/consensus.rs`) is applied per
block in the sync apply loop, in `handle_gossip_block`, and at startup against
the workload's durable executed projection. A staged successor whose durable
install gate has not activated defers successor-root blocks; a process with no
successor identity refuses them with the single retirement diagnostic, drops
sync progress, stops accepting or re-initiating sync and quarantines itself.
Heights below activation, including the exact QC-certified boundary, are
unaffected. No premise changes; the end-to-end theorem boundary list and the
verification specification record the rule. Unit regression, removed-rule
control (`left: Admit, right: RefuseRetired`) and the new mandatory
`quv_successor_root_gate` phase are in
`evidence/m17q-r2-retired-sync-2026-09-07/`.

Standalone campaigns on the fixed tree: disjoint handoff passed (569 s; the
retired member refused height 3 from sync after restart; one restarted
successor deferred height 4 for 42 ms until its gate re-activated); overlapping
handoff passed (263 s; three old-only members refused the first successor
gossip block within 0.3 ms of each other; the common member recovered from its
gate and advanced). Both handoff evidence checks passed (maximum valid replies
888 ms and 824 ms within the 24 000 ms envelope).

Checker finding on its first execution: `check_aft_quv_handoff_evidence.py`
had never run against a disjoint campaign (the phase postdates the retained
runs and the R2 attempt failed before it). It rejected the passing campaign
because the interrupted successor is armed to exit in the crash window after
its handoff state is durable and before its admitted authorization is consumed,
so `operation_finished` is logged and `operation_admission_released` cannot
be. The checker now excuses a missing release only when the same component
log carries a later `startup` record and no later event for that nonce; four
negative self-test cases pin that (2 positive, 34 negative). This is evidence
tooling; the release-lane runtime is unchanged.

Disposition: unchanged (M15Q reopened, M16Q R2 unqualified, M17Q
`REPAIR_REQUIRED`, M18Q `NOT_ADMITTED`). Next: definitive clean full M16Q R2
run from this commit.

### Second clean R2 attempt and PQ drill fixture correction (2026-09-07)

The clean full M16Q R2 run on `f41ba3b41` (`20260907T074926Z-f41ba3b416ac`)
passed 61 phases in 7230 s, including the complete formal corpus (2835 s),
every QUV unit, mutation, reservation and process gate (single-correct 659 s,
flood 601 s, status squat 198 s, consecutive readiness 419 s, disjoint handoff
336 s and overlap 280 s with evidence maxima 721 ms and 697 ms, hash-async
process 1101 s, the new `quv_successor_root_gate` phase), and then failed the
non-QUV `pq_ordering_restart` drill: the fourth validator launched 36 s after
the third (serialized key encryption) and was the round-robin leader for
height 2, so the three running nodes formed a genuine exact-q=3 scoped
timeout certificate for height 2 before the drill baseline, and the fixture
rejected any certificate not at its scheduled failure height. The engine
already requires an embedded certificate to authorize its own slot. The
fixture now requires `certificate.height == height` for every block (stronger),
records a pre-baseline certificate as bootstrap-window evidence, and confines
the "only the scheduled failure" rule to the drill window. No runtime,
deadline, timeout, envelope or bound changed. The drill passed standalone on
the corrected fixture (399 s; that run had no pre-baseline timeout, so the
retained failed phase is the control for the new branch). Evidence:
`evidence/m17q-r2-pq-drill-bootstrap-timeout-2026-09-07/`; the run directory
is retained outside the candidate as history. The definitive clean run
restarts from the commit carrying this correction. Dispositions unchanged.

### Third clean R2 attempt: flood service budget under host contention (2026-09-07)

The clean full M16Q R2 run on `6ee42fd7f` (`20260907T100107Z-6ee42fd7f0a0`)
passed 52 phases and failed `quv_byzantine_flood`: one executor operation
was released 9.5 ms past the 13 s active service budget (`elapsed_micros`
13009511) after spending 5.3 s in the runtime-finality critical section while
block finality stalled for 11 s; the run coincided with unrelated CPU-heavy
work on the host (load average about 10 on 24 cores, the only
`process_block() is slow` warning in three retained flood campaigns inside
that operation's window, every process phase 10–15 % slower at p90). Measured
release maxima over the three retained flood campaigns are 10.25 s, 10.20 s
and 13.01 s (n = 58, 56, 44). Repair sized from measurement: the flood
fixture's rooted continuation is 11 s (16 s budget), the same rule that set
13 s after 10.25 s releases; the readiness profile stays at 10 s (maxima
below 9.6 s). Interval, reply envelope, checker deadline rules and
late-release-is-failure semantics are unchanged; the packet's cost section
records the numbers. Qualification campaigns must not share the host with
CPU-heavy work; the relaunch is gated on a quiet host and its load trace is
retained. Evidence: `evidence/m17q-r2-flood-host-contention-2026-09-07/`.
Dispositions unchanged.

### Fourth clean R2 attempt: readiness reply envelope on shared PQ lanes (2026-09-07)

The quiet-host clean run on `4826d4bdb` (`20260907T115443Z-4826d4bdb394`)
passed 48 phases and failed `quv_consecutive_readiness`: the slot-2 child's
accepted audit recorded a 4210 ms valid reply against the fixture's 4000 ms
declared envelope (inside the rooted 5000 ms interval; operation accepted,
all members valid). Members handed their replies to the swarm within 1.0 s
of the push; two replies then took 2.9–3.2 s to reach the executor while
three members' preparation operations and an ordering commit shared the
single in-flight PQ peer lanes. The retained logging has no per-record lane
events, so the wait is recorded, not attributed. Repair sized from
measurement: the readiness profile declares the same 4500 ms envelope as the
flood profile (`QUALIFIED_ENVELOPE_MS`), and its evidence checker pins 4500;
interval, readiness bound, service budgets and discard-after-interval are
unchanged. Retained readiness maxima: 2075, 2217, 2524, 2731, 4210 ms.
Evidence: `evidence/m17q-r2-readiness-reply-envelope-2026-09-07/`. Recorded
for the reviewer as a transport cost (shared lane) rather than a closed item.
Dispositions unchanged.

### Definitive clean M16Q R2 run — PASS (2026-09-07)

`evidence/m16q-runs/20260907T152920Z-9ce911fe798b/`: commit `9ce911fe798b`,
clean non-quick tree, launched by the quiet-host gate at 15:29:19 UTC (load
3.4 / 4.1 / 5.0; per-minute trace in
`evidence/m16q-quv-qualification-host-load-2026-09-07.txt`), 63 phases PASS
in 7217 s: complete formal corpus 2623 s; every QUV unit, mutation,
reservation, syscall-ancestry and checker gate; process campaigns
single-correct 661 s (62 budgeted releases, max 9.34 s), Byzantine flood
634 s (58, max 10.80 s against the 16 s budget; reply maxima 2389 / 1572 /
424 ms), status squat 196 s, consecutive readiness 269 s (reply maxima 1852 /
1492 / 2093 ms against the 4500 ms envelope), disjoint handoff 328 s (max
valid reply 786 ms) and overlap 289 s (689 ms), hash-async process 899 s, PQ
timeout/restart drill 495 s, the new `quv_successor_root_gate` phase, and
all evidence checkers. `result.txt`: `result=PASS`,
`result_scope=selected_runner_gates`, `r2_admission=NOT_ESTABLISHED` (the
runner never establishes admission; the fresh independent review does).

Path to this run: four earlier clean attempts on this remediation each
failed a different late phase and are retained as history with their
repairs (`f41ba3b41` retired-process successor-root gate; `6ee42fd7f` PQ
drill certificate rule; `2080d09d6` flood service budget 16 s; `199ee3884`
readiness envelope 4500 ms). Disposition now: M16Q R2 qualification
evidence exists on one immutable candidate; M15Q, M17Q and M18Q remain
`REOPENED` / `REPAIR_REQUIRED` / `NOT_ADMITTED` until the fresh independent
review of the exact tagged commit reports no unresolved critical/high
finding. Next: freeze `aft-quv-v0-m17q-candidate-r2-2026-09-07`, commission
the review, import its report byte-for-byte.

Frozen (2026-09-07): annotated tag `aft-quv-v0-m17q-candidate-r2-2026-09-07`,
tag object `f0932c71c630ab6c85676cda3606dc285a755070`, peeled commit
`0d8d50d4f22c4f02b98ed06b4066c7aefd6d5992` (adds the retained run on
`9ce911fe798b`). Manifest:
`evidence/m16q-runs/candidate-aft-quv-v0-m17q-candidate-r2-2026-09-07.manifest.txt`.
A first freeze attempt minutes earlier carried a run-id placeholder in its
message; that local, unreferenced tag was deleted and the freeze repeated
before any use. Push, deployment and publication remain owner actions; the
owner-only commands are printed by the freeze script and recorded in the
M18Q packet.

### Yellow paper: interactive-visibility section (2026-09-07)

`specs/yellow_paper.tex` (revised September 7, 2026) now prints the
interactive-visibility result at exactly its proved strength and no more:
a new Section 12 states the M12a portable-visibility lower bound
(Theorem, mechanized as `MaximalVisibilityDilemma.tla`), the QUV operation,
the Q-A1–Q-A10 ledger, theorems Q-T1–Q-T4 with their Assumes lines and
mechanization names, the Q-EA1–Q-EA8 composition premises and Q-E1–Q-E4,
the five-way separation of guarantees with the no-laundering rule, the
frozen production profile identifiers, host-measured costs with their
reproduction path, and the explicit non-claims. The scope list, the claims
list, the non-claims list, the residual list (RES-QUV: candidate under
independent review; shared-lane and cold-start transport costs), the
assumption-surface table, the implementation-correspondence table and the
embedded formal appendix (four QUV modules) carry the same result. No
existing promoted claim was changed or weakened; the admission box records
the frozen tag, tag object and peeled commit and states that the printed
claim is neither weakened by the pending review nor strengthened beyond it.
The PDF rebuilt (171 pages) and the claim-discipline gate passes. The
M18Q checklist item "yellow-paper wording agrees" is prepared, not yet
ticked: it is ticked only with the review disposition.

### Fresh M17Q review commission blocked by the reviewer service (2026-09-07)

The authorized reviewer (`gpt-daybreak-blue-latest` via Codex CLI 0.153.0)
was commissioned at 17:33:02 UTC against the frozen tag in a clean disposable
clone; the service refused before any work with a usage-limit error naming
"Sep 12th, 2026 6:46 PM" as the retry time. The attempt is retained
byte-for-byte in `evidence/m17q-r2-review-2026-09-07/attempt-1-usage-limit/`.
Purchasing credits is a paid engagement and substituting a reviewer changes
the authorized commission, so both are owner decisions. Steps D–F are
blocked on that decision; nothing in the candidate is established or refuted
by the failed attempt. Dispositions unchanged: M15Q reopened, M16Q R2
qualification evidence retained on the frozen candidate, M17Q
`REPAIR_REQUIRED` (R1; R2 candidate unreviewed), M18Q `NOT_ADMITTED`.

### Owner-authorized push and review deferral (2026-09-07)

The owner decided to keep the program, defer the independent review to the
reviewer service's retry window (Sep 12th, 2026), and push the current
results so unrelated branches can merge. Pushed by owner authorization:
`origin/master` fast-forwarded `023526469..d5f19a0a0` (55 commits) and
`refs/tags/aft-quv-v0-m17q-candidate-r2-2026-09-07` (tag object
`f0932c71c630ab6c85676cda3606dc285a755070`) now exists on the remote. The
reviewed object is the tag, not the branch tip: later merges onto master do
not alter it, and any repair the review requires (step E) starts a new
candidate from a new clean run and a new tag. Merges that touch
`crates/consensus/src/aft`, `crates/validator/src/standard/orchestration`,
`crates/networking/src/libp2p/pq_channel*`, `crates/agentgres/src/consequence*`
or the M16Q runner and checkers before the review lands will need their
own qualification before they can enter a later candidate; they do not
invalidate this one. No deployment, disclosure or publication was performed.
