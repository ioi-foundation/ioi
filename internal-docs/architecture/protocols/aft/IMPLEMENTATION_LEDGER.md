# AFT Post-Quantum Assurance Implementation Ledger

Status: active implementation ledger; supporting protocol context, non-canonical.
Authority: code, accepted ADRs, `docs/architecture/`, and reproducible evidence cited here.
Baseline: `master` / `origin/master` at `ef20d4ff5` when this program began on 2026-09-01.

This ledger tracks the completed/in-review M0–M8 implementation program and
the gated M9–M18 maximal-consensus program. A checked item is not a
claim of completion unless its evidence column names an authoritative artifact
or reproducible command. Only one milestone may be marked **CRITICAL PATH**.

## Milestone status

| Milestone | State | Evidence / next required proof |
|---|---|---|
| M0 claim and schema freeze | **COMPLETE** | Canonical `GuaranteeVectorV1`, conservative legacy/profile census, accepted claim ADR, assumption census, and fail-closed transform boundary; current 459-test authoritative types-library run passes |
| M1 PQ cryptographic substrate | **IN PROGRESS** | SLH-DSA seal custody, ML-DSA live/header signatures, strict rotating PQ swarm records, durable ACK outbox, independent-implementation interop, stateful-seal fuzzing, and the strict four-validator timeout/restart drill pass; independent cryptographic review remains release-blocking |
| M2 PQ optimistic live core | **COMPLETE** | Exact unit-weight 3f+1 / 2f+1 PQ geometry, guardian-independent authority, versioned scoped timeout votes/certificates, strict-PQ relay, canonical D2 trigger, and crash-safe restart are implemented; full optimistic/fallback composition belongs to M3 |
| M3 hash-only asynchronous fallback | **COMPLETE** | R10 D1–D4, hash-only RBC/RA/ASKS/gather/VABA/ACS, durable PQ transport/storage, exact-q certificates, canonical execution/admission, cross-path fencing, bounded formal composition, adversarial/mutation/crash/race campaigns, n=130 benchmark evidence, and the strengthened four-validator cold-restart drill pass under the declared static-adversary model |
| M4 no-laundering theorem/runtime | **COMPLETE** | Exact certificate-derived meet, opaque policy input, exhaustive default-deny transform registry, T6/L-M paper/formal proof, runtime-v3 recomputation, and laundering mutation corpus |
| M5 consequence externalization | **COMPLETE** | Agentgres-bound EffectManifestV1, exact atomic-resource profile, durable claim-before-call executor, lookup-only reconciliation, T10/L-X, formal/crash/mutation evidence |
| M6 economic assurance | **COMPLETE** | Exact native-asset floor from objective evidence and distinct bond snapshots; T8 stays open |
| M7 portable receipts | **COMPLETE** | Canonical ML-DSA envelope, payload-scoped PQ channel/seal/endpoint proofs, offline library/CLI, full constituent/transform report, golden vectors, validly re-enveloped negative corpus and independent RustCrypto/fips205/Python reproduction |
| M8 integrated release | **IN PROGRESS** | All local implementation, mixed-domain demonstration, proof, receipt, clean-room, authorization-census and affected-workspace gates pass in one retained integrated process; M9 freezes the review candidate and M10 owns independent review/release admission |
| M9 immutable PQ v1 candidate | **COMPLETE** | T5d/T8 reconciled; all local M8/static/formal/affected-workspace gates reproduced; exact contents bound by annotated tag `aft-pq-v1-review-candidate-2026-09-03`; see `evidence/m9-pq-v1-candidate-freeze-2026-09-03.md` |
| M10 independent PQ v1 review and release | **WAITING OWNER COMMISSIONING — CRITICAL PATH** | Owner must name and engage an independent reviewer against the full commit resolved by the M9 tag; require complete findings, remediation/retest, final attributable report, and no unresolved high/critical finding |
| M11 exact maximal task/model | **COMPLETE (LOCAL SPEC)** | `specs/maximal_consensus_task.md` fixes non-vacuous internal/external agreement, validity, decision versus effect liveness, durability, setup, verifier semantics, all communication profiles, role switching, and exact `f=n-1` cases |
| M12 non-circular visibility viability | **IN PROGRESS — INDEPENDENT THEOREM REVIEW REQUIRED** | `specs/maximal_visibility_viability.md` gives L-MAX, a generalized role-switching impossibility candidate; the dated primary-source comparison attacks Dolev–Strong, FLP/DLS, RBC/ACS/DAG/DA, shared-object, Geeq, and consequence-register escapes. Transferable non-conflict plus silent-`n-1` non-Abort/effect liveness still requires unanimity support or a new external authority; M13-M18 remain locked unless a concrete construction defeats it |
| M13 maximal consensus theorem | **LOCKED BY M12** | Agreement, validity, `f=n-1` termination, lower-bound pairings, costs, and mechanization over the constructed primitive |
| M14 end-to-end theorem lift | **LOCKED BY M12** | Carry the result through ordering, durable state, effect authorization, consequence externalization, and portable assurance |
| M15 production implementation | **LOCKED BY M12** | One explicitly named theorem-bearing profile; no relabeling of Classic BFT, hash-async, or research code |
| M16 adversarial/performance qualification | **LOCKED BY M12** | Real-process permanent-silence/equivocation, restart/fork/rotation, receipt/consequence, conformance, and profile-specific cost campaigns |
| M17 independent maximal review | **LOCKED BY M12** | Fresh security/theorem review, spec-only twin, full finding remediation, and immutable-candidate sign-off |
| M18 public admission and release | **LOCKED BY M12** | Public adversarial evidence, peer-review disposition, zero relevant `L-OPEN`, claim admission, and immutable release |

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

## In-progress slice: M1 PQ cryptographic substrate

Implemented, but not yet milestone-complete:

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

Open M1 gates:

- Obtain the required independent cryptographic review of the selected
  providers, custody discipline, authenticated-channel construction and
  implementation. The independent implementations used as interoperability
  oracles are explicitly not substitutes for this release-blocking review.

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

## In-progress slice: M8 integrated demonstration and release

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
  and the generated Rust trace replay matched. Release authorization remains
  blocked only on the independent review listed below and in the M8 gate audit.
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

M8 remains release-blocked. The portable complete-path PQ evidence, independent
offline decision reproduction, estate-wide AFT externalization-authorization
census, affected-workspace CI and retained integrated mixed-workload process
exit are locally closed. The required independent cryptographic/provider/
custody/channel review has not occurred. Local tests,
interop, fuzzing, duplicate implementations and formal work do not substitute
for that review.

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
- Current v2 seal shares are production-authorized or independently reviewed.
- The PQ channel implementation or startup slice is independently reviewed or
  sufficient by itself to set `channel_pq=true`; only the complete
  payload-scoped ADR 0047 evidence verifier may derive that coordinate locally.
- ML-DSA vote support alone makes the live or header path end-to-end PQ.
- Arbitrary HTTP or physical effects are at-most-once.
- Slashable collateral is a general cost-to-violate or closes T8.
- M1, M8, or the final release is complete.

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
