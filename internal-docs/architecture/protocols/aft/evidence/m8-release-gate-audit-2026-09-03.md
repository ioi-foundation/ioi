# M8 integrated release-gate audit — 2026-09-03

Status: **ALL LOCAL GATES PASS — release blocked on independent review**.

## Integrated harness

`scripts/run_aft_m8_release_demo.sh` composes the real four-validator adverse
fallback/restart/re-entry drill, PQ checkpoint issuer, complete portable
receipt and laundering negatives, crash/reconciliation executor, clean-room
and independent PQ implementation checks, and the complete formal harness.

The cross-domain model separately holds one unanimous ring permanently stalled
while another domain enters fallback and externalizes three effects. Result:
41 generated / 10 distinct states, depth 6, no violation.

## Release gates

| # | Gate | Status / evidence |
|---:|---|---|
| 1 | Every load-bearing primitive/channel in demonstrated path PQ | PASS (local evidence) — PQ-issued hash-async finality, complete rooted ML-KEM/ML-DSA channel graph, unanimous SLH-DSA seal, rooted ML-DSA endpoint and receipt envelope derive `end_to_end_pq=true`; independent review remains gate 15 |
| 2 | Hash-only ACS default fallback | PASS — D2 trigger, production drill and R10 evidence |
| 3 | Seal keys identity/config/domain/state bound | implementation/fuzz PASS; independent custody review OPEN |
| 4 | Production authorization uses `GuaranteeVectorV1` | PASS — estate-wide AFT external-mutation census finds one production owner; it requires opaque `VerifiedGuaranteeV1`, committed runtime-v3 re-verification, exact policy/profile binding and the atomic-resource fence |
| 5 | No timeout/wrapper downgrade or amplification | PASS — T6/L-M, formal model and mutation corpora |
| 6 | External at-most-once requires modeled contract | PASS — T10/L-X and M5 crash corpus |
| 7 | Economic receipts prove only non-double-counted slashable collateral | PASS — T11/L-C and M6 corpus |
| 8 | Independent offline verifier reproduces decisions | PASS — no-IOI-import clean room requires external network/configuration/key/signer/anchor/policy roots, accepts the 1.08 MB complete path, and rejects seven validly re-enveloped inner forgeries (including withheld unanimity) using independent ML-DSA/SLH-DSA implementations |
| 9 | Tests/sims/formal/benchmarks/negative corpora reproducible | PASS — `scripts/run_aft_m8_release_demo.sh` completed the process drill, receipt/corpus, clean-room/oracles, TLAPS, every TLC model and trace replay in one uninterrupted exit-0 run |
| 10 | Specs/code/theorems/claim matrix agree | PASS — T12/L-PQCH, theorem/claim/census gates and 147-page yellow-paper build pass |
| 11 | Static adversary stated; no adaptive implication | PASS in R10, theorem surface and claim gates |
| 12 | “No setup” scoped to no private threshold setup/DKG | PASS in types, receipts and claim text |
| 13 | Superlatives backed by dated systematic comparison | N/A — release makes no “first/unique/no competitor” claim |
| 14 | Full affected-workspace CI | PASS — types 459/459, crypto 63/63, networking 13/13, consensus 229/229, finality 57/57, Agentgres 99/99 and validator 260/260; Hypervisor, validator distribution and portable verifier compile checks pass |
| 15 | No unresolved high-severity security finding | OPEN — required independent cryptographic/custody/channel review has not occurred |

## Clean-break and Hypervisor boundary

ADR 0048 makes AFT PQ v1 a genesis/new-network cutover. The production CLI no
longer dispatches legacy v2/runtime-v3 receipt bundles, the scalar assurance
migration and unused BLS aggregation placeholder are removed, and non-classic
guardian modes remain rejected by production profile admission. The hash-only
path remains mandatory because it is the randomized asynchronous liveness
construction, not a compatibility fallback.

The default Hypervisor daemon build now excludes `ioi-consensus`,
`ioi-validator`, and SLH-DSA from its Cargo graph. Consensus/validator and
terminal-seal/portable-receipt dependencies are activated only by explicit
kernel/AFT features. The remaining `ioi-client` and `ioi-state` edges are
owned by wallet/runtime services Hypervisor calls. A locked default
`hypervisor-daemon` check passes; the existing warning census is unchanged and
is not represented as new AFT debt.

## Honest blocker boundary

Interop, ACVP vectors, fuzzing, formal verification, clean-room reproduction
and internal adversarial review are evidence, but are not an independent
cryptographic audit. The portable channel-evidence gap is closed locally, and
the exact complete receipt may derive `channel_pq=true`; the release still must
not declare M1/M8 complete or print the intended headline until an independent
reviewer signs off the providers, key custody, channel construction and
implementation.

## Latest reproducible results

- `cargo test --locked -p ioi-types --lib` — PASS, 459 / 459 in 491.19 seconds.
- `cargo test --locked -p ioi-crypto --features aft-terminal-seals --lib` —
  PASS, 63 / 63 in 11.51 seconds after compilation.
- `cargo test --locked -p ioi-networking --lib` — PASS, 13 / 13 in 23.65
  seconds after compilation.
- `cargo test --locked -p ioi-consensus --features aft --lib` — PASS, 229 /
  229 in 138.09 seconds.
- `cargo test --locked -p ioi-finality --features portable-assurance --lib` —
  PASS, 57 / 57 in 221.33 seconds.
- `cargo test --locked -p agentgres --lib` — PASS, 99 / 99 in 63.83 seconds.
- `cargo test --locked -p ioi-validator --features
  consensus-aft,vm-wasm,state-iavl --lib` — PASS, 260 / 260 in 39.41 seconds
  after compilation.
- `cargo check --locked -p ioi-node --bin hypervisor-daemon` — PASS in 1m30s;
  dependency census contains no `ioi-consensus`, `ioi-validator`, or SLH-DSA.
- `cargo check --locked -p ioi-node --features validator-mode --bin
  ioi-validator` — PASS after all full-node distributions were made to inherit
  the explicit `kernel-node` dependency bundle.
- `cargo check --locked -p ioi-finality --features portable-assurance --bin
  ioi-receipt-proof-verify` — PASS.
- `cargo check --locked -p ioi-finality --no-default-features` — PASS.
- complete receipt production corpus — PASS, 5 / 5 including external trust
  and relying-party-policy substitution; external
  clean room accepted the positive receipt and rejected seven validly
  re-enveloped inner forgeries.
- `cargo fmt --all -- --check` — PASS.
- `git diff --check` — PASS.
- theorem-assumption and claim-discipline gates — PASS.
- formal census — PASS, 40 = 27 executed + 13 explicitly manual modules.
- TLAPS — PASS, 1,015 obligations across all nine registered proof modules.
- TLC prefix through both boundary-liveness configurations — PASS, including
  CanonicalOrderingRetrievability at 632,887,809 generated / 66,846,976
  distinct states, depth 39.
- TLC tail plus trace replay — PASS with observed exit 0; MembershipTransition
  was the largest tail model at 21,764,161 generated / 1,254,528 distinct
  states, depth 22.
- `bash scripts/run_aft_m8_release_demo.sh` — PASS with one uninterrupted exit
  0 on the final integrated tree. The real four-validator fallback/restart
  drill passed in 636.80 seconds; the PQ issuer in 61.94 seconds; portable
  receipts 5 / 5 in 196.03 seconds; consequences 12 / 12; both independent PQ
  interop pairs, all 1,015 TLAPS obligations, every TLC model and the generated
  trace replay passed. `CanonicalOrderingRetrievability` again exhausted
  632,887,809 generated / 66,846,976 distinct states to depth 39.

The M9 post-reconciliation reproduction also completed with one uninterrupted
exit 0 after hardening restart-readiness sampling: the process drill passed in
585.42 seconds, the PQ issuer in 86.25 seconds, portable receipts 5 / 5 in
283.71 seconds, consequences 12 / 12, both interop pairs, all 1,015 TLAPS
obligations, every TLC model, and trace replay passed. The largest TLC model
again reached 632,887,809 generated / 66,846,976 distinct states, depth 39, in
28 minutes 17 seconds.

An earlier attempt failed before test execution when the linker received
`SIGBUS` with only 480 MiB free on the filesystem. `cargo clean -p ioi-cli`
removed 15.5 GiB of rebuildable package artifacts; the unchanged runner then
completed as the exit-0 run recorded above. The infrastructure failure is not
represented as protocol evidence.
