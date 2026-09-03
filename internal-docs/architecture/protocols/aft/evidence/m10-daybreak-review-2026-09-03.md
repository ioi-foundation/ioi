# M10 owner-commissioned automated independent review

- Date: 2026-09-03
- Reviewer: OpenAI Codex using `gpt-daybreak-blue-latest`
- Kind: owner-authorized automated independent review under ADR 0049
- Human peer review: no
Professional assurance: no

## Immutable target

- tag: `aft-pq-v1-review-candidate-2026-09-03`
- annotated-tag object: `3db5f4d08fb5819ab586982f0be60be626ed527b`
- commit: `09aaf34b63c8fa8520c4de014a6d72f6360f7e16`
- signature: none
- checkout: detached clean disposable clone
  `/tmp/ioi-m10-audit.3hX9sU/audit`
- shared checkout and external state: not modified by the reviewer

Pinned providers observed in `Cargo.lock` included `dcrypt 4.0.1`,
`slh-dsa 0.2.0-rc.5`, `ml-dsa 0.1.1`, and
`chacha20poly1305 0.10.1`.

## Disposition

`FAIL / REPAIR_REQUIRED`

Gate 15 could not pass for this candidate: two high and four medium findings
were open, the mandatory verifier was absent from the immutable tree, and the
integrated release demonstration was not reproducible.

## Findings

### AFT-M10-001 — clean-room verifier absent

- Severity: high
- State at review: open

The tag did not contain `tools/aft-assurance-cleanroom/verify.py` or its
corpus because `.gitignore` ignored `/tools/*` except the interoperability
tool. The exact verifier invocation exited 2, and the release demonstration's
verifier step was therefore impossible.

Required remediation: commit and narrowly unignore the verifier and corpus,
run them from a clean clone in CI, cut a new immutable candidate, and retest.

### AFT-M10-002 — portable assurance was represented as load-bearing

- Severity: high
- State at review: open

`verify_portable_assurance_bytes` returns an offline portable verification
report and optional guarantee vector. It does not produce the opaque
authorization consumed by `ConsequenceStore::authorize`. The production
mutation path instead verifies the pre-consequence committed runtime-v3
bundle. No production call path connects the post-consequence portable
receipt verifier to the sole mutation owner.

This did not demonstrate arbitrary mutation: runtime evidence, the manifest,
opaque verified guarantees, fences, and the modeled resource contract remain
enforced. It did invalidate packet wording that required a canonical portable
receipt-to-mutation trace. Remediation must either implement that claimed
trace or correct the claim and explicitly preserve the non-circular causal
boundary between pre-consequence authorization and post-consequence receipt.

### AFT-M10-003 — integrated demo was not self-contained

- Severity: medium
- State at review: open

`scripts/run_aft_m8_release_demo.sh` invoked the AFT E2E test before building
its documented `ioi-signer` prerequisite. It failed with exit 101. The runner
must build or explicitly verify the pinned signer and then run from a fresh
clone/empty target.

### AFT-M10-004 — key-store header algorithm confusion

- Severity: medium
- State at review: open

The V1 decryptor parsed but ignored the KDF identifier, memory, iterations,
lanes, and AEAD identifier, and the header was not associated data. A mutated
header could continue to decrypt while declaring unsupported or false
parameters. The format must strictly validate or implement every declared
field, authenticate the complete header, and test every mutation.

### AFT-M10-005 — PQ secrets lacked zeroization

- Severity: medium
- State at review: open

ML-DSA and hybrid-KEM private/shared-secret bytes were held in clonable
ordinary vectors and dropped without wiping. Exploitation requires local
memory disclosure, allocator-reuse inspection, a crash dump, or equivalent
access. Secret storage and intermediates must be zeroizing, unnecessary
cloning removed, and lifecycle behavior tested.

### AFT-M10-006 — failed PQ rotation retained stale state

- Severity: medium
- State at review: open

Networking replaced its PQ manager only after successful construction; a
failure retained the old manager and sessions. Orchestration sent
configuration and enrollment messages and advanced its desired configuration
hash without an installation acknowledgement. This permitted split
configuration and stale-session retention, although no independent consensus
safety failure was established. Rotation must be acknowledged and atomic,
and orchestration must advance only after successful installation.

## Positive attack results

The reviewer found no successful identity substitution, role reflection,
unknown-key-share, cross-scope replay, terminal-share rebinding, rooted-key
bypass, fallback classical-signature downgrade, or duplicate modeled effect
invocation. The reviewed bindings covered complete seal authority scope,
member/key/slot/root/successor identity, channel roles and identities,
carrier/enrollment/KEM material, record sequence/type/length, and durable
outbox scope/endpoints/payload.

The consequence state machine persisted `InFlight` before the sole
`invoke_atomic` call and used lookup-only reconciliation. Its at-most-once
claim remains bounded to resources supplying the modeled atomic idempotency
register. Filesystem anchors continue to depend on documented external
anti-rollback and snapshot assumptions. Endpoint completion attestations are
payload-scoped evidence, not proof of all historical delivery or adaptive
security.

## Commands and results

| Command | Result |
|---|---|
| `cargo fmt --all -- --check` | pass |
| `git diff --check` | pass |
| `check_aft_theorem_assumes.sh` | pass; 28 theorem blocks |
| `check_aft_claim_discipline.sh` | pass |
| `check_aft_production_authorization.sh` | pass; one mutation owner |
| `run_aft_m8_release_demo.sh` | fail 101; missing signer |
| `cargo test --locked -p ioi-crypto --lib` | pass; 63/63 |
| `cargo test --locked -p ioi-networking --lib` | pass; 13/13 after disposable ENOSPC cleanup |
| `cargo test --locked -p ioi-consensus --features aft --lib` | pass; 229/229 |
| `cargo test --locked -p ioi-finality --features portable-assurance --lib` | pass; 57/57 |
| `cargo test --locked -p agentgres --lib` | pass; 99/99 |
| exact validator feature suite | incomplete |
| standalone PQ interoperability oracle | incomplete |
| clean-room verifier | fail 2; absent |

The `ioi-types` run showed 459 tests before capture ended without a retained
exit status. The review did not establish provider correctness, side-channel
certification, adaptive-corruption security, snapshot-safe custody, or
arbitrary-resource at-most-once execution.

This report records an automated AI review. It must not be represented as a
human, signed, institutional, or authenticity-verifiable peer review.
