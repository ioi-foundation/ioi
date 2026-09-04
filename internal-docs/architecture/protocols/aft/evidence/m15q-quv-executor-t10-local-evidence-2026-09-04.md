# M15Q QUV executor-to-T10 path — local evidence

Date: 2026-09-04

Status: **PASS for the real-process executor-to-members-to-T10 slice at code
commit `bd1e91a6d`; the remaining handoff restart matrix passed at `ce34c31a9`,
so M15Q is COMPLETE LOCALLY and awaits M17Q review.**
This is local implementation evidence, not M16Q qualification, independent
review, or a public production claim.

## Implemented path

The production workload now registers one canonical `EffectManifestV1` per
finalized block through `aft_effect_registry/register_manifest_v1`. The
runtime-finality coordinator extracts those exact transaction bytes, validates
their canonical JCS form, binds the manifest commitment into the block's
Agentgres recognized-effect record, and resolves the committed manifest by its
effect identity.

`ExecuteAftQuvEffect` accepts only an effect identity and an ordinary signed QUV
candidate. It does not accept a QUV transcript, certificate, cached verdict, or
caller assertion. The receiving executor:

1. resolves the exact committed Agentgres record and manifest;
2. re-verifies the modeled atomic-resource contract and the achieved assurance
   vector;
3. loads the durable effect authorization and exact QUV binding;
4. samples a fresh nonce and starts its own `PUSHQUERY` operation against the
   active configuration;
5. directly consumes the returned process-local, non-serializable continuation
   in `execute_with_online_authorization`; and
6. persists `Claimed` before invoking a file-backed atomic put-if-absent
   resource that returns ML-DSA-authenticated endpoint evidence.

The RPC response is canonical consequence state and audit evidence only. It is
always labeled `portable_final_receipt=false` and cannot be presented to a
second executor as authorization.

The implementation keeps two roots distinct. The `EffectFenceV1`
configuration root selects the active canonical QUV member set and is checked
by the live operation. The ordering-assurance configuration hash, when a policy
requires it, commits the runtime membership-evidence object. Treating these
different objects as one root caused a fail-closed `FenceExpired` result during
the first process run; the repair verifies each root at its own theorem
boundary and does not remove either check.

## Process evidence

The existing eight-process disjoint-root fixture now additionally:

- submits a canonical online-QUV effect manifest through the real workload;
- waits for native finality and Agentgres admission;
- constructs a candidate bound to the manifest commitment, conflict domain,
  slot, policy root, and active successor configuration root;
- invokes the public executor endpoint after successor restart;
- observes an `Executed` consequence containing a nonportable live-QUV audit;
- opens the resource state independently of the RPC response;
- observes the exact durable record; and
- verifies its rooted ML-DSA endpoint evidence.

The test still exercises disjoint old and successor roots, four independent
successor live handoffs, strict-PQ activation, exact-gate restart recovery,
post-recovery ordering progress, source-signature substitution refusal, missing
gate refusal after expiry, and retired-old-key refusal.

## Reproduction and observed results

```text
cargo test -p agentgres consequence:: --lib

cargo test -p ioi-services aft_effect_registry::tests --lib

cargo test -p ioi-validator \
  --features consensus-aft,vm-wasm,state-iavl \
  runtime_finality::tests --lib

cargo check -p ioi-cli --test aft_e2e \
  --features consensus-aft,vm-wasm,state-iavl

RUST_TEST_THREADS=1 cargo test -p ioi-cli --test aft_e2e \
  --features consensus-aft,vm-wasm,state-iavl \
  test_aft_quv_disjoint_successors_install_live_handoff_before_activation \
  -- --nocapture

git diff --check
```

Observed at `bd1e91a6d` or its immediately preceding clean worktree:

- Agentgres consequence suite: 14 passed, 0 failed;
- workload manifest registry: 2 passed, 0 failed;
- runtime-finality suite: 14 passed, 0 failed;
- full CLI harness compile: pass;
- eight-process handoff/restart/executor/T10 test: 1 passed, 0 failed in
  624.94 seconds; and
- formatting/diff check: pass.

The consequence suite covers direct-without-QUV refusal, exact binding,
single-use continuation consumption, claim-before-call, duplicate delivery,
ambiguous invocation, lookup-only reconciliation, crash recovery, unsafe
resource refusal, forged-evidence refusal, stalled-domain isolation, and the
durable PQ register's cross-instance at-most-once behavior.

## Remaining M15Q work

This slice closes the executor-to-members-to-T10 process obligation. M15Q still
requires fail-closed process evidence for pre-install/in-flight handoff durable
boundaries, explicit rollback-image restoration, and an overlapping-root
handoff/restart. Any future post-retirement observer role must use separately
rooted observer credentials. M16Q and fresh M17Q review have not begun.

No result here changes M12a, creates portable QUV finality, or supports an
asynchronous or classical-consensus claim.
