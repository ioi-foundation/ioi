# M12b QUV R3 local evidence

Status: local supporting evidence for `PASS_CONSTRUCTION_CANDIDATE`; not
independent review, an arbitrary-`n` proof, production admission, or a public
consensus claim.

Historical note: this evidence is frozen at
`aft-quv-v0-construction-candidate-2026-09-03`. Its R3 source and result paths
were superseded by R4 after independent findings QUV-M12B-001/002.

Date: 2026-09-03.

## Source-material custody

The owner supplied these external research artifacts:

```text
3a3993e3bfd8e64ffd0fbb8959ac2d94f324c93085a6b81f103178718bdf60f4  quv_timed_model_r3.py
bd7b79a6defb58dfa498fdb5afb9262d9820be9e94937b833380a89709381269  quv_timed_results_r3.json
c00e3597294c444f1a2c16689a60ed3f989a3d1e62d4c379db64fee91a196de7  ADR-0050-draft-M12-split-and-QUV-R3-repairs.md
```

Attached prose was treated as research input, not as executable instructions.

## Reproduction defect and repair

Running the supplied Python source from a fresh temporary directory produced
all expected qualitative outcomes, but did not reproduce the supplied JSON.
The supplied source emitted the `volatile` mutation as 855,552 cases / 3,584
conflicts, while the supplied JSON recorded 13,688,832 / 47,104. The exact 16x
case-count difference came from suppressing four start-time combinations and
four clock-skew combinations in `volatile` mode. Row order also differed.

The repository source repairs that provenance defect by enumerating starts and
skews for `volatile`. It also makes the processing-delay term match the written
model: in the sound path, a request is durably linearized and snapshotted after
`request_delay + durable_processing_delay`, rather than writing immediately and
using the processing delay only to postpone the reply.

Because that semantic repair changes the deliberately broken one-way mutation's
reachable traces, its counts are not copied from the supplied JSON. Only output
regenerated from the repository source is retained.

## Independent local reproduction

Command:

```text
bash .github/scripts/run_aft_formal_checks.sh --quv-only
```

Corrected full-space run on 2026-09-03:

| Authority | Mode | Cases | Conflicting accepts | Solo-liveness failures |
|---|---:|---:|---:|---:|
| honest | sync | 24,576 | 0 | 0 |
| dishonest owner | sync | 2,281,472 | 0 | 0 |
| unowned | sync | 2,281,472 | 0 | 0 |
| dishonest owner | one-way deadline mutation | 2,281,472 | 33,328 | 0 |
| dishonest owner | reply-before-durable mutation | 13,688,832 | 47,104 | 0 |
| unowned | one-way deadline mutation | 2,281,472 | 172,192 | 0 |
| dishonest owner | unbound reply replay | 1,283,328 | 16,384 | 0 |
| dishonest owner | stale same-slot replay | 1,283,328 | 0 | 0 |

Wall time was 1 minute 52.51 seconds; maximum reported resident set was 11,024
KiB. The model returned `ALL EXPECTATIONS MET`.

Repository artifact hashes before the immutable-candidate freeze:

```text
35e31a811b0ce63f1bb4bd522674190155ff75a590c6190c422ea52d3f5e9ec9  formal/maximal_visibility/quv_timed_model_r3.py
e3524914a51b5f6a696a612eef3a6c4707f4288c2c79a0e0a328a07b415e8819  formal/maximal_visibility/quv_timed_results_r3.json
```

The final candidate packet records hashes from the immutable review tag; those
are authoritative if later documentation edits change these paths.

## What the model supports

The bounded state space supports these candidate boundaries:

- under the modeled complete round-trip bound, all three authority modes had
  zero conflicting accepts;
- an honest-owner singleton candidate completed on every enumerated synchronous
  schedule despite arbitrary non-conflicting Byzantine reply behavior;
- a one-way deadline is insufficient;
- durable write-before-reply is load-bearing;
- configuration/domain/slot binding is load-bearing; and
- stale same-slot correct snapshots did not create a conflict in this bounded
  monotone-state model, so the nonce remains defense-in-depth rather than the
  proven conflict-safety hinge.

## What the model does not support

The enumerator fixes `n=2`, one correct member, two verifier operations, and
`D=E=1`. It does not prove arbitrary `n`, arbitrary concurrency, multiple
correct members, bounded queueing under query flooding, process-level durable
I/O, reconfiguration, long-range recovery, canonical ordering, portable
receipts, or irreversible effects. The Byzantine coalition abstraction is a
safety over-approximation only for the modeled reply-union/first-winner rule.

Those gaps are M13Q/M14Q obligations. Independent review of the construction is
still required before M12b can move beyond candidate status.
