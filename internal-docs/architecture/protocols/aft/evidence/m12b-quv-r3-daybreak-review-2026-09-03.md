# M12b QUV R3 Daybreak construction review

Principal disposition: **`REPAIR_REQUIRED`**.

This is an owner-authorized automated independent review under ADR 0049. It is
not human peer review, institutional certification, professional assurance, or
production security certification.

## Provenance

Reviewer: context-isolated OpenAI Codex agent using
`gpt-daybreak-blue-latest`, task `/root/quv_m12b_daybreak`. The reviewer did not
author the candidate and reported no known conflict.

```text
tag:        aft-quv-v0-construction-candidate-2026-09-03
tag object: bdea46545ad066fd661cd2a508aa5e967ee2deac
commit:     3b82bbdad594305b623701056a11627b00c53b06
message:    AFT QUV v0 construction candidate
clone:      /tmp/aft-m12b-quv-review.LZ5q9C/repo
```

The reviewer used a fresh no-hardlinks clone, checked out the annotated tag
detached, reported a clean checkout, and did not modify the shared repository.

## QUV-M12B-001 — correct-witness intersection gap

Severity: **critical**.

Affected: Q-A3 and Q-S1.

R3 guaranteed only that at least one correct member was timely for each
operation. It did not require that the same correct member be included in both
conflicting verifier operations.

Counterexample with two correct members `c0,c1`:

1. `c0` linearizes `X` before delayed `Y`.
2. `c1` linearizes `Y` before delayed `X`.
3. Only `c0`'s singleton `{X}` reply reaches the `X` executor by its deadline.
4. Only `c1`'s singleton `{Y}` reply reaches the `Y` executor by its deadline.
5. Byzantine members remain silent.

Both executors accept in the owned-equivocation union rule and the unowned
first-winner rule. Every request may still have been sent to every member. The
Q-S1 proof's “choose any correct `c`” step therefore did not follow from R3
Q-A3.

Required repair: guarantee a common correct intersection witness for all
operations during the authority lifetime. The simplest admitted form is that
every correct member completes every operation within the bound. Add bounded
multi-correct opposite-order coverage and a mutation that permits split timely
witnesses and recovers the conflict.

## QUV-M12B-002 — liveness evidence partly vacuous

Severity: **medium**.

Affected: Q-L1 bounded evidence.

R3 incremented `solo_failures` only for honest authority, synchronous mode,
`X` already present in correct state, and all-`X` operations. Dishonest and
unowned synchronous rows therefore reported zero without exercising a
liveness predicate, and fresh initially absent correct state was excluded.

Required repair: use a dedicated exactly-one-valid-candidate generator for
every applicable authority mode, include empty correct state and Byzantine
silence/non-conflicting behavior, or narrow the claim and labels.

## Reproduction

| Surface | Result |
|---|---|
| formal census | pass, 44 modules; 0.02 s, 10,776 KiB |
| maximal-visibility models | pass including expected counterexamples; 3.01 s, 267,512 KiB |
| QUV model | pass and structural JSON match; 1:27.50, 11,196 KiB |

```text
model SHA-256: 35e31a811b0ce63f1bb4bd522674190155ff75a590c6190c422ea52d3f5e9ec9
JSON SHA-256:  e3524914a51b5f6a696a612eef3a6c4707f4288c2c79a0e0a328a07b415e8819
runner SHA-256: 5a6088a9edbaa9c79cfe9e8d9abc32d0271b355ea01c58594d8ba42592fec84b
```

Environment: Linux 6.17.9 amd64, Python 3.12.3, Bash 5.2.21, OpenJDK
21.0.10.

## Limits and gate effect

The review covered source/model evidence, not production durability/load tests
or M13Q/M14Q. M12a remains intact. No portable-finality, asynchronous-safety,
Byzantine-consensus, ordering, recovery, reconfiguration, or effect theorem is
established.

R3 does not pass M12b. R4 must repair both findings, freeze a new immutable
candidate, and receive an exact-candidate independent retest.
