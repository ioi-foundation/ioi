# M16Q QUV qualification evidence — 2026-09-04

Status: `PASS`

Current gate disposition: **REOPENED after M17Q R1 `REPAIR_REQUIRED`**.
The PASS below records the historical commands on the exact subject; it is
not admission evidence for the current implementation or for coverage absent
from that runner. See `m17q-r1-import-2026-09-04/README.md`. All R1 repairs
require clean full R2 qualification and fresh independent review.

## Exact subject

- Code commit: `ab8d2e58103a2eef3e39c1c6042ffefd7d3c86f4`
- Clean-run directory:
  `m16q-runs/20260904T204403Z-ab8d2e58103a`
- Runner: `.github/scripts/run_aft_m16q_qualification.sh`
- Started: `2026-09-04T20:44:03Z`
- Completed: `2026-09-04T21:42:50Z`
- Source worktree: clean (`tree_dirty=false`)
- Toolchain: Rust 1.93.1, Cargo 1.93.1, Python 3.12.3, Node 22.22.0,
  npm 10.9.4, Linux x86_64, 24 logical CPUs

The evidence-bearing documentation commit is a descendant of the code commit.
`source-sha256.txt`, `artifact-sha256.txt`, commands, complete logs, environment,
and phase results are retained in the run directory.

## Complete runner result

| Phase | Result | Seconds |
|---|---:|---:|
| QUV R4 formal checks | PASS | 65 |
| QUV core | PASS | 287 |
| PQ transport | PASS | 95 |
| PQ swarm admission | PASS | 6 |
| T10 consequence | PASS | 3 |
| Terminal-seal simulation | PASS | 0 |
| Terminal-seal receipts | PASS | 247 |
| QUV component timing | PASS | 106 |
| QUV sole-correct process campaign | PASS | 318 |
| Disjoint reconfiguration | PASS | 313 |
| Overlap reconfiguration | PASS | 260 |
| PQ hash-async process | PASS | 1135 |
| PQ ordering restart | PASS | 540 |
| Hypervisor web build | PASS | 95 |
| Hypervisor daemon build | PASS | 57 |

All 15 phases passed. The runner's `phase-results.tsv` and `result.txt` are the
machine-readable disposition.

## Deployment-envelope observations

The release-mode 256-sample component profiles reported microsecond tuples in
the form `[samples,min,p50,p95,p99,max]`:

- ML-DSA-44 signing of 4096 bytes:
  `[256,155131,157874,222946,247908,269431]`
- durable write-before-reply with the hash signer:
  `[256,33423,36155,40261,57969,62008]`
- durable write-before-reply with ML-DSA-44:
  `[256,180874,201396,229544,238247,250921]`

The process campaign exercised every sole-correct placement. Maximum valid
reply observations were 260, 252, 272, and 260 ms. Authenticated saturation
reached 2722 ms, below the configured 4000 ms qualified envelope and the
5000 ms rooted end-to-end deadline used by the fixture. Concurrent opposing
valid candidates produced zero accepts, and an unrelated domain subsequently
executed.

These measurements qualify the recorded hardware/software fixture. They do
not convert known synchrony into an asynchronous guarantee; operators must
derive a deployment-specific rooted round-trip envelope with explicit margin
and fail closed outside it.

## Claim boundary

M16Q qualifies the production implementation of online Query-Unanimity
Verification under its declared timing, reachability, durability, signature,
configuration, and executor-side revalidation assumptions. It does not prove
portable or offline finality, asynchronous progress, exact-decision Byzantine
agreement, or classical Byzantine consensus. Audit transcripts remain
non-authorizing and `portable_final_receipt=false`.

M12a remains the proved portable byte-only lower bound. Original M13-M18 remain
blocked. This PASS advances only the separately named interactive path to M17Q.
