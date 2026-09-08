# Scoped initialized receipt reservation evidence

30 consequence, 7 type, 21 runtime, 2 executor tests, CLI, format/syntax and
all scoped proof/syscall gates passed on unchanged selected source. The final
endpoint and receipt traces include removed-rule controls. The latter checks
full initialization before QUV and all four audit/Claim/InFlight/Executed swaps.
The production live-allocation fallback mutant failed the intended lost-capacity
assertion (exit 101); exact source was restored. The reused index/record proof
sources are additionally bound and reproduced in supplemental-proof-binding.json.

Failed raw JSON preallocation designs are retained: reported allocation exceeded
payload capacity by 4096 bytes. The final AFTCR001 format records physical charge
separately, caps it at twice fixed capacity per file and initializes all blocks.
The test-header capacity expectation was corrected from 16384 to 20480 (including
32-byte header and page rounding). The initial syscall census expected three
swaps; source/trace showed four, including audit persistence; the gate requires
all four. Failed logs/checker sources remain in development artifacts.

Reproduce with run_checks.py. run_mutations.py temporarily applies a local
defensive mutant and restores the exact baseline; do not run other source writers
at the same time. This is a selected dirty-worktree source campaign, not clean
M16Q R2. Aggregate rooted admission, RAM/metadata/service, recovery/retention, full
transition refinement, final qualification, fresh review and M18Q remain open.
All 13 whole R1 findings remain OPEN. No immutable candidate or admitted claim.
