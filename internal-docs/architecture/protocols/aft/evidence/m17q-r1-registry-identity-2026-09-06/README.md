# Registry identity admission repair — scoped evidence

The v2 registry reserves each exact validated effect ID jointly with its manifest,
height and schema marker in the workload transaction overlay. A different manifest
cannot reuse the ID and invalidate retrieval of the prior admitted effect. An
absent schema marker initializes only an empty namespace; old or partial state
refuses without erasure. No automatic legacy migration is implemented.

Four registry tests and two restored omission controls cover identity substitution,
unchanged prior state, unrelated same-height admission, snapshot restoration, and
unindexed/unknown schema refusal. Snapshot restoration is not process recovery.
The conditional locator proof has 10 TLAPS obligations; models explore 35 and 21
states. Three expected countermodels cover duplicate registry identity, discarded
index ambiguity, and prematurely trusted recovery.

The collector also passed 15 runtime-finality tests, CLI compilation, formatting,
and runner syntax. The transaction-write cleanup gate initially failed compilation
with ENOSPC. Its original log/results/completed.json are preserved. Only inactive
incremental caches were removed (cache-cleanup*.json); the same one-test command
then passed on unchanged selected sources (retry-*.json). combined-disposition.json
records this scoped retry outcome without replacing the initial failure.

Reproduce with `python3 run_checks.py` and `python3 run_mutations.py` from the
repository root using this directory's script paths. The mutation script temporarily
edits one production file and restores it; run exclusively, without other writers.
Exact commands and source copies/hashes are retained. Toolchain versions were
observed later in the same session (toolchain-observed.json), not captured by
the original collector. This is selected
dirty-worktree evidence, not an immutable qualified checkout. The earlier receipt
pressure/restart process predates this registry change.

Assumes: authenticated committed state; exclusive registry namespace ownership;
valid complete schema bootstrap; transaction failure discards all overlay writes;
current committed-record revalidation at retrieval. Aggregate history, physical
resource/service bounds, migration qualification and full transition refinement
remain open. All 13 whole findings remain OPEN; M16Q R2 unqualified, M17Q
REPAIR_REQUIRED, M18Q NOT_ADMITTED.
