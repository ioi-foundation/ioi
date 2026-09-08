# Durable reconciliation exhaustion guard — local validation passed

Reconciliation now checks the recorded observation count before performing a
resource lookup. Once the manifest's maximum is reached, subsequent calls return
ReconciliationExhausted without lookup, receipt mutation or resource invocation.
The regression retains the three permitted ambiguous observations, clears the
transient lookup fault, retries repeatedly, reopens the store and retries again.
The durable receipt and lookup count must remain unchanged after exhaustion.

This enforces the existing completed-observation limit. It does not yet reserve
an attempt durably before lookup, so a crash between lookup and recording its
result is outside this bound. Terminal-result lookups and global request fairness
also require separate budgeting. Exhaustion is refusal, not effect liveness or
an authorization downgrade. Finding 010 remains open.

The preceding terminal-replay process pass belongs to the source snapshot in its
own evidence bundle. This guard is a later source change and must be included in
future full R2 qualification; the earlier process result is not relabeled as a
run of this revision.

All 19 consequence tests passed, with zero ignored. Command, source hashes and
raw output are retained in check.json and consequence.log.
