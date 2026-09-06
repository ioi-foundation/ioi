# Durable reconciliation attempt reservation — local validation passed

Receipts now commit reconciliation_attempts. Reconciliation takes the greater
of this count and legacy recorded ambiguous observations, refuses an exhausted
budget, and durably increments the count before invoking lookup. Crashes before
or after lookup cannot erase that reservation under the existing atomic durable,
non-rollback receipt-store assumption. A reserved attempt can be spent without a
lookup if the process crashes first; the budget is conservative, not liveness.
A later ambiguous lookup preserves an already known Executed phase rather than
attempting an illegal Executed-to-Unknown transition.

The field defaults to zero and is omitted at zero, preserving old canonical bytes
and receipt roots. Nonzero values are receipt-root committed; older strict
readers that do not know the field will reject such receipts. This requires
coordinated reader upgrades and is not claimed to be transparent to old readers.
Legacy ambiguous observations still count. The maximum remains the manifest's
maximum_observations setting. Terminal-result verification lookups are separate
from reconciliation attempts and their request budgeting/fairness remains open.

All 21 consequence tests and the production validator compile check passed. The
new tests cover repeated crashes immediately after reservation and after lookup,
reopen, exhaustion without further lookup, zero-field encoding, legacy count
carry-forward and preservation of known execution. The general persistence/crash
suite now includes AfterLookupReserved. Earlier raw process results belong to
their earlier source snapshots; this change is not yet process-qualified.

The mandatory formal and M16Q runners now include ReconciliationBudget.tla/cfg.
TLC checked 30 distinct states (54 generated, depth 7) for MaxAttempts=3 and all
legacy counts 0..3; the existing T10 model also passed. This small component
model assumes atomic non-rollback reservation and does not prove filesystem
refinement, arbitrary deployment scheduling, fairness, or the complete R1 model.
All critical/high R1 findings remain open until complete qualification/review.
