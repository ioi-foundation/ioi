# All-operation active service contract


### Required all-operation service contract — implementation in validation (2026-09-05)

AftQuvDomainPolicyV0 now requires operation_service_millis, with no serde default.
The canonical policy root moves to `ioi/aft/quv-policy/v3-operation-service` and
commits this field. The limit must exceed Delta, fit within checked Delta plus
continuation, and cover the independent preparation active limit. Root/config
validation refuses missing, insufficient or overflowing contracts. Existing
provisioning bindings therefore reject old roots; no migration or fallback is
introduced. Fixture policies and candidate roots explicitly supply the new field.

Every admitted operation now gets an active deadline: foreground and handoff use
the all-operation limit, and independent preparation uses its no-wider attempt
limit. The existing startup/dispatch timeout, capped decision timer, non-extending
live-grant expiry cap, pre-write expiry check and final completion check apply to
all roles. Deadlines start after exclusive admission. Queueing and selection are
outside this active interval and still require separate rooted aggregate bounds.
A deadline failure is logged as operation_service_expired. Evidence gates reject
that marker, the prior preparation marker, or any completed operation lacking
explicit service_budgeted=true and service_budget_met=true. No timeout grants
authority or establishes inclusion/effect progress.

**Assumes still unqualified:** actual startup/transport/storage/cleanup completion
within the active service contract, bounded selection/FIFO delay, correct clock
behavior and restart composition. An already-running blocking write retains its
shared admission permit until it returns or unwinds; a timeout cannot make that
write stop or bound its actual duration. Thus finite declared active budgets do
not yet discharge the queue/readiness lemma's elapsed-time premise.

Validation is ongoing in `evidence/m17q-r1-all-operation-service-2026-09-05/`.
Configuration tests and 40 core tests passed (one pre-existing ignored test remains
separate). Runtime, CLI, removed-rule and process qualification must be completed
for this exact root change. Earlier process evidence is historical. All whole
R1 findings, full transition refinement, clean R2 and release admission remain open.


### All-operation service local validation (2026-09-05)

For the v3-operation-service implementation, configuration validation passed,
40 core tests passed with the separately retained existing ignored test, and all
16 QUV runtime tests passed. The CLI aft_e2e test target compiled. Omitting the
operation-service field from canonical hashing makes the new binding regression
fail; bypassing the foreground budget makes the role-selection regression fail.
Restored source passes both. These are scoped binding/selection controls, not a
claim that the complete production timeout workflow has been mutated end to end.

The strengthened main checker passes 2 positive/26 negative process cases and
1 positive/31 negative overlap/component cases; the handoff checker passes
1 positive/26 negative cases. Removing each checker's completed-operation service
guard causes its self-test to fail. Affected Rust formatting, runner syntax and
diff checks pass. The CLI fixture was formatted after compilation; this formatting
change has no behavioral validation claim beyond rustfmt's successful parse.
Raw commands, outcomes and final hashes are retained in
`evidence/m17q-r1-all-operation-service-2026-09-05/`.

Process and restart qualification of this root/behavior change remains required,
as do a derived and qualified queue/readiness bound, full transition refinement,
clean R2 and closure of every whole R1 finding. No declaration of finite service
or successful local test turns refusal, timeout or a stalled durable write into
progress.


### v3-operation-service foreground campaign (2026-09-05)

The unchanged-source campaign passed its process test and all three retained
evidence checks. All four sole-correct placements and saturation operations
executed; four-way overlap was 4927.347ms. The concurrent conflict case had zero
acceptances, two typed refusals, zero durable records and non-mutation: safety
only, no conflict-case progress. The unrelated effect executed, and unchanged
terminal-result retrieval observed height 70 beyond expiry 65. Worker diagnostics
matched 17 starts and 9 accepted completions across the expected workers.

Evidence is under `evidence/m17q-r1-all-operation-service-2026-09-05/foreground-process/`.
The source audits in that directory still identify incomplete startup/dispatch
admission ownership and completion sampling before final permit release. This
process pass neither resolves those findings nor proves actual admission-release
or aggregate queue/readiness bounds. All whole R1 findings and clean R2 remain open.
