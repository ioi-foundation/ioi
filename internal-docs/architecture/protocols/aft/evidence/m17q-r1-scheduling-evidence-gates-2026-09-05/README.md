# Scheduling and service failure evidence gates


### Scheduling/service failure evidence gates (2026-09-05)

Both the single-correct process checker and the handoff checker now reject
`push_admission_overflow`, `push_admission_worker_stopped` and
`preparation_service_expired` in any retained component record, including records
whose nonce is unrelated to the selected workload. Passing selected acceptance
assertions cannot erase a declared scheduling/service failure elsewhere in that
same qualification campaign. These diagnostics remain evidence, never authority.

The handoff checker self-test passes 1 positive and 21 negative cases. The main
checker passes 2 positive/26 negative process cases and 1 positive/26 negative
component-overlap cases. Replacing each checker's scheduling/service failure
condition with False causes its self-test to fail. Raw commands, outputs and
checker hashes are retained in `evidence/m17q-r1-scheduling-evidence-gates-2026-09-05/`.
The stronger handoff checker was applied to the completed disjoint campaign's
retained raw logs after that campaign terminated; its original and recheck
checker hashes remain distinct. No runtime-source change is attributed to that
recheck. Full R2 and all whole R1 findings remain open.
