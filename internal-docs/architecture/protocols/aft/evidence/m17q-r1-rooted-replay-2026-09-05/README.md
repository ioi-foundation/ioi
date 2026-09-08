# Rooted preparation replay and bounded waiting — scoped evidence

The recorded schema-8 revision passes 62 QUV tests (one unrelated ignored benchmark), 21 runtime tests, CLI test-target compilation, workspace formatting and qualification-runner syntax. `started.json` contains the exact selected source hashes and retained source copies; `results.json` records every command and exit status; `completed.json` verifies unchanged selected sources. This is a dirty-worktree source subset, not an immutable R2 candidate.

Preparation records carry the complete rooted policy preimage. Live staging and authenticated recovery check its commitment and attempt cap, so exhaustion survives reopen. Negative regressions reject a substituted policy and a third reservation beyond a two-attempt cap without disk/anchor/memory changes. Schema-7 bootstrap refusal is specifically `ProvisioningMismatch` and preserves existing bytes. Safe migration remains unresolved; never erase conflict knowledge to start schema 8 under the same authority.

The runtime explicitly permits only one waiting preparation request. Duplicate preparation is refused; cancellation releases capacity and replacement joins behind a waiting foreground request. Combined with the existing one-waiter-per-domain rule, there are at most D+1 waiting operations and one active operation. This bounds queue count, not wall-clock service, scheduler delay or Q-A9.

All 117 artifacts and 65 selected source hashes in the preceding schema-7 journal campaign match their retained manifests (`prior-evidence-check.json`). Its process and benchmark results remain historical and do not qualify this revision.

Full rooted authority lifetime/byte/rate/slot quotas, safe retention/compaction, aggregate service and recovery bounds, complete transition refinement, clean full R2, fresh independent M17Q review and M18Q admission remain outstanding. All 13 whole R1 findings remain open. Fixed M12a/M12b assumptions and `portable_final_receipt=false` are unchanged.

The subsequent [streaming-recovery revision](streaming-recovery/README.md) passes 64 QUV tests, 21 runtime tests and the same build/format/syntax gates on its own unchanged source subset. Use its `started.json` and `completed.json` for the newest scoped revision. Neither revision is full R2 qualification.


Schema-9 finite-profile evidence is retained in [finite-profile](finite-profile/README.md)
and its recorded repeat [finite-profile-final](finite-profile-final/README.md).
These selected-source checks add first-two summaries, finite rooted horizons,
encoded lifetime accounting and formal algebra. They are not physical allocation,
full transition refinement, clean R2 or release admission.
