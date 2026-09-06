# Non-executable online retry audit preservation — local validation passed

The online consequence execution entry point now requires Authorized or Claimed
state before consuming a process-local continuation or replacing the stored
audit. InFlight, Unknown, Executed and Reconciled states return WrongState without
changing the receipt. This aligns the effect boundary with the existing public
online-requirement eligibility check.

The regression reaches Executed through normal execution, InFlight through the
existing before-call crash hook, Unknown through recovery, and Reconciled through
lookup. Retries before/after reopen must preserve receipt bytes, generation,
audit and resource counters and must never call the supplied continuation's
consume method. The existing positive Authorized and Claimed execution tests
remain in the same suite. These are local state-machine checks, not full process
crash qualification or a mutation campaign against production binaries.

This patch does not implement public terminal-result idempotency or reconcile
fairness, and does not close finding 010. Every new effect still requires live
QUV; the preserved audit supplies no independent authorization.

All 18 consequence tests passed, with zero ignored; check.json and consequence.log
retain the command, source hashes and raw output. This dirty-checkout evidence
is not clean M16Q R2 qualification.
