# Expired online result retrieval — local validation passed

A new preparation entry point distinguishes existing result retrieval from new
execution. It permits an expired upper time fence only when a stored online
receipt is InFlight, Unknown, Executed or Reconciled. All manifest, achieved
profile, original authorization evidence and fence identity checks still run.
Protocol-height lower bounds remain enforced. Missing receipts and Authorized
or Claimed receipts cannot obtain this exception. The public authorize method
and immediate pre-call fence remain strict.

Both production callers use preparation before candidate binding and retry
handling; they still use strict authorize after live QUV. Existing results then
follow the resource lookup comparison or bounded reconciliation path and never
invoke the mutation method. Current committed admission is still required:
expiry does not permit retrieval under substituted, revoked or unavailable
admission, or turn an audit into fresh execution authority.

All 22 consequence tests and the validator compile check passed. Tests cover
both protocol-height and authority-epoch fences, unchanged terminal bytes,
reopen, changed admission, changed epoch/snapshot, missing/Authorized/Claimed
expiry rejection, and unchanged invocation counts. The production expired-result
RPC path is not yet process-qualified; earlier terminal replay evidence used the
earlier source and live fences. No R1 finding is closed by these local checks.
