# Expired terminal-result observation regression

Local development evidence only. This fixture correction changes neither live
QUV authorization nor terminal-receipt semantics. All whole R1 findings remain
open; this is not clean R2 qualification.

`unit-results.json` binds the exact helper test command and source hashes. The
positive and restored runs pass. Three removed-rule controls fail the actual
regression: admitting equality at the expiry fence, ignoring changed receipt
bytes, and allowing portability. Their raw test logs are retained.

The fixture polls the effect endpoint's admitted-height metadata, instead of
using public block availability as a proxy. Any RPC error, malformed metadata,
changed receipt or portable result is immediately fatal. Only an unchanged
nonportable result at a strictly later admitted height satisfies the case. The
whole observation is bounded by 240 seconds, each RPC by 30 seconds.

`process/started.json` records the process command, environment and selected
source hashes; `process/result.json` records its eventual terminal status and
any source changes. Component logs are retained from before process startup.
Process evidence must pass the repository's strict process/overlap checker;
worker diagnostics alone cannot admit a failed campaign.

`previous-failed-campaign-worker-check.json` is scoped to the earlier failed
active-service campaign. Fifteen worker completions matched live-query and active
service diagnostics, with five evidence controls rejected. That campaign still
failed its combined expired-result assertion. Its failed field and root cause
remain unknown; no result here retroactively changes its disposition.


The expiry-observation campaign terminated with exit 101 on unchanged recorded
sources. Four sole-correct placements and four saturation effects executed;
both conflicting candidates were rejected with resource non-mutation (safety
only). The unrelated effect failed exact four-member audit coverage, so the
new expiry case was not reached. Its missing member completed durable processing,
but the reply was routed approximately 5296.857ms after the operation-start
log, beyond the rooted 5000ms decision interval, and was absent from the audit.
These are same-host diagnostics; they do not isolate transport, queue, lock or
scheduler delay, or qualify the timing premise. The strict process checker
rejects the run. No retry or relaxed coverage is used to turn it into a pass.
Raw logs and the extracted lifecycle are in
`evidence/m17q-r1-expiry-observation-2026-09-05/process/`.
The strengthened expiry fixture remains locally tested but process-unqualified.
All whole R1 findings and aggregate readiness/timing qualification remain open.
