# ioi.ai — IOI rebind

`apps/ioi-ai` is the **one** ioi.ai application (owner ruling, 2026-08-07). It
began as a vendored fork of the QM web shell and now receives IOI modifications
directly. There is no second ioi.ai runtime.

Per-file provenance is recorded in
[`../../docs/architecture/_meta/ioi-ai-vendor-snapshot.v1.json`](../../docs/architecture/_meta/ioi-ai-vendor-snapshot.v1.json):
`vendored` · `vendored_then_modified` (carrying its upstream hash) · `ioi_owned`.
The pristine upstream hashes are frozen at
[`../../docs/architecture/_meta/ioi-ai-upstream-baseline.v1.json`](../../docs/architecture/_meta/ioi-ai-upstream-baseline.v1.json).
`npm run check:ioi-ai-vendor` verifies the ledger and prints the tally.

---

This is the IOI-owned, executable `ioi.ai` product. It composes GoalRun and
OutcomeRoom application semantics over the canonical Hypervisor daemon while
retaining the mature chat, project, file, schedule, keychain, application,
memory, and skill interaction grammar from the QM web shell.

The vendor source under `apps/ioi-ai/` remains dormant and is locked to its
committed Git mode/blob identities by `vendor-snapshot.v1.json`. The ledger
records upstream repository and commit metadata but does not independently
attest the upstream tree. This product began as a derivative of its
`plugins/web-ui` package under the MIT license in [`LICENSE`](LICENSE); shared
chassis and core wire types are consumed read-only from the vendor snapshot so
local drift is explicit at typecheck time.

The rebind owns its server, browser UI, tests, build, and release evidence. It
does not grant execution authority: the Hypervisor daemon remains the owner of
thread, fork, session, launch, harness, receipt, and replay truth.

From `plugins/web-ui` with Node 24 or newer:

```bash
npm ci
npm run build
npm run typecheck
npm test
npm run smoke:browser
```
