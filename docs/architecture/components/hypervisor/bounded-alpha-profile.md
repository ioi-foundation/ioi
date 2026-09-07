# Hypervisor Bounded-Alpha Profile

Status: canonical architecture authority.
Canonical owner: this file for the Hypervisor base-platform alpha profile — the
intended user, the one supported deployment, the qualified harness/model and
execution venue, the essential journey, the base-versus-optional acceptance
split, and the journey-to-contract-to-implementation readiness matrix.
Supersedes: readings of the flagship first-proof ruling as the platform's only
product proof.
Superseded by: none.
Last alignment pass: 2026-09-07 (ADR 0052 adoption).
Doctrine status: canonical
Implementation status: partial (see the readiness matrix; no packaged release,
no update/rollback path, and no release-qualified journey pass exist yet)
Last implementation audit: 2026-09-07
Implementation refs:
  - `crates/node/src/bin/hypervisor-daemon.rs`
  - `crates/node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs`
  - `crates/node/src/bin/hypervisor_daemon_routes/managed_runtime_routes.rs`
  - `apps/hypervisor/scripts/serve-product-ui.mjs`
  - `apps/hypervisor/scripts/ioi-agent-runs.mjs`
  - `packages/hypervisor-harness-shims/generic-cli-local.mjs`

## Purpose

Hypervisor is an integrated application for governed execution: projects and
workspaces, sessions, harness and model selection, environments, connections,
applications, automation, operational controls, and recoverable results. This
document fixes the smallest release of that platform that a real technical
user can complete a useful, governed, recoverable workflow on, and separates
that proof from every optional application, System-conformance, marketplace,
cloud, network and flagship ioi.ai proof.

[ADR 0052](../../../decisions/0052-hypervisor-bounded-alpha-profile-and-base-platform-acceptance.md)
adopts the profile. GoalRun, OutcomeRoom and their pursuit/collaboration
semantics belong to applications built on Hypervisor
([ADR 0022](../../../decisions/0022-goal-orchestration-application-layer-and-clean-slate.md),
[ADR 0031](../../../decisions/0031-goalrun-execution-composes-thread-orchestration.md));
nothing in this profile requires them, and no step here is a room, a goal
object, or an ioi.ai account.

## Intended user and supported deployment

| Facet | Alpha selection | Explicitly unqualified |
| --- | --- | --- |
| User | one invited technical operator who administers the host | multi-user organizations, invited members, IdP-federated identity |
| Host | one Linux x86_64 host the operator controls; daemon, served App and headless client on the same host | macOS, Windows, hosted/managed deployments, exposed (non-loopback) daemon postures |
| Identity | deployment-local operator identity bootstrapped from the daemon's one-boot bootstrap token; password login thereafter; optional passkey factor | SSO/OIDC, org membership, invite flows |
| Authority | a deployment-local wallet.network authority node whose approval key the operator holds; every consequential execution is an exact-effect approval by that key, rendered and confirmed in the App | hosted wallet.network, standing envelopes, portable v3 grants, external approver devices |
| Clients | the owned served App (`apps/hypervisor/scripts/serve-product-ui.mjs`) and the daemon HTTP API as the headless client | the Vite workbench, a dedicated CLI, SDKs, MCP gateway clients |
| Workspace | `local-workspace-v0` environment class under `local_workspace_provider_v0` (a directory on the host) | devcontainer, microVM, every cloud, GPU-market and DePIN provider |
| Harness and model | `generic-cli-local` shim over one local OpenAI-compatible model route (Ollama; `qwen2.5:7b` on the qualification host) | opencode/deepseek adapter drivers, remote model providers, model-route failover |
| Execution venue | the daemon's `host_spawn` lane: a host process in the session workspace with a minimal, secret-free environment and a bounded timeout | `native_local` decision lane, `container` lane, workload-bound isolation (ADR 0027) |

The isolation posture of the alpha venue is **host-process isolation only**:
the harness runs as the daemon's user, in the session workspace, with `PATH`,
`HOME` and the model endpoint as its whole environment. It is not a microVM,
not a container, and not the hostile-guest boundary; canon never infers one
from the other.

## The essential journey

```text
install
  -> bootstrap identity (bootstrap token -> operator password) and authority (local approver key)
  -> establish readiness (daemon, model route, workspace provider, wallet.network authority)
  -> open a project or scratch workspace
  -> select harness, model route and the session's connections (closed authority profile)
  -> start useful work (session create -> exact-effect approval -> execute)
  -> inspect progress, written artifacts, receipts, cost and approvals
  -> stop the run / revoke a connection
  -> restart the daemon and recover the session and its records
  -> back up and restore the deployment's durable state
  -> obtain diagnostics (doctor, status, logs, audit trail)
  -> update or roll back the release (qualification requirement)
```

App and headless client must agree on daemon-owned durable state at every
step: sessions, receipts, environments, connectors and backups are daemon
records, and neither client keeps lifecycle truth of its own.

## Base-platform acceptance versus optional and flagship proofs

| Class | What it covers | Alpha relationship |
| --- | --- | --- |
| Base platform | the journey above, on the selected profile, with the checks named in the matrix | required |
| Optional applications and capabilities | Data, Ontology, Pipelines, Foundry/models, Evaluations, Approvals, Automate, Packages, Studio/application building, bounded-System genesis and conformance, marketplace, decentralized.cloud, AIIP and network enrollment | each ships under its own owner's availability label and check; none gates the alpha; none is removed |
| Flagship ioi.ai proofs | sovereign-local completeness on the OutcomeRoom-backed institution, continuity across failure domains, two-sovereign AIIP, the north-star external-Worker proof | strong integration evidence for the application and substrate; never the platform's front-door proof |

## Journey → contract → implementation readiness matrix

Status vocabulary: `built` (implemented and covered by a named check),
`partial` (implemented in part or covered only by inspection), `program`
(landed or being landed by the 2026-09-07 program; evidence named in the
program-evidence section), `not built`. A status here claims exactly what its
basis says.

| # | Journey step | Contract owner | Implementation anchor | Check / basis | Status |
| --- | --- | --- | --- | --- | --- |
| 1 | Install a supported release | `core-clients-surfaces.md` § *Zero-To-Operable Local Deployment* | source build only: `cargo build -p ioi-node --bin hypervisor-daemon`, `npm ci` | none; `shipped-products.v1.json` posture `development_only` | not built (packaged release, signer, supply-chain evidence absent) |
| 2a | Bootstrap identity | `identity-access-and-metering.md` | `startup_auth_notice` prints a one-boot token; `POST /v1/hypervisor/auth/bootstrap`; `/__ioi/login` | `check:session-authority` (bootstrap → operator session) | built; App first-run form is `program` |
| 2b | Bootstrap authority | `wallet-network/doctrine.md`; `daemon-runtime/doctrine.md` | `IOI_HYPERVISOR_AUTHORITY_PRINCIPAL_REF` + wallet.network resolution (`governed_authority.rs`); approval grant minted by the deployment approver key | wallet.network fixture in `apps/hypervisor/scripts/lib/wallet-network-principal-authority-fixture.mjs`; local approver key mode is `program` | partial (authority node is a test fixture with a public approver seed; operator approval interaction is `program`) |
| 3 | Establish readiness | `daemon-runtime/platform-operability.md` § *Readiness and Degraded States* | `/healthz`, `/readyz` (static), `/v1/doctor`, `/v1/hypervisor/substrate/status`, `ExecutionSubstrate::probe` at execute | inspection; `check:launch-chain` (no-model refusal is typed) | partial (readiness is component-specific only at execute time) |
| 4 | Open a project or workspace | `core-clients-surfaces.md` § *Hypervisor Projects* | `/projects` (vendored SPA over `ioi-api-adapter.mjs`), `POST /v1/hypervisor/projects`, environments | `check:projects-saga`, `check:launch-chain` | built |
| 5a | Select harness and model route | `core-clients-surfaces.md` § *Agent Harness Adapters*; `model-routes` owner | `agent-runner-profiles`, `model-routes`, new-session composer (`augmentation/50-new-session.js`) | `check:model-route-authority`, `check:launch-chain` | built |
| 5b | Select the session's connections (closed authority profile) | `core-clients-surfaces.md` § *Hypervisor Sessions* (session authority profile) | `authority_profile.connection_refs` at session create; connector invoke admission | `check:session-authority-profile` | program |
| 6 | Start useful work | `daemon-runtime/api.md` sessions; `default-harness-profile.md` | `POST /v1/hypervisor/sessions` → `POST /sessions/:id/execute` (`host_spawn`, `generic-cli-local`) | `check:launch-chain` (admission chain), `verify-hypervisor-editor-harness-model-e2e.mjs` (real execute, dev signer) | built for execution; operator approval interaction is `program` |
| 7 | Inspect progress, artifacts, receipts, cost, approvals | `core-clients-surfaces.md` § *Hypervisor Sessions*, § *Receipts, Replay, And Improvement* | session record `latest_receipt_refs`, `sessions/:id/events`, `/__ioi/run-timeline`, `/__ioi/work-ledger`, `/v1/hypervisor/usage/consumption`, `/governance/approvals` | inspection; `check:launch-chain` events | partial (per-session cost not projected; approvals queue is the governance family, not the execute approval) |
| 8 | Stop / revoke | `daemon-runtime/api.md`; `connectors-tools/doctrine.md` | thread cancel, `harness-session-launches/:id/stop`, `sessions/:id/ports/revoke`, connector delete / credential revoke, `authority/revoke` | `check:launch-chain`, `check:session-authority` | built |
| 9 | Restart and recover | `daemon-runtime/doctrine.md` recovery; `managed_runtime_routes.rs` | session-create WAL, pending-execution recovery, launch-chain replay after daemon kill | `check:launch-chain` (kill/restart), `check:session-authority` (restart survival) | built |
| 10 | Back up and restore | `providers-and-environments.md` archive/restore; `platform-operability.md` § *Checkpoint, Backup, Restore* | managed backup bundle export/import (8 MiB import ceiling), restore plans with writer fence | `check:backup-restore` (two real daemons) | built, bounded (import size disclosed; bundle issuer is not verified) |
| 11 | Diagnostics | `platform-operability.md`; `operations-support` | `/v1/doctor`, support incidents, `/v1/hypervisor/audit/trail`, `/__ioi/operations` | inspection | partial |
| 12 | Update / rollback | `core-clients-surfaces.md` § *Zero-To-Operable Local Deployment* (`HypervisorChangePlan`) | none (no daemon self-update or release rollback path) | none | not built |
| 13 | App and headless agree on durable state | `core-clients-surfaces.md` § *First-Class Clients* | both clients read daemon records; the headless client is the HTTP API | `check:session-authority` (served vs daemon reads) | partial (no dedicated CLI) |

## Release qualification

The alpha may be called release-qualified only when, on the exact packaged
build, safe qualification records steps 1–13 with the evidence named above,
names the supported and unsupported profiles, records whether any uncertain
external effect needs reconciliation, and never treats a restore as permission
to repeat an effect. Steps 1 and 12 are `not built`; the alpha is therefore
**not release-qualified**, and the shipped-products register keeps
`development_only` until they are.

## Nonclaims

- No claim that any provider, harness, model or isolation posture other than
  the selected ones is qualified.
- No claim that host-spawn execution is workload-bound or hostile-guest
  isolation.
- No claim that the wallet.network fixture used in qualification is a
  production authority node; its approver seed is public test material.
- No claim of an end-to-end standalone product pass; that remains the
  flagship class's `sovereign-local` claim under `execution-horizons.md`.

## Program evidence (2026-09-07)

Recorded by the boundary and bounded-alpha program as it lands. Each row names
the command and the checkout it ran on; an absent row is an absent claim.

| Evidence | Command | Checkout | Result |
| --- | --- | --- | --- |
| (pending) | | | |

## Related Canon

- [`core-clients-surfaces.md`](./core-clients-surfaces.md) — sessions, clients, zero-to-operable journey.
- [`providers-and-environments.md`](./providers-and-environments.md) — environments, venues, archive/restore.
- [`identity-access-and-metering.md`](./identity-access-and-metering.md) — bootstrap and access contract.
- [`../daemon-runtime/doctrine.md`](../daemon-runtime/doctrine.md) — admission, recovery, effect boundary.
- [`../daemon-runtime/platform-operability.md`](../daemon-runtime/platform-operability.md) — readiness, backup, diagnostics.
- [`../../_meta/execution-horizons.md`](../../_meta/execution-horizons.md) — the flagship proofs this profile is separated from.
- [`../../_meta/shipped-products.v1.json`](../../_meta/shipped-products.v1.json) — release posture register.
