# Hypervisor Bounded-Alpha Profile

Status: canonical architecture authority.
Canonical owner: this file for the Hypervisor base-platform alpha profile — the
intended user, the one supported deployment, the qualified harness/model and
execution venue, the essential journey, the base-versus-optional acceptance
split, and the journey-to-contract-to-implementation readiness matrix.
Supersedes: readings of the flagship first-proof ruling as the platform's only
product proof.
Superseded by: none.
Last alignment pass: 2026-09-07 (ADR 0052 adoption; closure program the same day).
Doctrine status: canonical
Implementation status: built (every matrix row has a named check; the journey
passed 44/44 on the release-profile packages without a checkout — see
§ Release qualification for the exact claim and its bounded properties)
Last implementation audit: 2026-09-08
Implementation refs:
  - `crates/node/src/bin/hypervisor-daemon.rs`
  - `crates/node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs`
  - `crates/node/src/bin/hypervisor_daemon_routes/managed_runtime_routes.rs`
  - `crates/node/src/bin/hypervisor_daemon_routes/release_change_plan_routes.rs`
  - `crates/cli/src/bin/wallet_network_local_authority.rs`
  - `apps/hypervisor/scripts/serve-product-ui.mjs`
  - `apps/hypervisor/scripts/ioi-agent-runs.mjs`
  - `apps/hypervisor/scripts/wallet-network-authority.mjs`
  - `apps/hypervisor/scripts/verify-hypervisor-alpha-journey.mjs`
  - `apps/hypervisor/scripts/verify-hypervisor-session-authority-profile.mjs`
  - `apps/hypervisor/scripts/verify-hypervisor-launch-chain.mjs`
  - `apps/hypervisor/scripts/verify-hypervisor-backup-restore.mjs`
  - `scripts/package-hypervisor-alpha-release.mjs`
  - `scripts/install-hypervisor-alpha-release.mjs`
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
| Harness and model | `generic-cli-local` shim over one local OpenAI-compatible model route (Ollama; `qwen2.5:7b` on the qualification host), or over one remote OpenAI-compatible route whose key is sealed to the route record through the App's custody card and used only inside the daemon's model-mount proxy (`M13.9`, bar met 2026-09-11 on `gpt-4o-mini`; the harness holds a run-scoped model-mount token, never the key) | opencode/deepseek adapter drivers, model-route failover, any remote route without a sealed credential (the process-environment key path) |
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
| 1 | Install a supported release | `core-clients-surfaces.md` § *Zero-To-Operable Local Deployment* | `scripts/package-hypervisor-alpha-release.mjs` (signed manifest: checkout, toolchains, cargo profile, per-file digests, SBOM) → `install.mjs verify/install/activate` against an operator-pinned signer; the package ships BOTH grant signers (`bin/mint-approval-grant`, and since `8281d915e` `bin/mint-standing-approval-grant` — R-23) | `test:hypervisor-alpha-release` (4/4); `check:alpha-journey` package + no-checkout mode step 1 — re-derived 2026-09-10 on `8281d915e`, 46/46 (the daemon, App, signer, shim, installer and authority node under test are the installed release-profile bytes; no cargo reachable) | built (2026-09-08, release cargo profile; the package is self-sufficient on a host without a checkout) |
| 2a | Bootstrap identity | `identity-access-and-metering.md` | `startup_auth_notice` prints a one-boot token; `POST /v1/hypervisor/auth/bootstrap` (accepts the operator's name and email); the sign-in page is the first-run setup form (`/__ioi/bootstrap`) while no operator exists | `check:session-authority` (bootstrap → operator session); `check:alpha-journey` step 2a | built (2026-09-07) |
| 2b | Bootstrap authority | `wallet-network/doctrine.md`; `daemon-runtime/doctrine.md` | `wallet-network-authority.mjs up` (§ *Supported deployment bring-up*): generated control root, sealed capability client key and operator approver key, durable Solo chain, binding v1; `daemon.env`/`serve.env`; the approval act mints one one-use grant for the daemon's capability audience and RECORDS it on the node (`record-approval`) before the daemon consumes it; `rotate` / `revoke` | `check:alpha-journey` deployment + no-checkout mode steps 2b (incl. the closure assertion: launcher, node binaries and installer outside the repository, no cargo on any child PATH), 6, 2c-rotation, 2c-revocation; standalone drills (checkout: up → rotate → revoke → resume → rotate; package: `up` from `/tmp` with cargo absent; empty pinned dir → typed `node_binaries_absent`) | built (2026-09-08); bounded: deterministic chain clock unless `--wall-clock` |
| 3 | Establish readiness | `daemon-runtime/platform-operability.md` § *Readiness and Degraded States* | `/healthz`, `/readyz` (static), `/v1/doctor`, `/v1/hypervisor/substrate/status`, `ExecutionSubstrate::probe` at execute | inspection; `check:launch-chain` (no-model refusal is typed) | partial (readiness is component-specific only at execute time) |
| 4 | Open a project or workspace | `core-clients-surfaces.md` § *Hypervisor Projects* | `/projects` (vendored SPA over `ioi-api-adapter.mjs`), `POST /v1/hypervisor/projects`, environments | `check:projects-saga`, `check:launch-chain` | built |
| 5a | Select harness and model route | `core-clients-surfaces.md` § *Agent Harness Adapters*; `model-routes` owner | `agent-runner-profiles`, `model-routes`, new-session composer (`augmentation/50-new-session.js`) | `check:model-route-authority`, `check:launch-chain` | built |
| 5b | Select the session's connections (closed authority profile) | `core-clients-surfaces.md` § *Hypervisor Sessions* § *Session authority profile* | `authority_profile.connection_refs` at session create (durable, projected); connector invoke admission in `handle_connector_invoke`; the New Session modal's closed picker | `check:session-authority-profile` (21/21, CI-gated, floor-pinned) | built (2026-09-07) |
| 6 | Start useful work | `daemon-runtime/api.md` sessions; `default-harness-profile.md` | `POST /v1/hypervisor/sessions` → `POST /sessions/:id/execute` (`host_spawn`, `generic-cli-local`); the composer run parks on the operator's approval; Work / Sessions AND the SPA session pane render the exact effect with Approve / Deny; approving mints + records one grant and resumes the execute | `check:launch-chain` (admission chain); `check:alpha-journey` step 6 (real execute after operator approval: `done`, artifact written, 239 s on the qualification host) | built and qualified (2026-09-07) |
| 7 | Inspect progress, artifacts, receipts, cost, approvals | `core-clients-surfaces.md` § *Hypervisor Sessions* § *Session surface*, § *Receipts, Replay, And Improvement* | the SPA session pane's Run Timeline bound to the daemon session record, its `latest_receipt_refs` (execute receipt with capability lease), `sessions/:id/events`, and the parked approval; `/__ioi/sessions` as the Operations readout; `/__ioi/work-ledger`; `/v1/hypervisor/usage/consumption` | `check:session-truth-rebind` (11/11); `check:alpha-journey` step 7 (artifact on disk, execute receipt binding the lease, proof band from daemon records) | built (2026-09-07); bounded: per-session cost is not projected |
| 8 | Stop / revoke | `daemon-runtime/api.md`; `connectors-tools/doctrine.md` | thread cancel, `harness-session-launches/:id/stop`, `sessions/:id/ports/revoke`, connector delete / credential revoke, `authority/revoke` | `check:launch-chain`, `check:session-authority` | built |
| 9 | Restart and recover | `daemon-runtime/doctrine.md` recovery; `managed_runtime_routes.rs` | session-create WAL, pending-execution recovery, launch-chain replay after daemon kill | `check:launch-chain` (kill/restart), `check:session-authority` (restart survival) | built |
| 10 | Back up and restore | `providers-and-environments.md` archive/restore; `platform-operability.md` § *Checkpoint, Backup, Restore* | managed backup bundle export/import (8 MiB import ceiling), restore plans with writer fence | `check:backup-restore` (two real daemons) | built, bounded (import size disclosed; bundle issuer is not verified) |
| 11 | Diagnostics | `platform-operability.md`; `operations-support` | `/v1/doctor`, support incidents, `/v1/hypervisor/audit/trail`, `/__ioi/operations` | inspection | partial |
| 12 | Update / rollback | `core-clients-surfaces.md` § *Zero-To-Operable Local Deployment* (`HypervisorChangePlan`); `daemon-runtime/api.md` § *Release Change Plans* | `POST /v1/hypervisor/release-change-plans` (admit; no-op and double-admission refused) → `install.mjs activate` / `rollback` + restart → `…/observe` (the daemon hashes its own executable against the target) → receipts | `check:alpha-journey` — re-derived 2026-09-10 on `8281d915e` (debug-profile packages v1 `0.1.0-alpha.8` → v2 `0.1.0-alpha.9`, daemon digest observed `465fb0dc…`, rollback observed) package mode step 12 (update to v2 completed, rollback to v1 completed, both observed by the daemon's own digest; durable state intact across both) | built (2026-09-08: v2 is a real successor build — `5c5340ea6` adds the running crate version to the change-plan listing — on the release profile) |
| 13 | App and headless agree on durable state | `core-clients-surfaces.md` § *First-Class Clients* | both clients read daemon records; the headless client is the HTTP API | `check:session-authority` (served vs daemon reads); `check:alpha-journey` step 13 and step 12 (plans listed by the headless client agree with the installer's activation history) | built for the two alpha clients (no dedicated CLI is claimed) |

## Declared widenings (2026-09-10, ADR 0053)

Three widenings of the supported profile are declared as units with a
qualification bar each. A row here moves a facet of the supported table above
only when its bar is met by a named check on a named checkout, never by this
declaration: `M13.11` met its bar on 2026-09-11 (ledger XXXVIII); `M13.9` met
its bar on 2026-09-11 with the owner's key (ledger XL); `M13.10` is not built.

| Widening | Unit | Qualification bar | Status |
| --- | --- | --- | --- |
| A remote frontier model route, selectable in the session composer beside the local one; the daemon's model-mount proxy performs the provider call with a credential sealed to the route record, so the harness environment stays secret-free | `M13.9` | the essential journey passes with the remote route selected; receipts name the route; the credential is never observable in the session environment; the process-environment key path stays refused by default; a live run is recorded with its cost, and without an operator credential the lane records a typed absence | **program** — bar MET 2026-09-11: `check:alpha-journey` remote lane **53/53** on `adca48912` with the owner's key (fixture authority): the custody card in Agent Studio, the key sealed with a custody lease, the session bound at the daemon's `/v1`, the daemon's proxy answered by the provider (200, 173 tokens, ≈ $0.00005 at list price — an estimate), the intent's file written from the model's answer, the run-scoped model-mount token issued and revoked, the harness environment secret-free, the plaintext in no file of the state tree, the env-key path refused (ledger XL; evidence `_meta/evidence/m13-9-remote-route-live-2026-09-11.v1.json`) |
| The microVM venue (the existing cloud-hypervisor provider: KVM boundary, no guest NIC, workspace over vsock, pinned toolchain) as a selectable execution venue, with the model endpoint reaching the guest only through a brokered, admitted channel | `M13.10` | the essential journey passes with the venue selected; the harness runs inside the guest; the host checkout is untouched; receipts name the venue; host readiness measured by `scripts/phase1/verify-vm-toolchain.mjs` (PASS on the qualification host 2026-09-10: cloud-hypervisor and firecracker READY, qemu host-gated on vsock permission) | not built |
| The flagship developer journey: issue → reviewed pull request through a governed SCM connector in the session's authority profile — silent draws within a standing envelope, an exact-effect review on the push, receipts on every crossing, revocation ending the authority | `M13.11` | a composed verifier over the estate's own fixture SCM target proves the governed path end to end; a live GitHub run is optional and separately authorized; the unit claims the governed path, never the work's quality | not built |

## Supported deployment bring-up (authority node, keys, daemon, App)

The alpha's authority node is a deployment-local wallet.network node the
operator brings up on the same host, with keys generated there and custodied
there. The supported bring-up is one command per act; nothing here uses the
cargo test fixture or its public seeds.

```text
# 1. Authority node (foreground; run under your supervisor). First run generates
#    keys/root.seed (control root), keys/capability.key (the daemon's sealed
#    wallet client key), keys/approver.seed (YOUR approval key, 0600), starts the
#    Solo single-validator node with durable chain state, issues the control
#    root, registers the client and the approver, binds the approver to the
#    principal (binding v1), and writes daemon.env + serve.env.
node apps/hypervisor/scripts/wallet-network-authority.mjs up \
  --state-dir /var/lib/ioi/authority --principal-ref domain://<your-host>

# 2. Daemon and served App read those env files (the daemon's IOI_WALLET_NETWORK_*
#    endpoint is a loopback TLS front with a per-life pinned CA; the App's
#    IOI_HYPERVISOR_LOCAL_APPROVER_KEY_PATH is your approver key).
set -a; . /var/lib/ioi/authority/daemon.env; set +a; hypervisor-daemon
set -a; . /var/lib/ioi/authority/serve.env;  set +a; node apps/hypervisor/scripts/serve-product-ui.mjs

# 3. Key lifecycle — operator acts against the serving node, each one
#    root-signed control-plane transaction; a resumed node refuses to serve a
#    substituted root or a binding that no longer matches the custodied key.
node apps/hypervisor/scripts/wallet-network-authority.mjs rotate --state-dir /var/lib/ioi/authority   # new key, binding v(n+1) Active; old key retired read-only as keys/approver.seed.v<n>
node apps/hypervisor/scripts/wallet-network-authority.mjs revoke --state-dir /var/lib/ioi/authority   # Revoked successor; every later run fails closed before any harness runs
node apps/hypervisor/scripts/wallet-network-authority.mjs status --state-dir /var/lib/ioi/authority   # custodied record + the live chain head
```

From the packaged release the same commands run from `<install>/current`
(`node <install>/current/apps/hypervisor/scripts/wallet-network-authority.mjs up …`):
the launcher pins the node's validator binaries to `<install>/current/node-bins`
(`IOI_NODE_BINARY_DIR`), needs no cargo and no checkout, and refuses with a
typed `node_binaries_absent` error rather than building if a binary is missing.

Implementation: `crates/cli/src/bin/wallet_network_local_authority.rs` (node,
keys, control-plane transactions, `record-approval`),
`apps/hypervisor/scripts/lib/wallet-network-local-authority.mjs` (lifecycle,
TLS front, env files), `crates/cli/src/testing/build.rs` (`IOI_NODE_BINARY_DIR`).
The daemon's authority resolution, grant verification, consumption and receipt
paths are unchanged; the approver's scope allowlist is exactly
`scope:hypervisor.live-route.*`. Bounded property stated, not hidden: the chain
clock is the deterministic single-node clock unless `--wall-clock` is given.

## Release qualification

The alpha may be called release-qualified only when, on the exact packaged
build, safe qualification records steps 1–13 with the evidence named above,
names the supported and unsupported profiles, records whether any uncertain
external effect needs reconciliation, and never treats a restore as permission
to repeat an effect.

**Ruling (2026-09-08, owner-reversible; supersedes the 2026-09-07 ruling):**
on the release-profile packages named in the program-evidence table, steps
1–13 are recorded 44/44 by `check:alpha-journey` in deployment + package +
no-checkout mode: the installer, launcher, authority node, daemon, served App,
signer and shim under test were the installed bytes, the install prefix was
not a checkout, no child could reach cargo, the update went to a real
successor build and rolled back, both observed by the daemon's own digest. The
supported and unqualified profiles are the tables above; no external effect
outside the host was attempted; the restore leg is the backup verifier's
separate two-daemon proof. The bounded alpha is therefore
**release-qualified**, and the shipped-products register moves the Hypervisor
lane to `production_candidate` (a candidate: the alpha is bounded, not
general availability). Properties stated rather than hidden: the chain clock
of the authority node is deterministic unless `--wall-clock`; the qualification
host was shared with other work (approved run 80 s); the signer key in
qualification was generated for the run — a real release pins the release
signer's public key on every installing host.

**Re-derivation (2026-09-10, owner-reversible; the 2026-09-08 ruling stands and
is re-anchored):** thirteen daemon/App commits landed after `5c5340ea6`, so the
qualified bytes were no longer the tree. On `8281d915e` (clean) the essential
journey is **38/38 in deployment mode from source** and **46/46 in deployment +
package + no-checkout mode** on debug-profile packages built from that tree (v1
`0.1.0-alpha.8`, v2 `0.1.0-alpha.9`, both grant signers shipped); the seven
standing gates, the doc gates and `check:shipped-products` are green on
`cc6f73dae`/`8281d915e`. The re-derivation found and fixed one real gap: R-14's
deployment standing mint (landed 2026-09-09, after the 44/44 ruling) could not
run on a no-checkout host because the package omitted the standing signer and
its script fell back to `cargo build` (R-23, fixed `8281d915e`; the first
package-mode run on `cc6f73dae` failed step 5c and its run took the approval
lane, 46/47 — recorded, not repaired away). One source-mode run on `cc6f73dae`
failed 6-work at host load ≈10 immediately after two daemon builds (35/38); the
same commit ran the identical silent lane to done in 70 s in fixture mode, and
the deployment re-run on a quiet host is the 38/38 above. **After the re-derivation (2026-09-10, leg 1 of the correctness program before
the review; ADR 0052 § 8):** the four connector authority routes changed — a
registration binds its principal and is never overwritten, and register, bind,
revoke and invoke refuse an unresolved caller with one typed 401 — so the tree
is again newer than the qualified bytes. The fixture-mode journey is re-proven
33/33 on that tree (row below); deployment mode and package mode were not
re-run before the review window, so the 38/38 and 46/46 above stand for
`8281d915e` only, never for the current tree. **Typed absence, not a
pass:** the *release* cargo profile was not rebuilt on this tree during the
independent review window (host kept quiet); the 2026-09-08 release-profile
evidence stands for `23424ea93`/`5c5340ea6` only. Closure test: package +
no-checkout mode green on release-profile packages built from the tree that
claims it. The posture stays `production_candidate`.

## Nonclaims

- No claim that any provider, harness, model or isolation posture other than
  the selected ones is qualified.
- No claim that host-spawn execution is workload-bound or hostile-guest
  isolation.
- No claim that the authority node is hosted or multi-party: it is one
  deployment-local Solo node whose keys the operator generated and custodies.
  The cargo test fixture (public `07…` seed) is no longer used for
  qualification of steps 2b, 6 and 7; fixture mode remains available to the
  journey for comparison only.
- The alpha's deployment-local operator **can** mint a standing envelope, under
  the recognized `deployment_local_operator` custody tier (ADR 0052 § 7, ruled
  2026-09-09, owner-reversible). The ceremony is the operator's own act with the
  key they custody on the host; the registered `auth-factor-receipt/v2` receipt
  attests that custody — host, key-path hash, mode 0600, the moment of
  acknowledgement — and never a person, and recording is a control-plane act
  signed by the deployment's control root. **No claim of a passkey**: this tier
  is a floor, and a deployment that enrols a passkey keeps the stronger one.
  **No claim on a deterministic clock**: a deployment that mints standing
  envelopes runs its authority node on the wall clock, because an envelope's
  expiry is a real-time promise the daemon checks at every bind and draw.
- No claim of general availability: `production_candidate` names a bounded
  alpha whose every unqualified row in the tables above stays unqualified.
- No claim of an end-to-end standalone product pass; that remains the
  flagship class's `sovereign-local` claim under `execution-horizons.md`.

## Program evidence (2026-09-07)

Recorded by the boundary and bounded-alpha program as it lands. Each row names
the command and the checkout it ran on; an absent row is an absent claim.

| Evidence | Command | Checkout | Result |
| --- | --- | --- | --- |
| Session authority profile at daemon admission (empty default, closed set, direct-daemon refusal with durable receipt, in-profile challenge, deletion fencing, restart survival) | `npm run check:session-authority-profile --workspace=@ioi/hypervisor-app` | `3bec178d1` (daemon built from it) | 21/21 |
| Session plane identity gate, owned verbs, receipts, restart survival, typed 410 | `npm run check:session-authority --workspace=@ioi/hypervisor-app` | `3bec178d1` | 24/24 |
| Launch chain admission → launch → stop/archive → daemon kill/restart recovery | `npm run check:launch-chain --workspace=@ioi/hypervisor-app` | `3bec178d1` | 58/58 |
| Canonical routes serve their lanes; landings carry no implementation narrative; developer route ledger | `npm run test:hypervisor-route-shell` | `3bec178d1` | 17/17 |
| Route-fault isolation, dead-daemon posture, no-undef over the serve runtime set and augmentation bundle | `npm run check:app-runtime-safety --workspace=@ioi/hypervisor-app` (against a serve on an ephemeral port) | `3bec178d1` | 32/32 |
| Shell parity freeze | `npm run check:shell-parity --workspace=@ioi/hypervisor-app` | `3bec178d1` | 6/6 |
| Landing-designation exit gate | `node apps/hypervisor/scripts/check-landing-designations.mjs --exit-gate` | `3bec178d1` | 10/10 |
| Browser smoke of all 65 owned-served routes (light context) | `IOI_PRODUCT_SMOKE_PRODUCT=hypervisor IOI_PRODUCT_SMOKE_MODE=light npm run smoke:product-surfaces` | `3bec178d1` | 65 route renders passed |
| Architecture docs and contract projections | `npm run check:architecture-docs` · `npm run check:architecture-contracts` | `60ca5f95b` | green (181 files, 11 rules) |
| **The essential journey WITHOUT a deployment authority node** (`IOI_ALPHA_JOURNEY_AUTHORITY=none`): first-run bootstrap through the served form (operator-named identity, one-shot token, sign-in again), readiness, project, harness/model/connections selection, closed profile bound at create + UI-bypass refusal, composer run fails CLOSED with the daemon's typed not-configured code (no execute receipt, nothing ran), stop/teardown, connection revocation fence, daemon kill + serve restart recovery, diagnostics, App/headless agreement; update/rollback recorded as a typed absence | `IOI_ALPHA_JOURNEY_AUTHORITY=none npm run check:alpha-journey --workspace=@ioi/hypervisor-app` — evidence [`m13-alpha-journey-no-authority-2026-09-07.v1.json`](../../_meta/evidence/m13-alpha-journey-no-authority-2026-09-07.v1.json) | `dc19e811e` + the run-lane fail-closed fix (daemon binary from `3bec178d1`) | 23/24 — the one red is the backup sub-verifier's pre-existing census-coverage drift (its 75 functional backup/restore assertions pass; the census omits the newer media-snapshot and skill-set-snapshot routes) |
| **The essential journey WITH the deployment authority node** (`check:alpha-journey`, fixture mode): six attempts on 2026-09-07 — one reached the journey and failed at the first step on the serve header defect fixed in `dc19e811e`; one was blocked by the runner's own mirror-port collision (fixed in the same commit); four were BLOCKED by the wallet.network test fixture (readiness or setup-transaction commit timeouts on a host loaded by other work). Steps 6–7 were **not qualified** by that program | `IOI_WALLET_FIXTURE_READY_TIMEOUT_MS=3600000 npm run check:alpha-journey --workspace=@ioi/hypervisor-app` | `dc19e811e`+ | blocked (historical; both root causes found and fixed by the closure program below) |
| **Closure program (2026-09-07), root cause 1 — the fixture blocks:** the fixture's DEFAULT ordering profile is the four-validator AFT (ML-DSA classic-BFT) cluster of debug binaries; its setup transactions needed BFT commits across four starved validators. The alpha names ONE node, so the journey now starts the fixture in the Solo single-validator profile (`IOI_M049_ORDERING_PROFILE=Solo`). Fixture mode then converged (readiness 416 s incl. a one-time node build) and reached the operator's approval for the first time | `npm run check:alpha-journey --workspace=@ioi/hypervisor-app` (fixture mode) | `11676cfcf` + the Solo change (daemon `3bec178d1`) | 25/29 — the reds were root cause 2 |
| **Root cause 2 — the approved grant was refused by the chain:** the local approver minted the grant with no `audience`, and wallet.network consumes only when the audience is the consuming signer (the daemon's capability account); then, with the audience, the daemon's preflight found *no state for the exact approval grant* — the approval decision must be RECORDED on the node before consumption. Fixed: the challenge carries `approval.audience` + `approval.target_scope`; the approval act mints one one-use grant and records it (`record-approval`, or the fixture's command directory) before resuming the execute | direct reproduction against a fresh daemon + the standalone node (record committed at nonce 3, execute proceeded); the deployment-mode journey below | `ced3f1b9c`, `a1bf94cbc` | fixed |
| **Deployment-local authority node bring-up** (generated keys, durable Solo chain, TLS front, env files; rotate → revoke → stop → resume → rotate) | `node apps/hypervisor/scripts/wallet-network-authority.mjs up|rotate|revoke|status` (standalone drill) | `15b19290f` | v1 active → v2 active (old key retired 0400) → v3 revoked → resumed with the revoked head reported → v4 active |
| **Packaged release** (build, verify under the pinned signer, install, activate; the served App boots from the installed tree outside the checkout; archive form 1.56 GB verified from the tarball) | `npm run test:hypervisor-alpha-release` · `node scripts/package-hypervisor-alpha-release.mjs …` · `node <release>/install.mjs verify|install|activate` | `f4e3e9907` | 4/4 · 753 files · verified |
| **THE ESSENTIAL JOURNEY on the PACKAGED RELEASE with the DEPLOYMENT-LOCAL AUTHORITY NODE** (`IOI_ALPHA_JOURNEY_AUTHORITY=deployment IOI_ALPHA_JOURNEY_PACKAGE=1`): signed packages v1/v2 verified + installed, v1 activated; node up with generated keys; first-run identity; readiness; project; closed authority profile + UI-bypass refusal; run parks → approval card on Work / Sessions AND the SPA session pane → operator approval (mint + record) → execute `done`, `ALPHA_JOURNEY.md` written, execute receipt binding the capability lease; rotation → second run approved under the new key executes; revocation → third run fails closed, no receipt; stop/revoke; daemon kill + restart recovery (`done`, 1 receipt); backup/restore 76/76; diagnostics; update plan to v2 → activate → restart → observed completed by the daemon's own digest; rollback plan to v1 → completed; App/headless agree | `IOI_ALPHA_JOURNEY_AUTHORITY=deployment IOI_ALPHA_JOURNEY_PACKAGE=1 IOI_ALPHA_RELEASE_TRUST=… IOI_ALPHA_RELEASE_V1=… IOI_ALPHA_RELEASE_V2=… npm run check:alpha-journey --workspace=@ioi/hypervisor-app` — evidence [`m13-alpha-journey-deployment-package-2026-09-07.v1.json`](../../_meta/evidence/m13-alpha-journey-deployment-package-2026-09-07.v1.json) | tree of `e83e9af93` = `7a23c3ca4` (the same tree re-committed as `a1bf94cbc` + `7a23c3ca4`; 17 dirty paths: this program's final journey/packager/canon edits committed next, and 13 `apps/decentralized-cloud/docs` deletions that were the decentralized-cloud program's own retirement of the face-era docs (`4bae6253b`)); packaged daemon `bf52b030…` (v1) / `2fe951fd…` (v2) | **43/43** |
| Standing gates on the final daemon build | `check:session-authority-profile` · `check:session-authority` · `check:launch-chain` · `check:session-truth-rebind` · `check:backup-restore` | `a1bf94cbc`+ | 21/21 · 24/24 · 58/58 · 11/11 · 76/76 |
| **Relocation drills (2026-09-08):** a pinned empty directory refuses typed (`node_binaries_absent`) with cargo absent; the checkout's debug node binaries launch pinned with no cargo on PATH; a debug package installed under `/tmp` brings its node up from its own `node-bins/` with cargo absent (the packaged `orchestration` is the running process) | `IOI_NODE_BINARY_DIR=… wallet-network-local-authority serve …` · `node <install>/current/apps/hypervisor/scripts/wallet-network-authority.mjs up …` | `23424ea93` | READY / typed refusal as expected |
| **THE ESSENTIAL JOURNEY on the RELEASE-PROFILE PACKAGES WITHOUT A CHECKOUT** (`IOI_ALPHA_JOURNEY_AUTHORITY=deployment IOI_ALPHA_JOURNEY_PACKAGE=1 IOI_ALPHA_JOURNEY_NO_CHECKOUT=1`): v1 `0.1.0-alpha.4` (release profile, daemon 77.7 MB, digest `6eff5798…`, tree of `23424ea93`) and v2 `0.1.0-alpha.5` (digest `241f514d…`, tree of `5c5340ea6` — a real successor) verified under the pinned signer and installed by the package's own installer outside the repository; the closure assertion holds (launcher binary and node binaries under the prefix, prefix not a git checkout, cargo absent from every child PATH, no child PATH entry inside the repository); every other step as in the 2026-09-07 run; update to v2 and rollback to v1 observed by the daemon's own digest | evidence [`m12-alpha-journey-release-no-checkout-2026-09-08.v1.json`](../../_meta/evidence/m12-alpha-journey-release-no-checkout-2026-09-08.v1.json) | `5c5340ea6` (2 dirty paths: the closure-assertion fix committed next, and the private sequencing file) | **44/44** |
| Standing gates on the tree of `5c5340ea6` | `check:session-authority-profile` · `check:session-authority` · `check:launch-chain` · `check:session-truth-rebind` · `test:hypervisor-alpha-release` | `5c5340ea6` | 21/21 · 24/24 · 58/58 · 11/11 · 4/4 |
| `npm run check:shipped-products` is green again: `apps/decentralized-cloud` is dispositioned as a shipped lane at `development_only` (owner may refine) | `npm run check:shipped-products` · `npm run test:shipped-products` | `d9e9da0f5` | 7 lanes · 23/23 |
| **The essential journey on the REMOTE frontier route** (`IOI_ALPHA_MODEL_ROUTE=remote`, fixture mode, `gpt-4o-mini`): sealed credential (custody crossing approved), daemon-proxied provider call receipted, run-scoped model-mount token in the harness, non-possession on the execute receipt, plaintext grep of the state tree, env-key path refused | `IOI_ALPHA_MODEL_ROUTE=remote IOI_ALPHA_PROVIDER_KEY=… npm run check:alpha-journey --workspace=@ioi/hypervisor-app` | `42007f60e` | 42/46 on 2026-09-11 (run 7; the four open clauses are the provider's acceptance and what depends on it: the run completing on the model, its artifacts, the intent's file) — the open clauses are the provider's acceptance and what depends on it: the provider answered 401 (invalid API key) to the operator's sealed key through the daemon's proxy on every run — 1 proxied call, 0 tokens, no cost; the same key probed directly answers 401 'Incorrect API key provided' |
| **Leg 0 of the MVP finish-line program (2026-09-11): the journey on the tree it now is, every supported mode on one commit** — fixture (custody card drill, in-flight reconcile drill), deployment from source, deployment + package, deployment + package + no-checkout; debug-profile packages v1 `0.1.0-alpha.6` / v2 `0.1.0-alpha.7` by the recorded recipe | `npm run check:alpha-journey --workspace=@ioi/hypervisor-app` · `IOI_ALPHA_JOURNEY_AUTHORITY=deployment …` · `… IOI_ALPHA_JOURNEY_PACKAGE=1 …` · `… IOI_ALPHA_JOURNEY_NO_CHECKOUT=1 …` | `fe9f8a770` | fixture 39/39 (2026-09-11, run 3) · deployment 44/44 (2026-09-11, run 2) · package 51/51 (2026-09-11, run 2) · no-checkout 52/52 (2026-09-11, run 3; run 2's one red was the run's own construction — packages built under the repository's .artifacts/, so the package's own installer failed the outside-the-repository clause; the identical packages were moved outside the repository) (evidence `_meta/evidence/l0-mvp-finish-line-2026-09-11.v1.json`, ledger XL) |

## Program evidence (2026-09-10 re-derivation)

Each row names the command and the checkout it ran on; an absent row is an
absent claim. Failures are recorded as they happened.

| Evidence | Command | Checkout | Result |
| --- | --- | --- | --- |
| Standing gates on the current tree | `test:hypervisor-alpha-release` · `check:session-authority-profile` · `check:session-authority` · `check:launch-chain` · `check:session-truth-rebind` · `test:hypervisor-route-shell` · `check:backup-restore` | `cc6f73dae` | 4/4 · 22/22 · 24/24 · 58/58 · 11/11 · 17/17 · 76/76 |
| Doc and contract gates · shipped-products (Hypervisor `production_candidate`, decentralized-cloud `development_only`) | `check:architecture-docs` · `check:architecture-contracts` · `check:shipped-products` | `cc6f73dae` | green (200 files, 11 rules) · up to date · 7 lanes |
| R-19 closed — a headless act no longer skips exact-effect review | `check:standing-consumer-loop` | `cc6f73dae` | 45/45 |
| Essential journey, fixture authority mode (the silent lane on this commit) | `IOI_ALPHA_JOURNEY_AUTHORITY=fixture check:alpha-journey` | `cc6f73dae` (+3 uncommitted R-23 files) | 33/33 · 6-work done in 70 s |
| **Recorded failure** — deployment mode from source at host load ≈10, right after two daemon builds: run registered and the standing draw receipted, but the harness transcript never arrived within 902 s | `IOI_ALPHA_JOURNEY_AUTHORITY=deployment check:alpha-journey` | `cc6f73dae` | 35/38 (6-work ×2, 9-recover cascaded) — environmental; see the 38/38 below |
| **Recorded failure** — package + no-checkout mode: step 5c `standing_lease_request_invalid — Failed to build mint-standing-approval-grant`; the run fell to the approval lane | `IOI_ALPHA_JOURNEY_PACKAGE=1 IOI_ALPHA_JOURNEY_NO_CHECKOUT=1 …` | `cc6f73dae` | 46/47 — **R-23**, fixed `8281d915e` |
| **THE ESSENTIAL JOURNEY WITH THE DEPLOYMENT AUTHORITY NODE**, from source, quiet host (load 4.3) | `IOI_ALPHA_JOURNEY_AUTHORITY=deployment check:alpha-journey` | `8281d915e` (clean) | **38/38** — [`m13-alpha-journey-deployment-standing-2026-09-10.v1.json`](../../_meta/evidence/m13-alpha-journey-deployment-standing-2026-09-10.v1.json) |
| **THE ESSENTIAL JOURNEY ON PACKAGES WITHOUT A CHECKOUT**: v1 `0.1.0-alpha.8` / v2 `0.1.0-alpha.9` (debug profile, both grant signers shipped) verified under the run's signer, installed, v1 activated; 5c MINTED under `deployment_local_operator`; 6-work silent lane; update admitted, daemon observed digest `465fb0dc…` = v2; rollback observed | `IOI_ALPHA_JOURNEY_AUTHORITY=deployment IOI_ALPHA_JOURNEY_PACKAGE=1 IOI_ALPHA_JOURNEY_NO_CHECKOUT=1 check:alpha-journey` | `8281d915e` (clean) | **46/46** — [`m12-alpha-journey-release-no-checkout-2026-09-10.v1.json`](../../_meta/evidence/m12-alpha-journey-release-no-checkout-2026-09-10.v1.json) |
| Connector authority rulings R-20/R-22 (ADR 0052 § 8; the correctness program before the review, leg 1): register resolves and binds its caller and never overwrites, and the four connector authority routes refuse an unresolved caller identically — the essential journey re-run in fixture mode on the tree carrying them; deployment and package modes NOT re-run before the review window | `IOI_ALPHA_JOURNEY_AUTHORITY=fixture check:alpha-journey` | `6bc07025d` + leg 1's files | **33/33** — [`m13-alpha-journey-fixture-connector-authority-2026-09-10.v1.json`](../../_meta/evidence/m13-alpha-journey-fixture-connector-authority-2026-09-10.v1.json) |
| Release cargo profile on this tree | — | — | **not run** (typed absence; review-window quiet host) |

## Related Canon

- [`core-clients-surfaces.md`](./core-clients-surfaces.md) — sessions, clients, zero-to-operable journey.
- [`providers-and-environments.md`](./providers-and-environments.md) — environments, venues, archive/restore.
- [`identity-access-and-metering.md`](./identity-access-and-metering.md) — bootstrap and access contract.
- [`../daemon-runtime/doctrine.md`](../daemon-runtime/doctrine.md) — admission, recovery, effect boundary.
- [`../daemon-runtime/platform-operability.md`](../daemon-runtime/platform-operability.md) — readiness, backup, diagnostics.
- [`../../_meta/execution-horizons.md`](../../_meta/execution-horizons.md) — the flagship proofs this profile is separated from.
- [`../../_meta/shipped-products.v1.json`](../../_meta/shipped-products.v1.json) — release posture register.
