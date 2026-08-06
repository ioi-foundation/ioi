# Operations — implementation brief

Canonical route: `/operations` · Owner: substrate (`substrate_application`, substrate lane — not an owner application, not a core workspace)
Brief status: authored 2026-08-05 from bytes at `21ae389fe` · v0 seed corrected where noted

## 1. Canon digest

- **Class**: Operations is the second of exactly two substrate applications ("type 1 + 2 face") beside the twelve owner applications and distinct from the six core workspaces (`core-clients-surfaces.md:856-859`, `:1756-1765`); registration discriminator `substrate_application` (`:1781-1786`, `:4555-4560`). Canonical route `/operations` (`:905`); no aliases (`:874-880`).
- **Remit (one line)**: "infrastructure: scheduler health, providers, placement/failover, storage custody, capacity, provider spend" (`core-clients-surfaces.md:858-859`).
- **Local ownership**: queued/running/failed/retried *infrastructure* jobs; provider, placement, capacity, custody, member readiness, catch-up, verified roots, leases, writer epochs, fencing, RPO/RTO, degraded/partition posture, and admitted add/drain/promote/remove operations (`core-clients-surfaces.md:1197-1201`). The **Operations resource facet** owns queues, quotas, rate limits, capacity, utilization, spend, and budgets (`:1203-1204`; restated by the Change Plane at `providers-and-environments.md:2133-2134`).
- **Operator grammar** it must answer: "what is healthy, saturated, blocked, failed, queued, degraded, over budget, migrating, falling back, or awaiting remediation?" (`core-clients-surfaces.md:285-287`); Operations rows in the operator-expectation table: substrate overview, inventory tables, infrastructure tasks/events/logs/alerts, RBAC/policy/audit/lifecycle (`:299-306`) — visible controls must still feel like infrastructure control (`:308-313`).
- **Action boundary**: Systems may compare desired and observed topology, but *Operations performs admitted provider, placement, fencing, failover, and member actions*; Governance authorizes protected transitions; daemon/domain contracts execute; Agentgres records admitted truth (`core-clients-surfaces.md:1655-1657`). Remediation split: human approval/policy review = Governance, logical remediation/incidents = Work, infrastructure remediation/support = Operations (`:1231-1233`).
- **Capacity doctrine**: capacity shock and budget exhaustion are Operations resource/scheduler problems; compute seconds/tokens/GPU occupancy/queue depth are internal signals, never the product goal (`providers-and-environments.md:1940-1946`). Operations owns cross-workload posture for capacity pools, resource queues, rate limits, provider quotas, spend ceilings, budget burn, scarcity windows, priority classes, preemption decisions, degradation policies, catch-up policies, verified-work efficiency (`:1948-1963`). Objects: `HypervisorResourcePool` / `ResourceBudget` / `ResourceAllocationRequest` / `ResourceAllocationDecision` / `SchedulerCatchupPolicy` (`:1965-2093`). Budget exhaustion is discovered before provider mutation; preemption/cancellation are receipted with visible reasons; invisible starvation is not a canonical state (`:2095-2104`). Raw usage is not success — analytics must relate usage to verified accepted work (`:2106-2109`).
- **Provider/custody split ruling**: "Environments shows the account catalog with credential/preflight/spend posture; Operations shows provider health and the recent receipt trail — both stating customer-borne spend plainly" (`byo-provider-plane.md:322-327`). BYO spend is customer-borne; the daemon records/governs/estimates/reconciles, never hidden markup (`byo-provider-plane.md:23-31`).
- **Storage custody**: decentralized storage (Filecoin/CAS/IPFS) is the archive-and-custody lane, not compute; backends hold encrypted bytes by content address while daemon/Agentgres state remains restore truth (`byo-provider-plane.md:221`, `providers-and-environments.md:207-216`).
- **Failover/membership boundary**: environment recovery ≠ logical-system failover; writer promotion requires catch-up/root evidence, a higher epoch, and old-writer fencing (INV-22..24); provider auto-scaling creates candidates, only declared membership policy admits them (`providers-and-environments.md:1905-1938`).
- **Change plane**: Governance owns the release/change cockpit; the Operations resource facet feeds gates and blocked reasons but never becomes rollout truth (`providers-and-environments.md:2111-2161`; `core-clients-surfaces.md:1162-1179`). Lifecycle strips on capability pages deep-link back to Governance, Operations, or Provenance (`core-clients-surfaces.md:1170-1173`).
- **Learning boundary facet**: Operations shows actual placement, keys, custody, egress enforcement, and proof posture (`core-clients-surfaces.md:1091-1092`).
- **Embodied Systems**: nothing of its registration rehomes here — the daemon taxonomy already carries its own `planned`/`propose_only` row beside the two `substrate_application` rows for Environments and Operations (`hypervisor_core_taxonomy.json` served at `GET /v1/hypervisor/core-taxonomy`, `hypervisor-daemon.rs:1055-1058`; canon `core-clients-surfaces.md:906`, `:921-933`).

## 2. Schema map

Registry = `docs/architecture/_meta/schemas/architecture-contract-registry.v1.json`. Daemon-minted `schema_version` strings without registry JSON Schemas are marked *(daemon-literal)*.

| Canon object / contract | Registry entry or canon block | Daemon route(s) today |
| --- | --- | --- |
| Execution-health projection (scheduler + runs + webhooks — automation substrate only) | daemon-local | `GET /v1/hypervisor/operations` (`hypervisor-daemon.rs:1313-1316`; builder `orchestration_routes.rs:403-460`) |
| Scheduler read surface | W0.6 target | **route-missing — W0.6/W3**: the scheduler is an in-process background task (`hypervisor-daemon.rs:3481-3483`, `:4430`); no `/v1/hypervisor/scheduler/status`; the only scheduler read is folded into `/operations` |
| Unified infrastructure-jobs projection (automation + harness + coordination + failover + storage/provider ops) | canon `core-clients-surfaces.md:1197-1199` | **route-missing — W3**: today the jobs queue is composed client-side from 4 planes (`serve-product-ui.mjs:1780-1800`) |
| Proof stream feeding jobs/analytics | daemon-local | `GET /v1/hypervisor/work-ledger` (`hypervisor-daemon.rs:1308-1311`) |
| Environment failure incidents / recovery attempts | canon `providers-and-environments.md:1787-1879` | `GET /v1/hypervisor/incidents`, `GET /v1/hypervisor/recovery-attempts` (`hypervisor-daemon.rs:1194-1201`) |
| Operability metrics / incident reconstruction / guardrails | daemon-local | `GET /v1/hypervisor/operability/metrics`, `GET /v1/hypervisor/operability/incidents/:id`, `GET/POST /v1/hypervisor/guardrails` (`hypervisor-daemon.rs:2683-2699`) |
| `HypervisorResourcePool` / `ResourceBudget` / allocation decisions / work queue / catch-up / receipts | canon `providers-and-environments.md:1965-2093` *(no registry schemas)* | `GET/POST /v1/hypervisor/resource/pools`, `GET/POST …/budgets`, `POST …/allocate`, `POST …/release`, `GET …/work-queue`, `POST …/catchup`, `GET …/receipts` (`hypervisor-daemon.rs:2758-2785`) |
| Provider catalog + health | `byo-provider-plane.md:249-251` | `GET /v1/hypervisor/providers` (`hypervisor-daemon.rs:2789-2792`) |
| Provider crossing receipts (success AND failure) + admitted ops | `ioi.hypervisor.provider-receipt.v1` / `provider-operation.v1` *(daemon-literal; `byo-provider-plane.md:273-280`)* | `GET /v1/hypervisor/provider-receipts` (`:2821-2824`), `GET /v1/hypervisor/provider-operations` (`:2833-2836`), `GET /v1/hypervisor/provider-materials` (`:2817-2820`) |
| Provider spend exposures `pse_*` + reconciliation | `ioi.hypervisor.provider-spend-exposure.v1` *(daemon-literal; `provider_routes.rs:6175-6179`)* | `GET /v1/hypervisor/provider-spend/reconciliation` (`hypervisor-daemon.rs:2829-2832`) |
| Storage backends (`local_disk·cas·ipfs·filecoin`) + sealed credential + preflight | `ioi.hypervisor.storage-backend-account.v1` *(daemon-literal; kinds `storage_backend_routes.rs:36`)* | `GET/POST /v1/hypervisor/storage-backends`, `PATCH/DELETE …/:id`, `POST …/:id/credential`, `POST …/:id/preflight` (`hypervisor-daemon.rs:2844-2861`) |
| Archive ops export/verify/restore/repair (sealed-before-write; wallet-gated crossing) | `storage-archive-object.v1.schema.json`, `storage-backend-write-admission.v1.schema.json` (registry) | `POST /v1/hypervisor/storage-archive-ops` (`hypervisor-daemon.rs:2862-2865`; op dispatch `storage_backend_routes.rs:745-749`; lease crossing `:759`) |
| Archive inventory / incidents / repair receipts | `storage-artifact-availability-incident.v1.schema.json`, `artifact-repair-receipt.v1.schema.json` (registry) | `GET /v1/hypervisor/storage-archives`, `GET /v1/hypervisor/storage-incidents`, `GET /v1/hypervisor/storage-receipts` (`hypervisor-daemon.rs:2866-2877`) |
| DePIN (Akash) deployments/bids/leases/redeploy posture | daemon records | `GET /v1/hypervisor/akash-deployments` (`hypervisor-daemon.rs:2837-2841`) |
| Failover plans `fpl_*` / runs `for_*` / arm/disarm/evaluate | `ioi.hypervisor.failover-plan.v1` / `failover-event.v1` *(daemon-literal; `placement_failover_routes.rs:420-462`, `:586`)* | `GET/POST /v1/hypervisor/failover/plans`, `POST …/run`, `GET …/runs(:id)`, `POST …/plans/:id/arm|disarm`, `POST …/evaluate` (`hypervisor-daemon.rs:2620-2648`) — shared family with Environments; Operations renders health/runs, Environments renders per-env readiness |
| Warm pools (pre-started capacity) | daemon records | `GET/POST /v1/hypervisor/warm-pools`, `POST …/:id/claim` (`hypervisor-daemon.rs:2673-2681`) |
| Autonomous-system posture reads (member readiness, catch-up, verified roots, writer epochs, fencing) | genesis/membership/writer schema families in registry (`autonomous-system-*.schema.json`) | `GET /v1/hypervisor/autonomous-systems(+/projection,:id)` (`hypervisor-daemon.rs:2172-2183`), `GET …/:id/membership/projection` (`:2266-2269`), `GET …/:id/topology/minimum` (`:2270-2273`), `GET …/:id/writer/epoch` (`:2289-2292`), `GET …/:id/writer/lost-suffixes` (`:2300-2303`) |
| Admitted add/drain/promote/remove + writer transitions (Operations performs; Governance authorizes) | `autonomous-system-membership-transition.v1` / `writer-epoch-transition.v1` (registry) | `POST /v1/hypervisor/autonomous-systems/:id/membership/:op` (`hypervisor-daemon.rs:2281-2288`), `POST …/writer/transitions/:kind` (`:2311-2318`), continuity `POST …/continuity/:op` (`:2220-2227`) |
| Substrate status | daemon-local | `GET /v1/hypervisor/substrate/status` (`hypervisor-daemon.rs:2825-2828`) |
| RPO/RTO + degraded/partition posture rollup | canon `core-clients-surfaces.md:1199-1201` | **route-missing — W3** (composable today only from membership/writer/failover reads; no rollup projection) |
| Capacity/utilization overview (pools × committed × available × health) | canon `providers-and-environments.md:1965-1988` | partial: pool records carry `capacity_limit/committed_usage/available_usage/health_posture`; no cross-pool utilization overview route — fold into the W3 jobs/capacity projection |

## 3. UI seed map

- **T2 native readout `/__ioi/operations`** — wired, read-first, already a jobs/custody cockpit (`serve-product-ui.mjs:8802-8819`, render `:1704-2030`). It composes twelve planes in one bounded-read pass: operations, auth-policy, providers, provider-receipts, spend-reconciliation, storage-backends, storage-incidents, akash-deployments, failover-runs, failover-plans, goal-runs, work-ledger (`:8803-8816`). Panes:
  - per-plane availability banner — unavailable planes render "unknown, not zero" (`:1720-1723`);
  - scheduler health table (state/schedule/next/last/concurrency/failure-policy) (`:1764-1773`);
  - **Jobs** — one merged queue over automation runs, harness executions, IOI-Agent coordination runs, and failover recovery runs, per-kind capped, type chips, wallet-gate chips for `awaiting_authority_*` rows, per-row proof (timeline or state root) (`:1774-1845`);
  - operate console: run rows select into a drawer joining run ↔ scheduler record with remediation forms that POST to the *Automations-owned* lanes `/__ioi/automations/:id/run|pause|resume` (`:1846-1995`) — Operations holds no authority of its own here;
  - run health, needs-attention failures, webhook health (`:1856-1878`);
  - provider health + customer-borne spend statement + recent provider receipts (`:1879-1896`);
  - spend reconciliation: headroom / reserved-open-estimates / actual spent / open exposures / finalized / incomplete-teardown warnings (`:1897-1921`);
  - storage backend health + open incidents + repair receipts, custody rule stated in-surface (`:1922-1935`);
  - DePIN (Akash) deployments/leases/redeploy plans (`:1936-1951`);
  - cross-provider failover runs + auto-trigger posture (armed/triggered; "never automatic authority") (`:1952-1968`);
  - Work Analytics facet: run funnel + failure rate, ledger-kind histogram, improvement handoff into the real proposal lane (`:1996-2012`).
  Census: 200, 40 controls, 0 disabled (`census: tier_t2_native_readouts.nat-operations`); the only mutation controls are the three Automations-delegating remediation forms.
- **Cross-surface consumers**: the incidents port readout reads the operations plane (`serve-product-ui.mjs:8795-8800`); work-ledger drawer links provider crossings and storage custody rows to `/__ioi/operations` (`:1679-1680`); failover-run refs resolve to the Operations readout (`:5845`, `:8640`).
- **T3 registered surfaces** — none owned by Operations (`scripts/surface-registry.mjs:50-63`; the `incidents` slug is Missions/Work-lineage, and canon routes legacy Issues to `Work / Incidents`, `core-clients-surfaces.md:1421-1426`).
- **Catalog seed** — native Applications tile "Operations — Infrastructure — scheduler health, providers, placement/failover, storage custody, capacity, spend." → `/__ioi/operations` (`serve-product-ui.mjs:1472`).
- **Canonical route `/operations`** — resolves nowhere (census: `canonical_target_routes` row `{"route":"/operations","resolves":false}`; no hit in `apps/hypervisor/src`). The daemon taxonomy registration row exists (§1 last bullet).

### Corrections vs v0

- v0 said: "operations reads … exist" — bytes show the singular `GET /v1/hypervisor/operations` is **automation-execution health only** (scheduler + run + webhook over the automations substrate — `orchestration_routes.rs:403-460`; the daemon's own comment says so, `hypervisor-daemon.rs:1312`). The cockpit's provider/custody/spend/failover posture comes from ~10 sibling read families composed client-side; there is no unified infrastructure-jobs, capacity, or RPO/RTO rollup route (W3 rows in §2).
- v0 omitted the **resource-management plane** — pools/budgets/allocate/release/work-queue/catchup/receipts all exist (`hypervisor-daemon.rs:2758-2785`) and are canon's "Operations resource facet" (`core-clients-surfaces.md:1203-1204`); they belong in this cockpit and are rendered nowhere today.
- v0 said: "build the jobs/capacity/custody cockpit read-first" — bytes show the jobs+custody cockpit **already exists read-first** at `/__ioi/operations`, including the merged 4-kind jobs queue and a remediation drawer that correctly delegates authority to Automations lanes (`serve-product-ui.mjs:1774-1995`); the genuinely missing panes are capacity/resource posture and autonomous-system membership/writer posture. The W1 job is a rehome plus two new read panes, not a build.
- Census listed 14 registered T3 surface directories — the live tree has 6 module dirs (`apps/hypervisor/surfaces/`), all 14 entries still registered in `scripts/surface-registry.mjs:50-63`; no Operations impact, recorded as census drift.
- v0 W0.6 still holds at the bytes: no scheduler read surface exists (`grep scheduler hypervisor-daemon.rs` → background task only, `:3481-3483`, `:4430`).

#### Addendum 2026-08-06 (mesh packet 4 — cite refresh at `ba9e2ea0a`)

Two corrections; canon and daemon cites otherwise resolve.

| §3 said | Bytes at `ba9e2ea0a` |
|---|---|
| readout handler `serve-product-ui.mjs:8802-8819`, twelve reads at `:8803-8816` | handler at **`:8838`**; the twelve reads compose at **`:8838-8857`** (the numbers slid when W0.6 landed adjacent handlers) |
| "no scheduler read surface exists" (last Corrections bullet) | **superseded — W0.6 landed it.** `GET /v1/hypervisor/scheduler/status` is registered at `hypervisor-daemon.rs:1323` (handler `orchestration_routes::handle_scheduler_status`, documented `:4473`). The §2 W0.6 row is satisfied; the cockpit does not read it yet, so the *pane* is still W1 work |

The twelve composed reads re-verified at `:8838-8857`:

```text
operations · auth/policy · providers · provider-receipts
provider-spend/reconciliation · storage-backends · storage-incidents
akash-deployments · failover/runs · failover/plans · goal-runs · work-ledger
```

Census re-read: `nat-operations` = **40 controls, 0 disabled, HTTP 200** (§3 reads
the HTTP status and the count as one figure; they are separate).

## 4. Schema→UI binding table

Reads ride the W0.3 read-projection client; authority actions ride the W0.3 authority client (403 wallet challenge → 428 credential → receipted). Jobs rows carry `session_ref`/GoalRun refs from the ledger and goal-run planes — display-only today; the W3 unified jobs projection MUST name work subjects via `subject_attachments[]` reads (owner-registered `subject_kind`+`subject_ref`), never named app-family fields (`core-clients-surfaces.md:2683-2687`, `:3971-3990`).

| UI element (pane/control) | Backing schema + route | Current state | Target state |
| --- | --- | --- | --- |
| Per-plane availability banner ("unknown, not zero") | bounded multi-plane read (`serve-product-ui.mjs:8803-8816`) | wired | keep — `wired-read` idiom for every pane |
| Scheduler health table | `/operations`.scheduler (`hypervisor-daemon.rs:1313`) | wired-read | `wired-read`; repoint to the W0.6 scheduler read surface when it lands |
| Jobs queue (automation·harness·ioi-agent·failover, wallet-gate chips, proof column) | `/operations`.runs + `/work-ledger` + goal-runs + `/failover/runs` | wired-read (client-side compose) | `wired-read`; W3: replace compose with the unified infra-jobs projection binding subjects via `subject_attachments` |
| Operate-console remediation (re-run / pause / resume) | Automations routes `POST /v1/hypervisor/automations/:id/start|runs` + patch (`hypervisor-daemon.rs:1267-1287`) | wired-action (delegating via serve forms) | `wired-action-receipted` through the authority client, still Automations-owned lanes — Operations never mints its own automation authority |
| Run health / needs-attention / webhook health | `/operations` projection | wired-read | `wired-read` |
| Provider health table + spend rule statement | `/providers` (`:2789`) | wired-read | `wired-read` |
| Recent provider receipts trail (success and refusal crossings) | `/provider-receipts` (`:2821`); `/provider-operations` (`:2833`) | receipts wired-read; operations list unrendered | `wired-read` both |
| Spend reconciliation (headroom, reserved, spent, open `pse_*`, incomplete teardowns) | `/provider-spend/reconciliation` (`:2829`) | wired-read | `wired-read` |
| Storage backend health + custody rule + open incidents + repair receipts | storage reads (`:2844-2877`) | wired-read | `wired-read` |
| Storage backend registration / credential / preflight | storage-backends POST/PATCH/DELETE + `/credential` + `/preflight` (`:2844-2861`) | daemon-only (verifier-driven) | `wired-action-receipted` (sealed credential crossing) |
| Archive ops export / verify / restore / repair | `/storage-archive-ops` (`:2862`; wallet crossing `storage_backend_routes.rs:759`) | daemon-only | `wired-action-receipted`; restore refusal states rendered (restore truth = admitted state roots only) |
| DePIN posture (deployments, leases, redeploy plans) | `/akash-deployments` (`:2837`) | wired-read | `wired-read` |
| Failover runs + auto-trigger posture | `/failover/runs`, `/failover/plans` (`:2620-2648`) | wired-read | `wired-read`; run/arm/disarm = `wired-action-receipted` here (canon: Operations performs admitted failover actions, `core-clients-surfaces.md:1655-1657`; runs park at `awaiting_authority_*`) |
| Resource facet panes: pools, budgets, allocation work-queue, decisions + receipts | resource routes (`:2758-2785`) | routes exist, unrendered | `wired-read` (pools/budgets/queue/receipts); allocate/release/catchup = `wired-action-receipted` with typed decision + visible reason per canon (`providers-and-environments.md:2042-2104`) |
| Warm-pool capacity pane | `/warm-pools` (`:2673`) | unrendered | `wired-read`; create/claim = `wired-action-receipted` |
| Autonomous-system posture pane (membership readiness, topology minimum, writer epoch, lost suffixes) | autonomous-systems reads (`:2172-2183`, `:2266-2273`, `:2289-2303`) | unrendered | `wired-read` |
| Admitted add / drain / promote / remove; writer transitions; continuity ops | membership/writer/continuity `POST` routes (`:2281-2318`, `:2220-2227`) | daemon-only (governed proposal/decision shape) | `wired-action-receipted` via authority client; Governance gates the protected transition — Operations renders proposal state, never bypasses (`core-clients-surfaces.md:1655-1657`) |
| Environment failure incidents + recovery attempts (infra lane) | `/incidents`, `/recovery-attempts` (`:1194-1201`) | rendered on incidents-port readout, not here | `wired-read` pane with deep link to the Environments recover flow |
| Incident reconstruction + operability metrics | `/operability/incidents/:id`, `/operability/metrics` (`:2693-2699`) | unrendered | `wired-read` |
| Guardrails get/set | `/guardrails` (`:2683-2687`) | daemon-only | read `wired-read`; set = `wired-action-receipted` or `disabled-named-gap` if no lease admission exists at PR time |
| Substrate status chip | `/substrate/status` (`:2825`) | unrendered | `wired-read` |
| Work Analytics facet (funnel, ledger kinds, improvement handoff) | `/operations` + `/work-ledger` | wired-read | `wired-read`; keep the verified-work framing (`providers-and-environments.md:2106-2109`) |
| RPO/RTO + degraded/partition rollup | none | absent | `disabled-named-gap` → W3 rollup row in §2 |
| Capacity/utilization overview | pool fields only | absent | `disabled-named-gap` → W3 (fold into unified projection) |
| Auth-policy plane read (`/v1/hypervisor/auth/policy`) | daemon read (`serve-product-ui.mjs:8805`) | wired-read | `wired-read` (posture display only) |

## 5. Ordered PR list

1. **W0** — v2 shell route `/operations` renders the rehomed readout body; legacy `/__ioi/operations` keeps serving until cutover (W0.1).
2. **W0.6** — scheduler read surface (`GET /v1/hypervisor/scheduler/status`) — small backend route, serialize on the central router file.
3. **W1** — Rehome the twelve-plane cockpit reads through the W0.3 read client, preserving the per-plane "unknown, not zero" idiom.
4. **W1** — New read panes over existing routes: resource facet (pools/budgets/work-queue/decision receipts), warm pools, autonomous-system posture (membership projection, topology minimum, writer epoch, lost suffixes), incidents/recovery-attempts, provider-operations, operability metrics + incident reconstruction, substrate status.
5. **W1** — Event freshness: new pane updates ride the M5 plane (`/v1/event-streams*` + `/v1/subscriptions*`, `hypervisor-daemon.rs:2350-2379`); no new per-resource SSE.
6. **W2** — Remediation actions through the authority client: Automations-delegating re-run/pause/resume; failover run/arm/disarm; storage backend registration/credential/preflight; archive export/verify/restore/repair; resource allocate/release/catchup; warm-pool create/claim; guardrails set.
7. **W2** — Membership/writer/continuity operations pane: proposal → Governance-gated decision → receipted execution, rendered as the governed two-step it is.
8. **W3** — Backend builds + UI same wave: unified infrastructure-jobs projection (subjects via `subject_attachments`), capacity/utilization overview, RPO/RTO + degraded/partition rollup (§2 route-missing rows).
9. **W4** — Cutover: `/__ioi/operations` retired with typed 410 per the 6-step rule; catalog tile (`serve-product-ui.mjs:1472`) repointed by the compiler projection; incidents-port and work-ledger cross-links repointed to `/operations`.

### Git/Agentgres transition-chain interfaces (epic)

From the 2026-08-05 audit ([epic §2](../scm-transition-chain-epic.md)):
Operations gains the ingestion-health plane: signature failures, ingest lag,
duplicates/out-of-order, Agentgres conflicts, dead letters,
backfill/reconciliation, provider outages, and checkpoint health; it owns
the health half of the reconciliation contracts (epic §3 C7 — Governance
owns the approval half). Lands P2/P3, riding this brief's existing
unified-jobs and rollup projections.

## 6. Seed mesh ledger (2026-08-06)

Canon cites without a file prefix are `core-clients-surfaces.md`; serve cites are
`apps/hypervisor/scripts/serve-product-ui.mjs`.

**Tier 3: none** owned by Operations (the `incidents` slug is Work-lineage, and
canon routes legacy Issues to `Work / Incidents`, :1421-1426) → **0 of the 563
baseline controls**. **Tier 4: none.** Both honest absences.

| Seed element (tier + path) | Census/control facts | Canon end state (cite) | Disposition | Wave |
|---|---|---|---|---|
| **T2 operations cockpit** — `/__ioi/operations` (serve `:8838`, renderer `:1704-2030`), twelve composed reads (`:8838-8857`) | T2 census `nat-operations`: **40 controls, 0 disabled**, HTTP 200. **Only three are mutation controls** — the Automations-delegating remediation forms | Operations is the substrate/infrastructure cockpit (§1) | **rehome** — the cockpit exists read-first; W1 is a rehome plus two new read panes, not a build | W1 |
| ↳ per-plane availability banner (`:1720-1723`) | part of the 40 | honest degradation | **rehome** — and the rule it encodes ("unavailable planes render **unknown, not zero**") is the single most valuable behavior on this surface; it must survive the rehome verbatim | W1 |
| ↳ scheduler health table (`:1764-1773`) | part of the 40 | scheduler posture read | **rehome** — and now **rebind** to `GET /v1/hypervisor/scheduler/status` (`hypervisor-daemon.rs:1323`), which W0.6 landed after this brief was written; the table currently derives posture from the operations aggregate instead | W1 |
| ↳ **Jobs** merged queue — automation runs + harness executions + IOI-Agent coordination runs + failover recovery runs, per-kind capped, type chips, wallet-gate chips for `awaiting_authority_*`, per-row proof (`:1774-1845`) | part of the 40 | unified infrastructure-jobs projection — **route-missing, W3** (§2); subjects bind via `subject_attachments` | **rehome** — the client-side merge is the pane until the projection route lands; the wallet-gate chips are honest authority state, not decoration | W1 · W3 |
| ↳ operate console + remediation drawer → POSTs to `/__ioi/automations/:id/{run,pause,resume}` (`:1846-1995`) | the 3 mutation controls of the 40 | Operations holds **no authority of its own**; remediation is Automations-owned | **rehome** — preserving the delegation exactly; a rehome that quietly moved these verbs under Operations would mint authority canon does not grant | W1 · W2 |
| ↳ run health · needs-attention failures · webhook health (`:1856-1878`) | part of the 40 | run health read | **rehome** | W1 |
| ↳ provider health + customer-borne spend statement + recent receipts (`:1879-1896`) | part of the 40 | provider posture; spend is never faked | **rehome** | W1 |
| ↳ spend reconciliation — headroom / reserved-open-estimates / actual / open exposures / finalized / incomplete-teardown warnings (`:1897-1921`) | part of the 40 | reserved estimates are never presented as spend | **rehome** | W1 |
| ↳ storage backend health + open incidents + repair receipts, custody rule stated in-surface (`:1922-1935`) | part of the 40 | custody **health** is Operations'; the per-env archive rows are Environments' (split ruling, `environments.md` §6) | **rehome** | W1 |
| ↳ DePIN (Akash) deployments / leases / redeploy plans (`:1936-1951`) | part of the 40 | provider substrate | **rehome** | W1 |
| ↳ cross-provider failover runs + auto-trigger posture ("never automatic authority") (`:1952-1968`) | part of the 40 | armed/triggered posture, authority never automatic | **rehome** — the "never automatic authority" statement is contract, not copy | W1 |
| ↳ Work Analytics facet — run funnel, failure rate, ledger-kind histogram, improvement handoff into the real proposal lane (`:1996-2012`) | part of the 40 | analytics is a facet, not a surface; Improvement owns proposals | **rehome** — the handoff must keep landing in the real proposal lane, never a local form | W1 |
| **T5 `/__apps/scheduler`** — harvest capture; inventory owner is **"Automations"** with `ownerUrl: /__ioi/operations` (`harvest-seed-inventory.mjs:33`); class `reference_capture`, capture state `shell_only`, grammar `table_list`, tier aux, `reboundLane: null`, note "schedule table; unbound" | not in the 563 | the scheduler **health table** is an Operations pane; the scheduler **object** (schedules, triggers, concurrency, failure policy) is Automations-owned | **pattern-harvest** — table grammar only, meshed here because its `ownerUrl` points at this surface. The owner-name/ownerUrl split is recorded, not resolved: canon gives the object to Automations and the health readout to Operations, so both are correct and neither is a defect | — |
| **Cross-surface consumers** — incidents readout reads the operations plane (serve `:8795-8800`); work-ledger drawer links provider-crossing and storage-custody rows here (`:1679-1680`); failover-run refs resolve here (`:5845`, `:8640`) | not census controls | deep links per kind | **rehome** — the link targets move to `/operations` with the surface; the linking surfaces are unaffected | W1 · W4 |
| **Catalog tile** — Applications tile "Operations — Infrastructure…" → `/__ioi/operations` (serve `:1472`) | not census controls | canonical route `/operations` (census: `resolves: false`) | **retire-at-cutover** — repointed by the compiler projection | W4 |

**Census reconciliation.** Operations holds **0 of the 563** T3 baseline controls
(no registered surface). Its T2 readout carries **40 controls, 0 disabled**, outside
that baseline. Only three of the forty cross authority, and all three delegate to
Automations — so Operations' own governed-control count is **zero by design**, which
is the correct reading of its canon role (it observes substrate; it does not command
it).

**Disposition summary.** 12 rehome (one of which also **rebinds** to the new
scheduler-status route) · 1 pattern-harvest · 1 retire-at-cutover · 0 blocked.

## 7. Ontology wiring

**None — not object-bound, across the whole surface**, for the same structural
reason as Environments: Operations' objects are runs, schedulers, providers,
receipts, backends, incidents, failover plans, and spend records. None is a
`CanonicalObjectModel` instance. All twelve composed reads are platform-substrate
or goal-orchestration routes; **not one is a `/v1/hypervisor/odk/*` route.**

| Pane/flow | Semantic primitive + envelope | Route | Read/Write | Notes |
|---|---|---|---|---|
| Every pane | **none — not object-bound** | twelve substrate reads (`serve:8838-8857`) | Read | substrate objects, not semantic-plane objects |
| Work Analytics facet | **none.** Ledger-kind histograms count receipt kinds, not ontology facts | work-ledger read | Read | canon permits work/tool analytics to *become* policy-bound datasets through a DataRecipe (`domain-ontologies-and-data-recipes.md`, "What This Layer Is"); that conversion is Data-owned and does not make this pane object-bound |
| **Write side — whole surface** | **none**, twice over | — | — | Operations admits no semantic write, and holds no authority of its own at all: its three mutation controls POST to Automations-owned lanes |

The one adjacency that will tempt a later packet: ODK **materializing runs** are
runs, and this surface renders runs. They are still not Operations' — the
materializing-run plane is read by Provenance's lineage lens (`provenance.md` §7)
and owned by Data/Ontology. If a unified infrastructure-jobs projection (W3) ever
includes them, it does so as a typed subject with a deep link, never as an
Operations-owned row.

## 8. ODK descriptor and extension lane

Program doc: [`../odk-extension-apps.md`](../odk-extension-apps.md).

### (a) This surface as descriptor consumer

| Pane | Matching `composition_pattern` | Disposition | Why |
|---|---|---|---|
| Whole cockpit (scheduler health, run health, provider health, storage health, failover posture) | `monitoring_console` | **exempt — no bindable primitive** | the shape is the canonical `monitoring_console` almost exactly; substrate objects are not ontology-bound (§7), so invariant 11's fields have nothing to name |
| Spend reconciliation + Work Analytics facet | `dashboard` | **exempt — no bindable primitive** | same |
| Jobs merged queue | `list_detail` | **exempt — no bindable primitive** | same |
| Operate console remediation drawer | `object_editor` | **exempt — authority-crossing, and not this surface's authority** | a descriptor scaffolds views, never admission — and here the admission is not even Operations' to scaffold |

Zero expressible, zero rendered. Fourth surface hitting the **platform-object
blocking finding** (X-2), and the first where the *shape* match is exact enough to
sting: `monitoring_console` was written for exactly this pane, and the descriptor
still cannot bind it.

### (b) This surface as primitive exposer

**n/a.** Operations owns no stage of the composable-application journey
(`odk-extension-apps.md` §2), exposes no ODK primitive, and holds no descriptor.

The one true adjacency, recorded because canon assigns it: Operations **observes**
Domain App runtime state at the mount ladder's rungs
(`domain-ontologies-and-data-recipes.md`, "Domain Apps And The Governed Mount
Ladder" — Governance admits, Operations observes). That is a read of runtime
posture, not participation in the lane: Operations never mounts, serves, stops, or
kills a Domain App. When the runtime plane surfaces here, it arrives as another
typed row in the Jobs queue with its receipts as proof links.
