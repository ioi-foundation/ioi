# SCM / Agentgres transition-chain epic — cross-surface brief

Absorbs the owner-delivered research audit of 2026-08-05 into the
bring-to-life run (`../overhaul/2026-08-05-hypervisor-bring-to-life-run.md`).
Scope: the Git/provider workflow experience — inbound provider events,
Agentgres-admitted repository state, publication, and its projection across
the EXISTING owner surfaces. Same discipline as the surface briefs: every
cite below was re-verified at the bytes on 2026-08-05; where the audit's
`file:line` drifted, the correction is recorded inline (bytes win).

Reuse note: the M5 event plane (`/v1/event-streams`, `/v1/subscriptions`) and
the SCM publication machinery (`scm_publication_routes.rs` — outbound
publication effects behind the registered contract) are foundations this epic
builds ON. Neither models inbound provider workflow state today: the daemon's
only inbound webhook lane is the automation trigger webhook
(token-hash-authenticated, session-less, per-automation —
`orchestration_routes.rs:235-245`); there is no signed provider-event
ingestion anywhere.

## §1 The five P0 current-interface defects

Repair or disable each BEFORE any surface presents the Git workflow
experience as governed. One PR per defect is fine; the ledger row
`P0: SCM truthfulness defects` in the run charter covers all five.

**P0-1 — Publish PR uses the wrong contract (lane is dead as wired).**
Daemon: `handle_scm_publish` requires `destination_binding_ref` +
`proposal_ref` and refuses otherwise, returning `publication_effect` +
receipts (`crates/node/src/bin/hypervisor_daemon_routes/scm_publication_routes.rs:1773`,
refusal at `:1798`; audit cited :1771 — corrected). UI: `publishRunViaConnector`
sends `{ connector_id, title }` and expects the older `receipt`/`remote_ref`
shape (`apps/hypervisor/scripts/ioi-agent-runs.mjs:450`; payload `:482`/`:495`;
expectation `:501-503`; audit cited :446 — corrected). Every UI publish
therefore hits the typed refusal. Disposition: REPAIR — rewire the client to
the registered contract (resolve destination binding + bound proposal, render
`publication_effect` + receipts). Owning surface: Developer Workspace
(workbench/run publish lane), daemon side already correct.

**P0-2 — `/__ioi/code` publication trail is substring-matched, not queried.**
`renderCodeRepositories` filters work-ledger rows on
`String(e.kind||"").includes("publish")`
(`apps/hypervisor/scripts/serve-product-ui.mjs:1400`, function `:1396`,
handler `:8682`; audit's path `product-ui/serve-product-ui.mjs:8681` does not
exist — corrected to `scripts/`, handler at `:8682`). The work-ledger emits
`kind: "marketplace_publish"` rows
(`crates/node/src/bin/hypervisor_daemon_routes/orchestration_routes.rs:908-916`,
handler `:529-532`; audit cited :897 — corrected), so marketplace publication
renders as code publication. Disposition: REPAIR-OR-DISABLE — query SCM
publication effects (P2 projection) or, until then, restrict the pane to the
SCM publication-effect record family / remove the trail. Owning surface:
Developer Workspace (`/__ioi/code` folds into the workbench per its own
header comment).

**P0-3 — PR draft synthesizes an `agentgres://` ref without admission.**
`POST /v1/hypervisor/environments/:id/pull-request-drafts` writes a plain
record and answers
`proposal_ref: "agentgres://pull-request-draft/{pid}"`
(`crates/node/src/bin/hypervisor_daemon_routes/environment_routes.rs:916`
route doc, handler `:921`, plain `persist_record` `:1033`, ref synthesis
`:1035` — audit cite verified). No exact-head admission, no authority proof,
no durable receipt — an `agentgres://` ref implying admitted chain state that
never crossed admission. Disposition: REPAIR — until owner-controlled
Agentgres exact-head admission exists (P1 contract, P2 wiring), the response
must stop minting `agentgres://` refs; return an honestly-named local
proposal ref. Owning surface: Work (agent-run → draft lane,
`ioi-agent-runs.mjs:416` `createLocalPullRequestDraft`), daemon route repair.

**P0-4 — GitHub App setup registers no webhook and subscribes to no events.**
`handle_github_app_manifest` deliberately omits `hook_attributes` and sets
`default_events: []`
(`crates/node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs:16948`
handler, explicit no-webhook comment `:16972-16975`, empty events `:16984`;
audit cited :16937 — corrected). Deliberate for the localhost BYOA flow, but
the consequence stands: workflow events cannot be ingested, so no surface may
present provider workflow state as live. Disposition: REPAIR at P2 (signed
webhook registration + event subscription, Developer Console); until then any
UI copy implying live provider events is disabled-with-named-gap. Owning
surface: Developer Console.

**P0-5 — apps/sas-xyz/v2 displays fabricated signed/hash-linked receipts.**
`synthesizeReceipt` mints `chain.thisHash`/`prevHash` from `Math.random()`
with "Receipt signed and chained" copy
(`apps/sas-xyz/v2/receipt.jsx:229-231`, trace copy `:223`; audit cite :229
verified), and `onDraftGoLive` synthesizes a "live" contract client-side
(`apps/sas-xyz/v2/app.jsx:285-302`, fabricated `receipts30d` `:296`; audit
cite :285 verified). The app makes zero daemon calls (no `/v1/hypervisor`
references). Disposition: DEMO-LABEL or quarantine — unmistakable demo-fixture
labeling on every fabricated-proof rendering, in the same P0 PR. Owning
surface: none of the nine (estate app) — see `repo-ux-disposition.md`.

## §2 Missing Git/Agentgres interface coverage, by EXISTING owner

Never a new top-level app. Each row lands inside the named brief's waves;
the brief carries a matching `### Git/Agentgres transition-chain interfaces
(epic)` pointer back to this table.

| Owner (brief) | Missing interface coverage |
|---|---|
| Projects (`surfaces/projects.md`) | Repo/installation/ref/workflow enrollment; typed Git OIDs (algorithm-tagged); workflow policy; latest admitted state; chain health per project |
| Developer Console (`surfaces/developer-console.md`) | Signed webhook registration; secret rotation; provider permissions/events; repo selection; delivery/reconciliation health |
| Developer Workspace (`surfaces/developer-workspace.md`) | Commit/PR check timeline; provider-observed vs IOI-admitted state; policy preflight; receipt links; reconcile/retry; stale/fork/unknown states |
| Automations (`surfaces/automations.md`) | Provider-event mapping; workflow revision/run-attempt identity; legal transition graph; reconciliation; receipted outbound check projection |
| Work (`surfaces/work.md`) | Repository/ref/commit/check subjects + integration transition history on WorkRun; `HypervisorWorkRunIntegrationStatus` is named in work.md §1 (`work.md:74`, canon `core-clients-surfaces.md:4300-4310`) but mapped in neither §2 nor §4 — closed by this epic at P2 |
| Governance (`surfaces/governance.md`) | Admission + required-check policy; authority freshness; policy version/revocation; override justification; reconciliation approval; witness policy |
| Provenance (`surfaces/provenance.md`) | Transition-chain search/timeline; head/predecessor/gap/fork verification; integrity vs currentness; checkpoint verification; proof export |
| Operations (`surfaces/operations.md`) | Signature failures; ingest lag; duplicates/out-of-order; Agentgres conflicts; dead letters; backfill/reconciliation; provider outages; checkpoint health |
| Settings / Home / Systems (`surfaces/settings.md`, `home.md`, `systems.md`) | Preferences + read-only summaries/deep links ONLY — never competing truth owners |

## §3 Missing contracts beneath the UI — build-list with owner assignment

Kinds: **daemon** = daemon route/record family · **schema** = schema-registry /
canon contract entry · **client** = shared client (`apps/hypervisor/surfaces/*`,
route shell) work.

| # | Contract | Kind | Owner | Phase |
|---|---|---|---|---|
| C1 | Registered provider-neutral transition profile + legal state machine (state vocabulary) | schema | Governance (canon) + registry | P1 |
| C2 | Owner-qualified repository/workflow bindings + algorithm-tagged Git OIDs | schema + daemon | Projects | P1/P2 |
| C3 | Delivery / workflow / run / check / attempt identities | schema | Automations | P1 |
| C4 | Signed, replay-protected, idempotent webhook ingestion with tenant/repository binding | daemon | Developer Console | P2 |
| C5 | Owner-controlled Agentgres exact-head admission | daemon | Projects (admission), Governance (policy) | P1 contract / P2 wiring |
| C6 | List / head / detail / history / filtered projections over the chain | daemon | each owner's read family | P2 |
| C7 | Duplicate / omission / out-of-order / force-push / outage reconciliation | daemon | Operations (health) + Governance (approval) | P2/P3 |
| C8 | Policy / override / revocation / authority-freshness objects | schema + daemon | Governance | P1/P3 |
| C9 | Receipt / checkpoint verification + export routes | daemon | Provenance | P3 |
| C10 | Domain event namespace for live UI updates (rides the M5 plane) | daemon + client | event plane (W0.4 client already landed) | P2 |
| C11 | Principal/policy filtering + redaction before counts/search/exports | daemon (cross-cutting) | every projection above | P2/P3 |
| C12 | Stable cross-surface deep-link grammar | client | route shell (`v2-route-shell.mjs:328` is exact root lookup today) | P1 (W1 addendum) |
| C13 | UI/API/CLI/TUI/MCP parity for inspect/verify/watch/preflight/reconcile/export | client + `crates/cli` | parity lane | P3 |

## §4 Sequencing — P0→P3, interleaved with the run's waves

- **P0 — truthfulness (lands FIRST).** The five §1 defects, before any
  surface presents the Git workflow as governed and before the `work build`
  ledger row starts. Interleave: alongside W0.5/W0.6; no P1-P3 item and no
  surface's Git-facing pane ships while a P0 defect is live on that lane.
- **P1 — contracts.** Ownership map (§2), schemas + state vocabulary (C1-C3),
  threat model for the ingestion boundary, admission + reconciliation
  contracts (C5, C8), deep-link grammar (C12). Interleave: rides the W1
  window; every P1 contract that a P2 wiring item consumes must be registered
  before that wiring lands (contracts before wiring, the run's standing
  8-step discipline).
- **P2 — ingestion + projections + owner wiring.** Provider ingestion (C4),
  Agentgres projections (C5 wiring, C6, C10, C11), then wire Projects /
  Developer Console / Developer Workspace / Automations / Work per §2 —
  including closing Work's `HypervisorWorkRunIntegrationStatus`
  named-but-unmapped gap. Interleave: W2 (authority-crossing registrations
  via the lease client) and W3 (new backend families ride the W3 build-list
  mechanism; `hypervisor-daemon.rs` route PRs serialize).
- **P3 — proofs + parity + acceptance.** Governance/Provenance/Operations
  actions + proofs (C7 approval leg, C8 actions, C9), CLI/TUI parity (C13),
  a11y/security/observability/real-daemon-E2E acceptance for the Git
  workflow lanes. Interleave: W3/W4; the cutover of any legacy Git-facing
  readout (e.g. `/__ioi/code`) happens at its owner's W4 leg per the 6-step
  rule.

## §5 Non-goals

- **No new top-level application.** All coverage lands in the nine existing
  owners (§2); the taxonomy stays 12 owner apps + 2 substrate + 6 core
  workspaces.
- **Settings, Home, Systems stay read-only** for this domain: preferences,
  summaries, deep links — never a competing truth owner over chain state.
- **No proof apparatus** (run charter regime).
- **QM (`apps/ioi-ai`) is out of scope** — separate Postgres authority
  boundary; its surfaces are dispositioned (or held) in
  `repo-ux-disposition.md`, not wired here.
- **No re-decision of C-1..C-4**: chain subjects attach to sessions via
  `subject_attachments`, never named app fields.

## Agentgres positioning constraints (owner ruling, 2026-08-05)

Canon positioning is fixed by `postgres-bridge-and-readiness-contract.md:18-26`
("canonical state substrate with a Postgres bridge") and `doctrine.md:61/:81`
("Rows are views. Settled state is truth" · "Git versions code. Agentgres
versions autonomous work"). Owner ruling: this is emphasis-binding for the
epic, not a mechanics change. Consequences, in force for every epic PR:

1. **Admission is the only write story.** No surface, route, or client may
   present Agentgres state with mutation semantics; writes surface only as
   admission crossings (expected-head CAS) with receipts. This RAISES P0
   defect 3: the synthesized `agentgres://pull-request-draft/...` ref fakes
   admission itself — disable is preferred over repair until owner-controlled
   exact-head admission exists.
2. **No bridge front-running.** The Postgres bridge is `planned`
   (`postgres-bridge-and-readiness-contract.md:9`); no UI copy, docs page, or
   demo may promise SQL/psql/ORM access to Agentgres state until it lands.
   Reads render projections of settled state, labeled as such. (Estate grep
   2026-08-05: no violating copy found in the Hypervisor UI lanes.)
3. **Headline = versions-autonomous-work.** Epic P2/P3 UI stories lead with
   branchable, replayable agent-execution state (transition chains, replay,
   receipts); Postgres-shaped reads are the secondary adoption feature, per
   the canonicality hierarchy — never the identity.
