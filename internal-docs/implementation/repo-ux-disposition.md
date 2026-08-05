# Repository-wide UX surface disposition ledger

Companion to `scm-transition-chain-epic.md` (2026-08-05 audit absorption).
One row per user-facing surface in the estate OUTSIDE the twenty briefed
hypervisor surfaces. "What it is" is byte-verified (existence + whether it
talks to the hypervisor daemon, checked by grepping for `/v1/hypervisor`).
Dispositions: adopt · integrate · retain-static · demo-label · retire ·
UNDISPOSITIONED-needs-owner-ruling. Rows the owner has not ruled and canon
does not decide are UNDISPOSITIONED — candidates are recorded as candidates,
never as rulings. The run charter carries one ledger row to rule the
UNDISPOSITIONED set.

| Surface | What it is (byte-verified) | Disposition | Next action |
|---|---|---|---|
| `apps/hypervisor` (product UI, serve lane, scripts, surfaces/ clients) | The hypervisor product estate; daemon-backed throughout; subject of the bring-to-life run | **adopt** (already the run's subject) | Continue the run; epic P0 defects 1-3 live here/daemon |
| Rust CLI + agent TUI (`crates/cli`, incl. `src/commands/agent_tui.rs`, `agent_tui_loop.rs`, `agent_event_stream.rs`) | Exists; daemon-backed; the most functional non-web interface; has no web-parity brief | **integrate** (per epic P3 parity, C13) | Parity lane for inspect/verify/watch/preflight/reconcile/export at epic P3 |
| Editor extension targets (`packages/hypervisor-adapter-targets/`: `code-editors/vscode-extension`, `jetbrains`, `ssh`) | Exist as adapter targets with a manifest (`editor-targets.manifest.json`) | UNDISPOSITIONED-needs-owner-ruling | Owner rules whether editor targets carry epic C13 parity obligations (the audit's parity list is UI/API/CLI/TUI/MCP — editors are not named) |
| `apps/hypervisor-web` | Exists; static Vite scaffold "browser-facing Hypervisor product and marketing surface" (its README); zero `/v1/hypervisor` calls | UNDISPOSITIONED-needs-owner-ruling | Candidate retain-static (marketing); owner confirms + a sweep for any governed-state renderings that would need demo-labels |
| `apps/developers-ioi-ai` (developers.ioi.ai) | Exists; static curated developer-experience site; zero `/v1/hypervisor` calls | UNDISPOSITIONED-needs-owner-ruling | Candidate retain-static; epic P1 contracts may later pull reference docs onto it |
| `apps/benchmarks` | Exists; static React benchmark surface; zero `/v1/hypervisor` calls | UNDISPOSITIONED-needs-owner-ruling | Candidate retain-static; verify benchmark claims stay sourced, not fabricated |
| `apps/aiagent-xyz` (aiagent.xyz) | Exists; static marketing surface ("composable autonomous supply"); zero `/v1/hypervisor` calls | UNDISPOSITIONED-needs-owner-ruling | Candidate retain-static (marketing) |
| `apps/sas-xyz` (sas.xyz, `/v2` SPA) | Exists; static in-browser React demo (CDN React + Babel); zero daemon calls; renders FABRICATED signed/hash-linked receipts (`v2/receipt.jsx:230-231` Math.random chain; `v2/app.jsx:285-302` client-synthesized live contract) | **demo-label** (ruled by epic P0-5) | Quarantine or unmistakable demo-fixture labeling in the P0 PR; owner may later upgrade to retire |
| `apps/ioi-ai` (QM: web/admin/portal/auth plugins, Slack surfaces `src/surfaces/slack-*.ts`, deployment CLI `cli/`) | Exists; separate product on its OWN Postgres authority boundary; not hypervisor-daemon-backed | UNDISPOSITIONED-needs-owner-ruling (held) | Out of epic scope; QM adoption is governed by the M-sequencer program (dormant adoption gates M5 exit per owner ruling) — UX disposition rides that ruling, not this run |
| `apps/hypervisor/ux-seeds/` (workspaces · widgets · lineage) | Exists; DORMANT ported-seed evidence preserved by PRs #93-#95 under `ported-seed-preservation.v1.json` | **retain-static** (already ruled: preserved dormant) | Per-seed adopt-or-archive decided at each owner's W4 cutover PR (already in the briefs) |
| `packages/hypervisor-workbench` | Exists; TypeScript workbench package consumed by the product UI; mounted-preview adapter honesty is tracked in `surfaces/developer-workspace.md`, not here | **adopt** (part of the briefed estate) | No separate row-level action; epic P0-1/P0-2 touch its publish/code lanes |

Notes:

- The audit lists this exact surface set as "surfaces with NO disposition" —
  UNDISPOSITIONED here is therefore the owner's own current state, not a gap
  this ledger invented. Ruling the UNDISPOSITIONED rows is a single
  owner-scope pass (charter ledger row).
- `retire` appears in no row yet: no surface has an owner ruling to delete,
  and this ledger never guesses one.
