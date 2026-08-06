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

## Harvest-capture disposition sweep (X-3, 2026-08-06)

Packet X-3 of the seed-mesh + ODK wiring run
(`internal-docs/overhaul/2026-08-06-seed-mesh-and-odk-wiring-run.md`). The run's
exit criterion for seeds is that **every one of the 39 `/__apps/*` harvest captures
has exactly one home** — a mesh-ledger row in some surface brief, or a ruled row
here.

**Result: 39 of 39 homed. Zero UNDISPOSITIONED. Zero multi-homed.** All 39 are
dispositioned inside surface briefs, so no capture needs a row in the ledger above;
this table is the index into them.

Sweep method: enumerate `harvest-app-parity-matrix.json → seeds[].slug` (39), then
locate each slug's row in the `## N. Seed mesh ledger` section of every brief under
`internal-docs/implementation/surfaces/`. Ownership below is the **meshing brief**,
which is the canonical owner — the matrix's `owner` field still carries four retired
names (Missions, Marketplace, Workbench, Domain Apps) and is marked where it does.

| capture | matrix owner | meshed in (brief §6) | disposition | parity_class | capture_state |
|---|---|---|---|---|---|
| `monitors` | Automations | `automations.md` | pattern-harvest | daemon_wired | boots_graph |
| `dataset` | Data | `data.md` | blocked-missing-route | reference_capture | shell_only |
| `ingest` | Data | `data.md` | pattern-harvest | reference_capture | shell_only |
| `pipeline` | Data | `data.md` | blocked-missing-capture | daemon_wired | blocked_missing_capture |
| `sources` | Data | `data.md` | pattern-harvest | daemon_wired | shell_only |
| `devconsole` | Developer Console | `developer-console.md` | blocked-missing-capture | reference_capture | blocked_missing_capture |
| `developer` | Developer Console | `developer-console.md` | blocked-missing-capture | reference_capture | blocked_missing_capture |
| `widgets` | Developer Console | `developer-console.md` | blocked-missing-capture | reference_capture | blocked_missing_capture |
| `notepad` | **Workbench** (retired) | `developer-workspace.md` | blocked-missing-capture | reference_capture | blocked_missing_capture |
| `repositories` | **Workbench** (retired) | `developer-workspace.md` | blocked-missing-capture | reference_capture | blocked_missing_capture |
| `workspaces` | **Workbench** (retired) | `developer-workspace.md` | pattern-harvest | reference_capture | boots_landing |
| `map` | Environments | `environments.md` | blocked-missing-capture | reference_capture | blocked_missing_capture |
| `analysis` | Evaluations | `evaluations.md` | pattern-harvest | reference_capture | shell_only |
| `evalsuites` | Evaluations | `evaluations.md` | pattern-harvest | daemon_wired | boots_editor_canvas |
| `quiver` | Evaluations | `evaluations.md` | blocked-missing-route | reference_capture | shell_only |
| `inference` | Foundry | `foundry.md` | pattern-harvest | reference_capture | boots_wizard |
| `models` | Foundry | `foundry.md` | pattern-harvest | daemon_wired | boots_table_list |
| `modelstudio` | Foundry | `foundry.md` | pattern-harvest | reference_capture | shell_only |
| `approvals` | Governance | `governance.md` | **rehome (as the registered T3 surface)** | daemon_wired | boots_table_list |
| `changes` | Improvement | `improvement.md` | rebind | daemon_wired | boots_editor_canvas |
| `explorer` | Ontology | `ontology.md` | pattern-harvest | daemon_wired | boots_graph |
| `objecteditor` | Ontology | `ontology.md` | blocked-missing-capture | reference_capture | blocked_missing_capture |
| `objectview` | Ontology | `ontology.md` | blocked-missing-capture | reference_capture | blocked_missing_capture |
| `schema` | Ontology | `ontology.md` | pattern-harvest | daemon_wired | boots_table_list |
| `scheduler` | Automations (`ownerUrl` → Operations) | `operations.md` | pattern-harvest | reference_capture | shell_only |
| `listings` | **Marketplace** (retired) | `packages.md` | rebind | daemon_wired | boots_graph |
| `registry` | **Marketplace** (retired) | `packages.md` | blocked-missing-capture | reference_capture | blocked_missing_capture |
| `lineage` | Provenance | `provenance.md` | rebind | substrate_bound | boots_graph |
| `vertex` | Provenance | `provenance.md` | blocked-missing-capture | substrate_bound | blocked_missing_capture |
| `contour` | **Domain Apps** (retired) | `studio.md` | pattern-harvest | reference_capture | shell_only |
| `designer` | Studio | `studio.md` | **rebind** (→ ODK composition patterns + surface descriptors) | daemon_wired | boots_graph |
| `fusion` | **Domain Apps** (retired) | `studio.md` | pattern-harvest | reference_capture | shell_only |
| `logic` | **Domain Apps** (retired) | `studio.md` | pattern-harvest | reference_capture | shell_only |
| `machinery` | Studio | `studio.md` | pattern-harvest | daemon_wired | boots_graph |
| `module` | Studio | `studio.md` | pattern-harvest | reference_capture | shell_only |
| `slate` | **Domain Apps** (retired) | `studio.md` | pattern-harvest | reference_capture | blocked_missing_capture |
| `workshop` | Studio | `studio.md` | blocked-missing-capture | reference_capture | blocked_missing_capture |
| `incidents` | **Missions** (retired) | `work.md` | rebind | daemon_wired | boots_table_list |
| `jobs` | **Missions** (retired) | `work.md` | rebind | substrate_bound | boots_editor_canvas |

**Totals.** 18 pattern-harvest · 12 blocked-missing-capture · 6 rebind ·
2 blocked-missing-route · 1 rehome = **39**.

### What the sweep found

**Twelve of thirty-nine captures cannot be inspected at all.** `capture_state:
blocked_missing_capture` means the artifact does not boot, so no claim about its
interaction grammar is supportable. Roughly a third of the harvest estate is
therefore evidence in name only, and the blocks cluster where they hurt most:
Developer Console (three of its four), Ontology's two object panes,
`workshop` (the one capture whose grammar is literally "application builder"), and
`registry` (the one depicting a versioned artifact registry, which is also the
plane that does not exist).

**Only six captures rebind**, and three of those six are the estate's only captures
with a declared `reboundLane` in `harvest-seed-inventory.mjs` — `designer` (→ ODK
composition patterns and surface descriptors), `listings` (→ the daemon marketplace
listing plane), and `changes` (→ daemon improvement-proposals). The other three
(`jobs`, `incidents`, `lineage`) rebind through lanes the serve layer already
answers with daemon truth.

**Eighteen are pattern-harvest — the modal outcome, and the correct one.** A
capture's value is its interaction grammar; harvesting the grammar moves no code and
licenses nothing. Every pattern-harvest row above stays dormant under the
ported-seed-preservation invariant until its surface's cutover.

**Four retired owner names still label ten captures**: Missions (2), Marketplace
(2), Workbench (3), Domain Apps (4, counting `slate`/`logic`/`contour`/`fusion`).
All ten rehome into their canonical owners above and none is revived as a peer
application. `scheduler` is the one row where the matrix's `owner` and `ownerUrl`
disagree (Automations vs `/__ioi/operations`); both are correct — canon gives the
scheduler *object* to Automations and the health *readout* to Operations — and the
row is meshed by `operations.md` accordingly.

**No capture is multi-homed.** `dataset` and `quiver` are both cross-referenced
between `data.md` and `evaluations.md` because they share a pending owner ruling
(the datasets / time-series / media-sets plane), but each has exactly one meshing
row: `dataset` in `data.md`, `quiver` in `evaluations.md`.
