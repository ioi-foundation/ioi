// Pipeline Builder CONTROL MATRIX (interaction-fidelity wave #66) — the complete census of the
// reference workspace's controls (state atlas: scripts/pipeline-reference-atlas.mjs against the
// live :9225 Blueprint SPA capture), each mapped to EXACTLY one of four outcomes:
//   daemon_action    — invokes existing daemon truth/authority (read navigation or governed call)
//   local_view       — view-only interaction, no daemon authority needed (client or URL state)
//   disabled_reason  — visible control, disabled IN PLACE with its missing authority named
//   unsupported      — reference control consciously not ported; the reason is recorded HERE so
//                      nothing is silently inert or silently omitted (the 4th outcome exists for
//                      reference session machinery with no IOI plane behind it)
// The interaction verifier asserts: every entry has a valid outcome; disabled entries carry a
// reason; daemon_action/local_view entries name their binding (href param or client control id);
// and the rendered page accounts for every non-unsupported control.
export const CONTROL_OUTCOMES = ["daemon_action", "local_view", "disabled_reason", "unsupported"];

export const CONTROL_MATRIX = [
  // ---- Header (reference: ws-resource-header) --------------------------------------------------
  { id: "hdr.file-menu", region: "header", label: "File menu", reference: "New/Open/Rename/Move/Copy path/Share/Favorite/Tags/Trash", outcome: "disabled_reason", reason: "pipeline file operations have no daemon plane — ontologies are the pipeline identity (named gap)" },
  { id: "hdr.settings-menu", region: "header", label: "Settings menu", reference: "branches/export/marketplace validation/preferences/flags", outcome: "disabled_reason", reason: "builder settings lanes have no daemon plane (named gap)" },
  { id: "hdr.help-menu", region: "header", label: "Help menu", reference: "tour/hotkeys/AIP assist/docs/updates", outcome: "disabled_reason", reason: "reference help lanes (named gap)" },
  { id: "hdr.favorite-star", region: "header", label: "Favorite star", reference: "toggles resource favorite", outcome: "unsupported", reason: "no favorites plane exists; the star is certified header chrome" },
  { id: "hdr.batch-badge", region: "header", label: "Batch badge", reference: "organizations popover", outcome: "unsupported", reason: "no organizations plane; badge is certified chrome" },
  { id: "hdr.tabs-mode", region: "header", label: "Graph / Proposals / History tabs", reference: "switches the workspace between graph, proposal review, and version history", outcome: "unsupported", reason: "no proposal/branch/version plane exists — the surface is permanently the Graph workspace; run history lives on the Provenance surface (linked from node details)" },
  { id: "hdr.undo", region: "header", label: "Undo", reference: "undo last graph edit", outcome: "unsupported", reason: "no authoring, so no edit history; reference session-state zone is replaced by the real command cluster" },
  { id: "hdr.redo", region: "header", label: "Redo", reference: "redo", outcome: "unsupported", reason: "no authoring edit history" },
  { id: "hdr.branch-selector", region: "header", label: "Branch selector (Main)", reference: "branch popover + create branch", outcome: "unsupported", reason: "no pipeline branching plane; ODK revisions are the versioning primitive (Manager surface)" },
  { id: "hdr.branch-actions", region: "header", label: "Additional branch actions", reference: "resolve/discard/reset", outcome: "unsupported", reason: "no branching plane" },
  { id: "hdr.saved", region: "header", label: "Saved indicator", reference: "save state", outcome: "unsupported", reason: "nothing authors here, so nothing saves; daemon records carry their own revisions" },
  { id: "hdr.propose", region: "header", label: "Propose", reference: "opens proposal flow", outcome: "unsupported", reason: "no proposal plane" },
  { id: "hdr.deploy-icon", region: "header", label: "Deploy (icon)", reference: "deploy drawer", outcome: "disabled_reason", reason: "no pipeline deploy exists yet — a named gap", binding: "command:deploy" },
  { id: "hdr.build-settings-icon", region: "header", label: "Modify build settings", reference: "build settings drawer", outcome: "unsupported", reason: "no build-settings plane; Build itself is the governed ODK ladder (see command:build)" },
  { id: "hdr.actions", region: "header", label: "Actions menu", reference: "explore data lineage etc.", outcome: "disabled_reason", reason: "Actions menu is a reference-only lane (named gap)" },
  { id: "hdr.share", region: "header", label: "Share", reference: "sharing dialog", outcome: "disabled_reason", reason: "Sharing is a reference-only lane (named gap)" },
  { id: "hdr.panel-toggle", region: "header", label: "Panel layout toggle", reference: "layout toggle", outcome: "disabled_reason", reason: "Panel layout toggle — named gap" },

  // ---- Command cluster (IOI's real commands live in the reference's masked session-state zone) --
  { id: "cmd.build", region: "commands", label: "Build", reference: "runs the pipeline build", outcome: "daemon_action", binding: "href:?pane=build", proof: "the governed ladder workflow — MaterializingRun → wallet-approved lease (403 challenge → externally signed grant) → sealed ConnectorSession → ONE bounded execute; every stage a declared receipted action, resumable from record status; header disabled with the missing rungs named until the ladder is coherent-ready" },
  { id: "cmd.preview", region: "commands", label: "Preview", reference: "previews output rows", outcome: "daemon_action", binding: "href:?node=materialized&tab=preview#pb-preview", proof: "real materialized rows + provenance refs in the tray" },
  { id: "cmd.schedule", region: "commands", label: "Schedule", reference: "build schedules", outcome: "disabled_reason", reason: "no pipeline scheduler exists yet — a named gap (author + run via a materializing run)", binding: "command:schedule" },
  { id: "cmd.deploy", region: "commands", label: "Deploy", reference: "deploy pipeline", outcome: "disabled_reason", reason: "no pipeline deploy exists yet — a named gap", binding: "command:deploy" },
  { id: "cmd.lineage", region: "commands", label: "Lineage", reference: "(IOI owner link)", outcome: "daemon_action", binding: "href:/__ioi/lineage?ontology=" },
  { id: "cmd.ontology-manager", region: "commands", label: "Ontology Manager", reference: "(IOI owner link)", outcome: "daemon_action", binding: "href:/__ioi/ontology/manager?ontology=" },

  // ---- Canvas toolbar (floating tool card) -----------------------------------------------------
  { id: "tool.pan-mode", region: "toolbar", label: "Panning mode", reference: "radio: drag pans the canvas", outcome: "local_view", binding: "client:pb-tool-pan", note: "the live pan mode — drag pans the SVG viewBox" },
  { id: "tool.select-mode", region: "toolbar", label: "Drag select mode", reference: "radio: drag draws a selection marquee", outcome: "disabled_reason", reason: "multi-select has no consumer — selection is single-node URL state (?node=); a marquee would select nothing actionable (named gap)" },
  { id: "tool.marquee", region: "toolbar", label: "Selection tool", reference: "marquee select", outcome: "disabled_reason", reason: "multi-select has no consumer (named gap)" },
  { id: "tool.graph-remove", region: "toolbar", label: "Remove from graph", reference: "removes selected node", outcome: "disabled_reason", reason: "graph authoring is a named gap — ladder records are authored in the Ontology Manager" },
  { id: "tool.layout", region: "toolbar", label: "Layout nodes", reference: "auto-layout", outcome: "disabled_reason", reason: "the ladder layout is fixed by the ODK contract order — freeform layout is a named gap" },
  { id: "tool.grid-snap", region: "toolbar", label: "Toggle grid snapping", reference: "grid snapping", outcome: "disabled_reason", reason: "no freeform node placement, so nothing snaps (named gap)" },
  { id: "tool.text-box", region: "toolbar", label: "Text box", reference: "canvas annotation", outcome: "disabled_reason", reason: "canvas annotations have no persistence plane (named gap)" },
  { id: "tool.canvas-search", region: "toolbar", label: "Canvas search", reference: "swaps right panel + legend into search mode", outcome: "local_view", binding: "href:?panel=search", note: "the right panel becomes the real pipeline-record search; the reference additionally reflows the toolcard/legend into search-mode chrome — a recorded divergence (IOI keeps standard canvas chrome)" },
  { id: "tool.collapse-colors", region: "toolbar", label: "Collapse colors", reference: "collapse-by-color popover", outcome: "disabled_reason", reason: "color grouping is a reference-only lane (named gap)" },
  { id: "tool.add-data", region: "toolbar", label: "Add data", reference: "add data menu (4 lanes)", outcome: "daemon_action", binding: "href:/__ioi/odk?ontology=", note: "routes to the real ODK authoring ladder" },
  { id: "tool.reusables", region: "toolbar", label: "Reusables", reference: "parameters/expressions/UDFs/models", outcome: "disabled_reason", reason: "Reusable transforms library — a named gap" },
  { id: "tool.transform", region: "toolbar", label: "Transform", reference: "authors a transform on selection (the reference ENABLES the strip when a node is selected)", outcome: "disabled_reason", reason: "transform authoring requires a TransformationRun authoring authority — a named gap; the declared plan is inspectable on the Transform plan node (recorded divergence: IOI keeps the strip disabled on selection)" },
  { id: "tool.join", region: "toolbar", label: "Join", reference: "join tables", outcome: "disabled_reason", reason: "join authoring — named gap (no authoring authority)" },
  { id: "tool.union", region: "toolbar", label: "Union", reference: "union tables", outcome: "disabled_reason", reason: "union authoring — named gap" },
  { id: "tool.split", region: "toolbar", label: "Split", reference: "split table", outcome: "disabled_reason", reason: "split authoring — named gap" },
  { id: "tool.import-model", region: "toolbar", label: "Import trained model", reference: "apply model", outcome: "disabled_reason", reason: "model application — named gap (model routes live in the Model Catalog)" },
  { id: "tool.use-llm", region: "toolbar", label: "Use LLM", reference: "LLM transform", outcome: "disabled_reason", reason: "AIP transform lanes are reference-only (named gap)" },
  { id: "tool.aip-generate", region: "toolbar", label: "Generate (AIP)", reference: "NL pipeline generation", outcome: "disabled_reason", reason: "AIP generation is a reference-only lane (named gap)" },
  { id: "tool.aip-explain", region: "toolbar", label: "Explain (AIP)", reference: "NL pipeline explanation", outcome: "disabled_reason", reason: "AIP explanation is a reference-only lane (named gap)" },
  { id: "tool.edit", region: "toolbar", label: "Edit", reference: "edit selected transform", outcome: "disabled_reason", reason: "transform editing — named gap (no authoring authority)" },

  // ---- Legend ----------------------------------------------------------------------------------
  { id: "legend.toggle", region: "legend", label: "Legend collapse/expand", reference: "collapses the legend card", outcome: "local_view", binding: "client:pb-legend-toggle" },
  { id: "legend.eye", region: "legend", label: "Category eye (hide color)", reference: "hides nodes of a color", outcome: "local_view", binding: "client:pb-legeye", note: "hides that category's nodes in the SVG; persisted as ?hide= via replaceState" },
  { id: "legend.add-color", region: "legend", label: "Add color", reference: "color authoring picker", outcome: "disabled_reason", reason: "Legend color authoring — a named gap" },

  // ---- Canvas / graph --------------------------------------------------------------------------
  { id: "canvas.node-select", region: "canvas", label: "Node click select", reference: "selection ring + header card + quick strip + enables transform strip + Preview tab", outcome: "daemon_action", binding: "href:?node=<key>", note: "URL-state selection; the tray Selection-preview panel renders the node's real record" },
  { id: "canvas.node-keyboard", region: "canvas", label: "Keyboard node navigation", reference: "(reference is mouse-first; IOI adds arrows/Home/End + Enter)", outcome: "local_view", binding: "client:pb-graph-keys" },
  { id: "canvas.pan", region: "canvas", label: "Canvas drag pan", reference: "left-drag pans", outcome: "local_view", binding: "client:pb-pan" },
  { id: "canvas.ctrl-wheel-zoom", region: "canvas", label: "Ctrl+wheel zoom", reference: "zooms", outcome: "local_view", binding: "client:pb-wheel" },
  { id: "canvas.zoom-in", region: "canvas", label: "Zoom in", reference: "zooms in", outcome: "local_view", binding: "client:pb-zin" },
  { id: "canvas.zoom-out", region: "canvas", label: "Zoom out", reference: "zooms out", outcome: "local_view", binding: "client:pb-zout" },
  { id: "canvas.zoom-fit", region: "canvas", label: "Zoom to fit", reference: "fits graph", outcome: "local_view", binding: "client:pb-zfit" },
  { id: "canvas.node-context-open", region: "canvas", label: "Node context: Open", reference: "opens the resource", outcome: "daemon_action", binding: "client:pb-ctx-open", note: "navigates to the node's own selection URL (embed-safe pre-rendered href)" },
  { id: "canvas.node-context-copy-ref", region: "canvas", label: "Node context: Copy record ref", reference: "Copy RID", outcome: "local_view", binding: "client:pb-ctx-copy" },
  { id: "canvas.node-context-authoring", region: "canvas", label: "Node context: Rename/Copy/Paste/Duplicate/Remove/Color/Hide/Read mode/Packaging/Sampling", reference: "node authoring menu items", outcome: "disabled_reason", reason: "node authoring is a named gap — ladder records are authored in the Ontology Manager" },
  { id: "canvas.quick-strip", region: "canvas", label: "Node quick-action strip (Transform/Split/Join/Union/LLM/Generate/Explain/Add)", reference: "per-node authoring strip on selection", outcome: "disabled_reason", reason: "per-node authoring — named gaps (no authoring authority); rendered beside the selected node like the reference, disabled in place and hit-transparent so neighboring nodes stay clickable (reasons machine-readable via data-ioi-disabled-reason)" },
  { id: "canvas.snapshot-pill", region: "canvas", label: "Snapshot sampling pill", reference: "Snapshot/Incremental/Example sampling", outcome: "disabled_reason", reason: "sampling strategies have no daemon plane — preview rows are the set's real bounded objects (named gap)" },
  { id: "canvas.edge-insert", region: "canvas", label: "Edge insert '+' dot", reference: "insert transform mid-edge", outcome: "unsupported", reason: "edge insertion is authoring; edges here are TYPED PROOF (each is justified by a real cross-record ref rendered in its tooltip) — inserting between them has no meaning" },

  // ---- Bottom tray -----------------------------------------------------------------------------
  { id: "tray.tab-selection", region: "tray", label: "Selection preview tab", reference: "selected node's About/Columns/Schedules", outcome: "local_view", binding: "href:?tab=selection", note: "renders the selected node's real record (About/Fields/Receipts sub-tabs)" },
  { id: "tray.tab-preview", region: "tray", label: "Preview tab (on selection)", reference: "row preview; appears only when a node is selected", outcome: "daemon_action", binding: "href:?tab=preview", note: "the materialized set's real bounded rows" },
  { id: "tray.tab-suggestions", region: "tray", label: "Suggestions tab", reference: "AIP suggestions + compute-profile banner", outcome: "local_view", binding: "href:?tab=suggestions", note: "functional tab; content is the honest named gap (no suggestion authority)" },
  { id: "tray.tab-warnings", region: "tray", label: "Pipeline warnings tab", reference: "warning list with Go-to-node links", outcome: "daemon_action", binding: "href:?tab=warnings", note: "REAL warnings — blocked_reasons/missing_contracts/missing_authority/health across the ladder, each with its Go-to-node link" },
  { id: "tray.collapse", region: "tray", label: "Tray collapse chevron", reference: "collapses the bottom panel", outcome: "local_view", binding: "client:pb-tray-toggle", note: "persisted as ?tray=0 via replaceState; survives refresh" },
  { id: "tray.node-subtabs", region: "tray", label: "Node detail sub-tabs (About/Fields/Receipts)", reference: "About/Columns/Schedules sub-tabs", outcome: "local_view", binding: "client:pb-subtab", note: "Schedules has no plane; IOI's third sub-tab is the record's REAL receipt chain" },

  // ---- Right outputs panel ---------------------------------------------------------------------
  { id: "out.search", region: "outputs", label: "Search outputs", reference: "filters output cards", outcome: "local_view", binding: "client:pb-outsearch" },
  { id: "out.card-select", region: "outputs", label: "Output card select", reference: "card enters edit-affordance state", outcome: "local_view", binding: "href:?output=<id>", note: "selection only — the projection's real detail renders in the tray; authoring stays a gap" },
  { id: "out.gear", region: "outputs", label: "Outputs gear menu", reference: "Build/Output/Packaging settings, Replace with objects", outcome: "disabled_reason", reason: "output settings lanes are authored in the ODK substrate — named gap here" },
  { id: "out.panel-table-icon", region: "outputs", label: "Outputs panel-table icon", reference: "list layout toggle", outcome: "disabled_reason", reason: "layout toggle — named gap" },
  { id: "out.add", region: "outputs", label: "Add output", reference: "adds an output", outcome: "disabled_reason", reason: "Adding outputs is authored in the ODK substrate — a named gap here" },
  { id: "out.lineage-btn", region: "outputs", label: "View lineage (header icon)", reference: "opens lineage in new window", outcome: "daemon_action", binding: "href:/__ioi/lineage?ontology=", note: "covered by the command cluster's Lineage link" },
  { id: "out.more-options", region: "outputs", label: "More options (Reset ontology changes)", reference: "reset menu", outcome: "disabled_reason", reason: "reset is a daemon authority (named gap; deletion lanes are the governed-build PR)" },
  { id: "out.edit-settings", region: "outputs", label: "Edit output settings", reference: "Manage output settings dialog", outcome: "daemon_action", binding: "href:/__ioi/odk?ontology=", note: "routes to the real ODK substrate where output declarations live" },

  // ---- Right icon rail (panel toggles) ----------------------------------------------------------
  { id: "rail.outputs", region: "rstrip", label: "Pipeline outputs panel", reference: "default panel", outcome: "local_view", binding: "href:?panel=outputs" },
  { id: "rail.search", region: "rstrip", label: "Search pipeline panel", reference: "search term + conditions", outcome: "local_view", binding: "href:?panel=search", note: "real search over the pipeline's ladder records" },
  { id: "rail.changes", region: "rstrip", label: "View changes panel", reference: "branch diff", outcome: "disabled_reason", reason: "no branching plane — nothing diffs (named gap)" },
  { id: "rail.deploy", region: "rstrip", label: "Deploy panel", reference: "deploy status + action", outcome: "disabled_reason", reason: "no pipeline deploy exists yet — a named gap" },
  { id: "rail.build-settings", region: "rstrip", label: "Build settings panel", reference: "compute profile/job groups", outcome: "disabled_reason", reason: "no build-settings plane — Build is the governed ODK ladder (named gap)" },
  { id: "rail.schedules", region: "rstrip", label: "Build schedules panel", reference: "schedule list", outcome: "disabled_reason", reason: "no pipeline scheduler exists yet — a named gap" },
  { id: "rail.file-tree", region: "rstrip", label: "Pipeline file tree panel", reference: "resource tree", outcome: "local_view", binding: "href:?panel=tree", note: "the real ladder-record tree, every record linked to its node" },
  { id: "rail.unit-tests", region: "rstrip", label: "Unit tests panel", reference: "test cases", outcome: "disabled_reason", reason: "pipeline unit tests have no daemon plane — evaluation suites live in Evaluations (named gap)" },
  { id: "rail.sources", region: "rstrip", label: "Pipeline sources panel", reference: "imported sources", outcome: "disabled_reason", reason: "source catalog is the Data Connection surface (owner: /__ioi/data/sources) — duplicate lane disabled (named gap)" },

  // ---- Pipeline picker (IOI-only control, no reference counterpart) -----------------------------
  { id: "ioi.pipeline-picker", region: "canvas", label: "Pipeline picker", reference: "(none — IOI multi-ontology affordance)", outcome: "daemon_action", binding: "href:?ontology=<id>" },
];

// Sanity: fail the import (and thus serve boot) on a malformed matrix — same fail-fast doctrine
// as the surface registry.
for (const c of CONTROL_MATRIX) {
  if (!c.id || !c.region || !c.label || !CONTROL_OUTCOMES.includes(c.outcome)) throw new Error(`control-matrix: malformed entry ${c.id || "?"}`);
  if (c.outcome === "disabled_reason" && !c.reason) throw new Error(`control-matrix: ${c.id} is disabled without a reason`);
  if (c.outcome === "unsupported" && !c.reason) throw new Error(`control-matrix: ${c.id} is unsupported without a recorded reason`);
  if ((c.outcome === "daemon_action" || c.outcome === "local_view") && !c.binding) throw new Error(`control-matrix: ${c.id} claims ${c.outcome} without a binding`);
}
