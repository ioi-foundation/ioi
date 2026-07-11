// Pipeline Builder — the first extracted app module (functional-runtime wave). The render/data
// code below is moved VERBATIM from serve-product-ui.mjs (zero behavior change by construction);
// this module adds only the surface contract the registry mounts:
//   meta            — code-side identity (joined with surface-registry.mjs + the parity matrix)
//   load(ctx)       — daemon-truth loaders (ctx.daemon = daemon base URL)
//   render(model, ctx) — pure HTML over the loaded model (ctx.url carries selection params)
//   actions         — empty until the command-discipline PR wires real authority
// Shell-pixel note: /__ioi/pipeline is a certified shell (pixel-certifications/pipeline.json);
// pixels are frozen by the harness gate, so edits here must re-certify.
import { bpIcon, PIPELINE_APP_ICON_URI, AIP_GRADIENT_SVG_TOOLBAR } from "../../scripts/bp-icons.mjs";
import { ioiGlobalRailHtml, IOI_GRAIL_CSS } from "../chrome.mjs";
import { escHtml } from "../kit.mjs";

const CX_ESC = escHtml; // local alias so the moved block stays byte-identical to its serve original

export const meta = {
  slug: "pipeline",
  route: "/__ioi/pipeline",
  verifier: "scripts/verify-hypervisor-app-parity-pipeline.mjs",
  certification: "pixel-certifications/pipeline.json",
};

// Daemon-truth loaders — the exact fetch set the serve's flat branch (then its #55 inline
// binding) performed; a dead daemon yields honest empty lists, never fabricated rows.
export async function load(ctx) {
  const J = (p) => fetch(`${ctx.daemon}${p}`).then((r) => r.json()).catch(() => ({}));
  const [o, ds, cm, pv, tr, op, lp, mr, cs, ms] = await Promise.all([
    J("/v1/hypervisor/odk/domain-ontologies"),
    J("/v1/hypervisor/data-sources"),
    J("/v1/hypervisor/odk/connector-mappings"),
    J("/v1/hypervisor/odk/policy-bound-data-views"),
    J("/v1/hypervisor/odk/transformation-runs"),
    J("/v1/hypervisor/odk/ontology-projections"),
    J("/v1/hypervisor/odk/capability-lease-plans"),
    J("/v1/hypervisor/odk/materializing-runs"),
    J("/v1/hypervisor/odk/connector-sessions"),
    J("/v1/hypervisor/odk/materialized-object-sets"),
  ]);
  return {
    ontologies: o.ontologies || [],
    data_sources: ds.data_sources || [],
    connector_mappings: cm.connector_mappings || [],
    policy_views: pv.policy_bound_data_views || [],
    transformation_runs: tr.transformation_runs || [],
    ontology_projections: op.ontology_projections || [],
    capability_lease_plans: lp.capability_lease_plans || [],
    materializing_runs: mr.materializing_runs || [],
    connector_sessions: cs.connector_sessions || [],
    materialized_sets: ms.materialized_object_sets || [],
  };
}

export function render(model, ctx) {
  return renderPipelineBuilder(model, ctx.url.searchParams.get("ontology") || "");
}

// No commands are wired yet: Build/Preview/Schedule/Deploy stay exactly as the certified shell
// renders them (the command-discipline PR gives them the authority-or-disabled contract).
export const actions = [];

// ============================ PIPELINE BUILDER (reference-UX parity over the ODK ladder) =========
// The Reference UX Port program (post-#31 reset), substrate for the Data Pipeline Builder. The reference
// capture (/__apps/pipeline, /workspace/builder/) is the FAMILIAR STARTING POINT; this IOI-owned
// surface renders the SAME builder grammar — a datasource → transform → output pipeline of nodes on
// a canvas, with a Build / Preview / Schedule / Deploy toolbar — but every node is DAEMON TRUTH: the
// landed ODK ladder for the selected ontology IS the pipeline. Supported lanes reflect real daemon
// state; unsupported builder lanes (freeform canvas authoring, drag-connect, transform code editor,
// schedule, deploy) are visible but honest named gaps. Reference-familiar UX; IOI truth underneath.
function pipeStatusPill(cls, label) {
  const c = cls === "live" ? "ok" : cls === "declared" ? "warn" : "muted";
  return `<span class="pill ${c}" style="margin:0">${CX_ESC(label)}</span>`;
}
// ============================ PIPELINE BUILDER — reference UX PORT (#32, first reference_ported shell).
// A PORTED reference builder shell, NOT the dark automationsShell: a source-neutral rebuild of the
// /workspace/builder/ layout — a full-height left RAIL (pipelines + stage palette), a HEADER bar, a
// graph TOOLBAR (Build/Preview/Schedule/Deploy — unsupported controls disabled IN PLACE, not hidden),
// a central CANVAS rendering the ODK authority ladder as connected pipeline node cards, a right
// OUTPUT PANEL (projection schema + output stats), and a bottom TRAY (preview rows + warnings). Every
// cell is REAL daemon truth. This is `reference_ported`, NOT `daemon_wired`: the local /workspace/
// builder/* reference currently ERRORS, so parity cannot yet be certified by the Playwright harness —
// daemon_wired awaits a valid (non-errored) builder reference to compare against.
function renderPipelineBuilder(lists, selectedId) {
  const ontologies = Array.isArray(lists.ontologies) ? lists.ontologies : [];
  const sets = Array.isArray(lists.materialized_sets) ? lists.materialized_sets : [];
  const builtRefs = new Set(sets.map((s) => s.ontology_ref));
  // Prefer an explicit selection; else a "built" pipeline (has a materialized set); else most recent.
  const selected = ontologies.find((x) => x.id === selectedId)
    || ontologies.find((x) => builtRefs.has(x.ref))
    || ontologies[0] || null;
  const oref = selected ? selected.ref : "__none__";
  const oid = selected ? selected.id : "";
  const F = (arr) => (Array.isArray(arr) ? arr : []).filter((x) => x.ontology_ref === oref);
  const maps = F(lists.connector_mappings), views = F(lists.policy_views), truns = F(lists.transformation_runs);
  const projs = F(lists.ontology_projections), plans = F(lists.capability_lease_plans), mruns = F(lists.materializing_runs);
  const sessions = F(lists.connector_sessions), osets = F(lists.materialized_sets);
  const dsIds = new Set(maps.map((m) => m.data_source_id).filter(Boolean));
  const dsources = (lists.data_sources || []).filter((d) => dsIds.has(d.source_id));
  const instances = osets.reduce((a, s) => a + (s.count || 0), 0);
  const anyReady = (arr, pred) => arr.filter(pred).length;

  // The pipeline nodes, in ODK-ladder order. Each node: real daemon state → live / declared / missing.
  const mk = (icon, label, kind, n, live, declared, count, detail, pane) => ({ icon, label, kind, n, cls: n === 0 ? "missing" : live ? "live" : declared ? "declared" : "declared", count, detail, pane });
  const nodes = [
    mk("🌐", "Datasource", "input", dsources.length, dsources.length > 0, true, dsources.length, dsources.map((d) => d.name || d.source_id).slice(0, 2).join(", "), "data"),
    mk("🔗", "Object mapping", "transform", maps.length, anyReady(maps, (m) => (m.health || {}).status === "ready") > 0, true, maps.length, "source fields → typed properties", "resources"),
    mk("🛡", "Policy gate", "transform", views.length, anyReady(views, (v) => (v.health || {}).status === "ready") > 0, true, views.length, "capability envelope", "resources"),
    mk("📋", "Transform plan", "transform", truns.length, anyReady(truns, (r) => r.status === "dry_run_ready") > 0, true, truns.length, "dry-run validated", "resources"),
    mk("🔭", "Read projection", "transform", projs.length, anyReady(projs, (p) => p.status === "ready") > 0, true, projs.length, "explorer/search shape", "resources"),
    mk("🎟", "Lease + session", "authority", plans.length, anyReady(mruns, (r) => ["lease_obtained", "executed"].includes(r.status)) > 0 && anyReady(sessions, (c) => c.status === "session_obtained") > 0, plans.length > 0, plans.length, `${anyReady(mruns, (r) => ["lease_obtained", "executed"].includes(r.status))} lease · ${anyReady(sessions, (c) => c.status === "session_obtained")} session`, "resources"),
    mk("📦", "Materialized objects", "output", osets.length, instances > 0, osets.length > 0, instances, `${instances} object instance${instances === 1 ? "" : "s"}`, "explorer"),
  ];
  const enc = encodeURIComponent, esc = CX_ESC;
  const oname = selected ? esc(selected.domain || selected.id) : "no pipeline";

  // Preview + output projection (daemon truth) — feeds the bottom tray + right output panel.
  const proj = projs.find((p) => p.status !== "retired") || projs[0] || null;
  const mset = osets.find((s) => proj && s.ontology_projection_id === proj.id) || osets[0] || null;
  const cols = proj ? (proj.visible_properties || []) : [];
  const previewTable = proj
    ? `<table class="pb-table"><thead><tr>${cols.map((c) => `<th>${esc(c)}</th>`).join("")}</tr></thead><tbody>${(mset && (mset.objects || []).length)
        ? mset.objects.slice(0, 12).map((o) => `<tr>${cols.map((c) => `<td>${esc(String((o.properties || {})[c] ?? ""))}</td>`).join("")}</tr>`).join("")
        : `<tr><td colspan="${cols.length || 1}" class="pb-empty-cell">No rows yet — Build a materializing run to populate this output (object_instances stays 0 until then).</td></tr>`}</tbody></table>`
    : `<div class="pb-empty">No read projection on this pipeline yet — add one in the Ontology Manager.</div>`;

  // ---- SHARED pixel-aligned GLOBAL RAIL (#43) — Pipeline Builder active. The live pipeline PICKER
  // (no reference counterpart in the rail) lives in the canvas body (excluded region), keeping the rail
  // pixel-faithful while the control keeps its function.
  const globalRail = ioiGlobalRailHtml({ label: "Pipeline Builder", href: "/__ioi/pipeline", iconUri: PIPELINE_APP_ICON_URI, railVariant: "rv-pipe", viewAll: false, star: false, badges: true, aipGradient: true, acctMuted: true });
  const railPipes = ontologies.length
    ? ontologies.map((x) => { const on = selected && x.id === selected.id; const built = builtRefs.has(x.ref); return `<a class="pb-pipe ${on ? "on" : ""}" href="/__ioi/pipeline?ontology=${enc(x.id)}">${esc(x.domain || x.id)}${built ? `<span class="pb-tag">built</span>` : ""}</a>`; }).join("")
    : `<div class="pb-empty">No pipelines yet. <a href="/__ioi/odk/ontologies/new">Create an ontology</a>.</div>`;
  const nodeCard = (nd) => `<div class="pb-node pb-${nd.cls}"${selected ? ` onclick="location.href='/__ioi/odk?ontology=${enc(oid)}#pane-${nd.pane}'"` : ""}>
    <div class="pb-nhead"><span class="pb-nicon">${nd.icon}</span><span class="pb-dot pb-${nd.cls}"></span></div>
    <div class="pb-nlabel">${esc(nd.label)}</div>
    <div class="pb-ncount"><b>${esc(String(nd.count))}</b> ${nd.kind === "output" ? "objects" : nd.kind === "input" ? "source" + (nd.count === 1 ? "" : "s") : "record" + (nd.count === 1 ? "" : "s")}</div>
    <div class="pb-ndetail">${esc(nd.detail || "")}</div>
  </div>`;
  const legendGroups = [
    ["Input Data", "#8f99a8", dsources.length],
    ["Data Cleaning", "#238551", maps.length + views.length],
    ["Calculations", "#d1980b", truns.length + projs.length + plans.length],
    ["Output Dataset", "#147eb3", osets.length],
  ];

  // ---- HEADER (h51, white, hairline shadow) — the reference navbar: app chip · breadcrumb title row
  // (live names → masked as dynamic data) + File/Settings/Help menu row (named gaps) + Batch tag · a
  // FLUID MIDDLE zone that in the reference carries captured SESSION STATE (tabs/undo/branch/build
  // state — masked as dynamic residue) and in the port carries the LIVE Build/Preview controls · right
  // cluster Actions ▾ / Share / panel toggle (named gaps).
  const header = `<header class="pb-header">
    <span class="pb-hchip"></span>
    <div class="pb-htitles">
      <div class="pb-crumbrow"><span class="pb-crumb">${oname} <span class="pb-cx">›</span> <b>Pipeline Builder</b>${selected ? ` <span class="pb-cxt">— ${instances > 0 ? `<span class="pb-live">built</span>` : `<span class="pb-declared">not built</span>`} · ${nodes.filter((n) => n.cls === "live").length}/${nodes.length} stages live</span>` : ""}</span><span class="pb-star">${bpIcon("star-empty")}</span></div>
      <div class="pb-menurow">
        <span class="pb-menu gap" title="File menu is a reference-only lane (named gap)">File ${bpIcon("caret-down", 16)}</span>
        <span class="pb-menu gap" title="named gap">Settings ${bpIcon("caret-down", 16)}</span>
        <span class="pb-menu gap" title="named gap">Help ${bpIcon("caret-down", 16)}</span>
        <span class="pb-menudiv"></span>
        <span class="pb-batch">${bpIcon("office", 16)}<span class="pb-batchn">1</span></span>
        <span class="pb-menudiv d2"></span>
        <span class="pb-batchtag">Batch</span>
      </div>
    </div>
    <div class="pb-hmid">
      <a class="pb-btn primary" href="/__ioi/odk?ontology=${enc(oid)}">Build</a>
      <a class="pb-btn ghost" href="#pb-preview">Preview</a>
      <button class="pb-btn ghost" disabled title="No pipeline scheduler yet — a named gap (author + run via a materializing run).">Schedule</button>
      <button class="pb-btn ghost" disabled title="No pipeline deploy yet — a named gap.">Deploy</button>
      <a class="pb-btn link" href="/__ioi/lineage?ontology=${enc(oid)}">Lineage</a>
      <a class="pb-btn link" href="/__ioi/odk?ontology=${enc(oid)}">Ontology Manager</a>
    </div>
    <div class="pb-hright">
      <span class="pb-hbtn gap" title="Actions menu is a reference-only lane (named gap)">Actions ${bpIcon("caret-down")}</span>
      <span class="pb-hdrdiv"></span>
      <span class="pb-hbtn gap" title="Sharing is a reference-only lane (named gap)">${bpIcon("people")} Share</span>
      <span class="pb-hico gap" title="Panel layout toggle — named gap">${bpIcon("properties")}</span>
    </div>
  </header>`;

  // ---- FLOATING TOOL CARD (canvas top-left) — the reference's grouped canvas tools as GROUP UNITS in a
  // wrapping flex card: at 1440 the groups wrap to three rows exactly like the reference; at 1920 they
  // fit one row. All named gaps except Add data (routes to the real authoring ladder).
  const tbtn = (icon, opts = {}) => `<${opts.href ? `a href="${opts.href}"` : "button disabled"} class="pb-ticon${opts.look ? " " + opts.look : ""}${opts.tint ? " pb-i-" + opts.tint : ""}" title="${esc(opts.title || "named gap")}">${icon === "@aip-grad" ? AIP_GRADIENT_SVG_TOOLBAR : bpIcon(icon)}${opts.href ? "</a>" : "</button>"}`;
  const seg = (...btns) => `<span class="pb-seg">${btns.join("")}</span>`;
  const toolcard = `<div class="pb-toolcard">
    <div class="pb-tg">
      <div class="pb-tgrow">${seg(tbtn("move", { look: "act" }), tbtn("select"))}${seg(tbtn("selection"))}${seg(tbtn("graph-remove", { look: "dim" }))}${seg(tbtn("layout-sorted-clusters"), tbtn("grid"))}${seg(tbtn("new-text-box"))}</div>
      <div class="pb-tghints"><span style="left:15.5px">Tools</span><span style="left:72.3px">Select</span><span class="pb-hwrap" style="left:115px">Remove</span><span style="left:175.5px">Layout</span><span style="left:242px">Text</span></div>
    </div>
    <div class="pb-tg pb-tg2">
      <a class="pb-twide" href="/__ioi/odk?ontology=${enc(oid)}" title="Add data — routes to the real ODK authoring ladder">${bpIcon("import")} Add data ${bpIcon("caret-down")}</a>
      <button class="pb-twide" disabled title="Reusable transforms library — a named gap">${bpIcon("repeat")} Reusables ${bpIcon("caret-down")}</button>
    </div>
    <div class="pb-tg pb-tg3">
      <div class="pb-tgrow">${seg(tbtn("path", { look: "dim", tint: "blue" }), tbtn("join-table", { look: "dim", tint: "cyan" }), tbtn("add-row-bottom", { look: "dim", tint: "rose" }), tbtn("split-columns", { look: "dim", tint: "green" }), tbtn("model", { look: "dim", tint: "violet" }))}${seg(tbtn("@aip-grad", { look: "dim" }), tbtn("clean", { tint: "violet" }), tbtn("lightbulb", { tint: "violet" }))}${seg(tbtn("edit", { look: "dim" }))}</div>
      <div class="pb-tghints"><span style="left:45.9px">Transform</span><span style="left:195.3px">AIP</span><span style="left:268.7px">Edit</span></div>
    </div>
  </div>`;

  // ---- FLOATING canvas buttons (search / fit) + ZOOM stack (bottom-left) — reference chrome, named gaps.
  const floatbtns = `<div class="pb-floatbtns">${tbtn("search")}${tbtn("many-to-many")}</div>
  <div class="pb-zoomstack">${tbtn("zoom-in")}${tbtn("zoom-out")}${tbtn("zoom-to-fit")}</div>`;

  // ---- LEGEND card (canvas top-right, left of the outputs panel) — live category counts masked as data.
  const legend = `<div class="pb-legend">
    <div class="pb-legendhd">Legend <span class="pb-legcaret">${bpIcon("caret-up")}</span></div>
    <div class="pb-leggrid">
      ${legendGroups.map(([g, c, n]) => `<div class="pb-legrow"><span class="pb-legchip" style="background:${c}"></span><span class="pb-legname">${esc(g)}</span> <b>(${n})</b> <span class="pb-legeye">${bpIcon("eye-open", 14)}</span></div>`).join("")}
    </div>
    <button class="pb-addcolor" disabled title="Legend color authoring — a named gap">${bpIcon("plus")} Add color</button>
  </div>`;

  const canvasWrap = `<div class="pb-canvaszone">
    <div class="pb-toolband" role="toolbar" aria-label="Canvas tools"></div>
    ${toolcard}
    ${floatbtns}
    ${legend}
    <div class="pb-canvas" id="pb-canvas">${selected
      ? `<div class="pb-pickrow"><details class="pb-pick"><summary>Pipeline: ${oname} ▾</summary><div class="pb-picklist">${railPipes}</div></details></div><div class="pb-flow">${nodes.map((nd, i) => `${i ? `<div class="pb-arrow">→</div>` : ""}${nodeCard(nd)}`).join("")}</div>`
      : `<div class="pb-empty" style="margin:120px auto;max-width:420px">Select or create a pipeline to see its datasource → transform → output graph. <a href="/__ioi/odk/ontologies/new">Create an ontology →</a></div>`}</div>
    <div class="pb-tray" id="pb-preview">
      <div class="pb-traytabs">
        <span class="pb-tab on">${bpIcon("panel-table")} Selection preview</span>
        <span class="pb-tab s2">${bpIcon("clean")} Suggestions<span class="pb-tabpill" title="suggestions count — reference-only lane"></span></span>
        <span class="pb-tab warn">${bpIcon("warning-sign")} Pipeline warnings</span>
        <span class="pb-traycollapse">${bpIcon("double-chevron-down")}</span>
      </div>
      <div class="pb-traybody">${previewTable}
        <div class="pb-gapnote">Freeform canvas authoring — drag-connect nodes, transform code editor, scheduling, deploy — are <b>reference-only lanes disabled above</b>, not yet wired. Author stages in the <a href="/__ioi/odk?ontology=${enc(oid)}">Ontology Manager</a>; execute via a materializing run. Reference: <a href="/__apps/pipeline">Pipeline Builder capture ↗</a>.</div>
      </div>
    </div>
  </div>`;

  // ---- RIGHT "Pipeline outputs" PANEL (w386 = 336 content + 50 icon strip) — live projection values
  // masked as data; Output settings block bottom-anchored like the reference.
  const mapped = cols.length;
  const stripIcons = ["circle-arrow-right", "search", "split-view", "build", "settings", "calendar", "folder-open", "form", "import"];
  const rightPanel = `<aside class="pb-right">
    <div class="pb-rmain">
      <div class="pb-righthd"><span class="pb-righttitle">Pipeline outputs</span><span class="pb-rhdico gap">${bpIcon("cog")}</span><span class="pb-rhdico gap">${bpIcon("panel-table")}</span><button class="pb-addbtn" disabled title="Adding outputs is authored in the ODK substrate — a named gap here">${bpIcon("plus")} Add</button></div>
      <div class="pb-rsearch">${bpIcon("search")}<input placeholder="Search outputs…" disabled aria-label="Search outputs (reference-only, not wired)"></div>
      ${proj ? `<div class="pb-outcard"><div class="pb-outcode">${bpIcon("panel-table")} ${esc(proj.name || proj.id)}</div><div class="pb-outsub">${esc(selected ? (selected.domain || selected.id) : "")} · read projection</div><div class="pb-outmapped">✓ ${mapped}/${mapped} column${mapped === 1 ? "" : "s"} mapped</div></div>` : `<div class="pb-empty">No read projection on this pipeline yet.</div>`}
      <div class="pb-outstat">${instances} object instance${instances === 1 ? "" : "s"} materialized · ${nodes.filter((n) => n.cls === "missing").length ? nodes.filter((n) => n.cls === "missing").map((n) => esc(n.label) + " not built").join(" · ") : "all ladder stages present"}</div>
      <div class="pb-settings">
        <div class="pb-outboxt">Output settings</div>
        <div class="pb-setrow"><span class="pb-setk">Target ontology</span><span class="pb-setv">${selected ? esc(selected.domain || selected.id) : "No ontology selected"}</span></div>
        <div class="pb-setrow"><span class="pb-setk">Output folder</span><span class="pb-setv">No location selected</span></div>
        <div class="pb-editrow"><a class="pb-editbtn" href="/__ioi/odk?ontology=${enc(oid)}">Edit output settings</a><span class="pb-moreico gap">${bpIcon("more")}</span></div>
      </div>
    </div>
    <div class="pb-rstrip">${stripIcons.map((ic, i) => `<span class="pb-stripico${i === 0 ? " on" : ""}${i && i % 3 === 0 ? " g" : ""} gap" title="Right-panel lane — named gap">${bpIcon(ic)}</span>`).join("")}</div>
  </aside>`;

  // LIGHT application surface, geometry pinned to the reference (glyph-anchored): header h51 · toolcard
  // groups h55 wrapping at the reference's break points · Legend/right panel right-anchored · tray
  // bottom-anchored (vh-300). The harness certifies the SHELL cards; the canvas/graph is the live body.
  const css = `:root{color-scheme:light}*{box-sizing:border-box}
    body{margin:0;background:#f6f7f9;color:#1c2127;font:14px/1.28581 Source-Sans-Pro,Helvetica,sans-serif}
    a{color:#215db0;text-decoration:none}
    .pb-shell{display:flex;height:100vh;width:100vw;overflow:hidden}
    ${IOI_GRAIL_CSS}
    .pb-main{flex:1;min-width:0;display:flex;flex-direction:column;height:100vh}
    .pb-header{flex:0 0 51px;position:relative;height:51px;display:flex;align-items:stretch;background:#fff;box-shadow:0 1px 0 0 #dce0e5;z-index:6}
    .pb-hchip{width:50px;height:51px;flex:0 0 50px;background:rgba(90,217,207,.1) url('${PIPELINE_APP_ICON_URI}') center no-repeat}
    .pb-htitles{display:flex;flex-direction:column;padding:4px 0 0 15px;min-width:0}
    .pb-crumbrow{display:flex;align-items:center;gap:8px;height:20px}
    .pb-crumb{font-size:14px;color:#1c2127;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:350px;line-height:16px}
    .pb-cx{color:#8b9099}.pb-cxt{color:#5f6b7c;font-size:12px}
    .pb-star{position:absolute;left:431.4px;top:6.5px;display:inline-flex;color:#5f6b7c;width:16px}
    .pb-menurow{display:flex;align-items:center;height:26px;gap:0;margin:-1px 0 0 -7px}
    .pb-menu{display:inline-flex;align-items:center;gap:8px;font-size:14px;line-height:16.1px;color:#1c2127;padding:0 5px 0 7px;cursor:default}
    .pb-menu svg{color:#5f6b7c}
    .pb-menudiv{width:1px;height:16px;background:#d3d8de;margin-left:5px}
    .pb-menudiv.d2{margin-left:8px}
    .pb-batch{display:inline-flex;align-items:center;gap:3px;margin-left:11px;color:#5f6b7c;font-size:12px}
    .pb-batch svg{color:#404854}
    .pb-batchn{font-size:12px;color:#1c2127}
    .pb-batchtag{margin-left:5.6px;background:#5f6b7c;color:#fff;font-size:12px;line-height:16px;border-radius:3px;padding:2px 4px}
    .pb-hmid{position:absolute;left:468px;top:0;width:494px;height:51px;display:flex;align-items:center;gap:7px;overflow:hidden}
    .pb-btn{display:inline-flex;align-items:center;height:28px;padding:0 10px;border-radius:4px;border:1px solid #d3d8de;background:#fff;color:#1c2127;font:inherit;font-size:13px;line-height:16px;font-weight:400;cursor:pointer}
    .pb-btn.primary{background:#0e9f6e;color:#fff;border-color:#0e9f6e}
    .pb-btn.link{border-color:transparent;background:transparent;color:#215db0;padding:0 5px}
    .pb-btn[disabled]{opacity:.5;cursor:not-allowed}
    .pb-hright{margin-left:auto;display:flex;align-items:flex-start;gap:0;padding-right:20px}
    .pb-hbtn{display:inline-flex;align-items:center;gap:8px;height:30px;margin-top:10px;padding:0 12px;border-radius:4px;font-size:14px;line-height:16px;color:#1c2127;cursor:default}
    .pb-hdrdiv{width:1px;height:30px;background:#d3d8de;margin:10px 0 0 6.6px}
    .pb-hdrdiv+.pb-hbtn{margin-left:5.4px}
    .pb-hbtn svg{color:#5f6b7c}
    .pb-hico{display:inline-flex;align-items:center;justify-content:center;width:30px;height:30px;margin:10px 0 0 2px;color:#5f6b7c;cursor:default}
    .pb-work{flex:1 1 auto;display:flex;min-height:0}
    .pb-canvaszone{flex:1 1 auto;min-width:0;position:relative;background:#edeff2;overflow:hidden}
    .pb-toolband{position:absolute;left:10px;top:10px;width:414px;height:165px;pointer-events:none}
    @media(min-width:1600px){.pb-toolband{width:872px;height:56px}.pb-tg2{margin-left:30px}.pb-tg3{margin-left:15px}.pb-tghints span.pb-hwrap{width:auto;white-space:nowrap}}
    .pb-toolcard{position:absolute;left:10px;top:10px;display:flex;flex-wrap:wrap;width:fit-content;max-width:calc(100% - 424px);background:#fff;border-radius:3px;box-shadow:0 1px 3px rgba(20,24,30,.12);z-index:4}
    .pb-tg{position:relative;height:55px;padding:0}
    .pb-tgrow{display:flex;align-items:center;height:30px;margin-top:0;gap:15px}
    .pb-seg{display:inline-flex}
    .pb-seg .pb-ticon+.pb-ticon{margin-left:-1px}
    .pb-seg .pb-ticon{border-radius:0}.pb-seg .pb-ticon:first-child{border-radius:4px 0 0 4px}.pb-seg .pb-ticon:last-child{border-radius:0 4px 4px 0}.pb-seg .pb-ticon:only-child{border-radius:4px}
    .pb-ticon{display:inline-flex;align-items:center;justify-content:center;width:30px;height:30px;border:0;background:#f7f8f8;color:#5f6b7c;border-radius:4px;padding:0;cursor:default;box-shadow:inset 0 0 0 1px rgba(64,72,84,.33),0 1px 2px rgba(17,20,24,.1)}
    .pb-ticon.act{background:#dfe0e2;box-shadow:inset 0 0 0 1px rgba(64,72,84,.33),0 1px 2px rgba(17,20,24,.2)}
    .pb-ticon.dim{background:rgba(143,153,168,.2);box-shadow:none;color:#8f99a8}
    a.pb-ticon{cursor:pointer}
    .pb-ticon[disabled]{opacity:1}
    .pb-tghints{position:relative;height:19px;font-size:12px;line-height:15px;color:#5f6b7c}
    .pb-tghints span{position:absolute;top:4px;white-space:nowrap}
    .pb-tghints span.pb-hwrap{white-space:normal;width:46px;text-align:center;line-height:15.4297px}
    .pb-tg2{display:flex;align-items:flex-start;gap:15px;padding:0}
    .pb-twide{display:inline-flex;align-items:center;gap:8px;height:30px;padding:0 8px;border:0;border-radius:4px;background:#f7f8f8;color:#1c2127;font:inherit;font-size:14px;line-height:16px;box-shadow:inset 0 0 0 1px rgba(64,72,84,.33),0 1px 2px rgba(17,20,24,.1)}
    .pb-twide svg{color:#5f6b7c}
    .pb-twide[disabled]{cursor:not-allowed}
    .pb-i-blue svg{color:#4c90f0}.pb-i-cyan svg{color:#3fa6da}.pb-i-rose svg{color:#db2c6f}.pb-i-green svg{color:#32a467}.pb-i-violet svg{color:#7961db}
    .pb-floatbtns{position:absolute;right:330px;top:10px;display:flex;gap:10px;z-index:4}
    .pb-zoomstack .pb-ticon+.pb-ticon{margin-top:-1px}
    .pb-zoomstack .pb-ticon:first-child{border-radius:4px 4px 0 0}.pb-zoomstack .pb-ticon:nth-child(2){border-radius:0}.pb-zoomstack .pb-ticon:last-child{border-radius:0 0 4px 4px}
    .pb-zoomstack{position:absolute;left:10px;bottom:310px;display:flex;flex-direction:column;z-index:4}
    .pb-legend{position:absolute;right:7px;top:9px;width:314px;background:#f6f7f9;border:1px solid #cbccd0;border-radius:3px;padding:0 10px 8px;z-index:4}
    .pb-legendhd{display:flex;align-items:center;justify-content:space-between;height:30px;font-size:14px;line-height:16px;color:#1c2127;padding:0;margin:0 0 0 -2px}
    .pb-legcaret{display:inline-flex;color:#5f6b7c}
    .pb-leggrid{display:grid;grid-template-columns:1fr 1fr;gap:0 8px;margin-top:2px}
    .pb-legrow{display:flex;align-items:center;gap:5px;height:29px;font-size:12px;line-height:15.4297px;color:#1c2127}
    .pb-legchip{width:14px;height:14px;border-radius:3px;flex:0 0 14px}
    .pb-legname{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:70px}
    .pb-legeye{display:inline-flex;color:#5f6b7c;margin:0 7px 0 auto}
    .pb-addcolor{display:flex;align-items:center;justify-content:center;gap:7.5px;width:140px;height:24px;margin:4.5px 2px 0 auto;padding:0;border:1px solid rgba(33,93,176,.6);border-radius:4px;background:transparent;color:#215db0;font:inherit;font-size:12px;line-height:13.8px;cursor:not-allowed}
    .pb-canvas{position:absolute;inset:51px 0 300px 0;overflow:auto;padding:60px 20px 20px}
    .pb-pickrow{margin:110px 0 14px}
    .pb-pick{position:relative;display:inline-block}
    .pb-pick>summary{list-style:none;cursor:pointer;font-size:13px;color:#5f6b7c;background:#fff;border:1px solid #d3d8de;border-radius:4px;padding:4px 10px}
    .pb-pick>summary::-webkit-details-marker{display:none}
    .pb-picklist{position:absolute;top:32px;left:0;min-width:240px;background:#fff;border:1px solid #e0e3e8;border-radius:8px;box-shadow:0 8px 28px rgba(20,24,31,.14);padding:6px;z-index:20}
    .pb-pipe{display:flex;align-items:center;justify-content:space-between;padding:6px 9px;border-radius:6px;color:#3a3f46}
    .pb-pipe:hover{background:#f1f3f6}.pb-pipe.on{background:#eef2fb;color:#1a1d21;font-weight:600}
    .pb-tag{font-size:10px;padding:1px 6px;border-radius:999px;background:#eafaf1;color:#0e8a53;border:1px solid #8fdcb6}
    .pb-flow{display:flex;align-items:stretch;gap:0}
    .pb-arrow{flex:0 0 auto;color:#a9b0bb;padding:0 8px;font-size:17px;align-self:center}
    .pb-node{flex:0 0 auto;width:156px;border:1px solid #dfe2e7;border-radius:6px;padding:11px 12px;background:#fff;cursor:pointer;box-shadow:0 1px 3px rgba(20,24,30,.05)}
    .pb-node:hover{border-color:#0e9f6e}
    .pb-node.pb-live{border-top:3px solid #2f9e6b}.pb-node.pb-declared{border-top:3px solid #d68a2a}.pb-node.pb-missing{border-top:3px solid #c2c6cd}
    .pb-nhead{display:flex;align-items:center;justify-content:space-between}.pb-nicon{font-size:18px}
    .pb-nlabel{font-weight:600;font-size:13px;margin:5px 0 6px;color:#15181d}
    .pb-dot{width:8px;height:8px;border-radius:50%;background:#b8bdc6}.pb-dot.pb-live{background:#2f9e6b}.pb-dot.pb-declared{background:#d68a2a}
    .pb-ncount{font-size:12px;color:#3a3f49}.pb-ndetail{font-size:10.5px;color:#8a909c;margin:3px 0 0;min-height:14px}
    .pb-tray{position:absolute;left:0;right:0;bottom:0;height:300px;background:#fff;display:flex;flex-direction:column;z-index:5}
    .pb-traytabs{flex:0 0 35px;display:flex;align-items:stretch}
    .pb-tab{display:inline-flex;align-items:center;gap:5px;padding:0 8px;font-size:14px;line-height:16px;font-weight:600;color:#1c2127;border-right:1px solid #dce0e5}
    .pb-tab.s2 svg{color:#7961db}
    .pb-tabpill{width:20px;height:20px;border-radius:4px;background:rgba(143,153,168,.15)}
    .pb-tab svg{color:#5f6b7c}
    .pb-tab.on{background:rgba(138,187,255,.4);color:#215db0}.pb-tab.on svg{color:#215db0}
    .pb-tab.warn{color:#935610}.pb-tab.warn svg{color:#c87619}
    .pb-traycollapse{margin-left:auto;display:inline-flex;align-items:center;padding:0 14px;color:#5f6b7c}
    .pb-traybody{flex:1;overflow:auto;padding:12px 16px}
    .pb-table{border-collapse:collapse;width:100%;font-size:12px}.pb-table th{text-align:left;color:#7b8494;font-weight:600;padding:4px 12px 4px 0;border-bottom:1px solid #e2e4e8}
    .pb-table td{padding:4px 12px 4px 0;border-bottom:1px solid #f0f1f4;color:#2a2f38}
    .pb-empty-cell{text-align:center;color:#8a909c;padding:16px 8px}
    .pb-empty{color:#7b8494;padding:14px;border:1px dashed #d8dbe1;border-radius:10px;background:#fbfbfc}
    .pb-gapnote{margin:12px 0 0;padding:10px 12px;border:1px solid #e5e7eb;border-radius:9px;background:#f7f8fa;color:#5b6270;font-size:11.5px;line-height:1.6}
    .pb-right{flex:0 0 386px;width:386px;display:flex;background:#fff;border-left:1px solid #dce0e5}
    .pb-rmain{flex:1 1 auto;min-width:0;display:flex;flex-direction:column;padding:0 0 9px}
    .pb-righthd{display:flex;align-items:center;height:auto;padding:6.5px 9px 0 7px}
    .pb-righttitle{font-size:14px;line-height:18.0013px;font-weight:600;color:#1c2127;flex:1}
    .pb-rhdico{display:inline-flex;color:#5f6b7c;padding:0 7px;cursor:default}
    .pb-addbtn{display:inline-flex;align-items:center;gap:8px;height:30px;margin-left:11px;padding:0 8px;border:0;border-radius:4px;background:#f7f8f8;color:#1c2127;font:inherit;font-size:14px;line-height:16px;cursor:not-allowed;box-shadow:inset 0 0 0 1px rgba(64,72,84,.33),0 1px 2px rgba(17,20,24,.1)}
    .pb-rsearch{display:flex;align-items:center;gap:7px;height:30px;margin:15.5px 10px 0 7px;border:0;border-radius:4px;background:#fff;padding:0 8px;color:#5f6b7c;box-shadow:inset 0 0 0 1px rgba(17,20,24,.2),inset 0 1px 1px rgba(17,20,24,.3)}
    .pb-rsearch input{flex:1;border:0;background:transparent;font:inherit;font-size:14px;line-height:16px;color:#1c2127;outline:none;padding:0}
    .pb-rsearch input::placeholder{color:#5f6b7c}
    .pb-outcard{margin:12px 8px 0;border:1px solid #e5e7eb;border-radius:3px;padding:9px 10px;background:#fff}
    .pb-outcode{display:flex;align-items:center;gap:7px;font-size:14px;line-height:16px;color:#215db0;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .pb-outcode svg{color:#2d72d2;flex:0 0 16px}
    .pb-outsub{font-size:12px;color:#5f6b7c;margin:3px 0 0 23px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .pb-outmapped{font-size:12px;color:#0e8a53;margin:6px 0 0 23px}
    .pb-outstat{margin:10px 8px 0;font-size:12px;color:#5f6b7c}
    .pb-settings{margin-top:auto;padding:12px 10px 0 8px;border-top:1px solid #eef0f2}
    .pb-outboxt{font-size:14px;line-height:18.0013px;font-weight:600;color:#1c2127;margin:0 0 10px}
    .pb-setrow{display:flex;gap:10px;font-size:12px;line-height:15.4297px;color:#1c2127;padding:0 0 8px}
    .pb-setk{color:#5f6b7c;width:96px;flex:0 0 96px}
    .pb-setv{font-style:italic;color:#5f6b7c;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .pb-editrow{display:flex;align-items:center;gap:0;margin-top:2px}
    .pb-editbtn{flex:1;display:inline-flex;align-items:center;justify-content:center;height:30px;border:0;border-radius:4px 0 0 4px;background:#f7f8f8;color:#1c2127;font-size:14px;line-height:16px;box-shadow:inset 0 0 0 1px rgba(64,72,84,.33),0 1px 2px rgba(17,20,24,.1)}
    .pb-moreico{display:inline-flex;align-items:center;justify-content:center;width:30px;height:30px;border:0;border-radius:0 4px 4px 0;color:#5f6b7c;background:#f7f8f8;box-shadow:inset 0 0 0 1px rgba(64,72,84,.33),0 1px 2px rgba(17,20,24,.1)}
    .pb-rstrip{flex:0 0 50px;width:50px;background:#fff;border-left:1px solid #e2e4e8;display:flex;flex-direction:column;align-items:center;padding:5px 0;gap:5px}
    .pb-stripico{display:inline-flex;align-items:center;justify-content:center;width:40px;height:40px;border-radius:4px;color:#5f6b7c}
    .pb-stripico.g{margin-top:14px;position:relative}
    .pb-stripico.g::before{content:"";position:absolute;top:-7.5px;left:0;width:40px;height:1px;background:#d8dbde}
    .pb-stripico.on{background:#dfe0e1}`;

  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Pipeline Builder</title><style>${css}</style></head>
    <body><div class="pb-shell">${globalRail}<div class="pb-main">${header}<div class="pb-work">${canvasWrap}${rightPanel}</div></div></div></body></html>`;
}
