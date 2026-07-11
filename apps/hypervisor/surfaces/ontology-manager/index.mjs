// Ontology Manager — extracted app module (Ontology Application Runtime wave). The render code
// below is moved VERBATIM from serve-product-ui.mjs (zero behavior change by construction); the
// module adds only the surface contract the registry mounts. /__ioi/ontology/manager is a
// certified shell (pixel-certifications/schema.json) — pixels are frozen by the harness gate.
import { bpIcon, ONTOLOGY_APP_ICON_URI } from "../../scripts/bp-icons.mjs";
import { ioiGlobalRailHtml, IOI_GRAIL_CSS } from "../chrome.mjs";
import { escHtml } from "../kit.mjs";
import { loadOntologyModel } from "../ontology-context.mjs";

const CX_ESC = escHtml; // local alias so the moved block stays byte-identical to its serve original

export const meta = {
  slug: "schema",
  route: "/__ioi/ontology/manager",
  verifier: "scripts/verify-hypervisor-app-parity-ontology-manager.mjs",
  certification: "pixel-certifications/schema.json",
};

export async function load(ctx) {
  return loadOntologyModel(ctx.daemon);
}

export function render(model, ctx) {
  return renderOntologyManagerPort(model.overview, model.lists, ctx.url.searchParams.get("ontology") || "");
}

// Inspection-first: authoring stays in the ODK substrate; interactive selection arrives with the
// Manager-interaction PR under the command-discipline contract.
export const actions = [];

// ============================ ONTOLOGY MANAGER — reference UX PORT (#34, daemon_wired).
// A FAITHFUL source-neutral port of the reference Ontology Manager UX (NOT a dark native redesign):
//   - a DARK global platform RAIL (source-neutral IOI nav: Home/Search/…/Applications · Ontology Manager)
//   - a LIGHT app RAIL: Discover / Proposals / History · Resources (Object types · Properties · Link
//     types · Action types · Value types · Functions) · Health issues / Cleanup / Ontology configuration
//   - a LIGHT HEADER: app title · ontology switcher · "Search resources…" · New
//   - a LIGHT card-first BODY: "Object types recently modified" as object-type CARDS, then the typed
//     schema detail + configuration below.
// Light theme + card-first IA + the reference's landmark labels — matched so the HARDENED harness
// (theme + IA landmarks + region geometry, #34 review) can certify visual parity. Wired to the REAL
// ODK CanonicalObjectModel; READ-ONLY (authoring + object materialization stay in /__ioi/odk).


function renderOntologyManagerPort(ov, lists, selectedId) {
  const enc = encodeURIComponent, esc = CX_ESC;
  const o = ov || {};
  const ontologies = Array.isArray(lists.ontologies) ? lists.ontologies : [];
  const selected = ontologies.find((x) => x.id === selectedId) || ontologies.find((x) => (x.health || {}).status === "ready") || ontologies[0] || null;
  const com = (selected && selected.canonical_object_model) || {};
  const arr = (k) => (Array.isArray(com[k]) ? com[k] : []);
  const vts = arr("value_types"), ots = arr("object_types"), lts = arr("link_types"), ats = arr("action_types");
  const funcs = ats.filter((a) => a.kind === "function"), nonFuncActs = ats.filter((a) => a.kind !== "function");
  const health = (selected && selected.health) || {};
  const msets = (lists.materialized_sets || []).filter((m) => selected && m.ontology_ref === selected.ref);
  const projs = (lists.projections || []).filter((p) => selected && p.ontology_ref === selected.ref);
  const totalInstances = msets.reduce((a, m) => a + (m.count || 0), 0);
  const propCount = ots.reduce((n, x) => n + (Array.isArray(x.properties) ? x.properties.length : 0), 0);
  const rollup = o.ontology_health || {};
  const idc = (x) => `<code class="om-code">${esc(x || "")}</code>`;
  const hstate = health.status || "empty";
  const hpill = `<span class="om-pill ${hstate === "ready" ? "ok" : hstate === "empty" ? "muted" : "warn"}">${esc(hstate)}</span>`;

  const oid = selected ? selected.id : "";
  const domainLabel = selected ? esc(selected.domain || selected.id) : "no ontology";
  const objsOf = (t) => msets.filter((m) => m.object_type_id === t.id).reduce((a, m) => a + (m.count || 0), 0);
  const depsOf = (t) => lts.filter((l) => l.from === t.id || l.to === t.id).length;
  const svg = (p) => `<svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">${p}</svg>`;
  const CUBE = '<path d="M12 2l9 5v10l-9 5-9-5V7z"/>';

  // DARK global platform rail — the SHARED pixel-aligned reference shell (ioiGlobalRailHtml).
  const globalRail = ioiGlobalRailHtml({ label: "Ontology Manager", href: "/__ioi/ontology/manager", iconUri: ONTOLOGY_APP_ICON_URI });

  // LIGHT header — the reference navbar layout: app-icon chip · title · centered Search-resources input
  // (ctrl+K) · branch selector (named gap) · New. The ONTOLOGY SWITCHER (a live control with no reference
  // counterpart in the navbar) lives in the BODY section heading — the shell stays pixel-faithful while
  // the live control keeps its function where the ontology name already appears.
  const header = `<header class="og-header">
    <span class="og-hchip"></span>
    <h5 class="og-htitle">Ontology Manager</h5>
    <div class="og-search" title="Search + ctrl+K command palette are reference-only — not wired (named gap)"><span class="og-sico">${bpIcon("search")}</span><input placeholder="Search resources…" disabled aria-label="Search resources (reference-only, not wired)"><span class="og-skbd">ctrl + K</span></div>
    <div class="og-headright">
      <span class="og-branch" title="Branching is a reference-only lane — no authority contract yet (named gap).">${bpIcon("git-branch")}<span class="og-branchname">Main</span>${bpIcon("caret-down")}</span>
      <a class="og-new" href="/__ioi/odk/ontologies/new">New ${bpIcon("caret-down")}</a>
    </div>
  </header>`;

  // LIGHT app rail — the reference nav column: icon rows at a 40px pitch, sentence-case "Resources"
  // header, indented resource items with right-aligned COUNT PILLS (live daemon values — masked as
  // dynamic data on the IOI side; the reference's captured counts are masked on its side), hairline
  // group dividers, Health/Cleanup/Configuration at group level.
  const arailItem = (icon, label, count, href, opts = {}) => {
    const c = count == null ? "" : `<span class="og-c">${count}</span>`;
    const inner = `<span class="og-nico">${bpIcon(icon)}</span><span class="og-nlabel">${esc(label)}</span>${c}`;
    const cls = `og-nav${opts.on ? " on" : ""}${opts.sub ? " sub" : ""}`;
    return href
      ? `<a class="${cls}" href="${href}">${inner}</a>`
      : `<span class="${cls} gap" title="${esc(label)} is a reference-only lane — no authority contract yet (named gap).">${inner}</span>`;
  };
  const appRail = `<nav class="og-arail" aria-label="Ontology Manager">
    ${arailItem("compass", "Discover", null, "#og-discover", { on: true })}
    ${arailItem("people", "Proposals", null, null)}
    ${arailItem("time", "History", null, "#og-config")}
    <div class="og-adiv"></div>
    <div class="og-asec">Resources</div>
    ${arailItem("cube", "Object types", ots.length, "#og-discover", { sub: true })}
    ${arailItem("properties", "Properties", propCount, "#og-properties", { sub: true })}
    ${arailItem("globe-network", "Shared properties", 0, null, { sub: true })}
    ${arailItem("arrows-horizontal", "Link types", lts.length, "#og-link-types", { sub: true })}
    ${arailItem("take-action", "Action types", nonFuncActs.length, "#og-action-types", { sub: true })}
    ${arailItem("group-objects", "Groups", 0, null, { sub: true })}
    ${arailItem("selection-box", "Interfaces", 0, null, { sub: true })}
    <div class="og-agap"></div>
    ${arailItem("intersection", "Value types", vts.length, "#og-value-types", { sub: true })}
    ${arailItem("function", "Functions", funcs.length, "#og-functions", { sub: true })}
    <div class="og-adiv2"></div>
    ${arailItem("pulse", "Health issues", null, "#og-health")}
    ${arailItem("clean", "Cleanup", null, null)}
    ${arailItem("cog", "Ontology configuration", null, "#og-config")}
  </nav>`;

  // LIGHT card-first body: object-type cards ("recently modified"), then typed detail + configuration.
  const cardOf = (t) => {
    const desc = (t.description || "").trim();
    return `<a class="og-card" href="/__ioi/odk/ontologies/${selected ? enc(selected.id) : "new"}#ot-${enc(t.id)}" title="${esc(t.name || t.id)} — open in the substrate ontology detail">
      <div class="og-cardtop"><span class="og-cardico">${svg(CUBE)}</span><span class="og-cardname">${esc(t.name || t.id)}</span><span class="og-cardbook">${svg('<path d="M4 5a2 2 0 012-2h12v18H6a2 2 0 01-2-2z"/><path d="M8 3v18"/>')}</span></div>
      <div class="og-cardobj"><b>${objsOf(t)}</b> object${objsOf(t) === 1 ? "" : "s"}</div>
      <div class="og-carddep">${depsOf(t)} dependent${depsOf(t) === 1 ? "" : "s"}</div>
      <div class="og-carddesc">${desc ? esc(desc) : "No description"}</div>
    </a>`;
  };
  const tbl = (head, rows, empty) => rows ? `<table class="og-table"><thead><tr>${head.map((h) => `<th>${h}</th>`).join("")}</tr></thead><tbody>${rows}</tbody></table>` : `<div class="og-none">${empty}</div>`;
  const propRows = ots.flatMap((t) => (Array.isArray(t.properties) ? t.properties : []).map((p) => `<tr><td>${esc(t.name || t.id)}</td><td>${esc(p.name || p.id)} ${idc(p.id)}</td><td>${idc(p.value_type || "")}</td><td>${p.required ? "yes" : "—"}${t.title_property === p.id ? ` <span class="om-pill ok">title</span>` : ""}</td></tr>`)).join("");
  const valRows = vts.map((v) => `<tr><td>${esc(v.name || v.id)} ${idc(v.id)}</td><td><span class="om-pill muted">${esc(v.base || "string")}</span></td><td>${(v.enum_values && v.enum_values.length) ? v.enum_values.map((e) => `<span class="om-pill muted">${esc(e)}</span>`).join(" ") : "—"}</td></tr>`).join("");
  const linkRows = lts.map((l) => `<tr><td>${esc(l.name || l.id)} ${idc(l.id)}</td><td>${idc(l.from || "")} → ${idc(l.to || "")}</td><td><span class="om-pill muted">${esc(l.cardinality || "")}</span></td></tr>`).join("");
  const actRows = nonFuncActs.map((a) => `<tr><td>${esc(a.name || a.id)} ${idc(a.id)}</td><td><span class="om-pill muted">${esc(a.kind || "")}</span></td><td>${a.applies_to ? idc(a.applies_to) : "—"}</td></tr>`).join("");
  const funcRows = funcs.map((a) => `<tr><td>${esc(a.name || a.id)} ${idc(a.id)}</td><td>${a.applies_to ? idc(a.applies_to) : "—"}</td></tr>`).join("");
  const body = `<main class="og-body" role="main">${selected ? `
    <section id="og-discover" class="og-discover">
      <div class="og-sechd"><h2>Object types recently modified in</h2>
        <details class="og-ontomenu"><summary>${domainLabel}${selected ? ` <span class="og-ver">v${esc(selected.version || "0.1.0")}</span>` : ""} ▾</summary>
          <div class="og-ontolist">${ontologies.length ? ontologies.map((x) => `<a class="og-ontoitem${selected && x.id === selected.id ? " on" : ""}" href="/__ioi/ontology/manager?ontology=${enc(x.id)}">${esc(x.domain || x.id)} <span class="og-dot og-${(x.health || {}).status === "ready" ? "ok" : (x.health || {}).status === "empty" ? "muted" : "warn"}"></span></a>`).join("") : `<div class="og-none">No ontologies yet.</div>`}</div>
        </details>
        <a class="og-explorerlink" href="/__ioi/ontology/explorer" title="Object Explorer — browse object types and materialized object sets (the symmetric #35 surface)">Object Explorer →</a>
        <a class="og-configlink" href="/__ioi/odk/ontologies/${enc(selected.id)}/edit">Configure</a></div>
      ${ots.length ? `<div class="og-cards">${ots.map(cardOf).join("")}</div>` : `<div class="og-none">No object types yet. <a href="/__ioi/odk/ontologies/${enc(selected.id)}/edit">Add typed object types →</a></div>`}
    </section>
    <section id="og-properties"><h2>Properties <span class="og-subn">${propCount}</span></h2>${tbl(["Object type", "Property", "Value type", "Required"], propRows, "No properties declared.")}</section>
    <section id="og-value-types"><h2>Value types <span class="og-subn">${vts.length}</span></h2>${tbl(["Value type", "Base", "Enum"], valRows, "No value types.")}</section>
    <section id="og-link-types"><h2>Link types <span class="og-subn">${lts.length}</span></h2>${tbl(["Link", "From → To", "Cardinality"], linkRows, "No link types.")}</section>
    <section id="og-action-types"><h2>Action types <span class="og-subn">${nonFuncActs.length}</span></h2><div class="og-note">Action <b>declarations</b> only — writeback/execution is not wired (needs a PolicyBoundDataView + TransformationRun). Declaring an action never runs it.</div>${tbl(["Action", "Kind", "Applies to"], actRows, "No action types.")}</section>
    <section id="og-functions"><h2>Functions <span class="og-subn">${funcs.length}</span></h2><div class="og-note">Function <b>declarations</b> only — evaluation/execution is not wired.</div>${tbl(["Function", "Applies to"], funcRows, "No function declarations.")}</section>
    <section id="og-health"><h2>Health issues</h2><div class="og-healthbox"><div class="og-sechd2"><b>Readiness</b> ${hpill} <span class="og-sub">${(health.counts || {}).object_types || 0} obj · ${(health.counts || {}).value_types || 0} val · ${(health.counts || {}).link_types || 0} link · ${(health.counts || {}).action_types || 0} act</span></div>${(health.gaps || []).length ? `<ul class="og-gaps">${health.gaps.map((g) => `<li>${esc(g)}</li>`).join("")}</ul>` : `<div class="og-sub">No health issues — the required semantic pieces are present.</div>`}<div class="og-sub" style="margin-top:6px"><b>${esc(String(health.object_instances == null ? 0 : health.object_instances))}</b> object instances — ${esc(health.object_data_note || "schema only; no object-instance plane bound until an OntologyProjection exists.")}</div></div></section>
    <section id="og-config"><h2>Ontology configuration</h2><div class="og-cfg">
      <div class="og-cfgrow"><span>Ref</span>${idc(selected.ref)}</div>
      <div class="og-cfgrow"><span>Revision</span><b>rev ${esc(String(selected.revision || 1))}</b></div>
      <div class="og-cfgrow"><span>Receipts</span><b>${(selected.receipt_refs || []).length}</b></div>
      <div class="og-cfgrow"><span>History</span><b>${(selected.history || []).length}</b></div>
      <div class="og-cfgrow"><span>Object sets · objects</span><b>${msets.length} · ${totalInstances}</b></div>
      <div class="og-cfgrow"><span>Projections</span><b>${projs.length}</b></div>
      <div class="og-cfgrow"><span>Estate</span><span><span class="om-pill ok">${rollup.ready || 0} ready</span> <span class="om-pill warn">${rollup.incomplete || 0} incomplete</span> <span class="om-pill muted">${rollup.empty || 0} empty</span></span></div>
      <a class="og-editlink" href="/__ioi/odk/ontologies/${enc(selected.id)}/edit">Configure model in substrate →</a>
      <div class="og-note" style="margin-top:8px">Named gaps (reference-only lanes, no authority contract yet): in-canvas schema editing · Proposals · Shared properties · Groups · Interfaces · Cleanup · action/function execution. Reference: <a href="/__apps/schema" target="_blank" rel="noopener">Ontology Manager ↗</a>.</div>
    </div></section>
  ` : `<div class="og-none" style="margin:40px auto;max-width:520px">Select or create an ontology to see its schema. <a href="/__ioi/odk/ontologies/new">Create an ontology →</a></div>`}</main>`;

  const css = `@font-face{font-family:'Source-Sans-Pro';font-style:normal;font-weight:400;font-display:block;src:url(/__ioi/fonts/source-sans-pro-400.woff2) format('woff2')}
    @font-face{font-family:'Source-Sans-Pro';font-style:normal;font-weight:600;font-display:block;src:url(/__ioi/fonts/source-sans-pro-600.woff2) format('woff2')}
    @font-face{font-family:'Source-Sans-Pro';font-style:normal;font-weight:700;font-display:block;src:url(/__ioi/fonts/source-sans-pro-700.woff2) format('woff2')}
    html{color-scheme:light}*{box-sizing:border-box}
    body{margin:0;background:#f4f5f7;color:#1c2127;font:14px/1.28581 Source-Sans-Pro,Helvetica,sans-serif}
    a{color:#2f6fd8;text-decoration:none}
    .og-shell{display:flex;height:100vh;width:100vw;overflow:hidden}
    ${IOI_GRAIL_CSS}
    .og-main{flex:1;min-width:0;display:flex;flex-direction:column;height:100vh}
    .og-header{flex:0 0 auto;position:relative;height:50px;display:flex;align-items:center;padding:0 15px 0 0;background:#fff;box-shadow:0 1px 0 0 #dce0e5;z-index:5}
    .og-hchip{width:50px;height:50px;flex:0 0 50px;background:rgba(102,158,255,.1) url('${ONTOLOGY_APP_ICON_URI}') center no-repeat}
    .og-htitle{margin:0 0 0 15px;font-weight:600;font-size:16px;color:#1c2127;line-height:18px}
    .og-ontomenu{position:relative;display:inline-block}.og-ontomenu>summary{list-style:none;cursor:pointer;font-size:14px;color:#1c2127;background:#f1f3f6;border:1px solid #e0e3e8;border-radius:4px;padding:3px 10px}
    .og-ontomenu>summary::-webkit-details-marker{display:none}.og-ver{color:#8b9099}
    .og-ontolist{position:absolute;top:32px;left:0;min-width:230px;background:#fff;border:1px solid #e0e3e8;border-radius:9px;box-shadow:0 8px 28px rgba(20,24,31,.14);padding:6px;z-index:20}
    .og-ontoitem{display:flex;align-items:center;justify-content:space-between;padding:6px 9px;border-radius:6px;color:#3a3f46}
    .og-ontoitem:hover{background:#f1f3f6}.og-ontoitem.on{background:#eef2fb;color:#1a1d21;font-weight:600}
    .og-search{position:absolute;left:50%;top:10px;transform:translateX(-50%);width:350px;height:30px;display:flex;align-items:center;background:#f6f7f9;border-radius:4px;padding:0 10px 0 7px}
    .og-sico{display:inline-flex;color:#5f6b7c;flex:0 0 16px;margin-right:1px}
    .og-search input{flex:1;border:0;background:transparent;font:inherit;font-size:14px;line-height:16px;height:16px;padding:0;color:#1c2127;outline:none}
    .og-search input::placeholder{color:#5f6b7c}
    .og-skbd{font-size:14px;line-height:16px;color:#5f6b7c;white-space:nowrap}
    .og-headright{margin-left:auto;display:flex;align-items:center;gap:23px}
    .og-branch{display:inline-flex;align-items:center;gap:8px;color:#5f6b7c;font-size:14px;line-height:16px;cursor:default}
    .og-branchname{color:#1c2127}
    .og-new{display:inline-flex;align-items:center;justify-content:center;gap:8px;width:70px;height:30px;padding:0;border:1px solid #d7dade;border-radius:4px;background:#fff;color:#1c2127;font-size:14px;line-height:16px;font-weight:400}
    .og-new svg{color:#5f6b7c}
    .og-work{flex:1 1 auto;display:flex;min-height:0}
    .og-arail{flex:0 0 299px;width:299px;background:#fff;border-right:1px solid #dce0e5;overflow-y:auto;padding:6px 5px 6px 6px}
    .og-nav{display:flex;align-items:center;gap:10px;height:35px;padding:0 10px;border-radius:3px;color:#1c2127;font-size:14px;margin:0 0 5px}
    .og-nav.sub{padding-left:15px}
    .og-nico{display:inline-flex;align-items:center;justify-content:center;width:16px;height:16px;color:#5f6b7c;flex:0 0 16px}
    .og-nlabel{flex:1 1 auto;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .og-nav:hover{background:#f6f7f9}
    .og-nav.on{background:#f3f8ff;color:#215db0}.og-nav.on .og-nico{color:#215db0}
    .og-nav .og-c{font-size:12px;color:#1c2127;background:#eef0f3;border-radius:4px;padding:1px 7px;line-height:18px}
    .og-nav.gap{color:#1c2127;cursor:default}.og-nav.gap:hover{background:transparent}
    .og-asec{font-size:14px;color:#1c2127;padding:1px 10px 9px 15px;font-weight:600}
    .og-adiv{height:1px;background:#e5e8eb;margin:10px 10px}
    .og-adiv2{height:1px;background:#e5e8eb;margin:5px 10px 10px}
    .og-agap{height:14px}
    .og-body{flex:1 1 auto;overflow:auto;padding:20px 24px;background:#f6f7f9}
    .og-body section{margin:0 0 26px}
    .og-sechd{display:flex;align-items:center;justify-content:space-between;margin:0 0 12px}
    .og-body h2{font-size:15px;margin:0 0 12px;font-weight:600}.og-subn{color:#9aa0a8;font-weight:400;font-size:13px}
    .og-configlink{font-size:13px}
    .og-explorerlink{font-size:13px;margin-right:14px}
    .og-cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:14px}
    .og-card{display:block;background:#fff;border:1px solid #e4e7ec;border-radius:10px;padding:14px 15px;box-shadow:0 1px 2px rgba(20,24,31,.04);color:#1a1d21}
    .og-card:hover{border-color:#c9d3e6;box-shadow:0 3px 10px rgba(20,24,31,.08)}
    .og-cardtop{display:flex;align-items:center;gap:9px;margin:0 0 8px}.og-cardico{display:inline-flex;color:#5b6472}
    .og-cardname{font-weight:600;font-size:13.5px;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.og-cardbook{color:#b6bcc4}
    .og-cardobj{font-size:12.5px;color:#3a3f46}.og-carddep{font-size:12px;color:#8b9099;margin:2px 0 8px}
    .og-carddesc{font-size:12.5px;color:#9aa0a8;font-style:italic}
    .og-table{border-collapse:collapse;width:100%;font-size:12.5px;background:#fff;border:1px solid #e6e8ec;border-radius:8px;overflow:hidden}
    .og-table th{text-align:left;color:#8b9099;font-weight:600;padding:8px 14px;border-bottom:1px solid #eceef1;background:#fafbfc}
    .og-table td{padding:8px 14px;border-bottom:1px solid #f0f1f4}
    .og-note{color:#6b7178;font-size:12px;border:1px solid #e4e7ec;border-radius:8px;padding:9px 12px;margin:0 0 10px;background:#fbfcfd}
    .og-healthbox,.og-cfg{background:#fff;border:1px solid #e6e8ec;border-radius:10px;padding:14px 16px}
    .og-sechd2{display:flex;align-items:center;gap:8px;margin:0 0 6px}.og-gaps{margin:6px 0 0;padding-left:18px;color:#6b7178}
    .og-cfgrow{display:flex;justify-content:space-between;gap:10px;padding:6px 0;border-bottom:1px solid #f0f1f4}.og-cfgrow>span:first-child{color:#8b9099}
    .og-editlink{display:inline-block;margin-top:10px;font-size:13px}
    .og-none{color:#8b9099;padding:16px;border:1px dashed #d8dbe0;border-radius:10px;background:#fff}
    .og-sub{color:#8b9099;font-size:12px}
    .om-code{font-family:ui-monospace,monospace;font-size:11px;color:#6b7178;background:#f1f3f6;padding:1px 5px;border-radius:4px}
    .og-dot{width:8px;height:8px;border-radius:50%;display:inline-block}
    .og-dot.og-ok{background:#22a35a}.og-dot.og-warn{background:#d6a13a}.og-dot.og-muted{background:#aab0b8}
    .om-pill{display:inline-block;padding:1px 8px;border-radius:999px;font-size:11px;border:1px solid;white-space:nowrap}
    .om-pill.ok{color:#1a7f43;border-color:#bfe4cd;background:#eafaf0}
    .om-pill.warn{color:#a2730c;border-color:#efd9a6;background:#fdf6e6}
    .om-pill.muted{color:#6b7178;border-color:#e0e3e8;background:#f3f4f6}`;

  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Ontology Manager</title><style>${css}</style></head>
    <body><div class="og-shell">${globalRail}<div class="og-main">${header}<div class="og-work">${appRail}${body}</div></div></body></html>`;
}

