// Object Explorer — extracted app module (Ontology Application Runtime wave). The render code
// below is moved VERBATIM from serve-product-ui.mjs (zero behavior change by construction); the
// module adds only the surface contract the registry mounts. /__ioi/ontology/explorer is a
// certified shell (pixel-certifications/explorer.json) — pixels are frozen by the harness gate.
import { bpIcon, EXPLORER_APP_ICON_URI } from "../../scripts/bp-icons.mjs";
import { ioiGlobalRailHtml, IOI_GRAIL_CSS } from "../chrome.mjs";
import { escHtml } from "../kit.mjs";
import { loadOntologyModel } from "../ontology-context.mjs";

const CX_ESC = escHtml; // local alias so the moved block stays byte-identical to its serve original

export const meta = {
  slug: "explorer",
  route: "/__ioi/ontology/explorer",
  verifier: "scripts/verify-hypervisor-app-parity-object-explorer.mjs",
  certification: "pixel-certifications/explorer.json",
};

export async function load(ctx) {
  return loadOntologyModel(ctx.daemon);
}

export function render(model, ctx) {
  return renderObjectExplorerPort(model.overview, model.lists, { q: ctx.url.searchParams.get("q") || "" });
}

// Browsing-first: object-type/set selection arrives with the Explorer-interaction PR under the
// command-discipline contract.
export const actions = [];

// ============================ OBJECT EXPLORER — reference UX PORT (#35, reference_ported).
// A FAITHFUL source-neutral port of the reference Object Explorer (dark global platform rail + a light
// "Object Explorer search" header with the Filter/Search bar + a Shortcuts strip + an Object type
// CATALOG table + an Object set CATALOG), wired to the REAL ODK truth (object types across ontologies,
// materialized object sets, per-type object + usage counts, a working server-side object-type filter).
// READ-ONLY; the sibling /__ioi/ontology/manager is linked first-class. NOT daemon_wired: the local
// /workspace/hubble reference does not cleanly boot (the proxy renders a blank body; the mirror's data
// lanes render "Failed to load"), so the hardened harness has no valid reference to certify
// visual_parity against — honest `reference_ported`, promotable on a clean re-harvest.
// ============================ OBJECT EXPLORER (#46 — the origin-aligned promotion. #44 proved the
// old "blank/failed Hubble reference" blocker WRONG: the capture-origin lane localhost:9225/workspace/
// hubble/ renders the full Object Explorer with data. This port is the faithful shell of THAT
// reference over real IOI ODK truth: object types across live DomainOntologies, object counts from
// materialized sets, the object-set catalog from real materialized sets, and a WORKING ?q= type
// filter. Reference-only lanes (object-instance search, Filter-by facets, Recents/Favorites, sort,
// type-group/application lanes, exploration tabs, ontology selector) are named gaps disabled in
// place. The catalog/set ROWS are the live body (excluded from shell-pixel certification, verified
// semantically); the chrome is glyph-anchored to the reference: tab bar h40 · centered search hero ·
// shortcuts row + cards · catalog heading/filter/sort band · table header · object-set band. The
// content block is the reference's responsive rule: max-width 1400, width calc(100% − 120px),
// centered (margins 60 @1440 → 145 @1920).
function renderObjectExplorerPort(ov, lists, opts) {
  const enc = encodeURIComponent, esc = CX_ESC;
  const q = (opts && opts.q ? String(opts.q) : "").trim();
  const ontologies = Array.isArray(lists.ontologies) ? lists.ontologies : [];
  const msets = Array.isArray(lists.materialized_sets) ? lists.materialized_sets : [];
  const projs = Array.isArray(lists.projections) ? lists.projections : [];
  const arr = (oo, k) => { const com = (oo && oo.canonical_object_model) || {}; return Array.isArray(com[k]) ? com[k] : []; };

  // REAL daemon truth: the flat object-type catalog + per-type materialized counts + link usage.
  const allTypes = ontologies.flatMap((oo) => arr(oo, "object_types").map((t) => ({ oo, t })));
  const objectsOf = (oo, t) => msets.filter((m) => m.ontology_ref === oo.ref && m.object_type_id === t.id).reduce((a, m) => a + (m.count || 0), 0);
  const usageOf = (oo, t) => arr(oo, "link_types").filter((l) => l.from === t.id || l.to === t.id).length;
  const catalog = q ? allTypes.filter(({ oo, t }) => `${t.name || ""} ${t.id || ""} ${oo.domain || ""}`.toLowerCase().includes(q.toLowerCase())) : allTypes;
  const fmtN = (n) => (n >= 1000 ? `${Math.round(n / 100) / 10}K` : String(n));
  // Shortcuts = the real top materialized sets by object count (live data — masked in the pixel gate).
  const shortcuts = msets.slice().sort((a, b) => (b.count || 0) - (a.count || 0)).slice(0, 3);
  const CHIP_COLORS = ["#bd6bbd", "#13c9ba", "#4c90f0"];

  const typeRow = ({ oo, t }) => {
    const n = objectsOf(oo, t);
    return `<tr class="oe-trow" onclick="location.href='/__ioi/ontology/manager?ontology=${enc(oo.id)}'">
      <td class="oe-tname"><span class="oe-tchip" style="color:${CHIP_COLORS[(t.id || "").length % 3]}">${bpIcon("cube", 14)}</span>${esc(t.name || t.id)}</td>
      <td class="oe-tstatus">${bpIcon("manual", 14)}</td>
      <td>${esc(fmtN(n))}</td>
      <td>${usageOf(oo, t)} link${usageOf(oo, t) === 1 ? "" : "s"}</td>
      <td class="oe-tgroups"></td>
      <td class="oe-tdesc">${esc(oo.domain || oo.id)}</td>
    </tr>`;
  };
  const setRow = (m) => `<tr class="oe-trow" onclick="location.href='/__ioi/odk?ontology=${enc((ontologies.find((oo) => oo.ref === m.ontology_ref) || {}).id || "")}'">
    <td class="oe-tname"><span class="oe-tchip" style="color:#13c9ba">${bpIcon("layout-grid", 14)}</span>${esc(m.name || m.set_id || m.object_type_id)}</td>
    <td>${esc(fmtN(m.count || 0))} object${(m.count || 0) === 1 ? "" : "s"}</td>
    <td class="oe-tdesc">${esc((ontologies.find((oo) => oo.ref === m.ontology_ref) || {}).domain || m.ontology_ref || "")}</td>
    <td class="oe-tdesc"><a href="/__ioi/ontology/manager">Ontology Manager →</a></td>
  </tr>`;

  const globalRail = ioiGlobalRailHtml({ label: "Object Explorer", href: "/__ioi/ontology/explorer", iconUri: EXPLORER_APP_ICON_URI, railVariant: "rv-pipe", viewAll: false, star: false, badges: true, aipGradient: true, acctMuted: true, hiliteNav: "Ontology" });

  const tabbar = `<div class="oe-tabbar oe-topbar">
    <span class="oe-sqbtn gap" aria-disabled="true" title="Active exploration — a reference-only session lane (named gap)"><span class="oe-sqico"></span></span>
    <span class="oe-tab" title="Explorations are a reference-only session lane — this tab is the honest default state">${bpIcon("search")}<span class="oe-tabt">New exploration</span></span>
    <span class="oe-plus gap" aria-disabled="true" title="Opening more exploration tabs is a reference-only lane (named gap)">${bpIcon("plus")}</span>
    <span class="oe-ontsel gap" aria-disabled="true" title="Ontology scoping is a reference-only lane — the catalog below spans ALL live ontologies honestly">All Ontologies ${bpIcon("caret-down")}</span>
  </div>`;

  const hero = `<div class="oe-hero">
    <h2 class="oe-htitle">Object Explorer search</h2>
    <div class="oe-searchrow">
      <div class="oe-herogrp">
        <span class="oe-filterby gap" aria-disabled="true" title="Faceted object filters are a reference-only lane — no object-instance search plane (named gap)">${bpIcon("filter-funnel")}<span class="oe-fbt">Filter by...</span>${bpIcon("caret-down")}</span>
        <div class="oe-objsearch" title="Full-text object search is a reference-only lane — objects exist as materialized sets (the catalog below is real)">${bpIcon("search")}<input placeholder="Search for objects..." disabled aria-label="Search for objects (reference-only, not wired)"><span class="oe-send gap" aria-disabled="true">${bpIcon("send-to")}</span></div>
      </div>
    </div>
  </div>`;

  const cards = shortcuts.map((m, i) => `<a class="oe-card" href="/__ioi/odk?ontology=${enc((ontologies.find((oo) => oo.ref === m.ontology_ref) || {}).id || "")}">
    <span class="oe-cchip" style="background:${CHIP_COLORS[i]}1a;color:${CHIP_COLORS[i]}">${bpIcon("layout-grid", 14)}</span>
    <span class="oe-cbody"><span class="oe-ctitle">${esc(m.name || m.set_id || m.object_type_id)}</span><span class="oe-csub">Object Type&nbsp;&nbsp;•&nbsp;&nbsp;${esc(fmtN(m.count || 0))} object${(m.count || 0) === 1 ? "" : "s"}</span></span>
  </a>`).join("");
  const shortcutsBand = `<div class="oe-shrow">
    <span class="oe-shlabel">Shortcuts</span>
    <span class="oe-lanes">
      <span class="oe-lane on gap" aria-disabled="true" title="Recents are a reference-only per-user lane (named gap) — the cards below are the real top materialized sets">Recents</span>
      <span class="oe-lane gap" aria-disabled="true" title="Favorites are a reference-only per-user lane (named gap)">Favorites</span>
      <span class="oe-lane gap" aria-disabled="true" title="Your object sets — the real materialized sets render in the catalog below">Your object sets</span>
      <span class="oe-shchev gap" aria-disabled="true">${bpIcon("chevron-right")}</span>
    </span>
  </div>
  <div class="oe-cards">${cards || `<div class="oe-cardempty">No materialized sets yet — run a materializing run to populate shortcuts. This row reads real daemon sets; nothing is fabricated.</div>`}</div>`;

  const catalogBand = `<h3 class="oe-cathead"><span class="oe-cathd">Object type catalog</span></h3>
  <div class="oe-filterrow">
    <form class="oe-filterform" method="GET" action="/__ioi/ontology/explorer">${bpIcon("filter-funnel")}<input name="q" value="${esc(q)}" placeholder="Filter for an object type..." aria-label="Filter for an object type (live)"><span class="oe-count">${catalog.length} of ${allTypes.length}</span></form>
    <span class="oe-sortlanes">
      <span class="oe-sort gap" aria-disabled="true" title="Relevancy sorting is a reference-only lane — rows are ordered by ontology then name (named gap)">${bpIcon("sort-desc")}<span class="oe-sortt">Relevancy</span>${bpIcon("caret-down")}</span>
      <span class="oe-lane on gap" aria-disabled="true" title="named gap">All</span>
      <span class="oe-lane gap" aria-disabled="true" title="Type groups are a reference-only lane — the daemon records none (named gap)">Type group</span>
      <span class="oe-lane gap" aria-disabled="true" title="Application scoping is a reference-only lane (named gap)">Application</span>
    </span>
  </div>
  <div class="oe-tablebox">
    <table class="oe-table">
      <thead><tr><th class="oe-thname">Object type name</th><th class="oe-thstatus">Status</th><th class="oe-thcount">Object count</th><th class="oe-thusage">Usage</th><th class="oe-thgroups">Type groups</th><th>Description</th></tr></thead>
      <tbody>${catalog.length ? catalog.map(typeRow).join("") : `<tr><td colspan="6" class="oe-none">${q ? `No object types match “${esc(q)}”.` : "No object types yet — create an ontology in the Ontology Manager."} <a href="/__ioi/ontology/manager">Ontology Manager →</a></td></tr>`}</tbody>
    </table>
  </div>`;

  const setBand = `<div class="oe-setrow">
    <span class="oe-setlabel">Object set catalog <span class="oe-setsub">(explorations and lists)</span></span>
    <span class="oe-setlanes">
      <input class="oe-setsearch" placeholder="Search explorations..." disabled aria-label="Search explorations (reference-only, not wired)" title="Exploration search is a reference-only lane (named gap)">
      <span class="oe-slane on gap" aria-disabled="true" title="named gap">All</span>
      <span class="oe-slane gap" aria-disabled="true" title="Per-user set lanes are reference-only (named gap)">Created by me</span>
      <span class="oe-slane gap" aria-disabled="true" title="named gap">Shared with me</span>
      <span class="oe-slane gap" aria-disabled="true" title="named gap">Favorites</span>
    </span>
  </div>
  <div class="oe-setbox">
    <table class="oe-table oe-settable">
      <tbody>${msets.length ? msets.slice(0, 20).map(setRow).join("") : `<tr><td class="oe-none">No object sets yet — a materialized set appears once an OntologyProjection reads a source (${projs.length} projection${projs.length === 1 ? "" : "s"} declared). <a href="/__ioi/odk">ODK substrate →</a></td></tr>`}</tbody>
    </table>
    <div class="oe-foot">Every row is daemon truth: ${allTypes.length} object type${allTypes.length === 1 ? "" : "s"} across ${ontologies.length} live ontolog${ontologies.length === 1 ? "y" : "ies"} · ${msets.length} materialized set${msets.length === 1 ? "" : "s"}. Schema authoring: <a href="/__ioi/ontology/manager">Ontology Manager →</a> · substrate: <a href="/__ioi/odk">ODK</a> · reference: <a href="/__apps/explorer" target="_blank" rel="noopener">Object Explorer capture ↗</a></div>
  </div>`;

  const css = `:root{color-scheme:light}*{box-sizing:border-box}
    body{margin:0;background:#fff;color:#1c2127;font:14px/1.28581 Source-Sans-Pro,Helvetica,sans-serif}
    a{color:#215db0;text-decoration:none}
    .oe-shell{display:flex;height:100vh;width:100vw;overflow:hidden}
    ${IOI_GRAIL_CSS}
    .oe-main{flex:1;min-width:0;display:flex;flex-direction:column;height:100vh}
    .oe-tabbar{flex:0 0 40px;display:flex;align-items:stretch;background:#edeff2;box-shadow:inset 0 -1px 0 0 rgba(17,20,24,.15)}
    .oe-sqbtn{width:41px;display:flex;align-items:center;justify-content:center;background:rgba(189,173,255,.1)}
    .oe-sqico{width:24px;height:24px;border-radius:4px;background:rgba(167,182,194,.1) url('${EXPLORER_APP_ICON_URI}') center/20px no-repeat}
    .oe-tab{display:flex;align-items:center;gap:5px;width:180px;padding:0 0 0 15px;background:#fff;box-shadow:inset 0 -1px 0 0 rgba(17,20,24,.15)}
    .oe-tab svg{color:#5f6b7c}
    .oe-tabt{font-size:14px;line-height:18.0013px;color:#1c2127}
    .oe-plus{display:flex;align-items:center;justify-content:center;width:30px;color:#5f6b7c}
    .oe-ontsel{margin-left:auto;display:inline-flex;align-items:center;gap:8px;height:30px;margin-top:5px;margin-right:10px;padding:0 8px;border-radius:4px;font-size:14px;line-height:16.1px;color:#1c2127;cursor:default;background:#fff;box-shadow:inset 0 0 0 1px rgba(64,72,84,.33),0 1px 2px rgba(17,20,24,.1)}
    .oe-ontsel svg{color:#5f6b7c}
    .oe-body{flex:1 1 auto;min-width:0;overflow-y:auto;overflow-x:hidden;background:#fff}
    .oe-content{max-width:1400px;width:calc(100% - 121px);margin:0 auto;position:relative}
    .oe-hero{text-align:center}
    .oe-htitle{font-size:16px;line-height:19px;font-weight:600;color:#1c2127;margin:21px 0 0;position:relative;top:-1px}
    .oe-searchrow{display:flex;justify-content:center;margin-top:16px}
    .oe-herogrp{display:flex;border-radius:4px;box-shadow:0 0 0 1px rgba(17,20,24,.17),0 2px 8px rgba(17,20,24,.22);margin-left:2px}
    .oe-filterby{display:inline-flex;align-items:center;width:250px;height:40px;padding:0 12px;background:#f6f7f9;border-right:1px solid rgba(17,20,24,.15);border-radius:4px 0 0 4px;cursor:default}
    .oe-filterby svg{color:#5f6b7c}
    .oe-fbt{flex:1;font-size:14px;line-height:18.0013px;color:#5f6b7c;margin-left:4px;text-align:left}
    .oe-objsearch{display:flex;align-items:center;width:450px;height:40px;padding:0 5px 0 8px;background:#fff;border-radius:0 4px 4px 0}
    .oe-objsearch svg{color:#5f6b7c}
    .oe-objsearch input{flex:1;border:0;background:transparent;font:inherit;font-size:14px;line-height:18.0013px;color:#1c2127;outline:none;padding:0;margin-left:4px}
    .oe-objsearch input::placeholder{color:#5f6b7c}
    .oe-send{display:inline-flex;align-items:center;justify-content:center;width:32px;height:32px;border-radius:50%;background:#2d72d2}
    .oe-send svg{color:#fff}
    .oe-shrow{display:flex;align-items:center;margin-top:19px}
    .oe-shlabel{font-size:14px;line-height:16px;font-weight:600;color:#1c2127}
    .oe-lanes{margin-left:auto;display:inline-flex;align-items:center}
    .oe-lane{display:inline-flex;align-items:center;height:30px;padding:0 8px;border-radius:4px;font-size:14px;line-height:16.1px;color:#5f6b7c;cursor:default;margin-left:2px}
    .oe-lane.on{background:#fff;color:#1c2127;box-shadow:inset 0 0 0 1px rgba(64,72,84,.33),0 1px 2px rgba(17,20,24,.1)}
    .oe-shchev{display:inline-flex;color:#5f6b7c;margin:0 7.5px 0 26px}
    .oe-cards{display:flex;gap:14px;margin-top:11px}
    .oe-card{flex:1;display:flex;align-items:center;height:57px;padding:0 14px;border-radius:4px;box-shadow:inset 0 0 0 1px rgba(17,20,24,.15)}
    .oe-cchip{display:inline-flex;align-items:center;justify-content:center;width:24px;height:24px;border-radius:4px;flex:0 0 24px}
    .oe-cbody{display:flex;flex-direction:column;margin-left:14px;min-width:0}
    .oe-ctitle{font-size:14px;line-height:18.0013px;color:#1c2127;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .oe-csub{font-size:14px;line-height:18.0013px;color:#5f6b7c}
    .oe-cardempty{flex:1;display:flex;align-items:center;height:57px;padding:0 14px;border-radius:4px;border:1px dashed #d3d8de;color:#5f6b7c;font-size:12.5px}
    .oe-cathead{margin:63px 0 0;font-size:14px;line-height:16px;font-weight:600;color:#1c2127}
    .oe-cathd{border-bottom:1px dotted #8f99a8;line-height:15px;display:inline-block}
    .oe-filterrow{display:flex;align-items:center;margin-top:12px}
    .oe-filterform{display:flex;align-items:center;width:450px;height:30px;padding:0 5px 0 7px;background:#fff;box-shadow:inset 0 0 0 1px rgba(17,20,24,.2),inset 0 1px 1px rgba(17,20,24,.3);border-radius:4px}
    .oe-filterform svg{color:#5f6b7c}
    .oe-filterform input{flex:1;border:0;background:transparent;font:inherit;font-size:14px;color:#1c2127;outline:none;padding:0;margin-left:7px}
    .oe-filterform input::placeholder{color:#5f6b7c}
    .oe-count{display:inline-flex;align-items:center;height:20px;padding:0 6px;border-radius:4px;background:rgba(143,153,168,.15);font-size:12px;line-height:16px;color:#1c2127;white-space:nowrap}
    .oe-sortlanes{margin-left:auto;display:inline-flex;align-items:center}
    .oe-sort{display:inline-flex;align-items:center;gap:8px;height:30px;padding:0 8px;font-size:14px;line-height:16.1px;color:#1c2127;cursor:default;margin-right:12px}
    .oe-sort svg{color:#5f6b7c}
    .oe-table{border-collapse:collapse;width:100%;font-size:14px;table-layout:fixed}
    .oe-tablebox{margin-top:8px;height:430px;overflow-y:auto;border-radius:4px;box-shadow:0 0 0 1px rgba(17,20,24,.15)}
    .oe-table thead th{position:sticky;top:0;background:#f6f7f9;text-align:left;font-size:12px;line-height:15.4297px;font-weight:400;color:#5f6b7c;text-transform:uppercase;padding:7.3px 10px 8px;border-bottom:1px solid #e5e8eb;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .oe-thname{width:284.8px;padding-left:20px !important}
    .oe-thstatus{width:79.2px}.oe-thcount{width:90.8px}.oe-thusage{width:181.5px}.oe-thgroups{width:181.5px}
    .oe-trow{cursor:pointer}
    .oe-trow:hover{background:#f6f7f9}
    .oe-trow td{padding:11px 10px;border-bottom:1px solid #eef0f2;color:#1c2127;line-height:18.0013px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:280px}
    .oe-tname{padding-left:20px !important}
    .oe-tchip{display:inline-flex;vertical-align:-2px;margin-right:12px}
    .oe-tstatus svg{color:#935610}
    .oe-tdesc{color:#5f6b7c !important}
    .oe-none{padding:18px 20px;color:#5f6b7c}
    .oe-setrow{display:flex;align-items:center;margin-top:24px}
    .oe-setlabel{font-size:14px;line-height:16px;font-weight:600;color:#1c2127}
    .oe-setsub{font-weight:400;color:#5f6b7c}
    .oe-setlanes{margin-left:auto;display:inline-flex;align-items:center;gap:8px}
    .oe-setsearch{width:219px;height:30px;border:0;border-radius:30px;background:#fff;box-shadow:inset 0 0 0 1px rgba(17,20,24,.2);font:inherit;font-size:14px;color:#1c2127;outline:none;padding:0 12px 0 30px}
    .oe-slane{display:inline-flex;align-items:center;height:30px;padding:0 10px;border-radius:30px;font-size:14px;line-height:18.0013px;color:#1c2127;cursor:default}
    .oe-slane.on{background:#c0d4f1;color:#184a90;font-weight:600}
    .oe-setbox{margin:10px 0 30px}
    .oe-foot{margin-top:14px;color:#7b8494;font-size:12px;line-height:1.5}`;

  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Object Explorer</title><style>${css}</style></head>
    <body><div class="oe-shell">${globalRail}<div class="oe-main">${tabbar}<div class="oe-body"><main class="oe-content" role="main">${hero}${shortcutsBand}${catalogBand}${setBand}</main></div></div></div></body></html>`;
}
