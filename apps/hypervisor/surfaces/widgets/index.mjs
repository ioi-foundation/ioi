// Developer Console · Custom Widgets — the faithful Custom-Widgets landing (origin-aligned
// reference /workspace/custom-widgets/ on the :9225 mirror), READ-ONLY over the estate's REAL
// widget/extension registration plane: GET /v1/hypervisor/odk/surface-descriptors (the ODK
// OntologySurfaceDescriptor registry — the estate's declared surface registrations). The landing
// grammar maps honestly: the file table = registered surface descriptors (name · ref ·
// composition pattern · ontology binding · status · created date); creator / last-edited-by /
// last-viewed render honest em-dashes (no principal or view tracking exists on the registry —
// named gaps, never invented). Registration itself is an ODK dev-kit lane (the daemon's
// POST /v1/hypervisor/odk/surface-descriptors requires a declared ontology binding), so New
// widget set ROUTES to the ODK builder — this surface mutates NOTHING. The reference's
// build-in-environment vs scaffold-externally fork is vendor chrome the estate does not bind —
// a named gap, stated in place.
import { bpIcon } from "../../scripts/bp-icons.mjs";
import { WG_APP_TILE_URI, WG_ROW_TUTORIAL_ICON_URI } from "../../scripts/widgets-assets.mjs";
import { ioiGlobalRailHtml, IOI_GRAIL_CSS } from "../chrome.mjs";
import { escHtml } from "../kit.mjs";

const CX_ESC = escHtml;

export const meta = {
  slug: "widgets",
  route: "/__ioi/developer-console/widgets",
  verifier: "scripts/verify-hypervisor-app-parity-widgets.mjs",
  certification: "pixel-certifications/widgets.json",
};

export async function load(ctx) {
  const J = (p) => fetch(`${ctx.daemon}${p}`).then((r) => r.json()).catch(() => null);
  const sd = await J("/v1/hypervisor/odk/surface-descriptors");
  return { descriptors: (sd && sd.surface_descriptors) || [], planeOk: !!(sd && sd.ok) };
}

export function render(model, ctx) {
  return renderWidgetsPort(model, { embed: ctx.embed });
}

// ============================ DEVELOPER CONSOLE · CUSTOM WIDGETS — landing port.
// Reference anatomy (measured): 230px rail · 50px+1px-hairline topbar (50x50 violet chip · title ·
// New-widget-set / Help right cluster — NO store dropdown on this capture) · 88px white band
// (h1 + subtitle, bottom hairline) · the content = a 1000px block centered right of the rail
// (offset 0 @1440, +240 @1920): View pill row (Recents active · Favorites; 10px pill margins on
// this capture) · the sources-family table (name 50% + 3 × 16.667% cols, 57px rows, container
// height max(360px, 100vh − 249px)). No hero illustration, no examples band on this landing.
function renderWidgetsPort(model, opts) {
  const esc = CX_ESC;
  const embed = !!(opts && opts.embed);
  const descriptors = Array.isArray(model.descriptors) ? model.descriptors : [];
  const fdate = (iso) => { const d = new Date(iso || 0); return isNaN(d) ? "—" : d.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" }); };
  const gapDash = (why) => `<span class="wg-dash" title="${esc(why)}">—</span>`;

  const ordered = [...descriptors].sort((a, b) => String(b.created_at || "").localeCompare(String(a.created_at || "")));
  const shown = ordered.slice(0, 12);
  const rowsHtml = shown.length ? shown.map((d) => `<div class="wg-row" title="A REGISTERED surface descriptor — a declared ODK registration record; no generated UI artifact is produced by the plane">
      <span class="wg-cell name">
        <span class="wg-rowico" aria-hidden="true"></span>
        <span class="wg-rowdata">
          <span class="wg-rowname"><a href="/__ioi/odk">${esc(d.name || d.id)}</a><span class="wg-st">${esc(d.status || "draft")}</span></span>
          <span class="wg-rowpath">${esc(d.ref || d.id)} · ${esc(d.composition_pattern || "?")} · ${esc(d.ontology_ref || "no ontology binding")} · created ${fdate(d.created_at)}</span>
        </span>
      </span>
      <span class="wg-cell">${gapDash("No registering principal is recorded on the surface-descriptor registry (named gap)")}</span>
      <span class="wg-cell">${gapDash("No edit principal is recorded on the surface-descriptor registry (named gap)")}</span>
      <span class="wg-cell">${gapDash("View tracking is not recorded on the surface-descriptor registry (named gap)")}</span>
    </div>`).join("") : `<div class="wg-empty">No widget sets registered — this table renders the real ODK surface-descriptor registry and never fabricates rows. Registrations are declared through the <a href="/__ioi/odk">ODK dev kit</a> (a descriptor binds a declared ontology; no generated UI artifact is produced).</div>`;

  // Below-the-fold truth census.
  const byPattern = {}; const byStatus = {};
  for (const d of descriptors) {
    byPattern[d.composition_pattern || "?"] = (byPattern[d.composition_pattern || "?"] || 0) + 1;
    byStatus[d.status || "draft"] = (byStatus[d.status || "draft"] || 0) + 1;
  }
  const chips = (obj) => Object.entries(obj).sort((a, b) => b[1] - a[1]).map(([k, n]) => `<span class="wg-chip">${esc(k)} <b>${n}</b></span>`).join("") || `<span class="wg-chip">none registered</span>`;

  const truth = `<section class="wg-truth" id="widgets-catalog">
    <h2 class="wg-trutht">Registered widget sets <span class="wg-count">${descriptors.length}</span> <span class="wg-truthsub">the real ODK surface-descriptor registry — ${descriptors.length ? "newest 12 shown above" : "honestly empty"}; every record is daemon truth, nothing invented${model.planeOk ? "" : " (the registry plane did not answer — nothing is invented)"}</span></h2>
    <p class="wg-boundary"><b>The registration boundary:</b> this surface READS the registry and mutates nothing — a widget set is an ODK <i>surface descriptor</i>: a declared, ontology-bound registration record (<code>POST /v1/hypervisor/odk/surface-descriptors</code> requires a declared ontology binding; the plane produces NO generated UI artifact). New widget set routes to the <a href="/__ioi/odk">ODK dev kit</a>; the Developer Console owner surface is the <a href="/__ioi/connections">Connections cockpit</a>.</p>
    <div class="wg-truthcols">
      <div class="wg-truthcol"><h3>By composition pattern</h3><div class="wg-chips">${chips(byPattern)}</div><p class="wg-gapnote">Patterns are the daemon's own canonical vocabulary on the records — never a hardcoded copy.</p></div>
      <div class="wg-truthcol"><h3>By status</h3><div class="wg-chips">${chips(byStatus)}</div><p class="wg-gapnote">Descriptors are DRAFT registrations; admission/serve ladders live on the governed Domain-App planes, not here.</p></div>
      <div class="wg-truthcol"><h3>Named gaps (disabled in place)</h3><p class="wg-gapnote">The reference's build-in-environment vs scaffold-externally dev-kit fork (generated SDK/CLI) is vendor chrome the estate does not bind; Favorites and view/principal tracking are not recorded on the registry; Help is a reference-only lane. Creator / last-edited-by / last-viewed columns render em-dashes.</p></div>
    </div>
    <p class="wg-foot">Owner family: <a href="/__ioi/connections">Developer Console (Connections cockpit) →</a> · <a href="/__ioi/odk">ODK dev kit →</a>. Reference: the origin-aligned <a href="http://localhost:9225/workspace/custom-widgets/" rel="noopener">Custom Widgets capture</a> — the <a href="/__apps/widgets">/__apps/widgets proxy lane ↗</a> is documented insufficient (renders no data; #44 sweep evidence).</p>
  </section>`;

  // Embedded (native container contract #65): the native rail owns platform nav — emit no global rail.
  const globalRail = embed ? "" : ioiGlobalRailHtml({ label: "Custom Widgets", href: "/__ioi/developer-console/widgets", iconUri: WG_APP_TILE_URI, railVariant: "rv-pipe rv-wg", viewAll: false, star: false, badges: true, aipGradient: true, acctMuted: true });

  const topbar = `<header class="wg-topbar">
    <span class="wg-hchip" aria-hidden="true"></span>
    <h1 class="wg-htitle">Custom Widgets</h1>
    <div class="wg-hright">
      <a class="wg-hbtn success" href="/__ioi/odk" title="Widget-set registration is an ODK dev-kit lane — a surface descriptor is declared against a bound ontology there; this surface mutates nothing">${bpIcon("plus")}<span>New widget set</span></a>
      <span class="wg-hbtn outlined gap" aria-disabled="true" title="Reference help lane (named gap)"><span>Help</span>${bpIcon("help")}</span>
    </div>
  </header>`;

  const band = `<div class="wg-band"><div class="wg-bandin">
    <h3 class="wg-h1">Custom Widgets</h3>
    <p class="wg-sub">Develop custom frontend widgets for use within Foundry applications.</p>
  </div></div>`;

  const viewrow = `<div class="wg-viewrow">
    <span class="wg-viewlbl">View</span>
    <span class="wg-pill on" title="The newest registrations of the surface-descriptor registry">Recents</span>
    <span class="wg-pill gap" aria-disabled="true" title="Favorites are not recorded on the surface-descriptor registry (named gap)">Favorites</span>
  </div>`;

  const table = `<div class="wg-table">
    <div class="wg-thead"><span class="wg-th name">Files</span><span class="wg-th">Creator</span><span class="wg-th">Last edited by</span><span class="wg-th">Last viewed</span></div>
    <div class="wg-rows">${rowsHtml}</div>
  </div>`;

  const css = `:root{color-scheme:light}*{box-sizing:border-box}
    body{margin:0;background:#fff;color:#1c2127;font:14px/1.28581 Source-Sans-Pro,Helvetica,sans-serif}
    a{color:#215db0;text-decoration:none}
    .wg-shell{display:flex;height:100vh;width:100vw;overflow:hidden}
    ${IOI_GRAIL_CSS}
    .rv-wg .og-gappico{background-color:rgb(40,42,60)}
    .wg-main{flex:1;min-width:0;display:flex;flex-direction:column;height:100vh;background:#f6f7f9}
    .wg-topbar{flex:0 0 51px;height:51px;display:flex;align-items:flex-start;background:#fff;border-bottom:1px solid #d3d8de}
    .wg-hchip{width:50px;height:50px;flex:0 0 50px;background:rgb(244,242,254) url('${WG_APP_TILE_URI}') center/24px no-repeat}
    .wg-htitle{font-size:16px;line-height:36px;font-weight:600;color:#404854;margin:7px 0 0 12px;flex:0 0 auto}
    .wg-hright{margin-left:auto;display:flex;align-items:flex-start;gap:10px;padding-right:20px}
    .wg-hbtn{display:inline-flex;align-items:center;gap:8px;height:30px;margin-top:10px;padding:0 8px;border-radius:4px;font-size:14px;line-height:16.1px;cursor:default}
    .wg-hbtn.success{background:#238551;color:#fff;box-shadow:inset 0 0 0 1px rgba(17,20,24,.2),0 1px 2px rgba(17,20,24,.1)}
    .wg-hbtn.success svg{color:#fff}
    a.wg-hbtn.success{cursor:pointer}
    .wg-hbtn.outlined{border:1px solid rgba(95,107,124,.25);color:#1c2127}
    .wg-hbtn.outlined svg{color:#5f6b7c}
    .wg-body{flex:1 1 auto;min-width:0;overflow-y:auto}
    .wg-band{background:#fff;height:88px;box-shadow:0 1px 0 0 rgba(17,20,24,.15)}
    .wg-bandin{max-width:1040px;height:100%;margin:0 auto;padding:20px 20px 0}
    .wg-h1{font-size:22px;line-height:25px;font-weight:600;color:#1c2127;margin:0}
    .wg-sub{font-size:14px;line-height:18.0013px;color:#5f6b7c;margin:0;padding-top:5px}
    .wg-content{max-width:1000px;margin:0 auto;padding:0 0 40px}
    .wg-viewrow{display:flex;align-items:center;margin-top:40px;height:30px}
    .wg-viewlbl{font-size:14px;line-height:18.0013px;color:#1c2127}
    .wg-pill{display:inline-flex;align-items:center;height:30px;margin-left:10px;padding:6px 10px;border-radius:30px;font-size:14px;line-height:18px;color:#1c2127;cursor:default}
    .wg-pill.on{background:rgba(45,114,210,.3);color:#184a90;font-weight:600}
    .wg-pill:not(.on){background:rgba(143,153,168,.15)}
    .wg-table{margin-top:10px;height:max(360px,calc(100vh - 249px));overflow-y:auto;background:#fff;border-radius:4px;box-shadow:0 0 0 1px rgba(17,20,24,.15)}
    .wg-thead{display:flex;height:30px;box-shadow:inset 0 -1px 0 #dcdcdd}
    .wg-th{width:16.667%;padding:8px 0 0 11px;font-size:12px;line-height:15.43px;color:#5f6b7c;text-transform:uppercase}
    .wg-th.name{width:50%;padding-left:20px}
    .wg-row{display:flex;height:57px;box-shadow:inset 0 -1px 0 #dcdcdd;color:#1c2127}
    .wg-cell{width:16.667%;padding:19.5px 0 0 11px;font-size:14px;line-height:18px}
    .wg-cell.name{width:50%;padding:11px 0 0 20px;display:flex;align-items:flex-start}
    .wg-rowico{width:16px;height:16px;flex:0 0 16px;margin-top:2px;background:url('${WG_ROW_TUTORIAL_ICON_URI}') center/16px no-repeat}
    .wg-rowdata{margin-left:7px;min-width:0;flex:1;padding-right:16px}
    .wg-rowname{display:block;font-size:14px;line-height:18px;color:#1c2127;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .wg-rowpath{display:block;font-size:12px;line-height:15.43px;color:#5f6b7c;margin-top:1px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .wg-st{display:inline-block;margin-left:8px;padding:0 6px;border-radius:9px;background:rgba(143,153,168,.15);color:#5f6b7c;font-size:11px;line-height:16px;vertical-align:1px}
    .wg-dash{color:#5f6b7c}
    .wg-empty{padding:24px 20px;font-size:14px;color:#5f6b7c}
    .wg-truth{margin-top:30px;padding-bottom:40px}
    .wg-trutht{font-size:18px;font-weight:600;color:#1c2127;margin:0 0 8px}
    .wg-count{margin-left:8px;font-size:14px;font-weight:400;color:#5f6b7c;background:rgba(143,153,168,.15);border-radius:9px;padding:1px 8px}
    .wg-truthsub{font-size:13px;font-weight:400;color:#5f6b7c;margin-left:8px}
    .wg-boundary{font-size:13px;line-height:1.55;color:#1c2127;background:#fff;border-radius:4px;box-shadow:0 0 0 1px rgba(200,118,25,.4);padding:12px 14px;margin:0 0 14px}
    .wg-truthcols{display:flex;gap:16px;align-items:flex-start}
    .wg-truthcol{flex:1;min-width:0;background:#fff;border-radius:4px;box-shadow:0 0 0 1px rgba(17,20,24,.15);padding:14px 16px}
    .wg-truthcol h3{font-size:14px;font-weight:600;margin:0 0 8px;color:#1c2127}
    .wg-chips{display:flex;gap:6px;flex-wrap:wrap}
    .wg-chip{display:inline-flex;gap:5px;padding:3px 10px;border-radius:12px;background:rgba(143,153,168,.15);color:#1c2127;font-size:12px}
    .wg-gapnote{font-size:12px;color:#5f6b7c;margin:8px 0 0;line-height:1.5}
    .wg-foot{font-size:12px;line-height:1.6;color:#7b8494;margin-top:18px}`;

  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Custom Widgets</title><style>${css}</style></head>
    <body><div class="wg-shell">${globalRail}<div class="wg-main">${topbar}<div class="wg-body">${band}<main class="wg-content">${viewrow}${table}${truth}</main></div></div></div></body></html>`;
}
