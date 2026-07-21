// Workbench · Code Workspaces — the faithful Code-Workspaces launchpad landing (origin-aligned
// reference /workspace/code-workspaces/ on the :9225 mirror), READ-ONLY over the estate's REAL
// session projection: GET /v1/hypervisor/sessions (the daemon's newest-50 projection + total) and
// GET /v1/hypervisor/editor-targets (the probed editor registry). The launchpad grammar maps
// honestly: "Running workspaces" = sessions whose lifecycle_state is non-terminal (provisioned);
// the table = the newest sessions with their workspace roots, environment/editor refs, and
// lifecycle pills; creator / last-edited-by / last-edited render honest em-dashes (no principal
// or edit tracking exists on the session projection — named gaps, never invented). The
// reference's VS Code / Jupyter / RStudio filter pills are FOREIGN editor taxonomy — they stay
// as named-gap chrome; the estate's own editor kinds (the daemon editor-target registry with
// probed open posture) render in the below-fold census. New workspace routes to the Workbench
// owner surface (the real session/environment lanes) — this surface mutates NOTHING.
import { bpIcon } from "../../scripts/bp-icons.mjs";
import { CW_APP_TILE_URI, CW_VSCODE_ICON_URI, CW_JUPYTER_ICON_URI, CW_RSTUDIO_ICON_URI } from "../../scripts/workspaces-assets.mjs";
import { MCH_STORE_ICON_URI, MCH_EXAMPLES_STRIP_URI } from "../../scripts/machinery-assets.mjs";
import { DSG_ROW_DOC_URI } from "../../scripts/designer-assets.mjs";
import { ioiGlobalRailHtml, IOI_GRAIL_CSS } from "../chrome.mjs";
import { escHtml } from "../kit.mjs";

const CX_ESC = escHtml;

export const meta = {
  slug: "workspaces",
  route: "/__ioi/workbench/workspaces",
  verifier: "scripts/verify-hypervisor-app-parity-workspaces.mjs",
  certification: "pixel-certifications/workspaces.json",
};

export async function load(ctx) {
  const J = (p) => fetch(`${ctx.daemon}${p}`).then((r) => r.json()).catch(() => null);
  const [se, et] = await Promise.all([
    J("/v1/hypervisor/sessions"),
    J("/v1/hypervisor/editor-targets"),
  ]);
  return {
    sessions: (se && se.sessions) || [],
    total: se && typeof se.total === "number" ? se.total : null,
    truthSource: (se && se.runtimeTruthSource) || "",
    targets: (et && et.targets) || [],
  };
}

export function render(model, ctx) {
  return renderWorkspacesPort(model, {
    embed: ctx.embed,
    view: ctx.url.searchParams.get("view") === "all" ? "all" : "recents",
  });
}

// ============================ WORKBENCH · CODE WORKSPACES — launchpad landing port.
// Reference anatomy (measured): 230px rail · 50px+1px-hairline topbar (50x50 orange chip · title ·
// store dropdown / New workspace / Help right cluster) · 143px white band (h1 + subtitle, bottom
// hairline) · the content = a 1000px block centered right of the rail (offset 0 @1440, +240 @1920):
// overlapping "Running workspaces" bp6 card (margin-top −55px, h130) · View pill row (h30) ·
// table (name 50% + 3 × 16.667% cols, 57px rows, height max(360px, 100vh − 648px) — the sources
// rule) · "Explore reference examples" band (VERBATIM marketplace strip, reused from #50).
function renderWorkspacesPort(model, opts) {
  const esc = CX_ESC;
  const embed = !!(opts && opts.embed);
  const sessions = Array.isArray(model.sessions) ? model.sessions : [];
  const targets = Array.isArray(model.targets) ? model.targets : [];
  const fdate = (iso) => { const d = new Date(iso || 0); return isNaN(d) ? "—" : d.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" }); };
  const sref = (s) => String(s.session_ref || "").replace(/^session:/, "");
  const gapDash = (why) => `<span class="cw-dash" title="${esc(why)}">—</span>`;

  // Lifecycle truth: the daemon vocabulary on this projection is provisioned / executed /
  // execution_failed. "Running" maps to the non-terminal state ONLY — nothing is invented.
  const TERMINAL = ["executed", "execution_failed"];
  const ordered = [...sessions].sort((a, b) => String(b.created_at || "").localeCompare(String(a.created_at || "")));
  const running = ordered.filter((s) => !TERMINAL.includes(s.lifecycle_state));
  const cExecuted = ordered.filter((s) => s.lifecycle_state === "executed").length;
  const cFailed = ordered.filter((s) => s.lifecycle_state === "execution_failed").length;

  const lifecyclePill = (st) => st === "executed" ? `<span class="cw-lc ok">executed</span>`
    : st === "execution_failed" ? `<span class="cw-lc bad">execution_failed</span>`
    : `<span class="cw-lc run">${esc(st || "provisioned")}</span>`;

  // Running-workspaces card interior — REAL provisioned sessions (a data region on both sides:
  // the capture shows the reference tenant's empty state, the estate shows live truth).
  const runBody = running.length ? `<div class="cw-runbody" title="Sessions whose lifecycle_state is non-terminal, from the daemon's newest-50 projection">
      <span class="cw-runcount"><b>${running.length}</b> provisioned session${running.length === 1 ? "" : "s"} in the newest-50 projection</span>
      <span class="cw-runrefs">${running.slice(0, 2).map((s) => `<a href="/__ioi/workbench#sessions" title="${esc(s.workspace_root || "")}"><code>${esc(sref(s))}</code></a>`).join(" · ")}${running.length > 2 ? ` · <a href="#workspaces-catalog">all ↓</a>` : ""}</span>
    </div>` : `<div class="cw-runbody cw-runempty">You have no running workspaces. Create or open a workspace<br>to get started.</div>`;

  const shown = opts.view === "all" ? ordered : ordered.slice(0, 12);
  const rowsHtml = shown.length ? shown.map((s) => `<div class="cw-row" title="A REAL daemon session — workspace root, environment and editor-target refs are projection truth; principals are not recorded (named gap)">
      <span class="cw-cell name">
        <span class="cw-rowico" aria-hidden="true"></span>
        <span class="cw-rowdata">
          <span class="cw-rowname"><a href="/__ioi/workbench#sessions">${esc(sref(s))}</a>${lifecyclePill(s.lifecycle_state)}</span>
          <span class="cw-rowpath">${esc(s.workspace_root || "no workspace root")} · ${esc(s.environment_ref || "no environment")} · ${esc(s.editor_target_ref || "no editor target")} · created ${fdate(s.created_at)}</span>
        </span>
      </span>
      <span class="cw-cell">${gapDash("No creating principal is recorded on the session projection (named gap)")}</span>
      <span class="cw-cell">${gapDash("No edit principal is recorded on the session projection (named gap)")}</span>
      <span class="cw-cell">${gapDash("Edit tracking is not recorded on the session projection — created_at renders in the row detail (named gap)")}</span>
    </div>`).join("") : `<div class="cw-empty">No sessions in the daemon projection — this table renders the real session plane and never fabricates rows. Sessions are created from the <a href="/__ioi/workbench">Workbench</a> owner surface.</div>`;

  // Below-the-fold truth census (both viewports keep this under the fold).
  const byLifecycle = {};
  for (const s of sessions) byLifecycle[s.lifecycle_state || "?"] = (byLifecycle[s.lifecycle_state || "?"] || 0) + 1;
  const chips = (obj) => Object.entries(obj).sort((a, b) => b[1] - a[1]).map(([k, n]) => `<span class="cw-chip">${esc(k)} <b>${n}</b></span>`).join("");
  const targetRows = targets.map((t) => {
    const op = t.open_posture || {};
    return `<li class="cw-etline"><b>${esc((t.profile && t.profile.displayName) || t.target_id)}</b> <code>${esc(t.target_id)}</code> — ${op.openable ? `<span class="cw-lc ok">openable</span>` : `<span class="cw-lc bad" title="${esc((op.probe && op.probe.evidence && op.probe.evidence.note) || "probe failed")}">not openable</span>`} · ${esc(op.open_kind || "unknown kind")}</li>`;
  }).join("");

  const truth = `<section class="cw-truth" id="workspaces-catalog">
    <h2 class="cw-trutht">Session catalog <span class="cw-count">${model.total === null ? sessions.length : model.total}</span> <span class="cw-truthsub">the real session plane — the daemon serves a newest-50 projection${model.total !== null ? ` of ${model.total} total sessions` : ""}; ${opts.view === "all" ? `all ${sessions.length} projection rows shown above` : "newest 12 shown above"}; every row is daemon truth, nothing invented</span></h2>
    <p class="cw-boundary"><b>The launchpad boundary:</b> this surface READS the session projection and mutates nothing — workspace creation, environment provisioning, and editor opens are the <a href="/__ioi/workbench">Workbench</a> owner surface's lanes (New workspace routes there). Lifecycle census over the projection: ${chips(byLifecycle)} — ${running.length} non-terminal · ${cExecuted} executed · ${cFailed} failed.</p>
    <div class="cw-truthcols">
      <div class="cw-truthcol"><h3>The estate's real editor kinds</h3><p class="cw-gapnote">The reference filters by its own editor taxonomy (VS Code · Jupyter · RStudio — named-gap chrome above); the estate's editor truth is the daemon editor-target registry with PROBED open posture:</p>${targetRows ? `<ul class="cw-etlist">${targetRows}</ul>` : `<p class="cw-gapnote">The editor-target registry is unreachable or empty — nothing is invented.</p>`}</div>
      <div class="cw-truthcol"><h3>Named gaps (disabled in place)</h3><p class="cw-gapnote">Favorites and Created-by-me are identity/favorite tracking the session projection does not record; the VS Code/Jupyter/RStudio pills are foreign editor taxonomy; the store dropdown and example-workspace installs are marketplace lanes not bound to this surface; Help is a reference-only lane. Creator / last-edited-by / last-edited columns render em-dashes — no principal or edit tracking exists on the projection.</p></div>
      <div class="cw-truthcol"><h3>Owner family</h3><p class="cw-gapnote"><a href="/__ioi/workbench">Workbench (environments · editors · sessions) →</a> · <a href="/__ioi/sessions">Sessions root →</a> · <a href="/__ioi/environments">Environment posture →</a>${model.truthSource ? ` · runtime truth source: <code>${esc(model.truthSource)}</code>` : ""}</p></div>
    </div>
    <p class="cw-foot">Reference: the origin-aligned <a href="http://localhost:9225/workspace/code-workspaces/" rel="noopener">Code Workspaces capture</a> — the <a href="/__apps/workspaces">/__apps/workspaces proxy lane ↗</a> is documented insufficient (renders no data; #44 sweep evidence). The example cards above are the reference's own marketplace vendor chrome, embedded verbatim — not estate data.</p>
  </section>`;

  // Embedded (native container contract #65): the native rail owns platform nav — emit no global rail.
  const globalRail = embed ? "" : ioiGlobalRailHtml({ label: "Code Workspaces", href: "/__ioi/workbench/workspaces", iconUri: CW_APP_TILE_URI, railVariant: "rv-pipe rv-cw", viewAll: false, star: false, badges: true, aipGradient: true, acctMuted: true });

  const topbar = `<header class="cw-topbar">
    <span class="cw-hchip" aria-hidden="true"></span>
    <h1 class="cw-htitle">Code Workspaces</h1>
    <div class="cw-hright">
      <span class="cw-hbtn store gap" aria-disabled="true" title="Recent installations — marketplace install lanes are not bound to this surface (named gap)"><span class="cw-storeico" aria-hidden="true"></span>${bpIcon("caret-down")}</span>
      <a class="cw-hbtn success" href="/__ioi/workbench" title="Workspace creation is the Workbench owner surface's lane — sessions/environments are provisioned there; this launchpad mutates nothing">${bpIcon("plus")}<span>New workspace</span></a>
      <span class="cw-hbtn outlined gap" aria-disabled="true" title="Reference help lane (named gap)"><span>Help</span>${bpIcon("help")}</span>
    </div>
  </header>`;

  const band = `<div class="cw-band"><div class="cw-bandin">
    <h3 class="cw-h1">Code Workspaces</h3>
    <p class="cw-sub">Launch code workspaces that run open-source IDEs and notebooks.</p>
  </div></div>`;

  const runcard = `<section class="cw-runcard">
    <h4 class="cw-runh">Running workspaces</h4>
    ${runBody}
  </section>`;

  const viewrow = `<div class="cw-viewrow">
    <span class="cw-viewlbl">View</span>
    <a class="cw-pill${opts.view === "all" ? "" : " on"}" href="/__ioi/workbench/workspaces${embed ? "?embed=1" : ""}" title="The newest 12 sessions of the daemon projection">Recents</a>
    <span class="cw-pill gap" aria-disabled="true" title="Favorites are not recorded on the session projection (named gap)">Favorites</span>
    <a class="cw-pill${opts.view === "all" ? " on" : ""}" href="/__ioi/workbench/workspaces?view=all${embed ? "&embed=1" : ""}" title="All 50 rows of the daemon's newest-50 projection">All</a>
    <span class="cw-vdiv" aria-hidden="true"></span>
    <span class="cw-pill gap" aria-disabled="true" title="Identity-scoped filtering needs the identity-mapping phase — no principal is recorded on the session projection (named gap)">Created by me</span>
    <span class="cw-vdiv" aria-hidden="true"></span>
    <span class="cw-pill ico gap" aria-disabled="true" title="Foreign editor taxonomy — the estate's editor kinds are the daemon editor-target registry, rendered in the census below (named gap)"><span class="cw-pico vsc" aria-hidden="true"></span>VS Code</span>
    <span class="cw-pill ico gap" aria-disabled="true" title="Foreign editor taxonomy — the estate's editor kinds are the daemon editor-target registry, rendered in the census below (named gap)"><span class="cw-pico jup" aria-hidden="true"></span>Jupyter</span>
    <span class="cw-pill ico gap" aria-disabled="true" title="Foreign editor taxonomy — the estate's editor kinds are the daemon editor-target registry, rendered in the census below (named gap)"><span class="cw-pico rst" aria-hidden="true"></span>RStudio</span>
  </div>`;

  const table = `<div class="cw-table">
    <div class="cw-thead"><span class="cw-th name">Workspaces</span><span class="cw-th">Creator</span><span class="cw-th">Last edited by</span><span class="cw-th">Last edited</span></div>
    <div class="cw-rows">${rowsHtml}</div>
  </div>`;

  const examples = `<div class="cw-examples">
    <h5 class="cw-exh">Explore reference examples</h5>
    <div class="cw-exsub">Learn how to build your use case using example workspaces from Marketplace.</div>
    <div class="cw-exstripwrap">
      <img class="cw-exstrip" src="${MCH_EXAMPLES_STRIP_URI}" width="562" height="272" alt="Reference marketplace example cards (verbatim capture chrome)">
      <span class="cw-excard c1 gap" aria-disabled="true" title="Marketplace example installs are a reference-only lane (named gap)"></span>
      <span class="cw-excard c2 gap" aria-disabled="true" title="Marketplace example installs are a reference-only lane (named gap)"></span>
    </div>
  </div>`;

  const css = `:root{color-scheme:light}*{box-sizing:border-box}
    body{margin:0;background:#fff;color:#1c2127;font:14px/1.28581 Source-Sans-Pro,Helvetica,sans-serif}
    a{color:#215db0;text-decoration:none}
    .cw-shell{display:flex;height:100vh;width:100vw;overflow:hidden}
    ${IOI_GRAIL_CSS}
    .rv-cw .og-gappico{background-color:rgba(251,179,96,.1)}
    .cw-main{flex:1;min-width:0;display:flex;flex-direction:column;height:100vh;background:#f6f7f9}
    .cw-topbar{flex:0 0 51px;height:51px;display:flex;align-items:flex-start;background:#fff;border-bottom:1px solid #d3d8de}
    .cw-hchip{width:50px;height:50px;flex:0 0 50px;background:rgba(251,179,96,.1) url('${CW_APP_TILE_URI}') center/24px no-repeat}
    .cw-htitle{font-size:16px;line-height:36px;font-weight:600;color:#404854;margin:7px 0 0 12px;flex:0 0 auto}
    .cw-hright{margin-left:auto;display:flex;align-items:flex-start;gap:10px;padding-right:20px}
    .cw-hbtn{display:inline-flex;align-items:center;gap:8px;height:30px;margin-top:10px;padding:0 8px;border-radius:4px;font-size:14px;line-height:16.1px;cursor:default}
    .cw-hbtn.success{background:#238551;color:#fff;box-shadow:inset 0 0 0 1px rgba(17,20,24,.2),0 1px 2px rgba(17,20,24,.1)}
    .cw-hbtn.success svg{color:#fff}
    a.cw-hbtn.success{cursor:pointer}
    .cw-hbtn.outlined{border:1px solid rgba(95,107,124,.25);color:#1c2127}
    .cw-hbtn.outlined svg{color:#5f6b7c}
    .cw-hbtn.store{gap:8px;padding:4px 8px;background:#f7f8f8;box-shadow:inset 0 0 0 1px rgba(64,72,84,.33),0 1px 2px rgba(17,20,24,.1)}
    .cw-storeico{width:16px;height:16px;flex:0 0 16px;background:url('${MCH_STORE_ICON_URI}') center/16px no-repeat}
    .cw-body{flex:1 1 auto;min-width:0;overflow-y:auto}
    .cw-band{background:#fff;height:143px;box-shadow:0 1px 0 0 rgba(17,20,24,.15)}
    .cw-bandin{max-width:1040px;height:100%;margin:0 auto;padding:20px 20px 0}
    .cw-h1{font-size:22px;line-height:25px;font-weight:600;color:#1c2127;margin:0}
    .cw-sub{font-size:14px;line-height:18.0013px;color:#5f6b7c;margin:0;padding-top:5px}
    .cw-content{max-width:1000px;margin:-55px auto 0;padding:0 0 40px}
    .cw-runcard{height:130px;background:#fff;border-radius:4px;box-shadow:0 0 0 1px rgba(0,0,0,.15),0 0 5px rgba(0,0,0,.02);overflow:hidden}
    .cw-runh{font-size:16px;line-height:19px;font-weight:600;color:#1c2127;margin:0;padding:20px 20px 0}
    .cw-runbody{width:400px;margin:15px auto 0;text-align:center;font-size:14px;line-height:18.0013px;color:#5f6b7c;display:flex;flex-direction:column;gap:4px}
    .cw-runbody.cw-runempty{display:block}
    .cw-runcount b{color:#1c2127}
    .cw-runrefs code{font-size:12px}
    .cw-viewrow{display:flex;align-items:center;margin-top:30px;height:30px}
    .cw-viewlbl{font-size:14px;line-height:18.0013px;color:#1c2127}
    .cw-pill{display:inline-flex;align-items:center;height:30px;margin-left:8px;padding:6px 10px;border-radius:30px;font-size:14px;line-height:18px;color:#1c2127;cursor:default}
    .cw-pill.on{background:rgba(45,114,210,.3);color:#184a90;font-weight:600}
    .cw-pill:not(.on){background:rgba(143,153,168,.15)}
    a.cw-pill{cursor:pointer}
    .cw-pill.ico{gap:8px}
    .cw-pico{width:16px;height:16px;flex:0 0 16px;background-position:center;background-size:16px;background-repeat:no-repeat}
    .cw-pico.vsc{background-image:url('${CW_VSCODE_ICON_URI}')}
    .cw-pico.jup{background-image:url('${CW_JUPYTER_ICON_URI}')}
    .cw-pico.rst{background-image:url('${CW_RSTUDIO_ICON_URI}')}
    .cw-vdiv{width:1px;height:20px;background:#d3d8de;margin-left:12px}
    .cw-vdiv + .cw-pill{margin-left:12px}
    .cw-table{margin-top:8px;height:max(360px,calc(100vh - 648px));overflow-y:auto;background:#fff;border-radius:4px;box-shadow:0 0 0 1px rgba(17,20,24,.15)}
    .cw-thead{display:flex;height:30px;box-shadow:inset 0 -1px 0 #dcdcdd}
    .cw-th{width:16.667%;padding:8px 0 0 11px;font-size:12px;line-height:15.43px;color:#5f6b7c;text-transform:uppercase}
    .cw-th.name{width:50%;padding-left:20px}
    .cw-row{display:flex;height:57px;box-shadow:inset 0 -1px 0 #dcdcdd;color:#1c2127}
    .cw-cell{width:16.667%;padding:19.5px 0 0 11px;font-size:14px;line-height:18px}
    .cw-cell.name{width:50%;padding:11px 0 0 20px;display:flex;align-items:flex-start}
    .cw-rowico{width:16px;height:16px;flex:0 0 16px;margin-top:2px;background:url('${DSG_ROW_DOC_URI}') center/16px no-repeat}
    .cw-rowdata{margin-left:7px;min-width:0;flex:1;padding-right:16px}
    .cw-rowname{display:block;font-size:14px;line-height:18px;color:#1c2127;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .cw-rowpath{display:block;font-size:12px;line-height:15.43px;color:#5f6b7c;margin-top:1px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .cw-lc{display:inline-block;margin-left:8px;padding:0 6px;border-radius:9px;font-size:11px;line-height:16px;vertical-align:1px}
    .cw-lc.run{background:rgba(45,114,210,.15);color:#184a90}
    .cw-lc.ok{background:rgba(35,133,81,.15);color:#1c6e42}
    .cw-lc.bad{background:rgba(205,66,70,.15);color:#ac2f33}
    .cw-dash{color:#5f6b7c}
    .cw-empty{padding:24px 20px;font-size:14px;color:#5f6b7c}
    .cw-examples{margin-top:28px}
    .cw-exh{font-size:16px;line-height:19px;font-weight:600;color:#1c2127;margin:0}
    .cw-exsub{font-size:14px;line-height:18.0013px;color:#1c2127;margin-top:12px}
    .cw-exstripwrap{position:relative;margin-top:7px;width:562px;margin-left:-1px}
    .cw-exstrip{display:block}
    .cw-excard{position:absolute;top:1px;width:270px;height:270px;cursor:default}
    .cw-excard.c1{left:1px}.cw-excard.c2{left:291px}
    .cw-truth{margin-top:30px;padding-bottom:40px}
    .cw-trutht{font-size:18px;font-weight:600;color:#1c2127;margin:0 0 8px}
    .cw-count{margin-left:8px;font-size:14px;font-weight:400;color:#5f6b7c;background:rgba(143,153,168,.15);border-radius:9px;padding:1px 8px}
    .cw-truthsub{font-size:13px;font-weight:400;color:#5f6b7c;margin-left:8px}
    .cw-boundary{font-size:13px;line-height:1.55;color:#1c2127;background:#fff;border-radius:4px;box-shadow:0 0 0 1px rgba(200,118,25,.4);padding:12px 14px;margin:0 0 14px}
    .cw-truthcols{display:flex;gap:16px;align-items:flex-start}
    .cw-truthcol{flex:1;min-width:0;background:#fff;border-radius:4px;box-shadow:0 0 0 1px rgba(17,20,24,.15);padding:14px 16px}
    .cw-truthcol h3{font-size:14px;font-weight:600;margin:0 0 8px;color:#1c2127}
    .cw-chip{display:inline-flex;gap:5px;padding:3px 10px;border-radius:12px;background:rgba(143,153,168,.15);color:#1c2127;font-size:12px}
    .cw-etlist{margin:6px 0 0;padding-left:18px}
    .cw-etline{margin:0 0 6px;font-size:12.5px}
    .cw-gapnote{font-size:12px;color:#5f6b7c;margin:8px 0 0;line-height:1.5}
    .cw-foot{font-size:12px;line-height:1.6;color:#7b8494;margin-top:18px}`;

  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Code Workspaces</title><style>${css}</style></head>
    <body><div class="cw-shell">${globalRail}<div class="cw-main">${topbar}<div class="cw-body">${band}<main class="cw-content">${runcard}${viewrow}${table}${examples}${truth}</main></div></div></div></body></html>`;
}
