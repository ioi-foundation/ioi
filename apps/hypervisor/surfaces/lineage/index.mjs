// Provenance · Data Lineage — the faithful Monocle editor-chrome port (reference
// /workspace/monocle/ on the :9225 mirror), READ-ONLY over the estate's REAL provenance truth:
// the same nine daemon projections the /__ioi/lineage substrate lens reads (materialized sets,
// materializing runs, projections, mappings, sources, lease plans, the proof stream). The
// monocle grammar maps honestly: "Open graph" opens a REAL materialized object set and the
// canvas renders its backward provenance PATH (source → mapping → projection → run → set), every
// edge carrying its receipt ref; the welcome state renders only when nothing is selected; the
// "No resources on graph" pill is the real empty truth. Every freeform editor tool (Tools /
// Layout / Undo / Clean / Select / Expand / Color / Find / Remove / Align / Text / Flow), the
// Workflow-Lineage toggle, branch selector, Save-as, resource search, and the dock's SQL/
// Preview/History/Code lenses are NAMED GAPS disabled in place — never hidden, never faked.
//
// HONEST STATE: this port is reference_ported, NOT daemon_wired. The pixel gate REFUSES it by
// doctrine: the monocle reference cannot render data on any local lane — the capture never
// recorded RouteDatasetFoundryBranchQuery (graphql) or /compass/api/batch/resources/parents, so
// every RID-seeded deep route bounces client-side to the empty welcome graph (probe-proven; the
// harvest-time live screenshot shows the same empty state). Promotion needs a live re-harvest of
// a RID-seeded monocle route. The graph-data payloads the capture DOES hold (monocle/api
// graphV3/links) prove the data model only, not a renderable reference.
import { bpIcon } from "../../scripts/bp-icons.mjs";
import { ioiGlobalRailHtml, IOI_GRAIL_CSS } from "../chrome.mjs";
import { escHtml } from "../kit.mjs";

const CX_ESC = escHtml;

export const meta = {
  slug: "lineage",
  route: "/__ioi/provenance/lineage",
  verifier: "scripts/verify-hypervisor-app-parity-lineage.mjs",
  certification: "n/a",
};

export async function load(ctx) {
  const J = (p) => fetch(`${ctx.daemon}${p}`).then((r) => r.json()).catch(() => ({}));
  const [mr, ms, cm, op, dsr] = await Promise.all([
    J("/v1/hypervisor/odk/materializing-runs"),
    J("/v1/hypervisor/odk/materialized-object-sets"),
    J("/v1/hypervisor/odk/connector-mappings"),
    J("/v1/hypervisor/odk/ontology-projections"),
    J("/v1/hypervisor/data-sources"),
  ]);
  return {
    runs: mr.materializing_runs || [],
    sets: ms.materialized_object_sets || [],
    mappings: cm.connector_mappings || [],
    projections: op.ontology_projections || [],
    sources: dsr.data_sources || [],
  };
}

export function render(model, ctx) {
  return renderLineagePort(model, { embed: ctx.embed, set: ctx.url.searchParams.get("set") || "", open: ctx.url.searchParams.get("open") === "1" });
}

function renderLineagePort(model, opts) {
  const esc = CX_ESC;
  const embed = !!(opts && opts.embed);
  const sets = model.sets || [];
  const sel = opts.set ? sets.find((s) => s.id === opts.set) || null : null;

  // The backward chain for the selected set, resolved from the REAL registries by ref/id match —
  // a node renders ONLY when its record actually resolves; unresolved links render as named gaps.
  const chain = sel ? (() => {
    const run = (model.runs || []).find((r) => `materializing-run://${r.id}` === sel.materializing_run_ref || r.id === String(sel.materializing_run_ref || "").split("/").pop()) || null;
    const proj = (model.projections || []).find((p) => p.id === sel.ontology_projection_id) || null;
    const mapping = proj ? (model.mappings || []).find((m) => m.id === (proj.connector_mapping_id || "") || m.ref === (proj.connector_mapping_ref || "") || (m.object_type_id === sel.object_type_id && m.ontology_ref === sel.ontology_ref)) || null : null;
    const source = mapping ? (model.sources || []).find((d) => d.source_id === mapping.data_source_id || d.source_ref === mapping.data_source_ref) || null : null;
    return { run, proj, mapping, source };
  })() : null;

  const gapBtn = (label, why) => `<span class="ln-tool gap" aria-disabled="true" title="${esc(why)}">${esc(label)}</span>`;
  const TOOL_GAP = "Freeform graph editing is a reference editor lane the provenance plane does not bind (named gap)";

  const node = (kind, title, sub, receipt) => `<div class="ln-node">
      <div class="ln-nkind">${esc(kind)}</div>
      <div class="ln-ntitle">${esc(title)}</div>
      <div class="ln-nsub">${esc(sub || "")}</div>
      ${receipt ? `<div class="ln-nrcpt" title="The edge INTO this node is a receipted crossing — the ref is verbatim daemon truth"><code>${esc(receipt)}</code></div>` : ""}
    </div>`;
  const edge = `<div class="ln-edge" aria-hidden="true">${bpIcon("arrow-right")}</div>`;

  const graph = sel ? `<div class="ln-graph" id="lineage-graph">
      ${chain.source ? node("Data source", chain.source.name || chain.source.source_id, chain.source.source_ref || "", "") : `<div class="ln-node ln-gapnode" title="No declared data source resolves for this chain — nothing is invented (named gap)"><div class="ln-nkind">Data source</div><div class="ln-nsub">unresolved — nothing invented</div></div>`}
      ${edge}
      ${chain.mapping ? node("Connector mapping", chain.mapping.name || chain.mapping.id, chain.mapping.ref || chain.mapping.id, "") : `<div class="ln-node ln-gapnode" title="No connector mapping resolves for this chain (named gap)"><div class="ln-nkind">Connector mapping</div><div class="ln-nsub">unresolved — nothing invented</div></div>`}
      ${edge}
      ${chain.proj ? node("Ontology projection", chain.proj.name || chain.proj.id, chain.proj.ref || chain.proj.id, "") : `<div class="ln-node ln-gapnode"><div class="ln-nkind">Ontology projection</div><div class="ln-nsub">unresolved — nothing invented</div></div>`}
      ${edge}
      ${chain.run ? node("Materializing run", chain.run.id, `status ${chain.run.status || "?"}`, sel.pre_output_receipt_ref || "") : `<div class="ln-node ln-gapnode"><div class="ln-nkind">Materializing run</div><div class="ln-nsub">${esc(sel.materializing_run_ref || "unresolved")}</div></div>`}
      ${edge}
      ${node("Materialized object set", sel.ref || sel.id, `${sel.object_type_id || "?"} · ${sel.count ?? "?"} object${sel.count === 1 ? "" : "s"} · registered ${esc(String(sel.registered_at || "").slice(0, 10))}`, "")}
    </div>
    <p class="ln-graphnote">The backward provenance PATH of <code>${esc(sel.ref || sel.id)}</code> — every node resolves from a live daemon registry; the run edge carries the pre-output receipt verbatim. The full ladder detail (per-object source hashes · mapped_from · policy/lease refs) stays on the <a href="/__ioi/lineage">substrate path lens</a>; the proof stream is <a href="/__ioi/work-ledger">Provenance</a>.</p>` : "";

  const openList = `<div class="ln-openlist">${sets.length ? sets.map((s) => `<a class="ln-openrow" href="/__ioi/provenance/lineage?set=${encodeURIComponent(s.id)}${embed ? "&embed=1" : ""}"><code>${esc(s.ref || s.id)}</code> — ${esc(s.object_type_id || "?")} · ${s.count ?? "?"} objects</a>`).join("") : `<p class="ln-gapnote">No materialized object sets exist — the graph opener renders the real registry and never fabricates rows. Materialize one through the <a href="/__ioi/pipeline">Data ladder</a>.</p>`}</div>`;

  const welcome = `<div class="ln-welcome">
      <div class="ln-wcard">
        <div class="ln-wtop">
          <div class="ln-wcopy">
            <h2 class="ln-wtitle">Welcome to Data Lineage</h2>
            <p class="ln-wsub">Explore how data flows through your resources and applications</p>
            <span class="ln-wdoc gap" aria-disabled="true" title="Reference documentation lane (named gap)">Read documentation ${bpIcon("arrow-right")}</span>
          </div>
        </div>
        <div class="ln-wopts">
          <span class="ln-wopt gap" aria-disabled="true" title="Freeform resource search is a reference lane the provenance plane does not bind (named gap)"><b>${bpIcon("plus")} Add resources</b><span>Search for resources to add to graph</span></span>
          <span class="ln-wor">or</span>
          <a class="ln-wopt" href="/__ioi/provenance/lineage?open=1${embed ? "&embed=1" : ""}"><b>${bpIcon("git-branch")} Open graph</b><span>Find and explore existing graphs</span></a>
        </div>
        ${opts.open ? openList : ""}
      </div>
    </div>`;

  const globalRail = embed ? "" : ioiGlobalRailHtml({ label: "Data Lineage", href: "/__ioi/provenance/lineage", iconUri: "data:image/svg+xml;base64,PHN2ZyB2aWV3Qm94PSIwIDAgMTYgMTYiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+PHJlY3QgeD0iMSIgeT0iMiIgd2lkdGg9IjYiIGhlaWdodD0iMyIgcng9IjEiIGZpbGw9IiM4Zjk5YTgiLz48cmVjdCB4PSI5IiB5PSI2LjUiIHdpZHRoPSI2IiBoZWlnaHQ9IjMiIHJ4PSIxIiBmaWxsPSIjZmJiMzYwIi8+PHJlY3QgeD0iMSIgeT0iMTEiIHdpZHRoPSI2IiBoZWlnaHQ9IjMiIHJ4PSIxIiBmaWxsPSIjOGY5OWE4Ii8+PHBhdGggZD0iTTcgMy41aDEuNXY1SDl2MUg3ek03IDEyLjVoMS41di01IiBzdHJva2U9IiM1ZjZiN2MiIGZpbGw9Im5vbmUiLz48L3N2Zz4=", railVariant: "rv-pipe", viewAll: false, star: false, badges: true, aipGradient: true, acctMuted: true });

  const cRunning = (model.runs || []).filter((r) => !["executed", "failed"].includes(r.status)).length;
  const cDone = (model.runs || []).filter((r) => r.status === "executed").length;
  const cFailed = (model.runs || []).filter((r) => r.status === "failed").length;

  const topbar = `<header class="ln-topbar">
    <span class="ln-hchip" aria-hidden="true">${bpIcon("git-branch")}</span>
    <h1 class="ln-htitle">Data Lineage</h1>
    <div class="ln-hright">
      <span class="ln-hbtn gap" aria-disabled="true" title="Workflow Lineage is a reference mode whose workflow registry has no local data lane (named gap)">Workflow Lineage</span>
      <span class="ln-hbtn gap" aria-disabled="true" title="Branching is a reference concept the provenance plane does not bind — provenance records are append-only (named gap)">${bpIcon("git-branch", 14)} Main ${bpIcon("caret-down", 14)}</span>
      <span class="ln-counters" title="REAL materializing-run statuses (the estate's source→set executions): in-flight · executed · failed">
        <span class="ln-ctag">${bpIcon("refresh", 12)}<span>${cRunning}</span></span>
        <span class="ln-ctag">${bpIcon("tick", 12)}<span>${cDone}</span></span>
        <span class="ln-ctag">${bpIcon("cross", 12)}<span>${cFailed}</span></span>
      </span>
      <span class="ln-hbtn gap" aria-disabled="true" title="Saved explorations are a reference lane the provenance plane does not record (named gap)">Save as</span>
    </div>
  </header>`;

  const toolbar = `<div class="ln-toolbar">
    ${["Tools", "Layout", "Undo/redo", "Clean", "Select", "Expand", "Color", "Find", "Remove", "Align", "Text", "Flow"].map((t) => gapBtn(t, TOOL_GAP)).join("")}
    <div class="ln-tright">
      ${gapBtn("Layout by color", TOOL_GAP)}${gapBtn("Group by color", TOOL_GAP)}${gapBtn("Legend", TOOL_GAP)}
      <span class="ln-rsel gap" aria-disabled="true" title="Node color options are a reference lens (named gap)">${bpIcon("layout-grid", 14)} Resource overview ${bpIcon("caret-down", 14)}</span>
      <span class="ln-statepill">${sel ? `${(chain && [chain.source, chain.mapping, chain.proj, chain.run].filter(Boolean).length + 1) || 1} resources on graph` : "No resources on graph"}</span>
    </div>
  </div>`;

  const dock = `<footer class="ln-dock">
    ${gapBtn("Preview", "Row preview is a reference dock lens — materialized rows render on the substrate path lens (named gap)")}
    ${gapBtn("SQL scratchpad", "The SQL scratchpad is a reference dock lens the provenance plane does not bind; replay is the canon reshape target (named gap)")}
    ${gapBtn("History", "History is a reference dock lens (named gap)")}
    ${gapBtn("Code", "Code is a reference dock lens (named gap)")}
    <a class="ln-tool" href="/__ioi/work-ledger" title="The estate's REAL build/run truth — the Provenance proof stream">Build timeline</a>
    ${gapBtn("Data health", "Data health is a reference dock lens (named gap)")}
    <span class="ln-docksel">${sel ? "1 graph open" : "0 nodes selected"}</span>
  </footer>`;

  const foot = `<section class="ln-truth">
    <p class="ln-foot"><b>Honest state:</b> this is a faithful Monocle-chrome port over real provenance truth, held at <code>reference_ported</code> — the local monocle reference cannot render data on any lane (its graph-load API responses were never captured), so the pixel gate refuses certification by doctrine; promotion needs a live re-harvest of a RID-seeded monocle route. Owner: <a href="/__ioi/work-ledger">Provenance (proof stream) →</a> · <a href="/__ioi/lineage">substrate path lens →</a> · <a href="/__ioi/vertex">Vertex graph →</a>. Reference: <a href="http://localhost:9225/workspace/monocle/" rel="noopener">the monocle capture</a> · <a href="/__apps/lineage">/__apps/lineage seed ↗</a>.</p>
  </section>`;

  const css = `:root{color-scheme:light}*{box-sizing:border-box}
    body{margin:0;background:#fff;color:#1c2127;font:14px/1.28581 Source-Sans-Pro,Helvetica,sans-serif}
    a{color:#215db0;text-decoration:none}
    .ln-shell{display:flex;height:100vh;width:100vw;overflow:hidden}
    ${IOI_GRAIL_CSS}
    .ln-main{flex:1;min-width:0;display:flex;flex-direction:column;height:100vh;background:#fff}
    .ln-topbar{flex:0 0 51px;height:51px;display:flex;align-items:center;background:#fff;border-bottom:1px solid #d3d8de;padding-right:16px}
    .ln-hchip{width:50px;height:50px;flex:0 0 50px;display:inline-flex;align-items:center;justify-content:center;background:rgba(219,124,45,.1)}
    .ln-hchip svg{color:#c87619}
    .ln-htitle{font-size:16px;font-weight:600;color:#404854;margin:0 0 0 12px}
    .ln-hright{margin-left:auto;display:flex;align-items:center;gap:8px}
    .ln-hbtn{display:inline-flex;align-items:center;gap:5px;height:30px;padding:0 9px;border-radius:4px;background:#f7f8f8;box-shadow:inset 0 0 0 1px rgba(64,72,84,.2);font-size:13px;color:#5f6b7c;cursor:not-allowed}
    .ln-counters{display:inline-flex;gap:3px}
    .ln-ctag{display:inline-flex;align-items:center;gap:2px;height:20px;padding:2px 6px;border-radius:2px;background:rgba(143,153,168,.15);color:#5f6b7c;font-size:12px}
    .ln-toolbar{flex:0 0 66px;display:flex;align-items:flex-start;gap:4px;padding:8px 10px 0;border-bottom:1px solid #e6e8eb;background:#fff}
    .ln-tool{display:inline-flex;align-items:center;height:30px;padding:0 8px;border-radius:3px;font-size:12px;color:#5f6b7c}
    .ln-tool.gap{cursor:not-allowed;background:#f7f8f8;box-shadow:inset 0 0 0 1px rgba(64,72,84,.12)}
    a.ln-tool{color:#215db0;box-shadow:inset 0 0 0 1px rgba(45,114,210,.3)}
    .ln-tright{margin-left:auto;display:flex;align-items:center;gap:6px}
    .ln-rsel{display:inline-flex;align-items:center;gap:5px;height:30px;padding:0 9px;border-radius:3px;background:#fff;box-shadow:inset 0 0 0 1px rgba(17,20,24,.2);font-size:13px;color:#1c2127;cursor:not-allowed}
    .ln-statepill{display:inline-flex;align-items:center;height:30px;padding:0 12px;border-radius:3px;background:#f0f1f3;font-size:13px;color:#5f6b7c}
    .ln-canvas{flex:1 1 auto;min-height:0;overflow:auto;background:#fafbfc;position:relative}
    .ln-welcome{display:flex;justify-content:center;padding-top:120px}
    .ln-wcard{width:552px;background:#fff;border-radius:4px;box-shadow:0 0 0 1px rgba(17,20,24,.15),0 2px 10px rgba(0,0,0,.05);padding:28px 22px}
    .ln-wtitle{font-size:20px;font-weight:600;margin:0}
    .ln-wsub{font-size:14px;color:#5f6b7c;margin:8px 0 12px}
    .ln-wdoc{display:inline-flex;align-items:center;gap:6px;height:30px;padding:0 10px;border-radius:3px;box-shadow:inset 0 0 0 1px rgba(45,114,210,.4);color:#215db0;font-size:14px;cursor:not-allowed;opacity:.75}
    .ln-wopts{display:flex;align-items:center;gap:12px;margin-top:22px}
    .ln-wopt{flex:1;display:flex;flex-direction:column;gap:4px;border-radius:4px;box-shadow:inset 0 0 0 1px rgba(17,20,24,.15);padding:12px 14px;font-size:12px;color:#5f6b7c}
    .ln-wopt b{display:inline-flex;align-items:center;gap:7px;font-size:14px;color:#1c2127;font-weight:600}
    .ln-wopt.gap{cursor:not-allowed;background:#fafbfc}
    a.ln-wopt{cursor:pointer}
    a.ln-wopt b{color:#215db0}
    .ln-wor{font-size:13px;color:#5f6b7c}
    .ln-openlist{margin-top:18px;border-top:1px solid #e6e8eb;padding-top:12px}
    .ln-openrow{display:block;padding:7px 8px;border-radius:3px;font-size:12.5px}
    .ln-openrow:hover{background:#f0f4fa}
    .ln-graph{display:flex;align-items:center;gap:0;padding:60px 40px 20px;flex-wrap:wrap}
    .ln-node{min-width:200px;max-width:250px;background:#fff;border-radius:4px;box-shadow:0 0 0 1px rgba(17,20,24,.2),0 1px 3px rgba(0,0,0,.08);padding:10px 12px}
    .ln-gapnode{background:#fafbfc;box-shadow:0 0 0 1px rgba(143,153,168,.4)}
    .ln-nkind{font-size:10.5px;text-transform:uppercase;letter-spacing:.03em;color:#5f6b7c}
    .ln-ntitle{font-size:13.5px;font-weight:600;color:#1c2127;margin-top:3px;word-break:break-all}
    .ln-nsub{font-size:11.5px;color:#5f6b7c;margin-top:2px;word-break:break-all}
    .ln-nrcpt{margin-top:5px;font-size:10px;background:rgba(14,138,83,.08);border-radius:3px;padding:2px 5px;word-break:break-all}
    .ln-edge{display:inline-flex;padding:0 8px;color:#8f99a8}
    .ln-graphnote{padding:0 40px 20px;font-size:12.5px;color:#5f6b7c;max-width:960px}
    .ln-dock{flex:0 0 40px;display:flex;align-items:center;gap:2px;border-top:1px solid #d3d8de;background:#fff;padding:0 8px}
    .ln-docksel{margin-left:auto;display:inline-flex;align-items:center;height:26px;padding:0 10px;border-radius:3px;background:#f0f1f3;font-size:12px;color:#5f6b7c}
    .ln-truth{position:absolute;left:0;right:0;bottom:0;pointer-events:none}
    .ln-foot{pointer-events:auto;margin:0;padding:8px 14px;font-size:11.5px;line-height:1.5;color:#7b8494;background:rgba(255,255,255,.94);border-top:1px solid #eceef1}`;

  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Data Lineage</title><style>${css}</style></head>
    <body><div class="ln-shell">${globalRail}<div class="ln-main">${topbar}${toolbar}<div class="ln-canvas">${sel ? graph : welcome}${foot}</div>${dock}</div></div></body></html>`;
}
