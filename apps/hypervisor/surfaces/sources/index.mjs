// Data · Sources (Data Connection) — the governed DECLARE-SOURCE cut (operational wave PR #69,
// atlas queue head). The render code below is moved from serve-product-ui.mjs (the #52 certified
// landing, #64 semantic selection preserved); the module adds the surface contract PLUS the
// surface's FIRST mutation: New source / Connect to external system open a bounded declare form
// whose kind picker and endpoint requirement derive from the daemon's own declaration vocabulary
// (GET /v1/hypervisor/data-sources/overview → source_kinds), and submit through the estate action
// runtime to the EXISTING fail-closed authority POST /v1/hypervisor/data-sources — atomic
// record-first/receipt-second persistence, dsr_ receipt returned explicitly, every typed daemon
// refusal rendered in place. NO free-text secret field exists anywhere in the form (credential
// posture is a declared vocabulary pick); endpoints render scheme+host+path only. Everything past
// declaration — extraction, connection tests, editing, deletion, syncs, agents, listeners,
// external stacks, uploads, synthesis, marketplace installs — stays DISABLED with its exact
// missing-contract reason (data-source PATCH/DELETE routes absent; ingestion authority absent).
import { bpIcon } from "../../scripts/bp-icons.mjs";
import { SRC_APP_TILE_URI, SRC_HERO_URI, SRC_SETUP_STRIP_URI } from "../../scripts/sources-assets.mjs";
import { MCH_STORE_ICON_URI, MCH_EXAMPLES_STRIP_URI } from "../../scripts/machinery-assets.mjs";
import { DSG_ROW_DOC_URI } from "../../scripts/designer-assets.mjs";
import { ioiGlobalRailHtml, IOI_GRAIL_CSS } from "../chrome.mjs";
import { escHtml } from "../kit.mjs";
import { managerLink, managerResourceLink, pipelineNodeLink } from "../ontology-context.mjs";

const CX_ESC = escHtml; // local alias so the moved block stays aligned with its serve original

export const meta = {
  slug: "sources",
  route: "/__ioi/data/sources",
  verifier: "scripts/verify-hypervisor-app-parity-sources.mjs",
  certification: "pixel-certifications/sources.json",
};

export async function load(ctx) {
  const J = (p) => fetch(`${ctx.daemon}${p}`).then((r) => r.json()).catch(() => null);
  const [ds, mr, cm, ov] = await Promise.all([
    J("/v1/hypervisor/data-sources"),
    J("/v1/hypervisor/odk/materializing-runs"),
    J("/v1/hypervisor/odk/connector-mappings"),
    J("/v1/hypervisor/data-sources/overview"),
  ]);
  return {
    sources: (ds && ds.data_sources) || [],
    runs: (mr && mr.materializing_runs) || [],
    mappings: (cm && cm.connector_mappings) || [],
    // The declaration vocabulary is DAEMON TRUTH: null when unreachable — the form fails closed.
    overview: ov && Array.isArray(ov.source_kinds) ? ov : null,
  };
}

export function render(model, ctx) {
  const sp = ctx.url.searchParams;
  return renderSourcesPort(model.sources, model.runs, model.mappings, sp.get("dataSource") || "", {
    embed: ctx.embed,
    declare: sp.get("declare") === "1",
    kind: sp.get("kind") || "",
    overview: model.overview,
    banner: {
      acted: sp.get("acted") || "",
      receipt: sp.get("receipt") || "",
      refused: sp.get("refused") || "",
      reason: sp.get("reason") || "",
      record: sp.get("record") || "",
      result: sp.get("result") || "",
    },
  });
}

// The surface's ONE receipted mutation (atlas: governed_receipted_action for New source and the
// Connect-to-external-system card — both funnel here). Declaration is PERMANENT (no delete
// authority exists on the plane), so the runtime enforces explicit confirmation server-side.
export const actions = [
  {
    id: "declare", method: "POST", route: "/actions/declare",
    fields: ["name", "kind", "endpoint", "credential_posture"],
    context: [],
    authority: { plane: "data-sources", operation: "POST /v1/hypervisor/data-sources" },
    receipt: "ioi.hypervisor.data-source-receipt.v1",
    confirm: true, success: "return-to-surface", refusal: "typed-banner",
  },
];

// One typed result, always: success carries the created record id + the explicit dsr_ receipt ref
// and redirects to the new record's selection; refusal carries the daemon's typed code/message
// with state untouched (the redirect re-opens the declare pane, echoing ONLY the validated kind —
// never the endpoint, which could carry the rejected credential material).
export async function handleAction({ fields, daemon }) {
  const payload = {};
  for (const k of ["name", "kind", "endpoint", "credential_posture"]) {
    if (fields[k] !== undefined && String(fields[k]).trim() !== "") payload[k] = String(fields[k]).trim();
  }
  const kindEcho = /^[a-z_]{1,40}$/.test(payload.kind || "") ? `&kind=${payload.kind}` : "";
  const paneRedirect = `/__ioi/data/sources?declare=1${kindEcho}`;
  const r = await fetch(`${daemon}/v1/hypervisor/data-sources`, {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload),
  }).then(async (x) => ({ status: x.status, j: await x.json().catch(() => ({})) })).catch(() => null);
  if (!r) return { kind: "failure", http: 502, code: "daemon_unavailable", message: "the daemon did not answer — nothing was declared", redirect: paneRedirect };
  if (r.j && r.j.error) return { kind: "refusal", http: r.status || 400, code: r.j.error.code || "data_source_refused", message: r.j.error.message || "refused — state unchanged", redirect: paneRedirect };
  const rec = r.j && r.j.data_source;
  const receipt = r.j && r.j.data_source_receipt;
  if (r.status !== 201 || !rec || !rec.source_id) {
    return { kind: "failure", http: 502, code: "data_source_result_invalid", message: "the daemon returned no declared record — failing closed", redirect: paneRedirect };
  }
  if (!receipt || !receipt.receipt_ref || receipt.schema_version !== "ioi.hypervisor.data-source-receipt.v1") {
    return { kind: "failure", http: 502, code: "receipt_missing", message: "the declaration returned no explicit receipt — failing closed (do not trust the mutation)", redirect: paneRedirect };
  }
  return { kind: "success", status: "declared", created: rec.source_id, receipt_ref: receipt.receipt_ref, redirect: `/__ioi/data/sources?dataSource=${encodeURIComponent(rec.source_id)}` };
}

// ============================ DATA · SOURCES — Data Connection landing port (#52; declare #69).
// #64: mappings resolve per source (data_source_id join) — the semantic layer over declared
// sources. ?dataSource= is URL-addressable selection; #69 adds ?declare=1 (the governed declare
// pane — the ONLY pane with a form; the bare certified render carries none). No credential lanes,
// endpoints stay scheme+host+path.
function renderSourcesPort(sources, mruns, srcMappings, dataSourceSel, opts) {
  const mapsOf = (sid) => srcMappings.filter((mm) => mm.data_source_id === sid);
  const esc = CX_ESC;
  const list = Array.isArray(sources) ? sources : [];
  const runs = Array.isArray(mruns) ? mruns : [];
  const embed = !!(opts && opts.embed);
  const fdate = (iso) => { const d = new Date(iso || 0); return isNaN(d) ? "—" : d.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" }); };
  // SAFE endpoint rendering: scheme + host + path ONLY — userinfo, query and fragment are stripped
  // (never render a credential-bearing URL part; the registry itself must never hold secrets).
  const safeEndpoint = (ep) => {
    if (!ep) return "";
    try { const u = new URL(ep); return `${u.protocol}//${u.host}${u.pathname}`; } catch { return String(ep).split(/[?#@]/)[0]; }
  };

  // Sync-counter cluster semantics over REAL plane truth: the estate's source→set executions are
  // ODK materializing runs — in-flight (not yet executed/failed) · executed · failed.
  const cInflight = runs.filter((r) => !["executed", "failed"].includes(r.status)).length;
  const cDone = runs.filter((r) => r.status === "executed").length;
  const cFailed = runs.filter((r) => r.status === "failed").length;

  const recent = [...list].sort((a, b) => String(b.created_at || "").localeCompare(String(a.created_at || ""))).slice(0, 12);
  const gapDash = (why) => `<span class="src-dash" title="${esc(why)}">—</span>`;
  const rowsHtml = recent.length ? recent.map((s) => `<div class="src-row${dataSourceSel && s.source_id === dataSourceSel ? " src-sel" : ""}"${dataSourceSel && s.source_id === dataSourceSel ? ' aria-current="true"' : ""} title="A DECLARED source — a registry record, not a connection; extraction requires a future authority crossing (the daemon's own boundary)">
      <span class="src-cell name">
        <span class="src-rowico" aria-hidden="true"></span>
        <span class="src-rowdata">
          <span class="src-rowname">${esc(s.name || s.source_id)}${s.ingestion && s.ingestion.wired === false ? `<span class="src-wired" title="${esc((s.ingestion || {}).note || "declaration only")}">not wired</span>` : ""}</span>
          <span class="src-rowpath">${esc(s.source_ref || s.source_id)} · ${esc(s.kind || "?")} · ${esc(s.credential_posture || "no posture")} · ${esc((s.lifecycle || {}).status || "declared")} · created ${fdate(s.created_at)}${s.endpoint ? ` · ${esc(safeEndpoint(s.endpoint))}` : ""} · ${mapsOf(s.source_id).length ? `<a href="/__ioi/data/sources?dataSource=${encodeURIComponent(s.source_id)}">${mapsOf(s.source_id).length} semantic mapping${mapsOf(s.source_id).length === 1 ? "" : "s"} →</a>` : `<span class="src-dash" title="No connector mapping declares this source — nothing is invented">no semantic mapping declared</span>`}</span>
        </span>
      </span>
      <span class="src-cell">${gapDash("No principal is recorded on the data-source registry (named gap)")}</span>
      <span class="src-cell">${gapDash("No edit principal is recorded on the data-source registry (named gap)")}</span>
      <span class="src-cell">${gapDash("View tracking is not recorded on the data-source registry (named gap)")}</span>
    </div>`).join("") : `<div class="src-empty">No data sources declared yet — this table renders the real DataSource registry and never fabricates rows. Declare one with <a href="/__ioi/data/sources?declare=1">New source</a> (a receipted registry record), or through the <a href="/__ioi/pipeline">Data ladder</a>.</div>`;

  // Declared-catalog census (below the fold): kinds + credential postures + the wired:false boundary.
  const byKind = {}; const byPosture = {};
  let wiredFalse = 0;
  for (const s of list) {
    byKind[s.kind || "?"] = (byKind[s.kind || "?"] || 0) + 1;
    byPosture[s.credential_posture || "none"] = (byPosture[s.credential_posture || "none"] || 0) + 1;
    if (s.ingestion && s.ingestion.wired === false) wiredFalse++;
  }
  const ingestionNote = (list[0] && list[0].ingestion && list[0].ingestion.note) || "declaration only — extraction requires a future authority crossing (named gap)";
  const chips = (obj) => Object.entries(obj).sort((a, b) => b[1] - a[1]).map(([k, n]) => `<span class="src-chip">${esc(k)} <b>${n}</b></span>`).join("");

  // Action-result banner (#ap-result — the runtime's redirect anchor): success shows the durable
  // dsr_ receipt ref + the created record (selected); refusal shows the daemon's typed code and
  // message and states plainly that nothing changed. Renders ONLY when the runtime redirected
  // here with result params — the bare/certified render carries no banner.
  const bn = (opts && opts.banner) || {};
  const banner = bn.acted && bn.receipt
    ? `<div id="ap-result" class="src-banner src-ok" tabindex="-1"><b>${esc(bn.acted)}</b> recorded${bn.result ? ` — <b>${esc(bn.result)}</b>` : ""} · receipt <code class="src-rcpt">${esc(bn.receipt)}</code>${bn.record ? ` · <a href="/__ioi/data/sources?dataSource=${encodeURIComponent(bn.record)}">record</a>` : ""} · <a href="/__ioi/work-ledger">proof stream</a></div>`
    : bn.refused
      ? `<div id="ap-result" class="src-banner src-no" tabindex="-1">refused: <code>${esc(bn.refused)}</code>${bn.reason ? ` — ${esc(bn.reason)}` : ""} · <b>state unchanged</b> — the daemon's typed fail-closed boundary held; nothing was declared</div>`
      : "";

  // #69 — the governed DECLARE pane (?declare=1 only; the certified bare render never carries it).
  // The kind picker + per-kind endpoint requirement derive from the DAEMON's own declaration
  // vocabulary (overview.source_kinds / credential_postures) — never a hardcoded copy. No
  // free-text secret field exists: the credential story is a declared POSTURE pick; the secret
  // stays in the daemon credential planes. Declaration is permanent (no delete authority), so the
  // form carries a required confirmation the runtime re-enforces server-side.
  const ov = opts && opts.overview;
  const declarePane = !(opts && opts.declare) ? "" : `<section class="src-declare" id="declare-pane">
    ${banner}
    <h2 class="src-decth">Declare a new data source <span class="src-truthsub">a validated, receipted registry record via <code>POST /v1/hypervisor/data-sources</code> — declaration only; extraction stays a named gap</span></h2>
    ${ov ? (() => {
      const kinds = ov.source_kinds || [];
      const postures = ov.credential_postures || [];
      const selKind = kinds.some((k) => k.kind === opts.kind) ? opts.kind : kinds[0] ? kinds[0].kind : "";
      const selReq = (kinds.find((k) => k.kind === selKind) || {}).requires_endpoint === true;
      const kindNav = `location.href='/__ioi/data/sources?declare=1${embed ? "&embed=1" : ""}&kind='+encodeURIComponent(this.value)`;
      return `<form class="src-decform" method="post" action="/__ioi/data/sources/actions/declare">
      <input type="hidden" name="return" value="/__ioi/data/sources?declare=1${selKind ? `&kind=${esc(selKind)}` : ""}">
      <label class="src-declabel">Name <input class="src-decinp" type="text" name="name" maxlength="120" required placeholder="A display name for the declared source"></label>
      <label class="src-declabel">Kind <select class="src-decsel" name="kind" onchange="${kindNav}" title="The kind vocabulary is daemon truth (overview.source_kinds); picking a kind re-derives the endpoint requirement">${kinds.map((k) => `<option value="${esc(k.kind)}"${k.kind === selKind ? " selected" : ""}>${esc(k.kind)} — ${k.requires_endpoint ? "endpoint required" : "no endpoint (local)"}</option>`).join("")}</select></label>
      <label class="src-declabel">Endpoint <input class="src-decinp" type="text" name="endpoint" maxlength="2000"${selReq ? " required" : ""} placeholder="${selReq ? "required for this kind — scheme://host/path, no userinfo, no credential query params" : "not required for this local kind"}"> <span class="src-dechint">${selReq ? "required" : "optional"} for <code>${esc(selKind)}</code> (daemon truth) — a credential-bearing endpoint is refused typed</span></label>
      <label class="src-declabel">Credential posture <select class="src-decsel" name="credential_posture" title="A declared posture from the daemon vocabulary — never a credential value">${postures.map((p) => `<option value="${esc(p)}">${esc(p)}</option>`).join("")}</select></label>
      <label class="src-decconfirm"><input type="checkbox" name="confirm" value="1" required> confirm — this declares a <b>permanent</b> registry record (no delete/retire authority exists on the plane); the declaration is recorded with a durable receipt</label>
      <button class="src-decsubmit" type="submit">Declare source</button>
      <p class="src-gapnote">No secret field exists on this form by design — credentials are a declared <b>posture</b>, never a value; the daemon rejects plaintext-secret keys and credential-bearing endpoints outright. This form declares a record only: live-connection setup/extraction is not a bound lane (the <code>wired:false</code> boundary), and credential binding by lease ref stays an API-level declaration (no custody picker on this surface — named gap).</p>
    </form>`;
    })() : `<p class="src-gapnote src-decfail">The declaration vocabulary (kinds, endpoint requirements, credential postures) is DAEMON TRUTH and the daemon overview is unreachable — the form fails closed rather than invent options. Nothing can be declared right now.</p>`}
    <a class="src-decclose" href="/__ioi/data/sources">Close</a>
  </section>`;

  // #64: the selected source's semantic panel — its real mappings with owner links (Manager
  // typed resource · object-type definition · ontology · Pipeline mapping node). Fail-closed on
  // an unknown id; "no semantic mapping declared" is stated, never invented. #69 adds the
  // record's own disabled mutations with their EXACT missing contracts.
  const selSrc = dataSourceSel ? list.find((s) => s.source_id === dataSourceSel) || null : null;
  const selGaps = `<div class="src-selgaps">
      <span class="src-selgap" aria-disabled="true" title="PATCH /v1/hypervisor/data-sources/:id does not exist — no update authority on the declared registry (named gap)">Edit source</span>
      <span class="src-selgap" aria-disabled="true" title="DELETE /v1/hypervisor/data-sources/:id does not exist — no delete/retire authority; declarations are permanent records (named gap)">Delete source</span>
      <span class="src-selgap" aria-disabled="true" title="No connection-test authority exists — the plane is declaration-only; ingestion.wired:false is the daemon's own boundary (named gap)">Test connection</span>
      <span class="src-selgap" aria-disabled="true" title="Extraction requires a future wallet/authority crossing bound to admitted substrate — the daemon's own named gap; the governed read path is the ODK ladder">Extract</span>
    </div>`;
  const selPanel = !dataSourceSel ? "" : `<section class="src-truth" id="source-selected">${!(opts && opts.declare) ? banner : ""}${selSrc ? (() => {
    const sm = mapsOf(selSrc.source_id);
    const smRows = sm.map((mm) => {
      const ontId = String(mm.ontology_ref || "").replace("ontology://", "");
      return `<li class="src-mapline"><b>${esc(mm.name || mm.id)}</b> <code>${esc(mm.ref || mm.id)}</code> — <a href="${managerResourceLink(ontId, "connector-mapping", mm.id)}">Manager resource</a> · <a href="${managerLink({ ontology: ontId, section: "object-types", definitionKind: "object-type", definitionId: mm.object_type_id })}">object type ${esc(mm.object_type_id || "")}</a> · <a href="${managerLink({ ontology: ontId })}">ontology</a> · <a href="${pipelineNodeLink(ontId, "mapping")}">Pipeline</a></li>`;
    }).join("");
    return `<h2 class="src-trutht">Selected source — ${esc(selSrc.name || selSrc.source_id)} <span class="src-truthsub">${esc(selSrc.source_ref || "")} · ${esc(selSrc.kind || "")} · ${esc(selSrc.credential_posture || "")}</span></h2>
    ${selGaps}
    ${sm.length ? `<ul class="src-maplist">${smRows}</ul>` : `<p class="src-gapnote">No semantic mapping declared for this source — nothing is invented. Declare one through the <a href="/__ioi/pipeline">ODK ladder</a>.</p>`}`;
  })() : `<p class="src-gapnote">No declared source matches <code>${esc(dataSourceSel)}</code> — nothing selected (fail-closed).</p>`}</section>`;

  const truth = `${selPanel}<section class="src-truth" id="sources-catalog">
    <h2 class="src-trutht">Declared source catalog <span class="src-count">${list.length}</span> <span class="src-truthsub">the real DataSource registry — newest 12 shown above; every record is daemon truth, nothing invented</span></h2>
    <p class="src-boundary"><b>The authority boundary:</b> ${wiredFalse} of ${list.length} source${list.length === 1 ? "" : "s"} carry <code>ingestion.wired:false</code> — the daemon's own note, verbatim: <i>“${esc(ingestionNote)}”</i>. This surface is a DECLARED catalog: no extraction, no connection test, no live connector read, no materialization happens here — the governed path runs through the <a href="/__ioi/pipeline">ODK ladder</a> (mapping → policy gate → projection → lease → sealed session → materialized set).</p>
    <div class="src-truthcols">
      <div class="src-truthcol"><h3>By kind</h3><div class="src-chips">${chips(byKind)}</div></div>
      <div class="src-truthcol"><h3>By credential posture</h3><div class="src-chips">${chips(byPosture)}</div><p class="src-gapnote">Credential postures are declared postures — credential VALUES never appear on this surface, in the registry records, or in receipts.</p></div>
      <div class="src-truthcol"><h3>Sync activity (real)</h3><p class="src-gapnote">The header counters are the estate's REAL source→set executions (ODK materializing runs): ${cInflight} in-flight · ${cDone} executed · ${cFailed} failed. Endpoints render scheme+host+path only (userinfo/query/fragment stripped).</p></div>
    </div>
    <p class="src-foot"><b>New source</b> and <b>Connect to external system</b> are the surface's governed receipted declaration (POST /v1/hypervisor/data-sources → dsr_ receipt); everything past declaration stays a <b>named gap disabled in place</b>, never hidden — live-connection setup/extraction (the wired:false boundary), source edit/delete (no PATCH/DELETE route exists), connection tests, static upload, data synthesis, the store menu, Syncs/Agents/Listeners/External-stacks tabs, marketplace example installs (the set-up cards and example cards are the reference's own onboarding chrome, embedded verbatim, not extraction affordances). Owner family: <a href="/__ioi/pipeline">Data ladder (Pipeline Builder)</a> · <a href="/__ioi/odk">ODK builder</a>. Reference: the origin-aligned <a href="http://localhost:9225/workspace/data-ingestion-app/" rel="noopener">Data Connection capture</a> — the <a href="/__apps/sources">/__apps/sources proxy lane ↗</a> is documented insufficient (renders no data; #44 sweep evidence).</p>
  </section>`;

  // Embedded (native container contract #65): the native rail owns platform nav — emit no global rail.
  const globalRail = embed ? "" : ioiGlobalRailHtml({ label: "Data Connection", href: "/__ioi/data/sources", iconUri: SRC_APP_TILE_URI, railVariant: "rv-pipe rv-dsg", viewAll: true, star: false, badges: true, aipGradient: true, acctMuted: true });

  const header = `<header class="src-header">
    <span class="src-hchip" aria-hidden="true"></span>
    <h1 class="src-htitle">Data Connection</h1>
    <span class="src-hdiv" aria-hidden="true"></span>
    <nav class="src-tabs">
      <a class="src-tab" href="/__ioi/data/sources" aria-current="page">Sources</a>
      <span class="src-tab gap" aria-disabled="true" title="Sync scheduling is not a bound lane — the estate's real source→set executions are ODK materializing runs (named gap)">Syncs</span>
      <span class="src-tab gap" aria-disabled="true" title="Connection agents are a reference-only lane (named gap)">Agents</span>
      <span class="src-tab gap" aria-disabled="true" title="Listeners are a reference-only lane (named gap)">Listeners</span>
      <span class="src-tab gap" aria-disabled="true" title="External stacks are a reference-only lane (named gap)">External stacks</span>
    </nav>
    <div class="src-hright">
      <span class="src-hbtn store gap" aria-disabled="true" title="Recent installations — marketplace install lanes are not bound to this surface (named gap)"><span class="src-storeico" aria-hidden="true"></span>${bpIcon("caret-down")}</span>
      <a class="src-hbtn success" href="/__ioi/data/sources?declare=1" title="Declare a new data source — a validated, receipted registry record via the daemon's fail-closed POST /v1/hypervisor/data-sources (declaration only; extraction stays a named gap)">${bpIcon("plus")}<span>New source</span></a>
      <span class="src-hbtn outlined gap" aria-disabled="true" title="Reference help lane (named gap)">${bpIcon("help")}<span>Help</span></span>
      <span class="src-counters gap" aria-disabled="true" title="REAL sync activity — the estate's ODK materializing runs: in-flight · executed · failed (live daemon truth, not the capture's zeros)">
        <span class="src-ctag">${bpIcon("refresh", 14)}<span>${cInflight}</span></span>
        <span class="src-ctag">${bpIcon("tick", 14)}<span>${cDone}</span></span>
        <span class="src-ctag">${bpIcon("cross", 14)}<span>${cFailed}</span></span>
      </span>
    </div>
  </header>`;

  const hero = `<section class="src-hero">
    <img class="src-heroimg" src="${SRC_HERO_URI}" alt="" aria-hidden="true">
    <div class="src-heroct">
      <h3 class="src-h1">Data Connection</h3>
      <p class="src-desc">Synchronize and manage data flows between Foundry and external systems.</p>
    </div>
  </section>`;

  const setup = `<div class="src-setupcard">
    <h4 class="src-setuph">Set up new connections</h4>
    <img class="src-setupstrip" src="${SRC_SETUP_STRIP_URI}" width="962" height="222" alt="Reference set-up option cards (verbatim capture chrome — vendor onboarding, not an extraction affordance)">
    <a class="src-opt c1" href="/__ioi/data/sources?declare=1" title="Connect to external system — DECLARES a validated, receipted source record (POST /v1/hypervisor/data-sources); the live-connection/extraction half stays a named gap (the wired:false boundary)"></a>
    <span class="src-opt c2 gap" aria-disabled="true" title="Static upload is a reference-only lane (named gap)"></span>
    <span class="src-opt c3 gap" aria-disabled="true" title="Data synthesis is a reference-only lane (named gap)"></span>
  </div>`;

  const viewRow = `<div class="src-viewrow">
    <span class="src-viewlbl">View</span>
    <span class="src-pill on">Recents</span>
    <span class="src-pill gap" aria-disabled="true" title="Favorites are not recorded on the data-source registry (named gap)">Favorites</span>
    <a class="src-viewall" href="#sources-catalog" title="The full declared-catalog census below"><span>View all</span>${bpIcon("arrow-right")}</a>
  </div>`;

  const table = `<div class="src-table">
    <div class="src-thead"><span class="src-th name">Files</span><span class="src-th">Creator</span><span class="src-th">Last edited by</span><span class="src-th">Last viewed</span></div>
    <div class="src-rows">${rowsHtml}</div>
  </div>`;

  const examples = `<div class="src-examples">
    <h5 class="src-exh">Explore reference examples</h5>
    <div class="src-exsub">New to Data Connection? Learn what to do with Data Connection using an example data source.</div>
    <div class="src-exstripwrap">
      <img class="src-exstrip" src="${MCH_EXAMPLES_STRIP_URI}" width="562" height="272" alt="Reference marketplace example cards (verbatim capture chrome)">
      <span class="src-excard c1 gap" aria-disabled="true" title="Marketplace example installs are a reference-only lane (named gap)"></span>
      <span class="src-excard c2 gap" aria-disabled="true" title="Marketplace example installs are a reference-only lane (named gap)"></span>
    </div>
  </div>`;

  const css = `:root{color-scheme:light}*{box-sizing:border-box}
    body{margin:0;background:#fff;color:#1c2127;font:14px/1.28581 Source-Sans-Pro,Helvetica,sans-serif}
    a{color:#215db0;text-decoration:none}
    .src-shell{display:flex;height:100vh;width:100vw;overflow:hidden}
    ${IOI_GRAIL_CSS}
    .rv-dsg .og-gappico{background-color:rgba(45,114,210,.1)}
    .rv-dsg .og-gsecrow{padding:30px 7px 5px 5px}
    .rv-dsg .og-gitem.on{margin-right:-11px}
    .src-main{flex:1;min-width:0;display:flex;flex-direction:column;height:100vh}
    .src-header{flex:0 0 48px;height:48px;display:flex;align-items:center;background:#fff;border-bottom:1px solid #d3d8de;z-index:6}
    .src-hchip{width:48px;height:48px;flex:0 0 48px;background:rgba(255,178,102,.1) url('${SRC_APP_TILE_URI}') center/24px no-repeat}
    .src-htitle{font-size:16px;line-height:20.6px;font-weight:600;color:#404854;margin:0 0 0 12px;flex:0 0 auto}
    .src-hdiv{width:1px;height:20px;background:#d3d8de;margin:0 16px}
    .src-tabs{display:flex;align-self:stretch;gap:20px}
    .src-tab{display:inline-flex;align-items:center;font-size:16px;line-height:48px;color:#1c2127;cursor:default}
    a.src-tab{cursor:pointer;color:#1c2127}
    .src-hright{margin-left:auto;display:flex;align-items:flex-start;gap:8px;padding-right:8px}
    .src-hbtn{display:inline-flex;align-items:center;gap:8px;height:30px;margin-top:8.5px;padding:0 8px;border-radius:4px;font-size:14px;line-height:16.1px;cursor:default}
    .src-hbtn.success{background:#238551;color:#fff;box-shadow:inset 0 0 0 1px rgba(17,20,24,.2),0 1px 2px rgba(17,20,24,.1)}
    .src-hbtn.success svg{color:#fff}
    a.src-hbtn.success{cursor:pointer}
    .src-hbtn.outlined{border:1px solid rgba(95,107,124,.25);padding:0 8px;color:#1c2127}
    .src-hbtn.outlined svg{color:#5f6b7c}
    .src-hbtn.store{gap:4px;padding:0 7px;background:#f7f8f8;box-shadow:inset 0 0 0 1px rgba(64,72,84,.33),0 1px 2px rgba(17,20,24,.1)}
    .src-storeico{width:16px;height:16px;flex:0 0 16px;background:url('${MCH_STORE_ICON_URI}') center/16px no-repeat}
    .src-counters{display:inline-flex;align-items:center;gap:3px;height:30px;margin-top:8.5px;padding:0 10px;opacity:1;cursor:default}
    .src-ctag{display:inline-flex;align-items:center;gap:2px;height:20px;padding:2px 6px;border-radius:2px;background:rgba(143,153,168,.15);color:#5f6b7c;font-size:12px;line-height:16px}
    .src-ctag svg{color:#5f6b7c}
    .src-body{flex:1 1 auto;min-width:0;overflow-y:auto;background:#f6f7f9}
    .src-content{max-width:1090px;margin:0 auto;padding:0 45px}
    .src-hero{position:relative;background:#fff;height:143px;box-shadow:0 1px 0 0 rgba(17,20,24,.15)}
    .src-heroct{position:relative;max-width:1040px;height:100%;margin:0 auto;padding:0 20px;background:linear-gradient(90deg,#fff 575px,rgba(255,255,255,0) 100%)}
    .src-heroimg{position:absolute;right:0;top:0;width:519.4px;height:143px}
    .src-h1{position:relative;font-size:22px;line-height:25px;font-weight:600;color:#1c2127;margin:0;padding-top:20px}
    .src-desc{position:relative;width:625px;font-size:14px;line-height:18.0013px;color:#5f6b7c;margin:6px 0 0}
    .src-setupcard{position:relative;z-index:2;margin-top:-55px;height:288.4px;background:#fff;border-radius:4px;box-shadow:0 0 0 1px rgba(17,20,24,.15),0 0 5px rgba(0,0,0,.02)}
    .src-setuph{font-size:16px;line-height:19px;font-weight:600;color:#1c2127;margin:0;padding:20px 20px 0}
    .src-setupstrip{position:absolute;left:19px;top:53px}
    .src-opt{position:absolute;top:54px;width:310px;height:215px;cursor:default}
    a.src-opt{cursor:pointer}
    .src-opt.c1{left:20px}.src-opt.c2{left:345.3px}.src-opt.c3{left:670.7px}
    .src-viewrow{display:flex;align-items:center;margin-top:40px;height:30px}
    .src-viewlbl{font-size:14px;line-height:18px;color:#1c2127}
    .src-pill{display:inline-flex;align-items:center;height:30px;margin-left:10px;padding:6px 10px;border-radius:30px;font-size:14px;line-height:18px;cursor:default}
    .src-pill.on{background:rgba(45,114,210,.3);color:#184a90;font-weight:600}
    .src-pill.gap{background:rgba(143,153,168,.15);color:#1c2127}
    .src-viewall{margin-left:auto;display:inline-flex;align-items:center;gap:9px;font-size:14px;line-height:18px;color:#215db0}
    .src-viewall svg{color:#215db0}
    .src-table{margin-top:10px;height:max(360px,calc(100vh - 648px));overflow-y:auto;background:#fff;border-radius:4px;box-shadow:0 0 0 1px rgba(17,20,24,.15)}
    .src-thead{display:flex;height:30px;box-shadow:inset 0 -1px 0 #dcdcdd}
    .src-th{width:16.667%;padding:8px 0 0 11px;font-size:12px;line-height:15.43px;color:#5f6b7c;text-transform:uppercase}
    .src-th.name{width:50%;padding-left:20px}
    .src-row{display:flex;height:57px;box-shadow:inset 0 -1px 0 #dcdcdd;color:#1c2127}
    .src-row.src-sel{outline:2px solid rgba(45,114,210,.45);outline-offset:-2px;border-radius:4px}
    .src-maplist{margin:6px 0;padding-left:18px}.src-mapline{margin:0 0 6px;font-size:12.5px}
    .src-cell{width:16.667%;padding:19.5px 0 0 11px;font-size:14px;line-height:18px}
    .src-cell.name{width:50%;padding:11px 0 0 20px;display:flex;align-items:flex-start}
    .src-rowico{width:16px;height:16px;flex:0 0 16px;margin-top:2px;background:url('${DSG_ROW_DOC_URI}') center/16px no-repeat}
    .src-rowdata{margin-left:7px;min-width:0;flex:1;padding-right:16px}
    .src-rowname{display:block;font-size:14px;line-height:18px;color:#1c2127;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .src-wired{display:inline-block;margin-left:8px;padding:0 6px;border-radius:9px;background:rgba(200,118,25,.15);color:#935610;font-size:11px;line-height:16px;vertical-align:1px}
    .src-rowpath{display:block;font-size:12px;line-height:15.43px;color:#5f6b7c;margin-top:1px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .src-dash{color:#5f6b7c}
    .src-empty{padding:24px 20px;font-size:14px;color:#5f6b7c}
    .src-examples{margin-top:28px}
    .src-exh{font-size:16px;line-height:19px;font-weight:600;color:#1c2127;margin:0}
    .src-exsub{font-size:14px;line-height:18px;color:#1c2127;margin-top:12px}
    .src-exstripwrap{position:relative;margin-top:7px;width:562px;margin-left:-1px}
    .src-exstrip{display:block}
    .src-excard{position:absolute;top:1px;width:270px;height:270px;cursor:default}
    .src-excard.c1{left:1px}.src-excard.c2{left:291px}
    .src-truth{margin-top:30px;padding-bottom:40px}
    .src-trutht{font-size:18px;font-weight:600;color:#1c2127;margin:0 0 8px}
    .src-count{margin-left:8px;font-size:14px;font-weight:400;color:#5f6b7c;background:rgba(143,153,168,.15);border-radius:9px;padding:1px 8px}
    .src-truthsub{font-size:13px;font-weight:400;color:#5f6b7c;margin-left:8px}
    .src-boundary{font-size:13px;line-height:1.55;color:#1c2127;background:#fff;border-radius:4px;box-shadow:0 0 0 1px rgba(200,118,25,.4);padding:12px 14px;margin:0 0 14px}
    .src-truthcols{display:flex;gap:16px;align-items:flex-start}
    .src-truthcol{flex:1;min-width:0;background:#fff;border-radius:4px;box-shadow:0 0 0 1px rgba(17,20,24,.15);padding:14px 16px}
    .src-truthcol h3{font-size:14px;font-weight:600;margin:0 0 8px;color:#1c2127}
    .src-chips{display:flex;gap:6px;flex-wrap:wrap}
    .src-chip{display:inline-flex;gap:5px;padding:3px 10px;border-radius:12px;background:rgba(143,153,168,.15);color:#1c2127;font-size:12px}
    .src-gapnote{font-size:12px;color:#5f6b7c;margin:8px 0 0;line-height:1.5}
    .src-foot{font-size:12px;line-height:1.6;color:#7b8494;margin-top:18px}
    .src-declare{position:relative;z-index:3;margin-top:20px;background:#fff;border-radius:4px;box-shadow:0 0 0 1px rgba(45,114,210,.45),0 0 5px rgba(0,0,0,.02);padding:16px 20px 18px}
    .src-decth{font-size:16px;font-weight:600;color:#1c2127;margin:0 0 10px}
    .src-decform{display:flex;flex-direction:column;gap:10px;max-width:640px}
    .src-declabel{display:flex;flex-direction:column;gap:4px;font-size:12px;color:#5f6b7c}
    .src-decinp,.src-decsel{height:30px;padding:0 9px;border:1px solid #d3d8de;border-radius:4px;font:inherit;font-size:14px;background:#fff;color:#1c2127}
    .src-dechint{font-size:11.5px;color:#5f6b7c}
    .src-decconfirm{display:flex;align-items:flex-start;gap:7px;font-size:12px;color:#5f6b7c;line-height:1.5}
    .src-decsubmit{align-self:flex-start;padding:6px 14px;border-radius:4px;border:0;background:#238551;color:#fff;font:inherit;font-size:13px;font-weight:600;cursor:pointer}
    .src-decclose{display:inline-block;margin-top:10px;font-size:12.5px}
    .src-decfail{margin:0}
    .src-selgaps{display:flex;gap:6px;flex-wrap:wrap;margin:0 0 10px}
    .src-selgap{display:inline-flex;align-items:center;padding:3px 10px;border-radius:4px;background:rgba(143,153,168,.15);color:#5f6b7c;font-size:12px;cursor:not-allowed}
    .src-banner{margin:0 0 12px;padding:9px 12px;border-radius:6px;font-size:12.5px;line-height:1.5;outline:none}
    .src-banner code{font-size:10.5px;word-break:break-all}
    .src-banner.src-ok{border:1px solid #8fdcb6;background:#eafaf1;color:#0e6b41}
    .src-banner.src-no{border:1px solid #e8c48d;background:#fdf7ec;color:#935610}
    .src-rcpt{background:rgba(14,138,83,.08);border-radius:3px;padding:1px 4px}`;

  // The banner must always be reachable at the runtime's #ap-result anchor: inside the declare
  // pane when it is open, inside the selection panel when a record is selected, else standalone
  // at the top of the content column (bare certified render carries none of the three).
  const looseBanner = banner && !(opts && opts.declare) && !dataSourceSel ? `<div class="src-truth" style="margin-top:20px;padding-bottom:0">${banner}</div>` : "";

  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Data Connection</title><style>${css}</style></head>
    <body><div class="src-shell">${globalRail}<div class="src-main">${header}<div class="src-body">${hero}<main class="src-content">${looseBanner}${declarePane}${setup}${viewRow}${table}${examples}${truth}</main></div></div></div></body></html>`;
}
