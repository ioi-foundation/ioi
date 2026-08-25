// Object Explorer — extracted app module (Ontology Application Runtime wave). The render code
// below is moved VERBATIM from serve-product-ui.mjs (zero behavior change by construction); the
// module adds only the surface contract the registry mounts. /__ioi/ontology/explorer is a
// certified shell (pixel-certifications/explorer.json) — pixels are frozen by the harness gate.
import { bpIcon, EXPLORER_APP_ICON_URI } from "../../scripts/bp-icons.mjs";
import { ioiGlobalRailHtml, IOI_GRAIL_CSS } from "../chrome.mjs";
import { escHtml } from "../kit.mjs";
import { loadOntologyModel, parseOntologyContext, managerLink, managerResourceLink, objectTypeLink, objectSetLink, pipelineNodeLink, lineageLink, vertexLink, provenanceSetLink, semanticBreadcrumb, semanticInspectorShell, disabledSemanticAction, formatRef } from "../ontology-context.mjs";
import { createReadClient } from "../read-client.mjs";

const CX_ESC = escHtml; // local alias so the moved block stays byte-identical to its serve original

export const meta = {
  slug: "explorer",
  route: "/__ioi/ontology/explorer",
  verifier: "scripts/verify-hypervisor-app-parity-object-explorer.mjs",
  certification: "pixel-certifications/explorer.json",
};

// XIV Leg 1 — SURF-ontology. Two of the three controls XIII left as named gaps bind here. The
// contracts landed in XIII; what was missing was a SURFACE. The gap was never "no plane" and the
// atlas said so, which is why closing it is a binding and not a contract.
const SEARCH_PLANE = "/v1/hypervisor/odk/object-instance-search";
const SAVED_SETS_PLANE = "/v1/hypervisor/odk/saved-object-sets";
const SAVED_SET_SCHEMA = "ioi.hypervisor.odk.saved-object-set.v1";

/**
 * OBJECT-INSTANCE SEARCH IS A READ, and rides the read client even though the daemon spells it
 * POST — the body carries the query, not a mutation. It answers a TYPED CORPUS-ABSENT state
 * distinct from "no matches", and rendering those as the same thing would be the surface telling a
 * user the corpus is empty when the query simply missed.
 */
async function loadInstanceSearch(ctx, client) {
  const q = (ctx.url.searchParams.get("oq") || "").trim();
  const objectTypeId = (ctx.url.searchParams.get("ot") || "").trim();
  const ontologyRef = (ctx.url.searchParams.get("ontology") || "").trim();
  if (!q && !objectTypeId) return null;
  const body = { limit: 25 };
  if (q) body.q = q;
  if (objectTypeId) body.object_type_id = objectTypeId;
  if (ontologyRef) body.ontology_ref = ontologyRef;
  const r = await client.read(SEARCH_PLANE, {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
  });
  if (!r.ok) return { q, objectTypeId, refused: { code: r.code || "search_unavailable", message: r.message || "the search plane did not answer" } };
  return { q, objectTypeId, payload: r.payload };
}

export async function load(ctx) {
  const client = typeof ctx.daemonFetch === "function"
    ? createReadClient({ daemon: "", fetchImpl: ctx.daemonFetch })
    : createReadClient({ daemon: ctx.daemon });
  const [model, search, saved] = await Promise.all([
    loadOntologyModel(ctx.daemon),
    loadInstanceSearch(ctx, client),
    client.read(SAVED_SETS_PLANE),
  ]);
  model.search = search;
  // The saved-set catalog is scoped per principal by the daemon; a refusal is reported, never
  // rendered as an empty catalog — an empty list and an unanswered read are different facts.
  model.savedSets = saved.ok ? (saved.payload.saved_object_sets || []) : null;
  model.savedSetsRefusal = saved.ok ? null : { code: saved.code || "saved_sets_unavailable", message: saved.message || "the saved-set plane did not answer" };
  return model;
}

export function render(model, ctx) {
  return renderObjectExplorerPort(model.overview, model.lists, {
    q: ctx.url.searchParams.get("q") || "",
    sel: parseOntologyContext(ctx.url),
    embed: ctx.embed,
    // W2.1 rehome: the module serves at BOTH its legacy and canonical mounts; self-referring
    // forms post back to the mount that rendered them, so scoping works identically at each.
    basePath: ctx.url.pathname,
    search: model.search,
    savedSets: model.savedSets,
    savedSetsRefusal: model.savedSetsRefusal,
    setQuery: ctx.url.searchParams.get("setq") || "",
    result: ctx.url.searchParams.get("saved") || "",
    refusalCode: ctx.url.searchParams.get("refused") || "",
  });
}

// Object SELECTION remains read-navigation through the shared ontology context. The one authority
// this surface now carries is SAVING A SET — an ordinary governed mutation against a contract that
// already existed, with no wallet crossing and no second admission path: it posts to the same
// `ontology_workbench_routes` plane that owns the family.
export const actions = [
  {
    id: "save-object-set", method: "POST", route: "/actions/save-object-set",
    fields: ["name", "description", "ontology_ref", "object_type_id", "q"],
    context: [],
    authority: { plane: "odk-saved-object-sets", operation: `POST ${SAVED_SETS_PLANE}` },
    receipt: SAVED_SET_SCHEMA,
    confirm: false, success: "return-to-surface", refusal: "typed-banner",
  },
];

export async function handleAction({ action, fields, daemonFetch, url }) {
  if (action.id !== "save-object-set") {
    return { kind: "failure", http: 400, code: "unknown_action", message: "this surface declares one action" };
  }
  // No capability, no mutation — the approvals precedent. A module that authored its own identity
  // headers would be crossing as itself rather than as the caller.
  if (typeof daemonFetch !== "function") {
    return { kind: "failure", http: 500, code: "identity_capability_missing", message: "the action runtime supplied no request-scoped daemon capability — refusing to save without the caller's identity" };
  }
  const bounded = (v, max) => (typeof v === "string" ? v.slice(0, max).trim() : "");
  const selection = {};
  const objectTypeId = bounded(fields.object_type_id, 400);
  const q = bounded(fields.q, 400);
  if (objectTypeId) selection.object_type_id = objectTypeId;
  if (q) selection.q = q;
  const back = `${url.pathname}${url.search || ""}`;
  // THE SELECTION IS THE POINT OF A SAVED SET. Posting an empty one would earn the daemon's own
  // `saved_object_set_selection_required`, but refusing here keeps the caller's context: the
  // surface can say which control was empty, which a relayed 400 cannot.
  if (!selection.object_type_id && !selection.q) {
    return { kind: "refusal", http: 400, code: "saved_object_set_selection_required", message: "a saved set stores a SELECTION — search for objects or pick a type before saving", redirect: back };
  }
  const name = bounded(fields.name, 200);
  if (!name) return { kind: "refusal", http: 400, code: "odk_field_required", message: "`name` is required — a saved set is found by its name", redirect: back };
  const ontologyRef = bounded(fields.ontology_ref, 400);
  if (!ontologyRef) return { kind: "refusal", http: 400, code: "odk_field_required", message: "`ontology_ref` is required — a saved set belongs to one ontology", redirect: back };

  const body = { name, ontology_ref: ontologyRef, selection };
  const description = bounded(fields.description, 2000);
  if (description) body.description = description;
  const r = await daemonFetch(SAVED_SETS_PLANE, {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
  }).then(async (x) => ({ status: x.status, j: await x.json().catch(() => ({})) })).catch(() => null);
  if (!r) return { kind: "failure", http: 502, code: "daemon_unavailable", message: "the daemon did not answer — nothing was saved", redirect: back };
  if (r.j && r.j.error) return { kind: "refusal", http: r.status || 400, code: r.j.error.code || "saved_object_set_refused", message: r.j.error.message || "refused — state unchanged", redirect: back };
  const rec = r.j && r.j.saved_object_set;
  // A 2xx WITHOUT the declared record fails CLOSED. A surface that reports success on a shape it
  // cannot recognise is guessing, and the guess is always in the optimistic direction.
  if (r.status !== 201 || !rec || !rec.ref || rec.schema_version !== SAVED_SET_SCHEMA) {
    return { kind: "failure", http: 502, code: "saved_object_set_result_invalid", message: `the plane answered without a ${SAVED_SET_SCHEMA} record — failing closed`, redirect: back };
  }
  // THE DURABLE REFERENCE IS THE RECORD'S OWN REF. This family emits no separate receipt object —
  // the record IS the artifact — so that ref is what the surface can prove, and the runtime's
  // "success without a receipt fails closed" rule is satisfied by evidence rather than by a
  // placeholder. Claiming a receipt schema this plane never emits would be the decorative version.
  return { kind: "success", created: rec.ref, receipt_ref: rec.ref, redirect: `${url.pathname}?saved=${encodeURIComponent(rec.id)}` };
}

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
// filter. Lanes with NO SURFACE CONTROL YET — object-instance search and saved object sets both
// landed as daemon truth in next-legs XIII, so the gap is a binding, not a contract — plus lanes
// with no plane at all (Recents/Favorites, sort,
// type-group/application lanes, exploration tabs, ontology selector) are named gaps disabled in
// place. The catalog/set ROWS are the live body (excluded from shell-pixel certification, verified
// semantically); the chrome is glyph-anchored to the reference: tab bar h40 · centered search hero ·
// shortcuts row + cards · catalog heading/filter/sort band · table header · object-set band. The
// content block is the reference's responsive rule: max-width 1400, width calc(100% − 120px),
// centered (margins 60 @1440 → 145 @1920).
/**
 * The search result region.
 *
 * THE TWO EMPTIES ARE DIFFERENT FACTS, and the daemon types them apart —
 * `object_instance_corpus_absent` (nothing has been materialized in this scope, so there was nothing
 * to search) versus `object_instance_query_unmatched` (the corpus was searched and matched nothing).
 * Rendering both as "no results" would tell a user their query missed when in fact nothing exists to
 * miss. Every row carries its provenance because an instance with no materializing run behind it is
 * indistinguishable from an invented one.
 */
function renderSearchResults(search, esc) {
  if (!search) return "";
  if (search.refused) {
    return `<div class="oe-sres oe-sres-refused" role="status"><b>The object-instance search plane did not answer.</b> <code>${esc(search.refused.code)}</code> — ${esc(search.refused.message)}. Nothing below is a search result.</div>`;
  }
  const p = search.payload || {};
  const rows = Array.isArray(p.results) ? p.results : [];
  const corpus = p.corpus || {};
  const absence = p.absence || null;
  const scope = `searched ${corpus.object_instances_in_scope ?? 0} instance${corpus.object_instances_in_scope === 1 ? "" : "s"} across ${corpus.materialized_object_sets_in_scope ?? 0} materialized set${corpus.materialized_object_sets_in_scope === 1 ? "" : "s"}`;
  if (absence) {
    return `<div class="oe-sres" role="status"><b>${absence.code === "object_instance_corpus_absent" ? "Nothing is materialized in this scope" : "No instance matched"}</b> — ${esc(absence.message)} <span class="oe-sscope">(${esc(scope)})</span></div>`;
  }
  const body = rows.map((r) => {
    const o = r.object && typeof r.object === "object" ? r.object : {};
    const label = o.title || o.name || o.id || "(untitled instance)";
    return `<tr><td class="oe-srlabel">${esc(String(label))}</td><td class="oe-srtype">${esc(String(r.object_type_id || ""))}</td><td class="oe-srprov" title="provenance travels with every row">${esc(String(r.materializing_run_ref || "—"))}</td></tr>`;
  }).join("");
  return `<div class="oe-sres" role="status">
    <div class="oe-srhead"><b>${p.total_matched ?? rows.length} match${(p.total_matched ?? rows.length) === 1 ? "" : "es"}</b> <span class="oe-sscope">(${esc(scope)}${p.truncated ? `, showing ${rows.length}` : ""})</span></div>
    <table class="oe-table oe-srtable"><tbody>${body}</tbody></table>
  </div>`;
}

function renderObjectExplorerPort(ov, lists, opts) {
  const enc = encodeURIComponent, esc = CX_ESC;
  const q = (opts && opts.q ? String(opts.q) : "").trim();
  const basePath = (opts && opts.basePath) || "/__ioi/ontology/explorer";
  const ontologies = Array.isArray(lists.ontologies) ? lists.ontologies : [];
  const allSets = Array.isArray(lists.materialized_sets) ? lists.materialized_sets : [];
  const projs = Array.isArray(lists.projections) ? lists.projections : [];
  const policyViews = Array.isArray(lists.policy_views) ? lists.policy_views : [];
  const arr = (oo, k) => { const com = (oo && oo.canonical_object_model) || {}; return Array.isArray(com[k]) ? com[k] : []; };

  // W2.1 (brief §4): the ontology-scope selector is LIVE — a scoped catalog over the already
  // loaded DomainOntology list. Scope narrows types, sets, and shortcuts to one ontology; no
  // scope means every live ontology, honestly, and an unknown scope fails closed to unscoped.
  const scopeSel = (opts && opts.sel && opts.sel.ontology) || "";
  const scopeOnt = scopeSel ? ontologies.find((oo) => oo.id === scopeSel) || null : null;
  const scopedOntologies = scopeOnt ? [scopeOnt] : ontologies;
  const msets = scopeOnt ? allSets.filter((m) => m.ontology_ref === scopeOnt.ref) : allSets;

  // REAL daemon truth: the flat object-type catalog + per-type materialized counts + link usage.
  const allTypes = scopedOntologies.flatMap((oo) => arr(oo, "object_types").map((t) => ({ oo, t })));
  const objectsOf = (oo, t) => allSets.filter((m) => m.ontology_ref === oo.ref && m.object_type_id === t.id).reduce((a, m) => a + (m.count || 0), 0);
  const usageOf = (oo, t) => arr(oo, "link_types").filter((l) => l.from === t.id || l.to === t.id).length;
  const catalog = q ? allTypes.filter(({ oo, t }) => `${t.name || ""} ${t.id || ""} ${oo.domain || ""}`.toLowerCase().includes(q.toLowerCase())) : allTypes;
  const fmtN = (n) => (n >= 1000 ? `${Math.round(n / 100) / 10}K` : String(n));
  // Shortcuts = the real top materialized sets by object count (live data — masked in the pixel gate).
  const shortcuts = msets.slice().sort((a, b) => (b.count || 0) - (a.count || 0)).slice(0, 3);
  const CHIP_COLORS = ["#bd6bbd", "#13c9ba", "#4c90f0"];

  // ---- Semantic selection (Ontology wave): the URL carries the context (ontology/objectType/
  // objectSet through the shared ontology-context kit). The bare route — the pixel gate's
  // capture — renders NO inspector and keeps the certified chrome byte-stable; explicit context
  // params swap in the semantic inspector aside. Unknown context fails CLOSED with an honest
  // note, never a crash. Rows/cards are the excluded live body, so their selection styling and
  // retargeted hrefs are pixel-legal.
  const sel = (opts && opts.sel) || {};
  const hasSelParam = !!(sel.objectType || sel.objectSet);
  const selOnt = sel.ontology ? ontologies.find((oo) => oo.id === sel.ontology) || null : null;
  const selType = sel.objectType && selOnt ? arr(selOnt, "object_types").find((t) => t.id === sel.objectType) || null : null;
  const selSet = sel.objectSet ? allSets.find((m) => m.id === sel.objectSet) || null : null;
  const selSetOnt = selSet ? ontologies.find((oo) => oo.ref === selSet.ontology_ref) || null : null;
  const withQ = (href) => (q ? `${href}${href.includes("?") ? "&" : "?"}q=${enc(q)}` : href);

  const typeRow = ({ oo, t }) => {
    const n = objectsOf(oo, t);
    const href = withQ(objectTypeLink(oo.id, t.id));
    const on = !!(selType && selOnt && oo.id === selOnt.id && t.id === selType.id);
    return `<tr class="oe-trow${on ? " oe-sel" : ""}" data-objecttype="${esc(t.id)}"${on ? ' aria-current="true"' : ""} onclick="location.href='${href}'">
      <td class="oe-tname"><span class="oe-tchip" style="color:${CHIP_COLORS[(t.id || "").length % 3]}">${bpIcon("cube", 14)}</span><a class="oe-tlink" href="${href}">${esc(t.name || t.id)}</a></td>
      <td class="oe-tstatus">${bpIcon("manual", 14)}</td>
      <td>${esc(fmtN(n))}</td>
      <td>${usageOf(oo, t)} link${usageOf(oo, t) === 1 ? "" : "s"}</td>
      <td class="oe-tgroups"></td>
      <td class="oe-tdesc">${esc(oo.domain || oo.id)}</td>
    </tr>`;
  };
  const setRow = (m) => {
    const so = ontologies.find((oo) => oo.ref === m.ontology_ref) || {};
    const href = withQ(objectSetLink(so.id || "", m.id));
    const on = !!(selSet && m.id === selSet.id);
    return `<tr class="oe-trow${on ? " oe-sel" : ""}" data-objectset="${esc(m.id)}"${on ? ' aria-current="true"' : ""} onclick="location.href='${href}'">
    <td class="oe-tname"><span class="oe-tchip" style="color:#13c9ba">${bpIcon("layout-grid", 14)}</span><a class="oe-tlink" href="${href}">${esc(m.name || m.set_id || m.object_type_id)}</a></td>
    <td>${esc(fmtN(m.count || 0))} object${(m.count || 0) === 1 ? "" : "s"}</td>
    <td class="oe-tdesc">${esc(so.domain || m.ontology_ref || "")}</td>
    <td class="oe-tdesc"><a href="/__ioi/ontology/manager">Ontology Manager →</a></td>
  </tr>`;
  };

  // Embedded (native container contract #65): the native rail owns platform nav — emit no global rail.
  const globalRail = opts.embed ? "" : ioiGlobalRailHtml({ label: "Object Explorer", href: "/__ioi/ontology/explorer", iconUri: EXPLORER_APP_ICON_URI, railVariant: "rv-pipe", viewAll: false, star: false, badges: true, aipGradient: true, acctMuted: true, hiliteNav: "Ontology" });

  const tabbar = `<div class="oe-tabbar oe-topbar">
    <span class="oe-sqbtn gap" aria-disabled="true" title="The active-exploration TAB is a reference-only session lane (named gap) — transient view state; saved object sets are daemon truth and are a different thing" data-ioi-disabled-reason="The active-exploration TAB is a reference-only session lane (named gap) — transient view state; saved object sets are daemon truth and are a different thing"><span class="oe-sqico"></span></span>
    <span class="oe-tab" title="Exploration TABS are a reference-only session lane — this tab is the honest default state; a SAVED object set is a saved exploration and does have a daemon plane">${bpIcon("search")}<span class="oe-tabt">New exploration</span></span>
    <span class="oe-plus gap" aria-disabled="true" title="Opening more exploration TABS is a reference-only lane (named gap) — transient view state, not a saved selection" data-ioi-disabled-reason="Opening more exploration TABS is a reference-only lane (named gap) — transient view state, not a saved selection">${bpIcon("plus")}</span>
    <form class="oe-ontform" method="GET" action="${esc(basePath)}" title="Scope the catalog to one live ontology — no ontology is globally canonical">${q ? `<input type="hidden" name="q" value="${esc(q)}">` : ""}<select class="oe-ontsel oe-ontlive" name="ontology" aria-label="Ontology scope" onchange="this.form.submit()"><option value=""${scopeOnt ? "" : " selected"}>All ontologies (${ontologies.length})</option>${ontologies.map((oo) => `<option value="${esc(oo.id)}"${scopeOnt && scopeOnt.id === oo.id ? " selected" : ""}>${esc(oo.domain || oo.id)}</option>`).join("")}</select><noscript><button class="oe-ontgo" type="submit">Go</button></noscript></form>
  </div>`;

  // XIV Leg 1 — THE OBJECT SEARCH CONTROL IS BOUND. XIII landed
  // `POST /v1/hypervisor/odk/object-instance-search` and left this input disabled; the named gap was
  // a binding, not a contract, and the atlas said so in those words. Faceted narrowing on TOP of the
  // query stays a named gap and stays disabled — closing a gap by widening what "search" means is
  // the narrowing this run is forbidden to do.
  const search = opts && opts.search;
  const hero = `<div class="oe-hero">
    <h2 class="oe-htitle">Object Explorer search</h2>
    <div class="oe-searchrow">
      <form class="oe-herogrp" method="get" action="${esc(basePath)}">
        ${sel.ontology ? `<input type="hidden" name="ontology" value="${esc(sel.ontology)}">` : ""}
        ${q ? `<input type="hidden" name="q" value="${esc(q)}">` : ""}
        <span class="oe-filterby gap" aria-disabled="true" title="Faceted object filters remain a named gap — the query below is bound to the object-instance search plane, but narrowing it by facet has no daemon contract" data-ioi-disabled-reason="Faceted object filters remain a named gap — the query below is bound to the object-instance search plane, but narrowing it by facet has no daemon contract">${bpIcon("filter-funnel")}<span class="oe-fbt">Filter by...</span>${bpIcon("caret-down")}</span>
        <div class="oe-objsearch" title="Object search runs against POST /v1/hypervisor/odk/object-instance-search — ontology-scoped, typed corpus-absent distinct from no-matches">${bpIcon("search")}<input class="oe-objq" name="oq" value="${esc(search && search.q ? search.q : "")}" placeholder="Search for objects..." aria-label="Search for objects across this ontology's instances"><button class="oe-send" type="submit" aria-label="Run object search">${bpIcon("send-to")}</button></div>
      </form>
    </div>
    ${renderSearchResults(search, esc)}
  </div>`;

  const cards = shortcuts.map((m, i) => {
    const so = ontologies.find((oo) => oo.ref === m.ontology_ref) || {};
    return `<a class="oe-card" data-shortcut-type="${esc(m.object_type_id)}" href="${withQ(objectTypeLink(so.id || "", m.object_type_id))}">
    <span class="oe-cchip" style="background:${CHIP_COLORS[i]}1a;color:${CHIP_COLORS[i]}">${bpIcon("layout-grid", 14)}</span>
    <span class="oe-cbody"><span class="oe-ctitle">${esc(m.name || m.set_id || m.object_type_id)}</span><span class="oe-csub">Object Type&nbsp;&nbsp;•&nbsp;&nbsp;${esc(fmtN(m.count || 0))} object${(m.count || 0) === 1 ? "" : "s"}</span></span>
  </a>`;
  }).join("");
  const shortcutsBand = `<div class="oe-shrow">
    <span class="oe-shlabel">Shortcuts</span>
    <span class="oe-lanes">
      <span class="oe-lane on gap" aria-disabled="true" title="Recents are a reference-only per-user lane (named gap) — the cards below are the real top materialized sets" data-ioi-disabled-reason="Recents are a reference-only per-user lane (named gap) — the cards below are the real top materialized sets">Recents</span>
      <span class="oe-lane gap" aria-disabled="true" title="Favorites are a reference-only per-user lane (named gap)" data-ioi-disabled-reason="Favorites are a reference-only per-user lane (named gap)">Favorites</span>
      <span class="oe-lane gap" aria-disabled="true" title="Your object sets — the real materialized sets render in the catalog below" data-ioi-disabled-reason="Your object sets — the real materialized sets render in the catalog below">Your object sets</span>
      <span class="oe-shchev gap" aria-disabled="true">${bpIcon("chevron-right")}</span>
    </span>
  </div>
  <div class="oe-cards">${cards || `<div class="oe-cardempty">No materialized sets yet — run a materializing run to populate shortcuts. This row reads real daemon sets; nothing is fabricated.</div>`}</div>`;

  const catalogBand = `<h3 class="oe-cathead"><span class="oe-cathd">Object type catalog</span></h3>
  <div class="oe-filterrow">
    <form class="oe-filterform" method="GET" action="${esc(basePath)}">${bpIcon("filter-funnel")}<input name="q" value="${esc(q)}" placeholder="Filter for an object type..." aria-label="Filter for an object type (live)">${sel.ontology ? `<input type="hidden" name="ontology" value="${esc(sel.ontology)}">` : ""}${sel.objectType ? `<input type="hidden" name="objectType" value="${esc(sel.objectType)}">` : ""}${sel.objectSet ? `<input type="hidden" name="objectSet" value="${esc(sel.objectSet)}">` : ""}<span class="oe-count">${catalog.length} of ${allTypes.length}</span></form>
    <span class="oe-sortlanes">
      <span class="oe-sort gap" aria-disabled="true" title="Relevancy sorting is a reference-only lane — rows are ordered by ontology then name (named gap)" data-ioi-disabled-reason="Relevancy sorting is a reference-only lane — rows are ordered by ontology then name (named gap)">${bpIcon("sort-desc")}<span class="oe-sortt">Relevancy</span>${bpIcon("caret-down")}</span>
      <span class="oe-lane on gap" aria-disabled="true" title="named gap" data-ioi-disabled-reason="named gap">All</span>
      <span class="oe-lane gap" aria-disabled="true" title="Type groups are a reference-only lane — the daemon records none (named gap)" data-ioi-disabled-reason="Type groups are a reference-only lane — the daemon records none (named gap)">Type group</span>
      <span class="oe-lane gap" aria-disabled="true" title="Application scoping is a reference-only lane (named gap)" data-ioi-disabled-reason="Application scoping is a reference-only lane (named gap)">Application</span>
    </span>
  </div>
  <div class="oe-tablebox">
    <table class="oe-table">
      <thead><tr><th class="oe-thname">Object type name</th><th class="oe-thstatus">Status</th><th class="oe-thcount">Object count</th><th class="oe-thusage">Usage</th><th class="oe-thgroups">Type groups</th><th>Description</th></tr></thead>
      <tbody>${catalog.length ? catalog.map(typeRow).join("") : `<tr><td colspan="6" class="oe-none">${q ? `No object types match “${esc(q)}”.` : "No object types yet — create an ontology in the Ontology Manager."} <a href="/__ioi/ontology/manager">Ontology Manager →</a></td></tr>`}</tbody>
    </table>
  </div>`;

  // XIV Leg 1 — THE SAVED-OBJECT-SET CONTROL IS BOUND. The family landed in XIII
  // (GET/POST /v1/hypervisor/odk/saved-object-sets, scoped per principal); this surface had no
  // control for it. The catalog below is the REAL saved-set list, and the form saves the selection
  // the user is actually looking at.
  const setQuery = (opts && opts.setQuery ? String(opts.setQuery) : "").trim();
  const savedSets = Array.isArray(opts && opts.savedSets) ? opts.savedSets : null;
  const savedRefusal = opts && opts.savedSetsRefusal;
  const searchState = opts && opts.search;
  const scopedOnt = ontologies.find((o) => o && (o.id === sel.ontology || o.ref === sel.ontology)) || ontologies[0] || null;
  const scopedRef = scopedOnt ? String(scopedOnt.ref || scopedOnt.id || "") : "";
  // THE SELECTION IS WHAT IS BEING SAVED, so it is rendered as the form's own fields rather than
  // reconstructed at submit time: a control that saves something other than what it displays is the
  // same defect as a reason that names something other than what exists.
  const saveTypeId = (searchState && searchState.objectTypeId) || sel.objectType || "";
  const selQ = (searchState && searchState.q) || "";
  const filtered = savedSets ? savedSets.filter((s) => !setQuery || String(s.name || "").toLowerCase().includes(setQuery.toLowerCase())) : [];
  const savedRows = filtered.slice(0, 20).map((s) => {
    const sn = s.selection || {};
    const what = [sn.object_type_id ? `type ${sn.object_type_id}` : "", sn.q ? `q “${sn.q}”` : ""].filter(Boolean).join(" · ") || "—";
    return `<tr><td class="oe-ssname">${esc(String(s.name || s.id || ""))}</td><td class="oe-sssel">${esc(what)}</td><td class="oe-ssref">${esc(String(s.ref || ""))}</td></tr>`;
  }).join("");
  const savedBody = savedRefusal
    ? `<tr><td class="oe-none oe-ssrefused">The saved-object-set plane did not answer — <code>${esc(savedRefusal.code)}</code> ${esc(savedRefusal.message)}. This is not an empty catalog.</td></tr>`
    : (savedRows || `<tr><td class="oe-none">No saved object sets yet${setQuery ? " matching this filter" : ""} — save the selection you are looking at to create one.</td></tr>`);
  const savedResult = (opts && opts.result)
    ? `<p class="oe-ssok" role="status">Saved — <code>saved-object-set://${esc(String(opts.result))}</code></p>`
    : ((opts && opts.refusalCode) ? `<p class="oe-ssrefusal" role="alert">Refused — <code>${esc(String(opts.refusalCode))}</code>. Nothing was saved.</p>` : "");
  const savedSetsHtml = `<div class="oe-savedbox">
    <div class="oe-savedhead"><b>Saved object sets</b> <span class="oe-setsub">your explorations, from GET /v1/hypervisor/odk/saved-object-sets</span></div>
    ${savedResult}
    <table class="oe-table oe-savedtable"><tbody>${savedBody}</tbody></table>
    ${scopedRef ? `<form class="oe-saveform" method="post" action="${esc(basePath)}/actions/save-object-set">
      <input type="hidden" name="ontology" value="${esc(String(scopedOnt.id || ""))}">
      <input type="hidden" name="ontology_ref" value="${esc(scopedRef)}">
      <input type="hidden" name="object_type_id" value="${esc(String(saveTypeId))}">
      <input type="hidden" name="q" value="${esc(String(selQ))}">
      <label class="oe-savelbl">Name <input class="oe-savename" name="name" required maxlength="200" placeholder="Name this exploration" aria-label="Name for the saved object set"></label>
      <label class="oe-savelbl">Description <input class="oe-savedesc" name="description" maxlength="2000" placeholder="Optional" aria-label="Description for the saved object set"></label>
      <button class="oe-savebtn" type="submit"${saveTypeId || selQ ? "" : ` disabled title="A saved set stores a SELECTION — search for objects or select a type first"`}>Save this selection</button>
      <span class="oe-savewhat">${saveTypeId || selQ ? `saves ${esc([saveTypeId ? `type ${saveTypeId}` : "", selQ ? `q “${selQ}”` : ""].filter(Boolean).join(" · "))}` : "nothing selected yet"}</span>
    </form>` : `<p class="oe-savegap">No ontology is in scope, so there is no selection to save — saved sets belong to one ontology.</p>`}
  </div>`;

  const setBand = `<div class="oe-setrow">
    <span class="oe-setlabel">Object set catalog <span class="oe-setsub">(explorations and lists)</span></span>
    <span class="oe-setlanes">
      <form class="oe-setfilter" method="get" action="${esc(basePath)}">${sel.ontology ? `<input type="hidden" name="ontology" value="${esc(sel.ontology)}">` : ""}<input class="oe-setsearch" name="setq" value="${esc(setQuery)}" placeholder="Search explorations..." aria-label="Filter saved object sets by name" title="Filters the saved object sets below, read from GET /v1/hypervisor/odk/saved-object-sets"></form>
      <span class="oe-slane on gap" aria-disabled="true" title="named gap" data-ioi-disabled-reason="named gap">All</span>
      <span class="oe-slane gap" aria-disabled="true" title="Per-user lanes over the MATERIALIZED set catalog are reference-only (named gap) — that catalog records no per-user ownership; saved object sets are a different store and are scoped per principal" data-ioi-disabled-reason="Per-user lanes over the MATERIALIZED set catalog are reference-only (named gap) — that catalog records no per-user ownership; saved object sets are a different store and are scoped per principal">Created by me</span>
      <span class="oe-slane gap" aria-disabled="true" title="named gap" data-ioi-disabled-reason="named gap">Shared with me</span>
      <span class="oe-slane gap" aria-disabled="true" title="named gap" data-ioi-disabled-reason="named gap">Favorites</span>
    </span>
  </div>
  ${savedSetsHtml}
  <div class="oe-setbox">
    <table class="oe-table oe-settable">
      <tbody>${msets.length ? msets.slice(0, 20).map(setRow).join("") : `<tr><td class="oe-none">No object sets yet — a materialized set appears once an OntologyProjection reads a source (${projs.length} projection${projs.length === 1 ? "" : "s"} declared). <a href="/__ioi/odk">ODK substrate →</a></td></tr>`}</tbody>
    </table>
    <div class="oe-foot">Every row is daemon truth: ${allTypes.length} object type${allTypes.length === 1 ? "" : "s"} across ${ontologies.length} live ontolog${ontologies.length === 1 ? "y" : "ies"} · ${msets.length} materialized set${msets.length === 1 ? "" : "s"}. Schema authoring: <a href="/__ioi/ontology/manager">Ontology Manager →</a> · substrate: <a href="/__ioi/odk">ODK</a> · reference: <a href="/__apps/explorer" target="_blank" rel="noopener">Object Explorer capture ↗</a></div>
  </div>`;

  // ---- Semantic inspectors — real COM/set truth only: declarations stay declarations, no
  // editor, no action execution (the standing boundary), no fabricated rows. Refs render through
  // formatRef; the set's source contact is reduced to its ORIGIN (path redacted).
  const irow = (k, v) => `<div class="oe-irow"><span class="oe-ik">${esc(k)}</span><span class="oe-iv">${v}</span></div>`;
  // Consent/visibility ladder (canon: every semantic object carries one; brief §4 W1 row):
  // project the postures of the PolicyBoundDataViews binding this ontology/type onto the
  // inspector as a badge row. HONEST ABSENCE when no view binds — a missing ladder renders as
  // a named gap, never as an implied "public".
  const POSTURE_KEYS = ["retention_posture", "export_posture", "training_posture", "evaluation_posture", "publish_route_posture"];
  const viewsFor = (ontologyRef, objectTypeId) => policyViews.filter((v) =>
    v.ontology_ref === ontologyRef && (!objectTypeId || !v.object_type_id || v.object_type_id === objectTypeId));
  const consentRow = (ontologyRef, objectTypeId) => {
    const views = viewsFor(ontologyRef, objectTypeId);
    if (!views.length) {
      return irow("consent / visibility", `<span class="oe-redact">no policy-bound view binds this ${objectTypeId ? "object type" : "ontology"} — the consent/visibility ladder is honestly absent (declare one in Data)</span>`);
    }
    const badges = views.map((v) => {
      const chips = POSTURE_KEYS.filter((k) => v[k]).map((k) => `<span class="oe-pbadge" title="${esc(k)}">${esc(String(v[k]))}</span>`).join("");
      const health = v.health && v.health.status ? `<span class="oe-pbadge oe-ph-${esc(String(v.health.status))}">${esc(String(v.health.status))}</span>` : "";
      return `<span class="oe-pview">${formatRef(v.ref || v.id)} ${chips || '<span class="oe-redact">no postures declared</span>'}${health}</span>`;
    }).join("<br>");
    return irow("consent / visibility", badges);
  };
  const ihint = (h, warn) => `<div class="oe-ihint${warn ? " oe-warnhint" : ""}">${h}</div>`;
  const safeOrigin = (e) => { try { const u = new URL(e); return `${esc(u.protocol)}//${esc(u.host)}/… <span class="oe-redact">(path redacted)</span>`; } catch { return "(endpoint redacted)"; } };
  function typeInspector() {
    const oo = selOnt, t = selType;
    const props = Array.isArray(t.properties) ? t.properties : [];
    const links = arr(oo, "link_types").filter((l) => l.from === t.id || l.to === t.id);
    const acts = arr(oo, "action_types").filter((a) => a.applies_to === t.id);
    const n = objectsOf(oo, t);
    const typeSets = msets.filter((m) => m.ontology_ref === oo.ref && m.object_type_id === t.id);
    const relProjs = projs.filter((p) => p.ontology_ref === oo.ref && (!p.object_type_id || p.object_type_id === t.id));
    const filteredOut = q && !catalog.some((c) => c.oo.id === oo.id && c.t.id === t.id);
    return {
      title: t.name || t.id,
      sub: `${oo.ref} · object type ${t.id}`,
      body: [
        semanticBreadcrumb([{ label: oo.domain || oo.id, href: managerLink({ ontology: oo.id }) }, { label: t.name || t.id }]),
        filteredOut ? ihint(`The selected type is hidden by the current filter “${esc(q)}” — <a href="${objectTypeLink(oo.id, t.id)}">clear the filter</a> to see its row.`, true) : "",
        irow("ontology", `${esc(oo.domain || oo.id)} ${formatRef(oo.ref)}`),
        irow("object type", `${esc(t.name || t.id)} ${formatRef(t.id)}`),
        irow("title property", t.title_property ? formatRef(t.title_property) : "—"),
        consentRow(oo.ref, t.id),
        irow("objects", `<b>${n}</b> across ${typeSets.length} materialized set${typeSets.length === 1 ? "" : "s"}${typeSets.length ? ` — <a href="${objectSetLink(oo.id, typeSets[0].id)}">inspect the set</a>` : ""}`),
        props.length
          ? `<table class="oe-itable"><thead><tr><th>property</th><th>value type</th><th></th></tr></thead><tbody>${props.map((p) => `<tr><td>${esc(p.name || p.id)}</td><td>${formatRef(p.value_type || "")}</td><td>${p.id === t.title_property ? "title" : p.required ? "required" : ""}</td></tr>`).join("")}</tbody></table>`
          : ihint("No properties declared on this type — an honest empty declaration."),
        irow("link declarations", links.length ? links.map((l) => `${formatRef(l.from)} → ${formatRef(l.to)}${l.name ? ` <span class="oe-redact">(${esc(l.name)})</span>` : ""}`).join("<br>") : "none declared"),
        irow("action declarations", acts.length ? acts.map((a) => `${esc(a.name || a.id)} ${formatRef(a.kind || "")}`).join("<br>") : "none declared"),
        acts.length ? ihint("Action <b>declarations</b> only — no action authority exists on this surface; execution stays a named gap (standing boundary).") : "",
        irow("projections", relProjs.length ? relProjs.map((p) => esc(p.name || p.id)).join(", ") : "none"),
        irow("open in", `<a href="${managerLink({ ontology: oo.id, section: "object-types", definitionKind: "object-type", definitionId: t.id })}">Manager definition</a> · <a href="${pipelineNodeLink(oo.id, "mapping")}">Pipeline</a>`),
        `<div class="oe-iacts">${disabledSemanticAction({ label: "Execute action", reason: "action declarations carry no execution authority — no action plane exists on this surface (standing boundary)" })}${disabledSemanticAction({ label: "Search instances", reason: "object-instance search has no surface control yet — the plane exists as daemon truth (POST /v1/hypervisor/odk/object-instance-search) and walks the materialized-set store; binding this control to it is the named gap" })}</div>`,
      ].join(""),
    };
  }
  function setInspector() {
    const m = selSet, so = selSetOnt || {};
    const p = projs.find((x) => x.id === m.ontology_projection_id) || null;
    const pcols = p ? (p.visible_properties || []) : Object.keys(((m.objects || [])[0] || {}).properties || {});
    const prows = (m.objects || []).slice(0, 8);
    const typeHref = so.id ? objectTypeLink(so.id, m.object_type_id) : "";
    return {
      title: m.name || m.object_type_id || m.id,
      sub: m.ref || m.id,
      body: [
        semanticBreadcrumb([{ label: so.domain || m.ontology_ref || "ontology", href: so.id ? managerLink({ ontology: so.id }) : undefined }, { label: m.object_type_id || "type", href: typeHref || undefined }, { label: "object set" }]),
        irow("object set", formatRef(m.ref || m.id)),
        irow("object type", typeHref ? `<a href="${typeHref}">${esc(m.object_type_id)}</a>` : formatRef(m.object_type_id)),
        consentRow(m.ontology_ref, m.object_type_id),
        irow("objects", `<b>${m.count ?? 0}</b> (rows fetched ${m.rows_fetched ?? "—"}${m.truncated_to_limit ? " · truncated to limit" : ""})`),
        irow("registered", esc(m.registered_at || "—")),
        irow("provenance", [m.materializing_run_ref, m.connector_session_ref, m.capability_lease_plan_ref].filter(Boolean).map(formatRef).join(" ") || "—"),
        irow("pre-output receipt", m.pre_output_receipt_ref ? formatRef(m.pre_output_receipt_ref) : "—"),
        m.source_contact ? irow("source contact", `${safeOrigin(m.source_contact.endpoint || "")} · http ${esc(String(m.source_contact.http_status ?? "—"))}`) : "",
        irow("preview", `${prows.length} of ${m.count ?? 0} row${(m.count ?? 0) === 1 ? "" : "s"} below — real daemon objects`),
        prows.length
          ? `<table class="oe-itable"><thead><tr>${pcols.map((c) => `<th>${esc(c)}</th>`).join("")}</tr></thead><tbody>${prows.map((o2) => `<tr>${pcols.map((c) => `<td>${esc(String((o2.properties || {})[c] ?? ""))}</td>`).join("")}</tr>`).join("")}</tbody></table>`
          : ihint("This set holds no rows — honest empty; nothing is fabricated."),
        irow("open in", `<a href="${pipelineNodeLink(so.id || "", "materialized")}">Pipeline</a> · <a href="${lineageLink(so.id || "", m.id)}">Lineage</a> · <a href="${vertexLink(so.id || "", m.id)}">Vertex</a> · <a href="${provenanceSetLink(m.id)}">Provenance</a> · ${m.object_type_id ? `<a href="${managerLink({ ontology: so.id || "", section: "object-types", definitionKind: "object-type", definitionId: m.object_type_id })}">Manager definition</a>` : `<a href="${managerLink({ ontology: so.id || "" })}">Ontology Manager</a>`}`),
      ].join(""),
    };
  }
  const insp = !hasSelParam ? null : selSet ? setInspector() : selType ? typeInspector() : {
    title: "Nothing selected",
    sub: "fail-closed",
    body: ihint(`Unknown ${sel.objectSet ? `object set ${formatRef(sel.objectSet)}` : `object type ${formatRef(sel.objectType || "")}${sel.ontology ? ` in ontology ${formatRef(sel.ontology)}` : " (no ontology given)"}`} — nothing is selected (fail-closed).`, true)
      + ihint("Select an object type or an object set from the catalog to inspect its semantic truth. Nothing is recommended or fabricated."),
  };
  const inspectorAside = insp ? `<aside class="oe-inspector" data-testid="oe-inspector">${semanticInspectorShell({ id: "oe-sem-inspector", title: insp.title, subtitle: insp.sub, body: insp.body })}</aside>` : "";

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
    .oe-ontsel{display:inline-flex;align-items:center;gap:8px;height:30px;margin-top:5px;margin-right:10px;padding:0 8px;border-radius:4px;font-size:14px;line-height:16.1px;color:#1c2127;cursor:default;background:#fff;box-shadow:inset 0 0 0 1px rgba(64,72,84,.33),0 1px 2px rgba(17,20,24,.1)}
    .oe-ontsel svg{color:#5f6b7c}
    .oe-ontform{margin-left:auto;display:inline-flex;align-items:center}
    select.oe-ontlive{margin-left:0;appearance:auto;border:0;font:inherit;cursor:pointer;max-width:240px}
    .oe-ontgo{height:30px;margin:5px 10px 0 4px;border:0;border-radius:4px;background:#2d72d2;color:#fff;font:inherit;padding:0 10px}
    .oe-pbadge{display:inline-block;margin:0 4px 2px 0;padding:1px 6px;border-radius:3px;background:#eef2f7;color:#394b59;font-size:10.5px;border:1px solid #d3dce6}
    .oe-ph-ready{background:#e8f4ea;border-color:#bcd9c2;color:#1d7324}
    .oe-ph-incomplete{background:#fdf7ec;border-color:#e8c48d;color:#935610}
    .oe-pview{display:inline-block;margin-bottom:3px}
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
    .oe-foot{margin-top:14px;color:#7b8494;font-size:12px;line-height:1.5}
    .oe-tlink{color:inherit}
    .oe-trow.oe-sel{background:#f3f8ff;box-shadow:inset 2px 0 0 #2d72d2}
    .oe-trow.oe-sel:hover{background:#eef4fd}
    .oe-withinsp{display:flex;overflow:hidden}
    .oe-withinsp .oe-content{flex:1 1 auto;min-width:0;width:auto;margin:0 30px;overflow-y:auto}
    .oe-inspector{flex:0 0 380px;border-left:1px solid #dce0e5;background:#fff;overflow-y:auto}
    .oe-inspector .ioi-inspector-hd{display:flex;flex-direction:column;gap:2px;padding:12px 14px 10px;border-bottom:1px solid #eef0f2}
    .oe-inspector .ioi-inspector-title{font-size:14px;line-height:18.0013px;font-weight:600;color:#1c2127}
    .oe-inspector .ioi-inspector-sub{font-size:11px;color:#5f6b7c;font-family:ui-monospace,SFMono-Regular,monospace;word-break:break-all}
    .oe-inspector .ioi-inspector-body{padding:12px 14px;font-size:12px}
    .ioi-sem-breadcrumb{font-size:12px;color:#5f6b7c;margin:0 0 12px}
    span.ioi-sem-crumb{color:#1c2127}
    .oe-irow{display:flex;gap:10px;font-size:12px;line-height:15.4297px;padding:0 0 8px}
    .oe-ik{color:#5f6b7c;width:110px;flex:0 0 110px}
    .oe-iv{color:#1c2127;min-width:0;word-break:break-word}
    .ioi-ref{font-family:ui-monospace,SFMono-Regular,monospace;font-size:10.5px;background:#f1f3f6;border-radius:3px;padding:1px 4px;word-break:break-all}
    .oe-redact{color:#8f99a8;font-size:11px}
    .oe-ihint{margin:6px 0 10px;padding:8px 10px;border:1px solid #e5e7eb;border-radius:6px;background:#f7f8fa;color:#5b6270;font-size:11.5px;line-height:1.55}
    .oe-warnhint{border-color:#e8c48d;background:#fdf7ec;color:#935610}
    .oe-itable{border-collapse:collapse;width:100%;font-size:11.5px;margin:0 0 10px;table-layout:auto}
    .oe-itable th{text-align:left;color:#7b8494;font-weight:600;padding:3px 8px 3px 0;border-bottom:1px solid #e2e4e8;text-transform:none}
    .oe-itable td{padding:3px 8px 3px 0;border-bottom:1px solid #f0f1f4;color:#2a2f38;word-break:break-word}
    .oe-iacts{display:flex;gap:8px;margin-top:8px}
    .ioi-cmd-disabled{display:inline-flex;align-items:center;height:24px;padding:0 8px;border:1px solid #d3d8de;border-radius:4px;background:#f7f8f8;color:#8f99a8;font:inherit;font-size:12px;cursor:not-allowed}
    @media(max-width:700px){
      .oe-main{height:100svh}.oe-tabbar{min-width:0}
      .oe-sqbtn{width:35px;flex:0 0 35px}.oe-tab{width:auto;min-width:0;flex:1;padding-left:9px}.oe-tabt{font-size:13px}
      .oe-plus{display:none}.oe-ontsel{max-width:120px;margin-right:6px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis}
      .oe-body{overflow-x:hidden}.oe-content{width:auto;margin:0 14px}
      .oe-htitle{margin-top:18px}.oe-searchrow{margin-top:12px}
      .oe-herogrp{width:100%;flex-direction:column;margin-left:0}
      .oe-filterby,.oe-objsearch{width:100%;border-right:0;border-radius:4px}.oe-filterby{height:34px;border-bottom:1px solid rgba(17,20,24,.15)}
      .oe-shrow{align-items:flex-start;flex-wrap:wrap}.oe-lanes{width:100%;margin:8px 0 0;overflow-x:auto}.oe-lane{flex:0 0 auto}
      .oe-shchev{display:none}.oe-cards{flex-direction:column}.oe-card,.oe-cardempty{flex:0 0 auto;width:100%;min-height:57px;height:auto;padding-top:10px;padding-bottom:10px}
      .oe-cathead{margin-top:38px}.oe-filterrow{align-items:flex-start;flex-wrap:wrap;gap:8px}.oe-filterform{width:100%}.oe-sortlanes{margin-left:0;width:100%;overflow-x:auto}
      .oe-tablebox{height:360px}.oe-table th:nth-child(n+3),.oe-table td:nth-child(n+3){display:none}
      .oe-thname{width:calc(100% - 78px)}.oe-thstatus{width:78px}
      .oe-setrow{align-items:flex-start;flex-direction:column;gap:9px}.oe-setlanes{width:100%;margin-left:0;overflow-x:auto}.oe-setsearch{width:170px;flex:0 0 170px}
      .oe-withinsp{display:flex;flex-direction:column;overflow-y:auto}.oe-withinsp .oe-content{width:auto;margin:0 14px;overflow:visible;flex:0 0 auto}
      .oe-inspector{width:100%;flex:0 0 auto;border-left:0;border-top:1px solid #dce0e5;overflow:visible}
      .oe-irow{flex-direction:column;gap:2px}.oe-ik{width:auto;flex:0 0 auto}
    }`;

  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Object Explorer</title><style>${css}</style></head>
    <body><div class="oe-shell">${globalRail}<div class="oe-main">${tabbar}<div class="oe-body${insp ? " oe-withinsp" : ""}"><main class="oe-content" role="main">${hero}${shortcutsBand}${catalogBand}${setBand}</main>${inspectorAside}</div></div></div></body></html>`;
}
