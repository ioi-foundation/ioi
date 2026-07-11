// Ontology Manager — extracted app module (Ontology Application Runtime wave). The render code
// below is moved VERBATIM from serve-product-ui.mjs (zero behavior change by construction); the
// module adds only the surface contract the registry mounts. /__ioi/ontology/manager is a
// certified shell (pixel-certifications/schema.json) — pixels are frozen by the harness gate.
import { bpIcon, ONTOLOGY_APP_ICON_URI } from "../../scripts/bp-icons.mjs";
import { ioiGlobalRailHtml, IOI_GRAIL_CSS } from "../chrome.mjs";
import { escHtml } from "../kit.mjs";
import { loadOntologyModel, parseOntologyContext, ontologyContextQuery, explorerLink, objectTypeLink, objectSetLink, semanticBreadcrumb, disabledSemanticAction, formatRef, sourcesLink, managerResourceLink, pipelineNodeLink, lineageLink, vertexLink, provenanceSetLink } from "../ontology-context.mjs";

const CX_ESC = escHtml; // local alias so the moved block stays byte-identical to its serve original

export const meta = {
  slug: "schema",
  route: "/__ioi/ontology/manager",
  verifier: "scripts/verify-hypervisor-app-parity-ontology-manager.mjs",
  certification: "pixel-certifications/schema.json",
};

// Operational load (#63): the shared ontology model + the resource projections the inspectors
// need (connector mappings + policy-bound views + the daemon's edit vocabulary). A dead daemon
// projection yields null (an honest "unavailable" inspector state), never a fabricated array.
export async function load(ctx) {
  const base = await loadOntologyModel(ctx.daemon);
  const J = (p) => fetch(`${ctx.daemon}${p}`).then((r) => r.json()).catch(() => null);
  const [cm, pv] = await Promise.all([
    J("/v1/hypervisor/odk/connector-mappings"),
    J("/v1/hypervisor/odk/policy-bound-data-views"),
  ]);
  base.lists.connector_mappings = cm && Array.isArray(cm.connector_mappings) ? cm.connector_mappings : (cm === null ? null : []);
  base.lists.policy_views = pv && Array.isArray(pv.policy_bound_data_views) ? pv.policy_bound_data_views : (pv === null ? null : []);
  base.vocab = (base.overview && base.overview.odk_vocabulary) || { base_value_types: ["string", "integer", "double", "boolean", "timestamp", "enum"], link_cardinalities: ["one_to_one", "one_to_many", "many_to_many"], action_kinds: ["create_object", "modify_object", "delete_object", "function"] };
  return base;
}

export function render(model, ctx) {
  const sel = parseOntologyContext(ctx.url);
  return renderOntologyManagerPort(model.overview, model.lists, sel.ontology || "", {
    sel, vocab: model.vocab,
    q: ctx.url.searchParams.get("q") || "",
    banner: {
      acted: ctx.url.searchParams.get("acted") || "", receipt: ctx.url.searchParams.get("receipt") || "",
      refused: ctx.url.searchParams.get("refused") || "", reason: ctx.url.searchParams.get("reason") || "",
      created: ctx.url.searchParams.get("created") || "",
    },
  });
}

// Structured typed-model authoring through the EXISTING ODK DomainOntology create/patch authority.
// Every definition action clones the current COM server-side, applies ONE bounded structured edit,
// and submits the complete replacement with expected_revision (optimistic concurrency) — the
// browser NEVER sends a canonical_object_model. IDs are immutable after creation. Deletion,
// object-instance editing, and action/function execution stay disabled named gaps.
const ONT_AUTHORITY = { plane: "odk.domain-ontology", operation: "POST|PATCH /v1/hypervisor/odk/domain-ontologies" };
const ONT_RECEIPT = "ioi.hypervisor.odk.ontology-receipt.v1";
const mkAction = (id, fields, extra) => ({ id, method: "POST", route: "/actions/" + id, fields, context: ["ontology"], authority: ONT_AUTHORITY, receipt: ONT_RECEIPT, confirm: false, success: "return-to-surface", refusal: "typed-banner", ...(extra || {}) });
export const actions = [
  mkAction("create-ontology", ["domain", "version", "description"], { context: [] }),
  mkAction("update-metadata", ["domain", "version", "description"]),
  mkAction("upsert-value-type", ["def_id", "name", "base", "enum_values"]),
  mkAction("upsert-object-type", ["def_id", "name", "description", "title_property"]),
  mkAction("upsert-property", ["object_type_id", "def_id", "name", "value_type", "required"]),
  mkAction("upsert-link-type", ["def_id", "name", "from", "to", "cardinality"]),
  mkAction("upsert-action-type", ["def_id", "name", "kind", "applies_to"]),
];

const bounded = (v, max) => (typeof v === "string" ? v.slice(0, max) : "");
// Clone the current COM and upsert one entry into one collection by id (immutable id, merged fields).
function comUpsert(com, collection, entry) {
  const next = JSON.parse(JSON.stringify(com || {}));
  if (!Array.isArray(next[collection])) next[collection] = [];
  const i = next[collection].findIndex((e) => e && e.id === entry.id);
  if (i >= 0) next[collection][i] = { ...next[collection][i], ...entry };
  else next[collection].push(entry);
  return next;
}

// One typed result per action (#62 contract): success carries the durable ontology receipt;
// refusal carries the daemon's typed code (revision conflict, validation, not-found) with state
// untouched; failure claims nothing. All authoring goes through create/patch — never a raw COM.
export async function handleAction({ action, fields, daemon, url }) {
  const D = (p, method, bodyObj) => fetch(`${daemon}${p}`, { method, headers: { "content-type": "application/json" }, body: JSON.stringify(bodyObj) }).then((x) => x.json()).catch(() => null);
  if (action.id === "create-ontology") {
    const domain = bounded(fields.domain, 120).trim();
    if (!domain) return { kind: "refusal", http: 400, code: "odk_domain_required", message: "a new ontology needs a domain" };
    const r = await D("/v1/hypervisor/odk/domain-ontologies", "POST", { domain, version: bounded(fields.version, 60) || undefined, description: bounded(fields.description, 2000) });
    if (!r) return { kind: "failure", http: 502, code: "daemon_unavailable", message: "the daemon did not answer — nothing was created" };
    if (r.ok !== true) return { kind: "refusal", http: 400, code: (r.error && r.error.code) || "odk_create_refused", message: (r.error && r.error.message) || "create refused" };
    if (!r.ontology_receipt || r.ontology_receipt.schema_version !== ONT_RECEIPT) return { kind: "failure", http: 502, code: "receipt_missing", message: "create returned no declared receipt — failing closed" };
    return { kind: "success", createdOntology: r.ontology.id, receipt_ref: r.ontology_receipt.receipt_ref, redirect: ontologyContextQuery("/__ioi/ontology/manager", { ontology: r.ontology.id, section: "configuration" }) };
  }
  // Every other action edits an existing ontology under optimistic concurrency.
  const ontId = url.searchParams.get("ontology") || fields.ontology || "";
  const cur = await D(`/v1/hypervisor/odk/domain-ontologies/${encodeURIComponent(ontId)}`, "GET");
  if (!cur || cur.ok === false || !cur.ontology) return { kind: "refusal", http: 404, code: "odk_ontology_not_found", message: "select an existing ontology first" };
  const ont = cur.ontology;
  const patch = { expected_revision: ont.revision };
  let redirectCtx = { ontology: ontId, section: "configuration" };
  if (action.id === "update-metadata") {
    if (fields.domain !== undefined) patch.domain = bounded(fields.domain, 120);
    if (fields.version !== undefined) patch.version = bounded(fields.version, 60);
    if (fields.description !== undefined) patch.description = bounded(fields.description, 2000);
  } else {
    const com = ont.canonical_object_model || {};
    const id = bounded(fields.def_id || fields.object_type_id, 64).trim();
    if (!/^[a-z][a-z0-9_]*$/.test(action.id === "upsert-property" ? bounded(fields.def_id, 64).trim() : id)) return { kind: "refusal", http: 400, code: "ontology_type_id_invalid", message: "id must match ^[a-z][a-z0-9_]*$" };
    if (action.id === "upsert-value-type") {
      const e = { id, name: bounded(fields.name, 200), base: bounded(fields.base, 32) || "string" };
      if (e.base === "enum") e.enum_values = bounded(fields.enum_values, 2000).split(",").map((s) => s.trim()).filter(Boolean);
      patch.canonical_object_model = comUpsert(com, "value_types", e);
      redirectCtx = { ontology: ontId, section: "value-types", definitionKind: "value-type", definitionId: id };
    } else if (action.id === "upsert-object-type") {
      const prevOt = (com.object_types || []).find((t) => t.id === id) || {};
      const e = { ...prevOt, id, name: bounded(fields.name, 200), description: bounded(fields.description, 2000) };
      if (fields.title_property) e.title_property = bounded(fields.title_property, 64);
      patch.canonical_object_model = comUpsert(com, "object_types", e);
      redirectCtx = { ontology: ontId, section: "object-types", definitionKind: "object-type", definitionId: id };
    } else if (action.id === "upsert-property") {
      const otId = bounded(fields.object_type_id, 64).trim();
      const next = JSON.parse(JSON.stringify(com || {}));
      const ot = (next.object_types || []).find((t) => t.id === otId);
      if (!ot) return { kind: "refusal", http: 400, code: "ontology_ref_unresolved", message: `object type '${otId}' not found` };
      if (!Array.isArray(ot.properties)) ot.properties = [];
      const pe = { id, name: bounded(fields.name, 200), value_type: bounded(fields.value_type, 64), required: fields.required === "1" || fields.required === "on" };
      const pi = ot.properties.findIndex((p) => p && p.id === id);
      if (pi >= 0) ot.properties[pi] = { ...ot.properties[pi], ...pe }; else ot.properties.push(pe);
      patch.canonical_object_model = next;
      redirectCtx = { ontology: ontId, section: "object-types", definitionKind: "object-type", definitionId: otId };
    } else if (action.id === "upsert-link-type") {
      const e = { id, name: bounded(fields.name, 200), from: bounded(fields.from, 64), to: bounded(fields.to, 64), cardinality: bounded(fields.cardinality, 32) };
      patch.canonical_object_model = comUpsert(com, "link_types", e);
      redirectCtx = { ontology: ontId, section: "link-types", definitionKind: "link-type", definitionId: id };
    } else if (action.id === "upsert-action-type") {
      const e = { id, name: bounded(fields.name, 200), kind: bounded(fields.kind, 32) };
      if (fields.applies_to) e.applies_to = bounded(fields.applies_to, 64);
      patch.canonical_object_model = comUpsert(com, "action_types", e);
      const isFn = e.kind === "function";
      redirectCtx = { ontology: ontId, section: isFn ? "functions" : "action-types", definitionKind: isFn ? "function" : "action-type", definitionId: id };
    }
  }
  const r = await D(`/v1/hypervisor/odk/domain-ontologies/${encodeURIComponent(ontId)}`, "PATCH", patch);
  if (!r) return { kind: "failure", http: 502, code: "daemon_unavailable", message: "the daemon did not answer — nothing was changed" };
  if (r.ok !== true) return { kind: "refusal", http: (r.error && r.error.code === "odk_revision_conflict") ? 409 : 400, code: (r.error && r.error.code) || "odk_patch_refused", message: (r.error && r.error.message) || "patch refused" };
  if (!r.ontology_receipt || r.ontology_receipt.schema_version !== ONT_RECEIPT) return { kind: "failure", http: 502, code: "receipt_missing", message: "patch returned no declared receipt — failing closed" };
  return { kind: "success", status: `rev ${r.ontology.revision}`, receipt_ref: r.ontology_receipt.receipt_ref, redirect: ontologyContextQuery("/__ioi/ontology/manager", redirectCtx) };
}

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


function renderOntologyManagerPort(ov, lists, selectedId, opts) {
  const enc = encodeURIComponent, esc = CX_ESC;
  const o = ov || {};
  const O = opts || {};
  const sel = O.sel || {};
  const vocab = O.vocab || { base_value_types: ["string", "integer", "double", "boolean", "timestamp", "enum"], link_cardinalities: ["one_to_one", "one_to_many", "many_to_many"], action_kinds: ["create_object", "modify_object", "delete_object", "function"] };
  const q = (O.q || "").trim();
  // Manager context (#63): the URL carries section + definitionKind/definitionId (shared ontology
  // context). The bare route — no section, no definition, no create, no q — renders exactly the
  // certified shell (the inspector aside + authoring appear ONLY under explicit context, in the
  // excluded body region). An unknown section fails closed to discover with a visible note.
  const KNOWN_SECTIONS = ["discover", "object-types", "properties", "value-types", "link-types", "action-types", "functions", "health", "resources", "configuration", "create"];
  const rawSection = sel.section || "";
  const section = rawSection && KNOWN_SECTIONS.includes(rawSection) ? rawSection : (rawSection ? "discover" : "");
  const badSection = !!(rawSection && !KNOWN_SECTIONS.includes(rawSection));
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
  // Definition selection anchors (#63): cards/rows retarget to MANAGER selection through the shared
  // ontology context (definitionKind/definitionId in the URL), opening the semantic inspector; the
  // inspector keeps an explicit "Open substrate record" link. Selection is body (excluded region).
  // Declared BEFORE the header/rail (which use mHref/sHref) to avoid a temporal-dead-zone crash.
  const mHref = (ctx) => ontologyContextQuery("/__ioi/ontology/manager", { ontology: oid, ...ctx, ...(sel.embed ? { embed: sel.embed } : {}) });
  const defHref = (kind, id, extra) => mHref({ section: extra && extra.section, definitionKind: kind, definitionId: id });
  const selD = { kind: sel.definitionKind || "", id: sel.definitionId || "" };
  const isSel = (kind, id) => selD.kind === kind && selD.id === id;
  // Real search filter over typed definitions (kept certified: the header input stays the named
  // gap; this is a body filter form). A hidden selection stays selected with a "filtered" notice.
  const matchQ = (name, id) => !q || `${name || ""} ${id || ""}`.toLowerCase().includes(q.toLowerCase());
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
      <a class="og-new" href="${ontologyContextQuery("/__ioi/ontology/manager", { ontology: oid, section: "create", ...(sel.embed ? { embed: sel.embed } : {}) })}">New ${bpIcon("caret-down")}</a>
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
  // Rail section links carry the Manager section (real navigation) while keeping the certified
  // markup (href-only change — pixels unaffected). Named-gap lanes stay disabled in place.
  const sHref = (s) => mHref({ section: s });
  const appRail = `<nav class="og-arail" aria-label="Ontology Manager">
    ${arailItem("compass", "Discover", null, sHref("discover"), { on: true })}
    ${arailItem("people", "Proposals", null, null)}
    ${arailItem("time", "History", null, sHref("configuration"))}
    <div class="og-adiv"></div>
    <div class="og-asec">Resources</div>
    ${arailItem("cube", "Object types", ots.length, sHref("object-types"), { sub: true })}
    ${arailItem("properties", "Properties", propCount, sHref("properties"), { sub: true })}
    ${arailItem("globe-network", "Shared properties", 0, null, { sub: true })}
    ${arailItem("arrows-horizontal", "Link types", lts.length, sHref("link-types"), { sub: true })}
    ${arailItem("take-action", "Action types", nonFuncActs.length, sHref("action-types"), { sub: true })}
    ${arailItem("group-objects", "Groups", 0, null, { sub: true })}
    ${arailItem("selection-box", "Interfaces", 0, null, { sub: true })}
    <div class="og-agap"></div>
    ${arailItem("intersection", "Value types", vts.length, sHref("value-types"), { sub: true })}
    ${arailItem("function", "Functions", funcs.length, sHref("functions"), { sub: true })}
    <div class="og-adiv2"></div>
    ${arailItem("pulse", "Health issues", null, sHref("health"))}
    ${arailItem("clean", "Cleanup", null, null)}
    ${arailItem("cog", "Ontology configuration", null, sHref("configuration"))}
  </nav>`;

  // LIGHT card-first body: object-type cards ("recently modified"), then typed detail + configuration.
  const cardOf = (t) => {
    const desc = (t.description || "").trim();
    return `<a class="og-card${isSel("object-type", t.id) ? " og-selcard" : ""}" data-objecttype="${esc(t.id)}" href="${defHref("object-type", t.id, { section: "object-types" })}" title="${esc(t.name || t.id)} — inspect this object type">
      <div class="og-cardtop"><span class="og-cardico">${svg(CUBE)}</span><span class="og-cardname">${esc(t.name || t.id)}</span><span class="og-cardbook">${svg('<path d="M4 5a2 2 0 012-2h12v18H6a2 2 0 01-2-2z"/><path d="M8 3v18"/>')}</span></div>
      <div class="og-cardobj"><b>${objsOf(t)}</b> object${objsOf(t) === 1 ? "" : "s"}</div>
      <div class="og-carddep">${depsOf(t)} dependent${depsOf(t) === 1 ? "" : "s"}</div>
      <div class="og-carddesc">${desc ? esc(desc) : "No description"}</div>
    </a>`;
  };
  const tbl = (head, rows, empty) => rows ? `<table class="og-table"><thead><tr>${head.map((h) => `<th>${h}</th>`).join("")}</tr></thead><tbody>${rows}</tbody></table>` : `<div class="og-none">${empty}</div>`;
  // Rows are selection anchors (definitionKind/definitionId in the URL). The whole row navigates;
  // the name cell is a keyboard-reachable link. The selected row highlights.
  const drow = (kind, id, section, cells) => `<tr class="og-drow${isSel(kind, id) ? " og-selrow" : ""}" data-def="${esc(kind)}:${esc(id)}"${isSel(kind, id) ? ' aria-current="true"' : ""} onclick="location.href='${defHref(kind, id, { section })}'">${cells}</tr>`;
  const dname = (kind, id, label) => `<a class="og-dlink" href="${defHref(kind, id, { section: kind === "value-type" ? "value-types" : kind === "link-type" ? "link-types" : kind === "action-type" ? "action-types" : kind === "function" ? "functions" : "properties" })}">${label}</a>`;
  const propRows = ots.flatMap((t) => (Array.isArray(t.properties) ? t.properties : []).filter((p) => matchQ(p.name, p.id)).map((p) => drow("property", `${t.id}.${p.id}`, "properties", `<td>${esc(t.name || t.id)}</td><td>${dname("property", `${t.id}.${p.id}`, esc(p.name || p.id))} ${idc(p.id)}</td><td>${idc(p.value_type || "")}</td><td>${p.required ? "yes" : "—"}${t.title_property === p.id ? ` <span class="om-pill ok">title</span>` : ""}</td>`))).join("");
  const valRows = vts.filter((v) => matchQ(v.name, v.id)).map((v) => drow("value-type", v.id, "value-types", `<td>${dname("value-type", v.id, esc(v.name || v.id))} ${idc(v.id)}</td><td><span class="om-pill muted">${esc(v.base || "string")}</span></td><td>${(v.enum_values && v.enum_values.length) ? v.enum_values.map((e) => `<span class="om-pill muted">${esc(e)}</span>`).join(" ") : "—"}</td>`)).join("");
  const linkRows = lts.filter((l) => matchQ(l.name, l.id)).map((l) => drow("link-type", l.id, "link-types", `<td>${dname("link-type", l.id, esc(l.name || l.id))} ${idc(l.id)}</td><td>${idc(l.from || "")} → ${idc(l.to || "")}</td><td><span class="om-pill muted">${esc(l.cardinality || "")}</span></td>`)).join("");
  const actRows = nonFuncActs.filter((a) => matchQ(a.name, a.id)).map((a) => drow("action-type", a.id, "action-types", `<td>${dname("action-type", a.id, esc(a.name || a.id))} ${idc(a.id)}</td><td><span class="om-pill muted">${esc(a.kind || "")}</span></td><td>${a.applies_to ? idc(a.applies_to) : "—"}</td>`)).join("");
  const funcRows = funcs.filter((a) => matchQ(a.name, a.id)).map((a) => drow("function", a.id, "functions", `<td>${dname("function", a.id, esc(a.name || a.id))} ${idc(a.id)}</td><td>${a.applies_to ? idc(a.applies_to) : "—"}</td>`)).join("");
  // ---- Semantic inspectors + structured authoring (#63). Every value is daemon truth; forms are
  // selects/checkboxes/bounded inputs only (no JSON editor); IDs are immutable after create.
  const irow = (k, v) => `<div class="og-irow"><span class="og-ik">${esc(k)}</span><span class="og-iv">${v}</span></div>`;
  const ihint = (h, warn) => `<div class="og-ihint${warn ? " og-warnhint" : ""}">${h}</div>`;
  const opt = (list, cur) => list.map((v) => `<option value="${esc(v)}"${v === cur ? " selected" : ""}>${esc(v)}</option>`).join("");
  const RET = `<input type="hidden" name="ontology" value="${esc(oid)}">${sel.embed ? `<input type="hidden" name="embed" value="1">` : ""}`;
  const aForm = (id, inner) => `<form class="og-form" method="post" action="/__ioi/ontology/manager/actions/${id}">${RET}${inner}<button class="og-save" type="submit">Save</button></form>`;
  const otOptions = ots.map((t) => t.id);
  const findOt = (id) => ots.find((t) => t.id === id);
  // Resolve the selected definition to a real record (or null → honest fail-closed inspector).
  function resolveDef() {
    if (!selD.kind) return null;
    if (selD.kind === "object-type") return findOt(selD.id) ? { ot: findOt(selD.id) } : { missing: true };
    if (selD.kind === "property") { const [otId, pId] = selD.id.split("."); const ot = findOt(otId); const p = ot && (ot.properties || []).find((x) => x.id === pId); return p ? { ot, p } : { missing: true }; }
    if (selD.kind === "value-type") { const v = vts.find((x) => x.id === selD.id); return v ? { v } : { missing: true }; }
    if (selD.kind === "link-type") { const l = lts.find((x) => x.id === selD.id); return l ? { l } : { missing: true }; }
    if (selD.kind === "action-type" || selD.kind === "function") { const a = ats.find((x) => x.id === selD.id); return a ? { a } : { missing: true }; }
    if (selD.kind === "health-gap") return { gap: selD.id };
    // Typed resource kinds (#64): resolve the EXACT requested family before id lookup — identical
    // ids across families can never select the wrong record. The old generic "resource" kind
    // stays readable as a compatibility fallback (fixed family order) but is never emitted.
    const cmList = (lists.connector_mappings === null ? [] : (lists.connector_mappings || [])).filter((x) => x.ontology_ref === selected.ref);
    const pvList = (lists.policy_views === null ? [] : (lists.policy_views || [])).filter((x) => x.ontology_ref === selected.ref);
    if (selD.kind === "connector-mapping") { const m = cmList.find((x) => x.id === selD.id); return m ? { cm: m } : { missing: true }; }
    if (selD.kind === "policy-view") { const v2 = pvList.find((x) => x.id === selD.id); return v2 ? { pv2: v2 } : { missing: true }; }
    if (selD.kind === "ontology-projection") { const p2 = projs.find((x) => x.id === selD.id); return p2 ? { pj: p2 } : { missing: true }; }
    if (selD.kind === "materialized-set") { const s2 = msets.find((x) => x.id === selD.id); return s2 ? { ms2: s2 } : { missing: true }; }
    if (selD.kind === "resource") {
      const m = cmList.find((x) => x.id === selD.id); if (m) return { cm: m };
      const v2 = pvList.find((x) => x.id === selD.id); if (v2) return { pv2: v2 };
      const p2 = projs.find((x) => x.id === selD.id); if (p2) return { pj: p2 };
      const s2 = msets.find((x) => x.id === selD.id); if (s2) return { ms2: s2 };
      return { missing: true };
    }
    return { missing: true };
  }
  const def = selected ? resolveDef() : null;
  const openSubstrate = selected ? `<a class="og-sublink" href="/__ioi/odk/ontologies/${enc(selected.id)}/edit">Open substrate record →</a>` : "";
  function inspectorFor() {
    if (!def) return "";
    const crumb = semanticBreadcrumb([{ label: selected.domain || selected.id, href: mHref({ section: "discover" }) }, { label: selD.kind }, { label: selD.id }]);
    if (def.missing) return `<div class="og-inspector" data-testid="og-inspector"><div class="og-ihd"><b>Not found</b></div><div class="og-ibody">${crumb}${ihint(`No ${esc(selD.kind)} <code>${esc(selD.id)}</code> in this ontology — failed closed. <a href="${mHref({ section: "discover" })}">Back to discover</a>.`, true)}</div></div>`;
    let title = selD.id, bodyHtml = "";
    if (def.ot) {
      const t = def.ot; title = t.name || t.id;
      const props = Array.isArray(t.properties) ? t.properties : [];
      const tsets = msets.filter((m) => m.object_type_id === t.id);
      bodyHtml = [
        irow("id · name", `${formatRef(t.id)} · ${esc(t.name || "—")}`),
        irow("description", esc(t.description || "—")),
        irow("title property", t.title_property ? formatRef(t.title_property) : "— none"),
        irow("objects", `<b>${objsOf(t)}</b> across ${tsets.length} set${tsets.length === 1 ? "" : "s"}`),
        props.length ? `<table class="og-itable"><thead><tr><th>property</th><th>value type</th><th></th></tr></thead><tbody>${props.map((p) => `<tr><td><a href="${defHref("property", `${t.id}.${p.id}`, { section: "properties" })}">${esc(p.name || p.id)}</a></td><td>${formatRef(p.value_type || "")}</td><td>${p.id === t.title_property ? "title" : p.required ? "required" : ""}</td></tr>`).join("")}</tbody></table>` : ihint("No properties yet."),
        irow("links", lts.filter((l) => l.from === t.id || l.to === t.id).map((l) => `<a href="${defHref("link-type", l.id, { section: "link-types" })}">${esc(l.name || l.id)}</a>`).join(", ") || "none"),
        irow("actions", ats.filter((a) => a.applies_to === t.id).map((a) => `<a href="${defHref(a.kind === "function" ? "function" : "action-type", a.id)}">${esc(a.name || a.id)}</a>`).join(", ") || "none"),
        irow("open in", `<a href="${objectTypeLink(oid, t.id)}">Explorer</a> · <a href="${pipelineNodeLink(oid, "mapping")}">Pipeline</a>`),
        `<h4 class="og-fhd">Edit object type</h4>`,
        aForm("upsert-object-type", `<input type="hidden" name="def_id" value="${esc(t.id)}"><label class="og-fl">Name<input name="name" maxlength="200" value="${esc(t.name || "")}" required></label><label class="og-fl">Description<input name="description" maxlength="2000" value="${esc(t.description || "")}"></label><label class="og-fl">Title property<select name="title_property"><option value="">— none —</option>${opt(props.map((p) => p.id), t.title_property || "")}</select></label>`),
        `<h4 class="og-fhd">Add / edit a property</h4>`,
        aForm("upsert-property", `<input type="hidden" name="object_type_id" value="${esc(t.id)}"><label class="og-fl">Property id<input name="def_id" maxlength="64" pattern="[a-z][a-z0-9_]*" placeholder="lower_snake" required></label><label class="og-fl">Name<input name="name" maxlength="200" required></label><label class="og-fl">Value type<select name="value_type" required>${opt([...vocab.base_value_types, ...vts.map((v) => v.id)], "")}</select></label><label class="og-fc"><input type="checkbox" name="required" value="1"> required</label>`),
      ].join("");
    } else if (def.p) {
      const { ot, p } = def; title = p.name || p.id;
      bodyHtml = [
        irow("owning object type", `<a href="${defHref("object-type", ot.id, { section: "object-types" })}">${esc(ot.name || ot.id)}</a>`),
        irow("id · name", `${formatRef(p.id)} · ${esc(p.name || "—")}`),
        irow("value type", formatRef(p.value_type || "")),
        irow("posture", `${p.required ? "required" : "optional"}${ot.title_property === p.id ? " · title property" : ""}`),
        irow("mapping usage", (lists.connector_mappings === null) ? "unavailable — daemon did not answer" : (lists.connector_mappings || []).filter((m) => m.ontology_ref === selected.ref && (m.field_mappings || []).some((f) => f.property_id === p.id) || (m.key_mapping && m.key_mapping.property_id === p.id)).length + " mapping(s)"),
      ].join("");
    } else if (def.v) {
      const v = def.v; title = v.name || v.id;
      bodyHtml = [
        irow("id · name", `${formatRef(v.id)} · ${esc(v.name || "—")}`),
        irow("base", `<span class="om-pill muted">${esc(v.base || "string")}</span>`),
        irow("enum values", (v.enum_values || []).length ? v.enum_values.map((e) => `<span class="om-pill muted">${esc(e)}</span>`).join(" ") : "—"),
        irow("used by", ots.flatMap((t) => (t.properties || []).filter((p) => p.value_type === v.id).map((p) => `${esc(t.id)}.${esc(p.id)}`)).join(", ") || "no properties"),
        `<h4 class="og-fhd">Edit value type</h4>`,
        aForm("upsert-value-type", `<input type="hidden" name="def_id" value="${esc(v.id)}"><label class="og-fl">Name<input name="name" maxlength="200" value="${esc(v.name || "")}" required></label><label class="og-fl">Base<select name="base">${opt(vocab.base_value_types, v.base || "string")}</select></label><label class="og-fl">Enum values (comma-separated, if base=enum)<input name="enum_values" maxlength="2000" value="${esc((v.enum_values || []).join(", "))}"></label>`),
      ].join("");
    } else if (def.l) {
      const l = def.l; title = l.name || l.id;
      bodyHtml = [
        irow("id · name", `${formatRef(l.id)} · ${esc(l.name || "—")}`),
        irow("from → to", `<a href="${objectTypeLink(oid, l.from)}">${esc(l.from)}</a> → <a href="${objectTypeLink(oid, l.to)}">${esc(l.to)}</a>`),
        irow("cardinality", `<span class="om-pill muted">${esc(l.cardinality || "")}</span>`),
        ihint("Relationship browsing (walking instances across this link) is a disabled named gap — no object-instance graph plane is bound."),
        `<h4 class="og-fhd">Edit link type</h4>`,
        aForm("upsert-link-type", `<input type="hidden" name="def_id" value="${esc(l.id)}"><label class="og-fl">Name<input name="name" maxlength="200" value="${esc(l.name || "")}" required></label><label class="og-fl">From<select name="from" required>${opt(otOptions, l.from || "")}</select></label><label class="og-fl">To<select name="to" required>${opt(otOptions, l.to || "")}</select></label><label class="og-fl">Cardinality<select name="cardinality" required>${opt(vocab.link_cardinalities, l.cardinality || "")}</select></label>`),
      ].join("");
    } else if (def.a) {
      const a = def.a; title = a.name || a.id; const isFn = a.kind === "function";
      bodyHtml = [
        irow("id · name", `${formatRef(a.id)} · ${esc(a.name || "—")}`),
        irow("kind", `<span class="om-pill muted">${esc(a.kind || "")}</span>`),
        irow("applies to", a.applies_to ? `<a href="${defHref("object-type", a.applies_to, { section: "object-types" })}">${esc(a.applies_to)}</a>` : "—"),
        irow("status", "declaration only"),
        ihint(`${isFn ? "Function evaluation" : "Action execution"} is a disabled named gap — a declaration is not execution authority (no execution plane is bound).`),
        `<div class="og-iacts">${disabledSemanticAction({ label: isFn ? "Evaluate function" : "Execute action", reason: "declarations carry no execution authority — no execution plane exists on this surface" })}</div>`,
        `<h4 class="og-fhd">Edit ${isFn ? "function" : "action type"}</h4>`,
        aForm("upsert-action-type", `<input type="hidden" name="def_id" value="${esc(a.id)}"><label class="og-fl">Name<input name="name" maxlength="200" value="${esc(a.name || "")}" required></label><label class="og-fl">Kind<select name="kind">${opt(vocab.action_kinds, a.kind || "")}</select></label><label class="og-fl">Applies to<select name="applies_to"><option value="">— none —</option>${opt(otOptions, a.applies_to || "")}</select></label>`),
      ].join("");
    } else if (def.gap) {
      title = "Health gap";
      bodyHtml = [irow("readiness", hpill), irow("gap", esc(def.gap)), irow("revision", `rev ${esc(String(selected.revision || 1))}`), irow("remediate", `<a href="${mHref({ section: "object-types" })}">object types</a> · <a href="${mHref({ section: "properties" })}">properties</a>`)].join("");
    } else if (def.cm) {
      const cm2 = def.cm; title = cm2.name || cm2.id;
      bodyHtml = [
        irow("connector mapping", formatRef(cm2.ref || cm2.id)),
        irow("object type", cm2.object_type_id ? `<a href="${defHref("object-type", cm2.object_type_id, { section: "object-types" })}">${esc(cm2.object_type_id)}</a>` : "—"),
        irow("mapped properties", `${(cm2.health || {}).mapped_properties ?? (cm2.field_mappings || []).length} of ${(cm2.health || {}).total_properties ?? "—"}`),
        irow("health", esc((cm2.health || {}).status || "—")),
        irow("open in", `${sourcesLink(cm2.data_source_id) ? `<a href="${sourcesLink(cm2.data_source_id)}">Data Connection</a> · ` : ""}<a href="${pipelineNodeLink(oid, "mapping")}">Pipeline</a>`),
      ].join("");
    } else if (def.pv2) {
      const v3 = def.pv2; title = v3.name || v3.id;
      bodyHtml = [
        irow("policy-bound view", formatRef(v3.ref || v3.id)),
        irow("operations", (v3.allowed_operations || []).map(formatRef).join(" ") || "—"),
        irow("subjects", (v3.authority_subjects || []).map(formatRef).join(" ") || "—"),
        irow("open in", `${v3.connector_mapping_id ? `<a href="${managerResourceLink(oid, "connector-mapping", v3.connector_mapping_id)}">mapping</a> · ` : ""}<a href="${pipelineNodeLink(oid, "policy")}">Pipeline</a>`),
      ].join("");
    } else if (def.pj) {
      const p3 = def.pj; title = p3.name || p3.id;
      bodyHtml = [
        irow("projection", formatRef(p3.ref || p3.id)),
        irow("visible properties", (p3.visible_properties || []).map(formatRef).join(" ") || "—"),
        irow("open in", `<a href="${explorerLink({ ontology: oid })}">Explorer</a> · <a href="${pipelineNodeLink(oid, "projection")}">Pipeline</a>`),
      ].join("");
    } else if (def.ms2) {
      const s3 = def.ms2; title = s3.object_type_id || s3.id;
      bodyHtml = [
        irow("materialized set", formatRef(s3.ref || s3.id)),
        irow("objects", `<b>${s3.count ?? 0}</b>`),
        irow("open in", `<a href="${objectSetLink(oid, s3.id)}">Explorer</a> · <a href="${lineageLink(oid, s3.id)}">Lineage</a> · <a href="${vertexLink(oid, s3.id)}">Vertex</a> · <a href="${provenanceSetLink(s3.id)}">Provenance</a> · <a href="${pipelineNodeLink(oid, "materialized")}">Pipeline</a>`),
      ].join("");
    }
    return `<div class="og-inspector" data-testid="og-inspector"><div class="og-ihd"><b>${esc(title)}</b><span class="og-ikind">${esc(selD.kind)}</span></div><div class="og-ibody">${crumb}${bodyHtml}${openSubstrate}</div></div>`;
  }
  // Create-ontology form (section=create) — the one authoring lane without a selected ontology.
  const createPane = section === "create" ? `<div class="og-inspector" data-testid="og-inspector"><div class="og-ihd"><b>Create ontology</b></div><div class="og-ibody">${ihint("A new DomainOntology draft (revision 1) with a create receipt. Add typed definitions after it exists.")}<form class="og-form" method="post" action="/__ioi/ontology/manager/actions/create-ontology">${sel.embed ? `<input type="hidden" name="embed" value="1">` : ""}<label class="og-fl">Domain<input name="domain" maxlength="120" placeholder="e.g. lending" required></label><label class="og-fl">Version<input name="version" maxlength="60" placeholder="0.1.0"></label><label class="og-fl">Description<input name="description" maxlength="2000"></label><button class="og-save" type="submit">Create</button></form></div></div>` : "";
  const aside = createPane || (def ? inspectorFor() : "");

  // Result banner (#ap-result — the runtime's redirect anchor). Renders only after an action.
  const bn = O.banner || {};
  const banner = bn.acted && bn.receipt
    ? `<div id="ap-result" class="og-banner og-ok" tabindex="-1"><b>${esc(bn.acted)}</b> recorded${bn.result ? ` — <b>${esc(bn.result)}</b>` : ""} · receipt <code>${esc(bn.receipt)}</code> · <a href="/__ioi/work-ledger">proof stream</a></div>`
    : bn.refused ? `<div id="ap-result" class="og-banner og-no" tabindex="-1">refused: <code>${esc(bn.refused)}</code>${bn.reason ? ` — ${esc(bn.reason)}` : ""} · <b>state unchanged</b></div>` : "";
  const filterNote = q && def && !def.missing ? ihint(`Filtered by “${esc(q)}”. <a href="${defHref(selD.kind, selD.id)}">Clear filter</a> to see the full list.`) : "";
  const searchForm = section ? `<form class="og-searchbody" method="GET" action="/__ioi/ontology/manager">${RET}${section ? `<input type="hidden" name="section" value="${esc(section)}">` : ""}${selD.kind ? `<input type="hidden" name="definitionKind" value="${esc(selD.kind)}"><input type="hidden" name="definitionId" value="${esc(selD.id)}">` : ""}<input name="q" value="${esc(q)}" placeholder="Search resources…" aria-label="Search typed definitions (live)"><button type="submit">Filter</button></form>` : "";

  const body = `<main class="og-body" role="main">${banner}${badSection ? ihint(`Unknown section — showing Discover.`, true) : ""}${searchForm}${filterNote}${selected ? `
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

  const asideCss = `
    .og-searchbody{display:flex;gap:6px;margin:0 0 14px;max-width:460px}
    .og-searchbody input{flex:1;border:1px solid #d3d8de;border-radius:4px;padding:6px 9px;font:inherit;font-size:13px}
    .og-searchbody button{border:1px solid #d3d8de;border-radius:4px;background:#f7f8f8;font:inherit;font-size:13px;padding:0 12px;cursor:pointer}
    .og-banner{margin:0 0 14px;padding:9px 12px;border-radius:6px;font-size:12.5px;line-height:1.5;outline:none}
    .og-banner code{font-size:10.5px;word-break:break-all}
    .og-banner.og-ok{border:1px solid #8fdcb6;background:#eafaf1;color:#0e6b41}
    .og-banner.og-no{border:1px solid #e8c48d;background:#fdf7ec;color:#935610}
    .og-selcard{border-color:#2d72d2!important;box-shadow:0 0 0 2px rgba(45,114,210,.3)!important}
    .og-drow{cursor:pointer}.og-drow:hover{background:#f6f7f9}.og-drow.og-selrow{background:#f3f8ff;box-shadow:inset 2px 0 0 #2d72d2}
    .og-dlink{color:inherit}
    .og-inspectorwrap{flex:0 0 360px;width:360px;border-left:1px solid #dce0e5;background:#fff;overflow-y:auto}
    .og-inspector{display:flex;flex-direction:column}
    .og-ihd{display:flex;align-items:center;gap:8px;padding:12px 14px 10px;border-bottom:1px solid #eef0f2}
    .og-ihd b{font-size:14px;color:#1c2127}.og-ikind{font-size:11px;color:#5f6b7c;text-transform:uppercase;letter-spacing:.4px}
    .og-ibody{padding:12px 14px;font-size:12px}
    .ioi-sem-breadcrumb{font-size:12px;color:#5f6b7c;margin:0 0 12px}span.ioi-sem-crumb{color:#1c2127}
    .og-irow{display:flex;gap:10px;font-size:12px;line-height:15.4297px;padding:0 0 8px}
    .og-ik{color:#5f6b7c;width:118px;flex:0 0 118px}.og-iv{color:#1c2127;min-width:0;word-break:break-word}
    .ioi-ref{font-family:ui-monospace,monospace;font-size:10.5px;background:#f1f3f6;border-radius:3px;padding:1px 4px;word-break:break-all}
    .og-ihint{margin:6px 0 10px;padding:8px 10px;border:1px solid #e5e7eb;border-radius:6px;background:#f7f8fa;color:#5b6270;font-size:11.5px;line-height:1.55}
    .og-warnhint{border-color:#e8c48d;background:#fdf7ec;color:#935610}
    .og-itable{border-collapse:collapse;width:100%;font-size:11.5px;margin:0 0 10px}.og-itable th{text-align:left;color:#7b8494;font-weight:600;padding:3px 8px 3px 0;border-bottom:1px solid #e2e4e8}.og-itable td{padding:3px 8px 3px 0;border-bottom:1px solid #f0f1f4}
    .og-fhd{font-size:12px;margin:14px 0 8px;color:#1c2127}
    .og-form{display:flex;flex-direction:column;gap:8px;border:1px solid #e5e7eb;border-radius:8px;padding:10px;background:#fbfcfd;margin:0 0 10px}
    .og-fl{display:flex;flex-direction:column;gap:3px;font-size:11px;color:#5f6b7c}
    .og-fl input,.og-fl select{border:1px solid #d3d8de;border-radius:4px;padding:5px 8px;font:inherit;font-size:12.5px;color:#1c2127}
    .og-fc{display:flex;align-items:center;gap:6px;font-size:12px;color:#5f6b7c}
    .og-save{align-self:flex-start;border:1px solid #2f6fd8;background:#2f6fd8;color:#fff;border-radius:4px;font:inherit;font-size:12.5px;font-weight:600;padding:6px 14px;cursor:pointer}
    .og-iacts{margin:8px 0}.ioi-cmd-disabled{display:inline-flex;align-items:center;height:24px;padding:0 8px;border:1px solid #d3d8de;border-radius:4px;background:#f7f8f8;color:#8f99a8;font:inherit;font-size:12px;cursor:not-allowed}
    .og-sublink{display:inline-block;margin-top:10px;font-size:12px}`;
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Ontology Manager</title><style>${css}${aside ? asideCss : ""}</style></head>
    <body><div class="og-shell">${globalRail}<div class="og-main">${header}<div class="og-work">${appRail}${body}${aside ? `<aside class="og-inspectorwrap">${aside}</aside>` : ""}</div></div></body></html>`;
}

