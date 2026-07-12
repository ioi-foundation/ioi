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
import { escHtml, parseSelection, selectionQuery, inspectorShell, trayShell, disabledCommand, proofLink } from "../kit.mjs";
import { managerLink, managerResourceLink, objectTypeLink, objectSetLink, sourcesLink, lineageLink, vertexLink, provenanceSetLink, semanticBreadcrumb } from "../ontology-context.mjs";

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
  const [o, ds, cm, pv, tr, op, lp, mr, cs, ms, cn] = await Promise.all([
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
    J("/v1/hypervisor/connectors"),
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
    connectors: cn.connectors || [],
  };
}

export function render(model, ctx) {
  // The URL is the single source of interaction truth (#66): selection (ontology/node/output),
  // tray tab, right-panel choice, and persisted view state (tray/legend collapse, hidden legend
  // categories) all parse here and fail CLOSED to defaults on unknown values.
  const sel = parseSelection(ctx.url, ["ontology", "node", "tab", "panel", "output", "hide", "tray", "legend", "pane", "run", "session", "challenge_policy", "challenge_request"]);
  sel.banner = parseSelection(ctx.url, ["acted", "receipt", "refused", "reason", "record", "result"]);
  return renderPipelineBuilder(model, sel, ctx.embed);
}

// The Pipeline command table (command-discipline contract): every command is either an ENABLED
// action carrying its route + expected proof, or DISABLED with a reason naming exactly what is
// missing — never a blank href, never a silent no-op. Build stays DISABLED: materialization is
// the governed ODK ladder (MaterializingRun citing a CapabilityLeasePlan → wallet-approved lease
// → sealed ConnectorSession → execute) — a multi-step, wallet-gated authority, not a single safe
// call; a POST that pretended otherwise would cross an authority line this surface doesn't own.
// The header renders FROM this table, so the UI cannot drift from the declared command model.
// The Pipeline COMMAND table (command-discipline contract, #58/#66): every header command is an
// ENABLED navigation carrying its route + expected proof, or DISABLED with the reason naming
// exactly what is missing. Build (#67) is now the governed workflow entry — a read navigation to
// the review pane; every MUTATION inside the workflow is a declared runtime action below.
export const commands = [
  { key: "preview", label: "Preview", enabled: true, kind: "read_navigation", route: "/__ioi/pipeline?node=materialized&tab=preview", proof: "the materialized set's real rows + provenance refs render in the tray (read-only — no authority crossed)" },
  { key: "build", label: "Build", enabled: true, kind: "read_navigation", route: "/__ioi/pipeline?pane=build", authority: { plane: "odk.materializing-runs", operation: "the governed ladder — MaterializingRun → wallet-approved lease → sealed ConnectorSession → bounded execute, each stage a declared receipted action" }, proof: "the review pane derives every stage from existing records; header renders it DISABLED with the missing rungs named until the ladder is coherent-ready" },
  { key: "schedule", label: "Schedule", enabled: false, authority: null, reason: "no pipeline scheduler exists yet — a named gap (author + run via a materializing run)" },
  { key: "deploy", label: "Deploy", enabled: false, authority: null, reason: "no pipeline deploy exists yet — a named gap" },
];

// ---- Governed Build workflow (#67) — the runtime MUTATION descriptors. Every stage is a
// declared action over an EXISTING daemon authority (no PipelineBuild plane exists); the wallet
// grant rides ONE bounded opaque field (fieldMax covers external wallets' larger grants), is
// forwarded to the daemon exactly once, and is never persisted, logged, or echoed. State is
// never a URL claim: every handler re-reads the record and the daemon's own state machine is the
// idempotency backstop (already_obtained / terminal_immutable / already_registered).
const MRUN_RECEIPT = "ioi.hypervisor.odk.materializing-run-receipt.v1";
const SESS_RECEIPT = "ioi.hypervisor.odk.connector-session-receipt.v1";
const GRANT_FIELD_MAX = 8192;
const bAct = (id, route, fields, receipt, extra) => ({ id, method: "POST", route, fields: [...fields, "ontology", "return"], context: ["ontology"], authority: extra && extra.authority ? extra.authority : { plane: "odk.materializing-runs", operation: extra && extra.operation ? extra.operation : "" }, receipt, confirm: !!(extra && extra.confirm), fieldMax: extra && extra.fieldMax, success: "return-to-surface", refusal: "typed-banner" });
export const actions = [
  bAct("admit-run", "/actions/admit-run", ["capability_lease_plan_id", "name"], MRUN_RECEIPT, { operation: "POST /v1/hypervisor/odk/materializing-runs" }),
  bAct("submit-lease-grant", "/:id/submit-lease-grant", ["wallet_approval_grant"], MRUN_RECEIPT, { operation: "POST /v1/hypervisor/odk/materializing-runs/:id/acquire-lease", fieldMax: GRANT_FIELD_MAX }),
  bAct("cancel-run", "/:id/cancel-run", [], MRUN_RECEIPT, { operation: "POST /v1/hypervisor/odk/materializing-runs/:id/cancel", confirm: true }),
  bAct("release-lease", "/:id/release-lease", [], MRUN_RECEIPT, { operation: "POST /v1/hypervisor/odk/materializing-runs/:id/release-lease", confirm: true }),
  bAct("admit-session", "/:id/admit-session", ["connector_id", "name"], SESS_RECEIPT, { authority: { plane: "odk.connector-sessions", operation: "POST /v1/hypervisor/odk/connector-sessions" } }),
  bAct("submit-session-grant", "/:id/submit-session-grant", ["connector_session_id", "wallet_approval_grant"], SESS_RECEIPT, { authority: { plane: "odk.connector-sessions", operation: "POST /v1/hypervisor/odk/connector-sessions/:id/open" }, fieldMax: GRANT_FIELD_MAX }),
  bAct("release-session", "/:id/release-session", ["connector_session_id"], SESS_RECEIPT, { authority: { plane: "odk.connector-sessions", operation: "POST /v1/hypervisor/odk/connector-sessions/:id/release" }, confirm: true }),
  bAct("execute", "/:id/execute", ["connector_session_id", "limit"], MRUN_RECEIPT, { operation: "POST /v1/hypervisor/odk/materializing-runs/:id/execute", confirm: true }),
];

// One typed result, always. Receipts come from the RECORD's own history (the daemon receipts
// every transition, including refusals); a challenge (403) is returned as a typed refusal whose
// redirect carries ONLY the two public commitment hashes — the pane re-renders the full
// challenge from the same plan truth the daemon derived it from. The grant blob exists in this
// scope for the single forward POST and is never referenced afterwards.
export async function handleAction({ action, id, fields, daemon }) {
  const J = async (method, path, body) => {
    const r = await fetch(`${daemon}${path}`, { method, headers: { "content-type": "application/json" }, body: body === undefined ? undefined : JSON.stringify(body) }).then(async (x) => ({ status: x.status, j: await x.json().catch(() => ({})) })).catch(() => null);
    return r;
  };
  const ont = fields.ontology || "";
  const buildBack = (params) => `/__ioi/pipeline?${new URLSearchParams({ ontology: ont, pane: "build", ...params }).toString()}`;
  const lastReceipt = (rec, ops) => {
    const h = (rec && rec.history) || [];
    for (let i = h.length - 1; i >= 0; i--) if (ops.includes(h[i].op) && h[i].receipt_ref) return h[i].receipt_ref;
    return "";
  };
  const refuse = (code, message, redirect) => ({ kind: "refusal", code, message: String(message || "").slice(0, 200), redirect });
  const fail = (code, message, redirect) => ({ kind: "failure", code, message: String(message || "").slice(0, 200), redirect });
  const challengeRefusal = (body, params) => {
    const ap = (body && body.approval) || {};
    // Public commitments only — hashes name WHAT to sign; the grant itself never appears here.
    const qp = { ...params };
    if (/^sha256:[0-9a-f]{64}$/.test(ap.policy_hash || "")) qp.challenge_policy = ap.policy_hash;
    if (/^sha256:[0-9a-f]{64}$/.test(ap.request_hash || "")) qp.challenge_request = ap.request_hash;
    return refuse((body && body.reason) || "wallet_authority_required", (body && body.message) || "wallet authority required", buildBack(qp));
  };
  const parseGrant = (raw) => {
    if (!raw) return { grant: undefined };
    try {
      const g = JSON.parse(raw);
      if (!g || typeof g !== "object" || Array.isArray(g)) return { err: "the pasted grant is not a JSON object" };
      return { grant: g };
    } catch { return { err: "the pasted grant is not valid JSON (was it truncated?)" }; }
  };

  if (action.id === "admit-run") {
    const plan = String(fields.capability_lease_plan_id || "");
    if (!plan) return refuse("plan_required", "no capability lease plan named — the ladder review names the plan", buildBack({}));
    // Idempotency precheck: a non-terminal run already citing this plan is RESUMED, never duplicated.
    const runs = await J("GET", "/v1/hypervisor/odk/materializing-runs");
    const existing = ((runs && runs.j.materializing_runs) || []).find((r) => r.capability_lease_plan_id === plan && ["planned", "lease_obtained"].includes(r.status));
    if (existing) return refuse("run_already_admitted", `run ${existing.id} already cites this plan — resuming it instead of minting a duplicate`, buildBack({ run: existing.id }));
    const r = await J("POST", "/v1/hypervisor/odk/materializing-runs", { capability_lease_plan_id: plan, name: String(fields.name || "governed build") });
    if (!r) return fail("daemon_unavailable", "the daemon did not answer — nothing was admitted");
    const rec = r.j.materializing_run;
    if (r.status >= 400 || !rec) return refuse((r.j.error && r.j.error.code) || "run_admission_refused", (r.j.error && r.j.error.message) || r.j.reason, buildBack({}));
    const receipt = lastReceipt(rec, ["created"]);
    if (!receipt) return fail("receipt_missing", "admission returned no receipt — failing closed");
    return { kind: "success", status: rec.status, created: rec.id, receipt_ref: receipt, redirect: buildBack({ run: rec.id }) };
  }

  if (action.id === "submit-lease-grant") {
    const { grant, err } = parseGrant(fields.wallet_approval_grant);
    if (err) return refuse("grant_invalid_json", err, buildBack({ run: id }));
    const r = await J("POST", `/v1/hypervisor/odk/materializing-runs/${encodeURIComponent(id)}/acquire-lease`, grant ? { wallet_approval_grant: grant } : {});
    if (!r) return fail("daemon_unavailable", "the daemon did not answer — state unchanged");
    if (r.status === 403) return challengeRefusal(r.j, { run: id });
    const rec = r.j.materializing_run;
    if (r.status >= 400 || !rec) return refuse((r.j.error && r.j.error.code) || "lease_refused", (r.j.error && r.j.error.message) || r.j.reason, buildBack({ run: id }));
    const receipt = lastReceipt(rec, ["lease_obtained"]);
    if (!receipt) return fail("receipt_missing", "lease obtained without a receipt — failing closed");
    return { kind: "success", status: rec.status, receipt_ref: receipt, redirect: buildBack({ run: id }) };
  }

  if (action.id === "cancel-run" || action.id === "release-lease") {
    const lane = action.id === "cancel-run" ? "cancel" : "release-lease";
    const r = await J("POST", `/v1/hypervisor/odk/materializing-runs/${encodeURIComponent(id)}/${lane}`);
    if (!r) return fail("daemon_unavailable", "the daemon did not answer — state unchanged");
    const rec = r.j.materializing_run;
    if (r.status >= 400 || !rec) return refuse((r.j.error && r.j.error.code) || "lifecycle_refused", (r.j.error && r.j.error.message) || r.j.reason, buildBack({ run: id }));
    const receipt = lastReceipt(rec, ["cancelled", "lease_released"]);
    if (!receipt) return fail("receipt_missing", "the transition returned no receipt — failing closed");
    return { kind: "success", status: rec.status, receipt_ref: receipt, redirect: buildBack({ run: id }) };
  }

  if (action.id === "admit-session") {
    const runs = await J("GET", "/v1/hypervisor/odk/connector-sessions");
    const existing = ((runs && runs.j.connector_sessions) || []).find((c) => c.materializing_run_id === id && ["requested", "session_obtained"].includes(c.status));
    if (existing) return refuse("session_already_admitted", `session ${existing.id} already exists for this run — resuming it`, buildBack({ run: id, session: existing.id }));
    const r = await J("POST", "/v1/hypervisor/odk/connector-sessions", { materializing_run_id: id, connector_id: String(fields.connector_id || ""), name: String(fields.name || "governed build session") });
    if (!r) return fail("daemon_unavailable", "the daemon did not answer — nothing was admitted");
    const rec = r.j.connector_session;
    if (r.status >= 400 || !rec) return refuse((r.j.error && r.j.error.code) || "session_admission_refused", (r.j.error && r.j.error.message) || r.j.reason, buildBack({ run: id }));
    const receipt = lastReceipt(rec, ["created"]);
    if (!receipt) return fail("receipt_missing", "session admission returned no receipt — failing closed");
    return { kind: "success", status: rec.status, created: rec.id, receipt_ref: receipt, redirect: buildBack({ run: id, session: rec.id }) };
  }

  if (action.id === "submit-session-grant") {
    const sid = String(fields.connector_session_id || "");
    if (!sid) return refuse("session_required", "no session named", buildBack({ run: id }));
    const { grant, err } = parseGrant(fields.wallet_approval_grant);
    if (err) return refuse("grant_invalid_json", err, buildBack({ run: id, session: sid }));
    const r = await J("POST", `/v1/hypervisor/odk/connector-sessions/${encodeURIComponent(sid)}/open`, grant ? { wallet_approval_grant: grant } : {});
    if (!r) return fail("daemon_unavailable", "the daemon did not answer — state unchanged");
    if (r.status === 428) return refuse((r.j.reason) || "credential_unresolved", (r.j.message) || "the connector needs a resolvable sealed credential before this crossing", buildBack({ run: id, session: sid }));
    if (r.status === 403) return challengeRefusal(r.j, { run: id, session: sid });
    const rec = r.j.connector_session;
    if (r.status >= 400 || !rec) return refuse((r.j.error && r.j.error.code) || "session_open_refused", (r.j.error && r.j.error.message) || r.j.reason, buildBack({ run: id, session: sid }));
    const receipt = lastReceipt(rec, ["session_obtained"]);
    if (!receipt) return fail("receipt_missing", "session opened without a receipt — failing closed");
    return { kind: "success", status: rec.status, receipt_ref: receipt, redirect: buildBack({ run: id, session: sid }) };
  }

  if (action.id === "release-session") {
    const sid = String(fields.connector_session_id || "");
    const r = await J("POST", `/v1/hypervisor/odk/connector-sessions/${encodeURIComponent(sid)}/release`);
    if (!r) return fail("daemon_unavailable", "the daemon did not answer — state unchanged");
    const rec = r.j.connector_session;
    if (r.status >= 400 || !rec) return refuse((r.j.error && r.j.error.code) || "release_refused", (r.j.error && r.j.error.message) || r.j.reason, buildBack({ run: id, session: sid }));
    const receipt = lastReceipt(rec, ["session_released"]);
    if (!receipt) return fail("receipt_missing", "release returned no receipt — failing closed");
    return { kind: "success", status: rec.status, receipt_ref: receipt, redirect: buildBack({ run: id }) };
  }

  if (action.id === "execute") {
    const sid = String(fields.connector_session_id || "");
    const limit = Math.max(1, Math.min(500, parseInt(fields.limit, 10) || 100));
    const r = await J("POST", `/v1/hypervisor/odk/materializing-runs/${encodeURIComponent(id)}/execute`, { connector_session_id: sid, limit });
    if (!r) return fail("daemon_unavailable", "the daemon did not answer — state unchanged");
    if (r.status === 428) return refuse(r.j.reason || (r.j.error && r.j.error.code) || "credential_unresolved", r.j.message || (r.j.error && r.j.error.message), buildBack({ run: id, session: sid }));
    const rec = r.j.materializing_run;
    if (r.status >= 400 || !rec) return refuse((r.j.error && r.j.error.code) || r.j.reason || "execution_refused", (r.j.error && r.j.error.message) || r.j.message || r.j.reason, buildBack({ run: id, session: sid }));
    const receipt = lastReceipt(rec, ["materialized_output_registered"]);
    if (!receipt) return fail("receipt_missing", "execution registered no receipt — failing closed");
    // Success lands ON the result: materialized node selected, Preview tab open, real rows visible.
    return { kind: "success", status: rec.status, receipt_ref: receipt, redirect: `/__ioi/pipeline?${new URLSearchParams({ ontology: ont, node: "materialized", tab: "preview" }).toString()}` };
  }

  return refuse("action_unknown", `undeclared stage '${action.id}'`);
}

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
function renderPipelineBuilder(lists, sel, embed) {
  const selectedId = sel.ontology || "", nodeParam = sel.node || "";
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
  const connectors = Array.isArray(lists.connectors) ? lists.connectors : [];
  const dsIds = new Set(maps.map((m) => m.data_source_id).filter(Boolean));
  const dsources = (lists.data_sources || []).filter((d) => dsIds.has(d.source_id));
  const instances = osets.reduce((a, s) => a + (s.count || 0), 0);
  const anyReady = (arr, pred) => arr.filter(pred).length;
  // First-record picks — shared by the typed-edge derivation AND the node detail panels.
  const d0 = dsources[0], m0 = maps[0], v0 = views[0], r0 = truns[0], pl0 = plans[0], st0 = osets[0];
  const mr0 = mruns.find((x) => ["lease_obtained", "executed"].includes(x.status)) || mruns[0];
  const ssn0 = sessions.find((x) => x.status === "session_obtained") || sessions[0];

  // The pipeline nodes, in ODK-ladder order. Each node: real daemon state → live / declared / missing.
  // key = the node's URL identity (?node=<key>) for the selection lane.
  const mk = (key, icon, label, kind, n, live, declared, count, detail, pane) => ({ key, icon, label, kind, n, cls: n === 0 ? "missing" : live ? "live" : declared ? "declared" : "declared", count, detail, pane });
  const nodes = [
    mk("datasource", "🌐", "Datasource", "input", dsources.length, dsources.length > 0, true, dsources.length, dsources.map((d) => d.name || d.source_id).slice(0, 2).join(", "), "data"),
    mk("mapping", "🔗", "Object mapping", "transform", maps.length, anyReady(maps, (m) => (m.health || {}).status === "ready") > 0, true, maps.length, "source fields → typed properties", "resources"),
    mk("policy", "🛡", "Policy gate", "transform", views.length, anyReady(views, (v) => (v.health || {}).status === "ready") > 0, true, views.length, "capability envelope", "resources"),
    mk("transform", "📋", "Transform plan", "transform", truns.length, anyReady(truns, (r) => r.status === "dry_run_ready") > 0, true, truns.length, "dry-run validated", "resources"),
    mk("projection", "🔭", "Read projection", "transform", projs.length, anyReady(projs, (p) => p.status === "ready") > 0, true, projs.length, "explorer/search shape", "resources"),
    mk("lease", "🎟", "Lease + session", "authority", plans.length, anyReady(mruns, (r) => ["lease_obtained", "executed"].includes(r.status)) > 0 && anyReady(sessions, (c) => c.status === "session_obtained") > 0, plans.length > 0, plans.length, `${anyReady(mruns, (r) => ["lease_obtained", "executed"].includes(r.status))} lease · ${anyReady(sessions, (c) => c.status === "session_obtained")} session`, "resources"),
    mk("materialized", "📦", "Materialized objects", "output", osets.length, instances > 0, osets.length > 0, instances, `${instances} object instance${instances === 1 ? "" : "s"}`, "explorer"),
  ];
  // ---- Node selection (functional-runtime wave): the URL is the selection's single source of
  // truth (kit parseSelection/selectionQuery). Default = datasource, the first ladder stage; an
  // explicit ?node= ALSO swaps the right panel to that node's inspector and the tray to its
  // proof. An unknown ?node= fails CLOSED to the default with an honest note — never a crash.
  // The pixel gate captures the bare route (no ?node=), whose certified chrome stays byte-stable:
  // the selected-card highlight lives in the canvas, the excluded live body.
  const nodeValid = nodes.some((n) => n.key === nodeParam);
  const selNodeKey = selected ? (nodeValid ? nodeParam : "datasource") : "";
  const inspectorMode = !!(selected && nodeParam);
  const invalidNode = !!(nodeParam && !nodeValid);
  const nodeHref = (key) => selectionQuery("/__ioi/pipeline", { ontology: oid, node: key });
  const missingRungs = nodes.filter((n) => n.cls === "missing").map((n) => n.label);
  // ---- Interaction state (#66) — every dimension fails CLOSED with a visible note, never a crash.
  const TRAY_TABS = ["selection", "preview", "suggestions", "warnings"];
  const PANELS = ["outputs", "search", "tree"];
  const outputSel = sel.output && projs.some((p) => p.id === sel.output) ? sel.output : "";
  const invalidOutput = !!(sel.output && !outputSel);
  const hasSelection = inspectorMode || !!outputSel;
  let trayTabKey = TRAY_TABS.includes(sel.tab) ? sel.tab : "selection";
  const invalidTab = !!(sel.tab && !TRAY_TABS.includes(sel.tab));
  const previewWithoutSel = trayTabKey === "preview" && !hasSelection;
  if (previewWithoutSel) trayTabKey = "selection"; // the Preview tab exists only on selection (reference behavior)
  const panelKey = PANELS.includes(sel.panel) ? sel.panel : "outputs";
  const invalidPanel = !!(sel.panel && !PANELS.includes(sel.panel));
  const CATEGORY_KEYS = ["input", "clean", "calc", "output"];
  const hiddenCats = (sel.hide || "").split(",").map((x) => x.trim()).filter((x) => CATEGORY_KEYS.includes(x));
  const trayCollapsed = sel.tray === "0";
  const legendCollapsed = sel.legend === "0";
  // ---- Governed Build (#67): the URL carries ONLY record ids + the pane name; the STAGE is a
  // pure function of record status re-read from daemon truth on every render (refresh resumes
  // exactly; a stale/foreign id fails closed to review with a visible note).
  const paneKey = sel.pane === "build" ? "build" : "";
  const invalidBuildPane = !!(sel.pane && !paneKey);
  const runRec = sel.run ? mruns.find((r) => r.id === sel.run) || null : null;
  const invalidRun = !!(sel.run && !runRec);
  const sessRec = sel.session ? sessions.find((c) => c.id === sel.session && (!runRec || c.materializing_run_id === runRec.id)) || null : null;
  const invalidSession = !!(sel.session && !sessRec);
  const runSel = runRec ? runRec.id : "";
  const sessSel = sessRec ? sessRec.id : "";
  const setForRun = runRec ? osets.find((x) => x.materializing_run_ref === runRec.ref) || null : null;
  const RUN_TERMINAL = ["lease_released", "cancelled"];
  const buildStage = !runRec ? "review"
    : RUN_TERMINAL.includes(runRec.status) || (sessRec && ["session_released", "cancelled"].includes(sessRec.status) && runRec.status !== "executed") ? "ended"
    : runRec.status === "planned" ? "lease"
    : runRec.status === "lease_obtained" && !sessRec ? "session"
    : runRec.status === "lease_obtained" && sessRec.status === "requested" ? "open"
    : runRec.status === "lease_obtained" && sessRec.status === "session_obtained" ? "execute"
    : runRec.status === "executed" ? "done"
    : "review";
  const resumableRun = mruns.find((r) => pl0 && r.capability_lease_plan_id === pl0.id && ["planned", "lease_obtained"].includes(r.status)) || null;
  // Canonical current-state href builder — links preserve every non-default dimension, so tab
  // switches keep the selection, panel swaps keep the tab, and refresh reproduces the view.
  const state = { ontology: oid };
  if (inspectorMode) state.node = selNodeKey;
  if (outputSel) state.output = outputSel;
  if (trayTabKey !== "selection") state.tab = trayTabKey;
  if (panelKey !== "outputs") state.panel = panelKey;
  if (hiddenCats.length) state.hide = hiddenCats.join(",");
  if (trayCollapsed) state.tray = "0";
  if (legendCollapsed) state.legend = "0";
  if (paneKey) state.pane = paneKey;
  if (runSel) state.run = runSel;
  if (sessSel) state.session = sessSel;
  const stateHref = (over) => selectionQuery("/__ioi/pipeline", { ...state, ...over });
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

  // ---- Node inspectors (functional-runtime wave) — every value below is an already-loaded
  // daemon record; nothing is fetched twice and nothing is fabricated. Credential material NEVER
  // renders: the datasource endpoint is reduced to its ORIGIN, and the lease/session inspector
  // renders status booleans + refs only (the plan's own lease.credential_material=false is the
  // boundary, shown as such). Empty stages render the honest missing-contract state.
  const irow = (k, v) => `<div class="pb-irow"><span class="pb-ik">${esc(k)}</span><span class="pb-iv">${v}</span></div>`;
  const icode = (v) => `<code class="pb-icode">${esc(v)}</code>`;
  const ihint = (h) => `<div class="pb-ihint">${h}</div>`;
  const irefs = (refs) => (refs || []).length ? refs.slice(0, 4).map(icode).join(" ") : "—";
  const safeOrigin = (e) => { try { const u = new URL(e); return `${esc(u.protocol)}//${esc(u.host)}/… <span class="pb-redact">(path redacted)</span>`; } catch { return "(endpoint redacted)"; } };
  const emptyStage = (label) => ihint(`No ${esc(label)} record exists on this pipeline yet — an honest missing contract, not an error. Author the stage in the <a href="${managerLink({ ontology: oid })}">Ontology Manager</a> (<a href="/__ioi/odk?ontology=${enc(oid)}">ODK substrate</a>).`);
  const trayTable = (heads, rowsArr) => `<table class="pb-table"><thead><tr>${heads.map((h) => `<th>${esc(h)}</th>`).join("")}</tr></thead><tbody>${rowsArr.length ? rowsArr.map((row) => `<tr>${row.map((c) => `<td>${c}</td>`).join("")}</tr>`).join("") : `<tr><td colspan="${heads.length}" class="pb-empty-cell">No records for this stage yet.</td></tr>`}</tbody></table>`;
  function nodeInspector(key) {
    const d = d0, m = m0, v = v0, r = r0, pl = pl0, st = st0, mr = mr0, ssn = ssn0;
    switch (key) {
      case "datasource": return {
        title: "Datasource", sub: d ? (d.source_ref || d.source_id || "") : "no record",
        body: d ? [
          irow("records", `${dsources.length} source${dsources.length === 1 ? "" : "s"} mapped into this pipeline${dsources.length > 1 ? " · showing first" : ""}`),
          irow("name", esc(d.name || "—")),
          irow("kind", esc(d.kind || "—")),
          irow("endpoint", safeOrigin(d.endpoint || "")),
          irow("credential posture", icode(d.credential_posture || "—")),
          irow("lifecycle", esc((d.lifecycle || {}).status || "—")),
          irow("receipts", irefs(d.receipt_refs)),
          ihint(`Ingestion boundary — wired: <b>${(d.ingestion || {}).wired === true}</b>. ${esc((d.ingestion || {}).note || "")}`),
          irow("proof", proofLink({ href: "/__ioi/work-ledger", label: "work ledger" })),
          irow("open in", `${sourcesLink(d.source_id) ? `<a href="${sourcesLink(d.source_id)}">Data Connection</a>` : "—"}${maps.filter((x) => x.data_source_id === d.source_id).slice(0, 3).map((x) => ` · <a href="${managerResourceLink(oid, "connector-mapping", x.id)}">mapping ${esc(x.id)}</a>`).join("")}`),
        ].join("") : emptyStage("Datasource"),
        trayTitle: "Datasource — declaration boundary",
        tray: trayTable(["source", "kind", "endpoint (origin)", "credential posture", "lifecycle"],
          dsources.slice(0, 8).map((x) => [esc(x.name || x.source_id), esc(x.kind || ""), safeOrigin(x.endpoint || ""), icode(x.credential_posture || ""), esc((x.lifecycle || {}).status || "")])),
      };
      case "mapping": return {
        title: "Object mapping", sub: m ? (m.ref || `connector-mapping://${m.id}`) : "no record",
        body: m ? [
          irow("records", `${maps.length} mapping${maps.length === 1 ? "" : "s"}${maps.length > 1 ? " · showing first" : ""}`),
          irow("name", esc(m.name || "—")),
          irow("object type", icode(m.object_type_id || "—")),
          irow("key mapping", m.key_mapping ? `${icode(m.key_mapping.property_id)} ← ${icode(m.key_mapping.source_field)} <span class="pb-redact">(${esc(m.key_mapping.source_type || "")})</span>` : "—"),
          irow("title mapping", m.title_mapping ? `${icode(m.title_mapping.property_id)} ← ${icode(m.title_mapping.source_field)}` : "—"),
          irow("mapped properties", `${(m.health || {}).mapped_properties ?? (m.field_mappings || []).length} of ${(m.health || {}).total_properties ?? "—"}`),
          irow("field mappings", (m.field_mappings || []).length ? m.field_mappings.map((f) => `${icode(f.property_id)} ← ${icode(f.source_field)}`).join(" · ") : "—"),
          irow("health", `${esc((m.health || {}).status || "—")}${((m.health || {}).missing_contracts || []).length ? " · missing: " + (m.health.missing_contracts || []).map(icode).join(" ") : ""}`),
          irow("receipts", irefs(m.receipt_refs)),
          ihint(esc((m.health || {}).note || (m.ingestion || {}).note || "")),
          irow("open in", `${sourcesLink(m.data_source_id) ? `<a href="${sourcesLink(m.data_source_id)}">source</a> · ` : ""}<a href="${managerResourceLink(oid, "connector-mapping", m.id)}">Manager resource</a> · <a href="${managerLink({ ontology: oid, section: "object-types", definitionKind: "object-type", definitionId: m.object_type_id })}">object type</a>`),
        ].join("") : emptyStage("Object mapping"),
        trayTitle: "Object mapping — field table",
        tray: m ? trayTable(["role", "property", "source field", "source type"], [
          ...(m.key_mapping ? [["key", icode(m.key_mapping.property_id), icode(m.key_mapping.source_field), esc(m.key_mapping.source_type || "")]] : []),
          ...(m.title_mapping ? [["title", icode(m.title_mapping.property_id), icode(m.title_mapping.source_field), esc(m.title_mapping.source_type || "")]] : []),
          ...(m.field_mappings || []).map((f) => ["field", icode(f.property_id), icode(f.source_field), esc(f.source_type || "")]),
        ]) : trayTable(["role", "property", "source field", "source type"], []),
      };
      case "policy": return {
        title: "Policy gate", sub: v ? (v.ref || `policy-bound-data-view://${v.id}`) : "no record",
        body: v ? [
          irow("records", `${views.length} gate${views.length === 1 ? "" : "s"}${views.length > 1 ? " · showing first" : ""}`),
          irow("name", esc(v.name || "—")),
          irow("allowed operations", (v.allowed_operations || []).map(icode).join(" ") || "—"),
          irow("subjects", (v.authority_subjects || []).map(icode).join(" ") || "—"),
          ...(v.purpose ? [irow("purpose", esc(v.purpose))] : []),
          irow("property scope", (v.property_scope || []).map(icode).join(" ") || "—"),
          irow("postures (obligations)", `evaluation ${icode(v.evaluation_posture || "—")} · export ${icode(v.export_posture || "—")}${v.publish_route_posture ? ` · publish ${icode(v.publish_route_posture)}` : ""}${v.retention_posture ? ` · retention ${icode(v.retention_posture)}` : ""}`),
          irow("health", `${esc((v.health || {}).status || "—")}${((v.health || {}).missing_contracts || []).length ? " · missing: " + (v.health.missing_contracts || []).map(icode).join(" ") : ""}`),
          ihint(esc((v.health || {}).note || (v.authority || {}).note || "")),
          irow("open in", `<a href="${managerResourceLink(oid, "connector-mapping", v.connector_mapping_id)}">mapping</a> · <a href="${managerResourceLink(oid, "policy-view", v.id)}">Manager resource</a>`),
        ].join("") : emptyStage("Policy gate"),
        trayTitle: "Policy gate — scope and operations",
        tray: v ? trayTable(["allowed operation", "subjects", "property scope"],
          (v.allowed_operations || ["—"]).map((op) => [icode(op), (v.authority_subjects || []).map(icode).join(" "), (v.property_scope || []).map(icode).join(" ")])) : trayTable(["allowed operation", "subjects", "property scope"], []),
      };
      case "transform": return {
        title: "Transform plan", sub: r ? (r.ref || `transformation-run://${r.id}`) : "no record",
        body: r ? [
          irow("records", `${truns.length} plan${truns.length === 1 ? "" : "s"}${truns.length > 1 ? " · showing first" : ""}`),
          irow("name", esc(r.name || "—")),
          irow("status", icode(r.status || "—")),
          irow("blocked reasons", (r.blocked_reasons || []).length ? r.blocked_reasons.map(esc).join(" · ") : "none"),
          irow("missing contracts", (r.missing_contracts || []).length ? r.missing_contracts.map(icode).join(" ") : "none"),
          irow("receipt chain", `${(r.history || []).length} receipt${(r.history || []).length === 1 ? "" : "s"} (full chain in the tray)`),
          irow("latest receipt", (r.history || []).length ? icode(r.history[r.history.length - 1].receipt_ref || "—") : "—"),
          ihint(`Execution boundary — source_contacted: <b>${(r.execution || {}).source_contacted === true}</b> · data_moved: <b>${(r.execution || {}).data_moved === true}</b> · object_instances: <b>${(r.execution || {}).object_instances ?? 0}</b>. ${esc((r.execution || {}).note || "")}`),
        ].join("") : emptyStage("Transform plan"),
        trayTitle: "Transform plan — receipt chain / dry-run plan",
        tray: r ? trayTable(["at", "op", "summary", "receipt"],
          (r.history || []).slice(0, 10).map((h) => [esc(h.at || ""), icode(h.op || ""), esc(h.summary || ""), icode(h.receipt_ref || "")])) : trayTable(["at", "op", "summary", "receipt"], []),
      };
      case "projection": return {
        title: "Read projection", sub: proj ? (proj.ref || `ontology-projection://${proj.id}`) : "no record",
        body: proj ? [
          irow("records", `${projs.length} projection${projs.length === 1 ? "" : "s"}${projs.length > 1 ? " · showing active" : ""}`),
          irow("name", esc(proj.name || "—")),
          irow("status", icode(proj.status || "—")),
          irow("layout · key", `${esc(proj.layout || "—")} · key ${icode(proj.key_field || "—")}`),
          irow("visible properties", (proj.visible_properties || []).map(icode).join(" ") || "—"),
          irow("facets", (proj.facet_properties || []).length ? proj.facet_properties.map(icode).join(" ") : "none declared"),
          irow("affordance gates", `export ${proj.export_affordance_enabled ? "enabled" : "disabled"} · ${(proj.action_affordances || []).length} action affordance${(proj.action_affordances || []).length === 1 ? "" : "s"}`),
          irow("object instances", `<b>${(proj.health || {}).object_instances ?? 0}</b>`),
          ...(proj.materialized ? [irow("materialized", `${esc(String(proj.materialized.count ?? ""))} at ${esc(proj.materialized.at || "")} via ${icode(proj.materialized.materializing_run_ref || "")}`)] : []),
          ihint(esc((proj.health || {}).note || "")),
          irow("open in", `<a href="${managerResourceLink(oid, "ontology-projection", proj.id)}">Manager resource</a>${mset ? ` · <a href="${objectSetLink(oid, mset.id)}">Explorer set</a>` : ""}${proj.object_type_id ? ` · <a href="${objectTypeLink(oid, proj.object_type_id)}">Explorer type</a>` : ""}`),
        ].join("") : emptyStage("Read projection"),
        trayTitle: "Read projection — columns and facets",
        tray: proj ? trayTable(["column", "facet?", "notes"],
          (proj.visible_properties || []).map((c) => [icode(c), (proj.facet_properties || []).includes(c) ? "facet" : "—", c === proj.key_field ? "key field" : ""])) : trayTable(["column", "facet?", "notes"], []),
      };
      case "lease": return {
        title: "Lease + session", sub: pl ? (pl.ref || `capability-lease-plan://${pl.id}`) : "no record",
        body: pl ? [
          irow("plan", icode(pl.ref || pl.id)),
          irow("credential posture", icode(pl.credential_posture || "—")),
          irow("gateway", `${icode((pl.gateway || {}).route || "—")} · ${icode((pl.gateway || {}).primitive || "—")}`),
          irow("TTL", `${esc(String(pl.ttl_seconds ?? (mr ? mr.ttl_seconds : "—")))}s`),
          ...(mr ? [irow("materializing run", `${icode(mr.ref || mr.id)} · status ${icode(mr.status || "—")} · subject ${icode(mr.subject || "—")}${mr.purpose ? ` · purpose ${esc(mr.purpose)}` : ""}`)] : [irow("materializing run", "none yet — the lease is a plan only")]),
          ...(ssn ? [irow("sealed session", `${icode(ssn.ref || ssn.id)} · status ${icode(ssn.status || "—")} · ${(ssn.operations || []).length} op${(ssn.operations || []).length === 1 ? "" : "s"} · ${(ssn.properties || []).length} propert${(ssn.properties || []).length === 1 ? "y" : "ies"}`)] : [irow("sealed session", "none yet")]),
          ihint(`Credential material is <b>never held or rendered here</b> — the plan records credential_material: <b>${(pl.lease || {}).credential_material === true}</b>, minted: <b>${(pl.lease || {}).minted === true}</b>. ${esc((pl.lease || {}).note || "")}`),
        ].join("") : emptyStage("Capability lease plan"),
        trayTitle: "Lease + session — gateway and proof refs (no secrets)",
        tray: trayTable(["record", "ref", "receipts"], [
          ...(pl ? [["lease plan", icode(pl.ref || pl.id), irefs(pl.receipt_refs)]] : []),
          ...(mr ? [["materializing run", icode(mr.ref || mr.id), irefs(mr.receipt_refs)]] : []),
          ...(ssn ? [["connector session", icode(ssn.ref || ssn.id), irefs(ssn.receipt_refs)]] : []),
        ]),
      };
      case "materialized": return {
        title: "Materialized objects", sub: st ? (st.ref || st.id || "") : "no record",
        body: st ? [
          irow("object set", icode(st.ref || st.id)),
          irow("object count", `<b>${esc(String(st.count ?? 0))}</b> (rows fetched ${esc(String(st.rows_fetched ?? "—"))}${st.truncated_to_limit ? " · truncated to limit" : ""})`),
          irow("registered", esc(st.registered_at || "—")),
          irow("provenance", [st.materializing_run_ref, st.connector_session_ref, st.capability_lease_plan_ref].filter(Boolean).map(icode).join(" ") || "—"),
          irow("pre-output receipt", st.pre_output_receipt_ref ? icode(st.pre_output_receipt_ref) : "—"),
          ...(st.source_contact ? [irow("source contact", `${safeOrigin(st.source_contact.endpoint || "")} · http ${esc(String(st.source_contact.http_status ?? "—"))} · ${esc(String(st.source_contact.elapsed_ms ?? "—"))}ms${st.source_contact.at ? ` · ${esc(st.source_contact.at)}` : ""}`)] : []),
          irow("reset", disabledCommand({ label: "Delete object set", reason: "deletion is a daemon authority (DELETE …/materialized-object-sets/:id) — command wiring is the command-discipline PR, a named gap here" })),
          irow("open in", `<a href="${objectSetLink(oid, st.id)}">Explorer set</a> · <a href="${lineageLink(oid, st.id)}">Lineage</a> · <a href="${vertexLink(oid, st.id)}">Vertex</a> · <a href="${provenanceSetLink(st.id)}">Provenance</a>${st.object_type_id ? ` · <a href="${managerLink({ ontology: oid, section: "object-types", definitionKind: "object-type", definitionId: st.object_type_id })}">object type</a>` : ""}`),
        ].join("") : emptyStage("Materialized object set"),
        trayTitle: "Materialized objects — preview rows",
        tray: (st ? "" : ihint(missingRungs.length
          ? `Nothing is materialized on this pipeline yet — missing rung${missingRungs.length === 1 ? "" : "s"}: ${missingRungs.map((l) => `<b>${esc(l)}</b>`).join(" · ")}. Build runs the governed ladder from the <a href="/__ioi/odk?ontology=${enc(oid)}">Ontology Manager</a>; nothing is fabricated here.`
          : `Every ladder rung is declared but the materializing run has not executed yet — nothing is materialized, and nothing is fabricated here. Execute the run from the <a href="/__ioi/odk?ontology=${enc(oid)}">Ontology Manager</a>.`)) + previewTable,
      };
      default: return { title: "Pipeline", sub: "", body: emptyStage("node"), trayTitle: "Selection", tray: previewTable };
    }
  }
  const insp = inspectorMode ? nodeInspector(selNodeKey) : null;

  // ---- SHARED pixel-aligned GLOBAL RAIL (#43) — Pipeline Builder active. The live pipeline PICKER
  // (no reference counterpart in the rail) lives in the canvas body (excluded region), keeping the rail
  // pixel-faithful while the control keeps its function.
  // Embedded (native container contract #65): the native IOI rail outside the iframe owns platform
  // navigation — the module emits NO global rail at all (structural, not hidden).
  const globalRail = embed ? "" : ioiGlobalRailHtml({ label: "Pipeline Builder", href: "/__ioi/pipeline", iconUri: PIPELINE_APP_ICON_URI, railVariant: "rv-pipe", viewAll: false, star: false, badges: true, aipGradient: true, acctMuted: true });
  const railPipes = ontologies.length
    ? ontologies.map((x) => { const on = selected && x.id === selected.id; const built = builtRefs.has(x.ref); return `<a class="pb-pipe ${on ? "on" : ""}" href="/__ioi/pipeline?ontology=${enc(x.id)}">${esc(x.domain || x.id)}${built ? `<span class="pb-tag">built</span>` : ""}</a>`; }).join("")
    : `<div class="pb-empty">No pipelines yet. <a href="/__ioi/odk/ontologies/new">Create an ontology</a>.</div>`;
  // Node cards are selection anchors (progressive enhancement: plain link navigation, so the URL
  // carries the state and refresh/deep-links Just Work; tab order + Enter give keyboard selection).
  // The old jump-to-ODK click moved into each inspector's Ontology-Manager link.
  const nodeCard = (nd) => `<a class="pb-node pb-${nd.cls}${nd.key === selNodeKey ? " pb-nsel" : ""}" data-node="${nd.key}" href="${selected ? nodeHref(nd.key) : "#"}"${nd.key === selNodeKey ? ' aria-current="true"' : ""}>
    <div class="pb-nhead"><span class="pb-nicon">${nd.icon}</span><span class="pb-dot pb-${nd.cls}"></span></div>
    <div class="pb-nlabel">${esc(nd.label)}</div>
    <div class="pb-ncount"><b>${esc(String(nd.count))}</b> ${nd.kind === "output" ? "objects" : nd.kind === "input" ? "source" + (nd.count === 1 ? "" : "s") : "record" + (nd.count === 1 ? "" : "s")}</div>
    <div class="pb-ndetail">${esc(nd.detail || "")}</div>
  </a>`;
  const legendGroups = [
    ["Input Data", "#8f99a8", dsources.length, "input"],
    ["Data Cleaning", "#238551", maps.length + views.length, "clean"],
    ["Calculations", "#d1980b", truns.length + projs.length + plans.length, "calc"],
    ["Output Dataset", "#147eb3", osets.length, "output"],
  ];
  const CAT_COLOR = { input: "#8f99a8", clean: "#238551", calc: "#d1980b", output: "#147eb3" };
  const NODE_CATEGORY = { datasource: "input", mapping: "clean", policy: "clean", transform: "calc", projection: "calc", lease: "calc", materialized: "output" };

  // ---- REFERENCE-DENSITY GRAPH (#66) — the reference renders nodes as SVG groups (200x60 rects,
  // category-colored title bars, Bezier edges with arrowheads); this graph renders the SAME
  // grammar over the REAL ladder. Every node is a selection anchor (URL-state, keyboard-focusable)
  // and every edge is TYPED PROOF: drawn only when the downstream record actually carries the
  // upstream ref, with the justifying field named in its tooltip. Nothing is fabricated: a missing
  // rung renders as a dashed missing node with NO invented edges.
  const NODE_POS = { datasource: [40, 120], mapping: [300, 120], policy: [560, 120], transform: [820, 120], projection: [1080, 120], lease: [1300, 280], materialized: [1600, 120] };
  const nodeRef = (key) => ({ datasource: d0 && (d0.source_ref || d0.source_id), mapping: m0 && (m0.ref || m0.id), policy: v0 && (v0.ref || v0.id), transform: r0 && (r0.ref || r0.id), projection: proj && (proj.ref || proj.id), lease: pl0 && (pl0.ref || pl0.id), materialized: st0 && (st0.ref || st0.id) })[key] || "";
  const edges = [];
  const pushEdge = (from, to, ref, field) => { if (ref) edges.push({ from, to, ref: String(ref), field }); };
  pushEdge("datasource", "mapping", d0 && m0 && (m0.data_source_ref || m0.data_source_id), "mapping.data_source_ref");
  pushEdge("mapping", "policy", m0 && v0 && (v0.connector_mapping_ref || v0.connector_mapping_id), "policy.connector_mapping_ref");
  pushEdge("policy", "transform", v0 && r0 && (r0.policy_view_ref || r0.policy_view_id), "transform.policy_view_ref");
  pushEdge("mapping", "transform", m0 && r0 && r0.connector_mapping_ref, "transform.connector_mapping_ref");
  pushEdge("mapping", "projection", m0 && proj && proj.connector_mapping_ref, "projection.connector_mapping_ref");
  pushEdge("policy", "projection", v0 && proj && proj.policy_view_ref, "projection.policy_view_ref");
  pushEdge("transform", "lease", r0 && pl0 && pl0.transformation_run_ref, "lease-plan.transformation_run_ref");
  pushEdge("projection", "lease", proj && pl0 && pl0.ontology_projection_ref, "lease-plan.ontology_projection_ref");
  pushEdge("lease", "materialized", pl0 && st0 && st0.capability_lease_plan_ref, "set.capability_lease_plan_ref");
  pushEdge("projection", "materialized", proj && st0 && st0.ontology_projection_id, "set.ontology_projection_id");
  const NW = 200, NH = 60;
  const edgePath = (e) => {
    const [fx, fy] = NODE_POS[e.from], [tx, ty] = NODE_POS[e.to];
    const x1 = fx + NW, y1 = fy + NH / 2, x2 = tx - 8, y2 = ty + NH / 2;
    return `M ${x1} ${y1} C ${x1 + 55} ${y1}, ${x2 - 55} ${y2}, ${x2} ${y2}`;
  };
  const clip = (t, n) => { const v = String(t || ""); return v.length > n ? v.slice(0, n - 1) + "\u2026" : v; };
  const svgNode = (nd) => {
    const [x, y] = NODE_POS[nd.key];
    const cat = NODE_CATEGORY[nd.key];
    const on = nd.key === selNodeKey; // default = datasource (the #57 selection contract; canvas = excluded body
    const unit = nd.kind === "output" ? "objects" : nd.kind === "input" ? "source" + (nd.count === 1 ? "" : "s") : "record" + (nd.count === 1 ? "" : "s");
    return `<a class="pb-node pb-${nd.cls}${on ? " pb-nsel" : ""}" data-node="${nd.key}" data-category="${cat}"${hiddenCats.includes(cat) ? ' style="display:none"' : ""} href="${selected ? stateHref({ node: nd.key, output: "" }) : "#"}"${on ? ' aria-current="true"' : ""} aria-label="${esc(nd.label)}">
      <g class="pb-gnode" transform="translate(${x},${y})">
        <rect class="pb-nbody" width="${NW}" height="${NH}" rx="2"/>
        <rect class="pb-ntitle" width="${NW}" height="26" fill="${nd.cls === "missing" ? "#c2c6cd" : CAT_COLOR[cat]}"/>
        <rect class="pb-nchip" width="26" height="26" fill="#edeff2"/>
        <text class="pb-nchipico" x="13" y="18" text-anchor="middle" font-size="13">${nd.icon}</text>
        <text class="pb-ntext" x="33" y="17.5">${esc(clip(nd.label, 24))}</text>
        <line x1="0" y1="26" x2="${NW}" y2="26" stroke="#abb3bf" stroke-width="0.5"/>
        <text class="pb-nsub" x="8" y="42">${esc(String(nd.count))} ${unit}</text>
        <text class="pb-ndeet" x="8" y="55">${esc(clip(nd.detail, 36))}</text>
        <circle class="pb-gdot" cx="188" cy="40" r="4" fill="${nd.cls === "live" ? "#2f9e6b" : nd.cls === "declared" ? "#d68a2a" : "#b8bdc6"}"/>
        <rect class="pb-nstroke" width="${NW}" height="${NH}" rx="2"/>
      </g>
    </a>`;
  };
  const graphSvg = `<svg id="pb-graph" viewBox="0 70 1860 320" preserveAspectRatio="xMidYMid meet" role="group" aria-label="Pipeline graph" tabindex="0">
    <defs><marker id="pb-arrow" viewBox="0 -4 8 8" refX="7" refY="0" markerWidth="8" markerHeight="8" orient="auto"><path d="M0,-4L8,0L0,4" fill="#abb3bf"/></marker></defs>
    <g class="pb-graphlayer" id="pb-graphlayer">
      ${edges.map((e) => `<path class="pb-edge" data-edge="${e.from}:${e.to}" d="${edgePath(e)}" marker-end="url(#pb-arrow)"><title>typed edge — ${esc(e.field)} = ${esc(e.ref)}</title></path>`).join("\n      ")}
      ${nodes.map(svgNode).join("\n      ")}
    </g>
  </svg>`;
  const graphData = JSON.stringify(nodes.map((nd) => ({ key: nd.key, label: nd.label, category: NODE_CATEGORY[nd.key], ref: nodeRef(nd.key), href: selected ? stateHref({ node: nd.key, output: "" }) : "#", pos: NODE_POS[nd.key] }))).replace(/</g, "\\u003c");

  // ---- Build readiness (#67): ONE coherent ready ladder = every rung's own readiness predicate
  // AND the typed-edge chain unbroken (the same proof the graph draws). Owner links for anything
  // missing live in the review pane + the warnings tab (Go-to-node -> the rung's Manager links).
  const readyChecks = [
    { key: "datasource", label: "Datasource", ok: dsources.length > 0, node: "datasource" },
    { key: "mapping", label: "Object mapping (health ready)", ok: !!(m0 && (m0.health || {}).status === "ready"), node: "mapping" },
    { key: "policy", label: "Policy gate (health ready)", ok: !!(v0 && (v0.health || {}).status === "ready"), node: "policy" },
    { key: "transform", label: "Transform plan (dry-run validated)", ok: !!(r0 && r0.status === "dry_run_ready"), node: "transform" },
    { key: "projection", label: "Read projection (ready)", ok: !!(proj && proj.status === "ready"), node: "projection" },
    { key: "plan", label: "Capability lease plan (declared)", ok: !!pl0, node: "lease" },
    { key: "coherence", label: "Typed-edge coherence (one unbroken chain)", ok: ["datasource:mapping", "mapping:policy", "policy:transform", "transform:lease", "projection:lease"].every((k) => edges.some((e) => `${e.from}:${e.to}` === k)), node: "lease" },
  ];
  const missingForBuild = readyChecks.filter((c) => !c.ok).map((c) => c.label);
  const buildReady = missingForBuild.length === 0;
  // The covering connector — the SAME same-origin + path-prefix rule the daemon enforces
  // (connector_covers_endpoint); the daemon re-checks authoritatively at admit/open/execute.
  const coversEndpoint = (baseUrl, endpoint) => { try { const b = new URL(baseUrl), e = new URL(endpoint); return b.protocol === e.protocol && b.host.toLowerCase() === e.host.toLowerCase() && (e.pathname === b.pathname || e.pathname.startsWith(b.pathname.endsWith("/") ? b.pathname : b.pathname + "/")); } catch { return false; } };
  const coveringConnector = d0 ? connectors.find((c) => coversEndpoint(c.base_url || "", d0.endpoint || "")) || null : null;

  // ---- Command state (command-discipline): the header renders from the module's declared
  // command table. Preview is a real read-navigation — it selects the materialized node (URL
  // state, ontology preserved) and lands on the tray, where real rows or the honest missing-rung
  // state render. Build/Schedule/Deploy are visibly disabled with their named reasons (the whole
  // cluster sits inside the harness's both-sides session-state mask, so command-state changes
  // never move certified shell pixels). The old Build→ODK jump lives on as the explicit
  // "Ontology Manager" link — a labeled navigation, not a command pretending to build.
  const cmd = Object.fromEntries(commands.map((a) => [a.key, a]));
  const previewHref = `${stateHref({ node: "materialized", tab: "preview" })}#pb-preview`;

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
      ${(buildReady || resumableRun || (paneKey && runRec)) ? `<a class="pb-btn primary" data-cmd="build" href="${stateHref({ pane: "build", run: resumableRun ? resumableRun.id : runSel })}">Build</a>` : `<button class="pb-btn primary" disabled title="${esc(`the ladder is not coherent-ready — missing: ${missingForBuild.join(" · ")} (each rung links to its owner in the Pipeline warnings tab)`)}" data-ioi-disabled-reason="${esc(`the ladder is not coherent-ready — missing: ${missingForBuild.join(" · ")} — the governed ladder is MaterializingRun → wallet-approved lease → sealed ConnectorSession → execute`)}">Build</button>`}
      <a class="pb-btn ghost" data-cmd="preview" href="${previewHref}">Preview</a>
      <button class="pb-btn ghost" disabled title="${esc(cmd.schedule.reason)}" data-ioi-disabled-reason="${esc(cmd.schedule.reason)}">Schedule</button>
      <button class="pb-btn ghost" disabled title="${esc(cmd.deploy.reason)}" data-ioi-disabled-reason="${esc(cmd.deploy.reason)}">Deploy</button>
      <a class="pb-btn link" href="/__ioi/lineage?ontology=${enc(oid)}">Lineage</a>
      <a class="pb-btn link" href="${managerLink({ ontology: oid })}">Ontology Manager</a>
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
  // tbtn: href → live link · live → enabled client control (id) · else disabled with the reason
  // named in BOTH title and data-ioi-disabled-reason (the every-control-accounted sweep's hook).
  const tbtn = (icon, opts = {}) => {
    const cls = `pb-ticon${opts.look ? " " + opts.look : ""}${opts.tint ? " pb-i-" + opts.tint : ""}`;
    const body = icon === "@aip-grad" ? AIP_GRADIENT_SVG_TOOLBAR : bpIcon(icon);
    if (opts.href) return `<a href="${opts.href}" class="${cls}" title="${esc(opts.title || "")}">${body}</a>`;
    if (opts.live) return `<button type="button" id="${opts.live}" class="${cls} live" title="${esc(opts.title || "")}">${body}</button>`;
    const reason = opts.title || "named gap";
    return `<button disabled class="${cls}" title="${esc(reason)}" data-ioi-disabled-reason="${esc(reason)}">${body}</button>`;
  };
  const seg = (...btns) => `<span class="pb-seg">${btns.join("")}</span>`;
  const toolcard = `<div class="pb-toolcard">
    <div class="pb-tg">
      <div class="pb-tgrow">${seg(tbtn("move", { look: "act", live: "pb-tool-pan", title: "Panning mode — drag pans the canvas (live)" }), tbtn("select", { title: "multi-select has no consumer — selection is single-node URL state (?node=); a marquee would select nothing actionable (named gap)" }))}${seg(tbtn("selection", { title: "multi-select has no consumer (named gap)" }))}${seg(tbtn("graph-remove", { look: "dim", title: "graph authoring is a named gap — ladder records are authored in the Ontology Manager" }))}${seg(tbtn("layout-sorted-clusters", { title: "the ladder layout is fixed by the ODK contract order — freeform layout is a named gap" }), tbtn("grid", { title: "no freeform node placement, so nothing snaps (named gap)" }))}${seg(tbtn("new-text-box", { title: "canvas annotations have no persistence plane (named gap)" }))}</div>
      <div class="pb-tghints"><span style="left:15.5px">Tools</span><span style="left:72.3px">Select</span><span class="pb-hwrap" style="left:115px">Remove</span><span style="left:175.5px">Layout</span><span style="left:242px">Text</span></div>
    </div>
    <div class="pb-tg pb-tg2">
      <a class="pb-twide" href="/__ioi/odk?ontology=${enc(oid)}" title="Add data — routes to the real ODK authoring ladder">${bpIcon("import")} Add data ${bpIcon("caret-down")}</a>
      <button class="pb-twide" disabled title="Reusable transforms library — a named gap">${bpIcon("repeat")} Reusables ${bpIcon("caret-down")}</button>
    </div>
    <div class="pb-tg pb-tg3">
      <div class="pb-tgrow">${seg(tbtn("path", { look: "dim", tint: "blue", title: "transform authoring requires a TransformationRun authoring authority — a named gap; the declared plan is inspectable on the Transform plan node" }), tbtn("join-table", { look: "dim", tint: "cyan", title: "join authoring — named gap (no authoring authority)" }), tbtn("add-row-bottom", { look: "dim", tint: "rose", title: "union authoring — named gap" }), tbtn("split-columns", { look: "dim", tint: "green", title: "split authoring — named gap" }), tbtn("model", { look: "dim", tint: "violet", title: "model application — named gap (model routes live in the Model Catalog)" }))}${seg(tbtn("@aip-grad", { look: "dim", title: "AIP transform lanes are reference-only (named gap)" }), tbtn("clean", { tint: "violet", title: "AIP generation is a reference-only lane (named gap)" }), tbtn("lightbulb", { tint: "violet", title: "AIP explanation is a reference-only lane (named gap)" }))}${seg(tbtn("edit", { look: "dim", title: "transform editing — named gap (no authoring authority)" }))}</div>
      <div class="pb-tghints"><span style="left:45.9px">Transform</span><span style="left:195.3px">AIP</span><span style="left:268.7px">Edit</span></div>
    </div>
  </div>`;

  // ---- FLOATING canvas buttons (search / fit) + ZOOM stack (bottom-left) — reference chrome, named gaps.
  const floatbtns = `<div class="pb-floatbtns">${tbtn("search", { href: stateHref({ panel: "search" }), title: "Search pipeline — the right panel becomes the real record search" })}${tbtn("many-to-many", { title: "color grouping is a reference-only lane (named gap)" })}</div>
  <div class="pb-zoomstack">${tbtn("zoom-in", { live: "pb-zin", title: "Zoom in" })}${tbtn("zoom-out", { live: "pb-zout", title: "Zoom out" })}${tbtn("zoom-to-fit", { live: "pb-zfit", title: "Zoom to fit" })}</div>`;

  // ---- LEGEND card (canvas top-right, left of the outputs panel) — live category counts masked as data.
  const legend = `<div class="pb-legend${legendCollapsed ? " pb-lcollapsed" : ""}" id="pb-legend">
    <div class="pb-legendhd">Legend <button type="button" class="pb-legcaret" id="pb-legend-toggle" title="Toggle legend" aria-expanded="${!legendCollapsed}">${bpIcon(legendCollapsed ? "caret-down" : "caret-up")}</button></div>
    <div class="pb-leggrid">
      ${legendGroups.map(([g, c, n, catKey]) => `<div class="pb-legrow${hiddenCats.includes(catKey) ? " off" : ""}" data-cat="${catKey}"><span class="pb-legchip" style="background:${c}"></span><span class="pb-legname">${esc(g)}</span> <b>(${n})</b> <button type="button" class="pb-legeye" data-cat="${catKey}" title="${hiddenCats.includes(catKey) ? "Show this color" : "Hide this color"}">${bpIcon("eye-open", 14)}</button></div>`).join("")}
    </div>
    <button class="pb-addcolor" disabled title="Legend color authoring — a named gap" data-ioi-disabled-reason="Legend color authoring — a named gap">${bpIcon("plus")} Add color</button>
  </div>`;

  // ---- TRAY CONTENT (#66) — one body per tab, all real truth or honest named gaps.
  // Warnings are REAL: missing rungs, unhealthy records, blocked reasons, missing contracts and
  // missing authority across the ladder — each with its Go-to-node link (the reference grammar).
  const redactUrls = (t) => String(t || "").replace(/(https?:\/\/[^/\s"']+)[^\s"']*/g, "$1/\u2026");
  const warnings = [];
  for (const nd of nodes) if (nd.cls === "missing") warnings.push({ node: nd.key, label: nd.label, kind: "missing rung", detail: `no ${nd.label} record exists on this pipeline yet` });
  const warnRec = (key, label, rec) => {
    if (!rec) return;
    const h = rec.health || {};
    if (h.status && h.status !== "ready") warnings.push({ node: key, label, kind: `health ${h.status}`, detail: redactUrls(h.note) });
    for (const c of h.missing_contracts || []) warnings.push({ node: key, label, kind: "missing contract", detail: c });
    for (const b of rec.blocked_reasons || []) warnings.push({ node: key, label, kind: "blocked", detail: b });
    const ma = rec.missing_authority;
    for (const a of Array.isArray(ma) ? ma : ma ? [ma] : []) warnings.push({ node: key, label, kind: "missing authority", detail: a });
  };
  warnRec("mapping", "Object mapping", m0); warnRec("policy", "Policy gate", v0); warnRec("transform", "Transform plan", r0);
  warnRec("projection", "Read projection", proj); warnRec("lease", "Lease + session", pl0); warnRec("lease", "Lease + session", mr0);
  const warningsPanel = warnings.length
    ? `<div class="ioi-tray-hd">Pipeline warnings — real ladder truth (${warnings.length})</div><table class="pb-table"><thead><tr><th>node</th><th>warning</th><th>detail</th><th></th></tr></thead><tbody>${warnings.slice(0, 30).map((w) => `<tr><td>${esc(w.label)}</td><td>${icode(w.kind)}</td><td>${esc(redactUrls(w.detail).slice(0, 300))}</td><td><a href="${stateHref({ node: w.node, tab: "", output: "" })}">Go to node</a></td></tr>`).join("")}</tbody></table>`
    : `<div class="pb-trayempty">No pipeline warnings — every declared rung is healthy, nothing is blocked, and no contract or authority is missing.</div>`;
  const suggestionsPanel = `<div class="pb-sugbanner">Compute profile — native-acceleration and compute-profile suggestions are a reference-only lane (no suggestion authority; named gap).</div>
    <div class="pb-ihint">AIP Assist suggestions have no daemon plane on this surface — a named gap, not a hidden lane. Improvement proposals over real outcomes live in <a href="/__ioi/agent-studio#improvement-proposals">Agent Studio</a>.</div>`;
  const previewProvenance = mset ? `<div class="pb-ihint">Rows above are the REAL materialized set ${icode(mset.ref || mset.id)} (count ${esc(String(mset.count ?? 0))}, rows fetched ${esc(String(mset.rows_fetched ?? "—"))}) — provenance ${[mset.materializing_run_ref, mset.connector_session_ref].filter(Boolean).map(icode).join(" ")}.</div>` : "";
  const previewPanel = (st0 ? "" : ihint(missingRungs.length
    ? `Nothing is materialized on this pipeline yet — missing rung${missingRungs.length === 1 ? "" : "s"}: ${missingRungs.map((l) => `<b>${esc(l)}</b>`).join(" · ")}. Build runs the governed ladder from the <a href="/__ioi/odk?ontology=${enc(oid)}">Ontology Manager</a>; nothing is fabricated here.`
    : `Every ladder rung is declared but the materializing run has not executed yet — nothing is materialized, and nothing is fabricated here.`)) + previewTable + previewProvenance;
  // Receipt chains per node — the record's real history[] mirrored by receipt_refs (the third
  // sub-tab; the reference's "Schedules" slot has no plane here, so IOI shows PROOF instead).
  const historyRowsOf = (key) => {
    const recs = { datasource: [d0], mapping: [m0], policy: [v0], transform: [r0], projection: [proj], lease: [pl0, mr0, ssn0], materialized: [st0] }[key] || [];
    const rows = [];
    for (const rec of recs.filter(Boolean)) {
      for (const h of rec.history || []) rows.push([esc(h.at || ""), icode(h.op || ""), esc(redactUrls(h.summary)), icode(h.receipt_ref || "")]);
      if (!(rec.history || []).length) for (const rr of rec.receipt_refs || []) rows.push(["", icode("receipt"), esc(rec.name || rec.id || ""), icode(rr)]);
      if (rec.pre_output_receipt_ref) rows.push(["", icode("pre_output_receipt"), "persisted BEFORE output registration", icode(rec.pre_output_receipt_ref)]);
    }
    return rows;
  };
  const subtab = (key, label, on, gapReason) => gapReason
    ? `<button type="button" class="pb-subtab" disabled title="${esc(gapReason)}" data-ioi-disabled-reason="${esc(gapReason)}">${esc(label)}</button>`
    : `<button type="button" class="pb-subtab${on ? " on" : ""}" data-sub="${key}">${esc(label)}</button>`;
  const nodeDetailPanel = insp ? trayShell({
    id: "pb-tray-node",
    title: insp.trayTitle,
    body: (invalidNode ? `<div class="pb-ihint pb-warnhint">Unknown node <code>${esc(nodeParam)}</code> — failed closed to the default selection (Datasource).</div>` : "")
      + semanticBreadcrumb([{ label: selected ? (selected.domain || selected.id) : "ontology", href: managerLink({ ontology: oid }) }, { label: insp.title }])
      + `<div class="pb-subtabs">${subtab("about", "About", true)}${subtab("fields", "Fields", false)}${subtab("receipts", "Receipts", false)}${subtab("", "Schedules", false, "no pipeline scheduler exists yet — a named gap")}</div>`
      + `<div class="pb-subpane" data-sub="about">${inspectorShell({ id: "pb-inspector", title: insp.title, subtitle: insp.sub, body: insp.body })}</div>`
      + `<div class="pb-subpane" data-sub="fields" hidden>${insp.tray}</div>`
      + `<div class="pb-subpane" data-sub="receipts" hidden>${trayTable(["at", "op", "summary", "receipt"], historyRowsOf(selNodeKey))}</div>`,
  }) : "";
  const outProj = outputSel ? projs.find((p) => p.id === outputSel) : null;
  const outputDetailPanel = outProj ? trayShell({
    id: "pb-tray-output",
    title: `Output — ${esc(outProj.name || outProj.id)}`,
    body: semanticBreadcrumb([{ label: selected ? (selected.domain || selected.id) : "ontology", href: managerLink({ ontology: oid }) }, { label: outProj.name || outProj.id }])
      + irow("projection", icode(outProj.ref || outProj.id))
      + irow("status", icode(outProj.status || "—"))
      + irow("layout · key", `${esc(outProj.layout || "—")} · key ${icode(outProj.key_field || "—")}`)
      + irow("columns", (outProj.visible_properties || []).map(icode).join(" ") || "—")
      + (outProj.materialized ? irow("materialized", `${esc(String(outProj.materialized.count ?? ""))} via ${icode(outProj.materialized.materializing_run_ref || "")}`) : "")
      + irow("open in", `<a href="${managerResourceLink(oid, "ontology-projection", outProj.id)}">Manager resource</a>${mset ? ` · <a href="${objectSetLink(oid, mset.id)}">Explorer set</a>` : ""} · <a href="${stateHref({ node: "projection", output: "" })}">projection node</a>`),
  }) : "";
  const selectionEmpty = `<div class="pb-trayempty">${bpIcon("panel-table", 20)} Select a single node to preview its record — click a node on the graph (or focus it with ← → and press Enter).</div>`
    + (invalidOutput ? `<div class="pb-ihint pb-warnhint">Unknown output <code>${esc(sel.output)}</code> — no projection with that id on this pipeline (failed closed).</div>` : "")
    + (invalidTab ? `<div class="pb-ihint pb-warnhint">Unknown tray tab <code>${esc(sel.tab)}</code> — failed closed to Selection preview.</div>` : "")
    + (previewWithoutSel ? `<div class="pb-ihint pb-warnhint">The Preview tab exists only with a selection (reference behavior) — failed closed to Selection preview. Select a node first.</div>` : "")
    + (invalidPanel ? `<div class="pb-ihint pb-warnhint">Unknown panel <code>${esc(sel.panel)}</code> — failed closed to Pipeline outputs.</div>` : "");
  // ---- GOVERNED BUILD PANE (#67) — every fact below is a loaded daemon record; every mutation
  // is a declared runtime action; the wallet grant is pasted, forwarded once, dropped. The pane
  // is fully resumable: stage = f(record status), so refresh/back/direct links re-derive it.
  const bHere = stateHref({});
  const bForm = (actionPath, inner, submitId, submitLabel, opts = {}) => `<form class="pb-bd-form" method="post" action="/__ioi/pipeline${actionPath}">
      <input type="hidden" name="ontology" value="${esc(oid)}">
      <input type="hidden" name="return" value="${esc(bHere)}">
      ${inner}
      ${opts.confirm ? `<label class="pb-bd-confirm"><input type="checkbox" name="confirm" value="1" required> ${esc(opts.confirm)}</label>` : ""}
      <button id="${submitId}" class="pb-btn ${opts.ghost ? "ghost" : "primary"}" type="submit">${esc(submitLabel)}</button>
    </form>`;
  const bChip = (key, label) => {
    const order = ["review", "lease", "session", "open", "execute", "done"];
    const cur = order.indexOf(buildStage === "ended" ? "review" : buildStage);
    const me = order.indexOf(key);
    return `<span class="pb-bd-chip${me === cur ? " on" : me < cur ? " done" : ""}">${esc(label)}</span>`;
  };
  const bHistory = (rec, title) => rec ? `<div class="ioi-tray-hd">${esc(title)} — receipted history (refusals included)</div>` + trayTable(["at", "op", "summary", "receipt"], (rec.history || []).slice(-8).map((h) => [esc(h.at || ""), icode(h.op || ""), esc(redactUrls(h.summary)), icode(h.receipt_ref || "")])) : "";
  const custodyNote = ["scm_credential_required", "execution_credential_unresolved", "credential_unresolved"].includes((sel.banner || {}).refused || "")
    ? `<div class="pb-ihint pb-warnhint">The connector holds <b>no resolvable sealed credential</b> for this crossing. Resolve it in <a href="/__ioi/connections">connector custody (Developer Console)</a> — Pipeline never accepts or displays credential material. Then re-run this stage.</div>` : "";
  const challengePanel = (kindLabel, toolPrefix) => (sel.challenge_policy && sel.challenge_request) ? `<div class="pb-bd-challenge" id="pb-bd-challenge">
      <div class="ioi-tray-hd">Wallet authority challenge — ${esc(kindLabel)} (sign OUTSIDE this surface)</div>
      <div class="pb-irow"><span class="pb-ik">policy hash</span><span class="pb-iv">${icode(sel.challenge_policy)}</span></div>
      <div class="pb-irow"><span class="pb-ik">request hash</span><span class="pb-iv">${icode(sel.challenge_request)}</span></div>
      <div class="pb-irow"><span class="pb-ik">allowed tools</span><span class="pb-iv">${(pl0 ? pl0.requested_operations || [] : []).map((op) => icode(`${toolPrefix}.${op}`)).join(" ") || "—"}</span></div>
      <div class="pb-irow"><span class="pb-ik">resource refs</span><span class="pb-iv">${pl0 ? [pl0.data_source_ref, pl0.connector_mapping_ref, pl0.policy_view_ref, pl0.transformation_run_ref, pl0.ontology_projection_ref].filter(Boolean).map(icode).join(" ") : "—"}</span></div>
      <div class="pb-ihint">The hashes are the daemon's 403 challenge VERBATIM (deterministic public commitments over the declared plan — the scope rows above are that same declaration). Sign them with an external wallet and paste the grant JSON below: it is forwarded to the daemon <b>once</b> and dropped — never persisted, logged, or echoed. The refusal itself is receipted on the record history below.</div>
    </div>` : "";
  const grantForm = (actionPath, submitId, extraInputs) => bForm(actionPath,
    `${extraInputs || ""}<textarea class="pb-bd-grant" name="wallet_approval_grant" rows="4" placeholder="paste the externally signed wallet_approval_grant JSON" aria-label="Signed wallet approval grant"></textarea>`,
    submitId, "Submit signed grant");
  const requestForm = (actionPath, submitId, label, extraInputs) => bForm(actionPath, extraInputs || "", submitId, label, { ghost: true });
  const sessInput = `<input type="hidden" name="connector_session_id" value="${esc(sessSel)}">`;
  const buildPane = (() => {
    if (!paneKey) return "";
    const notes = [
      invalidBuildPane ? `Unknown pane <code>${esc(sel.pane)}</code>` : "",
      invalidRun ? `Unknown run <code>${esc(sel.run)}</code> — failed closed to review` : "",
      invalidSession ? `Unknown/mismatched session <code>${esc(sel.session)}</code> — dropped` : "",
    ].filter(Boolean).map((n) => `<div class="pb-ihint pb-warnhint">${n}</div>`).join("");
    const chips = `<div class="pb-bd-chips">${bChip("review", "Review")}${bChip("lease", "Run + lease")}${bChip("session", "Session")}${bChip("open", "Sealed open")}${bChip("execute", "Execute")}${bChip("done", "Registered")}</div>`;
    const crumb = semanticBreadcrumb([{ label: selected ? (selected.domain || selected.id) : "ontology", href: managerLink({ ontology: oid }) }, { label: "Governed build" }]);
    let body = "";
    if (buildStage === "review") {
      const rows = readyChecks.map((c) => `<tr><td>${esc(c.label)}</td><td>${c.ok ? '<span class="pb-live">ready</span>' : '<span class="pb-declared">missing</span>'}</td><td>${c.ok ? "" : `<a href="${stateHref({ node: c.node, pane: "", run: "", session: "", tab: "" })}">Go to node</a> · <a href="${managerLink({ ontology: oid })}">Ontology Manager</a>`}</td></tr>`).join("");
      const review = pl0 ? [
        irow("source origin", d0 ? safeOrigin(d0.endpoint || "") : "—"),
        irow("object type", m0 ? `${icode(m0.object_type_id || "—")} · <a href="${managerLink({ ontology: oid, section: "object-types", definitionKind: "object-type", definitionId: m0.object_type_id })}">definition</a>` : "—"),
        irow("fields", m0 ? [m0.key_mapping && `${icode(m0.key_mapping.property_id)} (key)`, m0.title_mapping && `${icode(m0.title_mapping.property_id)} (title)`, ...(m0.field_mappings || []).map((f) => icode(f.property_id))].filter(Boolean).join(" ") : "—"),
        irow("purpose", esc(pl0.purpose || "—")),
        irow("operations", (pl0.requested_operations || []).map(icode).join(" ") || "—"),
        irow("TTL", `${esc(String(pl0.ttl_seconds ?? "—"))}s`),
        irow("obligations", v0 ? `evaluation ${icode(v0.evaluation_posture || "—")} · export ${icode(v0.export_posture || "—")}${v0.retention_posture ? ` · retention ${icode(v0.retention_posture)}` : ""}` : "—"),
        irow("connector", coveringConnector ? `${icode(coveringConnector.connector_id || coveringConnector.id)} covers the source origin` : `<span class="pb-declared">none covers the source</span> — declare one in <a href="/__ioi/connections">connector custody</a>`),
        irow("row limit", `bounded 1–500 (set at execute; default 100) — exactly ONE read of the declared endpoint`),
        irow("standing output", mset ? `${icode(mset.ref || mset.id)} already registered — executing again materializes a NEW set under a NEW governed run (the prior set stands until reset)` : "none — first build"),
      ].join("") : "";
      const resume = resumableRun ? `<div class="pb-ihint">A non-terminal run already cites this plan — <a href="${stateHref({ run: resumableRun.id })}">resume run ${icode(resumableRun.id)}</a> (duplicates are never minted).</div>` : "";
      const cta = !buildReady
        ? `<button class="pb-btn primary" disabled title="${esc(`missing: ${missingForBuild.join(" · ")}`)}" data-ioi-disabled-reason="${esc(`the ladder is not coherent-ready — missing: ${missingForBuild.join(" · ")}`)}">Admit materializing run</button>`
        : resumableRun ? ""
        : bForm("/actions/admit-run", `<input type="hidden" name="capability_lease_plan_id" value="${esc(pl0 ? pl0.id : "")}"><input type="hidden" name="name" value="${esc(`governed build — ${selected ? selected.domain || selected.id : ""}`)}">`, "pb-bd-admit", "Admit materializing run");
      body = `<div class="ioi-tray-hd">Review — the declared ladder this build will consume</div><table class="pb-table"><thead><tr><th>rung</th><th>state</th><th>owner</th></tr></thead><tbody>${rows}</tbody></table>${review}${resume}${cta}`;
    } else if (buildStage === "lease") {
      body = irow("materializing run", `${icode(runRec.ref || runRec.id)} · status ${icode(runRec.status)}`)
        + irow("plan", icode(runRec.capability_lease_plan_id || ""))
        + challengePanel("materializing-run lease", "odk.materialize")
        + custodyNote
        + requestForm(`/${enc(runSel)}/submit-lease-grant`, "pb-bd-lease-request", sel.challenge_policy ? "Re-show challenge (receipted refusal)" : "Request lease — surfaces the wallet challenge")
        + (sel.challenge_policy ? grantForm(`/${enc(runSel)}/submit-lease-grant`, "pb-bd-lease-submit") : "")
        + bForm(`/${enc(runSel)}/cancel-run`, "", "pb-bd-cancel", "Cancel run", { confirm: "cancel this planned run (terminal, receipted)", ghost: true })
        + bHistory(runRec, "Run");
    } else if (buildStage === "session") {
      body = irow("materializing run", `${icode(runRec.ref || runRec.id)} · ${icode(runRec.status)} · lease ${icode((runRec.lease || {}).lease_id || "")}`)
        + (coveringConnector
          ? bForm(`/${enc(runSel)}/admit-session`, `<input type="hidden" name="connector_id" value="${esc(coveringConnector.connector_id || coveringConnector.id)}"><input type="hidden" name="name" value="${esc(`governed build session — ${selected ? selected.domain || selected.id : ""}`)}">`, "pb-bd-admit-session", "Admit connector session")
          : `<div class="pb-ihint pb-warnhint">No registered connector covers the declared source origin — declare one in <a href="/__ioi/connections">connector custody</a>; the daemon re-checks coverage at every stage (confused-deputy fail-closed).</div>`)
        + bForm(`/${enc(runSel)}/release-lease`, "", "pb-bd-release", "Release lease", { confirm: "release the held lease before execution (terminal for this run, receipted)", ghost: true })
        + bHistory(runRec, "Run");
    } else if (buildStage === "open") {
      body = irow("session", `${icode(sessRec.ref || sessRec.id)} · status ${icode(sessRec.status)} · connector ${icode(sessRec.connector_id || "")}`)
        + challengePanel("sealed connector session", "odk.session")
        + custodyNote
        + requestForm(`/${enc(runSel)}/submit-session-grant`, "pb-bd-open-request", sel.challenge_policy ? "Re-show challenge (receipted refusal)" : "Open sealed session — resolves the credential server-side, then surfaces the wallet challenge", sessInput)
        + (sel.challenge_policy ? grantForm(`/${enc(runSel)}/submit-session-grant`, "pb-bd-open-submit", sessInput) : "")
        + bHistory(sessRec, "Session") + bHistory(runRec, "Run");
    } else if (buildStage === "execute") {
      body = irow("sealed session", `${icode((sessRec.session || {}).session_ref || sessRec.id)} · credential material held: <b>${(sessRec.session || {}).credential_material === true}</b>`)
        + irow("bounded read", `exactly ONE GET of ${d0 ? safeOrigin(d0.endpoint || "") : "the declared endpoint"} · redirects refused · all-or-nothing row validation`)
        + bForm(`/${enc(runSel)}/execute`, `${sessInput}<label class="pb-bd-limit">row limit <input type="number" name="limit" min="1" max="500" value="100"></label>`, "pb-bd-execute", "Execute materialization", { confirm: "execute ONE bounded read under the held lease + sealed session (receipted before registration)" })
        + bForm(`/${enc(runSel)}/release-session`, sessInput, "pb-bd-release-session", "Release session", { confirm: "release the sealed session (terminal for the session, receipted)", ghost: true })
        + bHistory(sessRec, "Session") + bHistory(runRec, "Run");
    } else if (buildStage === "done") {
      body = irow("registered set", setForRun ? `${icode(setForRun.ref || setForRun.id)} · <b>${esc(String(setForRun.count ?? 0))}</b> objects` : "executed — the set was since reset (honest note; receipts below stand)")
        + (setForRun ? irow("pre-output receipt", icode(setForRun.pre_output_receipt_ref || "")) : "")
        + irow("open in", `<a href="${stateHref({ node: "materialized", tab: "preview", pane: "", run: "", session: "" })}#pb-preview">Preview rows</a>${setForRun ? ` · <a href="${objectSetLink(oid, setForRun.id)}">Explorer set</a> · <a href="${lineageLink(oid, setForRun.id)}">Lineage</a> · <a href="${vertexLink(oid, setForRun.id)}">Vertex</a> · <a href="${provenanceSetLink(setForRun.id)}">Provenance</a>` : ""}`)
        + bHistory(runRec, "Run") + (sessRec ? bHistory(sessRec, "Session") : "");
    } else { // ended
      body = `<div class="pb-ihint">This run ended before execution (${icode(runRec ? runRec.status : "")}${sessRec ? ` · session ${icode(sessRec.status)}` : ""}) — receipts below stand; start a fresh review to build.</div>`
        + `<a class="pb-btn ghost" href="${stateHref({ run: "", session: "" })}">Back to review</a>`
        + bHistory(runRec, "Run") + (sessRec ? bHistory(sessRec, "Session") : "");
    }
    return `<div id="pb-build" class="pb-bd">${crumb}${chips}${notes}${body}
      <div class="pb-gapnote">This workflow crosses ONLY existing daemon authorities (MaterializingRun → wallet-approved CapabilityLease → sealed ConnectorSession → ONE bounded execute). No PipelineBuild plane exists; grants are pasted from an external wallet, forwarded once, and dropped — the serve holds no signer (dev test signer only under its explicit flag).</div></div>`;
  })();
  const trayBody = paneKey ? buildPane
    : trayTabKey === "warnings" ? warningsPanel
    : trayTabKey === "suggestions" ? suggestionsPanel
    : trayTabKey === "preview" ? previewPanel
    : inspectorMode ? nodeDetailPanel
    : outputSel ? outputDetailPanel
    : selectionEmpty;
  const gapnote = `<div class="pb-gapnote">Freeform canvas authoring — drag-connect nodes, transform code editor, scheduling, deploy — are <b>reference-only lanes disabled above</b>, not yet wired. Author stages in the <a href="${managerLink({ ontology: oid })}">Ontology Manager</a> (<a href="/__ioi/odk?ontology=${enc(oid)}">ODK substrate</a>); execute via a materializing run. Reference: <a href="/__apps/pipeline">Pipeline Builder capture ↗</a>.</div>`;
  const trayTabLink = (key, icon2, label, extraCls) => `<a class="pb-tab${extraCls ? " " + extraCls : ""}${trayTabKey === key && !paneKey ? " on" : ""}" data-traytab="${key}" href="${stateHref({ tab: key === "selection" ? "" : key, pane: "", run: "", session: "" })}">${bpIcon(icon2)} ${label}${key === "suggestions" ? `<span class="pb-tabpill" title="suggestions count — reference-only lane"></span>` : ""}</a>`;

  // Node quick-action strip + header card (reference on-selection chrome) — rendered in the
  // excluded canvas body, positioned by the client beside the selected node; every action is
  // authoring, so every button is disabled IN PLACE with its reason.
  const qbtn = (icon2, tint, label, reason) => `<button disabled class="pb-qbtn${tint ? " pb-i-" + tint : ""}" title="${esc(reason)}" data-ioi-disabled-reason="${esc(reason)}" aria-label="${esc(label)}">${icon2 === "@aip-grad" ? AIP_GRADIENT_SVG_TOOLBAR : bpIcon(icon2)}</button>`;
  const selNode = inspectorMode ? nodes.find((n) => n.key === selNodeKey) : null;
  const nodeFloat = selNode ? `<div class="pb-nodefloat" id="pb-nodefloat" hidden>
    <div class="pb-nfcol">
    <div class="pb-nfcard"><span class="pb-nficon">${selNode.icon}</span><div><div class="pb-nfname">${esc(selNode.label)}</div><div class="pb-nfsub">${esc(String(selNode.count))} record${selNode.count === 1 ? "" : "s"}</div></div></div>
    <button class="pb-snappill" disabled title="sampling strategies have no daemon plane — preview rows are the set's real bounded objects (named gap)" data-ioi-disabled-reason="sampling strategies have no daemon plane — preview rows are the set's real bounded objects (named gap)">Snapshot ${bpIcon("caret-down", 12)}</button>
    </div>
    <div class="pb-quickstrip">${qbtn("path", "green", "Transform", "transform authoring requires a TransformationRun authoring authority — a named gap")}${qbtn("split-columns", "green", "Split", "split authoring — named gap")}${qbtn("join-table", "cyan", "Join", "join authoring — named gap (no authoring authority)")}${qbtn("add-row-bottom", "rose", "Union", "union authoring — named gap")}${qbtn("@aip-grad", "", "Use LLM", "AIP transform lanes are reference-only (named gap)")}${qbtn("clean", "violet", "Generate", "AIP generation is a reference-only lane (named gap)")}${qbtn("lightbulb", "violet", "Explain", "AIP explanation is a reference-only lane (named gap)")}${qbtn("add", "gold", "Add", "adding downstream nodes is authoring — a named gap")}</div>
  </div>` : "";
  const ctxMenu = `<div class="pb-ctxmenu" id="pb-ctxmenu" hidden>
    <button type="button" id="pb-ctx-open">Open</button>
    <button type="button" id="pb-ctx-copy">Copy record ref</button>
    ${["Rename", "Duplicate", "Remove node", "Color nodes", "Hide nodes"].map((l) => `<button disabled title="node authoring is a named gap — ladder records are authored in the Ontology Manager" data-ioi-disabled-reason="node authoring is a named gap — ladder records are authored in the Ontology Manager">${l}</button>`).join("")}
  </div>`;

  const canvasWrap = `<div class="pb-canvaszone${trayCollapsed ? " pb-traymin" : ""}" id="pb-canvaszone">
    <div class="pb-toolband" role="toolbar" aria-label="Canvas tools"></div>
    ${toolcard}
    ${floatbtns}
    ${legend}
    <div class="pb-canvas" id="pb-canvas">${selected
      ? `<div class="pb-pickrow"><details class="pb-pick"><summary>Pipeline: ${oname} ▾</summary><div class="pb-picklist">${railPipes}</div></details></div><div class="pb-graphwrap">${graphSvg}</div>`
      : `<div class="pb-empty" style="margin:120px auto;max-width:420px">Select or create a pipeline to see its datasource → transform → output graph. <a href="/__ioi/odk/ontologies/new">Create an ontology →</a></div>`}</div>
    ${nodeFloat}
    ${ctxMenu}
    <div class="pb-tray${trayCollapsed ? " pb-collapsed" : ""}" id="pb-preview">
      <div class="pb-traytabs">
        ${paneKey ? `<a class="pb-tab on" data-traytab="build" href="${stateHref({})}">${bpIcon("build")} Build</a>` : ""}
        ${trayTabLink("selection", "panel-table", "Selection preview")}
        ${hasSelection ? trayTabLink("preview", "eye-open", "Preview") : ""}
        ${trayTabLink("suggestions", "clean", "Suggestions", "s2")}
        ${trayTabLink("warnings", "warning-sign", "Pipeline warnings", "warn")}
        <button type="button" class="pb-traycollapse" id="pb-tray-toggle" title="Toggle bottom bar" aria-expanded="${!trayCollapsed}">${bpIcon("double-chevron-down")}</button>
      </div>
      <div class="pb-traybody">${(sel.banner && (sel.banner.acted || sel.banner.refused)) ? (sel.banner.acted
        ? `<div class="pb-ihint pb-bd-ok" id="ap-result">✓ ${esc(sel.banner.acted)} — ${sel.banner.result ? `status ${icode(sel.banner.result)} · ` : ""}receipt ${icode(sel.banner.receipt || "")}${sel.banner.record ? ` · record ${icode(sel.banner.record)}` : ""}</div>`
        : `<div class="pb-ihint pb-warnhint" id="ap-result">✕ refused ${icode(sel.banner.refused)} — ${esc(sel.banner.reason || "")} · state unchanged</div>`) : ""}${trayBody}
        ${trayTabKey === "selection" && !hasSelection ? gapnote : ""}
      </div>
    </div>
  </div>`;

  // ---- RIGHT PANEL (#66) — the outputs panel is STABLE: node selection never replaces it (node
  // truth lives in the tray now, like the reference). The far-right icon strip is the reference's
  // panel-toggle rail: outputs / search / file-tree are real view swaps (?panel=), the other six
  // lanes are disabled in place with their missing plane named. Geometry (386px = 336 + 50 strip)
  // is certified chrome and never moves.
  const mapped = cols.length;
  const stripDef = [
    { icon: "circle-arrow-right", key: "outputs", title: "Pipeline outputs" },
    { icon: "search", key: "search", title: "Search pipeline — real record search" },
    { icon: "split-view", gap: "no branching plane — nothing diffs (named gap)" },
    { icon: "build", gap: "no pipeline deploy exists yet — a named gap" },
    { icon: "settings", gap: "no build-settings plane — Build is the governed ODK ladder (named gap)" },
    { icon: "calendar", gap: "no pipeline scheduler exists yet — a named gap" },
    { icon: "folder-open", key: "tree", title: "Pipeline file tree — the real ladder-record tree" },
    { icon: "form", gap: "pipeline unit tests have no daemon plane — evaluation suites live in Evaluations (named gap)" },
    { icon: "import", gap: "source catalog is the Data Connection surface (owner: /__ioi/data/sources) — duplicate lane disabled (named gap)" },
  ];
  const rstrip = `<div class="pb-rstrip">${stripDef.map((it, i) => {
    const grp = i && i % 3 === 0 ? " g" : "";
    if (it.key) return `<a class="pb-stripico${panelKey === it.key ? " on" : ""}${grp}" data-panel="${it.key}" href="${stateHref({ panel: it.key === "outputs" ? "" : it.key })}" title="${esc(it.title)}">${bpIcon(it.icon)}</a>`;
    return `<span class="pb-stripico${grp} gap" title="${esc(it.gap)}" data-ioi-disabled-reason="${esc(it.gap)}">${bpIcon(it.icon)}</span>`;
  }).join("")}</div>`;
  // Output cards — ALL projections on this pipeline, each a real selection anchor (?output=).
  const outCards = projs.length ? projs.map((p2) => {
    const on = outputSel === p2.id;
    const nCols = (p2.visible_properties || []).length;
    return `<a class="pb-outcard${on ? " pb-outsel" : ""}" data-output="${esc(p2.id)}"${on ? ' aria-current="true"' : ""} href="${stateHref({ output: on ? "" : p2.id, node: "", tab: "" })}"><div class="pb-outcode">${bpIcon("panel-table")} ${esc(p2.name || p2.id)}</div><div class="pb-outsub">${esc(selected ? (selected.domain || selected.id) : "")} · read projection · ${icode(p2.status || "—")}</div><div class="pb-outmapped">✓ ${nCols}/${nCols} column${nCols === 1 ? "" : "s"} mapped</div></a>`;
  }).join("") : `<div class="pb-empty">No read projection on this pipeline yet.</div>`;
  const outputsMain = `<div class="pb-rmain">
      <div class="pb-righthd"><span class="pb-righttitle">Pipeline outputs</span><span class="pb-rhdico gap" title="output settings lanes are authored in the ODK substrate — named gap here" data-ioi-disabled-reason="output settings lanes are authored in the ODK substrate — named gap here">${bpIcon("cog")}</span><span class="pb-rhdico gap" title="layout toggle — named gap" data-ioi-disabled-reason="layout toggle — named gap">${bpIcon("panel-table")}</span><button class="pb-addbtn" disabled title="Adding outputs is authored in the ODK substrate — a named gap here" data-ioi-disabled-reason="Adding outputs is authored in the ODK substrate — a named gap here">${bpIcon("plus")} Add</button></div>
      <div class="pb-rsearch">${bpIcon("search")}<input id="pb-outsearch" placeholder="Search outputs…" aria-label="Search outputs (client-side filter)"></div>
      ${outCards}
      <div class="pb-outstat">${instances} object instance${instances === 1 ? "" : "s"} materialized · ${nodes.filter((n) => n.cls === "missing").length ? nodes.filter((n) => n.cls === "missing").map((n) => esc(n.label) + " not built").join(" · ") : "all ladder stages present"}</div>
      <div class="pb-settings">
        <div class="pb-outboxt">Output settings</div>
        <div class="pb-setrow"><span class="pb-setk">Target ontology</span><span class="pb-setv">${selected ? esc(selected.domain || selected.id) : "No ontology selected"}</span></div>
        <div class="pb-setrow"><span class="pb-setk">Output folder</span><span class="pb-setv">No location selected</span></div>
        <div class="pb-editrow"><a class="pb-editbtn" href="/__ioi/odk?ontology=${enc(oid)}">Edit output settings</a><span class="pb-moreico gap" title="reset is a daemon authority (named gap; deletion lanes are the governed-build PR)" data-ioi-disabled-reason="reset is a daemon authority (named gap; deletion lanes are the governed-build PR)">${bpIcon("more")}</span></div>
      </div>
    </div>`;
  // Search panel — the REAL pipeline-record census, filtered as-you-type (client), every row a
  // node-selection link. Nothing fabricated: rows are the already-loaded ladder records.
  const census = [
    ...dsources.map((x) => ({ name: x.name || x.source_id, id: x.source_id, kind: "data source", node: "datasource" })),
    ...maps.map((x) => ({ name: x.name || x.id, id: x.id, kind: "connector mapping", node: "mapping" })),
    ...views.map((x) => ({ name: x.name || x.id, id: x.id, kind: "policy view", node: "policy" })),
    ...truns.map((x) => ({ name: x.name || x.id, id: x.id, kind: "transformation run", node: "transform" })),
    ...projs.map((x) => ({ name: x.name || x.id, id: x.id, kind: "read projection", node: "projection" })),
    ...plans.map((x) => ({ name: x.name || x.id, id: x.id, kind: "capability lease plan", node: "lease" })),
    ...mruns.map((x) => ({ name: x.name || x.id, id: x.id, kind: "materializing run", node: "lease" })),
    ...sessions.map((x) => ({ name: x.name || x.id, id: x.id, kind: "connector session", node: "lease" })),
    ...osets.map((x) => ({ name: x.name || x.id, id: x.id, kind: "materialized set", node: "materialized" })),
  ];
  const censusRow = (c) => `<a class="pb-srow" data-search="${esc(`${c.name} ${c.id} ${c.kind}`.toLowerCase())}" href="${stateHref({ node: c.node, tab: "", output: "" })}"><b>${esc(c.name)}</b> <code class="pb-icode">${esc(c.id)}</code> <span class="pb-srkind">${esc(c.kind)}</span></a>`;
  const searchMain = `<div class="pb-rmain">
      <div class="pb-righthd"><span class="pb-righttitle">Search pipeline</span></div>
      <div class="pb-rsearch">${bpIcon("search")}<input id="pb-psearch" placeholder="Search term…" aria-label="Search pipeline records"></div>
      <div class="pb-srcount" id="pb-srcount">${census.length} record${census.length === 1 ? "" : "s"} on this pipeline</div>
      <div class="pb-srlist">${census.map(censusRow).join("") || `<div class="pb-empty">No records on this pipeline yet.</div>`}</div>
    </div>`;
  const RUNG_LABEL = { datasource: "Datasource", mapping: "Object mapping", policy: "Policy gate", transform: "Transform plan", projection: "Read projection", lease: "Lease + session", materialized: "Materialized objects" };
  const treeMain = `<div class="pb-rmain">
      <div class="pb-righthd"><span class="pb-righttitle">Pipeline file tree</span></div>
      <div class="pb-srlist">${Object.keys(RUNG_LABEL).map((k) => {
        const rows = census.filter((c) => c.node === k);
        return `<div class="pb-treegrp">${esc(RUNG_LABEL[k])} (${rows.length})</div>${rows.map((c) => `<a class="pb-trow" href="${stateHref({ node: c.node, tab: "", output: "" })}">${esc(c.name)} <code class="pb-icode">${esc(c.id)}</code></a>`).join("") || `<div class="pb-treeempty">no record — missing rung</div>`}`;
      }).join("")}</div>
    </div>`;
  const rightPanel = `<aside class="pb-right">${panelKey === "search" ? searchMain : panelKey === "tree" ? treeMain : outputsMain}${rstrip}</aside>`;

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
    .pb-canvas{position:absolute;inset:51px 0 300px 0;overflow:auto;padding:60px 20px 20px;display:flex;flex-direction:column}
    .pb-canvaszone.pb-traymin .pb-canvas{inset:51px 0 35px 0}
    .pb-canvaszone.pb-traymin .pb-zoomstack{bottom:45px}
    .pb-pickrow{margin:110px 0 14px}
    .pb-pick{position:relative;display:inline-block}
    .pb-pick>summary{list-style:none;cursor:pointer;font-size:13px;color:#5f6b7c;background:#fff;border:1px solid #d3d8de;border-radius:4px;padding:4px 10px}
    .pb-pick>summary::-webkit-details-marker{display:none}
    .pb-picklist{position:absolute;top:32px;left:0;min-width:240px;background:#fff;border:1px solid #e0e3e8;border-radius:8px;box-shadow:0 8px 28px rgba(20,24,31,.14);padding:6px;z-index:20}
    .pb-pipe{display:flex;align-items:center;justify-content:space-between;padding:6px 9px;border-radius:6px;color:#3a3f46}
    .pb-pipe:hover{background:#f1f3f6}.pb-pipe.on{background:#eef2fb;color:#1a1d21;font-weight:600}
    .pb-tag{font-size:10px;padding:1px 6px;border-radius:999px;background:#eafaf1;color:#0e8a53;border:1px solid #8fdcb6}
    .pb-graphwrap{flex:1 1 auto;min-height:220px;overflow:hidden}
    #pb-graph{width:100%;height:100%;display:block;cursor:grab;outline:none}
    #pb-graph.panning{cursor:grabbing}
    .pb-gnode .pb-nbody{fill:#fff}
    .pb-gnode .pb-nstroke{fill:none;stroke:#c5cbd3;stroke-width:3}
    a.pb-node{cursor:pointer}
    a.pb-node:focus{outline:none}
    a.pb-node:focus .pb-nstroke{stroke:#2d72d2;stroke-width:4}
    a.pb-node.pb-nsel .pb-nstroke{stroke:#738191;stroke-width:6}
    .pb-node.pb-missing .pb-nstroke{stroke-dasharray:6 4}
    .pb-gnode .pb-ntext{fill:#fff;font-size:12.5px;font-weight:600}
    .pb-gnode .pb-nsub{fill:#5f6b7c;font-size:11px}
    .pb-gnode .pb-ndeet{fill:#8a909c;font-size:9.5px}
    .pb-edge{stroke:#abb3bf;stroke-width:2;fill:none}
    .pb-tray{position:absolute;left:0;right:0;bottom:0;height:300px;background:#fff;display:flex;flex-direction:column;z-index:5}
    .pb-traytabs{flex:0 0 35px;display:flex;align-items:stretch}
    .pb-tab{display:inline-flex;align-items:center;gap:5px;padding:0 8px;font-size:14px;line-height:16px;font-weight:600;color:#1c2127;border-right:1px solid #dce0e5}
    .pb-tab.s2 svg{color:#7961db}
    .pb-tabpill{width:20px;height:20px;border-radius:4px;background:rgba(143,153,168,.15)}
    .pb-tab svg{color:#5f6b7c}
    .pb-tab.on{background:rgba(138,187,255,.4);color:#215db0}.pb-tab.on svg{color:#215db0}
    .pb-tab.warn{color:#935610}.pb-tab.warn svg{color:#c87619}
    .pb-tab.warn.on{background:rgba(200,118,25,.28);color:#935610}.pb-tab.warn.on svg{color:#c87619}
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
    .pb-stripico.on{background:#dfe0e1}

    .pb-rinspect{overflow:auto}
    .pb-right .ioi-inspector{display:flex;flex-direction:column;min-height:100%}
    .pb-right .ioi-inspector-hd{display:flex;flex-direction:column;gap:2px;padding:8.5px 10px 8px 9px;border-bottom:1px solid #eef0f2}
    .pb-right .ioi-inspector-title{font-size:14px;line-height:18.0013px;font-weight:600;color:#1c2127}
    .pb-right .ioi-inspector-sub{font-size:11px;color:#5f6b7c;font-family:ui-monospace,SFMono-Regular,monospace;word-break:break-all}
    .pb-right .ioi-inspector-body{padding:10px 10px 9px 9px}
    .pb-iback{display:inline-block;font-size:12px;color:#215db0;margin:0 0 10px}
    .pb-irow{display:flex;gap:10px;font-size:12px;line-height:15.4297px;padding:0 0 8px}
    .pb-ik{color:#5f6b7c;width:118px;flex:0 0 118px}
    .pb-iv{color:#1c2127;min-width:0;word-break:break-word}
    .pb-icode{font-family:ui-monospace,SFMono-Regular,monospace;font-size:10.5px;background:#f1f3f6;border-radius:3px;padding:1px 4px;word-break:break-all}
    .pb-redact{color:#8f99a8;font-size:11px}
    .pb-ihint{margin:6px 0 10px;padding:8px 10px;border:1px solid #e5e7eb;border-radius:6px;background:#f7f8fa;color:#5b6270;font-size:11.5px;line-height:1.55}
    .pb-warnhint{border-color:#e8c48d;background:#fdf7ec;color:#935610}
    .pb-traybody .ioi-tray-hd{font-size:12px;font-weight:600;color:#1c2127;margin:0 0 8px}
    .ioi-cmd-disabled{display:inline-flex;align-items:center;height:24px;padding:0 8px;border:1px solid #d3d8de;border-radius:4px;background:#f7f8f8;color:#8f99a8;font:inherit;font-size:12px;cursor:not-allowed}
    .ioi-proof-link{font-size:12px}
    /* #66 interaction chrome — everything below renders in excluded body regions or under
       explicit params; certified-island geometry above is untouched. */
    a.pb-tab{cursor:pointer}
    button.pb-traycollapse{background:none;border:0;cursor:pointer;font:inherit;margin-left:auto;display:inline-flex;align-items:center;padding:0 14px;color:#5f6b7c}
    .pb-tray.pb-collapsed{height:35px}.pb-tray.pb-collapsed .pb-traybody{display:none}
    button.pb-legcaret{background:none;border:0;padding:0;cursor:pointer;color:#5f6b7c;display:inline-flex}
    .pb-legend.pb-lcollapsed .pb-leggrid,.pb-legend.pb-lcollapsed .pb-addcolor{display:none}
    button.pb-legeye{background:none;border:0;padding:0;cursor:pointer;display:inline-flex;color:#5f6b7c;margin:0 7px 0 auto}
    .pb-legrow.off{opacity:.45}
    .pb-ticon.live{cursor:pointer}
    a.pb-stripico{cursor:pointer}
    .pb-subtabs{display:flex;gap:2px;margin:8px 0 10px}
    .pb-subtab{border:0;background:#f1f3f6;border-radius:4px 4px 0 0;padding:5px 12px;font:inherit;font-size:12px;color:#5f6b7c;cursor:pointer}
    .pb-subtab.on{background:rgba(138,187,255,.35);color:#215db0;font-weight:600}
    .pb-subtab[disabled]{color:#a5adba;cursor:not-allowed}
    .pb-trayempty{display:flex;align-items:center;gap:10px;color:#5f6b7c;padding:26px 8px;justify-content:center}
    .pb-sugbanner{padding:10px 12px;border:1px solid #d0e0f5;background:#f0f6ff;border-radius:6px;color:#215db0;font-size:12px;margin:0 0 10px}
    /* hit-transparent: every strip action is a disabled named gap, so the overlay must never
       swallow clicks meant for the node beneath it (reasons stay machine-readable). */
    .pb-nodefloat{position:absolute;z-index:4;display:flex;flex-direction:row;gap:8px;align-items:flex-start;pointer-events:none}
    .pb-nfcol{display:flex;flex-direction:column;gap:6px;align-items:flex-start}
    .pb-traybody .ioi-inspector-hd{display:flex;flex-direction:column;gap:2px;margin:0 0 8px}
    .pb-traybody .ioi-inspector-title{font-size:13px;font-weight:600;color:#1c2127}
    .pb-traybody .ioi-inspector-sub{font-size:11px;color:#5f6b7c;font-family:ui-monospace,SFMono-Regular,monospace;word-break:break-all}
    .pb-nfcard{display:flex;gap:8px;background:#fff;border:1px solid #dfe2e7;border-radius:6px;padding:8px 12px;box-shadow:0 2px 8px rgba(20,24,30,.12);align-items:center}
    .pb-nficon{font-size:18px}.pb-nfname{font-weight:600;font-size:13px}.pb-nfsub{font-size:11px;color:#5f6b7c}
    .pb-snappill{border:0;background:#fff;border-radius:4px;box-shadow:inset 0 0 0 1px rgba(64,72,84,.2);font:inherit;font-size:11px;color:#5f6b7c;padding:3px 8px;cursor:not-allowed;display:inline-flex;align-items:center;gap:4px}
    .pb-quickstrip{display:flex;flex-direction:column;gap:2px;background:#fff;border:1px solid #dfe2e7;border-radius:6px;padding:4px;width:38px;box-shadow:0 2px 8px rgba(20,24,30,.12)}
    .pb-qbtn{display:inline-flex;align-items:center;justify-content:center;width:30px;height:30px;border:0;border-radius:4px;background:#fff;color:#5f6b7c;cursor:not-allowed}
    .pb-ctxmenu{position:fixed;z-index:40;background:#fff;border:1px solid #d8dbe1;border-radius:6px;box-shadow:0 8px 28px rgba(20,24,31,.2);padding:5px;min-width:190px}
    .pb-ctxmenu button{display:block;width:100%;text-align:left;border:0;background:none;font:inherit;font-size:12.5px;padding:6px 10px;border-radius:4px;cursor:pointer;color:#1c2127}
    .pb-ctxmenu button:hover{background:#f1f3f6}
    .pb-ctxmenu button[disabled]{color:#a5adba;cursor:not-allowed}
    .pb-srcount{margin:10px 10px 4px 8px;font-size:11px;color:#7b8494}
    .pb-srlist{overflow:auto;padding:0 8px 8px;min-height:0}
    .pb-srow{display:block;padding:6px 9px;border-radius:6px;font-size:12px;color:#1c2127}
    .pb-srow:hover{background:#f1f3f6}
    .pb-srkind{color:#7b8494;font-size:11px}
    .pb-treegrp{font-size:11px;font-weight:600;color:#7b8494;text-transform:uppercase;letter-spacing:.03em;margin:12px 2px 4px}
    .pb-trow{display:block;padding:4px 9px;border-radius:4px;font-size:12px;color:#1c2127}
    .pb-trow:hover{background:#f1f3f6}
    .pb-treeempty{font-size:11px;color:#a5adba;padding:2px 9px;font-style:italic}
    .pb-outcard.pb-outsel{border-color:#2d72d2;box-shadow:0 0 0 2px rgba(45,114,210,.35)}
    a.pb-outcard{display:block}
    /* governed build pane (#67) — tray-body content, excluded live region */
    .pb-bd{max-width:980px}
    .pb-bd-chips{display:flex;gap:6px;margin:8px 0 12px;flex-wrap:wrap}
    .pb-bd-chip{font-size:11px;padding:3px 10px;border-radius:999px;background:#f1f3f6;color:#5f6b7c;border:1px solid #e0e3e8}
    .pb-bd-chip.on{background:rgba(138,187,255,.35);color:#215db0;border-color:#8abbff;font-weight:600}
    .pb-bd-chip.done{background:#eafaf1;color:#0e8a53;border-color:#8fdcb6}
    .pb-bd-form{margin:10px 0;display:flex;flex-direction:column;gap:8px;align-items:flex-start}
    .pb-bd-grant{width:100%;max-width:720px;font-family:ui-monospace,SFMono-Regular,monospace;font-size:10.5px;border:1px solid #d3d8de;border-radius:4px;padding:6px 8px;background:#fbfbfc}
    .pb-bd-confirm{font-size:12px;color:#935610;display:flex;gap:6px;align-items:center}
    .pb-bd-limit{font-size:12px;color:#1c2127;display:flex;gap:6px;align-items:center}
    .pb-bd-limit input{width:72px;border:1px solid #d3d8de;border-radius:4px;padding:3px 6px;font:inherit}
    .pb-bd-challenge{margin:10px 0;padding:10px 12px;border:1px solid #d0e0f5;border-radius:6px;background:#f0f6ff}
    .pb-bd-ok{border-color:#8fdcb6;background:#eafaf1;color:#0e8a53}
    .pb-live{color:#0e8a53;font-weight:600}.pb-declared{color:#935610;font-weight:600}
    /* 1140px embedded-header fix (#66): the command cluster is an absolute 494px box flex never
       sees, so below 1440 it collides with the right cluster. Bare captures are exactly 1440/1920
       wide, so a max-width:1439 rule is capture-invisible; it clamps the box at the right cluster
       and lets the two owner links shrink with ellipsis instead of painting over Actions. */
    @media(max-width:1439px){
      .pb-hmid{width:auto;right:250px;max-width:494px}
      .pb-hmid .pb-btn.link{flex:0 1 auto;min-width:0;display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;line-height:26px}
    }`;

  // Client behavior (#66) — ONE inline script, view-only: pan/zoom/fit on the SVG viewBox,
  // keyboard node navigation, tray/legend collapse + legend eyes persisted via replaceState
  // (embed=1 already rides the URL, so view state never drops embedded mode), sub-tab toggles,
  // client-side filters, and a node context menu whose Open uses the node's PRE-RENDERED href
  // (embed threaded server-side). It mutates nothing authoritative.
  const clientJs = "(function () {\n  var svg = document.getElementById(\"pb-graph\");\n  var initVB = svg ? svg.getAttribute(\"viewBox\") : null;\n  function vb() { return svg.getAttribute(\"viewBox\").split(/\\s+/).map(Number); }\n  function setVB(a) { svg.setAttribute(\"viewBox\", a.join(\" \")); positionFloat(); }\n  function zoom(f) { if (!svg) return; var v = vb(); var cx = v[0] + v[2] / 2, cy = v[1] + v[3] / 2; var w = v[2] * f, h = v[3] * f; setVB([cx - w / 2, cy - h / 2, w, h]); }\n  var zin = document.getElementById(\"pb-zin\"); if (zin) zin.addEventListener(\"click\", function () { zoom(0.8); });\n  var zout = document.getElementById(\"pb-zout\"); if (zout) zout.addEventListener(\"click\", function () { zoom(1.25); });\n  var zfit = document.getElementById(\"pb-zfit\"); if (zfit) zfit.addEventListener(\"click\", function () { if (svg && initVB) { svg.setAttribute(\"viewBox\", initVB); positionFloat(); } });\n  var panning = null;\n  if (svg) {\n    svg.addEventListener(\"pointerdown\", function (e) {\n      if (e.button !== 0 || (e.target.closest && e.target.closest(\"a\"))) return;\n      var v = vb(); panning = { x: e.clientX, y: e.clientY, v: v, k: v[2] / svg.getBoundingClientRect().width };\n      svg.classList.add(\"panning\"); try { svg.setPointerCapture(e.pointerId); } catch (x) {}\n    });\n    svg.addEventListener(\"pointermove\", function (e) {\n      if (!panning) return;\n      setVB([panning.v[0] - (e.clientX - panning.x) * panning.k, panning.v[1] - (e.clientY - panning.y) * panning.k, panning.v[2], panning.v[3]]);\n    });\n    svg.addEventListener(\"pointerup\", function () { panning = null; svg.classList.remove(\"panning\"); });\n    svg.addEventListener(\"wheel\", function (e) { if (!e.ctrlKey) return; e.preventDefault(); zoom(e.deltaY > 0 ? 1.12 : 0.89); }, { passive: false });\n    svg.addEventListener(\"keydown\", function (e) {\n      var anchors = Array.prototype.slice.call(svg.querySelectorAll(\"a.pb-node\"));\n      if (!anchors.length) return;\n      var idx = anchors.indexOf(document.activeElement);\n      var next = null;\n      if (e.key === \"ArrowRight\") next = anchors[Math.min(anchors.length - 1, idx + 1)];\n      else if (e.key === \"ArrowLeft\") next = anchors[idx < 0 ? 0 : Math.max(0, idx - 1)];\n      else if (e.key === \"Home\") next = anchors[0];\n      else if (e.key === \"End\") next = anchors[anchors.length - 1];\n      if (next) { e.preventDefault(); next.focus(); }\n      if (e.key === \"Enter\" && document.activeElement && document.activeElement.classList && document.activeElement.classList.contains(\"pb-node\")) {\n        e.preventDefault(); location.href = document.activeElement.getAttribute(\"href\");\n      }\n    });\n  }\n  function setParam(k, v) { try { var u = new URL(location.href); if (v) u.searchParams.set(k, v); else u.searchParams.delete(k); history.replaceState(null, \"\", u.pathname + u.search + u.hash); } catch (e) {} }\n  var trayT = document.getElementById(\"pb-tray-toggle\");\n  if (trayT) trayT.addEventListener(\"click\", function () {\n    var tray = document.getElementById(\"pb-preview\"), zone = document.getElementById(\"pb-canvaszone\");\n    var min = tray.classList.toggle(\"pb-collapsed\");\n    if (zone) zone.classList.toggle(\"pb-traymin\", min);\n    trayT.setAttribute(\"aria-expanded\", String(!min));\n    setParam(\"tray\", min ? \"0\" : \"\");\n  });\n  var legT = document.getElementById(\"pb-legend-toggle\");\n  if (legT) legT.addEventListener(\"click\", function () {\n    var lg = document.getElementById(\"pb-legend\");\n    var min = lg.classList.toggle(\"pb-lcollapsed\");\n    legT.setAttribute(\"aria-expanded\", String(!min));\n    setParam(\"legend\", min ? \"0\" : \"\");\n  });\n  Array.prototype.forEach.call(document.querySelectorAll(\".pb-legeye\"), function (b) {\n    b.addEventListener(\"click\", function () {\n      var cat = b.getAttribute(\"data-cat\");\n      var row = b.closest(\".pb-legrow\");\n      var off = row.classList.toggle(\"off\");\n      Array.prototype.forEach.call(document.querySelectorAll('a.pb-node[data-category=\"' + cat + '\"]'), function (n) { n.style.display = off ? \"none\" : \"\"; });\n      var hid = Array.prototype.map.call(document.querySelectorAll(\".pb-legrow.off\"), function (r) { return r.getAttribute(\"data-cat\"); }).join(\",\");\n      setParam(\"hide\", hid);\n      b.setAttribute(\"title\", off ? \"Show this color\" : \"Hide this color\");\n    });\n  });\n  Array.prototype.forEach.call(document.querySelectorAll(\".pb-subtab[data-sub]\"), function (b) {\n    b.addEventListener(\"click\", function () {\n      Array.prototype.forEach.call(document.querySelectorAll(\".pb-subtab[data-sub]\"), function (x) { x.classList.toggle(\"on\", x === b); });\n      Array.prototype.forEach.call(document.querySelectorAll(\".pb-subpane\"), function (pn) { pn.hidden = pn.getAttribute(\"data-sub\") !== b.getAttribute(\"data-sub\"); });\n    });\n  });\n  function wireFilter(inputId, rowSel, countId) {\n    var inp = document.getElementById(inputId); if (!inp) return;\n    inp.addEventListener(\"input\", function () {\n      var q = inp.value.toLowerCase(); var n = 0;\n      Array.prototype.forEach.call(document.querySelectorAll(rowSel), function (r) {\n        var hay = (r.getAttribute(\"data-search\") || r.textContent || \"\").toLowerCase();\n        var hit = !q || hay.indexOf(q) >= 0; r.style.display = hit ? \"\" : \"none\"; if (hit) n++;\n      });\n      var c = countId ? document.getElementById(countId) : null; if (c) c.textContent = n + \" match\" + (n === 1 ? \"\" : \"es\");\n    });\n  }\n  wireFilter(\"pb-outsearch\", \".pb-outcard\", null);\n  wireFilter(\"pb-psearch\", \".pb-srow\", \"pb-srcount\");\n  var graphCache = null;\n  function graph() { if (graphCache) return graphCache; var el = document.getElementById(\"pb-graph-data\"); try { graphCache = el ? JSON.parse(el.textContent) : []; } catch (e) { graphCache = []; } return graphCache; }\n  var ctx = document.getElementById(\"pb-ctxmenu\"), ctxNode = null;\n  if (ctx) {\n    document.addEventListener(\"contextmenu\", function (e) {\n      var a = e.target.closest && e.target.closest(\"a.pb-node\");\n      if (!a) { ctx.hidden = true; return; }\n      e.preventDefault(); ctxNode = a;\n      ctx.hidden = false; ctx.style.left = e.clientX + \"px\"; ctx.style.top = e.clientY + \"px\";\n    });\n    document.addEventListener(\"click\", function () { ctx.hidden = true; });\n    document.getElementById(\"pb-ctx-open\").addEventListener(\"click\", function () { if (ctxNode) location.href = ctxNode.getAttribute(\"href\"); });\n    document.getElementById(\"pb-ctx-copy\").addEventListener(\"click\", function () {\n      if (!ctxNode) return;\n      var data = graph(), k = ctxNode.getAttribute(\"data-node\"), rec = null;\n      for (var i = 0; i < data.length; i++) if (data[i].key === k) rec = data[i];\n      if (rec && rec.ref && navigator.clipboard) navigator.clipboard.writeText(rec.ref);\n    });\n  }\n  function positionFloat() {\n    var f = document.getElementById(\"pb-nodefloat\"); if (!f || !svg) return;\n    var g = svg.querySelector(\"a.pb-nsel .pb-gnode\"); if (!g) { f.hidden = true; return; }\n    var r = g.getBoundingClientRect(), zone = document.getElementById(\"pb-canvaszone\");\n    var z = zone.getBoundingClientRect();\n    f.hidden = false;\n    var fh = f.getBoundingClientRect().height || 180;\n    var trayEl = document.getElementById(\"pb-preview\");\n    var limit = (trayEl ? trayEl.getBoundingClientRect().top - z.top : z.height) - fh - 8;\n    f.style.left = Math.min(z.width - 260, r.right - z.left + 10) + \"px\";\n    f.style.top = Math.max(8, Math.min(limit, r.top - z.top - 8)) + \"px\";\n  }\n  positionFloat();\n  window.addEventListener(\"resize\", positionFloat);\n})();";
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Pipeline Builder</title><style>${css}</style></head>
    <body><div class="pb-shell">${globalRail}<div class="pb-main">${header}<div class="pb-work">${canvasWrap}${rightPanel}</div></div></div><script id="pb-graph-data" type="application/json">${graphData}</script><script>${clientJs}</script></body></html>`;
}
