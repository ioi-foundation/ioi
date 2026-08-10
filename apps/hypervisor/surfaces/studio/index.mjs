// Studio — the canonical /studio surface packet (W2.1 next-legs II Leg 1b).
//
// Five views over one module, all read via the shared read-projection client and all mutation via
// the runtime-supplied `daemonFetch` capability (the same admission contract the daemon's studio
// + ODK families speak: owner_ref on create, idempotency_key on every write, expected_head CAS on
// every successor):
//
//   landing        — the T2 agent-estate lens REHOMED read-first (seed preservation: the same
//                    panes/labels the /__ioi/agent-studio readout renders; vendor-authoring
//                    controls render DISABLED with data-ioi-disabled-reason naming the owning
//                    legacy lane — they keep operating there until the W4 cutover). Per OQ-2 the
//                    Machinery links do NOT rehome here (no machinery content on /studio).
//   system-design  — the designer composition map read (composition pattern library + saved
//                    system designs = admitted ODK surface descriptors), read-only, linking to
//                    the protected /__ioi/studio/designer seed.
//   composer       — a Studio intent-frame COMPILE: the form projects a prompt through the
//                    daemon's kernel projection (POST /v1/studio/intent-frame) and renders the
//                    compiled frame. A projection only — nothing is created, admitted or run —
//                    so it rides the read lane (the action runtime's receipt-or-fail-closed
//                    contract is for mutations; a receiptless projection has no place there).
//   blueprints     — list/detail + create/update/promote over the studio blueprints family
//                    (PR #233): derived ids, content_hash readback, admitted_head-seeded CAS
//                    forms, promote COMPOSES a governance ApprovalRequest (status stays draft).
//   descriptors    — surface-descriptor authoring over the SAME admission contract (OQ-1: these
//                    are ordinary governed mutations — daemonFetch, never the CapabilityLease
//                    client; the daemon gates them with identity + owner scope, not a wallet).
//
// Receipt discipline (copied from the approvals module): a mutation success is believed ONLY when
// the daemon's reply carries the family's admission evidence — `receipt_ref` plus the record under
// the declared schema_version. A 2xx without that evidence FAILS CLOSED. Typed refusals render
// verbatim; a CAS head conflict adds the one honest remedy (re-open the record for the fresh head).
import { escHtml } from "../kit.mjs";

const esc = escHtml;
const enc = encodeURIComponent;
const LEGACY_ROUTE = "/__ioi/studio/workbench";

export const meta = {
  slug: "studio-home",
  route: LEGACY_ROUTE,
  verifier: "scripts/verify-hypervisor-studio-journey.mjs",
  certification: "n/a",
};

const BLUEPRINT_SCHEMA = "ioi.hypervisor.studio.blueprint.v1";
const DESCRIPTOR_SCHEMA = "ioi.hypervisor.odk.surface-descriptor.v1";
const BLUEPRINT_PLANE = "/v1/hypervisor/studio/blueprints";
const DESCRIPTOR_PLANE = "/v1/hypervisor/odk/surface-descriptors";

// ---------------------------------------------------------------------------------------------
// load — the lens fan-out plus the per-view detail reads. Every plane degrades INDEPENDENTLY and
// TYPED (the read client's contract): a down plane renders as its code, never a fabricated [].
export async function load(ctx) {
  const { createReadClient } = await import("../read-client.mjs");
  const client = createReadClient({ daemon: ctx.daemon });
  const sp = ctx.url.searchParams;
  const results = await client.readMany({
    // The agent-estate lens planes (the /__ioi/agent-studio T2 readout grammar).
    agents: "/v1/agents",
    profiles: "/v1/hypervisor/agent-runner-profiles",
    conversations: "/v1/hypervisor/agentops/conversations",
    runs: "/v1/hypervisor/agent-run-transcripts",
    model_routes: "/v1/hypervisor/model-routes",
    launch_policies: "/v1/goal-orchestration/ioi-agent/launch-policies",
    memory: "/v1/hypervisor/memory-entries",
    skills: "/v1/hypervisor/skill-entries",
    affinities: "/v1/hypervisor/automation-affinities",
    connectors: "/v1/hypervisor/connectors",
    leases: "/v1/hypervisor/capability-leases",
    proposals: "/v1/hypervisor/memory-mutation-proposals",
    review: "/v1/hypervisor/intelligence/review-queue",
    mining: "/v1/hypervisor/intelligence/outcome-mining",
    improvements: "/v1/hypervisor/intelligence/improvement-proposals",
    odk_overview: "/v1/hypervisor/odk/overview",
    descriptors: DESCRIPTOR_PLANE,
    ontologies: "/v1/hypervisor/odk/domain-ontologies",
    blueprints: BLUEPRINT_PLANE,
  });
  const model = { results };
  // Selected-record detail reads: the GET carries `admitted_head` from the admitted stream — the
  // exact value the CAS forms must send back. Without it the successor forms render disabled.
  const bp = (sp.get("bp") || "").trim();
  if (bp) model.blueprintDetail = await client.read(`${BLUEPRINT_PLANE}/${enc(bp)}`);
  const sd = (sp.get("sd") || "").trim();
  if (sd) model.descriptorDetail = await client.read(`${DESCRIPTOR_PLANE}/${enc(sd)}`);
  // Composer: compile the intent frame through the daemon's kernel projection. A projection READ
  // with a POST verb — the read client carries the init through; nothing is created or admitted.
  const prompt = (sp.get("prompt") || "").trim();
  if ((sp.get("view") || "") === "composer" && prompt) {
    model.frame = await client.read("/v1/studio/intent-frame", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        prompt,
        input: (sp.get("input") || "").trim() || undefined,
        query: (sp.get("query") || "").trim() || undefined,
        execution_mode: (sp.get("execution_mode") || "").trim() || undefined,
      }),
    });
  }
  return model;
}

// ---------------------------------------------------------------------------------------------
// actions — the declared mutation contract. Every write is an owner-scoped admitted mutation on
// the daemon (identity from the forwarded session via daemonFetch; owner_ref asked of the
// operator, never invented; idempotency_key minted per rendered form; expected_head threaded from
// the record's GET). `receipt` names the record schema the module validates on success.
const BP_AUTHORITY = { plane: "studio.blueprints", operation: "POST|PATCH /v1/hypervisor/studio/blueprints" };
const SD_AUTHORITY = { plane: "odk.surface-descriptors", operation: "POST|PATCH /v1/hypervisor/odk/surface-descriptors" };
export const actions = [
  { id: "create-blueprint", method: "POST", route: "/actions/create-blueprint", fields: ["owner_ref", "idempotency_key", "name", "description", "graph_json", "layout_ref"], fieldMax: 8192, context: [], authority: BP_AUTHORITY, receipt: BLUEPRINT_SCHEMA, confirm: false, success: "return-to-surface", refusal: "typed-banner" },
  { id: "update-blueprint", method: "POST", route: "/:id/update", fields: ["idempotency_key", "expected_head", "name", "description", "graph_json", "layout_ref"], fieldMax: 8192, context: ["id"], authority: BP_AUTHORITY, receipt: BLUEPRINT_SCHEMA, confirm: false, success: "return-to-surface", refusal: "typed-banner" },
  { id: "promote-blueprint", method: "POST", route: "/:id/promote", fields: ["idempotency_key", "expected_head", "reason"], context: ["id"], authority: { plane: "studio.blueprints+governance.approval-requests", operation: "POST /v1/hypervisor/studio/blueprints/:id/promote (composes an ApprovalRequest)" }, receipt: BLUEPRINT_SCHEMA, confirm: false, success: "return-to-surface", refusal: "typed-banner" },
  { id: "create-descriptor", method: "POST", route: "/actions/create-descriptor", fields: ["owner_ref", "idempotency_key", "name", "description", "composition_pattern", "ontology_ref"], context: [], authority: SD_AUTHORITY, receipt: DESCRIPTOR_SCHEMA, confirm: false, success: "return-to-surface", refusal: "typed-banner" },
  { id: "update-descriptor", method: "POST", route: "/:id/update-descriptor", fields: ["idempotency_key", "expected_head", "name", "description", "composition_pattern"], context: ["id"], authority: SD_AUTHORITY, receipt: DESCRIPTOR_SCHEMA, confirm: false, success: "return-to-surface", refusal: "typed-banner" },
];

// One typed result per action. Success carries the daemon's admission evidence (receipt_ref) or
// fails CLOSED; refusal carries the daemon's typed code/message verbatim with state untouched.
export async function handleAction({ action, id, fields, daemonFetch }) {
  if (typeof daemonFetch !== "function") {
    return { kind: "failure", http: 500, code: "identity_capability_missing", message: "the action runtime supplied no request-scoped daemon capability — refusing to mutate without the caller's identity" };
  }
  // `graph` is authored as JSON text in the form; it must parse to a plain object BEFORE the
  // daemon sees it — forwarding unparseable text would surface as a transport error, not the
  // typed shape refusal the operator can act on. Shape-checking only; never authority.
  let graph;
  if (fields.graph_json !== undefined && String(fields.graph_json).trim() !== "") {
    try {
      graph = JSON.parse(fields.graph_json);
    } catch {
      return { kind: "refusal", http: 400, code: "studio_graph_json_unparseable", message: "the graph document is not valid JSON — nothing was sent" };
    }
    if (!graph || typeof graph !== "object" || Array.isArray(graph)) {
      return { kind: "refusal", http: 400, code: "studio_graph_json_invalid", message: "the graph document must be a JSON object — nothing was sent" };
    }
  }
  const view = action.id.endsWith("descriptor") ? "descriptors" : "blueprints";
  const back = (recordId, key) => `${LEGACY_ROUTE}?view=${view}${recordId ? `&${key}=${enc(recordId)}` : ""}`;
  let path = "";
  let method = "POST";
  const body = { idempotency_key: fields.idempotency_key };
  if (action.id === "create-blueprint") {
    path = BLUEPRINT_PLANE;
    body.owner_ref = fields.owner_ref;
    body.name = fields.name;
    if (fields.description !== undefined) body.description = fields.description;
    if (graph !== undefined) body.graph = graph;
    if (fields.layout_ref) body.layout_ref = fields.layout_ref;
  } else if (action.id === "update-blueprint") {
    path = `${BLUEPRINT_PLANE}/${enc(id)}`;
    method = "PATCH";
    body.expected_head = fields.expected_head;
    if (fields.name !== undefined) body.name = fields.name;
    if (fields.description !== undefined) body.description = fields.description;
    if (graph !== undefined) body.graph = graph;
    if (fields.layout_ref) body.layout_ref = fields.layout_ref;
  } else if (action.id === "promote-blueprint") {
    path = `${BLUEPRINT_PLANE}/${enc(id)}/promote`;
    body.expected_head = fields.expected_head;
    if (fields.reason) body.reason = fields.reason;
  } else if (action.id === "create-descriptor") {
    path = DESCRIPTOR_PLANE;
    body.owner_ref = fields.owner_ref;
    body.name = fields.name;
    if (fields.description !== undefined) body.description = fields.description;
    body.composition_pattern = fields.composition_pattern;
    body.ontology_ref = fields.ontology_ref;
  } else if (action.id === "update-descriptor") {
    path = `${DESCRIPTOR_PLANE}/${enc(id)}`;
    method = "PATCH";
    body.expected_head = fields.expected_head;
    if (fields.name !== undefined) body.name = fields.name;
    if (fields.description !== undefined) body.description = fields.description;
    if (fields.composition_pattern) body.composition_pattern = fields.composition_pattern;
  } else {
    return { kind: "failure", http: 500, code: "action_unknown", message: `undeclared action '${action.id}'` };
  }
  const response = await daemonFetch(path, {
    method,
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  }).catch(() => null);
  if (!response) return { kind: "failure", http: 502, code: "daemon_unavailable", message: "the daemon did not answer — nothing was changed" };
  const payload = await response.json().catch(() => null);
  if (!payload) return { kind: "failure", http: 502, code: "daemon_reply_unreadable", message: `the daemon answered ${response.status} without a readable body — do not trust the mutation` };
  if (payload.ok !== true) {
    // The daemon's typed refusal, VERBATIM — both body shapes the families answer with
    // ({error:{code,message}} on validation, flat {code,message} on scope/admission refusals).
    const code = payload.error?.code || payload.code || `http_${response.status}`;
    let message = payload.error?.message || payload.message || payload.reason || "refused — state unchanged";
    if (code === "event_stream_expected_head_conflict") {
      message = `${message} — the record moved; re-open it to get the fresh admitted head, then re-submit`;
    }
    return { kind: "refusal", http: response.status || 409, code, message };
  }
  // Admission evidence or nothing: the family's receipt_ref plus the record under its declared
  // schema_version. A 2xx missing either is NOT a success — fail closed.
  const record = payload.blueprint || payload.surface_descriptor || null;
  const receiptRef = typeof payload.receipt_ref === "string" ? payload.receipt_ref : "";
  if (!record || record.schema_version !== action.receipt || !receiptRef) {
    return { kind: "failure", http: 502, code: "receipt_missing", message: `the mutation answered 2xx without the ${action.receipt} record + receipt_ref admission evidence — failing closed (do not trust the mutation)` };
  }
  return {
    kind: "success",
    status: action.id === "promote-blueprint" ? (record.promote_state || record.status || "") : (record.status || ""),
    created: record.id || "",
    receipt_ref: receiptRef,
    redirect: back(record.id || id, view === "descriptors" ? "sd" : "bp"),
  };
}

// ---------------------------------------------------------------------------------------------
// render helpers
const pill = (cls, label) => `<span class="pill ${cls}">${esc(label)}</span>`;
const code = (v) => (v ? `<code>${esc(String(v))}</code>` : "—");
const shortHash = (h) => { const s = String(h || ""); return s.length > 22 ? `${s.slice(0, 22)}…` : s; };
// A read-client result rendered honestly: rows when ok, a typed absence when degraded.
const degraded = (result) => `<div class="empty">unavailable — <code>${esc(result?.code || "daemon_unavailable")}</code> (${esc(result?.message || "the plane did not answer")})</div>`;
const rowsOf = (result, key) => (result?.ok ? (Array.isArray(result.payload?.[key]) ? result.payload[key] : (Array.isArray(result.payload) ? result.payload : [])) : null);
// Seed preservation: an authoring control that still lives on its legacy owner lane renders
// DISABLED here with the reason machine-readable (data-ioi-disabled-reason), never removed and
// never silently wired to a second authority path.
const disabledCtl = (label, reason) => `<button class="act ghost" type="button" disabled data-ioi-disabled-reason="${esc(reason)}">${esc(label)}</button>`;
const LEGACY_STUDIO_REASON = "vendor-authoring control — operates on the /__ioi/agent-studio owner lane until the Studio W4 cutover (seed preservation)";
const pickv = (o, a, b) => (o && (o[a] !== undefined ? o[a] : o[b])) ?? "";

function banner(sp) {
  const acted = sp.get("acted") || "";
  const receipt = sp.get("receipt") || "";
  const refused = sp.get("refused") || "";
  const reason = sp.get("reason") || "";
  const result = sp.get("result") || "";
  const record = sp.get("record") || "";
  if (acted && receipt) {
    return `<div id="ap-result" class="banner ok-banner" tabindex="-1"><b>${esc(acted)}</b> recorded${result ? ` — <b>${esc(result)}</b>` : ""}${record ? ` · record <code>${esc(record)}</code>` : ""} · receipt <code>${esc(receipt)}</code> · <a href="/__ioi/work-ledger">proof stream</a></div>`;
  }
  if (refused) {
    return `<div id="ap-result" class="banner no-banner" tabindex="-1">refused: <code>${esc(refused)}</code>${reason ? ` — ${esc(reason)}` : ""} · <b>state unchanged</b></div>`;
  }
  return "";
}

// The landing's agent-estate lens — the /__ioi/agent-studio readout grammar, read-first.
function agentEstate(model, base, sp) {
  const r = model.results;
  const agents = rowsOf(r.agents, "agents");
  if (agents === null) return `<h2>Agent estate</h2>${degraded(r.agents)}`;
  const q = (sp.get("q") || "").trim();
  const qn = q.toLowerCase();
  const filtered = qn ? agents.filter((a) => `${a.id || ""} ${pickv(a, "model_id", "modelId")}`.toLowerCase().includes(qn)) : agents;
  const selId = sp.get("agent") || "";
  const sel = filtered.find((a) => a.id === selId) || filtered[0] || agents[0] || null;
  const agentShort = (idv) => { const s = String(idv || ""); return s.length > 30 ? `${s.slice(0, 30)}…` : s; };
  const list = filtered.length
    ? filtered.map((a) => `<a class="asrow${sel && a.id === sel.id ? " sel" : ""}" href="${base}&agent=${enc(a.id || "")}${q ? `&q=${enc(q)}` : ""}"><div class="nm">${esc(agentShort(a.id))} ${pill((a.status || "") === "active" ? "ok" : "muted", a.status || "—")}</div><div class="ml">${esc(pickv(a, "model_id", "modelId") || "—")}</div></a>`).join("")
    : `<div class="empty">No agents match “${esc(q)}”.</div>`;
  const search = `<form method="get" action="${base.split("?")[0]}"><input type="hidden" name="view" value=""><input class="asearch" name="q" value="${esc(q)}" placeholder="Search agents by id or model…"></form>`;
  if (!agents.length) {
    return `<h2>Agent estate</h2><div class="empty">No agents yet. An agent is created when you start a session or run an automation — once one exists it will appear here with its model route, runtime posture, and activity.</div>`;
  }
  const a = sel || {};
  const dec = a.model_route_decision || a.modelRouteDecision || {};
  const rc = a.runtime_controls || a.runtimeControls || {};
  const rcm = rc.model || {};
  const subs = (a.options && (a.options.subagentNames || a.options.subagent_names)) || [];
  const receipts = a.receipt_refs || a.receiptRefs || [];
  const mcp = pickv(a, "mcpRegistry", "mcp_registry");
  const cfg = (label, val) => `<dt>${label}</dt><dd>${val}</dd>`;
  const grid = `<dl class="grid">
    ${cfg("Agent id", code(a.id))}
    ${cfg("Status", pill((a.status || "") === "active" ? "ok" : "muted", a.status || "—"))}
    ${cfg("Model", code(pickv(a, "model_id", "modelId")))}
    ${cfg("Selected model", code(pickv(rcm, "selected_model") || pickv(a, "requestedModelId", "requested_model_id")))}
    ${cfg("Mode · approval", `${esc(rc.mode || "—")} · ${esc(rc.approval_mode || "—")}`)}
    ${cfg("Reasoning effort", esc(pickv(rcm, "reasoning_effort") || pickv(rc, "reasoning_effort") || "default"))}
    ${cfg("Working dir", code(a.cwd))}
    ${cfg("MCP registry", mcp ? code(mcp) : `<span class="sub" style="margin:0">none bound</span>`)}
    ${cfg("Subagents", subs.length ? subs.map((s) => `<code>${esc(s)}</code>`).join(" ") : `<span class="sub" style="margin:0">none</span>`)}
    ${cfg("Created · updated", `${esc(pickv(a, "created_at", "createdAt") || "—")}<br><span class="sub" style="margin:0">${esc(pickv(a, "updated_at", "updatedAt") || "")}</span>`)}
  </dl>`;
  const posture = `<div class="chips"><span class="chiplabel">Runner posture</span>
    ${pill("muted", `runtime: ${a.runtime || pickv(dec, "local_remote_placement") || "—"}`)}
    ${pill("muted", `provider: ${pickv(dec, "provider_kind") || "—"}`)}
    ${pill(pickv(dec, "privacy_posture") === "local_only" ? "ok" : "muted", `privacy: ${pickv(dec, "privacy_posture") || "—"}`)}
    ${pill("muted", `capability: ${dec.capability || "—"}`)}
    ${pickv(dec, "never_send_auto_upstream") === true ? pill("ok", "never auto-upstream") : ""}
  </div>`;
  const routeGrid = `<dl class="grid">
    ${cfg("Route", code(pickv(a, "model_route_id", "modelRouteId")))}
    ${cfg("Endpoint", code(pickv(a, "model_route_endpoint_id", "modelRouteEndpointId")))}
    ${cfg("Provider", code(pickv(a, "model_route_provider_id", "modelRouteProviderId")))}
    ${cfg("Route receipt", code(pickv(a, "model_route_receipt_id", "modelRouteReceiptId")))}
    ${cfg("Proof receipts", receipts.length ? `${receipts.length} ref(s)` : "—")}
  </dl>`;
  const convs = rowsOf(r.conversations, "conversations");
  const runs = rowsOf(r.runs, "runs");
  const latestRun = runs ? runs.slice().sort((x, y) => String(pickv(y, "recorded_at", "started_at") || "").localeCompare(String(pickv(x, "recorded_at", "started_at") || "")))[0] : null;
  const recentConv = convs ? convs[0] : null;
  const activity = `<div class="row">
    <a class="act" href="/__ioi/automations/new">Use in Automation →</a>
    ${recentConv && recentConv.environment_id ? `<a class="act ghost" href="/details/${enc(recentConv.environment_id)}">Open recent conversation →</a>` : ""}
    ${latestRun && latestRun.run_id ? `<a class="act ghost" href="/__ioi/run-timeline/${enc(latestRun.run_id)}">Open latest run timeline ↗</a>` : ""}
    <span class="sub" style="margin:0">${convs === null ? "conversations unavailable (typed)" : `${convs.length} conversation(s)`} · ${runs === null ? "runs unavailable (typed)" : `${runs.length} recorded run(s)`}</span>
  </div>`;
  return `<h2>Agent estate</h2><div class="asgrid"><div>${search}<div class="aslist">${list}</div></div><div>${grid}${posture}${routeGrid}${activity}</div></div>`;
}

// The System designs pane — the designer composition map read (same pane/labels as the seed's
// renderStudioSystemDesigns; the canvas link targets the PROTECTED /__ioi/studio/designer seed).
function systemDesigns(model) {
  const r = model.results;
  const prettyPattern = (p) => String(p || "").replace(/_/g, " ");
  const patterns = r.odk_overview?.ok ? (r.odk_overview.payload?.composition_patterns || []) : null;
  const designs = rowsOf(r.descriptors, "surface_descriptors");
  const patternLib = patterns === null
    ? degraded(r.odk_overview)
    : (patterns.length
      ? `<div class="chips" style="margin:2px 0 4px">${patterns.map((p) => pill("muted", prettyPattern(p))).join("")}</div>`
      : `<div class="empty">The daemon exposes no composition patterns.</div>`);
  const designRows = designs === null
    ? degraded(r.descriptors)
    : (designs.length
      ? `<table><thead><tr><th>System design</th><th>Pattern</th><th>Ref</th></tr></thead><tbody>${designs.map((d) => `<tr>
          <td><b>${esc(d.name || d.title || d.id || "—")}</b></td>
          <td>${pill("muted", prettyPattern(d.composition_pattern || d.pattern || "—"))}</td>
          <td><code style="font-size:11px">${esc(d.ref || d.surface_descriptor_ref || d.id || "")}</code></td>
        </tr>`).join("")}</tbody></table>`
      : `<div class="empty">No saved system designs yet. Compose one on the <a href="/__ioi/studio/designer">system design canvas →</a>; the daemon persists an admitted design as an ODK surface descriptor.</div>`);
  return `<h2 id="system-designs">System designs</h2>
    <p class="sub" style="margin:-4px 0 12px">The Studio composition plane — a system design composes typed <b>concept / component / resource</b> nodes into an IOI system shape. This is a <b>read-only design map</b> over real composition truth: browse the <a href="/__ioi/studio/designer">Solution Designer seed →</a>; author descriptors in the <a href="?view=descriptors">Descriptor authoring view</a>.</p>
    <h3 style="margin:14px 0 4px;font-size:13px">Composition pattern library <span class="sub" style="text-transform:none;letter-spacing:0;font-weight:400">— the canonical system shapes the daemon recognizes</span></h3>${patternLib}
    <h3 style="margin:16px 0 4px;font-size:13px">Saved system designs <span class="sub" style="text-transform:none;letter-spacing:0;font-weight:400">— admitted ODK surface descriptors</span></h3>${designRows}`;
}

// Harness profiles — the seed's registry table, columns preserved; the planner-admitted
// controls stay on the legacy owner lane and render disabled here with the reason.
function harnessProfiles(model) {
  const profiles = rowsOf(model.results.profiles, "profiles");
  if (profiles === null) return `<h2 id="harness-profiles">Harness profiles</h2>${degraded(model.results.profiles)}`;
  if (!profiles.length) return "";
  const runPill = (state) => pill(state === "runnable" ? "ok" : state === "not_probed" ? "muted" : "warn", state || "not_probed");
  const rows = profiles.map((p) => {
    const lc = p.lifecycle_status || "declared";
    return `<tr>
      <td><b>${esc(p.display_name || p.harness || "—")}</b>${p.default ? ` ${pill("ok", "default")}` : ""}<div style="color:#878a93;font-size:11.5px;margin-top:2px"><code>${esc(p.profile_ref || p.harness || "")}</code></div></td>
      <td>${(p.modes || []).map((m) => esc(m)).join(" · ") || "—"}</td>
      <td>${(p.models || []).map((m) => `<code>${esc(m)}</code>`).join(" ") || "—"}</td>
      <td>${(p.reasoning || []).map(esc).join("/") || "—"}</td>
      <td>${p.tool_use ? "✓" : "—"} · ${p.image_input ? "img" : "—"}</td>
      <td>${pill(String(p.provider_trust || "").startsWith("remote") ? "warn" : "ok", p.provider_trust || "—")}</td>
      <td>${pill(lc === "active" ? "ok" : "muted", lc)}</td>
      <td>${runPill(p.runnability_state)}</td>
      <td>${disabledCtl("Probe", LEGACY_STUDIO_REASON)} ${disabledCtl(lc === "active" ? "Disable" : "Enable", LEGACY_STUDIO_REASON)} ${p.default ? "" : disabledCtl("Set default", LEGACY_STUDIO_REASON)}</td>
    </tr>`;
  }).join("");
  return `<h2 id="harness-profiles">Harness profiles</h2><p class="sub" style="margin:-4px 0 12px">The daemon harness-profile registry — every selectable runtime harness with its capability matrix, probed runnability, and lifecycle. Enable/disable/default are planner-admitted, receipted mutations on the owner lane.</p><table><thead><tr><th>Harness</th><th>Modes</th><th>Models</th><th>Reasoning</th><th>Tools</th><th>Trust</th><th>Lifecycle</th><th>Runnability</th><th>Controls</th></tr></thead><tbody>${rows}</tbody></table>`;
}

// Model routes + launch policies — read summaries of the seed's registry panes; administration
// stays on the owner lane (disabled controls carry the reason).
function modelRoutesPane(model) {
  const routes = rowsOf(model.results.model_routes, "routes");
  if (routes === null) return `<h2 id="model-routes">Model routes</h2>${degraded(model.results.model_routes)}`;
  const rows = routes.length
    ? `<table><thead><tr><th>Route</th><th>Model</th><th>Availability</th><th>Default</th><th>Controls</th></tr></thead><tbody>${routes.map((rt) => {
      const av = rt.availability || {};
      return `<tr><td>${code(rt.route_id || rt.id)}</td><td>${code((rt.model || {}).model_id || rt.model_id)}</td><td>${pill((av.state || "declared") === "available" ? "ok" : "muted", av.state || "declared")}${av.stale ? ` ${pill("muted", "stale")}` : ""}</td><td>${rt.default ? pill("ok", "default") : "—"}</td><td>${disabledCtl("Manage", LEGACY_STUDIO_REASON)}</td></tr>`;
    }).join("")}</tbody></table>`
    : `<div class="empty">No model routes yet — the registry is empty, not fabricated.</div>`;
  return `<h2 id="model-routes">Model routes</h2><p class="sub" style="margin:-4px 0 12px">The real model-route registry — availability is probe evidence, never assumed. Administration (enable · probe · select default) lives on the owner lane.</p>${rows}`;
}

function launchPoliciesPane(model) {
  const policies = rowsOf(model.results.launch_policies, "policies");
  if (policies === null) return `<h2 id="launch-policies">Launch policies</h2>${degraded(model.results.launch_policies)}`;
  const rows = policies.length
    ? `<table><thead><tr><th>Policy</th><th>Status</th><th>Rollout</th><th>Controls</th></tr></thead><tbody>${policies.map((p) => `<tr><td><b>${esc(p.display_name || p.policy_id || "—")}</b><div style="color:#878a93;font-size:11.5px"><code>${esc(p.policy_id || "")}</code></div></td><td>${pill(p.status === "active" ? "ok" : "muted", p.status || "—")}</td><td>${p.rollout ? pill("warn", "learned rollout") : "—"}</td><td>${disabledCtl("Manage", LEGACY_STUDIO_REASON)}</td></tr>`).join("")}</tbody></table>`
    : `<div class="empty">No launch policies yet.</div>`;
  return `<h2 id="launch-policies">Launch policies</h2>${rows}`;
}

// The intelligence cockpit band — the seed's per-plane panes summarized read-first (counts +
// honest degradation); every lifecycle/authoring control stays on the owner lane.
function intelligencePane(model) {
  const r = model.results;
  const fam = (label, result, key) => {
    const rows = rowsOf(result, key);
    return `<tr><td><b>${esc(label)}</b></td><td>${rows === null ? `<span class="sub" style="margin:0">unavailable — <code>${esc(result?.code || "daemon_unavailable")}</code></span>` : `${rows.length} record(s)`}</td><td>${disabledCtl("Author", LEGACY_STUDIO_REASON)}</td></tr>`;
  };
  return `<h2 id="intelligence">Intelligence</h2><p class="sub" style="margin:-4px 0 12px">The agent-intelligence planes — memory, skills, affinities, connectors, capability leases, and the improvement loop. Lifecycle transitions (promote · dispute · archive · propose · approve · apply) are receipted mutations on the owner lane.</p>
  <table><thead><tr><th>Plane</th><th>Records</th><th>Controls</th></tr></thead><tbody>
    ${fam("Memory", r.memory, "entries")}
    ${fam("Skills", r.skills, "skills")}
    ${fam("Affinities", r.affinities, "affinities")}
    ${fam("Connectors", r.connectors, "connectors")}
    ${fam("Capability leases", r.leases, "leases")}
    ${fam("Mutation proposals", r.proposals, "proposals")}
    ${fam("Review queue", r.review, "items")}
    ${fam("Outcome mining", r.mining, "candidates")}
    ${fam("Improvement proposals", r.improvements, "proposals")}
  </tbody></table>`;
}

// ---- Blueprints view ---------------------------------------------------------------------------
function blueprintsView(model, sp) {
  const listResult = model.results.blueprints;
  const rows = rowsOf(listResult, "blueprints");
  const selectedId = (sp.get("bp") || "").trim();
  const mintKey = () => `studio-ui-${globalThis.crypto.randomUUID()}`;
  const ownerField = `<label class="fl">Owner (org:// or project://)<input name="owner_ref" placeholder="org://… or project://…" required title="The single org:// or project:// that owns this record. The daemon admits the write under it and refuses a caller who holds no authority over it."></label>`;
  const list = rows === null
    ? degraded(listResult)
    : (rows.length
      ? `<table><thead><tr><th>Blueprint</th><th>Status</th><th>Promotion</th><th>Content hash</th><th>Updated</th></tr></thead><tbody>${rows.map((b) => `<tr>
          <td><a href="?view=blueprints&bp=${enc(b.id || "")}"><b>${esc(b.name || b.id || "—")}</b></a><div style="color:#878a93;font-size:11.5px"><code>${esc(b.ref || "")}</code></div></td>
          <td>${pill(b.status === "draft" ? "muted" : "ok", b.status || "—")}</td>
          <td>${b.promote_state ? pill("warn", b.promote_state) : "—"}</td>
          <td><code title="${esc(b.content_hash || "")}">${esc(shortHash(b.content_hash))}</code></td>
          <td>${esc(b.updated_at || "—")}</td>
        </tr>`).join("")}</tbody></table>`
      : `<div class="empty">No blueprints yet — draft one below. A blueprint is an authored composition draft; nothing here mounts a surface or grants authority.</div>`);
  const createForm = `<h3 style="margin:18px 0 6px;font-size:13px">Draft a blueprint</h3>
    <form class="aform" method="post" action="${LEGACY_ROUTE}/actions/create-blueprint">
      <input type="hidden" name="idempotency_key" value="${esc(mintKey())}">
      <input type="hidden" name="return" value="${esc(`${LEGACY_ROUTE}?view=blueprints`)}">
      ${ownerField}
      <label class="fl">Name<input name="name" maxlength="200" required></label>
      <label class="fl">Description<input name="description" maxlength="2000"></label>
      <label class="fl">Graph (JSON object, ≤64KiB serialized)<textarea name="graph_json" rows="4" placeholder='{"nodes":[],"edges":[]}'></textarea></label>
      <label class="fl">Layout ref (artifact://…, optional)<input name="layout_ref" maxlength="300" placeholder="artifact://layouts/…"></label>
      <button class="act" type="submit">Create draft</button>
    </form>`;
  let detail = "";
  if (selectedId) {
    const d = model.blueprintDetail;
    if (!d?.ok || d.payload?.ok !== true || !d.payload.blueprint) {
      detail = `<h3 style="margin:18px 0 6px;font-size:13px">Blueprint ${esc(selectedId)}</h3>${d?.ok && d.payload?.ok === false ? `<div class="empty">not found — <code>studio_blueprint_not_found</code></div>` : degraded(d)}`;
    } else {
      const b = d.payload.blueprint;
      const head = d.payload.admitted_head || "";
      const cas = head
        ? `<input type="hidden" name="expected_head" value="${esc(head)}">`
        : "";
      const casNote = head
        ? `<span class="sub" style="margin:0">compare-and-swap against admitted head <code>${esc(shortHash(head))}</code></span>`
        : `<span class="sub" style="margin:0">no admitted head is readable — successor writes are disabled rather than guessed</span>`;
      const dis = head ? "" : " disabled";
      detail = `<h3 id="blueprint-detail" style="margin:18px 0 6px;font-size:13px">Blueprint detail</h3>
      <dl class="grid">
        <dt>Name</dt><dd><b>${esc(b.name || "—")}</b></dd>
        <dt>Ref</dt><dd>${code(b.ref)}</dd>
        <dt>Status</dt><dd>${pill(b.status === "draft" ? "muted" : "ok", b.status || "—")} — a draft never auto-applies; promotion only composes a governance request</dd>
        <dt>Content hash</dt><dd><code data-testid="bp-content-hash">${esc(b.content_hash || "—")}</code></dd>
        <dt>Admitted head</dt><dd><code data-testid="bp-admitted-head">${esc(head || "—")}</code></dd>
        <dt>Owner</dt><dd>${code(b.owner_ref)}</dd>
        <dt>Description</dt><dd>${esc(b.description || "—")}</dd>
        <dt>Layout ref</dt><dd>${b.layout_ref ? code(b.layout_ref) : "—"}</dd>
        <dt>Promotion</dt><dd>${b.promote_state ? `${pill("warn", b.promote_state)} · approval ${code(b.approval_request_ref)} — decide on <a href="/governance/approvals">Approvals</a>` : "not requested"}</dd>
        <dt>Updated</dt><dd>${esc(b.updated_at || "—")}</dd>
      </dl>
      <pre>${esc(JSON.stringify(b.graph ?? {}, null, 2).slice(0, 4000))}</pre>
      <h3 style="margin:16px 0 6px;font-size:13px">Revise</h3>
      <form class="aform" method="post" action="${LEGACY_ROUTE}/${enc(b.id)}/update">
        <input type="hidden" name="idempotency_key" value="${esc(mintKey())}">
        <input type="hidden" name="return" value="${esc(`${LEGACY_ROUTE}?view=blueprints&bp=${enc(b.id)}`)}">
        ${cas}
        <label class="fl">Name<input name="name" maxlength="200" value="${esc(b.name || "")}"${dis}></label>
        <label class="fl">Description<input name="description" maxlength="2000" value="${esc(b.description || "")}"${dis}></label>
        <label class="fl">Graph (JSON object; leave blank to keep the current graph)<textarea name="graph_json" rows="4"${dis}></textarea></label>
        <label class="fl">Layout ref (artifact://…; leave blank to keep)<input name="layout_ref" maxlength="300" value="${esc(b.layout_ref || "")}"${dis}></label>
        <button class="act" type="submit"${dis}>Submit revision</button> ${casNote}
      </form>
      <h3 style="margin:16px 0 6px;font-size:13px">Request promotion</h3>
      <p class="sub" style="margin:0 0 8px">Promotion COMPOSES governance: a real ApprovalRequest (subject <code>${esc(b.ref || "")}</code>, kind <code>studio_blueprint_promotion</code>) is created and linked; the blueprint stays a draft — an approval decision authorizes nothing automatically.</p>
      <form class="aform" method="post" action="${LEGACY_ROUTE}/${enc(b.id)}/promote">
        <input type="hidden" name="idempotency_key" value="${esc(mintKey())}">
        <input type="hidden" name="return" value="${esc(`${LEGACY_ROUTE}?view=blueprints&bp=${enc(b.id)}`)}">
        ${cas}
        <label class="fl">Reason (optional, ≤2000)<input name="reason" maxlength="2000"></label>
        <button class="act" type="submit"${dis}>Request promotion</button> ${casNote}
      </form>`;
    }
  }
  return `<h2 id="blueprints">Blueprints</h2><p class="sub" style="margin:-4px 0 12px">Content-addressed composition drafts (the daemon studio family): every write is an owner-scoped admitted mutation — owner-derived ids, caller idempotency, compare-and-swap successors, receipts. <code>content_hash</code> is the canonical identity of the four authored fields.</p>${list}${detail}${selectedId ? "" : createForm}`;
}

// ---- Descriptor authoring view -----------------------------------------------------------------
function descriptorsView(model, sp) {
  const r = model.results;
  const rows = rowsOf(r.descriptors, "surface_descriptors");
  const patterns = r.odk_overview?.ok ? (r.odk_overview.payload?.composition_patterns || []) : [];
  const ontologies = rowsOf(r.ontologies, "ontologies") || [];
  const selectedId = (sp.get("sd") || "").trim();
  const mintKey = () => `studio-ui-${globalThis.crypto.randomUUID()}`;
  const patternOpts = (cur) => (patterns.length ? patterns : ["list_detail"]).map((p) => `<option value="${esc(p)}"${p === cur ? " selected" : ""}>${esc(String(p).replace(/_/g, " "))}</option>`).join("");
  const list = rows === null
    ? degraded(r.descriptors)
    : (rows.length
      ? `<table><thead><tr><th>Descriptor</th><th>Pattern</th><th>Status</th><th>Ontology</th><th>Updated</th></tr></thead><tbody>${rows.map((d) => `<tr>
          <td><a href="?view=descriptors&sd=${enc(d.id || "")}"><b>${esc(d.name || d.id || "—")}</b></a><div style="color:#878a93;font-size:11.5px"><code>${esc(d.ref || "")}</code></div></td>
          <td>${pill("muted", String(d.composition_pattern || "—").replace(/_/g, " "))}</td>
          <td>${pill(d.status === "draft" ? "muted" : "ok", d.status || "—")}</td>
          <td>${code(d.ontology_ref)}</td>
          <td>${esc(d.updated_at || "—")}</td>
        </tr>`).join("")}</tbody></table>`
      : `<div class="empty">No surface descriptors yet — author one below. A descriptor is a declared composition; nothing here generates or mounts a surface.</div>`);
  const createForm = ontologies.length
    ? `<h3 style="margin:18px 0 6px;font-size:13px">Author a descriptor</h3>
    <form class="aform" method="post" action="${LEGACY_ROUTE}/actions/create-descriptor">
      <input type="hidden" name="idempotency_key" value="${esc(mintKey())}">
      <input type="hidden" name="return" value="${esc(`${LEGACY_ROUTE}?view=descriptors`)}">
      <label class="fl">Owner (org:// or project://)<input name="owner_ref" placeholder="org://… or project://…" required title="The single org:// or project:// that owns this record. The daemon admits the write under it and refuses a caller who holds no authority over it."></label>
      <label class="fl">Name<input name="name" maxlength="200" required></label>
      <label class="fl">Description<input name="description" maxlength="2000"></label>
      <label class="fl">Composition pattern<select name="composition_pattern">${patternOpts("")}</select></label>
      <label class="fl">Ontology<select name="ontology_ref">${ontologies.map((o) => `<option value="${esc(o.ref || "")}">${esc(o.domain || o.id || o.ref || "")}</option>`).join("")}</select></label>
      <button class="act" type="submit">Create descriptor</button>
    </form>`
    : `<div class="empty" style="margin-top:14px">${r.ontologies?.ok ? `Descriptor authoring needs an existing ontology (the daemon requires a resolvable <code>ontology_ref</code>) — create one in the <a href="/ontology/schema">Ontology Manager</a> first.` : `The ontology plane is unavailable (<code>${esc(r.ontologies?.code || "daemon_unavailable")}</code>) — authoring is disabled rather than guessed.`}</div>`;
  let detail = "";
  if (selectedId) {
    const d = model.descriptorDetail;
    if (!d?.ok || d.payload?.ok !== true || !d.payload.surface_descriptor) {
      detail = `<h3 style="margin:18px 0 6px;font-size:13px">Descriptor ${esc(selectedId)}</h3>${d?.ok && d.payload?.ok === false ? `<div class="empty">not found — <code>odk_surface_descriptor_not_found</code></div>` : degraded(d)}`;
    } else {
      const sd = d.payload.surface_descriptor;
      const head = d.payload.admitted_head || "";
      const dis = head ? "" : " disabled";
      const casNote = head
        ? `<span class="sub" style="margin:0">compare-and-swap against admitted head <code>${esc(shortHash(head))}</code></span>`
        : `<span class="sub" style="margin:0">no admitted head is readable — successor writes are disabled rather than guessed</span>`;
      detail = `<h3 id="descriptor-detail" style="margin:18px 0 6px;font-size:13px">Descriptor detail</h3>
      <dl class="grid">
        <dt>Name</dt><dd><b>${esc(sd.name || "—")}</b></dd>
        <dt>Ref</dt><dd>${code(sd.ref)}</dd>
        <dt>Status</dt><dd>${pill(sd.status === "draft" ? "muted" : "ok", sd.status || "—")}</dd>
        <dt>Pattern</dt><dd>${pill("muted", String(sd.composition_pattern || "—").replace(/_/g, " "))}</dd>
        <dt>Ontology</dt><dd>${code(sd.ontology_ref)}</dd>
        <dt>Owner</dt><dd>${code(sd.owner_ref)}</dd>
        <dt>Admitted head</dt><dd><code data-testid="sd-admitted-head">${esc(head || "—")}</code></dd>
        <dt>Updated</dt><dd>${esc(sd.updated_at || "—")}</dd>
      </dl>
      <h3 style="margin:16px 0 6px;font-size:13px">Revise</h3>
      <form class="aform" method="post" action="${LEGACY_ROUTE}/${enc(sd.id)}/update-descriptor">
        <input type="hidden" name="idempotency_key" value="${esc(mintKey())}">
        <input type="hidden" name="return" value="${esc(`${LEGACY_ROUTE}?view=descriptors&sd=${enc(sd.id)}`)}">
        ${head ? `<input type="hidden" name="expected_head" value="${esc(head)}">` : ""}
        <label class="fl">Name<input name="name" maxlength="200" value="${esc(sd.name || "")}"${dis}></label>
        <label class="fl">Description<input name="description" maxlength="2000" value="${esc(sd.description || "")}"${dis}></label>
        <label class="fl">Composition pattern<select name="composition_pattern"${dis}>${patternOpts(sd.composition_pattern || "")}</select></label>
        <button class="act" type="submit"${dis}>Submit revision</button> ${casNote}
      </form>`;
    }
  }
  return `<h2 id="descriptors">Descriptor authoring</h2><p class="sub" style="margin:-4px 0 12px">ODK surface descriptors authored over the shared owner-scoped admission contract (OQ-1: ordinary governed mutations — identity + owner scope + caller idempotency + CAS; no wallet crossing). A descriptor declares a composition; mounting stays a separate governed ladder.</p>${list}${detail}${selectedId ? "" : createForm}`;
}

// ---- Composer view -----------------------------------------------------------------------------
function composerView(model, sp) {
  const prompt = (sp.get("prompt") || "").trim();
  const form = `<form class="aform" method="get" action="">
    <input type="hidden" name="view" value="composer">
    <label class="fl">Prompt<input name="prompt" maxlength="2000" value="${esc(prompt)}" placeholder="what should this system do?" required></label>
    <label class="fl">Input (optional)<input name="input" maxlength="2000" value="${esc(sp.get("input") || "")}"></label>
    <label class="fl">Query (optional)<input name="query" maxlength="2000" value="${esc(sp.get("query") || "")}"></label>
    <button class="act" type="submit">Compile intent frame</button>
  </form>`;
  let out = "";
  if (prompt) {
    const f = model.frame;
    out = f?.ok
      ? `<h3 id="compiled-frame" style="margin:16px 0 6px;font-size:13px">Compiled intent frame</h3><pre data-testid="intent-frame">${esc(JSON.stringify(f.payload, null, 2).slice(0, 8000))}</pre>`
      : `<div class="empty">the intent-frame projection did not answer — <code>${esc(f?.code || "daemon_unavailable")}</code>${f?.message ? ` (${esc(f.message)})` : ""}</div>`;
  }
  return `<h2 id="composer">Composer</h2><p class="sub" style="margin:-4px 0 12px"><b>Projection only</b> — the daemon's kernel compiles the prompt into a Studio intent frame and this view renders it. Nothing is created, admitted, or run; turning a frame into a blueprint is the <a href="?view=blueprints">Blueprints</a> authoring lane.</p>${form}${out}`;
}

// ---------------------------------------------------------------------------------------------
export function render(model, ctx) {
  const sp = ctx.url.searchParams;
  const view = sp.get("view") || "";
  const base = `${ctx.url.pathname}?view=${enc(view)}`;
  const nav = ["", "system-design", "composer", "blueprints", "descriptors"].map((v) => {
    const label = v === "" ? "Studio" : v === "system-design" ? "System design" : v.charAt(0).toUpperCase() + v.slice(1);
    return `<a class="tab${(view || "") === v ? " active" : ""}" href="${ctx.url.pathname}${v ? `?view=${v}` : ""}">${esc(label)}</a>`;
  }).join("");
  let bodyHtml = "";
  if (view === "system-design") bodyHtml = systemDesigns(model);
  else if (view === "composer") bodyHtml = composerView(model, sp);
  else if (view === "blueprints") bodyHtml = blueprintsView(model, sp);
  else if (view === "descriptors") bodyHtml = descriptorsView(model, sp);
  else {
    // The landing — the rehomed agent-estate lens (seed panes/labels; Machinery does NOT rehome
    // here per OQ-2 — its definitions plane keeps its own lane).
    const head = `<h1>Studio</h1><p class="sub"><a href="?view=system-design">System design map →</a> (concept/component/resource map over the <a href="/__ioi/studio/designer">Solution Designer seed</a>) · <a href="?view=blueprints">Blueprints →</a> (content-addressed composition drafts) · Compose systems &amp; agents. The agent lens is live — the agent estate — every configured agent, its model route and runtime posture, the platform's harness adapters, and recent activity. Author and operate agents here; <a href="/__ioi/automations">put one to work in an Automation →</a></p>`;
    bodyHtml = head + agentEstate(model, `${ctx.url.pathname}?view=`, sp) + systemDesigns(model) + harnessProfiles(model) + modelRoutesPane(model) + launchPoliciesPane(model) + intelligencePane(model);
  }
  const css = `:root{color-scheme:dark}
  body{margin:0;background:#0c0d10;color:#e6e7ea;font:14px/1.55 -apple-system,Segoe UI,Roboto,sans-serif}
  .wrap{max-width:1180px;margin:0 auto;padding:32px 24px 80px}
  a{color:#8ab4ff}
  h1{font-size:26px;margin:0 0 6px;letter-spacing:-.02em}
  .sub{color:#9a9da6;margin:0 0 22px;max-width:760px}
  h2{font-size:13px;letter-spacing:.04em;text-transform:uppercase;color:#878a93;margin:26px 0 10px;font-weight:600}
  .row{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin:12px 0 22px}
  .act{padding:8px 14px;border-radius:8px;border:0;background:#fff;color:#111;font:inherit;font-weight:600;text-decoration:none;cursor:pointer}
  .act.ghost{background:transparent;color:#cbd0da;border:1px solid #2a2c33}
  .act[disabled]{opacity:.45;cursor:not-allowed}
  .pill{display:inline-block;padding:2px 9px;border-radius:999px;font-size:11px;border:1px solid;white-space:nowrap;margin-left:4px}
  .ok{color:#46c277;border-color:#235c3b;background:#11281b}
  .warn{color:#d6a13a;border-color:#5c4a23;background:#28220f}
  .muted{color:#9a9da6;border-color:#2a2c33}
  .empty{color:#6f7280;padding:18px;border:1px dashed #24262d;border-radius:12px}
  .grid{display:grid;grid-template-columns:180px 1fr;gap:8px 16px;padding:16px;border:1px solid #24262d;border-radius:12px;background:#15171c;margin:0 0 18px}
  .grid dt{color:#878a93;font-size:12.5px}
  .grid dd{margin:0;color:#e6e7ea;word-break:break-all}
  code{font-size:11.5px;color:#aab;background:#0e0f13;padding:1px 5px;border-radius:4px}
  pre{background:#0e0f13;border:1px solid #24262d;border-radius:8px;padding:12px;overflow:auto;font:11.5px/1.5 ui-monospace,monospace;color:#cdd1d8;white-space:pre-wrap;word-break:break-all}
  table{width:100%;border-collapse:collapse;font-size:13px;margin:0 0 14px}
  th{text-align:left;color:#878a93;font-weight:600;font-size:11.5px;text-transform:uppercase;letter-spacing:.04em;padding:6px 10px;border-bottom:1px solid #24262d}
  td{padding:8px 10px;border-bottom:1px solid #1b1d23;vertical-align:top}
  .tabs{display:flex;gap:4px;border-bottom:1px solid #24262d;margin:0 0 18px;flex-wrap:wrap}
  .tab{border-bottom:2px solid transparent;color:#9a9da6;font-weight:600;padding:9px 14px;text-decoration:none}
  .tab.active{color:#fff;border-bottom-color:#3a82f6}
  .chips{display:flex;align-items:center;gap:6px;flex-wrap:wrap;margin:0 0 14px}
  .chiplabel{color:#878a93;font-size:11.5px;text-transform:uppercase;letter-spacing:.04em;font-weight:600}
  .asgrid{display:grid;grid-template-columns:248px 1fr;gap:20px;align-items:start}
  .aslist{max-height:60vh;overflow:auto;display:flex;flex-direction:column;gap:6px}
  .asrow{display:block;padding:10px 12px;border:1px solid #24262d;border-radius:10px;background:#15171c;text-decoration:none;color:inherit}
  .asrow:hover{border-color:#3a82f6}.asrow.sel{border-color:#3a82f6;box-shadow:0 0 0 1px #3a82f6 inset}
  .asrow .nm{font-weight:600;color:#fff;font-size:12.5px}
  .asrow .ml{color:#878a93;font-size:11.5px;margin-top:2px;word-break:break-all}
  .asearch{width:100%;box-sizing:border-box;padding:9px 12px;border-radius:9px;border:1px solid #2a2c33;background:#0e0f13;color:#e6e7ea;font:inherit;margin-bottom:10px}
  .aform{display:flex;flex-direction:column;gap:10px;max-width:640px;padding:14px 16px;border:1px solid #24262d;border-radius:12px;background:#15171c;margin:0 0 16px}
  .fl{display:flex;flex-direction:column;gap:4px;color:#878a93;font-size:12px}
  .fl input,.fl textarea,.fl select{padding:8px;border-radius:8px;border:1px solid #2a2c33;background:#0e0f13;color:#e6e7ea;font:inherit}
  .banner{margin:0 0 14px;padding:9px 12px;border-radius:8px;font-size:12.5px;line-height:1.5;outline:none}
  .banner code{word-break:break-all}
  .ok-banner{border:1px solid #235c3b;background:#11281b;color:#46c277}
  .no-banner{border:1px solid #5c4a23;background:#28220f;color:#d6a13a}
  @media(max-width:760px){.asgrid{grid-template-columns:1fr}.grid{grid-template-columns:120px 1fr}table{display:block;overflow-x:auto;max-width:100%}}`;
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Studio · Hypervisor</title><style>${css}</style></head>
<body><div class="wrap"><nav class="tabs" aria-label="Studio">${nav}</nav>${banner(sp)}${bodyHtml}</div></body></html>`;
}
