// M08.15 — the App's projection of the daemon's machine read model, as pure functions.
// (docs/architecture/components/hypervisor/core-clients-surfaces.md § Workstation and Infrastructure
// delivery forms; providers-and-environments.md § Machine-control contract family; register R-215.)
//
// WHAT THIS MODULE IS, AND IS NOT. The daemon answers GET /v1/hypervisor/machines and
// GET /v1/hypervisor/machines/:workload with a spine it DERIVES from its records on every read — the head,
// the desired and observed generations and phases, the declaration the workload is bound to, its operations
// in chain order, its receipts. This module PICKS those members and renders them; it derives nothing. There
// is no head computation here, no generation arithmetic, no phase table, no cache: a client that re-derived
// any of these would be the parallel truth ACC-20 clause 2 forbids, and the gate pins this file against it.
//
// The rendered pages carry every member as a data attribute so that a reader — the gate, or anyone — can
// take the App's readout back off the page and compare it member for member with a second client's. That
// is how "integrated and standalone are the same product truth" is measured rather than asserted.
//
// The extension seam: an admitted extension_application's runtime view may render the PUBLIC read model
// and nothing else. `PUBLIC_EXTENSION_READS` is the closed list of `daemon_api_refs` a descriptor may name
// and have rendered; every other ref is listed as declared-and-not-rendered with a typed reason. An
// `allowed_action_refs` member is an OFFER the view shows disabled with a typed reason — the invocation
// crossing for an extension does not exist in this cut and the page says so instead of pretending.

export const MACHINES_API = "/v1/hypervisor/machines";
export const MACHINES_ROUTE = "/__ioi/environments/machines";
export const MACHINE_LANE_PATH = "/__ioi/machine-ops";
export const PUBLIC_EXTENSION_READS = Object.freeze({ "api://v1/hypervisor/machines": MACHINES_API });
export const EXTENSION_ACTION_REASON = "extension_action_invocation_not_admitted";
export const EXTENSION_READ_NOT_PUBLIC_REASON = "daemon_api_ref_not_a_public_read_model";

/** The spine members every client renders, in the order the pages list them. */
export const SPINE_MEMBERS = Object.freeze([
  "workload_ref", "workload_id", "head", "head_error", "desired_generation", "observed_generation",
  "desired_phase", "observed_phase", "backend_registration_ref", "capability_declaration_ref",
  "capability_declaration_hash", "capability_declaration_resolves", "evidence_mode", "operation_count",
  "admitted_count", "refused_count", "receipt_count", "cleanup_obligation_refs",
]);
export const OPERATION_MEMBERS = Object.freeze([
  "operation_ref", "operation", "desired_generation", "expected_head", "state", "admitted", "refusal_dimension",
  "refusal_reason", "previous_head", "admitted_request_hash", "receipt_ref", "result", "submitted_by",
  "capability_declaration_ref", "capability_declaration_hash",
]);
export const RECEIPT_MEMBERS = Object.freeze([
  "receipt_ref", "operation_ref", "result", "result_reason", "backend_native_operation_id",
  "desired_generation_before", "desired_generation_after", "observed_generation_before",
  "observed_generation_after", "verifier_profile_ref",
]);

const str = (v) => (v == null ? "" : Array.isArray(v) ? v.map(str).join(" ") : typeof v === "object" ? JSON.stringify(v) : String(v));
const defaultEsc = (s) => String(s == null ? "" : s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
const unesc = (s) => String(s ?? "").replace(/&quot;/g, "\"").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");
const pick = (source, members) => Object.fromEntries(members.map((k) => [k, str(source?.[k])]));

/** The App's readout of one spine: exactly the members, as strings, nothing derived. */
export function projectMachineSpine(machine) {
  const m = machine || {};
  return {
    ...pick(m, SPINE_MEMBERS),
    operations: (Array.isArray(m.operations) ? m.operations : []).map((o) => pick(o, OPERATION_MEMBERS)),
    receipts: (Array.isArray(m.receipts) ? m.receipts : []).map((r) => pick(r, RECEIPT_MEMBERS)),
  };
}

/** The inventory readout: one row per machine, the members a list shows. */
export const INVENTORY_MEMBERS = Object.freeze(["workload_id", "workload_ref", "head", "desired_generation", "observed_generation", "desired_phase", "observed_phase", "capability_declaration_ref", "evidence_mode", "operation_count", "receipt_count"]);
export function projectMachineInventory(machines) {
  return (Array.isArray(machines) ? machines : []).map((m) => pick(m, INVENTORY_MEMBERS));
}

function attrs(esc, pairs) {
  return Object.entries(pairs).map(([k, v]) => ` ${k}="${esc(str(v))}"`).join("");
}

/** HTML: the inventory table (data attributes carry the readout). */
export function renderMachineInventory(machines, { esc = defaultEsc, route = MACHINES_ROUTE } = {}) {
  const rows = projectMachineInventory(machines);
  const body = rows.length
    ? rows.map((r) => `<tr class="machine-row"${attrs(esc, { "data-ioi-machine": r.workload_id, "data-ioi-workload-ref": r.workload_ref, "data-ioi-head": r.head, "data-ioi-desired": r.desired_generation, "data-ioi-observed": r.observed_generation, "data-ioi-desired-phase": r.desired_phase, "data-ioi-observed-phase": r.observed_phase, "data-ioi-declaration": r.capability_declaration_ref, "data-ioi-evidence-mode": r.evidence_mode, "data-ioi-operations": r.operation_count, "data-ioi-receipts": r.receipt_count })}><td><a href="${esc(route)}/${encodeURIComponent(r.workload_id)}"><code>${esc(r.workload_ref)}</code></a></td><td><code>${esc(r.head.slice(0, 19))}…</code></td><td>${esc(r.desired_phase)} / ${esc(r.observed_phase)}</td><td>${esc(r.desired_generation)} / ${esc(r.observed_generation)}</td><td><code>${esc(r.capability_declaration_ref)}</code> <span class="pill muted">${esc(r.evidence_mode || "unresolved")}</span></td><td>${esc(r.operation_count)} · ${esc(r.receipt_count)}</td></tr>`).join("")
    : `<tr><td colspan="6"><div class="empty" data-ioi-machines-empty="true">No governed machine is recorded on this daemon. A machine exists when its first operation is admitted; nothing here is invented ahead of the record.</div></td></tr>`;
  return `<table data-ioi-machine-inventory="${rows.length}"><thead><tr><th>Workload</th><th>Head</th><th>Desired / observed phase</th><th>Desired / observed generation</th><th>Declaration · evidence</th><th>Ops · receipts</th></tr></thead><tbody>${body}</tbody></table>`;
}

/** HTML: one workload's detail (spine members, operations, receipts) with the lifecycle proposal form. */
export function renderMachineDetail(machine, { esc = defaultEsc, laneUrl = MACHINE_LANE_PATH, route = MACHINES_ROUTE } = {}) {
  const s = projectMachineSpine(machine);
  const members = SPINE_MEMBERS.map((k) => `<tr${attrs(esc, { "data-ioi-member": k, "data-ioi-value": s[k] })}><th>${esc(k)}</th><td><code>${esc(s[k] || "—")}</code></td></tr>`).join("");
  const ops = s.operations.length
    ? s.operations.map((o) => `<tr${attrs(esc, { "data-ioi-machine-operation": o.operation_ref, "data-ioi-verb": o.operation, "data-ioi-generation": o.desired_generation, "data-ioi-expected-head": o.expected_head, "data-ioi-state": o.state, "data-ioi-admitted": o.admitted, "data-ioi-refusal": o.refusal_dimension, "data-ioi-refusal-reason": o.refusal_reason, "data-ioi-previous-head": o.previous_head, "data-ioi-hash": o.admitted_request_hash, "data-ioi-receipt": o.receipt_ref, "data-ioi-result": o.result, "data-ioi-submitted-by": o.submitted_by, "data-ioi-declaration": o.capability_declaration_ref, "data-ioi-declaration-hash": o.capability_declaration_hash })}><td><code>${esc(o.operation_ref)}</code></td><td>${esc(o.operation)}</td><td>${esc(o.state)}${o.refusal_dimension ? ` · <span class="pill warn">${esc(o.refusal_dimension)}</span> <span class="sub" style="margin:0">${esc(o.refusal_reason)}</span>` : ""}</td><td>${esc(o.result || "—")}</td><td><code>${esc(o.receipt_ref || "—")}</code></td><td><code>${esc(o.submitted_by || "—")}</code></td></tr>`).join("")
    : `<tr><td colspan="6"><div class="empty">No operation recorded.</div></td></tr>`;
  const receipts = s.receipts.length
    ? s.receipts.map((r) => `<tr${attrs(esc, { "data-ioi-machine-receipt": r.receipt_ref, "data-ioi-operation": r.operation_ref, "data-ioi-result": r.result, "data-ioi-reason": r.result_reason, "data-ioi-native": r.backend_native_operation_id, "data-ioi-generations": `${r.desired_generation_before}/${r.desired_generation_after}/${r.observed_generation_before}/${r.observed_generation_after}`, "data-ioi-profile": r.verifier_profile_ref })}><td><code>${esc(r.receipt_ref)}</code></td><td>${esc(r.result)}${r.result_reason ? ` · ${esc(r.result_reason)}` : ""}</td><td>${esc(r.desired_generation_before)}→${esc(r.desired_generation_after)} / ${esc(r.observed_generation_before)}→${esc(r.observed_generation_after)}</td><td><code>${esc(r.backend_native_operation_id || "—")}</code></td></tr>`).join("")
    : `<tr><td colspan="4"><div class="empty">No receipt recorded.</div></td></tr>`;
  const form = `<form method="post" action="${esc(laneUrl)}" data-ioi-machine-lane="${esc(laneUrl)}" class="machine-lane"><input type="hidden" name="workload" value="${esc(s.workload_id)}"><input type="hidden" name="expected_head" value="${esc(s.head)}"><label>Operation <select name="operation">${["start", "stop", "pause", "resume", "reboot", "snapshot", "delete"].map((v) => `<option value="${v}">${v}</option>`).join("")}</select></label> <label>Desired generation <input name="desired_generation" type="number" min="1" value="${esc(Number(s.desired_generation || 0) + 1)}"></label> <button class="act" type="submit">Propose to the daemon</button><p class="sub" style="margin:6px 0 0">A proposal. The daemon resolves the capability declaration, admits or refuses through its kernel, mints the identity and writes the record; this form carries the head the daemon last answered and nothing it computed itself.</p></form>`;
  return `<section data-ioi-machine-spine="${esc(s.workload_id)}"><h2>Spine (the daemon's read model, verbatim)</h2><table class="machine-spine"><tbody>${members}</tbody></table>${form}<h2>Operations (chain order, then refused proposals)</h2><table class="machine-operations"><thead><tr><th>Operation</th><th>Verb</th><th>State</th><th>Result</th><th>Receipt</th><th>Submitted by</th></tr></thead><tbody>${ops}</tbody></table><h2>Receipts</h2><table class="machine-receipts"><thead><tr><th>Receipt</th><th>Result</th><th>Generations (desired / observed)</th><th>Backend-native id (evidence)</th></tr></thead><tbody>${receipts}</tbody></table></section>`;
}

/** HTML: what an admitted extension's runtime view may show of the daemon — the public read model only. */
export function renderExtensionMachineReads({ descriptor, machines, esc = defaultEsc } = {}) {
  const refs = Array.isArray(descriptor?.daemon_api_refs) ? descriptor.daemon_api_refs.map(String) : [];
  const actions = Array.isArray(descriptor?.allowed_action_refs) ? descriptor.allowed_action_refs.map(String) : [];
  if (!refs.length && !actions.length) return "";
  const parts = [];
  for (const ref of refs) {
    if (PUBLIC_EXTENSION_READS[ref]) {
      const rows = projectMachineInventory(machines);
      parts.push(`<h2>Public read model: governed machines <span class="sub" style="text-transform:none;letter-spacing:0;font-weight:400">(${esc(ref)} → ${esc(PUBLIC_EXTENSION_READS[ref])}, read-only)</span></h2><table data-ioi-ext-read="${esc(ref)}" data-ioi-ext-machine-count="${rows.length}"><thead><tr><th>Workload</th><th>Head</th><th>Desired / observed phase</th><th>Generations</th></tr></thead><tbody>${rows.length ? rows.map((r) => `<tr${attrs(esc, { "data-ioi-ext-machine": r.workload_id, "data-ioi-ext-head": r.head, "data-ioi-ext-desired": r.desired_generation, "data-ioi-ext-observed": r.observed_generation, "data-ioi-ext-desired-phase": r.desired_phase, "data-ioi-ext-observed-phase": r.observed_phase })}><td><code>${esc(r.workload_ref)}</code></td><td><code>${esc(r.head.slice(0, 19))}…</code></td><td>${esc(r.desired_phase)} / ${esc(r.observed_phase)}</td><td>${esc(r.desired_generation)} / ${esc(r.observed_generation)}</td></tr>`).join("") : `<tr><td colspan="4"><div class="empty">No governed machine is recorded.</div></td></tr>`}</tbody></table>`);
    } else {
      parts.push(`<p class="sub"><span class="pill warn" aria-disabled="true"${attrs(esc, { "data-ioi-ext-api-not-public": ref, "data-ioi-disabled-reason": EXTENSION_READ_NOT_PUBLIC_REASON })}>${esc(ref)}</span> is declared by the descriptor and is not a public read model: nothing from it is fetched or rendered here.</p>`);
    }
  }
  if (actions.length) {
    parts.push(`<h2>Offered actions</h2><p class="sub">An action named by the descriptor is an OFFER, not a capability: this view does not invoke, and no invocation crossing exists for an extension in this cut.</p><div class="row">${actions.map((a) => `<button class="act ghost" disabled aria-disabled="true"${attrs(esc, { "data-ioi-ext-action": a, "data-ioi-disabled-reason": EXTENSION_ACTION_REASON, title: EXTENSION_ACTION_REASON })}>${esc(a)}</button>`).join(" ")}</div>`);
  }
  return `<section data-ioi-ext-reads="${refs.length}">${parts.join("")}</section>`;
}

// ---- readers: take the readout back off a rendered page ---------------------------------------------------
function readAttrs(tag) {
  const out = {};
  for (const m of tag.matchAll(/([a-z-]+)="([^"]*)"/g)) out[m[1]] = unesc(m[2]);
  return out;
}
function rowsWith(html, marker) {
  return [...String(html).matchAll(new RegExp(`<tr[^>]*\\b${marker}="[^"]*"[^>]*>`, "g"))].map((m) => readAttrs(m[0]));
}
export function spineFromRenderedDetail(html) {
  const h = String(html);
  const spine = {};
  for (const m of h.matchAll(/<tr data-ioi-member="([^"]+)" data-ioi-value="([^"]*)">/g)) spine[unesc(m[1])] = unesc(m[2]);
  const opMap = { "data-ioi-machine-operation": "operation_ref", "data-ioi-verb": "operation", "data-ioi-generation": "desired_generation", "data-ioi-expected-head": "expected_head", "data-ioi-state": "state", "data-ioi-admitted": "admitted", "data-ioi-refusal": "refusal_dimension", "data-ioi-refusal-reason": "refusal_reason", "data-ioi-previous-head": "previous_head", "data-ioi-hash": "admitted_request_hash", "data-ioi-receipt": "receipt_ref", "data-ioi-result": "result", "data-ioi-submitted-by": "submitted_by", "data-ioi-declaration": "capability_declaration_ref", "data-ioi-declaration-hash": "capability_declaration_hash" };
  spine.operations = rowsWith(h, "data-ioi-machine-operation").map((a) => Object.fromEntries(Object.entries(opMap).map(([attr, k]) => [k, a[attr] ?? ""])));
  spine.receipts = rowsWith(h, "data-ioi-machine-receipt").map((a) => {
    const g = String(a["data-ioi-generations"] ?? "///").split("/");
    return { receipt_ref: a["data-ioi-machine-receipt"] ?? "", operation_ref: a["data-ioi-operation"] ?? "", result: a["data-ioi-result"] ?? "", result_reason: a["data-ioi-reason"] ?? "", backend_native_operation_id: a["data-ioi-native"] ?? "", desired_generation_before: g[0] ?? "", desired_generation_after: g[1] ?? "", observed_generation_before: g[2] ?? "", observed_generation_after: g[3] ?? "", verifier_profile_ref: a["data-ioi-profile"] ?? "" };
  });
  return spine;
}
export function inventoryFromRendered(html) {
  const map = { "data-ioi-machine": "workload_id", "data-ioi-workload-ref": "workload_ref", "data-ioi-head": "head", "data-ioi-desired": "desired_generation", "data-ioi-observed": "observed_generation", "data-ioi-desired-phase": "desired_phase", "data-ioi-observed-phase": "observed_phase", "data-ioi-declaration": "capability_declaration_ref", "data-ioi-evidence-mode": "evidence_mode", "data-ioi-operations": "operation_count", "data-ioi-receipts": "receipt_count" };
  return rowsWith(html, "data-ioi-machine").map((a) => Object.fromEntries(Object.entries(map).map(([attr, k]) => [k, a[attr] ?? ""])));
}
export function extensionReadsFromRendered(html) {
  const h = String(html);
  const machines = rowsWith(h, "data-ioi-ext-machine").map((a) => ({ workload_id: a["data-ioi-ext-machine"] ?? "", head: a["data-ioi-ext-head"] ?? "", desired_generation: a["data-ioi-ext-desired"] ?? "", observed_generation: a["data-ioi-ext-observed"] ?? "", desired_phase: a["data-ioi-ext-desired-phase"] ?? "", observed_phase: a["data-ioi-ext-observed-phase"] ?? "" }));
  const notPublic = [...h.matchAll(/data-ioi-ext-api-not-public="([^"]*)"/g)].map((m) => unesc(m[1]));
  // The `disabled` ATTRIBUTE, not the word: `data-ioi-disabled-reason` carries the word on every offer,
  // so a word match would call an enabled button disabled (the mutation battery planted exactly that).
  const actions = [...h.matchAll(/<button[^>]*data-ioi-ext-action="([^"]*)"[^>]*>/g)].map((m) => ({ ref: unesc(m[1]), disabled: /\sdisabled(?=[\s>=])/.test(m[0]), reason: readAttrs(m[0])["data-ioi-disabled-reason"] ?? "" }));
  return { machines, not_public: notPublic, actions, has_form: /<form\b/i.test(h), has_script_fetch: /\bfetch\(|XMLHttpRequest|\bWebSocket\(/.test(h), names_lane: h.includes(MACHINE_LANE_PATH) };
}

// ---- parity: member for member, as strings, both sides -------------------------------------------------------
export function spineParity(left, right) {
  const f = [];
  const a = projectMachineSpine(left); const b = projectMachineSpine(right);
  for (const k of SPINE_MEMBERS) if (a[k] !== b[k]) f.push(`${k}:${a[k].slice(0, 40)}≠${b[k].slice(0, 40)}`);
  if (a.operations.length !== b.operations.length) f.push(`operations:${a.operations.length}≠${b.operations.length}`);
  else a.operations.forEach((o, i) => { for (const k of OPERATION_MEMBERS) if (o[k] !== b.operations[i][k]) f.push(`operations[${i}].${k}:${o[k].slice(0, 40)}≠${b.operations[i][k].slice(0, 40)}`); });
  if (a.receipts.length !== b.receipts.length) f.push(`receipts:${a.receipts.length}≠${b.receipts.length}`);
  else a.receipts.forEach((r, i) => { for (const k of RECEIPT_MEMBERS) if (r[k] !== b.receipts[i][k]) f.push(`receipts[${i}].${k}:${r[k].slice(0, 40)}≠${b.receipts[i][k].slice(0, 40)}`); });
  return f;
}
export function inventoryParity(left, right) {
  const f = [];
  const a = projectMachineInventory(left); const b = projectMachineInventory(right);
  if (a.length !== b.length) return [`count:${a.length}≠${b.length}`];
  a.forEach((r, i) => { for (const k of INVENTORY_MEMBERS) if (r[k] !== b[i][k]) f.push(`[${i}].${k}:${r[k].slice(0, 40)}≠${b[i][k].slice(0, 40)}`); });
  return f;
}
