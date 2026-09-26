// Governance / Leases & Limits (ADR 0056: Bounded Authority → Governance) — the lane that bounds what
// people and automations may do. Its first live section is CHECKPOINTS (ADR 0056 P5, the
// justification-checkpoint plane): Configuration declares which interactions need a justification in
// the caller's organization and what the person must say; Review lists the records their answers
// left, with the checkpoint's wording exactly as shown. Leases live in Connections (capability leases
// are Connections' bindings) and are handed off there. Limits — budgets and standing limits — need an
// authority node, which this deployment has none of and which is never stood up unasked; that section
// is a named gap.
//
// Every read is the daemon's, on every request; every write is the plane's own owner-scoped write,
// posted as a form the serve re-encodes with the caller's organization and a per-render key.
import crypto from "node:crypto";
import { callerOwnerRef, escHtml as esc } from "../surfaces/kit.mjs";

export const LIMITS_ROUTE = "/governance/limits";
export const LIMITS_LANE = "/__ioi/governance/limits";

// The daemon's catalog, labelled for people. Only interactions the daemon gates appear here.
const INTERACTIONS = {
  "automation.run_now": ["Run an automation now", "a person's Run now — scheduled and webhook runs are never prompted"],
  "support_incident.file": ["File an issue", "Issues' New dialog; the items are what the issue affects"],
  "health_check.declare": ["Declare a health check", "Operations / Health's New check; the item is the check's target"],
};
const KINDS = [["response", "A written answer"], ["acknowledgment", "An acknowledgment"], ["dropdown", "A choice of reasons"]];
const FREE_TEXT = [["none", "No explanation"], ["optional", "Optional explanation"], ["required", "Required explanation"]];

const tail = (ref, scheme) => String(ref || "").startsWith(scheme) ? String(ref).slice(scheme.length) : String(ref || "");
const when = (iso) => { const m = /^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})/u.exec(String(iso || "")); return m ? `${m[1]} ${m[2]} UTC` : String(iso || "—"); };
const hidden = (name, value) => `<input type="hidden" name="${esc(name)}" value="${esc(value)}">`;
const lines = (text) => String(text || "").split(/\r?\n/u).map((s) => s.trim()).filter(Boolean);
const label = (kind) => (INTERACTIONS[kind] || [kind])[0];
const CSS = `<style>.lm-scroll{overflow-x:auto;max-width:100%}.lm-scroll table{width:100%;min-width:640px}.lm-scroll code{word-break:break-all}.lm-tabs{display:flex;gap:6px;flex-wrap:wrap;margin:0 0 16px}.lm-tabs a{padding:6px 12px;border:1px solid #2a2c33;border-radius:8px;text-decoration:none}.lm-tabs a[aria-current="page"]{font-weight:600;border-color:#3a82f6}form.grid[data-limits-new]>*{min-width:0}form.grid[data-limits-new] input:not([type=checkbox]),form.grid[data-limits-new] select,form.grid[data-limits-new] textarea{width:100%;max-width:100%;box-sizing:border-box}@media (max-width:640px){form.grid[data-limits-new]{grid-template-columns:1fr!important}}</style>`;

function itemLink(ref) {
  const r = String(ref || "");
  const auto = tail(r, "automation://");
  if (r.startsWith("automation://")) return `<a href="/__ioi/automations/${encodeURIComponent(auto)}"><code>${esc(r)}</code></a>`;
  if (r.startsWith("system://")) return `<a href="/systems/${tail(r, "system://").split("/").map(encodeURIComponent).join("/")}"><code>${esc(r)}</code></a>`;
  return `<code>${esc(r)}</code>`;
}

function answerText(j) {
  if (!j) return "—";
  if (j.kind === "acknowledgment") return j.acknowledged ? "Acknowledged" : "—";
  if (j.kind === "dropdown") return `${(j.selected || []).map(esc).join(", ")}${j.text ? ` — ${esc(j.text)}` : ""}`;
  return esc(j.text || "—");
}

function tabs(active) {
  const t = [["checkpoints", "Checkpoints"], ["leases", "Leases"], ["limits", "Limits"]];
  return `<nav class="lm-tabs" aria-label="Leases &amp; Limits">${t.map(([k, l]) => `<a href="${LIMITS_ROUTE}?tab=${k}"${k === active ? ' aria-current="page"' : ""}>${l}</a>`).join("")}</nav>`;
}

function review(data, q) {
  const { records, checkpoints } = data;
  const kind = q.get("kind") || "", checkpoint = q.get("checkpoint") || "", who = (q.get("submitted_by") || "").trim(), interaction = (q.get("interaction") || "").trim();
  const shown = records.filter((r) => (!kind || r.interaction_kind === kind) && (!checkpoint || tail(r.checkpoint_ref, "justification-checkpoint://") === checkpoint)
    && (!who || String(r.submitted_by_principal_ref || "").includes(who)) && (!interaction || r.interaction_ref === interaction));
  const opt = (v, l, sel) => `<option value="${esc(v)}"${sel ? " selected" : ""}>${esc(l)}</option>`;
  const filters = `<form method="get" action="${LIMITS_ROUTE}" class="row" data-limits-filters="1" style="margin:0 0 12px">${hidden("tab", "checkpoints")}${hidden("view", "review")}
    <select name="kind">${opt("", "Every interaction", !kind)}${Object.keys(INTERACTIONS).map((k) => opt(k, label(k), k === kind)).join("")}</select>
    <select name="checkpoint">${opt("", "Every checkpoint", !checkpoint)}${checkpoints.map((c) => opt(tail(c.checkpoint_id, "justification-checkpoint://"), c.display_name, tail(c.checkpoint_id, "justification-checkpoint://") === checkpoint)).join("")}</select>
    <input name="submitted_by" value="${esc(who)}" placeholder="Submitted by (user://…)">
    <input name="interaction" value="${esc(interaction)}" placeholder="Interaction (interaction://…)">
    <button class="act ghost" type="submit">Filter</button>${kind || checkpoint || who || interaction ? ` <a href="${LIMITS_ROUTE}?tab=checkpoints&amp;view=review">Clear</a>` : ""}</form>`;
  const selected = q.get("record") || "";
  const rows = shown.map((r) => `<tr data-limits-record="${esc(r.record_id)}">
      <td><a href="${LIMITS_ROUTE}?tab=checkpoints&amp;view=review&amp;record=${encodeURIComponent(tail(r.record_id, "justification-record://"))}#record">${esc(when(r.created_at))}</a></td>
      <td><code>${esc(r.submitted_by_principal_ref)}</code></td>
      <td>${esc(r.language?.title || "")}</td>
      <td>${esc(label(r.interaction_kind))}</td>
      <td>${(r.checkpointed_item_refs || []).map(itemLink).join("<br>") || "—"}</td>
      <td>${answerText(r.justification)}</td>
    </tr>`).join("");
  const table = shown.length
    ? `<div class="lm-scroll"><table data-limits-records="${shown.length}"><thead><tr><th>When</th><th>Submitted by</th><th>Checkpoint (as shown)</th><th>Interaction</th><th>Items</th><th>Justification</th></tr></thead><tbody>${rows}</tbody></table></div>`
    : `<div class="empty" data-limits-records-empty="1">No justification records you can see${kind || checkpoint || who || interaction ? " match these filters" : ""}. A record is written each time someone answers a checkpoint.</div>`;
  let detail = "";
  if (selected) {
    const r = records.find((x) => tail(x.record_id, "justification-record://") === selected);
    detail = r
      ? `<div class="card" id="record" style="display:block;margin:14px 0 0" data-limits-record-detail="${esc(r.record_id)}"><b>${esc(r.language?.title || "")}</b>
          <div class="sub" style="margin:6px 0;white-space:pre-wrap">${esc(r.language?.body || "")}</div>
          <div class="grid" style="grid-template-columns:160px 1fr;margin:8px 0 0"><span>Record</span><code>${esc(r.record_id)}</code><span>Checkpoint</span><code>${esc(r.checkpoint_ref)}</code><span>Its version then</span><code>${esc(r.checkpoint_head)}</code><span>Interaction</span><code>${esc(r.interaction_ref)}</code><span>Submitted by</span><code>${esc(r.submitted_by_principal_ref)}</code><span>Justification</span><span>${answerText(r.justification)}</span><span>Admitted</span><code>${esc(r.admitted_head || "—")}</code></div>
          <p class="sub" style="margin:8px 0 0">The wording above is exactly what was shown; editing or archiving the checkpoint later never changes it. <a href="${LIMITS_ROUTE}?tab=checkpoints&amp;view=review&amp;interaction=${encodeURIComponent(r.interaction_ref)}">Every record from this interaction →</a></p></div>`
      : `<div class="empty" data-limits-record-missing="1">No record <code>${esc(selected)}</code> is visible to you.</div>`;
  }
  return filters + table + detail;
}

function configurationList(data, canWrite, why) {
  const { checkpoints } = data;
  if (!checkpoints.length) return `<div class="empty" data-limits-checkpoints-empty="1">No checkpoints yet. Configure one below — choose the interactions that need a justification and what the person must say.</div>`;
  const verbs = (c) => {
    if (!canWrite) return `<span class="sub" style="margin:0">${esc(why)}</span>`;
    const id = tail(c.checkpoint_id, "justification-checkpoint://");
    const form = (to, text, cls) => `<form method="post" action="${LIMITS_LANE}/checkpoints/enablement" style="display:inline">${hidden("id", id)}${hidden("enablement", to)}${hidden("nonce", crypto.randomUUID())}<button class="${cls}" type="submit" data-limits-${to === "enabled" ? "resume" : to === "paused" ? "pause" : "archive"}="${esc(id)}">${text}</button></form>`;
    if (c.enablement === "enabled") return `${form("paused", "Pause", "act ghost")} ${form("archived", "Archive", "act danger")}`;
    if (c.enablement === "paused") return `${form("enabled", "Resume", "act ghost")} ${form("archived", "Archive", "act danger")}`;
    return form("enabled", "Restore", "act ghost");
  };
  const rows = checkpoints.map((c) => `<tr data-limits-checkpoint="${esc(c.checkpoint_id)}" data-limits-enablement="${esc(c.enablement)}">
      <td><b>${esc(c.display_name)}</b><div class="sub" style="margin:2px 0 0;font-size:11px"><code>${esc(c.checkpoint_id)}</code></div>${c.description ? `<div class="sub" style="margin:2px 0 0">${esc(c.description)}</div>` : ""}</td>
      <td>${(c.interaction_kinds || []).map((k) => esc(label(k))).join("<br>")}</td>
      <td>“${esc(c.prompt?.title || "")}” · ${esc((KINDS.find(([k]) => k === c.justification?.kind) || ["", c.justification?.kind])[1])}</td>
      <td style="font-size:12.5px">${(c.conditions?.item_refs || []).length ? `only ${(c.conditions.item_refs).map(itemLink).join(", ")}` : "every item"}${(c.conditions?.exempt_principal_refs || []).length ? `<br>except ${(c.conditions.exempt_principal_refs).map((p) => `<code>${esc(p)}</code>`).join(", ")}` : ""}</td>
      <td><span class="pill ${c.enablement === "enabled" ? "ok" : "muted"}" style="margin:0">${esc(c.enablement)}</span></td>
      <td>${verbs(c)}</td>
    </tr>`).join("");
  return `<div class="lm-scroll"><table data-limits-checkpoints="${checkpoints.length}"><thead><tr><th>Checkpoint</th><th>Interactions</th><th>Prompt</th><th>Applies to</th><th>State</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>`;
}

function newCheckpointForm(data, values, canWrite, why) {
  const v = values || {};
  const dis = canWrite ? "" : " disabled";
  const chosen = new Set(v.interaction_kinds || []);
  const opt = (value, text, selected) => `<option value="${esc(value)}"${selected ? " selected" : ""}>${esc(text)}</option>`;
  const kinds = Object.entries(INTERACTIONS).map(([k, [l, note]]) => `<label style="display:flex;gap:8px;align-items:flex-start;margin:0 0 4px"><input type="checkbox" name="interaction_kinds" value="${esc(k)}"${chosen.has(k) ? " checked" : ""}${dis}> <span>${esc(l)}<span class="sub" style="display:block;margin:0;font-size:12px">${esc(note)}</span></span></label>`).join("");
  return `<form method="post" action="${LIMITS_LANE}/checkpoints/new" id="new-checkpoint" data-limits-new="1" class="grid" style="grid-template-columns:200px 1fr">
    ${hidden("nonce", v.nonce || crypto.randomUUID())}
    <label for="lm-name">Name</label><div><input id="lm-name" name="display_name" maxlength="160" value="${esc(v.display_name || "")}" placeholder="Production runs need a reason"${dis}><div class="sub" style="margin:4px 0 0">Seen by configurators, never by the person prompted.</div></div>
    <label for="lm-desc">Description</label><input id="lm-desc" name="description" maxlength="2000" value="${esc(v.description || "")}"${dis}>
    <label>Interactions</label><div data-limits-field="interaction_kinds">${kinds}</div>
    <label>Applies in</label><div><code>${esc(data.owner || "—")}</code><div class="sub" style="margin:4px 0 0">A checkpoint applies inside the organization that owns it.</div></div>
    <label for="lm-items">Only these items</label><div><textarea id="lm-items" name="item_refs" rows="2" placeholder="One reference per line (automation://…). Empty: every item."${dis}>${esc(v.item_refs || "")}</textarea></div>
    <label for="lm-exempt">Except these people</label><textarea id="lm-exempt" name="exempt_principal_refs" rows="2" placeholder="One user:// per line"${dis}>${esc(v.exempt_principal_refs || "")}</textarea>
    <label for="lm-title">Prompt title</label><input id="lm-title" name="prompt_title" maxlength="45" value="${esc(v.prompt_title || "")}" placeholder="Why run this now?"${dis}>
    <label for="lm-body">Prompt</label><textarea id="lm-body" name="prompt_body" rows="3" maxlength="4000" placeholder="What the person reads before answering"${dis}>${esc(v.prompt_body || "")}</textarea>
    <label for="lm-pdesc">Prompt details</label><textarea id="lm-pdesc" name="prompt_description" rows="2" maxlength="4000"${dis}>${esc(v.prompt_description || "")}</textarea>
    <label for="lm-kind">The person must give</label><select id="lm-kind" name="justification_kind" data-limits-field="justification_kind"${dis}>${KINDS.map(([k, l]) => opt(k, l, (v.justification_kind || "response") === k)).join("")}</select>
    <label for="lm-pattern">Answer must match</label><div><input id="lm-pattern" name="response_pattern" maxlength="500" value="${esc(v.response_pattern || "")}" placeholder="For a written answer: a pattern, e.g. ^TICKET-[0-9]+ (optional)"${dis}></div>
    <label for="lm-ack">Acknowledgment text</label><input id="lm-ack" name="acknowledgment_text" maxlength="500" value="${esc(v.acknowledgment_text || "")}" placeholder="For an acknowledgment: I understand this runs against production"${dis}>
    <label for="lm-options">Reasons</label><div><textarea id="lm-options" name="options" rows="3" placeholder="For a choice of reasons: one per line"${dis}>${esc(v.options || "")}</textarea><label style="display:flex;gap:8px;align-items:center;margin-top:6px"><input type="checkbox" name="multiple"${v.multiple ? " checked" : ""}${dis}> more than one reason may be chosen</label></div>
    <label for="lm-free">Explanation</label><select id="lm-free" name="free_text"${dis}>${FREE_TEXT.map(([k, l]) => opt(k, l, (v.free_text || "none") === k)).join("")}</select>
    <span></span><div><button class="act" type="submit"${dis}>Configure checkpoint</button>${canWrite ? "" : ` <span class="sub" style="margin:0" data-limits-new-disabled="1">${esc(why)}</span>`}</div>
  </form>`;
}

const NAMED_GAPS = [
  ["checkpoint_reauthentication_absent", "Re-authentication as a justification", "asking the person to sign in again needs an identity step-up plane, which does not exist yet"],
  ["checkpoint_conflict_panel_absent", "A conflicts check while configuring", "overlapping checkpoints all apply — each is shown to the person — but the form does not warn about overlap yet"],
];

export function renderGovernanceLimits(data, opts = {}) {
  const q = opts.query || new URLSearchParams();
  const tab = ["checkpoints", "leases", "limits"].includes(q.get("tab")) ? q.get("tab") : "checkpoints";
  const view = q.get("view") === "configuration" ? "configuration" : "review";
  const canWrite = Boolean(data.owner) && !data.readError;
  const why = data.readError ? "checkpoints could not be read, so nothing can be changed" : data.signedOut ? "you are signed out — sign in to configure checkpoints" : "your sign-in belongs to no organization of this deployment, so a checkpoint would have no owner";
  const head = `${CSS}<h1>Leases &amp; Limits</h1><p class="sub">What bounds the actions people and automations take in your organization. Checkpoints ask for a justification before an action runs and keep the answer as an audit record — a speed bump, never an approval. <a href="/governance/approvals">Approvals →</a> · <a href="/__ioi/connections">Connections →</a></p>`;
  const notice = q.get("note") ? `<div class="card" style="display:block" data-limits-notice="${q.get("ok") === "1" ? "ok" : "err"}"><span class="pill ${q.get("ok") === "1" ? "ok" : "warn"}" style="margin:0 8px 0 0">${q.get("ok") === "1" ? "Done" : "Not done"}</span>${esc(q.get("note"))}</div>` : "";
  if (tab === "leases") {
    return head + tabs(tab) + `<div class="card" style="display:block" data-limits-leases="1"><b>Leases live in Connections.</b><p class="sub" style="margin:6px 0 0">A capability lease binds one person or automation to one connector's tools, for a time, and every use names it on its receipt. Connections owns every capability binding, so leases are granted, listed and revoked there. <a href="/__ioi/connections">Open Connections →</a></p></div>`;
  }
  if (tab === "limits") {
    return head + tabs(tab) + `<div class="empty" data-named-gap="system_limits_authority_node_absent" data-limits-authority-gap="1"><b>Budgets and standing limits</b> — a named gap: they are enforced by an authority node (ADR 0056 Ruling 8), and this deployment has none. None is stood up without the owner deciding to.</div>`;
  }
  if (data.readError) {
    return head + tabs(tab) + notice + `<div class="empty" data-limits-read-error="${esc(data.readError.code || "")}">Checkpoints could not be read — <code>${esc(data.readError.code || "unavailable")}</code>: ${esc(data.readError.message || "")}.${data.signInHref ? ` <a href="${esc(data.signInHref)}" target="_top">Sign in</a> to see them.` : ""} Nothing is shown in their place.</div>`;
  }
  const sub = `<nav class="lm-tabs" aria-label="Checkpoints"><a href="${LIMITS_ROUTE}?tab=checkpoints&amp;view=review"${view === "review" ? ' aria-current="page"' : ""}>Review</a><a href="${LIMITS_ROUTE}?tab=checkpoints&amp;view=configuration"${view === "configuration" ? ' aria-current="page"' : ""}>Configuration</a></nav>`;
  const body = view === "review"
    ? review(data, q)
    : configurationList(data, canWrite, why) + `<h2>Configure new checkpoint</h2>`
      + (opts.error ? `<div class="card" style="display:block" data-limits-new-error="1"><span class="pill warn" style="margin:0 8px 0 0">Not configured</span>${esc(opts.error)}</div>` : "")
      + newCheckpointForm(data, opts.values, canWrite, why)
      + `<h2>Not built yet</h2><ul class="sub" data-limits-named-gaps="${NAMED_GAPS.length}">${NAMED_GAPS.map(([code, l, t]) => `<li data-named-gap="${esc(code)}"><b>${esc(l)}</b> — ${esc(t)}.</li>`).join("")}</ul>`;
  return head + tabs(tab) + notice + sub + body;
}

// ---- Serving ------------------------------------------------------------------------------------
async function readJson(daemonFetch, path) {
  try {
    const r = await daemonFetch(path);
    return { status: r.status, body: await r.json().catch(() => ({})) };
  } catch (e) {
    return { status: 0, body: {}, networkError: String((e && e.message) || e) };
  }
}

async function loadLimitsData({ daemonFetch }) {
  const [cpR, recR, whoR] = await Promise.all([
    readJson(daemonFetch, "/v1/hypervisor/justification-checkpoints"),
    readJson(daemonFetch, "/v1/hypervisor/justification-records"),
    readJson(daemonFetch, "/v1/hypervisor/auth/whoami"),
  ]);
  let readError = null;
  if (cpR.networkError) readError = { code: "daemon_unreachable", message: cpR.networkError };
  else if (cpR.status !== 200 || cpR.body.ok === false) {
    const b = cpR.body || {};
    readError = { code: b.code || b.error?.code || `http_${cpR.status}`, message: b.message || b.error?.message || "" };
  }
  const signedOut = whoR.status === 401 || whoR.body?.authenticated === false;
  return {
    checkpoints: cpR.body.checkpoints || [],
    records: recR.body.justification_records || [],
    owner: signedOut ? "" : callerOwnerRef(whoR.body || {}),
    signedOut,
    readError,
    signInHref: readError && /principal_required/u.test(readError.code) ? `/__ioi/login?next=${encodeURIComponent(LIMITS_ROUTE)}` : "",
  };
}

async function writeJson(daemonFetch, path, payload) {
  try {
    const r = await daemonFetch(path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload) });
    return { status: r.status, body: await r.json().catch(() => ({})) };
  } catch {
    return { status: 0, body: {} };
  }
}

export async function handleGovernanceLimits(req, res, pathname, body, deps) {
  const { daemonFetch, whyRefused, send } = deps;
  if (pathname === LIMITS_LANE && req.method === "GET") {
    send(res, 200, renderGovernanceLimits(await loadLimitsData(deps), { query: new URL(req.url, "http://x").searchParams }));
    return true;
  }
  if (!pathname.startsWith(`${LIMITS_LANE}/checkpoints/`) || req.method !== "POST") return false;
  const f = new URLSearchParams(body.toString());
  const back = (ok, note) => {
    const qs = new URLSearchParams({ tab: "checkpoints", view: "configuration", ok: ok ? "1" : "0", note });
    res.writeHead(303, { Location: `${LIMITS_ROUTE}?${qs}`, "Cache-Control": "no-store" });
    res.end();
  };
  const data = await loadLimitsData(deps);
  const noOwner = data.signedOut ? "you are signed out — sign in and try again" : "your sign-in belongs to no organization of this deployment";
  const action = pathname.slice(`${LIMITS_LANE}/checkpoints/`.length);
  if (action === "new") {
    const values = {
      nonce: f.get("nonce") || "", display_name: (f.get("display_name") || "").slice(0, 160), description: (f.get("description") || "").slice(0, 2000),
      interaction_kinds: f.getAll("interaction_kinds").filter((k) => k in INTERACTIONS), item_refs: f.get("item_refs") || "", exempt_principal_refs: f.get("exempt_principal_refs") || "",
      prompt_title: (f.get("prompt_title") || "").slice(0, 45), prompt_body: (f.get("prompt_body") || "").slice(0, 4000), prompt_description: (f.get("prompt_description") || "").slice(0, 4000),
      justification_kind: f.get("justification_kind") || "response", response_pattern: (f.get("response_pattern") || "").slice(0, 500), acknowledgment_text: (f.get("acknowledgment_text") || "").slice(0, 500),
      options: f.get("options") || "", multiple: f.get("multiple") === "on", free_text: f.get("free_text") || "none",
    };
    const refuse = (error) => send(res, 200, renderGovernanceLimits(data, { query: new URLSearchParams({ tab: "checkpoints", view: "configuration" }), values, error }));
    if (!values.display_name.trim()) return refuse("give the checkpoint a name."), true;
    if (!values.interaction_kinds.length) return refuse("choose at least one interaction that needs a justification."), true;
    if (!values.prompt_title.trim() || !values.prompt_body.trim()) return refuse("write the prompt the person reads: a title and the prompt itself."), true;
    if (values.justification_kind === "dropdown" && !lines(values.options).length) return refuse("list at least one reason to choose from."), true;
    if (!data.owner) return refuse(`${noOwner}, so the checkpoint would have no owner.`), true;
    const r = await writeJson(daemonFetch, "/v1/hypervisor/justification-checkpoints", {
      owner_ref: data.owner, idempotency_key: `justification-checkpoint-${values.nonce || crypto.randomUUID()}`,
      display_name: values.display_name.trim(), description: values.description.trim(), interaction_kinds: values.interaction_kinds, scope_ref: data.owner,
      conditions: { item_refs: lines(values.item_refs), exempt_principal_refs: lines(values.exempt_principal_refs) },
      prompt: { title: values.prompt_title.trim(), body: values.prompt_body.trim(), description: values.prompt_description.trim() },
      justification: { kind: values.justification_kind, acknowledgment_text: values.acknowledgment_text.trim(), response_pattern: values.response_pattern.trim(), options: lines(values.options), multiple: values.multiple, free_text: values.free_text },
    });
    if (!(r.status >= 200 && r.status < 300 && r.body.ok === true)) return refuse(`${whyRefused(r.body)}.`), true;
    back(true, r.body.replayed ? "This checkpoint was already configured — the same form was submitted twice, so nothing new was written." : `Configured. From now on, a justification is asked for before: ${values.interaction_kinds.map((k) => label(k).toLowerCase()).join(", ")} (in ${data.owner}).`);
    return true;
  }
  if (action === "enablement") {
    const id = tail((f.get("id") || "").slice(0, 200), "justification-checkpoint://");
    const to = f.get("enablement") || "";
    if (!/^jc_[0-9a-f]{16}$/u.test(id) || !["enabled", "paused", "archived"].includes(to)) return back(false, "Not changed: that is not a checkpoint state."), true;
    if (!data.owner) return back(false, `Not changed: ${noOwner}.`), true;
    const r = await writeJson(daemonFetch, `/v1/hypervisor/justification-checkpoints/${encodeURIComponent(id)}/enablement`, { owner_ref: data.owner, idempotency_key: `justification-checkpoint-${to}-${f.get("nonce") || crypto.randomUUID()}`, enablement: to });
    if (!(r.status >= 200 && r.status < 300 && r.body.ok === true)) return back(false, `Not changed: ${whyRefused(r.body)}.`), true;
    return back(true, `The checkpoint is now ${r.body.checkpoint?.enablement || to}.`), true;
  }
  return false;
}
