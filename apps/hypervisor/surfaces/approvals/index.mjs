// Approvals — the governed-action-runtime PILOT (operational wave PR62). The render code below is
// moved VERBATIM from serve-product-ui.mjs; the module adds the surface contract PLUS the first
// `actions` + `handleAction` implementation: approve/reject/revoke run through the EXISTING daemon
// authority (PATCH /v1/hypervisor/governance/approval-requests/:id), which now emits a durable
// approval-transition receipt — a success without that receipt FAILS CLOSED. Reject and revoke
// require explicit confirmation (a UX safeguard, not substitute authority). No create/delete/
// reassignment/delegation/comments/bulk actions are declared.
import { bpIcon, APPROVALS_APP_ICON_URI } from "../../scripts/bp-icons.mjs";
import { ioiGlobalRailHtml, IOI_GRAIL_CSS } from "../chrome.mjs";
import { escHtml } from "../kit.mjs";

const CX_ESC = escHtml; // local alias so the moved block stays byte-identical to its serve original
// Local transition-form builder (the serve's govTform, module-local so the moved block renders
// byte-identically; the action runtime adds confirm/return/embed fields through `extra`).
const govTform = (fam, id, transition, label, cls, extra) => `<form class="inline" method="post" action="/__ioi/governance/${fam}/${encodeURIComponent(id)}/transition"><input type="hidden" name="transition" value="${transition}">${extra || ""}<button class="act ${cls || "ghost"}" type="submit">${label}</button></form>`;
// Module-local copies of the serve's shared governance helpers (verbatim — the serve keeps its
// own for the remaining inline governance families until they extract).
function govSubjectLink(ref) {
  const r = String(ref || "");
  if (!r) return "—";
  const code = `<code style="font-size:10.5px">${CX_ESC(r)}</code>`;
  if (r.startsWith("domain-app://")) return `<a href="/__ioi/domain-apps/${encodeURIComponent(r.slice("domain-app://".length))}" style="text-decoration:none">${code} →</a>`;
  if (r.startsWith("marketplace-")) return `<a href="/__ioi/marketplace" style="text-decoration:none">${code} →</a>`;
  if (r.startsWith("failover-run://")) return `<a href="/__ioi/operations" style="text-decoration:none">${code} →</a>`;
  if (r.startsWith("fspec_") || r.startsWith("frun_")) return `<a href="/__ioi/foundry" style="text-decoration:none">${code} →</a>`;
  return code;
}
function govAge(iso) {
  const ms = Date.now() - Date.parse(iso || "");
  if (!isFinite(ms) || ms < 0) return "—";
  const m = Math.floor(ms / 60000);
  if (m < 1) return "just now";
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h}h ${m % 60}m`;
  return `${Math.floor(h / 24)}d`;
}


export const meta = {
  slug: "approvals",
  route: "/__ioi/governance/approvals",
  verifier: "scripts/verify-hypervisor-app-parity-approvals.mjs",
  certification: "pixel-certifications/approvals.json",
};

export async function load(ctx) {
  const ap = await fetch(`${ctx.daemon}/v1/hypervisor/governance/approval-requests`).then((x) => x.json()).catch(() => ({}));
  return { records: ap.approval_requests || [] };
}

export function render(model, ctx) {
  const sp = ctx.url.searchParams;
  return renderApprovalsPort(model.records, sp.get("status") || "", {
    selected: sp.get("req") || "", embed: ctx.embed,
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

// The action-descriptor contract: id · method · route pattern · allowed transition · allowlisted
// input fields · required context · authority plane/operation · expected receipt family ·
// confirmation posture · success return policy · refusal behavior. The runtime enforces it; the
// module only speaks to the daemon.
export const actions = [
  { id: "approve", method: "POST", route: "/:id/transition", transition: "approve", from: "pending", to: "approved", fields: ["reviewer_ref"], context: ["id"], authority: { plane: "governance.approval-requests", operation: "PATCH /v1/hypervisor/governance/approval-requests/:id" }, receipt: "ioi.hypervisor.governance.approval-transition-receipt.v1", confirm: false, success: "return-to-surface", refusal: "typed-banner" },
  { id: "reject", method: "POST", route: "/:id/transition", transition: "reject", from: "pending", to: "rejected", fields: ["reviewer_ref"], context: ["id"], authority: { plane: "governance.approval-requests", operation: "PATCH /v1/hypervisor/governance/approval-requests/:id" }, receipt: "ioi.hypervisor.governance.approval-transition-receipt.v1", confirm: true, success: "return-to-surface", refusal: "typed-banner" },
  { id: "revoke", method: "POST", route: "/:id/transition", transition: "revoke", from: "approved", to: "revoked", fields: ["reviewer_ref"], context: ["id"], authority: { plane: "governance.approval-requests", operation: "PATCH /v1/hypervisor/governance/approval-requests/:id" }, receipt: "ioi.hypervisor.governance.approval-transition-receipt.v1", confirm: true, success: "return-to-surface", refusal: "typed-banner" },
];

// One typed result, always: success carries the authoritative record + receipt ref; refusal
// carries the daemon's typed code/message with state untouched; failure claims nothing.
export async function handleAction({ action, id, fields, daemon }) {
  const payload = { transition: action.transition };
  if (fields.reviewer_ref) payload.reviewer_ref = fields.reviewer_ref;
  const r = await fetch(`${daemon}/v1/hypervisor/governance/approval-requests/${encodeURIComponent(id)}`, {
    method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify(payload),
  }).then((x) => x.json()).catch(() => null);
  if (!r) return { kind: "failure", http: 502, code: "daemon_unavailable", message: "the daemon did not answer — nothing was changed" };
  if (r.ok !== true) return { kind: "refusal", http: 409, code: (r.error && r.error.code) || "governance_refused", message: (r.error && r.error.message) || r.reason || "refused — state unchanged" };
  const receipt = r.transition_receipt;
  if (!receipt || !receipt.receipt_ref || receipt.schema_version !== action.receipt) {
    return { kind: "failure", http: 502, code: "receipt_missing", message: "the transition returned no declared receipt — failing closed (do not trust the mutation)" };
  }
  return { kind: "success", status: (r.approval_request || {}).status || action.to, record: r.approval_request, receipt_ref: receipt.receipt_ref };
}

// ============================ APPROVALS INBOX — reference UX PORT (#36, daemon_wired TRUE parity).
// A FAITHFUL LIGHT port of the reference "Approvals inbox" (dark global RAIL · light HEADER · a light
// faceted SIDEBAR: Quick filters [Your inbox / Created by you / All requests] + Additional filters
// [Status wired to ?status=, plus faithful named-gap facets] · a light request LIST with status pills ·
// an on-select right DETAIL with approve/reject/revoke), over the REAL daemon ApprovalRequest queue —
// the same records + the same transitions the substrate ?tab=approvals view uses (no new governance
// semantics). #33 shipped this as a dark native shell; #34's hardened gate correctly refused it; #36
// REBUILT it faithfully so it passes the hardened harness (theme + IA landmarks) → PROMOTED to
// `daemon_wired`, closing the #34 reclassification loop. Actions post a same-origin `return` to land here.
function renderApprovalsPort(records, statusFilter, opts) {
  const enc = encodeURIComponent, esc = CX_ESC;
  const all = Array.isArray(records) ? records : [];
  const STATUSES = [["pending", "Pending approval"], ["approved", "Approved"], ["rejected", "Rejected"], ["revoked", "Revoked"]];
  const byStatus = { pending: 0, approved: 0, rejected: 0, revoked: 0 };
  for (const a of all) if (byStatus[a.status] != null) byStatus[a.status]++;
  const view = ["pending", "approved", "rejected", "revoked", "all"].includes(statusFilter) ? statusFilter : "pending";
  const rows = view === "all" ? all : all.filter((a) => a.status === view);
  const selected = (opts && opts.selected) ? all.find((a) => a.id === opts.selected) : null;
  const svg = (p) => `<svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">${p}</svg>`;
  const CHECK = '<rect x="3" y="3" width="18" height="18" rx="4"/><path d="M8 12l3 3 5-6"/>';
  const CUBE = '<path d="M12 2l9 5v10l-9 5-9-5V7z"/>';

  // DARK global platform rail — the SHARED pixel-aligned reference shell (ioiGlobalRailHtml, #42).
  // Embedded (native container contract #65): the native rail owns platform nav — emit no global rail.
  const globalRail = opts.embed ? "" : ioiGlobalRailHtml({ label: "Approvals", href: "/__ioi/governance/approvals", iconUri: APPROVALS_APP_ICON_URI });

  // LIGHT faceted filter sidebar — Quick filters (real status shortcuts) + Additional filters (Status
  // is wired to ?status=; the rest are faithful faceted controls disabled as named gaps).
  const QF_ICON = { "Your inbox": "inbox", "Created by you": "follower", "All requests": "form" };
  const qf = (label, count, href, on, gap) => gap
    ? `<span class="ap-qf gap" title="${esc(label)} needs a per-user creator/identity plane — named gap (no count)"><span class="ap-qfi">${bpIcon(QF_ICON[label] || "form")}</span>${esc(label)}<span class="ap-qfc">—</span></span>`
    : `<a class="ap-qf${on ? " on" : ""}" href="${href}"><span class="ap-qfi">${bpIcon(QF_ICON[label] || "form")}</span>${esc(label)}<span class="ap-qfc">${count}</span></a>`;
  const statusOpt = (v, label) => `<option value="${v}"${v === view ? " selected" : ""}>${esc(label)}</option>`;
  const facets = `<aside class="ap-facets">
    <div class="ap-ftitle"><span class="ap-fappico" style="background-image:url('${APPROVALS_APP_ICON_URI}')"></span><h5>Approvals</h5><a class="ap-subst" href="/__ioi/governance?tab=approvals" title="The substrate approvals table">⇱</a></div>
    <div class="ap-fsec first">Quick filters</div>
    <div class="ap-qfbox">
      ${qf("Your inbox", byStatus.pending, "/__ioi/governance/approvals?status=pending", view === "pending")}
      ${qf("Created by you", 0, "", false, true)}
      <div class="ap-qfdiv"></div>
      ${qf("All requests", all.length, "/__ioi/governance/approvals?status=all", view === "all")}
    </div>
    <div class="ap-fsec">Additional filters <a class="ap-clear" href="/__ioi/governance/approvals">Clear</a></div>
    <form class="ap-ff" method="GET" action="/__ioi/governance/approvals">
      <label class="ap-flabel">Request type</label>
      <select class="ap-fsel" disabled title="Request-type facet is a named gap"><option>Access requests</option></select>
      <label class="ap-flabel">Status</label>
      <select class="ap-fsel" name="status" onchange="this.form.submit()">${statusOpt("all", "All requests")}${STATUSES.map(([v, l]) => statusOpt(v, l)).join("")}</select>
      <label class="ap-flabel">Created by</label>
      <select class="ap-fsel" disabled title="named gap"><option>Select user</option></select>
      <label class="ap-fcheck gap" title="named gap"><input type="checkbox" disabled> Assigned to you</label>
      <label class="ap-flabel">Project requested to</label>
      <select class="ap-fsel" disabled title="named gap"><option>Select project</option></select>
      <label class="ap-flabel">Users or groups in request</label>
      <select class="ap-fsel" disabled title="named gap"><option>Select user or group</option></select>
      <label class="ap-flabel">Groups requested to</label>
      <select class="ap-fsel" disabled title="named gap"><option>Select group</option></select>
    </form>
  </aside>`;

  const statusPill = (s) => `<span class="ap-pill ${s === "approved" ? "ok" : s === "pending" ? "warn" : "muted"}">${esc(s === "pending" ? "Pending approval" : ((s || "").charAt(0).toUpperCase() + (s || "").slice(1)))}</span>`;
  const subjShort = (r) => { const s = String(r || ""); return esc(s.length > 46 ? s.slice(0, 46) + "…" : s); };
  const rowHref = (a) => `/__ioi/governance/approvals?${view ? `status=${view}&` : ""}req=${enc(a.id)}`;
  const listHeading = view === "pending" ? "Your inbox" : view === "all" ? "All requests" : (STATUSES.find(([v]) => v === view) || [, "Requests"])[1];
  const list = `<main class="ap-list" role="main">
    <div class="ap-listhd"><h2>${esc(listHeading)} <span class="ap-n">(${rows.length})</span></h2>
      <div class="ap-listtools"><span class="ap-search" title="Full-text request search is a named gap">${svg('<circle cx="11" cy="11" r="7"/><path d="M21 21l-4-4"/>')} Search for requests…</span><span class="ap-sort" title="Sort is a named gap">Sort: Recently created ▾</span></div>
    </div>
    ${rows.length ? `<div class="ap-rows">${rows.map((a) => `<a class="ap-row${selected && selected.id === a.id ? " on" : ""}" href="${rowHref(a)}">
      <span class="ap-rowic">${svg('<rect x="4" y="3" width="14" height="18" rx="2"/><path d="M8 8h6M8 12h6M8 16h3"/>')}</span>
      <span class="ap-rowmain"><span class="ap-rowtitle">${esc(a.request_kind || "approval")} · ${subjShort(a.subject_ref)} <code class="ap-code">${esc(a.id || "")}</code></span><span class="ap-rowsub">Created ${esc(govAge(a.created_at))}${a.reason ? ` · ${esc(String(a.reason).slice(0, 60))}` : ""}</span></span>
      <span class="ap-rowst">${statusPill(a.status)}</span></a>`).join("")}</div>`
      : `<div class="ap-empty">Nothing in <b>${esc(listHeading)}</b> — pick another filter.</div>`}
  </main>`;

  // Right detail panel — ONLY when a request is selected (faithful: the reference default has no detail).
  // The approve/reject/revoke forms are the REAL daemon transitions (preserved wiring), return-aware.
  const RET = `<input type="hidden" name="return" value="${esc(rowHref(selected || { id: "" }))}">`;
  const blast = (a) => { const wc = (a.would_call || []).length, ar = (a.required_authority_refs || []).length; return (!wc && !ar) ? "none declared" : `${wc ? `${wc} call${wc > 1 ? "s" : ""}` : ""}${wc && ar ? " · " : ""}${ar ? `${ar} authorit${ar > 1 ? "ies" : "y"}` : ""}`; };
  // Confirmation is a UX safeguard, not substitute authority: reject/revoke carry VISIBLE
  // transition metadata and a REQUIRED confirmation checkbox (native enforcement, no JS; the
  // runtime re-enforces server-side with a typed confirmation_required refusal). Approve submits
  // directly. Every form posts return= (this inbox state); embedded mode adds embed= upstream.
  const CONFIRM = (a, t, to) => `<label class="ap-confirm"><input type="checkbox" name="confirm" value="1" required> confirm ${t} — ${esc(a.status)} → ${to}, recorded with a transition receipt</label>`;
  const decide = (a) => a.status === "pending"
    ? govTform("approvals", a.id, "approve", "Approve", "primary", `<input name="reviewer_ref" placeholder="reviewer" class="ap-inp">` + RET) + govTform("approvals", a.id, "reject", "Reject", "ghost", CONFIRM(a, "reject", "rejected") + RET)
    : a.status === "approved" ? govTform("approvals", a.id, "revoke", "Revoke", "ghost", CONFIRM(a, "revoke", "revoked") + RET) : `<span class="ap-muted">terminal — no further transition</span>`;
  // Action-result banner (#ap-result — the runtime's redirect anchor): success shows the
  // authoritative status + the durable transition receipt ref + proof links; refusal shows the
  // daemon's typed code/message and states plainly that nothing changed. Renders ONLY when the
  // runtime redirected here with result params — the bare/certified render carries no banner.
  const bn = (opts && opts.banner) || {};
  const banner = bn.acted && bn.receipt
    ? `<div id="ap-result" class="ap-banner ap-ok" tabindex="-1"><b>${esc(bn.acted)}</b> recorded${bn.result ? ` — status <b>${esc(bn.result)}</b>` : ""} · receipt <code class="ap-rcpt">${esc(bn.receipt)}</code> · <a href="/__ioi/governance/approvals?req=${encodeURIComponent(bn.record)}">record</a> · <a href="/__ioi/work-ledger">proof stream</a></div>`
    : bn.refused
      ? `<div id="ap-result" class="ap-banner ap-no" tabindex="-1">refused: <code>${esc(bn.refused)}</code>${bn.reason ? ` — ${esc(bn.reason)}` : ""} · <b>state unchanged</b>${bn.record ? ` · <a href="/__ioi/governance/approvals?req=${encodeURIComponent(bn.record)}">back to the request</a>` : ""}</div>`
      : "";
  const detail = selected ? `<aside class="ap-detail">${banner}
    <div class="ap-dhd"><b>${esc(selected.request_kind || "approval")}</b> ${statusPill(selected.status)}</div>
    <div class="ap-drow"><span>Subject</span>${govSubjectLink(selected.subject_ref)}</div>
    <div class="ap-drow"><span>Request id</span><code class="ap-code">${esc(selected.id || "")}</code></div>
    <div class="ap-drow"><span>Reason</span>${esc(selected.reason || "—")}</div>
    <div class="ap-drow"><span>Blast radius</span>${blast(selected)}</div>
    <div class="ap-drow"><span>Created</span>${esc(selected.created_at || "")}</div>
    <div class="ap-dactions">${decide(selected)}</div>
    <a class="ap-dclose" href="/__ioi/governance/approvals${view ? `?status=${view}` : ""}">Close</a>
    <div class="ap-dgaps">Named gaps: reviewer assignment · delegation · threaded comments · SLA/escalation · audit exports — reference-only lanes.</div>
  </aside>` : (banner ? `<aside class="ap-detail">${banner}</aside>` : "");

  const css = `html{color-scheme:light}*{box-sizing:border-box}
    body{margin:0;background:#f6f7f9;color:#1c2127;font:14px/1.28581 Source-Sans-Pro,Helvetica,sans-serif}
    a{color:#2f6fd8;text-decoration:none}
    .ap-shell{display:flex;height:100vh;width:100vw;overflow:hidden}
    ${IOI_GRAIL_CSS}
    .ap-main{flex:1;min-width:0;display:flex;flex-direction:column;height:100vh;position:relative}
    .ap-topbar{position:absolute;top:0;left:0;right:0;height:51px;pointer-events:none}
    .ap-work{flex:1 1 auto;display:flex;justify-content:center;min-height:0}
    .ap-content{display:flex;flex:0 1 1210px;max-width:1210px;min-width:0}
    .ap-facets{flex:0 0 300px;width:300px;background:#fff;border-right:1px solid #dce0e5;overflow-y:auto;padding:0 27px 24px 25px}
    .ap-ftitle{display:flex;align-items:flex-start;height:84px;padding-top:7px}
    .ap-fappico{width:24px;height:24px;flex:0 0 24px;margin-right:13px;border-radius:3px;background-color:rgba(102,158,255,.1);background-position:center;background-size:16px;background-repeat:no-repeat}
    .ap-ftitle h5{margin:0;font-size:16px;line-height:36px;font-weight:600;color:#1c2127;flex:1}
    .ap-subst{font-size:13px;color:#8b9099}
    .ap-fsec{font-size:14px;font-weight:600;color:#1c2127;height:40px;margin:13px 0 0 30px;display:flex;justify-content:space-between;align-items:center}
    .ap-clear{font-size:14px;font-weight:400;color:#215db0;margin-right:-4px}
    .ap-fsec.first{margin-top:7px}
    .ap-fsec .ap-clear{align-self:center}
    .ap-qfbox{background:#fff;border:1px solid #d3d8de;border-radius:6px;padding:4px 6px 6px;margin:0 0 0 30px;width:230px}
    .ap-qf{display:flex;align-items:center;gap:10px;height:35px;margin-bottom:5px;padding:0 8px 0 9px;border-radius:4px;color:#1c2127;font-size:14px}
    .ap-qf:hover{background:#f6f7f9}.ap-qf.on{background:#f3f8ff;color:#215db0;font-weight:400;box-shadow:inset 0 0 0 1px #689df3;border-radius:3px}
    .ap-qf.gap{color:#1c2127;cursor:default}.ap-qfi{display:inline-flex;color:#5f6b7c;width:16px;flex:0 0 16px}.ap-qf.on .ap-qfi{color:#215db0}
    .ap-qfc{margin-left:auto;font-size:12px;color:#1c2127;background:#eef0f3;border-radius:4px;padding:1px 7px;line-height:18px}
    .ap-qf:last-child{margin-bottom:0}
    .ap-qfdiv{height:1px;background:#eef0f3;margin:0 0 5px}
    .ap-ff{display:flex;flex-direction:column;padding:0 0 0 45px;margin-top:0}
    .ap-ff .ap-flabel:first-child{margin-top:15px}
    .ap-flabel{display:block;font-size:12px;line-height:15.4297px;height:15.43px;color:#5f6b7c;margin:31px 0 0}
    .ap-fsel{margin-top:5px;height:30px;padding:0 9px;border:1px solid #d3d8de;border-radius:4px;font:inherit;font-size:14px;background:#fff;color:#1c2127;width:100%}
    .ap-fsel[disabled]{background:#eef1f5;color:#3a3f46;cursor:not-allowed}
    .ap-fcheck{display:flex;align-items:center;gap:8px;font-size:14px;color:#1c2127;margin-top:20px}.ap-fcheck.gap{cursor:not-allowed}
    .ap-list{flex:1 1 auto;overflow:auto;padding:18px 22px;background:#f4f5f7}
    .ap-listhd{display:flex;align-items:center;justify-content:space-between;gap:12px;margin:0 0 14px}
    .ap-list h2{font-size:15px;margin:0;font-weight:600}.ap-n{color:#9aa0a8;font-weight:400}
    .ap-listtools{display:flex;align-items:center;gap:12px}
    .ap-search{display:inline-flex;align-items:center;gap:7px;background:#fff;border:1px solid #d6dae0;border-radius:8px;padding:6px 12px;color:#9aa0a8;font-size:12.5px;cursor:not-allowed}
    .ap-sort{color:#6b7178;font-size:12.5px;cursor:not-allowed}
    .ap-rows{background:#fff;border:1px solid #e6e8ec;border-radius:10px;overflow:hidden}
    .ap-row{display:flex;align-items:center;gap:12px;padding:12px 16px;border-bottom:1px solid #f0f1f4;color:#1a1d21}
    .ap-row:last-child{border-bottom:0}.ap-row:hover{background:#f7f9fc}.ap-row.on{background:#eef2fb}
    .ap-rowic{display:inline-flex;color:#8b9099}
    .ap-rowmain{flex:1;min-width:0;display:flex;flex-direction:column;gap:2px}
    .ap-rowtitle{font-weight:600;font-size:13px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
    .ap-rowsub{font-size:12px;color:#8b9099}.ap-rowst{flex:0 0 auto}
    .ap-detail{flex:0 0 320px;width:320px;background:#fff;border-left:1px solid #e6e8ec;overflow-y:auto;padding:18px}
    .ap-dhd{display:flex;align-items:center;gap:9px;font-size:14px;margin:0 0 12px}
    .ap-drow{display:flex;justify-content:space-between;gap:10px;padding:7px 0;border-bottom:1px solid #f0f1f4;font-size:12.5px}.ap-drow>span:first-child{color:#8b9099}
    .ap-dactions{margin:14px 0 8px;display:flex;gap:6px;align-items:center;flex-wrap:wrap}
    .ap-dclose{font-size:12.5px}.ap-dgaps{color:#8b9099;font-size:11.5px;margin-top:12px;line-height:1.6}
    .ap-pill{display:inline-block;padding:2px 10px;border-radius:999px;font-size:11.5px;border:1px solid;white-space:nowrap;font-weight:500}
    .ap-pill.ok{color:#1a7f43;border-color:#bfe4cd;background:#eafaf0}
    .ap-pill.warn{color:#2f6fd8;border-color:#c5d8f5;background:#eef4fe}
    .ap-pill.muted{color:#6b7178;border-color:#e0e3e8;background:#f3f4f6}
    .ap-muted{color:#8b9099}.ap-code{font-family:ui-monospace,monospace;font-size:11px;color:#6b7178;background:#f1f3f6;padding:1px 5px;border-radius:4px}
    .ap-empty{color:#8b9099;padding:24px;border:1px dashed #d8dbe0;border-radius:12px;background:#fff}
    .ap-inp{width:96px;padding:6px 9px;border-radius:7px;border:1px solid #d6dae0;background:#fff;color:#1a1d21;font:inherit;font-size:12px;margin-right:4px}
    form.inline{display:inline}
    .act{padding:6px 13px;border-radius:7px;border:1px solid #d6dae0;background:#fff;color:#3a3f46;font:inherit;font-size:12.5px;font-weight:600;cursor:pointer;margin-right:4px}
    .act.primary{background:#2f6fd8;color:#fff;border-color:#2f6fd8}.act.ghost:hover{border-color:#b6bcc4}
    .ap-banner{margin:0 0 12px;padding:9px 12px;border-radius:6px;font-size:12.5px;line-height:1.5;outline:none}
    .ap-banner code{font-size:10.5px;word-break:break-all}
    .ap-banner.ap-ok{border:1px solid #8fdcb6;background:#eafaf1;color:#0e6b41}
    .ap-banner.ap-no{border:1px solid #e8c48d;background:#fdf7ec;color:#935610}
    .ap-rcpt{background:rgba(14,138,83,.08);border-radius:3px;padding:1px 4px}
    .ap-confirm{display:flex;align-items:center;gap:6px;font-size:11.5px;color:#5f6b7c;margin:0 8px 0 0}`;

  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Approvals inbox</title><style>${css}</style></head>
    <body><div class="ap-shell">${globalRail}<div class="ap-main"><div class="ap-topbar" aria-hidden="true"></div><div class="ap-work"><div class="ap-content">${facets}${list}${detail}</div></div></div></div></body></html>`;
}

