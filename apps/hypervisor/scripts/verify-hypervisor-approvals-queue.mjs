#!/usr/bin/env node
// Approvals queue readiness verifier (06-approvals graft — the wallet-gate station of the P0 walk).
//
// Drives the review-inbox grammar on the Governance approvals tab against REAL ApprovalRequest
// records: creates a pending request with a declared blast radius, asserts the inbox chips /
// queue row / age / blast-radius cells and drawer data are bound to the record's own fields
// (nothing fabricated — requester is honestly "not recorded"), walks approve → revoke through
// the serve forms, asserts terminal rendering, and cleans up. Also asserts the honest empty
// posture text when no requests exist for a filter.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-approvals-queue.mjs

const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");
const SERVE = (process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173").replace(/\/$/, "");

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
async function jd(method, path, body) {
  const r = await fetch(`${DAEMON}${path}`, { method, headers: { "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined });
  return { status: r.status, j: await r.json().catch(() => null) };
}
async function sGet(path) {
  const r = await fetch(`${SERVE}${path}`);
  return { status: r.status, text: await r.text() };
}
async function sForm(path, fields) {
  const r = await fetch(`${SERVE}${path}`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(fields).toString(), redirect: "manual" });
  return r.status;
}

let id = null;
async function run() {
  // 1. Create a pending request with a REAL declared blast radius.
  const created = await jd("POST", "/v1/hypervisor/governance/approval-requests", {
    subject_ref: "authority-action://verify-approvals-queue",
    request_kind: "crossing",
    reason: "verifier: queue grammar exercise",
    required_authority_refs: ["wallet.network/spend"],
    would_call: ["POST /v1/hypervisor/environments (provision)", "POST /v1/hypervisor/authority/grant"],
  });
  id = created.j && created.j.approval_request && created.j.approval_request.id;
  ok("pending request created with blast radius", created.status === 201 && !!id, id || JSON.stringify(created.j));

  // 2. Queue renders the record's own fields.
  const page = await sGet("/__ioi/governance?tab=approvals");
  ok("approvals tab renders 200", page.status === 200);
  ok("inbox chips with counts", page.text.includes("Needs decision") && /data-aq-status="pending"/.test(page.text));
  ok("queue row cites the request", page.text.includes(id) && page.text.includes("verifier: queue grammar exercise"));
  ok("blast radius from record fields", /2 calls/.test(page.text) && /1 authority</.test(page.text));
  ok("subject rendered verbatim", page.text.includes("authority-action://verify-approvals-queue"));
  ok("drawer payload embeds the full record", page.text.includes('id="aq-data"') && page.text.includes("wallet.network/spend"));
  ok("requester honestly not recorded", page.text.includes("not recorded — single-operator estate"));
  ok("oldest-pending age summarized", /oldest pending <b>/.test(page.text));

  // 3. Decide: approve through the serve form (the real transition lane), then verify daemon truth.
  const ap = await sForm(`/__ioi/governance/approvals/${encodeURIComponent(id)}/transition`, { transition: "approve", reviewer_ref: "principal://verifier" });
  ok("approve transition accepted", ap === 302 || ap === 303, `status ${ap}`);
  const after = await jd("GET", `/v1/hypervisor/governance/approval-requests/${encodeURIComponent(id)}`);
  const rec = after.j && (after.j.approval_request || after.j);
  ok("daemon records decision + reviewer", rec && rec.status === "approved" && rec.reviewer_ref === "principal://verifier" && !!rec.decided_at);

  // 4. Approved view offers revoke; walk it to terminal.
  const page2 = await sGet("/__ioi/governance?tab=approvals");
  ok("approved row offers revoke", page2.text.includes(`approvals/${id}/transition`) && page2.text.includes('value="revoke"'));
  const rv = await sForm(`/__ioi/governance/approvals/${encodeURIComponent(id)}/transition`, { transition: "revoke" });
  ok("revoke transition accepted", rv === 302 || rv === 303, `status ${rv}`);
  const page3 = await sGet("/__ioi/governance?tab=approvals");
  ok("terminal state renders", page3.text.includes(">terminal<") || page3.text.includes("revoked"));

  // 5. Home decisions strip stays consistent with the queue (no pending left from this run).
  const home = await sGet("/__ioi/home");
  const pending = ((await jd("GET", "/v1/hypervisor/governance/approval-requests?status=pending")).j || {}).approval_requests || [];
  if (pending.length === 0) ok("Home decisions strip consistent (0 pending)", home.text.includes("no pending approval requests"));
  else ok("Home decisions strip consistent (pending cited)", pending.every((p) => home.text.includes(p.subject_ref || "@")), `${pending.length} pending`);
}

run().then(async () => {
  if (id) await jd("DELETE", `/v1/hypervisor/governance/approval-requests/${encodeURIComponent(id)}`);
  const fails = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
  console.log(`\n${results.length - fails.length}/${results.length} passed`);
  if (fails.length) process.exit(1);
  console.log("approvals-queue readiness: OK");
}).catch(async (e) => {
  if (id) await jd("DELETE", `/v1/hypervisor/governance/approval-requests/${encodeURIComponent(id)}`);
  console.error("verifier crashed:", e);
  process.exit(1);
});
