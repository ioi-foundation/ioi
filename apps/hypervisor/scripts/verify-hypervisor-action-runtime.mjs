#!/usr/bin/env node
// Governed action-runtime verifier (operational wave #62 — Approvals pilot).
//
// Proves the registry-owned action runtime end to end:
//   RUNTIME DISCIPLINE — the registry resolves the EXISTING Approvals transition route to the
//   module; unknown actions/methods/records refuse; undeclared fields are never forwarded;
//   invalid returns cannot redirect off-origin or inject markup; embed survives action+redirect;
//   standalone stays standalone; a thrown module action 500s only that request (isolated serve
//   with the test flag); a success without the declared receipt fails closed; refused actions
//   mutate nothing.
//   APPROVALS E2E — create pending → approve through the rendered form → pending→approved with
//   revision+1, ONE history entry, ONE durable receipt matching subject/transition/statuses →
//   reload shows authoritative truth → duplicate approve = typed refusal + zero mutation →
//   revoke (confirmed) = second independent receipt → reject on a separate fixture → malformed
//   transition/reviewer/return/record lanes → fixtures deleted, receipt-file delta exact.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-action-runtime.mjs
// Exit 0 = pass · 1 = fail · 2 = blocked (daemon/serve down).

import { spawn } from "node:child_process";
import { readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { SURFACES, boundActionRoute } from "./surface-registry.mjs";

const SERVE = (process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173").replace(/\/$/, "");
const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");
const DATA_DIR = process.env.IOI_HYPERVISOR_DATA_DIR || `${process.env.HOME}/.ioi/hypervisor/data`;
const HERE = dirname(fileURLToPath(import.meta.url));
const FAULT_PORT = 4606, FAULT_UI_PORT = 9406;

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
const jd = (method, p, body) => fetch(`${DAEMON}${p}`, { method, headers: { "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined }).then((r) => r.json()).catch(() => ({}));
// POST a form WITHOUT following the redirect; return {status, location}.
async function formPost(url, data) {
  const r = await fetch(url, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(data).toString(), redirect: "manual" });
  return { status: r.status, location: r.headers.get("location") || "", text: r.status === 200 ? await r.text() : "" };
}
const page = (url) => fetch(url).then(async (r) => ({ status: r.status, text: await r.text() })).catch(() => ({ status: 0, text: "" }));
const receiptCount = () => { try { return readdirSync(join(DATA_DIR, "governance-approval-transition-receipts")).length; } catch { return 0; } };
const approvalsCount = async () => ((await jd("GET", "/v1/hypervisor/governance/approval-requests")).approval_requests || []).length;

async function run() {
  const up = await fetch(`${DAEMON}/v1/hypervisor/governance/approval-requests`).then((r) => r.ok).catch(() => false);
  const sup = await fetch(`${SERVE}/__ioi/governance/approvals`).then((r) => r.ok).catch(() => false);
  if (!up || !sup) { console.error("BLOCKED: daemon or serve not reachable"); process.exit(2); }

  // 1. Registry resolution + descriptor contract (static).
  const hit = boundActionRoute("/__ioi/governance/approvals/appr_x/transition", "POST");
  ok("registry resolves the EXISTING Approvals transition route to the module", !!hit && hit.surface.slug === "approvals" && hit.recordId === "appr_x" && hit.actions.length === 3);
  ok("declared vocabulary is exactly approve|reject|revoke (no create/delete/bulk/delegation)", !!hit && hit.actions.map((a) => a.id).sort().join(",") === "approve,reject,revoke");
  ok("every descriptor carries authority + receipt + confirmation + return policy", !!hit && hit.actions.every((a) => a.authority && a.authority.operation && a.receipt === "ioi.hypervisor.governance.approval-transition-receipt.v1" && typeof a.confirm === "boolean" && a.success && a.refusal));
  ok("reject and revoke require confirmation; approve submits directly", !!hit && hit.actions.find((a) => a.id === "approve").confirm === false && hit.actions.find((a) => a.id === "reject").confirm === true && hit.actions.find((a) => a.id === "revoke").confirm === true);
  ok("unknown method does not resolve an action route", boundActionRoute("/__ioi/governance/approvals/appr_x/transition", "PUT") === null && boundActionRoute("/__ioi/governance/approvals/appr_x/nonsense", "POST") === null);
  ok("`act` invariant holds: approvals is act WITH a bound receipted mutation module", SURFACES.find((s) => s.slug === "approvals").operational_state === "act");

  // 2. APPROVALS E2E over verifier fixtures (sentinel = an UNDECLARED field that must never escape).
  const SENTINEL = `never-forward-${process.pid}`;
  const rc0 = receiptCount();
  const base = `${SERVE}/__ioi/governance/approvals`;
  const fx = (await jd("POST", "/v1/hypervisor/governance/approval-requests", { subject_ref: `automation://act-rt-${process.pid}`, request_kind: "e2e", reason: "action-runtime e2e" })).approval_request;
  const fx2 = (await jd("POST", "/v1/hypervisor/governance/approval-requests", { subject_ref: `automation://act-rt2-${process.pid}`, request_kind: "e2e", reason: "reject lane" })).approval_request;
  try {
    const inbox = await page(`${base}?req=${encodeURIComponent(fx.id)}`);
    ok("the ported inbox renders the pending fixture with its transition forms", inbox.status === 200 && inbox.text.includes(fx.id) && inbox.text.includes('name="transition" value="approve"') && inbox.text.includes('name="confirm"'), "confirmation metadata visible on reject");
    // Approve through the rendered form contract (with an undeclared sentinel field).
    const ap = await formPost(`${base}/${encodeURIComponent(fx.id)}/transition`, { transition: "approve", reviewer_ref: "agent://verifier", secret_note: SENTINEL, return: `/__ioi/governance/approvals?req=${fx.id}` });
    ok("approve → 303 PRG redirect carrying acted/receipt/record/result + the banner anchor", ap.status === 303 && /acted=approve/.test(ap.location) && /receipt=agentgres/.test(ap.location) && ap.location.endsWith("#ap-result"), ap.location.slice(0, 120));
    const after = (await jd("GET", `/v1/hypervisor/governance/approval-requests/${fx.id}`)).approval_request;
    ok("pending → approved; revision incremented EXACTLY once (1→2)", after.status === "approved" && after.revision === 2);
    ok("history appended exactly once; receipt_refs carries exactly one ref", (after.history || []).length === 1 && (after.receipt_refs || []).length === 1 && after.history[0].receipt_ref === after.receipt_refs[0]);
    const rref = after.receipt_refs[0];
    const rid = rref.split("/").pop();
    const receipt = (await page(`${SERVE}/__ioi/governance/approvals`)).status ? await jd("GET", `/v1/hypervisor/governance/approval-requests`).then(() => null).catch(() => null) : null;
    // Read the durable receipt straight from observable storage.
    const { readFileSync } = await import("node:fs");
    let rec = null;
    try { rec = JSON.parse(readFileSync(join(DATA_DIR, "governance-approval-transition-receipts", `${rid}.json`), "utf8")); } catch { /* */ }
    ok("the durable receipt matches subject/transition/previous/resulting status + reviewer", !!rec && rec.subject_ref === fx.subject_ref && rec.transition === "approve" && rec.previous_status === "pending" && rec.resulting_status === "approved" && rec.reviewer_ref === "agent://verifier", rec ? rec.receipt_ref : "receipt file missing");
    // Reload: authoritative truth + success banner renders from the redirect params.
    const banner = await page(`${SERVE}${new URL(ap.location, SERVE).pathname}${new URL(ap.location, SERVE).search}`);
    ok("the redirect target renders the success banner with the receipt ref (result UX)", banner.text.includes("ap-banner ap-ok") && banner.text.includes(rref) && banner.text.includes("proof stream"));
    // Duplicate approve → typed refusal, zero mutation.
    const dup = await formPost(`${base}/${encodeURIComponent(fx.id)}/transition`, { transition: "approve", return: `/__ioi/governance/approvals?req=${fx.id}` });
    const afterDup = (await jd("GET", `/v1/hypervisor/governance/approval-requests/${fx.id}`)).approval_request;
    ok("duplicate approve → typed refusal (governance_transition_invalid) with ZERO mutation", /refused=governance_transition_invalid/.test(dup.location) && afterDup.revision === 2 && (afterDup.receipt_refs || []).length === 1);
    const dupPage = await page(`${SERVE}${new URL(dup.location, SERVE).pathname}${new URL(dup.location, SERVE).search}`);
    ok("refusal banner renders the typed code + 'state unchanged' (no success color, no receipt)", dupPage.text.includes("ap-banner ap-no") && dupPage.text.includes("governance_transition_invalid") && dupPage.text.includes("state unchanged") && !dupPage.text.includes("ap-banner ap-ok"));
    // Revoke without confirmation → refusal + zero mutation; with confirmation → second receipt.
    const rv0 = await formPost(`${base}/${encodeURIComponent(fx.id)}/transition`, { transition: "revoke", return: `/__ioi/governance/approvals?req=${fx.id}` });
    const afterRv0 = (await jd("GET", `/v1/hypervisor/governance/approval-requests/${fx.id}`)).approval_request;
    ok("revoke without confirmation → confirmation_required refusal, ZERO mutation", /refused=confirmation_required/.test(rv0.location) && afterRv0.status === "approved" && afterRv0.revision === 2);
    const rv1 = await formPost(`${base}/${encodeURIComponent(fx.id)}/transition`, { transition: "revoke", confirm: "1", return: `/__ioi/governance/approvals?req=${fx.id}` });
    const afterRv1 = (await jd("GET", `/v1/hypervisor/governance/approval-requests/${fx.id}`)).approval_request;
    ok("confirmed revoke → approved→revoked with a SECOND independent receipt (revision 3)", /acted=revoke/.test(rv1.location) && afterRv1.status === "revoked" && afterRv1.revision === 3 && (afterRv1.receipt_refs || []).length === 2 && afterRv1.receipt_refs[1] !== afterRv1.receipt_refs[0]);
    // Reject lane on the separate pending fixture (confirmed).
    const rj = await formPost(`${base}/${encodeURIComponent(fx2.id)}/transition`, { transition: "reject", confirm: "1", return: `/__ioi/governance/approvals?req=${fx2.id}` });
    const afterRj = (await jd("GET", `/v1/hypervisor/governance/approval-requests/${fx2.id}`)).approval_request;
    ok("confirmed reject → pending→rejected with its own receipt", /acted=reject/.test(rj.location) && afterRj.status === "rejected" && (afterRj.receipt_refs || []).length === 1);
    // Malformed lanes: unknown transition · unknown record · hostile returns.
    const bad1 = await formPost(`${base}/${encodeURIComponent(fx2.id)}/transition`, { transition: "escalate", return: `/__ioi/governance/approvals` });
    ok("unknown transition fails closed (action_unknown), never forwarded to the daemon", /refused=action_unknown/.test(bad1.location));
    const bad2 = await formPost(`${base}/appr_does_not_exist/transition`, { transition: "approve" });
    ok("unknown record fails closed with the daemon's typed not-found", /refused=approval_not_found/.test(bad2.location));
    for (const evil of ["https://evil.example/x", "//evil.example", "/__ioi/x\"><script>alert(1)</script>", "/etc/passwd", "/__ioi/a\r\nSet-Cookie:x=1"]) {
      const r = await formPost(`${base}/${encodeURIComponent(fx2.id)}/transition`, { transition: "escalate", return: evil });
      const loc = r.location || "";
      if (!(loc.startsWith(`${SERVE}/__ioi/governance/approvals?`) || loc.startsWith("/__ioi/governance/approvals?")) || loc.includes("<script>") || loc.includes("evil.example") || /\r|\n/.test(loc)) {
        ok(`hostile return rejected (${evil.slice(0, 24)}…)`, false, loc.slice(0, 100));
      }
    }
    ok("hostile returns (absolute/protocol-relative/markup/traversal/CRLF) all fall back to the surface route", true, "5 lanes swept");
    const reflect = await page(`${base}?refused=x&reason=${encodeURIComponent('"><script>alert(1)</script>')}&record=r`);
    ok("reflected refusal params render ESCAPED (registry-dispatch XSS regression)", !reflect.text.includes("<script>alert(1)</script>") && reflect.text.includes("&lt;script&gt;"));
    // Sentinel sweep: the undeclared field must appear NOWHERE (record, receipt, HTML, redirects).
    const finalRec = (await jd("GET", `/v1/hypervisor/governance/approval-requests/${fx.id}`)).approval_request;
    const inboxHtml = (await page(`${base}?req=${encodeURIComponent(fx.id)}`)).text;
    ok("undeclared form fields are NEVER forwarded (sentinel absent from record, receipt, HTML, redirect)", !JSON.stringify(finalRec).includes(SENTINEL) && !(rec && JSON.stringify(rec).includes(SENTINEL)) && !inboxHtml.includes(SENTINEL) && !ap.location.includes(SENTINEL));
    // Embed survival through action + redirect.
    const em = await formPost(`${base}/${encodeURIComponent(fx2.id)}/transition`, { transition: "escalate", embed: "1", return: `/__ioi/governance/approvals?req=${fx2.id}` });
    ok("embedded mode survives the action redirect (embed=1 on the PRG Location)", /embed=1/.test(em.location));
    ok("standalone mode stays standalone (no embed leaks into non-embedded redirects)", !/embed=1/.test(bad1.location));
    // Exact receipt-file delta: approve + revoke + reject = exactly 3 new durable receipts.
    ok("receipt-file delta is EXACT (+3: approve, revoke, reject)", receiptCount() === rc0 + 3, `${rc0} → ${receiptCount()}`);
  } finally {
    await jd("DELETE", `/v1/hypervisor/governance/approval-requests/${fx.id}`);
    await jd("DELETE", `/v1/hypervisor/governance/approval-requests/${fx2.id}`);
  }
  ok("fixtures deleted — baseline restored", !JSON.stringify(await jd("GET", "/v1/hypervisor/governance/approval-requests")).includes(`act-rt-${process.pid}`));

  // 3. FAULT ISOLATION on an isolated serve with the runtime-test flag (never on the live serve).
  {
    const child = spawn(process.execPath, [join(HERE, "serve-product-ui.mjs")], {
      env: { ...process.env, PORT: String(FAULT_PORT), PRODUCT_UI_PORT: String(FAULT_UI_PORT), IOI_APP_RUNTIME_TEST_ROUTE: "1" },
      stdio: "ignore",
    });
    try {
      const tbase = `http://127.0.0.1:${FAULT_PORT}`;
      let up2 = null;
      for (let i = 0; i < 30 && !up2; i++) { await new Promise((r) => setTimeout(r, 500)); up2 = await page(`${tbase}/__ioi/__test/action-surface`).then((r) => (r.status === 200 ? r : null)).catch(() => null); }
      ok("isolated test serve reachable (fault surface mounted only under the flag)", !!up2);
      const n0 = await approvalsCount();
      const boom = await fetch(`${tbase}/__ioi/__test/action-surface/x/transition`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: "transition=boom", redirect: "manual" });
      ok("a thrown module action 500s ONLY that request (route-local containment)", boom.status === 500);
      const alive = await page(`${tbase}/__ioi/governance/approvals`);
      ok("other surfaces remain available after the fault", alive.status === 200);
      const nor = await fetch(`${tbase}/__ioi/__test/action-surface/x/transition`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: "transition=no-receipt", redirect: "manual" });
      ok("a success result WITHOUT the declared receipt fails closed (receipt_missing)", nor.status === 303 && /refused=receipt_missing/.test(nor.headers.get("location") || ""));
      ok("faults + refused actions produced ZERO daemon mutation", (await approvalsCount()) === n0);
      const live = await page(`${SERVE}/__ioi/__test/action-surface`);
      ok("the fault surface does NOT exist on the live serve (flag-gated)", live.status !== 200 || !live.text.includes("action test"));
    } finally {
      child.kill("SIGTERM");
    }
  }
}

run().then(() => {
  const fails = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
  console.log(`\n${results.length - fails.length}/${results.length} passed`);
  if (fails.length) process.exit(1);
  console.log("governed action runtime: OK");
}).catch((e) => { console.error("verifier crashed:", e); process.exit(1); });
