#!/usr/bin/env node
// SUBSTRATE-TRUTH verifier (reclassified substrate_bound by the #31 Reference-UX-Port reset — checks DAEMON TRUTH, NOT reference UX parity) — Governance · Approvals done-bar (approvals seed only).
//
// The parity phase's eighth surface. The reference capture (/__apps/approvals = the approvals inbox)
// is the familiar baseline; the IOI-owned Governance owner surface already renders the SAME
// review-inbox grammar at /__ioi/governance?tab=approvals over REAL daemon ApprovalRequest records
// (status-count inbox chips, blast radius, age, per-row inspector, in-row decisions). This cut
// FORMALIZES that binding (matrix + verifier) and names the unsupported lanes.
//
// SCOPE (tight, by direction): only `approvals` binds. Release controls, kill switches, cohorts, and
// improvement gates remain supporting Governance context (not separate parity claims).
//
// Because the queue is a read-only projection over existing ApprovalRequest truth, the guard is a
// CROSS-CHECK: create one fixture request, then read the live daemon and assert the rendered queue's
// total, status counts, and the oldest+newest pending requests match the daemon exactly.
//
// Asserts:
//   - MATRIX: approvals = substrate_bound → /__ioi/governance?tab=approvals (Governance); not over-claimed.
//   - REFERENCE BASELINE: /__apps/approvals boots the approvals-inbox grammar.
//   - IOI SURFACE = DAEMON TRUTH (substrate, not reference UX parity): the queue renders; total, pending/approved counts,
//     and the oldest+newest pending requests all MATCH the live daemon; the fixture renders in-row.
//   - NO FALSE COVERAGE: named gaps (reviewer assignment / delegation / comments / SLA / identity-team
//     / audit exports); brand-clean; reference seed secondary.
//   - DISCOVERABILITY: the Governance overview links the approvals lens first-class (tab + link).
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-app-parity-approvals.mjs
// Exit 2 = BLOCKED.

import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const SERVE = (process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173").replace(/\/$/, "");
const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");
const here = path.dirname(fileURLToPath(import.meta.url));

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
async function jd(method, p, body) {
  const r = await fetch(`${DAEMON}${p}`, { method, headers: { "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined });
  return { status: r.status, j: await r.json().catch(() => ({})) };
}
const page = (url) => fetch(url).then(async (r) => ({ status: r.status, text: await r.text() })).catch(() => ({ status: 0, text: "" }));

async function run() {
  const up = await fetch(`${DAEMON}/v1/hypervisor/governance/approval-requests`).then((r) => r.ok).catch(() => false);
  if (!up) { console.error("BLOCKED: daemon governance plane not reachable at " + DAEMON); process.exit(2); }

  // 0. Matrix current + honest.
  const check = spawnSync("node", [path.join(here, "build-app-parity-matrix.mjs"), "--check"], { encoding: "utf8" });
  ok("parity matrix is current (regenerated == committed)", check.status === 0, (check.stderr || "").trim().slice(0, 80));
  const matrix = JSON.parse(spawnSync("node", ["-e", `import(${JSON.stringify(path.join(here, "..", "harvest-app-parity-matrix.json"))}, { with: { type: "json" } }).then(m => console.log(JSON.stringify(m.default)))`], { encoding: "utf8" }).stdout || "{}");
  const bySlug = Object.fromEntries((matrix.seeds || []).map((s) => [s.slug, s]));
  ok("matrix binds approvals as substrate_bound → /__ioi/governance?tab=approvals (Governance)", bySlug.approvals?.parity_class === "substrate_bound" && bySlug.approvals?.substrate_surface === "/__ioi/governance?tab=approvals" && bySlug.approvals?.surface_name === "Governance");
  ok("no 'covered' anywhere; prior reclassified surfaces still bound (substrate_bound|daemon_wired) (pipeline/lineage/vertex/jobs/incidents/evalsuites/designer)", !(matrix.seeds || []).some((s) => s.parity_class === "covered") && ["pipeline", "lineage", "vertex", "jobs", "incidents", "evalsuites", "designer"].every((k) => ["substrate_bound", "daemon_wired"].includes(bySlug[k]?.parity_class)));

  // 1. Reference baseline.
  const ref = await page(`${SERVE}/__apps/approvals`);
  ok("reference baseline /__apps/approvals boots the approvals-inbox grammar", ref.status === 200 && /<title>[^<]*(Approval|Task|Request|Inbox)/i.test(ref.text));

  // 2. Fixture: one real pending ApprovalRequest (named subject ref — allowed without resolution).
  const KIND = "app_parity_fixture";
  const created = await jd("POST", "/v1/hypervisor/governance/approval-requests", {
    subject_ref: "authority-action://app-parity-approvals-fixture", request_kind: KIND,
    reason: "app-parity-approvals verifier fixture", required_authority_refs: ["authority-action://parity-a"], would_call: ["tool://parity-x", "tool://parity-y"],
  });
  const fix = created.j.approval_request;
  ok("fixture ApprovalRequest created (pending, real ref)", created.status === 201 && fix?.status === "pending" && fix?.ref?.startsWith("approval-request://"), fix?.id || "");

  // 3. Live daemon truth — the projection the queue must reflect.
  const all = (await jd("GET", "/v1/hypervisor/governance/approval-requests")).j.approval_requests || [];
  const total = all.length;
  const byStatus = { pending: 0, approved: 0, rejected: 0, revoked: 0 };
  for (const a of all) if (byStatus[a.status] != null) byStatus[a.status]++;
  const pend = all.filter((a) => a.status === "pending");
  const sortedPend = pend.slice().sort((a, b) => String(a.created_at || "").localeCompare(String(b.created_at || "")));
  const oldestPend = sortedPend[0];
  const newestPend = sortedPend[sortedPend.length - 1];

  // 4. IOI surface = the review-inbox queue over real truth (cross-checked).
  const q = await page(`${SERVE}/__ioi/governance?tab=approvals`);
  const t = q.text;
  ok("IOI /__ioi/governance?tab=approvals renders the review-inbox queue (inbox chips + queue table)", q.status === 200 && /id="aq-inbox"/.test(t) && />Request<\/th>/.test(t) && />Blast radius<\/th>/.test(t) && />Decide<\/th>/.test(t));
  ok("CROSS-CHECK: status-count inbox chips match the daemon (pending / approved / all)", new RegExp(`Needs decision ${byStatus.pending}\\b`).test(t) && new RegExp(`Approved ${byStatus.approved}\\b`).test(t) && new RegExp(`All ${total}\\b`).test(t), `pending ${byStatus.pending} · approved ${byStatus.approved} · all ${total}`);
  ok("CROSS-CHECK: the family total matches the daemon record count", new RegExp(`Approval Requests \\(${total}\\)`).test(t));
  ok("the fixture request renders in-row (kind + subject_ref + id)", fix && t.includes(KIND) && t.includes("authority-action://app-parity-approvals-fixture") && t.includes(fix.id));
  ok("blast radius renders from the record's own would_call + required_authority_refs", />2 calls</.test(t) && /1 authority</.test(t));
  ok("CROSS-CHECK: newest + oldest pending requests both render (queue spans the real range)", oldestPend && newestPend && t.includes(oldestPend.id) && t.includes(newestPend.id) && /oldest pending/.test(t), `${oldestPend?.id} … ${newestPend?.id}`);

  // 5. No false coverage — named gaps + brand-clean + secondary reference.
  ok("named gaps: reviewer assignment / delegation / comments / SLA / identity-team / audit exports", /reviewer assignment/.test(t) && /delegation/.test(t) && /threaded comments/.test(t) && /SLA/.test(t) && /identity\/team/.test(t) && /audit exports/.test(t));
  ok("reference capture linked as secondary; IOI surface brand-clean (no Palantir)", t.includes("/__apps/approvals") && !/\bPalantir\b/.test(t));

  // 6. Discoverability — the Governance overview links the approvals lens first-class.
  const ov = await page(`${SERVE}/__ioi/governance`);
  ok("Governance overview links the approvals lens first-class (tab + link)", ov.status === 200 && ov.text.includes("/__ioi/governance?tab=approvals") && />Approval Requests</.test(ov.text));

  // 7. Cleanup — delete the fixture; the queue total drops back.
  if (fix?.id) {
    const del = await jd("DELETE", `/v1/hypervisor/governance/approval-requests/${fix.id}`);
    const after = (await jd("GET", "/v1/hypervisor/governance/approval-requests")).j.approval_requests || [];
    ok("fixture cleaned up (deleted; queue total returns to baseline)", (del.status === 200 || del.status === 204) && after.length === total - 1, `${total} → ${after.length}`);
  }
}

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`substrate-truth-approvals readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => { console.error("verifier crashed:", e); process.exit(1); });
