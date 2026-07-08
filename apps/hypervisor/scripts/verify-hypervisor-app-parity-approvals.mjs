#!/usr/bin/env node
// APPROVALS INBOX REFERENCE PORT — #33 done-bar (the FIRST true daemon_wired / reference UX parity).
//
// /__ioi/governance/approvals is a ported source-neutral "Approvals inbox" SHELL (left rail of inbox
// views · header · toolbar · request table · right detail panel · bottom tray) — NOT the dark
// automationsShell — over the REAL daemon ApprovalRequest queue, with the existing approve/reject/
// revoke transitions (no new governance semantics). The local /__apps/approvals reference BOOTS
// (non-errored), so the Playwright harness certifies structural parity → daemon_wired.
//
// Asserts:
//   - MATRIX: approvals = daemon_wired → /__ioi/governance/approvals (port_surface).
//   - REFERENCE VALID: /__apps/approvals boots the Approvals-inbox grammar, non-errored, brand-clean.
//   - PORTED SHELL (not automationsShell): the page is the ap-shell (rail + body); no .wrap doc.
//   - STRUCTURAL PARITY (harness): structural_parity TRUE against a VALID reference, real screenshots.
//   - DAEMON TRUTH: a real fixture ApprovalRequest renders in the inbox (kind · subject · id); the rail
//     "Needs decision" count + total match the live daemon.
//   - ACTIONS WORK: approving the fixture through the ported inbox drives the real daemon transition
//     and lands back on the port (no new semantics).
//   - NAMED GAPS DISABLED IN PLACE: reviewer-assignment / delegation are disabled controls, not hidden.
//   - DISCOVERABILITY: the Governance surface links the ported inbox first-class.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-app-parity-approvals.mjs
// Exit 2 = BLOCKED.

import { spawnSync } from "node:child_process";
import { readFileSync, existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const SERVE = (process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173").replace(/\/$/, "");
const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");
const here = path.dirname(fileURLToPath(import.meta.url));
const appRoot = path.resolve(here, "..");

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
const jd = async (method, p, body) => { const r = await fetch(`${DAEMON}${p}`, { method, headers: { "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined }); return { status: r.status, j: await r.json().catch(() => ({})) }; };
const page = (url) => fetch(url).then(async (r) => ({ status: r.status, text: await r.text() })).catch(() => ({ status: 0, text: "" }));

async function run() {
  const up = await fetch(`${DAEMON}/v1/hypervisor/governance/approval-requests`).then((r) => r.ok).catch(() => false);
  if (!up) { console.error("BLOCKED: daemon governance plane not reachable at " + DAEMON); process.exit(2); }

  // 0. Matrix — approvals is daemon_wired (the port), not substrate_bound.
  const check = spawnSync("node", [path.join(here, "build-app-parity-matrix.mjs"), "--check"], { encoding: "utf8" });
  ok("parity matrix is current (regenerated == committed)", check.status === 0, (check.stderr || "").trim().slice(0, 80));
  const matrix = JSON.parse(spawnSync("node", ["-e", `import(${JSON.stringify(path.join(here, "..", "harvest-app-parity-matrix.json"))}, { with: { type: "json" } }).then(m => console.log(JSON.stringify(m.default)))`], { encoding: "utf8" }).stdout || "{}");
  const bySlug = Object.fromEntries((matrix.seeds || []).map((s) => [s.slug, s]));
  ok("matrix classifies approvals as daemon_wired → /__ioi/governance/approvals (TRUE parity)", bySlug.approvals?.parity_class === "daemon_wired" && bySlug.approvals?.port_surface === "/__ioi/governance/approvals" && bySlug.approvals?.candidate_surface === "/__ioi/governance/approvals");
  ok("estate honest: reference_capture still the majority; no false 'covered'", (matrix.by_parity_class?.reference_capture || 0) >= (matrix.by_parity_class?.daemon_wired || 0) && !(matrix.seeds || []).some((s) => s.parity_class === "covered"));

  // 1. Reference boots (valid, non-errored).
  const ref = await page(`${SERVE}/__apps/approvals`);
  ok("reference /__apps/approvals boots the Approvals-inbox grammar (non-errored, brand-clean)", ref.status === 200 && /Approvals/i.test(ref.text) && !/an error occurred|something went wrong/i.test(ref.text) && !/\bPalantir\b/.test(ref.text));

  // Fixture: one real pending ApprovalRequest (named subject ref — allowed without resolution).
  const KIND = "app_parity_port";
  const created = await jd("POST", "/v1/hypervisor/governance/approval-requests", { subject_ref: "authority-action://app-parity-approvals-port-fixture", request_kind: KIND, reason: "app-parity approvals PORT fixture", required_authority_refs: ["authority-action://parity-a"], would_call: ["tool://parity-x", "tool://parity-y"] });
  const fix = created.j.approval_request;
  ok("fixture ApprovalRequest created (pending)", created.status === 201 && fix?.status === "pending", fix?.id || "");

  // 2. PORTED SHELL — the ap-shell, not automationsShell.
  const port = await page(`${SERVE}/__ioi/governance/approvals`);
  const t = port.text;
  ok("the ported inbox is the ap-shell (rail + body + right), NOT automationsShell", port.status === 200 && /class="ap-shell"/.test(t) && /class="ap-rail"/.test(t) && /id="ap-body"/.test(t) && !/max-width:920px/.test(t) && !/class="wrap"/.test(t));
  ok("<title>Approvals inbox</title> + inbox views rail (Needs decision / Approved / Rejected / Revoked / All)", /<title>Approvals inbox/.test(t) && /Needs decision/.test(t) && /class="ap-view/.test(t) && [">Approved<", ">Rejected<", ">Revoked<", ">All<"].every((v) => t.includes(v)));

  // 3. STRUCTURAL PARITY — the harness certifies against the VALID reference.
  const artDir = path.join(appRoot, ".artifacts", "approvals-port-verify");
  const h = spawnSync("node", [path.join(here, "harness-reference-parity.mjs")], { encoding: "utf8", timeout: 90000, env: { ...process.env, IOI_HARNESS_SURFACES: "approvals", IOI_HARNESS_ARTIFACT_DIR: artDir } });
  let hp = null;
  if (h.status === 0 && existsSync(path.join(artDir, "result.json"))) hp = (JSON.parse(readFileSync(path.join(artDir, "result.json"), "utf8")).surfaces || [])[0];
  ok("Playwright harness: the port PASSES structural parity against a VALID (non-errored) reference, with real screenshots", hp && hp.structural_parity === true && hp.reference_valid === true && hp.reference_errored === false && hp.evidence_ok === true, hp ? `ref[${hp.reference_regions}] ioi[${hp.ioi_regions}] score ${hp.parity_score} errored=${hp.reference_errored}` : "harness did not run");
  ok("the port reproduces the reference shell (rail + header + body) at score ≥ 0.8", hp && ["rail", "header", "body"].every((r) => hp.ioi_regions.includes(r)) && hp.parity_score >= 0.8);

  // 4. DAEMON TRUTH — the real fixture renders + counts cross-check the live daemon.
  const all = (await jd("GET", "/v1/hypervisor/governance/approval-requests")).j.approval_requests || [];
  const pending = all.filter((a) => a.status === "pending").length;
  ok("the fixture ApprovalRequest renders in the inbox (kind · subject · id) — real daemon truth", fix && t.includes(KIND) && t.includes("authority-action://app-parity-approvals-port-fixture") && t.includes(fix.id));
  ok("CROSS-CHECK: the rail 'Needs decision' count + total match the live daemon", new RegExp(`Needs decision<span class="ap-count">${pending}</span>`).test(t) && new RegExp(`>All<span class="ap-count">${all.length}</span>`).test(t), `pending ${pending} · all ${all.length}`);
  ok("blast radius renders from the record's own would_call + required_authority_refs", /2 calls/.test(t) && /1 authorit/.test(t));

  // 5. ACTIONS WORK — approving through the port drives the REAL daemon transition + returns to the port.
  const form = new URLSearchParams({ transition: "approve", reviewer_ref: "agent://verifier", return: "/__ioi/governance/approvals" });
  const act = await fetch(`${SERVE}/__ioi/governance/approvals/${encodeURIComponent(fix.id)}/transition`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: form.toString(), redirect: "manual" }).catch(() => null);
  const loc = act ? (act.headers.get("location") || "") : "";
  const after = (await jd("GET", `/v1/hypervisor/governance/approval-requests/${fix.id}`)).j.approval_request;
  ok("Approve through the ported inbox drives the real daemon transition (pending → approved) and returns to the port", act && (act.status === 302 || act.status === 303) && loc.includes("/__ioi/governance/approvals") && after?.status === "approved", `redirect ${loc} · now ${after?.status}`);

  // 6. Named gaps disabled in place; brand-clean.
  ok("named gaps are DISABLED controls in place (reviewer assignment · delegation), not hidden", /<button[^>]*disabled[^>]*>Assign reviewer<\/button>/.test(t) && /<button[^>]*disabled[^>]*>Delegate<\/button>/.test(t) && /reviewer assignment/.test(t));
  ok("reference linked as secondary; substrate table still reachable; brand-clean", t.includes("/__apps/approvals") && t.includes("/__ioi/governance?tab=approvals") && !/\bPalantir\b/.test(t));

  // 7. Discoverability — the Governance surface links the ported inbox first-class.
  const gov = await page(`${SERVE}/__ioi/governance`);
  ok("the Governance surface links the ported Approvals inbox first-class", gov.status === 200 && gov.text.includes("/__ioi/governance/approvals"));

  // 8. Cleanup.
  if (fix?.id) await jd("DELETE", `/v1/hypervisor/governance/approval-requests/${fix.id}`);
}

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`approvals-port readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => { console.error("verifier crashed:", e); process.exit(1); });
