#!/usr/bin/env node
// APPROVALS INBOX REFERENCE PORT — #36 done-bar (PROMOTED reference_ported → daemon_wired).
//
// #33 shipped a dark native inbox; #34's hardened gate correctly refused it (theme mismatch vs the
// LIGHT faceted reference). #36 REBUILDS /__ioi/governance/approvals as a FAITHFUL LIGHT FACETED inbox
// matching /__apps/approvals — a dark global rail + a light faceted sidebar (Quick filters: Your inbox /
// Created by you / All requests · Additional filters: Status wired to ?status=, plus faithful named-gap
// facets) + a light request list (kind · subject · id · created · status pill) + an on-select right
// detail with the EXISTING approve/reject/revoke transitions (no new governance semantics). The
// reference boots data-clean (real request rows, light), so the hardened harness certifies visual_parity
// → the SECOND daemon_wired, closing the #34 reclassification loop.
//
// Asserts:
//   - MATRIX: approvals = daemon_wired → /__ioi/governance/approvals, real reference_landmarks, NO
//     parity_blocked (the old block is removed).
//   - REFERENCE VALID + LIGHT + DATA-CLEAN: /__apps/approvals boots the faceted inbox with real rows.
//   - FAITHFUL FACETED SHELL: og-grail global rail + light ap-facets sidebar + light ap-list — NOT the
//     earlier dark ap-rail/ap-table shell, NOT automationsShell.
//   - VISUAL PARITY (hardened harness): visual_parity TRUE — theme light/light + IA-landmark reproduction
//     + region geometry, both sides valid.
//   - DAEMON TRUTH: a real fixture ApprovalRequest renders; the Quick-filters counts match the daemon.
//   - ACTIONS WORK: the on-select detail exposes the real transition; approving drives pending→approved
//     and returns to the port.
//   - NAMED GAPS + DISCOVERABILITY: unwired facets disabled in place; Governance links the inbox; clean.
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
// Retry once: a long harness spawn can leave an idle keep-alive socket that resets on the next fetch.
const page = async (url) => { for (let i = 0; i < 2; i++) { try { const r = await fetch(url); return { status: r.status, text: await r.text() }; } catch { if (i) return { status: 0, text: "" }; } } };

async function run() {
  const up = await fetch(`${DAEMON}/v1/hypervisor/governance/approval-requests`).then((r) => r.ok).catch(() => false);
  if (!up) { console.error("BLOCKED: daemon governance plane not reachable at " + DAEMON); process.exit(2); }

  // 0. Matrix — approvals is daemon_wired, real landmark spec, no parity_blocked.
  const check = spawnSync("node", [path.join(here, "build-app-parity-matrix.mjs"), "--check"], { encoding: "utf8" });
  ok("parity matrix is current (regenerated == committed)", check.status === 0, (check.stderr || "").trim().slice(0, 80));
  const matrix = JSON.parse(spawnSync("node", ["-e", `import(${JSON.stringify(path.join(here, "..", "harvest-app-parity-matrix.json"))}, { with: { type: "json" } }).then(m => console.log(JSON.stringify(m.default)))`], { encoding: "utf8" }).stdout || "{}");
  const bySlug = Object.fromEntries((matrix.seeds || []).map((s) => [s.slug, s]));
  ok("matrix classifies approvals as daemon_wired → /__ioi/governance/approvals (TRUE parity)", bySlug.approvals?.parity_class === "daemon_wired" && bySlug.approvals?.port_surface === "/__ioi/governance/approvals" && bySlug.approvals?.candidate_surface === "/__ioi/governance/approvals");
  ok("approvals carries a real reference_landmarks spec (≥ 5 IA labels) and NO parity_blocked (the #34 block is removed)", Array.isArray(bySlug.approvals?.reference_landmarks) && bySlug.approvals.reference_landmarks.length >= 5 && bySlug.approvals.reference_landmarks.includes("Quick filters") && bySlug.approvals.reference_landmarks.includes("Your inbox") && !bySlug.approvals.parity_blocked, (bySlug.approvals?.reference_landmarks || []).length + " landmarks");
  ok("daemon_wired is the faithful-port set (schema + approvals, + pipeline since #39); reference_capture is the majority", bySlug.schema?.parity_class === "daemon_wired" && bySlug.approvals?.parity_class === "daemon_wired" && (matrix.by_parity_class?.daemon_wired || 0) >= 2 && (matrix.by_parity_class?.reference_capture || 0) > (matrix.by_parity_class?.daemon_wired || 0) && !(matrix.seeds || []).some((s) => s.parity_class === "covered"));

  // 1. Reference boots (light, non-errored) — the SPA hydrates client-side, so the raw HTML shows the
  // app chrome; the DATA-CLEAN faceted IA (Quick filters + real rows) is proven by the Playwright
  // harness (rendered DOM) in step 3, not by the raw HTML here.
  const ref = await page(`${SERVE}/__apps/approvals`);
  ok("reference /__apps/approvals boots the Approvals app (non-errored)", ref.status === 200 && /Approvals/i.test(ref.text) && !/an error occurred|something went wrong|failed to load/i.test(ref.text));

  // Fixture: one real pending ApprovalRequest.
  const KIND = "app_parity_port";
  const created = await jd("POST", "/v1/hypervisor/governance/approval-requests", { subject_ref: "authority-action://app-parity-approvals-port-fixture", request_kind: KIND, reason: "app-parity approvals PORT fixture", required_authority_refs: ["authority-action://parity-a"], would_call: ["tool://parity-x", "tool://parity-y"] });
  const fix = created.j.approval_request;
  ok("fixture ApprovalRequest created (pending)", created.status === 201 && fix?.status === "pending", fix?.id || "");

  // 2. FAITHFUL FACETED SHELL — light, not the earlier dark ap-rail/ap-table shell.
  const port = await page(`${SERVE}/__ioi/governance/approvals`);
  const t = port.text;
  ok("the ported inbox is the FACETED shell (dark og-grail + light ap-facets sidebar w/ its Approvals title + light <main> ap-list)", port.status === 200 && /class="og-grail"/.test(t) && /class="ap-facets"/.test(t) && /<main class="ap-list"[^>]*role="main"/.test(t) && /class="ap-ftitle"/.test(t));
  ok("it is LIGHT-themed and NOT the earlier dark native shell (no ap-rail / ap-table / ap-view; not automationsShell)", /html\{color-scheme:light\}/.test(t) && /background:#f6f7f9/.test(t) && !/color-scheme:dark/.test(t) && !/background:#0c0d10/.test(t) && !/class="ap-rail"/.test(t) && !/class="ap-table"/.test(t) && !/class="ap-view /.test(t) && !/class="wrap"/.test(t) && !/max-width:920px/.test(t));
  ok("<title>Approvals inbox</title> + the reference faceted IA (Quick filters / Additional filters + inbox facets)", /<title>Approvals inbox/.test(t) && ["Quick filters", "Your inbox", "Created by you", "All requests", "Additional filters", "Request type", "Status"].every((l) => t.includes(l)));

  // 3. VISUAL PARITY — the hardened harness certifies against the VALID light reference.
  const artDir = path.join(appRoot, ".artifacts", "approvals-port-verify");
  const h = spawnSync("node", [path.join(here, "harness-reference-parity.mjs")], { encoding: "utf8", timeout: 90000, env: { ...process.env, IOI_HARNESS_SURFACES: "approvals", IOI_HARNESS_ARTIFACT_DIR: artDir } });
  let hp = null;
  if (h.status === 0 && existsSync(path.join(artDir, "result.json"))) hp = (JSON.parse(readFileSync(path.join(artDir, "result.json"), "utf8")).surfaces || [])[0];
  ok("HARDENED harness: the port PASSES visual_parity — theme MATCH (light/light) + full IA-landmark reproduction + region geometry, both sides valid", hp && hp.visual_parity === true && hp.theme_match === true && hp.reference_theme === "light" && hp.ioi_theme === "light" && hp.reference_valid === true && hp.ioi_valid === true && hp.evidence_ok === true, hp ? `visual=${hp.visual_parity} regions ${hp.region_score} theme ${hp.reference_theme}/${hp.ioi_theme} landmarks ${hp.landmark_covered}/${hp.landmark_applicable}` : "harness did not run");
  ok("the port reproduces ALL of the reference's IA landmarks (coverage 1.0) + the core shell regions", hp && hp.landmark_applicable >= 6 && hp.landmark_covered === hp.landmark_applicable && ["rail", "header", "body"].every((r) => hp.ioi_regions.includes(r)) && (hp.landmarks_missing || []).length === 0, hp ? `missing: ${(hp.landmarks_missing || []).join(",") || "none"}` : "");

  // 4. DAEMON TRUTH — the real fixture renders + Quick-filters counts cross-check the live daemon. The
  // count cross-check re-fetches the port + the daemon in ONE adjacent window (the port `t` above was
  // captured before the ~90s harness spawn) so a concurrent create/delete can't cause a false FAIL.
  ok("the fixture ApprovalRequest renders in the list (kind · id) — real daemon truth (the full subject shows in the detail)", fix && t.includes(KIND) && t.includes(fix.id));
  let all = [], pending = 0, tNow = t, matched = false;
  for (let i = 0; i < 5; i++) {
    all = (await jd("GET", "/v1/hypervisor/governance/approval-requests")).j.approval_requests || [];
    pending = all.filter((a) => a.status === "pending").length;
    tNow = (await page(`${SERVE}/__ioi/governance/approvals`)).text;
    matched = new RegExp(`Your inbox<span class="ap-qfc">${pending}</span>`).test(tNow) && new RegExp(`All requests<span class="ap-qfc">${all.length}</span>`).test(tNow);
    if (matched) break;
  }
  ok("CROSS-CHECK: the Quick-filters counts (Your inbox = pending, All requests = total) match the live daemon", matched, `pending ${pending} · all ${all.length}`);

  // 5. ACTIONS WORK — the on-select detail exposes the real transition; approving drives it + returns.
  const detail = await page(`${SERVE}/__ioi/governance/approvals?status=pending&req=${encodeURIComponent(fix.id)}`);
  ok("selecting a request opens the right detail (full subject + REAL approve transition form, return-aware)", /class="ap-detail"/.test(detail.text) && detail.text.includes("authority-action://app-parity-approvals-port-fixture") && new RegExp(`action="/__ioi/governance/approvals/${fix.id}/transition"`).test(detail.text) && /name="transition" value="approve"/.test(detail.text) && detail.text.includes('name="return"'));
  const form = new URLSearchParams({ transition: "approve", reviewer_ref: "agent://verifier", return: "/__ioi/governance/approvals" });
  const act = await fetch(`${SERVE}/__ioi/governance/approvals/${encodeURIComponent(fix.id)}/transition`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: form.toString(), redirect: "manual" }).catch(() => null);
  const loc = act ? (act.headers.get("location") || "") : "";
  const after = (await jd("GET", `/v1/hypervisor/governance/approval-requests/${fix.id}`)).j.approval_request;
  ok("Approve through the ported inbox drives the real daemon transition (pending → approved) and returns to the port", act && (act.status === 302 || act.status === 303) && loc.includes("/__ioi/governance/approvals") && after?.status === "approved", `redirect ${loc} · now ${after?.status}`);
  // SECURITY: a malicious `return` must NOT reflect unescaped into the failure-render page (no XSS). A
  // transition on a bogus id fails → the failure page echoes the (escaped) back link.
  const xss = await fetch(`${SERVE}/__ioi/governance/approvals/${encodeURIComponent("appr_does_not_exist")}/transition`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ transition: "approve", return: `/__ioi/x"><script>alert(1)</script>` }).toString(), redirect: "manual" }).then(async (r) => ({ status: r.status, text: await r.text().catch(() => "") })).catch(() => ({ status: 0, text: "" }));
  ok("SECURITY: a malicious `return` is neutralized — the failure page does NOT reflect a raw <script> (no reflected XSS)", !/<script>alert\(1\)<\/script>/.test(xss.text) && !/"><script/.test(xss.text), `status ${xss.status}`);

  // 6. Named gaps disabled in place; brand-clean.
  ok("unwired facets are DISABLED faithful controls in place (Request type / Created by / Assigned to you / Project / Users-or-groups / Groups + Created-by-you)", (t.match(/class="ap-fsel" disabled/g) || []).length >= 5 && /class="ap-fcheck gap"/.test(t) && /class="ap-qf gap"/.test(t));
  ok("full-text search + sort are named gaps disabled in place", /class="ap-search"[^>]*title="[^"]*named gap/.test(t) && /class="ap-sort"[^>]*title="[^"]*named gap/.test(t));
  ok("substrate table reachable + brand-clean IOI surface", t.includes("/__ioi/governance?tab=approvals") && !/\bPalantir\b|\bFoundry\b/.test(t));

  // 7. Discoverability — the Governance surface links the ported inbox first-class.
  const gov = await page(`${SERVE}/__ioi/governance`);
  ok("the Governance surface links the ported Approvals inbox first-class", gov.status === 200 && gov.text.includes("/__ioi/governance/approvals"));

  // 8. SHELL PIXEL CERTIFICATION (#42) — shell_pixel_certified is a layer ON TOP of daemon_wired:
  // pixel-identical SHELL (committed evidence written by the harness itself), semantically-truthful BODY
  // (the live ApprovalRequest queue + transitions everything above just proved). Matrix and cert agree;
  // the cert is genuine measurement (non-pinned, both desktop viewports, calibrated budgets).
  {
    const { readFileSync } = await import("node:fs");
    const path = (await import("node:path")).default;
    const { fileURLToPath } = await import("node:url");
    const here2 = path.dirname(fileURLToPath(import.meta.url));
    const appRoot2 = path.resolve(here2, "..");
    let row = null, cert = null;
    try { const m = JSON.parse(readFileSync(path.join(appRoot2, "harvest-app-parity-matrix.json"), "utf8")); row = (m.seeds || []).find((x) => x.slug === "approvals"); } catch { /* */ }
    try { cert = JSON.parse(readFileSync(path.join(appRoot2, row.shell_pixel_certification_artifact), "utf8")); } catch { /* */ }
    ok("matrix: approvals is shell_pixel_certified (pixel-identical shell, semantically-truthful body) with a committed evidence pointer, still daemon_wired", row && row.shell_pixel_certified === true && row.shell_pixel_certification_artifact === "pixel-certifications/approvals.json" && row.parity_class === "daemon_wired");
    ok("the committed certification is REAL: approvals slug, certified, NON-pinned, both desktop viewports certified, mobile honestly not-supported", cert && cert.schema === "ioi.hypervisor.shell-pixel-certification.v1" && cert.slug === "approvals" && cert.shell_pixel_certified === true && cert.viewports_pinned === false && (cert.viewports || []).length === 2 && cert.viewports.every((v) => v.certified === true) && /not_supported/.test(cert.mobile), cert ? cert.viewports.map((v) => `${v.viewport}: dilated ${v.metrics.shell_diff_dilated_pct}% raw ${v.metrics.shell_diff_raw_pct}%`).join(" · ") : "cert missing");
    ok("the certification is MEASUREMENT, not convenience: dilated ≤ 1.25% AND raw ≤ 3.0% on every certified viewport, with real certified-shell coverage", cert && cert.viewports.every((v) => v.metrics.shell_diff_dilated_pct <= 1.25 && v.metrics.shell_diff_raw_pct <= 3.0 && v.metrics.coverage.certified_fraction >= 0.05));
  }

  // 9. Cleanup.
  if (fix?.id) await jd("DELETE", `/v1/hypervisor/governance/approval-requests/${fix.id}`);
}

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`approvals-port readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => { console.error("verifier crashed:", e); process.exit(1); });
