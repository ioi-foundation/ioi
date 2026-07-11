#!/usr/bin/env node
// PIXEL-CERTIFIED PARITY verifier — Improvement · Changes done-bar (#53, changes seed only).
//
// The TWELFTH faithful port, the FIFTH from the origin-alignment queue, and the FIRST
// Improvement-family certified surface. The #44 sweep proved the Upgrade Assistant data-bearing on
// the capture-origin lane (localhost:9225/workspace/upgrade-assistant/) while the /__apps/changes
// proxy lane renders thin data; #53 stamps reference_url_override onto the honest lane (the
// What's-new modal dismissed by a reference-only pre-capture hook) and builds
// /__ioi/improvement/changes as a READ-ONLY PROJECTION over the EXISTING improvement-proposal plane.
//
// THE AUTHORITY BOUNDARY (same as Sources): show the improvement truth, never an execution surface.
//   1. MATRIX/CERT/SWEEP: daemon_wired + origin-aligned + REAL non-pinned certification; census >= 12.
//   2. PLANE CROSS-CHECKS: rendered lane count equals the plane after the same filter; a real
//      proposal's signal/ref/kind/state renders; the proof trail (gate posture · approval/release/
//      simulation refs) renders; the Past-due lane is honestly empty (no due-date concept).
//   3. NO EXECUTION SEMANTICS: read-only (no forms, no apply/approve/reject/deploy/release lanes);
//      those stay on the owner surface (/__ioi/agent-studio#improvement-proposals), linked both ways.
//   4. NO body pixel claim: the certification is SHELL-scoped; the grouped rows are masked live data.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-app-parity-changes.mjs
// Exit 2 = BLOCKED.

import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const SERVE = (process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173").replace(/\/$/, "");
const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");
const here = path.dirname(fileURLToPath(import.meta.url));
const appRoot = path.resolve(here, "..");

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
const page = (url) => fetch(url).then(async (r) => ({ status: r.status, text: await r.text() })).catch(() => ({ status: 0, text: "" }));
const jd = (p) => fetch(`${DAEMON}${p}`).then((r) => r.json()).catch(() => ({}));

async function run() {
  const pj = await jd("/v1/hypervisor/intelligence/improvement-proposals");
  const props = pj.proposals || [];
  if (!Array.isArray(pj.proposals)) { console.error("BLOCKED: daemon improvement-proposal plane not reachable at " + DAEMON); process.exit(2); }
  if (!props.length) { console.error("BLOCKED: the improvement plane holds no proposals — the projection port cannot be truth-checked against an empty plane; this verifier never fabricates upgrades."); process.exit(2); }

  // 0. Matrix current + honest.
  const check = spawnSync("node", [path.join(here, "build-app-parity-matrix.mjs"), "--check"], { encoding: "utf8" });
  ok("parity matrix is current (regenerated == committed)", check.status === 0, (check.stderr || "").trim().slice(0, 80));
  const matrix = JSON.parse(readFileSync(path.join(appRoot, "harvest-app-parity-matrix.json"), "utf8"));
  const bySlug = Object.fromEntries((matrix.seeds || []).map((s) => [s.slug, s]));
  const row = bySlug.changes;
  ok("matrix: changes is daemon_wired at /__ioi/improvement/changes (Improvement) with Upgrade-Assistant-IA landmarks", row && row.parity_class === "daemon_wired" && row.candidate_surface === "/__ioi/improvement/changes" && row.surface_name === "Improvement" && Array.isArray(row.reference_landmarks) && row.reference_landmarks.length >= 8, row ? `class=${row.parity_class}` : "row missing");
  ok("matrix: the reference is ORIGIN-ALIGNED (reference_url_override → localhost:9225/workspace/upgrade-assistant/)", row && row.reference_url_override === "http://localhost:9225/workspace/upgrade-assistant/");
  ok("the estate census accepts changes among the certified daemon_wired surfaces (>= 12 since #53); reference_capture stays the honest majority", (matrix.by_parity_class?.daemon_wired || 0) >= 12 && (matrix.by_parity_class?.reference_capture || 0) >= 20, JSON.stringify(matrix.by_parity_class));

  // 0b. Certification is REAL, committed, non-pinned, SHELL-scoped.
  let cert = null;
  try { cert = JSON.parse(readFileSync(path.join(appRoot, row.shell_pixel_certification_artifact), "utf8")); } catch { /* */ }
  ok("matrix: changes is shell_pixel_certified with a committed evidence pointer, still daemon_wired", row && row.shell_pixel_certified === true && row.shell_pixel_certification_artifact === "pixel-certifications/changes.json" && row.parity_class === "daemon_wired");
  ok("the committed certification is REAL: changes slug, certified, NON-pinned, both desktop viewports certified, mobile honestly not-supported", cert && cert.schema === "ioi.hypervisor.shell-pixel-certification.v1" && cert.slug === "changes" && cert.shell_pixel_certified === true && cert.viewports_pinned === false && (cert.viewports || []).length === 2 && cert.viewports.every((v) => v.certified === true) && /not_supported/.test(cert.mobile), cert ? cert.viewports.map((v) => `${v.viewport}: dilated ${v.metrics.shell_diff_dilated_pct}% raw ${v.metrics.shell_diff_raw_pct}%`).join(" | ") : "cert missing");
  ok("the certification passed the visual gates on BOTH viewports (theme + structure + landmarks, both sides valid, against the ORIGIN reference)", cert && cert.reference_url === "http://localhost:9225/workspace/upgrade-assistant/" && cert.viewports.every((v) => v.gates && v.gates.theme_match && v.gates.structural_parity && !v.gates.reference_errored && !v.gates.ioi_errored && v.gates.landmark_covered === v.gates.landmark_applicable));
  ok("NO full-body pixel claim: the certification is explicitly SHELL-scoped (the grouped rows are the masked live data, verified semantically below)", cert && /SHELL/i.test(cert.note || "") && /body/i.test(cert.note || ""));

  // 0c. Sweep contract.
  let sweep = null;
  try { sweep = JSON.parse(readFileSync(path.join(appRoot, "reference-clean-sweep.json"), "utf8")); } catch { /* */ }
  const sw = sweep && (sweep.seeds || []).find((s) => s.slug === "changes");
  ok("clean sweep: changes classifies data_clean on the aligned (origin/override) lane, with real data evidence", sw && sw.clean_state === "data_clean" && ["origin", "override"].includes(sw.lane_used) && (sw.data_evidence?.table_rows > 0 || sw.data_evidence?.cards > 0), sw ? `${sw.clean_state} via ${sw.lane_used}` : "sweep row missing");
  ok("clean sweep: the proxy-lane thin-data blocker stays documented (evidence, not hidden)", sw && (sw.lanes_summary || []).some((l) => l.lane === "proxy"), sw ? JSON.stringify((sw.lanes_summary || []).map((l) => `${l.lane}:score${l.data_score}`)) : "");

  // 1. Reference lanes (SPA — identity markers in raw HTML; data-bearing proven by sweep + cert gates).
  const origin = await page("http://localhost:9225/workspace/upgrade-assistant/");
  ok("origin-aligned reference serves the Upgrade Assistant workspace (valid; data-bearing per sweep + cert gates)", origin.status === 200 && /Upgrade Assistant|upgrade-assistant/.test(origin.text));
  const ref = await page(`${SERVE}/__apps/changes`);
  ok("the /__apps/changes proxy lane still serves (kept as the familiar baseline; documented insufficient — never silently removed)", ref.status === 200);

  // 2. The PORT = the faithful inbox shell over the real plane.
  const cp = await page(`${SERVE}/__ioi/improvement/changes`);
  const t = cp.text;
  ok("the port renders the faithful Upgrade Assistant inbox shell (header + banner + tabs + Filters sidebar + grouped list + truth)", cp.status === 200 && /class="chg-htitle">Upgrade Assistant</.test(t) && /class="chg-tab on"[^>]*>Active</.test(t) && /You are viewing resources for which you are personally assigned actions/.test(t) && /class="chg-sidebar"/.test(t) && /UPGRADE PROGRESS|Upgrade progress/i.test(t) && /Pre-published/.test(t) && /Published/.test(t) && /id="changes-truth"/.test(t));
  ok("all matrix reference landmarks render on the port", (row.reference_landmarks || []).every((l) => t.toLowerCase().includes(String(l).toLowerCase())), (row.reference_landmarks || []).filter((l) => !t.toLowerCase().includes(String(l).toLowerCase())).join(" · ") || "10/10");

  // 3. PLANE CROSS-CHECKS.
  const active = props.filter((p) => p.state !== "rejected");
  const pending = active.filter((p) => p.state === "pending");
  ok("live cross-check: the Active lane's 'All upgrades' count equals the daemon plane after the same filter (non-rejected)", new RegExp(`All upgrades</span><span class="chg-rcount">${active.length}</span>`).test(t), `daemon active=${active.length}`);
  ok("live cross-check: 'Upgrades requiring my action' equals pending-review proposals (the honest mapping — no principal assignment on the plane)", new RegExp(`Upgrades requiring my action</span><span class="chg-rcount">${pending.length}</span>`).test(t), `pending=${pending.length}`);
  // The default view is the Active lane filtered to pending review; assert a real PENDING proposal
  // renders there, and (via the filter=all page) that any proposal's full record renders.
  const pendingProp = pending[0] || active[0];
  const allView = (await page(`${SERVE}/__ioi/improvement/changes?lane=active&filter=all`)).text;
  ok("a REAL proposal renders: signal + proposal_ref + kind pill + state pill (pending in the default view; any in filter=all)", pendingProp && t.includes(pendingProp.proposal_ref) && t.includes(pendingProp.proposal_kind) && allView.includes(props[0].proposal_ref) && allView.includes(props[0].state), pendingProp && pendingProp.proposal_ref);
  ok("the proof trail renders (gate posture + approval/release/simulation refs abbreviated) — real records, never invented", /class="chg-proof"/.test(t) && (/awaiting_approval|awaiting_/.test(t) || / · appr| · rel| · sim/.test(t)));
  ok("the grouped lanes render (Pre-published = not-yet-applied · Published = applied) with live counts", /class="chg-grouptitle"[^>]*>Pre-published<\/h6><span class="chg-grouptag">\d+/.test(t) && /Published<\/h6><span class="chg-grouptag">\d+/.test(t));

  // 4. The Past-due lane is honestly empty (no due-date concept on the plane).
  const pastdue = await page(`${SERVE}/__ioi/improvement/changes?lane=pastdue`);
  ok("the Past-due lane is HONESTLY EMPTY (no due-date concept on the improvement plane — a named gap, not a filtered query)", /The improvement plane records no due dates/.test(pastdue.text) && /named gap/.test(pastdue.text));
  const archived = await page(`${SERVE}/__ioi/improvement/changes?lane=archived`);
  const rejected = props.filter((p) => p.state === "rejected");
  ok("the Archived lane renders the REJECTED proposals (terminal, never applied)", archived.text.includes("Archived upgrades") && (rejected.length ? archived.text.includes(rejected[0].proposal_ref) : /No .* archived proposals/.test(archived.text)), `rejected=${rejected.length}`);

  // 5. NO EXECUTION SEMANTICS — the hard line.
  ok("the surface is READ-ONLY (no forms; no apply/approve/reject/deploy/release affordance)", !/<form/.test(t) && !/action="[^"]*\/(apply|approve|reject|deploy|release|open)"/.test(t));
  ok("the boundary is declared in place: read-only projection, nothing mutates/applies/deploys/releases", /read-only projection/.test(t) && /nothing here mutates, applies, deploys or releases/.test(t));
  ok("unsupported controls are DISABLED IN PLACE with named-gap titles (org · Admin/Assignee view · Help · search · type facets · sort)", (t.match(/aria-disabled="true"/g) || []).length >= 10 && /Organization scoping is a named gap/.test(t) && /Name search is a reference-only lane/.test(t) && /upgrade-type taxonomy is a named gap/.test(t) && /Due-date sorting is a named gap/.test(t), `${(t.match(/aria-disabled="true"/g) || []).length} disabled controls`);

  // 6. Owner discoverability + brand.
  const owner = await page(`${SERVE}/__ioi/agent-studio`);
  ok("owner discoverability: Agent Studio (improvement-proposals) links the inbox first-class, and the port links the owner back", owner.status === 200 && owner.text.includes("/__ioi/improvement/changes") && t.includes("/__ioi/agent-studio#improvement-proposals"));
  ok("the origin-aligned reference + the insufficient proxy lane are BOTH linked and explained on the surface", t.includes("http://localhost:9225/workspace/upgrade-assistant/") && t.includes("/__apps/changes") && /renders thin data/.test(t));
  ok("IOI surface brand-clean (no Palantir)", !/\bPalantir\b/.test(t));
}

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`app-parity-changes readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => { console.error("verifier crashed:", e); process.exit(1); });
