#!/usr/bin/env node
// PIXEL-CERTIFIED PARITY verifier — Workbench · Code Workspaces done-bar (workspaces seed only).
//
// The FOURTEENTH faithful port, the SEVENTH from the origin-alignment queue, and the FIRST
// Workbench-family certified surface. The #44 sweep proved the Code Workspaces launchpad
// data-bearing on the capture-origin lane (localhost:9225/workspace/code-workspaces/) while the
// /__apps/workspaces proxy lane renders no data; this cut stamps reference_url_override onto the
// honest lane and builds /__ioi/workbench/workspaces as a READ-ONLY launchpad over the estate's
// REAL session projection (GET /v1/hypervisor/sessions) + the probed editor-target registry.
//
// THE LAUNCHPAD BOUNDARY IS THE POINT OF THIS VERIFIER: a read projection, never a mutation.
//   1. MATRIX/CERT/SWEEP: daemon_wired + origin-aligned + REAL non-pinned certification; census >= 14.
//   2. SESSION CROSS-CHECKS: rendered rows equal the projection after the declared cap (newest 12;
//      ?view=all renders the whole projection); a REAL session's ref/root/refs render; the
//      Running-workspaces count equals the projection's non-terminal census; the catalog count is
//      the daemon's own total; creator/edited columns are HONEST em-dashes (no principal or edit
//      tracking exists on the projection — named gaps, never invented).
//   3. EDITOR TRUTH: the reference's VS Code/Jupyter/RStudio pills stay named-gap chrome (foreign
//      editor taxonomy); the estate's REAL editor kinds render from the daemon editor-target
//      registry with their PROBED open posture.
//   4. READ-ONLY: the render carries NO form and no mutation affordance; New workspace ROUTES to
//      the Workbench owner surface (the real session/environment lanes); every unbound reference
//      lane is disabled in place with its named reason.
//   5. NO body pixel claim: the certification is SHELL-scoped; rows are masked live data.
//
// FIXTURE ISOLATION: this verifier NEVER writes to the shared daemon. When the real session
// projection is empty (a fresh estate), the dynamic render checks run against an ISOLATED
// daemon+serve pair (lib/isolated-daemon.mjs) with a fixture session provisioned THERE
// (POST /v1/hypervisor/sessions — a real provisioned session) and torn down whole.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-app-parity-workspaces.mjs
// Exit 2 = BLOCKED.

import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { startIsolatedPlane } from "./lib/isolated-daemon.mjs";

const SERVE = (process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173").replace(/\/$/, "");
const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");
const here = path.dirname(fileURLToPath(import.meta.url));
const appRoot = path.resolve(here, "..");

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
const page = (url) => fetch(url).then(async (r) => ({ status: r.status, text: await r.text() })).catch(() => ({ status: 0, text: "" }));

async function run() {
  const seProbe = await fetch(`${DAEMON}/v1/hypervisor/sessions`).then((r) => r.json()).catch(() => ({}));
  if (!Array.isArray(seProbe.sessions)) { console.error("BLOCKED: daemon session projection not reachable at " + DAEMON); process.exit(2); }
  // FIXTURE ISOLATION: with a populated projection the dynamic checks read it as-is (zero writes).
  // With an EMPTY projection they run on an isolated daemon+serve pair with a fixture session
  // provisioned there — the shared daemon is NEVER written.
  let SERVE_D = SERVE, DAEMON_D = DAEMON, plane = null;
  if (!seProbe.sessions.length) {
    plane = await startIsolatedPlane({ serve: true });
    if (!plane) { console.error("BLOCKED: session projection is empty and target/debug/hypervisor-daemon is not built for the isolated fixture lane"); process.exit(2); }
    SERVE_D = plane.serveUrl; DAEMON_D = plane.daemonUrl;
    await fetch(`${DAEMON_D}/v1/hypervisor/sessions`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({}) });
  }
  const jd = (p) => fetch(`${DAEMON_D}${p}`).then((r) => r.json()).catch(() => ({}));
  const se = await jd("/v1/hypervisor/sessions");
  const sessions = se.sessions || [];
  const targets = ((await jd("/v1/hypervisor/editor-targets")).targets) || [];
  const TERMINAL = ["executed", "execution_failed"];
  const running = sessions.filter((s) => !TERMINAL.includes(s.lifecycle_state));

  // 0. Matrix current + honest.
  const check = spawnSync("node", [path.join(here, "build-app-parity-matrix.mjs"), "--check"], { encoding: "utf8" });
  ok("parity matrix is current (regenerated == committed)", check.status === 0, (check.stderr || "").trim().slice(0, 80));
  const matrix = JSON.parse(readFileSync(path.join(appRoot, "harvest-app-parity-matrix.json"), "utf8"));
  const bySlug = Object.fromEntries((matrix.seeds || []).map((s) => [s.slug, s]));
  const row = bySlug.workspaces;
  ok("matrix: workspaces is daemon_wired at /__ioi/workbench/workspaces (Workbench) with launchpad-IA landmarks", row && row.parity_class === "daemon_wired" && row.candidate_surface === "/__ioi/workbench/workspaces" && row.surface_name === "Workbench" && Array.isArray(row.reference_landmarks) && row.reference_landmarks.length >= 8, row ? `class=${row.parity_class}` : "row missing");
  ok("matrix: the reference is ORIGIN-ALIGNED (reference_url_override → localhost:9225/workspace/code-workspaces/)", row && row.reference_url_override === "http://localhost:9225/workspace/code-workspaces/");
  ok("the estate census accepts workspaces among the certified daemon_wired surfaces (>= 14); reference_capture stays the honest majority", (matrix.by_parity_class?.daemon_wired || 0) >= 14 && (matrix.by_parity_class?.reference_capture || 0) >= 20, JSON.stringify(matrix.by_parity_class));

  // 0b. Certification is REAL, committed, non-pinned, SHELL-scoped.
  let cert = null, certRaw = "";
  try { certRaw = readFileSync(path.join(appRoot, row.shell_pixel_certification_artifact), "utf8"); cert = JSON.parse(certRaw); } catch { /* */ }
  ok("matrix: workspaces is shell_pixel_certified with a committed evidence pointer, still daemon_wired", row && row.shell_pixel_certified === true && row.shell_pixel_certification_artifact === "pixel-certifications/workspaces.json" && row.parity_class === "daemon_wired");
  ok("the committed certification is REAL: workspaces slug, certified, NON-pinned, both desktop viewports certified, mobile honestly not-supported", cert && cert.schema === "ioi.hypervisor.shell-pixel-certification.v1" && cert.slug === "workspaces" && cert.shell_pixel_certified === true && cert.viewports_pinned === false && (cert.viewports || []).length === 2 && cert.viewports.every((v) => v.certified === true) && /not_supported/.test(cert.mobile), cert ? cert.viewports.map((v) => `${v.viewport}: dilated ${v.metrics.shell_diff_dilated_pct}% raw ${v.metrics.shell_diff_raw_pct}%`).join(" | ") : "cert missing");
  ok("the certification passed the visual gates on BOTH viewports (theme + structure + landmarks, both sides valid, against the ORIGIN reference)", cert && cert.reference_url === "http://localhost:9225/workspace/code-workspaces/" && cert.viewports.every((v) => v.gates && v.gates.theme_match && v.gates.structural_parity && !v.gates.reference_errored && !v.gates.ioi_errored && v.gates.landmark_covered === v.gates.landmark_applicable));
  ok("NO full-body pixel claim: the certification is explicitly SHELL-scoped (session rows are the masked live data, verified semantically below)", cert && /SHELL/i.test(cert.note || "") && /body/i.test(cert.note || ""));

  // 0c. Sweep contract.
  let sweep = null;
  try { sweep = JSON.parse(readFileSync(path.join(appRoot, "reference-clean-sweep.json"), "utf8")); } catch { /* */ }
  const sw = sweep && (sweep.seeds || []).find((s) => s.slug === "workspaces");
  ok("clean sweep: workspaces classifies data_clean on the aligned (origin/override) lane, with real data evidence", sw && sw.clean_state === "data_clean" && ["origin", "override"].includes(sw.lane_used) && (sw.data_evidence?.table_rows > 0 || sw.data_evidence?.cards > 0), sw ? `${sw.clean_state} via ${sw.lane_used}` : "sweep row missing");
  ok("clean sweep: the proxy-lane no-data blocker stays documented (evidence, not hidden)", sw && (sw.lanes_summary || []).some((l) => l.lane === "proxy" && (l.data_score || 0) < 3), sw ? JSON.stringify((sw.lanes_summary || []).map((l) => `${l.lane}:score${l.data_score}`)) : "");

  // 1. Reference lanes (the origin lane is an SPA shell — identity markers in raw HTML; data-bearing
  // rendering is proven by the sweep's Playwright evidence + the certification's reference gates).
  const origin = await page("http://localhost:9225/workspace/code-workspaces/");
  ok("origin-aligned reference serves the Code Workspaces workspace (valid; data-bearing per sweep + cert gates)", origin.status === 200 && /Code Workspaces|code-workspaces/.test(origin.text));
  const ref = await page(`${SERVE}/__apps/workspaces`);
  ok("the /__apps/workspaces proxy lane still serves (kept as the familiar baseline; documented insufficient — never silently removed)", ref.status === 200);

  // 2. The PORT = the faithful launchpad shell over the real projection.
  const sp = await page(`${SERVE_D}/__ioi/workbench/workspaces`);
  const t = sp.text;
  ok("the port renders the faithful Code Workspaces launchpad shell (topbar + band + running card + View pills + table + examples + catalog)", sp.status === 200 && /class="cw-htitle">Code Workspaces</.test(t) && /Running workspaces/.test(t) && /Launch code workspaces that run open-source IDEs and notebooks\./.test(t) && /class="cw-thead"/.test(t) && /Explore reference examples/.test(t) && /id="workspaces-catalog"/.test(t));
  ok("all matrix reference landmarks render on the port", (row.reference_landmarks || []).every((l) => t.toLowerCase().includes(String(l).toLowerCase())), (row.reference_landmarks || []).filter((l) => !t.toLowerCase().includes(String(l).toLowerCase())).join(" · ") || `${(row.reference_landmarks || []).length}/${(row.reference_landmarks || []).length}`);

  // 3. SESSION CROSS-CHECKS.
  const catalogTotal = typeof se.total === "number" ? se.total : sessions.length;
  ok("the session-catalog count is the daemon's own total (never the capped rows)", new RegExp(`Session catalog <span class="cw-count">${catalogTotal}</span>`).test(t), `daemon total=${catalogTotal}`);
  ok("rendered rows equal the projection after the declared cap (newest 12)", (t.match(/class="cw-row"/g) || []).length === Math.min(12, sessions.length) && /newest 12 shown above/.test(t), `${(t.match(/class="cw-row"/g) || []).length} rows vs ${Math.min(12, sessions.length)}`);
  const all = await page(`${SERVE_D}/__ioi/workbench/workspaces?view=all`);
  ok("?view=all renders the WHOLE projection (the All pill is wired, honestly capped at the daemon's newest-50 projection)", (all.text.match(/class="cw-row"/g) || []).length === sessions.length && new RegExp(`all ${sessions.length} projection rows shown above`).test(all.text), `${(all.text.match(/class="cw-row"/g) || []).length} vs ${sessions.length}`);
  const newest = [...sessions].sort((a, b) => String(b.created_at || "").localeCompare(String(a.created_at || "")))[0];
  ok("a REAL session renders: ref + workspace root + lifecycle state in the newest row", newest && t.includes(String(newest.session_ref || "").replace(/^session:/, "")) && (!newest.workspace_root || t.includes(newest.workspace_root)) && t.includes(newest.lifecycle_state || "provisioned"), newest && newest.session_ref);
  ok("the Running-workspaces card equals the projection's non-terminal census (or renders the honest empty copy)", running.length ? new RegExp(`<b>${running.length}</b> provisioned session`).test(t) : /You have no running workspaces/.test(t), `${running.length} non-terminal`);
  ok("creator / last-edited-by / last-edited columns are HONEST em-dashes (no principal or edit tracking on the projection)", (t.match(/class="cw-dash"/g) || []).length === 3 * Math.min(12, sessions.length) && /No creating principal is recorded/.test(t) && /No edit principal is recorded/.test(t));
  ok("the lifecycle census renders real projection truth (non-terminal · executed · failed)", new RegExp(`${running.length} non-terminal · \\d+ executed · \\d+ failed`).test(t));

  // 3b. EDITOR TRUTH.
  ok("the estate's REAL editor kinds render from the daemon editor-target registry with probed posture", targets.length ? targets.every((tg) => t.includes(tg.target_id)) && /PROBED open posture/.test(t) : /unreachable or empty — nothing is invented/.test(t), `${targets.length} targets`);
  ok("the reference's editor pills stay NAMED-GAP chrome (foreign taxonomy, declared)", /Foreign editor taxonomy/.test(t) && /VS Code/.test(t) && /Jupyter/.test(t) && /RStudio/.test(t));

  // 4. READ-ONLY — the launchpad boundary.
  ok("the render carries NO form and no mutation affordance", !/<form/.test(t) && !/method="post"/i.test(t));
  ok("New workspace ROUTES to the Workbench owner surface (a link, not a mutation on this surface)", /<a class="cw-hbtn success" href="\/__ioi\/workbench"/.test(t) && /mutates nothing/.test(t));
  ok("unbound reference lanes stay DISABLED IN PLACE with named reasons (store · Help · Favorites · Created-by-me · editor pills ×3 · example installs ×2)", (t.match(/aria-disabled="true"/g) || []).length >= 9 && /marketplace install lanes are not bound/i.test(t) && /Favorites are not recorded/.test(t) && /identity-mapping phase/i.test(t), `${(t.match(/aria-disabled="true"/g) || []).length} disabled controls`);
  ok("the verbatim strip is declared capture chrome, not estate data", /verbatim capture chrome/.test(t) && /not estate data/.test(t));

  // 5. Owner discoverability + brand.
  const wb = await page(`${SERVE_D}/__ioi/workbench`);
  ok("owner discoverability: Workbench links the launchpad first-class, and the port links Workbench + Sessions + Environments back", wb.status === 200 && wb.text.includes("/__ioi/workbench/workspaces") && t.includes('href="/__ioi/workbench"') && t.includes('href="/__ioi/sessions"') && t.includes('href="/__ioi/environments"'));
  ok("the origin-aligned reference + the insufficient proxy lane are BOTH linked and explained on the surface", t.includes("http://localhost:9225/workspace/code-workspaces/") && t.includes("/__apps/workspaces") && /renders no data/.test(t));
  ok("IOI surface brand-clean (no Palantir)", !/\bPalantir\b/.test(t));

  if (plane) await plane.stop();
}

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`app-parity-workspaces readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => { console.error("verifier crashed:", e); process.exit(1); });
