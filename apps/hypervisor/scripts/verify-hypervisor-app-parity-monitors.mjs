#!/usr/bin/env node
// PIXEL-CERTIFIED PARITY verifier — Automations · Monitors done-bar (#51, monitors seed only).
//
// The TENTH faithful port, the THIRD from the origin-alignment queue, and the FIRST
// Automations-family certified surface. The #44 sweep proved the Automate overview data-bearing on
// the capture-origin lane (localhost:9225/workspace/object-monitoring/) while the /__apps/monitors
// proxy lane fails with a favorites-load error + CORS-blocked session lanes; #51 stamps
// reference_url_override onto the honest lane and builds /__ioi/automations/monitors as a NEW
// dedicated port route — a READ-ONLY PROJECTION over the EXISTING automation plane. What this asserts:
//   1. MATRIX: monitors is daemon_wired at /__ioi/automations/monitors, origin-aligned,
//      landmark-pinned, shell_pixel_certified (REAL committed NON-pinned cert); census floor >= 10.
//   2. REFERENCE: the origin lane renders the data-bearing overview; the proxy lane stays served
//      AND documented-insufficient.
//   3. SUBSTRATE TRUTH: the port renders the REAL automation plane — live counts equal the daemon
//      after the same filters (active/user-executed/paused via enabled=false), a real automation id
//      + its executor_identity render, a real execution renders in the Recently-triggered feed with
//      its status + execution/environment refs (the proof trail), and empty lanes stay honest.
//   4. NO NEW SEMANTICS: the surface is read-only (no forms, no run/step/execute), authoring stays
//      on /__ioi/automations (linked first-class both ways), notification lane = honest named gap.
//   5. NO body pixel claim: the certification is SHELL-scoped; the live-data regions sit below the
//      fold and are verified here semantically.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-app-parity-monitors.mjs
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
  const aRes = await jd("/v1/hypervisor/automations");
  const autos = aRes.automations || [];
  if (!Array.isArray(aRes.automations)) { console.error("BLOCKED: daemon automation plane not reachable at " + DAEMON); process.exit(2); }
  if (!autos.length) { console.error("BLOCKED: the automation plane holds no records — the projection port cannot be truth-checked against an empty plane (create one on /__ioi/automations first; this verifier never fabricates monitors)."); process.exit(2); }

  // 0. Matrix current + honest.
  const check = spawnSync("node", [path.join(here, "build-app-parity-matrix.mjs"), "--check"], { encoding: "utf8" });
  ok("parity matrix is current (regenerated == committed)", check.status === 0, (check.stderr || "").trim().slice(0, 80));
  const matrix = JSON.parse(readFileSync(path.join(appRoot, "harvest-app-parity-matrix.json"), "utf8"));
  const bySlug = Object.fromEntries((matrix.seeds || []).map((s) => [s.slug, s]));
  const row = bySlug.monitors;
  ok("matrix: monitors is daemon_wired at /__ioi/automations/monitors (Automations) with Automate-IA landmarks", row && row.parity_class === "daemon_wired" && row.candidate_surface === "/__ioi/automations/monitors" && row.surface_name === "Automations" && Array.isArray(row.reference_landmarks) && row.reference_landmarks.length >= 8, row ? `class=${row.parity_class}` : "row missing");
  ok("matrix: the reference is ORIGIN-ALIGNED (reference_url_override → localhost:9225/workspace/object-monitoring/)", row && row.reference_url_override === "http://localhost:9225/workspace/object-monitoring/");
  ok("the estate census accepts monitors among the certified daemon_wired surfaces (>= 10 since #51); reference_capture stays the honest majority", (matrix.by_parity_class?.daemon_wired || 0) >= 10 && (matrix.by_parity_class?.reference_capture || 0) >= 20, JSON.stringify(matrix.by_parity_class));

  // 0b. Shell-pixel certification is REAL, committed, non-pinned, SHELL-scoped.
  let cert = null;
  try { cert = JSON.parse(readFileSync(path.join(appRoot, row.shell_pixel_certification_artifact), "utf8")); } catch { /* */ }
  ok("matrix: monitors is shell_pixel_certified with a committed evidence pointer, still daemon_wired", row && row.shell_pixel_certified === true && row.shell_pixel_certification_artifact === "pixel-certifications/monitors.json" && row.parity_class === "daemon_wired");
  ok("the committed certification is REAL: monitors slug, certified, NON-pinned, both desktop viewports certified, mobile honestly not-supported", cert && cert.schema === "ioi.hypervisor.shell-pixel-certification.v1" && cert.slug === "monitors" && cert.shell_pixel_certified === true && cert.viewports_pinned === false && (cert.viewports || []).length === 2 && cert.viewports.every((v) => v.certified === true) && /not_supported/.test(cert.mobile), cert ? cert.viewports.map((v) => `${v.viewport}: dilated ${v.metrics.shell_diff_dilated_pct}% raw ${v.metrics.shell_diff_raw_pct}%`).join(" | ") : "cert missing");
  ok("the certification passed the visual gates on BOTH viewports (theme + structure + landmarks 10/10, both sides valid, against the ORIGIN reference)", cert && cert.reference_url === "http://localhost:9225/workspace/object-monitoring/" && cert.viewports.every((v) => v.gates && v.gates.theme_match && v.gates.structural_parity && !v.gates.reference_errored && !v.gates.ioi_errored && v.gates.landmark_covered === v.gates.landmark_applicable));
  ok("NO full-body pixel claim: the certification is explicitly SHELL-scoped (the live-data regions sit below the fold, verified semantically below)", cert && /SHELL/i.test(cert.note || "") && /body/i.test(cert.note || ""));

  // 0c. Sweep contract.
  let sweep = null;
  try { sweep = JSON.parse(readFileSync(path.join(appRoot, "reference-clean-sweep.json"), "utf8")); } catch { /* */ }
  const sw = sweep && (sweep.seeds || []).find((s) => s.slug === "monitors");
  ok("clean sweep: monitors classifies data_clean on the aligned (origin/override) lane, with real data evidence", sw && sw.clean_state === "data_clean" && ["origin", "override"].includes(sw.lane_used) && (sw.data_evidence?.table_rows > 0 || sw.data_evidence?.cards > 0), sw ? `${sw.clean_state} via ${sw.lane_used}` : "sweep row missing");
  ok("clean sweep: the proxy-lane favorites/CORS blocker stays documented (evidence, not hidden)", sw && (sw.lanes_summary || []).some((l) => l.lane === "proxy" && (l.cors_signals > 0 || l.console_errors > 0)), sw ? JSON.stringify((sw.lanes_summary || []).map((l) => `${l.lane}:cors${l.cors_signals}`)) : "");

  // 1. Reference lanes.
  const origin = await page("http://localhost:9225/workspace/object-monitoring/");
  // The origin lane is an SPA shell — the overview copy renders via JS; the raw HTML carries the
  // Automate identity (title + workspace path). Data-bearing rendering is proven by the sweep's
  // Playwright evidence (0c) and the certification's reference gates (0b) above.
  ok("origin-aligned reference serves the Automate workspace (valid; data-bearing per sweep + cert gates)", origin.status === 200 && /<title>Automate/.test(origin.text) && /object-monitoring/.test(origin.text));
  const ref = await page(`${SERVE}/__apps/monitors`);
  ok("the /__apps/monitors proxy lane still serves (kept as the familiar baseline; documented insufficient — never silently removed)", ref.status === 200 && /monitor|automat/i.test(ref.text));

  // 2. The PORT = the faithful overview shell over the real plane.
  const mp = await page(`${SERVE}/__ioi/automations/monitors`);
  const t = mp.text;
  ok("the port renders the faithful Automate overview shell (tabbed header + hero + Getting started + wizard + strips + stats + table + feed)", mp.status === 200 && /class="mon-htitle">Automate</.test(t) && /class="mon-tab on"[^>]*>Overview</.test(t) && /Create and manage automations/.test(t) && /Getting started/.test(t) && /class="mon-wizcard"/.test(t) && /class="mon-cardsstrip"/.test(t) && /Active automations/.test(t) && /Recently viewed/.test(t) && /Recently triggered/.test(t));
  ok("all matrix reference landmarks render on the port", (row.reference_landmarks || []).every((l) => t.toLowerCase().includes(String(l).toLowerCase())), (row.reference_landmarks || []).filter((l) => !t.toLowerCase().includes(String(l).toLowerCase())).join(" · ") || "10/10");

  // 3. LIVE CROSS-CHECKS against the daemon plane (same filters both sides).
  const paused = autos.filter((a) => a.enabled === false);
  const active = autos.filter((a) => a.enabled !== false);
  const userExec = autos.filter((a) => (a.executor_identity || {}).kind === "user");
  ok("live cross-check: the Active-automations count equals the daemon plane after the same filter (enabled !== false)", new RegExp(`Active automations<span class="mon-statcount">${active.length}</span>`).test(t), `daemon active=${active.length}`);
  ok("live cross-check: the user-executed and paused tile counts equal the daemon plane (executor_identity.kind=user · enabled=false)", t.includes(`(real daemon truth)">${userExec.length}<`) && t.includes(`(the plane's own pause lane)">${paused.length}<`), `user=${userExec.length} paused=${paused.length}`);
  ok("the notification tile is an HONEST named-gap 0 (no substrate concept — never a fabricated count)", /No notification-subscription lane exists on the automation plane[^"]*named gap[^"]*">0</.test(t));
  const newest = [...autos].sort((a, b) => String(b.created_at || "").localeCompare(String(a.created_at || "")))[0];
  ok("a REAL automation renders as a row: id + project + trigger + steps census; CREATOR = the real executor_identity.ref", t.includes(newest.automation_id) && t.includes(newest.project_id || "") && ((newest.executor_identity || {}).ref ? t.includes(newest.executor_identity.ref) : true), newest.automation_id);
  ok("rendered rows equal the daemon plane after the same cap (newest 12)", (t.match(/class="mon-row"/g) || []).length === Math.min(12, autos.length), `${(t.match(/class="mon-row"/g) || []).length} rows vs ${Math.min(12, autos.length)}`);
  // A real execution renders with status + proof refs. RE-AIMED (remediation v2): the old check
  // sampled the newest AUTOMATION's first run — not the feed's semantics (top-10 by started_at
  // across the WHOLE plane) — and began failing as the plane grew. Assert exactly what the
  // surface renders: the plane-wide newest execution.
  const runsAll = await Promise.all(autos.map((a) => jd(`/v1/hypervisor/automations/${encodeURIComponent(a.automation_id)}/runs`).then((j) => j.runs || []).catch(() => [])));
  const newestRun = runsAll.flat().sort((x, y) => String(y.started_at || "").localeCompare(String(x.started_at || "")))[0];
  let feedChecked = false, feedDetail = "no executions exist on the plane — feed checked for honest-empty render";
  if (newestRun) { feedChecked = t.includes(newestRun.execution_id); feedDetail = newestRun.execution_id; }
  ok("the PLANE-WIDE NEWEST execution renders in the Recently-triggered feed with its execution ref (the proof trail) — or the feed is honestly empty", feedChecked || /No executions recorded yet/.test(t), feedDetail);
  ok("execution statuses render honestly (completed vs status verbatim; never invented)", /Execution completed|Execution status:|No executions recorded yet/.test(t));
  ok("the em-dash gap columns name their gaps (no edit principal · no view tracking on the automation plane)", /No edit principal is recorded on the automation plane \(named gap\)/.test(t) && /View tracking is not recorded on the automation plane \(named gap\)/.test(t));
  ok("the Recently-viewed ordering is HONESTLY declared creation-recency (no view tracking)", /Ordered by creation recency[^"]*named gap/.test(t));

  // 4. NO NEW SEMANTICS — read-only projection; owner keeps authority lanes.
  ok("the surface is READ-ONLY (no form posts anywhere; no run/step/execute affordance)", !/<form/.test(t) && !/action="[^"]*\/(run|step|execute)"/.test(t));
  ok("the projection declares itself + no scheduler/execution semantics were added", /read-only projection over the real automation plane/.test(t) && /no scheduler or execution semantics were added/.test(t));
  // RE-AIMED by AUT-2: New automation ×2 became LIVE in-shell create links (a gap became a
  // function); the remaining census is store dropdown · Help · template docs ×3 · example installs ×2.
  ok("unsupported controls are DISABLED IN PLACE with named-gap titles (store dropdown · Help · template docs ×3 · example installs ×2); New automation is LIVE", (t.match(/aria-disabled="true"/g) || []).length >= 7 && !/Automation authoring from this surface is a reference-only lane/.test(t) && t.includes("?tab=automations&view=new") && /Template docs are a reference-only lane/.test(t) && /Marketplace example installs are a reference-only lane/.test(t), `${(t.match(/aria-disabled="true"/g) || []).length} disabled controls`);
  ok("the verbatim strips are declared capture chrome (vendor content, never estate data)", /verbatim capture chrome/.test(t) && /never estate data/.test(t));

  // 5. Owner discoverability + brand.
  const owner = await page(`${SERVE}/__ioi/automations`);
  ok("owner discoverability: /__ioi/automations links the overview port first-class, and the port links back (tab + View-all + copy)", owner.status === 200 && owner.text.includes("/__ioi/automations/monitors") && t.includes('href="/__ioi/automations"'));
  ok("the Automations tab is the IN-SHELL live lane (AUT-1) and View-all lands on the owner substrate", /<a class="mon-tab" href="\/__ioi\/automations\/monitors\?tab=automations"/.test(t) && /class="mon-viewall" href="\/__ioi\/automations"/.test(t));

  // 6. AUT-1 — the Automations tab: the reference's own in-app /automations faceted list
  // (atlas: reference-family-atlas.v1.json monitors tab_lane state, 8 facet groups) rebuilt LIVE
  // inside the certified shell. Semantic truth checked against the plane fetched above.
  const tabPage = await page(`${SERVE}/__ioi/automations/monitors?tab=automations`);
  const tt = tabPage.text;
  ok("AUT-1: tab renders 200 with the certified shell (rail + Automate header)", tabPage.status === 200 && tt.includes("og-grail") && tt.includes("Automate"), String(tabPage.status));
  ok("AUT-1: all 7 reference facet groups render", ["STATUS", "CONDITION", "EFFECTS", "RECEIVING NOTIFICATIONS", "OWNER", "CREATOR", "EXPIRATION DATE"].every((g) => tt.includes(g)));
  ok("AUT-1: reference columns render (Name · Condition · Status · Creator)", [">Name</span>", ">Condition</span>", ">Status</span>", ">Creator</span>"].every((c) => tt.includes(c)));
  const liveActive = autos.filter((a) => a.enabled !== false).length;
  const livePaused = autos.length - liveActive;
  ok("AUT-1: row count equals the REAL plane count (no fabrication, no cap)", (tt.match(/class="mon-arow"/g) || []).length === autos.length, `rows=${(tt.match(/class="mon-arow"/g) || []).length} plane=${autos.length}`);
  ok("AUT-1: STATUS facet counts are LIVE plane truth (Active/Paused)", tt.includes(`Active<span class="mon-fn">${liveActive}</span>`) && tt.includes(`Paused<span class="mon-fn">${livePaused}</span>`));
  ok("AUT-1: a sampled REAL automation id renders as a row linking the IN-SHELL detail (AUT-2)", autos.length > 0 && tt.includes(autos[0].automation_id) && tt.includes(`?tab=automations&automation=`));

  // 7. AUT-2 — verbs rehomed under the Automate grammar: in-shell detail + create, every mutation
  // a form posting the EXISTING seed lane (back=automate) — same lanes re-chromed, no second spine.
  const det = await page(`${SERVE}/__ioi/automations/monitors?tab=automations&automation=${encodeURIComponent(autos[0].automation_id)}`);
  const dt = det.text;
  ok("AUT-2: detail renders the REAL spec (name + id + project + trigger)", det.status === 200 && dt.includes(autos[0].automation_id) && dt.includes(autos[0].project_id || ""), autos[0].automation_id);
  ok("AUT-2: run/pause-or-resume/delete are forms posting the SEED lanes with back=automate", [`/run?back=automate`, `/delete?back=automate`].every((v) => dt.includes(v)) && (dt.includes(`/pause?back=automate`) || dt.includes(`/resume?back=automate`)));
  ok("AUT-2: NO new mutation route — every form action targets /__ioi/automations seed lanes only", [...dt.matchAll(/action="([^"]+)"/g)].every((m) => m[1].startsWith("/__ioi/automations")));
  ok("AUT-2: webhook rotate stays a LINK to the substrate (show-once token boundary, recorded)", dt.includes(`href="/__ioi/automations/${encodeURIComponent(autos[0].automation_id)}"`) && /SHOW-ONCE token/.test(dt));
  ok("AUT-2: detail run history renders real executions or an honest empty", dt.includes("Run history") && (dt.includes("mon-runrow") || /No executions recorded for this automation/.test(dt)));
  const neu = await page(`${SERVE}/__ioi/automations/monitors?tab=automations&view=new`);
  ok("AUT-2: the create form posts the SEED create lane (project-first: project_ref required)", neu.status === 200 && neu.text.includes(`action="/__ioi/automations?back=automate"`) && neu.text.includes(`name="project_ref" required`));
  ok("AUT-2: New-automation entries are LIVE in-shell links (no longer gaps)", t.includes(`?tab=automations&view=new`) && !/New automation<\/span><\/span>/.test(t));
  ok("AUT-1: unsupported facets are typed absences in BOTH vocabularies (aria-disabled+title AND data-ioi-disabled-reason)", (tt.match(/aria-disabled="true"[^>]*data-ioi-disabled-reason/g) || []).length >= 8);
  ok("AUT-1: the lane is READ-ONLY (no form posts anywhere on the tab)", !tt.includes("<form"));
  const pausedPage = await page(`${SERVE}/__ioi/automations/monitors?tab=automations&status=paused`);
  ok("AUT-1: the paused filter is a LIVE server-side lane whose row count equals plane truth", pausedPage.status === 200 && (pausedPage.text.match(/class="mon-arow"/g) || []).length === livePaused);
  ok("AUT-1: the tab links back to the Overview in-shell", tt.includes('href="/__ioi/automations/monitors"'));
  ok("the origin-aligned reference + the insufficient proxy lane are BOTH linked and explained on the surface", t.includes("http://localhost:9225/workspace/object-monitoring/") && t.includes("/__apps/monitors") && /favorites-load failure/.test(t));
  ok("IOI surface brand-clean (no Palantir)", !/\bPalantir\b/.test(t));
}

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`app-parity-monitors readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => { console.error("verifier crashed:", e); process.exit(1); });
