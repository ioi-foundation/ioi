#!/usr/bin/env node
// SUBSTRATE-TRUTH verifier — transitional Work projection on the legacy /missions route.
//
// The parity phase's first OPERATIONAL owner-family. The reference captures (/__apps/jobs = the
// job-tracker "Builds" table, /__apps/incidents = the issues-app remediation inbox) are the familiar
// baselines; the IOI-owned /__ioi/missions renders the SAME table/list grammar — a run/job status
// queue + a status-lane incident/remediation inbox — but over REAL daemon truth: the operations run
// queue (recent runs, statuses, scheduled automations) and typed incidents (real run
// failures + real GoalRun blockers), each linking back to its own proof/timeline.
//
// Taxonomy-v2 resolution: Work is the core workspace; Missions is only a compatibility route/label.
// Operations stays substrate/infra, and the certified Issues seed is Work / Incidents.
//
// Because Work is a READ-ONLY PROJECTION over existing estate truth (not a built fixture ladder),
// the fabrication guard is a CROSS-CHECK: the surface's counts + sample rows must EQUAL what the live
// daemon reports — exactly. A surface that invented incidents/runs would diverge from the daemon.
//
// Asserts:
//   - MATRIX: jobs + incidents = substrate_bound → /__ioi/missions (Missions), not over-claimed.
//   - REFERENCE BASELINES: /__apps/jobs + /__apps/incidents boot the familiar table grammar.
//   - IOI SURFACE = DAEMON TRUTH (substrate, not reference UX parity): /__ioi/missions renders the run queue + incident
//     inbox; the run count, the newest real run, the incident count, and a real blocker's goal-run
//     proof link all MATCH the live daemon (no fabrication).
//   - HONEST EMPTY / NO SILENT CAP: incident count == real failures + blockers exactly; when the
//     table is capped it says "showing first N" (no silent truncation).
//   - OWNER DISCOVERABILITY: /__ioi/missions links Operations (substrate) + Provenance (proof);
//     Operations links back to Missions; the suite card opens /__ioi/missions (not /__ioi/sessions);
//     each run row → its timeline, each blocker → its goal-run proof.
//   - NO FALSE COVERAGE: named gaps present; substrate/infra incidents deferred to Operations;
//     brand-clean IOI surface.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-app-parity-missions.mjs
// Exit 2 = BLOCKED.

import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const SERVE = (process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173").replace(/\/$/, "");
const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");
const here = path.dirname(fileURLToPath(import.meta.url));

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
const jd = async (p) => fetch(`${DAEMON}${p}`).then((r) => r.json()).catch(() => ({}));
const page = (url) => fetch(url).then(async (r) => ({ status: r.status, text: await r.text() })).catch(() => ({ status: 0, text: "" }));

async function run() {
  const up = await fetch(`${DAEMON}/v1/hypervisor/operations`).then((r) => r.ok).catch(() => false);
  if (!up) { console.error("BLOCKED: daemon operations plane not reachable at " + DAEMON); process.exit(2); }

  // 0. Matrix current + honest.
  const check = spawnSync("node", [path.join(here, "build-app-parity-matrix.mjs"), "--check"], { encoding: "utf8" });
  ok("parity matrix is current (regenerated == committed)", check.status === 0, (check.stderr || "").trim().slice(0, 80));
  const matrix = JSON.parse(spawnSync("node", ["-e", `import(${JSON.stringify(path.join(here, "..", "harvest-app-parity-matrix.json"))}, { with: { type: "json" } }).then(m => console.log(JSON.stringify(m.default)))`], { encoding: "utf8" }).stdout || "{}");
  const bySlug = Object.fromEntries((matrix.seeds || []).map((s) => [s.slug, s]));
  ok("historical matrix evidence keeps jobs bound to the /__ioi/missions compatibility route", bySlug.jobs?.parity_class === "substrate_bound" && bySlug.jobs?.substrate_surface === "/__ioi/missions" && bySlug.jobs?.surface_name === "Missions");
  // #45 PROMOTED incidents to daemon_wired (certified port at /__ioi/missions/incidents) — the
  // substrate surface stays bound; the class pin became a set (the frozen-class pin broke on promotion).
  ok("historical matrix evidence keeps incidents on its intact compatibility routes", ["substrate_bound", "daemon_wired"].includes(bySlug.incidents?.parity_class) && bySlug.incidents?.substrate_surface === "/__ioi/missions" && bySlug.incidents?.surface_name === "Missions");
  ok("no over-claim estate-wide (no 'covered'); prior reclassified surfaces still bound (substrate_bound|daemon_wired) (pipeline/lineage/vertex)", !(matrix.seeds || []).some((s) => s.parity_class === "covered") && ["pipeline", "lineage", "vertex"].every((k) => ["substrate_bound", "daemon_wired", "reference_ported", "reference_port_pending"].includes(bySlug[k]?.parity_class)));

  // 1. Reference baselines (raw familiar captures; brand-clean enforced on the IOI surface below).
  const refJobs = await page(`${SERVE}/__apps/jobs`);
  const refInc = await page(`${SERVE}/__apps/incidents`);
  ok("reference baseline /__apps/jobs boots the job/build table grammar", refJobs.status === 200 && /<title>[^<]*(Build|Job)/i.test(refJobs.text));
  ok("reference baseline /__apps/incidents boots the issues/remediation grammar", refInc.status === 200 && /<title>[^<]*(Issue|Incident)/i.test(refInc.text));

  // Live daemon truth — the projection the surface must faithfully reflect.
  const ops = await jd("/v1/hypervisor/operations");
  const runs = ops.runs || {};
  const recent = Array.isArray(runs.recent) ? runs.recent : [];
  const failures = Array.isArray(runs.failures) ? runs.failures : [];
  const grAll = (await jd("/v1/hypervisor/goal-runs")).goal_runs || [];
  const blocked = grAll.filter((r) => Array.isArray(r.blockers) && r.blockers.length);
  const incidentCount = failures.length + blocked.length;

  // 2. IOI surface = the table/list grammar.
  const m = await page(`${SERVE}/__ioi/missions`);
  const t = m.text;
  ok("IOI /__ioi/missions renders the Work compatibility projection (title + run queue + incident inbox)", m.status === 200 && /<h1[^>]*>Work/.test(t) && /legacy \/missions route/.test(t) && /id="missions-queue"/.test(t) && /id="missions-incidents"/.test(t));

  // 3. Run queue = REAL (cross-check counts + newest run against the live daemon).
  ok("run-queue heading reflects the real recent/total run counts (no fabrication)", t.includes(`recent typed runs (${recent.length} of ${runs.total || 0})`));
  const newest = recent[0];
  ok("the newest real run appears with its status + a timeline proof link", !newest || (t.includes(newest.name || newest.execution_id || "__missing_run__") && (!newest.timeline_ref || t.includes(newest.timeline_ref))), newest ? (newest.name || newest.execution_id) : "no runs (honest-empty ok)");

  // 4. Incident lane = REAL (exact count + a real blocker's goal-run proof link).
  ok("incident count MATCHES real run-failures + GoalRun blockers exactly (fabrication guard)", new RegExp(`needing remediation \\(${incidentCount}\\)`).test(t));
  const sampleBlocked = blocked[0];
  ok("a real GoalRun blocker renders with its reason_code + goal-run proof link", !sampleBlocked || (t.includes(`/__ioi/run-timeline/goal-run/${sampleBlocked.goal_run_id}`) && t.includes(String(sampleBlocked.blockers[0]?.reason_code || ""))), sampleBlocked ? sampleBlocked.goal_run_id : "no blockers (honest-empty ok)");
  ok("incidents lane present as run-failures + blockers (or honest empty when zero)", incidentCount > 0 ? /Incidents &amp; blockers/.test(t) && /run-timeline\/goal-run\//.test(t) : /No incidents/.test(t));

  // 5. NO SILENT CAP — if the blocker table is capped, the heading says so.
  const shown = failures.length + Math.min(blocked.length, 50);
  ok("no silent truncation: a capped incident table declares 'showing first N'", shown >= incidentCount ? true : new RegExp(`showing first ${shown}`).test(t), `${shown}/${incidentCount}`);

  // 6. Workspace placement and discoverability.
  ok("Work links its substrate (Operations) + proof (Provenance) surfaces first-class", t.includes("/__ioi/operations") && t.includes("/__ioi/work-ledger"));
  const opsPage = await page(`${SERVE}/__ioi/operations`);
  ok("Operations links back to the Work compatibility route", opsPage.status === 200 && opsPage.text.includes("/__ioi/missions") && /Work projection/.test(opsPage.text));
  const catalogPage = await page(`${SERVE}/__ioi/api/applications`);
  let catalog = null; try { catalog = JSON.parse(catalogPage.text); } catch { /* non-json */ }
  ok("typed catalog registers Work and nests Incidents without a Missions peer app", catalogPage.status === 200 && (catalog?.core_workspaces || []).some((entry) => entry.ref === "workspace:work" && entry.launch_route === "/__ioi/missions") && (catalog?.workspace_views || []).some((entry) => entry.slug === "incidents" && entry.placement === "Work / Incidents") && !(catalog?.applications || []).some((entry) => entry.name === "Missions"));

  // 7. No false coverage / honest gaps / brand-clean.
  ok("unsupported reference lanes named (create/assign incidents · edit job defs · board views · SLA · comments)", /creating\/assigning incidents/.test(t) && /editing job\/build definitions/.test(t) && /board\/kanban views/.test(t) && /SLA/.test(t));
  ok("substrate/infra incidents (storage repair, provider failover) explicitly deferred to Operations", /storage repair, provider failover\) live in <a href="\/__ioi\/operations">Operations<\/a>/.test(t));
  ok("reference captures linked as secondary baselines; IOI surface brand-clean (no Palantir/Foundry)", t.includes("/__apps/jobs") && t.includes("/__apps/incidents") && !/\bPalantir\b/.test(t) && !/\bFoundry\b/.test(t));
}

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`work-compatibility-projection readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => { console.error("verifier crashed:", e); process.exit(1); });
