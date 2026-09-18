#!/usr/bin/env node
// SUBSTRATE-TRUTH verifier (reclassified substrate_bound by the #31 Reference-UX-Port reset — checks DAEMON TRUTH, NOT reference UX parity) — Missions owner-family done-bar (jobs + incidents seeds).
//
// The parity phase's first OPERATIONAL owner-family. The reference captures (/__apps/jobs = the
// job-tracker "Builds" table, /__apps/incidents = the issues-app remediation inbox) are the familiar
// baselines; the IOI-owned /__ioi/missions renders the SAME table/list grammar — a run/job status
// queue + a status-lane incident/remediation inbox — but over REAL daemon truth: the operations run
// queue (recent runs, statuses, scheduled missions) and the mission-level incidents (real run
// failures + real GoalRun blockers), each linking back to its own proof/timeline.
//
// Naming resolution (the drift this cut fixes): Missions is the OWNER surface for suite/run work;
// Operations stays substrate/infra. The suite card no longer points Missions at /__ioi/sessions, and
// the inventory no longer homes jobs/incidents under /__ioi/operations.
//
// Because Missions is a READ-ONLY PROJECTION over existing estate truth (not a built fixture ladder),
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
import * as missionsSurface from "../surfaces/missions/index.mjs";

const SERVE = (process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173").replace(/\/$/, "");
const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");
const here = path.dirname(fileURLToPath(import.meta.url));

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
const jd = async (p) => fetch(`${DAEMON}${p}`).then((r) => r.json()).catch(() => ({}));
const page = (url) => fetch(url).then(async (r) => ({ status: r.status, text: await r.text() })).catch(() => ({ status: 0, text: "" }));
const plane = (rows = [], payload = {}) => ({ ok: true, status: 200, code: "", rows, payload });

function renderRelationshipProbe() {
  // R-191 (S4d-3): the probe used to build a two-room graph across seven planes that no longer
  // exist. It now builds the two planes the surface reads, and asserts the same three things
  // that mattered: the selected subject binds its OWN records, an unknown selection fails closed,
  // and a selection outside the active filter fails closed rather than escaping it.
  const runA = {
    goal_run_id: "gr_probe_a",
    goal_ref: "goal://gr_probe_a",
    normalized_goal: "Audit the lunar relay",
    status: "active",
    continuation_state: "open",
    orchestration_ref: "app-scope://ioi-ai/orchestration/orc_probe",
    blockers: [],
  };
  const runB = {
    goal_run_id: "gr_probe_b",
    goal_ref: "goal://gr_probe_b",
    normalized_goal: "Unrelated pursuit",
    status: "complete",
    continuation_state: "complete",
    orchestration_ref: null,
    blockers: [],
  };
  const resultA = { work_result_id: "work-result://wr_aa", work_subject_ref: runA.goal_ref, outcome_class: "positive", status: "completed" };
  const resultB = { work_result_id: "work-result://wr_bb", work_subject_ref: runB.goal_ref, outcome_class: "negative", status: "completed" };
  const plane = (rows, ok = true) => ({ ok, status: 200, code: "", rows, payload: null });
  const model = {
    goalRuns: plane([runA, runB]),
    results: plane([resultA, resultB]),
    operations: { ok: true, status: 200, code: "", rows: [], payload: { runs: { total: 0, recent: [], failures: [] } } },
    unattributedResults: 0,
  };
  const renderWith = (query) => missions.render(model, {
    url: new URL(`http://x/__ioi/missions${query}`),
    daemon: "http://127.0.0.1:1",
    embed: true,
  });
  return {
    html: renderWith(`?goal=${encodeURIComponent(runA.goal_run_id)}`),
    unknownHtml: renderWith("?goal=gr_probe_absent"),
    filteredHtml: renderWith(`?status=complete&goal=${encodeURIComponent(runA.goal_run_id)}`),
    defaultHtml: renderWith(""),
    runA: runA.goal_run_id,
    runB: runB.goal_run_id,
    resultA: resultA.work_result_id,
    resultB: resultB.work_result_id,
    objectiveA: runA.normalized_goal,
    objectiveB: runB.normalized_goal,
  };
}

async function run() {
  const up = await fetch(`${DAEMON}/v1/hypervisor/operations`).then((r) => r.ok).catch(() => false);
  if (!up) { console.error("BLOCKED: daemon operations plane not reachable at " + DAEMON); process.exit(2); }

  // 0. Matrix current + honest.
  const check = spawnSync("node", [path.join(here, "build-app-parity-matrix.mjs"), "--check"], { encoding: "utf8" });
  ok("parity matrix is current (regenerated == committed)", check.status === 0, (check.stderr || "").trim().slice(0, 80));
  const matrix = JSON.parse(spawnSync("node", ["-e", `import(${JSON.stringify(path.join(here, "..", "harvest-app-parity-matrix.json"))}, { with: { type: "json" } }).then(m => console.log(JSON.stringify(m.default)))`], { encoding: "utf8" }).stdout || "{}");
  const bySlug = Object.fromEntries((matrix.seeds || []).map((s) => [s.slug, s]));
  // JOB-1 PROMOTED jobs to reference_ported (the Builds port at /__ioi/missions/builds) — the same
  // shape #45 hit when incidents was promoted: the frozen-class PIN breaks, the substrate binding
  // must not. So the pin becomes a set and the assertion gets STRONGER, not weaker: the substrate
  // surface is still asserted bound (the port CARRIES substrate_surface forward, so /__ioi/missions
  // is never unbound by the promotion), and a ported jobs row must additionally name the sibling
  // port surface. A promotion that silently dropped /__ioi/missions now fails here.
  ok("matrix binds jobs (substrate_bound|reference_ported) with the intact /__ioi/missions substrate (Missions)", ["substrate_bound", "reference_ported"].includes(bySlug.jobs?.parity_class) && bySlug.jobs?.substrate_surface === "/__ioi/missions" && bySlug.jobs?.surface_name === "Missions");
  ok("a PORTED jobs row names its sibling Builds surface and never re-points the substrate at it", bySlug.jobs?.parity_class !== "reference_ported" || (bySlug.jobs?.port_surface === "/__ioi/missions/builds" && bySlug.jobs?.candidate_surface === "/__ioi/missions/builds" && bySlug.jobs?.substrate_surface === "/__ioi/missions" && /#jobs-port/.test(bySlug.jobs?.adjudication_ref || "")), bySlug.jobs?.port_surface || "(none)");
  // #45 PROMOTED incidents to daemon_wired (certified port at /__ioi/missions/incidents) — the
  // substrate surface stays bound; the class pin became a set (the frozen-class pin broke on promotion).
  ok("matrix binds incidents (substrate_bound|daemon_wired) with the intact /__ioi/missions substrate (Missions)", ["substrate_bound", "daemon_wired"].includes(bySlug.incidents?.parity_class) && bySlug.incidents?.substrate_surface === "/__ioi/missions" && bySlug.incidents?.surface_name === "Missions");
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
  const grAll = (await jd("/v1/goal-orchestration/goal-runs")).goal_runs || [];
  const blocked = grAll.filter((r) => Array.isArray(r.blockers) && r.blockers.length);
  const incidentCount = failures.length + blocked.length;
  const resultPlane = await jd("/v1/hypervisor/work-results");
  const workResults = resultPlane.work_results || [];
  const openRuns = grAll.filter((run) => ["draft", "active", "paused"].includes(run.status));
  const runGoalRefs = new Set(grAll.map((run) => run.goal_ref));
  const unattributed = workResults.filter((result) => !runGoalRefs.has(result.work_subject_ref));

  // 2. IOI surface = the table/list grammar.
  const m = await page(`${SERVE}/__ioi/missions`);
  const t = m.text;
  ok("IOI /__ioi/missions renders the Missions grammar (title + run queue + incident inbox)", m.status === 200 && /<h1[^>]*>Missions/.test(t) && /id="missions-queue"/.test(t) && /id="missions-incidents"/.test(t));
  ok("Missions is the GoalRun workspace over the planes the daemon still serves, not only the legacy run queue",
    /Goal runs and their results/.test(t) && /data-missions-work-graph="goal-runs"/.test(t)
      && /Goal runs<\/span>/.test(t)
      && !/outcome-room:\/\//.test(t) && !/Mission rooms/.test(t));
  ok("summary counts equal daemon truth exactly",
    t.includes(`data-missions-metric="goal-runs" data-value="${grAll.length}"`)
      && t.includes(`data-missions-metric="open" data-value="${openRuns.length}"`)
      && t.includes(`data-missions-metric="results" data-value="${workResults.length}"`)
      && t.includes(`data-missions-metric="unattributed-results" data-value="${unattributed.length}"`),
    `${grAll.length}/${openRuns.length}/${workResults.length}/${unattributed.length}`);
  const sampleRun = grAll.find((run) => ["draft", "active", "paused"].includes(run.status)) || grAll[0];
  if (sampleRun) {
    const selectedPage = await page(`${SERVE}/__ioi/missions?goal=${encodeURIComponent(sampleRun.goal_run_id)}`);
    const selectedText = selectedPage.text;
    const runResults = workResults.filter((record) => record.work_subject_ref === sampleRun.goal_ref);
    ok("run selection is refresh-stable and resolves the exact GoalRun coordinate",
      selectedPage.status === 200
        && selectedText.includes(`data-missions-selected-run="${sampleRun.goal_run_id}"`)
        && selectedText.includes(sampleRun.normalized_goal || sampleRun.goal_ref || "__missing_goal__"),
      sampleRun.goal_run_id);
    ok("the selected run projects its own results and the membership ref the application stamped",
      runResults.every((record) => selectedText.includes(record.work_result_id))
        && selectedText.includes(`data-missions-orchestration="${sampleRun.orchestration_ref || "none"}"`));
  } else {
    ok("an empty GoalRun plane renders an honest no-run state", /No goal runs in this view/.test(t));
    ok("an empty selection invents no relationship", /Choose a goal run to inspect/.test(t));
  }
  const relationshipProbe = renderRelationshipProbe();
  ok("a two-run render binds the selected inspector to that run's own records only",
    relationshipProbe.html.includes(`data-missions-selected-run="${relationshipProbe.runA}"`)
      && relationshipProbe.html.includes(relationshipProbe.resultA)
      && !relationshipProbe.html.includes(relationshipProbe.resultB));
  ok("an explicit unknown run selection fails closed instead of inspecting the first run",
    relationshipProbe.unknownHtml.includes('data-missions-selection="goal_run_not_found"')
      && !relationshipProbe.unknownHtml.includes(`data-missions-selected-run="${relationshipProbe.runA}"`)
      && relationshipProbe.unknownHtml.includes("not in the daemon's list"));
  ok("an explicit run outside the active status filter fails closed instead of escaping the filter",
    relationshipProbe.filteredHtml.includes('data-missions-selection="goal_run_filter_mismatch"')
      && !relationshipProbe.filteredHtml.includes(`data-missions-selected-run="${relationshipProbe.runA}"`)
      && relationshipProbe.filteredHtml.includes("filtered out of this view"));
  ok("the bare route still selects the first open run for the normal operator landing",
    relationshipProbe.defaultHtml.includes(`data-missions-selected-run="${relationshipProbe.runA}"`));

  // 3. Run queue = REAL (cross-check counts + newest run against the live daemon).
  ok("run-queue heading reflects the real recent/total run counts (no fabrication)", t.includes(`recent mission runs (${recent.length} of ${runs.total || 0})`));
  const newest = recent[0];
  ok("the newest real run appears with its status + a timeline proof link", !newest || (t.includes(newest.name || newest.execution_id || "__missing_run__") && (!newest.timeline_ref || t.includes(newest.timeline_ref))), newest ? (newest.name || newest.execution_id) : "no runs (honest-empty ok)");

  // 4. Incident lane = REAL (exact count + a real blocker's goal-run proof link).
  ok("incident count MATCHES real run-failures + GoalRun blockers exactly (fabrication guard)", new RegExp(`needing remediation \\(${incidentCount}\\)`).test(t));
  const sampleBlocked = blocked[0];
  ok("a real GoalRun blocker renders with its reason_code + goal-run proof link", !sampleBlocked || (t.includes(`/__ioi/run-timeline/goal-run/${sampleBlocked.goal_run_id}`) && t.includes(String(sampleBlocked.blockers[0]?.reason_code || ""))), sampleBlocked ? sampleBlocked.goal_run_id : "no blockers (honest-empty ok)");
  ok("incidents lane present as run-failures + blockers (or honest empty when zero)", incidentCount > 0 ? /Incidents &amp; blockers/.test(t) && /run-timeline\/goal-run\//.test(t) : /No incidents/.test(t));

  // 5. NO SILENT CAP — if the blocker table is capped, the heading says so.
  const shown = failures.length + Math.min(blocked.length, 50);
  ok("no silent truncation: a capped incident table declares 'showing first N of M'", shown >= incidentCount ? true : new RegExp(`showing first ${shown} of ${incidentCount}`).test(t), `${shown}/${incidentCount}`);

  // 6. Owner discoverability.
  ok("Missions links its substrate (Operations) + proof (Provenance) surfaces first-class", t.includes("/__ioi/operations") && t.includes("/__ioi/work-ledger"));
  const opsPage = await page(`${SERVE}/__ioi/operations`);
  ok("Operations links BACK to Missions (drift resolved: suite/run work homed in Missions)", opsPage.status === 200 && opsPage.text.includes("/__ioi/missions"));
  const apps = await page(`${SERVE}/__ioi/applications`);
  ok("the suite Missions card opens /__ioi/missions (drift from /__ioi/sessions resolved)", apps.status === 200 && new RegExp(`href="/__ioi/missions"[^>]*>[\\s\\S]{0,1600}?Missions`) /* window widened 400→1600: the app-tile icon data-URI grew past the old window (pre-existing stale assertion, confirmed failing at HEAD by JOB-1) */.test(apps.text));

  // 7. No false coverage / honest gaps / brand-clean.
  ok("unsupported reference lanes named (create/assign incidents · edit job defs · board views · SLA · comments)", /creating\/assigning incidents/.test(t) && /editing job\/build definitions/.test(t) && /board\/kanban views/.test(t) && /SLA/.test(t));
  ok("substrate/infra incidents (storage repair, provider failover) explicitly deferred to Operations", /storage repair, provider failover\) live in <a href="\/__ioi\/operations">Operations<\/a>/.test(t));
  ok("reference captures linked as secondary baselines; IOI surface brand-clean (no Palantir/Foundry)", t.includes("/__apps/jobs") && t.includes("/__apps/incidents") && !/\bPalantir\b/.test(t) && !/\bFoundry\b/.test(t));
  ok("authority boundary is explicit and the surface exposes no action form",
    /Hosted admission only/.test(t)
      && /grants no acceptance, verdict, settlement, execution, or federation authority/.test(t)
      && !/<form\b/i.test(t)
      && !/method="post"/i.test(t));
  const registry = spawnSync("node", ["--input-type=module", "-e",
    `import { surfaceBySlug, boundActionRoute } from ${JSON.stringify(path.join(here, "surface-registry.mjs"))}; const s=surfaceBySlug("missions"); console.log(JSON.stringify({state:s?.operational_state,capabilities:s?.capabilities,action:!!boundActionRoute("/__ioi/missions/room/transition","POST")}));`
  ], { encoding: "utf8" });
  const registration = JSON.parse(registry.stdout || "{}");
  ok("surface registry declares Missions read-only-by-contract with no action dispatch",
    registry.status === 0 && registration.state === "read_only_by_contract"
      && registration.capabilities?.includes("inspect") && registration.capabilities?.includes("proof")
      && registration.action === false);
  const embedded = await page(`${SERVE}/__ioi/missions?embed=1`);
  ok("native application embedding keeps one platform rail and the Missions local workspace",
    embedded.status === 200
      && embedded.text.includes('class="ms-main"')
      && !embedded.text.includes('<aside class="og-grail')
      && embedded.text.includes("embed=1"));
}

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`substrate-truth-missions readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => { console.error("verifier crashed:", e); process.exit(1); });
