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
  const roomA = "outcome-room://or_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  const roomB = "outcome-room://or_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  const frontierA = "frontier://wfi_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  const frontierB = "frontier://wfi_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  const claimA = "work-claim://wcl_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  const claimB = "work-claim://wcl_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  const attemptA = "attempt://att_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  const attemptB = "attempt://att_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  const challengeA = "verifier-challenge://vc_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  const challengeB = "verifier-challenge://vc_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  const model = {
    rooms: plane([
      { outcome_room_id: roomA, objective: "Audit the lunar relay", status: "open", room_mode: "hosted", revision: 3 },
      { outcome_room_id: roomB, objective: "Unrelated room", status: "open", room_mode: "hosted", revision: 1 },
    ]),
    requests: plane([]),
    participants: plane([
      { outcome_room_ref: roomA, participant_lease_id: "participant-lease://pl_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", participant_ref: "principal://alice", status: "active" },
    ]),
    frontier: plane([
      { outcome_room_ref: roomA, frontier_item_id: frontierA, title: "Validate telemetry", status: "ready", max_concurrency: 1 },
      { outcome_room_ref: roomB, frontier_item_id: frontierB, title: "Cross-room frontier sentinel", status: "ready", max_concurrency: 1 },
    ]),
    claims: plane([
      { outcome_room_ref: roomA, work_claim_id: claimA, frontier_item_ref: frontierA, status: "active" },
      { outcome_room_ref: roomB, work_claim_id: claimB, frontier_item_ref: frontierB, status: "active" },
    ]),
    resourceOffers: plane([]),
    capabilityOffers: plane([]),
    matches: plane([]),
    attempts: plane([
      { outcome_room_ref: roomA, attempt_id: attemptA, status: "submitted", work_result_ref: "work-result://wr_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
      { outcome_room_ref: roomB, attempt_id: attemptB, status: "submitted", work_result_ref: "work-result://wr_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" },
    ]),
    findings: plane([]),
    results: plane([]),
    challenges: plane([
      { outcome_room_ref: roomA, verifier_challenge_id: challengeA, challenged_ref: attemptA, challenge_kind: "evidence", status: "investigating" },
      { outcome_room_ref: roomB, verifier_challenge_id: challengeB, challenged_ref: attemptB, challenge_kind: "evidence", status: "investigating" },
    ]),
    goalRuns: plane([]),
    operations: plane([], { runs: { total: 0, recent: [], failures: [] } }),
  };
  return {
    html: missionsSurface.render(model, {
      url: new URL(`http://missions.test/__ioi/missions?room=${encodeURIComponent(roomA)}`),
      embed: true,
    }),
    roomA,
    frontierA,
    frontierB,
    claimA,
    claimB,
    attemptA,
    attemptB,
    challengeA,
    challengeB,
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
  ok("matrix binds jobs as substrate_bound → /__ioi/missions (Missions)", bySlug.jobs?.parity_class === "substrate_bound" && bySlug.jobs?.substrate_surface === "/__ioi/missions" && bySlug.jobs?.surface_name === "Missions");
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
  const grAll = (await jd("/v1/hypervisor/goal-runs")).goal_runs || [];
  const blocked = grAll.filter((r) => Array.isArray(r.blockers) && r.blockers.length);
  const incidentCount = failures.length + blocked.length;
  const roomPlane = await jd("/v1/hypervisor/outcome-rooms");
  const frontierPlane = await jd("/v1/hypervisor/work-frontier-items");
  const claimPlane = await jd("/v1/hypervisor/work-claim-leases");
  const attemptPlane = await jd("/v1/hypervisor/attempts");
  const findingPlane = await jd("/v1/hypervisor/findings");
  const challengePlane = await jd("/v1/hypervisor/verifier-challenges");
  const rooms = roomPlane.outcome_rooms || [];
  const frontier = frontierPlane.frontier_items || [];
  const claims = claimPlane.work_claims || [];
  const attempts = attemptPlane.attempts || [];
  const findings = findingPlane.findings || [];
  const challenges = challengePlane.verifier_challenges || [];
  const liveClaims = claims.filter((claim) => ["proposed", "active", "waiting"].includes(claim.status));
  const unresolvedChallenges = challenges.filter((challenge) => ["proposed", "admitted", "investigating", "upheld", "rule_changed", "reverifying"].includes(challenge.status));

  // 2. IOI surface = the table/list grammar.
  const m = await page(`${SERVE}/__ioi/missions`);
  const t = m.text;
  ok("IOI /__ioi/missions renders the Missions grammar (title + run queue + incident inbox)", m.status === 200 && /<h1[^>]*>Missions/.test(t) && /id="missions-queue"/.test(t) && /id="missions-incidents"/.test(t));
  ok("Missions is the hosted work-graph workspace, not only the legacy run queue",
    /Hosted work graph/.test(t) && /data-missions-work-graph="hosted"/.test(t)
      && /Mission rooms/.test(t)
      && (rooms.length === 0 || (/Frontier and claims/.test(t)
        && /Participation/.test(t) && /Attempts, Findings, and WorkResults/.test(t)
        && /Verifier challenges/.test(t))));
  ok("hosted graph summary counts equal daemon truth exactly",
    t.includes(`data-missions-rooms="${rooms.length}"`)
      && t.includes(`data-missions-frontier="${frontier.length}"`)
      && t.includes(`data-missions-live-claims="${liveClaims.length}"`)
      && t.includes(`data-missions-attempts="${attempts.length}"`)
      && t.includes(`data-missions-findings="${findings.length}"`)
      && t.includes(`data-missions-unresolved-challenges="${unresolvedChallenges.length}"`),
    `${rooms.length}/${frontier.length}/${liveClaims.length}/${attempts.length}/${findings.length}/${unresolvedChallenges.length}`);
  const sampleRoom = rooms.find((room) => room.status === "open") || rooms[0];
  if (sampleRoom) {
    const selectedPage = await page(`${SERVE}/__ioi/missions?room=${encodeURIComponent(sampleRoom.outcome_room_id)}`);
    const selectedText = selectedPage.text;
    const roomFrontier = frontier.filter((record) => record.outcome_room_ref === sampleRoom.outcome_room_id);
    const roomClaims = claims.filter((record) => record.outcome_room_ref === sampleRoom.outcome_room_id);
    const roomChallenges = challenges.filter((record) => record.outcome_room_ref === sampleRoom.outcome_room_id);
    ok("room selection is refresh-stable and resolves the exact OutcomeRoom coordinate",
      selectedPage.status === 200
        && selectedText.includes(`data-missions-selected-room="${sampleRoom.outcome_room_id}"`)
        && selectedText.includes(sampleRoom.objective || sampleRoom.objective_ref || "__missing_objective__"),
      sampleRoom.outcome_room_id);
    ok("selected room projects only its frontier, claims, and challenge relationship",
      roomFrontier.every((record) => selectedText.includes(record.frontier_item_id))
        && roomClaims.every((record) => selectedText.includes(record.frontier_item_ref))
        && roomChallenges.every((record) => selectedText.includes(record.verifier_challenge_id)));
  } else {
    ok("empty OutcomeRoom registry renders an honest no-room state", /No rooms in this view/.test(t));
    ok("empty room selection invents no graph relationship", /Select a mission room/.test(t));
  }
  const relationshipProbe = renderRelationshipProbe();
  ok("two-room render binds the selected inspector to exact hosted graph coordinates",
    relationshipProbe.html.includes(`data-missions-selected-room="${relationshipProbe.roomA}"`)
      && relationshipProbe.html.includes(relationshipProbe.frontierA)
      && relationshipProbe.html.includes(relationshipProbe.claimA)
      && relationshipProbe.html.includes(relationshipProbe.attemptA)
      && relationshipProbe.html.includes(relationshipProbe.challengeA)
      && !relationshipProbe.html.includes(relationshipProbe.frontierB)
      && !relationshipProbe.html.includes(relationshipProbe.claimB)
      && !relationshipProbe.html.includes(relationshipProbe.attemptB)
      && !relationshipProbe.html.includes(relationshipProbe.challengeB));

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
  ok("no silent truncation: a capped incident table declares 'showing first N'", shown >= incidentCount ? true : new RegExp(`showing first ${shown}`).test(t), `${shown}/${incidentCount}`);

  // 6. Owner discoverability.
  ok("Missions links its substrate (Operations) + proof (Provenance) surfaces first-class", t.includes("/__ioi/operations") && t.includes("/__ioi/work-ledger"));
  const opsPage = await page(`${SERVE}/__ioi/operations`);
  ok("Operations links BACK to Missions (drift resolved: suite/run work homed in Missions)", opsPage.status === 200 && opsPage.text.includes("/__ioi/missions"));
  const apps = await page(`${SERVE}/__ioi/applications`);
  ok("the suite Missions card opens /__ioi/missions (drift from /__ioi/sessions resolved)", apps.status === 200 && new RegExp(`href="/__ioi/missions"[^>]*>[\\s\\S]{0,400}?Missions`).test(apps.text));

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
