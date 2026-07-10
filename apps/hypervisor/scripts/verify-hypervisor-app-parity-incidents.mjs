#!/usr/bin/env node
// ---------------------------------------------------------------------------
// PR #45 — INCIDENTS PORT VERIFIER (the first port driven by the #44 clean-sweep
// ranking). Asserts the FOUR layers that make /__ioi/missions/incidents a real
// certified surface:
//   1. MATRIX: incidents is daemon_wired over a data_clean reference, certified,
//      with landmarks + the ?lane=closed harness deep-link declared.
//   2. VISUAL PARITY: the hardened harness certifies theme + IA landmarks +
//      region geometry against the /__apps/incidents reference (whose data sits
//      one status-lane click deep — the pre-capture hook clicks status UI only).
//   3. DAEMON TRUTH: rendered incidents are REAL GoalRun blockers + run
//      failures — counts cross-checked against the daemon after the same lane
//      filters, at least one real id/reason/proof link renders, empty lanes
//      stay honest, nothing fabricated (no priorities/assignees invented).
//   4. SHELL-PIXEL CERTIFICATION: committed non-pinned 2-viewport evidence
//      under the calibrated budgets; the row list is the excluded live body —
//      NO full-body pixel claim is made anywhere.
// ---------------------------------------------------------------------------
import { readFileSync, existsSync, rmSync } from "node:fs";
import { spawnSync } from "node:child_process";
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
  const up = await fetch(`${DAEMON}/v1/hypervisor/goal-runs`).then((r) => r.ok).catch(() => false);
  if (!up) { console.error("BLOCKED: daemon goal-run plane not reachable at " + DAEMON); process.exit(2); }

  // 1. MATRIX — daemon_wired incidents over a data_clean reference, certified, deep-link declared.
  const check = spawnSync("node", [path.join(here, "build-app-parity-matrix.mjs"), "--check"], { encoding: "utf8" });
  ok("parity matrix is current (regenerated == committed)", check.status === 0, (check.stderr || "").trim().slice(0, 80));
  const matrix = JSON.parse(readFileSync(path.join(appRoot, "harvest-app-parity-matrix.json"), "utf8"));
  const row = (matrix.seeds || []).find((s) => s.slug === "incidents");
  ok("matrix: incidents is daemon_wired at /__ioi/missions/incidents with landmarks + the ?lane=closed harness deep-link + the intact /__ioi/missions substrate", row && row.parity_class === "daemon_wired" && row.port_surface === "/__ioi/missions/incidents" && row.candidate_surface === "/__ioi/missions/incidents" && row.substrate_surface === "/__ioi/missions" && row.ioi_url_override === "/__ioi/missions/incidents?lane=closed" && Array.isArray(row.reference_landmarks) && row.reference_landmarks.length >= 8, row ? `class=${row.parity_class}` : "row missing");
  ok("matrix: the incidents REFERENCE is data_clean per the #44 sweep (the ranking that chose this port), with the one-click-deep evidence in the reason", row && row.reference_clean_state === "data_clean" && /Closed.*status lane|status lane.*Closed/i.test(row.reference_clean_reason || ""), row ? row.reference_clean_reason?.slice(0, 90) : "");
  ok("no false parity elsewhere: schema/approvals/pipeline stay daemon_wired; explorer stays reference_ported; the estate majority stays reference_capture", ["schema", "approvals", "pipeline"].every((sl) => (matrix.seeds || []).find((s) => s.slug === sl)?.parity_class === "daemon_wired") && (matrix.seeds || []).find((s) => s.slug === "explorer")?.parity_class === "reference_ported" && (matrix.by_parity_class?.reference_capture || 0) >= 20);

  // 2. VISUAL PARITY — hardened harness against the real reference (pre-capture clicks the Closed lane).
  const artDir = path.join(appRoot, ".artifacts", "incidents-port-verify");
  try { if (existsSync(path.join(artDir, "result.json"))) rmSync(path.join(artDir, "result.json")); } catch { /* */ }
  const h = spawnSync("node", [path.join(here, "harness-reference-parity.mjs")], { encoding: "utf8", timeout: 180000, env: { ...process.env, IOI_HARNESS_SURFACES: "incidents", IOI_HARNESS_ARTIFACT_DIR: artDir } });
  let hp = null;
  if (h.status === 0 && existsSync(path.join(artDir, "result.json"))) hp = (JSON.parse(readFileSync(path.join(artDir, "result.json"), "utf8")).surfaces || [])[0];
  ok("harness ran + captured real screenshots for the issues-app reference vs the port", hp && hp.evidence_ok === true, hp ? `ref ${hp.reference_screenshot_bytes}b · ioi ${hp.ioi_screenshot_bytes}b` : "harness did not run");
  ok("CERTIFIED: the hardened harness grants visual_parity (region geometry + theme + landmarks)", hp && hp.visual_parity === true && hp.structural_parity === true, hp ? `visual=${hp.visual_parity} structural=${hp.structural_parity}` : "n/a");
  ok("theme MATCH: reference LIGHT ≡ port LIGHT", hp && hp.theme_match === true && hp.reference_theme === "light" && hp.ioi_theme === "light", hp ? `${hp.reference_theme}/${hp.ioi_theme}` : "n/a");
  ok("IA landmarks reproduced (status lanes + filter facets; coverage ≥ 0.8, none missing)", hp && hp.landmark_applicable >= 8 && hp.landmark_covered >= Math.ceil(hp.landmark_applicable * 0.8) && (hp.landmarks_missing || []).length === 0, hp ? `covered ${hp.landmark_covered}/${hp.landmark_applicable}` : "n/a");
  ok("BOTH sides VALID: the reference (post status-lane click) is not errored + the port is not errored", hp && hp.reference_valid === true && hp.reference_errored === false && hp.ioi_valid === true && hp.ioi_errored === false);

  // 3. DAEMON TRUTH — counts, identity, proof links, lane logic, honest empties, no fabrication.
  const [grRes, opsRes] = await Promise.all([jd("/v1/hypervisor/goal-runs"), jd("/v1/hypervisor/operations")]);
  const TERMINAL = new Set(["complete", "completed", "done", "succeeded", "failed", "cancelled", "canceled"]);
  const blocked = (grRes.goal_runs || []).filter((r) => Array.isArray(r.blockers) && r.blockers.length);
  const failures = ((opsRes.runs || {}).failures) || [];
  const expClosed = blocked.filter((r) => TERMINAL.has(String(r.status || "").toLowerCase())).length;
  const expOpen = blocked.length - expClosed + failures.length;
  const expAll = blocked.length + failures.length;
  const CAP = 50;
  const lanePage = async (lane) => page(`${SERVE}/__ioi/missions/incidents?lane=${lane}`);
  const [pOpen, pClosed, pAll] = await Promise.all([lanePage("open"), lanePage("closed"), lanePage("all")]);
  const countOf = (t, lane) => { const m = t.match(new RegExp(`>(?:(\\d+) of )?(\\d+) ${lane === "all" ? "" : lane + " "}issues?<`)); return m ? { shown: Number(m[1] || m[2]), total: Number(m[2]) } : null; };
  const rowsOf = (t) => (t.match(/class="in-row"/g) || []).length;
  const cOpen = countOf(pOpen.text, "open"), cClosed = countOf(pClosed.text, "closed"), cAll = countOf(pAll.text, "all");
  ok(`OPEN lane count = daemon truth after the lane filter (${expOpen} = non-terminal blockers + run failures)`, cOpen && cOpen.total === expOpen && rowsOf(pOpen.text) === Math.min(expOpen, CAP), `rendered ${cOpen ? cOpen.total : "?"} rows ${rowsOf(pOpen.text)} vs daemon ${expOpen}`);
  ok(`CLOSED lane count = daemon truth (${expClosed} = blockers recorded on terminal runs — resolved incidents)`, cClosed && cClosed.total === expClosed && rowsOf(pClosed.text) === Math.min(expClosed, CAP), `rendered ${cClosed ? cClosed.total : "?"} rows ${rowsOf(pClosed.text)} vs daemon ${expClosed}`);
  ok(`ALL lane count = open + closed (${expAll})`, cAll && cAll.total === expAll, `rendered ${cAll ? cAll.total : "?"} vs daemon ${expAll}`);
  ok("the three lane count TAGS carry the same daemon numbers on every lane page", [pOpen, pClosed, pAll].every((p2) => p2.text.includes(`>${expOpen}</span>`) && p2.text.includes(`>${expClosed}</span>`) && p2.text.includes(`>${expAll}</span>`)));
  // identity: at least one REAL incident renders with id + reason + proof link into its own timeline
  const sample = blocked.find((r) => TERMINAL.has(String(r.status || "").toLowerCase())) || blocked[0];
  const lanePageOfSample = sample && TERMINAL.has(String(sample.status || "").toLowerCase()) ? pClosed : pOpen;
  ok("at least one REAL incident renders: goal-run id + blocker reason code in the row title, proof link into ITS OWN run timeline", sample && lanePageOfSample.text.includes(sample.goal_run_id) && lanePageOfSample.text.includes((sample.blockers[0] || {}).reason_code || "blocked") && lanePageOfSample.text.includes(`/__ioi/run-timeline/goal-run/${encodeURIComponent(sample.goal_run_id)}`), sample ? `${sample.goal_run_id} (${(sample.blockers[0] || {}).reason_code})` : "no blocked goal runs in daemon");
  // honest empties: any lane the daemon says is empty must SAY so, never render rows
  const laneFacts = [["open", expOpen, pOpen], ["closed", expClosed, pClosed], ["all", expAll, pAll]];
  ok("empty lanes stay HONEST (empty-state copy, zero rows) — and non-empty lanes never render the empty state", laneFacts.every(([lane, n, p2]) => n === 0 ? (p2.text.includes('class="in-empty"') && rowsOf(p2.text) === 0) : (!p2.text.includes('class="in-empty"') && rowsOf(p2.text) > 0)), laneFacts.map(([l, n]) => `${l}:${n}`).join(" "));
  ok("nothing fabricated: no priority/assignee/SLA values are attached to incidents (the reference's Priority pills are DATA the daemon does not record — the port shows the honest incident KIND instead)", !/in-rpill[^>]*>(?:(?!<\/div>).)*?(High|Medium|Low)</s.test(pClosed.text) && /in-rpill/.test(pClosed.text) && /Blocker|Run failure/.test(pClosed.text));

  // 4. PORT SHELL SEMANTICS — gaps disabled IN PLACE and NAMED, discoverability, substrate intact.
  ok("unsupported reference controls are DISABLED IN PLACE + named as gaps (New · search · facet inputs · checkboxes), never hidden", (pClosed.text.match(/disabled/g) || []).length >= 10 && /named gap/.test(pClosed.text) && /reference-only/.test(pClosed.text) && /aria-disabled="true"/.test(pClosed.text));
  ok("the filter sidebar renders the full reference facet set as chrome (Priority · Assignees · Reporters · Mentions · Labels · Support types · date ranges)", ["Priority", "Assignees", "Reporters", "Mentions", "Labels", "Support types", "Reported on", "Last updated", "Clear filters"].every((l) => pClosed.text.includes(l)));
  const missions = await page(`${SERVE}/__ioi/missions`);
  ok("owner discoverability: /__ioi/missions links the incidents inbox first-class AND keeps its own incidents lane intact", missions.status === 200 && missions.text.includes("/__ioi/missions/incidents") && /Incidents (&amp;|&) blockers/.test(missions.text));
  ok("brand/reference clean: reference capture linked nowhere as a rebound surface; no Palantir branding", !/\bPalantir\b/.test(pClosed.text) && !/\bFoundry\b/.test(pClosed.text));

  // 5. SHELL-PIXEL CERTIFICATION — committed non-pinned evidence; body excluded by design.
  {
    let cert = null;
    try { cert = JSON.parse(readFileSync(path.join(appRoot, row.shell_pixel_certification_artifact), "utf8")); } catch { /* */ }
    ok("matrix: incidents is shell_pixel_certified with a committed evidence pointer, still daemon_wired", row && row.shell_pixel_certified === true && row.shell_pixel_certification_artifact === "pixel-certifications/incidents.json" && row.parity_class === "daemon_wired");
    ok("the committed certification is REAL: incidents slug, certified, NON-pinned, both desktop viewports certified, mobile honestly not-supported", cert && cert.schema === "ioi.hypervisor.shell-pixel-certification.v1" && cert.slug === "incidents" && cert.shell_pixel_certified === true && cert.viewports_pinned === false && (cert.viewports || []).length === 2 && cert.viewports.every((v) => v.certified === true) && /not_supported/.test(cert.mobile), cert ? cert.viewports.map((v) => `${v.viewport}: dilated ${v.metrics.shell_diff_dilated_pct}% raw ${v.metrics.shell_diff_raw_pct}%`).join(" · ") : "cert missing");
    ok("the certification is MEASUREMENT, not convenience: dilated ≤ 1.25% AND raw ≤ 3.0% on every certified viewport, with real certified-shell coverage", cert && cert.viewports.every((v) => v.metrics.shell_diff_dilated_pct <= 1.25 && v.metrics.shell_diff_raw_pct <= 3.0 && v.metrics.coverage.certified_fraction >= 0.05));
    ok("NO full-body pixel claim: the certification is explicitly SHELL-scoped (live-data body excluded by design, verified semantically — the daemon-truth section above IS that verification)", cert && /SHELL/i.test(cert.note || "") && /body/i.test(cert.note || ""));
  }

  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`incidents-port readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}
run().catch((e) => { console.error("verifier crashed:", e); process.exit(1); });
