#!/usr/bin/env node
// M04.8's SCHEDULED release qualification — the soak lane, hardened.
//
// WHAT WAS WRONG WITH RUNNING THE SOAK DIRECTLY. `soak:m4-room-participation-contribution-wallet-authority`
// was a bare `node verify-m4-room-participation-contribution-plane.mjs` behind one env var. Its exit
// code says "every assertion that ran, passed" — which is a different claim from "the assertions this
// lane exists to make all ran, over the full approval workload". Delete an assertion and the run is
// still green with one fewer. Shorten the campaign and it is green and faster. Neither is visible in
// an exit code, and a release qualification that cannot see either is not qualifying anything.
//
// SO THIS WRAPPER REQUIRES FOUR THINGS OF A RUN, and refuses it otherwise:
//
//   1. THE ASSERTION POPULATION, EXACTLY. Every pinned name must appear as `PASS: <name>`, and the
//      run's own `N/M passed` line must agree with the pinned count in BOTH directions — a missing
//      assertion and an unpinned extra one are different defects and each is refused by name.
//   2. THE DEPTH CAMPAIGN, REPORTED AND FLOORED. The verifier now counts every governed crossing
//      (challenge -> recorded wallet approval -> resolved commit against the real chain) and prints
//      the total. Two independent bounds hold it: a SOURCE-BOUND floor, the number of `await
//      governed(` call sites read out of the verifier itself, so deleting a crossing lowers the
//      floor and is caught by the ratchet instead; and the RATCHET, the highest count any previously
//      qualified artifact recorded. A run reporting no crossings at all is refused as a missing
//      campaign, never treated as a campaign of zero.
//   3. A FRESH ARTIFACT. The qualification writes its own artifact from THIS run and refuses to
//      treat a pre-existing one as evidence. An artifact is the output of qualifying, never an input.
//   4. THE RELEASE FIXTURE. `IOI_WALLET_FIXTURE_RELEASE=1` is set here rather than left to a caller,
//      because a scheduled lane that silently ran the debug fixture would qualify a different thing.
//
// NONCLAIM, ON RECORD. This wrapper does not make the soak deeper; it makes the depth it already has
// non-reducible in silence. Whether the campaign is deep ENOUGH is the lane's own design question,
// and the floor recorded here is the depth as it stands, not a judgement that it suffices.
//
// Exit: 0 qualified · 1 refused · 2 blocked (the lane could not start).
//   --drill   run the wrapper's own logic against synthetic runs instead of the real lane: a run
//             missing an assertion, one with a reduced campaign, one reporting no campaign at all,
//             and a good one. Each must be refused or accepted as named. No wallet fixture needed.
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP = path.resolve(HERE, "..");
const ROOT = path.resolve(APP, "..", "..");
const LANE = path.join(HERE, "verify-m4-room-participation-contribution-plane.mjs");
const ARTIFACT_DIR = path.join(ROOT, "docs/architecture/_meta/evidence");
const drill = process.argv.includes("--drill");

// The assertion population, transcribed from the lane rather than scraped at run time: a pin the
// run could regenerate is a pin the run can also shrink.
const PINNED_ASSERTIONS = [
  "DEPENDENCIES: active bounded System, strict GoalRun owner, and open OutcomeRoom exist",
  "PAIRING: missing authority challenges without mutation and owner-local session grants nothing",
  "TERMS: exact envelope acceptance is evidence and grants neither membership nor authority",
  "CAS: stale room heads refuse before authority or mutation",
  "PARTICIPATION: pairing is single-use and replay writes nothing",
  "ADMISSION: unsupported hosted principals fail before mutation",
  "LEASE: room System admits a bounded worker lease from exact terms acceptance",
  "OFFERS: resource and capability offers resolve a live lease and stay within its grants",
  "ELIGIBILITY: match is receipt evidence only and structurally grants nothing",
  "CLAIM: exclusive acquisition refuses a duplicate live claim",
  "LIVENESS: heartbeat is a receipt ref on a successor, not a new object family",
  "LINEAGE: Attempt, Finding, WorkResult, and challenge compose without a Contribution object",
  "RELEASE: one terminal claim successor restores projected claimability and retains Attempt lineage",
  "EXCLUSIONS: M11 discovery/state-bundle, Contribution, and verdict surfaces are unavailable",
  "RESTART: all ten named lifecycles and auxiliary terms/eligibility evidence reproject exactly",
];

const results = [];
const ok = (name, cond, detail = "") => {
  results.push({ name, pass: !!cond });
  console.log(`${cond ? "PASS" : "FAIL"} ${name}${detail ? ` — ${detail}` : ""}`);
  return !!cond;
};

/** The floor, read out of the lane's own source. Deleting a crossing lowers this, which is why the
 *  ratchet below is the second, independent bound rather than a convenience. */
function sourceBoundFloor(laneSource) {
  return (laneSource.match(/await governed\(/gu) ?? []).length;
}

/** The highest campaign any previously qualified artifact recorded. */
function ratchetFloor() {
  if (!fs.existsSync(ARTIFACT_DIR)) return 0;
  let highest = 0;
  for (const name of fs.readdirSync(ARTIFACT_DIR)) {
    if (!/^m04-8-room-participation-soak-.*\.v1\.json$/u.test(name)) continue;
    try {
      const recorded = JSON.parse(fs.readFileSync(path.join(ARTIFACT_DIR, name), "utf8"));
      const count = Number(recorded?.depth_campaign?.governed_crossings ?? 0);
      if (Number.isFinite(count) && count > highest) highest = count;
    } catch { /* an unreadable artifact floors nothing */ }
  }
  return highest;
}

/** Everything this qualification reads out of a run, in one place. */
function readRun(stdout) {
  const observed = new Set();
  for (const line of stdout.split("\n")) {
    const match = line.match(/^PASS: (.+?)(?: — |$)/u);
    if (match) observed.add(match[1].trim());
  }
  const tally = stdout.match(/^(\d+)\/(\d+) passed$/mu);
  const crossings = stdout.match(/^governed crossings: (\d+)$/mu);
  const routes = stdout.match(/^governed routes: (.*)$/mu);
  return {
    observed,
    passed: tally ? Number(tally[1]) : null,
    total: tally ? Number(tally[2]) : null,
    crossings: crossings ? Number(crossings[1]) : null,
    routes: routes ? routes[1].split(" ").filter(Boolean) : [],
  };
}

/** Judge one run against the pinned population and both depth bounds. */
function qualify(run, floors, { record = true } = {}) {
  const verdicts = [];
  const say = (name, cond, detail) => verdicts.push({ name, pass: !!cond, detail: detail ?? "" });

  const missing = PINNED_ASSERTIONS.filter((name) => !run.observed.has(name));
  say("every pinned assertion of the lane actually ran and passed", missing.length === 0,
    missing.length ? `missing: ${missing.map((m) => m.split(":")[0]).join(", ")}` : `${PINNED_ASSERTIONS.length} pinned`);

  const extra = [...run.observed].filter((name) => !PINNED_ASSERTIONS.includes(name));
  say("the lane ran no assertion this qualification does not pin", extra.length === 0,
    extra.length ? `unpinned: ${extra.map((e) => e.split(":")[0]).join(", ")}` : "none");

  say("the lane's own tally agrees with the pinned population in both directions",
    run.passed === PINNED_ASSERTIONS.length && run.total === PINNED_ASSERTIONS.length,
    `run says ${run.passed}/${run.total}, pinned ${PINNED_ASSERTIONS.length}`);

  // A campaign that was not reported is MISSING, never zero. Treating an absent line as 0 would let
  // a lane that stopped reporting its depth pass every floor of 0 forever.
  say("the run reported its depth campaign at all", run.crossings !== null,
    run.crossings === null ? "no `governed crossings:` line — the campaign is missing, not empty" : `${run.crossings} crossings`);

  if (run.crossings !== null) {
    say("the campaign meets the floor read out of the lane's own source",
      run.crossings >= floors.source,
      `${run.crossings} >= ${floors.source} (await governed( call sites)`);
    say("the campaign does not fall below the deepest campaign any qualified artifact recorded",
      run.crossings >= floors.ratchet,
      `${run.crossings} >= ${floors.ratchet} (ratchet)`);
  }

  if (record) for (const verdict of verdicts) ok(verdict.name, verdict.pass, verdict.detail);
  return verdicts.every((verdict) => verdict.pass);
}

const laneSource = fs.readFileSync(LANE, "utf8");
const floors = { source: sourceBoundFloor(laneSource), ratchet: ratchetFloor() };

// SOURCE-BIND THE POPULATION BEFORE ANYTHING ELSE. A pinned name that no longer exists in the lane
// can never be observed, so every real run would be refused for a defect in the PIN rather than in
// the run — and a transcription slip (these names were first copied from truncated output) would
// look exactly like a deleted assertion. This is checked here, not left to whoever reads the
// refusal, and it is fatal: a qualification whose own population is wrong qualifies nothing.
const unbound = PINNED_ASSERTIONS.filter((name) => !laneSource.includes(name));
if (unbound.length > 0) {
  for (const name of unbound) console.log(`FAIL pinned assertion is not in the lane's source: ${name}`);
  console.log(`FAIL qualify:m4-room-participation-contribution-soak — ${unbound.length} pinned assertion(s) no longer exist in ${path.relative(ROOT, LANE)}; re-derive the population before qualifying anything`);
  process.exit(1);
}

// --------------------------------------------------------------------------------- the self-drill
if (drill) {
  const good = [
    ...PINNED_ASSERTIONS.map((name) => `PASS: ${name} — detail`),
    "governed crossings: 12",
    "governed routes: /a /b",
    `${PINNED_ASSERTIONS.length}/${PINNED_ASSERTIONS.length} passed`,
  ].join("\n");
  const withoutOne = good.replace(`PASS: ${PINNED_ASSERTIONS[4]} — detail\n`, "")
    .replace(`${PINNED_ASSERTIONS.length}/${PINNED_ASSERTIONS.length} passed`, `${PINNED_ASSERTIONS.length - 1}/${PINNED_ASSERTIONS.length - 1} passed`);
  const shallow = good.replace("governed crossings: 12", `governed crossings: ${Math.max(floors.source - 1, 0)}`);
  const silent = good.replace("governed crossings: 12\n", "");
  const drillFloors = { source: floors.source, ratchet: 12 };

  ok("DRILL positive control: a complete run over the full campaign qualifies",
    qualify(readRun(good), drillFloors, { record: false }), "");
  ok("DRILL: a run missing ONE pinned assertion is refused — a green exit code with one fewer assertion is the defect this wrapper exists to catch",
    !qualify(readRun(withoutOne), drillFloors, { record: false }), "");
  ok("DRILL: a run whose campaign fell below the source-bound floor is refused",
    !qualify(readRun(shallow), drillFloors, { record: false }), "");
  ok("DRILL: a run that reports NO campaign is refused as missing, not accepted as a campaign of zero",
    !qualify(readRun(silent), drillFloors, { record: false }), "");
  ok("DRILL: a run that meets the source floor but falls below a deeper qualified artifact is refused by the ratchet",
    !qualify(readRun(good.replace("governed crossings: 12", "governed crossings: 11")), drillFloors, { record: false }), "");
  ok("the source-bound floor is derived from the lane and is not zero — a floor of zero would pass every run",
    floors.source > 0, `${floors.source} governed call sites`);

  const failed = results.filter((r) => !r.pass).length;
  console.log(`${failed ? "FAIL" : "PASS"} qualify:m4-room-participation-contribution-soak --drill — ${results.length - failed}/${results.length} · the wrapper's own refusals, no wallet fixture required`);
  process.exit(failed ? 1 : 0);
}

// ------------------------------------------------------------------------------------- the lane
console.log(`# M04.8 scheduled release qualification · source floor ${floors.source} · ratchet ${floors.ratchet}`);
const run = spawnSync("node", [LANE], {
  cwd: APP,
  encoding: "utf8",
  env: { ...process.env, IOI_WALLET_FIXTURE_RELEASE: "1" },
  maxBuffer: 64 * 1024 * 1024,
});
process.stdout.write(run.stdout ?? "");
if (run.stderr) process.stderr.write(run.stderr);
if (run.status === null) {
  console.log(`BLOCKED qualify:m4-room-participation-contribution-soak — the lane did not run to completion (${run.error?.message ?? "no exit status"})`);
  process.exit(2);
}

const observed = readRun(run.stdout ?? "");
ok("the soak lane itself exited 0", run.status === 0, `exit ${run.status}`);
const qualified = qualify(observed, floors) && run.status === 0;

// THE ARTIFACT IS AN OUTPUT. It is written from THIS run and only when the run qualified; a
// pre-existing artifact is never read as evidence that anything was qualified today.
if (qualified) {
  const commit = spawnSync("git", ["rev-parse", "HEAD"], { cwd: ROOT, encoding: "utf8" }).stdout?.trim() ?? "unknown";
  const stamp = new Date().toISOString().slice(0, 10);
  const artifact = {
    evidence_format: "ioi.m04-8.room-participation-soak-qualification.v1",
    unit: "M04.8",
    qualified_at: new Date().toISOString(),
    commit,
    release_fixture: true,
    assertion_population: { pinned: PINNED_ASSERTIONS.length, observed: [...observed.observed].sort() },
    depth_campaign: {
      governed_crossings: observed.crossings,
      routes: observed.routes,
      source_bound_floor: floors.source,
      ratchet_floor_at_qualification: floors.ratchet,
    },
    nonclaim: "This artifact records that the lane's pinned assertions all ran and its approval campaign was not reduced. It is not a claim that the campaign is deep enough, which is the lane's own design question.",
  };
  const out = path.join(ARTIFACT_DIR, `m04-8-room-participation-soak-${stamp}.v1.json`);
  fs.writeFileSync(out, `${JSON.stringify(artifact, null, 2)}\n`);
  ok("a fresh qualified artifact was written from THIS run", fs.existsSync(out), path.relative(ROOT, out));
}

const failed = results.filter((r) => !r.pass).length;
console.log(`${failed ? "FAIL" : "PASS"} qualify:m4-room-participation-contribution-soak — ${results.length - failed}/${results.length} · M04.8 scheduled release qualification`);
process.exit(failed ? 1 : 0);
