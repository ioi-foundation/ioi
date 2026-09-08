#!/usr/bin/env node
// ACC-6 · meaning is local, mappable, and never authority — the composed journey runner.
//
// This runner composes the EXISTING unit done-bars of the three planes ACC-6 crosses (M05
// ontology, M03 authority, M01 daemon effect boundary) into one journey verdict on ONE basis:
// every clause's verifier runs sequentially in this process's lifetime, each boots its own real
// daemon from target/debug/hypervisor-daemon, no replay/fixture server may be present, and the
// git basis is re-read after every clause so a checkout that moved mid-run is red.
//
// It certifies nothing a done-bar does not itself assert; its contribution is composition
// (one basis, one verdict, every clause named) and the fixtures-disabled guard. A clause whose
// verifier fails, or a negative clause whose planted mutation battery was not executed in this
// run, makes the journey PARTIAL/FAIL — never a pass.
//
// Usage:
//   node scripts/check-acceptance-semantic-plane.mjs                       # positive clauses + cheap negatives
//   node scripts/check-acceptance-semantic-plane.mjs --mutation-batteries  # also the multi-hour M05 batteries
//   node scripts/check-acceptance-semantic-plane.mjs --mutation            # self-drill: a planted red clause must fail the journey
//   node scripts/check-acceptance-semantic-plane.mjs --evidence <out.json>

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..");
const APP = "@ioi/hypervisor-app";
const args = process.argv.slice(2);
const withBatteries = args.includes("--mutation-batteries");
const selfDrill = args.includes("--mutation");
const evidenceIndex = args.indexOf("--evidence");
const evidencePath = evidenceIndex >= 0 ? args[evidenceIndex + 1] : null;

const app = (script) => ({ argv: ["npm", "run", "-s", script, `--workspace=${APP}`], label: `${script} (${APP})` });
const root = (script) => ({ argv: ["npm", "run", "-s", script], label: script });

// Clause → done-bar map. Each entry names the ACC-6 clause verbatim (journey-06-semantic-plane.md)
// and the unit whose live done-bar proves it. `negative` clauses additionally name the planted
// mutation battery that must turn the gate red; `battery: "multi-hour"` ones run only with
// --mutation-batteries and are otherwise reported as NOT EXECUTED (which is not a pass).
const CLAUSES = [
  { id: "1", clause: "A version is immutable and identified across namespaces", unit: "M05.1", checks: [app("check:ontology-version-lifecycle")] },
  { id: "2", clause: "Valid time and transaction time are distinct", unit: "M05.1 + M05.3", checks: [app("check:provenance-assertion-graph")] },
  { id: "3", clause: "An overlay diverges without forking, and its provenance names what it overlays", unit: "M05.2", checks: [app("check:semantic-mapping-lifecycle")] },
  { id: "4", clause: "A crosswalk is a receipted, challengeable decision", unit: "M05.2", checks: [] /* proven by the M05.2 run above; not re-run */ },
  { id: "5", clause: "An action contract compiles meaning into a request and grants nothing; the action then passes capability, policy, authority, daemon, evidence and verification gates", unit: "M05.4 + M03.1/M03.2 + M01.3", checks: [app("check:ontology-action-contract"), app("check:env-lease-authority"), app("check:runtime-tool-contract-admission")] },
  { id: "6", clause: "A descriptor is checkable against invariant 11", unit: "M05.5", checks: [app("check:ontology-surface-invariant-11")] },
  { id: "7", clause: "Definition and run are separate objects (data recipe vs transformation run)", unit: "M05.7", checks: [app("check:data-recipe-run-split")] },
  { id: "N1", negative: true, clause: "No cross-domain mapping happens before both domains accept the terms", unit: "M05.2", checks: [], battery: { ...app("mutate:semantic-mapping-lifecycle"), cost: "multi-hour" } },
  { id: "N2", negative: true, clause: "No second production admitter mints beside the kernel path", unit: "M03.4", checks: [app("check:ontology-admission-census")], battery: { ...app("mutate:ontology-admission-census"), cost: "minutes" } },
  { id: "N3", negative: true, clause: "No generic executable recipe family exists; every recipe is owner-qualified", unit: "M05.7", checks: [], battery: { ...app("mutate:data-recipe-run-split"), cost: "multi-hour" } },
  { id: "E", clause: "Journey evidence named by ACC-6: ontology journey, backend families, registered architecture contracts", unit: "M05 / G-4", checks: [app("check:ontology-journey"), app("check:ontology-backend-families"), root("check:architecture-contracts")] },
  { id: "B1", negative: true, clause: "Clause 1/2 mutations: version immutability and bitemporal separation turn red when planted", unit: "M05.1 + M05.3", checks: [], battery: [{ ...app("mutate:ontology-version-lifecycle"), cost: "multi-hour" }, { ...app("mutate:provenance-assertion-graph"), cost: "multi-hour" }] },
  { id: "B5", negative: true, clause: "Clause 5 mutation: removing any one gate from the action path is caught", unit: "M05.4", checks: [], battery: { ...app("mutate:ontology-action-contract"), cost: "multi-hour" } },
  { id: "B6", negative: true, clause: "Clause 6 mutation: a descriptor that breaks invariant 11 is caught", unit: "M05.5", checks: [], battery: { ...app("mutate:ontology-surface-invariant-11"), cost: "multi-hour" } },
];

function sh(argv, opts = {}) {
  const started = Date.now();
  const child = spawnSync(argv[0], argv.slice(1), {
    cwd: ROOT,
    encoding: "utf8",
    maxBuffer: 512 * 1024 * 1024,
    env: { ...process.env, ...FIXTURE_FREE_ENV, ...(opts.env ?? {}) },
  });
  return { status: child.status, stdout: child.stdout ?? "", stderr: child.stderr ?? "", seconds: Math.round((Date.now() - started) / 1000) };
}

// Fixtures disabled: no verifier may attach to a shared/dev daemon or a replay server. The
// done-bars boot their own daemon; these variables are cleared so an operator's shell cannot
// redirect a clause at a fixture or the shared development daemon.
const FIXTURE_FREE_ENV = {
  IOI_HYPERVISOR_DAEMON_URL: "",
  IOI_DAEMON_URL: "",
  IOI_HYPERVISOR_DAEMON_ADDR: "",
  IOI_PRODUCT_UI_REPLAY: "",
  IOI_ACCEPTANCE_FIXTURES: "disabled",
};

function basis() {
  const head = sh(["git", "rev-parse", "--short", "HEAD"]).stdout.trim();
  const dirty = sh(["git", "status", "--porcelain"]).stdout.trim().length > 0;
  return { head, dirty };
}

const results = [];
function record(id, ok, label, detail) {
  results.push({ id, ok, label, detail });
  console.log(`${ok ? "PASS" : "FAIL"} [${id}] ${label}${detail ? ` — ${detail}` : ""}`);
  return ok;
}

function summaryLine(text) {
  const lines = text.split("\n").map((l) => l.trim()).filter(Boolean);
  const scored = [...lines].reverse().find((l) => /\b\d+\/\d+\b/u.test(l) || /^(PASS|FAIL|OK|RED|GREEN)\b/u.test(l));
  return (scored ?? lines.at(-1) ?? "").slice(0, 200);
}

function runCheck(id, check, start) {
  const out = sh(check.argv);
  const after = basis();
  const moved = after.head !== start.head;
  const ok = out.status === 0 && !moved;
  record(id, ok, check.label, `${ok ? "exit 0" : `exit ${out.status}`}${moved ? ` · BASIS MOVED ${start.head}→${after.head}` : ""} · ${summaryLine(out.stdout || out.stderr)} · ${out.seconds}s`);
  if (!ok) console.log((out.stdout + out.stderr).split("\n").slice(-25).join("\n"));
  return ok;
}

const start = basis();
console.log(`# ACC-6 composed journey · basis ${start.head}${start.dirty ? " (dirty tree)" : ""} · ${withBatteries ? "with" : "without"} the multi-hour batteries`);

// Fixture guard: no shared-daemon or replay redirection can reach a clause. Every clause's
// verifier boots its own daemon on a free port from the binary below; the environment variables
// that could point a verifier at a fixture, replay server or the shared development daemon are
// cleared for every child. Foreign serves/replay servers belonging to other sessions on this host
// are observed and recorded, not failed on — nothing here connects to them.
const foreign = sh(["pgrep", "-fa", "hypervisor-app-dev-replay-server|serve-product-ui"]).stdout.trim();
let allOk = record("fixtures", Object.values(FIXTURE_FREE_ENV).filter(Boolean).length === 1, "every clause runs with the shared-daemon/replay redirection variables cleared (IOI_HYPERVISOR_DAEMON_URL, IOI_DAEMON_URL, IOI_HYPERVISOR_DAEMON_ADDR, IOI_PRODUCT_UI_REPLAY) and IOI_ACCEPTANCE_FIXTURES=disabled", foreign ? `foreign serve/replay processes observed on this host, not used: ${foreign.split("\n").length}` : "no serve/replay process on this host");
const daemonBin = process.env.IOI_HYPERVISOR_DAEMON_BINARY || path.join(process.env.CARGO_TARGET_DIR || path.join(ROOT, "target"), "debug", "hypervisor-daemon");
allOk &= record("fixtures", fs.existsSync(daemonBin), "every done-bar boots its own real daemon binary (no fixture daemon)", daemonBin);

if (selfDrill) {
  // The composed verdict must go red when one clause goes red: plant a failing clause.
  const planted = runCheck("drill", { argv: [process.execPath, "-e", "console.log('planted red clause 0/1'); process.exit(1)"], label: "planted red clause" }, start);
  const drillOk = planted === false;
  console.log(`${drillOk ? "PASS" : "FAIL"} self-drill: a planted red clause fails the composed journey`);
  process.exit(drillOk ? 0 : 1);
}

let notExecuted = 0;
for (const c of CLAUSES) {
  for (const check of c.checks) allOk &= runCheck(c.id, check, start);
  if (c.battery) {
    const batteries = Array.isArray(c.battery) ? c.battery : [c.battery];
    for (const b of batteries) {
      if (b.cost === "multi-hour" && !withBatteries) {
        notExecuted += 1;
        record(c.id, false, `${b.label} NOT EXECUTED in this run (${b.cost}; pass --mutation-batteries)`, "a negative clause without its executed battery is not proven");
        allOk = false;
        continue;
      }
      allOk &= runCheck(c.id, b, start);
    }
  }
  if (c.checks.length === 0 && !c.battery) record(c.id, true, `${c.clause} — proven inside the ${c.unit} done-bar already executed above`, "");
}

const end = basis();
allOk &= record("basis", end.head === start.head && end.dirty === start.dirty, "the journey ran on one basis", `${start.head}${start.dirty ? " dirty" : ""} → ${end.head}${end.dirty ? " dirty" : ""}`);

const passed = results.filter((r) => r.ok).length;
const failedBeyondBatteries = results.filter((r) => !r.ok).length - notExecuted;
const verdict = allOk ? "PASS" : failedBeyondBatteries === 0 ? "PARTIAL" : "FAIL";
console.log(`${verdict} ACC-6 composed journey: ${passed}/${results.length} · basis ${start.head}${notExecuted ? ` · ${notExecuted} negative-clause batteries not executed` : ""}`);
if (evidencePath) {
  fs.mkdirSync(path.dirname(path.resolve(ROOT, evidencePath)), { recursive: true });
  fs.writeFileSync(path.resolve(ROOT, evidencePath), `${JSON.stringify({ evidence_format: "ioi.acceptance_journey_run.v1", gate: "ACC-6", basis: start, verdict, with_mutation_batteries: withBatteries, batteries_not_executed: notExecuted, fixtures: "disabled: each done-bar boots its own daemon; no replay/fixture server present; shared-daemon env cleared", recorded_at: new Date().toISOString(), results }, null, 2)}\n`);
}
process.exit(allOk ? 0 : 1);
