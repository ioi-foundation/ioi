#!/usr/bin/env node
// ACC-15 · one consumer afternoon — the composed journey runner.
//
// This runner composes the EXISTING done-bars of the planes ACC-15 crosses (M13 session surface
// and posture, M03 standing authority, M01 daemon admission) into one verdict on ONE basis:
// every clause's verifier runs sequentially in this process's lifetime, each boots its own real
// daemon, the shared-daemon/replay redirection variables are cleared for every child, and the git
// basis is re-read after every clause so a checkout that moved mid-run is red.
//
// It certifies nothing a done-bar does not itself assert. Its contributions are composition (one
// basis, one verdict, every clause named) and HONESTY ABOUT WHAT IS MISSING: a clause with no
// executable proof is recorded as a TYPED ABSENCE naming the unit that owns it, and any absence
// caps the verdict at PARTIAL. ACC-15 cannot read as a pass while M13.6 (the browser head) and
// M13.7 (memory provenance) are unbuilt — which is the point.
//
//   node scripts/check-acceptance-consumer-afternoon.mjs
//   node scripts/check-acceptance-consumer-afternoon.mjs --with-alpha-journey   # + the on-demand alpha journey (fixture authority mode)
//   node scripts/check-acceptance-consumer-afternoon.mjs --mutation             # self-drill: a planted red clause fails the journey
//   node scripts/check-acceptance-consumer-afternoon.mjs --evidence <out.json>

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..");
const APP = "@ioi/hypervisor-app";
const args = process.argv.slice(2);
const withAlphaJourney = args.includes("--with-alpha-journey");
const selfDrill = args.includes("--mutation");
const evidenceIndex = args.indexOf("--evidence");
const evidencePath = evidenceIndex >= 0 ? args[evidenceIndex + 1] : null;

const app = (script, extra = []) => ({ argv: ["npm", "run", "-s", script, `--workspace=${APP}`, ...extra], label: `${script} (${APP})` });
const node = (script, extra = []) => ({ argv: ["node", script, ...extra], label: `node ${script} ${extra.join(" ")}`.trim() });

// Fixtures disabled where the clause allows: every done-bar below boots its own daemon on a free
// port, so the variables that could point a child at a fixture, a replay server or the shared
// development daemon are cleared. The alpha journey's own wallet fixture is the exception the
// clause allows — it IS the deployment's authority node in that lane, and it is labelled.
const FIXTURE_FREE_ENV = {
  IOI_HYPERVISOR_DAEMON_URL: "",
  IOI_DAEMON_URL: "",
  IOI_HYPERVISOR_DAEMON_ADDR: "",
  IOI_PRODUCT_UI_REPLAY: "",
  IOI_ACCEPTANCE_FIXTURES: "disabled",
};

// The alpha journey's fixture-mode standing legs are heavy and on-demand. They are CITED from
// their tracked evidence unless --with-alpha-journey executes them here; a citation is never
// counted as an execution.
const ALPHA_EVIDENCE = "docs/architecture/_meta/evidence/m13-alpha-journey-fixture-standing-2026-09-08.v1.json";

const CLAUSES = [
  {
    id: "1",
    clause: "Two minutes, zero vocabulary: a fresh principal reaches a running session with one scoped connection attached without meeting a kernel noun",
    unit: "M13.1 · M13.2 · M03.8",
    checks: [app("check:consumer-path-vocabulary")],
    cited: [{ label: "the alpha journey's first-run bootstrap → project → bounded connection → session (steps 2a, 4, 5b, 5c)", evidence: ALPHA_EVIDENCE }],
  },
  {
    id: "2",
    clause: "One session surface: every session click target resolves to the designated session view and the projection readout is Operations-only",
    unit: "M13.4",
    checks: [app("check:session-truth-rebind"), node("apps/hypervisor/scripts/check-landing-designations.mjs", ["--exit-gate"])],
  },
  {
    id: "3",
    clause: "The view renders daemon truth: request, activity, artifacts and the proof band reproduce from the daemon's own records",
    unit: "M13.4",
    provenBy: "2",
  },
  {
    id: "4",
    clause: "Configured and silent where policy allows: in-envelope silent_within_policy actions complete with zero approval prompts, the silence attributable to draw-down receipts, and a mutation marking one action interactive_exact_effect produces the exact-effect review instead",
    unit: "M13.5 · M03.11",
    checks: [app("check:standing-consumer-loop")],
  },
  {
    id: "5",
    clause: "Out of bounds refuses, typed: the daemon names the bound, the surface routes widening to Connections, and the same probe via direct daemon invoke refuses identically",
    unit: "M13.5",
    provenBy: "4",
  },
  {
    id: "6",
    clause: "Receipts on demand: after the run the person can answer what it touched and under what authority, citing receipts rather than narrative",
    unit: "M13.4 · M06.1",
    provenBy: "2",
    checks: [app("check:receipts-on-demand")],
  },
  {
    id: "7",
    clause: "Watching is a projection, touching is a crossing: the browser watch pane replays the receipted session and a take-over produces the same admission and receipts",
    unit: "M13.6",
    absences: [{ what: "the browser head is UNBUILT — no watch pane, no take-over crossing, no verifier", owner: "M13.6" }],
  },
  {
    id: "8",
    clause: "Leaving is real: revoking the connection ends the authority, the next session naming it refuses at create or first draw, and the revocation is receipted",
    unit: "M13.3 · M03.12",
    provenBy: "4",
  },
  {
    id: "N1",
    negative: true,
    clause: "No in-run approval prompt appears for an in-envelope silent_within_policy action, and conversely an exact-effect review required by current policy cannot be suppressed by the standing envelope or device posture",
    unit: "M13.5 · ACC-18",
    provenBy: "4",
  },
  {
    id: "N2",
    negative: true,
    clause: "No governance vocabulary appears on the consumer path, and no daemon object is renamed to achieve that",
    unit: "M13.4",
    // The SAME run proves this: check:consumer-path-vocabulary scans every declared consumer
    // surface AND asserts the daemon did not rename its objects to get a clean scan. Pointing at
    // clause 1 rather than re-listing the check keeps it to one execution on one basis.
    provenBy: "1",
  },
  {
    id: "N3",
    negative: true,
    clause: "No credential is present in the session's environment at any point a probe can observe (non-possession holds even mid-run)",
    unit: "M03.13",
    absences: [{ what: "check:worker-secret-non-possession is named by M03's acceptance and DOES NOT EXIST", owner: "M03.13" }],
  },
  {
    id: "N4",
    negative: true,
    clause: "No pixel similarity to the reference seed is cited as evidence for any clause",
    unit: "ACC-15",
    // Computed over the CLAUSE TABLE, not over this file's prose: every executed check and every
    // citation must be a daemon-truth command or a tracked evidence record, never an image.
    structural: () => {
      const cited = CLAUSES.flatMap((c) => [
        ...(c.checks ?? []).map((k) => k.argv.join(" ")),
        ...(c.cited ?? []).map((k) => k.evidence),
      ]);
      const pictorial = cited.filter((entry) => /\.(png|jpe?g|gif|webp|svg)$/iu.test(entry) || /screenshot|pixel|visual-pair/iu.test(entry));
      return {
        ok: pictorial.length === 0,
        detail: `${cited.length} executed/cited evidence entries, none pictorial${pictorial.length ? `: ${pictorial.join(", ")}` : ""}`,
      };
    },
  },
  {
    id: "E",
    clause: "Evidence the journey names: the M13.2 scoped-admission verifier rerun inside the journey, and the named-gap contract",
    unit: "M13.2 · G-8",
    checks: [app("check:session-authority-profile"), app("check:named-gap-truth")],
  },
  {
    id: "A",
    clause: "The alpha journey's fixture-mode standing legs: a silent run to done with no approval card, a second run over the envelope failing closed, and revocation refusing the next session",
    unit: "M13.3 · M13.5 · M12.2",
    checks: withAlphaJourney ? [{ ...app("check:alpha-journey"), env: { IOI_ALPHA_JOURNEY_AUTHORITY: "fixture" }, allowsFixture: true }] : [],
    cited: withAlphaJourney ? [] : [{ label: "the 2026-09-08 fixture-mode run (33/33 including the standing legs)", evidence: ALPHA_EVIDENCE }],
    absences: withAlphaJourney ? [] : [{ what: "NOT EXECUTED in this run (on-demand; needs Ollama and the wallet fixture) — pass --with-alpha-journey", owner: "this runner" }],
  },
];

function sh(argv, opts = {}) {
  const started = Date.now();
  const child = spawnSync(argv[0], argv.slice(1), {
    cwd: ROOT,
    encoding: "utf8",
    maxBuffer: 512 * 1024 * 1024,
    env: { ...process.env, ...(opts.allowsFixture ? {} : FIXTURE_FREE_ENV), ...(opts.env ?? {}) },
    ...(opts.timeoutMs ? { timeout: opts.timeoutMs, killSignal: "SIGKILL" } : {}),
  });
  return {
    status: child.status,
    stdout: child.stdout ?? "",
    stderr: child.stderr ?? "",
    timedOut: opts.timeoutMs !== undefined && child.signal === "SIGKILL",
    seconds: Math.round((Date.now() - started) / 1000),
  };
}

function basis() {
  return {
    head: sh(["git", "rev-parse", "--short", "HEAD"]).stdout.trim(),
    dirty: sh(["git", "status", "--porcelain"]).stdout.trim().length > 0,
  };
}

const results = [];
function record(id, kind, ok, label, detail) {
  results.push({ id, kind, ok, label, detail });
  const tag = kind === "absence" ? "ABSENT" : ok ? "PASS" : "FAIL";
  console.log(`${tag} [${id}] ${label}${detail ? ` — ${detail}` : ""}`);
  return ok;
}

function summaryLine(text) {
  const lines = text.split("\n").map((l) => l.trim()).filter(Boolean);
  return (([...lines].reverse().find((l) => /\b\d+\/\d+\b/u.test(l) || /^(PASS|FAIL|OK|PARTIAL)\b/u.test(l))) ?? lines.at(-1) ?? "").slice(0, 200);
}

function runCheck(id, check, start) {
  const out = sh(check.argv, { env: check.env, allowsFixture: check.allowsFixture, timeoutMs: check.timeoutMs });
  const after = basis();
  const moved = after.head !== start.head || after.dirty !== start.dirty;
  const ok = out.status === 0 && !moved && !out.timedOut;
  record(id, "check", ok, check.label, `${out.timedOut ? "TIMED OUT" : ok ? "exit 0" : `exit ${out.status}`}${moved ? ` · BASIS MOVED ${start.head}${start.dirty ? "+dirty" : ""}→${after.head}${after.dirty ? "+dirty" : ""}` : ""} · ${summaryLine(out.stdout || out.stderr)} · ${out.seconds}s`);
  if (!ok) console.log((out.stdout + out.stderr).split("\n").slice(-25).join("\n"));
  return ok;
}

const start = basis();
console.log(`# ACC-15 composed journey · basis ${start.head}${start.dirty ? " (dirty tree)" : ""} · alpha journey ${withAlphaJourney ? "EXECUTED" : "cited"}`);

if (selfDrill) {
  const planted = runCheck("drill", { argv: [process.execPath, "-e", "console.log('planted red clause 0/1'); process.exit(1)"], label: "planted red clause" }, start);
  console.log(`${planted === false ? "PASS" : "FAIL"} self-drill: a planted red clause fails the composed journey`);
  process.exit(planted === false ? 0 : 1);
}

let failures = 0;
let absences = 0;
for (const c of CLAUSES) {
  for (const check of c.checks ?? []) if (!runCheck(c.id, check, start)) failures += 1;
  if (c.structural) {
    const { ok, detail } = c.structural();
    if (!record(c.id, "check", ok, c.clause, detail)) failures += 1;
  }
  if (c.provenBy) record(c.id, "composed", true, c.clause, `proven inside the clause ${c.provenBy} done-bar already executed above`);
  for (const cite of c.cited ?? []) {
    const present = fs.existsSync(path.resolve(ROOT, cite.evidence));
    if (!record(c.id, "cited", present, `CITED, not executed: ${cite.label}`, `${cite.evidence}${present ? "" : " (MISSING)"}`)) failures += 1;
  }
  for (const absence of c.absences ?? []) {
    record(c.id, "absence", false, `TYPED ABSENCE — ${c.clause}`, `${absence.what} · owner: ${absence.owner}`);
    absences += 1;
  }
}

const end = basis();
if (!record("basis", "check", end.head === start.head && end.dirty === start.dirty, "the journey ran on one basis", `${start.head}${start.dirty ? " dirty" : ""} → ${end.head}${end.dirty ? " dirty" : ""}`)) failures += 1;

const executed = results.filter((r) => r.kind === "check" && r.ok).length;
const verdict = failures > 0 ? "FAIL" : absences > 0 ? "PARTIAL" : "PASS";
console.log(`${verdict} ACC-15 composed journey: ${executed} executed clause checks green · ${absences} typed absences · basis ${start.head}`);
if (absences > 0) console.log("PARTIAL is not a pass: ACC-15 closes when every typed absence above has an executable proof.");
if (evidencePath) {
  fs.mkdirSync(path.dirname(path.resolve(ROOT, evidencePath)), { recursive: true });
  fs.writeFileSync(path.resolve(ROOT, evidencePath), `${JSON.stringify({
    evidence_format: "ioi.acceptance_journey_run.v1",
    gate: "ACC-15",
    basis: start,
    verdict,
    executed_checks: executed,
    typed_absences: absences,
    alpha_journey: withAlphaJourney ? "executed in this run (fixture authority mode)" : `cited from ${ALPHA_EVIDENCE}`,
    fixtures: "disabled for every clause except the alpha journey's own wallet fixture, which IS that lane's authority node and is labelled",
    recorded_at: new Date().toISOString(),
    results,
  }, null, 2)}\n`);
}
process.exit(verdict === "FAIL" ? 1 : 0);
