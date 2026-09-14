// The shared composed-journey harness for the ACC acceptance gates.
//
// Every ACC journey runner (scripts/check-acceptance-*.mjs) is a CLAUSE TABLE over this harness.
// The harness is the part that must be identical across journeys, because it is the part that
// makes a journey verdict mean one thing: every clause's existing done-bar runs sequentially in
// one process lifetime, each boots its own real daemon, the shared-daemon/replay/fixture
// redirection is cleared for every child, and the git basis is re-read after every clause so a
// checkout that moved mid-run is red. It was extracted from the ACC-15 runner
// (scripts/check-acceptance-consumer-afternoon.mjs), which stays as it is: a green runner is not
// refactored for symmetry.
//
// It certifies nothing a done-bar does not itself assert. Its contributions are composition (one
// basis, one verdict, every clause named) and HONESTY ABOUT WHAT IS MISSING. A clause has exactly
// one of these postures, and the verdict is derived from them rather than declared:
//
//   checks      executed here; exit 0 on an unmoved basis is the only green
//   provenBy    proven inside another clause's done-bar already executed in this run
//   cited       a tracked evidence record named, NOT executed — presence is asserted, never a pass
//   battery     a planted-mutation battery; runs only with --mutation-batteries, otherwise it is
//               reported NOT EXECUTED, which caps the verdict at PARTIAL
//   absences    TYPED ABSENCE naming the unit that owes the proof — caps the verdict at PARTIAL
//   ruledOut    ruled out on record by a named ruling — a category of its own, never a pass,
//               and it does not hold the gate
//   fenced      a check whose ONLY red is a finding the register assigns to another owner; the
//               fence's matcher must recognise the failure exactly, the owner and ruling are
//               printed, and the verdict is capped at PARTIAL unless the fence's `holdsGate` is
//               false — which is a ruling the runner must cite, not a default
//   scheduled   a live leg that needs a credential, provider, fleet or independently administered
//               party this basis cannot supply. It is recorded SCHEDULED-OUTSTANDING with its exact
//               prerequisite and the ruling that lets the gate close at MVP depth without it (the
//               M01.7 precedent: the path is proven offline in an executed check, the live run is
//               retained once and re-qualified by an applicability gate). Never a pass; it does
//               not hold the gate ONLY because a named ruling says so, and the ruling is printed.
//   structural  a predicate over the clause table itself (no child process)
//
// PARTIAL is never a pass: the runner exits 0 only on PASS. FAIL exits 1. PARTIAL exits 2 so a
// caller can tell "not yet" from "broken" without parsing text.
//
// R-15 (2026-09-10): a bounded check dies as a TREE. A check with `timeoutMs` is started in its
// own process group and the deadline kills the group — SIGTERM first so the verifier's own signal
// handler reaps what it owns, SIGKILL after a grace — and the group is SIGKILLed once more after
// any exit. Same shape as scripts/check-cargo-test-population.mjs.

import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const ROOT = path.resolve(HERE, "..", "..");
export const APP = "@ioi/hypervisor-app";

// Fixtures disabled where the clause allows: every done-bar boots its own daemon on a free port,
// so the variables that could point a child at a fixture, a replay server or the shared
// development daemon are cleared. A lane whose OWN fixture is the thing under test (the alpha
// journey's wallet fixture is that deployment's authority node) sets `allowsFixture` and is
// labelled as such in the evidence.
export const FIXTURE_FREE_ENV = {
  IOI_HYPERVISOR_DAEMON_URL: "",
  IOI_DAEMON_URL: "",
  IOI_HYPERVISOR_DAEMON_ADDR: "",
  IOI_PRODUCT_UI_REPLAY: "",
  IOI_ACCEPTANCE_FIXTURES: "disabled",
};

export const app = (script, extra = []) => ({
  argv: ["npm", "run", "-s", script, `--workspace=${APP}`, ...extra],
  label: `${script} (${APP})${extra.length ? ` ${extra.join(" ")}` : ""}`,
});
export const rootScript = (script, extra = []) => ({
  argv: ["npm", "run", "-s", script, ...extra],
  label: `${script}${extra.length ? ` ${extra.join(" ")}` : ""}`,
});
export const node = (script, extra = []) => ({
  argv: ["node", script, ...extra],
  label: `node ${script} ${extra.join(" ")}`.trim(),
});
export const cargoTest = (pkg, extra = []) => ({
  argv: ["cargo", "test", "--locked", "-p", pkg, ...extra],
  label: `cargo test --locked -p ${pkg} ${extra.join(" ")}`.trim(),
});
export const bounded = (check, minutes) => ({ ...check, timeoutMs: minutes * 60_000 });

function sh(argv, opts = {}) {
  const started = Date.now();
  const child = spawnSync(argv[0], argv.slice(1), {
    cwd: ROOT,
    encoding: "utf8",
    maxBuffer: 512 * 1024 * 1024,
    env: { ...process.env, ...(opts.allowsFixture ? {} : FIXTURE_FREE_ENV), ...(opts.env ?? {}) },
  });
  return {
    status: child.status,
    stdout: child.stdout ?? "",
    stderr: child.stderr ?? "",
    timedOut: false,
    seconds: Math.round((Date.now() - started) / 1000),
  };
}

let activeBoundedGroup = null;
function killGroup(pid, signal) {
  try { process.kill(-pid, signal); } catch { /* already gone */ }
}
function shBounded(argv, opts = {}) {
  const started = Date.now();
  return new Promise((resolve) => {
    let stdout = "", stderr = "", timedOut = false, settled = false;
    const child = spawn(argv[0], argv.slice(1), {
      cwd: ROOT,
      env: { ...process.env, ...(opts.allowsFixture ? {} : FIXTURE_FREE_ENV), ...(opts.env ?? {}) },
      stdio: ["ignore", "pipe", "pipe"],
      detached: true,
    });
    activeBoundedGroup = child.pid;
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    const deadline = setTimeout(() => {
      timedOut = true;
      killGroup(child.pid, "SIGTERM");
      setTimeout(() => killGroup(child.pid, "SIGKILL"), 20_000).unref();
    }, opts.timeoutMs);
    const finish = (status, signal) => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      killGroup(child.pid, "SIGKILL");
      activeBoundedGroup = null;
      resolve({ status, signal, stdout, stderr, timedOut, seconds: Math.round((Date.now() - started) / 1000) });
    };
    child.on("error", () => finish(null, null));
    child.on("exit", finish);
  });
}
for (const signal of ["SIGTERM", "SIGINT", "SIGHUP"]) {
  process.on(signal, () => {
    if (activeBoundedGroup) {
      killGroup(activeBoundedGroup, "SIGTERM");
      setTimeout(() => killGroup(activeBoundedGroup, "SIGKILL"), 5_000).unref();
    }
    process.exit(1);
  });
}

export function basis() {
  return {
    head: sh(["git", "rev-parse", "--short", "HEAD"]).stdout.trim(),
    dirty: sh(["git", "status", "--porcelain"]).stdout.trim().length > 0,
  };
}

function summaryLine(text) {
  const lines = text.split("\n").map((l) => l.trim()).filter(Boolean);
  return (([...lines].reverse().find((l) => /\b\d+\/\d+\b/u.test(l) || /^(PASS|FAIL|OK|PARTIAL|VERDICT)\b/u.test(l))) ?? lines.at(-1) ?? "").slice(0, 200);
}

// The journey definition:
//   gate       "ACC-1"
//   title      the journey's title verbatim
//   doc        internal-docs path of the journey document (printed, not read)
//   clauses    the clause table (see the postures above)
//   argv       process.argv.slice(2) — the harness owns --mutation, --mutation-batteries, --evidence
//   flags      optional map of extra boolean flags the runner recognises, { "--with-x": bool }
export async function runJourney({ gate, title, doc, clauses, argv = process.argv.slice(2) }) {
  const selfDrill = argv.includes("--mutation");
  const withBatteries = argv.includes("--mutation-batteries");
  const evidenceIndex = argv.indexOf("--evidence");
  const evidencePath = evidenceIndex >= 0 ? argv[evidenceIndex + 1] : null;

  const results = [];
  function record(id, kind, ok, label, detail) {
    results.push({ id, kind, ok, label, detail });
    const tag = kind === "absence" ? "ABSENT" : kind === "fenced" ? "FENCED" : kind === "not_executed" ? "NOT-EXECUTED" : kind === "scheduled" ? "SCHEDULED" : ok ? "PASS" : "FAIL";
    console.log(`${tag} [${id}] ${label}${detail ? ` — ${detail}` : ""}`);
    return ok;
  }

  async function runCheck(id, check, start) {
    const out = check.timeoutMs
      ? await shBounded(check.argv, { env: check.env, allowsFixture: check.allowsFixture, timeoutMs: check.timeoutMs })
      : sh(check.argv, { env: check.env, allowsFixture: check.allowsFixture });
    const after = basis();
    const moved = after.head !== start.head || after.dirty !== start.dirty;
    const ok = out.status === 0 && !moved && !out.timedOut;
    const detail = `${out.timedOut ? "TIMED OUT" : ok ? "exit 0" : `exit ${out.status}`}${moved ? ` · BASIS MOVED ${start.head}${start.dirty ? "+dirty" : ""}→${after.head}${after.dirty ? "+dirty" : ""}` : ""} · ${summaryLine(out.stdout || out.stderr)} · ${out.seconds}s${check.allowsFixture ? " · own fixture allowed (labelled)" : ""}`;
    let fenceMatched = false;
    if (!ok && !moved && !out.timedOut && check.fence) {
      try { fenceMatched = check.fence.matches({ stdout: out.stdout, stderr: out.stderr, status: out.status }) === true; } catch { fenceMatched = false; }
    }
    if (fenceMatched) {
      record(id, "fenced", false, `${check.label} — red ONLY on ${check.fence.ruling} (owner: ${check.fence.owner})`, `${detail} · ${check.fence.what}`);
      return { ok: false, fenced: true, holdsGate: check.fence.holdsGate !== false };
    }
    record(id, "check", ok, check.label, detail);
    if (!ok) console.log((out.stdout + out.stderr).split("\n").slice(-25).join("\n"));
    return { ok, fenced: false };
  }

  const start = basis();
  console.log(`# ${gate} composed journey · ${title} · basis ${start.head}${start.dirty ? " (dirty tree)" : ""} · batteries ${withBatteries ? "EXECUTED" : "not executed"}`);
  console.log(`# clause source: ${doc}`);

  if (selfDrill) {
    const planted = await runCheck("drill", { argv: [process.execPath, "-e", "console.log('planted red clause 0/1'); process.exit(1)"], label: "planted red clause" }, start);
    console.log(`${planted.ok === false ? "PASS" : "FAIL"} self-drill: a planted red clause fails the composed journey`);
    process.exit(planted.ok === false ? 0 : 1);
  }

  let failures = 0;
  let absences = 0;
  let ruledOut = 0;
  let fenced = 0;
  let fencedHolding = 0;
  let notExecuted = 0;
  let scheduled = 0;
  const ids = new Set();
  for (const c of clauses) {
    if (ids.has(c.id)) { record(c.id, "check", false, "duplicate clause id in the runner's own table", c.clause); failures += 1; }
    ids.add(c.id);
    for (const check of c.checks ?? []) {
      const r = await runCheck(c.id, check, start);
      if (r.fenced) { fenced += 1; if (r.holdsGate) fencedHolding += 1; }
      else if (!r.ok) failures += 1;
    }
    if (c.structural) {
      const { ok, detail } = c.structural(clauses);
      if (!record(c.id, "check", ok, c.clause, detail)) failures += 1;
    }
    if (c.provenBy) {
      const target = clauses.find((x) => x.id === c.provenBy);
      const executed = target && (target.checks ?? []).length > 0;
      if (!record(c.id, "composed", !!executed, c.clause, executed ? `proven inside the clause ${c.provenBy} done-bar already executed above` : `provenBy ${c.provenBy} names a clause with no executed check — the runner's own table is wrong`)) failures += 1;
    }
    for (const cite of c.cited ?? []) {
      const present = fs.existsSync(path.resolve(ROOT, cite.evidence));
      if (!record(c.id, "cited", present, `CITED, not executed: ${cite.label}`, `${cite.evidence}${present ? "" : " (MISSING)"}`)) failures += 1;
    }
    // Batteries: `cost: "minutes"` (a population drill or a verifier-side drill that plants nothing
    // in tracked source) runs on every invocation; `cost: "multi-hour"` (a battery that plants
    // defects in daemon source and rebuilds, or is otherwise hours long) runs only with
    // --mutation-batteries and is otherwise NOT EXECUTED, which caps the verdict at PARTIAL.
    const batteries = Array.isArray(c.battery) ? c.battery : c.battery ? [c.battery] : [];
    for (const battery of batteries) {
      if (withBatteries || battery.cost === "minutes") {
        const r = await runCheck(c.id, battery, start);
        if (!r.ok) failures += 1;
      } else {
        record(c.id, "not_executed", false, `battery NOT EXECUTED (${battery.cost ?? "cost not stated"}): ${battery.label}`, "pass --mutation-batteries to run it; a battery not run in this basis is not evidence for it");
        notExecuted += 1;
      }
    }
    for (const absence of c.absences ?? []) {
      record(c.id, "absence", false, `TYPED ABSENCE — ${c.clause}`, `${absence.what} · owner: ${absence.owner}`);
      absences += 1;
    }
    if (c.ruledOut) {
      record(c.id, "ruled_out", true, `RULED OUT AT MVP DEPTH (on record, not a pass) — ${c.clause}`, `${c.ruledOut.what} · ruling: ${c.ruledOut.ruling}`);
      ruledOut += 1;
    }
    for (const s of c.scheduled ?? []) {
      if (!s.ruling || !s.prerequisite) { record(c.id, "check", false, "a scheduled leg without a ruling or a prerequisite is not scheduled, it is missing", c.clause); failures += 1; continue; }
      record(c.id, "scheduled", true, `SCHEDULED-OUTSTANDING (live; not a pass, does not hold the gate by ruling) — ${s.what}`, `prerequisite: ${s.prerequisite} · ruling: ${s.ruling}`);
      scheduled += 1;
    }
  }

  const end = basis();
  if (!record("basis", "check", end.head === start.head && end.dirty === start.dirty, "the journey ran on one basis", `${start.head}${start.dirty ? " dirty" : ""} → ${end.head}${end.dirty ? " dirty" : ""}`)) failures += 1;

  const executed = results.filter((r) => r.kind === "check" && r.ok).length;
  const verdict = failures > 0 ? "FAIL" : absences > 0 || notExecuted > 0 || fencedHolding > 0 ? "PARTIAL" : "PASS";
  console.log(`${verdict} ${gate} composed journey${verdict === "PASS" && (ruledOut > 0 || fenced > 0 || scheduled > 0) ? " at MVP depth" : ""}: ${executed} executed clause checks green · ${absences} typed absences · ${notExecuted} batteries not executed · ${fenced} fenced (${fencedHolding} holding the gate) · ${scheduled} live leg(s) scheduled-outstanding by ruling · ${ruledOut} clause(s) ruled out on record · basis ${start.head}`);
  if (verdict === "PARTIAL") console.log(`PARTIAL is not a pass: ${gate} closes when every typed absence has an executable proof, every battery has run on the claimed basis, and no fenced finding holds the gate.`);
  if (evidencePath) {
    fs.mkdirSync(path.dirname(path.resolve(ROOT, evidencePath)), { recursive: true });
    fs.writeFileSync(path.resolve(ROOT, evidencePath), `${JSON.stringify({
      evidence_format: "ioi.acceptance_journey_run.v1",
      gate,
      title,
      basis: start,
      verdict,
      executed_checks: executed,
      typed_absences: absences,
      batteries_not_executed: notExecuted,
      fenced,
      fenced_holding_gate: fencedHolding,
      scheduled_outstanding_live: scheduled,
      ruled_out_on_record: ruledOut,
      fixtures: "disabled for every clause unless the check is labelled as allowing its own fixture",
      recorded_at: new Date().toISOString(),
      results,
    }, null, 2)}\n`);
  }
  process.exit(verdict === "FAIL" ? 1 : verdict === "PARTIAL" ? 2 : 0);
}
