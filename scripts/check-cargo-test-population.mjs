#!/usr/bin/env node
// Source-bound, fail-empty Cargo test-population wrapper.
//
// A raw `cargo test -p crate some_filter` exits 0 when the filter selects zero tests, so a
// renamed or deleted module reads as green. This driver turns a closed Rust population into a
// release-accountable check:
//
//   1. every pinned test name must appear as `fn <leaf>` in the pinned source file (source-bound);
//   2. `cargo test ... -- --list --exact <names>` must list EXACTLY the pinned set (no missing, no
//      extra, never empty);
//   3. the run must report `test result: ok` with passed == pinned count, 0 failed, 0 ignored;
//   4. optional `source_pins` assert a regex hit-count in a source file (e.g. the crash-edge
//      phase arrays a test iterates);
//   5. optional `supplementary` commands run afterwards, sequentially, and must exit 0.
//
// Usage:
//   node scripts/check-cargo-test-population.mjs --population scripts/test-populations/<name>.v1.json
//   node scripts/check-cargo-test-population.mjs --population <file> --mutation   # self-drill
//   node scripts/check-cargo-test-population.mjs --population <file> --evidence <out.json>
//
// `--mutation` plants an absent test name into the first family and a zero-test family, and
// asserts the driver refuses both; it is how this verifier proves it can fail on its own finding.

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..");
const FORMAT = "ioi.cargo_test_population.v1";

const args = process.argv.slice(2);
const flag = (name) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
};
const populationPath = flag("--population");
const mutation = args.includes("--mutation");
const evidencePath = flag("--evidence");
if (!populationPath) {
  console.error("usage: check-cargo-test-population.mjs --population <file> [--mutation] [--evidence <out>]");
  process.exit(2);
}

const population = JSON.parse(fs.readFileSync(path.resolve(ROOT, populationPath), "utf8"));
if (population.format !== FORMAT) {
  console.error(`population ${populationPath}: format must be ${FORMAT}`);
  process.exit(2);
}

const results = [];
function record(ok, label, detail) {
  results.push({ ok, label, detail: detail ?? "" });
  console.log(`${ok ? "PASS" : "FAIL"} ${label}${detail ? ` — ${detail}` : ""}`);
  return ok;
}

function run(argv, opts = {}) {
  const started = Date.now();
  const child = spawnSync(argv[0], argv.slice(1), {
    cwd: ROOT,
    encoding: "utf8",
    maxBuffer: 256 * 1024 * 1024,
    env: { ...process.env, CARGO_TERM_COLOR: "never", ...(opts.env ?? {}) },
  });
  return {
    status: child.status,
    stdout: child.stdout ?? "",
    stderr: child.stderr ?? "",
    seconds: Math.round((Date.now() - started) / 1000),
  };
}

function cargoArgv(family, harnessArgs) {
  const argv = ["cargo", "test", "--locked", "-p", family.package, ...(family.target ?? [])];
  if (family.features?.length) argv.push("--features", family.features.join(","));
  if (family.all_features) argv.push("--all-features");
  argv.push("--", ...harnessArgs);
  return argv;
}

// A cargo test invocation with several --exact names selects every test whose full path
// equals one of them; libtest accepts multiple positional filters.
function listSelected(family, tests) {
  const out = run(cargoArgv(family, ["--list", "--exact", ...tests]));
  const listed = new Set();
  for (const line of out.stdout.split("\n")) {
    const m = /^(\S+): test$/u.exec(line.trim());
    if (m) listed.add(m[1]);
  }
  return { out, listed };
}

function parseResult(stdout) {
  const lines = stdout.split("\n").filter((l) => l.startsWith("test result:"));
  const last = lines.at(-1) ?? "";
  const m =
    /^test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out/u.exec(last);
  if (!m) return null;
  return { verdict: m[1], passed: +m[2], failed: +m[3], ignored: +m[4], filteredOut: +m[6], line: last };
}

function checkFamily(family, { plantAbsent = false, plantWrongPath = false, empty = false } = {}) {
  const name = family.name;
  let tests = [...(family.tests ?? [])];
  if (empty) tests = [];
  if (plantAbsent) tests.push(`${tests[0] ?? "planted"}__planted_absent_test`);
  if (plantWrongPath) {
    // The leaf `fn` exists in source, so only the harness listing can refuse this one.
    const leaf = (tests[0] ?? "planted").split("::").at(-1);
    tests.push(`${name}__planted_module::tests::${leaf}`);
  }
  const failures = [];

  if (tests.length === 0) {
    failures.push("pinned population is empty");
    return { name, failures, count: 0 };
  }
  if (new Set(tests).size !== tests.length) failures.push("pinned population has duplicates");

  // 1. source-bound: every leaf name is a `fn` in the pinned source file(s).
  const sources = Array.isArray(family.source) ? family.source : [family.source].filter(Boolean);
  if (sources.length === 0) failures.push("family names no source file");
  const sourceText = sources
    .map((s) => {
      const p = path.resolve(ROOT, s);
      if (!fs.existsSync(p)) {
        failures.push(`source ${s} does not exist`);
        return "";
      }
      return fs.readFileSync(p, "utf8");
    })
    .join("\n");
  for (const t of tests) {
    const leaf = t.split("::").at(-1);
    if (!new RegExp(`\\bfn\\s+${leaf}\\s*[<(]`, "u").test(sourceText)) {
      failures.push(`test ${t} has no \`fn ${leaf}\` in ${sources.join(", ")}`);
    }
  }
  if (failures.length) return { name, failures, count: tests.length };

  // 2. the harness lists exactly the pinned set.
  const { out: listOut, listed } = listSelected(family, tests);
  if (listOut.status !== 0) {
    failures.push(`cargo --list exited ${listOut.status}: ${(listOut.stderr || listOut.stdout).slice(-600)}`);
    return { name, failures, count: tests.length };
  }
  const missing = tests.filter((t) => !listed.has(t));
  const extra = [...listed].filter((t) => !tests.includes(t));
  if (missing.length) failures.push(`not selectable: ${missing.join(", ")}`);
  if (extra.length) failures.push(`selected beyond the pin: ${extra.join(", ")}`);
  if (listed.size === 0) failures.push("zero tests selected");
  if (failures.length) return { name, failures, count: tests.length, listed: listed.size };

  // 3. run them; the count must be exact.
  const runOut = run(cargoArgv(family, ["--exact", ...tests]));
  const parsed = parseResult(runOut.stdout);
  if (!parsed) {
    failures.push(`no \`test result:\` summary (exit ${runOut.status}): ${(runOut.stderr || runOut.stdout).slice(-600)}`);
  } else {
    if (runOut.status !== 0 || parsed.verdict !== "ok") failures.push(`run failed: ${parsed.line}`);
    if (parsed.passed !== tests.length) failures.push(`passed ${parsed.passed} of ${tests.length} pinned: ${parsed.line}`);
    if (parsed.failed !== 0 || parsed.ignored !== 0) failures.push(`failed/ignored nonzero: ${parsed.line}`);
    if (runOut.status !== 0) {
      const failedTests = [...runOut.stdout.matchAll(/^test (\S+) \.\.\. FAILED$/gmu)].map((m) => m[1]);
      if (failedTests.length) failures.push(`failing tests: ${failedTests.join(", ")}`);
    }
  }
  return { name, failures, count: tests.length, listed: listed.size, summary: parsed?.line, seconds: runOut.seconds };
}

function checkSourcePin(pin) {
  const p = path.resolve(ROOT, pin.path);
  if (!fs.existsSync(p)) return record(false, `source pin ${pin.label}`, `${pin.path} missing`);
  const text = fs.readFileSync(p, "utf8");
  const hits = text.match(new RegExp(pin.pattern, "gmu")) ?? [];
  return record(
    hits.length === pin.expect,
    `source pin ${pin.label}`,
    `${pin.path} /${pin.pattern}/ hit ${hits.length} (expect ${pin.expect})`,
  );
}

let allOk = true;
console.log(`# ${population.script ?? populationPath} · unit ${population.unit ?? "?"} · ${population.families.length} families`);

if (mutation) {
  // Self-drill: the driver must refuse a planted absent name and an empty population.
  const first = population.families[0];
  const planted = checkFamily(first, { plantAbsent: true });
  allOk &= record(
    planted.failures.length > 0,
    `mutation: planted absent test name in ${first.name} is refused`,
    planted.failures[0] ?? "NOT refused",
  );
  const wrongPath = checkFamily(first, { plantWrongPath: true });
  allOk &= record(
    wrongPath.failures.some((f) => f.startsWith("not selectable")),
    `mutation: a pinned name the harness cannot list (source fn exists, wrong module path) is refused at --list`,
    wrongPath.failures[0] ?? "NOT refused",
  );
  const empty = checkFamily(first, { empty: true });
  allOk &= record(
    empty.failures.length > 0,
    `mutation: an empty population for ${first.name} is refused`,
    empty.failures[0] ?? "NOT refused",
  );
  process.exit(allOk ? 0 : 1);
}

for (const family of population.families) {
  const r = checkFamily(family);
  allOk &= record(
    r.failures.length === 0,
    `family ${r.name}: ${r.count} pinned tests selected and passed`,
    r.failures.length ? r.failures.join(" | ") : `${r.summary} (${r.seconds}s)`,
  );
}
for (const pin of population.source_pins ?? []) allOk &= checkSourcePin(pin);
for (const sup of population.supplementary ?? []) {
  const out = run(sup.argv);
  let ok = out.status === 0;
  let detail = ok ? `exit 0 (${out.seconds}s)` : `exit ${out.status}: ${(out.stderr || out.stdout).slice(-400)}`;
  if (ok && typeof sup.min_passed === "number") {
    // A whole-crate regression suite is not name-pinned, but it must not be empty either.
    const passed = [...out.stdout.matchAll(/^test result: ok\. (\d+) passed;/gmu)].reduce((n, m) => n + Number(m[1]), 0);
    ok = passed >= sup.min_passed;
    detail = ok ? `${passed} tests passed (${out.seconds}s)` : `only ${passed} tests passed (min ${sup.min_passed})`;
  }
  allOk &= record(ok, `supplementary ${sup.label}`, detail);
}

const total = population.families.reduce((n, f) => n + (f.tests?.length ?? 0), 0);
const passed = results.filter((r) => r.ok).length;
console.log(`${allOk ? "PASS" : "FAIL"} ${population.script ?? populationPath}: ${passed}/${results.length} checks; ${total} pinned tests`);
if (evidencePath) {
  const gitHead = run(["git", "rev-parse", "--short", "HEAD"]).stdout.trim();
  fs.mkdirSync(path.dirname(path.resolve(ROOT, evidencePath)), { recursive: true });
  fs.writeFileSync(
    path.resolve(ROOT, evidencePath),
    `${JSON.stringify({ evidence_format: "ioi.cargo_test_population_run.v1", population: populationPath, unit: population.unit, script: population.script, basis: gitHead, recorded_at: new Date().toISOString(), verdict: allOk ? "pass" : "fail", pinned_tests: total, results }, null, 2)}\n`,
  );
}
process.exit(allOk ? 0 : 1);
