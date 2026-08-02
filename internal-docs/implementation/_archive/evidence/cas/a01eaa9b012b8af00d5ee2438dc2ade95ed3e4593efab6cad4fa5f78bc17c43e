#!/usr/bin/env node
// MACHINE-OUTPUT CONTRACT FIXTURE.
//
//   node tools/test-json-stdout-purity.mjs
//
// WHY IT EXISTS
//
// `check-program.mjs --json` printed its bar table, its coverage line and its
// skip accounting to STDOUT before the JSON verdict. The output looked fine to
// a human and was unusable to a machine: `JSON.parse(stdout)` threw on the
// prefix, so every consumer had to hunt for the first `{`. A verdict a consumer
// has to hunt for is not a machine interface, and nothing in the estate would
// have said so — the defect was found by an owner reading output, which is the
// slowest detector available.
//
// THE CONTRACT THIS FIXTURE PINS, for every tool that advertises `--json`:
//
//   1. stdout parses AS A WHOLE. Not "starts with JSON", not "contains JSON":
//      JSON.parse over the entire stdout buffer, which fails on any prefix, any
//      suffix, and on two concatenated values.
//   2. The parsed value is a report envelope — check / result / error_count /
//      warn_count / skip_count / findings — so an empty stdout or a bare `null`
//      cannot pass as "parseable".
//   3. Narration is RELOCATED, not deleted. A tool that used to narrate must
//      still narrate, on stderr. Silencing a progress line would satisfy rule 1
//      and lose real information, so this fixture refuses it.
//
// AND THE FIXTURE CHECKS ITSELF. `assertSingleJson` is a pure function fed
// synthetic bad input on every run: a human prefix, a trailing line, two
// values, empty output, and a non-envelope value. A fixture whose refusals
// never fire is an empty function that reports PASS.
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { spawnSync } from "node:child_process";
import { ESTATE_ROOT, finding, progress, REPO_ROOT, report } from "./lib/estate.mjs";

// Subjects: every tool that advertises `--json` in its own source. The list is
// DERIVED, not maintained by hand, and cross-checked below — a new `--json`
// tool joins this fixture by existing, not by being remembered.
const DECLARED_SUBJECTS = [
  { rel: "tools/check-estate.mjs", args: ["--json"], narrates: false },
  { rel: "tools/check-attestations.mjs", args: ["--json"], narrates: true },
  { rel: "tools/check-no-competing-guides.mjs", args: ["--json"], narrates: true },
  { rel: "tools/check-canonical-estate.mjs", args: ["--json"], narrates: true },
  { rel: "tools/check-overlay-dispositions.mjs", args: ["--json"], narrates: true },
  { rel: "tools/check-successor-manifest.mjs", args: ["--json"], narrates: true },
  { rel: "tools/check-release-closure.mjs", args: ["--json"], narrates: false },
  { rel: "tools/check-claim-rung-closures.mjs", args: ["--json"], narrates: false },
  { rel: "tools/canon-impact.mjs", args: ["--check", "--json"], narrates: false },
  // check-program is the subject the defect was found in. It runs here over a
  // NAMED BAR SUBSET: the emission path under test is the same one a full audit
  // uses, and a subset keeps this fixture at milliseconds instead of re-running
  // the entire audit from inside the audit. `--bars` refuses to select this
  // fixture, so the recursion this would otherwise open is closed in the tool.
  {
    rel: "tools/check-program.mjs",
    args: ["--json", "--bars=attestations"],
    narrates: true,
  },
];

const ENVELOPE_KEYS = [
  "check",
  "result",
  "error_count",
  "warn_count",
  "skip_count",
  "findings",
];

// --- the pure core, so the refusals can be exercised on synthetic input ------

export function assertSingleJson(stdout) {
  const defects = [];
  if (stdout.length === 0) {
    defects.push("stdout is EMPTY; --json must emit exactly one JSON value");
    return defects;
  }
  let parsed;
  try {
    // Whole-buffer parse. This is the strictness: a prefix, a suffix, or a
    // second concatenated value all throw here rather than being tolerated by
    // a "find the first brace" reader.
    parsed = JSON.parse(stdout);
  } catch (error) {
    const head = JSON.stringify(stdout.slice(0, 120));
    defects.push(
      `stdout is not ONE parseable JSON value (${error.message}); it begins ${head}. Human progress belongs on stderr.`,
    );
    return defects;
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    defects.push(
      `stdout parsed to ${
        Array.isArray(parsed) ? "an array" : String(parsed)
      }, not a report envelope`,
    );
    return defects;
  }
  for (const key of ENVELOPE_KEYS) {
    if (parsed[key] === undefined) {
      defects.push(`report envelope is missing "${key}"`);
    }
  }
  if (!Array.isArray(parsed.findings)) {
    defects.push(`report envelope "findings" is not an array`);
  }
  if (!["PASS", "FAIL"].includes(parsed.result)) {
    defects.push(`report envelope "result" is ${JSON.stringify(parsed.result)}`);
  }
  return defects;
}

// Tools that advertise `--json` must be subjects here. Derived from source so
// the fixture cannot fall behind the toolbox.
export const SELF_REL = "tools/test-json-stdout-purity.mjs";

export function undeclaredJsonTools(readSource, listTools, declared) {
  const declaredSet = new Set(declared);
  const missing = [];
  for (const rel of listTools()) {
    // This file names the flag in order to PASS it to its subjects. It has no
    // --json mode of its own, and a fixture that reported itself as an
    // unchecked subject would be reporting its own subject list back at itself.
    if (rel === SELF_REL) continue;
    const src = readSource(rel);
    if (!/"--json"/u.test(src)) continue;
    if (!declaredSet.has(rel)) missing.push(rel);
  }
  return missing;
}

// --- self-test: every refusal above, against synthetic bad input ------------

// Set by selfTest() so the narration can never claim a refusal count the case
// table does not carry.
let SELF_TEST_ASSERTIONS = 0;

function selfTest() {
  const out = [];
  const good = JSON.stringify(
    {
      check: "x",
      result: "PASS",
      error_count: 0,
      warn_count: 0,
      skip_count: 0,
      findings: [],
    },
    null,
    2,
  );

  const cases = [
    ["human prefix", `bars 22 (16 green)\n${good}\n`],
    ["human suffix", `${good}\nno certification-relevant SKIP withheld\n`],
    ["two values", `${good}\n${good}\n`],
    ["empty stdout", ""],
    ["not an envelope", `"PASS"\n`],
    ["missing findings", JSON.stringify({ check: "x", result: "PASS" })],
    ["result not a verdict", JSON.stringify({ ...JSON.parse(good), result: "ok" })],
  ];
  SELF_TEST_ASSERTIONS = cases.length + 2; // + the positive case + the derivation

  for (const [name, sample] of cases) {
    if (assertSingleJson(sample).length === 0) {
      out.push(
        finding(
          "error",
          "self-test",
          `assertSingleJson ACCEPTED the "${name}" sample; this fixture has no teeth`,
        ),
      );
    }
  }
  // The positive case must pass, or the fixture refuses everything and proves
  // nothing.
  if (assertSingleJson(`${good}\n`).length !== 0) {
    out.push(
      finding(
        "error",
        "self-test",
        "assertSingleJson rejected well-formed output; a fixture that refuses the good case refuses nothing meaningfully",
      ),
    );
  }
  // And the derivation refuses to forget a tool.
  const missed = undeclaredJsonTools(
    () => `if (process.argv.includes("--json")) {}`,
    () => ["tools/pretend.mjs"],
    [],
  );
  if (missed.length === 0) {
    out.push(
      finding(
        "error",
        "self-test",
        "undeclaredJsonTools did not report a --json tool that is absent from the subject list",
      ),
    );
  }
  return out;
}

function main() {
  const findings = selfTest();

  const toolsDir = path.join(ESTATE_ROOT, "tools");
  const missing = undeclaredJsonTools(
    (rel) => fs.readFileSync(path.join(ESTATE_ROOT, rel), "utf8"),
    () =>
      fs
        .readdirSync(toolsDir)
        .filter((f) => f.endsWith(".mjs"))
        .map((f) => `tools/${f}`)
        .sort(),
    DECLARED_SUBJECTS.map((s) => s.rel),
  );
  for (const rel of missing) {
    findings.push(
      finding(
        "error",
        "subject-coverage",
        `${rel} advertises --json and is not a subject of this fixture; a machine-output contract that skips a tool is a contract that tool does not have`,
      ),
    );
  }

  for (const subject of DECLARED_SUBJECTS) {
    const run = spawnSync(
      "node",
      [path.join("internal-docs/implementation", subject.rel), ...subject.args],
      {
        cwd: REPO_ROOT,
        encoding: "utf8",
        // A truncated capture is indistinguishable from a malformed tail, and
        // the default cap silently truncates the larger reports. A fixture must
        // never report "not parseable" when the real fault was its own reader.
        maxBuffer: 256 * 1024 * 1024,
      },
    );
    if (run.error) {
      findings.push(
        finding("error", "subject-run", `${subject.rel}: ${run.error.message}`),
      );
      continue;
    }
    if (run.status === null) {
      findings.push(
        finding(
          "error",
          "subject-run",
          `${subject.rel} did not exit normally (signal ${run.signal}); its stdout cannot be trusted to be complete`,
        ),
      );
      continue;
    }
    for (const defect of assertSingleJson(run.stdout ?? "")) {
      findings.push(
        finding("error", "json-stdout-purity", `${subject.rel}: ${defect}`),
      );
    }
    if (subject.narrates && (run.stderr ?? "").trim().length === 0) {
      findings.push(
        finding(
          "error",
          "narration-lost",
          `${subject.rel} emitted nothing on stderr. The repair moves progress OFF stdout; deleting it instead would satisfy the parse and lose the information.`,
        ),
      );
    }
  }

  progress(
    `machine-output contract: ${DECLARED_SUBJECTS.length} --json subject(s) piped and whole-buffer parsed; ${SELF_TEST_ASSERTIONS} predeclared assertions self-tested`,
  );
  process.exit(report("test-json-stdout-purity", findings));
}

if (import.meta.url === `file://${process.argv[1]}`) main();
