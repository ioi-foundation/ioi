// The ioi.program.literal_exit.v1 retained-log contract, shared by the
// producer (writeLiteralExitLog), the checker (check-literal-exit-contract),
// the certification gate (transition.mjs), and stage certification
// (certify-stage.mjs).
//
// A retained log is content-bound evidence: it names the artifact it
// certifies and pins that artifact's digest, carries exactly one
// <BAR>_EXIT=<code> literal line, and states its own nonclaim. A task or
// process exit code is never the proof carrier.
//
// This module is the SINGLE owner of the contract. It was extracted after a
// `verified` transition was admitted against an exit artifact that was
// free-form prose: the checker knew the contract, and the transition did not
// ask it. Every admitting caller now asks the same validator, and every
// rejection carries a stable refusal NAME so a refusal can be asserted in a
// test and cited in a record instead of being matched on prose.
import fs from "node:fs";
import path from "node:path";
import { REPO_ROOT, sha256File } from "./estate.mjs";

export const FORMAT = "ioi.program.literal_exit.v1";
export const LITERAL_LINE = /^([A-Z0-9_]+_EXIT)=(\d+)$/;

export function writeLiteralExitLog({
  bar,
  literal,
  artifactRel,
  nonclaim,
  outRel,
}) {
  const match = LITERAL_LINE.exec(literal);
  if (!match) throw new Error(`not a literal-exit line: ${literal}`);
  const artifactAbs = path.join(REPO_ROOT, artifactRel);
  if (!fs.existsSync(artifactAbs)) {
    throw new Error(`artifact does not exist: ${artifactRel}`);
  }
  const lines = [
    `IOI_LITERAL_EXIT_LOG_FORMAT=${FORMAT}`,
    `BAR=${bar}`,
    `ARTIFACT=${artifactRel}`,
    `ARTIFACT_SHA256=${sha256File(artifactAbs)}`,
    literal,
    `NONCLAIM=${nonclaim}`,
  ];
  const outAbs = path.join(REPO_ROOT, outRel);
  fs.mkdirSync(path.dirname(outAbs), { recursive: true });
  fs.writeFileSync(outAbs, `${lines.join("\n")}\n`);
  return outAbs;
}

// Validates retained-log TEXT against the contract. Returns a list of defect
// strings; empty means valid. `expectLiteral` (optional) additionally pins the
// exact successful literal the caller requires.
export function validateLiteralExitText(
  text,
  { expectLiteral = null, repoRoot = REPO_ROOT } = {},
) {
  const defects = [];
  if (!text.endsWith("\n")) defects.push("truncated: no trailing newline");
  const lines = text.split("\n").slice(0, -1);
  if (lines.length === 0) return ["malformed: empty log"];
  if (lines[0] !== `IOI_LITERAL_EXIT_LOG_FORMAT=${FORMAT}`) {
    defects.push("malformed: first line is not the format declaration");
  }
  const keys = new Map();
  const literals = [];
  for (const line of lines) {
    const eq = line.indexOf("=");
    if (eq <= 0) {
      defects.push(`malformed: not a KEY=VALUE line: ${JSON.stringify(line)}`);
      continue;
    }
    const key = line.slice(0, eq);
    keys.set(key, (keys.get(key) ?? 0) + 1);
    const lit = LITERAL_LINE.exec(line);
    if (lit) literals.push({ key: lit[1], code: Number(lit[2]) });
  }
  for (const [key, count] of keys) {
    if (count > 1) defects.push(`duplicate key: ${key}`);
  }
  for (const key of ["BAR", "ARTIFACT", "ARTIFACT_SHA256", "NONCLAIM"]) {
    if (!keys.has(key)) defects.push(`missing key: ${key}`);
  }
  if (literals.length === 0) {
    defects.push("missing literal: no <BAR>_EXIT=<code> line");
  } else if (literals.length > 1) {
    const distinct = new Set(literals.map((l) => l.key));
    defects.push(
      distinct.size > 1
        ? `conflicting literals: ${[...distinct].sort().join(", ")}`
        : `duplicate literal: ${literals[0].key}`,
    );
  } else if (literals[0].code !== 0) {
    defects.push(
      `non-success literal: ${literals[0].key}=${literals[0].code}`,
    );
  }
  if (expectLiteral && literals.length === 1) {
    const line = `${literals[0].key}=${literals[0].code}`;
    if (line !== expectLiteral) {
      defects.push(`literal mismatch: expected ${expectLiteral}, found ${line}`);
    }
  }
  // Content binding: the artifact must resolve inside the repo and its digest
  // must match. A log whose artifact rotted is stale evidence, not evidence.
  const artifactLine = lines.find((l) => l.startsWith("ARTIFACT="));
  const shaLine = lines.find((l) => l.startsWith("ARTIFACT_SHA256="));
  if (artifactLine && shaLine) {
    const rel = artifactLine.slice("ARTIFACT=".length);
    const abs = path.resolve(repoRoot, rel);
    const inside = abs === repoRoot || abs.startsWith(`${repoRoot}${path.sep}`);
    if (!inside) {
      defects.push(`malformed: artifact escapes the repository: ${rel}`);
    } else if (!fs.existsSync(abs)) {
      defects.push(`stale: artifact does not exist: ${rel}`);
    } else {
      const actual = sha256File(abs);
      const declared = shaLine.slice("ARTIFACT_SHA256=".length);
      if (actual !== declared) {
        defects.push(
          `stale: artifact digest mismatch for ${rel}: declared ${declared}, actual ${actual}`,
        );
      }
    }
  }
  return defects;
}

export function validateLiteralExitFile(rel, opts = {}) {
  const repoRoot = opts.repoRoot ?? REPO_ROOT;
  const abs = path.join(repoRoot, rel);
  if (!fs.existsSync(abs)) return [`missing: ${rel}`];
  return validateLiteralExitText(fs.readFileSync(abs, "utf8"), opts);
}

// --- named refusals -------------------------------------------------------
//
// A defect string is for a reader. A refusal NAME is for a machine: it is what
// a caller reports, what a test asserts, and what a record cites. The table is
// ordered, longest-discriminating prefix first, and is closed: an unmapped
// defect still refuses, under `proof-literal-log-nonconforming`, because a
// defect nobody named is not a defect nobody has.
const REFUSAL_TABLE = [
  ["truncated", "proof-literal-log-truncated"],
  ["malformed", "proof-literal-log-malformed"],
  ["missing key", "proof-literal-log-missing-key"],
  ["duplicate key", "proof-literal-log-duplicate-key"],
  ["missing literal", "proof-literal-log-missing-literal"],
  ["duplicate literal", "proof-literal-log-duplicate-literal"],
  ["conflicting literals", "proof-literal-log-conflicting-literals"],
  ["non-success literal", "proof-literal-log-non-success"],
  ["literal mismatch", "proof-literal-log-literal-mismatch"],
  ["stale", "proof-literal-log-stale"],
  ["missing: ", "proof-literal-log-absent"],
];

export const REFUSAL_NAMES = [
  ...new Set(REFUSAL_TABLE.map(([, name]) => name)),
  "proof-literal-log-nonconforming",
];

export function refusalFor(defect) {
  for (const [prefix, name] of REFUSAL_TABLE) {
    if (defect.startsWith(prefix)) return name;
  }
  return "proof-literal-log-nonconforming";
}

// The one entry point an admitting caller uses. Returns a list of
// {check, message} refusals; empty means the artifact IS a conforming
// ioi.program.literal_exit.v1 retained log. `expectLiteral` additionally pins
// the exact successful literal the caller requires, so a conforming log that
// certifies a DIFFERENT bar cannot be presented as this one's proof.
export function refuseUnlessConformingLiteralExitLog(
  artifactRel,
  { expectLiteral = null, repoRoot = REPO_ROOT } = {},
) {
  const defects = validateLiteralExitFile(artifactRel, {
    expectLiteral,
    repoRoot,
  });
  return defects.map((defect) => ({
    check: refusalFor(defect),
    message:
      `${artifactRel} is not a conforming ${FORMAT} retained log: ${defect}`,
    defect,
  }));
}
