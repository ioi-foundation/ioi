#!/usr/bin/env node
// Generates docs/conformance/claims-table.v1.md — the public maturity/claims
// surface — from the status-bearing tables in docs/conformance/README.md.
//
// The ruled adoption plan forbids hand-written public maturity tables: the
// public claims surface must be a PROJECTION of the conformance ladder, never a
// parallel hand-maintained copy that can drift from it. This generator parses
// the ladder's two status-bearing tables (§ Conformance States, which owns the
// status vocabulary, and § Claim Coverage Index, which carries every claim row)
// and emits the grouped claims table with per-status counts.
//
// Fail-closed, never skip-silent: if the table shape drifts (missing header or
// separator, wrong cell count), the status vocabulary drifts in either
// direction from the pin below, a State cell fails to parse, a status-bearing
// cell appears in a table this generator does not parse, or the claim-row count
// falls below the pinned minimum, the generator exits nonzero with a loud
// message and emits NO partial output.
//
//   node scripts/generate-conformance-claims.mjs          # write the projection
//   node scripts/generate-conformance-claims.mjs --check  # regenerate in-memory;
//                                                         # fail unless the committed
//                                                         # file matches byte-exact
//                                                         # (the check:architecture-contracts idiom)

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SOURCE = "docs/conformance/README.md";
const TARGET = "docs/conformance/claims-table.v1.md";

// The ruled conformance-state vocabulary, pinned in ladder order. The source's
// § Conformance States table is parsed and must match this pin EXACTLY (same
// states, same order): vocabulary is a ruled surface, so adding, removing, or
// reordering a state is a deliberate two-file change, never a silent one.
const EXPECTED_STATES = [
  "active_invariant",
  "target_runnable",
  "target_defined",
  "named_target",
  "out_of_scope_nonclaim",
  "deprecated_stub",
];

// Fewer parsed claim rows than this means claims vanished from the coverage
// index (or the parser went blind). The public claims surface never shrinks
// silently. 35 rows at pin time (2026-08-12).
const MINIMUM_CLAIM_ROWS = 30;

const args = process.argv.slice(2);
let mode;
if (args.length === 0) mode = "write";
else if (args.length === 1 && args[0] === "--check") mode = "check";
else {
  console.error(
    `Unsupported invocation: ${args.join(" ")}. Supported invocations are exactly no arguments (write) or --check.`,
  );
  process.exit(2);
}

const failures = [];
const fail = (message) => failures.push(message);
function abortOnFailures() {
  if (failures.length === 0) return;
  for (const failure of failures) console.error(`${SOURCE}: ${failure}`);
  console.error(
    `\n${failures.length} conformance-claims generation failure(s) — the source drifted from the parsed shape; NO output was emitted. Fix ${SOURCE} or update this generator deliberately.`,
  );
  process.exit(1);
}

const sourcePath = path.join(root, SOURCE);
if (!fs.existsSync(sourcePath)) {
  fail("source file does not exist");
  abortOnFailures();
}
const source = fs.readFileSync(sourcePath, "utf8");
const lines = source.split("\n");

const isRow = (line) => /^\|.*\|\s*$/u.test(line);
const isSeparator = (line) => /^\|(?:\s*:?-{3,}:?\s*\|)+\s*$/u.test(line);
const cellsOf = (line) =>
  line
    .replace(/^\|/u, "")
    .replace(/\|\s*$/u, "")
    .split("|")
    .map((cell) => cell.trim());

// Locates exactly one table by its exact header cells, requires the separator
// row, and collects contiguous data rows. Every shape defect is a failure.
function findTable(headerCells, section) {
  const headerLines = [];
  for (let i = 0; i < lines.length; i += 1) {
    if (!isRow(lines[i])) continue;
    const cells = cellsOf(lines[i]);
    if (cells.length === headerCells.length && cells.every((cell, j) => cell === headerCells[j])) {
      headerLines.push(i);
    }
  }
  if (headerLines.length !== 1) {
    fail(
      `expected exactly one \`| ${headerCells.join(" | ")} |\` table header (${section}) — found ${headerLines.length}; table shape drifted`,
    );
    return null;
  }
  const headerAt = headerLines[0];
  if (!isSeparator(lines[headerAt + 1] ?? "")) {
    fail(
      `the ${section} table header at line ${headerAt + 1} is not followed by a \`| --- |\` separator row — table shape drifted`,
    );
    return null;
  }
  const rows = [];
  for (let i = headerAt + 2; i < lines.length && isRow(lines[i]); i += 1) {
    const cells = cellsOf(lines[i]);
    if (cells.length !== headerCells.length) {
      fail(
        `${section} row at line ${i + 1} has ${cells.length} cells, expected ${headerCells.length} — refusing to guess a row shape: ${lines[i]}`,
      );
      continue;
    }
    rows.push({ line: i, cells });
  }
  return { headerAt, rows };
}

// Line numbers consumed as status-bearing rows, for the closed-world scan below.
const consumed = new Set();

// --- § Conformance States: the status vocabulary and its meanings. -----------
const statesTable = findTable(["State", "Meaning"], "Conformance States");
abortOnFailures();
const meanings = new Map();
for (const { line, cells } of statesTable.rows) {
  const match = cells[0].match(/^`([a-z0-9_]+)`$/u);
  if (!match) {
    fail(`Conformance States row at line ${line + 1} does not open with one backticked state: ${cells[0]}`);
    continue;
  }
  if (meanings.has(match[1])) {
    fail(`duplicate state \`${match[1]}\` in the Conformance States table`);
    continue;
  }
  meanings.set(match[1], cells[1]);
  consumed.add(line);
}
const derivedStates = [...meanings.keys()];
if (derivedStates.join(" ") !== EXPECTED_STATES.join(" ")) {
  fail(
    `status vocabulary drifted — source declares [${derivedStates.join(", ")}] but this generator pins [${EXPECTED_STATES.join(", ")}]; a vocabulary change updates BOTH in one deliberate cut`,
  );
}
abortOnFailures();

// --- § Claim Coverage Index: every claim row. --------------------------------
const claimsTable = findTable(["Canon claim", "Target", "State"], "Claim Coverage Index");
abortOnFailures();
const claims = [];
for (const { line, cells } of claimsTable.rows) {
  const [claim, target, stateCell] = cells;
  const match = stateCell.match(/^`([a-z0-9_]+)`(?:\s+\((.+)\))?$/u);
  if (!match) {
    fail(
      `Claim Coverage Index row at line ${line + 1} has an unparseable State cell — expected \`state\` plus an optional parenthetical note, got: ${stateCell}`,
    );
    continue;
  }
  if (!EXPECTED_STATES.includes(match[1])) {
    fail(`Claim Coverage Index row at line ${line + 1} carries state \`${match[1]}\`, outside the pinned vocabulary`);
    continue;
  }
  if (claim === "" || target === "") {
    fail(`Claim Coverage Index row at line ${line + 1} has an empty claim or target cell`);
    continue;
  }
  claims.push({ claim, target, state: match[1], note: match[2] ?? "" });
  consumed.add(line);
}
abortOnFailures();
if (claims.length < MINIMUM_CLAIM_ROWS) {
  fail(
    `only ${claims.length} claim rows parsed — the pinned minimum is ${MINIMUM_CLAIM_ROWS}; claim rows do not vanish silently`,
  );
}

// --- Closed world: no status-bearing table cell outside the parsed tables. ---
// A NEW table that starts carrying backticked vocabulary states would otherwise
// ship claims this projection never sees.
for (let i = 0; i < lines.length; i += 1) {
  if (!isRow(lines[i]) || isSeparator(lines[i]) || consumed.has(i)) continue;
  for (const cell of cellsOf(lines[i])) {
    const match = cell.match(/^`([a-z0-9_]+)`/u);
    if (match && EXPECTED_STATES.includes(match[1])) {
      fail(
        `line ${i + 1} carries a status-bearing table cell (\`${match[1]}\`) outside the parsed tables — teach this generator about that table before it ships claims`,
      );
    }
  }
}

// The projection inherits the source header's alignment date, so the emitted
// bytes stay a pure function of the source (no wall-clock timestamps).
const alignmentPass = lines
  .slice(0, 20)
  .join("\n")
  .match(/^Last alignment pass:\s*(.+?)\.?\s*$/mu)?.[1]
  ?.trim();
if (!alignmentPass) {
  fail("source header lacks `Last alignment pass:` in its first 20 lines — the projection cannot inherit an alignment date");
}
abortOnFailures();

// --- Render. -----------------------------------------------------------------
const grouped = new Map(EXPECTED_STATES.map((state) => [state, []]));
for (const claim of claims) grouped.get(claim.state).push(claim);
const countOf = (state) => grouped.get(state).length;

const out = [];
out.push("# Conformance Claims Table");
out.push("");
out.push("Status: generated projection; do not edit by hand.");
out.push(
  "Canonical owner: [`README.md`](./README.md) — this file is a generated projection of its status-bearing tables (§ Conformance States, § Claim Coverage Index) and owns no claim of its own.",
);
out.push("Supersedes: any hand-written public maturity or claims table.");
out.push("Superseded by: none.");
out.push(`Last alignment pass: ${alignmentPass} (inherited from the source header).`);
out.push("");
out.push("> **GENERATED — edit `docs/conformance/README.md` and regenerate.**");
out.push("> Generator: `scripts/generate-conformance-claims.mjs`");
out.push("> (`npm run generate:conformance-claims`). Source: `docs/conformance/README.md`.");
out.push("> Freshness is CI-gated by `npm run check:conformance-claims`, which fails");
out.push("> unless this file matches a fresh regeneration byte-for-byte.");
out.push("");
out.push("## Claim counts");
out.push("");
out.push("| State | Claims |");
out.push("| --- | ---: |");
for (const state of EXPECTED_STATES) {
  out.push(`| \`${state}\` | ${countOf(state)} |`);
}
out.push(`| **Total** | **${claims.length}** |`);
for (const state of EXPECTED_STATES) {
  out.push("");
  out.push(`## \`${state}\` (${countOf(state)})`);
  out.push("");
  out.push(meanings.get(state));
  out.push("");
  if (countOf(state) === 0) {
    out.push("No claim in the coverage index currently carries this state.");
    continue;
  }
  out.push("| Canon claim | Target | Honesty note |");
  out.push("| --- | --- | --- |");
  for (const { claim, target, note } of grouped.get(state)) {
    out.push(`| ${claim} | ${target} | ${note === "" ? "—" : note} |`);
  }
}
out.push("");
const rendered = out.join("\n");

const summary = `${claims.length} claims (${EXPECTED_STATES.map((state) => `${state} ${countOf(state)}`).join(", ")})`;
const targetPath = path.join(root, TARGET);

if (mode === "check") {
  if (!fs.existsSync(targetPath) || fs.readFileSync(targetPath, "utf8") !== rendered) {
    console.error(`Conformance claims projection is out of date: ${TARGET} does not match a fresh regeneration from ${SOURCE}.`);
    console.error("Run npm run generate:conformance-claims and commit the result.");
    process.exit(1);
  }
  console.log(`Conformance claims projection is up to date — ${summary}.`);
} else {
  fs.writeFileSync(targetPath, rendered);
  console.log(`Generated ${TARGET} — ${summary}.`);
}
