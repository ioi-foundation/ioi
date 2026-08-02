#!/usr/bin/env node
// Enforced boundary for the `agentgres://` ref scheme (owner ruling 2026-08-01).
//
// DEFECT: nothing guarantees an `agentgres://` ref was issued by Agentgres — the
// scheme is minted by string interpolation at dozens of consumer sites, so any
// consumer, receipt chain, replay, export, or audit treating the scheme as
// evidence of canonical admission is trusting string formatting. Same class as
// the pre-a5d88f3da auth fail-open: a convention that reads as a guarantee,
// enforced nowhere, relied on everywhere downstream.
//
// TERMINAL STATE: `agentgres://` refs are minted only by crates/agentgres or by
// a single helper that Agentgres backs; this check then fails on ANY
// construction site elsewhere.
//
// RATCHET (current state): every existing construction site is pinned in
// scripts/agentgres-ref-minting-baseline.v1.json. This check FAILS when
//   - a construction site appears in a file not in the baseline, or
//   - a baselined file's construction-site count EXCEEDS its pin.
// Counts below the pin are reported and require a deliberate baseline shrink
// (--write-baseline) in the same change — the pin is monotone: it only goes
// down. New sites therefore cannot be introduced, and migrated sites cannot
// silently regress. Interim self-minted planes (the runtime-events spine et
// al.) remain pinned debt tied to m5-agentgres-durable-event-subscription-
// successor; each re-homed family shrinks its pin toward zero.
//
//   node scripts/check-agentgres-ref-minting.mjs [--write-baseline] [--self-test]
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const REPO = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const BASELINE_PATH = path.join(REPO, "scripts", "agentgres-ref-minting-baseline.v1.json");

// Files allowed to construct the scheme in the terminal state.
const TERMINAL_ALLOWED = [/^crates\/agentgres\//];

// Scanned populations. Generated projections are excluded (they own nothing and
// are regenerated from the registry); verifier scripts are excluded (they probe
// and assert on refs, and adding a fixture ref there is not minting daemon truth).
const SCAN_ROOTS = [
  { root: "crates", exts: [".rs"] },
  { root: "apps/hypervisor/scripts", exts: [".mjs", ".js"] },
  { root: "scripts", exts: [".mjs", ".js"] },
];
const EXCLUDED = [
  /^crates\/types\/src\/app\/generated\//,
  /node_modules\//,
  /\/target\//,
  /^apps\/hypervisor\/scripts\/verify-/,
  /^scripts\/check-agentgres-ref-minting\.mjs$/,
  /^apps\/hypervisor\/product-ui\//,
];

// A CONSTRUCTION site interpolates around the scheme; a plain complete literal
// (doc comment, fixture value, starts_with comparison) is reference, not minting.
const RUST_CONSTRUCTION = [
  /format!\s*\(\s*"[^"]*agentgres:\/\/[^"]*\{/u, // format! with interpolation after the scheme
  /"agentgres:\/\/[^"]*"\s*\.to_string\(\)\s*\+/u,
  /String::from\s*\(\s*"agentgres:\/\/[^"]*"\s*\)\s*\+/u,
  /push_str\s*\(\s*"agentgres:\/\/[^"]*"/u,
  /concat!\s*\(\s*"[^"]*agentgres:\/\//u,
];
const JS_CONSTRUCTION = [
  /`[^`]*agentgres:\/\/[^`]*\$\{/u, // template literal with interpolation
  /"agentgres:\/\/[^"]*"\s*\+/u,
  /'agentgres:\/\/[^']*'\s*\+/u,
  /\+\s*"agentgres:\/\/[^"]*"/u,
  /\+\s*'agentgres:\/\/[^']*'/u,
];

function walk(dir, exts, out) {
  if (!fs.existsSync(dir)) return out;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const abs = path.join(dir, entry.name);
    const rel = path.relative(REPO, abs).replaceAll(path.sep, "/");
    if (EXCLUDED.some((pattern) => pattern.test(rel + (entry.isDirectory() ? "/" : "")))) continue;
    if (entry.isDirectory()) walk(abs, exts, out);
    else if (exts.some((ext) => entry.name.endsWith(ext))) out.push({ abs, rel });
  }
  return out;
}

export function constructionSites(rel, contents) {
  const patterns = rel.endsWith(".rs") ? RUST_CONSTRUCTION : JS_CONSTRUCTION;
  const sites = [];
  const lines = contents.split("\n");
  lines.forEach((line, index) => {
    if (!line.includes("agentgres://")) return;
    const trimmed = line.trimStart();
    if (trimmed.startsWith("//") || trimmed.startsWith("*")) return; // comment/doc reference
    if (patterns.some((pattern) => pattern.test(line))) {
      sites.push({ line: index + 1, text: line.trim().slice(0, 160) });
    }
  });
  return sites;
}

function scan() {
  const files = [];
  for (const { root, exts } of SCAN_ROOTS) walk(path.join(REPO, root), exts, files);
  const found = new Map();
  for (const { abs, rel } of files) {
    const sites = constructionSites(rel, fs.readFileSync(abs, "utf8"));
    if (sites.length > 0) found.set(rel, sites);
  }
  return found;
}

function selfTest() {
  const failures = [];
  const mustCatch = [
    ["x.rs", '        let r = format!("agentgres://runtime-events/{stream}/head/{seq}");'],
    ["x.rs", '    out.push_str("agentgres://forged/");'],
    ["x.mjs", "  const ref = `agentgres://automation-proposal/${pid}`;"],
    ['x.mjs', '  const ref = "agentgres://" + kind + "/" + id;'],
  ];
  const mustPass = [
    ["x.rs", '// doc: refs look like agentgres://runtime-events/<stream>'],
    ["x.rs", '    if ref.starts_with("agentgres://runtime-events/") {'],
    ["x.rs", '        "operation_ref": "agentgres://operation/fixed/literal",'],
    ["x.mjs", '  assert(ref === "agentgres://operation/fixed/literal");'],
  ];
  for (const [name, line] of mustCatch) {
    if (constructionSites(name, line).length !== 1) failures.push(`must-catch missed: ${line.trim()}`);
  }
  for (const [name, line] of mustPass) {
    if (constructionSites(name, line).length !== 0) failures.push(`false positive: ${line.trim()}`);
  }
  return failures;
}

function main() {
  const writeBaseline = process.argv.includes("--write-baseline");
  const selfTestFailures = selfTest();
  if (selfTestFailures.length > 0) {
    for (const failure of selfTestFailures) console.error(`SELF-TEST FAIL: ${failure}`);
    process.exit(1);
  }

  const found = scan();
  // Terminal-allowed files (the substrate's own constructors) are the
  // boundary, not debt: they never enter the pinned manifest.
  const manifest = Object.fromEntries(
    [...found.entries()]
      .filter(([rel]) => !TERMINAL_ALLOWED.some((pattern) => pattern.test(rel)))
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([rel, sites]) => [rel, sites.length]),
  );

  if (writeBaseline) {
    fs.writeFileSync(
      BASELINE_PATH,
      `${JSON.stringify(
        {
          evidence_format: "ioi.checks.agentgres_ref_minting_baseline.v1",
          role: "Pinned ratchet of agentgres:// construction sites. Counts only go DOWN; the terminal state is crates/agentgres only. Interim self-minted planes are debt owned by m5-agentgres-durable-event-subscription-successor.",
          terminal_allowed: TERMINAL_ALLOWED.map(String),
          files: manifest,
        },
        null,
        2,
      )}\n`,
    );
    console.log(`wrote baseline: ${Object.keys(manifest).length} files, ${Object.values(manifest).reduce((a, b) => a + b, 0)} construction sites`);
    return;
  }

  if (!fs.existsSync(BASELINE_PATH)) {
    console.error("FAIL: baseline missing — run --write-baseline once and commit it");
    process.exit(1);
  }
  const baseline = JSON.parse(fs.readFileSync(BASELINE_PATH, "utf8")).files ?? {};
  const errors = [];
  const shrunk = [];
  for (const [rel, count] of Object.entries(manifest)) {
    const terminal = TERMINAL_ALLOWED.some((pattern) => pattern.test(rel));
    if (terminal) continue;
    const pinned = baseline[rel];
    if (pinned === undefined) {
      errors.push(`NEW minting file outside the boundary: ${rel} (${count} site${count === 1 ? "" : "s"})`);
      for (const site of found.get(rel) ?? []) errors.push(`    ${rel}:${site.line}: ${site.text}`);
    } else if (count > pinned) {
      errors.push(`RATCHET VIOLATION: ${rel} has ${count} construction sites, pin is ${pinned}`);
    } else if (count < pinned) {
      shrunk.push(`${rel}: ${pinned} -> ${count}`);
    }
  }
  for (const rel of Object.keys(baseline)) {
    if (!(rel in manifest)) shrunk.push(`${rel}: ${baseline[rel]} -> 0 (gone)`);
  }
  if (shrunk.length > 0) {
    errors.push(
      `BASELINE STALE (progress must be pinned deliberately — rerun --write-baseline in this change): ${shrunk.join("; ")}`,
    );
  }
  if (errors.length > 0) {
    for (const error of errors) console.error(`FAIL: ${error}`);
    process.exit(1);
  }
  const total = Object.values(manifest).reduce((a, b) => a + b, 0);
  console.log(
    `check-agentgres-ref-minting: PASS (self-test 8/8; ${Object.keys(manifest).length} pinned files, ${total} construction sites, 0 new, 0 ratchet violations)`,
  );
}

main();
