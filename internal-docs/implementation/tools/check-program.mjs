#!/usr/bin/env node
// LANE 3 — full program / release audit.
//
//   node tools/check-program.mjs [--json]
//
// Everything, once, at a program or release boundary. Not after every edit.
// Each bar runs exactly once; nothing is recomputed by a second bar, which is
// what the previous single acceptance bar did for roughly half its wall clock.
//
// --- WHAT THIS FILE GOT WRONG, AND WHAT CHANGED --------------------------
//
// On 2026-07-29 this bar list reported PASS while four checkers in the same
// directory were failing: the retained-log contract (95 errors), the claim
// lock (4 stale sources), the invariant census, and route-census coherence.
// None of them were in BARS. The audit was not wrong about what it ran; it was
// wrong about what it implied, because a hand-maintained list of bars is a
// claim about coverage that nothing checked.
//
// Two changes, both structural:
//
//   1. The list is longer, and it is expected to be RED. A release audit that
//      cannot go red is not an audit.
//   2. BAR COVERAGE IS ITSELF A BAR. Every checker in tools/ must be in BARS or
//      be explicitly declared not-a-bar with a reason. A checker that is
//      neither is reported by name as `unlisted-checker`, so the next omission
//      announces itself instead of waiting to be discovered by an owner.
//
// And the SKIP accounting is honest: SKIPs are classified against
// program/skip-taxonomy.v1.json into certification-relevant and benign, with
// the fail-closed default that an unclassified SKIP is certification-relevant.
// A certification-relevant SKIP is an ERROR of this audit — not because the
// underlying bar failed, but because the program cannot be called certifiable
// while a verification is withheld. "PASS with 221 SKIPs" is not available as
// an outcome any more.
//
// --- MACHINE-OUTPUT CONTRACT (repaired 2026-07-29, owner-found defect) ------
//
// `--json` MUST put exactly one parseable JSON value on stdout. This file used
// to print its bar table, its coverage line, and its skip accounting to stdout
// FIRST, so `check-program.mjs --json | jq` failed on the prefix and every
// machine consumer had to guess where the JSON began. Guessing where a verdict
// begins is not a machine interface.
//
// The repair is structural rather than conditional: narration goes through
// lib/estate.mjs `progress()`, which writes to stderr in EVERY mode. There is
// no `if (json)` around it to forget. tools/test-json-stdout-purity.mjs pipes
// `--json` and strict-parses the whole of stdout, so a reintroduced prefix or
// suffix fails a bar instead of surprising a consumer.
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { execFileSync } from "node:child_process";
import {
  ESTATE_ROOT,
  finding,
  progress,
  readJson,
  REPO_ROOT,
  report,
} from "./lib/estate.mjs";

const BARS = [
  { id: "estate-structure", cmd: ["tools/check-estate.mjs"] },
  // --- work-item-contract REPLACED work-item-shape as the bar on 2026-07-29
  // under owner ruling. The two bars ran the same shape census twice: the
  // contract bar imports validateRecord/applyWaivers from the shape bar and
  // calls them on every record, then adds the published-schema validation, the
  // reference lint, and the fail-closed bad-fixture self-test on top. Running
  // both spent the census twice for one census worth of coverage.
  { id: "work-item-contract", cmd: ["tools/check-work-item-contract.mjs"] },
  { id: "canon-impact", cmd: ["tools/canon-impact.mjs", "--check"] },
  { id: "canon-snapshots", cmd: ["tools/refresh-canon-snapshots.mjs"] },
  { id: "status-authority", cmd: ["tools/reconcile-status.mjs"] },
  { id: "orientation-freshness", cmd: ["tools/generate-now.mjs", "--check"] },
  { id: "canon-gap-projection", cmd: ["tools/generate-canon-gap-projection.mjs", "--check"] },
  { id: "no-competing-guides", cmd: ["tools/check-no-competing-guides.mjs"] },
  { id: "attestations", cmd: ["tools/check-attestations.mjs"] },
  // --- added 2026-07-29 under owner ruling. Every one of these already
  // existed and was already runnable; omitting them is what made PASS mean
  // less than it appeared to.
  { id: "literal-exits", cmd: ["tools/check-literal-exit-contract.mjs"] },
  { id: "claim-lock", cmd: ["tools/check-claim-lock.mjs"] },
  { id: "claim-rung-closures", cmd: ["tools/check-claim-rung-closures.mjs"] },
  { id: "invariant-census", cmd: ["tools/invariant-census.mjs", "--check"] },
  { id: "route-census", cmd: ["tools/check-route-census-maintenance.mjs"] },
  { id: "canon-owner-coverage", cmd: ["tools/check-canon-owner-coverage.mjs"] },
  { id: "acceptance-integrity", cmd: ["tools/check-acceptance-integrity.mjs"] },
  // --- admitted 2026-07-29 by explicit owner ruling. Both guard certified
  // claims and are consumed by verified M0 records, so neither qualifies
  // for a not-a-bar exclusion. Both are expected RED until their
  // successor evidence reproduces; do not refresh either predecessor
  // artifact in place to clear them.
  { id: "source-dispositions", cmd: ["tools/check-source-dispositions.mjs"] },
  { id: "enum-member-census", cmd: ["tools/enum-member-census.mjs", "--check"] },
  // --- added 2026-07-29 under owner rulings 1 and 2. There was no bar at all
  // over WHICH copy of this gitignored tree is authoritative, over byte
  // aliasing between worktrees, over immutability of stored evidence, or over
  // what a canon baseline is permitted to bind. A baseline that binds the
  // ambient filesystem, and a hard link that lets another tree write into this
  // one, are both invisible to every other bar in this list.
  { id: "canonical-estate", cmd: ["tools/check-canonical-estate.mjs"] },
  // --- added 2026-07-29 under the owner's attribution-closure ruling. The
  // canonical-estate bar answers whether the overlay members ARE what the
  // manifest says; it deliberately does not answer who is ACCOUNTABLE for them,
  // and its owning record puts curating them out of scope. That second question
  // had no bar at all: 194 of 220 bound members carried no owner, and the first
  // attempt to give them one let the enumeration attribute to itself.
  {
    id: "overlay-dispositions",
    cmd: ["tools/check-overlay-dispositions.mjs"],
  },
  // --- added 2026-07-29 under the owner's manifest-succession ruling. The
  // frozen manifest's governing rule told a retirement to append to the frozen
  // manifest, which is an edit into a body this estate freezes; two identities
  // were tombstoned in the disposition ledger with nothing carrying them
  // forward, and no bar anywhere could see that a version succession had
  // dropped an identity, re-digested one, resurrected a retired one, or lost
  // the retired bytes.
  {
    id: "successor-manifest",
    cmd: ["tools/check-successor-manifest.mjs"],
  },
  {
    id: "open-successor-holds",
    cmd: ["tools/check-open-successor-holds.mjs", "--check"],
  },
  // --- admitted 2026-07-29 by explicit owner ruling. It guards where an
  // adjacent canon document is permitted to live, which is a placement claim a
  // verified M0 record already made; a checker for a made claim is a bar.
  {
    id: "adjacent-canon-placement",
    cmd: ["tools/check-adjacent-canon-placement.mjs"],
  },
  // The authoritative conjunction that used to exist only across one hold
  // file and several owner messages. It does not recurse into check-program;
  // this outer bar owns the top-level PASS and the closure bar owns the exact
  // successor, generation, hold, baseline, and independent-review inputs.
  {
    id: "release-closure",
    cmd: ["tools/check-release-closure.mjs"],
  },
  // --- fixtures: the bars that keep the bars honest
  { id: "transition-fixture", cmd: ["tools/test-transition.mjs"] },
  {
    id: "aggregate-verification-binding-fixture",
    cmd: ["tools/test-aggregate-verification-binding.mjs"],
  },
  {
    id: "stage-certification-cache-fixture",
    cmd: ["tools/test-certify-stage-cache.mjs"],
  },
  { id: "canon-impact-fixture", cmd: ["tools/test-canon-impact.mjs"] },
  { id: "insertion-fixture", cmd: ["tools/test-insertion.mjs"] },
  { id: "generated-orientation-fixture", cmd: ["tools/test-generated-orientation.mjs"] },
  { id: "json-stdout-purity-fixture", cmd: ["tools/test-json-stdout-purity.mjs"] },
];

// The one bar that may never be selected by --bars, because the fixture's
// subject is THIS FILE: letting a subset run select it would have check-program
// spawn check-program spawn check-program without bound.
const FIXTURE_BAR_ID = "json-stdout-purity-fixture";

// A checker may be absent from BARS only with a stated reason. `deferred`
// entries are reported as ERRORS by name: they are runnable checkers that the
// owner-enumerated bar list does not yet include, and the honest state of an
// undecided omission is red, not silence.
// A checker may be declared not-a-bar ONLY when all three hold (owner ruling
// 2026-07-29): it guards no certified claim, it is consumed by no verified
// record or aggregate, and it has a durable owner-approved reason.
const NOT_A_BAR = {
  "tools/check-fast.mjs": {
    class: "lane",
    reason:
      "Lane 1. It runs a bounded subset of these same checks against what changed; running it here would recompute this lane's own inputs.",
  },
  "tools/check-program.mjs": {
    class: "lane",
    reason: "This file.",
  },
  // Admitted to BARS on 2026-07-29 by owner ruling; the deferred entries that
  // used to sit here for check-work-item-contract.mjs and
  // check-adjacent-canon-placement.mjs are gone because the owner decided them.
  "tools/check-work-item-shape.mjs": {
    class: "imported-fast-lane-check",
    reason:
      "NOT a coverage exclusion and NOT deferred. This module IS the shape census, and the shape census still runs at this boundary — the work-item-contract bar imports validateRecord() and applyWaivers() from this file and calls them on every record before adding schema validation, reference lint, and its bad-fixture self-test. Listing it as a second bar would re-walk the same records and re-run the identical census for zero additional coverage, which is the precise reason it is excluded: duplication, not omission. It keeps its own entry point because lane 1 (check-fast.mjs) validates ONLY the records that changed and must be able to call the shape census alone.",
    subsumed_by: "tools/check-work-item-contract.mjs",
    coverage_retained: true,
  },
};

const SKIP_TAXONOMY_REL = "program/skip-taxonomy.v1.json";

function loadSkipTaxonomy() {
  const abs = path.join(ESTATE_ROOT, SKIP_TAXONOMY_REL);
  if (!fs.existsSync(abs)) return null;
  const taxonomy = readJson(abs);
  const index = new Map();
  for (const entry of taxonomy.entries ?? []) {
    index.set(`${entry.bar} ${entry.check}`, entry);
  }
  return { taxonomy, index };
}

// A sub-tool prints `[SKIP] <check>: <message>`; check-program strips the tag,
// so the sub-check is the token before the first colon.
function subCheck(message) {
  const colon = message.indexOf(":");
  return colon === -1 ? message.trim() : message.slice(0, colon).trim();
}

// Every checker in tools/ must be a bar or be declared not-a-bar. This is the
// bar list checking itself.
//
// Discovery widened 2026-07-29 to include test-*.mjs. The fixtures are what
// keep the bars honest, and until now they were invisible to the coverage bar:
// a fixture could be written, never listed, and never run, and nothing would
// say so. They are discovered on exactly the same terms as the checkers.
function barCoverage(findings) {
  const declared = new Set(BARS.map((b) => b.cmd[0]));
  const toolsDir = path.join(ESTATE_ROOT, "tools");
  const checkers = fs
    .readdirSync(toolsDir)
    .filter((f) =>
      f.endsWith(".mjs") &&
      (f.startsWith("check-") || f.startsWith("test-") ||
        f.endsWith("-census.mjs"))
    )
    .map((f) => `tools/${f}`)
    .sort();
  for (const rel of checkers) {
    if (declared.has(rel)) continue;
    const exemption = NOT_A_BAR[rel];
    if (!exemption) {
      findings.push(
        finding(
          "error",
          "bar-coverage",
          `unlisted-checker: ${rel} is a runnable checker that is neither a bar nor declared not-a-bar. A bar list nobody checks is a coverage claim nobody checks.`,
        ),
      );
    } else if (exemption.class === "deferred") {
      findings.push(
        finding(
          "error",
          "bar-coverage",
          `deferred-checker: ${rel} — ${exemption.reason}`,
        ),
      );
    }
  }
  return checkers.length;
}

// `--bars=a,b` runs a named subset. It exists so the machine-output fixture can
// exercise this file's real `--json` emission path in milliseconds instead of
// re-running the whole audit, and it is loud about being partial: a subset run
// certifies nothing, and it may never select the fixture that spawns this file.
function parseBarSelection(argv, findings) {
  const flag = argv.find((a) => a === "--bars" || a.startsWith("--bars="));
  if (!flag) return BARS;
  const raw = flag.includes("=")
    ? flag.slice(flag.indexOf("=") + 1)
    : (argv[argv.indexOf(flag) + 1] ?? "");
  const wanted = raw.split(",").map((s) => s.trim()).filter(Boolean);
  const known = new Map(BARS.map((b) => [b.id, b]));
  const selected = [];
  for (const id of wanted) {
    if (id === FIXTURE_BAR_ID) {
      findings.push(
        finding(
          "error",
          "bar-selection",
          `--bars may not select ${FIXTURE_BAR_ID}: its subject is this file, so selecting it would spawn check-program from check-program without bound`,
        ),
      );
      continue;
    }
    const bar = known.get(id);
    if (!bar) {
      findings.push(
        finding("error", "bar-selection", `--bars names no such bar: ${id}`),
      );
      continue;
    }
    selected.push(bar);
  }
  findings.push(
    finding(
      "warn",
      "bar-selection",
      `PARTIAL RUN: ${selected.length} of ${BARS.length} bars selected. A subset is a probe, not a program audit: it certifies nothing, and its PASS says only that the selected bars passed.`,
    ),
  );
  return selected;
}

function main() {
  const findings = [];
  const results = [];
  const bars = parseBarSelection(process.argv.slice(2), findings);
  const partial = bars.length !== BARS.length;
  for (const bar of bars) {
    const started = Date.now();
    let code = 0;
    let output = "";
    try {
      const [script, ...flags] = bar.cmd;
      output = execFileSync(
        "node",
        [path.join("internal-docs/implementation", script), ...flags],
        { cwd: REPO_ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
      );
    } catch (error) {
      code = error.status ?? 1;
      output = `${error.stdout ?? ""}${error.stderr ?? ""}`;
    }
    const seconds = (Date.now() - started) / 1000;
    // Sub-bar warnings and SKIPs are surfaced, not swallowed. A release-boundary
    // audit that reports only exit codes would let a waived finding or an
    // explicit SKIP pass as an unqualified green.
    const warns = (output.match(/^\[WARN\]/gmu) ?? []).length;
    const skips = (output.match(/^\[SKIP\]/gmu) ?? []).length;
    const errors = (output.match(/^\[ERROR\]/gmu) ?? []).length;
    results.push({ bar: bar.id, exit: code, seconds, warns, skips, errors });
    for (const line of output.split("\n")) {
      if (line.startsWith("[WARN]")) {
        findings.push(finding("warn", bar.id, line.slice(7).trim()));
      } else if (line.startsWith("[SKIP]")) {
        findings.push(finding("skip", bar.id, line.slice(7).trim()));
      }
    }
    if (code !== 0) {
      const detail = output
        .split("\n")
        .filter((l) => l.startsWith("[ERROR]"))
        .slice(0, 12)
        .join("\n  ");
      findings.push(
        finding(
          "error",
          bar.id,
          `bar failed (exit ${code}, ${errors} error finding(s))${
            detail ? `\n  ${detail}` : ""
          }`,
        ),
      );
    }
  }

  const checkerCount = barCoverage(findings);

  // --- SKIP accounting
  const loaded = loadSkipTaxonomy();
  if (!loaded) {
    findings.push(
      finding(
        "error",
        "skip-accounting",
        `${SKIP_TAXONOMY_REL} is missing; with no taxonomy every SKIP is unclassified and this audit cannot say what its skips withhold`,
      ),
    );
  }
  const skipFindings = findings.filter((f) => f.level === "skip");
  const byClass = { certification_relevant: [], benign: [], unclassified: [] };
  for (const f of skipFindings) {
    const key = `${f.check} ${subCheck(f.message)}`;
    const entry = loaded?.index.get(key) ?? null;
    if (!entry) byClass.unclassified.push(f);
    else if (entry.class === "benign") byClass.benign.push(f);
    else byClass.certification_relevant.push(f);
  }
  const withheld = byClass.certification_relevant.length +
    byClass.unclassified.length;

  // Group the withheld skips so the count is attributable rather than a total.
  const grouped = new Map();
  for (const f of [...byClass.certification_relevant, ...byClass.unclassified]) {
    const key = `${f.check}/${subCheck(f.message)}`;
    grouped.set(key, (grouped.get(key) ?? 0) + 1);
  }
  for (const [key, count] of [...grouped].sort()) {
    const [bar, check] = key.split("/");
    const entry = loaded?.index.get(`${bar} ${check}`) ?? null;
    findings.push(
      finding(
        "error",
        "skip-accounting",
        `${count} certification-relevant SKIP(s) from ${key}${
          entry ? `: ${entry.rationale}` : " — UNCLASSIFIED in program/skip-taxonomy.v1.json; unclassified skips are certification-relevant by default"
        }`,
      ),
    );
  }

  // --- narration. stderr, always. See the machine-output contract at the head
  // of this file: stdout belongs to report(), and in --json mode report() puts
  // exactly one JSON value there.
  const total = results.reduce((a, r) => a + r.seconds, 0);
  const failed = results.filter((r) => r.exit !== 0);
  progress(
    `${
      results
        .map((r) =>
          `${r.bar} ${r.seconds.toFixed(2)}s exit=${r.exit}${
            r.warns ? ` warn=${r.warns}` : ""
          }${r.skips ? ` skip=${r.skips}` : ""}${
            r.errors ? ` errors=${r.errors}` : ""
          }`
        )
        .join("\n")
    }\ntotal ${total.toFixed(2)}s`,
  );
  progress(
    `bars ${results.length}${partial ? ` of ${BARS.length} (PARTIAL)` : ""} (${
      results.length - failed.length
    } green, ${failed.length} RED${
      failed.length ? `: ${failed.map((r) => r.bar).join(", ")}` : ""
    })`,
  );
  progress(
    `checkers and fixtures discovered in tools/ ${checkerCount}; declared not-a-bar ${
      Object.keys(NOT_A_BAR).length
    }`,
  );
  progress(
    `skips ${skipFindings.length} = ${byClass.certification_relevant.length} certification-relevant + ${byClass.unclassified.length} unclassified (treated as certification-relevant) + ${byClass.benign.length} benign`,
  );
  progress(
    withheld === 0
      ? "no certification-relevant SKIP withheld"
      : `${withheld} certification-relevant SKIP(s) withhold verification; a skip is not a success`,
  );

  process.exit(
    report("check-program", findings, { json: process.argv.includes("--json") }),
  );
}

if (import.meta.url === `file://${process.argv[1]}`) main();
