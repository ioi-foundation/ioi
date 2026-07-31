#!/usr/bin/env node
// Canon-owner coverage and orphan bar (m0-canon-owner-coverage-and-orphan-verifier).
//
// Builds the private ArchitectureCoverageEntry projection — every canon owner
// path cited by any work-item record, with its current digest and its citing
// records — and enforces the five predeclared fail-closed rejections:
//
//   zero-owner        a cited canon owner that does not resolve on disk
//   multiple-owner    a canon subject classified more than once in canon-map
//   stale-digest      a record canon_snapshot owner digest that no longer
//                     matches the file (and is not explicitly recorded as
//                     missing_in_checkout)
//   archive-as-owner  a canon owner under docs/architecture/_archive/
//   public-queue      a canon owner under docs/architecture/_meta/work-items/
//                     (tracked status mirrors own no doctrine)
//
// plus the orphan rejection: an obligation-bearing mappable canon subject with
// no classification in program/canon-map.v1.json. Every rejection is
// self-tested against a synthetic bad input on every run, so the bar cannot
// silently lose its teeth.
//
//   node tools/check-canon-owner-coverage.mjs [--write]
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import {
  ESTATE_ROOT,
  REPO_ROOT,
  finding,
  readJson,
  report,
  sha256File,
} from "./lib/estate.mjs";
import {
  discoverCanonSubjects,
  mappableSubjects,
} from "./lib/canon-universe.mjs";

const OUT_ABS = path.join(
  ESTATE_ROOT,
  "generated",
  "architecture-coverage.v1.json",
);
const CANON_MAP = path.join(ESTATE_ROOT, "program", "canon-map.v1.json");
const OPEN_SUCCESSOR_HOLDS = path.join(
  ESTATE_ROOT,
  "_archive",
  "holds",
  "open-successor-holds.v1.json",
);

function listRecords() {
  const out = [];
  for (const sub of ["work-items/proposed", "work-items/active", "work-items"]) {
    const dir = path.join(ESTATE_ROOT, sub);
    if (!fs.existsSync(dir)) continue;
    for (const entry of fs.readdirSync(dir).sort()) {
      if (!entry.endsWith(".v1.json")) continue;
      const abs = path.join(dir, entry);
      if (fs.statSync(abs).isFile()) out.push(readJson(abs));
    }
  }
  return out;
}

// The rejection core, pure over its inputs so the self-test can feed it
// synthetic estates.
export function evaluate({
  records,
  canonMapSubjects,
  universe,
  qualifiedHistoricalIds = new Set(),
}) {
  const findings = [];
  const coverage = new Map();

  for (const record of records) {
    const id = record.work_item_id;
    for (const owner of record.canon_owners ?? []) {
      if (!coverage.has(owner)) {
        const abs = path.join(REPO_ROOT, owner);
        coverage.set(owner, {
          path: owner,
          exists: fs.existsSync(abs),
          sha256: fs.existsSync(abs) ? sha256File(abs) : null,
          cited_by: [],
        });
      }
      coverage.get(owner).cited_by.push(id);
      if (owner.startsWith("docs/architecture/_archive/")) {
        findings.push(
          finding("error", "archive-as-owner", `${id}: archived history cited as canon owner: ${owner}`),
        );
      }
      if (owner.startsWith("docs/architecture/_meta/work-items/")) {
        findings.push(
          finding("error", "public-queue", `${id}: tracked status mirror cited as canon owner: ${owner}`),
        );
      }
    }
    for (const snap of record.canon_snapshot?.owners ?? []) {
      if (snap.missing_in_checkout) continue;
      const abs = path.join(REPO_ROOT, snap.path);
      if (!fs.existsSync(abs)) {
        findings.push(
          finding("error", "zero-owner", `${id}: snapshot owner does not resolve: ${snap.path}`),
        );
      } else if (snap.sha256 && sha256File(abs) !== snap.sha256) {
        const qualifiedHistorical = qualifiedHistoricalIds.has(id);
        findings.push(
          finding(
            qualifiedHistorical ? "warn" : "error",
            qualifiedHistorical ? "stale-qualified-historical" : "stale-digest",
            qualifiedHistorical
              ? `${id}: historical snapshot digest differs for ${snap.path}; an open successor hold withholds current closure`
              : `${id}: snapshot digest stale for ${snap.path}; qualify the historical record through a successor hold or re-anchor before admission`,
          ),
        );
      }
    }
  }

  for (const entry of coverage.values()) {
    entry.cited_by.sort();
    if (!entry.exists) {
      findings.push(
        finding(
          "error",
          "zero-owner",
          `canon owner cited by ${entry.cited_by.length} record(s) does not resolve: ${entry.path}`,
        ),
      );
    }
  }

  const counts = new Map();
  for (const s of canonMapSubjects) {
    counts.set(s.id, (counts.get(s.id) ?? 0) + 1);
  }
  for (const [id, n] of counts) {
    if (n > 1) {
      findings.push(
        finding("error", "multiple-owner", `canon subject classified ${n} times in canon-map: ${id}`),
      );
    }
  }

  const classified = new Set(counts.keys());
  for (const subject of mappableSubjects(universe)) {
    if (!subject.obligation_bearing) continue;
    if (!classified.has(subject.id)) {
      findings.push(
        finding("error", "orphan", `obligation-bearing canon subject has no classification: ${subject.id}`),
      );
    }
  }

  return { findings, coverage: [...coverage.values()].sort((a, b) => (a.path < b.path ? -1 : 1)) };
}

function selfTest() {
  const out = [];
  const cases = [
    {
      rejection: "zero-owner",
      records: [{
        work_item_id: "fixture-zero-owner",
        canon_owners: ["docs/architecture/foundations/does-not-exist.md"],
      }],
      canonMapSubjects: [],
      universe: [],
    },
    {
      rejection: "multiple-owner",
      records: [],
      canonMapSubjects: [{ id: "docs/architecture/README.md" }, { id: "docs/architecture/README.md" }],
      universe: [],
    },
    {
      rejection: "stale-digest",
      records: [{
        work_item_id: "fixture-stale-digest",
        canon_owners: [],
        canon_snapshot: {
          owners: [{ path: "docs/architecture/README.md", sha256: "0".repeat(64) }],
        },
      }],
      canonMapSubjects: [],
      universe: [],
    },
    {
      rejection: "archive-as-owner",
      records: [{
        work_item_id: "fixture-archive-owner",
        canon_owners: ["docs/architecture/_archive/some-ledger.md"],
      }],
      canonMapSubjects: [],
      universe: [],
    },
    {
      rejection: "public-queue",
      records: [{
        work_item_id: "fixture-public-queue",
        canon_owners: ["docs/architecture/_meta/work-items/some-record.v1.json"],
      }],
      canonMapSubjects: [],
      universe: [],
    },
    {
      rejection: "orphan",
      records: [],
      canonMapSubjects: [],
      universe: [{
        id: "docs/architecture/fixture-unclassified.md",
        obligation_bearing: true,
        attaches_to: null,
      }],
    },
  ];
  for (const testCase of cases) {
    const { findings } = evaluate(testCase);
    if (!findings.some((f) => f.level === "error" && f.check === testCase.rejection)) {
      out.push(
        finding("error", "self-test", `synthetic ${testCase.rejection} input was ACCEPTED; the rejection has no teeth`),
      );
    }
  }
  const qualifiedId = "fixture-qualified-historical";
  const qualified = evaluate({
    records: [{
      work_item_id: qualifiedId,
      canon_owners: [],
      canon_snapshot: {
        owners: [{ path: "docs/architecture/README.md", sha256: "0".repeat(64) }],
      },
    }],
    canonMapSubjects: [],
    universe: [],
    qualifiedHistoricalIds: new Set([qualifiedId]),
  }).findings;
  if (
    qualified.some((f) => f.level === "error" && f.check === "stale-digest")
    || !qualified.some((f) => f.level === "warn" && f.check === "stale-qualified-historical")
  ) {
    out.push(
      finding(
        "error",
        "self-test",
        "a successor-qualified historical snapshot was not retained as a non-closing warning",
      ),
    );
  }
  return out;
}

function qualifiedHistoricalPredecessors() {
  const ledger = readJson(OPEN_SUCCESSOR_HOLDS);
  const ids = new Set();
  for (const hold of ledger.holds ?? []) {
    if (hold.projection_qualification !== "verified_historical_with_open_successor") continue;
    for (const id of hold.predecessor_records ?? []) ids.add(id);
  }
  return ids;
}

function main() {
  const write = process.argv.includes("--write");
  const findings = selfTest();

  const records = listRecords();
  const canonMap = readJson(CANON_MAP);
  const universe = discoverCanonSubjects();
  const { findings: liveFindings, coverage } = evaluate({
    records,
    canonMapSubjects: canonMap.subjects,
    universe,
    qualifiedHistoricalIds: qualifiedHistoricalPredecessors(),
  });
  findings.push(...liveFindings);

  if (write) {
    fs.mkdirSync(path.dirname(OUT_ABS), { recursive: true });
    fs.writeFileSync(
      OUT_ABS,
      `${
        JSON.stringify(
          {
            format: "ioi.program.architecture_coverage.v1",
            role: "Generated ArchitectureCoverageEntry projection: every canon owner cited by any work-item record, with current digest and citing records. Derived output; never authority and never status truth.",
            owner_count: coverage.length,
            unresolved_owner_count: coverage.filter((c) => !c.exists).length,
            entries: coverage,
          },
          null,
          2,
        )
      }\n`,
    );
    findings.push(
      finding("skip", "coverage", `wrote ${coverage.length} owner entr(ies)`),
    );
  }

  report("check-canon-owner-coverage", findings);
  process.exit(findings.some((f) => f.level === "error") ? 1 : 0);
}

main();
