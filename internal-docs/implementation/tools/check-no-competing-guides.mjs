#!/usr/bin/env node
// Rejects new active implementation guidance outside the approved estate.
//
//   node tools/check-no-competing-guides.mjs [--json] [--report]
//
// An artifact is ACTIVE IMPLEMENTATION GUIDANCE when it presently orders
// implementation work, defines a current phase or milestone, tells an
// implementer what to build, assigns implementation dependencies, defines exit
// gates, carries a current checklist, or acts as a master guide, roadmap, rework
// specification, or action plan.
//
// Detection is by SEMANTICS with a filename tiebreak, never by filename alone:
// a file is flagged only when it carries an active-guidance marker AND does not
// carry an honest archival or non-directive header.
//
// Every known first-party file is classified in
// program/guide-registry.v1.json. An unclassified file that trips a marker is an
// error; a classified one reports its declared disposition. That is what keeps
// canonical indexes such as the implementation matrix from being flagged for
// their filenames.
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

// Markers that indicate a file presently orders work.
const ACTIVE_MARKERS = [
  { id: "ordered-phase", re: /^#{1,4}\s+(?:Phase|Cut|Milestone|Step|Wave|Sprint)\s+\d+/mu },
  { id: "unchecked-checklist", re: /^\s*[-*]\s+\[ \]\s+/mu },
  { id: "exit-gate", re: /^#{1,4}\s+.*(?:Exit gate|Exit criteria|Acceptance gate)/imu },
  { id: "master-guide-role", re: /^#{1,2}\s+.*(?:Master Guide|Action Plan|Rework Spec|Implementation Plan|Roadmap)\b/imu },
  { id: "imperative-build", re: /\b(?:you must build|implementers? must|do not reintroduce|treat .* as the source of truth)\b/imu },
];

// Headers that honestly demote a file: archived, historical, non-directive, or
// explicitly routed to the estate.
const DEMOTING_HEADERS = [
  /^\s*>?\s*(?:Status|Doctrine status):\s*archived/imu,
  /archived terminal record/imu,
  /historical evidence only/imu,
  /non-actionable/imu,
  /Canonical owner:\s*none/imu,
  /Execution routing \(\d{4}-\d{2}-\d{2}\)/mu,
  /This (?:file|document) schedules nothing/imu,
  /^\s*Document class:\s*pointer/imu,
];

// Roots that are never first-party IOI implementation guidance.
const EXCLUDED_ROOTS = [
  "node_modules/",
  "target/",
  "dist/",
  "build/",
  ".git/",
  "examples/",
  "vendor/",
  "internal-docs/reverse-engineering/",
  "internal-docs/implementation/_archive/",
  "internal-docs/implementation/generated/",
];

function trackedMarkdown() {
  try {
    return execFileSync("git", ["ls-files", "*.md"], {
      cwd: REPO_ROOT,
      encoding: "utf8",
      maxBuffer: 32 * 1024 * 1024,
    })
      .split("\n")
      .filter(Boolean);
  } catch {
    return [];
  }
}

function ignoredFirstParty(registry) {
  const out = [];
  for (const root of registry.ignored_first_party_roots ?? []) {
    const absolute = path.join(REPO_ROOT, root);
    if (!fs.existsSync(absolute)) continue;
    const stack = [absolute];
    while (stack.length > 0) {
      const dir = stack.pop();
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const child = path.join(dir, entry.name);
        const rel = path.relative(REPO_ROOT, child);
        if (EXCLUDED_ROOTS.some((p) => rel.startsWith(p))) continue;
        if (entry.isDirectory()) stack.push(child);
        else if (entry.name.endsWith(".md")) out.push(rel);
      }
    }
  }
  return out;
}

function main() {
  const registryPath = path.join(
    ESTATE_ROOT,
    "program",
    "guide-registry.v1.json",
  );
  const registry = readJson(registryPath);
  const classified = new Map(
    registry.classified.map((c) => [c.path, c]),
  );

  const candidates = [
    ...new Set([...trackedMarkdown(), ...ignoredFirstParty(registry)]),
  ]
    .filter((p) => !EXCLUDED_ROOTS.some((r) => p.startsWith(r)))
    .filter((p) => !p.startsWith("internal-docs/implementation/"))
    .sort();

  const findings = [];
  const flagged = [];
  const sourceDispositionPath = path.join(
    ESTATE_ROOT,
    "source-dispositions.v1.json",
  );
  const sourceDispositions = fs.existsSync(sourceDispositionPath)
    ? readJson(sourceDispositionPath)
    : { entries: [] };
  const dispositionsByPath = new Map(
    (sourceDispositions.entries ?? []).map((entry) => [entry.path, entry]),
  );

  for (const rel of candidates) {
    const absolute = path.join(REPO_ROOT, rel);
    let text;
    try {
      text = fs.readFileSync(absolute, "utf8");
    } catch {
      continue;
    }
    const head = text.slice(0, 4000);
    if (DEMOTING_HEADERS.some((re) => re.test(head))) continue;

    const hits = ACTIVE_MARKERS.filter((m) => m.re.test(text)).map((m) => m.id);
    if (hits.length === 0) continue;

    const entry = classified.get(rel);
    if (!entry) {
      findings.push(
        finding(
          "error",
          "competing-guide",
          `unclassified first-party file carries active implementation-guidance markers [${
            hits.join(", ")
          }]: ${rel}. Classify it in program/guide-registry.v1.json, demote it with an honest header, or relocate its active substance into the estate.`,
          { path: rel, markers: hits },
        ),
      );
      flagged.push({ path: rel, markers: hits, classification: null });
      continue;
    }
    flagged.push({ path: rel, markers: hits, classification: entry.classification });
    if (entry.classification === "active-implementation-guidance") {
      // `report-only` is for a file whose disposition is a decision this refactor
      // does not own — user in-flight branch work, or a canon path. It is named,
      // classified, and visible; it is never hidden.
      const reportOnly = entry.disposition === "report-only";
      findings.push(
        finding(
          reportOnly ? "warn" : "error",
          "competing-guide",
          reportOnly
            ? `${rel} is active implementation guidance outside the estate, reported not applied: ${entry.note ?? ""}`
            : `${rel} is classified active-implementation-guidance outside the estate; disposition "${entry.disposition}" is not yet applied`,
          { path: rel },
        ),
      );
    }
  }

  // Registry entries whose file is absent. A path under a declared ignored root
  // is absent from a clean checkout BY DESIGN (it is developer-host state), so
  // it is reported as an explicit SKIP with its reason rather than as drift.
  // Anything else is real registry staleness.
  const ignoredRoots = registry.ignored_first_party_roots ?? [];
  let ignoredAbsent = 0;
  let tombstoned = 0;
  for (const entry of registry.classified) {
    if (fs.existsSync(path.join(REPO_ROOT, entry.path))) continue;
    // A deletion is closed only when the source-disposition ledger carries the
    // same path as a tombstone. Retaining and validating that fact is evidence;
    // it is not an unperformed check and therefore must not be called a SKIP.
    if (entry.tombstoned_in) {
      const disposition = dispositionsByPath.get(entry.path);
      if (
        !disposition ||
        disposition.sha256 !== null ||
        disposition.tombstone?.recorded_in !== entry.tombstoned_in ||
        disposition.status_authority !== false
      ) {
        findings.push(
          finding(
            "error",
            "tombstoned-deletion",
            `classified path is absent and claims tombstone ${entry.tombstoned_in}, but the source-disposition ledger does not reproduce a non-authoritative tombstone for the same path: ${entry.path}`,
          ),
        );
      } else {
        tombstoned += 1;
      }
      continue;
    }
    if (ignoredRoots.some((r) => entry.path.startsWith(`${r}/`) || entry.path === r)) {
      ignoredAbsent += 1;
      continue;
    }
    findings.push(
      finding(
        "warn",
        "registry-stale",
        `guide registry classifies a tracked path that no longer exists: ${entry.path}`,
      ),
    );
  }
  if (tombstoned > 0) {
    progress(
      `${tombstoned} absent classified path(s) reproduce as non-authoritative tombstones in the source-disposition ledger`,
    );
  }
  if (ignoredAbsent > 0) {
    findings.push(
      finding(
        "skip",
        "ignored-estate-absent",
        `${ignoredAbsent} classified path(s) live under declared ignored first-party roots and are absent from this checkout. Their classification is retained; it is not verified here. SKIP is not success.`,
      ),
    );
  }

  if (process.argv.includes("--report")) {
    progress(`${JSON.stringify(flagged, null, 2)}`);
  }
  progress(
    `scanned ${candidates.length} first-party markdown file(s); ${flagged.length} carry active-guidance markers`,
  );
  process.exit(
    report("check-no-competing-guides", findings, {
      json: process.argv.includes("--json"),
    }),
  );
}

if (import.meta.url === `file://${process.argv[1]}`) main();
