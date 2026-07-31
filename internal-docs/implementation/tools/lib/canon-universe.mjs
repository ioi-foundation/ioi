// Enumerates the canon subject universe FROM THE FILESYSTEM.
//
// This replaces the previous model, in which the universe was the union of four
// hand-maintained index files and the obligation set was an ~840-line hardcoded
// literal inside the generator. Under that model a canon change could not add an
// obligation, 30 of 135 canon files were invisible in every role, and the orphan
// rule structurally could not fire on 23 architecture files. Here the universe is
// whatever is on disk, so a new canon file is a detected addition, not a silent
// omission.
import fs from "node:fs";
import path from "node:path";
import { REPO_ROOT, sha256File } from "./estate.mjs";

// Ordered: the first matching rule wins.
export const DISCOVERY_RULES = [
  {
    id: "architecture_archive",
    root: "docs/architecture/_archive",
    match: /\.(md|json)$/,
    kind: "archived_canon",
    obligation_bearing: false,
    note: "Archived terminal records. Each carries its own archived status axis and a live canonical-owner pointer.",
  },
  {
    id: "contract_registry",
    root: "docs/architecture/_meta/schemas",
    match: /^architecture-contract-registry\.v1\.json$/,
    depth: 0,
    kind: "contract_registry",
    obligation_bearing: true,
  },
  {
    id: "contract_invariants",
    root: "docs/architecture/_meta/schemas/invariants",
    match: /\.invariants\.json$/,
    kind: "contract_invariants",
    obligation_bearing: false,
    attaches_to: (rel) =>
      `docs/architecture/_meta/schemas/${
        path.basename(rel).replace(/\.invariants\.json$/, ".schema.json")
      }`,
  },
  {
    id: "contract_fixtures",
    root: "docs/architecture/_meta/schemas/fixtures",
    match: /\.json$/,
    kind: "contract_fixture",
    obligation_bearing: false,
    // Fixture directories name their subject with a dashed version suffix
    // (`authority-grant-envelope-v1`) while the schema uses a dotted one
    // (`authority-grant-envelope.v1.schema.json`).
    attaches_to: (rel) => {
      const dir = rel.split("/")[5] ?? "";
      const dotted = dir.replace(/-(v\d+)$/u, ".$1");
      return `docs/architecture/_meta/schemas/${dotted}.schema.json`;
    },
  },
  {
    id: "contract_schema",
    root: "docs/architecture/_meta/schemas",
    match: /\.schema\.json$/,
    depth: 0,
    kind: "contract_schema",
    obligation_bearing: true,
  },
  {
    id: "schema_support",
    root: "docs/architecture/_meta/schemas",
    match: /\.json$/,
    depth: 0,
    kind: "schema_support",
    obligation_bearing: false,
  },
  {
    id: "tracked_status_record",
    root: "docs/architecture/_meta/work-items",
    match: /\.(json|md)$/,
    kind: "tracked_status_record",
    obligation_bearing: false,
    note: "Merged implementation-status records. Workflow records inside a canon path; they grant nothing and own no doctrine.",
  },
  {
    id: "architecture_doc",
    root: "docs/architecture",
    match: /\.(md|tex)$/,
    kind: "architecture_doc",
    obligation_bearing: true,
  },
  {
    id: "adr_index",
    root: "docs/decisions",
    match: /^README\.md$/,
    depth: 0,
    kind: "adr_index",
    obligation_bearing: false,
  },
  {
    id: "adr",
    root: "docs/decisions",
    match: /^\d{4}-.*\.md$/,
    depth: 0,
    kind: "adr",
    obligation_bearing: true,
  },
  {
    id: "conformance",
    root: "docs/conformance",
    match: /\.(md|json)$/,
    kind: "conformance_target",
    obligation_bearing: true,
  },
  {
    // Retained evidence is enumerated ONE LEVEL DEEP: the per-programme bundle
    // directories (docs/evidence/<programme>/*.json|md) are real subjects,
    // because files such as pg-gate-map.json, release-ladder.json and
    // selected-profile.json carry programme obligations, not run artifacts, and
    // five work items cite them directly. Anything deeper — per-run validation
    // dumps, of which a checkout can hold tens of thousands — stays evidence and
    // is not enumerated.
    //
    // An earlier version used depth 0, which matched NOTHING: walk() emits only
    // files, and docs/evidence has no depth-0 files. An independent review
    // caught that the comment claimed a classification the code never made.
    id: "retained_evidence",
    root: "docs/evidence",
    match: /\.(md|json)$/,
    depth: 1,
    kind: "retained_evidence",
    obligation_bearing: false,
    note: "Immutable retained evidence for the commit and canon revision it certified. Never rewritten to appear current. Enumerated at depth 0; per-run artifacts below are evidence, not coverage subjects.",
  },
  {
    id: "adjacent_spec",
    root: "docs/specs",
    match: /\.md$/,
    kind: "adjacent_canon",
    obligation_bearing: true,
  },
  {
    id: "adjacent_security",
    root: "docs/security",
    match: /\.md$/,
    kind: "adjacent_canon",
    obligation_bearing: true,
  },
  {
    id: "adjacent_crypto",
    root: "docs/crypto",
    match: /\.md$/,
    kind: "adjacent_canon",
    obligation_bearing: true,
  },
  {
    id: "adjacent_commitment",
    root: "docs/commitment",
    match: /\.md$/,
    kind: "adjacent_canon",
    obligation_bearing: true,
  },
  {
    id: "adjacent_template",
    root: "docs/templates",
    match: /\.md$/,
    kind: "adjacent_canon",
    obligation_bearing: false,
  },
  {
    id: "brand",
    root: "docs/brand-guidelines",
    match: /\.md$/,
    kind: "non_canon_communication",
    obligation_bearing: false,
  },
];

// A directory that looks like one certification run — a date or a run id — holds
// per-run artifacts, never coverage subjects.
const PER_RUN_DIR = /^\d{4}-\d{2}-\d{2}|^\d{4}-\d{2}-\d{2}T|^[0-9a-f]{8,}$|^run-|^\d{8}/u;

function walk(root, relativeRoot, depth, skipPerRunDirs = false) {
  const absolute = path.join(root, relativeRoot);
  if (!fs.existsSync(absolute)) return [];
  const out = [];
  const stack = [{ dir: absolute, level: 0 }];
  while (stack.length > 0) {
    const { dir, level } = stack.pop();
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const child = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (depth === 0) continue;
        if (level >= depth) continue;
        if (skipPerRunDirs && PER_RUN_DIR.test(entry.name)) continue;
        stack.push({ dir: child, level: level + 1 });
      } else if (entry.isFile()) {
        out.push(path.relative(root, child));
      }
    }
  }
  return out;
}

// Discover every canon subject on disk, classified by the first matching rule.
export function discoverCanonSubjects({ repoRoot = REPO_ROOT } = {}) {
  const seen = new Map();
  for (const rule of DISCOVERY_RULES) {
    for (
      const rel of walk(
        repoRoot,
        rule.root,
        rule.depth ?? Infinity,
        rule.id === "retained_evidence",
      )
    ) {
      if (seen.has(rel)) continue;
      if (!rule.match.test(path.basename(rel))) continue;
      seen.set(rel, {
        id: rel,
        kind: rule.kind,
        rule: rule.id,
        obligation_bearing: rule.obligation_bearing,
        attaches_to: rule.attaches_to ? rule.attaches_to(rel) : null,
        sha256: sha256File(path.join(repoRoot, rel)),
        byte_count: fs.statSync(path.join(repoRoot, rel)).size,
      });
    }
  }
  // An attachment whose declared parent does not exist is not silently dropped:
  // it becomes a subject in its own right and must be classified explicitly.
  // (`fixtures/system-genesis-compiler-v1/` is one such case — it fixtures a
  // compiler, not a schema, and is consumed by tracked verifiers.)
  for (const subject of seen.values()) {
    if (subject.attaches_to && !seen.has(subject.attaches_to)) {
      subject.unresolved_attachment_parent = subject.attaches_to;
      subject.attaches_to = null;
    }
  }
  return [...seen.values()].sort((a, b) => (a.id < b.id ? -1 : 1));
}

// Subjects that must carry an explicit classification in program/canon-map.v1.json.
// Attachments inherit their parent's classification, so the map stays proportional
// to distinct subjects rather than to every fixture file on disk.
export function mappableSubjects(subjects) {
  return subjects.filter((s) => s.attaches_to === null);
}

export function readAdrStatus(rel, { repoRoot = REPO_ROOT } = {}) {
  const text = fs.readFileSync(path.join(repoRoot, rel), "utf8");
  const m = /^-?\s*Status:\s*(.+)$/mu.exec(text);
  if (!m) return { status: "unknown", accepted: false };
  const raw = m[1].trim();
  return { status: raw, accepted: !/superseded/iu.test(raw) };
}
