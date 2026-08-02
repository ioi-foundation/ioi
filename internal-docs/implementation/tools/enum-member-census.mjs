#!/usr/bin/env node
// Canonical-enum member-set binding and legacy string census
// (m0-canonical-enum-member-set-binding-and-legacy-string-census).
//
// Parses every member set DIRECTLY from
// docs/architecture/foundations/canonical-enums.md — headings of the form
// `## Title (\`enum_key\`)` followed by a fenced text block, one member per
// line — with no hand-written member list and no hand-written expected-count
// constant. Joins each set to the work-item records that cite it, censuses
// the legacy free-form `risk_class`/`effect_class` literals and the
// deprecated-alias table across daemon runtime surfaces with file locators,
// and records (without resolving) the NativeEmbodiedRuntimeProfile ownership
// conflict.
//
//   node tools/enum-member-census.mjs --write | --check
//
// Citation rule, stated because it is part of the census contract: a record
// cites a member set when it contains the enum key as a token, or an exact
// distinctive member token (a member containing `_` or `-`; short bare words
// such as `read` would bind every record and fake coverage). Zero citations
// is an honest UNCOVERED row, never silently covered.
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import {
  ESTATE_ROOT,
  REPO_ROOT,
  finding,
  report,
  sha256Text,
} from "./lib/estate.mjs";

const ENUMS_REL = "docs/architecture/foundations/canonical-enums.md";
const OUT_ABS = path.join(ESTATE_ROOT, "generated", "enum-member-census.v1.json");

// Daemon runtime surfaces for the legacy-literal census.
const RUNTIME_ROOTS = [
  "crates/services/src",
  "crates/node/src",
  "crates/types/src",
];

export function parseMemberSets(text) {
  const sets = [];
  const heading = /^#{2,3}\s+.*\(`([a-zA-Z_][A-Za-z0-9_]*)`\)\s*$/gmu;
  let match;
  const positions = [];
  while ((match = heading.exec(text)) !== null) {
    positions.push({ key: match[1], start: match.index });
  }
  for (let i = 0; i < positions.length; i += 1) {
    const end = i + 1 < positions.length ? positions[i + 1].start : text.length;
    const body = text.slice(positions[i].start, end);
    const fence = /```text\n([\s\S]*?)```/u.exec(body);
    const members = fence
      ? fence[1].split("\n").map((l) => l.trim()).filter((l) => /^[a-z0-9_]+$/u.test(l))
      : [];
    sets.push({
      enum_key: positions[i].key,
      members,
      parsed: members.length > 0,
    });
  }
  if (sets.length === 0) {
    throw new Error("parsed zero member sets from the canonical-enums owner; refusing to emit an empty census");
  }
  return sets;
}

export function parseDeprecatedAliases(text) {
  const section = /Deprecated aliases[\s\S]*?\n\n/u.exec(text);
  const out = [];
  const row = /^\|\s*`([a-z0-9_]+)`\s*\|\s*`([a-z0-9_]+)`/gmu;
  let match;
  while ((match = row.exec(section ? section[0] : text)) !== null) {
    if (match[1] === "Deprecated") continue;
    out.push({ deprecated: match[1], canonical: match[2] });
  }
  return out;
}

function listRecordTexts() {
  const out = [];
  for (const sub of ["work-items/proposed", "work-items/active", "work-items"]) {
    const dir = path.join(ESTATE_ROOT, sub);
    if (!fs.existsSync(dir)) continue;
    for (const entry of fs.readdirSync(dir).sort()) {
      if (!entry.endsWith(".v1.json")) continue;
      const abs = path.join(dir, entry);
      if (!fs.statSync(abs).isFile()) continue;
      out.push({
        id: entry.replace(/\.v1\.json$/u, ""),
        text: fs.readFileSync(abs, "utf8"),
      });
    }
  }
  return out;
}

function distinctive(member) {
  return member.includes("_") || member.includes("-");
}

function tokenRe(token) {
  return new RegExp(`\\b${token.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&")}\\b`, "u");
}

function scanRuntimeLiterals(needles) {
  const hits = [];
  for (const root of RUNTIME_ROOTS) {
    const rootAbs = path.join(REPO_ROOT, root);
    if (!fs.existsSync(rootAbs)) continue;
    const stack = [rootAbs];
    while (stack.length > 0) {
      const dir = stack.pop();
      for (const entry of fs.readdirSync(dir, { withFileTypes: true }).sort()) {
        const abs = path.join(dir, entry.name);
        if (entry.isDirectory()) stack.push(abs);
        else if (entry.isFile() && entry.name.endsWith(".rs")) {
          const text = fs.readFileSync(abs, "utf8");
          if (!/risk_class|effect_class/u.test(text)) continue;
          const rel = path.relative(REPO_ROOT, abs);
          const lines = text.split("\n");
          lines.forEach((line, i) => {
            if (!/risk_class|effect_class/u.test(line)) return;
            for (const needle of needles) {
              if (line.includes(`"${needle}"`)) {
                hits.push({ literal: needle, file: rel, line: i + 1 });
              }
            }
            const free = /"([a-z0-9_]+)"/gu;
            let m;
            while ((m = free.exec(line)) !== null) {
              if (!needles.includes(m[1])) {
                hits.push({ literal: m[1], file: rel, line: i + 1, free_form: true });
              }
            }
          });
        }
      }
    }
  }
  hits.sort((a, b) =>
    a.file === b.file ? a.line - b.line : a.file < b.file ? -1 : 1
  );
  return hits;
}

export function derive(enumsText) {
  const sets = parseMemberSets(enumsText);
  const aliases = parseDeprecatedAliases(enumsText);
  const records = listRecordTexts();

  const bindings = sets.map((set) => {
    const cited = [];
    for (const record of records) {
      const keyHit = tokenRe(set.enum_key).test(record.text);
      const memberHit = set.members.some(
        (m) => distinctive(m) && tokenRe(m).test(record.text),
      );
      if (keyHit || memberHit) cited.push(record.id);
    }
    cited.sort();
    return {
      enum_key: set.enum_key,
      member_count: set.members.length,
      members: set.members,
      parsed: set.parsed,
      cited_by_records: cited,
      covered: cited.length > 0,
    };
  });

  const riskSet = sets.find((s) => s.enum_key === "risk_class");
  const canonicalMembers = riskSet ? riskSet.members : [];
  const legacyNeedles = aliases.map((a) => a.deprecated);
  const literalHits = scanRuntimeLiterals([...legacyNeedles, ...canonicalMembers]);

  return {
    format: "ioi.program.enum_member_census.v1",
    role: "Generated member-set binding and legacy-literal census. Member sets parse directly from the canonical owner; counts are derived, never hand-written. UNCOVERED is an honest gap. The census records ownership conflicts; it resolves none.",
    owner: { path: ENUMS_REL, sha256: sha256Text(enumsText) },
    citation_rule: "enum-key token match, or exact distinctive member token (contains _ or -); short bare members never bind",
    member_sets: bindings,
    set_count: bindings.length,
    uncovered_count: bindings.filter((b) => !b.covered).length,
    deprecated_aliases: aliases,
    legacy_literal_census: {
      scanned_roots: RUNTIME_ROOTS,
      scope: "lines mentioning risk_class or effect_class in daemon runtime surfaces",
      hits: literalHits,
      hit_count: literalHits.length,
      free_form_count: literalHits.filter((h) => h.free_form).length,
    },
    recorded_conflicts: [
      {
        subject: "NativeEmbodiedRuntimeProfile",
        conflict: "m11-canonical-embodied-contract-alignment declares owner_path docs/architecture/foundations/common-objects-and-envelopes.md while canonical-enums.md claims the member set",
        routed_to: "docs/architecture/foundations/canonical-enums.md",
        resolved_here: false,
      },
    ],
  };
}

function main() {
  const write = process.argv.includes("--write");
  const outputIndex = process.argv.indexOf("--output");
  const outputAbs = outputIndex >= 0
    ? path.resolve(process.argv[outputIndex + 1] ?? "")
    : OUT_ABS;
  const findings = [];

  const enumsAbs = path.join(REPO_ROOT, ENUMS_REL);
  if (!fs.existsSync(enumsAbs)) {
    findings.push(finding("error", "owner", `canonical-enums owner missing: ${ENUMS_REL}; fails closed`));
    report("enum-member-census", findings);
    process.exit(1);
  }

  // Self-test: an empty owner fails closed rather than deriving zero sets.
  let failedClosed = false;
  try {
    derive("");
  } catch {
    failedClosed = true;
  }
  if (!failedClosed) {
    findings.push(finding("error", "self-test", "an empty owner derived a census instead of failing closed"));
  }

  const census = derive(fs.readFileSync(enumsAbs, "utf8"));
  const rendered = `${JSON.stringify(census, null, 2)}\n`;

  if (write) {
    fs.mkdirSync(path.dirname(outputAbs), { recursive: true });
    fs.writeFileSync(outputAbs, rendered);
    if (outputAbs !== OUT_ABS) {
      report("enum-member-census", findings);
      process.exit(findings.some((f) => f.level === "error") ? 1 : 0);
    }
  }
  if (!fs.existsSync(OUT_ABS)) {
    findings.push(finding("error", "census", "no generated census on disk; run --write"));
  } else if (fs.readFileSync(OUT_ABS, "utf8") !== rendered) {
    findings.push(
      finding("error", "census", "census does not reproduce byte-for-byte from a fresh derivation; a hand edit or stale generation fails closed"),
    );
  }

  report("enum-member-census", findings);
  process.exit(findings.some((f) => f.level === "error") ? 1 : 0);
}

main();
