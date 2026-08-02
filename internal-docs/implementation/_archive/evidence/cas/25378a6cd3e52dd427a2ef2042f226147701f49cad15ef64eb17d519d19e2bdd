#!/usr/bin/env node
// INV-* invariant registry census (m0-invariant-registry-census).
//
// Parses every INV-* identifier DIRECTLY from the registry file
// (docs/architecture/foundations/invariants.md) — no hand-written identifier
// list — and joins each to the work-item records, stage modules, and reusable
// modules that cite it. Zero citations is reported as an honest UNOWNED
// invariant, never as covered. A census proves ownership bookkeeping only; it
// proves nothing about code enforcement.
//
//   node tools/invariant-census.mjs --write    regenerate the projection
//   node tools/invariant-census.mjs --check    re-derive; byte-for-byte diff
//
// Fail-closed properties, self-tested on every run:
//   - a missing registry file is an error, never "zero invariants, pass";
//   - a hand-edited census that does not reproduce from a fresh derivation
//     fails --check byte-for-byte;
//   - a renamed invariant derives as one removal plus one addition between
//     generations, never as unchanged.
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

const REGISTRY_REL = "docs/architecture/foundations/invariants.md";
const OUT_ABS = path.join(ESTATE_ROOT, "generated", "invariant-census.v1.json");
const INV = /\bINV-\d+\b/gu;

function parseRegistry(text) {
  const ids = [...new Set(text.match(INV) ?? [])];
  return ids.sort((a, b) => Number(a.slice(4)) - Number(b.slice(4)));
}

function citations(dirAbs, extension, ids) {
  const hits = new Map(ids.map((id) => [id, []]));
  if (!fs.existsSync(dirAbs)) return hits;
  const stack = [dirAbs];
  while (stack.length > 0) {
    const current = stack.pop();
    for (const entry of fs.readdirSync(current, { withFileTypes: true }).sort()) {
      const abs = path.join(current, entry.name);
      if (entry.isDirectory()) {
        stack.push(abs);
      } else if (entry.isFile() && entry.name.endsWith(extension)) {
        const text = fs.readFileSync(abs, "utf8");
        const found = new Set(text.match(INV) ?? []);
        const rel = path.relative(ESTATE_ROOT, abs);
        for (const id of found) if (hits.has(id)) hits.get(id).push(rel);
      }
    }
  }
  for (const list of hits.values()) list.sort();
  return hits;
}

export function derive(registryText) {
  const ids = parseRegistry(registryText);
  if (ids.length === 0) {
    throw new Error("registry parsed to zero INV identifiers; refusing to emit an empty census");
  }
  const workItems = citations(path.join(ESTATE_ROOT, "work-items"), ".json", ids);
  const stages = citations(path.join(ESTATE_ROOT, "stages"), ".md", ids);
  const modules = citations(path.join(ESTATE_ROOT, "modules"), ".md", ids);
  const invariants = ids.map((id) => {
    const cited = {
      work_items: workItems.get(id),
      stages: stages.get(id),
      modules: modules.get(id),
    };
    const owned = cited.work_items.length + cited.stages.length + cited.modules.length > 0;
    return { id, owned, cited_by: cited };
  });
  return {
    format: "ioi.program.invariant_census.v1",
    role: "Generated ownership-bookkeeping census. Proves which estate objects cite each registry invariant; proves nothing about code enforcement. UNOWNED is an honest gap, never silently covered.",
    registry: {
      path: REGISTRY_REL,
      sha256: sha256Text(registryText),
    },
    invariant_count: invariants.length,
    unowned_count: invariants.filter((i) => !i.owned).length,
    invariants,
  };
}

function render(census) {
  return `${JSON.stringify(census, null, 2)}\n`;
}

function selfTest() {
  const out = [];
  // 1. Missing registry fails closed.
  let failedClosed = false;
  try {
    derive(""); // an unreadable/absent registry derives from no text
  } catch {
    failedClosed = true;
  }
  if (!failedClosed) {
    out.push(
      finding("error", "self-test", "an empty registry derived a census instead of failing closed"),
    );
  }
  // 2. A rename derives as one removal plus one addition, never unchanged.
  const a = derive("INV-1 INV-2 INV-3");
  const b = derive("INV-1 INV-2 INV-4"); // INV-3 renamed to INV-4
  const aIds = new Set(a.invariants.map((i) => i.id));
  const bIds = new Set(b.invariants.map((i) => i.id));
  const removed = [...aIds].filter((id) => !bIds.has(id));
  const added = [...bIds].filter((id) => !aIds.has(id));
  if (removed.length !== 1 || added.length !== 1) {
    out.push(
      finding("error", "self-test", `rename derived as ${removed.length} removal(s) + ${added.length} addition(s); required exactly 1 + 1`),
    );
  }
  return out;
}

function main() {
  const write = process.argv.includes("--write");
  const check = process.argv.includes("--check");
  const outputIndex = process.argv.indexOf("--output");
  const outputAbs = outputIndex >= 0
    ? path.resolve(process.argv[outputIndex + 1] ?? "")
    : OUT_ABS;
  const findings = selfTest();

  const registryAbs = path.join(REPO_ROOT, REGISTRY_REL);
  if (!fs.existsSync(registryAbs)) {
    findings.push(
      finding("error", "registry", `registry file missing: ${REGISTRY_REL}; a deleted registry fails closed, it does not report zero invariants`),
    );
    report("invariant-census", findings);
    process.exit(1);
  }

  const census = derive(fs.readFileSync(registryAbs, "utf8"));
  const rendered = render(census);

  if (write) {
    fs.mkdirSync(path.dirname(outputAbs), { recursive: true });
    fs.writeFileSync(outputAbs, rendered);
    if (outputAbs !== OUT_ABS) {
      report("invariant-census", findings);
      process.exit(findings.some((f) => f.level === "error") ? 1 : 0);
    }
  }
  if (check || !write) {
    if (!fs.existsSync(OUT_ABS)) {
      findings.push(finding("error", "census", "no generated census on disk; run --write"));
    } else {
      const onDisk = fs.readFileSync(OUT_ABS, "utf8");
      if (onDisk !== rendered) {
        findings.push(
          finding("error", "census", "generated census does not reproduce byte-for-byte from a fresh derivation; a hand edit or a stale generation fails closed"),
        );
      }
    }
  }

  report("invariant-census", findings);
  process.exit(findings.some((f) => f.level === "error") ? 1 : 0);
}

main();
