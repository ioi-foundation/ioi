#!/usr/bin/env node
// Adjacent-canon placement bar (m0-adjacent-canon-doc-class-and-placement-disposition).
//
// Every canon subject outside docs/architecture/ and docs/conformance/ — the
// five adjacent directories docs/security/, docs/crypto/, docs/commitment/,
// docs/specs/, docs/templates/ — must resolve to exactly one document class,
// one canonical owner or an explicit disclaimer, and the two-axis status
// front matter that _meta/doc-classes.md requires. The subject set is
// enumerated through tools/lib/canon-universe.mjs (kind: adjacent_canon),
// never from a hand-written literal. scripts/check-architecture-docs.mjs is
// bound to docs/architecture only, so this verifier is the standing gate over
// these directories.
//
//   node tools/check-adjacent-canon-placement.mjs [--write]
//
// --write regenerates generated/adjacent-canon-placement.v1.json, which
// retains each subject's ruling verbatim (the front-matter lines themselves).
// Frozen thresholds, declared before observation: zero subjects without a
// class, zero without an owner-or-disclaimer, zero without both status axes.
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import {
  ESTATE_ROOT,
  REPO_ROOT,
  finding,
  report,
} from "./lib/estate.mjs";
import { discoverCanonSubjects } from "./lib/canon-universe.mjs";

const OUT_ABS = path.join(
  ESTATE_ROOT,
  "generated",
  "adjacent-canon-placement.v1.json",
);

const CLASSES = new Set([
  "canonical-index",
  "canonical-digest",
  "canonical-doctrine",
  "canonical-reference",
  "canonical-schema",
  "conformance-contract",
  "implementation-plan",
  "product-context",
  "decision-history",
  "formal-source",
  "formal-generated",
  "evidence-artifact",
]);

function frontMatterLines(text) {
  // The placement block sits between the title line and the first section
  // heading; capture every "Key: value" style line inside it.
  const lines = text.split("\n");
  const out = [];
  for (const line of lines.slice(1)) {
    if (/^#{1,6}\s/u.test(line)) break;
    if (/^[A-Z][A-Za-z -]*:\s/u.test(line)) out.push(line.trimEnd());
  }
  return out;
}

function parsePlacement(text) {
  const fm = frontMatterLines(text);
  const get = (key) => {
    const line = fm.find((l) => l.startsWith(`${key}:`));
    return line ? line.slice(key.length + 1).trim() : null;
  };
  const classLine = get("Document class");
  const classMatch = classLine ? /`([a-z-]+)`/u.exec(classLine) : null;
  return {
    front_matter: fm,
    document_class: classMatch ? classMatch[1] : null,
    canonical_owner: get("Canonical owner"),
    doctrine_status: get("Doctrine status"),
    implementation_status: get("Implementation status"),
  };
}

function main() {
  const write = process.argv.includes("--write");
  const findings = [];

  const subjects = discoverCanonSubjects().filter(
    (s) => s.kind === "adjacent_canon",
  );
  if (subjects.length === 0) {
    findings.push(
      finding("error", "enumeration", "canon-universe enumerated zero adjacent-canon subjects; an empty universe fails closed"),
    );
    report("check-adjacent-canon-placement", findings);
    process.exit(1);
  }

  const entries = [];
  for (const subject of subjects) {
    const text = fs.readFileSync(path.join(REPO_ROOT, subject.id), "utf8");
    const placement = parsePlacement(text);
    const defects = [];
    if (!placement.document_class) {
      defects.push("no document class");
    } else if (!CLASSES.has(placement.document_class)) {
      defects.push(`unknown document class: ${placement.document_class}`);
    }
    if (!placement.canonical_owner) {
      defects.push("no canonical owner and no explicit disclaimer");
    }
    if (!placement.doctrine_status) defects.push("no doctrine status axis");
    if (!placement.implementation_status) {
      defects.push("no implementation status axis");
    }
    const classCount = placement.front_matter.filter((l) =>
      l.startsWith("Document class:")
    ).length;
    if (classCount > 1) defects.push(`${classCount} document classes; exactly one is required`);

    for (const defect of defects) {
      findings.push(finding("error", "placement", `${subject.id}: ${defect}`));
    }
    entries.push({
      id: subject.id,
      sha256: subject.sha256,
      document_class: placement.document_class,
      doctrine_status: placement.doctrine_status,
      implementation_status: placement.implementation_status,
      ruling_verbatim: placement.front_matter,
      defects,
    });
  }

  if (write) {
    fs.mkdirSync(path.dirname(OUT_ABS), { recursive: true });
    fs.writeFileSync(
      OUT_ABS,
      `${
        JSON.stringify(
          {
            format: "ioi.program.adjacent_canon_placement.v1",
            role: "Generated placement-disposition projection over every adjacent-canon subject. Retains each ruling verbatim; changes no subject's status by its own authority.",
            enumerated_through: "internal-docs/implementation/tools/lib/canon-universe.mjs (kind: adjacent_canon)",
            frozen_thresholds: {
              subjects_without_document_class: 0,
              subjects_without_owner_or_disclaimer: 0,
              subjects_missing_status_axes: 0,
            },
            subject_count: entries.length,
            defect_count: entries.filter((e) => e.defects.length > 0).length,
            subjects: entries,
          },
          null,
          2,
        )
      }\n`,
    );
    findings.push(
      finding("skip", "placement", `wrote ${entries.length} subject ruling(s)`),
    );
  }

  report("check-adjacent-canon-placement", findings);
  process.exit(findings.some((f) => f.level === "error") ? 1 : 0);
}

main();
