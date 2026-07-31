#!/usr/bin/env node
// Insertion test.
//
//   node tools/test-insertion.mjs
//
// Proves that a new bounded obligation can be added WITHOUT rewriting the
// program: inserting a stage between two existing stages, adding a module, and
// adding a canon obligation each touch a bounded set of files and renumber
// nothing.
//
// The measurement that matters is `files_touched` and `identifiers_changed`.
// Under the retiring model, inserting a stage meant editing a 2,120-line
// sequencer, an ~840-line hardcoded obligation literal, two hardcoded expected
// counts, and every downstream prose inventory.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { computeImpact } from "./canon-impact.mjs";

let failures = 0;
function check(name, condition, detail = "") {
  if (condition) process.stdout.write(`  ok   ${name}\n`);
  else {
    failures += 1;
    process.stdout.write(`  FAIL ${name}${detail ? ` — ${detail}` : ""}\n`);
  }
}

function write(root, rel, content) {
  const absolute = path.join(root, rel);
  fs.mkdirSync(path.dirname(absolute), { recursive: true });
  fs.writeFileSync(absolute, content);
}

function snapshot(root) {
  const out = new Map();
  const stack = [root];
  while (stack.length > 0) {
    const dir = stack.pop();
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const abs = path.join(dir, entry.name);
      if (entry.isDirectory()) stack.push(abs);
      else out.set(path.relative(root, abs), fs.readFileSync(abs, "utf8"));
    }
  }
  return out;
}

function diff(before, after) {
  const touched = [];
  for (const [k, v] of after) {
    if (!before.has(k)) touched.push(`+ ${k}`);
    else if (before.get(k) !== v) touched.push(`~ ${k}`);
  }
  for (const k of before.keys()) if (!after.has(k)) touched.push(`- ${k}`);
  return touched.sort();
}

function build() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-insertion-"));
  const estate = path.join(root, "internal-docs", "implementation");
  write(root, "docs/architecture/foundations/alpha.md", "# Alpha\n");
  write(root, "docs/architecture/foundations/beta.md", "# Beta\n");
  write(
    estate,
    "program/sequence.v1.json",
    `${
      JSON.stringify(
        {
          format: "ioi.program.sequence.v1",
          stages: [
            { id: "S1", title: "One", depends_on: [], module: "stages/s1.md", pulled_modules: ["m-a"], exit_gate: { aggregate_work_item_id: "s1-exit" } },
            { id: "S3", title: "Three", depends_on: ["S1"], module: "stages/s3.md", pulled_modules: ["m-a"], exit_gate: { aggregate_work_item_id: "s3-exit" } },
          ],
          modules: [{ id: "m-a", path: "modules/m-a.md", applies_to_stages: ["S1", "S3"] }],
        },
        null,
        2,
      )
    }\n`,
  );
  write(estate, "stages/s1.md", "# S1\n");
  write(estate, "stages/s3.md", "# S3\n");
  write(estate, "modules/m-a.md", "# M A\n");
  write(estate, "work-items/s1-exit.v1.json", '{"work_item_id":"s1-exit"}\n');
  write(estate, "work-items/s3-exit.v1.json", '{"work_item_id":"s3-exit"}\n');
  write(estate, "work-items/alpha-cut.v1.json", '{"work_item_id":"alpha-cut"}\n');
  write(
    estate,
    "program/canon-map.v1.json",
    `${
      JSON.stringify(
        {
          format: "ioi.program.canon_map.v1",
          subjects: [
            { id: "docs/architecture/foundations/alpha.md", kind: "architecture_doc", classification: "actively_sequenced", stages: ["S1"], modules: ["m-a"], work_items: ["alpha-cut"], contract_families: [], conformance_targets: [], code_anchors: [], proof_gates: [], reason: "fixture" },
            { id: "docs/architecture/foundations/beta.md", kind: "architecture_doc", classification: "planned", stages: ["S3"], modules: ["m-a"], work_items: ["s3-exit"], contract_families: [], conformance_targets: [], code_anchors: [], proof_gates: [], reason: "fixture" },
          ],
        },
        null,
        2,
      )
    }\n`,
  );
  return { root, estate };
}

function main() {
  const { root, estate } = build();
  process.stdout.write("insertion test\n");

  const before = snapshot(estate);
  const beforeSequence = JSON.parse(
    fs.readFileSync(path.join(estate, "program/sequence.v1.json"), "utf8"),
  );
  const beforeIds = beforeSequence.stages.map((s) => s.id);

  // --- INSERT stage S2 between S1 and S3, plus a new module and a new obligation
  const seq = JSON.parse(
    fs.readFileSync(path.join(estate, "program/sequence.v1.json"), "utf8"),
  );
  seq.stages.push({
    id: "S2",
    title: "Two",
    depends_on: ["S1"],
    module: "stages/s2.md",
    pulled_modules: ["m-a", "m-b"],
    exit_gate: { aggregate_work_item_id: "s2-exit" },
  });
  seq.stages.find((s) => s.id === "S3").depends_on = ["S2"];
  seq.modules.push({ id: "m-b", path: "modules/m-b.md", applies_to_stages: ["S2"] });
  fs.writeFileSync(
    path.join(estate, "program/sequence.v1.json"),
    `${JSON.stringify(seq, null, 2)}\n`,
  );
  write(estate, "stages/s2.md", "# S2\n");
  write(estate, "modules/m-b.md", "# M B\n");
  write(estate, "work-items/s2-exit.v1.json", '{"work_item_id":"s2-exit"}\n');

  write(root, "docs/architecture/foundations/gamma.md", "# Gamma\n");
  const map = JSON.parse(
    fs.readFileSync(path.join(estate, "program/canon-map.v1.json"), "utf8"),
  );
  map.subjects.push({
    id: "docs/architecture/foundations/gamma.md",
    kind: "architecture_doc",
    classification: "planned",
    stages: ["S2"],
    modules: ["m-b"],
    work_items: ["s2-exit"],
    contract_families: [],
    conformance_targets: [],
    code_anchors: [],
    proof_gates: [],
    reason: "new bounded obligation",
  });
  fs.writeFileSync(
    path.join(estate, "program/canon-map.v1.json"),
    `${JSON.stringify(map, null, 2)}\n`,
  );

  const after = snapshot(estate);
  const touched = diff(before, after);
  const afterSequence = JSON.parse(
    fs.readFileSync(path.join(estate, "program/sequence.v1.json"), "utf8"),
  );

  // --- no identifier was renumbered
  const afterIds = afterSequence.stages.map((s) => s.id);
  check(
    "no existing stage identifier changed",
    beforeIds.every((id) => afterIds.includes(id)),
    `${beforeIds} -> ${afterIds}`,
  );
  check(
    "no existing stage title changed",
    beforeSequence.stages.every((s) =>
      afterSequence.stages.find((q) => q.id === s.id)?.title === s.title
    ),
  );
  check(
    "no existing module id changed",
    beforeSequence.modules.every((m) =>
      afterSequence.modules.find((q) => q.id === m.id)
    ),
  );
  check(
    "no existing canon-map entry id changed",
    JSON.parse(fs.readFileSync(path.join(estate, "program/canon-map.v1.json"), "utf8"))
      .subjects.filter((s) => s.id !== "docs/architecture/foundations/gamma.md")
      .every((s) =>
        ["docs/architecture/foundations/alpha.md", "docs/architecture/foundations/beta.md"]
          .includes(s.id)
      ),
  );

  // --- the change is bounded
  const modified = touched.filter((t) => t.startsWith("~"));
  const added = touched.filter((t) => t.startsWith("+"));
  check(
    "exactly two existing files were modified (sequence + canon map)",
    modified.length === 2,
    JSON.stringify(modified),
  );
  check(
    "the only modified files are the two declared single owners",
    modified.every((t) =>
      t.endsWith("program/sequence.v1.json") || t.endsWith("program/canon-map.v1.json")
    ),
    JSON.stringify(modified),
  );
  check(
    "no existing stage module or method module was rewritten",
    !modified.some((t) => t.includes("stages/") || t.includes("modules/")),
    JSON.stringify(modified),
  );
  check(
    "three new files were added (stage module, method module, work item)",
    added.length === 3,
    JSON.stringify(added),
  );
  check("nothing was deleted", !touched.some((t) => t.startsWith("-")));

  // --- the inserted program is coherent
  const r = computeImpact({ repoRoot: root, estateRoot: estate });
  const errors = r.findings.filter((f) => f.level === "error");
  check(
    "the inserted program has no orphans or broken bindings",
    errors.length === 0,
    JSON.stringify(errors.map((e) => e.message)),
  );
  check(
    "the new obligation routes review to the new stage only",
    r.classification_counts.planned === 2,
    JSON.stringify(r.classification_counts),
  );

  fs.rmSync(root, { recursive: true, force: true });
  process.stdout.write(
    `  touched: ${touched.length} file(s) — ${touched.join(", ")}\n`,
  );
  process.stdout.write(
    failures === 0 ? "insertion test: PASS\n" : `insertion test: FAIL (${failures})\n`,
  );
  process.exit(failures === 0 ? 0 : 1);
}

main();
