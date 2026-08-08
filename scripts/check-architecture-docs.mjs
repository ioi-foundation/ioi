#!/usr/bin/env node
// Integrity gate for docs/architecture, docs/decisions, and docs/conformance,
// plus the work-item status records those docs point at for status truth.
//
// Deliberately small. It checks only what canon claims about itself, it owns no
// fixture corpus, and it is one file. `docs/engineering-lessons.md` records why
// that restraint matters: on 2026-08-05 this repo deleted 75 checker scripts
// because the proof apparatus had become a second product with its own defects.
// If this file ever needs fixtures or a second module, delete the rule instead.
//
//   node scripts/check-architecture-docs.mjs               # docs + work-item records
//   node scripts/check-architecture-docs.mjs --work-items  # records only (check:work-items)
//
// Doc rules:
//   1. every relative markdown link resolves
//   2. a backticked filename link label matches its target's basename
//   3. every canon doc declares `Canonical owner:` + both status-axis fields in its header
//   4. every path named under `Implementation refs:` exists
//   5. a doc declaring `built` or `partial` names its code anchors (doc-classes.md)
//   6. every contract-registry `canonical_owner_ref` uses the one repo-root-absolute
//      `canon://docs/architecture/...` form and resolves to a file that exists
//   7. status-axis VALUES come from the doc-classes.md vocabulary — doctrine is
//      exactly canonical|reference|archived; implementation opens with
//      built|partial|planned|speculative|mixed|n/a or a resolving `see` form
//   8. a doc declaring `built`, `partial`, or `mixed` carries `Last implementation audit:`
//
// Work-item record rules, owned by docs/architecture/_meta/work-items/README.md.
// They run in both modes, so status truth cannot rot without CI noticing:
//   9. every record parses and declares `evidence_format` `ioi.program.work_item.v1`
//  10. `status` is one of the sequencer vocabulary
//  11. every `code_anchors[]` entry names a file that exists, and contains its
//      optional `must_contain` literal — except a `present_when: "pr_open"` anchor,
//      which is reported pending, not failed, when the file is not in this checkout
//  12. every `evidence_refs[]` path exists
//  13. every record path is repository-relative: no absolute path, none that climbs
//      out of the tree, and none that leaves it through a symlink, is status truth
//  14. a `verified` record carries no `pr_open` anchor — promotion requires anchors
//      that always validate

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const ROOTS = ["docs/architecture", "docs/decisions", "docs/conformance"];
const WORK_ITEMS = "docs/architecture/_meta/work-items";
const WORK_ITEM_FORMAT = "ioi.program.work_item.v1";
const STATUSES = [
  "proposed",
  "scoped",
  "active",
  "evidence_ready",
  "verified",
  "blocked",
  "superseded",
  "rejected",
];
const PRESENCE = ["merged", "pr_open"];

const workItemsOnly = process.argv.slice(2).includes("--work-items");
const failures = [];
const pending = [];

function walk(dir, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full, out);
    else if (full.endsWith(".md")) out.push(full);
  }
  return out;
}

const files = workItemsOnly ? [] : ROOTS.flatMap((r) => walk(path.join(root, r)));
const rel = (f) => path.relative(root, f);

// A record path is evidence in THIS repository. An absolute path or one that
// climbs out of the tree names something no reader can review from a checkout,
// so it can never stand for status truth — reject it before touching the disk.
function contains(base, target) {
  const relative = path.relative(base, target);
  return relative !== "" && !relative.startsWith("..") && !path.isAbsolute(relative);
}

function insideRepo(candidate) {
  if (candidate === "" || path.isAbsolute(candidate)) return false;
  return contains(root, path.resolve(root, candidate));
}

// A lexically-clean path can still leave the tree through a symlink, so anything
// that exists is re-checked against its real target.
const realRoot = fs.realpathSync(root);
function escapesRepo(resolved) {
  return !contains(realRoot, fs.realpathSync(resolved));
}

for (const file of files) {
  const source = fs.readFileSync(file, "utf8");
  const dir = path.dirname(file);

  // 1 + 2 — links resolve, and labels are not stale filenames.
  for (const match of source.matchAll(/\[([^\]]*)\]\(([^)\s]+)\)/gu)) {
    const [, label, target] = match;
    if (/^[a-z][a-z0-9+.-]*:/iu.test(target) || target.startsWith("#")) continue;
    const withoutFragment = target.split("#")[0];
    if (withoutFragment === "") continue;

    let decoded;
    try {
      decoded = decodeURIComponent(withoutFragment);
    } catch {
      failures.push(`${rel(file)}: invalid link ${target}`);
      continue;
    }
    if (!fs.existsSync(path.resolve(dir, decoded))) {
      failures.push(`${rel(file)}: broken link ${target}`);
      continue;
    }
    const labelFile = label.match(/^`([^`]+\.md)`$/u)?.[1];
    if (labelFile && path.basename(labelFile) !== path.basename(decoded)) {
      failures.push(
        `${rel(file)}: stale link label \`${path.basename(labelFile)}\` points at ${path.basename(decoded)}`,
      );
    }
  }

  // 3 + 7 + 8 — the status axis every canon doc declares, with VALUES from the
  // doc-classes.md vocabulary, not just presence. Values are read from the header
  // (first 20 lines) so deep per-section status prose and fenced vocabulary
  // listings cannot false-positive; audit presence is whole-file because long
  // owner headers legitimately carry it past line 20. ADRs carry their own header.
  let declared;
  if (file.includes(`${path.sep}docs${path.sep}architecture${path.sep}`) && !path.basename(file).startsWith("_")) {
    const head = source.split("\n").slice(0, 20).join("\n");
    for (const field of ["Doctrine status:", "Implementation status:", "Canonical owner:"]) {
      if (!head.includes(field)) failures.push(`${rel(file)}: missing \`${field}\` in the header (first 20 lines)`);
    }
    const doctrine = head.match(/^Doctrine status:\s*(.+)$/mu)?.[1]?.trim();
    if (doctrine !== undefined && !["canonical", "reference", "archived"].includes(doctrine)) {
      failures.push(`${rel(file)}: Doctrine status must be exactly canonical | reference | archived — got \`${doctrine}\``);
    }
    const impl = head.match(/^Implementation status:\s*(.+)$/mu)?.[1]?.trim();
    if (impl !== undefined) {
      const see = impl.match(/^see\s+(?:\[[^\]]*\]\(([^)\s]+)\)|`([^`\s]+)`|(\S+))/u);
      if (see) {
        const target = (see[1] ?? see[2] ?? see[3]).split("#")[0];
        if (!fs.existsSync(path.resolve(dir, target))) {
          failures.push(`${rel(file)}: Implementation status \`see\` target does not resolve — ${target}`);
        }
      } else {
        declared = impl.match(/^([a-z/]+)/u)?.[1];
        if (!["built", "partial", "planned", "speculative", "mixed", "n/a"].includes(declared)) {
          failures.push(
            `${rel(file)}: Implementation status must open with built | partial | planned | speculative | mixed | n/a, or a resolving \`see\` form — got \`${impl}\``,
          );
          declared = undefined;
        } else if (
          ["built", "partial", "mixed"].includes(declared) &&
          !source.includes("Last implementation audit:")
        ) {
          failures.push(`${rel(file)}: Implementation status \`${declared}\` declares no \`Last implementation audit:\``);
        }
      }
    }
  }

  // 5 — doc-classes.md: `built` and `partial` name their code anchors.
  if (
    ["built", "partial"].includes(declared) &&
    !/^Implementation refs:/mu.test(source) &&
    !file.includes(`${path.sep}_archive${path.sep}`)
  ) {
    failures.push(`${rel(file)}: Implementation status \`${declared}\` declares no \`Implementation refs\``);
  }

  // 4 — declared implementation refs resolve.
  const block = source.match(/^Implementation refs:\n((?:\s+-\s+.*\n)+)/mu);
  for (const line of block?.[1].split("\n") ?? []) {
    const ref = line.match(/^\s+-\s+`?([^`\s]+)`?\s*$/u)?.[1];
    if (!ref || ref === "none") continue;
    if (!fs.existsSync(path.resolve(root, ref))) {
      failures.push(`${rel(file)}: Implementation ref does not exist — ${ref}`);
    }
  }
}

// 6 — the contract registry's canonical_owner_ref plane resolves, in one form.
// The markdown link gate above is airtight because it exists; this is the same
// gate for the JSON reference plane, which had drifted 25-of-165 unnoticed —
// 17 refs at a path that never existed and 8 in an incompatible relative form.
const REGISTRY = "docs/architecture/_meta/schemas/architecture-contract-registry.v1.json";
if (!workItemsOnly) {
  try {
    const registry = JSON.parse(fs.readFileSync(path.join(root, REGISTRY), "utf8"));
    for (const contract of registry.contracts ?? []) {
      const at = `${REGISTRY}: ${contract.contract_id}`;
      const ref = contract.canonical_owner_ref;
      if (typeof ref !== "string" || !ref.startsWith("canon://docs/architecture/")) {
        failures.push(
          `${at}: canonical_owner_ref must use the repo-root-absolute canon://docs/architecture/ form — got ${JSON.stringify(ref)}`,
        );
        continue;
      }
      const target = ref.slice("canon://".length).split("#")[0];
      if (!insideRepo(target) || !fs.existsSync(path.resolve(root, target))) {
        failures.push(`${at}: canonical_owner_ref does not resolve — ${ref}`);
      }
    }
  } catch (error) {
    failures.push(`${REGISTRY}: unreadable — ${error.message}`);
  }
}

// 9-14 — the work-item status records, per `_meta/work-items/README.md`.
const workItemDir = path.join(root, WORK_ITEMS);
const records = fs.existsSync(workItemDir)
  ? fs
      .readdirSync(workItemDir)
      .filter((name) => name.endsWith(".json"))
      .sort()
  : [];
if (records.length === 0) failures.push(`${WORK_ITEMS}: no work-item records found`);
let anchorCount = 0;

for (const name of records) {
  const id = `${WORK_ITEMS}/${name}`;

  let record;
  try {
    record = JSON.parse(fs.readFileSync(path.join(workItemDir, name), "utf8"));
  } catch (error) {
    failures.push(`${id}: invalid JSON — ${error.message}`);
    continue;
  }
  if (record === null || typeof record !== "object" || Array.isArray(record)) {
    failures.push(`${id}: record is not a JSON object`);
    continue;
  }

  // 6 + 7 — the record declares its format and a status from the sequencer vocabulary.
  if (record.evidence_format !== WORK_ITEM_FORMAT) {
    failures.push(
      `${id}: evidence_format must be \`${WORK_ITEM_FORMAT}\` — got ${JSON.stringify(record.evidence_format)}`,
    );
  }
  if (!STATUSES.includes(record.status)) {
    failures.push(
      `${id}: status outside the sequencer vocabulary \`${STATUSES.join(" | ")}\` — got ${JSON.stringify(record.status)}`,
    );
  }

  // 8 — code anchors exist and carry their literal; pr_open anchors may be pending.
  const anchors = record.code_anchors ?? [];
  if (!Array.isArray(anchors)) failures.push(`${id}: code_anchors must be an array`);
  for (const [index, anchor] of (Array.isArray(anchors) ? anchors : []).entries()) {
    anchorCount += 1;
    const at = `code_anchors[${index}]`;
    if (anchor === null || typeof anchor !== "object" || Array.isArray(anchor) || typeof anchor.path !== "string") {
      failures.push(`${id}: ${at} must be an object naming a \`path\` string`);
      continue;
    }
    if (!insideRepo(anchor.path)) {
      failures.push(`${id}: ${at} path must be repository-relative evidence — ${anchor.path}`);
      continue;
    }
    const presence = anchor.present_when ?? "merged";
    if (!PRESENCE.includes(presence)) {
      failures.push(
        `${id}: ${at} present_when must be \`${PRESENCE.join("` or `")}\` — got ${JSON.stringify(anchor.present_when)}`,
      );
      continue;
    }
    // Promotion to `verified` requires anchors that always validate. A held PR
    // branch never does, present in this checkout today or not.
    if (presence === "pr_open" && record.status === "verified") {
      failures.push(`${id}: ${at} status \`verified\` cannot rest on a \`pr_open\` anchor — ${anchor.path}`);
      continue;
    }

    const anchored = path.resolve(root, anchor.path);
    const stat = fs.statSync(anchored, { throwIfNoEntry: false });
    if (!stat) {
      // A held PR branch is not merged truth and is not a defect either.
      if (presence === "pr_open") pending.push(`${id}: ${at} pending — PR-open anchor absent here: ${anchor.path}`);
      else failures.push(`${id}: ${at} code anchor does not exist — ${anchor.path}`);
      continue;
    }
    if (escapesRepo(anchored)) {
      failures.push(`${id}: ${at} code anchor leaves the repository through a symlink — ${anchor.path}`);
      continue;
    }
    if (!stat.isFile()) {
      failures.push(`${id}: ${at} code anchor is not a file — ${anchor.path}`);
      continue;
    }
    if (anchor.must_contain === undefined) continue;
    // An empty or blank literal is satisfied by every file, so it would pin nothing
    // while reading like a pinned anchor.
    if (typeof anchor.must_contain !== "string" || anchor.must_contain.trim() === "") {
      failures.push(`${id}: ${at} must_contain must be a non-empty literal`);
      continue;
    }
    if (!fs.readFileSync(anchored, "utf8").includes(anchor.must_contain)) {
      failures.push(`${id}: ${at} ${anchor.path} does not contain \`${anchor.must_contain}\``);
    }
  }

  // 9 — evidence refs resolve.
  const refs = record.evidence_refs ?? [];
  if (!Array.isArray(refs)) failures.push(`${id}: evidence_refs must be an array`);
  for (const [index, ref] of (Array.isArray(refs) ? refs : []).entries()) {
    if (typeof ref !== "string") {
      failures.push(`${id}: evidence_refs[${index}] must be a path string`);
      continue;
    }
    if (!insideRepo(ref)) {
      failures.push(`${id}: evidence_refs[${index}] must be repository-relative evidence — ${ref}`);
      continue;
    }
    const referenced = path.resolve(root, ref);
    if (!fs.existsSync(referenced)) {
      failures.push(`${id}: evidence_refs[${index}] does not exist — ${ref}`);
      continue;
    }
    if (escapesRepo(referenced)) {
      failures.push(`${id}: evidence_refs[${index}] leaves the repository through a symlink — ${ref}`);
    }
  }
}

for (const note of pending) console.log(note);

if (failures.length > 0) {
  for (const failure of failures) console.error(failure);
  console.error(`\n${failures.length} ${workItemsOnly ? "work-item record" : "architecture-doc"} integrity failures`);
  process.exit(1);
}
const count = (n, noun) => `${n} ${noun}${n === 1 ? "" : "s"}`;
if (!workItemsOnly) console.log(`Architecture docs OK — ${files.length} files, 8 rules.`);
console.log(
  `Work-item records OK — ${count(records.length, "record")} checked, ${count(anchorCount, "code anchor")}, ${count(pending.length, "pending PR anchor")}.`,
);
