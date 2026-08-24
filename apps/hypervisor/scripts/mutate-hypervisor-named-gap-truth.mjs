#!/usr/bin/env node
// M03.3 MUTATION BATTERY — the explicit authority-denial schema must fail closed.
//
// Each mutation runs in a private temporary tree. The checkout is never rewritten. These fast
// source-contract mutants prove the three seams introduced by M03.3: exact entry shape, exact
// method+route adjudication, and preservation by the canonical atlas builder.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP = path.resolve(HERE, "..");
const ROOT = path.resolve(APP, "..", "..");
const MANIFEST = path.join(APP, "named-gap-truth.mutants.v1.json");
const GATE_REL = "apps/hypervisor/scripts/verify-hypervisor-named-gap-truth.mjs";
const manifest = JSON.parse(fs.readFileSync(MANIFEST, "utf8"));

const runGate = (root, gate = path.join(root, GATE_REL)) => spawnSync("node", [gate], {
  cwd: ROOT,
  env: { ...process.env, IOI_GAPTRUTH_ROOT: root, IOI_VERIFIER_CENSUS_DIR: "" },
  encoding: "utf8",
  maxBuffer: 64 * 1024 * 1024,
});
const failures = (run) => `${run.stdout || ""}\n${run.stderr || ""}`
  .split("\n").filter((line) => line.startsWith("FAIL"));

if (manifest.expected_mutations !== 3 || manifest.anchors?.length !== manifest.expected_mutations) {
  console.error(`BLOCKED — mutation manifest count ${manifest.anchors?.length ?? 0} != expected ${manifest.expected_mutations}`);
  process.exit(2);
}

const baseline = runGate(ROOT, path.join(ROOT, GATE_REL));
if (baseline.status !== 0) {
  console.error("BLOCKED — named-gap truth gate is red before any mutation:");
  for (const line of failures(baseline)) console.error(`  ${line}`);
  process.exit(2);
}

const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-named-gap-truth-mutants-"));
const copy = (relative) => {
  const from = path.join(ROOT, relative);
  const to = path.join(scratch, relative);
  fs.mkdirSync(path.dirname(to), { recursive: true });
  fs.cpSync(from, to, { recursive: true });
};

try {
  copy("crates/node/src/bin/hypervisor-daemon.rs");
  copy("apps/hypervisor/application-operational-depth.json");
  copy("apps/hypervisor/surfaces");
  copy("apps/hypervisor/scripts");

  const verdicts = [];
  for (const anchor of manifest.anchors) {
    const target = path.join(scratch, anchor.anchor_file);
    const before = fs.readFileSync(target, "utf8");
    if (!before.includes(anchor.find)) {
      verdicts.push({ ...anchor, pass: false, verdict: "ANCHOR-ABSENT" });
      console.log(`FAIL ANCHOR-ABSENT  ${anchor.id} — ${anchor.anchor_file}`);
      continue;
    }
    fs.writeFileSync(target, before.replace(anchor.find, () => anchor.replace));
    let run;
    try {
      run = runGate(scratch);
    } finally {
      fs.writeFileSync(target, before);
    }
    const red = failures(run);
    const onTarget = run.status !== 0 && red.some((line) => line.includes(`[${anchor.red_on}]`));
    const verdict = onTarget ? "RED-ON-TARGET" : run.status === 0 ? "GREEN" : "RED-OFF-TARGET";
    verdicts.push({ ...anchor, pass: onTarget, verdict });
    console.log(`${onTarget ? "PASS" : "FAIL"} ${verdict.padEnd(14)} ${anchor.id} -> ${anchor.red_on}`);
    if (!onTarget) for (const line of red.slice(0, 4)) console.log(`     ${line.slice(0, 220)}`);
  }

  const restored = runGate(scratch);
  const restoredGreen = restored.status === 0;
  console.log(`${restoredGreen ? "PASS" : "FAIL"} ${"TREE-RESTORED".padEnd(14)} temporary source copy is green after all mutations`);
  const failed = verdicts.filter((verdict) => !verdict.pass);
  console.log(`\n${verdicts.length - failed.length}/${manifest.expected_mutations} mutations RED-ON-TARGET; temporary tree ${restoredGreen ? "restored" : "red"}`);
  if (failed.length || !restoredGreen) process.exitCode = 1;
} finally {
  fs.rmSync(scratch, { recursive: true, force: true });
}
