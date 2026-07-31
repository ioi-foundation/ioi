#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { failWith, implementationRoot, listTreeFiles, readJson } from "./lib.mjs";

const master = "ioi-target-end-state-master-implementation-guide.md";
const errors = [];
const skips = [];
const registry = readJson(path.join(implementationRoot, "source-dispositions.v1.json"));
const compatibilityHolds = new Map(
  registry.sources
    .filter((entry) => entry.compatibility_hold !== null)
    .map((entry) => [entry.source_path, entry.compatibility_hold]),
);
const activeMarkdown = listTreeFiles(implementationRoot)
  .filter((file) => file.endsWith(".md"))
  .map((file) => path.relative(implementationRoot, file).split(path.sep).join("/"))
  .filter((relative) => !relative.startsWith("audits/") && !relative.startsWith("_archive/") && !relative.startsWith("work-items/logs/"));

let sequencers = 0;
for (const relative of activeMarkdown) {
  const source = fs.readFileSync(path.join(implementationRoot, relative), "utf8");
  const stageHeadings = [...source.matchAll(/^###\s+M(?:[0-9]|1[0-4])\s+[—-]/gmu)].length;
  const claimsSequencer = /Document role:\s*sole internal M0[–-]M14 implementation sequencer/iu.test(source);
  const phaseOrCutHeadings = [...source.matchAll(/^#{1,6}\s+(?:Phase|Cut)\s+\d+\b/gmu)].length;
  const releaseOrClaimLadder = /(?:release|claim) ladder[\s\S]{0,500}\|\s*P[0-9]/iu.test(source);
  const legacyGateOrder = /^##\s+Execution order\s*$/gmiu.test(source)
    && [...source.matchAll(/^###\s+Gate\s+\d+\b/gmu)].length > 0
    && /^##\s+Completion condition\s*$/gmiu.test(source);
  const sequencingSignals = [
    ...(stageHeadings >= 10 ? [`${stageHeadings} M-stage headings`] : []),
    ...(phaseOrCutHeadings > 0 ? [`${phaseOrCutHeadings} ordered Phase/Cut headings`] : []),
    ...(releaseOrClaimLadder ? ["peer release/claim ladder"] : []),
    ...(legacyGateOrder ? ["legacy Execution order / Gate 0-5 / Completion condition body"] : []),
  ];
  const compatibilityHold = compatibilityHolds.get(relative);

  if (claimsSequencer || (stageHeadings >= 10 && compatibilityHold === undefined)) {
    sequencers += 1;
    if (relative !== master) errors.push(`${relative} functions as a second sequencer`);
  }
  if (relative !== master && sequencingSignals.length > 0) {
    if (compatibilityHold !== undefined) {
      skips.push({
        path: relative,
        sequencing_signals: sequencingSignals,
        reason: compatibilityHold.reason,
        approval_needed: compatibilityHold.approval_needed,
      });
    } else {
      if (phaseOrCutHeadings > 0) errors.push(`${relative} contains active ordered Phase/Cut headings`);
      if (releaseOrClaimLadder) errors.push(`${relative} contains a peer release/claim ladder`);
      if (legacyGateOrder) errors.push(`${relative} contains an active legacy gate/execution-order body`);
    }
  }
}
if (sequencers !== 1) errors.push(`expected exactly one sequencer, found ${sequencers}`);
failWith("single-sequencer check", errors);
for (const skip of skips) {
  process.stdout.write(`${JSON.stringify({
    result: "SKIP",
    check: "single-sequencer-compatibility-hold",
    ...skip,
    nonclaim: "The sole M0-M14 authority is unambiguous, but physical removal of this legacy ordering body is not proven. This SKIP closes no work item or stage.",
  })}\n`);
}
const physicalResult = skips.length === 0
  ? "physical legacy ordering bodies are fully collapsed"
  : "physical legacy-body unification remains unproven while any SKIP remains";
process.stdout.write(
  `single-sequencer check passed with ${skips.length} explicit compatibility-hold SKIP(s): ${activeMarkdown.length} active Markdown files and one M0-M14 master; ${physicalResult}\n`,
);
