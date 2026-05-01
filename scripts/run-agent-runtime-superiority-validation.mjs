#!/usr/bin/env node
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  evaluateAgentRuntimeSuperiority,
  validateAgentRuntimeSuperiority,
  writeAgentRuntimeSuperiorityEvidence,
} from "./lib/agent-runtime-superiority-contract.mjs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, "..");

function parseArgs(argv) {
  const options = {
    outputRoot: "docs/evidence/agent-runtime-superiority-validation",
    requireGuiEvidence: false,
    contractOnly: false,
  };
  for (let index = 2; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--require-gui-evidence") {
      options.requireGuiEvidence = true;
    } else if (arg === "--contract-only") {
      options.contractOnly = true;
    } else if (arg === "--output-root") {
      options.outputRoot = argv[++index] ?? options.outputRoot;
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }
  return options;
}

function printSummary(superiority, validation, result = null) {
  const status = validation.ok ? "CompletePlus" : "Partial";
  console.log(`Agent runtime smarter-superiority validation: ${status}`);
  console.log(`  Scenarios: ${superiority.counts.scenarios}`);
  console.log(`  CompletePlus scenarios: ${superiority.counts.completePlusScenarios}`);
  console.log(`  Covered surfaces: ${superiority.coverage.coveredSurfaces.join(", ")}`);
  console.log(
    `  Covered smarter dimensions: ${superiority.counts.coveredSmarterDimensions}/${superiority.counts.requiredSmarterDimensions}`,
  );
  console.log(`  P3 evidence: ${superiority.p3Evidence?.resultPath ?? "missing"}`);
  console.log(`  GUI evidence: ${superiority.guiEvidence?.resultPath ?? "missing"}`);
  if (result) {
    console.log(`  Evidence bundle: ${result.outputDir}`);
    console.log(`  Scenario ledger: ${result.scenarioLedgerPath}`);
    console.log(`  Scorecard: ${result.scorecardPath}`);
  }
  if (!validation.ok) {
    console.log("Failures:");
    for (const failure of validation.failures) {
      console.log(`  - ${failure}`);
    }
  }
}

const options = parseArgs(process.argv);

if (options.contractOnly) {
  const superiority = evaluateAgentRuntimeSuperiority(repoRoot, {
    requireGuiEvidence: options.requireGuiEvidence,
  });
  const validation = validateAgentRuntimeSuperiority(superiority);
  printSummary(superiority, validation);
  process.exit(validation.ok ? 0 : 1);
}

const { superiority, validation, result } = writeAgentRuntimeSuperiorityEvidence(repoRoot, {
  outputRoot: options.outputRoot,
  requireGuiEvidence: options.requireGuiEvidence,
});
printSummary(superiority, validation, result);
process.exit(validation.ok ? 0 : 1);
