#!/usr/bin/env node
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  evaluateAgentRuntimeP3Readiness,
  validateAgentRuntimeP3Readiness,
  writeAgentRuntimeP3Evidence,
} from "./lib/agent-runtime-p3-contract.mjs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, "..");

function parseArgs(argv) {
  const options = {
    outputRoot: "docs/evidence/agent-runtime-p3-validation",
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

function printSummary(readiness, validation, result = null) {
  const status = validation.ok ? "Complete" : "Partial";
  console.log(`Agent runtime P3 validation: ${status}`);
  console.log(`  P3 product polish: ${readiness.counts.p3}`);
  console.log(`  Exhaustive workflow suites: ${readiness.counts.exhaustiveWorkflowSuites}`);
  console.log(`  Better-agent validations: ${readiness.counts.betterAgentValidations}`);
  console.log(`  Runtime scorecard dimensions: ${readiness.counts.scorecardDimensions}`);
  console.log(`  Incomplete items: ${readiness.counts.incomplete}`);
  if (readiness.guiEvidence) {
    console.log(`  GUI evidence: ${readiness.guiEvidence.resultPath}`);
  } else {
    console.log("  GUI evidence: not found in this validation pass");
  }
  if (result) {
    console.log(`  Evidence bundle: ${result.outputDir}`);
    console.log(`  Dashboard index: ${result.dashboardIndexPath}`);
    console.log(`  Redacted diagnostics: ${result.redactedDiagnosticBundlePath}`);
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
  const readiness = evaluateAgentRuntimeP3Readiness(repoRoot, {
    requireGuiEvidence: options.requireGuiEvidence,
  });
  const validation = validateAgentRuntimeP3Readiness(readiness);
  printSummary(readiness, validation);
  process.exit(validation.ok ? 0 : 1);
}

const { readiness, validation, result } = writeAgentRuntimeP3Evidence(repoRoot, {
  outputRoot: options.outputRoot,
  requireGuiEvidence: options.requireGuiEvidence,
});
printSummary(readiness, validation, result);
process.exit(validation.ok ? 0 : 1);
