import path from "path";

import {
  loadStudioArtifactParityCorpusSummary,
  writeStudioArtifactParityLoopLedger,
} from "./lib/studio-artifact-parity-loop.mjs";

const repoRoot = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");

const { summaryPath, corpusSummary } = loadStudioArtifactParityCorpusSummary({ repoRoot });

if (!corpusSummary) {
  throw new Error(
    `Studio artifact corpus summary is missing at '${summaryPath}'. Run the corpus harness first.`,
  );
}

const { ledgerPath, receipt } = writeStudioArtifactParityLoopLedger({
  repoRoot,
  corpusSummary,
});

console.log(`Studio artifact parity loop receipt written to ${ledgerPath}`);
console.log(`Decision: ${receipt.decision.kind}`);
if (receipt.selectedInterventionFamily) {
  console.log(`Selected intervention family: ${receipt.selectedInterventionFamily}`);
}
if (receipt.weakestTarget?.label) {
  console.log(`Weakest target: ${receipt.weakestTarget.label}`);
}
