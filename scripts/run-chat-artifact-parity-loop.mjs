import path from "path";

import {
  loadChatRuntimeArtifactParityCorpusSummary,
  writeChatRuntimeArtifactParityLoopLedger,
} from "./lib/chat-artifact-parity-loop.mjs";

const repoRoot = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");

const { summaryPath, corpusSummary } = loadChatRuntimeArtifactParityCorpusSummary({ repoRoot });

if (!corpusSummary) {
  throw new Error(
    `ChatRuntime artifact corpus summary is missing at '${summaryPath}'. Run the corpus harness first.`,
  );
}

const { ledgerPath, receipt } = writeChatRuntimeArtifactParityLoopLedger({
  repoRoot,
  corpusSummary,
});

console.log(`ChatRuntime artifact parity loop receipt written to ${ledgerPath}`);
console.log(`Decision: ${receipt.decision.kind}`);
if (receipt.selectedInterventionFamily) {
  console.log(`Selected intervention family: ${receipt.selectedInterventionFamily}`);
}
if (receipt.weakestTarget?.label) {
  console.log(`Weakest target: ${receipt.weakestTarget.label}`);
}
