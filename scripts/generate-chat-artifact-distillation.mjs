import path from "path";

import { writeChatRuntimeArtifactDistillationLedger } from "./lib/chat-artifact-distillation.mjs";

const repoRoot = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");

const { ledgerPath, ledger } = writeChatRuntimeArtifactDistillationLedger({ repoRoot });

console.log(`ChatRuntime artifact distillation ledger written to ${ledgerPath}`);
console.log(`Proposals: ${ledger.proposalCount}`);
console.log(`Applied: ${ledger.appliedCount}`);
