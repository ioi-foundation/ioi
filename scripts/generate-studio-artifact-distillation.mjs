import path from "path";

import { writeStudioArtifactDistillationLedger } from "./lib/studio-artifact-distillation.mjs";

const repoRoot = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");

const { ledgerPath, ledger } = writeStudioArtifactDistillationLedger({ repoRoot });

console.log(`Studio artifact distillation ledger written to ${ledgerPath}`);
console.log(`Proposals: ${ledger.proposalCount}`);
console.log(`Applied: ${ledger.appliedCount}`);
