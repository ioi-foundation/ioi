import path from "path";

import { writeStudioArtifactArenaLedger } from "./lib/studio-artifact-arena.mjs";

const repoRoot = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");

const { ledgerPath, ledger } = writeStudioArtifactArenaLedger({ repoRoot });

console.log(`Studio artifact arena ledger written to ${ledgerPath}`);
console.log(`Benchmarks: ${ledger.executedBenchmarkCount}/${ledger.benchmarkCount}`);
console.log(`Pending blind matches: ${ledger.pendingBlindMatchCount}`);
