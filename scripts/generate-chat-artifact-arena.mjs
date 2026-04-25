import path from "path";

import { writeChatRuntimeArtifactArenaLedger } from "./lib/chat-artifact-arena.mjs";

const repoRoot = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");

const { ledgerPath, ledger } = writeChatRuntimeArtifactArenaLedger({ repoRoot });

console.log(`ChatRuntime artifact arena ledger written to ${ledgerPath}`);
console.log(`Benchmarks: ${ledger.executedBenchmarkCount}/${ledger.benchmarkCount}`);
console.log(`Pending blind matches: ${ledger.pendingBlindMatchCount}`);
