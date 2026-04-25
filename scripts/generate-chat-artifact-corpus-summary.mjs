import path from "path";
import { fileURLToPath } from "url";

import { writeChatRuntimeArtifactCorpusIndex } from "./lib/chat-artifact-corpus.mjs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, "..");

const { outputPath, summary } = writeChatRuntimeArtifactCorpusIndex({ repoRoot });

console.log(
  `ChatRuntime artifact corpus summary written to ${outputPath} (${summary.totals.caseCount} primary cases, ${summary.auxiliaryCases.length} auxiliary cases)`,
);
