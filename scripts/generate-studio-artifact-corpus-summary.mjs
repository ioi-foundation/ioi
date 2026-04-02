import path from "path";
import { fileURLToPath } from "url";

import { writeStudioArtifactCorpusIndex } from "./lib/studio-artifact-corpus.mjs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, "..");

const { outputPath, summary } = writeStudioArtifactCorpusIndex({ repoRoot });

console.log(
  `Studio artifact corpus summary written to ${outputPath} (${summary.totals.caseCount} primary cases, ${summary.auxiliaryCases.length} auxiliary cases)`,
);
