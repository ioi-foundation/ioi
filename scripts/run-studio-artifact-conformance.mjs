import fs from "fs";
import path from "path";

import { collectStudioArtifactConformanceReport } from "./lib/studio-artifact-conformance.mjs";

const repoRoot = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const report = collectStudioArtifactConformanceReport({ repoRoot });
const outputPath = path.join(
  repoRoot,
  "docs",
  "evidence",
  "studio-artifact-surface",
  "conformance-report.json",
);

fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, JSON.stringify(report, null, 2));

console.log(`Studio artifact conformance report written to ${outputPath}`);
for (const check of report.checks) {
  console.log(`${check.status.toUpperCase()}: ${check.id}`);
}

if (!report.passing) {
  process.exitCode = 1;
}
