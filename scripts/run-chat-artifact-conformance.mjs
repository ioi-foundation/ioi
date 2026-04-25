import fs from "fs";
import path from "path";

import { collectChatRuntimeArtifactConformanceReport } from "./lib/chat-artifact-conformance.mjs";

const repoRoot = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const report = collectChatRuntimeArtifactConformanceReport({ repoRoot });
const outputPath = path.join(
  repoRoot,
  "docs",
  "evidence",
  "chat-artifact-surface",
  "conformance-report.json",
);

fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, JSON.stringify(report, null, 2));

console.log(`ChatRuntime artifact conformance report written to ${outputPath}`);
for (const check of report.checks) {
  console.log(`${check.status.toUpperCase()}: ${check.id}`);
}

if (!report.passing) {
  process.exitCode = 1;
}
