import path from "path";

import { writeChatRuntimeArtifactReleaseGates } from "./lib/chat-artifact-release-gates.mjs";

const repoRoot = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");

const { reportPath, report } = writeChatRuntimeArtifactReleaseGates({ repoRoot });

console.log(`ChatRuntime artifact release gates written to ${reportPath}`);
console.log(`Status: ${report.status}`);
console.log(`Blocking gates: ${report.summary.blockingGateIds.join(", ") || "none"}`);
