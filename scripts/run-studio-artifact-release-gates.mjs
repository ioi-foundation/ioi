import path from "path";

import { writeStudioArtifactReleaseGates } from "./lib/studio-artifact-release-gates.mjs";

const repoRoot = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");

const { reportPath, report } = writeStudioArtifactReleaseGates({ repoRoot });

console.log(`Studio artifact release gates written to ${reportPath}`);
console.log(`Status: ${report.status}`);
console.log(`Blocking gates: ${report.summary.blockingGateIds.join(", ") || "none"}`);
