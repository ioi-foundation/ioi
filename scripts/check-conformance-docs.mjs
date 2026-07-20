#!/usr/bin/env node
import path from "node:path";
import { fileURLToPath } from "node:url";
import { checkConformanceDocsIntegrity } from "./lib/conformance-docs-integrity.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const failures = checkConformanceDocsIntegrity({ root });

if (failures.length > 0) {
  console.error("Conformance documentation integrity failed:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log(
  JSON.stringify(
    {
      ok: true,
      scope: "docs/conformance/**",
      checks: [
        "local-link-targets",
        "local-markdown-anchors",
        "platform-fault-matrix-contract",
        "platform-fault-matrix-jcs-sha256-profile",
        "sovereign-local-completeness-matrix-contract",
        "sovereign-local-completeness-jcs-sha256-profile",
      ],
    },
    null,
    2,
  ),
);
