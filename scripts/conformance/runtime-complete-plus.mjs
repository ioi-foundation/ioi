#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const evidenceDir = path.join(root, "docs/evidence/architectural-improvements-broad");
fs.mkdirSync(evidenceDir, { recursive: true });

const commands = [
  ["npm", ["run", "check:pre-next-leg"]],
  ["npm", ["run", "check:execution-surface-leg"]],
  ["npm", ["run", "build:agent-sdk"]],
  ["npm", ["test", "--workspace=@ioi/agent-sdk"]],
  ["npm", ["run", "evidence:runtime-complete-plus"]],
  ["npm", ["run", "test:daemon-runtime-api"]],
  ["npm", ["run", "test:runtime-events"]],
  ["npm", ["run", "test:mcp-skills-hooks"]],
  ["npm", ["run", "test:subagents"]],
  ["npm", ["run", "test:agentgres-runtime-state"]],
  ["npm", ["run", "test:workflow-compositor-dogfood"]],
  ["npm", ["run", "test:hosted-workers"]],
  ["npm", ["run", "test:autopilot-gui-harness"]],
  ["npm", ["run", "validate:agent-runtime-p3"]],
  ["npm", ["run", "validate:agent-runtime-superiority"]],
  ["npm", ["run", "validate:cursor-sdk-parity"]],
];

const results = commands.map(([command, args]) => {
  const startedAt = new Date().toISOString();
  const result = spawnSync(command, args, {
    cwd: root,
    encoding: "utf8",
    env: process.env,
  });
  return {
    command: [command, ...args].join(" "),
    startedAt,
    completedAt: new Date().toISOString(),
    status: result.status ?? 1,
    signal: result.signal,
    stdout: result.stdout,
    stderr: result.stderr,
  };
});

const summary = {
  schemaVersion: "ioi.architectural-improvements-broad.validation.v1",
  generatedAt: new Date().toISOString(),
  status: results.every((result) => result.status === 0) ? "passed" : "failed",
  results,
  evidence: {
    checklist: "docs/evidence/architectural-improvements-broad/checklist.json",
    sdkEvidence: "docs/evidence/architectural-improvements-broad/evidence-summary.json",
    validationSummary: "docs/evidence/architectural-improvements-broad/validation-summary.json",
  },
};

fs.writeFileSync(
  path.join(evidenceDir, "validation-summary.json"),
  `${JSON.stringify(summary, null, 2)}\n`,
);

for (const result of results) {
  console.log(`${result.status === 0 ? "pass" : "fail"} ${result.command}`);
}
console.log(`Evidence: ${path.relative(root, path.join(evidenceDir, "validation-summary.json"))}`);

if (summary.status !== "passed") {
  process.exit(1);
}
