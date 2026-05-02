#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const schemaPath = path.join(
  root,
  "docs",
  "implementation",
  "runtime-action-schema.json",
);
const schema = JSON.parse(fs.readFileSync(schemaPath, "utf8"));

const tsPath = path.join(
  root,
  "packages",
  "agent-ide",
  "src",
  "runtime",
  "generated",
  "action-schema.ts",
);
const rustPath = path.join(
  root,
  "apps",
  "autopilot",
  "src-tauri",
  "src",
  "generated",
  "runtime_action_schema.rs",
);

function tsArray(name, values) {
  return `export const ${name} = [\n${values.map((value) => `  ${JSON.stringify(value)},`).join("\n")}\n] as const;`;
}

function rustArray(name, values) {
  return `pub const ${name}: &[&str] = &[\n${values.map((value) => `    ${JSON.stringify(value)},`).join("\n")}\n];`;
}

const ts = `${tsArray("AGENT_ACTION_KINDS", schema.actionKinds)}

export const AGENT_ACTION_SCHEMA_VERSION = ${JSON.stringify(schema.schemaVersion)} as const;

${tsArray("AGENT_ACTION_ENTRY_KINDS", schema.entryKinds)}

${tsArray("AGENT_ACTION_TERMINAL_KINDS", schema.terminalKinds)}

${tsArray("AGENT_ACTION_COMPLETION_VERIFICATION_KINDS", schema.completionVerificationKinds)}
`;

const rust = `pub const RUNTIME_ACTION_SCHEMA_VERSION: &str = ${JSON.stringify(schema.schemaVersion)};

${rustArray("RUNTIME_ACTION_KINDS", schema.actionKinds)}

${rustArray("RUNTIME_ACTION_ENTRY_KINDS", schema.entryKinds)}

${rustArray("RUNTIME_ACTION_TERMINAL_KINDS", schema.terminalKinds)}

${rustArray("RUNTIME_ACTION_COMPLETION_VERIFICATION_KINDS", schema.completionVerificationKinds)}
`;

fs.mkdirSync(path.dirname(tsPath), { recursive: true });
fs.mkdirSync(path.dirname(rustPath), { recursive: true });
if (process.argv.includes("--check")) {
  const mismatches = [];
  if (!fs.existsSync(tsPath) || fs.readFileSync(tsPath, "utf8") !== ts) {
    mismatches.push(path.relative(root, tsPath));
  }
  if (!fs.existsSync(rustPath) || fs.readFileSync(rustPath, "utf8") !== rust) {
    mismatches.push(path.relative(root, rustPath));
  }
  if (mismatches.length > 0) {
    console.error("Runtime action contracts are out of date:");
    for (const mismatch of mismatches) {
      console.error(`- ${mismatch}`);
    }
    console.error("Run npm run generate:runtime-action-contracts.");
    process.exit(1);
  }
  console.log("Runtime action contracts are up to date.");
  process.exit(0);
}
fs.writeFileSync(tsPath, ts);
fs.writeFileSync(rustPath, rust);
