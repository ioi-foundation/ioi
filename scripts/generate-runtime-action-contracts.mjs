#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

function parseCliMode(args) {
  if (args.length === 1 && args[0] === "--write") return "write";
  if (args.length === 1 && args[0] === "--check") return "check";
  throw new Error(
    `Unsupported runtime-action generator arguments: ${JSON.stringify(args)}. ` +
      "Supported invocations are exactly --write or --check.",
  );
}

let cliMode;
try {
  cliMode = parseCliMode(process.argv.slice(2));
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(2);
}

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const { safeRepositoryPath } = await import(
  "./lib/repository-path-boundary.mjs"
);
const schemaRelativePath =
  "docs/architecture/_meta/schemas/runtime-action-schema.json";
const targetRelativePaths = [
  "packages/hypervisor-workbench/src/runtime/generated/action-schema.ts",
  "crates/types/src/app/generated/runtime_action_schema.rs",
];

function safePath(relativePath, at, mustExist = false) {
  return safeRepositoryPath({
    root,
    relativePath,
    at,
    mustExist,
  });
}

const schema = JSON.parse(
  fs.readFileSync(
    safePath(schemaRelativePath, "runtime action schema read", true),
    "utf8",
  ),
);

function tsArray(name, values) {
  return `export const ${name} = [\n${values.map((value) => `  ${JSON.stringify(value)},`).join("\n")}\n] as const;`;
}

function rustArray(name, values) {
  if (values.length <= 2) {
    return `pub const ${name}: &[&str] = &[${values.map((value) => JSON.stringify(value)).join(", ")}];`;
  }
  return `pub const ${name}: &[&str] = &[\n${values.map((value) => `    ${JSON.stringify(value)},`).join("\n")}\n];`;
}

function documentedRustArray(name, values, doc) {
  return `/// ${doc}\n${rustArray(name, values)}`;
}

const ts = `${tsArray("AGENT_ACTION_KINDS", schema.actionKinds)}

export const AGENT_ACTION_SCHEMA_VERSION = ${JSON.stringify(schema.schemaVersion)} as const;

${tsArray("AGENT_ACTION_ENTRY_KINDS", schema.entryKinds)}

${tsArray("AGENT_ACTION_TERMINAL_KINDS", schema.terminalKinds)}

${tsArray("AGENT_ACTION_COMPLETION_VERIFICATION_KINDS", schema.completionVerificationKinds)}
`;

const rust = `//! Generated runtime action schema constants shared with Hypervisor Workbench.

/// Runtime action schema version shared by Rust and Hypervisor Workbench clients.
pub const RUNTIME_ACTION_SCHEMA_VERSION: &str = ${JSON.stringify(schema.schemaVersion)};

${documentedRustArray("RUNTIME_ACTION_KINDS", schema.actionKinds, "All runtime action kinds accepted by the shared action schema.")}

${documentedRustArray("RUNTIME_ACTION_ENTRY_KINDS", schema.entryKinds, "Runtime action kinds that can start an action graph.")}

${documentedRustArray("RUNTIME_ACTION_TERMINAL_KINDS", schema.terminalKinds, "Runtime action kinds that terminate an action graph.")}

${documentedRustArray("RUNTIME_ACTION_COMPLETION_VERIFICATION_KINDS", schema.completionVerificationKinds, "Runtime action kinds that can satisfy completion verification.")}
`;

const renderedTargets = [
  [targetRelativePaths[0], ts],
  [targetRelativePaths[1], rust],
];
if (cliMode === "check") {
  const mismatches = [];
  for (const [relativePath, content] of renderedTargets) {
    const targetPath = safePath(
      relativePath,
      `runtime action generated target ${relativePath}`,
    );
    if (!fs.existsSync(targetPath)) {
      mismatches.push(relativePath);
      continue;
    }
    const checkedPath = safePath(
      relativePath,
      `runtime action generated target read ${relativePath}`,
      true,
    );
    if (fs.readFileSync(checkedPath, "utf8") !== content) {
      mismatches.push(relativePath);
    }
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
for (const [relativePath, content] of renderedTargets) {
  const targetPath = safePath(
    relativePath,
    `runtime action generated target ${relativePath}`,
  );
  fs.mkdirSync(path.dirname(targetPath), { recursive: true });
  fs.writeFileSync(
    safePath(
      relativePath,
      `runtime action generated target write ${relativePath}`,
    ),
    content,
  );
}
