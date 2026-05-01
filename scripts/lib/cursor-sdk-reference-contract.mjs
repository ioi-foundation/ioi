import childProcess from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export const CURSOR_SDK_REFERENCE_SCHEMA_VERSION = "ioi.cursor-sdk-reference.v1";

export const REQUIRED_CURSOR_REFERENCE_MODULES = Object.freeze([
  "dist/esm/stubs.d.ts",
  "dist/esm/agent.d.ts",
  "dist/esm/options.d.ts",
  "dist/esm/run.d.ts",
  "dist/esm/messages.d.ts",
  "dist/esm/errors.d.ts",
  "dist/esm/cloud-api-client.d.ts",
  "dist/esm/run-event-tailer.d.ts",
  "dist/esm/run-interaction-accumulator.d.ts",
  "dist/esm/platform.d.ts",
  "dist/esm/subagent-conversion.d.ts",
]);

export const REQUIRED_CURSOR_CAPABILITIES = Object.freeze([
  "Agent.create",
  "Agent.resume",
  "Agent.prompt",
  "Agent.list",
  "Agent.listRuns",
  "Agent.get",
  "Agent.getRun",
  "Agent.archive",
  "Agent.unarchive",
  "Agent.delete",
  "Agent.messages.list",
  "Cursor.me",
  "Cursor.models.list",
  "Cursor.repositories.list",
  "agent.send",
  "agent.close",
  "agent.reload",
  "Run.stream",
  "Run.wait",
  "Run.cancel",
  "Run.conversation",
  "mcpServers",
  "agents",
  "sandboxOptions",
  "structured_errors",
]);

export function collectCursorSdkReference({
  repoRoot = process.cwd(),
  evidenceDir,
  packageName = "@cursor/sdk",
} = {}) {
  const npmView = JSON.parse(run("npm", ["view", packageName, "--json"], repoRoot).stdout);
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-cursor-sdk-ref-"));
  const packJson = JSON.parse(
    run("npm", ["pack", packageName, "--pack-destination", tempDir, "--json"], repoRoot).stdout,
  );
  const tarball = path.join(tempDir, packJson[0].filename);
  run("tar", ["-xzf", tarball, "-C", tempDir], repoRoot);
  const packageRoot = path.join(tempDir, "package");
  const packageJson = readJson(path.join(packageRoot, "package.json"));
  const modules = {};
  for (const modulePath of REQUIRED_CURSOR_REFERENCE_MODULES) {
    const absolutePath = path.join(packageRoot, modulePath);
    modules[modulePath] = fs.existsSync(absolutePath)
      ? extractDtsModuleFacts(fs.readFileSync(absolutePath, "utf8"))
      : { missing: true, exports: [], interfaces: [], classes: [], methods: [] };
  }
  const reference = {
    schemaVersion: CURSOR_SDK_REFERENCE_SCHEMA_VERSION,
    capturedAt: new Date().toISOString(),
    packageName,
    npmVersion: npmView.version,
    distTagLatest: npmView["dist-tags"]?.latest,
    engines: npmView.engines,
    packageJson: {
      name: packageJson.name,
      version: packageJson.version,
      type: packageJson.type,
      exports: packageJson.exports,
      dependencies: packageJson.dependencies,
      optionalDependencies: packageJson.optionalDependencies,
    },
    capabilities: REQUIRED_CURSOR_CAPABILITIES,
    modules,
  };
  if (evidenceDir) {
    fs.mkdirSync(evidenceDir, { recursive: true });
    fs.writeFileSync(path.join(evidenceDir, "reference-api.json"), `${JSON.stringify(reference, null, 2)}\n`);
  }
  return reference;
}

export function assertReferenceInventoryComplete(reference) {
  const missingModules = Object.entries(reference.modules)
    .filter(([, facts]) => facts.missing)
    .map(([modulePath]) => modulePath);
  if (missingModules.length > 0) {
    throw new Error(`Cursor SDK reference modules missing: ${missingModules.join(", ")}`);
  }
  for (const capability of REQUIRED_CURSOR_CAPABILITIES) {
    if (!reference.capabilities.includes(capability)) {
      throw new Error(`Cursor capability not classified: ${capability}`);
    }
  }
}

function extractDtsModuleFacts(source) {
  return {
    exports: [...source.matchAll(/export\s+(?:declare\s+)?(?:class|interface|type|const|function)\s+([A-Za-z0-9_]+)/g)].map(
      (match) => match[1],
    ),
    interfaces: [...source.matchAll(/interface\s+([A-Za-z0-9_]+)/g)].map((match) => match[1]),
    classes: [...source.matchAll(/class\s+([A-Za-z0-9_]+)/g)].map((match) => match[1]),
    methods: [...source.matchAll(/(?:static\s+)?([A-Za-z0-9_]+)\s*\(/g)].map((match) => match[1]),
  };
}

function run(command, args, cwd) {
  const result = childProcess.spawnSync(command, args, {
    cwd,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} failed\n${result.stderr}`);
  }
  return result;
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}
