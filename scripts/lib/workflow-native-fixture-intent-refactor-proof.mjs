#!/usr/bin/env node
import assert from "node:assert/strict";
import childProcess from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const outputPath = process.argv[2];

if (!outputPath) {
  throw new Error("usage: workflow-native-fixture-intent-refactor-proof.mjs <output-path>");
}

const repoRoot = process.cwd();

function readRepoFile(relativePath) {
  return fs.readFileSync(path.join(repoRoot, relativePath), "utf8");
}

function tailText(value, max = 4000) {
  const text = String(value ?? "");
  return text.length > max ? text.slice(-max) : text;
}

function runCommand(command, args) {
  const startedAtMs = Date.now();
  const result = childProcess.spawnSync(command, args, {
    cwd: repoRoot,
    encoding: "utf8",
    maxBuffer: 10 * 1024 * 1024,
  });
  const durationMs = Date.now() - startedAtMs;
  return {
    command: [command, ...args].join(" "),
    status: result.status,
    signal: result.signal,
    durationMs,
    stdoutTail: tailText(result.stdout),
    stderrTail: tailText(result.stderr),
  };
}

const modelMounting = readRepoFile("packages/runtime-daemon/src/model-mounting.mjs");
const intentModule = readRepoFile("packages/runtime-daemon/src/model-mounting/native-fixture-intent.mjs");
const intentTest = readRepoFile("packages/runtime-daemon/src/model-mounting/native-fixture-intent.test.mjs");

assert.match(modelMounting, /native-fixture-intent\.mjs/);
assert.doesNotMatch(modelMounting, /function nativeFixtureQueryWorkspaceConstrained\(/);
assert.doesNotMatch(modelMounting, /function nativeFixtureConversationReply\(/);
assert.match(intentModule, /export function nativeFixtureQueryWorkspaceConstrained/);
assert.match(intentModule, /autopilot plan progress/);
assert.match(intentTest, /classifies autopilot plan progress as workspace-constrained/);

const commandResults = [
  runCommand("node", ["--check", "packages/runtime-daemon/src/model-mounting.mjs"]),
  runCommand("node", ["--check", "packages/runtime-daemon/src/model-mounting/native-fixture-intent.mjs"]),
  runCommand("node", ["--test", "packages/runtime-daemon/src/model-mounting/native-fixture-intent.test.mjs"]),
  runCommand("node", ["--test", "packages/runtime-daemon/src/model-mounting/native-fixture-repo-aware.test.mjs"]),
  runCommand("node", ["--check", "scripts/lib/workflow-live-late-progress-recap-summary-proof.mjs"]),
  runCommand("node", ["--check", "scripts/lib/workflow-evidence-manifest-proof.mjs"]),
];

for (const result of commandResults) {
  assert.equal(result.status, 0, `${result.command} failed\n${result.stderrTail}`);
  assert.equal(result.signal, null, `${result.command} signaled ${result.signal}`);
}

const proof = {
  schemaVersion: "ioi.autopilot.stage78.native-fixture-intent-refactor-proof.v1",
  passed: true,
  generatedAt: new Date().toISOString(),
  checks: {
    modelMountingImportsIntentModule: /native-fixture-intent\.mjs/.test(modelMounting),
    modelMountingNoLongerOwnsWorkspaceClassifier: !/function nativeFixtureQueryWorkspaceConstrained\(/.test(modelMounting),
    modelMountingNoLongerOwnsConversationFixture: !/function nativeFixtureConversationReply\(/.test(modelMounting),
    intentModuleExportsWorkspaceClassifier: /export function nativeFixtureQueryWorkspaceConstrained/.test(intentModule),
    planProgressWorkspaceSignalCovered: /autopilot plan progress/.test(intentModule),
    planProgressRegressionTestPresent: /classifies autopilot plan progress as workspace-constrained/.test(intentTest),
    focusedCommandsPassed: commandResults.every((result) => result.status === 0 && result.signal === null),
  },
  commands: commandResults,
  artifacts: {
    modelMounting: "packages/runtime-daemon/src/model-mounting.mjs",
    intentModule: "packages/runtime-daemon/src/model-mounting/native-fixture-intent.mjs",
    intentTest: "packages/runtime-daemon/src/model-mounting/native-fixture-intent.test.mjs",
    repoAwareTest: "packages/runtime-daemon/src/model-mounting/native-fixture-repo-aware.test.mjs",
  },
};

fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`);
