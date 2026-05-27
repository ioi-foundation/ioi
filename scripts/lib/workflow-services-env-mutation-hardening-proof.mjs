#!/usr/bin/env node
import assert from "node:assert/strict";
import childProcess from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const outputPath = process.argv[2];

if (!outputPath) {
  throw new Error("usage: workflow-services-env-mutation-hardening-proof.mjs <output-path>");
}

const servicesSrc = "crates/services/src";
const forbiddenEnvMutation = /\b(?:std::env|env)::(?:set_var|remove_var)\b/;

function listRustFiles(root) {
  const files = [];
  const stack = [root];
  while (stack.length > 0) {
    const current = stack.pop();
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const absolute = path.join(current, entry.name);
      if (entry.isDirectory()) {
        stack.push(absolute);
      } else if (entry.isFile() && entry.name.endsWith(".rs")) {
        files.push(absolute);
      }
    }
  }
  return files.sort();
}

function isTestFile(filePath) {
  const normalized = filePath.split(path.sep).join("/");
  const basename = path.basename(filePath);
  return (
    basename === "tests.rs" ||
    basename.endsWith("_tests.rs") ||
    normalized.includes("/tests/") ||
    normalized.includes("/tests_parts/")
  );
}

const envMutationMatches = [];
for (const filePath of listRustFiles(servicesSrc).filter(isTestFile)) {
  const text = fs.readFileSync(filePath, "utf8");
  const lines = text.split("\n");
  lines.forEach((line, index) => {
    if (forbiddenEnvMutation.test(line)) {
      envMutationMatches.push({
        file: filePath,
        line: index + 1,
        text: line.trim(),
      });
    }
  });
}
assert.deepEqual(envMutationMatches, []);

const startedAtMs = Date.now();
const result = childProcess.spawnSync("cargo", ["test", "-p", "ioi-services", "--lib"], {
  cwd: process.cwd(),
  encoding: "utf8",
  maxBuffer: 80 * 1024 * 1024,
});
const durationMs = Date.now() - startedAtMs;
const output = `${result.stdout ?? ""}\n${result.stderr ?? ""}`;

assert.equal(result.status, 0, output.slice(-12000));
assert.equal(result.signal, null);
assert.match(output, /test result: ok\./);
assert.match(output, /2268 passed/);
assert.match(output, /0 failed/);
assert.match(output, /4 ignored/);

const proof = {
  schemaVersion: "ioi.autopilot.stage88.services-env-mutation-hardening-proof.v1",
  passed: true,
  generatedAt: new Date().toISOString(),
  checks: {
    noServicesTestEnvMutations: envMutationMatches.length === 0,
    defaultParallelServicesSuitePassed: result.status === 0,
    noSignal: result.signal === null,
    testResultOk: /test result: ok\./.test(output),
  },
  metrics: {
    durationMs,
    passed: 2268,
    failed: 0,
    ignored: 4,
    envMutationMatches: envMutationMatches.length,
  },
  command: {
    command: "cargo test -p ioi-services --lib",
    status: result.status,
    signal: result.signal,
    stdoutTail: String(result.stdout ?? "").slice(-12000),
    stderrTail: String(result.stderr ?? "").slice(-4000),
  },
};

fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`);
