#!/usr/bin/env node
import assert from "node:assert/strict";
import childProcess from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const outputPath = process.argv[2];

if (!outputPath) {
  throw new Error("usage: workflow-namespace-runner-host-smoke-proof.mjs <output-path>");
}

const repoRoot = process.cwd();

function runCommand(command, args) {
  const startedAtMs = Date.now();
  const result = childProcess.spawnSync(command, args, {
    cwd: repoRoot,
    encoding: "utf8",
    maxBuffer: 10 * 1024 * 1024,
  });
  return {
    command: [command, ...args].join(" "),
    status: result.status,
    signal: result.signal,
    durationMs: Date.now() - startedAtMs,
    stdout: String(result.stdout ?? ""),
    stderr: String(result.stderr ?? ""),
  };
}

function which(binary) {
  const result = runCommand("which", [binary]);
  return result.status === 0 ? result.stdout.trim() : null;
}

function publicCommand(result) {
  return {
    command: result.command,
    status: result.status,
    signal: result.signal,
    durationMs: result.durationMs,
    stdoutTail: result.stdout.slice(-4000),
    stderrTail: result.stderr.slice(-4000),
  };
}

const bwrapPath = which("bwrap");
const unsharePath = which("unshare");

assert.equal(typeof bwrapPath, "string");
assert.equal(typeof unsharePath, "string");

const commonBwrapArgs = [
  "5",
  "bwrap",
  "--ro-bind",
  "/usr",
  "/usr",
  "--ro-bind",
  "/bin",
  "/bin",
  "--ro-bind",
  "/lib",
  "/lib",
  "--ro-bind",
  "/lib64",
  "/lib64",
  "--proc",
  "/proc",
  "--dev",
  "/dev",
  "--tmpfs",
  "/tmp",
];

const bwrapTrue = runCommand("timeout", [...commonBwrapArgs, "/bin/true"]);
const bwrapNet = runCommand("timeout", [
  ...commonBwrapArgs,
  "--unshare-net",
  "/usr/bin/node",
  "-e",
  "const fs=require('node:fs'); const route=fs.readFileSync('/proc/net/route','utf8').trim(); console.log(route || 'NO_ROUTES');",
]);
const unshareTrue = runCommand("timeout", [
  "5",
  "unshare",
  "--user",
  "--map-root-user",
  "--mount",
  "--pid",
  "--fork",
  "/bin/true",
]);

assert.equal(bwrapTrue.status, 0, bwrapTrue.stderr);
assert.equal(bwrapNet.status, 0, bwrapNet.stderr);
assert.equal(unshareTrue.status, 0, unshareTrue.stderr);

const netRouteLines = bwrapNet.stdout.trim().split(/\n+/).filter(Boolean);
const nonHeaderRoutes = netRouteLines.filter((line) => !/^Iface\s+Destination\s+Gateway/i.test(line));
assert.deepEqual(nonHeaderRoutes, []);

const proof = {
  schemaVersion: "ioi.autopilot.stage80.namespace-runner-host-smoke-proof.v1",
  passed: true,
  generatedAt: new Date().toISOString(),
  status: "host-capable-product-not-wired",
  checks: {
    bwrapAvailable: Boolean(bwrapPath),
    unshareAvailable: Boolean(unsharePath),
    bwrapBasicNamespaceRuns: bwrapTrue.status === 0,
    bwrapNetworkNamespaceHasNoRoutes: nonHeaderRoutes.length === 0,
    unshareUserMountPidNamespaceRuns: unshareTrue.status === 0,
    productScopeStillFuturePlusGated: true,
  },
  hostTools: {
    bwrapPath,
    unsharePath,
  },
  commands: [bwrapTrue, bwrapNet, unshareTrue].map(publicCommand),
  recommendation: {
    trigger:
      "Only wire a namespace runner if product scope expands from allowlisted commands to arbitrary shell execution.",
    runnerProfile:
      "Use bwrap/nsjail with workspace bind mount, tmpfs /tmp, sanitized env, output cap, timeout, process cleanup, and default network deny.",
    currentScope:
      "Autopilot remains safer by keeping arbitrary shell approval-gated and proving file/env/symlink boundaries at the daemon policy layer.",
  },
  sources: [
    "internal-docs/reverse-engineering/antigravity-sandbox-boundary-report.md",
    "docs/evidence/autopilot-agent-studio-gui-chat-ux-compositor-harness-parity-plus/2026-05-25T12-40-00-000Z-stage75-reverse-engineering-sandbox-refresh/workflow-reverse-engineering-sandbox-delta-refresh-proof.json",
  ].filter((file) => fs.existsSync(path.join(repoRoot, file))),
};

fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`);
