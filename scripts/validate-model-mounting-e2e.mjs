#!/usr/bin/env node
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { startRuntimeDaemonService } from "../packages/runtime-daemon/src/index.mjs";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const defaultOutputRoot = path.join(repoRoot, "docs/evidence/model-mounting-e2e");
const schemaVersion = "ioi.model-mounting.e2e.v1";
const secretRedaction = "[REDACTED]";

function timestamp() {
  return new Date().toISOString().replaceAll(":", "-").replace(/\.\d{3}Z$/, "Z");
}

function parseArgs(argv) {
  const options = {
    outputRoot: defaultOutputRoot,
    skipGui: process.env.IOI_MODEL_MOUNTING_E2E_SKIP_GUI === "1",
  };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--output-root") {
      options.outputRoot = path.resolve(argv[++index]);
    } else if (arg === "--skip-gui") {
      options.skipGui = true;
    } else if (arg === "--include-gui") {
      options.skipGui = false;
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }
  return options;
}

function redactText(text, secretNeedles = []) {
  let redacted = String(text ?? "");
  for (const needle of secretNeedles) {
    if (needle) {
      redacted = redacted.split(needle).join(secretRedaction);
    }
  }
  return redacted;
}

function sanitize(value, secretNeedles = []) {
  return JSON.parse(redactText(JSON.stringify(value), secretNeedles));
}

async function requestJson(endpoint, route, { method = "GET", body, token } = {}) {
  const response = await fetch(`${endpoint}${route}`, {
    method,
    headers: {
      accept: "application/json",
      ...(body === undefined ? {} : { "content-type": "application/json" }),
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await response.text();
  const json = text ? JSON.parse(text) : undefined;
  return { response, json };
}

async function requestSse(endpoint, route, { method = "POST", body, token } = {}) {
  const response = await fetch(`${endpoint}${route}`, {
    method,
    headers: {
      accept: "text/event-stream",
      ...(body === undefined ? {} : { "content-type": "application/json" }),
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await response.text();
  return { response, text, events: parseSseEvents(text) };
}

async function requestSseAndAbortAfterFirstChunk(endpoint, route, { method = "POST", body, token } = {}) {
  const controller = new AbortController();
  const response = await fetch(`${endpoint}${route}`, {
    method,
    signal: controller.signal,
    headers: {
      accept: "text/event-stream",
      ...(body === undefined ? {} : { "content-type": "application/json" }),
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const reader = response.body.getReader();
  const first = await reader.read();
  const text = new TextDecoder().decode(first.value ?? new Uint8Array());
  controller.abort();
  try {
    await reader.read();
  } catch {
    // Aborting an SSE response rejects the reader on some Node versions.
  }
  return { response, text };
}

function parseSseEvents(text) {
  return String(text)
    .trim()
    .split(/\n\n+/)
    .filter(Boolean)
    .map((block) => {
      const lines = block.split(/\n/);
      const event = lines.find((line) => line.startsWith("event: "))?.slice("event: ".length) ?? "message";
      const dataText = lines
        .filter((line) => line.startsWith("data: "))
        .map((line) => line.slice("data: ".length))
        .join("\n");
      return { event, data: dataText === "[DONE]" ? "[DONE]" : dataText ? JSON.parse(dataText) : null };
    });
}

function parseOpenAiSseChunks(text) {
  return String(text)
    .trim()
    .split(/\n\n+/)
    .filter(Boolean)
    .map((block) => {
      const dataText = block
        .split(/\n/)
        .filter((line) => line.startsWith("data: "))
        .map((line) => line.slice("data: ".length))
        .join("\n");
      return dataText === "[DONE]" ? "[DONE]" : JSON.parse(dataText);
    });
}

async function expectOk(endpoint, route, options) {
  const result = await requestJson(endpoint, route, options);
  assert.equal(result.response.ok, true, `${route} -> ${result.response.status} ${JSON.stringify(result.json)}`);
  return result.json;
}

async function waitForReceipt(endpoint, predicate, { timeoutMs = 3000 } = {}) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    const receipts = await expectOk(endpoint, "/api/v1/receipts");
    const receipt = receipts.find(predicate);
    if (receipt) return receipt;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  assert.fail("Expected receipt was not recorded before timeout.");
}

function assertNativeLocalStreamReceipt(receipt, { kind, streamKind, selectedModel, endpointId, status, reason } = {}) {
  assert.equal(receipt.kind, kind);
  assert.equal(receipt.redaction, "redacted");
  assert.equal(receipt.details.streamKind, streamKind);
  assert.equal(receipt.details.routeId, "route.native-local");
  assert.equal(receipt.details.selectedModel, selectedModel);
  assert.equal(receipt.details.endpointId, endpointId);
  assert.equal(receipt.details.providerId, "provider.autopilot.local");
  assert.equal(receipt.details.backendId, "backend.autopilot.native-local.fixture");
  assert.equal(receipt.details.selectedBackend, "backend.autopilot.native-local.fixture");
  assert.equal(receipt.details.streamSource, "provider_native");
  assert.equal(typeof receipt.details.invocationReceiptId, "string");
  assert.ok(receipt.details.backendEvidenceRefs.includes("autopilot_native_local_provider_native_stream"));
  if (status) {
    assert.equal(receipt.details.status, status);
  }
  if (reason) {
    assert.equal(receipt.details.reason, reason);
  }
}

function resolveCliCommand(evidence) {
  const explicit = process.env.IOI_MODEL_MOUNTING_CLI_BIN;
  if (explicit) {
    return { command: explicit, prefix: [] };
  }
  const binaryName = process.platform === "win32" ? "cli.exe" : "cli";
  const targetBinary = path.join(repoRoot, "target", "debug", binaryName);
  if (fs.existsSync(targetBinary) && !cliTargetNeedsRebuild(targetBinary)) {
    return { command: targetBinary, prefix: [] };
  }
  const build = spawnSync("cargo", ["build", "-p", "ioi-cli", "--bin", "cli"], {
    cwd: repoRoot,
    encoding: "utf8",
  });
  evidence.commands.push({
    command: "cargo build -p ioi-cli --bin cli",
    status: build.status === 0 ? "passed" : "failed",
  });
  if (build.status !== 0) {
    throw new Error(`Failed to build CLI:\n${build.stdout}\n${build.stderr}`);
  }
  return { command: targetBinary, prefix: [] };
}

function cliTargetNeedsRebuild(targetBinary) {
  const targetMtime = fs.statSync(targetBinary).mtimeMs;
  const cliSources = [
    path.join(repoRoot, "crates/cli/src/main.rs"),
    path.join(repoRoot, "crates/cli/src/commands/models.rs"),
    path.join(repoRoot, "crates/cli/src/commands/backends.rs"),
    path.join(repoRoot, "crates/cli/src/commands/model_mount_http.rs"),
    path.join(repoRoot, "crates/cli/src/commands/vault.rs"),
  ];
  return cliSources.some((source) => fs.existsSync(source) && fs.statSync(source).mtimeMs > targetMtime);
}

function runCli(cli, args, { endpoint, token, secretNeedles, evidence, env = {} }) {
  const commandArgs = [args[0], "--endpoint", endpoint, ...args.slice(1)];
  const command = [cli.command, ...cli.prefix, ...commandArgs];
  return new Promise((resolve, reject) => {
    const child = spawn(command[0], command.slice(1), {
      cwd: repoRoot,
      env: {
        ...process.env,
        IOI_DAEMON_ENDPOINT: endpoint,
        IOI_DAEMON_TOKEN: token,
        ...env,
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    let settled = false;
    const printableCommand = command.map((part) => (part === token ? secretRedaction : part)).join(" ");
    const timeout = setTimeout(() => {
      if (settled) return;
      settled = true;
      child.kill("SIGTERM");
      const redactedStdout = redactText(stdout, secretNeedles);
      const redactedStderr = redactText(stderr, secretNeedles);
      evidence.commands.push({
        command: printableCommand,
        status: "failed",
        stdoutBytes: redactedStdout.length,
        stderrBytes: redactedStderr.length,
      });
      reject(new Error(`${printableCommand} timed out\n${redactedStdout}\n${redactedStderr}`));
    }, 20000);
    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });
    child.on("error", (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      evidence.commands.push({
        command: printableCommand,
        status: "failed",
        stdoutBytes: redactText(stdout, secretNeedles).length,
        stderrBytes: redactText(stderr, secretNeedles).length,
      });
      reject(error);
    });
    child.on("close", (code, signal) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      const redactedStdout = redactText(stdout, secretNeedles);
      const redactedStderr = redactText(stderr, secretNeedles);
      evidence.commands.push({
        command: printableCommand,
        status: code === 0 ? "passed" : "failed",
        stdoutBytes: redactedStdout.length,
        stderrBytes: redactedStderr.length,
      });
      if (code !== 0) {
        reject(new Error(`${printableCommand} exited with ${code ?? signal}\n${redactedStdout}\n${redactedStderr}`));
        return;
      }
      resolve(redactedStdout.trim() ? JSON.parse(redactedStdout) : null);
    });
  });
}

async function runStep(evidence, name, fn) {
  const startedAt = new Date().toISOString();
  try {
    const summary = await fn();
    evidence.steps.push({
      name,
      status: "passed",
      startedAt,
      completedAt: new Date().toISOString(),
      summary: summary ?? null,
    });
    return summary;
  } catch (error) {
    evidence.steps.push({
      name,
      status: "failed",
      startedAt,
      completedAt: new Date().toISOString(),
      error: error instanceof Error ? error.message : String(error),
    });
    throw error;
  }
}

function scanFilesForSecrets(roots, needles) {
  const findings = [];
  for (const root of roots) {
    if (!root || !fs.existsSync(root)) continue;
    const pending = [root];
    while (pending.length > 0) {
      const current = pending.pop();
      const stat = fs.statSync(current);
      if (stat.isDirectory()) {
        for (const entry of fs.readdirSync(current)) {
          pending.push(path.join(current, entry));
        }
        continue;
      }
      if (!stat.isFile() || stat.size > 8 * 1024 * 1024) continue;
      let text = "";
      try {
        text = fs.readFileSync(current, "utf8");
      } catch {
        continue;
      }
      for (const needle of needles) {
        if (needle && text.includes(needle)) {
          findings.push({ file: current, needleHash: `sha256:${stableHash(needle)}` });
        }
      }
    }
  }
  return { passed: findings.length === 0, findings };
}

async function sha256Hex(text) {
  const { createHash } = await import("node:crypto");
  return createHash("sha256").update(text).digest("hex");
}

function stableHash(text) {
  let hash = 0;
  for (const char of String(text)) {
    hash = (hash * 31 + char.charCodeAt(0)) >>> 0;
  }
  return hash.toString(16).padStart(8, "0");
}

function latestResultJson(root) {
  if (!fs.existsSync(root)) return null;
  const candidates = fs
    .readdirSync(root, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => path.join(root, entry.name, "result.json"))
    .filter((candidate) => fs.existsSync(candidate))
    .sort();
  return candidates.at(-1) ?? null;
}

function runGuiValidation(evidence, outputRoot, secretNeedles) {
  const guiRoot = path.join(outputRoot, "gui");
  fs.mkdirSync(guiRoot, { recursive: true });
  const result = spawnSync("node", ["scripts/run-model-mounts-gui-validation.mjs", "--output-root", guiRoot], {
    cwd: repoRoot,
    encoding: "utf8",
  });
  const stdout = redactText(result.stdout, secretNeedles);
  const stderr = redactText(result.stderr, secretNeedles);
  evidence.commands.push({
    command: "node scripts/run-model-mounts-gui-validation.mjs --output-root <evidence>/gui",
    status: result.status === 0 ? "passed" : "failed",
    stdoutBytes: stdout.length,
    stderrBytes: stderr.length,
  });
  assert.equal(result.status, 0, `Mounts GUI validation failed:\n${stdout}\n${stderr}`);
  const resultPath = latestResultJson(guiRoot);
  assert.ok(resultPath, "Mounts GUI validation did not write result.json");
  const guiResult = JSON.parse(fs.readFileSync(resultPath, "utf8"));
  assert.equal(guiResult.passed, true);
  assert.equal(guiResult.secretScan?.passed, true);
  assert.ok(Array.isArray(guiResult.screenshots) && guiResult.screenshots.length >= 8);
  assert.ok(guiResult.screenshots.every((item) => item.capture_mode === "window"));
  return {
    resultPath,
    screenshotCount: guiResult.screenshots.length,
    captureModes: [...new Set(guiResult.screenshots.map((item) => item.capture_mode))],
    snapshotCounts: guiResult.seed?.snapshot_counts ?? null,
  };
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const outputRoot = path.join(options.outputRoot, timestamp());
  fs.mkdirSync(outputRoot, { recursive: true });

  const workspaceDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-model-mounting-e2e-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-model-mounting-e2e-state-"));
  const evidence = {
    schemaVersion,
    startedAt: new Date().toISOString(),
    outputRoot,
    workspaceDir,
    stateDir,
    daemonEndpoint: null,
    steps: [],
    commands: [],
    artifacts: {},
    passed: false,
    error: null,
  };
  const secretNeedles = [];
  let daemon = null;
  let mainGrant = null;
  let nativeReceiptId = null;
  let nativeStreamCompletionReceiptId = null;
  let nativeStreamCompletionInvocationReceiptId = null;
  let nativeStreamAbortReceiptId = null;
  let nativeStreamAbortInvocationReceiptId = null;
  let runtimeSurveyReceiptId = null;
  let ephemeralReceiptId = null;
  let ephemeralToolReceiptIds = [];
  const cliVaultRef = "vault://provider/e2e-cli/api-key";
  let cliVaultHash = null;

  try {
    daemon = await startRuntimeDaemonService({ cwd: workspaceDir, stateDir });
    evidence.daemonEndpoint = daemon.endpoint;

    await runStep(evidence, "server status and fail-closed token probes", async () => {
      const status = await expectOk(daemon.endpoint, "/api/v1/server/status");
      assert.equal(status.schemaVersion, "ioi.model-mounting.runtime.v1");

      const unauthenticated = await requestJson(daemon.endpoint, "/api/v1/chat", {
        method: "POST",
        body: { input: "blocked" },
      });
      assert.equal(unauthenticated.response.status, 401);

      const deniedGrant = await expectOk(daemon.endpoint, "/api/v1/tokens", {
        method: "POST",
        body: { allowed: ["model.chat:*"], denied: ["model.chat:*"] },
      });
      secretNeedles.push(deniedGrant.token);
      const denied = await requestJson(daemon.endpoint, "/api/v1/chat", {
        method: "POST",
        token: deniedGrant.token,
        body: { input: "blocked by deny" },
      });
      assert.equal(denied.response.status, 403);

      const expiredGrant = await expectOk(daemon.endpoint, "/api/v1/tokens", {
        method: "POST",
        body: { allowed: ["model.chat:*"], expiresAt: "2000-01-01T00:00:00.000Z" },
      });
      secretNeedles.push(expiredGrant.token);
      const expired = await requestJson(daemon.endpoint, "/api/v1/chat", {
        method: "POST",
        token: expiredGrant.token,
        body: { input: "expired" },
      });
      assert.equal(expired.response.status, 403);

      const revokedGrant = await expectOk(daemon.endpoint, "/api/v1/tokens", {
        method: "POST",
        body: { allowed: ["model.chat:*"] },
      });
      secretNeedles.push(revokedGrant.token);
      await expectOk(daemon.endpoint, `/api/v1/tokens/${revokedGrant.id}`, { method: "DELETE" });
      const revoked = await requestJson(daemon.endpoint, "/api/v1/chat", {
        method: "POST",
        token: revokedGrant.token,
        body: { input: "revoked" },
      });
      assert.equal(revoked.response.status, 403);

      return {
        nativeBaseUrl: status.nativeBaseUrl,
        openAiCompatibleBaseUrl: status.openAiCompatibleBaseUrl,
        failClosedStatuses: [unauthenticated.response.status, denied.response.status, expired.response.status, revoked.response.status],
      };
    });

    mainGrant = await runStep(evidence, "create scoped capability token", async () => {
      const grant = await expectOk(daemon.endpoint, "/api/v1/tokens", {
        method: "POST",
        body: {
          audience: "autopilot-local-server",
          allowed: [
            "model.chat:*",
            "model.responses:*",
            "model.embeddings:*",
            "model.rerank:*",
            "model.load:*",
            "model.unload:*",
            "model.mount:*",
            "model.download:*",
            "model.import:*",
            "model.delete:*",
            "server.control:*",
            "server.logs:*",
            "backend.control:*",
            "provider.write:*",
            "vault.write:*",
            "vault.read:*",
            "vault.delete:*",
            "route.write:*",
            "route.use:*",
            "mcp.import:*",
            "mcp.call:huggingface.model_search",
          ],
          denied: ["connector.gmail.send", "filesystem.write", "shell.exec"],
        },
      });
      secretNeedles.push(grant.token);
      return grant;
    });
    const token = mainGrant.token;

    const serverControlEvidence = await runStep(evidence, "server control and redacted log tail", async () => {
      const stopped = await expectOk(daemon.endpoint, "/api/v1/server/stop", { method: "POST", token });
      assert.equal(stopped.controlStatus, "stopped");
      const restarted = await expectOk(daemon.endpoint, "/api/v1/server/restart", { method: "POST", token });
      assert.equal(restarted.controlStatus, "running");
      const logs = await expectOk(daemon.endpoint, "/api/v1/server/logs?limit=20", { token });
      assert.equal(logs.redaction, "redacted");
      assert.ok(logs.records.some((record) => record.event === "server_restart"));
      const events = await expectOk(daemon.endpoint, "/api/v1/server/events?limit=20", { token });
      assert.ok(events.events.some((event) => event.event === "server_events_read"));
      return {
        stopReceiptId: stopped.receiptId,
        restartReceiptId: restarted.receiptId,
        logReceiptId: logs.receiptId,
        eventReceiptId: events.receiptId,
        logCount: logs.records.length,
      };
    });

    await runStep(evidence, "discover providers and backends", async () => {
      const snapshot = await expectOk(daemon.endpoint, "/api/v1/models");
      const providerKinds = new Set(snapshot.providers.map((provider) => provider.kind));
      for (const kind of [
        "local_folder",
        "ioi_native_local",
        "lm_studio",
        "ollama",
        "llama_cpp",
        "vllm",
        "openai_compatible",
        "custom_http",
        "depin_tee",
      ]) {
        assert.ok(providerKinds.has(kind), `missing provider kind ${kind}`);
      }
      const backendIds = new Set(snapshot.backends.map((backend) => backend.id));
      for (const id of [
        "backend.fixture",
        "backend.autopilot.native-local.fixture",
        "backend.llama-cpp",
        "backend.ollama",
        "backend.vllm",
        "backend.lmstudio",
        "backend.openai-compatible",
      ]) {
        assert.ok(backendIds.has(id), `missing backend ${id}`);
      }
      return {
        providers: snapshot.providers.length,
        backends: snapshot.backends.length,
        artifacts: snapshot.artifacts.length,
        routes: snapshot.routes.length,
      };
    });

    await runStep(evidence, "runtime engines and hardware survey", async () => {
      const engines = await expectOk(daemon.endpoint, "/api/v1/runtime/engines");
      assert.ok(
        engines.some((engine) => engine.id === "backend.autopilot.native-local.fixture"),
        "missing native-local runtime engine",
      );
      const survey = await expectOk(daemon.endpoint, "/api/v1/runtime/survey", { method: "POST" });
      runtimeSurveyReceiptId = survey.receiptId;
      assert.equal(survey.schemaVersion, "ioi.model-mounting.runtime.v1");
      assert.match(runtimeSurveyReceiptId, /^receipt_runtime_survey_/);
      assert.equal(typeof survey.hardware.totalMemoryBytes, "number");
      assert.ok(Array.isArray(survey.engines));
      assert.ok(survey.engines.length >= engines.length);
      const receipt = await expectOk(daemon.endpoint, `/api/v1/receipts/${runtimeSurveyReceiptId}`);
      assert.equal(receipt.kind, "runtime_survey");
      assert.equal(receipt.details.engineCount, survey.engines.length);
      const receiptText = JSON.stringify(receipt);
      assert.equal(receiptText.includes(path.join(os.homedir(), ".lmstudio/bin/lms")), false);
      assert.equal(receiptText.includes(path.join(os.homedir(), ".local/bin/lm-studio")), false);
      assert.equal(receiptText.includes(path.join(os.homedir(), ".local/bin/lm-studio.AppImage")), false);
      const selection = await expectOk(daemon.endpoint, "/api/v1/runtime/select", {
        method: "POST",
        body: { engine_id: "backend.autopilot.native-local.fixture" },
      });
      assert.equal(selection.selectedEngineId, "backend.autopilot.native-local.fixture");
      const profile = await expectOk(daemon.endpoint, "/api/v1/runtime/engines/backend.autopilot.native-local.fixture", {
        method: "PATCH",
        body: {
          label: "Autopilot native fixture e2e",
          priority: 1,
          defaultLoadOptions: { gpu: "auto", contextLength: 3584, parallel: 3, ttlSeconds: 540, identifier: "e2e-runtime-profile" },
        },
      });
      assert.equal(profile.engine.operatorProfile.defaultLoadOptions.contextLength, 3584);
      const detail = await expectOk(daemon.endpoint, "/api/v1/runtime/engines/backend.autopilot.native-local.fixture");
      assert.equal(detail.profile.defaultLoadOptions.parallel, 3);
      const selectedEngines = await expectOk(daemon.endpoint, "/api/v1/runtime/engines");
      assert.equal(selectedEngines.find((engine) => engine.id === selection.selectedEngineId)?.selected, true);
      return {
        engineCount: survey.engines.length,
        memoryPressure: survey.hardware.memoryPressure,
        lmStudioStatus: survey.lmStudio.status,
        receiptId: runtimeSurveyReceiptId,
        selectedEngineId: selection.selectedEngineId,
        profileReceiptId: profile.receiptId,
      };
    });

    await runStep(evidence, "import, mount, and load deterministic native-local artifact", async () => {
      const artifactPath = path.join(workspaceDir, "autopilot-e2e.Q4_K_M.gguf");
      fs.writeFileSync(
        artifactPath,
        ["family=autopilot-e2e", "quantization=Q4_K_M", "context=4096", "fixture bytes"].join("\n"),
      );
      const imported = await expectOk(daemon.endpoint, "/api/v1/models/import", {
        method: "POST",
        token,
        body: {
          model_id: "native:e2e",
          provider_id: "provider.autopilot.local",
          path: artifactPath,
          capabilities: ["chat", "responses", "embeddings"],
        },
      });
      assert.match(imported.checksum, /^sha256:/);
      const mounted = await expectOk(daemon.endpoint, "/api/v1/models/mount", {
        method: "POST",
        token,
        body: { model_id: "native:e2e", id: "endpoint.e2e.native-local", provider_id: "provider.autopilot.local" },
      });
      const defaultEstimate = await expectOk(daemon.endpoint, "/api/v1/models/load", {
        method: "POST",
        token,
        body: {
          endpoint_id: mounted.id,
          estimate_only: true,
        },
      });
      assert.equal(defaultEstimate.loadOptions.contextLength, 3584);
      assert.equal(defaultEstimate.loadOptions.parallel, 3);
      const estimate = await expectOk(daemon.endpoint, "/api/v1/models/load", {
        method: "POST",
        token,
        body: {
          endpoint_id: mounted.id,
          load_policy: { mode: "on_demand", idleTtlSeconds: 600, autoEvict: true },
          load_options: {
            estimateOnly: true,
            gpu: "auto",
            contextLength: 4096,
            parallel: 2,
            ttlSeconds: 600,
            identifier: "e2e-estimate",
          },
        },
      });
      assert.equal(estimate.status, "estimate_only");
      assert.equal(estimate.runtimeEngineId, "backend.autopilot.native-local.fixture");
      const loaded = await expectOk(daemon.endpoint, "/api/v1/models/load", {
        method: "POST",
        token,
        body: {
          endpoint_id: mounted.id,
          load_policy: { mode: "on_demand", idleTtlSeconds: 900, autoEvict: true },
          load_options: {
            gpu: "max",
            contextLength: 4096,
            parallel: 2,
            ttlSeconds: 900,
            identifier: "e2e-native-load",
          },
        },
      });
      assert.equal(loaded.backendId, "backend.autopilot.native-local.fixture");
      assert.equal(loaded.runtimeEngineId, "backend.autopilot.native-local.fixture");
      assert.equal(loaded.identifier, "e2e-native-load");
      assert.equal(loaded.contextLength, 4096);
      assert.equal(loaded.backendProcess.status, "started");
      assert.match(loaded.backendProcess.pidHash, /^[a-f0-9]{16}$/);
      assert.equal(loaded.backendProcess.argsRedacted.includes("--context"), true);
      const processBackends = await expectOk(daemon.endpoint, "/api/v1/backends");
      const nativeProcessBackend = processBackends.find((backend) => backend.id === "backend.autopilot.native-local.fixture");
      assert.equal(nativeProcessBackend.process.status, "started");
      assert.equal(nativeProcessBackend.process.argsRedacted.includes("4096"), true);
      return {
        artifactId: imported.id,
        endpointId: mounted.id,
        instanceId: loaded.id,
        estimateReceiptId: estimate.receiptId,
        backendProcessId: loaded.backendProcess.id,
        checksum: imported.checksum,
      };
    });

    await runStep(evidence, "exercise native and OpenAI-compatible inference APIs", async () => {
      const chat = await expectOk(daemon.endpoint, "/api/v1/chat", {
        method: "POST",
        token,
        body: { route_id: "route.native-local", model: "native:e2e", input: "native chat e2e" },
      });
      nativeReceiptId = chat.receipt_id;
      assert.match(chat.output_text, /Autopilot native local model response/);

      const compatChat = await expectOk(daemon.endpoint, "/v1/chat/completions", {
        method: "POST",
        token,
        body: {
          route_id: "route.native-local",
          model: "native:e2e",
          messages: [{ role: "user", content: "compat chat e2e" }],
        },
      });
      assert.equal(compatChat.choices[0].message.role, "assistant");

      const responses = await expectOk(daemon.endpoint, "/api/v1/responses", {
        method: "POST",
        token,
        body: { route_id: "route.native-local", model: "native:e2e", input: "responses e2e" },
      });
      assert.match(responses.output_text, /Autopilot native local model response/);

      const embeddings = await expectOk(daemon.endpoint, "/v1/embeddings", {
        method: "POST",
        token,
        body: { route_id: "route.native-local", model: "native:e2e", input: ["alpha", "beta"] },
      });
      assert.equal(embeddings.data.length, 2);

      const streamedChat = await requestSse(daemon.endpoint, "/v1/chat/completions", {
        method: "POST",
        token,
        body: {
          route_id: "route.native-local",
          model: "native:e2e",
          stream: true,
          messages: [{ role: "user", content: "stream native local e2e" }],
        },
      });
      assert.equal(streamedChat.response.status, 200);
      assert.equal(streamedChat.response.headers.get("x-ioi-stream-source"), "provider_native");
      const streamedChatChunks = parseOpenAiSseChunks(streamedChat.text);
      assert.equal(streamedChatChunks.at(-1), "[DONE]");
      const streamedChatText = streamedChatChunks
        .filter((chunk) => chunk !== "[DONE]")
        .map((chunk) => chunk.choices?.[0]?.delta?.content ?? "")
        .join("");
      assert.match(streamedChatText, /Autopilot native local model response/);
      const streamedChatMetadata = streamedChatChunks.find((chunk) => chunk !== "[DONE]" && chunk.stream_receipt_id);
      assert.equal(streamedChatMetadata.route_id, "route.native-local");
      assert.equal(streamedChatMetadata.provider_stream, "native");
      nativeStreamCompletionInvocationReceiptId = streamedChatMetadata.receipt_id;
      nativeStreamCompletionReceiptId = streamedChatMetadata.stream_receipt_id;
      const streamInvocationReceipt = await expectOk(
        daemon.endpoint,
        `/api/v1/receipts/${nativeStreamCompletionInvocationReceiptId}`,
      );
      assert.equal(streamInvocationReceipt.kind, "model_invocation");
      assert.equal(streamInvocationReceipt.details.streamStatus, "started");
      assert.equal(streamInvocationReceipt.details.streamSource, "provider_native");
      assert.equal(streamInvocationReceipt.details.providerResponseKind, "native_local.chat.stream");
      const streamCompletionReceipt = await expectOk(daemon.endpoint, `/api/v1/receipts/${nativeStreamCompletionReceiptId}`);
      assertNativeLocalStreamReceipt(streamCompletionReceipt, {
        kind: "model_invocation_stream_completed",
        streamKind: "openai_chat_completions_native_local",
        selectedModel: "native:e2e",
        endpointId: "endpoint.e2e.native-local",
      });
      assert.equal(streamCompletionReceipt.details.providerResponseKind, "native_local.chat.stream");
      assert.equal(streamCompletionReceipt.details.invocationReceiptId, nativeStreamCompletionInvocationReceiptId);
      assert.equal(
        streamCompletionReceipt.details.outputHash,
        crypto.createHash("sha256").update(streamedChatText).digest("hex"),
      );

      const priorStreamDelay = process.env.IOI_DETERMINISTIC_PROVIDER_STREAM_DELAY_MS;
      process.env.IOI_DETERMINISTIC_PROVIDER_STREAM_DELAY_MS = "25";
      try {
        const abortedResponseStream = await requestSseAndAbortAfterFirstChunk(daemon.endpoint, "/v1/responses", {
          method: "POST",
          token,
          body: {
            route_id: "route.native-local",
            model: "native:e2e",
            stream: true,
            input: "abort native local e2e response stream",
          },
        });
        assert.equal(abortedResponseStream.response.status, 200);
        assert.match(abortedResponseStream.text, /response\.created/);
      } finally {
        if (priorStreamDelay === undefined) {
          delete process.env.IOI_DETERMINISTIC_PROVIDER_STREAM_DELAY_MS;
        } else {
          process.env.IOI_DETERMINISTIC_PROVIDER_STREAM_DELAY_MS = priorStreamDelay;
        }
      }
      const streamAbortReceipt = await waitForReceipt(
        daemon.endpoint,
        (receipt) =>
          receipt.kind === "model_invocation_stream_canceled" &&
          receipt.details?.streamKind === "openai_responses_native_local" &&
          receipt.details?.routeId === "route.native-local" &&
          receipt.details?.selectedModel === "native:e2e",
      );
      nativeStreamAbortReceiptId = streamAbortReceipt.id;
      nativeStreamAbortInvocationReceiptId = streamAbortReceipt.details.invocationReceiptId;
      assertNativeLocalStreamReceipt(streamAbortReceipt, {
        kind: "model_invocation_stream_canceled",
        streamKind: "openai_responses_native_local",
        selectedModel: "native:e2e",
        endpointId: "endpoint.e2e.native-local",
        status: "aborted",
        reason: "client_disconnect",
      });
      assert.equal(streamAbortReceipt.details.providerResponseKind, "native_local.responses.stream");
      const streamAbortInvocation = await expectOk(daemon.endpoint, `/api/v1/receipts/${nativeStreamAbortInvocationReceiptId}`);
      assert.equal(streamAbortInvocation.kind, "model_invocation");
      assert.equal(streamAbortInvocation.details.streamStatus, "started");
      assert.equal(streamAbortInvocation.details.streamSource, "provider_native");
      assert.equal(streamAbortInvocation.details.providerResponseKind, "native_local.responses.stream");

      return {
        nativeReceiptId,
        compatModel: compatChat.model,
        responsesReceiptId: responses.receipt_id,
        embeddingVectors: embeddings.data.length,
        streamCompletionReceiptId: nativeStreamCompletionReceiptId,
        streamAbortReceiptId: nativeStreamAbortReceiptId,
      };
    });

    await runStep(evidence, "catalog search, import modes, cleanup, and download lifecycle", async () => {
      const catalog = await expectOk(daemon.endpoint, "/api/v1/models/catalog/search?q=autopilot");
      assert.ok(catalog.results.some((entry) => entry.sourceUrl === "fixture://catalog/autopilot-native-3b-q4"));
      const catalogImport = await expectOk(daemon.endpoint, "/api/v1/models/catalog/import-url", {
        method: "POST",
        token,
        body: { source_url: "fixture://catalog/autopilot-native-3b-q4", model_id: "native:e2e-catalog" },
      });
      assert.equal(catalogImport.status, "completed");
      assert.equal(catalogImport.download.variant.quantization, "Q4_K_M");
      const dryRunPath = path.join(workspaceDir, "autopilot-e2e-dry-run.Q4_K_M.gguf");
      fs.writeFileSync(dryRunPath, "family=e2e-dry-run\ncontext=1024\nquantization=Q4_K_M\n");
      const dryRun = await expectOk(daemon.endpoint, "/api/v1/models/import", {
        method: "POST",
        token,
        body: { model_id: "native:e2e-dry-run", path: dryRunPath, import_mode: "dry_run" },
      });
      assert.equal(dryRun.status, "dry_run");
      const copied = await expectOk(daemon.endpoint, "/api/v1/models/import", {
        method: "POST",
        token,
        body: { model_id: "native:e2e-copied", path: dryRunPath, import_mode: "copy" },
      });
      assert.equal(copied.importMode, "copy");
      const queued = await expectOk(daemon.endpoint, "/api/v1/models/download", {
        method: "POST",
        token,
        body: {
          model_id: "native:e2e-cancel",
          provider_id: "provider.autopilot.local",
          source_url: "fixture://e2e/cancel",
          queued_only: true,
        },
      });
      const canceled = await expectOk(daemon.endpoint, `/api/v1/models/download/${queued.id}/cancel`, {
        method: "POST",
        token,
      });
      assert.equal(canceled.status, "canceled");
      const completed = await expectOk(daemon.endpoint, "/api/v1/models/download", {
        method: "POST",
        token,
        body: {
          model_id: "native:e2e-downloaded",
          provider_id: "provider.autopilot.local",
          source_url: "fixture://e2e/downloaded",
          fixture_content: "family=e2e-downloaded\ncontext=2048\nquantization=Q4_K_M\n",
        },
      });
      assert.equal(completed.status, "completed");
      assert.equal(completed.progress, 1);
      const cleanup = await expectOk(daemon.endpoint, "/api/v1/models/storage/cleanup", { method: "POST", token });
      assert.equal(cleanup.status, "scanned");
      const deleted = await expectOk(daemon.endpoint, `/api/v1/models/${encodeURIComponent(copied.id)}`, {
        method: "DELETE",
        token,
      });
      assert.equal(deleted.status, "deleted");
      return {
        catalogResults: catalog.results.length,
        catalogDownloadJobId: catalogImport.download.id,
        dryRunReceiptId: dryRun.receiptId,
        canceledJobId: canceled.id,
        completedJobId: completed.id,
        completedReceiptId: completed.receiptId,
        cleanupReceiptId: cleanup.receiptId,
        deletedArtifactId: deleted.artifactId,
      };
    });

    await runStep(evidence, "persistent and ephemeral MCP through governed receipts", async () => {
      const persistentVaultRef = "vault://e2e/mcp/huggingface";
      const ephemeralVaultRef = "vault://e2e/mcp/ephemeral-huggingface";
      secretNeedles.push(persistentVaultRef, ephemeralVaultRef);
      const mcpJsonPath = path.join(workspaceDir, "mcp.json");
      fs.writeFileSync(
        mcpJsonPath,
        JSON.stringify(
          {
            mcpServers: {
              huggingface: {
                url: "https://example.invalid/mcp",
                allowed_tools: ["model_search"],
                headers: { authorization: persistentVaultRef },
              },
            },
          },
          null,
          2,
        ),
      );
      const imported = await expectOk(daemon.endpoint, "/api/v1/mcp/import", {
        method: "POST",
        token,
        body: JSON.parse(fs.readFileSync(mcpJsonPath, "utf8")),
      });
      assert.equal(imported.count, 1);
      const tool = await expectOk(daemon.endpoint, "/api/v1/mcp/invoke", {
        method: "POST",
        token,
        body: { server_label: "huggingface", tool: "model_search", input: { q: "qwen" } },
      });
      assert.equal(tool.receipt.kind, "mcp_tool_invocation");
      const response = await expectOk(daemon.endpoint, "/api/v1/responses", {
        method: "POST",
        token,
        body: {
          route_id: "route.local-first",
          input: "Use ephemeral MCP and answer locally.",
          integrations: [
            {
              type: "ephemeral_mcp",
              server_label: "huggingface",
              server_url: "https://example.invalid/mcp",
              allowed_tools: ["model_search"],
              headers: { authorization: ephemeralVaultRef },
            },
          ],
        },
      });
      ephemeralReceiptId = response.receipt_id;
      ephemeralToolReceiptIds = response.tool_receipt_ids;
      assert.equal(ephemeralToolReceiptIds.length, 1);
      const receipt = await expectOk(daemon.endpoint, `/api/v1/receipts/${ephemeralReceiptId}`);
      assert.deepEqual(receipt.details.toolReceiptIds, ephemeralToolReceiptIds);
      assert.equal(JSON.stringify(receipt).includes(ephemeralVaultRef), false);
      return {
        persistentToolReceiptId: tool.receipt.id,
        ephemeralReceiptId,
        linkedToolReceipts: ephemeralToolReceiptIds.length,
      };
    });

    await runStep(evidence, "route policy and workflow node execution", async () => {
      const route = await expectOk(daemon.endpoint, "/api/v1/routes", {
        method: "POST",
        token,
        body: {
          id: "route.e2e.native",
          role: "verifier",
          privacy: "local_only",
          max_cost_usd: 0,
          fallback: ["endpoint.e2e.native-local"],
          provider_eligibility: ["ioi_native_local"],
          denied_providers: ["openai", "anthropic", "gemini", "lm_studio"],
        },
      });
      assert.equal(route.id, "route.e2e.native");

      const routeTest = await expectOk(daemon.endpoint, "/api/v1/routes/route.e2e.native/test", {
        method: "POST",
        token,
        body: { capability: "chat", model_policy: { privacy: "local_only" } },
      });
      assert.equal(routeTest.selection.endpoint.id, "endpoint.e2e.native-local");

      const routerNode = await expectOk(daemon.endpoint, "/api/v1/workflows/nodes/execute", {
        method: "POST",
        token,
        body: { node: "Model Router", route_id: "route.e2e.native", model_policy: { privacy: "local_only" } },
      });
      assert.equal(routerNode.status, "selected");

      const modelCall = await expectOk(daemon.endpoint, "/api/v1/workflows/nodes/execute", {
        method: "POST",
        token,
        body: { node: "Model Call", route_id: "route.e2e.native", input: "workflow model call" },
      });
      assert.equal(modelCall.status, "executed");

      const embedding = await expectOk(daemon.endpoint, "/api/v1/workflows/nodes/execute", {
        method: "POST",
        token,
        body: { node: "Embedding", route_id: "route.e2e.native", input: "workflow embedding" },
      });
      assert.equal(embedding.status, "executed");

      const localTool = await expectOk(daemon.endpoint, "/api/v1/workflows/nodes/execute", {
        method: "POST",
        token,
        body: {
          node: "Local Tool/MCP",
          mcp: { server_label: "huggingface", tool: "model_search", input: { q: "qwen" } },
        },
      });
      assert.equal(localTool.status, "executed");

      const blockedGate = await requestJson(daemon.endpoint, "/api/v1/workflows/receipt-gate", {
        method: "POST",
        body: { receipt_id: ephemeralReceiptId, route_id: "route.mismatch" },
      });
      assert.equal(blockedGate.response.status, 412);
      const passedGate = await expectOk(daemon.endpoint, "/api/v1/workflows/receipt-gate", {
        method: "POST",
        body: {
          receipt_id: ephemeralReceiptId,
          redaction: "redacted",
          route_id: "route.local-first",
          selected_model: "local:auto",
          selected_endpoint: "endpoint.local.auto",
          selected_backend: "backend.fixture",
          required_tool_receipt_ids: ephemeralToolReceiptIds,
        },
      });
      assert.equal(passedGate.status, "passed");
      return {
        routerSelectedEndpoint: routerNode.selection.endpoint.id,
        modelCallReceiptId: modelCall.receipt.id,
        embeddingReceiptId: embedding.receipt.id,
        localToolReceiptId: localTool.receipt.id,
        receiptGateReceiptId: passedGate.gateReceipt.id,
      };
    });

    await runStep(evidence, "CLI sees same daemon state", async () => {
      const cli = resolveCliCommand(evidence);
      const common = { endpoint: daemon.endpoint, token, secretNeedles, evidence };
      const status = await runCli(cli, ["server", "--json", "status"], common);
      assert.equal(status.schemaVersion, "ioi.model-mounting.runtime.v1");
      const serverRestart = await runCli(cli, ["server", "--json", "restart"], common);
      assert.equal(serverRestart.controlStatus, "running");
      const serverLogs = await runCli(cli, ["server", "--json", "logs", "--limit", "20"], common);
      assert.ok(serverLogs.records.some((record) => record.event === "server_restart"));
      assert.equal(JSON.stringify(serverLogs).includes(token), false);
      const backends = await runCli(cli, ["backends", "--json", "ls"], common);
      assert.ok(backends.some((backend) => backend.id === "backend.autopilot.native-local.fixture"));
      const models = await runCli(cli, ["models", "--json", "ls"], common);
      assert.ok(models.artifacts.some((artifact) => artifact.modelId === "native:e2e"));
      const providerModels = await runCli(cli, ["models", "--json", "provider-models", "provider.autopilot.local"], common);
      assert.ok(providerModels.some((model) => model.modelId === "autopilot:native-fixture"));
      const cliVaultMaterial = `cli-e2e-${crypto.randomUUID()}`;
      secretNeedles.push(cliVaultMaterial);
      const vaultSet = await runCli(
        cli,
        [
          "vault",
          "--json",
          "set",
          "--vault-ref",
          cliVaultRef,
          "--material-env",
          "IOI_E2E_CLI_VAULT_SECRET",
          "--purpose",
          "provider.auth:provider.e2e.cli-auth",
          "--label",
          "CLI Auth Provider",
        ],
        { ...common, env: { IOI_E2E_CLI_VAULT_SECRET: cliVaultMaterial } },
      );
      assert.equal(vaultSet.configured, true);
      cliVaultHash = vaultSet.vaultRefHash;
      assert.equal(vaultSet.vaultRef.redacted, true);
      assert.equal(JSON.stringify(vaultSet).includes(cliVaultRef), false);
      assert.equal(JSON.stringify(vaultSet).includes(cliVaultMaterial), false);
      const vaultMeta = await runCli(cli, ["vault", "--json", "get-meta", "--vault-ref", cliVaultRef], common);
      assert.equal(vaultMeta.configured, true);
      assert.equal(vaultMeta.vaultRefHash, vaultSet.vaultRefHash);
      assert.equal(JSON.stringify(vaultMeta).includes(cliVaultRef), false);
      const vaultStatus = await runCli(cli, ["vault", "--json", "status"], common);
      assert.equal(vaultStatus.port, "VaultPort");
      assert.equal(typeof vaultStatus.materialAdapter.implementation, "string");
      assert.equal(vaultStatus.materialAdapter.plaintextPersistence, false);
      assert.equal(JSON.stringify(vaultStatus).includes(cliVaultRef), false);
      assert.equal(JSON.stringify(vaultStatus).includes(cliVaultMaterial), false);
      const vaultHealth = await runCli(cli, ["vault", "--json", "health"], common);
      assert.equal(vaultHealth.port, "VaultPort");
      assert.equal(vaultHealth.materialAdapter.plaintextPersistence, false);
      assert.equal(typeof vaultHealth.receiptId, "string");
      assert.equal(JSON.stringify(vaultHealth).includes(cliVaultRef), false);
      assert.equal(JSON.stringify(vaultHealth).includes(cliVaultMaterial), false);
      const vaultHealthLatest = await runCli(cli, ["vault", "--json", "health", "--latest"], common);
      assert.equal(vaultHealthLatest.receipt.id, vaultHealth.receiptId);
      assert.equal(vaultHealthLatest.replay.receipt.id, vaultHealth.receiptId);
      assert.equal(JSON.stringify(vaultHealthLatest).includes(cliVaultRef), false);
      assert.equal(JSON.stringify(vaultHealthLatest).includes(cliVaultMaterial), false);
      const configuredProvider = await runCli(
        cli,
        [
          "models",
          "--json",
          "provider-set",
          "--id",
          "provider.e2e.cli-auth",
          "--kind",
          "openai_compatible",
          "--label",
          "CLI Auth Provider",
          "--api-format",
          "openai_compatible",
          "--base-url",
          "http://127.0.0.1:65535/v1",
          "--privacy-class",
          "workspace",
          "--capabilities",
          "chat,responses",
          "--secret-ref",
          cliVaultRef,
          "--auth-scheme",
          "api_key",
          "--auth-header-name",
          "x-api-key",
        ],
        common,
      );
      assert.equal(configuredProvider.secretConfigured, true);
      assert.equal(configuredProvider.secretRef.redacted, true);
      assert.equal(configuredProvider.authScheme, "api_key");
      assert.equal(configuredProvider.authHeaderName, "x-api-key");
      assert.equal(JSON.stringify(configuredProvider).includes(cliVaultRef), false);
      assert.equal(JSON.stringify(configuredProvider).includes(cliVaultMaterial), false);
      const loaded = await runCli(cli, ["models", "--json", "ps"], common);
      assert.ok(loaded.some((instance) => instance.modelId === "native:e2e"));
      const providerHealth = await runCli(cli, ["models", "--json", "provider-health", "provider.autopilot.local"], common);
      assert.equal(providerHealth.status, "available");
      const runtimeSurvey = await runCli(cli, ["backends", "--json", "survey"], common);
      assert.match(runtimeSurvey.receiptId, /^receipt_runtime_survey_/);
      const runtimeEngines = await runCli(cli, ["backends", "--json", "engines"], common);
      assert.ok(runtimeEngines.some((engine) => engine.id === "backend.autopilot.native-local.fixture"));
      const runtimeEngineUpdate = await runCli(
        cli,
        [
          "backends",
          "--json",
          "engine-update",
          "backend.autopilot.native-local.fixture",
          "--priority",
          "2",
          "--gpu",
          "auto",
          "--context-length",
          "4096",
          "--parallel",
          "2",
          "--ttl-seconds",
          "600",
          "--identifier",
          "cli-runtime-profile",
        ],
        common,
      );
      assert.equal(runtimeEngineUpdate.engine.operatorProfile.defaultLoadOptions.contextLength, 4096);
      const runtimeEngineGet = await runCli(cli, ["backends", "--json", "engine-get", "backend.autopilot.native-local.fixture"], common);
      assert.equal(runtimeEngineGet.profile.defaultLoadOptions.identifier, "cli-runtime-profile");
      const runtimeSelect = await runCli(cli, ["backends", "--json", "select", "backend.autopilot.native-local.fixture"], common);
      assert.equal(runtimeSelect.selectedEngineId, "backend.autopilot.native-local.fixture");
      const runtimeEngineRemove = await runCli(cli, ["backends", "--json", "engine-remove", "backend.autopilot.native-local.fixture"], common);
      assert.equal(runtimeEngineRemove.removed, true);
      const catalogSearch = await runCli(cli, ["models", "--json", "catalog-search", "--query", "autopilot"], common);
      assert.ok(catalogSearch.results.length > 0);
      const catalogImport = await runCli(
        cli,
        ["models", "--json", "catalog-import-url", "fixture://catalog/autopilot-native-3b-q4", "--model-id", "native:e2e-cli-catalog"],
        common,
      );
      assert.equal(catalogImport.status, "completed");
      const cleanup = await runCli(cli, ["models", "--json", "cleanup"], common);
      assert.equal(cleanup.status, "scanned");
      const loadEstimate = await runCli(
        cli,
        [
          "models",
          "--json",
          "load",
          "--model-id",
          "native:e2e",
          "--estimate-only",
          "--context-length",
          "4096",
          "--parallel",
          "2",
          "--gpu",
          "auto",
          "--ttl-seconds",
          "600",
          "--identifier",
          "cli-estimate",
        ],
        common,
      );
      assert.equal(loadEstimate.status, "estimate_only");
      const providerHealthLatest = await runCli(
        cli,
        ["models", "--json", "provider-health", "provider.autopilot.local", "--latest"],
        common,
      );
      assert.equal(providerHealthLatest.receipt.id, providerHealth.discovery.lastHealthCheck.receiptId);
      assert.equal(providerHealthLatest.replay.receipt.id, providerHealth.discovery.lastHealthCheck.receiptId);
      const routes = await runCli(cli, ["routes", "--json", "ls"], common);
      assert.ok(routes.some((route) => route.id === "route.e2e.native"));
      const routeTest = await runCli(cli, ["routes", "--json", "test", "route.e2e.native", "--privacy", "local_only"], common);
      assert.equal(routeTest.selection.endpoint.id, "endpoint.e2e.native-local");
      const mcpServers = await runCli(cli, ["mcp", "--json", "ls"], common);
      assert.ok(mcpServers.some((server) => server.label === "huggingface"));
      const mcpInvoke = await runCli(
        cli,
        ["mcp", "--json", "invoke", "--server-label", "huggingface", "--tool", "model_search", "--input-json", "{\"q\":\"qwen\"}"],
        common,
      );
      assert.equal(mcpInvoke.result.ok, true);
      const tokens = await runCli(cli, ["tokens", "--json", "ls"], common);
      assert.equal(JSON.stringify(tokens).includes(token), false);
      const receipts = await runCli(cli, ["receipts", "--json", "ls"], common);
      assert.ok(receipts.some((receipt) => receipt.id === nativeReceiptId));
      assert.ok(receipts.some((receipt) => receipt.id === nativeStreamCompletionReceiptId));
      assert.ok(receipts.some((receipt) => receipt.id === nativeStreamAbortReceiptId));
      const receipt = await runCli(cli, ["receipts", "--json", "get", nativeReceiptId], common);
      assert.equal(receipt.id, nativeReceiptId);
      const replay = await runCli(cli, ["receipts", "--json", "replay", nativeReceiptId], common);
      assert.equal(replay.receipt.id, nativeReceiptId);
      const streamCompletionReceipt = await runCli(cli, ["receipts", "--json", "get", nativeStreamCompletionReceiptId], common);
      assertNativeLocalStreamReceipt(streamCompletionReceipt, {
        kind: "model_invocation_stream_completed",
        streamKind: "openai_chat_completions_native_local",
        selectedModel: "native:e2e",
        endpointId: "endpoint.e2e.native-local",
      });
      assert.equal(streamCompletionReceipt.details.invocationReceiptId, nativeStreamCompletionInvocationReceiptId);
      const streamCompletionReplay = await runCli(
        cli,
        ["receipts", "--json", "replay", nativeStreamCompletionReceiptId],
        common,
      );
      assert.equal(streamCompletionReplay.receipt.id, nativeStreamCompletionReceiptId);
      assert.equal(streamCompletionReplay.route.id, "route.native-local");
      assert.equal(streamCompletionReplay.endpoint.id, "endpoint.e2e.native-local");
      const streamAbortReceipt = await runCli(cli, ["receipts", "--json", "get", nativeStreamAbortReceiptId], common);
      assertNativeLocalStreamReceipt(streamAbortReceipt, {
        kind: "model_invocation_stream_canceled",
        streamKind: "openai_responses_native_local",
        selectedModel: "native:e2e",
        endpointId: "endpoint.e2e.native-local",
        status: "aborted",
        reason: "client_disconnect",
      });
      assert.equal(streamAbortReceipt.details.invocationReceiptId, nativeStreamAbortInvocationReceiptId);
      const streamAbortReplay = await runCli(cli, ["receipts", "--json", "replay", nativeStreamAbortReceiptId], common);
      assert.equal(streamAbortReplay.receipt.id, nativeStreamAbortReceiptId);
      assert.equal(streamAbortReplay.route.id, "route.native-local");
      assert.equal(streamAbortReplay.endpoint.id, "endpoint.e2e.native-local");
      return {
        cli: path.basename(cli.command),
        models: models.artifacts.length,
        loaded: loaded.length,
        receipts: receipts.length,
        streamCompletionReceiptId: nativeStreamCompletionReceiptId,
        streamAbortReceiptId: nativeStreamAbortReceiptId,
        serverRestartReceiptId: serverControlEvidence.restartReceiptId,
        runtimeSurveyReceiptId: runtimeSurvey.receiptId,
      };
    });

    await runStep(evidence, "receipt replay and projection continuity after daemon restart", async () => {
      await daemon.close();
      daemon = await startRuntimeDaemonService({ cwd: workspaceDir, stateDir });
      evidence.restartedDaemonEndpoint = daemon.endpoint;
      const receipt = await expectOk(daemon.endpoint, `/api/v1/receipts/${nativeReceiptId}`);
      assert.equal(receipt.id, nativeReceiptId);
      const replay = await expectOk(daemon.endpoint, `/api/v1/receipts/${nativeReceiptId}/replay`);
      assert.equal(replay.receipt.id, nativeReceiptId);
      assert.equal(replay.route.id, "route.native-local");
      const projection = await expectOk(daemon.endpoint, "/api/v1/projections/model-mounting");
      assert.ok(projection.artifacts.some((artifact) => artifact.modelId === "native:e2e"));
      assert.ok(projection.invocationReceipts.some((item) => item.id === nativeReceiptId));
      assert.ok(projection.receipts.some((item) => item.id === nativeStreamCompletionReceiptId));
      assert.ok(projection.receipts.some((item) => item.id === nativeStreamAbortReceiptId));
      assert.ok(projection.runtimeSurveyReceipts.some((item) => item.id === runtimeSurveyReceiptId));
      assert.ok(projection.toolReceipts.some((item) => ephemeralToolReceiptIds.includes(item.id)));
      const streamCompletionReceipt = await expectOk(daemon.endpoint, `/api/v1/receipts/${nativeStreamCompletionReceiptId}`);
      assertNativeLocalStreamReceipt(streamCompletionReceipt, {
        kind: "model_invocation_stream_completed",
        streamKind: "openai_chat_completions_native_local",
        selectedModel: "native:e2e",
        endpointId: "endpoint.e2e.native-local",
      });
      const streamCompletionReplay = await expectOk(daemon.endpoint, `/api/v1/receipts/${nativeStreamCompletionReceiptId}/replay`);
      assert.equal(streamCompletionReplay.receipt.id, nativeStreamCompletionReceiptId);
      assert.equal(streamCompletionReplay.route.id, "route.native-local");
      assert.equal(streamCompletionReplay.endpoint.id, "endpoint.e2e.native-local");
      const streamAbortReceipt = await expectOk(daemon.endpoint, `/api/v1/receipts/${nativeStreamAbortReceiptId}`);
      assertNativeLocalStreamReceipt(streamAbortReceipt, {
        kind: "model_invocation_stream_canceled",
        streamKind: "openai_responses_native_local",
        selectedModel: "native:e2e",
        endpointId: "endpoint.e2e.native-local",
        status: "aborted",
        reason: "client_disconnect",
      });
      const streamAbortReplay = await expectOk(daemon.endpoint, `/api/v1/receipts/${nativeStreamAbortReceiptId}/replay`);
      assert.equal(streamAbortReplay.receipt.id, nativeStreamAbortReceiptId);
      assert.equal(streamAbortReplay.route.id, "route.native-local");
      assert.equal(streamAbortReplay.endpoint.id, "endpoint.e2e.native-local");
      const restartedProcess = projection.backendProcesses.find((process) => process.backendId === "backend.autopilot.native-local.fixture");
      assert.equal(restartedProcess.status, "stale_recovered");
      assert.equal(restartedProcess.staleReason, "daemon_boot_mismatch");
      const runtimeSurveyReplay = await expectOk(daemon.endpoint, `/api/v1/receipts/${runtimeSurveyReceiptId}/replay`);
      assert.equal(runtimeSurveyReplay.receipt.id, runtimeSurveyReceiptId);
      const vaultMeta = await expectOk(daemon.endpoint, "/api/v1/vault/refs/meta", {
        method: "POST",
        token,
        body: { vault_ref: cliVaultRef },
      });
      assert.equal(vaultMeta.configured, true);
      assert.equal(vaultMeta.vaultRefHash, cliVaultHash);
      assert.equal(vaultMeta.resolvedMaterial, false);
      assert.equal(vaultMeta.requiresRebind, true);
      assert.equal(JSON.stringify(vaultMeta).includes(cliVaultRef), false);
      return {
        projectionWatermark: projection.watermark,
        invocationReceipts: projection.invocationReceipts.length,
        streamCompletionReceiptId: nativeStreamCompletionReceiptId,
        streamAbortReceiptId: nativeStreamAbortReceiptId,
        runtimeSurveyReceipts: projection.runtimeSurveyReceipts.length,
        toolReceipts: projection.toolReceipts.length,
        vaultMetadataRequiresRebind: vaultMeta.requiresRebind,
      };
    });

    if (!options.skipGui) {
      await runStep(evidence, "Mounts desktop GUI validation bundle", async () => {
        return runGuiValidation(evidence, outputRoot, secretNeedles);
      });
    } else {
      evidence.steps.push({
        name: "Mounts desktop GUI validation bundle",
        status: "skipped",
        startedAt: new Date().toISOString(),
        completedAt: new Date().toISOString(),
        summary: { reason: "skipped by --skip-gui or IOI_MODEL_MOUNTING_E2E_SKIP_GUI=1" },
      });
    }

    await runStep(evidence, "secret redaction scan", async () => {
      const scan = scanFilesForSecrets([stateDir, outputRoot], secretNeedles);
      assert.equal(scan.passed, true, JSON.stringify(scan.findings));
      return scan;
    });

    evidence.secretNeedleHashes = await Promise.all(secretNeedles.map(async (needle) => `sha256:${await sha256Hex(needle)}`));
    evidence.passed = true;
  } catch (error) {
    evidence.error = error instanceof Error ? error.stack ?? error.message : String(error);
    throw error;
  } finally {
    if (daemon) {
      await daemon.close();
    }
    evidence.completedAt = new Date().toISOString();
    const resultPath = path.join(outputRoot, "result.json");
    fs.writeFileSync(resultPath, JSON.stringify(sanitize(evidence, secretNeedles), null, 2), "utf8");
    console.log(`[model-mounting-e2e] results: ${resultPath}`);
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.stack ?? error.message : String(error));
  process.exit(1);
});
