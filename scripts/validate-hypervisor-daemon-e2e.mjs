#!/usr/bin/env node
// Phase 5/6 e2e: prove the Rust true-north hypervisor-daemon compiles, runs, and
// serves the real ModelMountCore kernel + inference edge over HTTP. Runs offline
// (no Ollama) by pointing the inference upstream at an unreachable port and
// asserting the honest no_model_route path — the same contract the app consumes.
//
// Usage: node scripts/validate-hypervisor-daemon-e2e.mjs
import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, existsSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const BIN = path.join(ROOT, "target", "debug", "hypervisor-daemon");
const PORT = 8793;
const BASE = `http://127.0.0.1:${PORT}`;

function fail(message) {
  console.error(`FAIL: ${message}`);
  process.exit(1);
}

function ensureBinary() {
  if (existsSync(BIN)) return;
  console.log("Building hypervisor-daemon (not found)...");
  const build = spawnSync(
    "cargo",
    ["build", "-p", "ioi-node", "--bin", "hypervisor-daemon"],
    { cwd: ROOT, stdio: "inherit" },
  );
  if (build.status !== 0) fail("cargo build hypervisor-daemon failed");
}

async function waitForHealth(timeoutMs = 30000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${BASE}/healthz`);
      if (response.ok) return;
    } catch {
      // not up yet
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  fail("daemon did not become healthy in time");
}

async function main() {
  ensureBinary();
  const dataDir = mkdtempSync(path.join(os.tmpdir(), "ioi-hd-e2e-"));
  const daemon = spawn(BIN, [], {
    cwd: ROOT,
    env: {
      ...process.env,
      IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${PORT}`,
      IOI_HYPERVISOR_DATA_DIR: dataDir,
      // Unreachable upstream -> exercise the honest no-model path offline.
      IOI_HYPERVISOR_MODEL_UPSTREAM: "http://127.0.0.1:1/v1",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let daemonLog = "";
  daemon.stdout.on("data", (chunk) => (daemonLog += chunk));
  daemon.stderr.on("data", (chunk) => (daemonLog += chunk));

  try {
    await waitForHealth();

    // 1. Health
    const health = await fetch(`${BASE}/healthz`).then((r) => r.text());
    if (health.trim() !== "OK") fail(`/healthz returned ${health}`);

    // 2. dev-replay status (so the app dev-replay client can bind to Rust Core)
    const status = await fetch(`${BASE}/v1/hypervisor/dev-replay/status`).then(
      (r) => r.json(),
    );
    if (status.status !== "ready") fail("dev-replay status not ready");
    if (status.schema_version !== "ioi.hypervisor.dev_replay_status.v1") {
      fail("dev-replay status schema_version mismatch");
    }

    // 3. Real ModelMountCore projection over HTTP (not a fixture)
    const snapshot = await fetch(`${BASE}/v1/model-mount/snapshot`).then((r) =>
      r.json(),
    );
    if (!snapshot || typeof snapshot !== "object") {
      fail("snapshot is not an object");
    }
    if (!snapshot.adapterBoundaries) {
      fail(
        `snapshot missing adapterBoundaries (real kernel projection): ${JSON.stringify(
          snapshot,
        ).slice(0, 200)}`,
      );
    }

    // 4. Session turn: real inference attempt -> honest no_model_route SSE
    const turn = await fetch(`${BASE}/v1/hypervisor/session-turns`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        messages: [
          {
            role: "user",
            content: "create a website that explains post-quantum computers",
          },
        ],
      }),
    });
    if (turn.status !== 200) fail(`session-turn status ${turn.status}`);
    const turnText = await turn.text();
    if (!/event: error/.test(turnText)) fail("session-turn missing error event");
    if (!/"code":"no_model_route"/.test(turnText)) {
      fail("session-turn missing no_model_route code");
    }
    if (/Plan:/.test(turnText)) fail("session-turn leaked deterministic prose");

    // 5. Real native-local model-mount inference through the kernel admission
    //    chain (admit_provider_execution -> invoke_provider), fully offline.
    const native = await fetch(`${BASE}/v1/model-mount/native-local`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        model: "qwen2.5-coder",
        messages: [{ role: "user", content: "explain post-quantum computers" }],
      }),
    });
    if (native.status !== 200) {
      fail(`native-local status ${native.status}: ${await native.text()}`);
    }
    const result = await native.json();
    if (result.execution_backend !== "rust_model_mount_native_local") {
      fail(`native-local execution_backend mismatch: ${result.execution_backend}`);
    }
    if (result.backend_id !== "backend.hypervisor.native-local.fixture") {
      fail(`native-local backend_id mismatch: ${result.backend_id}`);
    }
    if (!/Hypervisor native local model response/.test(result.output_text || "")) {
      fail(`native-local output_text mismatch: ${result.output_text}`);
    }
    if (!/^sha256:[a-f0-9]{64}$/.test(result.invocation_hash || "")) {
      fail(`native-local invocation_hash mismatch: ${result.invocation_hash}`);
    }

    console.log("PASS: hypervisor-daemon serves real Core over HTTP");
    console.log("  - /healthz OK");
    console.log("  - /v1/hypervisor/dev-replay/status ready");
    console.log("  - /v1/model-mount/snapshot -> real ModelMountCore projection");
    console.log("  - /v1/hypervisor/session-turns -> honest no_model_route SSE");
    console.log(
      "  - /v1/model-mount/native-local -> real kernel admission->invoke (offline), " +
        `output: ${JSON.stringify((result.output_text || "").slice(0, 64))}`,
    );
  } finally {
    daemon.kill("SIGKILL");
    rmSync(dataDir, { recursive: true, force: true });
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
