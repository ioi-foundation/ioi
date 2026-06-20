// Shared harness for spawning the Rust true-north hypervisor-daemon binary.
// Used by validate-model-mounting-e2e.mjs and the JS runtime-daemon integration
// gates that co-run a Rust daemon so model-route-control resolves through Rust
// (the model-mount facade retirement).

import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");

export function resolveHypervisorDaemonBinary(evidence = { commands: [] }) {
  const explicit = process.env.IOI_HYPERVISOR_DAEMON_BIN;
  if (explicit) return explicit;
  const binaryName =
    process.platform === "win32" ? "hypervisor-daemon.exe" : "hypervisor-daemon";
  const targetBinary = path.join(repoRoot, "target", "debug", binaryName);
  if (fs.existsSync(targetBinary)) return targetBinary;
  const build = spawnSync(
    "cargo",
    ["build", "-p", "ioi-node", "--bin", "hypervisor-daemon"],
    { cwd: repoRoot, encoding: "utf8" },
  );
  if (Array.isArray(evidence?.commands)) {
    evidence.commands.push({
      command: "cargo build -p ioi-node --bin hypervisor-daemon",
      status: build.status === 0 ? "passed" : "failed",
    });
  }
  if (build.status !== 0) {
    throw new Error(
      `Failed to build hypervisor-daemon:\n${build.stdout}\n${build.stderr}`,
    );
  }
  return targetBinary;
}

export async function getFreePort() {
  const net = await import("node:net");
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

// Spawn the built binary on a free port against a fresh state dir, offline by
// default (unreachable upstream -> native-local / honest no-model path).
export async function startRustHypervisorDaemon({ stateDir, evidence = { commands: [] } }) {
  const binary = resolveHypervisorDaemonBinary(evidence);
  const port = await getFreePort();
  const endpoint = `http://127.0.0.1:${port}`;
  const child = spawn(binary, [], {
    cwd: repoRoot,
    env: {
      ...process.env,
      IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${port}`,
      IOI_HYPERVISOR_DATA_DIR: stateDir,
      IOI_HYPERVISOR_MODEL_UPSTREAM:
        process.env.IOI_HYPERVISOR_MODEL_UPSTREAM ?? "http://127.0.0.1:1/v1",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let log = "";
  child.stdout.on("data", (chunk) => (log += chunk));
  child.stderr.on("data", (chunk) => (log += chunk));
  const deadline = Date.now() + 30000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      throw new Error(`hypervisor-daemon exited early (${child.exitCode}):\n${log}`);
    }
    try {
      const response = await fetch(`${endpoint}/healthz`);
      if (response.ok) break;
    } catch {
      // not up yet
    }
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  return {
    endpoint,
    stateDir,
    close: () =>
      new Promise((resolve) => {
        if (child.exitCode !== null) return resolve();
        child.once("exit", () => resolve());
        child.kill("SIGKILL");
      }),
  };
}
