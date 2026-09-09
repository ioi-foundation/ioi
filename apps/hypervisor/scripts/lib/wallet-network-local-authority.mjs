// wallet-network-local-authority — the deployment-local wallet.network authority node the
// Hypervisor bounded alpha is pointed at (ADR 0052; bounded-alpha-profile.md step 2b).
//
// This module owns the node's LIFECYCLE on the host: it runs the Rust control-plane binary
// (`crates/cli/src/bin/wallet_network_local_authority.rs`, which generates and custodies the
// deployment's keys, runs the Solo single-validator chain with durable state, and issues the
// root-signed control-plane records), fronts the node's loopback gRPC endpoint with the pinned
// TLS front the daemon requires, and writes the exact environment the daemon and the served App
// need under the state directory:
//
//   <state-dir>/daemon.env   the daemon's IOI_WALLET_NETWORK_* + capability key + principal ref
//   <state-dir>/serve.env    the served App's IOI_HYPERVISOR_LOCAL_APPROVER_KEY_PATH
//
// It replaces the cargo test fixture (public `07…` approver seed) as the alpha's authority node.
// It adds no second authority plane: the daemon's resolution, grant verification, consumption
// and receipt paths are untouched; only who holds the keys and how the node is started changed.
//
// Rotation and revocation are operator acts against the SERVING node (`rotate` / `revoke`), so a
// retired key's grants are refused from the next resolution on, and a revoked principal makes
// every later run fail closed before any harness runs.

import { spawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { startPinnedTlsProxy } from "./wallet-network-principal-authority-fixture.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..", "..", "..", "..");
const TLS_SERVER_NAME = "wallet-network.local";
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// Inside a packaged release ROOT is the install root: bin/ and node-bins/ sit beside apps/. In a
// checkout ROOT is the repository and the binary comes from target/debug (built on demand).
const PACKAGED_BINARY = path.join(ROOT, "bin", "wallet-network-local-authority");
const PACKAGED_NODE_BINS = path.join(ROOT, "node-bins");
export const DEFAULT_BINARY = fs.existsSync(PACKAGED_BINARY) ? PACKAGED_BINARY : path.join(ROOT, "target", "debug", "wallet-network-local-authority");

/** The node binaries a pinned launch uses: IOI_NODE_BINARY_DIR, else the package's node-bins/. */
export function pinnedNodeBinaryDir() {
  if (process.env.IOI_NODE_BINARY_DIR) return path.resolve(process.env.IOI_NODE_BINARY_DIR);
  if (fs.existsSync(path.join(PACKAGED_NODE_BINS, "orchestration"))) return PACKAGED_NODE_BINS;
  return null;
}

export function resolveBinary(binary = process.env.IOI_WALLET_AUTHORITY_BINARY || DEFAULT_BINARY, { build = true } = {}) {
  if (fs.existsSync(binary)) return binary;
  if (!build || binary !== DEFAULT_BINARY) {
    throw new Error(`wallet-network-local-authority binary is absent at ${binary}`);
  }
  const result = spawnSync("cargo", ["build", "-p", "ioi-cli", "--bin", "wallet-network-local-authority"], {
    cwd: ROOT, stdio: "inherit",
  });
  if (result.status !== 0) throw new Error("cargo build of wallet-network-local-authority failed");
  return binary;
}

/** Read `KEY=value` lines (the files this module writes) into an object. */
export function readEnvFile(file) {
  const out = {};
  for (const line of fs.readFileSync(file, "utf8").split("\n")) {
    const match = line.match(/^([A-Z0-9_]+)=(.*)$/u);
    if (match) out[match[1]] = match[2];
  }
  return out;
}

function writeSecretFile(file, text) {
  fs.writeFileSync(file, text, { mode: 0o600 });
  fs.chmodSync(file, 0o600);
}

/**
 * The guardian pass seals the daemon's wallet capability key. The operator may supply it
 * (IOI_GUARDIAN_KEY_PASS); otherwise one is generated on first bring-up and custodied at
 * <state-dir>/keys/guardian.pass (0600) so later bring-ups open the same key.
 */
function guardianPass(stateDir) {
  if (process.env.IOI_GUARDIAN_KEY_PASS) return process.env.IOI_GUARDIAN_KEY_PASS;
  const file = path.join(stateDir, "keys", "guardian.pass");
  if (fs.existsSync(file)) return fs.readFileSync(file, "utf8").trim();
  const pass = randomBytes(24).toString("base64url");
  writeSecretFile(file, `${pass}\n`);
  return pass;
}

/**
 * Bring up (or resume) the deployment-local authority node. Resolves once the node is READY and
 * the TLS front is up, with the env the daemon and serve need. `stop()` shuts the node down in
 * order (shutdown file → process exit → TLS front) and leaves the durable state for resume.
 */
export async function startLocalAuthority({
  stateDir,
  principalRef,
  binary,
  wallClock = false,
  readyTimeoutMs = Number(process.env.IOI_WALLET_AUTHORITY_READY_TIMEOUT_MS || 1_800_000),
  log = (line) => process.stderr.write(`${line}\n`),
} = {}) {
  if (!stateDir || !principalRef) throw new Error("stateDir and principalRef are required");
  stateDir = path.resolve(stateDir);
  fs.mkdirSync(path.join(stateDir, "keys"), { recursive: true, mode: 0o700 });
  fs.mkdirSync(path.join(stateDir, "tls"), { recursive: true, mode: 0o700 });
  fs.chmodSync(stateDir, 0o700);
  const pass = guardianPass(stateDir);
  const bin = resolveBinary(binary);
  const readyPath = path.join(stateDir, "ready.json");
  const shutdownPath = path.join(stateDir, "shutdown");
  try { fs.rmSync(readyPath, { force: true }); } catch { /* none */ }
  try { fs.rmSync(shutdownPath, { force: true }); } catch { /* none */ }

  const args = ["serve", "--state-dir", stateDir, "--principal-ref", principalRef, ...(wallClock ? ["--wall-clock"] : [])];
  let output = "";
  const nodeBins = pinnedNodeBinaryDir();
  const child = spawn(bin, args, {
    cwd: ROOT,
    env: { ...process.env, ...(nodeBins ? { IOI_NODE_BINARY_DIR: nodeBins } : {}), IOI_GUARDIAN_KEY_PASS: pass, CARGO_TERM_COLOR: "never", RUST_MIN_STACK: String(32 * 1024 * 1024) },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let exited = null;
  const exitPromise = new Promise((resolve) => child.once("exit", (code, signal) => { exited = { code, signal }; resolve(exited); }));
  const capture = (chunk) => { output = `${output}${chunk}`.slice(-32_000); for (const line of String(chunk).split("\n")) if (line.trim()) log(`[authority] ${line}`); };
  child.stdout.on("data", capture);
  child.stderr.on("data", capture);

  const deadline = Date.now() + readyTimeoutMs;
  while (!fs.existsSync(readyPath)) {
    if (exited) throw new Error(`wallet-network-local-authority exited before readiness (${JSON.stringify(exited)}):\n${output}`);
    if (Date.now() >= deadline) {
      try { fs.writeFileSync(shutdownPath, "ready-timeout\n"); } catch { /* best effort */ }
      throw new Error(`wallet-network-local-authority did not become ready within ${readyTimeoutMs}ms:\n${output}`);
    }
    await delay(100);
  }
  const ready = JSON.parse(fs.readFileSync(readyPath, "utf8"));
  const tls = await startPinnedTlsProxy(ready.rpc_addr, path.join(stateDir, "tls"), TLS_SERVER_NAME);
  const daemonEnv = {
    IOI_WALLET_NETWORK_URL: "",
    IOI_WALLET_NETWORK_RPC_ADDR: tls.rpcAddr,
    IOI_WALLET_NETWORK_CHAIN_ID: String(ready.chain_id),
    IOI_WALLET_NETWORK_TLS_CA_PATH: tls.caPath,
    IOI_WALLET_NETWORK_TLS_SERVER_NAME: tls.serverName,
    IOI_HYPERVISOR_WALLET_CLIENT_KEY_PATH: ready.capability_key_path,
    IOI_WALLET_NETWORK_ROOT_RECORD_PATH: ready.root_record_path,
    IOI_WALLET_NETWORK_TRANSACTION_LOCK_PATH: ready.transaction_lock_path,
    IOI_GUARDIAN_KEY_PASS: pass,
    IOI_HYPERVISOR_AUTHORITY_PRINCIPAL_REF: ready.principal_ref,
    // The single-validator debug chain commits slowly under load; match the estate's 900 s
    // held-operation ceiling rather than failing honest slow inclusion.
    IOI_WALLET_NETWORK_RESOLUTION_TIMEOUT_MS: "900000",
    IOI_TESTING_RPC_COMMIT_TIMEOUT_SECS: "900",
    IOI_HYPERVISOR_GOVERNED_REPLAY_TIMEOUT_MS: "45000",
  };
  const serveEnv = {
    IOI_HYPERVISOR_LOCAL_APPROVER_KEY_PATH: ready.approver_key_path,
    // The approval act records the grant on THIS node through the control binary.
    IOI_HYPERVISOR_LOCAL_AUTHORITY_STATE_DIR: stateDir,
    IOI_WALLET_AUTHORITY_BINARY: bin,
    // The attach-time standing envelope (M13.3) names the deployment principal in its envelope and
    // ceremony, so the serve needs the same principal ref the daemon resolves authority for; and
    // the deployment-local operator custody tier (R-14) attests the host the approver key sits on.
    IOI_HYPERVISOR_AUTHORITY_PRINCIPAL_REF: ready.principal_ref,
    IOI_HYPERVISOR_AUTHORITY_HOST_REF: `deployment-host://${String(ready.principal_ref).replace(/^[a-z]+:\/\//u, "")}`,
  };
  const envText = (obj) => `${Object.entries(obj).map(([k, v]) => `${k}=${v}`).join("\n")}\n`;
  writeSecretFile(path.join(stateDir, "daemon.env"), envText(daemonEnv));
  writeSecretFile(path.join(stateDir, "serve.env"), envText(serveEnv));

  let stopped = false;
  async function stop() {
    if (stopped) return;
    stopped = true;
    try { await tls.stop(); } catch { /* best effort */ }
    if (!exited) {
      try { fs.writeFileSync(shutdownPath, "stop\n"); } catch { /* best effort */ }
      await Promise.race([exitPromise, delay(60_000)]);
      if (!exited) { try { child.kill("SIGKILL"); } catch { /* gone */ } await exitPromise; }
    }
    try { tls.destroy(); } catch { /* best effort */ }
    try { fs.rmSync(path.join(stateDir, "daemon.env"), { force: true }); } catch { /* keep */ }
  }
  process.once("exit", () => { if (!stopped) { try { fs.writeFileSync(shutdownPath, "parent-exit\n"); } catch { /* best effort */ } try { child.kill("SIGTERM"); } catch { /* gone */ } tls.destroy(); } });
  return {
    stateDir, ready, daemonEnv, serveEnv, binary: bin, nodeBinaryDir: nodeBins, pid: child.pid,
    approverKeyPath: ready.approver_key_path, authorityRecordPath: ready.authority_record_path,
    exitPromise, stop,
    readAuthorityRecord: () => JSON.parse(fs.readFileSync(ready.authority_record_path, "utf8")),
  };
}

/** Operator acts against the SERVING node; each is one root-signed control-plane transaction. */
export function authorityAct(act, { stateDir, binary, reason } = {}) {
  const bin = resolveBinary(binary, { build: false });
  const args = [act, "--state-dir", path.resolve(stateDir), ...(act === "revoke" && reason ? ["--reason", reason] : [])];
  const passFile = path.join(path.resolve(stateDir), "keys", "guardian.pass");
  const pass = process.env.IOI_GUARDIAN_KEY_PASS || (fs.existsSync(passFile) ? fs.readFileSync(passFile, "utf8").trim() : "");
  const result = spawnSync(bin, args, { cwd: ROOT, encoding: "utf8", env: { ...process.env, CARGO_TERM_COLOR: "never", ...(pass ? { IOI_GUARDIAN_KEY_PASS: pass } : {}) } });
  return { ok: result.status === 0, status: result.status, stdout: result.stdout || "", stderr: result.stderr || "" };
}
