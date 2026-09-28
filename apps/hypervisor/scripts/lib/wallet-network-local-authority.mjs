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
//   <state-dir>/serve.env    the served App's principal and host refs — public identifiers only
//
// KEY CUSTODY (owner decision 2026-09-28). The control root and the operator's approver key exist
// on disk only SEALED under the operator passphrase (keys/root.seed.sealed, keys/approver.seed.sealed,
// 0600), with their public halves beside them (keys/root.pub, keys/approver.pub). The passphrase is
// IOI_AUTHORITY_OPERATOR_PASS for the one command that needs it, or a TTY prompt; it is never an
// argument, never a file, never in daemon.env or serve.env. The node needs it once, on the FIRST
// bring-up (the new keys are sealed with it and the root signs the genesis binding); a resume
// needs none, and after bring-up no process holds the approver or root private key. The served App
// holds NO signing key and no path to one: a grant is minted only by the operator's explicit
// `approve` act (`approveGrant` / `wallet-network-authority.mjs approve`), which unseals the
// approver key in memory, signs one one-use grant for exactly the challenge's hashes and records it.
// Plaintext seeds exist only behind the dev/test `plaintextKeys` opt-in, which the operator CLI
// never passes.
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

/** The operator passphrase's one variable. The launcher forwards it to exactly one child act. */
export const OPERATOR_PASS_ENV = "IOI_AUTHORITY_OPERATOR_PASS";

/** A fresh state dir holds no control root seed of either custody; only its bring-up needs the passphrase. */
export function isFreshStateDir(stateDir) {
  const keys = path.join(path.resolve(stateDir), "keys");
  return !["root.seed.sealed", "root.seed"].some((name) => fs.existsSync(path.join(keys, name)));
}

/**
 * The child environment for one act: the ambient passphrase is ALWAYS stripped, and the one given
 * here is added only when this act needs it. Nothing else of the passphrase reaches a child.
 */
function childEnv(extra = {}, operatorPass = "") {
  const env = { ...process.env, ...extra };
  delete env[OPERATOR_PASS_ENV];
  if (operatorPass) env[OPERATOR_PASS_ENV] = operatorPass;
  return env;
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
 *
 * `operatorPass` is forwarded to the node ONLY for a fresh sealed bring-up (it seals the new keys
 * and lets the root sign genesis); a resume never receives it. With no `operatorPass` on a fresh
 * dir, the node prompts on this terminal when stdin is one, and refuses otherwise.
 * `plaintextKeys` is the DEV/TEST opt-in for plaintext seeds; a deployment never passes it.
 */
export async function startLocalAuthority({
  stateDir,
  principalRef,
  binary,
  wallClock = false,
  plaintextKeys = false,
  operatorPass = "",
  readyTimeoutMs = Number(process.env.IOI_WALLET_AUTHORITY_READY_TIMEOUT_MS || 1_800_000),
  log = (line) => process.stderr.write(`${line}\n`),
} = {}) {
  if (!stateDir || !principalRef) throw new Error("stateDir and principalRef are required");
  stateDir = path.resolve(stateDir);
  fs.mkdirSync(path.join(stateDir, "keys"), { recursive: true, mode: 0o700 });
  fs.mkdirSync(path.join(stateDir, "tls"), { recursive: true, mode: 0o700 });
  fs.chmodSync(stateDir, 0o700);
  const fresh = isFreshStateDir(stateDir);
  const sealedGenesis = fresh && !plaintextKeys;
  const promptOnTerminal = sealedGenesis && !operatorPass && Boolean(process.stdin.isTTY);
  if (sealedGenesis && !operatorPass && !promptOnTerminal) {
    throw new Error(`${stateDir} is a fresh state dir: the first bring-up seals the new control root and approver key with the operator passphrase and the root signs the genesis binding. Supply ${OPERATOR_PASS_ENV} for this one bring-up (or run on a terminal to be prompted); every later bring-up resumes without it.`);
  }
  const pass = guardianPass(stateDir);
  const bin = resolveBinary(binary);
  const readyPath = path.join(stateDir, "ready.json");
  const shutdownPath = path.join(stateDir, "shutdown");
  try { fs.rmSync(readyPath, { force: true }); } catch { /* none */ }
  try { fs.rmSync(shutdownPath, { force: true }); } catch { /* none */ }

  const args = ["serve", "--state-dir", stateDir, "--principal-ref", principalRef, ...(wallClock ? ["--wall-clock"] : []), ...(plaintextKeys ? ["--plaintext-keys"] : [])];
  let output = "";
  const nodeBins = pinnedNodeBinaryDir();
  const child = spawn(bin, args, {
    cwd: ROOT,
    // The passphrase rides only to a sealed genesis; the node scrubs it from its own environment
    // block at startup, so none of the validator processes it launches inherits it.
    env: childEnv({ ...(nodeBins ? { IOI_NODE_BINARY_DIR: nodeBins } : {}), IOI_GUARDIAN_KEY_PASS: pass, CARGO_TERM_COLOR: "never", RUST_MIN_STACK: String(32 * 1024 * 1024) }, sealedGenesis ? operatorPass : ""),
    // A terminal prompt needs the terminal: the node reads the passphrase from /dev/tty itself.
    stdio: [promptOnTerminal ? "inherit" : "ignore", "pipe", "pipe"],
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
  // the deployment's TLS front persists (CA, certificate, port): a restarted node answers where the daemon pinned it,
  // and the certificate outlives a day (the fixture's per-life CA expired after 24 h and broke the daemon's handshake)
  const tls = await startPinnedTlsProxy(ready.rpc_addr, path.join(stateDir, "tls"), TLS_SERVER_NAME, { persist: true, days: 3650 });
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
  // The served App holds NO signing key and no path to one (master guide §0.5.2, W0.2): no
  // approver key path, no authority state dir (whose guardian.pass opens the daemon's capability
  // key), no control binary. A run that needs a grant parks with the daemon's challenge verbatim,
  // and the operator approves it with `wallet-network-authority.mjs approve`, which mints and
  // records the one-use grant itself. The principal and host refs are public identifiers.
  const serveEnv = {
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
    keyCustody: ready.key_custody || (plaintextKeys ? "plaintext" : "sealed"),
    approverPublicKeyPath: ready.approver_public_key_path,
    // A path a process could sign with exists only for a dev/test plaintext node.
    approverKeyPath: ready.approver_key_path || null,
    authorityRecordPath: ready.authority_record_path,
    exitPromise, stop,
    readAuthorityRecord: () => JSON.parse(fs.readFileSync(ready.authority_record_path, "utf8")),
  };
}

// The acts that open the sealed root or approver key, and so take the operator passphrase.
const PASSPHRASE_ACTS = new Set(["approve", "rotate", "revoke", "seal-keys", "record-standing-approval", "revoke-standing-approval"]);

/**
 * Operator acts against the SERVING node (`rotate`, `revoke`, `status`, `approve`) and the
 * offline `seal-keys` conversion. `operatorPass` is forwarded only to an act that opens a sealed
 * key; without it, the act prompts on this terminal (stdin inherited, read from /dev/tty by the
 * binary) or refuses. `args` carries the act's own flags; never a key or a passphrase.
 */
export function authorityAct(act, { stateDir, binary, reason, operatorPass = "", plaintextKeys = false, args: actArgs = [] } = {}) {
  const bin = resolveBinary(binary, { build: false });
  const args = [
    act, "--state-dir", path.resolve(stateDir),
    ...(act === "revoke" && reason ? ["--reason", reason] : []),
    ...(plaintextKeys && PASSPHRASE_ACTS.has(act) && act !== "seal-keys" ? ["--plaintext-keys"] : []),
    ...actArgs,
  ];
  const passFile = path.join(path.resolve(stateDir), "keys", "guardian.pass");
  const pass = process.env.IOI_GUARDIAN_KEY_PASS || (fs.existsSync(passFile) ? fs.readFileSync(passFile, "utf8").trim() : "");
  const result = spawnSync(bin, args, {
    cwd: ROOT,
    encoding: "utf8",
    env: childEnv({ CARGO_TERM_COLOR: "never", ...(pass ? { IOI_GUARDIAN_KEY_PASS: pass } : {}) }, PASSPHRASE_ACTS.has(act) ? operatorPass : ""),
    stdio: [PASSPHRASE_ACTS.has(act) && !operatorPass && process.stdin.isTTY ? "inherit" : "ignore", "pipe", "pipe"],
  });
  return { ok: result.status === 0, status: result.status, stdout: result.stdout || "", stderr: result.stderr || "" };
}

/**
 * The operator's approval act: mint ONE one-use grant for exactly the challenge's hashes with the
 * sealed approver key, record it on the node, and return it. Returns `{ ok, grant, outcome }` or
 * `{ ok: false, stderr }`; stdout never carries a seed.
 */
export function approveGrant({ stateDir, binary, operatorPass = "", plaintextKeys = false, policyHash, requestHash, audience, targetScope, expiresInSecs, reason } = {}) {
  if (!policyHash || !requestHash || !audience || !targetScope) throw new Error("approve needs policyHash, requestHash, audience and targetScope (the challenge's exact coordinates)");
  const args = ["--policy-hash", policyHash, "--request-hash", requestHash, "--audience", audience, "--target-scope", targetScope,
    ...(expiresInSecs ? ["--expires-in-secs", String(expiresInSecs)] : []), ...(reason ? ["--reason", reason] : [])];
  const result = authorityAct("approve", { stateDir, binary, operatorPass, plaintextKeys, args });
  if (!result.ok) return { ...result, grant: null, outcome: null };
  const line = result.stdout.trim().split("\n").reverse().find((l) => l.startsWith("{"));
  const outcome = line ? JSON.parse(line) : null;
  return { ...result, outcome, grant: outcome?.approval_grant || null };
}
