import {
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawn, spawnSync } from "node:child_process";
import { appendFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { connect as connectTcp } from "node:net";
import { createServer as createTlsServer } from "node:tls";

import { mintApprovalGrant } from "../../../../scripts/lib/mint-approval-grant.mjs";
import { mintStandingApprovalGrant } from "../../../../scripts/lib/mint-standing-approval-grant.mjs";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../..");
const guardianPath = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "wallet-network-fixture-guardian.mjs",
);
const seeds = new Map([
  ["domain://acme-host", "07".repeat(32)],
  ["org://acme/research", "07".repeat(32)],
  ["worker://independent-alloy-lab", "09".repeat(32)],
  ["worker://replication-lab-two", "0a".repeat(32)],
  ["worker://replication-lab-three", "0b".repeat(32)],
  ["worker://frontier-only-lab", "0c".repeat(32)],
  ["org://acme/successor-authority", "0d".repeat(32)],
]);

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// Opt-in commit-path profiling reuses the estate's EXISTING AFT benchmark trace
// seam (IOI_AFT_BENCH_TRACE / IOI_AFT_BENCH_TRACE_DIR), the same gate
// crates/execution and crates/validator read. It is not a second tracer, and it
// is inert unless that seam is explicitly enabled.
const COMMIT_PATH_OBSERVATIONS_FILE = "commit-path-observations.jsonl";

export function commitPathProfileTraceDir(env = process.env) {
  if (!env.IOI_AFT_BENCH_TRACE) return null;
  const dir = env.IOI_AFT_BENCH_TRACE_DIR;
  return typeof dir === "string" && dir.length > 0 ? dir : null;
}

// Append one commit-path observation, correlated by `request_hash`.
//
// Observations are diagnostics only. A write failure never fails the journey,
// and nothing written here is read back into any authority decision.
export function recordCommitPathObservation(kind, observation, env = process.env) {
  const dir = commitPathProfileTraceDir(env);
  if (!dir) return;
  try {
    appendFileSync(
      path.join(dir, COMMIT_PATH_OBSERVATIONS_FILE),
      `${JSON.stringify({ kind, observed_at_ms: Date.now(), ...observation })}\n`,
    );
  } catch {
    /* diagnostics never fail the journey */
  }
}

const MAX_PENDING_COMMANDS = 64;
const MAX_COMMAND_BYTES = 64 * 1024;
const COMMAND_TIMEOUT_MS = Number(
  process.env.IOI_WALLET_FIXTURE_COMMAND_TIMEOUT_MS || "900000",
);
const WALLET_FIXTURE_MIN_STACK_BYTES = 32 * 1024 * 1024;

function publishFixtureOwnerMarker(
  fixtureDir,
  ownerPid,
  ownerStartTimeTicks,
) {
  const markerPath = path.join(fixtureDir, ".ioi-verifier-owner.json");
  const temporary = `${markerPath}.${process.pid}.${randomUUID()}.tmp`;
  writeFileSync(
    temporary,
    JSON.stringify({
      schema_version: 2,
      owner_pid: ownerPid,
      owner_start_time_ticks: ownerStartTimeTicks,
      owner_kind: "wallet-network-principal-authority-fixture",
      process_group_id: null,
      process_group_start_time_ticks: null,
    }),
    {
      encoding: "utf8",
      flag: "wx",
      mode: 0o600,
    },
  );
  const temporaryFd = openSync(temporary, "r");
  try {
    fsyncSync(temporaryFd);
  } finally {
    closeSync(temporaryFd);
  }
  renameSync(temporary, markerPath);
  const directoryFd = openSync(fixtureDir, "r");
  try {
    fsyncSync(directoryFd);
  } finally {
    closeSync(directoryFd);
  }
}

export function walletFixtureProcessGroupAlive(processGroupId) {
  if (!Number.isInteger(processGroupId) || processGroupId <= 0) return false;
  try {
    process.kill(-processGroupId, 0);
    return true;
  } catch (error) {
    if (error?.code === "ESRCH") return false;
    throw error;
  }
}

export function walletFixtureProcessGroupStartTimeTicks(processGroupId) {
  if (!Number.isInteger(processGroupId) || processGroupId <= 0) return null;
  try {
    const stat = readFileSync(`/proc/${processGroupId}/stat`, "utf8");
    const commandEnd = stat.lastIndexOf(") ");
    if (commandEnd < 0) return null;
    const fieldsAfterCommand = stat
      .slice(commandEnd + 2)
      .trim()
      .split(/\s+/);
    const startTimeTicks = fieldsAfterCommand[19];
    return /^[0-9]+$/.test(startTimeTicks || "") ? startTimeTicks : null;
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    throw error;
  }
}

export function walletFixtureProcessGroupIdentityMatches(marker) {
  return (
    Number.isInteger(marker?.process_group_id) &&
    marker.process_group_id > 0 &&
    typeof marker?.process_group_start_time_ticks === "string" &&
    /^[0-9]+$/.test(marker.process_group_start_time_ticks) &&
    walletFixtureProcessGroupStartTimeTicks(marker.process_group_id) ===
      marker.process_group_start_time_ticks
  );
}

export function walletFixtureOwnerIdentityMatches(marker) {
  return (
    Number.isInteger(marker?.owner_pid) &&
    marker.owner_pid > 0 &&
    typeof marker?.owner_start_time_ticks === "string" &&
    /^[0-9]+$/.test(marker.owner_start_time_ticks) &&
    walletFixtureProcessGroupStartTimeTicks(marker.owner_pid) ===
      marker.owner_start_time_ticks
  );
}

function exactHex32(value, label) {
  const normalized = String(value || "").trim().replace(/^sha256:/, "").toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(normalized)) {
    throw new Error(`${label} must be exact 32-byte hex`);
  }
  return normalized;
}

function grantHex32(grant, field) {
  const bytes = grant?.[field];
  if (!Array.isArray(bytes) || bytes.length !== 32 || bytes.some((byte) => !Number.isInteger(byte) || byte < 0 || byte > 255)) {
    throw new Error(`approval grant ${field} must be a 32-byte array`);
  }
  return Buffer.from(bytes).toString("hex");
}

function createCommandDirectory(commandsDir) {
  const pending = readdirSync(commandsDir, { withFileTypes: true })
    .filter((entry) => entry.isDirectory()).length;
  if (pending >= MAX_PENDING_COMMANDS) {
    throw new Error(`wallet.network fixture command queue is full (${pending}/${MAX_PENDING_COMMANDS})`);
  }
  for (let attempt = 0; attempt < 4; attempt += 1) {
    const commandId = randomUUID();
    const commandDir = path.join(commandsDir, commandId);
    try {
      mkdirSync(commandDir, { mode: 0o700 });
      return { commandId, commandDir };
    } catch (error) {
      if (error?.code !== "EEXIST") throw error;
    }
  }
  throw new Error("wallet.network fixture could not allocate a collision-free command id");
}

function runOpenSsl(args, fixtureDir) {
  const result = spawnSync("openssl", args, { cwd: fixtureDir, encoding: "utf8" });
  if (result.error || result.status !== 0) {
    throw new Error(`openssl ${args[0]} failed: ${result.error?.message || result.stderr || `exit ${result.status}`}`);
  }
}

async function startPinnedTlsProxy(upstreamAddr, fixtureDir) {
  runOpenSsl([
    "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
    "-keyout", "wallet-network-ca.key", "-out", "wallet-network-ca.pem",
    "-subj", "/CN=IOI Hypervisor wallet.network fixture CA",
    "-addext", "basicConstraints=critical,CA:TRUE",
    "-addext", "keyUsage=critical,keyCertSign,cRLSign",
  ], fixtureDir);
  runOpenSsl([
    "req", "-new", "-newkey", "rsa:2048", "-nodes",
    "-keyout", "wallet-network-server.key", "-out", "wallet-network-server.csr",
    "-subj", "/CN=wallet-network.fixture",
  ], fixtureDir);
  writeFileSync(path.join(fixtureDir, "wallet-network-server.ext"), [
    "basicConstraints=critical,CA:FALSE",
    "keyUsage=critical,digitalSignature,keyEncipherment",
    "extendedKeyUsage=serverAuth",
    "subjectAltName=DNS:wallet-network.fixture",
    "",
  ].join("\n"));
  runOpenSsl([
    "x509", "-req", "-days", "1",
    "-in", "wallet-network-server.csr",
    "-CA", "wallet-network-ca.pem", "-CAkey", "wallet-network-ca.key", "-CAcreateserial",
    "-out", "wallet-network-server.pem", "-extfile", "wallet-network-server.ext",
  ], fixtureDir);

  const upstream = new URL(upstreamAddr.includes("://") ? upstreamAddr : `http://${upstreamAddr}`);
  const sockets = new Set();
  const server = createTlsServer({
    key: readFileSync(path.join(fixtureDir, "wallet-network-server.key")),
    cert: readFileSync(path.join(fixtureDir, "wallet-network-server.pem")),
    ALPNProtocols: ["h2"],
  }, (client) => {
    sockets.add(client);
    const target = connectTcp({ host: upstream.hostname, port: Number(upstream.port) });
    sockets.add(target);
    client.on("close", () => { sockets.delete(client); target.destroy(); });
    target.on("close", () => { sockets.delete(target); client.destroy(); });
    client.on("error", () => target.destroy());
    target.on("error", () => client.destroy());
    client.pipe(target);
    target.pipe(client);
  });
  server.on("tlsClientError", () => {});
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  server.on("error", () => {});
  const destroy = () => {
    for (const socket of sockets) socket.destroy();
    try { server.close(); } catch { /* already closed */ }
  };
  return {
    rpcAddr: `https://127.0.0.1:${server.address().port}`,
    caPath: path.join(fixtureDir, "wallet-network-ca.pem"),
    serverName: "wallet-network.fixture",
    destroy,
    async stop() {
      for (const socket of sockets) socket.destroy();
      await new Promise((resolve) => {
        try {
          server.close(resolve);
        } catch {
          resolve();
        }
      });
    },
  };
}

export async function startRealWalletNetworkPrincipalAuthorityFixture({
  baseEnv = process.env,
  rootSeedHex,
  resumeResourceDir,
  persistChainState = false,
  wallClockChain = false,
} = {}) {
  const readyTimeoutMs = Number(
    baseEnv.IOI_WALLET_FIXTURE_READY_TIMEOUT_MS || "600000",
  );
  if (!Number.isSafeInteger(readyTimeoutMs) || readyTimeoutMs < 1_000 || readyTimeoutMs > 3_600_000) {
    throw new Error("IOI_WALLET_FIXTURE_READY_TIMEOUT_MS must be an integer between 1000 and 3600000");
  }
  const normalizedRootSeed = rootSeedHex == null
    ? null
    : exactHex32(rootSeedHex, "rootSeedHex");
  const ownerStartTimeTicks = walletFixtureProcessGroupStartTimeTicks(
    process.pid,
  );
  if (ownerStartTimeTicks === null) {
    throw new Error("wallet.network fixture parent lacks a process identity");
  }
  let fixtureDir;
  if (resumeResourceDir == null) {
    fixtureDir = path.join(
      tmpdir(),
      `ioi-wallet-network-pa-${process.pid}-${ownerStartTimeTicks}-${randomUUID()}`,
    );
    mkdirSync(fixtureDir, { mode: 0o700 });
  } else {
    // Checkpoint-lane TRUE RESUME: reclaim the EXACT recorded fixture path so
    // any absolute-path reference a restored daemon plane carries stays
    // valid, and RESUME the recorded wallet chain from the durable cluster
    // state the capture archived under <fixtureDir>/chain-state (see
    // IOI_TESTING_CLUSTER_STATE_DIR in crates/cli/src/testing/cluster.rs).
    // Old wallet raw state — committed consumptions, nonces, receipts — is
    // preserved; only this life's control files are cleared so readiness and
    // ownership are re-published by the resumed fixture process.
    fixtureDir = path.resolve(String(resumeResourceDir));
    if (
      path.dirname(fixtureDir) !== path.resolve(tmpdir()) ||
      !path.basename(fixtureDir).startsWith("ioi-wallet-network-pa-")
    ) {
      throw new Error(
        "wallet.network fixture resume path must be a verifier-owned wallet fixture directory",
      );
    }
    if (
      !existsSync(
        path.join(fixtureDir, "chain-state", "cluster-state.json"),
      )
    ) {
      throw new Error(
        "wallet.network fixture resume requires archived durable chain state at " +
          `${path.join(fixtureDir, "chain-state")}; re-capture this checkpoint`,
      );
    }
    for (const controlEntry of [
      "shutdown",
      "ready.json",
      "commands",
      ".ioi-verifier-owner.json",
      "hypervisor-wallet-transactions.lock",
      "wallet-network-ca.key",
      "wallet-network-ca.pem",
      "wallet-network-ca.srl",
      "wallet-network-server.key",
      "wallet-network-server.csr",
      "wallet-network-server.pem",
      "wallet-network-server.ext",
    ]) {
      rmSync(path.join(fixtureDir, controlEntry), {
        recursive: true,
        force: true,
      });
    }
    persistChainState = true;
  }
  try {
    publishFixtureOwnerMarker(
      fixtureDir,
      process.pid,
      ownerStartTimeTicks,
    );
  } catch (error) {
    rmSync(fixtureDir, { recursive: true, force: true });
    throw error;
  }
  let output = "";
  let exited = null;
  let tlsProxy;
  let cleanupFinished = false;
  let stopPromise = null;
  // Opt-in release fixture: builds the cargo-test fixture process AND the
  // node binaries it launches (IOI_TEST_BUILD_PROFILE) with optimizations.
  // Chain and authorization semantics are identical; only wall-clock changes.
  const releaseFixture = process.env.IOI_WALLET_FIXTURE_RELEASE === "1";
  const cargoArgs = [
    "test", "-p", "ioi-cli",
    ...(releaseFixture ? ["--release"] : []),
    "--test", "hypervisor_wallet_network_fixture",
    "wallet_network_principal_authority_fixture",
    "--", "--ignored", "--nocapture",
  ];
  const spawnEnv = {
    ...baseEnv,
  };
  // The durable-chain-state opt-in is explicit per fixture start: never let
  // an ambient IOI_TESTING_CLUSTER_STATE_DIR leak a foreign state dir into
  // this fixture's private cluster.
  delete spawnEnv.IOI_TESTING_CLUSTER_STATE_DIR;
  if (persistChainState) {
    spawnEnv.IOI_TESTING_CLUSTER_STATE_DIR = path.join(
      fixtureDir,
      "chain-state",
    );
  }
  if (releaseFixture) {
    spawnEnv.IOI_TEST_BUILD_PROFILE = "release";
  }
  // READINESS SEMANTICS, not a measurement. IOI_AFT_BENCH_TRACE makes the
  // in-process cluster treat itself as a benchmark harness, which RAISES the
  // default ready-height lag from 1 to 16 (crates/cli/src/testing/cluster.rs).
  // A profiled run must keep the soak's exact readiness bar, so the caller has
  // to pin it — and `sanitizedVerifierBaseEnv` strips every IOI_TEST_* name
  // before it reaches here, so the pin only survives by being re-asserted
  // explicitly, exactly as IOI_TEST_BUILD_PROFILE is above.
  if (process.env.IOI_AFT_BENCH_TRACE) {
    const readyHeightLagMax = process.env.IOI_TEST_READY_HEIGHT_LAG_MAX;
    if (!/^[0-9]+$/.test(String(readyHeightLagMax || ""))) {
      throw new Error(
        "IOI_AFT_BENCH_TRACE changes cluster readiness semantics; a profiled wallet fixture must " +
          "pin IOI_TEST_READY_HEIGHT_LAG_MAX to the readiness bar it intends to measure",
      );
    }
    spawnEnv.IOI_TEST_READY_HEIGHT_LAG_MAX = String(readyHeightLagMax);
  }
  const child = spawn(
    process.execPath,
    [guardianPath],
    {
      cwd: repoRoot,
      env: {
        ...spawnEnv,
        CARGO_TERM_COLOR: "never",
        IOI_HYPERVISOR_WALLET_FIXTURE_DIR: fixtureDir,
        IOI_HYPERVISOR_WALLET_FIXTURE_OWNER_PID: String(process.pid),
        IOI_HYPERVISOR_WALLET_FIXTURE_OWNER_START_TIME_TICKS:
          ownerStartTimeTicks,
        IOI_WALLET_FIXTURE_GUARDIAN_CARGO_ARGS: JSON.stringify(cargoArgs),
        IOI_WALLET_FIXTURE_GUARDIAN_CARGO_CWD: repoRoot,
        // Long held journeys execute enough IAVL-backed wallet blocks to make
        // the debug runtime's default worker stack unsafe. Keep this fixture
        // process-local; it changes no chain or authorization semantics.
        RUST_MIN_STACK: String(WALLET_FIXTURE_MIN_STACK_BYTES),
        ...(normalizedRootSeed
          ? { IOI_HYPERVISOR_WALLET_FIXTURE_ROOT_SEED_HEX: normalizedRootSeed }
          : {}),
        ...(wallClockChain
          ? { IOI_HYPERVISOR_WALLET_FIXTURE_WALL_CLOCK: "1" }
          : {}),
        IOI_GUARDIAN_KEY_PASS: "hypervisor-held-bar",
        // Deep-journey blocks commit slowly on the debug fixture; the
        // fixture's own approval submissions need the same patience the
        // daemon's consumptions were granted.
        IOI_TESTING_RPC_COMMIT_TIMEOUT_SECS: "900",
        // Diagnostic passthrough: surface wallet-chain execution logs when a
        // caller needs to see WHY a transaction produced no receipt.
        ...(process.env.IOI_WALLET_FIXTURE_RUST_LOG
          ? { RUST_LOG: process.env.IOI_WALLET_FIXTURE_RUST_LOG }
          : {}),
      },
      detached: true,
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  const processGroupId = child.pid;
  const processGroupStartTimeTicks =
    walletFixtureProcessGroupStartTimeTicks(processGroupId);
  if (processGroupStartTimeTicks === null) {
    try { child.kill("SIGKILL"); } catch { /* child already exited */ }
    rmSync(fixtureDir, { recursive: true, force: true });
    throw new Error(
      "wallet.network fixture guardian lacks a process-group identity",
    );
  }
  const ownedProcessGroupIdentityMatches = () =>
    walletFixtureProcessGroupStartTimeTicks(processGroupId) ===
      processGroupStartTimeTicks;
  const teeLogPath = baseEnv.IOI_WALLET_FIXTURE_TEE_LOG || null;
  const capture = (chunk) => {
    output = `${output}${chunk}`;
    if (output.length > 32_000) output = output.slice(-32_000);
    // Env-gated diagnostic tee: the rolling in-memory window is useless once
    // the plane is torn down; a retained log is the only way to see a
    // wallet-side transaction refusal that produced no receipt.
    if (teeLogPath) {
      try {
        appendFileSync(teeLogPath, chunk);
      } catch {
        /* diagnostics never fail the fixture */
      }
    }
  };
  child.stdout.on("data", capture);
  child.stderr.on("data", capture);
  const exitPromise = new Promise((resolve) => {
    let settled = false;
    const finish = (code, signal) => {
      if (settled) return;
      settled = true;
      exited = { code, signal };
      resolve(exited);
    };
    child.once("exit", finish);
    child.once("error", (error) => {
      finish(null, `spawn-error:${error.code || error.message}`);
    });
  });
  const killOwnedProcessGroupAndWait = async () => {
    if (ownedProcessGroupIdentityMatches()) {
      try { process.kill(-processGroupId, "SIGKILL"); } catch (error) {
        if (error?.code !== "ESRCH") throw error;
      }
    }
    await exitPromise;
    const deadline = Date.now() + 30_000;
    while (ownedProcessGroupIdentityMatches() && Date.now() < deadline) {
      await delay(25);
    }
    if (ownedProcessGroupIdentityMatches()) {
      throw new Error(
        `wallet.network fixture process group ${processGroupId} still has owned descendants after SIGKILL`,
      );
    }
  };
  const exitCleanup = () => {
    if (cleanupFinished) return;
    if (!exited) {
      try { writeFileSync(path.join(fixtureDir, "shutdown"), "parent-exit\n"); } catch { /* best effort */ }
      if (ownedProcessGroupIdentityMatches()) {
        try { process.kill(-processGroupId, "SIGKILL"); } catch { /* already gone */ }
      }
    }
    try { tlsProxy?.destroy(); } catch { /* best effort */ }
    try { rmSync(fixtureDir, { recursive: true, force: true }); } catch { /* best effort */ }
  };
  process.on("exit", exitCleanup);

  let manifest;
  let capabilityAccountId;
  let commandsDir;
  let transactionLockPath;
  try {
    const readyPath = path.join(fixtureDir, "ready.json");
    const deadline = Date.now() + readyTimeoutMs;
    while (!existsSync(readyPath)) {
      if (exited) {
        throw new Error(`real wallet.network fixture exited before readiness (${JSON.stringify(exited)}):\n${output}`);
      }
      if (Date.now() >= deadline) {
        throw new Error(`real wallet.network fixture did not become ready after ${readyTimeoutMs}ms:\n${output}`);
      }
      await delay(50);
    }
    manifest = JSON.parse(readFileSync(readyPath, "utf8"));
    if (!Number.isSafeInteger(manifest.chain_timestamp_ms) || manifest.chain_timestamp_ms < 1) {
      throw new Error("real wallet.network fixture returned an invalid chain timestamp");
    }
    const ownerMarker = JSON.parse(
      readFileSync(
        path.join(fixtureDir, ".ioi-verifier-owner.json"),
        "utf8",
      ),
    );
    if (
      ownerMarker.schema_version !== 2 ||
      ownerMarker.owner_pid !== process.pid ||
      ownerMarker.owner_start_time_ticks !== ownerStartTimeTicks ||
      ownerMarker.owner_kind !==
        "wallet-network-principal-authority-fixture" ||
      ownerMarker.process_group_id !== processGroupId ||
      ownerMarker.process_group_start_time_ticks !==
        processGroupStartTimeTicks ||
      !walletFixtureProcessGroupIdentityMatches(ownerMarker)
    ) {
      throw new Error(
        "real wallet.network fixture did not publish its exact process-group ownership before readiness",
      );
    }
    capabilityAccountId = exactHex32(
      manifest.capability_account_id,
      "capability_account_id",
    );
    commandsDir = path.resolve(String(manifest.commands_dir || ""));
    if (commandsDir !== path.join(fixtureDir, "commands")) {
      throw new Error("real wallet.network fixture returned an unexpected command directory");
    }
    transactionLockPath = path.resolve(
      String(manifest.transaction_lock_path || ""),
    );
    if (
      transactionLockPath !==
      path.join(fixtureDir, "hypervisor-wallet-transactions.lock")
    ) {
      throw new Error(
        "real wallet.network fixture returned an unexpected transaction lock path",
      );
    }
    tlsProxy = await startPinnedTlsProxy(manifest.rpc_addr, fixtureDir);
  } catch (error) {
    process.off("exit", exitCleanup);
    let cleanupError;
    try {
      await killOwnedProcessGroupAndWait();
    } catch (failure) {
      cleanupError = failure;
    }
    try { tlsProxy?.destroy(); } catch { /* best effort */ }
    rmSync(fixtureDir, { recursive: true, force: true });
    error.processGroupId = processGroupId;
    error.processGroupStartTimeTicks = processGroupStartTimeTicks;
    error.cleanupConfirmed = !ownedProcessGroupIdentityMatches();
    if (cleanupError) error.cause = cleanupError;
    throw error;
  }
  async function runCommand(payload) {
    const { commandId, commandDir } = createCommandDirectory(commandsDir);
    const requestPath = path.join(commandDir, "request.json");
    const tempPath = path.join(commandDir, "request.json.tmp");
    const command = JSON.stringify(payload);
    if (Buffer.byteLength(command) > MAX_COMMAND_BYTES) {
      rmSync(commandDir, { recursive: true, force: true });
      throw new Error(
        `wallet.network fixture command exceeds ${MAX_COMMAND_BYTES} bytes`,
      );
    }
    writeFileSync(tempPath, command, {
      encoding: "utf8",
      flag: "wx",
      mode: 0o600,
    });
    renameSync(tempPath, requestPath);

    const responsePath = path.join(commandDir, "response.json");
    const deadline = Date.now() + COMMAND_TIMEOUT_MS;
    while (!existsSync(responsePath)) {
      if (exited) {
        throw new Error(
          `real wallet.network fixture exited during ${payload.operation} (${JSON.stringify(exited)}):\n${output}`,
        );
      }
      if (Date.now() >= deadline) {
        throw new Error(
          `real wallet.network fixture ${payload.operation} timed out after ${COMMAND_TIMEOUT_MS}ms`,
        );
      }
      await delay(25);
    }
    const response = JSON.parse(readFileSync(responsePath, "utf8"));
    rmSync(commandDir, { recursive: true, force: true });
    if (response.schema_version !== 1 || response.command_id !== commandId) {
      throw new Error(
        "real wallet.network fixture returned a mismatched command response",
      );
    }
    if (!response.ok) {
      throw new Error(
        `wallet.network ${payload.operation} refused: ${response.error || "unknown error"}\n${output}`,
      );
    }
    return response;
  }

  async function recordApproval(
    principalRef,
    policyHash,
    requestHash,
    grant,
    targetScope = "scope:autonomous_system.genesis_admit",
  ) {
    if (!seeds.has(principalRef)) {
      throw new Error(`real wallet.network fixture has no approver for ${principalRef}`);
    }
    const normalizedPolicyHash = exactHex32(policyHash, "policyHash");
    const normalizedRequestHash = exactHex32(requestHash, "requestHash");
    if (grantHex32(grant, "policy_hash") !== normalizedPolicyHash ||
        grantHex32(grant, "request_hash") !== normalizedRequestHash) {
      throw new Error("approval grant does not match the requested policy/request hashes");
    }
    if (grantHex32(grant, "audience") !== capabilityAccountId) {
      throw new Error("approval grant does not target the fixture capability account");
    }

    const command = {
      schema_version: 1,
      operation: "record_approval",
      principal_ref: principalRef,
      policy_hash: normalizedPolicyHash,
      request_hash: normalizedRequestHash,
      approval_grant: grant,
      target_scope: targetScope,
    };
    let response;
    let recordAttempts = 0;
    const recordStarted = process.hrtime.bigint();
    for (let attempt = 0; attempt < 3; attempt += 1) {
      try {
        recordAttempts += 1;
        response = await runCommand(command);
        break;
      } catch (error) {
        const message = String(error?.message || error);
        if (
          attempt === 2 ||
          !message.includes("wallet.network record_approval refused") ||
          !message.includes("Timeout waiting for tx")
        ) {
          throw error;
        }
        // record_approval is keyed by request_hash. The fixture checks that
        // exact key before submitting, so retrying this byte-identical command
        // observes a late commit or safely resubmits after a transport timeout.
        await new Promise((resolve) => setTimeout(resolve, 250));
      }
    }
    if (!response) {
      throw new Error("wallet.network record_approval produced no response");
    }
    if (response.request_hash !== normalizedRequestHash) {
      throw new Error("wallet.network record_approval response named a different request hash");
    }
    // Opt-in observation only. The response object is returned exactly as the
    // fixture produced it; nothing above or below this call is conditioned on
    // whether profiling is enabled.
    recordCommitPathObservation("approval_record", {
      request_hash: normalizedRequestHash,
      policy_hash: normalizedPolicyHash,
      target_scope: targetScope,
      principal_ref: principalRef,
      record_approval_ms: Number(
        (process.hrtime.bigint() - recordStarted) / 1_000_000n,
      ),
      record_approval_attempts: recordAttempts,
    });
    return response;
  }

  async function revokePrincipalAuthority(principalRef) {
    if (!seeds.has(principalRef)) {
      throw new Error(
        `real wallet.network fixture has no binding for ${principalRef}`,
      );
    }
    const response = await runCommand({
      schema_version: 1,
      operation: "revoke_principal_authority",
      principal_ref: principalRef,
    });
    if (
      typeof response.binding_ref !== "string" ||
      !response.binding_ref.startsWith(
        "wallet.network://principal-authority-binding/",
      )
    ) {
      throw new Error(
        "wallet.network revocation response lacks canonical binding coordinates",
      );
    }
    return response;
  }

  async function recordStandingApprovalGrant(
    principalRef,
    grant,
    standingAuthorityEnvelope,
    approvalCeremonyContext,
    authFactorReceipt,
  ) {
    if (!seeds.has(principalRef)) {
      throw new Error(`real wallet.network fixture has no approver for ${principalRef}`);
    }
    if (grantHex32(grant, "audience") !== capabilityAccountId) {
      throw new Error("standing approval grant does not target the fixture capability account");
    }
    const response = await runCommand({
      schema_version: 1,
      operation: "record_standing_approval_grant",
      principal_ref: principalRef,
      standing_approval_grant: grant,
      standing_authority_envelope: standingAuthorityEnvelope,
      approval_ceremony_context: approvalCeremonyContext,
      auth_factor_receipt: authFactorReceipt,
    });
    const expected = grantHex32(grant, "standing_envelope_hash");
    if (response.standing_envelope_hash !== expected) {
      throw new Error("wallet.network standing grant response named a different envelope hash");
    }
    return response;
  }

  async function revokeStandingApprovalGrant(principalRef, grantHash) {
    if (!seeds.has(principalRef)) {
      throw new Error(`real wallet.network fixture has no approver for ${principalRef}`);
    }
    const normalized = exactHex32(grantHash, "grantHash");
    const response = await runCommand({
      schema_version: 1,
      operation: "revoke_standing_approval_grant",
      principal_ref: principalRef,
      standing_grant_hash: normalized,
    });
    if (response.standing_grant_hash !== normalized || response.standing_grant_status !== "revoked") {
      throw new Error("wallet.network standing revocation response is not exact and terminal");
    }
    return response;
  }

  async function readChainTimestampMs() {
    const response = await runCommand({
      schema_version: 1,
      operation: "read_chain_timestamp",
      // Fixture commands retain one closed request schema. This read does not
      // resolve or exercise principal authority, but the field remains
      // explicit so a future schema split cannot accidentally infer one.
      principal_ref: "fixture://wallet-network/chain-clock",
    });
    if (!Number.isSafeInteger(response.chain_timestamp_ms) || response.chain_timestamp_ms < 1) {
      throw new Error("wallet.network fixture returned an invalid current chain timestamp");
    }
    return response.chain_timestamp_ms;
  }
  return {
    resourceDir: fixtureDir,
    processGroupId,
    processGroupStartTimeTicks,
    env: {
      IOI_WALLET_NETWORK_URL: "",
      IOI_WALLET_NETWORK_RPC_ADDR: tlsProxy.rpcAddr,
      IOI_WALLET_NETWORK_CHAIN_ID: String(manifest.chain_id),
      IOI_HYPERVISOR_WALLET_CLIENT_KEY_PATH: manifest.capability_key_path,
      IOI_WALLET_NETWORK_TRANSACTION_LOCK_PATH: transactionLockPath,
      IOI_WALLET_NETWORK_ROOT_RECORD_PATH: manifest.root_record_path,
      IOI_WALLET_NETWORK_TLS_CA_PATH: tlsProxy.caPath,
      IOI_WALLET_NETWORK_TLS_SERVER_NAME: tlsProxy.serverName,
      IOI_GUARDIAN_KEY_PASS: manifest.guardian_key_pass,
      // The in-process one-validator fixture intentionally executes and commits every lookup;
      // leave production's five-second default untouched, but do not make the positive held bar
      // flaky when the debug cluster is saturated by the full lifecycle journey.
      // Late-journey consumptions on the debug fixture legitimately take
      // minutes as the IAVL chain deepens; match the estate's 900s
      // held-operation ceiling rather than failing honest slow inclusion.
      IOI_WALLET_NETWORK_RESOLUTION_TIMEOUT_MS: "900000",
      IOI_TESTING_RPC_COMMIT_TIMEOUT_SECS: "900",
      IOI_HYPERVISOR_GOVERNED_REPLAY_TIMEOUT_MS: "45000",
    },
    capabilityAccountId,
    chainTimestampMs: manifest.chain_timestamp_ms,
    mint(principalRef, policyHash, requestHash) {
      const seed = seeds.get(principalRef);
      if (!seed) throw new Error(`real wallet.network fixture has no approver for ${principalRef}`);
      return mintApprovalGrant({ seed, policyHash, requestHash });
    },
    mintForCapability(principalRef, policyHash, requestHash) {
      const seed = seeds.get(principalRef);
      if (!seed) throw new Error(`real wallet.network fixture has no approver for ${principalRef}`);
      return mintApprovalGrant({
        seed,
        policyHash,
        requestHash,
        audience: capabilityAccountId,
      });
    },
    mintStandingForCapability(principalRef, options) {
      const seed = seeds.get(principalRef);
      if (!seed) throw new Error(`real wallet.network fixture has no approver for ${principalRef}`);
      return mintStandingApprovalGrant({
        ...options,
        seed,
        audience: capabilityAccountId,
      });
    },
    async mintRecorded(principalRef, policyHash, requestHash, targetScope) {
      if (typeof targetScope !== "string" || targetScope.length === 0) {
        throw new Error("recorded approval requires the challenge's exact target scope");
      }
      const seed = seeds.get(principalRef);
      if (!seed) throw new Error(`real wallet.network fixture has no approver for ${principalRef}`);
      const grant = mintApprovalGrant({
        seed,
        policyHash,
        requestHash,
        audience: capabilityAccountId,
      });
      await recordApproval(
        principalRef,
        policyHash,
        requestHash,
        grant,
        targetScope,
      );
      return grant;
    },
    recordApproval,
    recordStandingApprovalGrant,
    readChainTimestampMs,
    revokeStandingApprovalGrant,
    revokePrincipalAuthority,
    stop({ preserveResourceDir = false } = {}) {
      if (cleanupFinished) return Promise.resolve();
      if (stopPromise) return stopPromise;
      stopPromise = (async () => {
        let stopError;
        let treeError;
        try {
          await tlsProxy.stop();
          if (!exited) writeFileSync(path.join(fixtureDir, "shutdown"), "stop\n");
          const stopDeadline = Date.now() + 30_000;
          while (!exited && Date.now() < stopDeadline) await delay(25);
        } catch (error) {
          stopError = error;
        } finally {
          try {
            await killOwnedProcessGroupAndWait();
          } catch (error) {
            treeError = error;
          }
          try { tlsProxy.destroy(); } catch { /* best effort */ }
          // The fixture directory is removed only after cargo has emitted exit, so a subsequent
          // fixture cannot overlap a still-exiting process that retains handles into this tree.
          // Checkpoint capture preserves the exited directory for archival; its caller owns the
          // removal that every other stop() performs here.
          if (!preserveResourceDir) {
            rmSync(fixtureDir, { recursive: true, force: true });
          }
          process.off("exit", exitCleanup);
        }
        if (ownedProcessGroupIdentityMatches()) {
          throw new Error(
            `wallet.network fixture process group ${processGroupId} survived teardown`,
          );
        }
        cleanupFinished = true;
        if (treeError) throw treeError;
        if (stopError) throw stopError;
      })().catch((error) => {
        stopPromise = null;
        throw error;
      });
      return stopPromise;
    },
  };
}
