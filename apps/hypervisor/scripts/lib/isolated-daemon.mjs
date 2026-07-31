// Isolated-daemon verifier plane (#69 infrastructure) — spawn a THROWAWAY hypervisor daemon
// (and optionally a serve instance pointed at it) on a temporary IOI_HYPERVISOR_DATA_DIR and a
// random IOI_HYPERVISOR_DAEMON_ADDR, so a verifier can run EVERY successful and rejected mutation
// journey without writing a single record into the real daemon's registry.
//
// WHY THIS EXISTS: DELETE /v1/hypervisor/data-sources/:id does not exist (deliberately — no
// delete authority is designed on that plane), yet several older verifiers "clean up" fixtures by
// firing that DELETE without checking the response. Every such run leaked a fixture declaration
// into the real registry. The fix is NOT to add production DELETE authority for the convenience
// of tests — it is to run mutating verifier journeys on an isolated plane that is torn down
// whole. This helper is the reusable seam for that.
//
// KNOWN LEGACY DEBT (follow-up infrastructure work, recorded here deliberately): these verifiers
// still create fixtures on the shared daemon and rely on unchecked DELETE cleanup —
//   verify-hypervisor-semantic-journey.mjs · verify-hypervisor-provenance-proof-stream-threading.mjs
//   verify-hypervisor-connector-{mapping,execution}.mjs · verify-hypervisor-capability-lease-plan.mjs
//   verify-hypervisor-app-parity-{pipeline,vertex,lineage,studio-designer}.mjs · verify-hypervisor-governed-build.mjs
// Migrating them onto this helper is queued infrastructure debt; existing leaked records in the
// real registry are NOT deleted (no delete authority exists; removal would be un-receipted).
//
// Contract:
//   const plane = await startIsolatedPlane({ serve: true });   // null => BLOCKED (no binary)
//   ... plane.daemonUrl / plane.serveUrl / plane.dataDir ...
//   await plane.stop();                                         // ALWAYS — kills both processes
//                                                               // and removes the temp data dir
// stop() is idempotent, runs on success or failure (call it in `finally`), and a best-effort
// process-exit hook covers crashes between spawn and finally.
import { spawn } from "node:child_process";
import {
  closeSync,
  mkdtempSync,
  rmSync,
  readdirSync,
  readFileSync,
  readlinkSync,
  openSync,
  readSync,
  statSync,
} from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const APP = join(HERE, "..", "..");
const REPO = join(APP, "..", "..");
export const DAEMON_BINARY = join(REPO, "target", "debug", "hypervisor-daemon");

// Keep the verifier-only transport-log boundary beside the helper that owns the
// filenames. Durable-state snapshots may exclude exactly these root files, but
// must continue to census every production-owned record and unknown residue.
export function isIsolatedDaemonLogName(name) {
  return (
    name === "isolated-daemon.log" ||
    /^isolated-daemon-restart-\d+-\d+-\d+[.]log$/u.test(name)
  );
}

// A held verifier must not inherit fault-injection or an ambient wallet fixture from the shell
// that launched it. Deliberate faults and authority fixtures are passed through `env` instead.
export function sanitizedVerifierBaseEnv(source = process.env) {
  return Object.fromEntries(
    Object.entries(source).filter(
      ([key]) =>
        !key.startsWith("IOI_TEST_") &&
        !key.startsWith("IOI_HYPERVISOR_WALLET_") &&
        !key.startsWith("IOI_WALLET_NETWORK_"),
    ),
  );
}

const STARTUP_LOG_TAIL_BYTES = 16 * 1024;

// Startup diagnostics must survive teardown of helper-owned temporary directories, but the
// exception must neither ingest an unbounded log nor echo authority material. Read only the tail
// and redact the common JSON/header/environment spellings used by local verifier fixtures.
export function boundedSanitizedLogTail(
  logPath,
  maxBytes = STARTUP_LOG_TAIL_BYTES,
) {
  const limit = Number.isSafeInteger(maxBytes) && maxBytes > 0
    ? Math.min(maxBytes, STARTUP_LOG_TAIL_BYTES)
    : STARTUP_LOG_TAIL_BYTES;
  let fd;
  try {
    const size = statSync(logPath).size;
    const length = Math.min(size, limit);
    const bytes = Buffer.alloc(length);
    fd = openSync(logPath, "r");
    readSync(fd, bytes, 0, length, Math.max(0, size - length));
    let tail = bytes.toString("utf8");
    tail = tail.replace(
      /("[^"\n]*(?:secret|password|token|private[_-]?key|approval[_-]?grant)[^"\n]*"\s*:\s*)"[^"\n]*"/giu,
      '$1"[REDACTED]"',
    );
    tail = tail.replace(
      /\b([A-Z0-9_]*(?:SECRET|PASSWORD|TOKEN|PRIVATE_KEY|APPROVAL_GRANT)[A-Z0-9_]*=)[^\s]+/gu,
      "$1[REDACTED]",
    );
    tail = tail.replace(
      /\b(authorization\s*:\s*(?:bearer\s+)?)[^\s]+/giu,
      "$1[REDACTED]",
    );
    return tail.trimEnd();
  } catch (error) {
    return `[startup log unavailable: ${error?.code || error?.message || "read failed"}]`;
  } finally {
    if (fd !== undefined) {
      try { closeSync(fd); } catch { /* already closed */ }
    }
  }
}

// A genuinely free ephemeral port, handed back by the kernel (listen on 0, read, close).
function freePort() {
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
    srv.on("error", reject);
  });
}

async function waitFor(url, tries = 60, delayMs = 500) {
  for (let i = 0; i < tries; i++) {
    const r = await fetch(url).then((x) => (x.ok ? x : null)).catch(() => null);
    if (r) return true;
    await new Promise((res) => setTimeout(res, delayMs));
  }
  return false;
}

const LINUX_LISTEN_STATE = "0A";

function linuxListeningSocketInodes(port, procRoot) {
  if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) {
    throw new Error(`isolated listener port is invalid: ${port}`);
  }
  const portHex = port.toString(16).toUpperCase().padStart(4, "0");
  const inodes = new Set();
  let readableTableCount = 0;
  for (const table of ["tcp", "tcp6"]) {
    let text;
    try {
      text = readFileSync(join(procRoot, "net", table), "utf8");
      readableTableCount += 1;
    } catch (error) {
      if (error?.code === "ENOENT") continue;
      throw error;
    }
    for (const line of text.split(/\r?\n/u).slice(1)) {
      const fields = line.trim().split(/\s+/u);
      if (fields.length < 10 || fields[3] !== LINUX_LISTEN_STATE) continue;
      const local = fields[1] || "";
      const separator = local.lastIndexOf(":");
      const localPort = separator >= 0 ? local.slice(separator + 1).toUpperCase() : "";
      const inode = fields[9] || "";
      if (localPort === portHex && /^\d+$/u.test(inode)) inodes.add(inode);
    }
  }
  if (readableTableCount === 0) {
    throw new Error(`Linux listener tables are unavailable beneath ${procRoot}`);
  }
  return inodes;
}

function linuxProcessSocketInodes(pid, procRoot) {
  if (!Number.isSafeInteger(pid) || pid < 1) {
    throw new Error(`isolated listener PID is invalid: ${pid}`);
  }
  const inodes = new Set();
  const fdRoot = join(procRoot, String(pid), "fd");
  for (const fd of readdirSync(fdRoot)) {
    let target;
    try {
      target = readlinkSync(join(fdRoot, fd));
    } catch (error) {
      // Descriptors unrelated to the long-lived listener can close while /proc is enumerated.
      if (error?.code === "ENOENT") continue;
      throw error;
    }
    const match = /^socket:\[(\d+)\]$/u.exec(target);
    if (match) inodes.add(match[1]);
  }
  return inodes;
}

// Prove that every listening socket bound to an isolated verifier port belongs to the exact
// process this helper spawned. Health + liveness alone are insufficient: freePort() necessarily
// releases its reservation before the daemon binds, so a stale or racing process could otherwise
// answer the health probe while the spawned child remains alive. The M4 proof environment is
// Linux; fail closed when its kernel socket ownership boundary cannot be inspected.
export function linuxListenerOwnershipEvidence(pid, port, procRoot = "/proc") {
  const listenerInodes = [...linuxListeningSocketInodes(port, procRoot)].sort();
  const processSocketInodes = linuxProcessSocketInodes(pid, procRoot);
  const foreignListenerInodes = listenerInodes.filter(
    (inode) => !processSocketInodes.has(inode),
  );
  return {
    proof_kind: "ioi.verifier.linux-listener-ownership.v1",
    pid,
    port,
    listener_inodes: listenerInodes,
    foreign_listener_inodes: foreignListenerInodes,
    owned:
      listenerInodes.length > 0 && foreignListenerInodes.length === 0,
  };
}

function requireLinuxListenerOwnership(child, port, role) {
  if (process.platform !== "linux") {
    throw new Error(
      `isolated ${role} listener ownership requires the Linux /proc proof boundary`,
    );
  }
  const evidence = linuxListenerOwnershipEvidence(child?.pid, port);
  if (!evidence.owned) {
    throw new Error(
      `isolated ${role} listener on port ${port} is not owned exclusively by spawned pid ${child?.pid || "unassigned"}` +
        ` (listeners=${evidence.listener_inodes.join(",") || "none"}; foreign=${evidence.foreign_listener_inodes.join(",") || "none"})`,
    );
  }
  console.log(
    `IOI_ISOLATED_LISTENER_OWNERSHIP role=${role} pid=${evidence.pid} port=${evidence.port}` +
      ` inode=${evidence.listener_inodes.join(",")} owned=true`,
  );
  return evidence;
}

// Count durable receipt FILES for a record family straight from observable storage (the same
// evidence lane the action-runtime verifier uses for its exact receipt deltas).
export function receiptFileCount(dataDir, family) {
  try { return readdirSync(join(dataDir, family)).length; } catch { return 0; }
}

/**
 * Spawn an isolated daemon (+ optional serve) on a temp data dir and random ports.
 * Returns null when the daemon binary is missing (caller should exit 2 BLOCKED), throws when the
 * processes spawn but never become healthy (that is a real failure, not an environment gap).
 * options.serve   — also spawn a serve-product-ui instance bound to the isolated daemon.
 * options.env     — extra env for BOTH processes (e.g. test flags for a flagged serve).
 * options.dataDir — reuse an EXISTING isolated data dir (crash/restart lanes prove recovery
 *                   against the same durable state); the caller keeps ownership of cleanup.
 * The returned handle exposes daemonPid/servePid so callers can prove the process they test is
 * the one this helper started; crash lanes may SIGKILL daemonPid mid-request.
 */
const EXIT_CLEANUPS = new Set();
process.on("exit", () => { for (const fn of EXIT_CLEANUPS) fn(); });

export async function startIsolatedPlane({
  serve = false,
  env = {},
  dataDir: reuseDataDir = null,
  baseEnv = process.env,
} = {}) {
  const { existsSync } = await import("node:fs");
  if (!existsSync(DAEMON_BINARY)) return null;
  const reused = !!reuseDataDir;
  const dataDir = reuseDataDir || mkdtempSync(join(tmpdir(), "ioi-isolated-plane-"));
  const daemonPort = await freePort();
  const daemonUrl = `http://127.0.0.1:${daemonPort}`;
  const logPath = join(
    dataDir,
    reused
      ? `isolated-daemon-restart-${Date.now()}-${process.pid}-${daemonPort}.log`
      : "isolated-daemon.log",
  );
  const logFd = openSync(logPath, "w");
  const children = [];
  const childExits = new Map();
  const trackChild = (child) => {
    children.push(child);
    childExits.set(
      child,
      new Promise((resolve) => {
        let settled = false;
        const finish = (code, signal) => {
          if (settled) return;
          settled = true;
          resolve({ code, signal });
        };
        if (child.exitCode !== null || child.signalCode !== null) {
          finish(child.exitCode, child.signalCode);
          return;
        }
        child.once("exit", finish);
        child.once("error", (error) => finish(null, `spawn-error:${error.code || error.message}`));
      }),
    );
    return child;
  };
  const daemon = trackChild(spawn(DAEMON_BINARY, [], {
    env: {
      ...baseEnv,
      IOI_HYPERVISOR_DATA_DIR: dataDir,
      IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${daemonPort}`,
      IOI_WALLET_SECRET_PASS:
        baseEnv.IOI_WALLET_SECRET_PASS || "ioi-isolated-verifier-pass",
      ...env,
    },
    stdio: ["ignore", logFd, logFd],
  }));
  closeSync(logFd);
  const childIsAlive = (child) => {
    if (!Number.isInteger(child?.pid) || child.pid <= 0) return false;
    if (child.exitCode !== null || child.signalCode !== null || child.killed) return false;
    try {
      process.kill(child.pid, 0);
      return true;
    } catch {
      return false;
    }
  };

  let cleanupFinished = false;
  let stopPromise = null;
  // Crash cover between spawn and the caller's finally: kill children, drop only OUR temp dir.
  // ONE shared exit hook for every plane (a per-plane listener trips MaxListenersExceeded once
  // fault/restart lanes spawn a dozen planes), and stop() DEREGISTERS the plane's cleanup so a
  // long verifier process retains no dead child/data-dir closures (#72 round 12 finding 3).
  const cleanup = () => {
    if (cleanupFinished) return;
    for (const c of children) { try { c.kill("SIGKILL"); } catch { /* already gone */ } }
    if (!reused) { try { rmSync(dataDir, { recursive: true, force: true }); } catch { /* best effort */ } }
  };
  EXIT_CLEANUPS.add(cleanup);
  const stop = () => {
    if (cleanupFinished) return Promise.resolve();
    if (stopPromise) return stopPromise;
    stopPromise = (async () => {
      for (const c of children) { try { c.kill("SIGTERM"); } catch { /* already gone */ } }
      await Promise.race([
        Promise.all([...childExits.values()]),
        new Promise((r) => setTimeout(r, 400)),
      ]);
      for (const c of children) {
        if (c.exitCode === null && c.signalCode === null) {
          try { c.kill("SIGKILL"); } catch { /* already gone */ }
        }
      }
      await Promise.all([...childExits.values()]);
      // OWNERSHIP (#72 round 6 finding 5): only directories THIS helper created are deleted; a
      // reused dataDir is caller-owned and survives stop and startup failure alike. Removal or
      // reuse happens only after every child has emitted exit, so no old daemon can overlap it.
      if (!reused) rmSync(dataDir, { recursive: true, force: true });
      cleanupFinished = true;
      EXIT_CLEANUPS.delete(cleanup);
    })().catch((error) => {
      stopPromise = null;
      throw error;
    });
    return stopPromise;
  };

  if (!(await waitFor(`${daemonUrl}/v1/hypervisor/data-sources`)) || !childIsAlive(daemon)) {
    const diagnosticTail = boundedSanitizedLogTail(logPath);
    const exit = await Promise.race([
      childExits.get(daemon),
      new Promise((resolve) => setTimeout(() => resolve(null), 250)),
    ]);
    await stop();
    throw new Error(
      `isolated daemon never became healthy as owned pid ${daemon.pid || "unassigned"} on ${daemonUrl}` +
      ` (exit=${exit ? `${exit.code ?? "null"}/${exit.signal ?? "none"}` : "still-pending"}; ` +
      `${reused ? `retained log ${logPath}` : "helper-owned log removed after bounded capture"})` +
      `\n--- bounded sanitized daemon log tail ---\n${diagnosticTail || "[empty log]"}`,
    );
  }
  let daemonListenerOwnership;
  try {
    daemonListenerOwnership = requireLinuxListenerOwnership(
      daemon,
      daemonPort,
      "daemon",
    );
  } catch (error) {
    const diagnosticTail = boundedSanitizedLogTail(logPath);
    await stop();
    throw new Error(
      `${error.message}\n--- bounded sanitized daemon log tail ---\n${diagnosticTail || "[empty log]"}`,
    );
  }

  let serveUrl = null;
  let serveChild = null;
  let serveListenerOwnership = null;
  if (serve) {
    const servePort = await freePort();
    const seedBackendPort = await freePort(); // isolate the seed server's fixture backend from :9301
    serveUrl = `http://127.0.0.1:${servePort}`;
    const serveLogFd = openSync(logPath, "a");
    serveChild = trackChild(spawn(process.execPath, [join(APP, "scripts", "serve-product-ui.mjs")], {
      env: {
        ...baseEnv,
        PORT: String(servePort), PRODUCT_UI_PORT: String(seedBackendPort),
        IOI_HYPERVISOR_DAEMON_URL: daemonUrl, IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${daemonPort}`,
        IOI_HYPERVISOR_DATA_DIR: dataDir,
        IOI_PRODUCT_UI_PUBLIC:
          baseEnv.IOI_PRODUCT_UI_PUBLIC ||
          join(APP, "product-ui", "owned", "public"),
        IOI_WALLET_TEST_SIGNER: "", IOI_APP_RUNTIME_TEST_ROUTE: "",
        ...env,
      },
      stdio: ["ignore", serveLogFd, serveLogFd],
    }));
    closeSync(serveLogFd);
    if (!(await waitFor(`${serveUrl}/__ioi/data/sources`)) || !childIsAlive(serveChild)) {
      const diagnosticTail = boundedSanitizedLogTail(logPath);
      const exit = await Promise.race([
        childExits.get(serveChild),
        new Promise((resolve) => setTimeout(() => resolve(null), 250)),
      ]);
      await stop();
      throw new Error(
        `isolated serve never became healthy as owned pid ${serveChild.pid || "unassigned"} on ${serveUrl}` +
        ` (exit=${exit ? `${exit.code ?? "null"}/${exit.signal ?? "none"}` : "still-pending"}; ` +
        `${reused ? `retained log ${logPath}` : "helper-owned log removed after bounded capture"})` +
        `\n--- bounded sanitized isolated-plane log tail ---\n${diagnosticTail || "[empty log]"}`,
      );
    }
    try {
      serveListenerOwnership = requireLinuxListenerOwnership(
        serveChild,
        servePort,
        "serve",
      );
    } catch (error) {
      const diagnosticTail = boundedSanitizedLogTail(logPath);
      await stop();
      throw new Error(
        `${error.message}\n--- bounded sanitized isolated-plane log tail ---\n${diagnosticTail || "[empty log]"}`,
      );
    }
  }

  return {
    daemonUrl,
    serveUrl,
    dataDir,
    stop,
    daemonPid: daemon.pid,
    servePid: serveChild?.pid || null,
    listenerOwnership: {
      daemon: daemonListenerOwnership,
      serve: serveListenerOwnership,
    },
  };
}
