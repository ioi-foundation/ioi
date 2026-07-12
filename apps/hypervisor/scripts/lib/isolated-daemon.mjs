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
import { mkdtempSync, rmSync, readdirSync, openSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const APP = join(HERE, "..", "..");
const REPO = join(APP, "..", "..");
export const DAEMON_BINARY = join(REPO, "target", "debug", "hypervisor-daemon");

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

// Count durable receipt FILES for a record family straight from observable storage (the same
// evidence lane the action-runtime verifier uses for its exact receipt deltas).
export function receiptFileCount(dataDir, family) {
  try { return readdirSync(join(dataDir, family)).length; } catch { return 0; }
}

/**
 * Spawn an isolated daemon (+ optional serve) on a temp data dir and random ports.
 * Returns null when the daemon binary is missing (caller should exit 2 BLOCKED), throws when the
 * processes spawn but never become healthy (that is a real failure, not an environment gap).
 * options.serve  — also spawn a serve-product-ui instance bound to the isolated daemon.
 * options.env    — extra env for BOTH processes (e.g. test flags for a flagged serve).
 */
export async function startIsolatedPlane({ serve = false, env = {} } = {}) {
  const { existsSync } = await import("node:fs");
  if (!existsSync(DAEMON_BINARY)) return null;
  const dataDir = mkdtempSync(join(tmpdir(), "ioi-isolated-plane-"));
  const daemonPort = await freePort();
  const daemonUrl = `http://127.0.0.1:${daemonPort}`;
  const logFd = openSync(join(dataDir, "isolated-daemon.log"), "w");
  const children = [];
  const daemon = spawn(DAEMON_BINARY, [], {
    env: {
      ...process.env,
      IOI_HYPERVISOR_DATA_DIR: dataDir,
      IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${daemonPort}`,
      IOI_WALLET_SECRET_PASS: process.env.IOI_WALLET_SECRET_PASS || "ioi-isolated-verifier-pass",
      ...env,
    },
    stdio: ["ignore", logFd, logFd],
  });
  children.push(daemon);

  let stopped = false;
  const stop = async () => {
    if (stopped) return;
    stopped = true;
    for (const c of children) { try { c.kill("SIGTERM"); } catch { /* already gone */ } }
    await new Promise((r) => setTimeout(r, 400));
    for (const c of children) { try { c.kill("SIGKILL"); } catch { /* already gone */ } }
    try { rmSync(dataDir, { recursive: true, force: true }); } catch { /* best effort */ }
  };
  // Crash cover between spawn and the caller's finally: kill children, drop the temp dir.
  process.on("exit", () => {
    if (stopped) return;
    for (const c of children) { try { c.kill("SIGKILL"); } catch { /* already gone */ } }
    try { rmSync(dataDir, { recursive: true, force: true }); } catch { /* best effort */ }
  });

  if (!(await waitFor(`${daemonUrl}/v1/hypervisor/data-sources`))) {
    await stop();
    throw new Error(`isolated daemon never became healthy on ${daemonUrl} (log was in the removed temp dir)`);
  }

  let serveUrl = null;
  if (serve) {
    const servePort = await freePort();
    const mirrorPort = await freePort(); // the serve spawns its own mock mirror — keep it off :9301
    serveUrl = `http://127.0.0.1:${servePort}`;
    const child = spawn(process.execPath, [join(APP, "scripts", "serve-product-ui.mjs")], {
      env: {
        ...process.env,
        PORT: String(servePort), PRODUCT_UI_PORT: String(mirrorPort),
        IOI_HYPERVISOR_DAEMON_URL: daemonUrl, IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${daemonPort}`,
        IOI_HYPERVISOR_DATA_DIR: dataDir,
        IOI_PRODUCT_UI_PUBLIC: process.env.IOI_PRODUCT_UI_PUBLIC || join(APP, "product-ui", "owned", "public"),
        IOI_WALLET_TEST_SIGNER: "", IOI_APP_RUNTIME_TEST_ROUTE: "",
        ...env,
      },
      stdio: ["ignore", logFd, logFd],
    });
    children.push(child);
    if (!(await waitFor(`${serveUrl}/__ioi/data/sources`))) {
      await stop();
      throw new Error(`isolated serve never became healthy on ${serveUrl}`);
    }
  }

  return { daemonUrl, serveUrl, dataDir, stop };
}
