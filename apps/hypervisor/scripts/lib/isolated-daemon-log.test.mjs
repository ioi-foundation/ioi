// The isolated plane's log keeps EVERY writer's lines (the HARNESS FIX HYP filed on 2026-10-13 14:55 EDT from
// BUILD-DELTA #48 ticket 9's miss A4). The daemon and the serve share one log file: if either writer opens it
// WITHOUT append (the daemon used "w"), that writer keeps its own file offset, and every later write it makes
// lands over whatever the other writer appended meanwhile, so the other writer's lines vanish without a trace
// and any evidence read from them is silently empty. Here the plane is started with a STAND-IN daemon
// (isolated-daemon-log.test-fixture.mjs: it binds the plane's address, answers /healthz and the
// local-development posture, and writes log lines on demand) so the test can make the daemon write AFTER the
// other writer and then read what the log kept.
//
//   node --test apps/hypervisor/scripts/lib/isolated-daemon-log.test.mjs
import assert from "node:assert/strict";
import { closeSync, existsSync, openSync, readdirSync, readFileSync, writeSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
// DAEMON_BINARY resolves from the process environment when the helper module loads, so the stand-in is
// named before the helper is imported (the override also skips the helper's cargo build).
process.env.IOI_HYPERVISOR_DAEMON_BINARY = join(HERE, "isolated-daemon-log.test-fixture.mjs");
const { isIsolatedDaemonLogName, startIsolatedPlane } = await import("./isolated-daemon.mjs");

const linuxProcAvailable = () =>
  process.platform === "linux" && existsSync("/proc/net/tcp") && existsSync(`/proc/${process.pid}/fd`);

function planeLog(plane) {
  const logs = readdirSync(plane.dataDir).filter(isIsolatedDaemonLogName);
  assert.deepEqual(logs, ["isolated-daemon.log"], "a fresh plane keeps one log, isolated-daemon.log");
  return join(plane.dataDir, logs[0]);
}

// The stand-in daemon writes about `bytes` bytes of lines to its stdout (the plane's log) before it answers.
async function daemonWrites(plane, bytes, tag) {
  const answer = await fetch(`${plane.daemonUrl}/__stand_in/write?bytes=${bytes}&tag=${tag}`).then((r) => r.json());
  assert.ok(answer.written >= bytes, `the stand-in daemon wrote its ${bytes} bytes`);
  return answer.last;
}

const DAEMON_STARTED = /^\[stand-in-daemon\] started pid=\d+$/mu;

test("HARNESS: the plane's log keeps a line from EACH writer: the serve's own line survives the daemon's later writes", async (t) => {
  if (!linuxProcAvailable()) {
    t.skip("the isolated plane needs the Linux /proc listener-ownership boundary");
    return;
  }
  const plane = await startIsolatedPlane({ serve: true });
  assert.ok(plane, "the plane started with the stand-in daemon");
  try {
    const log = planeLog(plane);
    const servePort = new URL(plane.serveUrl).port;
    const serveLine = new RegExp(`^\\[hypervisor\\] product-ui bundle \\+ IOI /api adapter on http://127\\.0\\.0\\.1:${servePort}$`, "mu");
    assert.match(readFileSync(log, "utf8"), serveLine, "precondition: the serve wrote its startup line to the plane's log");
    // The daemon then writes 64 KiB, more than the serve wrote, at whatever offset its descriptor holds.
    const last = await daemonWrites(plane, 64 * 1024, "late");
    const text = readFileSync(log, "utf8");
    // assert.ok, not assert.match: a failure names the line lost without printing the 64 KiB log.
    assert.ok(DAEMON_STARTED.test(text), "the daemon's first line survives");
    assert.ok(serveLine.test(text), "the serve's startup line survives the daemon's later writes");
    assert.ok(text.includes(`${last}\n`), "and the daemon's later lines are all there");
  } finally {
    await plane.stop();
  }
});

test("HARNESS: a line appended to the plane's log by any other writer survives the daemon's later writes", async (t) => {
  if (!linuxProcAvailable()) {
    t.skip("the isolated plane needs the Linux /proc listener-ownership boundary");
    return;
  }
  const plane = await startIsolatedPlane({ serve: false });
  assert.ok(plane, "the plane started with the stand-in daemon");
  try {
    const log = planeLog(plane);
    // Another writer, opened the way the plane opens the serve's descriptor: append.
    const other = `[another-writer] line ${process.pid}`;
    const fd = openSync(log, "a");
    try {
      writeSync(fd, `${other}\n`);
    } finally {
      closeSync(fd);
    }
    const last = await daemonWrites(plane, 4 * 1024, "after");
    const text = readFileSync(log, "utf8");
    assert.ok(DAEMON_STARTED.test(text), "the daemon's first line survives");
    assert.ok(text.includes(`${other}\n`), "the other writer's line survives the daemon's later writes");
    assert.ok(text.includes(`${last}\n`), "and the daemon's later lines are all there");
    assert.ok(text.indexOf(`${other}\n`) < text.indexOf(`${last}\n`), "in the order they were written");
  } finally {
    await plane.stop();
  }
});
