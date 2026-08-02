import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { createServer } from "node:net";
import { once } from "node:events";
import test from "node:test";

import { linuxListenerOwnershipEvidence } from "./isolated-daemon.mjs";

function linuxProcAvailable() {
  return process.platform === "linux" &&
    existsSync("/proc/net/tcp") &&
    existsSync(`/proc/${process.pid}/fd`);
}

async function closeServer(server) {
  if (!server.listening) return;
  server.close();
  await once(server, "close");
}

test("Linux listener proof binds the selected port to the exact owning PID", async (t) => {
  if (!linuxProcAvailable()) {
    t.skip("Linux /proc socket ownership boundary is unavailable");
    return;
  }
  const server = createServer();
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  try {
    const address = server.address();
    assert.equal(typeof address, "object");
    const evidence = linuxListenerOwnershipEvidence(process.pid, address.port);
    assert.equal(evidence.proof_kind, "ioi.verifier.linux-listener-ownership.v1");
    assert.equal(evidence.pid, process.pid);
    assert.equal(evidence.port, address.port);
    assert.equal(evidence.owned, true);
    assert.ok(evidence.listener_inodes.length > 0);
    assert.deepEqual(evidence.foreign_listener_inodes, []);
  } finally {
    await closeServer(server);
  }
});

test("Linux listener proof refuses a live non-owner PID", async (t) => {
  if (!linuxProcAvailable()) {
    t.skip("Linux /proc socket ownership boundary is unavailable");
    return;
  }
  const server = createServer();
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const nonOwner = spawn(
    process.execPath,
    ["-e", "setInterval(() => {}, 1000)"],
    { stdio: "ignore" },
  );
  await once(nonOwner, "spawn");
  try {
    const address = server.address();
    assert.equal(typeof address, "object");
    const evidence = linuxListenerOwnershipEvidence(nonOwner.pid, address.port);
    assert.equal(evidence.pid, nonOwner.pid);
    assert.equal(evidence.port, address.port);
    assert.equal(evidence.owned, false);
    assert.ok(evidence.listener_inodes.length > 0);
    assert.deepEqual(
      evidence.foreign_listener_inodes,
      evidence.listener_inodes,
    );
  } finally {
    const nonOwnerExit = once(nonOwner, "exit");
    nonOwner.kill("SIGTERM");
    await nonOwnerExit;
    await closeServer(server);
  }
});
