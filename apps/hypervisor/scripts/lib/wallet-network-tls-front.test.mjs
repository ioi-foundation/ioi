// The deployment authority's TLS front persists (CA, certificate, port) so a restarted node keeps the daemon's pin; a test fixture mints per life.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import net from "node:net";
import { startPinnedTlsProxy } from "./wallet-network-principal-authority-fixture.mjs";
test("a persisted TLS front comes back with the same CA and port; a fixture front does not persist", async () => {
  const upstream = net.createServer((s) => s.end()); await new Promise((r) => upstream.listen(0, "127.0.0.1", r));
  const up = `127.0.0.1:${upstream.address().port}`;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tls-persist-"));
  const a = await startPinnedTlsProxy(up, dir, "wallet-network.local", { persist: true, days: 3650 });
  const ca1 = fs.readFileSync(a.caPath, "utf8"); const port1 = a.rpcAddr; await a.stop();
  assert.equal((fs.statSync(path.join(dir, "wallet-network-server.key")).mode & 0o777), 0o600);
  const b = await startPinnedTlsProxy(up, dir, "wallet-network.local", { persist: true, days: 3650 });
  assert.equal(fs.readFileSync(b.caPath, "utf8"), ca1, "the same CA, so the daemon's pin still holds");
  assert.equal(b.rpcAddr, port1, "the same port");
  await b.stop();
  const fdir = fs.mkdtempSync(path.join(os.tmpdir(), "tls-fixture-"));
  const f1 = await startPinnedTlsProxy(up, fdir); const c1 = fs.readFileSync(f1.caPath, "utf8"); await f1.stop();
  const f2 = await startPinnedTlsProxy(up, fdir); assert.notEqual(fs.readFileSync(f2.caPath, "utf8"), c1, "a fixture mints per life"); await f2.stop();
  upstream.close();
});
