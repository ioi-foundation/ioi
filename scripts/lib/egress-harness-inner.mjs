#!/usr/bin/env node
// egress-harness-inner — the half of scripts/lib/egress-harness.mjs that runs INSIDE the
// namespace. It brings the declared loopback bridges up on the fixture's ports, forwarding each
// connection to the unix socket the outer exporter owns (path-based unix sockets cross the
// network namespace), watches each bridge's fault trigger, and then runs the work under a
// seccomp-filtered strace whose ledger the outer half reads. It records, it forwards, it severs
// on request; it decides nothing.
//
//   node scripts/lib/egress-harness-inner.mjs <config.json>

import { spawn } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";

const configPath = process.argv[2];
if (!configPath) { console.error("usage: egress-harness-inner.mjs <config.json>"); process.exit(2); }
const config = JSON.parse(fs.readFileSync(configPath, "utf8"));
const controlDir = path.dirname(configPath);
const summary = { label: config.label, started_at: new Date().toISOString(), bridges: {}, child: null };
const writeJson = (file, value) => { try { fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`); } catch { /* best effort */ } };

const bridges = [];
function startBridge({ name, listenPort, socketPath, statsPath, faultTriggerPath }) {
  const state = { name, listen: `127.0.0.1:${listenPort}`, socket_path: socketPath, connections: 0, active: 0, bytes_to_dependency: 0, bytes_from_dependency: 0, severed: false, severed_at: null, severed_active: 0, refused_after_sever: 0, upstream_failures: 0 };
  const actives = new Set();
  const persist = () => writeJson(statsPath, state);
  const server = net.createServer((client) => {
    if (state.severed) { state.refused_after_sever += 1; client.destroy(); persist(); return; }
    state.connections += 1; state.active += 1;
    const up = net.connect(socketPath);
    const pair = { client, up };
    actives.add(pair);
    const done = () => { if (actives.delete(pair)) { state.active -= 1; persist(); } client.destroy(); up.destroy(); };
    up.on("error", () => { state.upstream_failures += 1; done(); });
    client.on("error", done);
    up.on("close", done);
    client.on("close", done);
    // Persist on DATA as well as on open/close: a watcher deciding "is the model stream open and
    // has the request gone out?" reads this file while the connection is still active, and a
    // counter that only lands at close would answer a question about the past.
    client.on("data", (d) => { state.bytes_to_dependency += d.length; persist(); });
    up.on("data", (d) => { state.bytes_from_dependency += d.length; persist(); });
    client.pipe(up);
    up.pipe(client);
    persist();
  });
  const sever = (why) => {
    if (state.severed) return;
    state.severed = true; state.severed_at = new Date().toISOString(); state.severed_active = actives.size; state.severed_by = why;
    // The listener closes so every later connect is refused by the kernel (ECONNREFUSED — exactly
    // a dead dependency), and every in-flight stream is destroyed mid-body on both sides.
    try { server.close(); } catch { /* closing */ }
    for (const { client, up } of [...actives]) { try { client.destroy(new Error("severed")); } catch { /* gone */ } try { up.destroy(); } catch { /* gone */ } }
    persist();
  };
  let watcher = null;
  if (faultTriggerPath) {
    watcher = setInterval(() => { if (fs.existsSync(faultTriggerPath)) sever(`trigger file ${path.basename(faultTriggerPath)}`); }, 250);
    watcher.unref();
  }
  const stop = () => { if (watcher) clearInterval(watcher); try { server.close(); } catch { /* closed */ } for (const { client, up } of [...actives]) { client.destroy(); up.destroy(); } persist(); };
  return new Promise((resolve, reject) => {
    server.on("error", reject);
    server.listen(listenPort, "127.0.0.1", () => { persist(); resolve({ name, state, stop, sever }); });
  });
}

async function main() {
  for (const b of config.bridges ?? []) {
    try {
      const bridge = await startBridge(b);
      bridges.push(bridge);
      summary.bridges[b.name] = { listen: bridge.state.listen, ok: true };
    } catch (error) {
      summary.bridges[b.name] = { ok: false, error: String(error?.message || error) };
      writeJson(path.join(controlDir, "summary.json"), { ...summary, failed: `bridge ${b.name} did not listen` });
      console.error(`egress-harness-inner: bridge ${b.name} did not listen on 127.0.0.1:${b.listenPort}: ${error?.message || error}`);
      process.exit(3);
    }
  }
  writeJson(config.readyPath, { ready_at: new Date().toISOString(), bridges: Object.keys(summary.bridges) });
  const { argv, cwd, env } = config.command;
  const straceArgv = [...config.straceArgs, "-o", config.ledgerPath, "--", ...argv];
  summary.child = { argv, strace: straceArgv.slice(0, config.straceArgs.length), started_at: new Date().toISOString() };
  const child = spawn("strace", straceArgv, { cwd, env: { ...env, IOI_EGRESS_HARNESS_LEDGER: config.ledgerPath }, stdio: "inherit" });
  const exit = await new Promise((resolve) => { child.on("exit", (code, signal) => resolve({ code, signal })); child.on("error", (e) => resolve({ code: null, signal: `spawn-error:${e.message}` })); });
  summary.child.exit = exit;
  summary.child.finished_at = new Date().toISOString();
  for (const b of bridges) b.stop();
  summary.finished_at = new Date().toISOString();
  writeJson(path.join(controlDir, "summary.json"), summary);
  process.exit(exit.code === null ? 1 : exit.code);
}

for (const signal of ["SIGTERM", "SIGINT", "SIGHUP"]) {
  process.on(signal, () => { for (const b of bridges) b.stop(); writeJson(path.join(controlDir, "summary.json"), { ...summary, interrupted: signal }); process.exit(1); });
}
main().catch((error) => { console.error(`egress-harness-inner: ${error?.stack || error}`); process.exit(1); });
