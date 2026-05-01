#!/usr/bin/env node
import path from "node:path";
import { fileURLToPath } from "node:url";

import { startRuntimeDaemonService } from "../packages/runtime-daemon/src/index.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const args = new Map();
for (let index = 2; index < process.argv.length; index += 2) {
  args.set(process.argv[index], process.argv[index + 1]);
}

const daemon = await startRuntimeDaemonService({
  cwd: args.get("--cwd") ?? root,
  stateDir:
    args.get("--state-dir") ??
    path.join(root, "docs/evidence/architectural-improvements-broad/live-agentgres"),
  port: args.has("--port") ? Number(args.get("--port")) : 0,
});

const ready = {
  schemaVersion: "ioi.runtime-daemon.ready.v1",
  endpoint: daemon.endpoint,
  stateDir: daemon.stateDir,
  pid: process.pid,
};

console.log(JSON.stringify(ready));

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, async () => {
    await daemon.close();
    process.exit(0);
  });
}
