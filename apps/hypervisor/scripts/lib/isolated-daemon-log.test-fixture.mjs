#!/usr/bin/env node
// A STAND-IN daemon for isolated-daemon-log.test.mjs (test fixture; never a daemon): it binds the
// address the isolated plane gives it (IOI_HYPERVISOR_DAEMON_ADDR), answers /healthz, and writes log
// lines to its stdout (the plane's log) on demand, so the test can make the "daemon" write AFTER
// another writer and read what the plane's log kept. It holds no state, reads no file and writes
// nothing but its own stdout.
//
//   GET /healthz                               200 "ok"
//   GET /__stand_in/write?bytes=N&tag=T        writes about N bytes of "[stand-in-daemon] T <i> ..." lines
//                                              (synchronously, before answering), then 200 {"last": <the last line>}
//   GET /v1/hypervisor/auth/policy             the local-development posture, in which the product shell serves
//                                              its internal surfaces (as product-shell-cross-origin.test.mjs's
//                                              stand-in answers it)
//   any other request                          200 {} (so a serve probing through it is answered)
import http from "node:http";
import { writeSync } from "node:fs";

const addr = process.env.IOI_HYPERVISOR_DAEMON_ADDR || "";
const separator = addr.lastIndexOf(":");
const host = addr.slice(0, separator);
const port = Number(addr.slice(separator + 1));
if (!host || !Number.isInteger(port) || port <= 0) {
  writeSync(2, `[stand-in-daemon] IOI_HYPERVISOR_DAEMON_ADDR is not host:port (${JSON.stringify(addr)})\n`);
  process.exit(2);
}

writeSync(1, `[stand-in-daemon] started pid=${process.pid}\n`);

const server = http.createServer((req, res) => {
  const url = new URL(req.url, "http://stand-in");
  if (url.pathname === "/healthz") {
    res.writeHead(200, { "content-type": "text/plain" });
    return res.end("ok");
  }
  if (url.pathname === "/__stand_in/write") {
    const bytes = Math.min(Math.max(Number(url.searchParams.get("bytes")) || 0, 1), 4 * 1024 * 1024);
    const tag = (url.searchParams.get("tag") || "line").replace(/[^a-z0-9-]/giu, "").slice(0, 32) || "line";
    let written = 0;
    let last = "";
    for (let i = 0; written < bytes; i += 1) {
      last = `[stand-in-daemon] ${tag} ${i} ${"x".repeat(64)}`;
      written += writeSync(1, `${last}\n`);
    }
    res.writeHead(200, { "content-type": "application/json" });
    return res.end(JSON.stringify({ last, written }));
  }
  if (url.pathname === "/v1/hypervisor/auth/policy") {
    res.writeHead(200, { "content-type": "application/json" });
    return res.end(JSON.stringify({ ok: true, deployment_auth_posture: "local_development" }));
  }
  res.writeHead(200, { "content-type": "application/json" });
  return res.end("{}");
});
server.listen(port, host);
