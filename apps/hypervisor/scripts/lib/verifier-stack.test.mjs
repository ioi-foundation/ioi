// verifier-stack — the owner's stack is refused, a 401 reads as a 401, and the caller rides only
// the stack's own origins (R-240, verifier auth sweep, 2026-09-29).
// Run: node --test apps/hypervisor/scripts/lib/verifier-stack.test.mjs
import assert from "node:assert/strict";
import { createServer } from "node:http";
import test from "node:test";
import {
  ANONYMOUS,
  OWNER_STACK_PORTS,
  describeHttp,
  installCallerFetch,
  ownerStackRefusal,
} from "./verifier-stack.mjs";

test("the owner's daemon and both of the owner's serves are refused by port", () => {
  assert.deepEqual([...OWNER_STACK_PORTS].sort((a, b) => a - b), [4173, 8765, 36173]);
  for (const url of ["http://127.0.0.1:8765", "http://127.0.0.1:8765/", "http://localhost:36173/ai", "http://127.0.0.1:4173", "http://[::1]:8765"]) {
    assert.match(ownerStackRefusal(url) ?? "", /owner's stack/u, url);
  }
});

test("a stack the verifier owns (any other port) is not refused, and no URL is not a refusal", () => {
  for (const url of ["http://127.0.0.1:41234", "http://127.0.0.1:18765", "http://127.0.0.1:4174/"]) {
    assert.equal(ownerStackRefusal(url), null, url);
  }
  assert.equal(ownerStackRefusal(undefined), null);
  assert.equal(ownerStackRefusal(""), null);
  assert.match(ownerStackRefusal("not a url") ?? "", /not a URL/u);
});

test("a refused caller reads as its status and typed code, never as an unreachable daemon", () => {
  assert.equal(describeHttp(401, { error: { code: "request_principal_required" } }), "HTTP 401 request_principal_required");
  assert.equal(describeHttp(401, { code: "request_principal_required" }), "HTTP 401 request_principal_required");
  assert.equal(describeHttp(404, null), "HTTP 404");
  assert.equal(describeHttp(0, null), "no answer (connection refused or timed out)");
});

test("the session rides every request to the stack's own origins, and only those, unless one names its own identity or opts out", async () => {
  const seen = [];
  const server = createServer((req, res) => {
    seen.push({ path: req.url, cookie: req.headers.cookie ?? null, authorization: req.headers.authorization ?? null, anon: req.headers[ANONYMOUS] ?? null });
    res.end("{}");
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const other = createServer((req, res) => {
    seen.push({ path: `other${req.url}`, cookie: req.headers.cookie ?? null });
    res.end("{}");
  });
  await new Promise((r) => other.listen(0, "127.0.0.1", r));
  const own = `http://127.0.0.1:${server.address().port}`;
  const foreign = `http://127.0.0.1:${other.address().port}`;
  const restore = installCallerFetch({ origins: [own, null], cookie: "ioi_session=tok" });
  try {
    await fetch(`${own}/v1/hypervisor/odk/domain-ontologies`);
    await fetch(`${own}/v1/x`, { headers: { authorization: "Bearer capability" } });
    await fetch(`${own}/v1/y`, { headers: { cookie: "ioi_session=member" } });
    await fetch(`${own}/v1/z`, { headers: { [ANONYMOUS]: "1" } });
    await fetch(`${foreign}/leak`);
  } finally {
    restore();
    server.close();
    other.close();
  }
  assert.deepEqual(seen, [
    { path: "/v1/hypervisor/odk/domain-ontologies", cookie: "ioi_session=tok", authorization: null, anon: null },
    { path: "/v1/x", cookie: null, authorization: "Bearer capability", anon: null },
    { path: "/v1/y", cookie: "ioi_session=member", authorization: null, anon: null },
    { path: "/v1/z", cookie: null, authorization: null, anon: null },
    { path: "other/leak", cookie: null },
  ]);
});

test("an explicit owner URL makes verifierStack exit 2 before anything is sent", async () => {
  const { spawnSync } = await import("node:child_process");
  const { fileURLToPath } = await import("node:url");
  const helper = fileURLToPath(new URL("./verifier-stack.mjs", import.meta.url));
  for (const [key, url] of [["IOI_HYPERVISOR_DAEMON_URL", "http://127.0.0.1:8765"], ["IOI_HYPERVISOR_SERVE_URL", "http://127.0.0.1:36173"], ["IOI_HYPERVISOR_SERVE_URL", "http://127.0.0.1:4173"]]) {
    const run = spawnSync(process.execPath, ["--input-type=module", "-e", `import { verifierStack } from ${JSON.stringify(helper)}; await verifierStack({ serve: true }); console.log("REACHED");`], {
      env: { ...process.env, IOI_HYPERVISOR_DAEMON_URL: "", IOI_HYPERVISOR_SERVE_URL: "", [key]: url },
      encoding: "utf8",
      timeout: 30_000,
    });
    assert.equal(run.status, 2, `${key}=${url}: ${run.stderr}`);
    assert.match(run.stderr, /BLOCKED: .*owner's stack/u);
    assert.doesNotMatch(run.stdout, /REACHED/u);
  }
});

test("a census gate's own serve is never handed the owner's daemon: gateDaemon throws on :8765/:36173/:4173", async () => {
  const { gateDaemon } = await import("./verifier-stack.mjs");
  const saved = process.env.IOI_HYPERVISOR_DAEMON_URL;
  try {
    for (const url of ["http://127.0.0.1:8765", "http://127.0.0.1:36173/", "http://localhost:4173"]) {
      process.env.IOI_HYPERVISOR_DAEMON_URL = url;
      await assert.rejects(gateDaemon(), /refused: .*owner's stack/u, url);
    }
  } finally {
    if (saved === undefined) delete process.env.IOI_HYPERVISOR_DAEMON_URL;
    else process.env.IOI_HYPERVISOR_DAEMON_URL = saved;
  }
});

test("every refusal the stack answers is observed with its status and typed code (and a success is not)", async () => {
  const server = createServer((req, res) => {
    if (req.url === "/ok") { res.end("{}"); return; }
    res.writeHead(501, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: { code: "authority_principal_not_configured" } }));
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const own = `http://127.0.0.1:${server.address().port}`;
  const seen = [];
  const restore = installCallerFetch({ origins: [own], cookie: "ioi_session=tok", onRefusal: (r) => seen.push(r) });
  try {
    await fetch(`${own}/ok`);
    await fetch(`${own}/v1/hypervisor/odk/materializing-runs/mrun_1/acquire-lease`, { method: "POST", body: "{}" });
    await new Promise((r) => setTimeout(r, 50));
  } finally {
    restore();
    server.close();
  }
  assert.deepEqual(seen, [{ method: "POST", path: "/v1/hypervisor/odk/materializing-runs/mrun_1/acquire-lease", status: 501, described: "HTTP 501 authority_principal_not_configured" }]);
});
