// The product shell refuses a state-changing request from another origin. Cross-port 127.0.0.1 is
// the same SITE, so the session cookie alone does not tell the owner's own page from content served
// on another loopback port (a preview or an editor); the browser's Origin / Sec-Fetch-Site do. A
// refused request reaches no daemon route. Requests without browser origin headers, and requests
// from the shell's own origin, are not refused by this check.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import http from "node:http";
import net from "node:net";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "../../..");

function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close((error) => (error ? reject(error) : resolve(port)));
    });
  });
}

async function waitFor(url, child) {
  const deadline = Date.now() + 20_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`product shell exited early with ${child.exitCode}`);
    try {
      const response = await fetch(url);
      if (response.ok) return response;
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`product shell did not become ready: ${url}`);
}

async function stop(child) {
  if (child.exitCode !== null) return;
  child.kill("SIGTERM");
  await Promise.race([
    new Promise((resolve) => child.once("exit", resolve)),
    new Promise((resolve) => setTimeout(() => { if (child.exitCode === null) child.kill("SIGKILL"); resolve(); }, 2_000)),
  ]);
}

test("a cross-origin state change to the product shell is refused and reaches no daemon route", async () => {
  // A fake daemon that records every call and answers each with an empty JSON object.
  const calls = [];
  const daemon = http.createServer((req, res) => {
    calls.push(`${req.method} ${req.url}`);
    req.resume();
    req.on("end", () => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end("{}");
    });
  });
  await new Promise((resolve) => daemon.listen(0, "127.0.0.1", resolve));
  const [port, productPort] = await Promise.all([freePort(), freePort()]);
  const child = spawn(process.execPath, [path.join(here, "serve-product-ui.mjs")], {
    cwd: root,
    env: {
      ...process.env,
      PORT: String(port),
      PRODUCT_UI_PORT: String(productPort),
      IOI_HYPERVISOR_DAEMON_URL: `http://127.0.0.1:${daemon.address().port}`,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  child.stdout.on("data", (chunk) => { output += chunk; });
  child.stderr.on("data", (chunk) => { output += chunk; });
  const shell = `http://127.0.0.1:${port}`;
  const post = (headers) =>
    fetch(`${shell}/api/ioi.v1.EnvironmentService/CreateEnvironment`, {
      method: "POST",
      redirect: "manual",
      headers: { "content-type": "application/json", cookie: "ioi_session=ioi_sess_owner_stub", ...headers },
      body: JSON.stringify({ spec: {} }),
    });
  try {
    await waitFor(`${shell}/__ioi/product-ui-identity`, child);
    for (const [label, headers] of [
      ["a preview site", { origin: "http://p0123456789abcdef.localhost:41000", "sec-fetch-site": "cross-site" }],
      ["another loopback port", { origin: "http://127.0.0.1:41001", "sec-fetch-site": "same-site" }],
      ["another loopback port (Origin only)", { origin: "http://127.0.0.1:41002" }],
    ]) {
      calls.length = 0;
      const response = await post(headers);
      const body = await response.text();
      assert.equal(response.status, 403, `${label}: refused (${body})`);
      assert.match(body, /cross_origin_request_refused/u, `${label}: refused by name`);
      assert.deepEqual(calls.filter((call) => !call.startsWith("GET ")), [], `${label}: no daemon write was attempted`);
    }
    for (const [label, headers] of [
      ["the shell's own origin", { origin: shell, "sec-fetch-site": "same-origin" }],
      ["a client with no browser origin headers", {}],
    ]) {
      calls.length = 0;
      const response = await post(headers);
      const body = await response.text();
      assert.doesNotMatch(body, /cross_origin_request_refused/u, `${label}: not refused by the origin check (${response.status})`);
      assert.ok(calls.some((call) => !call.startsWith("GET ")), `${label}: the write reached the daemon (${calls.join(", ")})`);
    }
  } catch (error) {
    throw new Error(`${error.message}\nproduct shell output:\n${output.slice(-8_000)}`);
  } finally {
    await stop(child);
    daemon.close();
  }
});

test("the session cookie is host-only on the shell's host, and a cross-origin sign-in is refused", async () => {
  const calls = [];
  const daemon = http.createServer((req, res) => {
    calls.push(`${req.method} ${req.url}`);
    req.resume();
    req.on("end", () => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(req.url === "/v1/hypervisor/auth/login" ? JSON.stringify({ ok: true, session_token: "ioi_sess_host_only" }) : "{}");
    });
  });
  await new Promise((resolve) => daemon.listen(0, "127.0.0.1", resolve));
  const [port, productPort] = await Promise.all([freePort(), freePort()]);
  const child = spawn(process.execPath, [path.join(here, "serve-product-ui.mjs")], {
    cwd: root,
    env: {
      ...process.env,
      PORT: String(port),
      PRODUCT_UI_PORT: String(productPort),
      IOI_HYPERVISOR_DAEMON_URL: `http://127.0.0.1:${daemon.address().port}`,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  child.stdout.on("data", (chunk) => { output += chunk; });
  child.stderr.on("data", (chunk) => { output += chunk; });
  const shell = `http://127.0.0.1:${port}`;
  const login = (headers) =>
    fetch(`${shell}/__ioi/login`, {
      method: "POST",
      redirect: "manual",
      headers: { "content-type": "application/x-www-form-urlencoded", ...headers },
      body: "email=owner%40example.test&password=pw",
    });
  try {
    await waitFor(`${shell}/__ioi/product-ui-identity`, child);
    const own = await login({ origin: shell, "sec-fetch-site": "same-origin" });
    await own.text();
    const setCookie = own.headers.get("set-cookie") || "";
    assert.equal(own.status, 302, `a same-origin sign-in is answered with the session cookie (${setCookie})`);
    assert.match(setCookie, /^ioi_session=ioi_sess_host_only;/u, "the session cookie is set");
    // Host-only (no Domain attribute): a browser sends it only to this exact host, never to a
    // preview or editor served on its own *.localhost name.
    assert.doesNotMatch(setCookie, /;\s*domain=/iu, `the session cookie is host-only: ${setCookie}`);
    assert.match(setCookie, /HttpOnly/u, "the session cookie is HttpOnly");
    calls.length = 0;
    const cross = await login({ origin: "http://p0123456789abcdef.localhost:41000", "sec-fetch-site": "cross-site" });
    const body = await cross.text();
    assert.equal(cross.status, 403, `a cross-origin sign-in is refused (${body})`);
    assert.equal(cross.headers.get("set-cookie"), null, "a refused sign-in sets no cookie");
    assert.deepEqual(calls.filter((call) => !call.startsWith("GET ")), [], "a refused sign-in reaches no daemon route");
  } catch (error) {
    throw new Error(`${error.message}\nproduct shell output:\n${output.slice(-8_000)}`);
  } finally {
    await stop(child);
    daemon.close();
  }
});
