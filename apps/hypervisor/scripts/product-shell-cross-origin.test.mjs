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

test("a cross-site GET changes nothing: each state-changing shell route acts only on a same-origin POST", async () => {
  const calls = [];
  // A local-development daemon (the posture in which the shell serves its internal surfaces) that
  // records every call and answers each with an empty JSON object.
  const daemon = http.createServer((req, res) => {
    calls.push(`${req.method} ${req.url}`);
    req.resume();
    req.on("end", () => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(req.url.startsWith("/v1/hypervisor/auth/policy") ? JSON.stringify({ ok: true, deployment_auth_posture: "local_development" }) : "{}");
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
  const owner = "ioi_session=ioi_sess_owner_stub";
  const writes = () => calls.filter((call) => !call.startsWith("GET "));
  // A top-level navigation from another site: the browser sends the owner's SameSite=Lax cookie, no
  // Origin, and Sec-Fetch-Site: cross-site. Every state change it would cause is collected and named.
  const navigate = (target, extra = {}) =>
    fetch(`${shell}${target}`, {
      redirect: "manual",
      headers: { cookie: owner, "sec-fetch-site": "cross-site", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document", ...extra },
    });
  const ownPost = (target, extra = {}) =>
    fetch(`${shell}${target}`, {
      method: "POST",
      redirect: "manual",
      headers: { cookie: owner, origin: shell, "sec-fetch-site": "same-origin", "content-type": "application/x-www-form-urlencoded", ...extra },
      body: "",
    });
  try {
    await waitFor(`${shell}/__ioi/product-ui-identity`, child);
    const changed = [];
    for (const target of [
      "/api/ioi.v1.EnvironmentService/CreateEnvironment",
      "/api/ioi/exec",
      "/__ioi/editor/open?environmentId=env-1",
      "/__ioi/logout",
      "/__ioi/login/sso/sso-1",
      "/__ioi/github-app/start",
      "/__ioi/github-app/callback?code=attacker-code",
      "/__ioi/github-app/installed?installation_id=42",
      "/__ioi/integrations/connect/conn-1",
    ]) {
      calls.length = 0;
      const response = await navigate(target);
      await response.text();
      const cleared = /ioi_session=;/u.test(response.headers.get("set-cookie") || "");
      if (writes().length || cleared) changed.push(`${target} (${response.status}): ${writes().join(", ")}${cleared ? " and the session cookie cleared" : ""}`);
    }
    const reset = await navigate("/__ioi/fallthrough/reset");
    const resetBody = await reset.text();
    if (/"ok":\s*true/u.test(resetBody)) changed.push(`/__ioi/fallthrough/reset (${reset.status}): the tracker was reset`);
    assert.deepEqual(changed, [], `a cross-site GET reaches no daemon write and resets nothing:\n${changed.join("\n")}`);

    // The shell's own pages: a same-origin navigation is answered with a form that POSTs (the GET
    // itself changes nothing), and the same-origin POST acts.
    calls.length = 0;
    const page = await navigate("/__ioi/editor/open?environmentId=env-1", { "sec-fetch-site": "same-origin" });
    const html = await page.text();
    assert.match(html, /<form[^>]*method="post"/iu, `a same-origin GET is answered with a form that POSTs (${page.status})`);
    assert.deepEqual(writes(), [], "the same-origin GET itself changes nothing");
    calls.length = 0;
    await (await ownPost("/__ioi/editor/open?environmentId=env-1")).text();
    assert.ok(calls.some((call) => call.startsWith("POST /v1/hypervisor/editor-services")), `the same-origin POST opens the editor (${calls.join(", ")})`);
    calls.length = 0;
    const out = await ownPost("/__ioi/logout");
    await out.text();
    assert.ok(calls.includes("POST /v1/hypervisor/auth/logout"), `the same-origin POST signs out (${calls.join(", ")})`);
    assert.match(out.headers.get("set-cookie") || "", /^ioi_session=;/u, "and clears the session cookie");
    calls.length = 0;
    const rpc = await fetch(`${shell}/api/ioi.v1.EnvironmentService/CreateEnvironment`, {
      method: "POST",
      headers: { cookie: owner, origin: shell, "sec-fetch-site": "same-origin", "content-type": "application/json" },
      body: JSON.stringify({ spec: {} }),
    });
    await rpc.text();
    assert.ok(writes().length > 0, `an RPC POST from the shell still reaches the daemon (${calls.join(", ")})`);

    // The GitHub App callbacks act only with the state the shell's own start set.
    const start = await ownPost("/__ioi/github-app/start");
    await start.text();
    const state = /ioi_github_app_state=([^;]+)/u.exec(start.headers.get("set-cookie") || "")?.[1];
    assert.ok(state, `the start sets the flow's state cookie (${start.headers.get("set-cookie")})`);
    calls.length = 0;
    const wrong = await navigate(`/__ioi/github-app/callback?code=c&state=${state}x`, { cookie: `${owner}; ioi_github_app_state=${state}` });
    await wrong.text();
    assert.deepEqual(writes(), [], "a callback with another state reaches no daemon write");
    calls.length = 0;
    const back = await navigate(`/__ioi/github-app/callback?code=c&state=${state}`, { cookie: `${owner}; ioi_github_app_state=${state}` });
    await back.text();
    assert.ok(calls.includes("POST /v1/hypervisor/scm-connect/github-app/conversion"), `the callback with the start's state converts (${calls.join(", ")})`);
  } catch (error) {
    throw new Error(`${error.message}\nproduct shell output:\n${output.slice(-8_000)}`);
  } finally {
    await stop(child);
    daemon.close();
  }
});
