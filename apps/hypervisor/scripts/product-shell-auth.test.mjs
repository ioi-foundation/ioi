import assert from "node:assert/strict";
import { spawn } from "node:child_process";
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
      const address = server.address();
      server.close((error) =>
        error ? reject(error) : resolve(address.port),
      );
    });
  });
}

async function waitFor(url, child) {
  const deadline = Date.now() + 20_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      throw new Error(`product shell exited early with ${child.exitCode}`);
    }
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
    new Promise((resolve) =>
      setTimeout(() => {
        if (child.exitCode === null) child.kill("SIGKILL");
        resolve();
      }, 2_000),
    ),
  ]);
}

test("the product shell serves the owned artifact and fails closed when identity authority is unavailable", async () => {
  const [port, productPort] = await Promise.all([freePort(), freePort()]);
  const child = spawn(
    process.execPath,
    [path.join(here, "serve-product-ui.mjs")],
    {
      cwd: root,
      env: {
        ...process.env,
        PORT: String(port),
        PRODUCT_UI_PORT: String(productPort),
        IOI_HYPERVISOR_DAEMON_URL: "http://127.0.0.1:1",
      },
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  let output = "";
  child.stdout.on("data", (chunk) => {
    output += chunk;
  });
  child.stderr.on("data", (chunk) => {
    output += chunk;
  });
  try {
    const identityResponse = await waitFor(
      `http://127.0.0.1:${port}/__ioi/product-ui-identity`,
      child,
    );
    const identity = await identityResponse.json();
    assert.equal(identity.tree, "owned");
    assert.equal(identity.public_dir, "owned/public");
    assert.match(identity.index_sha256, /^[a-f0-9]{64}$/u);

    const protectedResponse = await fetch(`http://127.0.0.1:${port}/home`, {
      headers: { accept: "text/html" },
    });
    const body = await protectedResponse.text();
    assert.equal(protectedResponse.status, 503);
    assert.equal(protectedResponse.headers.get("cache-control"), "no-store");
    assert.match(body, /identity_authority_unavailable/u);
  } catch (error) {
    throw new Error(`${error.message}\nproduct shell output:\n${output.slice(-8_000)}`);
  } finally {
    await stop(child);
  }
});

test("an SSO sign-in the daemon refuses shows the daemon's own message, which names the recovery", async () => {
  const http = await import("node:http");
  const message = "this SSO identity is not linked to an account <yet>; sign in another way (or ask an administrator to set a password), then link it";
  const daemon = http.createServer((req, res) => {
    req.resume();
    req.on("end", () => {
      res.writeHead(req.url === "/v1/hypervisor/auth/oidc/callback" ? 403 : 200, { "content-type": "application/json" });
      res.end(req.url === "/v1/hypervisor/auth/oidc/callback" ? JSON.stringify({ ok: false, code: "hypervisor.sso_link_required", message }) : "{}");
    });
  });
  await new Promise((resolve) => daemon.listen(0, "127.0.0.1", resolve));
  const [port, productPort] = await Promise.all([freePort(), freePort()]);
  const child = spawn(process.execPath, [path.join(here, "serve-product-ui.mjs")], {
    cwd: root,
    env: { ...process.env, PORT: String(port), PRODUCT_UI_PORT: String(productPort), IOI_HYPERVISOR_DAEMON_URL: `http://127.0.0.1:${daemon.address().port}` },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  child.stdout.on("data", (chunk) => { output += chunk; });
  child.stderr.on("data", (chunk) => { output += chunk; });
  try {
    await waitFor(`http://127.0.0.1:${port}/__ioi/product-ui-identity`, child);
    const response = await fetch(`http://127.0.0.1:${port}/__ioi/login/sso/callback?code=c&state=s`, { redirect: "manual" });
    const body = await response.text();
    assert.equal(response.status, 401, "the sign-in is refused");
    assert.equal(response.headers.get("set-cookie"), null, "no session cookie");
    assert.ok(body.includes("ask an administrator to set a password"), `the page shows the daemon's message: ${body.slice(-600)}`);
    assert.ok(body.includes("&lt;yet&gt;") && !body.includes("<yet>"), "escaped as text");
  } catch (error) {
    throw new Error(`${error.message}\nproduct shell output:\n${output.slice(-8_000)}`);
  } finally {
    await stop(child);
    daemon.close();
  }
});
