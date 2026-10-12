// BUILD-DELTA #24: the /__ioi/invite/<id> page's answers, against a stub daemon (no real daemon, no network
// beyond loopback). Each case pins one rule: the create-account form is offered only when no session is
// presented or the daemon SUCCESSFULLY says signed out; a failure of any kind reads as a neutral error.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import http from "node:http";
import net from "node:net";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "../../..");
const EMAIL = "member@example.test";
const COOKIE = "ioi_session=ioi_sess_test";
const INVITE = "/__ioi/invite/inv_test";

const freePort = () =>
  new Promise((resolve, reject) => {
    const s = net.createServer();
    s.once("error", reject);
    s.listen(0, "127.0.0.1", () => {
      const p = s.address().port;
      s.close(() => resolve(p));
    });
  });

const mode = { whoami: "member", accept: "null" };
function stubDaemon() {
  return http.createServer((q, s) => {
    const send = (status, text) => {
      s.writeHead(status, { "content-type": "application/json" });
      s.end(text);
    };
    q.resume();
    if (q.url.startsWith("/v1/hypervisor/auth/whoami")) {
      switch (mode.whoami) {
        case "fail": return send(500, "daemon error, not json");
        case "503-signed-out": return send(503, JSON.stringify({ ok: false, authenticated: false }));
        case "malformed": return send(200, "[1,2]");
        case "signed-out": return send(200, JSON.stringify({ ok: true, authenticated: false }));
        case "drop": return q.socket.destroy();
        default: return send(200, JSON.stringify({ ok: true, authenticated: true, principal: { principal_id: "p1", email: EMAIL } }));
      }
    }
    if (q.url.startsWith("/v1/hypervisor/organization")) return send(200, JSON.stringify({ ok: true, organization: { display_name: "Acme Test Org" } }));
    if (q.url.startsWith("/v1/hypervisor/org-invite/accept")) {
      switch (mode.accept) {
        case "drop": return q.socket.destroy();
        case "refuse": return send(403, JSON.stringify({ ok: false, code: "hypervisor.org_invite_principal_mismatch" }));
        case "truthy-strings": return send(200, JSON.stringify({ ok: "false", joined: "false" }));
        case "joined": return send(200, JSON.stringify({ ok: true, joined: true }));
        default: return send(200, "null");
      }
    }
    send(404, JSON.stringify({ ok: false }));
  });
}

async function withShell(fn) {
  const stub = stubDaemon();
  await new Promise((r) => stub.listen(0, "127.0.0.1", r));
  const [port, productPort] = await Promise.all([freePort(), freePort()]);
  const child = spawn(process.execPath, [path.join(here, "serve-product-ui.mjs")], {
    cwd: root,
    env: {
      ...process.env,
      PORT: String(port),
      PRODUCT_UI_PORT: String(productPort),
      IOI_HYPERVISOR_DAEMON_URL: `http://127.0.0.1:${stub.address().port}`,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  child.stdout.on("data", (c) => (output += c));
  child.stderr.on("data", (c) => (output += c));
  try {
    const deadline = Date.now() + 20_000;
    for (;;) {
      if (child.exitCode !== null) throw new Error(`shell exited ${child.exitCode}\n${output.slice(-4000)}`);
      try {
        if ((await fetch(`http://127.0.0.1:${port}/__ioi/product-ui-identity`)).ok) break;
      } catch {}
      if (Date.now() > deadline) throw new Error("shell not ready");
      await new Promise((r) => setTimeout(r, 100));
    }
    const base = `http://127.0.0.1:${port}`;
    const page = async (cookie) => {
      const r = await fetch(base + INVITE, { headers: cookie ? { cookie } : {}, redirect: "manual" });
      return { status: r.status, text: await r.text() };
    };
    const post = async (fields, cookie) => {
      const r = await fetch(base + INVITE, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded", ...(cookie ? { cookie } : {}) },
        body: new URLSearchParams(fields).toString(),
        redirect: "manual",
      });
      return { status: r.status, text: await r.text(), location: r.headers.get("location") };
    };
    await fn({ page, post });
  } finally {
    const exited = new Promise((r) => child.once("exit", r));
    child.kill("SIGKILL");
    await exited;
    child.stdout.destroy();
    child.stderr.destroy();
    stub.close();
    stub.closeAllConnections?.();
  }
}

const failed = (t) => t.includes("Couldn't complete joining") || t.includes("Couldn&#39;t complete joining");
const noCreate = (t) => !t.includes('name="password"') && !/Create (your )?account/.test(t);

test("the invite page's answers", { timeout: 120_000 }, async (t) => {
  await withShell(async ({ page, post }) => {
    await t.test("signed out: the new-account form", async () => {
      const r = await page();
      assert.equal(r.status, 200);
      assert.match(r.text, /name="password"/);
      assert.match(r.text, /Create account/);
    });
    await t.test("signed in: the join view, no password field", async () => {
      mode.whoami = "member";
      const r = await page(COOKIE);
      assert.equal(r.status, 200);
      assert.ok(r.text.includes(`Join Acme Test Org as ${EMAIL}`));
      assert.ok(noCreate(r.text));
    });
    await t.test("a session the daemon successfully reports as signed out: the new-account form", async () => {
      mode.whoami = "signed-out";
      const r = await page(COOKIE);
      assert.match(r.text, /name="password"/);
    });
    await t.test("whoami 503 saying authenticated:false is a failure, never the form", async () => {
      mode.whoami = "503-signed-out";
      const r = await page(COOKIE);
      assert.equal(r.status, 503);
      assert.ok(failed(r.text) && noCreate(r.text));
    });
    await t.test("whoami 500 / malformed body / dropped connection: the neutral error", async () => {
      for (const m of ["fail", "malformed", "drop"]) {
        mode.whoami = m;
        const r = await page(COOKIE);
        assert.equal(r.status, 503, m);
        assert.ok(failed(r.text) && noCreate(r.text), m);
      }
    });
    await t.test("a null JSON answer to the accept while signed in: a failed join, join view kept", async () => {
      mode.whoami = "member";
      mode.accept = "null";
      const r = await post({ email: EMAIL }, COOKIE);
      assert.equal(r.status, 403);
      assert.ok(failed(r.text) && noCreate(r.text));
      assert.ok(r.text.includes(`Join Acme Test Org as ${EMAIL}`));
    });
    await t.test("a transport failure on the accept while signed in: the neutral error", async () => {
      mode.accept = "drop";
      const r = await post({ email: EMAIL }, COOKIE);
      assert.equal(r.status, 502);
      assert.ok(failed(r.text) && noCreate(r.text));
    });
    await t.test("ok/joined as truthy strings do not join", async () => {
      mode.accept = "truthy-strings";
      const r = await post({ email: EMAIL }, COOKIE);
      assert.equal(r.status, 403);
      assert.equal(r.location, null);
      assert.ok(failed(r.text));
    });
    await t.test("ok:true joined:true joins: 302 /ai", async () => {
      mode.accept = "joined";
      const r = await post({ email: EMAIL }, COOKIE);
      assert.equal(r.status, 302);
      assert.equal(r.location, "/ai");
    });
    await t.test("a refusal with whoami failing: the refusal's message, no form", async () => {
      mode.whoami = "fail";
      mode.accept = "refuse";
      const r = await post({ email: EMAIL }, COOKIE);
      assert.equal(r.status, 403);
      assert.match(r.text, /belongs to another account/);
      assert.ok(noCreate(r.text));
    });
  });
});
