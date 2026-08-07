import { createHmac } from "node:crypto";
import { createServer, type IncomingMessage } from "node:http";
import type { AddressInfo } from "node:net";
import { test } from "node:test";
import assert from "node:assert/strict";
import { mintPortalIdentity, PORTAL_IDENTITY_HEADER } from "../../../../ioi-ai/plugins/chassis/src/portal-identity.ts";

const PORTAL_SECRET = "portal-daemon-bff-route-portal-secret";
const EXCHANGE_SECRET = "portal-daemon-bff-route-exchange-secret-0000000000000";
const ISSUER = "surface://ioi.ai/bff-route-test";
const AUDIENCE = "daemon://hypervisor/bff-route-test";
const TENANT = "org://local";

const observed: Array<{ path: string; authorization?: string; cookie?: string; principal?: string }> = [];
const daemon = createServer(async (req: IncomingMessage, res) => {
  const path = new URL(req.url ?? "/", "http://daemon.test").pathname;
  let raw = "";
  for await (const chunk of req) raw += chunk;
  if (path === "/v1/hypervisor/auth/portal-session-exchange") {
    const assertion = (JSON.parse(raw) as { assertion: string }).assertion;
    const [header, claims, signature] = assertion.split(".");
    const expected = createHmac("sha256", EXCHANGE_SECRET).update(`${header}.${claims}`).digest("base64url");
    assert.equal(signature, expected);
    const decoded = JSON.parse(Buffer.from(claims!, "base64url").toString("utf8")) as {
      iss: string;
      aud: string;
      sub: string;
      tenant_ref: string;
    };
    assert.equal(decoded.iss, ISSUER);
    assert.equal(decoded.aud, AUDIENCE);
    assert.equal(decoded.tenant_ref, TENANT);
    observed.push({ path, principal: decoded.sub, cookie: req.headers.cookie });
    res.writeHead(200, { "content-type": "application/json" });
    return void res.end(
      JSON.stringify({
        ok: true,
        session_token: "ioi_sess_bff_route_server_only",
        expires_at: new Date(Date.now() + 300_000).toISOString(),
        principal: { principal_id: decoded.sub, tenant_refs: [TENANT] },
      }),
    );
  }
  observed.push({
    path,
    authorization: req.headers.authorization,
    cookie: req.headers.cookie,
  });
  if (req.headers.authorization !== "Bearer ioi_sess_bff_route_server_only") {
    res.writeHead(401, { "content-type": "application/json" });
    return void res.end(JSON.stringify({ reason: "authentication_required" }));
  }
  res.writeHead(200, { "content-type": "application/json" });
  if (path.endsWith("/whoami")) {
    return void res.end(
      JSON.stringify({
        authenticated: true,
        principal: { principal_id: "alice", tenant_refs: [TENANT] },
      }),
    );
  }
  res.end(JSON.stringify({ ok: true, goal_runs: [{ goal_run_id: "gr_portal_route" }] }));
});
await new Promise<void>((resolve) => daemon.listen(0, "127.0.0.1", resolve));

const core = createServer((_req, res) => {
  res.writeHead(200, { "content-type": "application/json" });
  res.end("{}");
});
await new Promise<void>((resolve) => core.listen(0, "127.0.0.1", resolve));

process.env.NODE_ENV = "production";
process.env.CORE_API_URL = `http://127.0.0.1:${(core.address() as AddressInfo).port}`;
process.env.CORE_SIGNING_SECRET = "portal-daemon-bff-route-core-signing-secret";
process.env.PORTAL_IDENTITY_SECRET = PORTAL_SECRET;
process.env.WEB_UI_PRINCIPALS = "alice";
process.env.IOI_HYPERVISOR_DAEMON_URL = `http://127.0.0.1:${(daemon.address() as AddressInfo).port}`;
process.env.IOI_PORTAL_DAEMON_EXCHANGE_SECRET = EXCHANGE_SECRET;
process.env.IOI_PORTAL_DAEMON_EXCHANGE_ISSUER = ISSUER;
process.env.IOI_PORTAL_DAEMON_EXCHANGE_AUDIENCE = AUDIENCE;
process.env.IOI_PORTAL_DAEMON_EXCHANGE_TENANT_REF = TENANT;

const { handler } = await import("../server/index.ts");
const surface = createServer((req, res) => void handler(req, res));
await new Promise<void>((resolve) => surface.listen(0, "127.0.0.1", resolve));
const base = `http://127.0.0.1:${(surface.address() as AddressInfo).port}`;

test.after(() => {
  surface.close();
  core.close();
  daemon.close();
});

test("signed portal request crosses the derivative BFF and reaches GoalRun with the same daemon principal", async () => {
  const portalIdentity = mintPortalIdentity({ p: "alice", exp: Date.now() + 60_000 }, PORTAL_SECRET);
  const response = await fetch(`${base}/api/ioi/goals`, {
    headers: {
      [PORTAL_IDENTITY_HEADER]: portalIdentity,
      cookie: "ioi_session=browser-attacker-session",
      authorization: "Bearer browser-attacker-bearer",
    },
  });
  assert.equal(response.status, 200);
  const body = await response.text();
  assert.match(body, /gr_portal_route/u);
  assert.doesNotMatch(body, /ioi_sess_bff_route_server_only/u);
  assert.deepEqual(
    observed.map(({ path }) => path),
    [
      "/v1/hypervisor/auth/portal-session-exchange",
      "/v1/hypervisor/auth/whoami",
      "/v1/goal-orchestration/goal-runs",
    ],
  );
  assert.equal(observed[0]?.principal, "alice");
  assert.ok(observed.every(({ cookie }) => cookie === undefined));
  assert.ok(observed.slice(1).every(({ authorization }) => authorization === "Bearer ioi_sess_bff_route_server_only"));
});

test("invalid portal signature is refused before the daemon exchange", async () => {
  observed.length = 0;
  const forged = mintPortalIdentity({ p: "alice", exp: Date.now() + 60_000 }, "wrong-portal-secret");
  const response = await fetch(`${base}/api/ioi/goals`, {
    headers: { [PORTAL_IDENTITY_HEADER]: forged },
  });
  assert.equal(response.status, 401);
  assert.deepEqual(observed, []);
});
