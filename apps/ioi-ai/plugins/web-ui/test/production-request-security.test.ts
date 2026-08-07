import assert from "node:assert/strict";
import { createServer, type IncomingMessage } from "node:http";
import type { AddressInfo } from "node:net";
import { test } from "node:test";
import { mintPortalIdentity, PORTAL_IDENTITY_HEADER } from "../../../../ioi-ai/plugins/chassis/src/portal-identity.ts";

let coreMutations = 0;
const core = createServer((req: IncomingMessage, res) => {
  if (["POST", "PUT", "PATCH", "DELETE"].includes(req.method ?? "")) coreMutations += 1;
  req.resume();
  req.on("end", () => {
    res.writeHead(200, { "content-type": "application/json", "cache-control": "public, max-age=3600" });
    res.end(JSON.stringify({ ok: true, project: {}, permissions: [], deployments: [] }));
  });
});
await new Promise<void>((resolve) => core.listen(0, resolve));

const coreSecret = "production-request-core-secret";
const portalSecret = "production-request-portal-secret";
process.env.NODE_ENV = "production";
process.env.CORE_API_URL = `http://127.0.0.1:${(core.address() as AddressInfo).port}`;
process.env.CORE_SIGNING_SECRET = coreSecret;
process.env.PORTAL_IDENTITY_SECRET = portalSecret;
process.env.WEB_UI_PUBLIC_URL = "https://ioi.example";
process.env.WEB_UI_PRINCIPALS = "alice";
process.env.DEPLOY_APPS_DOMAIN = "apps.example";

const { handler } = await import("../server/index.ts");
const surface = createServer((req, res) => void handler(req, res));
await new Promise<void>((resolve) => surface.listen(0, resolve));
const base = `http://127.0.0.1:${(surface.address() as AddressInfo).port}`;
const identity = mintPortalIdentity({ p: "alice", exp: Date.now() + 60_000 }, portalSecret);
const signed = { [PORTAL_IDENTITY_HEADER]: identity };
const sameOrigin = { origin: "https://ioi.example", "sec-fetch-site": "same-origin" };

test.after(() => {
  surface.close();
  core.close();
});

test("production never accepts unsigned cookie identity and emits Secure no-store identity cookies", async () => {
  const unsigned = await fetch(`${base}/me`, { headers: { cookie: "webuiuser=alice" } });
  assert.equal(unsigned.status, 401);
  assert.equal(unsigned.headers.get("cache-control"), "no-store");

  const me = await fetch(`${base}/me`, { headers: signed });
  assert.equal(me.status, 200);
  assert.equal(me.headers.get("cache-control"), "no-store");
  assert.match(me.headers.get("set-cookie") ?? "", /; Secure/);

  const signout = await fetch(`${base}/signout`, {
    method: "POST",
    headers: { ...signed, "content-type": "application/json" },
    body: "{}",
  });
  assert.equal(signout.status, 200);
  assert.equal(signout.headers.get("cache-control"), "no-store");
  assert.match(signout.headers.get("set-cookie") ?? "", /; Secure/);
});

test("every current state-changing API route rejects cross-site browser metadata before any effect", async () => {
  const jsonRoutes: Array<[string, string]> = [
    ["POST", "/signout"],
    ["POST", "/api/ioi/goal-activations"],
    ["POST", "/api/ioi/goal-activations/gra_123/submit"],
    ["POST", "/api/ioi/goals"],
    ["POST", "/api/ioi/goals/gr_123/start"],
    ["POST", "/api/ioi/goals/gr_123/reconcile"],
    ["POST", "/api/ioi/rooms"],
    ["POST", "/api/ioi/rooms/or_123/goal-runs/attach"],
    ["POST", "/api/ioi/rooms/or_123/goal-runs/detach"],
    ["PUT", "/api/contexts/channel%3AC1/ambient-policy"],
    ["POST", "/api/projects"],
    ["PATCH", "/api/projects/p1"],
    ["POST", "/api/projects/p1/members"],
    ["DELETE", "/api/projects/p1/members/bob"],
    ["PUT", "/api/runtime-config"],
    ["POST", "/api/skills"],
    ["PUT", "/api/skills/s1"],
    ["DELETE", "/api/skills/s1"],
    ["POST", "/api/skills/s1/restore"],
    ["POST", "/api/sessions/s1/title"],
    ["POST", "/api/sessions/s1/fork"],
    ["POST", "/api/sessions/s1"],
    ["POST", "/api/memory/restore"],
    ["PUT", "/api/memory"],
    ["POST", "/api/connectors/slack/start"],
    ["POST", "/api/connectors/revoke"],
    ["POST", "/api/keychain/grants/g1/revoke"],
    ["POST", "/api/keychain/drops"],
    ["DELETE", "/api/keychain/credentials/c1"],
    ["POST", "/api/deployments/d1/display-name"],
    ["POST", "/api/deployments/d1/name"],
    ["POST", "/api/deployments/d1/archive"],
    ["POST", "/api/deployments/d1/restore"],
    ["POST", "/api/approvals/a1"],
    ["POST", "/api/turn"],
    ["POST", "/api/runs/r1/signal"],
    ["PATCH", "/api/crons/c1"],
    ["POST", "/api/crons/c1/disable"],
    ["POST", "/api/crons/c1/enable"],
    ["POST", "/api/crons/c1/run"],
    ["DELETE", "/api/crons/c1"],
  ];
  const before = coreMutations;
  for (const [method, path] of jsonRoutes) {
    const response = await fetch(`${base}${path}`, {
      method,
      headers: {
        ...signed,
        origin: "https://evil.example",
        "sec-fetch-site": "cross-site",
        "content-type": "application/json",
      },
      body: "{}",
    });
    assert.equal(response.status, 403, `${method} ${path}`);
    assert.equal(((await response.json()) as { error?: string }).error, "cross_site_request_refused", path);
  }
  for (const path of ["/api/blobs?sha=abc", "/api/files/upload?sha=abc&name=x&mimetype=text%2Fplain"]) {
    const response = await fetch(`${base}${path}`, {
      method: "POST",
      headers: {
        ...signed,
        origin: "https://evil.example",
        "sec-fetch-site": "cross-site",
        "content-type": "application/octet-stream",
      },
      body: "x",
    });
    assert.equal(response.status, 403, path);
  }
  assert.equal(coreMutations, before);
});

test("same-origin and signed non-browser mutations are narrow accepted paths with route-specific media", async () => {
  const crossSiteSigned = await fetch(`${base}/api/projects`, {
    method: "POST",
    headers: {
      ...signed,
      origin: "https://evil.example",
      "sec-fetch-site": "cross-site",
      "content-type": "application/json",
    },
    body: JSON.stringify({ name: "Rejected" }),
  });
  assert.equal(crossSiteSigned.status, 403);

  const wrongJsonMedia = await fetch(`${base}/api/projects`, {
    method: "POST",
    headers: { ...signed, ...sameOrigin, "content-type": "application/octet-stream" },
    body: "{}",
  });
  assert.equal(wrongJsonMedia.status, 415);

  const wrongUploadMedia = await fetch(`${base}/api/blobs?sha=${"a".repeat(64)}`, {
    method: "POST",
    headers: { ...signed, ...sameOrigin, "content-type": "multipart/form-data; boundary=x" },
    body: "--x--",
  });
  assert.equal(wrongUploadMedia.status, 415);

  const browser = await fetch(`${base}/api/projects`, {
    method: "POST",
    headers: { ...signed, ...sameOrigin, "content-type": "application/json" },
    body: JSON.stringify({ name: "Browser" }),
  });
  assert.equal(browser.status, 200);

  const service = await fetch(`${base}/api/projects`, {
    method: "POST",
    headers: { ...signed, "content-type": "application/json" },
    body: JSON.stringify({ name: "Service" }),
  });
  assert.equal(service.status, 200);
});

test("identity and authenticated private responses remain no-store even when upstream says public", async () => {
  for (const path of ["/me", "/api/memory", "/deployments/d1/"]) {
    const response = await fetch(`${base}${path}`, { headers: signed });
    assert.equal(response.headers.get("cache-control"), "no-store", path);
    assert.equal(response.headers.get("pragma"), "no-cache", path);
  }
  const appEdit = await fetch(`${base}/app-edit?slug=demo`, { headers: signed });
  assert.equal(appEdit.headers.get("cache-control"), "no-store");
});
