import { createHmac } from "node:crypto";
import { test } from "node:test";
import assert from "node:assert/strict";
import type { IncomingMessage } from "node:http";
import { createIoiDaemonGateway } from "../server/ioi-daemon.ts";
import {
  mintPortalDaemonExchangeAssertion,
  portalIdentityHash,
  type PortalDaemonExchangeConfig,
} from "../server/portal-daemon-exchange.ts";

const config: PortalDaemonExchangeConfig = {
  secret: "portal-daemon-exchange-test-secret-000000000000000000",
  issuer: "surface://ioi.ai/test",
  audience: "daemon://hypervisor/test",
  tenantRef: "org://local",
};

function request(headers: IncomingMessage["headers"]): IncomingMessage {
  return { headers } as IncomingMessage;
}

function decodeAndVerify(assertion: string): Record<string, unknown> {
  const [encodedHeader, encodedClaims, signature] = assertion.split(".");
  assert.ok(encodedHeader && encodedClaims && signature);
  const expected = createHmac("sha256", config.secret)
    .update(`${encodedHeader}.${encodedClaims}`)
    .digest("base64url");
  assert.equal(signature, expected);
  const header = JSON.parse(Buffer.from(encodedHeader, "base64url").toString("utf8"));
  assert.deepEqual(header, { alg: "HS256", typ: "ioi-portal-daemon-exchange+jwt" });
  return JSON.parse(Buffer.from(encodedClaims, "base64url").toString("utf8")) as Record<string, unknown>;
}

test("minted assertion is short-lived, audience/tenant bound, and contains only a portal token hash", () => {
  const portalToken = "signed.portal.identity";
  const { assertion, claims } = mintPortalDaemonExchangeAssertion(config, "alice", portalToken, {
    nowMs: 1_800_000_000_000,
    nonce: "fixed_nonce_00000000000000000000000000000000",
  });
  assert.deepEqual(decodeAndVerify(assertion), claims);
  assert.equal(claims.iss, config.issuer);
  assert.equal(claims.aud, config.audience);
  assert.equal(claims.sub, "alice");
  assert.equal(claims.tenant_ref, "org://local");
  assert.equal(claims.exp - claims.iat, 30);
  assert.equal(claims.source_identity_hash, portalIdentityHash(portalToken));
  assert.doesNotMatch(assertion, /signed\.portal\.identity/u);
});

test("gateway exchanges server-side, ignores browser daemon credentials, then proves principal and tenant", async () => {
  const calls: Array<{ path: string; headers: Record<string, string>; body?: string }> = [];
  const fetcher: typeof fetch = async (input, init) => {
    const url = new URL(String(input));
    const headers = init?.headers as Record<string, string>;
    calls.push({ path: url.pathname, headers, body: init?.body as string | undefined });
    if (url.pathname.endsWith("/portal-session-exchange")) {
      assert.equal(headers.authorization, undefined);
      const claims = decodeAndVerify(JSON.parse(String(init?.body)).assertion);
      assert.equal(claims.sub, "alice");
      return new Response(
        JSON.stringify({
          ok: true,
          session_token: "ioi_sess_server_only",
          expires_at: new Date(Date.now() + 300_000).toISOString(),
          principal: { principal_id: "alice", tenant_refs: ["org://local"] },
        }),
        { status: 200 },
      );
    }
    assert.equal(headers.authorization, "Bearer ioi_sess_server_only");
    assert.equal(headers.cookie, undefined);
    if (url.pathname.endsWith("/whoami")) {
      return new Response(
        JSON.stringify({
          authenticated: true,
          principal: { principal_id: "alice", tenant_refs: ["org://local"] },
        }),
        { status: 200 },
      );
    }
    return new Response(JSON.stringify({ ok: true, goal_runs: [] }), { status: 200 });
  };
  const gateway = createIoiDaemonGateway("https://daemon.example", fetcher, {
    portalExchange: config,
    requirePortalExchange: true,
  });
  const response = await gateway.request(
    request({
      "x-portal-identity": "verified.portal.identity",
      cookie: "ioi_session=browser-chosen-daemon-session",
      authorization: "Bearer browser-chosen-daemon-bearer",
    }),
    "alice",
    "GET",
    "/v1/goal-orchestration/goal-runs",
  );
  assert.equal(response.status, 200);
  assert.doesNotMatch(response.text, /ioi_sess_server_only/u);
  assert.deepEqual(
    calls.map((call) => call.path),
    [
      "/v1/hypervisor/auth/portal-session-exchange",
      "/v1/hypervisor/auth/whoami",
      "/v1/goal-orchestration/goal-runs",
    ],
  );
  assert.ok(calls.slice(1).every((call) => call.headers.cookie === undefined));
});

test("production-required exchange refuses browser credentials when trust is absent", async () => {
  let calls = 0;
  const gateway = createIoiDaemonGateway(
    "https://daemon.example",
    async () => {
      calls++;
      return new Response("{}");
    },
    { requirePortalExchange: true },
  );
  const response = await gateway.request(
    request({ cookie: "ioi_session=browser-token", authorization: "Bearer browser-token" }),
    "alice",
    "GET",
    "/v1/goal-orchestration/goal-runs",
  );
  assert.equal(response.status, 503);
  assert.match(response.text, /portal_exchange_not_configured/u);
  assert.equal(calls, 0);
});

test("gateway refuses a daemon session whose server-resolved tenant does not match", async () => {
  let requestedGoalRuns = false;
  const gateway = createIoiDaemonGateway(
    "https://daemon.example",
    async (input) => {
      const path = new URL(String(input)).pathname;
      if (path.endsWith("/portal-session-exchange")) {
        return new Response(
          JSON.stringify({
            session_token: "ioi_sess_wrong_tenant",
            expires_at: new Date(Date.now() + 300_000).toISOString(),
            principal: { principal_id: "alice", tenant_refs: ["org://elsewhere"] },
          }),
          { status: 200 },
        );
      }
      requestedGoalRuns = true;
      return new Response("{}", { status: 200 });
    },
    { portalExchange: config, requirePortalExchange: true },
  );
  const response = await gateway.request(
    request({ "x-portal-identity": "verified.portal.identity" }),
    "alice",
    "GET",
    "/v1/goal-orchestration/goal-runs",
  );
  assert.equal(response.status, 403);
  assert.match(response.text, /principal_mismatch/u);
  assert.equal(requestedGoalRuns, false);
});

test("gateway refuses a daemon session outside the bounded five-minute exchange lifetime", async () => {
  let requestedWhoami = false;
  const gateway = createIoiDaemonGateway(
    "https://daemon.example",
    async (input) => {
      const path = new URL(String(input)).pathname;
      if (path.endsWith("/portal-session-exchange")) {
        return new Response(
          JSON.stringify({
            session_token: "ioi_sess_overlong",
            expires_at: new Date(Date.now() + 3_600_000).toISOString(),
            principal: { principal_id: "alice", tenant_refs: ["org://local"] },
          }),
          { status: 200 },
        );
      }
      requestedWhoami = true;
      return new Response("{}", { status: 200 });
    },
    { portalExchange: config, requirePortalExchange: true },
  );
  const response = await gateway.request(
    request({ "x-portal-identity": "verified.portal.identity" }),
    "alice",
    "GET",
    "/v1/goal-orchestration/goal-runs",
  );
  assert.equal(response.status, 403);
  assert.match(response.text, /principal_mismatch/u);
  assert.equal(requestedWhoami, false);
});
