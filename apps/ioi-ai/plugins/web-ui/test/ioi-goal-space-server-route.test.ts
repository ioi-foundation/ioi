import { test } from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { createServer, type IncomingMessage } from "node:http";
import type { AddressInfo } from "node:net";
import { mintPortalIdentity, PORTAL_IDENTITY_HEADER } from "../../../../ioi-ai/plugins/chassis/src/portal-identity.ts";

interface Call {
  method: string;
  path: string;
  body: Record<string, unknown>;
  cookie: string;
  authorization: string;
}

const calls: Call[] = [];
const authorityHeaders: IncomingMessage["headers"][] = [];
const exchangeSecret = "goal-space-portal-daemon-exchange-secret-000000000000";
const exchangeIssuer = "surface://ioi.ai/goal-space-test";
const exchangeAudience = "daemon://hypervisor/goal-space-test";
const exchangeTenant = "org://local";
let refuseCachedSession = false;
let refuseExchange = false;
const daemon = createServer((req: IncomingMessage, res) => {
  let raw = "";
  req.on("data", (chunk) => (raw += chunk));
  req.on("end", () => {
    if (req.url === "/v1/hypervisor/auth/portal-session-exchange") {
      if (refuseExchange) {
        res.writeHead(401, { "content-type": "application/json" });
        return res.end(JSON.stringify({ code: "exchange_refused" }));
      }
      const assertion = (JSON.parse(raw) as { assertion: string }).assertion;
      const [header, claims, signature] = assertion.split(".");
      const expected = createHmac("sha256", exchangeSecret).update(`${header}.${claims}`).digest("base64url");
      assert.equal(signature, expected);
      const identity = JSON.parse(Buffer.from(claims!, "base64url").toString("utf8")) as {
        iss: string;
        aud: string;
        sub: string;
        tenant_ref: string;
      };
      assert.deepEqual(identity, {
        ...identity,
        iss: exchangeIssuer,
        aud: exchangeAudience,
        sub: "alice",
        tenant_ref: exchangeTenant,
      });
      res.writeHead(200, { "content-type": "application/json" });
      return res.end(
        JSON.stringify({
          ok: true,
          session_token: "ioi_sess_goal_space_bff",
          expires_at: new Date(Date.now() + 300_000).toISOString(),
          principal: { principal_id: "alice", tenant_refs: [exchangeTenant] },
        }),
      );
    }
    if (req.url === "/v1/hypervisor/auth/whoami") {
      authorityHeaders.push(req.headers);
      if (refuseCachedSession || req.headers.authorization !== "Bearer ioi_sess_goal_space_bff") {
        res.writeHead(401, { "content-type": "application/json" });
        return res.end(JSON.stringify({ reason: "authentication_required" }));
      }
      res.writeHead(200, { "content-type": "application/json" });
      return res.end(
        JSON.stringify({
          authenticated: true,
          principal: { principal_id: "alice", tenant_refs: [exchangeTenant] },
        }),
      );
    }
    if (req.url === "/v1/goal-orchestration/outcome-rooms/overview") {
      req.socket.destroy();
      return;
    }
    calls.push({
      method: req.method ?? "GET",
      path: req.url ?? "",
      body: raw ? (JSON.parse(raw) as Record<string, unknown>) : {},
      cookie: req.headers.cookie ?? "",
      authorization: req.headers.authorization ?? "",
    });
    if (req.method === "GET" && req.url === "/v1/goal-orchestration/goal-runs/gr_123") {
      res.writeHead(200, { "content-type": "application/json" });
      return res.end(
        JSON.stringify({
          ok: true,
          goal_run: {
            schema_version: "ioi.goal-run.v1",
            goal_run_id: "gr_123",
            goal_ref: "goal://gr_123",
            owner_ref: "user://alice",
            outcome_room_ref: null,
            receipt_refs: ["receipt://goal-run/gr_123/admission"],
            work_result_refs: [],
            status: "draft",
          },
        }),
      );
    }
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ ok: true, goal_runs: [], outcome_rooms: [] }));
  });
});
await new Promise<void>((resolve) => daemon.listen(0, resolve));

const core = createServer((_req, res) => {
  res.writeHead(200, { "content-type": "application/json" });
  res.end("{}");
});
await new Promise<void>((resolve) => core.listen(0, resolve));

const secret = "goal-space-production-identity-secret";
process.env.NODE_ENV = "production";
delete process.env.ALLOW_UNSIGNED_TEST_IDENTITY;
process.env.CORE_SIGNING_SECRET = "goal-space-core-signing-secret";
process.env.PORTAL_IDENTITY_SECRET = secret;
process.env.IOI_AI_ALLOW_LOOPBACK_DAEMON_TRUST = "1";
process.env.IOI_HYPERVISOR_DAEMON_URL = `http://127.0.0.1:${(daemon.address() as AddressInfo).port}`;
process.env.IOI_PORTAL_DAEMON_EXCHANGE_SECRET = exchangeSecret;
process.env.IOI_PORTAL_DAEMON_EXCHANGE_ISSUER = exchangeIssuer;
process.env.IOI_PORTAL_DAEMON_EXCHANGE_AUDIENCE = exchangeAudience;
process.env.IOI_PORTAL_DAEMON_EXCHANGE_TENANT_REF = exchangeTenant;
process.env.CORE_API_URL = `http://127.0.0.1:${(core.address() as AddressInfo).port}`;
process.env.WEB_UI_PRINCIPALS = "alice";
process.env.WEB_UI_PUBLIC_URL = "https://ioi.example";

const { handler, goalRunMembershipRoot } = await import("../server/index.ts");
const surface = createServer((req, res) => void handler(req, res));
await new Promise<void>((resolve) => surface.listen(0, resolve));
const base = `http://127.0.0.1:${(surface.address() as AddressInfo).port}`;
const identity = mintPortalIdentity({ p: "alice", exp: Date.now() + 60_000 }, secret);

function headers(session = "daemon-session"): Record<string, string> {
  return {
    [PORTAL_IDENTITY_HEADER]: identity,
    cookie: `ioi_session=${session}`,
  };
}

test.after(() => {
  surface.close();
  core.close();
  daemon.close();
});

test("production posture binds every Goal Space route to the same signed portal and daemon principal", async () => {
  const first = await fetch(`${base}/api/ioi/goals`, { headers: headers() });
  await fetch(`${base}/api/ioi/goal-activations/gra_789`, {
    headers: headers(),
  });
  await fetch(`${base}/api/ioi/goals/gr_123/events`, { headers: headers() });
  await fetch(`${base}/api/ioi/rooms/or_456/replay`, { headers: headers() });
  assert.equal(first.status, 200);
  assert.equal(first.headers.get("cache-control"), "no-store");
  assert.deepEqual(
    calls.slice(-4).map((call) => [call.method, call.path]),
    [
      ["GET", "/v1/goal-orchestration/goal-runs"],
      ["GET", "/v1/goal-orchestration/goal-run-activations/gra_789"],
      ["GET", "/v1/goal-orchestration/goal-runs/gr_123/events"],
      ["GET", "/v1/goal-orchestration/outcome-rooms/or_456/replay"],
    ],
  );
  assert.ok(calls.slice(-4).every((call) => call.cookie === ""));
  assert.ok(calls.slice(-4).every((call) => call.authorization === "Bearer ioi_sess_goal_space_bff"));
  assert.ok(authorityHeaders.slice(-4).every((value) => value["x-ioi-forwarded"] === "ioi-ai"));
});

test("a browser cannot substitute another daemon principal beneath a signed portal principal", async () => {
  const before = calls.length;
  const response = await fetch(`${base}/api/ioi/goals`, {
    headers: headers("mallory-session"),
  });
  assert.equal(response.status, 200);
  assert.equal(calls.length, before + 1);
  assert.equal(calls.at(-1)?.cookie, "");
  assert.equal(calls.at(-1)?.authorization, "Bearer ioi_sess_goal_space_bff");
});

test("a signed portal principal without daemon authority fails closed", async () => {
  const before = calls.length;
  refuseCachedSession = true;
  refuseExchange = true;
  const response = await fetch(`${base}/api/ioi/goals`, { headers: headers() });
  refuseCachedSession = false;
  refuseExchange = false;
  assert.equal(response.status, 401);
  assert.equal(calls.length, before);
});

test("activation requests are closed and cannot substitute identity, schema, profile, or review decision", async () => {
  await fetch(`${base}/api/ioi/goal-activations`, {
    method: "POST",
    headers: { ...headers(), "content-type": "application/json" },
    body: JSON.stringify({
      schema_version: "attacker",
      goal_text: "Produce a verified outcome",
      constraints: ["bounded"],
      project_ref: null,
      result_profile: "attacker",
      idempotency_key: "idem-1",
      owner_ref: "user://mallory",
    }),
  });
  assert.deepEqual(calls.at(-1)?.body, {
    schema_version: "ioi.goal-run-activation-draft-request.v1",
    goal_text: "Produce a verified outcome",
    constraints: ["bounded"],
    project_ref: null,
    result_profile: "research",
    idempotency_key: "idem-1",
  });

  await fetch(`${base}/api/ioi/goal-activations/gra_123/submit`, {
    method: "POST",
    headers: { ...headers(), "content-type": "application/json" },
    body: JSON.stringify({
      schema_version: "attacker",
      expected_activation_hash: "sha256:abc",
      review_decision: "attacker",
      wallet_approval_grant: { grant_ref: "grant://1" },
      requesting_principal_ref: "user://mallory",
    }),
  });
  assert.deepEqual(calls.at(-1)?.body, {
    schema_version: "ioi.goal-run-activation-submit-request.v1",
    expected_activation_hash: "sha256:abc",
    review_decision: "approve",
    wallet_approval_grant: { grant_ref: "grant://1" },
  });
});

test("browser mutations require the exact public origin, same-origin fetch metadata, and JSON", async () => {
  const before = calls.length;
  const accepted = await fetch(`${base}/api/ioi/goal-activations`, {
    method: "POST",
    headers: {
      ...headers(),
      origin: "https://ioi.example",
      "sec-fetch-site": "same-origin",
      "content-type": "application/json; charset=utf-8",
    },
    body: JSON.stringify({
      goal_text: "Exact origin",
      idempotency_key: "idem-origin",
    }),
  });
  assert.equal(accepted.status, 200);
  assert.equal(calls.length, before + 1);

  for (const requestHeaders of [
    {
      ...headers(),
      origin: "https://evil.example",
      "sec-fetch-site": "cross-site",
      "content-type": "application/json",
    },
    {
      ...headers(),
      origin: "https://ioi.example",
      "sec-fetch-site": "same-site",
      "content-type": "application/json",
    },
  ]) {
    const response = await fetch(`${base}/api/ioi/goal-activations`, {
      method: "POST",
      headers: requestHeaders,
      body: "{}",
    });
    assert.equal(response.status, 403);
    assert.equal(response.headers.get("cache-control"), "no-store");
  }
  const unsupported = await fetch(`${base}/api/ioi/goal-activations`, {
    method: "POST",
    headers: { ...headers(), "content-type": "text/plain" },
    body: "{}",
  });
  assert.equal(unsupported.status, 415);
  assert.equal(unsupported.headers.get("cache-control"), "no-store");
  assert.equal(calls.length, before + 1);
});

test("activation mutations reject every non-object JSON body before daemon authority", async () => {
  const before = calls.length;
  for (const body of ["null", "[]", '"text"', "7"]) {
    const response = await fetch(`${base}/api/ioi/goal-activations`, {
      method: "POST",
      headers: { ...headers(), "content-type": "application/json" },
      body,
    });
    assert.equal(response.status, 400);
    assert.equal(response.headers.get("cache-control"), "no-store");
    assert.match(await response.text(), /JSON object/);
  }
  assert.equal(calls.length, before);
});

test("all local IOI failures and upstream transport failures are non-cacheable", async () => {
  const cases: Array<[string, RequestInit, number]> = [
    ["/api/ioi/goals", {}, 401],
    ["/api/ioi/goals/bad", { headers: headers() }, 400],
    ["/api/ioi/not-a-route", { headers: headers() }, 404],
    ["/api/ioi/rooms/overview", { headers: headers() }, 502],
    [
      "/api/ioi/goal-activations",
      {
        method: "POST",
        headers: { ...headers(), "content-type": "application/json" },
        body: JSON.stringify({ value: "x".repeat(1_000_001) }),
      },
      413,
    ],
  ];
  for (const [path, init, status] of cases) {
    const response = await fetch(`${base}${path}`, init);
    assert.equal(response.status, status);
    assert.equal(response.headers.get("cache-control"), "no-store");
  }
});

test("generic GoalRun create, start, and reconcile are closed relays with no identity substitution", async () => {
  const before = calls.length;
  await fetch(`${base}/api/ioi/goals`, {
    method: "POST",
    headers: { ...headers(), "content-type": "application/json" },
    body: JSON.stringify({
      goal: "Implement the bounded change",
      session_ref: "session:hyp-123",
      model_route_ref: "model-route://primary",
      owner_ref: "user://mallory",
    }),
  });
  assert.equal(calls.length, before, "unknown GoalRun fields refuse before daemon authority");

  await fetch(`${base}/api/ioi/goals`, {
    method: "POST",
    headers: { ...headers(), "content-type": "application/json" },
    body: JSON.stringify({
      goal: "Implement the bounded change",
      session_ref: "session:hyp-123",
      model_route_ref: "model-route://primary",
    }),
  });
  assert.deepEqual(calls.at(-1)?.body, {
    goal: "Implement the bounded change",
    session_ref: "session:hyp-123",
    origin_surface: "api",
    model_route_ref: "model-route://primary",
  });

  await fetch(`${base}/api/ioi/goals/gr_123/start`, {
    method: "POST",
    headers: { ...headers(), "content-type": "application/json" },
    body: JSON.stringify({ wallet_approval_grant: { grant_ref: "grant://start" } }),
  });
  assert.equal(calls.at(-1)?.path, "/v1/goal-orchestration/goal-runs/gr_123/start");
  assert.deepEqual(calls.at(-1)?.body, { wallet_approval_grant: { grant_ref: "grant://start" } });

  await fetch(`${base}/api/ioi/goals/gr_123/reconcile`, {
    method: "POST",
    headers: { ...headers(), "content-type": "application/json" },
    body: JSON.stringify({ idempotency_key: "reconcile-one", wallet_approval_grant: { grant_ref: "grant://r" } }),
  });
  assert.equal(calls.at(-1)?.path, "/v1/goal-orchestration/goal-runs/gr_123/reconcile");
  assert.deepEqual(calls.at(-1)?.body, {
    idempotency_key: "reconcile-one",
    wallet_approval_grant: { grant_ref: "grant://r" },
  });
});

test("OutcomeRoom materialization derives identity and selected profile while membership derives the GoalRun head", async () => {
  const governance = {
    stop_policy_ref: "policy://room/stop",
    visibility_policy_ref: "policy://room/visibility",
    participation_policy_ref: "policy://room/participation",
    privacy_policy_ref: "policy://room/privacy",
    contribution_policy_ref: "policy://room/contribution",
    cooperation_surplus_policy_ref: "policy://room/surplus",
    coordination_policy_ref: "policy://room/coordination",
    ordering_and_merge_policy_ref: "policy://room/ordering",
    conflict_and_failover_policy_ref: "policy://room/failover",
  };
  await fetch(`${base}/api/ioi/rooms`, {
    method: "POST",
    headers: { ...headers(), "content-type": "application/json" },
    body: JSON.stringify({
      system_id: "system://room/one",
      goal_run_ref: "goal://gr_123",
      objective: "Coordinate one bounded outcome",
      room_mode: "permissioned_team",
      governance,
    }),
  });
  assert.deepEqual(calls.at(-1)?.body, {
    schema_version: "ioi.applications.ioi-ai.outcome-room.v2",
    system_id: "system://room/one",
    owner_or_sponsor_ref: "user://alice",
    objective_ref: "goal://gr_123",
    objective: "Coordinate one bounded outcome",
    room_mode: "permissioned_team",
    coordination_topology: "hosted_admission",
    host_domain_ref: "system://room/one",
    ...governance,
    constraint_refs: [],
    acceptance_criteria_refs: [],
    collaboration_terms_refs: [],
    artifact_license_rights_retention_and_export_policy_refs: [],
    ontology_profile_refs: [],
    scorecard_and_guardrail_refs: [],
    verifier_path_refs: [],
    resource_and_budget_refs: [],
    discovery_and_external_admission_policy_refs: [],
    multi_party_collaboration_ref: null,
    settlement_policy_ref: null,
  });

  await fetch(`${base}/api/ioi/rooms/or_456/goal-runs/attach`, {
    method: "POST",
    headers: { ...headers(), "content-type": "application/json" },
    body: JSON.stringify({ goal_run_ref: "goal://gr_123", expected_revision: 7 }),
  });
  const currentGoal = {
    schema_version: "ioi.goal-run.v1",
    goal_run_id: "gr_123",
    goal_ref: "goal://gr_123",
    owner_ref: "user://alice",
    outcome_room_ref: null,
    receipt_refs: ["receipt://goal-run/gr_123/admission"],
    work_result_refs: [],
    status: "draft",
  };
  assert.deepEqual(calls.slice(-2).map((call) => [call.method, call.path]), [
    ["GET", "/v1/goal-orchestration/goal-runs/gr_123"],
    ["POST", "/v1/goal-orchestration/outcome-rooms/or_456/attach-goal-run"],
  ]);
  assert.deepEqual(calls.at(-1)?.body, {
    goal_run_ref: "goal://gr_123",
    expected_revision: 7,
    expected_goal_run_record_root: goalRunMembershipRoot(currentGoal),
  });
});

test("malformed canonical ids refuse before reaching the daemon", async () => {
  const before = calls.length;
  const response = await fetch(`${base}/api/ioi/goals/${encodeURIComponent("gr_bad/path")}`, {
    headers: headers(),
  });
  assert.equal(response.status, 400);
  assert.equal(calls.length, before);
});

test("signout revokes the matching daemon session and expires every local identity cookie", async () => {
  const response = await fetch(`${base}/signout`, {
    method: "POST",
    headers: { ...headers(), "content-type": "application/json" },
    body: "{}",
  });
  assert.equal(response.status, 200);
  assert.equal(calls.at(-1)?.path, "/v1/hypervisor/auth/logout");
  const setCookies = response.headers.getSetCookie();
  for (const name of ["webuiuser", "webuiuser_name", "webui_impersonator", "ioi_session"]) {
    assert.ok(setCookies.some((value) => value.startsWith(`${name}=`) && value.includes("Max-Age=0")));
  }
});
