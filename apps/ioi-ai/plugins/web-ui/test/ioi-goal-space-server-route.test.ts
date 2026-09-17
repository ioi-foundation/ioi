import { test } from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { createServer, type IncomingMessage } from "node:http";
import type { AddressInfo } from "node:net";
import { mintPortalIdentity, PORTAL_IDENTITY_HEADER } from "../../../../ioi-ai/plugins/chassis/src/portal-identity.ts";
import { systemRecordSlug } from "../../../../../packages/agent-sdk/dist/index.js";

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
let threadCounter = 0;
const seamChains = new Map<
  string,
  Array<{ record: Record<string, unknown>; head: string; admission: Record<string, unknown> }>
>();
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
    if (req.url === "/v1/hypervisor/autonomous-systems/projection") {
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
    if (req.method === "POST" && req.url === "/v1/threads") {
      threadCounter += 1;
      res.writeHead(200, { "content-type": "application/json" });
      return res.end(
        JSON.stringify({
          thread_id: `thread_stub_${threadCounter}`,
          status: "active",
          title: (JSON.parse(raw) as { goal?: string }).goal ?? "",
        }),
      );
    }
    const thread = req.url?.match(/^\/v1\/threads\/([^/?]+)(\/subagents)?$/u);
    if (req.method === "GET" && thread) {
      res.writeHead(200, { "content-type": "application/json" });
      return res.end(
        JSON.stringify(
          thread[2] ? { subagents: [] } : { thread_id: decodeURIComponent(thread[1]!), status: "active", title: "" },
        ),
      );
    }
    const seam = req.url?.match(/^\/v1\/hypervisor\/autonomous-systems\/([^/?]+)\/records(?:\/([^/?]+)\/([^/?]+))?(?:\?.*)?$/u);
    if (seam) {
      const systemId = decodeURIComponent(seam[1]!);
      if (seam[2]) {
        const chain = seamChains.get(`${systemId}/${decodeURIComponent(seam[2])}/${decodeURIComponent(seam[3]!)}`);
        if (!chain) {
          res.writeHead(403, { "content-type": "application/json" });
          return res.end(
            JSON.stringify({
              error: {
                code: "request_resource_scope_required",
                message: "the requested resource has no scope visible to the authenticated principal",
              },
            }),
          );
        }
        res.writeHead(200, { "content-type": "application/json" });
        return res.end(
          JSON.stringify({
            ok: true,
            current: chain.at(-1)!.record,
            revisions: chain.map((entry) => entry.record),
            admissions: chain.map((entry) => entry.admission),
            head: chain.at(-1)!.head,
          }),
        );
      }
      if (req.method === "GET") {
        const records = [...seamChains.entries()]
          .filter(([key]) => key.startsWith(`${systemId}/`))
          .map(([key, chain]) => ({
            resource_ref: key,
            contract_id: chain.at(-1)!.admission.contract_id,
            current: chain.at(-1)!.record,
            head: chain.at(-1)!.head,
            revisions: chain.length,
          }));
        res.writeHead(200, { "content-type": "application/json" });
        return res.end(JSON.stringify({ ok: true, system_id: systemId, records, count: records.length }));
      }
      const input = JSON.parse(raw) as {
        contract_id: string;
        object_id: string;
        parent_scope_ref: string;
        record: Record<string, unknown>;
        expected_head: string | null;
        idempotency_key: string;
      };
      const key = `${systemId}/${systemRecordSlug(input.contract_id)}/${systemRecordSlug(input.object_id)}`;
      const chain = seamChains.get(key) ?? [];
      const head = chain.at(-1)?.head ?? null;
      if ((input.expected_head ?? null) !== head) {
        res.writeHead(409, { "content-type": "application/json" });
        return res.end(JSON.stringify({ error: { code: "system_record_expected_head_conflict" } }));
      }
      const nextHead = `sha256:${createHmac("sha256", "seam").update(`${head ?? "genesis"}|${JSON.stringify(input.record)}`).digest("hex")}`;
      const record = {
        ...input.record,
        system_binding: {
          schema_version: "ioi.foundations.system-scoped-object-binding.v1",
          system_id: systemId,
          parent_scope_ref: input.parent_scope_ref,
          proposed_or_issued_by_ref: "user://alice",
          payload_root: `sha256:${"b".repeat(64)}`,
          created_at: "2026-09-17T12:00:00Z",
          updated_at: null,
        },
      };
      const admission = {
        seq: chain.length,
        head: nextHead,
        contract_id: input.contract_id,
        idempotency_key: input.idempotency_key,
        receipt_ref: `receipt://event-stream/system-records/${chain.length}`,
        operation_ref: `agentgres://event-stream/system-records/${chain.length}`,
      };
      chain.push({ record, head: nextHead, admission });
      seamChains.set(key, chain);
      res.writeHead(200, { "content-type": "application/json" });
      return res.end(
        JSON.stringify({
          ok: true,
          replayed: false,
          system_id: systemId,
          contract_id: input.contract_id,
          resource_ref: key,
          record,
          admission,
          expected_head_for_successor: nextHead,
          receipt_ref: admission.receipt_ref,
          operation_ref: admission.operation_ref,
        }),
      );
    }
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

const { handler } = await import("../server/index.ts");
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
  const absent = await fetch(
    `${base}/api/ioi/orchestrations/orc_456/replay?system_id=${encodeURIComponent("system://estate/one")}`,
    { headers: headers() },
  );
  assert.equal(first.status, 200);
  assert.equal(first.headers.get("cache-control"), "no-store");
  assert.equal(absent.status, 403);
  assert.equal(absent.headers.get("cache-control"), "no-store");
  assert.equal(((await absent.json()) as { error: { code: string } }).error.code, "request_resource_scope_required");
  assert.deepEqual(
    calls.slice(-4, -1).map((call) => [call.method, call.path]),
    [
      ["GET", "/v1/goal-orchestration/goal-runs"],
      ["GET", "/v1/goal-orchestration/goal-run-activations/gra_789"],
      ["GET", "/v1/goal-orchestration/goal-runs/gr_123/events"],
    ],
  );
  assert.equal(calls.at(-1)?.method, "GET");
  assert.equal(
    calls.at(-1)?.path,
    `/v1/hypervisor/autonomous-systems/${encodeURIComponent("system://estate/one")}/records/${encodeURIComponent(
      systemRecordSlug("schema://ioi/applications/ioi-ai/orchestration/v1"),
    )}/${encodeURIComponent(systemRecordSlug("orchestration://orc_456"))}`,
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
    ["/api/ioi/orchestrations", { headers: headers() }, 502],
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

test("orchestration composition creates the coordinating thread, admits the record under the resolved owner scope, and revises membership only on the exact head", async () => {
  const governance = {
    stop_policy_ref: "policy://estate/stop",
    visibility_policy_ref: "policy://estate/visibility",
    participation_policy_ref: "policy://estate/participation",
    privacy_policy_ref: "policy://estate/privacy",
    contribution_policy_ref: "policy://estate/contribution",
    cooperation_surplus_policy_ref: "policy://estate/surplus",
    coordination_policy_ref: "policy://estate/coordination",
    ordering_and_merge_policy_ref: "policy://estate/ordering",
    conflict_and_failover_policy_ref: "policy://estate/failover",
  };
  const systemId = "system://estate/one";
  const seamRoot = `/v1/hypervisor/autonomous-systems/${encodeURIComponent(systemId)}/records`;
  const composed = await fetch(`${base}/api/ioi/orchestrations`, {
    method: "POST",
    headers: { ...headers(), "content-type": "application/json" },
    body: JSON.stringify({
      system_id: systemId,
      objective: "Coordinate one bounded outcome",
      objective_ref: "goal://gr_123",
      mode: "permissioned_team",
      governance,
    }),
  });
  assert.equal(composed.status, 201);
  const composedBody = (await composed.json()) as {
    orchestration: Record<string, unknown>;
    head: string;
    thread_id: string;
    admission: Record<string, unknown>;
    replayed: boolean;
  };
  const [threadCall, admitCall] = calls.slice(-2);
  assert.deepEqual([threadCall?.method, threadCall?.path], ["POST", "/v1/threads"]);
  assert.equal(threadCall?.body.goal, "Coordinate one bounded outcome");
  assert.deepEqual([admitCall?.method, admitCall?.path], ["POST", seamRoot]);
  const tail = String(admitCall?.body.object_id).slice("orchestration://".length);
  assert.match(tail, /^orc_[0-9a-f]{24}$/u);
  assert.deepEqual(
    {
      owner_ref: admitCall?.body.owner_ref,
      contract_id: admitCall?.body.contract_id,
      parent_scope_ref: admitCall?.body.parent_scope_ref,
      expected_head: admitCall?.body.expected_head,
    },
    {
      owner_ref: "org://local",
      contract_id: "schema://ioi/applications/ioi-ai/orchestration/v1",
      parent_scope_ref: `app-scope://ioi-ai/orchestration/${tail}`,
      expected_head: null,
    },
  );
  const record = admitCall?.body.record as Record<string, unknown>;
  assert.equal("system_binding" in record, false);
  assert.deepEqual(
    {
      orchestration_id: record.orchestration_id,
      orchestration_ref: record.orchestration_ref,
      owner_ref: record.owner_ref,
      composed_by_ref: record.composed_by_ref,
      thread_ref: record.thread_ref,
      objective_ref: record.objective_ref,
      mode: record.mode,
      coordination_topology: record.coordination_topology,
      member_goal_run_refs: record.member_goal_run_refs,
      status: record.status,
      settlement_policy_ref: record.settlement_policy_ref,
      constraint_refs: record.constraint_refs,
      stop_policy_ref: record.stop_policy_ref,
    },
    {
      orchestration_id: `orchestration://${tail}`,
      orchestration_ref: `app-scope://ioi-ai/orchestration/${tail}`,
      owner_ref: "org://local",
      composed_by_ref: "user://alice",
      thread_ref: "thread://thread_stub_1",
      objective_ref: "goal://gr_123",
      mode: "permissioned_team",
      coordination_topology: "hosted_admission",
      member_goal_run_refs: [],
      status: "open",
      settlement_policy_ref: null,
      constraint_refs: [],
      stop_policy_ref: "policy://estate/stop",
    },
  );
  assert.equal(composedBody.thread_id, "thread_stub_1");
  assert.equal(composedBody.replayed, false);
  assert.equal(composedBody.admission.receipt_ref, "receipt://event-stream/system-records/0");
  assert.match(composedBody.head, /^sha256:[0-9a-f]{64}$/u);

  const attach = await fetch(`${base}/api/ioi/orchestrations/${tail}/goal-runs/attach`, {
    method: "POST",
    headers: { ...headers(), "content-type": "application/json" },
    body: JSON.stringify({ system_id: systemId, goal_run_ref: "goal://gr_123", expected_head: composedBody.head }),
  });
  assert.equal(attach.status, 200);
  const attached = (await attach.json()) as {
    head: string;
    membership_transition: string;
    orchestration: { member_goal_run_refs: string[] };
  };
  assert.equal(attached.membership_transition, "attach");
  assert.deepEqual(attached.orchestration.member_goal_run_refs, ["goal://gr_123"]);
  assert.notEqual(attached.head, composedBody.head);
  assert.deepEqual(calls.slice(-2).map((call) => [call.method, call.path]), [
    ["GET", `${seamRoot}/${encodeURIComponent(systemRecordSlug("schema://ioi/applications/ioi-ai/orchestration/v1"))}/${encodeURIComponent(systemRecordSlug(`orchestration://${tail}`))}`],
    ["POST", seamRoot],
  ]);
  assert.equal(calls.at(-1)?.body.expected_head, composedBody.head);
  assert.equal("system_binding" in (calls.at(-1)?.body.record as Record<string, unknown>), false);

  const stale = await fetch(`${base}/api/ioi/orchestrations/${tail}/goal-runs/detach`, {
    method: "POST",
    headers: { ...headers(), "content-type": "application/json" },
    body: JSON.stringify({ system_id: systemId, goal_run_ref: "goal://gr_123", expected_head: composedBody.head }),
  });
  assert.equal(stale.status, 409);
  assert.equal(((await stale.json()) as { error: { code: string } }).error.code, "system_record_expected_head_conflict");

  const twice = await fetch(`${base}/api/ioi/orchestrations/${tail}/goal-runs/attach`, {
    method: "POST",
    headers: { ...headers(), "content-type": "application/json" },
    body: JSON.stringify({ system_id: systemId, goal_run_ref: "goal://gr_123", expected_head: attached.head }),
  });
  assert.equal(twice.status, 409);
  assert.equal(((await twice.json()) as { error: string }).error, "orchestration_goal_run_already_attached");

  const detach = await fetch(`${base}/api/ioi/orchestrations/${tail}/goal-runs/detach`, {
    method: "POST",
    headers: { ...headers(), "content-type": "application/json" },
    body: JSON.stringify({ system_id: systemId, goal_run_ref: "goal://gr_123", expected_head: attached.head }),
  });
  assert.equal(detach.status, 200);
  const detached = (await detach.json()) as { orchestration: { member_goal_run_refs: string[] } };
  assert.deepEqual(detached.orchestration.member_goal_run_refs, []);

  const listed = await fetch(`${base}/api/ioi/orchestrations?system_id=${encodeURIComponent(systemId)}`, { headers: headers() });
  assert.equal(listed.status, 200);
  const listBody = (await listed.json()) as { orchestrations: Array<{ revisions: number; system_id: string }> };
  assert.deepEqual(
    listBody.orchestrations.map((entry) => [entry.system_id, entry.revisions]),
    [[systemId, 3]],
  );

  const replay = await fetch(`${base}/api/ioi/orchestrations/${tail}/replay?system_id=${encodeURIComponent(systemId)}`, { headers: headers() });
  assert.equal(replay.status, 200);
  const replayBody = (await replay.json()) as { revisions: unknown[]; admissions: unknown[] };
  assert.equal(replayBody.revisions.length, 3);
  assert.equal(replayBody.admissions.length, 3);

  const graph = await fetch(`${base}/api/ioi/orchestrations/${tail}/graph?system_id=${encodeURIComponent(systemId)}`, { headers: headers() });
  assert.equal(graph.status, 200);
  const graphBody = (await graph.json()) as { graph: { root: string; nodes: Array<{ kind: string }> } };
  assert.equal(graphBody.graph.root, "thread:thread_stub_1");
  assert.deepEqual(
    graphBody.graph.nodes.map((node) => node.kind).sort(),
    ["record", "system", "thread"],
  );
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
