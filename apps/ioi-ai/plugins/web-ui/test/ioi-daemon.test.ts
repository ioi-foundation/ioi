import { test } from "node:test";
import assert from "node:assert/strict";
import type { IncomingMessage } from "node:http";
import { boundedIoiId, createIoiDaemonGateway } from "../server/ioi-daemon.ts";

function request(headers: IncomingMessage["headers"]): IncomingMessage {
  return { headers } as IncomingMessage;
}

test("the gateway proves the daemon principal before forwarding only daemon identity material", async () => {
  const calls: Array<{ url: string; init: RequestInit | undefined }> = [];
  const gateway = createIoiDaemonGateway(
    "http://127.0.0.1:8765/",
    async (url, init) => {
      calls.push({ url: String(url), init });
      if (String(url).endsWith("/v1/hypervisor/auth/whoami")) {
        return new Response(JSON.stringify({ authenticated: true, principal: { principal_id: "alice" } }), {
          status: 200,
        });
      }
      return new Response(JSON.stringify({ ok: false, error: { code: "typed_refusal" } }), { status: 422 });
    },
    { timeoutMs: 500 },
  );
  const response = await gateway.request(
    request({
      host: "localhost:8096",
      cookie: "webuiuser=alice; ioi_session=daemon-secret; unrelated=drop-me",
      authorization: "Bearer daemon-bearer",
    }),
    "alice",
    "POST",
    "/v1/goal-orchestration/goal-runs/gr_1/start",
    "{}",
  );
  assert.equal(calls.length, 2);
  assert.equal(calls[0]?.url, "http://127.0.0.1:8765/v1/hypervisor/auth/whoami");
  assert.equal(calls[1]?.url, "http://127.0.0.1:8765/v1/goal-orchestration/goal-runs/gr_1/start");
  assert.equal(calls[1]?.init?.method, "POST");
  assert.equal((calls[1]?.init?.headers as Record<string, string>).cookie, "ioi_session=daemon-secret");
  assert.equal((calls[1]?.init?.headers as Record<string, string>).authorization, "Bearer daemon-bearer");
  assert.equal((calls[1]?.init?.headers as Record<string, string>)["x-ioi-forwarded"], "ioi-ai");
  assert.equal(response.status, 422);
  assert.match(response.text, /typed_refusal/);
});

test("a mismatched daemon principal fails closed before the requested route", async () => {
  const calls: string[] = [];
  const gateway = createIoiDaemonGateway("http://127.0.0.1:8765", async (url) => {
    calls.push(String(url));
    return new Response(JSON.stringify({ authenticated: true, principal: { principal_id: "mallory" } }), {
      status: 200,
    });
  });
  const response = await gateway.request(
    request({ cookie: "ioi_session=mallory" }),
    "alice",
    "GET",
    "/v1/goal-orchestration/goal-runs",
  );
  assert.equal(response.status, 403);
  assert.match(response.text, /ioi_daemon_principal_mismatch/);
  assert.deepEqual(calls, ["http://127.0.0.1:8765/v1/hypervisor/auth/whoami"]);
});

test("the gateway preserves an unauthenticated whoami refusal without reaching the requested route", async () => {
  let calls = 0;
  const gateway = createIoiDaemonGateway("http://127.0.0.1:8765", async () => {
    calls++;
    return new Response(JSON.stringify({ reason: "authentication_required" }), { status: 401 });
  });
  const response = await gateway.request(request({}), "alice", "GET", "/v1/goal-orchestration/goal-runs");
  assert.equal(response.status, 401);
  assert.equal(calls, 1);
});

test("the gateway never lets a caller-controlled Host header inherit daemon loopback trust", async () => {
  const observed: Record<string, string>[] = [];
  const gateway = createIoiDaemonGateway("http://127.0.0.1:8765", async (url, init) => {
    observed.push(init?.headers as Record<string, string>);
    if (String(url).endsWith("/whoami")) {
      return new Response(JSON.stringify({ authenticated: true, principal: { principal_id: "alice" } }), {
        status: 200,
      });
    }
    return new Response("{}", { status: 200 });
  });
  await gateway.request(request({ host: "localhost:8096" }), "alice", "GET", "/v1/goal-orchestration/goal-runs");
  assert.ok(observed.every((headers) => headers["x-ioi-forwarded"] === "ioi-ai"));
});

test("an explicit development seam retains loopback trust only for the same local principal", async () => {
  const observed: Record<string, string>[] = [];
  const gateway = createIoiDaemonGateway(
    "http://127.0.0.1:8765",
    async (url, init) => {
      observed.push(init?.headers as Record<string, string>);
      if (String(url).endsWith("/whoami")) {
        return new Response(JSON.stringify({ authenticated: false, principal: { principal_id: "local-operator" } }), {
          status: 200,
        });
      }
      return new Response("{}", { status: 200 });
    },
    { timeoutMs: 500, allowLoopbackTrust: true },
  );
  const accepted = await gateway.request(
    request({ host: "untrusted.example" }),
    "local-operator",
    "GET",
    "/v1/goal-orchestration/goal-runs",
  );
  assert.equal(accepted.status, 200);
  assert.ok(observed.every((headers) => headers["x-ioi-forwarded"] === undefined));
  const refused = await gateway.request(
    request({ host: "untrusted.example" }),
    "alice",
    "GET",
    "/v1/goal-orchestration/goal-runs",
  );
  assert.equal(refused.status, 403);
});

test("daemon credentials cannot cross plaintext non-loopback transport without an explicit development option", () => {
  assert.throws(() => createIoiDaemonGateway("http://daemon.example"), /must use HTTPS/);
  assert.doesNotThrow(() =>
    createIoiDaemonGateway("http://daemon.example", async () => new Response("{}"), {
      allowInsecureRemoteHttp: true,
    }),
  );
  assert.doesNotThrow(() => createIoiDaemonGateway("https://daemon.example"));
});

test("bounded route identifiers reject cross-family, slash, and overlong values", () => {
  assert.equal(boundedIoiId("gr_123", "gr_"), "gr_123");
  assert.equal(boundedIoiId("or_123", "gr_"), null);
  assert.equal(boundedIoiId("gr_bad%2Fpath", "gr_"), null);
  assert.equal(boundedIoiId(`gr_${"x".repeat(200)}`, "gr_"), null);
});
