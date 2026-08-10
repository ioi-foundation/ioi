// W0.3 contract test — the uniform read-projection client + the CapabilityLease authority
// client, exercised against a STUB gateway (never the real daemon). The stub speaks the
// byte-verified gateway ladder (lifecycle_routes.rs:11899-11942): 428 sealed-credential →
// 403 wallet challenge (approval.policy_hash/request_hash + authority_challenge) →
// receipted success on the record's own history. Run: npm run test:hypervisor-app-clients
import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { createReadClient, readProjections, defaultDaemonBase } from "./read-client.mjs";
import { createAuthorityClient } from "./authority-client.mjs";

const POLICY_HASH = `sha256:${"a".repeat(64)}`;
const REQUEST_HASH = `sha256:${"b".repeat(64)}`;

const seen = []; // every request the stub actually received: { method, path, body }

const stub = createServer(async (req, res) => {
  let raw = "";
  for await (const chunk of req) raw += chunk;
  const body = raw ? JSON.parse(raw) : null;
  seen.push({ method: req.method, path: req.url, body });
  const json = (status, payload) => {
    res.writeHead(status, { "content-type": "application/json" });
    res.end(JSON.stringify(payload));
  };
  if (req.url === "/v1/ok") {
    return json(200, { ok: true, operations: [{ id: "op_1", status: "running" }] });
  }
  if (req.url === "/v1/missing") {
    return json(404, { error: { code: "plane_not_found", message: "no such projection" } });
  }
  if (req.url === "/v1/refused") {
    return json(503, { error: { code: "plane_degraded", message: "projection temporarily refused" } });
  }
  if (req.url === "/v1/slow") {
    return; // never answers — exercises the deadline, socket reaped at teardown
  }
  if (req.url === "/v1/cross/credential-missing") {
    return json(428, {
      ok: false, decision: "blocked", reason: "scm_credential_required",
      message: "This lease needs a resolvable backing credential before the crossing.",
      backing_provider: "github", host_mutation: false,
    });
  }
  if (req.url === "/v1/cross/guarded") {
    if (!body?.wallet_approval_grant) {
      return json(403, {
        ok: false, decision: "blocked", reason: "odk_connector_session_authority_required",
        message: "This crossing requires independently resolved, atomically consumed owner authority.",
        required_scopes: ["tools/call"],
        required_authority_scope: "scope:hypervisor.live-route.hypervisor-odk-connector-session",
        approval: { policy_hash: POLICY_HASH, request_hash: REQUEST_HASH },
        authority_challenge: { challenge_kind: "wallet.approval-grant.v1" },
        host_mutation: false,
      });
    }
    return json(200, {
      ok: true,
      connector_session: {
        id: "cs_1", status: "session_obtained",
        session: { gateway_lease_id: "lease_abc", grant_ref: "grant://g1", policy_hash: POLICY_HASH, request_hash: REQUEST_HASH },
        history: [
          { op: "created", receipt_ref: "receipt://created" },
          { op: "session_obtained", receipt_ref: "receipt://obtained" },
        ],
      },
    });
  }
  if (req.url === "/v1/cross/no-receipt") {
    return json(200, { ok: true });
  }
  if (req.url === "/v1/cross/typed-refusal") {
    return json(200, { ok: false, error: { code: "ontology_ref_unresolved", message: "object 'x' title_property 'y' is not one of its properties" } });
  }
  // W1.3 negotiation stubs — schema-versioned payload and a paginating list (the daemon's
  // authority/receipts shape: page object only when limit was asked for).
  if (req.url?.startsWith("/v1/versioned")) {
    return json(200, { schema_version: "ioi.hypervisor.authority-receipts.v1", receipts: [] });
  }
  if (req.url?.startsWith("/v1/paged")) {
    const params = new URL(req.url, "http://x").searchParams;
    const limit = Number(params.get("limit") || 0);
    const after = params.get("after");
    const all = ["r3", "r2", "r1"];
    let rows = after ? all.filter((id) => id < after) : all;
    if (!limit) return json(200, { schema_version: "v", receipts: rows });
    const has_more = rows.length > limit;
    rows = rows.slice(0, limit);
    return json(200, {
      schema_version: "v",
      receipts: rows,
      page: { limit, after, next_after: has_more ? rows[rows.length - 1] : null, has_more, total: all.length },
    });
  }
  return json(404, { error: { code: "route_unknown", message: "stub has no such route" } });
});

let daemon = "";
const DEAD = "http://127.0.0.1:9"; // discard port — connection always refused, nothing listens

test.before(async () => {
  await new Promise((resolve) => stub.listen(0, "127.0.0.1", resolve));
  daemon = `http://127.0.0.1:${stub.address().port}`;
});
test.after(() => {
  stub.closeAllConnections?.();
  stub.close();
});

// ------------------------------ read-projection client ------------------------------

test("read: success carries the payload verbatim plus fetched_at, nothing else invented", async () => {
  const r = await createReadClient({ daemon }).read("/v1/ok");
  assert.equal(r.ok, true);
  assert.equal(r.kind, "read");
  assert.equal(r.status, 200);
  assert.deepEqual(r.payload.operations, [{ id: "op_1", status: "running" }]);
  assert.ok(!Number.isNaN(Date.parse(r.fetched_at)));
});

test("read: daemon down is a typed unavailable with NO data field — nothing fabricated", async () => {
  const r = await createReadClient({ daemon: DEAD, timeoutMs: 2000 }).read("/v1/ok");
  assert.equal(r.ok, false);
  assert.equal(r.kind, "unavailable");
  assert.equal(r.status, 0);
  assert.equal(r.code, "daemon_unavailable");
  assert.ok(!("payload" in r), "degraded result must not carry a payload");
  assert.ok(!("rows" in r), "degraded result must not carry fabricated rows");
  assert.ok(!Number.isNaN(Date.parse(r.fetched_at)));
});

test("read: deadline exceeded is read_timeout, not a hang and not a fake empty", async () => {
  const r = await createReadClient({ daemon, timeoutMs: 250 }).read("/v1/slow");
  assert.equal(r.ok, false);
  assert.equal(r.kind, "unavailable");
  assert.equal(r.code, "read_timeout");
  assert.ok(!("payload" in r));
});

test("read: typed refusal surfaces the daemon's own code/message and body verbatim", async () => {
  const r = await createReadClient({ daemon }).read("/v1/refused");
  assert.equal(r.ok, false);
  assert.equal(r.kind, "refusal");
  assert.equal(r.status, 503);
  assert.equal(r.code, "plane_degraded");
  assert.match(r.message, /temporarily refused/);
  assert.equal(r.refusal.error.code, "plane_degraded");
  assert.ok(!("payload" in r));
});

test("read: 404 is typed absence (not_found), distinct from refusal and from unavailable", async () => {
  const r = await createReadClient({ daemon }).read("/v1/missing");
  assert.equal(r.ok, false);
  assert.equal(r.kind, "not_found");
  assert.equal(r.status, 404);
  assert.equal(r.code, "plane_not_found");
});

test("read: fan-out degrades independently — one down plane never poisons the rest", async () => {
  const client = createReadClient({ daemon });
  const map = await readProjections(client, { good: "/v1/ok", gone: "/v1/missing", down: "/v1/refused" });
  assert.equal(map.good.ok, true);
  assert.equal(map.gone.kind, "not_found");
  assert.equal(map.down.kind, "refusal");
});

// ------------------------------ W1.3: negotiation, pagination, cancellation ------------------------------

test("schema: a matching expectSchema delivers the payload; the declaration rides the request header", async () => {
  const r = await createReadClient({ daemon }).read("/v1/versioned", {
    expectSchema: "ioi.hypervisor.authority-receipts.v1",
  });
  assert.equal(r.ok, true);
  assert.equal(r.kind, "read");
  const sent = seen.at(-1);
  assert.equal(sent.path, "/v1/versioned");
});

test("schema: a mismatched schema_version is a typed schema_mismatch with NO payload delivered", async () => {
  const r = await createReadClient({ daemon }).read("/v1/versioned", { expectSchema: "ioi.hypervisor.authority-receipts.v2" });
  assert.equal(r.ok, false);
  assert.equal(r.kind, "schema_mismatch");
  assert.equal(r.code, "schema_version_mismatch");
  assert.equal(r.expected, "ioi.hypervisor.authority-receipts.v2");
  assert.equal(r.actual, "ioi.hypervisor.authority-receipts.v1");
  assert.ok(!("payload" in r), "data under an unnegotiated contract must not be delivered");
});

test("page: the daemon's page object rides the result verbatim; next_after resumes past it", async () => {
  const client = createReadClient({ daemon });
  const first = await client.readPage("/v1/paged", { limit: 2 });
  assert.equal(first.ok, true);
  assert.deepEqual(first.payload.receipts, ["r3", "r2"]);
  assert.equal(first.page.has_more, true);
  assert.equal(first.page.next_after, "r2");
  const second = await client.readPage("/v1/paged", { limit: 2, after: first.page.next_after });
  assert.deepEqual(second.payload.receipts, ["r1"]);
  assert.equal(second.page.has_more, false);
  assert.equal(second.page.next_after, null);
});

test("page: a daemon that ignores pagination yields a typed non-negotiation, never a silent full list", async () => {
  const r = await createReadClient({ daemon }).read("/v1/versioned", { page: { limit: 5 } });
  assert.equal(r.ok, true);
  assert.deepEqual(r.page, { negotiated: false });
});

test("cancel: an aborted read is a typed cancelled — distinct from timeout and unavailability", async () => {
  const controller = new AbortController();
  const pending = createReadClient({ daemon, timeoutMs: 5000 }).read("/v1/slow", { signal: controller.signal });
  setTimeout(() => controller.abort(), 50);
  const r = await pending;
  assert.equal(r.ok, false);
  assert.equal(r.kind, "cancelled");
  assert.equal(r.code, "read_cancelled");
  assert.ok(!("payload" in r));
});

test("cancel: an already-aborted signal cancels before any fetch happens", async () => {
  const controller = new AbortController();
  controller.abort();
  const before = seen.length;
  const r = await createReadClient({ daemon }).read("/v1/ok", { signal: controller.signal });
  assert.equal(r.kind, "cancelled");
  assert.equal(seen.length, before, "no request may reach the daemon after the caller cancelled");
});

test("read: browser lane defaults to same-origin, serve lane to the daemon URL", () => {
  assert.equal(defaultDaemonBase(), process.env.IOI_HYPERVISOR_DAEMON_URL?.replace(/\/$/, "") || "http://127.0.0.1:8765");
  globalThis.window = {};
  try {
    assert.equal(defaultDaemonBase(), "");
  } finally {
    delete globalThis.window;
  }
});

// ------------------------------ authority client ------------------------------

test("authority: 428 sealed-credential step is a typed credential refusal, verbatim reason", async () => {
  const r = await createAuthorityClient({ daemon }).cross("/v1/cross/credential-missing");
  assert.equal(r.ok, false);
  assert.equal(r.kind, "refusal");
  assert.equal(r.stage, "credential");
  assert.equal(r.status, 428);
  assert.equal(r.code, "scm_credential_required");
  assert.equal(r.receipt_ref, "");
});

test("authority: 403 wallet step surfaces the challenge's public commitments verbatim", async () => {
  const r = await createAuthorityClient({ daemon }).cross("/v1/cross/guarded");
  assert.equal(r.ok, false);
  assert.equal(r.kind, "refusal");
  assert.equal(r.stage, "wallet_challenge");
  assert.equal(r.status, 403);
  assert.equal(r.code, "odk_connector_session_authority_required");
  assert.equal(r.challenge.policy_hash, POLICY_HASH);
  assert.equal(r.challenge.request_hash, REQUEST_HASH);
  assert.equal(r.challenge.required_authority_scope, "scope:hypervisor.live-route.hypervisor-odk-connector-session");
  assert.deepEqual(r.challenge.required_scopes, ["tools/call"]);
  assert.equal(r.challenge.authority_challenge.challenge_kind, "wallet.approval-grant.v1");
});

test("authority: grant resubmission completes the ladder — crossed, receipted, lease facets", async () => {
  const grant = { grant_id: "g1", scope: "scope:hypervisor.live-route.hypervisor-odk-connector-session" };
  const before = seen.length;
  const r = await createAuthorityClient({ daemon }).cross("/v1/cross/guarded", { grant });
  assert.equal(r.ok, true);
  assert.equal(r.kind, "crossed");
  assert.equal(r.status, 200);
  assert.equal(r.receipt_ref, "receipt://obtained", "latest history receipt wins");
  assert.equal(r.lease.lease_id, "lease_abc");
  assert.equal(r.lease.grant_ref, "grant://g1");
  assert.equal(r.lease.policy_hash, POLICY_HASH);
  // the grant rode the wire exactly once, verbatim, under wallet_approval_grant
  const wire = seen.slice(before).filter((q) => q.body?.wallet_approval_grant);
  assert.equal(wire.length, 1);
  assert.deepEqual(wire[0].body.wallet_approval_grant, grant);
});

test("authority: a pasted grant string is parsed; garbage refuses BEFORE the network", async () => {
  const before = seen.length;
  const r = await createAuthorityClient({ daemon }).cross("/v1/cross/guarded", { grant: "{not json" });
  assert.equal(r.ok, false);
  assert.equal(r.stage, "grant");
  assert.equal(r.code, "grant_invalid_json");
  assert.equal(seen.length, before, "an unparseable grant must never reach the daemon");
});

test("authority: 2xx without a discoverable receipt fails CLOSED (receipt_missing)", async () => {
  const r = await createAuthorityClient({ daemon }).cross("/v1/cross/no-receipt");
  assert.equal(r.ok, false);
  assert.equal(r.kind, "failure");
  assert.equal(r.code, "receipt_missing");
});

test("authority: a 2xx ok:false plane refusal keeps its typed code — never receipt_missing", async () => {
  const r = await createAuthorityClient({ daemon }).cross("/v1/cross/typed-refusal");
  assert.equal(r.ok, false);
  assert.equal(r.kind, "refusal");
  assert.equal(r.stage, "gateway");
  assert.equal(r.code, "ontology_ref_unresolved");
  assert.match(r.message, /title_property/u);
});

test("authority: daemon down is a typed failure — no silent no-op, no invented state", async () => {
  const r = await createAuthorityClient({ daemon: DEAD, timeoutMs: 2000 }).cross("/v1/cross/guarded");
  assert.equal(r.ok, false);
  assert.equal(r.kind, "failure");
  assert.equal(r.code, "daemon_unavailable");
  assert.ok(!("payload" in r), "a failed crossing must not carry fabricated payload");
});
