// W0.4 contract test — the M5-plane event client + the legacy SSE wrap, exercised
// against a STUB of the daemon's subscription plane (never the real daemon). The stub
// speaks the byte-verified contract (event_stream_routes.rs; registrations
// hypervisor-daemon.rs:2350-2381): POST /v1/subscriptions → lease view · GET lease ·
// GET /delivery from the durable checkpoint (window-bounded, typed outcome) ·
// POST /checkpoint (forward-only, admitted seqs only) · typed {error:{code,message}}
// refusals. Run: npm run test:hypervisor-app-events
import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { subscribeDurable, wrapLegacySse, createEventClient } from "./event-client.mjs";

const NS = "automation-scheduler"; // the owner namespace the M5 contract already fixtures
const STREAM = "aut_3d81ff40";

// In-memory plane state, reset per scenario via freshStream/freshLease helpers.
const streams = new Map(); // "ns/tail" -> [{ seq, head_ref, payload:{class_id,payload_schema_ref,payload} }]
const leases = new Map(); // "ns/leaseTail" -> { lease_state, acknowledged_seq, window, stream_tail, owner_namespace }
const seen = []; // every request the stub actually received: { method, path, body }
let failDelivery = false; // when true the delivery route hangs up mid-request

const admit = (streamTail, seq, class_id, payload) => {
  const key = `${NS}/${streamTail}`;
  if (!streams.has(key)) streams.set(key, []);
  streams.get(key).push({
    seq,
    head_ref: `head_${seq}`,
    payload: { class_id, payload_schema_ref: `schema://ioi/test/${class_id}/v1`, payload },
  });
};

const leaseView = (leaseTail, lease) => ({
  schema_version: "projection-subscription-lease.v1",
  lease_id: `subscription-lease://${leaseTail}`,
  stream_id: `event-stream://${lease.owner_namespace}/${lease.stream_tail}`,
  lease_state: lease.lease_state,
  acknowledged_checkpoint: lease.acknowledged_seq == null
    ? null
    : { acknowledged_seq: lease.acknowledged_seq, acknowledged_head_ref: `head_${lease.acknowledged_seq}` },
  backpressure: { max_undelivered_events: lease.window, lag_outcome: "bounded_by_backpressure_window" },
  delivery_adapter_kind: "pull",
});

const stub = createServer(async (req, res) => {
  let raw = "";
  for await (const chunk of req) raw += chunk;
  const body = raw ? JSON.parse(raw) : null;
  seen.push({ method: req.method, path: req.url, body });
  const json = (status, payload) => {
    res.writeHead(status, { "content-type": "application/json" });
    res.end(JSON.stringify(payload));
  };
  const refuse = (status, code, message) => json(status, { error: { code, message } });

  // ---- legacy per-resource SSE lanes ----
  if (req.url === "/__legacy/conversation/live") {
    res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache" });
    res.write(":\n\n"); // keepalive comment — must never dispatch as an event
    res.write(`event: state\ndata: ${JSON.stringify({ chunk_id: "c1", todo_groups: [] })}\n\n`);
    res.write(`event: block\ndata: ${JSON.stringify({ frame: "frame-1" })}\n\n`);
    return; // held open like the serve layer's lane; the wrap's stop() closes it
  }
  if (req.url === "/__legacy/ends-after-one") {
    res.writeHead(200, { "content-type": "text/event-stream" });
    res.write(`event: block\ndata: ${JSON.stringify({ frame: "only" })}\n\n`);
    res.end(); // EOF — the wrap must reconnect VISIBLY, never silently
    return;
  }
  if (req.url === "/__legacy/refused") {
    return refuse(403, "run_cache_refused", "local run cache admission refused");
  }

  // ---- the durable subscription plane ----
  if (req.url === "/v1/subscriptions" && req.method === "POST") {
    for (const field of ["owner_namespace", "stream_tail", "subscriber_ref", "lease_tail"]) {
      if (!body?.[field]) return refuse(400, "subscription_field_required", "owner_namespace, stream_tail, subscriber_ref, and lease_tail are required");
    }
    if (!streams.has(`${body.owner_namespace}/${body.stream_tail}`)) {
      return refuse(422, "subscription_stream_unresolved", "a lease requires an admitted stream at the named coordinates");
    }
    if (!Array.isArray(body.permitted_event_class_ids) || body.permitted_event_class_ids.length === 0) {
      return refuse(422, "subscription_scope_required", "a lease names at least one permitted event class");
    }
    if (!(body.max_undelivered_events > 0)) {
      return refuse(422, "subscription_backpressure_unbounded", "a lease declares a bounded backpressure window");
    }
    const lease = {
      owner_namespace: body.owner_namespace,
      stream_tail: body.stream_tail,
      lease_state: "active",
      acknowledged_seq: null,
      window: body.max_undelivered_events,
    };
    leases.set(`${body.owner_namespace}/${body.lease_tail}`, lease);
    return json(200, leaseView(body.lease_tail, lease));
  }
  const sub = req.url?.match(/^\/v1\/subscriptions\/([^/]+)\/([^/]+)(\/checkpoint|\/delivery|\/revoke)?$/);
  if (sub) {
    const [, ns, leaseTail, op] = sub;
    const lease = leases.get(`${ns}/${leaseTail}`);
    if (!lease) return refuse(404, "subscription_lease_not_found", "no admitted lease exists at these coordinates");
    if (!op && req.method === "GET") return json(200, leaseView(leaseTail, lease));
    if (op === "/revoke") {
      lease.lease_state = "revoked";
      return json(200, leaseView(leaseTail, lease));
    }
    if (lease.lease_state !== "active") {
      return refuse(409, "subscription_lease_revoked", "this lease is revoked; delivery under a revoked lease is unleased delivery");
    }
    const history = streams.get(`${ns}/${lease.stream_tail}`) ?? [];
    if (op === "/checkpoint") {
      const to = body?.acknowledged_seq;
      if (lease.acknowledged_seq != null && to < lease.acknowledged_seq) {
        return refuse(409, "subscription_checkpoint_would_rewind", "a checkpoint advances");
      }
      if (!history.some((e) => e.seq === to)) {
        return refuse(422, "subscription_checkpoint_not_admitted", "the acknowledged sequence is not an admitted operation on this lease's stream");
      }
      lease.acknowledged_seq = to;
      return json(200, leaseView(leaseTail, lease));
    }
    if (op === "/delivery") {
      if (failDelivery) { req.socket.destroy(); return; }
      let pending = history.filter((e) => lease.acknowledged_seq == null || e.seq > lease.acknowledged_seq);
      const total = pending.length;
      const lagged = lease.window > 0 && total > lease.window;
      if (lagged) pending = pending.slice(0, lease.window);
      return json(200, {
        lease_id: `subscription-lease://${leaseTail}`,
        delivered_from_checkpoint: lease.acknowledged_seq,
        events: pending,
        pending_total: total,
        backpressure_window: lease.window,
        delivery_outcome: lagged ? "bounded_by_backpressure_window" : "drained",
        resume_after_seq: pending.at(-1)?.seq ?? lease.acknowledged_seq,
      });
    }
  }
  return refuse(404, "route_unknown", "stub has no such route");
});

let daemon = "";
const DEAD = "http://127.0.0.1:9"; // discard port — connection always refused, nothing listens
const FAST = { pollMs: 25, backoffBaseMs: 20, backoffMaxMs: 100, timeoutMs: 2000 };

const until = async (predicate, ms = 4000) => {
  const start = Date.now();
  while (!predicate()) {
    if (Date.now() - start > ms) throw new Error("condition not reached in time");
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
};
const settle = (ms = 120) => new Promise((resolve) => setTimeout(resolve, ms));

test.before(async () => {
  await new Promise((resolve) => stub.listen(0, "127.0.0.1", resolve));
  daemon = `http://127.0.0.1:${stub.address().port}`;
});
test.after(() => {
  stub.closeAllConnections?.();
  stub.close();
});

// ------------------------------ durable plane ------------------------------

test("durable: subscribe → events in admitted order → checkpoint on the wire → resume without redelivery", async () => {
  admit(STREAM, 1, "schedule.fired", { automation: "aut_1" });
  admit(STREAM, 2, "trigger.suppressed", { automation: "aut_1" });

  const events = [];
  const checkpoints = [];
  const spec = {
    owner_namespace: NS, stream_tail: STREAM, subscriber_ref: "surface://work", lease_tail: "lease_a",
    permitted_event_class_ids: ["schedule.fired", "trigger.suppressed"], max_undelivered_events: 10,
    onEvent: (e) => events.push(e), onCheckpoint: (t) => checkpoints.push(t),
  };
  const sub = subscribeDurable({ daemon, ...FAST }, spec);
  await until(() => events.length === 2 && sub.state().state === "live");
  sub.stop();

  assert.deepEqual(events.map((e) => e.seq), [1, 2], "admitted order, exactly once");
  assert.equal(events[0].class_id, "schedule.fired");
  assert.equal(events[0].payload_schema_ref, "schema://ioi/test/schedule.fired/v1");
  assert.deepEqual(events[0].payload, { automation: "aut_1" });
  assert.equal(events[0].delivery, "admitted");
  assert.equal(events[0].head_ref, "head_1");
  assert.ok(!Number.isNaN(Date.parse(events[0].at)));
  // the acknowledgement rode the wire as the daemon's own checkpoint operation
  const acked = seen.filter((q) => q.path === `/v1/subscriptions/${NS}/lease_a/checkpoint`);
  assert.equal(acked.at(-1).body.acknowledged_seq, 2);
  assert.equal(sub.checkpoint().acknowledged_seq, 2, "checkpoint() hands back the durable token");
  assert.equal(checkpoints.at(-1).acknowledged_seq, 2, "onCheckpoint hands every advance back for persistence");
  assert.equal(sub.state().state, "stopped");

  // resume: a NEW handle on the same lease receives only what came after the checkpoint
  admit(STREAM, 3, "schedule.fired", { automation: "aut_2" });
  const resumed = [];
  const sub2 = subscribeDurable({ daemon, ...FAST }, { ...spec, onEvent: (e) => resumed.push(e), onCheckpoint: null });
  await until(() => resumed.length === 1);
  sub2.stop();
  assert.deepEqual(resumed.map((e) => e.seq), [3], "the durable checkpoint resumes; nothing is redelivered");
});

test("durable: an accepted persisted checkpoint token advances the lease before first delivery", async () => {
  admit("str_token", 1, "schedule.fired", { n: 1 });
  admit("str_token", 2, "schedule.fired", { n: 2 });
  admit("str_token", 3, "schedule.fired", { n: 3 });
  const events = [];
  const sub = subscribeDurable({ daemon, ...FAST }, {
    owner_namespace: NS, stream_tail: "str_token", subscriber_ref: "surface://work", lease_tail: "lease_token",
    permitted_event_class_ids: ["schedule.fired"], max_undelivered_events: 10,
    checkpoint: { acknowledged_seq: 2, acknowledged_head_ref: "head_2" },
    onEvent: (e) => events.push(e),
  });
  await until(() => events.length === 1);
  sub.stop();
  assert.deepEqual(events.map((e) => e.seq), [3], "delivery starts after the accepted token");
  const advances = seen.filter((q) => q.path === `/v1/subscriptions/${NS}/lease_token/checkpoint`);
  assert.equal(advances[0].body.acknowledged_seq, 2, "the token was advanced ON THE LEASE, not held client-side");
});

test("durable: a window-bounded delivery drains immediately — no event dropped, lag typed not silent", async () => {
  for (let seq = 1; seq <= 7; seq++) admit("str_lag", seq, "schedule.fired", { n: seq });
  const events = [];
  const outcomes = [];
  const sub = subscribeDurable({ daemon, ...FAST }, {
    owner_namespace: NS, stream_tail: "str_lag", subscriber_ref: "surface://work", lease_tail: "lease_lag",
    permitted_event_class_ids: ["schedule.fired"], max_undelivered_events: 3,
    onEvent: (e) => events.push(e),
    onState: (s) => { if (s.state === "live") outcomes.push(s.delivery_outcome); },
  });
  await until(() => events.length === 7);
  sub.stop();
  assert.deepEqual(events.map((e) => e.seq), [1, 2, 3, 4, 5, 6, 7], "backpressure bounds a batch, never loses the tail");
  assert.ok(outcomes.includes("bounded_by_backpressure_window"), "lag surfaced as the daemon's typed outcome");
});

test("durable: daemon down is typed daemon_unavailable with bounded visible backoff — nothing fabricated, never live", async () => {
  const events = [];
  const states = [];
  const sub = subscribeDurable({ daemon: DEAD, ...FAST }, {
    owner_namespace: NS, stream_tail: STREAM, subscriber_ref: "surface://work", lease_tail: "lease_down",
    permitted_event_class_ids: ["schedule.fired"], max_undelivered_events: 10,
    onEvent: (e) => events.push(e), onState: (s) => states.push(s),
  });
  await until(() => states.filter((s) => s.state === "daemon_unavailable").length >= 3);
  sub.stop();
  assert.equal(events.length, 0, "a down daemon must never fabricate events");
  assert.ok(!states.some((s) => s.state === "live"), "a down daemon is never presented as live");
  const down = states.filter((s) => s.state === "daemon_unavailable");
  assert.equal(down[0].code, "daemon_unavailable");
  assert.ok(down.every((s) => s.retry_in_ms <= FAST.backoffMaxMs), "backoff is bounded");
  assert.ok(down[1].attempt > down[0].attempt, "each retry is a visible, counted attempt");
  assert.ok(down[1].retry_in_ms > down[0].retry_in_ms, "backoff grows toward the bound");
});

test("durable: a typed refusal (revoked lease) is TERMINAL — verbatim code, no silent retry", async () => {
  admit("str_rev", 1, "schedule.fired", { n: 1 });
  const states = [];
  const sub = subscribeDurable({ daemon, ...FAST }, {
    owner_namespace: NS, stream_tail: "str_rev", subscriber_ref: "surface://work", lease_tail: "lease_rev",
    permitted_event_class_ids: ["schedule.fired"], max_undelivered_events: 10,
    onState: (s) => states.push(s),
  });
  await until(() => sub.state().state === "live");
  leases.get(`${NS}/lease_rev`).lease_state = "revoked"; // revoked out from under the subscriber
  await until(() => sub.state().state === "refused");
  const requestsAtRefusal = seen.length;
  await settle();
  assert.equal(seen.length, requestsAtRefusal, "a refused subscription stops asking — no silent retry loop");
  const refused = sub.state();
  assert.equal(refused.status, 409);
  assert.equal(refused.code, "subscription_lease_revoked", "the daemon's own refusal code, verbatim");
  assert.match(refused.message, /unleased delivery/);
  assert.equal(refused.refusal.error.code, "subscription_lease_revoked", "refusal body verbatim");
  sub.stop();
  assert.equal(sub.state().state, "refused", "stop() never papers over a terminal refusal");
});

test("durable: subscription create refusal (stream unresolved) surfaces the daemon's typed code", async () => {
  const sub = subscribeDurable({ daemon, ...FAST }, {
    owner_namespace: NS, stream_tail: "str_never_declared", subscriber_ref: "surface://work", lease_tail: "lease_none",
    permitted_event_class_ids: ["schedule.fired"], max_undelivered_events: 10,
  });
  await until(() => sub.state().state === "refused");
  assert.equal(sub.state().status, 422);
  assert.equal(sub.state().code, "subscription_stream_unresolved");
  sub.stop();
});

test("durable: an outage after live is never presented as live — stale is dated, resume recovers", async () => {
  admit("str_out", 1, "schedule.fired", { n: 1 });
  const events = [];
  const sub = subscribeDurable({ daemon, ...FAST }, {
    owner_namespace: NS, stream_tail: "str_out", subscriber_ref: "surface://work", lease_tail: "lease_out",
    permitted_event_class_ids: ["schedule.fired"], max_undelivered_events: 10,
    onEvent: (e) => events.push(e),
  });
  await until(() => events.length === 1 && sub.state().state === "live");
  const lastLive = sub.state().at;

  failDelivery = true; // the daemon goes away mid-subscription
  try {
    await until(() => sub.state().state === "daemon_unavailable");
    assert.equal(sub.state().last_live_at, lastLive, "staleness is dated, not hidden");
    await settle();
    assert.notEqual(sub.state().state, "live", "while down, state() never claims live");

    failDelivery = false; // the daemon returns; the durable checkpoint resumes delivery
    admit("str_out", 2, "schedule.fired", { n: 2 });
    await until(() => events.length === 2 && sub.state().state === "live");
    assert.deepEqual(events.map((e) => e.seq), [1, 2], "resume delivers exactly what followed the checkpoint");
  } finally {
    failDelivery = false;
    sub.stop();
  }
});

test("durable: revoke() retires the lease through the plane's own operation", async () => {
  admit("str_revoke_op", 1, "schedule.fired", { n: 1 });
  const sub = subscribeDurable({ daemon, ...FAST }, {
    owner_namespace: NS, stream_tail: "str_revoke_op", subscriber_ref: "surface://work", lease_tail: "lease_revoke_op",
    permitted_event_class_ids: ["schedule.fired"], max_undelivered_events: 10,
  });
  await until(() => sub.state().state === "live");
  const r = await sub.revoke();
  assert.equal(r.ok, true);
  assert.equal(r.lease_state, "revoked");
  assert.equal(leases.get(`${NS}/lease_revoke_op`).lease_state, "revoked");
});

// ------------------------------ legacy SSE wrap ------------------------------

test("legacy wrap: SAME consumer interface — event shape, typed states, handle — over per-resource SSE", async () => {
  // a durable-lane reference event to compare shapes against
  admit("str_parity", 1, "schedule.fired", { n: 1 });
  const durableEvents = [];
  const durable = subscribeDurable({ daemon, ...FAST }, {
    owner_namespace: NS, stream_tail: "str_parity", subscriber_ref: "surface://work", lease_tail: "lease_parity",
    permitted_event_class_ids: ["schedule.fired"], max_undelivered_events: 10,
    onEvent: (e) => durableEvents.push(e),
  });

  const legacyEvents = [];
  const legacyStates = [];
  const legacy = wrapLegacySse(`${daemon}/__legacy/conversation/live`, {
    onEvent: (e) => legacyEvents.push(e),
    onState: (s) => legacyStates.push(s),
  }, FAST);
  await until(() => legacyEvents.length === 2 && durableEvents.length === 1);
  durable.stop();
  legacy.stop();

  // one interface: identical event keys in both lanes
  assert.deepEqual(Object.keys(legacyEvents[0]).sort(), Object.keys(durableEvents[0]).sort(),
    "legacy and durable lanes hand consumers the same event shape");
  assert.equal(legacyEvents[0].lane, "legacy_sse");
  assert.equal(legacyEvents[0].delivery, "legacy_sse");
  assert.equal(legacyEvents[0].class_id, "state", "the SSE event name maps onto class_id");
  assert.equal(legacyEvents[0].payload.chunk_id, "c1", "data: JSON parsed for the consumer");
  assert.equal(legacyEvents[1].class_id, "block");
  assert.equal(legacyEvents[1].payload.frame, "frame-1");
  // absence stays absent: no admitted coordinates are invented for SSE
  assert.equal(legacyEvents[0].seq, null);
  assert.equal(legacyEvents[0].head_ref, null);
  assert.equal(legacyEvents[0].payload_schema_ref, null);
  assert.equal(legacy.checkpoint(), null, "SSE has no durable checkpoint and the wrap does not extend one on");
  // same typed lifecycle vocabulary, and the keepalive comment dispatched nothing
  assert.ok(legacyStates.some((s) => s.state === "live"));
  assert.equal(legacy.state().state, "stopped");
  assert.equal(legacyEvents.length, 2, "keepalive comments never dispatch as events");
});

test("legacy wrap: a typed HTTP refusal is terminal refused, verbatim — never retried forever", async () => {
  const states = [];
  const wrapped = wrapLegacySse(`${daemon}/__legacy/refused`, { onState: (s) => states.push(s) }, FAST);
  await until(() => wrapped.state().state === "refused");
  const requestsAtRefusal = seen.length;
  await settle();
  assert.equal(seen.length, requestsAtRefusal, "a refused legacy lane stops asking");
  assert.equal(wrapped.state().status, 403);
  assert.equal(wrapped.state().code, "run_cache_refused", "the endpoint's own refusal code, verbatim");
  wrapped.stop();
});

test("legacy wrap: endpoint down / EOF are typed and visible — reconnect is never a silent loop", async () => {
  const states = [];
  const down = wrapLegacySse(`${DEAD}/__legacy/conversation/live`, { onState: (s) => states.push(s) }, FAST);
  await until(() => states.filter((s) => s.state === "daemon_unavailable").length >= 2);
  down.stop();
  assert.ok(!states.some((s) => s.state === "live"), "an unreachable endpoint is never presented as live");
  assert.ok(states.every((s) => s.state !== "daemon_unavailable" || s.retry_in_ms <= FAST.backoffMaxMs));

  const eofEvents = [];
  const eofStates = [];
  const eof = wrapLegacySse(`${daemon}/__legacy/ends-after-one`, {
    onEvent: (e) => eofEvents.push(e), onState: (s) => eofStates.push(s),
  }, FAST);
  await until(() => eofEvents.length >= 2); // EOF → visible backoff → reconnected and re-delivered
  eof.stop();
  assert.ok(eofStates.some((s) => s.state === "daemon_unavailable" && s.code === "stream_ended"),
    "EOF surfaces as a typed state before any reconnect");
  assert.ok(eofStates.some((s) => s.state === "resuming"), "the reconnect itself is a visible state");
});

// ------------------------------ bound client ------------------------------

test("createEventClient mirrors the W0.3 bound-client idiom over both constructors", async () => {
  admit("str_bound", 1, "schedule.fired", { n: 1 });
  const client = createEventClient({ daemon, ...FAST });
  const events = [];
  const sub = client.subscribe({
    owner_namespace: NS, stream_tail: "str_bound", subscriber_ref: "surface://work", lease_tail: "lease_bound",
    permitted_event_class_ids: ["schedule.fired"], max_undelivered_events: 10,
    onEvent: (e) => events.push(e),
  });
  await until(() => events.length === 1);
  sub.stop();
  assert.equal(events[0].seq, 1);
  const legacy = client.wrapLegacySse(`${daemon}/__legacy/conversation/live`, {});
  assert.equal(legacy.lane, "legacy_sse");
  legacy.stop();
});
