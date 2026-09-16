// R-172 S2 — an orchestration is COMPOSED from the daemon's thread orchestration primitives and the
// system-record seam; the SDK holds no coordination object of its own. These tests pin (1) the pure
// derivations against the S1 gate's independently written oracle, (2) the graph projection's
// determinism and provenance, and (3) that the composer drives exactly the primitives' routes with
// exactly the bodies the daemon's handlers read.
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import {
  Orchestration,
  RESERVATION_GENESIS_HEAD,
  SYSTEM_RECORD_ROUTES,
  WORK_LIFECYCLE_ROUTES,
  createRuntimeSubstrateClient,
  deriveSystemRecordIdempotencyKey,
  deriveSystemRecordPayloadRoot,
  projectOrchestrationGraph,
  reservationStreamTail,
  systemRecordResourceRef,
  systemRecordSlug,
} from "../dist/index.js";
// The S1 gate's own oracle, written before this module existed: two independent spellings of the
// seam's derivations must agree, or one of them has drifted from the daemon.
import { derivePayloadRoot as gatePayloadRoot, slug as gateSlug } from "../../../apps/hypervisor/scripts/verify-hypervisor-system-record-seam.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const fixtures = path.resolve(here, "../../../docs/architecture/_meta/schemas/fixtures");
const readFixture = (family, name) => JSON.parse(fs.readFileSync(path.join(fixtures, family, name), "utf8"));

const SYSTEM = "system://ioi/orchestration/test";
const CONTRACT = "schema://ioi/applications/ioi-ai/work-frontier-item/v3";

test("the SDK's seam derivations agree with the S1 gate's independent oracle", () => {
  for (const ref of [CONTRACT, "frontier://a/b c/1", "work-claim://x/y?z=1", SYSTEM]) {
    assert.equal(systemRecordSlug(ref), gateSlug(ref), ref);
  }
  assert.equal(systemRecordSlug("schema://ioi/x/y/v3"), "schema-ioi.x.y.v3");
  assert.equal(
    systemRecordResourceRef(SYSTEM, CONTRACT, "frontier://a/1"),
    `${SYSTEM}/schema-ioi.applications.ioi-ai.work-frontier-item.v3/frontier-a.1`,
  );
  const fixture = readFixture("work-frontier-item-v3", "positive-admitted.json");
  const { system_binding: _binding, ...record } = fixture;
  assert.equal(deriveSystemRecordPayloadRoot(record), gatePayloadRoot(record));
  assert.equal(deriveSystemRecordPayloadRoot({ ...record, system_binding: { authored: true } }), gatePayloadRoot(record), "the binding never enters its own root");
  assert.notEqual(deriveSystemRecordPayloadRoot({ ...record, objective: "edited" }), gatePayloadRoot(record));
  // Content-derived idempotency: the same record on the same head keys the same; any drift re-keys.
  const key = deriveSystemRecordIdempotencyKey(CONTRACT, "frontier://a/1", record, null);
  assert.equal(key, deriveSystemRecordIdempotencyKey(CONTRACT, "frontier://a/1", { ...record }, null));
  assert.notEqual(key, deriveSystemRecordIdempotencyKey(CONTRACT, "frontier://a/1", record, "sha256:1"));
  assert.match(key, /^record:frontier-a\.1:[0-9a-f]{24}$/u);
});

test("the reservation stream tail mirrors the daemon: outermost ancestor, canonical alphabet", () => {
  assert.equal(reservationStreamTail({ ancestor_chain: ["work-run://acme/w1/parent-1", "work-run://acme/w1", "org://acme"] }), "reservations.org---acme");
  assert.equal(reservationStreamTail({ ancestor_chain: [] }), null);
  assert.match(reservationStreamTail({ ancestor_chain: ["thread://t/1"] }), /^[A-Za-z0-9_.-]+$/u, "no character outside the substrate's tail alphabet");
});

test("the graph is projected deterministically from the primitives' records and names its provenance", () => {
  const input = {
    system_id: SYSTEM,
    scope_ref: "app-scope://ioi-ai/objective/1",
    thread: { thread_id: "thr_root", status: "active", title: "coordinate" },
    subagents: [
      { subagent_id: "sub_b", run_id: "run_b", parent_thread_id: "thr_root", role: "worker", status: "completed" },
      { subagent_id: "sub_a", run_id: "run_a", parent_thread_id: "thr_root", role: "reviewer", lifecycle_status: "running" },
    ],
    reservations: [
      { reservation: { reservation_ref: "work-reservation://x/2", dimension: "attempts", reserved_units: 1, holder_ref: "thr_root" }, stream_tail: "reservations.t", admitted_head: "sha256:2" },
      { reservation: { reservation_ref: "work-reservation://x/1", dimension: "attempts", reserved_units: 1, holder_ref: "thr_root" }, stream_tail: "reservations.t", admitted_head: "sha256:1" },
    ],
    records: [
      { resource_ref: `${SYSTEM}/c/b`, contract_id: CONTRACT, current: { system_binding: { parent_scope_ref: "app-scope://ioi-ai/objective/1", payload_root: "sha256:b" } }, head: "sha256:hb", revisions: 2 },
      { resource_ref: `${SYSTEM}/c/a`, contract_id: CONTRACT, current: null, head: "sha256:ha", revisions: 1 },
    ],
  };
  const graph = projectOrchestrationGraph(input);
  const shuffled = projectOrchestrationGraph({ ...input, subagents: [...input.subagents].reverse(), records: [...input.records].reverse(), reservations: [...input.reservations].reverse() });
  assert.deepEqual(shuffled, graph, "input order never changes the projection");
  assert.equal(graph.root, "thread:thr_root");
  assert.deepEqual(graph.nodes.map((n) => n.kind), ["system", "thread", "subagent", "subagent", "reservation", "reservation", "record", "record"]);
  assert.deepEqual(graph.nodes.map((n) => n.id).slice(2, 4), ["subagent:sub_a", "subagent:sub_b"]);
  assert.deepEqual(new Set(graph.nodes.map((n) => n.owner)), new Set(["system-genesis", "thread-kernel", "work-lifecycle-kernel", "system-record-seam"]));
  assert.equal(graph.edges.filter((e) => e.kind === "delegates").length, 2);
  assert.equal(graph.edges.filter((e) => e.kind === "reserves").length, 2);
  assert.equal(graph.edges.filter((e) => e.kind === "records").length, 2);
  assert.equal(graph.edges.filter((e) => e.kind === "scopes").length, 2);
  assert.ok(graph.edges.every((e) => graph.nodes.some((n) => n.id === e.from) && graph.nodes.some((n) => n.id === e.to)), "every edge joins two projected nodes");
  const record = graph.nodes.find((n) => n.id === `record:${SYSTEM}/c/b`);
  assert.equal(record.detail.parent_scope_ref, "app-scope://ioi-ai/objective/1");
  assert.equal(record.detail.payload_root, "sha256:b");
  assert.match(graph.nonclaim, /mints no object and grants no authority/u);
  // No application vocabulary on the platform-facing surface: the graph speaks primitives and graph words only.
  assert.doesNotMatch(JSON.stringify(Object.keys(graph)).concat(graph.nodes.map((n) => n.kind).join(",")), /\b(room|participant|lease|frontier|claim)\b/iu);
});

test("the composer drives exactly the primitives' routes with the bodies their handlers read", async () => {
  const fixture = readFixture("work-frontier-item-v3", "positive-admitted.json");
  const { system_binding: _binding, ...record } = fixture;
  const objectId = record.frontier_item_id;
  const calls = [];
  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const raw = Buffer.concat(chunks).toString("utf8");
    const body = raw ? JSON.parse(raw) : undefined;
    calls.push({ route: `${request.method} ${url.pathname}${url.search}`, body });
    let reply = { ok: true };
    if (url.pathname === "/v1/threads" && request.method === "POST") reply = { thread_id: "thr_root", status: "active", title: body?.goal ?? "" };
    else if (url.pathname === "/v1/threads/thr_root" && request.method === "GET") reply = { thread_id: "thr_root", status: "active", title: "coordinate" };
    else if (url.pathname === "/v1/threads/thr_root/subagents" && request.method === "POST") reply = { subagent_id: `sub_${calls.length}`, run_id: `run_${calls.length}`, parent_thread_id: "thr_root", role: body?.role ?? "worker", status: "completed" };
    else if (url.pathname === "/v1/threads/thr_root/subagents" && request.method === "GET") reply = { object: "ioi.runtime_subagent_list", count: 1, subagents: [{ subagent_id: "sub_3", run_id: "run_3", parent_thread_id: "thr_root", role: "worker", status: "completed" }] };
    else if (url.pathname === WORK_LIFECYCLE_ROUTES.reservations) reply = { reservation: body.reservation, stream_tail: reservationStreamTail(body.reservation), admitted_head: `sha256:${"a".repeat(63)}${calls.length}` };
    else if (url.pathname.endsWith("/records") && request.method === "POST") reply = { ok: true, replayed: false, system_id: SYSTEM, contract_id: body.contract_id, resource_ref: systemRecordResourceRef(SYSTEM, body.contract_id, body.object_id), record: { ...body.record, system_binding: { system_id: SYSTEM, parent_scope_ref: body.parent_scope_ref, payload_root: deriveSystemRecordPayloadRoot(body.record) } }, admission: { idempotency_key: body.idempotency_key }, expected_head_for_successor: `sha256:${"b".repeat(63)}${calls.length}` };
    else if (url.pathname.endsWith("/records") && request.method === "GET") reply = { ok: true, system_id: SYSTEM, records: [{ resource_ref: `${SYSTEM}/c/a`, contract_id: CONTRACT, current: null, head: "sha256:ha", revisions: 1 }], count: 1 };
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify(reply));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const client = createRuntimeSubstrateClient({ endpoint: `http://127.0.0.1:${server.address().port}` });
    const orchestration = await Orchestration.compose(client, {
      system_id: SYSTEM,
      owner_ref: "org://acme",
      scope_ref: "app-scope://ioi-ai/objective/1",
      objective: "coordinate the objective",
      thread: { runtime_profile: "default" },
    });
    assert.equal(orchestration.thread_id, "thr_root");
    assert.deepEqual(orchestration.handle(), { system_id: SYSTEM, owner_ref: "org://acme", scope_ref: "app-scope://ioi-ai/objective/1", thread_id: "thr_root" });

    const delegated = await orchestration.delegate({ prompt: "review the plan", role: "reviewer" });
    assert.equal(delegated.parent_thread_id, "thr_root");

    const chain = ["thread://thr_root", "org://acme"];
    const bounds = [{ ancestor_ref: "thread://thr_root", bound_units: 4 }, { ancestor_ref: "org://acme", bound_units: 8 }];
    assert.equal(orchestration.reservationHead(chain), RESERVATION_GENESIS_HEAD, "a first claim names genesis");
    const first = await orchestration.reserve({ reservation_ref: "work-reservation://acme/thr_root/attempts/1", work_ref: "work-run://acme/thr_root/1", holder_ref: "thread://thr_root", dimension: "attempts", reserved_units: 1, ancestor_chain: chain, ancestor_bounds: bounds, expires_at_ms: 2_000_000_000_000 });
    assert.equal(orchestration.reservationHead(chain), first.admitted_head, "the successor names the admitted head");
    const second = await orchestration.reserve({ reservation_ref: "work-reservation://acme/thr_root/attempts/2", work_ref: "work-run://acme/thr_root/2", holder_ref: "thread://thr_root", dimension: "attempts", reserved_units: 1, ancestor_chain: chain, ancestor_bounds: bounds, expires_at_ms: 2_000_000_000_000 });
    assert.notEqual(second.admitted_head, first.admitted_head);
    assert.equal(orchestration.reservations().length, 2);

    const admitted = await orchestration.record({ contract_id: CONTRACT, object_id: objectId, record });
    assert.equal(admitted.record.system_binding.parent_scope_ref, "app-scope://ioi-ai/objective/1", "parent scope defaults to the composition's own scope");
    const revised = await orchestration.record({ contract_id: CONTRACT, object_id: objectId, record: { ...record, objective: "revised" } });
    assert.equal(calls.at(-1).body.expected_head, admitted.expected_head_for_successor, "the successor names the head the seam handed back");
    await orchestration.recordChain(CONTRACT, objectId);
    const graph = await orchestration.graph();
    assert.equal(graph.root, "thread:thr_root");
    assert.equal(graph.nodes.filter((n) => n.kind === "reservation").length, 2);
    assert.equal(graph.nodes.filter((n) => n.kind === "subagent").length, 1);
    assert.equal(graph.nodes.filter((n) => n.kind === "record").length, 1);
    assert.notEqual(revised.expected_head_for_successor, admitted.expected_head_for_successor);

    const reopened = Orchestration.open(client, orchestration.handle());
    assert.equal(reopened.reservationHead(chain), RESERVATION_GENESIS_HEAD, "a re-attached composer remembers nothing: heads come from the daemon's replies");
  } finally {
    server.close();
  }

  const routes = calls.map((c) => c.route);
  assert.deepEqual(routes.slice(0, 2), ["POST /v1/threads", "POST /v1/threads/thr_root/subagents"]);
  assert.equal(calls[0].body.goal, "coordinate the objective");
  assert.equal(calls[0].body.runtime_profile, "default");
  assert.equal(calls[1].body.prompt, "review the plan");
  assert.equal(calls[1].body.role, "reviewer");
  assert.equal(routes[2], `POST ${WORK_LIFECYCLE_ROUTES.reservations}`);
  assert.equal(calls[2].body.reservation.expected_ancestor_head, RESERVATION_GENESIS_HEAD);
  assert.equal(calls[2].body.reservation.status, "active");
  assert.equal(calls[2].body.reservation.transferred_to_ref, null);
  assert.deepEqual(calls[2].body.ancestor_bounds, [{ ancestor_ref: "thread://thr_root", bound_units: 4 }, { ancestor_ref: "org://acme", bound_units: 8 }]);
  assert.match(calls[3].body.reservation.expected_ancestor_head, /^sha256:a{63}3$/u);
  assert.equal(routes[4], `POST ${SYSTEM_RECORD_ROUTES.admit(SYSTEM)}`);
  assert.deepEqual(Object.keys(calls[4].body).sort(), ["contract_id", "expected_head", "idempotency_key", "object_id", "owner_ref", "parent_scope_ref", "record"], "exactly the seam's request fields, nothing authored");
  assert.equal(calls[4].body.expected_head, null);
  assert.equal(calls[4].body.owner_ref, "org://acme");
  assert.match(calls[4].body.idempotency_key, /^record:/u);
  assert.equal(routes[6], `GET ${SYSTEM_RECORD_ROUTES.get(SYSTEM, CONTRACT, objectId)}`);
  assert.ok(routes.slice(7).includes("GET /v1/threads/thr_root") && routes.slice(7).includes("GET /v1/threads/thr_root/subagents") && routes.slice(7).includes(`GET ${SYSTEM_RECORD_ROUTES.list(SYSTEM)}`), routes.join("\n"));
});
