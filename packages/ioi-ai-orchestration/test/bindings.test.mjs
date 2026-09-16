// M11.3 — bindings are replaceable transports: the envelope hash is the adapter's only fidelity check,
// an inactive or equivalence-claiming profile carries nothing, and each wire shape hands back exactly
// what a stub peer acknowledged.
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import {
  A2aBinding,
  BINDING_CONTRACT,
  HttpJsonRpcBinding,
  McpBinding,
  deriveCrossingEnvelopeHash,
  requireActiveProfile,
  selectBinding,
} from "../dist/index.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const schemas = path.resolve(here, "../../../docs/architecture/_meta/schemas");
const readJson = (rel) => JSON.parse(fs.readFileSync(path.join(schemas, rel), "utf8"));
const profiles = ["positive-a2a-transport.json", "positive-mcp-transport.json", "positive-http-json-rpc-transport.json", "positive-native-aiip.json"].map((n) => readJson(`fixtures/aiip-external-protocol-binding-envelope-v1/${n}`));

test("profiles: the registered fixtures select by kind, an inactive one is refused, and a non-native profile without non-equivalences is refused", () => {
  assert.equal(BINDING_CONTRACT, "schema://ioi/foundations/objects/aiip-external-protocol-binding-envelope/v1");
  assert.equal(selectBinding(profiles, "a2a").protocol_kind, "a2a");
  assert.equal(selectBinding(profiles, "native_aiip").assurance_non_equivalences.length, 0, "native AIIP records no non-equivalence: it is the reference");
  assert.throws(() => selectBinding(profiles, "grpc"), (e) => e.code === "binding_unavailable");
  assert.throws(() => selectBinding([{ ...profiles[0], status: "revoked" }], "a2a"), (e) => e.code === "binding_not_active");
  assert.throws(() => requireActiveProfile({ ...profiles[1], assurance_non_equivalences: [] }), (e) => e.code === "binding_claims_equivalence");
  const negative = readJson("fixtures/aiip-external-protocol-binding-envelope-v1/negative-a2a-claims-equivalence.json");
  assert.throws(() => requireActiveProfile(negative), (e) => e.code === "binding_claims_equivalence", "the registered negative fixture is refused for the registered reason");
});

test("the crossing envelope hash is over the contract id and the canonical record, independent of key order", () => {
  const envelope = { contract_id: "schema://ioi/applications/ioi-ai/orchestration-participation-request/v2", record: { b: 1, a: [2, { d: 4, c: 3 }] } };
  const shuffled = { record: { a: [2, { c: 3, d: 4 }], b: 1 }, contract_id: envelope.contract_id };
  assert.equal(deriveCrossingEnvelopeHash(envelope), deriveCrossingEnvelopeHash(shuffled));
  assert.notEqual(deriveCrossingEnvelopeHash(envelope), deriveCrossingEnvelopeHash({ ...envelope, record: { ...envelope.record, b: 2 } }));
  assert.notEqual(deriveCrossingEnvelopeHash(envelope), deriveCrossingEnvelopeHash({ ...envelope, contract_id: "schema://other" }));
});

async function withPeer(handler, fn) {
  const server = http.createServer(async (req, res) => {
    const chunks = []; for await (const c of req) chunks.push(c);
    const body = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
    const reply = handler(req.url, body);
    res.writeHead(reply.status ?? 200, { "content-type": "application/json" });
    res.end(JSON.stringify(reply.body));
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  try { return await fn(`http://127.0.0.1:${server.address().port}`); } finally { server.close(); }
}

test("each wire shape carries the envelope and reports the peer's acknowledgement; an altered envelope is refused as not a binding; a peer refusal is a transport failure", async () => {
  const envelope = { contract_id: "schema://ioi/applications/ioi-ai/orchestration-participation-request/v2", record: { participation_request_id: "participation-request://x/1", terms_response: "accept" } };
  const hash = deriveCrossingEnvelopeHash(envelope);
  const seen = [];
  await withPeer((url, body) => {
    if (url === "/tasks/send") { seen.push(["a2a", body.message.parts[0].data]); return { body: { id: body.id, status: { state: "completed" }, artifacts: [{ parts: [{ type: "data", data: { received_hash: deriveCrossingEnvelopeHash(body.message.parts[0].data) } }] }] } }; }
    if (url === "/mcp") { seen.push(["mcp", body.params.arguments]); return { body: { jsonrpc: "2.0", id: 1, result: { content: [{ type: "text", text: JSON.stringify({ received_hash: deriveCrossingEnvelopeHash(body.params.arguments) }) }], isError: false } } }; }
    if (url === "/rpc") { seen.push(["rpc", body.params.envelope]); return { body: { jsonrpc: "2.0", id: 1, result: { received_hash: deriveCrossingEnvelopeHash(body.params.envelope), state: "delivered" } } }; }
    return { status: 400, body: { error: { message: "unsupported" } } };
  }, async (url) => {
    const receipts = await Promise.all([
      new A2aBinding(selectBinding(profiles, "a2a"), url).deliver(envelope),
      new McpBinding(selectBinding(profiles, "mcp"), url).deliver(envelope),
      new HttpJsonRpcBinding(selectBinding(profiles, "http_json_rpc"), url).deliver(envelope),
    ]);
    assert.deepEqual(receipts.map((r) => r.envelope_hash), [hash, hash, hash]);
    assert.deepEqual(receipts.map((r) => r.transport_state), ["completed", "isError:false", "delivered"]);
    assert.deepEqual(receipts.map((r) => r.protocol_kind), ["a2a", "mcp", "http_json_rpc"]);
    assert.ok(seen.every(([, e]) => deriveCrossingEnvelopeHash(e) === hash), "every peer received the envelope byte-identically");
  });
  await withPeer((url, body) => {
    if (url === "/tasks/send") { const altered = { ...body.message.parts[0].data, record: { ...body.message.parts[0].data.record, terms_response: "decline" } }; return { body: { id: body.id, status: { state: "completed" }, artifacts: [{ parts: [{ type: "data", data: { received_hash: deriveCrossingEnvelopeHash(altered) } }] }] } }; }
    return { status: 400, body: { error: { message: "unsupported" } } };
  }, async (url) => {
    await assert.rejects(new A2aBinding(selectBinding(profiles, "a2a"), url).deliver(envelope), (e) => e.code === "binding_altered_envelope");
  });
  await withPeer(() => ({ status: 503, body: { error: { message: "peer down" } } }), async (url) => {
    await assert.rejects(new HttpJsonRpcBinding(selectBinding(profiles, "http_json_rpc"), url).deliver(envelope), (e) => e.code === "binding_transport_failed");
  });
});
