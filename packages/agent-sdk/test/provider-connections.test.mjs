// M03.16 — the SDK path shares the API's exact routes and the registered fixtures' exact
// derivations: the same records verify the same way whether a relying party reads them through
// the SDK or holds the JSON.
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import {
  createRuntimeSubstrateClient,
  deriveProviderAccountSubjectHash,
  deriveProviderConnectionBindingHash,
  deriveProviderConnectionCeremonyHash,
  deriveProviderProfileRef,
  providerCredentialIsFenced,
  verifyProviderConnectionChain,
} from "../dist/index.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const fixtures = path.resolve(here, "../../../docs/architecture/_meta/schemas/fixtures");
const readFixture = (family, name) => JSON.parse(fs.readFileSync(path.join(fixtures, family, name), "utf8"));

test("SDK provider-connection methods hit the daemon's exact connection routes", async () => {
  const requests = [];
  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    requests.push(`${request.method} ${url.pathname}`);
    request.resume();
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ ok: true, connections: [], current: null, versions: [], head: null, dependents: { lease_grants: [], connector_sessions: [], obligations: [] } }));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const client = createRuntimeSubstrateClient({ endpoint: `http://127.0.0.1:${server.address().port}` });
    const owner = { owner_ref: "org://acme", idempotency_key: "sdk-1" };
    await client.startProviderConnection({ ...owner, connector_id: "cnx_sdk", redirect_uri: "http://127.0.0.1:4173/cb" });
    await client.completeProviderConnection({ ...owner, state: "st_x", code: "code_x" });
    await client.listProviderConnections();
    await client.getProviderConnection("cnx_sdk~user-p1");
    await client.getProviderConnectionDependents("cnx_sdk~user-p1");
    await client.verifyProviderConnection("cnx_sdk~user-p1", { ...owner, expected_head: "h" });
    await client.reauthorizeProviderConnection("cnx_sdk~user-p1", { ...owner, redirect_uri: "http://127.0.0.1:4173/cb" });
    await client.disconnectProviderConnection("cnx_sdk~user-p1", { ...owner, expected_head: "h" });
  } finally {
    server.close();
  }
  assert.deepEqual(requests, [
    "POST /v1/hypervisor/auth/connections/authorization/start",
    "POST /v1/hypervisor/auth/connections/authorization/complete",
    "GET /v1/hypervisor/auth/connections",
    "GET /v1/hypervisor/auth/connections/cnx_sdk~user-p1",
    "GET /v1/hypervisor/auth/connections/cnx_sdk~user-p1/dependents",
    "POST /v1/hypervisor/auth/connections/cnx_sdk~user-p1/verify",
    "POST /v1/hypervisor/auth/connections/cnx_sdk~user-p1/reauthorize",
    "POST /v1/hypervisor/auth/connections/cnx_sdk~user-p1/disconnect",
  ]);
});

test("SDK derivations reproduce the registered fixtures' commitments exactly", () => {
  for (const name of ["positive-issued.json", "positive-completed.json", "positive-refused.json"]) {
    const record = readFixture("provider-connection-ceremony-v1", name);
    assert.equal(deriveProviderConnectionCeremonyHash(record), record.content_hash, name);
  }
  for (const name of ["positive-active.json", "positive-disconnected.json", "positive-superseded.json"]) {
    const record = readFixture("provider-connection-binding-v1", name);
    assert.equal(deriveProviderConnectionBindingHash(record), record.content_hash, name);
  }
  const drift = readFixture("provider-connection-binding-v1", "negative-content-hash-drift.json");
  assert.notEqual(deriveProviderConnectionBindingHash(drift), drift.content_hash);
});

test("SDK verifies a version chain and computes the fence offline", () => {
  const v1 = readFixture("provider-connection-binding-v1", "positive-active.json");
  const v2 = readFixture("provider-connection-binding-v1", "positive-disconnected.json");
  assert.deepEqual(verifyProviderConnectionChain([v2, v1]), []);
  const tampered = { ...v2, connection_revocation_epoch: 0 };
  assert.ok(verifyProviderConnectionChain([v1, tampered]).some((f) => /content_hash|epoch/u.test(f)));
  assert.deepEqual(providerCredentialIsFenced({ kind: "bearer" }, null), { fenced: false, cause: "legacy credential without a connection" });
  assert.equal(providerCredentialIsFenced({ connection_ref: v1.connection_ref, credential_binding_ref: v1.credential_binding_ref, connection_revocation_epoch: 0 }, v1, Date.parse("2026-09-17T00:00:00Z")).fenced, false);
  assert.equal(providerCredentialIsFenced({ connection_ref: v1.connection_ref, credential_binding_ref: v1.credential_binding_ref, connection_revocation_epoch: 0 }, v2).cause, "connection_disconnected");
  assert.equal(providerCredentialIsFenced({ connection_ref: v1.connection_ref, credential_binding_ref: v1.credential_binding_ref, connection_revocation_epoch: 0 }, { ...v1, credential_binding_ref: `${v1.credential_binding_ref.replace(/@1$/u, "")}@2` }).cause, "connection_credential_superseded");
  assert.equal(providerCredentialIsFenced({ connection_ref: v1.connection_ref, credential_binding_ref: v1.credential_binding_ref, connection_revocation_epoch: 0 }, v1, Date.parse("2027-01-01T00:00:00Z")).cause, "connection_reauthorization_required");
});

test("SDK provider profile and subject commitments exclude secrets and bind the profile", () => {
  const a = deriveProviderProfileRef({ connector_id: "cnx_a", auth_profile: { authorization_endpoint: "https://p/auth", token_endpoint: "https://p/token", client_id: "c1", sealed_client_secret: "xxx" } });
  const b = deriveProviderProfileRef({ connector_id: "cnx_a", auth_profile: { authorization_endpoint: "https://p/auth", token_endpoint: "https://p/token", client_id: "c1", sealed_client_secret: "yyy" } });
  const c = deriveProviderProfileRef({ connector_id: "cnx_a", auth_profile: { authorization_endpoint: "https://p/auth", token_endpoint: "https://p/token2", client_id: "c1" } });
  assert.equal(a, b);
  assert.notEqual(a, c);
  assert.notEqual(deriveProviderAccountSubjectHash(a, "s1"), deriveProviderAccountSubjectHash(c, "s1"));
});
