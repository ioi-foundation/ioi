import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const __dirname = dirname(fileURLToPath(import.meta.url));
const packageRoot = resolve(__dirname, "..");

async function readJson(relativePath) {
  const raw = await readFile(resolve(packageRoot, relativePath), "utf8");
  return JSON.parse(raw);
}

test("exports canonical wallet protocol version, methods, and fixtures", async () => {
  const protocol = await import("../dist/index.js");

  assert.equal(protocol.WALLET_PROTOCOL_SCHEMA_VERSION, "ioi.wallet.protocol.v1");
  assert.ok(protocol.APPROVAL_MODES.includes("session_envelope"));
  assert.ok(protocol.AUTHORITY_RISK_CLASSES.includes("secret_export"));
  assert.ok(protocol.WALLET_NETWORK_KERNEL_METHODS.includes("issue_session_lease@v1"));
  assert.equal(
    protocol.WALLET_NETWORK_PROTOCOL_METHODS.issueCapabilityLease,
    "wallet.capability.lease.issue",
  );
  assert.equal(
    protocol.EXAMPLE_AUTHORITY_REVIEW.schema_version,
    protocol.WALLET_PROTOCOL_SCHEMA_VERSION,
  );
});

test("checked-in schemas and OpenAPI are valid JSON with expected ids", async () => {
  const protocol = await import("../dist/index.js");
  const schemaFiles = [
    "schemas/authority-review.schema.json",
    "schemas/capability-lease.schema.json",
    "schemas/wallet-receipt.schema.json",
    "schemas/exchange-intent.schema.json",
    "schemas/trade-intent.schema.json",
  ];

  const ids = [];
  for (const schemaFile of schemaFiles) {
    const schema = await readJson(schemaFile);
    assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema");
    assert.equal(schema.type, "object");
    ids.push(schema.$id);
  }

  assert.deepEqual(ids, [...protocol.WALLET_PROTOCOL_SCHEMA_IDS]);

  const openapi = await readJson("openapi/wallet-network.openapi.json");
  assert.equal(openapi.openapi, "3.1.0");
  assert.ok(openapi.paths["/v1/authority/reviews"]);
  assert.ok(openapi.paths["/v1/capability/leases"]);
  assert.ok(openapi.paths["/v1/exchange/intents"]);
  assert.ok(openapi.paths["/v1/trade/intents"]);
  assert.ok(openapi.paths["/v1/receipts"]);
});

test("fixture payloads preserve the wallet authority grammar", async () => {
  const fixture = await readJson("fixtures/wallet-protocol-fixtures.json");
  const review = fixture.authority_review;

  assert.equal(fixture.schema_version, "ioi.wallet.protocol.v1");
  assert.match(review.requested_scopes[0], /^scope:/);
  assert.equal(review.candidate_evidence[0].coverage_state, "assessed");
  assert.equal(review.policy_checks[0].result, "passed");
  assert.equal(review.policy_result, "requires_human");
});
