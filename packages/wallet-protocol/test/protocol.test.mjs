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
  assert.ok(protocol.WALLET_PRESENTATION_PROFILES.includes("lite_approval_card"));
  assert.ok(protocol.AUTHORITY_RISK_CLASSES.includes("secret_export"));
  assert.ok(protocol.WALLET_NETWORK_KERNEL_METHODS.includes("issue_session_lease@v1"));
  for (const method of [
    "issue_principal_authority_binding@v1",
    "revoke_principal_authority_binding@v1",
    "resolve_principal_authority@v1",
    "lookup_principal_authority_binding@v1",
  ]) {
    assert.ok(protocol.WALLET_NETWORK_KERNEL_METHODS.includes(method));
  }
  assert.equal(
    protocol.WALLET_NETWORK_PROTOCOL_METHODS.resolvePrincipalAuthority,
    "resolve_principal_authority@v1",
  );
  assert.equal(
    protocol.WALLET_NETWORK_PROTOCOL_METHODS.issueCapabilityLease,
    "wallet.capability.lease.issue",
  );
  assert.equal(
    protocol.WALLET_NETWORK_PROTOCOL_METHODS.revokeCapabilityLease,
    "wallet.capability.lease.revoke",
  );
  assert.equal(typeof protocol.assertExchangeIntentCandidateEvidence, "function");
  assert.equal(typeof protocol.assertTradeIntentCandidateEvidence, "function");
  assert.equal(typeof protocol.assertPrincipalAuthorityBindingProof, "function");
  assert.equal(typeof protocol.assertPrincipalAuthorityResolutionReceipt, "function");
  assert.equal(typeof protocol.exchangeRouteSourceAdapter, "function");
  assert.equal(typeof protocol.tradeVenueSourceAdapter, "function");
  assert.equal(typeof protocol.buildCandidateEvidenceFromSourceAdapter, "function");
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
    "schemas/capability-lease-revocation.schema.json",
    "schemas/wallet-receipt.schema.json",
    "schemas/exchange-intent.schema.json",
    "schemas/trade-intent.schema.json",
    "schemas/principal-authority-binding-proof.schema.json",
    "schemas/principal-authority-resolution.schema.json",
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
  assert.ok(openapi.paths["/v1/authority/principal-bindings"]);
  assert.ok(openapi.paths["/v1/authority/principal-bindings/revoke"]?.post);
  assert.ok(openapi.paths["/v1/authority/principal-bindings/resolve"]);
  assert.ok(openapi.paths["/v1/authority/principal-bindings/lookup"]?.post);
  assert.equal(openapi.paths["/v1/authority/principal-bindings/lookup"]?.get, undefined);
  assert.equal(openapi.paths["/v1/authority/principal-bindings/{binding_ref}"], undefined);
  assert.ok(openapi.paths["/v1/capability/leases"]);
  assert.ok(openapi.paths["/v1/capability/leases/{lease_id}/revoke"]);
  assert.ok(openapi.paths["/v1/exchange/intents"]);
  assert.ok(openapi.paths["/v1/trade/intents"]);
  assert.ok(openapi.paths["/v1/receipts"]);
});

test("fixture payloads preserve the wallet authority grammar", async () => {
  const protocol = await import("../dist/index.js");
  const fixture = await readJson("fixtures/wallet-protocol-fixtures.json");
  const review = fixture.authority_review;

  assert.equal(fixture.schema_version, "ioi.wallet.protocol.v1");
  assert.match(review.requested_scopes[0], /^scope:/);
  assert.equal(review.candidate_evidence[0].coverage_state, "assessed");
  assert.equal(
    fixture.exchange_intent.candidate_evidence[0].candidate_id,
    fixture.exchange_intent.route_candidate_id,
  );
  assert.equal(
    fixture.trade_intent.candidate_evidence[0].candidate_id,
    fixture.trade_intent.venue_candidate_id,
  );
  assert.deepEqual(review.allowed_approval_modes, ["one_shot_review", "step_up_review"]);
  assert.equal(review.recommended_presentation_profile, "standard_wallet_review");
  assert.equal(review.policy_checks[0].result, "passed");
  assert.equal(review.policy_result, "requires_human");
  assert.match(fixture.capability_lease.capability_scope, /^scope:/);
  assert.equal(fixture.capability_lease_revocation.lease_id, fixture.capability_lease.lease_id);
  assert.equal(
    fixture.capability_lease_revocation.revocation_epoch,
    fixture.capability_lease.revocation_epoch + 1,
  );
  assert.equal(
    fixture.principal_authority_binding_proof.statement.principal_ref,
    "agentgres://domain/acme.example",
  );
  assert.equal(
    fixture.principal_authority_revocation_proof.statement.previous_binding_ref,
    fixture.principal_authority_binding_proof.binding_ref,
  );
  assert.deepEqual(
    fixture.principal_authority_resolution_request.expected_coordinates.binding_hash,
    fixture.principal_authority_resolution.coordinates.binding_hash,
  );
  assert.deepEqual(
    fixture.principal_authority_binding_proof,
    JSON.parse(JSON.stringify(protocol.EXAMPLE_PRINCIPAL_AUTHORITY_BINDING_PROOF)),
  );
  assert.deepEqual(
    fixture.principal_authority_revocation_proof,
    JSON.parse(JSON.stringify(protocol.EXAMPLE_PRINCIPAL_AUTHORITY_REVOCATION_PROOF)),
  );
  assert.deepEqual(
    fixture.principal_authority_resolution_request,
    JSON.parse(JSON.stringify(protocol.EXAMPLE_RESOLVE_PRINCIPAL_AUTHORITY_PARAMS)),
  );
  assert.deepEqual(
    fixture.principal_authority_resolution,
    JSON.parse(JSON.stringify(protocol.EXAMPLE_PRINCIPAL_AUTHORITY_RESOLUTION_RECEIPT.resolution)),
  );
});

test("principal authority proof and pinned resolution validation fail closed", async () => {
  const protocol = await import("../dist/index.js");
  const active = protocol.EXAMPLE_PRINCIPAL_AUTHORITY_BINDING_PROOF;
  const revoked = protocol.EXAMPLE_PRINCIPAL_AUTHORITY_REVOCATION_PROOF;
  const request = protocol.EXAMPLE_RESOLVE_PRINCIPAL_AUTHORITY_PARAMS;
  const receipt = protocol.EXAMPLE_PRINCIPAL_AUTHORITY_RESOLUTION_RECEIPT;

  assert.equal(
    protocol.assertIssuePrincipalAuthorityBindingParams({ proof: active }).proof.statement.status,
    "active",
  );
  assert.equal(
    protocol.assertRevokePrincipalAuthorityBindingParams({
      predecessor_binding_ref: active.binding_ref,
      proof: revoked,
    }).proof.statement.binding_version,
    2,
  );
  assert.equal(
    protocol.assertPrincipalAuthorityResolutionReceipt(request, receipt).resolution.coordinates
      .binding_version,
    1,
  );
  assert.deepEqual(
    protocol.approvalAuthorityArtifactHash(receipt.resolution.approval_authority),
    receipt.resolution.approval_authority_snapshot_hash,
    "protocol JCS/SHA-256 must reproduce Rust ApprovalAuthority::artifact_hash()",
  );
  assert.equal(
    protocol.assertLookupPrincipalAuthorityBindingReceipt(
      protocol.EXAMPLE_LOOKUP_PRINCIPAL_AUTHORITY_BINDING_PARAMS,
      protocol.EXAMPLE_LOOKUP_PRINCIPAL_AUTHORITY_BINDING_RECEIPT,
    ).proof.binding_ref,
    active.binding_ref,
  );

  for (const principal_ref of [
    "service://sas/runtime-audit-weekly",
    "domain://carwash/vehicle-prep",
    "domain://marketplace/services",
    "agentgres://domain/hypervisor/local",
  ]) {
    assert.equal(
      protocol.assertPrincipalAuthorityBindingProof({
        ...active,
        statement: { ...active.statement, principal_ref },
      }).statement.principal_ref,
      principal_ref,
    );
  }

  for (const principal_ref of [
    "user://local-login",
    "agent://caller-field",
    "wallet://trust-on-first-use",
    "domain://acme.example?role=admin",
    "org:///acme",
    "org://acme//owner",
    "org://acme/",
    "org://.acme/owner",
    "org://acme-/owner",
    "domain://marketplace/-services",
    "domain://marketplace/../services",
    "agentgres://domain/hypervisor/*",
  ]) {
    assert.throws(
      () =>
        protocol.assertPrincipalAuthorityBindingProof({
          ...active,
          statement: { ...active.statement, principal_ref },
        }),
      (error) => {
        assert.equal(error.code, "principal_authority_principal_ref_invalid");
        return true;
      },
    );
  }

  assert.throws(
    () =>
      protocol.assertPrincipalAuthorityBindingProof({
        ...revoked,
        statement: { ...revoked.statement, reason: undefined },
      }),
    (error) => {
      assert.equal(error.code, "principal_authority_binding_revocation_reason_missing");
      return true;
    },
  );

  assert.throws(
    () =>
      protocol.assertPrincipalAuthorityBindingProof({
        ...revoked,
        statement: {
          ...revoked.statement,
          previous_binding_hash: Array(32).fill(99),
        },
      }),
    (error) => {
      assert.equal(error.code, "principal_authority_binding_predecessor_hash_mismatch");
      return true;
    },
  );

  assert.throws(
    () =>
      protocol.assertLookupPrincipalAuthorityBindingReceipt(
        {
          ...protocol.EXAMPLE_LOOKUP_PRINCIPAL_AUTHORITY_BINDING_PARAMS,
          expected_binding_hash: Array(32).fill(99),
        },
        protocol.EXAMPLE_LOOKUP_PRINCIPAL_AUTHORITY_BINDING_RECEIPT,
      ),
    (error) => {
      assert.equal(error.code, "principal_authority_binding_request_pin_mismatch");
      return true;
    },
  );

  assert.throws(
    () =>
      protocol.assertPrincipalAuthorityResolutionReceipt(request, {
        ...receipt,
        resolved_at_ms: receipt.resolved_at_ms + 1,
      }),
    (error) => {
      assert.equal(error.code, "principal_authority_resolution_timestamp_mismatch");
      return true;
    },
  );

  assert.throws(
    () =>
      protocol.assertPrincipalAuthorityResolutionReceipt(
        {
          ...request,
          expected_coordinates: {
            ...request.expected_coordinates,
            binding_version: 2,
          },
        },
        receipt,
      ),
    (error) => {
      assert.equal(error.code, "principal_authority_resolution_pin_mismatch");
      return true;
    },
  );

  assert.throws(
    () =>
      protocol.assertRevokePrincipalAuthorityBindingParams({
        predecessor_binding_ref: revoked.binding_ref,
        proof: revoked,
      }),
    (error) => {
      assert.equal(error.code, "principal_authority_binding_predecessor_mismatch");
      return true;
    },
  );

  assert.throws(
    () =>
      protocol.assertPrincipalAuthorityResolutionReceipt(
        { ...request, required_scope: "room_participation.reject" },
        {
          ...receipt,
          resolution: {
            ...receipt.resolution,
            required_scope: "room_participation.reject",
            matched_scope: "room_participation.reject",
            approval_authority: {
              ...receipt.resolution.approval_authority,
              scope_allowlist: [
                ...receipt.resolution.approval_authority.scope_allowlist,
                "room_participation.reject",
              ],
            },
          },
        },
      ),
    (error) => {
      assert.equal(error.code, "principal_authority_snapshot_hash_mismatch");
      return true;
    },
  );

  for (const approval_authority of [
    {
      ...receipt.resolution.approval_authority,
      expires_at: receipt.resolution.approval_authority.expires_at + 1,
    },
    {
      ...receipt.resolution.approval_authority,
      revoked: true,
    },
  ]) {
    assert.throws(
      () =>
        protocol.assertPrincipalAuthorityResolutionReceipt(request, {
          ...receipt,
          resolution: {
            ...receipt.resolution,
            approval_authority,
          },
        }),
      (error) => {
        assert.equal(error.code, "principal_authority_snapshot_hash_mismatch");
        return true;
      },
    );
  }

  assert.throws(
    () =>
      protocol.assertPrincipalAuthorityResolutionReceipt(request, {
        ...receipt,
        resolution: {
          ...receipt.resolution,
          approval_authority: {
            ...receipt.resolution.approval_authority,
            scope_allowlist: [],
          },
          approval_authority_snapshot_hash: protocol.approvalAuthorityArtifactHash({
            ...receipt.resolution.approval_authority,
            scope_allowlist: [],
          }),
        },
      }),
    (error) => {
      assert.equal(error.code, "principal_authority_scope_denied");
      return true;
    },
  );

  assert.throws(
    () =>
      protocol.assertPrincipalAuthorityResolutionReceipt(
        { ...request, required_scope: "room_participation.reject" },
        receipt,
      ),
    (error) => {
      assert.equal(error.code, "principal_authority_resolution_principal_mismatch");
      return true;
    },
  );

  assert.throws(
    () =>
      protocol.assertPrincipalAuthorityResolutionReceipt(
        { ...request, required_scope: "*" },
        receipt,
      ),
    (error) => {
      assert.equal(error.code, "principal_authority_required_scope_invalid");
      return true;
    },
  );

  assert.throws(
    () =>
      protocol.assertPrincipalAuthorityBindingProof({
        ...active,
        statement: { ...active.statement, binding_version: 4096 },
      }),
    (error) => {
      assert.equal(error.code, "principal_authority_terminal_revocation_reserved");
      return true;
    },
  );
});

test("candidate evidence validators fail closed for stale or mismatched exchange and trade intents", async () => {
  const protocol = await import("../dist/index.js");

  assert.equal(
    protocol.assertExchangeIntentCandidateEvidence(protocol.EXAMPLE_EXCHANGE_INTENT, {
      now: "2026-06-17T00:00:30.000Z",
    }).intent_id,
    "intent:exchange-example",
  );
  assert.equal(
    protocol.assertTradeIntentCandidateEvidence(protocol.EXAMPLE_TRADE_INTENT, {
      now: "2026-06-17T00:05:00.000Z",
    }).intent_id,
    "intent:trade-example",
  );

  assert.throws(
    () =>
      protocol.assertExchangeIntentCandidateEvidence({
        ...protocol.EXAMPLE_EXCHANGE_INTENT,
        route_candidate_id: "route:other",
      }),
    (error) => {
      assert.equal(error.name, "WalletProtocolValidationError");
      assert.equal(error.code, "exchange_intent_candidate_evidence_mismatch");
      return true;
    },
  );

  assert.throws(
    () =>
      protocol.assertTradeIntentCandidateEvidence({
        ...protocol.EXAMPLE_TRADE_INTENT,
        candidate_evidence: [
          {
            ...protocol.EXAMPLE_TRADE_INTENT.candidate_evidence[0],
            coverage_state: "unknown",
          },
        ],
      }),
    (error) => {
      assert.equal(error.code, "candidate_evidence_not_executable");
      return true;
    },
  );

  assert.throws(
    () =>
      protocol.assertExchangeIntentCandidateEvidence(protocol.EXAMPLE_EXCHANGE_INTENT, {
        now: "2026-06-17T00:02:00.000Z",
      }),
    (error) => {
      assert.equal(error.code, "candidate_evidence_expired");
      return true;
    },
  );
});

test("candidate source adapters produce executable evidence without becoming trust roots", async () => {
  const protocol = await import("../dist/index.js");
  const adapter = protocol.exchangeRouteSourceAdapter({
    adapter_id: "adapter:unit-direct-pool",
    source: "decentralized.exchange",
  });

  assert.equal(adapter.trust_boundary, "candidate_source_only");
  assert.equal(adapter.evidence_policy, "claims_plus_refs_required");

  const evidence = protocol.buildCandidateEvidenceFromSourceAdapter({
    adapter,
    candidate_id: "route:unit-direct-pool",
    observed_at: "2026-06-17T00:00:00.000Z",
    expires_at: "2026-06-17T00:01:00.000Z",
    evidence_refs: ["agentgres://evidence/unit-route"],
    risk_labels: ["No Bridge"],
    claims: {
      venue: "direct-pool",
      simulation_hash: "hash:unit-route-simulation",
    },
    validation: { now: "2026-06-17T00:00:10.000Z" },
  });

  assert.equal(evidence.source, "decentralized.exchange");
  assert.equal(evidence.adapter_id, "adapter:unit-direct-pool");
  assert.equal(evidence.coverage_state, "assessed");

  assert.throws(
    () =>
      protocol.buildCandidateEvidenceFromSourceAdapter({
        adapter: {
          ...adapter,
          trust_boundary: "execution_truth",
        },
        candidate_id: "route:bad-trust-root",
        observed_at: "2026-06-17T00:00:00.000Z",
        expires_at: "2026-06-17T00:01:00.000Z",
        evidence_refs: ["agentgres://evidence/bad-route"],
        claims: { venue: "bad-route" },
      }),
    /candidate sources, not trust roots/,
  );

  assert.throws(
    () =>
      protocol.buildCandidateEvidenceFromSourceAdapter({
        adapter,
        candidate_id: "route:unassessed",
        observed_at: "2026-06-17T00:00:00.000Z",
        expires_at: "2026-06-17T00:01:00.000Z",
        coverage_state: "unassessed",
        evidence_refs: ["agentgres://evidence/unassessed-route"],
        claims: { venue: "unassessed-route" },
        validation: { now: "2026-06-17T00:00:10.000Z" },
      }),
    (error) => {
      assert.equal(error.code, "candidate_evidence_not_executable");
      return true;
    },
  );
});
