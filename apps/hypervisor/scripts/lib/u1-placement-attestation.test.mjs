import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import { stableStringify } from "./c7-c8-certificate.mjs";
import { sealU1Certificate } from "./u1-campaign-certificate.mjs";
import { validU1Fixture } from "./u1-campaign-certificate.test-fixture.mjs";
import { qualifyU1Provider, sha256Bytes } from "./u1-provider-preflight.mjs";
import {
  akashAddressFromPublicKey,
  cosmosAddressFromPublicKey,
  placementSigningBytes,
  publicKeyFingerprint,
  verifyPlacementAttestation,
} from "./u1-placement-attestation.mjs";

test("matches the published Cosmos compressed-key address vector", () => {
  const compressed = Buffer.from("At8sTdbKdkdyvxi8FjLe4Dl9PYc+u19VMqCpmA7PBrPz", "base64");
  const uncompressed = crypto.ECDH.convertKey(compressed, "secp256k1", undefined, undefined, "uncompressed");
  const publicKey = crypto.createPublicKey({
    format: "jwk",
    key: {
      kty: "EC",
      crv: "secp256k1",
      x: uncompressed.subarray(1, 33).toString("base64url"),
      y: uncompressed.subarray(33, 65).toString("base64url"),
    },
  });
  assert.equal(cosmosAddressFromPublicKey(publicKey, "hid"), "hid18vux70nvs5ee0sfvqfjgt6rq5fd89asd7xaypj");
});

function rebindMeasurementResponses(certificate) {
  const response = (value) => {
    const raw = Buffer.from(stableStringify(value));
    return {
      bytes: raw.length,
      sha256: `sha256:${crypto.createHash("sha256").update(raw).digest("hex")}`,
      body_base64: raw.toString("base64"),
    };
  };
  const environment = response(certificate.measurement.environment);
  const results = response(certificate.measurement.aggregate);
  certificate.measurement.manifest.artifacts = [
    { name: "environment.json", bytes: environment.bytes, sha256: environment.sha256 },
    { name: "result.json", bytes: results.bytes, sha256: results.sha256 },
  ];
  const responses = {
    status: response(certificate.measurement.status),
    environment,
    results,
    manifest: response(certificate.measurement.manifest),
  };
  certificate.measurement.response_hashes = Object.fromEntries(
    Object.entries(responses).map(([name, item]) => [name, { bytes: item.bytes, sha256: item.sha256 }]),
  );
  certificate.measurement.raw_response_bodies_base64 = Object.fromEntries(
    Object.entries(responses).map(([name, item]) => [name, item.body_base64]),
  );
  certificate.lifecycle.result_binding.status_hash = responses.status.sha256;
  certificate.lifecycle.result_binding.environment_hash = responses.environment.sha256;
  certificate.lifecycle.result_binding.result_hash = responses.results.sha256;
  certificate.lifecycle.result_binding.manifest_hash = responses.manifest.sha256;
}

function rebindProviderPreflight(certificate, providerAddress) {
  const response = JSON.parse(
    Buffer.from(certificate.provider_preflight_response.body_base64, "base64").toString("utf8"),
  );
  response.owner = providerAddress;
  const raw = Buffer.from(JSON.stringify(response));
  const preflight = {
    schema_version: "ioi.aft.u1-provider-preflight.v1",
    provider_response_sha256: sha256Bytes(raw),
    ...qualifyU1Provider(response, providerAddress),
  };
  certificate.provider_preflight = preflight;
  certificate.provider_preflight_response = {
    bytes: raw.length,
    sha256: preflight.provider_response_sha256,
    body_base64: raw.toString("base64"),
  };
  certificate.authority.provider_preflight_sha256 = sha256Bytes(
    Buffer.from(`${JSON.stringify(preflight, null, 2)}\n`),
  );
}

function fixture() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "secp256k1" });
  const providerAddress = akashAddressFromPublicKey(publicKey);
  const campaignA = validU1Fixture();
  campaignA.authority.provider_address = providerAddress;
  campaignA.authority.provider_selector.provider_address = providerAddress;
  campaignA.provider.provider_address = providerAddress;
  rebindProviderPreflight(campaignA, providerAddress);
  campaignA.certificate_hash = sealU1Certificate(campaignA).certificate_hash;
  const campaignB = structuredClone(campaignA);
  campaignB.authority.campaign_id = "u1-campaign-b";
  campaignB.measurement.status.campaign_id = "u1-campaign-b";
  campaignB.measurement.environment.campaign_id = "u1-campaign-b";
  campaignB.measurement.aggregate.campaign_id = "u1-campaign-b";
  campaignB.measurement.manifest.campaign_id = "u1-campaign-b";
  campaignB.provider.dseq = "1787000000001";
  rebindMeasurementResponses(campaignB);
  campaignB.certificate_hash = sealU1Certificate(campaignB).certificate_hash;
  const attestation = {
    schema_version: "ioi.aft.provider-placement-attestation.v2",
    provider_address: campaignA.provider.provider_address,
    campaigns: [campaignA, campaignB].map((campaign) => ({
      campaign_id: campaign.authority.campaign_id,
      dseq: campaign.provider.dseq,
      image_digest: campaign.authority.image_digest,
      observed_from: "2026-08-21T12:00:00Z",
      observed_until: "2026-08-21T13:00:00Z",
    })),
    placement: {
      class: "reserved_bare_metal",
      same_physical_host: true,
      host_fingerprint: `sha256:${"a".repeat(64)}`,
      cpu: {
        vendor: "fixture",
        family_model: "fixture",
        sockets: 1,
        physical_cores: 8,
        threads: 16,
        smt: "enabled",
        governor_or_frequency_posture: "fixed",
        maximum_overcommit_ratio: "1:1",
      },
      memory: { limit_bytes: 17_179_869_184, ballooning: false, host_swap_during_interval: false },
    },
    attestor: {
      name_or_role: "provider operator",
      authority_ref: campaignA.provider.provider_address,
      public_key_ref: publicKeyFingerprint(publicKey),
      signature_algorithm: "secp256k1-sha256-der",
    },
  };
  attestation.signature = crypto.sign("sha256", placementSigningBytes(attestation), { key: privateKey, dsaEncoding: "der" }).toString("base64");
  return { publicKey, privateKey, campaignA, campaignB, attestation };
}

test("verifies a signed attestation bound to both exact campaign certificates", () => {
  const { publicKey, campaignA, campaignB, attestation } = fixture();
  const result = verifyPlacementAttestation(attestation, publicKey, [campaignA, campaignB]);
  assert.equal(result.ok, true);
  assert.equal(result.classification, "qualified_reserved_bare_metal");
});

test("refuses dseq substitution even after the attestation is re-signed", () => {
  const { publicKey, privateKey, campaignA, campaignB, attestation } = fixture();
  attestation.campaigns[1].dseq = "1787000099999";
  attestation.signature = crypto.sign("sha256", placementSigningBytes(attestation), { key: privateKey, dsaEncoding: "der" }).toString("base64");
  const result = verifyPlacementAttestation(attestation, publicKey, [campaignA, campaignB]);
  assert.equal(result.ok, false);
  assert(!result.failures.some((failure) => failure.code === "placement_signature_invalid"));
  assert(result.failures.some((failure) => failure.code === "placement_campaign_binding_mismatch"));
});

test("refuses bare-metal elevation when overcommit or memory isolation is weaker", () => {
  const { publicKey, privateKey, campaignA, campaignB, attestation } = fixture();
  attestation.placement.cpu.maximum_overcommit_ratio = "2:1";
  attestation.signature = crypto.sign("sha256", placementSigningBytes(attestation), { key: privateKey, dsaEncoding: "der" }).toString("base64");
  const result = verifyPlacementAttestation(attestation, publicKey, [campaignA, campaignB]);
  assert.equal(result.classification, "same_provider_container_unknown_host");
  assert(result.failures.some((failure) => failure.code === "placement_bare_metal_facts_insufficient"));
});

test("returns a failed verification for an invalid independently supplied key", () => {
  const { campaignA, campaignB, attestation } = fixture();
  const result = verifyPlacementAttestation(attestation, Buffer.from("not a key"), [campaignA, campaignB]);
  assert.equal(result.ok, false);
  assert(result.failures.some((failure) => failure.code === "placement_attestor_key_invalid"));
});

test("refuses an extra duplicate campaign statement and mismatched authority", () => {
  const { publicKey, privateKey, campaignA, campaignB, attestation } = fixture();
  attestation.campaigns.push(structuredClone(attestation.campaigns[0]));
  attestation.attestor.authority_ref = "akash1other";
  attestation.signature = crypto.sign("sha256", placementSigningBytes(attestation), { key: privateKey, dsaEncoding: "der" }).toString("base64");
  const result = verifyPlacementAttestation(attestation, publicKey, [campaignA, campaignB]);
  assert.equal(result.ok, false);
  assert(result.failures.some((failure) => failure.code === "placement_campaign_set_invalid"));
  assert(result.failures.some((failure) => failure.code === "placement_attestor_authority_mismatch"));
});

test("refuses an attacker key that self-asserts the real provider address", () => {
  const { campaignA, campaignB, attestation } = fixture();
  const attacker = crypto.generateKeyPairSync("ec", { namedCurve: "secp256k1" });
  attestation.attestor.public_key_ref = publicKeyFingerprint(attacker.publicKey);
  attestation.signature = crypto.sign(
    "sha256",
    placementSigningBytes(attestation),
    { key: attacker.privateKey, dsaEncoding: "der" },
  ).toString("base64");
  const result = verifyPlacementAttestation(attestation, attacker.publicKey, [campaignA, campaignB]);
  assert.equal(result.ok, false);
  assert(!result.failures.some((failure) => failure.code === "placement_signature_invalid"));
  assert(result.failures.some((failure) => failure.code === "placement_attestor_address_mismatch"));
});
