import crypto from "node:crypto";
import { stableStringify } from "./c7-c8-certificate.mjs";
import { validateU1Certificate } from "./u1-campaign-certificate.mjs";

const hash = (value) => typeof value === "string" && /^sha256:[0-9a-f]{64}$/u.test(value);

export function publicKeyFingerprint(publicKey) {
  const key = publicKey?.type === "public" ? publicKey : crypto.createPublicKey(publicKey);
  const der = key.export({ type: "spki", format: "der" });
  return `sha256:${crypto.createHash("sha256").update(der).digest("hex")}`;
}

const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

function bech32Polymod(values) {
  const generators = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let checksum = 1;
  for (const value of values) {
    const top = checksum >>> 25;
    checksum = ((checksum & 0x1ffffff) << 5) ^ value;
    for (let index = 0; index < generators.length; index += 1) {
      if ((top >>> index) & 1) checksum ^= generators[index];
    }
  }
  return checksum >>> 0;
}

function convertBits(bytes, fromBits, toBits) {
  let accumulator = 0;
  let bitCount = 0;
  const mask = (1 << toBits) - 1;
  const output = [];
  for (const byte of bytes) {
    accumulator = (accumulator << fromBits) | byte;
    bitCount += fromBits;
    while (bitCount >= toBits) {
      bitCount -= toBits;
      output.push((accumulator >>> bitCount) & mask);
    }
  }
  if (bitCount > 0) output.push((accumulator << (toBits - bitCount)) & mask);
  return output;
}

function bech32Encode(hrp, bytes) {
  const hrpValues = [
    ...[...hrp].map((character) => character.charCodeAt(0) >>> 5),
    0,
    ...[...hrp].map((character) => character.charCodeAt(0) & 31),
  ];
  const payload = convertBits(bytes, 8, 5);
  const polymodInput = [...hrpValues, ...payload, 0, 0, 0, 0, 0, 0];
  const checksum = bech32Polymod(polymodInput) ^ 1;
  const checksumWords = Array.from({ length: 6 }, (_, index) => (checksum >>> (5 * (5 - index))) & 31);
  return `${hrp}1${[...payload, ...checksumWords].map((value) => BECH32_CHARSET[value]).join("")}`;
}

export function cosmosAddressFromPublicKey(publicKey, hrp) {
  const key = publicKey?.type === "public" ? publicKey : crypto.createPublicKey(publicKey);
  if (key.asymmetricKeyType !== "ec" || key.asymmetricKeyDetails?.namedCurve !== "secp256k1") {
    throw new Error("Cosmos account addresses require a secp256k1 public key");
  }
  if (typeof hrp !== "string" || !/^[a-z0-9]+$/u.test(hrp)) throw new Error("invalid bech32 human-readable prefix");
  const jwk = key.export({ format: "jwk" });
  const x = Buffer.from(jwk.x, "base64url");
  const y = Buffer.from(jwk.y, "base64url");
  if (x.length !== 32 || y.length !== 32) throw new Error("invalid secp256k1 public key coordinates");
  const compressed = Buffer.concat([Buffer.from([(y[y.length - 1] & 1) === 1 ? 0x03 : 0x02]), x]);
  const sha = crypto.createHash("sha256").update(compressed).digest();
  const account = crypto.createHash("ripemd160").update(sha).digest();
  return bech32Encode(hrp, account);
}

export function akashAddressFromPublicKey(publicKey) {
  return cosmosAddressFromPublicKey(publicKey, "akash");
}

export function placementSigningBytes(attestation) {
  const unsigned = structuredClone(attestation);
  delete unsigned.signature;
  return Buffer.from(stableStringify(unsigned));
}

export function verifyPlacementAttestation(attestation, publicKey, campaignCertificates) {
  const failures = [];
  const fail = (code, path, detail) => failures.push({ code, path, detail });
  const certificates = campaignCertificates || [];
  if (attestation?.schema_version !== "ioi.aft.provider-placement-attestation.v2") fail("placement_schema_invalid", "schema_version", "unsupported placement schema");
  if (certificates.length !== 2 || certificates.some((certificate) => !validateU1Certificate(certificate).ok)) fail("placement_campaign_certificate_invalid", "campaign_certificates", "two valid U1 campaign certificates are required");
  let resolvedKey = null;
  let fingerprint = null;
  let derivedProviderAddress = null;
  try {
    resolvedKey = publicKey?.type === "public" ? publicKey : crypto.createPublicKey(publicKey);
    fingerprint = publicKeyFingerprint(resolvedKey);
    derivedProviderAddress = akashAddressFromPublicKey(resolvedKey);
  } catch {
    fail("placement_attestor_key_invalid", "attestor.public_key_ref", "independently supplied secp256k1 provider key could not be parsed");
  }
  if (resolvedKey && (resolvedKey.asymmetricKeyType !== "ec" || resolvedKey.asymmetricKeyDetails?.namedCurve !== "secp256k1")) fail("placement_attestor_key_type_invalid", "attestor.public_key_ref", "placement attestations require the Akash provider's secp256k1 key");
  if (fingerprint && attestation?.attestor?.public_key_ref !== fingerprint) fail("placement_attestor_key_mismatch", "attestor.public_key_ref", "resolved key differs from the signed key reference");
  if (typeof attestation?.attestor?.name_or_role !== "string" || !attestation.attestor.name_or_role.trim() || typeof attestation?.attestor?.authority_ref !== "string" || !attestation.attestor.authority_ref.trim()) fail("placement_attestor_identity_missing", "attestor", "attestor role and independently resolvable authority reference are required");
  if (!["secp256k1-sha256-der", "secp256k1-sha256-p1363"].includes(attestation?.attestor?.signature_algorithm)) fail("placement_signature_algorithm_invalid", "attestor.signature_algorithm", "signature encoding must be declared");
  let signatureValid = false;
  try {
    signatureValid = crypto.verify(
      "sha256",
      placementSigningBytes(attestation),
      {
        key: resolvedKey,
        dsaEncoding: attestation.attestor.signature_algorithm === "secp256k1-sha256-p1363" ? "ieee-p1363" : "der",
      },
      Buffer.from(attestation?.signature || "", "base64"),
    );
  } catch {}
  if (!signatureValid) fail("placement_signature_invalid", "signature", "provider signature did not verify over canonical JSON without signature");

  const expectedProvider = certificates[0]?.provider?.provider_address;
  if (!expectedProvider || certificates[1]?.provider?.provider_address !== expectedProvider || attestation?.provider_address !== expectedProvider) fail("placement_provider_mismatch", "provider_address", "attestation and both campaigns must name the same exact provider");
  if (attestation?.attestor?.authority_ref !== expectedProvider) fail("placement_attestor_authority_mismatch", "attestor.authority_ref", "attestor authority must resolve to the exact provider address");
  if (derivedProviderAddress && derivedProviderAddress !== expectedProvider) fail("placement_attestor_address_mismatch", "attestor.public_key_ref", "the signing key does not derive to the exact Akash provider address");
  const campaignStatements = Array.isArray(attestation?.campaigns) ? attestation.campaigns : [];
  const campaignMap = new Map(campaignStatements.map((campaign) => [campaign?.campaign_id, campaign]));
  if (campaignStatements.length !== 2 || campaignMap.size !== 2) fail("placement_campaign_set_invalid", "campaigns", "exactly two unique campaign statements are required");
  for (const certificate of certificates) {
    const campaignId = certificate?.authority?.campaign_id;
    const statement = campaignMap.get(campaignId);
    if (!statement
        || String(statement.dseq) !== String(certificate?.provider?.dseq)
        || statement.image_digest !== certificate?.authority?.image_digest
        || !Number.isFinite(Date.parse(statement.observed_from || ""))
        || !Number.isFinite(Date.parse(statement.observed_until || ""))
        || Date.parse(statement.observed_until) <= Date.parse(statement.observed_from)) {
      fail("placement_campaign_binding_mismatch", `campaigns.${campaignId}`, "campaign ID, dseq, image, or observation interval differs");
    }
  }

  const placement = attestation?.placement || {};
  const allowedClasses = ["reserved_bare_metal", "dedicated_physical_cores", "shared_container"];
  if (!allowedClasses.includes(placement.class)) fail("placement_class_invalid", "placement.class", "unknown placement class");
  const cpu = placement.cpu || {};
  const memory = placement.memory || {};
  if (!hash(placement.host_fingerprint)
      || typeof cpu.vendor !== "string"
      || !cpu.vendor.trim()
      || typeof cpu.family_model !== "string"
      || !cpu.family_model.trim()
      || !Number.isSafeInteger(cpu.sockets)
      || cpu.sockets < 1
      || !Number.isSafeInteger(cpu.physical_cores)
      || cpu.physical_cores < 8
      || !Number.isSafeInteger(cpu.threads)
      || cpu.threads < cpu.physical_cores
      || !["enabled", "disabled"].includes(cpu.smt)
      || typeof cpu.governor_or_frequency_posture !== "string"
      || !cpu.governor_or_frequency_posture.trim()
      || typeof cpu.maximum_overcommit_ratio !== "string"
      || !Number.isSafeInteger(memory.limit_bytes)
      || memory.limit_bytes < 17_179_869_184) {
    fail("placement_hardware_facts_invalid", "placement", "host fingerprint, CPU, or memory facts are incomplete");
  }
  if (placement.class === "reserved_bare_metal" && (
    placement.same_physical_host !== true
    || cpu.maximum_overcommit_ratio !== "1:1"
    || memory.ballooning !== false
    || memory.host_swap_during_interval !== false
  )) fail("placement_bare_metal_facts_insufficient", "placement", "reserved bare metal requires same host, 1:1 cores, no ballooning, and no host swap");
  if (placement.class === "dedicated_physical_cores" && (
    cpu.maximum_overcommit_ratio !== "1:1"
    || memory.ballooning !== false
    || memory.host_swap_during_interval !== false
  )) fail("placement_dedicated_cpu_facts_insufficient", "placement", "dedicated CPU requires 1:1 cores, no ballooning, and no host swap");

  const classification = placement.class === "reserved_bare_metal"
    ? "qualified_reserved_bare_metal"
    : placement.class === "dedicated_physical_cores"
      ? "provider_attested_dedicated_cpu"
      : "same_provider_container_unknown_host";
  return {
    ok: failures.length === 0,
    failures,
    classification: failures.length === 0 ? classification : "same_provider_container_unknown_host",
    attestation_sha256: `sha256:${crypto.createHash("sha256").update(stableStringify(attestation)).digest("hex")}`,
    public_key_fingerprint: fingerprint,
    derived_provider_address: derivedProviderAddress,
    campaign_certificate_hashes: certificates.map((certificate) => certificate.certificate_hash),
  };
}
