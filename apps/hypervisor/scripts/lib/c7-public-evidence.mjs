import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { stableStringify, validateCertificate } from "./c7-c8-certificate.mjs";

const sha256Bytes = (value) => `sha256:${crypto.createHash("sha256").update(value).digest("hex")}`;
const sha256Text = (value) => sha256Bytes(Buffer.from(String(value), "utf8"));
const hashLocator = (value) => value ? sha256Text(value) : null;

const forbiddenPatterns = [
  { code: "bearer_session", pattern: /ioi_(?:sess|bootstrap)_[A-Za-z0-9_-]+/u },
  { code: "credential_key", pattern: /"(?:password|session_token|api_key|sealed_token|recovery_material|mnemonic|private_key|access_token|refresh_token)"\s*:/iu },
  { code: "private_key_pem", pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/u },
  { code: "operator_email", pattern: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/iu },
  { code: "absolute_home_path", pattern: /(?:^|["'\s])\/(?:home|Users)\/[A-Za-z0-9._-]+\//u },
  { code: "provider_account_locator", pattern: /provider-account:\/\//u },
];

export function assertDisclosureSafe(value, canary = "") {
  const serialized = typeof value === "string" ? value : stableStringify(value);
  const failures = forbiddenPatterns
    .filter(({ pattern }) => pattern.test(serialized))
    .map(({ code }) => code);
  if (canary && serialized.includes(canary)) failures.push("seeded_canary");
  if (failures.length > 0) {
    throw new Error(`public evidence disclosure scan refused: ${[...new Set(failures)].join(",")}`);
  }
}

function publicFacets(certificate) {
  const facets = structuredClone(certificate.authority.reviewed_facets);
  delete facets.provider_account_ref;
  delete facets.sdl_yaml;
  return facets;
}

export function buildPublicEvidence(certificate, verification) {
  const structural = validateCertificate(certificate);
  if (!structural.ok) {
    throw new Error(`certificate is not structurally valid: ${JSON.stringify(structural.failures)}`);
  }
  if (certificate.source.publication_eligible !== true) {
    throw new Error("certificate is not publication eligible");
  }
  if (verification?.ok !== true || verification?.mutations?.ok !== true) {
    throw new Error("independent verification and mutation testing must both pass");
  }
  if (!Number.isSafeInteger(verification.mutations.mutation_count) || verification.mutations.mutation_count < 20) {
    throw new Error("public evidence requires the corrected adversarial mutation suite");
  }

  const summary = {
    schema_version: "ioi.hypervisor.c7-c8-public-evidence.v1",
    certified_scope: certificate.claims.certified_scope,
    certificate: {
      schema_version: certificate.schema_version,
      certificate_hash: certificate.certificate_hash,
      verifier_schema_version: verification.schema_version,
      verifier_passed: true,
      adversarial_mutation_count: verification.mutations.mutation_count,
    },
    source: certificate.source,
    authority: {
      custody_tier: "sovereign-local",
      policy_hash: certificate.authority.policy_hash,
      request_hash: certificate.authority.request_hash,
      reviewed_facets: publicFacets(certificate),
      authenticated_operator_principal_hash: hashLocator(certificate.operator.principal_ref),
      grant_ref_hash: hashLocator(certificate.authority.grant_ref),
      lease_ref_hash: hashLocator(certificate.authority.lease.lease_ref),
      usage_count: certificate.authority.lease.usage_count,
      remaining_calls: certificate.authority.lease.remaining_calls,
      terminal_state: certificate.authority.lease.state,
    },
    workload: certificate.workload,
    proposal: {
      source: certificate.proposal.source,
      proposal_ref_hash: hashLocator(certificate.proposal.proposal_ref),
      admission_receipt_ref_hash: hashLocator(certificate.proposal.admission_receipt_ref),
      consumption_receipt_ref_hash: hashLocator(certificate.proposal.consumption_receipt_ref),
      admission_root: certificate.proposal.admission_root,
      consumption_root: certificate.proposal.consumption_root,
      request_hash: certificate.proposal.request_hash,
      consumed_once: certificate.proposal.consumed_once,
    },
    journal: certificate.journal,
    provider: certificate.provider,
    teardown: certificate.teardown,
    settlement: certificate.settlement,
    negative_receipt_hashes: certificate.negative_receipts.map(hashLocator),
    claims: certificate.claims,
    nonclaims: certificate.nonclaims,
    durable: {
      environment_ref_hash: hashLocator(certificate.durable.environment_ref),
      locator_hashes: Object.fromEntries(
        Object.entries(certificate.durable)
          .filter(([key]) => key.endsWith("_id") || key.endsWith("_ref"))
          .map(([key, value]) => [key, hashLocator(value)]),
      ),
      substrate_muxlog_bytes: certificate.durable.substrate_muxlog_bytes,
      substrate_muxlog_prefix_sha256: certificate.durable.substrate_muxlog_prefix_sha256,
    },
  };
  assertDisclosureSafe(summary);
  return summary;
}

const mediaType = (name) => name.endsWith(".json")
  ? "application/json"
  : name.endsWith(".yaml") ? "application/yaml" : "text/plain";

function writeAtomic(file, bytes) {
  const temporary = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(temporary, bytes, { mode: 0o644, flag: "wx" });
  fs.renameSync(temporary, file);
}

export function writePublicEvidenceBundle(outputDir, summary, verification, canary = "") {
  fs.mkdirSync(outputDir, { recursive: true, mode: 0o755 });
  const existing = fs.readdirSync(outputDir);
  if (existing.length > 0) throw new Error("public evidence output directory must be empty");
  const files = new Map([
    ["public-evidence.json", `${JSON.stringify(summary, null, 2)}\n`],
    ["claims-and-nonclaims.json", `${JSON.stringify({ schema_version: "ioi.hypervisor.c7-c8-claims.v1", claims: summary.claims, nonclaims: summary.nonclaims }, null, 2)}\n`],
    ["verification-summary.json", `${JSON.stringify({ schema_version: verification.schema_version, ok: verification.ok, mutation_count: verification.mutations.mutation_count, mutation_failures: verification.mutations.failures }, null, 2)}\n`],
    ["redacted-sdl.yaml", summary.workload.redacted_sdl],
  ]);
  for (const [name, bytes] of files) {
    assertDisclosureSafe(bytes, canary);
    writeAtomic(path.join(outputDir, name), bytes);
  }
  const entries = [...files.keys()].sort().map((name) => {
    const bytes = fs.readFileSync(path.join(outputDir, name));
    return { path: name, media_type: mediaType(name), bytes: bytes.length, sha256: sha256Bytes(bytes) };
  });
  const artifactManifest = `${JSON.stringify({ schema_version: "ioi.hypervisor.public-artifact-manifest.v1", entries }, null, 2)}\n`;
  assertDisclosureSafe(artifactManifest, canary);
  writeAtomic(path.join(outputDir, "artifact-manifest.json"), artifactManifest);
  const manifestNames = [...files.keys(), "artifact-manifest.json"].sort();
  const checksumManifest = `${manifestNames.map((name) => `${sha256Bytes(fs.readFileSync(path.join(outputDir, name))).slice(7)}  ${name}`).join("\n")}\n`;
  assertDisclosureSafe(checksumManifest, canary);
  writeAtomic(path.join(outputDir, "manifest.sha256"), checksumManifest);
  for (const name of fs.readdirSync(outputDir)) {
    const file = path.join(outputDir, name);
    if (fs.lstatSync(file).isSymbolicLink() || !fs.lstatSync(file).isFile()) {
      throw new Error(`public evidence contains a non-regular file: ${name}`);
    }
    assertDisclosureSafe(fs.readFileSync(file, "utf8"), canary);
  }
  return { output_dir: outputDir, artifact_count: fs.readdirSync(outputDir).length };
}
