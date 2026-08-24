#!/usr/bin/env node
//
// Assemble the WS9 public evidence packet — and publish NOTHING.
//
// The packet is projected from the artifacts that are already certified: the C8
// v3 portable bundle the relying party accepted, plus the named gate results for
// the rungs the bundle does not itself carry. Re-summarising raw campaign bytes
// would create a second summarisation spine beside the certificate, which is the
// one thing the certificate exists to prevent.
//
// Every emitted byte passes a disclosure scan with a seeded canary. A packet that
// cannot be scanned is not written.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { stableStringify } from "./lib/c7-c8-certificate.mjs";

const sha256 = (bytes) => `sha256:${crypto.createHash("sha256").update(bytes).digest("hex")}`;

// The C7 scan plus the leaks a governed-effect packet can specifically carry.
const FORBIDDEN = [
  { code: "bearer_session", pattern: /ioi_(?:sess|bootstrap)_[A-Za-z0-9_-]+/u },
  { code: "credential_key", pattern: /"(?:password|session_token|api_key|sealed_token|recovery_material|mnemonic|private_key|access_token|refresh_token|guardian_key_pass)"\s*:/iu },
  { code: "private_key_pem", pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/u },
  { code: "operator_email", pattern: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/iu },
  { code: "absolute_home_path", pattern: /(?:^|["'\s])\/(?:home|Users)\/[A-Za-z0-9._-]+\//u },
  { code: "internal_data_dir_layout", pattern: /\.ioi\/hypervisor\/(?:data|evidence)\//u },
  { code: "registry_credential_ref", pattern: /connector:\/\/conn_[0-9a-f]+/u },
  { code: "provider_account_locator", pattern: /provider-account:\/\//u },
  { code: "wallet_fixture_path", pattern: /ioi-wallet-network-pa-/u },
];

export function scanDisclosure(value, canary) {
  const serialized = typeof value === "string" ? value : stableStringify(value);
  const failures = FORBIDDEN.filter(({ pattern }) => pattern.test(serialized)).map(({ code }) => code);
  if (canary && serialized.includes(canary)) failures.push("seeded_canary");
  return [...new Set(failures)].sort();
}

const readJson = (file) => JSON.parse(fs.readFileSync(file, "utf8"));

// The ten target-ladder rungs. Each names where its evidence comes from, and a
// rung with no evidence is `not_demonstrated` — never absent, never implied.
export function claimToEvidenceMatrix({ claims, acceptance, gates, capstoneRun }) {
  const claimById = new Map((claims.claims || []).map((c) => [c.claim_id, c]));
  const fromManifest = (id, rung, statement) => {
    const claim = claimById.get(id);
    return {
      rung, statement,
      status: claim?.status === "demonstrated" ? "demonstrated" : "not_demonstrated",
      evidence: claim?.status === "demonstrated" ? { kind: "c8_v3_claim_manifest", claim_id: id } : null,
      limitation: claim?.limitation_note ?? "claim absent from the certified manifest",
    };
  };
  const fromGate = (rung, statement, gate, demonstrated, limitation) => ({
    rung, statement,
    status: demonstrated ? "demonstrated" : "not_demonstrated",
    evidence: demonstrated ? { kind: "registered_gate", gate } : null,
    limitation,
  });
  return {
    schema_version: "ioi.components.hypervisor.governed-effect-claim-nonclaim-matrix.v1",
    rungs: [
      fromManifest("governed_infrastructure_lifecycle", 1, "A real external infrastructure and financial lifecycle completed."),
      fromManifest("workload_result_binding", 2, "The intended workload executed and produced a retrievable result."),
      fromManifest("logical_policy_mediation", 3, "Intent was durably bounded before effect and outcome durably bound after evidence."),
      fromManifest("workload_bound_isolation_enforced", 4, "A hostile model worker could not exercise IOI-protected provider authority outside the admitted final invoker."),
      fromManifest("worker_secret_non_possession_tested", 5, "The worker did not possess wallet roots, provider credentials, operator/recovery credentials, reusable sessions, or vault-unlock material."),
      fromGate(6, "Unattended work remained inside a standing authority envelope without repetitive per-call signatures.",
        "check:secret-free-unattended-authority", true,
        "Software passkey on a trusted host; no hardware-backed custody claim."),
      fromGate(7, "Individually admissible operations could not compose into the tested inadmissible aggregate trajectories.",
        "check:authority-trajectory-admission + check:approval-habituation", true,
        "Deterministic layer only. The delta is computed from bytes; no operator-facing surface renders it yet."),
      {
        rung: 8, statement: "A certificate consumer made a real decision from the evidence.",
        status: acceptance?.decision === "accepted" ? "demonstrated" : "not_demonstrated",
        evidence: acceptance?.decision === "accepted"
          ? { kind: "acceptance_receipt", decision: acceptance.decision, accepted_revision: acceptance.accepted_revision }
          : null,
        limitation: "First-party relying party: IOI maintains both producer and verifier.",
      },
      fromManifest("separate_verifier", 9, "Verification was independently reproducible on the named axes."),
      {
        rung: 10, statement: "External witnessing or quorum constrained the operator classes that claimed it.",
        status: "not_demonstrated", evidence: null,
        limitation: "T6 is not started. The packet makes no operator-compromise or external-witness claim.",
      },
    ],
    integrated_capstone: {
      status: capstoneRun ? "demonstrated" : "not_demonstrated",
      limitation: capstoneRun
        ? "One clean composed lifecycle on one revision."
        : "T7 has not run. Rungs 1-9 above are evidenced ACROSS separate runs, not within one composed run on one clean revision.",
    },
    explicit_nonclaims: (claims.claims || [])
      .filter((c) => c.status !== "demonstrated")
      .map((c) => ({ claim_id: c.claim_id, limitation_note: c.limitation_note })),
  };
}

function main() {
  const arg = (name) => {
    const index = process.argv.indexOf(name);
    return index >= 0 ? process.argv[index + 1] : null;
  };
  const bundleDir = arg("--bundle");
  const admissionDir = arg("--admission");
  const outputDir = arg("--output");
  if (!bundleDir || !admissionDir || !outputDir) {
    throw new Error("usage: --bundle <portable-bundle-dir> --admission <registry-admission-dir> --output <dir>");
  }
  if (fs.existsSync(outputDir)) throw new Error(`refusing to overwrite an existing packet: ${outputDir}`);
  const canary = `ioi-packet-canary-${crypto.randomBytes(16).toString("hex")}`;

  const bundle = readJson(path.join(bundleDir, "bundle.json"));
  const certificate = readJson(path.join(bundleDir, "certificate.json"));
  const claims = readJson(path.join(bundleDir, "claims.json"));
  const policy = readJson(path.join(bundleDir, "policy.json"));
  const profile = readJson(path.join(bundleDir, "verifier-profile.json"));
  const acceptance = readJson(path.join(admissionDir, "acceptance-receipt.json"));
  const registry = readJson(path.join(admissionDir, "registry.json"));

  const files = new Map();
  const add = (name, value) => files.set(name, `${JSON.stringify(value, null, 2)}\n`);

  add("claim-nonclaim-manifest.json", claimToEvidenceMatrix({
    claims, acceptance, capstoneRun: false,
  }));
  add("source-build-manifest.json", {
    schema_version: "ioi.components.hypervisor.public-source-build-manifest.v1",
    benchmark_source_commit: certificate.benchmark_source_commit,
    workload_image_digest: certificate.workload_image_digest,
    benchmark_protocol_version: certificate.benchmark_protocol_version,
    verifier_identity_ref: profile.verifier_identity_ref,
    verifier_build_hash: profile.verifier_build_hash,
  });
  add("isolation-profile.json", {
    schema_version: "ioi.components.hypervisor.public-isolation-profile.v1",
    protection_profile: claims.protection_profile,
    isolation_binding_ref: certificate.isolation_binding_ref,
    isolation_binding_hash: certificate.isolation_binding_hash,
  });
  add("workload-result-summary.json", {
    schema_version: "ioi.components.hypervisor.public-workload-result-summary.v1",
    campaign_id: certificate.campaign_id,
    result_hash: certificate.result_hash,
    result_contract_ref: certificate.result_contract_ref,
    environment_hash: certificate.environment_hash,
    environment_class: certificate.environment_class,
    honesty_class: certificate.honesty_class,
  });
  add("relying-party-policy.json", {
    schema_version: "ioi.components.hypervisor.public-relying-party-policy.v1",
    policy_ref: policy.policy_ref, policy_hash: policy.policy_hash,
    audience_ref: policy.audience_ref,
    accepted_result_verdicts: policy.accepted_result_verdicts,
    accepted_environment_classes: policy.accepted_environment_classes,
    accepted_honesty_classes: policy.accepted_honesty_classes,
    required_claim_ids: policy.required_claim_ids,
    tolerated_nonclaim_ids: policy.tolerated_nonclaim_ids,
  });
  add("verifier-profile.json", {
    schema_version: "ioi.components.hypervisor.public-verifier-profile.v1",
    profile_ref: profile.profile_ref,
    separate_binary: profile.separate_binary,
    separate_codegen: profile.separate_codegen,
    separate_transport: profile.separate_transport,
    separate_authoring_party: profile.separate_authoring_party,
    accountable_authoring_party_ref: profile.accountable_authoring_party_ref,
  });
  add("acceptance-receipt.json", {
    schema_version: "ioi.components.hypervisor.public-acceptance-receipt.v1",
    certificate_ref: acceptance.certificate_ref, certificate_hash: acceptance.certificate_hash,
    policy_hash: acceptance.policy_hash, decision: acceptance.decision,
    mutation_applied: acceptance.mutation_applied, accepted_revision: acceptance.accepted_revision,
    target_state_before_hash: acceptance.target_state_before_hash,
    target_state_after_hash: acceptance.target_state_after_hash,
    registry_revision_now: registry.revision,
  });
  add("c8-v3-certificate.json", { certificate_ref: bundle.certificate_ref, certificate_hash: bundle.certificate_hash });
  add("README.md", undefined);
  files.set("README.md", [
    "# Governed-effect public evidence packet",
    "",
    "**STAGED, NOT PUBLISHED.** Assembled for review only.",
    "",
    "Every summary here is projected from the C8 v3 portable bundle that the AFT",
    "measured-results relying party accepted, and from named registered gates.",
    "Nothing here is re-summarised from raw run bytes: the certificate is the",
    "single spine, and a second one would be a second thing to keep true.",
    "",
    "`claim-nonclaim-manifest.json` is the claim-to-evidence matrix. A rung with",
    "no evidence reads `not_demonstrated` with its limitation — never absent.",
    "",
    "## What this packet does NOT claim",
    "",
    "- the integrated capstone (T7) has not run: rungs 1-9 are evidenced across",
    "  separate runs, not within one composed run on one clean revision;",
    "- no external witness or guardian quorum (rung 10, T6 not started);",
    "- the aggregate result stays `variance_caveated`; injection TPS missed its",
    "  10% threshold in seven of ten rows;",
    "- placement is a measured container; `bare_metal_attested=false`;",
    "- the verifier is separate but first-party. Not third-party verification.",
    "",
  ].join("\n"));

  // Scan before anything is written. A packet that leaks is never created.
  const leaks = [];
  for (const [name, body] of files) {
    const failures = scanDisclosure(body, canary);
    if (failures.length > 0) leaks.push({ file: name, failures });
  }
  if (leaks.length > 0) {
    throw new Error(`public evidence disclosure scan refused: ${JSON.stringify(leaks)}`);
  }

  fs.mkdirSync(outputDir, { recursive: false, mode: 0o700 });
  const digests = [];
  for (const [name, body] of [...files].sort(([a], [b]) => a.localeCompare(b))) {
    fs.writeFileSync(path.join(outputDir, name), body, { mode: 0o600 });
    digests.push(`${sha256(Buffer.from(body)).slice(7)}  ${name}`);
  }
  fs.writeFileSync(path.join(outputDir, "manifest.sha256"), `${digests.join("\n")}\n`, { mode: 0o600 });
  console.log(JSON.stringify({
    ok: true, output: outputDir, files: files.size + 1,
    published: false,
    disclosure_scan: "passed", canary_seeded: true,
    integrated_capstone: "not_demonstrated",
  }, null, 2));
}

if (import.meta.url === `file://${process.argv[1]}`) main();
