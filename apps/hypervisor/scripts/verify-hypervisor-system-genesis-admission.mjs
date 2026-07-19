#!/usr/bin/env node
// Autonomous System genesis admission live verifier. Every mutation runs against a throwaway
// daemon and every successful authority decision traverses the real wallet.network fixture.

import { createHash } from "node:crypto";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { mintApprovalGrant } from "../../../scripts/lib/mint-approval-grant.mjs";
import { startIsolatedPlane } from "./lib/isolated-daemon.mjs";
import { startRealWalletNetworkPrincipalAuthorityFixture } from "./lib/wallet-network-principal-authority-fixture.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, "..", "..", "..");
const FIXTURES = join(REPO, "docs", "architecture", "_meta", "schemas", "fixtures");
const SYSTEM_GENESIS_SOURCE = join(
  REPO,
  "crates",
  "node",
  "src",
  "bin",
  "hypervisor_daemon_routes",
  "system_genesis_routes.rs",
);
const ROUTE = "/v1/hypervisor/autonomous-systems";
const PROPOSER = "project://acme/outcome-operator";
const OWNER = "org://acme/research";
const SYSTEM_ID = "system://acme/system-alpha";
const GENESIS_REF = "genesis://acme/system-alpha/zero";
const RECORD_FAMILY = "autonomous-system-genesis-registry";
const RECEIPT_FAMILY = "autonomous-system-genesis-receipts";
const INTENT_FAMILY = "autonomous-system-genesis-intents";
const CONSUMPTION_FAMILY = "autonomous-system-genesis-authority-consumptions";
const SYSTEM_FAMILIES = [
  RECORD_FAMILY,
  RECEIPT_FAMILY,
  INTENT_FAMILY,
  CONSUMPTION_FAMILY,
];
const REQUIRED_SCOPE = "scope:autonomous_system.genesis_admit";
const REAL_DATA_DIR =
  process.env.IOI_HYPERVISOR_DATA_DIR || `${process.env.HOME}/.ioi/hypervisor/data`;
const TEMP_PREFIXES = [
  "ioi-isolated-plane-",
  "ioi-system-genesis-fault-",
  "ioi-system-genesis-agentgres-durability-",
  "ioi-system-genesis-required-",
  "ioi-system-genesis-wallet-consumption-",
  "ioi-system-genesis-binding-revocation-",
  "ioi-wallet-network-pa-",
];

const EXPECTED = {
  componentSetHash: "sha256:8cd8d649b1ae06bb99cf6cbe9fa671ef47b48ca523cbdce8b943224c279340fc",
  releaseRoot: "sha256:78ca76fbeb4fc51bdc114f68afd9078cedf52c8a3760ed1e2bb3be173091858b",
  bundleRoot: "sha256:eba5d6e0594d6d3ba68f46c287b30fa5b922fe3ba4a3b740da043180ce422e48",
  operationCommitment:
    "sha256:37b92d683d7b543a26e1e82ab80c54bb4609119047b0957437c52d14cc0bce9d",
  proposalRoot: "sha256:1d337b534c9ee000ba3dafffb86b00ff727e0d58d05468595d037514e43c29c6",
};

const results = [];
const ownedTempPaths = new Set();

function ok(name, pass, detail = "") {
  const result = { name, pass: Boolean(pass), detail };
  results.push(result);
  console.log(`${result.pass ? "PASS" : "FAIL"}: ${name}${detail ? ` - ${detail}` : ""}`);
}

function requireValue(value, message) {
  if (!value) throw new Error(message);
  return value;
}

function clone(value) {
  return structuredClone(value);
}

function fixture(relativePath) {
  return JSON.parse(readFileSync(join(FIXTURES, relativePath), "utf8"));
}

// The fixture corpus contains ordinary JSON values, so this is the exact RFC 8785 ordering and
// ECMAScript primitive serialization used by serde_jcs for these inputs.
function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function sameJson(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

function domainHash(domain, value) {
  const bytes = canonicalJson({ domain, value });
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function recordOutputHash(record, excludes = []) {
  const material = clone(record);
  for (const field of excludes) delete material[field];
  return `sha256:${createHash("sha256").update(canonicalJson(material)).digest("hex")}`;
}

function walletConsumptionReceiptHash(receipt) {
  const material = clone(receipt);
  material.receipt_hash = Array(32).fill(0);
  return [
    ...createHash("sha256").update(canonicalJson(material)).digest(),
  ];
}

function recomputeReleaseHashes(release) {
  const componentMaterial = clone(release.typed_components);
  delete componentMaterial.component_set_hash;
  release.typed_components.component_set_hash = domainHash(
    "ioi.autonomous-system-component-set-jcs-sha256.v1",
    componentMaterial,
  );

  const releaseMaterial = clone(release);
  delete releaseMaterial.release_root;
  delete releaseMaterial.registry_status;
  delete releaseMaterial.receipts.package_readiness_receipt_ref;
  delete releaseMaterial.release.publisher_signature_ref;
  delete releaseMaterial.release.registry_published_at;
  release.release_root = domainHash(
    "ioi.autonomous-system-manifest-release-root-jcs-sha256.v1",
    releaseMaterial,
  );
}

function exactFixtureBody() {
  const release = fixture("autonomous-system-manifest-v1/positive-reusable-release.json");
  recomputeReleaseHashes(release);

  const candidate = fixture("autonomous-system-genesis-v1/positive-proposed.json");
  delete candidate.admitted_manifest_root;
  delete candidate.initial_profile_bundle_root;
  delete candidate.cryptographic_origin.genesis_operation_commitment;
  delete candidate.cryptographic_origin.genesis_transition_commitment_ref;
  candidate.initial_component_bindings.admitted_component_set_hash =
    release.typed_components.component_set_hash;

  return {
    release,
    proposed_instantiation: {
      schema_version: "ioi.autonomous-system-genesis-proposal-input.v1",
      candidate,
      template_bindings: {
        constitution_template_ref: release.constitution_template_ref,
        deployment_template_ref:
          release.required_profile_templates.deployment_template_ref,
        ordering_admission_finality_template_ref:
          release.required_profile_templates.ordering_admission_finality_template_ref,
        oracle_evidence_template_refs:
          release.required_profile_templates.oracle_evidence_template_refs,
        lifecycle_continuity_template_ref:
          release.required_profile_templates.lifecycle_continuity_template_ref,
        network_enrollment_constraint_ref:
          release.required_profile_templates.network_enrollment_constraint_ref,
      },
      constitution: fixture("autonomous-system-constitution-v1/positive-draft.json"),
      ordering_profile: fixture(
        "ordering-admission-finality-profile-v1/positive-single-authority.json",
      ),
      oracle_profiles: [
        fixture("oracle-evidence-profile-v1/positive-fail-closed.json"),
      ],
      lifecycle_profile: fixture(
        "lifecycle-continuity-profile-v1/positive-successor-governed.json",
      ),
      network_enrollment: null,
    },
  };
}

function familyNames(dataDir, family) {
  try {
    return readdirSync(join(dataDir, family))
      .filter((name) => name.endsWith(".json"))
      .sort();
  } catch {
    return [];
  }
}

function familyCounts(dataDir) {
  return Object.fromEntries(
    SYSTEM_FAMILIES.map((family) => [family, familyNames(dataDir, family).length]),
  );
}

function collectJsonFiles(root, current = root, output = []) {
  let entries;
  try {
    entries = readdirSync(current, { withFileTypes: true });
  } catch {
    return output;
  }
  for (const entry of entries) {
    const absolute = join(current, entry.name);
    const relative = absolute.slice(root.length + 1);
    if (entry.isDirectory()) {
      collectJsonFiles(root, absolute, output);
    } else if (entry.isFile() && entry.name.endsWith(".json")) {
      output.push([relative, readFileSync(absolute, "utf8")]);
    }
  }
  return output.sort(([left], [right]) => left.localeCompare(right));
}

function jsonSnapshot(dataDir) {
  return JSON.stringify(collectJsonFiles(dataDir));
}

function tempResidue(root) {
  const residue = [];
  function walk(current) {
    let entries;
    try {
      entries = readdirSync(current, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const absolute = join(current, entry.name);
      if (entry.name.includes(".tmp-")) residue.push(absolute);
      if (entry.isDirectory()) walk(absolute);
    }
  }
  walk(root);
  return residue.sort();
}

function daemonLogText(dataDir) {
  try {
    return readdirSync(dataDir)
      .filter((name) => name.endsWith(".log"))
      .sort()
      .map((name) => readFileSync(join(dataDir, name), "utf8"))
      .join("\n");
  } catch {
    return "";
  }
}

function tempDataEntries() {
  try {
    return readdirSync(tmpdir(), { withFileTypes: true })
      .filter(
        (entry) =>
          entry.isDirectory() &&
          TEMP_PREFIXES.some((prefix) => entry.name.startsWith(prefix)),
      )
      .map((entry) => entry.name)
      .sort();
  } catch {
    return [];
  }
}

async function jsonCall(base, method, path, body) {
  const response = await fetch(`${base}${path}`, {
    method,
    headers: { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return {
    status: response.status,
    body: await response.json().catch(() => ({})),
  };
}

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function pollJson(call, accept, timeoutMs = 90_000) {
  const deadline = Date.now() + timeoutMs;
  let last;
  while (Date.now() < deadline) {
    last = await call();
    if (accept(last)) return last;
    await delay(50);
  }
  return last;
}

function requiredDomainState(status, family) {
  const domain = status?.body?.engine_domains?.[family];
  if (
    !domain ||
    domain.root === null ||
    domain.root === undefined ||
    domain.admitted_seq === null ||
    domain.admitted_seq === undefined
  ) {
    return null;
  }
  return {
    root: domain.root,
    admitted_seq: domain.admitted_seq,
  };
}

function blockerPairs(response) {
  return (response.body.error?.blocker_report?.blockers || []).map((blocker) => [
    blocker.code,
    blocker.path,
  ]);
}

async function compilerRefusal(call, dataDir, name, mutate, expectedPairs, exact = false) {
  const body = exactFixtureBody();
  mutate(body);
  const before = jsonSnapshot(dataDir);
  const response = await call("POST", ROUTE, body);
  const after = jsonSnapshot(dataDir);
  const actualPairs = blockerPairs(response);
  const expectedPresent = expectedPairs.every(([code, path]) =>
    actualPairs.some(([actualCode, actualPath]) => actualCode === code && actualPath === path),
  );
  const report = response.body.error?.blocker_report;
  const exactMatch = !exact || sameJson(actualPairs, expectedPairs);
  ok(
    name,
    response.status === 422 &&
      response.body.error?.code === "system_genesis_proposal_invalid" &&
      report?.schema_version === "ioi.autonomous-system-genesis-blocker-report.v1" &&
      expectedPresent &&
      exactMatch &&
      !response.body.error?.approval &&
      before === after,
    `${response.status}/${response.body.error?.code || "no-code"} blockers=${JSON.stringify(actualPairs)} zero_write=${before === after}`,
  );
  return response;
}

function expectedBoundFacts(record) {
  const genesis = record.authorized_genesis;
  return {
    package_id: record.package_id,
    manifest_ref: record.manifest_ref,
    manifest_release_root: record.admitted_manifest_root,
    manifest_release_payload_hash: record.manifest_release_payload_hash,
    proposed_instantiation_payload_hash: record.proposed_instantiation_payload_hash,
    system_id: record.system_id,
    genesis_ref: record.genesis_ref,
    constitution_ref: genesis.constitution_ref,
    constitution_root: record.initial_profile_bundle.constitution.constitution_root,
    initial_profile_refs: genesis.initial_profile_refs,
    governing_decision_ref: record.governing_decision_ref,
    proposed_by_ref: record.proposed_by_ref,
    governing_authority_ref: record.governing_authority_ref,
    canonical_authority_grant_ref: record.canonical_authority_grant_ref,
    wallet_authority_grant_ref: record.wallet_authority_grant_ref,
    wallet_grant_consumption_ref: record.wallet_grant_consumption_ref,
    wallet_grant_consumption_evidence_ref:
      record.wallet_grant_consumption_evidence_ref,
    sequence: genesis.cryptographic_origin.sequence,
    proposal_root: record.proposal_root,
    initial_profile_bundle_root: record.initial_profile_bundle_root,
    genesis_operation_commitment:
      genesis.cryptographic_origin.genesis_operation_commitment,
    genesis_transition_commitment_ref:
      genesis.cryptographic_origin.genesis_transition_commitment_ref,
    initial_state_root: genesis.cryptographic_origin.initial_state_root,
    initial_receipt_root: genesis.cryptographic_origin.initial_receipt_root,
    genesis_status: "authorized",
    active_profile_materialization_admitted: false,
    activation_admitted: false,
    runtime_effect_admitted: false,
  };
}

async function challengeAndGrant(call, resolver, body) {
  const challenge = await call("POST", ROUTE, body);
  const approval = challenge.body.error?.approval;
  const grant =
    approval?.policy_hash && approval?.request_hash
      ? resolver.mintForCapability(
          OWNER,
          approval.policy_hash,
          approval.request_hash,
        )
      : null;
  if (grant) {
    await resolver.recordApproval(
      OWNER,
      approval.policy_hash,
      approval.request_hash,
      grant,
    );
  }
  return { challenge, grant };
}

async function runPrimaryJourney(resolver) {
  const plane = await startIsolatedPlane({ serve: false, env: resolver.env });
  if (!plane) throw new Error("BLOCKED: target/debug/hypervisor-daemon is not built");
  ownedTempPaths.add(plane.dataDir);
  const call = (method, path, body) => jsonCall(plane.daemonUrl, method, path, body);

  try {
    const startupJson = new Map(collectJsonFiles(plane.dataDir));
    const fixtureBody = exactFixtureBody();
    const routeSource = readFileSync(SYSTEM_GENESIS_SOURCE, "utf8");
    const readStart = routeSource.indexOf("fn handle_get_tail(");
    const readEnd = routeSource.indexOf(
      "\npub(crate) async fn complete_governed_system_genesis_intents",
      readStart,
    );
    const exactRead = routeSource.slice(readStart, readEnd);
    const lockAt = exactRead.indexOf("let _plane = SYSTEM_GENESIS_LOCK");
    const intentScanAt = exactRead.indexOf("scan_intents(data_dir)");
    const recordReadAt = exactRead.indexOf("load_record(data_dir, tail)");
    ok(
      "VISIBILITY: one plane lock encloses the exact intent scan and record read",
      readStart >= 0 &&
        readEnd > readStart &&
        lockAt >= 0 &&
        lockAt < intentScanAt &&
        intentScanAt < recordReadAt &&
        !exactRead.slice(lockAt, recordReadAt).includes("drop(_plane)"),
      `lock=${lockAt} scan=${intentScanAt} read=${recordReadAt}`,
    );
    ok(
      "AUTHORITY DISCIPLINE: production admission consumes a recorded wallet grant and never records approvals itself",
      routeSource.includes("consume_wallet_grant_for_intent") &&
        !routeSource.includes("record_approval"),
      `consume=${routeSource.includes("consume_wallet_grant_for_intent")} production_record=${routeSource.includes("record_approval")}`,
    );
    ok(
      "FIXTURE: exact compiler inputs reconstruct both immutable release commitments",
      fixtureBody.release.typed_components.component_set_hash === EXPECTED.componentSetHash &&
        fixtureBody.release.release_root === EXPECTED.releaseRoot &&
        fixtureBody.proposed_instantiation.candidate.admitted_manifest_root === undefined &&
        fixtureBody.proposed_instantiation.candidate.initial_profile_bundle_root === undefined &&
        fixtureBody.proposed_instantiation.candidate.cryptographic_origin
          .genesis_operation_commitment === undefined &&
        fixtureBody.proposed_instantiation.candidate.cryptographic_origin
          .genesis_transition_commitment_ref === undefined,
      `${fixtureBody.release.typed_components.component_set_hash}/${fixtureBody.release.release_root}`,
    );

    await compilerRefusal(
      call,
      plane.dataDir,
      "COMPILER: upgrade-only release returns the exact blocker before authority with zero mutation",
      (body) => {
        body.release.system_binding.allowed_use = "upgrade_existing";
        recomputeReleaseHashes(body.release);
      },
      [["new_system_instantiation_forbidden", "$.release.system_binding.allowed_use"]],
      true,
    );
    const secretSentinel = "SENTINEL_SYSTEM_GENESIS_SECRET_DO_NOT_PERSIST";
    const secretBody = exactFixtureBody();
    secretBody.proposed_instantiation.constitution.declared_purpose.audit = {
      api_key: secretSentinel,
    };
    const beforeSecret = jsonSnapshot(plane.dataDir);
    const secretResponse = await call("POST", ROUTE, secretBody);
    const afterSecret = jsonSnapshot(plane.dataDir);
    const serializedSecretResponse = JSON.stringify(secretResponse.body);
    const localJsonEvidence = JSON.stringify(collectJsonFiles(plane.dataDir));
    const localDaemonLogs = daemonLogText(plane.dataDir);
    ok(
      "INTAKE: recursive plaintext secret is typed, zero-write, and the sentinel is absent",
      secretResponse.status === 422 &&
        secretResponse.body.error?.code ===
          "system_genesis_plaintext_secret_rejected" &&
        !secretResponse.body.error?.approval &&
        beforeSecret === afterSecret &&
        !serializedSecretResponse.includes(secretSentinel) &&
        !localJsonEvidence.includes(secretSentinel) &&
        !localDaemonLogs.includes(secretSentinel),
      `${secretResponse.status}/${secretResponse.body.error?.code || "no-code"} response_clean=${!serializedSecretResponse.includes(secretSentinel)} json_clean=${!localJsonEvidence.includes(secretSentinel)} log_clean=${!localDaemonLogs.includes(secretSentinel)}`,
    );
    await compilerRefusal(
      call,
      plane.dataDir,
      "COMPILER: recursive unknown field is rejected before authority with zero mutation",
      (body) => {
        body.proposed_instantiation.candidate.cryptographic_origin.unknown_commitment =
          "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
      },
      [
        [
          "unknown_property",
          "$.proposed.candidate.cryptographic_origin.unknown_commitment",
        ],
      ],
    );
    await compilerRefusal(
      call,
      plane.dataDir,
      "COMPILER: activation claim is rejected before authority with zero mutation",
      (body) => {
        body.proposed_instantiation.candidate.activation_receipt_ref =
          "receipt://acme/system-alpha/forged-activation";
      },
      [
        [
          "genesis_activation_claim_forbidden",
          "$.proposed.candidate.activation_receipt_ref",
        ],
      ],
    );

    const topLevelUnknown = exactFixtureBody();
    topLevelUnknown.activation = true;
    const beforeTopLevel = jsonSnapshot(plane.dataDir);
    const topLevelResponse = await call("POST", ROUTE, topLevelUnknown);
    ok(
      "SHAPE: route-owned top-level field is rejected before authority with zero mutation",
      topLevelResponse.status === 422 &&
        topLevelResponse.body.error?.code === "system_genesis_field_unknown" &&
        !topLevelResponse.body.error?.approval &&
        beforeTopLevel === jsonSnapshot(plane.dataDir),
      `${topLevelResponse.status}/${topLevelResponse.body.error?.code || "no-code"}`,
    );

    const multiOwnerBody = exactFixtureBody();
    multiOwnerBody.proposed_instantiation.constitution.governance.governance_owner_refs.push(
      "domain://acme-host",
    );
    const beforeMultiOwner = jsonSnapshot(plane.dataDir);
    const multiOwner = await call("POST", ROUTE, multiOwnerBody);
    ok(
      "AUTHORITY: multi-owner constitution is typed unavailable until authority aggregation exists",
      multiOwner.status === 501 &&
        multiOwner.body.error?.code ===
          "system_genesis_authority_aggregation_unavailable" &&
        !multiOwner.body.error?.approval &&
        beforeMultiOwner === jsonSnapshot(plane.dataDir),
      `${multiOwner.status}/${multiOwner.body.error?.code || "no-code"}`,
    );

    const beforeAuthority = jsonSnapshot(plane.dataDir);
    const { challenge, grant } = await challengeAndGrant(call, resolver, fixtureBody);
    ok(
      "AUTHORITY: exact compiled proposal receives a 403 scope-bound wallet challenge",
      challenge.status === 403 &&
        challenge.body.error?.code === "system_genesis_host_authority_required" &&
        challenge.body.error?.required_scope === REQUIRED_SCOPE &&
        challenge.body.error?.required_authority_ref === OWNER &&
        challenge.body.error?.approval?.policy_hash?.startsWith("sha256:") &&
        challenge.body.error?.approval?.request_hash?.startsWith("sha256:") &&
        challenge.body.error?.approval?.effect_hash?.startsWith("sha256:") &&
        beforeAuthority === jsonSnapshot(plane.dataDir),
      `${challenge.status}/${challenge.body.error?.required_scope || "no-scope"}`,
    );
    requireValue(grant, `exact proposal did not expose a mintable challenge: ${JSON.stringify(challenge)}`);

    const foreignGrant = mintApprovalGrant({
      seed: "08".repeat(32),
      policyHash: challenge.body.error.approval.policy_hash,
      requestHash: challenge.body.error.approval.request_hash,
      audience: resolver.capabilityAccountId,
    });
    const foreign = await call("POST", ROUTE, {
      ...fixtureBody,
      wallet_approval_grant: foreignGrant,
    });
    ok(
      "AUTHORITY: same-hash foreign signer is refused with zero mutation",
      foreign.status === 403 &&
        foreign.body.error?.code === "system_genesis_host_authority_required" &&
        beforeAuthority === jsonSnapshot(plane.dataDir),
      `${foreign.status}/${foreign.body.error?.code || "no-code"}`,
    );

    const swappedBody = exactFixtureBody();
    swappedBody.proposed_instantiation.constitution.declared_purpose.statement =
      "Pursue bounded research outcomes for accountable project stakeholders with review.";
    const swapped = await call("POST", ROUTE, {
      ...swappedBody,
      wallet_approval_grant: grant,
    });
    ok(
      "AUTHORITY: proposal/body swap under the original signed grant is refused with zero mutation",
      swapped.status === 403 &&
        swapped.body.error?.code === "system_genesis_host_authority_required" &&
        swapped.body.error?.approval?.policy_hash ===
          challenge.body.error.approval.policy_hash &&
        swapped.body.error?.approval?.request_hash !==
          challenge.body.error.approval.request_hash &&
        swapped.body.error?.approval?.effect_hash !==
          challenge.body.error.approval.effect_hash &&
        beforeAuthority === jsonSnapshot(plane.dataDir),
      `${swapped.status}/${swapped.body.error?.code || "no-code"} request_changed=${swapped.body.error?.approval?.request_hash !== challenge.body.error.approval.request_hash}`,
    );

    const releaseProjectionSwap = exactFixtureBody();
    releaseProjectionSwap.release.registry_status = "deprecated";
    const releaseProjectionResponse = await call("POST", ROUTE, {
      ...releaseProjectionSwap,
      wallet_approval_grant: grant,
    });
    ok(
      "AUTHORITY: release fields excluded from release_root still change the exact signed effect",
      releaseProjectionSwap.release.release_root === fixtureBody.release.release_root &&
        releaseProjectionResponse.status === 403 &&
        releaseProjectionResponse.body.error?.code ===
          "system_genesis_host_authority_required" &&
        releaseProjectionResponse.body.error?.approval?.policy_hash ===
          challenge.body.error.approval.policy_hash &&
        releaseProjectionResponse.body.error?.approval?.request_hash !==
          challenge.body.error.approval.request_hash &&
        releaseProjectionResponse.body.error?.approval?.effect_hash !==
          challenge.body.error.approval.effect_hash &&
        beforeAuthority === jsonSnapshot(plane.dataDir),
      `${releaseProjectionResponse.status}/${releaseProjectionResponse.body.error?.code || "no-code"} release_root_same=${releaseProjectionSwap.release.release_root === fixtureBody.release.release_root} effect_changed=${releaseProjectionResponse.body.error?.approval?.effect_hash !== challenge.body.error.approval.effect_hash}`,
    );

    const admitted = await call("POST", ROUTE, {
      ...fixtureBody,
      wallet_approval_grant: grant,
    });
    const record = admitted.body.autonomous_system_genesis_admission;
    const receipt = admitted.body.autonomous_system_genesis_receipt;
    ok(
      "ADMIT: real signed wallet grant commits one authorized admission and receipt",
      admitted.status === 201 &&
        record?.system_id === SYSTEM_ID &&
        record?.genesis_ref === GENESIS_REF &&
        receipt?.receipt_type === "AutonomousSystemGenesisReceipt" &&
        receipt?.principal_authority_binding?.principal_ref === OWNER &&
        receipt?.principal_authority_binding?.required_scope === REQUIRED_SCOPE &&
        Boolean(receipt?.wallet_approval_grant?.approver_sig) &&
        admitted.body.wallet_grant_consumption_receipt?.usage_ordinal === 1 &&
        admitted.body.wallet_grant_consumption_receipt?.remaining_usages === 0,
      `${admitted.status}/${record?.admission_id || admitted.body.error?.code || "no-record"}`,
    );
    requireValue(record, `signed admission did not return a record: ${JSON.stringify(admitted)}`);
    requireValue(receipt, `signed admission did not return a receipt: ${JSON.stringify(admitted)}`);

    const recordKey = String(record.admission_id).replace(
      "system-genesis-admission://",
      "",
    );
    const receiptKey = String(receipt.receipt_ref).replace("receipt://", "");
    const consumptionKey = String(record.wallet_grant_consumption_evidence_ref).replace(
      "system-genesis-authority-consumption://",
      "",
    );
    const recordPath = join(plane.dataDir, RECORD_FAMILY, `${recordKey}.json`);
    const receiptPath = join(plane.dataDir, RECEIPT_FAMILY, `${receiptKey}.json`);
    const consumptionPath = join(
      plane.dataDir,
      CONSUMPTION_FAMILY,
      `${consumptionKey}.json`,
    );
    const persistedRecord = JSON.parse(readFileSync(recordPath, "utf8"));
    const persistedReceipt = JSON.parse(readFileSync(receiptPath, "utf8"));
    const persistedConsumption = JSON.parse(readFileSync(consumptionPath, "utf8"));

    ok(
      "COMPILE: admitted record binds the exact fixture release and all compiler golden roots",
      sameJson(record.manifest_release, fixtureBody.release) &&
        record.manifest_release_payload_hash === recordOutputHash(fixtureBody.release) &&
        record.proposed_instantiation_payload_hash ===
          recordOutputHash(fixtureBody.proposed_instantiation) &&
        record.proposal_root === EXPECTED.proposalRoot &&
        record.initial_profile_bundle_root === EXPECTED.bundleRoot &&
        record.authorized_genesis.cryptographic_origin.genesis_operation_commitment ===
          EXPECTED.operationCommitment &&
        record.proposal_hash_profile ===
          "ioi.autonomous-system-genesis-proposal-root-jcs-sha256.v1" &&
        record.initial_profile_bundle_hash_profile ===
          "ioi.autonomous-system-initial-profile-bundle-jcs-sha256.v1" &&
        record.proposal_authority_boundary ===
          "unverified_proposal_only_no_authority_admission_activation_or_effect" &&
        record.proposed_by_ref === PROPOSER &&
        record.governing_authority_ref === OWNER,
      `${record.proposal_root}/${record.initial_profile_bundle_root}`,
    );
    ok(
      "DURABLE: response record and receipt are byte-equivalent to their canonical files",
        sameJson(record, persistedRecord) &&
        sameJson(receipt, persistedReceipt) &&
        sameJson(
          admitted.body.wallet_grant_consumption_receipt,
          persistedConsumption,
        ) &&
        familyNames(plane.dataDir, RECORD_FAMILY).length === 1 &&
        familyNames(plane.dataDir, RECEIPT_FAMILY).length === 1 &&
        familyNames(plane.dataDir, CONSUMPTION_FAMILY).length === 1 &&
        familyNames(plane.dataDir, INTENT_FAMILY).length === 0 &&
        tempResidue(plane.dataDir).length === 0,
      `records=${familyNames(plane.dataDir, RECORD_FAMILY).length} receipts=${familyNames(plane.dataDir, RECEIPT_FAMILY).length} intents=${familyNames(plane.dataDir, INTENT_FAMILY).length}`,
    );

    const bySystem = await call(
      "GET",
      `${ROUTE}?system_id=${encodeURIComponent(SYSTEM_ID)}`,
    );
    const byKey = await call("GET", `${ROUTE}/${recordKey}`);
    ok(
      "GET: exact system_id query and exact deterministic record key return the same admission",
      bySystem.status === 200 &&
        byKey.status === 200 &&
        sameJson(bySystem.body.autonomous_system_genesis_admission, record) &&
        sameJson(byKey.body.autonomous_system_genesis_admission, record) &&
        bySystem.body.authority?.status === "configured" &&
        bySystem.body.authority?.code ===
          "system_genesis_authority_binding_configured" &&
        bySystem.body.authority?.reachability === "not_probed" &&
        byKey.body.nonclaims?.activation === false,
      `${bySystem.status}/${byKey.status}/${recordKey} detail=${bySystem.body.error?.message || byKey.body.error?.message || ""}`,
    );

    const recordBytes = readFileSync(recordPath);
    const receiptBytes = readFileSync(receiptPath);
    const consumptionBytes = readFileSync(consumptionPath);
    const muxPath = join(plane.dataDir, "substrate", "muxlog.bin");
    const muxBytes = readFileSync(muxPath);

    const forgedRecord = clone(persistedRecord);
    forgedRecord.activation_state = "activated";
    writeFileSync(recordPath, JSON.stringify(forgedRecord));
    const forgedRecordRead = await call("GET", `${ROUTE}/${recordKey}`);
    writeFileSync(recordPath, recordBytes);
    ok(
      "GET PROOF: a locally plausible but receipt-inconsistent aggregate refuses typed",
      forgedRecordRead.status === 500 &&
        forgedRecordRead.body.error?.code ===
          "system_genesis_local_evidence_mismatch",
      `${forgedRecordRead.status}/${forgedRecordRead.body.error?.code || "no-code"}`,
    );

    const forgedReceipt = clone(persistedReceipt);
    forgedReceipt.assurance_note = "forged assurance";
    writeFileSync(receiptPath, JSON.stringify(forgedReceipt));
    const forgedReceiptRead = await call("GET", `${ROUTE}/${recordKey}`);
    writeFileSync(receiptPath, receiptBytes);
    ok(
      "GET PROOF: a forged local admission receipt refuses typed",
      forgedReceiptRead.status === 500 &&
        forgedReceiptRead.body.error?.code ===
          "system_genesis_local_evidence_mismatch",
      `${forgedReceiptRead.status}/${forgedReceiptRead.body.error?.code || "no-code"}`,
    );

    const forgedConsumption = clone(persistedConsumption);
    forgedConsumption.consumed_at_ms = Math.max(
      1,
      Number(forgedConsumption.consumed_at_ms) - 1,
    );
    forgedConsumption.receipt_hash =
      walletConsumptionReceiptHash(forgedConsumption);
    writeFileSync(consumptionPath, JSON.stringify(forgedConsumption));
    const forgedConsumptionRead = await call("GET", `${ROUTE}/${recordKey}`);
    writeFileSync(consumptionPath, consumptionBytes);
    ok(
      "GET PROOF: a self-consistent rehashed local wallet-use receipt still refuses against immutable Agentgres evidence",
      forgedConsumptionRead.status === 500 &&
        forgedConsumptionRead.body.error?.code ===
          "system_genesis_agentgres_evidence_mismatch",
      `${forgedConsumptionRead.status}/${forgedConsumptionRead.body.error?.code || "no-code"}`,
    );

    writeFileSync(muxPath, muxBytes.subarray(0, muxBytes.length - 1));
    const truncatedAgentgresRead = await call("GET", `${ROUTE}/${recordKey}`);
    writeFileSync(muxPath, muxBytes);
    const restoredProofRead = await call("GET", `${ROUTE}/${recordKey}`);
    ok(
      "GET PROOF: a truncated Agentgres log refuses typed and exact restoration recovers",
      truncatedAgentgresRead.status === 500 &&
        truncatedAgentgresRead.body.error?.code ===
          "system_genesis_agentgres_evidence_mismatch" &&
        restoredProofRead.status === 200 &&
        sameJson(
          restoredProofRead.body.autonomous_system_genesis_admission,
          persistedRecord,
        ),
      `${truncatedAgentgresRead.status}/${truncatedAgentgresRead.body.error?.code || "no-code"} restored=${restoredProofRead.status}/${restoredProofRead.body.error?.code || "ok"} detail=${restoredProofRead.body.error?.message || ""}`,
    );

    ok(
      "RECEIPT: output hash and complete bound_facts recompute from the persisted record",
      receipt.output_hash ===
        recordOutputHash(persistedRecord, receipt.hash_scope_excludes || []) &&
        sameJson(receipt.bound_facts, expectedBoundFacts(persistedRecord)) &&
        receipt.assurance_posture === "genesis_admitted_not_activated" &&
        sameJson(receipt.authority_scopes, [REQUIRED_SCOPE]) &&
        receipt.authorized_effect?.proposal_root === record.proposal_root &&
        receipt.authorized_effect?.manifest_release_payload_hash ===
          record.manifest_release_payload_hash &&
        receipt.authorized_effect?.proposed_instantiation_payload_hash ===
          record.proposed_instantiation_payload_hash &&
        receipt.authorized_effect?.target_status === "authorized" &&
        receipt.authorized_effect?.activation_admitted === false &&
        receipt.authorized_effect?.runtime_effect_admitted === false,
      `${receipt.output_hash}/bound=${sameJson(receipt.bound_facts, expectedBoundFacts(persistedRecord))}`,
    );

    const nonclaims = admitted.body.nonclaims;
    const genesis = record.authorized_genesis;
    const currentJson = new Map(collectJsonFiles(plane.dataDir));
    const jsonDelta = [...currentJson.keys()]
      .filter((path) => !startupJson.has(path))
      .sort();
    const changedStartupJson = [...startupJson]
      .filter(([path, bytes]) => currentJson.get(path) !== bytes)
      .map(([path]) => path)
      .sort();
    ok(
      "BOUNDARY: authorized is not activated and no runtime, member, or lifecycle effect lands",
      record.admission_status === "authorized" &&
        record.active_profile_materialization_state === "pending_m1_4" &&
        record.activation_state === "not_started" &&
        record.live_runtime_state_created === false &&
        genesis.status === "authorized" &&
        genesis.activation_receipt_ref === null &&
        sameJson(genesis.lifecycle_transition_refs, []) &&
        Object.values(nonclaims || {}).every((claim) => claim === false) &&
        changedStartupJson.length === 0 &&
        sameJson(jsonDelta, [
          `${CONSUMPTION_FAMILY}/${consumptionKey}.json`,
          `${RECEIPT_FAMILY}/${receiptKey}.json`,
          `${RECORD_FAMILY}/${recordKey}.json`,
        ].sort()),
      `status=${record.admission_status}/${genesis.status} json_delta=${JSON.stringify(jsonDelta)} changed_startup=${JSON.stringify(changedStartupJson)}`,
    );

    const beforeDuplicate = jsonSnapshot(plane.dataDir);
    const duplicate = await call("POST", ROUTE, {
      ...fixtureBody,
      wallet_approval_grant: grant,
    });
    ok(
      "IDENTITY: duplicate System/genesis admission is refused with byte-exact zero mutation",
      duplicate.status === 409 &&
        duplicate.body.error?.code === "system_genesis_already_admitted" &&
        beforeDuplicate === jsonSnapshot(plane.dataDir),
      `${duplicate.status}/${duplicate.body.error?.code || "no-code"}`,
    );
  } finally {
    await plane.stop();
  }
}

async function runDurabilityReplay(resolver) {
  const dataDir = mkdtempSync(join(tmpdir(), "ioi-system-genesis-fault-"));
  ownedTempPaths.add(dataDir);
  let plane;
  try {
    plane = await startIsolatedPlane({
      serve: false,
      env: {
        ...resolver.env,
        IOI_TEST_FORCE_DIRSYNC_UNCONFIRMED: RECEIPT_FAMILY,
      },
      dataDir,
    });
    if (!plane) throw new Error("BLOCKED: durability plane could not start");
    const faultCall = (method, path, body) => jsonCall(plane.daemonUrl, method, path, body);
    const body = exactFixtureBody();
    const { challenge, grant } = await challengeAndGrant(faultCall, resolver, body);
    requireValue(grant, `durability lane did not expose a challenge: ${JSON.stringify(challenge)}`);
    const pending = await faultCall("POST", ROUTE, {
      ...body,
      wallet_approval_grant: grant,
    });
    const pendingReceiptName = familyNames(dataDir, RECEIPT_FAMILY)[0];
    const pendingIntentName = familyNames(dataDir, INTENT_FAMILY)[0];
    const pendingReceipt = pendingReceiptName
      ? JSON.parse(readFileSync(join(dataDir, RECEIPT_FAMILY, pendingReceiptName), "utf8"))
      : null;
    const pendingIntent = pendingIntentName
      ? JSON.parse(readFileSync(join(dataDir, INTENT_FAMILY, pendingIntentName), "utf8"))
      : null;
    ok(
      "DURABILITY: forced receipt dirsync uncertainty returns typed pending and retains a sealed intent",
      pending.status === 500 &&
        pending.body.error?.code === "system_genesis_pending_convergence" &&
        familyNames(dataDir, RECEIPT_FAMILY).length === 1 &&
        familyNames(dataDir, RECORD_FAMILY).length === 0 &&
        familyNames(dataDir, INTENT_FAMILY).length === 1 &&
        pendingIntent?.schema_version ===
          "ioi.hypervisor.autonomous-system-genesis-intent.v1" &&
        pendingIntent?.receipt?.wallet_approval_grant?.approver_sig &&
        pendingIntent?.receipt?.principal_authority_binding?.principal_ref === OWNER &&
        sameJson(pendingIntent?.receipt, pendingReceipt) &&
        tempResidue(dataDir).length === 0,
      `${pending.status}/${pending.body.error?.code || "no-code"} counts=${JSON.stringify(familyCounts(dataDir))}`,
    );
    requireValue(
      pendingIntent,
      `durability hook did not leave a replayable intent: ${JSON.stringify(pending)}`,
    );
    const pendingRecordKey = pendingIntent.record_tail;
    const pendingBySystem = await faultCall(
      "GET",
      `${ROUTE}?system_id=${encodeURIComponent(SYSTEM_ID)}`,
    );
    const pendingByKey = await faultCall("GET", `${ROUTE}/${pendingRecordKey}`);
    ok(
      "DURABILITY: exact GETs report pending convergence while the matching intent exists",
      pendingBySystem.status === 500 &&
        pendingBySystem.body.error?.code === "system_genesis_pending_convergence" &&
        pendingByKey.status === 500 &&
        pendingByKey.body.error?.code === "system_genesis_pending_convergence",
      `system=${pendingBySystem.status}/${pendingBySystem.body.error?.code || "no-code"} key=${pendingByKey.status}/${pendingByKey.body.error?.code || "no-code"}`,
    );

    process.kill(plane.daemonPid, "SIGKILL");
    await plane.stop();
    plane = null;

    plane = await startIsolatedPlane({ serve: false, env: resolver.env, dataDir });
    if (!plane) throw new Error("BLOCKED: restart replay plane could not start");
    const replayCall = (method, path, replayBody) =>
      jsonCall(plane.daemonUrl, method, path, replayBody);
    const converged = await pollJson(
      () =>
        replayCall(
          "GET",
          `${ROUTE}?system_id=${encodeURIComponent(SYSTEM_ID)}`,
        ),
      (response) =>
        response.status === 200 && familyNames(dataDir, INTENT_FAMILY).length === 0,
    );
    const replayReceiptName = familyNames(dataDir, RECEIPT_FAMILY)[0];
    const replayReceipt = replayReceiptName
      ? JSON.parse(readFileSync(join(dataDir, RECEIPT_FAMILY, replayReceiptName), "utf8"))
      : null;
    const replayRecord = converged?.body?.autonomous_system_genesis_admission;
    ok(
      "REPLAY: SIGKILL restart reauthorizes and converges the exact receipt plus one immutable record",
      converged?.status === 200 &&
        replayRecord?.system_id === SYSTEM_ID &&
        replayRecord?.genesis_ref === GENESIS_REF &&
        familyNames(dataDir, RECORD_FAMILY).length === 1 &&
        familyNames(dataDir, RECEIPT_FAMILY).length === 1 &&
        familyNames(dataDir, INTENT_FAMILY).length === 0 &&
        sameJson(replayReceipt, pendingReceipt) &&
        replayReceipt?.output_hash === recordOutputHash(replayRecord, []) &&
        tempResidue(dataDir).length === 0,
      `${converged?.status || "no-status"} counts=${JSON.stringify(familyCounts(dataDir))}`,
    );
  } finally {
    if (plane) await plane.stop();
    rmSync(dataDir, { recursive: true, force: true });
  }
}

async function runRequiredDurabilityConfirmation(resolver) {
  const dataDir = mkdtempSync(
    join(tmpdir(), "ioi-system-genesis-agentgres-durability-"),
  );
  ownedTempPaths.add(dataDir);
  let plane;
  const asyncAgentgresEnv = {
    ...resolver.env,
    IOI_SUBSTRATE_ASYNC_FLUSH: "1",
    IOI_SUBSTRATE_REPLICA_ADDRS: "127.0.0.1:1",
  };
  try {
    plane = await startIsolatedPlane({
      serve: false,
      env: {
        ...asyncAgentgresEnv,
        IOI_TEST_FORCE_REQUIRED_ADMISSION_SYNC_FAILURE: "1",
      },
      dataDir,
    });
    if (!plane) throw new Error("BLOCKED: Agentgres durability plane could not start");
    let call = (method, path, body) => jsonCall(plane.daemonUrl, method, path, body);
    const body = exactFixtureBody();
    const { challenge, grant } = await challengeAndGrant(call, resolver, body);
    requireValue(
      grant,
      `Agentgres durability lane did not expose a challenge: ${JSON.stringify(challenge)}`,
    );
    const pending = await call("POST", ROUTE, {
      ...body,
      wallet_approval_grant: grant,
    });
    const status = await call("GET", "/v1/hypervisor/substrate/status");
    ok(
      "AGENTGRES DURABILITY: an unconfirmed required-admission sync retains the intent and refuses success",
      pending.status === 500 &&
        pending.body.error?.code === "system_genesis_agentgres_admission_failed" &&
        familyNames(dataDir, CONSUMPTION_FAMILY).length === 1 &&
        familyNames(dataDir, RECEIPT_FAMILY).length === 0 &&
        familyNames(dataDir, RECORD_FAMILY).length === 0 &&
        familyNames(dataDir, INTENT_FAMILY).length === 1 &&
        status.body.required_admission_durability?.includes(
          "explicit muxlog file sync",
        ) &&
        daemonLogText(dataDir).includes("forcing per-batch sync"),
      `${pending.status}/${pending.body.error?.code || "no-code"} counts=${JSON.stringify(familyCounts(dataDir))}`,
    );

    process.kill(plane.daemonPid, "SIGKILL");
    await plane.stop();
    plane = null;

    plane = await startIsolatedPlane({
      serve: false,
      env: asyncAgentgresEnv,
      dataDir,
    });
    if (!plane) throw new Error("BLOCKED: Agentgres durability restart could not start");
    call = (method, path, restartBody) =>
      jsonCall(plane.daemonUrl, method, path, restartBody);
    const converged = await pollJson(
      () =>
        call(
          "GET",
          `${ROUTE}?system_id=${encodeURIComponent(SYSTEM_ID)}`,
        ),
      (response) =>
        response.status === 200 && familyNames(dataDir, INTENT_FAMILY).length === 0,
    );
    const statusAfter = await call("GET", "/v1/hypervisor/substrate/status");
    ok(
      "AGENTGRES DURABILITY: restart explicitly syncs the exact replay before consuming its anchor",
      converged?.status === 200 &&
        requiredDomainState(statusAfter, RECORD_FAMILY) &&
        requiredDomainState(statusAfter, RECEIPT_FAMILY) &&
        requiredDomainState(statusAfter, CONSUMPTION_FAMILY) &&
        familyNames(dataDir, RECORD_FAMILY).length === 1 &&
        familyNames(dataDir, RECEIPT_FAMILY).length === 1 &&
        familyNames(dataDir, CONSUMPTION_FAMILY).length === 1 &&
        familyNames(dataDir, INTENT_FAMILY).length === 0 &&
        tempResidue(dataDir).length === 0,
      `${converged?.status || "no-status"} counts=${JSON.stringify(familyCounts(dataDir))}`,
    );
  } finally {
    if (plane) await plane.stop();
    rmSync(dataDir, { recursive: true, force: true });
  }
}

async function runRequiredAdmissionBoundary(resolver) {
  const dataDir = mkdtempSync(join(tmpdir(), "ioi-system-genesis-required-"));
  ownedTempPaths.add(dataDir);
  let plane;
  try {
    plane = await startIsolatedPlane({
      serve: false,
      env: {
        ...resolver.env,
        IOI_TEST_FORCE_SYSTEM_GENESIS_AFTER_AGENTGRES: "1",
      },
      dataDir,
    });
    if (!plane) throw new Error("BLOCKED: required-admission plane could not start");
    let call = (method, path, body) => jsonCall(plane.daemonUrl, method, path, body);
    const body = exactFixtureBody();
    const { challenge, grant } = await challengeAndGrant(call, resolver, body);
    requireValue(
      grant,
      `required-admission plane did not expose a challenge: ${JSON.stringify(challenge)}`,
    );
    const pending = await call("POST", ROUTE, {
      ...body,
      wallet_approval_grant: grant,
    });
    const recordNames = familyNames(dataDir, RECORD_FAMILY);
    const receiptNames = familyNames(dataDir, RECEIPT_FAMILY);
    const consumptionNames = familyNames(dataDir, CONSUMPTION_FAMILY);
    const intentNames = familyNames(dataDir, INTENT_FAMILY);
    ok(
      "AGENTGRES FAULT: POST stops pending after exactly one admission in each mandatory evidence domain",
      pending.status === 500 &&
        pending.body.error?.code === "system_genesis_pending_convergence" &&
        recordNames.length === 1 &&
        receiptNames.length === 1 &&
        consumptionNames.length === 1 &&
        intentNames.length === 1 &&
        tempResidue(dataDir).length === 0,
      `${pending.status}/${pending.body.error?.code || "no-code"} counts=${JSON.stringify(familyCounts(dataDir))}`,
    );
    const recordName = requireValue(
      recordNames[0],
      `post-Agentgres fault did not persist a record: ${JSON.stringify(pending)}`,
    );
    const record = JSON.parse(
      readFileSync(join(dataDir, RECORD_FAMILY, recordName), "utf8"),
    );
    const recordKey = recordName.replace(/\.json$/, "");
    requireValue(
      receiptNames[0],
      `post-Agentgres fault did not persist a receipt: ${JSON.stringify(pending)}`,
    );
    requireValue(
      consumptionNames[0],
      `post-Agentgres fault did not persist wallet-use evidence: ${JSON.stringify(pending)}`,
    );
    requireValue(
      intentNames[0],
      `post-Agentgres fault did not retain an intent: ${JSON.stringify(pending)}`,
    );
    const statusBefore = await pollJson(
      () => call("GET", "/v1/hypervisor/substrate/status"),
      (response) =>
        response.status === 200 &&
        requiredDomainState(response, RECORD_FAMILY) &&
        requiredDomainState(response, RECEIPT_FAMILY) &&
        requiredDomainState(response, CONSUMPTION_FAMILY),
    );
    const requiredDomains = statusBefore?.body?.required_admission_domains || [];
    const soakDomains = statusBefore?.body?.soak?.domains || [];
    const recordStateBefore = requiredDomainState(statusBefore, RECORD_FAMILY);
    const receiptStateBefore = requiredDomainState(statusBefore, RECEIPT_FAMILY);
    const consumptionStateBefore = requiredDomainState(
      statusBefore,
      CONSUMPTION_FAMILY,
    );
    const pendingBySystem = await call(
      "GET",
      `${ROUTE}?system_id=${encodeURIComponent(SYSTEM_ID)}`,
    );
    const pendingByKey = await call("GET", `${ROUTE}/${recordKey}`);
    ok(
      "AGENTGRES: all three mandatory evidence domains are admitted without soak while exact GETs remain pending",
      statusBefore?.status === 200 &&
        sameJson(
          [...requiredDomains].sort(),
          [RECORD_FAMILY, RECEIPT_FAMILY, CONSUMPTION_FAMILY].sort(),
        ) &&
        !soakDomains.includes(RECORD_FAMILY) &&
        !soakDomains.includes(RECEIPT_FAMILY) &&
        !soakDomains.includes(CONSUMPTION_FAMILY) &&
        recordStateBefore &&
        receiptStateBefore &&
        consumptionStateBefore &&
        Number(recordStateBefore.admitted_seq) > 0 &&
        Number(receiptStateBefore.admitted_seq) > 0 &&
        Number(consumptionStateBefore.admitted_seq) > 0 &&
        (statusBefore.body.admitted || 0) >= 3 &&
        statusBefore.body.errors === 0 &&
        statusBefore.body.engine_open_error === null &&
        pendingBySystem.status === 500 &&
        pendingBySystem.body.error?.code === "system_genesis_pending_convergence" &&
        pendingByKey.status === 500 &&
        pendingByKey.body.error?.code === "system_genesis_pending_convergence" &&
        familyNames(dataDir, INTENT_FAMILY).length === 1,
      `required=${JSON.stringify(requiredDomains)} admitted=${statusBefore?.body?.admitted ?? "missing"} errors=${statusBefore?.body?.errors ?? "missing"} gets=${pendingBySystem.status}/${pendingByKey.status}`,
    );

    process.kill(plane.daemonPid, "SIGKILL");
    await plane.stop();
    plane = null;

    plane = await startIsolatedPlane({ serve: false, env: resolver.env, dataDir });
    if (!plane) throw new Error("BLOCKED: required-admission restart could not start");
    call = (method, path, restartBody) =>
      jsonCall(plane.daemonUrl, method, path, restartBody);
    const getAfter = await pollJson(
      () => call("GET", `${ROUTE}/${recordKey}`),
      (response) =>
        response.status === 200 && familyNames(dataDir, INTENT_FAMILY).length === 0,
    );
    const getAfterBySystem = await call(
      "GET",
      `${ROUTE}?system_id=${encodeURIComponent(SYSTEM_ID)}`,
    );
    const statusAfter = await pollJson(
      () => call("GET", "/v1/hypervisor/substrate/status"),
      (response) =>
        response.status === 200 &&
        requiredDomainState(response, RECORD_FAMILY) &&
        requiredDomainState(response, RECEIPT_FAMILY) &&
        requiredDomainState(response, CONSUMPTION_FAMILY),
    );
    const recordStateAfter = requiredDomainState(statusAfter, RECORD_FAMILY);
    const receiptStateAfter = requiredDomainState(statusAfter, RECEIPT_FAMILY);
    const consumptionStateAfter = requiredDomainState(
      statusAfter,
      CONSUMPTION_FAMILY,
    );
    const requiredDomainsAfter =
      statusAfter?.body?.required_admission_domains || [];
    const soakDomainsAfter = statusAfter?.body?.soak?.domains || [];
    ok(
      "AGENTGRES REPLAY: SIGKILL restart converges without advancing either required domain",
      getAfter?.status === 200 &&
        sameJson(getAfter.body.autonomous_system_genesis_admission, record) &&
        getAfterBySystem.status === 200 &&
        sameJson(
          getAfterBySystem.body.autonomous_system_genesis_admission,
          record,
        ) &&
        sameJson(
          [...requiredDomainsAfter].sort(),
          [RECORD_FAMILY, RECEIPT_FAMILY, CONSUMPTION_FAMILY].sort(),
        ) &&
        !soakDomainsAfter.includes(RECORD_FAMILY) &&
        !soakDomainsAfter.includes(RECEIPT_FAMILY) &&
        !soakDomainsAfter.includes(CONSUMPTION_FAMILY) &&
        sameJson(recordStateAfter, recordStateBefore) &&
        sameJson(receiptStateAfter, receiptStateBefore) &&
        sameJson(consumptionStateAfter, consumptionStateBefore) &&
        statusAfter?.body?.errors === 0 &&
        statusAfter?.body?.engine_open_error === null &&
        familyNames(dataDir, RECORD_FAMILY).length === 1 &&
        familyNames(dataDir, RECEIPT_FAMILY).length === 1 &&
        familyNames(dataDir, INTENT_FAMILY).length === 0 &&
        tempResidue(dataDir).length === 0,
      `record_state=${JSON.stringify(recordStateBefore)}->${JSON.stringify(recordStateAfter)} receipt_state=${JSON.stringify(receiptStateBefore)}->${JSON.stringify(receiptStateAfter)} consumption_state=${JSON.stringify(consumptionStateBefore)}->${JSON.stringify(consumptionStateAfter)} counts=${JSON.stringify(familyCounts(dataDir))}`,
    );
  } finally {
    if (plane) await plane.stop();
    rmSync(dataDir, { recursive: true, force: true });
  }
}

async function runWalletConsumptionReplay(resolver) {
  const dataDir = mkdtempSync(
    join(tmpdir(), "ioi-system-genesis-wallet-consumption-"),
  );
  ownedTempPaths.add(dataDir);
  let plane;
  try {
    plane = await startIsolatedPlane({
      serve: false,
      env: {
        ...resolver.env,
        IOI_TEST_FORCE_SYSTEM_GENESIS_AFTER_WALLET_CONSUME: "1",
      },
      dataDir,
    });
    if (!plane) throw new Error("BLOCKED: wallet-consumption fault plane could not start");
    let call = (method, path, body) => jsonCall(plane.daemonUrl, method, path, body);
    const body = exactFixtureBody();
    const { challenge, grant } = await challengeAndGrant(call, resolver, body);
    requireValue(
      grant,
      `wallet-consumption lane did not expose a challenge: ${JSON.stringify(challenge)}`,
    );
    const interrupted = await call("POST", ROUTE, {
      ...body,
      wallet_approval_grant: grant,
    });
    ok(
      "WALLET CONSUMPTION: interruption after wallet commit retains only the prepared replay anchor locally",
      interrupted.status === 500 &&
        interrupted.body.error?.code === "system_genesis_pending_convergence" &&
        familyNames(dataDir, INTENT_FAMILY).length === 1 &&
        familyNames(dataDir, CONSUMPTION_FAMILY).length === 0 &&
        familyNames(dataDir, RECORD_FAMILY).length === 0 &&
        familyNames(dataDir, RECEIPT_FAMILY).length === 0,
      `${interrupted.status}/${interrupted.body.error?.code || "no-code"} counts=${JSON.stringify(familyCounts(dataDir))}`,
    );

    process.kill(plane.daemonPid, "SIGKILL");
    await plane.stop();
    plane = null;

    plane = await startIsolatedPlane({ serve: false, env: resolver.env, dataDir });
    if (!plane) throw new Error("BLOCKED: wallet-consumption replay plane could not start");
    call = (method, path, replayBody) =>
      jsonCall(plane.daemonUrl, method, path, replayBody);
    const converged = await pollJson(
      () =>
        call(
          "GET",
          `${ROUTE}?system_id=${encodeURIComponent(SYSTEM_ID)}`,
        ),
      (response) =>
        response.status === 200 && familyNames(dataDir, INTENT_FAMILY).length === 0,
    );
    const walletReceipt = converged?.body?.wallet_grant_consumption_receipt;
    ok(
      "WALLET CONSUMPTION REPLAY: restart recovers the same immutable use receipt without spending a second grant usage",
      converged?.status === 200 &&
        walletReceipt?.usage_ordinal === 1 &&
        walletReceipt?.remaining_usages === 0 &&
        familyNames(dataDir, CONSUMPTION_FAMILY).length === 1 &&
        familyNames(dataDir, RECORD_FAMILY).length === 1 &&
        familyNames(dataDir, RECEIPT_FAMILY).length === 1 &&
        familyNames(dataDir, INTENT_FAMILY).length === 0 &&
        tempResidue(dataDir).length === 0,
      `${converged?.status || "no-status"} usage=${walletReceipt?.usage_ordinal ?? "missing"} remaining=${walletReceipt?.remaining_usages ?? "missing"} counts=${JSON.stringify(familyCounts(dataDir))}`,
    );
  } finally {
    if (plane) await plane.stop();
    rmSync(dataDir, { recursive: true, force: true });
  }
}

async function runBindingRevocationAfterPrepare(resolver) {
  const dataDir = mkdtempSync(
    join(tmpdir(), "ioi-system-genesis-binding-revocation-"),
  );
  ownedTempPaths.add(dataDir);
  let plane;
  try {
    plane = await startIsolatedPlane({
      serve: false,
      env: {
        ...resolver.env,
        IOI_TEST_FORCE_SYSTEM_GENESIS_AFTER_PREPARE: "1",
      },
      dataDir,
    });
    if (!plane) {
      throw new Error("BLOCKED: binding-revocation plane could not start");
    }
    let call = (method, path, requestBody) =>
      jsonCall(plane.daemonUrl, method, path, requestBody);
    const body = exactFixtureBody();
    const { challenge, grant } = await challengeAndGrant(
      call,
      resolver,
      body,
    );
    requireValue(
      grant,
      `binding-revocation lane did not expose a challenge: ${JSON.stringify(challenge)}`,
    );
    const pending = await call("POST", ROUTE, {
      ...body,
      wallet_approval_grant: grant,
    });
    const intentNames = familyNames(dataDir, INTENT_FAMILY);
    const intentName = requireValue(
      intentNames[0],
      `prepare fault emitted no durable intent: ${JSON.stringify(pending)}`,
    );
    const intentPath = join(dataDir, INTENT_FAMILY, intentName);
    const intentBefore = readFileSync(intentPath);
    const revoked = await resolver.revokePrincipalAuthority(OWNER);
    ok(
      "WALLET BINDING PREPARE: the durable intent exists before a real root-signed principal-authority revocation",
      pending.status === 500 &&
        pending.body.error?.code === "system_genesis_pending_convergence" &&
        intentNames.length === 1 &&
        familyNames(dataDir, RECORD_FAMILY).length === 0 &&
        familyNames(dataDir, RECEIPT_FAMILY).length === 0 &&
        familyNames(dataDir, CONSUMPTION_FAMILY).length === 0 &&
        revoked.binding_ref?.startsWith(
          "wallet.network://principal-authority-binding/",
        ),
      `${pending.status}/${pending.body.error?.code || "no-code"} binding=${revoked.binding_ref || "missing"}`,
    );

    process.kill(plane.daemonPid, "SIGKILL");
    await plane.stop();
    plane = null;
    plane = await startIsolatedPlane({
      serve: false,
      env: resolver.env,
      dataDir,
    });
    if (!plane) {
      throw new Error("BLOCKED: binding-revocation restart could not start");
    }
    call = (method, path, requestBody) =>
      jsonCall(plane.daemonUrl, method, path, requestBody);
    await delay(1_500);
    const get = await call(
      "GET",
      `${ROUTE}?system_id=${encodeURIComponent(SYSTEM_ID)}`,
    );
    let restartLogs = "";
    for (let attempt = 0; attempt < 20; attempt += 1) {
      restartLogs = readdirSync(dataDir)
        .filter((name) => name.startsWith("isolated-daemon-restart-"))
        .map((name) => readFileSync(join(dataDir, name), "utf8"))
        .join("\n");
      if (restartLogs.includes("wallet consumption pending")) break;
      await delay(500);
    }
    ok(
      "WALLET BINDING ATOMICITY: revocation after prepare refuses first consumption with the intent byte-exact and zero admission effects",
      get.status === 500 &&
        get.body.error?.code === "system_genesis_pending_convergence" &&
        familyNames(dataDir, INTENT_FAMILY).length === 1 &&
        readFileSync(intentPath).equals(intentBefore) &&
        familyNames(dataDir, RECORD_FAMILY).length === 0 &&
        familyNames(dataDir, RECEIPT_FAMILY).length === 0 &&
        familyNames(dataDir, CONSUMPTION_FAMILY).length === 0 &&
        restartLogs.includes("wallet consumption pending") &&
        restartLogs.includes(
          "principal_authority_binding_coordinates_stale",
        ),
      `get=${get.status}/${get.body.error?.code || "no-code"} counts=${JSON.stringify(familyCounts(dataDir))} log_match=${restartLogs.includes("wallet consumption pending")}/${restartLogs.includes("principal_authority_binding_coordinates_stale")} log_tail=${JSON.stringify(restartLogs.slice(-400))}`,
    );
  } finally {
    if (plane) await plane.stop();
    rmSync(dataDir, { recursive: true, force: true });
  }
}

async function runConcurrentExactAdmission(resolver) {
  const plane = await startIsolatedPlane({ serve: false, env: resolver.env });
  if (!plane) throw new Error("BLOCKED: concurrent admission plane could not start");
  ownedTempPaths.add(plane.dataDir);
  const call = (method, path, body) => jsonCall(plane.daemonUrl, method, path, body);
  try {
    const body = exactFixtureBody();
    const { challenge, grant } = await challengeAndGrant(call, resolver, body);
    requireValue(
      grant,
      `concurrency lane did not expose a challenge: ${JSON.stringify(challenge)}`,
    );
    const responses = await Promise.all(
      Array.from({ length: 16 }, () =>
        call("POST", ROUTE, {
          ...body,
          wallet_approval_grant: grant,
        }),
      ),
    );
    const admitted = responses.filter((response) => response.status === 201);
    const refused = responses.filter(
      (response) =>
        response.status === 409 &&
        [
          "system_genesis_mutation_in_flight",
          "system_genesis_already_admitted",
        ].includes(response.body.error?.code),
    );
    const get = await call(
      "GET",
      `${ROUTE}?system_id=${encodeURIComponent(SYSTEM_ID)}`,
    );
    ok(
      "CONCURRENCY: sixteen exact admissions linearize to one record, one receipt, and one wallet usage",
      admitted.length === 1 &&
        refused.length === 15 &&
        get.status === 200 &&
        get.body.wallet_grant_consumption_receipt?.usage_ordinal === 1 &&
        get.body.wallet_grant_consumption_receipt?.remaining_usages === 0 &&
        familyNames(plane.dataDir, RECORD_FAMILY).length === 1 &&
        familyNames(plane.dataDir, RECEIPT_FAMILY).length === 1 &&
        familyNames(plane.dataDir, CONSUMPTION_FAMILY).length === 1 &&
        familyNames(plane.dataDir, INTENT_FAMILY).length === 0,
      `created=${admitted.length} refused=${refused.length} statuses=${responses.map((response) => `${response.status}/${response.body.error?.code || "ok"}`).join(",")}`,
    );
  } finally {
    await plane.stop();
  }
}

async function runStartupCompleterRace(resolver) {
  const preparation = await startIsolatedPlane({
    serve: false,
    env: resolver.env,
  });
  if (!preparation) {
    throw new Error("BLOCKED: startup-race preparation plane could not start");
  }
  ownedTempPaths.add(preparation.dataDir);
  const body = exactFixtureBody();
  let grant;
  try {
    const prepareCall = (method, path, requestBody) =>
      jsonCall(preparation.daemonUrl, method, path, requestBody);
    const result = await challengeAndGrant(
      prepareCall,
      resolver,
      body,
    );
    grant = requireValue(
      result.grant,
      `startup-race preparation did not expose a challenge: ${JSON.stringify(result.challenge)}`,
    );
  } finally {
    await preparation.stop();
  }

  const plane = await startIsolatedPlane({
    serve: false,
    env: {
      ...resolver.env,
      IOI_TEST_SYSTEM_GENESIS_COMPLETER_PRE_SCAN_PAUSE_MS: "750",
    },
  });
  if (!plane) throw new Error("BLOCKED: startup-race plane could not start");
  ownedTempPaths.add(plane.dataDir);
  const call = (method, path, body) =>
    jsonCall(plane.daemonUrl, method, path, body);
  try {
    const responses = await Promise.all(
      Array.from({ length: 16 }, () =>
        call("POST", ROUTE, {
          ...body,
          wallet_approval_grant: grant,
        }),
      ),
    );
    const admitted = responses.filter((response) => response.status === 201);
    const refused = responses.filter(
      (response) =>
        response.status === 409 &&
        [
          "system_genesis_mutation_in_flight",
          "system_genesis_already_admitted",
        ].includes(response.body.error?.code),
    );
    const falseFailures = responses.filter((response) => response.status >= 500);
    const get = await call(
      "GET",
      `${ROUTE}?system_id=${encodeURIComponent(SYSTEM_ID)}`,
    );
    ok(
      "STARTUP OWNERSHIP: the boot completer and sixteen online admissions share one gate, yielding one 201 and no false convergence failure",
      admitted.length === 1 &&
        refused.length === 15 &&
        falseFailures.length === 0 &&
        get.status === 200 &&
        familyNames(plane.dataDir, RECORD_FAMILY).length === 1 &&
        familyNames(plane.dataDir, RECEIPT_FAMILY).length === 1 &&
        familyNames(plane.dataDir, CONSUMPTION_FAMILY).length === 1 &&
        familyNames(plane.dataDir, INTENT_FAMILY).length === 0,
      `created=${admitted.length} refused=${refused.length} 5xx=${falseFailures.length} statuses=${responses.map((response) => `${response.status}/${response.body.error?.code || "ok"}`).join(",")}`,
    );
  } finally {
    await plane.stop();
  }
}

async function withFreshResolver(journey) {
  const resolver = await startRealWalletNetworkPrincipalAuthorityFixture();
  try {
    await journey(resolver);
  } finally {
    await resolver.stop();
  }
}

async function run() {
  const tempBefore = tempDataEntries();
  const realBefore = familyCounts(REAL_DATA_DIR);
  let fatal;
  try {
    const journeys = new Map([
      ["primary", runPrimaryJourney],
      ["wallet-replay", runWalletConsumptionReplay],
      ["binding-revocation", runBindingRevocationAfterPrepare],
      ["durability", runDurabilityReplay],
      ["agentgres-durability", runRequiredDurabilityConfirmation],
      ["agentgres-replay", runRequiredAdmissionBoundary],
      ["concurrency", runConcurrentExactAdmission],
      ["startup-race", runStartupCompleterRace],
    ]);
    const selected = (
      process.env.IOI_SYSTEM_GENESIS_VERIFIER_JOURNEYS ||
      [...journeys.keys()].join(",")
    )
      .split(",")
      .map((value) => value.trim())
      .filter(Boolean);
    for (const name of selected) {
      const journey = journeys.get(name);
      if (!journey) throw new Error(`unknown verifier journey '${name}'`);
      await withFreshResolver(journey);
    }
  } catch (error) {
    fatal = error;
  }

  const realAfter = familyCounts(REAL_DATA_DIR);
  const tempAfter = tempDataEntries();
  ok(
    "ISOLATION: real daemon System-genesis family counts are unchanged",
    sameJson(realBefore, realAfter),
    `${JSON.stringify(realBefore)} -> ${JSON.stringify(realAfter)}`,
  );
  ok(
    "TEARDOWN: every verifier-owned temp data directory is removed",
    [...ownedTempPaths].every((path) => !existsSync(path)),
    `owned_removed=${[...ownedTempPaths].every((path) => !existsSync(path))} concurrent_temp_census=${tempBefore.length}->${tempAfter.length}`,
  );

  if (fatal) {
    const blocked = String(fatal.message || fatal).startsWith("BLOCKED:");
    console.error(`${blocked ? "BLOCKED" : "VERIFIER CRASH"}:`, fatal);
    process.exitCode = blocked ? 2 : 1;
    return;
  }

  const passed = results.filter((result) => result.pass).length;
  console.log(`${passed}/${results.length} passed`);
  if (passed !== results.length) {
    process.exitCode = 1;
    return;
  }
  console.log(
    "system-genesis admission integration bar: PASS (isolated real-wallet authority, durability replay, and mandatory Agentgres admission verified)",
  );
}

run().catch((error) => {
  console.error("VERIFIER CRASH:", error);
  process.exitCode = 1;
});
