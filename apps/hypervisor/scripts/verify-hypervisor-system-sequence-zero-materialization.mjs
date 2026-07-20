#!/usr/bin/env node
// M1.4 sequence-zero materialization held bar. Every successful mutation crosses the real
// wallet.network fixture and every plane runs on caller-owned isolated storage.

import { createHash } from "node:crypto";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import grpc from "@grpc/grpc-js";
import protoLoader from "@grpc/proto-loader";

import { mintApprovalGrant } from "../../../scripts/lib/mint-approval-grant.mjs";
import { startIsolatedPlane } from "./lib/isolated-daemon.mjs";
import { startRealWalletNetworkPrincipalAuthorityFixture } from "./lib/wallet-network-principal-authority-fixture.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, "..", "..", "..");
const VERIFIER_SOURCE = fileURLToPath(import.meta.url);
const FIXTURES = join(REPO, "docs", "architecture", "_meta", "schemas", "fixtures");
const IPC_PROTO_ROOT = join(REPO, "crates", "ipc", "proto");
const PUBLIC_PROTO = join(IPC_PROTO_ROOT, "public", "v1", "public.proto");
const SYSTEM_SEQUENCE_ZERO_SOURCE = join(
  REPO,
  "crates",
  "node",
  "src",
  "bin",
  "hypervisor_daemon_routes",
  "system_sequence_zero_routes.rs",
);
const GENESIS_ROUTE = "/v1/hypervisor/autonomous-systems";
const OWNER = "org://acme/research";
const OWNER_APPROVER_SEED = "07".repeat(32);
const GENESIS_SCOPE = "scope:autonomous_system.genesis_admit";
const MATERIALIZE_SCOPE = "scope:autonomous_system.genesis_materialize";
const JOURNEY_SELECTOR_ENV =
  "IOI_SYSTEM_SEQUENCE_ZERO_VERIFIER_JOURNEYS";
const SOURCE_FAMILIES = [
  "autonomous-system-genesis-registry",
  "autonomous-system-genesis-receipts",
  "autonomous-system-genesis-authority-consumptions",
];
const SOURCE_INTENT_FAMILY = "autonomous-system-genesis-intents";
const MATERIALIZATION_FAMILIES = [
  "autonomous-system-sequence-zero-materializations",
  "autonomous-system-sequence-zero-materialization-receipts",
  "autonomous-system-sequence-zero-component-registries",
  "autonomous-system-sequence-zero-authority-consumptions",
];
const INTENT_FAMILY =
  "autonomous-system-sequence-zero-materialization-intents";
const MATERIALIZATION_RESPONSE_FIELDS = [
  "autonomous_system_sequence_zero_materialization",
  "autonomous_system_sequence_zero_materialization_receipt",
  "component_registry_snapshot",
  "wallet_grant_consumption_receipt",
];
const EXACT_FALSE_NONCLAIMS = {
  active_profile_admission: false,
  initialize: false,
  activation: false,
  live_chain: false,
  node_membership: false,
  network_effect: false,
  runtime_effect: false,
  systems_product_surface: false,
};
const PARTIAL_PREFIX_CASES = [
  {
    name: "required-agentgres-durability",
    env: { IOI_TEST_FORCE_REQUIRED_ADMISSION_SYNC_FAILURE: "1" },
    interruptedCode: "system_sequence_zero_agentgres_admission_failed",
    expectedCounts: [0, 0, 0, 1],
  },
  {
    name: "after-component",
    env: { IOI_TEST_FORCE_SYSTEM_SEQUENCE_ZERO_AFTER_COMPONENT: "1" },
    interruptedCode: "system_sequence_zero_pending_convergence",
    expectedCounts: [0, 0, 1, 1],
  },
  {
    name: "after-receipt",
    env: { IOI_TEST_FORCE_SYSTEM_SEQUENCE_ZERO_AFTER_RECEIPT: "1" },
    interruptedCode: "system_sequence_zero_pending_convergence",
    expectedCounts: [0, 1, 1, 1],
  },
  {
    name: "after-materialization",
    env: {
      IOI_TEST_FORCE_SYSTEM_SEQUENCE_ZERO_AFTER_MATERIALIZATION: "1",
    },
    interruptedCode: "system_sequence_zero_pending_convergence",
    expectedCounts: [1, 1, 1, 1],
  },
];
const localCorruptionProofName = (family) =>
  `GET PROOF: ${family} corruption refuses typed and exact bytes restore`;
const agentgresCorruptionProofName = (family) =>
  `GET PROOF: isolated ${family} Agentgres corruption refuses the M1.4 code and restores exactly`;
const JOURNEY_PROOF_CENSUS = new Map([
  [
    "primary",
    {
      resources: 1,
      proofs: [
        "M1.3 AUTHORITY: a wallet-proven materialization-scope grant is discarded unspent",
        "SOURCE: M1.3 local and Agentgres evidence is exact and non-vacuous before M1.4",
        "INTAKE: callers cannot author operational roots",
        "INTAKE: recursive sensitive keys refuse before any write",
        "CAS: stale M1.3 source roots refuse before authority with zero mutation",
        "AUTHORITY: a wallet-proven wrong-scope grant is discarded unspent with zero mutation",
        "PREFLIGHT: malformed occupied record slots refuse as uncertain evidence, never ordinary completion",
        "AUTHORITY: materialization has a distinct real-wallet scope and zero-write challenge",
        "AUTHORITY: unsigned fields outside the closed typed grant projection refuse with zero evidence",
        "AUTHORITY: same-hash foreign signer refuses with zero mutation",
        "AUTHORITY: a validly signed multi-use grant refuses before mutation",
        "CONCURRENCY: twelve exact requests linearize to one materialization",
        "ROOTS: all six sequence-zero commitments recompute independently from M1.3 truth",
        "TRACE: proposal roots remain explicit history and never become operational roots",
        "RECEIPT: the live durable receipt conforms to the closed portable M1.4 profile",
        "GET PROOF: all four local and Agentgres families equal the POST evidence exactly",
        "SOURCE IMMUTABILITY: M1.3 bytes and Agentgres heads are unchanged",
        "DURABILITY: every M1.4 response has one exact local record and non-vacuous Agentgres proof",
        ...MATERIALIZATION_FAMILIES.map(localCorruptionProofName),
        ...MATERIALIZATION_FAMILIES.map(agentgresCorruptionProofName),
      ],
    },
  ],
  [
    "wallet-replay",
    {
      resources: 1,
      proofs: [
        "REPLAY PREPARE: interruption after wallet consumption retains only the durable intent",
        "REPLAY: an already-consumed grant converges after binding revocation without re-authoring",
      ],
    },
  ],
  [
    "partial-prefix-replay",
    {
      resources: PARTIAL_PREFIX_CASES.length,
      proofs: PARTIAL_PREFIX_CASES.flatMap(({ name }) => [
        `PREFIX ${name}: partial evidence stays non-servable with its replay anchor`,
        `PREFIX ${name}: restart converges exactly once without another authority use`,
      ]),
    },
  ],
  [
    "dependency-ordered-replay",
    {
      resources: 1,
      proofs: [
        "DEPENDENCY PREPARE: M1.3 can retain a fully admitted replay anchor",
        "DEPENDENCY REPLAY: one boot converges M1.3 before its M1.4 successor",
      ],
    },
  ],
  [
    "unconsumed-revocation",
    {
      resources: 1,
      proofs: [
        "REPLAY PRE-AUTHORITY: interruption after prepare retains an unconsumed intent only",
        "REPLAY AUTHORITY: an unconsumed grant cannot cross a revoked binding on restart",
      ],
    },
  ],
]);

const results = [];
const ownedDataDirs = new Map();
const executedJourneys = [];
let activeJourney = null;
let publicApiConstructor;

function ok(name, pass, detail = "") {
  results.push({
    journey: activeJourney || "verifier",
    name,
    pass: Boolean(pass),
    detail,
  });
  console.log(`${pass ? "PASS" : "FAIL"}: ${name}${detail ? ` - ${detail}` : ""}`);
}

function requireValue(value, message) {
  if (!value) throw new Error(message);
  return value;
}

function clone(value) {
  return structuredClone(value);
}

function createOwnedDataDir(prefix) {
  requireValue(activeJourney, "verifier-owned data directories require an active journey");
  const dataDir = mkdtempSync(join(tmpdir(), prefix));
  if (ownedDataDirs.has(dataDir)) {
    throw new Error(`verifier-owned data directory was registered twice: ${dataDir}`);
  }
  ownedDataDirs.set(dataDir, activeJourney);
  return dataDir;
}

function startVerifierPlane({ dataDir, env = {}, ...options } = {}) {
  return startIsolatedPlane({
    dataDir,
    ...options,
    env: {
      ...env,
      RUST_LOG: "off",
    },
  });
}

function exactJourneyCensus(name, observedProofs, observedResources) {
  const expected = requireValue(
    JOURNEY_PROOF_CENSUS.get(name),
    `journey '${name}' lacks an exact proof census`,
  );
  if (!sameJson(observedProofs, expected.proofs)) {
    throw new Error(
      `journey '${name}' proof census mismatch: expected=${canonicalJson(expected.proofs)} observed=${canonicalJson(observedProofs)}`,
    );
  }
  if (observedResources.length !== expected.resources) {
    throw new Error(
      `journey '${name}' resource census mismatch: expected=${expected.resources} observed=${observedResources.length}`,
    );
  }
  if (
    observedResources.some(
      (path) => ownedDataDirs.get(path) !== name,
    )
  ) {
    throw new Error(`journey '${name}' resource census contains an unowned path`);
  }
}

async function executeJourneyWithCensus(name, journey) {
  const resultStart = results.length;
  const resourcesBefore = new Set(ownedDataDirs.keys());
  if (activeJourney !== null) {
    throw new Error(`journey '${name}' cannot nest inside '${activeJourney}'`);
  }
  activeJourney = name;
  try {
    await journey();
  } finally {
    activeJourney = null;
  }
  const observedProofs = results
    .slice(resultStart)
    .filter((result) => result.journey === name)
    .map((result) => result.name);
  const observedResources = [...ownedDataDirs.keys()].filter(
    (path) => !resourcesBefore.has(path),
  );
  exactJourneyCensus(name, observedProofs, observedResources);
}

async function noopJourneysRefuseCertification() {
  for (const name of JOURNEY_PROOF_CENSUS.keys()) {
    const resultStart = results.length;
    const resourcesBefore = new Set(ownedDataDirs.keys());
    await (async () => {})();
    const observedProofs = results.slice(resultStart).map((result) => result.name);
    const observedResources = [...ownedDataDirs.keys()].filter(
      (path) => !resourcesBefore.has(path),
    );
    try {
      exactJourneyCensus(name, observedProofs, observedResources);
      return false;
    } catch (error) {
      if (!String(error.message || error).includes("proof census mismatch")) {
        throw error;
      }
    }
  }
  return true;
}

function teardownComplete(resources, selectedJourneys) {
  if (resources.size === 0 || selectedJourneys.length === 0) return false;
  const expectedResources = selectedJourneys.reduce(
    (total, name) => total + JOURNEY_PROOF_CENSUS.get(name).resources,
    0,
  );
  return (
    resources.size === expectedResources &&
    selectedJourneys.every((name) =>
      [...resources.values()].includes(name),
    ) &&
    [...resources.keys()].every((path) => !existsSync(path))
  );
}

function fixture(relativePath) {
  return JSON.parse(readFileSync(join(FIXTURES, relativePath), "utf8"));
}

// The fixture and daemon projections contain ordinary JSON values, so this is the RFC 8785
// ordering and ECMAScript primitive serialization used by serde_jcs for this held bar.
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
  return `sha256:${createHash("sha256")
    .update(canonicalJson({ domain, value }))
    .digest("hex")}`;
}

function deploymentProfileRoot(profileRefs) {
  const deploymentRef = profileRefs?.deployment_profile_ref;
  const match =
    typeof deploymentRef === "string"
      ? /^deployment-profile:\/\/([^\s?#\\]+)\/revision\/sha256:([0-9a-f]{64})$/.exec(
          deploymentRef,
        )
      : null;
  if (!match) {
    throw new Error(
      "M1.4 deployment_profile_ref must end in /revision/sha256:<64 lowercase hex>",
    );
  }
  return `sha256:${match[2]}`;
}

function recordOutputHash(record, excludes = []) {
  const material = clone(record);
  for (const field of excludes) delete material[field];
  return `sha256:${createHash("sha256")
    .update(canonicalJson(material))
    .digest("hex")}`;
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

function exactGenesisBody(genesisId = null) {
  const release = fixture("autonomous-system-manifest-v1/positive-reusable-release.json");
  recomputeReleaseHashes(release);
  const candidate = fixture("autonomous-system-genesis-v1/positive-proposed.json");
  delete candidate.admitted_manifest_root;
  delete candidate.initial_profile_bundle_root;
  delete candidate.cryptographic_origin.genesis_operation_commitment;
  delete candidate.cryptographic_origin.genesis_transition_commitment_ref;
  if (genesisId) candidate.genesis_id = genesisId;
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

function familyFiles(dataDir, family) {
  const familyDir = join(dataDir, family);
  try {
    return readdirSync(familyDir, { withFileTypes: true })
      .map((entry) => {
        if (!entry.isFile()) {
          throw new Error(
            `evidence family '${family}' contains nonregular entry '${entry.name}'`,
          );
        }
        return entry.name;
      })
      .filter((name) => name.endsWith(".json"))
      .sort();
  } catch (error) {
    if (error?.code === "ENOENT") return [];
    throw error;
  }
}

function familyBytes(dataDir, family) {
  return familyFiles(dataDir, family).map((name) => [
    name,
    readFileSync(join(dataDir, family, name), "utf8"),
  ]);
}

function singleFamilyRecord(dataDir, family) {
  const files = familyFiles(dataDir, family);
  if (files.length !== 1) return null;
  try {
    return JSON.parse(readFileSync(join(dataDir, family, files[0]), "utf8"));
  } catch {
    return null;
  }
}

function familiesSnapshot(dataDir, families) {
  return canonicalJson(
    Object.fromEntries(
      families.map((family) => {
        const familyDir = join(dataDir, family);
        return [
          family,
          existsSync(familyDir) ? recursiveBytesSnapshot(familyDir) : null,
        ];
      }),
    ),
  );
}

function recursiveBytesSnapshot(root) {
  const rootStat = lstatSync(root);
  if (!rootStat.isDirectory()) {
    throw new Error(`snapshot root is not a directory: ${root}`);
  }
  const rows = [["directory", "", null]];
  function walk(current, relative = "") {
    const entries = readdirSync(current, { withFileTypes: true });
    for (const entry of entries) {
      const nextRelative = relative ? `${relative}/${entry.name}` : entry.name;
      const absolute = join(current, entry.name);
      const stat = lstatSync(absolute);
      if (stat.isDirectory()) {
        rows.push(["directory", nextRelative, null]);
        walk(absolute, nextRelative);
      } else if (stat.isFile()) {
        rows.push(["file", nextRelative, readFileSync(absolute).toString("base64")]);
      } else {
        throw new Error(`snapshot refuses nonregular entry: ${absolute}`);
      }
    }
  }
  walk(root);
  return canonicalJson(
    rows.sort((left, right) => {
      const pathOrder = left[1].localeCompare(right[1]);
      return pathOrder || left[0].localeCompare(right[0]);
    }),
  );
}

async function stableDataPlaneSnapshot(call, dataDir) {
  const status = await call("GET", "/v1/hypervisor/substrate/status");
  requireValue(
    status.status === 200,
    `data-plane snapshot warmup failed: ${status.status}/${status.body.error?.code || "no-code"}`,
  );
  let previous = recursiveBytesSnapshot(dataDir);
  for (let attempt = 0; attempt < 20; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 25));
    const current = recursiveBytesSnapshot(dataDir);
    if (current === previous) return current;
    previous = current;
  }
  throw new Error("data-plane snapshot did not become byte-stable");
}

function loadPublicApiConstructor() {
  if (publicApiConstructor) return publicApiConstructor;
  const definition = protoLoader.loadSync(PUBLIC_PROTO, {
    includeDirs: [IPC_PROTO_ROOT],
    keepCase: true,
    longs: String,
    enums: String,
    defaults: true,
    oneofs: true,
  });
  publicApiConstructor =
    grpc.loadPackageDefinition(definition).ioi.public.v1.PublicApi;
  return publicApiConstructor;
}

async function queryWalletRawState(resolver, key) {
  const rpcUrl = new URL(resolver.env.IOI_WALLET_NETWORK_RPC_ADDR);
  const serverName = resolver.env.IOI_WALLET_NETWORK_TLS_SERVER_NAME;
  const client = new (loadPublicApiConstructor())(
    `${rpcUrl.hostname}:${rpcUrl.port}`,
    grpc.credentials.createSsl(
      readFileSync(resolver.env.IOI_WALLET_NETWORK_TLS_CA_PATH),
    ),
    {
      "grpc.ssl_target_name_override": serverName,
      "grpc.default_authority": serverName,
    },
  );
  try {
    return await new Promise((resolve, reject) => {
      client.queryRawState({ key }, (error, response) => {
        if (error) {
          reject(error);
          return;
        }
        resolve(response.found ? Buffer.from(response.value) : null);
      });
    });
  } finally {
    client.close();
  }
}

async function walletConsumptionStateBytes(resolver, requestHash) {
  const normalized = String(requestHash || "")
    .replace(/^sha256:/, "")
    .toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(normalized)) {
    throw new Error("wallet consumption state query requires an exact request hash");
  }
  const key = Buffer.concat([
    Buffer.from("_service_data::wallet_network::approval_consumption::"),
    Buffer.from(normalized, "hex"),
  ]);
  return queryWalletRawState(resolver, key);
}

function parseMuxFrames(bytes) {
  const frames = [];
  let offset = 0;
  while (offset < bytes.length) {
    if (offset + 4 > bytes.length) {
      throw new Error(`mux log has a partial frame length at byte ${offset}`);
    }
    const length = bytes.readUInt32LE(offset);
    if (length === 0 || offset + 4 + length > bytes.length) {
      throw new Error(`mux log has an invalid frame length ${length} at byte ${offset}`);
    }
    const encoded = bytes.subarray(offset, offset + 4 + length);
    const body = encoded.subarray(4);
    frames.push({
      value: JSON.parse(body.toString("utf8")),
      encoded: Buffer.from(encoded),
    });
    offset += 4 + length;
  }
  return frames;
}

function encodeMuxFrame(value) {
  const body = Buffer.from(JSON.stringify(value));
  const length = Buffer.alloc(4);
  length.writeUInt32LE(body.length);
  return Buffer.concat([length, body]);
}

function shaHex(...parts) {
  return `sha256:${createHash("sha256").update(Buffer.concat(parts)).digest("hex")}`;
}

function mutateLengthPreservingScalar(value) {
  if (typeof value === "string") {
    const match = /[a-zA-Z0-9](?!.*[a-zA-Z0-9])/.exec(value);
    if (!match) return null;
    const replacement = match[0] === "1" ? "2" : "1";
    return `${value.slice(0, match.index)}${replacement}${value.slice(match.index + 1)}`;
  }
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) {
      const mutated = mutateLengthPreservingScalar(value[index]);
      if (mutated !== null) {
        value[index] = mutated;
        return value;
      }
    }
    return null;
  }
  if (value !== null && typeof value === "object") {
    for (const key of Object.keys(value)) {
      const mutated = mutateLengthPreservingScalar(value[key]);
      if (mutated !== null) {
        value[key] = mutated;
        return value;
      }
    }
  }
  return null;
}

function corruptAgentgresFamily(bytes, targetFamily) {
  const frames = parseMuxFrames(bytes);
  const roundTrip = Buffer.concat(frames.map(({ value }) => encodeMuxFrame(value)));
  requireValue(
    roundTrip.equals(bytes),
    "Agentgres mux log is not byte-exactly JSON round-trippable",
  );
  const domains = new Map();
  let mutations = 0;
  const rewritten = frames.map(({ value }) => {
    const frame = clone(value);
    if (frame.frame === "Admitted") {
      const domain = frame.op?.domain;
      const state = domains.get(domain) || {
        root: "sha256:genesis",
        heads: new Map(),
        pendingHashes: [],
        pendingHeads: new Map(),
      };
      domains.set(domain, state);
      if (domain === targetFamily) {
        requireValue(
          mutateLengthPreservingScalar(frame.op?.payload),
          `Agentgres ${targetFamily} payload lacks a length-preserving scalar`,
        );
        mutations += 1;
      }
      const priorHead =
        state.pendingHeads.get(frame.op.object_ref) ||
        state.heads.get(frame.op.object_ref) ||
        "";
      frame.new_head = shaHex(
        Buffer.from("head|"),
        Buffer.from(priorHead),
        Buffer.from("|"),
        Buffer.from(JSON.stringify(frame.op)),
      );
      const encoded = encodeMuxFrame(frame);
      state.pendingHashes.push(
        createHash("sha256").update(encoded).digest(),
      );
      state.pendingHeads.set(frame.op.object_ref, frame.new_head);
      return encoded;
    }
    if (frame.frame === "DomainRoot") {
      const state = requireValue(
        domains.get(frame.domain),
        `Agentgres root lacks admitted domain '${frame.domain}'`,
      );
      requireValue(
        state.pendingHashes.length > 0,
        `Agentgres root for '${frame.domain}' is vacuous`,
      );
      frame.rec.prev_root = state.root;
      frame.rec.root = shaHex(
        Buffer.from("root|"),
        Buffer.from(state.root),
        Buffer.from("|"),
        Buffer.concat(state.pendingHashes),
      );
      state.root = frame.rec.root;
      for (const [objectRef, head] of state.pendingHeads) {
        state.heads.set(objectRef, head);
      }
      state.pendingHashes = [];
      state.pendingHeads.clear();
      return encodeMuxFrame(frame);
    }
    return encodeMuxFrame(frame);
  });
  requireValue(
    mutations === 1,
    `Agentgres corruption expected one ${targetFamily} frame, found ${mutations}`,
  );
  const corrupted = Buffer.concat(rewritten);
  requireValue(
    corrupted.length === bytes.length && !corrupted.equals(bytes),
    `Agentgres ${targetFamily} corruption was not isolated and length-preserving`,
  );
  return corrupted;
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

function requiredDomainState(response, family) {
  const domain = response.body?.engine_domains?.[family];
  return domain && domain.root != null && domain.admitted_seq != null
    ? { root: domain.root, admitted_seq: domain.admitted_seq }
    : null;
}

function requiredDomainIsNonVacuous(response, family) {
  const state = requiredDomainState(response, family);
  return Boolean(
    response?.status === 200 &&
      state &&
      typeof state.root === "string" &&
      state.root.length > 0 &&
      Number.isInteger(Number(state.admitted_seq)) &&
      Number(state.admitted_seq) > 0,
  );
}

function responseHasExactEvidence(body, expected) {
  return MATERIALIZATION_RESPONSE_FIELDS.every(
    (field) =>
      Object.hasOwn(body ?? {}, field) &&
      body[field] !== null &&
      body[field] !== undefined &&
      sameJson(body[field], expected[field]),
  );
}

function hasExactFalseNonclaims(body) {
  return sameJson(body?.nonclaims, EXACT_FALSE_NONCLAIMS);
}

async function challengeAndGrant(call, resolver, path, body, scope) {
  const challenge = await call("POST", path, body);
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
      scope,
    );
  }
  return { challenge, grant };
}

async function admitGenesis(
  call,
  resolver,
  dataDir,
  { exerciseWrongScope = false, genesisId = null } = {},
) {
  const body = exactGenesisBody(genesisId);
  if (exerciseWrongScope) {
    const probeBody = clone(body);
    probeBody.proposed_instantiation.candidate.genesis_id =
      "genesis://acme/system-alpha/wrong-scope-probe";
    const probeChallenge = await call("POST", GENESIS_ROUTE, probeBody);
    const probeApproval = probeChallenge.body.error?.approval;
    requireValue(
      probeChallenge.status === 403 &&
        probeChallenge.body.error?.code ===
          "system_genesis_host_authority_required" &&
        probeApproval?.policy_hash &&
        probeApproval?.request_hash,
      `M1.3 probe did not expose its governed challenge: ${JSON.stringify(probeChallenge)}`,
    );
    const wrongScopeGrant = mintApprovalGrant({
      seed: OWNER_APPROVER_SEED,
      policyHash: probeApproval.policy_hash,
      requestHash: probeApproval.request_hash,
      audience: resolver.capabilityAccountId,
    });
    await resolver.recordApproval(
      OWNER,
      probeApproval.policy_hash,
      probeApproval.request_hash,
      wrongScopeGrant,
      MATERIALIZE_SCOPE,
    );
    const beforeWrongScope = await stableDataPlaneSnapshot(call, dataDir);
    const walletStateBeforeWrongScope = requireValue(
      await walletConsumptionStateBytes(
        resolver,
        probeApproval.request_hash,
      ),
      "M1.3 wrong-scope grant lacks committed wallet consumption state",
    );
    const wrongScope = await call("POST", GENESIS_ROUTE, {
      ...probeBody,
      wallet_approval_grant: wrongScopeGrant,
    });
    const walletStateAfterWrongScope = requireValue(
      await walletConsumptionStateBytes(
        resolver,
        probeApproval.request_hash,
      ),
      "M1.3 wrong-scope refusal removed wallet consumption state",
    );
    const walletStateUnchanged =
      walletStateBeforeWrongScope.equals(walletStateAfterWrongScope);
    const dataPlaneUnchanged =
      beforeWrongScope === recursiveBytesSnapshot(dataDir);
    ok(
      "M1.3 AUTHORITY: a wallet-proven materialization-scope grant is discarded unspent",
      wrongScope.status === 422 &&
        wrongScope.body.error?.code ===
          "system_genesis_wallet_consumption_precondition_refused" &&
        walletStateUnchanged &&
        dataPlaneUnchanged &&
        familyFiles(dataDir, SOURCE_INTENT_FAMILY).length === 0 &&
        SOURCE_FAMILIES.every(
          (family) => familyFiles(dataDir, family).length === 0,
        ),
      `${wrongScope.status}/${wrongScope.body.error?.code || "no-code"} wallet-unchanged=${walletStateUnchanged} data-unchanged=${dataPlaneUnchanged} wallet-bytes=${walletStateAfterWrongScope.length}`,
    );
  }
  const challenge = await call("POST", GENESIS_ROUTE, body);
  const approval = challenge.body.error?.approval;
  requireValue(
    challenge.status === 403 &&
      challenge.body.error?.code === "system_genesis_host_authority_required" &&
      approval?.policy_hash &&
      approval?.request_hash,
    `M1.3 did not expose its governed challenge: ${JSON.stringify(challenge)}`,
  );
  const grant = resolver.mintForCapability(
    OWNER,
    approval.policy_hash,
    approval.request_hash,
  );
  await resolver.recordApproval(
    OWNER,
    approval.policy_hash,
    approval.request_hash,
    grant,
    GENESIS_SCOPE,
  );
  requireValue(
    grant,
    "M1.3 challenge did not produce its correctly scoped grant",
  );
  const admitted = await call("POST", GENESIS_ROUTE, {
    ...body,
    wallet_approval_grant: grant,
  });
  requireValue(
    admitted.status === 201,
    `M1.3 source admission failed: ${JSON.stringify(admitted)}`,
  );
  const record = requireValue(
    admitted.body.autonomous_system_genesis_admission,
    "M1.3 response lacks its record",
  );
  const receipt = requireValue(
    admitted.body.autonomous_system_genesis_receipt,
    "M1.3 response lacks its receipt",
  );
  const walletReceipt = requireValue(
    admitted.body.wallet_grant_consumption_receipt,
    "M1.3 response lacks its wallet consumption receipt",
  );
  const sourceTail = String(record.admission_id || "").replace(
    "system-genesis-admission://",
    "",
  );
  return {
    sourceTail,
    record,
    receipt,
    walletReceipt,
    recordRoot: domainHash(
      "ioi.autonomous-system-genesis-admission-record-jcs-sha256.v1",
      record,
    ),
    receiptRoot: domainHash(
      "ioi.autonomous-system-genesis-admission-receipt-jcs-sha256.v1",
      receipt,
    ),
  };
}

function persistedGenesisSource(dataDir) {
  const recordName = requireValue(
    familyFiles(dataDir, SOURCE_FAMILIES[0])[0],
    "persisted M1.3 source lacks its admission record",
  );
  const receiptName = requireValue(
    familyFiles(dataDir, SOURCE_FAMILIES[1])[0],
    "persisted M1.3 source lacks its admission receipt",
  );
  const record = JSON.parse(
    readFileSync(join(dataDir, SOURCE_FAMILIES[0], recordName), "utf8"),
  );
  const receipt = JSON.parse(
    readFileSync(join(dataDir, SOURCE_FAMILIES[1], receiptName), "utf8"),
  );
  return {
    sourceTail: String(record.admission_id || "").replace(
      "system-genesis-admission://",
      "",
    ),
    record,
    receipt,
    recordRoot: domainHash(
      "ioi.autonomous-system-genesis-admission-record-jcs-sha256.v1",
      record,
    ),
    receiptRoot: domainHash(
      "ioi.autonomous-system-genesis-admission-receipt-jcs-sha256.v1",
      receipt,
    ),
  };
}

function normalizeComponentBindings(genesis) {
  const bindings = genesis.initial_component_bindings;
  const rows = [];
  for (const [field, kind] of [
    ["goal_run_profiles", "goal_run_profile"],
    ["workflow_templates", "workflow_template"],
    ["automation_specs", "automation_spec"],
    ["harness_profiles", "harness_profile"],
    ["agent_harness_adapters", "agent_harness_adapter"],
    ["data_recipes", "data_recipe"],
    ["runtime_tool_contracts", "runtime_tool_contract"],
  ]) {
    for (const row of bindings[field]) {
      rows.push({
        kind,
        binding_ref: row.revision_ref,
        binding_hash: row.content_hash,
        evidence_refs: [],
        evidence_hashes: [],
      });
    }
  }
  for (const row of bindings.automation_installations) {
    rows.push({
      kind: "automation_installation",
      binding_ref: row.binding_revision_ref,
      binding_hash: row.binding_hash,
      evidence_refs: [row.admission_receipt_ref],
      evidence_hashes: [],
    });
  }
  for (const row of bindings.skill_entries) {
    rows.push({
      kind: "skill_entry",
      binding_ref: row.binding_revision_ref,
      binding_hash: row.binding_hash,
      evidence_refs: [row.skill_manifest_revision_ref],
      evidence_hashes: [row.skill_manifest_content_hash],
    });
  }
  for (const row of bindings.mcp_gateway_profiles) {
    rows.push({
      kind: "mcp_gateway_profile",
      binding_ref: row.profile_revision_ref,
      binding_hash: row.profile_content_hash,
      evidence_refs: [],
      evidence_hashes: [],
    });
  }
  return rows.sort((left, right) =>
    Buffer.compare(
      Buffer.from(canonicalJson(left)),
      Buffer.from(canonicalJson(right)),
    ),
  );
}

function recomputeMaterialization(source, materialization) {
  const genesis = source.record.authorized_genesis;
  const deploymentRoot = deploymentProfileRoot(genesis.initial_profile_refs);
  const componentBindings = normalizeComponentBindings(genesis);
  const componentRegistryMaterial = {
    schema_version: "ioi.autonomous-system-component-registry-snapshot.v1",
    system_id: genesis.system_id,
    genesis_ref: genesis.genesis_id,
    component_bindings: componentBindings,
  };
  const componentRegistryRoot = domainHash(
    "ioi.autonomous-system-component-registry-jcs-sha256.v1",
    componentRegistryMaterial,
  );
  const profileBundleRoot = domainHash(
    "ioi.autonomous-system-initial-profile-bundle-jcs-sha256.v1",
    source.record.initial_profile_bundle,
  );
  const profileMaterializationRoot = domainHash(
    "ioi.autonomous-system-profile-materialization-jcs-sha256.v1",
    {
      schema_version: "ioi.autonomous-system-profile-materialization.v1",
      system_id: genesis.system_id,
      genesis_ref: genesis.genesis_id,
      profile_bundle_root: profileBundleRoot,
      deployment_profile_root: deploymentRoot,
      profile_refs: genesis.initial_profile_refs,
    },
  );
  const componentRegistryRef =
    `agentgres://object-set/autonomous-system-components/${componentRegistryRoot}`;
  const materializationId =
    `system-materialization://sequence-zero/${source.recordRoot}`;
  const operationCommitment = domainHash(
    "ioi.autonomous-system-sequence-zero-operation-jcs-sha256.v1",
    {
      schema_version: "ioi.autonomous-system-sequence-zero-operation.v1",
      operation: "materialize_sequence_zero",
      materialization_id: materializationId,
      system_id: genesis.system_id,
      genesis_ref: genesis.genesis_id,
      genesis_admission_receipt_ref: source.receipt.receipt_ref,
      genesis_admission_record_root: source.recordRoot,
      genesis_admission_receipt_root: source.receiptRoot,
      proposed_initial_state_root:
        genesis.cryptographic_origin.initial_state_root,
      proposed_initial_receipt_root:
        genesis.cryptographic_origin.initial_receipt_root,
      package_id: genesis.package_id,
      manifest_ref: genesis.manifest_ref,
      admitted_manifest_root: genesis.admitted_manifest_root,
      constitution_ref: genesis.constitution_ref,
      constitution_root:
        source.record.initial_profile_bundle.constitution.constitution_root,
      profile_bundle_root: profileBundleRoot,
      profile_materialization_root: profileMaterializationRoot,
      deployment_profile_root: deploymentRoot,
      profile_refs: genesis.initial_profile_refs,
      component_registry_ref: componentRegistryRef,
      component_registry_root: componentRegistryRoot,
      component_bindings: componentBindings,
      sequence: 0,
      predecessor_transition_commitment_ref: null,
      target_status: "materialized_pending_activation",
      activation_admitted: false,
      runtime_effect_admitted: false,
    },
  );
  const initialStateRoot = domainHash(
    "ioi.autonomous-system-sequence-zero-state-jcs-sha256.v1",
    {
      schema_version: "ioi.autonomous-system-sequence-zero-state.v1",
      materialization_id: materializationId,
      system_id: genesis.system_id,
      genesis_ref: genesis.genesis_id,
      package_id: genesis.package_id,
      manifest_ref: genesis.manifest_ref,
      admitted_manifest_root: genesis.admitted_manifest_root,
      constitution_ref: genesis.constitution_ref,
      constitution_root:
        source.record.initial_profile_bundle.constitution.constitution_root,
      profile_bundle_root: profileBundleRoot,
      profile_materialization_root: profileMaterializationRoot,
      deployment_profile_root: deploymentRoot,
      profile_refs: genesis.initial_profile_refs,
      component_registry_ref: componentRegistryRef,
      component_registry_root: componentRegistryRoot,
      component_bindings: componentBindings,
      sequence: 0,
      node_membership_refs: [],
      worker_instance_refs: [],
      workflow_refs: [],
      activation_state: "not_started",
      status: "materialized_pending_activation",
    },
  );
  const materializationReceiptRef =
    `receipt://aszmr_${operationCommitment.replace("sha256:", "")}`;
  const initialReceiptRoot = domainHash(
    "ioi.autonomous-system-sequence-zero-receipt-jcs-sha256.v1",
    {
      schema_version: "ioi.autonomous-system-sequence-zero-receipt-root.v1",
      sequence: 0,
      genesis_admission_receipt_ref: source.receipt.receipt_ref,
      genesis_admission_receipt_root: source.receiptRoot,
      materialization_receipt_ref: materializationReceiptRef,
      operation_commitment: operationCommitment,
      initial_state_root: initialStateRoot,
    },
  );
  const transitionHash = domainHash(
    "ioi.autonomous-system-sequence-zero-transition-jcs-sha256.v1",
    {
      schema_version: "ioi.autonomous-system-sequence-zero-transition.v1",
      sequence: 0,
      predecessor_transition_commitment_ref: null,
      operation_commitment: operationCommitment,
      admission_proof_ref: materializationReceiptRef,
      resulting_state_root: initialStateRoot,
      receipt_root: initialReceiptRoot,
    },
  );
  return {
    componentBindings,
    componentRegistryRoot,
    componentRegistryRef,
    profileBundleRoot,
    profileMaterializationRoot,
    deploymentProfileRoot: deploymentRoot,
    materializationId,
    operationCommitment,
    initialStateRoot,
    initialReceiptRoot,
    materializationReceiptRef,
    transitionCommitmentRef:
      `commitment://ioi/system-sequence-zero/${transitionHash}`,
    responseMatches:
      materialization.component_registry_root === componentRegistryRoot &&
      materialization.profile_bundle_root === profileBundleRoot &&
      materialization.profile_materialization_root === profileMaterializationRoot &&
      materialization.deployment_profile_root === deploymentRoot &&
      materialization.materialization_id === materializationId &&
      materialization.operation_commitment === operationCommitment &&
      materialization.initial_state_root === initialStateRoot &&
      materialization.initial_receipt_root === initialReceiptRoot &&
      materialization.materialization_receipt_ref === materializationReceiptRef &&
      materialization.transition_commitment_ref ===
        `commitment://ioi/system-sequence-zero/${transitionHash}`,
  };
}

async function runPrimaryJourney() {
  let resolver = await startRealWalletNetworkPrincipalAuthorityFixture();
  const dataDir = createOwnedDataDir("ioi-system-sequence-zero-primary-");
  let plane;
  let wrongScopeResolver;
  try {
    plane = await startVerifierPlane({ dataDir, env: resolver.env });
    if (!plane) throw new Error("BLOCKED: target/debug/hypervisor-daemon is not built");
    const call = (method, path, body) =>
      jsonCall(plane.daemonUrl, method, path, body);
    const source = await admitGenesis(call, resolver, dataDir, {
      exerciseWrongScope: true,
    });
    const path =
      `${GENESIS_ROUTE}/${source.sourceTail}/sequence-zero-materialization`;
    const sourceBytesBefore = familiesSnapshot(dataDir, SOURCE_FAMILIES);
    const sourceStatusBefore = await call("GET", "/v1/hypervisor/substrate/status");
    const sourceEvidence = [
      [SOURCE_FAMILIES[0], source.record],
      [SOURCE_FAMILIES[1], source.receipt],
      [SOURCE_FAMILIES[2], source.walletReceipt],
    ];
    ok(
      "SOURCE: M1.3 local and Agentgres evidence is exact and non-vacuous before M1.4",
      sourceEvidence.every(
        ([family, expected]) =>
          sameJson(singleFamilyRecord(dataDir, family), expected) &&
          requiredDomainIsNonVacuous(sourceStatusBefore, family),
      ),
      `families=${sourceEvidence.filter(
        ([family, expected]) =>
          sameJson(singleFamilyRecord(dataDir, family), expected) &&
          requiredDomainIsNonVacuous(sourceStatusBefore, family),
      ).length}/${sourceEvidence.length}`,
    );
    const request = {
      expected_genesis_admission_record_root: source.recordRoot,
      expected_genesis_admission_receipt_root: source.receiptRoot,
    };

    const unknownBefore = await stableDataPlaneSnapshot(call, dataDir);
    const unknown = await call("POST", path, {
      ...request,
      initial_state_root: "sha256:".padEnd(71, "0"),
    });
    ok(
      "INTAKE: callers cannot author operational roots",
      unknown.status === 422 &&
        unknown.body.error?.code ===
          "system_sequence_zero_request_field_unknown" &&
        unknownBefore === recursiveBytesSnapshot(dataDir),
      `${unknown.status}/${unknown.body.error?.code || "no-code"}`,
    );

    const secret = await call("POST", path, {
      ...request,
      metadata: { api_token: "SEQUENCE_ZERO_SECRET_SENTINEL" },
    });
    ok(
      "INTAKE: recursive sensitive keys refuse before any write",
      secret.status === 422 &&
        secret.body.error?.code ===
          "system_sequence_zero_sensitive_field_rejected" &&
        !JSON.stringify(secret.body).includes("SEQUENCE_ZERO_SECRET_SENTINEL") &&
        unknownBefore === recursiveBytesSnapshot(dataDir),
      `${secret.status}/${secret.body.error?.code || "no-code"}`,
    );

    const conflict = await call("POST", path, {
      ...request,
      expected_genesis_admission_record_root:
        "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    });
    ok(
      "CAS: stale M1.3 source roots refuse before authority with zero mutation",
      conflict.status === 409 &&
        conflict.body.error?.code === "system_sequence_zero_source_conflict" &&
        unknownBefore === recursiveBytesSnapshot(dataDir),
      `${conflict.status}/${conflict.body.error?.code || "no-code"}`,
    );

    await plane.stop();
    plane = undefined;
    await resolver.stop();
    resolver = undefined;
    wrongScopeResolver =
      await startRealWalletNetworkPrincipalAuthorityFixture();
    plane = await startVerifierPlane({
      dataDir,
      env: wrongScopeResolver.env,
    });
    if (!plane) {
      throw new Error("BLOCKED: wrong-scope probe daemon is not built");
    }
    const wrongScopeChallenge = await call("POST", path, request);
    const wrongScopeApproval = wrongScopeChallenge.body.error?.approval;
    requireValue(
      wrongScopeChallenge.status === 403 &&
        wrongScopeChallenge.body.error?.code ===
          "system_sequence_zero_host_authority_required" &&
        wrongScopeApproval?.policy_hash &&
        wrongScopeApproval?.request_hash,
      `M1.4 wrong-scope probe lacks its challenge: ${JSON.stringify(wrongScopeChallenge)}`,
    );
    const wrongScopeGrant = wrongScopeResolver.mintForCapability(
      OWNER,
      wrongScopeApproval.policy_hash,
      wrongScopeApproval.request_hash,
    );
    await wrongScopeResolver.recordApproval(
      OWNER,
      wrongScopeApproval.policy_hash,
      wrongScopeApproval.request_hash,
      wrongScopeGrant,
      GENESIS_SCOPE,
    );
    const wrongScopePlaneBefore = await stableDataPlaneSnapshot(call, dataDir);
    const walletStateBeforeWrongScope = requireValue(
      await walletConsumptionStateBytes(
        wrongScopeResolver,
        wrongScopeApproval.request_hash,
      ),
      "M1.4 wrong-scope grant lacks committed wallet consumption state",
    );
    const wrongScope = await call("POST", path, {
      ...request,
      wallet_approval_grant: wrongScopeGrant,
    });
    const walletStateAfterWrongScope = requireValue(
      await walletConsumptionStateBytes(
        wrongScopeResolver,
        wrongScopeApproval.request_hash,
      ),
      "M1.4 wrong-scope refusal removed wallet consumption state",
    );
    const walletStateUnchanged =
      walletStateBeforeWrongScope.equals(walletStateAfterWrongScope);
    const dataPlaneUnchanged =
      wrongScopePlaneBefore === recursiveBytesSnapshot(dataDir);
    ok(
      "AUTHORITY: a wallet-proven wrong-scope grant is discarded unspent with zero mutation",
      wrongScope.status === 422 &&
        wrongScope.body.error?.code ===
          "system_sequence_zero_wallet_consumption_precondition_refused" &&
        walletStateUnchanged &&
        dataPlaneUnchanged &&
        familyFiles(dataDir, INTENT_FAMILY).length === 0 &&
        MATERIALIZATION_FAMILIES.every(
          (family) => familyFiles(dataDir, family).length === 0,
        ),
      `${wrongScope.status}/${wrongScope.body.error?.code || "no-code"} wallet-unchanged=${walletStateUnchanged} data-unchanged=${dataPlaneUnchanged} wallet-bytes=${walletStateAfterWrongScope.length}`,
    );
    await plane.stop();
    plane = undefined;
    await wrongScopeResolver.stop();
    wrongScopeResolver = undefined;
    resolver = await startRealWalletNetworkPrincipalAuthorityFixture();
    plane = await startVerifierPlane({ dataDir, env: resolver.env });
    if (!plane) {
      throw new Error("BLOCKED: correctly scoped primary daemon is not built");
    }

    const correctPlaneBefore = await stableDataPlaneSnapshot(call, dataDir);
    const occupiedFamily = join(dataDir, MATERIALIZATION_FAMILIES[0]);
    const occupiedTail = `aszm_${source.recordRoot.slice("sha256:".length)}`;
    mkdirSync(occupiedFamily, { recursive: true });
    writeFileSync(join(occupiedFamily, `${occupiedTail}.json`), "{}");
    const malformedOccupied = await call("POST", path, request);
    rmSync(occupiedFamily, { recursive: true, force: true });
    ok(
      "PREFLIGHT: malformed occupied record slots refuse as uncertain evidence, never ordinary completion",
      malformedOccupied.status === 500 &&
        malformedOccupied.body.error?.code ===
          "system_sequence_zero_materialization_invalid" &&
        correctPlaneBefore === recursiveBytesSnapshot(dataDir),
      `${malformedOccupied.status}/${malformedOccupied.body.error?.code || "no-code"}`,
    );

    const challenge = await call("POST", path, request);
    const approval = challenge.body.error?.approval;
    const grant =
      approval?.policy_hash && approval?.request_hash
        ? resolver.mintForCapability(
            OWNER,
            approval.policy_hash,
            approval.request_hash,
          )
        : null;
    ok(
      "AUTHORITY: materialization has a distinct real-wallet scope and zero-write challenge",
      challenge.status === 403 &&
        challenge.body.error?.code ===
          "system_sequence_zero_host_authority_required" &&
        challenge.body.error?.required_scope === MATERIALIZE_SCOPE &&
        challenge.body.error?.required_authority_ref === OWNER &&
        grant &&
        correctPlaneBefore === recursiveBytesSnapshot(dataDir),
      `${challenge.status}/${challenge.body.error?.required_scope || "no-scope"}`,
    );
    requireValue(grant, "M1.4 challenge did not produce a grant");

    await resolver.recordApproval(
      OWNER,
      approval.policy_hash,
      approval.request_hash,
      grant,
      MATERIALIZE_SCOPE,
    );

    const nonCanonicalGrant = {
      ...grant,
      memo: "sk-live-SEQUENCE_ZERO-SENTINEL",
    };
    const nonCanonical = await call("POST", path, {
      ...request,
      wallet_approval_grant: nonCanonicalGrant,
    });
    ok(
      "AUTHORITY: unsigned fields outside the closed typed grant projection refuse with zero evidence",
      nonCanonical.status === 403 &&
        nonCanonical.body.error?.code ===
          "system_sequence_zero_host_authority_required" &&
        !JSON.stringify(nonCanonical.body).includes(
          "sk-live-SEQUENCE_ZERO-SENTINEL",
        ) &&
        correctPlaneBefore === recursiveBytesSnapshot(dataDir),
      `${nonCanonical.status}/${nonCanonical.body.error?.code || "no-code"}`,
    );

    const foreignGrant = mintApprovalGrant({
      seed: "08".repeat(32),
      policyHash: approval.policy_hash,
      requestHash: approval.request_hash,
      audience: resolver.capabilityAccountId,
    });
    const foreign = await call("POST", path, {
      ...request,
      wallet_approval_grant: foreignGrant,
    });
    ok(
      "AUTHORITY: same-hash foreign signer refuses with zero mutation",
      foreign.status === 403 &&
        foreign.body.error?.code ===
          "system_sequence_zero_host_authority_required" &&
        correctPlaneBefore === recursiveBytesSnapshot(dataDir),
      `${foreign.status}/${foreign.body.error?.code || "no-code"}`,
    );

    const multiUseGrant = mintApprovalGrant({
      seed: OWNER_APPROVER_SEED,
      policyHash: approval.policy_hash,
      requestHash: approval.request_hash,
      audience: resolver.capabilityAccountId,
      maxUsages: 2,
    });
    const multiUse = await call("POST", path, {
      ...request,
      wallet_approval_grant: multiUseGrant,
    });
    ok(
      "AUTHORITY: a validly signed multi-use grant refuses before mutation",
      multiUse.status === 422 &&
        multiUse.body.error?.code ===
          "system_sequence_zero_authority_evidence_invalid" &&
        correctPlaneBefore === recursiveBytesSnapshot(dataDir),
      `${multiUse.status}/${multiUse.body.error?.code || "no-code"}`,
    );

    const concurrent = await Promise.all(
      Array.from({ length: 12 }, () =>
        call("POST", path, {
          ...request,
          wallet_approval_grant: grant,
        }),
      ),
    );
    const winners = concurrent.filter((response) => response.status === 201);
    const refusals = concurrent.filter((response) => response.status === 409);
    const winner = requireValue(
      winners[0],
      `M1.4 concurrency had no winner: ${JSON.stringify(concurrent)}`,
    );
    ok(
      "CONCURRENCY: twelve exact requests linearize to one materialization",
      winners.length === 1 &&
        refusals.length === 11 &&
        refusals.every(
          (response) =>
            response.body.error?.code ===
            "system_sequence_zero_already_materialized",
        ),
      `created=${winners.length} conflicts=${refusals.length}`,
    );

    const materialization = requireValue(
      winner.body.autonomous_system_sequence_zero_materialization,
      "M1.4 response lacks its materialization",
    );
    const receipt = requireValue(
      winner.body.autonomous_system_sequence_zero_materialization_receipt,
      "M1.4 response lacks its materialization receipt",
    );
    const componentRegistry = requireValue(
      winner.body.component_registry_snapshot,
      "M1.4 response lacks its component-registry snapshot",
    );
    const walletConsumptionReceipt = requireValue(
      winner.body.wallet_grant_consumption_receipt,
      "M1.4 response lacks its wallet consumption receipt",
    );
    const exactEvidence = {
      autonomous_system_sequence_zero_materialization: materialization,
      autonomous_system_sequence_zero_materialization_receipt: receipt,
      component_registry_snapshot: componentRegistry,
      wallet_grant_consumption_receipt: walletConsumptionReceipt,
    };
    const recomputed = recomputeMaterialization(source, materialization);
    ok(
      "ROOTS: all six sequence-zero commitments recompute independently from M1.3 truth",
      recomputed.responseMatches &&
        sameJson(materialization.component_bindings, recomputed.componentBindings) &&
        sameJson(componentRegistry.component_bindings, recomputed.componentBindings) &&
        componentRegistry.component_registry_root ===
          recomputed.componentRegistryRoot &&
        componentRegistry.component_registry_ref ===
          recomputed.componentRegistryRef,
      `${materialization.operation_commitment}/${materialization.initial_state_root}`,
    );
    ok(
      "TRACE: proposal roots remain explicit history and never become operational roots",
      materialization.proposed_initial_state_root ===
        source.record.authorized_genesis.cryptographic_origin.initial_state_root &&
        materialization.proposed_initial_receipt_root ===
          source.record.authorized_genesis.cryptographic_origin.initial_receipt_root &&
        materialization.initial_state_root !==
          materialization.proposed_initial_state_root &&
        materialization.initial_receipt_root !==
          materialization.proposed_initial_receipt_root,
      `${materialization.proposed_initial_state_root} -> ${materialization.initial_state_root}`,
    );
    ok(
      "RECEIPT: the live durable receipt conforms to the closed portable M1.4 profile",
      receipt.output_hash ===
        recordOutputHash(materialization, receipt.hash_scope_excludes || []) &&
        receipt.bound_facts?.proposed_initial_state_root ===
          materialization.proposed_initial_state_root &&
        receipt.bound_facts?.proposed_initial_receipt_root ===
          materialization.proposed_initial_receipt_root &&
        receipt.bound_facts?.deployment_profile_root ===
          recomputed.deploymentProfileRoot &&
        receipt.schema_version ===
          "ioi.autonomous-system-sequence-zero-materialization-receipt.v1" &&
        receipt.receipt_type ===
          "autonomous_system_sequence_zero_materialization" &&
        receipt.receipt_profile_ref ===
          "schema://ioi/foundations/autonomous-system-sequence-zero-materialization-receipt/v1" &&
        receipt.actor_id === "runtime://hypervisor-runtime" &&
        receipt.receipt_id === receipt.receipt_ref &&
        receipt.timestamp === receipt.at &&
        /^grant:\/\/wallet[.]network\/approval\/sha256:[0-9a-f]{64}$/.test(
          receipt.authority_grant_id || "",
        ) &&
        sameJson(receipt.authority_scopes, [MATERIALIZE_SCOPE]) &&
        sameJson(receipt.artifact_refs, []) &&
        receipt.public_commitment_ref === null &&
        !Object.hasOwn(receipt, "l1_commitment") &&
        !receipt.attested_boundary_fact_refs?.some((reference) =>
          String(reference).startsWith(
            "wallet.network://approval-effect-consumption/",
          ),
        ) &&
        receipt.attested_boundary_fact_refs?.includes(
          receipt.bound_facts?.wallet_grant_consumption_evidence_ref,
        ) &&
        String(receipt.bound_facts?.wallet_grant_consumption_ref || "").startsWith(
          "wallet.network://approval-effect-consumption/",
        ) &&
        receipt.assurance_posture ===
          "sequence_zero_materialized_not_activated",
      `${receipt.output_hash}/${receipt.authority_scopes?.join(",")}`,
    );

    const read = await call("GET", path);
    ok(
      "GET PROOF: all four local and Agentgres families equal the POST evidence exactly",
      read.status === 200 &&
        responseHasExactEvidence(read.body, exactEvidence) &&
        hasExactFalseNonclaims(winner.body) &&
        hasExactFalseNonclaims(read.body),
      `${read.status}/${read.body.error?.code || "ok"}`,
    );

    const sourceStatusAfter = await call("GET", "/v1/hypervisor/substrate/status");
    ok(
      "SOURCE IMMUTABILITY: M1.3 bytes and Agentgres heads are unchanged",
      sourceBytesBefore === familiesSnapshot(dataDir, SOURCE_FAMILIES) &&
        sourceStatusBefore.status === 200 &&
        sourceStatusAfter.status === 200 &&
        SOURCE_FAMILIES.every((family) =>
          requiredDomainIsNonVacuous(sourceStatusBefore, family) &&
          requiredDomainIsNonVacuous(sourceStatusAfter, family) &&
          sameJson(
            requiredDomainState(sourceStatusBefore, family),
            requiredDomainState(sourceStatusAfter, family),
          ),
        ),
      `bytes=${sourceBytesBefore === familiesSnapshot(dataDir, SOURCE_FAMILIES)}`,
    );
    const familyEvidence = MATERIALIZATION_FAMILIES.map((family, index) => [
      family,
      exactEvidence[MATERIALIZATION_RESPONSE_FIELDS[index]],
    ]);
    ok(
      "DURABILITY: every M1.4 response has one exact local record and non-vacuous Agentgres proof",
      familyEvidence.every(
        ([family, expected]) =>
          sameJson(singleFamilyRecord(dataDir, family), expected) &&
          requiredDomainIsNonVacuous(sourceStatusAfter, family),
      ) &&
        familyFiles(dataDir, INTENT_FAMILY).length === 0 &&
        tempResidue(dataDir).length === 0,
      JSON.stringify(
        Object.fromEntries(
          MATERIALIZATION_FAMILIES.map((family) => [
            family,
            familyFiles(dataDir, family).length,
          ]),
        ),
      ),
    );

    const localCorruptionCases = [
      {
        family: MATERIALIZATION_FAMILIES[0],
        expectedCode: "system_sequence_zero_materialization_invalid",
        corrupt(value) {
          value.status = "active";
        },
      },
      {
        family: MATERIALIZATION_FAMILIES[1],
        expectedCode: "system_sequence_zero_receipt_evidence_mismatch",
        corrupt(value) {
          value.assurance_posture = "forged_assurance";
        },
      },
      {
        family: MATERIALIZATION_FAMILIES[2],
        expectedCode: "system_sequence_zero_component_evidence_mismatch",
        corrupt(value) {
          value.status = "active";
        },
      },
      {
        family: MATERIALIZATION_FAMILIES[3],
        expectedCode: "system_sequence_zero_agentgres_evidence_mismatch",
        corrupt(value) {
          const consumedAt = Number(value.consumed_at_ms);
          value.consumed_at_ms = consumedAt > 1 ? consumedAt - 1 : consumedAt + 1;
          value.receipt_hash = walletConsumptionReceiptHash(value);
        },
      },
    ];
    for (const testCase of localCorruptionCases) {
      const fileName = requireValue(
        familyFiles(dataDir, testCase.family)[0],
        `M1.4 corruption probe lacks ${testCase.family}`,
      );
      const filePath = join(dataDir, testCase.family, fileName);
      const originalBytes = readFileSync(filePath);
      const corrupted = JSON.parse(originalBytes.toString("utf8"));
      testCase.corrupt(corrupted);
      const corruptedBytes = Buffer.from(JSON.stringify(corrupted));
      requireValue(
        !originalBytes.equals(corruptedBytes),
        `M1.4 ${testCase.family} corruption probe was vacuous`,
      );
      let refused;
      try {
        writeFileSync(filePath, corruptedBytes);
        refused = await call("GET", path);
      } finally {
        writeFileSync(filePath, originalBytes);
      }
      const restored = await call("GET", path);
      ok(
        `GET PROOF: ${testCase.family} corruption refuses typed and exact bytes restore`,
        refused.status === 500 &&
          refused.body.error?.code === testCase.expectedCode &&
          readFileSync(filePath).equals(originalBytes) &&
          restored.status === 200 &&
          responseHasExactEvidence(restored.body, exactEvidence) &&
          hasExactFalseNonclaims(restored.body),
        `${refused.status}/${refused.body.error?.code || "no-code"} restored=${restored.status}/${restored.body.error?.code || "ok"}`,
      );
    }

    const muxPath = join(dataDir, "substrate", "muxlog.bin");
    const muxBytes = readFileSync(muxPath);
    requireValue(
      muxBytes.length > 1,
      "M1.4 Agentgres corruption probe requires a non-empty mux log",
    );
    for (const family of MATERIALIZATION_FAMILIES) {
      const corruptedMuxBytes = corruptAgentgresFamily(muxBytes, family);
      await plane.stop();
      plane = undefined;
      let refused;
      try {
        writeFileSync(muxPath, corruptedMuxBytes);
        plane = await startVerifierPlane({ dataDir, env: resolver.env });
        if (!plane) {
          throw new Error("BLOCKED: Agentgres corruption plane is not built");
        }
        refused = await call("GET", path);
      } finally {
        if (plane) await plane.stop();
        plane = undefined;
        writeFileSync(muxPath, muxBytes);
      }
      plane = await startVerifierPlane({ dataDir, env: resolver.env });
      if (!plane) {
        throw new Error("BLOCKED: Agentgres restoration plane is not built");
      }
      const restored = await call("GET", path);
      ok(
        agentgresCorruptionProofName(family),
        refused.status === 500 &&
          refused.body.error?.code ===
            "system_sequence_zero_agentgres_evidence_mismatch" &&
          readFileSync(muxPath).equals(muxBytes) &&
          restored.status === 200 &&
          responseHasExactEvidence(restored.body, exactEvidence) &&
          hasExactFalseNonclaims(restored.body),
        `${refused.status}/${refused.body.error?.code || "no-code"} restored=${restored.status}/${restored.body.error?.code || "ok"}`,
      );
    }
  } finally {
    if (plane) await plane.stop();
    if (wrongScopeResolver) await wrongScopeResolver.stop();
    if (resolver) await resolver.stop();
    rmSync(dataDir, { recursive: true, force: true });
  }
}

async function runCrashReplayJourney() {
  const resolver = await startRealWalletNetworkPrincipalAuthorityFixture();
  const dataDir = createOwnedDataDir("ioi-system-sequence-zero-replay-");
  let plane;
  try {
    plane = await startVerifierPlane({
      dataDir,
      env: {
        ...resolver.env,
        IOI_TEST_FORCE_SYSTEM_SEQUENCE_ZERO_AFTER_WALLET_CONSUME: "1",
      },
    });
    if (!plane) throw new Error("BLOCKED: target/debug/hypervisor-daemon is not built");
    let call = (method, path, body) =>
      jsonCall(plane.daemonUrl, method, path, body);
    const source = await admitGenesis(call, resolver, dataDir);
    const path =
      `${GENESIS_ROUTE}/${source.sourceTail}/sequence-zero-materialization`;
    const sourceBefore = familiesSnapshot(dataDir, SOURCE_FAMILIES);
    const request = {
      expected_genesis_admission_record_root: source.recordRoot,
      expected_genesis_admission_receipt_root: source.receiptRoot,
    };
    const { grant } = await challengeAndGrant(
      call,
      resolver,
      path,
      request,
      MATERIALIZE_SCOPE,
    );
    requireValue(grant, "replay lane did not mint the M1.4 grant");
    const interrupted = await call("POST", path, {
      ...request,
      wallet_approval_grant: grant,
    });
    ok(
      "REPLAY PREPARE: interruption after wallet consumption retains only the durable intent",
      interrupted.status === 500 &&
        interrupted.body.error?.code ===
          "system_sequence_zero_pending_convergence" &&
        familyFiles(dataDir, INTENT_FAMILY).length === 1 &&
        MATERIALIZATION_FAMILIES.every(
          (family) => familyFiles(dataDir, family).length === 0,
        ),
      `${interrupted.status}/${interrupted.body.error?.code || "no-code"}`,
    );
    await plane.stop();
    await resolver.revokePrincipalAuthority(OWNER);
    plane = await startVerifierPlane({ dataDir, env: resolver.env });
    if (!plane) throw new Error("BLOCKED: restart daemon is not built");
    call = (method, route, body) =>
      jsonCall(plane.daemonUrl, method, route, body);
    const deadline = Date.now() + 90_000;
    let converged;
    while (Date.now() < deadline) {
      converged = await call("GET", path);
      if (converged.status === 200) break;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    ok(
      "REPLAY: an already-consumed grant converges after binding revocation without re-authoring",
      converged?.status === 200 &&
        familyFiles(dataDir, INTENT_FAMILY).length === 0 &&
        MATERIALIZATION_FAMILIES.every(
          (family) => familyFiles(dataDir, family).length === 1,
        ) &&
        converged.body.wallet_grant_consumption_receipt?.usage_ordinal === 1 &&
        converged.body.wallet_grant_consumption_receipt?.remaining_usages === 0 &&
        sourceBefore === familiesSnapshot(dataDir, SOURCE_FAMILIES) &&
        tempResidue(dataDir).length === 0,
      `${converged?.status || "none"}/${converged?.body?.error?.code || "ok"}`,
    );
  } finally {
    if (plane) await plane.stop();
    await resolver.stop();
    rmSync(dataDir, { recursive: true, force: true });
  }
}

async function runPartialPrefixReplayJourney() {
  const resolver = await startRealWalletNetworkPrincipalAuthorityFixture();
  try {
    for (const [index, testCase] of PARTIAL_PREFIX_CASES.entries()) {
      const dataDir = createOwnedDataDir(
        `ioi-system-sequence-zero-${testCase.name}-`,
      );
      let plane;
      try {
        plane = await startVerifierPlane({ dataDir, env: resolver.env });
        if (!plane) {
          throw new Error("BLOCKED: target/debug/hypervisor-daemon is not built");
        }
        let call = (method, path, body) =>
          jsonCall(plane.daemonUrl, method, path, body);
        const source = await admitGenesis(call, resolver, dataDir, {
          genesisId: `genesis://acme/system-alpha/prefix-${index}`,
        });
        const sourceBefore = familiesSnapshot(dataDir, SOURCE_FAMILIES);
        const path =
          `${GENESIS_ROUTE}/${source.sourceTail}/sequence-zero-materialization`;
        const request = {
          expected_genesis_admission_record_root: source.recordRoot,
          expected_genesis_admission_receipt_root: source.receiptRoot,
        };
        await plane.stop();
        plane = await startVerifierPlane({
          dataDir,
          env: { ...resolver.env, ...testCase.env },
        });
        if (!plane) throw new Error("BLOCKED: fault plane is not built");
        call = (method, route, body) =>
          jsonCall(plane.daemonUrl, method, route, body);
        const { grant } = await challengeAndGrant(
          call,
          resolver,
          path,
          request,
          MATERIALIZE_SCOPE,
        );
        requireValue(grant, `${testCase.name} did not mint a grant`);
        const interrupted = await call("POST", path, {
          ...request,
          wallet_approval_grant: grant,
        });
        const pending = await call("GET", path);
        const counts = MATERIALIZATION_FAMILIES.map(
          (family) => familyFiles(dataDir, family).length,
        );
        ok(
          `PREFIX ${testCase.name}: partial evidence stays non-servable with its replay anchor`,
          interrupted.status === 500 &&
            interrupted.body.error?.code === testCase.interruptedCode &&
            pending.status === 500 &&
            pending.body.error?.code ===
              "system_sequence_zero_pending_convergence" &&
            sameJson(counts, testCase.expectedCounts) &&
            familyFiles(dataDir, INTENT_FAMILY).length === 1 &&
            sourceBefore === familiesSnapshot(dataDir, SOURCE_FAMILIES),
          `${interrupted.status}/${interrupted.body.error?.code || "no-code"} counts=${counts.join(",")}`,
        );

        await plane.stop();
        plane = await startVerifierPlane({ dataDir, env: resolver.env });
        if (!plane) throw new Error("BLOCKED: replay plane is not built");
        call = (method, route, body) =>
          jsonCall(plane.daemonUrl, method, route, body);
        const deadline = Date.now() + 90_000;
        let converged;
        while (Date.now() < deadline) {
          converged = await call("GET", path);
          if (converged.status === 200) break;
          await new Promise((resolve) => setTimeout(resolve, 50));
        }
        ok(
          `PREFIX ${testCase.name}: restart converges exactly once without another authority use`,
          converged?.status === 200 &&
            familyFiles(dataDir, INTENT_FAMILY).length === 0 &&
            MATERIALIZATION_FAMILIES.every(
              (family) => familyFiles(dataDir, family).length === 1,
            ) &&
            converged.body.wallet_grant_consumption_receipt?.usage_ordinal ===
              1 &&
            converged.body.wallet_grant_consumption_receipt
              ?.remaining_usages === 0 &&
            sourceBefore === familiesSnapshot(dataDir, SOURCE_FAMILIES) &&
            tempResidue(dataDir).length === 0,
          `${converged?.status || "none"}/${converged?.body?.error?.code || "ok"}`,
        );
      } finally {
        if (plane) await plane.stop();
        rmSync(dataDir, { recursive: true, force: true });
      }
    }
  } finally {
    await resolver.stop();
  }
}

async function runDependencyOrderedReplayJourney() {
  const resolver = await startRealWalletNetworkPrincipalAuthorityFixture();
  const dataDir = createOwnedDataDir(
    "ioi-system-sequence-zero-dependency-order-",
  );
  let plane;
  try {
    plane = await startVerifierPlane({
      dataDir,
      env: {
        ...resolver.env,
        IOI_TEST_FORCE_SYSTEM_GENESIS_AFTER_AGENTGRES: "1",
      },
    });
    if (!plane) throw new Error("BLOCKED: target/debug/hypervisor-daemon is not built");
    let call = (method, path, body) =>
      jsonCall(plane.daemonUrl, method, path, body);
    const genesisBody = exactGenesisBody(
      "genesis://acme/system-alpha/dependency-order",
    );
    const { grant: genesisGrant } = await challengeAndGrant(
      call,
      resolver,
      GENESIS_ROUTE,
      genesisBody,
      GENESIS_SCOPE,
    );
    requireValue(genesisGrant, "dependency replay did not mint the M1.3 grant");
    const interruptedGenesis = await call("POST", GENESIS_ROUTE, {
      ...genesisBody,
      wallet_approval_grant: genesisGrant,
    });
    const source = persistedGenesisSource(dataDir);
    const sourceIntentName = requireValue(
      familyFiles(dataDir, SOURCE_INTENT_FAMILY)[0],
      "dependency replay lacks its M1.3 intent",
    );
    const sourceIntentBytes = readFileSync(
      join(dataDir, SOURCE_INTENT_FAMILY, sourceIntentName),
    );
    ok(
      "DEPENDENCY PREPARE: M1.3 can retain a fully admitted replay anchor",
      interruptedGenesis.status === 500 &&
        interruptedGenesis.body.error?.code ===
          "system_genesis_pending_convergence" &&
        SOURCE_FAMILIES.every(
          (family) => familyFiles(dataDir, family).length === 1,
        ) &&
        familyFiles(dataDir, SOURCE_INTENT_FAMILY).length === 1,
      `${interruptedGenesis.status}/${interruptedGenesis.body.error?.code || "no-code"}`,
    );

    await plane.stop();
    plane = await startVerifierPlane({ dataDir, env: resolver.env });
    if (!plane) throw new Error("BLOCKED: M1.3 replay plane is not built");
    call = (method, route, body) =>
      jsonCall(plane.daemonUrl, method, route, body);
    const sourcePath = `${GENESIS_ROUTE}/${source.sourceTail}`;
    const sourceDeadline = Date.now() + 90_000;
    let sourceRead;
    while (Date.now() < sourceDeadline) {
      sourceRead = await call("GET", sourcePath);
      if (
        sourceRead.status === 200 &&
        familyFiles(dataDir, SOURCE_INTENT_FAMILY).length === 0
      ) {
        break;
      }
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    requireValue(
      sourceRead?.status === 200 &&
        familyFiles(dataDir, SOURCE_INTENT_FAMILY).length === 0,
      "dependency replay could not first converge M1.3",
    );

    await plane.stop();
    plane = await startVerifierPlane({
      dataDir,
      env: {
        ...resolver.env,
        IOI_TEST_FORCE_SYSTEM_SEQUENCE_ZERO_AFTER_PREPARE: "1",
      },
    });
    if (!plane) throw new Error("BLOCKED: M1.4 prepare plane is not built");
    call = (method, route, body) =>
      jsonCall(plane.daemonUrl, method, route, body);
    const path =
      `${GENESIS_ROUTE}/${source.sourceTail}/sequence-zero-materialization`;
    const request = {
      expected_genesis_admission_record_root: source.recordRoot,
      expected_genesis_admission_receipt_root: source.receiptRoot,
    };
    const { grant } = await challengeAndGrant(
      call,
      resolver,
      path,
      request,
      MATERIALIZE_SCOPE,
    );
    requireValue(grant, "dependency replay did not mint the M1.4 grant");
    const interruptedMaterialization = await call("POST", path, {
      ...request,
      wallet_approval_grant: grant,
    });
    requireValue(
      interruptedMaterialization.status === 500 &&
        interruptedMaterialization.body.error?.code ===
          "system_sequence_zero_pending_convergence" &&
        familyFiles(dataDir, INTENT_FAMILY).length === 1,
      "dependency replay could not retain its M1.4 intent",
    );
    await plane.stop();
    plane = undefined;

    mkdirSync(join(dataDir, SOURCE_INTENT_FAMILY), { recursive: true });
    writeFileSync(
      join(dataDir, SOURCE_INTENT_FAMILY, sourceIntentName),
      sourceIntentBytes,
    );
    plane = await startVerifierPlane({ dataDir, env: resolver.env });
    if (!plane) throw new Error("BLOCKED: ordered replay plane is not built");
    call = (method, route, body) =>
      jsonCall(plane.daemonUrl, method, route, body);
    const deadline = Date.now() + 90_000;
    let converged;
    while (Date.now() < deadline) {
      converged = await call("GET", path);
      if (converged.status === 200) break;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    ok(
      "DEPENDENCY REPLAY: one boot converges M1.3 before its M1.4 successor",
      converged?.status === 200 &&
        familyFiles(dataDir, SOURCE_INTENT_FAMILY).length === 0 &&
        familyFiles(dataDir, INTENT_FAMILY).length === 0 &&
        MATERIALIZATION_FAMILIES.every(
          (family) => familyFiles(dataDir, family).length === 1,
        ) &&
        converged.body.wallet_grant_consumption_receipt?.usage_ordinal === 1 &&
        converged.body.wallet_grant_consumption_receipt?.remaining_usages ===
          0 &&
        tempResidue(dataDir).length === 0,
      `${converged?.status || "none"}/${converged?.body?.error?.code || "ok"}`,
    );
  } finally {
    if (plane) await plane.stop();
    await resolver.stop();
    rmSync(dataDir, { recursive: true, force: true });
  }
}

async function runUnconsumedRevocationJourney() {
  const resolver = await startRealWalletNetworkPrincipalAuthorityFixture();
  const dataDir = createOwnedDataDir(
    "ioi-system-sequence-zero-unconsumed-revocation-",
  );
  let plane;
  try {
    plane = await startVerifierPlane({
      dataDir,
      env: {
        ...resolver.env,
        IOI_TEST_FORCE_SYSTEM_SEQUENCE_ZERO_AFTER_PREPARE: "1",
      },
    });
    if (!plane) throw new Error("BLOCKED: target/debug/hypervisor-daemon is not built");
    let call = (method, path, body) =>
      jsonCall(plane.daemonUrl, method, path, body);
    const source = await admitGenesis(call, resolver, dataDir);
    const path =
      `${GENESIS_ROUTE}/${source.sourceTail}/sequence-zero-materialization`;
    const sourceBefore = familiesSnapshot(dataDir, SOURCE_FAMILIES);
    const request = {
      expected_genesis_admission_record_root: source.recordRoot,
      expected_genesis_admission_receipt_root: source.receiptRoot,
    };
    const { grant } = await challengeAndGrant(
      call,
      resolver,
      path,
      request,
      MATERIALIZE_SCOPE,
    );
    requireValue(grant, "unconsumed-revocation lane did not mint the M1.4 grant");
    const interrupted = await call("POST", path, {
      ...request,
      wallet_approval_grant: grant,
    });
    const intentBeforeRevocation = familiesSnapshot(dataDir, [INTENT_FAMILY]);
    ok(
      "REPLAY PRE-AUTHORITY: interruption after prepare retains an unconsumed intent only",
      interrupted.status === 500 &&
        interrupted.body.error?.code ===
          "system_sequence_zero_pending_convergence" &&
        familyFiles(dataDir, INTENT_FAMILY).length === 1 &&
        MATERIALIZATION_FAMILIES.every(
          (family) => familyFiles(dataDir, family).length === 0,
        ),
      `${interrupted.status}/${interrupted.body.error?.code || "no-code"}`,
    );

    await plane.stop();
    await resolver.revokePrincipalAuthority(OWNER);
    plane = await startVerifierPlane({ dataDir, env: resolver.env });
    if (!plane) throw new Error("BLOCKED: restart daemon is not built");
    call = (method, route, body) =>
      jsonCall(plane.daemonUrl, method, route, body);
    await new Promise((resolve) => setTimeout(resolve, 750));
    const pending = await call("GET", path);
    ok(
      "REPLAY AUTHORITY: an unconsumed grant cannot cross a revoked binding on restart",
      pending.status === 500 &&
        pending.body.error?.code ===
          "system_sequence_zero_pending_convergence" &&
        intentBeforeRevocation === familiesSnapshot(dataDir, [INTENT_FAMILY]) &&
        MATERIALIZATION_FAMILIES.every(
          (family) => familyFiles(dataDir, family).length === 0,
        ) &&
        sourceBefore === familiesSnapshot(dataDir, SOURCE_FAMILIES) &&
        tempResidue(dataDir).length === 0,
      `${pending.status}/${pending.body.error?.code || "no-code"}`,
    );
  } finally {
    if (plane) await plane.stop();
    await resolver.stop();
    rmSync(dataDir, { recursive: true, force: true });
  }
}

function selectJourneys(rawSelection, journeyNames) {
  const available = [...journeyNames];
  if (rawSelection === undefined) return available;
  const tokens = rawSelection.split(",").map((value) => value.trim());
  if (tokens.length === 0 || tokens.some((value) => value.length === 0)) {
    throw new Error(
      `${JOURNEY_SELECTOR_ENV} must name one or more comma-separated journeys without empty entries`,
    );
  }
  const seen = new Set();
  for (const name of tokens) {
    if (seen.has(name)) {
      throw new Error(
        `${JOURNEY_SELECTOR_ENV} contains duplicate journey '${name}'`,
      );
    }
    if (!available.includes(name)) {
      throw new Error(
        `${JOURNEY_SELECTOR_ENV} names unknown journey '${name}'`,
      );
    }
    seen.add(name);
  }
  return tokens;
}

function selectorRefuses(rawSelection, journeyNames, expectedFragment) {
  try {
    selectJourneys(rawSelection, journeyNames);
    return false;
  } catch (error) {
    return String(error.message || error).includes(expectedFragment);
  }
}

function sameJourneySet(left, right) {
  return (
    left.length === right.length &&
    new Set(left).size === left.length &&
    left.every((name) => right.includes(name))
  );
}

async function run() {
  let fatal;
  let requiredJourneys = [];
  let selectedJourneys = [];
  try {
    const routeSource = readFileSync(SYSTEM_SEQUENCE_ZERO_SOURCE, "utf8");
    const verifierSource = readFileSync(VERIFIER_SOURCE, "utf8");
    ok(
      "SOURCE: the held verifier is pinned to all four required M1.4 evidence families",
      MATERIALIZATION_FAMILIES.every((family) =>
        routeSource.includes(`"${family}"`),
      ) &&
        MATERIALIZATION_RESPONSE_FIELDS.every(
          (field) => routeSource.split(`"${field}"`).length >= 3,
        ) &&
        routeSource.includes("verify_required_exact"),
      `families=${MATERIALIZATION_FAMILIES.filter((family) =>
        routeSource.includes(`"${family}"`),
      ).length}/${MATERIALIZATION_FAMILIES.length}`,
    );
    const journeys = new Map([
      ["primary", runPrimaryJourney],
      ["wallet-replay", runCrashReplayJourney],
      ["partial-prefix-replay", runPartialPrefixReplayJourney],
      ["dependency-ordered-replay", runDependencyOrderedReplayJourney],
      ["unconsumed-revocation", runUnconsumedRevocationJourney],
    ]);
    requiredJourneys = [...journeys.keys()];
    ok(
      "SOURCE GUARD: every held journey has an exact nonempty proof and resource census",
      sameJson([...JOURNEY_PROOF_CENSUS.keys()], requiredJourneys) &&
        [...JOURNEY_PROOF_CENSUS.values()].every(
          ({ proofs, resources }) =>
            proofs.length > 0 &&
            new Set(proofs).size === proofs.length &&
            Number.isInteger(resources) &&
            resources > 0,
        ) &&
        verifierSource.includes(
          "await executeJourneyWithCensus(name, journey)",
        ),
      `journeys=${JOURNEY_PROOF_CENSUS.size}/${requiredJourneys.length}`,
    );
    ok(
      "SELF-TEST: substituting async no-ops for all five journeys fails certification",
      await noopJourneysRefuseCertification(),
    );
    ok(
      "SELF-TEST: an empty verifier-owned resource ledger cannot satisfy teardown",
      !teardownComplete(new Map(), ["primary"]),
    );
    ok(
      "SELECTOR: an omitted selector defaults to every journey",
      sameJson(
        selectJourneys(undefined, requiredJourneys),
        requiredJourneys,
      ),
    );
    ok(
      "SELECTOR: delimiter-only and empty-token selectors fail closed",
      selectorRefuses(" , ", requiredJourneys, "without empty entries") &&
        selectorRefuses(
          "primary,,wallet-replay",
          requiredJourneys,
          "without empty entries",
        ),
    );
    ok(
      "SELECTOR: duplicate journeys fail closed",
      selectorRefuses(
        "primary,primary",
        requiredJourneys,
        "duplicate journey 'primary'",
      ),
    );
    ok(
      "SELECTOR: unknown journeys fail closed",
      selectorRefuses(
        "primary,not-a-journey",
        requiredJourneys,
        "unknown journey 'not-a-journey'",
      ),
    );
    ok(
      "SELECTOR: a valid subset remains focused and ordered",
      sameJson(
        selectJourneys(
          "wallet-replay, primary",
          requiredJourneys,
        ),
        ["wallet-replay", "primary"],
      ),
    );
    selectedJourneys = selectJourneys(
      process.env[JOURNEY_SELECTOR_ENV],
      requiredJourneys,
    );
    for (const name of selectedJourneys) {
      const journey = journeys.get(name);
      await executeJourneyWithCensus(name, journey);
      executedJourneys.push(name);
    }
  } catch (error) {
    fatal = error;
  }
  ok(
    "TEARDOWN: the nonempty exact verifier-owned resource ledger is fully removed",
    teardownComplete(ownedDataDirs, selectedJourneys),
    `owned=${ownedDataDirs.size} removed=${[...ownedDataDirs.keys()].filter((path) => !existsSync(path)).length}`,
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
  if (sameJourneySet(executedJourneys, requiredJourneys)) {
    console.log(
      `system sequence-zero materialization held bar: PASS (journeys=${executedJourneys.join(",")}; real-wallet authority and exact durable evidence verified)`,
    );
  } else {
    console.log(
      `system sequence-zero materialization focused verifier: PASS (journeys=${executedJourneys.join(",")}; subset only, held bar not claimed)`,
    );
  }
}

run().catch((error) => {
  console.error("VERIFIER CRASH:", error);
  process.exitCode = 1;
});
