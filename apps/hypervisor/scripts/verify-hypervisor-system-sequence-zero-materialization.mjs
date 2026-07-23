#!/usr/bin/env node
// M1.4 sequence-zero materialization held bar. Every successful mutation crosses the real
// wallet.network fixture and every plane runs on caller-owned isolated storage.

import { createHash, randomUUID } from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import {
  closeSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import grpc from "@grpc/grpc-js";
import protoLoader from "@grpc/proto-loader";

import { mintApprovalGrant } from "../../../scripts/lib/mint-approval-grant.mjs";
import {
  DAEMON_BINARY,
  startIsolatedPlane,
} from "./lib/isolated-daemon.mjs";
import {
  startRealWalletNetworkPrincipalAuthorityFixture,
  walletFixtureOwnerIdentityMatches,
  walletFixtureProcessGroupAlive,
  walletFixtureProcessGroupIdentityMatches,
  walletFixtureProcessGroupStartTimeTicks,
} from "./lib/wallet-network-principal-authority-fixture.mjs";

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
const COMPATIBILITY_BASE_COMMIT =
  "562d1b08999be2e9bbb967ef60bb250f440452e5";
const LEGACY_RECEIPT_WRITER_COMMIT =
  "7280df95cc5f327f86b99f7d204674602c086a6a";
const COMPATIBILITY_FIXTURE_SHA256 = new Map([
  [
    "autonomous-system-genesis-v1/positive-proposed.json",
    "904170cd53850f7980cc8073127884792e54a74a1a6c916c31908cd84b0973db",
  ],
  [
    "autonomous-system-manifest-v1/positive-reusable-release.json",
    "fdf0f9857e5981aaa64acf3a02501cd8f992da20999865e155750b668df5c539",
  ],
  [
    "autonomous-system-constitution-v1/positive-draft.json",
    "3c344fbd37c4421a282898bb582273897692c3d7113a48cd70e8caef81eb520a",
  ],
  [
    "ordering-admission-finality-profile-v1/positive-single-authority.json",
    "cd5ca8bd88750bd21bddf2de267fc6c31c329704562fa060dd0bb5f20224d224",
  ],
  [
    "oracle-evidence-profile-v1/positive-fail-closed.json",
    "863e854daf9f26cbf317f7ea0e5d78579e219802a3be93d823d06ca008cbd46a",
  ],
  [
    "lifecycle-continuity-profile-v1/positive-successor-governed.json",
    "78be672419d800a4b02c43735400259ca44cc32c7f8623efdc6ea65836519066",
  ],
]);
const GENESIS_ROUTE = "/v1/hypervisor/autonomous-systems";
const OWNER = "org://acme/research";
const OWNER_APPROVER_SEED = "07".repeat(32);
const FOREIGN_WALLET_ROOT_SEED = "42".repeat(32);
const GENESIS_SCOPE = "scope:autonomous_system.genesis_admit";
const MATERIALIZE_SCOPE = "scope:autonomous_system.genesis_materialize";
const INITIALIZE_SCOPE = "scope:autonomous_system.lifecycle.initialize";
const ACTIVATE_SCOPE = "scope:autonomous_system.lifecycle.activate";
const LEGACY_RECEIPT_SCHEMA =
  "ioi.autonomous-system-sequence-zero-materialization-receipt.v1";
const LEGACY_RECEIPT_PROFILE =
  "schema://ioi/foundations/autonomous-system-sequence-zero-materialization-receipt/v1";
const CURRENT_RECEIPT_SCHEMA =
  "ioi.autonomous-system-sequence-zero-materialization-receipt.v2";
const CURRENT_RECEIPT_PROFILE =
  "schema://ioi/foundations/autonomous-system-sequence-zero-materialization-receipt/v2";
const JOURNEY_SELECTOR_ENV =
  "IOI_SYSTEM_SEQUENCE_ZERO_VERIFIER_JOURNEYS";
const FOCUSED_VERIFIER_OPT_IN_ENV =
  "IOI_SYSTEM_SEQUENCE_ZERO_ALLOW_FOCUSED";
const CERTIFICATION_MODE_ENV =
  "IOI_SYSTEM_SEQUENCE_ZERO_CERTIFY";
const POST_WALLET_CRASH_PAUSE_ENV =
  "IOI_TEST_PAUSE_SYSTEM_SEQUENCE_ZERO_AFTER_WALLET_CONSUMPTION_EVIDENCE";
const POST_WALLET_CRASH_MARKER_ENV =
  "IOI_TEST_SYSTEM_SEQUENCE_ZERO_WALLET_EVIDENCE_MARKER_PATH";
const TERMINAL_UNLINK_CRASH_FAMILY_ENV =
  "IOI_TEST_PAUSE_AFTER_TERMINAL_INTENT_UNLINK_FAMILY";
const TERMINAL_UNLINK_CRASH_MARKER_ENV =
  "IOI_TEST_TERMINAL_INTENT_UNLINKED_MARKER_PATH";
const UNCONFIRMED_RESTORE_CRASH_FAMILY_ENV =
  "IOI_TEST_PAUSE_AFTER_UNCONFIRMED_INTENT_RESTORE_FAMILY";
const UNCONFIRMED_RESTORE_CRASH_MARKER_ENV =
  "IOI_TEST_UNCONFIRMED_INTENT_RESTORED_MARKER_PATH";
const SOURCE_FAMILIES = [
  "autonomous-system-genesis-registry",
  "autonomous-system-genesis-receipts",
  "autonomous-system-genesis-authority-consumptions",
];
const CATALOG_SEED_FAMILIES = [
  "model-providers",
  "model-provider-inventory",
  "model-backend-lifecycle-controls",
];
const SOURCE_INTENT_FAMILY = "autonomous-system-genesis-intents";
const SOURCE_RESPONSE_FIELDS = [
  "autonomous_system_genesis_admission",
  "autonomous_system_genesis_receipt",
  "wallet_grant_consumption_receipt",
];
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
const INITIALIZE_INTENT_FAMILY = "autonomous-system-initialize-intents";
const ACTIVATE_INTENT_FAMILY = "autonomous-system-activate-intents";
const LIFECYCLE_FAMILIES = [
  "autonomous-system-deployment-profile-revisions",
  "autonomous-system-lifecycle-authority-evidence",
  "autonomous-system-lifecycle-authority-consumptions",
  "autonomous-system-lifecycle-proposals",
  "autonomous-system-lifecycle-authority-decisions",
  "autonomous-system-lifecycle-transitions",
  "autonomous-system-initialize-transition-receipts",
  "autonomous-system-activation-receipts",
  "autonomous-system-activation-states",
  "autonomous-system-active-profile-sets",
  "autonomous-system-home-bindings",
  "autonomous-system-operation-log-revisions",
  "autonomous-system-chain-revisions",
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
    "constitutional-amendment",
    {
      resources: 2,
      proofs: [
        "M1.5c ELIGIBILITY: amendment admits from the active head with zero committed amendment evidence",
        "M1.5c DECLARED DIFF: an over-declared and an undeclared change both refuse before authority with zero evidence",
        "M1.5c PROTECTED CLAUSE: a change under a declared protected path refuses before authority with zero evidence",
        "M1.5c MACHINE FLOOR: rewriting the governance subtree refuses as machine-protected with zero evidence",
        "M1.5c STALE HEAD: an expected chain head that is not the live head refuses conflict with zero evidence",
        "M1.5c WRONG SCOPE: a pause-scoped grant cannot authorize constitutional amendment",
        "M1.5c AMEND: a real-wallet amendment swaps the constitution and profile set at one sequence with operational status unchanged",
      ],
    },
  ],
  [
    "protected-transition",
    {
      resources: 2,
      proofs: [
        "M1.5b ELIGIBILITY: pause admits from active while complete_recovery refuses the canon matrix",
        "M1.5b ILLEGAL MATRIX: complete_recovery over active refuses before any authority with zero lifecycle evidence",
        "M1.5b STALE HEAD: an expected chain head behind the live head refuses conflict with zero evidence",
        "M1.5b PAUSE: twelve real-wallet pause requests linearize to one sequence-three graph",
        "M1.5b WRONG SCOPE: a resume-scoped grant cannot authorize suspend",
        "M1.5b REPLAY: a crash after wallet consumption converges exactly one resume at sequence four on restart",
      ],
    },
  ],
  [
    "system-activation",
    {
      resources: 2,
      proofs: [
        "M1.5a INTAKE: embedded sensitive-key aliases refuse before authority with zero lifecycle evidence",
        "M1.5a INITIALIZE: twelve real-wallet requests linearize to one initialized sequence-one graph",
        "M1.5a INITIALIZE GET: complete graph is exact and carries no active set or chain",
        "M1.5a ACTIVATE PARTIAL: activation parks after a real wallet use and one local write while the competing lifecycle operation refuses",
        "M1.5a INTENT IDENTITY: a relocated sealed activation intent refuses without replay or mutation",
        "M1.5a ACTIVATE REPLAY: restart reuses the consumed grant and converges exactly one sequence-two graph",
        "M1.5a ACTIVATE GET: exact 0/1/2 log and compact non-runtime chain are fully durable",
        "M1.5a SOURCE: real M1.3/M1.4 bytes remain unchanged across initialize and activate",
      ],
    },
  ],
  [
    "primary",
    {
      resources: 5,
      proofs: [
        "M1.3 AUTHORITY: wrong-scope refusal leaves the exact wallet approval-consumption slot and daemon tree byte-exact",
        "SOURCE: M1.3 local and Agentgres evidence is exact and non-vacuous before M1.4",
        "INTAKE: callers cannot author operational roots",
        "INTAKE: recursive sensitive keys refuse before any write",
        "CAS: stale M1.3 source roots refuse before authority with a byte-exact daemon tree",
        "CATALOG SEED IDEMPOTENCY: two consecutive fresh-daemon boots preserve exact seed-catalog names and bytes",
        "AUTHORITY: wrong-scope refusal leaves the exact wallet approval-consumption slot and daemon tree byte-exact",
        "PREFLIGHT: malformed occupied record slots refuse as uncertain evidence, never ordinary completion",
        "AUTHORITY: materialization has a distinct real-wallet scope and byte-exact daemon-tree challenge",
        "AUTHORITY: unsigned fields outside the closed typed grant projection refuse with zero evidence",
        "AUTHORITY: same-hash foreign signer refuses with a byte-exact daemon tree",
        "AUTHORITY: a validly signed multi-use grant refuses before mutation",
        "CONCURRENCY: twelve exact requests linearize to one materialization",
        "ROOTS: all six sequence-zero commitments recompute independently from M1.3 truth",
        "TRACE: proposal roots remain explicit history and never become operational roots",
        "RECEIPT: the live durable receipt conforms to the closed portable M1.4 profile",
        "RECEIPT: authority_grant_id and boundary refs bind the independently recomputed signed-grant JCS hash",
        "GET PROOF: all four local and Agentgres families equal the POST evidence exactly",
        "SOURCE IMMUTABILITY: M1.3 bytes and Agentgres heads are unchanged",
        "DURABILITY: every M1.4 response has one exact local record and non-vacuous Agentgres proof",
        "GET AUTHORITY ROOT: converged evidence signed by a foreign configured wallet root refuses byte-exactly",
        ...MATERIALIZATION_FAMILIES.map(localCorruptionProofName),
        ...MATERIALIZATION_FAMILIES.map(agentgresCorruptionProofName),
      ],
    },
  ],
  [
    "wallet-replay",
    {
      resources: 3,
      proofs: [
        "CRASH POST-WALLET: a marker-pinned durable intent survives SIGKILL while the request is still in flight",
        "CRASH POST-WALLET RESTART: the same data directory converges the exact four-family evidence once",
        "REPLAY PREPARE: interruption after wallet consumption retains only the durable intent",
        "REPLAY GUARD: a structurally rebound but cryptographically forged retained binding is quarantined byte-exactly",
        "REPLAY: an already-consumed grant converges after binding revocation without re-authoring",
      ],
    },
  ],
  [
    "partial-prefix-replay",
    {
      resources: PARTIAL_PREFIX_CASES.length + 1,
      proofs: PARTIAL_PREFIX_CASES.flatMap(({ name }) => [
        `PREFIX ${name}: partial evidence stays non-servable with its replay anchor`,
        `PREFIX ${name}: restart converges exactly once without another authority use`,
      ]),
    },
  ],
  [
    "dependency-ordered-replay",
    {
      resources: 2,
      proofs: [
        "DEPENDENCY PREPARE: M1.3 can retain a fully admitted replay anchor",
        "DEPENDENCY REPLAY: one boot converges M1.3 before its M1.4 successor",
      ],
    },
  ],
  [
    "unconsumed-revocation",
    {
      resources: 2,
      proofs: [
        "REPLAY PRE-AUTHORITY: interruption after prepare retains an unconsumed intent only",
        "REPLAY AUTHORITY: an unconsumed grant cannot cross a revoked binding on restart",
      ],
    },
  ],
  [
    "cross-version-compatibility",
    {
      resources: 5,
      proofs: [
        "COMPAT SOURCE: the pinned M1.3 predecessor admits its exact historical request bundle with the unversioned deployment profile",
        "COMPAT UPGRADE: HEAD materializes M1.4 from the preserved predecessor M1.3 evidence",
        "COMPAT IMMUTABILITY: HEAD leaves predecessor M1.3 local bytes and Agentgres domain coordinates unchanged",
        "COMPAT LEGACY PRE-CONSUMPTION: HEAD replays untouched predecessor intent bytes",
        "COMPAT LEGACY POST-CONSUMPTION: HEAD reuses the consumed grant and converges untouched predecessor intent bytes",
        "REPLAY ISOLATION: an unrelated owner running past its watchdog cannot starve consumed System convergence",
      ],
    },
  ],
  [
    "receipt-version-compatibility",
    {
      resources: 4,
      proofs: [
        "RECEIPT COMPAT V1 REPLAY GUARD: the current daemon retains an interrupted historical intent without creating its missing v1 receipt",
        "RECEIPT COMPAT V1 WRITE: the pinned historical daemon emits the frozen identity and exact historical boundary semantics",
        "RECEIPT COMPAT V1 READ: the current daemon serves the historical receipt byte-exactly without rewriting any M1.4 family",
        "RECEIPT COMPAT V2 WRITE: an ordinary current daemon emits only the current identity and exact retained-grant boundary semantics",
        "RECEIPT COMPAT SPLIT: historical read support and current write policy remain distinct, non-aliased contracts",
      ],
    },
  ],
  [
    "precondition-cleanup",
    {
      resources: 3,
      proofs: [
        "CLEANUP M1.3 PREPARE: a wrong-target grant adds one record to the daemon-owned intent family",
        "CLEANUP M1.3 RESTART: precondition refusal restores the exact empty intent-family baseline",
        "CLEANUP M1.4 PREPARE: a wrong-target grant adds one record to the daemon-owned intent family",
        "CLEANUP M1.4 RESTART: precondition refusal restores the exact empty intent-family baseline",
      ],
    },
  ],
  [
    "terminal-intent-durability",
    {
      resources: 4,
      proofs: [
        "TERMINAL M1.3 SIGKILL: committed evidence and an absent replay anchor survive a marker-pinned post-unlink crash",
        "TERMINAL M1.3 RESTART: the same data directory serves the exact admission with no replay anchor",
        "TERMINAL M1.4 SIGKILL: committed evidence and an absent replay anchor survive a marker-pinned post-unlink crash",
        "TERMINAL M1.4 RESTART: the same data directory serves all exact materialization evidence with no replay anchor",
        "TERMINAL M1.4 PRE-FSYNC: an unconfirmed intent unlink restores its byte-exact replay anchor after all evidence is durable",
        "TERMINAL M1.4 PRE-FSYNC RESTART: the restored anchor converges to the exact already-durable evidence",
      ],
    },
  ],
]);

const results = [];
const ownedResources = new Map();
const ownedBinaryChildren = new Set();
const ownedProcessGroups = new Map();
const executedJourneys = [];
let activeJourney = null;
let publicApiConstructor;
const VERIFIER_OWNER_MARKER = ".ioi-verifier-owner.json";
const VERIFIER_TEMP_OWNER_POLICIES = [
  {
    prefix: "ioi-system-",
    ownerKind: "system-sequence-zero-held-bar",
  },
  {
    prefix: "ioi-m13-",
    ownerKind: "system-sequence-zero-held-bar",
  },
  {
    prefix: "ioi-wallet-network-pa-",
    ownerKind: "wallet-network-principal-authority-fixture",
    ownsProcessGroup: true,
  },
];

process.on("exit", () => {
  for (const child of ownedBinaryChildren) {
    try {
      child.kill("SIGKILL");
    } catch {
      // The verifier is already exiting.
    }
  }
  for (const [processGroupId, startTimeTicks] of ownedProcessGroups) {
    if (ownedProcessGroupIdentityIsAlive(processGroupId, startTimeTicks)) {
      try {
        process.kill(-processGroupId, "SIGKILL");
      } catch {
        // The verifier is already exiting.
      }
    }
  }
  for (const resource of ownedResources.keys()) {
    try {
      rmSync(resource, { recursive: true, force: true });
    } catch {
      // Best effort only during abnormal process teardown.
    }
  }
});

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

function createOwnedTempDir(prefix) {
  requireValue(activeJourney, "verifier-owned resources require an active journey");
  const resourceDir = mkdtempSync(join(tmpdir(), prefix));
  if (ownedResources.has(resourceDir)) {
    throw new Error(`verifier-owned resource was registered twice: ${resourceDir}`);
  }
  writeFileSync(
    join(resourceDir, VERIFIER_OWNER_MARKER),
    JSON.stringify({
      schema_version: 1,
      owner_pid: process.pid,
      owner_kind: "system-sequence-zero-held-bar",
    }),
    { mode: 0o600 },
  );
  ownedResources.set(resourceDir, activeJourney);
  return resourceDir;
}

function processIsAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error?.code === "EPERM";
  }
}

async function waitForCrashMarker(markerPath, timeoutMs = 90_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (existsSync(markerPath)) {
      return readFileSync(markerPath);
    }
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error(`crash marker did not appear within ${timeoutMs}ms: ${markerPath}`);
}

function observedRequest(promise) {
  return promise.then(
    (response) => ({ kind: "response", response }),
    (error) => ({ kind: "error", error }),
  );
}

async function sigkillPlaneAtMarker({
  plane,
  markerPath,
  inFlight,
  boundaryReady,
  captureAtBoundary,
}) {
  const firstBoundary = await Promise.race([
    waitForCrashMarker(markerPath).then((markerBytes) => ({
      kind: "marker",
      markerBytes,
    })),
    inFlight.then((requestOutcome) => ({
      kind: "request",
      requestOutcome,
    })),
  ]);
  if (firstBoundary.kind === "request") {
    throw new Error(
      `request completed before crash marker ${markerPath}: ${canonicalJson(firstBoundary.requestOutcome)}`,
    );
  }
  const markerBytes = firstBoundary.markerBytes;
  requireValue(
    markerBytes.length > 0,
    `crash marker is empty: ${markerPath}`,
  );
  requireValue(
    boundaryReady(),
    `durable crash boundary is incomplete at marker ${markerPath}`,
  );
  const boundaryEvidence = captureAtBoundary?.();
  const daemonPid = requireValue(
    plane.daemonPid,
    "isolated plane did not expose daemonPid for crash evidence",
  );
  process.kill(daemonPid, "SIGKILL");
  await plane.stop();
  let timeout;
  const requestOutcome = await Promise.race([
    inFlight,
    new Promise((resolve) => {
      timeout = setTimeout(() => resolve({ kind: "timeout" }), 10_000);
    }),
  ]);
  clearTimeout(timeout);
  const daemonExited = !processIsAlive(daemonPid);
  rmSync(markerPath, { force: true });
  return { boundaryEvidence, daemonExited, markerBytes, requestOutcome };
}

function ownedTempPolicy(entryName) {
  return VERIFIER_TEMP_OWNER_POLICIES.find(
    ({ prefix }) => entryName.startsWith(prefix),
  ) || null;
}

function exactOwnedMarker(entryName, marker) {
  const policy = ownedTempPolicy(entryName);
  if (
    policy === null ||
    marker?.owner_kind !== policy.ownerKind ||
    !Number.isInteger(marker?.owner_pid) ||
    marker.owner_pid <= 0
  ) {
    return false;
  }
  if (policy.ownsProcessGroup === true) {
    return (
      marker.schema_version === 2 &&
      typeof marker.owner_start_time_ticks === "string" &&
      /^[0-9]+$/.test(marker.owner_start_time_ticks) &&
      Number.isInteger(marker.process_group_id) &&
      marker.process_group_id > 0 &&
      typeof marker.process_group_start_time_ticks === "string" &&
      /^[0-9]+$/.test(marker.process_group_start_time_ticks)
    );
  }
  return marker.schema_version === 1;
}

function exactProvisionalOwnedMarker(entryName, marker) {
  const policy = ownedTempPolicy(entryName);
  return (
    policy?.ownsProcessGroup === true &&
    marker?.schema_version === 2 &&
    marker.owner_kind === policy.ownerKind &&
    Number.isInteger(marker.owner_pid) &&
    marker.owner_pid > 0 &&
    typeof marker.owner_start_time_ticks === "string" &&
    /^[0-9]+$/.test(marker.owner_start_time_ticks) &&
    marker.process_group_id === null &&
    marker.process_group_start_time_ticks === null
  );
}

function markerlessWalletOwnerMarker(entryName) {
  const match = /^ioi-wallet-network-pa-([1-9][0-9]*)-([0-9]+)-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.exec(
    entryName,
  );
  if (match === null) return null;
  const ownerPid = Number(match[1]);
  if (!Number.isSafeInteger(ownerPid)) return null;
  return {
    schema_version: 2,
    owner_pid: ownerPid,
    owner_start_time_ticks: match[2],
    owner_kind: "wallet-network-principal-authority-fixture",
    process_group_id: null,
    process_group_start_time_ticks: null,
  };
}

function ownedMarkerOwnerIsAlive(policy, marker) {
  return policy?.ownsProcessGroup === true
    ? walletFixtureOwnerIdentityMatches(marker)
    : processIsAlive(marker.owner_pid);
}

function ownedProcessGroupIdentityIsAlive(
  processGroupId,
  processGroupStartTimeTicks,
) {
  return walletFixtureProcessGroupIdentityMatches({
    process_group_id: processGroupId,
    process_group_start_time_ticks: processGroupStartTimeTicks,
  });
}

function readOwnedMarker(resource) {
  try {
    return JSON.parse(
      readFileSync(join(resource, VERIFIER_OWNER_MARKER), "utf8"),
    );
  } catch {
    return null;
  }
}

function readOwnedMarkerEvidence(resource, entryName) {
  if (existsSync(join(resource, VERIFIER_OWNER_MARKER))) {
    return readOwnedMarker(resource);
  }
  return markerlessWalletOwnerMarker(entryName);
}

async function reapMarkedWalletFixtureProcessGroup(policy, marker) {
  if (policy?.ownsProcessGroup !== true) return true;
  const processGroupId = marker.process_group_id;
  if (!walletFixtureProcessGroupIdentityMatches(marker)) return true;
  try {
    process.kill(-processGroupId, "SIGKILL");
  } catch (error) {
    if (error?.code !== "ESRCH") throw error;
  }
  const deadline = Date.now() + 30_000;
  while (
    walletFixtureProcessGroupIdentityMatches(marker) &&
    Date.now() < deadline
  ) {
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  return !walletFixtureProcessGroupIdentityMatches(marker);
}

async function scavengeDeadVerifierTempDirs(
  { beforeRevalidate, beforeQuarantine } = {},
) {
  const removed = [];
  for (const entry of readdirSync(tmpdir(), { withFileTypes: true })) {
    if (!entry.isDirectory() || ownedTempPolicy(entry.name) === null) {
      continue;
    }
    const resource = join(tmpdir(), entry.name);
    try {
      if (!lstatSync(resource).isDirectory()) continue;
    } catch {
      continue;
    }
    const marker = readOwnedMarkerEvidence(resource, entry.name);
    const policy = ownedTempPolicy(entry.name);
    const finalMarker = exactOwnedMarker(entry.name, marker);
    const provisionalMarker =
      exactProvisionalOwnedMarker(entry.name, marker);
    if (
      (!finalMarker && !provisionalMarker) ||
      ownedMarkerOwnerIsAlive(policy, marker)
    ) {
      continue;
    }
    beforeRevalidate?.(resource);
    const revalidated = readOwnedMarkerEvidence(resource, entry.name);
    let stillDirectory = false;
    try {
      stillDirectory = lstatSync(resource).isDirectory();
    } catch {
      // A concurrent remover or replacement means this verifier no longer owns the path.
    }
    if (
      !stillDirectory ||
      !(
        exactOwnedMarker(entry.name, revalidated) ||
        exactProvisionalOwnedMarker(entry.name, revalidated)
      ) ||
      !sameJson(marker, revalidated) ||
      ownedMarkerOwnerIsAlive(policy, revalidated)
    ) {
      continue;
    }
    if (
      exactOwnedMarker(entry.name, revalidated) &&
      !(await reapMarkedWalletFixtureProcessGroup(policy, revalidated))
    ) {
      continue;
    }
    beforeQuarantine?.(resource);
    const quarantine = join(
      tmpdir(),
      `${policy.prefix}quarantine-${process.pid}-${randomUUID()}`,
    );
    try {
      renameSync(resource, quarantine);
    } catch {
      continue;
    }
    const quarantinedMarker = readOwnedMarkerEvidence(
      quarantine,
      entry.name,
    );
    if (
      (
        exactOwnedMarker(basename(quarantine), quarantinedMarker) ||
        exactProvisionalOwnedMarker(
          basename(quarantine),
          quarantinedMarker,
        )
      ) &&
      sameJson(marker, quarantinedMarker) &&
      !ownedMarkerOwnerIsAlive(policy, quarantinedMarker)
    ) {
      rmSync(quarantine, { recursive: true, force: true });
      removed.push(resource);
      continue;
    }
    try {
      renameSync(quarantine, resource);
    } catch {
      // The captured replacement is left quarantined and is never recursively removed.
    }
  }
  return removed;
}

async function staleTempScavengerSelfTest() {
  const deadPid = 2_147_483_647;
  const valid = mkdtempSync(
    join(tmpdir(), "ioi-system-sequence-zero-stale-valid-"),
  );
  const foreignOwner = mkdtempSync(
    join(tmpdir(), "ioi-system-sequence-zero-stale-foreign-"),
  );
  const wrongSchema = mkdtempSync(
    join(tmpdir(), "ioi-system-sequence-zero-stale-schema-"),
  );
  const wrongPrefixOwner = mkdtempSync(
    join(tmpdir(), "ioi-wallet-network-pa-stale-system-owner-"),
  );
  const changedBeforeRemoval = mkdtempSync(
    join(tmpdir(), "ioi-system-sequence-zero-stale-changed-"),
  );
  const replacedBeforeQuarantine = mkdtempSync(
    join(tmpdir(), "ioi-system-sequence-zero-stale-raced-"),
  );
  const orphanWallet = mkdtempSync(
    join(tmpdir(), "ioi-wallet-network-pa-stale-orphan-"),
  );
  const provisionalWallet = mkdtempSync(
    join(tmpdir(), "ioi-wallet-network-pa-stale-provisional-"),
  );
  const unpublishedWallet = join(
    tmpdir(),
    `ioi-wallet-network-pa-${deadPid}-0-${randomUUID()}`,
  );
  mkdirSync(unpublishedWallet, { mode: 0o700 });
  writeFileSync(
    join(unpublishedWallet, `${VERIFIER_OWNER_MARKER}.fixture.tmp`),
    "",
  );
  const reusedGroupWallet = mkdtempSync(
    join(tmpdir(), "ioi-wallet-network-pa-stale-reused-group-"),
  );
  const displacedOwnedPath = `${replacedBeforeQuarantine}-owned`;
  const writeMarker = (
    resource,
    schemaVersion,
    ownerKind,
    extra = {},
  ) => {
    writeFileSync(
      join(resource, VERIFIER_OWNER_MARKER),
      JSON.stringify({
        schema_version: schemaVersion,
        owner_pid: deadPid,
        owner_start_time_ticks: "0",
        owner_kind: ownerKind,
        ...extra,
      }),
    );
  };
  const orphanProcess = spawn(
    process.execPath,
    ["-e", "setInterval(() => {}, 1000)"],
    {
      detached: true,
      stdio: "ignore",
    },
  );
  orphanProcess.unref();
  const reusedProcess = spawn(
    process.execPath,
    ["-e", "setInterval(() => {}, 1000)"],
    {
      detached: true,
      stdio: "ignore",
    },
  );
  reusedProcess.unref();
  const orphanProcessStartTimeTicks = requireValue(
    walletFixtureProcessGroupStartTimeTicks(orphanProcess.pid),
    "orphan-scavenger fixture lacks its process identity",
  );
  const reusedProcessStartTimeTicks = requireValue(
    walletFixtureProcessGroupStartTimeTicks(reusedProcess.pid),
    "reused-group fixture lacks its process identity",
  );
  try {
    writeMarker(valid, 1, "system-sequence-zero-held-bar");
    writeMarker(foreignOwner, 1, "future-unowned-verifier");
    writeMarker(wrongSchema, 2, "system-sequence-zero-held-bar");
    writeMarker(wrongPrefixOwner, 1, "system-sequence-zero-held-bar");
    writeMarker(changedBeforeRemoval, 1, "system-sequence-zero-held-bar");
    writeMarker(replacedBeforeQuarantine, 1, "system-sequence-zero-held-bar");
    writeMarker(
      orphanWallet,
      2,
      "wallet-network-principal-authority-fixture",
      {
        owner_pid: process.pid,
        owner_start_time_ticks: `${BigInt(
          requireValue(
            walletFixtureProcessGroupStartTimeTicks(process.pid),
            "scavenger fixture owner lacks its process identity",
          ),
        ) + 1n}`,
        process_group_id: orphanProcess.pid,
        process_group_start_time_ticks: orphanProcessStartTimeTicks,
      },
    );
    writeMarker(
      provisionalWallet,
      2,
      "wallet-network-principal-authority-fixture",
      {
        process_group_id: null,
        process_group_start_time_ticks: null,
      },
    );
    writeMarker(
      reusedGroupWallet,
      2,
      "wallet-network-principal-authority-fixture",
      {
        process_group_id: reusedProcess.pid,
        process_group_start_time_ticks:
          `${BigInt(reusedProcessStartTimeTicks) + 1n}`,
      },
    );
    const removed = await scavengeDeadVerifierTempDirs({
      beforeRevalidate(resource) {
        if (resource === changedBeforeRemoval) {
          writeMarker(resource, 1, "future-unowned-verifier");
        }
      },
      beforeQuarantine(resource) {
        if (resource === replacedBeforeQuarantine) {
          renameSync(resource, displacedOwnedPath);
          mkdirSync(resource);
          writeMarker(resource, 1, "future-unowned-verifier");
        }
      },
    });
    return {
      pass:
        removed.includes(valid) &&
        removed.includes(orphanWallet) &&
        removed.includes(provisionalWallet) &&
        removed.includes(unpublishedWallet) &&
        removed.includes(reusedGroupWallet) &&
        !existsSync(valid) &&
        !existsSync(orphanWallet) &&
        !existsSync(provisionalWallet) &&
        !existsSync(unpublishedWallet) &&
        !existsSync(reusedGroupWallet) &&
        !walletFixtureProcessGroupAlive(orphanProcess.pid) &&
        walletFixtureProcessGroupAlive(reusedProcess.pid) &&
        !removed.includes(foreignOwner) &&
        existsSync(foreignOwner) &&
        !removed.includes(wrongSchema) &&
        existsSync(wrongSchema) &&
        !removed.includes(wrongPrefixOwner) &&
        existsSync(wrongPrefixOwner) &&
        !removed.includes(changedBeforeRemoval) &&
        existsSync(changedBeforeRemoval) &&
        !removed.includes(replacedBeforeQuarantine) &&
        existsSync(replacedBeforeQuarantine) &&
        readOwnedMarker(replacedBeforeQuarantine)?.owner_kind ===
          "future-unowned-verifier" &&
        existsSync(displacedOwnedPath),
      removed: removed.length,
    };
  } finally {
    for (const resource of [
      valid,
      foreignOwner,
      wrongSchema,
      wrongPrefixOwner,
      changedBeforeRemoval,
      replacedBeforeQuarantine,
      displacedOwnedPath,
      orphanWallet,
      provisionalWallet,
      unpublishedWallet,
      reusedGroupWallet,
    ]) {
      rmSync(resource, { recursive: true, force: true });
    }
    if (
      ownedProcessGroupIdentityIsAlive(
        orphanProcess.pid,
        orphanProcessStartTimeTicks,
      )
    ) {
      try {
        process.kill(-orphanProcess.pid, "SIGKILL");
      } catch {
        // The test process group exited during cleanup.
      }
    }
    if (
      ownedProcessGroupIdentityIsAlive(
        reusedProcess.pid,
        reusedProcessStartTimeTicks,
      )
    ) {
      try {
        process.kill(-reusedProcess.pid, "SIGKILL");
      } catch {
        // The reused-group test process exited during cleanup.
      }
    }
  }
}

function sanitizeVerifierEnv(sourceEnv) {
  return Object.fromEntries(
    Object.entries(sourceEnv).filter(([key]) => {
      if (key.startsWith("IOI_TEST_")) return false;
      if (key.startsWith("IOI_HYPERVISOR_GOVERNED_REPLAY_")) return false;
      if (key.startsWith("IOI_WALLET_NETWORK_")) return false;
      if (key.startsWith("IOI_HYPERVISOR_WALLET_")) return false;
      return ![
        "IOI_HYPERVISOR_DATA_DIR",
        "IOI_HYPERVISOR_DAEMON_ADDR",
        "IOI_WALLET_SECRET_PASS",
        JOURNEY_SELECTOR_ENV,
        FOCUSED_VERIFIER_OPT_IN_ENV,
        CERTIFICATION_MODE_ENV,
      ].includes(key);
    }),
  );
}

function sanitizedProcessEnv() {
  return sanitizeVerifierEnv(process.env);
}

function startVerifierPlane({ dataDir, env = {}, ...options } = {}) {
  return startIsolatedPlane({
    dataDir,
    ...options,
    baseEnv: sanitizedProcessEnv(),
    env: {
      ...env,
      RUST_LOG: "off",
    },
  });
}

async function startOwnedWalletResolver(options = {}) {
  requireValue(activeJourney, "wallet fixture resources require an active journey");
  const resolver = await startRealWalletNetworkPrincipalAuthorityFixture({
    baseEnv: sanitizedProcessEnv(),
    ...options,
  });
  const processGroupId = requireValue(
    resolver.processGroupId,
    "wallet fixture did not expose its owned process group",
  );
  const processGroupStartTimeTicks = requireValue(
    resolver.processGroupStartTimeTicks,
    "wallet fixture did not expose its owned process-group identity",
  );
  ownedProcessGroups.set(processGroupId, processGroupStartTimeTicks);
  const resourceDir = requireValue(
    resolver.resourceDir,
    "wallet fixture did not expose its owned resource directory",
  );
  if (ownedResources.has(resourceDir)) {
    await resolver.stop();
    throw new Error(`wallet fixture resource was registered twice: ${resourceDir}`);
  }
  ownedResources.set(resourceDir, activeJourney);
  return resolver;
}

async function walletFixtureReadinessCleanupSelfTest() {
  try {
    const fixture = await startRealWalletNetworkPrincipalAuthorityFixture({
      baseEnv: {
        ...sanitizedProcessEnv(),
        IOI_TEST_WALLET_FIXTURE_MALFORMED_READY: "1",
      },
    });
    await fixture.stop();
    return false;
  } catch (error) {
    if (Number.isInteger(error.processGroupId)) {
      ownedProcessGroups.set(
        error.processGroupId,
        error.processGroupStartTimeTicks,
      );
    }
    return (
      error instanceof SyntaxError &&
      error.cleanupConfirmed === true &&
      Number.isInteger(error.processGroupId) &&
      !ownedProcessGroupIdentityIsAlive(
        error.processGroupId,
        error.processGroupStartTimeTicks,
      )
    );
  }
}

async function walletFixtureGuardianOwnerDeathSelfTest() {
  const fixtureDir = mkdtempSync(
    join(tmpdir(), "ioi-wallet-network-pa-guardian-owner-death-"),
  );
  const fakeBin = mkdtempSync(
    join(tmpdir(), "ioi-wallet-network-pa-guardian-bin-"),
  );
  symlinkSync(process.execPath, join(fakeBin, "cargo"));
  const owner = spawn(
    process.execPath,
    ["-e", "setInterval(() => {}, 1000)"],
    { stdio: "ignore" },
  );
  const ownerExit = new Promise((resolve) => owner.once("exit", resolve));
  let guardian;
  let guardianExit;
  try {
    const ownerDeadline = Date.now() + 10_000;
    let ownerStartTimeTicks;
    while (Date.now() < ownerDeadline) {
      ownerStartTimeTicks =
        walletFixtureProcessGroupStartTimeTicks(owner.pid);
      if (ownerStartTimeTicks !== null) break;
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    ownerStartTimeTicks = requireValue(
      ownerStartTimeTicks,
      "guardian owner-death self-test could not identify its owner",
    );
    writeFileSync(
      join(fixtureDir, VERIFIER_OWNER_MARKER),
      JSON.stringify({
        schema_version: 2,
        owner_pid: owner.pid,
        owner_start_time_ticks: ownerStartTimeTicks,
        owner_kind: "wallet-network-principal-authority-fixture",
        process_group_id: null,
        process_group_start_time_ticks: null,
      }),
      { mode: 0o600 },
    );
    guardian = spawn(process.execPath, [
      join(HERE, "lib", "wallet-network-fixture-guardian.mjs"),
    ], {
      cwd: REPO,
      detached: true,
      env: {
        ...sanitizedProcessEnv(),
        PATH: `${fakeBin}:${process.env.PATH || ""}`,
        IOI_HYPERVISOR_WALLET_FIXTURE_DIR: fixtureDir,
        IOI_HYPERVISOR_WALLET_FIXTURE_OWNER_PID: String(owner.pid),
        IOI_HYPERVISOR_WALLET_FIXTURE_OWNER_START_TIME_TICKS:
          ownerStartTimeTicks,
        IOI_WALLET_FIXTURE_GUARDIAN_CARGO_ARGS: JSON.stringify([
          "-e",
          "setInterval(() => {}, 1000)",
        ]),
        IOI_WALLET_FIXTURE_GUARDIAN_CARGO_CWD: REPO,
      },
      stdio: "ignore",
    });
    const guardianStartTimeTicks = requireValue(
      walletFixtureProcessGroupStartTimeTicks(guardian.pid),
      "guardian owner-death self-test lacks a process-group identity",
    );
    ownedProcessGroups.set(guardian.pid, guardianStartTimeTicks);
    guardianExit = new Promise((resolve) => guardian.once("exit", resolve));
    const markerDeadline = Date.now() + 10_000;
    let marker;
    while (Date.now() < markerDeadline) {
      marker = readOwnedMarker(fixtureDir);
      if (
        marker?.process_group_id === guardian.pid &&
        walletFixtureProcessGroupIdentityMatches(marker)
      ) {
        break;
      }
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    requireValue(
      marker?.process_group_id === guardian.pid &&
        walletFixtureProcessGroupIdentityMatches(marker),
      "guardian owner-death self-test never published exact process ownership",
    );

    owner.kill("SIGKILL");
    await ownerExit;
    await Promise.race([
      guardianExit,
      new Promise((_, reject) =>
        setTimeout(
          () => reject(new Error("guardian did not exit with its dead owner")),
          10_000,
        ),
      ),
    ]);
    const groupDeadline = Date.now() + 30_000;
    while (
      ownedProcessGroupIdentityIsAlive(
        guardian.pid,
        guardianStartTimeTicks,
      ) &&
      Date.now() < groupDeadline
    ) {
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
    return (
      !ownedProcessGroupIdentityIsAlive(
        guardian.pid,
        guardianStartTimeTicks,
      ) &&
      readOwnedMarker(fixtureDir)?.owner_start_time_ticks ===
        ownerStartTimeTicks
    );
  } finally {
    if (processIsAlive(owner.pid)) {
      try { owner.kill("SIGKILL"); } catch { /* already exited */ }
      await ownerExit;
    }
    if (
      guardian?.pid &&
      ownedProcessGroupIdentityIsAlive(
        guardian.pid,
        ownedProcessGroups.get(guardian.pid),
      )
    ) {
      try {
        process.kill(-guardian.pid, "SIGKILL");
      } catch {
        // The guardian group exited during cleanup.
      }
    }
    if (guardianExit) {
      await Promise.race([
        guardianExit,
        new Promise((resolve) => setTimeout(resolve, 2_000)),
      ]);
    }
    rmSync(fixtureDir, { recursive: true, force: true });
    rmSync(fakeBin, { recursive: true, force: true });
  }
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
      (path) => ownedResources.get(path) !== name,
    )
  ) {
    throw new Error(`journey '${name}' resource census contains an unowned path`);
  }
}

async function executeJourneyWithCensus(name, journey) {
  const resultStart = results.length;
  const resourcesBefore = new Set(ownedResources.keys());
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
  const observedResources = [...ownedResources.keys()].filter(
    (path) => !resourcesBefore.has(path),
  );
  exactJourneyCensus(name, observedProofs, observedResources);
}

async function noopJourneysRefuseCertification() {
  for (const name of JOURNEY_PROOF_CENSUS.keys()) {
    const resultStart = results.length;
    const resourcesBefore = new Set(ownedResources.keys());
    await (async () => {})();
    const observedProofs = results.slice(resultStart).map((result) => result.name);
    const observedResources = [...ownedResources.keys()].filter(
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

function teardownComplete(resources, selectedJourneys, processGroups = ownedProcessGroups) {
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
    [...resources.keys()].every((path) => !existsSync(path)) &&
    [...processGroups].every(
      ([processGroupId, startTimeTicks]) =>
        !ownedProcessGroupIdentityIsAlive(
          processGroupId,
          startTimeTicks,
        ),
    )
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

function artifactHash(domain, artifact) {
  return `sha256:${createHash("sha256")
    .update(canonicalJson({ domain, artifact }))
    .digest("hex")}`;
}

function lifecycleDeploymentRevisionForGenesis(genesis) {
  const revision = fixture(
    "autonomous-system-deployment-profile-revision-v1/positive-candidate.json",
  );
  revision.profile.system_id = genesis.system_id;
  revision.profile.constitution_ref = genesis.constitution_ref;
  revision.profile.manifest_ref = genesis.manifest_ref;
  revision.profile.ordering_admission_finality_profile_ref =
    genesis.initial_profile_refs.ordering_admission_finality_profile_ref;
  const root = `sha256:${createHash("sha256")
    .update(canonicalJson({
      domain:
        "ioi.autonomous-system-deployment-profile-revision-jcs-sha256.v1",
      profile: revision.profile,
    }))
    .digest("hex")}`;
  revision.deployment_profile_root = root;
  revision.deployment_profile_ref =
    `${revision.profile.deployment_profile_id}/revision/${root}`;
  return revision;
}

function lifecycleDeploymentRevision(source) {
  return lifecycleDeploymentRevisionForGenesis(
    source.record.authorized_genesis,
  );
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

function exactGenesisBody(
  genesisId = null,
  candidateFixture = null,
  fixtureLoader = fixture,
) {
  const release = fixtureLoader(
    "autonomous-system-manifest-v1/positive-reusable-release.json",
  );
  recomputeReleaseHashes(release);
  const candidate = candidateFixture
    ? clone(candidateFixture)
    : fixtureLoader("autonomous-system-genesis-v1/positive-proposed.json");
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
      constitution: fixtureLoader(
        "autonomous-system-constitution-v1/positive-draft.json",
      ),
      ordering_profile: fixtureLoader(
        "ordering-admission-finality-profile-v1/positive-single-authority.json",
      ),
      oracle_profiles: [
        fixtureLoader(
          "oracle-evidence-profile-v1/positive-fail-closed.json",
        ),
      ],
      lifecycle_profile: fixtureLoader(
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
    const entries = readdirSync(familyDir, { withFileTypes: true });
    for (const entry of entries) {
      if (!entry.isFile()) {
        throw new Error(
          `evidence family '${family}' contains nonregular entry '${entry.name}'`,
        );
      }
      if (!entry.name.endsWith(".json")) {
        throw new Error(
          `evidence family '${family}' contains unexpected non-json entry '${entry.name}'`,
        );
      }
    }
    return entries.map((entry) => entry.name).sort();
  } catch (error) {
    if (error?.code === "ENOENT") return [];
    throw error;
  }
}

function strictFamilyEnumerationSelfTest() {
  const dataDir = mkdtempSync(join(tmpdir(), "ioi-evidence-family-enumeration-"));
  const family = "fixture-family";
  const familyDir = join(dataDir, family);
  mkdirSync(familyDir);
  const refuses = (pattern) => {
    try {
      familyFiles(dataDir, family);
      return false;
    } catch (error) {
      return pattern.test(String(error.message || error));
    }
  };
  try {
    if (familyFiles(dataDir, family).length !== 0) return false;

    writeFileSync(join(familyDir, "orphan.bin"), "residue");
    if (!refuses(/unexpected non-json entry 'orphan[.]bin'/u)) return false;
    rmSync(join(familyDir, "orphan.bin"));

    writeFileSync(join(familyDir, "record.json"), "{}");
    writeFileSync(join(familyDir, "record.json.bak"), "{}");
    if (!refuses(/unexpected non-json entry 'record[.]json[.]bak'/u)) return false;
    rmSync(join(familyDir, "record.json.bak"));

    mkdirSync(join(familyDir, "nonregular.json"));
    if (!refuses(/nonregular entry 'nonregular[.]json'/u)) return false;
    rmSync(join(familyDir, "nonregular.json"), { recursive: true });

    return familyFiles(dataDir, family).length === 1;
  } finally {
    rmSync(dataDir, { recursive: true, force: true });
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

function recursiveBytesSnapshot(root, { ignoredRootNames = new Set() } = {}) {
  const rootStat = lstatSync(root);
  if (!rootStat.isDirectory()) {
    throw new Error(`snapshot root is not a directory: ${root}`);
  }
  const rows = [["directory", "", null]];
  function walk(current, relative = "") {
    const entries = readdirSync(current, { withFileTypes: true }).filter(
      (entry) => relative !== "" || !ignoredRootNames.has(entry.name),
    );
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

function recursiveDataDirSnapshot(root) {
  const ignoredRootNames = new Set(
    readdirSync(root)
      .filter((name) =>
        /^isolated-daemon(?:-restart-\d+)?[.]log$/u.test(name)
      ),
  );
  return recursiveBytesSnapshot(root, { ignoredRootNames });
}

async function stableDataDirSnapshot(dataDir) {
  let previous = recursiveDataDirSnapshot(dataDir);
  let stableReads = 0;
  for (let attempt = 0; attempt < 100; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 50));
    const current = recursiveDataDirSnapshot(dataDir);
    if (current === previous) {
      stableReads += 1;
      if (stableReads >= 4) return current;
    } else {
      previous = current;
      stableReads = 0;
    }
  }
  throw new Error("recursive data-dir byte snapshot did not become stable");
}

function dataDirSnapshotDelta(before, after) {
  const beforeRows = new Map(
    JSON.parse(before).map((row) => [
      row[1],
      canonicalJson(row),
    ]),
  );
  const afterRows = new Map(
    JSON.parse(after).map((row) => [
      row[1],
      canonicalJson(row),
    ]),
  );
  return [...new Set([...beforeRows.keys(), ...afterRows.keys()])]
    .filter((relativePath) => (
      beforeRows.get(relativePath) !== afterRows.get(relativePath)
    ))
    .sort();
}

async function stableDataPlaneSnapshot(call, dataDir) {
  const status = await call("GET", "/v1/hypervisor/substrate/status");
  requireValue(
    status.status === 200,
    `data-plane snapshot warmup failed: ${status.status}/${status.body.error?.code || "no-code"}`,
  );
  const missingSource = await call(
    "GET",
    `${GENESIS_ROUTE}/asg_${"0".repeat(64)}`,
  );
  requireValue(
    missingSource.status === 404 &&
      missingSource.body.error?.code === "system_genesis_not_found",
    `Agentgres snapshot warmup failed: ${missingSource.status}/${missingSource.body.error?.code || "no-code"}`,
  );
  let previous = recursiveDataDirSnapshot(dataDir);
  for (let attempt = 0; attempt < 20; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 25));
    const current = recursiveDataDirSnapshot(dataDir);
    if (current === previous) return current;
    previous = current;
  }
  throw new Error("data-plane snapshot did not become byte-stable");
}

async function dataPlaneStayedByteExact(call, dataDir, before) {
  const after = await stableDataPlaneSnapshot(call, dataDir);
  if (before === after) return true;
  const beforeRows = new Map(
    JSON.parse(before).map(([kind, path, bytes]) => [
      path,
      canonicalJson([kind, bytes]),
    ]),
  );
  const afterRows = new Map(
    JSON.parse(after).map(([kind, path, bytes]) => [
      path,
      canonicalJson([kind, bytes]),
    ]),
  );
  const changedPaths = [...new Set([...beforeRows.keys(), ...afterRows.keys()])]
    .filter((path) => beforeRows.get(path) !== afterRows.get(path))
    .sort();
  console.error(
    `data-plane byte delta (${changedPaths.length}): ${changedPaths.join(", ")}`,
  );
  return false;
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

function buildCurrentDaemon() {
  const result = spawnSync(
    "cargo",
    [
      "build",
      "--locked",
      "-p",
      "ioi-node",
      "--bin",
      "hypervisor-daemon",
    ],
    {
      cwd: REPO,
      env: {
        ...process.env,
        CARGO_TARGET_DIR: join(REPO, "target"),
      },
      stdio: "inherit",
    },
  );
  if (result.error) {
    throw new Error(`current daemon build could not start: ${result.error.message}`);
  }
  if (result.status !== 0) {
    throw new Error(
      `current daemon build failed with ${result.signal || `exit ${result.status}`}`,
    );
  }
  let binaryStat;
  try {
    binaryStat = lstatSync(DAEMON_BINARY);
  } catch (error) {
    throw new Error(
      `current daemon build did not produce ${DAEMON_BINARY}: ${error.message}`,
    );
  }
  if (!binaryStat.isFile()) {
    throw new Error(`current daemon build output is not a regular file: ${DAEMON_BINARY}`);
  }
}

function checkedSpawnSync(command, args, options, label) {
  const result = spawnSync(command, args, options);
  if (result.error) {
    throw new Error(`${label} could not start: ${result.error.message}`);
  }
  if (result.status !== 0) {
    const output = [result.stdout, result.stderr]
      .filter(Boolean)
      .map((value) => String(value).trim())
      .filter(Boolean)
      .join("\n");
    throw new Error(
      `${label} failed with ${result.signal || `exit ${result.status}`}${output ? `:\n${output}` : ""}`,
    );
  }
  return result;
}

function buildPinnedCompatibilityDaemon({
  commit,
  buildPrefix,
  label,
}) {
  const buildRoot = createOwnedTempDir(buildPrefix);
  const worktree = join(buildRoot, "worktree");
  const targetDir = join(buildRoot, "target");
  let worktreeAdded = false;
  let keepBuild = false;
  try {
    checkedSpawnSync(
      "git",
      ["worktree", "add", "--detach", worktree, commit],
      { cwd: REPO, encoding: "utf8" },
      `${label} detached worktree creation`,
    );
    worktreeAdded = true;
    checkedSpawnSync(
      "cargo",
      [
        "build",
        "--locked",
        "-p",
        "ioi-node",
        "--bin",
        "hypervisor-daemon",
      ],
      {
        cwd: worktree,
        env: {
          ...process.env,
          CARGO_TARGET_DIR: targetDir,
        },
        stdio: "inherit",
      },
      `${label} hypervisor-daemon build`,
    );
    const binary = join(targetDir, "debug", "hypervisor-daemon");
    if (!lstatSync(binary).isFile()) {
      throw new Error(`${label} daemon output is not a regular file: ${binary}`);
    }
    keepBuild = true;
    return {
      binary,
      commit,
      cleanup: () => rmSync(buildRoot, { recursive: true, force: true }),
    };
  } finally {
    try {
      if (worktreeAdded) {
        checkedSpawnSync(
          "git",
          ["worktree", "remove", "--force", worktree],
          { cwd: REPO, encoding: "utf8" },
          `${label} detached worktree cleanup`,
        );
      }
    } finally {
      if (!keepBuild) {
        rmSync(buildRoot, { recursive: true, force: true });
      }
    }
  }
}

function buildCompatibilityBaseDaemon() {
  const commit = COMPATIBILITY_BASE_COMMIT;
  const fixtureBundle = new Map();
  for (const [relativePath, expectedHash] of COMPATIBILITY_FIXTURE_SHA256) {
    const repositoryPath =
      `docs/architecture/_meta/schemas/fixtures/${relativePath}`;
    const bytes = Buffer.from(
      checkedSpawnSync(
        "git",
        ["show", `${commit}:${repositoryPath}`],
        { cwd: REPO, encoding: null, maxBuffer: 4 * 1024 * 1024 },
        `pinned M1.3 fixture read (${relativePath})`,
      ).stdout,
    );
    const observedHash = createHash("sha256").update(bytes).digest("hex");
    if (observedHash !== expectedHash) {
      throw new Error(
        `pinned M1.3 fixture digest mismatch for ${relativePath}: expected=${expectedHash} observed=${observedHash}`,
      );
    }
    fixtureBundle.set(relativePath, {
      bytes,
      json: JSON.parse(bytes.toString("utf8")),
      hash: observedHash,
    });
  }
  const fixtureLoader = (relativePath) =>
    clone(requireValue(
      fixtureBundle.get(relativePath)?.json,
      `pinned M1.3 fixture bundle lacks ${relativePath}`,
    ));
  const candidateFixture =
    fixtureBundle.get("autonomous-system-genesis-v1/positive-proposed.json");
  return {
    ...buildPinnedCompatibilityDaemon({
      commit,
      buildPrefix: "ioi-m13-compatibility-build-",
      label: "pinned M1.3",
    }),
    fixtureBytes: candidateFixture.bytes,
    fixtureHash: candidateFixture.hash,
    fixtureCount: fixtureBundle.size,
    genesisBodyFor: (genesisId = null) =>
      exactGenesisBody(genesisId, null, fixtureLoader),
  };
}

function freeLoopbackPort() {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

async function startVerifierPlaneFromBinary({ binary, dataDir, env }) {
  const port = await freeLoopbackPort();
  const daemonUrl = `http://127.0.0.1:${port}`;
  const logPath = join(dataDir, "origin-master-daemon.log");
  const logFd = openSync(logPath, "w");
  const child = spawn(binary, [], {
    env: {
      ...sanitizedProcessEnv(),
      IOI_HYPERVISOR_DATA_DIR: dataDir,
      IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${port}`,
      IOI_WALLET_SECRET_PASS:
        process.env.IOI_WALLET_SECRET_PASS || "ioi-isolated-verifier-pass",
      ...env,
    },
    stdio: ["ignore", logFd, logFd],
  });
  ownedBinaryChildren.add(child);
  closeSync(logFd);
  let exited = false;
  const exitPromise = new Promise((resolve) => {
    child.once("exit", (code, signal) => {
      exited = true;
      ownedBinaryChildren.delete(child);
      resolve({ code, signal });
    });
  });
  let stopped = false;
  const stop = async () => {
    if (stopped) return;
    stopped = true;
    if (!exited) child.kill("SIGTERM");
    await Promise.race([
      exitPromise,
      new Promise((resolve) => setTimeout(resolve, 400)),
    ]);
    if (!exited) child.kill("SIGKILL");
    await exitPromise;
  };
  for (let attempt = 0; attempt < 120; attempt += 1) {
    if (exited) break;
    const healthy = await fetch(
      `${daemonUrl}/v1/hypervisor/data-sources`,
    ).then((response) => response.ok).catch(() => false);
    if (healthy) {
      return { daemonUrl, dataDir, stop };
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  await stop();
  const log = readFileSync(logPath, "utf8");
  throw new Error(
    `pinned M1.3 daemon never became healthy${log ? `:\n${log}` : ""}`,
  );
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

function retainedSignedGrantIdentity(receipt) {
  const grant = receipt?.wallet_approval_grant;
  if (grant === null || typeof grant !== "object" || Array.isArray(grant)) {
    return null;
  }
  return `grant://wallet.network/approval/sha256:${createHash("sha256")
    .update(canonicalJson(grant))
    .digest("hex")}`;
}

function legacySignedGrantIdentity(receipt) {
  const currentIdentity = retainedSignedGrantIdentity(receipt);
  const artifactHash = currentIdentity?.match(
    /^grant:\/\/wallet[.]network\/approval\/sha256:([0-9a-f]{64})$/u,
  )?.[1];
  if (!artifactHash) return null;
  const walletGrantRef =
    `wallet.network://grant/approval/${artifactHash}`;
  return `grant://wallet.network/approval/sha256:${createHash("sha256")
    .update(walletGrantRef)
    .digest("hex")}`;
}

function receiptBoundaryRefOracle(receipt, sourceRecord, version) {
  const facts = receipt?.bound_facts;
  const profiles = facts?.profile_refs;
  const grantId =
    version === "legacy-v1"
      ? legacySignedGrantIdentity(receipt)
      : retainedSignedGrantIdentity(receipt);
  const sourceBoundary =
    version === "legacy-v1"
      ? sourceRecord?.admission_id
      : facts?.genesis_admission_record_root;
  const required = [
    facts?.system_id,
    facts?.genesis_ref,
    facts?.manifest_ref,
    facts?.constitution_ref,
    facts?.component_registry_ref,
    profiles?.deployment_profile_ref,
    profiles?.ordering_admission_finality_profile_ref,
    profiles?.lifecycle_continuity_profile_ref,
    sourceBoundary,
    facts?.genesis_admission_receipt_ref,
    facts?.governing_authority_ref,
    grantId,
    ...(version === "current-v2"
      ? [facts?.wallet_grant_consumption_ref]
      : []),
    facts?.wallet_grant_consumption_evidence_ref,
  ];
  const oracleRefs = profiles?.oracle_evidence_profile_refs ?? [];
  const networkRef = profiles?.network_enrollment_ref;
  const expected = [
    ...required,
    ...(networkRef === null ? [] : [networkRef]),
    ...oracleRefs,
  ];
  const actual = receipt?.attested_boundary_fact_refs;
  return {
    grantId,
    pass:
      grantId === receipt?.authority_grant_id &&
      required.every((reference) => typeof reference === "string") &&
      (networkRef === null || typeof networkRef === "string") &&
      Array.isArray(oracleRefs) &&
      oracleRefs.every((reference) => typeof reference === "string") &&
      Array.isArray(actual) &&
      new Set(expected).size === expected.length &&
      new Set(actual).size === actual.length &&
      sameJson([...actual].sort(), [...expected].sort()),
  };
}

function receiptHasExactBoundaryRefs(receipt) {
  return receiptBoundaryRefOracle(receipt, null, "current-v2").pass;
}

function boundaryRefOracleSelfTest() {
  const receipt = {
    wallet_approval_grant: { signed: "grant", counter: 1 },
    bound_facts: {
      system_id: "system://a",
      genesis_ref: "genesis://a",
      manifest_ref: "package://a/release/sha256:a",
      constitution_ref: "constitution://a",
      component_registry_ref: "agentgres://object-set/a",
      genesis_admission_record_root: "sha256:a",
      genesis_admission_receipt_ref: "receipt://a",
      governing_authority_ref: "org://a",
      wallet_grant_consumption_ref: "wallet.network://approval-effect-consumption/a",
      wallet_grant_consumption_evidence_ref:
        "system-sequence-zero-authority-consumption://a",
      profile_refs: {
        deployment_profile_ref: "deployment-profile://a",
        ordering_admission_finality_profile_ref: "ordering-profile://a",
        lifecycle_continuity_profile_ref: "lifecycle-profile://a",
        network_enrollment_ref: null,
        oracle_evidence_profile_refs: ["oracle-evidence-profile://a"],
      },
    },
  };
  receipt.authority_grant_id = retainedSignedGrantIdentity(receipt);
  receipt.attested_boundary_fact_refs = [
    receipt.bound_facts.system_id,
    receipt.bound_facts.genesis_ref,
    receipt.bound_facts.manifest_ref,
    receipt.bound_facts.constitution_ref,
    receipt.bound_facts.component_registry_ref,
    receipt.bound_facts.profile_refs.deployment_profile_ref,
    receipt.bound_facts.profile_refs.ordering_admission_finality_profile_ref,
    receipt.bound_facts.profile_refs.lifecycle_continuity_profile_ref,
    receipt.bound_facts.genesis_admission_record_root,
    receipt.bound_facts.genesis_admission_receipt_ref,
    receipt.bound_facts.governing_authority_ref,
    receipt.authority_grant_id,
    receipt.bound_facts.wallet_grant_consumption_ref,
    receipt.bound_facts.wallet_grant_consumption_evidence_ref,
    ...receipt.bound_facts.profile_refs.oracle_evidence_profile_refs,
  ];
  const missingRequired = clone(receipt);
  missingRequired.attested_boundary_fact_refs =
    missingRequired.attested_boundary_fact_refs.slice(1);
  const unexpected = clone(receipt);
  unexpected.attested_boundary_fact_refs.push("unexpected://a");
  const copiedGrantIdentity = clone(receipt);
  copiedGrantIdentity.authority_grant_id =
    "grant://wallet.network/approval/sha256:" + "a".repeat(64);
  copiedGrantIdentity.attested_boundary_fact_refs =
    copiedGrantIdentity.attested_boundary_fact_refs.map((reference) =>
      reference === receipt.authority_grant_id
        ? copiedGrantIdentity.authority_grant_id
        : reference
    );
  return (
    receiptHasExactBoundaryRefs(receipt) &&
    !receiptHasExactBoundaryRefs(missingRequired) &&
    !receiptHasExactBoundaryRefs(unexpected) &&
    !receiptHasExactBoundaryRefs(copiedGrantIdentity)
  );
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

async function challengeAndWrongTargetGrant(
  call,
  resolver,
  path,
  body,
  wrongTargetScope,
) {
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
      wrongTargetScope,
    );
  }
  return { challenge, grant };
}

async function admitGenesis(
  call,
  resolver,
  dataDir,
  {
    exerciseWrongScope = false,
    genesisBody = null,
    genesisId = null,
  } = {},
) {
  const body = genesisBody ? clone(genesisBody) : exactGenesisBody(genesisId);
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
    const dataPlaneUnchanged = await dataPlaneStayedByteExact(
      call,
      dataDir,
      beforeWrongScope,
    );
    ok(
      "M1.3 AUTHORITY: wrong-scope refusal leaves the exact wallet approval-consumption slot and daemon tree byte-exact",
      wrongScope.status === 422 &&
        wrongScope.body.error?.code ===
          "system_genesis_wallet_consumption_precondition_refused" &&
        walletStateUnchanged &&
        dataPlaneUnchanged &&
        familyFiles(dataDir, SOURCE_INTENT_FAMILY).length === 0 &&
        SOURCE_FAMILIES.every(
          (family) => familyFiles(dataDir, family).length === 0,
        ),
      `${wrongScope.status}/${wrongScope.body.error?.code || "no-code"} wallet-approval-consumption-slot-unchanged=${walletStateUnchanged} daemon-tree-unchanged=${dataPlaneUnchanged} wallet-slot-bytes=${walletStateAfterWrongScope.length}`,
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

async function materializeGenesisSource(call, resolver, source) {
  const path =
    `${GENESIS_ROUTE}/${source.sourceTail}/sequence-zero-materialization`;
  const request = {
    expected_genesis_admission_record_root: source.recordRoot,
    expected_genesis_admission_receipt_root: source.receiptRoot,
  };
  const { challenge, grant } = await challengeAndGrant(
    call,
    resolver,
    path,
    request,
    MATERIALIZE_SCOPE,
  );
  requireValue(
    challenge.status === 403 &&
      challenge.body.error?.code ===
        "system_sequence_zero_host_authority_required" &&
      grant,
    `M1.4 compatibility challenge failed: ${JSON.stringify(challenge)}`,
  );
  const response = await call("POST", path, {
    ...request,
    wallet_approval_grant: grant,
  });
  requireValue(
    response.status === 201,
    `M1.4 compatibility materialization failed: ${JSON.stringify(response)}`,
  );
  return { path, request, response };
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
  let resolver = await startOwnedWalletResolver();
  const dataDir = createOwnedTempDir("ioi-system-sequence-zero-primary-");
  let plane;
  let wrongScopeResolver;
  let foreignRootResolver;
  try {
    plane = await startVerifierPlane({ dataDir, env: resolver.env });
    if (!plane) throw new Error("BLOCKED: target/debug/hypervisor-daemon is not built");
    const call = (method, path, body) =>
      jsonCall(plane.daemonUrl, method, path, body);
    const catalogSeedBefore = familiesSnapshot(
      dataDir,
      CATALOG_SEED_FAMILIES,
    );
    requireValue(
      CATALOG_SEED_FAMILIES.every(
        (family) => familyFiles(dataDir, family).length > 0,
      ),
      "fresh daemon did not materialize every catalog seed family",
    );
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
        (await dataPlaneStayedByteExact(call, dataDir, unknownBefore)),
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
        (await dataPlaneStayedByteExact(call, dataDir, unknownBefore)),
      `${secret.status}/${secret.body.error?.code || "no-code"}`,
    );

    const conflict = await call("POST", path, {
      ...request,
      expected_genesis_admission_record_root:
        "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    });
    ok(
      "CAS: stale M1.3 source roots refuse before authority with a byte-exact daemon tree",
      conflict.status === 409 &&
        conflict.body.error?.code === "system_sequence_zero_source_conflict" &&
        (await dataPlaneStayedByteExact(call, dataDir, unknownBefore)),
      `${conflict.status}/${conflict.body.error?.code || "no-code"}`,
    );

    await plane.stop();
    plane = undefined;
    await resolver.stop();
    resolver = undefined;
    wrongScopeResolver =
      await startOwnedWalletResolver();
    plane = await startVerifierPlane({
      dataDir,
      env: wrongScopeResolver.env,
    });
    if (!plane) {
      throw new Error("BLOCKED: wrong-scope probe daemon is not built");
    }
    ok(
      "CATALOG SEED IDEMPOTENCY: two consecutive fresh-daemon boots preserve exact seed-catalog names and bytes",
      catalogSeedBefore ===
        familiesSnapshot(dataDir, CATALOG_SEED_FAMILIES),
      `families=${CATALOG_SEED_FAMILIES.join(",")}`,
    );
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
    const dataPlaneUnchanged = await dataPlaneStayedByteExact(
      call,
      dataDir,
      wrongScopePlaneBefore,
    );
    ok(
      "AUTHORITY: wrong-scope refusal leaves the exact wallet approval-consumption slot and daemon tree byte-exact",
      wrongScope.status === 422 &&
        wrongScope.body.error?.code ===
          "system_sequence_zero_wallet_consumption_precondition_refused" &&
        walletStateUnchanged &&
        dataPlaneUnchanged &&
        familyFiles(dataDir, INTENT_FAMILY).length === 0 &&
        MATERIALIZATION_FAMILIES.every(
          (family) => familyFiles(dataDir, family).length === 0,
        ),
      `${wrongScope.status}/${wrongScope.body.error?.code || "no-code"} wallet-approval-consumption-slot-unchanged=${walletStateUnchanged} daemon-tree-unchanged=${dataPlaneUnchanged} wallet-slot-bytes=${walletStateAfterWrongScope.length}`,
    );
    await plane.stop();
    plane = undefined;
    await wrongScopeResolver.stop();
    wrongScopeResolver = undefined;
    resolver = await startOwnedWalletResolver();
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
        (await dataPlaneStayedByteExact(call, dataDir, correctPlaneBefore)),
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
      "AUTHORITY: materialization has a distinct real-wallet scope and byte-exact daemon-tree challenge",
      challenge.status === 403 &&
        challenge.body.error?.code ===
          "system_sequence_zero_host_authority_required" &&
        challenge.body.error?.required_scope === MATERIALIZE_SCOPE &&
        challenge.body.error?.required_authority_ref === OWNER &&
        grant &&
        (await dataPlaneStayedByteExact(call, dataDir, correctPlaneBefore)),
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
        (await dataPlaneStayedByteExact(call, dataDir, correctPlaneBefore)),
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
      "AUTHORITY: same-hash foreign signer refuses with a byte-exact daemon tree",
      foreign.status === 403 &&
        foreign.body.error?.code ===
          "system_sequence_zero_host_authority_required" &&
        (await dataPlaneStayedByteExact(call, dataDir, correctPlaneBefore)),
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
        (await dataPlaneStayedByteExact(call, dataDir, correctPlaneBefore)),
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
          "ioi.autonomous-system-sequence-zero-materialization-receipt.v2" &&
        receipt.receipt_type ===
          "autonomous_system_sequence_zero_materialization" &&
        receipt.receipt_profile_ref ===
          "schema://ioi/foundations/autonomous-system-sequence-zero-materialization-receipt/v2" &&
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
        receiptHasExactBoundaryRefs(receipt) &&
        String(receipt.bound_facts?.wallet_grant_consumption_ref || "").startsWith(
          "wallet.network://approval-effect-consumption/",
        ) &&
        receipt.assurance_posture ===
          "sequence_zero_materialized_not_activated",
      `${receipt.output_hash}/${receipt.authority_scopes?.join(",")}`,
    );
    const recomputedGrantId = retainedSignedGrantIdentity(receipt);
    ok(
      "RECEIPT: authority_grant_id and boundary refs bind the independently recomputed signed-grant JCS hash",
      recomputedGrantId !== null &&
        receipt.authority_grant_id === recomputedGrantId &&
        receipt.attested_boundary_fact_refs.includes(recomputedGrantId) &&
        receiptHasExactBoundaryRefs(receipt),
      recomputedGrantId || "missing retained signed grant",
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

    const convergedBytes = familiesSnapshot(
      dataDir,
      MATERIALIZATION_FAMILIES,
    );
    await plane.stop();
    plane = undefined;
    foreignRootResolver = await startOwnedWalletResolver({
      rootSeedHex: FOREIGN_WALLET_ROOT_SEED,
    });
    requireValue(
      !readFileSync(
        resolver.env.IOI_WALLET_NETWORK_ROOT_RECORD_PATH,
      ).equals(
        readFileSync(
          foreignRootResolver.env.IOI_WALLET_NETWORK_ROOT_RECORD_PATH,
        ),
      ),
      "foreign-root GET probe reused the materialization wallet root",
    );
    plane = await startVerifierPlane({
      dataDir,
      env: foreignRootResolver.env,
    });
    if (!plane) {
      throw new Error("BLOCKED: foreign-root GET probe daemon is not built");
    }
    const foreignRootRead = await call("GET", path);
    ok(
      "GET AUTHORITY ROOT: converged evidence signed by a foreign configured wallet root refuses byte-exactly",
      foreignRootRead.status === 500 &&
        foreignRootRead.body.error?.code ===
          "system_sequence_zero_receipt_authority_root_invalid" &&
        familiesSnapshot(dataDir, MATERIALIZATION_FAMILIES) ===
          convergedBytes,
      `${foreignRootRead.status}/${foreignRootRead.body.error?.code || "no-code"}`,
    );
    await plane.stop();
    plane = undefined;
    await foreignRootResolver.stop();
    foreignRootResolver = undefined;
    plane = await startVerifierPlane({ dataDir, env: resolver.env });
    if (!plane) {
      throw new Error("BLOCKED: post-foreign-root restoration daemon is not built");
    }
    const restoredRootRead = await call("GET", path);
    requireValue(
      restoredRootRead.status === 200 &&
        responseHasExactEvidence(restoredRootRead.body, exactEvidence) &&
        familiesSnapshot(dataDir, MATERIALIZATION_FAMILIES) ===
          convergedBytes,
      "foreign-root GET probe did not restore the original configured-root view",
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
    if (foreignRootResolver) await foreignRootResolver.stop();
    if (wrongScopeResolver) await wrongScopeResolver.stop();
    if (resolver) await resolver.stop();
    rmSync(dataDir, { recursive: true, force: true });
  }
}

async function runPostWalletSigkillCase(resolver) {
  const dataDir = createOwnedTempDir(
    "ioi-system-sequence-zero-post-wallet-sigkill-",
  );
  const markerPath = join(dataDir, ".post-wallet-consumption-crash-marker");
  let plane;
  try {
    plane = await startVerifierPlane({
      dataDir,
      env: {
        ...resolver.env,
        [POST_WALLET_CRASH_PAUSE_ENV]: "1",
        [POST_WALLET_CRASH_MARKER_ENV]: markerPath,
      },
    });
    if (!plane) {
      throw new Error("BLOCKED: post-wallet crash daemon is not built");
    }
    let call = (method, path, body) =>
      jsonCall(plane.daemonUrl, method, path, body);
    const source = await admitGenesis(call, resolver, dataDir, {
      genesisId: "genesis://acme/system-alpha/post-wallet-sigkill",
    });
    const sourceBefore = familiesSnapshot(dataDir, SOURCE_FAMILIES);
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
    requireValue(grant, "post-wallet crash lane did not mint the M1.4 grant");
    const inFlight = observedRequest(
      call("POST", path, {
        ...request,
        wallet_approval_grant: grant,
      }),
    );
    const crashed = await sigkillPlaneAtMarker({
      plane,
      markerPath,
      inFlight,
      boundaryReady: () =>
        familyFiles(dataDir, INTENT_FAMILY).length === 1 &&
        sameJson(
          MATERIALIZATION_FAMILIES.map(
            (family) => familyFiles(dataDir, family).length,
          ),
          [0, 0, 0, 1],
        ),
    });
    plane = undefined;
    ok(
      "CRASH POST-WALLET: a marker-pinned durable intent survives SIGKILL while the request is still in flight",
      crashed.daemonExited &&
        crashed.requestOutcome.kind === "error" &&
        familyFiles(dataDir, INTENT_FAMILY).length === 1 &&
        sameJson(
          MATERIALIZATION_FAMILIES.map(
            (family) => familyFiles(dataDir, family).length,
          ),
          [0, 0, 0, 1],
        ) &&
        sourceBefore === familiesSnapshot(dataDir, SOURCE_FAMILIES),
      `exited=${crashed.daemonExited} request=${crashed.requestOutcome.kind} marker-bytes=${crashed.markerBytes.length}`,
    );

    plane = await startVerifierPlane({ dataDir, env: resolver.env });
    if (!plane) {
      throw new Error("BLOCKED: post-wallet crash restart daemon is not built");
    }
    call = (method, route, body) =>
      jsonCall(plane.daemonUrl, method, route, body);
    const deadline = Date.now() + 90_000;
    let converged;
    while (Date.now() < deadline) {
      converged = await call("GET", path);
      if (converged.status === 200) break;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    const exactEvidence = Object.fromEntries(
      MATERIALIZATION_RESPONSE_FIELDS.map((field) => [
        field,
        converged?.body?.[field],
      ]),
    );
    ok(
      "CRASH POST-WALLET RESTART: the same data directory converges the exact four-family evidence once",
      converged?.status === 200 &&
        responseHasExactEvidence(converged.body, exactEvidence) &&
        MATERIALIZATION_FAMILIES.every(
          (family, index) =>
            familyFiles(dataDir, family).length === 1 &&
            sameJson(
              singleFamilyRecord(dataDir, family),
              exactEvidence[MATERIALIZATION_RESPONSE_FIELDS[index]],
            ),
        ) &&
        familyFiles(dataDir, INTENT_FAMILY).length === 0 &&
        sourceBefore === familiesSnapshot(dataDir, SOURCE_FAMILIES) &&
        tempResidue(dataDir).length === 0,
      `${converged?.status || "none"}/${converged?.body?.error?.code || "ok"}`,
    );
  } finally {
    if (plane) await plane.stop();
    rmSync(dataDir, { recursive: true, force: true });
  }
}

async function runCrashReplayJourney() {
  const resolver = await startOwnedWalletResolver();
  const dataDir = createOwnedTempDir("ioi-system-sequence-zero-replay-");
  let plane;
  try {
    await runPostWalletSigkillCase(resolver);
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
    plane = undefined;
    const intentName = requireValue(
      familyFiles(dataDir, INTENT_FAMILY)[0],
      "replay guard lacks its durable intent",
    );
    const intentPath = join(dataDir, INTENT_FAMILY, intentName);
    const pristineIntentBytes = readFileSync(intentPath);
    const forgedIntent = JSON.parse(pristineIntentBytes.toString("utf8"));
    const forgedBinding = forgedIntent.receipt.principal_authority_binding;
    const forgedProof = forgedBinding.binding_proof;
    forgedProof.issuer_signature_proof.signature[0] ^= 1;
    const forgedBindingHash = createHash("sha256")
      .update(
        canonicalJson({
          domain: "ioi.wallet-network.principal-authority-binding-proof.v1",
          schema_version: forgedProof.schema_version,
          statement: forgedProof.statement,
          statement_hash: forgedProof.statement_hash,
          issuer_signature_proof: forgedProof.issuer_signature_proof,
        }),
      )
      .digest();
    const forgedBindingRef =
      `wallet.network://principal-authority-binding/${forgedBindingHash.toString("hex")}`;
    forgedProof.binding_hash = [...forgedBindingHash];
    forgedProof.binding_ref = forgedBindingRef;
    forgedBinding.coordinates.binding_hash = [...forgedBindingHash];
    forgedBinding.coordinates.binding_ref = forgedBindingRef;
    delete forgedIntent.intent_hash;
    forgedIntent.intent_hash = recordOutputHash(forgedIntent);
    const forgedIntentBytes = Buffer.from(JSON.stringify(forgedIntent));
    writeFileSync(intentPath, forgedIntentBytes);
    plane = await startVerifierPlane({ dataDir, env: resolver.env });
    if (!plane) throw new Error("BLOCKED: forged-intent replay daemon is not built");
    call = (method, route, body) =>
      jsonCall(plane.daemonUrl, method, route, body);
    const forgedRead = await call("GET", path);
    ok(
      "REPLAY GUARD: a structurally rebound but cryptographically forged retained binding is quarantined byte-exactly",
      forgedRead.status === 500 &&
        forgedRead.body.error?.code ===
          "system_sequence_zero_pending_convergence" &&
        familyFiles(dataDir, INTENT_FAMILY).length === 1 &&
        readFileSync(intentPath).equals(forgedIntentBytes) &&
        MATERIALIZATION_FAMILIES.every(
          (family) => familyFiles(dataDir, family).length === 0,
        ),
      `${forgedRead.status}/${forgedRead.body.error?.code || "no-code"} intent-retained=${familyFiles(dataDir, INTENT_FAMILY).length}`,
    );
    await plane.stop();
    plane = undefined;
    writeFileSync(intentPath, pristineIntentBytes);
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
  const resolver = await startOwnedWalletResolver();
  try {
    for (const [index, testCase] of PARTIAL_PREFIX_CASES.entries()) {
      const dataDir = createOwnedTempDir(
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
  const resolver = await startOwnedWalletResolver();
  const dataDir = createOwnedTempDir(
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
  const resolver = await startOwnedWalletResolver();
  const dataDir = createOwnedTempDir(
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

async function runLegacyM13IntentUpgradeCase(
  base,
  resolver,
  {
    faultEnv,
    genesisId,
    proofName,
    forceUnrelatedFamilyWatchdog = false,
  },
) {
  const dataDir = createOwnedTempDir("ioi-system-genesis-legacy-upgrade-");
  let basePlane;
  let headPlane;
  try {
    basePlane = await startVerifierPlaneFromBinary({
      binary: base.binary,
      dataDir,
      env: {
        ...resolver.env,
        [faultEnv]: "1",
      },
    });
    let call = (method, path, body) =>
      jsonCall(basePlane.daemonUrl, method, path, body);
    const body = base.genesisBodyFor(genesisId);
    const { challenge, grant } = await challengeAndGrant(
      call,
      resolver,
      GENESIS_ROUTE,
      body,
      GENESIS_SCOPE,
    );
    requireValue(grant, `${proofName} did not mint its M1.3 grant`);
    const requestHash = challenge.body.error?.approval?.request_hash;
    const interrupted = await call("POST", GENESIS_ROUTE, {
      ...body,
      wallet_approval_grant: grant,
    });
    const intentFiles = familyFiles(dataDir, SOURCE_INTENT_FAMILY);
    const intentPath = intentFiles.length === 1
      ? join(dataDir, SOURCE_INTENT_FAMILY, intentFiles[0])
      : null;
    const intentBeforeStop = intentPath === null
      ? null
      : readFileSync(intentPath);
    const intentRecord = intentBeforeStop === null
      ? null
      : JSON.parse(intentBeforeStop.toString("utf8"));
    const consumptionBeforeRestart = requestHash
      ? await walletConsumptionStateBytes(resolver, requestHash)
      : null;
    const postConsumption =
      faultEnv === "IOI_TEST_FORCE_SYSTEM_GENESIS_AFTER_WALLET_CONSUME";

    await basePlane.stop();
    basePlane = undefined;
    const intentUnchangedBeforeUpgrade =
      intentPath !== null &&
      intentBeforeStop !== null &&
      readFileSync(intentPath).equals(intentBeforeStop);
    const replayStartedAt = Date.now();
    headPlane = await startVerifierPlane({
      dataDir,
      env: {
        ...resolver.env,
        IOI_HYPERVISOR_GOVERNED_REPLAY_INTERVAL_MS: "100",
        ...(forceUnrelatedFamilyWatchdog
          ? {
              IOI_TEST_FORCE_GOVERNED_REPLAY_WATCHDOG_FAMILY:
                "room-participation",
              IOI_TEST_FORCE_GOVERNED_REPLAY_WATCHDOG_MS: "50",
              // The unrelated owner remains live beyond the assertion budget.
              // Its held slot prevents overlap while System converges independently.
              IOI_TEST_FORCE_GOVERNED_REPLAY_WORK_MS: "43000",
            }
          : {}),
      },
    });
    if (!headPlane) {
      throw new Error("BLOCKED: HEAD legacy-intent daemon is not built");
    }
    const converged = await waitForIntentRecordsToClear(
      dataDir,
      SOURCE_INTENT_FAMILY,
    );
    const elapsedMs = Date.now() - replayStartedAt;
    call = (method, path, requestBody) =>
      jsonCall(headPlane.daemonUrl, method, path, requestBody);
    const source = converged ? persistedGenesisSource(dataDir) : null;
    const read = source
      ? await call("GET", `${GENESIS_ROUTE}/${source.sourceTail}`)
      : null;
    const consumptionAfter = requestHash
      ? await walletConsumptionStateBytes(resolver, requestHash)
      : null;
    const consumptionPosture = postConsumption
      ? consumptionBeforeRestart !== null &&
        consumptionAfter !== null &&
        consumptionAfter.equals(consumptionBeforeRestart)
      : consumptionBeforeRestart !== null &&
        consumptionAfter !== null &&
        !consumptionAfter.equals(consumptionBeforeRestart);
    ok(
      proofName,
      interrupted.status === 500 &&
        interrupted.body.error?.code === "system_genesis_pending_convergence" &&
        intentRecord !== null &&
        !Object.hasOwn(intentRecord, "intent_family_created_by_request") &&
        intentUnchangedBeforeUpgrade &&
        converged &&
        SOURCE_FAMILIES.every(
          (family) => familyFiles(dataDir, family).length === 1,
        ) &&
        source !== null &&
        source.record?.proposed_genesis?.genesis_id === genesisId &&
        read?.status === 200 &&
        consumptionPosture &&
        tempResidue(dataDir).length === 0,
      `${interrupted.status}/${interrupted.body.error?.code || "no-code"} converged=${converged} consumption-posture=${consumptionPosture} elapsed-ms=${elapsedMs}`,
    );
    if (forceUnrelatedFamilyWatchdog) {
      ok(
        "REPLAY ISOLATION: an unrelated owner running past its watchdog cannot starve consumed System convergence",
        postConsumption && converged && elapsedMs < 43_000,
        `elapsed-ms=${elapsedMs}`,
      );
    }
  } finally {
    if (headPlane) await headPlane.stop();
    if (basePlane) await basePlane.stop();
    rmSync(dataDir, { recursive: true, force: true });
  }
}

async function runCrossVersionCompatibilityJourney() {
  let base;
  let resolver;
  let dataDir;
  let basePlane;
  let headPlane;
  try {
    base = buildCompatibilityBaseDaemon();
    const masterCandidate = JSON.parse(base.fixtureBytes.toString("utf8"));
    const unversionedDeploymentRef =
      masterCandidate.initial_profile_refs?.deployment_profile_ref;
    requireValue(
      unversionedDeploymentRef ===
        "deployment-profile://acme/system-alpha/local",
      `pinned M1.3 fixture no longer has the expected unversioned deployment profile: ${unversionedDeploymentRef}`,
    );
    resolver = await startOwnedWalletResolver();
    dataDir = createOwnedTempDir(
      "ioi-system-sequence-zero-cross-version-",
    );
    basePlane = await startVerifierPlaneFromBinary({
      binary: base.binary,
      dataDir,
      env: resolver.env,
    });
    let call = (method, path, body) =>
      jsonCall(basePlane.daemonUrl, method, path, body);
    const source = await admitGenesis(call, resolver, dataDir, {
      genesisBody: base.genesisBodyFor(),
    });
    const sourceStatusBefore = await call(
      "GET",
      "/v1/hypervisor/substrate/status",
    );
    const sourceBytesBefore = familiesSnapshot(dataDir, SOURCE_FAMILIES);
    const sourceDomainsBefore = Object.fromEntries(
      SOURCE_FAMILIES.map((family) => [
        family,
        requiredDomainState(sourceStatusBefore, family),
      ]),
    );
    ok(
      "COMPAT SOURCE: the pinned M1.3 predecessor admits its exact historical request bundle with the unversioned deployment profile",
      sameJson(source.record.proposed_genesis, masterCandidate) &&
        source.record.proposed_genesis?.initial_profile_refs
          ?.deployment_profile_ref === unversionedDeploymentRef &&
        SOURCE_FAMILIES.every(
          (family) =>
            familyFiles(dataDir, family).length === 1 &&
            requiredDomainIsNonVacuous(sourceStatusBefore, family),
        ),
      `commit=${base.commit} pinned-fixtures=${base.fixtureCount} candidate-sha256=${base.fixtureHash}`,
    );

    await basePlane.stop();
    basePlane = undefined;
    headPlane = await startVerifierPlane({ dataDir, env: resolver.env });
    if (!headPlane) {
      throw new Error("BLOCKED: HEAD compatibility daemon is not built");
    }
    call = (method, path, body) =>
      jsonCall(headPlane.daemonUrl, method, path, body);
    const path =
      `${GENESIS_ROUTE}/${source.sourceTail}/sequence-zero-materialization`;
    const request = {
      expected_genesis_admission_record_root: source.recordRoot,
      expected_genesis_admission_receipt_root: source.receiptRoot,
    };
    const { challenge, grant } = await challengeAndGrant(
      call,
      resolver,
      path,
      request,
      MATERIALIZE_SCOPE,
    );
    const materialized = grant
      ? await call("POST", path, {
          ...request,
          wallet_approval_grant: grant,
        })
      : challenge;
    const read = await call("GET", path);
    const statusAfter = await call(
      "GET",
      "/v1/hypervisor/substrate/status",
    );
    const exactEvidence = materialized.status === 201
      ? Object.fromEntries(
          MATERIALIZATION_RESPONSE_FIELDS.map((field) => [
            field,
            materialized.body[field],
          ]),
        )
      : null;
    const persistedEvidence = exactEvidence
      ? MATERIALIZATION_FAMILIES.every(
          (family, index) =>
            sameJson(
              singleFamilyRecord(dataDir, family),
              exactEvidence[MATERIALIZATION_RESPONSE_FIELDS[index]],
            ) &&
            requiredDomainIsNonVacuous(statusAfter, family),
        )
      : false;
    ok(
      "COMPAT UPGRADE: HEAD materializes M1.4 from the preserved predecessor M1.3 evidence",
      materialized.status === 201 &&
        exactEvidence !== null &&
        persistedEvidence &&
        read.status === 200 &&
        responseHasExactEvidence(read.body, exactEvidence) &&
        hasExactFalseNonclaims(read.body),
      `${materialized.status}/${materialized.body.error?.code || "created"}; expectation=HEAD must accept the preserved unversioned deployment-profile reference`,
    );
    const sourceDomainsAfter = Object.fromEntries(
      SOURCE_FAMILIES.map((family) => [
        family,
        requiredDomainState(statusAfter, family),
      ]),
    );
    ok(
      "COMPAT IMMUTABILITY: HEAD leaves predecessor M1.3 local bytes and Agentgres domain coordinates unchanged",
      sourceBytesBefore === familiesSnapshot(dataDir, SOURCE_FAMILIES) &&
        sameJson(sourceDomainsAfter, sourceDomainsBefore) &&
        singleFamilyRecord(dataDir, SOURCE_FAMILIES[0])
          ?.proposed_genesis?.initial_profile_refs
          ?.deployment_profile_ref === unversionedDeploymentRef &&
        tempResidue(dataDir).length === 0,
      `local-bytes=${sourceBytesBefore === familiesSnapshot(dataDir, SOURCE_FAMILIES)} agentgres-domains=${sameJson(sourceDomainsAfter, sourceDomainsBefore)}`,
    );
    await runLegacyM13IntentUpgradeCase(base, resolver, {
      faultEnv: "IOI_TEST_FORCE_SYSTEM_GENESIS_AFTER_PREPARE",
      genesisId: "genesis://acme/system-alpha/legacy-pre-consumption",
      proofName:
        "COMPAT LEGACY PRE-CONSUMPTION: HEAD replays untouched predecessor intent bytes",
    });
    await runLegacyM13IntentUpgradeCase(base, resolver, {
      faultEnv: "IOI_TEST_FORCE_SYSTEM_GENESIS_AFTER_WALLET_CONSUME",
      genesisId: "genesis://acme/system-alpha/legacy-post-consumption",
      proofName:
        "COMPAT LEGACY POST-CONSUMPTION: HEAD reuses the consumed grant and converges untouched predecessor intent bytes",
      forceUnrelatedFamilyWatchdog: true,
    });
  } finally {
    if (headPlane) await headPlane.stop();
    if (basePlane) await basePlane.stop();
    if (resolver) await resolver.stop();
    if (dataDir) rmSync(dataDir, { recursive: true, force: true });
    if (base) base.cleanup();
  }
}

async function runReceiptVersionCompatibilityJourney() {
  let resolver;
  let legacyWriter;
  let legacyDataDir;
  let currentDataDir;
  let plane;
  try {
    resolver = await startOwnedWalletResolver();
    legacyWriter = buildPinnedCompatibilityDaemon({
      commit: LEGACY_RECEIPT_WRITER_COMMIT,
      buildPrefix: "ioi-m14-v1-receipt-compatibility-build-",
      label: "pinned v1 receipt writer",
    });
    legacyDataDir = createOwnedTempDir(
      "ioi-system-sequence-zero-receipt-v1-",
    );
    currentDataDir = createOwnedTempDir(
      "ioi-system-sequence-zero-receipt-v2-",
    );
    plane = await startVerifierPlaneFromBinary({
      binary: legacyWriter.binary,
      dataDir: legacyDataDir,
      env: {
        ...resolver.env,
        IOI_TEST_FORCE_SYSTEM_SEQUENCE_ZERO_AFTER_COMPONENT: "1",
      },
    });
    let call = (method, path, body) =>
      jsonCall(plane.daemonUrl, method, path, body);
    const legacySource = await admitGenesis(call, resolver, legacyDataDir, {
      genesisId: "genesis://acme/system-alpha/receipt-compatibility-v1",
    });
    const legacyPath =
      `${GENESIS_ROUTE}/${legacySource.sourceTail}/sequence-zero-materialization`;
    const legacyRequest = {
      expected_genesis_admission_record_root: legacySource.recordRoot,
      expected_genesis_admission_receipt_root: legacySource.receiptRoot,
    };
    const { grant: legacyGrant } = await challengeAndGrant(
      call,
      resolver,
      legacyPath,
      legacyRequest,
      MATERIALIZE_SCOPE,
    );
    requireValue(
      legacyGrant,
      "historical compatibility interruption did not mint its grant",
    );
    const interrupted = await call("POST", legacyPath, {
      ...legacyRequest,
      wallet_approval_grant: legacyGrant,
    });
    requireValue(
      interrupted.status === 500 &&
        interrupted.body.error?.code ===
          "system_sequence_zero_pending_convergence",
      `historical compatibility interruption failed: ${JSON.stringify(interrupted)}`,
    );
    const interruptedBytes = familiesSnapshot(
      legacyDataDir,
      [...MATERIALIZATION_FAMILIES, INTENT_FAMILY],
    );

    await plane.stop();
    plane = undefined;
    plane = await startVerifierPlane({
      dataDir: legacyDataDir,
      env: {
        ...resolver.env,
        IOI_HYPERVISOR_GOVERNED_REPLAY_INTERVAL_MS: "100",
      },
    });
    if (!plane) {
      throw new Error("BLOCKED: current historical-replay guard daemon is not built");
    }
    call = (method, path, body) =>
      jsonCall(plane.daemonUrl, method, path, body);
    await new Promise((resolve) => setTimeout(resolve, 750));
    const guardedRead = await call("GET", legacyPath);
    ok(
      "RECEIPT COMPAT V1 REPLAY GUARD: the current daemon retains an interrupted historical intent without creating its missing v1 receipt",
      guardedRead.status !== 200 &&
        familyFiles(legacyDataDir, INTENT_FAMILY).length === 1 &&
        familyFiles(legacyDataDir, MATERIALIZATION_FAMILIES[0]).length === 0 &&
        familyFiles(legacyDataDir, MATERIALIZATION_FAMILIES[1]).length === 0 &&
        familyFiles(legacyDataDir, MATERIALIZATION_FAMILIES[2]).length === 1 &&
        familyFiles(legacyDataDir, MATERIALIZATION_FAMILIES[3]).length === 1 &&
        familiesSnapshot(
          legacyDataDir,
          [...MATERIALIZATION_FAMILIES, INTENT_FAMILY],
        ) === interruptedBytes,
      `${guardedRead.status}/${guardedRead.body.error?.code || "no-code"} receipt-count=${familyFiles(legacyDataDir, MATERIALIZATION_FAMILIES[1]).length}`,
    );

    await plane.stop();
    plane = undefined;
    plane = await startVerifierPlaneFromBinary({
      binary: legacyWriter.binary,
      dataDir: legacyDataDir,
      env: {
        ...resolver.env,
        IOI_HYPERVISOR_GOVERNED_REPLAY_INTERVAL_MS: "100",
      },
    });
    call = (method, path, body) =>
      jsonCall(plane.daemonUrl, method, path, body);
    const legacyDeadline = Date.now() + 90_000;
    let legacyConverged;
    while (Date.now() < legacyDeadline) {
      legacyConverged = await call("GET", legacyPath);
      if (legacyConverged.status === 200) break;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    requireValue(
      legacyConverged?.status === 200,
      `pinned historical writer did not finish its own v1 receipt: ${JSON.stringify(legacyConverged)}`,
    );
    const legacyWrite = {
      path: legacyPath,
      request: legacyRequest,
      response: legacyConverged,
    };
    const legacyReceipt = requireValue(
      legacyWrite.response.body
        .autonomous_system_sequence_zero_materialization_receipt,
      "legacy compatibility write lacks its receipt",
    );
    const legacyBoundary = receiptBoundaryRefOracle(
      legacyReceipt,
      legacySource.record,
      "legacy-v1",
    );
    const legacyExactEvidence = Object.fromEntries(
      MATERIALIZATION_RESPONSE_FIELDS.map((field) => [
        field,
        legacyWrite.response.body[field],
      ]),
    );
    const legacyFamilyBytes = familiesSnapshot(
      legacyDataDir,
      MATERIALIZATION_FAMILIES,
    );
    ok(
      "RECEIPT COMPAT V1 WRITE: the pinned historical daemon emits the frozen identity and exact historical boundary semantics",
      legacyReceipt.schema_version === LEGACY_RECEIPT_SCHEMA &&
        legacyReceipt.receipt_profile_ref === LEGACY_RECEIPT_PROFILE &&
        legacyBoundary.pass &&
        legacyReceipt.attested_boundary_fact_refs.includes(
          legacySource.record.admission_id,
        ) &&
        !legacyReceipt.attested_boundary_fact_refs.includes(
          legacyReceipt.bound_facts?.genesis_admission_record_root,
        ) &&
        !legacyReceipt.attested_boundary_fact_refs.includes(
          legacyReceipt.bound_facts?.wallet_grant_consumption_ref,
        ) &&
        MATERIALIZATION_FAMILIES.every(
          (family, index) =>
            sameJson(
              singleFamilyRecord(legacyDataDir, family),
              legacyExactEvidence[MATERIALIZATION_RESPONSE_FIELDS[index]],
            ),
        ),
      `${legacyReceipt.schema_version}/${legacyBoundary.grantId || "missing-grant"}`,
    );

    await plane.stop();
    plane = undefined;
    plane = await startVerifierPlane({
      dataDir: legacyDataDir,
      env: resolver.env,
    });
    if (!plane) {
      throw new Error("BLOCKED: current compatibility reader daemon is not built");
    }
    call = (method, path, body) =>
      jsonCall(plane.daemonUrl, method, path, body);
    const legacyRead = await call("GET", legacyWrite.path);
    ok(
      "RECEIPT COMPAT V1 READ: the current daemon serves the historical receipt byte-exactly without rewriting any M1.4 family",
      legacyRead.status === 200 &&
        responseHasExactEvidence(legacyRead.body, legacyExactEvidence) &&
        familiesSnapshot(legacyDataDir, MATERIALIZATION_FAMILIES) ===
          legacyFamilyBytes &&
        tempResidue(legacyDataDir).length === 0,
      `${legacyRead.status}/${legacyRead.body.error?.code || "ok"}`,
    );

    await plane.stop();
    plane = undefined;
    plane = await startVerifierPlane({
      dataDir: currentDataDir,
      env: resolver.env,
    });
    if (!plane) {
      throw new Error("BLOCKED: current-receipt compatibility daemon is not built");
    }
    call = (method, path, body) =>
      jsonCall(plane.daemonUrl, method, path, body);
    const currentSource = await admitGenesis(call, resolver, currentDataDir, {
      genesisId: "genesis://acme/system-alpha/receipt-compatibility-v2",
    });
    const currentWrite = await materializeGenesisSource(
      call,
      resolver,
      currentSource,
    );
    const currentReceipt = requireValue(
      currentWrite.response.body
        .autonomous_system_sequence_zero_materialization_receipt,
      "current compatibility write lacks its receipt",
    );
    const currentBoundary = receiptBoundaryRefOracle(
      currentReceipt,
      currentSource.record,
      "current-v2",
    );
    ok(
      "RECEIPT COMPAT V2 WRITE: an ordinary current daemon emits only the current identity and exact retained-grant boundary semantics",
      currentReceipt.schema_version === CURRENT_RECEIPT_SCHEMA &&
        currentReceipt.receipt_profile_ref === CURRENT_RECEIPT_PROFILE &&
        currentBoundary.pass &&
        currentReceipt.attested_boundary_fact_refs.includes(
          currentReceipt.bound_facts?.genesis_admission_record_root,
        ) &&
        currentReceipt.attested_boundary_fact_refs.includes(
          currentReceipt.bound_facts?.wallet_grant_consumption_ref,
        ) &&
        !currentReceipt.attested_boundary_fact_refs.includes(
          currentSource.record.admission_id,
        ),
      `${currentReceipt.schema_version}/${currentBoundary.grantId || "missing-grant"}`,
    );
    ok(
      "RECEIPT COMPAT SPLIT: historical read support and current write policy remain distinct, non-aliased contracts",
      legacyReceipt.schema_version !== currentReceipt.schema_version &&
        legacyReceipt.receipt_profile_ref !==
          currentReceipt.receipt_profile_ref &&
        legacyBoundary.grantId !== currentBoundary.grantId &&
        legacyBoundary.grantId ===
          legacySignedGrantIdentity(legacyReceipt) &&
        currentBoundary.grantId ===
          retainedSignedGrantIdentity(currentReceipt) &&
        legacyBoundary.grantId !==
          retainedSignedGrantIdentity(legacyReceipt) &&
        currentBoundary.grantId !==
          legacySignedGrantIdentity(currentReceipt),
      `${legacyReceipt.schema_version} -> ${currentReceipt.schema_version}`,
    );
  } finally {
    if (plane) await plane.stop();
    if (resolver) await resolver.stop();
    legacyWriter?.cleanup();
    if (legacyDataDir) rmSync(legacyDataDir, { recursive: true, force: true });
    if (currentDataDir) rmSync(currentDataDir, { recursive: true, force: true });
  }
}

async function waitForIntentRecordsToClear(dataDir, family) {
  const deadline = Date.now() + 90_000;
  while (Date.now() < deadline) {
    if (familyFiles(dataDir, family).length === 0) return true;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  return false;
}

async function runPreconditionCleanupJourney() {
  const resolver = await startOwnedWalletResolver();
  try {
    const genesisDataDir = createOwnedTempDir(
      "ioi-system-genesis-precondition-cleanup-",
    );
    let genesisPlane;
    try {
      genesisPlane = await startVerifierPlane({
        dataDir: genesisDataDir,
        env: {
          ...resolver.env,
          IOI_TEST_FORCE_SYSTEM_GENESIS_AFTER_PREPARE: "1",
        },
      });
      if (!genesisPlane) {
        throw new Error("BLOCKED: M1.3 cleanup prepare daemon is not built");
      }
      let call = (method, path, body) =>
        jsonCall(genesisPlane.daemonUrl, method, path, body);
      await stableDataPlaneSnapshot(call, genesisDataDir);
      const body = exactGenesisBody(
        "genesis://acme/system-alpha/precondition-cleanup",
      );
      const { grant } = await challengeAndWrongTargetGrant(
        call,
        resolver,
        GENESIS_ROUTE,
        body,
        MATERIALIZE_SCOPE,
      );
      requireValue(grant, "M1.3 cleanup journey did not mint a wrong-target grant");
      const familyPreexisted = existsSync(
        join(genesisDataDir, SOURCE_INTENT_FAMILY),
      );
      const preRequestShape = await stableDataDirSnapshot(genesisDataDir);
      const interrupted = await call("POST", GENESIS_ROUTE, {
        ...body,
        wallet_approval_grant: grant,
      });
      ok(
        "CLEANUP M1.3 PREPARE: a wrong-target grant adds one record to the daemon-owned intent family",
        familyPreexisted &&
          interrupted.status === 500 &&
          interrupted.body.error?.code === "system_genesis_pending_convergence" &&
          familyFiles(genesisDataDir, SOURCE_INTENT_FAMILY).length === 1 &&
          singleFamilyRecord(genesisDataDir, SOURCE_INTENT_FAMILY)
            ?.intent_family_created_by_request === false &&
          SOURCE_FAMILIES.every(
            (family) => familyFiles(genesisDataDir, family).length === 0,
          ),
        `${interrupted.status}/${interrupted.body.error?.code || "no-code"}: ${interrupted.body.error?.message || "no-message"}`,
      );

      await genesisPlane.stop();
      genesisPlane = await startVerifierPlane({
        dataDir: genesisDataDir,
        env: resolver.env,
      });
      if (!genesisPlane) {
        throw new Error("BLOCKED: M1.3 cleanup restart daemon is not built");
      }
      const intentCleared = await waitForIntentRecordsToClear(
        genesisDataDir,
        SOURCE_INTENT_FAMILY,
      );
      const familyRetained = existsSync(
        join(genesisDataDir, SOURCE_INTENT_FAMILY),
      );
      const restoredShape = await stableDataDirSnapshot(genesisDataDir);
      const shapeDelta = dataDirSnapshotDelta(preRequestShape, restoredShape);
      ok(
        "CLEANUP M1.3 RESTART: precondition refusal restores the exact empty intent-family baseline",
        intentCleared &&
          familyRetained &&
          familyFiles(genesisDataDir, SOURCE_INTENT_FAMILY).length === 0 &&
          restoredShape === preRequestShape &&
          SOURCE_FAMILIES.every(
            (family) => familyFiles(genesisDataDir, family).length === 0,
          ) &&
          tempResidue(genesisDataDir).length === 0,
        `intent-cleared=${intentCleared} family-retained=${familyRetained} shape-delta=${shapeDelta.join(",") || "none"}`,
      );
    } finally {
      if (genesisPlane) await genesisPlane.stop();
      rmSync(genesisDataDir, { recursive: true, force: true });
    }

    const materializationDataDir = createOwnedTempDir(
      "ioi-system-sequence-zero-precondition-cleanup-",
    );
    let materializationPlane;
    try {
      materializationPlane = await startVerifierPlane({
        dataDir: materializationDataDir,
        env: resolver.env,
      });
      if (!materializationPlane) {
        throw new Error("BLOCKED: M1.4 cleanup source daemon is not built");
      }
      let call = (method, path, body) =>
        jsonCall(materializationPlane.daemonUrl, method, path, body);
      const source = await admitGenesis(
        call,
        resolver,
        materializationDataDir,
        {
          genesisId: "genesis://acme/system-alpha/m1-4-precondition-cleanup",
        },
      );
      const sourceBefore = familiesSnapshot(
        materializationDataDir,
        SOURCE_FAMILIES,
      );
      await materializationPlane.stop();
      materializationPlane = await startVerifierPlane({
        dataDir: materializationDataDir,
        env: {
          ...resolver.env,
          IOI_TEST_FORCE_SYSTEM_SEQUENCE_ZERO_AFTER_PREPARE: "1",
        },
      });
      if (!materializationPlane) {
        throw new Error("BLOCKED: M1.4 cleanup prepare daemon is not built");
      }
      call = (method, path, body) =>
        jsonCall(materializationPlane.daemonUrl, method, path, body);
      const path =
        `${GENESIS_ROUTE}/${source.sourceTail}/sequence-zero-materialization`;
      const request = {
        expected_genesis_admission_record_root: source.recordRoot,
        expected_genesis_admission_receipt_root: source.receiptRoot,
      };
      const { grant } = await challengeAndWrongTargetGrant(
        call,
        resolver,
        path,
        request,
        GENESIS_SCOPE,
      );
      requireValue(grant, "M1.4 cleanup journey did not mint a wrong-target grant");
      const familyPreexisted = existsSync(
        join(materializationDataDir, INTENT_FAMILY),
      );
      const preRequestShape = await stableDataDirSnapshot(materializationDataDir);
      const interrupted = await call("POST", path, {
        ...request,
        wallet_approval_grant: grant,
      });
      ok(
        "CLEANUP M1.4 PREPARE: a wrong-target grant adds one record to the daemon-owned intent family",
        familyPreexisted &&
          interrupted.status === 500 &&
          interrupted.body.error?.code ===
            "system_sequence_zero_pending_convergence" &&
          familyFiles(materializationDataDir, INTENT_FAMILY).length === 1 &&
          singleFamilyRecord(materializationDataDir, INTENT_FAMILY)
            ?.intent_family_created_by_request === false &&
          MATERIALIZATION_FAMILIES.every(
            (family) => familyFiles(materializationDataDir, family).length === 0,
          ),
        `${interrupted.status}/${interrupted.body.error?.code || "no-code"}: ${interrupted.body.error?.message || "no-message"}`,
      );

      await materializationPlane.stop();
      materializationPlane = await startVerifierPlane({
        dataDir: materializationDataDir,
        env: resolver.env,
      });
      if (!materializationPlane) {
        throw new Error("BLOCKED: M1.4 cleanup restart daemon is not built");
      }
      const intentCleared = await waitForIntentRecordsToClear(
        materializationDataDir,
        INTENT_FAMILY,
      );
      const familyRetained = existsSync(
        join(materializationDataDir, INTENT_FAMILY),
      );
      const restoredShape = await stableDataDirSnapshot(materializationDataDir);
      const shapeDelta = dataDirSnapshotDelta(preRequestShape, restoredShape);
      ok(
        "CLEANUP M1.4 RESTART: precondition refusal restores the exact empty intent-family baseline",
        intentCleared &&
          familyRetained &&
          familyFiles(materializationDataDir, INTENT_FAMILY).length === 0 &&
          restoredShape === preRequestShape &&
          sourceBefore === familiesSnapshot(
            materializationDataDir,
            SOURCE_FAMILIES,
          ) &&
          MATERIALIZATION_FAMILIES.every(
            (family) => familyFiles(materializationDataDir, family).length === 0,
          ) &&
          tempResidue(materializationDataDir).length === 0,
        `intent-cleared=${intentCleared} family-retained=${familyRetained} shape-delta=${shapeDelta.join(",") || "none"}`,
      );
    } finally {
      if (materializationPlane) await materializationPlane.stop();
      rmSync(materializationDataDir, { recursive: true, force: true });
    }
  } finally {
    await resolver.stop();
  }
}

async function runTerminalIntentDurabilityJourney() {
  const resolver = await startOwnedWalletResolver();
  let genesisPlane;
  let materializationPlane;
  let restorationPlane;
  try {
    const genesisDataDir = createOwnedTempDir(
      "ioi-system-genesis-terminal-unlink-",
    );
    const genesisMarkerPath = join(
      genesisDataDir,
      ".system-genesis-terminal-unlink-crash-marker",
    );
    try {
      genesisPlane = await startVerifierPlane({
        dataDir: genesisDataDir,
        env: {
          ...resolver.env,
          [TERMINAL_UNLINK_CRASH_FAMILY_ENV]: SOURCE_INTENT_FAMILY,
          [TERMINAL_UNLINK_CRASH_MARKER_ENV]: genesisMarkerPath,
        },
      });
      if (!genesisPlane) {
        throw new Error("BLOCKED: terminal M1.3 daemon is not built");
      }
      let call = (method, path, body) =>
        jsonCall(genesisPlane.daemonUrl, method, path, body);
      const genesisBody = exactGenesisBody(
        "genesis://acme/system-alpha/terminal-unlink",
      );
      const { grant } = await challengeAndGrant(
        call,
        resolver,
        GENESIS_ROUTE,
        genesisBody,
        GENESIS_SCOPE,
      );
      requireValue(grant, "terminal M1.3 challenge did not mint a grant");
      const inFlight = observedRequest(
        call("POST", GENESIS_ROUTE, {
          ...genesisBody,
          wallet_approval_grant: grant,
        }),
      );
      const crashed = await sigkillPlaneAtMarker({
        plane: genesisPlane,
        markerPath: genesisMarkerPath,
        inFlight,
        boundaryReady: () =>
          familyFiles(genesisDataDir, SOURCE_INTENT_FAMILY).length === 0 &&
          SOURCE_FAMILIES.every(
            (family) => familyFiles(genesisDataDir, family).length === 1,
          ),
        captureAtBoundary: () => ({
          bytes: familiesSnapshot(genesisDataDir, SOURCE_FAMILIES),
          evidence: Object.fromEntries(
            SOURCE_FAMILIES.map((family, index) => [
              SOURCE_RESPONSE_FIELDS[index],
              requireValue(
                singleFamilyRecord(genesisDataDir, family),
                `terminal M1.3 boundary lacks ${family}`,
              ),
            ]),
          ),
        }),
      });
      genesisPlane = undefined;
      const sourceEvidence = requireValue(
        crashed.boundaryEvidence,
        "terminal M1.3 crash lacks its pre-SIGKILL evidence oracle",
      );
      const sourceRecord = requireValue(
        sourceEvidence.evidence.autonomous_system_genesis_admission,
        "terminal M1.3 pre-SIGKILL oracle lacks its admission record",
      );
      const sourceTail = String(sourceRecord.admission_id || "").replace(
        "system-genesis-admission://",
        "",
      );
      ok(
        "TERMINAL M1.3 SIGKILL: committed evidence and an absent replay anchor survive a marker-pinned post-unlink crash",
        crashed.daemonExited &&
          crashed.requestOutcome.kind === "error" &&
          familyFiles(genesisDataDir, SOURCE_INTENT_FAMILY).length === 0 &&
          familiesSnapshot(genesisDataDir, SOURCE_FAMILIES) ===
            sourceEvidence.bytes &&
          SOURCE_FAMILIES.every(
            (family) => familyFiles(genesisDataDir, family).length === 1,
          ),
        `exited=${crashed.daemonExited} request=${crashed.requestOutcome.kind} intent-count=${familyFiles(genesisDataDir, SOURCE_INTENT_FAMILY).length}`,
      );
      genesisPlane = await startVerifierPlane({
        dataDir: genesisDataDir,
        env: resolver.env,
      });
      call = (method, path, body) =>
        jsonCall(genesisPlane.daemonUrl, method, path, body);
      const restarted = await call(
        "GET",
        `${GENESIS_ROUTE}/${sourceTail}`,
      );
      ok(
        "TERMINAL M1.3 RESTART: the same data directory serves the exact admission with no replay anchor",
        restarted.status === 200 &&
          familyFiles(genesisDataDir, SOURCE_INTENT_FAMILY).length === 0 &&
          familiesSnapshot(genesisDataDir, SOURCE_FAMILIES) ===
            sourceEvidence.bytes &&
          SOURCE_RESPONSE_FIELDS.every((field) =>
            sameJson(restarted.body[field], sourceEvidence.evidence[field])
          ),
        `${restarted.status}/${restarted.body.error?.code || "admitted"}`,
      );
    } finally {
      if (genesisPlane) await genesisPlane.stop();
      rmSync(genesisDataDir, { recursive: true, force: true });
    }

    const materializationDataDir = createOwnedTempDir(
      "ioi-system-sequence-zero-terminal-unlink-",
    );
    const materializationMarkerPath = join(
      materializationDataDir,
      ".system-sequence-zero-terminal-unlink-crash-marker",
    );
    try {
      materializationPlane = await startVerifierPlane({
        dataDir: materializationDataDir,
        env: resolver.env,
      });
      if (!materializationPlane) {
        throw new Error("BLOCKED: terminal M1.4 daemon is not built");
      }
      let call = (method, path, body) =>
        jsonCall(materializationPlane.daemonUrl, method, path, body);
      const source = await admitGenesis(call, resolver, materializationDataDir, {
        genesisId: "genesis://acme/system-alpha/terminal-materialization-unlink",
      });
      const sourceBefore = familiesSnapshot(
        materializationDataDir,
        SOURCE_FAMILIES,
      );
      const path =
        `${GENESIS_ROUTE}/${source.sourceTail}/sequence-zero-materialization`;
      const request = {
        expected_genesis_admission_record_root: source.recordRoot,
        expected_genesis_admission_receipt_root: source.receiptRoot,
      };
      await materializationPlane.stop();
      materializationPlane = await startVerifierPlane({
        dataDir: materializationDataDir,
        env: {
          ...resolver.env,
          [TERMINAL_UNLINK_CRASH_FAMILY_ENV]: INTENT_FAMILY,
          [TERMINAL_UNLINK_CRASH_MARKER_ENV]: materializationMarkerPath,
        },
      });
      if (!materializationPlane) {
        throw new Error("BLOCKED: terminal M1.4 crash daemon is not built");
      }
      call = (method, route, body) =>
        jsonCall(materializationPlane.daemonUrl, method, route, body);
      const { grant } = await challengeAndGrant(
        call,
        resolver,
        path,
        request,
        MATERIALIZE_SCOPE,
      );
      requireValue(grant, "terminal M1.4 challenge did not mint a grant");
      const inFlight = observedRequest(
        call("POST", path, {
          ...request,
          wallet_approval_grant: grant,
        }),
      );
      const crashed = await sigkillPlaneAtMarker({
        plane: materializationPlane,
        markerPath: materializationMarkerPath,
        inFlight,
        boundaryReady: () =>
          familyFiles(materializationDataDir, INTENT_FAMILY).length === 0 &&
          MATERIALIZATION_FAMILIES.every(
            (family) => familyFiles(materializationDataDir, family).length === 1,
          ),
        captureAtBoundary: () => ({
          bytes: familiesSnapshot(
            materializationDataDir,
            MATERIALIZATION_FAMILIES,
          ),
          evidence: Object.fromEntries(
            MATERIALIZATION_FAMILIES.map((family, index) => [
              MATERIALIZATION_RESPONSE_FIELDS[index],
              requireValue(
                singleFamilyRecord(materializationDataDir, family),
                `terminal M1.4 boundary lacks ${family}`,
              ),
            ]),
          ),
        }),
      });
      materializationPlane = undefined;
      const materializationEvidence = requireValue(
        crashed.boundaryEvidence,
        "terminal M1.4 crash lacks its pre-SIGKILL evidence oracle",
      );
      ok(
        "TERMINAL M1.4 SIGKILL: committed evidence and an absent replay anchor survive a marker-pinned post-unlink crash",
        crashed.daemonExited &&
          crashed.requestOutcome.kind === "error" &&
          familyFiles(materializationDataDir, INTENT_FAMILY).length === 0 &&
          familiesSnapshot(
            materializationDataDir,
            MATERIALIZATION_FAMILIES,
          ) === materializationEvidence.bytes &&
          MATERIALIZATION_FAMILIES.every(
            (family) => familyFiles(materializationDataDir, family).length === 1,
          ) &&
          sourceBefore === familiesSnapshot(
            materializationDataDir,
            SOURCE_FAMILIES,
          ),
        `exited=${crashed.daemonExited} request=${crashed.requestOutcome.kind} intent-count=${familyFiles(materializationDataDir, INTENT_FAMILY).length}`,
      );
      materializationPlane = await startVerifierPlane({
        dataDir: materializationDataDir,
        env: resolver.env,
      });
      call = (method, path, body) =>
        jsonCall(materializationPlane.daemonUrl, method, path, body);
      const restarted = await call("GET", path);
      ok(
        "TERMINAL M1.4 RESTART: the same data directory serves all exact materialization evidence with no replay anchor",
        restarted.status === 200 &&
          familyFiles(materializationDataDir, INTENT_FAMILY).length === 0 &&
          familiesSnapshot(
            materializationDataDir,
            MATERIALIZATION_FAMILIES,
          ) === materializationEvidence.bytes &&
          responseHasExactEvidence(
            restarted.body,
            materializationEvidence.evidence,
          ) &&
          MATERIALIZATION_FAMILIES.every(
            (family, index) =>
              sameJson(
                singleFamilyRecord(materializationDataDir, family),
                materializationEvidence.evidence[
                  MATERIALIZATION_RESPONSE_FIELDS[index]
                ],
              ),
        ),
        `${restarted.status}/${restarted.body.error?.code || "materialized"}`,
      );

    } finally {
      if (materializationPlane) await materializationPlane.stop();
      rmSync(materializationDataDir, { recursive: true, force: true });
    }

    const restorationDataDir = createOwnedTempDir(
      "ioi-system-sequence-zero-terminal-restoration-",
    );
    const restorationMarkerPath = join(
      restorationDataDir,
      ".system-sequence-zero-unconfirmed-restoration-crash-marker",
    );
    try {
      restorationPlane = await startVerifierPlane({
        dataDir: restorationDataDir,
        env: resolver.env,
      });
      if (!restorationPlane) {
        throw new Error(
          "BLOCKED: terminal M1.4 restoration source daemon is not built",
        );
      }
      let call = (method, path, body) =>
        jsonCall(restorationPlane.daemonUrl, method, path, body);
      const source = await admitGenesis(call, resolver, restorationDataDir, {
        genesisId:
          "genesis://acme/system-alpha/terminal-pre-fsync-restoration",
      });
      const path =
        `${GENESIS_ROUTE}/${source.sourceTail}/sequence-zero-materialization`;
      const request = {
        expected_genesis_admission_record_root: source.recordRoot,
        expected_genesis_admission_receipt_root: source.receiptRoot,
      };
      await restorationPlane.stop();
      restorationPlane = await startVerifierPlane({
        dataDir: restorationDataDir,
        env: {
          ...resolver.env,
          IOI_TEST_FORCE_UNLINK_DIRSYNC_UNCONFIRMED: INTENT_FAMILY,
          [UNCONFIRMED_RESTORE_CRASH_FAMILY_ENV]: INTENT_FAMILY,
          [UNCONFIRMED_RESTORE_CRASH_MARKER_ENV]: restorationMarkerPath,
        },
      });
      if (!restorationPlane) {
        throw new Error(
          "BLOCKED: terminal M1.4 pre-fsync restoration daemon is not built",
        );
      }
      call = (method, route, body) =>
        jsonCall(restorationPlane.daemonUrl, method, route, body);
      const { grant } = await challengeAndGrant(
        call,
        resolver,
        path,
        request,
        MATERIALIZE_SCOPE,
      );
      requireValue(
        grant,
        "terminal M1.4 pre-fsync challenge did not mint a grant",
      );
      const inFlight = observedRequest(
        call("POST", path, {
          ...request,
          wallet_approval_grant: grant,
        }),
      );
      const crashed = await sigkillPlaneAtMarker({
        plane: restorationPlane,
        markerPath: restorationMarkerPath,
        inFlight,
        boundaryReady: () =>
          familyFiles(restorationDataDir, INTENT_FAMILY).length === 1 &&
          MATERIALIZATION_FAMILIES.every(
            (family) => familyFiles(restorationDataDir, family).length === 1,
          ),
        captureAtBoundary: () => ({
          evidence: Object.fromEntries(
            MATERIALIZATION_FAMILIES.map((family, index) => [
              MATERIALIZATION_RESPONSE_FIELDS[index],
              requireValue(
                singleFamilyRecord(restorationDataDir, family),
                `terminal M1.4 pre-fsync boundary lacks ${family}`,
              ),
            ]),
          ),
          evidenceBytes: familiesSnapshot(
            restorationDataDir,
            MATERIALIZATION_FAMILIES,
          ),
          intentBytes: familiesSnapshot(
            restorationDataDir,
            [INTENT_FAMILY],
          ),
        }),
      });
      restorationPlane = undefined;
      const restoredBoundary = requireValue(
        crashed.boundaryEvidence,
        "terminal M1.4 pre-fsync crash lacks its restored replay-anchor oracle",
      );
      ok(
        "TERMINAL M1.4 PRE-FSYNC: an unconfirmed intent unlink restores its byte-exact replay anchor after all evidence is durable",
        crashed.daemonExited &&
          crashed.requestOutcome.kind === "error" &&
          familyFiles(restorationDataDir, INTENT_FAMILY).length === 1 &&
          MATERIALIZATION_FAMILIES.every(
            (family) => familyFiles(restorationDataDir, family).length === 1,
          ) &&
          familiesSnapshot(
            restorationDataDir,
            MATERIALIZATION_FAMILIES,
          ) === restoredBoundary.evidenceBytes &&
          familiesSnapshot(restorationDataDir, [INTENT_FAMILY]) ===
            restoredBoundary.intentBytes &&
          tempResidue(restorationDataDir).length === 0,
        `exited=${crashed.daemonExited} request=${crashed.requestOutcome.kind} intent-count=${familyFiles(restorationDataDir, INTENT_FAMILY).length}`,
      );

      restorationPlane = await startVerifierPlane({
        dataDir: restorationDataDir,
        env: resolver.env,
      });
      call = (method, route, body) =>
        jsonCall(restorationPlane.daemonUrl, method, route, body);
      const restoredIntentCleared = await waitForIntentRecordsToClear(
        restorationDataDir,
        INTENT_FAMILY,
      );
      const restoredRead = await call("GET", path);
      ok(
        "TERMINAL M1.4 PRE-FSYNC RESTART: the restored anchor converges to the exact already-durable evidence",
        restoredIntentCleared &&
          restoredRead.status === 200 &&
          responseHasExactEvidence(
            restoredRead.body,
            restoredBoundary.evidence,
          ) &&
          familyFiles(restorationDataDir, INTENT_FAMILY).length === 0 &&
          restoredBoundary.intentBytes !==
            familiesSnapshot(restorationDataDir, [INTENT_FAMILY]) &&
          familiesSnapshot(
            restorationDataDir,
            MATERIALIZATION_FAMILIES,
          ) === restoredBoundary.evidenceBytes &&
          tempResidue(restorationDataDir).length === 0,
        `${restoredRead.status}/${restoredRead.body.error?.code || "materialized"} intent-cleared=${restoredIntentCleared} intent-count=${familyFiles(restorationDataDir, INTENT_FAMILY).length}`,
      );
    } finally {
      if (restorationPlane) await restorationPlane.stop();
      rmSync(restorationDataDir, { recursive: true, force: true });
    }
  } finally {
    await resolver.stop();
  }
}

const PROTECTED_INTENT_FAMILY = "autonomous-system-protected-transition-intents";
const LIFECYCLE_STATE_FAMILY = "autonomous-system-lifecycle-states";

async function runProtectedTransitionJourney() {
  const resolver = await startOwnedWalletResolver();
  const dataDir = createOwnedTempDir("ioi-protected-transition-");
  let plane;
  try {
    plane = await startVerifierPlane({ dataDir, env: resolver.env });
    if (!plane) {
      throw new Error("BLOCKED: M1.5b Hypervisor daemon is not built");
    }
    let call = (method, path, body) =>
      jsonCall(plane.daemonUrl, method, path, body);

    // Bootstrap one System to its converged ACTIVE head through the real
    // governed prefix (genesis -> materialize -> initialize -> activate).
    const genesisBody = exactGenesisBody("genesis://acme/system-alpha/m1-5b");
    const pinnedDeploymentRevision = lifecycleDeploymentRevisionForGenesis(
      genesisBody.proposed_instantiation.candidate,
    );
    genesisBody.proposed_instantiation.candidate.initial_profile_refs.deployment_profile_ref =
      pinnedDeploymentRevision.deployment_profile_ref;
    const source = await admitGenesis(call, resolver, dataDir, { genesisBody });
    const materializePath =
      `${GENESIS_ROUTE}/${source.sourceTail}/sequence-zero-materialization`;
    const materializeRequest = {
      expected_genesis_admission_record_root: source.recordRoot,
      expected_genesis_admission_receipt_root: source.receiptRoot,
    };
    const materializeAuthority = await challengeAndGrant(
      call,
      resolver,
      materializePath,
      materializeRequest,
      MATERIALIZE_SCOPE,
    );
    const materialized = await call("POST", materializePath, {
      ...materializeRequest,
      wallet_approval_grant: requireValue(
        materializeAuthority.grant,
        "M1.5b setup lacks the M1.4 grant",
      ),
    });
    requireValue(
      materialized.status === 201,
      `M1.5b setup failed M1.4: ${materialized.status}`,
    );
    const materialization =
      materialized.body.autonomous_system_sequence_zero_materialization;
    const materializationReceipt =
      materialized.body.autonomous_system_sequence_zero_materialization_receipt;
    const revision = lifecycleDeploymentRevision(source);
    const initializePath = `${GENESIS_ROUTE}/${source.sourceTail}/initialize`;
    const initializeRequest = {
      expected_sequence_zero_materialization_root: artifactHash(
        "ioi.autonomous-system-sequence-zero-materialization-artifact-jcs-sha256.v1",
        materialization,
      ),
      expected_sequence_zero_materialization_receipt_root: artifactHash(
        "ioi.autonomous-system-sequence-zero-materialization-receipt-artifact-jcs-sha256.v1",
        materializationReceipt,
      ),
      deployment_profile_revision: revision,
    };
    const initializeAuthority = await challengeAndGrant(
      call,
      resolver,
      initializePath,
      initializeRequest,
      INITIALIZE_SCOPE,
    );
    const initialized = await call("POST", initializePath, {
      ...initializeRequest,
      wallet_approval_grant: requireValue(
        initializeAuthority.grant,
        "M1.5b setup lacks the initialize grant",
      ),
    });
    requireValue(
      initialized.status === 200,
      `M1.5b setup failed initialize: ${initialized.status}/${initialized.body.error?.code || "no-code"}`,
    );
    const initializedState = initialized.body.autonomous_system_activation_state;
    const initializedReceipt = initialized.body.lifecycle_receipt;
    const activatePath = `${GENESIS_ROUTE}/${source.sourceTail}/activate`;
    const activateRequest = {
      expected_initialize_proposal_root:
        initializedReceipt.bound_facts.proposal_root,
      expected_initialize_decision_root:
        initializedReceipt.bound_facts.decision_root,
      expected_initialize_state_root: initializedState.activation_state_root,
      expected_initialize_transition_root: initializedState.transition_root,
      expected_initialize_receipt_root: initializedState.transition_receipt_root,
    };
    const activateAuthority = await challengeAndGrant(
      call,
      resolver,
      activatePath,
      activateRequest,
      ACTIVATE_SCOPE,
    );
    const activated = await call("POST", activatePath, {
      ...activateRequest,
      wallet_approval_grant: requireValue(
        activateAuthority.grant,
        "M1.5b setup lacks the activate grant",
      ),
    });
    requireValue(
      activated.status === 200,
      `M1.5b setup failed activate: ${activated.status}/${activated.body.error?.code || "no-code"}`,
    );
    const activeChain = requireValue(
      activated.body.autonomous_system_chain,
      "M1.5b setup lacks the live chain",
    );
    const activeState = activated.body.autonomous_system_activation_state;

    const transitionPath = (op) =>
      `${GENESIS_ROUTE}/${source.sourceTail}/transitions/${op}`;

    // 1) Eligibility projection follows the canon matrix over the live head.
    const pauseGet = await call("GET", transitionPath("pause"));
    const recoveryGet = await call("GET", transitionPath("complete_recovery"));
    ok(
      "M1.5b ELIGIBILITY: pause admits from active while complete_recovery refuses the canon matrix",
      pauseGet.status === 200 &&
        pauseGet.body.eligible_now?.predecessor_status === "active" &&
        pauseGet.body.eligible_now?.admits === true &&
        pauseGet.body.committed_entries?.length === 0 &&
        recoveryGet.status === 200 &&
        recoveryGet.body.eligible_now?.admits === false,
      `${pauseGet.status}/${pauseGet.body.eligible_now?.admits} ${recoveryGet.status}/${recoveryGet.body.eligible_now?.admits}`,
    );

    const lifecycleFamilies = [
      PROTECTED_INTENT_FAMILY,
      LIFECYCLE_STATE_FAMILY,
      "autonomous-system-protected-transition-receipts",
    ];
    const beforeIllegal = familiesSnapshot(dataDir, lifecycleFamilies);

    // 2) Illegal matrix rows refuse before any authority crossing.
    const illegal = await call("POST", transitionPath("complete_recovery"), {
      expected_chain_head_root: activeChain.chain_root,
      expected_predecessor_state_root: activeState.activation_state_root,
    });
    ok(
      "M1.5b ILLEGAL MATRIX: complete_recovery over active refuses before any authority with zero lifecycle evidence",
      illegal.status === 422 &&
        illegal.body.error?.code === "system_lifecycle_plan_invalid" &&
        String(illegal.body.error?.message).includes("cannot lawfully leave") &&
        beforeIllegal === familiesSnapshot(dataDir, lifecycleFamilies),
      `${illegal.status}/${illegal.body.error?.code || "no-code"}`,
    );

    // 3) Stale caller views refuse as conflicts.
    const stale = await call("POST", transitionPath("pause"), {
      expected_chain_head_root: `sha256:${"9".repeat(64)}`,
      expected_predecessor_state_root: activeState.activation_state_root,
    });
    ok(
      "M1.5b STALE HEAD: an expected chain head behind the live head refuses conflict with zero evidence",
      stale.status === 409 &&
        stale.body.error?.code === "system_lifecycle_head_conflict" &&
        beforeIllegal === familiesSnapshot(dataDir, lifecycleFamilies),
      `${stale.status}/${stale.body.error?.code || "no-code"}`,
    );

    // 4) Twelve racing pause requests linearize to exactly one graph.
    const pauseRequest = {
      expected_chain_head_root: activeChain.chain_root,
      expected_predecessor_state_root: activeState.activation_state_root,
    };
    const pauseAuthority = await challengeAndGrant(
      call,
      resolver,
      transitionPath("pause"),
      pauseRequest,
      "scope:autonomous_system.lifecycle.pause",
    );
    const pauseGrant = requireValue(
      pauseAuthority.grant,
      `M1.5b pause challenge lacks a grant: ${JSON.stringify(pauseAuthority.challenge)}`,
    );
    const pauseResponses = await Promise.all(
      Array.from({ length: 12 }, () =>
        call("POST", transitionPath("pause"), {
          ...pauseRequest,
          wallet_approval_grant: pauseGrant,
        }),
      ),
    );
    const pauseWinners = pauseResponses.filter((r) => r.status === 200);
    const paused = pauseWinners[0]?.body;
    ok(
      "M1.5b PAUSE: twelve real-wallet pause requests linearize to one sequence-three graph",
      pauseWinners.length === 1 &&
        paused?.sequence === 3 &&
        paused?.autonomous_system_chain?.status === "paused" &&
        paused?.autonomous_system_chain?.latest_sequence === 3 &&
        paused?.operation_log?.schema_version ===
          "ioi.autonomous-system-operation-log.v2" &&
        paused?.operation_log?.entries?.length === 4 &&
        paused?.lifecycle_receipt?.op === "pause" &&
        familyFiles(dataDir, LIFECYCLE_STATE_FAMILY).length === 1 &&
        familyFiles(dataDir, PROTECTED_INTENT_FAMILY).length === 0,
      `winners=${pauseWinners.length} first=${JSON.stringify(pauseResponses[0]?.body?.error || null)} responses=${pauseResponses.map((r) => `${r.status}/${r.body.op || r.body.error?.code || "no-code"}`).join(",")}`,
    );

    // 5) Scope substitution refuses: a resume grant cannot authorize suspend.
    const pausedChain = paused.autonomous_system_chain;
    const pausedState = paused.lifecycle_state;
    const resumeRequest = {
      expected_chain_head_root: pausedChain.chain_root,
      expected_predecessor_state_root: pausedState.lifecycle_state_root,
    };
    const resumeAuthority = await challengeAndGrant(
      call,
      resolver,
      transitionPath("resume"),
      resumeRequest,
      "scope:autonomous_system.lifecycle.resume",
    );
    const resumeGrant = requireValue(
      resumeAuthority.grant,
      "M1.5b resume challenge lacks a grant",
    );
    const beforeSubstitution = familiesSnapshot(dataDir, lifecycleFamilies);
    const substituted = await call("POST", transitionPath("suspend"), {
      expected_chain_head_root: pausedChain.chain_root,
      expected_predecessor_state_root: pausedState.lifecycle_state_root,
      wallet_approval_grant: resumeGrant,
    });
    ok(
      "M1.5b WRONG SCOPE: a resume-scoped grant cannot authorize suspend",
      substituted.status !== 200 &&
        beforeSubstitution === familiesSnapshot(dataDir, lifecycleFamilies),
      `${substituted.status}/${substituted.body.error?.code || "no-code"}`,
    );

    // 6) Crash after real wallet consumption converges exactly once on restart.
    await plane.stop();
    plane = await startVerifierPlane({
      dataDir,
      env: {
        ...resolver.env,
        IOI_TEST_FORCE_SYSTEM_LIFECYCLE_AFTER_WALLET_CONSUMPTION: "resume",
      },
    });
    if (!plane) {
      throw new Error("BLOCKED: M1.5b fault plane is not built");
    }
    call = (method, path, body) => jsonCall(plane.daemonUrl, method, path, body);
    const interrupted = await call("POST", transitionPath("resume"), {
      ...resumeRequest,
      wallet_approval_grant: resumeGrant,
    });
    requireValue(
      interrupted.status === 500 &&
        interrupted.body.error?.code === "system_lifecycle_pending_convergence" &&
        familyFiles(dataDir, PROTECTED_INTENT_FAMILY).length === 1,
      `M1.5b fault injection did not park the resume: ${interrupted.status}/${interrupted.body.error?.code || "no-code"} intents=${familyFiles(dataDir, PROTECTED_INTENT_FAMILY).length}`,
    );
    await plane.stop();
    plane = await startVerifierPlane({ dataDir, env: resolver.env });
    if (!plane) {
      throw new Error("BLOCKED: M1.5b replay plane is not built");
    }
    call = (method, path, body) => jsonCall(plane.daemonUrl, method, path, body);
    const protectedIntentCleared = await waitForIntentRecordsToClear(
      dataDir,
      PROTECTED_INTENT_FAMILY,
    );
    const converged = await call("GET", transitionPath("resume"));
    const daemonReplayLines = readdirSync(dataDir)
      .filter((name) => name.startsWith("isolated-daemon"))
      .flatMap((name) => {
        try {
          return readFileSync(join(dataDir, name), "utf8")
            .split("\n")
            .filter((line) => line.includes("ProtectedTransition"));
        } catch {
          return [];
        }
      })
      .slice(-3);
    ok(
      "M1.5b REPLAY: a crash after wallet consumption converges exactly one resume at sequence four on restart",
      protectedIntentCleared &&
        converged.status === 200 &&
        converged.body.chain_head?.latest_sequence === 4 &&
        converged.body.chain_head?.status === "active" &&
        converged.body.committed_entries?.length === 1 &&
        familyFiles(dataDir, LIFECYCLE_STATE_FAMILY).length === 2,
      `cleared=${protectedIntentCleared} sequence=${converged.body.chain_head?.latest_sequence} status=${converged.body.chain_head?.status} daemon=${JSON.stringify(daemonReplayLines)}`,
    );
  } finally {
    if (plane) await plane.stop();
    await resolver.stop();
    rmSync(dataDir, { recursive: true, force: true });
  }
}

const AMENDMENT_SCOPE = "scope:autonomous_system.lifecycle.amend_constitution";
const AMENDMENT_INTENT_FAMILY = "autonomous-system-amendment-intents";
const AMENDMENT_RECEIPT_FAMILY = "autonomous-system-amendment-receipts";
const CONSTITUTION_FAMILY = "autonomous-system-constitutions";
const AMENDMENT_DECLARATION_FAMILY = "autonomous-system-constitution-amendments";

/// A constitution's authoritative root: the SAME profile-candidate recipe
/// genesis and activation use, over the whole body. The body's declared
/// `constitution_root` field is carried, non-authoritative, and never this
/// value (it cannot be, without self-reference).
function constitutionCandidateRoot(body) {
  return artifactHashKind(
    "ioi.autonomous-system-profile-candidate-jcs-sha256.v1",
    "constitution",
    body,
  );
}

function artifactHashKind(domain, kind, candidate) {
  return `sha256:${createHash("sha256")
    .update(canonicalJson({ domain, kind, candidate }))
    .digest("hex")}`;
}

/// Mint a successor constitution from the live predecessor body. Structural
/// lineage fields (id, version, predecessor ref, status, activation receipt)
/// are diff-excluded by canon; `mutate` applies the amendable change.
function successorConstitution(
  predecessor,
  { id, version, activationReceiptRef, mutate },
) {
  const successor = clone(predecessor);
  successor.constitution_id = id;
  successor.version = version;
  successor.predecessor_constitution_ref = predecessor.constitution_id;
  successor.status = "active";
  successor.activation_receipt_ref = activationReceiptRef;
  mutate(successor);
  // Structural, diff-excluded and non-authoritative: carried verbatim.
  successor.constitution_root = predecessor.constitution_root;
  return successor;
}

/// A contract-valid amendment declaration binding exactly one predecessor
/// and successor pair plus the paths it claims to change.
function amendmentDeclaration({
  systemId,
  ordinal,
  predecessor,
  predecessorRoot,
  successor,
  changedFieldPaths,
}) {
  return {
    schema_version: "ioi.autonomous-system-constitution-amendment.v1",
    amendment_id: `constitution-amendment://acme/system-alpha/${ordinal}`,
    system_id: systemId,
    predecessor_constitution_ref: predecessor.constitution_id,
    predecessor_constitution_root: predecessorRoot,
    proposed_successor_constitution_ref: successor.constitution_id,
    proposed_successor_constitution_root: constitutionCandidateRoot(successor),
    changed_field_paths: changedFieldPaths,
    protected_field_paths: ["/declared_purpose"],
    governing_decision_profile_ref: "policy://acme/governance/amendments",
    proposal_ref: `proposal://acme/constitution-amendment/${ordinal}`,
    evidence_refs: [`evidence://acme/amendment/${ordinal}`],
    authority_requirement_refs: [
      "authority-requirement://acme/governance/amend",
    ],
    proposed_by_ref: "governance://acme/research",
    decision_ref: null,
    status: "proposed",
  };
}

const AMENDABLE_POINTER =
  "/normative_constraints/permitted_ontology_action_contract_refs";

async function runConstitutionalAmendmentJourney() {
  const resolver = await startOwnedWalletResolver();
  const dataDir = createOwnedTempDir("ioi-constitutional-amendment-");
  let plane;
  try {
    plane = await startVerifierPlane({ dataDir, env: resolver.env });
    if (!plane) {
      throw new Error("BLOCKED: M1.5c Hypervisor daemon is not built");
    }
    const call = (method, path, body) =>
      jsonCall(plane.daemonUrl, method, path, body);

    // Bootstrap one System to its converged ACTIVE head through the real
    // governed prefix (genesis -> materialize -> initialize -> activate).
    const genesisBody = exactGenesisBody("genesis://acme/system-alpha/m1-5c");
    const pinnedDeploymentRevision = lifecycleDeploymentRevisionForGenesis(
      genesisBody.proposed_instantiation.candidate,
    );
    genesisBody.proposed_instantiation.candidate.initial_profile_refs.deployment_profile_ref =
      pinnedDeploymentRevision.deployment_profile_ref;
    const source = await admitGenesis(call, resolver, dataDir, { genesisBody });
    const materializePath =
      `${GENESIS_ROUTE}/${source.sourceTail}/sequence-zero-materialization`;
    const materializeRequest = {
      expected_genesis_admission_record_root: source.recordRoot,
      expected_genesis_admission_receipt_root: source.receiptRoot,
    };
    const materializeAuthority = await challengeAndGrant(
      call,
      resolver,
      materializePath,
      materializeRequest,
      MATERIALIZE_SCOPE,
    );
    const materialized = await call("POST", materializePath, {
      ...materializeRequest,
      wallet_approval_grant: requireValue(
        materializeAuthority.grant,
        "M1.5c setup lacks the M1.4 grant",
      ),
    });
    requireValue(
      materialized.status === 201,
      `M1.5c setup failed M1.4: ${materialized.status}`,
    );
    const materialization =
      materialized.body.autonomous_system_sequence_zero_materialization;
    const materializationReceipt =
      materialized.body.autonomous_system_sequence_zero_materialization_receipt;
    const revision = lifecycleDeploymentRevision(source);
    const initializePath = `${GENESIS_ROUTE}/${source.sourceTail}/initialize`;
    const initializeRequest = {
      expected_sequence_zero_materialization_root: artifactHash(
        "ioi.autonomous-system-sequence-zero-materialization-artifact-jcs-sha256.v1",
        materialization,
      ),
      expected_sequence_zero_materialization_receipt_root: artifactHash(
        "ioi.autonomous-system-sequence-zero-materialization-receipt-artifact-jcs-sha256.v1",
        materializationReceipt,
      ),
      deployment_profile_revision: revision,
    };
    const initializeAuthority = await challengeAndGrant(
      call,
      resolver,
      initializePath,
      initializeRequest,
      INITIALIZE_SCOPE,
    );
    const initialized = await call("POST", initializePath, {
      ...initializeRequest,
      wallet_approval_grant: requireValue(
        initializeAuthority.grant,
        "M1.5c setup lacks the initialize grant",
      ),
    });
    requireValue(
      initialized.status === 200,
      `M1.5c setup failed initialize: ${initialized.status}/${initialized.body.error?.code || "no-code"}`,
    );
    const initializedState = initialized.body.autonomous_system_activation_state;
    const initializedReceipt = initialized.body.lifecycle_receipt;
    const activatePath = `${GENESIS_ROUTE}/${source.sourceTail}/activate`;
    const activateRequest = {
      expected_initialize_proposal_root:
        initializedReceipt.bound_facts.proposal_root,
      expected_initialize_decision_root:
        initializedReceipt.bound_facts.decision_root,
      expected_initialize_state_root: initializedState.activation_state_root,
      expected_initialize_transition_root: initializedState.transition_root,
      expected_initialize_receipt_root: initializedState.transition_receipt_root,
    };
    const activateAuthority = await challengeAndGrant(
      call,
      resolver,
      activatePath,
      activateRequest,
      ACTIVATE_SCOPE,
    );
    const activated = await call("POST", activatePath, {
      ...activateRequest,
      wallet_approval_grant: requireValue(
        activateAuthority.grant,
        "M1.5c setup lacks the activate grant",
      ),
    });
    requireValue(
      activated.status === 200,
      `M1.5c setup failed activate: ${activated.status}/${activated.body.error?.code || "no-code"}`,
    );
    const activeChain = requireValue(
      activated.body.autonomous_system_chain,
      "M1.5c setup lacks the live chain",
    );
    const activeState = activated.body.autonomous_system_activation_state;

    const amendmentPath = `${GENESIS_ROUTE}/${source.sourceTail}/amendments`;
    const systemId = activeChain.system_id;
    // The chain's active constitution is the body genesis admitted.
    const predecessorConstitution = requireValue(
      source.record.initial_profile_bundle?.constitution,
      "M1.5c setup lacks the admitted constitution body",
    );
    const activationReceiptRef = requireValue(
      activeState.transition_receipt_ref,
      "M1.5c setup lacks the activation receipt ref",
    );

    // 1) Eligibility projects the amendment gate over the live head.
    const eligibility = await call("GET", amendmentPath);
    ok(
      "M1.5c ELIGIBILITY: amendment admits from the active head with zero committed amendment evidence",
      eligibility.status === 200 &&
        eligibility.body.eligible_now?.admits === true &&
        eligibility.body.eligible_now?.predecessor_status === "active" &&
        eligibility.body.required_scope === AMENDMENT_SCOPE &&
        eligibility.body.current_constitution?.constitution_root ===
          activeChain.constitution_root &&
        eligibility.body.committed_amendments?.length === 0 &&
        eligibility.body.retained_declarations?.length === 0,
      `${eligibility.status}/${eligibility.body.eligible_now?.admits} committed=${eligibility.body.committed_amendments?.length} retained=${eligibility.body.retained_declarations?.length}`,
    );

    const amendmentFamilies = [
      AMENDMENT_INTENT_FAMILY,
      AMENDMENT_RECEIPT_FAMILY,
      CONSTITUTION_FAMILY,
      AMENDMENT_DECLARATION_FAMILY,
      LIFECYCLE_STATE_FAMILY,
    ];
    const beforeRefusals = familiesSnapshot(dataDir, amendmentFamilies);

    const lawfulSuccessor = successorConstitution(predecessorConstitution, {
      id: "constitution://acme/system-alpha/v2",
      version: "1.1.0",
      activationReceiptRef,
      mutate: (body) => {
        body.normative_constraints.permitted_ontology_action_contract_refs = [
          "ontology-action://acme/amended/v1",
        ];
      },
    });
    const lawfulDeclaration = amendmentDeclaration({
      systemId,
      ordinal: 1,
      predecessor: predecessorConstitution,
      predecessorRoot: activeChain.constitution_root,
      successor: lawfulSuccessor,
      changedFieldPaths: [AMENDABLE_POINTER],
    });
    const pinnedRoots = {
      expected_chain_head_root: activeChain.chain_root,
      expected_predecessor_state_root: activeState.activation_state_root,
    };

    // 2) The declared change set must equal the canonical diff exactly, in
    //    both directions: neither an extra claimed path nor an undeclared
    //    real change may pass.
    const overDeclared = await call("POST", amendmentPath, {
      ...pinnedRoots,
      amendment: {
        ...lawfulDeclaration,
        changed_field_paths: [AMENDABLE_POINTER, "/shutdown/kill_switch_ref"],
      },
      successor_constitution: lawfulSuccessor,
    });
    const undeclaredSuccessor = successorConstitution(
      predecessorConstitution,
      {
        id: "constitution://acme/system-alpha/v2-undeclared",
        version: "1.1.0",
        activationReceiptRef,
        mutate: (body) => {
          body.normative_constraints.permitted_ontology_action_contract_refs = [
            "ontology-action://acme/amended/v1",
          ];
          body.shutdown.kill_switch_ref = "policy://acme/shutdown/smuggled";
        },
      },
    );
    const underDeclared = await call("POST", amendmentPath, {
      ...pinnedRoots,
      amendment: amendmentDeclaration({
        systemId,
        ordinal: 1,
        predecessor: predecessorConstitution,
        predecessorRoot: activeChain.constitution_root,
        successor: undeclaredSuccessor,
        changedFieldPaths: [AMENDABLE_POINTER],
      }),
      successor_constitution: undeclaredSuccessor,
    });
    ok(
      "M1.5c DECLARED DIFF: an over-declared and an undeclared change both refuse before authority with zero evidence",
      overDeclared.status === 422 &&
        overDeclared.body.error?.code === "system_lifecycle_plan_invalid" &&
        String(overDeclared.body.error?.message).includes(
          "do not equal the canonical diff",
        ) &&
        underDeclared.status === 422 &&
        underDeclared.body.error?.code === "system_lifecycle_plan_invalid" &&
        String(underDeclared.body.error?.message).includes(
          "do not equal the canonical diff",
        ) &&
        sameJson(familiesSnapshot(dataDir, amendmentFamilies), beforeRefusals),
      `over=${overDeclared.status}/${overDeclared.body.error?.code} under=${underDeclared.status}/${underDeclared.body.error?.code}`,
    );

    // 3) A clause the declaration itself protects cannot be amended.
    const protectedSuccessor = successorConstitution(predecessorConstitution, {
      id: "constitution://acme/system-alpha/v2-protected",
      version: "1.1.0",
      activationReceiptRef,
      mutate: (body) => {
        body.declared_purpose.statement = "Pursue whatever the operator wants.";
      },
    });
    const protectedRefusal = await call("POST", amendmentPath, {
      ...pinnedRoots,
      amendment: amendmentDeclaration({
        systemId,
        ordinal: 1,
        predecessor: predecessorConstitution,
        predecessorRoot: activeChain.constitution_root,
        successor: protectedSuccessor,
        changedFieldPaths: ["/declared_purpose/statement"],
      }),
      successor_constitution: protectedSuccessor,
    });
    ok(
      "M1.5c PROTECTED CLAUSE: a change under a declared protected path refuses before authority with zero evidence",
      protectedRefusal.status === 422 &&
        protectedRefusal.body.error?.code === "system_lifecycle_plan_invalid" &&
        String(protectedRefusal.body.error?.message).includes(
          "protected by declared path",
        ) &&
        sameJson(familiesSnapshot(dataDir, amendmentFamilies), beforeRefusals),
      `${protectedRefusal.status}/${protectedRefusal.body.error?.code}: ${protectedRefusal.body.error?.message}`,
    );

    // 4) The governance subtree is machine-protected: amendment may never
    //    rewrite its own amendment rules on this path.
    const governanceSuccessor = successorConstitution(predecessorConstitution, {
      id: "constitution://acme/system-alpha/v2-governance",
      version: "1.1.0",
      activationReceiptRef,
      mutate: (body) => {
        // A contract-LEGAL governance edit, so the refusal proves the
        // machine floor itself and not schema validation.
        body.governance.affected_party_policy_ref =
          "policy://acme/governance/affected-parties-v2";
      },
    });
    const governanceRefusal = await call("POST", amendmentPath, {
      ...pinnedRoots,
      amendment: amendmentDeclaration({
        systemId,
        ordinal: 1,
        predecessor: predecessorConstitution,
        predecessorRoot: activeChain.constitution_root,
        successor: governanceSuccessor,
        changedFieldPaths: ["/governance/affected_party_policy_ref"],
      }),
      successor_constitution: governanceSuccessor,
    });
    ok(
      "M1.5c MACHINE FLOOR: rewriting the governance subtree refuses as machine-protected with zero evidence",
      governanceRefusal.status === 422 &&
        governanceRefusal.body.error?.code ===
          "system_lifecycle_plan_invalid" &&
        String(governanceRefusal.body.error?.message).includes(
          "machine-protected",
        ) &&
        sameJson(familiesSnapshot(dataDir, amendmentFamilies), beforeRefusals),
      `${governanceRefusal.status}/${governanceRefusal.body.error?.code}: ${governanceRefusal.body.error?.message}`,
    );

    // 5) A stale pinned head refuses as a conflict.
    const staleRefusal = await call("POST", amendmentPath, {
      expected_chain_head_root: `sha256:${"5c".repeat(32)}`,
      expected_predecessor_state_root: activeState.activation_state_root,
      amendment: lawfulDeclaration,
      successor_constitution: lawfulSuccessor,
    });
    ok(
      "M1.5c STALE HEAD: an expected chain head that is not the live head refuses conflict with zero evidence",
      staleRefusal.status === 409 &&
        staleRefusal.body.error?.code === "system_lifecycle_head_conflict" &&
        sameJson(familiesSnapshot(dataDir, amendmentFamilies), beforeRefusals),
      `${staleRefusal.status}/${staleRefusal.body.error?.code}`,
    );

    // 6) Lifecycle authority is not constitutional authority: a pause-scoped
    //    grant cannot execute an amendment.
    // A distinct declaration so this probe carries its own request hash: one
    // request hash may name exactly one wallet approval decision.
    const wrongScopeDeclaration = amendmentDeclaration({
      systemId,
      ordinal: 9,
      predecessor: predecessorConstitution,
      predecessorRoot: activeChain.constitution_root,
      successor: lawfulSuccessor,
      changedFieldPaths: [AMENDABLE_POINTER],
    });
    const wrongScopeRequest = {
      ...pinnedRoots,
      amendment: wrongScopeDeclaration,
      successor_constitution: lawfulSuccessor,
    };
    const pauseScopedAuthority = await challengeAndGrant(
      call,
      resolver,
      amendmentPath,
      wrongScopeRequest,
      "scope:autonomous_system.lifecycle.pause",
    );
    const wrongScope = await call("POST", amendmentPath, {
      ...wrongScopeRequest,
      wallet_approval_grant: pauseScopedAuthority.grant,
    });
    ok(
      "M1.5c WRONG SCOPE: a pause-scoped grant cannot authorize constitutional amendment",
      wrongScope.status >= 400 &&
        familyFiles(dataDir, CONSTITUTION_FAMILY).length === 0 &&
        familyFiles(dataDir, AMENDMENT_INTENT_FAMILY).length === 0,
      `${wrongScope.status}/${wrongScope.body.error?.code} constitutions=${familyFiles(dataDir, CONSTITUTION_FAMILY).length}`,
    );

    // 7) The lawful amendment executes exactly once: the constitution and the
    //    active profile set swap while operational status is unchanged.
    const amendAuthority = await challengeAndGrant(
      call,
      resolver,
      amendmentPath,
      { ...pinnedRoots, amendment: lawfulDeclaration, successor_constitution: lawfulSuccessor },
      AMENDMENT_SCOPE,
    );
    const amended = await call("POST", amendmentPath, {
      ...pinnedRoots,
      amendment: lawfulDeclaration,
      successor_constitution: lawfulSuccessor,
      wallet_approval_grant: requireValue(
        amendAuthority.grant,
        "M1.5c lacks the amendment grant",
      ),
    });
    const amendedChain = amended.body.autonomous_system_chain;
    const amendedSet = amended.body.active_profile_set;
    const priorSet = eligibility.body.current_active_profile_set;
    ok(
      "M1.5c AMEND: a real-wallet amendment swaps the constitution and profile set at one sequence with operational status unchanged",
      amended.status === 200 &&
        amended.body.sequence === 3 &&
        amendedChain?.constitution_ref === lawfulSuccessor.constitution_id &&
        amendedChain?.constitution_root === constitutionCandidateRoot(lawfulSuccessor) &&
        amendedChain?.latest_sequence === 3 &&
        amendedChain?.status === "active" &&
        amended.body.lifecycle_state?.status === "active" &&
        amended.body.operation_log?.head_entry?.entry_kind ===
          "constitution_amendment" &&
        amendedSet?.schema_version ===
          "ioi.autonomous-system-active-profile-set.v2" &&
        amendedSet?.supersedes_profile_set_ref ===
          priorSet?.active_profile_set_ref &&
        amendedSet?.constitution?.candidate_profile_root ===
          constitutionCandidateRoot(lawfulSuccessor) &&
        amended.body.claims?.constitution_changed === true &&
        amended.body.nonclaims?.status_change === false &&
        familyFiles(dataDir, AMENDMENT_INTENT_FAMILY).length === 0,
      `${amended.status}/${amended.body.error?.code || "ok"} msg=${String(amended.body.error?.message || "").slice(0, 300)} seq=${amended.body.sequence} kind=${amended.body.operation_log?.head_entry?.entry_kind} set=${amendedSet?.schema_version}`,
    );
  } finally {
    if (plane) await plane.stop();
    await resolver.stop();
    rmSync(dataDir, { recursive: true, force: true });
  }
}

async function runSystemActivationJourney() {
  const resolver = await startOwnedWalletResolver();
  const dataDir = createOwnedTempDir("ioi-system-activation-");
  let plane;
  try {
    plane = await startVerifierPlane({ dataDir, env: resolver.env });
    if (!plane) {
      throw new Error("BLOCKED: M1.5a Hypervisor daemon is not built");
    }
    let call = (method, path, body) =>
      jsonCall(plane.daemonUrl, method, path, body);
    const genesisBody = exactGenesisBody(
      "genesis://acme/system-alpha/m1-5a",
    );
    const pinnedDeploymentRevision = lifecycleDeploymentRevisionForGenesis(
      genesisBody.proposed_instantiation.candidate,
    );
    genesisBody.proposed_instantiation.candidate.initial_profile_refs.deployment_profile_ref =
      pinnedDeploymentRevision.deployment_profile_ref;
    const source = await admitGenesis(call, resolver, dataDir, {
      genesisBody,
    });
    const materializePath =
      `${GENESIS_ROUTE}/${source.sourceTail}/sequence-zero-materialization`;
    const materializeRequest = {
      expected_genesis_admission_record_root: source.recordRoot,
      expected_genesis_admission_receipt_root: source.receiptRoot,
    };
    const materializeAuthority = await challengeAndGrant(
      call,
      resolver,
      materializePath,
      materializeRequest,
      MATERIALIZE_SCOPE,
    );
    const materialized = await call("POST", materializePath, {
      ...materializeRequest,
      wallet_approval_grant: requireValue(
        materializeAuthority.grant,
        "M1.5a setup lacks M1.4 grant",
      ),
    });
    requireValue(
      materialized.status === 201,
      `M1.5a setup failed M1.4: ${materialized.status}/${materialized.body.error?.code || "no-code"}`,
    );
    const materialization = requireValue(
      materialized.body.autonomous_system_sequence_zero_materialization,
      "M1.5a setup lacks M1.4 materialization",
    );
    const materializationReceipt = requireValue(
      materialized.body.autonomous_system_sequence_zero_materialization_receipt,
      "M1.5a setup lacks M1.4 receipt",
    );
    const predecessorBytes = familiesSnapshot(
      dataDir,
      [...SOURCE_FAMILIES, ...MATERIALIZATION_FAMILIES],
    );

    const revision = lifecycleDeploymentRevision(source);
    const initializePath = `${GENESIS_ROUTE}/${source.sourceTail}/initialize`;
    const initializeRequest = {
      expected_sequence_zero_materialization_root: artifactHash(
        "ioi.autonomous-system-sequence-zero-materialization-artifact-jcs-sha256.v1",
        materialization,
      ),
      expected_sequence_zero_materialization_receipt_root: artifactHash(
        "ioi.autonomous-system-sequence-zero-materialization-receipt-artifact-jcs-sha256.v1",
        materializationReceipt,
      ),
      deployment_profile_revision: revision,
    };
    const lifecycleBeforeSensitive = familiesSnapshot(dataDir, [
      INITIALIZE_INTENT_FAMILY,
      ACTIVATE_INTENT_FAMILY,
      ...LIFECYCLE_FAMILIES,
    ]);
    const sensitiveSentinel = "m1-5a-never-store";
    const sensitive = await call("POST", initializePath, {
      ...initializeRequest,
      deployment_profile_revision: {
        ...revision,
        operatorPasswordHint: sensitiveSentinel,
      },
    });
    ok(
      "M1.5a INTAKE: embedded sensitive-key aliases refuse before authority with zero lifecycle evidence",
      sensitive.status === 422 &&
        sensitive.body.error?.code ===
          "system_lifecycle_sensitive_field_rejected" &&
        !JSON.stringify(sensitive.body).includes(sensitiveSentinel) &&
        lifecycleBeforeSensitive ===
          familiesSnapshot(dataDir, [
            INITIALIZE_INTENT_FAMILY,
            ACTIVATE_INTENT_FAMILY,
            ...LIFECYCLE_FAMILIES,
          ]),
      `${sensitive.status}/${sensitive.body.error?.code || "no-code"}`,
    );
    const initializeAuthority = await challengeAndGrant(
      call,
      resolver,
      initializePath,
      initializeRequest,
      INITIALIZE_SCOPE,
    );
    const initializeGrant = requireValue(
      initializeAuthority.grant,
      `M1.5a initialize challenge lacks a grant: ${JSON.stringify(initializeAuthority.challenge)} m1.4=${materialization.profile_refs?.deployment_profile_ref} revision=${revision.deployment_profile_ref}`,
    );
    const initializeResponses = await Promise.all(
      Array.from({ length: 12 }, () =>
        call("POST", initializePath, {
          ...initializeRequest,
          wallet_approval_grant: initializeGrant,
        }),
      ),
    );
    const initializeWinners = initializeResponses.filter(
      (response) => response.status === 200,
    );
    const initializeConflicts = initializeResponses.filter(
      (response) => response.status === 409,
    );
    ok(
      "M1.5a INITIALIZE: twelve real-wallet requests linearize to one initialized sequence-one graph",
      initializeWinners.length === 1 &&
        initializeConflicts.length === 11 &&
        initializeConflicts.every(
          (response) =>
            response.body.error?.code === "system_lifecycle_sequence_conflict",
        ) &&
        familyFiles(dataDir, INITIALIZE_INTENT_FAMILY).length === 0,
      `winners=${initializeWinners.length} conflicts=${initializeConflicts.length} responses=${initializeResponses.map((response) => `${response.status}/${response.body.operation || response.body.error?.code || "no-code"}`).join(",")}`,
    );
    requireValue(
      initializeWinners.length === 1,
      `M1.5a initialize did not produce one winner: ${JSON.stringify(initializeResponses)}`,
    );
    const initializeGet = await call("GET", initializePath);
    const initializedState = initializeGet.body.autonomous_system_activation_state;
    const initializedReceipt = initializeGet.body.lifecycle_receipt;
    ok(
      "M1.5a INITIALIZE GET: complete graph is exact and carries no active set or chain",
      initializeGet.status === 200 &&
        initializedState?.sequence === 1 &&
        initializedState?.status === "initialized" &&
        initializedState?.active_profile_set_ref === null &&
        initializedState?.chain_ref === null &&
        initializeGet.body.active_profile_set === null &&
        initializeGet.body.autonomous_system_chain === null,
      `${initializeGet.status}/${initializeGet.body.error?.code || initializedState?.status}`,
    );

    const activatePath = `${GENESIS_ROUTE}/${source.sourceTail}/activate`;
    const activateRequest = {
      expected_initialize_proposal_root:
        initializedReceipt.bound_facts.proposal_root,
      expected_initialize_decision_root:
        initializedReceipt.bound_facts.decision_root,
      expected_initialize_state_root: initializedState.activation_state_root,
      expected_initialize_transition_root: initializedState.transition_root,
      expected_initialize_receipt_root:
        initializedState.transition_receipt_root,
    };
    await plane.stop();
    plane = await startVerifierPlane({
      dataDir,
      env: {
        ...resolver.env,
        IOI_TEST_FORCE_SYSTEM_LIFECYCLE_AFTER_LOCAL_PERSIST:
          "autonomous-system-lifecycle-authority-consumptions",
      },
    });
    if (!plane) {
      throw new Error("BLOCKED: M1.5a fault plane is not built");
    }
    call = (method, path, body) =>
      jsonCall(plane.daemonUrl, method, path, body);
    const activateAuthority = await challengeAndGrant(
      call,
      resolver,
      activatePath,
      activateRequest,
      ACTIVATE_SCOPE,
    );
    const activateGrant = requireValue(
      activateAuthority.grant,
      `M1.5a activate challenge lacks a grant: ${JSON.stringify(activateAuthority.challenge)}`,
    );
    const race = await Promise.all([
      call("POST", initializePath, {
        ...initializeRequest,
        wallet_approval_grant: initializeGrant,
      }),
      call("POST", activatePath, {
        ...activateRequest,
        wallet_approval_grant: activateGrant,
      }),
    ]);
    const competingInitialize = race[0];
    const interruptedActivation = race[1];
    ok(
      "M1.5a ACTIVATE PARTIAL: activation parks after a real wallet use and one local write while the competing lifecycle operation refuses",
      interruptedActivation?.body.error?.code ===
        "system_lifecycle_pending_convergence" &&
        ((competingInitialize?.status === 409 &&
          competingInitialize.body.error?.code ===
            "system_lifecycle_sequence_conflict") ||
          (competingInitialize?.status === 500 &&
            competingInitialize.body.error?.code ===
              "system_lifecycle_pending_convergence")) &&
        familyFiles(dataDir, ACTIVATE_INTENT_FAMILY).length === 1 &&
        familyFiles(
          dataDir,
          "autonomous-system-lifecycle-authority-consumptions",
        ).length === 2 &&
        familyFiles(dataDir, "autonomous-system-activation-states").length ===
          1,
      race.map((response) => `${response.status}/${response.body.operation || response.body.error?.code}`).join(","),
    );

    await plane.stop();
    const [activationIntentName] = familyFiles(
      dataDir,
      ACTIVATE_INTENT_FAMILY,
    );
    const relocatedIntentName = `asaci_${"f".repeat(64)}.json`;
    requireValue(
      activationIntentName && activationIntentName !== relocatedIntentName,
      `M1.5a relocation probe lacks one distinct activation intent: ${activationIntentName}`,
    );
    const activationIntentDir = join(dataDir, ACTIVATE_INTENT_FAMILY);
    renameSync(
      join(activationIntentDir, activationIntentName),
      join(activationIntentDir, relocatedIntentName),
    );
    const relocatedBefore = familiesSnapshot(dataDir, [
      ACTIVATE_INTENT_FAMILY,
      ...LIFECYCLE_FAMILIES,
    ]);
    plane = await startVerifierPlane({ dataDir, env: resolver.env });
    if (!plane) {
      throw new Error("BLOCKED: M1.5a relocated-intent plane is not built");
    }
    call = (method, path, body) =>
      jsonCall(plane.daemonUrl, method, path, body);
    const relocatedRead = await call("GET", activatePath);
    ok(
      "M1.5a INTENT IDENTITY: a relocated sealed activation intent refuses without replay or mutation",
      relocatedRead.status === 500 &&
        relocatedRead.body.error?.code ===
          "system_lifecycle_intent_unreadable" &&
        familyFiles(dataDir, ACTIVATE_INTENT_FAMILY).length === 1 &&
        familyFiles(dataDir, "autonomous-system-activation-states").length ===
          1 &&
        relocatedBefore ===
          familiesSnapshot(dataDir, [
            ACTIVATE_INTENT_FAMILY,
            ...LIFECYCLE_FAMILIES,
          ]),
      `${relocatedRead.status}/${relocatedRead.body.error?.code || "no-code"} intent-count=${familyFiles(dataDir, ACTIVATE_INTENT_FAMILY).length}`,
    );
    await plane.stop();
    renameSync(
      join(activationIntentDir, relocatedIntentName),
      join(activationIntentDir, activationIntentName),
    );
    plane = await startVerifierPlane({ dataDir, env: resolver.env });
    if (!plane) {
      throw new Error("BLOCKED: M1.5a replay plane is not built");
    }
    call = (method, path, body) =>
      jsonCall(plane.daemonUrl, method, path, body);
    const activationIntentCleared = await waitForIntentRecordsToClear(
      dataDir,
      ACTIVATE_INTENT_FAMILY,
    );
    const replayedActivation = await call("GET", activatePath);
    ok(
      "M1.5a ACTIVATE REPLAY: restart reuses the consumed grant and converges exactly one sequence-two graph",
      activationIntentCleared &&
        replayedActivation.status === 200 &&
        replayedActivation.body.autonomous_system_activation_state?.sequence ===
          2 &&
        familyFiles(dataDir, ACTIVATE_INTENT_FAMILY).length === 0,
      `${replayedActivation.status}/${replayedActivation.body.error?.code || replayedActivation.body.autonomous_system_activation_state?.status} intent-cleared=${activationIntentCleared}`,
    );

    const activateGet = await call("GET", activatePath);
    const activeState = activateGet.body.autonomous_system_activation_state;
    const operationLog = activateGet.body.operation_log;
    const chain = activateGet.body.autonomous_system_chain;
    const substrateStatus = await call("GET", "/v1/hypervisor/substrate/status");
    const expectedCounts = new Map([
      ["autonomous-system-deployment-profile-revisions", 1],
      ["autonomous-system-lifecycle-authority-evidence", 2],
      ["autonomous-system-lifecycle-authority-consumptions", 2],
      ["autonomous-system-lifecycle-proposals", 2],
      ["autonomous-system-lifecycle-authority-decisions", 2],
      ["autonomous-system-lifecycle-transitions", 2],
      ["autonomous-system-initialize-transition-receipts", 1],
      ["autonomous-system-activation-receipts", 1],
      ["autonomous-system-activation-states", 2],
      ["autonomous-system-active-profile-sets", 1],
      ["autonomous-system-home-bindings", 1],
      ["autonomous-system-operation-log-revisions", 1],
      ["autonomous-system-chain-revisions", 1],
    ]);
    ok(
      "M1.5a ACTIVATE GET: exact 0/1/2 log and compact non-runtime chain are fully durable",
      activateGet.status === 200 &&
        activeState?.sequence === 2 &&
        activeState?.status === "active" &&
        sameJson(operationLog?.entries?.map((entry) => entry.sequence), [0, 1, 2]) &&
        sameJson(chain?.node_membership_refs, []) &&
        sameJson(chain?.worker_instance_refs, []) &&
        sameJson(chain?.workflow_refs, []) &&
        sameJson(chain?.pending_proposal_refs, []) &&
        chain?.active_writer_epoch === null &&
        chain?.latest_transition_commitment_ref === null &&
        LIFECYCLE_FAMILIES.every(
          (family) =>
            familyFiles(dataDir, family).length === expectedCounts.get(family) &&
            requiredDomainIsNonVacuous(substrateStatus, family),
        ),
      `${activateGet.status}/${activateGet.body.error?.code || activeState?.status}`,
    );
    ok(
      "M1.5a SOURCE: real M1.3/M1.4 bytes remain unchanged across initialize and activate",
      predecessorBytes ===
        familiesSnapshot(dataDir, [...SOURCE_FAMILIES, ...MATERIALIZATION_FAMILIES]),
      `byte-exact=${predecessorBytes === familiesSnapshot(dataDir, [...SOURCE_FAMILIES, ...MATERIALIZATION_FAMILIES])}`,
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

function selectionMayRun(selectedJourneys, requiredJourneys, focusedOptIn) {
  return (
    sameJourneySet(selectedJourneys, requiredJourneys) ||
    focusedOptIn === "1"
  );
}

function certificationSelectionMayRun(
  certificationMode,
  rawSelection,
  focusedOptIn,
) {
  return (
    certificationMode !== "1" ||
    (rawSelection === undefined && focusedOptIn === undefined)
  );
}

async function run() {
  let fatal;
  let requiredJourneys = [];
  let selectedJourneys = [];
  try {
    const scavengerSelfTest = await staleTempScavengerSelfTest();
    ok(
      "TEARDOWN SELF-TEST: stale resources are atomically quarantined and revalidated before recursive removal",
      scavengerSelfTest.pass,
      `removed=${scavengerSelfTest.removed}`,
    );
    ok(
      "FIXTURE SELF-TEST: malformed atomically published readiness kills and reaps the complete owned process group",
      await walletFixtureReadinessCleanupSelfTest(),
    );
    ok(
      "FIXTURE SELF-TEST: the guardian kills its complete fixture group when the exact parent identity dies",
      await walletFixtureGuardianOwnerDeathSelfTest(),
    );
    buildCurrentDaemon();
    ok(
      "BUILD: the verifier compiled the current locked hypervisor-daemon source before runtime journeys",
      true,
      DAEMON_BINARY,
    );
    const routeSource = readFileSync(SYSTEM_SEQUENCE_ZERO_SOURCE, "utf8");
    const verifierSource = readFileSync(VERIFIER_SOURCE, "utf8");
    const productionReceiptBuilder =
      routeSource.match(
        /fn build_receipt\([\s\S]*?\n\}\n\nfn map_commit_failure/u,
      )?.[0] || "";
    const productionIntentCompleter =
      routeSource.match(
        /fn complete_intent_locked\([\s\S]*?\n\}\n\nasync fn consume_wallet_grant/u,
      )?.[0] || "";
    ok(
      "SOURCE: the held verifier is pinned to all four required M1.4 evidence families",
      MATERIALIZATION_FAMILIES.every((family) =>
        routeSource.includes(`"${family}"`),
      ) &&
        MATERIALIZATION_RESPONSE_FIELDS.every(
          (field) => routeSource.split(`"${field}"`).length >= 3,
        ) &&
        routeSource.includes("verify_required_exact") &&
        productionReceiptBuilder.includes("ReceiptVersion::CurrentV2") &&
        !productionReceiptBuilder.includes("ReceiptVersion::LegacyV1") &&
        !productionReceiptBuilder.includes("std::env") &&
        productionIntentCompleter.indexOf(
          "require_legacy_receipt_preexisting",
        ) >= 0 &&
        productionIntentCompleter.indexOf(
          "require_legacy_receipt_preexisting",
        ) < productionIntentCompleter.indexOf("persist_immutable") &&
        verifierSource.includes(LEGACY_RECEIPT_WRITER_COMMIT),
      `families=${MATERIALIZATION_FAMILIES.filter((family) =>
        routeSource.includes(`"${family}"`),
      ).length}/${MATERIALIZATION_FAMILIES.length} current-write-only=${productionReceiptBuilder.includes("ReceiptVersion::CurrentV2") && productionIntentCompleter.includes("require_legacy_receipt_preexisting")}`,
    );
    const journeys = new Map([
      ["constitutional-amendment", runConstitutionalAmendmentJourney],
      ["protected-transition", runProtectedTransitionJourney],
      ["system-activation", runSystemActivationJourney],
      ["primary", runPrimaryJourney],
      ["wallet-replay", runCrashReplayJourney],
      ["partial-prefix-replay", runPartialPrefixReplayJourney],
      ["dependency-ordered-replay", runDependencyOrderedReplayJourney],
      ["unconsumed-revocation", runUnconsumedRevocationJourney],
      ["cross-version-compatibility", runCrossVersionCompatibilityJourney],
      [
        "receipt-version-compatibility",
        runReceiptVersionCompatibilityJourney,
      ],
      ["precondition-cleanup", runPreconditionCleanupJourney],
      ["terminal-intent-durability", runTerminalIntentDurabilityJourney],
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
      "SELF-TEST: substituting async no-ops for every held journey fails certification",
      await noopJourneysRefuseCertification(),
    );
    ok(
      "SELF-TEST: an empty verifier-owned resource ledger cannot satisfy teardown",
      !teardownComplete(new Map(), ["primary"]),
    );
    ok(
      "SELF-TEST: evidence families refuse orphan.bin, .bak, and nonregular residue",
      strictFamilyEnumerationSelfTest(),
    );
    ok(
      "SELF-TEST: exact boundary refs admit the nullable profile lane but refuse omission and stuffing",
      boundaryRefOracleSelfTest(),
    );
    const scrubbedEnv = sanitizeVerifierEnv({
      PATH: "/bin",
      IOI_TEST_FAULT_SENTINEL: "1",
      IOI_HYPERVISOR_GOVERNED_REPLAY_TIMEOUT_MS: "1",
      IOI_WALLET_NETWORK_RPC_ADDR: "http://ambient.invalid",
      [JOURNEY_SELECTOR_ENV]: "primary",
      [FOCUSED_VERIFIER_OPT_IN_ENV]: "1",
      [CERTIFICATION_MODE_ENV]: "1",
    });
    ok(
      "SELF-TEST: child planes inherit no ambient fault, replay, wallet, or selector controls",
      sameJson(scrubbedEnv, { PATH: "/bin" }),
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
    ok(
      "SELECTOR: a focused subset requires the explicit non-certifying opt-in",
      !selectionMayRun(
        ["wallet-replay", "primary"],
        requiredJourneys,
        undefined,
      ) &&
        selectionMayRun(
          ["wallet-replay", "primary"],
          requiredJourneys,
          "1",
        ),
    );
    ok(
      "CERTIFICATION MODE: selectors and focused opt-ins cannot produce a held-bar certificate",
      certificationSelectionMayRun("1", undefined, undefined) &&
        !certificationSelectionMayRun("1", "primary", undefined) &&
        !certificationSelectionMayRun("1", undefined, "1"),
    );
    if (
      !certificationSelectionMayRun(
        process.env[CERTIFICATION_MODE_ENV],
        process.env[JOURNEY_SELECTOR_ENV],
        process.env[FOCUSED_VERIFIER_OPT_IN_ENV],
      )
    ) {
      throw new Error(
        `${CERTIFICATION_MODE_ENV}=1 requires the complete default journey set with no selector or focused opt-in`,
      );
    }
    selectedJourneys = selectJourneys(
      process.env[JOURNEY_SELECTOR_ENV],
      requiredJourneys,
    );
    if (!selectionMayRun(
      selectedJourneys,
      requiredJourneys,
      process.env[FOCUSED_VERIFIER_OPT_IN_ENV],
    )) {
      throw new Error(
        `${FOCUSED_VERIFIER_OPT_IN_ENV}=1 is required to run a non-certifying journey subset`,
      );
    }
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
    teardownComplete(ownedResources, selectedJourneys),
    `owned=${ownedResources.size} removed=${[...ownedResources.keys()].filter((path) => !existsSync(path)).length} process_groups=${ownedProcessGroups.size} descendants_remaining=${[...ownedProcessGroups].filter(([processGroupId, startTimeTicks]) => ownedProcessGroupIdentityIsAlive(processGroupId, startTimeTicks)).length}`,
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
  if (
    sameJourneySet(executedJourneys, requiredJourneys) &&
    process.env[CERTIFICATION_MODE_ENV] === "1"
  ) {
    console.log(
      `system sequence-zero materialization held bar: PASS (journeys=${executedJourneys.join(",")}; real-wallet authority and exact durable evidence verified)`,
    );
  } else if (sameJourneySet(executedJourneys, requiredJourneys)) {
    console.log(
      `system sequence-zero materialization full verifier: PASS (journeys=${executedJourneys.join(",")}; set ${CERTIFICATION_MODE_ENV}=1 for a held-bar certificate)`,
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
