#!/usr/bin/env node

// M4 aggregate done-bar. This runner owns a fresh daemon, product-shell process, wallet.network
// authority fixture, registry, and workspace root. It proves the direct GoalRun activation lane
// first, then compiles the reusable OutcomeRoom package through genesis into one active bounded
// System. A distinct runtime-adjudicated collective GoalRun is attached by exact-head CAS; only
// its real successful invocation candidate may produce the room WorkResult/OutcomeDelta. The public client
// has no generic room-child or graph-write route.

import { createHash } from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import {
  cpSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readlinkSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { get as httpGet } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

import {
  DAEMON_BINARY,
  isIsolatedDaemonLogName,
  sanitizedVerifierBaseEnv,
  startIsolatedPlane,
} from "./lib/isolated-daemon.mjs";
import { startRealWalletNetworkPrincipalAuthorityFixture } from "./lib/wallet-network-principal-authority-fixture.mjs";
import {
  bootstrapActiveSystem,
  exactGenesisBody,
  rebindGenesisBodySystem,
  recomputeReleaseHashes,
} from "./verify-hypervisor-system-sequence-zero-materialization.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, "..", "..", "..");
const SCHEMAS = join(REPO, "docs", "architecture", "_meta", "schemas");
const ROOM_SCHEMA = "ioi.applications.ioi-ai.outcome-room.v2";
const OUTCOME_PACKAGE = "package://ioi/outcome-room";
const SYSTEM_ID = "system://ioi/outcome-room/m4-hosted-proof";
const GENESIS_ID = "genesis://ioi/outcome-room/m4-hosted-proof/genesis";
const CONSTITUTION_REF = "constitution://ioi/outcome-room/m4-hosted-proof/v1";
const LOCAL_OWNER = "user://local-operator";
const DEPLOYMENT_AUTHORITY_REF = "domain://acme-host";
const GOAL_RUN_CREATE_SCOPE = "scope:goal.run.create";
const GOAL_RUN_START_SCOPE = "scope:hypervisor.live-route.session-execute";
const RESULT_REGISTRY_PROJECTION_SCHEMA =
  "ioi.hypervisor.versioned-work-result-registry-projection.v1";
const DELTA_REGISTRY_PROJECTION_SCHEMA =
  "ioi.hypervisor.versioned-outcome-delta-registry-projection.v1";
const RESULT_RECORD_SCHEMAS = ["ioi.foundations.work-result.v3"];
const DELTA_RECORD_SCHEMAS = ["ioi.foundations.outcome-delta.v3"];

const checks = [];
// 90 static check() sites execute as 98 assertions: the five-field runtime-substitution loop and
// the five-surface pending-intent fence loop each contribute four executions beyond their one
// static call site. Any case-count change must update this explanation and the exact done bar.
const EXPECTED_CHECKS = 98;
const CLEAN_BASE_ENV = sanitizedVerifierBaseEnv();
const check = (name, pass, detail = "") =>
  checks.push({ name, pass: Boolean(pass), detail });
const requireValue = (value, message) => {
  if (!value) throw new Error(message);
  return value;
};

function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
    .join(",")}}`;
}

function wireTokenVariants(values) {
  const variants = new Set();
  const htmlAttributeEscape = (value) =>
    value
      .replaceAll("&", "&amp;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#39;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;");
  for (const candidate of values) {
    if (typeof candidate !== "string" || candidate.length === 0) continue;
    const bytes = Buffer.from(candidate, "utf8");
    for (const variant of [
      candidate,
      encodeURIComponent(candidate),
      bytes.toString("base64"),
      bytes.toString("base64url"),
      htmlAttributeEscape(candidate),
      [...candidate].map((character) => `&#${character.codePointAt(0)};`).join(""),
      [...candidate]
        .map((character) => `&#x${character.codePointAt(0).toString(16)};`)
        .join(""),
    ]) {
      if (variant.length > 0) variants.add(variant);
    }
  }
  return [...variants];
}

function responseWireMaterial(response) {
  const payload =
    typeof response?.raw === "string"
      ? response.raw
      : typeof response?.body === "string"
        ? response.body
        : canonicalJson(response?.body ?? null);
  return `${canonicalJson(response?.headers || {})}\n${payload}`;
}

function responseOmitsWireTokens(response, forbiddenTokens) {
  const wire = responseWireMaterial(response);
  return forbiddenTokens.every((token) => !wire.includes(token));
}

function conversationHistoryCarriesAgentText(
  body,
  { chunkId, previousId, blockId, expectedText },
) {
  if (
    !Array.isArray(body?.chunks) ||
    body.chunks.length !== 1 ||
    body?.has_more !== false
  ) {
    return false;
  }
  const chunk = body.chunks[0];
  if (
    chunk?.id !== chunkId ||
    chunk?.previous_id !== previousId ||
    !Array.isArray(chunk?.frames) ||
    chunk.frames.length !== 1
  ) {
    return false;
  }
  const encodedFrame = chunk.frames[0];
  if (
    typeof encodedFrame !== "string" ||
    encodedFrame.length === 0 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(
      encodedFrame,
    )
  ) {
    return false;
  }
  const bytes = Buffer.from(encodedFrame, "base64");
  if (bytes.toString("base64") !== encodedFrame) return false;
  const payload = bytes.subarray(1);
  // The restored product shell's harvested conversation wire uses frame kind 1 for an
  // AgentResponseBlock followed by a protobuf payload. Assert both the exact summary-block id and
  // the durable summary inside that binary payload rather than searching the base64 JSON envelope.
  return bytes.length > 1 &&
    bytes[0] === 1 &&
    payload.includes(Buffer.from(blockId, "utf8")) &&
    payload.includes(Buffer.from(expectedText, "utf8"));
}

function jcsRoot(domain, value) {
  return `sha256:${createHash("sha256")
    .update(canonicalJson({ domain, value }))
    .digest("hex")}`;
}

function systemScopedPayloadRoot(record) {
  const payload = structuredClone(record);
  delete payload.system_binding;
  return jcsRoot("ioi.system-scoped-object-payload-jcs-sha256.v1", payload);
}

function receiptRefBindsRoot(receiptRef, receiptRoot) {
  return typeof receiptRef === "string" &&
    typeof receiptRoot === "string" &&
    /^sha256:[0-9a-f]{64}$/u.test(receiptRoot) &&
    receiptRef.endsWith(`/${receiptRoot.slice("sha256:".length)}`);
}

function canonicalSha256(value) {
  return `sha256:${createHash("sha256").update(canonicalJson(value)).digest("hex")}`;
}

function rootedRuntimeRecordRoot(domain, record, rootField) {
  return canonicalSha256({
    domain,
    record: { ...record, [rootField]: null },
  });
}

function strictFamilyEntries(dataDir, family) {
  const directory = join(dataDir, family);
  try {
    const status = lstatSync(directory);
    if (!status.isDirectory() || status.isSymbolicLink()) {
      throw new Error(`${family} is not a pinned ordinary directory`);
    }
    const entries = readdirSync(directory, { withFileTypes: true });
    const unexpected = entries.filter(
      (entry) => !entry.isFile() || !entry.name.endsWith(".json"),
    );
    if (unexpected.length) {
      throw new Error(
        `${family} contains unexpected entries: ${unexpected
          .map((entry) => entry.name)
          .sort()
          .join(",")}`,
      );
    }
    return entries.sort((left, right) => left.name.localeCompare(right.name));
  } catch (error) {
    if (error?.code === "ENOENT") return [];
    throw new Error(`strict family census failed for ${family}: ${error.message}`);
  }
}

function familyCount(dataDir, family) {
  return strictFamilyEntries(dataDir, family).length;
}

function familyRecords(dataDir, family) {
  return strictFamilyEntries(dataDir, family).map((entry) => {
    const path = join(dataDir, family, entry.name);
    let record;
    try {
      record = JSON.parse(readFileSync(path, "utf8"));
    } catch (error) {
      throw new Error(`strict family record read failed for ${family}/${entry.name}: ${error.message}`);
    }
    if (!record || typeof record !== "object" || Array.isArray(record)) {
      throw new Error(`${family}/${entry.name} is not a JSON object`);
    }
    return record;
  });
}

function installIsolatedJsonFixture(dataDir, family, tail, record) {
  const directory = join(dataDir, family);
  const directoryExisted = existsSync(directory);
  mkdirSync(directory, { recursive: true });
  const path = join(directory, `${tail}.json`);
  const bytes = Buffer.from(`${JSON.stringify(record)}\n`);
  writeFileSync(path, bytes, { flag: "wx" });
  return {
    bytes,
    path,
    cleanup() {
      rmSync(path, { force: true });
      if (
        !directoryExisted &&
        existsSync(directory) &&
        readdirSync(directory).length === 0
      ) {
        rmSync(directory, { recursive: true, force: true });
      }
    },
  };
}

function fileRootOrNull(path) {
  if (!existsSync(path)) return null;
  return `sha256:${createHash("sha256").update(readFileSync(path)).digest("hex")}`;
}

async function expectOwnedRestartRefusal({ dataDir, baseEnv, env, expectedCode }) {
  // Capture startup diagnostics outside the durable tree. The shared isolated-plane helper owns
  // a root-level log file; creating that verifier-only file would legitimately change the data
  // directory's inode timestamps and make an exact failed-recovery no-write proof impossible.
  // Binding port zero lets a valid daemon become healthy without colliding with another process;
  // the bounded timer then identifies and terminates that unexpected success.
  const chunks = [];
  let bytes = 0;
  let outputOversize = false;
  let spawnError = null;
  let timedOut = false;
  const child = spawn(DAEMON_BINARY, [], {
    env: {
      ...baseEnv,
      IOI_HYPERVISOR_DATA_DIR: dataDir,
      IOI_HYPERVISOR_DAEMON_ADDR: "127.0.0.1:0",
      IOI_WALLET_SECRET_PASS:
        baseEnv.IOI_WALLET_SECRET_PASS || "ioi-isolated-verifier-pass",
      ...env,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  const capture = (chunk) => {
    bytes += chunk.length;
    if (bytes > 4 * 1024 * 1024) {
      outputOversize = true;
      child.kill("SIGKILL");
      return;
    }
    chunks.push(chunk);
  };
  child.stdout.on("data", capture);
  child.stderr.on("data", capture);
  child.on("error", (error) => {
    spawnError = error;
  });
  const exit = await new Promise((resolve) => {
    const timeout = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, 10_000);
    child.on("close", (code, signal) => {
      clearTimeout(timeout);
      resolve({ code, signal });
    });
  });
  const logText = Buffer.concat(chunks).toString("utf8");
  const refused =
    spawnError === null &&
    !timedOut &&
    !outputOversize &&
    exit.code !== 0 &&
    logText.includes(expectedCode);
  return {
    expectedCode,
    logText,
    newLogs: ["owned-captured-daemon-output"],
    refused,
    startupError: spawnError
      ? String(spawnError.message || spawnError)
      : timedOut
        ? "unexpectedly_healthy_restart"
        : outputOversize
          ? "restart_diagnostic_output_oversize"
          : exit.code === 0
            ? "unexpected_clean_exit"
            : null,
  };
}

async function expectClonedRestartRefusal({
  sourceDataDir,
  tempPrefix,
  baseEnv,
  env,
  expectedCode,
  install,
}) {
  const root = mkdtempSync(join(tmpdir(), tempPrefix));
  const clonedDataDir = join(root, "data");
  try {
    cpSync(sourceDataDir, clonedDataDir, {
      recursive: true,
      dereference: false,
      preserveTimestamps: true,
      verbatimSymlinks: true,
    });
    const installed = install(clonedDataDir);
    const treeBefore = roomAdmissionSideEffectSnapshot(clonedDataDir);
    const probe = await expectOwnedRestartRefusal({
      dataDir: clonedDataDir,
      baseEnv,
      env,
      expectedCode,
    });
    const treeAfter = roomAdmissionSideEffectSnapshot(clonedDataDir);
    return {
      ...probe,
      installedRetained:
        !installed ||
        (existsSync(installed.path) &&
          readFileSync(installed.path).equals(installed.bytes)),
      treeUnchanged: treeAfter === treeBefore,
    };
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

function buildCurrentDaemonBinary() {
  const result = spawnSync(
    "cargo",
    ["build", "-p", "ioi-node", "--bin", "hypervisor-daemon"],
    {
      cwd: REPO,
      env: {
        ...CLEAN_BASE_ENV,
        CARGO_TERM_COLOR: "never",
        NO_COLOR: "1",
      },
      encoding: "utf8",
      timeout: 45 * 60 * 1000,
      maxBuffer: 8 * 1024 * 1024,
    },
  );
  if (result.error || result.status !== 0) {
    throw new Error(
      `current_daemon_build_failed:${result.error?.message || result.status}\n${result.stdout || ""}\n${result.stderr || ""}`,
    );
  }
  return requireValue(
    fileRootOrNull(DAEMON_BINARY),
    "current_daemon_build_missing_binary",
  );
}

function roomAdmissionSideEffectSnapshot(dataDir) {
  const metadataFields = (metadata, type) => ({
    type,
    inode: String(metadata.ino),
    mode: Number(metadata.mode),
    nlink: String(metadata.nlink),
    mtime_ns: String(metadata.mtimeNs),
    ctime_ns: String(metadata.ctimeNs),
  });
  const rootMetadata = lstatSync(dataDir, { bigint: true });
  const entries = [["", metadataFields(rootMetadata, "directory")]];
  const visit = (directory, prefix = "") => {
    for (const name of readdirSync(directory).sort()) {
      if (!prefix && isIsolatedDaemonLogName(name)) continue;
      const path = join(directory, name);
      const relative = prefix ? `${prefix}/${name}` : name;
      const metadata = lstatSync(path, { bigint: true });
      if (metadata.isSymbolicLink()) {
        entries.push([relative, {
          ...metadataFields(metadata, "symlink"),
          target: readlinkSync(path),
        }]);
      } else if (metadata.isDirectory()) {
        entries.push([relative, metadataFields(metadata, "directory")]);
        visit(path, relative);
      } else if (metadata.isFile()) {
        entries.push([relative, {
          ...metadataFields(metadata, "file"),
          size: String(metadata.size),
          root: fileRootOrNull(path),
        }]);
      } else {
        entries.push([relative, metadataFields(metadata, "non-regular")]);
      }
    }
  };
  visit(dataDir);
  return canonicalJson(entries);
}

// Managed owner-boundary probes include formerly fire-and-forget cache helpers. A response alone
// is not proof that an escaped implementation did not enqueue a delayed write, so observe the
// complete durable tree for a bounded minimum horizon and require three consecutive stable reads
// before recording the post-probe snapshot.
async function quiescentRoomAdmissionSideEffectSnapshot(dataDir) {
  const startedAt = Date.now();
  let previous = roomAdmissionSideEffectSnapshot(dataDir);
  let stableSamples = 0;
  for (let attempt = 0; attempt < 30; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 100));
    const current = roomAdmissionSideEffectSnapshot(dataDir);
    stableSamples = current === previous ? stableSamples + 1 : 0;
    previous = current;
    if (Date.now() - startedAt >= 750 && stableSamples >= 3) return current;
  }
  throw new Error(
    "owner-boundary durable tree did not reach quiescence after asynchronous mutation probes",
  );
}

function durableTruthSnapshot(dataDir, families) {
  return canonicalJson({
    muxlog_root: fileRootOrNull(join(dataDir, "substrate", "muxlog.bin")),
    families: Object.fromEntries(
      [...new Set(families)].sort().map((family) => [
        family,
        {
          present: existsSync(join(dataDir, family)),
          entries: strictFamilyEntries(dataDir, family).map((entry) => {
            const path = join(dataDir, family, entry.name);
            return {
              name: entry.name,
              bytes: lstatSync(path).size,
              root: fileRootOrNull(path),
            };
          }),
        },
      ]),
    ),
  });
}

async function boundedResponseText(response, limit = 4 * 1024 * 1024) {
  const chunks = [];
  let bytes = 0;
  if (!response.body) return "";
  const reader = response.body.getReader();
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    bytes += value.byteLength;
    if (bytes > limit) {
      await reader.cancel("response_oversize").catch(() => {});
      throw new Error(`daemon_response_oversize:${response.url}`);
    }
    chunks.push(Buffer.from(value));
  }
  return Buffer.concat(chunks).toString("utf8");
}

async function request(base, method, path, body, headers = {}) {
  const response = await fetch(`${base}${path}`, {
    method,
    headers: { "content-type": "application/json", ...headers },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(30 * 60 * 1000),
  });
  const raw = await boundedResponseText(response);
  return {
    status: response.status,
    headers: Object.fromEntries(
      [...response.headers.entries()].sort(([left], [right]) =>
        left.localeCompare(right),
      ),
    ),
    raw,
    body: (() => {
      try {
        return JSON.parse(raw);
      } catch {
        return {};
      }
    })(),
  };
}

function readHttpText(url, headers = {}, timeoutMs = 60_000) {
  return new Promise((resolve, reject) => {
    const request = httpGet(
      url,
      { headers: { accept: "text/html", connection: "close", ...headers } },
      (response) => {
        const chunks = [];
        let bytes = 0;
        response.on("data", (chunk) => {
          bytes += chunk.length;
          if (bytes > 4 * 1024 * 1024) {
            response.destroy(
              new Error("product_projection_transport_oversize: exceeded 4 MiB"),
            );
            return;
          }
          chunks.push(chunk);
        });
        response.on("aborted", () =>
          reject(new Error("product_projection_transport_aborted")),
        );
        response.on("error", (error) =>
          reject(
            new Error(
              `product_projection_transport_response_error: ${error.message}`,
            ),
          ),
        );
        response.on("end", () =>
          resolve({
            status: response.statusCode || 0,
            headers: Object.fromEntries(
              Object.entries(response.headers)
                .sort(([left], [right]) => left.localeCompare(right))
                .map(([key, value]) => [
                  key,
                  Array.isArray(value) ? [...value] : String(value ?? ""),
                ]),
            ),
            body: Buffer.concat(chunks).toString("utf8"),
          }),
        );
      },
    );
    request.setTimeout(timeoutMs, () =>
      request.destroy(new Error("product_projection_transport_timeout")),
    );
    request.on("error", (error) =>
      reject(
        String(error?.message || "").startsWith("product_projection_transport_")
          ? error
          : new Error(`product_projection_transport_request_error: ${error.message}`),
      ),
    );
  });
}

// Read one bounded prefix from a deliberately long-lived SSE/NDJSON helper, then cancel the
// transport. Refusal responses remain finite and use readHttpText; this helper exists only to prove
// that the loopback-local success lane still opens and emits its declared wire protocol.
async function readHttpStreamPrefix(url, headers = {}) {
  const response = await fetch(url, {
    headers: { accept: "*/*", ...headers },
    signal: AbortSignal.timeout(60_000),
  });
  const reader = response.body?.getReader();
  let body = "";
  if (reader) {
    const first = await reader.read();
    if (!first.done && first.value) body = Buffer.from(first.value).toString("utf8");
    await reader.cancel("bounded_local_cache_helper_probe").catch(() => {});
  }
  return {
    status: response.status,
    contentType: response.headers.get("content-type") || "",
    body,
  };
}

function runFocusedOutcomeRoomRustTests(filter, failureStem) {
  const args = [
    "test",
    "-p",
    "ioi-node",
    "--bin",
    "hypervisor-daemon",
    filter,
    "--",
    "--test-threads=1",
  ];
  const env = Object.fromEntries(
    Object.entries(process.env).filter(
      ([key]) =>
        !key.startsWith("IOI_TEST_") &&
        !key.startsWith("IOI_HYPERVISOR_") &&
        !key.startsWith("IOI_WALLET_") &&
        !key.startsWith("IOI_WALLET_NETWORK_") &&
        !key.startsWith("NEXTEST_") &&
        !["PORT", "PRODUCT_UI_PORT", "RUST_TEST_THREADS"].includes(key),
    ),
  );
  env.CARGO_TERM_COLOR = "never";
  env.NO_COLOR = "1";
  env.RUST_TEST_THREADS = "1";
  return new Promise((resolve) => {
    const child = spawn("cargo", args, {
      cwd: REPO,
      env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const chunks = [];
    let bytes = 0;
    let failure = null;
    const capture = (chunk) => {
      bytes += chunk.length;
      if (bytes > 4 * 1024 * 1024) {
        failure ||= `${failureStem}_output_oversize`;
        child.kill("SIGKILL");
        return;
      }
      chunks.push(chunk);
    };
    child.stdout.on("data", capture);
    child.stderr.on("data", capture);
    const timeout = setTimeout(() => {
      failure ||= `${failureStem}_timeout`;
      child.kill("SIGKILL");
    }, 5 * 60 * 1000);
    child.on("error", (error) => {
      failure ||= `${failureStem}_spawn_error:${error.message}`;
    });
    child.on("close", (code, signal) => {
      clearTimeout(timeout);
      resolve({
        command: `cargo ${args.join(" ")}`,
        code,
        signal,
        failure,
        output: Buffer.concat(chunks).toString("utf8"),
      });
    });
  });
}

function runDeepChildAdmissionGuardTests() {
  return runFocusedOutcomeRoomRustTests(
    "outcome_room_system_routes::tests::owner_child_admission_refuses_",
    "deep_child_guard_test",
  );
}

function runStableAgentgresRoomCasTests() {
  return runFocusedOutcomeRoomRustTests(
    "substrate_store::tests::outcome_room_system_operation_uses_one_stable_expected_head",
    "stable_agentgres_room_cas_test",
  );
}

function runDeepMembershipDetachGuardTests() {
  return runFocusedOutcomeRoomRustTests(
    "outcome_room_system_routes::tests::membership_detach_",
    "deep_membership_detach_guard_test",
  );
}

function runRuntimeDependencyResolverGuardTests() {
  return runFocusedOutcomeRoomRustTests(
    "goal_run_seam_tests::m4_runtime_dependency_resolvers_refuse_missing_duplicate_and_substituted_truth",
    "runtime_dependency_resolver_guard_test",
  );
}

function runPredecessorChildProfileFenceTests() {
  return runFocusedOutcomeRoomRustTests(
    "predecessor_child_profile_",
    "predecessor_child_profile_fence_test",
  );
}

function m4GenesisBody() {
  let body = exactGenesisBody();
  body.release.package_id = OUTCOME_PACKAGE;
  body.release.manifest_id = `${OUTCOME_PACKAGE}/release/sha256:${"4".repeat(64)}`;
  body.release.display_name = "OutcomeRoom bounded-System package";
  body.release.description =
    "Reusable hosted OutcomeRoom package for the M4 bounded-System proof.";
  body.proposed_instantiation.candidate.package_id = OUTCOME_PACKAGE;
  body.proposed_instantiation.candidate.manifest_ref = body.release.manifest_id;
  body.proposed_instantiation.candidate.instantiation.proposed_by =
    "project://ioi/outcome-room";
  recomputeReleaseHashes(body.release);
  return rebindGenesisBodySystem(body, {
    systemId: SYSTEM_ID,
    genesisId: GENESIS_ID,
    constitutionRef: CONSTITUTION_REF,
    deploymentProfileRef: `deployment-profile://ioi/outcome-room/m4-hosted-proof/local/revision/sha256:${"d".repeat(64)}`,
    orderingProfileRef:
      "ordering-profile://ioi/outcome-room/m4-hosted-proof/hosted",
    oracleProfileRef:
      "oracle-evidence-profile://ioi/outcome-room/m4-hosted-proof/fail-closed",
    lifecycleProfileRef:
      "lifecycle-profile://ioi/outcome-room/m4-hosted-proof/default",
  });
}

function roomRequest(objectiveRef, overrides = {}) {
  return {
    schema_version: ROOM_SCHEMA,
    system_id: SYSTEM_ID,
    owner_or_sponsor_ref: LOCAL_OWNER,
    objective_ref: objectiveRef,
    objective:
      "Produce one bounded, replayable hosted collaboration with adversarial proof.",
    constraint_refs: ["policy://ioi/m4/hosted-only"],
    acceptance_criteria_refs: ["gate://ioi/m4/adversarial-proof"],
    stop_policy_ref: "policy://ioi/m4/stop",
    room_mode: "permissioned_team",
    visibility_policy_ref: "policy://ioi/m4/visibility",
    participation_policy_ref: "policy://ioi/m4/participation",
    privacy_policy_ref: "policy://ioi/m4/privacy",
    contribution_policy_ref: "policy://ioi/m4/contribution",
    cooperation_surplus_policy_ref: "policy://ioi/m4/cooperation-surplus",
    collaboration_terms_refs: ["terms://ioi/m4/hosted"],
    discovery_and_external_admission_policy_refs: [],
    artifact_license_rights_retention_and_export_policy_refs: [
      "policy://ioi/m4/export",
    ],
    coordination_topology: "hosted_admission",
    coordination_policy_ref: "policy://ioi/m4/hosted-admission",
    host_domain_ref: SYSTEM_ID,
    ordering_and_merge_policy_ref: "policy://ioi/m4/order-and-merge",
    conflict_and_failover_policy_ref: "policy://ioi/m4/conflict-and-failover",
    multi_party_collaboration_ref: null,
    ontology_profile_refs: [],
    scorecard_and_guardrail_refs: ["gate://ioi/m4/room-integrity"],
    verifier_path_refs: ["verifier-path://ioi/m4/default"],
    resource_and_budget_refs: ["budget://ioi/m4/bounded"],
    settlement_policy_ref: null,
    ...overrides,
  };
}

function collectivePathRequest() {
  return {
    requested_path: "system_bound",
    goal_run_profile_revision_ref:
      "goal-run-profile://generic-adaptive/revision/m4-hosted-room-v1",
    goal_run_profile_content_hash: `sha256:${"1".repeat(64)}`,
    effective_constraint_hash: `sha256:${"2".repeat(64)}`,
    result_profile: "research",
    policy_refs: ["policy://ioi/m4/hosted-only"],
    authority_refs: ["grant://ioi/m4/local-operator"],
    capability_requirement_refs: [],
  };
}

async function createDirectActivation(base, authorityResolver) {
  const draft = await request(
    base,
    "POST",
    "/v1/goal-orchestration/goal-run-activations",
    {
      schema_version: "ioi.goal-run-activation-draft-request.v1",
      goal_text: "Execute the hosted OutcomeRoom M4 proof journey",
      constraints: ["hosted admission only", "retain negative evidence"],
      project_ref: null,
      result_profile: "research",
      idempotency_key: "m4-outcome-room-system-spine-direct-v1",
    },
  );
  requireValue(draft.status === 201, `activation draft failed ${draft.status}`);
  const tail = String(draft.body.activation.activation_id).replace(
    "goal-run-activation://",
    "",
  );
  const authorityChallenge = await request(
    base,
    "POST",
    `/v1/goal-orchestration/goal-run-activations/${tail}/submit`,
    {
      schema_version: "ioi.goal-run-activation-submit-request.v1",
      expected_activation_hash: draft.body.activation_hash,
      review_decision: "approve",
    },
  );
  requireValue(
    authorityChallenge.status === 403 &&
      authorityChallenge.body.error?.code ===
        "goal_run_activation_authority_required" &&
      authorityChallenge.body.error?.required_scope === GOAL_RUN_CREATE_SCOPE,
    `activation authority challenge failed ${authorityChallenge.status}/${authorityChallenge.body.error?.code}`,
  );
  const approval = authorityChallenge.body.error?.approval;
  const grant = await authorityResolver.mintRecorded(
    DEPLOYMENT_AUTHORITY_REF,
    approval?.policy_hash,
    approval?.request_hash,
    GOAL_RUN_CREATE_SCOPE,
  );
  const submit = await request(
    base,
    "POST",
    `/v1/goal-orchestration/goal-run-activations/${tail}/submit`,
    {
      schema_version: "ioi.goal-run-activation-submit-request.v1",
      expected_activation_hash: draft.body.activation_hash,
      review_decision: "approve",
      wallet_approval_grant: grant,
    },
  );
  const submitErrorDetailKeys = Object.keys(submit.body.error?.details || {})
    .sort()
    .slice(0, 32)
    .map((key) => key.slice(0, 120));
  requireValue(
    submit.status === 201,
    `authorized activation submit failed ${submit.status}/${submit.body.error?.code || "none"}/detail_keys=${submitErrorDetailKeys.join(",")}`,
  );
  return {
    tail,
    authorityChallenge,
    activation: submit.body.activation,
    goalRun: submit.body.goal_run,
  };
}

async function walletAuthorizedPost(call, resolver, path, body, scope) {
  const challenge = await call("POST", path, body);
  const approval = challenge.body.approval || challenge.body.error?.approval;
  requireValue(
    challenge.status === 403 && approval?.policy_hash && approval?.request_hash,
    `authority challenge absent for ${path}: ${challenge.status}/${challenge.body.error?.code || challenge.body.reason}`,
  );
  const grant = await resolver.mintRecorded(
    DEPLOYMENT_AUTHORITY_REF,
    approval.policy_hash,
    approval.request_hash,
    scope,
  );
  const operationToken =
    challenge.body.operation_token ||
    challenge.body.authority_challenge?.operation_token;
  const response = await call("POST", path, {
    ...body,
    ...(operationToken ? { operation_token: operationToken } : {}),
    wallet_approval_grant: grant,
  });
  return { challenge, response };
}

const ajv = new Ajv2020({ allErrors: true, strict: false });
addFormats(ajv);
const validateRoom = ajv.compile(
  JSON.parse(readFileSync(join(SCHEMAS, "outcome-room.v2.schema.json"), "utf8")),
);
const validateGraph = ajv.compile(
  JSON.parse(
    readFileSync(join(SCHEMAS, "collaborative-work-graph.v1.schema.json"), "utf8"),
  ),
);
const validateDiscussion = ajv.compile(
  JSON.parse(
    readFileSync(
      join(SCHEMAS, "outcome-room-discussion-projection.v1.schema.json"),
      "utf8",
    ),
  ),
);

const dataDir = mkdtempSync(join(tmpdir(), "ioi-m4-outcome-room-spine-"));
const sessionsRoot = join(dataDir, "verifier-session-workspaces");
let resolver;
let plane;
let completed = false;
let builtDaemonRoot = null;

try {
  builtDaemonRoot = buildCurrentDaemonBinary();
  console.log(`M4_DAEMON_BINARY_SHA256=${builtDaemonRoot}`);
  resolver = await startRealWalletNetworkPrincipalAuthorityFixture({
    baseEnv: CLEAN_BASE_ENV,
  });
  const basePlaneEnv = {
    ...resolver.env,
    IOI_HYPERVISOR_AUTHORITY_PRINCIPAL_REF: DEPLOYMENT_AUTHORITY_REF,
    IOI_HYPERVISOR_MODEL: "qwen2.5:7b",
    IOI_HYPERVISOR_SESSIONS_ROOT: sessionsRoot,
  };
  plane = await startIsolatedPlane({
    dataDir,
    baseEnv: CLEAN_BASE_ENV,
    env: basePlaneEnv,
    serve: true,
  });
  requireValue(plane, "BLOCKED: build target/debug/hypervisor-daemon first");
  let call = (method, path, body, headers) =>
    request(plane.daemonUrl, method, path, body, headers);

  // 1. The explicit conversation-to-goal crossing is a direct, roomless lane. Ordinary Session
  // submit is proved by its focused runner; this aggregate consumes the explicit activation
  // contract and proves that a room cannot be inferred from it.
  const direct = await createDirectActivation(plane.daemonUrl, resolver);
  const directGoalRunId = requireValue(
    direct.goalRun?.goal_run_id,
    "direct activation omitted goal_run_id",
  );
  check(
    "DIRECT ACTIVATION: explicit review and authority crossing admit the ioi_goal_draft",
    direct.authorityChallenge?.status === 403 &&
      direct.activation?.status === "admitted" &&
      direct.activation?.source_context?.source_kind === "ioi_goal_draft",
    `${direct.authorityChallenge?.status}/${direct.activation?.status}/${direct.activation?.source_context?.source_kind}`,
  );
  check(
    "DIRECT ACTIVATION: admitted GoalRun stays direct and cannot manufacture a room",
    direct.goalRun?.admission_path_status === "direct_non_system" &&
      direct.goalRun?.outcome_room_ref === null &&
      [
        "outcome-room-registry",
        "outcome-room-system-admission-intents",
        "outcome-room-system-receipts",
      ].every((family) => familyCount(dataDir, family) === 0),
    `${direct.goalRun?.admission_path_status}/rooms=${familyCount(dataDir, "outcome-room-registry")}/intents=${familyCount(dataDir, "outcome-room-system-admission-intents")}/receipts=${familyCount(dataDir, "outcome-room-system-receipts")}`,
  );
  await plane.stop();
  plane = await startIsolatedPlane({
    dataDir,
    baseEnv: CLEAN_BASE_ENV,
    env: basePlaneEnv,
    serve: true,
  });
  requireValue(plane, "BLOCKED: direct-lane restart failed");
  call = (method, path, body, headers) =>
    request(plane.daemonUrl, method, path, body, headers);
  const modelRoutes = await call("GET", "/v1/hypervisor/model-routes");
  const seededModelRoute = modelRoutes.body.routes?.find(
    (route) => route.route_id === "mrt_local_default",
  );
  const modelRouteProbe = await call(
    "POST",
    "/v1/hypervisor/model-routes/mrt_local_default/probe",
    {},
  );
  requireValue(
    modelRoutes.status === 200 &&
      seededModelRoute?.model?.model_id === "qwen2.5:7b" &&
      modelRouteProbe.status === 200 &&
      modelRouteProbe.body.availability?.state === "available",
    `BLOCKED: the isolated daemon's real model route is unavailable (${modelRoutes.status}/${seededModelRoute?.model?.model_id}/${modelRouteProbe.status}/${modelRouteProbe.body.availability?.state})`,
  );
  const genericCurrentCreate = await call(
    "POST",
    "/v1/hypervisor/work-results",
    {
      goal_ref: "goal://m4-current-generic-result",
      result_profile: "custom",
      outcome_class: "negative",
      status: "completed",
      uncertainty: {
        source_disposition: "current generic substrate fixture",
      },
      next_action: "none",
    },
  );
  const genericCurrentResult = genericCurrentCreate.body.work_result;
  const genericCurrentWorkResultId = requireValue(
    genericCurrentResult?.work_result_id,
    "BLOCKED: current generic WorkResult fixture was not admitted",
  );
  const genericCurrentBytes = Buffer.from(
    `${JSON.stringify(genericCurrentResult)}\n`,
  );
  const initialVersionedResults = await call(
    "GET",
    "/v1/hypervisor/work-results",
  );
  const directAfterRestart = await call(
    "GET",
    `/v1/goal-orchestration/goal-runs/${directGoalRunId}`,
  );
  check(
    "DIRECT RESTART: reviewed activation reconstructs as the same roomless GoalRun",
    directAfterRestart.status === 200 &&
      directAfterRestart.body.goal_run?.outcome_room_ref === null &&
      directAfterRestart.body.goal_run?.goal_run_id === directGoalRunId &&
      genericCurrentCreate.status === 201 &&
      genericCurrentResult?.schema_version ===
        "ioi.foundations.work-result.v3" &&
      genericCurrentResult?.system_binding === null &&
      initialVersionedResults.status === 200 &&
      initialVersionedResults.body.schema_version ===
        RESULT_REGISTRY_PROJECTION_SCHEMA &&
      canonicalJson(
        initialVersionedResults.body.accepted_record_schema_versions,
      ) === canonicalJson(RESULT_RECORD_SCHEMAS) &&
      canonicalJson(initialVersionedResults.body.record_schema_counts) ===
        canonicalJson({
          "ioi.foundations.work-result.v3": 1,
        }),
    `${directAfterRestart.status}/${directAfterRestart.body.goal_run?.goal_run_id}/generic=${genericCurrentCreate.status}/${genericCurrentResult?.schema_version}/registry=${initialVersionedResults.status}/${canonicalJson(initialVersionedResults.body.record_schema_counts)}`,
  );
  check(
    "DIRECT RESTART: direct GoalRun acquires no result/delta and only the current generic contract is live",
    directAfterRestart.body.goal_run?.work_result_refs?.length === 0 &&
      (directAfterRestart.body.goal_run?.outcome_delta_refs || []).length === 0 &&
      familyCount(dataDir, "work-result-registry") === 1 &&
      familyCount(dataDir, "outcome-delta-registry") === 0 &&
      initialVersionedResults.body.work_results?.every(
        (record) => record.schema_version === "ioi.foundations.work-result.v3",
      ),
    `results=${familyCount(dataDir, "work-result-registry")}/deltas=${familyCount(dataDir, "outcome-delta-registry")}`,
  );

  // 2. Compile the reusable package through the real genesis/System owner before claiming that
  // the System-bound path is available.
  const active = await bootstrapActiveSystem(
    call,
    resolver,
    dataDir,
    m4GenesisBody(),
  );
  check(
    "SYSTEM: package compiles through genesis with exact constitutional coordinates",
    active.chain?.system_id === SYSTEM_ID &&
      active.chain?.package_id === OUTCOME_PACKAGE &&
      active.chain?.genesis_ref === GENESIS_ID &&
      active.chain?.constitution_ref === CONSTITUTION_REF,
    `${active.chain?.system_id}/${active.chain?.package_id}`,
  );
  check(
    "SYSTEM: both admitted chain and materialized bounded-System state are active",
    active.chain?.status === "active" && active.state?.status === "active",
    `${active.chain?.status}/${active.state?.status}`,
  );

  const missingSystemDurableBefore = roomAdmissionSideEffectSnapshot(dataDir);
  const missingSystem = await call(
    "POST",
    "/v1/goal-orchestration/outcome-rooms",
    roomRequest(direct.goalRun.goal_ref, {
      system_id: "system://ioi/outcome-room/not-admitted",
    }),
  );
  const missingSystemDurableAfter = roomAdmissionSideEffectSnapshot(dataDir);
  check(
    "SYSTEM REFUSAL: absent System cannot become a room",
    missingSystem.status === 422 &&
      missingSystem.body.error?.code === "outcome_room_active_system_required" &&
      missingSystemDurableAfter === missingSystemDurableBefore,
    `${missingSystem.status}/${missingSystem.body.error?.code}/durable_unchanged=${missingSystemDurableAfter === missingSystemDurableBefore}`,
  );
  const directRoomDurableBefore = roomAdmissionSideEffectSnapshot(dataDir);
  const directRoom = await call(
    "POST",
    "/v1/goal-orchestration/outcome-rooms",
    roomRequest(direct.goalRun.goal_ref),
  );
  const directRoomDurableAfter = roomAdmissionSideEffectSnapshot(dataDir);
  check(
    "ROOM REFUSAL: the direct GoalRun cannot be silently upgraded into collective truth",
    directRoom.status === 422 &&
      directRoom.body.error?.code === "outcome_room_collective_path_required" &&
      directRoomDurableAfter === directRoomDurableBefore,
    `${directRoom.status}/${directRoom.body.error?.code}/durable_unchanged=${directRoomDurableAfter === directRoomDurableBefore}`,
  );

  // 3. A separate GoalRun is admitted from current live profile/System facts and performs one
  // real harness execution. The second profile is disabled after topology selection so its
  // partial failure remains explicit without widening this proof to M5 collaboration lifecycles.
  for (const profileId of ["hp_opencode", "hp_deepseek_tui"]) {
    const enabled = await call(
      "POST",
      `/v1/hypervisor/harness-profiles/${profileId}/enable`,
      {},
    );
    requireValue(
      enabled.status >= 200 && enabled.status < 300,
      `profile ${profileId} did not enable (${enabled.status})`,
    );
  }
  const sessionRef = "session:m4-bounded-room-runtime";
  const session = await call("POST", "/v1/hypervisor/sessions", {
    session_ref: sessionRef,
  });
  check(
    "RUNTIME SESSION: bounded target workspace is durably provisioned",
    session.status === 202 &&
      session.body.session_ref === sessionRef &&
      seededModelRoute?.route_ref === "model-route:mrt_local_default" &&
      modelRouteProbe.body.availability?.state === "available" &&
      String(session.body.receipt_ref || "").startsWith(
        "receipt://hypervisor/session-provision/",
      ) &&
      String(modelRouteProbe.body.receipt_ref || "").startsWith(
        "agentgres://model-route-receipt/",
      ),
    `${session.status}/${session.body.error?.code}/model=${seededModelRoute?.model?.model_id}/${seededModelRoute?.route_ref}/${modelRouteProbe.body.availability?.state}/session_receipt=${session.body.receipt_ref}/probe_receipt=${modelRouteProbe.body.receipt_ref}`,
  );
  requireValue(session.status === 202, "collective target Session did not provision");
  const goalsBeforeFactSubstitution = familyCount(dataDir, "goal-runs");
  const forgedFacts = {
    single_bounded_work_subject: false,
    requires_system_membership: true,
    requires_shared_frontier: true,
    requires_outcome_room: true,
    requires_collective_scheduling: true,
    capabilities_fit_single_execution: false,
    authority_fits_single_execution: true,
    risk_and_isolation_fit_single_execution: true,
    has_unresolved_system_dependency: false,
    policy_requires_system_path: true,
    system_path_available: true,
  };
  const missingSystemFactDurableBefore =
    roomAdmissionSideEffectSnapshot(dataDir);
  const missingSystemFactClaim = await call(
    "POST",
    "/v1/goal-orchestration/goal-runs",
    {
      goal: "Caller cannot invent a collective System",
      session_ref: sessionRef,
      target_system_id: "system://ioi/outcome-room/not-admitted",
      admission_path_request: {
        ...collectivePathRequest(),
        runtime_facts: forgedFacts,
      },
    },
  );
  const missingSystemFactDurableAfter =
    roomAdmissionSideEffectSnapshot(dataDir);
  const topologyFactDurableBefore = roomAdmissionSideEffectSnapshot(dataDir);
  const topologyFactClaim = await call(
    "POST",
    "/v1/goal-orchestration/goal-runs",
    {
      goal: "Caller cannot downgrade the resolved collective topology",
      session_ref: sessionRef,
      target_system_id: SYSTEM_ID,
      admission_path_request: {
        ...collectivePathRequest(),
        runtime_facts: {
          ...forgedFacts,
          requires_collective_scheduling: false,
        },
      },
    },
  );
  const topologyFactDurableAfter = roomAdmissionSideEffectSnapshot(dataDir);
  check(
    "COLLECTIVE FACT REFUSAL: caller facts cannot invent System availability",
    missingSystemFactClaim.status === 422 &&
      missingSystemFactClaim.body.error?.code ===
        "admission_fact_substitution_refused" &&
      missingSystemFactDurableAfter === missingSystemFactDurableBefore,
    `${missingSystemFactClaim.status}/${missingSystemFactClaim.body.error?.code}/durable_unchanged=${missingSystemFactDurableAfter === missingSystemFactDurableBefore}`,
  );
  check(
    "COLLECTIVE FACT REFUSAL: caller cannot downgrade daemon topology or persist either forged claim",
    topologyFactClaim.status === 422 &&
      topologyFactClaim.body.error?.code ===
        "admission_fact_substitution_refused" &&
      familyCount(dataDir, "goal-runs") === goalsBeforeFactSubstitution &&
      topologyFactDurableAfter === topologyFactDurableBefore,
    `${topologyFactClaim.status}/${topologyFactClaim.body.error?.code}/goals=${familyCount(dataDir, "goal-runs")}/durable_unchanged=${topologyFactDurableAfter === topologyFactDurableBefore}`,
  );
  const collectiveCreate = await call(
    "POST",
    "/v1/goal-orchestration/goal-runs",
    {
      // Keep the expected output canary out of the durable intent text. Otherwise a product
      // projection that correctly renders the GoalRun intent contains the same byte sequence as
      // the result payload and makes the export-leakage assertion a false positive. The runtime
      // still has an exact, deterministic output contract without receiving the canary verbatim.
      goal: "Use the available workspace file tool to create m4-room-load-proof.txt containing, with no trailing newline, the four words bounded, room, load, and proven joined by one ASCII space in that order. Read the file back before returning. Do not report completion unless that exact file exists with exactly the requested four-word ASCII-space sequence",
      session_ref: sessionRef,
      target_system_id: SYSTEM_ID,
      admission_path_request: collectivePathRequest(),
    },
  );
  let collectiveGoal = collectiveCreate.body.goal_run;
  const collectiveGoalRunId = requireValue(
    collectiveGoal?.goal_run_id,
    `collective GoalRun failed ${collectiveCreate.status}/${collectiveCreate.body.error?.code}`,
  );
  check(
    "COLLECTIVE GOAL: daemon admits the local owner on the System-bound path",
    collectiveCreate.status === 201 &&
      collectiveGoal?.owner_ref === LOCAL_OWNER &&
      collectiveGoal?.admission_path_decision?.decision === "system_bound_required",
    `${collectiveCreate.status}/${collectiveGoal?.owner_ref}/${collectiveGoal?.admission_path_decision?.decision}`,
  );
  check(
    "COLLECTIVE GOAL: daemon-resolved facts require an available OutcomeRoom System",
    collectiveGoal?.admission_path_decision?.runtime_facts?.requires_outcome_room === true &&
      collectiveGoal?.admission_path_decision?.runtime_facts?.system_path_available === true &&
      collectiveGoal?.target_system_id === SYSTEM_ID &&
      collectiveGoal?.admission_path_fact_resolution?.resolver ===
        "hypervisor_daemon",
    `${collectiveGoal?.target_system_id}/${collectiveGoal?.admission_path_fact_resolution?.resolver}`,
  );
  check(
    "COLLECTIVE GOAL: resolved package proof and two-role topology are commitment-bound",
      collectiveGoal?.admission_path_fact_resolution?.system_evidence?.package_id ===
        OUTCOME_PACKAGE &&
      String(
        collectiveGoal?.admission_path_fact_resolution?.resolution_root || "",
      ).startsWith("sha256:") &&
      collectiveGoal?.role_topology?.implementer_refs?.length === 2,
    `${collectiveCreate.status}/${collectiveGoal?.admission_path_decision?.decision}`,
  );
  await call(
    "POST",
    "/v1/hypervisor/harness-profiles/hp_deepseek_tui/disable",
    {},
  );
  const started = await walletAuthorizedPost(
    call,
    resolver,
    `/v1/goal-orchestration/goal-runs/${collectiveGoalRunId}/start`,
    {},
    GOAL_RUN_START_SCOPE,
  );
  const invocations = started.response.body.invocations || [];
  const successfulInvocation = invocations.find(
    (invocation) =>
      invocation.status === "waiting_on_conductor" &&
      invocation.implementation_result === undefined &&
      invocation.implementation_result_candidate?.execution_succeeded === true &&
      String(invocation.implementation_result_candidate?.candidate_ref || "").startsWith(
        "implementation-result-candidate://",
      ) &&
      String(invocation.execution_receipt?.id || "").startsWith("receipt://") &&
      invocation.execution_receipt?.exit_status === "success" &&
      invocation.execution_receipt?.exit_code === 0,
  );
  check(
    "RUNTIME LOAD: wallet authority gate precedes an admitted execution",
    started.challenge.status === 403 &&
      started.response.status === 200,
    `${started.challenge.status}/${started.response.status}`,
  );
  check(
    "RUNTIME LOAD: exact two-role census has one receipted execution waiting on its conductor and one explicit failure",
    successfulInvocation &&
      successfulInvocation.work_result_ref == null &&
      successfulInvocation.profile_result_ref == null &&
      successfulInvocation.implementation_result === undefined &&
      invocations.length === 2 &&
      invocations.filter(
        (invocation) => invocation.status === "waiting_on_conductor",
      ).length === 1 &&
      invocations.filter((invocation) => invocation.status === "failed").length === 1 &&
      new Set(invocations.map((invocation) => invocation.harness_invocation_id)).size === 2 &&
      new Set(invocations.map((invocation) => invocation.role_key)).size === 2 &&
      ["implementer_a", "implementer_b"].every((role) =>
        invocations.some((invocation) => invocation.role_key === role),
      ),
    `${started.response.status}/total=${invocations.length}/waiting=${invocations.filter((value) => value.status === "waiting_on_conductor").length}/failed=${invocations.filter((value) => value.status === "failed").length}/roles=${invocations.map((value) => value.role_key).join(",")}`,
  );
  requireValue(
    successfulInvocation,
    "BLOCKED: no real successful waiting-on-conductor invocation exists for the room WorkResult",
  );
  const currentCollective = await call(
    "GET",
    `/v1/goal-orchestration/goal-runs/${collectiveGoalRunId}`,
  );
  collectiveGoal = requireValue(
    currentCollective.body.goal_run,
    "collective GoalRun disappeared after execution",
  );

  // 4. Room creation binds the exact active System and collective GoalRun. Same-body replay is
  // idempotent; changed body, caller-owned System coordinates, and owner substitution fail.
  const requestBody = roomRequest(collectiveGoal.goal_ref);
  const systemCoordinateSubstitutions = [
    ["package_id", "package://substituted/room"],
    ["genesis_ref", "genesis://substituted/room"],
    ["constitution_ref", "constitution://substituted/room"],
    [
      "latest_transition_commitment_ref",
      "commitment://substituted/room/predecessor",
    ],
  ];
  const systemCoordinateSideEffectsBefore =
    roomAdmissionSideEffectSnapshot(dataDir);
  const callerSystemCoordinates = await Promise.all(
    systemCoordinateSubstitutions.map(([field, value]) =>
      call("POST", "/v1/goal-orchestration/outcome-rooms", {
        ...requestBody,
        [field]: value,
      }),
    ),
  );
  const selectedProfileSubstitutionCases = [
    [
      "host-domain owner",
      { host_domain_ref: "domain://ioi/substituted-host" },
      "outcome_room_host_domain_owner_mismatch",
    ],
    [
      "federated topology",
      { coordination_topology: "federated_admission" },
      "outcome_room_federated_admission_unavailable",
    ],
    [
      "cross-org mode",
      { room_mode: "cross_org" },
      "outcome_room_external_participation_unavailable",
    ],
    [
      "open-challenge mode",
      { room_mode: "open_challenge" },
      "outcome_room_external_participation_unavailable",
    ],
    [
      "external discovery",
      {
        discovery_and_external_admission_policy_refs: [
          "aiip://channel/m4-out-of-scope",
        ],
      },
      "outcome_room_external_discovery_unavailable",
    ],
    [
      "multi-party collaboration",
      {
        multi_party_collaboration_ref: "collaboration://m4/out-of-scope",
      },
      "outcome_room_multi_party_collaboration_unavailable",
    ],
    [
      "settlement",
      { settlement_policy_ref: "policy://m4/out-of-scope-settlement" },
      "outcome_room_settlement_unavailable",
    ],
  ];
  const selectedProfileSideEffectsBefore =
    roomAdmissionSideEffectSnapshot(dataDir);
  const selectedProfileSubstitutions = await Promise.all(
    selectedProfileSubstitutionCases.map(([, fields]) =>
      call("POST", "/v1/goal-orchestration/outcome-rooms", {
        ...requestBody,
        ...fields,
      }),
    ),
  );
  const selectedProfileSideEffectsAfter =
    roomAdmissionSideEffectSnapshot(dataDir);
  check(
    "ROOM REFUSAL: caller cannot substitute System coordinates or widen the selected hosted M4 profile",
    callerSystemCoordinates.every(
      (response) =>
        response.status === 422 &&
        response.body.error?.code ===
          "outcome_room_system_binding_plane_owned",
    ) &&
      selectedProfileSubstitutions.every(
        (response, index) =>
          response.status === 422 &&
          response.body.error?.code ===
            selectedProfileSubstitutionCases[index][2],
      ) &&
      selectedProfileSideEffectsAfter === selectedProfileSideEffectsBefore &&
      roomAdmissionSideEffectSnapshot(dataDir) ===
        systemCoordinateSideEffectsBefore,
    `${systemCoordinateSubstitutions
      .map(
        ([field], index) =>
          `${field}=${callerSystemCoordinates[index].status}/${callerSystemCoordinates[index].body.error?.code}`,
      )
      .join(" ")} profile=${selectedProfileSubstitutionCases.map(([name, , code], index) => `${name}=${selectedProfileSubstitutions[index].status}/${selectedProfileSubstitutions[index].body.error?.code}/${code}`).join(" ")}/durable_unchanged=${selectedProfileSideEffectsAfter === selectedProfileSideEffectsBefore}`,
  );
  const wrongOwnerDurableBefore = roomAdmissionSideEffectSnapshot(dataDir);
  const wrongOwner = await call(
    "POST",
    "/v1/goal-orchestration/outcome-rooms",
    roomRequest(collectiveGoal.goal_ref, {
      owner_or_sponsor_ref: "user://another-operator",
    }),
  );
  const wrongOwnerDurableAfter = roomAdmissionSideEffectSnapshot(dataDir);
  check(
    "ROOM REFUSAL: caller cannot substitute the collective GoalRun owner",
    wrongOwner.status === 403 &&
      wrongOwner.body.error?.code === "outcome_room_owner_mismatch" &&
      wrongOwnerDurableAfter === wrongOwnerDurableBefore,
    `${wrongOwner.status}/${wrongOwner.body.error?.code}/durable_unchanged=${wrongOwnerDurableAfter === wrongOwnerDurableBefore}`,
  );
  const collisionTail = `or_${jcsRoot(
    "ioi.outcome-room-system-identity-jcs-sha256.v1",
    { system_id: SYSTEM_ID },
  ).replace("sha256:", "")}`;
  const collisionDirectory = join(dataDir, "outcome-room-registry");
  const collisionPath = join(collisionDirectory, `${collisionTail}.json`);
  const historicalRoomBytes = `${JSON.stringify({
    schema_version: "ioi.applications.ioi-ai.outcome-room.v1",
    outcome_room_id: `outcome-room://${collisionTail}`,
    system_id: SYSTEM_ID,
    historical_predecessor: true,
  })}\n`;
  mkdirSync(collisionDirectory, { recursive: true });
  let predecessorCollision;
  let predecessorBytesPreserved = false;
  let predecessorSideEffectsPreserved = false;
  let collisionFixtureCreated = false;
  try {
    requireValue(
      !existsSync(collisionPath),
      "BLOCKED: deterministic room slot was occupied before the verifier collision fixture",
    );
    writeFileSync(collisionPath, historicalRoomBytes, { flag: "wx" });
    collisionFixtureCreated = true;
    const sideEffectsBefore = roomAdmissionSideEffectSnapshot(dataDir);
    predecessorCollision = await call(
      "POST",
      "/v1/goal-orchestration/outcome-rooms",
      requestBody,
    );
    predecessorBytesPreserved =
      readFileSync(collisionPath, "utf8") === historicalRoomBytes;
    predecessorSideEffectsPreserved =
      roomAdmissionSideEffectSnapshot(dataDir) === sideEffectsBefore;
  } finally {
    if (collisionFixtureCreated) rmSync(collisionPath, { force: true });
  }
  check(
    "ROOM PREDECESSOR COLLISION: historical bytes in the deterministic v2 slot fail closed without overwrite",
    predecessorCollision?.status === 409 &&
      predecessorCollision?.body.error?.code ===
        "outcome_room_system_identity_conflict" &&
      predecessorBytesPreserved &&
      predecessorSideEffectsPreserved,
    `${predecessorCollision?.status}/${predecessorCollision?.body.error?.code}/bytes=${predecessorBytesPreserved}/side_effects=${predecessorSideEffectsPreserved}`,
  );
  const roomTail = collisionTail;
  const roomPath = `/v1/goal-orchestration/outcome-rooms/${roomTail}`;
  const eventPath =
    `/v1/goal-orchestration/goal-runs/${collectiveGoalRunId}/events`;
  const graphPath = `${roomPath}/collaborative-work-graph`;
  const discussionPath = `${roomPath}/discussion-projection`;
  const productPath = `${roomPath}/product-projection`;
  const replayPath = `${roomPath}/replay`;

  // Force the genesis transaction to stop after required Agentgres admission and before the
  // room projection becomes visible. The retained intent must be sufficient for startup to
  // converge the exact same room, operation, and receipt once, after which the original create
  // body is an immutable replay rather than a second genesis.
  await plane.stop();
  plane = await startIsolatedPlane({
    dataDir,
    baseEnv: CLEAN_BASE_ENV,
    env: {
      ...basePlaneEnv,
      IOI_TEST_FORCE_OUTCOME_ROOM_AFTER_AGENTGRES: "1",
    },
    serve: true,
  });
  requireValue(plane, "BLOCKED: room-genesis fault lane did not start");
  call = (method, path, body, headers) =>
    request(plane.daemonUrl, method, path, body, headers);
  const faultedCreate = await call(
    "POST",
    "/v1/goal-orchestration/outcome-rooms",
    requestBody,
  );
  const pendingGenesisIntents = familyRecords(
    dataDir,
    "outcome-room-system-admission-intents",
  );
  const pendingGenesisIntent = pendingGenesisIntents[0];
  const pendingGenesisRoomCount = familyCount(
    dataDir,
    "outcome-room-registry",
  );
  const pendingGenesisReceiptCount = familyCount(
    dataDir,
    "outcome-room-system-receipts",
  );
  const pendingRoomPoint = await call("GET", roomPath);
  requireValue(
    faultedCreate.status === 503 &&
      faultedCreate.body.error?.code ===
        "outcome_room_admission_pending_recovery" &&
      pendingGenesisIntents.length === 1,
    `room-genesis fault did not retain exactly one recoverable intent (${faultedCreate.status}/${faultedCreate.body.error?.code || "none"}/intents=${pendingGenesisIntents.length})`,
  );

  await plane.stop();
  plane = await startIsolatedPlane({
    dataDir,
    baseEnv: CLEAN_BASE_ENV,
    env: basePlaneEnv,
    serve: true,
  });
  requireValue(plane, "BLOCKED: room-genesis recovery lane did not start");
  call = (method, path, body, headers) =>
    request(plane.daemonUrl, method, path, body, headers);
  const recoveredRoomPoint = await call("GET", roomPath);
  const recoveredGenesisReplay = await call("GET", replayPath);
  const recoveredGenesisOperations =
    recoveredGenesisReplay.body.operations?.filter(
      (operation) => operation.operation_kind === "room_genesis",
    ) || [];
  const recoveredGenesisOperation = recoveredGenesisOperations[0];
  const expectedGenesisRequestRoot = jcsRoot(
    "ioi.outcome-room-create-request-jcs-sha256.v1",
    requestBody,
  );
  const pendingGenesisPayloadRoot = jcsRoot(
    "ioi.outcome-room-system-operation-jcs-sha256.v1",
    pendingGenesisIntent?.operation,
  );
  const expectedGenesisOperationRoot = jcsRoot(
    "ioi.agentgres-operation-jcs-sha256.v1",
    {
      domain: `outcome-room-system-operations.${roomTail}`,
      object_ref: `agentgres://outcome-room-system-operations/${roomTail}`,
      op_kind: "outcome_room.room_genesis",
      expected_head: null,
      expected_absent: true,
      payload: pendingGenesisIntent?.operation,
      recorded_at_ms: Date.parse(pendingGenesisIntent?.operation?.at),
      idem_key: `orop_${pendingGenesisPayloadRoot.slice("sha256:".length)}`,
    },
  );
  const recoveredGenesisReceipts = familyRecords(
    dataDir,
    "outcome-room-system-receipts",
  );
  let room = recoveredRoomPoint.body.outcome_room;
  const expectedRecoveredGenesisRoom = {
    ...structuredClone(pendingGenesisIntent?.candidate_room || {}),
    latest_sequence: recoveredGenesisOperation?.sequence,
    latest_transition_commitment_ref:
      recoveredGenesisOperation?.resulting_transition_commitment_ref,
    room_state_root: recoveredGenesisOperation?.resulting_room_state_root,
    room_receipt_root: recoveredGenesisOperation?.receipt_root,
    admission_and_replay_refs: [recoveredGenesisOperation?.receipt_ref],
  };
  const replayedCreateDurableBefore = roomAdmissionSideEffectSnapshot(dataDir);
  const replayedCreate = await call(
    "POST",
    "/v1/goal-orchestration/outcome-rooms",
    requestBody,
  );
  const replayedCreateDurableAfter = roomAdmissionSideEffectSnapshot(dataDir);
  check(
    "ROOM FAULT/RECOVERY: post-Agentgres interruption hides the projection and restart admits the canonical v2 room",
    faultedCreate.status === 503 &&
      faultedCreate.body.error?.code ===
        "outcome_room_admission_pending_recovery" &&
      pendingGenesisRoomCount === 0 &&
      pendingRoomPoint.status === 404 &&
      recoveredRoomPoint.status === 200 &&
      validateRoom(room),
    `fault=${faultedCreate.status}/${faultedCreate.body.error?.code}/pending_rooms=${pendingGenesisRoomCount}/pending_point=${pendingRoomPoint.status}/recovered=${recoveredRoomPoint.status}/${recoveredRoomPoint.body.error?.code || ajv.errorsText(validateRoom.errors)}`,
  );
  check(
    "ROOM: admitted room binds exact System/package/genesis/constitution coordinates",
    room?.system_id === SYSTEM_ID &&
      room?.package_id === OUTCOME_PACKAGE &&
      room?.genesis_ref === GENESIS_ID &&
      room?.constitution_ref === CONSTITUTION_REF,
    `${room?.system_id}/${room?.package_id}/${room?.genesis_ref}`,
  );
  check(
    "ROOM: objective, owner, and initial head bind the collective GoalRun",
    room?.objective_ref === collectiveGoal.goal_ref &&
      room?.owner_or_sponsor_ref === LOCAL_OWNER &&
      room?.latest_sequence === 0,
    `${room?.objective_ref}/${room?.owner_or_sponsor_ref}/seq=${room?.latest_sequence}`,
  );
  requireValue(
    recoveredRoomPoint.status === 200 && room,
    "bounded room did not recover",
  );
  check(
    "AGENTGRES GENESIS RECOVERY: retained intent converges exactly one rooted room, operation, and receipt",
    existsSync(join(dataDir, "substrate", "muxlog.bin")) &&
      pendingGenesisIntents.length === 1 &&
      canonicalJson(pendingGenesisIntent?.request) === canonicalJson(requestBody) &&
      canonicalJson(pendingGenesisIntent?.candidate_room) ===
        canonicalJson(pendingGenesisIntent?.operation?.typed_payload) &&
      pendingGenesisReceiptCount === 0 &&
      recoveredGenesisReplay.status === 200 &&
      recoveredGenesisOperations.length === 1 &&
      recoveredGenesisReceipts.length === 0 &&
      recoveredGenesisOperation?.operation_kind === "room_genesis" &&
      recoveredGenesisOperation?.operation_root ===
        expectedGenesisOperationRoot &&
      pendingGenesisIntent?.operation?.expected_system_predecessor?.chain_root ===
        active.chain.chain_root &&
      pendingGenesisIntent?.operation?.expected_system_predecessor?.state_root ===
        active.chain.latest_state_root &&
      recoveredGenesisOperation?.collective_goal_run_ref ===
        collectiveGoal.goal_ref &&
      recoveredGenesisOperation?.collective_path_decision_ref ===
        collectiveGoal.admission_path_decision?.decision_ref &&
      recoveredGenesisOperation?.request_root === expectedGenesisRequestRoot &&
      String(recoveredGenesisOperation?.receipt_ref || "").startsWith(
        "receipt://agentgres/outcome-room-system/",
      ) &&
      recoveredGenesisOperation?.receipt_root === room?.room_receipt_root &&
      recoveredGenesisOperation?.resulting_room_state_root ===
        room?.room_state_root &&
      canonicalJson(room) === canonicalJson(expectedRecoveredGenesisRoom) &&
      familyCount(dataDir, "outcome-room-registry") === 1 &&
      familyCount(dataDir, "outcome-room-system-admission-intents") === 0,
    `pending_intents=${pendingGenesisIntents.length}/pending_receipts=${pendingGenesisReceiptCount}/recovered_ops=${recoveredGenesisOperations.length}/operation_root=${recoveredGenesisOperation?.operation_root}/${expectedGenesisOperationRoot}/system_roots=${pendingGenesisIntent?.operation?.expected_system_predecessor?.chain_root}/${pendingGenesisIntent?.operation?.expected_system_predecessor?.state_root}/collective=${recoveredGenesisOperation?.collective_goal_run_ref}/${recoveredGenesisOperation?.collective_path_decision_ref}/request=${recoveredGenesisOperation?.request_root}/${expectedGenesisRequestRoot}/recovered_receipts=${recoveredGenesisReceipts.length}/rooms=${familyCount(dataDir, "outcome-room-registry")}/remaining_intents=${familyCount(dataDir, "outcome-room-system-admission-intents")}`,
  );
  const changedCreateDurableBefore = roomAdmissionSideEffectSnapshot(dataDir);
  const changedCreate = await call(
    "POST",
    "/v1/goal-orchestration/outcome-rooms",
    roomRequest(collectiveGoal.goal_ref, {
      objective: "Changed objective under the same deterministic room identity.",
    }),
  );
  const changedCreateDurableAfter = roomAdmissionSideEffectSnapshot(dataDir);
  const canonicalLifecycleDurableBefore =
    roomAdmissionSideEffectSnapshot(dataDir);
  const canonicalLifecycle = await call(
    "POST",
    `/v1/goal-orchestration/outcome-rooms/${roomTail}/lifecycle/transitions`,
    { transition: "pause", expected_revision: room.latest_sequence },
  );
  const canonicalLifecycleDurableAfter =
    roomAdmissionSideEffectSnapshot(dataDir);
  const retiredLifecycleDurableBefore =
    roomAdmissionSideEffectSnapshot(dataDir);
  const retiredLifecycle = await call(
    "POST",
    `/v1/goal-orchestration/outcome-rooms/${roomTail}/transition`,
    { transition: "pause", expected_revision: room.latest_sequence },
  );
  const retiredLifecycleDurableAfter =
    roomAdmissionSideEffectSnapshot(dataDir);
  check(
    "ROOM IDEMPOTENCY: the exact admitted create body replays without a second genesis",
    replayedCreate.status === 200 &&
      replayedCreate.body.replayed === true &&
      replayedCreateDurableAfter === replayedCreateDurableBefore,
    `${replayedCreate.status}/replayed=${replayedCreate.body.replayed}/durable_unchanged=${replayedCreateDurableAfter === replayedCreateDurableBefore}`,
  );
  check(
    "ROOM ROUTE/IDEMPOTENCY REFUSAL: changed create and both lifecycle paths are typed and side-effect free",
    changedCreate.status === 409 &&
      changedCreate.body.error?.code === "outcome_room_create_body_conflict" &&
      changedCreateDurableAfter === changedCreateDurableBefore &&
      canonicalLifecycle.status === 422 &&
      canonicalLifecycle.body.error?.code ===
        "outcome_room_v2_lifecycle_transition_unavailable" &&
      canonicalLifecycleDurableAfter === canonicalLifecycleDurableBefore &&
      retiredLifecycle.status === 410 &&
      retiredLifecycle.body.error?.code ===
        "outcome_room_transition_route_retired" &&
      retiredLifecycleDurableAfter === retiredLifecycleDurableBefore,
    `changed=${changedCreate.status}/${changedCreate.body.error?.code}/canonical=${canonicalLifecycle.status}/${canonicalLifecycle.body.error?.code}/retired=${retiredLifecycle.status}/${retiredLifecycle.body.error?.code}/whole_tree_unchanged=${changedCreateDurableAfter === changedCreateDurableBefore && canonicalLifecycleDurableAfter === canonicalLifecycleDurableBefore && retiredLifecycleDurableAfter === retiredLifecycleDurableBefore}`,
  );

  // 5. Reciprocal membership is an exact dual-head CAS in both directions. Stale, wrong-room,
  // and non-member requests refuse before either side can become visible.
  const goalRoot = jcsRoot(
    "ioi.goal-run-room-membership-predecessor-jcs-sha256.v1",
    collectiveGoal,
  );
  const preAttachDetachSnapshotBefore = roomAdmissionSideEffectSnapshot(dataDir);
  const preAttachDetach = await call(
    "POST",
    `/v1/goal-orchestration/outcome-rooms/${roomTail}/detach-goal-run`,
    {
      goal_run_ref: collectiveGoal.goal_ref,
      expected_revision: room.latest_sequence,
      expected_goal_run_record_root: goalRoot,
    },
  );
  const preAttachDetachSnapshotAfter = roomAdmissionSideEffectSnapshot(dataDir);
  const staleGoalSnapshotBefore = roomAdmissionSideEffectSnapshot(dataDir);
  const staleGoal = await call(
    "POST",
    `/v1/goal-orchestration/outcome-rooms/${roomTail}/attach-goal-run`,
    {
      goal_run_ref: collectiveGoal.goal_ref,
      expected_revision: room.latest_sequence,
      expected_goal_run_record_root: `sha256:${"f".repeat(64)}`,
    },
  );
  const staleGoalSnapshotAfter = roomAdmissionSideEffectSnapshot(dataDir);
  const membershipGoalOracleSnapshotBefore =
    roomAdmissionSideEffectSnapshot(dataDir);
  const membershipExistingNoncollective = await call(
    "POST",
    `/v1/goal-orchestration/outcome-rooms/${roomTail}/attach-goal-run`,
    {
      goal_run_ref: direct.goalRun.goal_ref,
      expected_revision: room.latest_sequence,
      expected_goal_run_record_root: `sha256:${"a".repeat(64)}`,
    },
  );
  const membershipMissingNoncollective = await call(
    "POST",
    `/v1/goal-orchestration/outcome-rooms/${roomTail}/attach-goal-run`,
    {
      goal_run_ref: "goal://gr_m4_missing_membership_oracle",
      expected_revision: room.latest_sequence,
      expected_goal_run_record_root: `sha256:${"a".repeat(64)}`,
    },
  );
  const membershipGoalOracleSnapshotAfter =
    roomAdmissionSideEffectSnapshot(dataDir);
  const inverseAttachRoot = mkdtempSync(
    join(tmpdir(), "ioi-m4-attach-after-roomless-result-"),
  );
  const inverseAttachDataDir = join(inverseAttachRoot, "data");
  let inverseGenericResult;
  let inverseAttach;
  let inverseAttachTreeUnchanged = false;
  let inverseResultRoomless = false;
  try {
    cpSync(dataDir, inverseAttachDataDir, {
      recursive: true,
      dereference: false,
      preserveTimestamps: true,
      verbatimSymlinks: true,
    });
    const inversePlane = await startIsolatedPlane({
      dataDir: inverseAttachDataDir,
      baseEnv: CLEAN_BASE_ENV,
      env: basePlaneEnv,
      serve: false,
    });
    requireValue(inversePlane, "BLOCKED: inverse membership bypass lane did not start");
    try {
      inverseGenericResult = await request(
        inversePlane.daemonUrl,
        "POST",
        "/v1/hypervisor/work-results",
        {
          goal_ref: collectiveGoal.goal_ref,
          result_profile: "research",
          outcome_class: "positive",
          status: "completed",
        },
      );
      const inverseGoal = await request(
        inversePlane.daemonUrl,
        "GET",
        `/v1/goal-orchestration/goal-runs/${collectiveGoalRunId}`,
      );
      const inverseGoalRoot = jcsRoot(
        "ioi.goal-run-room-membership-predecessor-jcs-sha256.v1",
        inverseGoal.body.goal_run,
      );
      inverseResultRoomless =
        inverseGenericResult.body.work_result?.outcome_room_ref == null &&
        inverseGenericResult.body.work_result?.room_admission == null &&
        inverseGenericResult.body.work_result?.system_binding == null;
      const treeBefore = roomAdmissionSideEffectSnapshot(inverseAttachDataDir);
      inverseAttach = await request(
        inversePlane.daemonUrl,
        "POST",
        `/v1/goal-orchestration/outcome-rooms/${roomTail}/attach-goal-run`,
        {
          goal_run_ref: collectiveGoal.goal_ref,
          expected_revision: room.latest_sequence,
          expected_goal_run_record_root: inverseGoalRoot,
        },
      );
      const treeAfter = roomAdmissionSideEffectSnapshot(inverseAttachDataDir);
      inverseAttachTreeUnchanged = treeAfter === treeBefore;
    } finally {
      await inversePlane.stop();
    }
  } finally {
    rmSync(inverseAttachRoot, { recursive: true, force: true });
  }
  const deepMembershipDetachGuardTests =
    await runDeepMembershipDetachGuardTests();
  check(
    "MEMBERSHIP REFUSAL: stale, wrong-room, and non-member guards precede every durable write",
    preAttachDetach.status === 422 &&
      preAttachDetach.body.error?.code === "outcome_room_goal_run_not_member" &&
      preAttachDetachSnapshotAfter === preAttachDetachSnapshotBefore &&
      staleGoal.status === 409 &&
      staleGoal.body.error?.code === "outcome_room_goal_run_head_conflict" &&
      staleGoalSnapshotAfter === staleGoalSnapshotBefore &&
      membershipExistingNoncollective.status === 422 &&
      membershipMissingNoncollective.status === 422 &&
      membershipExistingNoncollective.body.error?.code ===
        "outcome_room_collective_goal_run_required" &&
      membershipMissingNoncollective.body.error?.code ===
        "outcome_room_collective_goal_run_required" &&
      membershipExistingNoncollective.raw === membershipMissingNoncollective.raw &&
      membershipGoalOracleSnapshotAfter ===
        membershipGoalOracleSnapshotBefore &&
      inverseGenericResult?.status === 201 &&
      inverseResultRoomless &&
      inverseAttach?.status === 422 &&
      inverseAttach.body.error?.code ===
        "outcome_room_goal_run_attach_preexisting_work_truth" &&
      inverseAttachTreeUnchanged &&
      deepMembershipDetachGuardTests.code === 0 &&
      deepMembershipDetachGuardTests.failure === null &&
      /test .*membership_detach_guards_wrong_room_and_missing_reciprocity \.\.\. ok/u.test(
        deepMembershipDetachGuardTests.output,
      ) &&
      /1 passed; 0 failed/u.test(deepMembershipDetachGuardTests.output),
    `not_member=${preAttachDetach.status}/${preAttachDetach.body.error?.code}/stale=${staleGoal.status}/${staleGoal.body.error?.code}/oracle=${membershipExistingNoncollective.status}/${membershipExistingNoncollective.body.error?.code}/${membershipMissingNoncollective.status}/${membershipMissingNoncollective.body.error?.code}/oracle_raw_equal=${membershipExistingNoncollective.raw === membershipMissingNoncollective.raw}/oracle_tree=${membershipGoalOracleSnapshotAfter === membershipGoalOracleSnapshotBefore}/inverse=${inverseGenericResult?.status}/${inverseAttach?.status}/${inverseAttach?.body.error?.code}/inverse_roomless=${inverseResultRoomless}/inverse_tree=${inverseAttachTreeUnchanged}/whole_tree_unchanged=${preAttachDetachSnapshotAfter === preAttachDetachSnapshotBefore && staleGoalSnapshotAfter === staleGoalSnapshotBefore}/deep=${deepMembershipDetachGuardTests.code}`,
  );
  const attached = await call(
    "POST",
    `/v1/goal-orchestration/outcome-rooms/${roomTail}/attach-goal-run`,
    {
      goal_run_ref: collectiveGoal.goal_ref,
      expected_revision: room.latest_sequence,
      expected_goal_run_record_root: goalRoot,
    },
  );
  const collectiveAfterAttach = await call(
    "GET",
    `/v1/goal-orchestration/goal-runs/${collectiveGoalRunId}`,
  );
  const attachedGoalRoot = jcsRoot(
    "ioi.goal-run-room-membership-predecessor-jcs-sha256.v1",
    attached.body.goal_run,
  );
  const duplicateAttachSnapshotBefore = roomAdmissionSideEffectSnapshot(dataDir);
  const duplicateAttach = await call(
    "POST",
    `/v1/goal-orchestration/outcome-rooms/${roomTail}/attach-goal-run`,
    {
      goal_run_ref: collectiveGoal.goal_ref,
      expected_revision: attached.body.outcome_room.latest_sequence,
      expected_goal_run_record_root: attachedGoalRoot,
    },
  );
  const duplicateAttachSnapshotAfter = roomAdmissionSideEffectSnapshot(dataDir);

  const staleDetachRoomSnapshotBefore = roomAdmissionSideEffectSnapshot(dataDir);
  const staleDetachRoom = await call(
    "POST",
    `/v1/goal-orchestration/outcome-rooms/${roomTail}/detach-goal-run`,
    {
      goal_run_ref: collectiveGoal.goal_ref,
      expected_revision: 0,
      expected_goal_run_record_root: attachedGoalRoot,
    },
  );
  const staleDetachRoomSnapshotAfter = roomAdmissionSideEffectSnapshot(dataDir);
  const staleDetachGoalSnapshotBefore = roomAdmissionSideEffectSnapshot(dataDir);
  const staleDetachGoal = await call(
    "POST",
    `/v1/goal-orchestration/outcome-rooms/${roomTail}/detach-goal-run`,
    {
      goal_run_ref: collectiveGoal.goal_ref,
      expected_revision: attached.body.outcome_room.latest_sequence,
      expected_goal_run_record_root: `sha256:${"e".repeat(64)}`,
    },
  );
  const staleDetachGoalSnapshotAfter = roomAdmissionSideEffectSnapshot(dataDir);

  await plane.stop();
  const membershipConstructorFaultSourceRoot = mkdtempSync(
    join(tmpdir(), "ioi-m4-membership-after-intent-source-"),
  );
  const membershipConstructorFaultSourceDataDir = join(
    membershipConstructorFaultSourceRoot,
    "data",
  );
  cpSync(dataDir, membershipConstructorFaultSourceDataDir, {
    recursive: true,
    dereference: false,
    preserveTimestamps: true,
    verbatimSymlinks: true,
  });
  plane = await startIsolatedPlane({
    dataDir,
    baseEnv: CLEAN_BASE_ENV,
    env: {
      ...basePlaneEnv,
      IOI_TEST_FORCE_OUTCOME_ROOM_MEMBERSHIP_AFTER_GOAL_RUN: "1",
    },
    serve: true,
  });
  requireValue(plane, "BLOCKED: membership detach fault lane did not start");
  call = (method, path, body, headers) =>
    request(plane.daemonUrl, method, path, body, headers);
  const faultedDetach = await call(
    "POST",
    `/v1/goal-orchestration/outcome-rooms/${roomTail}/detach-goal-run`,
    {
      goal_run_ref: collectiveGoal.goal_ref,
      expected_revision: attached.body.outcome_room.latest_sequence,
      expected_goal_run_record_root: attachedGoalRoot,
    },
  );
  const membershipFencedRoom = await call("GET", roomPath);
  const membershipFencedRoomList = await call(
    "GET",
    "/v1/goal-orchestration/outcome-rooms",
  );
  const membershipFencedGoal = await call(
    "GET",
    `/v1/goal-orchestration/goal-runs/${collectiveGoalRunId}`,
  );
  const membershipFencedGoalList = await call(
    "GET",
    "/v1/goal-orchestration/goal-runs",
  );
  const membershipFencedGraph = await call("GET", graphPath);
  const membershipFencedDiscussion = await call("GET", discussionPath);
  const membershipFencedReplay = await call("GET", replayPath);
  const membershipFencedProduct = await call("GET", productPath);
  const membershipFaultForbidden = wireTokenVariants([
    collectiveGoal.goal_ref,
    attached.body.outcome_room.outcome_room_id,
    attachedGoalRoot,
    '"member_goal_run_refs"',
    '"resulting_goal_run"',
  ]);
  const membershipFencedResponses = [
    membershipFencedRoom,
    membershipFencedRoomList,
    membershipFencedGoal,
    membershipFencedGoalList,
    membershipFencedGraph,
    membershipFencedDiscussion,
    membershipFencedReplay,
    membershipFencedProduct,
  ];
  const pendingMembershipIntentCount = familyCount(
    dataDir,
    "outcome-room-membership-admission-intents",
  );

  await plane.stop();
  const selfConsistentMembershipRecoveryRoot = mkdtempSync(
    join(tmpdir(), "ioi-m4-membership-recovery-room-substitution-"),
  );
  const selfConsistentMembershipRecoveryDataDir = join(
    selfConsistentMembershipRecoveryRoot,
    "data",
  );
  let selfConsistentMembershipRecovery;
  let selfConsistentMembershipRecoveryTreeUnchanged = false;
  let selfConsistentMembershipIntentRetained = false;
  let selfConsistentMembershipBindingSubstituted = false;
  let selfConsistentMembershipRoomSchemaValid = false;
  try {
    let constructorFaultPlane = await startIsolatedPlane({
      dataDir: membershipConstructorFaultSourceDataDir,
      baseEnv: CLEAN_BASE_ENV,
      env: {
        ...basePlaneEnv,
        IOI_TEST_FORCE_OUTCOME_ROOM_MEMBERSHIP_AFTER_INTENT: "1",
      },
      serve: false,
    });
    requireValue(
      constructorFaultPlane,
      "BLOCKED: membership after-intent constructor fault lane did not start",
    );
    let constructorFaultResponse;
    try {
      constructorFaultResponse = await request(
        constructorFaultPlane.daemonUrl,
        "POST",
        `/v1/goal-orchestration/outcome-rooms/${roomTail}/detach-goal-run`,
        {
          goal_run_ref: collectiveGoal.goal_ref,
          expected_revision: attached.body.outcome_room.latest_sequence,
          expected_goal_run_record_root: attachedGoalRoot,
        },
      );
    } finally {
      await constructorFaultPlane.stop();
      constructorFaultPlane = null;
    }
    requireValue(
      constructorFaultResponse.status === 503 &&
        constructorFaultResponse.body.error?.code ===
          "outcome_room_membership_pending_recovery" &&
        familyCount(
          membershipConstructorFaultSourceDataDir,
          "outcome-room-membership-admission-intents",
        ) === 1,
      `BLOCKED: membership after-intent fault did not retain exactly one bounded intent (${constructorFaultResponse.status}/${constructorFaultResponse.body.error?.code})`,
    );
    cpSync(
      membershipConstructorFaultSourceDataDir,
      selfConsistentMembershipRecoveryDataDir,
      {
      recursive: true,
      dereference: false,
      preserveTimestamps: true,
      verbatimSymlinks: true,
      },
    );
    const intentEntry = requireValue(
      strictFamilyEntries(
        selfConsistentMembershipRecoveryDataDir,
        "outcome-room-membership-admission-intents",
      )[0],
      "BLOCKED: pending-membership room-substitution clone has no intent",
    );
    const intentPath = join(
      selfConsistentMembershipRecoveryDataDir,
      "outcome-room-membership-admission-intents",
      intentEntry.name,
    );
    const intent = JSON.parse(readFileSync(intentPath, "utf8"));
    const priorRoom = structuredClone(intent.candidate_room);
    const priorOperation = structuredClone(intent.operation);
    const substitutedRoom = structuredClone(intent.candidate_room);
    substitutedRoom.member_goal_run_refs = [
      ...(substitutedRoom.member_goal_run_refs || []),
      "goal://gr_m4_unrelated_membership_recovery",
    ];
    intent.candidate_room = substitutedRoom;
    const replacementPath = intentPath;
    const replacementBytes = Buffer.from(`${JSON.stringify(intent)}\n`);
    writeFileSync(replacementPath, replacementBytes);
    selfConsistentMembershipRoomSchemaValid = validateRoom(substitutedRoom);
    selfConsistentMembershipBindingSubstituted =
      canonicalJson(substitutedRoom) !== canonicalJson(priorRoom) &&
      canonicalJson(intent.operation) === canonicalJson(priorOperation);
    const treeBefore = roomAdmissionSideEffectSnapshot(
      selfConsistentMembershipRecoveryDataDir,
    );
    selfConsistentMembershipRecovery = await expectOwnedRestartRefusal({
      dataDir: selfConsistentMembershipRecoveryDataDir,
      baseEnv: CLEAN_BASE_ENV,
      env: basePlaneEnv,
      expectedCode: "outcome_room_recovery_invalid",
    });
    const treeAfter = roomAdmissionSideEffectSnapshot(
      selfConsistentMembershipRecoveryDataDir,
    );
    selfConsistentMembershipRecoveryTreeUnchanged = treeAfter === treeBefore;
    selfConsistentMembershipIntentRetained =
      existsSync(replacementPath) &&
      readFileSync(replacementPath).equals(replacementBytes);
  } finally {
    rmSync(selfConsistentMembershipRecoveryRoot, {
      recursive: true,
      force: true,
    });
    rmSync(membershipConstructorFaultSourceRoot, {
      recursive: true,
      force: true,
    });
  }
  const membershipRecoveryFenceBefore = roomAdmissionSideEffectSnapshot(dataDir);
  const malformedMembershipRecovery = await expectClonedRestartRefusal({
    sourceDataDir: dataDir,
    tempPrefix: "ioi-m4-membership-malformed-registry-",
    baseEnv: CLEAN_BASE_ENV,
    env: basePlaneEnv,
    expectedCode: "outcome_room_projection_goal_runs_unreadable",
    install(clonedDataDir) {
      const path = join(
        clonedDataDir,
        "goal-runs",
        "malformed-membership-recovery-sibling.json",
      );
      const bytes = Buffer.from("{not-json");
      writeFileSync(path, bytes, { flag: "wx" });
      return { path, bytes };
    },
  });
  const relocatedMembershipRecovery = await expectClonedRestartRefusal({
    sourceDataDir: dataDir,
    tempPrefix: "ioi-m4-membership-relocated-registry-",
    baseEnv: CLEAN_BASE_ENV,
    env: basePlaneEnv,
    expectedCode: "outcome_room_projection_goal_runs_unreadable",
    install(clonedDataDir) {
      const path = join(
        clonedDataDir,
        "goal-runs",
        "relocated-membership-recovery-sibling.json",
      );
      const bytes = Buffer.from(`${JSON.stringify(direct.goalRun)}\n`);
      writeFileSync(path, bytes, { flag: "wx" });
      return { path, bytes };
    },
  });
  const membershipRecoveryFenceAfter = roomAdmissionSideEffectSnapshot(dataDir);
  plane = await startIsolatedPlane({
    dataDir,
    baseEnv: CLEAN_BASE_ENV,
    env: basePlaneEnv,
    serve: true,
  });
  requireValue(plane, "BLOCKED: membership detach recovery lane did not start");
  call = (method, path, body, headers) =>
    request(plane.daemonUrl, method, path, body, headers);
  const recoveredDetachRoom = await call("GET", roomPath);
  const recoveredDetachGoal = await call(
    "GET",
    `/v1/goal-orchestration/goal-runs/${collectiveGoalRunId}`,
  );
  const recoveredDetachGraph = await call("GET", graphPath);
  const recoveredDetachDiscussion = await call("GET", discussionPath);
  const recoveredDetachReplay = await call("GET", replayPath);
  const recoveredDetachProduct = await call("GET", productPath);
  const membershipRecoveryReceipts = familyRecords(
    dataDir,
    "outcome-room-system-receipts",
  );
  const recoveredDetachOperation = recoveredDetachReplay.body.operations?.find(
    (operation) => operation.operation_kind === "goal_run_membership_detached",
  );
  const detachedGoalRoot = jcsRoot(
    "ioi.goal-run-room-membership-predecessor-jcs-sha256.v1",
    recoveredDetachGoal.body.goal_run,
  );
  const repeatedDetachSnapshotBefore = roomAdmissionSideEffectSnapshot(dataDir);
  const repeatedDetach = await call(
    "POST",
    `/v1/goal-orchestration/outcome-rooms/${roomTail}/detach-goal-run`,
    {
      goal_run_ref: collectiveGoal.goal_ref,
      expected_revision: recoveredDetachRoom.body.outcome_room.latest_sequence,
      expected_goal_run_record_root: detachedGoalRoot,
    },
  );
  const repeatedDetachSnapshotAfter = roomAdmissionSideEffectSnapshot(dataDir);

  const reattached = await call(
    "POST",
    `/v1/goal-orchestration/outcome-rooms/${roomTail}/attach-goal-run`,
    {
      goal_run_ref: collectiveGoal.goal_ref,
      expected_revision: recoveredDetachRoom.body.outcome_room.latest_sequence,
      expected_goal_run_record_root: detachedGoalRoot,
    },
  );
  room = reattached.body.outcome_room;
  const collectiveAfterReattach = await call(
    "GET",
    `/v1/goal-orchestration/goal-runs/${collectiveGoalRunId}`,
  );
  const reattachedGoalRoot = jcsRoot(
    "ioi.goal-run-room-membership-predecessor-jcs-sha256.v1",
    reattached.body.goal_run,
  );
  const membershipReplayAfterReattach = await call("GET", replayPath);
  const attachedOperation = membershipReplayAfterReattach.body.operations?.find(
    (operation) =>
      operation.sequence === 1 &&
      operation.operation_kind === "goal_run_membership_admitted",
  );
  const reattachedOperation =
    membershipReplayAfterReattach.body.operations?.find(
      (operation) =>
        operation.sequence === 3 &&
        operation.operation_kind === "goal_run_membership_admitted",
    );
  check(
    "MEMBERSHIP FAULT/RECOVERY: forced detach fences joined reads, converges both empty heads, then reattaches",
    attached.status === 200 &&
      attached.body.outcome_room?.member_goal_run_refs?.length === 1 &&
      attached.body.outcome_room.member_goal_run_refs[0] ===
        collectiveGoal.goal_ref &&
      collectiveAfterAttach.body.goal_run?.outcome_room_ref ===
        attached.body.outcome_room.outcome_room_id &&
      canonicalJson(collectiveAfterAttach.body.goal_run) ===
        canonicalJson(attached.body.goal_run) &&
      faultedDetach.status === 503 &&
      faultedDetach.body.error?.code ===
        "outcome_room_membership_pending_recovery" &&
      pendingMembershipIntentCount === 1 &&
      [malformedMembershipRecovery, relocatedMembershipRecovery].every(
        (probe) =>
          probe?.refused === true &&
          probe.newLogs.length === 1 &&
          probe.logText.includes(probe.expectedCode) &&
          probe.installedRetained === true &&
          probe.treeUnchanged === true,
      ) &&
      selfConsistentMembershipRecovery?.refused === true &&
      selfConsistentMembershipRecovery.newLogs.length === 1 &&
      selfConsistentMembershipRecovery.logText.includes(
        selfConsistentMembershipRecovery.expectedCode,
      ) &&
      selfConsistentMembershipRoomSchemaValid &&
      selfConsistentMembershipBindingSubstituted &&
      selfConsistentMembershipIntentRetained &&
      selfConsistentMembershipRecoveryTreeUnchanged &&
      membershipRecoveryFenceAfter === membershipRecoveryFenceBefore &&
      membershipFencedResponses.every(
        (response) =>
          response.status === 503 &&
          response.body.error?.code ===
            "outcome_room_mutation_pending_recovery",
      ) &&
      [faultedDetach, ...membershipFencedResponses].every((response) =>
        responseOmitsWireTokens(response, membershipFaultForbidden),
      ) &&
      recoveredDetachRoom.status === 200 &&
      recoveredDetachRoom.body.outcome_room?.member_goal_run_refs?.length === 0 &&
      recoveredDetachGoal.status === 200 &&
      recoveredDetachGoal.body.goal_run?.outcome_room_ref === null &&
      recoveredDetachGraph.status === 200 &&
      recoveredDetachGraph.body.collaborative_work_graph?.member_goal_run_refs
        ?.length === 0 &&
      recoveredDetachGraph.body.collaborative_work_graph
        ?.information_flow_label_refs?.length === 0 &&
      recoveredDetachProduct.status === 200 &&
      recoveredDetachProduct.body.member_goal_runs?.length === 0 &&
      recoveredDetachDiscussion.status === 200 &&
      recoveredDetachDiscussion.body.discussion_projection?.message_refs?.length ===
        0 &&
      recoveredDetachDiscussion.body.discussion_projection
        ?.information_flow_label_refs?.length === 0 &&
      recoveredDetachReplay.status === 200 &&
      reattached.status === 200 &&
      room?.member_goal_run_refs?.length === 1 &&
      room.member_goal_run_refs[0] === collectiveGoal.goal_ref &&
      collectiveAfterReattach.body.goal_run?.outcome_room_ref ===
        room.outcome_room_id &&
      canonicalJson(collectiveAfterReattach.body.goal_run) ===
        canonicalJson(reattached.body.goal_run),
    `attach=${attached.status}/fault=${faultedDetach.status}/${faultedDetach.body.error?.code}/recovery_registry_fences=${[malformedMembershipRecovery, relocatedMembershipRecovery].map((probe) => `${probe?.refused}/${probe?.logText.includes(probe.expectedCode)}/${probe?.newLogs.length}`).join(",")}/self_consistent=${selfConsistentMembershipRecovery?.refused}/${selfConsistentMembershipRecovery?.logText.includes(selfConsistentMembershipRecovery.expectedCode)}/${selfConsistentMembershipRecovery?.newLogs.length}/room_schema=${selfConsistentMembershipRoomSchemaValid}/binding_substituted=${selfConsistentMembershipBindingSubstituted}/intent_retained=${selfConsistentMembershipIntentRetained}/tree=${selfConsistentMembershipRecoveryTreeUnchanged}/whole_tree_unchanged=${membershipRecoveryFenceAfter === membershipRecoveryFenceBefore}/fences=${membershipFencedResponses.map((response) => `${response.status}/${response.body.error?.code}`).join(",")}/recovered=${recoveredDetachRoom.status}/${recoveredDetachGoal.status}/${recoveredDetachGraph.status}/${recoveredDetachDiscussion.status}/${recoveredDetachReplay.status}/${recoveredDetachProduct.status}/reattach=${reattached.status}/room_seq=${room?.latest_sequence}`,
  );
  check(
    "MEMBERSHIP RECOVERY: restart commits one Agentgres detach before the reattach successor",
    attached.body.agentgres_admission?.agentgres_sequence === 1 &&
      attached.body.agentgres_admission?.operation_kind ===
        "outcome_room.goal_run_membership_admitted" &&
      membershipReplayAfterReattach.status === 200 &&
      attachedOperation?.expected_goal_run_record_root === goalRoot &&
      attachedOperation?.resulting_goal_run_record_root === attachedGoalRoot &&
      attached.body.outcome_room?.room_receipt_root ===
        attached.body.agentgres_admission?.admission_root &&
      attached.body.outcome_room?.room_state_root ===
        attached.body.agentgres_admission?.resulting_head &&
      recoveredDetachOperation?.sequence === 2 &&
      recoveredDetachOperation?.operation_kind ===
        "goal_run_membership_detached" &&
      recoveredDetachOperation?.goal_run_ref === collectiveGoal.goal_ref &&
      recoveredDetachOperation?.expected_predecessor_commitment_ref ===
        attached.body.outcome_room?.room_state_root &&
      recoveredDetachOperation?.expected_goal_run_record_root ===
        attachedGoalRoot &&
      recoveredDetachOperation?.resulting_goal_run_record_root ===
        detachedGoalRoot &&
      recoveredDetachRoom.body.outcome_room?.room_receipt_root ===
        recoveredDetachOperation?.receipt_root &&
      recoveredDetachOperation?.resulting_room_state_root ===
        recoveredDetachRoom.body.outcome_room?.room_state_root &&
      String(recoveredDetachOperation?.operation_root || "").startsWith(
        "sha256:",
      ) &&
      String(recoveredDetachOperation?.receipt_ref || "").startsWith(
        "receipt://agentgres/outcome-room-system/",
      ) &&
      recoveredDetachReplay.body.operations?.filter(
        (operation) =>
          operation.operation_kind === "goal_run_membership_detached",
      ).length === 1 &&
      membershipRecoveryReceipts.length === 0 &&
      familyCount(dataDir, "outcome-room-membership-admission-intents") === 0 &&
      reattached.body.agentgres_admission?.agentgres_sequence === 3 &&
      reattached.body.agentgres_admission?.operation_kind ===
        "outcome_room.goal_run_membership_admitted" &&
      reattachedOperation?.expected_goal_run_record_root === detachedGoalRoot &&
      reattachedOperation?.resulting_goal_run_record_root ===
        reattachedGoalRoot &&
      room?.room_receipt_root ===
        reattached.body.agentgres_admission?.admission_root &&
      room?.latest_sequence === 3,
    `attach=${attached.body.agentgres_admission?.agentgres_sequence}/${attached.body.agentgres_admission?.operation_kind}/${attachedOperation?.resulting_goal_run_record_root}/${attachedGoalRoot}/detach=${recoveredDetachOperation?.sequence}/${recoveredDetachOperation?.operation_kind}/detach_ops=${recoveredDetachReplay.body.operations?.filter((operation) => operation.operation_kind === "goal_run_membership_detached").length}/parallel_receipts=${membershipRecoveryReceipts.length}/reattach=${reattached.body.agentgres_admission?.agentgres_sequence}/${reattached.body.agentgres_admission?.operation_kind}/${reattachedOperation?.resulting_goal_run_record_root}/${reattachedGoalRoot}`,
  );
  const staleRoomSnapshotBefore = roomAdmissionSideEffectSnapshot(dataDir);
  const staleRoomAttach = await call(
    "POST",
    `/v1/goal-orchestration/outcome-rooms/${roomTail}/attach-goal-run`,
    {
      goal_run_ref: collectiveGoal.goal_ref,
      expected_revision: 0,
      expected_goal_run_record_root: reattachedGoalRoot,
    },
  );
  const staleRoomSnapshotAfter = roomAdmissionSideEffectSnapshot(dataDir);
  check(
    "MEMBERSHIP REFUSAL: duplicate attach, stale detach heads, repeated detach, and stale attach preserve the whole durable tree",
    duplicateAttach.status === 422 &&
      duplicateAttach.body.error?.code ===
        "outcome_room_goal_run_already_member" &&
      duplicateAttachSnapshotAfter === duplicateAttachSnapshotBefore &&
      staleDetachRoom.status === 409 &&
      staleDetachRoom.body.error?.code === "outcome_room_revision_conflict" &&
      staleDetachRoomSnapshotAfter === staleDetachRoomSnapshotBefore &&
      staleDetachGoal.status === 409 &&
      staleDetachGoal.body.error?.code ===
        "outcome_room_goal_run_head_conflict" &&
      staleDetachGoalSnapshotAfter === staleDetachGoalSnapshotBefore &&
      repeatedDetach.status === 422 &&
      repeatedDetach.body.error?.code === "outcome_room_goal_run_not_member" &&
      repeatedDetachSnapshotAfter === repeatedDetachSnapshotBefore &&
      staleRoomAttach.status === 409 &&
      staleRoomAttach.body.error?.code === "outcome_room_revision_conflict" &&
      staleRoomSnapshotAfter === staleRoomSnapshotBefore,
    `duplicate_attach=${duplicateAttach.status}/${duplicateAttach.body.error?.code}/detach_room=${staleDetachRoom.status}/${staleDetachRoom.body.error?.code}/detach_goal=${staleDetachGoal.status}/${staleDetachGoal.body.error?.code}/repeated=${repeatedDetach.status}/${repeatedDetach.body.error?.code}/stale_attach=${staleRoomAttach.status}/${staleRoomAttach.body.error?.code}/whole_tree_unchanged=${duplicateAttachSnapshotAfter === duplicateAttachSnapshotBefore && staleDetachRoomSnapshotAfter === staleDetachRoomSnapshotBefore && staleDetachGoalSnapshotAfter === staleDetachGoalSnapshotBefore && repeatedDetachSnapshotAfter === repeatedDetachSnapshotBefore && staleRoomSnapshotAfter === staleRoomSnapshotBefore}`,
  );

  // 6. Only owner routes can propose the two M4 child families. A room WorkResult request may
  // name exactly one successful waiting invocation; identity, payload, result/status, evidence, producer,
  // output commitment, and room coordinates are daemon-owned runtime truth.
  const roomResultBody = {
    invocation_or_run_ref: successfulInvocation.harness_invocation_id,
  };
  const childBaseSubstitutionCases = [
    ["room System", { room_admission: { room_system_id: "system://substituted" } }],
    ["room identity", { outcome_room_ref: "outcome-room://substituted" }],
    [
      "predecessor",
      {
        room_admission: {
          expected_predecessor_commitment_ref:
            "commitment://substituted/predecessor",
        },
      },
    ],
    [
      "transition root",
      {
        room_admission: {
          resulting_transition_commitment_ref:
            "commitment://substituted/transition",
        },
      },
    ],
  ];
  const childBaseSideEffectsBefore = roomAdmissionSideEffectSnapshot(dataDir);
  const wrongSystemChildren = await Promise.all(
    childBaseSubstitutionCases.map(([, fields]) =>
      call(
        "POST",
        `/v1/goal-orchestration/goal-runs/${collectiveGoalRunId}/results`,
        { ...roomResultBody, ...fields },
      ),
    ),
  );
  const staleVerdictChild = await call(
    "POST",
    `/v1/goal-orchestration/goal-runs/${collectiveGoalRunId}/results`,
    {
      ...roomResultBody,
      room_admission: {
        admission_decision_ref: "decision://substituted/stale",
        admission_receipt_ref: "receipt://substituted/stale",
      },
    },
  );
  const childBaseSideEffectsAfter = roomAdmissionSideEffectSnapshot(dataDir);
  const deepChildGuardTests = await runDeepChildAdmissionGuardTests();
  const stableAgentgresRoomCasTests = await runStableAgentgresRoomCasTests();
  check(
    "DEEP CHILD BASE REFUSAL: v3 candidates reject caller-owned and wrong-room bindings before publication",
    deepChildGuardTests.code === 0 &&
      deepChildGuardTests.failure === null &&
      /test .*owner_child_admission_refuses_caller_owned_binding_before_publication \.\.\. ok/u.test(
        deepChildGuardTests.output,
      ) &&
      /test .*owner_child_admission_refuses_wrong_system_binding_before_agentgres_read \.\.\. ok/u.test(
        deepChildGuardTests.output,
      ) &&
      stableAgentgresRoomCasTests.code === 0 &&
      stableAgentgresRoomCasTests.failure === null &&
      /test .*outcome_room_system_operation_uses_one_stable_expected_head \.\.\. ok/u.test(
        stableAgentgresRoomCasTests.output,
      ) &&
      /1 passed; 0 failed/u.test(stableAgentgresRoomCasTests.output),
    `child=${deepChildGuardTests.code}/${deepChildGuardTests.signal || "no-signal"}/${deepChildGuardTests.failure || "no-failure"}/agentgres_cas=${stableAgentgresRoomCasTests.code}/${stableAgentgresRoomCasTests.failure || "no-failure"}`,
  );
  check(
    "DEEP CHILD SPINE/LABEL REFUSAL: owner candidates reject a parallel spine and missing-or-empty labels before publication",
    deepChildGuardTests.code === 0 &&
      deepChildGuardTests.failure === null &&
      /test .*owner_child_admission_refuses_parallel_spine_before_publication \.\.\. ok/u.test(
        deepChildGuardTests.output,
      ) &&
      /test .*owner_child_admission_refuses_missing_or_empty_projection_labels_guard_before_publication \.\.\. ok/u.test(
        deepChildGuardTests.output,
      ) &&
      /4 passed; 0 failed/u.test(deepChildGuardTests.output),
    `${deepChildGuardTests.command}/${deepChildGuardTests.code}`,
  );
  const runtimeSubstitutionCases = [
    ["work_result_id", "work-result://substituted"],
    ["result_payload_ref", "artifact://substituted"],
    ["outcome_class", "negative"],
    ["status", "failed"],
    ["produced_by_ref", "worker://substituted"],
  ];
  const runtimeSubstitutionSideEffectsBefore =
    roomAdmissionSideEffectSnapshot(dataDir);
  const runtimeSubstitutions = await Promise.all(
    runtimeSubstitutionCases.map(([field, value]) =>
      call(
        "POST",
        `/v1/goal-orchestration/goal-runs/${collectiveGoalRunId}/results`,
        { ...roomResultBody, [field]: value },
      ),
    ),
  );
  runtimeSubstitutionCases.forEach(([field], index) => {
    const response = runtimeSubstitutions[index];
    check(
      `RUNTIME RESULT REFUSAL: caller cannot author daemon-owned ${field}`,
      response.status === 422 &&
        response.body.error?.code === "work_result_runtime_field_plane_owned",
      `${response.status}/${response.body.error?.code}`,
    );
  });
  const wrongInvocation = await call(
    "POST",
    `/v1/goal-orchestration/goal-runs/${collectiveGoalRunId}/results`,
    { invocation_or_run_ref: "harness-invocation://substituted" },
  );
  const runtimeSubstitutionSideEffectsAfter =
    roomAdmissionSideEffectSnapshot(dataDir);
  const completedChangedFiles =
    successfulInvocation.execution_receipt?.files_written;
  const targetOutputOccurrences = Array.isArray(completedChangedFiles)
    ? completedChangedFiles.filter(
        (file) => file === "m4-room-load-proof.txt",
      ).length
    : 0;
  const completedOutputRel = requireValue(
    Array.isArray(completedChangedFiles) &&
      targetOutputOccurrences === 1
      ? "m4-room-load-proof.txt"
      : null,
    "BLOCKED: successful invocation receipt did not declare m4-room-load-proof.txt exactly once",
  );
  const completedOutputPath = join(
    successfulInvocation.candidate_workspace_root,
    completedOutputRel,
  );
  const completedOutputBytes = readFileSync(completedOutputPath);
  const expectedCompletedOutputBytes = Buffer.from(
    "bounded room load proven",
    "utf8",
  );
  const invocationReceipt = successfulInvocation.execution_receipt;
  const receiptOutputFacts = invocationReceipt?.output_file_facts;
  const receiptOutputFiles = Array.isArray(receiptOutputFacts?.files)
    ? receiptOutputFacts.files
    : [];
  const targetOutputFacts = receiptOutputFiles.filter(
    (fact) => fact?.relative_path === completedOutputRel,
  );
  const targetOutputFact = targetOutputFacts[0];
  const expectedCompletedOutputHash =
    "sha256:0574f58eca67ea2b257c1e263ff00dfb4aa5c4814bd96dc5ea9c4a533aeef847";
  const receiptFileSetClosed =
    Array.isArray(completedChangedFiles) &&
    receiptOutputFiles.length === completedChangedFiles.length &&
    canonicalJson(receiptOutputFiles.map((fact) => fact.relative_path).sort()) ===
      canonicalJson([...completedChangedFiles].sort());
  const invocationReceiptRootReproduces =
    invocationReceipt?.receipt_root ===
    rootedRuntimeRecordRoot(
      "ioi.goal-run-invocation-receipt-jcs-sha256.v1",
      invocationReceipt,
      "receipt_root",
    );
  const invocationOutputFactsHashReproduces =
    invocationReceipt?.output_file_facts_hash ===
    canonicalSha256(receiptOutputFacts);
  const completedOutputText = requireValue(
    completedOutputBytes.toString("utf8"),
    "BLOCKED: successful invocation target output is not a non-empty text proof",
  );
  let outputByteSubstitution;
  let outputByteSubstitutionTreeUnchanged = false;
  try {
    writeFileSync(
      completedOutputPath,
      Buffer.concat([completedOutputBytes, Buffer.from("\nsubstituted-after-receipt\n")]),
    );
    const treeBefore = roomAdmissionSideEffectSnapshot(dataDir);
    outputByteSubstitution = await call(
      "POST",
      `/v1/goal-orchestration/goal-runs/${collectiveGoalRunId}/results`,
      roomResultBody,
    );
    outputByteSubstitutionTreeUnchanged =
      roomAdmissionSideEffectSnapshot(dataDir) === treeBefore;
  } finally {
    writeFileSync(completedOutputPath, completedOutputBytes);
  }
  const preflightResultRegistryDirectory = join(
    dataDir,
    "work-result-registry",
  );
  const malformedOwnerPreflightPath = join(
    preflightResultRegistryDirectory,
    "malformed-owner-preflight.json",
  );
  let malformedOwnerPreflightTreeUnchanged = false;
  const malformedOwnerPreflight = await (async () => {
    try {
      writeFileSync(malformedOwnerPreflightPath, Buffer.from("{not-json"), {
        flag: "wx",
      });
      const treeBefore = roomAdmissionSideEffectSnapshot(dataDir);
      const response = await call(
        "POST",
        `/v1/goal-orchestration/goal-runs/${collectiveGoalRunId}/results`,
        roomResultBody,
      );
      malformedOwnerPreflightTreeUnchanged =
        roomAdmissionSideEffectSnapshot(dataDir) === treeBefore;
      return response;
    } finally {
      rmSync(malformedOwnerPreflightPath, { force: true });
    }
  })();
  const relocatedOwnerPreflightPath = join(
    preflightResultRegistryDirectory,
    "relocated-owner-preflight.json",
  );
  let relocatedOwnerPreflightTreeUnchanged = false;
  const relocatedOwnerPreflight = await (async () => {
    try {
      writeFileSync(relocatedOwnerPreflightPath, genericCurrentBytes, {
        flag: "wx",
      });
      const treeBefore = roomAdmissionSideEffectSnapshot(dataDir);
      const response = await call(
        "POST",
        `/v1/goal-orchestration/goal-runs/${collectiveGoalRunId}/results`,
        roomResultBody,
      );
      relocatedOwnerPreflightTreeUnchanged =
        roomAdmissionSideEffectSnapshot(dataDir) === treeBefore;
      return response;
    } finally {
      rmSync(relocatedOwnerPreflightPath, { force: true });
    }
  })();
  const nonRecordGoalRunPath = join(
    dataDir,
    "goal-runs",
    "projection-shadow",
  );
  let nonRecordGoalRunProjection;
  let nonRecordGoalRunMutation;
  let nonRecordGoalRunTreeUnchanged = false;
  try {
    writeFileSync(nonRecordGoalRunPath, Buffer.from("shadow bytes"), {
      flag: "wx",
    });
    const treeBefore = roomAdmissionSideEffectSnapshot(dataDir);
    nonRecordGoalRunProjection = await call("GET", graphPath);
    nonRecordGoalRunMutation = await call(
      "POST",
      `/v1/goal-orchestration/outcome-rooms/${roomTail}/detach-goal-run`,
      {
        goal_run_ref: collectiveGoal.goal_ref,
        expected_revision: room.latest_sequence,
        expected_goal_run_record_root: reattachedGoalRoot,
      },
    );
    nonRecordGoalRunTreeUnchanged =
      roomAdmissionSideEffectSnapshot(dataDir) === treeBefore;
  } finally {
    rmSync(nonRecordGoalRunPath, { force: true });
  }
  check(
    "RUNTIME RESULT REFUSAL: an unrelated invocation cannot supply WorkResult truth",
    wrongInvocation.status === 409 &&
      wrongInvocation.body.error?.code === "work_result_runtime_truth_unresolved",
    `${wrongInvocation.status}/${wrongInvocation.body.error?.code}`,
  );
  check(
    "RUNTIME RESULT REFUSAL: exact goal bytes are sealed and post-receipt substitution is detected",
    targetOutputOccurrences === 1 &&
      targetOutputFacts.length === 1 &&
      targetOutputFact?.bytes === 24 &&
      targetOutputFact?.sha256 === expectedCompletedOutputHash &&
      receiptFileSetClosed &&
      invocationReceiptRootReproduces &&
      invocationOutputFactsHashReproduces &&
      completedOutputBytes.equals(expectedCompletedOutputBytes) &&
      `sha256:${createHash("sha256").update(completedOutputBytes).digest("hex")}` ===
        expectedCompletedOutputHash &&
      outputByteSubstitution?.status === 409 &&
      outputByteSubstitution?.body.error?.code ===
        "work_result_output_truth_diverged" &&
      outputByteSubstitutionTreeUnchanged,
    `files=${JSON.stringify(completedChangedFiles)}/target_facts=${targetOutputFacts.length}/${targetOutputFact?.bytes}/${targetOutputFact?.sha256}/closed=${receiptFileSetClosed}/receipt_root=${invocationReceiptRootReproduces}/facts_root=${invocationOutputFactsHashReproduces}/exact=${completedOutputBytes.equals(expectedCompletedOutputBytes)}/${outputByteSubstitution?.status}/${outputByteSubstitution?.body.error?.code}/whole_tree_unchanged=${outputByteSubstitutionTreeUnchanged}`,
  );
  check(
    "RUNTIME RESULT REFUSAL: strict owner/GoalRun preflights and all substitutions leave durable truth unchanged",
    wrongSystemChildren.every(
      (response) =>
        response.status === 422 &&
        response.body.error?.code === "work_result_runtime_field_plane_owned",
    ) &&
      staleVerdictChild.status === 422 &&
      staleVerdictChild.body.error?.code === "work_result_runtime_field_plane_owned" &&
      malformedOwnerPreflight.status === 503 &&
      malformedOwnerPreflight.body.error?.code ===
        "outcome_room_owner_publication_registry_unreadable" &&
      relocatedOwnerPreflight.status === 503 &&
      relocatedOwnerPreflight.body.error?.code ===
        "outcome_room_owner_publication_registry_unreadable" &&
      nonRecordGoalRunProjection.status === 503 &&
      nonRecordGoalRunProjection.body.error?.code ===
        "outcome_room_projection_goal_runs_unreadable" &&
      nonRecordGoalRunMutation.status === 503 &&
      nonRecordGoalRunMutation.body.error?.code ===
        "outcome_room_projection_goal_runs_unreadable" &&
      childBaseSideEffectsAfter === childBaseSideEffectsBefore &&
      runtimeSubstitutionSideEffectsAfter ===
        runtimeSubstitutionSideEffectsBefore &&
      malformedOwnerPreflightTreeUnchanged &&
      relocatedOwnerPreflightTreeUnchanged &&
      nonRecordGoalRunTreeUnchanged &&
      familyCount(dataDir, "work-result-registry") === 1,
    `closed-selector=${childBaseSubstitutionCases
      .map(
        ([name], index) =>
          `${name}=${wrongSystemChildren[index].status}/${wrongSystemChildren[index].body.error?.code}`,
      )
      .join(" ")} stale=${staleVerdictChild.status}/${staleVerdictChild.body.error?.code} malformed_preflight=${malformedOwnerPreflight.status}/${malformedOwnerPreflight.body.error?.code}/${malformedOwnerPreflightTreeUnchanged} relocated_preflight=${relocatedOwnerPreflight.status}/${relocatedOwnerPreflight.body.error?.code}/${relocatedOwnerPreflightTreeUnchanged} non_record_goal_run=${nonRecordGoalRunProjection.status}/${nonRecordGoalRunProjection.body.error?.code}/${nonRecordGoalRunMutation.status}/${nonRecordGoalRunMutation.body.error?.code}/${nonRecordGoalRunTreeUnchanged} child_tree=${childBaseSideEffectsAfter === childBaseSideEffectsBefore}/runtime_tree=${runtimeSubstitutionSideEffectsAfter === runtimeSubstitutionSideEffectsBefore} results=${familyCount(dataDir, "work-result-registry")}`,
  );
  const rawAdmission = await call(
    "POST",
    `/v1/goal-orchestration/outcome-rooms/${roomTail}/admission-proposals`,
    { object_contract_id: "schema://ioi/foundations/work-result/v3" },
  );
  check(
    "CHILD REFUSAL: no public generic room-child admission route exists",
    rawAdmission.status === 404,
    String(rawAdmission.status),
  );
  const genericBypassDurableBefore = roomAdmissionSideEffectSnapshot(dataDir);
  const genericResultBypass = await call(
    "POST",
    "/v1/hypervisor/work-results",
    {
      goal_ref: collectiveGoal.goal_ref,
      outcome_room_ref: room.outcome_room_id,
    },
  );
  const genericDeltaBypass = await call(
    "POST",
    "/v1/hypervisor/outcome-deltas",
    {
      goal_ref: collectiveGoal.goal_ref,
      outcome_room_ref: room.outcome_room_id,
    },
  );
  const genericRoomlessResultBypass = await call(
    "POST",
    "/v1/hypervisor/work-results",
    {
      goal_ref: collectiveGoal.goal_ref,
      result_profile: "research",
      outcome_class: "positive",
      status: "completed",
    },
  );
  const genericRoomlessDeltaBypass = await call(
    "POST",
    "/v1/hypervisor/outcome-deltas",
    {
      goal_ref: collectiveGoal.goal_ref,
      delta_kind: "update",
      target_ref: "frontier://m4-generic-room-member-bypass",
      proposed_by_ref: "work-result://m4/generic-room-member-bypass",
    },
  );
  const genericBypassDurableAfter = roomAdmissionSideEffectSnapshot(dataDir);
  check(
    "CHILD REFUSAL: generic result/delta routes cannot persist room-associated truth outside the private v2 seam",
    genericResultBypass.status === 422 &&
      genericResultBypass.body.error?.code ===
        "generic_work_result_room_binding_refused" &&
      genericDeltaBypass.status === 422 &&
      genericDeltaBypass.body.error?.code ===
        "generic_outcome_delta_room_binding_refused" &&
      genericRoomlessResultBypass.status === 422 &&
      genericRoomlessResultBypass.body.error?.code ===
        "generic_work_truth_room_member_goal_refused" &&
      genericRoomlessDeltaBypass.status === 422 &&
      genericRoomlessDeltaBypass.body.error?.code ===
        "generic_work_truth_room_member_goal_refused" &&
      genericBypassDurableAfter === genericBypassDurableBefore,
    `${genericResultBypass.status}/${genericResultBypass.body.error?.code}/${genericDeltaBypass.status}/${genericDeltaBypass.body.error?.code}/roomless=${genericRoomlessResultBypass.status}/${genericRoomlessResultBypass.body.error?.code}/${genericRoomlessDeltaBypass.status}/${genericRoomlessDeltaBypass.body.error?.code}/durable_unchanged=${genericBypassDurableAfter === genericBypassDurableBefore}`,
  );
  // Interrupt after every runtime dependency is durable but before the room successor is reserved.
  // The child intent must already cover every side effect; every joined read fences, and startup
  // replays only those retained bytes before stamping WorkResult <-> HarnessInvocation.
  const preResultFaultRevision = room.latest_sequence;
  await plane.stop();
  const childConstructorFaultSourceRoot = mkdtempSync(
    join(tmpdir(), "ioi-m4-child-after-intent-source-"),
  );
  const childConstructorFaultSourceDataDir = join(
    childConstructorFaultSourceRoot,
    "data",
  );
  cpSync(dataDir, childConstructorFaultSourceDataDir, {
    recursive: true,
    dereference: false,
    preserveTimestamps: true,
    verbatimSymlinks: true,
  });
  // This independent clone retains invocation records whose sealed output coordinates are
  // absolute paths into the original verifier-owned data directory. Exercise and retain the
  // after-intent interruption while those exact output bytes still exist. Later recovery tests
  // deliberately remove the original output; deferring this request until after that removal
  // would test an unreadable input fixture rather than the child-intent constructor boundary.
  let constructorFaultPlane = await startIsolatedPlane({
    dataDir: childConstructorFaultSourceDataDir,
    baseEnv: CLEAN_BASE_ENV,
    env: {
      ...basePlaneEnv,
      IOI_TEST_FORCE_OUTCOME_ROOM_CHILD_AFTER_INTENT: "1",
    },
    serve: false,
  });
  requireValue(
    constructorFaultPlane,
    "BLOCKED: child after-intent constructor fault lane did not start",
  );
  let constructorFaultResponse;
  try {
    constructorFaultResponse = await request(
      constructorFaultPlane.daemonUrl,
      "POST",
      `/v1/goal-orchestration/goal-runs/${collectiveGoalRunId}/results`,
      roomResultBody,
    );
  } finally {
    await constructorFaultPlane.stop();
    constructorFaultPlane = null;
  }
  requireValue(
    constructorFaultResponse.status === 503 &&
      constructorFaultResponse.body.error?.code ===
        "outcome_room_child_pending_recovery" &&
      familyCount(
        childConstructorFaultSourceDataDir,
        "outcome-room-child-admission-intents",
      ) === 1,
    `BLOCKED: child after-intent fault did not retain exactly one bounded intent (${constructorFaultResponse.status}/${constructorFaultResponse.body.error?.code}/${constructorFaultResponse.body.error?.message})`,
  );
  plane = await startIsolatedPlane({
    dataDir,
    baseEnv: CLEAN_BASE_ENV,
    env: {
      ...basePlaneEnv,
      IOI_TEST_FORCE_OUTCOME_ROOM_CHILD_AFTER_RUNTIME_DEPENDENCIES: "1",
    },
    serve: true,
  });
  requireValue(plane, "BLOCKED: result fault lane did not start");
  call = (method, path, body, headers) =>
    request(plane.daemonUrl, method, path, body, headers);
  const pendingOutsiderId = `m4_pending_outsider_${Date.now().toString(16)}`;
  const pendingOutsiderEmail = `${pendingOutsiderId}@local`;
  const pendingOutsiderPassword = `m4-${pendingOutsiderId}-password`;
  const pendingOutsiderCreate = await call(
    "POST",
    "/v1/hypervisor/principals",
    {
      principal_id: pendingOutsiderId,
      email: pendingOutsiderEmail,
      password: pendingOutsiderPassword,
    },
  );
  const pendingOutsiderLogin = await call(
    "POST",
    "/v1/hypervisor/auth/login",
    { email: pendingOutsiderEmail, password: pendingOutsiderPassword },
  );
  requireValue(
    pendingOutsiderCreate.status === 200 &&
      pendingOutsiderLogin.status === 200 &&
      pendingOutsiderLogin.body.session_token,
    "BLOCKED: pending-state owner-order outsider principal did not authenticate",
  );
  const pendingOutsiderHeaders = {
    authorization: `Bearer ${pendingOutsiderLogin.body.session_token}`,
    "x-ioi-forwarded": "m4-aggregate-verifier",
  };
  const faultedResult = await call(
    "POST",
    `/v1/goal-orchestration/goal-runs/${collectiveGoalRunId}/results`,
    roomResultBody,
  );
  const fencedRoom = await call("GET", roomPath);
  const fencedGoal = await call(
    "GET",
    `/v1/goal-orchestration/goal-runs/${collectiveGoalRunId}`,
  );
  const fencedResults = await call("GET", "/v1/hypervisor/work-results");
  const fencedDeltas = await call("GET", "/v1/hypervisor/outcome-deltas");
  const fencedEvents = await call("GET", eventPath);
  const pendingGoalSpaceResponse = await readHttpText(
    `${plane.serveUrl}/__ioi/goal-space?room=${encodeURIComponent(
      room.outcome_room_id,
    )}`,
  );
  const pendingOutsiderRoomReads = await Promise.all(
    [roomPath, replayPath, graphPath, discussionPath, productPath].map((path) =>
      call("GET", path, undefined, pendingOutsiderHeaders),
    ),
  );
  const faultResponses = [
    faultedResult,
    fencedRoom,
    fencedGoal,
    fencedResults,
    fencedDeltas,
    fencedEvents,
  ];
  const pendingChildIntents = familyRecords(
    dataDir,
    "outcome-room-child-admission-intents",
  );
  const pendingChildIntent = pendingChildIntents[0];
  const pendingDependencies = pendingChildIntent?.runtime_dependencies;
  const pendingResult = pendingChildIntent?.owner_publication_record;
  const pendingAuthorityReceipt =
    pendingDependencies?.authority_admission_receipt?.record;
  const retainedAuthorityReceipts = familyRecords(dataDir, "receipts").filter(
    (receipt) => receipt.receipt_id === pendingAuthorityReceipt?.receipt_id,
  );
  const intentCoveredRuntimeDependencies =
    pendingChildIntents.length === 1 &&
    pendingDependencies?.schema_version ===
      "ioi.outcome-room-work-result-runtime-dependencies.v1" &&
    pendingDependencies?.work_result_ref === pendingResult?.work_result_id &&
    pendingDependencies?.payload_custody?.admission?.artifact_refs?.[0] ===
      pendingResult?.result_payload_ref &&
    strictFamilyEntries(dataDir, "outcome-room-result-payload-bytes").length ===
      1 &&
    pendingResult?.information_flow_label_refs?.[0] ===
      pendingDependencies?.information_flow_label?.record?.label_ref &&
    pendingResult?.producer_component_resolution
      ?.resolved_component_set_snapshot_ref ===
      pendingDependencies?.component_resolution_snapshot?.record?.snapshot_ref &&
    pendingResult?.claim_refs?.[0] ===
      pendingDependencies?.conductor_verification_evidence?.record?.evidence_ref &&
    pendingResult?.authority_and_policy_refs?.[0] ===
      pendingAuthorityReceipt?.receipt_id &&
    retainedAuthorityReceipts.length === 1 &&
    canonicalJson(retainedAuthorityReceipts[0]) ===
      canonicalJson(pendingAuthorityReceipt);
  const faultForbidden = wireTokenVariants([
    '"admitted_object"',
    '"work_result_id"',
    '"result_payload_ref"',
    pendingResult?.work_result_id,
    pendingResult?.result_payload_ref,
    pendingAuthorityReceipt?.receipt_id,
    pendingAuthorityReceipt?.receipt_ref,
    successfulInvocation.harness_invocation_id,
    completedOutputText,
    successfulInvocation.candidate_workspace_root,
    completedOutputPath,
  ]);
  check(
    "RESULT FAULT: post-dependency interruption is intent-covered and returns typed pending recovery, never false success",
    faultedResult.status === 503 &&
      faultedResult.body.error?.code === "outcome_room_child_pending_recovery" &&
      faultResponses.every((response) =>
        responseOmitsWireTokens(response, faultForbidden),
      ) &&
      pendingOutsiderRoomReads.every(
        (response) =>
          response.status === 403 &&
          response.body.error?.code === "outcome_room_owner_mismatch" &&
          responseOmitsWireTokens(response, faultForbidden),
      ) &&
      familyCount(dataDir, "work-result-registry") === 1 &&
      familyCount(dataDir, "outcome-delta-registry") === 0 &&
      intentCoveredRuntimeDependencies,
    `${faultedResult.status}/${faultedResult.body.error?.code}/intent_covered=${intentCoveredRuntimeDependencies}/outsider=${pendingOutsiderRoomReads.map((response) => `${response.status}/${response.body.error?.code}`).join(",")}/results=${familyCount(dataDir, "work-result-registry")}/deltas=${familyCount(dataDir, "outcome-delta-registry")}`,
  );
  for (const [name, response, expectedCode] of [
    ["room owner", fencedRoom, "outcome_room_mutation_pending_recovery"],
    ["GoalRun owner", fencedGoal, "outcome_room_mutation_pending_recovery"],
    ["WorkResult collection", fencedResults, "outcome_room_mutation_pending_recovery"],
    ["OutcomeDelta collection", fencedDeltas, "outcome_room_mutation_pending_recovery"],
    ["GoalRun event projection", fencedEvents, "outcome_room_mutation_pending_recovery"],
  ]) {
    check(
      `RESULT FAULT FENCE: ${name} refuses while the admitted child intent is pending`,
      response.status === 503 &&
        response.body.error?.code === expectedCode &&
        responseOmitsWireTokens(response, faultForbidden),
      `${response.status}/${response.body.error?.code}`,
    );
  }
  check(
    "RESULT FAULT PRODUCT STATE: ported shell renders typed unavailable state without cached child truth",
    pendingGoalSpaceResponse.status === 503 &&
      pendingGoalSpaceResponse.body.includes(
        'data-error-code="outcome_room_mutation_pending_recovery"',
      ) &&
      pendingGoalSpaceResponse.body.includes(
        "No OutcomeRoom, graph, discussion, GoalRun, WorkResult, OutcomeDelta, receipt, or replay owner truth is shown.",
      ) &&
      !pendingGoalSpaceResponse.body.includes(
        successfulInvocation.harness_invocation_id,
      ) &&
      !pendingGoalSpaceResponse.body.includes(completedOutputText) &&
      responseOmitsWireTokens(pendingGoalSpaceResponse, faultForbidden),
    `${pendingGoalSpaceResponse.status}/bytes=${pendingGoalSpaceResponse.body.length}`,
  );
  requireValue(
    faultedResult.status === 503 &&
      faultedResult.body.error?.code === "outcome_room_child_pending_recovery",
    "result fault did not retain an admitted child intent",
  );
  requireValue(
    pendingResult?.schema_version === "ioi.foundations.work-result.v3" &&
      typeof pendingResult.work_result_id === "string",
    "result fault did not retain its exact v3 owner-publication record",
  );
  rmSync(completedOutputPath, { force: true });
  await plane.stop();
  const tamperedChildRecoveryRoot = mkdtempSync(
    join(tmpdir(), "ioi-m4-child-recovery-tamper-"),
  );
  const tamperedChildRecoveryDataDir = join(
    tamperedChildRecoveryRoot,
    "data",
  );
  let tamperedChildRecovery;
  let tamperedChildRecoveryTreeUnchanged = false;
  let tamperedChildRecoveryRootsRecomputed = false;
  try {
    cpSync(dataDir, tamperedChildRecoveryDataDir, {
      recursive: true,
      dereference: false,
      preserveTimestamps: true,
      verbatimSymlinks: true,
    });
    const tamperedIntentEntries = strictFamilyEntries(
      tamperedChildRecoveryDataDir,
      "outcome-room-child-admission-intents",
    );
    const tamperedIntentEntry = requireValue(
      tamperedIntentEntries.length === 1 ? tamperedIntentEntries[0] : null,
      `BLOCKED: pending-child tamper clone has ${tamperedIntentEntries.length} intents`,
    );
    const tamperedIntentPath = join(
      tamperedChildRecoveryDataDir,
      "outcome-room-child-admission-intents",
      tamperedIntentEntry.name,
    );
    const tamperedIntent = JSON.parse(readFileSync(tamperedIntentPath, "utf8"));
    const priorOwnerRecord = structuredClone(
      tamperedIntent.owner_publication_record,
    );
    const priorOperation = structuredClone(tamperedIntent.operation);
    const tamperedOwnerRecord = JSON.parse(
      JSON.stringify(tamperedIntent.owner_publication_record),
    );
    tamperedOwnerRecord.recovery_schema_substitution =
      "must be refused before Agentgres admission";
    tamperedIntent.owner_publication_record = tamperedOwnerRecord;
    const tamperedIntentReplacementPath = tamperedIntentPath;
    writeFileSync(
      tamperedIntentReplacementPath,
      Buffer.from(`${JSON.stringify(tamperedIntent)}\n`),
    );
    tamperedChildRecoveryRootsRecomputed =
      canonicalJson(tamperedIntent.owner_publication_record) !==
        canonicalJson(priorOwnerRecord) &&
      canonicalJson(tamperedIntent.operation) === canonicalJson(priorOperation);
    const tamperedTreeBefore = roomAdmissionSideEffectSnapshot(
      tamperedChildRecoveryDataDir,
    );
    tamperedChildRecovery = await expectOwnedRestartRefusal({
      dataDir: tamperedChildRecoveryDataDir,
      baseEnv: CLEAN_BASE_ENV,
      env: basePlaneEnv,
      expectedCode: "outcome_room_recovery_invalid",
    });
    const tamperedTreeAfter = roomAdmissionSideEffectSnapshot(
      tamperedChildRecoveryDataDir,
    );
    tamperedChildRecoveryTreeUnchanged = tamperedTreeAfter === tamperedTreeBefore;
  } finally {
    rmSync(tamperedChildRecoveryRoot, { recursive: true, force: true });
  }
  const selfConsistentChildRecoveryRoot = mkdtempSync(
    join(tmpdir(), "ioi-m4-child-recovery-room-substitution-"),
  );
  const selfConsistentChildRecoveryDataDir = join(
    selfConsistentChildRecoveryRoot,
    "data",
  );
  let selfConsistentChildRecovery;
  let selfConsistentChildRecoveryTreeUnchanged = false;
  let selfConsistentChildIntentRetained = false;
  let selfConsistentChildRootsRecomputed = false;
  let selfConsistentChildRoomSchemaValid = false;
  try {
    cpSync(childConstructorFaultSourceDataDir, selfConsistentChildRecoveryDataDir, {
      recursive: true,
      dereference: false,
      preserveTimestamps: true,
      verbatimSymlinks: true,
    });
    const intentEntry = requireValue(
      strictFamilyEntries(
        selfConsistentChildRecoveryDataDir,
        "outcome-room-child-admission-intents",
      )[0],
      "BLOCKED: pending-child room-substitution clone has no intent",
    );
    const intentPath = join(
      selfConsistentChildRecoveryDataDir,
      "outcome-room-child-admission-intents",
      intentEntry.name,
    );
    const intent = JSON.parse(readFileSync(intentPath, "utf8"));
    const priorOwnerRecord = structuredClone(intent.owner_publication_record);
    const priorOperation = structuredClone(intent.operation);
    const substitutedOwnerRecord = structuredClone(
      intent.owner_publication_record,
    );
    substitutedOwnerRecord.result_payload_ref =
      "artifact://unrelated-self-consistent-recovery-payload";
    substitutedOwnerRecord.system_binding.payload_root =
      systemScopedPayloadRoot(substitutedOwnerRecord);
    intent.owner_publication_record = substitutedOwnerRecord;
    intent.operation.typed_payload = structuredClone(substitutedOwnerRecord);
    const substitutedOperationRoot = jcsRoot(
      "ioi.outcome-room-system-operation-jcs-sha256.v1",
      intent.operation,
    );
    const replacementPath = join(
      selfConsistentChildRecoveryDataDir,
      "outcome-room-child-admission-intents",
      `orop_${substitutedOperationRoot.slice("sha256:".length)}.json`,
    );
    const replacementBytes = Buffer.from(`${JSON.stringify(intent)}\n`);
    writeFileSync(replacementPath, replacementBytes);
    if (replacementPath !== intentPath) rmSync(intentPath);
    selfConsistentChildRoomSchemaValid = validateRoom(intent.candidate_room);
    selfConsistentChildRootsRecomputed =
      canonicalJson(substitutedOwnerRecord) !== canonicalJson(priorOwnerRecord) &&
      canonicalJson(intent.operation) !== canonicalJson(priorOperation) &&
      intent.operation.typed_payload.system_binding.payload_root ===
        systemScopedPayloadRoot(intent.operation.typed_payload) &&
      replacementPath.endsWith(
        `orop_${substitutedOperationRoot.slice("sha256:".length)}.json`,
      );
    const treeBefore = roomAdmissionSideEffectSnapshot(
      selfConsistentChildRecoveryDataDir,
    );
    selfConsistentChildRecovery = await expectOwnedRestartRefusal({
      dataDir: selfConsistentChildRecoveryDataDir,
      baseEnv: CLEAN_BASE_ENV,
      env: basePlaneEnv,
      expectedCode: "work_result_payload_artifact_substituted",
    });
    const treeAfter = roomAdmissionSideEffectSnapshot(
      selfConsistentChildRecoveryDataDir,
    );
    selfConsistentChildRecoveryTreeUnchanged = treeAfter === treeBefore;
    selfConsistentChildIntentRetained =
      existsSync(replacementPath) &&
      readFileSync(replacementPath).equals(replacementBytes);
  } finally {
    rmSync(selfConsistentChildRecoveryRoot, { recursive: true, force: true });
    rmSync(childConstructorFaultSourceRoot, { recursive: true, force: true });
  }
  const childRecoveryFenceBefore = roomAdmissionSideEffectSnapshot(dataDir);
  const malformedChildRecovery = await expectClonedRestartRefusal({
    sourceDataDir: dataDir,
    tempPrefix: "ioi-m4-child-malformed-registry-",
    baseEnv: CLEAN_BASE_ENV,
    env: basePlaneEnv,
    expectedCode: "outcome_room_recovery_owner_registry_unreadable",
    install(clonedDataDir) {
      const path = join(
        clonedDataDir,
        "work-result-registry",
        "malformed-child-recovery-sibling.json",
      );
      const bytes = Buffer.from("{not-json");
      writeFileSync(path, bytes, { flag: "wx" });
      return { path, bytes };
    },
  });
  const relocatedChildRecovery = await expectClonedRestartRefusal({
    sourceDataDir: dataDir,
    tempPrefix: "ioi-m4-child-relocated-registry-",
    baseEnv: CLEAN_BASE_ENV,
    env: basePlaneEnv,
    expectedCode: "outcome_room_recovery_owner_registry_unreadable",
    install(clonedDataDir) {
      const path = join(
        clonedDataDir,
        "work-result-registry",
        "relocated-child-recovery-sibling.json",
      );
      const bytes = Buffer.from(`${JSON.stringify(pendingResult)}\n`);
      writeFileSync(path, bytes, { flag: "wx" });
      return { path, bytes };
    },
  });
  const childRecoveryFenceAfter = roomAdmissionSideEffectSnapshot(dataDir);
  check(
    "RESULT RECOVERY PRECONDITION: transient bytes stay absent and retained intent refuses malformed, relocated, schema-invalid owner, or self-consistent resulting-room substitution",
    !existsSync(completedOutputPath) &&
      [malformedChildRecovery, relocatedChildRecovery].every(
        (probe) =>
          probe?.refused === true &&
          probe.newLogs.length === 1 &&
          probe.logText.includes(probe.expectedCode) &&
          probe.installedRetained === true &&
          probe.treeUnchanged === true,
      ) &&
      tamperedChildRecovery?.refused === true &&
      tamperedChildRecovery.newLogs.length === 1 &&
      tamperedChildRecovery.logText.includes(tamperedChildRecovery.expectedCode) &&
      tamperedChildRecoveryRootsRecomputed &&
      tamperedChildRecoveryTreeUnchanged &&
      selfConsistentChildRecovery?.refused === true &&
      selfConsistentChildRecovery.newLogs.length === 1 &&
      selfConsistentChildRecovery.logText.includes(
        selfConsistentChildRecovery.expectedCode,
      ) &&
      selfConsistentChildRoomSchemaValid &&
      selfConsistentChildRootsRecomputed &&
      selfConsistentChildIntentRetained &&
      selfConsistentChildRecoveryTreeUnchanged &&
      childRecoveryFenceAfter === childRecoveryFenceBefore,
    `candidate_absent=${!existsSync(completedOutputPath)}/registry_fences=${[malformedChildRecovery, relocatedChildRecovery].map((probe) => `${probe?.refused}/${probe?.logText.includes(probe.expectedCode)}/${probe?.newLogs.length}`).join(",")}/schema_invalid_tamper=${tamperedChildRecovery?.refused}/${tamperedChildRecovery?.logText.includes(tamperedChildRecovery.expectedCode)}/${tamperedChildRecovery?.newLogs.length}/schema_invalid_roots=${tamperedChildRecoveryRootsRecomputed}/schema_invalid_tree=${tamperedChildRecoveryTreeUnchanged}/self_consistent=${selfConsistentChildRecovery?.refused}/${selfConsistentChildRecovery?.logText.includes(selfConsistentChildRecovery.expectedCode)}/${selfConsistentChildRecovery?.newLogs.length}/room_schema=${selfConsistentChildRoomSchemaValid}/roots=${selfConsistentChildRootsRecomputed}/intent_retained=${selfConsistentChildIntentRetained}/tree=${selfConsistentChildRecoveryTreeUnchanged}/whole_tree_unchanged=${childRecoveryFenceAfter === childRecoveryFenceBefore}/self_consistent_startup=${selfConsistentChildRecovery?.startupError}/self_consistent_log_tail=${JSON.stringify(selfConsistentChildRecovery?.logText.slice(-1200))}`,
  );
  plane = await startIsolatedPlane({
    dataDir,
    baseEnv: CLEAN_BASE_ENV,
    env: basePlaneEnv,
    serve: true,
  });
  requireValue(plane, "BLOCKED: result recovery lane did not start");
  call = (method, path, body, headers) =>
    request(plane.daemonUrl, method, path, body, headers);
  const recoveredResultRoom = await call("GET", roomPath);
  const recoveredResultGoal = await call(
    "GET",
    `/v1/goal-orchestration/goal-runs/${collectiveGoalRunId}`,
  );
  const recoveredResultList = await call("GET", "/v1/hypervisor/work-results");
  const recoveredEvents = await call(
    "GET",
    eventPath,
  );
  const admittedResult = recoveredResultList.body.work_results?.find(
    (value) =>
      value.invocation_or_run_ref === successfulInvocation.harness_invocation_id,
  );
  requireValue(admittedResult, "runtime-derived room WorkResult did not recover");
  const recoveredResultPoint = await call(
    "GET",
    `/v1/hypervisor/work-results/${encodeURIComponent(
      admittedResult.work_result_id.replace("work-result://", ""),
    )}`,
  );
  const resultPayloadEntries = strictFamilyEntries(
    dataDir,
    "outcome-room-result-payload-bytes",
  );
  const resultPayloadPath = requireValue(
    resultPayloadEntries.length === 1
      ? join(
          dataDir,
          "outcome-room-result-payload-bytes",
          resultPayloadEntries[0].name,
        )
      : null,
    `BLOCKED: expected one durable result payload bundle, found ${resultPayloadEntries.length}`,
  );
  const resultPayloadBytes = readFileSync(resultPayloadPath);
  const resultPayloadBundle = JSON.parse(resultPayloadBytes.toString("utf8"));
  const bundledOutput = requireValue(
    resultPayloadBundle.files?.length === 1
      ? resultPayloadBundle.files[0]
      : null,
    "BLOCKED: result payload bundle does not contain exactly one output file",
  );
  const admittedResultLabels = requireValue(
    admittedResult.information_flow_label_refs?.length === 1
      ? admittedResult.information_flow_label_refs
      : null,
    "BLOCKED: room WorkResult does not carry exactly one durable information-flow label",
  );
  const linkedInvocation = recoveredEvents.body.invocations?.find(
    (value) =>
      value.harness_invocation_id === successfulInvocation.harness_invocation_id,
  );
  room = recoveredResultRoom.body.outcome_room;
  const postResultDetachGoalRoot = jcsRoot(
    "ioi.goal-run-room-membership-predecessor-jcs-sha256.v1",
    recoveredResultGoal.body.goal_run,
  );
  const postResultDetachBefore = roomAdmissionSideEffectSnapshot(dataDir);
  const postResultDetach = await call(
    "POST",
    `/v1/goal-orchestration/outcome-rooms/${roomTail}/detach-goal-run`,
    {
      goal_run_ref: collectiveGoal.goal_ref,
      expected_revision: room.latest_sequence,
      expected_goal_run_record_root: postResultDetachGoalRoot,
    },
  );
  const postResultDetachAfter = roomAdmissionSideEffectSnapshot(dataDir);
  const objectFaultForbidden = wireTokenVariants([
    collectiveGoal.goal_ref,
    room.outcome_room_id,
    admittedResult.work_result_id,
    admittedResult.system_binding?.payload_root,
  ]);
  // The retired room object/receipt caches are absent. This detach must resolve the admitted child
  // from Agentgres history and fail before any mutation. The focused substrate proof above
  // destructively removes and corrupts that history source and proves fail-closed, write-free reads.
  const treeBeforeAgentgresBackedDetach = roomAdmissionSideEffectSnapshot(dataDir);
  const agentgresBackedDetach = await call(
    "POST",
    `/v1/goal-orchestration/outcome-rooms/${roomTail}/detach-goal-run`,
    {
      goal_run_ref: collectiveGoal.goal_ref,
      expected_revision: room.latest_sequence,
      expected_goal_run_record_root: postResultDetachGoalRoot,
    },
  );
  const agentgresBackedOutsiderDetach = await call(
    "POST",
    `/v1/goal-orchestration/outcome-rooms/${roomTail}/detach-goal-run`,
    {
      goal_run_ref: collectiveGoal.goal_ref,
      expected_revision: room.latest_sequence,
      expected_goal_run_record_root: postResultDetachGoalRoot,
    },
    pendingOutsiderHeaders,
  );
  const agentgresBackedDetachTreeUnchanged =
    roomAdmissionSideEffectSnapshot(dataDir) === treeBeforeAgentgresBackedDetach;
  const resultPayloadContentHash =
    `sha256:${createHash("sha256").update(resultPayloadBytes).digest("hex")}`;
  const expectedResultLabelIdentityMaterial = {
    schema_version: "ioi.foundations.information-flow-label.v1",
    label_ref: null,
    profile_ref: room.privacy_policy_ref,
    content_hash: resultPayloadContentHash,
    origin: "tool_output",
    integrity: "untrusted",
    confidentiality: "private",
    instruction_authority: "none",
    egress_policy: {
      mode: "deny",
      allowed_destination_patterns: [],
      allowed_data_classes: [],
    },
    purpose: "outcome-room-work-result",
    retention: {
      max_seconds: 9007199254740991,
      disposition: "retain_under_policy",
    },
    derivation_kind: "direct",
    derivation_parent_refs: [],
    derivation_closure_refs: [],
  };
  const expectedResultLabelRef =
    `ifc-label://outcome-room/work-result/${createHash("sha256")
      .update(
        canonicalJson({
          domain: "ioi.outcome-room-information-flow-label-ref-jcs-sha256.v1",
          label: expectedResultLabelIdentityMaterial,
        }),
      )
      .digest("hex")}`;
  const runtimeDependencyResolverGuardTests =
    await runRuntimeDependencyResolverGuardTests();
  check(
    "ROOM RESULT RECOVERY: pending intent advances the room head exactly once",
    recoveredResultRoom.status === 200 &&
      room?.latest_sequence === preResultFaultRevision + 1 &&
      familyCount(dataDir, "outcome-room-child-admission-intents") === 0 &&
      postResultDetach.status === 422 &&
      postResultDetach.body.error?.code ===
        "outcome_room_goal_run_detach_has_admitted_children" &&
      postResultDetachAfter === postResultDetachBefore &&
      agentgresBackedDetach?.status === 422 &&
      agentgresBackedDetach.body.error?.code ===
        "outcome_room_goal_run_detach_has_admitted_children" &&
      responseOmitsWireTokens(agentgresBackedDetach, objectFaultForbidden) &&
      agentgresBackedOutsiderDetach?.status === 403 &&
      agentgresBackedOutsiderDetach.body.error?.code ===
        "outcome_room_owner_mismatch" &&
      responseOmitsWireTokens(
        agentgresBackedOutsiderDetach,
        objectFaultForbidden,
      ) &&
      agentgresBackedDetachTreeUnchanged &&
      familyCount(dataDir, "outcome-room-admitted-object-projections") === 0 &&
      familyCount(dataDir, "outcome-room-system-receipts") === 0,
    `${recoveredResultRoom.status}/seq=${room?.latest_sequence}/pending=${familyCount(dataDir, "outcome-room-child-admission-intents")}/post_result_detach=${postResultDetach.status}/${postResultDetach.body.error?.code}/tree_unchanged=${postResultDetachAfter === postResultDetachBefore}/agentgres_backed=${agentgresBackedDetach?.status}/${agentgresBackedDetach?.body.error?.code}/${agentgresBackedOutsiderDetach?.status}/${agentgresBackedOutsiderDetach?.body.error?.code}/${agentgresBackedDetachTreeUnchanged}`,
  );
  check(
    "ROOM RESULT RECOVERY: daemon-derived WorkResult validates the software implementation profile",
    admittedResult?.schema_version === "ioi.foundations.work-result.v3" &&
      admittedResult?.result_profile === "software_implementation",
    `${admittedResult?.schema_version}/${admittedResult?.result_profile}`,
  );
  check(
    "ROOM RESULT RECOVERY: successful execution candidate derives a positive completed outcome",
    admittedResult?.status === "completed" &&
      admittedResult?.outcome_class === "positive",
    `${admittedResult?.status}/${admittedResult?.outcome_class}`,
  );
  check(
    "ROOM RESULT RECOVERY: Agentgres admission binds the exact bounded System",
    admittedResult?.system_binding?.system_id === SYSTEM_ID &&
      admittedResult?.system_binding?.parent_scope_ref === room.outcome_room_id &&
      admittedResult?.system_binding?.payload_root ===
        systemScopedPayloadRoot(admittedResult),
    `${admittedResult?.system_binding?.system_id}/${admittedResult?.system_binding?.parent_scope_ref}`,
  );
  check(
    "ROOM RESULT RECOVERY: producer receipt, durable byte custody, and label derive from invocation truth",
      admittedResult?.producer_component_resolution?.component_resolution_receipt_ref ===
        successfulInvocation.execution_receipt.id &&
      admittedResult?.producer_component_resolution
        ?.resolved_component_set_snapshot_ref ===
        pendingDependencies?.component_resolution_snapshot?.record?.snapshot_ref &&
      admittedResult?.producer_component_resolution?.resolved_component_set_hash ===
        pendingDependencies?.component_resolution_snapshot?.record?.snapshot_hash &&
      admittedResult?.claim_refs?.length === 1 &&
      admittedResult.claim_refs[0] ===
        pendingDependencies?.conductor_verification_evidence?.record?.evidence_ref &&
      String(admittedResult?.result_payload_ref || "").startsWith(
        "artifact://goal-run/",
      ) &&
      resultPayloadBundle.schema_version ===
        "ioi.outcome-room-result-payload-bundle.v1" &&
      resultPayloadBundle.artifact_ref === admittedResult.result_payload_ref &&
      resultPayloadBundle.implementation_result?.work_result_ref ===
        admittedResult.work_result_id &&
      bundledOutput.relative_path === completedOutputRel &&
      bundledOutput.size_bytes === completedOutputBytes.length &&
      bundledOutput.sha256 ===
        `sha256:${createHash("sha256").update(completedOutputBytes).digest("hex")}` &&
      Buffer.from(bundledOutput.content_base64, "base64").equals(
        completedOutputBytes,
      ) &&
      admittedResult.supporting_evidence_refs?.some((reference) =>
        String(reference).startsWith(
          "evidence://storage-backend-write-admission/",
        ),
      ) &&
      String(admittedResultLabels[0]).startsWith(
        "ifc-label://outcome-room/work-result/",
      ) &&
      admittedResultLabels[0] === expectedResultLabelRef &&
      runtimeDependencyResolverGuardTests.code === 0 &&
      runtimeDependencyResolverGuardTests.failure === null &&
      /m4_runtime_dependency_resolvers_refuse_missing_duplicate_and_substituted_truth \.\.\. ok/u.test(
        runtimeDependencyResolverGuardTests.output,
      ) &&
      /1 passed; 0 failed/u.test(runtimeDependencyResolverGuardTests.output),
    `${admittedResult?.producer_component_resolution?.component_resolution_receipt_ref}/${admittedResult?.result_payload_ref}/custody=${resultPayloadBytes.length}/label=${admittedResultLabels[0]}/expected_tool_output_label=${expectedResultLabelRef}/deep=${runtimeDependencyResolverGuardTests.code}/${runtimeDependencyResolverGuardTests.failure || "no-failure"}`,
  );
  check(
    "ROOM RESULT RECOVERY: WorkResult carries exactly the consumed invocation-authority admission receipt",
    admittedResult?.authority_and_policy_refs?.length === 1 &&
      String(admittedResult.authority_and_policy_refs[0]).startsWith(
        "receipt://goal-run-invocation-authority/",
      ) &&
      admittedResult?.supporting_evidence_refs?.includes(
        admittedResult.authority_and_policy_refs[0],
      ) &&
      retainedAuthorityReceipts.length === 1 &&
      retainedAuthorityReceipts[0].receipt_id ===
        admittedResult.authority_and_policy_refs[0] &&
      canonicalJson(retainedAuthorityReceipts[0]) ===
        canonicalJson(pendingAuthorityReceipt),
    String(admittedResult?.authority_and_policy_refs?.[0]),
  );
  check(
    "ROOM RESULT RECOVERY: exact owner census and GoalRun backlink publish one admitted WorkResult",
    recoveredResultList.status === 200 &&
      recoveredResultList.body.schema_version ===
        RESULT_REGISTRY_PROJECTION_SCHEMA &&
      canonicalJson(recoveredResultList.body.accepted_record_schema_versions) ===
        canonicalJson(RESULT_RECORD_SCHEMAS) &&
      canonicalJson(recoveredResultList.body.record_schema_counts) ===
        canonicalJson({
          "ioi.foundations.work-result.v3": 2,
        }) &&
      recoveredResultList.body.work_results?.length === 2 &&
      familyCount(dataDir, "work-result-registry") === 2 &&
      recoveredResultPoint.status === 200 &&
      recoveredResultPoint.body.schema_version ===
        RESULT_REGISTRY_PROJECTION_SCHEMA &&
      recoveredResultPoint.body.record_schema_version ===
        "ioi.foundations.work-result.v3" &&
      canonicalJson(recoveredResultPoint.body.work_result) ===
        canonicalJson(admittedResult) &&
      recoveredResultGoal.body.goal_run?.work_result_refs?.length === 1 &&
      recoveredResultGoal.body.goal_run.work_result_refs[0] ===
        admittedResult?.work_result_id,
    `${admittedResult?.work_result_id}/list=${recoveredResultList.body.work_results?.length}/family=${familyCount(dataDir, "work-result-registry")}/schemas=${canonicalJson(recoveredResultList.body.record_schema_counts)}/point=${recoveredResultPoint.status}/${recoveredResultPoint.body.record_schema_version}`,
  );
  check(
    "ROOM RESULT RECOVERY: HarnessInvocation publishes the exact reciprocal WorkResult backlink",
    linkedInvocation?.status === "completed" &&
      linkedInvocation?.implementation_result_candidate === undefined &&
      linkedInvocation?.work_result_ref === admittedResult?.work_result_id &&
      linkedInvocation?.profile_result_ref ===
        linkedInvocation?.implementation_result?.implementation_result_id,
    `${linkedInvocation?.status}/${linkedInvocation?.work_result_ref}/${linkedInvocation?.profile_result_ref}/${admittedResult?.work_result_id}`,
  );
  check(
    "ROOM RESULT RECOVERY: canonical ImplementationResult publishes the same reciprocal backlink and admitted artifact refs",
    linkedInvocation?.implementation_result?.work_result_ref ===
      admittedResult?.work_result_id &&
      linkedInvocation?.implementation_result?.status === "completed" &&
      linkedInvocation?.implementation_result?.harness_invocation_ref ===
        successfulInvocation.harness_invocation_id &&
      linkedInvocation?.implementation_result?.changed_file_refs?.includes(
        `artifact://goal-run/${collectiveGoalRunId}/${successfulInvocation.role_key}/${completedOutputRel}`,
      ) &&
      linkedInvocation?.implementation_result?.artifact_refs?.includes(
        `artifact://goal-run/${collectiveGoalRunId}/${successfulInvocation.role_key}/${completedOutputRel}`,
      ),
    `${linkedInvocation?.implementation_result?.work_result_ref}/${linkedInvocation?.implementation_result?.status}/${admittedResult?.work_result_id}`,
  );
  check(
    "ROOM RESULT RECOVERY: admitted-result and invocation-successor roots are sealed",
    linkedInvocation?.work_result_derivation?.admitted_work_result_root?.startsWith(
        "sha256:",
      ) &&
      linkedInvocation?.work_result_derivation?.invocation_successor_root?.startsWith(
        "sha256:",
      ),
    `${linkedInvocation?.work_result_derivation?.admitted_work_result_root}/${linkedInvocation?.work_result_derivation?.invocation_successor_root}`,
  );
  const resultReplayDurableBefore = roomAdmissionSideEffectSnapshot(dataDir);
  const replayedInvocationResult = await call(
    "POST",
    `/v1/goal-orchestration/goal-runs/${collectiveGoalRunId}/results`,
    roomResultBody,
  );
  const roomAfterResultReplayRefusal = await call("GET", roomPath);
  const resultsAfterResultReplayRefusal = await call(
    "GET",
    "/v1/hypervisor/work-results",
  );
  const invocationResultsAfterReplayRefusal =
    resultsAfterResultReplayRefusal.body.work_results?.filter(
      (value) =>
        value.invocation_or_run_ref === successfulInvocation.harness_invocation_id,
    ) || [];
  const resultReplayDurableAfter = roomAdmissionSideEffectSnapshot(dataDir);
  const payloadProbeBody = {
    proposed_by_ref: admittedResult.work_result_id,
    target_ref: "state://ioi/m4/room-course-correction",
    delta_kind: "course_correct",
    payload_ref: "state-delta://ioi/m4/room-course-correction",
    precondition_and_invariant_refs: ["policy://ioi/m4/retain-negative"],
    expected_effect_ref: "effect://ioi/m4/revise-room-approach",
    verifier_and_acceptance_refs: [
      "verifier-path://ioi/m4/room-course-correction",
    ],
    information_flow_label_refs: admittedResultLabels,
  };
  let missingPayloadDelta;
  let missingPayloadDeltaTreeUnchanged = false;
  try {
    rmSync(resultPayloadPath);
    const treeBefore = roomAdmissionSideEffectSnapshot(dataDir);
    missingPayloadDelta = await call(
      "POST",
      `/v1/goal-orchestration/goal-runs/${collectiveGoalRunId}/outcome-deltas`,
      payloadProbeBody,
    );
    missingPayloadDeltaTreeUnchanged =
      roomAdmissionSideEffectSnapshot(dataDir) === treeBefore;
  } finally {
    writeFileSync(resultPayloadPath, resultPayloadBytes);
  }
  let substitutedPayloadDelta;
  let substitutedPayloadDeltaTreeUnchanged = false;
  try {
    writeFileSync(
      resultPayloadPath,
      Buffer.concat([resultPayloadBytes, Buffer.from("\nsubstituted-custody\n")]),
    );
    const treeBefore = roomAdmissionSideEffectSnapshot(dataDir);
    substitutedPayloadDelta = await call(
      "POST",
      `/v1/goal-orchestration/goal-runs/${collectiveGoalRunId}/outcome-deltas`,
      payloadProbeBody,
    );
    substitutedPayloadDeltaTreeUnchanged =
      roomAdmissionSideEffectSnapshot(dataDir) === treeBefore;
  } finally {
    writeFileSync(resultPayloadPath, resultPayloadBytes);
  }
  check(
    "ROOM RESULT/PAYLOAD REFUSAL: replay, missing custody, and substituted bytes cannot mutate owner or room truth",
    replayedInvocationResult.status === 409 &&
      replayedInvocationResult.body.error?.code ===
        "work_result_invocation_truth_unresolved" &&
      roomAfterResultReplayRefusal.status === 200 &&
      roomAfterResultReplayRefusal.body.outcome_room?.latest_sequence ===
        preResultFaultRevision + 1 &&
      resultsAfterResultReplayRefusal.status === 200 &&
      invocationResultsAfterReplayRefusal.length === 1 &&
      invocationResultsAfterReplayRefusal[0].work_result_id ===
        admittedResult.work_result_id &&
      missingPayloadDelta?.status === 503 &&
      missingPayloadDelta?.body.error?.code ===
        "work_result_payload_unavailable" &&
      substitutedPayloadDelta?.status === 409 &&
      substitutedPayloadDelta?.body.error?.code ===
        "work_result_payload_bytes_substituted" &&
      resultReplayDurableAfter === resultReplayDurableBefore &&
      missingPayloadDeltaTreeUnchanged &&
      substitutedPayloadDeltaTreeUnchanged,
    `${replayedInvocationResult.status}/${replayedInvocationResult.body.error?.code}/missing=${missingPayloadDelta?.status}/${missingPayloadDelta?.body.error?.code}/${missingPayloadDeltaTreeUnchanged}/substituted=${substitutedPayloadDelta?.status}/${substitutedPayloadDelta?.body.error?.code}/${substitutedPayloadDeltaTreeUnchanged}/seq=${roomAfterResultReplayRefusal.body.outcome_room?.latest_sequence}/results=${invocationResultsAfterReplayRefusal.length}/replay_tree=${resultReplayDurableAfter === resultReplayDurableBefore}`,
  );
  const deltaSubstitutionDurableBefore = roomAdmissionSideEffectSnapshot(dataDir);
  const deltaSubstitution = await call(
    "POST",
    `/v1/goal-orchestration/goal-runs/${collectiveGoalRunId}/outcome-deltas`,
    {
      proposed_by_ref: admittedResult.work_result_id,
      target_ref: "state://ioi/m4/room-course-correction",
      delta_kind: "course_correct",
      payload_ref: "state-delta://ioi/m4/room-course-correction",
      information_flow_label_refs: [],
      room_admission: {
        expected_room_revision: 0,
        admission_decision_ref: "decision://substituted/stale",
      },
      },
  );
  const omittedInheritedLabels = await call(
    "POST",
    `/v1/goal-orchestration/goal-runs/${collectiveGoalRunId}/outcome-deltas`,
    {
      ...payloadProbeBody,
      information_flow_label_refs: [],
    },
  );
  const noncanonicalInheritedField = await call(
    "POST",
    `/v1/goal-orchestration/goal-runs/${collectiveGoalRunId}/outcome-deltas`,
    {
      ...payloadProbeBody,
      inherited_information_flow_label_refs: admittedResultLabels,
    },
  );
  const unknownAddedLabel = await call(
    "POST",
    `/v1/goal-orchestration/goal-runs/${collectiveGoalRunId}/outcome-deltas`,
    {
      ...payloadProbeBody,
      information_flow_label_refs: [
        ...admittedResultLabels,
        "ifc-label://ioi/m4/unknown",
      ],
    },
  );
  const deltaSubstitutionDurableAfter = roomAdmissionSideEffectSnapshot(dataDir);
  check(
    "DELTA REFUSAL: caller cannot substitute verdicts, omit parent labels, persist a second inheritance field, or add unresolved labels",
    deltaSubstitution.status === 422 &&
      deltaSubstitution.body.error?.code === "outcome_delta_plane_owned_field_refused" &&
      omittedInheritedLabels.status === 422 &&
      omittedInheritedLabels.body.error?.code ===
        "outcome_delta_information_flow_label_inheritance_required" &&
      noncanonicalInheritedField.status === 422 &&
      noncanonicalInheritedField.body.error?.code ===
        "outcome_delta_noncanonical_field_refused" &&
      unknownAddedLabel.status === 503 &&
      unknownAddedLabel.body.error?.code ===
        "outcome_room_information_flow_label_unresolved" &&
      deltaSubstitutionDurableAfter === deltaSubstitutionDurableBefore,
    `plane=${deltaSubstitution.status}/${deltaSubstitution.body.error?.code}/omitted=${omittedInheritedLabels.status}/${omittedInheritedLabels.body.error?.code}/extra_field=${noncanonicalInheritedField.status}/${noncanonicalInheritedField.body.error?.code}/unknown=${unknownAddedLabel.status}/${unknownAddedLabel.body.error?.code}/durable_unchanged=${deltaSubstitutionDurableAfter === deltaSubstitutionDurableBefore}`,
  );
  const deltaRequestBody = {
    proposed_by_ref: admittedResult.work_result_id,
    target_ref: "state://ioi/m4/room-course-correction",
    delta_kind: "course_correct",
    payload_ref: "state-delta://ioi/m4/room-course-correction",
    precondition_and_invariant_refs: ["policy://ioi/m4/retain-negative"],
    expected_effect_ref: "effect://ioi/m4/revise-room-approach",
    verifier_and_acceptance_refs: [
      "verifier-path://ioi/m4/room-course-correction",
    ],
    information_flow_label_refs: admittedResultLabels,
  };
  const preDeltaFaultRevision = room.latest_sequence;
  const preDeltaFaultReceiptCount = familyCount(
    dataDir,
    "outcome-room-system-receipts",
  );
  const preDeltaFaultObjectCount = familyCount(
    dataDir,
    "outcome-room-admitted-object-projections",
  );
  await plane.stop();
  plane = await startIsolatedPlane({
    dataDir,
    baseEnv: CLEAN_BASE_ENV,
    env: {
      ...basePlaneEnv,
      // This point is after the operation/receipt/object have reached Agentgres and after the
      // room successor is locally visible, but before the OutcomeDelta owner record/backlink.
      IOI_TEST_FORCE_OUTCOME_ROOM_CHILD_AFTER_ROOM: "1",
    },
    serve: true,
  });
  requireValue(plane, "BLOCKED: OutcomeDelta post-room fault lane did not start");
  call = (method, path, body, headers) =>
    request(plane.daemonUrl, method, path, body, headers);
  const faultedDelta = await call(
    "POST",
    `/v1/goal-orchestration/goal-runs/${collectiveGoalRunId}/outcome-deltas`,
    deltaRequestBody,
  );
  const pendingDeltaIntents = familyRecords(
    dataDir,
    "outcome-room-child-admission-intents",
  );
  const pendingDeltaIntent = pendingDeltaIntents[0];
  const pendingDelta = pendingDeltaIntent?.owner_publication_record;
  const pendingDeltaRef = pendingDelta?.outcome_delta_id;
  const pendingDeltaRoom = familyRecords(dataDir, "outcome-room-registry").find(
    (record) => record.outcome_room_id === room.outcome_room_id,
  );
  const pendingDeltaParent = familyRecords(dataDir, "work-result-registry").find(
    (record) => record.work_result_id === admittedResult.work_result_id,
  );
  const deltaFaultFences = await Promise.all([
    call("GET", roomPath),
    call("GET", `/v1/goal-orchestration/goal-runs/${collectiveGoalRunId}`),
    call("GET", "/v1/hypervisor/work-results"),
    call("GET", "/v1/hypervisor/outcome-deltas"),
    call("GET", eventPath),
    call("GET", graphPath),
    call("GET", discussionPath),
    call("GET", productPath),
    call("GET", replayPath),
  ]);
  check(
    "ROOM DELTA FAULT: post-Agentgres/post-room interruption fences joined reads and leaves no public owner truth",
    faultedDelta.status === 503 &&
      faultedDelta.body.error?.code === "outcome_room_child_pending_recovery" &&
      pendingDeltaIntents.length === 1 &&
      pendingDeltaIntent?.owner_publication_family === "outcome-delta-registry" &&
      pendingDelta?.schema_version === "ioi.foundations.outcome-delta.v3" &&
      typeof pendingDeltaRef === "string" &&
      pendingDelta?.status === "proposed" &&
      pendingDelta?.system_binding?.system_id === SYSTEM_ID &&
      pendingDelta?.system_binding?.parent_scope_ref === room.outcome_room_id &&
      pendingDelta?.system_binding?.payload_root ===
        systemScopedPayloadRoot(pendingDelta) &&
      pendingDeltaIntent?.operation?.operation_kind === "room_child_admitted" &&
      pendingDeltaIntent?.operation?.typed_payload?.outcome_delta_id ===
        pendingDeltaRef &&
      pendingDeltaRoom?.latest_sequence === preDeltaFaultRevision + 1 &&
      String(pendingDeltaRoom?.room_state_root || "").startsWith("sha256:") &&
      String(pendingDeltaRoom?.room_receipt_root || "").startsWith("sha256:") &&
      familyCount(dataDir, "outcome-room-system-receipts") ===
        preDeltaFaultReceiptCount &&
      familyCount(dataDir, "outcome-room-admitted-object-projections") ===
        preDeltaFaultObjectCount &&
      familyCount(dataDir, "outcome-delta-registry") === 0 &&
      !(pendingDeltaParent?.outcome_delta_refs || []).includes(pendingDeltaRef) &&
      deltaFaultFences.every(
        (response) =>
          response.status === 503 &&
          response.body.error?.code === "outcome_room_mutation_pending_recovery" &&
          !response.raw.includes(pendingDeltaRef),
      ),
    `${faultedDelta.status}/${faultedDelta.body.error?.code}/intent=${pendingDeltaIntents.length}/pending=${pendingDeltaRef}/room_seq=${pendingDeltaRoom?.latest_sequence}/receipts=${familyCount(dataDir, "outcome-room-system-receipts")}/objects=${familyCount(dataDir, "outcome-room-admitted-object-projections")}/public_deltas=${familyCount(dataDir, "outcome-delta-registry")}/parent_refs=${pendingDeltaParent?.outcome_delta_refs?.length || 0}/fences=${deltaFaultFences.map((response) => `${response.status}/${response.body.error?.code}`).join(",")}`,
  );

  await plane.stop();
  plane = await startIsolatedPlane({
    dataDir,
    baseEnv: CLEAN_BASE_ENV,
    env: basePlaneEnv,
    serve: true,
  });
  requireValue(plane, "BLOCKED: OutcomeDelta recovery plane did not start");
  call = (method, path, body, headers) =>
    request(plane.daemonUrl, method, path, body, headers);
  const recoveredDeltaRoom = await call("GET", roomPath);
  room = recoveredDeltaRoom.body.outcome_room;
  const versionedDeltaList = await call(
    "GET",
    "/v1/hypervisor/outcome-deltas",
  );
  const admittedDelta = versionedDeltaList.body.outcome_deltas?.find(
    (record) => record.outcome_delta_id === pendingDeltaRef,
  );
  const admittedDeltaPoint = admittedDelta
    ? await call(
        "GET",
        `/v1/hypervisor/outcome-deltas/${encodeURIComponent(
          admittedDelta.outcome_delta_id.replace("outcome-delta://", ""),
        )}`,
      )
    : { status: 0, body: {} };
  const postDeltaResultPoint = await call(
    "GET",
    `/v1/hypervisor/work-results/${encodeURIComponent(
      admittedResult.work_result_id.replace("work-result://", ""),
    )}`,
  );
  const recoveredDeltaReplay = await call("GET", replayPath);
  const recoveredDeltaOperation = recoveredDeltaReplay.body.operations?.find(
    (operation) =>
      operation.operation_kind === "room_child_admitted" &&
      operation.object_ref === pendingDeltaRef,
  );
  const expectedRecoveredDeltaRoom = {
    ...structuredClone(pendingDeltaIntent?.candidate_room || {}),
    latest_sequence: recoveredDeltaOperation?.sequence,
    latest_transition_commitment_ref:
      recoveredDeltaOperation?.resulting_transition_commitment_ref,
    room_state_root: recoveredDeltaOperation?.resulting_room_state_root,
    room_receipt_root: recoveredDeltaOperation?.receipt_root,
    admission_and_replay_refs: [
      ...new Set([
        ...(pendingDeltaIntent?.candidate_room?.admission_and_replay_refs || []),
        recoveredDeltaOperation?.receipt_ref,
      ]),
    ],
  };
  const recoveredDeltaReceipts = familyRecords(
    dataDir,
    "outcome-room-system-receipts",
  );
  const recoveredDeltaReceipt = recoveredDeltaReceipts.find(
    () => false,
  );
  const recoveredDeltaObjects = familyRecords(
    dataDir,
    "outcome-room-admitted-object-projections",
  );
  const recoveredDeltaObject = recoveredDeltaObjects.find(
    (record) => record.object_ref === pendingDeltaRef,
  );
  const admittedDeltaJson = admittedDelta ? canonicalJson(admittedDelta) : "";
  const deltaNonclaimTruth = canonicalJson({
    delta: admittedDelta || null,
    object: recoveredDeltaObject || null,
    receipt: recoveredDeltaReceipt || null,
    operation: pendingDeltaIntent?.operation || null,
  });
  const deltaRetryDurableBefore = roomAdmissionSideEffectSnapshot(dataDir);
  const exactDeltaRetry = await call(
    "POST",
    `/v1/goal-orchestration/goal-runs/${collectiveGoalRunId}/outcome-deltas`,
    deltaRequestBody,
  );
  const deltaRetryDurableAfter = roomAdmissionSideEffectSnapshot(dataDir);
  check(
    "ROOM DELTA RECOVERY: restart converges exactly one canonical delta, parent backlink, receipt, and room head",
    recoveredDeltaRoom.status === 200 &&
      room?.latest_sequence === preDeltaFaultRevision + 1 &&
      canonicalJson(room) === canonicalJson(pendingDeltaRoom) &&
      canonicalJson(room) === canonicalJson(expectedRecoveredDeltaRoom) &&
      familyCount(dataDir, "outcome-room-child-admission-intents") === 0 &&
      admittedDelta?.schema_version === "ioi.foundations.outcome-delta.v3" &&
      admittedDelta?.status === "proposed" &&
      canonicalJson(admittedDelta) === canonicalJson(pendingDelta) &&
      admittedDelta?.system_binding?.system_id === SYSTEM_ID &&
      admittedDelta?.system_binding?.parent_scope_ref === room?.outcome_room_id &&
      admittedDelta?.system_binding?.payload_root ===
        systemScopedPayloadRoot(admittedDelta) &&
      recoveredDeltaReplay.status === 200 &&
      recoveredDeltaOperation?.sequence === room?.latest_sequence &&
      recoveredDeltaOperation?.object_root ===
        pendingDelta?.system_binding?.payload_root &&
      recoveredDeltaOperation?.resulting_room_state_root === room?.room_state_root &&
      recoveredDeltaOperation?.receipt_root === room?.room_receipt_root &&
      recoveredDeltaReceipts.length === preDeltaFaultReceiptCount &&
      recoveredDeltaObjects.length === preDeltaFaultObjectCount &&
      postDeltaResultPoint.status === 200 &&
      postDeltaResultPoint.body.work_result?.outcome_delta_refs?.length === 1 &&
      postDeltaResultPoint.body.work_result.outcome_delta_refs[0] ===
        admittedDelta?.outcome_delta_id &&
      familyCount(dataDir, "work-result-registry") === 2 &&
      familyCount(dataDir, "outcome-delta-registry") === 1 &&
      versionedDeltaList.status === 200 &&
      versionedDeltaList.body.schema_version ===
        DELTA_REGISTRY_PROJECTION_SCHEMA &&
      canonicalJson(versionedDeltaList.body.accepted_record_schema_versions) ===
        canonicalJson(DELTA_RECORD_SCHEMAS) &&
      canonicalJson(versionedDeltaList.body.record_schema_counts) ===
        canonicalJson({
          "ioi.foundations.outcome-delta.v3": 1,
        }) &&
      versionedDeltaList.body.outcome_deltas?.length === 1 &&
      admittedDeltaPoint.status === 200 &&
      admittedDeltaPoint.body.schema_version ===
        DELTA_REGISTRY_PROJECTION_SCHEMA &&
      admittedDeltaPoint.body.record_schema_version ===
        "ioi.foundations.outcome-delta.v3" &&
      canonicalJson(admittedDeltaPoint.body.outcome_delta) ===
        canonicalJson(admittedDelta),
    `${recoveredDeltaRoom.status}/seq=${room?.latest_sequence}/candidate_room_exact=${canonicalJson(room) === canonicalJson(expectedRecoveredDeltaRoom)}/fault_room_exact=${canonicalJson(room) === canonicalJson(pendingDeltaRoom)}/object_root=${recoveredDeltaOperation?.object_root}/${pendingDelta?.system_binding?.payload_root}/intent=${familyCount(dataDir, "outcome-room-child-admission-intents")}/delta=${admittedDelta?.outcome_delta_id}/${admittedDelta?.system_binding?.system_id}/receipts=${recoveredDeltaReceipts.length}/objects=${recoveredDeltaObjects.length}/results=${familyCount(dataDir, "work-result-registry")}/deltas=${familyCount(dataDir, "outcome-delta-registry")}/schemas=${canonicalJson(versionedDeltaList.body.record_schema_counts)}/points=${admittedDeltaPoint.status}/${admittedDeltaPoint.body.record_schema_version}/${postDeltaResultPoint.status}`,
  );
  check(
    "ROOM DELTA ORA-8: proposal grants no effect or acceptance and exact post-terminal retry is write-free",
      admittedDelta?.status === "proposed" &&
      !Object.prototype.hasOwnProperty.call(
        admittedDelta || {},
        "inherited_information_flow_label_refs",
      ) &&
      !deltaNonclaimTruth.includes('"effect_executed"') &&
      !deltaNonclaimTruth.includes('"acceptance_granted"') &&
      canonicalJson(admittedDelta?.information_flow_label_refs) ===
        canonicalJson(admittedResultLabels) &&
      exactDeltaRetry.status === 409 &&
      exactDeltaRetry.body.error?.code ===
        "outcome_room_delta_post_terminal_retry_refused" &&
      deltaRetryDurableAfter === deltaRetryDurableBefore &&
      familyCount(dataDir, "outcome-delta-registry") === 1 &&
      room.latest_sequence === preDeltaFaultRevision + 1,
    `status=${admittedDelta?.status}/effect_field=${admittedDeltaJson.includes('"effect_executed"')}/acceptance_field=${admittedDeltaJson.includes('"acceptance_granted"')}/retry=${exactDeltaRetry.status}/${exactDeltaRetry.body.error?.code}/whole_tree_unchanged=${deltaRetryDurableAfter === deltaRetryDurableBefore}/deltas=${familyCount(dataDir, "outcome-delta-registry")}/room_seq=${room?.latest_sequence}`,
  );
  requireValue(admittedDelta, "room OutcomeDelta admission failed");

  // 7. All projections derive from the exact owner head and export no payloads. M5-owned child
  // lifecycles remain honestly empty.
  const graphResponse = await call("GET", graphPath);
  const discussionResponse = await call("GET", discussionPath);
  const productResponse = await call("GET", productPath);
  const replayResponse = await call("GET", replayPath);
  const graph = graphResponse.body.collaborative_work_graph;
  const discussion = discussionResponse.body.discussion_projection;
  const product = productResponse.body;
  const resultAdmissionOperation = replayResponse.body.operations?.find(
    (operation) => operation.object_ref === admittedResult.work_result_id,
  );
  const deltaAdmissionOperation = replayResponse.body.operations?.find(
    (operation) => operation.object_ref === admittedDelta.outcome_delta_id,
  );
  const resultAdmissionReceiptRef = resultAdmissionOperation?.receipt_ref;
  const deltaAdmissionReceiptRef = deltaAdmissionOperation?.receipt_ref;
  check(
    "GRAPH: canonical collaborative-work projection is available and schema-valid",
    graphResponse.status === 200 && validateGraph(graph),
    `${graphResponse.status}/${ajv.errorsText(validateGraph.errors)}`,
  );
  check(
    "GRAPH: projection derives from the exact room revision and state root",
    graph?.source_room_revision === room.latest_sequence &&
      graph?.source_room_state_root === room.room_state_root &&
      graph?.authoritative === false &&
      graph?.client_writable === false,
    `seq=${graph?.source_room_revision}/root=${graph?.source_room_state_root}`,
  );
  check(
    "GRAPH: reciprocal GoalRun membership reconstructs at the selected head",
    graph?.member_goal_run_refs?.length === 1 &&
      graph.member_goal_run_refs[0] === collectiveGoal.goal_ref &&
      !graph.member_goal_run_refs.includes(direct.goalRun.goal_ref),
    `${collectiveGoal.goal_ref}/members=${graph?.member_goal_run_refs?.length}`,
  );
  check(
    "GRAPH: admitted WorkResult, OutcomeDelta, and receipt chain reconstruct together",
    graph?.work_result_refs?.length === 1 &&
      graph.work_result_refs[0] === admittedResult.work_result_id &&
      graph?.outcome_delta_refs?.length === 1 &&
      graph.outcome_delta_refs[0] === admittedDelta.outcome_delta_id &&
      graph?.source_admission_receipt_refs?.length === room.latest_sequence + 1 &&
      resultAdmissionOperation?.object_root ===
        admittedResult.system_binding.payload_root &&
      deltaAdmissionOperation?.object_root ===
        admittedDelta.system_binding.payload_root,
    `results=${graph?.work_result_refs?.length}/deltas=${graph?.outcome_delta_refs?.length}/receipts=${graph?.source_admission_receipt_refs?.length}`,
  );
  check(
    "DISCUSSION: durable projection is available and schema-valid",
    discussionResponse.status === 200 && validateDiscussion(discussion),
    `${discussionResponse.status}/${ajv.errorsText(validateDiscussion.errors)}`,
  );
  check(
    "DISCUSSION: projection derives from the exact room revision and state root",
    discussion?.source_room_revision === room.latest_sequence &&
      discussion?.source_room_state_root === room.room_state_root &&
      discussion?.authoritative === false &&
      discussion?.client_writable === false,
    `seq=${discussion?.source_room_revision}/root=${discussion?.source_room_state_root}`,
  );
  check(
    "DISCUSSION: message and redaction state remains honestly empty",
    discussion?.message_refs?.length === 0 &&
      discussion?.redaction_summary_refs?.length === 0,
    `messages=${discussion?.message_refs?.length}/redactions=${discussion?.redaction_summary_refs?.length}`,
  );
  const predecessorProfileWritePaths = [
    "/v1/goal-orchestration/room-participation-requests",
    "/v1/goal-orchestration/work-frontier-items",
    "/v1/goal-orchestration/work-claim-leases",
    "/v1/goal-orchestration/resource-offers",
    "/v1/goal-orchestration/capability-offers",
    "/v1/goal-orchestration/work-eligibility-matches",
    "/v1/goal-orchestration/attempts",
    "/v1/goal-orchestration/findings",
    "/v1/goal-orchestration/verifier-challenges",
  ];
  const predecessorProfileReadPaths = [
    "/v1/goal-orchestration/room-participation-requests",
    "/v1/goal-orchestration/room-participant-leases",
    "/v1/goal-orchestration/work-frontier-items",
    "/v1/goal-orchestration/work-claim-leases",
    "/v1/goal-orchestration/resource-offers",
    "/v1/goal-orchestration/capability-offers",
    "/v1/goal-orchestration/work-eligibility-matches",
    "/v1/goal-orchestration/attempts",
    "/v1/goal-orchestration/findings",
    "/v1/goal-orchestration/verifier-challenges",
  ];
  const predecessorProfileSnapshotBefore =
    roomAdmissionSideEffectSnapshot(dataDir);
  const predecessorProfileWriteResponses = await Promise.all(
    predecessorProfileWritePaths.map((path) =>
      call("POST", path, { outcome_room_ref: room.outcome_room_id }),
    ),
  );
  const predecessorProfileReadResponses = await Promise.all(
    predecessorProfileReadPaths.map((path) =>
      call(
        "GET",
        `${path}?room=${encodeURIComponent(room.outcome_room_id)}`,
      ),
    ),
  );
  const predecessorProfileSnapshotAfter =
    roomAdmissionSideEffectSnapshot(dataDir);
  const predecessorFixtureMarker = "m4-predecessor-fixture-must-not-leak";
  const frontierTail = `wfi_${"a".repeat(64)}`;
  const claimTail = `wcl_${"b".repeat(64)}`;
  const resourceTail = `rof_${"c".repeat(64)}`;
  const capabilityTail = `cof_${"d".repeat(64)}`;
  const matchTail = `wem_${"e".repeat(64)}`;
  const attemptTail = `att_${"f".repeat(64)}`;
  const findingTail = `fnd_${"1".repeat(64)}`;
  const challengeTail = `vc_${"2".repeat(64)}`;
  const predecessorProfileFixtures = [
    {
      family: "room-participation-requests",
      tail: "rpr_ab",
      basePath: "/v1/goal-orchestration/room-participation-requests",
      listField: "participation_requests",
      record: {
        schema_version: "ioi.hypervisor.room-participation-request.v1",
        participation_request_id: "participation-request://rpr_ab",
        outcome_room_ref: room.outcome_room_id,
        requested_by_ref: "worker://m4-predecessor-probe",
        status: "submitted",
        revision: 1,
        marker: predecessorFixtureMarker,
      },
      transition: { transition: "evaluate", expected_revision: 1 },
    },
    {
      family: "room-participant-leases",
      tail: "rpl_ab",
      basePath: "/v1/goal-orchestration/room-participant-leases",
      listField: "participant_leases",
      record: {
        schema_version: "ioi.hypervisor.room-participant-lease.v1",
        participant_lease_id: "participant-lease://rpl_ab",
        outcome_room_ref: room.outcome_room_id,
        participant_ref: "worker://m4-predecessor-probe",
        join_request_ref: "participation-request://rpr_ab",
        status: "active",
        revision: 1,
        marker: predecessorFixtureMarker,
      },
      transition: { transition: "sleep", expected_revision: 1 },
    },
    {
      family: "work-frontier-items",
      tail: frontierTail,
      basePath: "/v1/goal-orchestration/work-frontier-items",
      listField: "frontier_items",
      overview: true,
      record: {
        schema_version: "ioi.hypervisor.work-frontier-item.v1",
        frontier_item_id: `frontier://${frontierTail}`,
        outcome_room_ref: room.outcome_room_id,
        status: "open",
        revision: 1,
        marker: predecessorFixtureMarker,
      },
      transition: { transition: "block", expected_revision: 1 },
    },
    {
      family: "work-claim-leases",
      tail: claimTail,
      basePath: "/v1/goal-orchestration/work-claim-leases",
      listField: "work_claims",
      overview: true,
      record: {
        schema_version: "ioi.hypervisor.work-claim-lease.v1",
        work_claim_id: `work-claim://${claimTail}`,
        outcome_room_ref: room.outcome_room_id,
        frontier_item_ref: `frontier://${frontierTail}`,
        claimant_ref: "participant-lease://rpl_ab",
        eligibility_match_receipt_ref: null,
        status: "active",
        revision: 1,
        marker: predecessorFixtureMarker,
      },
      transition: { transition: "wait", expected_revision: 1 },
    },
    {
      family: "resource-offers",
      tail: resourceTail,
      basePath: "/v1/goal-orchestration/resource-offers",
      listField: "resource_offers",
      overview: true,
      record: {
        schema_version: "ioi.hypervisor.resource-offer.v1",
        resource_offer_id: `resource-offer://${resourceTail}`,
        outcome_room_ref: room.outcome_room_id,
        provider_participant_lease_ref: "participant-lease://rpl_ab",
        status: "offered",
        revision: 1,
        marker: predecessorFixtureMarker,
      },
      transition: { transition: "withdraw", expected_revision: 1 },
    },
    {
      family: "capability-offers",
      tail: capabilityTail,
      basePath: "/v1/goal-orchestration/capability-offers",
      listField: "capability_offers",
      overview: true,
      record: {
        schema_version: "ioi.hypervisor.capability-offer.v1",
        capability_offer_id: `capability-offer://${capabilityTail}`,
        outcome_room_ref: room.outcome_room_id,
        provider_participant_lease_ref: "participant-lease://rpl_ab",
        status: "offered",
        revision: 1,
        marker: predecessorFixtureMarker,
      },
      transition: { transition: "withdraw", expected_revision: 1 },
    },
    {
      family: "resource-capability-offer-receipts",
      tail: matchTail,
      basePath: "/v1/goal-orchestration/work-eligibility-matches",
      listField: "eligibility_match_receipts",
      overview: true,
      record: {
        schema_version: "ioi.hypervisor.work-eligibility-match-receipt.v1",
        receipt_ref: `receipt://${matchTail}`,
        receipt_type: "WorkEligibilityMatchReceipt",
        outcome_room_ref: "outcome-room://or_aa",
        bound_facts: { outcome_room_ref: room.outcome_room_id },
        marker: predecessorFixtureMarker,
      },
    },
    {
      family: "attempts",
      tail: attemptTail,
      basePath: "/v1/goal-orchestration/attempts",
      listField: "attempts",
      overview: true,
      record: {
        schema_version: "ioi.hypervisor.attempt-envelope.v1",
        attempt_id: `attempt://${attemptTail}`,
        outcome_room_ref: room.outcome_room_id,
        status: "draft",
        revision: 1,
        marker: predecessorFixtureMarker,
      },
      transition: { transition: "start", expected_revision: 1 },
    },
    {
      family: "findings",
      tail: findingTail,
      basePath: "/v1/goal-orchestration/findings",
      listField: "findings",
      overview: true,
      record: {
        schema_version: "ioi.hypervisor.finding-envelope.v1",
        finding_id: `finding://${findingTail}`,
        outcome_room_ref: room.outcome_room_id,
        status: "proposed",
        revision: 1,
        marker: predecessorFixtureMarker,
      },
      transition: { transition: "supersede", expected_revision: 1 },
    },
    {
      family: "verifier-challenges",
      tail: challengeTail,
      basePath: "/v1/goal-orchestration/verifier-challenges",
      listField: "verifier_challenges",
      overview: true,
      record: {
        schema_version: "ioi.hypervisor.verifier-challenge-envelope.v1",
        verifier_challenge_id: `verifier-challenge://${challengeTail}`,
        outcome_room_ref: room.outcome_room_id,
        challenged_ref: "",
        challenger_ref: "",
        affected_attempt_refs: [],
        status: "proposed",
        revision: 1,
        marker: predecessorFixtureMarker,
      },
      transition: { transition: "withdraw", expected_revision: 1 },
    },
  ];
  const predecessorFixtureCleanups = [];
  let predecessorFixtureGetResponses = [];
  let predecessorFixtureUnfilteredResponses = [];
  let predecessorFixtureOverviewResponses = [];
  let predecessorFixtureTransitionResponses = [];
  let predecessorFixtureBytesUnchanged = false;
  let predecessorFixtureSnapshotBefore;
  let predecessorFixtureSnapshotAfter;
  try {
    for (const fixture of predecessorProfileFixtures) {
      predecessorFixtureCleanups.push(
        installIsolatedJsonFixture(
          dataDir,
          fixture.family,
          fixture.tail,
          fixture.record,
        ),
      );
    }
    predecessorFixtureSnapshotBefore =
      roomAdmissionSideEffectSnapshot(dataDir);
    predecessorFixtureGetResponses = await Promise.all(
      predecessorProfileFixtures.map((fixture) =>
        call("GET", `${fixture.basePath}/${fixture.tail}`),
      ),
    );
    predecessorFixtureUnfilteredResponses = await Promise.all(
      predecessorProfileFixtures.map((fixture) => call("GET", fixture.basePath)),
    );
    predecessorFixtureOverviewResponses = await Promise.all(
      predecessorProfileFixtures
        .filter((fixture) => fixture.overview)
        .map((fixture) => call("GET", `${fixture.basePath}/overview`)),
    );
    predecessorFixtureTransitionResponses = await Promise.all(
      predecessorProfileFixtures
        .filter((fixture) => fixture.transition)
        .map((fixture) =>
          call(
            "POST",
            `${fixture.basePath}/${fixture.tail}/transition`,
            fixture.transition,
          ),
        ),
    );
    predecessorFixtureSnapshotAfter =
      roomAdmissionSideEffectSnapshot(dataDir);
    predecessorFixtureBytesUnchanged = predecessorFixtureCleanups.every(
      (fixture) =>
        existsSync(fixture.path) &&
        readFileSync(fixture.path).equals(fixture.bytes),
    );
  } finally {
    for (const fixture of predecessorFixtureCleanups.reverse()) fixture.cleanup();
  }
  const predecessorProfileFenceTests =
    await runPredecessorChildProfileFenceTests();
  const predecessorProfileResponses = [
    ...predecessorProfileWriteResponses,
    ...predecessorProfileReadResponses,
    ...predecessorFixtureGetResponses,
    ...predecessorFixtureUnfilteredResponses,
    ...predecessorFixtureOverviewResponses,
    ...predecessorFixtureTransitionResponses,
  ];
  const predecessorProfileForbidden = wireTokenVariants([
    SYSTEM_ID,
    GENESIS_ID,
    CONSTITUTION_REF,
    room.room_state_root,
    room.room_receipt_root,
    collectiveGoal.goal_ref,
    predecessorFixtureMarker,
  ]);
  check(
    "M5 BOUNDARY: predecessor writes/reads/completers fail closed and M4 projections stay empty",
    predecessorProfileWriteResponses.length === 9 &&
      predecessorProfileWriteResponses.every(
        (response) =>
          response.status >= 400 &&
          response.status < 500 &&
          response.body.error?.code ===
            "outcome_room_predecessor_child_profile_retired",
      ) &&
      predecessorProfileReadResponses.length === 10 &&
      predecessorProfileReadResponses.every(
        (response) =>
          response.status >= 400 &&
          response.status < 500 &&
          response.body.error?.code ===
            "outcome_room_predecessor_child_profile_retired",
      ) &&
      predecessorFixtureGetResponses.length === 10 &&
      predecessorFixtureGetResponses.every(
        (response) =>
          response.status >= 400 &&
          response.status < 500 &&
          response.body.error?.code ===
            "outcome_room_predecessor_child_profile_retired",
      ) &&
      predecessorFixtureTransitionResponses.length === 9 &&
      predecessorFixtureTransitionResponses.every(
        (response) =>
          response.status >= 400 &&
          response.status < 500 &&
          response.body.error?.code ===
            "outcome_room_predecessor_child_profile_retired",
      ) &&
      predecessorFixtureUnfilteredResponses.length === 10 &&
      predecessorFixtureUnfilteredResponses.every(
        (response, index) =>
          response.status === 200 &&
          Array.isArray(
            response.body[predecessorProfileFixtures[index].listField],
          ) &&
          response.body[predecessorProfileFixtures[index].listField].length ===
            0 &&
          !response.raw.includes(predecessorFixtureMarker),
      ) &&
      predecessorFixtureOverviewResponses.length === 8 &&
      predecessorFixtureOverviewResponses.every(
        (response) =>
          response.status === 200 &&
          response.body.count === 0 &&
          !response.raw.includes(predecessorFixtureMarker),
      ) &&
      predecessorFixtureBytesUnchanged &&
      predecessorProfileResponses.every((response) =>
        responseOmitsWireTokens(response, predecessorProfileForbidden),
      ) &&
      predecessorProfileSnapshotAfter === predecessorProfileSnapshotBefore &&
      predecessorFixtureSnapshotAfter === predecessorFixtureSnapshotBefore &&
      predecessorProfileFenceTests.code === 0 &&
      predecessorProfileFenceTests.failure === null &&
      /test .*predecessor_child_profile_generation_fence_defers_noncanonical_coordinates \.\.\. ok/u.test(
        predecessorProfileFenceTests.output,
      ) &&
      /test .*predecessor_child_profile_historical_filter_checks_every_candidate_coordinate \.\.\. ok/u.test(
        predecessorProfileFenceTests.output,
      ) &&
      [
        "participation_submit",
        "frontier_claim",
        "offer_match",
        "attempt_finding",
        "verifier_challenge",
      ].every((family) =>
        new RegExp(
          `test .*predecessor_child_profile_retains_${family}_intent_bytes \\.\\.\\. ok`,
          "u",
        ).test(predecessorProfileFenceTests.output),
      ) &&
      /7 passed; 0 failed/u.test(predecessorProfileFenceTests.output) &&
    [
      "participant_refs",
      "frontier_item_refs",
      "work_claim_refs",
      "attempt_refs",
      "finding_refs",
      "verifier_challenge_refs",
    ].every((field) => Array.isArray(graph?.[field]) && graph[field].length === 0) &&
      [
        "room-participation-requests",
        "room-participant-leases",
        "work-frontier-items",
        "work-claim-leases",
        "attempts",
        "findings",
        "verifier-challenges",
        "resource-offers",
        "capability-offers",
      ].every((family) => familyCount(dataDir, family) === 0) &&
      familyCount(dataDir, "outcome-room-admitted-object-projections") === 0 &&
      replayResponse.body.operations?.every(
        (operation) =>
          operation.typed_payload?.schema_version !==
          "ioi.applications.ioi-ai.participant-state-bundle.v2",
      ),
    `creates=${predecessorProfileWriteResponses.map((response) => `${response.status}/${response.body.error?.code}`).join(",")}/room_reads=${predecessorProfileReadResponses.map((response) => `${response.status}/${response.body.error?.code}`).join(",")}/gets=${predecessorFixtureGetResponses.map((response) => `${response.status}/${response.body.error?.code}`).join(",")}/transitions=${predecessorFixtureTransitionResponses.map((response) => `${response.status}/${response.body.error?.code}`).join(",")}/unfiltered=${predecessorFixtureUnfilteredResponses.map((response) => response.status).join(",")}/overviews=${predecessorFixtureOverviewResponses.map((response) => `${response.status}/${response.body.count}`).join(",")}/fixture_bytes_unchanged=${predecessorFixtureBytesUnchanged}/base_tree=${predecessorProfileSnapshotAfter === predecessorProfileSnapshotBefore}/fixture_tree=${predecessorFixtureSnapshotAfter === predecessorFixtureSnapshotBefore}/deep=${predecessorProfileFenceTests.code}`,
  );
  const projectionResponses = [
    graphResponse,
    discussionResponse,
    productResponse,
    replayResponse,
  ];
  const exportedWireBytes = projectionResponses
    .map(responseWireMaterial)
    .join("\n");
  const projectionCustodyForbidden = wireTokenVariants([
    admittedResult.result_payload_ref,
    "state-delta://ioi/m4/room-course-correction",
    completedOutputText,
    successfulInvocation.candidate_workspace_root,
    completedOutputPath,
  ]);
  const projectionPaths = [
    graphPath,
    discussionPath,
    productPath,
    replayPath,
  ];
  const resultRegistryDirectory = join(dataDir, "work-result-registry");
  const deltaRegistryDirectory = join(dataDir, "outcome-delta-registry");
  const admittedResultRegistryEntry = requireValue(
    strictFamilyEntries(dataDir, "work-result-registry")
      .map((entry) => {
        const path = join(resultRegistryDirectory, entry.name);
        const bytes = readFileSync(path);
        return { bytes, entry, path, record: JSON.parse(bytes.toString("utf8")) };
      })
      .find(
        ({ record }) =>
          record.work_result_id === admittedResult.work_result_id,
    ),
    "BLOCKED: admitted M4 WorkResult registry slot is absent",
  );
  let malformedSelectedSourceTreeUnchanged = false;
  const malformedSelectedSource = await (async () => {
    try {
      writeFileSync(admittedResultRegistryEntry.path, Buffer.from("{not-json"));
      const treeBefore = roomAdmissionSideEffectSnapshot(dataDir);
      const response = await call("GET", productPath);
      malformedSelectedSourceTreeUnchanged =
        roomAdmissionSideEffectSnapshot(dataDir) === treeBefore;
      return response;
    } finally {
      writeFileSync(
        admittedResultRegistryEntry.path,
        admittedResultRegistryEntry.bytes,
      );
    }
  })();
  const unreadableDeltaEntryPath = join(
    deltaRegistryDirectory,
    "unreadable-projection-source.json",
  );
  let unreadableSelectedSourceTreeUnchanged = false;
  const unreadableSelectedSource = await (async () => {
    try {
      mkdirSync(unreadableDeltaEntryPath);
      const treeBefore = roomAdmissionSideEffectSnapshot(dataDir);
      const response = await call("GET", productPath);
      unreadableSelectedSourceTreeUnchanged =
        roomAdmissionSideEffectSnapshot(dataDir) === treeBefore;
      return response;
    } finally {
      rmSync(unreadableDeltaEntryPath, { recursive: true, force: true });
    }
  })();
  const relocatedResultPath = join(
    resultRegistryDirectory,
    "relocated-projection-source.json",
  );
  let relocatedSelectedSourceTreeUnchanged = false;
  const relocatedSelectedSource = await (async () => {
    try {
      writeFileSync(relocatedResultPath, admittedResultRegistryEntry.bytes, {
        flag: "wx",
      });
      const treeBefore = roomAdmissionSideEffectSnapshot(dataDir);
      const response = await call("GET", productPath);
      relocatedSelectedSourceTreeUnchanged =
        roomAdmissionSideEffectSnapshot(dataDir) === treeBefore;
      return response;
    } finally {
      rmSync(relocatedResultPath, { force: true });
    }
  })();
  const duplicateCurrentAliasPath = join(
    resultRegistryDirectory,
    `${genericCurrentWorkResultId.replace(/[^a-zA-Z0-9_-]/gu, "_")}.json`,
  );
  let duplicateSelectedSourceTreeUnchanged = false;
  const duplicateSelectedSource = await (async () => {
    try {
      writeFileSync(duplicateCurrentAliasPath, genericCurrentBytes, {
        flag: "wx",
      });
      const treeBefore = roomAdmissionSideEffectSnapshot(dataDir);
      const response = await call("GET", productPath);
      duplicateSelectedSourceTreeUnchanged =
        roomAdmissionSideEffectSnapshot(dataDir) === treeBefore;
      return response;
    } finally {
      rmSync(duplicateCurrentAliasPath, { force: true });
    }
  })();
  const ownerRegistryRefusalResponses = [
    malformedSelectedSource,
    unreadableSelectedSource,
    relocatedSelectedSource,
    duplicateSelectedSource,
  ];
  let missingCustodyProjectionResponses = [];
  let missingCustodyProjectionTreeUnchanged = false;
  try {
    rmSync(resultPayloadPath, { force: true });
    const treeBefore = roomAdmissionSideEffectSnapshot(dataDir);
    for (const path of projectionPaths) {
      missingCustodyProjectionResponses.push(await call("GET", path));
    }
    missingCustodyProjectionTreeUnchanged =
      roomAdmissionSideEffectSnapshot(dataDir) === treeBefore;
  } finally {
    writeFileSync(resultPayloadPath, resultPayloadBytes);
  }
  let substitutedCustodyProjectionResponses = [];
  let substitutedCustodyProjectionTreeUnchanged = false;
  try {
    writeFileSync(
      resultPayloadPath,
      Buffer.concat([resultPayloadBytes, Buffer.from("\nprojection-substitution\n")]),
    );
    const treeBefore = roomAdmissionSideEffectSnapshot(dataDir);
    for (const path of projectionPaths) {
      substitutedCustodyProjectionResponses.push(await call("GET", path));
    }
    substitutedCustodyProjectionTreeUnchanged =
      roomAdmissionSideEffectSnapshot(dataDir) === treeBefore;
  } finally {
    writeFileSync(resultPayloadPath, resultPayloadBytes);
  }
  const custodyRefusalResponses = [
    ...missingCustodyProjectionResponses,
    ...substitutedCustodyProjectionResponses,
  ];
  const custodyAllRefusalResponses = [
    ...ownerRegistryRefusalResponses,
    ...custodyRefusalResponses,
  ];
  const custodyRefusalWireBytes = custodyAllRefusalResponses
    .map(responseWireMaterial)
    .join("\n");
  check(
    "PRODUCT: selected owner projection is available at the exact room head",
    productResponse.status === 200 &&
      product?.outcome_room?.room_state_root === room.room_state_root,
    `${productResponse.status}/${product?.outcome_room?.room_state_root}`,
  );
  check(
    "PRODUCT: selected summaries contain the admitted member, result, and delta",
    product?.member_goal_runs?.length === 1 &&
      product.member_goal_runs[0]?.goal_run_ref === collectiveGoal.goal_ref &&
      product.member_goal_runs[0]?.goal_run_ref !== direct.goalRun.goal_ref &&
      product?.work_results?.length === 1 &&
      product.work_results[0]?.work_result_id === admittedResult.work_result_id &&
      product?.outcome_deltas?.length === 1 &&
      product.outcome_deltas[0]?.outcome_delta_id === admittedDelta.outcome_delta_id,
    `members=${product?.member_goal_runs?.length}/results=${product?.work_results?.length}/deltas=${product?.outcome_deltas?.length}`,
  );
  check(
    "PRODUCT EXPORT: owner projection explicitly exports neither payload refs nor payload bytes",
    product?.payload_refs_exported === false &&
      product?.payload_bytes_exported === false,
    `${product?.payload_refs_exported}/${product?.payload_bytes_exported}`,
  );
  check(
    "PRODUCT/PROJECTION CUSTODY: bounded reads refuse partial owner registries and missing or substituted payload bytes",
    projectionResponses.every(
      (response) =>
        response.status === 200 &&
        typeof response.raw === "string" &&
        response.raw.length > 0 &&
        Buffer.byteLength(response.raw) <= 4 * 1024 * 1024,
    ) &&
      projectionCustodyForbidden.every(
        (forbidden) => !exportedWireBytes.includes(forbidden),
      ) &&
      custodyRefusalResponses.length === projectionPaths.length * 2 &&
      custodyRefusalResponses.every(
        (response) =>
          response.status === 503 &&
          response.body.error?.code ===
            "outcome_room_projection_runtime_dependency_unresolved",
      ) &&
      ownerRegistryRefusalResponses.length === 4 &&
      ownerRegistryRefusalResponses.every(
        (response) =>
          response.status === 503 &&
          response.body.error?.code ===
            "outcome_room_projection_owner_source_unreadable",
      ) &&
      custodyAllRefusalResponses.every((response) =>
        responseOmitsWireTokens(response, projectionCustodyForbidden),
      ) &&
      malformedSelectedSourceTreeUnchanged &&
      unreadableSelectedSourceTreeUnchanged &&
      relocatedSelectedSourceTreeUnchanged &&
      duplicateSelectedSourceTreeUnchanged &&
      missingCustodyProjectionTreeUnchanged &&
      substitutedCustodyProjectionTreeUnchanged,
    `wire_bytes=${Buffer.byteLength(exportedWireBytes)}/owner_registry=${ownerRegistryRefusalResponses.map((response) => `${response.status}/${response.body.error?.code}`).join(",")}/missing=${missingCustodyProjectionResponses.map((response) => `${response.status}/${response.body.error?.code}`).join(",")}/substituted=${substitutedCustodyProjectionResponses.map((response) => `${response.status}/${response.body.error?.code}`).join(",")}/refusal_wire_bytes=${Buffer.byteLength(custodyRefusalWireBytes)}/trees=${[malformedSelectedSourceTreeUnchanged, unreadableSelectedSourceTreeUnchanged, relocatedSelectedSourceTreeUnchanged, duplicateSelectedSourceTreeUnchanged, missingCustodyProjectionTreeUnchanged, substitutedCustodyProjectionTreeUnchanged].join(",")}`,
  );
  check(
    "REPLAY: Agentgres projection is available at the exact room head",
    replayResponse.status === 200 &&
      replayResponse.body.latest_sequence === room.latest_sequence &&
      replayResponse.body.room_state_root === room.room_state_root,
    `${replayResponse.status}/seq=${replayResponse.body.latest_sequence}`,
  );
  check(
    "REPLAY: contiguous operations reconstruct genesis through the current revision",
    replayResponse.body.operations?.length === room.latest_sequence + 1,
    `ops=${replayResponse.body.operations?.length}`,
  );
  check(
    "REPLAY EXPORT: operation projection contains neither payload bytes nor admitted objects",
      replayResponse.body.payload_bytes_exported === false &&
      replayResponse.body.operations?.every(
        (operation) => !Object.hasOwn(operation, "admitted_object"),
      ),
    `payload_bytes_exported=${replayResponse.body.payload_bytes_exported}`,
  );
  const headBeforeWrites = room.room_state_root;
  const directWriteDurableBefore = roomAdmissionSideEffectSnapshot(dataDir);
  const directWriteProbeCases = ["POST", "PUT", "PATCH", "DELETE"].flatMap(
    (method) => [
      {
        name: `${method} canonical graph`,
        method,
        path: graphPath,
        body: { frontier_item_refs: ["frontier://forged"] },
        expectedStatus: 405,
      },
      {
        name: `${method} discussion`,
        method,
        path: discussionPath,
        body: { message_refs: ["message://forged"] },
        expectedStatus: 405,
      },
      {
        name: `${method} graph alias`,
        method,
        path: `${roomPath}/graph`,
        body: { frontier_item_refs: ["frontier://forged"] },
        expectedStatus: 404,
      },
    ],
  );
  const directWriteProbeResponses = await Promise.all(
    directWriteProbeCases.map((probe) =>
      call(probe.method, probe.path, probe.body),
    ),
  );
  const afterWrites = await call("GET", roomPath);
  const directWriteDurableAfter = roomAdmissionSideEffectSnapshot(dataDir);
  check(
    "DIRECT-WRITE REFUSAL: no graph/discussion client mutation moves the owner head",
    afterWrites.body.outcome_room?.room_state_root === headBeforeWrites &&
      directWriteDurableAfter === directWriteDurableBefore,
    `${headBeforeWrites}/${afterWrites.body.outcome_room?.room_state_root}/durable_unchanged=${directWriteDurableAfter === directWriteDurableBefore}`,
  );
  check(
    "FROZEN THRESHOLD: m4.direct_client_shared_graph_writes = 0",
    directWriteProbeResponses.every(
      (response, index) =>
        response.status === directWriteProbeCases[index].expectedStatus,
    ) &&
      directWriteProbeResponses.filter(
        (response) => response.status >= 200 && response.status < 300,
      ).length === 0,
    directWriteProbeCases
      .map(
        (probe, index) =>
          `${probe.name}=${directWriteProbeResponses[index].status}`,
      )
      .join(" "),
  );
  const predecessorOwnerProbeTail = "or_4d346f776e6572";
  const predecessorOwnerProbeRef = `outcome-room://${predecessorOwnerProbeTail}`;
  const predecessorOwnerProbeMarker = "m4-predecessor-owner-probe-must-not-leak";
  const predecessorOwnerProbe = installIsolatedJsonFixture(
    dataDir,
    "outcome-room-registry",
    predecessorOwnerProbeTail,
    {
      schema_version: "ioi.applications.ioi-ai.outcome-room.v1",
      outcome_room_id: predecessorOwnerProbeRef,
      owner_or_sponsor_ref: LOCAL_OWNER,
      system_id: "system://ioi/outcome-room/predecessor-owner-probe",
      marker: predecessorOwnerProbeMarker,
    },
  );
  // Span the complete adversarial read/write batch. Equality must cover room wrappers,
  // projections, GoalRun events, legacy owner planes, shell routes, and cache helpers—not merely
  // the final subset—so a refusal cannot hide a metadata-only or hard-link side effect.
  const exposedOwnerReadsDurableBefore = roomAdmissionSideEffectSnapshot(dataDir);
  const exposedProduct = await call("GET", productPath, undefined, {
    "x-ioi-forwarded": "m4-aggregate-verifier",
  });
  const exposedGraph = await call("GET", graphPath, undefined, {
    "x-ioi-forwarded": "m4-aggregate-verifier",
  });
  const exposedDiscussion = await call("GET", discussionPath, undefined, {
    "x-ioi-forwarded": "m4-aggregate-verifier",
  });
  const exposedReplay = await call("GET", replayPath, undefined, {
    "x-ioi-forwarded": "m4-aggregate-verifier",
  });
  // A genuinely absent canonical slot proves the missing-room anti-oracle. A mnemonic stem is
  // not a valid OutcomeRoom key and correctly exercises source-unreadable semantics instead.
  const missingRoomPath =
    "/v1/goal-orchestration/outcome-rooms/or_4d34616273656e74";
  const exposedMissingReads = await Promise.all(
    [
      missingRoomPath,
      `${missingRoomPath}/product-projection`,
      `${missingRoomPath}/collaborative-work-graph`,
      `${missingRoomPath}/discussion-projection`,
      `${missingRoomPath}/replay`,
    ].map((path) =>
      call("GET", path, undefined, {
        "x-ioi-forwarded": "m4-aggregate-verifier",
      }),
    ),
  );
  const exposedCurrentRoomWrappers = await Promise.all(
    [
      "/v1/goal-orchestration/outcome-rooms",
      "/v1/goal-orchestration/outcome-rooms/overview",
      roomPath,
    ].map((path) =>
      call("GET", path, undefined, {
        "x-ioi-forwarded": "m4-aggregate-verifier",
      }),
    ),
  );
  const exposedEvents = await call("GET", eventPath, undefined, {
    "x-ioi-forwarded": "m4-aggregate-verifier",
  });
  const transcriptRunId = requireValue(
    linkedInvocation?.execution_provenance?.transcript_run_ref,
    "BLOCKED: admitted invocation omitted its durable transcript_run_ref",
  );
  const transcriptListPath = "/v1/hypervisor/agent-run-transcripts";
  const transcriptPointPath =
    `${transcriptListPath}/${encodeURIComponent(transcriptRunId)}`;
  const workLedgerPath = "/v1/hypervisor/work-ledger";
  const exposedTranscriptWriteId = "m4_forbidden_exposed_transcript";
  const outsiderTranscriptWriteId = "m4_forbidden_outsider_transcript";
  const timelineEnvProbeId = "m4_forbidden_timeline_environment";
  const timelineDraftProbeId = "m4_forbidden_timeline_draft";
  const agentServiceSendProbeText =
    "m4 forbidden managed agent-service mutation probe";
  const agentServiceSendProbeBlockId = "m4-forbidden-managed-input";
  const missingGoalRunProbeId = "gr_m4_missing_owner_probe";
  const missingWorkResultProbeTail = "wr_m4_missing_owner_probe";
  const missingOutcomeDeltaProbeTail = "od_m4_missing_owner_probe";
  const missingWorkTruthGoalRef = "goal://gr_m4_missing_work_truth_owner_probe";
  const forbiddenWorkTruthTargetRef =
    "frontier://m4-forbidden-work-truth-owner-probe";
  const cacheHelperPaths = [
    `/__ioi/env-latest-run/${encodeURIComponent(timelineEnvProbeId)}`,
    `/__ioi/agent-runs/${encodeURIComponent(transcriptRunId)}/conversation/history`,
    `/__ioi/agent-runs/${encodeURIComponent(transcriptRunId)}/conversation/live`,
    `/__ioi/agent-runs/${encodeURIComponent(transcriptRunId)}/conversation`,
  ];
  const unreboundInternalSurfaceProbeCases = [
    { name: "missions", path: "/__ioi/missions", marker: "<h1>Missions</h1>" },
    {
      name: "incidents",
      path: "/__ioi/missions/incidents",
      marker: "<title>Issues — incidents inbox</title>",
    },
    { name: "workbench", path: "/__ioi/workbench", marker: "<h1>Workbench</h1>" },
    { name: "agent-studio", path: "/__ioi/agent-studio", marker: "<h1>Studio</h1>" },
  ];
  const forbiddenTranscriptBody = (runId) => ({
    schema_version: "ioi.hypervisor.agent-run-transcript.v1",
    run_id: runId,
    kind: "forbidden-managed-substitution",
    status: "done",
    summary: "must never become retained owner truth",
  });
  const timelineOwnerForbidden = wireTokenVariants([
    collectiveGoalRunId,
    collectiveGoal.goal_ref,
    successfulInvocation.harness_invocation_id,
    transcriptRunId,
    linkedInvocation?.implementation_result?.implementation_result_id,
    linkedInvocation?.execution_provenance?.source_candidate_ref,
    admittedResult.work_result_id,
    admittedResult.result_payload_ref,
    genericCurrentWorkResultId,
    genericCurrentResult?.work_subject_ref,
    admittedDelta.outcome_delta_id,
    room.outcome_room_id,
    room.owner_or_sponsor_ref,
    room.system_id,
    room.package_id,
    room.genesis_ref,
    room.constitution_ref,
    room.manifest_ref,
    ...Object.entries(active.chain || {})
      .filter(
        ([field, value]) =>
          typeof value === "string" && /(?:_ref|_root)$/u.test(field),
      )
      .map(([, value]) => value),
    ...Object.entries(active.state || {})
      .filter(
        ([field, value]) =>
          typeof value === "string" && /(?:_ref|_root)$/u.test(field),
      )
      .map(([, value]) => value),
    ...Object.entries(active.source || {})
      .filter(
        ([field, value]) =>
          typeof value === "string" && /(?:Ref|Root|_ref|_root)$/u.test(field),
      )
      .map(([, value]) => value),
    ...Object.values(room.active_profile_refs || {}),
    ...(Array.isArray(room.admission_and_replay_refs)
      ? room.admission_and_replay_refs
      : []),
    ...(Array.isArray(graph?.source_admission_receipt_refs)
      ? graph.source_admission_receipt_refs
      : []),
    ...(Array.isArray(discussion?.source_admission_receipt_refs)
      ? discussion.source_admission_receipt_refs
      : []),
    resultAdmissionReceiptRef,
    deltaAdmissionReceiptRef,
    direct.activation?.activation_receipt_ref,
    ...(Array.isArray(direct.goalRun?.receipt_refs)
      ? direct.goalRun.receipt_refs
      : []),
    ...(Array.isArray(collectiveGoal?.receipt_refs)
      ? collectiveGoal.receipt_refs
      : []),
    session.body.receipt_ref,
    modelRouteProbe.body.receipt_ref,
    successfulInvocation.execution_receipt?.id,
    successfulInvocation.execution_receipt?.receipt_root,
    successfulInvocation.execution_receipt?.model_route_binding_receipt_ref,
    ...(Array.isArray(admittedResult?.authority_and_policy_refs)
      ? admittedResult.authority_and_policy_refs
      : []),
    pendingAuthorityReceipt?.receipt_id,
    pendingAuthorityReceipt?.receipt_ref,
    room.room_state_root,
    room.room_receipt_root,
    completedOutputText,
    exposedTranscriptWriteId,
    outsiderTranscriptWriteId,
    timelineEnvProbeId,
    timelineDraftProbeId,
    agentServiceSendProbeText,
    agentServiceSendProbeBlockId,
    missingGoalRunProbeId,
    missingWorkResultProbeTail,
    missingOutcomeDeltaProbeTail,
    missingWorkTruthGoalRef,
    forbiddenWorkTruthTargetRef,
    predecessorOwnerProbeRef,
    predecessorOwnerProbeMarker,
    "system://ioi/outcome-room/predecessor-owner-probe",
  ]);
  // Anonymous refusal codes are NOT per-case: deny-by-default (a5d88f3da) answers every
  // anonymous /v1 probe with one uniform authentication_required body, asserted by exact
  // byte equality below. Per-case codes exist only for authenticated phases.
  const ownerPointProbeCases = [
    {
      name: "goal-existing",
      path: `/v1/goal-orchestration/goal-runs/${encodeURIComponent(collectiveGoalRunId)}`,
      managedCode: "goal_run_global_truth_owner_mismatch",
      localMissingCode: null,
    },
    {
      name: "goal-missing",
      path: `/v1/goal-orchestration/goal-runs/${encodeURIComponent(missingGoalRunProbeId)}`,
      managedCode: "goal_run_global_truth_owner_mismatch",
      localMissingCode: "goal_run_not_found",
    },
    {
      name: "goal-events-missing",
      path: `/v1/goal-orchestration/goal-runs/${encodeURIComponent(missingGoalRunProbeId)}/events`,
      managedCode: "goal_run_global_truth_owner_mismatch",
      localMissingCode: "goal_run_not_found",
    },
    {
      name: "result-existing",
      path: `/v1/hypervisor/work-results/${encodeURIComponent(admittedResult.work_result_id.replace("work-result://", ""))}`,
      managedCode: "work_result_owner_mismatch",
      localMissingCode: null,
    },
    {
      name: "result-current-generic",
      path: `/v1/hypervisor/work-results/${encodeURIComponent(genericCurrentWorkResultId.replace("work-result://", ""))}`,
      managedCode: "work_result_owner_mismatch",
      localMissingCode: null,
    },
    {
      name: "result-missing",
      path: `/v1/hypervisor/work-results/${encodeURIComponent(missingWorkResultProbeTail)}`,
      managedCode: "work_result_owner_mismatch",
      localMissingCode: "not_found",
    },
    {
      name: "delta-existing",
      path: `/v1/hypervisor/outcome-deltas/${encodeURIComponent(admittedDelta.outcome_delta_id.replace("outcome-delta://", ""))}`,
      managedCode: "outcome_delta_owner_mismatch",
      localMissingCode: null,
    },
    {
      name: "delta-missing",
      path: `/v1/hypervisor/outcome-deltas/${encodeURIComponent(missingOutcomeDeltaProbeTail)}`,
      managedCode: "outcome_delta_owner_mismatch",
      localMissingCode: "not_found",
    },
  ];
  const predecessorOwnerProbePaths = [
    `/v1/goal-orchestration/outcome-rooms/${predecessorOwnerProbeTail}`,
    `/v1/goal-orchestration/outcome-rooms/${predecessorOwnerProbeTail}/product-projection`,
    `/v1/goal-orchestration/outcome-rooms/${predecessorOwnerProbeTail}/collaborative-work-graph`,
    `/v1/goal-orchestration/outcome-rooms/${predecessorOwnerProbeTail}/discussion-projection`,
    `/v1/goal-orchestration/outcome-rooms/${predecessorOwnerProbeTail}/replay`,
  ];
  const ownerCollectionProbeCases = [
    { name: "goal-runs", path: "/v1/goal-orchestration/goal-runs" },
    { name: "work-results", path: "/v1/hypervisor/work-results" },
    { name: "work-results-overview", path: "/v1/hypervisor/work-results/overview" },
    { name: "outcome-deltas", path: "/v1/hypervisor/outcome-deltas" },
  ];
  const zeroResultRecordSchemaCounts = Object.fromEntries(
    RESULT_RECORD_SCHEMAS.map((schema) => [schema, 0]),
  );
  const zeroDeltaRecordSchemaCounts = Object.fromEntries(
    DELTA_RECORD_SCHEMAS.map((schema) => [schema, 0]),
  );
  const genericWorkTruthMutationProbeCases = [
    {
      name: "work-result-foreign-goal",
      path: "/v1/hypervisor/work-results",
      body: {
        goal_ref: collectiveGoal.goal_ref,
        result_profile: "research",
        outcome_class: "positive",
        status: "completed",
      },
    },
    {
      name: "work-result-missing-goal",
      path: "/v1/hypervisor/work-results",
      body: {
        goal_ref: missingWorkTruthGoalRef,
        result_profile: "research",
        outcome_class: "positive",
        status: "completed",
      },
    },
    {
      name: "outcome-delta-foreign-goal",
      path: "/v1/hypervisor/outcome-deltas",
      body: {
        goal_ref: collectiveGoal.goal_ref,
        delta_kind: "update",
        target_ref: forbiddenWorkTruthTargetRef,
        proposed_by_ref: admittedResult.work_result_id,
      },
    },
    {
      name: "outcome-delta-missing-goal",
      path: "/v1/hypervisor/outcome-deltas",
      body: {
        goal_ref: missingWorkTruthGoalRef,
        delta_kind: "update",
        target_ref: forbiddenWorkTruthTargetRef,
        proposed_by_ref: admittedResult.work_result_id,
      },
    },
  ];
  const roomWriteWrapperCases = [
    ["current", roomPath],
    [
      "predecessor",
      `/v1/goal-orchestration/outcome-rooms/${predecessorOwnerProbeTail}`,
    ],
    ["missing", missingRoomPath],
  ].flatMap(([generation, base]) =>
    [
      ["lifecycle", `${base}/lifecycle/transitions`],
      ["attach", `${base}/attach-goal-run`],
      ["detach", `${base}/detach-goal-run`],
    ].map(([operation, path]) => ({
      name: `${generation}-${operation}`,
      path,
      body: {},
    })),
  );
  const managedRouteShapeProbeCases = [
    {
      name: "agent-run-unknown-suffix",
      method: "GET",
      path: `/__ioi/agent-runs/${encodeURIComponent(transcriptRunId)}/unknown`,
    },
    {
      name: "run-publish-wrong-method",
      method: "GET",
      path: `/__ioi/run-publish/${encodeURIComponent(transcriptRunId)}`,
    },
    {
      name: "env-latest-wrong-method",
      method: "POST",
      path: `/__ioi/env-latest-run/${encodeURIComponent(timelineEnvProbeId)}`,
      body: {},
    },
    {
      name: "conversation-wrong-method",
      method: "POST",
      path: `/__ioi/agent-runs/${encodeURIComponent(transcriptRunId)}/conversation/history`,
      body: {},
    },
    {
      name: "conversation-extra-suffix",
      method: "GET",
      path: `/__ioi/agent-runs/${encodeURIComponent(transcriptRunId)}/conversation/history/extra`,
    },
  ];
  const agentCacheAuthorityProbeCases = [
    {
      name: "run-publish",
      path: `/__ioi/run-publish/${encodeURIComponent(transcriptRunId)}`,
      body: {},
    },
    {
      name: "agent-list",
      path: "/api/ioi.v1.AgentService/ListAgentExecutions",
      body: { filter: { environmentIds: [timelineEnvProbeId] } },
    },
    {
      name: "agent-get",
      path: "/api/ioi.v1.AgentService/GetAgentExecution",
      body: { agentExecutionId: transcriptRunId },
    },
    {
      name: "agent-send",
      path: "/api/ioi.v1.AgentService/SendToAgentExecution",
      body: {
        agentExecutionId: transcriptRunId,
        userInput: {
          id: agentServiceSendProbeBlockId,
          inputs: [{ text: { content: agentServiceSendProbeText } }],
        },
      },
    },
    {
      name: "agent-start",
      path: "/api/ioi.v1.AgentService/StartAgent",
      body: { codeContext: { environmentId: timelineEnvProbeId } },
    },
  ];
  const probeAgentCacheAuthorities = (headers) =>
    Promise.all(
      agentCacheAuthorityProbeCases.map((probe) =>
        request(plane.serveUrl, "POST", probe.path, probe.body, headers),
      ),
    );
  const probeManagedRouteShapes = (headers) =>
    Promise.all(
      managedRouteShapeProbeCases.map((probe) =>
        request(
          plane.serveUrl,
          probe.method,
          probe.path,
          probe.body,
          { accept: "application/json", ...headers },
        ),
      ),
    );
  const exposedLegacyOwnerReads = await Promise.all(
    [transcriptListPath, transcriptPointPath, workLedgerPath].map((path) =>
      call("GET", path, undefined, {
        "x-ioi-forwarded": "m4-aggregate-verifier",
      }),
    ),
  );
  const exposedTranscriptWrite = await call(
    "POST",
    `${transcriptListPath}/${exposedTranscriptWriteId}`,
    forbiddenTranscriptBody(exposedTranscriptWriteId),
    { "x-ioi-forwarded": "m4-aggregate-verifier" },
  );
  const [exposedGoalSpace, exposedTimeline, exposedReplayIndex, exposedWorkLedger, exposedTranscriptTimeline] =
    await Promise.all([
      readHttpText(
        `${plane.serveUrl}/__ioi/goal-space?room=${encodeURIComponent(room.outcome_room_id)}`,
        { "x-ioi-forwarded": "m4-aggregate-verifier" },
      ),
      readHttpText(
        `${plane.serveUrl}/__ioi/run-timeline/goal-run/${collectiveGoalRunId}`,
        { "x-ioi-forwarded": "m4-aggregate-verifier" },
      ),
      readHttpText(`${plane.serveUrl}/__ioi/run-replay`, {
        "x-ioi-forwarded": "m4-aggregate-verifier",
      }),
      readHttpText(`${plane.serveUrl}/__ioi/work-ledger`, {
        "x-ioi-forwarded": "m4-aggregate-verifier",
      }),
      readHttpText(
        `${plane.serveUrl}/__ioi/agent-runs/${encodeURIComponent(transcriptRunId)}/timeline`,
        { "x-ioi-forwarded": "m4-aggregate-verifier" },
      ),
    ]);
  const exposedGenericTimelineAliases = await Promise.all([
    readHttpText(
      `${plane.serveUrl}/__ioi/run-timeline/${encodeURIComponent(transcriptRunId)}`,
      { "x-ioi-forwarded": "m4-aggregate-verifier" },
    ),
    readHttpText(
      `${plane.serveUrl}/__ioi/run-timeline/env/${encodeURIComponent(timelineEnvProbeId)}`,
      { "x-ioi-forwarded": "m4-aggregate-verifier" },
    ),
    readHttpText(
      `${plane.serveUrl}/__ioi/run-timeline/draft/${encodeURIComponent(timelineDraftProbeId)}`,
      { "x-ioi-forwarded": "m4-aggregate-verifier" },
    ),
  ]);
  const exposedCacheHelpers = await Promise.all(
    cacheHelperPaths.map((path) =>
      readHttpText(`${plane.serveUrl}${path}`, {
        "x-ioi-forwarded": "m4-aggregate-verifier",
      }),
    ),
  );
  const exposedAgentCacheAuthorities = await probeAgentCacheAuthorities({
    "x-ioi-forwarded": "m4-aggregate-verifier",
  });
  const exposedManagedRouteShapeProbes = await probeManagedRouteShapes({
    "x-ioi-forwarded": "m4-aggregate-verifier",
  });
  const exposedOwnerPointProbes = await Promise.all(
    ownerPointProbeCases.map((probe) =>
      call("GET", probe.path, undefined, {
        "x-ioi-forwarded": "m4-aggregate-verifier",
      }),
    ),
  );
  const exposedOwnerCollectionProbes = await Promise.all(
    ownerCollectionProbeCases.map((probe) =>
      call("GET", probe.path, undefined, {
        "x-ioi-forwarded": "m4-aggregate-verifier",
      }),
    ),
  );
  const exposedPredecessorOwnerProbes = await Promise.all(
    predecessorOwnerProbePaths.map((path) =>
      call("GET", path, undefined, {
        "x-ioi-forwarded": "m4-aggregate-verifier",
      }),
    ),
  );
  const exposedRoomWriteWrapperProbes = await Promise.all(
    roomWriteWrapperCases.map((probe) =>
      call("POST", probe.path, probe.body, {
        "x-ioi-forwarded": "m4-aggregate-verifier",
      }),
    ),
  );
  const exposedUnreboundInternalSurfaces = await Promise.all(
    unreboundInternalSurfaceProbeCases.map((probe) =>
      readHttpText(`${plane.serveUrl}${probe.path}`, {
        "x-ioi-forwarded": "m4-aggregate-verifier",
      }),
    ),
  );
  const exposedGenericWorkTruthMutations = await Promise.all(
    genericWorkTruthMutationProbeCases.map((probe) =>
      call("POST", probe.path, probe.body, {
        "x-ioi-forwarded": "m4-aggregate-verifier",
      }),
    ),
  );
  // Deny-by-default (a5d88f3da): the daemon's inbound auth ring answers every anonymous /v1
  // probe with ONE refusal body, so auth errors cannot be used as an existence, method, or
  // topology oracle. Probe each distinguishing class explicitly — wrong method on real owner
  // routes, never-registered namespaces (the ring wraps the router fallback), and the product
  // shell's verbatim /v1 proxy — and assert exact byte equality below, not status equality.
  const exposedWrongMethodProbes = await Promise.all(
    [
      ["DELETE", roomPath, undefined],
      ["PUT", graphPath, { frontier_item_refs: ["frontier://forged"] }],
      ["PATCH", productPath, { forged: true }],
      ["POST", replayPath, {}],
    ].map(([method, path, body]) =>
      call(method, path, body, { "x-ioi-forwarded": "m4-aggregate-verifier" }),
    ),
  );
  const exposedUnroutedProbes = await Promise.all(
    [
      "/v1/goal-orchestration/never-registered-owner-family",
      "/v1/future-namespace/resource",
    ].map((path) =>
      call("GET", path, undefined, { "x-ioi-forwarded": "m4-aggregate-verifier" }),
    ),
  );
  const exposedServeProxyProbes = await Promise.all(
    [
      ["GET", roomPath, undefined],
      ["GET", missingRoomPath, undefined],
      ["DELETE", roomPath, undefined],
      ["GET", eventPath, undefined],
    ].map(([method, path, body]) =>
      request(plane.serveUrl, method, path, body, {
        "x-ioi-forwarded": "m4-aggregate-verifier",
      }),
    ),
  );
  const exposedOwnerReadsDurableAfter =
    await quiescentRoomAdmissionSideEffectSnapshot(dataDir);
  const exposedOwnerProjectionResponses = [
    exposedProduct,
    exposedGraph,
    exposedDiscussion,
    exposedReplay,
    ...exposedMissingReads,
    ...exposedCurrentRoomWrappers,
    exposedEvents,
    ...exposedLegacyOwnerReads,
    exposedTranscriptWrite,
    exposedGoalSpace,
    exposedTimeline,
    exposedReplayIndex,
    exposedWorkLedger,
    exposedTranscriptTimeline,
    ...exposedGenericTimelineAliases,
    ...exposedCacheHelpers,
    ...exposedAgentCacheAuthorities,
    ...exposedManagedRouteShapeProbes,
    ...exposedOwnerPointProbes,
    ...exposedOwnerCollectionProbes,
    ...exposedPredecessorOwnerProbes,
    ...exposedRoomWriteWrapperProbes,
    ...exposedUnreboundInternalSurfaces,
    ...exposedGenericWorkTruthMutations,
    ...exposedWrongMethodProbes,
    ...exposedUnroutedProbes,
    ...exposedServeProxyProbes,
  ];
  const exposedOwnerBytesAbsent = exposedOwnerProjectionResponses.every(
    (response) => responseOmitsWireTokens(response, timelineOwnerForbidden),
  );
  // Deny-by-default strengthening: the retired assertion proved a route-specific
  // outcome_room_authentication_required refusal, which let an anonymous caller map which
  // route family answered. The gate now proves the strictly stronger property: ONE
  // byte-identical 401 authentication_required body across existing rooms, missing rooms,
  // collections, wrong methods, never-registered namespaces, and the shell's /v1 proxy —
  // an anonymous caller learns nothing about routes, methods, or topology from refusals.
  const anonymousDaemonRefusals = [
    exposedProduct,
    exposedGraph,
    exposedDiscussion,
    exposedReplay,
    ...exposedMissingReads,
    ...exposedCurrentRoomWrappers,
    ...exposedWrongMethodProbes,
    ...exposedUnroutedProbes,
    ...exposedServeProxyProbes,
  ];
  const anonymousUniformRefusalRaw = exposedProduct.raw;
  const anonymousRoomRefusalBodies = new Set(
    anonymousDaemonRefusals.map((response) => response.raw),
  );
  // The anchor is pinned on its own terms — exact declared key set, exact field values —
  // before any equality comparison. Uniformity against an unpinned anchor would only prove
  // the plane is consistently wrong together; pin plus byte-equality proves each response.
  const anonymousRefusalAnchorKeys = Object.keys(exposedProduct.body || {})
    .sort()
    .join(",");
  const anonymousRefusalAnchorPinned =
    anonymousRefusalAnchorKeys === "needs_bootstrap,ok,reason" &&
    exposedProduct.body.ok === false &&
    exposedProduct.body.reason === "authentication_required" &&
    typeof exposedProduct.body.needs_bootstrap === "boolean";
  check(
    "OWNER PROJECTION REFUSAL: anonymous room-owner probes — existing, missing, collection, wrong-method, unrouted, and UI-proxied — return one identical 401 authentication_required body",
    anonymousRefusalAnchorPinned &&
      anonymousDaemonRefusals.every(
        (response) =>
          response.status === 401 &&
          response.raw === anonymousUniformRefusalRaw &&
          response.body.ok === false &&
          response.body.reason === "authentication_required" &&
          response.body.error === undefined,
      ) &&
      anonymousRoomRefusalBodies.size === 1,
    `anchor_pinned=${anonymousRefusalAnchorPinned} anchor_keys=${anonymousRefusalAnchorKeys} statuses=${anonymousDaemonRefusals
      .map((response) => response.status)
      .join(",")} distinct_bodies=${anonymousRoomRefusalBodies.size} reason=${exposedProduct.body.reason}`,
  );
  // Same strengthening for invocation/work truth: the retired assertion accepted per-family
  // anonymous codes (goal_run_global_truth_*, outcome_room_*), a route-classification oracle.
  // Every anonymous daemon probe must now return the SAME bytes as the room-owner refusal
  // above, and every serve-owned shell/helper surface must present that one reason.
  const anonymousInvocationTruthRefusals = [
    exposedEvents,
    ...exposedLegacyOwnerReads,
    exposedTranscriptWrite,
    ...exposedOwnerPointProbes,
    ...exposedOwnerCollectionProbes,
    ...exposedPredecessorOwnerProbes,
    ...exposedRoomWriteWrapperProbes,
    ...exposedGenericWorkTruthMutations,
  ];
  const anonymousInvocationRefusalBodies = new Set(
    anonymousInvocationTruthRefusals.map((response) => response.raw),
  );
  const htmlErrorCode = (body) =>
    /data-error-code="([^"]*)"/u.exec(String(body))?.[1] ?? "none";
  check(
    "OWNER PROJECTION REFUSAL: anonymous invocation, work-truth, and shell probes present the identical authentication_required refusal without leaking owner truth",
    anonymousInvocationTruthRefusals.every(
      (response) =>
        response.status === 401 &&
        response.raw === anonymousUniformRefusalRaw &&
        response.body.reason === "authentication_required",
    ) &&
      anonymousInvocationRefusalBodies.size === 1 &&
      exposedGoalSpace.status === 401 &&
      exposedGoalSpace.body.includes(
        'data-error-code="authentication_required"',
      ) &&
      exposedGoalSpace.body.includes(
        "No OutcomeRoom, graph, discussion, GoalRun, WorkResult, OutcomeDelta, receipt, or replay owner truth is shown.",
      ) &&
      exposedTimeline.status === 401 &&
      exposedTimeline.body.includes(
        'data-error-code="authentication_required"',
      ) &&
      exposedTimeline.body.includes(
        "No owner GoalRun, invocation, result, receipt, or replay truth is shown.",
      ) &&
      exposedReplayIndex.status === 401 &&
      exposedReplayIndex.body.includes(
        'data-error-code="authentication_required"',
      ) &&
      exposedWorkLedger.status === 401 &&
      exposedWorkLedger.body.includes(
        'data-error-code="authentication_required"',
      ) &&
      exposedTranscriptTimeline.status === 401 &&
      exposedTranscriptTimeline.body.includes(
        '"code":"authentication_required"',
      ) &&
      exposedGenericTimelineAliases.every(
        (response) =>
          response.status === 401 &&
          response.body.includes('data-error-code="authentication_required"') &&
          response.body.includes(
            "No run, environment, draft, transcript, or timeline identity is resolved or shown.",
          ),
      ) &&
      exposedCacheHelpers.every(
        (response) =>
          response.status === 401 &&
          response.body.includes('"code":"authentication_required"') &&
          response.body.includes(
            "no run, environment, draft, transcript, or conversation truth is resolved or shown",
          ),
      ) &&
      exposedAgentCacheAuthorities.every(
        (response) =>
          response.status === 401 &&
          response.body.error?.code === "authentication_required",
      ) &&
      exposedManagedRouteShapeProbes.every(
        (response) =>
          response.status === 401 &&
          response.body.error?.code === "authentication_required",
      ) &&
      exposedUnreboundInternalSurfaces.every(
        (response) =>
          response.status === 401 &&
          response.body.includes('data-error-code="authentication_required"') &&
          response.body.includes(
            "This unrebound internal surface has no principal-scoped projection",
          ),
      ) &&
      exposedOwnerBytesAbsent &&
      exposedOwnerReadsDurableAfter === exposedOwnerReadsDurableBefore,
    `uniform_statuses=${anonymousInvocationTruthRefusals.map((response) => response.status).join(",")} distinct_bodies=${anonymousInvocationRefusalBodies.size} matches_room_refusal=${anonymousInvocationTruthRefusals.every((response) => response.raw === anonymousUniformRefusalRaw)} goal_space=${exposedGoalSpace.status}/${htmlErrorCode(exposedGoalSpace.body)} goal_shell=${exposedTimeline.status}/${htmlErrorCode(exposedTimeline.body)} replay_index=${exposedReplayIndex.status}/${htmlErrorCode(exposedReplayIndex.body)} ledger=${exposedWorkLedger.status}/${htmlErrorCode(exposedWorkLedger.body)} transcript_shell=${exposedTranscriptTimeline.status} generic_aliases=${exposedGenericTimelineAliases.map((response) => `${response.status}/${htmlErrorCode(response.body)}`).join(",")} cache_helpers=${exposedCacheHelpers.map((response) => response.status).join(",")} cache_authorities=${exposedAgentCacheAuthorities.map((response, index) => `${agentCacheAuthorityProbeCases[index].name}:${response.status}/${response.body.error?.code}`).join(",")} managed_shape_fence=${exposedManagedRouteShapeProbes.map((response, index) => `${managedRouteShapeProbeCases[index].name}:${response.status}/${response.body.error?.code}`).join(",")} unrebound=${exposedUnreboundInternalSurfaces.map((response, index) => `${unreboundInternalSurfaceProbeCases[index].name}:${response.status}`).join(",")} owner_bytes_absent=${exposedOwnerBytesAbsent}/whole_tree_unchanged=${exposedOwnerReadsDurableAfter === exposedOwnerReadsDurableBefore}`,
  );
  const outsiderId = `m4_outsider_${Date.now().toString(16)}`;
  const outsiderEmail = `${outsiderId}@local`;
  const outsiderPassword = `m4-${outsiderId}-password`;
  const outsiderCreate = await call("POST", "/v1/hypervisor/principals", {
    principal_id: outsiderId,
    email: outsiderEmail,
    password: outsiderPassword,
  });
  const outsiderLogin = await call("POST", "/v1/hypervisor/auth/login", {
    email: outsiderEmail,
    password: outsiderPassword,
  });
  const outsiderHeaders = {
    authorization: `Bearer ${outsiderLogin.body.session_token || ""}`,
    "x-ioi-forwarded": "m4-aggregate-verifier",
  };
  const outsiderOwnerReadsDurableBefore = roomAdmissionSideEffectSnapshot(dataDir);
  const outsiderEvents = await call(
    "GET",
    eventPath,
    undefined,
    outsiderHeaders,
  );
  const outsiderProduct = await call(
    "GET",
    productPath,
    undefined,
    outsiderHeaders,
  );
  const outsiderGraph = await call("GET", graphPath, undefined, outsiderHeaders);
  const outsiderDiscussion = await call(
    "GET",
    discussionPath,
    undefined,
    outsiderHeaders,
  );
  const outsiderReplay = await call(
    "GET",
    replayPath,
    undefined,
    outsiderHeaders,
  );
  const outsiderLegacyOwnerReads = await Promise.all(
    [transcriptListPath, transcriptPointPath, workLedgerPath].map((path) =>
      call("GET", path, undefined, outsiderHeaders),
    ),
  );
  const outsiderTranscriptWrite = await call(
    "POST",
    `${transcriptListPath}/${outsiderTranscriptWriteId}`,
    forbiddenTranscriptBody(outsiderTranscriptWriteId),
    outsiderHeaders,
  );
  const [outsiderGoalSpace, outsiderTimeline, outsiderReplayIndex, outsiderWorkLedger, outsiderTranscriptTimeline] =
    await Promise.all([
      readHttpText(
        `${plane.serveUrl}/__ioi/goal-space?room=${encodeURIComponent(room.outcome_room_id)}`,
        outsiderHeaders,
      ),
      readHttpText(
        `${plane.serveUrl}/__ioi/run-timeline/goal-run/${collectiveGoalRunId}`,
        outsiderHeaders,
      ),
      readHttpText(`${plane.serveUrl}/__ioi/run-replay`, outsiderHeaders),
      readHttpText(`${plane.serveUrl}/__ioi/work-ledger`, outsiderHeaders),
      readHttpText(
        `${plane.serveUrl}/__ioi/agent-runs/${encodeURIComponent(transcriptRunId)}/timeline`,
        outsiderHeaders,
      ),
    ]);
  const outsiderGenericTimelineAliases = await Promise.all([
    readHttpText(
      `${plane.serveUrl}/__ioi/run-timeline/${encodeURIComponent(transcriptRunId)}`,
      outsiderHeaders,
    ),
    readHttpText(
      `${plane.serveUrl}/__ioi/run-timeline/env/${encodeURIComponent(timelineEnvProbeId)}`,
      outsiderHeaders,
    ),
    readHttpText(
      `${plane.serveUrl}/__ioi/run-timeline/draft/${encodeURIComponent(timelineDraftProbeId)}`,
      outsiderHeaders,
    ),
  ]);
  const outsiderCacheHelpers = await Promise.all(
    cacheHelperPaths.map((path) =>
      readHttpText(`${plane.serveUrl}${path}`, outsiderHeaders),
    ),
  );
  const outsiderAgentCacheAuthorities = await probeAgentCacheAuthorities(outsiderHeaders);
  const outsiderManagedRouteShapeProbes = await probeManagedRouteShapes(outsiderHeaders);
  const outsiderOwnerPointProbes = await Promise.all(
    ownerPointProbeCases.map((probe) =>
      call("GET", probe.path, undefined, outsiderHeaders),
    ),
  );
  const outsiderPredecessorOwnerProbes = await Promise.all(
    predecessorOwnerProbePaths.map((path) =>
      call("GET", path, undefined, outsiderHeaders),
    ),
  );
  const outsiderMissingRoomReads = await Promise.all(
    [
      missingRoomPath,
      `${missingRoomPath}/product-projection`,
      `${missingRoomPath}/collaborative-work-graph`,
      `${missingRoomPath}/discussion-projection`,
      `${missingRoomPath}/replay`,
    ].map((path) => call("GET", path, undefined, outsiderHeaders)),
  );
  const outsiderOwnerCollectionProbes = await Promise.all(
    ownerCollectionProbeCases.map((probe) =>
      call("GET", probe.path, undefined, outsiderHeaders),
    ),
  );
  const outsiderRoomWriteWrapperProbes = await Promise.all(
    roomWriteWrapperCases.map((probe) =>
      call("POST", probe.path, probe.body, outsiderHeaders),
    ),
  );
  const outsiderUnreboundInternalSurfaces = await Promise.all(
    unreboundInternalSurfaceProbeCases.map((probe) =>
      readHttpText(`${plane.serveUrl}${probe.path}`, outsiderHeaders),
    ),
  );
  const outsiderGenericWorkTruthMutations = await Promise.all(
    genericWorkTruthMutationProbeCases.map((probe) =>
      call("POST", probe.path, probe.body, outsiderHeaders),
    ),
  );
  const outsiderOwnerReadsDurableAfter =
    await quiescentRoomAdmissionSideEffectSnapshot(dataDir);
  const outsiderOwnerProjectionResponses = [
    outsiderProduct,
    outsiderGraph,
    outsiderDiscussion,
    outsiderReplay,
    outsiderEvents,
    ...outsiderLegacyOwnerReads,
    outsiderTranscriptWrite,
    outsiderGoalSpace,
    outsiderTimeline,
    outsiderReplayIndex,
    outsiderWorkLedger,
    outsiderTranscriptTimeline,
    ...outsiderGenericTimelineAliases,
    ...outsiderCacheHelpers,
    ...outsiderAgentCacheAuthorities,
    ...outsiderManagedRouteShapeProbes,
    ...outsiderOwnerPointProbes,
    ...outsiderPredecessorOwnerProbes,
    ...outsiderMissingRoomReads,
    ...outsiderOwnerCollectionProbes,
    ...outsiderRoomWriteWrapperProbes,
    ...outsiderUnreboundInternalSurfaces,
    ...outsiderGenericWorkTruthMutations,
  ];
  const outsiderOwnerBytesAbsent = outsiderOwnerProjectionResponses.every(
    (response) => responseOmitsWireTokens(response, timelineOwnerForbidden),
  );
  check(
    "OWNER PROJECTION SETUP: distinct authenticated principal is admitted",
    outsiderCreate.status === 200 &&
      outsiderLogin.status === 200 &&
      Boolean(outsiderLogin.body.session_token),
    `${outsiderCreate.status}/${outsiderLogin.status}`,
  );
  check(
    "OWNER PROJECTION REFUSAL: authenticated wrong principal cannot read room or invocation truth",
    outsiderEvents.status === 403 &&
      outsiderEvents.body.error?.code === "goal_run_global_truth_owner_mismatch" &&
      [outsiderProduct, outsiderGraph, outsiderDiscussion, outsiderReplay].every(
        (response) =>
          response.status === 403 &&
          response.body.error?.code === "outcome_room_owner_mismatch",
      ) &&
      outsiderTimeline.status === 403 &&
      outsiderTimeline.body.includes(
        'data-error-code="goal_run_global_truth_owner_mismatch"',
      ) &&
      outsiderTimeline.body.includes(
        "No owner GoalRun, invocation, result, receipt, or replay truth is shown.",
      ) &&
      outsiderGoalSpace.status === 403 &&
      outsiderGoalSpace.body.includes(
        'data-error-code="outcome_room_owner_mismatch"',
      ) &&
      outsiderGoalSpace.body.includes(
        "No OutcomeRoom, graph, discussion, GoalRun, WorkResult, OutcomeDelta, receipt, or replay owner truth is shown.",
      ) &&
      outsiderLegacyOwnerReads[0]?.status === 403 &&
      outsiderLegacyOwnerReads[0]?.body.error?.code ===
        "agent_run_transcript_principal_scope_unavailable" &&
      outsiderLegacyOwnerReads[1]?.status === 403 &&
      outsiderLegacyOwnerReads[1]?.body.error?.code ===
        "agent_run_transcript_principal_scope_unavailable" &&
      outsiderLegacyOwnerReads[2]?.status === 403 &&
      outsiderLegacyOwnerReads[2]?.body.error?.code ===
        "work_ledger_principal_scope_unavailable" &&
      outsiderTranscriptWrite.status === 403 &&
      outsiderTranscriptWrite.body.error?.code ===
        "agent_run_transcript_principal_scope_unavailable" &&
      outsiderReplayIndex.status === 403 &&
      outsiderReplayIndex.body.includes(
        'data-error-code="agent_run_transcript_principal_scope_unavailable"',
      ) &&
      outsiderWorkLedger.status === 403 &&
      outsiderWorkLedger.body.includes(
        'data-error-code="work_ledger_principal_scope_unavailable"',
      ) &&
      outsiderTranscriptTimeline.status === 403 &&
      outsiderTranscriptTimeline.body.includes(
        '"code":"agent_run_timeline_principal_scope_unavailable"',
      ) &&
      outsiderGenericTimelineAliases.every(
        (response) =>
          response.status === 403 &&
          response.body.includes(
            'data-error-code="agent_run_timeline_principal_scope_unavailable"',
          ) &&
          response.body.includes(
            "no run, environment, draft, transcript, or timeline identity is resolved or shown on a managed deployment.",
          ),
      ) &&
      outsiderCacheHelpers.every(
        (response) =>
          response.status === 403 &&
          response.body.includes(
            '"code":"agent_run_timeline_principal_scope_unavailable"',
          ) &&
          response.body.includes(
            "no run, environment, draft, transcript, or conversation truth is resolved or shown",
          ),
      ) &&
      outsiderAgentCacheAuthorities.every(
        (response, index) =>
          response.status === 403 &&
          response.body.error?.code ===
            (agentCacheAuthorityProbeCases[index].name === "run-publish"
              ? "agent_run_timeline_principal_scope_unavailable"
              : "agent_run_cache_principal_scope_unavailable"),
      ) &&
      outsiderManagedRouteShapeProbes.every(
        (response) =>
          response.status === 403 &&
          response.body.error?.code ===
            "unrebound_internal_surface_principal_scope_unavailable",
      ) &&
      outsiderOwnerPointProbes.every(
        (response, index) =>
          response.status === 403 &&
          response.body.error?.code === ownerPointProbeCases[index].managedCode,
      ) &&
      outsiderPredecessorOwnerProbes.every(
        (response) =>
          response.status === 403 &&
          response.body.error?.code === "outcome_room_owner_mismatch",
      ) &&
      outsiderMissingRoomReads.every(
        (response) =>
          response.status === 403 &&
          response.body.error?.code === "outcome_room_owner_mismatch",
      ) &&
      outsiderOwnerCollectionProbes[0]?.status === 200 &&
      outsiderOwnerCollectionProbes[0]?.body.ok === true &&
      canonicalJson(outsiderOwnerCollectionProbes[0]?.body.goal_runs) === "[]" &&
      outsiderOwnerCollectionProbes[1]?.status === 200 &&
      canonicalJson(outsiderOwnerCollectionProbes[1]?.body.work_results) === "[]" &&
      canonicalJson(
        outsiderOwnerCollectionProbes[1]?.body.record_schema_counts,
      ) === canonicalJson(zeroResultRecordSchemaCounts) &&
      outsiderOwnerCollectionProbes[2]?.status === 200 &&
      outsiderOwnerCollectionProbes[2]?.body.work_results === 0 &&
      outsiderOwnerCollectionProbes[2]?.body.outcome_deltas === 0 &&
      canonicalJson(
        outsiderOwnerCollectionProbes[2]?.body.work_result_record_schema_counts,
      ) === canonicalJson(zeroResultRecordSchemaCounts) &&
      canonicalJson(
        outsiderOwnerCollectionProbes[2]?.body.outcome_delta_record_schema_counts,
      ) === canonicalJson(zeroDeltaRecordSchemaCounts) &&
      outsiderOwnerCollectionProbes[3]?.status === 200 &&
      canonicalJson(outsiderOwnerCollectionProbes[3]?.body.outcome_deltas) ===
        "[]" &&
      canonicalJson(
        outsiderOwnerCollectionProbes[3]?.body.record_schema_counts,
      ) === canonicalJson(zeroDeltaRecordSchemaCounts) &&
      outsiderRoomWriteWrapperProbes.every(
        (response) =>
          response.status === 403 &&
          response.body.error?.code === "outcome_room_owner_mismatch",
      ) &&
      outsiderUnreboundInternalSurfaces.every(
        (response) =>
          response.status === 403 &&
          response.body.includes(
            'data-error-code="unrebound_internal_surface_principal_scope_unavailable"',
          ) &&
          response.body.includes(
            "This unrebound internal surface has no principal-scoped projection",
          ),
      ) &&
      outsiderGenericWorkTruthMutations.every(
        (response) =>
          response.status === 403 &&
          response.body.error?.code === "work_truth_goal_owner_mismatch",
      ) &&
      outsiderOwnerBytesAbsent &&
      outsiderOwnerReadsDurableAfter === outsiderOwnerReadsDurableBefore,
    `events=${outsiderEvents.status}/${outsiderEvents.body.error?.code} goal_space=${outsiderGoalSpace.status} goal_shell=${outsiderTimeline.status} replay_index=${outsiderReplayIndex.status} ledger=${outsiderWorkLedger.status} transcript_shell=${outsiderTranscriptTimeline.status} generic_aliases=${outsiderGenericTimelineAliases.map((response) => response.status).join(",")} cache_helpers=${outsiderCacheHelpers.map((response) => response.status).join(",")} cache_authorities=${outsiderAgentCacheAuthorities.map((response, index) => `${agentCacheAuthorityProbeCases[index].name}:${response.status}/${response.body.error?.code}`).join(",")} managed_shape_fence=${outsiderManagedRouteShapeProbes.map((response, index) => `${managedRouteShapeProbeCases[index].name}:${response.status}/${response.body.error?.code}`).join(",")} points=${outsiderOwnerPointProbes.map((response, index) => `${ownerPointProbeCases[index].name}:${response.status}/${response.body.error?.code}`).join(",")} collections=${outsiderOwnerCollectionProbes.map((response, index) => `${ownerCollectionProbeCases[index].name}:${response.status}`).join(",")} predecessor=${outsiderPredecessorOwnerProbes.map((response) => `${response.status}/${response.body.error?.code}`).join(",")} missing_room=${outsiderMissingRoomReads.map((response) => `${response.status}/${response.body.error?.code}`).join(",")} wrappers=${outsiderRoomWriteWrapperProbes.map((response, index) => `${roomWriteWrapperCases[index].name}:${response.status}/${response.body.error?.code}`).join(",")} unrebound=${outsiderUnreboundInternalSurfaces.map((response, index) => `${unreboundInternalSurfaceProbeCases[index].name}:${response.status}`).join(",")} work_truth_writes=${outsiderGenericWorkTruthMutations.map((response, index) => `${genericWorkTruthMutationProbeCases[index].name}:${response.status}/${response.body.error?.code}`).join(",")} direct=${outsiderLegacyOwnerReads.map((response) => `${response.status}/${response.body.error?.code || response.body.reason}`).join(",")} write=${outsiderTranscriptWrite.status}/${outsiderTranscriptWrite.body.error?.code || outsiderTranscriptWrite.body.reason} owner_bytes_absent=${outsiderOwnerBytesAbsent}/whole_tree_unchanged=${outsiderOwnerReadsDurableAfter === outsiderOwnerReadsDurableBefore} room=${[
      outsiderProduct,
      outsiderGraph,
      outsiderDiscussion,
      outsiderReplay,
    ]
      .map((response) => `${response.status}/${response.body.error?.code}`)
      .join(" ")}`,
  );

  requireValue(
    existsSync(predecessorOwnerProbe.path) &&
      readFileSync(predecessorOwnerProbe.path).equals(predecessorOwnerProbe.bytes),
    "BLOCKED: predecessor owner-boundary fixture changed during adversarial reads or writes",
  );
  predecessorOwnerProbe.cleanup();
  requireValue(
    !existsSync(predecessorOwnerProbe.path),
    "BLOCKED: predecessor owner-boundary fixture survived its bounded proof interval",
  );

  // Seed one bounded local-operator cache record before the fresh-process replay. The restarted
  // product shell must rehydrate this daemon-owned transcript and keep every helper usable in the
  // only posture where the legacy family is admissible. Managed/exposed probes above ran before
  // this write and proved they neither disclosed nor created an equivalent cache occupant.
  const localCacheRunId = `m4_local_cache_${Date.now().toString(16)}`;
  const localCacheEnvId = `m4_local_env_${Date.now().toString(16)}`;
  const localCacheDraftId = `m4_local_draft_${Date.now().toString(16)}`;
  const localCachePrompt = "local cache owner-boundary success probe";
  const localCacheSummary = "local cache helper projection complete";
  const localCacheTranscriptCreate = await call(
    "POST",
    `${transcriptListPath}/${encodeURIComponent(localCacheRunId)}`,
    {
      schema_version: "ioi.hypervisor.agent-run-transcript.v1",
      run_id: localCacheRunId,
      environment_id: localCacheEnvId,
      session_ref: `session:${localCacheRunId}`,
      prompt: localCachePrompt,
      name: "Local cache owner-boundary proof",
      status: "done",
      summary: localCacheSummary,
      proposal_ref: `proposal://${localCacheDraftId}`,
      changed_files: [{ files: ["m4-local-cache-proof.txt"] }],
      user_input_block_id: `${localCacheRunId}-input`,
      activity_log: [{ kind: "done", text: localCacheSummary, at: "2026-07-31T00:00:00Z" }],
      created_at: "2026-07-31T00:00:00Z",
      updated_at: "2026-07-31T00:00:01Z",
    },
  );
  requireValue(
    localCacheTranscriptCreate.status === 200 &&
      localCacheTranscriptCreate.body.run_id === localCacheRunId &&
      typeof localCacheTranscriptCreate.body.state_root === "string",
    "BLOCKED: local cache helper proof transcript was not durably recorded before restart",
  );

  // 8. A second fresh process must project the same owner refs, roots, receipts, payload
  // commitments, and reciprocal invocation edge. Restart never reinterprets mutable workspace
  // bytes after the room-admitted result has been sealed.
  const preRestartRevision = room.latest_sequence;
  const preRestartRoot = room.room_state_root;
  const preRestartReceiptRoot = room.room_receipt_root;
  const preRestartRoomOwnerCoordinates = canonicalJson({
    outcome_room_id: room.outcome_room_id,
    owner_or_sponsor_ref: room.owner_or_sponsor_ref,
    system_id: room.system_id,
    package_id: room.package_id,
    genesis_ref: room.genesis_ref,
    constitution_ref: room.constitution_ref,
  });
  requireValue(
    Array.isArray(graph?.source_admission_receipt_refs) &&
      Array.isArray(discussion?.source_admission_receipt_refs) &&
      product?.outcome_room,
    "BLOCKED: pre-restart projection heads or owner coordinates are incomplete",
  );
  const preRestartGraphHead = canonicalJson({
    source_room_revision: graph.source_room_revision,
    source_room_state_root: graph.source_room_state_root,
    source_admission_receipt_refs: graph.source_admission_receipt_refs,
  });
  const preRestartDiscussionHead = canonicalJson({
    source_room_revision: discussion.source_room_revision,
    source_room_state_root: discussion.source_room_state_root,
    source_admission_receipt_refs: discussion.source_admission_receipt_refs,
  });
  const preRestartProductOwnerCoordinates = canonicalJson({
    outcome_room_ref: product.outcome_room.outcome_room_ref,
    owner_or_sponsor_ref: product.outcome_room.owner_or_sponsor_ref,
    system_id: product.outcome_room.system_id,
    package_id: product.outcome_room.package_id,
    genesis_ref: product.outcome_room.genesis_ref,
    constitution_ref: product.outcome_room.constitution_ref,
  });
  const preRestartReceiptRecords = [...(replayResponse.body.operations || [])];
  const preRestartReceiptRefs = [...preRestartReceiptRecords]
    .sort((left, right) => left.sequence - right.sequence)
    .map((receipt) => receipt.receipt_ref);
  const preRestartReceiptSnapshot = canonicalJson(preRestartReceiptRecords);
  requireValue(
    preRestartReceiptRecords.length === preRestartRevision + 1 &&
      preRestartReceiptRefs.every(
        (receiptRef) =>
          typeof receiptRef === "string" && receiptRef.startsWith("receipt://"),
      ) &&
      canonicalJson(graph.source_admission_receipt_refs) ===
        canonicalJson(preRestartReceiptRefs) &&
      canonicalJson(discussion.source_admission_receipt_refs) ===
        canonicalJson(preRestartReceiptRefs) &&
      canonicalJson(room.admission_and_replay_refs) ===
        canonicalJson(preRestartReceiptRefs) &&
      preRestartReceiptRecords.every((operation) =>
        receiptRefBindsRoot(operation.receipt_ref, operation.receipt_root)
      ),
    "BLOCKED: Agentgres receipt census does not exactly bind both pre-restart projections",
  );
  const preRestartInvocationProof = {
    output_commitment:
      linkedInvocation?.execution_provenance?.output_commitment,
    admitted_work_result_root:
      linkedInvocation?.work_result_derivation?.admitted_work_result_root,
    invocation_successor_root:
      linkedInvocation?.work_result_derivation?.invocation_successor_root,
    result_payload_ref: linkedInvocation?.work_result_derivation?.result_payload_ref,
  };
  await plane.stop();
  plane = await startIsolatedPlane({
    dataDir,
    baseEnv: CLEAN_BASE_ENV,
    env: basePlaneEnv,
    serve: true,
  });
  requireValue(plane, "BLOCKED: replay process did not start");
  call = (method, path, body, headers) =>
    request(plane.daemonUrl, method, path, body, headers);
  const recoveredRoom = await call("GET", roomPath);
  const recoveredGoal = await call(
    "GET",
    `/v1/goal-orchestration/goal-runs/${collectiveGoalRunId}`,
  );
  const recoveredGraph = await call("GET", graphPath);
  const recoveredDiscussion = await call("GET", discussionPath);
  const recoveredReplay = await call("GET", replayPath);
  const recoveredProduct = await call("GET", productPath);
  const recoveredVersionedResults = await call(
    "GET",
    "/v1/hypervisor/work-results",
  );
  const recoveredVersionedDeltas = await call(
    "GET",
    "/v1/hypervisor/outcome-deltas",
  );
  const recoveredGenericResultPoint = await call(
    "GET",
    `/v1/hypervisor/work-results/${encodeURIComponent(
      genericCurrentWorkResultId.replace("work-result://", ""),
    )}`,
  );
  const recoveredM4ResultPoint = await call(
    "GET",
    `/v1/hypervisor/work-results/${encodeURIComponent(
      admittedResult.work_result_id.replace("work-result://", ""),
    )}`,
  );
  const recoveredM4DeltaPoint = await call(
    "GET",
    `/v1/hypervisor/outcome-deltas/${encodeURIComponent(
      admittedDelta.outcome_delta_id.replace("outcome-delta://", ""),
    )}`,
  );
  const recoveredEventTruth = await call(
    "GET",
    eventPath,
  );
  const recoveredInvocation = recoveredEventTruth.body.invocations?.find(
    (value) =>
      value.harness_invocation_id === successfulInvocation.harness_invocation_id,
  );
  const recoveredReceiptRecords = [...(recoveredReplay.body.operations || [])];
  const recoveredReceiptRefs = [...recoveredReceiptRecords]
    .sort((left, right) => left.sequence - right.sequence)
    .map((operation) => operation.receipt_ref);
  const recoveredReceiptSnapshot = canonicalJson(recoveredReceiptRecords);
  room = recoveredRoom.body.outcome_room;
  const activeSystemChainEntry = requireValue(
    strictFamilyEntries(dataDir, "autonomous-system-chain-revisions")
      .map((entry) => {
        const path = join(
          dataDir,
          "autonomous-system-chain-revisions",
          entry.name,
        );
        const bytes = readFileSync(path);
        return {
          path,
          bytes,
          record: JSON.parse(bytes.toString("utf8")),
        };
      })
      .find(({ record }) => record.chain_root === active.chain.chain_root),
    "BLOCKED: active bounded-System chain source is absent after restart",
  );
  let missingSystemSourceReplay;
  let missingSystemSourceOutsiderReplay;
  let missingSystemSourceTreeUnchanged = false;
  try {
    rmSync(activeSystemChainEntry.path, { force: true });
    const treeBefore = roomAdmissionSideEffectSnapshot(dataDir);
    missingSystemSourceReplay = await call("GET", replayPath);
    missingSystemSourceOutsiderReplay = await call(
      "GET",
      replayPath,
      undefined,
      outsiderHeaders,
    );
    const treeAfter = roomAdmissionSideEffectSnapshot(dataDir);
    missingSystemSourceTreeUnchanged = treeAfter === treeBefore;
  } finally {
    writeFileSync(activeSystemChainEntry.path, activeSystemChainEntry.bytes, {
      flag: "wx",
    });
  }
  let substitutedSystemSourceReplay;
  let substitutedSystemSourceOutsiderReplay;
  let substitutedSystemSourceTreeUnchanged = false;
  try {
    writeFileSync(
      activeSystemChainEntry.path,
      Buffer.from(
        `${JSON.stringify({
          ...activeSystemChainEntry.record,
          chain_root: `sha256:${"c".repeat(64)}`,
        })}\n`,
      ),
    );
    const treeBefore = roomAdmissionSideEffectSnapshot(dataDir);
    substitutedSystemSourceReplay = await call("GET", replayPath);
    substitutedSystemSourceOutsiderReplay = await call(
      "GET",
      replayPath,
      undefined,
      outsiderHeaders,
    );
    const treeAfter = roomAdmissionSideEffectSnapshot(dataDir);
    substitutedSystemSourceTreeUnchanged = treeAfter === treeBefore;
  } finally {
    writeFileSync(activeSystemChainEntry.path, activeSystemChainEntry.bytes);
  }
  const restoredSystemSourceReplay = await call("GET", replayPath);
  check(
    "RESTART/REPLAY: room preserves its immutable owner coordinates and exact sealed head",
    recoveredRoom.status === 200 &&
      room?.latest_sequence === preRestartRevision &&
      room?.room_state_root === preRestartRoot &&
      room?.room_receipt_root === preRestartReceiptRoot &&
      canonicalJson({
        outcome_room_id: room?.outcome_room_id,
        owner_or_sponsor_ref: room?.owner_or_sponsor_ref,
        system_id: room?.system_id,
        package_id: room?.package_id,
        genesis_ref: room?.genesis_ref,
        constitution_ref: room?.constitution_ref,
      }) === preRestartRoomOwnerCoordinates &&
      room?.member_goal_run_refs?.length === 1 &&
      room.member_goal_run_refs[0] === collectiveGoal.goal_ref &&
      !room.member_goal_run_refs.includes(direct.goalRun.goal_ref),
    `${recoveredRoom.status}/seq=${room?.latest_sequence}/state=${room?.room_state_root}/receipt=${room?.room_receipt_root}/owner_coordinates_unchanged=${canonicalJson({ outcome_room_id: room?.outcome_room_id, owner_or_sponsor_ref: room?.owner_or_sponsor_ref, system_id: room?.system_id, package_id: room?.package_id, genesis_ref: room?.genesis_ref, constitution_ref: room?.constitution_ref }) === preRestartRoomOwnerCoordinates}`,
  );
  check(
    "RESTART/REPLAY: graph and selected product preserve admitted result and delta at that root",
    recoveredGraph.status === 200 &&
      recoveredProduct.status === 200 &&
      recoveredGraph.body.collaborative_work_graph?.member_goal_run_refs?.length === 1 &&
      recoveredGraph.body.collaborative_work_graph.member_goal_run_refs[0] ===
        collectiveGoal.goal_ref &&
      recoveredGraph.body.collaborative_work_graph?.work_result_refs?.length === 1 &&
      recoveredGraph.body.collaborative_work_graph.work_result_refs[0] ===
        admittedResult.work_result_id &&
      recoveredGraph.body.collaborative_work_graph?.outcome_delta_refs?.length === 1 &&
      recoveredGraph.body.collaborative_work_graph.outcome_delta_refs[0] ===
        admittedDelta.outcome_delta_id &&
      canonicalJson({
        source_room_revision:
          recoveredGraph.body.collaborative_work_graph?.source_room_revision,
        source_room_state_root:
          recoveredGraph.body.collaborative_work_graph?.source_room_state_root,
        source_admission_receipt_refs:
          recoveredGraph.body.collaborative_work_graph
            ?.source_admission_receipt_refs,
      }) === preRestartGraphHead &&
      recoveredProduct.body.outcome_room?.room_state_root === room.room_state_root &&
      canonicalJson({
        outcome_room_ref: recoveredProduct.body.outcome_room?.outcome_room_ref,
        owner_or_sponsor_ref:
          recoveredProduct.body.outcome_room?.owner_or_sponsor_ref,
        system_id: recoveredProduct.body.outcome_room?.system_id,
        package_id: recoveredProduct.body.outcome_room?.package_id,
        genesis_ref: recoveredProduct.body.outcome_room?.genesis_ref,
        constitution_ref: recoveredProduct.body.outcome_room?.constitution_ref,
      }) === preRestartProductOwnerCoordinates &&
      recoveredProduct.body.member_goal_runs?.length === 1 &&
      recoveredProduct.body.member_goal_runs[0]?.goal_run_ref ===
        collectiveGoal.goal_ref &&
      recoveredProduct.body.work_results?.length === 1 &&
      recoveredProduct.body.work_results[0]?.work_result_id ===
        admittedResult.work_result_id &&
      recoveredProduct.body.outcome_deltas?.length === 1 &&
      recoveredProduct.body.outcome_deltas[0]?.outcome_delta_id ===
        admittedDelta.outcome_delta_id &&
      familyCount(dataDir, "work-result-registry") === 2 &&
      familyCount(dataDir, "outcome-delta-registry") === 1 &&
      recoveredVersionedResults.status === 200 &&
      recoveredVersionedResults.body.schema_version ===
        RESULT_REGISTRY_PROJECTION_SCHEMA &&
      canonicalJson(recoveredVersionedResults.body.record_schema_counts) ===
        canonicalJson({
          "ioi.foundations.work-result.v3": 2,
        }) &&
      recoveredVersionedDeltas.status === 200 &&
      recoveredVersionedDeltas.body.schema_version ===
        DELTA_REGISTRY_PROJECTION_SCHEMA &&
      canonicalJson(recoveredVersionedDeltas.body.record_schema_counts) ===
        canonicalJson({
          "ioi.foundations.outcome-delta.v3": 1,
        }) &&
      recoveredGenericResultPoint.status === 200 &&
      recoveredGenericResultPoint.body.record_schema_version ===
        "ioi.foundations.work-result.v3" &&
      canonicalJson(recoveredGenericResultPoint.body.work_result) ===
        canonicalJson(genericCurrentResult) &&
      recoveredM4ResultPoint.status === 200 &&
      recoveredM4ResultPoint.body.record_schema_version ===
        "ioi.foundations.work-result.v3" &&
      canonicalJson(recoveredM4ResultPoint.body.work_result) ===
        canonicalJson(postDeltaResultPoint.body.work_result) &&
      recoveredM4DeltaPoint.status === 200 &&
      recoveredM4DeltaPoint.body.record_schema_version ===
        "ioi.foundations.outcome-delta.v3" &&
      canonicalJson(recoveredM4DeltaPoint.body.outcome_delta) ===
        canonicalJson(admittedDelta) &&
      recoveredGraph.body.collaborative_work_graph?.source_room_state_root ===
        room.room_state_root &&
      recoveredGraph.body.collaborative_work_graph?.source_room_revision ===
        room.latest_sequence &&
      recoveredProduct.body.outcome_room?.outcome_room_ref ===
        room.outcome_room_id &&
      recoveredProduct.body.outcome_room?.owner_or_sponsor_ref === LOCAL_OWNER &&
      recoveredProduct.body.outcome_room?.system_id === SYSTEM_ID &&
      recoveredProduct.body.outcome_room?.package_id === OUTCOME_PACKAGE &&
      recoveredProduct.body.outcome_room?.genesis_ref === GENESIS_ID &&
      recoveredProduct.body.outcome_room?.constitution_ref === CONSTITUTION_REF,
    `${recoveredProduct.body.outcome_room?.room_state_root}/${room.room_state_root}/result_schemas=${canonicalJson(recoveredVersionedResults.body.record_schema_counts)}/delta_schemas=${canonicalJson(recoveredVersionedDeltas.body.record_schema_counts)}/points=${recoveredGenericResultPoint.status}/${recoveredM4ResultPoint.status}/${recoveredM4DeltaPoint.status}`,
  );
  check(
    "RESTART/REPLAY: operation chain remains contiguous through the recovered head",
    recoveredReplay.status === 200 &&
      recoveredReplay.body.latest_sequence === preRestartRevision &&
      recoveredReplay.body.room_state_root === preRestartRoot &&
      recoveredReplay.body.room_receipt_root === preRestartReceiptRoot &&
      recoveredReplay.body.operations?.length === room.latest_sequence + 1 &&
      [missingSystemSourceReplay, substitutedSystemSourceReplay].every(
        (response) =>
          response?.status === 503 &&
          response.body.error?.code ===
            "outcome_room_projection_system_unresolved",
      ) &&
      missingSystemSourceTreeUnchanged &&
      substitutedSystemSourceTreeUnchanged &&
      [
        missingSystemSourceOutsiderReplay,
        substitutedSystemSourceOutsiderReplay,
      ].every(
        (response) =>
          response?.status === 403 &&
          response.body.error?.code === "outcome_room_owner_mismatch" &&
          response.raw === outsiderReplay.raw &&
          responseOmitsWireTokens(response, timelineOwnerForbidden),
      ) &&
      readFileSync(activeSystemChainEntry.path).equals(
        activeSystemChainEntry.bytes,
      ) &&
      restoredSystemSourceReplay.status === 200 &&
      canonicalJson(restoredSystemSourceReplay.body) ===
        canonicalJson(recoveredReplay.body) &&
      canonicalJson(
        recoveredReplay.body.operations
          .slice(0, 4)
          .map((operation) => operation.operation_kind),
      ) ===
        canonicalJson([
          "room_genesis",
          "goal_run_membership_admitted",
          "goal_run_membership_detached",
          "goal_run_membership_admitted",
        ]),
    `${recoveredReplay.status}/ops=${recoveredReplay.body.operations?.length}/seq=${recoveredReplay.body.latest_sequence}/system_missing=${missingSystemSourceReplay?.status}/${missingSystemSourceReplay?.body.error?.code}/${missingSystemSourceTreeUnchanged}/missing_outsider=${missingSystemSourceOutsiderReplay?.status}/${missingSystemSourceOutsiderReplay?.body.error?.code}/${missingSystemSourceOutsiderReplay?.raw === outsiderReplay.raw}/system_substituted=${substitutedSystemSourceReplay?.status}/${substitutedSystemSourceReplay?.body.error?.code}/${substitutedSystemSourceTreeUnchanged}/substituted_outsider=${substitutedSystemSourceOutsiderReplay?.status}/${substitutedSystemSourceOutsiderReplay?.body.error?.code}/${substitutedSystemSourceOutsiderReplay?.raw === outsiderReplay.raw}/restored=${restoredSystemSourceReplay.status}/membership_kinds=${recoveredReplay.body.operations?.slice(0, 4).map((operation) => operation.operation_kind).join(",")}/state=${recoveredReplay.body.room_state_root}/receipt=${recoveredReplay.body.room_receipt_root}`,
  );
  check(
    "RESTART/REPLAY: invocation retains reciprocal backlink, output commitment, and derivation roots",
    recoveredEventTruth.status === 200 &&
      recoveredInvocation?.work_result_ref === admittedResult.work_result_id &&
      recoveredInvocation?.implementation_result?.work_result_ref ===
        admittedResult.work_result_id &&
      String(preRestartInvocationProof.output_commitment || "").startsWith(
        "sha256:",
      ) &&
      String(
        preRestartInvocationProof.admitted_work_result_root || "",
      ).startsWith("sha256:") &&
      String(
        preRestartInvocationProof.invocation_successor_root || "",
      ).startsWith("sha256:") &&
      preRestartInvocationProof.result_payload_ref ===
        admittedResult.result_payload_ref &&
      canonicalJson({
        output_commitment:
          recoveredInvocation?.execution_provenance?.output_commitment,
        admitted_work_result_root:
          recoveredInvocation?.work_result_derivation?.admitted_work_result_root,
        invocation_successor_root:
          recoveredInvocation?.work_result_derivation?.invocation_successor_root,
        result_payload_ref:
          recoveredInvocation?.work_result_derivation?.result_payload_ref,
      }) === canonicalJson(preRestartInvocationProof),
    `${recoveredInvocation?.work_result_ref}/${recoveredInvocation?.implementation_result?.work_result_ref}/${recoveredInvocation?.execution_provenance?.output_commitment}`,
  );
  check(
    "RESTART BACKLINKS: GoalRun retains reciprocal room membership and WorkResult publication",
    recoveredGoal.status === 200 &&
      recoveredGoal.body.goal_run?.outcome_room_ref === room.outcome_room_id &&
      recoveredGoal.body.goal_run?.work_result_refs?.length === 1 &&
      recoveredGoal.body.goal_run.work_result_refs[0] === admittedResult.work_result_id,
    `${recoveredGoal.status}/${recoveredGoal.body.goal_run?.outcome_room_ref}`,
  );
  check(
    "RESTART PROJECTIONS: replay receipt and honest-empty discussion preserve the exact room head",
      recoveredReplay.body.room_receipt_root === room.room_receipt_root &&
      familyCount(dataDir, "outcome-room-system-receipts") === 0 &&
      recoveredReceiptSnapshot === preRestartReceiptSnapshot &&
      recoveredReceiptRecords.length === room.latest_sequence + 1 &&
      new Set(
        recoveredReceiptRecords.map((receipt) => receipt.sequence),
      ).size === recoveredReceiptRecords.length &&
      recoveredReceiptRecords.every((operation) =>
        receiptRefBindsRoot(operation.receipt_ref, operation.receipt_root)
      ) &&
      canonicalJson(recoveredReceiptRefs) ===
        canonicalJson(room.admission_and_replay_refs) &&
      canonicalJson(recoveredReceiptRefs) === canonicalJson(
        recoveredGraph.body.collaborative_work_graph
          ?.source_admission_receipt_refs,
      ) &&
      canonicalJson(recoveredReceiptRefs) === canonicalJson(
        recoveredDiscussion.body.discussion_projection
          ?.source_admission_receipt_refs,
      ) &&
      recoveredDiscussion.status === 200 &&
      canonicalJson({
        source_room_revision:
          recoveredDiscussion.body.discussion_projection?.source_room_revision,
        source_room_state_root:
          recoveredDiscussion.body.discussion_projection?.source_room_state_root,
        source_admission_receipt_refs:
          recoveredDiscussion.body.discussion_projection
            ?.source_admission_receipt_refs,
      }) === preRestartDiscussionHead &&
      recoveredDiscussion.body.discussion_projection?.message_refs?.length === 0 &&
      recoveredDiscussion.body.discussion_projection?.redaction_summary_refs
        ?.length === 0,
    `${recoveredReplay.body.room_receipt_root}/${room.room_receipt_root}/receipts=${recoveredReceiptRecords.length}/stable=${recoveredReceiptSnapshot === preRestartReceiptSnapshot}/discussion=${recoveredDiscussion.status}/${recoveredDiscussion.body.discussion_projection?.source_room_revision}`,
  );

  // 9. The existing ported shell renders only the selected owner projection. It owns no writes
  // and states every scope bar explicitly.
  const goalSpaceResponse = await readHttpText(
    `${plane.serveUrl}/__ioi/goal-space?room=${encodeURIComponent(
      room.outcome_room_id,
    )}`,
    {},
    150_000,
  );
  const goalSpaceHtml = goalSpaceResponse.body;
  const runTimelineResponse = await readHttpText(
    `${plane.serveUrl}/__ioi/run-timeline/goal-run/${collectiveGoalRunId}`,
    {},
    150_000,
  );
  const runTimelineHtml = runTimelineResponse.body;
  let localEnvCacheResponse = { status: 0, body: "" };
  let localEnvCacheBody = {};
  for (let attempt = 0; attempt < 20; attempt += 1) {
    localEnvCacheResponse = await readHttpText(
      `${plane.serveUrl}/__ioi/env-latest-run/${encodeURIComponent(localCacheEnvId)}`,
    );
    try {
      localEnvCacheBody = JSON.parse(localEnvCacheResponse.body);
    } catch {
      localEnvCacheBody = {};
    }
    if (localEnvCacheBody.runId === localCacheRunId) break;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  const localGenericTimelineAliases = await Promise.all([
    readHttpText(
      `${plane.serveUrl}/__ioi/run-timeline/${encodeURIComponent(localCacheRunId)}`,
    ),
    readHttpText(
      `${plane.serveUrl}/__ioi/run-timeline/env/${encodeURIComponent(localCacheEnvId)}`,
    ),
    readHttpText(
      `${plane.serveUrl}/__ioi/run-timeline/draft/${encodeURIComponent(localCacheDraftId)}`,
    ),
  ]);
  const [localTimelineProjection, localConversationHistory] = await Promise.all([
    request(
      plane.serveUrl,
      "GET",
      `/__ioi/agent-runs/${encodeURIComponent(localCacheRunId)}/timeline`,
    ),
    request(
      plane.serveUrl,
      "GET",
      `/__ioi/agent-runs/${encodeURIComponent(localCacheRunId)}/conversation/history`,
    ),
  ]);
  const [localConversationLive, localConversationBare] = await Promise.all([
    readHttpStreamPrefix(
      `${plane.serveUrl}/__ioi/agent-runs/${encodeURIComponent(localCacheRunId)}/conversation/live`,
    ),
    readHttpStreamPrefix(
      `${plane.serveUrl}/__ioi/agent-runs/${encodeURIComponent(localCacheRunId)}/conversation`,
    ),
  ]);
  const [localAgentServiceList, localAgentServiceGet] = await Promise.all([
    request(
      plane.serveUrl,
      "POST",
      "/api/ioi.v1.AgentService/ListAgentExecutions",
      { filter: { environmentIds: [localCacheEnvId] } },
    ),
    request(
      plane.serveUrl,
      "POST",
      "/api/ioi.v1.AgentService/GetAgentExecution",
      { agentExecutionId: localCacheRunId },
    ),
  ]);
  const localMissingOwnerPointCases = ownerPointProbeCases.filter(
    (probe) => probe.localMissingCode,
  );
  const localMissingOwnerPointProbes = await Promise.all(
    localMissingOwnerPointCases.map((probe) => call("GET", probe.path)),
  );
  const localUnreboundInternalSurfaces = await Promise.all(
    unreboundInternalSurfaceProbeCases.map((probe) =>
      readHttpText(`${plane.serveUrl}${probe.path}`),
    ),
  );
  const renderedSection = (tag, id) =>
    goalSpaceHtml.match(
      new RegExp(`<${tag}[^>]*id="${id}"[^>]*>[\\s\\S]*?</${tag}>`, "u"),
    )?.[0] || "";
  const containsExactlyOnce = (html, value) =>
    typeof value === "string" && value.length > 0 && html.split(value).length === 2;
  const htmlAttribute = (value) => String(value ?? "").replace(
    /[&<>"']/gu,
    (character) => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    })[character],
  );
  const markedSourceReceipt = (html, owner, receiptRef) =>
    html.includes(
      `<code data-source-owner="${htmlAttribute(owner)}">${htmlAttribute(receiptRef)}</code>`,
    );
  const goalSpaceProjectionState = goalSpaceHtml.match(
    /id="m4-goal-space"[^>]*data-owner-projection-state="([^"]+)"/u,
  )?.[1] || "absent";
  const goalSpaceUnavailable = goalSpaceHtml.match(
    /id="m4-goal-space-unavailable"[^>]*data-error-code="([^"]+)"/u,
  )?.[1] || "none";
  const runTimelineUnavailable = runTimelineHtml.match(
    /id="goal-run-timeline-unavailable"[^>]*data-error-code="([^"]+)"/u,
  )?.[1] || "none";
  const graphStateHtml = renderedSection("dl", "m4-graph-state");
  const discussionStateHtml = renderedSection("dl", "m4-discussion-state");
  const resultStateHtml = renderedSection("table", "m4-direct-results");
  const deltaStateHtml = renderedSection("table", "m4-direct-deltas");
  const timelineImplementationResultRef =
    recoveredInvocation?.implementation_result?.implementation_result_id;
  const timelineSourceCandidateRef =
    recoveredInvocation?.execution_provenance?.source_candidate_ref;
  const timelineOutputCommitment =
    recoveredInvocation?.execution_provenance?.output_commitment;
  const productReadOnlyChecks = {
    no_write_path: goalSpaceHtml.includes("this page has no write path"),
    derived_read_only: goalSpaceHtml.includes(
      "derived · non-authoritative · read-only",
    ),
    discussion_honest_empty: goalSpaceHtml.includes(
      "honest empty — M4 admits no discussion messages",
    ),
    posture_marker: goalSpaceHtml.includes(
      'id="m4-nonclaims" data-product-posture="read-only-derived"',
    ),
  };
  const localCacheHelperChecks = {
    env_latest:
      localEnvCacheResponse.status === 200 &&
      localEnvCacheBody.runId === localCacheRunId,
    generic_timeline_aliases: localGenericTimelineAliases.every(
      (response) =>
        response.status === 200 && response.body.includes(localCacheRunId),
    ),
    timeline_projection:
      localTimelineProjection.status === 200 &&
      localTimelineProjection.body.runId === localCacheRunId &&
      localTimelineProjection.body.environmentId === localCacheEnvId,
    conversation_history:
      localConversationHistory.status === 200 &&
      conversationHistoryCarriesAgentText(
        localConversationHistory.body,
        {
          chunkId: `${localCacheRunId}-output`,
          previousId: `${localCacheRunId}-input`,
          blockId: `${localCacheRunId}-summary`,
          expectedText: localCacheSummary,
        },
      ),
    conversation_live:
      localConversationLive.status === 200 &&
      localConversationLive.contentType.startsWith("text/event-stream") &&
      localConversationLive.body.includes("event: state"),
    conversation_bare:
      localConversationBare.status === 200 &&
      localConversationBare.contentType.startsWith("text/plain") &&
      localConversationBare.body.includes(localCachePrompt),
    agent_service_selected_profile:
      localAgentServiceList.status === 200 &&
      localAgentServiceList.body.agentExecutions?.some(
        (execution) => execution.id === localCacheRunId,
      ) &&
      localAgentServiceGet.status === 200 &&
      localAgentServiceGet.body.agentExecution?.id === localCacheRunId,
    local_missing_point_posture: localMissingOwnerPointProbes.every(
      (response, index) =>
        response.status === 404 &&
        response.body.error?.code ===
          localMissingOwnerPointCases[index].localMissingCode,
    ),
    local_unrebound_surface_posture: localUnreboundInternalSurfaces.every(
      (response, index) =>
        response.status === 200 &&
        response.body.includes(unreboundInternalSurfaceProbeCases[index].marker),
    ),
  };
  const productBoundaryChecks = {
    scope_copy: goalSpaceHtml.includes(
      "Hosted admission only. No external participant, federation, cross-sovereign admission, AIIP discovery, wallet authority, settlement, P0, release closure, or complete M6 application journey is claimed.",
    ),
    payload_marker: goalSpaceHtml.includes('data-payload-exported="false"'),
    admission_route_marker: goalSpaceHtml.includes(
      'data-room-admission-route-exposed="false"',
    ),
    no_new_ioi_app: !existsSync(join(REPO, "apps", "ioi-ai")),
    goal_space_omits_payload_ref: !goalSpaceHtml.includes(
      admittedResult.result_payload_ref,
    ),
    goal_space_omits_payload_bytes: !goalSpaceHtml.includes(completedOutputText),
    timeline_omits_payload_ref: !runTimelineHtml.includes(
      admittedResult.result_payload_ref,
    ),
    timeline_omits_payload_bytes: !runTimelineHtml.includes(completedOutputText),
    no_room_admission_route: !goalSpaceHtml.includes("/admission-proposals"),
  };
  check(
    "PRODUCT STATE: ported shell serves Goal Space and the admitted local run-cache helpers in the existing frame",
    goalSpaceResponse.status === 200 &&
      goalSpaceHtml.includes("IOI Hypervisor") &&
      goalSpaceHtml.includes('id="m4-goal-space"') &&
      Object.values(localCacheHelperChecks).every(Boolean),
    `${goalSpaceResponse.status}/${goalSpaceUnavailable}/bytes=${goalSpaceHtml.length}/timeline=${runTimelineResponse.status}/${runTimelineUnavailable}/local_cache=${JSON.stringify(localCacheHelperChecks)}`,
  );
  check(
    "PRODUCT STATE: shell reports exact owner-projection agreement at the recovered head",
    goalSpaceProjectionState === "exact" &&
      goalSpaceHtml.includes('id="m4-projection-agreement"') &&
      goalSpaceHtml.includes("all projections match the room head") &&
      goalSpaceHtml.includes(room.outcome_room_id) &&
      goalSpaceHtml.includes(room.room_state_root) &&
      goalSpaceHtml.includes(room.room_receipt_root) &&
      graph.source_admission_receipt_refs.every((receiptRef) =>
        containsExactlyOnce(graphStateHtml, receiptRef) &&
          markedSourceReceipt(graphStateHtml, "graph", receiptRef),
      ) &&
      discussion.source_admission_receipt_refs.every((receiptRef) =>
        containsExactlyOnce(discussionStateHtml, receiptRef) &&
          markedSourceReceipt(discussionStateHtml, "discussion", receiptRef),
      ),
    `${room.outcome_room_id}/${room.room_state_root}/${room.room_receipt_root}/graph_receipts=${graph.source_admission_receipt_refs.length}/discussion_receipts=${discussion.source_admission_receipt_refs.length}/mode=${goalSpaceProjectionState}/unavailable=${goalSpaceUnavailable}`,
  );
  check(
    "PRODUCT STATE: selected projection renders reciprocal GoalRun and WorkResult identities",
    goalSpaceHtml.includes(collectiveGoal.goal_ref) &&
      goalSpaceHtml.includes(
        `data-member-goal-run-ref="${htmlAttribute(collectiveGoal.goal_ref)}"`,
      ) &&
      goalSpaceHtml.includes(admittedResult.work_result_id) &&
      containsExactlyOnce(resultStateHtml, resultAdmissionReceiptRef) &&
      resultStateHtml.includes(
        `data-work-result-ref="${htmlAttribute(admittedResult.work_result_id)}" data-admission-receipt="present"`,
      ) &&
      runTimelineResponse.status === 200 &&
      runTimelineHtml.includes("Invocation outputs") &&
      runTimelineHtml.includes('data-result-state="admitted-result"') &&
      typeof timelineImplementationResultRef === "string" &&
      timelineImplementationResultRef.startsWith("implementation_result://") &&
      runTimelineHtml.includes(timelineImplementationResultRef) &&
      runTimelineHtml.includes(admittedResult.work_result_id) &&
      runTimelineHtml.includes('data-result-state="retained-provenance"') &&
      typeof timelineSourceCandidateRef === "string" &&
      timelineSourceCandidateRef.startsWith("implementation-result-candidate://") &&
      runTimelineHtml.includes(timelineSourceCandidateRef) &&
      typeof timelineOutputCommitment === "string" &&
      timelineOutputCommitment.startsWith("sha256:") &&
      runTimelineHtml.includes(timelineOutputCommitment) &&
      !goalSpaceHtml.includes(direct.goalRun.goal_ref),
    `${collectiveGoal.goal_ref}/${admittedResult.work_result_id}/${timelineImplementationResultRef}/${timelineSourceCandidateRef}/${timelineOutputCommitment}/${resultAdmissionReceiptRef}/timeline=${runTimelineResponse.status}/mode=${goalSpaceProjectionState}/unavailable=${goalSpaceUnavailable}`,
  );
  check(
    "PRODUCT STATE: selected projection renders the admitted OutcomeDelta identity and receipt",
    goalSpaceHtml.includes(admittedDelta.outcome_delta_id) &&
      containsExactlyOnce(deltaStateHtml, deltaAdmissionReceiptRef) &&
      deltaStateHtml.includes(
        `data-outcome-delta-ref="${htmlAttribute(admittedDelta.outcome_delta_id)}" data-admission-receipt="present"`,
      ),
    `${admittedDelta.outcome_delta_id}/${deltaAdmissionReceiptRef}/mode=${goalSpaceProjectionState}/unavailable=${goalSpaceUnavailable}`,
  );
  check(
    "PRODUCT NONCLAIM: projection is explicitly read-only, derived, and honest-empty for discussion",
    Object.values(productReadOnlyChecks).every(Boolean),
    `mode=${goalSpaceProjectionState}/unavailable=${goalSpaceUnavailable}/checks=${JSON.stringify(productReadOnlyChecks)}`,
  );
  check(
    "PRODUCT NONCLAIM: scope exclusions and payload/admission boundaries are explicit",
    Object.values(productBoundaryChecks).every(Boolean),
    `mode=${goalSpaceProjectionState}/unavailable=${goalSpaceUnavailable}/checks=${JSON.stringify(productBoundaryChecks)}`,
  );
  check(
    "SCOPE BAR: room remains hosted, non-federated, non-external, non-settling, and participant-empty",
    room.coordination_topology === "hosted_admission" &&
      room.multi_party_collaboration_ref === null &&
      room.settlement_policy_ref === null &&
      room.discovery_and_external_admission_policy_refs?.length === 0 &&
      room.participant_lease_refs?.length === 0 &&
      familyCount(dataDir, "outcome-room-registry") === 1,
    `${room.coordination_topology}/federation=${room.multi_party_collaboration_ref}/settlement=${room.settlement_policy_ref}/external=${room.discovery_and_external_admission_policy_refs?.length}/participants=${room.participant_lease_refs?.length}/rooms=${familyCount(dataDir, "outcome-room-registry")}`,
  );
  requireValue(
    fileRootOrNull(DAEMON_BINARY) === builtDaemonRoot,
    "current_daemon_binary_changed_during_aggregate",
  );
  completed = true;
} catch (error) {
  console.error("VERIFIER CRASH:", error);
  // Environmental prerequisite failures are labeled so a reader (or the CI
  // failure-labeling step) can tell "the environment could not host the
  // proof" from "the proof ran and an assertion failed". The label NEVER
  // relaxes anything: the exit stays nonzero and the count enforcement still
  // refuses — provisioning is the fix, not tolerance.
  const crashText = String(error?.message || error);
  const environmental = [
    ["wallet.network fixture did not become ready", "wallet_network_fixture_unready"],
    ["isolated daemon never became healthy", "isolated_daemon_unready"],
    ["isolated serve never became healthy", "isolated_serve_unready"],
    ["model_route", "model_route_unavailable"],
    ["daemon binary", "daemon_binary_unavailable"],
  ].find(([needle]) => crashText.includes(needle));
  if (environmental) {
    console.error(`M4_ENVIRONMENTAL_PREREQUISITE_FAILED=${environmental[1]}`);
  }
  process.exitCode = crashText.startsWith("BLOCKED:")
    ? 2
    : 1;
} finally {
  if (plane) await plane.stop().catch(() => {});
  if (resolver) await resolver.stop().catch(() => {});
  rmSync(dataDir, { recursive: true, force: true });
}

for (const result of checks) {
  console.log(
    `${result.pass ? "PASS" : "FAIL"} ${result.name}${result.detail ? ` — ${result.detail}` : ""}`,
  );
}
const passed = checks.filter((result) => result.pass).length;
console.log(`${passed}/${checks.length} passed`);
const coverageMismatch = checks.length !== EXPECTED_CHECKS;
if (coverageMismatch) {
  console.error(`FAIL verifier coverage changed: expected ${EXPECTED_CHECKS}, got ${checks.length}`);
}
if (!completed || coverageMismatch || passed !== checks.length) {
  process.exitCode = process.exitCode || 1;
}
if (completed && !coverageMismatch && passed === checks.length) {
  console.log(
    "M4 outcome-room system spine: PASS (direct activation, real package/genesis/System, runtime-derived room result, reciprocal CAS, Agentgres replay/recovery, selected ported-shell projection)",
  );
}
