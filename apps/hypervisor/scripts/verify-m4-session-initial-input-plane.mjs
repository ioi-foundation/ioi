#!/usr/bin/env node

// M4 ordinary-composer durability proof. The accepted input remains owner-bound Session
// transcript truth; this verifier also proves that reservation/recovery never mints GoalRun truth.
// Every mutation runs in verifier-owned data/workspace directories against fresh daemon processes.

import { createHash } from "node:crypto";
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  sanitizedVerifierBaseEnv,
  startIsolatedPlane,
} from "./lib/isolated-daemon.mjs";
import { startRealWalletNetworkPrincipalAuthorityFixture } from "./lib/wallet-network-principal-authority-fixture.mjs";

const SESSION_SCHEMA = "ioi.hypervisor.session_record.v1";
const INTENT_FAMILY = "session-create-intents";
const DEPLOYMENT_AUTHORITY_REF = "domain://acme-host";
const SESSION_EXECUTE_SCOPE = "scope:hypervisor.live-route.session-execute";
const checks = [];
const EXPECTED_CHECKS = 111;
let blocked = false;
let executionAuthorityResolver = null;
const CLEAN_BASE_ENV = sanitizedVerifierBaseEnv();

const check = (name, pass, detail = "") =>
  checks.push({ name, pass: Boolean(pass), detail });
const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const jsonText = (value) => JSON.stringify(value);
const roots = (prefix) => {
  const dataDir = mkdtempSync(join(tmpdir(), `${prefix}-data-`));
  const sessionBaseDir = mkdtempSync(join(tmpdir(), `${prefix}-workspaces-`));
  return {
    dataDir,
    sessionBaseDir,
    workspaceFamily: join(sessionBaseDir, "ioi-hypervisor-sessions"),
  };
};
const cleanupRoots = ({ dataDir, sessionBaseDir }) => {
  rmSync(dataDir, { recursive: true, force: true });
  rmSync(sessionBaseDir, { recursive: true, force: true });
};
const filesAt = (root, family) => {
  try {
    return readdirSync(join(root, family));
  } catch {
    return [];
  }
};
const recordsAt = (root, family) =>
  filesAt(root, family)
    .filter((name) => name.endsWith(".json"))
    .flatMap((name) => {
      try {
        return [JSON.parse(readFileSync(join(root, family, name), "utf8"))];
      } catch {
        return [];
      }
    });
const recordAt = (root, family, predicate) => recordsAt(root, family).find(predicate);
const fileCountAt = (root, family) =>
  filesAt(root, family).filter((name) => name.endsWith(".json")).length;
const sessionRecordsAt = (root) =>
  recordsAt(root, "sessions").filter((record) => record.schema_version === SESSION_SCHEMA);
const workspaceCountAt = (workspaceFamily) => {
  try {
    return readdirSync(workspaceFamily).length;
  } catch {
    return 0;
  }
};
const goalTruthAbsent = (dataDir) =>
  fileCountAt(dataDir, "goal-runs") === 0 &&
  fileCountAt(dataDir, "goal-run-activations") === 0;

async function request(base, method, path, body, headers = {}) {
  const response = await fetch(`${base}${path}`, {
    method,
    headers: {
      ...(body === undefined ? {} : { "content-type": "application/json" }),
      ...headers,
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const raw = await response.text();
  let parsed = {};
  try {
    parsed = JSON.parse(raw);
  } catch {
    // Preserve raw response bytes for non-overclaim/leak assertions.
  }
  return { status: response.status, body: parsed, raw };
}

const responseDiagnostic = (response) =>
  `${response?.status ?? 0}/${
    response?.body?.error?.code ||
    (response?.status === 0 ? "transport_error" : "no_typed_error")
  }`;

function seedPrincipal(dataDir, principalId, token) {
  mkdirSync(join(dataDir, "principals"), { recursive: true });
  mkdirSync(join(dataDir, "sessions"), { recursive: true });
  writeFileSync(
    join(dataDir, "principals", `${principalId}.json`),
    `${JSON.stringify({
      schema_version: "ioi.hypervisor.principal.v1",
      principal_id: principalId,
      email: `${principalId}@example.test`,
      name: principalId,
      role: "member",
      status: "active",
      source: "m4-verifier",
      created_at: "2026-07-30T00:00:00Z",
      updated_at: "2026-07-30T00:00:00Z",
    })}\n`,
  );
  writeFileSync(
    join(dataDir, "sessions", `auth-${principalId}.json`),
    `${JSON.stringify({
      session_id: `auth-${principalId}`,
      token_hash: sha256(token),
      principal_id: principalId,
      source: "m4-verifier",
      created_at: "2026-07-30T00:00:00Z",
      expires_at: "2099-12-31T23:59:59Z",
    })}\n`,
  );
}

async function start(root, extraEnv = {}) {
  const plane = await startIsolatedPlane({
    dataDir: root.dataDir,
    baseEnv: CLEAN_BASE_ENV,
    env: {
      IOI_HYPERVISOR_SESSIONS_ROOT: root.sessionBaseDir,
      ...extraEnv,
    },
  });
  if (!plane) blocked = true;
  return plane;
}

async function runCoreIdentityOwnerPlane() {
  const root = roots("ioi-m4-session-core");
  const aliceToken = "m4-session-alice-token";
  const bobToken = "m4-session-bob-token";
  seedPrincipal(root.dataDir, "alice", aliceToken);
  seedPrincipal(root.dataDir, "bob", bobToken);
  const alice = { authorization: `Bearer ${aliceToken}` };
  const bob = { authorization: `Bearer ${bobToken}` };
  let plane = null;
  try {
    plane = await start(root);
    if (!plane) return;

    const invalidType = await request(plane.daemonUrl, "POST", "/v1/hypervisor/sessions", {
      session_ref: "session:m4-invalid-type",
      initial_input: { text: "not a string" },
    });
    const invalidBound = await request(plane.daemonUrl, "POST", "/v1/hypervisor/sessions", {
      session_ref: "session:m4-invalid-bound",
      initial_input: "x".repeat(32_769),
    });
    const invalidRef = await request(plane.daemonUrl, "POST", "/v1/hypervisor/sessions", {
      session_ref: `session:${"r".repeat(505)}`,
      initial_input: "must not provision",
    });
    check(
      "invalid input and non-canonical identity refuse before every durable side effect",
      invalidType.status === 422 &&
        invalidType.body?.error?.code === "session_initial_input_invalid" &&
        invalidBound.status === 422 &&
        invalidBound.body?.error?.code === "session_initial_input_invalid" &&
        invalidRef.status === 422 &&
        invalidRef.body?.error?.code === "session_ref_invalid" &&
        sessionRecordsAt(root.dataDir).length === 0 &&
        fileCountAt(root.dataDir, "receipts") === 0 &&
        fileCountAt(root.dataDir, INTENT_FAMILY) === 0 &&
        workspaceCountAt(root.workspaceFamily) === 0,
      `type=${invalidType.status} bound=${invalidBound.status} ref=${invalidRef.status}`,
    );

    const exposed = { "x-forwarded-host": "public.example.test" };
    const exposedPost = await request(
      plane.daemonUrl,
      "POST",
      "/v1/hypervisor/sessions",
      { session_ref: "session:m4-exposed-denied", initial_input: "private exposed prompt" },
      exposed,
    );
    const exposedList = await request(
      plane.daemonUrl,
      "GET",
      "/v1/hypervisor/sessions",
      undefined,
      exposed,
    );
    const exposedGet = await request(
      plane.daemonUrl,
      "GET",
      "/v1/hypervisor/sessions/session%3Am4-exposed-denied",
      undefined,
      exposed,
    );
    check(
      "anonymous exposed create/list/get deny before recovery, projection, or provisioning",
      exposedPost.status === 401 &&
        exposedList.status === 401 &&
        exposedGet.status === 401 &&
        sessionRecordsAt(root.dataDir).length === 0 &&
        fileCountAt(root.dataDir, "receipts") === 0 &&
        fileCountAt(root.dataDir, INTENT_FAMILY) === 0 &&
        workspaceCountAt(root.workspaceFamily) === 0,
      `${exposedPost.status}/${exposedList.status}/${exposedGet.status}`,
    );

    mkdirSync(join(root.dataDir, "environments"), { recursive: true });
    const ownedEnvironmentWorkspace = join(root.sessionBaseDir, "alice-environment-workspace");
    mkdirSync(ownedEnvironmentWorkspace);
    writeFileSync(
      join(root.dataDir, "environments", "env-alice.json"),
      `${JSON.stringify({
        id: "env-alice",
        owner_ref: "user://alice",
        status: {
          workspace_root: ownedEnvironmentWorkspace,
          tenant_posture: "single_user",
        },
      })}\n`,
    );
    const crossOwnerEnvironment = await request(
      plane.daemonUrl,
      "POST",
      "/v1/hypervisor/sessions",
      {
        session_ref: "session:m4-cross-owner-environment",
        environment_id: "env-alice",
        initial_input: "must not bind Alice workspace",
      },
      bob,
    );
    const symlinkTarget = join(root.sessionBaseDir, "symlink-environment-target");
    const symlinkWorkspace = join(root.sessionBaseDir, "symlink-environment-workspace");
    mkdirSync(symlinkTarget);
    symlinkSync(symlinkTarget, symlinkWorkspace);
    writeFileSync(
      join(root.dataDir, "environments", "env-symlink.json"),
      `${JSON.stringify({
        id: "env-symlink",
        owner_ref: "user://alice",
        status: { workspace_root: symlinkWorkspace, tenant_posture: "single_user" },
      })}\n`,
    );
    const symlinkEnvironment = await request(
      plane.daemonUrl,
      "POST",
      "/v1/hypervisor/sessions",
      {
        session_ref: "session:m4-symlink-environment",
        environment_id: "env-symlink",
        initial_input: "must not follow environment symlink",
      },
      alice,
    );
    check(
      "existing-environment bind enforces principal ownership and no-follow workspace containment",
      crossOwnerEnvironment.status === 412 &&
        crossOwnerEnvironment.body?.error?.code === "session_environment_binding_refused" &&
        symlinkEnvironment.status === 412 &&
        symlinkEnvironment.body?.error?.code === "session_environment_binding_refused" &&
        fileCountAt(root.dataDir, INTENT_FAMILY) === 0 &&
        workspaceCountAt(root.workspaceFamily) === 0,
      `${crossOwnerEnvironment.status}/${symlinkEnvironment.status}`,
    );

    const sessionRef = "session:m4-ported-composer";
    const initialInput =
      "Research the hosted OutcomeRoom admission boundary.\nRetain negative evidence.";
    const createBody = { initial_input: initialInput, session_ref: sessionRef };
    const created = await request(
      plane.daemonUrl,
      "POST",
      "/v1/hypervisor/sessions",
      createBody,
    );
    const replay = await request(
      plane.daemonUrl,
      "POST",
      "/v1/hypervisor/sessions",
      { session_ref: sessionRef, initial_input: initialInput },
    );
    const contentHash = `sha256:${sha256(initialInput)}`;
    const projection = created.body?.initial_input_projection;
    check(
      "ordinary composer creates one owner-bound receipt-backed Session projection",
      created.status === 202 &&
        created.body?.idempotent_replay === false &&
        created.body?.owner_ref === "user://local-operator" &&
        projection?.truth_class === "session_transcript" &&
        projection?.disposition === "session_only_non_goal" &&
        projection?.content === initialInput &&
        projection?.content_hash === contentHash &&
        projection?.owner_ref === "user://local-operator" &&
        projection?.goal_run_ref === null &&
        projection?.goal_run_activation_ref === null &&
        goalTruthAbsent(root.dataDir),
      `${created.status}/${created.body?.error?.code}`,
    );
    check(
      "same canonical identity and JCS-equivalent body replay without a second workspace or receipt",
      replay.status === 202 &&
        replay.body?.idempotent_replay === true &&
        replay.body?.request_hash === created.body?.request_hash &&
        sessionRecordsAt(root.dataDir).length === 1 &&
        fileCountAt(root.dataDir, "receipts") === 2 &&
        fileCountAt(root.dataDir, INTENT_FAMILY) === 1 &&
        workspaceCountAt(root.workspaceFamily) === 1,
      `${replay.status}/${replay.body?.error?.code}`,
    );

    const changedBody = await request(
      plane.daemonUrl,
      "POST",
      "/v1/hypervisor/sessions",
      { session_ref: sessionRef, initial_input: `${initialInput} changed` },
    );
    check(
      "same Session identity with a changed body is a no-clobber conflict",
      changedBody.status === 409 &&
        changedBody.body?.error?.code === "session_create_idempotency_conflict" &&
        sessionRecordsAt(root.dataDir).length === 1 &&
        fileCountAt(root.dataDir, "receipts") === 2 &&
        workspaceCountAt(root.workspaceFamily) === 1,
      `${changedBody.status}/${changedBody.body?.error?.code}`,
    );

    const expectedIntent = `session_create_${sha256(sessionRef)}.json`;
    const expectedSession = `session_${sha256(sessionRef)}.json`;
    check(
      "Session WAL and record keys bind the full exact identity digest",
      existsSync(join(root.dataDir, INTENT_FAMILY, expectedIntent)) &&
        existsSync(join(root.dataDir, "sessions", expectedSession)),
      `${expectedIntent}/${expectedSession}`,
    );

    const beforeRestart = JSON.stringify(projection);
    await plane.stop();
    plane = await start(root);
    if (!plane) return;
    const readAfterRestart = await request(
      plane.daemonUrl,
      "GET",
      `/v1/hypervisor/sessions/${encodeURIComponent(sessionRef)}`,
    );
    check(
      "fresh process replays byte-identical Session transcript truth",
      readAfterRestart.status === 200 &&
        JSON.stringify(readAfterRestart.body?.session?.initial_input_projection) === beforeRestart &&
        readAfterRestart.body?.session?.owner_ref === "user://local-operator" &&
        goalTruthAbsent(root.dataDir),
      `${readAfterRestart.status}/${readAfterRestart.body?.error?.code}`,
    );

    const prefix = "x".repeat(72);
    const collisionA = `session:${prefix}-a`;
    const collisionB = `session:${prefix}-b`;
    const collisionCreateA = await request(
      plane.daemonUrl,
      "POST",
      "/v1/hypervisor/sessions",
      { session_ref: collisionA, initial_input: "collision lane A" },
    );
    const collisionCreateB = await request(
      plane.daemonUrl,
      "POST",
      "/v1/hypervisor/sessions",
      { session_ref: collisionB, initial_input: "collision lane B" },
    );
    const collisionRecordA = recordAt(
      root.dataDir,
      "sessions",
      (record) => record.session_ref === collisionA,
    );
    const collisionRecordB = recordAt(
      root.dataDir,
      "sessions",
      (record) => record.session_ref === collisionB,
    );
    check(
      "identities sharing the old normalized/truncated prefix never alias",
      collisionCreateA.status === 202 &&
        collisionCreateB.status === 202 &&
        collisionRecordA?.workspace_root !== collisionRecordB?.workspace_root &&
        existsSync(join(root.dataDir, INTENT_FAMILY, `session_create_${sha256(collisionA)}.json`)) &&
        existsSync(join(root.dataDir, INTENT_FAMILY, `session_create_${sha256(collisionB)}.json`)) &&
        existsSync(join(root.dataDir, "sessions", `session_${sha256(collisionA)}.json`)) &&
        existsSync(join(root.dataDir, "sessions", `session_${sha256(collisionB)}.json`)),
      `${collisionCreateA.status}/${collisionCreateB.status}`,
    );
    const collisionATornDown = await request(
      plane.daemonUrl,
      "DELETE",
      `/v1/hypervisor/sessions/${encodeURIComponent(collisionA)}`,
    );
    const collisionBRead = await request(
      plane.daemonUrl,
      "GET",
      `/v1/hypervisor/sessions/${encodeURIComponent(collisionB)}`,
    );
    check(
      "teardown of one formerly-colliding identity cannot delete or mutate its sibling",
      collisionATornDown.status === 200 &&
        collisionATornDown.body?.workspace_removed === true &&
        typeof collisionRecordA?.workspace_root === "string" &&
        !existsSync(collisionRecordA.workspace_root) &&
        typeof collisionRecordB?.workspace_root === "string" &&
        existsSync(collisionRecordB.workspace_root) &&
        collisionBRead.status === 200 &&
        collisionBRead.body?.session?.initial_input_projection?.content === "collision lane B",
      `${collisionATornDown.status}/${collisionBRead.status}`,
    );

    const aliceRef = "session:m4-owner-alice";
    const alicePrompt = "Alice private hosted-room prompt";
    const aliceCreated = await request(
      plane.daemonUrl,
      "POST",
      "/v1/hypervisor/sessions",
      { session_ref: aliceRef, initial_input: alicePrompt },
      alice,
    );
    const bobGet = await request(
      plane.daemonUrl,
      "GET",
      `/v1/hypervisor/sessions/${encodeURIComponent(aliceRef)}`,
      undefined,
      bob,
    );
    const bobList = await request(
      plane.daemonUrl,
      "GET",
      "/v1/hypervisor/sessions",
      undefined,
      bob,
    );
    const bobCollision = await request(
      plane.daemonUrl,
      "POST",
      "/v1/hypervisor/sessions",
      { session_ref: aliceRef, initial_input: alicePrompt },
      bob,
    );
    const bobEvents = await request(
      plane.daemonUrl,
      "GET",
      `/v1/hypervisor/sessions/${encodeURIComponent(aliceRef)}/events`,
      undefined,
      bob,
    );
    const bobExecute = await request(
      plane.daemonUrl,
      "POST",
      `/v1/hypervisor/sessions/${encodeURIComponent(aliceRef)}/execute`,
      { lane: "native_local", intent: "must not reach the wallet gate" },
      bob,
    );
    const bobPorts = await request(
      plane.daemonUrl,
      "POST",
      `/v1/hypervisor/sessions/${encodeURIComponent(aliceRef)}/ports/revoke`,
      {},
      bob,
    );
    const bobDelete = await request(
      plane.daemonUrl,
      "DELETE",
      `/v1/hypervisor/sessions/${encodeURIComponent(aliceRef)}`,
      undefined,
      bob,
    );
    const aliceGet = await request(
      plane.daemonUrl,
      "GET",
      `/v1/hypervisor/sessions/${encodeURIComponent(aliceRef)}`,
      undefined,
      alice,
    );
    check(
      "authenticated Session create binds daemon-resolved principal ownership",
      aliceCreated.status === 202 &&
        aliceCreated.body?.owner_ref === "user://alice" &&
        aliceCreated.body?.initial_input_projection?.owner_ref === "user://alice" &&
        aliceGet.status === 200 &&
        aliceGet.body?.session?.owner_ref === "user://alice" &&
        aliceGet.body?.session?.initial_input_projection?.content === alicePrompt,
      `${aliceCreated.status}/${aliceGet.status}`,
    );
    check(
      "list/get/idempotency conflict never project one principal's prompt to another",
      bobGet.status === 404 &&
        !bobGet.raw.includes(alicePrompt) &&
        bobList.status === 200 &&
        bobList.body?.sessions?.every((record) => record.session_ref !== aliceRef) &&
        !bobList.raw.includes(alicePrompt) &&
        bobCollision.status === 409 &&
        !bobCollision.raw.includes(alicePrompt) &&
        goalTruthAbsent(root.dataDir),
      `${bobGet.status}/${bobList.status}/${bobCollision.status}`,
    );
    const aliceWorkspace = recordAt(
      root.dataDir,
      "sessions",
      (record) => record.session_ref === aliceRef,
    )?.workspace_root;
    check(
      "events/execute/port-revoke/teardown authorize owner before projection, wallet challenge, or effect",
      [bobEvents, bobExecute, bobPorts, bobDelete].every(
        (response) => response.status === 404 && !response.raw.includes(alicePrompt),
      ) &&
        typeof aliceWorkspace === "string" &&
        existsSync(aliceWorkspace),
      `${bobEvents.status}/${bobExecute.status}/${bobPorts.status}/${bobDelete.status}`,
    );
    const exposedEvents = await request(
      plane.daemonUrl,
      "GET",
      `/v1/hypervisor/sessions/${encodeURIComponent(aliceRef)}/events`,
      undefined,
      exposed,
    );
    const exposedExecute = await request(
      plane.daemonUrl,
      "POST",
      `/v1/hypervisor/sessions/${encodeURIComponent(aliceRef)}/execute`,
      { intent: "anonymous effect" },
      exposed,
    );
    const exposedPorts = await request(
      plane.daemonUrl,
      "POST",
      `/v1/hypervisor/sessions/${encodeURIComponent(aliceRef)}/ports/revoke`,
      {},
      exposed,
    );
    const exposedDelete = await request(
      plane.daemonUrl,
      "DELETE",
      `/v1/hypervisor/sessions/${encodeURIComponent(aliceRef)}`,
      undefined,
      exposed,
    );
    check(
      "anonymous exposed events/execute/port-revoke/teardown all deny without owner leakage",
      [exposedEvents, exposedExecute, exposedPorts, exposedDelete].every(
        (response) => response.status === 401 && !response.raw.includes(alicePrompt),
      ),
      `${exposedEvents.status}/${exposedExecute.status}/${exposedPorts.status}/${exposedDelete.status}`,
    );

    const tornDown = await request(
      plane.daemonUrl,
      "DELETE",
      `/v1/hypervisor/sessions/${encodeURIComponent(sessionRef)}`,
    );
    const readTornDown = await request(
      plane.daemonUrl,
      "GET",
      `/v1/hypervisor/sessions/${encodeURIComponent(sessionRef)}`,
    );
    check(
      "later Session lifecycle mutation advances the exact digest slot without split truth",
      tornDown.status === 200 &&
        tornDown.body?.workspace_removed === true &&
        readTornDown.status === 200 &&
        readTornDown.body?.session?.lifecycle_state === "torn_down" &&
        readTornDown.body?.session?.initial_input_projection?.content === initialInput &&
        sessionRecordsAt(root.dataDir).filter((record) => record.session_ref === sessionRef)
          .length === 1 &&
        existsSync(join(root.dataDir, "sessions", expectedSession)) &&
        goalTruthAbsent(root.dataDir),
      `${tornDown.status}/${readTornDown.status}`,
    );
  } finally {
    if (plane) await plane.stop();
    cleanupRoots(root);
  }
}

async function runCrossProcessConcurrencyPlane() {
  const root = roots("ioi-m4-session-concurrent");
  let first = null;
  let second = null;
  try {
    first = await start(root);
    second = await start(root);
    if (!first || !second) return;
    const sessionRef = "session:m4-cross-process-same-key";
    const body = { session_ref: sessionRef, initial_input: "one reservation, one workspace" };
    const [left, right] = await Promise.all([
      request(first.daemonUrl, "POST", "/v1/hypervisor/sessions", body),
      request(second.daemonUrl, "POST", "/v1/hypervisor/sessions", body),
    ]);
    const dispositions = [left.body?.idempotent_replay, right.body?.idempotent_replay].sort();
    check(
      "cross-process same-ref concurrency elects exactly one reservation/provisioning winner",
      left.status === 202 &&
        right.status === 202 &&
        dispositions[0] === false &&
        dispositions[1] === true &&
        fileCountAt(root.dataDir, INTENT_FAMILY) === 1 &&
        sessionRecordsAt(root.dataDir).length === 1 &&
        fileCountAt(root.dataDir, "receipts") === 2 &&
        workspaceCountAt(root.workspaceFamily) === 1 &&
        goalTruthAbsent(root.dataDir),
      `${left.status}/${right.status} replay=${jsonText(dispositions)}`,
    );
  } finally {
    if (first) await first.stop();
    if (second) await second.stop();
    cleanupRoots(root);
  }
}

async function runDurabilityFaultLane({ fault, sessionRef, before, recoveryVia = "get" }) {
  const root = roots("ioi-m4-session-fault");
  const initialInput = `Durability fault lane ${fault}; remain Session-only.`;
  let plane = null;
  let firstResponse = null;
  let transportCrashed = false;
  try {
    plane = await start(root, { IOI_TEST_SESSION_CREATE_DURABILITY_FAULT: fault });
    if (!plane) return;
    try {
      firstResponse = await request(plane.daemonUrl, "POST", "/v1/hypervisor/sessions", {
        session_ref: sessionRef,
        initial_input: initialInput,
      });
    } catch (error) {
      transportCrashed = true;
      firstResponse = { status: 0, body: {}, raw: String(error) };
    }
    const crash = fault.startsWith("crash:");
    const expectedFailCode = fault === "fail:prepare_intent"
      ? "session_create_reservation_failed"
      : "session_create_persist_failed";
    check(
      `${fault} cannot return false Session-create success`,
      crash
        ? transportCrashed && firstResponse.status !== 202
        : firstResponse.status === 503 && firstResponse.body?.error?.code === expectedFailCode,
      responseDiagnostic(firstResponse),
    );

    const intent = recordAt(
      root.dataDir,
      INTENT_FAMILY,
      (record) => record.session_ref === sessionRef,
    );
    check(
      `${fault} leaves exactly the declared durable boundary and no Goal identity`,
      (before.status === null ? intent === undefined : intent?.status === before.status) &&
        fileCountAt(root.dataDir, "receipts") === before.receipts &&
        sessionRecordsAt(root.dataDir).length === before.sessions &&
        workspaceCountAt(root.workspaceFamily) === before.workspaces &&
        goalTruthAbsent(root.dataDir),
      `intent=${intent?.status || "absent"} receipts=${fileCountAt(root.dataDir, "receipts")} sessions=${sessionRecordsAt(root.dataDir).length} workspaces=${workspaceCountAt(root.workspaceFamily)}`,
    );

    await plane.stop();
    plane = await start(root);
    if (!plane) return;
    let recovered;
    if (before.status === null) {
      recovered = await request(plane.daemonUrl, "POST", "/v1/hypervisor/sessions", {
        session_ref: sessionRef,
        initial_input: initialInput,
      });
    } else if (recoveryVia === "list") {
      const listed = await request(plane.daemonUrl, "GET", "/v1/hypervisor/sessions");
      check(
        `${fault} list performs recovery before projecting Session truth`,
        listed.status === 200 &&
          listed.body?.sessions?.some((record) => record.session_ref === sessionRef) &&
          !listed.raw.includes(initialInput),
        `${listed.status}/${listed.body?.error?.code}`,
      );
      recovered = await request(
        plane.daemonUrl,
        "GET",
        `/v1/hypervisor/sessions/${encodeURIComponent(sessionRef)}`,
      );
    } else {
      recovered = await request(
        plane.daemonUrl,
        "GET",
        `/v1/hypervisor/sessions/${encodeURIComponent(sessionRef)}`,
      );
    }
    const recoveredRecord = before.status === null
      ? recovered.body
      : recovered.body?.session;
    const recoveredProjection = before.status === null
      ? recovered.body?.initial_input_projection
      : recovered.body?.session?.initial_input_projection;
    const committed = recordAt(
      root.dataDir,
      INTENT_FAMILY,
      (record) => record.session_ref === sessionRef,
    );
    check(
      `${fault} fresh-process recovery converges to one complete committed Session bundle`,
      recovered.status === (before.status === null ? 202 : 200) &&
        recoveredProjection?.content === initialInput &&
        recoveredProjection?.disposition === "session_only_non_goal" &&
        recoveredProjection?.goal_run_ref === null &&
        recoveredProjection?.goal_run_activation_ref === null &&
        committed?.status === "committed" &&
        typeof committed?.committed_at === "string" &&
        fileCountAt(root.dataDir, "receipts") === 2 &&
        sessionRecordsAt(root.dataDir).length === 1 &&
        workspaceCountAt(root.workspaceFamily) === 1 &&
        recoveredRecord?.latest_receipt_refs?.length === 2 &&
        goalTruthAbsent(root.dataDir),
      `${recovered.status}/${recovered.body?.error?.code} intent=${committed?.status}`,
    );
  } finally {
    if (plane) await plane.stop();
    cleanupRoots(root);
  }
}

async function runLifecycleFaultLane({ fault, operation }) {
  const root = roots("ioi-m4-session-lifecycle-fault");
  const sessionRef = `session:m4-${fault.replace(":", "-")}`;
  const initialInput = `Lifecycle durability lane ${fault}`;
  let plane = null;
  try {
    plane = await start(root, { IOI_TEST_SESSION_LIFECYCLE_DURABILITY_FAULT: fault });
    if (!plane) return;
    const created = await request(plane.daemonUrl, "POST", "/v1/hypervisor/sessions", {
      session_ref: sessionRef,
      initial_input: initialInput,
    });
    const workspace = recordAt(
      root.dataDir,
      "sessions",
      (record) => record.session_ref === sessionRef,
    )?.workspace_root || "";
    check(`${fault} fixture Session commits before lifecycle fault`, created.status === 202);
    let result;
    let crashed = false;
    try {
      result = operation === "teardown"
        ? await request(
            plane.daemonUrl,
            "DELETE",
            `/v1/hypervisor/sessions/${encodeURIComponent(sessionRef)}`,
          )
        : await request(
            plane.daemonUrl,
            "POST",
            `/v1/hypervisor/sessions/${encodeURIComponent(sessionRef)}/ports/revoke`,
            {},
          );
    } catch (error) {
      crashed = true;
      result = { status: 0, body: {}, raw: String(error) };
    }
    const isCrash = fault.startsWith("crash:");
    check(
      `${fault} never returns false lifecycle success`,
      isCrash
        ? crashed && result.status !== 200
        : result.status === 503 &&
          result.body?.error?.code === "session_lifecycle_durability_unconfirmed",
      responseDiagnostic(result),
    );
    const beforeRestart = recordAt(
      root.dataDir,
      "sessions",
      (record) => record.session_ref === sessionRef,
    );
    if (fault === "fail:teardown_session_prepared") {
      check(
        `${fault} preserves workspace and pre-effect Session truth`,
        !beforeRestart?.pending_teardown &&
          beforeRestart?.lifecycle_state === "provisioned" &&
          typeof workspace === "string" &&
          existsSync(workspace),
      );
    } else if (operation === "teardown") {
      check(
        `${fault} retains a teardown replay anchor without reporting success`,
        beforeRestart?.pending_teardown &&
          typeof workspace === "string" &&
          (fault === "crash:teardown_session_prepared"
            ? existsSync(workspace)
            : !existsSync(workspace)),
      );
    } else {
      check(
        `${fault} retains a port-revoke replay anchor without reporting success`,
        beforeRestart?.pending_port_revoke,
      );
    }
    await plane.stop();
    plane = await start(root);
    if (!plane) return;
    let recovered = await request(
      plane.daemonUrl,
      "GET",
      `/v1/hypervisor/sessions/${encodeURIComponent(sessionRef)}`,
    );
    if (fault === "fail:teardown_session_prepared") {
      check(
        `${fault} restart keeps the unexecuted operation unapplied`,
        recovered.status === 200 &&
          recovered.body?.session?.lifecycle_state === "provisioned" &&
          existsSync(workspace),
      );
      recovered = await request(
        plane.daemonUrl,
        "DELETE",
        `/v1/hypervisor/sessions/${encodeURIComponent(sessionRef)}`,
      );
      check(
        `${fault} explicit retry reaches a durable teardown`,
        recovered.status === 200 && recovered.body?.workspace_removed === true,
      );
    } else if (operation === "teardown") {
      check(
        `${fault} fresh read recovers durable teardown before projection`,
        recovered.status === 200 &&
          recovered.body?.session?.lifecycle_state === "torn_down" &&
          !recovered.body?.session?.pending_teardown &&
          !existsSync(workspace),
        `${recovered.status}/${recovered.body?.error?.code}`,
      );
    } else {
      check(
        `${fault} fresh read recovers durable port-revoke before projection`,
        recovered.status === 200 &&
          !recovered.body?.session?.pending_port_revoke &&
          goalTruthAbsent(root.dataDir),
        `${recovered.status}/${recovered.body?.error?.code}`,
      );
    }
  } finally {
    if (plane) await plane.stop();
    cleanupRoots(root);
  }
}

async function runExecutionFaultLane({ fault, recovery }) {
  const root = roots("ioi-m4-session-execute-fault");
  const tag = fault.replace(":", "-");
  const sessionRef = `session:m4-execute-${tag}`;
  const intent = `write the deterministic native-local durability artifact for ${fault}`;
  let plane = null;
  try {
    plane = await start(root, {
      ...executionAuthorityResolver.env,
      IOI_HYPERVISOR_AUTHORITY_PRINCIPAL_REF: DEPLOYMENT_AUTHORITY_REF,
      IOI_TEST_SESSION_EXECUTE_DURABILITY_FAULT: fault,
    });
    if (!plane) return;
    const created = await request(plane.daemonUrl, "POST", "/v1/hypervisor/sessions", {
      session_ref: sessionRef,
      initial_input: `Execution durability fixture ${fault}`,
    });
    check(`${fault} fixture Session commits before execution fault`, created.status === 202);
    const workspace = recordAt(
      root.dataDir,
      "sessions",
      (record) => record.session_ref === sessionRef,
    )?.workspace_root;
    const executePath = `/v1/hypervisor/sessions/${encodeURIComponent(sessionRef)}/execute`;
    const challenge = await request(plane.daemonUrl, "POST", executePath, {
      lane: "native_local",
      intent,
    });
    const grant = await executionAuthorityResolver.mintRecorded(
      DEPLOYMENT_AUTHORITY_REF,
      challenge.body?.approval?.policy_hash,
      challenge.body?.approval?.request_hash,
      SESSION_EXECUTE_SCOPE,
    );
    let executed;
    let crashed = false;
    try {
      executed = await request(plane.daemonUrl, "POST", executePath, {
        lane: "native_local",
        intent,
        wallet_approval_grant: grant,
      });
    } catch (error) {
      crashed = true;
      executed = { status: 0, body: {}, raw: String(error) };
    }
    const isCrash = fault.startsWith("crash:");
    check(
      `${fault} never reports execution success across an unconfirmed durability boundary`,
      challenge.status === 403 &&
        challenge.body?.reason === "execution_authority_required" &&
        (isCrash
          ? crashed && executed.status !== 200
          : executed.status === 503 &&
            executed.body?.error?.code === "session_execute_durability_unconfirmed"),
      `${responseDiagnostic(challenge)}/${responseDiagnostic(executed)}`,
    );
    const artifact = workspace
      ? join(workspace, "lane-b-native-local", "decision-step.md")
      : "";
    const beforeRestart = recordAt(
      root.dataDir,
      "sessions",
      (record) => record.session_ref === sessionRef,
    );
    const phase = beforeRestart?.pending_execution_commit?.phase;
    const artifactBefore = Boolean(artifact && existsSync(artifact));
    const mtimeBefore = artifactBefore ? statSync(artifact).mtimeMs : null;
    check(
      `${fault} leaves the exact pre-effect or retained-outcome recovery anchor`,
      (recovery === "unapplied" && !beforeRestart?.pending_execution_commit && !artifactBefore) ||
        (recovery === "interrupted" && phase === "prepared" &&
          artifactBefore === (fault === "fail:execute_outcome_prepared")) ||
        (recovery === "committed" &&
          (phase === "outcome_ready" || !beforeRestart?.pending_execution_commit) &&
          artifactBefore),
      `phase=${phase || "absent"} artifact=${artifactBefore}`,
    );

    await plane.stop();
    plane = await start(root, {
      ...executionAuthorityResolver.env,
      IOI_HYPERVISOR_AUTHORITY_PRINCIPAL_REF: DEPLOYMENT_AUTHORITY_REF,
    });
    if (!plane) return;
    const recovered = await request(
      plane.daemonUrl,
      "GET",
      `/v1/hypervisor/sessions/${encodeURIComponent(sessionRef)}`,
    );
    const session = recovered.body?.session;
    const recoveredReceipt = recordAt(
      root.dataDir,
      "receipts",
      (record) => record.session_ref === sessionRef &&
        ["success", "failure", "interrupted_unconfirmed"].includes(record.exit_status),
    );
    const artifactAfter = Boolean(artifact && existsSync(artifact));
    const mtimeAfter = artifactAfter ? statSync(artifact).mtimeMs : null;
    check(
      `${fault} fresh read converges without replaying an unconfirmed external effect`,
      recovered.status === 200 &&
        !session?.pending_execution_commit &&
        (recovery === "unapplied"
          ? session?.lifecycle_state === "provisioned" && !artifactAfter
          : recovery === "interrupted"
            ? session?.lifecycle_state === "execution_interrupted_unconfirmed" &&
              recoveredReceipt?.exit_status === "interrupted_unconfirmed" &&
              recoveredReceipt?.status === "recovered_without_reexecution" &&
              artifactAfter === artifactBefore &&
              mtimeAfter === mtimeBefore
            : session?.lifecycle_state === "executed_native_local" &&
              recoveredReceipt?.exit_status === "success" &&
              artifactAfter &&
              mtimeAfter === mtimeBefore) &&
        goalTruthAbsent(root.dataDir),
      `${recovered.status}/${session?.lifecycle_state}/${recoveredReceipt?.exit_status}`,
    );
  } finally {
    if (plane) await plane.stop();
    cleanupRoots(root);
  }
}

async function runStrictWalAdversarialPlane() {
  const root = roots("ioi-m4-session-wal");
  let plane = null;
  try {
    plane = await start(root);
    if (!plane) return;
    const baselineRef = "session:m4-wal-baseline";
    const baselinePrompt = "baseline prompt must never escape a failed WAL census";
    const baseline = await request(plane.daemonUrl, "POST", "/v1/hypervisor/sessions", {
      session_ref: baselineRef,
      initial_input: baselinePrompt,
    });
    check("strict-WAL adversarial plane has a committed baseline", baseline.status === 202);

    const walDir = join(root.dataDir, INTENT_FAMILY);
    const outsideTarget = join(root.dataDir, "outside-wal-target.json");
    const secret = "symlink-target-secret-must-not-project";
    writeFileSync(outsideTarget, `${JSON.stringify({ secret })}\n`);
    const fixtures = [
      {
        name: "corrupt",
        path: join(walDir, `session_create_${"a".repeat(64)}.json`),
        install: (path) => writeFileSync(path, "{not-json\n"),
        cleanup: (path) => unlinkSync(path),
      },
      {
        name: "unreadable",
        path: join(walDir, `session_create_${"b".repeat(64)}.json`),
        install: (path) => {
          writeFileSync(path, "{}\n");
          chmodSync(path, 0o000);
        },
        cleanup: (path) => {
          chmodSync(path, 0o600);
          unlinkSync(path);
        },
      },
      {
        name: "symlink",
        path: join(walDir, `session_create_${"c".repeat(64)}.json`),
        install: (path) => symlinkSync(outsideTarget, path),
        cleanup: (path) => unlinkSync(path),
      },
      {
        name: "semantic-invalid",
        sessionRef: "session:m4-semantic-invalid-wal",
        path: null,
        install(path, sessionRef) {
          const key = `session_create_${sha256(sessionRef)}`;
          writeFileSync(
            path,
            `${JSON.stringify({
              schema_version: "ioi.hypervisor.session_create_intent.v1",
              intent_key: key,
              session_ref: sessionRef,
              owner_ref: "user://local-operator",
              request_hash: `sha256:${"d".repeat(64)}`,
              status: "committed",
            })}\n`,
          );
        },
        cleanup: (path) => unlinkSync(path),
        expectedCode: "session_create_recovery_intent_invalid",
      },
    ];
    for (const fixture of fixtures) {
      const fixturePath = fixture.path || join(
        walDir,
        `session_create_${sha256(fixture.sessionRef)}.json`,
      );
      fixture.install(fixturePath, fixture.sessionRef);
      const beforeIntentFiles = fileCountAt(root.dataDir, INTENT_FAMILY);
      const beforeSessions = sessionRecordsAt(root.dataDir).length;
      const beforeReceipts = fileCountAt(root.dataDir, "receipts");
      const beforeWorkspaces = workspaceCountAt(root.workspaceFamily);
      const list = await request(plane.daemonUrl, "GET", "/v1/hypervisor/sessions");
      const get = await request(
        plane.daemonUrl,
        "GET",
        `/v1/hypervisor/sessions/${encodeURIComponent(baselineRef)}`,
      );
      const post = await request(plane.daemonUrl, "POST", "/v1/hypervisor/sessions", {
        session_ref: `session:m4-wal-blocked-${fixture.name}`,
        initial_input: `blocked ${fixture.name} prompt`,
      });
      let fixturePreserved = existsSync(fixturePath);
      if (fixture.name === "symlink") fixturePreserved = lstatSync(fixturePath).isSymbolicLink();
      const expectedCode = fixture.expectedCode || "session_create_wal_unavailable";
      check(
        `${fixture.name} WAL slot makes list/get/create typed-unavailable without partial projection`,
        [list, get, post].every(
          (response) =>
            response.status === 503 &&
            response.body?.error?.code === expectedCode,
        ) &&
          !list.raw.includes(baselinePrompt) &&
          !get.raw.includes(baselinePrompt) &&
          !post.raw.includes(`blocked ${fixture.name} prompt`) &&
          !list.raw.includes(secret) &&
          !get.raw.includes(secret) &&
          !post.raw.includes(secret) &&
          fixturePreserved &&
          fileCountAt(root.dataDir, INTENT_FAMILY) === beforeIntentFiles &&
          sessionRecordsAt(root.dataDir).length === beforeSessions &&
          fileCountAt(root.dataDir, "receipts") === beforeReceipts &&
          workspaceCountAt(root.workspaceFamily) === beforeWorkspaces &&
          goalTruthAbsent(root.dataDir),
        `${list.status}/${get.status}/${post.status}`,
      );
      fixture.cleanup(fixturePath);
    }

    const committedIntent = recordAt(
      root.dataDir,
      INTENT_FAMILY,
      (record) => record.session_ref === baselineRef,
    );
    const provisionKey = committedIntent?.provisioning_receipt?.record_key;
    const provisionPath = join(root.dataDir, "receipts", `${provisionKey}.json`);
    const provisionBytes = readFileSync(provisionPath);
    unlinkSync(provisionPath);
    const missingMemberList = await request(
      plane.daemonUrl,
      "GET",
      "/v1/hypervisor/sessions",
    );
    check(
      "committed WAL marker cannot act as an umbrella claim over a missing durable member",
      missingMemberList.status === 503 &&
        missingMemberList.body?.error?.code === "session_create_wal_unavailable" &&
        !missingMemberList.raw.includes(baselinePrompt) &&
        sessionRecordsAt(root.dataDir).length === 1 &&
        workspaceCountAt(root.workspaceFamily) === 1 &&
        goalTruthAbsent(root.dataDir),
      `${missingMemberList.status}/${missingMemberList.body?.error?.code}`,
    );
    writeFileSync(provisionPath, provisionBytes);

    const sessionDir = join(root.dataDir, "sessions");
    const registryFixtures = [
      {
        name: "corrupt",
        path: join(sessionDir, "orphan-corrupt.json"),
        install: (path) => writeFileSync(path, "{not-json\n"),
      },
      {
        name: "symlink",
        path: join(sessionDir, "orphan-symlink.json"),
        install: (path) => symlinkSync(outsideTarget, path),
      },
    ];
    for (const fixture of registryFixtures) {
      fixture.install(fixture.path);
      const strictList = await request(plane.daemonUrl, "GET", "/v1/hypervisor/sessions");
      check(
        `${fixture.name} Session-registry slot blocks a partial list through the pinned no-follow census`,
        strictList.status === 503 &&
          strictList.body?.error?.code === "session_registry_unavailable" &&
          !strictList.raw.includes(baselinePrompt) &&
          !strictList.raw.includes(secret) &&
          existsSync(fixture.path) &&
          goalTruthAbsent(root.dataDir),
        `${strictList.status}/${strictList.body?.error?.code}`,
      );
      unlinkSync(fixture.path);
    }

    const sessionKey = committedIntent?.session_record?.record_key;
    const sessionPath = join(root.dataDir, "sessions", `${sessionKey}.json`);
    const sessionBytes = readFileSync(sessionPath);
    const poisonedSession = JSON.parse(sessionBytes.toString("utf8"));
    const mustSurvive = join(root.dataDir, "must-survive-teardown-containment");
    mkdirSync(mustSurvive);
    poisonedSession.workspace_root = mustSurvive;
    writeFileSync(sessionPath, `${JSON.stringify(poisonedSession)}\n`);
    const poisonedGet = await request(
      plane.daemonUrl,
      "GET",
      `/v1/hypervisor/sessions/${encodeURIComponent(baselineRef)}`,
    );
    const poisonedDelete = await request(
      plane.daemonUrl,
      "DELETE",
      `/v1/hypervisor/sessions/${encodeURIComponent(baselineRef)}`,
    );
    check(
      "tampered workspace coordinates fail closed before projection or destructive teardown",
      poisonedGet.status === 503 &&
        poisonedGet.body?.error?.code === "session_create_recovery_intent_invalid" &&
        poisonedDelete.status === 503 &&
        poisonedDelete.body?.error?.code === "session_record_unavailable" &&
        existsSync(mustSurvive) &&
        !poisonedGet.raw.includes(baselinePrompt) &&
        !poisonedDelete.raw.includes(baselinePrompt),
      `${poisonedGet.status}/${poisonedDelete.status}`,
    );
    writeFileSync(sessionPath, sessionBytes);
  } finally {
    if (plane) await plane.stop();
    cleanupRoots(root);
  }
}

await runCoreIdentityOwnerPlane();
await runCrossProcessConcurrencyPlane();

for (const lane of [
  {
    fault: "fail:prepare_intent",
    sessionRef: "session:m4-fail-prepare-intent",
    before: { status: null, receipts: 0, sessions: 0, workspaces: 0 },
  },
  {
    fault: "crash:prepare_intent",
    sessionRef: "session:m4-crash-prepare-intent",
    before: { status: "reserved", receipts: 0, sessions: 0, workspaces: 0 },
    recoveryVia: "list",
  },
  {
    fault: "fail:provision_bundle",
    sessionRef: "session:m4-fail-provision-bundle",
    before: { status: "reserved", receipts: 0, sessions: 0, workspaces: 1 },
  },
  {
    fault: "crash:provision_bundle",
    sessionRef: "session:m4-crash-provision-bundle",
    before: { status: "prepared", receipts: 0, sessions: 0, workspaces: 1 },
  },
  {
    fault: "fail:provisioning_receipt",
    sessionRef: "session:m4-fail-provisioning-receipt",
    before: { status: "prepared", receipts: 0, sessions: 0, workspaces: 1 },
  },
  {
    fault: "crash:provisioning_receipt",
    sessionRef: "session:m4-crash-provisioning-receipt",
    before: { status: "prepared", receipts: 1, sessions: 0, workspaces: 1 },
  },
  {
    fault: "fail:initial_input_receipt",
    sessionRef: "session:m4-fail-initial-input-receipt",
    before: { status: "prepared", receipts: 1, sessions: 0, workspaces: 1 },
  },
  {
    fault: "crash:initial_input_receipt",
    sessionRef: "session:m4-crash-initial-input-receipt",
    before: { status: "prepared", receipts: 2, sessions: 0, workspaces: 1 },
  },
  {
    fault: "fail:session_record",
    sessionRef: "session:m4-fail-session-record",
    before: { status: "prepared", receipts: 2, sessions: 0, workspaces: 1 },
  },
  {
    fault: "crash:session_record",
    sessionRef: "session:m4-crash-session-record",
    before: { status: "prepared", receipts: 2, sessions: 1, workspaces: 1 },
  },
  {
    fault: "fail:commit_intent",
    sessionRef: "session:m4-fail-commit-intent",
    before: { status: "prepared", receipts: 2, sessions: 1, workspaces: 1 },
  },
  {
    fault: "crash:commit_intent",
    sessionRef: "session:m4-crash-commit-intent",
    before: { status: "committed", receipts: 2, sessions: 1, workspaces: 1 },
  },
]) {
  await runDurabilityFaultLane(lane);
}

for (const lane of [
  { fault: "fail:teardown_session_prepared", operation: "teardown" },
  { fault: "crash:teardown_session_prepared", operation: "teardown" },
  { fault: "fail:teardown_session_final", operation: "teardown" },
  { fault: "fail:port_session_final", operation: "port" },
]) {
  await runLifecycleFaultLane(lane);
}

try {
  executionAuthorityResolver = await startRealWalletNetworkPrincipalAuthorityFixture({
    baseEnv: CLEAN_BASE_ENV,
  });
  for (const lane of [
    { fault: "fail:execute_session_prepared", recovery: "unapplied" },
    { fault: "crash:execute_session_prepared", recovery: "interrupted" },
    { fault: "fail:execute_outcome_prepared", recovery: "interrupted" },
    { fault: "crash:execute_outcome_prepared", recovery: "committed" },
    { fault: "fail:execute_receipt_final", recovery: "committed" },
    { fault: "crash:execute_receipt_final", recovery: "committed" },
    { fault: "fail:execute_session_final", recovery: "committed" },
    { fault: "crash:execute_session_final", recovery: "committed" },
  ]) {
    await runExecutionFaultLane(lane);
  }
} finally {
  if (executionAuthorityResolver) await executionAuthorityResolver.stop();
  executionAuthorityResolver = null;
}

await runStrictWalAdversarialPlane();

for (const item of checks) {
  console.log(`${item.pass ? "PASS" : "FAIL"} ${item.name}${item.detail ? ` — ${item.detail}` : ""}`);
}
const failed = checks.filter((item) => !item.pass);
if (blocked) {
  console.error("BLOCKED: build target/debug/hypervisor-daemon before running this verifier");
  process.exitCode = 2;
} else if (failed.length > 0) {
  process.exitCode = 1;
} else if (checks.length !== EXPECTED_CHECKS) {
  console.error(`FAIL verifier coverage changed: expected ${EXPECTED_CHECKS}, got ${checks.length}`);
  process.exitCode = 1;
} else {
  console.log(`M4 Session initial-input isolated plane: PASS (${EXPECTED_CHECKS}/${EXPECTED_CHECKS})`);
}
