#!/usr/bin/env node

import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  isIsolatedDaemonLogName,
  sanitizedVerifierBaseEnv,
  startIsolatedPlane,
} from "./lib/isolated-daemon.mjs";
import {
  recordCommitPathObservation,
  startRealWalletNetworkPrincipalAuthorityFixture,
} from "./lib/wallet-network-principal-authority-fixture.mjs";
import {
  bootstrapActiveSystem,
  exactGenesisBody,
  rebindGenesisBodySystem,
  recomputeReleaseHashes,
} from "./verify-hypervisor-system-sequence-zero-materialization.mjs";

const SYSTEM_ID = "system://ioi/outcome-room/m048-hosted-proof";
const GENESIS_ID = "genesis://ioi/outcome-room/m048-hosted-proof/genesis";
const CONSTITUTION_REF = "constitution://ioi/outcome-room/m048-hosted-proof/v1";
const OUTCOME_PACKAGE = "package://ioi/outcome-room";
let OWNER = "user://local-operator";
const DEPLOYMENT_AUTHORITY = "domain://acme-host";
let SYSTEM_AUTHORITY = "org://acme/research";
const ROOT_A = `sha256:${"a".repeat(64)}`;
const ROOT_B = `sha256:${"b".repeat(64)}`;
const AI_ADVERTISEMENT = "ai://ioi/m048/proof";
const CAPABILITY_ALIAS = "capability://advertised/ai/ioi/m048/proof";
const results = [];
const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
// Harness profile driver paths are repository-relative. Normalize npm workspace execution to the
// same working directory as a direct verifier invocation before any profile is resolved.
process.chdir(REPO);

const check = (name, pass, detail = "") => {
  results.push({ name, pass: Boolean(pass), detail });
  console.log(`${pass ? "PASS" : "FAIL"}: ${name}${detail ? ` — ${detail}` : ""}`);
};
const requireValue = (value, message) => {
  if (!value) throw new Error(message);
  return value;
};
const invocationFailureSummary = (response) => (response.body?.invocations ?? []).map(
  (candidate) => ({
    role_key: candidate.role_key ?? null,
    status: candidate.status ?? null,
    blocker: candidate.blocker ?? null,
    execution_receipt: candidate.execution_receipt == null ? null : {
      exit_status: candidate.execution_receipt.exit_status ?? null,
      timed_out: candidate.execution_receipt.timed_out ?? null,
      spawn_error: candidate.execution_receipt.spawn_error ?? null,
    },
    implementation_result_candidate: candidate.implementation_result_candidate == null ? null : {
      execution_succeeded: candidate.implementation_result_candidate.execution_succeeded ?? null,
      summary: candidate.implementation_result_candidate.summary ?? null,
    },
  }),
);
const delay = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));
const waitForOwnerProjection = async (call, path, timeoutMs = 30_000) => {
  const deadline = Date.now() + timeoutMs;
  let response;
  do {
    response = await call("GET", path, undefined);
    if (response.status !== 503) return response;
    await delay(250);
  } while (Date.now() < deadline);
  return response;
};
const tail = (ref) => String(ref).slice(String(ref).indexOf("://") + 3);
const canonical = (value) => {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
};
const hash = (value) => `sha256:${createHash("sha256").update(canonical(value)).digest("hex")}`;
const jcsRoot = (domain, value) => hash({ domain, value });
const familyNames = (dataDir, family) => {
  try {
    return readdirSync(join(dataDir, family)).filter((name) => name.endsWith(".json")).sort();
  } catch (error) {
    if (error?.code === "ENOENT") return [];
    throw error;
  }
};
const snapshot = (dataDir) => canonical(Object.fromEntries(
  readdirSync(dataDir, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => [entry.name, familyNames(dataDir, entry.name)]),
));

async function jsonCall(base, method, path, body, headers = {}) {
  const payload = body === undefined ? undefined : JSON.stringify(body);
  return await new Promise((resolve, reject) => {
    const url = new URL(path, base);
    const request = httpRequest(url, {
      method,
      headers: {
        "content-type": "application/json",
        ...(payload === undefined ? {} : { "content-length": Buffer.byteLength(payload) }),
        ...headers,
      },
    }, (response) => {
      const chunks = [];
      let size = 0;
      response.on("data", (chunk) => {
        size += chunk.length;
        if (size > 16 * 1024 * 1024) {
          request.destroy(new Error(`response exceeded 16 MiB at ${method} ${path}`));
          return;
        }
        chunks.push(chunk);
      });
      response.on("end", () => {
        clearTimeout(deadline);
        const raw = Buffer.concat(chunks).toString("utf8");
        let parsed = {};
        try { parsed = raw ? JSON.parse(raw) : {}; } catch {}
        resolve({ status: response.statusCode ?? 0, body: parsed });
      });
    });
    // Real recorded wallet decisions can exceed fifteen minutes on a loaded local verifier host.
    // This is one absolute transport ceiling (including response headers), and a timeout remains
    // a hard failure rather than authority or success.
    const deadline = setTimeout(() => {
      request.destroy(new Error(`HTTP timeout after 1800s at ${method} ${path}`));
    }, 1_800_000);
    request.on("error", (error) => {
      clearTimeout(deadline);
      reject(error);
    });
    if (payload !== undefined) request.write(payload);
    request.end();
  });
}

// Opt-in profiling correlates a governed route with the approval it recorded.
// It observes wall time around calls that are made identically either way; the
// helpers' return shapes and every requireValue above them are unchanged.
const elapsedMs = (startedAt) => Number((process.hrtime.bigint() - startedAt) / 1_000_000n);

function observeGovernedRoute(route, approval, targetScope, timings) {
  recordCommitPathObservation("governed_route", {
    route,
    request_hash: String(approval?.request_hash ?? "").replace(/^sha256:/u, ""),
    policy_hash: String(approval?.policy_hash ?? "").replace(/^sha256:/u, ""),
    target_scope: targetScope ?? null,
    ...timings,
  });
}

async function governed(call, resolver, path, body) {
  const challengeStarted = process.hrtime.bigint();
  const challenge = await call("POST", path, body);
  const challengeMs = elapsedMs(challengeStarted);
  const refusal = challenge.body?.error ?? challenge.body;
  const approval = refusal?.approval;
  requireValue(
    challenge.status === 403 && approval?.policy_hash && approval?.request_hash,
    `authority challenge absent for ${path}: ${challenge.status}/${challenge.body?.error?.code || "none"}`,
  );
  requireValue(
    refusal?.required_authority_ref === SYSTEM_AUTHORITY,
    `authority was not resolved from active System owner truth for ${path}: ${refusal?.required_authority_ref || "none"}`,
  );
  const mintStarted = process.hrtime.bigint();
  const grant = await resolver.mintRecorded(
    SYSTEM_AUTHORITY,
    approval.policy_hash,
    approval.request_hash,
    refusal.required_scope,
  );
  const mintRecordedMs = elapsedMs(mintStarted);
  const resolutionStarted = process.hrtime.bigint();
  const response = await call("POST", path, { ...body, wallet_approval_grant: grant });
  const authorityResolutionMs = elapsedMs(resolutionStarted);
  observeGovernedRoute(path, approval, refusal.required_scope, {
    challenge_ms: challengeMs,
    mint_recorded_ms: mintRecordedMs,
    authority_resolution_ms: authorityResolutionMs,
    response_status: response.status,
  });
  return { challenge, response, grant };
}

async function walletAuthorizedPost(call, resolver, path, body, scope) {
  const challengeStarted = process.hrtime.bigint();
  const challenge = await call("POST", path, body);
  const challengeMs = elapsedMs(challengeStarted);
  const approval = challenge.body?.approval ?? challenge.body?.error?.approval;
  requireValue(
    challenge.status === 403 && approval?.policy_hash && approval?.request_hash,
    `authority challenge absent for ${path}: ${challenge.status}/${challenge.body?.error?.code || "none"}`,
  );
  const mintStarted = process.hrtime.bigint();
  const grant = await resolver.mintRecorded(DEPLOYMENT_AUTHORITY, approval.policy_hash, approval.request_hash, scope);
  const mintRecordedMs = elapsedMs(mintStarted);
  const operationToken = challenge.body?.operation_token ?? challenge.body?.authority_challenge?.operation_token;
  const resolutionStarted = process.hrtime.bigint();
  const response = await call("POST", path, {
    ...body,
    ...(operationToken ? { operation_token: operationToken } : {}),
    wallet_approval_grant: grant,
  });
  const authorityResolutionMs = elapsedMs(resolutionStarted);
  observeGovernedRoute(path, approval, scope, {
    challenge_ms: challengeMs,
    mint_recorded_ms: mintRecordedMs,
    authority_resolution_ms: authorityResolutionMs,
    response_status: response.status,
  });
  return { challenge, response, grant };
}

function genesisBody() {
  const body = exactGenesisBody();
  body.release.package_id = OUTCOME_PACKAGE;
  body.release.manifest_id = `${OUTCOME_PACKAGE}/release/sha256:${"4".repeat(64)}`;
  body.release.display_name = "OutcomeRoom M04.8 verifier package";
  body.release.description = "Hermetic hosted participation and contribution proof.";
  body.proposed_instantiation.candidate.package_id = OUTCOME_PACKAGE;
  body.proposed_instantiation.candidate.manifest_ref = body.release.manifest_id;
  body.proposed_instantiation.candidate.instantiation.proposed_by = "project://ioi/m048";
  recomputeReleaseHashes(body.release);
  return rebindGenesisBodySystem(body, {
    systemId: SYSTEM_ID,
    genesisId: GENESIS_ID,
    constitutionRef: CONSTITUTION_REF,
    deploymentProfileRef: `deployment-profile://ioi/outcome-room/m048-hosted-proof/local/revision/sha256:${"d".repeat(64)}`,
    orderingProfileRef: "ordering-profile://ioi/outcome-room/m048-hosted-proof/hosted",
    oracleProfileRef: "oracle-evidence-profile://ioi/outcome-room/m048-hosted-proof/fail-closed",
    lifecycleProfileRef: "lifecycle-profile://ioi/outcome-room/m048-hosted-proof/default",
  });
}

function profileBody() {
  return {
    owner_ref: OWNER,
    display_name: "M04.8 hosted collective proof",
    description: "Released verifier profile for one bounded hosted room.",
    version: "1.0.0",
    applicable_goal_class_refs: ["schema://ioi/ioi-ai/goal-draft/v1"],
    compatible_domain_object_schema_refs: ["schema://ioi/foundations/work-result/v3"],
    orchestration_policy_ref: "orchestration-policy://bounded-general",
    constraint_derivation_policy_refs: [], workflow_template_revision_refs: [],
    role_topology_requirement_refs: [],
    harness_requirement_refs: ["harness://hypervisor_worker", "harness://opencode", "harness://deepseek_tui"],
    pinned_harness_profile_revision_refs: [], skill_requirement_refs: [],
    pinned_skill_manifest_revision_refs: [], worker_requirement_refs: [],
    model_route_requirement_refs: [], service_requirement_refs: [],
    runtime_tool_contract_requirement_refs: [], primitive_capability_requirements: [],
    context_requirement_profile_refs: [],
    input_contract_ref: "schema://ioi/ioi-ai/goal-draft/v1",
    output_contract_ref: "schema://ioi/foundations/work-result/v3",
    acceptance_contract_refs: [], verifier_requirement_refs: [],
    budget_time_and_resource_ceiling_refs: [],
    stop_policy_ref: "policy://ioi/goal-run/bounded-stop/v1",
    recovery_policy_ref: "policy://ioi/goal-run/bounded-recovery/v1",
    escalation_policy_ref: "policy://ioi/goal-run/bounded-escalation/v1",
    learning_boundary_requirement_ref: null, pinned_learning_boundary_profile_ref: null,
    allowed_override_schema_ref: null, compatibility_refs: [], provenance_refs: [],
    evaluation_and_benchmark_refs: [], promotion_policy_ref: null,
    revocation_and_recall_policy_ref: null, registry_status: "released",
  };
}

function roomBody(goalRef) {
  return {
    schema_version: "ioi.applications.ioi-ai.outcome-room.v2",
    system_id: SYSTEM_ID,
    owner_or_sponsor_ref: OWNER,
    objective_ref: goalRef,
    objective: "Prove hosted participation and contribution without widening kernel truth.",
    constraint_refs: ["policy://ioi/m048/hosted-only"],
    acceptance_criteria_refs: ["gate://ioi/m048/live-proof"],
    stop_policy_ref: "policy://ioi/m048/stop",
    room_mode: "permissioned_team",
    visibility_policy_ref: "policy://ioi/m048/visibility",
    participation_policy_ref: "policy://ioi/m048/participation",
    privacy_policy_ref: "policy://ioi/m048/privacy",
    contribution_policy_ref: "policy://ioi/m048/contribution",
    cooperation_surplus_policy_ref: "policy://ioi/m048/surplus",
    collaboration_terms_refs: ["terms://ioi/m048/hosted"],
    discovery_and_external_admission_policy_refs: [],
    artifact_license_rights_retention_and_export_policy_refs: ["policy://ioi/m048/export"],
    coordination_topology: "hosted_admission",
    coordination_policy_ref: "policy://ioi/m048/hosted-admission",
    host_domain_ref: SYSTEM_ID,
    ordering_and_merge_policy_ref: "policy://ioi/m048/order",
    conflict_and_failover_policy_ref: "policy://ioi/m048/failover",
    multi_party_collaboration_ref: null,
    ontology_profile_refs: [], scorecard_and_guardrail_refs: ["gate://ioi/m048/integrity"],
    verifier_path_refs: ["verifier-path://ioi/m048/default"],
    resource_and_budget_refs: ["budget://ioi/m048/bounded"], settlement_policy_ref: null,
  };
}

async function establishRoom(call, resolver, profile) {
  for (const id of ["hp_opencode", "hp_deepseek_tui"]) {
    const enabled = await call("POST", `/v1/hypervisor/harness-profiles/${id}/enable`, {});
    requireValue(enabled.status >= 200 && enabled.status < 300, `harness ${id} unavailable`);
  }
  const liveProfiles = await call("GET", "/v1/hypervisor/harness-profiles?live=1", undefined);
  const implementerFacts = (liveProfiles.body?.profiles ?? [])
    .filter((candidate) => ["opencode", "deepseek_tui"].includes(candidate.harness))
    .map((candidate) => ({
      harness: candidate.harness,
      lifecycle: candidate.lifecycle?.status,
      runnability: candidate.runnability?.state,
      wiring: candidate.adapter?.execution_wiring,
      trust: candidate.adapter?.provider_trust,
    }));
  requireValue(
    liveProfiles.status === 200 && implementerFacts.length === 2 &&
    implementerFacts.every((fact) => fact.lifecycle === "active" && fact.runnability === "runnable" &&
      fact.wiring === "lane_a_host_spawn" && fact.trust === "local"),
    `live implementer facts unavailable ${JSON.stringify(implementerFacts)}`,
  );
  const liveRoutes = await call("GET", "/v1/hypervisor/model-routes", undefined);
  const defaultRoute = (liveRoutes.body?.routes ?? []).find((candidate) => candidate.default_route === true);
  requireValue(
    liveRoutes.status === 200 && defaultRoute?.availability?.state === "available",
    `live default model route unavailable ${JSON.stringify(defaultRoute?.availability ?? null)}`,
  );
  const sessionRef = "session:m048-hosted-proof";
  const session = await call("POST", "/v1/hypervisor/sessions", { session_ref: sessionRef });
  requireValue(session.status === 202, `session failed ${session.status}/${session.body?.error?.code || "none"}`);
  const goalResponse = await call("POST", "/v1/goal-orchestration/goal-runs", {
    goal: "Use the available workspace file tool to create m048-room-load-proof.txt containing, with no trailing newline, the four words bounded, room, load, and proven joined by one ASCII space in that order. Read the file back before returning. Do not report completion unless that exact file exists with exactly the requested four-word ASCII-space sequence",
    session_ref: sessionRef,
    target_system_id: SYSTEM_ID,
    admission_path_request: {
      requested_path: "system_bound",
      goal_run_profile_revision_ref: profile.revision_ref,
      goal_run_profile_content_hash: profile.content_hash,
      result_profile: "research",
      policy_refs: ["policy://ioi/m4/hosted-only"],
      authority_refs: [], capability_requirement_refs: [],
    },
  });
  const goal = requireValue(
    goalResponse.body?.goal_run,
    `GoalRun failed ${goalResponse.status}/${goalResponse.body?.error?.code || "none"}/${JSON.stringify(goalResponse.body?.error?.details ?? {})}`,
  );
  await call("POST", "/v1/hypervisor/harness-profiles/hp_deepseek_tui/disable", {});
  const started = await walletAuthorizedPost(
    call,
    resolver,
    `/v1/goal-orchestration/goal-runs/${goal.goal_run_id}/start`,
    {},
    "scope:hypervisor.live-route.session-execute",
  );
  const invocation = requireValue(
    started.response.status === 200 && started.response.body?.invocations?.find(
      (candidate) => candidate.status === "waiting_on_conductor" &&
        candidate.implementation_result_candidate?.execution_succeeded === true,
    ),
    `GoalRun produced no successful waiting invocation (${started.response.status}): ${JSON.stringify(invocationFailureSummary(started.response))}`,
  );
  const currentGoalResponse = await call(
    "GET", `/v1/goal-orchestration/goal-runs/${goal.goal_run_id}`, undefined,
  );
  const currentGoal = requireValue(
    currentGoalResponse.status === 200 && currentGoalResponse.body?.goal_run,
    `GoalRun disappeared after execution ${currentGoalResponse.status}`,
  );
  const roomResponse = await call("POST", "/v1/goal-orchestration/outcome-rooms", roomBody(currentGoal.goal_ref));
  const room = requireValue(roomResponse.body?.outcome_room, `room failed ${roomResponse.status}/${roomResponse.body?.error?.code || "none"}`);
  requireValue(room.status === "open", `room is ${room.status}, not open`);
  const attached = await call(
    "POST",
    `/v1/goal-orchestration/outcome-rooms/${tail(room.outcome_room_id)}/attach-goal-run`,
    {
      goal_run_ref: currentGoal.goal_ref,
      expected_revision: room.latest_sequence,
      expected_goal_run_record_root: jcsRoot(
        "ioi.goal-run-room-membership-predecessor-jcs-sha256.v1",
        currentGoal,
      ),
    },
  );
  requireValue(
    attached.status === 200 && attached.body?.goal_run?.outcome_room_ref === room.outcome_room_id,
    `GoalRun room membership attach failed ${attached.status}/${attached.body?.error?.code || "none"}`,
  );
  // `start` may surface a successful waiting invocation a few scheduler ticks before the
  // conductor's exact verification projection becomes readable. WorkResult admission itself is
  // fail-closed and writes nothing until that truth exists, so retry only that one named
  // not-yet-resolved refusal and stop immediately on every other response.
  const resultDeadline = Date.now() + 120_000;
  let resultResponse;
  do {
    resultResponse = await call(
      "POST", `/v1/goal-orchestration/goal-runs/${goal.goal_run_id}/results`,
      { invocation_or_run_ref: invocation.harness_invocation_id },
    );
    if (resultResponse.status !== 409 ||
      resultResponse.body?.error?.code !== "work_result_verification_truth_unresolved" ||
      Date.now() >= resultDeadline) break;
    await delay(500);
  } while (true);
  const workResult = requireValue(
    resultResponse.status >= 200 && resultResponse.status < 300 && resultResponse.body?.admission?.admitted_object,
    `room WorkResult failed ${resultResponse.status}/${resultResponse.body?.error?.code || "none"}`,
  );
  return {
    goal: attached.body.goal_run,
    room: resultResponse.body?.admission?.outcome_room ?? attached.body.outcome_room,
    invocation,
    workResult,
  };
}

async function run() {
  const dataDir = mkdtempSync(join(tmpdir(), "ioi-m048-participation-"));
  let resolver;
  let plane;
  try {
    const baseEnv = {
      ...sanitizedVerifierBaseEnv(),
      IOI_HYPERVISOR_HARNESS_SHIM: join(REPO, "packages", "hypervisor-harness-shims", "generic-cli-local.mjs"),
    };
    resolver = await startRealWalletNetworkPrincipalAuthorityFixture({ baseEnv });
    const env = {
      ...resolver.env,
      IOI_HYPERVISOR_AUTHORITY_PRINCIPAL_REF: DEPLOYMENT_AUTHORITY,
      IOI_HYPERVISOR_MODEL: "qwen2.5:7b",
      IOI_HYPERVISOR_SESSIONS_ROOT: join(dataDir, "verifier-session-workspaces"),
    };
    plane = await startIsolatedPlane({ dataDir, baseEnv, env, serve: true });
    requireValue(plane, "BLOCKED: build target/debug/hypervisor-daemon first");
    const bootstrapLog = readdirSync(dataDir)
      .filter(isIsolatedDaemonLogName)
      .map((name) => readFileSync(join(dataDir, name), "utf8"))
      .join("\n");
    const bootstrapToken = requireValue(
      bootstrapLog.match(/\b(ioi_bootstrap_[0-9a-f]+)\b/u)?.[1],
      "isolated daemon did not expose its bootstrap token",
    );
    const operator = await jsonCall(
      plane.daemonUrl,
      "POST",
      "/v1/hypervisor/auth/bootstrap",
      { token: bootstrapToken, password: "m048-verifier-operator-password" },
    );
    const sessionToken = requireValue(
      operator.status === 200 && operator.body?.session_token,
      `operator bootstrap failed ${operator.status}`,
    );
    OWNER = `user://${requireValue(operator.body?.principal?.principal_id, "operator identity missing")}`;
    const operatorHeaders = { authorization: `Bearer ${sessionToken}` };
    let call = (method, path, body) => jsonCall(plane.daemonUrl, method, path, body, operatorHeaders);
    const profileResponse = await call("POST", "/v1/goal-orchestration/goal-run-profiles", profileBody());
    const profile = requireValue(
      profileResponse.status === 201 && profileResponse.body?.goal_run_profile,
      `profile failed ${profileResponse.status}/${profileResponse.body?.error?.code || "none"}`,
    );
    // The canonical M04.6 boundary registers the reusable profile, restarts, proves the selected
    // model route, and only then activates the bounded System and enables implementer profiles.
    await plane.stop();
    plane = await startIsolatedPlane({ dataDir, baseEnv, env, serve: true });
    requireValue(plane, "daemon did not restart after System bootstrap");
    call = (method, path, body) => jsonCall(plane.daemonUrl, method, path, body, operatorHeaders);
    const modelRoutes = await call("GET", "/v1/hypervisor/model-routes", undefined);
    const modelRoute = modelRoutes.body?.routes?.find((route) => route.route_id === "mrt_local_default");
    const modelProbe = await call("POST", "/v1/hypervisor/model-routes/mrt_local_default/probe", {});
    requireValue(
      modelRoutes.status === 200 && modelRoute?.model?.model_id === "qwen2.5:7b" &&
      modelProbe.status === 200 && modelProbe.body?.availability?.state === "available",
      `real model route unavailable ${modelRoutes.status}/${modelRoute?.model?.model_id || "none"}/${modelProbe.status}`,
    );
    const activeSystem = await bootstrapActiveSystem(call, resolver, dataDir, genesisBody());
    SYSTEM_AUTHORITY = requireValue(
      activeSystem.source?.record?.governing_authority_ref,
      "verified System genesis omitted its governing authority",
    );
    const established = await establishRoom(call, resolver, profile);
    const { goal, workResult } = established;
    let room = established.room;
    const roomRef = room.outcome_room_id;
    const roomTail = tail(roomRef);
    const child = async (path, body) => {
      const admitted = await governed(call, resolver, path, body);
      requireValue(
        admitted.response.status === 200 && admitted.response.body?.admitted_object,
        `child admission failed at ${path}: ${admitted.response.status}/${admitted.response.body?.error?.code || "none"}/${admitted.response.body?.error?.message || JSON.stringify(admitted.response.body)}`,
      );
      room = { ...room, room_state_root: admitted.response.body.agentgres_evidence.room_state_root };
      return admitted;
    };
    const roomQuery = `?outcome_room_ref=${encodeURIComponent(roomRef)}`;
    check("DEPENDENCIES: active bounded System, strict GoalRun owner, and open OutcomeRoom exist",
      goal.admission_path_status === "system_bound" && room.system_id === SYSTEM_ID && room.status === "open",
      `${goal.admission_path_status}/${room.status}/${room.room_state_root}`);

    const unauthSnapshot = snapshot(dataDir);
    const pairingBody = {
      outcome_room_ref: room.outcome_room_id,
      initiating_surface_ref: "surface://ioi/m048/local-pairing",
      display_name: "Independent alloy worker",
      challenge_hash: ROOT_A,
      ttl_seconds: 300,
    };
    const pairing = await governed(call, resolver, "/v1/goal-orchestration/local-agent-pairing-sessions", pairingBody);
    check("PAIRING: missing authority challenges without mutation and owner-local session grants nothing",
      pairing.challenge.status === 403 && pairing.response.status === 200 &&
      pairing.response.body?.pairing_session?.bootstrap_non_grants?.room_membership === "none" &&
      pairing.response.body?.pairing_session?.bootstrap_non_grants?.authority === "none" &&
      snapshot(dataDir) !== unauthSnapshot,
      `${pairing.challenge.status}/${pairing.response.status}`);

    const pairingSession = requireValue(pairing.response.body?.pairing_session, "pairing session absent");
    const terms = await governed(call, resolver, "/v1/goal-orchestration/collaboration-terms", {
      outcome_room_ref: roomRef,
      version: "1",
      terms_body_root: ROOT_B,
      predecessor_terms_ref: null,
    });
    const termsRecord = requireValue(
      terms.response.status === 200 && terms.response.body?.collaboration_terms,
      `terms failed ${terms.response.status}`,
    );
    const acceptance = await governed(
      call,
      resolver,
      `/v1/goal-orchestration/collaboration-terms/${tail(termsRecord.collaboration_terms_id)}/accept`,
      { accepted_terms_root: ROOT_B },
    );
    const acceptanceReceipt = requireValue(
      acceptance.response.status === 200 && acceptance.response.body?.terms_acceptance_receipt,
      `terms acceptance failed ${acceptance.response.status}`,
    );
    check("TERMS: exact envelope acceptance is evidence and grants neither membership nor authority",
      acceptanceReceipt.grants_membership === false && acceptanceReceipt.grants_authority === false &&
      acceptanceReceipt.accepted_terms_root === ROOT_B);

    const staleSnapshot = snapshot(dataDir);
    const staleParticipation = await call("POST", "/v1/goal-orchestration/room-participation-requests", {
      outcome_room_ref: roomRef,
      expected_room_state_root: ROOT_A,
      pairing_session_id: pairingSession.pairing_session_id,
      pairing_proof_hash: ROOT_A,
      collaboration_terms_ref: termsRecord.collaboration_terms_id,
      collaboration_terms_root: ROOT_B,
      capability_offer_refs: [], eligibility_evidence_refs: [],
      requested_role_frontier_and_visibility_refs: ["policy://ioi/m048/visibility"],
      privacy_custody_and_context_policy_refs: ["policy://ioi/m048/privacy"],
    });
    check("CAS: stale room heads refuse before authority or mutation",
      staleParticipation.status === 409 && snapshot(dataDir) === staleSnapshot,
      `${staleParticipation.status}/${staleParticipation.body?.error?.code || "none"}`);

    const participation = await child("/v1/goal-orchestration/room-participation-requests", {
      outcome_room_ref: roomRef,
      expected_room_state_root: room.room_state_root,
      pairing_session_id: pairingSession.pairing_session_id,
      pairing_proof_hash: ROOT_A,
      collaboration_terms_ref: termsRecord.collaboration_terms_id,
      collaboration_terms_root: ROOT_B,
      capability_offer_refs: [],
      eligibility_evidence_refs: ["evidence://ioi/m048/independent-worker"],
      requested_role_frontier_and_visibility_refs: ["policy://ioi/m048/visibility"],
      privacy_custody_and_context_policy_refs: ["policy://ioi/m048/privacy"],
    });
    const participationRequest = participation.response.body.admitted_object;
    const replaySnapshot = snapshot(dataDir);
    const pairingReplay = await governed(call, resolver, "/v1/goal-orchestration/room-participation-requests", {
      outcome_room_ref: roomRef,
      expected_room_state_root: room.room_state_root,
      pairing_session_id: pairingSession.pairing_session_id,
      pairing_proof_hash: ROOT_A,
      collaboration_terms_ref: termsRecord.collaboration_terms_id,
      collaboration_terms_root: ROOT_B,
      capability_offer_refs: [],
      eligibility_evidence_refs: ["evidence://ioi/m048/independent-worker"],
      requested_role_frontier_and_visibility_refs: ["policy://ioi/m048/visibility"],
      privacy_custody_and_context_policy_refs: ["policy://ioi/m048/privacy"],
    });
    check("PARTICIPATION: pairing is single-use and replay writes nothing",
      pairingReplay.response.status === 409 && snapshot(dataDir) === replaySnapshot,
      `${pairingReplay.response.status}/${pairingReplay.response.body?.error?.code || "none"}`);

    const unsupportedSnapshot = snapshot(dataDir);
    const unsupported = await call(
      "POST",
      `/v1/goal-orchestration/room-participation-requests/${tail(participationRequest.participation_request_id)}/admit`,
      {
        outcome_room_ref: roomRef, expected_room_state_root: room.room_state_root,
        participant_ref: "service://ioi/m048/refused", operator_ref: "service://ioi/m048/refused",
        home_domain_ref: "domain://alloy-lab.example", admitted_role: "implementer",
        visibility_scope_ref: "policy://ioi/m048/visibility",
        terms_acceptance_ref: acceptanceReceipt.receipt_ref,
        capability_advertisement_refs: [AI_ADVERTISEMENT],
        context_and_authority_lease_refs: [],
        runtime_resource_and_budget_lease_refs: ["resource-lease://ioi/m048/cpu", "budget://ioi/m048/bounded"],
        ttl_seconds: 3600,
      },
    );
    check("ADMISSION: unsupported hosted principals fail before mutation",
      unsupported.status === 400 && unsupported.body?.error?.code === "m048_admit_request_invalid" &&
      snapshot(dataDir) === unsupportedSnapshot,
      `${unsupported.status}/${unsupported.body?.error?.code || "none"}`);

    const leaseAdmission = await child(
      `/v1/goal-orchestration/room-participation-requests/${tail(participationRequest.participation_request_id)}/admit`,
      {
        outcome_room_ref: roomRef, expected_room_state_root: room.room_state_root,
        participant_ref: participationRequest.requested_by_ref, operator_ref: OWNER,
        home_domain_ref: "domain://alloy-lab.example", admitted_role: "implementer",
        visibility_scope_ref: "policy://ioi/m048/visibility",
        terms_acceptance_ref: acceptanceReceipt.receipt_ref,
        capability_advertisement_refs: [AI_ADVERTISEMENT],
        context_and_authority_lease_refs: [],
        runtime_resource_and_budget_lease_refs: ["resource-lease://ioi/m048/cpu", "budget://ioi/m048/bounded"],
        ttl_seconds: 3600,
      },
    );
    const lease = leaseAdmission.response.body.admitted_object;
    check("LEASE: room System admits a bounded worker lease from exact terms acceptance",
      lease.status === "active" && lease.system_binding?.system_id === SYSTEM_ID &&
      lease.system_binding?.proposed_or_issued_by_ref === SYSTEM_ID &&
      lease.participant_ref === participationRequest.requested_by_ref && lease.operator_ref === OWNER &&
      lease.terms_acceptance_ref === acceptanceReceipt.receipt_ref);

    const resourceAdmission = await child("/v1/goal-orchestration/resource-offers", {
      outcome_room_ref: roomRef, expected_room_state_root: room.room_state_root,
      provider_participant_lease_ref: lease.participant_lease_id,
      backing_provider_ref: "provider://ioi/m048/local",
      resource_profile_ref: "resource://ioi/m048/cpu",
      capacity_and_availability_ref: "capacity://ioi/m048/one",
      locality_and_custody_refs: ["region://ioi/local"],
      trust_and_assurance_refs: ["evidence://ioi/m048/attestation"],
      cost_ref: "quote://ioi/m048/zero", eligible_work_classes: ["verification_need"],
      policy_constraint_refs: [], allocation_policy_ref: "policy://ioi/m048/allocation",
      queue_preemption_and_fairness_policy_ref: "policy://ioi/m048/fairness",
      expires_at: "2099-01-01T00:00:00Z",
    });
    const resourceOffer = resourceAdmission.response.body.admitted_object;
    const capabilityAdmission = await child("/v1/goal-orchestration/capability-offers", {
      outcome_room_ref: roomRef, expected_room_state_root: room.room_state_root,
      participant_lease_ref: lease.participant_lease_id,
      backing_worker_or_service_ref: lease.participant_ref,
      capability_descriptor_refs: [AI_ADVERTISEMENT, CAPABILITY_ALIAS],
      eligible_frontier_classes: ["verification_need"],
      model_harness_tool_and_connector_refs: ["harness-profile://ioi/m048/local"],
      authority_and_context_requirements: [],
      privacy_cost_quality_and_latency_refs: ["benchmark://ioi/m048/quality"],
      availability_ref: "schedule://ioi/m048/always",
    });
    const capabilityOffer = capabilityAdmission.response.body.admitted_object;
    check("OFFERS: resource and capability offers resolve a live lease and stay within its grants",
      resourceOffer.status === "offered" && capabilityOffer.status === "offered");

    const frontierAdmission = await child("/v1/goal-orchestration/work-frontier-items", {
      outcome_room_ref: roomRef, expected_room_state_root: room.room_state_root,
      item_kind: "verification_need", objective: "Verify the bounded M04.8 hosted contribution lane.",
      dependency_refs: [], required_capability_refs: [CAPABILITY_ALIAS],
      required_context_resource_authority_and_evidence_refs: [],
      expected_value: 1, uncertainty: 0.1, priority: 10,
      stop_condition_ref: "policy://ioi/m048/stop", expires_at: null,
    });
    const frontier = frontierAdmission.response.body.admitted_object;
    const match = await governed(call, resolver, "/v1/goal-orchestration/work-eligibility-matches", {
      outcome_room_ref: roomRef, frontier_item_ref: frontier.frontier_item_id,
      participant_lease_ref: lease.participant_lease_id,
      resource_offer_refs: [resourceOffer.resource_offer_id],
      capability_offer_refs: [capabilityOffer.capability_offer_id],
    });
    const eligibility = requireValue(
      match.response.status === 200 && match.response.body?.work_eligibility_match_receipt,
      `eligibility failed ${match.response.status}/${match.response.body?.error?.code || "none"}`,
    );
    check("ELIGIBILITY: match is receipt evidence only and structurally grants nothing",
      eligibility.allocation_created === false && eligibility.claim_created === false &&
      eligibility.execution_authority_granted === false);

    const claimAdmission = await child("/v1/goal-orchestration/work-claim-leases", {
      outcome_room_ref: roomRef, expected_room_state_root: room.room_state_root,
      frontier_item_ref: frontier.frontier_item_id,
      participant_lease_ref: lease.participant_lease_id,
      eligibility_match_receipt_ref: eligibility.receipt_ref,
      resource_offer_refs: [resourceOffer.resource_offer_id],
      capability_offer_refs: [capabilityOffer.capability_offer_id],
      bounded_scope_ref: "policy://ioi/m048/contribution-scope",
      contribution_policy_ref: "policy://ioi/m048/contribution",
      budget_reservation_ref: "budget://ioi/m048/bounded",
      context_lease_refs: [],
      authority_resource_compute_data_budget_and_tool_lease_refs: ["budget://ioi/m048/bounded"],
      ttl_seconds: 3600,
    });
    let claim = claimAdmission.response.body.admitted_object;

    // A second claimant must cross the complete hosted admission path. The authority operation
    // identity is intentionally keyed by claimant lease + acquire + frontier, so changing a field
    // on the first claimant's request would prove replay protection, not claim exclusivity.
    const competingPairing = await governed(
      call,
      resolver,
      "/v1/goal-orchestration/local-agent-pairing-sessions",
      {
        outcome_room_ref: roomRef,
        initiating_surface_ref: "surface://ioi/m048/local-pairing",
        display_name: "Independent cobalt worker",
        challenge_hash: ROOT_B,
        ttl_seconds: 300,
      },
    );
    const competingPairingSession = requireValue(
      competingPairing.response.status === 200 && competingPairing.response.body?.pairing_session,
      `competing pairing failed ${competingPairing.response.status}`,
    );
    const competingParticipation = await child(
      "/v1/goal-orchestration/room-participation-requests",
      {
        outcome_room_ref: roomRef,
        expected_room_state_root: room.room_state_root,
        pairing_session_id: competingPairingSession.pairing_session_id,
        pairing_proof_hash: ROOT_B,
        collaboration_terms_ref: termsRecord.collaboration_terms_id,
        collaboration_terms_root: ROOT_B,
        capability_offer_refs: [],
        eligibility_evidence_refs: ["evidence://ioi/m048/competing-worker"],
        requested_role_frontier_and_visibility_refs: ["policy://ioi/m048/visibility"],
        privacy_custody_and_context_policy_refs: ["policy://ioi/m048/privacy"],
      },
    );
    const competingRequest = competingParticipation.response.body.admitted_object;
    const competingLeaseAdmission = await child(
      `/v1/goal-orchestration/room-participation-requests/${tail(competingRequest.participation_request_id)}/admit`,
      {
        outcome_room_ref: roomRef,
        expected_room_state_root: room.room_state_root,
        participant_ref: competingRequest.requested_by_ref,
        operator_ref: OWNER,
        home_domain_ref: "domain://cobalt-lab.example",
        admitted_role: "implementer",
        visibility_scope_ref: "policy://ioi/m048/visibility",
        terms_acceptance_ref: acceptanceReceipt.receipt_ref,
        capability_advertisement_refs: [AI_ADVERTISEMENT],
        context_and_authority_lease_refs: [],
        runtime_resource_and_budget_lease_refs: [
          "resource-lease://ioi/m048/cpu",
          "budget://ioi/m048/bounded",
        ],
        ttl_seconds: 3600,
      },
    );
    const competingLease = competingLeaseAdmission.response.body.admitted_object;
    const competingResourceAdmission = await child("/v1/goal-orchestration/resource-offers", {
      outcome_room_ref: roomRef,
      expected_room_state_root: room.room_state_root,
      provider_participant_lease_ref: competingLease.participant_lease_id,
      backing_provider_ref: "provider://ioi/m048/local",
      resource_profile_ref: "resource://ioi/m048/cpu",
      capacity_and_availability_ref: "capacity://ioi/m048/one",
      locality_and_custody_refs: ["region://ioi/local"],
      trust_and_assurance_refs: ["evidence://ioi/m048/attestation"],
      cost_ref: "quote://ioi/m048/zero",
      eligible_work_classes: ["verification_need"],
      policy_constraint_refs: [],
      allocation_policy_ref: "policy://ioi/m048/allocation",
      queue_preemption_and_fairness_policy_ref: "policy://ioi/m048/fairness",
      expires_at: "2099-01-01T00:00:00Z",
    });
    const competingResource = competingResourceAdmission.response.body.admitted_object;
    const competingCapabilityAdmission = await child("/v1/goal-orchestration/capability-offers", {
      outcome_room_ref: roomRef,
      expected_room_state_root: room.room_state_root,
      participant_lease_ref: competingLease.participant_lease_id,
      backing_worker_or_service_ref: competingLease.participant_ref,
      capability_descriptor_refs: [AI_ADVERTISEMENT, CAPABILITY_ALIAS],
      eligible_frontier_classes: ["verification_need"],
      model_harness_tool_and_connector_refs: ["harness-profile://ioi/m048/local"],
      authority_and_context_requirements: [],
      privacy_cost_quality_and_latency_refs: ["benchmark://ioi/m048/quality"],
      availability_ref: "schedule://ioi/m048/always",
    });
    const competingCapability = competingCapabilityAdmission.response.body.admitted_object;
    const competingMatch = await governed(
      call,
      resolver,
      "/v1/goal-orchestration/work-eligibility-matches",
      {
        outcome_room_ref: roomRef,
        frontier_item_ref: frontier.frontier_item_id,
        participant_lease_ref: competingLease.participant_lease_id,
        resource_offer_refs: [competingResource.resource_offer_id],
        capability_offer_refs: [competingCapability.capability_offer_id],
      },
    );
    const competingEligibility = requireValue(
      competingMatch.response.status === 200 &&
        competingMatch.response.body?.work_eligibility_match_receipt,
      `competing eligibility failed ${competingMatch.response.status}`,
    );
    const duplicate = await governed(call, resolver, "/v1/goal-orchestration/work-claim-leases", {
      outcome_room_ref: roomRef, expected_room_state_root: room.room_state_root,
      frontier_item_ref: frontier.frontier_item_id,
      participant_lease_ref: competingLease.participant_lease_id,
      eligibility_match_receipt_ref: competingEligibility.receipt_ref,
      resource_offer_refs: [competingResource.resource_offer_id],
      capability_offer_refs: [competingCapability.capability_offer_id],
      bounded_scope_ref: "policy://ioi/m048/contribution-scope",
      contribution_policy_ref: "policy://ioi/m048/contribution",
      budget_reservation_ref: "budget://ioi/m048/bounded", context_lease_refs: [],
      authority_resource_compute_data_budget_and_tool_lease_refs: ["budget://ioi/m048/bounded"],
      ttl_seconds: 3600,
    });
    check("CLAIM: exclusive acquisition refuses a duplicate live claim",
      duplicate.response.status === 409 &&
      duplicate.response.body?.error?.code === "m048_work_claim_exclusive",
      `${duplicate.response.status}/${duplicate.response.body?.error?.code || "none"}`);

    const heartbeat = await child(
      `/v1/goal-orchestration/work-claim-leases/${tail(claim.work_claim_id)}/transition`,
      { outcome_room_ref: roomRef, expected_room_state_root: room.room_state_root,
        op: "heartbeat", heartbeat_ref: "receipt://ioi/m048/worker-heartbeat" },
    );
    claim = heartbeat.response.body.admitted_object;
    check("LIVENESS: heartbeat is a receipt ref on a successor, not a new object family",
      claim.heartbeat_ref === "receipt://ioi/m048/worker-heartbeat" && claim.renewal_count === 1);

    const attemptAdmission = await child("/v1/goal-orchestration/attempts", {
      outcome_room_ref: roomRef, expected_room_state_root: room.room_state_root,
      work_claim_ref: claim.work_claim_id, goal_run_ref: goal.goal_ref,
      declared_method_and_hypothesis_refs: ["method://ioi/m048/bounded"],
      input_state_and_environment_refs: ["state://ioi/m048/input"],
      worker_model_resolver_tool_and_runtime_version_refs: [lease.participant_ref],
      authority_and_policy_refs: ["policy://ioi/m048/contribution"],
      resource_and_cost_refs: ["resource-lease://ioi/m048/cpu"], outcome_class: "positive",
      artifact_evidence_and_receipt_refs: ["evidence://ioi/m048/artifact"],
      artifact_license_ip_retention_and_export_refs: ["policy://ioi/m048/export"],
    });
    const attempt = attemptAdmission.response.body.admitted_object;
    const findingAdmission = await child("/v1/goal-orchestration/findings", {
      outcome_room_ref: roomRef, expected_room_state_root: room.room_state_root,
      attempt_ref: attempt.attempt_id, work_result_ref: workResult.work_result_id,
      proposition: "The bounded hosted collaboration plane preserves owner and kernel boundaries.",
      finding_kind: "observation", confidence_or_uncertainty: 0.95,
      source_and_observation_context_refs: [attempt.attempt_id],
      supporting_evidence_refs: ["evidence://ioi/m048/artifact"], proof_refs: [],
      contradicting_evidence_refs: [], applicability_and_counterexample_refs: [],
      provenance_ontology_and_mapping_refs: ["ontology-mapping://ioi/m048/canonical"], supersedes_ref: null,
    });
    let finding = findingAdmission.response.body.admitted_object;
    const challengeAdmission = await child("/v1/goal-orchestration/verifier-challenges", {
      outcome_room_ref: roomRef, expected_room_state_root: room.room_state_root,
      challenger_participant_lease_ref: lease.participant_lease_id,
      challenged_ref: finding.finding_id, challenge_kind: "evidence",
      challenge_evidence_refs: ["evidence://ioi/m048/challenge"],
      adjudicator_policy_ref: "policy://ioi/m048/adjudication", prior_rule_version_ref: null,
      affected_attempt_refs: [attempt.attempt_id], reverification_required: true,
    });
    const challenge = challengeAdmission.response.body.admitted_object;
    const findingGet = await call(
      "GET", `/v1/goal-orchestration/findings/${tail(finding.finding_id)}${roomQuery}`, undefined,
    );
    finding = findingGet.body?.projection?.admitted_object;
    check("LINEAGE: Attempt, Finding, WorkResult, and challenge compose without a Contribution object",
      attempt.work_result_ref === null && finding?.work_result_ref === workResult.work_result_id &&
      finding?.status === "disputed" && challenge.challenged_ref === finding.finding_id);

    const release = await child(
      `/v1/goal-orchestration/work-claim-leases/${tail(claim.work_claim_id)}/transition`,
      { outcome_room_ref: roomRef, expected_room_state_root: room.room_state_root,
        op: "release", release_or_reassignment_reason: "bounded proof complete" },
    );
    const frontierGet = await call(
      "GET", `/v1/goal-orchestration/work-frontier-items/${tail(frontier.frontier_item_id)}${roomQuery}`, undefined,
    );
    const attemptGet = await call(
      "GET", `/v1/goal-orchestration/attempts/${tail(attempt.attempt_id)}${roomQuery}`, undefined,
    );
    check("RELEASE: one terminal claim successor restores projected claimability and retains Attempt lineage",
      release.response.body.admitted_object.status === "released" &&
      frontierGet.body?.projection?.admitted_object?.claimability === "open" &&
      attemptGet.body?.projection?.admitted_object?.attempt_id === attempt.attempt_id);

    const forbiddenBefore = snapshot(dataDir);
    const forbiddenResponses = await Promise.all([
      call("POST", "/v1/goal-orchestration/outcome-room-discoveries", {}),
      call("POST", "/v1/goal-orchestration/participant-state-bundles", {}),
      call("POST", "/v1/goal-orchestration/contributions", {}),
      call("POST", `/v1/goal-orchestration/findings/${tail(finding.finding_id)}/transition`, {
        outcome_room_ref: roomRef, expected_room_state_root: room.room_state_root, status: "rejected",
      }),
    ]);
    check("EXCLUSIONS: M11 discovery/state-bundle, Contribution, and verdict surfaces are unavailable",
      forbiddenResponses.every((response) => response.status >= 400) && snapshot(dataDir) === forbiddenBefore,
      forbiddenResponses.map((response) => response.status).join("/"));

    await plane.stop();
    plane = await startIsolatedPlane({ dataDir, baseEnv, env, serve: true });
    requireValue(plane, "daemon did not restart");
    call = (method, path, body) => jsonCall(plane.daemonUrl, method, path, body, operatorHeaders);
    const families = [
      ["room-participation-requests", 2], ["room-participant-leases", 2],
      ["resource-offers", 2], ["capability-offers", 2],
      ["work-frontier-items", 1], ["work-claim-leases", 1],
      ["attempts", 1], ["findings", 1], ["verifier-challenges", 1],
    ];
    const restored = [];
    const restoredCounts = [];
    for (const [path, expectedCount] of families) {
      const response = await call("GET", `/v1/goal-orchestration/${path}${roomQuery}`, undefined);
      restoredCounts.push(`${path}:${response.status}/${response.body?.count ?? "none"}`);
      restored.push(
        response.status === 200 && Array.isArray(response.body?.objects) &&
        response.body.objects.length === expectedCount && response.body.count === expectedCount,
      );
    }
    const pairingList = await call("GET", "/v1/goal-orchestration/local-agent-pairing-sessions", undefined);
    const termsList = await call("GET", "/v1/goal-orchestration/collaboration-terms", undefined);
    const matchList = await call("GET", `/v1/goal-orchestration/work-eligibility-matches${roomQuery}`, undefined);
    // The daemon's generic health probe can become ready before the OutcomeRoom owner has
    // completed pending-intent recovery, Agentgres history hydration, and its cross-owner
    // projection census. Restart proof is eventual-within-bound, never "first request wins";
    // a durable 503 still fails after this bounded readiness window.
    const replay = await waitForOwnerProjection(
      call,
      `/v1/goal-orchestration/outcome-rooms/${roomTail}/replay`,
    );
    const replayError = replay.body?.error;
    check("RESTART: all ten named lifecycles and auxiliary terms/eligibility evidence reproject exactly",
      restored.every(Boolean) && pairingList.body?.count === 2 && termsList.body?.count === 1 &&
      matchList.body?.count === 2 && replay.status === 200 && Array.isArray(replay.body?.operations) &&
      replay.body.operations.length === replay.body.latest_sequence + 1,
      `${restored.filter(Boolean).length}/9 room-child families (${restoredCounts.join(",")}); ` +
      `${pairingList.body?.count}/${termsList.body?.count}/${matchList.body?.count}; ` +
      `replay=${replay.status}/${replay.body?.operations?.length ?? "none"}/${replay.body?.latest_sequence ?? "none"}` +
      `${replayError ? `/${replayError.code ?? "unknown"}:${replayError.message ?? ""}` : ""}`);
  } finally {
    if (plane) await plane.stop();
    if (resolver) await resolver.stop();
    rmSync(dataDir, { recursive: true, force: true });
  }
  const passed = results.filter((result) => result.pass).length;
  console.log(`${passed}/${results.length} passed`);
  if (passed !== results.length) process.exitCode = 1;
}

run().catch((error) => {
  console.error("VERIFIER CRASH:", error);
  process.exitCode = 1;
});
