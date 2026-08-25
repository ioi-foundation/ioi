#!/usr/bin/env node

import { mkdtempSync, readFileSync, rmSync, readdirSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startIsolatedPlane } from "./lib/isolated-daemon.mjs";
import { emitVerifierCensus } from "./lib/verifier-census.mjs";

const H1 = `sha256:${"1".repeat(64)}`;
const H2 = `sha256:${"2".repeat(64)}`;
const dataDir = mkdtempSync(join(tmpdir(), "ioi-m3-goalrun-"));
const checks = [];
const check = (name, condition, detail = "") => checks.push({ name, pass: Boolean(condition), detail });
const count = (family) => { try { return readdirSync(join(dataDir, family)).filter((name) => name.endsWith(".json")).length; } catch { return 0; } };
const onlyRecord = (family) => {
  try {
    const files = readdirSync(join(dataDir, family)).filter((name) => name.endsWith(".json"));
    return files.length === 1 ? JSON.parse(readFileSync(join(dataDir, family, files[0]), "utf8")) : {};
  } catch { return {}; }
};
const canonical = (value) => {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
};
const sha256 = (value) => `sha256:${createHash("sha256").update(canonical(value)).digest("hex")}`;

const pathRequest = {
  requested_path: "direct_non_system",
  goal_run_profile_revision_ref: "",
  goal_run_profile_content_hash: "",
  result_profile: "research",
  capability_requirement_refs: [],
  runtime_facts: {
    single_bounded_work_subject: true,
    requires_system_membership: false,
    requires_shared_frontier: false,
    requires_outcome_room: false,
    requires_collective_scheduling: false,
    capabilities_fit_single_execution: true,
    authority_fits_single_execution: true,
    risk_and_isolation_fit_single_execution: true,
    has_unresolved_system_dependency: false,
    policy_requires_system_path: false,
    system_path_available: false,
  },
};

const definitionResolution = {
  workflow_template_revision_refs: ["workflow-template://research/revision/1"],
  component_hashes: {
    "workflow-template://research/revision/1": H1,
  },
};

let session = "";
async function request(base, method, path, body, authenticated = true) {
  const response = await fetch(`${base}${path}`, {
    method,
    headers: {
      "content-type": "application/json",
      ...(authenticated && session ? { cookie: `ioi_session=${session}` } : {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: response.status, body: await response.json().catch(() => ({})) };
}

let plane;
try {
  plane = await startIsolatedPlane({ dataDir });
  if (!plane) {
    console.error("BLOCKED: build target/debug/hypervisor-daemon first");
    process.exitCode = 2;
  } else {
    const daemonLogName = readdirSync(dataDir)
      .filter((name) => name === "isolated-daemon.log" || name.startsWith("isolated-daemon-restart-"))
      .sort()
      .at(-1);
    const daemonLog = daemonLogName ? readFileSync(join(dataDir, daemonLogName), "utf8") : "";
    const bootstrapToken = daemonLog.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? "";
    const bootstrap = await request(plane.daemonUrl, "POST", "/v1/hypervisor/auth/bootstrap", {
      token: bootstrapToken,
      password: "m3-goalrun-plane-v1",
      email: "m3-goalrun@ioi.local",
    }, false);
    session = bootstrap.body?.session_token ?? "";
    const who = await request(plane.daemonUrl, "GET", "/v1/hypervisor/auth/whoami");
    const principalRef = who.body?.principal?.principal_ref
      || (who.body?.principal?.principal_id ? `user://${who.body.principal.principal_id}` : "");
    const workflowAdmission = await request(plane.daemonUrl, "POST", "/v1/hypervisor/workflow-templates", {
      owner_ref: principalRef,
      display_name: "M3 bounded research workflow",
      version: "1.0.0",
      graph_ref: "workflow://graph/m3-bounded-research-v1",
      graph_hash: H1,
      registry_status: "released",
    });
    const workflow = workflowAdmission.body?.workflow_template ?? {};
    const profileAdmission = await request(plane.daemonUrl, "POST", "/v1/goal-orchestration/goal-run-profiles", {
      owner_ref: principalRef,
      display_name: "M3 bounded research",
      description: "A canonical profile fixture for the general GoalRun verifier.",
      version: "1.0.0",
      applicable_goal_class_refs: ["schema://ioi/ioi-ai/goal-draft/v1"],
      compatible_domain_object_schema_refs: ["schema://ioi/foundations/work-result/v3"],
      orchestration_policy_ref: "orchestration-policy://bounded-general",
      workflow_template_revision_refs: [workflow.revision_ref],
      harness_requirement_refs: ["harness://hypervisor_worker"],
      runtime_tool_contract_requirement_refs: ["tool://ioi/runtime/file__read"],
      input_contract_ref: "schema://ioi/ioi-ai/goal-draft/v1",
      output_contract_ref: "schema://ioi/foundations/work-result/v3",
      stop_policy_ref: "policy://ioi/goal-run/bounded-stop/v1",
      recovery_policy_ref: "policy://ioi/goal-run/bounded-recovery/v1",
      escalation_policy_ref: "policy://ioi/goal-run/bounded-escalation/v1",
      registry_status: "released",
    });
    const profile = profileAdmission.body?.goal_run_profile ?? {};
    pathRequest.goal_run_profile_revision_ref = profile.revision_ref ?? "";
    pathRequest.goal_run_profile_content_hash = profile.content_hash ?? "";
    delete definitionResolution.component_hashes["workflow-template://research/revision/1"];
    definitionResolution.workflow_template_revision_refs = [workflow.revision_ref];
    check("the verifier bootstraps a real principal and admits the selected workflow and portable profile",
      session.startsWith("ioi_sess_") && principalRef.startsWith("user://")
        && workflowAdmission.status === 201 && profileAdmission.status === 201
        && pathRequest.goal_run_profile_revision_ref.includes("/revision/sha256:"),
      `${bootstrap.status}/${workflowAdmission.status}/${profileAdmission.status}/${principalRef}`);

    const before = count("goal-runs");
    const invalidDefinitions = structuredClone(definitionResolution);
    invalidDefinitions.workflow_template_revision_refs = ["workflow-template://research"];
    const refused = await request(plane.daemonUrl, "POST", "/v1/goal-orchestration/goal-runs", {
      goal: "Research the bounded selected profile",
      admission_path_request: pathRequest,
      definition_resolution: invalidDefinitions,
    });
    check("a caller-substituted workflow definition is refused before persistence",
      refused.status === 409 && refused.body?.error?.code === "goal_run_workflow_resolution_substitution"
        && count("goal-runs") === before,
      `${refused.status}/${refused.body?.error?.code}`);

    const created = await request(plane.daemonUrl, "POST", "/v1/goal-orchestration/goal-runs", {
      goal: "Research the bounded selected profile",
      origin_surface: "api",
      admission_path_request: pathRequest,
      definition_resolution: definitionResolution,
    });
    const run = created.body.goal_run;
    check("direct GoalRun admits active through exact profile resolution and daemon-derived ownership", created.status === 201 && run?.status === "active" && run?.schema_version === "ioi.goal-run.v1" && run?.admission_path_status === "direct_non_system" && run?.owner_ref === principalRef, `${created.status}/${created.body?.error?.code}/${run?.owner_ref}`);
    check("component, canonical active-skill, resolution, and lifecycle records persist without the legacy GoalRun-local family",
      count("goal-run-component-snapshots") === 1
        && count("canonical-active-skill-set-snapshots") === 1
        && count("canonical-active-skill-set-resolution-receipts") === 1
        && count("active-skill-set-snapshots") === 0
        && count("goal-run-profile-resolution-receipts") === 1
        && count("work-lifecycle-records") === 2);
    const canonicalSkillSnapshot = onlyRecord("canonical-active-skill-set-snapshots");
    const canonicalSkillReceipt = onlyRecord("canonical-active-skill-set-resolution-receipts");
    const canonicalSkillMaterial = {
      domain: "ioi.active-skill-set-jcs-sha256.v1",
      work_subject_ref: canonicalSkillSnapshot.work_subject_ref,
      selected_skills: canonicalSkillSnapshot.selected_skills,
      excluded_candidates: canonicalSkillSnapshot.excluded_candidates,
      compatibility_and_evaluation_result_refs: canonicalSkillSnapshot.compatibility_and_evaluation_result_refs,
      resolved_runtime_tool_contracts: canonicalSkillSnapshot.resolved_runtime_tool_contracts,
      context_lease_refs: canonicalSkillSnapshot.context_lease_refs,
    };
    check("the GoalRun and canonical skill owner bind one reproducible snapshot and resolution receipt",
      canonicalSkillSnapshot.work_subject_ref === run?.goal_ref
        && canonicalSkillSnapshot.active_set_hash === sha256(canonicalSkillMaterial)
        && canonicalSkillSnapshot.active_skill_set_snapshot_id === `active-skill-set://snapshot/${canonicalSkillSnapshot.active_set_hash}`
        && canonicalSkillSnapshot.active_skill_set_snapshot_id === run?.active_skill_set_snapshot_ref
        && canonicalSkillSnapshot.active_set_hash === run?.active_skill_set_hash
        && canonicalSkillSnapshot.resolution_receipt_ref === canonicalSkillReceipt.receipt_ref
        && canonicalSkillReceipt.receipt_hash === sha256(canonicalSkillReceipt.material)
        && run?.receipt_refs?.includes(canonicalSkillReceipt.receipt_ref));
    const admittedState = onlyRecord("goal-run-activation-admitted-states");
    const admittedStateCommitment = structuredClone(admittedState);
    admittedStateCommitment.state_root = null;
    admittedStateCommitment.state_root_ref = null;
    check("direct admission retains a reproducible Agentgres-backed state root instead of a prefix-shaped placeholder",
      count("goal-run-activation-admitted-states") === 1
        && admittedState.activation_ref === null
        && admittedState.goal_run_ref === run?.goal_ref
        && admittedState.requesting_principal_ref === principalRef
        && admittedState.declared_invocation_budget?.max_total_invocations === 1
        && admittedState.declared_invocation_budget?.max_parallel_invocations === 1
        && admittedState.state_root === sha256(admittedStateCommitment)
        && admittedState.state_root_ref === run?.admitted_state_root_ref
        && admittedState.state_root_ref?.endsWith(`/${admittedState.state_root}`),
      `${admittedState.state_root_ref ?? "missing"}`);
    check("direct admission retains exact lifecycle and typed receipt obligations",
      String(run?.lifecycle_head).startsWith("sha256:")
        && run?.lifecycle_record_refs?.length === 2
        && run?.receipt_obligations?.length === 2
        && run?.source_context_binding?.target_session_ref === null
        && run?.source_context_binding?.project_ref === null
        && run?.authority_scope_refs?.length === 0);

    const id = String(run?.goal_ref ?? "").replace("goal://", "");
    const admittedStateDir = join(dataDir, "goal-run-activation-admitted-states");
    const admittedStatePath = join(
      admittedStateDir,
      readdirSync(admittedStateDir).find((name) => name.endsWith(".json")),
    );
    const admittedStateBytes = readFileSync(admittedStatePath);
    rmSync(admittedStatePath);
    const missingAdmittedState = await request(
      plane.daemonUrl,
      "GET",
      `/v1/goal-orchestration/goal-runs/${id}`,
    );
    writeFileSync(admittedStatePath, admittedStateBytes);
    check("general GoalRun readback refuses a retained state-root ref with missing owner evidence",
      missingAdmittedState.status === 409
        && missingAdmittedState.body?.error?.code === "goal_run_admitted_state_evidence_missing",
      `${missingAdmittedState.status}/${missingAdmittedState.body?.error?.code}`);
    const result = await request(plane.daemonUrl, "POST", `/v1/goal-orchestration/goal-runs/${id}/results`, {
      work_result_id: "work-result://research/negative-1",
      result_profile: "research",
      outcome_class: "negative",
      status: "failed",
      result_payload_ref: "artifact://research/negative-1",
      produced_by_ref: "worker://research",
      submitted_by_ref: "worker://research",
      claim_refs: [],
      uncertainty: "bounded uncertainty retained",
      supporting_evidence_refs: [],
      contradicting_evidence_refs: ["evidence://research/contradiction"],
    });
    check("negative generic WorkResult is retained without success coercion", result.status === 201 && result.body?.admission?.work_result?.outcome_class === "negative" && result.body?.admission?.retention_disposition === "retained", `${result.status}/${result.body?.error?.code}/${result.body?.error?.message ?? ""}`);

    const componentSnapshotPath = join(dataDir, "goal-run-component-snapshots", `${id}.json`);
    const exactComponentSnapshot = readFileSync(componentSnapshotPath);
    const changedComponentSnapshot = JSON.parse(exactComponentSnapshot.toString("utf8"));
    const resolvedHarnessRef = Object.keys(changedComponentSnapshot.component_hashes)
      .find((reference) => reference.startsWith("harness-profile://"));
    changedComponentSnapshot.component_hashes[resolvedHarnessRef] = H2;
    writeFileSync(componentSnapshotPath, JSON.stringify(changedComponentSnapshot));
    const resultCountBeforeRefusal = count("work-result-registry");
    const changedSnapshotResult = await request(plane.daemonUrl, "POST", `/v1/goal-orchestration/goal-runs/${id}/results`, {
      work_result_id: "work-result://research/changed-snapshot",
      result_profile: "research",
      outcome_class: "negative",
      status: "failed",
      result_payload_ref: "artifact://research/changed-snapshot",
      produced_by_ref: "worker://research",
      submitted_by_ref: "worker://research",
    });
    writeFileSync(componentSnapshotPath, exactComponentSnapshot);
    check("a changed component snapshot refuses result admission before persistence",
      changedSnapshotResult.status === 409
        && changedSnapshotResult.body?.error?.code === "goal_run_component_snapshot_changed"
        && count("work-result-registry") === resultCountBeforeRefusal,
      `${changedSnapshotResult.status}/${changedSnapshotResult.body?.error?.code}`);

    await plane.stop();
    plane = await startIsolatedPlane({ dataDir });
    const replayed = await request(plane.daemonUrl, "GET", `/v1/goal-orchestration/goal-runs/${id}`);
    check("restart reconstructs GoalRun identity, head, and result lineage", replayed.status === 200 && replayed.body?.goal_run?.goal_ref === run.goal_ref && replayed.body?.goal_run?.lifecycle_head === run.lifecycle_head && replayed.body?.goal_run?.work_result_refs?.includes("work-result://research/negative-1"));
  }
} finally {
  if (plane) await plane.stop();
  rmSync(dataDir, { recursive: true, force: true });
}

for (const item of checks) console.log(`${item.pass ? "PASS" : "FAIL"} ${item.name}${item.detail ? ` — ${item.detail}` : ""}`);
const failed = checks.filter((item) => !item.pass);
emitVerifierCensus({ verifierId: "m3-goalrun-plane", sourceUrl: import.meta.url, results: checks });
if (failed.length) process.exitCode = 1;
else if (process.exitCode !== 2) console.log(`M3 GoalRun isolated plane: PASS (${checks.length}/${checks.length})`);
