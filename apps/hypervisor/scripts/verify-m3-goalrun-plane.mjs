#!/usr/bin/env node

import { mkdtempSync, rmSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startIsolatedPlane } from "./lib/isolated-daemon.mjs";

const H1 = `sha256:${"1".repeat(64)}`;
const H2 = `sha256:${"2".repeat(64)}`;
const dataDir = mkdtempSync(join(tmpdir(), "ioi-m3-goalrun-"));
const checks = [];
const check = (name, condition, detail = "") => checks.push({ name, pass: Boolean(condition), detail });
const count = (family) => { try { return readdirSync(join(dataDir, family)).filter((name) => name.endsWith(".json")).length; } catch { return 0; } };

const pathRequest = {
  requested_path: "direct_non_system",
  goal_run_profile_revision_ref: "goal-run-profile://generic-adaptive/revision/1",
  goal_run_profile_content_hash: H1,
  effective_constraint_hash: H2,
  result_profile: "research",
  policy_refs: ["policy://bounded-research"],
  authority_refs: ["grant://research"],
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
  skill_manifest_revision_refs: ["skill://literature/revision/2"],
  active_skill_entry_refs: ["skill-entry://literature/search"],
  harness_profile_revision_refs: ["harness-profile://research/revision/3"],
  runtime_tool_contract_refs: ["tool://search/revision/1"],
  effective_constraint_envelope_ref: "constraint://research",
  effective_constraint_envelope_hash: H2,
  orchestration_policy_ref: "orchestration-policy://bounded",
  orchestration_policy_version_or_hash: "1",
  resolved_skill_bindings: [{
    skill_entry_ref: "skill-entry://literature/search",
    skill_entry_binding_revision_ref: "skill-entry://literature/search/revision/1",
    skill_entry_binding_hash: H1,
    skill_manifest_revision_ref: "skill://literature/revision/2",
    skill_manifest_content_hash: H2,
  }],
  component_hashes: {
    "workflow-template://research/revision/1": H1,
    "skill://literature/revision/2": H2,
    "harness-profile://research/revision/3": H1,
    "tool://search/revision/1": H2,
  },
};

async function request(base, method, path, body) {
  const response = await fetch(`${base}${path}`, {
    method,
    headers: { "content-type": "application/json" },
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
    const before = count("goal-runs");
    const invalidDefinitions = structuredClone(definitionResolution);
    invalidDefinitions.workflow_template_revision_refs = ["workflow-template://research"];
    const refused = await request(plane.daemonUrl, "POST", "/v1/goal-orchestration/goal-runs", {
      goal: "Research the bounded selected profile",
      admission_path_request: pathRequest,
      definition_resolution: invalidDefinitions,
    });
    check("mutable definition is refused before persistence", refused.status === 422 && count("goal-runs") === before, `${refused.status}/${refused.body?.error?.code}`);

    const created = await request(plane.daemonUrl, "POST", "/v1/goal-orchestration/goal-runs", {
      goal: "Research the bounded selected profile",
      owner_ref: "user://operator",
      origin_surface: "api",
      authority_scope_refs: ["scope:goal.run.orchestrate"],
      admission_path_request: pathRequest,
      definition_resolution: definitionResolution,
    });
    const run = created.body.goal_run;
    check("direct GoalRun admits active through exact profile resolution", created.status === 201 && run?.status === "active" && run?.schema_version === "ioi.goal-run.v1" && run?.admission_path_status === "direct_non_system", `${created.status}/${created.body?.error?.code}`);
    check("component, active-skill, resolution, and lifecycle records persist", count("goal-run-component-snapshots") === 1 && count("active-skill-set-snapshots") === 1 && count("goal-run-profile-resolution-receipts") === 1 && count("work-lifecycle-records") === 2);
    check("activation retained exact lifecycle and state commitments", String(run?.lifecycle_head).startsWith("sha256:") && String(run?.admitted_state_root_ref).startsWith("agentgres://state-root/") && run?.lifecycle_record_refs?.length === 2);

    const id = String(run.goal_ref).replace("goal://", "");
    const result = await request(plane.daemonUrl, "POST", `/v1/goal-orchestration/goal-runs/${id}/results`, {
      work_result_id: "work-result://research/negative-1",
      result_profile: "research",
      outcome_class: "negative",
      status: "failed",
      result_payload_ref: "artifact://research/negative-1",
      produced_by_ref: "worker://research",
      submitted_by_ref: "worker://research",
      claim_refs: [],
      uncertainty: ["bounded uncertainty retained"],
      supporting_evidence_refs: [],
      contradicting_evidence_refs: ["evidence://research/contradiction"],
    });
    check("negative generic WorkResult is retained without success coercion", result.status === 201 && result.body?.admission?.work_result?.outcome_class === "negative" && result.body?.admission?.retention_disposition === "retained", `${result.status}/${result.body?.error?.code}`);

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
if (failed.length) process.exitCode = 1;
else if (process.exitCode !== 2) console.log(`M3 GoalRun isolated plane: PASS (${checks.length}/${checks.length})`);
