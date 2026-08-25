#!/usr/bin/env node

import {
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startIsolatedPlane } from "./lib/isolated-daemon.mjs";
import { emitVerifierCensus } from "./lib/verifier-census.mjs";

const H1 = `sha256:${"1".repeat(64)}`;
const dataDir = mkdtempSync(join(tmpdir(), "ioi-m4-work-lifecycle-"));
const checks = [];
const check = (name, condition, detail = "") => checks.push({ name, pass: Boolean(condition), detail });
const familyFiles = (family) => {
  try {
    return readdirSync(join(dataDir, family)).filter((name) => name.endsWith(".json"));
  } catch {
    return [];
  }
};
const count = (family) => familyFiles(family).length;
const onlyRecord = (family) => {
  const files = familyFiles(family);
  return files.length === 1
    ? JSON.parse(readFileSync(join(dataDir, family, files[0]), "utf8"))
    : {};
};

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
  workflow_template_revision_refs: [],
  component_hashes: {},
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
      password: "m4-work-lifecycle-plane-v1",
      email: "m4-work-lifecycle@ioi.local",
    }, false);
    session = bootstrap.body?.session_token ?? "";
    const who = await request(plane.daemonUrl, "GET", "/v1/hypervisor/auth/whoami");
    const principalRef = who.body?.principal?.principal_ref
      || (who.body?.principal?.principal_id ? `user://${who.body.principal.principal_id}` : "");

    const workflowAdmission = await request(plane.daemonUrl, "POST", "/v1/hypervisor/workflow-templates", {
      owner_ref: principalRef,
      display_name: "M04.6 bounded lifecycle workflow",
      version: "1.0.0",
      graph_ref: "workflow://graph/m046-bounded-lifecycle-v1",
      graph_hash: H1,
      registry_status: "released",
    });
    const workflow = workflowAdmission.body?.workflow_template ?? {};
    const profileAdmission = await request(plane.daemonUrl, "POST", "/v1/goal-orchestration/goal-run-profiles", {
      owner_ref: principalRef,
      display_name: "M04.6 bounded lifecycle",
      description: "A canonical fixture for the shared work-lifecycle persistence verifier.",
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
    definitionResolution.workflow_template_revision_refs = [workflow.revision_ref];

    check(
      "the live verifier admits exact workflow and profile evidence under one authenticated principal",
      session.startsWith("ioi_sess_") && principalRef.startsWith("user://")
        && workflowAdmission.status === 201 && profileAdmission.status === 201,
      `${bootstrap.status}/${workflowAdmission.status}/${profileAdmission.status}/${principalRef}`,
    );

    const created = await request(plane.daemonUrl, "POST", "/v1/goal-orchestration/goal-runs", {
      goal: "Exercise the shared work lifecycle plane",
      origin_surface: "api",
      admission_path_request: pathRequest,
      definition_resolution: definitionResolution,
    });
    const run = created.body?.goal_run ?? {};
    const id = String(run.goal_ref ?? "").replace("goal://", "");
    check(
      "a generally admitted GoalRun binds the shared owner at one active lifecycle head",
      created.status === 201 && run.status === "active" && run.owner_ref === principalRef
        && String(run.lifecycle_head).startsWith("sha256:")
        && run.lifecycle_record_refs?.length === 3,
      `${created.status}/${created.body?.error?.code}/${run.lifecycle_head}`,
    );

    const plan = onlyRecord("goal-run-orchestration-plan-revisions");
    const receipt = onlyRecord("goal-run-orchestration-plan-selection-receipts");
    const cell = onlyRecord("goal-run-context-cells");
    check(
      "the GoalRun owner durably retains exactly one immutable application plan, selection receipt, and ContextCell",
      count("goal-run-orchestration-plan-revisions") === 1
        && count("goal-run-orchestration-plan-selection-receipts") === 1
        && count("goal-run-context-cells") === 1
        && plan.schema_version === "ioi.orchestration-plan.v1"
        && receipt.schema_version === "ioi.orchestration-plan-selection-decision-receipt.v1"
        && cell.schema_version === "ioi.context-cell.v1",
    );
    check(
      "the selected application plan binds the exact admitted profile, workflow, hash, and decision receipt",
      run.orchestration_plan_revision_refs?.length === 1
        && run.orchestration_plan_revision_refs[0] === plan.revision_ref
        && run.selected_orchestration_plan_revision_ref === plan.revision_ref
        && run.selected_orchestration_plan_content_hash === plan.content_hash
        && plan.goal_run_profile_revision_ref === profile.revision_ref
        && plan.workflow_template_revision_refs?.[0] === workflow.revision_ref
        && plan.selection_decision_receipt_ref === receipt.receipt_id
        && run.orchestration_decision_receipt_ref === receipt.receipt_id,
    );
    check(
      "the selection receipt reproduces the plan choice and preserves its profile-resolution evidence basis",
      receipt.goal_ref === run.goal_ref
        && receipt.selected_orchestration_plan_revision_ref === plan.revision_ref
        && receipt.selected_orchestration_plan_content_hash === plan.content_hash
        && plan.evidence_basis_refs?.[0] === run.goal_run_profile_resolution_receipt_ref
        && run.receipt_refs?.includes(receipt.receipt_id),
    );
    check(
      "GoalRun application state stays topology-less and carries no kernel-owned session, route, lease, or assignment truth",
      run.context_cell_refs?.length === 1 && run.context_cell_refs[0] === cell.context_cell_id
        && cell.work_subject_ref === run.goal_ref
        && cell.role_topology_revision_ref === null
        && cell.resolver_revision_ref === null
        && cell.model_route_ref === null
        && cell.active_runtime_assignment_ref === null
        && run.context_lease_refs?.length === 0
        && run.runtime_assignment_refs?.length === 0
        && run.source_context_binding?.target_session_ref === null,
    );

    const encodedObject = encodeURIComponent(run.goal_ref);
    const encodedOwner = encodeURIComponent(principalRef);
    const records = await request(
      plane.daemonUrl,
      "GET",
      `/v1/hypervisor/work-lifecycle/records?object_ref=${encodedObject}&owner_ref=${encodedOwner}`,
    );
    const projection = await request(
      plane.daemonUrl,
      "GET",
      `/v1/hypervisor/work-lifecycle/projection?object_ref=${encodedObject}&owner_ref=${encodedOwner}`,
    );
    check(
      "the shared record route reconstructs the exact three-edge GoalRun chain",
      records.status === 200 && records.body?.record_count === 3
        && records.body?.records?.map((record) => record.record_id).join("|") === run.lifecycle_record_refs.join("|")
        && records.body?.records?.at(-1)?.resulting_head === run.lifecycle_head
        && records.body?.records?.every((record) => record.object_kind === "goal_run"
          && record.object_ref === run.goal_ref && record.owner_ref === principalRef),
      `${records.status}/${records.body?.error?.code}`,
    );
    check(
      "the shared projection route rebuilds the active phase and typed ContextCell child at the same head",
      projection.status === 200
        && projection.body?.projection?.head === run.lifecycle_head
        && projection.body?.projection?.active_phase === "active"
        && projection.body?.projection?.record_count === 3
        && projection.body?.projection?.active_children?.context_cell?.[0]?.child_ref === cell.context_cell_id,
      `${projection.status}/${projection.body?.error?.code}`,
    );

    const status = await request(plane.daemonUrl, "GET", "/v1/hypervisor/work-lifecycle/status");
    const families = status.body?.durable_family_object_counts ?? {};
    const goalRunKind = status.body?.per_kind_lifecycle_counts?.find((entry) => entry.object_kind === "goal_run");
    check(
      "status reports all five durable families, the one GoalRun binding, and the kernel-truth nonclaim",
      status.status === 200 && status.body?.kernel_present === true
        && families["work-lifecycle-records"] === 1
        && families["work-lifecycle-projections"] === 1
        && families["work-lifecycle-cancellation-plans"] === 0
        && families["work-lifecycle-archive-segments"] === 1
        && families["work-lifecycle-snapshots"] === 1
        && goalRunKind?.object_count === 1 && goalRunKind?.record_count === 3
        && status.body?.live_owner_route_bindings?.[0]?.object_kind === "goal_run"
        && status.body?.nonclaim?.includes("Session, launch, thread, HarnessInvocation"),
    );
    const anonymousStatus = await request(
      plane.daemonUrl,
      "GET",
      "/v1/hypervisor/work-lifecycle/status",
      undefined,
      false,
    );
    check("the shared status surface has no anonymous existence oracle", anonymousStatus.status === 401);

    const foreignOwner = await request(
      plane.daemonUrl,
      "GET",
      `/v1/hypervisor/work-lifecycle/projection?object_ref=${encodedObject}&owner_ref=${encodeURIComponent("user://foreign")}`,
    );
    check(
      "owner-scoped lifecycle reads refuse a caller-substituted owner before object disclosure",
      foreignOwner.status === 403 && foreignOwner.body?.error?.code === "work_lifecycle_owner_forbidden",
      `${foreignOwner.status}/${foreignOwner.body?.error?.code}`,
    );

    const cancellationBefore = families["work-lifecycle-cancellation-plans"];
    const substitutedRequester = await request(
      plane.daemonUrl,
      "POST",
      "/v1/hypervisor/work-lifecycle/cancellation-plan",
      {
        object_ref: run.goal_ref,
        owner_ref: principalRef,
        requested_by_ref: "user://foreign",
        reason: "forged cancellation requester",
      },
    );
    const statusAfterSubstitution = await request(
      plane.daemonUrl,
      "GET",
      "/v1/hypervisor/work-lifecycle/status",
    );
    check(
      "cancellation planning derives requester authority and persists nothing for substitution",
      substitutedRequester.status === 403
        && substitutedRequester.body?.error?.code === "work_lifecycle_requester_substitution"
        && statusAfterSubstitution.body?.durable_family_object_counts?.["work-lifecycle-cancellation-plans"]
          === cancellationBefore,
      `${substitutedRequester.status}/${substitutedRequester.body?.error?.code}`,
    );
    const cancellation = await request(
      plane.daemonUrl,
      "POST",
      "/v1/hypervisor/work-lifecycle/cancellation-plan",
      {
        object_ref: run.goal_ref,
        owner_ref: principalRef,
        requested_by_ref: principalRef,
        reason: "bounded verifier cancellation plan",
      },
    );
    const cancellationPlan = cancellation.body?.cancellation_plan ?? {};
    const statusAfterCancellation = await request(
      plane.daemonUrl,
      "GET",
      "/v1/hypervisor/work-lifecycle/status",
    );
    check(
      "the exact principal owner can durably plan ContextCell fanout without claiming child completion",
      cancellation.status === 200
        && cancellationPlan.schema_version === "ioi.cancellation-fanout-plan.v1"
        && cancellationPlan.object_ref === run.goal_ref
        && cancellationPlan.source_head === run.lifecycle_head
        && cancellationPlan.requested_by_ref === principalRef
        && cancellationPlan.targets?.[0]?.relation_kind === "context_cell"
        && cancellationPlan.targets?.[0]?.target_ref === cell.context_cell_id
        && cancellationPlan.requires_completion_receipt === true
        && !JSON.stringify(cancellationPlan).includes("completed")
        && statusAfterCancellation.body?.durable_family_object_counts?.["work-lifecycle-cancellation-plans"] === 1,
      `${cancellation.status}/${cancellation.body?.error?.code}`,
    );
    check(
      "cancellation planning appends no lifecycle edge and leaves the GoalRun active",
      (await request(
        plane.daemonUrl,
        "GET",
        `/v1/hypervisor/work-lifecycle/records?object_ref=${encodedObject}&owner_ref=${encodedOwner}`,
      )).body?.record_count === 3
        && (await request(
          plane.daemonUrl,
          "GET",
          `/v1/hypervisor/work-lifecycle/projection?object_ref=${encodedObject}&owner_ref=${encodedOwner}`,
        )).body?.projection?.active_phase === "active",
    );

    const compaction = await request(
      plane.daemonUrl,
      "POST",
      "/v1/hypervisor/work-lifecycle/compaction",
      { object_ref: run.goal_ref, owner_ref: principalRef },
    );
    const statusAfterCompaction = await request(
      plane.daemonUrl,
      "GET",
      "/v1/hypervisor/work-lifecycle/status",
    );
    check(
      "compaction returns the archive-first checkpoint bound to the exact head while retaining the hot log",
      compaction.status === 200
        && compaction.body?.through_head === run.lifecycle_head
        && compaction.body?.archive_root?.startsWith("sha256:")
        && compaction.body?.archive_segment?.archive_root === compaction.body?.archive_root
        && compaction.body?.snapshot?.archive_root === compaction.body?.archive_root
        && compaction.body?.snapshot?.through_head === run.lifecycle_head
        && statusAfterCompaction.body?.durable_family_object_counts?.["work-lifecycle-archive-segments"] === 1
        && statusAfterCompaction.body?.durable_family_object_counts?.["work-lifecycle-snapshots"] === 1
        && statusAfterCompaction.body?.durable_family_object_counts?.["work-lifecycle-records"] === 1,
      `${compaction.status}/${compaction.body?.error?.code}`,
    );

    const cellPath = join(dataDir, "goal-run-context-cells", `${id}.json`);
    const exactCellBytes = readFileSync(cellPath);
    const changedCell = JSON.parse(exactCellBytes.toString("utf8"));
    changedCell.accountable_actor_ref = "actor://caller-substitution";
    writeFileSync(cellPath, JSON.stringify(changedCell));
    const changedReadback = await request(
      plane.daemonUrl,
      "GET",
      `/v1/goal-orchestration/goal-runs/${id}`,
    );
    writeFileSync(cellPath, exactCellBytes);
    check(
      "GoalRun readback fails closed when its executable application ContextCell bytes change",
      changedReadback.status === 409
        && changedReadback.body?.error?.code === "goal_run_context_cell_binding_changed",
      `${changedReadback.status}/${changedReadback.body?.error?.code}`,
    );

    await plane.stop();
    plane = await startIsolatedPlane({ dataDir });
    const replayedRun = await request(plane.daemonUrl, "GET", `/v1/goal-orchestration/goal-runs/${id}`);
    const replayedProjection = await request(
      plane.daemonUrl,
      "GET",
      `/v1/hypervisor/work-lifecycle/projection?object_ref=${encodedObject}&owner_ref=${encodedOwner}`,
    );
    const replayedStatus = await request(plane.daemonUrl, "GET", "/v1/hypervisor/work-lifecycle/status");
    check(
      "restart reconstructs GoalRun plan/context readback and snapshot-plus-tail lifecycle state",
      replayedRun.status === 200
        && replayedRun.body?.goal_run?.selected_orchestration_plan_revision_ref === plan.revision_ref
        && replayedRun.body?.goal_run?.context_cell_refs?.[0] === cell.context_cell_id
        && replayedProjection.status === 200
        && replayedProjection.body?.projection?.head === run.lifecycle_head
        && replayedStatus.body?.durable_family_object_counts?.["work-lifecycle-cancellation-plans"] === 1
        && replayedStatus.body?.durable_family_object_counts?.["work-lifecycle-archive-segments"] === 1
        && replayedStatus.body?.durable_family_object_counts?.["work-lifecycle-snapshots"] === 1,
      `${replayedRun.status}/${replayedProjection.status}/${replayedStatus.status}`,
    );
  }
} finally {
  if (plane) await plane.stop();
  rmSync(dataDir, { recursive: true, force: true });
}

for (const item of checks) {
  console.log(`${item.pass ? "PASS" : "FAIL"} ${item.name}${item.detail ? ` — ${item.detail}` : ""}`);
}
const failed = checks.filter((item) => !item.pass);
emitVerifierCensus({ verifierId: "m4-work-lifecycle-plane", sourceUrl: import.meta.url, results: checks });
if (failed.length) process.exitCode = 1;
else if (process.exitCode !== 2) console.log(`M04.6 work lifecycle isolated plane: PASS (${checks.length}/${checks.length})`);
