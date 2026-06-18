import assert from "node:assert/strict";
import test from "node:test";

import type {
  HypervisorLaunchedSessionProjection,
  HypervisorNewSessionLaunchSummary,
} from "./hypervisorShellNavigationModel.ts";
import {
  HYPERVISOR_LAUNCHED_SESSION_PROJECTIONS_LIMIT,
  HYPERVISOR_LAUNCHED_SESSION_PROJECTIONS_STORAGE_KEY,
  HYPERVISOR_REFERENCE_LAUNCHED_SESSION_PROJECTIONS,
  loadHypervisorLaunchedSessionProjections,
  mergeHypervisorLaunchedSessionProjection,
  persistHypervisorLaunchedSessionProjections,
} from "./hypervisorLaunchedSessionPersistence.ts";

class MemoryStorage {
  private readonly values = new Map<string, string>();

  getItem(key: string): string | null {
    return this.values.get(key) ?? null;
  }

  setItem(key: string, value: string): void {
    this.values.set(key, value);
  }
}

function launchSummary(id: string): HypervisorNewSessionLaunchSummary {
  return {
    schema_version: "ioi.hypervisor.new_session_launch_summary.v1",
    recipe_ref: "mission.default",
    seed_intent: `Run ${id}`,
    target_binding_ref: `target-binding:${id}`,
    target_binding: {
      schema_version: "ioi.hypervisor.new_session_target_binding.v1",
      target_binding_ref: `target-binding:${id}`,
      recipe_ref: "mission.default",
      target_kind: "mission",
      surface_id: "sessions",
      project_ref: "project:ioi",
      operator_intent_ref: `target-binding:${id}/intent`,
      session_route_ref: `session-route:sessions/${id}`,
      code_editor_adapter_target_ref: null,
      automation_recipe_ref: null,
      agent_template_ref: null,
      foundry_job_ref: null,
      provider_candidate_ref: null,
      environment_ref: null,
      private_workspace_ref: null,
      runtimeTruthSource: "daemon-runtime",
    },
    project_ref: "project:ioi",
    code_editor_adapter_ref: "code-editor-adapter:embedded_code_editor",
    code_editor_adapter_target_ref: "code-editor-target:embedded",
    code_editor_adapter_custody_posture: "local_projection",
    code_editor_adapter_launch_plan_ref: `launch-plan:${id}`,
    code_editor_adapter_connection_contract_ref: `connection-contract:${id}`,
    code_editor_adapter_executor_lane: "embedded_code_editor_host",
    code_editor_adapter_control_action: "open_embedded_code_editor",
    code_editor_adapter_control_channel_ref: `control-channel:${id}`,
    code_editor_adapter_access_lease_refs: [`lease:code-editor/${id}`],
    code_editor_adapter_authority_scope_refs: ["scope:workspace.read"],
    code_editor_adapter_receipt_refs: [`receipt://code-editor/${id}`],
    harness_selection_ref: "harness-profile:default_harness_profile",
    harness_selection_kind: "harness_profile",
    harness_label: "Default Harness Profile",
    harness_runtime_truth_source: "daemon-runtime",
    harness_truth_boundary: "daemon-owned",
    harness_verdict_state: "compatible",
    model_route_ref: "model-route:hypervisor/default-local",
    model_route_availability_state: "daemon_verified",
    model_route_available: true,
    model_route_endpoint_refs: ["model-endpoint:hypervisor/default-local"],
    privacy_posture_ref: "privacy:ctee-private-workspace",
    authority_scope_refs: ["scope:workspace.read", "scope:receipt.write"],
    receipt_preview_ref: `receipt-preview:new-session/${id}`,
    requires_daemon_gate: true,
    runtimeTruthSource: "daemon-runtime",
  };
}

function launchedSession(
  id: string,
  launchedAtMs = 1_718_000,
): HypervisorLaunchedSessionProjection {
  return {
    schema_version: "ioi.hypervisor.launched_session_projection.v1",
    session_ref: `session:launch/${id}`,
    launch_receipt_ref: `receipt://hypervisor/new-session/${id}`,
    recipe_ref: "mission.default",
    recipe_kind: "mission",
    surface_id: "sessions",
    project_ref: "project:ioi",
    project_label: "IOI",
    launched_at_ms: launchedAtMs,
    admission_state: "daemon_admitted",
    code_editor_adapter_admission: null,
    code_editor_adapter_admission_ref: null,
    launch_summary: launchSummary(id),
    runtimeTruthSource: "daemon-runtime",
  };
}

test("launched session cache loads only daemon-runtime projection records", () => {
  const storage = new MemoryStorage();
  storage.setItem(
    HYPERVISOR_LAUNCHED_SESSION_PROJECTIONS_STORAGE_KEY,
    JSON.stringify([
      launchedSession("valid"),
      { schema_version: "ioi.hypervisor.launched_session_projection.v1" },
      {
        ...launchedSession("wrong-truth"),
        runtimeTruthSource: "local-ui-cache",
      },
    ]),
  );

  const loaded = loadHypervisorLaunchedSessionProjections({ storage });
  assert.equal(loaded.length, 1);
  assert.equal(loaded[0]?.session_ref, "session:launch/valid");
  assert.equal(loaded[0]?.runtimeTruthSource, "daemon-runtime");
});

test("launched session merge deduplicates session refs and caps local projection history", () => {
  const current = Array.from(
    { length: HYPERVISOR_LAUNCHED_SESSION_PROJECTIONS_LIMIT + 3 },
    (_, index) => launchedSession(`older-${index}`, index),
  );
  const duplicate = {
    ...launchedSession("older-3", 99),
    project_label: "Updated",
  };

  const merged = mergeHypervisorLaunchedSessionProjection(current, duplicate);
  assert.equal(merged.length, HYPERVISOR_LAUNCHED_SESSION_PROJECTIONS_LIMIT);
  assert.equal(merged[0]?.session_ref, "session:launch/older-3");
  assert.equal(merged[0]?.project_label, "Updated");
  assert.equal(
    merged.filter((projection) => projection.session_ref === "session:launch/older-3")
      .length,
    1,
  );
});

test("launched session cache persists normalized projections only", () => {
  const storage = new MemoryStorage();
  persistHypervisorLaunchedSessionProjections({
    storage,
    projections: [
      launchedSession("persisted"),
      {
        ...launchedSession("bad"),
        session_ref: "not-a-session-ref",
      },
    ],
  });

  const raw = storage.getItem(HYPERVISOR_LAUNCHED_SESSION_PROJECTIONS_STORAGE_KEY);
  assert.ok(raw);
  const parsed = JSON.parse(raw) as HypervisorLaunchedSessionProjection[];
  assert.equal(parsed.length, 1);
  assert.equal(parsed[0]?.session_ref, "session:launch/persisted");
  assert.equal(parsed[0]?.launch_summary.requires_daemon_gate, true);
});

test("reference launched session seed gives fresh shells IOI-reference rail history", () => {
  assert.equal(HYPERVISOR_REFERENCE_LAUNCHED_SESSION_PROJECTIONS.length, 3);
  assert.deepEqual(
    HYPERVISOR_REFERENCE_LAUNCHED_SESSION_PROJECTIONS.map(
      (session) => session.launch_summary.seed_intent,
    ),
    [
      "Write Parent Harness Evidence Boundary Doc",
      "Write Harness Tool Call Documentation",
      "Design Postquantum Computers Website",
    ],
  );
  assert.equal(
    HYPERVISOR_REFERENCE_LAUNCHED_SESSION_PROJECTIONS[0]?.recipe_ref,
    "workbench.default",
  );
  assert.equal(
    HYPERVISOR_REFERENCE_LAUNCHED_SESSION_PROJECTIONS[0]?.admission_state,
    "daemon_admitted",
  );
  assert.equal(
    HYPERVISOR_REFERENCE_LAUNCHED_SESSION_PROJECTIONS[0]
      ?.code_editor_adapter_admission?.decision,
    "admitted",
  );
  assert.deepEqual(
    HYPERVISOR_REFERENCE_LAUNCHED_SESSION_PROJECTIONS.map(
      (session) => session.branch_label,
    ),
    ["main", "main", "main"],
  );
  assert.deepEqual(
    HYPERVISOR_REFERENCE_LAUNCHED_SESSION_PROJECTIONS.map(
      (session) => session.relative_time_label,
    ),
    ["6h ago", "6h ago", "6h ago"],
  );
  assert.deepEqual(
    HYPERVISOR_REFERENCE_LAUNCHED_SESSION_PROJECTIONS.map(
      (session) => session.activity_count,
    ),
    [3, 4, 5],
  );
  assert.ok(
    HYPERVISOR_REFERENCE_LAUNCHED_SESSION_PROJECTIONS.every(
      (session) => session.runtimeTruthSource === "daemon-runtime",
    ),
  );
});
