import assert from "node:assert/strict";
import test from "node:test";

import {
  PHYSICAL_ACTION_INTENT_ADMISSION_SCHEMA_VERSION,
  admitPhysicalActionIntent,
} from "./runtime-physical-action-intent-admission.mjs";

function baseRequest(overrides = {}) {
  return {
    intent_id: "intent://physical/carwash/prep-vehicle-001",
    actor_id: "worker:carwash-prep-humanoid",
    task_id: "task://carwash/prep-vehicle-001",
    domain_ref: "domain://carwash/vehicle-prep",
    target_system_ref: "robot://bay-3/humanoid-1",
    action_kind: "manipulation",
    risk_class: "physical_action",
    execution_phase: "command_issued",
    requested_primitives: ["prim:physical.actuate"],
    requested_scopes: ["scope:physical.actuate"],
    physical_action_policy_ref: "policy://physical/carwash-prep",
    safety_envelope_ref: "safety://carwash/bay-3",
    human_supervision_policy_ref: "supervision://carwash/on-loop",
    supervision_mode: "human_on_loop",
    human_supervisor_refs: ["user://operator/bay-3"],
    emergency_stop_authority_ref: "estop://carwash/bay-3",
    emergency_stop_tested: true,
    emergency_stop_max_latency_ms: 250,
    sensor_evidence_receipt_refs: ["receipt://sensor/bay-3/preflight"],
    actuator_command_receipt_refs: ["receipt://actuator/bay-3/prep-command"],
    incident_policy_ref: "policy://physical/incidents/carwash",
    rollback_or_compensation_policy_ref: "policy://physical/compensation/carwash",
    wallet_approval_ref: "approval://wallet/physical-action/carwash",
    authority_ref: "grant://wallet/physical-action/carwash",
    policy_refs: [
      "policy://physical/carwash-prep",
      "policy://physical/incidents/carwash",
    ],
    receipt_refs: [
      "receipt://sensor/bay-3/preflight",
      "receipt://actuator/bay-3/prep-command",
    ],
    agentgres_operation_refs: [
      "agentgres://operation/physical-action/carwash/prep-vehicle-001",
    ],
    artifact_refs: ["artifact://sensor-video/bay-3/preflight"],
    state_root: "state_root:physical:carwash:001",
    execution_channel: "physical_action_adapter",
    ...overrides,
  };
}

test("admits physical action only through daemon-owned safety and receipt envelope", () => {
  const admission = admitPhysicalActionIntent(baseRequest(), {
    nowIso: () => "2026-06-17T18:00:00.000Z",
  });

  assert.equal(
    admission.schema_version,
    PHYSICAL_ACTION_INTENT_ADMISSION_SCHEMA_VERSION,
  );
  assert.equal(
    admission.admission_id,
    "physical-action-admission:intent_physical_carwash_prep-vehicle-001:manipulation",
  );
  assert.equal(admission.risk_class, "physical_action");
  assert.equal(admission.decision, "admitted");
  assert.equal(admission.requiresDaemonGate, true);
  assert.equal(admission.generic_tool_call_blocked, true);
  assert.equal(admission.runtimeTruthSource, "daemon-runtime");
  assert.deepEqual(admission.requested_scopes, ["scope:physical.actuate"]);
  assert.deepEqual(admission.sensor_evidence_receipt_refs, [
    "receipt://sensor/bay-3/preflight",
  ]);
});

test("blocks actuator-affecting work routed as a generic tool call", () => {
  assert.throws(
    () =>
      admitPhysicalActionIntent(
        baseRequest({
          execution_channel: "tool.invoke",
          generic_tool_call: true,
        }),
      ),
    (error) => {
      assert.equal(error.status, 403);
      assert.equal(error.code, "physical_action_generic_tool_call_blocked");
      return true;
    },
  );
});

test("requires tested emergency stop and current sensor evidence", () => {
  assert.throws(
    () =>
      admitPhysicalActionIntent(
        baseRequest({
          emergency_stop_tested: false,
        }),
      ),
    (error) => {
      assert.equal(error.status, 403);
      assert.equal(error.code, "physical_action_emergency_stop_test_required");
      return true;
    },
  );

  assert.throws(
    () =>
      admitPhysicalActionIntent(
        baseRequest({
          sensor_evidence_receipt_refs: [],
        }),
      ),
    (error) => {
      assert.equal(error.status, 403);
      assert.equal(error.code, "physical_action_sensor_evidence_receipt_refs_required");
      return true;
    },
  );
});

test("does not admit simulation-only evidence as actuator execution", () => {
  assert.throws(
    () =>
      admitPhysicalActionIntent(
        baseRequest({
          simulation_only: true,
          execution_phase: "command_issued",
        }),
      ),
    (error) => {
      assert.equal(error.status, 403);
      assert.equal(error.code, "physical_action_simulation_not_execution_receipt");
      return true;
    },
  );
});

test("manual-confirm physical actions require supervisor refs and wallet approval", () => {
  assert.throws(
    () =>
      admitPhysicalActionIntent(
        baseRequest({
          supervision_mode: "manual_confirm_each_action",
          human_supervisor_refs: [],
          wallet_approval_ref: null,
          authority_ref: null,
        }),
      ),
    (error) => {
      assert.equal(error.status, 403);
      assert.equal(
        error.code,
        "physical_action_human_supervision_authority_required",
      );
      return true;
    },
  );
});
