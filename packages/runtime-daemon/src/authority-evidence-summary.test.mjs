import assert from "node:assert/strict";
import test from "node:test";

import { authorityEvidenceSummaryForEvents } from "./authority-evidence-summary.mjs";

test("authority evidence summary emits canonical authority rows", () => {
  const summary = authorityEvidenceSummaryForEvents([
    {
      seq: 7,
      event_id: "event_authority_1",
      thread_id: "thread_alpha",
      turn_id: "turn_alpha",
      source_event_kind: "WorkflowRunCapabilityPreflightBlocked",
      event_kind: "policy.blocked",
      component_kind: "capability_preflight",
      status: "blocked",
      workflow_graph_id: "workflow.alpha",
      workflow_node_id: "node.workflow",
      payload_schema_version: "ioi.workflow.capability-preflight.v1",
      created_at: "2026-06-04T00:00:00.000Z",
      receipt_refs: ["receipt_event"],
      policy_decision_refs: ["policy_event"],
      payload: {
        event_kind: "WorkflowRunCapabilityPreflightBlocked",
        reason: "workflow_capability_preflight_blocked",
        run_id: "run_alpha",
        rows: [
          {
            node_id: "node_model",
            node_type: "agent_step",
            binding_kind: "model_capability",
            capability_ref: "model-capability:route.local-first",
            route_id: "route.local-first",
            authority_scope_requirements: ["model.chat:*"],
            receipt_refs: ["receipt_model"],
            policy_decision_refs: ["policy_model"],
          },
        ],
      },
    },
  ]);

  assert.equal(summary.schema_version, "ioi.authority-evidence-summary-list.v1");
  assert.equal(summary.row_count, 1);
  assert.equal(Object.hasOwn(summary, "schemaVersion"), false);
  assert.equal(Object.hasOwn(summary, "rowCount"), false);
  assert.equal(Object.hasOwn(summary, "generatedAt"), false);
  assert.equal(Object.hasOwn(summary, "rows"), false);
  assert.deepEqual(summary.filters, {
    thread_id: undefined,
    run_id: undefined,
    capability_ref: undefined,
    route_id: undefined,
  });

  const [row] = summary.items;
  assert.equal(row.schema_version, "ioi.authority-evidence-summary.v1");
  assert.equal(row.capability_ref, "model-capability:route.local-first");
  assert.equal(row.route_id, "route.local-first");
  assert.deepEqual(row.authority_scope_requirements, ["model.chat:*"]);
  assert.deepEqual(row.receipt_refs, ["receipt_event", "receipt_model"]);
  assert.deepEqual(row.policy_decision_refs, ["policy_event", "policy_model"]);
  assert.equal(row.source_run_id, "run_alpha");
  assert.equal(row.node_type, "agent_step");
  assert.equal(row.binding_kind, "model_capability");
  for (const retiredKey of [
    "schemaVersion",
    "capabilityRef",
    "routeId",
    "authorityScopeRequirements",
    "receiptRefs",
    "policyDecisionRefs",
    "sourceRunId",
    "nodeType",
    "bindingKind",
    "createdAt",
    "eventSeq",
  ]) {
    assert.equal(Object.hasOwn(row, retiredKey), false);
  }
});

test("authority evidence summary filters on canonical request fields", () => {
  const summary = authorityEvidenceSummaryForEvents(
    [
      authorityEvent({
        capability_ref: "tool-capability:filesystem.write",
        route_id: null,
        thread_id: "thread_alpha",
        run_id: "run_alpha",
      }),
      authorityEvent({
        capability_ref: "model-capability:route.remote",
        route_id: "route.remote",
        thread_id: "thread_beta",
        run_id: "run_beta",
      }),
    ],
    { capability_ref: "tool-capability:filesystem.write", thread_id: "thread_alpha" },
  );

  assert.equal(summary.row_count, 1);
  assert.equal(summary.items[0].capability_ref, "tool-capability:filesystem.write");
  assert.equal(summary.items[0].thread_id, "thread_alpha");
});

function authorityEvent({ capability_ref, route_id, thread_id, run_id }) {
  return {
    event_id: `event_${run_id}`,
    thread_id,
    source_event_kind: "WorkflowRunCapabilityPreflightBlocked",
    component_kind: "capability_preflight",
    payload_schema_version: "ioi.workflow.capability-preflight.v1",
    receipt_refs: [`receipt_${run_id}`],
    payload: {
      event_kind: "WorkflowRunCapabilityPreflightBlocked",
      reason: "workflow_capability_preflight_blocked",
      run_id,
      rows: [
        {
          capability_ref,
          route_id,
          authority_scope_requirements: ["scope:test"],
          receipt_refs: [`receipt_row_${run_id}`],
        },
      ],
    },
  };
}
