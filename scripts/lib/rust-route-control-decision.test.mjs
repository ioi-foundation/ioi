// Faithful Rust route-control contract gate.
//
// Co-runs the Rust true-north hypervisor-daemon and drives the JS runtime
// daemon's run/turn route-selection (`store.resolveModelRoute`) through the
// Rust route-control client (createRustRouteControlClient). Asserts that the
// model_route_decision the Rust daemon authors satisfies the dual-cased
// contract the runtime records (camelCase) and run events (snake_case) consume.
//
// This proves the model-mount-facade-retirement route-control boundary: the
// decision is authored by Rust (daemon = execution semantics), not the retired
// in-process JS facade. The broader thread/turn HTTP projection still depends on
// the remaining Rust daemon-core typed APIs (MCP, context-policy, thread
// lifecycle, ...) which are tracked separately.

import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { startRuntimeDaemonService } from "../../packages/runtime-daemon/src/index.mjs";
import { createRustRouteControlClient } from "../../packages/runtime-daemon/src/threads/rust-route-control-client.mjs";
import { startRustHypervisorDaemon } from "./rust-hypervisor-daemon.mjs";

let rust;
let token;

test.before(async () => {
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-rust-route-control-state-"));
  rust = await startRustHypervisorDaemon({ stateDir });
  const grantResponse = await fetch(`${rust.endpoint}/v1/model-mount/tokens`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      audience: "hypervisor-local-server",
      allowed: ["route.use:*", "route.write:*"],
      denied: [],
    }),
  });
  assert.equal(grantResponse.ok, true, "token grant should succeed");
  token = (await grantResponse.json()).token;
});

test.after(async () => {
  if (rust) await rust.close();
});

test("Rust route-control authors the faithful model_route_decision for auto + native-local", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-rust-route-control-ws-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-rust-route-control-runtime-"));
  const daemon = await startRuntimeDaemonService({
    cwd,
    stateDir,
    routeControlClient: createRustRouteControlClient({
      daemonEndpoint: rust.endpoint,
      token,
    }),
  });
  try {
    // Mirrors the options buildAgentCreateCandidate hands store.resolveModelRoute
    // for a `POST /v1/threads` with model {id:"auto", routeId:"route.native-local",
    // reasoningEffort:"low", workflow...}. modelPolicyForOptions reads the camel
    // reasoningEffort; modelWorkflowContext reads the snake workflow_* / route_id.
    const modelRoute = await daemon.store.resolveModelRoute(
      {
        local: { cwd },
        model: {
          id: "auto",
          route_id: "route.native-local",
          reasoningEffort: "low",
          workflow_graph_id: "tti-parity",
          workflow_node_id: "workflow.model-router",
          workflow_node_type: "Model Router",
        },
      },
      {
        evidenceRefs: ["runtime_agent_model_route"],
        workflowNodeId: "runtime.model-router",
        workflowNodeType: "Model Router",
      },
    );

    // Top-level resolution.
    assert.equal(modelRoute.selectedModel, "hypervisor:native-fixture");
    assert.equal(modelRoute.routeId, "route.native-local");

    const decision = modelRoute.decision;
    assert.ok(decision, "decision should be present");

    // camelCase surface — consumed by the thread/turn HTTP records.
    assert.equal(decision.eventKind, "ModelRouteDecision");
    assert.equal(decision.requestedModel, "auto");
    assert.equal(decision.requestedModelMode, "auto");
    assert.equal(decision.autoResolved, true);
    assert.equal(decision.selectedModel, "hypervisor:native-fixture");
    assert.equal(decision.upstreamModel, "hypervisor:native-fixture");
    assert.equal(decision.neverSendAutoUpstream, true);
    assert.equal(decision.localRemotePlacement, "local");
    assert.equal(decision.privacyPosture, "local_only");
    assert.equal(decision.reasoningEffort, "low");
    assert.equal(decision.workflowNodeId, "workflow.model-router");
    assert.equal(decision.workflowGraphId, "tti-parity");
    assert.equal(decision.providerKind, "ioi_native_local");

    // snake_case surface — consumed by the run-event projection (the SDK type).
    assert.equal(decision.event_kind, "ModelRouteDecision");
    assert.equal(decision.requested_model_mode, "auto");
    assert.equal(decision.selected_model, "hypervisor:native-fixture");
    assert.equal(decision.upstream_model, "hypervisor:native-fixture");
    assert.equal(decision.never_send_auto_upstream, true);
    assert.equal(decision.reasoning_effort, "low");
    assert.equal(decision.local_remote_placement, "local");
    assert.equal(decision.privacy_posture, "local_only");
    assert.ok(decision.decision_id, "snake decision_id should be present for run-event id");

    // The decision is authored by the Rust true-north daemon, not the JS facade.
    assert.equal(decision.rust_core_boundary, "model_mount.route_control");
  } finally {
    await daemon.close();
  }
});

test("Rust route-control resolves an explicit model without auto coercion", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-rust-route-control-ws-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-rust-route-control-runtime-"));
  const daemon = await startRuntimeDaemonService({
    cwd,
    stateDir,
    routeControlClient: createRustRouteControlClient({
      daemonEndpoint: rust.endpoint,
      token,
    }),
  });
  try {
    const modelRoute = await daemon.store.resolveModelRoute(
      { local: { cwd }, model: { id: "qwen-explicit", route_id: "route.native-local" } },
      { evidenceRefs: ["runtime_agent_model_route"] },
    );
    assert.equal(modelRoute.selectedModel, "qwen-explicit");
    assert.equal(modelRoute.decision.requestedModelMode, "explicit");
    assert.equal(modelRoute.decision.autoResolved, false);
    assert.equal(modelRoute.decision.selectedModel, "qwen-explicit");
  } finally {
    await daemon.close();
  }
});
