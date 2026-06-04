import assert from "node:assert/strict";
import test from "node:test";

import {
  MODEL_MOUNT_ROUTE_DECISION_COMMAND_SCHEMA_VERSION,
  ModelMountRouteDecisionRunnerError,
  RustModelMountRouteDecisionRunner,
} from "./route-decision-runner.mjs";

function routeRequest() {
  return {
    schema_version: "ioi.model_mount.route_decision.v1",
    route_ref: "route.local-first",
    provider_ref: "provider.local",
    endpoint_ref: "endpoint.local",
    model_ref: "model.local",
    capability: "chat",
    policy_hash: "sha256:policy",
    idempotency_key: "model_route_decision:test",
    receipt_refs: ["receipt://route"],
    authority_grant_refs: [],
    authority_receipt_refs: [],
    privacy_profile: "local_private",
    node_plaintext_allowed: false,
  };
}

test("Rust model_mount route-decision runner sends bridge admission request", () => {
  const calls = [];
  const runner = new RustModelMountRouteDecisionRunner({
    command: "mock-model-mount-bridge",
    spawnSyncImpl(command, args, options) {
      const request = JSON.parse(options.input);
      calls.push({ command, args, request });
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: true,
          result: {
            source: "rust_model_mount_command",
            backend: "rust_model_mount_live",
            record: {
              ...request.request,
              route_decision_ref: "model_mount://route_decision/test",
              route_decision_hash: "sha256:test",
            },
            route_decision_ref: "model_mount://route_decision/test",
            route_decision_hash: "sha256:test",
            receipt_refs: request.request.receipt_refs,
            evidence_refs: ["rust_model_mount_core"],
          },
        }),
        stderr: "",
      };
    },
  });

  const result = runner.admitRouteDecision(routeRequest());

  assert.equal(calls.length, 1);
  assert.equal(calls[0].command, "mock-model-mount-bridge");
  assert.equal(calls[0].request.schema_version, MODEL_MOUNT_ROUTE_DECISION_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "admit_model_mount_route_decision");
  assert.equal(calls[0].request.backend, "rust_model_mount_live");
  assert.equal(calls[0].request.request.model_ref, "model.local");
  assert.equal(result.route_decision_ref, "model_mount://route_decision/test");
  assert.equal(result.record.route_decision_hash, "sha256:test");
});

test("Rust model_mount route-decision runner fails closed without command", () => {
  const runner = new RustModelMountRouteDecisionRunner();

  assert.throws(
    () => runner.admitRouteDecision(routeRequest()),
    (error) =>
      error instanceof ModelMountRouteDecisionRunnerError &&
      error.code === "model_mount_route_decision_bridge_unconfigured",
  );
});
