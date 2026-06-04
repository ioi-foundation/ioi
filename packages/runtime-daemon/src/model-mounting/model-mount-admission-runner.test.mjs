import assert from "node:assert/strict";
import test from "node:test";

import {
  MODEL_MOUNT_ADMISSION_COMMAND_ENV,
  MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION,
  ModelMountAdmissionRunnerError,
  createModelMountAdmissionRunnerFromEnv,
  RustModelMountAdmissionRunner,
} from "./model-mount-admission-runner.mjs";

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

function invocationRequest() {
  return {
    schema_version: "ioi.model_mount.invocation_admission.v1",
    invocation_ref: "model-invocation://response/test",
    route_decision_ref: "model_mount://route_decision/test",
    route_receipt_ref: "receipt://route",
    invocation_receipt_ref: "receipt://invocation",
    route_ref: "route.local-first",
    provider_ref: "provider.local",
    endpoint_ref: "endpoint.local",
    model_ref: "model.local",
    capability: "chat",
    invocation_kind: "responses",
    policy_hash: "sha256:policy",
    input_hash: "sha256:input",
    output_hash: "sha256:output",
    idempotency_key: "model_invocation:test",
    receipt_refs: ["receipt://route", "receipt://invocation"],
    authority_grant_refs: ["grant://wallet/model-chat"],
    authority_receipt_refs: [],
    provider_auth_evidence_refs: [],
    backend_evidence_refs: [],
    tool_receipt_refs: [],
    privacy_profile: "local_private",
    node_plaintext_allowed: false,
  };
}

test("Rust model_mount admission runner sends route-decision bridge request", () => {
  const calls = [];
  const runner = new RustModelMountAdmissionRunner({
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
  assert.equal(calls[0].request.schema_version, MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "admit_model_mount_route_decision");
  assert.equal(calls[0].request.backend, "rust_model_mount_live");
  assert.equal(calls[0].request.request.model_ref, "model.local");
  assert.equal(result.route_decision_ref, "model_mount://route_decision/test");
  assert.equal(result.record.route_decision_hash, "sha256:test");
});

test("Rust model_mount admission runner sends invocation bridge request", () => {
  const calls = [];
  const runner = new RustModelMountAdmissionRunner({
    command: "mock-model-mount-bridge",
    spawnSyncImpl(command, args, options) {
      const request = JSON.parse(options.input);
      calls.push({ command, args, request });
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: true,
          result: {
            source: "rust_model_mount_invocation_command",
            backend: "rust_model_mount_live",
            record: {
              ...request.request,
              invocation_admission_ref: "model_mount://invocation_admission/test",
              invocation_admission_hash: "sha256:invocation-test",
            },
            invocation_admission_ref: "model_mount://invocation_admission/test",
            invocation_admission_hash: "sha256:invocation-test",
            receipt_refs: request.request.receipt_refs,
            evidence_refs: ["rust_model_mount_core"],
          },
        }),
        stderr: "",
      };
    },
  });

  const result = runner.admitInvocation(invocationRequest());

  assert.equal(calls.length, 1);
  assert.equal(calls[0].request.schema_version, MODEL_MOUNT_ADMISSION_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "admit_model_mount_invocation");
  assert.equal(calls[0].request.request.route_decision_ref, "model_mount://route_decision/test");
  assert.equal(result.invocation_admission_ref, "model_mount://invocation_admission/test");
  assert.equal(result.record.invocation_admission_hash, "sha256:invocation-test");
});

test("Rust model_mount admission runner reads the generic admission command env", () => {
  const runner = createModelMountAdmissionRunnerFromEnv({
    [MODEL_MOUNT_ADMISSION_COMMAND_ENV]: "mock-model-mount-bridge",
  });

  assert.equal(runner.command, "mock-model-mount-bridge");
});

test("Rust model_mount admission runner fails closed without command", () => {
  const runner = new RustModelMountAdmissionRunner();

  assert.throws(
    () => runner.admitRouteDecision(routeRequest()),
    (error) =>
      error instanceof ModelMountAdmissionRunnerError &&
      error.code === "model_mount_admission_bridge_unconfigured",
  );
});
