import assert from "node:assert/strict";
import test from "node:test";

import {
  HYPERVISOR_ENVIRONMENT_STATUS_SCHEMA_VERSION,
  HYPERVISOR_WORKSPACE_INITIALIZER_SCHEMA_VERSION,
  ENVIRONMENT_COMPONENT_KEYS,
  buildHypervisorEnvironmentStatus,
  buildEnvironmentPort,
  deriveWorkspaceInitializer,
} from "./runtime-environment-status-projection.mjs";

test("builds a ready environment status with all canonical component sub-objects", () => {
  const status = buildHypervisorEnvironmentStatus({
    environmentRef: "environment:session-abc",
    workspaceRoot: "/tmp/ioi-hypervisor-sessions/session-abc",
    workspaceMountPolicy: "public_trunk",
    modelRouteRef: "model-route:hypervisor/default-local",
    harnessSessionRef: "harness-session-spawn:abc",
  });
  assert.equal(
    status.schema_version,
    HYPERVISOR_ENVIRONMENT_STATUS_SCHEMA_VERSION,
  );
  assert.equal(status.environment_ref, "environment:session-abc");
  assert.equal(status.phase, "running");
  for (const key of ENVIRONMENT_COMPONENT_KEYS) {
    assert.equal(status.components[key].phase, "ready", key);
  }
  assert.equal(status.components.workspace_content.custody_posture, "public_trunk");
  assert.equal(
    status.components.model_mount.model_route_ref,
    "model-route:hypervisor/default-local",
  );
  assert.equal(status.runtimeTruthSource, "daemon-runtime");
  assert.deepEqual(status.ports, []);
});

test("aggregate phase becomes starting while a component is still provisioning", () => {
  const status = buildHypervisorEnvironmentStatus({
    environmentRef: "environment:session-prov",
    componentPhases: { provisioner: "creating", workspace_content: "initializing" },
  });
  assert.equal(status.components.provisioner.phase, "creating");
  assert.equal(status.components.workspace_content.phase, "initializing");
  assert.equal(status.phase, "starting");
});

test("readiness check failures degrade the model_mount and harness phases", () => {
  const status = buildHypervisorEnvironmentStatus({
    environmentRef: "environment:session-degraded",
    readinessChecks: [
      { id: "harness_binary", status: "pass" },
      { id: "qwen_model_available", status: "fail" },
    ],
  });
  assert.equal(status.components.harness.phase, "ready");
  assert.equal(status.components.model_mount.phase, "degraded");
  assert.equal(status.phase, "updating");
});

test("a failed component drives the aggregate to failed", () => {
  const status = buildHypervisorEnvironmentStatus({
    componentPhases: { sandbox: "failed" },
    failureMessage: "sandbox could not start",
  });
  assert.equal(status.phase, "failed");
  assert.equal(status.failure_message, "sandbox could not start");
});

test("derives a scratch initializer for a fresh workspace", () => {
  const initializer = deriveWorkspaceInitializer({
    workspaceMountPolicy: "ctee_private_workspace",
    authorityScopeRefs: ["wallet-capability:workspace-write"],
  });
  assert.equal(
    initializer.schema_version,
    HYPERVISOR_WORKSPACE_INITIALIZER_SCHEMA_VERSION,
  );
  assert.deepEqual(initializer.specs, []);
  assert.equal(initializer.custody_posture, "ctee_private_workspace");
  assert.deepEqual(initializer.authority_scope_refs, [
    "wallet-capability:workspace-write",
  ]);
});

test("derives a git initializer spec from a remote", () => {
  const initializer = deriveWorkspaceInitializer({
    gitSpec: { remote_uri: "https://github.com/teamioitest/ioi" },
    workspaceMountPolicy: "public_trunk",
  });
  assert.equal(initializer.specs.length, 1);
  assert.equal(
    initializer.specs[0].git.remote_uri,
    "https://github.com/teamioitest/ioi",
  );
  assert.equal(initializer.specs[0].git.clone_target, ".");
});

test("builds a wallet-gated environment port with safe defaults", () => {
  const port = buildEnvironmentPort({ port: 4173, url: "http://127.0.0.1:4173" });
  assert.equal(port.port, 4173);
  assert.equal(port.access_policy, "session_lease");
  assert.equal(port.exposure_state, "lease_required");
  assert.equal(port.url, "http://127.0.0.1:4173");
});
