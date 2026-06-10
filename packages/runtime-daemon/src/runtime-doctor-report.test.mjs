import assert from "node:assert/strict";
import test from "node:test";

import { createRuntimeDoctorReport } from "./runtime-doctor-report.mjs";
import { doctorCheck } from "./runtime-value-helpers.mjs";

function createHarness({ exists = () => true, env = {} } = {}) {
  const helper = createRuntimeDoctorReport({
    doctorCheck,
    doctorHash: (value) => `hash:${String(value).length}`,
    doctorProviderKeyReport: () => [{ name: "OPENAI_API_KEY", configured: false }],
    fs: { existsSync: exists },
    normalizeArray: (value) => (Array.isArray(value) ? value.filter(Boolean) : []),
    path: { join: (...parts) => parts.join("/") },
    processEnv: env,
    redactRuntimeNodeForDoctor: (node, { doctorHash }) => ({
      ...node,
      endpoint: node.endpoint ? "redacted" : null,
      endpointHash: node.endpoint ? doctorHash(node.endpoint) : null,
    }),
  });
  const store = {
    defaultCwd: "/workspace",
    stateDir: "/state",
    schemaVersion: "ioi.agentgres.runtime.v0",
    modelMounting: {
      projection: () => ({
        artifacts: [{ id: "model-one" }],
        routes: [{ id: "route.local-first" }],
        mcpServers: [{ id: "mcp-one", transport: "stdio", status: "ready", secretRefs: ["secret-a"] }],
      }),
    },
    memory: {
      records: new Map([["memory-one", {}]]),
      policies: new Map([["policy-one", {}]]),
      pathProjection: () => ({
        recordsPath: "/state/memory-records",
        policiesPath: "/state/memory-policies",
      }),
      effectivePolicy: () => ({ id: "policy-default", effective: true }),
    },
    skillHookCatalog: () => ({
      status: "pass",
      skillCount: 1,
      hookCount: 1,
      sources: [{ id: "workspace" }],
      activeSkillSetHash: "skill-hash",
      activeHookSetHash: "hook-hash",
      validationIssueCount: 0,
    }),
    listTools: () => [{ stable_tool_id: "fs.read" }],
    runs: new Map([["run-one", {}], ["run-two", {}], ["run-three", {}]]),
    listRuntimeNodes: () => [{ id: "hosted", endpoint: "https://provider.example" }],
  };
  return { helper, store };
}

test("runtime doctor report projects ready degraded status with redacted endpoints", () => {
  const { helper, store } = createHarness({
    env: {
      IOI_AGENTGRES_URL: "https://agentgres.example",
      IOI_WALLET_NETWORK_URL: "https://wallet.example",
    },
  });

  const report = helper.doctorReport(store, { baseUrl: "http://127.0.0.1:7777" });

  assert.equal(report.schemaVersion, "ioi.agent-runtime.doctor.v1");
  assert.equal(report.daemon.endpoint, "http://127.0.0.1:7777");
  assert.equal(report.readiness, "ready");
  assert.equal(report.status, "degraded");
  assert.equal(report.modelRoutes.selectedDefaultRoute, "route.local-first");
  assert.equal(report.mcp.servers[0].secretRefCount, 1);
  assert.equal(report.mcp.servers[0].secretsRedacted, true);
  assert.equal(report.agentgres.remoteAdapterConfigured, true);
  assert.equal(report.agentgres.source, "agentgres_canonical_state_projection");
  assert.equal(report.agentgres.runStateWatermark, 3);
  assert.equal(report.wallet.networkConfigured, true);
  assert.equal(report.runtimeNodes[0].endpoint, "redacted");
  assert.equal(report.runtimeNodes[0].endpointHash, "hash:24");
  assert.ok(report.optionalWarnings.includes("lsp.status"));
});

test("runtime doctor report blocks when required state paths are missing", () => {
  const { helper, store } = createHarness({
    exists: (target) => target !== "/workspace" && target !== "/state/memory-records",
  });

  const report = helper.doctorReport(store);

  assert.equal(report.status, "blocked");
  assert.equal(report.readiness, "blocked");
  assert.ok(report.blockers.includes("workspace.root"));
  assert.ok(report.blockers.includes("memory.store"));
  assert.equal(report.workspace.exists, false);
});

test("runtime doctor report degrades when runtime tool catalog projection is Rust-core required", () => {
  const { helper, store } = createHarness();
  store.listTools = () => {
    const error = new Error("Runtime tool catalog requires Rust core.");
    error.code = "runtime_tool_catalog_rust_core_required";
    error.details = {
      rust_core_boundary: "runtime.tool_catalog",
      projection_kind: "tools",
      workspace_root: "/workspace",
    };
    throw error;
  };
  store.listRuntimeNodes = () => {
    const error = new Error("Runtime nodes require Rust core.");
    error.code = "runtime_tool_catalog_rust_core_required";
    error.details = {
      rust_core_boundary: "runtime.tool_catalog",
      projection_kind: "runtime_nodes",
      workspace_root: "/workspace",
    };
    throw error;
  };

  const report = helper.doctorReport(store);
  const toolCheck = report.checks.find((check) => check.id === "tool.catalog");

  assert.equal(report.readiness, "ready");
  assert.equal(toolCheck.status, "degraded");
  assert.equal(toolCheck.required, false);
  assert.ok(report.optionalWarnings.includes("tool.catalog"));
  assert.equal(report.runtimeNodes.length, 0);
});
