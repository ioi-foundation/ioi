import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { startRuntimeDaemonService } from "./index.mjs";

async function fetchJson(url, options = {}) {
  const response = await fetch(url, {
    headers: { "content-type": "application/json" },
    ...options,
  });
  const text = await response.text();
  const body = text ? JSON.parse(text) : null;
  assert.ok(response.ok, `${response.status} ${response.statusText} for ${url}: ${text}`);
  return body;
}

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function restoreEnv(name, value) {
  if (value === undefined) {
    delete process.env[name];
  } else {
    process.env[name] = value;
  }
}

function modelMountAdmissionRunnerForApprovalLeaseTest() {
  return {
    planReadProjection(request) {
      const projection = { source: "agentgres_model_mounting_projection" };
      return {
        source: "rust_model_mount_read_projection_command",
        backend: "rust_model_mount_read_projection",
        projection_kind: request.projection_kind,
        projection,
        evidence_refs: [
          "rust_daemon_core_model_mount_projection",
          "agentgres_model_mount_read_truth",
          "model_mount_js_read_projection_authoring_retired",
        ],
      };
    },
  };
}

function runtimeAgentgresAdmissionRunnerForApprovalLeaseTest() {
  function writeCommittedRecord(stateDir, recordPath, value) {
    const targetPath = path.join(stateDir, recordPath);
    fs.mkdirSync(path.dirname(targetPath), { recursive: true });
    fs.writeFileSync(targetPath, `${JSON.stringify(value, null, 2)}\n`);
  }

  return {
    commitRuntimeAgentState(stateDir, request) {
      const recordPath = `agents/${request.agent_id}.json`;
      writeCommittedRecord(stateDir, recordPath, request.agent ?? request);
      return {
        source: "rust_agentgres_runtime_agent_state_commit_command",
        agent_id: request.agent_id,
        object_ref: `agentgres://runtime-state/agents/${request.agent_id}/records/${recordPath}`,
        content_hash: "sha256:approval-lease-agent-content",
        admission_hash: "sha256:approval-lease-agent-admission",
        commit_hash: "sha256:approval-lease-agent-commit",
        written_record: { record_path: recordPath },
        evidence_refs: ["rust_agentgres_runtime_agent_state_commit"],
      };
    },
    commitRuntimeRunState(stateDir, request) {
      const recordPath = `runs/${request.run_id}.json`;
      writeCommittedRecord(stateDir, recordPath, request.run ?? request);
      return {
        source: "rust_agentgres_runtime_run_state_commit_command",
        operation_ref: `agentgres://runtime-state/runs/${request.run_id}/operations/${request.operation_kind}_approval_lease_test`,
        state_root_after: "sha256:approval-lease-state-root-after",
        resulting_head: `agentgres://runtime-state/runs/${request.run_id}/head/approval-lease-test`,
        transition_hash: "sha256:approval-lease-transition",
        materialization_hash: "sha256:approval-lease-materialization",
        write_set_hash: "sha256:approval-lease-write-set",
        persistence_hash: "sha256:approval-lease-persistence",
        commit_hash: "sha256:approval-lease-run-commit",
        written_records: [recordPath],
        evidence_refs: ["rust_agentgres_runtime_run_state_commit"],
      };
    },
  };
}

test("coding tool approval leases stop satisfying retries after expiry", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-approval-lease-expiry-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-approval-lease-expiry-state-"));
  const targetPath = path.join(cwd, "lease.txt");
  fs.writeFileSync(targetPath, "lease before\n", "utf8");
  const previousFixtureEnv = process.env.IOI_EXPOSE_INTERNAL_FIXTURE_MODELS;
  process.env.IOI_EXPOSE_INTERNAL_FIXTURE_MODELS = "1";
  let daemon;

  try {
    daemon = await startRuntimeDaemonService({
      cwd,
      stateDir,
      modelMountAdmissionRunner: modelMountAdmissionRunnerForApprovalLeaseTest(),
      runtimeAgentgresAdmissionRunner: runtimeAgentgresAdmissionRunnerForApprovalLeaseTest(),
    });
    const now = new Date().toISOString();
    const agent = {
      id: "agent_approval_lease_expiry",
      status: "active",
      runtime: "agent",
      cwd,
      modelId: "autopilot:native-fixture",
      requestedModelId: "auto",
      modelRouteId: "route.native-local",
      modelRouteEndpointId: null,
      modelRouteProviderId: null,
      modelRouteReceiptId: null,
      modelRouteDecision: null,
      runtimeControls: {
        mode: "yolo",
        approvalMode: "never_prompt",
        model: { id: "auto", routeId: "route.native-local" },
      },
      mcpRegistry: null,
      createdAt: now,
      updatedAt: now,
      options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
    };
    daemon.store.agents.set(agent.id, agent);
    daemon.store.writeAgent(agent, "agent.create.approval-lease-expiry-test");
    const thread = daemon.store.threadForAgent(agent);
    const toolEndpoint = `${daemon.endpoint}/v1/threads/${thread.thread_id}/tools/file.apply_patch/invoke`;
    const ttlMs = 1200;
    const request = {
      source: "react_flow",
      workflowGraphId: "workflow.runtime-daemon.approval-lease-expiry",
      workflowNodeId: "workflow.approval-lease.file.apply-patch",
      toolCallId: "coding_tool_approval_lease_expiry_probe",
      ttlMs,
      requiresApproval: true,
      approvalMode: "human_required",
      nodeApprovalOverride: "require_approval",
      trustProfile: "review_required",
      toolPack: {
        coding: {
          requiresApproval: true,
          approvalMode: "human_required",
          nodeApprovalOverride: "require_approval",
          trustProfile: "review_required",
        },
      },
      input: {
        path: "lease.txt",
        oldText: "lease before",
        newText: "lease after",
        dryRun: true,
      },
    };

    const blocked = await fetchJson(toolEndpoint, {
      method: "POST",
      body: JSON.stringify({
        ...request,
        idempotencyKey: "approval-lease-expiry-blocked",
      }),
    });
    assert.equal(blocked.status, "blocked");
    assert.equal(blocked.approval_required, true);
    assert.equal(fs.readFileSync(targetPath, "utf8"), "lease before\n");

    const approved = await fetchJson(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/approvals/${blocked.approval_id}/approve`,
      {
        method: "POST",
        body: JSON.stringify({
          source: "react_flow",
          workflowGraphId: request.workflowGraphId,
          workflowNodeId: request.workflowNodeId,
          reason: "Approve short-lived lease before expiry.",
        }),
      },
    );
    assert.equal(approved.decision, "approve");
    assert.equal(approved.lease_status, "active");

    const executedBeforeExpiry = await fetchJson(toolEndpoint, {
      method: "POST",
      body: JSON.stringify({
        ...request,
        idempotencyKey: "approval-lease-expiry-before",
        approvalId: blocked.approval_id,
      }),
    });
    assert.equal(executedBeforeExpiry.status, "completed");
    assert.equal(executedBeforeExpiry.event.payload_summary.approval_satisfied, true);
    assert.equal(fs.readFileSync(targetPath, "utf8"), "lease before\n");

    const expiresAtMs = Date.parse(approved.approval_lease.expires_at);
    assert.ok(Number.isFinite(expiresAtMs));
    await wait(Math.max(0, expiresAtMs - Date.now()) + 80);

    const blockedAfterExpiry = await fetchJson(toolEndpoint, {
      method: "POST",
      body: JSON.stringify({
        ...request,
        idempotencyKey: "approval-lease-expiry-after",
        approvalId: blocked.approval_id,
      }),
    });
    assert.equal(blockedAfterExpiry.status, "blocked");
    assert.equal(blockedAfterExpiry.approval_required, true);
    assert.equal(blockedAfterExpiry.error?.code, "coding_tool_approval_required");
    assert.equal(fs.readFileSync(targetPath, "utf8"), "lease before\n");
  } finally {
    if (daemon) await daemon.close();
    restoreEnv("IOI_EXPOSE_INTERNAL_FIXTURE_MODELS", previousFixtureEnv);
  }
});
