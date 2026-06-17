import assert from "node:assert/strict";
import test from "node:test";

import { createRuntimeCodingToolInvocationSurface } from "./runtime-coding-tool-invocation-surface.mjs";

function codingToolSourceEventKindForTest(toolId = "") {
  return `CodingTool.${String(toolId)
    .split(/[._-]/)
    .filter(Boolean)
    .map((part) => part.slice(0, 1).toUpperCase() + part.slice(1))
    .join("")}`;
}

function planCodingToolResultEnvelopeForTest(_store, input = {}) {
  const receiptRefs = Array.isArray(input.receipt_refs) ? input.receipt_refs : [];
  const artifactRefs = Array.isArray(input.artifact_refs) ? input.artifact_refs : [];
  const rollbackRefs = Array.isArray(input.rollback_refs) ? input.rollback_refs : [];
  const turnOrThread = input.turn_id || input.thread_id;
  const stepModuleContext = {
    run_id: `run:${input.thread_id}`,
    task_id: `task:${turnOrThread}`,
    thread_id: input.thread_id,
    workflow_graph_id: input.workflow_graph_id ?? null,
    workflow_node_id: input.workflow_node_id,
    action_proposal_ref: `action:coding-tool:${input.tool_call_id}`,
    gate_result_ref: `gate:coding-tool:${input.tool_call_id}`,
    approval_ref: input.approval_id ? `approval:${input.approval_id}` : null,
    idempotency_key: input.idempotency_key,
    status: input.status === "failed" ? "failure" : "success",
    workflow_projection_status: "live",
    receipt_refs: receiptRefs,
    artifact_refs: artifactRefs,
    workspace_root: input.workspace_root ?? null,
  };
  const base = {
    source: "rust_coding_tool_result_envelope_plan_command",
    backend: "rust_runtime_coding_tool_event",
    planned: true,
    operation_kind: "runtime.coding_tool.result_envelope",
    phase: input.phase,
    step_module_context: stepModuleContext,
    receipt_refs: receiptRefs,
    artifact_refs: artifactRefs,
    rollback_refs: rollbackRefs,
    envelope_hash: `sha256:envelope-${input.phase}-${input.tool_call_id}`,
  };
  if (input.phase === "step_module_context") {
    return {
      ...base,
      event: null,
      payload_summary: null,
      record: {
        ...base,
        status: "planned",
      },
    };
  }
  const stepModule = input.step_module && typeof input.step_module === "object" ? input.step_module : {};
  const payloadSummary = {
    schema_version: "ioi.runtime.coding-tool-result.v1",
    event_kind: "CodingToolResult",
    tool_pack: "coding",
    tool_name: input.tool_id,
    tool_call_id: input.tool_call_id,
    thread_id: input.thread_id,
    turn_id: input.turn_id ?? null,
    workspace_root: input.workspace_root ?? null,
    workflow_graph_id: input.workflow_graph_id ?? null,
    workflow_node_id: input.workflow_node_id,
    status: input.status ?? "completed",
    summary: input.summary ?? null,
    shell_fallback_used: false,
    input_summary: input.input_summary ?? null,
    result_summary: input.result_summary ?? null,
    result: input.result ?? null,
    error: input.error ?? null,
    rollback_refs: rollbackRefs,
    diagnostics_repair_context: input.diagnostics_repair_context ?? null,
    approval_required: Boolean(input.approval_required),
    approval_satisfied: Boolean(input.approval_satisfied),
    approval_id: input.approval_id ?? null,
    approval_manifest: input.approval_manifest ?? null,
    approval_decision_event_id: input.approval_decision_event_id ?? null,
    approval_receipt_refs: input.approval_receipt_refs ?? [],
    approval_policy_decision_refs: input.approval_policy_decision_refs ?? [],
    receipt_id: input.receipt_id ?? null,
    receipt_count: receiptRefs.length,
    artifact_count: artifactRefs.length,
    step_module_backend: input.step_module_backend ?? stepModule.backend ?? null,
    step_module_invocation: stepModule.invocation ?? null,
    step_module_result: stepModule.result ?? null,
    step_module_error: input.step_module_error ?? null,
  };
  const event = {
    event_stream_id: input.event_stream_id,
    thread_id: input.thread_id,
    turn_id: input.turn_id ?? null,
    item_id: `${turnOrThread}:item:coding-tool:${input.tool_id}:${input.tool_call_id}`,
    idempotency_key: input.idempotency_key,
    source: input.source ?? "runtime_auto",
    source_event_kind: codingToolSourceEventKindForTest(input.tool_id),
    event_kind: input.status === "failed" ? "tool.failed" : "tool.completed",
    status: input.status ?? "completed",
    actor: "runtime",
    workspace_root: input.workspace_root ?? null,
    workflow_graph_id: input.workflow_graph_id ?? null,
    workflow_node_id: input.workflow_node_id,
    component_kind: "coding_tool",
    tool_call_id: input.tool_call_id,
    artifact_refs: artifactRefs,
    receipt_refs: receiptRefs,
    rollback_refs: rollbackRefs,
    payload_schema_version: "ioi.runtime.coding-tool-result.v1",
    payload_summary: payloadSummary,
  };
  return {
    ...base,
    event,
    payload_summary: payloadSummary,
    record: {
      ...base,
      status: "planned",
      event,
      payload_summary: payloadSummary,
    },
  };
}

function createSurface(overrides = {}) {
  return createRuntimeCodingToolInvocationSurface({
    codingToolApprovalBlockForThread(input) {
      input.store?.calls?.push({ name: "rustApprovalBlock", input });
      return {
        source: "rust_coding_tool_approval_block_protocol",
        backend: "rust_authority",
        status: "blocked",
        operation_kind: "coding_tool.approval.block",
        approval_id: input.approval_gate?.approval_id ?? null,
        reason: input.approval_gate?.reason ?? "approval_not_satisfied",
        receipt_refs: input.receiptRefs ?? [],
        policy_decision_refs: input.policyDecisionRefs ?? [],
        artifact_refs: [],
        rollback_refs: input.rollbackRefs ?? [],
        result: {
          schema_version: "ioi.runtime.coding-tool-result.v1",
          tool_name: input.toolId,
          status: "blocked",
          approval_required: true,
          approval_satisfied: false,
          approval_id: input.approval_gate?.approval_id ?? null,
          approval_manifest: input.approval_manifest,
          rust_authority_block: true,
          error: {
            code: "coding_tool_approval_required",
            details: {
              reason: input.approval_gate?.reason ?? "approval_not_satisfied",
            },
          },
        },
        event: {
          event_stream_id: `${input.threadId}:events`,
          thread_id: input.threadId,
          turn_id: input.turnId,
          item_id: `${input.turnId || input.threadId}:item:coding-tool:${input.toolId}:blocked`,
          idempotency_key: input.idempotencyKey,
          source: "runtime_auto",
          source_event_kind: "coding_tool.approval.blocked",
          event_kind: "tool.blocked",
          status: "blocked",
          actor: "runtime",
          workspace_root: input.workspaceRoot,
          workflow_graph_id: input.workflowGraphId,
          workflow_node_id: input.workflowNodeId,
          component_kind: "coding_tool",
          tool_call_id: input.toolCallId,
          receipt_refs: input.receiptRefs ?? [],
          policy_decision_refs: input.policyDecisionRefs ?? [],
          artifact_refs: [],
          rollback_refs: input.rollbackRefs ?? [],
          payload_schema_version: "ioi.runtime.coding-tool-result.v1",
          payload_summary: {
            schema_version: "ioi.runtime.coding-tool-result.v1",
            event_kind: "CodingToolResult",
            tool_name: input.toolId,
            tool_call_id: input.toolCallId,
            thread_id: input.threadId,
            turn_id: input.turnId,
            status: "blocked",
            approval_required: true,
            approval_satisfied: false,
            approval_id: input.approval_gate?.approval_id ?? null,
            approval_manifest: input.approval_manifest,
            rust_authority_block: true,
            receipt_refs: input.receiptRefs ?? [],
          },
        },
        record: {
          schema_version: "ioi.runtime.coding-tool-approval-block-result.v1",
          status: "blocked",
          operation_kind: "coding_tool.approval.block",
        },
      };
    },
    codingToolApprovalManifestForThread: () => null,
    codingToolBudgetPolicyForRequest: () => ({ status: "allowed" }),
    codingToolResultWithoutDrafts(result = {}, artifacts = []) {
      const publicResult = { ...result };
      delete publicResult.artifactDrafts;
      delete publicResult.artifact_drafts;
      return {
        ...publicResult,
        artifact_refs: artifacts.map((artifactRecord) => artifactRecord.id),
        receipt_refs: ["receipt_result"],
      };
    },
    diagnosticsRepairContextForRequest: (request = {}) => request.diagnosticsRepairContext ?? null,
    diagnosticsRepairContextForToolPack: (_request, _input, toolId) => ({ source: "tool_pack", toolId }),
    codingToolResultEnvelopeForThread: planCodingToolResultEnvelopeForTest,
    codingToolResultEventAdmissionForThread(store, input = {}) {
      const event = input.event ?? input;
      store.calls.push({ name: "rustResultEventAdmission", input, event });
      const nextSeq = store.latestRuntimeEventSeq(event.event_stream_id) + 1;
      const admitted = {
        ...event,
        event_id: event.event_id ?? `event_${nextSeq}`,
        seq: nextSeq,
        created_at: "rust_daemon_core",
        payload_refs: [
          ...(Array.isArray(event.payload_refs) ? event.payload_refs : []),
          `payload://runtime-events/${event.event_stream_id.replace(/[^a-zA-Z0-9_.-]+/g, "_")}/events/event_${nextSeq}`,
        ],
        receipt_refs: event.receipt_refs ?? [],
        artifact_refs: event.artifact_refs ?? [],
        rollback_refs: event.rollback_refs ?? [],
        expected_heads: [`agentgres://runtime-events/${event.event_stream_id.replace(/[^a-zA-Z0-9_.-]+/g, "_")}/head/${nextSeq - 1}`],
        state_root_before: `sha256:before-${nextSeq - 1}`,
        state_root_after: `sha256:after-${nextSeq}`,
        resulting_head: `agentgres://runtime-events/${event.event_stream_id.replace(/[^a-zA-Z0-9_.-]+/g, "_")}/head/after-${nextSeq}`,
        agentgres_operation_ref: `agentgres://runtime-events/${event.event_stream_id.replace(/[^a-zA-Z0-9_.-]+/g, "_")}/operations/event_${nextSeq}`,
        agentgres_storage_admission_hash: `sha256:storage-${nextSeq}`,
      };
      store.registerRuntimeEvent(admitted);
      return admitted;
    },
    ...overrides,
  });
}

const retiredInvocationErrorDetailAliasKeys = ["threadId", "toolId"];

function assertNoRetiredInvocationErrorDetailAliases(details) {
  for (const key of retiredInvocationErrorDetailAliasKeys) {
    assert.equal(Object.hasOwn(details, key), false, `retired invocation error detail alias ${key} must be absent`);
  }
}

function workloadApiFromRunner(runner) {
  return {
    runCodingToolStepModule(request = {}) {
      const projection = runner.runCodingTool({
        toolId: request.tool_id,
        input: request.input,
        context: request,
      });
      const workloadResult =
        projection?.workload_result && typeof projection.workload_result === "object"
          ? projection.workload_result
          : projection;
      return {
        ...workloadResult,
        source: workloadResult?.source ?? projection?.source,
        invocation: workloadResult?.invocation ?? projection?.invocation ?? null,
        result: workloadResult?.result ?? projection?.result ?? null,
        receipt_refs: workloadResult?.receipt_refs ?? projection?.receipt_refs ?? [],
      };
    },
  };
}

function createStore(options = {}) {
  const events = [];
  const idempotency = new Map();
  const calls = [];
  const store = {
    calls,
    events,
    idempotency,
    agentForThread(threadId) {
      calls.push({ name: "agentForThread", threadId });
      return { id: "agent_alpha", cwd: "/tmp/workspace" };
    },
    threadForAgent(agent) {
      calls.push({ name: "threadForAgent", agent });
      return { latest_turn_id: "turn_latest" };
    },
    runtimeEventStream(eventStreamId) {
      calls.push({ name: "runtimeEventStream", eventStreamId });
      return { idempotency, events };
    },
    latestRuntimeEventSeq(eventStreamId) {
      calls.push({ name: "latestRuntimeEventSeq", eventStreamId });
      return events
        .filter((event) => event.event_stream_id === eventStreamId)
        .reduce((latest, event) => Math.max(latest, event.seq ?? 0), 0);
    },
    registerRuntimeEvent(record) {
      calls.push({ name: "registerRuntimeEvent", record });
      events.push(record);
      events.sort((left, right) => left.seq - right.seq);
      idempotency.set(record.idempotency_key, record);
      return record;
    },
    codingToolArtifactSurface: {
      readCodingToolArtifact(surfaceStore, threadId, artifactId, range) {
        assert.equal(surfaceStore, store);
        calls.push({ name: "readArtifact", threadId, artifactId, range });
        return {
          schema_version: "ioi.runtime.coding-tool-result.v1",
          artifact_id: artifactId,
          artifact_refs: [artifactId],
          content: "stored artifact\n",
          content_hash: "artifact-content-hash",
          full_content_hash: "artifact-full-hash",
          offset_bytes: range?.offset_bytes ?? 0,
          length_bytes: 16,
          total_bytes: 16,
          truncated: false,
          receipt_refs: ["receipt_artifact_read"],
          shell_fallback_used: false,
        };
      },
      retrieveCodingToolResult(surfaceStore, threadId, query) {
        assert.equal(surfaceStore, store);
        calls.push({ name: "retrieveResult", threadId, query });
        return {
          schema_version: "ioi.runtime.coding-tool-result.v1",
          tool_call_id: query.tool_call_id ?? "tool_from_artifact",
          artifact_id: query.artifact_id ?? "artifact_result",
          artifact_refs: [query.artifact_id ?? "artifact_result"],
          channel: query.channel ?? "stdout",
          content: "stored result\n",
          content_hash: "result-content-hash",
          full_content_hash: "result-full-hash",
          offset_bytes: query.range?.offset_bytes ?? 0,
          length_bytes: 14,
          total_bytes: 14,
          truncated: false,
          available_artifacts: [{ artifact_id: query.artifact_id ?? "artifact_result", channel: query.channel ?? "stdout" }],
          receipt_refs: ["receipt_tool_retrieve_result"],
          shell_fallback_used: false,
        };
      },
      materializeCodingToolArtifactDrafts(surfaceStore, input) {
        assert.equal(surfaceStore, store);
        calls.push({ name: "materializeArtifacts", input });
        return [{ id: "artifact_stdout" }];
      },
      admitCodingToolCommandStreamEvents(surfaceStore, input) {
        assert.equal(surfaceStore, store);
        calls.push({ name: "rustCommandStreamAdmission", input });
        return [{ event_id: "event_command_stream", event_kind: "artifact.command_stream" }];
      },
    },
    prepareWorkspaceSnapshotForPatch(input) {
      calls.push({ name: "prepareSnapshot", input });
      if (options.onPrepareSnapshot) {
        return options.onPrepareSnapshot(input);
      }
      return {
        record: {
          snapshot_id: "snapshot_alpha",
          artifact_refs: ["artifact_snapshot"],
          receipt_refs: ["receipt_snapshot"],
        },
        event: { event_id: "event_snapshot" },
      };
    },
    appendWorkspaceSnapshotEvent() {
      calls.push({ name: "appendSnapshotEvent" });
      throw new Error("appendWorkspaceSnapshotEvent must not be called by coding-tool invocation");
    },
    appendRuntimeEvent(event) {
      throw new Error(`appendRuntimeEvent must not be called by coding-tool invocation result admission: ${event?.event_kind}`);
    },
    diagnosticsFeedbackSurface: {
      maybeRunPostEditDiagnostics(surfaceStore, input) {
        assert.equal(surfaceStore, store);
        calls.push({ name: "diagnostics", input });
        return { status: "completed", patchToolCallId: input.patchToolCallId };
      },
    },
    codingToolGovernanceSurface: {
      blockCodingToolForBudget(surfaceStore, input) {
        assert.equal(surfaceStore, store);
        calls.push({ name: "blockBudget", input });
        return {
          event: {
            event_stream_id: `${input.threadId}:events`,
            thread_id: input.threadId,
            turn_id: input.turnId,
            item_id: `${input.turnId}:item:coding-tool:${input.toolId}:budget-blocked`,
            idempotency_key: input.codingToolIdempotencyKey,
            source: "runtime_auto",
            source_event_kind: "coding_tool.budget.blocked",
            event_kind: "tool.blocked",
            status: "blocked",
            actor: "runtime",
            workspace_root: "/tmp/workspace",
            workflow_graph_id: input.workflowGraphId,
            workflow_node_id: input.workflowNodeId,
            component_kind: "coding_tool",
            tool_call_id: input.toolCallId,
            receipt_refs: ["receipt_budget"],
            artifact_refs: [],
            rollback_refs: [],
            payload_schema_version: "ioi.runtime.coding-tool-result.v1",
            payload_summary: {
              schema_version: "ioi.runtime.coding-tool-result.v1",
              tool_name: input.toolId,
              tool_call_id: input.toolCallId,
              status: "blocked",
              receipt_refs: ["receipt_budget"],
              rust_budget_block: true,
            },
            event_id: "event_budget",
          },
          receipt_refs: ["receipt_budget"],
          policy_decision_refs: ["policy_budget"],
        };
      },
    },
    invokeComputerUseBrowserDiscoveryTool(threadId, toolId, request) {
      calls.push({ name: "browserDiscovery", threadId, toolId, request });
      return { routed: "browser_discovery", toolId };
    },
  };
  return store;
}

test("coding tool invocation surface fails closed without Rust workload API before JS execution", () => {
  const surface = createSurface();
  const store = createStore();

  assert.throws(
    () =>
      surface.invokeThreadTool(store, "thread_alpha", "file.apply_patch", {
        tool_call_id: "tool_alpha",
        workflowGraphId: "graph_alpha",
        source: "runtime_auto",
        rollback_refs: ["rollback_request"],
        input: { patch: "*** Begin Patch\n*** End Patch\n" },
      }),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "runtime_coding_tool_workload_rust_core_required");
      assert.equal(error.details.rust_core_boundary, "runtime.coding_tool_invocation");
      assert.equal(error.details.operation, "coding_tool_step_module_execution");
      assert.equal(error.details.operation_kind, "runtime.coding_tool.step_module");
      assert.equal(error.details.thread_id, "thread_alpha");
      assert.equal(error.details.tool_id, "file.apply_patch");
      assert.equal(error.details.tool_call_id, "tool_alpha");
      assert.deepEqual(error.details.evidence_refs, [
        "step_module_runner_js_facade_retired",
        "rust_daemon_core_workload_api_required",
        "step_module_router_dispatch_required",
      ]);
      return true;
    },
  );
  assert.ok(!store.calls.some((call) => call.name === "materializeArtifacts"));
  assert.ok(!store.calls.some((call) => call.name === "rustCommandStreamAdmission"));
  assert.ok(!store.calls.some((call) => call.name === "prepareSnapshot"));
});

test("coding tool invocation surface fails closed before workload execution without Rust result envelope planning", () => {
  let runnerCalled = false;
  const liveRunner = {
    backend: "rust_workload_live",
    blocksDaemonJsExecution: true,
    runCodingTool() {
      runnerCalled = true;
      throw new Error("runner must not be called without Rust envelope planning");
    },
  };
  const surface = createRuntimeCodingToolInvocationSurface({
    codingToolApprovalManifestForThread: () => null,
    codingToolBudgetPolicyForRequest: () => ({ status: "allowed" }),
    codingToolResultWithoutDrafts: (result = {}) => result,
    diagnosticsRepairContextForRequest: () => null,
    diagnosticsRepairContextForToolPack: () => null,
    daemonCoreWorkloadApi: workloadApiFromRunner(liveRunner),
  });
  const store = createStore();

  assert.throws(
    () =>
      surface.invokeThreadTool(store, "thread_alpha", "workspace.status", {
        tool_call_id: "tool_status_envelope_required",
        workflow_graph_id: "graph_alpha",
        workflow_node_id: "node_status",
        input: {},
      }),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "runtime_coding_tool_result_envelope_rust_core_required");
      assert.equal(error.details.rust_core_boundary, "runtime.coding_tool_invocation");
      assert.equal(error.details.operation, "coding_tool_result_envelope_planning");
      assert.equal(error.details.operation_kind, "runtime.coding_tool.result_envelope");
      assert.equal(error.details.phase, "step_module_context");
      assert.deepEqual(error.details.evidence_refs, [
        "coding_tool_result_envelope_js_authoring_retired",
        "rust_daemon_core_coding_tool_result_envelope_required",
        "agentgres_coding_tool_result_event_admission_required",
      ]);
      return true;
    },
  );
  assert.equal(runnerCalled, false);
  assert.equal(store.events.length, 0);
});

test("coding tool invocation surface fails closed until Rust result-event admission is wired", () => {
  const liveRunner = {
    backend: "rust_workload_live",
    blocksDaemonJsExecution: true,
    runCodingTool() {
      return {
        backend: "rust_workload_live",
        mode: "live",
        blocking: true,
        source: "rust_workload_api",
        invocation: {
          schema_version: "ioi.step_module_invocation.v1",
          invocation_id: "invocation://rust-live/workspace.status",
        },
        result: {
          schema_version: "ioi.step_module_result.v1",
          invocation_id: "invocation://rust-live/workspace.status",
          status: "success",
          receipt_refs: ["receipt://rust-live/workspace.status"],
          artifact_refs: [],
          payload_refs: [],
          agentgres_operation_refs: [],
          state_root_after: null,
          resulting_head: null,
          workflow_projection: { status: "live" },
        },
        workload_result: {
          router_admission: {
            schema_version: "ioi.step_module_router_admission.v1",
            backend: "workload_grpc",
          },
          workload_observation: {
            tool: "workspace.status",
            result: {
              schema_version: "ioi.runtime.coding-tool-result.v1",
              workspace_root: "/tmp/workspace",
              git: { available: true },
              changed_files: [],
              counts: { changed: 0, untracked: 0, ignored: 0 },
              shell_fallback_used: false,
            },
          },
        },
      };
    },
  };
  const surface = createRuntimeCodingToolInvocationSurface({
    codingToolApprovalManifestForThread: () => null,
    codingToolBudgetPolicyForRequest: () => ({ status: "allowed" }),
    codingToolResultWithoutDrafts: (result = {}) => result,
    diagnosticsRepairContextForRequest: () => null,
    diagnosticsRepairContextForToolPack: () => null,
    codingToolResultEnvelopeForThread: planCodingToolResultEnvelopeForTest,
    daemonCoreWorkloadApi: workloadApiFromRunner(liveRunner),
  });
  const store = createStore();

  assert.throws(
    () =>
      surface.invokeThreadTool(store, "thread_alpha", "workspace.status", {
        tool_call_id: "tool_status_core_required",
        workflow_graph_id: "graph_alpha",
        workflow_node_id: "node_status",
        input: {},
      }),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "runtime_coding_tool_invocation_rust_core_required");
      assert.equal(error.details.rust_core_boundary, "runtime.coding_tool_invocation");
      assert.equal(error.details.operation, "coding_tool_result_event_admission");
      assert.equal(error.details.operation_kind, "runtime.coding_tool_result_event");
      assert.equal(error.details.thread_id, "thread_alpha");
      assert.equal(error.details.tool_name, "workspace.status");
      assert.equal(error.details.tool_call_id, "tool_status_core_required");
      assert.deepEqual(error.details.evidence_refs, [
        "coding_tool_result_event_js_append_retired",
        "rust_daemon_core_coding_tool_result_event_admission_required",
        "agentgres_coding_tool_expected_head_required",
      ]);
      assertNoRetiredInvocationErrorDetailAliases(error.details);
      return true;
    },
  );
  assert.equal(store.events.length, 0);
});

test("coding tool invocation surface ignores local idempotency cache before Rust execution", () => {
  const surface = createSurface();
  const store = createStore();
  const duplicateEvent = { event_id: "event_duplicate", payload_summary: { status: "completed" } };
  store.idempotency.set("thread:thread_alpha:coding-tool:tool_alpha", duplicateEvent);

  assert.throws(
    () =>
      surface.invokeThreadTool(store, "thread_alpha", "file.inspect", {
        tool_call_id: "tool_alpha",
      }),
    (error) => {
      assert.equal(error.code, "runtime_coding_tool_workload_rust_core_required");
      assert.equal(error.details.tool_call_id, "tool_alpha");
      return true;
    },
  );
  assert.ok(!store.calls.some((call) => call.name === "runtimeEventStream"));
});

test("coding tool invocation surface ignores retired request identity aliases", () => {
  const runnerCalls = [];
  const liveRunner = {
    backend: "rust_workload_live",
    blocksDaemonJsExecution: true,
    runCodingTool(input) {
      runnerCalls.push(input);
      return {
        backend: "rust_workload_live",
        mode: "live",
        blocking: true,
        source: "rust_workload_api",
        invocation: {
          schema_version: "ioi.step_module_invocation.v1",
          invocation_id: "invocation://rust-live/workspace.status",
        },
        result: {
          schema_version: "ioi.step_module_result.v1",
          invocation_id: "invocation://rust-live/workspace.status",
          status: "success",
          receipt_refs: ["receipt://rust-live/workspace.status"],
          artifact_refs: [],
          payload_refs: [],
          agentgres_operation_refs: [],
          state_root_after: null,
          resulting_head: null,
          workflow_projection: {
            workflow_graph_id: input.context.workflow_graph_id,
            workflow_node_id: input.context.workflow_node_id,
            component_kind: "CodingToolNode",
            status: "live",
            attempt_id: "attempt://rust-live/workspace.status",
            evidence_refs: [],
            receipt_refs: ["receipt://rust-live/workspace.status"],
          },
        },
        workload_result: {
          router_admission: {
            schema_version: "ioi.step_module_router_admission.v1",
            backend: "workload_grpc",
          },
          workload_observation: {
            tool: "workspace.status",
            result: {
              schema_version: "ioi.runtime.coding-tool-result.v1",
              workspace_root: "/tmp/workspace",
              git: { available: true },
              changed_files: [],
              counts: { changed: 0, untracked: 0, ignored: 0 },
              shell_fallback_used: false,
            },
          },
        },
      };
    },
  };
  const surface = createSurface({ daemonCoreWorkloadApi: workloadApiFromRunner(liveRunner) });
  const store = createStore();

  const result = surface.invokeThreadTool(store, "thread_alpha", "workspace.status", {
    tool_call_id: "tool_status_alias_retired",
    toolCallId: "tool_status_legacy",
    turnId: "turn_retired",
    workflowGraphId: "graph_retired",
    workflowNodeId: "node_retired",
    idempotencyKey: "coding_tool_idempotency_retired",
    input: {},
  });

  assert.equal(runnerCalls.length, 1);
  assert.equal(runnerCalls[0].context.task_id, "task:turn_latest");
  assert.equal(runnerCalls[0].context.workflow_graph_id, null);
  assert.equal(runnerCalls[0].context.workflow_node_id, "runtime.coding-tool.workspace.status");
  assert.equal(result.turn_id, "turn_latest");
  assert.equal(result.workflow_graph_id, null);
  assert.equal(result.workflow_node_id, "runtime.coding-tool.workspace.status");
  assert.equal(result.event.turn_id, "turn_latest");
  assert.equal(result.event.workflow_graph_id, null);
  assert.equal(result.event.workflow_node_id, "runtime.coding-tool.workspace.status");
  assert.equal(result.event.idempotency_key, "thread:thread_alpha:coding-tool:tool_status_alias_retired");
});

test("coding tool invocation surface accepts canonical idempotency key", () => {
  const liveRunner = {
    backend: "rust_workload_live",
    blocksDaemonJsExecution: true,
    runCodingTool() {
      return {
        backend: "rust_workload_live",
        mode: "live",
        blocking: true,
        source: "rust_workload_api",
        invocation: {
          schema_version: "ioi.step_module_invocation.v1",
          invocation_id: "invocation://rust/workspace.status",
        },
        result: {
          schema_version: "ioi.step_module_result.v1",
          status: "success",
          receipt_refs: ["receipt_step"],
          artifact_refs: [],
          payload_refs: [],
          agentgres_operation_refs: [],
          state_root_after: null,
          resulting_head: null,
          workflow_projection: { status: "accepted" },
          router_admission: {
            schema_version: "ioi.step_module_router_admission.v1",
            backend: "workload_grpc",
          },
        },
      };
    },
  };
  const surface = createSurface({ daemonCoreWorkloadApi: workloadApiFromRunner(liveRunner) });
  const store = createStore();

  const result = surface.invokeThreadTool(store, "thread_alpha", "workspace.status", {
    tool_call_id: "tool_status_canonical",
    idempotency_key: "coding_tool_idempotency_canonical",
    input: {},
  });

  assert.equal(result.event.idempotency_key, "coding_tool_idempotency_canonical");
});

test("coding tool invocation surface returns canonical failed result when rust live runner fails", () => {
  const liveRunner = {
    backend: "rust_workload_live",
    blocksDaemonJsExecution: true,
    runCodingTool() {
      const error = new Error("runner unavailable");
      error.code = "rust_live_runner_unavailable";
      error.details = {
        reason: "fixture",
        schemaVersion: "retired.error.schema",
        toolName: "retired.workspace.status",
      };
      throw error;
    },
  };
  const surface = createSurface({ daemonCoreWorkloadApi: workloadApiFromRunner(liveRunner) });
  const store = createStore();

  const result = surface.invokeThreadTool(store, "thread_alpha", "workspace.status", {
        tool_call_id: "tool_status_execution_failed",
    input: {},
  });

  assert.equal(result.status, "failed");
  assert.equal(result.result.schema_version, "ioi.runtime.coding-tool-result.v1");
  assert.equal(result.result.tool_name, "workspace.status");
  assert.equal(result.result.status, "failed");
  assert.equal(result.result.error.code, "rust_live_runner_unavailable");
  assert.equal(Object.hasOwn(result.result, "schemaVersion"), false);
  assert.equal(Object.hasOwn(result.result, "toolName"), false);
  assert.equal(result.event.event_kind, "tool.failed");
  assert.equal(result.event.payload_summary.result.schema_version, "ioi.runtime.coding-tool-result.v1");
  assert.equal(result.event.payload_summary.result.tool_name, "workspace.status");
  assert.equal(Object.hasOwn(result.event.payload_summary.result, "schemaVersion"), false);
  assert.equal(Object.hasOwn(result.event.payload_summary.result, "toolName"), false);
});

test("coding tool invocation surface runs workspace.status through rust workload live path", () => {
  const runnerCalls = [];
  const liveRunner = {
    backend: "rust_workload_live",
    blocksDaemonJsExecution: true,
    runCodingTool(input) {
      runnerCalls.push(input);
      return {
        backend: "rust_workload_live",
        mode: "live",
        blocking: true,
        source: "rust_workload_api",
        invocation: {
          schema_version: "ioi.step_module_invocation.v1",
          invocation_id: "invocation://rust-live/workspace.status",
        },
        result: {
          schema_version: "ioi.step_module_result.v1",
          invocation_id: "invocation://rust-live/workspace.status",
          status: "success",
          execution_result_ref: "result://rust-live/workspace.status",
          normalized_observation_ref: "observation://rust-live/workspace.status",
          receipt_refs: ["receipt://rust-live/workspace.status"],
          artifact_refs: [],
          payload_refs: [],
          agentgres_operation_refs: [],
          state_root_after: null,
          resulting_head: null,
          workflow_projection: {
            workflow_graph_id: "graph_alpha",
            workflow_node_id: "node_status",
            component_kind: "CodingToolNode",
            status: "live",
            attempt_id: "attempt://rust-live/workspace.status",
            evidence_refs: [],
            receipt_refs: ["receipt://rust-live/workspace.status"],
          },
          next: {
            model_reentry_required: false,
            verifier_required: false,
          },
        },
        workload_result: {
          router_admission: {
            schema_version: "ioi.step_module_router_admission.v1",
            backend: "workload_grpc",
          },
          workload_observation: {
            tool: "workspace.status",
            result: {
              schemaVersion: "retired.result.schema",
              toolName: "retired.workspace.status",
              workspaceRoot: "/tmp/workspace",
              schema_version: "ioi.runtime.coding-tool-result.v1",
              workspace_root: "/tmp/workspace",
              git: {
                available: true,
                branch: "main",
                porcelainHash: "abc123",
                porcelain_hash: "abc123",
              },
              changedFiles: [{ status: "M", path: "README.md" }],
              changed_files: [{ status: "M", path: "README.md" }],
              counts: { changed: 1, untracked: 0, ignored: 0 },
              artifactRefs: ["artifact://retired/workspace.status"],
              executionResultRef: "result://retired/workspace.status",
              normalizedObservationRef: "observation://retired/workspace.status",
              receiptRefs: ["receipt://retired/workspace.status"],
              rustWorkload: false,
              shellFallbackUsed: false,
              stepModuleBackend: "daemon_js",
            },
          },
        },
      };
    },
  };
  const surface = createSurface({
    daemonCoreWorkloadApi: workloadApiFromRunner(liveRunner),
  });
  const store = createStore();

  const result = surface.invokeThreadTool(store, "thread_alpha", "workspace.status", {
    tool_call_id: "tool_status",
    workflowGraphId: "graph_alpha",
    workflowNodeId: "node_status",
    rollback_refs: ["rollback_canonical"],
    rollbackRefs: ["rollback_retired"],
    input: { includeIgnored: true },
  });

  assert.equal(result.status, "completed");
  assert.equal(runnerCalls.length, 1);
  assert.equal(runnerCalls[0].context.schema_version, "ioi.runtime.coding-tool-step-module-request.v1");
  assert.equal(Object.hasOwn(runnerCalls[0].context, "workflow_projection_status"), false);
  assert.equal(result.result.rust_workload, true);
  assert.equal(result.result.git.available, true);
  assert.equal(result.result.git.branch, "main");
  assert.deepEqual(result.result.changed_files, [{ status: "M", path: "README.md" }]);
  assert.equal(result.result.counts.changed, 1);
  assert.equal(result.result.schema_version, "ioi.runtime.coding-tool-result.v1");
  assert.equal(result.result.tool_name, "workspace.status");
  assert.equal(result.result.execution_result_ref, "result://rust-live/workspace.status");
  assert.equal(result.result.router_admission.schema_version, "ioi.step_module_router_admission.v1");
  assert.equal(result.result.observation.tool, "workspace.status");
  assert.equal(Object.hasOwn(result.step_module.workload_result, "workload_observation"), true);
  assert.equal(Object.hasOwn(result.step_module.workload_result, "shadow_observation"), false);
  assert.equal(Object.hasOwn(result.result, "routerAdmission"), false);
  assert.equal(Object.hasOwn(result.result, "schemaVersion"), false);
  assert.equal(Object.hasOwn(result.result, "toolName"), false);
  assert.equal(Object.hasOwn(result.result, "workspaceRoot"), false);
  assert.equal(Object.hasOwn(result.result, "rustWorkload"), false);
  assert.equal(Object.hasOwn(result.result, "stepModuleBackend"), false);
  assert.equal(Object.hasOwn(result.result, "executionResultRef"), false);
  assert.equal(Object.hasOwn(result.result, "normalizedObservationRef"), false);
  assert.equal(Object.hasOwn(result.result, "receiptRefs"), false);
  assert.equal(Object.hasOwn(result.result, "artifactRefs"), false);
  assert.equal(Object.hasOwn(result.result, "shellFallbackUsed"), false);
  assert.equal(Object.hasOwn(result.result, "changedFiles"), false);
  assert.equal(Object.hasOwn(result.result.git, "porcelainHash"), false);
  assert.equal(result.step_module.backend, "rust_workload_live");
  assert.equal(result.event.created_at, "rust_daemon_core");
  assert.equal(result.event.state_root_after, "sha256:after-1");
  assert.equal(result.event.resulting_head, "agentgres://runtime-events/thread_alpha_events/head/after-1");
  assert.equal(result.event.payload_summary.step_module_backend, "rust_workload_live");
  assert.equal(result.event.payload_summary.approval_required, false);
  assert.deepEqual(result.event.rollback_refs, ["rollback_canonical"]);
  assert.equal(result.event.rollback_refs.includes("rollback_retired"), false);
  for (const field of [
    "approvalRequired",
    "approvalSatisfied",
    "approvalId",
    "approvalManifest",
    "approvalDecisionEventId",
    "diagnosticsRepairContext",
  ]) {
    assert.equal(Object.hasOwn(result.event.payload_summary, field), false);
  }
  assert.ok(result.receipt_refs.includes("receipt://rust-live/workspace.status"));
  assert.ok(store.calls.some((call) => call.name === "rustResultEventAdmission"));
  assert.ok(store.calls.some((call) => call.name === "registerRuntimeEvent"));
  assert.ok(!store.calls.some((call) => call.name === "materializeArtifacts"));
});

test("coding tool invocation surface runs file.inspect through rust workload live path", () => {
  const runnerCalls = [];
  const liveRunner = {
    backend: "rust_workload_live",
    blocksDaemonJsExecution: true,
    runCodingTool(input) {
      runnerCalls.push(input);
      return {
        backend: "rust_workload_live",
        mode: "live",
        blocking: true,
        source: "rust_workload_api",
        invocation: {
          schema_version: "ioi.step_module_invocation.v1",
          invocation_id: "invocation://rust-live/file.inspect",
        },
        result: {
          schema_version: "ioi.step_module_result.v1",
          invocation_id: "invocation://rust-live/file.inspect",
          status: "success",
          execution_result_ref: "result://rust-live/file.inspect",
          normalized_observation_ref: "observation://rust-live/file.inspect",
          receipt_refs: ["receipt://rust-live/file.inspect"],
          artifact_refs: [],
          payload_refs: [],
          agentgres_operation_refs: [],
          state_root_after: null,
          resulting_head: null,
          workflow_projection: {
            workflow_graph_id: "graph_alpha",
            workflow_node_id: "node_inspect",
            component_kind: "FilesystemToolNode",
            status: "live",
            attempt_id: "attempt://rust-live/file.inspect",
            evidence_refs: [],
            receipt_refs: ["receipt://rust-live/file.inspect"],
          },
          next: {
            model_reentry_required: false,
            verifier_required: false,
          },
        },
        workload_result: {
          router_admission: {
            schema_version: "ioi.step_module_router_admission.v1",
            backend: "workload_grpc",
          },
          workload_observation: {
            tool: "file.inspect",
            result: {
              schema_version: "ioi.runtime.coding-tool-result.v1",
              workspace_root: "/tmp/workspace",
              path: "README.md",
              kind: "file",
              exists: true,
              size_bytes: 42,
              preview: "# IOI",
              preview_bytes: 5,
              preview_hash: "sha256:test",
              truncated: false,
              preview_line_count: 1,
              shell_fallback_used: false,
            },
          },
        },
      };
    },
  };
  const surface = createSurface({
    daemonCoreWorkloadApi: workloadApiFromRunner(liveRunner),
  });
  const store = createStore();

  const result = surface.invokeThreadTool(store, "thread_alpha", "file.inspect", {
    tool_call_id: "tool_inspect",
    workflowGraphId: "graph_alpha",
    workflowNodeId: "node_inspect",
    input: { path: "README.md" },
  });

  assert.equal(result.status, "completed");
  assert.equal(runnerCalls.length, 1);
  assert.equal(runnerCalls[0].context.schema_version, "ioi.runtime.coding-tool-step-module-request.v1");
  assert.equal(Object.hasOwn(runnerCalls[0].context, "workflow_projection_status"), false);
  assert.equal(result.result.rust_workload, true);
  assert.equal(result.result.path, "README.md");
  assert.equal(result.result.kind, "file");
  assert.equal(result.result.size_bytes, 42);
  assert.equal(Object.hasOwn(result.result, "sizeBytes"), false);
  assert.equal(Object.hasOwn(result.result, "previewHash"), false);
  assert.equal(result.step_module.backend, "rust_workload_live");
  assert.ok(result.receipt_refs.includes("receipt://rust-live/file.inspect"));
  assert.ok(!store.calls.some((call) => call.name === "materializeArtifacts"));
});

test("coding tool invocation surface runs git.diff through rust workload live path", () => {
  const runnerCalls = [];
  const liveRunner = {
    backend: "rust_workload_live",
    blocksDaemonJsExecution: true,
    runCodingTool(input) {
      runnerCalls.push(input);
      return {
        backend: "rust_workload_live",
        mode: "live",
        blocking: true,
        source: "rust_workload_api",
        invocation: {
          schema_version: "ioi.step_module_invocation.v1",
          invocation_id: "invocation://rust-live/git.diff",
        },
        result: {
          schema_version: "ioi.step_module_result.v1",
          invocation_id: "invocation://rust-live/git.diff",
          status: "success",
          execution_result_ref: "result://rust-live/git.diff",
          normalized_observation_ref: "observation://rust-live/git.diff",
          receipt_refs: ["receipt://rust-live/git.diff"],
          artifact_refs: [],
          payload_refs: [],
          agentgres_operation_refs: [],
          state_root_after: null,
          resulting_head: null,
          workflow_projection: {
            workflow_graph_id: "graph_alpha",
            workflow_node_id: "node_diff",
            component_kind: "GitToolNode",
            status: "live",
            attempt_id: "attempt://rust-live/git.diff",
            evidence_refs: [],
            receipt_refs: ["receipt://rust-live/git.diff"],
          },
          next: {
            model_reentry_required: false,
            verifier_required: false,
          },
        },
        workload_result: {
          router_admission: {
            schema_version: "ioi.step_module_router_admission.v1",
            backend: "workload_grpc",
          },
          workload_observation: {
            tool: "git.diff",
            result: {
              schema_version: "ioi.runtime.coding-tool-result.v1",
              workspace_root: "/tmp/workspace",
              paths: ["README.md"],
              git: { available: true },
              diff: "diff --git a/README.md b/README.md",
              diffBytes: 128,
              diffHash: "abc123",
              diff_bytes: 128,
              diff_hash: "abc123",
              truncated: false,
              stat: " README.md | 1 +",
              artifactDrafts: [{ channel: "retired", content: "retired draft" }],
              artifact_drafts: [{ channel: "stdout", content: "canonical diff draft" }],
              shell_fallback_used: false,
            },
          },
        },
      };
    },
  };
  const surface = createSurface({
    daemonCoreWorkloadApi: workloadApiFromRunner(liveRunner),
  });
  const store = createStore();

  const result = surface.invokeThreadTool(store, "thread_alpha", "git.diff", {
    tool_call_id: "tool_diff",
    workflowGraphId: "graph_alpha",
    workflowNodeId: "node_diff",
    input: { path: "README.md" },
  });

  assert.equal(result.status, "completed");
  assert.equal(runnerCalls.length, 1);
  assert.equal(runnerCalls[0].context.schema_version, "ioi.runtime.coding-tool-step-module-request.v1");
  assert.equal(Object.hasOwn(runnerCalls[0].context, "workflow_projection_status"), false);
  assert.equal(result.result.rust_workload, true);
  assert.deepEqual(result.result.paths, ["README.md"]);
  assert.equal(result.result.diff_hash, "abc123");
  assert.equal(Object.hasOwn(result.result, "diffHash"), false);
  assert.equal(result.step_module.backend, "rust_workload_live");
  assert.ok(result.receipt_refs.includes("receipt://rust-live/git.diff"));
  const materializeCall = store.calls.find((call) => call.name === "materializeArtifacts");
  assert.ok(materializeCall);
  assert.equal(Object.hasOwn(materializeCall.input.result, "artifactDrafts"), false);
  assert.equal(materializeCall.input.result.artifact_drafts[0].content, "canonical diff draft");
  assert.equal(Object.hasOwn(result.result, "artifactDrafts"), false);
  assert.equal(Object.hasOwn(result.result, "artifact_drafts"), false);
});

test("coding tool invocation surface runs lsp.diagnostics through rust workload live path", () => {
  const runnerCalls = [];
  const liveRunner = {
    backend: "rust_workload_live",
    blocksDaemonJsExecution: true,
    runCodingTool(input) {
      runnerCalls.push(input);
      return {
        backend: "rust_workload_live",
        mode: "live",
        blocking: true,
        source: "rust_workload_api",
        invocation: {
          schema_version: "ioi.step_module_invocation.v1",
          invocation_id: "invocation://rust-live/lsp.diagnostics",
        },
        result: {
          schema_version: "ioi.step_module_result.v1",
          invocation_id: "invocation://rust-live/lsp.diagnostics",
          status: "success",
          execution_result_ref: "result://rust-live/lsp.diagnostics",
          normalized_observation_ref: "observation://rust-live/lsp.diagnostics",
          receipt_refs: ["receipt://rust-live/lsp.diagnostics"],
          artifact_refs: [],
          payload_refs: [],
          agentgres_operation_refs: [],
          state_root_after: null,
          resulting_head: null,
          workflow_projection: {
            workflow_graph_id: "graph_alpha",
            workflow_node_id: "node_diagnostics",
            component_kind: "LspDiagnosticsNode",
            status: "live",
            attempt_id: "attempt://rust-live/lsp.diagnostics",
            evidence_refs: [],
            receipt_refs: ["receipt://rust-live/lsp.diagnostics"],
          },
          next: {
            model_reentry_required: false,
            verifier_required: false,
          },
        },
        workload_result: {
          router_admission: {
            schema_version: "ioi.step_module_router_admission.v1",
            backend: "workload_grpc",
          },
          workload_observation: {
            tool: "lsp.diagnostics",
            result: {
              schema_version: "ioi.runtime.coding-tool-result.v1",
              workspace_root: "/tmp/workspace",
              command_id: "node.check",
              requested_command_id: "node.check",
              resolved_command_id: "node.check",
              command: "node --check",
              cwd: ".",
              backend: "node.check",
              backend_status: "available",
              backend_reason: null,
              fallback_used: false,
              fallback_from: null,
              project_context: {
                schema_version: "ioi.runtime.diagnostics-project-context.v1",
                cwd: ".",
                paths: ["src/index.mjs"],
              },
              diagnostic_status: "clean",
              diagnostics: [],
              diagnostic_count: 0,
              paths: ["src/index.mjs"],
              exit_code: 0,
              timed_out: false,
              duration_ms: 12,
              timeout_ms: 30000,
              stdout: "",
              stderr: "",
              output_bytes: 0,
              output_hash: "abc123",
              truncated: false,
              spillover_recommended: false,
              artifact_drafts: [],
              allowed_command_ids: ["auto", "node.check", "typescript.check"],
              shell_fallback_used: false,
            },
          },
        },
      };
    },
  };
  const surface = createSurface({
    daemonCoreWorkloadApi: workloadApiFromRunner(liveRunner),
  });
  const store = createStore();

  const result = surface.invokeThreadTool(store, "thread_alpha", "lsp.diagnostics", {
    tool_call_id: "tool_diagnostics",
    workflowGraphId: "graph_alpha",
    workflowNodeId: "node_diagnostics",
    input: { commandId: "node.check", path: "src/index.mjs" },
  });

  assert.equal(result.status, "completed");
  assert.equal(runnerCalls.length, 1);
  assert.equal(runnerCalls[0].context.schema_version, "ioi.runtime.coding-tool-step-module-request.v1");
  assert.equal(Object.hasOwn(runnerCalls[0].context, "workflow_projection_status"), false);
  assert.equal(result.result.rust_workload, true);
  assert.equal(result.result.backend, "node.check");
  assert.equal(result.result.diagnostic_status, "clean");
  assert.equal(result.result.diagnostic_count, 0);
  assert.deepEqual(result.result.paths, ["src/index.mjs"]);
  assert.equal(Object.hasOwn(result.result, "diagnosticStatus"), false);
  assert.equal(Object.hasOwn(result.result, "diagnosticCount"), false);
  assert.equal(Object.hasOwn(result.result, "projectContext"), false);
  assert.equal(result.step_module.backend, "rust_workload_live");
  assert.ok(result.receipt_refs.includes("receipt://rust-live/lsp.diagnostics"));
  assert.ok(!store.calls.some((call) => call.name === "materializeArtifacts"));
});

test("coding tool invocation surface runs test.run through rust workload live path", () => {
  const runnerCalls = [];
  const liveRunner = {
    backend: "rust_workload_live",
    blocksDaemonJsExecution: true,
    runCodingTool(input) {
      runnerCalls.push(input);
      return {
        backend: "rust_workload_live",
        mode: "live",
        blocking: true,
        source: "rust_workload_api",
        invocation: {
          schema_version: "ioi.step_module_invocation.v1",
          invocation_id: "invocation://rust-live/test.run",
        },
        result: {
          schema_version: "ioi.step_module_result.v1",
          invocation_id: "invocation://rust-live/test.run",
          status: "success",
          execution_result_ref: "result://rust-live/test.run",
          normalized_observation_ref: "observation://rust-live/test.run",
          receipt_refs: ["receipt://rust-live/test.run"],
          artifact_refs: [],
          payload_refs: [],
          agentgres_operation_refs: [],
          state_root_after: null,
          resulting_head: null,
          workflow_projection: {
            workflow_graph_id: "graph_alpha",
            workflow_node_id: "node_test",
            component_kind: "TestRunNode",
            status: "live",
            attempt_id: "attempt://rust-live/test.run",
            evidence_refs: [],
            receipt_refs: ["receipt://rust-live/test.run"],
          },
          next: {
            model_reentry_required: false,
            verifier_required: false,
          },
        },
        workload_result: {
          router_admission: {
            schema_version: "ioi.step_module_router_admission.v1",
            backend: "workload_grpc",
          },
          workload_observation: {
            tool: "test.run",
            result: {
              schema_version: "ioi.runtime.coding-tool-result.v1",
              workspace_root: "/tmp/workspace",
              command_id: "node.test",
              command: "node --test",
              executable: "node",
              args: ["--test", "src/index.test.mjs"],
              cwd: ".",
              exit_code: 0,
              signal: null,
              test_status: "passed",
              timed_out: false,
              duration_ms: 18,
              timeout_ms: 60000,
              stdout: "ok 1 - passes",
              stderr: "",
              stdout_bytes: 13,
              stderr_bytes: 0,
              output_bytes: 13,
              output_hash: "abc123",
              truncated: false,
              spillover_recommended: false,
              artifact_drafts: [],
              allowed_command_ids: ["node.test", "npm.test", "cargo.test", "cargo.check"],
              shell_fallback_used: false,
            },
          },
        },
      };
    },
  };
  const surface = createSurface({
    daemonCoreWorkloadApi: workloadApiFromRunner(liveRunner),
  });
  const store = createStore();

  const result = surface.invokeThreadTool(store, "thread_alpha", "test.run", {
    tool_call_id: "tool_test",
    workflowGraphId: "graph_alpha",
    workflowNodeId: "node_test",
    input: { commandId: "node.test", path: "src/index.test.mjs" },
  });

  assert.equal(result.status, "completed");
  assert.equal(runnerCalls.length, 1);
  assert.equal(runnerCalls[0].context.schema_version, "ioi.runtime.coding-tool-step-module-request.v1");
  assert.equal(Object.hasOwn(runnerCalls[0].context, "workflow_projection_status"), false);
  assert.equal(result.result.rust_workload, true);
  assert.equal(result.result.command_id, "node.test");
  assert.equal(result.result.test_status, "passed");
  assert.equal(result.result.exit_code, 0);
  assert.equal(Object.hasOwn(result.result, "commandId"), false);
  assert.equal(Object.hasOwn(result.result, "testStatus"), false);
  assert.equal(Object.hasOwn(result.result, "exitCode"), false);
  assert.deepEqual(result.result.args, ["--test", "src/index.test.mjs"]);
  assert.equal(result.step_module.backend, "rust_workload_live");
  assert.ok(result.receipt_refs.includes("receipt://rust-live/test.run"));
  assert.ok(!store.calls.some((call) => call.name === "materializeArtifacts"));
});

test("coding tool invocation surface runs file.apply_patch through rust workload live path", () => {
  const runnerCalls = [];
  const liveRunner = {
    backend: "rust_workload_live",
    blocksDaemonJsExecution: true,
    runCodingTool(input) {
      runnerCalls.push(input);
      return {
        backend: "rust_workload_live",
        mode: "live",
        blocking: true,
        source: "rust_workload_api",
        invocation: {
          schema_version: "ioi.step_module_invocation.v1",
          invocation_id: "invocation://rust-live/file.apply_patch",
        },
        result: {
          schema_version: "ioi.step_module_result.v1",
          invocation_id: "invocation://rust-live/file.apply_patch",
          status: "success",
          execution_result_ref: "result://rust-live/file.apply_patch",
          normalized_observation_ref: "observation://rust-live/file.apply_patch",
          receipt_refs: ["receipt://rust-live/file.apply_patch"],
          artifact_refs: [],
          payload_refs: ["payload://workspace/file.apply_patch/README.md/after"],
          agentgres_operation_refs: ["agentgres://operation/file.apply_patch/README.md/after"],
          state_root_after: "state://workspace/README.md/after",
          resulting_head: "head://workspace/README.md/after",
          workflow_projection: {
            workflow_graph_id: "graph_alpha",
            workflow_node_id: "node_patch",
            component_kind: "FilesystemPatchNode",
            status: "live",
            attempt_id: "attempt://rust-live/file.apply_patch",
            evidence_refs: ["evidence://agentgres/file.apply_patch"],
            receipt_refs: ["receipt://rust-live/file.apply_patch"],
          },
          next: {
            model_reentry_required: false,
            verifier_required: false,
          },
        },
        workload_result: {
          router_admission: {
            schema_version: "ioi.step_module_router_admission.v1",
            backend: "workload_grpc",
            authoritative_transition: true,
          },
          agentgres_admission: {
            schema_version: "ioi.agentgres_admission.v1",
            operation_ref: "agentgres://operation/file.apply_patch/README.md/after",
            state_root_after: "state://workspace/README.md/after",
            resulting_head: "head://workspace/README.md/after",
          },
          workload_observation: {
            tool: "file.apply_patch",
            result: {
              schema_version: "ioi.runtime.coding-tool-result.v1",
              workspace_root: "/tmp/workspace",
              path: "README.md",
              dry_run: false,
              applied: true,
              changed: true,
              created: false,
              edit_count: 1,
              edits: [{ type: "replace", occurrence: "only", matches: 1 }],
              before_hash: "beforehash",
              after_hash: "afterhash",
              diff: "--- a/README.md\n+++ b/README.md",
              diff_bytes: 32,
              diff_hash: "diffhash",
              truncated: false,
              changed_files: [
                {
                  path: "README.md",
                  before_hash: "beforehash",
                  after_hash: "afterhash",
                  before_exists: true,
                  after_exists: true,
                  before_size_bytes: 7,
                  after_size_bytes: 6,
                  before_mtime_ms: 1,
                  after_mtime_ms: 2,
                  created: false,
                  diagnostics_recommended: true,
                },
              ],
              workspace_snapshot_drafts: [
                {
                  path: "README.md",
                  encoding: "utf8",
                  before_exists: true,
                  after_exists: true,
                  before_content: "before\n",
                  after_content: "after\n",
                },
              ],
              diagnostics_recommended: true,
              receipt_refs: ["receipt_file_apply_patch_README.md_after"],
              payload_refs: ["payload://workspace/file.apply_patch/README.md/after"],
              shell_fallback_used: false,
            },
          },
        },
      };
    },
  };
  const surface = createSurface({
    daemonCoreWorkloadApi: workloadApiFromRunner(liveRunner),
  });
  const store = createStore();

  const result = surface.invokeThreadTool(store, "thread_alpha", "file.apply_patch", {
    tool_call_id: "tool_patch",
    workflowGraphId: "graph_alpha",
    workflowNodeId: "node_patch",
    input: { path: "README.md", oldText: "before", newText: "after" },
  });

  assert.equal(result.status, "completed");
  assert.equal(runnerCalls.length, 1);
  assert.equal(runnerCalls[0].context.schema_version, "ioi.runtime.coding-tool-step-module-request.v1");
  assert.equal(Object.hasOwn(runnerCalls[0].context, "workflow_projection_status"), false);
  assert.equal(result.result.rust_workload, true);
  assert.equal(result.result.applied, true);
  assert.equal(result.result.edit_count, 1);
  assert.equal(result.result.diff_hash, "diffhash");
  assert.equal(result.result.workspace_snapshot_id, "snapshot_alpha");
  assert.equal(Object.hasOwn(result.result, "workspaceSnapshot"), false);
  assert.equal(Object.hasOwn(result.result, "workspaceSnapshotId"), false);
  assert.equal(Object.hasOwn(result.result, "schemaVersion"), false);
  assert.equal(Object.hasOwn(result.result, "workspaceRoot"), false);
  assert.equal(Object.hasOwn(result.result, "dryRun"), false);
  assert.equal(Object.hasOwn(result.result, "editCount"), false);
  assert.equal(Object.hasOwn(result.result, "beforeHash"), false);
  assert.equal(Object.hasOwn(result.result, "afterHash"), false);
  assert.equal(Object.hasOwn(result.result, "diffHash"), false);
  assert.equal(Object.hasOwn(result.result, "receiptRefs"), false);
  assert.equal(Object.hasOwn(result.result, "payloadRefs"), false);
  assert.equal(Object.hasOwn(result.result, "shellFallbackUsed"), false);
  assert.ok(result.receipt_refs.includes("receipt://rust-live/file.apply_patch"));
  assert.ok(result.receipt_refs.includes("receipt_snapshot"));
  assert.ok(result.artifact_refs.includes("artifact_snapshot"));
  assert.equal(result.workspace_snapshot.snapshot_id, "snapshot_alpha");
  assert.equal(result.workspace_snapshot_event.event_id, "event_snapshot");
  assert.equal(result.auto_diagnostics.status, "completed");
  for (const field of [
    "workspaceSnapshot",
    "workspaceSnapshotEvent",
    "autoDiagnostics",
    "stepModule",
    "stepModuleError",
    "commandStreamEvents",
  ]) {
    assert.equal(Object.hasOwn(result, field), false);
  }
	  assert.equal(result.step_module.result.agentgres_operation_refs[0], "agentgres://operation/file.apply_patch/README.md/after");
	  assert.ok(store.calls.some((call) => call.name === "prepareSnapshot"));
	  assert.ok(!store.calls.some((call) => call.name === "appendSnapshotEvent"));
	  assert.ok(!store.calls.some((call) => call.name === "materializeArtifacts"));

	  const retiredSnapshotStore = createStore({
	    onPrepareSnapshot() {
	      const error = new Error("Runtime workspace snapshot and restore mutation requires direct Rust daemon-core admission and persistence.");
	      error.status = 501;
	      error.code = "runtime_workspace_snapshot_rust_core_required";
	      error.details = { rust_core_boundary: "runtime.workspace_snapshot" };
	      throw error;
	    },
	  });
	  const resultWithoutJsSnapshot = surface.invokeThreadTool(
	    retiredSnapshotStore,
	    "thread_alpha",
	    "file.apply_patch",
	    {
	      tool_call_id: "tool_patch_no_js_snapshot",
	      workflowGraphId: "graph_alpha",
	      workflowNodeId: "node_patch",
	      input: { path: "README.md", oldText: "before", newText: "after" },
	    },
	  );
	  assert.equal(resultWithoutJsSnapshot.status, "failed");
	  assert.equal(resultWithoutJsSnapshot.result.status, "failed");
	  assert.equal(
	    resultWithoutJsSnapshot.result.error.code,
	    "runtime_workspace_snapshot_rust_core_required",
	  );
	  assert.equal(resultWithoutJsSnapshot.workspace_snapshot, null);
	  assert.equal(resultWithoutJsSnapshot.workspace_snapshot_event, null);
	  assert.equal(
	    resultWithoutJsSnapshot.receipt_refs.includes("receipt_snapshot"),
	    false,
	  );
	  assert.ok(retiredSnapshotStore.calls.some((call) => call.name === "prepareSnapshot"));
	  assert.ok(!retiredSnapshotStore.calls.some((call) => call.name === "appendSnapshotEvent"));
	});

test("coding tool invocation surface runs artifact.read through rust workload live path", () => {
  const runnerCalls = [];
  const liveRunner = {
    backend: "rust_workload_live",
    blocksDaemonJsExecution: true,
    runCodingTool(input) {
      runnerCalls.push(input);
      const artifactResult = input.input.rust_workload_data_plane.result;
      return {
        backend: "rust_workload_live",
        mode: "live",
        blocking: true,
        source: "rust_workload_api",
        invocation: {
          schema_version: "ioi.step_module_invocation.v1",
          invocation_id: "invocation://rust-live/artifact.read",
        },
        result: {
          schema_version: "ioi.step_module_result.v1",
          invocation_id: "invocation://rust-live/artifact.read",
          status: "success",
          execution_result_ref: "result://rust-live/artifact.read",
          normalized_observation_ref: "observation://rust-live/artifact.read",
          receipt_refs: ["receipt://rust-live/artifact.read"],
          artifact_refs: artifactResult.artifact_refs,
          payload_refs: [],
          agentgres_operation_refs: [],
          state_root_after: null,
          resulting_head: null,
          workflow_projection: {
            workflow_graph_id: "graph_alpha",
            workflow_node_id: "node_artifact",
            component_kind: "ArtifactReadNode",
            status: "live",
            attempt_id: "attempt://rust-live/artifact.read",
            evidence_refs: ["evidence://rust-live/artifact.read"],
            receipt_refs: ["receipt://rust-live/artifact.read"],
          },
          next: {
            model_reentry_required: false,
            verifier_required: false,
          },
        },
        workload_result: {
          router_admission: {
            schema_version: "ioi.step_module_router_admission.v1",
            backend: "workload_grpc",
          },
          workload_observation: {
            tool: "artifact.read",
            result: {
              ...artifactResult,
              backend: "rust_artifact_read",
              data_plane_source: "daemon_artifact_store",
              shell_fallback_used: false,
            },
          },
        },
      };
    },
  };
  const surface = createSurface({
    daemonCoreWorkloadApi: workloadApiFromRunner(liveRunner),
  });
  const store = createStore();

  const result = surface.invokeThreadTool(store, "thread_alpha", "artifact.read", {
    tool_call_id: "tool_artifact",
    workflowGraphId: "graph_alpha",
    workflowNodeId: "node_artifact",
    input: { artifact_id: "artifact_alpha", offset_bytes: 2, length_bytes: 8 },
  });

  assert.equal(result.status, "completed");
  assert.equal(runnerCalls.length, 1);
  assert.equal(runnerCalls[0].context.schema_version, "ioi.runtime.coding-tool-step-module-request.v1");
  assert.equal(Object.hasOwn(runnerCalls[0].context, "workflow_projection_status"), false);
  assert.equal(runnerCalls[0].input.rust_workload_data_plane.schema_version, "ioi.runtime.coding-tool-data-plane.v1");
  assert.equal(runnerCalls[0].input.rust_workload_data_plane.source, "daemon_artifact_store");
  assert.equal(runnerCalls[0].input.rust_workload_data_plane.result.content, "stored artifact\n");
  assert.equal(Object.hasOwn(runnerCalls[0].input, "rustWorkloadDataPlane"), false);
  assert.equal(Object.hasOwn(runnerCalls[0].input.rust_workload_data_plane, "schemaVersion"), false);
  assert.ok(store.calls.some((call) => call.name === "readArtifact"));
  assert.equal(result.result.rust_workload, true);
  assert.equal(result.result.backend, "rust_artifact_read");
  assert.equal(result.result.artifact_id, "artifact_alpha");
  assert.equal(result.result.data_plane_source, "daemon_artifact_store");
  for (const field of ["artifactId", "dataPlaneSource", "shellFallbackUsed"]) {
    assert.equal(Object.hasOwn(result.result, field), false);
  }
  assert.ok(result.receipt_refs.includes("receipt://rust-live/artifact.read"));
  assert.ok(result.artifact_refs.includes("artifact_alpha"));
  assert.ok(!store.calls.some((call) => call.name === "materializeArtifacts"));

  const readCallsBeforeRetiredAlias = store.calls.filter((call) => call.name === "readArtifact").length;
  const retiredArtifactAlias = surface.invokeThreadTool(store, "thread_alpha", "artifact.read", {
    tool_call_id: "tool_artifact_retired",
    input: { artifactId: "artifact_alpha" },
  });
  assert.equal(retiredArtifactAlias.status, "failed");
  assert.equal(retiredArtifactAlias.result.error.code, "artifact_read_id_required");
  assert.equal(retiredArtifactAlias.result.error.details.thread_id, "thread_alpha");
  assert.equal(retiredArtifactAlias.result.error.details.tool_id, "artifact.read");
  assertNoRetiredInvocationErrorDetailAliases(retiredArtifactAlias.result.error.details);
  assert.equal(store.calls.filter((call) => call.name === "readArtifact").length, readCallsBeforeRetiredAlias);

  const retiredRangeAlias = surface.invokeThreadTool(store, "thread_alpha", "artifact.read", {
    tool_call_id: "tool_artifact_range_retired",
    input: { artifact_id: "artifact_alpha", offsetBytes: 2 },
  });
  assert.equal(retiredRangeAlias.status, "failed");
  assert.equal(retiredRangeAlias.result.error.code, "artifact_read_range_aliases_retired");
  assert.equal(retiredRangeAlias.result.error.details.thread_id, "thread_alpha");
  assert.equal(retiredRangeAlias.result.error.details.tool_id, "artifact.read");
  assert.deepEqual(retiredRangeAlias.result.error.details.retired_aliases, ["offsetBytes"]);
  assertNoRetiredInvocationErrorDetailAliases(retiredRangeAlias.result.error.details);
  assert.equal(Object.hasOwn(retiredRangeAlias.result.error.details, "offsetBytes"), false);
  assert.equal(store.calls.filter((call) => call.name === "readArtifact").length, readCallsBeforeRetiredAlias);
});

test("coding tool invocation surface runs tool.retrieve_result through rust workload live path", () => {
  const runnerCalls = [];
  const liveRunner = {
    backend: "rust_workload_live",
    blocksDaemonJsExecution: true,
    runCodingTool(input) {
      runnerCalls.push(input);
      const retrieveResult = input.input.rust_workload_data_plane.result;
      return {
        backend: "rust_workload_live",
        mode: "live",
        blocking: true,
        source: "rust_workload_api",
        invocation: {
          schema_version: "ioi.step_module_invocation.v1",
          invocation_id: "invocation://rust-live/tool.retrieve_result",
        },
        result: {
          schema_version: "ioi.step_module_result.v1",
          invocation_id: "invocation://rust-live/tool.retrieve_result",
          status: "success",
          execution_result_ref: "result://rust-live/tool.retrieve_result",
          normalized_observation_ref: "observation://rust-live/tool.retrieve_result",
          receipt_refs: ["receipt://rust-live/tool.retrieve_result"],
          artifact_refs: retrieveResult.artifact_refs,
          payload_refs: [],
          agentgres_operation_refs: [],
          state_root_after: null,
          resulting_head: null,
          workflow_projection: {
            workflow_graph_id: "graph_alpha",
            workflow_node_id: "node_retrieve",
            component_kind: "ToolRetrieveResultNode",
            status: "live",
            attempt_id: "attempt://rust-live/tool.retrieve_result",
            evidence_refs: ["evidence://rust-live/tool.retrieve_result"],
            receipt_refs: ["receipt://rust-live/tool.retrieve_result"],
          },
          next: {
            model_reentry_required: false,
            verifier_required: false,
          },
        },
        workload_result: {
          router_admission: {
            schema_version: "ioi.step_module_router_admission.v1",
            backend: "workload_grpc",
          },
          workload_observation: {
            tool: "tool.retrieve_result",
            result: {
              ...retrieveResult,
              backend: "rust_tool_result_retrieve",
              data_plane_source: "daemon_artifact_store",
              shell_fallback_used: false,
            },
          },
        },
      };
    },
  };
  const surface = createSurface({
    daemonCoreWorkloadApi: workloadApiFromRunner(liveRunner),
  });
  const store = createStore();

  const result = surface.invokeThreadTool(store, "thread_alpha", "tool.retrieve_result", {
    tool_call_id: "tool_retrieve",
    workflowGraphId: "graph_alpha",
    workflowNodeId: "node_retrieve",
    input: { tool_call_id: "tool_patch", channel: "stdout", max_bytes: 32 },
  });

  assert.equal(result.status, "completed");
  assert.equal(runnerCalls.length, 1);
  assert.equal(runnerCalls[0].context.schema_version, "ioi.runtime.coding-tool-step-module-request.v1");
  assert.equal(Object.hasOwn(runnerCalls[0].context, "workflow_projection_status"), false);
  assert.equal(runnerCalls[0].input.rust_workload_data_plane.schema_version, "ioi.runtime.coding-tool-data-plane.v1");
  assert.equal(runnerCalls[0].input.rust_workload_data_plane.query.tool_call_id, "tool_patch");
  assert.equal(runnerCalls[0].input.rust_workload_data_plane.result.content, "stored result\n");
  assert.equal(Object.hasOwn(runnerCalls[0].input, "rustWorkloadDataPlane"), false);
  assert.equal(Object.hasOwn(runnerCalls[0].input.rust_workload_data_plane, "schemaVersion"), false);
  assert.ok(store.calls.some((call) => call.name === "retrieveResult"));
  assert.equal(result.result.rust_workload, true);
  assert.equal(result.result.backend, "rust_tool_result_retrieve");
  assert.equal(result.result.tool_call_id, "tool_patch");
  assert.equal(result.result.data_plane_source, "daemon_artifact_store");
  for (const field of ["toolCallId", "dataPlaneSource", "shellFallbackUsed"]) {
    assert.equal(Object.hasOwn(result.result, field), false);
  }
  assert.ok(result.receipt_refs.includes("receipt://rust-live/tool.retrieve_result"));
  assert.ok(result.artifact_refs.includes("artifact_result"));
  assert.ok(!store.calls.some((call) => call.name === "materializeArtifacts"));

  const retrieveCallsBeforeRetiredAlias = store.calls.filter((call) => call.name === "retrieveResult").length;
  const retiredRetrieveAlias = surface.invokeThreadTool(store, "thread_alpha", "tool.retrieve_result", {
    tool_call_id: "tool_retrieve_retired",
    input: { toolCallId: "tool_patch" },
  });
  assert.equal(retiredRetrieveAlias.status, "failed");
  assert.equal(retiredRetrieveAlias.result.error.code, "tool_retrieve_result_target_required");
  assert.equal(retiredRetrieveAlias.result.error.details.thread_id, "thread_alpha");
  assert.equal(retiredRetrieveAlias.result.error.details.tool_id, "tool.retrieve_result");
  assertNoRetiredInvocationErrorDetailAliases(retiredRetrieveAlias.result.error.details);
  assert.equal(store.calls.filter((call) => call.name === "retrieveResult").length, retrieveCallsBeforeRetiredAlias);

  const retiredRetrieveRangeAlias = surface.invokeThreadTool(store, "thread_alpha", "tool.retrieve_result", {
    tool_call_id: "tool_retrieve_range_retired",
    input: { tool_call_id: "tool_patch", maxBytes: 32 },
  });
  assert.equal(retiredRetrieveRangeAlias.status, "failed");
  assert.equal(retiredRetrieveRangeAlias.result.error.code, "artifact_read_range_aliases_retired");
  assert.equal(retiredRetrieveRangeAlias.result.error.details.thread_id, "thread_alpha");
  assert.equal(retiredRetrieveRangeAlias.result.error.details.tool_id, "tool.retrieve_result");
  assert.deepEqual(retiredRetrieveRangeAlias.result.error.details.retired_aliases, ["maxBytes"]);
  assertNoRetiredInvocationErrorDetailAliases(retiredRetrieveRangeAlias.result.error.details);
  assert.equal(Object.hasOwn(retiredRetrieveRangeAlias.result.error.details, "maxBytes"), false);
  assert.equal(store.calls.filter((call) => call.name === "retrieveResult").length, retrieveCallsBeforeRetiredAlias);
});

test("coding tool invocation surface runs computer_use.request_lease through rust workload live path", () => {
  const runnerCalls = [];
  const liveRunner = {
    backend: "rust_workload_live",
    blocksDaemonJsExecution: true,
    runCodingTool(input) {
      runnerCalls.push(input);
      return {
        backend: "rust_workload_live",
        mode: "live",
        blocking: true,
        source: "rust_workload_api",
        invocation: {
          schema_version: "ioi.step_module_invocation.v1",
          invocation_id: "invocation://rust-live/computer_use.request_lease",
        },
        result: {
          schema_version: "ioi.step_module_result.v1",
          invocation_id: "invocation://rust-live/computer_use.request_lease",
          status: "success",
          execution_result_ref: "result://rust-live/computer_use.request_lease",
          normalized_observation_ref: "observation://rust-live/computer_use.request_lease",
          receipt_refs: [
            "receipt://rust-live/computer_use.request_lease",
            "receipt_computer_use_lease_request_alpha",
          ],
          artifact_refs: [],
          payload_refs: [],
          agentgres_operation_refs: [],
          state_root_after: null,
          resulting_head: null,
          workflow_projection: {
            workflow_graph_id: "graph_alpha",
            workflow_node_id: "node_computer_use",
            component_kind: "ComputerUseLeaseRequestNode",
            status: "live",
            attempt_id: "attempt://rust-live/computer_use.request_lease",
            evidence_refs: ["evidence://rust-live/computer_use.request_lease"],
            receipt_refs: ["receipt://rust-live/computer_use.request_lease"],
          },
          next: {
            model_reentry_required: false,
            verifier_required: false,
          },
        },
        workload_result: {
          router_admission: {
            schema_version: "ioi.step_module_router_admission.v1",
            backend: "workload_grpc",
          },
          workload_observation: {
            tool: "computer_use.request_lease",
            result: {
              schema_version: "ioi.runtime.coding-tool-result.v1",
              object: "ioi.coding_agent_computer_use_lease_request",
              request_ref: "computer_use_lease_request_alpha",
              workspace_root: "/tmp/workspace",
              lease_request: {
                prompt: "Open the browser and click sign in.",
                lane: "native_browser",
                session_mode: "controlled_relaunch",
                action_kind: "click",
                authority_scope: "computer_use.native_browser.act",
                repo_authority_scope: "workspace.read",
                shared_clipboard_policy: "disabled_until_explicit_approval",
                artifact_policy: "redacted_trace_artifacts_only",
                approval_ref: null,
                fail_closed_when_unavailable: true,
                provider_id: "ioi.computer_use.native_browser.task_scoped_profile",
                provider_kind: "task_scoped_browser_profile",
                wallet_network_authority_required_before_execution: true,
              },
              thread_tool: {
                tool_pack: "computer_use",
                tool_name: "ioi.computer_use.native_browser",
                unavailable_reason: null,
                input: {
                  prompt: "Open the browser and click sign in.",
                  action_kind: "click",
                  session_mode: "controlled_relaunch",
                },
              },
              approval_required_before_execution: true,
              wallet_network_authority_boundary: {
                authority_layer: "wallet.network",
                required_before_execution: true,
                grant_refs: [],
                receipt_refs: [],
              },
              evidence_refs: [
                "computer_use_lease_request_alpha",
                "ioi.computer_use.native_browser.task_scoped_profile",
                "computer_use_lease_request_receipt",
                "coding_tool_receipt",
                "wallet.network.authority_boundary",
              ],
              receipt_refs: ["receipt_computer_use_lease_request_alpha"],
              shell_fallback_used: false,
            },
          },
        },
      };
    },
  };
  const surface = createSurface({
    daemonCoreWorkloadApi: workloadApiFromRunner(liveRunner),
  });
  const store = createStore();

  const result = surface.invokeThreadTool(store, "thread_alpha", "computer_use.request_lease", {
    tool_call_id: "tool_computer_use",
    workflowGraphId: "graph_alpha",
    workflowNodeId: "node_computer_use",
    input: {
      prompt: "Open the browser and click sign in.",
      lane: "native_browser",
      session_mode: "controlled_relaunch",
      action_kind: "click",
    },
  });

  assert.equal(result.status, "completed");
  assert.equal(runnerCalls.length, 1);
  assert.equal(runnerCalls[0].context.schema_version, "ioi.runtime.coding-tool-step-module-request.v1");
  assert.equal(Object.hasOwn(runnerCalls[0].context, "workflow_projection_status"), false);
  assert.equal(runnerCalls[0].input.action_kind, "click");
  assert.equal(result.result.rust_workload, true);
  assert.equal(result.result.request_ref, "computer_use_lease_request_alpha");
  assert.equal(result.result.approval_required_before_execution, true);
  assert.equal(result.result.wallet_network_authority_boundary.authority_layer, "wallet.network");
  assert.equal(result.result.lease_request.authority_scope, "computer_use.native_browser.act");
  for (const field of [
    "requestRef",
    "leaseRequest",
    "threadTool",
    "approvalRequiredBeforeExecution",
    "walletNetworkAuthorityBoundary",
    "evidenceRefs",
    "receiptRefs",
  ]) {
    assert.equal(Object.hasOwn(result.result, field), false);
  }
  assert.equal(result.step_module.backend, "rust_workload_live");
  assert.ok(result.receipt_refs.includes("receipt://rust-live/computer_use.request_lease"));
  assert.ok(result.receipt_refs.includes("receipt_computer_use_lease_request_alpha"));
  assert.ok(!store.calls.some((call) => call.name === "materializeArtifacts"));
});

test("coding tool invocation surface fails closed for budget blocks", () => {
  const surface = createSurface({
    codingToolBudgetPolicyForRequest: () => ({
      status: "blocked",
      usage_telemetry: { prompt_tokens: 10 },
      policy_decision_refs: ["policy_budget"],
    }),
  });
  const store = createStore();

  assert.throws(
    () =>
      surface.invokeThreadTool(store, "thread_alpha", "file.inspect", {
        tool_call_id: "tool_budget",
      }),
    (error) => {
      assert.equal(error.status, 403);
      assert.equal(error.code, "policy");
      assert.equal(error.details.event_id, "event_budget");
      assert.deepEqual(error.details.receipt_refs, ["receipt_budget"]);
      assert.deepEqual(error.details.budget_usage_telemetry, {
        prompt_tokens: 10,
      });
      assert.equal(error.details.context_budget_status, "blocked");
      assert.deepEqual(error.details.policy_decision_refs, ["policy_budget"]);
      assert.equal(
        Object.prototype.hasOwnProperty.call(
          error.details,
          "budgetUsageTelemetry",
        ),
        false,
      );
      for (const field of [
        "contextBudgetStatus",
        "contextBudget",
        "eventId",
        "receiptRefs",
        "policyDecisionRefs",
      ]) {
        assert.equal(Object.hasOwn(error.details, field), false);
      }
      return true;
    },
  );
  assert.ok(store.calls.some((call) => call.name === "blockBudget"));
  const admissionCall = store.calls.find((call) => call.name === "rustResultEventAdmission");
  assert.ok(admissionCall);
  assert.equal(admissionCall.event.event_id, "event_budget");
  assert.equal(admissionCall.input.budget_block.event.event_id, "event_budget");
});

test("coding tool invocation surface executes approval-required tools only after Rust satisfaction", () => {
  const approvalManifest = {
    thread_id: "thread_alpha",
    tool_id: "file.inspect",
    tool_call_id: "tool_approval",
    effect_class: "local_read",
    input_hash: "sha256:approval",
  };
  const runnerCalls = [];
  const liveRunner = {
    backend: "rust_workload_live",
    blocksDaemonJsExecution: true,
    runCodingTool(input) {
      runnerCalls.push(input);
      return {
        backend: "rust_workload_live",
        mode: "live",
        blocking: true,
        source: "rust_workload_api",
        invocation: {
          schema_version: "ioi.step_module_invocation.v1",
          invocation_id: "invocation://rust-live/file.inspect",
        },
        result: {
          schema_version: "ioi.step_module_result.v1",
          invocation_id: "invocation://rust-live/file.inspect",
          status: "success",
          execution_result_ref: "result://rust-live/file.inspect",
          normalized_observation_ref: "observation://rust-live/file.inspect",
          receipt_refs: ["receipt://rust-live/file.inspect"],
          artifact_refs: [],
          payload_refs: [],
          agentgres_operation_refs: [],
          state_root_after: "state://root/after",
          resulting_head: "agentgres://head/after",
          workflow_projection: {
            status: "live",
            receipt_refs: ["receipt://rust-live/file.inspect"],
          },
        },
        workload_result: {
          router_admission: {
            schema_version: "ioi.step_module_router_admission.v1",
            backend: "workload_grpc",
          },
          workload_observation: {
            tool: "file.inspect",
            result: {
              schema_version: "ioi.runtime.coding-tool-result.v1",
              workspace_root: "/tmp/workspace",
              path: "README.md",
              kind: "file",
              exists: true,
              shell_fallback_used: false,
            },
          },
        },
      };
    },
  };
  const surface = createSurface({
    codingToolApprovalManifestForThread: () => approvalManifest,
    codingToolApprovalSatisfactionForThread({ store, threadId, toolId, toolCallId, approval_manifest: manifest }) {
      store.calls.push({
        name: "rustApprovalSatisfaction",
        threadId,
        toolId,
        toolCallId,
        approval_manifest: manifest,
      });
      return {
        source: "rust_coding_tool_approval_satisfaction_protocol",
        satisfied: true,
        approval_id: "approval_alpha",
        decision_event_id: "event_decision",
        decision_seq: 4,
        lease_id: "lease_alpha",
        expires_at: "2026-06-06T04:45:00.000Z",
        reason: "approval_approved",
        receipt_refs: ["receipt_approval"],
        policy_decision_refs: ["policy_approval"],
      };
    },
    daemonCoreWorkloadApi: workloadApiFromRunner(liveRunner),
  });
  const store = createStore();

  const result = surface.invokeThreadTool(store, "thread_alpha", "file.inspect", {
    tool_call_id: "tool_approval",
    approval_id: "approval_alpha",
    input: { path: "README.md" },
  });

  assert.equal(result.status, "completed");
  assert.equal(runnerCalls.length, 1);
  assert.equal(runnerCalls[0].context.approval_ref, "approval:approval_alpha");
  assert.ok(result.receipt_refs.includes("receipt_approval"));
  assert.equal(result.event.payload_summary.approval_required, true);
  assert.equal(result.event.payload_summary.approval_satisfied, true);
  assert.equal(result.event.payload_summary.approval_id, "approval_alpha");
  assert.equal(result.event.payload_summary.approval_manifest, approvalManifest);
  assert.equal(result.event.payload_summary.approval_decision_event_id, "event_decision");
  assert.deepEqual(result.event.payload_summary.approval_receipt_refs, ["receipt_approval"]);
  assert.deepEqual(result.event.payload_summary.approval_policy_decision_refs, ["policy_approval"]);
  assert.ok(store.calls.some((call) => call.name === "rustApprovalSatisfaction"));
  assert.ok(!store.calls.some((call) => call.name === "blockApproval"));
  assert.ok(!store.calls.some((call) => call.name === "approvalSatisfaction"));
});

test("coding tool invocation surface returns Rust-planned approval block results before execution", () => {
  const approvalManifest = {
    thread_mode: "agent",
    approval_mode: "required",
    effect_class: "write",
  };
  const surface = createSurface({
    codingToolApprovalManifestForThread: () => approvalManifest,
  });
  const store = createStore();

  const result = surface.invokeThreadTool(store, "thread_alpha", "file.inspect", {
    tool_call_id: "tool_approval",
  });

  assert.equal(result.status, "blocked");
  assert.equal(result.approval_required, true);
  assert.equal(result.approval_manifest, approvalManifest);
  assert.equal(result.result.rust_authority_block, true);
  assert.equal(result.event.event_kind, "tool.blocked");
  assert.equal(result.event.created_at, "rust_daemon_core");
  assert.equal(result.event.state_root_after, "sha256:after-1");
  assert.equal(result.event.payload_summary.rust_authority_block, true);
  assert.equal(Object.hasOwn(result, "approvalManifest"), false);
  assert.ok(!store.calls.some((call) => call.name === "approvalSatisfaction"));
  const blockCall = store.calls.find((call) => call.name === "rustApprovalBlock");
  assert.ok(blockCall);
  assert.equal(blockCall.input.approval_manifest, approvalManifest);
  assert.equal(blockCall.input.toolId, "file.inspect");
  assert.equal(Object.hasOwn(blockCall.input, "approvalManifest"), false);
  const admissionCall = store.calls.find((call) => call.name === "rustResultEventAdmission");
  assert.ok(admissionCall);
  assert.equal(admissionCall.event.event_kind, "tool.blocked");
  assert.ok(store.calls.some((call) => call.name === "registerRuntimeEvent"));
  assert.ok(!store.calls.some((call) => call.name === "blockApproval"));
  assert.ok(!store.calls.some((call) => call.name === "materializeArtifacts"));
});

test("coding tool invocation surface preserves computer-use dispatch and not-found behavior", () => {
  const surface = createSurface();
  const store = createStore();

  const routed = surface.invokeThreadTool(store, "thread_alpha", "computer_use.browser_discovery", {});

  assert.equal(routed.routed, "browser_discovery");
  assert.throws(
    () => surface.invokeThreadTool(store, "thread_alpha", "not.a.tool", {}),
    (error) => {
      assert.equal(error.status, 404);
      assert.equal(error.details.thread_id, "thread_alpha");
      assert.equal(error.details.tool_id, "not.a.tool");
      assertNoRetiredInvocationErrorDetailAliases(error.details);
      return true;
    },
  );
});
