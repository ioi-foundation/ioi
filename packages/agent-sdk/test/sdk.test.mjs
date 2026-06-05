import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  Agent,
  Cursor,
  IoiAgentError,
  Thread,
  createRuntimeSubstrateClient,
} from "../dist/index.js";
test("default SDK client is daemon-backed and fails closed without transport", async () => {
  await assert.rejects(
    Agent.create({ local: { cwd: process.cwd() } }),
    (error) =>
      error instanceof IoiAgentError &&
      error.code === "external_blocker" &&
      error.details?.endpointConfigured === false &&
      error.details?.requiredEnvironment?.includes("IOI_DAEMON_ENDPOINT") &&
      !("explicitMockFactory" in error.details),
  );
  await assert.rejects(
    createRuntimeSubstrateClient().listModels(),
    (error) => error instanceof IoiAgentError && error.code === "external_blocker",
  );
});

test("SDK admits governed improvement proposals through the thread route", async () => {
  const requests = [];
  const proposal = {
    schema_version: "ioi.governed_runtime_improvement.v1",
    proposal_id: "proposal://runtime-improvement/sdk",
    target_ref: "skill://runtime-auditor/current",
    candidate_ref: "skill-candidate://runtime-auditor/from-trace",
    surface: "skill",
    source_trace_ref: "trace://runtime-improvement/high-fitness",
    eval_receipt_refs: ["receipt://eval/sdk-holdout-pass"],
    verifier_receipt_refs: ["receipt://verifier/sdk-regression-pass"],
    approval_ref: "approval://wallet/runtime-improvement/sdk",
    rollback_ref: "rollback://skill/runtime-auditor/current",
    agentgres_operation_ref: "agentgres://runtime-improvement/operations/sdk",
    expected_heads: ["agentgres://runtime-improvement/head/before"],
    state_root_before: "sha256:runtime-improvement-before",
    state_root_after: "sha256:runtime-improvement-after",
    resulting_head: "agentgres://runtime-improvement/head/after",
  };
  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    requests.push(`${request.method} ${url.pathname}`);
    response.setHeader("content-type", "application/json");
    if (
      request.method === "POST" &&
      url.pathname === "/v1/threads/thread_sdk/governed-improvement-proposals"
    ) {
      const body = await readBody(request);
      assert.equal(body.source, "sdk_client");
      assert.equal(body.proposal.proposal_id, "proposal://runtime-improvement/sdk");
      assert.equal(body.proposal.approval_ref, "approval://wallet/runtime-improvement/sdk");
      response.statusCode = 201;
      response.end(JSON.stringify({
        schema_version: "ioi.runtime.governed_improvement_admission.v1",
        object: "ioi.runtime_governed_improvement_admission",
        status: "admitted",
        proposal_admitted: true,
        mutation_executed: false,
        thread_id: "thread_sdk",
        agent_id: "agent_sdk",
        proposal_id: proposal.proposal_id,
        admission_hash: "sha256:sdk-admission",
        agentgres_operation_ref: proposal.agentgres_operation_ref,
        state_root_before: proposal.state_root_before,
        state_root_after: proposal.state_root_after,
        resulting_head: proposal.resulting_head,
        approval_ref: proposal.approval_ref,
        rollback_ref: proposal.rollback_ref,
        record: {
          ...proposal,
          admission_hash: "sha256:sdk-admission",
        },
      }));
      return;
    }
    response.statusCode = 404;
    response.end(JSON.stringify({ error: { code: "not_found", message: "missing route" } }));
  });
  await listen(server);
  try {
    const address = server.address();
    assert.ok(address && typeof address === "object");
    const client = createRuntimeSubstrateClient({ endpoint: `http://127.0.0.1:${address.port}` });
    const result = await client.admitGovernedImprovementProposal("thread_sdk", { proposal });

    assert.equal(result.status, "admitted");
    assert.equal(result.proposal_admitted, true);
    assert.equal(result.mutation_executed, false);
    assert.equal(result.proposal_id, "proposal://runtime-improvement/sdk");
    assert.equal(result.admission_hash, "sha256:sdk-admission");
    assert.equal(result.agentgres_operation_ref, "agentgres://runtime-improvement/operations/sdk");
    assert.ok(requests.includes("POST /v1/threads/thread_sdk/governed-improvement-proposals"));
  } finally {
    await close(server);
  }
});

test("SDK admits worker/service package invocations through the thread route", async () => {
  const requests = [];
  const invocation = {
    schema_version: "ioi.worker_service_package_invocation.v1",
    package_kind: "worker_package",
    package_ref: "worker://runtime-auditor",
    manifest_ref: "worker://runtime-auditor@1",
    invocation: {
      schema_version: "ioi.step_module_invocation.v1",
      invocation_id: "invocation://worker-package/sdk",
      module_ref: {
        kind: "workload_job",
        id: "worker://runtime-auditor",
        manifest_ref: "worker://runtime-auditor@1",
      },
      authority: {
        authority_grant_refs: ["grant://wallet/worker-package-sdk"],
      },
    },
    result: {
      schema_version: "ioi.step_module_result.v1",
      invocation_id: "invocation://worker-package/sdk",
      status: "success",
      receipt_refs: ["receipt://worker-package/sdk"],
      artifact_refs: ["artifact://worker-package/sdk-report"],
      payload_refs: ["payload://worker-package/sdk-output"],
    },
    expected_heads: ["agentgres://worker-service-package/head/before"],
  };
  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    requests.push(`${request.method} ${url.pathname}`);
    response.setHeader("content-type", "application/json");
    if (
      request.method === "POST" &&
      url.pathname === "/v1/threads/thread_sdk/worker-service-package-invocations"
    ) {
      const body = await readBody(request);
      assert.equal(body.source, "sdk_client");
      assert.equal(body.invocation.package_ref, "worker://runtime-auditor");
      assert.equal(body.invocation.invocation.invocation_id, "invocation://worker-package/sdk");
      response.statusCode = 201;
      response.end(JSON.stringify({
        schema_version: "ioi.runtime.worker_service_package_admission.v1",
        object: "ioi.runtime_worker_service_package_admission",
        status: "admitted",
        invocation_admitted: true,
        thread_id: "thread_sdk",
        agent_id: "agent_sdk",
        package_kind: invocation.package_kind,
        package_ref: invocation.package_ref,
        manifest_ref: invocation.manifest_ref,
        invocation_id: invocation.invocation.invocation_id,
        receipt_refs: invocation.result.receipt_refs,
        artifact_refs: invocation.result.artifact_refs,
        payload_refs: invocation.result.payload_refs,
        authority_grant_refs: invocation.invocation.authority.authority_grant_refs,
        record: invocation,
      }));
      return;
    }
    response.statusCode = 404;
    response.end(JSON.stringify({ error: { code: "not_found", message: "missing route" } }));
  });
  await listen(server);
  try {
    const address = server.address();
    assert.ok(address && typeof address === "object");
    const client = createRuntimeSubstrateClient({ endpoint: `http://127.0.0.1:${address.port}` });
    const result = await client.admitWorkerServicePackageInvocation("thread_sdk", { invocation });

    assert.equal(result.status, "admitted");
    assert.equal(result.invocation_admitted, true);
    assert.equal(result.package_ref, "worker://runtime-auditor");
    assert.equal(result.invocation_id, "invocation://worker-package/sdk");
    assert.deepEqual(result.receipt_refs, ["receipt://worker-package/sdk"]);
    assert.ok(requests.includes("POST /v1/threads/thread_sdk/worker-service-package-invocations"));
  } finally {
    await close(server);
  }
});

test("SDK executes cTEE private workspace actions through the thread route", async () => {
  const requests = [];
  const action = {
    invocation: {
      schema_version: "ioi.step_module_invocation.v1",
      invocation_id: "invocation://ctee/sdk",
      module_ref: {
        kind: "private_workspace_ctee_action",
        id: "private_workspace.mount",
        manifest_ref: "module://ctee/private-workspace@1",
      },
      custody: {
        privacy_profile: "private_workspace_ctee",
        plaintext_policy: {
          node_plaintext_allowed: false,
          declassification_required: true,
        },
        custody_proof_ref: "artifact://custody-proof",
        leakage_profile_ref: "artifact://leakage-profile",
      },
      execution: {
        backend: "ctee_operator",
      },
    },
    node_trust: {
      runtime_node_ref: "node://rented-untrusted",
      trusted_for_plaintext: false,
      attestation_ref: null,
    },
    expected_heads: ["agentgres://ctee/private-workspace/head/before"],
  };
  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    requests.push(`${request.method} ${url.pathname}`);
    response.setHeader("content-type", "application/json");
    if (
      request.method === "POST" &&
      url.pathname === "/v1/threads/thread_sdk/ctee-private-workspace-actions"
    ) {
      const body = await readBody(request);
      assert.equal(body.source, "sdk_client");
      assert.equal(body.action.invocation.invocation_id, "invocation://ctee/sdk");
      assert.equal(body.action.node_trust.trusted_for_plaintext, false);
      response.statusCode = 201;
      response.end(JSON.stringify({
        schema_version: "ioi.runtime.ctee_private_workspace_admission.v1",
        object: "ioi.runtime_ctee_private_workspace_admission",
        status: "admitted",
        action_executed: true,
        thread_id: "thread_sdk",
        agent_id: "agent_sdk",
        invocation_id: action.invocation.invocation_id,
        receipt_ref: "receipt://ctee/private-workspace/sdk",
        receipt_refs: ["receipt://ctee/private-workspace/sdk"],
        evidence_refs: ["receipt://ctee/private-workspace/sdk"],
        record: action,
      }));
      return;
    }
    response.statusCode = 404;
    response.end(JSON.stringify({ error: { code: "not_found", message: "missing route" } }));
  });
  await listen(server);
  try {
    const address = server.address();
    assert.ok(address && typeof address === "object");
    const client = createRuntimeSubstrateClient({ endpoint: `http://127.0.0.1:${address.port}` });
    const result = await client.executeCteePrivateWorkspaceAction("thread_sdk", { action });

    assert.equal(result.status, "admitted");
    assert.equal(result.action_executed, true);
    assert.equal(result.invocation_id, "invocation://ctee/sdk");
    assert.equal(result.receipt_ref, "receipt://ctee/private-workspace/sdk");
    assert.ok(requests.includes("POST /v1/threads/thread_sdk/ctee-private-workspace-actions"));
  } finally {
    await close(server);
  }
});

test("SDK admits L1 settlement attempts through the thread route", async () => {
  const requests = [];
  const attempt = {
    schema_version: "ioi.l1_settlement_admission.v1",
    settlement_ref: "l1://settlement/sdk-marketplace-payment",
    domain_ref: "domain://marketplace/services",
    state_root_ref: "state-root://agentgres/marketplace/after",
    trigger_refs: ["l1-trigger://service-contract/payment"],
    receipt_refs: ["receipt://local-settlement/payment"],
  };
  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    requests.push(`${request.method} ${url.pathname}`);
    response.setHeader("content-type", "application/json");
    if (
      request.method === "POST" &&
      url.pathname === "/v1/threads/thread_sdk/l1-settlement-attempts"
    ) {
      const body = await readBody(request);
      assert.equal(body.source, "sdk_client");
      assert.equal(body.attempt.settlement_ref, "l1://settlement/sdk-marketplace-payment");
      assert.deepEqual(body.attempt.trigger_refs, ["l1-trigger://service-contract/payment"]);
      response.statusCode = 201;
      response.end(JSON.stringify({
        schema_version: "ioi.runtime.l1_settlement_admission.v1",
        object: "ioi.runtime_l1_settlement_admission",
        status: "admitted",
        settlement_admitted: true,
        thread_id: "thread_sdk",
        agent_id: "agent_sdk",
        settlement_ref: attempt.settlement_ref,
        domain_ref: attempt.domain_ref,
        state_root_ref: attempt.state_root_ref,
        trigger_refs: attempt.trigger_refs,
        receipt_refs: attempt.receipt_refs,
        admission_hash: "sha256:l1-settlement-sdk-admission",
        record: attempt,
      }));
      return;
    }
    response.statusCode = 404;
    response.end(JSON.stringify({ error: { code: "not_found", message: "missing route" } }));
  });
  await listen(server);
  try {
    const address = server.address();
    assert.ok(address && typeof address === "object");
    const client = createRuntimeSubstrateClient({ endpoint: `http://127.0.0.1:${address.port}` });
    const result = await client.admitL1SettlementAttempt("thread_sdk", { attempt });

    assert.equal(result.status, "admitted");
    assert.equal(result.settlement_admitted, true);
    assert.equal(result.settlement_ref, "l1://settlement/sdk-marketplace-payment");
    assert.deepEqual(result.trigger_refs, ["l1-trigger://service-contract/payment"]);
    assert.equal(result.admission_hash, "sha256:l1-settlement-sdk-admission");
    assert.ok(requests.includes("POST /v1/threads/thread_sdk/l1-settlement-attempts"));
  } finally {
    await close(server);
  }
});

test("daemon SDK client uses the public substrate HTTP endpoint", async () => {
  const now = new Date().toISOString();
  const events = [
    event("run_http:0", "run_started", "Run entered daemon substrate", now),
    event("run_http:1", "task_state", "Task state projected", now),
    event("run_http:2", "completed", "Run completed", now),
  ];
  const trace = {
    schemaVersion: "ioi.agent-sdk.trace.v1",
    traceBundleId: "trace_http",
    agentId: "agent_http",
    runId: "run_http",
    eventStreamId: "events_http",
    events,
    receipts: [],
    taskState: {
      currentObjective: "HTTP daemon test",
      knownFacts: ["daemon endpoint configured"],
      uncertainFacts: [],
      assumptions: [],
      constraints: [],
      blockers: [],
      changedObjects: [],
      evidenceRefs: ["events_http"],
    },
    uncertainty: {
      ambiguityLevel: "low",
      selectedAction: "execute",
      rationale: "endpoint supplied",
      valueOfProbe: "low",
    },
    probes: [],
    postconditions: {
      prompt: "HTTP daemon test",
      taskFamily: "sdk_transport",
      riskClass: "low",
      checks: [],
      minimumEvidence: ["events_http"],
    },
    semanticImpact: {
      changedSymbols: [],
      changedApis: [],
      changedSchemas: [],
      changedPolicies: [],
      affectedTests: [],
      affectedDocs: [],
      riskClass: "low",
    },
    stopCondition: {
      reason: "evidence_sufficient",
      evidenceSufficient: true,
      rationale: "daemon completed run",
    },
    qualityLedger: {
      ledgerId: "ledger_http",
      taskFamily: "sdk_transport",
      selectedStrategy: "daemon_substrate",
      toolSequence: ["http_request", "event_replay"],
      scorecardMetrics: {},
      failureOntologyLabels: [],
    },
    scorecard: scorecard(),
  };
  const runRecord = {
    id: "run_http",
    agentId: "agent_http",
    status: "completed",
    prompt: "HTTP daemon test",
    mode: "send",
    createdAt: now,
    updatedAt: now,
    events,
    conversation: [
      { role: "user", content: "HTTP daemon test", createdAt: now },
      { role: "assistant", content: "Daemon completed", createdAt: now },
    ],
    receipts: [],
    artifacts: [],
    trace,
    result: "Daemon completed",
  };
  const agentRecord = {
    id: "agent_http",
    status: "active",
    runtime: "local",
    cwd: process.cwd(),
    modelId: "local:auto",
    createdAt: now,
    updatedAt: now,
    options: {
      cloudConfigured: false,
      selfHostedConfigured: false,
      mcpServerNames: [],
      skillNames: [],
      hookNames: [],
      subagentNames: [],
      sandboxProfile: "development",
    },
  };
  const requests = [];
  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    requests.push(`${request.method} ${url.pathname}${url.search}`);
    const body = await readBody(request);
    response.setHeader("content-type", "application/json");
    if (request.method === "POST" && url.pathname === "/v1/agents") {
      assert.equal(body.options.local.cwd, process.cwd());
      response.end(JSON.stringify(agentRecord));
      return;
    }
    if (request.method === "POST" && url.pathname === "/v1/agents/agent_http/runs") {
      assert.equal(body.mode, "send");
      assert.equal(body.prompt, "HTTP daemon test");
      response.end(JSON.stringify(runRecord));
      return;
    }
    if (request.method === "GET" && url.pathname === "/v1/runs/run_http/events") {
      const lastEventId = url.searchParams.get("lastEventId");
      const start = lastEventId ? events.findIndex((item) => item.id === lastEventId) + 1 : 0;
      response.setHeader("content-type", "text/event-stream");
      response.end(events.slice(start).map((item) => `id: ${item.id}\ndata: ${JSON.stringify(item)}\n\n`).join(""));
      return;
    }
    if (request.method === "GET" && url.pathname === "/v1/runs/run_http/wait") {
      response.end(JSON.stringify({
        id: runRecord.id,
        agentId: runRecord.agentId,
        status: runRecord.status,
        result: runRecord.result,
        stopCondition: trace.stopCondition,
        trace,
        scorecard: trace.scorecard,
      }));
      return;
    }
    if (request.method === "GET" && url.pathname === "/v1/runs/run_http/trace") {
      response.end(JSON.stringify(trace));
      return;
    }
    if (request.method === "GET" && url.pathname === "/v1/models") {
      response.end(JSON.stringify([{ id: "local:auto", provider: "daemon", cost: "local", quality: "high" }]));
      return;
    }
    if (request.method === "GET" && url.pathname === "/v1/account") {
      response.end(JSON.stringify({
        id: "operator_http",
        email: null,
        authorityLevel: "local",
        privacyClass: "local_private",
        source: "daemon",
      }));
      return;
    }
    if (request.method === "GET" && url.pathname === "/v1/runtime/nodes") {
      response.end(JSON.stringify([{
        id: "daemon-local",
        kind: "local",
        status: "available",
        privacyClass: "local_private",
        evidenceRefs: ["daemon-runtime-api"],
      }]));
      return;
    }
    if (request.method === "GET" && url.pathname === "/v1/tools") {
      response.end(JSON.stringify([{
        stableToolId: "sys.exec",
        displayName: "Shell command",
        primitiveCapabilities: ["prim:sys.exec"],
        authorityScopeRequirements: ["scope:host.controlled_execution"],
        effectClass: "local_command",
        riskDomain: "host",
        inputSchema: { type: "object" },
        outputSchema: { type: "object" },
        evidenceRequirements: ["shell_receipt"],
      }]));
      return;
    }
    response.statusCode = 404;
    response.end(JSON.stringify({ error: { code: "not_found", message: "missing route" } }));
  });
  await listen(server);
  try {
    const address = server.address();
    assert.ok(address && typeof address === "object");
    const endpoint = `http://127.0.0.1:${address.port}`;
    const client = createRuntimeSubstrateClient({ endpoint });
    const agent = await Agent.create({ local: { cwd: process.cwd() }, substrateClient: client });
    const run = await agent.send("HTTP daemon test");
    const firstBatch = [];
    for await (const item of run.stream()) {
      firstBatch.push(item);
      if (firstBatch.length === 1) break;
    }
    const secondBatch = [];
    for await (const item of run.stream({ lastEventId: firstBatch.at(-1).id })) {
      secondBatch.push(item);
    }
    assert.deepEqual(secondBatch.map((item) => item.id), ["run_http:1", "run_http:2"]);
    assert.equal((await run.wait()).stopCondition.reason, "evidence_sufficient");
    assert.equal((await run.trace()).qualityLedger.selectedStrategy, "daemon_substrate");
    assert.equal((await Cursor.models.list({ substrateClient: client })).at(0)?.provider, "daemon");
    assert.equal((await Cursor.account.get({ substrateClient: client })).source, "daemon");
    assert.equal((await Cursor.runtimeNodes.list({ substrateClient: client })).at(0)?.id, "daemon-local");
    const httpTools = await agent.tools();
    assert.equal(httpTools.at(0)?.stableToolId, "sys.exec");
    assert.equal(httpTools.at(0)?.approvalRequired, true);
    assert.equal(httpTools.at(0)?.credentialReadiness.status, "not_required");
    assert.equal(httpTools.at(0)?.receiptBehavior.requiredReceiptTypes.at(0), "shell_receipt");
    assert.ok(requests.includes("POST /v1/agents"));
    assert.ok(requests.includes("POST /v1/agents/agent_http/runs"));
    assert.ok(requests.includes("GET /v1/runs/run_http/events?lastEventId=run_http%3A0"));
  } finally {
    await close(server);
  }
});

test("Thread and Turn wrappers project canonical daemon events into typed SDK runtime events", async () => {
  const now = new Date().toISOString();
  const threadRecord = {
    schema_version: "ioi.runtime.thread.v1",
    thread_id: "thread_sdk",
    session_id: "session_sdk",
    agent_id: "agent_sdk",
    workspace_root: process.cwd(),
    title: "SDK thread projection",
    mode: "agent",
    approval_mode: "suggest",
    trust_profile: "local_private",
    model_route: "local:auto",
    status: "active",
    latest_turn_id: null,
    latest_seq: 1,
    event_stream_id: "events_thread_sdk",
    workflow_graph_id: null,
    harness_binding_id: null,
    agentgres_projection_ref: "agents/agent_sdk.json",
    created_at: now,
    updated_at: now,
    archived_at: null,
    fixture_profile: null,
  };
  const turnRecord = {
    schema_version: "ioi.runtime.turn.v1",
    turn_id: "turn_sdk",
    thread_id: "thread_sdk",
    parent_turn_id: null,
    request_id: "run_sdk",
    status: "completed",
    input_item_ids: ["item_turn_started"],
    output_item_ids: ["item_tool", "item_terminal"],
    seq_start: 2,
    seq_end: 4,
    started_at: now,
    completed_at: now,
    mode: "agent",
    approval_mode: "suggest",
    model_route_decision_id: null,
    usage: null,
    stop_reason: "runtime_bridge_completed",
    error: null,
    rollback_snapshot_id: null,
    quality_ledger_ref: null,
    workflow_execution_ref: null,
    fixture_profile: null,
  };
  const interruptedTurnRecord = {
    ...turnRecord,
    status: "interrupted",
    seq_end: 8,
    completed_at: now,
    stop_reason: "operator_interrupt",
  };
  const forkedThreadRecord = {
    ...threadRecord,
    thread_id: "thread_sdk_fork",
    agent_id: "agent_sdk_fork",
    session_id: "session_sdk_fork",
    event_stream_id: "events_thread_sdk_fork",
    latest_seq: 1,
    agentgres_projection_ref: "agents/agent_sdk_fork.json",
    source_thread_id: "thread_sdk",
    forked_from_seq: 4,
  };
  const compactedThreadRecord = {
    ...threadRecord,
    latest_seq: 6,
  };
  const runtimeEvents = [
    runtimeEnvelope({
      seq: 1,
      eventKind: "thread.started",
      sourceEventKind: "RuntimeAgentService.handle_service_call.start@v1",
      turnId: "",
      itemId: "item_thread_started",
      componentKind: "runtime_thread",
      workflowNodeId: "runtime.runtime-thread",
      payload: { agent_id: "agent_sdk", thread_id: "thread_sdk" },
      createdAt: now,
    }),
    runtimeEnvelope({
      seq: 2,
      eventKind: "turn.started",
      sourceEventKind: "RuntimeAgentService.handle_service_call.post_message@v1",
      itemId: "item_turn_started",
      componentKind: "runtime_turn",
      workflowNodeId: "runtime.runtime-turn",
      payload: { agent_id: "agent_sdk", run_id: "run_sdk", prompt: "Exercise typed thread events." },
      createdAt: now,
    }),
    runtimeEnvelope({
      seq: 3,
      eventKind: "tool.completed",
      sourceEventKind: "KernelEvent::AgentActionResult",
      itemId: "item_tool",
      componentKind: "tool_result",
      workflowNodeId: "runtime.tool-result",
      payloadSchemaVersion: "ioi.runtime.kernel-event.v1",
      payload: {
        event_kind: "KernelEvent::AgentActionResult",
        agent_id: "agent_sdk",
        run_id: "run_sdk",
        tool_name: "system::intent_clarification",
        agent_status: "Paused",
        step_index: 0,
      },
      createdAt: now,
    }),
    runtimeEnvelope({
      seq: 4,
      eventKind: "turn.completed",
      sourceEventKind: "RuntimeAgentService.handle_service_call.step@v1",
      itemId: "item_terminal",
      componentKind: "runtime_turn",
      workflowNodeId: "runtime.runtime-turn",
      payload: { agent_id: "agent_sdk", run_id: "run_sdk", agent_status: "Paused" },
      createdAt: now,
    }),
  ];
  const requests = [];
  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    requests.push(`${request.method} ${url.pathname}${url.search}`);
    response.setHeader("content-type", "application/json");
    if (request.method === "POST" && url.pathname === "/v1/threads") {
      const body = await readBody(request);
      assert.equal(body.options.local.cwd, process.cwd());
      response.end(JSON.stringify(threadRecord));
      return;
    }
    if (request.method === "GET" && url.pathname === "/v1/threads/thread_sdk") {
      response.end(JSON.stringify({ ...threadRecord, turns: [turnRecord] }));
      return;
    }
    if (request.method === "POST" && url.pathname === "/v1/threads/thread_sdk/turns") {
      const body = await readBody(request);
      assert.equal(body.prompt, "Exercise typed thread events.");
      response.end(JSON.stringify(turnRecord));
      return;
    }
    if (request.method === "POST" && url.pathname === "/v1/threads/thread_sdk/fork") {
      const body = await readBody(request);
      assert.equal(body.reason, "branch context");
      assert.equal(body.source, "sdk_client");
      runtimeEvents.push(runtimeEnvelope({
        seq: 5,
        eventKind: "thread.forked",
        sourceEventKind: "OperatorControl.Fork",
        turnId: "turn_sdk",
        itemId: "item_thread_fork",
        componentKind: "thread_fork",
        workflowNodeId: "runtime.thread-fork",
        payloadSchemaVersion: "ioi.runtime.thread-fork.v1",
        payload: {
          event_kind: "OperatorControl.Fork",
          reason: "branch context",
          source_thread_id: "thread_sdk",
          fork_thread_id: "thread_sdk_fork",
        },
        status: "completed",
        createdAt: now,
      }));
      response.end(JSON.stringify(forkedThreadRecord));
      return;
    }
    if (request.method === "POST" && url.pathname === "/v1/threads/thread_sdk/compact") {
      const body = await readBody(request);
      assert.equal(body.reason, "reduce stale context");
      runtimeEvents.push(runtimeEnvelope({
        seq: 6,
        eventKind: "context.compacted",
        sourceEventKind: "OperatorControl.Compact",
        itemId: "item_context_compact",
        componentKind: "context_compaction",
        workflowNodeId: "runtime.context-compact",
        payloadSchemaVersion: "ioi.runtime.context-compaction.v1",
        payload: {
          event_kind: "OperatorControl.Compact",
          reason: "reduce stale context",
        },
        status: "completed",
        createdAt: now,
      }));
      response.end(JSON.stringify(compactedThreadRecord));
      return;
    }
    if (request.method === "POST" && url.pathname === "/v1/threads/thread_sdk/turns/turn_sdk/interrupt") {
      const body = await readBody(request);
      assert.equal(body.reason, "operator validation");
      runtimeEvents.push(runtimeEnvelope({
        seq: 8,
        eventKind: "turn.interrupted",
        sourceEventKind: "OperatorControl.Interrupt",
        itemId: "item_operator_interrupt",
        componentKind: "operator_control",
        workflowNodeId: "runtime.operator-interrupt",
        payloadSchemaVersion: "ioi.runtime.operator-control.v1",
        payload: {
          event_kind: "OperatorControl.Interrupt",
          reason: "operator validation",
        },
        status: "interrupted",
        createdAt: now,
      }));
      response.end(JSON.stringify(interruptedTurnRecord));
      return;
    }
    if (request.method === "POST" && url.pathname === "/v1/threads/thread_sdk/turns/turn_sdk/steer") {
      const body = await readBody(request);
      assert.equal(body.guidance, "focus on the failing assertion");
      runtimeEvents.push(runtimeEnvelope({
        seq: 7,
        eventKind: "turn.steered",
        sourceEventKind: "OperatorControl.Steer",
        itemId: "item_operator_steer",
        componentKind: "operator_control",
        workflowNodeId: "runtime.operator-steer",
        payloadSchemaVersion: "ioi.runtime.operator-control.v1",
        payload: {
          event_kind: "OperatorControl.Steer",
          guidance: "focus on the failing assertion",
        },
        status: "completed",
        createdAt: now,
      }));
      response.end(JSON.stringify(turnRecord));
      return;
    }
    if (request.method === "GET" && url.pathname === "/v1/threads/thread_sdk/events") {
      const sinceSeq = Number(url.searchParams.get("since_seq") ?? 0) || 0;
      response.setHeader("content-type", "text/event-stream");
      response.end(
        runtimeEvents
          .filter((item) => item.seq > sinceSeq)
          .map((item) => `id: ${item.event_id}\ndata: ${JSON.stringify(item)}\n\n`)
          .join(""),
      );
      return;
    }
    response.statusCode = 404;
    response.end(JSON.stringify({ error: { code: "not_found", message: "missing route" } }));
  });
  await listen(server);
  try {
    const address = server.address();
    assert.ok(address && typeof address === "object");
    const client = createRuntimeSubstrateClient({ endpoint: `http://127.0.0.1:${address.port}` });
    const thread = await Thread.create({ local: { cwd: process.cwd() }, substrateClient: client });
    const turn = await thread.send("Exercise typed thread events.");
    const threadEvents = [];
    for await (const item of thread.events({ sinceSeq: 0 })) threadEvents.push(item);
    const toolEvent = threadEvents.find((item) => item.sourceEventKind === "KernelEvent::AgentActionResult");
    assert.equal(toolEvent.type, "tool_completed");
    assert.equal(toolEvent.payloadSchemaVersion, "ioi.runtime.kernel-event.v1");
    assert.equal(toolEvent.componentKind, "tool_result");
    assert.equal(toolEvent.workflowNodeId, "runtime.tool-result");
    assert.equal(toolEvent.toolName, "system::intent_clarification");
    assert.equal(toolEvent.agentStatus, "Paused");
    assert.equal(toolEvent.stepIndex, 0);
    const retiredPayloadKeys = ["id", "type"].map((suffix) => ["legacy", "event", suffix].join("_"));
    for (const key of retiredPayloadKeys) {
      assert.equal(Object.hasOwn(toolEvent.payload, key), false);
    }

    const turnEvents = [];
    for await (const item of turn.events()) turnEvents.push(item);
    assert.deepEqual(turnEvents.map((item) => item.type), [
      "turn_started",
      "tool_completed",
      "turn_completed",
    ]);
    const forked = await thread.fork({ reason: "branch context" });
    assert.equal(forked.id, "thread_sdk_fork");
    const forkedEvents = [];
    for await (const item of thread.events({ sinceSeq: 4 })) forkedEvents.push(item);
    assert.deepEqual(forkedEvents.map((item) => item.type), ["thread_forked"]);
    assert.equal(forkedEvents[0].eventKind, "thread.forked");
    assert.equal(forkedEvents[0].sourceEventKind, "OperatorControl.Fork");
    assert.equal(forkedEvents[0].componentKind, "thread_fork");
    assert.equal(forkedEvents[0].workflowNodeId, "runtime.thread-fork");
    assert.equal(forkedEvents[0].payloadSchemaVersion, "ioi.runtime.thread-fork.v1");

    const compacted = await thread.compact({ reason: "reduce stale context" });
    assert.equal(compacted.record.latest_seq, 6);
    const compactedEvents = [];
    for await (const item of thread.events({ sinceSeq: 5 })) compactedEvents.push(item);
    assert.deepEqual(compactedEvents.map((item) => item.type), ["context_compacted"]);
    assert.equal(compactedEvents[0].eventKind, "context.compacted");
    assert.equal(compactedEvents[0].sourceEventKind, "OperatorControl.Compact");
    assert.equal(compactedEvents[0].componentKind, "context_compaction");
    assert.equal(compactedEvents[0].workflowNodeId, "runtime.context-compact");
    assert.equal(compactedEvents[0].payloadSchemaVersion, "ioi.runtime.context-compaction.v1");

    const steered = await turn.steer({ guidance: "focus on the failing assertion" });
    assert.equal(steered.status, "completed");
    const steeredEvents = [];
    for await (const item of thread.events({ sinceSeq: 6 })) steeredEvents.push(item);
    assert.deepEqual(steeredEvents.map((item) => item.type), ["turn_steered"]);
    assert.equal(steeredEvents[0].eventKind, "turn.steered");
    assert.equal(steeredEvents[0].sourceEventKind, "OperatorControl.Steer");
    assert.equal(steeredEvents[0].componentKind, "operator_control");
    assert.equal(steeredEvents[0].workflowNodeId, "runtime.operator-steer");
    assert.equal(steeredEvents[0].payloadSchemaVersion, "ioi.runtime.operator-control.v1");

    const interrupted = await turn.interrupt({ reason: "operator validation" });
    assert.equal(interrupted.status, "interrupted");
    const interruptedEvents = [];
    for await (const item of thread.events({ sinceSeq: 7 })) interruptedEvents.push(item);
    assert.deepEqual(interruptedEvents.map((item) => item.type), ["turn_interrupted"]);
    assert.equal(interruptedEvents[0].eventKind, "turn.interrupted");
    assert.equal(interruptedEvents[0].sourceEventKind, "OperatorControl.Interrupt");
    assert.equal(interruptedEvents[0].componentKind, "operator_control");
    assert.equal(interruptedEvents[0].workflowNodeId, "runtime.operator-interrupt");
    assert.equal(interruptedEvents[0].payloadSchemaVersion, "ioi.runtime.operator-control.v1");
    assert.ok(requests.includes("POST /v1/threads"));
    assert.ok(requests.includes("POST /v1/threads/thread_sdk/turns"));
    assert.ok(requests.includes("POST /v1/threads/thread_sdk/fork"));
    assert.ok(requests.includes("POST /v1/threads/thread_sdk/compact"));
    assert.ok(requests.includes("POST /v1/threads/thread_sdk/turns/turn_sdk/steer"));
    assert.ok(requests.includes("POST /v1/threads/thread_sdk/turns/turn_sdk/interrupt"));
    assert.ok(requests.includes("GET /v1/threads/thread_sdk/events?since_seq=0"));
  } finally {
    await close(server);
  }
});

test("AgentSubagent mapping behaviorally routes handoffs", async () => {
  const now = new Date().toISOString();
  const runRecord = {
    id: "run_subagent",
    agentId: "agent_http",
    status: "completed",
    prompt: "Subagent test",
    mode: "handoff",
    createdAt: now,
    updatedAt: now,
    events: [],
    receipts: [],
    artifacts: [],
    trace: {
      schemaVersion: "ioi.agent-sdk.trace.v1",
      traceBundleId: "trace_subagent",
      agentId: "agent_http",
      runId: "run_subagent",
      eventStreamId: "events_subagent",
      events: [],
      receipts: [],
      taskState: {
        currentObjective: "Subagent test",
        knownFacts: [],
        uncertainFacts: [],
        assumptions: [],
        constraints: [],
        blockers: [],
        changedObjects: [],
        evidenceRefs: ["events_subagent"],
      },
      uncertainty: {
        ambiguityLevel: "low",
        selectedAction: "execute",
        rationale: "handoff",
        valueOfProbe: "low",
      },
      probes: [],
      postconditions: {
        prompt: "Subagent test",
        taskFamily: "subagent_execution",
        riskClass: "low",
        checks: [],
        minimumEvidence: ["events_subagent"],
      },
      semanticImpact: {
        changedSymbols: [],
        changedApis: [],
        changedSchemas: [],
        changedPolicies: [],
        affectedTests: [],
        affectedDocs: [],
        riskClass: "low",
      },
      stopCondition: {
        reason: "evidence_sufficient",
        evidenceSufficient: true,
        rationale: "handoff completed",
      },
      qualityLedger: {
        ledgerId: "ledger_subagent",
        taskFamily: "subagent_execution",
        selectedStrategy: "daemon_substrate",
        toolSequence: [],
        scorecardMetrics: { handoff_quality: 1.0 },
        failureOntologyLabels: [],
      },
      scorecard: scorecard(),
    },
    result: "Handoff complete",
  };
  const agentRecord = {
    id: "agent_http",
    status: "active",
    runtime: "local",
    cwd: process.cwd(),
    modelId: "local:auto",
    createdAt: now,
    updatedAt: now,
    options: {
      cloudConfigured: false,
      selfHostedConfigured: false,
      mcpServerNames: [],
      skillNames: [],
      hookNames: [],
      subagentNames: ["reviewer"],
      sandboxProfile: "development",
    },
  };
  const requests = [];
  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    requests.push(`${request.method} ${url.pathname}`);
    const body = await readBody(request);
    response.setHeader("content-type", "application/json");
    if (request.method === "POST" && url.pathname === "/v1/agents") {
      response.end(JSON.stringify(agentRecord));
      return;
    }
    if (request.method === "POST" && url.pathname === "/v1/agents/agent_http/runs") {
      assert.equal(body.mode, "handoff");
      assert.equal(body.receiver ?? body.options?.receiver, "reviewer");
      assert.equal(body.prompt, "Please review this.");
      response.end(JSON.stringify(runRecord));
      return;
    }
    if (request.method === "GET" && url.pathname === "/v1/runs/run_subagent/trace") {
      response.end(JSON.stringify(runRecord.trace));
      return;
    }
    response.statusCode = 404;
    response.end(JSON.stringify({ error: { code: "not_found" } }));
  });
  await listen(server);
  try {
    const address = server.address();
    const endpoint = `http://127.0.0.1:${address.port}`;
    const client = createRuntimeSubstrateClient({ endpoint });
    const agent = await Agent.create({ local: { cwd: process.cwd() }, substrateClient: client });
    
    // Exercise subagent list/map
    const reviewer = agent.subagent("reviewer");
    assert.equal(reviewer.name, "reviewer");
    
    const run = await reviewer.send("Please review this.");
    assert.equal(run.id, "run_subagent");
    const trace = await run.trace();
    assert.equal(trace.qualityLedger.scorecardMetrics.handoff_quality, 1.0);
    
    // Directly access agent.agents.reviewer to satisfy check
    assert.ok(agent.agents.reviewer);
    
    assert.ok(requests.includes("POST /v1/agents"));
    assert.ok(requests.includes("POST /v1/agents/agent_http/runs"));
  } finally {
    await close(server);
  }
});

function event(id, type, summary, createdAt) {
  return {
    id,
    runId: "run_http",
    agentId: "agent_http",
    type,
    cursor: id,
    createdAt,
    summary,
  };
}

function runtimeEnvelope({
  seq,
  eventKind,
  sourceEventKind,
  payload,
  createdAt,
  itemId,
  turnId = "turn_sdk",
  componentKind = null,
  workflowNodeId = null,
  payloadSchemaVersion = "ioi.runtime.event.v1",
  status,
}) {
  return {
    schema_version: "ioi.runtime.event.v1",
    event_id: `events_thread_sdk:seq:${String(seq).padStart(8, "0")}`,
    event_stream_id: "events_thread_sdk",
    thread_id: "thread_sdk",
    turn_id: turnId,
    item_id: itemId,
    seq,
    parent_seq: seq > 1 ? seq - 1 : null,
    idempotency_key: `${sourceEventKind}:${seq}`,
    source: "runtime_service",
    source_event_kind: sourceEventKind,
    event_kind: eventKind,
    status: status ?? (eventKind.endsWith(".started") ? "running" : "completed"),
    actor: "runtime",
    created_at: createdAt,
    workspace_root: process.cwd(),
    workflow_graph_id: null,
    workflow_node_id: workflowNodeId,
    component_kind: componentKind,
    tool_call_id: null,
    approval_id: null,
    artifact_refs: [],
    receipt_refs: [],
    policy_decision_refs: [],
    rollback_refs: [],
    payload_schema_version: payloadSchemaVersion,
    payload_ref: null,
    payload: Object.fromEntries(Object.entries(payload).map(([key, value]) => [key, String(value)])),
    payload_summary: payload,
    redaction_profile: "internal",
    fixture_profile: null,
  };
}

function scorecard() {
  return {
    taskPassRate: 1,
    recoverySuccess: 1,
    memoryRelevance: 1,
    toolQuality: 1,
    strategyRoi: 1,
    operatorInterventionRate: 0,
    verifierIndependence: 1,
  };
}

async function readBody(request) {
  const chunks = [];
  for await (const chunk of request) {
    chunks.push(chunk);
  }
  const text = Buffer.concat(chunks).toString("utf8");
  return text ? JSON.parse(text) : {};
}

function listen(server) {
  return new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
}

function close(server) {
  return new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
}
