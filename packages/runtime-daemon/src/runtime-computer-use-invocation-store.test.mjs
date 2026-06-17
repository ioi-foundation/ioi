import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { AgentgresRuntimeStateStore } from "./index.mjs";

async function withStore(fn, options = {}) {
  const stateDir = mkdtempSync(join(tmpdir(), "ioi-computer-use-invocation-store-"));
  const store = new AgentgresRuntimeStateStore(stateDir, {
    cwd: stateDir,
    modelMountCore: modelMountCoreForComputerUseTest(),
    ...options,
  });
  try {
    return await fn(store);
  } finally {
    store.close();
    rmSync(stateDir, { recursive: true, force: true });
  }
}

function threadLifecycleApiForComputerUseRunMaterialization() {
  const calls = [];
  return {
    calls,
    planRunCreateStateUpdate(request) {
      calls.push(request);
      assert.equal(request.schema_version, "ioi.runtime.run-create-state-update-request.v1");
      assert.equal(request.run.trace.computerUse, null);
      assert.equal(Object.hasOwn(request.run, "computerUse"), false);
      assert.equal(
        request.run.computer_use_materialization_request?.schema_version,
        "ioi.runtime.computer-use-run-materialization-request.v1",
      );
      assert.equal(
        request.run.computer_use_materialization_request?.request?.computer_use,
        true,
      );
      const {
        computer_use_materialization_request: _retiredShim,
        ...run
      } = request.run;
      return {
        status: "planned",
        operation_kind: "run.create",
        created_at: run.createdAt,
        updated_at: run.updatedAt,
        run: {
          ...run,
          trace: {
            ...run.trace,
            computerUse: {
              source: "rust_daemon_core_run_create",
              lease: {
                lane: "native_browser",
              },
            },
          },
          events: [
            ...run.events,
            {
              type: "computer_use_observation",
              data: {
                rust_daemon_core_materialized: true,
              },
            },
          ],
          receipts: [
            ...run.receipts,
            {
              id: "receipt_run_browser_computer_use_trace",
              kind: "computer_use_trace",
              evidenceRefs: ["rust_daemon_core_computer_use_run_materialization"],
            },
          ],
          artifacts: [
            ...run.artifacts,
            {
              id: "artifact_run_browser_computer_use_trace_json",
              name: "computer-use-trace.json",
              receiptId: "receipt_run_browser_computer_use_trace",
              content: "{}",
            },
          ],
        },
      };
    },
  };
}

function modelMountCoreForComputerUseTest() {
  return {
    planReadProjection(request) {
      return {
        source: "rust_daemon_core.model_mount.read_projection",
        projection_kind: request.projection_kind,
        projection: { source: "agentgres_model_mounting_projection" },
        evidence_refs: [
          "rust_daemon_core_model_mount_projection",
          "agentgres_model_mount_read_truth",
          "model_mount_js_read_projection_authoring_retired",
        ],
      };
    },
  };
}

function memoryProjectionApiForComputerUseTest() {
  return {
    planRuntimeMemoryCommand(request = {}) {
      return {
        source: "rust_runtime_memory_command_plan_api",
        backend: "rust_policy",
        object: "ioi.runtime_memory_command_plan",
        status: "planned",
        operation: "runtime_memory_command_plan",
        operation_kind: request.operation_kind ?? "memory.run_command.plan",
        command_kind: "none",
        thread_id: request.thread_id ?? null,
        agent_id: request.agent_id ?? null,
        command: { kind: "none" },
        evidence_refs: [
          "rust_daemon_core_memory_command_parser",
          "runtime_memory_command_parser_js_retired",
          "run_memory_command_grammar_rust_owned",
        ],
        receipt_refs: ["receipt_runtime_memory_command_plan"],
      };
    },
    projectRuntimeMemoryProjection(request = {}) {
      return {
        source: "rust_runtime_memory_projection_api",
        projection_kind: request.projection_kind,
        operation_kind: request.operation_kind,
        projection: memoryProjectionForComputerUseRequest(request),
        record_count: 0,
        evidence_refs: ["runtime_memory_public_projection_rust_owned"],
        receipt_refs: [`receipt_runtime_memory_projection_${request.projection_kind}`],
      };
    },
  };
}

function memoryProjectionForComputerUseRequest(request = {}) {
  const projection = {
    schema_version: "ioi.agent-runtime.memory.v1",
    object: "ioi.agent_memory_projection",
    agent_id: request.agent_id ?? null,
    thread_id: request.thread_id ?? null,
    workspace: request.workspace_root ?? null,
    policy: {
      id: `policy_${request.thread_id ?? "runtime"}`,
      injection_enabled: true,
      read_only: false,
      write_requires_approval: false,
    },
    paths: {
      records_path: `${request.state_dir}/memory-records`,
      policies_path: `${request.state_dir}/memory-policies`,
      effective_policy_id: `policy_${request.thread_id ?? "runtime"}`,
    },
    filters: request.filters ?? {},
    records: [],
    total_matches: 0,
    state_dir_replay_required: true,
  };
  switch (request.projection_kind) {
    case "records":
      return projection;
    case "policy":
      return projection.policy;
    case "path":
      return projection.paths;
    case "status":
      return {
        object: "ioi.runtime_memory_manager_status",
        status: "ready",
        record_count: 0,
        thread_id: request.thread_id ?? null,
        agent_id: request.agent_id ?? null,
        workspace: request.workspace_root ?? null,
      };
    case "validation":
      return {
        object: "ioi.runtime_memory_manager_validation",
        ok: true,
        record_count: 0,
        thread_id: request.thread_id ?? null,
        agent_id: request.agent_id ?? null,
        workspace: request.workspace_root ?? null,
      };
    default:
      return {};
  }
}

function repositoryWorkflowProjectionApiForComputerUseTest() {
  return {
    projectRepositoryWorkflow(request = {}) {
      return repositoryWorkflowProjectionResultForComputerUseRequest(request);
    },
  };
}

function repositoryWorkflowProjectionResultForComputerUseRequest(request = {}) {
  const workspaceRoot = request.workspace_root ?? "/workspace";
  const generatedAt = "2026-06-15T18:00:00.000Z";
  const repositoryContext = {
    schemaVersion: "ioi.agent-runtime.repository-context.v1",
    object: "ioi.repository_context",
    contextId: "repoctx_computer_use",
    generatedAt,
    workspaceRoot,
    workspaceRootHash: "hash_workspace",
    provider: "git",
    readOnly: true,
    mutationExecuted: false,
    status: {
      isDirty: false,
      counts: {
        staged: 0,
        unstaged: 0,
        untracked: 0,
        conflicted: 0,
      },
    },
    isGitRepository: false,
    repoRoot: null,
    repoRootHash: null,
    branch: null,
    defaultBranch: null,
    detachedHead: false,
    headShortSha: null,
    upstream: null,
    remoteCount: 0,
    redaction: { profile: "repository_context_safe" },
  };
  const branchPolicy = {
    schemaVersion: "ioi.agent-runtime.branch-policy.v1",
    object: "ioi.branch_policy",
    policyId: "branch_policy_computer_use",
    repositoryContextId: repositoryContext.contextId,
    generatedAt,
    status: "blocked",
    branch: null,
    defaultBranch: null,
    protectedBranch: false,
    detachedHead: false,
    dirty: false,
    upstream: null,
    ahead: 0,
    behind: 0,
    blockers: ["not_git_repository"],
    warnings: [],
    mutationAllowed: false,
    prCreationAllowed: false,
    reviewRequired: true,
    mutationExecuted: false,
    summary: "Repository workflow projection is blocked outside a Git repository.",
    redaction: { profile: "branch_policy_safe" },
  };
  const githubContext = {
    schemaVersion: "ioi.agent-runtime.github-context.v1",
    object: "ioi.github_context",
    contextId: "github_context_computer_use",
    repositoryContextId: repositoryContext.contextId,
    branchPolicyId: branchPolicy.policyId,
    generatedAt,
    status: "unavailable",
    githubRemotePresent: false,
    defaultRemoteName: null,
    owner: null,
    repo: null,
    repoFullName: null,
    branch: null,
    defaultBranch: null,
    branchPolicyStatus: branchPolicy.status,
    credentials: { tokenAvailable: false },
    prCreationEligible: false,
    networkLookupPerformed: false,
    mutationExecuted: false,
    summary: "No GitHub remote is available.",
    redaction: { profile: "github_context_safe" },
  };
  const prAttempt = {
    schemaVersion: "ioi.agent-runtime.pr-attempt.v1",
    object: "ioi.pr_attempt",
    attemptId: "pr_attempt_computer_use",
    repositoryContextId: repositoryContext.contextId,
    branchPolicyId: branchPolicy.policyId,
    githubContextId: githubContext.contextId,
    generatedAt,
    status: "blocked",
    outcome: "failed_precondition",
    repoFullName: null,
    branch: null,
    defaultBranch: null,
    headShortSha: null,
    blockers: ["not_git_repository"],
    warnings: ["pr_attempt_preview_only"],
    authority: {
      requiredScopes: ["github.pr.create"],
      missingScopes: ["github.pr.create"],
      scopeGranted: false,
    },
    branchArtifact: {
      artifactName: "pr-branch.json",
      mediaType: "application/json",
      artifactHash: "hash_pr_branch",
    },
    diffArtifact: {
      artifactName: "pr-diff.patch",
      mediaType: "text/x-diff",
      artifactHash: "hash_pr_diff",
      diffHash: "hash_pr_diff",
      fileCount: 0,
    },
    mutationAttempted: false,
    mutationExecuted: false,
    networkLookupPerformed: false,
    summary: "PR attempt was not ready; no mutation was executed.",
    redaction: { profile: "pr_attempt_safe", diffContentInProjection: false },
  };
  const issueContext = {
    schemaVersion: "ioi.agent-runtime.issue-context.v1",
    object: "ioi.issue_context",
    contextId: "issue_context_computer_use",
    repositoryContextId: repositoryContext.contextId,
    githubContextId: githubContext.contextId,
    prAttemptId: prAttempt.attemptId,
    reviewGateId: "review_gate_computer_use",
    generatedAt,
    status: "unbound",
    repoFullName: null,
    bound: false,
    issueProvided: false,
    issueNumber: null,
    sourceKind: "none",
    warnings: [],
    networkLookupPerformed: false,
    mutationExecuted: false,
    summary: "No issue context is bound.",
    redaction: { profile: "issue_context_safe" },
  };
  const reviewGate = {
    schemaVersion: "ioi.agent-runtime.review-gate.v1",
    object: "ioi.review_gate",
    gateId: "review_gate_computer_use",
    repositoryContextId: repositoryContext.contextId,
    branchPolicyId: branchPolicy.policyId,
    githubContextId: githubContext.contextId,
    prAttemptId: prAttempt.attemptId,
    generatedAt,
    status: "blocked",
    decision: "blocked",
    repoFullName: null,
    branch: null,
    defaultBranch: null,
    reviewRequired: true,
    reviewSatisfied: false,
    approvalRequired: true,
    approvalSatisfied: false,
    requiredReviewers: [],
    requiredChecks: [],
    blockers: ["pr_attempt_not_ready"],
    warnings: [],
    mutationAllowed: false,
    prCreationAllowed: false,
    mutationExecuted: false,
    networkLookupPerformed: false,
    summary: "Review gate blocked PR creation.",
    redaction: { profile: "review_gate_safe" },
  };
  const githubPrCreatePlan = {
    schemaVersion: "ioi.agent-runtime.github-pr-create-plan.v1",
    object: "ioi.github_pr_create_plan",
    planId: "github_pr_create_plan_computer_use",
    repositoryContextId: repositoryContext.contextId,
    branchPolicyId: branchPolicy.policyId,
    githubContextId: githubContext.contextId,
    issueContextId: issueContext.contextId,
    prAttemptId: prAttempt.attemptId,
    reviewGateId: reviewGate.gateId,
    generatedAt,
    status: "blocked",
    decision: "blocked",
    dryRun: true,
    toolName: "github.create_pull_request",
    repoFullName: null,
    baseBranch: null,
    headBranch: null,
    issueNumber: null,
    reviewGateStatus: reviewGate.status,
    reviewSatisfied: false,
    request: {
      payloadHash: "hash_pr_payload",
      bodyIncluded: false,
      tokenIncluded: false,
    },
    authority: {
      requiredScopes: ["github.pr.create"],
      missingScopes: ["github.pr.create"],
      scopeGranted: false,
    },
    blockers: ["pr_attempt_not_ready"],
    warnings: [],
    mutationAttempted: false,
    mutationExecuted: false,
    networkLookupPerformed: false,
    summary: "GitHub PR create plan is blocked and remains dry-run only.",
    redaction: { profile: "github_pr_create_plan_safe" },
  };
  reviewGate.issueContextId = issueContext.contextId;
  const projectionByKind = {
    repository_context: repositoryContext,
    branch_policy: branchPolicy,
    github_context: githubContext,
    pr_attempts: [prAttempt],
    issue_context: issueContext,
    review_gate: reviewGate,
    github_pr_create_plan: githubPrCreatePlan,
  };
  return {
    source: "rust_repository_workflow_projection_api",
    status: "projected",
    operation: request.operation,
    operation_kind: request.operation_kind,
    projection_kind: request.projection_kind,
    workspace_root: workspaceRoot,
    projection: projectionByKind[request.projection_kind] ?? {},
    repository_context: repositoryContext,
    branch_policy: branchPolicy,
    github_context: githubContext,
    pr_attempt: prAttempt,
    issue_context: issueContext,
    review_gate: reviewGate,
    github_pr_create_plan: githubPrCreatePlan,
    repositories: [],
    record_count: 1,
    evidence_refs: ["runtime_repository_workflow_rust_projection"],
    receipt_refs: [`receipt_repository_workflow_projection_${request.projection_kind}`],
  };
}

function poisonJsComputerUseTruthPaths(store) {
  store.agentForThread = () => {
    throw new Error("agentForThread must not be called by computer-use public Rust lease adapter");
  };
  store.runtimeEventStream = () => {
    throw new Error("runtimeEventStream must not be read by computer-use public Rust lease adapter");
  };
}

function mountRustLeaseRequestSurface(store) {
  const calls = [];
  store.codingToolInvocationSurface = {
    invokeThreadTool(surfaceStore, threadId, toolId, request) {
      calls.push({ surfaceStore, threadId, toolId, request });
      return {
        schema_version: "ioi.runtime.coding-tool-result.v1",
        object: "ioi.runtime_coding_tool_result",
        tool_name: toolId,
        status: "completed",
        receipt_refs: ["receipt://rust/computer-use-lease"],
        result: {
          rust_workload: true,
          request_ref: "computer_use_lease_request_test",
          lease_request: {
            lane: request.input?.lane ?? null,
            session_mode: request.input?.session_mode ?? null,
            action_kind: request.input?.action_kind ?? null,
            sandbox_provider: request.input?.sandbox_provider ?? null,
          },
          thread_tool: {
            tool_pack: "computer_use",
            tool_name: request.computer_use_public_tool_id,
            input: request.input,
          },
          wallet_network_authority_boundary: {
            authority_layer: "wallet.network",
            required_before_execution: true,
            grant_refs: [],
            receipt_refs: [],
          },
          evidence_refs: [
            "rust_daemon_core_computer_use_request_lease",
            "wallet.network.authority_boundary",
          ],
          receipt_refs: ["receipt://rust/computer-use-lease"],
          shell_fallback_used: false,
        },
      };
    },
  };
  return calls;
}

test("computer-use public invocation facades route to Rust request-lease StepModule", async () => {
  await withStore(async (store) => {
    poisonJsComputerUseTruthPaths(store);
    const calls = mountRustLeaseRequestSurface(store);
    store.pathFor = () => {
      throw new Error("pathFor must not be called by computer-use public Rust lease adapter");
    };

    const request = {
      tool_call_id: "tool_alpha",
      workflow_graph_id: "graph_alpha",
    };
    const results = [
      store.invokeComputerUseBrowserDiscoveryTool(
        "thread_alpha",
        "ioi.computer_use.browser_discovery",
        request,
      ),
      store.invokeComputerUseControlTool("thread_alpha", "ioi.computer_use.control", request),
      await store.invokeComputerUseNativeBrowserTool(
        "thread_alpha",
        "ioi.computer_use.native_browser",
        request,
      ),
      await store.invokeComputerUseVisualGuiTool("thread_alpha", "ioi.computer_use.visual_gui", request),
      await store.invokeComputerUseSandboxedHostedTool(
        "thread_alpha",
        "ioi.computer_use.sandboxed_hosted",
        request,
      ),
      await store.invokeComputerUseVisualGuiObserveTool(
        "thread_alpha",
        "ioi.computer_use.visual_gui.observe",
        request,
      ),
    ];

    assert.equal(calls.length, 6);
    assert.deepEqual(
      calls.map((call) => call.toolId),
      Array(6).fill("computer_use.request_lease"),
    );
    assert.deepEqual(
      calls.map((call) => call.request.computer_use_operation_kind),
      [
        "computer_use.browser_discovery",
        "computer_use.control",
        "computer_use.native_browser",
        "computer_use.visual_gui",
        "computer_use.sandboxed_hosted",
        "computer_use.visual_gui.observe",
      ],
    );
    assert.ok(calls.every((call) => call.surfaceStore === store));
    assert.ok(calls.every((call) => call.threadId === "thread_alpha"));
    assert.ok(results.every((result) => result.status === "completed"));
    assert.ok(results.every((result) => result.result.rust_workload === true));
    assert.ok(
      results.every((result) =>
        result.result.receipt_refs.includes("receipt://rust/computer-use-lease"),
      ),
    );
    assert.ok(
      results.every(
        (result) => result.result.wallet_network_authority_boundary.authority_layer === "wallet.network",
      ),
    );
  });
});

test("computer-use public invocation adapter preserves canonical lease request fields", async () => {
  await withStore(async (store) => {
    const calls = mountRustLeaseRequestSurface(store);

    await store.invokeComputerUseNativeBrowserTool("thread_alpha", "ioi.computer_use.native_browser", {
      tool_call_id: "tool_alpha",
      workflow_graph_id: "graph_alpha",
      workflow_node_id: "node_alpha",
      input: {
        prompt: "Click the sign-in button.",
        lane: "native_browser",
        session_mode: "attached_browser",
        action_kind: "click",
        url: "https://example.test",
        target_ref: "target_alpha",
        selector: "#sign-in",
      },
    });
    await store.invokeComputerUseVisualGuiTool("thread_alpha", "ioi.computer_use.visual_gui", {
      input: {},
    });
    await store.invokeComputerUseSandboxedHostedTool("thread_alpha", "ioi.computer_use.sandboxed_hosted", {
      input: {},
    });
    store.invokeComputerUseBrowserDiscoveryTool("thread_alpha", "ioi.computer_use.browser_discovery", {
      prompt: "List governed browser sessions.",
      lane: "native_browser",
      action_kind: "inspect",
      url: "https://example.test/start",
    });

    assert.equal(calls[0].request.tool_call_id, "tool_alpha");
    assert.equal(calls[0].request.workflow_graph_id, "graph_alpha");
    assert.equal(calls[0].request.workflow_node_id, "node_alpha");
    assert.deepEqual(calls[0].request.input, {
      prompt: "Click the sign-in button.",
      lane: "native_browser",
      session_mode: "attached_browser",
      action_kind: "click",
      url: "https://example.test",
      target_ref: "target_alpha",
      selector: "#sign-in",
    });
    assert.equal(calls[1].request.input.lane, "visual_gui");
    assert.equal(calls[1].request.input.session_mode, "visual_fallback");
    assert.equal(calls[1].request.input.action_kind, "inspect");
    assert.equal(calls[2].request.input.lane, "sandboxed_hosted");
    assert.equal(calls[2].request.input.session_mode, "local_sandbox");
    assert.equal(calls[2].request.input.action_kind, "inspect");
    assert.equal(calls[2].request.input.sandbox_provider, "local_fixture");
    assert.deepEqual(calls[3].request.input, {
      prompt: "List governed browser sessions.",
      lane: "native_browser",
      action_kind: "inspect",
      url: "https://example.test/start",
    });
    for (const call of calls) {
      for (const key of [
        "toolCallId",
        "workflowGraphId",
        "workflowNodeId",
        "computerUseLane",
        "computerUseSessionMode",
        "actionKind",
        "sandboxProvider",
      ]) {
        assert.equal(Object.hasOwn(call.request, key), false, `${key} request alias must be absent`);
        assert.equal(Object.hasOwn(call.request.input, key), false, `${key} input alias must be absent`);
      }
    }
  });
});

test("computer-use run materialization is delegated to Rust run-create planning", async () => {
  const daemonCoreThreadLifecycleApi = threadLifecycleApiForComputerUseRunMaterialization();
  await withStore(async (store) => {
    const writes = [];
    store.writeRun = (run, operationKind) => {
      writes.push({ run, operationKind });
    };
    store.turnForRun = (run) => ({
      thread_id: "thread_browser",
      request_id: run.id,
      run_id: run.id,
      turn_id: run.turn_id ?? run.id,
    });
    store.agents.set("agent_browser", {
      id: "agent_browser",
      status: "active",
      runtime: "local",
      cwd: store.defaultCwd,
      modelId: "model.local",
      options: {
        mcpServerNames: [],
        skillNames: [],
        hookNames: [],
      },
      runtimeControls: {
        mode: "agent",
        approval_mode: "suggest",
      },
      createdAt: "2026-06-15T18:00:00.000Z",
      updatedAt: "2026-06-15T18:00:00.000Z",
    });

    await store.createTurn("thread_browser", {
      mode: "send",
      prompt: "Inspect the browser page without side effects.",
      metadata: {
        computer_use: true,
        computer_use_lane: "native_browser",
        computer_use_action_kind: "inspect",
        computer_use_target_ref: "target_browser",
      },
    });
    const run = writes[0].run;

    assert.equal(daemonCoreThreadLifecycleApi.calls.length, 1);
    assert.equal(run.trace.computerUse.source, "rust_daemon_core_run_create");
    assert.equal(run.trace.computerUse.lease.lane, "native_browser");
    assert.equal(Object.hasOwn(run, "computer_use_materialization_request"), false);
    assert.equal(Object.hasOwn(run, "computerUse"), false);
    assert.ok(run.events.some((event) => event.type === "computer_use_observation"));
    assert.ok(run.receipts.some((receipt) => receipt.kind === "computer_use_trace"));
    assert.ok(run.artifacts.some((artifact) => artifact.name === "computer-use-trace.json"));
    assert.deepEqual(writes, [{ run, operationKind: "run.create" }]);
  }, {
    daemonCoreRuntimeProjectionApi: repositoryWorkflowProjectionApiForComputerUseTest(),
    daemonCoreThreadLifecycleApi,
    daemonCoreThreadMemoryApi: memoryProjectionApiForComputerUseTest(),
  });
});
