import crypto from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export const CODING_TOOL_PACK_SCHEMA_VERSION = "ioi.runtime.coding-tool-pack.v1";
export const CODING_TOOL_RESULT_SCHEMA_VERSION = "ioi.runtime.coding-tool-result.v1";
export const CODING_TOOL_PACK_ID = "coding";
export const CODING_TOOL_IDS = new Set([
  "workspace.status",
  "git.diff",
  "file.inspect",
  "file.apply_patch",
  "test.run",
  "lsp.diagnostics",
  "artifact.read",
  "tool.retrieve_result",
  "computer_use.request_lease",
]);

const CODING_TOOL_DEFAULT_PREVIEW_BYTES = 16 * 1024;
const CODING_TOOL_MAX_PREVIEW_BYTES = 64 * 1024;
const CODING_TOOL_DIFF_MAX_BYTES = 64 * 1024;
const CODING_TOOL_APPLY_PATCH_MAX_FILE_BYTES = 1024 * 1024;
const CODING_TOOL_APPLY_PATCH_MAX_DIFF_BYTES = 32 * 1024;
const CODING_TOOL_APPLY_PATCH_MAX_EDITS = 20;
const CODING_TOOL_TEST_MAX_OUTPUT_BYTES = 64 * 1024;
const CODING_TOOL_TEST_MAX_TIMEOUT_MS = 5 * 60 * 1000;
const CODING_TOOL_TEST_DEFAULT_TIMEOUT_MS = 60 * 1000;
const CODING_TOOL_TEST_COMMAND_IDS = ["node.test", "npm.test", "cargo.test", "cargo.check"];
const CODING_TOOL_DIAGNOSTIC_MAX_OUTPUT_BYTES = 64 * 1024;
const CODING_TOOL_DIAGNOSTIC_MAX_TIMEOUT_MS = 2 * 60 * 1000;
const CODING_TOOL_DIAGNOSTIC_DEFAULT_TIMEOUT_MS = 30 * 1000;
const CODING_TOOL_DIAGNOSTIC_COMMAND_IDS = ["auto", "node.check", "typescript.check"];
const CODING_TOOL_ARTIFACT_MAX_READ_BYTES = 256 * 1024;
const CODING_TOOL_ARTIFACT_DEFAULT_READ_BYTES = 64 * 1024;
const NODE_CHECK_PATH_PATTERN = /\.(cjs|js|mjs)$/i;
const TYPESCRIPT_PATH_PATTERN = /\.(cts|mts|ts|tsx)$/i;
const CODING_TOOL_BUDGET_WORKFLOW_CONFIG_FIELDS = [
  "toolPack.coding.budgetMode",
  "toolPack.coding.budgetUsageField",
  "toolPack.coding.maxTotalTokens",
  "toolPack.coding.maxCostUsd",
  "toolPack.coding.maxContextPressure",
  "toolPack.coding.warnAtRatio",
];

export function codingToolContracts() {
  return [
    {
      schemaVersion: CODING_TOOL_PACK_SCHEMA_VERSION,
      stableToolId: "workspace.status",
      displayName: "Workspace status",
      pack: CODING_TOOL_PACK_ID,
      primitiveCapabilities: ["prim:workspace.status", "prim:git.status"],
      authorityScopeRequirements: [],
      effectClass: "local_read",
      riskDomain: "workspace",
      inputSchema: {
        type: "object",
        additionalProperties: false,
        properties: {
          includeIgnored: { type: "boolean" },
        },
      },
      outputSchema: {
        type: "object",
        required: ["workspaceRoot", "git", "changedFiles", "shellFallbackUsed"],
      },
      evidenceRequirements: ["workspace_status_receipt", "coding_tool_receipt"],
      workflowNodeType: "CodingToolNode",
      workflowConfigFields: [
        "toolPack.coding.workspaceStatus",
        "toolPack.coding.gitEnabled",
        ...CODING_TOOL_BUDGET_WORKFLOW_CONFIG_FIELDS,
      ],
    },
    {
      schemaVersion: CODING_TOOL_PACK_SCHEMA_VERSION,
      stableToolId: "git.diff",
      displayName: "Git diff",
      pack: CODING_TOOL_PACK_ID,
      primitiveCapabilities: ["prim:git.diff"],
      authorityScopeRequirements: [],
      effectClass: "local_read",
      riskDomain: "git",
      inputSchema: {
        type: "object",
        additionalProperties: false,
        properties: {
          path: { type: "string" },
          paths: { type: "array", items: { type: "string" } },
          maxBytes: { type: "integer", minimum: 1, maximum: CODING_TOOL_DIFF_MAX_BYTES },
        },
      },
      outputSchema: {
        type: "object",
        required: ["workspaceRoot", "paths", "diff", "diffHash", "shellFallbackUsed"],
      },
      evidenceRequirements: ["git_diff_receipt", "coding_tool_receipt"],
      workflowNodeType: "GitToolNode",
      workflowConfigFields: [
        "toolPack.coding.gitEnabled",
        "toolPack.coding.allowedPaths",
        ...CODING_TOOL_BUDGET_WORKFLOW_CONFIG_FIELDS,
      ],
    },
    {
      schemaVersion: CODING_TOOL_PACK_SCHEMA_VERSION,
      stableToolId: "file.inspect",
      displayName: "Inspect file",
      pack: CODING_TOOL_PACK_ID,
      primitiveCapabilities: ["prim:fs.inspect"],
      authorityScopeRequirements: [],
      effectClass: "local_read",
      riskDomain: "filesystem",
      inputSchema: {
        type: "object",
        required: ["path"],
        additionalProperties: false,
        properties: {
          path: { type: "string" },
          maxBytes: { type: "integer", minimum: 1, maximum: CODING_TOOL_MAX_PREVIEW_BYTES },
          previewLines: { type: "integer", minimum: 1, maximum: 500 },
        },
      },
      outputSchema: {
        type: "object",
        required: ["workspaceRoot", "path", "kind", "exists", "shellFallbackUsed"],
      },
      evidenceRequirements: ["file_inspect_receipt", "coding_tool_receipt"],
      workflowNodeType: "FilesystemToolNode",
      workflowConfigFields: [
        "toolPack.coding.filesystemEnabled",
        "toolPack.coding.allowedPaths",
        ...CODING_TOOL_BUDGET_WORKFLOW_CONFIG_FIELDS,
      ],
    },
    {
      schemaVersion: CODING_TOOL_PACK_SCHEMA_VERSION,
      stableToolId: "file.apply_patch",
      displayName: "Apply file patch",
      pack: CODING_TOOL_PACK_ID,
      primitiveCapabilities: ["prim:fs.apply_patch", "prim:fs.write"],
      authorityScopeRequirements: ["scope:workspace.write"],
      effectClass: "local_write",
      riskDomain: "filesystem",
      inputSchema: {
        type: "object",
        required: ["path"],
        additionalProperties: false,
        properties: {
          path: { type: "string" },
          dryRun: { type: "boolean" },
          create: { type: "boolean" },
          oldText: { type: "string" },
          newText: { type: "string" },
          appendText: { type: "string" },
          prependText: { type: "string" },
          occurrence: { type: "string", enum: ["only", "first", "all"] },
          diagnosticsMode: { type: "string", enum: ["advisory", "blocking", "skip"] },
          diagnosticCommandId: { type: "string", enum: CODING_TOOL_DIAGNOSTIC_COMMAND_IDS },
          diagnosticTimeoutMs: { type: "integer", minimum: 1, maximum: CODING_TOOL_DIAGNOSTIC_MAX_TIMEOUT_MS },
          diagnosticMaxOutputBytes: { type: "integer", minimum: 1, maximum: CODING_TOOL_DIAGNOSTIC_MAX_OUTPUT_BYTES },
          edits: {
            type: "array",
            maxItems: CODING_TOOL_APPLY_PATCH_MAX_EDITS,
            items: {
              type: "object",
              required: ["type"],
              additionalProperties: false,
              properties: {
                type: { type: "string", enum: ["replace", "append", "prepend"] },
                oldText: { type: "string" },
                newText: { type: "string" },
                text: { type: "string" },
                occurrence: { type: "string", enum: ["only", "first", "all"] },
              },
            },
          },
        },
      },
      outputSchema: {
        type: "object",
        required: [
          "workspaceRoot",
          "path",
          "dryRun",
          "applied",
          "changed",
          "beforeHash",
          "afterHash",
          "shellFallbackUsed",
        ],
      },
      evidenceRequirements: [
        "file_apply_patch_receipt",
        "workspace_mutation_receipt",
        "workspace_snapshot_receipt",
        "coding_tool_receipt",
      ],
      workflowNodeType: "FilesystemPatchNode",
      workflowConfigFields: [
        "toolPack.coding.filesystemEnabled",
        "toolPack.coding.writeEnabled",
        "toolPack.coding.allowedPaths",
        "toolPack.coding.dryRun",
        "toolPack.coding.diagnosticsMode",
        "toolPack.coding.defaultDiagnosticCommandId",
        "toolPack.coding.restorePolicy",
        "toolPack.coding.restoreConflictPolicy",
        "toolPack.coding.diagnosticsRepairDefault",
        "toolPack.coding.operatorOverrideRequiresApproval",
        "toolPack.coding.approvalMode",
        "toolPack.coding.trustProfile",
        "toolPack.coding.nodeApprovalOverride",
        "toolPack.coding.requiresApproval",
        ...CODING_TOOL_BUDGET_WORKFLOW_CONFIG_FIELDS,
      ],
    },
    {
      schemaVersion: CODING_TOOL_PACK_SCHEMA_VERSION,
      stableToolId: "test.run",
      displayName: "Run tests",
      pack: CODING_TOOL_PACK_ID,
      primitiveCapabilities: ["prim:test.run", "prim:process.exec_file"],
      authorityScopeRequirements: ["scope:workspace.test"],
      effectClass: "local_command",
      riskDomain: "test",
      inputSchema: {
        type: "object",
        additionalProperties: false,
        properties: {
          commandId: { type: "string", enum: CODING_TOOL_TEST_COMMAND_IDS },
          cwd: { type: "string" },
          path: { type: "string" },
          paths: { type: "array", items: { type: "string" } },
          args: { type: "array", items: { type: "string" } },
          timeoutMs: { type: "integer", minimum: 1, maximum: CODING_TOOL_TEST_MAX_TIMEOUT_MS },
          maxOutputBytes: { type: "integer", minimum: 1, maximum: CODING_TOOL_TEST_MAX_OUTPUT_BYTES },
          env: { type: "object", additionalProperties: { type: "string" } },
        },
      },
      outputSchema: {
        type: "object",
        required: [
          "workspaceRoot",
          "commandId",
          "cwd",
          "exitCode",
          "testStatus",
          "stdout",
          "stderr",
          "outputHash",
          "shellFallbackUsed",
        ],
      },
      evidenceRequirements: ["test_run_receipt", "coding_tool_receipt"],
      workflowNodeType: "TestRunNode",
      workflowConfigFields: [
        "toolPack.coding.testEnabled",
        "toolPack.coding.allowedTestCommandIds",
        "toolPack.coding.allowedPaths",
        "toolPack.coding.timeoutMs",
        "toolPack.coding.approvalMode",
        "toolPack.coding.trustProfile",
        "toolPack.coding.nodeApprovalOverride",
        "toolPack.coding.requiresApproval",
        ...CODING_TOOL_BUDGET_WORKFLOW_CONFIG_FIELDS,
      ],
    },
    {
      schemaVersion: CODING_TOOL_PACK_SCHEMA_VERSION,
      stableToolId: "lsp.diagnostics",
      displayName: "LSP diagnostics",
      pack: CODING_TOOL_PACK_ID,
      primitiveCapabilities: ["prim:lsp.diagnostics", "prim:process.exec_file"],
      authorityScopeRequirements: [],
      effectClass: "local_read",
      riskDomain: "diagnostics",
      inputSchema: {
        type: "object",
        additionalProperties: false,
        properties: {
          commandId: { type: "string", enum: CODING_TOOL_DIAGNOSTIC_COMMAND_IDS },
          cwd: { type: "string" },
          path: { type: "string" },
          paths: { type: "array", items: { type: "string" } },
          args: { type: "array", items: { type: "string" } },
          timeoutMs: { type: "integer", minimum: 1, maximum: CODING_TOOL_DIAGNOSTIC_MAX_TIMEOUT_MS },
          maxOutputBytes: { type: "integer", minimum: 1, maximum: CODING_TOOL_DIAGNOSTIC_MAX_OUTPUT_BYTES },
        },
      },
      outputSchema: {
        type: "object",
        required: [
          "workspaceRoot",
          "commandId",
          "resolvedCommandId",
          "backend",
          "diagnosticStatus",
          "diagnostics",
          "diagnosticCount",
          "outputHash",
          "shellFallbackUsed",
        ],
      },
      evidenceRequirements: ["lsp_diagnostics_receipt", "coding_tool_receipt"],
      workflowNodeType: "LspDiagnosticsNode",
      workflowConfigFields: [
        "toolPack.coding.diagnosticsEnabled",
        "toolPack.coding.allowedDiagnosticCommandIds",
        "toolPack.coding.diagnosticsMode",
        "toolPack.coding.defaultDiagnosticCommandId",
        "toolPack.coding.restorePolicy",
        "toolPack.coding.restoreConflictPolicy",
        "toolPack.coding.diagnosticsRepairDefault",
        "toolPack.coding.operatorOverrideRequiresApproval",
        "toolPack.coding.allowedPaths",
        "toolPack.coding.timeoutMs",
        ...CODING_TOOL_BUDGET_WORKFLOW_CONFIG_FIELDS,
      ],
    },
    {
      schemaVersion: CODING_TOOL_PACK_SCHEMA_VERSION,
      stableToolId: "artifact.read",
      displayName: "Read artifact",
      pack: CODING_TOOL_PACK_ID,
      primitiveCapabilities: ["prim:artifact.read"],
      authorityScopeRequirements: [],
      effectClass: "local_read",
      riskDomain: "artifact",
      inputSchema: {
        type: "object",
        required: ["artifactId"],
        additionalProperties: false,
        properties: {
          artifactId: { type: "string" },
          artifactRef: { type: "string" },
          offsetBytes: { type: "integer", minimum: 0 },
          lengthBytes: { type: "integer", minimum: 1, maximum: CODING_TOOL_ARTIFACT_MAX_READ_BYTES },
          maxBytes: { type: "integer", minimum: 1, maximum: CODING_TOOL_ARTIFACT_MAX_READ_BYTES },
        },
      },
      outputSchema: {
        type: "object",
        required: ["artifactId", "offsetBytes", "lengthBytes", "content", "contentHash", "shellFallbackUsed"],
      },
      evidenceRequirements: ["artifact_read_receipt", "coding_tool_receipt"],
      workflowNodeType: "ArtifactReadNode",
      workflowConfigFields: [
        "toolPack.coding.artifactEnabled",
        "toolPack.coding.resultRetrievalEnabled",
        ...CODING_TOOL_BUDGET_WORKFLOW_CONFIG_FIELDS,
      ],
    },
    {
      schemaVersion: CODING_TOOL_PACK_SCHEMA_VERSION,
      stableToolId: "tool.retrieve_result",
      displayName: "Retrieve tool result",
      pack: CODING_TOOL_PACK_ID,
      primitiveCapabilities: ["prim:tool.retrieve_result", "prim:artifact.read"],
      authorityScopeRequirements: [],
      effectClass: "local_read",
      riskDomain: "artifact",
      inputSchema: {
        type: "object",
        additionalProperties: false,
        properties: {
          toolCallId: { type: "string" },
          artifactId: { type: "string" },
          artifactRef: { type: "string" },
          channel: { type: "string" },
          offsetBytes: { type: "integer", minimum: 0 },
          lengthBytes: { type: "integer", minimum: 1, maximum: CODING_TOOL_ARTIFACT_MAX_READ_BYTES },
          maxBytes: { type: "integer", minimum: 1, maximum: CODING_TOOL_ARTIFACT_MAX_READ_BYTES },
        },
      },
      outputSchema: {
        type: "object",
        required: ["toolCallId", "artifactId", "content", "contentHash", "shellFallbackUsed"],
      },
      evidenceRequirements: ["tool_result_retrieval_receipt", "artifact_read_receipt", "coding_tool_receipt"],
      workflowNodeType: "ToolResultRetrievalNode",
      workflowConfigFields: [
        "toolPack.coding.resultRetrievalEnabled",
        "toolPack.coding.artifactEnabled",
        ...CODING_TOOL_BUDGET_WORKFLOW_CONFIG_FIELDS,
      ],
    },
    {
      schemaVersion: CODING_TOOL_PACK_SCHEMA_VERSION,
      stableToolId: "computer_use.request_lease",
      displayName: "Request computer-use lease",
      pack: CODING_TOOL_PACK_ID,
      primitiveCapabilities: ["prim:computer_use.lease.request", "prim:computer_use.manifest"],
      authorityScopeRequirements: ["computer_use.lease.request"],
      effectClass: "local_read",
      riskDomain: "computer_use",
      inputSchema: {
        type: "object",
        required: ["prompt"],
        additionalProperties: false,
        properties: {
          prompt: { type: "string" },
          lane: { type: "string", enum: ["native_browser", "visual_gui", "sandboxed_hosted"] },
          sessionMode: { type: "string" },
          session_mode: { type: "string" },
          actionKind: { type: "string" },
          action_kind: { type: "string" },
          url: { type: "string" },
          targetRef: { type: "string" },
          target_ref: { type: "string" },
          selector: { type: "string" },
          approvalRef: { type: "string" },
          approval_ref: { type: "string" },
          observationRetentionMode: { type: "string" },
          observation_retention_mode: { type: "string" },
        },
      },
      outputSchema: {
        type: "object",
        required: ["requestRef", "leaseRequest", "threadTool"],
      },
      evidenceRequirements: ["computer_use_lease_request_receipt", "coding_tool_receipt"],
      workflowNodeType: "ComputerUseLeaseRequestNode",
      workflowConfigFields: [
        "toolPack.coding.computerUseLeaseRequest",
        "computerUse.lane",
        "computerUse.sessionMode",
        "computerUse.actionKind",
        "computerUse.approvalPolicy",
        ...CODING_TOOL_BUDGET_WORKFLOW_CONFIG_FIELDS,
      ],
    },
  ];
}

export function codingToolInputForRequest(request = {}) {
  if (!request || typeof request !== "object" || Array.isArray(request)) return {};
  const input = Object.hasOwn(request, "input") ? request.input : request;
  if (!input || typeof input !== "object" || Array.isArray(input)) return {};
  return input;
}

export function executeCodingTool(toolId, workspaceRoot, input = {}, context = {}) {
  switch (toolId) {
    case "workspace.status":
      return workspaceStatusTool(workspaceRoot, input);
    case "git.diff":
      return gitDiffTool(workspaceRoot, input);
    case "file.inspect":
      return fileInspectTool(workspaceRoot, input);
    case "file.apply_patch":
      return fileApplyPatchTool(workspaceRoot, input);
    case "test.run":
      return testRunTool(workspaceRoot, input);
    case "lsp.diagnostics":
      return lspDiagnosticsTool(workspaceRoot, input);
    case "artifact.read":
      return artifactReadTool(input, context);
    case "tool.retrieve_result":
      return toolRetrieveResultTool(input, context);
    case "computer_use.request_lease":
      return computerUseLeaseRequestTool(workspaceRoot, input);
    default:
      throw codingToolError(404, "not_found", `Coding tool not found: ${toolId}`, {
        toolId,
        pack: CODING_TOOL_PACK_ID,
      });
  }
}

export function codingToolInputSummary(toolId, input = {}) {
  if (toolId === "file.inspect") return { path: optionalString(input.path) ?? null };
  if (toolId === "file.apply_patch") {
    return {
      path: optionalString(input.path) ?? null,
      dryRun: Boolean(input.dryRun ?? input.dry_run),
      editCount: normalizePatchEdits(input).length,
    };
  }
  if (toolId === "test.run") {
    return {
      commandId: optionalString(input.commandId ?? input.command_id) ?? "node.test",
      paths: codingToolRawPathSummary(input),
      cwd: optionalString(input.cwd) ?? ".",
      timeoutMs: input.timeoutMs ?? input.timeout_ms ?? null,
    };
  }
  if (toolId === "lsp.diagnostics") {
    return {
      commandId: optionalString(input.commandId ?? input.command_id) ?? "auto",
      paths: codingToolRawPathSummary(input),
      cwd: optionalString(input.cwd) ?? ".",
      timeoutMs: input.timeoutMs ?? input.timeout_ms ?? null,
    };
  }
  if (toolId === "artifact.read") {
    return {
      artifactId: optionalString(input.artifactId ?? input.artifact_id ?? input.artifactRef ?? input.artifact_ref) ?? null,
      offsetBytes: Number(input.offsetBytes ?? input.offset_bytes ?? 0),
      lengthBytes: input.lengthBytes ?? input.length_bytes ?? input.maxBytes ?? input.max_bytes ?? null,
    };
  }
  if (toolId === "tool.retrieve_result") {
    return {
      toolCallId: optionalString(input.toolCallId ?? input.tool_call_id) ?? null,
      artifactId: optionalString(input.artifactId ?? input.artifact_id ?? input.artifactRef ?? input.artifact_ref) ?? null,
      channel: optionalString(input.channel) ?? null,
    };
  }
  if (toolId === "computer_use.request_lease") {
    return {
      lane: computerUseLaneForInput(input),
      sessionMode: computerUseSessionModeForInput(input),
      actionKind: computerUseActionKindForInput(input),
      url: optionalString(input.url) ?? null,
    };
  }
  if (toolId === "git.diff") return { paths: codingToolRawPathSummary(input) };
  if (toolId === "workspace.status") {
    return { includeIgnored: Boolean(input.includeIgnored ?? input.include_ignored) };
  }
  return {};
}

export function codingToolResultSummary(toolId, result = {}) {
  if (toolId === "workspace.status") {
    return {
      changed: Number(result?.counts?.changed ?? 0),
      branch: result?.git?.branch ?? null,
      gitAvailable: Boolean(result?.git?.available),
    };
  }
  if (toolId === "git.diff") {
    return {
      paths: normalizeArray(result?.paths),
      diffBytes: Number(result?.diffBytes ?? 0),
      truncated: Boolean(result?.truncated),
    };
  }
  if (toolId === "file.inspect") {
    return {
      path: result?.path ?? null,
      kind: result?.kind ?? null,
      sizeBytes: Number(result?.sizeBytes ?? 0),
      truncated: Boolean(result?.truncated),
    };
  }
  if (toolId === "file.apply_patch") {
    return {
      path: result?.path ?? null,
      dryRun: Boolean(result?.dryRun),
      applied: Boolean(result?.applied),
      changed: Boolean(result?.changed),
      editCount: Number(result?.editCount ?? 0),
      changedFileCount: normalizeArray(result?.changedFiles).length,
      workspaceSnapshotId: result?.workspaceSnapshotId ?? result?.workspace_snapshot_id ?? null,
    };
  }
  if (toolId === "test.run") {
    return {
      commandId: result?.commandId ?? null,
      testStatus: result?.testStatus ?? null,
      exitCode: Number(result?.exitCode ?? 0),
      durationMs: Number(result?.durationMs ?? 0),
      truncated: Boolean(result?.truncated),
      spilloverRecommended: Boolean(result?.spilloverRecommended),
    };
  }
  if (toolId === "lsp.diagnostics") {
    return {
      commandId: result?.commandId ?? null,
      resolvedCommandId: result?.resolvedCommandId ?? null,
      backend: result?.backend ?? null,
      diagnosticStatus: result?.diagnosticStatus ?? null,
      diagnosticCount: Number(result?.diagnosticCount ?? 0),
      backendStatus: result?.backendStatus ?? null,
      fallbackUsed: Boolean(result?.fallbackUsed),
      truncated: Boolean(result?.truncated),
      spilloverRecommended: Boolean(result?.spilloverRecommended),
    };
  }
  if (toolId === "artifact.read") {
    return {
      artifactId: result?.artifactId ?? null,
      offsetBytes: Number(result?.offsetBytes ?? 0),
      lengthBytes: Number(result?.lengthBytes ?? 0),
      truncated: Boolean(result?.truncated),
    };
  }
  if (toolId === "tool.retrieve_result") {
    return {
      toolCallId: result?.toolCallId ?? null,
      artifactId: result?.artifactId ?? null,
      offsetBytes: Number(result?.offsetBytes ?? 0),
      lengthBytes: Number(result?.lengthBytes ?? 0),
      truncated: Boolean(result?.truncated),
    };
  }
  if (toolId === "computer_use.request_lease") {
    return {
      requestRef: result?.requestRef ?? null,
      lane: result?.leaseRequest?.lane ?? null,
      sessionMode: result?.leaseRequest?.sessionMode ?? null,
      actionKind: result?.leaseRequest?.actionKind ?? null,
      approvalRequiredBeforeExecution: Boolean(result?.approvalRequiredBeforeExecution),
    };
  }
  return {};
}

export function codingToolSummary(toolId, result = {}, status = "completed") {
  if (status === "failed") return `${toolId} failed.`;
  if (toolId === "workspace.status") {
    return `Workspace status inspected ${Number(result?.counts?.changed ?? 0)} changed file(s).`;
  }
  if (toolId === "git.diff") {
    return `Git diff inspected ${Number(result?.diffBytes ?? 0)} byte(s).`;
  }
  if (toolId === "file.inspect") {
    return `Inspected ${result?.kind ?? "path"} ${result?.path ?? ""}`.trim();
  }
  if (toolId === "file.apply_patch") {
    if (result?.dryRun) return `Patch previewed ${result?.path ?? "file"}.`;
    return result?.changed
      ? `Patch applied to ${result?.path ?? "file"}.`
      : `Patch checked ${result?.path ?? "file"} with no content change.`;
  }
  if (toolId === "test.run") {
    return `Test run ${result?.testStatus ?? "completed"} with exit code ${Number(result?.exitCode ?? 0)}.`;
  }
  if (toolId === "lsp.diagnostics") {
    return `Diagnostics ${result?.diagnosticStatus ?? "completed"} with ${Number(result?.diagnosticCount ?? 0)} finding(s).`;
  }
  if (toolId === "artifact.read") {
    return `Read artifact ${result?.artifactId ?? "artifact"}.`;
  }
  if (toolId === "tool.retrieve_result") {
    return `Retrieved tool result ${result?.toolCallId ?? result?.artifactId ?? "artifact"}.`;
  }
  if (toolId === "computer_use.request_lease") {
    return `Recorded computer-use lease request ${result?.requestRef ?? ""}`.trim();
  }
  return `${toolId} completed.`;
}

export function codingToolSourceEventKind(toolId) {
  return `CodingTool.${toolId
    .split(/[._-]/)
    .map((part) => part.slice(0, 1).toUpperCase() + part.slice(1))
    .join("")}`;
}

function computerUseLeaseRequestTool(workspaceRoot, input = {}) {
  const prompt = optionalString(input.prompt ?? input.goal ?? input.objective) ??
    "Coding agent requested a governed computer-use lease.";
  const lane = computerUseLaneForInput(input);
  const sessionMode = computerUseSessionModeForInput(input);
  const actionKind = computerUseActionKindForInput(input);
  const approvalRef = optionalString(input.approvalRef ?? input.approval_ref) ?? null;
  const requestSeed = JSON.stringify({
    workspaceRoot,
    prompt,
    lane,
    sessionMode,
    actionKind,
    url: optionalString(input.url) ?? null,
    targetRef: optionalString(input.targetRef ?? input.target_ref) ?? null,
    selector: optionalString(input.selector) ?? null,
  });
  const requestRef = `computer_use_lease_request_${hashText(requestSeed).slice(0, 16)}`;
  const authorityScope =
    actionKind === "inspect" || actionKind === "hover" || actionKind === "wait" || actionKind === "scroll"
      ? `computer_use.${lane}.read`
      : `computer_use.${lane}.act`;
  const threadToolName = lane === "native_browser" ? "ioi.computer_use.native_browser" : null;
  const threadToolInput = {
    prompt,
    url: optionalString(input.url) ?? null,
    actionKind,
    sessionMode,
    targetRef: optionalString(input.targetRef ?? input.target_ref) ?? null,
    selector: optionalString(input.selector) ?? null,
    approvalRef,
    observationRetentionMode:
      optionalString(input.observationRetentionMode ?? input.observation_retention_mode) ??
      "prompt_visible_summary_only",
  };
  return {
    schemaVersion: CODING_TOOL_RESULT_SCHEMA_VERSION,
    object: "ioi.coding_agent_computer_use_lease_request",
    requestRef,
    workspaceRoot,
    leaseRequest: {
      prompt,
      lane,
      sessionMode,
      actionKind,
      authorityScope,
      repoAuthorityScope: "workspace.read",
      sharedClipboardPolicy: "disabled_until_explicit_approval",
      artifactPolicy: "redacted_trace_artifacts_only",
      approvalRef,
      failClosedWhenUnavailable: true,
    },
    threadTool: {
      toolPack: "computer_use",
      toolName: threadToolName,
      unavailableReason: threadToolName
        ? null
        : "Requested lane is recorded as a governed lease request; concrete visual/hosted execution adapter is not mounted yet.",
      input: threadToolInput,
    },
    approvalRequiredBeforeExecution: authorityScope.endsWith(".act") && !approvalRef,
    evidenceRefs: [
      requestRef,
      "computer_use_lease_request_receipt",
      "coding_tool_receipt",
    ],
    shellFallbackUsed: false,
  };
}

function computerUseLaneForInput(input = {}) {
  const value = optionalString(input.lane ?? input.computerUseLane ?? input.computer_use_lane);
  if (value === "visual_gui" || value === "sandboxed_hosted") return value;
  return "native_browser";
}

function computerUseSessionModeForInput(input = {}) {
  const value = optionalString(input.sessionMode ?? input.session_mode);
  if (value) return value;
  const lane = computerUseLaneForInput(input);
  if (lane === "visual_gui") return "visual_fallback";
  if (lane === "sandboxed_hosted") return "hosted_sandbox";
  return "owned_hermetic_browser";
}

function computerUseActionKindForInput(input = {}) {
  const value = optionalString(input.actionKind ?? input.action_kind)?.toLowerCase().replace(/[\s-]+/g, "_");
  if (!value) return "inspect";
  if (value === "type" || value === "input_text") return "type_text";
  if (value === "keypress") return "key_press";
  if ([
    "click",
    "type_text",
    "key_press",
    "scroll",
    "drag",
    "hover",
    "select",
    "upload",
    "clipboard",
    "wait",
    "shell",
    "mobile_gesture",
    "navigate",
    "inspect",
  ].includes(value)) return value;
  return "inspect";
}

function workspaceStatusTool(workspaceRoot, input = {}) {
  const includeIgnored = Boolean(input.includeIgnored ?? input.include_ignored);
  const args = ["status", "--short", "--branch", "--untracked-files=all"];
  if (includeIgnored) args.push("--ignored");
  const status = execGitReadOnly(workspaceRoot, args);
  if (!status.ok) {
    return {
      schemaVersion: CODING_TOOL_RESULT_SCHEMA_VERSION,
      workspaceRoot,
      git: {
        available: false,
        status: "not_git_repository",
        error: status.stderr || status.stdout || "git status failed",
      },
      changedFiles: [],
      counts: { changed: 0, untracked: 0, ignored: 0 },
      shellFallbackUsed: false,
    };
  }
  const lines = status.stdout.split(/\r?\n/).filter(Boolean);
  const branch = lines.find((line) => line.startsWith("##"))?.replace(/^##\s*/, "") ?? null;
  const changedFiles = lines
    .filter((line) => !line.startsWith("##"))
    .map((line) => ({
      status: line.slice(0, 2).trim() || "modified",
      path: line.slice(3).trim(),
    }))
    .filter((entry) => entry.path);
  const counts = changedFiles.reduce(
    (acc, entry) => {
      acc.changed += 1;
      if (entry.status.includes("?")) acc.untracked += 1;
      if (entry.status.includes("!")) acc.ignored += 1;
      return acc;
    },
    { changed: 0, untracked: 0, ignored: 0 },
  );
  return {
    schemaVersion: CODING_TOOL_RESULT_SCHEMA_VERSION,
    workspaceRoot,
    git: {
      available: true,
      branch,
      porcelainHash: hashText(status.stdout),
    },
    changedFiles,
    counts,
    shellFallbackUsed: false,
  };
}

function gitDiffTool(workspaceRoot, input = {}) {
  const paths = codingToolPaths(workspaceRoot, input);
  const maxBytes = boundedInteger(
    input.maxBytes ?? input.max_bytes,
    CODING_TOOL_DIFF_MAX_BYTES,
    1,
    CODING_TOOL_DIFF_MAX_BYTES,
  );
  const args = ["diff", "--", ...paths.map((entry) => entry.relativePath)];
  const diffResult = execGitReadOnly(workspaceRoot, args);
  if (!diffResult.ok) {
    throw codingToolError(400, "git_diff_failed", "git diff failed for the requested workspace path(s).", {
      workspaceRoot,
      paths: paths.map((entry) => entry.relativePath),
      error: diffResult.stderr || diffResult.stdout,
    });
  }
  const statResult = execGitReadOnly(workspaceRoot, [
    "diff",
    "--stat",
    "--",
    ...paths.map((entry) => entry.relativePath),
  ]);
  const preview = utf8Preview(diffResult.stdout, maxBytes);
  return {
    schemaVersion: CODING_TOOL_RESULT_SCHEMA_VERSION,
    workspaceRoot,
    paths: paths.map((entry) => entry.relativePath),
    git: { available: true },
    diff: preview.text,
    diffBytes: Buffer.byteLength(diffResult.stdout, "utf8"),
    diffHash: hashText(diffResult.stdout),
    truncated: preview.truncated,
    stat: statResult.ok ? statResult.stdout : "",
    shellFallbackUsed: false,
  };
}

function fileInspectTool(workspaceRoot, input = {}) {
  const selectedPath = optionalString(input.path);
  if (!selectedPath) {
    throw codingToolError(400, "file_inspect_path_required", "file.inspect requires a workspace-relative path.", {
      toolId: "file.inspect",
    });
  }
  const target = resolveWorkspacePath(workspaceRoot, selectedPath);
  if (!fs.existsSync(target.absolutePath)) {
    throw codingToolError(404, "not_found", `File not found: ${target.relativePath}`, {
      workspaceRoot,
      path: target.relativePath,
    });
  }
  const stat = fs.statSync(target.absolutePath);
  if (stat.isDirectory()) {
    const entries = fs
      .readdirSync(target.absolutePath, { withFileTypes: true })
      .slice(0, 100)
      .map((entry) => ({
        name: entry.name,
        kind: entry.isDirectory() ? "directory" : entry.isFile() ? "file" : "other",
      }));
    return {
      schemaVersion: CODING_TOOL_RESULT_SCHEMA_VERSION,
      workspaceRoot,
      path: target.relativePath,
      kind: "directory",
      exists: true,
      sizeBytes: stat.size,
      entries,
      entryCount: entries.length,
      shellFallbackUsed: false,
    };
  }
  if (!stat.isFile()) {
    return {
      schemaVersion: CODING_TOOL_RESULT_SCHEMA_VERSION,
      workspaceRoot,
      path: target.relativePath,
      kind: "other",
      exists: true,
      sizeBytes: stat.size,
      shellFallbackUsed: false,
    };
  }
  const maxBytes = boundedInteger(
    input.maxBytes ?? input.max_bytes,
    CODING_TOOL_DEFAULT_PREVIEW_BYTES,
    1,
    CODING_TOOL_MAX_PREVIEW_BYTES,
  );
  const previewLines = boundedInteger(input.previewLines ?? input.preview_lines, 200, 1, 500);
  const bytesToRead = Math.min(stat.size, maxBytes);
  const buffer = Buffer.alloc(bytesToRead);
  const fd = fs.openSync(target.absolutePath, "r");
  let bytesRead = 0;
  try {
    bytesRead = fs.readSync(fd, buffer, 0, bytesToRead, 0);
  } finally {
    fs.closeSync(fd);
  }
  const preview = buffer.subarray(0, bytesRead).toString("utf8");
  const lines = preview.split(/\r?\n/);
  const linePreview = lines.slice(0, previewLines).join("\n");
  return {
    schemaVersion: CODING_TOOL_RESULT_SCHEMA_VERSION,
    workspaceRoot,
    path: target.relativePath,
    kind: "file",
    exists: true,
    sizeBytes: stat.size,
    preview: linePreview,
    previewBytes: Buffer.byteLength(linePreview, "utf8"),
    previewHash: hashText(linePreview),
    truncated: bytesRead < stat.size || lines.length > previewLines,
    previewLineCount: Math.min(lines.length, previewLines),
    shellFallbackUsed: false,
  };
}

function fileApplyPatchTool(workspaceRoot, input = {}) {
  const selectedPath = optionalString(input.path);
  if (!selectedPath) {
    throw codingToolError(400, "file_apply_patch_path_required", "file.apply_patch requires a workspace-relative path.", {
      toolId: "file.apply_patch",
    });
  }
  const target = resolveWorkspacePath(workspaceRoot, selectedPath);
  const dryRun = Boolean(input.dryRun ?? input.dry_run);
  const create = Boolean(input.create);
  const exists = fs.existsSync(target.absolutePath);
  const beforeStat = exists ? fs.statSync(target.absolutePath) : null;
  if (!exists && !create) {
    throw codingToolError(404, "not_found", `File not found: ${target.relativePath}`, {
      workspaceRoot,
      path: target.relativePath,
    });
  }
  if (exists) {
    if (!beforeStat.isFile()) {
      throw codingToolError(400, "file_apply_patch_not_file", "file.apply_patch can only edit regular files.", {
        workspaceRoot,
        path: target.relativePath,
      });
    }
    if (beforeStat.size > CODING_TOOL_APPLY_PATCH_MAX_FILE_BYTES) {
      throw codingToolError(413, "file_apply_patch_file_too_large", "file.apply_patch refused a file over the edit size limit.", {
        workspaceRoot,
        path: target.relativePath,
        sizeBytes: beforeStat.size,
        maxBytes: CODING_TOOL_APPLY_PATCH_MAX_FILE_BYTES,
      });
    }
  } else {
    const parent = path.dirname(target.absolutePath);
    if (!fs.existsSync(parent) || !fs.statSync(parent).isDirectory()) {
      throw codingToolError(404, "file_apply_patch_parent_missing", "file.apply_patch create mode requires an existing parent directory.", {
        workspaceRoot,
        path: target.relativePath,
      });
    }
  }
  const before = exists ? fs.readFileSync(target.absolutePath, "utf8") : "";
  const edits = normalizePatchEdits(input);
  if (!edits.length) {
    throw codingToolError(400, "file_apply_patch_empty", "file.apply_patch requires at least one edit.", {
      workspaceRoot,
      path: target.relativePath,
    });
  }
  const appliedEdits = [];
  let after = before;
  for (const edit of edits) {
    const applied = applyPatchEdit(after, edit, target.relativePath);
    after = applied.text;
    appliedEdits.push(applied.summary);
  }
  const beforeHash = hashText(before);
  const afterHash = hashText(after);
  const changed = beforeHash !== afterHash;
  const diff = textDiffPreview(target.relativePath, before, after, CODING_TOOL_APPLY_PATCH_MAX_DIFF_BYTES);
  if (!dryRun && changed) {
    fs.writeFileSync(target.absolutePath, after, "utf8");
  }
  const afterStat = !dryRun && fs.existsSync(target.absolutePath) ? fs.statSync(target.absolutePath) : null;
  const beforeBytes = Buffer.byteLength(before, "utf8");
  const afterBytes = Buffer.byteLength(after, "utf8");
  return {
    schemaVersion: CODING_TOOL_RESULT_SCHEMA_VERSION,
    workspaceRoot,
    path: target.relativePath,
    dryRun,
    applied: !dryRun && changed,
    changed,
    created: !exists,
    editCount: appliedEdits.length,
    edits: appliedEdits,
    beforeHash,
    afterHash,
    diff: diff.text,
    diffBytes: diff.bytes,
    diffHash: hashText(diff.text),
    truncated: diff.truncated,
    changedFiles: changed
      ? [
          {
            path: target.relativePath,
            beforeHash,
            afterHash,
            beforeExists: exists,
            afterExists: !dryRun ? true : exists,
            beforeSizeBytes: exists ? beforeBytes : 0,
            afterSizeBytes: afterBytes,
            beforeMtimeMs: exists ? Math.round(beforeStat.mtimeMs) : null,
            afterMtimeMs: afterStat ? Math.round(afterStat.mtimeMs) : null,
            created: !exists,
            diagnosticsRecommended: !dryRun,
          },
        ]
      : [],
    workspaceSnapshotDrafts: changed && !dryRun
      ? [
          {
            path: target.relativePath,
            encoding: "utf8",
            beforeExists: exists,
            afterExists: true,
            beforeContent: exists ? before : null,
            afterContent: after,
          },
        ]
      : [],
    diagnosticsRecommended: Boolean(changed && !dryRun),
    receiptRefs: [
      `receipt_file_apply_patch_${safeReceiptPath(target.relativePath)}_${afterHash.slice(0, 12)}`,
    ],
    shellFallbackUsed: false,
  };
}

function testRunTool(workspaceRoot, input = {}) {
  const commandId = optionalString(input.commandId ?? input.command_id) ?? "node.test";
  const runCwd = resolveWorkspaceDirectory(workspaceRoot, optionalString(input.cwd) ?? ".");
  const timeoutMs = boundedInteger(
    input.timeoutMs ?? input.timeout_ms,
    CODING_TOOL_TEST_DEFAULT_TIMEOUT_MS,
    1,
    CODING_TOOL_TEST_MAX_TIMEOUT_MS,
  );
  const maxOutputBytes = boundedInteger(
    input.maxOutputBytes ?? input.max_output_bytes,
    CODING_TOOL_TEST_MAX_OUTPUT_BYTES,
    1,
    CODING_TOOL_TEST_MAX_OUTPUT_BYTES,
  );
  const command = testCommandForInput(commandId, workspaceRoot, runCwd, input);
  const extraArgs = normalizeStringArray(input.args).slice(0, 100);
  const args = [...command.args, ...extraArgs];
  const startedAt = Date.now();
  const run = execFileCaptured(command.executable, args, {
    cwd: runCwd.absolutePath,
    timeoutMs,
    env: sanitizeTestEnv(input.env),
  });
  const durationMs = Date.now() - startedAt;
  const stdoutPreview = utf8Preview(run.stdout, maxOutputBytes);
  const stderrPreview = utf8Preview(run.stderr, maxOutputBytes);
  const outputBytes = Buffer.byteLength(run.stdout, "utf8") + Buffer.byteLength(run.stderr, "utf8");
  const outputHash = hashText(`${run.stdout}\n${run.stderr}`);
  const truncated = stdoutPreview.truncated || stderrPreview.truncated;
  const testStatus = run.timedOut ? "timed_out" : run.exitCode === 0 ? "passed" : "failed";
  const artifactDrafts = truncated
    ? [
        {
          name: "test-run-output.txt",
          channel: "output",
          mediaType: "text/plain",
          content: `${run.stdout}\n${run.stderr}`,
        },
        {
          name: "test-run-stdout.txt",
          channel: "stdout",
          mediaType: "text/plain",
          content: run.stdout,
        },
        {
          name: "test-run-stderr.txt",
          channel: "stderr",
          mediaType: "text/plain",
          content: run.stderr,
        },
      ]
    : [];
  return {
    schemaVersion: CODING_TOOL_RESULT_SCHEMA_VERSION,
    workspaceRoot,
    commandId,
    command: command.displayCommand,
    executable: command.executable,
    args,
    cwd: runCwd.relativePath,
    exitCode: run.exitCode,
    signal: run.signal,
    testStatus,
    timedOut: run.timedOut,
    durationMs,
    timeoutMs,
    stdout: stdoutPreview.text,
    stderr: stderrPreview.text,
    stdoutBytes: Buffer.byteLength(run.stdout, "utf8"),
    stderrBytes: Buffer.byteLength(run.stderr, "utf8"),
    outputBytes,
    outputHash,
    truncated,
    spilloverRecommended: truncated,
    artifactDrafts,
    allowedCommandIds: CODING_TOOL_TEST_COMMAND_IDS,
    receiptRefs: [`receipt_test_run_${safeReceiptPath(commandId)}_${outputHash.slice(0, 12)}`],
    shellFallbackUsed: false,
  };
}

function lspDiagnosticsTool(workspaceRoot, input = {}) {
  const commandId = optionalString(input.commandId ?? input.command_id) ?? "auto";
  const runCwd = resolveWorkspaceDirectory(workspaceRoot, optionalString(input.cwd) ?? ".");
  const timeoutMs = boundedInteger(
    input.timeoutMs ?? input.timeout_ms,
    CODING_TOOL_DIAGNOSTIC_DEFAULT_TIMEOUT_MS,
    1,
    CODING_TOOL_DIAGNOSTIC_MAX_TIMEOUT_MS,
  );
  const maxOutputBytes = boundedInteger(
    input.maxOutputBytes ?? input.max_output_bytes,
    CODING_TOOL_DIAGNOSTIC_MAX_OUTPUT_BYTES,
    1,
    CODING_TOOL_DIAGNOSTIC_MAX_OUTPUT_BYTES,
  );
  const paths = codingToolPaths(workspaceRoot, input);
  if (!paths.length) {
    throw codingToolError(400, "lsp_diagnostics_path_required", "lsp.diagnostics requires path or paths.", {
      toolId: "lsp.diagnostics",
    });
  }
  const diagnosticPlan = diagnosticsPlanForInput({
    commandId,
    workspaceRoot,
    runCwd,
    paths,
    input,
  });
  const startedAt = Date.now();
  const diagnosticRun = executeDiagnosticsPlan(diagnosticPlan, workspaceRoot, runCwd, paths, timeoutMs, input);
  const durationMs = Date.now() - startedAt;
  const stdoutPreview = utf8Preview(diagnosticRun.stdout, maxOutputBytes);
  const stderrPreview = utf8Preview(diagnosticRun.stderr, maxOutputBytes);
  const outputHash = hashText(`${diagnosticRun.stdout}\n${diagnosticRun.stderr}`);
  const truncated = stdoutPreview.truncated || stderrPreview.truncated;
  const artifactDrafts = truncated
    ? [
        {
          name: "diagnostics-output.txt",
          channel: "diagnostics",
          mediaType: "text/plain",
          content: `${diagnosticRun.stdout}\n${diagnosticRun.stderr}`,
        },
      ]
    : [];
  const receiptRefs = [
    `receipt_lsp_diagnostics_${safeReceiptPath(diagnosticRun.backend)}_${outputHash.slice(0, 12)}`,
    ...(diagnosticRun.backendStatus === "degraded"
      ? [
          `receipt_lsp_diagnostics_degraded_${safeReceiptPath(diagnosticRun.backendReason ?? diagnosticRun.backend)}_${outputHash.slice(0, 12)}`,
        ]
      : []),
    ...(diagnosticRun.fallbackUsed
      ? [
          `receipt_lsp_diagnostics_fallback_${safeReceiptPath(diagnosticRun.fallbackFrom ?? diagnosticRun.backend)}_${outputHash.slice(0, 12)}`,
        ]
      : []),
  ];
  return {
    schemaVersion: CODING_TOOL_RESULT_SCHEMA_VERSION,
    workspaceRoot,
    commandId,
    requestedCommandId: diagnosticPlan.requestedCommandId,
    resolvedCommandId: diagnosticRun.resolvedCommandId,
    command: diagnosticRun.displayCommand,
    cwd: runCwd.relativePath,
    backend: diagnosticRun.backend,
    backendStatus: diagnosticRun.backendStatus,
    backendReason: diagnosticRun.backendReason ?? null,
    fallbackUsed: Boolean(diagnosticRun.fallbackUsed),
    fallbackFrom: diagnosticRun.fallbackFrom ?? null,
    projectContext: diagnosticRun.projectContext ?? diagnosticPlan.projectContext,
    diagnosticStatus: diagnosticRun.diagnosticStatus,
    diagnostics: diagnosticRun.diagnostics,
    diagnosticCount: diagnosticRun.diagnostics.length,
    paths: paths.map((entry) => entry.relativePath),
    exitCode: diagnosticRun.exitCode,
    timedOut: diagnosticRun.timedOut,
    durationMs,
    timeoutMs,
    stdout: stdoutPreview.text,
    stderr: stderrPreview.text,
    outputBytes: Buffer.byteLength(diagnosticRun.stdout, "utf8") + Buffer.byteLength(diagnosticRun.stderr, "utf8"),
    outputHash,
    truncated,
    spilloverRecommended: truncated,
    artifactDrafts,
    allowedCommandIds: CODING_TOOL_DIAGNOSTIC_COMMAND_IDS,
    receiptRefs,
    shellFallbackUsed: false,
  };
}

function nodeCheckDiagnostics(workspaceRoot, runCwd, paths, timeoutMs) {
  const diagnostics = [];
  const outputs = [];
  let exitCode = 0;
  let timedOut = false;
  let unsupportedCount = 0;
  for (const target of paths) {
    if (!NODE_CHECK_PATH_PATTERN.test(target.relativePath)) {
      unsupportedCount += 1;
      diagnostics.push({
        path: target.relativePath,
        severity: "warning",
        source: "node.check",
        code: "unsupported_path",
        message: "node.check only supports .js, .mjs, and .cjs files.",
        line: null,
        column: null,
      });
      continue;
    }
    const run = execFileCaptured(process.execPath, ["--check", target.absolutePath], {
      cwd: runCwd.absolutePath,
      timeoutMs,
      env: {},
    });
    outputs.push({ target, run });
    exitCode = Math.max(exitCode, Number(run.exitCode ?? 0));
    timedOut = timedOut || Boolean(run.timedOut);
    if (run.exitCode !== 0 || run.timedOut) {
      diagnostics.push(...nodeCheckOutputDiagnostics(target, run));
    }
  }
  const stdout = outputs.map(({ run }) => run.stdout).filter(Boolean).join("\n");
  const stderr = outputs
    .map(({ target, run }) => [`# ${target.relativePath}`, run.stderr].filter(Boolean).join("\n"))
    .filter(Boolean)
    .join("\n");
  const backendStatus =
    unsupportedCount === paths.length ? "degraded" : timedOut ? "timed_out" : "available";
  return {
    backend: "node.check",
    backendStatus,
    backendReason: backendStatus === "degraded" ? "unsupported_path" : null,
    resolvedCommandId: "node.check",
    fallbackUsed: false,
    displayCommand: "node --check",
    stdout,
    stderr,
    exitCode: timedOut ? 124 : exitCode,
    timedOut,
    diagnostics,
    diagnosticStatus:
      backendStatus === "degraded" ? "degraded" : diagnostics.some((item) => item.severity === "error") ? "findings" : "clean",
  };
}

function nodeCheckOutputDiagnostics(target, run) {
  if (run.timedOut) {
    return [
      {
        path: target.relativePath,
        severity: "error",
        source: "node.check",
        code: "timeout",
        message: "node.check timed out.",
        line: null,
        column: null,
      },
    ];
  }
  const stderr = String(run.stderr ?? "");
  const lines = stderr.split(/\r?\n/);
  const location = lines.find((line) => line.startsWith(target.absolutePath));
  const locationMatch = location?.match(/:(\d+)(?::(\d+))?$/);
  const message =
    lines.find((line) => /^(SyntaxError|TypeError|ReferenceError|Error):/.test(line.trim()))?.trim() ??
    stderr.trim().split(/\r?\n/).filter(Boolean).at(-1) ??
    "node.check reported a diagnostic.";
  const caretIndex = lines.findIndex((line) => /^\s*\^+\s*$/.test(line));
  const column = caretIndex > 0 ? Math.max(1, lines[caretIndex].indexOf("^") + 1) : Number(locationMatch?.[2] ?? 0) || null;
  return [
    {
      path: target.relativePath,
      severity: "error",
      source: "node.check",
      code: message.split(":")[0]?.toLowerCase().replace(/[^a-z0-9]+/g, "_") || "diagnostic",
      message,
      line: Number(locationMatch?.[1] ?? 0) || null,
      column,
    },
  ];
}

function diagnosticsPlanForInput({ commandId, workspaceRoot, runCwd, paths, input = {} } = {}) {
  if (!CODING_TOOL_DIAGNOSTIC_COMMAND_IDS.includes(commandId)) {
    throw codingToolError(403, "lsp_diagnostics_command_not_allowed", "lsp.diagnostics commandId is not allowlisted.", {
      commandId,
      allowedCommandIds: CODING_TOOL_DIAGNOSTIC_COMMAND_IDS,
    });
  }
  const projectContext = diagnosticsProjectContext(workspaceRoot, runCwd, paths);
  const hasTypescriptPath = paths.some((entry) => TYPESCRIPT_PATH_PATTERN.test(entry.relativePath));
  const executable = localTscExecutable(workspaceRoot, projectContext.projectRootAbsolutePath ?? runCwd.absolutePath);
  const tsconfigPath = projectContext.tsconfigAbsolutePath;
  if (commandId === "auto") {
    if (hasTypescriptPath && tsconfigPath && executable) {
      return {
        requestedCommandId: commandId,
        resolvedCommandId: "typescript.check",
        backend: "typescript.project.check",
        executable,
        tsconfigPath,
        projectContext: { ...projectContext, tscAvailable: true },
        fallbackUsed: false,
      };
    }
    if (hasTypescriptPath && tsconfigPath && !executable) {
      return {
        requestedCommandId: commandId,
        resolvedCommandId: "node.check",
        backend: "node.check",
        projectContext: { ...projectContext, tscAvailable: false },
        fallbackUsed: true,
        fallbackFrom: "typescript.project.check",
        fallbackReason: "typescript_executable_missing",
      };
    }
    return {
      requestedCommandId: commandId,
      resolvedCommandId: "node.check",
      backend: "node.check",
      projectContext: { ...projectContext, tscAvailable: Boolean(executable) },
      fallbackUsed: false,
    };
  }
  if (commandId === "node.check") {
    return {
      requestedCommandId: commandId,
      resolvedCommandId: "node.check",
      backend: "node.check",
      projectContext: { ...projectContext, tscAvailable: Boolean(executable) },
      fallbackUsed: false,
    };
  }
  return {
    requestedCommandId: commandId,
    resolvedCommandId: "typescript.check",
    backend: tsconfigPath ? "typescript.project.check" : "typescript.file.check",
    executable,
    tsconfigPath,
    projectContext: { ...projectContext, tscAvailable: Boolean(executable) },
    fallbackUsed: false,
  };
}

function executeDiagnosticsPlan(plan, workspaceRoot, runCwd, paths, timeoutMs, input = {}) {
  if (plan.resolvedCommandId === "node.check") {
    const run = nodeCheckDiagnostics(workspaceRoot, runCwd, paths, timeoutMs);
    if (!plan.fallbackUsed) {
      return {
        ...run,
        requestedCommandId: plan.requestedCommandId,
        projectContext: plan.projectContext,
      };
    }
    return {
      ...run,
      requestedCommandId: plan.requestedCommandId,
      projectContext: plan.projectContext,
      backendStatus: "degraded",
      backendReason: plan.fallbackReason,
      fallbackUsed: true,
      fallbackFrom: plan.fallbackFrom,
      diagnosticStatus: run.diagnosticStatus === "clean" ? "degraded" : run.diagnosticStatus,
    };
  }
  return typescriptDiagnostics(workspaceRoot, runCwd, paths, timeoutMs, input, plan);
}

function diagnosticsProjectContext(workspaceRoot, runCwd, paths) {
  const tsconfigPaths = uniqueStrings(
    paths
      .map((entry) => findNearestFile(path.dirname(entry.absolutePath), "tsconfig.json", workspaceRoot))
      .filter(Boolean),
  );
  const tsconfigAbsolutePath =
    tsconfigPaths[0] ?? findNearestFile(runCwd.absolutePath, "tsconfig.json", workspaceRoot);
  const projectRootAbsolutePath = tsconfigAbsolutePath ? path.dirname(tsconfigAbsolutePath) : runCwd.absolutePath;
  const packageJsonPath = findNearestFile(projectRootAbsolutePath, "package.json", workspaceRoot);
  const packageRootAbsolutePath = packageJsonPath ? path.dirname(packageJsonPath) : null;
  return {
    schemaVersion: "ioi.runtime.diagnostics-project-context.v1",
    projectRoot: path.relative(workspaceRoot, projectRootAbsolutePath) || ".",
    projectRootAbsolutePath,
    tsconfigPath: tsconfigAbsolutePath ? path.relative(workspaceRoot, tsconfigAbsolutePath) || "tsconfig.json" : null,
    tsconfigAbsolutePath: tsconfigAbsolutePath ?? null,
    tsconfigPaths: tsconfigPaths.map((item) => path.relative(workspaceRoot, item) || "tsconfig.json"),
    packageRoot: packageRootAbsolutePath ? path.relative(workspaceRoot, packageRootAbsolutePath) || "." : null,
    packageManager: packageRootAbsolutePath ? packageManagerForDirectory(packageRootAbsolutePath) : null,
    pathCount: paths.length,
  };
}

function typescriptDiagnostics(workspaceRoot, runCwd, paths, timeoutMs, input = {}, plan = {}) {
  const executable = plan.executable ?? localTscExecutable(workspaceRoot, plan.projectContext?.projectRootAbsolutePath ?? runCwd.absolutePath);
  if (!executable) {
    return {
      backend: plan.backend ?? "typescript.check",
      backendStatus: "degraded",
      backendReason: "typescript_executable_missing",
      resolvedCommandId: "typescript.check",
      fallbackUsed: false,
      projectContext: plan.projectContext ?? diagnosticsProjectContext(workspaceRoot, runCwd, paths),
      displayCommand: "tsc --noEmit --pretty false",
      stdout: "",
      stderr: "typescript.check degraded: local node_modules/.bin/tsc was not found.",
      exitCode: 0,
      timedOut: false,
      diagnostics: [],
      diagnosticStatus: "degraded",
    };
  }
  const extraArgs = normalizeStringArray(input.args).slice(0, 100);
  const projectArgs = plan.tsconfigPath
    ? ["-p", path.relative(runCwd.absolutePath, plan.tsconfigPath) || "tsconfig.json"]
    : [];
  const pathArgs = plan.tsconfigPath
    ? []
    : paths.map((entry) => path.relative(runCwd.absolutePath, entry.absolutePath) || ".");
  const args = ["--noEmit", "--pretty", "false", ...projectArgs, ...pathArgs, ...extraArgs];
  const run = execFileCaptured(executable, args, { cwd: runCwd.absolutePath, timeoutMs, env: {} });
  const diagnostics = run.exitCode === 0 && !run.timedOut
    ? []
    : typescriptOutputDiagnostics(workspaceRoot, runCwd, `${run.stdout}\n${run.stderr}`);
  if (run.timedOut && diagnostics.length === 0) {
    diagnostics.push({
      path: plan.projectContext?.tsconfigPath ?? paths[0]?.relativePath ?? null,
      severity: "error",
      source: "typescript.check",
      code: "timeout",
      message: "typescript.check timed out.",
      line: null,
      column: null,
    });
  }
  return {
    backend: plan.backend ?? "typescript.check",
    backendStatus: run.timedOut ? "timed_out" : "available",
    backendReason: null,
    resolvedCommandId: "typescript.check",
    fallbackUsed: false,
    projectContext: plan.projectContext ?? diagnosticsProjectContext(workspaceRoot, runCwd, paths),
    displayCommand: plan.tsconfigPath
      ? "tsc --noEmit --pretty false -p tsconfig.json"
      : "tsc --noEmit --pretty false",
    stdout: run.stdout,
    stderr: run.stderr,
    exitCode: run.exitCode,
    timedOut: run.timedOut,
    diagnostics,
    diagnosticStatus: run.timedOut || diagnostics.length ? "findings" : "clean",
  };
}

function typescriptOutputDiagnostics(workspaceRoot, runCwd, output) {
  return String(output ?? "")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const match = line.match(/^(.+?)\((\d+),(\d+)\):\s+error\s+(TS\d+):\s+(.+)$/);
      if (!match) return null;
      const relativePath = normalizeDiagnosticPath(workspaceRoot, runCwd, match[1]);
      return {
        path: relativePath,
        severity: "error",
        source: "typescript.check",
        code: match[4],
        message: match[5],
        line: Number(match[2]),
        column: Number(match[3]),
      };
    })
    .filter(Boolean);
}

function normalizeDiagnosticPath(workspaceRoot, runCwd, diagnosticPath) {
  const normalized = String(diagnosticPath ?? "").replaceAll("\\", "/");
  const absolutePath = path.isAbsolute(normalized)
    ? path.resolve(normalized)
    : path.resolve(runCwd.absolutePath, normalized);
  const relativePath = path.relative(workspaceRoot, absolutePath);
  if (isInsidePath(workspaceRoot, absolutePath)) {
    return relativePath.replaceAll("\\", "/") || ".";
  }
  return normalized;
}

function findNearestFile(startDirectory, fileName, workspaceRoot) {
  const root = path.resolve(workspaceRoot);
  let current = path.resolve(startDirectory);
  if (!isInsidePath(root, current)) current = root;
  while (isInsidePath(root, current)) {
    const candidate = path.join(current, fileName);
    if (fs.existsSync(candidate)) return candidate;
    if (current === root) break;
    current = path.dirname(current);
  }
  return null;
}

function packageManagerForDirectory(directory) {
  if (fs.existsSync(path.join(directory, "pnpm-lock.yaml"))) return "pnpm";
  if (fs.existsSync(path.join(directory, "yarn.lock"))) return "yarn";
  if (fs.existsSync(path.join(directory, "bun.lockb"))) return "bun";
  if (fs.existsSync(path.join(directory, "package-lock.json"))) return "npm";
  if (fs.existsSync(path.join(directory, "package.json"))) return "npm";
  return null;
}

function localTscExecutable(workspaceRoot, preferredDirectory = workspaceRoot) {
  const executableName = process.platform === "win32" ? "tsc.cmd" : "tsc";
  const root = path.resolve(workspaceRoot);
  let current = path.resolve(preferredDirectory);
  if (!isInsidePath(root, current)) current = root;
  while (isInsidePath(root, current)) {
    const executable = path.join(current, "node_modules", ".bin", executableName);
    if (fs.existsSync(executable)) return executable;
    if (current === root) break;
    current = path.dirname(current);
  }
  return null;
}

function isInsidePath(rootPath, candidatePath) {
  const relativePath = path.relative(path.resolve(rootPath), path.resolve(candidatePath));
  return relativePath === "" || (!relativePath.startsWith("..") && !path.isAbsolute(relativePath));
}

function artifactReadTool(input = {}, context = {}) {
  if (typeof context.readArtifact !== "function") {
    throw codingToolError(501, "artifact_read_unavailable", "artifact.read requires a daemon artifact store.", {
      toolId: "artifact.read",
    });
  }
  const artifactId = optionalString(input.artifactId ?? input.artifact_id ?? input.artifactRef ?? input.artifact_ref);
  if (!artifactId) {
    throw codingToolError(400, "artifact_read_id_required", "artifact.read requires artifactId or artifactRef.", {
      toolId: "artifact.read",
    });
  }
  return context.readArtifact(artifactId, artifactReadRange(input));
}

function toolRetrieveResultTool(input = {}, context = {}) {
  if (typeof context.retrieveToolResult !== "function") {
    throw codingToolError(501, "tool_retrieve_result_unavailable", "tool.retrieve_result requires a daemon artifact store.", {
      toolId: "tool.retrieve_result",
    });
  }
  const toolCallId = optionalString(input.toolCallId ?? input.tool_call_id);
  const artifactId = optionalString(input.artifactId ?? input.artifact_id ?? input.artifactRef ?? input.artifact_ref);
  if (!toolCallId && !artifactId) {
    throw codingToolError(
      400,
      "tool_retrieve_result_target_required",
      "tool.retrieve_result requires toolCallId or artifactId.",
      { toolId: "tool.retrieve_result" },
    );
  }
  return context.retrieveToolResult({
    toolCallId,
    artifactId,
    channel: optionalString(input.channel),
    range: artifactReadRange(input),
  });
}

function artifactReadRange(input = {}) {
  return {
    offsetBytes: boundedInteger(input.offsetBytes ?? input.offset_bytes, 0, 0, Number.MAX_SAFE_INTEGER),
    lengthBytes: boundedInteger(
      input.lengthBytes ?? input.length_bytes ?? input.maxBytes ?? input.max_bytes,
      CODING_TOOL_ARTIFACT_DEFAULT_READ_BYTES,
      1,
      CODING_TOOL_ARTIFACT_MAX_READ_BYTES,
    ),
  };
}

function codingToolPaths(workspaceRoot, input = {}) {
  const rawPaths = [
    ...codingToolPathList(input.paths),
    ...codingToolPathList(input.path),
  ].map((value) => optionalString(value)).filter(Boolean);
  return rawPaths.length
    ? rawPaths.map((selectedPath) => resolveWorkspacePath(workspaceRoot, selectedPath))
    : [];
}

function codingToolPathList(value) {
  if (Array.isArray(value)) return value;
  const text = optionalString(value);
  return text ? [text] : [];
}

function resolveWorkspacePath(workspaceRoot, selectedPath) {
  const root = path.resolve(workspaceRoot);
  const absolutePath = path.isAbsolute(selectedPath)
    ? path.resolve(selectedPath)
    : path.resolve(root, selectedPath);
  const relativePath = path.relative(root, absolutePath) || ".";
  if (relativePath.startsWith("..") || path.isAbsolute(relativePath)) {
    throw codingToolError(403, "policy", "Coding tool path must stay inside the workspace root.", {
      workspaceRoot: root,
      path: selectedPath,
    });
  }
  return { absolutePath, relativePath };
}

function resolveWorkspaceDirectory(workspaceRoot, selectedPath) {
  const target = resolveWorkspacePath(workspaceRoot, selectedPath);
  if (!fs.existsSync(target.absolutePath) || !fs.statSync(target.absolutePath).isDirectory()) {
    throw codingToolError(404, "test_run_cwd_missing", "test.run cwd must be an existing workspace directory.", {
      workspaceRoot,
      cwd: target.relativePath,
    });
  }
  return target;
}

function execGitReadOnly(workspaceRoot, args) {
  try {
    return {
      ok: true,
      stdout: execFileSync("git", ["-C", workspaceRoot, ...args], {
        encoding: "utf8",
        maxBuffer: 4 * 1024 * 1024,
        stdio: ["ignore", "pipe", "pipe"],
      }),
      stderr: "",
      exitCode: 0,
    };
  } catch (error) {
    return {
      ok: false,
      stdout: String(error?.stdout ?? ""),
      stderr: String(error?.stderr ?? error?.message ?? ""),
      exitCode: Number(error?.status ?? error?.code ?? 1),
    };
  }
}

function boundedInteger(value, fallback, min, max) {
  const number = Number(value ?? fallback);
  if (!Number.isFinite(number)) return fallback;
  return Math.max(min, Math.min(max, Math.trunc(number)));
}

function utf8Preview(text, maxBytes) {
  const buffer = Buffer.from(String(text ?? ""), "utf8");
  if (buffer.byteLength <= maxBytes) {
    return { text: String(text ?? ""), truncated: false };
  }
  return {
    text: buffer.subarray(0, maxBytes).toString("utf8"),
    truncated: true,
  };
}

function codingToolRawPathSummary(input = {}) {
  return [
    ...codingToolPathList(input.paths),
    ...codingToolPathList(input.path),
  ].map((value) => optionalString(value)).filter(Boolean);
}

function normalizeArray(value) {
  return Array.isArray(value) ? value.filter(Boolean) : [];
}

function uniqueStrings(values) {
  return [...new Set(normalizeArray(values).map((value) => String(value)).filter(Boolean))];
}

function normalizePatchEdits(input = {}) {
  const edits = Array.isArray(input.edits) ? input.edits.slice(0, CODING_TOOL_APPLY_PATCH_MAX_EDITS) : [];
  if (Object.hasOwn(input, "oldText") || Object.hasOwn(input, "old_text")) {
    edits.push({
      type: "replace",
      oldText: input.oldText ?? input.old_text,
      newText: input.newText ?? input.new_text ?? "",
      occurrence: input.occurrence,
    });
  }
  if (Object.hasOwn(input, "appendText") || Object.hasOwn(input, "append_text")) {
    edits.push({ type: "append", text: input.appendText ?? input.append_text ?? "" });
  }
  if (Object.hasOwn(input, "prependText") || Object.hasOwn(input, "prepend_text")) {
    edits.push({ type: "prepend", text: input.prependText ?? input.prepend_text ?? "" });
  }
  return edits
    .map((edit) => (edit && typeof edit === "object" && !Array.isArray(edit) ? edit : null))
    .filter(Boolean)
    .slice(0, CODING_TOOL_APPLY_PATCH_MAX_EDITS);
}

function applyPatchEdit(text, edit, relativePath) {
  const type = optionalString(edit.type);
  if (type === "append") {
    const addition = String(edit.text ?? "");
    return {
      text: `${text}${addition}`,
      summary: { type, bytesAdded: Buffer.byteLength(addition, "utf8") },
    };
  }
  if (type === "prepend") {
    const addition = String(edit.text ?? "");
    return {
      text: `${addition}${text}`,
      summary: { type, bytesAdded: Buffer.byteLength(addition, "utf8") },
    };
  }
  if (type !== "replace") {
    throw codingToolError(400, "file_apply_patch_unknown_edit", `Unsupported edit type for ${relativePath}.`, {
      path: relativePath,
      type,
    });
  }
  const oldText = String(edit.oldText ?? edit.old_text ?? "");
  const newText = String(edit.newText ?? edit.new_text ?? "");
  if (!oldText) {
    throw codingToolError(400, "file_apply_patch_empty_old_text", "Replace edits require non-empty oldText.", {
      path: relativePath,
    });
  }
  const occurrence = optionalString(edit.occurrence) ?? "only";
  const count = countOccurrences(text, oldText);
  if (count === 0) {
    throw codingToolError(409, "file_apply_patch_old_text_missing", "file.apply_patch could not find oldText.", {
      path: relativePath,
      occurrence,
    });
  }
  if (occurrence === "only" && count !== 1) {
    throw codingToolError(409, "file_apply_patch_old_text_ambiguous", "file.apply_patch oldText matched more than once.", {
      path: relativePath,
      matches: count,
    });
  }
  const nextText =
    occurrence === "all"
      ? text.split(oldText).join(newText)
      : text.replace(oldText, newText);
  return {
    text: nextText,
    summary: {
      type,
      occurrence,
      matches: occurrence === "all" ? count : 1,
      oldHash: hashText(oldText),
      newHash: hashText(newText),
    },
  };
}

function countOccurrences(text, needle) {
  if (!needle) return 0;
  let count = 0;
  let index = 0;
  while (index <= text.length) {
    const found = text.indexOf(needle, index);
    if (found === -1) break;
    count += 1;
    index = found + needle.length;
  }
  return count;
}

function textDiffPreview(relativePath, before, after, maxBytes) {
  if (before === after) return { text: "", bytes: 0, truncated: false };
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-coding-tool-diff-"));
  const beforePath = path.join(tmpRoot, "before");
  const afterPath = path.join(tmpRoot, "after");
  try {
    fs.writeFileSync(beforePath, before, "utf8");
    fs.writeFileSync(afterPath, after, "utf8");
    const diffResult = execFileReadOnly("git", [
      "diff",
      "--no-index",
      "--no-color",
      "--",
      beforePath,
      afterPath,
    ]);
    const raw = diffResult.stdout || diffResult.stderr || "";
    const labeled = raw
      .replaceAll(beforePath, `a/${relativePath}`)
      .replaceAll(afterPath, `b/${relativePath}`);
    const preview = utf8Preview(labeled, maxBytes);
    return {
      text: preview.text,
      bytes: Buffer.byteLength(labeled, "utf8"),
      truncated: preview.truncated,
    };
  } finally {
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  }
}

function execFileReadOnly(command, args) {
  try {
    return {
      ok: true,
      stdout: execFileSync(command, args, {
        encoding: "utf8",
        maxBuffer: 4 * 1024 * 1024,
        stdio: ["ignore", "pipe", "pipe"],
      }),
      stderr: "",
      exitCode: 0,
    };
  } catch (error) {
    return {
      ok: false,
      stdout: String(error?.stdout ?? ""),
      stderr: String(error?.stderr ?? error?.message ?? ""),
      exitCode: Number(error?.status ?? error?.code ?? 1),
    };
  }
}

function execFileCaptured(command, args, options = {}) {
  const env = { ...process.env, ...(options.env ?? {}) };
  for (const key of Object.keys(env)) {
    if (key.startsWith("NODE_TEST")) delete env[key];
  }
  const result = spawnSync(command, args, {
    cwd: options.cwd,
    encoding: "utf8",
    env,
    maxBuffer: 4 * 1024 * 1024,
    shell: false,
    stdio: ["ignore", "pipe", "pipe"],
    timeout: options.timeoutMs,
  });
  const timedOut = String(result.error?.code ?? "") === "ETIMEDOUT";
  return {
    ok: !result.error && Number(result.status ?? 0) === 0,
    stdout: String(result.stdout ?? ""),
    stderr: String(result.stderr ?? result.error?.message ?? ""),
    exitCode: timedOut ? 124 : Number(result.status ?? 1),
    signal: result.signal ?? null,
    timedOut,
  };
}

function testCommandForInput(commandId, workspaceRoot, runCwd, input = {}) {
  const paths = codingToolPaths(workspaceRoot, input);
  switch (commandId) {
    case "node.test": {
      const pathArgs = paths.map((entry) => path.relative(runCwd.absolutePath, entry.absolutePath) || ".");
      return {
        executable: process.execPath,
        displayCommand: "node --test",
        args: ["--test", ...pathArgs],
      };
    }
    case "npm.test":
      return {
        executable: "npm",
        displayCommand: "npm test",
        args: ["test"],
      };
    case "cargo.test":
      return {
        executable: "cargo",
        displayCommand: "cargo test",
        args: ["test"],
      };
    case "cargo.check":
      return {
        executable: "cargo",
        displayCommand: "cargo check",
        args: ["check"],
      };
    default:
      throw codingToolError(403, "test_run_command_not_allowed", "test.run commandId is not allowlisted.", {
        commandId,
        allowedCommandIds: CODING_TOOL_TEST_COMMAND_IDS,
      });
  }
}

function normalizeStringArray(value) {
  if (!Array.isArray(value)) return [];
  return value.map((item) => optionalString(item)).filter(Boolean);
}

function sanitizeTestEnv(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  return Object.fromEntries(
    Object.entries(value)
      .filter(([key, item]) => /^[A-Z_][A-Z0-9_]*$/i.test(key) && typeof item === "string")
      .slice(0, 40),
  );
}

function optionalString(value) {
  if (value === undefined || value === null) return undefined;
  const text = String(value).trim();
  return text ? text : undefined;
}

function hashText(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

function safeReceiptPath(value) {
  return String(value).replace(/[^a-zA-Z0-9._-]+/g, "_").slice(0, 48) || "file";
}

function codingToolError(status, code, message, details) {
  const error = new Error(message);
  error.status = status;
  error.code = code;
  error.details = details;
  return error;
}
