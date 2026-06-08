#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { startRuntimeDaemonService } from "../../packages/runtime-daemon/src/index.mjs";

const outputPath = process.argv[2];
if (!outputPath) {
  throw new Error("usage: workflow-sandbox-boundary-proof.mjs <output-path>");
}

process.env.IOI_STAGE11_SECRET_TOKEN = "stage11-secret-do-not-leak";
process.env.STAGE11_PUBLIC_MARKER = "stage11-public-ok";

async function fetchJson(url, options) {
  const response = await fetch(url, {
    headers: { "content-type": "application/json" },
    ...options,
  });
  const body = await response.json();
  assert.ok(response.ok, `${response.status} ${response.statusText} for ${url}: ${JSON.stringify(body)}`);
  return body;
}

async function fetchSseEvents(url) {
  const response = await fetch(url);
  const text = await response.text();
  assert.ok(response.ok, `${response.status} ${response.statusText} for ${url}: ${text}`);
  return text
    .trim()
    .split(/\n\n+/)
    .filter(Boolean)
    .map((block) => {
      const data = block
        .split(/\r?\n/)
        .filter((line) => line.startsWith("data:"))
        .map((line) => line.replace(/^data:\s?/, ""))
        .join("\n");
      return JSON.parse(data);
    });
}

function read(filePath) {
  return fs.readFileSync(filePath, "utf8");
}

const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-stage11-workspace-"));
const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-stage11-state-"));
const outsideRoot = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-stage11-outside-"));
const outsideSecret = path.join(outsideRoot, "outside-secret.txt");
const outsideSecretBefore = "outside secret stays outside\n";
const symlinkFile = path.join(cwd, "outside-link.txt");
const symlinkDir = path.join(cwd, "outside-dir");
const envTestPath = path.join(cwd, "env-boundary.test.mjs");

fs.writeFileSync(outsideSecret, outsideSecretBefore, "utf8");
fs.symlinkSync(outsideSecret, symlinkFile);
fs.symlinkSync(outsideRoot, symlinkDir, "dir");
fs.writeFileSync(
  envTestPath,
  [
    'import test from "node:test";',
    'import assert from "node:assert/strict";',
    'test("secret-shaped env is scrubbed but public env remains", () => {',
    "  assert.equal(process.env.IOI_STAGE11_SECRET_TOKEN, undefined);",
    '  assert.equal(process.env.STAGE11_PUBLIC_MARKER, "stage11-public-ok");',
    "});",
    "",
  ].join("\n"),
  "utf8",
);

const daemon = await startRuntimeDaemonService({ cwd, stateDir });

try {
  const workflowGraphId = "workflow.react-flow.sandbox-boundary";
  const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
    method: "POST",
    body: JSON.stringify({
      source: "react_flow",
      goal: "Prove sandbox boundary path, shell allowlist, network approval, and env filtering contracts.",
      options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
    }),
  });
  const mode = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/mode`, {
    method: "POST",
    body: JSON.stringify({
      source: "react_flow",
      workflowGraphId,
      workflowNodeId: "runtime.thread-mode.yolo.sandbox-boundary",
      mode: "yolo",
      approvalMode: "never_prompt",
    }),
  });
  assert.equal(mode.mode, "yolo");
  assert.equal(mode.approval_mode, "never_prompt");

  const invoke = (toolId, workflowNodeId, input, extraBody = {}) =>
    fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/tools/${toolId}/invoke`, {
      method: "POST",
      body: JSON.stringify({
        source: "react_flow",
        workflowGraphId,
        workflowNodeId,
        toolCallId: `coding_tool_${workflowNodeId.replace(/[^a-z0-9]+/gi, "_")}`,
        input,
        ...extraBody,
      }),
    });

  const lexicalEscape = await invoke(
    "file.inspect",
    "workflow.sandbox.file.inspect.lexical-escape",
    { path: path.relative(cwd, outsideSecret) },
  );
  const absoluteEscape = await invoke(
    "file.inspect",
    "workflow.sandbox.file.inspect.absolute-escape",
    { path: outsideSecret },
  );
  const symlinkReadEscape = await invoke(
    "file.inspect",
    "workflow.sandbox.file.inspect.symlink-escape",
    { path: "outside-link.txt" },
  );
  const symlinkWriteEscape = await invoke(
    "file.apply_patch",
    "workflow.sandbox.file.apply-patch.symlink-escape",
    {
      path: "outside-link.txt",
      oldText: "outside secret stays outside",
      newText: "outside secret leaked",
    },
  );
  const disallowedShell = await invoke(
    "test.run",
    "workflow.sandbox.test-run.disallowed-command",
    { commandId: "curl", args: ["https://example.com"] },
  );
  const symlinkCwd = await invoke(
    "test.run",
    "workflow.sandbox.test-run.symlink-cwd",
    { commandId: "node.test", cwd: "outside-dir" },
  );
  const envFiltered = await invoke(
    "test.run",
    "workflow.sandbox.test-run.env-filter",
    { commandId: "node.test", path: "env-boundary.test.mjs" },
  );
  const computerUseActLease = await invoke(
    "computer_use.request_lease",
    "workflow.sandbox.computer-use.network-approval",
    {
      prompt: "Navigate to https://example.com only after approval.",
      lane: "native_browser",
      actionKind: "navigate",
      url: "https://example.com",
    },
  );

  assert.equal(read(outsideSecret), outsideSecretBefore);
  assert.equal(lexicalEscape.status, "failed");
  assert.equal(absoluteEscape.status, "failed");
  assert.equal(symlinkReadEscape.status, "failed");
  assert.equal(symlinkWriteEscape.status, "failed");
  assert.equal(disallowedShell.error?.code, "test_run_command_not_allowed");
  assert.equal(symlinkCwd.error?.code, "policy");
  assert.equal(envFiltered.status, "completed");
  assert.equal(envFiltered.result?.testStatus, "passed");
  assert.equal(JSON.stringify(envFiltered).includes("stage11-secret-do-not-leak"), false);
  assert.equal(computerUseActLease.status, "completed");
  assert.equal(computerUseActLease.result?.approvalRequiredBeforeExecution, true);
  assert.equal(computerUseActLease.result?.leaseRequest?.authorityScope, "computer_use.native_browser.act");

  const events = await fetchSseEvents(`${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`);
  const failedPolicyEvents = events.filter(
    (event) => event.event_kind === "tool.failed" && event.payload_summary?.error?.code === "policy",
  );
  const completedEnvEvent = events.find(
    (event) => event.workflow_node_id === "workflow.sandbox.test-run.env-filter",
  );
  const leaseEvent = events.find(
    (event) => event.workflow_node_id === "workflow.sandbox.computer-use.network-approval",
  );

  const checks = {
    lexical_path_escape_denied: lexicalEscape.error?.code === "policy",
    absolute_path_escape_denied: absoluteEscape.error?.code === "policy",
    symlink_read_escape_denied: symlinkReadEscape.error?.code === "policy",
    symlink_write_escape_denied: symlinkWriteEscape.error?.code === "policy" && read(outsideSecret) === outsideSecretBefore,
    disallowed_shell_network_command_denied: disallowedShell.error?.code === "test_run_command_not_allowed",
    symlink_cwd_denied_before_shell_execution: symlinkCwd.error?.code === "policy",
    secret_env_filtered_from_subprocess:
      envFiltered.status === "completed" &&
      envFiltered.result?.testStatus === "passed" &&
      !JSON.stringify(envFiltered).includes("stage11-secret-do-not-leak"),
    public_env_still_available_for_builds:
      envFiltered.status === "completed" &&
      envFiltered.result?.testStatus === "passed",
    computer_use_act_requires_approval_before_execution:
      computerUseActLease.result?.approvalRequiredBeforeExecution === true &&
      computerUseActLease.result?.leaseRequest?.authorityScope === "computer_use.native_browser.act",
    runtime_timeline_carries_boundary_failures:
      failedPolicyEvents.length >= 4 &&
      completedEnvEvent?.event_kind === "tool.completed" &&
      leaseEvent?.event_kind === "tool.completed",
  };

  const proof = {
    schema_version: "workflow.sandbox-boundary-proof.v1",
    scenario: "linux_path_shell_network_env_boundary",
    passed: Object.values(checks).every(Boolean),
    started_at: new Date().toISOString(),
    workspace_root: cwd,
    state_dir: stateDir,
    outside_root: outsideRoot,
    thread_id: thread.thread_id,
    workflow_graph_id: workflowGraphId,
    results: {
      lexical_escape: { status: lexicalEscape.status, error_code: lexicalEscape.error?.code ?? null },
      absolute_escape: { status: absoluteEscape.status, error_code: absoluteEscape.error?.code ?? null },
      symlink_read_escape: {
        status: symlinkReadEscape.status,
        error_code: symlinkReadEscape.error?.code ?? null,
        resolved_path: symlinkReadEscape.error?.details?.resolvedPath ?? null,
      },
      symlink_write_escape: {
        status: symlinkWriteEscape.status,
        error_code: symlinkWriteEscape.error?.code ?? null,
        outside_content_preserved: read(outsideSecret) === outsideSecretBefore,
      },
      disallowed_shell: { status: disallowedShell.status, error_code: disallowedShell.error?.code ?? null },
      symlink_cwd: { status: symlinkCwd.status, error_code: symlinkCwd.error?.code ?? null },
      env_filtered: {
        status: envFiltered.status,
        test_status: envFiltered.result?.testStatus ?? null,
        secret_value_present_in_result: JSON.stringify(envFiltered).includes("stage11-secret-do-not-leak"),
      },
      computer_use_act_lease: {
        status: computerUseActLease.status,
        request_ref: computerUseActLease.result?.requestRef ?? null,
        approval_required_before_execution: computerUseActLease.result?.approvalRequiredBeforeExecution ?? null,
        authority_scope: computerUseActLease.result?.leaseRequest?.authorityScope ?? null,
      },
    },
    event_counts: {
      total: events.length,
      policy_failures: failedPolicyEvents.length,
    },
    checks,
    source_refs: [
      "packages/runtime-daemon/src/coding-tools.mjs:resolveWorkspacePath",
      "packages/runtime-daemon/src/coding-tools.mjs:execFileCaptured",
      "packages/runtime-daemon/src/coding-tools.mjs:computerUseLeaseRequestTool",
      "scripts/lib/workflow-sandbox-boundary-proof.mjs",
    ],
  };
  fs.writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`, "utf8");
} finally {
  await daemon.close();
  delete process.env.IOI_STAGE11_SECRET_TOKEN;
  delete process.env.STAGE11_PUBLIC_MARKER;
}
