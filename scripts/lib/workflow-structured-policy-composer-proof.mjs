#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { startRuntimeDaemonService } from "../../packages/runtime-daemon/src/index.mjs";

const outputPath = process.argv[2];
if (!outputPath) {
  throw new Error("usage: workflow-structured-policy-composer-proof.mjs <output-path>");
}

const {
  compileWorkflowStructuredPolicy,
  createPolicyBoundRuntimeCodingToolControlRequest,
} = await import("../../packages/agent-ide/src/runtime/workflow-structured-policy-composer.ts");
const { buildWorkflowRuntimePolicyLeasePanel } = await import(
  "../../packages/agent-ide/src/runtime/workflow-runtime-policy-lease-panel.ts"
);

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

const promptSoupPolicy = compileWorkflowStructuredPolicy({
  id: "policy.prompt-soup.stage17",
  advisoryGuidelines: [
    "Always be careful around local writes.",
    "Prefer explaining risky actions before doing them.",
  ],
});
assert.equal(promptSoupPolicy.status, "blocked");
assert.equal(promptSoupPolicy.promptSoupGuard, "blocked");
assert.ok(promptSoupPolicy.diagnostics.some((diagnostic) => diagnostic.code === "prompt_soup_no_enforceable_rules"));
assert.throws(() =>
  createPolicyBoundRuntimeCodingToolControlRequest({
    threadId: "thread_blocked",
    toolId: "file.apply_patch",
    toolInput: {},
    compiledPolicy: promptSoupPolicy,
  }),
);

const structuredPolicy = compileWorkflowStructuredPolicy({
  id: "policy.structured.stage17",
  name: "Stage 17 local-write policy composer proof",
  authorityRules: [
    {
      id: "local-write-review",
      target: "runtime_coding_tool",
      tools: ["file.apply_patch"],
      effectClasses: ["local_write"],
      requiresApproval: true,
      approvalMode: "policy_required",
      trustProfile: "review_required",
      nodeApprovalOverride: "require_approval",
      authorityScopes: ["scope:workspace.write"],
      leaseTtlMs: 120_000,
      expectedReceiptRefs: ["receipt_structured_policy_expected"],
      policyDecisionRefs: ["policy_structured_composer_authority_rule"],
    },
  ],
  memoryRules: [
    {
      id: "subagent-memory-readonly",
      target: "subagent",
      scope: "thread",
      readOnly: true,
      injectionEnabled: true,
      writeRequiresApproval: true,
      subagentInheritance: "read_only",
      retention: "session",
      redaction: "redacted",
    },
  ],
  modelRules: [
    {
      id: "local-only-model",
      privacy: "local_only",
      allowHostedFallback: false,
      maxCostUsd: 0.01,
      reasoningEffort: "low",
    },
  ],
  advisoryGuidelines: ["Keep explanations concise; this guideline is not authority."],
});
assert.equal(structuredPolicy.status, "ready");
assert.equal(structuredPolicy.promptSoupGuard, "passed");
assert.equal(structuredPolicy.enforceableRuleCount, 3);
assert.equal(structuredPolicy.advisoryGuidelineCount, 1);
assert.match(structuredPolicy.policyHash, /^stable-fnv1a32:[a-f0-9]{8}$/);

const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-stage17-workspace-"));
const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-stage17-state-"));
fs.writeFileSync(path.join(cwd, "policy.txt"), "before structured policy\n", "utf8");

const daemon = await startRuntimeDaemonService({ cwd, stateDir });

try {
  const workflowGraphId = "workflow.react-flow.structured-policy-composer";
  const workflowNodeId = "workflow.policy-composer.file.apply-patch";
  const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
    method: "POST",
    body: JSON.stringify({
      source: "react_flow",
      goal: "Prove structured Policy Composer output becomes daemon-enforced policy instead of prompt-only guidance.",
      options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
    }),
  });
  const mode = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/mode`, {
    method: "POST",
    body: JSON.stringify({
      source: "react_flow",
      workflowGraphId,
      workflowNodeId: "runtime.thread-mode.yolo.structured-policy-composer",
      mode: "yolo",
      approvalMode: "never_prompt",
    }),
  });
  assert.equal(mode.mode, "yolo");
  assert.equal(mode.approval_mode, "never_prompt");

  const request = createPolicyBoundRuntimeCodingToolControlRequest({
    threadId: thread.thread_id,
    toolId: "file.apply_patch",
    effectClass: "local_write",
    toolCallId: "coding_tool_structured_policy_composer_probe",
    workflowGraphId,
    workflowNodeId,
    actor: "operator",
    compiledPolicy: structuredPolicy,
    toolInput: {
      path: "policy.txt",
      oldText: "before structured policy",
      newText: "after structured policy",
      dryRun: true,
    },
  });
  assert.equal(request.body.requiresApproval, true);
  assert.equal(request.body.approvalMode, "policy_required");
  assert.equal(request.body.policyHash, structuredPolicy.policyHash);
  assert.equal(request.body.structuredPolicy.policyHash, structuredPolicy.policyHash);
  assert.equal(request.body.structuredPolicy.constraints.memory[0].subagentInheritance, "read_only");
  assert.equal(request.body.structuredPolicy.constraints.model[0].privacy, "local_only");
  assert.deepEqual(request.body.expectedReceiptRefs, ["receipt_structured_policy_expected"]);
  assert.deepEqual(request.body.authorityScopeRequirements, ["scope:workspace.write"]);

  const blocked = await fetchJson(`${daemon.endpoint}${request.endpoint}`, {
    method: request.method,
    body: JSON.stringify({
      ...request.body,
      idempotencyKey: "structured-policy-composer-blocked-attempt",
    }),
  });
  assert.equal(blocked.status, "blocked");
  assert.equal(blocked.approval_required, true);
  assert.equal(blocked.approval_manifest.workflow_policy.requiresApproval, true);
  assert.equal(blocked.approval_manifest.workflow_policy.approvalMode, "policy_required");
  assert.equal(blocked.approval_manifest.workflow_policy.trustProfile, "review_required");
  assert.equal(blocked.approval_manifest.nodeApprovalOverride, "require_approval");
  assert.equal(fs.readFileSync(path.join(cwd, "policy.txt"), "utf8"), "before structured policy\n");

  const events = await fetchSseEvents(
    `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`,
  );
  const leasePanel = buildWorkflowRuntimePolicyLeasePanel(events, { threadId: thread.thread_id, workflowGraphId });
  assert.equal(leasePanel.pendingCount, 1);
  const leaseRow = leasePanel.rows[0];
  assert.equal(leaseRow.policyHash, structuredPolicy.policyHash);
  assert.equal(leaseRow.ttlMs, 120_000);
  assert.ok(leaseRow.expectedReceiptRefs.includes("receipt_structured_policy_expected"));
  assert.ok(leaseRow.authorityScopeRequirements.includes("scope:workspace.write"));
  assert.ok(leaseRow.revokeEndpoint.includes(`/v1/threads/${thread.thread_id}/approvals/`));

  const approvalEvent = events.find((event) => event.event_kind === "approval.required");
  assert.ok(approvalEvent);
  assert.equal(approvalEvent.payload_summary.policy_hash, structuredPolicy.policyHash);
  assert.ok(!JSON.stringify(approvalEvent.payload_summary.approval_manifest).includes("Keep explanations concise"));

  const proof = {
    schemaVersion: "ioi.autopilot.stage17.structured-policy-composer-proof.v1",
    passed: true,
    cwd,
    stateDir,
    endpoint: daemon.endpoint,
    threadId: thread.thread_id,
    workflowGraphId,
    promptSoupPolicy,
    structuredPolicy,
    requestSummary: {
      endpoint: request.endpoint,
      method: request.method,
      policyHash: request.body.policyHash,
      requiresApproval: request.body.requiresApproval,
      approvalMode: request.body.approvalMode,
      trustProfile: request.body.trustProfile,
      authorityScopeRequirements: request.body.authorityScopeRequirements,
      expectedReceiptRefs: request.body.expectedReceiptRefs,
    },
    checks: {
      promptSoupBlocked: promptSoupPolicy.status === "blocked",
      structuredPolicyReady: structuredPolicy.status === "ready",
      requestCarriesPolicyHash: request.body.policyHash === structuredPolicy.policyHash,
      memoryConstraintCompiled: request.body.structuredPolicy.constraints.memory[0].subagentInheritance === "read_only",
      modelConstraintCompiled: request.body.structuredPolicy.constraints.model[0].privacy === "local_only",
      daemonRequiredApproval: blocked.approval_required === true,
      leasePanelCarriesPolicyHash: leaseRow.policyHash === structuredPolicy.policyHash,
      advisoryTextNotAuthority: !JSON.stringify(approvalEvent.payload_summary.approval_manifest).includes("Keep explanations concise"),
      dryRunDidNotMutateFile: fs.readFileSync(path.join(cwd, "policy.txt"), "utf8") === "before structured policy\n",
    },
    leasePanel,
    blocked,
  };
  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`);
} finally {
  await daemon.close();
}
