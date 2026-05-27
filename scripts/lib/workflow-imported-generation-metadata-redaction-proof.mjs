#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const outputPath = process.argv[2];
if (!outputPath) {
  throw new Error("usage: workflow-imported-generation-metadata-redaction-proof.mjs <output-path>");
}

const { buildWorkflowImportedGenerationMetadataPanel } = await import(
  "../../packages/agent-ide/src/runtime/workflow-imported-generation-metadata.ts"
);

const panel = buildWorkflowImportedGenerationMetadataPanel({
  sourceTable: "gen_metadata",
  trajectoryId: "trajectory-stage53",
  rows: [
    {
      sourceRowId: 1,
      kind: "prompt_context",
      text: "System prompt with sk-stage53supersecret and private plan PRIVATE_BUILD_PLAN_OMEGA.",
      modelId: "qwen/qwen3.5",
      routeId: "route.local-first",
      provider: "lm-studio",
      tokenCounts: { input: 1200, output: 0, reasoning: 0 },
      receiptRefs: ["receipt:ioi:gen-metadata:prompt"],
    },
    {
      sourceRowId: 2,
      kind: "thinking_trace",
      text: "Raw reasoning should not be retained: SECRET_REASONING_CANARY.",
      modelId: "qwen/qwen3.5",
      tokenCounts: { input: 0, output: 0, reasoning: 320 },
      receiptRefs: [],
    },
    {
      sourceRowId: 3,
      kind: "gateway_request",
      gatewayUrl: "http://daily-cloudcode-pa.googleapis.com/v1internal:streamGenerateContent?alt=sse",
      headers: {
        Authorization: "Bearer ya29.stage53oauthsecret",
        "x-antigravity-csrf": "ANTIGRAVITY_CSRF_TOKEN_STAGE53",
        "content-type": "application/json",
      },
      receiptRefs: ["receipt:ioi:gen-metadata:gateway"],
    },
    {
      sourceRowId: 4,
      kind: "assistant_output",
      text: "Assistant output containing a transient credential token=stage53-transient.",
      tokenCounts: { input: 0, output: 84, reasoning: 0 },
      receiptRefs: ["receipt:ioi:gen-metadata:assistant"],
    },
    {
      sourceRowId: 5,
      kind: "model_route",
      modelId: "route.local-first:qwen/qwen3.5",
      routeId: "route.local-first",
      provider: "local-native",
      receiptRefs: ["receipt:ioi:gen-metadata:model-route"],
    },
  ],
});

const rows = new Map(panel.rows.map((row) => [row.id, row]));
const promptRow = rows.get("gen:prompt_context:1");
const thinkingRow = rows.get("gen:thinking_trace:2");
const gatewayRow = rows.get("gen:gateway_request:3");
const assistantRow = rows.get("gen:assistant_output:4");
const modelRouteRow = rows.get("gen:model_route:5");

assert.equal(panel.schemaVersion, "ioi.workflow.imported-generation-metadata.v1");
assert.equal(panel.sourceTable, "gen_metadata");
assert.equal(panel.importedAuthority, "historical_only");
assert.equal(panel.applyMode, "audit_only");
assert.equal(panel.rawPromptRetention, "never");
assert.equal(panel.rawReasoningRetention, "never");
assert.equal(panel.status, "blocked");
assert.equal(panel.rowCount, 5);
assert.ok(panel.readyCount >= 3);
assert.ok(panel.needsReviewCount >= 1);
assert.ok(panel.blockedCount >= 1);

assert.ok(promptRow);
assert.equal(promptRow.status, "ready");
assert.equal(promptRow.retention, "summary_only");
assert.match(promptRow.contentHash ?? "", /^stable-fnv1a32:[a-f0-9]{8}$/);
assert.equal(promptRow.redactedPreview, "[PROMPT SUMMARY REDACTED]");
assert.equal(promptRow.modelId, "qwen/qwen3.5");
assert.deepEqual(promptRow.tokenCounts, { input: 1200, output: 0, reasoning: 0 });

assert.ok(thinkingRow);
assert.equal(thinkingRow.status, "needs_review");
assert.equal(thinkingRow.retention, "reasoning_summary_only");
assert.equal(thinkingRow.redactedPreview, "[REASONING SUMMARY REDACTED]");
assert.ok(thinkingRow.policyRefs.includes("policy:gen_metadata.review.missing_receipt"));

assert.ok(gatewayRow);
assert.equal(gatewayRow.status, "blocked");
assert.equal(gatewayRow.retention, "blocked");
assert.equal(gatewayRow.endpointHost, "daily-cloudcode-pa.googleapis.com");
assert.equal(gatewayRow.redactedHeaders.Authorization, "[REDACTED]");
assert.equal(gatewayRow.redactedHeaders["x-antigravity-csrf"], "[REDACTED]");
assert.ok(gatewayRow.policyRefs.includes("policy:gen_metadata.block.non_https_gateway_trace"));

assert.ok(assistantRow);
assert.equal(assistantRow.retention, "summary_only");
assert.equal(assistantRow.redactedPreview, "[ASSISTANT OUTPUT SUMMARY REDACTED]");
assert.ok(modelRouteRow);
assert.equal(modelRouteRow.retention, "metadata_only");
assert.equal(modelRouteRow.modelId, "route.local-first:qwen/qwen3.5");

const serialized = JSON.stringify(panel);
for (const canary of [
  "PRIVATE_BUILD_PLAN_OMEGA",
  "SECRET_REASONING_CANARY",
  "sk-stage53supersecret",
  "ya29.stage53oauthsecret",
  "ANTIGRAVITY_CSRF_TOKEN_STAGE53",
  "stage53-transient",
]) {
  assert.ok(!serialized.includes(canary), `panel leaked ${canary}`);
}

const proof = {
  schemaVersion: "ioi.autopilot.stage53.imported-generation-metadata-redaction-proof.v1",
  passed: true,
  generatedAt: new Date().toISOString(),
  checks: {
    historicalOnly: panel.importedAuthority === "historical_only",
    auditOnly: panel.applyMode === "audit_only",
    promptSummaryOnly: promptRow?.retention === "summary_only",
    reasoningSummaryOnly: thinkingRow?.retention === "reasoning_summary_only",
    gatewayHeadersRedacted: gatewayRow?.redactedHeaders.Authorization === "[REDACTED]",
    nonHttpsGatewayBlocked: gatewayRow?.status === "blocked",
    modelRouteMetadataVisible: modelRouteRow?.retention === "metadata_only",
    canariesAbsent: true,
  },
  panel,
};

fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`);
