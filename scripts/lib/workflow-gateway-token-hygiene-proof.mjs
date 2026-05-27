#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const outputPath = process.argv[2];
if (!outputPath) {
  throw new Error("usage: workflow-gateway-token-hygiene-proof.mjs <output-path>");
}

const { buildWorkflowGatewayTokenHygienePanel } = await import(
  "../../packages/agent-ide/src/runtime/workflow-gateway-token-hygiene.ts"
);

const panel = buildWorkflowGatewayTokenHygienePanel({
  localServer: {
    host: "127.0.0.1",
    port: 49152,
    csrfToken: "csrf-stage44-token-value",
    env: {
      ANTIGRAVITY_CSRF_TOKEN: "csrf-stage44-token-value",
      PATH: "/usr/bin",
    },
  },
  remoteRequests: [
    {
      id: "generate",
      url: "https://daily-cloudcode-pa.googleapis.com/google.internal.cloud.code.v1internal.PredictionService/GenerateContent",
      method: "POST",
      authToken: "ya29.stage44-oauth-token-value",
    },
    {
      id: "fetch-models",
      url: "https://daily-cloudcode-pa.googleapis.com/google.internal.cloud.code.v1internal.PredictionService/FetchAvailableModels",
      method: "POST",
      headers: {
        Authorization: "Bearer ya29.stage44-oauth-token-value",
      },
    },
  ],
});

const blockedPanel = buildWorkflowGatewayTokenHygienePanel({
  localServer: {
    host: "0.0.0.0",
    port: 49152,
    env: {},
  },
  remoteRequests: [
    {
      id: "insecure",
      url: "http://daily-cloudcode-pa.googleapis.com/google.internal.cloud.code.v1internal.PredictionService/GenerateContent",
      method: "POST",
    },
  ],
});

const serialized = JSON.stringify({ panel, blockedPanel });
const rows = new Map(panel.rows.map((row) => [row.id, row]));
const blockedRows = new Map(blockedPanel.rows.map((row) => [row.id, row]));

assert.equal(panel.schemaVersion, "ioi.workflow.gateway-token-hygiene.v1");
assert.equal(panel.applyMode, "plan_only");
assert.equal(panel.status, "ready");
assert.equal(panel.localServer.localhostOnly, true);
assert.equal(panel.localServer.csrfTokenPresent, true);
assert.equal(panel.localServer.redactedEnv.ANTIGRAVITY_CSRF_TOKEN, "[REDACTED]");
assert.equal(rows.get("generate")?.kind, "generate_content");
assert.equal(rows.get("fetch-models")?.kind, "fetch_models");
assert.equal(rows.get("generate")?.networkMode, "dry_run_plan");
assert.equal(rows.get("generate")?.redactedHeaders.Authorization, "[REDACTED]");
assert.equal(serialized.includes("csrf-stage44-token-value"), false);
assert.equal(serialized.includes("ya29.stage44-oauth-token-value"), false);
assert.equal(blockedPanel.status, "blocked");
assert.ok(blockedPanel.localServer.policyRefs.includes("policy:gateway.block.non_local_bind"));
assert.ok(blockedPanel.localServer.policyRefs.includes("policy:gateway.block.missing_csrf"));
assert.equal(blockedRows.get("insecure")?.status, "blocked");
assert.ok(blockedRows.get("insecure")?.policyRefs.includes("policy:gateway.block.non_https_remote"));
assert.ok(blockedRows.get("insecure")?.policyRefs.includes("policy:gateway.review.missing_oauth"));

const proof = {
  schemaVersion: "ioi.autopilot.stage44.gateway-token-hygiene-proof.v1",
  passed: true,
  generatedAt: new Date().toISOString(),
  checks: {
    localServerBoundToLocalhost: panel.localServer.localhostOnly,
    csrfTokenRedacted: panel.localServer.redactedEnv.ANTIGRAVITY_CSRF_TOKEN === "[REDACTED]",
    requestsAreDryRunPlans: panel.rows.every((row) => row.networkMode === "dry_run_plan"),
    predictionMethodsRecognized:
      rows.get("generate")?.kind === "generate_content" &&
      rows.get("fetch-models")?.kind === "fetch_models",
    oauthRedacted: !serialized.includes("ya29.stage44-oauth-token-value") &&
      panel.rows.every((row) => row.redactedHeaders.Authorization === "[REDACTED]"),
    nonLocalBindBlocked: blockedPanel.localServer.policyRefs.includes("policy:gateway.block.non_local_bind"),
    insecureRemoteBlocked: blockedRows.get("insecure")?.policyRefs.includes("policy:gateway.block.non_https_remote") === true,
  },
  panel,
  blockedPanel,
};

fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`);
