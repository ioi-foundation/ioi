#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const outputPath = process.argv[2];
if (!outputPath) {
  throw new Error("usage: workflow-imported-policy-draft-proof.mjs <output-path>");
}

const { buildWorkflowImportedExecutorConfigPanel } = await import(
  "../../packages/agent-ide/src/runtime/workflow-imported-executor-config.ts"
);
const { buildWorkflowImportedPolicyDraft } = await import(
  "../../packages/agent-ide/src/runtime/workflow-imported-policy-draft.ts"
);

const sourcePanel = buildWorkflowImportedExecutorConfigPanel({
  sourceTable: "executor_metadata",
  sourceRowId: 2,
  trajectoryId: "trajectory-stage52",
  allowedCommands: ["echo", "date", "cat", "curl", "python"],
  blockedCommands: ["rm", "ssh"],
  ideChecks: {
    diagnostics: true,
    tests: true,
    lint: false,
  },
  memoryLimitMb: 2048,
  networkDefault: "allow",
  receiptRefs: ["receipt:ioi:executor-config"],
});

const draft = buildWorkflowImportedPolicyDraft({ sourcePanel });
const items = new Map(draft.items.map((item) => [item.id, item]));
const authorityRule = draft.structuredPolicyDraft.authorityRules[0];

assert.equal(draft.schemaVersion, "ioi.workflow.imported-policy-draft.v1");
assert.equal(draft.applyMode, "draft_only");
assert.equal(draft.importedAuthority, "advisory_only");
assert.equal(draft.status, "needs_review");
assert.equal(draft.sourceSchemaVersion, "ioi.workflow.imported-executor-config.v1");
assert.equal(draft.structuredPolicyDraft.status, "ready");
assert.match(draft.structuredPolicyDraft.policyHash, /^stable-fnv1a32:[a-f0-9]{8}$/);
assert.equal(draft.forcedNetworkDefault, "deny");
assert.equal(draft.memoryLimitMb, 2048);
assert.deepEqual(draft.receiptRefs, ["receipt:ioi:executor-config"]);
assert.ok(draft.proposedCount >= 6);
assert.ok(draft.reviewCount >= 2);
assert.ok(draft.blockedCount >= 2);
assert.ok(draft.preservedCount >= 2);

assert.ok(authorityRule);
assert.equal(authorityRule.requiresApproval, true);
assert.equal(authorityRule.approvalMode, "operator_review_required");
assert.equal(authorityRule.trustProfile, "imported_advisory_only");
assert.ok(authorityRule.authorityScopes.includes("scope:network.deny_default"));
assert.ok(authorityRule.authorityScopes.includes("command:echo"));
assert.ok(authorityRule.authorityScopes.includes("command:date"));
assert.ok(authorityRule.authorityScopes.includes("command:cat"));
assert.ok(!authorityRule.authorityScopes.includes("command:curl"));
assert.ok(!authorityRule.authorityScopes.includes("command:python"));
assert.deepEqual(authorityRule.expectedReceiptRefs, ["receipt:ioi:executor-config"]);

assert.equal(items.get("draft:allow:echo")?.status, "proposed");
assert.equal(items.get("draft:allow:echo")?.selected, true);
assert.equal(items.get("draft:allow:curl")?.status, "blocked");
assert.equal(items.get("draft:allow:curl")?.selected, false);
assert.equal(items.get("draft:allow:python")?.status, "needs_review");
assert.equal(items.get("draft:allow:python")?.selected, false);
assert.equal(items.get("draft:block:ssh")?.status, "preserved");
assert.equal(items.get("draft:network:default")?.status, "blocked");
assert.ok(
  items
    .get("draft:network:default")
    ?.policyRefs.includes("policy:imported_policy_draft.force_network_default_deny"),
);
assert.ok(
  draft.policyInput.advisoryGuidelines?.some((line) =>
    line.includes("Force network default deny"),
  ),
);

const blockedSourcePanel = buildWorkflowImportedExecutorConfigPanel({
  sourceTable: "executor_metadata",
  sourceRowId: 3,
  trajectoryId: "trajectory-stage52-no-safe-command",
  allowedCommands: ["curl", "python"],
  blockedCommands: ["ssh"],
  ideChecks: {
    diagnostics: false,
    tests: false,
    lint: false,
  },
  memoryLimitMb: null,
  networkDefault: "unknown",
  receiptRefs: [],
});
const blockedDraft = buildWorkflowImportedPolicyDraft({ sourcePanel: blockedSourcePanel });
assert.equal(blockedDraft.status, "blocked");
assert.equal(blockedDraft.structuredPolicyDraft.status, "blocked");
assert.equal(blockedDraft.proposedCommandScopes.length, 0);
assert.ok(
  blockedDraft.structuredPolicyDraft.diagnostics.some(
    (diagnostic) => diagnostic.code === "prompt_soup_no_enforceable_rules",
  ),
);

const proof = {
  schemaVersion: "ioi.autopilot.stage52.imported-policy-draft-proof.v1",
  passed: true,
  generatedAt: new Date().toISOString(),
  checks: {
    draftOnly: draft.applyMode === "draft_only",
    importedAuthorityAdvisoryOnly: draft.importedAuthority === "advisory_only",
    safeBaseCommandsProposedWithApproval:
      authorityRule?.requiresApproval === true &&
      ["command:echo", "command:date", "command:cat"].every((scope) =>
        authorityRule.authorityScopes.includes(scope),
      ),
    networkAllowExcludedFromAuthority: !authorityRule?.authorityScopes.includes("command:curl"),
    nonBaseCommandHeldForReview: items.get("draft:allow:python")?.status === "needs_review",
    networkDefaultForcedDeny:
      draft.forcedNetworkDefault === "deny" &&
      authorityRule?.authorityScopes.includes("scope:network.deny_default") === true,
    denyHintsPreserved: items.get("draft:block:ssh")?.status === "preserved",
    noSafeCommandDraftBlocks: blockedDraft.status === "blocked",
  },
  sourcePanel,
  draft,
  blockedDraft,
};

fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`);
