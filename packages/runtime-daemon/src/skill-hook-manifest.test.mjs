import assert from "node:assert/strict";
import { test } from "node:test";

import {
  activeSkillHookManifestForRun,
  hookDryRunPlanForManifest,
  hookEscalationReceiptsForLedger,
  hookInvocationLedgerForPlan,
  normalizeManifestSelection,
  selectCatalogRecords,
} from "./skill-hook-manifest.mjs";

const catalog = {
  schemaVersion: "ioi.agent-runtime.skill-hook-catalog.v1",
  generatedAt: "2026-06-03T00:00:00.000Z",
  status: "pass",
  activeSkillSetHash: "skill-set-hash",
  activeHookSetHash: "hook-set-hash",
  skillCount: 2,
  hookCount: 3,
  workspace: { root: "/workspace" },
  skills: [
    {
      id: "skill.workspace.planner.aaaa",
      name: "Planner",
      skillHash: "skill-hash-planner",
      sourceId: "workspace.ioi.skills",
      compatibility: "ioi",
      trustLevel: "workspace",
      activationMode: "discoverable",
      validation: { status: "pass", issues: [] },
      provenance: { governed: true },
      evidenceRefs: ["skill"],
    },
    {
      id: "skill.workspace.writer.bbbb",
      name: "Writer",
      skillHash: "skill-hash-writer",
      sourceId: "workspace.agents.skills",
      compatibility: "agents",
      trustLevel: "workspace",
      activationMode: "manual",
      validation: { status: "pass", issues: [] },
      provenance: { governed: true },
      evidenceRefs: ["skill"],
    },
  ],
  hooks: [
    {
      id: "hook.workspace.pre_model.cccc",
      name: "pre_model_guard",
      definitionHash: "hook-hash-guard",
      sourceId: "workspace.ioi.hooks_file",
      compatibility: "ioi",
      trustLevel: "workspace",
      eventKinds: ["pre_model"],
      failurePolicy: "warn",
      sideEffectClass: "local_write",
      authorityScopes: [],
      toolContracts: [],
      commandConfigured: true,
      commandHash: "hashed-command",
      commandRedacted: true,
      validation: { status: "degraded", issues: ["missing_authority_scope", "missing_tool_contract"] },
      mutationPolicy: { mutationRequiresAuthorityScope: true },
      evidenceRefs: ["hook"],
    },
    {
      id: "hook.workspace.post_model.dddd",
      name: "post_model_report",
      definitionHash: "hook-hash-report",
      sourceId: "workspace.ioi.hooks_file",
      compatibility: "ioi",
      trustLevel: "workspace",
      eventKinds: ["post_model"],
      failurePolicy: "block",
      sideEffectClass: "none",
      authorityScopes: ["workspace.read"],
      toolContracts: ["runtime.trace"],
      commandConfigured: true,
      commandHash: "hashed-command-2",
      commandRedacted: true,
      validation: { status: "pass", issues: [] },
      mutationPolicy: { mutationRequiresAuthorityScope: true },
      evidenceRefs: ["hook"],
    },
    {
      id: "hook.workspace.disabled.eeee",
      name: "disabled_hook",
      definitionHash: "hook-hash-disabled",
      enabled: false,
      eventKinds: ["workflow_activation"],
      commandConfigured: true,
      validation: { status: "pass", issues: [] },
    },
  ],
};

test("manifest selection normalizes nested aliases and catalog records", () => {
  assert.deepEqual(
    normalizeManifestSelection([
      ["Planner", { id: "hook.workspace.pre_model.cccc" }],
      { name: "post_model_report", definitionHash: "hook-hash-report" },
      null,
    ]),
    ["Planner", "hook.workspace.pre_model.cccc", "post_model_report", "hook-hash-report"],
  );

  const records = selectCatalogRecords(catalog.skills, ["planner"], "skillHash");
  assert.deepEqual(records.map((record) => record.name), ["Planner"]);
});

test("active skill hook manifest preserves redacted selection and validation status", () => {
  const manifest = activeSkillHookManifestForRun({
    runId: "run_123",
    agent: {
      id: "agent_1",
      cwd: "/workspace",
      options: { skillNames: ["Planner"], hookNames: ["pre_model_guard"] },
    },
    request: { options: {} },
    catalog,
  });

  assert.equal(manifest.object, "ioi.agent_active_skill_hook_manifest");
  assert.equal(manifest.selectionMode, "explicit_or_configured");
  assert.deepEqual(manifest.selectedSkillIds, ["skill.workspace.planner.aaaa"]);
  assert.deepEqual(manifest.selectedHookIds, ["hook.workspace.pre_model.cccc"]);
  assert.deepEqual(manifest.mutationBlockedHookIds, ["hook.workspace.pre_model.cccc"]);
  assert.equal(manifest.validation.status, "degraded");
  assert.deepEqual(manifest.validation.issues, ["missing_authority_scope", "missing_tool_contract"]);
  assert.equal(manifest.redaction.hookCommandsIncluded, false);
  assert.equal(JSON.stringify(manifest).includes("hashed-command"), true);
});

test("hook dry-run plan and invocation ledger create escalation receipts for blocked hooks", () => {
  const manifest = activeSkillHookManifestForRun({
    runId: "run_456",
    agent: { id: "agent_1", cwd: "/workspace", options: {} },
    request: { options: { hooks: ["pre_model_guard", "post_model_report"] } },
    catalog,
  });
  const dryRunPlan = hookDryRunPlanForManifest({ runId: "run_456", manifest });
  const ledger = hookInvocationLedgerForPlan({ runId: "run_456", manifest, dryRunPlan });
  const receipts = hookEscalationReceiptsForLedger(ledger);

  assert.equal(dryRunPlan.decisionCount, 2);
  assert.equal(dryRunPlan.blockedCount, 1);
  assert.equal(dryRunPlan.wouldRunCount, 1);
  assert.equal(dryRunPlan.policyDecision.status, "blocked");
  assert.equal(ledger.invocationCount, 2);
  assert.equal(ledger.blockedCount, 1);
  assert.equal(ledger.wouldRunCount, 1);
  assert.equal(ledger.escalationCount, 1);
  assert.equal(receipts.length, 1);
  assert.equal(receipts[0].kind, "hook_escalation");
  assert.deepEqual(receipts[0].details.missingDeclarations, ["authorityScopes", "toolContracts"]);
});
