import crypto from "node:crypto";

import { HOOK_INVOCATION_RUNTIME_EVENTS } from "./runtime-contract-constants.mjs";

export function activeSkillHookManifestForRun({ runId, agent, request = {}, catalog = null } = {}) {
  const skills = normalizeArray(catalog?.skills);
  const hooks = normalizeArray(catalog?.hooks);
  const options = request.options ?? {};
  const requestedSkillRefs = normalizeManifestSelection([
    options.skills,
    options.skillIds,
    options.skill_ids,
    options.skillNames,
    options.skill_names,
    agent?.options?.skillNames,
  ]);
  const requestedHookRefs = normalizeManifestSelection([
    options.hooks,
    options.hookIds,
    options.hook_ids,
    options.hookNames,
    options.hook_names,
    agent?.options?.hookNames,
  ]);
  const selectedSkills = selectCatalogRecords(skills, requestedSkillRefs, "skillHash");
  const selectedHooks = selectCatalogRecords(
    hooks.filter((hook) => hook.enabled !== false),
    requestedHookRefs,
    "definitionHash",
  );
  const skillHashes = selectedSkills.map((skill) => skill.skillHash).filter(Boolean).sort();
  const hookHashes = selectedHooks.map((hook) => hook.definitionHash).filter(Boolean).sort();
  const blockedHooks = selectedHooks.filter((hook) =>
    hook.commandConfigured &&
    (normalizeArray(hook.authorityScopes).length === 0 || normalizeArray(hook.toolContracts).length === 0)
  );
  const manifestPayload = {
    skillHashes,
    hookHashes,
    catalogSkillSetHash: catalog?.activeSkillSetHash ?? doctorHash(""),
    catalogHookSetHash: catalog?.activeHookSetHash ?? doctorHash(""),
    blockedHookIds: blockedHooks.map((hook) => hook.id).sort(),
  };
  const manifestHash = doctorHash(JSON.stringify(manifestPayload));
  const validationIssues = [
    ...selectedSkills.flatMap((skill) => normalizeArray(skill.validation?.issues)),
    ...selectedHooks.flatMap((hook) => normalizeArray(hook.validation?.issues)),
  ];
  return {
    schemaVersion: "ioi.agent-runtime.active-skill-hook-manifest.v1",
    object: "ioi.agent_active_skill_hook_manifest",
    manifestId: `skill_hook_manifest_${runId}_${manifestHash.slice(0, 12)}`,
    runId,
    agentId: agent?.id ?? null,
    generatedAt: new Date().toISOString(),
    workspace: agent?.cwd ?? catalog?.workspace?.root ?? null,
    selectionMode:
      requestedSkillRefs.length > 0 || requestedHookRefs.length > 0
        ? "explicit_or_configured"
        : "catalog_snapshot_read_only",
    catalog: {
      schemaVersion: catalog?.schemaVersion ?? "ioi.agent-runtime.skill-hook-catalog.v1",
      generatedAt: catalog?.generatedAt ?? null,
      status: catalog?.status ?? "pass",
      activeSkillSetHash: catalog?.activeSkillSetHash ?? doctorHash(""),
      activeHookSetHash: catalog?.activeHookSetHash ?? doctorHash(""),
      skillCount: catalog?.skillCount ?? skills.length,
      hookCount: catalog?.hookCount ?? hooks.length,
    },
    activeSkillSetHash: doctorHash(skillHashes.join("\n")),
    activeHookSetHash: doctorHash(hookHashes.join("\n")),
    manifestHash,
    selectedSkillIds: selectedSkills.map((skill) => skill.id),
    selectedHookIds: selectedHooks.map((hook) => hook.id),
    requestedSkillRefs,
    requestedHookRefs,
    skills: selectedSkills.map((skill) => ({
      id: skill.id,
      name: skill.name,
      skillHash: skill.skillHash,
      sourceId: skill.sourceId,
      compatibility: skill.compatibility,
      trustLevel: skill.trustLevel,
      activationMode: skill.activationMode,
      validationStatus: skill.validation?.status ?? "pass",
      provenance: skill.provenance,
      evidenceRefs: normalizeArray(skill.evidenceRefs),
    })),
    hooks: selectedHooks.map((hook) => ({
      id: hook.id,
      name: hook.name,
      enabled: hook.enabled !== false,
      definitionHash: hook.definitionHash,
      sourceId: hook.sourceId,
      compatibility: hook.compatibility,
      trustLevel: hook.trustLevel,
      eventKinds: normalizeArray(hook.eventKinds),
      failurePolicy: hook.failurePolicy,
      sideEffectClass: hook.sideEffectClass ?? "none",
      authorityScopes: normalizeArray(hook.authorityScopes),
      toolContracts: normalizeArray(hook.toolContracts),
      commandConfigured: Boolean(hook.commandConfigured),
      commandHash: hook.commandHash ?? null,
      commandRedacted: Boolean(hook.commandRedacted),
      validationStatus: hook.validation?.status ?? "pass",
      mutationPolicy: hook.mutationPolicy,
      evidenceRefs: normalizeArray(hook.evidenceRefs),
    })),
    validation: {
      status: validationIssues.length > 0 ? "degraded" : "pass",
      issueCount: validationIssues.length,
      issues: [...new Set(validationIssues)].sort(),
    },
    hookExecution: {
      enabled: false,
      disabledReason: "hook_execution_policy_slice_pending",
      mutationBlockedWithoutDeclaredCapabilities: true,
      mutationAllowedHookIds: selectedHooks
        .filter((hook) =>
          hook.commandConfigured &&
          normalizeArray(hook.authorityScopes).length > 0 &&
          normalizeArray(hook.toolContracts).length > 0
        )
        .map((hook) => hook.id),
      mutationBlockedHookIds: blockedHooks.map((hook) => hook.id),
    },
    mutationBlockedHookIds: blockedHooks.map((hook) => hook.id),
    redaction: {
      profile: "active_skill_hook_manifest_safe",
      skillBodiesIncluded: false,
      hookCommandsIncluded: false,
      hookCommandsHashed: true,
      secretValuesIncluded: false,
    },
    evidenceRefs: [
      "active_skill_hook_manifest",
      "runtime_skill_hook_discovery",
      "prompt_audit",
      "hook_execution_disabled_until_policy",
    ],
  };
}

export function hookDryRunPlanForManifest({ runId, manifest } = {}) {
  const hooks = normalizeArray(manifest?.hooks);
  const decisions = hooks.map((hook) => {
    const authorityScopes = normalizeArray(hook.authorityScopes);
    const toolContracts = normalizeArray(hook.toolContracts);
    const commandConfigured = Boolean(hook.commandConfigured);
    const blockers = [];
    let decision = "skipped";
    let reason = "no_command_configured";

    if (commandConfigured) {
      if (authorityScopes.length === 0) blockers.push("missing_authority_scope");
      if (toolContracts.length === 0) blockers.push("missing_tool_contract");
      if (blockers.length > 0) {
        decision = "blocked";
        reason = "missing_declared_capabilities";
      } else {
        decision = "would_run";
        reason = "preview_only_authority_and_tool_contract_declared";
      }
    }

    return {
      hookId: hook.id,
      name: hook.name,
      eventKinds: normalizeArray(hook.eventKinds),
      failurePolicy: hook.failurePolicy ?? "warn",
      sideEffectClass: hook.sideEffectClass ?? "none",
      commandConfigured,
      commandHash: hook.commandHash ?? null,
      commandRedacted: Boolean(hook.commandRedacted),
      authorityScopes,
      toolContracts,
      decision,
      reason,
      blockers,
      execution: {
        previewOnly: true,
        commandExecuted: false,
        mutationAllowed: false,
      },
      evidenceRefs: normalizeArray(hook.evidenceRefs),
    };
  });
  const wouldRunCount = decisions.filter((decision) => decision.decision === "would_run").length;
  const blockedCount = decisions.filter((decision) => decision.decision === "blocked").length;
  const skippedCount = decisions.filter((decision) => decision.decision === "skipped").length;
  const planPayload = {
    manifestId: manifest?.manifestId ?? null,
    decisions: decisions.map((decision) => ({
      hookId: decision.hookId,
      decision: decision.decision,
      blockers: decision.blockers,
    })),
  };
  const planHash = doctorHash(JSON.stringify(planPayload));

  return {
    schemaVersion: "ioi.agent-runtime.hook-dry-run-plan.v1",
    object: "ioi.agent_hook_dry_run_plan",
    planId: `hook_dry_run_${runId}_${planHash.slice(0, 12)}`,
    runId,
    manifestId: manifest?.manifestId ?? null,
    activeHookSetHash: manifest?.activeHookSetHash ?? doctorHash(""),
    generatedAt: new Date().toISOString(),
    mode: "preview_only",
    hookExecutionEnabled: false,
    commandExecutionEnabled: false,
    decisionCount: decisions.length,
    wouldRunCount,
    blockedCount,
    skippedCount,
    decisions,
    policyDecision: {
      status: blockedCount > 0 ? "blocked" : "passed",
      summary:
        blockedCount > 0
          ? `${blockedCount} hook(s) blocked by missing declared capabilities; no commands executed.`
          : "All command-backed hooks are eligible for dry-run preview; no commands executed.",
      previewOnly: true,
      hookExecutionEnabled: false,
      commandExecutionEnabled: false,
    },
    redaction: {
      profile: "hook_dry_run_safe",
      hookCommandsIncluded: false,
      hookCommandsHashed: true,
      secretValuesIncluded: false,
    },
    evidenceRefs: [
      "hook_dry_run_plan",
      "hook_policy_decision",
      manifest?.manifestId,
    ].filter(Boolean),
  };
}

export function hookInvocationLedgerForPlan({ runId, manifest, dryRunPlan } = {}) {
  const hooks = normalizeArray(manifest?.hooks);
  const decisionsByHookId = new Map(
    normalizeArray(dryRunPlan?.decisions).map((decision) => [decision.hookId, decision]),
  );
  const records = [];
  for (const runtimeEvent of HOOK_INVOCATION_RUNTIME_EVENTS) {
    for (const hook of hooks) {
      const hookEventKinds = normalizeArray(hook.eventKinds);
      if (!hookEventKinds.includes(runtimeEvent.eventKind)) continue;
      const planDecision = decisionsByHookId.get(hook.id) ?? {};
      const decision = planDecision.decision ?? "skipped";
      const blockers = normalizeArray(planDecision.blockers);
      const invocationHash = doctorHash(
        JSON.stringify({
          runId,
          eventKind: runtimeEvent.eventKind,
          hookId: hook.id,
          decision,
          blockers,
        }),
      );
      const escalation =
        decision === "blocked"
          ? hookEscalationForBlockedInvocation({
              runId,
              invocationHash,
              runtimeEvent,
              hook,
              planDecision,
              blockers,
            })
          : {
              required: false,
              receiptId: null,
              missingAuthorityScopes: [],
              missingToolContracts: [],
              recommendedNextAction: "No hook escalation is required for this preview invocation.",
            };
      records.push({
        schemaVersion: "ioi.agent-runtime.hook-invocation-record.v1",
        object: "ioi.agent_hook_invocation_record",
        invocationId: `hook_invocation_${runId}_${invocationHash.slice(0, 12)}`,
        runId,
        manifestId: manifest?.manifestId ?? null,
        dryRunPlanId: dryRunPlan?.planId ?? null,
        eventKind: runtimeEvent.eventKind,
        runtimeEventType: runtimeEvent.runtimeEventType,
        runtimeEventPhase: runtimeEvent.phase,
        hookId: hook.id,
        hookName: hook.name,
        hookDefinitionHash: hook.definitionHash ?? null,
        hookEventKinds,
        failurePolicy: hook.failurePolicy ?? "warn",
        sideEffectClass: hook.sideEffectClass ?? "none",
        authorityScopes: normalizeArray(hook.authorityScopes),
        toolContracts: normalizeArray(hook.toolContracts),
        commandConfigured: Boolean(hook.commandConfigured),
        commandHash: hook.commandHash ?? null,
        commandRedacted: Boolean(hook.commandRedacted),
        state: decision,
        decision,
        reason: planDecision.reason ?? "preview_only_event_subscription_matched",
        blockers,
        escalation,
        policyDecisionStatus: dryRunPlan?.policyDecision?.status ?? null,
        execution: {
          previewOnly: true,
          commandExecuted: false,
          mutationAllowed: false,
        },
        workflowNodeId: `runtime.hook.${runtimeEvent.eventKind.replace(/_/g, "-")}`,
        hookPolicyNodeId: "runtime.hook-policy",
        evidenceRefs: [
          "hook_invocation_record",
          dryRunPlan?.planId,
          manifest?.manifestId,
          hook.id,
          runtimeEvent.eventKind,
        ].filter(Boolean),
      });
    }
  }
  const wouldRunCount = records.filter((record) => record.state === "would_run").length;
  const blockedCount = records.filter((record) => record.state === "blocked").length;
  const skippedCount = records.filter((record) => record.state === "skipped").length;
  const escalations = records
    .filter((record) => record.escalation?.required === true)
    .map((record) => ({
      ...record.escalation,
      invocationId: record.invocationId,
      hookId: record.hookId,
      hookName: record.hookName,
      eventKind: record.eventKind,
      failurePolicy: record.failurePolicy,
      workflowNodeId: record.workflowNodeId,
    }));
  const ledgerHash = doctorHash(
    JSON.stringify({
      manifestId: manifest?.manifestId ?? null,
      planId: dryRunPlan?.planId ?? null,
      records: records.map((record) => ({
        eventKind: record.eventKind,
        hookId: record.hookId,
        state: record.state,
      })),
    }),
  );
  return {
    schemaVersion: "ioi.agent-runtime.hook-invocation-ledger.v1",
    object: "ioi.agent_hook_invocation_ledger",
    ledgerId: `hook_invocations_${runId}_${ledgerHash.slice(0, 12)}`,
    runId,
    manifestId: manifest?.manifestId ?? null,
    dryRunPlanId: dryRunPlan?.planId ?? null,
    activeHookSetHash: manifest?.activeHookSetHash ?? doctorHash(""),
    generatedAt: new Date().toISOString(),
    mode: "preview_only",
    hookExecutionEnabled: false,
    commandExecutionEnabled: false,
    emittedEventKinds: HOOK_INVOCATION_RUNTIME_EVENTS.map((event) => event.eventKind),
    invocationCount: records.length,
    wouldRunCount,
    blockedCount,
    skippedCount,
    escalationCount: escalations.length,
    escalations,
    records,
    redaction: {
      profile: "hook_invocation_ledger_safe",
      hookCommandsIncluded: false,
      hookCommandsHashed: true,
      secretValuesIncluded: false,
    },
    evidenceRefs: [
      "hook_invocation_ledger",
      "hook_invocation_preview_only",
      dryRunPlan?.planId,
      manifest?.manifestId,
    ].filter(Boolean),
  };
}

export function hookEscalationForBlockedInvocation({
  runId,
  invocationHash,
  runtimeEvent,
  hook,
  planDecision,
  blockers,
} = {}) {
  const missingAuthorityScopes = blockers.includes("missing_authority_scope")
    ? ["declare_at_least_one_authority_scope"]
    : [];
  const missingToolContracts = blockers.includes("missing_tool_contract")
    ? ["declare_at_least_one_tool_contract"]
    : [];
  const missingDeclarations = [
    ...(missingAuthorityScopes.length > 0 ? ["authorityScopes"] : []),
    ...(missingToolContracts.length > 0 ? ["toolContracts"] : []),
  ];
  return {
    required: true,
    receiptId: `receipt_${runId}_hook_escalation_${invocationHash.slice(0, 12)}`,
    escalationKind: "missing_declared_capabilities",
    missingDeclarations,
    missingAuthorityScopes,
    missingToolContracts,
    eventKind: runtimeEvent?.eventKind ?? null,
    hookId: hook?.id ?? null,
    hookName: hook?.name ?? null,
    failurePolicy: hook?.failurePolicy ?? "warn",
    blockers,
    recommendedNextAction:
      missingDeclarations.length > 0
        ? `Declare ${missingDeclarations.join(" and ")} for this hook before requesting execution.`
        : "Review hook policy before requesting execution.",
    commandExecuted: false,
    approvalGrantCreated: false,
    evidenceRefs: [
      "hook_escalation_receipt",
      hook?.id,
      runtimeEvent?.eventKind,
      planDecision?.decision,
    ].filter(Boolean),
  };
}

export function hookEscalationReceiptsForLedger(ledger = {}) {
  return normalizeArray(ledger.records)
    .filter((record) => record.escalation?.required === true)
    .map((record) => ({
      id: record.escalation.receiptId,
      kind: "hook_escalation",
      summary: `Hook ${record.hookName} on ${record.eventKind} is blocked until ${record.escalation.missingDeclarations.join(" and ") || "policy"} are declared.`,
      redaction: "redacted",
      evidenceRefs: [
        ledger.ledgerId,
        record.invocationId,
        record.dryRunPlanId,
        record.manifestId,
        "hook_escalation_receipt",
      ].filter(Boolean),
      details: {
        schemaVersion: "ioi.agent-runtime.hook-escalation-receipt.v1",
        object: "ioi.agent_hook_escalation_receipt",
        receiptId: record.escalation.receiptId,
        invocationId: record.invocationId,
        hookId: record.hookId,
        hookName: record.hookName,
        eventKind: record.eventKind,
        failurePolicy: record.failurePolicy,
        blockers: record.blockers,
        missingDeclarations: record.escalation.missingDeclarations,
        missingAuthorityScopes: record.escalation.missingAuthorityScopes,
        missingToolContracts: record.escalation.missingToolContracts,
        recommendedNextAction: record.escalation.recommendedNextAction,
        workflowNodeId: record.workflowNodeId,
        hookPolicyNodeId: record.hookPolicyNodeId,
        commandExecuted: false,
        approvalGrantCreated: false,
      },
    }));
}

export function normalizeManifestSelection(values) {
  const items = [];
  const visit = (value) => {
    if (Array.isArray(value)) {
      value.forEach(visit);
      return;
    }
    if (value && typeof value === "object") {
      for (const key of ["id", "name", "skillHash", "definitionHash"]) {
        if (value[key]) items.push(value[key]);
      }
      return;
    }
    if (value !== undefined && value !== null) items.push(value);
  };
  values.forEach(visit);
  return items.map((value) => optionalString(value)).filter(Boolean);
}

export function selectCatalogRecords(records, requestedRefs, hashField) {
  if (requestedRefs.length === 0) return records;
  const requested = new Set(requestedRefs.map(normalizeManifestToken));
  return records.filter((record) => {
    const candidates = [
      record.id,
      record.name,
      record[hashField],
      record.sourceId,
    ].map(normalizeManifestToken);
    return candidates.some((candidate) => requested.has(candidate));
  });
}

export function normalizeManifestToken(value) {
  return String(value ?? "").trim().toLowerCase().replace(/\s+/g, "-");
}

function normalizeArray(value) {
  return Array.isArray(value) ? value : [];
}

function optionalString(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed ? trimmed : null;
}

function doctorHash(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}
