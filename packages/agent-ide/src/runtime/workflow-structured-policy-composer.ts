import {
  createRuntimeCodingToolControlRequest,
  type RuntimeCodingToolControlRequest,
} from "./workflow-runtime-coding-tool-control-nodes.ts";
import { stableContentHash } from "./harness-workflow/hashing.ts";

export const WORKFLOW_STRUCTURED_POLICY_COMPOSER_SCHEMA_VERSION =
  "ioi.workflow.structured-policy-composer.v1" as const;

export type WorkflowStructuredPolicyStatus = "ready" | "blocked";

export interface WorkflowStructuredAuthorityRuleInput {
  id?: string | null;
  target?: "runtime_coding_tool" | "computer_use" | "subagent" | string | null;
  tools?: readonly string[] | null;
  effectClasses?: readonly string[] | null;
  requiresApproval?: boolean | null;
  approvalMode?: string | null;
  trustProfile?: string | null;
  nodeApprovalOverride?: string | null;
  authorityScopes?: readonly string[] | null;
  leaseTtlMs?: number | string | null;
  expectedReceiptRefs?: readonly string[] | null;
  policyDecisionRefs?: readonly string[] | null;
}

export interface WorkflowStructuredMemoryRuleInput {
  id?: string | null;
  target?: "thread" | "subagent" | "workflow" | string | null;
  scope?: string | null;
  readOnly?: boolean | null;
  injectionEnabled?: boolean | null;
  writeRequiresApproval?: boolean | null;
  subagentInheritance?: string | null;
  retention?: string | null;
  redaction?: string | null;
}

export interface WorkflowStructuredModelRuleInput {
  id?: string | null;
  privacy?: string | null;
  allowHostedFallback?: boolean | null;
  maxCostUsd?: number | string | null;
  reasoningEffort?: string | null;
}

export interface WorkflowStructuredPolicyInput {
  id?: string | null;
  name?: string | null;
  authorityRules?: readonly WorkflowStructuredAuthorityRuleInput[] | null;
  memoryRules?: readonly WorkflowStructuredMemoryRuleInput[] | null;
  modelRules?: readonly WorkflowStructuredModelRuleInput[] | null;
  advisoryGuidelines?: readonly string[] | null;
}

export interface WorkflowStructuredAuthorityRule {
  id: string;
  target: string;
  tools: string[];
  effectClasses: string[];
  requiresApproval: boolean;
  approvalMode: string;
  trustProfile: string;
  nodeApprovalOverride: string;
  authorityScopes: string[];
  leaseTtlMs: number | null;
  expectedReceiptRefs: string[];
  policyDecisionRefs: string[];
}

export interface WorkflowStructuredMemoryRule {
  id: string;
  target: string;
  scope: string;
  readOnly: boolean;
  injectionEnabled: boolean;
  writeRequiresApproval: boolean;
  subagentInheritance: string;
  retention: string | null;
  redaction: string | null;
}

export interface WorkflowStructuredModelRule {
  id: string;
  privacy: string;
  allowHostedFallback: boolean;
  maxCostUsd: number | null;
  reasoningEffort: string | null;
}

export interface WorkflowStructuredPolicyDiagnostic {
  code: string;
  severity: "info" | "warning" | "error";
  message: string;
}

export interface WorkflowStructuredPolicyCompilation {
  schemaVersion: typeof WORKFLOW_STRUCTURED_POLICY_COMPOSER_SCHEMA_VERSION;
  status: WorkflowStructuredPolicyStatus;
  policyId: string;
  name: string | null;
  policyHash: string;
  enforceableRuleCount: number;
  advisoryGuidelineCount: number;
  promptSoupGuard: "passed" | "blocked";
  diagnostics: WorkflowStructuredPolicyDiagnostic[];
  authorityRules: WorkflowStructuredAuthorityRule[];
  memoryRules: WorkflowStructuredMemoryRule[];
  modelRules: WorkflowStructuredModelRule[];
  advisoryGuidelines: string[];
  constraints: {
    authority: WorkflowStructuredAuthorityRule[];
    memory: WorkflowStructuredMemoryRule[];
    model: WorkflowStructuredModelRule[];
  };
}

export interface PolicyBoundRuntimeCodingToolRequestInput {
  threadId: string;
  toolId: string;
  toolInput: Record<string, unknown>;
  compiledPolicy: WorkflowStructuredPolicyCompilation;
  workflowGraphId?: string | null;
  workflowNodeId?: string | null;
  actor?: string | null;
  effectClass?: string | null;
  toolCallId?: string | null;
}

export type PolicyBoundRuntimeCodingToolRequest = RuntimeCodingToolControlRequest & {
  body: RuntimeCodingToolControlRequest["body"] & Record<string, unknown>;
};

export function compileWorkflowStructuredPolicy(
  input: WorkflowStructuredPolicyInput,
): WorkflowStructuredPolicyCompilation {
  const authorityRules = (input.authorityRules ?? []).map((rule, index) =>
    normalizeAuthorityRule(rule, index),
  );
  const memoryRules = (input.memoryRules ?? []).map((rule, index) =>
    normalizeMemoryRule(rule, index),
  );
  const modelRules = (input.modelRules ?? []).map((rule, index) =>
    normalizeModelRule(rule, index),
  );
  const advisoryGuidelines = uniqueStrings(input.advisoryGuidelines ?? []);
  const enforceableRuleCount =
    authorityRules.length + memoryRules.length + modelRules.length;
  const diagnostics: WorkflowStructuredPolicyDiagnostic[] = [];
  if (enforceableRuleCount === 0) {
    diagnostics.push({
      code: "prompt_soup_no_enforceable_rules",
      severity: "error",
      message: "Policy Composer needs at least one structured rule before advisory text can affect runtime authority.",
    });
  }
  if (advisoryGuidelines.length > 0) {
    diagnostics.push({
      code: "advisory_guidelines_not_authority",
      severity: enforceableRuleCount > 0 ? "info" : "warning",
      message: "Advisory guidelines are retained for prompt context but do not grant or deny daemon authority.",
    });
  }
  const policyId = cleanString(input.id) ?? "workflow.policy.structured";
  const normalized = {
    policyId,
    name: cleanString(input.name),
    authorityRules,
    memoryRules,
    modelRules,
    advisoryGuidelines,
  };
  const policyHash = stableContentHash(normalized);
  const status: WorkflowStructuredPolicyStatus =
    enforceableRuleCount > 0 && !diagnostics.some((diagnostic) => diagnostic.severity === "error")
      ? "ready"
      : "blocked";
  return {
    schemaVersion: WORKFLOW_STRUCTURED_POLICY_COMPOSER_SCHEMA_VERSION,
    status,
    policyId,
    name: cleanString(input.name),
    policyHash,
    enforceableRuleCount,
    advisoryGuidelineCount: advisoryGuidelines.length,
    promptSoupGuard: status === "ready" ? "passed" : "blocked",
    diagnostics,
    authorityRules,
    memoryRules,
    modelRules,
    advisoryGuidelines,
    constraints: {
      authority: authorityRules,
      memory: memoryRules,
      model: modelRules,
    },
  };
}

export function createPolicyBoundRuntimeCodingToolControlRequest(
  input: PolicyBoundRuntimeCodingToolRequestInput,
): PolicyBoundRuntimeCodingToolRequest {
  if (input.compiledPolicy.status !== "ready") {
    throw new Error("Cannot build a daemon request from a blocked structured policy.");
  }
  const authorityRule = authorityRuleForTool(
    input.compiledPolicy,
    input.toolId,
    input.effectClass,
  );
  const toolPack = {
    structuredPolicy: {
      schemaVersion: input.compiledPolicy.schemaVersion,
      policyId: input.compiledPolicy.policyId,
      policyHash: input.compiledPolicy.policyHash,
    },
    policyHash: input.compiledPolicy.policyHash,
    policy_hash: input.compiledPolicy.policyHash,
    authorityScopes: authorityRule?.authorityScopes ?? [],
    authority_scope_requirements: authorityRule?.authorityScopes ?? [],
    expectedReceiptRefs: authorityRule?.expectedReceiptRefs ?? [],
    expected_receipt_refs: authorityRule?.expectedReceiptRefs ?? [],
    policyDecisionRefs: authorityRule?.policyDecisionRefs ?? [],
    policy_decision_refs: authorityRule?.policyDecisionRefs ?? [],
  };
  const request = createRuntimeCodingToolControlRequest({
    threadId: input.threadId,
    toolId: input.toolId,
    toolInput: input.toolInput,
    workflowGraphId: input.workflowGraphId,
    workflowNodeId: input.workflowNodeId,
    actor: input.actor,
    requiresApproval: authorityRule?.requiresApproval ?? false,
    approvalMode: authorityRule?.approvalMode ?? "suggest",
    trustProfile: authorityRule?.trustProfile ?? "local_private",
    nodeApprovalOverride: authorityRule?.nodeApprovalOverride ?? "inherit",
    toolPack,
  }) as PolicyBoundRuntimeCodingToolRequest;
  const requestFields: Record<string, unknown> = {
    structured_policy: {
      schemaVersion: input.compiledPolicy.schemaVersion,
      policyId: input.compiledPolicy.policyId,
      policyHash: input.compiledPolicy.policyHash,
      constraints: input.compiledPolicy.constraints,
    },
    structuredPolicy: {
      schemaVersion: input.compiledPolicy.schemaVersion,
      policyId: input.compiledPolicy.policyId,
      policyHash: input.compiledPolicy.policyHash,
      constraints: input.compiledPolicy.constraints,
    },
    policy_hash: input.compiledPolicy.policyHash,
    policyHash: input.compiledPolicy.policyHash,
    authority_scope_requirements: authorityRule?.authorityScopes ?? [],
    authorityScopeRequirements: authorityRule?.authorityScopes ?? [],
    expected_receipt_refs: authorityRule?.expectedReceiptRefs ?? [],
    expectedReceiptRefs: authorityRule?.expectedReceiptRefs ?? [],
    policy_decision_refs: authorityRule?.policyDecisionRefs ?? [],
    policyDecisionRefs: authorityRule?.policyDecisionRefs ?? [],
  };
  if (authorityRule?.leaseTtlMs) {
    requestFields.ttl_ms = authorityRule.leaseTtlMs;
    requestFields.ttlMs = authorityRule.leaseTtlMs;
    requestFields.lease_ttl_ms = authorityRule.leaseTtlMs;
    requestFields.leaseTtlMs = authorityRule.leaseTtlMs;
  }
  if (input.toolCallId) {
    requestFields.tool_call_id = input.toolCallId;
    requestFields.toolCallId = input.toolCallId;
  }
  request.body = {
    ...request.body,
    ...requestFields,
  };
  return request;
}

function normalizeAuthorityRule(
  rule: WorkflowStructuredAuthorityRuleInput,
  index: number,
): WorkflowStructuredAuthorityRule {
  const requiresApproval = rule.requiresApproval ?? false;
  return {
    id: cleanString(rule.id) ?? `authority-rule-${index + 1}`,
    target: cleanString(rule.target) ?? "runtime_coding_tool",
    tools: uniqueStrings(rule.tools ?? []),
    effectClasses: uniqueStrings(rule.effectClasses ?? []),
    requiresApproval,
    approvalMode: cleanString(rule.approvalMode) ?? (requiresApproval ? "human_required" : "suggest"),
    trustProfile: cleanString(rule.trustProfile) ?? "local_private",
    nodeApprovalOverride:
      cleanString(rule.nodeApprovalOverride) ?? (requiresApproval ? "require_approval" : "inherit"),
    authorityScopes: uniqueStrings(rule.authorityScopes ?? []),
    leaseTtlMs: positiveNumber(rule.leaseTtlMs),
    expectedReceiptRefs: uniqueStrings(rule.expectedReceiptRefs ?? []),
    policyDecisionRefs: uniqueStrings(rule.policyDecisionRefs ?? []),
  };
}

function normalizeMemoryRule(
  rule: WorkflowStructuredMemoryRuleInput,
  index: number,
): WorkflowStructuredMemoryRule {
  const readOnly = rule.readOnly ?? false;
  return {
    id: cleanString(rule.id) ?? `memory-rule-${index + 1}`,
    target: cleanString(rule.target) ?? "thread",
    scope: cleanString(rule.scope) ?? "thread",
    readOnly,
    injectionEnabled: rule.injectionEnabled ?? true,
    writeRequiresApproval: rule.writeRequiresApproval ?? readOnly,
    subagentInheritance: cleanString(rule.subagentInheritance) ?? (readOnly ? "read_only" : "explicit"),
    retention: cleanString(rule.retention),
    redaction: cleanString(rule.redaction),
  };
}

function normalizeModelRule(
  rule: WorkflowStructuredModelRuleInput,
  index: number,
): WorkflowStructuredModelRule {
  return {
    id: cleanString(rule.id) ?? `model-rule-${index + 1}`,
    privacy: cleanString(rule.privacy) ?? "local_only",
    allowHostedFallback: rule.allowHostedFallback ?? false,
    maxCostUsd: positiveNumber(rule.maxCostUsd),
    reasoningEffort: cleanString(rule.reasoningEffort),
  };
}

function authorityRuleForTool(
  compiledPolicy: WorkflowStructuredPolicyCompilation,
  toolId: string,
  effectClass: string | null | undefined,
): WorkflowStructuredAuthorityRule | null {
  const normalizedToolId = cleanString(toolId);
  const normalizedEffectClass = cleanString(effectClass);
  return (
    compiledPolicy.authorityRules.find((rule) => {
      if (rule.target !== "runtime_coding_tool") return false;
      const toolMatches = rule.tools.length === 0 || rule.tools.includes(normalizedToolId ?? "");
      const effectMatches =
        rule.effectClasses.length === 0 ||
        (normalizedEffectClass ? rule.effectClasses.includes(normalizedEffectClass) : true);
      return toolMatches && effectMatches;
    }) ?? null
  );
}

function cleanString(value: unknown): string | null {
  if (value === undefined || value === null) return null;
  const text = String(value).trim();
  return text ? text : null;
}

function positiveNumber(value: unknown): number | null {
  if (value === undefined || value === null || value === "") return null;
  const number = typeof value === "number" ? value : Number(value);
  return Number.isFinite(number) && number > 0 ? number : null;
}

function uniqueStrings(values: readonly unknown[]): string[] {
  return Array.from(
    new Set(values.map((value) => cleanString(value)).filter((value): value is string => Boolean(value))),
  ).sort();
}
