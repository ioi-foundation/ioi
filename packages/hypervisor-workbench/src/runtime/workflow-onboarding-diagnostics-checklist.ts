export const WORKFLOW_ONBOARDING_DIAGNOSTICS_CHECKLIST_SCHEMA_VERSION =
  "ioi.workflow.onboarding-diagnostics-checklist.v1" as const;

export type WorkflowOnboardingDiagnosticCategory =
  | "workspace"
  | "local_binary"
  | "runtime_daemon"
  | "model_provider"
  | "container"
  | "policy";

export type WorkflowOnboardingDiagnosticRequirement = "required" | "recommended" | "optional";
export type WorkflowOnboardingDiagnosticState = "ready" | "needs_setup" | "blocked";

export interface WorkflowOnboardingDiagnosticCheck {
  id: string;
  label: string;
  category: WorkflowOnboardingDiagnosticCategory;
  requirement: WorkflowOnboardingDiagnosticRequirement;
  command?: string | null;
  detected: boolean;
  version?: string | null;
  detail?: string | null;
  remediation?: string | null;
  policyRef?: string | null;
}

export interface WorkflowOnboardingDiagnosticsChecklistInput {
  checks: readonly WorkflowOnboardingDiagnosticCheck[];
}

export interface WorkflowOnboardingDiagnosticsChecklistRow {
  id: string;
  label: string;
  category: WorkflowOnboardingDiagnosticCategory;
  requirement: WorkflowOnboardingDiagnosticRequirement;
  state: WorkflowOnboardingDiagnosticState;
  command: string | null;
  version: string | null;
  detail: string;
  remediation: string | null;
  policyRefs: string[];
}

export interface WorkflowOnboardingDiagnosticsChecklist {
  schemaVersion: typeof WORKFLOW_ONBOARDING_DIAGNOSTICS_CHECKLIST_SCHEMA_VERSION;
  status: "ready" | "needs_setup" | "blocked";
  rowCount: number;
  readyCount: number;
  needsSetupCount: number;
  blockedCount: number;
  requiredMissingCount: number;
  recommendedMissingCount: number;
  localBinaryCount: number;
  modelProviderCount: number;
  containerCheckCount: number;
  rows: WorkflowOnboardingDiagnosticsChecklistRow[];
}

export function buildWorkflowOnboardingDiagnosticsChecklist(
  input: WorkflowOnboardingDiagnosticsChecklistInput,
): WorkflowOnboardingDiagnosticsChecklist {
  const rows = normalizeChecks(input.checks).map(onboardingDiagnosticRow);
  const blockedCount = rows.filter((row) => row.state === "blocked").length;
  const needsSetupCount = rows.filter((row) => row.state === "needs_setup").length;
  const readyCount = rows.filter((row) => row.state === "ready").length;

  return {
    schemaVersion: WORKFLOW_ONBOARDING_DIAGNOSTICS_CHECKLIST_SCHEMA_VERSION,
    status: blockedCount > 0 ? "blocked" : needsSetupCount > 0 ? "needs_setup" : "ready",
    rowCount: rows.length,
    readyCount,
    needsSetupCount,
    blockedCount,
    requiredMissingCount: rows.filter((row) => row.requirement === "required" && row.state === "blocked").length,
    recommendedMissingCount: rows.filter((row) => row.requirement === "recommended" && row.state === "needs_setup").length,
    localBinaryCount: rows.filter((row) => row.category === "local_binary").length,
    modelProviderCount: rows.filter((row) => row.category === "model_provider").length,
    containerCheckCount: rows.filter((row) => row.category === "container").length,
    rows,
  };
}

function onboardingDiagnosticRow(
  check: WorkflowOnboardingDiagnosticCheck,
): WorkflowOnboardingDiagnosticsChecklistRow {
  const state = check.detected
    ? "ready"
    : check.requirement === "required"
      ? "blocked"
      : "needs_setup";
  return {
    id: safeId(check.id),
    label: check.label,
    category: check.category,
    requirement: check.requirement,
    state,
    command: stringField(check.command),
    version: redactedText(check.version),
    detail: redactedText(check.detail) ?? defaultDetail(check, state),
    remediation: redactedText(check.remediation),
    policyRefs: policyRefsForCheck(check, state),
  };
}

function policyRefsForCheck(
  check: WorkflowOnboardingDiagnosticCheck,
  state: WorkflowOnboardingDiagnosticState,
): string[] {
  const refs = ["policy:onboarding.diagnostics.visible"];
  if (check.policyRef) refs.push(check.policyRef);
  if (state === "blocked") refs.push("policy:onboarding.required_prerequisite_missing");
  if (state === "needs_setup") refs.push("policy:onboarding.optional_setup_recommended");
  if (check.category === "model_provider") refs.push("policy:onboarding.model_provider.not_runtime_truth");
  return refs;
}

function defaultDetail(
  check: WorkflowOnboardingDiagnosticCheck,
  state: WorkflowOnboardingDiagnosticState,
): string {
  if (state === "ready") return `${check.label} is available.`;
  if (check.requirement === "required") return `${check.label} is required before Hypervisor Workbench can run local workflows.`;
  return `${check.label} is not required, but setup will improve local workflow coverage.`;
}

function normalizeChecks(
  checks: readonly WorkflowOnboardingDiagnosticCheck[] | undefined,
): WorkflowOnboardingDiagnosticCheck[] {
  return Array.isArray(checks) ? checks.filter(Boolean) : [];
}

function redactedText(value: unknown): string | null {
  const text = stringField(value);
  return text?.replace(/\b(?:sk-[a-z0-9_-]{8,}|ghp_[a-z0-9_]{8,})\b/gi, "[REDACTED]") ?? null;
}

function stringField(value: unknown): string | null {
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function safeId(value: string): string {
  return (
    value
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9._:-]+/g, "-")
      .replace(/^-+|-+$/g, "") || "check"
  );
}
