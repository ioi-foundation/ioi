export const WORKFLOW_SAFE_MODE_TOOL_SUPPRESSION_SCHEMA_VERSION =
  "ioi.workflow.safe-mode-tool-suppression.v1" as const;

export type WorkflowSafeModeTrigger =
  | "bridge_timeout"
  | "daemon_reconnect"
  | "security_scan"
  | "manual"
  | "unknown";

export type WorkflowSafeModeSurface =
  | "ask"
  | "agent"
  | "workflow"
  | "terminal"
  | "browser"
  | "migration"
  | "trace";

export type WorkflowSafeModeAuthority = "none" | "read" | "write" | "execute" | "network";
export type WorkflowSafeModeControlState = "enabled" | "read_only" | "disabled";

export interface WorkflowSafeModeState {
  enabled: boolean;
  reason?: string | null;
  trigger?: WorkflowSafeModeTrigger | null;
  enteredAtMs?: number | null;
  allowAskWithoutTools?: boolean | null;
  exitRequires?: "daemon_reconnect" | "user_ack" | "security_clearance" | "manual" | null;
}

export interface WorkflowSafeModeControl {
  id: string;
  label: string;
  surface: WorkflowSafeModeSurface;
  authority: WorkflowSafeModeAuthority;
  requiresRuntimeBridge?: boolean | null;
  receiptRequired?: boolean | null;
}

export interface WorkflowSafeModeToolSuppressionInput {
  safeMode: WorkflowSafeModeState;
  controls: readonly WorkflowSafeModeControl[];
}

export interface WorkflowSafeModeToolSuppressionRow {
  id: string;
  label: string;
  surface: WorkflowSafeModeSurface;
  authority: WorkflowSafeModeAuthority;
  state: WorkflowSafeModeControlState;
  reason: string | null;
  policyRefs: string[];
}

export interface WorkflowSafeModeToolSuppressionPanel {
  schemaVersion: typeof WORKFLOW_SAFE_MODE_TOOL_SUPPRESSION_SCHEMA_VERSION;
  status: "normal" | "safe_mode";
  trigger: WorkflowSafeModeTrigger;
  reason: string | null;
  exitRequires: "daemon_reconnect" | "user_ack" | "security_clearance" | "manual";
  responsibilityBoundary: {
    askDirectTextAllowed: boolean;
    agentHarnessAllowed: boolean;
    toolsSuppressed: boolean;
  };
  enabledCount: number;
  readOnlyCount: number;
  disabledCount: number;
  controls: WorkflowSafeModeToolSuppressionRow[];
}

export function buildWorkflowSafeModeToolSuppressionPanel(
  input: WorkflowSafeModeToolSuppressionInput,
): WorkflowSafeModeToolSuppressionPanel {
  const safeMode = input.safeMode ?? { enabled: false };
  const rows = normalizeControls(input.controls).map((control) => safeModeControlRow(control, safeMode));
  const disabledCount = rows.filter((row) => row.state === "disabled").length;
  const readOnlyCount = rows.filter((row) => row.state === "read_only").length;
  const enabledCount = rows.filter((row) => row.state === "enabled").length;
  const askDirectTextAllowed = rows.some((row) => row.surface === "ask" && row.state === "enabled");
  const agentHarnessAllowed = rows
    .filter((row) => row.surface === "agent")
    .every((row) => row.state !== "disabled");

  return {
    schemaVersion: WORKFLOW_SAFE_MODE_TOOL_SUPPRESSION_SCHEMA_VERSION,
    status: safeMode.enabled ? "safe_mode" : "normal",
    trigger: safeMode.trigger ?? "unknown",
    reason: stringField(safeMode.reason),
    exitRequires: safeMode.exitRequires ?? "daemon_reconnect",
    responsibilityBoundary: {
      askDirectTextAllowed,
      agentHarnessAllowed,
      toolsSuppressed: safeMode.enabled && disabledCount > 0,
    },
    enabledCount,
    readOnlyCount,
    disabledCount,
    controls: rows,
  };
}

function safeModeControlRow(
  control: WorkflowSafeModeControl,
  safeMode: WorkflowSafeModeState,
): WorkflowSafeModeToolSuppressionRow {
  if (!safeMode.enabled) {
    return {
      id: control.id,
      label: control.label,
      surface: control.surface,
      authority: control.authority,
      state: "enabled",
      reason: null,
      policyRefs: ["policy:safe_mode.normal"],
    };
  }

  const askDirectAllowed = safeMode.allowAskWithoutTools !== false &&
    control.surface === "ask" &&
    (control.authority === "none" || control.authority === "read") &&
    !control.requiresRuntimeBridge;

  if (askDirectAllowed) {
    return {
      id: control.id,
      label: control.label,
      surface: control.surface,
      authority: control.authority,
      state: "enabled",
      reason: "Direct Ask text is allowed while tool authority is suppressed.",
      policyRefs: [
        "policy:safe_mode.enabled",
        "policy:safe_mode.ask_direct_no_tools",
      ],
    };
  }

  if (control.authority === "read" && !control.requiresRuntimeBridge) {
    return {
      id: control.id,
      label: control.label,
      surface: control.surface,
      authority: control.authority,
      state: "read_only",
      reason: "Read-only review remains available during Safe Mode.",
      policyRefs: [
        "policy:safe_mode.enabled",
        "policy:safe_mode.read_only_review",
      ],
    };
  }

  return {
    id: control.id,
    label: control.label,
    surface: control.surface,
    authority: control.authority,
    state: "disabled",
    reason: disabledReason(control),
    policyRefs: [
      "policy:safe_mode.enabled",
      "policy:safe_mode.suppress_tools",
      ...(control.receiptRequired ? ["policy:safe_mode.receipt_required_before_resume"] : []),
    ],
  };
}

function disabledReason(control: WorkflowSafeModeControl): string {
  if (control.surface === "agent") {
    return "Agent harness is disabled until runtime authority is restored.";
  }
  if (control.authority === "network") {
    return "Network-capable actions are disabled during Safe Mode.";
  }
  if (control.authority === "execute") {
    return "Execution-capable actions are disabled during Safe Mode.";
  }
  if (control.requiresRuntimeBridge) {
    return "Runtime-bridge-backed actions are disabled during Safe Mode.";
  }
  return "Tool authority is disabled during Safe Mode.";
}

function normalizeControls(
  controls: readonly WorkflowSafeModeControl[] | undefined,
): WorkflowSafeModeControl[] {
  return Array.isArray(controls) ? controls.filter(Boolean) : [];
}

function stringField(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}
