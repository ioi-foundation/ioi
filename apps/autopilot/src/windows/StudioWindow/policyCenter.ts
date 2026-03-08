import { invoke } from "@tauri-apps/api/core";

export type PolicyDecisionMode = "auto" | "confirm" | "block";
export type AutomationPolicyMode =
  | "confirm_on_create"
  | "confirm_on_run"
  | "manual_only";
export type DataHandlingMode = "local_only" | "local_redacted";

export interface GlobalPolicyDefaults {
  reads: PolicyDecisionMode;
  writes: PolicyDecisionMode;
  admin: PolicyDecisionMode;
  expert: PolicyDecisionMode;
  automations: AutomationPolicyMode;
  dataHandling: DataHandlingMode;
}

export interface ConnectorPolicyOverride extends GlobalPolicyDefaults {
  inheritGlobal: boolean;
}

export interface ShieldPolicyState {
  version: 1;
  global: GlobalPolicyDefaults;
  overrides: Record<string, ConnectorPolicyOverride>;
}

export interface ConnectorPolicySummary {
  headline: string;
  detail: string;
}

const STORAGE_KEY = "ioi:shield-policy:v1";

const DEFAULT_GLOBAL_POLICY: GlobalPolicyDefaults = {
  reads: "auto",
  writes: "confirm",
  admin: "confirm",
  expert: "block",
  automations: "confirm_on_create",
  dataHandling: "local_only",
};

function isDecisionMode(value: unknown): value is PolicyDecisionMode {
  return value === "auto" || value === "confirm" || value === "block";
}

function isAutomationMode(value: unknown): value is AutomationPolicyMode {
  return (
    value === "confirm_on_create" || value === "confirm_on_run" || value === "manual_only"
  );
}

function isDataHandlingMode(value: unknown): value is DataHandlingMode {
  return value === "local_only" || value === "local_redacted";
}

function normalizeDefaults(input: unknown): GlobalPolicyDefaults {
  const record = input && typeof input === "object" ? (input as Record<string, unknown>) : {};
  return {
    reads: isDecisionMode(record.reads) ? record.reads : DEFAULT_GLOBAL_POLICY.reads,
    writes: isDecisionMode(record.writes) ? record.writes : DEFAULT_GLOBAL_POLICY.writes,
    admin: isDecisionMode(record.admin) ? record.admin : DEFAULT_GLOBAL_POLICY.admin,
    expert: isDecisionMode(record.expert) ? record.expert : DEFAULT_GLOBAL_POLICY.expert,
    automations: isAutomationMode(record.automations)
      ? record.automations
      : DEFAULT_GLOBAL_POLICY.automations,
    dataHandling: isDataHandlingMode(record.dataHandling)
      ? record.dataHandling
      : DEFAULT_GLOBAL_POLICY.dataHandling,
  };
}

function normalizeOverride(input: unknown): ConnectorPolicyOverride {
  const defaults = normalizeDefaults(input);
  const record = input && typeof input === "object" ? (input as Record<string, unknown>) : {};
  return {
    ...defaults,
    inheritGlobal: record.inheritGlobal !== false,
  };
}

export function createDefaultShieldPolicyState(): ShieldPolicyState {
  return {
    version: 1,
    global: { ...DEFAULT_GLOBAL_POLICY },
    overrides: {},
  };
}

export function normalizeShieldPolicyState(input: unknown): ShieldPolicyState {
  const parsed = input && typeof input === "object" ? (input as Record<string, unknown>) : {};
  const overridesRecord =
    parsed.overrides && typeof parsed.overrides === "object"
      ? (parsed.overrides as Record<string, unknown>)
      : {};

  return {
    version: 1,
    global: normalizeDefaults(parsed.global),
    overrides: Object.fromEntries(
      Object.entries(overridesRecord).map(([connectorId, value]) => [
        connectorId,
        normalizeOverride(value),
      ]),
    ),
  };
}

export function loadShieldPolicyState(): ShieldPolicyState {
  if (typeof window === "undefined") {
    return createDefaultShieldPolicyState();
  }

  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return createDefaultShieldPolicyState();
    return normalizeShieldPolicyState(JSON.parse(raw));
  } catch (_error) {
    return createDefaultShieldPolicyState();
  }
}

export function persistShieldPolicyState(state: ShieldPolicyState): void {
  if (typeof window === "undefined") return;
  window.localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
}

export async function fetchShieldPolicyStateFromRuntime(): Promise<ShieldPolicyState> {
  try {
    const result = await invoke("connector_policy_get");
    const normalized = normalizeShieldPolicyState(result);
    persistShieldPolicyState(normalized);
    return normalized;
  } catch (_error) {
    return loadShieldPolicyState();
  }
}

export async function persistShieldPolicyStateToRuntime(
  state: ShieldPolicyState,
): Promise<ShieldPolicyState> {
  persistShieldPolicyState(state);
  try {
    const result = await invoke("connector_policy_set", { policy: state });
    const normalized = normalizeShieldPolicyState(result);
    persistShieldPolicyState(normalized);
    return normalized;
  } catch (_error) {
    return state;
  }
}

export function resolveConnectorPolicy(
  state: ShieldPolicyState,
  connectorId: string,
): { effective: GlobalPolicyDefaults; override: ConnectorPolicyOverride | null } {
  const override = state.overrides[connectorId];
  if (!override || override.inheritGlobal) {
    return {
      effective: { ...state.global },
      override: override ?? null,
    };
  }
  return {
    effective: {
      reads: override.reads,
      writes: override.writes,
      admin: override.admin,
      expert: override.expert,
      automations: override.automations,
      dataHandling: override.dataHandling,
    },
    override,
  };
}

export function updateConnectorOverride(
  state: ShieldPolicyState,
  connectorId: string,
  nextOverride: Partial<ConnectorPolicyOverride>,
): ShieldPolicyState {
  const current = state.overrides[connectorId] ?? {
    inheritGlobal: true,
    ...state.global,
  };
  return {
    ...state,
    overrides: {
      ...state.overrides,
      [connectorId]: {
        ...current,
        ...nextOverride,
      },
    },
  };
}

export function resetConnectorOverride(
  state: ShieldPolicyState,
  connectorId: string,
): ShieldPolicyState {
  const nextOverrides = { ...state.overrides };
  delete nextOverrides[connectorId];
  return {
    ...state,
    overrides: nextOverrides,
  };
}

function decisionLabel(value: PolicyDecisionMode): string {
  switch (value) {
    case "auto":
      return "Auto";
    case "confirm":
      return "Confirm";
    case "block":
      return "Block";
    default:
      return value;
  }
}

function automationLabel(value: AutomationPolicyMode): string {
  switch (value) {
    case "confirm_on_create":
      return "Confirm on create";
    case "confirm_on_run":
      return "Confirm on run";
    case "manual_only":
      return "Manual only";
    default:
      return value;
  }
}

export function buildConnectorPolicySummary(
  state: ShieldPolicyState,
  connectorId: string,
): ConnectorPolicySummary {
  const { effective, override } = resolveConnectorPolicy(state, connectorId);
  return {
    headline:
      !override || override.inheritGlobal ? "Policy inherits global defaults" : "Policy override active",
    detail: `Reads ${decisionLabel(effective.reads)} · Writes ${decisionLabel(
      effective.writes,
    )} · Automations ${automationLabel(effective.automations)}`,
  };
}

export function countActiveOverrides(state: ShieldPolicyState): number {
  return Object.values(state.overrides).filter((override) => !override.inheritGlobal).length;
}
