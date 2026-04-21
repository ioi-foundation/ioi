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

export type SessionPermissionProfileId =
  | "safer_review"
  | "guided_default"
  | "autonomous"
  | "expert";

export interface SessionPermissionProfile {
  id: SessionPermissionProfileId;
  label: string;
  summary: string;
  detail: string;
  policy: GlobalPolicyDefaults;
}

export interface ShieldRememberedApprovalDecision {
  decisionId: string;
  connectorId: string;
  actionId: string;
  actionLabel: string;
  policyFamily: string;
  scopeKey: string;
  scopeLabel: string;
  scopeMode: ShieldApprovalScopeMode;
  sourceLabel: string;
  createdAtMs: number;
  lastMatchedAtMs?: number | null;
  expiresAtMs?: number | null;
  matchCount: number;
  status: string;
}

export type ShieldApprovalScopeMode =
  | "exact_action"
  | "connector_policy_family";

export interface ShieldApprovalHookReceipt {
  receiptId: string;
  timestampMs: number;
  hookKind: string;
  status: string;
  summary: string;
  connectorId: string;
  actionId: string;
  decisionId?: string | null;
}

export interface ShieldRememberedApprovalSnapshot {
  generatedAtMs: number;
  activeDecisionCount: number;
  recentReceiptCount: number;
  decisions: ShieldRememberedApprovalDecision[];
  recentReceipts: ShieldApprovalHookReceipt[];
}

export interface ShieldRememberApprovalInput {
  connectorId: string;
  actionId: string;
  actionLabel: string;
  policyFamily: string;
  scopeKey?: string | null;
  scopeLabel?: string | null;
  sourceLabel?: string | null;
  scopeMode?: ShieldApprovalScopeMode | null;
  expiresAtMs?: number | null;
}

export interface ShieldRememberedApprovalScopeUpdateInput {
  decisionId: string;
  scopeMode: ShieldApprovalScopeMode;
}

export interface ShieldRememberedApprovalExpiryUpdateInput {
  decisionId: string;
  expiresAtMs?: number | null;
}

export type PolicySimulationOutcome = "auto" | "gate" | "deny";

export interface PolicySimulationItem {
  id: string;
  label: string;
  outcome: PolicySimulationOutcome;
  detail: string;
  rationale: string;
}

export interface PolicySimulationDeck {
  summary: Record<PolicySimulationOutcome, number>;
  scenarios: PolicySimulationItem[];
  artifactHandling: {
    mode: DataHandlingMode;
    label: string;
    detail: string;
  };
}

export interface PolicyDeltaItem {
  id: string;
  label: string;
  baseline: string;
  next: string;
  change: "wider" | "tighter";
  detail: string;
}

export interface PolicyDeltaDeck {
  baselineLabel: string;
  nextLabel: string;
  items: PolicyDeltaItem[];
}

export type CapabilityPolicyIntentAction = "widen" | "baseline";

export type CapabilityGovernanceRequestStatus = "pending";

export interface CapabilityGovernanceRequest {
  requestId: string;
  createdAtMs: number;
  status: CapabilityGovernanceRequestStatus;
  action: CapabilityPolicyIntentAction;
  capabilityEntryId: string;
  capabilityLabel: string;
  capabilityKind: string;
  governingEntryId?: string | null;
  governingLabel?: string | null;
  governingKind?: string | null;
  connectorId: string;
  connectorLabel: string;
  sourceLabel: string;
  authorityTierLabel: string;
  governedProfileLabel?: string | null;
  leaseModeLabel?: string | null;
  whySelectable: string;
  headline: string;
  detail: string;
  requestedState: ShieldPolicyState;
}

export interface CapabilityGovernanceTargetOption {
  targetEntryId: string;
  targetLabel: string;
  targetKind: string;
  targetSummary: string;
  recommendationReason: string;
  deltaSummary: string;
  request: CapabilityGovernanceRequest;
  deltaMagnitude?: number;
}

export interface CapabilityGovernanceProposal {
  capabilityEntryId: string;
  capabilityLabel: string;
  action: CapabilityPolicyIntentAction;
  recommendedTargetEntryId: string;
  targets: CapabilityGovernanceTargetOption[];
  comparedEntryId?: string | null;
  comparedEntryLabel?: string | null;
}

const STORAGE_KEY = "ioi:shield-policy:v1";
const SHIELD_POLICY_UPDATED_EVENT = "ioi:shield-policy-updated";

const DEFAULT_GLOBAL_POLICY: GlobalPolicyDefaults = {
  reads: "auto",
  writes: "confirm",
  admin: "confirm",
  expert: "block",
  automations: "confirm_on_create",
  dataHandling: "local_only",
};

const SESSION_PERMISSION_PROFILES: SessionPermissionProfile[] = [
  {
    id: "safer_review",
    label: "Safer review",
    summary: "Keep risky actions approval-bound and durable automation disabled.",
    detail:
      "Best for cautious repo work, approvals, and policy review where the shell should bias toward confirmation before acting.",
    policy: {
      reads: "confirm",
      writes: "confirm",
      admin: "block",
      expert: "block",
      automations: "manual_only",
      dataHandling: "local_only",
    },
  },
  {
    id: "guided_default",
    label: "Guided default",
    summary: "Match the shipped runtime posture with guarded writes and blocked expert actions.",
    detail:
      "Balanced day-to-day operator posture: reads may flow automatically, writes stay approval-bound, and expert actions remain blocked.",
    policy: { ...DEFAULT_GLOBAL_POLICY },
  },
  {
    id: "autonomous",
    label: "Autonomous",
    summary: "Reduce friction for routine reads and writes while keeping admin changes reviewable.",
    detail:
      "Useful when the operator wants more autonomous task execution without opening the shell all the way to unrestricted expert behavior.",
    policy: {
      reads: "auto",
      writes: "auto",
      admin: "confirm",
      expert: "confirm",
      automations: "confirm_on_create",
      dataHandling: "local_redacted",
    },
  },
  {
    id: "expert",
    label: "Expert",
    summary: "Allow the broadest runtime posture, including expert actions and admin changes.",
    detail:
      "Closest to a bypass-style shell. Use only when the operator explicitly wants broad autonomous authority and redacted export handling.",
    policy: {
      reads: "auto",
      writes: "auto",
      admin: "auto",
      expert: "auto",
      automations: "confirm_on_create",
      dataHandling: "local_redacted",
    },
  },
];

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
  window.dispatchEvent(
    new CustomEvent<ShieldPolicyState>(SHIELD_POLICY_UPDATED_EVENT, {
      detail: state,
    }),
  );
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
  const previousState = loadShieldPolicyState();
  try {
    const result = await invoke("connector_policy_set", { policy: state });
    const normalized = normalizeShieldPolicyState(result);
    persistShieldPolicyState(normalized);
    return normalized;
  } catch (error) {
    persistShieldPolicyState(previousState);
    const detail = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to persist shield policy state to runtime: ${detail}`);
  }
}

export async function fetchShieldRememberedApprovalSnapshotFromRuntime(): Promise<ShieldRememberedApprovalSnapshot> {
  const result = await invoke("connector_policy_memory_get");
  return result as ShieldRememberedApprovalSnapshot;
}

export async function rememberShieldApprovalInRuntime(
  input: ShieldRememberApprovalInput,
): Promise<ShieldRememberedApprovalSnapshot> {
  const result = await invoke("connector_policy_memory_remember", { input });
  return result as ShieldRememberedApprovalSnapshot;
}

export async function forgetShieldApprovalInRuntime(
  decisionId: string,
): Promise<ShieldRememberedApprovalSnapshot> {
  const result = await invoke("connector_policy_memory_forget", { decisionId });
  return result as ShieldRememberedApprovalSnapshot;
}

export async function setShieldApprovalScopeModeInRuntime(
  input: ShieldRememberedApprovalScopeUpdateInput,
): Promise<ShieldRememberedApprovalSnapshot> {
  const result = await invoke("connector_policy_memory_set_scope_mode", {
    input,
  });
  return result as ShieldRememberedApprovalSnapshot;
}

export async function setShieldApprovalExpiryInRuntime(
  input: ShieldRememberedApprovalExpiryUpdateInput,
): Promise<ShieldRememberedApprovalSnapshot> {
  const result = await invoke("connector_policy_memory_set_expiry", { input });
  return result as ShieldRememberedApprovalSnapshot;
}

export function listSessionPermissionProfiles(): SessionPermissionProfile[] {
  return SESSION_PERMISSION_PROFILES.map((profile) => ({
    ...profile,
    policy: { ...profile.policy },
  }));
}

function policyDefaultsEqual(
  left: GlobalPolicyDefaults,
  right: GlobalPolicyDefaults,
): boolean {
  return (
    left.reads === right.reads &&
    left.writes === right.writes &&
    left.admin === right.admin &&
    left.expert === right.expert &&
    left.automations === right.automations &&
    left.dataHandling === right.dataHandling
  );
}

export function resolveSessionPermissionProfileId(
  state: ShieldPolicyState,
): SessionPermissionProfileId | null {
  const match = SESSION_PERMISSION_PROFILES.find((profile) =>
    policyDefaultsEqual(profile.policy, state.global),
  );
  return match?.id ?? null;
}

export function applySessionPermissionProfile(
  state: ShieldPolicyState,
  profileId: SessionPermissionProfileId,
): ShieldPolicyState {
  const profile = SESSION_PERMISSION_PROFILES.find(
    (candidate) => candidate.id === profileId,
  );
  if (!profile) {
    return state;
  }
  return {
    ...state,
    global: { ...profile.policy },
  };
}

export async function applySessionPermissionProfileToRuntime(
  profileId: SessionPermissionProfileId,
  currentState?: ShieldPolicyState,
): Promise<ShieldPolicyState> {
  const state = currentState ?? (await fetchShieldPolicyStateFromRuntime());
  const nextState = applySessionPermissionProfile(state, profileId);
  return persistShieldPolicyStateToRuntime(nextState);
}

export async function setConnectorOverrideInRuntime(
  connectorId: string,
  nextOverride: Partial<ConnectorPolicyOverride>,
  currentState?: ShieldPolicyState,
): Promise<ShieldPolicyState> {
  const state = currentState ?? (await fetchShieldPolicyStateFromRuntime());
  const nextState = updateConnectorOverride(state, connectorId, nextOverride);
  return persistShieldPolicyStateToRuntime(nextState);
}

export async function resetConnectorOverrideInRuntime(
  connectorId: string,
  currentState?: ShieldPolicyState,
): Promise<ShieldPolicyState> {
  const state = currentState ?? (await fetchShieldPolicyStateFromRuntime());
  const nextState = resetConnectorOverride(state, connectorId);
  return persistShieldPolicyStateToRuntime(nextState);
}

export function onShieldPolicyStateUpdated(
  listener: (state: ShieldPolicyState) => void,
): () => void {
  if (typeof window === "undefined") {
    return () => {};
  }
  const handleEvent = (event: Event) => {
    const customEvent = event as CustomEvent<ShieldPolicyState>;
    if (customEvent.detail) {
      listener(customEvent.detail);
    }
  };
  window.addEventListener(SHIELD_POLICY_UPDATED_EVENT, handleEvent);
  return () => {
    window.removeEventListener(SHIELD_POLICY_UPDATED_EVENT, handleEvent);
  };
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

export function dataHandlingLabel(value: DataHandlingMode): string {
  switch (value) {
    case "local_only":
      return "Local only";
    case "local_redacted":
      return "Local with redacted artifacts";
    default:
      return value;
  }
}

function decisionOutcome(value: PolicyDecisionMode): PolicySimulationOutcome {
  switch (value) {
    case "auto":
      return "auto";
    case "confirm":
      return "gate";
    case "block":
      return "deny";
    default:
      return "gate";
  }
}

function decisionStrength(value: PolicyDecisionMode): number {
  switch (value) {
    case "block":
      return 0;
    case "confirm":
      return 1;
    case "auto":
      return 2;
    default:
      return 1;
  }
}

function automationStrength(value: AutomationPolicyMode): number {
  switch (value) {
    case "manual_only":
      return 0;
    case "confirm_on_run":
      return 1;
    case "confirm_on_create":
      return 2;
    default:
      return 1;
  }
}

function dataHandlingStrength(value: DataHandlingMode): number {
  switch (value) {
    case "local_only":
      return 0;
    case "local_redacted":
      return 1;
    default:
      return 0;
  }
}

function buildPolicyDeltaDeckForPolicies(
  baseline: GlobalPolicyDefaults,
  next: GlobalPolicyDefaults,
  labels: {
    baselineLabel: string;
    nextLabel: string;
  },
): PolicyDeltaDeck {
  const items: PolicyDeltaItem[] = [];

  const pushDecisionDelta = (
    id: string,
    label: string,
    baselineValue: PolicyDecisionMode,
    nextValue: PolicyDecisionMode,
  ) => {
    const change = compareStrength(
      decisionStrength(baselineValue),
      decisionStrength(nextValue),
    );
    if (!change) return;
    items.push({
      id,
      label,
      baseline: decisionLabel(baselineValue),
      next: decisionLabel(nextValue),
      change,
      detail:
        change === "wider"
          ? "This widens authority compared with the baseline."
          : "This tightens authority compared with the baseline.",
    });
  };

  pushDecisionDelta("reads", "Read actions", baseline.reads, next.reads);
  pushDecisionDelta("writes", "Write actions", baseline.writes, next.writes);
  pushDecisionDelta("admin", "Admin actions", baseline.admin, next.admin);
  pushDecisionDelta("expert", "Expert actions", baseline.expert, next.expert);

  const automationChange = compareStrength(
    automationStrength(baseline.automations),
    automationStrength(next.automations),
  );
  if (automationChange) {
    items.push({
      id: "automations",
      label: "Automation posture",
      baseline: automationLabel(baseline.automations),
      next: automationLabel(next.automations),
      change: automationChange,
      detail:
        automationChange === "wider"
          ? "This reduces operator friction for durable automations."
          : "This adds stronger approval posture for durable automations.",
    });
  }

  const artifactChange = compareStrength(
    dataHandlingStrength(baseline.dataHandling),
    dataHandlingStrength(next.dataHandling),
  );
  if (artifactChange) {
    items.push({
      id: "dataHandling",
      label: "Artifact handling",
      baseline: dataHandlingLabel(baseline.dataHandling),
      next: dataHandlingLabel(next.dataHandling),
      change: artifactChange,
      detail:
        artifactChange === "wider"
          ? "This allows more evidence to leave the local shell after redaction."
          : "This keeps evidence more strictly local.",
    });
  }

  return {
    baselineLabel: labels.baselineLabel,
    nextLabel: labels.nextLabel,
    items,
  };
}

function compareStrength(baseline: number, next: number): "wider" | "tighter" | null {
  if (next > baseline) return "wider";
  if (next < baseline) return "tighter";
  return null;
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

export function buildPolicySimulationDeck(
  state: ShieldPolicyState,
  connectorId?: string | null,
): PolicySimulationDeck {
  const effective = connectorId
    ? resolveConnectorPolicy(state, connectorId).effective
    : state.global;

  const scenarios: PolicySimulationItem[] = [
    {
      id: "reads",
      label: "Read connector data",
      outcome: decisionOutcome(effective.reads),
      detail:
        "Inbox listing, latest-message reads, file lookups, and other read-only connector access.",
      rationale: `${decisionLabel(effective.reads)} for read actions in the effective policy.`,
    },
    {
      id: "writes",
      label: "Write or workflow actions",
      outcome: decisionOutcome(effective.writes),
      detail:
        "Reply drafts, file mutations, workflow-style writes, and other state-changing connector work.",
      rationale: `${decisionLabel(effective.writes)} for write and workflow actions.`,
    },
    {
      id: "admin",
      label: "Admin or configuration actions",
      outcome: decisionOutcome(effective.admin),
      detail:
        "Credential changes, subscription configuration, and other admin-scope connector operations.",
      rationale: `${decisionLabel(effective.admin)} for admin actions.`,
    },
    {
      id: "expert",
      label: "Expert / raw connector actions",
      outcome: decisionOutcome(effective.expert),
      detail:
        "Expert or raw connector requests that bypass higher-level guarded affordances.",
      rationale: `${decisionLabel(effective.expert)} for expert actions.`,
    },
    {
      id: "automations",
      label: "Automation trigger",
      outcome: "gate",
      detail:
        "Durable Gmail or Calendar automation creation and execution stay approval-bound on the current runtime path.",
      rationale: `${automationLabel(effective.automations)} automation posture is persisted, but live connector enforcement still gates automation actions explicitly.`,
    },
  ];

  const summary = scenarios.reduce<Record<PolicySimulationOutcome, number>>(
    (accumulator, scenario) => {
      accumulator[scenario.outcome] += 1;
      return accumulator;
    },
    { auto: 0, gate: 0, deny: 0 },
  );

  return {
    summary,
    scenarios,
    artifactHandling: {
      mode: effective.dataHandling,
      label: dataHandlingLabel(effective.dataHandling),
      detail:
        effective.dataHandling === "local_redacted"
          ? "Artifact exports may leave the local shell only after the runtime redacts them."
          : "Artifacts stay local to the shell/runtime path and do not permit redacted export handling.",
    },
  };
}

export function buildPolicyDeltaDeck(
  state: ShieldPolicyState,
  connectorId?: string | null,
): PolicyDeltaDeck {
  const baseline = connectorId ? state.global : createDefaultShieldPolicyState().global;
  const next = connectorId ? resolveConnectorPolicy(state, connectorId).effective : state.global;
  return buildPolicyDeltaDeckForPolicies(baseline, next, {
    baselineLabel: connectorId ? "Global baseline" : "Shipped default",
    nextLabel: connectorId ? "Effective connector posture" : "Current runtime posture",
  });
}

export function buildPolicyIntentDeltaDeck(
  baselineState: ShieldPolicyState,
  nextState: ShieldPolicyState,
  connectorId?: string | null,
  labels?: {
    baselineLabel?: string;
    nextLabel?: string;
  },
): PolicyDeltaDeck {
  const baseline = connectorId
    ? resolveConnectorPolicy(baselineState, connectorId).effective
    : baselineState.global;
  const next = connectorId
    ? resolveConnectorPolicy(nextState, connectorId).effective
    : nextState.global;

  return buildPolicyDeltaDeckForPolicies(baseline, next, {
    baselineLabel: labels?.baselineLabel ?? "Current effective posture",
    nextLabel: labels?.nextLabel ?? "Requested posture",
  });
}
