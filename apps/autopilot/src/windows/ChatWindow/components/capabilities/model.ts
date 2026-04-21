import type {
  ConnectorActionDefinition,
  ConnectorConfigureResult,
  ConnectorSummary,
} from "@ioi/agent-ide";
import type {
  ExtensionManifestRecord,
  SkillSourceRecord,
  LocalEngineControlPlane,
  LocalEngineSnapshot,
  SkillCatalogEntry,
  SkillDetailView,
} from "../../../../types";
import {
  createDefaultShieldPolicyState,
  resolveConnectorPolicy,
  type AutomationPolicyMode,
  type PolicyDecisionMode,
  type ShieldPolicyState,
} from "../../chatPolicyCenter";

export type CapabilitySurface = "engine" | "skills" | "connections" | "extensions";
export type SkillOrigin = "runtime" | "filesystem";
export type SkillDetailStatus = "idle" | "loading" | "ready" | "error";
export type ConnectionOrigin = "runtime";
export type ConnectionTemplateOrigin = "workspace_template";
export type ConnectionDetailSection =
  | "overview"
  | "setup"
  | "actions"
  | "policy";
export type RuntimeConnectorActionStatus = "idle" | "loading" | "ready" | "error";
export type EngineDetailSection =
  | "overview"
  | "runtime"
  | "configuration"
  | "catalogs"
  | "registry"
  | "activity"
  | "families";
export type ExtensionDetailSection =
  | "overview"
  | "manifest"
  | "contributions";

export interface WorkspaceSkill {
  hash: string;
  registryEntryId?: string | null;
  catalog: SkillCatalogEntry;
  detail: SkillDetailView | null;
  detailStatus: SkillDetailStatus;
  detailError: string | null;
  origin: SkillOrigin;
  addedBy: string;
  invokedBy: string;
  sourceId?: string | null;
  sourceLabel?: string | null;
  sourceUri?: string | null;
  sourceKind?: string | null;
  syncStatus?: string | null;
  relativePath?: string | null;
  extensionId?: string | null;
  extensionDisplayName?: string | null;
}

export interface RuntimeSkillDetailState {
  status: SkillDetailStatus;
  detail: SkillDetailView | null;
  error: string | null;
}

export interface WorkspaceExtension {
  id: string;
  name: string;
  description: string;
  displayName?: string | null;
  version?: string | null;
  statusLabel: string;
  meta: string;
  surfaces: string[];
  sourceId?: string | null;
  sourceLabel: string;
  sourceUri: string;
  sourceKind: string;
  manifestKind: string;
  manifestPath: string;
  rootPath: string;
  enabled: boolean;
  trustPosture: string;
  governedProfile: string;
  developerName?: string | null;
  authorName?: string | null;
  authorEmail?: string | null;
  authorUrl?: string | null;
  category?: string | null;
  homepage?: string | null;
  repository?: string | null;
  license?: string | null;
  keywords: string[];
  defaultPrompts: string[];
  contributionCount: number;
  filesystemSkillCount: number;
  contributions: ExtensionManifestRecord["contributions"];
  marketplaceName?: string | null;
  marketplaceDisplayName?: string | null;
  marketplaceCategory?: string | null;
  marketplaceInstallationPolicy?: string | null;
  marketplaceAuthenticationPolicy?: string | null;
  marketplaceProducts: string[];
}

export type CapabilityTrustTierId =
  | "planning_only"
  | "contained_local"
  | "governed"
  | "automation"
  | "expert"
  | "blocked";

export interface CapabilityTrustProfile {
  tierId: CapabilityTrustTierId;
  tierLabel: string;
  governedProfileId: string;
  governedProfileLabel: string;
  summary: string;
  detail: string;
  signals: string[];
}

export interface LocalEnginePanel {
  snapshot: LocalEngineSnapshot | null;
  loading: boolean;
  error: string | null;
  configDraft: LocalEngineControlPlane | null;
  configSaving: boolean;
  configMessage: string | null;
  stagingBusy: boolean;
}

export interface StoredConnectionDraft {
  id: string;
  pluginId: string;
  name: string;
  provider: string;
  category: ConnectorSummary["category"];
  description: string;
  authMode: ConnectorSummary["authMode"];
  scopes: string[];
  availabilityLabel?: string;
  notes?: string;
  endpoint?: string;
}

export interface WorkspaceConnectionRecord {
  connector: ConnectorSummary;
  origin: ConnectionOrigin;
}

export interface RuntimeConnectorActionState {
  status: RuntimeConnectorActionStatus;
  actions: ConnectorActionDefinition[];
  error: string | null;
}

export type WorkspaceTemplateSource = "custom";

export interface WorkspaceConnectionTemplateRecord {
  connector: ConnectorSummary;
  draft: StoredConnectionDraft;
  origin: ConnectionTemplateOrigin;
  source: WorkspaceTemplateSource;
}

export interface CapabilityTreeEntry {
  id: string;
  label: string;
  note: string;
  meta?: string;
  active: boolean;
  onSelect: () => void;
}

export const CUSTOM_CONNECTIONS_STORAGE_KEY =
  "autopilot.capabilities.custom-connections";

export function humanize(value: string): string {
  return value
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .replace(/::/g, " ")
    .replace(/[_-]/g, " ")
    .replace(/\b\w/g, (match) => match.toUpperCase());
}

export function formatSuccessRate(basisPoints: number): string {
  return `${Math.round(basisPoints / 100)}%`;
}

export function formatAuthMode(mode: ConnectorSummary["authMode"]): string {
  switch (mode) {
    case "wallet_capability":
      return "Wallet capability";
    case "wallet_network_session":
      return "Wallet session";
    case "oauth":
      return "OAuth";
    case "api_key":
      return "API key";
    default:
      return humanize(mode);
  }
}

export function connectorStatusLabel(
  status: ConnectorSummary["status"],
): string {
  switch (status) {
    case "connected":
      return "Connected";
    case "needs_auth":
      return "Needs auth";
    case "degraded":
      return "Needs attention";
    case "disabled":
      return "Disabled";
    default:
      return humanize(status);
  }
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
      return humanize(value);
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
      return humanize(value);
  }
}

export function governedProfileLabel(value: string): string {
  switch (value) {
    case "workspace_template":
      return "Workspace planning template";
    case "observe_only_connector":
      return "Read-biased connector";
    case "governed_connector":
      return "Governed connector";
    case "automation_connector":
      return "Automation-capable connector";
    case "expert_connector":
      return "Expert-capable connector";
    case "blocked_connector":
      return "Blocked connector";
    case "governed_marketplace":
      return "Governed marketplace package";
    case "automation_bridge":
      return "Automation bridge";
    case "runtime_bridge":
      return "Runtime bridge";
    case "local_skill_bundle":
      return "Local skill bundle";
    case "local_manifest":
      return "Local manifest";
    case "disabled_source":
      return "Disabled source";
    default:
      return humanize(value);
  }
}

function connectorHasAutomationSurface(connector: ConnectorSummary): boolean {
  return connector.scopes.some((scope) =>
    /(workflow|event|automation|watch|subscribe)/i.test(scope),
  );
}

function connectorHasExpertSurface(connector: ConnectorSummary): boolean {
  return connector.scopes.some((scope) => /(expert|raw)/i.test(scope));
}

export function buildConnectorTrustProfile(
  connector: ConnectorSummary,
  policyState: ShieldPolicyState = createDefaultShieldPolicyState(),
  options?: { template?: boolean },
): CapabilityTrustProfile {
  if (options?.template) {
    return {
      tierId: "planning_only",
      tierLabel: "Planning only",
      governedProfileId: "workspace_template",
      governedProfileLabel: governedProfileLabel("workspace_template"),
      summary:
        "This connector is still a workspace planning template, so it has no live runtime authority yet.",
      detail:
        "Use this draft to decide expected scopes, ownership, and guardrails before a real runtime adapter exists.",
      signals: [
        "No live auth attached",
        `${connector.scopes.length} planned scope${connector.scopes.length === 1 ? "" : "s"}`,
        `Auth path: ${formatAuthMode(connector.authMode)}`,
      ],
    };
  }

  const effective = resolveConnectorPolicy(policyState, connector.id).effective;
  const hasAutomationSurface = connectorHasAutomationSurface(connector);
  const hasExpertSurface = connectorHasExpertSurface(connector);

  if (effective.reads === "block" && effective.writes === "block" && effective.admin === "block") {
    return {
      tierId: "blocked",
      tierLabel: "Blocked",
      governedProfileId: "blocked_connector",
      governedProfileLabel: governedProfileLabel("blocked_connector"),
      summary:
        "Current policy blocks the connector's live read, write, and admin paths before execution starts.",
      detail:
        "Operators would need to widen Shield policy before this connector can do meaningful work.",
      signals: [
        `Reads ${decisionLabel(effective.reads)}`,
        `Writes ${decisionLabel(effective.writes)}`,
        `Admin ${decisionLabel(effective.admin)}`,
      ],
    };
  }

  if (hasExpertSurface && effective.expert !== "block") {
    return {
      tierId: "expert",
      tierLabel: "Expert / raw",
      governedProfileId: "expert_connector",
      governedProfileLabel: governedProfileLabel("expert_connector"),
      summary:
        effective.expert === "auto"
          ? "This connector can reach expert or raw actions without a per-run confirmation gate."
          : "This connector exposes expert or raw actions, but current policy still gates them before execution.",
      detail:
        "Expert-capable connectors carry the widest authority class because they can bypass higher-level convenience affordances.",
      signals: [
        `Expert ${decisionLabel(effective.expert)}`,
        `Auth path: ${formatAuthMode(connector.authMode)}`,
        connector.status === "connected"
          ? "Runtime auth attached"
          : `Status: ${connectorStatusLabel(connector.status)}`,
      ],
    };
  }

  if (hasAutomationSurface) {
    return {
      tierId: "automation",
      tierLabel: "Durable automation",
      governedProfileId: "automation_connector",
      governedProfileLabel: governedProfileLabel("automation_connector"),
      summary:
        "This connector can host durable automation surfaces such as event- or workflow-driven execution.",
      detail:
        "Shield policy still governs create/run posture, but the connector itself sits in the automation authority class.",
      signals: [
        `Automations ${automationLabel(effective.automations)}`,
        `Writes ${decisionLabel(effective.writes)}`,
        `Admin ${decisionLabel(effective.admin)}`,
      ],
    };
  }

  if (effective.writes !== "block" || effective.admin !== "block") {
    return {
      tierId: "governed",
      tierLabel: "Governed write",
      governedProfileId: "governed_connector",
      governedProfileLabel: governedProfileLabel("governed_connector"),
      summary:
        "This connector can mutate state, but its write/admin paths remain explicitly governed by current policy.",
      detail:
        "Use this class for reply drafts, file mutations, and other state-changing work that should remain operator-steerable.",
      signals: [
        `Writes ${decisionLabel(effective.writes)}`,
        `Admin ${decisionLabel(effective.admin)}`,
        `Reads ${decisionLabel(effective.reads)}`,
      ],
    };
  }

  return {
    tierId: "contained_local",
    tierLabel: "Observe / contained",
    governedProfileId: "observe_only_connector",
    governedProfileLabel: governedProfileLabel("observe_only_connector"),
    summary:
      "This connector is effectively constrained to read-biased or tightly governed access before execution starts.",
    detail:
      "It can help the operator inspect context without opening broad write, automation, or expert authority.",
    signals: [
      `Reads ${decisionLabel(effective.reads)}`,
      `Writes ${decisionLabel(effective.writes)}`,
      `Auth path: ${formatAuthMode(connector.authMode)}`,
    ],
  };
}

export function buildExtensionTrustProfile(
  extension: WorkspaceExtension,
): CapabilityTrustProfile {
  if (!extension.enabled) {
    return {
      tierId: "blocked",
      tierLabel: "Disabled source",
      governedProfileId: "disabled_source",
      governedProfileLabel: governedProfileLabel("disabled_source"),
      summary:
        "This extension is present on disk, but its tracked source is currently disabled.",
      detail:
        "Re-enable the source before its packaged skills or contributions can shape runtime behavior again.",
      signals: [
        `Source ${humanize(extension.sourceKind)}`,
        `Trust posture ${humanize(extension.trustPosture)}`,
        `${extension.contributionCount} contribution${extension.contributionCount === 1 ? "" : "s"}`,
      ],
    };
  }

  switch (extension.governedProfile) {
    case "governed_marketplace":
      return {
        tierId: "governed",
        tierLabel: "Governed package",
        governedProfileId: extension.governedProfile,
        governedProfileLabel: governedProfileLabel(extension.governedProfile),
        summary:
          "This extension carries explicit installation or authentication policy from the runtime catalog/marketplace layer.",
        detail:
          "Operators should review marketplace policy before widening authority because this package already declares governance expectations.",
        signals: [
          extension.marketplaceInstallationPolicy
            ? `Install ${humanize(extension.marketplaceInstallationPolicy)}`
            : "Install policy inherited",
          extension.marketplaceAuthenticationPolicy
            ? `Auth ${humanize(extension.marketplaceAuthenticationPolicy)}`
            : "Auth policy inherited",
          extension.marketplaceDisplayName ?? extension.sourceLabel,
        ],
      };
    case "automation_bridge":
      return {
        tierId: "automation",
        tierLabel: "Automation bridge",
        governedProfileId: extension.governedProfile,
        governedProfileLabel: governedProfileLabel(extension.governedProfile),
        summary:
          "This extension contributes hooks or other automation-facing surfaces that can shape durable runtime behavior.",
        detail:
          "Treat automation-capable extensions as higher-authority packages because they can influence behavior beyond a one-shot skill selection.",
        signals: [
          `${extension.contributionCount} contribution${extension.contributionCount === 1 ? "" : "s"}`,
          `${extension.filesystemSkillCount} filesystem skill${extension.filesystemSkillCount === 1 ? "" : "s"}`,
          `Source ${humanize(extension.sourceKind)}`,
        ],
      };
    case "runtime_bridge":
      return {
        tierId: "governed",
        tierLabel: "Runtime bridge",
        governedProfileId: extension.governedProfile,
        governedProfileLabel: governedProfileLabel(extension.governedProfile),
        summary:
          "This extension contributes runtime bridge surfaces such as MCP servers or apps in addition to local metadata.",
        detail:
          "Bridge packages deserve policy review because they can expand what the runtime can call, not just what it can describe.",
        signals: [
          `${extension.contributionCount} contribution${extension.contributionCount === 1 ? "" : "s"}`,
          extension.sourceLabel,
          `Trust posture ${humanize(extension.trustPosture)}`,
        ],
      };
    case "local_skill_bundle":
      return {
        tierId: "contained_local",
        tierLabel: "Contained local",
        governedProfileId: extension.governedProfile,
        governedProfileLabel: governedProfileLabel(extension.governedProfile),
        summary:
          "This extension is currently a local skill bundle without additional runtime bridge surfaces.",
        detail:
          "Contained local bundles stay closest to the source registry and mostly expand reusable instructions rather than network-facing authority.",
        signals: [
          `${extension.filesystemSkillCount} filesystem skill${extension.filesystemSkillCount === 1 ? "" : "s"}`,
          extension.sourceLabel,
          `Trust posture ${humanize(extension.trustPosture)}`,
        ],
      };
    default:
      return {
        tierId: "contained_local",
        tierLabel: "Contained local",
        governedProfileId: extension.governedProfile,
        governedProfileLabel: governedProfileLabel(extension.governedProfile),
        summary:
          "This extension is a local manifest with limited packaged authority beyond its own files and metadata.",
        detail:
          "It stays in the lowest extension-authority class until it adds governed marketplace posture or runtime bridge contributions.",
        signals: [
          `${extension.contributionCount} contribution${extension.contributionCount === 1 ? "" : "s"}`,
          extension.sourceLabel,
          `Trust posture ${humanize(extension.trustPosture)}`,
        ],
      };
  }
}

export function loadStoredConnectionDrafts(): StoredConnectionDraft[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = window.localStorage.getItem(CUSTOM_CONNECTIONS_STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as StoredConnectionDraft[]) : [];
  } catch {
    return [];
  }
}

export function cloneLocalEngineControlPlane(
  controlPlane: LocalEngineControlPlane,
): LocalEngineControlPlane {
  return JSON.parse(JSON.stringify(controlPlane)) as LocalEngineControlPlane;
}

export function patchMailConnectorFromConfiguredAccount(
  connectors: ConnectorSummary[],
  result: {
    accountEmail: string;
    mailbox: string;
    updatedAtMs: number;
  },
): ConnectorSummary[] {
  const syncedAt = new Date(result.updatedAtMs).toISOString();
  return connectors.map((connector) =>
    connector.id !== "mail.primary"
      ? connector
      : {
          ...connector,
          status: "connected",
          lastSyncAtUtc: syncedAt,
          notes: `Connected ${result.accountEmail} on mailbox "${result.mailbox}".`,
        },
  );
}

export function patchConnectorFromConfigurationResult(
  connectors: ConnectorSummary[],
  result: ConnectorConfigureResult,
): ConnectorSummary[] {
  return connectors.map((connector) =>
    connector.id !== result.connectorId
      ? connector
      : {
          ...connector,
          status: result.status,
          lastSyncAtUtc: result.executedAtUtc,
          notes: result.summary,
        },
  );
}

export function templateRecordFromDraft(
  draft: StoredConnectionDraft,
): WorkspaceConnectionTemplateRecord {
  return {
    connector: connectorFromDraft(draft),
    draft,
    origin: "workspace_template",
    source: "custom",
  };
}

export function connectorFromDraft(
  draft: StoredConnectionDraft,
): ConnectorSummary {
  return {
    id: draft.id,
    pluginId: draft.pluginId,
    name: draft.name,
    provider: draft.provider,
    category: draft.category,
    description: draft.description,
    status: "needs_auth",
    authMode: draft.authMode,
    scopes: draft.scopes,
    notes: draft.notes,
  };
}

export function providerAccent(provider: string): string {
  switch (provider.toLowerCase()) {
    case "google":
      return "var(--studio-accent-soft)";
    case "github":
      return "var(--text-secondary)";
    case "slack":
      return "var(--studio-accent-soft)";
    case "notion":
      return "var(--text-primary)";
    case "linear":
      return "var(--studio-accent-soft)";
    case "figma":
      return "var(--text-secondary)";
    case "wallet.network":
      return "var(--studio-accent-soft)";
    case "mcp":
      return "var(--text-secondary)";
    default:
      return "var(--text-tertiary)";
  }
}

function syntheticFilesystemCatalogEntry(params: {
  hash: string;
  name: string;
  description?: string | null;
  relativePath?: string | null;
  stale?: boolean;
  sourceType: string;
  lifecycleState: string;
}): SkillCatalogEntry {
  return {
    skill_hash: params.hash,
    name: params.name,
    description: params.description ?? "",
    lifecycle_state: params.lifecycleState,
    source_type: params.sourceType,
    success_rate_bps: 0,
    sample_size: 0,
    archival_record_id: 0,
    source_session_id: null,
    source_evidence_hash: null,
    relative_path: params.relativePath ?? null,
    stale: params.stale ?? false,
    definition: {
      name: params.name,
      description: params.description ?? "",
      parameters: "",
    },
  };
}

export function workspaceSkillFromSkillSource(
  source: SkillSourceRecord,
  skill: SkillSourceRecord["discoveredSkills"][number],
): WorkspaceSkill {
  const hash = `filesystem:${source.sourceId}:${skill.relativePath}`;
  const registryEntryId = `filesystem_skill:source:${source.sourceId}:${skill.relativePath
    .replace(/\\/g, "/")
    .replace(/^\.?\//, "")
    .replace(/\/+$/, "")}`;
  return {
    hash,
    registryEntryId,
    catalog: syntheticFilesystemCatalogEntry({
      hash,
      name: skill.name,
      description: skill.description,
      relativePath: skill.relativePath,
      sourceType: "filesystem_source",
      lifecycleState: source.syncStatus,
    }),
    detail: null,
    detailStatus: "idle",
    detailError: null,
    origin: "filesystem",
    addedBy: source.label,
    invokedBy: source.enabled
      ? "Available once the runtime attaches this source"
      : "Source disabled",
    sourceId: source.sourceId,
    sourceLabel: source.label,
    sourceUri: source.uri,
    sourceKind: source.kind,
    syncStatus: source.syncStatus,
    relativePath: skill.relativePath,
  };
}

export function workspaceSkillFromExtensionManifest(
  manifest: ExtensionManifestRecord,
  skill: ExtensionManifestRecord["filesystemSkills"][number],
  sourceId?: string | null,
): WorkspaceSkill {
  const hash = `filesystem:${manifest.extensionId}:${skill.relativePath}`;
  const registryEntryId = `filesystem_skill:extension:${manifest.extensionId}:${skill.relativePath
    .replace(/\\/g, "/")
    .replace(/^\.?\//, "")
    .replace(/\/+$/, "")}`;
  return {
    hash,
    registryEntryId,
    catalog: syntheticFilesystemCatalogEntry({
      hash,
      name: skill.name,
      description: skill.description ?? manifest.description,
      relativePath: skill.relativePath,
      sourceType: "extension_manifest",
      lifecycleState: manifest.enabled ? "discovered" : "disabled",
    }),
    detail: null,
    detailStatus: "idle",
    detailError: null,
    origin: "filesystem",
    addedBy: manifest.displayName ?? manifest.name,
    invokedBy: manifest.enabled
      ? "Packaged in a local extension manifest"
      : "Extension source disabled",
    sourceId,
    sourceLabel: manifest.sourceLabel,
    sourceUri: manifest.sourceUri,
    sourceKind: manifest.sourceKind,
    syncStatus: manifest.enabled ? "ready" : "disabled",
    relativePath: skill.relativePath,
    extensionId: manifest.extensionId,
    extensionDisplayName: manifest.displayName ?? manifest.name,
  };
}

export function extensionStatusLabel(
  manifest: ExtensionManifestRecord,
): string {
  if (!manifest.enabled) {
    return "Source disabled";
  }
  if (manifest.marketplaceInstallationPolicy) {
    const installation = humanize(manifest.marketplaceInstallationPolicy);
    const authentication = manifest.marketplaceAuthenticationPolicy
      ? humanize(manifest.marketplaceAuthenticationPolicy)
      : null;
    return authentication
      ? `${installation} · ${authentication}`
      : installation;
  }
  if (manifest.filesystemSkills.length > 0) {
    return `${manifest.filesystemSkills.length} filesystem skill${manifest.filesystemSkills.length === 1 ? "" : "s"}`;
  }
  return humanize(manifest.trustPosture);
}

export function groupLabelForConnection(
  connector: ConnectorSummary,
): string {
  if (connector.status === "connected") return "Connected";
  if (connector.status === "degraded") return "Needs attention";
  return "Not connected";
}

export function templateLabelForConnection(
  template: WorkspaceConnectionTemplateRecord,
): string {
  return template.draft.availabilityLabel ?? "Planning template";
}
