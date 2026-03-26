import type {
  ConnectorConfigureResult,
  ConnectorSummary,
} from "@ioi/agent-ide";
import type { SkillCatalogEntry, SkillDetailView } from "../../../../types";
import type { ConnectionCatalogItem } from "../capabilitiesCatalog";

export type CapabilitySurface = "skills" | "connections" | "extensions";
export type SkillOrigin = "starter" | "runtime";
export type ConnectionOrigin = "runtime" | "workspace";

export interface WorkspaceSkill {
  hash: string;
  catalog: SkillCatalogEntry;
  detail: SkillDetailView;
  origin: SkillOrigin;
  addedBy: string;
  invokedBy: string;
}

export interface WorkspaceExtension {
  id: string;
  name: string;
  description: string;
  status: string;
  meta: string;
  surfaces: string[];
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
  notes?: string;
  endpoint?: string;
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
export const SKILL_SWITCH_STORAGE_KEY =
  "autopilot.capabilities.enabled-skills";

export function humanize(value: string): string {
  return value
    .replace(/([a-z])([A-Z])/g, "$1 $2")
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

export function loadStoredSkillSwitches(): Record<string, boolean> {
  if (typeof window === "undefined") return {};
  try {
    const raw = window.localStorage.getItem(SKILL_SWITCH_STORAGE_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === "object"
      ? (parsed as Record<string, boolean>)
      : {};
  } catch {
    return {};
  }
}

export function skillDetailFromCatalog(
  entry: SkillCatalogEntry,
): SkillDetailView {
  return {
    skill_hash: entry.skill_hash,
    name: entry.name,
    description: entry.description,
    lifecycle_state: entry.lifecycle_state,
    source_type: entry.source_type,
    archival_record_id: entry.archival_record_id,
    success_rate_bps: entry.success_rate_bps,
    sample_size: entry.sample_size,
    source_session_id: entry.source_session_id,
    source_evidence_hash: entry.source_evidence_hash,
    relative_path: entry.relative_path,
    stale: entry.stale,
    used_tools: [entry.definition.name],
    steps: [],
    benchmark: {
      sample_size: entry.sample_size,
      success_rate_bps: entry.success_rate_bps,
      intervention_rate_bps: 0,
      policy_incident_rate_bps: 0,
      avg_cost: 0,
      avg_latency_ms: 0,
      passed: !entry.stale,
      last_evaluated_height: 0,
    },
    markdown: `# ${entry.name}\n\n${entry.description}`,
    neighborhood: {
      lens: "skills",
      title: entry.name,
      summary: entry.description,
      focus_id: `skill:${entry.skill_hash}`,
      nodes: [],
      edges: [],
    },
  };
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

export function connectionDraftFromCatalog(
  item: ConnectionCatalogItem,
): StoredConnectionDraft {
  if (item.id === "google_workspace") {
    return {
      id: "google.workspace",
      pluginId: "google_workspace",
      name: item.name,
      provider: item.provider,
      category: item.category,
      description: item.description,
      authMode: item.authMode,
      scopes: item.scopes,
      notes:
        "Added from the connection catalog. Authorize to activate the full Google capability surface.",
    };
  }

  if (item.id === "wallet_mail") {
    return {
      id: "mail.primary",
      pluginId: "wallet_mail",
      name: item.name,
      provider: item.provider,
      category: item.category,
      description: item.description,
      authMode: item.authMode,
      scopes: item.scopes,
      notes:
        "Added from the connection catalog. Connect one or more mailbox accounts to activate.",
    };
  }

  return {
    id: `catalog.${item.id}`,
    pluginId: item.id,
    name: item.name,
    provider: item.provider,
    category: item.category,
    description: item.description,
    authMode: item.authMode,
    scopes: item.scopes,
    notes:
      "Catalog connection staged in the workspace shell. Install or wire the adapter to activate runtime actions.",
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

export function extensionStatusFromConnectors(
  connectors: ConnectorSummary[],
  pluginId: string,
): string {
  const matching = connectors.filter(
    (connector) => connector.pluginId === pluginId,
  );
  if (matching.some((connector) => connector.status === "connected")) {
    return "Installed";
  }
  if (matching.some((connector) => connector.status === "degraded")) {
    return "Needs attention";
  }
  return "Ready";
}

export function groupLabelForConnection(
  connector: ConnectorSummary,
  origin: ConnectionOrigin,
): string {
  if (origin === "workspace") return "Workspace planned";
  if (connector.status === "connected") return "Connected";
  if (connector.status === "degraded") return "Needs attention";
  return "Not connected";
}
