import {
  type ReactNode,
  useDeferredValue,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import {
  GoogleWorkspaceConnectorPanel,
  MailConnectorPanel,
  type ConnectorConfigureResult,
  type ConnectorSummary,
  useMailConnectorActions,
} from "@ioi/agent-ide";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { TauriRuntime } from "../../../services/TauriRuntime";
import type { SkillCatalogEntry, SkillDetailView } from "../../../types";
import {
  CONNECTION_CATALOG,
  STARTER_SKILL_BUNDLES,
  type ConnectionCatalogItem,
} from "./capabilitiesCatalog";
import "./CapabilitiesView.css";

interface CapabilitiesViewProps {
  runtime: TauriRuntime;
  getConnectorPolicySummary?: (
    connector: ConnectorSummary,
  ) => { headline: string; detail: string } | null;
  onOpenPolicyCenter?: (connector: ConnectorSummary) => void;
}

type CapabilitySurface = "skills" | "connections" | "extensions";
type SkillOrigin = "starter" | "runtime";
type ConnectionOrigin = "runtime" | "workspace";

interface WorkspaceSkill {
  hash: string;
  catalog: SkillCatalogEntry;
  detail: SkillDetailView;
  origin: SkillOrigin;
  addedBy: string;
  invokedBy: string;
}

interface WorkspaceExtension {
  id: string;
  name: string;
  description: string;
  status: string;
  meta: string;
  surfaces: string[];
}

interface StoredConnectionDraft {
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

interface CapabilityTreeEntry {
  id: string;
  label: string;
  note: string;
  meta?: string;
  active: boolean;
  onSelect: () => void;
}

const CUSTOM_CONNECTIONS_STORAGE_KEY =
  "autopilot.capabilities.custom-connections";
const SKILL_SWITCH_STORAGE_KEY = "autopilot.capabilities.enabled-skills";

function IconBase({
  children,
  className,
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      className={className}
    >
      {children}
    </svg>
  );
}

function SparklesIcon() {
  return (
    <IconBase>
      <path d="m12 3 1.8 4.2L18 9l-4.2 1.8L12 15l-1.8-4.2L6 9l4.2-1.8Z" />
      <path d="m5 16 .9 2.1L8 19l-2.1.9L5 22l-.9-2.1L2 19l2.1-.9Z" />
      <path d="m19 13 .8 1.8L22 16l-2.2 1.2L19 19l-.8-1.8L16 16l2.2-1.2Z" />
    </IconBase>
  );
}

function CableIcon() {
  return (
    <IconBase>
      <path d="M8 7V5a2 2 0 1 1 4 0v2" />
      <path d="M12 7h4a2 2 0 0 1 2 2v3a4 4 0 0 1-4 4h-2v3" />
      <path d="M6 11h4" />
      <path d="M16 7V5a2 2 0 1 1 4 0v2" />
    </IconBase>
  );
}

function BlocksIcon() {
  return (
    <IconBase>
      <rect x="3" y="3" width="8" height="8" rx="2" />
      <rect x="13" y="3" width="8" height="8" rx="2" />
      <rect x="8" y="13" width="8" height="8" rx="2" />
    </IconBase>
  );
}

function SearchIcon() {
  return (
    <IconBase>
      <circle cx="11" cy="11" r="6.5" />
      <path d="m16 16 4 4" />
    </IconBase>
  );
}

function PlusIcon() {
  return (
    <IconBase>
      <path d="M12 5v14" />
      <path d="M5 12h14" />
    </IconBase>
  );
}

function CheckCircleIcon() {
  return (
    <IconBase>
      <circle cx="12" cy="12" r="9" />
      <path d="m8.8 12.2 2.1 2.1 4.4-4.5" />
    </IconBase>
  );
}

function XIcon() {
  return (
    <IconBase>
      <path d="m6 6 12 12" />
      <path d="m18 6-12 12" />
    </IconBase>
  );
}

function ChevronRightIcon({ className }: { className?: string }) {
  return (
    <IconBase className={className}>
      <path d="m9 6 6 6-6 6" />
    </IconBase>
  );
}

function ArrowLeftIcon() {
  return (
    <IconBase>
      <path d="m15 18-6-6 6-6" />
      <path d="M9 12h10" />
    </IconBase>
  );
}

function DetailDocument({
  title,
  summary,
  meta,
  children,
}: {
  title: string;
  summary: string;
  meta?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="capabilities-detail-document">
      <div className="capabilities-detail-document-toolbar">
        <div className="capabilities-detail-document-title">
          <strong>{title}</strong>
          <span>{summary}</span>
        </div>
        {meta ? <div className="capabilities-detail-document-meta">{meta}</div> : null}
      </div>
      <div className="capabilities-detail-document-body">{children}</div>
    </section>
  );
}

const MarkdownRenderer = ReactMarkdown as any;

function humanize(value: string): string {
  return value
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .replace(/[_-]/g, " ")
    .replace(/\b\w/g, (match) => match.toUpperCase());
}

function formatSuccessRate(basisPoints: number): string {
  return `${Math.round(basisPoints / 100)}%`;
}

function formatAuthMode(mode: ConnectorSummary["authMode"]): string {
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

function connectorStatusLabel(status: ConnectorSummary["status"]): string {
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

function loadStoredConnectionDrafts(): StoredConnectionDraft[] {
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

function loadStoredSkillSwitches(): Record<string, boolean> {
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

function skillDetailFromCatalog(entry: SkillCatalogEntry): SkillDetailView {
  return {
    skill_hash: entry.skill_hash,
    name: entry.name,
    description: entry.description,
    lifecycle_state: entry.lifecycle_state,
    source_type: entry.source_type,
    frame_id: entry.frame_id,
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

function patchMailConnectorFromConfiguredAccount(
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

function patchConnectorFromConfigurationResult(
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

function connectionDraftFromCatalog(
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

function connectorFromDraft(draft: StoredConnectionDraft): ConnectorSummary {
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

function providerAccent(provider: string): string {
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

function extensionStatusFromConnectors(
  connectors: ConnectorSummary[],
  pluginId: string,
): string {
  const matching = connectors.filter(
    (connector) => connector.pluginId === pluginId,
  );
  if (matching.some((connector) => connector.status === "connected"))
    return "Installed";
  if (matching.some((connector) => connector.status === "degraded"))
    return "Needs attention";
  return "Ready";
}

function groupLabelForConnection(
  connector: ConnectorSummary,
  origin: ConnectionOrigin,
): string {
  if (origin === "workspace") return "Workspace planned";
  if (connector.status === "connected") return "Connected";
  if (connector.status === "degraded") return "Needs attention";
  return "Not connected";
}

function MenuButton({
  active,
  icon,
  label,
  onClick,
}: {
  active: boolean;
  icon: ReactNode;
  label: string;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      className={`capabilities-nav-button ${active ? "is-active" : ""}`}
      onClick={onClick}
    >
      <span className="capabilities-nav-icon">{icon}</span>
      <span className="capabilities-nav-label">{label}</span>
    </button>
  );
}

export function CapabilitiesView({
  runtime,
  getConnectorPolicySummary,
  onOpenPolicyCenter,
}: CapabilitiesViewProps) {
  const connectionsMenuRef = useRef<HTMLDivElement | null>(null);
  const [surface, setSurface] = useState<CapabilitySurface | null>(null);
  const [query, setQuery] = useState("");
  const deferredQuery = useDeferredValue(query);
  const [runtimeConnectors, setRuntimeConnectors] = useState<
    ConnectorSummary[]
  >([]);
  const [runtimeSkills, setRuntimeSkills] = useState<SkillCatalogEntry[]>([]);
  const [runtimeSkillDetails, setRuntimeSkillDetails] = useState<
    Record<string, SkillDetailView>
  >({});
  const [toolCount, setToolCount] = useState<number | null>(null);
  const [storedConnections, setStoredConnections] = useState<
    StoredConnectionDraft[]
  >(() => loadStoredConnectionDrafts());
  const [enabledSkills, setEnabledSkills] = useState<Record<string, boolean>>(
    () => loadStoredSkillSwitches(),
  );
  const [selectedSkillHash, setSelectedSkillHash] = useState<string | null>(
    null,
  );
  const [selectedConnectionId, setSelectedConnectionId] = useState<
    string | null
  >(null);
  const [selectedExtensionId, setSelectedExtensionId] = useState<string | null>(
    null,
  );
  const [skillDetailSection, setSkillDetailSection] = useState<
    "overview" | "guide" | "procedure"
  >("guide");
  const [connectionDetailSection, setConnectionDetailSection] = useState<
    "overview" | "setup" | "policy"
  >("overview");
  const [extensionDetailSection, setExtensionDetailSection] = useState<
    "overview" | "surface"
  >("overview");
  const [catalogModalOpen, setCatalogModalOpen] = useState(false);
  const [customModalOpen, setCustomModalOpen] = useState(false);
  const [connectionsMenuOpen, setConnectionsMenuOpen] = useState(false);
  const [catalogCategoryFilter, setCatalogCategoryFilter] = useState<
    ConnectorSummary["category"] | "all"
  >("all");
  const [catalogQuery, setCatalogQuery] = useState("");
  const [customName, setCustomName] = useState("");
  const [customUrl, setCustomUrl] = useState("");
  const [customCategory, setCustomCategory] =
    useState<ConnectorSummary["category"]>("developer");
  const [customDescription, setCustomDescription] = useState(
    "Remote MCP surface exposed through a capability adapter.",
  );
  const [customScopes, setCustomScopes] = useState(
    "tools.invoke, resources.read",
  );
  const [customNotice, setCustomNotice] = useState<string | null>(null);
  const [genericConnectorMessage, setGenericConnectorMessage] = useState<
    string | null
  >(null);
  const [genericConnectorBusy, setGenericConnectorBusy] = useState(false);

  useEffect(() => {
    let cancelled = false;

    runtime
      .getConnectors()
      .then((items) => {
        if (!cancelled && Array.isArray(items)) {
          setRuntimeConnectors(items);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setRuntimeConnectors([]);
        }
      });

    void runtime
      .getSkillCatalog()
      .then((items) => {
        if (!cancelled && Array.isArray(items)) {
          setRuntimeSkills(items);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setRuntimeSkills([]);
        }
      });

    void runtime
      .getAvailableTools()
      .then((items) => {
        if (!cancelled && Array.isArray(items)) {
          setToolCount(items.length);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setToolCount(null);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [runtime]);

  useEffect(() => {
    if (typeof window === "undefined") return;
    window.localStorage.setItem(
      CUSTOM_CONNECTIONS_STORAGE_KEY,
      JSON.stringify(storedConnections),
    );
  }, [storedConnections]);

  useEffect(() => {
    if (typeof window === "undefined") return;
    window.localStorage.setItem(
      SKILL_SWITCH_STORAGE_KEY,
      JSON.stringify(enabledSkills),
    );
  }, [enabledSkills]);

  useEffect(() => {
    setQuery("");
    setConnectionsMenuOpen(false);
  }, [surface]);

  useEffect(() => {
    setSkillDetailSection("guide");
  }, [selectedSkillHash]);

  useEffect(() => {
    setConnectionDetailSection("overview");
    setGenericConnectorMessage(null);
  }, [selectedConnectionId]);

  useEffect(() => {
    setExtensionDetailSection("overview");
  }, [selectedExtensionId]);

  useEffect(() => {
    if (!connectionsMenuOpen) return;

    const handlePointerDown = (event: PointerEvent) => {
      if (
        connectionsMenuRef.current &&
        !connectionsMenuRef.current.contains(event.target as Node)
      ) {
        setConnectionsMenuOpen(false);
      }
    };

    window.addEventListener("pointerdown", handlePointerDown);
    return () => {
      window.removeEventListener("pointerdown", handlePointerDown);
    };
  }, [connectionsMenuOpen]);

  const mail = useMailConnectorActions(runtime, {
    onAccountConfigured(result) {
      setRuntimeConnectors((current) =>
        patchMailConnectorFromConfiguredAccount(current, result),
      );
    },
  });

  const workspaceSkills = useMemo<WorkspaceSkill[]>(() => {
    const runtimeByName = new Map(
      runtimeSkills.map((entry) => [entry.name.toLowerCase(), entry] as const),
    );

    const merged: WorkspaceSkill[] = runtimeSkills.map((entry) => ({
      hash: entry.skill_hash,
      catalog: entry,
      detail:
        runtimeSkillDetails[entry.skill_hash] ?? skillDetailFromCatalog(entry),
      origin: "runtime",
      addedBy: "Observed runtime",
      invokedBy: "Worker or workflow",
    }));

    for (const starter of STARTER_SKILL_BUNDLES) {
      if (runtimeByName.has(starter.catalog.name.toLowerCase())) {
        continue;
      }
      merged.push({
        hash: starter.catalog.skill_hash,
        catalog: starter.catalog,
        detail: starter.detail,
        origin: "starter",
        addedBy: starter.addedBy,
        invokedBy: starter.invokedBy,
      });
    }

    return merged.sort((left, right) => {
      if (left.origin !== right.origin) {
        return left.origin === "starter" ? -1 : 1;
      }
      if (left.catalog.stale !== right.catalog.stale) {
        return left.catalog.stale ? 1 : -1;
      }
      if (left.catalog.sample_size !== right.catalog.sample_size) {
        return right.catalog.sample_size - left.catalog.sample_size;
      }
      return left.catalog.name.localeCompare(right.catalog.name);
    });
  }, [runtimeSkillDetails, runtimeSkills]);

  const workspaceConnections = useMemo(() => {
    const runtimeIds = new Set(
      runtimeConnectors.map((connector) => connector.id),
    );
    const runtimePluginIds = new Set(
      runtimeConnectors.map((connector) => connector.pluginId),
    );
    const staged = storedConnections
      .filter(
        (draft) =>
          !runtimeIds.has(draft.id) && !runtimePluginIds.has(draft.pluginId),
      )
      .map((draft) => ({
        connector: connectorFromDraft(draft),
        origin: "workspace" as const,
      }));

    return [
      ...runtimeConnectors.map((connector) => ({
        connector,
        origin: "runtime" as const,
      })),
      ...staged,
    ];
  }, [runtimeConnectors, storedConnections]);

  const extensions = useMemo<WorkspaceExtension[]>(() => {
    const pluginMap = new Map<string, WorkspaceExtension>();

    pluginMap.set("core.operator", {
      id: "core.operator",
      name: "Core operator surface",
      description:
        "Built-in browser, file, and shell primitives available inside the local trust boundary.",
      status: "Built-in",
      meta:
        toolCount === null
          ? "Loading tool inventory from runtime"
          : `${toolCount} low-level tools available`,
      surfaces: ["Browser", "Files", "Shell", "Execution"],
    });

    for (const { connector } of workspaceConnections) {
      if (pluginMap.has(connector.pluginId)) continue;
      pluginMap.set(connector.pluginId, {
        id: connector.pluginId,
        name: humanize(connector.pluginId),
        description: connector.description,
        status: extensionStatusFromConnectors(
          workspaceConnections.map((item) => item.connector),
          connector.pluginId,
        ),
        meta: `${connector.provider} · ${connector.scopes.length} scopes`,
        surfaces: connector.scopes.slice(0, 6).map(humanize),
      });
    }

    return [...pluginMap.values()].sort((left, right) =>
      left.name.localeCompare(right.name),
    );
  }, [toolCount, workspaceConnections]);

  const filteredSkills = useMemo(() => {
    if (!deferredQuery.trim()) return workspaceSkills;
    const lowered = deferredQuery.trim().toLowerCase();
    return workspaceSkills.filter((skill) =>
      [
        skill.catalog.name,
        skill.catalog.description,
        skill.catalog.source_type,
        skill.detail.used_tools.join(" "),
      ]
        .join(" ")
        .toLowerCase()
        .includes(lowered),
    );
  }, [deferredQuery, workspaceSkills]);

  const filteredConnections = useMemo(() => {
    if (!deferredQuery.trim()) return workspaceConnections;
    const lowered = deferredQuery.trim().toLowerCase();
    return workspaceConnections.filter(({ connector }) =>
      [
        connector.name,
        connector.provider,
        connector.description,
        connector.scopes.join(" "),
      ]
        .join(" ")
        .toLowerCase()
        .includes(lowered),
    );
  }, [deferredQuery, workspaceConnections]);

  const filteredExtensions = useMemo(() => {
    if (!deferredQuery.trim()) return extensions;
    const lowered = deferredQuery.trim().toLowerCase();
    return extensions.filter((extension) =>
      [extension.name, extension.description, extension.surfaces.join(" ")]
        .join(" ")
        .toLowerCase()
        .includes(lowered),
    );
  }, [deferredQuery, extensions]);

  const connectedConnectionCount = workspaceConnections.filter(
    ({ connector }) => connector.status === "connected",
  ).length;

  const openSurface = (nextSurface: CapabilitySurface) => {
    setSurface(nextSurface);
  };

  const returnToHome = () => {
    setSurface(null);
    setQuery("");
    setConnectionsMenuOpen(false);
  };

  useEffect(() => {
    if (surface !== "skills") return;
    const next = filteredSkills[0]?.hash ?? null;
    if (
      !selectedSkillHash ||
      !filteredSkills.some((skill) => skill.hash === selectedSkillHash)
    ) {
      setSelectedSkillHash(next);
    }
  }, [filteredSkills, selectedSkillHash, surface]);

  useEffect(() => {
    if (surface !== "connections") return;
    const next = filteredConnections[0]?.connector.id ?? null;
    if (
      !selectedConnectionId ||
      !filteredConnections.some(
        ({ connector }) => connector.id === selectedConnectionId,
      )
    ) {
      setSelectedConnectionId(next);
    }
  }, [filteredConnections, selectedConnectionId, surface]);

  useEffect(() => {
    if (surface !== "extensions") return;
    const next = filteredExtensions[0]?.id ?? null;
    if (
      !selectedExtensionId ||
      !filteredExtensions.some((item) => item.id === selectedExtensionId)
    ) {
      setSelectedExtensionId(next);
    }
  }, [filteredExtensions, selectedExtensionId, surface]);

  const selectedSkill =
    workspaceSkills.find((skill) => skill.hash === selectedSkillHash) ?? null;
  const selectedConnectionRecord =
    workspaceConnections.find(
      ({ connector }) => connector.id === selectedConnectionId,
    ) ?? null;
  const selectedExtension =
    extensions.find((extension) => extension.id === selectedExtensionId) ??
    null;

  useEffect(() => {
    if (!selectedSkill || selectedSkill.origin !== "runtime") return;
    if (runtimeSkillDetails[selectedSkill.hash]) return;

    let cancelled = false;

    runtime
      .getSkillDetail(selectedSkill.hash)
      .then((detail) => {
        if (cancelled) return;
        setRuntimeSkillDetails((current) => ({
          ...current,
          [selectedSkill.hash]: detail,
        }));
      })
      .catch(() => {
        if (cancelled) return;
        setRuntimeSkillDetails((current) => ({
          ...current,
          [selectedSkill.hash]: skillDetailFromCatalog(selectedSkill.catalog),
        }));
      });

    return () => {
      cancelled = true;
    };
  }, [runtime, runtimeSkillDetails, selectedSkill]);

  const availableCatalogItems = useMemo(() => {
    const existingIds = new Set([
      ...workspaceConnections.map(({ connector }) => connector.pluginId),
      ...workspaceConnections.map(({ connector }) => connector.id),
    ]);
    const lowered = catalogQuery.trim().toLowerCase();

    return CONNECTION_CATALOG.filter((item) => {
      if (
        catalogCategoryFilter !== "all" &&
        item.category !== catalogCategoryFilter
      ) {
        return false;
      }
      if (
        lowered &&
        ![item.name, item.provider, item.description, item.scopes.join(" ")]
          .join(" ")
          .toLowerCase()
          .includes(lowered)
      ) {
        return false;
      }
      return true;
    }).map((item) => ({
      item,
      alreadyAdded:
        existingIds.has(item.id) ||
        existingIds.has(
          item.id === "google_workspace" ? "google.workspace" : item.id,
        ) ||
        existingIds.has(item.id === "wallet_mail" ? "mail.primary" : item.id),
    }));
  }, [catalogCategoryFilter, catalogQuery, workspaceConnections]);

  const addCatalogConnection = (item: ConnectionCatalogItem) => {
    const draft = connectionDraftFromCatalog(item);

    setStoredConnections((current) => {
      if (
        current.some(
          (existing) =>
            existing.id === draft.id || existing.pluginId === draft.pluginId,
        )
      ) {
        return current;
      }
      return [...current, draft];
    });

    setSelectedConnectionId(draft.id);
    setSurface("connections");
    setCatalogModalOpen(false);
    setConnectionsMenuOpen(false);
    setCustomNotice(`${item.name} added to the workspace shell.`);
  };

  const createCustomConnection = () => {
    const trimmedName = customName.trim();
    const trimmedUrl = customUrl.trim();
    if (!trimmedName || !trimmedUrl) {
      setCustomNotice(
        "Add a name and remote endpoint to register a custom connection.",
      );
      return;
    }

    const slug = trimmedName
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "");
    const draft: StoredConnectionDraft = {
      id: `custom.${slug || "connection"}`,
      pluginId: `custom.mcp.${slug || "connection"}`,
      name: trimmedName,
      provider: "mcp",
      category: customCategory,
      description: customDescription.trim(),
      authMode: "api_key",
      scopes: customScopes
        .split(",")
        .map((scope) => scope.trim())
        .filter(Boolean),
      notes:
        "Custom connection staged locally. Install or bind the remote MCP adapter to activate tool execution.",
      endpoint: trimmedUrl,
    };

    setStoredConnections((current) => {
      const next = current.filter((item) => item.id !== draft.id);
      next.push(draft);
      return next;
    });
    setSelectedConnectionId(draft.id);
    setSurface("connections");
    setCustomModalOpen(false);
    setConnectionsMenuOpen(false);
    setCustomName("");
    setCustomUrl("");
    setCustomDescription(
      "Remote MCP surface exposed through a capability adapter.",
    );
    setCustomScopes("tools.invoke, resources.read");
    setCustomNotice(`${trimmedName} added as a custom connection.`);
  };

  const runGenericConnectorSetup = async (connector: ConnectorSummary) => {
    if (!runtime.configureConnector) {
      setGenericConnectorMessage(
        "This connection is staged in the workspace, but the runtime does not expose a generic configure flow yet.",
      );
      return;
    }

    setGenericConnectorBusy(true);
    setGenericConnectorMessage(null);
    try {
      const result = await runtime.configureConnector({
        connectorId: connector.id,
        input: {},
      });
      setRuntimeConnectors((current) =>
        patchConnectorFromConfigurationResult(current, result),
      );
      setGenericConnectorMessage(result.summary);
    } catch (error) {
      setGenericConnectorMessage(String(error));
    } finally {
      setGenericConnectorBusy(false);
    }
  };

  const renderSkillList = () => {
    const starter = filteredSkills.filter(
      (skill) => skill.origin === "starter",
    );
    const runtimeObserved = filteredSkills.filter(
      (skill) => skill.origin === "runtime",
    );

    const skillEntriesFor = (skill: WorkspaceSkill): CapabilityTreeEntry[] => [
      {
        id: "guide",
        label: "SKILL.md",
        note: "Primary markdown instructions for the reusable behavior",
        meta: "Markdown",
        active: skillDetailSection === "guide",
        onSelect: () => setSkillDetailSection("guide"),
      },
      {
        id: "overview",
        label: "Overview",
        note: "Benchmarks, tool bundle, and operating posture",
        meta: formatSuccessRate(skill.detail.benchmark.success_rate_bps),
        active: skillDetailSection === "overview",
        onSelect: () => setSkillDetailSection("overview"),
      },
      {
        id: "procedure",
        label: "Procedure",
        note: "Observed execution outline and tool sequence",
        meta:
          skill.detail.steps.length > 0
            ? `${skill.detail.steps.length} steps`
            : "Macro",
        active: skillDetailSection === "procedure",
        onSelect: () => setSkillDetailSection("procedure"),
      },
    ];

    const renderSkillGroup = (title: string, items: WorkspaceSkill[]) => {
      if (items.length === 0) return null;
      return (
        <section className="capabilities-list-group">
          <div className="capabilities-list-group-head">
            <h3>{title}</h3>
            <span>{items.length}</span>
          </div>
          <div className="capabilities-list-rows">
            {items.map((skill) => {
              const isSelected = selectedSkillHash === skill.hash;
              const entries = skillEntriesFor(skill);

              return (
                <div
                  key={skill.hash}
                  className={`capabilities-tree-item ${isSelected ? "is-open" : ""}`}
                >
                  <button
                    type="button"
                    className={`capabilities-list-row ${isSelected ? "is-selected" : ""}`}
                    onClick={() => setSelectedSkillHash(skill.hash)}
                  >
                    <span className="capabilities-row-icon capabilities-row-icon-skill">
                      <SparklesIcon />
                    </span>
                    <span className="capabilities-row-copy">
                      <strong>{skill.catalog.name}</strong>
                      <small>{skill.catalog.description}</small>
                    </span>
                    <span className="capabilities-row-meta">
                      {skill.origin === "starter" ? "Starter" : "Runtime"}
                    </span>
                    <span
                      className={`capabilities-row-caret ${isSelected ? "is-open" : ""}`}
                      aria-hidden="true"
                    >
                      <ChevronRightIcon />
                    </span>
                  </button>

                  {isSelected ? renderTreeEntries(entries) : null}
                </div>
              );
            })}
          </div>
        </section>
      );
    };

    return (
      <>
        {renderSkillGroup("Starter library", starter)}
        {renderSkillGroup("Observed in runtime", runtimeObserved)}
        {filteredSkills.length === 0 ? (
          <div className="capabilities-empty-state">
            No skills match the current search.
          </div>
        ) : null}
      </>
    );
  };

  const renderConnectionList = () => {
    const groups = [
      "Not connected",
      "Connected",
      "Needs attention",
      "Workspace planned",
    ];

    return (
      <>
        {groups.map((group) => {
          const groupItems = filteredConnections.filter(
            ({ connector, origin }) =>
              groupLabelForConnection(connector, origin) === group,
          );
          if (groupItems.length === 0) return null;
          return (
            <section key={group} className="capabilities-list-group">
              <div className="capabilities-list-group-head">
                <h3>{group}</h3>
                <span>{groupItems.length}</span>
              </div>
              <div className="capabilities-list-rows">
                {groupItems.map(({ connector, origin }) => {
                  const isSelected = selectedConnectionId === connector.id;
                  const entries: CapabilityTreeEntry[] = [
                    {
                      id: "overview",
                      label: "Overview",
                      note: "Scopes, notes, and capability reach",
                      meta: `${connector.scopes.length} scopes`,
                      active: connectionDetailSection === "overview",
                      onSelect: () => setConnectionDetailSection("overview"),
                    },
                    {
                      id: "setup",
                      label: "Setup",
                      note:
                        origin === "workspace"
                          ? "Stage the adapter before runtime execution is available"
                          : "Attach auth and unlock callable actions",
                      meta: origin === "workspace" ? "Planned" : "Live",
                      active: connectionDetailSection === "setup",
                      onSelect: () => setConnectionDetailSection("setup"),
                    },
                    {
                      id: "policy",
                      label: "Policy",
                      note: "Governance, approvals, and connector-specific controls",
                      meta: "Guardrails",
                      active: connectionDetailSection === "policy",
                      onSelect: () => setConnectionDetailSection("policy"),
                    },
                  ];

                  return (
                    <div
                      key={connector.id}
                      className={`capabilities-tree-item ${isSelected ? "is-open" : ""}`}
                    >
                      <button
                        type="button"
                        className={`capabilities-list-row ${isSelected ? "is-selected" : ""}`}
                        onClick={() => setSelectedConnectionId(connector.id)}
                      >
                        <span
                          className="capabilities-provider-badge"
                          style={{ color: providerAccent(connector.provider) }}
                        >
                          {connector.name.slice(0, 1)}
                        </span>
                        <span className="capabilities-row-copy">
                          <strong>{connector.name}</strong>
                          <small>{connector.description}</small>
                        </span>
                        <span
                          className={`capabilities-row-status status-${connector.status}`}
                        >
                          {origin === "workspace"
                            ? "Staged"
                            : connectorStatusLabel(connector.status)}
                        </span>
                        <span
                          className={`capabilities-row-caret ${isSelected ? "is-open" : ""}`}
                          aria-hidden="true"
                        >
                          <ChevronRightIcon />
                        </span>
                      </button>

                      {isSelected ? renderTreeEntries(entries) : null}
                    </div>
                  );
                })}
              </div>
            </section>
          );
        })}
        {filteredConnections.length === 0 ? (
          <div className="capabilities-empty-state">
            No connections match the current search.
          </div>
        ) : null}
      </>
    );
  };

  const renderExtensionList = () => (
    <>
      <section className="capabilities-list-group">
        <div className="capabilities-list-group-head">
          <h3>Installed surfaces</h3>
          <span>{filteredExtensions.length}</span>
        </div>
        <div className="capabilities-list-rows">
          {filteredExtensions.map((extension) => {
            const isSelected = selectedExtensionId === extension.id;
            const entries: CapabilityTreeEntry[] = [
              {
                id: "overview",
                label: "Overview",
                note: "Why this package exists in the capability model",
                meta: extension.status,
                active: extensionDetailSection === "overview",
                onSelect: () => setExtensionDetailSection("overview"),
              },
              {
                id: "surface",
                label: "Surfaces",
                note: "Callable capability surfaces contributed by the package",
                meta: `${extension.surfaces.length} items`,
                active: extensionDetailSection === "surface",
                onSelect: () => setExtensionDetailSection("surface"),
              },
            ];

            return (
              <div
                key={extension.id}
                className={`capabilities-tree-item ${isSelected ? "is-open" : ""}`}
              >
                <button
                  type="button"
                  className={`capabilities-list-row ${isSelected ? "is-selected" : ""}`}
                  onClick={() => setSelectedExtensionId(extension.id)}
                >
                  <span className="capabilities-row-icon capabilities-row-icon-extension">
                    <BlocksIcon />
                  </span>
                  <span className="capabilities-row-copy">
                    <strong>{extension.name}</strong>
                    <small>{extension.description}</small>
                  </span>
                  <span className="capabilities-row-meta">
                    {extension.status}
                  </span>
                  <span
                    className={`capabilities-row-caret ${isSelected ? "is-open" : ""}`}
                    aria-hidden="true"
                  >
                    <ChevronRightIcon />
                  </span>
                </button>

                {isSelected ? renderTreeEntries(entries) : null}
              </div>
            );
          })}
        </div>
      </section>
      {filteredExtensions.length === 0 ? (
        <div className="capabilities-empty-state">
          No extensions match the current search.
        </div>
      ) : null}
    </>
  );

  const renderTreeEntries = (entries: CapabilityTreeEntry[]) => (
    <div className="capabilities-tree-children">
      {entries.map((entry) => (
        <button
          key={entry.id}
          type="button"
          className={`capabilities-tree-child ${entry.active ? "is-active" : ""}`}
          onClick={entry.onSelect}
          aria-current={entry.active ? "page" : undefined}
        >
          <span className="capabilities-tree-rail" aria-hidden="true" />
          <span className="capabilities-tree-copy">
            <strong>{entry.label}</strong>
            <small>{entry.note}</small>
          </span>
          {entry.meta ? (
            <span className="capabilities-tree-meta">{entry.meta}</span>
          ) : null}
        </button>
      ))}
    </div>
  );

  const renderSkillDetail = () => {
    if (!selectedSkill) {
      return (
        <div className="capabilities-empty-detail">
          Select a skill to inspect its procedure, tools, and benchmark posture.
        </div>
      );
    }

    const enabled = enabledSkills[selectedSkill.hash] ?? true;
    const sectionTitle =
      skillDetailSection === "guide"
        ? "SKILL.md"
        : humanize(skillDetailSection);
    const sectionSummary =
      skillDetailSection === "overview"
        ? "Benchmark posture, tool bundle, and readiness for worker attachment."
        : skillDetailSection === "procedure"
          ? "Observed or published execution flow for this reusable behavior."
          : "Primary markdown instructions used when the worker invokes this skill.";
    const sectionMeta =
      skillDetailSection === "guide"
        ? "Markdown"
        : skillDetailSection === "procedure"
          ? `${selectedSkill.detail.steps.length || 1} steps`
          : `${selectedSkill.detail.used_tools.length} tools`;

    return (
      <div className="capabilities-detail-scroll">
        <header className="capabilities-detail-header">
          <div>
            <span className="capabilities-kicker">
              {selectedSkill.origin === "starter" ? "Starter skill" : "Runtime skill"}
            </span>
            <h2>{selectedSkill.catalog.name}</h2>
          </div>
          <label className="capabilities-switch">
            <input
              type="checkbox"
              checked={enabled}
              onChange={(event) =>
                setEnabledSkills((current) => ({
                  ...current,
                  [selectedSkill.hash]: event.target.checked,
                }))
              }
            />
            <span>{enabled ? "Enabled" : "Disabled"}</span>
          </label>
        </header>

        <div className="capabilities-detail-inline-meta">
          <span>
            Added by <strong>{selectedSkill.addedBy}</strong>
          </span>
          <span>
            Invoked by <strong>{selectedSkill.invokedBy}</strong>
          </span>
          <span>
            Status{" "}
            <strong>{humanize(selectedSkill.catalog.lifecycle_state)}</strong>
          </span>
          <span>
            Success{" "}
            <strong>
              {formatSuccessRate(
                selectedSkill.detail.benchmark.success_rate_bps,
              )}
            </strong>
          </span>
        </div>

        <p className="capabilities-detail-summary">
          {selectedSkill.catalog.description}
        </p>

        <DetailDocument
          title={sectionTitle}
          summary={sectionSummary}
          meta={<span className="capabilities-pill">{sectionMeta}</span>}
        >
          {skillDetailSection === "overview" ? (
            <section className="capabilities-detail-card">
              <div className="capabilities-detail-card-head">
                <h3>Overview</h3>
                <span>{selectedSkill.detail.used_tools.length} tools</span>
              </div>
              <div className="capabilities-detail-meta-grid capabilities-detail-meta-grid-compact">
                <article>
                  <span>Sample size</span>
                  <strong>{selectedSkill.detail.benchmark.sample_size}</strong>
                </article>
                <article>
                  <span>Avg latency</span>
                  <strong>
                    {selectedSkill.detail.benchmark.avg_latency_ms} ms
                  </strong>
                </article>
                <article>
                  <span>Policy incidents</span>
                  <strong>
                    {selectedSkill.detail.benchmark.policy_incident_rate_bps} bps
                  </strong>
                </article>
              </div>
              <div className="capabilities-chip-row">
                {selectedSkill.detail.used_tools.map((toolName) => (
                  <span key={toolName} className="capabilities-chip">
                    {toolName}
                  </span>
                ))}
              </div>
            </section>
          ) : null}

          {skillDetailSection === "procedure" ? (
            <section className="capabilities-detail-card">
              <div className="capabilities-detail-card-head">
                <h3>Procedure</h3>
                <span>{selectedSkill.detail.steps.length} steps</span>
              </div>
              <ol className="capabilities-step-list">
                {selectedSkill.detail.steps.length > 0 ? (
                  selectedSkill.detail.steps.map((step) => (
                    <li key={`${step.tool_name}-${step.index}`}>
                      <strong>{step.tool_name}</strong>
                      <span>{step.target}</span>
                    </li>
                  ))
                ) : (
                  <li>
                    <strong>Published macro</strong>
                    <span>
                      This skill ships without a step-by-step trace in the local
                      runtime.
                    </span>
                  </li>
                )}
              </ol>
            </section>
          ) : null}

          {skillDetailSection === "guide" ? (
            <section className="capabilities-detail-card">
              <div className="capabilities-detail-card-head">
                <h3>Guide</h3>
                <span>Spec-aligned reusable behavior</span>
              </div>
              <div className="capabilities-markdown">
                <MarkdownRenderer remarkPlugins={[remarkGfm]}>
                  {selectedSkill.detail.markdown ||
                    `# ${selectedSkill.catalog.name}\n\n${selectedSkill.catalog.description}`}
                </MarkdownRenderer>
              </div>
            </section>
          ) : null}
        </DetailDocument>
      </div>
    );
  };

  const renderConnectionDetail = () => {
    if (!selectedConnectionRecord) {
      return (
        <div className="capabilities-empty-detail">
          Select a connection to inspect auth state, policy posture, and setup
          flows.
        </div>
      );
    }

    const { connector, origin } = selectedConnectionRecord;
    const policySummary = getConnectorPolicySummary?.(connector) ?? null;
    const sectionTitle = humanize(connectionDetailSection);
    const sectionSummary =
      connectionDetailSection === "overview"
        ? "Reach, scopes, and current notes for this authenticated surface."
        : connectionDetailSection === "setup"
          ? "Attach auth, finish adapter wiring, or stage the connector for runtime use."
          : "Governance and approval controls applied to this connection.";
    const sectionMeta =
      connectionDetailSection === "overview"
        ? `${connector.scopes.length} scopes`
        : connectionDetailSection === "setup"
          ? origin === "workspace"
            ? "Planned"
            : "Live"
          : "Guardrails";

    return (
      <div className="capabilities-detail-scroll">
        <header className="capabilities-detail-header">
          <div>
            <span className="capabilities-kicker">{humanize(connector.category)}</span>
            <h2>{connector.name}</h2>
          </div>
          <span className={`capabilities-pill status-${connector.status}`}>
            {origin === "workspace"
              ? "Staged"
              : connectorStatusLabel(connector.status)}
          </span>
        </header>

        <div className="capabilities-detail-inline-meta">
          <span>
            Provider <strong>{connector.provider}</strong>
          </span>
          <span>
            Category <strong>{humanize(connector.category)}</strong>
          </span>
          <span>
            Auth <strong>{formatAuthMode(connector.authMode)}</strong>
          </span>
          <span>
            Scopes <strong>{connector.scopes.length}</strong>
          </span>
        </div>

        <p className="capabilities-detail-summary">{connector.description}</p>

        <DetailDocument
          title={sectionTitle}
          summary={sectionSummary}
          meta={<span className="capabilities-pill">{sectionMeta}</span>}
        >
          {connectionDetailSection === "overview" ? (
            <section className="capabilities-detail-card">
              <div className="capabilities-detail-card-head">
                <h3>Overview</h3>
                <span>{connector.scopes.length} scopes</span>
              </div>
              <div className="capabilities-chip-row">
                {connector.scopes.map((scope) => (
                  <span key={scope} className="capabilities-chip">
                    {humanize(scope)}
                  </span>
                ))}
              </div>
              {connector.notes ? (
                <p className="capabilities-inline-note">{connector.notes}</p>
              ) : null}
            </section>
          ) : null}

          {connectionDetailSection === "policy" ? (
            policySummary ? (
              <section className="capabilities-detail-card capabilities-policy-card">
                <div className="capabilities-detail-card-head">
                  <h3>Policy</h3>
                  <button
                    type="button"
                    className="capabilities-inline-button"
                    onClick={() => onOpenPolicyCenter?.(connector)}
                  >
                    Open policy
                  </button>
                </div>
                <strong>{policySummary.headline}</strong>
                <p>{policySummary.detail}</p>
              </section>
            ) : (
              <section className="capabilities-detail-card">
                <div className="capabilities-detail-card-head">
                  <h3>Policy</h3>
                </div>
                <p>
                  No connection-specific policy summary is available yet for this
                  surface.
                </p>
              </section>
            )
          ) : null}

          {connectionDetailSection === "setup" ? (
            origin === "runtime" && connector.pluginId === "google_workspace" ? (
              <GoogleWorkspaceConnectorPanel
                runtime={runtime}
                connector={connector}
                onConfigured={(result) =>
                  setRuntimeConnectors((current) =>
                    patchConnectorFromConfigurationResult(current, result),
                  )
                }
                onOpenPolicyCenter={onOpenPolicyCenter}
                policySummary={policySummary ?? undefined}
              />
            ) : origin === "runtime" && connector.id === "mail.primary" ? (
              <MailConnectorPanel mail={mail} />
            ) : (
              <section className="capabilities-detail-card">
                <div className="capabilities-detail-card-head">
                  <h3>Setup</h3>
                  <span>{origin === "workspace" ? "Planned" : "Available"}</span>
                </div>
                <p>
                  {origin === "workspace"
                    ? "This connection is staged in the workspace shell so teams can design around it before the adapter ships."
                    : "This connection exposes a generic runtime surface. Configure it to attach auth and unlock its callable actions."}
                </p>
                <div className="capabilities-action-row">
                  {origin === "runtime" ? (
                    <button
                      type="button"
                      className="capabilities-primary-button"
                      disabled={genericConnectorBusy}
                      onClick={() => void runGenericConnectorSetup(connector)}
                    >
                      {genericConnectorBusy ? "Connecting..." : "Connect"}
                    </button>
                  ) : null}
                  <button
                    type="button"
                    className="capabilities-secondary-button"
                    onClick={() => onOpenPolicyCenter?.(connector)}
                  >
                    Open policy
                  </button>
                </div>
                {genericConnectorMessage ? (
                  <p className="capabilities-inline-note">
                    {genericConnectorMessage}
                  </p>
                ) : null}
              </section>
            )
          ) : null}
        </DetailDocument>
      </div>
    );
  };

  const renderExtensionDetail = () => {
    if (!selectedExtension) {
      return (
        <div className="capabilities-empty-detail">
          Select an extension to inspect the capability surface it contributes.
        </div>
      );
    }

    const sectionTitle =
      extensionDetailSection === "surface" ? "Surfaces" : "Overview";
    const sectionSummary =
      extensionDetailSection === "surface"
        ? "Capability surfaces currently contributed by this extension package."
        : "How this extension fits into the broader worker capability model.";
    const sectionMeta =
      extensionDetailSection === "surface"
        ? `${selectedExtension.surfaces.length} items`
        : selectedExtension.status;

    return (
      <div className="capabilities-detail-scroll">
        <header className="capabilities-detail-header">
          <div>
            <span className="capabilities-kicker">
              {selectedExtension.meta}
            </span>
            <h2>{selectedExtension.name}</h2>
          </div>
          <span className="capabilities-pill">{selectedExtension.status}</span>
        </header>

        <div className="capabilities-detail-inline-meta">
          <span>
            Status <strong>{selectedExtension.status}</strong>
          </span>
          <span>
            Package <strong>{selectedExtension.meta}</strong>
          </span>
          <span>
            Surfaces <strong>{selectedExtension.surfaces.length}</strong>
          </span>
        </div>

        <p className="capabilities-detail-summary">
          {selectedExtension.description}
        </p>

        <DetailDocument
          title={sectionTitle}
          summary={sectionSummary}
          meta={<span className="capabilities-pill">{sectionMeta}</span>}
        >
          {extensionDetailSection === "surface" ? (
            <section className="capabilities-detail-card">
              <div className="capabilities-detail-card-head">
                <h3>Surfaces</h3>
                <span>{selectedExtension.meta}</span>
              </div>
              <div className="capabilities-chip-row">
                {selectedExtension.surfaces.map((surfaceName) => (
                  <span key={surfaceName} className="capabilities-chip">
                    {surfaceName}
                  </span>
                ))}
              </div>
            </section>
          ) : null}

          {extensionDetailSection === "overview" ? (
            <section className="capabilities-detail-card">
              <div className="capabilities-detail-card-head">
                <h3>Overview</h3>
              </div>
              <p>
                Extensions package one or more capability surfaces into something
                the worker can reliably use. They can contribute connections,
                tools, wrappers, or local adapters without fragmenting the
                top-level model.
              </p>
            </section>
          ) : null}
        </DetailDocument>
      </div>
    );
  };

  const renderHomeLanding = () => {
    return (
      <section className="capabilities-home-pane">
        <div className="capabilities-home-shell">
          <div className="capabilities-home-hero">
            <div className="capabilities-home-icon">
              <BlocksIcon />
            </div>
            <h2>Manage capabilities</h2>
            <p>
              Choose one top-level surface from the left, then drill into the
              nested browser only when you need the deeper controls.
            </p>
            <div className="capabilities-home-meta" aria-label="Capability summary">
              <span>{workspaceSkills.length} skills available</span>
              <span>
                {connectedConnectionCount}/{workspaceConnections.length} connections
                active
              </span>
              <span>{extensions.length} extensions installed</span>
            </div>
          </div>
        </div>
      </section>
    );
  };

  return (
    <div className={`capabilities-workbench ${surface === null ? "is-home" : ""}`}>
      <aside className="capabilities-sidebar">
        <div className="capabilities-sidebar-head">
          <div className="capabilities-sidebar-titlebar">
            <button
              type="button"
              className="capabilities-sidebar-backdrop"
              onClick={returnToHome}
              disabled={surface === null}
              aria-label="Back to capabilities home"
              title="Back to capabilities home"
            >
              <ArrowLeftIcon />
            </button>
            <span>Capabilities</span>
          </div>
        </div>

        <nav className="capabilities-nav">
          <MenuButton
            active={surface === "skills"}
            icon={<SparklesIcon />}
            label="Skills"
            onClick={() => openSurface("skills")}
          />
          <MenuButton
            active={surface === "connections"}
            icon={<CableIcon />}
            label="Connections"
            onClick={() => openSurface("connections")}
          />
          <MenuButton
            active={surface === "extensions"}
            icon={<BlocksIcon />}
            label="Extensions"
            onClick={() => openSurface("extensions")}
          />
        </nav>
      </aside>

      {surface === null ? (
        renderHomeLanding()
      ) : (
        <>
          <section className="capabilities-list-pane">
            <header className="capabilities-pane-header">
              <div className="capabilities-pane-title">
                <span className="capabilities-pane-kicker">Workspace</span>
                <h2>{humanize(surface)}</h2>
                <span className="capabilities-pane-count">
                  {surface === "skills"
                    ? `${workspaceSkills.length} available`
                    : surface === "connections"
                      ? `${workspaceConnections.length} total`
                      : `${extensions.length} installed`}
                </span>
              </div>
              <div className="capabilities-pane-controls">
                <label className="capabilities-search">
                  <SearchIcon />
                  <input
                    value={query}
                    onChange={(event) => setQuery(event.target.value)}
                    placeholder={`Search ${surface}...`}
                    aria-label={`Search ${surface}`}
                  />
                </label>
                {surface === "connections" ? (
                  <div ref={connectionsMenuRef} className="capabilities-popover">
                    <button
                      type="button"
                      className="capabilities-icon-button"
                      onClick={() => setConnectionsMenuOpen((current) => !current)}
                      aria-label="Browse connections"
                      aria-expanded={connectionsMenuOpen}
                      aria-haspopup="menu"
                    >
                      <PlusIcon />
                    </button>
                    {connectionsMenuOpen ? (
                      <div className="capabilities-popover-menu" role="menu">
                        <button
                          type="button"
                          className="capabilities-popover-item"
                          role="menuitem"
                          onClick={() => {
                            setConnectionsMenuOpen(false);
                            setCatalogModalOpen(true);
                          }}
                        >
                          <strong>Browse connections</strong>
                          <span>Choose from the starter catalog</span>
                        </button>
                        <button
                          type="button"
                          className="capabilities-popover-item"
                          role="menuitem"
                          onClick={() => {
                            setConnectionsMenuOpen(false);
                            setCustomModalOpen(true);
                          }}
                        >
                          <strong>Add custom connection</strong>
                          <span>Register a remote MCP surface</span>
                        </button>
                      </div>
                    ) : null}
                  </div>
                ) : null}
              </div>
            </header>

            {customNotice ? (
              <div className="capabilities-pane-flash">
                <CheckCircleIcon />
                <span>{customNotice}</span>
                <button
                  type="button"
                  aria-label="Dismiss notice"
                  onClick={() => setCustomNotice(null)}
                >
                  <XIcon />
                </button>
              </div>
            ) : null}

            <div className="capabilities-list-scroll">
              {surface === "skills" ? renderSkillList() : null}
              {surface === "connections" ? renderConnectionList() : null}
              {surface === "extensions" ? renderExtensionList() : null}
            </div>
          </section>

          <section className="capabilities-detail-pane">
            {surface === "skills" ? renderSkillDetail() : null}
            {surface === "connections" ? renderConnectionDetail() : null}
            {surface === "extensions" ? renderExtensionDetail() : null}
          </section>
        </>
      )}

      {catalogModalOpen ? (
        <div className="capabilities-modal-backdrop" role="presentation">
          <div
            className="capabilities-modal capabilities-modal-wide"
            role="dialog"
            aria-modal="true"
            aria-label="Browse connections"
          >
            <div className="capabilities-modal-head">
              <div>
                <h2>Browse connections</h2>
                <p>
                  Add authenticated systems to the workspace shell before wiring
                  or expanding the underlying adapter.
                </p>
              </div>
              <button
                type="button"
                className="capabilities-icon-button"
                onClick={() => setCatalogModalOpen(false)}
                aria-label="Close browse connections"
              >
                <XIcon />
              </button>
            </div>

            <div className="capabilities-modal-toolbar">
              <label className="capabilities-search">
                <SearchIcon />
                <input
                  value={catalogQuery}
                  onChange={(event) => setCatalogQuery(event.target.value)}
                  placeholder="Search connection catalog..."
                />
              </label>
              <label className="capabilities-select">
                <span>Category</span>
                <select
                  value={catalogCategoryFilter}
                  onChange={(event) =>
                    setCatalogCategoryFilter(
                      event.target.value as
                        | ConnectorSummary["category"]
                        | "all",
                    )
                  }
                >
                  <option value="all">All</option>
                  <option value="communication">Communication</option>
                  <option value="productivity">Productivity</option>
                  <option value="storage">Storage</option>
                  <option value="developer">Developer</option>
                </select>
              </label>
            </div>

            <div className="capabilities-catalog-grid">
              {availableCatalogItems.map(({ item, alreadyAdded }) => (
                <article key={item.id} className="capabilities-catalog-card">
                  <div className="capabilities-catalog-card-head">
                    <span
                      className="capabilities-provider-badge"
                      style={{ color: providerAccent(item.provider) }}
                    >
                      {item.name.slice(0, 1)}
                    </span>
                    <div>
                      <strong>{item.name}</strong>
                      <small>{item.popularityLabel}</small>
                    </div>
                  </div>
                  <p>{item.description}</p>
                  <div className="capabilities-chip-row">
                    {item.scopes.slice(0, 3).map((scope) => (
                      <span key={scope} className="capabilities-chip">
                        {humanize(scope)}
                      </span>
                    ))}
                  </div>
                  <div className="capabilities-action-row">
                    <button
                      type="button"
                      className="capabilities-primary-button"
                      onClick={() => addCatalogConnection(item)}
                      disabled={alreadyAdded}
                    >
                      {alreadyAdded ? "Added" : "Add to workspace"}
                    </button>
                  </div>
                </article>
              ))}
            </div>
          </div>
        </div>
      ) : null}

      {customModalOpen ? (
        <div className="capabilities-modal-backdrop" role="presentation">
          <div
            className="capabilities-modal"
            role="dialog"
            aria-modal="true"
            aria-label="Add custom connection"
          >
            <div className="capabilities-modal-head">
              <div>
                <h2>Add custom connection</h2>
                <p>
                  Register a remote MCP or local adapter surface so teams can
                  design around it before the runtime is fully wired.
                </p>
              </div>
              <button
                type="button"
                className="capabilities-icon-button"
                onClick={() => setCustomModalOpen(false)}
                aria-label="Close custom connection modal"
              >
                <XIcon />
              </button>
            </div>

            <div className="capabilities-form-grid">
              <label>
                Name
                <input
                  value={customName}
                  onChange={(event) => setCustomName(event.target.value)}
                  placeholder="GitHub Enterprise"
                />
              </label>
              <label>
                Remote MCP server URL
                <input
                  value={customUrl}
                  onChange={(event) => setCustomUrl(event.target.value)}
                  placeholder="https://mcp.example.com"
                />
              </label>
              <label>
                Category
                <select
                  value={customCategory}
                  onChange={(event) =>
                    setCustomCategory(
                      event.target.value as ConnectorSummary["category"],
                    )
                  }
                >
                  <option value="developer">Developer</option>
                  <option value="communication">Communication</option>
                  <option value="productivity">Productivity</option>
                  <option value="storage">Storage</option>
                </select>
              </label>
              <label className="is-wide">
                Description
                <textarea
                  value={customDescription}
                  onChange={(event) => setCustomDescription(event.target.value)}
                />
              </label>
              <label className="is-wide">
                Scopes
                <input
                  value={customScopes}
                  onChange={(event) => setCustomScopes(event.target.value)}
                  placeholder="tools.invoke, resources.read"
                />
              </label>
            </div>

            <div className="capabilities-inline-note">
              Only register custom connections from developers you trust. A
              staged connection does not grant runtime execution until an
              adapter is installed and policy allows it.
            </div>

            <div className="capabilities-modal-actions">
              <button
                type="button"
                className="capabilities-secondary-button"
                onClick={() => setCustomModalOpen(false)}
              >
                Cancel
              </button>
              <button
                type="button"
                className="capabilities-primary-button"
                onClick={createCustomConnection}
              >
                Add connection
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}
