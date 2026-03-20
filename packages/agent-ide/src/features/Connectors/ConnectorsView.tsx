import { useCallback, useEffect, useMemo, useState } from "react";
import type {
  AgentRuntime,
  ConnectorConfigureResult,
  ConnectorSummary,
  ConnectorStatus,
  WalletMailConfigureAccountResult,
} from "../../runtime/agent-runtime";
import { Icons } from "../../ui/icons";
import { ConnectorsHeader } from "./components/ConnectorsHeader";
import { GoogleWorkspaceConnectorPanel } from "./components/GoogleWorkspaceConnectorPanel";
import { MailConnectorPanel } from "./components/MailConnectorPanel";
import { useMailConnectorActions } from "./hooks/useMailConnectorActions";
import "./ConnectorsView.css";

interface CapabilityOverviewItem {
  label: string;
  value: string;
  hint: string;
}

interface CapabilitySkillPreview {
  id: string;
  name: string;
  description: string;
  status: string;
  meta: string;
}

interface CapabilityExtensionPreview {
  id: string;
  name: string;
  description: string;
  status: string;
  meta: string;
}

interface ConnectorsViewProps {
  runtime: AgentRuntime;
  initialConnectors?: ConnectorSummary[];
  surfaceTitle?: string;
  surfaceDescription?: string;
  searchPlaceholder?: string;
  searchLabel?: string;
  overviewItems?: CapabilityOverviewItem[];
  skills?: CapabilitySkillPreview[];
  extensions?: CapabilityExtensionPreview[];
  connectionSectionTitle?: string;
  connectionSectionDescription?: string;
  getConnectorPolicySummary?: (
    connector: ConnectorSummary,
  ) => { headline: string; detail: string } | null;
  onOpenPolicyCenter?: (connector: ConnectorSummary) => void;
}

const FALLBACK_CONNECTORS: ConnectorSummary[] = [
  {
    id: "mail.primary",
    pluginId: "wallet_mail",
    name: "Mail",
    provider: "wallet.network",
    category: "communication",
    description:
      "Connect one or more inboxes for safe delegated read/send operations.",
    status: "needs_auth",
    authMode: "wallet_capability",
    scopes: [
      "mail.read.latest",
      "mail.list.recent",
      "mail.delete.spam",
      "mail.reply",
    ],
    notes:
      "Uses wallet-backed connector auth, mailbox-scoped credentials, and delegated capability leases.",
  },
  {
    id: "google.workspace",
    pluginId: "google_workspace",
    name: "Google",
    provider: "google",
    category: "productivity",
    description:
      "Single Google connector for Gmail, Calendar, Docs, Sheets, BigQuery, Drive, Tasks, Chat, workflows, events, and expert raw access.",
    status: "needs_auth",
    authMode: "wallet_capability",
    scopes: [
      "gmail",
      "calendar",
      "docs",
      "sheets",
      "bigquery",
      "drive",
      "tasks",
      "chat",
      "events",
      "workflow",
      "expert",
    ],
    notes:
      "Uses native Google OAuth for consent, with refreshable auth persisted through wallet-backed connector state.",
  },
];

const MAIL_CONNECTOR_DEFAULT: ConnectorSummary = {
  id: "mail.primary",
  pluginId: "wallet_mail",
  name: "Mail",
  provider: "wallet.network",
  category: "communication",
  description:
    "Connect one or more inboxes for safe delegated read/send operations.",
  status: "needs_auth",
  authMode: "wallet_capability",
  scopes: [
    "mail.read.latest",
    "mail.list.recent",
    "mail.delete.spam",
    "mail.reply",
  ],
  notes:
    "Uses wallet-backed connector auth, mailbox-scoped credentials, and delegated capability leases.",
};

function patchMailConnectorFromConfiguredAccount(
  connectors: ConnectorSummary[],
  result: WalletMailConfigureAccountResult,
): ConnectorSummary[] {
  const syncedAt = new Date(result.updatedAtMs).toISOString();
  const connectedNote = `Connected ${result.accountEmail} on mailbox "${result.mailbox}".`;

  let foundMailConnector = false;
  const next = connectors.map((connector) => {
    if (connector.id !== "mail.primary") return connector;
    foundMailConnector = true;
    return {
      ...connector,
      status: "connected" as ConnectorStatus,
      lastSyncAtUtc: syncedAt,
      notes: connectedNote,
    };
  });

  if (foundMailConnector) return next;

  return [
    {
      ...MAIL_CONNECTOR_DEFAULT,
      status: "connected" as ConnectorStatus,
      lastSyncAtUtc: syncedAt,
      notes: connectedNote,
    },
    ...next,
  ];
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

function statusLabel(status: ConnectorStatus): string {
  switch (status) {
    case "connected":
      return "Connected";
    case "needs_auth":
      return "Needs auth";
    case "degraded":
      return "Degraded";
    case "disabled":
      return "Disabled";
    default:
      return "Unknown";
  }
}

export function ConnectorsView({
  runtime,
  initialConnectors,
  surfaceTitle = "Connections",
  surfaceDescription = "Authenticated systems workers can reach. Secrets stay in Vault; workers receive bounded execution rights.",
  searchPlaceholder = "Search connections...",
  searchLabel = "Search connections",
  overviewItems,
  skills,
  extensions,
  connectionSectionTitle = "Connections",
  connectionSectionDescription,
  getConnectorPolicySummary,
  onOpenPolicyCenter,
}: ConnectorsViewProps) {
  const [connectors, setConnectors] = useState<ConnectorSummary[]>(
    initialConnectors && initialConnectors.length > 0
      ? initialConnectors
      : FALLBACK_CONNECTORS,
  );
  const [query, setQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<ConnectorStatus | "all">(
    "all",
  );

  useEffect(() => {
    if (initialConnectors && initialConnectors.length > 0) {
      setConnectors(initialConnectors);
    }
  }, [initialConnectors]);

  const onMailAccountConfigured = useCallback(
    (result: WalletMailConfigureAccountResult) => {
      setConnectors((current) =>
        patchMailConnectorFromConfiguredAccount(current, result),
      );
    },
    [],
  );
  const onConnectorConfigured = useCallback(
    (result: ConnectorConfigureResult) => {
      setConnectors((current) =>
        patchConnectorFromConfigurationResult(current, result),
      );
    },
    [],
  );
  const mail = useMailConnectorActions(runtime, {
    onAccountConfigured: onMailAccountConfigured,
  });

  const loadConnectors = useCallback(() => {
    let cancelled = false;
    if (!runtime.getConnectors) return () => {};

    runtime
      .getConnectors()
      .then((items) => {
        if (!cancelled && Array.isArray(items) && items.length > 0) {
          setConnectors(items);
        }
      })
      .catch(() => {
        // Keep fallback scaffold when runtime connector API is not active yet.
      });

    return () => {
      cancelled = true;
    };
  }, [runtime]);

  useEffect(() => {
    return loadConnectors();
  }, [loadConnectors]);

  const filtered = useMemo(() => {
    return connectors.filter((connector) => {
      const connectorStatus: ConnectorStatus =
        connector.id === "mail.primary" && mail.connectedMailAccounts.length > 0
          ? "connected"
          : connector.status;
      if (statusFilter !== "all" && connectorStatus !== statusFilter) {
        return false;
      }
      if (!query.trim()) return true;
      const q = query.trim().toLowerCase();
      const haystack = [
        connector.name,
        connector.provider,
        connector.description,
        connector.scopes.join(" "),
      ]
        .join(" ")
        .toLowerCase();
      return haystack.includes(q);
    });
  }, [connectors, mail.connectedMailAccounts.length, query, statusFilter]);

  const hasCapabilityPrelude =
    (overviewItems?.length ?? 0) > 0 ||
    skills !== undefined ||
    extensions !== undefined;
  const showConnectionSectionHead =
    hasCapabilityPrelude ||
    connectionSectionTitle !== "Connections" ||
    Boolean(connectionSectionDescription);

  return (
    <div className="connectors-view">
      <ConnectorsHeader
        title={surfaceTitle}
        description={surfaceDescription}
        query={query}
        onQueryChange={setQuery}
        statusFilter={statusFilter}
        onStatusFilterChange={setStatusFilter}
        statusLabel={statusLabel}
        searchPlaceholder={searchPlaceholder}
        searchLabel={searchLabel}
      />

      <div className="connectors-scroll">
        {overviewItems && overviewItems.length > 0 ? (
          <section
            className="capability-overview-grid"
            aria-label="Capability overview"
          >
            {overviewItems.map((item) => (
              <article key={item.label} className="capability-overview-card">
                <span>{item.label}</span>
                <strong>{item.value}</strong>
                <p>{item.hint}</p>
              </article>
            ))}
          </section>
        ) : null}

        {skills !== undefined ? (
          <section
            className="capability-preview-section"
            aria-label="Skills preview"
          >
            <div className="capability-section-head">
              <div>
                <h2>Skills</h2>
                <p>
                  Reusable procedures workers can attach and promote over time.
                </p>
              </div>
              <span>{skills.length}</span>
            </div>
            {skills.length > 0 ? (
              <div className="capability-preview-grid">
                {skills.map((skill) => (
                  <article key={skill.id} className="capability-preview-card">
                    <div className="capability-preview-card-head">
                      <strong>{skill.name}</strong>
                      <span>{skill.status}</span>
                    </div>
                    <p>{skill.description}</p>
                    <small>{skill.meta}</small>
                  </article>
                ))}
              </div>
            ) : (
              <div className="capability-empty-card">
                No durable skills are visible in this runtime yet.
              </div>
            )}
          </section>
        ) : null}

        {extensions !== undefined ? (
          <section
            className="capability-preview-section"
            aria-label="Extensions preview"
          >
            <div className="capability-section-head">
              <div>
                <h2>Extensions</h2>
                <p>
                  Installed packages that add connections, tools, wrappers, or
                  local adapters.
                </p>
              </div>
              <span>{extensions.length}</span>
            </div>
            {extensions.length > 0 ? (
              <div className="capability-preview-grid">
                {extensions.map((extension) => (
                  <article
                    key={extension.id}
                    className="capability-preview-card"
                  >
                    <div className="capability-preview-card-head">
                      <strong>{extension.name}</strong>
                      <span>{extension.status}</span>
                    </div>
                    <p>{extension.description}</p>
                    <small>{extension.meta}</small>
                  </article>
                ))}
              </div>
            ) : (
              <div className="capability-empty-card">
                No installed extensions are visible in this runtime yet.
              </div>
            )}
          </section>
        ) : null}

        <section className="connectors-section">
          {showConnectionSectionHead ? (
            <div className="capability-section-head">
              <div>
                <h2>{connectionSectionTitle}</h2>
                {connectionSectionDescription ? (
                  <p>{connectionSectionDescription}</p>
                ) : null}
              </div>
              <span>{filtered.length}</span>
            </div>
          ) : null}

          {filtered.length === 0 ? (
            <div className="capability-empty-card">
              No connections match the current search and status filters.
            </div>
          ) : (
            <div className="connectors-grid">
              {filtered.map((connector) => {
                const isMailConnector = connector.id.startsWith("mail.");
                const isGoogleConnector =
                  connector.pluginId === "google_workspace";
                const policySummary =
                  getConnectorPolicySummary?.(connector) ?? null;
                const connectorStatus: ConnectorStatus =
                  connector.id === "mail.primary" &&
                  mail.connectedMailAccounts.length > 0
                    ? "connected"
                    : connector.status;

                return (
                  <article key={connector.id} className="connector-card">
                    <div className="connector-card-head">
                      <div className="connector-name-wrap">
                        <span className="connector-icon">
                          {connector.name.toLowerCase().includes("mail") ? (
                            <Icons.Mail width="16" height="16" />
                          ) : (
                            <Icons.Plug width="16" height="16" />
                          )}
                        </span>
                        <div>
                          <h2>{connector.name}</h2>
                          <p>{connector.provider}</p>
                        </div>
                      </div>
                      <span
                        className={`connector-status status-${connectorStatus}`}
                      >
                        {statusLabel(connectorStatus)}
                      </span>
                    </div>

                    <p className="connector-description">
                      {connector.description}
                    </p>

                    <div className="connector-meta">
                      <span>Auth: {connector.authMode}</span>
                      {connector.lastSyncAtUtc ? (
                        <span>Last sync: {connector.lastSyncAtUtc}</span>
                      ) : null}
                    </div>

                    {isGoogleConnector ? (
                      <div className="connector-scopes connector-scopes-google">
                        {[
                          "Gmail",
                          "Calendar",
                          "Docs",
                          "Sheets",
                          "BigQuery",
                          "Automations",
                        ].map((bundle) => (
                          <span key={bundle} className="workspace-bundle-chip">
                            {bundle}
                          </span>
                        ))}
                      </div>
                    ) : (
                      <div className="connector-scopes">
                        {connector.scopes.map((scope) => (
                          <code key={scope}>{scope}</code>
                        ))}
                      </div>
                    )}

                    {connector.notes && !isGoogleConnector ? (
                      <p className="connector-notes">{connector.notes}</p>
                    ) : null}

                    {policySummary ? (
                      <div className="connector-policy-summary">
                        <div>
                          <span className="connector-policy-kicker">
                            Policy
                          </span>
                          <strong>{policySummary.headline}</strong>
                          <p>{policySummary.detail}</p>
                        </div>
                        {onOpenPolicyCenter ? (
                          <button
                            type="button"
                            className="btn-secondary"
                            onClick={() => onOpenPolicyCenter(connector)}
                          >
                            Manage policy
                          </button>
                        ) : null}
                      </div>
                    ) : null}

                    {connector.id === "mail.primary" ? (
                      <MailConnectorPanel mail={mail} />
                    ) : null}
                    {connector.pluginId === "google_workspace" ? (
                      <GoogleWorkspaceConnectorPanel
                        runtime={runtime}
                        connector={connector}
                        onConfigured={onConnectorConfigured}
                        onOpenPolicyCenter={onOpenPolicyCenter}
                        policySummary={policySummary ?? undefined}
                      />
                    ) : null}

                    {!isMailConnector &&
                    connector.pluginId !== "google_workspace" ? (
                      <div className="connector-actions">
                        <button type="button" className="btn-secondary">
                          Configure
                        </button>
                        <button
                          type="button"
                          className="btn-primary"
                          disabled={connectorStatus === "disabled"}
                        >
                          {connectorStatus === "connected"
                            ? "Manage Session"
                            : "Connect"}
                        </button>
                      </div>
                    ) : null}
                  </article>
                );
              })}
            </div>
          )}
        </section>
      </div>
    </div>
  );
}
