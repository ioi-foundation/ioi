import { useEffect, useMemo, useState } from "react";
import type {
  AgentRuntime,
  ConnectorSummary,
  ConnectorStatus,
  WalletMailApprovalArtifactResult,
  WalletMailConfigureAccountResult,
  WalletMailIntentResult,
  WalletMailListRecentResult,
  WalletMailReadLatestResult,
} from "../../runtime/agent-runtime";
import { Icons } from "../../ui/icons";
import "./ConnectorsView.css";

interface ConnectorsViewProps {
  runtime: AgentRuntime;
}

const FALLBACK_CONNECTORS: ConnectorSummary[] = [
  {
    id: "mail.primary",
    name: "Mail",
    provider: "wallet.network",
    category: "communication",
    description:
      "Agent-safe mail access via delegated session authority. Planned first wallet_network integration: check inbox and read latest email.",
    status: "needs_auth",
    authMode: "wallet_network_session",
    scopes: ["mail.read.latest", "mail.list.recent", "mail.delete.spam", "mail.reply"],
    notes:
      "Planned path: open session channel -> approve bounded read lease -> execute inbox/list and latest message read.",
  },
  {
    id: "calendar.primary",
    name: "Calendar",
    provider: "wallet.network",
    category: "productivity",
    description: "Scaffold for delegated calendar read/write operations.",
    status: "disabled",
    authMode: "wallet_network_session",
    scopes: ["calendar.read.events"],
  },
];

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

function intentLikelyRequiresApproval(query: string): boolean {
  const q = query.trim().toLowerCase();
  if (!q) return false;
  const isDeleteSpam =
    (q.includes("delete") || q.includes("remove") || q.includes("trash")) &&
    (q.includes("spam") || q.includes("junk"));
  const isReplyIntent =
    q.includes("reply") || q.includes("respond to") || q.includes("email bob");
  return isDeleteSpam || isReplyIntent;
}

type MailProviderPresetKey = "auto" | "gmail" | "outlook" | "yahoo" | "aol" | "custom";
type MailTlsMode = "plaintext" | "starttls" | "tls";
type SupportedProviderPreset = Exclude<MailProviderPresetKey, "auto" | "custom">;

interface MailProviderPreset {
  label: string;
  domains: string[];
  imapHost: string;
  imapPort: number;
  imapTlsMode: MailTlsMode;
  smtpHost: string;
  smtpPort: number;
  smtpTlsMode: MailTlsMode;
  note: string;
}

const MAIL_PROVIDER_PRESETS: Record<SupportedProviderPreset, MailProviderPreset> = {
  gmail: {
    label: "Gmail",
    domains: ["gmail.com", "googlemail.com"],
    imapHost: "imap.gmail.com",
    imapPort: 993,
    imapTlsMode: "tls",
    smtpHost: "smtp.gmail.com",
    smtpPort: 587,
    smtpTlsMode: "starttls",
    note: "Use app password when 2FA is enabled.",
  },
  outlook: {
    label: "Outlook / Microsoft",
    domains: ["outlook.com", "hotmail.com", "live.com", "msn.com"],
    imapHost: "outlook.office365.com",
    imapPort: 993,
    imapTlsMode: "tls",
    smtpHost: "smtp.office365.com",
    smtpPort: 587,
    smtpTlsMode: "starttls",
    note: "Use app password if your account enforces modern auth.",
  },
  yahoo: {
    label: "Yahoo",
    domains: ["yahoo.com", "ymail.com", "rocketmail.com"],
    imapHost: "imap.mail.yahoo.com",
    imapPort: 993,
    imapTlsMode: "tls",
    smtpHost: "smtp.mail.yahoo.com",
    smtpPort: 465,
    smtpTlsMode: "tls",
    note: "App password is typically required.",
  },
  aol: {
    label: "AOL",
    domains: ["aol.com"],
    imapHost: "imap.aol.com",
    imapPort: 993,
    imapTlsMode: "tls",
    smtpHost: "smtp.aol.com",
    smtpPort: 465,
    smtpTlsMode: "tls",
    note: "App password is typically required.",
  },
};

function inferProviderFromEmail(email: string): SupportedProviderPreset | "custom" {
  const domain = email.trim().toLowerCase().split("@")[1] ?? "";
  for (const [key, preset] of Object.entries(MAIL_PROVIDER_PRESETS)) {
    if (preset.domains.some((candidate) => candidate === domain)) {
      return key as SupportedProviderPreset;
    }
  }
  return "custom";
}

export function ConnectorsView({ runtime }: ConnectorsViewProps) {
  const [connectors, setConnectors] = useState<ConnectorSummary[]>(FALLBACK_CONNECTORS);
  const [query, setQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<ConnectorStatus | "all">("all");
  const [mailProviderPreset, setMailProviderPreset] = useState<MailProviderPresetKey>("auto");
  const [mailSetupEmail, setMailSetupEmail] = useState("");
  const [mailSetupPassword, setMailSetupPassword] = useState("");
  const [mailSetupMailbox, setMailSetupMailbox] = useState("primary");
  const [mailSetupImapHost, setMailSetupImapHost] = useState("imap.gmail.com");
  const [mailSetupImapPort, setMailSetupImapPort] = useState(993);
  const [mailSetupImapTlsMode, setMailSetupImapTlsMode] = useState<MailTlsMode>("tls");
  const [mailSetupSmtpHost, setMailSetupSmtpHost] = useState("smtp.gmail.com");
  const [mailSetupSmtpPort, setMailSetupSmtpPort] = useState(587);
  const [mailSetupSmtpTlsMode, setMailSetupSmtpTlsMode] = useState<MailTlsMode>("starttls");
  const [mailSetupImapUsername, setMailSetupImapUsername] = useState("");
  const [mailSetupSmtpUsername, setMailSetupSmtpUsername] = useState("");
  const [mailSetupAdvancedOpen, setMailSetupAdvancedOpen] = useState(false);
  const [showOperatorTools, setShowOperatorTools] = useState(false);
  const [mailChannelId, setMailChannelId] = useState("");
  const [mailLeaseId, setMailLeaseId] = useState("");
  const [mailMailbox, setMailMailbox] = useState("primary");
  const [mailLimit, setMailLimit] = useState(5);
  const [mailOpSeq, setMailOpSeq] = useState(1);
  const [mailIntentQuery, setMailIntentQuery] = useState("");
  const [mailApprovalArtifactJson, setMailApprovalArtifactJson] = useState("");
  const [mailApprovalTtlSeconds, setMailApprovalTtlSeconds] = useState(300);
  const [mailAutoGenerateApproval, setMailAutoGenerateApproval] = useState(true);
  const [mailBusy, setMailBusy] = useState(false);
  const [mailError, setMailError] = useState<string | null>(null);
  const [mailResult, setMailResult] = useState<string>("");

  useEffect(() => {
    let cancelled = false;
    if (!runtime.getConnectors) return;

    runtime
      .getConnectors()
      .then((items) => {
        if (!cancelled && Array.isArray(items) && items.length > 0) {
          setConnectors(items);
        }
      })
      .catch(() => {
        // Keep fallback scaffold when runtime connector api is not active yet.
      });

    return () => {
      cancelled = true;
    };
  }, [runtime]);

  const filtered = useMemo(() => {
    return connectors.filter((connector) => {
      if (statusFilter !== "all" && connector.status !== statusFilter) {
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
  }, [connectors, query, statusFilter]);

  const mailConnectorRuntimeReady = Boolean(
    runtime.walletMailReadLatest && runtime.walletMailListRecent
  );
  const mailAssistantRuntimeReady = Boolean(runtime.walletMailHandleIntent);
  const mailApprovalRuntimeReady = Boolean(runtime.walletMailGenerateApprovalArtifact);
  const mailSetupRuntimeReady = Boolean(runtime.walletMailConfigureAccount);
  const inferredPreset = inferProviderFromEmail(mailSetupEmail);
  const effectivePresetKey =
    mailProviderPreset === "auto" ? inferredPreset : mailProviderPreset;
  const effectivePreset =
    effectivePresetKey === "custom" ? null : MAIL_PROVIDER_PRESETS[effectivePresetKey];

  useEffect(() => {
    if (!effectivePreset) return;
    setMailSetupImapHost(effectivePreset.imapHost);
    setMailSetupImapPort(effectivePreset.imapPort);
    setMailSetupImapTlsMode(effectivePreset.imapTlsMode);
    setMailSetupSmtpHost(effectivePreset.smtpHost);
    setMailSetupSmtpPort(effectivePreset.smtpPort);
    setMailSetupSmtpTlsMode(effectivePreset.smtpTlsMode);
  }, [effectivePresetKey, effectivePreset]);

  useEffect(() => {
    const email = mailSetupEmail.trim();
    if (!email) return;
    if (!mailSetupImapUsername.trim()) {
      setMailSetupImapUsername(email);
    }
    if (!mailSetupSmtpUsername.trim()) {
      setMailSetupSmtpUsername(email);
    }
  }, [mailSetupEmail, mailSetupImapUsername, mailSetupSmtpUsername]);

  useEffect(() => {
    setMailMailbox(mailSetupMailbox.trim() || "primary");
  }, [mailSetupMailbox]);

  const validateMailContext = (requireConnectorRuntime: boolean) => {
    const channelId = mailChannelId.trim();
    const leaseId = mailLeaseId.trim();
    if (requireConnectorRuntime && !mailConnectorRuntimeReady) {
      setMailError("Runtime is missing wallet mail connector methods.");
      return null;
    }
    if (!channelId || !leaseId) {
      setMailError("Channel ID and Lease ID are required.");
      return null;
    }
    if (mailOpSeq < 1) {
      setMailError("Sequence must be >= 1.");
      return null;
    }
    return { channelId, leaseId };
  };

  const saveMailAccount = async () => {
    if (!runtime.walletMailConfigureAccount) {
      setMailError("Runtime is missing mail account setup support.");
      return;
    }

    const accountEmail = mailSetupEmail.trim();
    if (!accountEmail || !accountEmail.includes("@")) {
      setMailError("Enter a valid account email.");
      return;
    }
    if (!mailSetupPassword.trim()) {
      setMailError("Enter the account password or app password.");
      return;
    }
    if (!mailSetupImapHost.trim() || !mailSetupSmtpHost.trim()) {
      setMailError("IMAP and SMTP host values are required.");
      return;
    }
    if (mailSetupImapPort < 1 || mailSetupSmtpPort < 1) {
      setMailError("IMAP and SMTP ports must be greater than 0.");
      return;
    }

    setMailBusy(true);
    setMailError(null);
    try {
      const result: WalletMailConfigureAccountResult = await runtime.walletMailConfigureAccount({
        mailbox: mailSetupMailbox.trim() || "primary",
        accountEmail,
        authMode: "password",
        imapHost: mailSetupImapHost.trim(),
        imapPort: mailSetupImapPort,
        imapTlsMode: mailSetupImapTlsMode,
        smtpHost: mailSetupSmtpHost.trim(),
        smtpPort: mailSetupSmtpPort,
        smtpTlsMode: mailSetupSmtpTlsMode,
        imapUsername: mailSetupImapUsername.trim() || accountEmail,
        imapSecret: mailSetupPassword,
        smtpUsername: mailSetupSmtpUsername.trim() || accountEmail,
        smtpSecret: mailSetupPassword,
      });
      setMailSetupPassword("");
      setMailSetupMailbox(result.mailbox);
      setMailMailbox(result.mailbox);
      setMailResult(JSON.stringify(result, null, 2));
    } catch (error) {
      setMailError(error instanceof Error ? error.message : String(error));
    } finally {
      setMailBusy(false);
    }
  };

  const runMailListRecent = async () => {
    const context = validateMailContext(true);
    if (!context || !runtime.walletMailListRecent) return;
    setMailBusy(true);
    setMailError(null);
    try {
      const result: WalletMailListRecentResult = await runtime.walletMailListRecent({
        channelId: context.channelId,
        leaseId: context.leaseId,
        opSeq: mailOpSeq,
        mailbox: mailMailbox.trim() || "primary",
        limit: mailLimit,
      });
      setMailResult(JSON.stringify(result, null, 2));
      setMailOpSeq((value) => value + 1);
    } catch (error) {
      setMailError(error instanceof Error ? error.message : String(error));
    } finally {
      setMailBusy(false);
    }
  };

  const runMailReadLatest = async () => {
    const context = validateMailContext(true);
    if (!context || !runtime.walletMailReadLatest) return;
    setMailBusy(true);
    setMailError(null);
    try {
      const result: WalletMailReadLatestResult = await runtime.walletMailReadLatest({
        channelId: context.channelId,
        leaseId: context.leaseId,
        opSeq: mailOpSeq,
        mailbox: mailMailbox.trim() || "primary",
      });
      setMailResult(JSON.stringify(result, null, 2));
      setMailOpSeq((value) => value + 1);
    } catch (error) {
      setMailError(error instanceof Error ? error.message : String(error));
    } finally {
      setMailBusy(false);
    }
  };

  const runMailIntent = async () => {
    const context = validateMailContext(false);
    if (!context) return;
    if (!runtime.walletMailHandleIntent) {
      setMailError("Runtime is missing assistant mail intent method.");
      return;
    }
    if (!mailIntentQuery.trim()) {
      setMailError("Provide a mail request, for example: 'Read me the last email I received'.");
      return;
    }

    setMailBusy(true);
    setMailError(null);
    try {
      const requiresApproval = intentLikelyRequiresApproval(mailIntentQuery);
      let approvalArtifactJson = mailApprovalArtifactJson.trim() || undefined;
      if (requiresApproval && !approvalArtifactJson && mailAutoGenerateApproval) {
        if (!runtime.walletMailGenerateApprovalArtifact) {
          throw new Error(
            "Runtime is missing approval artifact generation. Paste artifact JSON manually or enable runtime support."
          );
        }
        const generated: WalletMailApprovalArtifactResult =
          await runtime.walletMailGenerateApprovalArtifact({
            channelId: context.channelId,
            leaseId: context.leaseId,
            opSeq: mailOpSeq,
            query: mailIntentQuery.trim(),
            mailbox: mailMailbox.trim() || "primary",
            ttlSeconds: mailApprovalTtlSeconds,
          });
        approvalArtifactJson = generated.approvalArtifactJson;
        setMailApprovalArtifactJson(generated.approvalArtifactJson);
      }

      const result: WalletMailIntentResult = await runtime.walletMailHandleIntent({
        channelId: context.channelId,
        leaseId: context.leaseId,
        opSeq: mailOpSeq,
        query: mailIntentQuery.trim(),
        mailbox: mailMailbox.trim() || "primary",
        listLimit: mailLimit,
        approvalArtifactJson,
      });
      setMailResult(JSON.stringify(result, null, 2));
      if (result.executed) {
        setMailOpSeq(Math.max(1, result.nextOpSeq));
      }
    } catch (error) {
      setMailError(error instanceof Error ? error.message : String(error));
    } finally {
      setMailBusy(false);
    }
  };

  const runGenerateMailApprovalArtifact = async () => {
    const context = validateMailContext(false);
    if (!context) return;
    if (!runtime.walletMailGenerateApprovalArtifact) {
      setMailError("Runtime is missing approval artifact generation.");
      return;
    }
    if (!mailIntentQuery.trim()) {
      setMailError("Provide a write mail request before generating an approval artifact.");
      return;
    }
    if (!intentLikelyRequiresApproval(mailIntentQuery)) {
      setMailError("Approval artifacts are only needed for write intents (delete spam / reply).");
      return;
    }

    setMailBusy(true);
    setMailError(null);
    try {
      const generated: WalletMailApprovalArtifactResult =
        await runtime.walletMailGenerateApprovalArtifact({
          channelId: context.channelId,
          leaseId: context.leaseId,
          opSeq: mailOpSeq,
          query: mailIntentQuery.trim(),
          mailbox: mailMailbox.trim() || "primary",
          ttlSeconds: mailApprovalTtlSeconds,
        });
      setMailApprovalArtifactJson(generated.approvalArtifactJson);
      setMailResult(JSON.stringify(generated, null, 2));
    } catch (error) {
      setMailError(error instanceof Error ? error.message : String(error));
    } finally {
      setMailBusy(false);
    }
  };

  return (
    <div className="connectors-view">
      <header className="connectors-header">
        <div className="connectors-title-wrap">
          <h1>Integrations</h1>
          <p>
            Connector-first surface for external apps. Secrets stay in Vault; agents receive bounded
            execution rights.
          </p>
        </div>
        <div className="connectors-filters">
          <input
            className="connectors-search"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search connectors..."
            aria-label="Search connectors"
          />
          <div className="connectors-status-row">
            {(["all", "connected", "needs_auth", "degraded", "disabled"] as const).map((value) => (
              <button
                key={value}
                type="button"
                className={`status-chip ${statusFilter === value ? "active" : ""}`}
                onClick={() => setStatusFilter(value)}
              >
                {value === "all" ? "All" : statusLabel(value)}
              </button>
            ))}
          </div>
        </div>
      </header>

      <section className="connectors-grid">
        {filtered.map((connector) => (
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
              <span className={`connector-status status-${connector.status}`}>
                {statusLabel(connector.status)}
              </span>
            </div>

            <p className="connector-description">{connector.description}</p>

            <div className="connector-meta">
              <span>Auth: {connector.authMode}</span>
              {connector.lastSyncAtUtc ? <span>Last sync: {connector.lastSyncAtUtc}</span> : null}
            </div>

            <div className="connector-scopes">
              {connector.scopes.map((scope) => (
                <code key={scope}>{scope}</code>
              ))}
            </div>

            {connector.notes ? <p className="connector-notes">{connector.notes}</p> : null}

            {connector.id === "mail.primary" ? (
              <div className="connector-test-panel">
                <div className="mail-account-setup">
                  <div className="mail-setup-head">
                    <h3>Quick Add Mail Account</h3>
                    <p>
                      Enter the same account details you would use in iOS Mail or Outlook.
                      Credentials are stored as vault aliases.
                    </p>
                  </div>
                  <div className="mail-account-grid">
                    <label>
                      Provider
                      <select
                        value={mailProviderPreset}
                        onChange={(event) =>
                          setMailProviderPreset(event.target.value as MailProviderPresetKey)
                        }
                      >
                        <option value="auto">Auto-detect from email</option>
                        <option value="gmail">Gmail</option>
                        <option value="outlook">Outlook / Microsoft</option>
                        <option value="yahoo">Yahoo</option>
                        <option value="aol">AOL</option>
                        <option value="custom">Custom IMAP/SMTP</option>
                      </select>
                    </label>
                    <label>
                      Email
                      <input
                        value={mailSetupEmail}
                        onChange={(event) => setMailSetupEmail(event.target.value)}
                        placeholder="you@example.com"
                        autoComplete="username"
                      />
                    </label>
                    <label>
                      Password / App Password
                      <input
                        type="password"
                        value={mailSetupPassword}
                        onChange={(event) => setMailSetupPassword(event.target.value)}
                        placeholder="Required"
                        autoComplete="current-password"
                      />
                    </label>
                    <label>
                      Mailbox label
                      <input
                        value={mailSetupMailbox}
                        onChange={(event) => setMailSetupMailbox(event.target.value)}
                        placeholder="primary"
                      />
                    </label>
                  </div>
                  <p className="mail-provider-hint">
                    {effectivePreset
                      ? `${effectivePreset.label}: ${effectivePreset.imapHost}:${effectivePreset.imapPort} (${effectivePreset.imapTlsMode.toUpperCase()}) and ${effectivePreset.smtpHost}:${effectivePreset.smtpPort} (${effectivePreset.smtpTlsMode.toUpperCase()}). ${effectivePreset.note}`
                      : "Custom mode: enter your provider's IMAP/SMTP host, port, and TLS mode in Advanced settings."}
                  </p>
                  <div className="mail-setup-actions">
                    <button
                      type="button"
                      className="btn-primary"
                      onClick={saveMailAccount}
                      disabled={mailBusy || !mailSetupRuntimeReady}
                    >
                      Save Mail Account
                    </button>
                    <button
                      type="button"
                      className="btn-secondary"
                      onClick={() => setMailSetupAdvancedOpen((value) => !value)}
                    >
                      {mailSetupAdvancedOpen ? "Hide Advanced Settings" : "Show Advanced Settings"}
                    </button>
                  </div>
                  {mailSetupAdvancedOpen ? (
                    <div className="mail-account-grid advanced">
                      <label>
                        IMAP host
                        <input
                          value={mailSetupImapHost}
                          onChange={(event) => setMailSetupImapHost(event.target.value)}
                          placeholder="imap.example.com"
                        />
                      </label>
                      <label>
                        IMAP port
                        <input
                          type="number"
                          min={1}
                          max={65535}
                          value={mailSetupImapPort}
                          onChange={(event) =>
                            setMailSetupImapPort(Math.max(1, Number(event.target.value) || 1))
                          }
                        />
                      </label>
                      <label>
                        IMAP TLS
                        <select
                          value={mailSetupImapTlsMode}
                          onChange={(event) =>
                            setMailSetupImapTlsMode(event.target.value as MailTlsMode)
                          }
                        >
                          <option value="tls">TLS</option>
                          <option value="starttls">STARTTLS</option>
                          <option value="plaintext">Plaintext (dev only)</option>
                        </select>
                      </label>
                      <label>
                        IMAP username
                        <input
                          value={mailSetupImapUsername}
                          onChange={(event) => setMailSetupImapUsername(event.target.value)}
                          placeholder={mailSetupEmail || "you@example.com"}
                        />
                      </label>
                      <label>
                        SMTP host
                        <input
                          value={mailSetupSmtpHost}
                          onChange={(event) => setMailSetupSmtpHost(event.target.value)}
                          placeholder="smtp.example.com"
                        />
                      </label>
                      <label>
                        SMTP port
                        <input
                          type="number"
                          min={1}
                          max={65535}
                          value={mailSetupSmtpPort}
                          onChange={(event) =>
                            setMailSetupSmtpPort(Math.max(1, Number(event.target.value) || 1))
                          }
                        />
                      </label>
                      <label>
                        SMTP TLS
                        <select
                          value={mailSetupSmtpTlsMode}
                          onChange={(event) =>
                            setMailSetupSmtpTlsMode(event.target.value as MailTlsMode)
                          }
                        >
                          <option value="starttls">STARTTLS</option>
                          <option value="tls">TLS</option>
                          <option value="plaintext">Plaintext (dev only)</option>
                        </select>
                      </label>
                      <label>
                        SMTP username
                        <input
                          value={mailSetupSmtpUsername}
                          onChange={(event) => setMailSetupSmtpUsername(event.target.value)}
                          placeholder={mailSetupEmail || "you@example.com"}
                        />
                      </label>
                    </div>
                  ) : null}
                </div>

                <button
                  type="button"
                  className="btn-secondary"
                  onClick={() => setShowOperatorTools((value) => !value)}
                >
                  {showOperatorTools ? "Hide Operator Tools" : "Show Operator Tools"}
                </button>

                {showOperatorTools ? (
                  <>
                    {mailAssistantRuntimeReady ? (
                      <div className="connector-intent-panel">
                        <label>
                          Assistant mail request
                          <textarea
                            value={mailIntentQuery}
                            onChange={(event) => setMailIntentQuery(event.target.value)}
                            placeholder="Read me the last email I received."
                            rows={3}
                          />
                        </label>
                        <label>
                          Approval artifact JSON (auto-generated for delete/reply when enabled)
                          <textarea
                            value={mailApprovalArtifactJson}
                            onChange={(event) => setMailApprovalArtifactJson(event.target.value)}
                            placeholder='{"interception":{...},"decision":"approved_by_human","approval_token":{...}}'
                            rows={3}
                          />
                        </label>
                        <label className="connector-intent-checkbox">
                          <input
                            type="checkbox"
                            checked={mailAutoGenerateApproval}
                            onChange={(event) => setMailAutoGenerateApproval(event.target.checked)}
                          />
                          Auto-generate approval artifact for write intents
                        </label>
                        <label>
                          Approval TTL seconds
                          <input
                            type="number"
                            min={30}
                            max={3600}
                            value={mailApprovalTtlSeconds}
                            onChange={(event) =>
                              setMailApprovalTtlSeconds(
                                Math.max(30, Math.min(3600, Number(event.target.value) || 30))
                              )
                            }
                            disabled={!mailApprovalRuntimeReady}
                          />
                        </label>
                        <button
                          type="button"
                          className="btn-secondary"
                          onClick={runGenerateMailApprovalArtifact}
                          disabled={mailBusy || !mailApprovalRuntimeReady}
                        >
                          Generate Approval Artifact
                        </button>
                        <button
                          type="button"
                          className="btn-primary"
                          onClick={runMailIntent}
                          disabled={mailBusy}
                        >
                          Run Assistant Intent
                        </button>
                      </div>
                    ) : null}
                    <div className="connector-test-grid">
                      <label>
                        Channel ID
                        <input
                          value={mailChannelId}
                          onChange={(event) => setMailChannelId(event.target.value)}
                          placeholder="32-byte hex channel id"
                        />
                      </label>
                      <label>
                        Lease ID
                        <input
                          value={mailLeaseId}
                          onChange={(event) => setMailLeaseId(event.target.value)}
                          placeholder="32-byte hex lease id"
                        />
                      </label>
                      <label>
                        Mailbox
                        <input
                          value={mailMailbox}
                          onChange={(event) => setMailMailbox(event.target.value)}
                          placeholder="primary"
                        />
                      </label>
                      <label>
                        Sequence
                        <input
                          type="number"
                          min={1}
                          value={mailOpSeq}
                          onChange={(event) =>
                            setMailOpSeq(Math.max(1, Number(event.target.value) || 1))
                          }
                        />
                      </label>
                      <label>
                        List limit
                        <input
                          type="number"
                          min={1}
                          max={20}
                          value={mailLimit}
                          onChange={(event) =>
                            setMailLimit(Math.max(1, Math.min(20, Number(event.target.value) || 1)))
                          }
                        />
                      </label>
                    </div>
                    <div className="connector-test-actions">
                      <button
                        type="button"
                        className="btn-secondary"
                        onClick={runMailListRecent}
                        disabled={mailBusy || !mailConnectorRuntimeReady}
                      >
                        List Recent (tx)
                      </button>
                      <button
                        type="button"
                        className="btn-secondary"
                        onClick={runMailReadLatest}
                        disabled={mailBusy || !mailConnectorRuntimeReady}
                      >
                        Read Latest (tx)
                      </button>
                    </div>
                  </>
                ) : null}
                {mailError ? <p className="connector-test-error">{mailError}</p> : null}
                {mailResult ? <pre className="connector-test-result">{mailResult}</pre> : null}
              </div>
            ) : null}

            <div className="connector-actions">
              <button type="button" className="btn-secondary">
                Configure
              </button>
              <button
                type="button"
                className="btn-primary"
                disabled={connector.status === "disabled"}
              >
                {connector.status === "connected" ? "Manage Session" : "Connect"}
              </button>
            </div>
          </article>
        ))}
      </section>
    </div>
  );
}
