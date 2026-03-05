import type { Dispatch, SetStateAction } from "react";
import { useEffect, useState } from "react";
import type {
  AgentRuntime,
  WalletMailApprovalArtifactResult,
  WalletMailConfigureAccountResult,
  WalletMailIntentResult,
  WalletMailListRecentResult,
  WalletMailReadLatestResult,
} from "../../../runtime/agent-runtime";

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

export type MailProviderPresetKey =
  | "auto"
  | "gmail"
  | "outlook"
  | "yahoo"
  | "aol"
  | "custom";
export type MailTlsMode = "plaintext" | "starttls" | "tls";
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

export interface ConnectedMailAccount {
  mailbox: string;
  accountEmail: string;
  updatedAtMs: number;
}

interface UseMailConnectorActionsOptions {
  onAccountConfigured?: (result: WalletMailConfigureAccountResult) => void;
}

function upsertConnectedMailAccount(
  accounts: ConnectedMailAccount[],
  result: WalletMailConfigureAccountResult
): ConnectedMailAccount[] {
  const next = accounts.filter((account) => account.mailbox !== result.mailbox);
  next.unshift({
    mailbox: result.mailbox,
    accountEmail: result.accountEmail,
    updatedAtMs: result.updatedAtMs,
  });
  return next;
}

export interface MailConnectorActionsState {
  mailProviderPreset: MailProviderPresetKey;
  setMailProviderPreset: Dispatch<SetStateAction<MailProviderPresetKey>>;
  mailSetupEmail: string;
  setMailSetupEmail: Dispatch<SetStateAction<string>>;
  mailSetupPassword: string;
  setMailSetupPassword: Dispatch<SetStateAction<string>>;
  mailSetupMailbox: string;
  setMailSetupMailbox: Dispatch<SetStateAction<string>>;
  mailSetupImapHost: string;
  setMailSetupImapHost: Dispatch<SetStateAction<string>>;
  mailSetupImapPort: number;
  setMailSetupImapPort: Dispatch<SetStateAction<number>>;
  mailSetupImapTlsMode: MailTlsMode;
  setMailSetupImapTlsMode: Dispatch<SetStateAction<MailTlsMode>>;
  mailSetupSmtpHost: string;
  setMailSetupSmtpHost: Dispatch<SetStateAction<string>>;
  mailSetupSmtpPort: number;
  setMailSetupSmtpPort: Dispatch<SetStateAction<number>>;
  mailSetupSmtpTlsMode: MailTlsMode;
  setMailSetupSmtpTlsMode: Dispatch<SetStateAction<MailTlsMode>>;
  mailSetupImapUsername: string;
  setMailSetupImapUsername: Dispatch<SetStateAction<string>>;
  mailSetupSmtpUsername: string;
  setMailSetupSmtpUsername: Dispatch<SetStateAction<string>>;
  mailSetupAdvancedOpen: boolean;
  setMailSetupAdvancedOpen: Dispatch<SetStateAction<boolean>>;
  showOperatorTools: boolean;
  setShowOperatorTools: Dispatch<SetStateAction<boolean>>;
  mailChannelId: string;
  setMailChannelId: Dispatch<SetStateAction<string>>;
  mailLeaseId: string;
  setMailLeaseId: Dispatch<SetStateAction<string>>;
  mailMailbox: string;
  setMailMailbox: Dispatch<SetStateAction<string>>;
  mailLimit: number;
  setMailLimit: Dispatch<SetStateAction<number>>;
  mailOpSeq: number;
  setMailOpSeq: Dispatch<SetStateAction<number>>;
  mailIntentQuery: string;
  setMailIntentQuery: Dispatch<SetStateAction<string>>;
  mailApprovalArtifactJson: string;
  setMailApprovalArtifactJson: Dispatch<SetStateAction<string>>;
  mailApprovalTtlSeconds: number;
  setMailApprovalTtlSeconds: Dispatch<SetStateAction<number>>;
  mailAutoGenerateApproval: boolean;
  setMailAutoGenerateApproval: Dispatch<SetStateAction<boolean>>;
  mailBusy: boolean;
  mailError: string | null;
  mailResult: string;
  mailSetupNotice: string | null;
  connectedMailAccounts: ConnectedMailAccount[];
  mailConnectorRuntimeReady: boolean;
  mailAssistantRuntimeReady: boolean;
  mailApprovalRuntimeReady: boolean;
  mailSetupRuntimeReady: boolean;
  effectivePreset: MailProviderPreset | null;
  selectConfiguredAccount: (mailbox: string) => void;
  runMailListRecent: () => Promise<void>;
  runMailReadLatest: () => Promise<void>;
  runMailIntent: () => Promise<void>;
  runGenerateMailApprovalArtifact: () => Promise<void>;
  saveMailAccount: () => Promise<void>;
}

export function useMailConnectorActions(
  runtime: AgentRuntime,
  options?: UseMailConnectorActionsOptions
): MailConnectorActionsState {
  const [mailProviderPreset, setMailProviderPreset] = useState<MailProviderPresetKey>("auto");
  const [mailSetupEmail, setMailSetupEmail] = useState("");
  const [mailSetupPassword, setMailSetupPassword] = useState("");
  const [mailSetupMailbox, setMailSetupMailbox] = useState("primary");
  const [mailSetupImapHost, setMailSetupImapHost] = useState("imap.gmail.com");
  const [mailSetupImapPort, setMailSetupImapPort] = useState(993);
  const [mailSetupImapTlsMode, setMailSetupImapTlsMode] = useState<MailTlsMode>("tls");
  const [mailSetupSmtpHost, setMailSetupSmtpHost] = useState("smtp.gmail.com");
  const [mailSetupSmtpPort, setMailSetupSmtpPort] = useState(587);
  const [mailSetupSmtpTlsMode, setMailSetupSmtpTlsMode] =
    useState<MailTlsMode>("starttls");
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
  const [mailSetupNotice, setMailSetupNotice] = useState<string | null>(null);
  const [connectedMailAccounts, setConnectedMailAccounts] = useState<ConnectedMailAccount[]>([]);

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
    setMailSetupNotice(null);
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
      setConnectedMailAccounts((accounts) => upsertConnectedMailAccount(accounts, result));
      setMailSetupPassword("");
      setMailSetupMailbox(result.mailbox);
      setMailMailbox(result.mailbox);
      setMailSetupNotice(
        `Connected ${result.accountEmail} to mailbox "${result.mailbox}".`
      );
      setMailResult(JSON.stringify(result, null, 2));
      options?.onAccountConfigured?.(result);
    } catch (error) {
      setMailSetupNotice(null);
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

  const selectConfiguredAccount = (mailbox: string) => {
    const normalized = mailbox.trim();
    if (!normalized) return;
    setMailSetupMailbox(normalized);
    setMailMailbox(normalized);
  };

  return {
    mailProviderPreset,
    setMailProviderPreset,
    mailSetupEmail,
    setMailSetupEmail,
    mailSetupPassword,
    setMailSetupPassword,
    mailSetupMailbox,
    setMailSetupMailbox,
    mailSetupImapHost,
    setMailSetupImapHost,
    mailSetupImapPort,
    setMailSetupImapPort,
    mailSetupImapTlsMode,
    setMailSetupImapTlsMode,
    mailSetupSmtpHost,
    setMailSetupSmtpHost,
    mailSetupSmtpPort,
    setMailSetupSmtpPort,
    mailSetupSmtpTlsMode,
    setMailSetupSmtpTlsMode,
    mailSetupImapUsername,
    setMailSetupImapUsername,
    mailSetupSmtpUsername,
    setMailSetupSmtpUsername,
    mailSetupAdvancedOpen,
    setMailSetupAdvancedOpen,
    showOperatorTools,
    setShowOperatorTools,
    mailChannelId,
    setMailChannelId,
    mailLeaseId,
    setMailLeaseId,
    mailMailbox,
    setMailMailbox,
    mailLimit,
    setMailLimit,
    mailOpSeq,
    setMailOpSeq,
    mailIntentQuery,
    setMailIntentQuery,
    mailApprovalArtifactJson,
    setMailApprovalArtifactJson,
    mailApprovalTtlSeconds,
    setMailApprovalTtlSeconds,
    mailAutoGenerateApproval,
    setMailAutoGenerateApproval,
    mailBusy,
    mailError,
    mailResult,
    mailSetupNotice,
    connectedMailAccounts,
    mailConnectorRuntimeReady,
    mailAssistantRuntimeReady,
    mailApprovalRuntimeReady,
    mailSetupRuntimeReady,
    effectivePreset,
    selectConfiguredAccount,
    runMailListRecent,
    runMailReadLatest,
    runMailIntent,
    runGenerateMailApprovalArtifact,
    saveMailAccount,
  };
}
