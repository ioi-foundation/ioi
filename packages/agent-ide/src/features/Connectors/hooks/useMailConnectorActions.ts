import type { Dispatch, SetStateAction } from "react";
import { useEffect, useState } from "react";
import type {
  AgentWorkbenchRuntime,
  WalletMailConfigureAccountResult,
  WalletMailConfiguredAccount,
  WalletMailListRecentResult,
  WalletMailReadLatestResult,
} from "../../../runtime/agent-runtime";
import {
  buildConnectorApprovalMemoryRequest,
  parseShieldApprovalRequest,
  type ShieldApprovalRequest,
} from "../../../runtime/shield-approval";

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
  senderDisplayName?: string;
  defaultChannelIdHex?: string;
  defaultLeaseIdHex?: string;
  updatedAtMs: number;
}

export interface MailPendingRunApproval {
  kind: "shield_policy";
  actionId: "mail.read_latest" | "mail.list_recent";
  actionLabel: string;
  message: string;
  request: ShieldApprovalRequest;
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
    senderDisplayName: result.senderDisplayName,
    defaultChannelIdHex: undefined,
    defaultLeaseIdHex: undefined,
    updatedAtMs: result.updatedAtMs,
  });
  return next;
}

function normalizeConnectedMailAccount(
  account: WalletMailConfiguredAccount
): ConnectedMailAccount | null {
  const mailbox = account.mailbox.trim();
  const accountEmail = account.accountEmail.trim();
  if (!mailbox || !accountEmail) {
    return null;
  }
  return {
    mailbox,
    accountEmail,
    senderDisplayName: account.senderDisplayName?.trim() || undefined,
    defaultChannelIdHex: account.defaultChannelIdHex?.trim() || undefined,
    defaultLeaseIdHex: account.defaultLeaseIdHex?.trim() || undefined,
    updatedAtMs: account.updatedAtMs,
  };
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
  mailSetupSenderDisplayName: string;
  setMailSetupSenderDisplayName: Dispatch<SetStateAction<string>>;
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
  mailBusy: boolean;
  mailError: string | null;
  mailResult: string;
  mailLastRunSummary: string | null;
  mailLastRunDetails: string[];
  mailSetupNotice: string | null;
  connectedMailAccounts: ConnectedMailAccount[];
  mailConnectorRuntimeReady: boolean;
  mailSetupRuntimeReady: boolean;
  effectivePreset: MailProviderPreset | null;
  pendingRunApproval: MailPendingRunApproval | null;
  selectConfiguredAccount: (mailbox: string) => void;
  runMailListRecent: () => Promise<void>;
  runMailReadLatest: () => Promise<void>;
  approvePendingRun: () => Promise<void>;
  cancelPendingRun: () => void;
  saveMailAccount: () => Promise<void>;
}

export function useMailConnectorActions(
  runtime: AgentWorkbenchRuntime,
  options?: UseMailConnectorActionsOptions
): MailConnectorActionsState {
  const [mailProviderPreset, setMailProviderPreset] = useState<MailProviderPresetKey>("auto");
  const [mailSetupEmail, setMailSetupEmail] = useState("");
  const [mailSetupPassword, setMailSetupPassword] = useState("");
  const [mailSetupMailbox, setMailSetupMailbox] = useState("primary");
  const [mailSetupSenderDisplayName, setMailSetupSenderDisplayName] = useState("");
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
  const [mailBusy, setMailBusy] = useState(false);
  const [mailError, setMailError] = useState<string | null>(null);
  const [mailResult, setMailResult] = useState<string>("");
  const [mailLastRunSummary, setMailLastRunSummary] = useState<string | null>(null);
  const [mailLastRunDetails, setMailLastRunDetails] = useState<string[]>([]);
  const [mailSetupNotice, setMailSetupNotice] = useState<string | null>(null);
  const [connectedMailAccounts, setConnectedMailAccounts] = useState<ConnectedMailAccount[]>([]);
  const [pendingRunApproval, setPendingRunApproval] =
    useState<MailPendingRunApproval | null>(null);

  const mailConnectorRuntimeReady = Boolean(
    runtime.walletMailReadLatest && runtime.walletMailListRecent
  );
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

  useEffect(() => {
    if (!runtime.walletMailListAccounts) {
      return;
    }

    let cancelled = false;
    runtime
      .walletMailListAccounts()
      .then((accounts) => {
        if (cancelled) {
          return;
        }
        const hydrated = (Array.isArray(accounts) ? accounts : [])
          .map(normalizeConnectedMailAccount)
          .filter((account): account is ConnectedMailAccount => account !== null);
        if (hydrated.length === 0) {
          return;
        }
        setConnectedMailAccounts(hydrated);
        const selectedMailbox = mailMailbox.trim() || "primary";
        if (!hydrated.some((account) => account.mailbox === selectedMailbox)) {
          const primaryAccount = hydrated[0];
          setMailSetupMailbox(primaryAccount.mailbox);
          setMailMailbox(primaryAccount.mailbox);
          setMailSetupEmail(primaryAccount.accountEmail);
          setMailSetupSenderDisplayName(primaryAccount.senderDisplayName ?? "");
        }
      })
      .catch(() => {
        // Leave Mail in setup-first mode if hydrated account discovery is unavailable.
      });

    return () => {
      cancelled = true;
    };
  }, [runtime, mailMailbox]);

  useEffect(() => {
    const selectedMailbox = mailMailbox.trim() || "primary";
    const selectedAccount = connectedMailAccounts.find(
      (account) => account.mailbox === selectedMailbox
    );
    if (!selectedAccount) {
      return;
    }
    if (!mailChannelId.trim() && selectedAccount.defaultChannelIdHex) {
      setMailChannelId(selectedAccount.defaultChannelIdHex);
    }
    if (!mailLeaseId.trim() && selectedAccount.defaultLeaseIdHex) {
      setMailLeaseId(selectedAccount.defaultLeaseIdHex);
    }
  }, [connectedMailAccounts, mailMailbox, mailChannelId, mailLeaseId]);

  const validateMailContext = (requireConnectorRuntime: boolean) => {
    const selectedMailbox = mailMailbox.trim() || "primary";
    const selectedAccount = connectedMailAccounts.find(
      (account) => account.mailbox === selectedMailbox
    );
    const channelId =
      mailChannelId.trim() || selectedAccount?.defaultChannelIdHex?.trim() || "";
    const leaseId =
      mailLeaseId.trim() || selectedAccount?.defaultLeaseIdHex?.trim() || "";
    if (requireConnectorRuntime && !mailConnectorRuntimeReady) {
      setMailError("Runtime is missing wallet mail connector methods.");
      return null;
    }
    if (!mailChannelId.trim() && channelId) {
      setMailChannelId(channelId);
    }
    if (!mailLeaseId.trim() && leaseId) {
      setMailLeaseId(leaseId);
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
        senderDisplayName: mailSetupSenderDisplayName.trim() || undefined,
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
      setMailSetupSenderDisplayName(result.senderDisplayName ?? "");
      setMailMailbox(result.mailbox);
      setMailSetupNotice(
        result.senderDisplayName
          ? `Connected ${result.accountEmail} as ${result.senderDisplayName} to mailbox "${result.mailbox}".`
          : `Connected ${result.accountEmail} to mailbox "${result.mailbox}".`
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

  const rememberShieldApproval = async (approvalRequest: ShieldApprovalRequest) => {
    if (!runtime.rememberConnectorApproval) {
      return;
    }
    const input = buildConnectorApprovalMemoryRequest(
      approvalRequest,
      "Mail connector panel"
    );
    if (!input) {
      return;
    }
    try {
      await runtime.rememberConnectorApproval(input);
    } catch (error) {
      console.warn("Failed to remember Shield approval for Mail connector:", error);
    }
  };

  const runMailListRecent = async (
    options?: {
      shieldApproved?: boolean;
    }
  ) => {
    const context = validateMailContext(true);
    if (!context || !runtime.walletMailListRecent) return;
    setMailBusy(true);
    setMailError(null);
    setMailLastRunSummary(null);
    setMailLastRunDetails([]);
    setPendingRunApproval(null);
    try {
      const result: WalletMailListRecentResult = await runtime.walletMailListRecent({
        channelId: context.channelId,
        leaseId: context.leaseId,
        opSeq: mailOpSeq,
        mailbox: mailMailbox.trim() || "primary",
        limit: mailLimit,
        shieldApproved: options?.shieldApproved ?? false,
      });
      setMailResult(JSON.stringify(result, null, 2));
      setMailLastRunSummary(
        `Listed ${result.messages.length} recent message${
          result.messages.length === 1 ? "" : "s"
        } from mailbox "${result.mailbox}".`
      );
      setMailLastRunDetails(
        result.messages
          .slice(0, 3)
          .map((message) => `${message.subject} — ${message.from}`)
      );
      setMailOpSeq((value) => value + 1);
    } catch (error) {
      const approvalRequest = parseShieldApprovalRequest(error);
      if (approvalRequest && !(options?.shieldApproved ?? false)) {
        setPendingRunApproval({
          kind: "shield_policy",
          actionId: "mail.list_recent",
          actionLabel: approvalRequest.actionLabel,
          message: approvalRequest.message,
          request: approvalRequest,
        });
        return;
      }
      setMailError(error instanceof Error ? error.message : String(error));
    } finally {
      setMailBusy(false);
    }
  };

  const runMailReadLatest = async (
    options?: {
      shieldApproved?: boolean;
    }
  ) => {
    const context = validateMailContext(true);
    if (!context || !runtime.walletMailReadLatest) return;
    setMailBusy(true);
    setMailError(null);
    setMailLastRunSummary(null);
    setMailLastRunDetails([]);
    setPendingRunApproval(null);
    try {
      const result: WalletMailReadLatestResult = await runtime.walletMailReadLatest({
        channelId: context.channelId,
        leaseId: context.leaseId,
        opSeq: mailOpSeq,
        mailbox: mailMailbox.trim() || "primary",
        shieldApproved: options?.shieldApproved ?? false,
      });
      setMailResult(JSON.stringify(result, null, 2));
      setMailLastRunSummary(
        `Read the latest message from mailbox "${result.mailbox}".`
      );
      setMailLastRunDetails([
        `${result.message.subject} — ${result.message.from}`,
        result.message.preview,
      ]);
      setMailOpSeq((value) => value + 1);
    } catch (error) {
      const approvalRequest = parseShieldApprovalRequest(error);
      if (approvalRequest && !(options?.shieldApproved ?? false)) {
        setPendingRunApproval({
          kind: "shield_policy",
          actionId: "mail.read_latest",
          actionLabel: approvalRequest.actionLabel,
          message: approvalRequest.message,
          request: approvalRequest,
        });
        return;
      }
      setMailError(error instanceof Error ? error.message : String(error));
    } finally {
      setMailBusy(false);
    }
  };

  const approvePendingRun = async () => {
    if (!pendingRunApproval) {
      return;
    }
    await rememberShieldApproval(pendingRunApproval.request);
    if (pendingRunApproval.actionId === "mail.list_recent") {
      await runMailListRecent({ shieldApproved: true });
      return;
    }
    await runMailReadLatest({ shieldApproved: true });
  };

  const cancelPendingRun = () => {
    setPendingRunApproval(null);
    setMailError(null);
  };

  const selectConfiguredAccount = (mailbox: string) => {
    const normalized = mailbox.trim();
    if (!normalized) return;
    const account = connectedMailAccounts.find((candidate) => candidate.mailbox === normalized);
    setMailSetupMailbox(normalized);
    setMailMailbox(normalized);
    if (account) {
      setMailSetupEmail(account.accountEmail);
      setMailSetupSenderDisplayName(account.senderDisplayName ?? "");
      if (account.defaultChannelIdHex) {
        setMailChannelId(account.defaultChannelIdHex);
      }
      if (account.defaultLeaseIdHex) {
        setMailLeaseId(account.defaultLeaseIdHex);
      }
    }
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
    mailSetupSenderDisplayName,
    setMailSetupSenderDisplayName,
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
    mailBusy,
    mailError,
    mailResult,
    mailLastRunSummary,
    mailLastRunDetails,
    mailSetupNotice,
    connectedMailAccounts,
    mailConnectorRuntimeReady,
    mailSetupRuntimeReady,
    effectivePreset,
    pendingRunApproval,
    selectConfiguredAccount,
    runMailListRecent: () => runMailListRecent(),
    runMailReadLatest: () => runMailReadLatest(),
    approvePendingRun,
    cancelPendingRun,
    saveMailAccount,
  };
}
