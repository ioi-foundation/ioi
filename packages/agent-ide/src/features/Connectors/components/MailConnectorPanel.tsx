import { useCallback, useMemo, useRef, useState } from "react";
import {
  ConnectorActionPreviewStage,
  ConnectorActionUnlockModal,
} from "./ConnectorUnlockSurface";
import {
  ConnectorActionWorkbench,
  ConnectorExecutionMeta,
  ConnectorInlineResultCard,
} from "./ConnectorExecutionWorkbench";
import { WorkspaceModal } from "./googleWorkspaceConnectorPanelParts";
import { getConnectorFocusedFormRecommendation } from "./connectorActionPatterns";
import type {
  MailConnectorActionsState,
  MailProviderPresetKey,
  MailTlsMode,
} from "../hooks/useMailConnectorActions";

interface MailConnectorPanelProps {
  mail: MailConnectorActionsState;
}

type MailWorkbenchAction = {
  id: "mail.read_latest" | "mail.list_recent";
  title: string;
  description: string;
  kind: "read" | "workflow";
  summary: string;
  fields: Array<{ type: string }>;
  runLabel: string;
};

const MAIL_WORKBENCH_ACTIONS: MailWorkbenchAction[] = [
  {
    id: "mail.read_latest",
    title: "Read latest mail",
    description:
      "Pull the newest message from the selected mailbox once the delegated inbox is connected.",
    kind: "read",
    summary:
      "Best for proving a mailbox quickly with the smallest useful read flow.",
    fields: [
      { type: "text" },
      { type: "text" },
      { type: "text" },
      { type: "number" },
    ],
    runLabel: "Run latest-mail read",
  },
  {
    id: "mail.list_recent",
    title: "List recent mail",
    description:
      "Inspect the latest deliveries from the selected mailbox with a configurable read limit.",
    kind: "workflow",
    summary:
      "Best for triage and mailbox review when you want a short recent-message batch.",
    fields: [
      { type: "text" },
      { type: "text" },
      { type: "text" },
      { type: "number" },
      { type: "number" },
    ],
    runLabel: "Run recent-mail list",
  },
];

export function MailConnectorPanel({ mail }: MailConnectorPanelProps) {
  const [selectedPreviewActionId, setSelectedPreviewActionId] = useState<
    string | null
  >(null);
  const [selectedWorkbenchActionId, setSelectedWorkbenchActionId] = useState<
    MailWorkbenchAction["id"]
  >("mail.read_latest");
  const [focusedActionModalOpen, setFocusedActionModalOpen] = useState(false);
  const emailInputRef = useRef<HTMLInputElement | null>(null);
  const passwordInputRef = useRef<HTMLInputElement | null>(null);
  const connectButtonRef = useRef<HTMLButtonElement | null>(null);
  const previewActions = useMemo(
    () => [
      {
        id: "mail.read_latest",
        categoryLabel: "Mailbox task",
        title: "Read latest mail",
        description:
          "Connect one inbox so Autopilot can pull the newest message from the selected mailbox.",
        hint: "Unlock this action: jump to local inbox setup",
        ariaLabel: "Unlock Read latest mail. Open action setup details.",
      },
      {
        id: "mail.list_recent",
        categoryLabel: "Mailbox task",
        title: "List recent mail",
        description:
          "Attach an inbox first, then inspect the last few deliveries from a named mailbox.",
        hint: "Unlock this action: jump to local inbox setup",
        ariaLabel: "Unlock List recent mail. Open action setup details.",
      },
    ],
    [],
  );
  const selectedPreviewAction = useMemo(
    () =>
      previewActions.find((action) => action.id === selectedPreviewActionId) ??
      null,
    [previewActions, selectedPreviewActionId],
  );
  const focusMailSetupTarget = useCallback(() => {
    const target = !mail.mailSetupEmail.trim()
      ? emailInputRef.current
      : !mail.mailSetupPassword.trim()
        ? passwordInputRef.current
        : connectButtonRef.current;
    if (!target) {
      return;
    }
    requestAnimationFrame(() => {
      target.scrollIntoView({ behavior: "smooth", block: "center" });
      target.focus({ preventScroll: true });
    });
  }, [mail.mailSetupEmail, mail.mailSetupPassword]);
  const closeUnlockDrilldown = useCallback(() => {
    setSelectedPreviewActionId(null);
  }, []);
  const continueFromUnlockDrilldown = useCallback(() => {
    closeUnlockDrilldown();
    focusMailSetupTarget();
  }, [closeUnlockDrilldown, focusMailSetupTarget]);
  const unlockBlockerHeadline =
    "A connected inbox is still blocking this mailbox task.";
  const unlockBlockerDetail = selectedPreviewAction
    ? `${selectedPreviewAction.title} needs one configured mailbox before Autopilot can read or inspect mail from it.`
    : "Connect one inbox first so mailbox tasks have a real account to use.";
  const unlockProviderHint = mail.effectivePreset
    ? `${mail.effectivePreset.label} settings are already prepared from the current email. ${mail.effectivePreset.note}`
    : "Auto-detect will fill provider defaults from the email when it can. Custom mode keeps IMAP and SMTP fields available when you need them.";
  const selectedWorkbenchAction =
    MAIL_WORKBENCH_ACTIONS.find((action) => action.id === selectedWorkbenchActionId) ??
    MAIL_WORKBENCH_ACTIONS[0];
  const activeConnectedAccount = useMemo(
    () =>
      mail.connectedMailAccounts.find(
        (account) => account.mailbox === (mail.mailMailbox.trim() || "primary"),
      ) ?? null,
    [mail.connectedMailAccounts, mail.mailMailbox],
  );
  const mockRunContextReady = Boolean(
    activeConnectedAccount?.defaultChannelIdHex &&
      activeConnectedAccount?.defaultLeaseIdHex,
  );
  const focusedFormRecommendation = getConnectorFocusedFormRecommendation(
    selectedWorkbenchAction,
  );

  const renderMailTaskComposer = ({
    inModal = false,
  }: {
    inModal?: boolean;
  }) => (
    <div className="workspace-action-panel workspace-composer-card mail-task-composer">
      <div className="workspace-panel-heading-row">
        <div className="workspace-panel-heading">
          <span>{inModal ? "Focused form" : "Task composer"}</span>
          <strong>{selectedWorkbenchAction.title}</strong>
          <p>{selectedWorkbenchAction.summary}</p>
        </div>
        {!inModal ? (
          <button
            type="button"
            className={`btn-secondary workspace-focus-form-button ${
              focusedFormRecommendation.recommended ? "recommended" : ""
            }`}
            onClick={() => setFocusedActionModalOpen(true)}
          >
            {focusedFormRecommendation.buttonLabel}
          </button>
        ) : null}
      </div>

      <div className="workspace-action-summary">
        <span className={`workspace-action-kind kind-${selectedWorkbenchAction.kind}`}>
          {selectedWorkbenchAction.kind === "read" ? "Read" : "Workflow"}
        </span>
        <p>{selectedWorkbenchAction.description}</p>
        {focusedFormRecommendation.note ? (
          <p className="workspace-inline-note">{focusedFormRecommendation.note}</p>
        ) : null}
        {mockRunContextReady ? (
          <p
            className="workspace-inline-note workspace-inline-note-success"
            role="status"
            aria-live="polite"
          >
            Connected mailbox run context is ready. Channel and lease defaults were loaded
            for this task surface.
          </p>
        ) : null}
      </div>

      <div className="workspace-action-grid">
        <label className="workspace-field">
          Channel ID
          <input
            value={mail.mailChannelId}
            onChange={(event) => mail.setMailChannelId(event.target.value)}
            placeholder="32-byte hex channel id"
          />
          <span>Delegated channel for this mailbox task run.</span>
        </label>
        <label className="workspace-field">
          Lease ID
          <input
            value={mail.mailLeaseId}
            onChange={(event) => mail.setMailLeaseId(event.target.value)}
            placeholder="32-byte hex lease id"
          />
          <span>Lease guarding the current connector session.</span>
        </label>
        <label className="workspace-field">
          Mailbox
          <input
            value={mail.mailMailbox}
            onChange={(event) => mail.setMailMailbox(event.target.value)}
            placeholder="primary"
          />
          <span>Pick the connected mailbox to read from.</span>
        </label>
        <label className="workspace-field">
          Sequence
          <input
            type="number"
            min={1}
            value={mail.mailOpSeq}
            onChange={(event) =>
              mail.setMailOpSeq(Math.max(1, Number(event.target.value) || 1))
            }
          />
          <span>Monotonic operation sequence for the delegated run.</span>
        </label>
        {selectedWorkbenchAction.id === "mail.list_recent" ? (
          <label className="workspace-field">
            List limit
            <input
              type="number"
              min={1}
              max={20}
              value={mail.mailLimit}
              onChange={(event) =>
                mail.setMailLimit(
                  Math.max(1, Math.min(20, Number(event.target.value) || 1)),
                )
              }
            />
            <span>How many recent deliveries to include in this batch.</span>
          </label>
        ) : null}
      </div>

      <ConnectorExecutionMeta>
        <span>
          Active mailbox: <code>{mail.mailMailbox.trim() || "primary"}</code>
        </span>
        <span>
          Connected inboxes: <code>{mail.connectedMailAccounts.length}</code>
        </span>
      </ConnectorExecutionMeta>

      {mail.mailLastRunSummary ? (
        <ConnectorInlineResultCard
          summary={mail.mailLastRunSummary}
          details={mail.mailLastRunDetails}
        />
      ) : null}

      {mail.pendingRunApproval ? (
        <div className="workspace-approval-card">
          <div className="workspace-approval-card-head">
            <strong>Shield approval required</strong>
            <span>{mail.pendingRunApproval.actionLabel}</span>
          </div>
          <p>{mail.pendingRunApproval.message}</p>
          <div className="workspace-required-scopes">
            <code>{mail.pendingRunApproval.request.connectorId}</code>
            <code>{mail.pendingRunApproval.request.actionId}</code>
          </div>
          <div className="workspace-action-actions">
            <button
              type="button"
              className="btn-primary"
              onClick={() => {
                void mail.approvePendingRun();
              }}
              disabled={mail.mailBusy || !mail.mailConnectorRuntimeReady}
              aria-label={`Approve and run ${mail.pendingRunApproval.actionLabel}`}
            >
              Approve and run
            </button>
            <button
              type="button"
              className="btn-secondary"
              onClick={mail.cancelPendingRun}
              disabled={mail.mailBusy}
            >
              Cancel
            </button>
          </div>
        </div>
      ) : null}

      <div className="workspace-action-actions">
        <button
          type="button"
          className="btn-primary"
          onClick={() => {
            if (selectedWorkbenchAction.id === "mail.list_recent") {
              void mail.runMailListRecent();
              return;
            }
            void mail.runMailReadLatest();
          }}
          disabled={mail.mailBusy || !mail.mailConnectorRuntimeReady}
        >
          {mail.mailBusy ? "Running..." : selectedWorkbenchAction.runLabel}
        </button>
      </div>
    </div>
  );

  return (
    <div className="connector-test-panel">
      {mail.connectedMailAccounts.length === 0 ? (
        <ConnectorActionPreviewStage
          title="Connect an inbox to unlock mailbox tasks"
          summary="Start with one inbox. Once it is attached, Autopilot can read the newest message or inspect recent deliveries from that mailbox."
          statusLabel="Inbox required"
          actions={previewActions}
          onSelectAction={setSelectedPreviewActionId}
        />
      ) : null}

      <div className="mail-account-setup">
        <div className="mail-setup-head">
          <h3>Connect Mail Account</h3>
          <p>
            Add an inbox Autopilot can use. You can connect more than one account by using
            different mailbox names.
          </p>
        </div>
        <div className="mail-account-grid">
          <label>
            Provider
            <select
              value={mail.mailProviderPreset}
              onChange={(event) =>
                mail.setMailProviderPreset(event.target.value as MailProviderPresetKey)
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
              ref={emailInputRef}
              value={mail.mailSetupEmail}
              onChange={(event) => mail.setMailSetupEmail(event.target.value)}
              placeholder="you@example.com"
              autoComplete="username"
            />
          </label>
          <label>
            Password / App Password
            <input
              ref={passwordInputRef}
              type="password"
              value={mail.mailSetupPassword}
              onChange={(event) => mail.setMailSetupPassword(event.target.value)}
              placeholder="Required"
              autoComplete="current-password"
            />
          </label>
          <label>
            Send as name
            <input
              value={mail.mailSetupSenderDisplayName}
              onChange={(event) => mail.setMailSetupSenderDisplayName(event.target.value)}
              placeholder="Optional display name"
              autoComplete="name"
            />
          </label>
          <label>
            Mailbox name
            <input
              value={mail.mailSetupMailbox}
              onChange={(event) => mail.setMailSetupMailbox(event.target.value)}
              placeholder="primary"
            />
          </label>
        </div>
        <p className="mail-provider-hint">
          {mail.effectivePreset
            ? `${mail.effectivePreset.label} settings detected. ${mail.effectivePreset.note}`
            : "Custom mode: provide IMAP/SMTP details in Advanced settings."}
        </p>
        <div className="mail-setup-actions">
          <button
            type="button"
            className="btn-primary"
            ref={connectButtonRef}
            onClick={mail.saveMailAccount}
            disabled={mail.mailBusy || !mail.mailSetupRuntimeReady}
          >
            {mail.mailBusy ? "Connecting..." : "Connect Account"}
          </button>
          <button
            type="button"
            className="btn-secondary"
            onClick={() => mail.setMailSetupAdvancedOpen((value) => !value)}
          >
            {mail.mailSetupAdvancedOpen
              ? "Hide Advanced Server Settings"
              : "Show Advanced Server Settings"}
          </button>
        </div>
        {mail.mailSetupNotice ? <p className="connector-test-success">{mail.mailSetupNotice}</p> : null}
        {mail.connectedMailAccounts.length > 0 ? (
          <div className="mail-connected-accounts">
            <h4>Connected Accounts</h4>
            <ul>
              {mail.connectedMailAccounts.map((account) => {
                const isActive = mail.mailMailbox.trim() === account.mailbox;
                return (
                  <li key={account.mailbox}>
                    <div className="mail-connected-identity">
                      <strong>{account.accountEmail}</strong>
                      {account.senderDisplayName ? <span>send as {account.senderDisplayName}</span> : null}
                      <span>
                        mailbox: <code>{account.mailbox}</code>
                      </span>
                    </div>
                    <button
                      type="button"
                      className="btn-secondary"
                      onClick={() => mail.selectConfiguredAccount(account.mailbox)}
                      disabled={isActive}
                    >
                      {isActive ? "Active" : "Use"}
                    </button>
                  </li>
                );
              })}
            </ul>
          </div>
        ) : null}
        {mail.mailSetupAdvancedOpen ? (
          <div className="mail-account-grid advanced">
            <label>
              IMAP host
              <input
                value={mail.mailSetupImapHost}
                onChange={(event) => mail.setMailSetupImapHost(event.target.value)}
                placeholder="imap.example.com"
              />
            </label>
            <label>
              IMAP port
              <input
                type="number"
                min={1}
                max={65535}
                value={mail.mailSetupImapPort}
                onChange={(event) =>
                  mail.setMailSetupImapPort(Math.max(1, Number(event.target.value) || 1))
                }
              />
            </label>
            <label>
              IMAP TLS
              <select
                value={mail.mailSetupImapTlsMode}
                onChange={(event) =>
                  mail.setMailSetupImapTlsMode(event.target.value as MailTlsMode)
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
                value={mail.mailSetupImapUsername}
                onChange={(event) => mail.setMailSetupImapUsername(event.target.value)}
                placeholder={mail.mailSetupEmail || "you@example.com"}
              />
            </label>
            <label>
              SMTP host
              <input
                value={mail.mailSetupSmtpHost}
                onChange={(event) => mail.setMailSetupSmtpHost(event.target.value)}
                placeholder="smtp.example.com"
              />
            </label>
            <label>
              SMTP port
              <input
                type="number"
                min={1}
                max={65535}
                value={mail.mailSetupSmtpPort}
                onChange={(event) =>
                  mail.setMailSetupSmtpPort(Math.max(1, Number(event.target.value) || 1))
                }
              />
            </label>
            <label>
              SMTP TLS
              <select
                value={mail.mailSetupSmtpTlsMode}
                onChange={(event) =>
                  mail.setMailSetupSmtpTlsMode(event.target.value as MailTlsMode)
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
                value={mail.mailSetupSmtpUsername}
                onChange={(event) => mail.setMailSetupSmtpUsername(event.target.value)}
                placeholder={mail.mailSetupEmail || "you@example.com"}
              />
            </label>
          </div>
        ) : null}
      </div>

      {mail.connectedMailAccounts.length > 0 ? (
        <ConnectorActionWorkbench
          className="mail-task-workbench"
          title="Mailbox tasks"
          summary="Use the connected inboxes above for the most common read flows, then fall back to the lower-level tools only when you need to debug the underlying connector context."
          actionLabel={selectedWorkbenchAction.title}
          shortcuts={MAIL_WORKBENCH_ACTIONS.map((action) => (
            <button
              key={action.id}
              type="button"
              className={`workspace-featured-action ${
                selectedWorkbenchActionId === action.id ? "active" : ""
              }`}
              onClick={() => setSelectedWorkbenchActionId(action.id)}
            >
              {action.title}
            </button>
          ))}
          browser={
            <div className="workspace-auth-stage">
              <div className="workspace-auth-stage-head">
                <div>
                  <span className="workspace-hero-kicker">Mailbox tasks</span>
                  <h4>Run connected Mail actions</h4>
                  <p>
                    Use the connected inboxes above for the most common read
                    flows, then fall back to the lower-level tools only when you
                    need to debug the underlying connector context.
                  </p>
                </div>
                <span className="workspace-health-pill tone-ready">
                  Inboxes ready
                </span>
              </div>

              <div className="workspace-capability-grid">
                {MAIL_WORKBENCH_ACTIONS.map((action) => (
                  <button
                    key={action.id}
                    type="button"
                    className={`workspace-featured-action ${
                      selectedWorkbenchActionId === action.id ? "active" : ""
                    }`}
                    onClick={() => setSelectedWorkbenchActionId(action.id)}
                  >
                    <strong>{action.title}</strong>
                    <p>{action.description}</p>
                  </button>
                ))}
              </div>
            </div>
          }
          sidebar={renderMailTaskComposer({ inModal: false })}
        />
      ) : null}

      <button
        type="button"
        className="btn-secondary"
        onClick={() => mail.setShowOperatorTools((value) => !value)}
      >
        {mail.showOperatorTools ? "Hide Developer Tools" : "Show Developer Tools"}
      </button>

      {mail.showOperatorTools ? (
        <>
          <div className="connector-test-grid">
            <label>
              Channel ID
              <input
                value={mail.mailChannelId}
                onChange={(event) => mail.setMailChannelId(event.target.value)}
                placeholder="32-byte hex channel id"
              />
            </label>
            <label>
              Lease ID
              <input
                value={mail.mailLeaseId}
                onChange={(event) => mail.setMailLeaseId(event.target.value)}
                placeholder="32-byte hex lease id"
              />
            </label>
            <label>
              Mailbox
              <input
                value={mail.mailMailbox}
                onChange={(event) => mail.setMailMailbox(event.target.value)}
                placeholder="primary"
              />
            </label>
            <label>
              Sequence
              <input
                type="number"
                min={1}
                value={mail.mailOpSeq}
                onChange={(event) =>
                  mail.setMailOpSeq(Math.max(1, Number(event.target.value) || 1))
                }
              />
            </label>
            <label>
              List limit
              <input
                type="number"
                min={1}
                max={20}
                value={mail.mailLimit}
                onChange={(event) =>
                  mail.setMailLimit(Math.max(1, Math.min(20, Number(event.target.value) || 1)))
                }
              />
            </label>
          </div>
          <div className="connector-test-actions">
            <button
              type="button"
              className="btn-secondary"
              onClick={mail.runMailListRecent}
              disabled={mail.mailBusy || !mail.mailConnectorRuntimeReady}
            >
              List Recent (tx)
            </button>
            <button
              type="button"
              className="btn-secondary"
              onClick={mail.runMailReadLatest}
              disabled={mail.mailBusy || !mail.mailConnectorRuntimeReady}
            >
              Read Latest (tx)
            </button>
          </div>
        </>
      ) : null}
      {mail.mailError ? <p className="connector-test-error">{mail.mailError}</p> : null}
      {mail.showOperatorTools && mail.mailResult ? (
        <pre className="connector-test-result">{mail.mailResult}</pre>
      ) : null}

      <ConnectorActionUnlockModal
        open={Boolean(selectedPreviewAction)}
        title={
          selectedPreviewAction
            ? `Unlock ${selectedPreviewAction.title}`
            : "Unlock mail task"
        }
        description={
          selectedPreviewAction
            ? "See what local inbox setup this mailbox task needs before you continue."
            : undefined
        }
        summaryCategory={selectedPreviewAction?.categoryLabel ?? "Mailbox task"}
        summaryTitle={selectedPreviewAction?.title ?? "Mail task"}
        summaryDescription={selectedPreviewAction?.description ?? ""}
        onClose={closeUnlockDrilldown}
      >
        {selectedPreviewAction ? (
          <>
            <div className="workspace-unlock-grid">
              <article className="workspace-stat-card workspace-summary-card">
                <span>Current blocker</span>
                <strong>{unlockBlockerHeadline}</strong>
                <p>{unlockBlockerDetail}</p>
              </article>

              <article className="workspace-stat-card workspace-summary-card">
                <span>Setup target</span>
                <strong>Continue to local inbox setup</strong>
                <p>
                  The primary action below jumps to the account form so you can
                  connect an inbox for this task.
                </p>
              </article>
            </div>

            <div className="workspace-warning-panel">
              <strong>What you will need</strong>
              <div className="workspace-warning-list">
                <span>Your inbox email address.</span>
                <span>Your password or app password.</span>
                <span>
                  A mailbox name if you want Autopilot to keep more than one
                  inbox configured.
                </span>
              </div>
            </div>

            <div className="workspace-storage-list">
              <span>{unlockProviderHint}</span>
            </div>

            <div className="workspace-modal-actions workspace-unlock-actions">
              <button
                type="button"
                className="btn-primary"
                onClick={continueFromUnlockDrilldown}
              >
                Continue to local inbox setup
              </button>
              <button
                type="button"
                className="btn-secondary"
                onClick={closeUnlockDrilldown}
              >
                Keep browsing
              </button>
            </div>
          </>
        ) : null}
      </ConnectorActionUnlockModal>

      <WorkspaceModal
        open={focusedActionModalOpen && mail.connectedMailAccounts.length > 0}
        title={selectedWorkbenchAction.title}
        description="Use the focused form when you want the primary Mail action fields and run control to stay fully in view."
        onClose={() => setFocusedActionModalOpen(false)}
      >
        {renderMailTaskComposer({ inModal: true })}
      </WorkspaceModal>
    </div>
  );
}
