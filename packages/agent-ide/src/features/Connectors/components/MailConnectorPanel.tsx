import type {
  MailConnectorActionsState,
  MailProviderPresetKey,
  MailTlsMode,
} from "../hooks/useMailConnectorActions";

interface MailConnectorPanelProps {
  mail: MailConnectorActionsState;
}

export function MailConnectorPanel({ mail }: MailConnectorPanelProps) {
  return (
    <div className="connector-test-panel">
      <div className="mail-account-setup">
        <div className="mail-setup-head">
          <h3>Quick Add Mail Account</h3>
          <p>
            Enter the same account details you would use in iOS Mail or Outlook. Credentials are
            stored as vault aliases.
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
              value={mail.mailSetupEmail}
              onChange={(event) => mail.setMailSetupEmail(event.target.value)}
              placeholder="you@example.com"
              autoComplete="username"
            />
          </label>
          <label>
            Password / App Password
            <input
              type="password"
              value={mail.mailSetupPassword}
              onChange={(event) => mail.setMailSetupPassword(event.target.value)}
              placeholder="Required"
              autoComplete="current-password"
            />
          </label>
          <label>
            Mailbox label
            <input
              value={mail.mailSetupMailbox}
              onChange={(event) => mail.setMailSetupMailbox(event.target.value)}
              placeholder="primary"
            />
          </label>
        </div>
        <p className="mail-provider-hint">
          {mail.effectivePreset
            ? `${mail.effectivePreset.label}: ${mail.effectivePreset.imapHost}:${mail.effectivePreset.imapPort} (${mail.effectivePreset.imapTlsMode.toUpperCase()}) and ${mail.effectivePreset.smtpHost}:${mail.effectivePreset.smtpPort} (${mail.effectivePreset.smtpTlsMode.toUpperCase()}). ${mail.effectivePreset.note}`
            : "Custom mode: enter your provider's IMAP/SMTP host, port, and TLS mode in Advanced settings."}
        </p>
        <div className="mail-setup-actions">
          <button
            type="button"
            className="btn-primary"
            onClick={mail.saveMailAccount}
            disabled={mail.mailBusy || !mail.mailSetupRuntimeReady}
          >
            Save Mail Account
          </button>
          <button
            type="button"
            className="btn-secondary"
            onClick={() => mail.setMailSetupAdvancedOpen((value) => !value)}
          >
            {mail.mailSetupAdvancedOpen ? "Hide Advanced Settings" : "Show Advanced Settings"}
          </button>
        </div>
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

      <button
        type="button"
        className="btn-secondary"
        onClick={() => mail.setShowOperatorTools((value) => !value)}
      >
        {mail.showOperatorTools ? "Hide Operator Tools" : "Show Operator Tools"}
      </button>

      {mail.showOperatorTools ? (
        <>
          {mail.mailAssistantRuntimeReady ? (
            <div className="connector-intent-panel">
              <label>
                Assistant mail request
                <textarea
                  value={mail.mailIntentQuery}
                  onChange={(event) => mail.setMailIntentQuery(event.target.value)}
                  placeholder="Read me the last email I received."
                  rows={3}
                />
              </label>
              <label>
                Approval artifact JSON (auto-generated for delete/reply when enabled)
                <textarea
                  value={mail.mailApprovalArtifactJson}
                  onChange={(event) => mail.setMailApprovalArtifactJson(event.target.value)}
                  placeholder='{"interception":{...},"decision":"approved_by_human","approval_token":{...}}'
                  rows={3}
                />
              </label>
              <label className="connector-intent-checkbox">
                <input
                  type="checkbox"
                  checked={mail.mailAutoGenerateApproval}
                  onChange={(event) => mail.setMailAutoGenerateApproval(event.target.checked)}
                />
                Auto-generate approval artifact for write intents
              </label>
              <label>
                Approval TTL seconds
                <input
                  type="number"
                  min={30}
                  max={3600}
                  value={mail.mailApprovalTtlSeconds}
                  onChange={(event) =>
                    mail.setMailApprovalTtlSeconds(
                      Math.max(30, Math.min(3600, Number(event.target.value) || 30))
                    )
                  }
                  disabled={!mail.mailApprovalRuntimeReady}
                />
              </label>
              <button
                type="button"
                className="btn-secondary"
                onClick={mail.runGenerateMailApprovalArtifact}
                disabled={mail.mailBusy || !mail.mailApprovalRuntimeReady}
              >
                Generate Approval Artifact
              </button>
              <button
                type="button"
                className="btn-primary"
                onClick={mail.runMailIntent}
                disabled={mail.mailBusy}
              >
                Run Assistant Intent
              </button>
            </div>
          ) : null}
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
      {mail.mailResult ? <pre className="connector-test-result">{mail.mailResult}</pre> : null}
    </div>
  );
}
