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
    </div>
  );
}
