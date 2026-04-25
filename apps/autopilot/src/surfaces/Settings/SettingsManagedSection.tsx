import { buildAuthorityAutomationPlan } from "../../windows/ChatShellWindow/utils/authorityAutomationModel";
import { formatSettingsTime } from "./settingsViewShared";
import type { SettingsViewBodyView } from "./settingsViewTypes";

function humanize(value: string): string {
  return value.replace(/[_-]/g, " ").replace(/\b\w/g, (match) => match.toUpperCase());
}

export function SettingsManagedSection({
  view,
}: {
  view: SettingsViewBodyView;
}) {
  const {
    engineSnapshot,
    engineSaving,
    engineMessage,
    engineError,
    governanceRequest,
    authorityHookSnapshot,
    authorityRememberedApprovals,
    authorityStatus,
    authorityError,
    authorityApplyingProfileId,
    authorityMessage,
    authorityCurrentProfileId,
    authorityActiveOverrideCount,
    handleApplyAuthorityProfile,
    onOpenPolicySurface,
    onOpenConnections,
    handleRefreshManagedSettings,
    handleClearManagedSettingsOverrides,
  } = view;

  const managedSettings = engineSnapshot?.managedSettings ?? null;
  const authorityPlan = buildAuthorityAutomationPlan({
    currentProfileId: authorityCurrentProfileId,
    hookSnapshot: authorityHookSnapshot,
    rememberedApprovals: authorityRememberedApprovals,
    governanceRequest: governanceRequest ?? null,
    activeOverrideCount: authorityActiveOverrideCount,
  });
  if (!managedSettings) {
    return (
      <article className="chat-settings-card">
        <div className="chat-settings-card-head">
          <div>
            <span className="chat-settings-card-eyebrow">Managed</span>
            <h2>Managed settings unavailable</h2>
          </div>
          <span className="chat-settings-pill">Kernel-backed</span>
        </div>
        <p className="chat-settings-body">
          Refresh the Local Engine snapshot to inspect signed settings channels and
          local override posture.
        </p>
      </article>
    );
  }

  return (
    <div className="chat-settings-stack">
      <article className="chat-settings-card">
        <div className="chat-settings-card-head">
          <div>
            <span className="chat-settings-card-eyebrow">Authority</span>
            <h2>Shared authority automation</h2>
          </div>
          <span className="chat-settings-pill">
            {humanize(authorityPlan.tone)}
          </span>
        </div>
        <p className="chat-settings-body">{authorityPlan.detail}</p>
        <div className="chat-settings-summary-grid">
          {authorityPlan.checklist.map((item) => (
            <article key={item} className="chat-settings-subcard">
              <strong>Signal</strong>
              <span>{item}</span>
            </article>
          ))}
        </div>
        {authorityStatus === "loading" ? (
          <p className="chat-settings-body">
            Loading hook and approval-memory posture from the shared runtime.
          </p>
        ) : null}
        {authorityMessage ? (
          <p className="chat-settings-success">{authorityMessage}</p>
        ) : null}
        {authorityError ? (
          <p className="chat-settings-error">{authorityError}</p>
        ) : null}
        <div className="chat-settings-actions">
          {authorityPlan.actionKind === "apply_profile" &&
          authorityPlan.recommendedProfileId ? (
            <button
              type="button"
              className="chat-settings-secondary"
              disabled={authorityApplyingProfileId !== null}
              onClick={() => {
                void handleApplyAuthorityProfile(
                  authorityPlan.recommendedProfileId!,
                );
              }}
            >
              {authorityApplyingProfileId === authorityPlan.recommendedProfileId
                ? "Applying..."
                : authorityPlan.primaryActionLabel || "Apply profile"}
            </button>
          ) : null}
          {authorityPlan.actionKind === "review_permissions" ? (
            <button
              type="button"
              className="chat-settings-secondary"
              onClick={onOpenPolicySurface}
            >
              {authorityPlan.primaryActionLabel || "Open policy"}
            </button>
          ) : null}
          {authorityPlan.actionKind === "review_hooks" ? (
            <button
              type="button"
              className="chat-settings-secondary"
              onClick={onOpenConnections}
            >
              {authorityPlan.primaryActionLabel || "Open connections"}
            </button>
          ) : null}
        </div>
      </article>

      <article className="chat-settings-card">
        <div className="chat-settings-card-head">
          <div>
            <span className="chat-settings-card-eyebrow">Managed</span>
            <h2>Signed settings channels</h2>
          </div>
          <span className="chat-settings-pill">
            {humanize(managedSettings.syncStatus)}
          </span>
        </div>
        <p className="chat-settings-body">{managedSettings.summary}</p>
        <div className="chat-settings-summary-grid">
          <article className="chat-settings-subcard">
            <strong>Active channel</strong>
            <span>{managedSettings.activeChannelLabel ?? "Local only"}</span>
          </article>
          <article className="chat-settings-subcard">
            <strong>Local overrides</strong>
            <span>{managedSettings.localOverrideCount}</span>
          </article>
          <article className="chat-settings-subcard">
            <strong>Channels</strong>
            <span>{managedSettings.channels.length}</span>
          </article>
          <article className="chat-settings-subcard">
            <strong>Last refresh</strong>
            <span>
              {managedSettings.lastRefreshedAtMs
                ? formatSettingsTime(managedSettings.lastRefreshedAtMs)
                : "Not synced"}
            </span>
          </article>
        </div>

        <div className="chat-settings-callout">
          <strong>Override semantics</strong>
          <p>
            Saving runtime settings while a signed channel is active preserves a local
            override document over the verified baseline instead of mutating the remote
            source directly.
          </p>
        </div>

        {engineMessage ? (
          <p className="chat-settings-success">{engineMessage}</p>
        ) : null}
        {engineError ? <p className="chat-settings-error">{engineError}</p> : null}

        <div className="chat-settings-actions">
          <button
            type="button"
            className="chat-settings-secondary"
            disabled={engineSaving}
            onClick={() => {
              void handleRefreshManagedSettings();
            }}
          >
            {engineSaving ? "Refreshing..." : "Refresh signed channels"}
          </button>
          <button
            type="button"
            className="chat-settings-secondary"
            disabled={engineSaving || managedSettings.localOverrideCount === 0}
            onClick={() => {
              void handleClearManagedSettingsOverrides();
            }}
          >
            Clear local overrides
          </button>
        </div>
      </article>

      <article className="chat-settings-card">
        <div className="chat-settings-card-head">
          <div>
            <span className="chat-settings-card-eyebrow">Channels</span>
            <h2>Authority and sync posture</h2>
          </div>
          <span className="chat-settings-pill">
            {managedSettings.channels.length} tracked
          </span>
        </div>
        <div className="chat-settings-stack chat-settings-stack--compact">
          {managedSettings.channels.length === 0 ? (
            <p className="chat-settings-body">
              No signed settings feeds have been configured yet. Local settings remain
              authoritative until a managed channel is refreshed into the runtime.
            </p>
          ) : (
            managedSettings.channels.map((channel) => (
              <article key={channel.channelId} className="chat-settings-subcard">
                <div className="chat-settings-subcard-head">
                  <strong>{channel.label}</strong>
                  <span>{humanize(channel.status)}</span>
                </div>
                <div className="chat-settings-chip-row">
                  <span className="chat-settings-chip">
                    {humanize(channel.verificationStatus)}
                  </span>
                  <span className="chat-settings-chip">
                    priority {channel.precedence}
                  </span>
                  {channel.authorityLabel ? (
                    <span className="chat-settings-chip">{channel.authorityLabel}</span>
                  ) : null}
                </div>
                <p>{channel.summary}</p>
                <small>{channel.sourceUri}</small>
                {channel.overriddenFields.length > 0 ? (
                  <div className="chat-settings-chip-row">
                    {channel.overriddenFields.map((field) => (
                      <span key={field} className="chat-settings-chip">
                        {field}
                      </span>
                    ))}
                  </div>
                ) : null}
              </article>
            ))
          )}
        </div>
      </article>

      <article className="chat-settings-card">
        <div className="chat-settings-card-head">
          <div>
            <span className="chat-settings-card-eyebrow">Overrides</span>
            <h2>Effective local drift</h2>
          </div>
          <span className="chat-settings-pill">
            {managedSettings.localOverrideCount} field
            {managedSettings.localOverrideCount === 1 ? "" : "s"}
          </span>
        </div>
        {managedSettings.localOverrideFields.length > 0 ? (
          <div className="chat-settings-chip-row">
            {managedSettings.localOverrideFields.map((field) => (
              <span key={field} className="chat-settings-chip">
                {field}
              </span>
            ))}
          </div>
        ) : (
          <p className="chat-settings-body">
            The effective control plane currently matches the signed managed baseline.
          </p>
        )}
        {managedSettings.refreshError ? (
          <div className="chat-settings-callout">
            <strong>Last refresh warning</strong>
            <p>{managedSettings.refreshError}</p>
          </div>
        ) : null}
      </article>
    </div>
  );
}
