import { useEffect, useRef, type ReactNode, type RefObject } from "react";
import type {
  ConnectorActionDefinition,
  ConnectorSubscriptionStatus,
  ConnectorSubscriptionSummary,
  ConnectorSummary,
} from "../../../runtime/agent-runtime";
import { getConnectorFocusedFormRecommendation } from "./connectorActionPatterns";
import type { GoogleWorkspaceConnectorState } from "../hooks/useGoogleWorkspaceConnector";
import {
  GOOGLE_SCOPE_BUNDLES,
  ONBOARDING_STEPS,
  SERVICE_ORDER,
  type WorkspaceOnboardingStepId,
} from "./googleWorkspaceConnectorPanelConfig";

export function actionKindLabel(kind: string): string {
  switch (kind) {
    case "read":
      return "Read";
    case "write":
      return "Write";
    case "workflow":
      return "Workflow";
    case "admin":
      return "Admin";
    case "expert":
      return "Expert";
    default:
      return kind;
  }
}

export function subscriptionStatusLabel(status: ConnectorSubscriptionStatus): string {
  switch (status) {
    case "active":
      return "Active";
    case "paused":
      return "Paused";
    case "renewing":
      return "Renewing";
    case "reauth_required":
      return "Reauth required";
    case "degraded":
      return "Degraded";
    case "stopped":
      return "Stopped";
    default:
      return status;
  }
}

export function formatTimestamp(value?: string): string | null {
  if (!value) return null;
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return parsed.toLocaleString();
}

export function orderIndex(service: string): number {
  const index = SERVICE_ORDER.indexOf(service as (typeof SERVICE_ORDER)[number]);
  return index === -1 ? SERVICE_ORDER.length : index;
}

export function availabilityLabel(status: ConnectorSummary["status"]): string {
  switch (status) {
    case "connected":
      return "Ready";
    case "degraded":
      return "Attention";
    case "disabled":
      return "Disabled";
    default:
      return "Connect required";
  }
}

export function availabilityTone(status: ConnectorSummary["status"]): "ready" | "attention" | "setup" {
  switch (status) {
    case "connected":
      return "ready";
    case "degraded":
      return "attention";
    default:
      return "setup";
  }
}

export function isMissingOauthClientError(message: string | null): boolean {
  if (!message) return false;
  return message.includes("Missing Google OAuth client ID");
}

export function serviceStateLabel(status?: string): string {
  switch (status) {
    case "ready":
      return "Ready";
    case "manual_input":
      return "Needs input";
    case "needs_scope":
      return "Needs scope";
    case "degraded":
      return "Attention";
    default:
      return "Setup";
  }
}

export function serviceStateTone(status?: string): "ready" | "attention" | "setup" {
  switch (status) {
    case "ready":
      return "ready";
    case "degraded":
    case "needs_scope":
      return "attention";
    default:
      return "setup";
  }
}

export function normalizeGoogleScope(scope: string): string {
  const trimmed = scope.trim();
  const prefix = "https://www.googleapis.com/auth/";
  if (trimmed.startsWith(prefix)) {
    return trimmed.slice(prefix.length);
  }
  if (trimmed === "https://www.googleapis.com/auth/userinfo.email") {
    return "email";
  }
  return trimmed;
}

export function googleScopeUri(scope: string): string {
  const normalized = normalizeGoogleScope(scope);
  if (normalized === "openid") {
    return "openid";
  }
  if (normalized === "email") {
    return "https://www.googleapis.com/auth/userinfo.email";
  }
  return `https://www.googleapis.com/auth/${normalized}`;
}

export function inferBundleSelectionFromScopes(scopes: string[]): string[] {
  const normalized = new Set(scopes.map(normalizeGoogleScope));
  return GOOGLE_SCOPE_BUNDLES.filter((bundle) =>
    bundle.scopes.some((scope) => normalized.has(normalizeGoogleScope(scope)))
  ).map((bundle) => bundle.id);
}

export function onboardingStepIndex(step: WorkspaceOnboardingStepId): number {
  return ONBOARDING_STEPS.findIndex((item) => item.id === step);
}

export function mergedFieldDescription(
  fieldDescription?: string,
  profileDescription?: string
): string | undefined {
  if (fieldDescription && profileDescription && fieldDescription !== profileDescription) {
    return `${profileDescription} ${fieldDescription}`;
  }
  return profileDescription ?? fieldDescription;
}

export function renderActionField(
  action: ConnectorActionDefinition,
  workspace: GoogleWorkspaceConnectorState,
  firstFieldRef?: RefObject<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement | null>
) {
  return action.fields.map((field, index) => {
    const value = workspace.input[field.id] ?? "";
    const fieldProfile = workspace.fieldProfiles[field.id];
    const fieldDescription = mergedFieldDescription(field.description, fieldProfile?.description);
    const profileOptions = fieldProfile?.options ?? [];
    const profileSuggestions = fieldProfile?.suggestions ?? [];
    const sharedRef = index === 0 ? firstFieldRef : undefined;
    const useProfileSelect =
      field.type !== "select" &&
      fieldProfile?.inputMode === "select" &&
      profileOptions.length > 0;

    if (field.type === "textarea") {
      return (
        <label key={field.id} className="workspace-field textarea">
          {field.label}
          <textarea
            ref={sharedRef as RefObject<HTMLTextAreaElement> | undefined}
            value={value}
            onChange={(event) => workspace.setInputValue(field.id, event.target.value)}
            placeholder={field.placeholder}
            rows={5}
          />
          {fieldDescription ? <span>{fieldDescription}</span> : null}
          {profileSuggestions.length > 0 ? (
            <div className="workspace-suggestion-row">
              {profileSuggestions.map((suggestion) => (
                <button
                  key={`${field.id}-${suggestion.value}`}
                  type="button"
                  className="workspace-suggestion-chip"
                  onClick={() => workspace.setInputValue(field.id, suggestion.value)}
                >
                  {suggestion.label}
                </button>
              ))}
            </div>
          ) : null}
        </label>
      );
    }

    if (field.type === "select" || useProfileSelect) {
      const options = field.type === "select" ? field.options ?? [] : profileOptions;
      return (
        <label key={field.id} className="workspace-field">
          {field.label}
          <select
            ref={sharedRef as RefObject<HTMLSelectElement> | undefined}
            value={value}
            onChange={(event) => workspace.setInputValue(field.id, event.target.value)}
          >
            {options.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
          {fieldDescription ? <span>{fieldDescription}</span> : null}
        </label>
      );
    }

    return (
      <label key={field.id} className="workspace-field">
        {field.label}
        <input
          ref={sharedRef as RefObject<HTMLInputElement> | undefined}
          type={field.type === "number" ? "number" : field.type === "email" ? "email" : "text"}
          value={value}
          onChange={(event) => workspace.setInputValue(field.id, event.target.value)}
          placeholder={field.placeholder}
        />
        {fieldDescription ? <span>{fieldDescription}</span> : null}
        {profileSuggestions.length > 0 ? (
          <div className="workspace-suggestion-row">
            {profileSuggestions.map((suggestion) => (
              <button
                key={`${field.id}-${suggestion.value}`}
                type="button"
                className="workspace-suggestion-chip"
                onClick={() => workspace.setInputValue(field.id, suggestion.value)}
              >
                {suggestion.label}
              </button>
            ))}
          </div>
        ) : null}
      </label>
    );
  });
}

export function WorkspaceActionComposer({
  action,
  workspace,
  eyebrow,
  showFocusedFormButton = false,
  onOpenFocusedForm,
  pinActionControls = false,
}: {
  action: ConnectorActionDefinition | null;
  workspace: GoogleWorkspaceConnectorState;
  eyebrow: string;
  showFocusedFormButton?: boolean;
  onOpenFocusedForm?: () => void;
  pinActionControls?: boolean;
}) {
  if (!action) {
    return (
      <div className="workspace-empty-state">
        <strong>Select an action</strong>
        <p>Pick a capability or automation recipe to configure it here.</p>
      </div>
    );
  }

  const composerRef = useRef<HTMLDivElement | null>(null);
  const firstFieldRef = useRef<
    HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement | null
  >(null);
  const approvalPrimaryButtonRef = useRef<HTMLButtonElement | null>(null);
  const focusedFormRecommendation = getConnectorFocusedFormRecommendation(action);

  useEffect(() => {
    const frame = window.requestAnimationFrame(() => {
      composerRef.current?.scrollIntoView({
        block: "start",
        inline: "nearest",
        behavior: "auto",
      });
      const firstField = firstFieldRef.current;
      firstField?.focus({ preventScroll: false });
      if (
        firstField &&
        (firstField instanceof HTMLInputElement ||
          firstField instanceof HTMLTextAreaElement)
      ) {
        firstField.select();
      }
    });
    return () => window.cancelAnimationFrame(frame);
  }, [action.id]);

  useEffect(() => {
    if (!workspace.pendingRunApproval) {
      return;
    }
    const frame = window.requestAnimationFrame(() => {
      approvalPrimaryButtonRef.current?.scrollIntoView({
        block: "nearest",
        inline: "nearest",
        behavior: "auto",
      });
      approvalPrimaryButtonRef.current?.focus({ preventScroll: false });
    });
    return () => window.cancelAnimationFrame(frame);
  }, [workspace.pendingRunApproval]);

  return (
    <div
      ref={composerRef}
      className={`workspace-action-panel workspace-composer-card ${
        pinActionControls ? "pinned-actions" : ""
      }`}
    >
      <div className="workspace-panel-heading-row">
        <div className="workspace-panel-heading">
          <span>{eyebrow}</span>
          <strong>{action.label}</strong>
        </div>
        {showFocusedFormButton ? (
          <button
            type="button"
            className={`btn-secondary workspace-focus-form-button ${
              focusedFormRecommendation.recommended ? "recommended" : ""
            }`}
            onClick={onOpenFocusedForm}
          >
            {focusedFormRecommendation.buttonLabel}
          </button>
        ) : null}
      </div>
      <div className="workspace-action-summary">
        <span className={`workspace-action-kind kind-${action.kind}`}>
          {actionKindLabel(action.kind)}
        </span>
        <p>{action.description}</p>
        {action.confirmBeforeRun ? (
          <p className="workspace-inline-note">
            This action requests confirmation before making changes in Google Workspace.
          </p>
        ) : null}
        {showFocusedFormButton && focusedFormRecommendation.note ? (
          <p className="workspace-inline-note">
            {focusedFormRecommendation.note}
          </p>
        ) : null}
        {action.requiredScopes?.length ? (
          <div className="workspace-required-scopes">
            {action.requiredScopes.map((scope) => (
              <code key={scope}>{scope}</code>
            ))}
          </div>
        ) : null}
      </div>

      {action.fields.length > 0 ? (
        <div className="workspace-action-grid">
          {renderActionField(action, workspace, firstFieldRef)}
        </div>
      ) : (
        <p className="workspace-auth-note">No additional input is required for this action.</p>
      )}

      {workspace.pendingRunApproval ? (
        <div
          className={`workspace-approval-card ${
            pinActionControls ? "sticky-approval-card" : ""
          }`}
        >
          <div className="workspace-approval-card-head">
            <strong>
              {workspace.pendingRunApproval.kind === "shield_policy"
                ? "Shield approval required"
                : "Confirm action"}
            </strong>
            <span>{workspace.pendingRunApproval.actionLabel}</span>
          </div>
          <p>{workspace.pendingRunApproval.message}</p>
          {workspace.pendingRunApproval.request ? (
            <div className="workspace-required-scopes">
              <code>{workspace.pendingRunApproval.request.connectorId}</code>
              <code>{workspace.pendingRunApproval.request.actionId}</code>
            </div>
          ) : null}
          <div className="workspace-action-actions">
            <button
              ref={approvalPrimaryButtonRef}
              type="button"
              className="btn-primary"
              onClick={() => {
                void workspace.approvePendingRun();
              }}
              disabled={workspace.busy || !workspace.runtimeReady}
              aria-label={
                workspace.pendingRunApproval.kind === "shield_policy"
                  ? `Approve and run ${workspace.pendingRunApproval.actionLabel}`
                  : `Confirm and run ${workspace.pendingRunApproval.actionLabel}`
              }
            >
              {workspace.pendingRunApproval.kind === "shield_policy"
                ? "Approve and run"
                : "Confirm and run"}
            </button>
            <button
              type="button"
              className="btn-secondary"
              onClick={workspace.cancelPendingRun}
              disabled={workspace.busy}
            >
              Cancel
            </button>
          </div>
        </div>
      ) : null}

      <div
        className={`workspace-action-actions workspace-primary-run-actions ${
          pinActionControls ? "sticky-run-actions" : ""
        }`}
      >
        <button
          type="button"
          className="btn-primary"
          onClick={workspace.runSelectedAction}
          disabled={workspace.busy || !workspace.runtimeReady}
        >
          {workspace.busy ? "Running..." : `Run ${action.label}`}
        </button>
      </div>
    </div>
  );
}

export function WorkspaceSubscriptionCard({
  subscription,
  workspace,
}: {
  subscription: ConnectorSubscriptionSummary;
  workspace: GoogleWorkspaceConnectorState;
}) {
  return (
    <article className="workspace-subscription-card">
      <div className="workspace-subscription-card-head">
        <div>
          <strong>{subscription.kind}</strong>
          <p>{subscription.pubsubSubscription}</p>
        </div>
        <span
          className={`workspace-action-kind workspace-subscription-status status-${subscription.status}`}
        >
          {subscriptionStatusLabel(subscription.status)}
        </span>
      </div>
      <div className="workspace-subscription-meta">
        <span>Topic: {subscription.pubsubTopic}</span>
        {subscription.accountEmail ? <span>Account: {subscription.accountEmail}</span> : null}
        {subscription.automationActionId ? (
          <span>Trigger: {subscription.automationActionId}</span>
        ) : (
          <span>Trigger: none</span>
        )}
        {subscription.renewAtUtc ? (
          <span>Renew at: {formatTimestamp(subscription.renewAtUtc)}</span>
        ) : null}
        {subscription.lastDeliveryAtUtc ? (
          <span>Last delivery: {formatTimestamp(subscription.lastDeliveryAtUtc)}</span>
        ) : null}
        {subscription.lastError ? <span>Error: {subscription.lastError}</span> : null}
      </div>
      <div className="workspace-subscription-actions">
        <button
          type="button"
          className="btn-secondary"
          onClick={() => workspace.renewSubscription(subscription.subscriptionId)}
          disabled={workspace.busy || !workspace.subscriptionRuntimeReady}
        >
          Renew
        </button>
        {subscription.status === "paused" ? (
          <button
            type="button"
            className="btn-secondary"
            onClick={() => workspace.resumeSubscription(subscription.subscriptionId)}
            disabled={workspace.busy || !workspace.subscriptionRuntimeReady}
          >
            Resume
          </button>
        ) : (
          <button
            type="button"
            className="btn-secondary"
            onClick={() => workspace.stopSubscription(subscription.subscriptionId)}
            disabled={workspace.busy || !workspace.subscriptionRuntimeReady}
          >
            Pause
          </button>
        )}
      </div>
    </article>
  );
}

export function WorkspaceModal({
  open,
  title,
  description,
  onClose,
  children,
}: {
  open: boolean;
  title: string;
  description?: string;
  onClose: () => void;
  children: ReactNode;
}) {
  if (!open) return null;

  return (
    <div className="workspace-modal-backdrop" role="presentation" onClick={onClose}>
      <div
        className="workspace-modal"
        role="dialog"
        aria-modal="true"
        aria-label={title}
        onClick={(event) => event.stopPropagation()}
      >
        <div className="workspace-modal-head">
          <div>
            <h4>{title}</h4>
            {description ? <p>{description}</p> : null}
          </div>
          <button type="button" className="btn-secondary" onClick={onClose}>
            Close
          </button>
        </div>
        <div className="workspace-modal-body">{children}</div>
      </div>
    </div>
  );
}
