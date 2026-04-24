import { formatSessionTimeAgo } from "@ioi/agent-ide";
import { useEffect } from "react";
import {
  openReviewConnectorPolicy,
  openReviewPolicyCenter,
} from "../../../services/reviewNavigation";
import type {
  AgentTask,
  ArtifactHubViewKey,
  ClarificationRequest,
  CredentialRequest,
  GateInfo,
  SessionHookSnapshot,
} from "../../../types";
import {
  applySessionPermissionProfile,
  buildPolicyDeltaDeck,
  buildPolicyIntentDeltaDeck,
  buildPolicySimulationDeck,
  dataHandlingLabel,
  resolveConnectorPolicy,
  type AutomationPolicyMode,
  type CapabilityGovernanceRequest,
  type ConnectorPolicyOverride,
  type DataHandlingMode,
  type PolicyDecisionMode,
  type SessionPermissionProfileId,
  type ShieldApprovalScopeMode,
  type ShieldRememberedApprovalSnapshot,
  type ShieldPolicyState,
} from "../../ChatWindow/chatPolicyCenter";
import type {
  ChatPermissionConnectorOverrideSummary,
  ChatPermissionProfileSummary,
} from "../hooks/useChatPermissions";
import type { ChatPrivacySnapshot } from "../hooks/useChatPrivacySettings";
import { buildAuthorityAutomationPlan } from "../utils/authorityAutomationModel";
import { buildAuthorityOverrideReviewCards } from "../utils/authorityOverrideReviewModel";
import { humanizeStatus, taskBlockerSummary } from "./ArtifactHubViewHelpers";

const PERMISSION_PROFILE_SHORTCUTS: Record<SessionPermissionProfileId, string> =
  {
    safer_review: "Alt+1",
    guided_default: "Alt+2",
    autonomous: "Alt+3",
    expert: "Alt+4",
  };

const PERMISSION_DECISION_OPTIONS: Array<{
  value: PolicyDecisionMode;
  label: string;
}> = [
  { value: "auto", label: "Auto-run" },
  { value: "confirm", label: "Confirm" },
  { value: "block", label: "Block" },
];

const PERMISSION_AUTOMATION_OPTIONS: Array<{
  value: AutomationPolicyMode;
  label: string;
}> = [
  { value: "confirm_on_create", label: "Confirm on create" },
  { value: "confirm_on_run", label: "Confirm on first run" },
  { value: "manual_only", label: "Manual only" },
];

const PERMISSION_DATA_OPTIONS: Array<{
  value: DataHandlingMode;
  label: string;
}> = [
  { value: "local_only", label: "Local only" },
  { value: "local_redacted", label: "Local with redacted artifacts" },
];

function approvalScopeModeLabel(
  scopeMode: ShieldApprovalScopeMode,
  policyFamily: string,
): string {
  if (scopeMode === "connector_policy_family") {
    return humanizeStatus(policyFamily) + " family";
  }
  return "Exact action";
}

function policyTone(value: string | null | undefined): string {
  const normalized = (value || "").trim().toLowerCase();
  if (normalized === "auto") return "auto";
  if (normalized === "confirm" || normalized === "gate") return "gate";
  if (normalized === "block" || normalized === "deny") return "deny";
  return "neutral";
}

function permissionSimulationOutcomeLabel(
  value: "auto" | "gate" | "deny",
): string {
  switch (value) {
    case "auto":
      return "Auto";
    case "gate":
      return "Gate";
    case "deny":
      return "Deny";
  }
}

function PermissionPolicySelect<T extends string>({
  label,
  value,
  options,
  disabled = false,
  onChange,
}: {
  label: string;
  value: T;
  options: Array<{ value: T; label: string }>;
  disabled?: boolean;
  onChange: (next: T) => void;
}) {
  return (
    <label className="artifact-hub-permissions-field">
      <span>{label}</span>
      <select
        className="artifact-hub-commit-input"
        value={value}
        disabled={disabled}
        onChange={(event) => onChange(event.target.value as T)}
      >
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
    </label>
  );
}

export function PrivacyView({
  snapshot,
  permissionsStatus,
  permissionsError,
  onOpenView,
  onRefreshPermissions,
}: {
  snapshot: ChatPrivacySnapshot;
  permissionsStatus: string;
  permissionsError: string | null;
  onOpenView?: (view: ArtifactHubViewKey) => void;
  onRefreshPermissions?: () => Promise<unknown>;
}) {
  return (
    <div className="artifact-hub-permissions">
      <section className="artifact-hub-files-identity artifact-hub-permissions__identity">
        <span className="artifact-hub-files-kicker">Privacy</span>
        <strong>Session privacy posture</strong>
        <p>
          Review how the active shell handles evidence, redaction, and local
          export before anything leaves the runtime.
        </p>
        <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
          <span>Policy sync: {humanizeStatus(permissionsStatus)}</span>
          <span>{snapshot.activeOverrideCount} connector overrides</span>
          <span>{snapshot.redactedOverrideCount} redacted export paths</span>
        </div>
      </section>

      {permissionsError ? (
        <p className="artifact-hub-note artifact-hub-note--error">
          {permissionsError}
        </p>
      ) : null}

      <div className="artifact-hub-permissions-grid">
        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>{snapshot.focusedScopeLabel}</strong>
            <span className="artifact-hub-policy-pill">
              {snapshot.focusedDataHandlingLabel}
            </span>
          </div>
          <p>{snapshot.focusedDataHandlingDetail}</p>
          <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
            <span>Source: {snapshot.governingSourceLabel}</span>
            <span>{snapshot.localOnlyOverrideCount} local-only overrides</span>
            <span>{snapshot.redactedOverrideCount} redacted overrides</span>
          </div>
        </section>

        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>{snapshot.sessionReviewLabel}</strong>
            <span className="artifact-hub-policy-pill">Review</span>
          </div>
          <p>{snapshot.sessionReviewDetail}</p>
          <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
            <span>{snapshot.exportSurfaceLabel}</span>
            <span>Operator initiated</span>
          </div>
          {snapshot.pendingGovernanceSummary ? (
            <p className="artifact-hub-generic-summary">
              {snapshot.pendingGovernanceSummary}
            </p>
          ) : null}
        </section>

        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>{snapshot.governanceHistoryLabel}</strong>
            <span className="artifact-hub-policy-pill">
              {snapshot.recentGovernanceReceipts.length} retained
            </span>
          </div>
          <p>{snapshot.governanceHistoryDetail}</p>
          {snapshot.recentGovernanceReceipts.length > 0 ? (
            <div className="artifact-hub-generic-list">
              {snapshot.recentGovernanceReceipts.map((receipt) => (
                <article
                  className="artifact-hub-generic-row"
                  key={receipt.receiptId}
                >
                  <div className="artifact-hub-generic-meta">
                    <span>{humanizeStatus(receipt.hookKind)}</span>
                    <span>{humanizeStatus(receipt.status)}</span>
                    <span>{formatSessionTimeAgo(receipt.timestampMs)}</span>
                  </div>
                  <div className="artifact-hub-generic-title">
                    {receipt.connectorId} · {receipt.actionId}
                  </div>
                  <p className="artifact-hub-generic-summary">
                    {receipt.summary}
                  </p>
                </article>
              ))}
            </div>
          ) : null}
        </section>
      </div>

      <section className="artifact-hub-permissions-card">
        <div className="artifact-hub-permissions-card__head">
          <strong>Export and sharing posture</strong>
          <span className="artifact-hub-policy-pill">Canonical export</span>
        </div>
        <p>{snapshot.exportSurfaceDetail}</p>
        <div className="artifact-hub-permissions-card__actions">
          {onOpenView ? (
            <button
              type="button"
              className="artifact-hub-open-btn"
              onClick={() => onOpenView("export")}
            >
              Export Evidence
            </button>
          ) : null}
          {onOpenView ? (
            <button
              type="button"
              className="artifact-hub-open-btn secondary"
              onClick={() => onOpenView("permissions")}
            >
              Review Permissions
            </button>
          ) : null}
          <button
            type="button"
            className="artifact-hub-open-btn secondary"
            onClick={() => void openReviewPolicyCenter()}
          >
            Open Chat Policy
          </button>
        </div>
      </section>

      {snapshot.connectors.length > 0 ? (
        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>Connector artifact handling</strong>
            <span className="artifact-hub-policy-pill">
              {snapshot.connectors.length} tracked
            </span>
          </div>
          <div className="artifact-hub-permissions-list">
            {snapshot.connectors.map((connector) => (
              <div
                key={connector.connectorId}
                className="artifact-hub-permissions-list__row"
              >
                <div>
                  <strong>{connector.label}</strong>
                  <p>{connector.headline}</p>
                </div>
                <span>
                  {connector.modeLabel}
                  {" · "}
                  {connector.detail}
                </span>
              </div>
            ))}
          </div>
        </section>
      ) : (
        <p className="artifact-hub-empty">
          No connector-specific privacy overrides are active. The session is
          currently following the global runtime privacy baseline.
        </p>
      )}

      {onRefreshPermissions ? (
        <div className="artifact-hub-permissions-card__actions">
          <button
            type="button"
            className="artifact-hub-open-btn"
            onClick={() => {
              void onRefreshPermissions();
            }}
          >
            Refresh privacy posture
          </button>
        </div>
      ) : null}
    </div>
  );
}

export function PermissionsView({
  currentTask,
  isGated,
  gateInfo,
  credentialRequest,
  clarificationRequest,
  onOpenGate,
  onOpenView,
  onRefreshPermissions,
  permissionsStatus,
  permissionsError,
  permissionPolicyState,
  permissionGovernanceRequest,
  permissionConnectorOverrides,
  permissionActiveOverrideCount,
  permissionProfiles,
  permissionCurrentProfileId,
  permissionApplyingProfileId,
  permissionEditingConnectorId,
  permissionApplyingGovernanceRequest,
  permissionRememberedApprovals,
  hookSnapshot,
  onApplyPermissionProfile,
  onApplyPermissionGovernanceRequest,
  onDismissPermissionGovernanceRequest,
  onForgetRememberedApproval,
  onUpdatePermissionOverride,
  onResetPermissionOverride,
  onSetRememberedApprovalScopeMode,
  onSetRememberedApprovalExpiry,
}: {
  currentTask: AgentTask | null;
  isGated?: boolean;
  gateInfo?: GateInfo;
  credentialRequest?: CredentialRequest;
  clarificationRequest?: ClarificationRequest;
  onOpenGate?: () => void;
  onOpenView?: (view: ArtifactHubViewKey) => void;
  onRefreshPermissions?: () => Promise<unknown>;
  permissionsStatus: string;
  permissionsError: string | null;
  permissionPolicyState: ShieldPolicyState;
  permissionGovernanceRequest: CapabilityGovernanceRequest | null;
  permissionConnectorOverrides: ChatPermissionConnectorOverrideSummary[];
  permissionActiveOverrideCount: number;
  permissionProfiles: ChatPermissionProfileSummary[];
  permissionCurrentProfileId: SessionPermissionProfileId | null;
  permissionApplyingProfileId: SessionPermissionProfileId | null;
  permissionEditingConnectorId: string | null;
  permissionApplyingGovernanceRequest: boolean;
  permissionRememberedApprovals: ShieldRememberedApprovalSnapshot | null;
  hookSnapshot: SessionHookSnapshot | null;
  onApplyPermissionProfile?: (
    profileId: SessionPermissionProfileId,
  ) => Promise<unknown>;
  onApplyPermissionGovernanceRequest?: () => Promise<unknown>;
  onDismissPermissionGovernanceRequest?: () => Promise<unknown>;
  onForgetRememberedApproval?: (decisionId: string) => Promise<unknown>;
  onUpdatePermissionOverride?: (
    connectorId: string,
    nextOverride: Partial<ConnectorPolicyOverride>,
  ) => Promise<unknown>;
  onResetPermissionOverride?: (connectorId: string) => Promise<unknown>;
  onSetRememberedApprovalScopeMode?: (
    decisionId: string,
    scopeMode: ShieldApprovalScopeMode,
  ) => Promise<unknown>;
  onSetRememberedApprovalExpiry?: (
    decisionId: string,
    expiresAtMs: number | null,
  ) => Promise<unknown>;
}) {
  const blocker = taskBlockerSummary(currentTask, {
    clarificationRequest,
    credentialRequest,
    gateInfo,
    isGated,
  });
  const focusedConnectorId =
    permissionGovernanceRequest?.connectorId ||
    permissionConnectorOverrides[0]?.connectorId ||
    null;
  const focusedScopeLabel =
    permissionGovernanceRequest?.connectorLabel ||
    permissionConnectorOverrides[0]?.label ||
    "Global runtime policy";
  const effectivePolicy = focusedConnectorId
    ? resolveConnectorPolicy(permissionPolicyState, focusedConnectorId)
        .effective
    : permissionPolicyState.global;
  const simulationDeck = buildPolicySimulationDeck(
    permissionPolicyState,
    focusedConnectorId,
  );
  const deltaDeck = buildPolicyDeltaDeck(
    permissionPolicyState,
    focusedConnectorId,
  );
  const requestCount =
    Number(Boolean(blocker)) +
    Number(Boolean(permissionGovernanceRequest)) +
    permissionActiveOverrideCount;
  const currentProfile =
    permissionProfiles.find(
      (profile) => profile.id === permissionCurrentProfileId,
    ) ?? null;
  const rememberedDecisionCount =
    permissionRememberedApprovals?.activeDecisionCount ?? 0;
  const recentHookReceiptCount =
    permissionRememberedApprovals?.recentReceiptCount ?? 0;
  const overrideReviewCards = buildAuthorityOverrideReviewCards({
    policyState: permissionPolicyState,
    connectorOverrides: permissionConnectorOverrides,
    governanceRequest: permissionGovernanceRequest,
  });
  const authorityAutomationPlan = buildAuthorityAutomationPlan({
    currentProfileId: permissionCurrentProfileId,
    hookSnapshot: hookSnapshot,
    rememberedApprovals: permissionRememberedApprovals,
    governanceRequest: permissionGovernanceRequest,
    activeOverrideCount: permissionActiveOverrideCount,
  });

  useEffect(() => {
    if (typeof window === "undefined" || !onApplyPermissionProfile) {
      return;
    }

    const shortcutProfiles: Record<string, SessionPermissionProfileId> = {
      Digit1: "safer_review",
      Numpad1: "safer_review",
      Digit2: "guided_default",
      Numpad2: "guided_default",
      Digit3: "autonomous",
      Numpad3: "autonomous",
      Digit4: "expert",
      Numpad4: "expert",
    };

    const handleKeyDown = (event: KeyboardEvent) => {
      if (!event.altKey || event.ctrlKey || event.metaKey || event.shiftKey) {
        return;
      }

      const targetProfileId = shortcutProfiles[event.code];
      if (!targetProfileId) {
        return;
      }

      if (
        permissionCurrentProfileId === targetProfileId ||
        permissionApplyingProfileId === targetProfileId
      ) {
        event.preventDefault();
        return;
      }

      event.preventDefault();
      void onApplyPermissionProfile(targetProfileId);
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => {
      window.removeEventListener("keydown", handleKeyDown);
    };
  }, [
    onApplyPermissionProfile,
    permissionApplyingProfileId,
    permissionCurrentProfileId,
  ]);

  const policyRows = [
    {
      id: "reads",
      label: "Reads",
      value: humanizeStatus(effectivePolicy.reads),
      tone: policyTone(effectivePolicy.reads),
    },
    {
      id: "writes",
      label: "Writes",
      value: humanizeStatus(effectivePolicy.writes),
      tone: policyTone(effectivePolicy.writes),
    },
    {
      id: "admin",
      label: "Admin",
      value: humanizeStatus(effectivePolicy.admin),
      tone: policyTone(effectivePolicy.admin),
    },
    {
      id: "expert",
      label: "Expert",
      value: humanizeStatus(effectivePolicy.expert),
      tone: policyTone(effectivePolicy.expert),
    },
    {
      id: "automations",
      label: "Automations",
      value: humanizeStatus(effectivePolicy.automations),
      tone: "neutral",
    },
    {
      id: "dataHandling",
      label: "Artifacts",
      value: dataHandlingLabel(effectivePolicy.dataHandling),
      tone: "neutral",
    },
  ];

  return (
    <div className="artifact-hub-permissions">
      <section className="artifact-hub-files-identity artifact-hub-permissions__identity">
        <span className="artifact-hub-files-kicker">Permissions</span>
        <strong>Session permissions</strong>
        <p>
          Live operator grants, pending runtime requests, and current Shield
          policy posture for this session.
        </p>
        <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
          <span>Policy sync: {humanizeStatus(permissionsStatus)}</span>
          <span>{requestCount} active items</span>
          <span>{permissionActiveOverrideCount} connector overrides</span>
          <span>{rememberedDecisionCount} remembered approvals</span>
        </div>
      </section>

      {permissionsError ? (
        <p className="artifact-hub-note artifact-hub-note--error">
          {permissionsError}
        </p>
      ) : null}

      {blocker ? (
        <section className="artifact-hub-permissions-card artifact-hub-permissions-card--alert">
          <div className="artifact-hub-permissions-card__head">
            <strong>{blocker.title}</strong>
            <span className="artifact-hub-policy-pill">Pending</span>
          </div>
          <p>{blocker.detail}</p>
          <div className="artifact-hub-permissions-card__actions">
            {onOpenView ? (
              <button
                type="button"
                className="artifact-hub-open-btn"
                onClick={() => onOpenView("tasks")}
              >
                Review Tasks
              </button>
            ) : null}
            {onOpenGate && isGated ? (
              <button
                type="button"
                className="artifact-hub-open-btn"
                onClick={onOpenGate}
              >
                Open Gate
              </button>
            ) : null}
            <button
              type="button"
              className="artifact-hub-open-btn"
              onClick={() =>
                void openReviewConnectorPolicy(
                  permissionGovernanceRequest?.connectorId ??
                    focusedConnectorId,
                )
              }
            >
              Open Chat Policy
            </button>
          </div>
        </section>
      ) : null}

      {permissionGovernanceRequest ? (
        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>{permissionGovernanceRequest.headline}</strong>
            <span className="artifact-hub-policy-pill">
              {humanizeStatus(permissionGovernanceRequest.action)}
            </span>
          </div>
          <p>{permissionGovernanceRequest.detail}</p>
          <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
            <span>{permissionGovernanceRequest.capabilityLabel}</span>
            <span>{permissionGovernanceRequest.connectorLabel}</span>
            <span>{permissionGovernanceRequest.authorityTierLabel}</span>
          </div>
          <div className="artifact-hub-permissions-card__actions">
            {onApplyPermissionGovernanceRequest ? (
              <button
                type="button"
                className="artifact-hub-open-btn"
                disabled={permissionApplyingGovernanceRequest}
                onClick={() => {
                  void onApplyPermissionGovernanceRequest();
                }}
              >
                {permissionApplyingGovernanceRequest
                  ? "Applying request..."
                  : "Apply request here"}
              </button>
            ) : null}
            {onDismissPermissionGovernanceRequest ? (
              <button
                type="button"
                className="artifact-hub-open-btn secondary"
                disabled={permissionApplyingGovernanceRequest}
                onClick={() => {
                  void onDismissPermissionGovernanceRequest();
                }}
              >
                Dismiss request
              </button>
            ) : null}
            <button
              type="button"
              className="artifact-hub-open-btn secondary"
              onClick={() =>
                void openReviewConnectorPolicy(
                  permissionGovernanceRequest.connectorId || null,
                )
              }
            >
              Review in Chat
            </button>
          </div>
        </section>
      ) : null}

      <section className="artifact-hub-permissions-card">
        <div className="artifact-hub-permissions-card__head">
          <strong>Session permission profiles</strong>
          <span className="artifact-hub-policy-pill">
            {currentProfile?.label ?? "Custom posture"}
          </span>
        </div>
        <p>
          Switch between curated runtime authority profiles. Connector-specific
          overrides stay intact while the session baseline changes.
        </p>
        <p className="artifact-hub-permissions-shortcuts">
          Quick apply: Alt+1 Safer review, Alt+2 Guided default, Alt+3
          Autonomous, Alt+4 Expert.
        </p>
        <div className="artifact-hub-permissions-profile-list">
          {permissionProfiles.map((profile) => {
            const isCurrent = permissionCurrentProfileId === profile.id;
            const isApplying = permissionApplyingProfileId === profile.id;
            const shortcutLabel = PERMISSION_PROFILE_SHORTCUTS[profile.id];
            const previewDeck = buildPolicyIntentDeltaDeck(
              permissionPolicyState,
              applySessionPermissionProfile(permissionPolicyState, profile.id),
              null,
              {
                baselineLabel: currentProfile?.label ?? "Current posture",
                nextLabel: profile.label,
              },
            );

            return (
              <article
                key={profile.id}
                className={`artifact-hub-permissions-profile${
                  isCurrent ? " is-active" : ""
                }`}
              >
                <div className="artifact-hub-permissions-profile__head">
                  <div>
                    <strong>{profile.label}</strong>
                    <p>{profile.summary}</p>
                  </div>
                  <div className="artifact-hub-permissions-profile__badges">
                    <span className="artifact-hub-policy-pill">
                      {shortcutLabel}
                    </span>
                    <span className="artifact-hub-policy-pill">
                      {isCurrent
                        ? "Current"
                        : previewDeck.items.length > 0
                          ? `${previewDeck.items.length} changes`
                          : "Matches current"}
                    </span>
                  </div>
                </div>
                <p>{profile.detail}</p>
                {previewDeck.items.length > 0 ? (
                  <div className="artifact-hub-permissions-list">
                    {previewDeck.items.slice(0, 3).map((item) => (
                      <div
                        key={`${profile.id}:${item.id}`}
                        className="artifact-hub-permissions-list__row"
                      >
                        <div>
                          <strong>{item.label}</strong>
                          <p>{item.detail}</p>
                        </div>
                        <span>
                          {item.baseline}
                          {" -> "}
                          {item.next}
                        </span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="artifact-hub-empty">
                    This profile already matches the current session posture.
                  </p>
                )}
                <div className="artifact-hub-permissions-card__actions">
                  <button
                    type="button"
                    className="artifact-hub-open-btn"
                    disabled={
                      isCurrent || isApplying || !onApplyPermissionProfile
                    }
                    aria-label={
                      isCurrent
                        ? `${profile.label} is the current permission profile`
                        : isApplying
                          ? `Applying ${profile.label} permission profile`
                          : `Apply ${profile.label} permission profile`
                    }
                    title={
                      isCurrent
                        ? `${profile.label} is current`
                        : `Apply ${profile.label} profile (${shortcutLabel})`
                    }
                    data-profile-id={profile.id}
                    onClick={() => {
                      if (!onApplyPermissionProfile) {
                        return;
                      }
                      void onApplyPermissionProfile(profile.id);
                    }}
                  >
                    {isApplying
                      ? `Applying ${profile.label}...`
                      : isCurrent
                        ? `${profile.label} is current`
                        : `Apply ${profile.label}`}
                  </button>
                </div>
              </article>
            );
          })}
        </div>
      </section>

      <section
        className={`artifact-hub-permissions-card ${
          authorityAutomationPlan.tone === "review"
            ? "artifact-hub-permissions-card--alert"
            : ""
        }`}
      >
        <div className="artifact-hub-permissions-card__head">
          <strong>{authorityAutomationPlan.statusLabel}</strong>
          <span className="artifact-hub-policy-pill">
            {humanizeStatus(authorityAutomationPlan.tone)}
          </span>
        </div>
        <p>{authorityAutomationPlan.detail}</p>
        <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
          {authorityAutomationPlan.checklist.map((item) => (
            <span key={item}>{item}</span>
          ))}
        </div>
        <div className="artifact-hub-permissions-card__actions">
          {authorityAutomationPlan.recommendedProfileId &&
          onApplyPermissionProfile ? (
            <button
              type="button"
              className="artifact-hub-open-btn"
              disabled={
                permissionApplyingProfileId ===
                authorityAutomationPlan.recommendedProfileId
              }
              onClick={() => {
                void onApplyPermissionProfile(
                  authorityAutomationPlan.recommendedProfileId!,
                );
              }}
            >
              {permissionApplyingProfileId ===
              authorityAutomationPlan.recommendedProfileId
                ? `Applying ${humanizeStatus(
                    authorityAutomationPlan.recommendedProfileId,
                  )}...`
                : authorityAutomationPlan.primaryActionLabel}
            </button>
          ) : null}
          {authorityAutomationPlan.recommendedView && onOpenView ? (
            <button
              type="button"
              className="artifact-hub-open-btn secondary"
              onClick={() =>
                onOpenView(authorityAutomationPlan.recommendedView!)
              }
            >
              {authorityAutomationPlan.recommendedView === "permissions"
                ? "Focus permissions"
                : "Review hooks"}
            </button>
          ) : null}
          <button
            type="button"
            className="artifact-hub-open-btn secondary"
            onClick={() => void openReviewConnectorPolicy(focusedConnectorId)}
          >
            Open Chat Policy
          </button>
        </div>
      </section>

      <section className="artifact-hub-permissions-card">
        <div className="artifact-hub-permissions-card__head">
          <strong>Remembered approvals</strong>
          <span className="artifact-hub-policy-pill">
            {rememberedDecisionCount} active
          </span>
        </div>
        <p>
          Shield approval decisions remembered for repeated connector runs in
          the same governed scope.
        </p>
        <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
          <span>{rememberedDecisionCount} remembered</span>
          <span>{recentHookReceiptCount} recent hook receipts</span>
          <span>Store: runtime authority memory</span>
        </div>
        {permissionRememberedApprovals?.decisions.length ? (
          <div className="artifact-hub-generic-list">
            {permissionRememberedApprovals.decisions.map((decision) => {
              const broadenedScope =
                decision.scopeMode === "connector_policy_family";
              return (
                <article
                  className="artifact-hub-generic-row"
                  key={decision.decisionId}
                >
                  <div className="artifact-hub-generic-meta">
                    <span>{humanizeStatus(decision.status)}</span>
                    <span>{decision.sourceLabel}</span>
                    <span>{decision.matchCount} matches</span>
                  </div>
                  <div className="artifact-hub-generic-title">
                    {decision.actionLabel}
                  </div>
                  <p className="artifact-hub-generic-summary">
                    {decision.scopeLabel} ·{" "}
                    {approvalScopeModeLabel(
                      decision.scopeMode,
                      decision.policyFamily,
                    )}{" "}
                    · created {formatSessionTimeAgo(decision.createdAtMs)}
                    {decision.lastMatchedAtMs
                      ? ` · last used ${formatSessionTimeAgo(
                          decision.lastMatchedAtMs,
                        )}`
                      : ""}
                    {decision.expiresAtMs
                      ? ` · expires ${formatSessionTimeAgo(decision.expiresAtMs)}`
                      : " · never expires"}
                  </p>
                  <div className="artifact-hub-permissions-card__actions">
                    {onSetRememberedApprovalScopeMode ? (
                      <button
                        type="button"
                        className="artifact-hub-open-btn secondary"
                        onClick={() => {
                          void onSetRememberedApprovalScopeMode(
                            decision.decisionId,
                            broadenedScope
                              ? "exact_action"
                              : "connector_policy_family",
                          );
                        }}
                      >
                        {broadenedScope
                          ? "Narrow to exact action"
                          : `Broaden to ${humanizeStatus(
                              decision.policyFamily,
                            )} family`}
                      </button>
                    ) : null}
                    {onSetRememberedApprovalExpiry ? (
                      <button
                        type="button"
                        className="artifact-hub-open-btn secondary"
                        onClick={() => {
                          void onSetRememberedApprovalExpiry(
                            decision.decisionId,
                            decision.expiresAtMs
                              ? null
                              : Date.now() + 24 * 60 * 60 * 1000,
                          );
                        }}
                      >
                        {decision.expiresAtMs
                          ? "Never expire"
                          : "Expire in 24h"}
                      </button>
                    ) : null}
                    {onForgetRememberedApproval ? (
                      <button
                        type="button"
                        className="artifact-hub-open-btn secondary"
                        onClick={() => {
                          void onForgetRememberedApproval(decision.decisionId);
                        }}
                      >
                        Revoke remembered approval
                      </button>
                    ) : null}
                    <button
                      type="button"
                      className="artifact-hub-open-btn"
                      onClick={() =>
                        void openReviewConnectorPolicy(decision.connectorId)
                      }
                    >
                      Open Chat Policy
                    </button>
                  </div>
                </article>
              );
            })}
          </div>
        ) : (
          <p className="artifact-hub-empty">
            No approvals have been remembered yet. The first remembered approval
            will appear here after an operator approves a rememberable Shield
            request.
          </p>
        )}
      </section>

      <section className="artifact-hub-task-section">
        <div className="artifact-hub-task-section-head">
          <span>Permission hook receipts</span>
          <span>{recentHookReceiptCount}</span>
        </div>
        {permissionRememberedApprovals?.recentReceipts.length ? (
          <div className="artifact-hub-generic-list">
            {permissionRememberedApprovals.recentReceipts.map((receipt) => (
              <article
                className="artifact-hub-generic-row"
                key={receipt.receiptId}
              >
                <div className="artifact-hub-generic-meta">
                  <span>{humanizeStatus(receipt.hookKind)}</span>
                  <span>{humanizeStatus(receipt.status)}</span>
                  <span>{formatSessionTimeAgo(receipt.timestampMs)}</span>
                </div>
                <div className="artifact-hub-generic-title">
                  {receipt.connectorId} · {receipt.actionId}
                </div>
                <p className="artifact-hub-generic-summary">
                  {receipt.summary}
                </p>
              </article>
            ))}
          </div>
        ) : (
          <p className="artifact-hub-empty">
            Hook receipts will appear here when a blocker escalates, a
            remembered approval auto-matches, expires, misses scope, or is
            revoked.
          </p>
        )}
      </section>

      <div className="artifact-hub-permissions-grid">
        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>{focusedScopeLabel}</strong>
            <span className="artifact-hub-policy-pill">Current posture</span>
          </div>
          <p>
            Effective runtime permission posture for{" "}
            {focusedConnectorId ? "the focused connector" : "the active shell"}.
          </p>
          <div className="artifact-hub-permissions-decisions">
            {policyRows.map((row) => (
              <div
                key={row.id}
                className={`artifact-hub-permissions-chip is-${row.tone}`}
              >
                <span>{row.label}</span>
                <strong>{row.value}</strong>
              </div>
            ))}
          </div>
          <div className="artifact-hub-permissions-card__actions">
            {onRefreshPermissions ? (
              <button
                type="button"
                className="artifact-hub-open-btn"
                onClick={() => {
                  void onRefreshPermissions();
                }}
              >
                Refresh posture
              </button>
            ) : null}
            <button
              type="button"
              className="artifact-hub-open-btn"
              onClick={() => void openReviewConnectorPolicy(focusedConnectorId)}
            >
              Open Chat Policy
            </button>
          </div>
        </section>

        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>Permission simulation</strong>
            <span className="artifact-hub-policy-pill">
              {simulationDeck.summary.auto} auto · {simulationDeck.summary.gate}{" "}
              gate
            </span>
          </div>
          <p>{simulationDeck.artifactHandling.detail}</p>
          <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
            <span>{simulationDeck.summary.auto} auto</span>
            <span>{simulationDeck.summary.gate} gate</span>
            <span>{simulationDeck.summary.deny} deny</span>
            <span>{simulationDeck.artifactHandling.label}</span>
          </div>
          {deltaDeck.items.length > 0 ? (
            <div className="artifact-hub-permissions-list">
              {deltaDeck.items.slice(0, 4).map((item) => (
                <div
                  key={item.id}
                  className="artifact-hub-permissions-list__row"
                >
                  <strong>{item.label}</strong>
                  <span>
                    {item.baseline}
                    {" -> "}
                    {item.next}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <p className="artifact-hub-empty">
              No connector-specific widening from the baseline is active.
            </p>
          )}
          <div className="artifact-hub-permissions-list">
            {simulationDeck.scenarios.map((scenario) => (
              <div
                key={scenario.id}
                className="artifact-hub-permissions-list__row"
              >
                <div>
                  <strong>{scenario.label}</strong>
                  <p>{scenario.detail}</p>
                </div>
                <span>
                  {permissionSimulationOutcomeLabel(scenario.outcome)}
                </span>
              </div>
            ))}
            <div className="artifact-hub-permissions-list__row">
              <div>
                <strong>Artifact handling</strong>
                <p>{simulationDeck.artifactHandling.detail}</p>
              </div>
              <span>{simulationDeck.artifactHandling.label}</span>
            </div>
          </div>
        </section>
      </div>

      {overrideReviewCards.length > 0 ? (
        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>Connector override review</strong>
            <span className="artifact-hub-policy-pill">
              {overrideReviewCards.length} tracked
            </span>
          </div>
          <p>
            Review connector-scoped authority changes, apply pending governance
            requests in place, and edit active overrides without leaving the
            runtime-backed Chat surface.
          </p>
          <div className="artifact-hub-permissions-profile-list">
            {overrideReviewCards.map((card) => {
              const isEditing =
                permissionEditingConnectorId === card.connectorId;
              return (
                <article
                  key={`${card.source}:${card.connectorId}`}
                  className="artifact-hub-permissions-profile"
                >
                  <div className="artifact-hub-permissions-profile__head">
                    <div>
                      <strong>{card.label}</strong>
                      <p>{card.headline}</p>
                    </div>
                    <div className="artifact-hub-permissions-profile__badges">
                      <span className="artifact-hub-policy-pill">
                        {card.source === "governance_request"
                          ? "Governance preview"
                          : "Live override"}
                      </span>
                      <span className="artifact-hub-policy-pill">
                        {card.simulationDeck.summary.auto} auto ·{" "}
                        {card.simulationDeck.summary.gate} gate
                      </span>
                    </div>
                  </div>
                  <p>{card.detail}</p>
                  {card.deltaDeck.items.length > 0 ? (
                    <div className="artifact-hub-permissions-list">
                      {card.deltaDeck.items.slice(0, 3).map((item) => (
                        <div
                          key={`${card.connectorId}:${item.id}`}
                          className="artifact-hub-permissions-list__row"
                        >
                          <div>
                            <strong>{item.label}</strong>
                            <p>{item.detail}</p>
                          </div>
                          <span>
                            {item.baseline}
                            {" -> "}
                            {item.next}
                          </span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="artifact-hub-empty">
                      This connector is currently aligned with its baseline
                      posture.
                    </p>
                  )}
                  {card.canEdit ? (
                    <div className="artifact-hub-permissions-form">
                      <PermissionPolicySelect
                        label="Read actions"
                        value={card.effectivePolicy.reads}
                        options={PERMISSION_DECISION_OPTIONS}
                        disabled={isEditing || !onUpdatePermissionOverride}
                        onChange={(value) => {
                          if (!onUpdatePermissionOverride) {
                            return;
                          }
                          void onUpdatePermissionOverride(card.connectorId, {
                            reads: value,
                          });
                        }}
                      />
                      <PermissionPolicySelect
                        label="Write actions"
                        value={card.effectivePolicy.writes}
                        options={PERMISSION_DECISION_OPTIONS}
                        disabled={isEditing || !onUpdatePermissionOverride}
                        onChange={(value) => {
                          if (!onUpdatePermissionOverride) {
                            return;
                          }
                          void onUpdatePermissionOverride(card.connectorId, {
                            writes: value,
                          });
                        }}
                      />
                      <PermissionPolicySelect
                        label="Admin actions"
                        value={card.effectivePolicy.admin}
                        options={PERMISSION_DECISION_OPTIONS}
                        disabled={isEditing || !onUpdatePermissionOverride}
                        onChange={(value) => {
                          if (!onUpdatePermissionOverride) {
                            return;
                          }
                          void onUpdatePermissionOverride(card.connectorId, {
                            admin: value,
                          });
                        }}
                      />
                      <PermissionPolicySelect
                        label="Expert / raw actions"
                        value={card.effectivePolicy.expert}
                        options={PERMISSION_DECISION_OPTIONS}
                        disabled={isEditing || !onUpdatePermissionOverride}
                        onChange={(value) => {
                          if (!onUpdatePermissionOverride) {
                            return;
                          }
                          void onUpdatePermissionOverride(card.connectorId, {
                            expert: value,
                          });
                        }}
                      />
                      <PermissionPolicySelect
                        label="Automations"
                        value={card.effectivePolicy.automations}
                        options={PERMISSION_AUTOMATION_OPTIONS}
                        disabled={isEditing || !onUpdatePermissionOverride}
                        onChange={(value) => {
                          if (!onUpdatePermissionOverride) {
                            return;
                          }
                          void onUpdatePermissionOverride(card.connectorId, {
                            automations: value,
                          });
                        }}
                      />
                      <PermissionPolicySelect
                        label="Artifact handling"
                        value={card.effectivePolicy.dataHandling}
                        options={PERMISSION_DATA_OPTIONS}
                        disabled={isEditing || !onUpdatePermissionOverride}
                        onChange={(value) => {
                          if (!onUpdatePermissionOverride) {
                            return;
                          }
                          void onUpdatePermissionOverride(card.connectorId, {
                            dataHandling: value,
                          });
                        }}
                      />
                    </div>
                  ) : null}
                  <div className="artifact-hub-permissions-card__actions">
                    {card.canEdit && onResetPermissionOverride ? (
                      <button
                        type="button"
                        className="artifact-hub-open-btn"
                        disabled={isEditing}
                        onClick={() => {
                          void onResetPermissionOverride(card.connectorId);
                        }}
                      >
                        {isEditing
                          ? "Saving override..."
                          : "Return to global baseline"}
                      </button>
                    ) : null}
                    {card.source === "governance_request" &&
                    card.canApplyGovernanceRequest &&
                    onApplyPermissionGovernanceRequest ? (
                      <button
                        type="button"
                        className="artifact-hub-open-btn"
                        disabled={permissionApplyingGovernanceRequest}
                        onClick={() => {
                          void onApplyPermissionGovernanceRequest();
                        }}
                      >
                        {permissionApplyingGovernanceRequest
                          ? "Applying request..."
                          : "Apply requested posture"}
                      </button>
                    ) : null}
                    {card.source === "governance_request" &&
                    onDismissPermissionGovernanceRequest ? (
                      <button
                        type="button"
                        className="artifact-hub-open-btn secondary"
                        disabled={permissionApplyingGovernanceRequest}
                        onClick={() => {
                          void onDismissPermissionGovernanceRequest();
                        }}
                      >
                        Dismiss request
                      </button>
                    ) : null}
                    <button
                      type="button"
                      className="artifact-hub-open-btn secondary"
                      onClick={() =>
                        void openReviewConnectorPolicy(card.connectorId)
                      }
                    >
                      Open Chat Policy
                    </button>
                  </div>
                </article>
              );
            })}
          </div>
        </section>
      ) : (
        <p className="artifact-hub-empty">
          No connector-specific overrides or pending connector governance
          requests are active. The shell is currently using the global runtime
          policy baseline.
        </p>
      )}
    </div>
  );
}
