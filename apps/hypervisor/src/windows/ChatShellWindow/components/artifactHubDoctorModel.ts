export type DoctorTone = "ready" | "setup" | "attention";

export type DoctorActionView =
  | "branch"
  | "compact"
  | "hooks"
  | "permissions"
  | "plugins"
  | "privacy"
  | "remote_env";

export interface DoctorCard {
  id:
    | "runtime"
    | "authority"
    | "extensions"
    | "workspace"
    | "durability"
    | "automation";
  label: string;
  tone: DoctorTone;
  value: string;
  detail: string;
  meta: string[];
  actionView?: DoctorActionView;
}

export interface BuildDoctorOverviewInput {
  runtime: {
    status: string;
    error: string | null;
    pendingApprovalCount: number;
    pendingControlCount: number;
    activeIssueCount: number;
    liveJobCount: number;
    backendCount: number;
    healthyBackendCount: number;
    degradedBackendCount: number;
  };
  authority: {
    permissionsStatus: string;
    permissionsError: string | null;
    pendingGovernance: boolean;
    activeOverrideCount: number;
    rememberedApprovalCount: number;
    requiresPrivacyReview: boolean;
    redactedOverrideCount: number;
  };
  extensions: {
    pluginCount: number;
    blockedPluginCount: number;
    reviewRequiredPluginCount: number;
    criticalUpdateCount: number;
    refreshFailedCount: number;
    updateAvailableCount: number;
    nonconformantChannelCount: number;
    nonconformantSourceCount: number;
  };
  workspace: {
    isRepo: boolean;
    changedFileCount: number;
    dirty: boolean;
    aheadCount: number;
    behindCount: number;
    worktreeRiskLabel: string | null;
  };
  durability: {
    status: string;
    error: string | null;
    activeSession: boolean;
    recordCount: number;
    shouldCompact: boolean;
    recommendedPolicyLabel: string | null;
    recommendationReasons: string[];
    resumeSafetyStatus: string | null;
  };
  automation: {
    remoteEnvStatus: string;
    remoteEnvError: string | null;
    bindingCount: number;
    redactedBindingCount: number;
    secretBindingCount: number;
    hooksStatus: string;
    hooksError: string | null;
    activeHookCount: number;
    disabledHookCount: number;
    hookReceiptCount: number;
  };
}

export interface DoctorOverview {
  tone: DoctorTone;
  headline: string;
  detail: string;
  reviewCount: number;
  watchCount: number;
  cards: DoctorCard[];
}

const DOCTOR_TONE_RANK: Record<DoctorTone, number> = {
  ready: 0,
  setup: 1,
  attention: 2,
};

function pluralize(value: number, singular: string, plural: string): string {
  return value === 1 ? singular : plural;
}

function strongestTone(values: DoctorTone[]): DoctorTone {
  return values.reduce<DoctorTone>((current, candidate) => {
    return DOCTOR_TONE_RANK[candidate] > DOCTOR_TONE_RANK[current]
      ? candidate
      : current;
  }, "ready");
}

function runtimeCard(
  input: BuildDoctorOverviewInput["runtime"],
): DoctorCard {
  const hasBlockingIssue =
    Boolean(input.error) ||
    input.activeIssueCount > 0 ||
    input.pendingApprovalCount > 0 ||
    input.degradedBackendCount > 0;
  const hasQueuedWork =
    input.liveJobCount > 0 ||
    input.pendingControlCount > 0 ||
    input.status === "loading";
  const tone: DoctorTone = hasBlockingIssue
    ? "attention"
    : hasQueuedWork
      ? "setup"
      : "ready";
  const value = input.error
    ? "Snapshot unavailable"
    : input.activeIssueCount > 0
      ? `${input.activeIssueCount} ${pluralize(input.activeIssueCount, "issue", "issues")}`
      : input.liveJobCount > 0
        ? `${input.liveJobCount} live ${pluralize(input.liveJobCount, "job", "jobs")}`
        : input.backendCount > 0
          ? `${input.healthyBackendCount}/${input.backendCount} backends healthy`
          : "Runtime idle";
  const detail = input.error
    ? input.error
    : input.activeIssueCount > 0
      ? "Kernel-owned runtime issues are active and should be reviewed before trusting the shell posture."
      : input.pendingApprovalCount > 0
        ? "Managed runtime work is waiting on operator approval before the kernel can advance."
        : input.degradedBackendCount > 0
          ? "One or more managed backends are not healthy yet."
          : input.liveJobCount > 0 || input.pendingControlCount > 0
            ? "The runtime is actively changing state, so diagnostics are still settling."
            : "Managed runtime backends and jobs are currently stable.";
  return {
    id: "runtime",
    label: "Runtime",
    tone,
    value,
    detail,
    meta: [
      `${input.pendingApprovalCount} approvals`,
      `${input.pendingControlCount} controls`,
      `${input.backendCount} tracked backends`,
    ],
  };
}

function authorityCard(
  input: BuildDoctorOverviewInput["authority"],
): DoctorCard {
  const needsImmediateReview =
    Boolean(input.permissionsError) ||
    input.pendingGovernance ||
    input.requiresPrivacyReview;
  const hasActiveContext =
    input.activeOverrideCount > 0 ||
    input.rememberedApprovalCount > 0 ||
    input.redactedOverrideCount > 0;
  const tone: DoctorTone = needsImmediateReview
    ? "attention"
    : hasActiveContext || input.permissionsStatus === "loading"
      ? "setup"
      : "ready";
  const value = input.permissionsError
    ? "Policy sync unavailable"
    : input.pendingGovernance
      ? "Governance review pending"
      : input.requiresPrivacyReview
        ? "Privacy review required"
        : input.activeOverrideCount > 0
          ? `${input.activeOverrideCount} active ${pluralize(input.activeOverrideCount, "override", "overrides")}`
          : input.rememberedApprovalCount > 0
            ? `${input.rememberedApprovalCount} remembered ${pluralize(input.rememberedApprovalCount, "grant", "grants")}`
            : "Policy posture synced";
  const detail = input.permissionsError
    ? input.permissionsError
    : input.pendingGovernance
      ? "A governed authority change is waiting for operator review."
      : input.requiresPrivacyReview
        ? "The current session posture requires privacy review before wider trust should be assumed."
        : hasActiveContext
          ? "Authority is synced, but scoped overrides or remembered approvals are currently shaping the run."
          : "Shield policy, remembered approvals, and privacy posture are aligned.";
  return {
    id: "authority",
    label: "Authority",
    tone,
    value,
    detail,
    meta: [
      `${input.activeOverrideCount} overrides`,
      `${input.rememberedApprovalCount} remembered approvals`,
      `${input.redactedOverrideCount} redacted connectors`,
    ],
    actionView: input.requiresPrivacyReview ? "privacy" : "permissions",
  };
}

function extensionsCard(
  input: BuildDoctorOverviewInput["extensions"],
): DoctorCard {
  const needsImmediateReview =
    input.blockedPluginCount > 0 ||
    input.criticalUpdateCount > 0 ||
    input.refreshFailedCount > 0 ||
    input.nonconformantChannelCount > 0 ||
    input.nonconformantSourceCount > 0;
  const hasFollowUp =
    input.reviewRequiredPluginCount > 0 || input.updateAvailableCount > 0;
  const tone: DoctorTone = needsImmediateReview
    ? "attention"
    : hasFollowUp
      ? "setup"
      : "ready";
  const value =
    input.pluginCount > 0
      ? `${input.pluginCount} tracked ${pluralize(input.pluginCount, "plugin", "plugins")}`
      : "No tracked plugins";
  const detail = needsImmediateReview
    ? "Plugin trust, catalog conformance, or update posture needs review before broader runtime load."
    : hasFollowUp
      ? "Plugin posture is stable, but review-required entries or updates are waiting."
      : "Tracked plugins and marketplace signals are currently stable.";
  return {
    id: "extensions",
    label: "Extensions",
    tone,
    value,
    detail,
    meta: [
      `${input.blockedPluginCount} blocked`,
      `${input.reviewRequiredPluginCount} review required`,
      `${input.updateAvailableCount} updates available`,
    ],
    actionView: "plugins",
  };
}

function workspaceCard(
  input: BuildDoctorOverviewInput["workspace"],
): DoctorCard {
  const needsImmediateReview =
    input.isRepo && input.behindCount > 0 && input.dirty;
  const hasActiveRisk =
    !input.isRepo || input.dirty || input.aheadCount > 0 || input.behindCount > 0;
  const tone: DoctorTone = needsImmediateReview
    ? "attention"
    : hasActiveRisk
      ? "setup"
      : "ready";
  const value = !input.isRepo
    ? "No repository"
    : input.changedFileCount > 0
      ? `${input.changedFileCount} changed ${pluralize(input.changedFileCount, "file", "files")}`
      : input.worktreeRiskLabel?.trim() || "Checkout clean";
  const detail = !input.isRepo
    ? "This session is not rooted in a git checkout yet, so branch and worktree diagnostics stay limited."
    : needsImmediateReview
      ? "Local modifications are present while the checkout is also behind upstream."
      : input.dirty
        ? "Local modifications are shaping the active worktree posture."
        : input.behindCount > 0
          ? "The checkout is behind upstream even though the worktree is clean."
          : input.aheadCount > 0
            ? "The checkout has local commits that are not reflected upstream yet."
            : "The active checkout is clean and in sync with retained branch posture.";
  return {
    id: "workspace",
    label: "Workspace",
    tone,
    value,
    detail,
    meta: [
      `${input.aheadCount} ahead`,
      `${input.behindCount} behind`,
      `${input.changedFileCount} changed files`,
    ],
    actionView: "branch",
  };
}

function durabilityCard(
  input: BuildDoctorOverviewInput["durability"],
): DoctorCard {
  const needsImmediateReview = Boolean(input.error) || input.shouldCompact;
  const hasFollowUp =
    !input.activeSession || input.recordCount === 0 || input.status === "loading";
  const tone: DoctorTone = needsImmediateReview
    ? "attention"
    : hasFollowUp
      ? "setup"
      : "ready";
  const value = input.error
    ? "Compaction unavailable"
    : input.shouldCompact
      ? input.recommendedPolicyLabel || "Compaction recommended"
      : input.recordCount > 0
        ? `${input.recordCount} retained ${pluralize(input.recordCount, "snapshot", "snapshots")}`
        : input.activeSession
          ? "No retained snapshots yet"
          : "No active session";
  const detail = input.error
    ? input.error
    : input.shouldCompact
      ? "Long-session durability would improve if the active session is compacted now."
      : input.recordCount > 0
        ? "Retained compaction records are available for replay-safe resume."
        : input.activeSession
          ? "The session is active, but no retained compaction record exists yet."
          : "Open or resume a session to inspect durability posture.";
  return {
    id: "durability",
    label: "Durability",
    tone,
    value,
    detail,
    meta: [
      input.resumeSafetyStatus
        ? `Resume safety: ${input.resumeSafetyStatus}`
        : "Resume safety: unknown",
      `${input.recommendationReasons.length} recommendation signals`,
      `${input.recordCount} retained records`,
    ],
    actionView: "compact",
  };
}

function automationCard(
  input: BuildDoctorOverviewInput["automation"],
): DoctorCard {
  const needsImmediateReview =
    Boolean(input.remoteEnvError) || Boolean(input.hooksError);
  const hasFollowUp =
    input.redactedBindingCount > 0 ||
    input.disabledHookCount > 0 ||
    input.remoteEnvStatus === "loading" ||
    input.hooksStatus === "loading";
  const tone: DoctorTone = needsImmediateReview
    ? "attention"
    : hasFollowUp
      ? "setup"
      : "ready";
  const value = needsImmediateReview
    ? "Automation snapshot unavailable"
    : `${input.activeHookCount} active ${pluralize(input.activeHookCount, "hook", "hooks")}`;
  const detail = input.remoteEnvError || input.hooksError
    ? input.remoteEnvError || input.hooksError || "Automation posture unavailable."
    : hasFollowUp
      ? "Remote environment redaction or hook posture still deserves review."
      : "Hook contributions and runtime environment posture are currently stable.";
  return {
    id: "automation",
    label: "Automation",
    tone,
    value,
    detail,
    meta: [
      `${input.bindingCount} env bindings`,
      `${input.redactedBindingCount} redacted`,
      `${input.hookReceiptCount} hook receipts`,
    ],
    actionView:
      input.redactedBindingCount > 0 || input.secretBindingCount > 0
        ? "remote_env"
        : "hooks",
  };
}

export function buildDoctorOverview(
  input: BuildDoctorOverviewInput,
): DoctorOverview {
  const cards = [
    runtimeCard(input.runtime),
    authorityCard(input.authority),
    extensionsCard(input.extensions),
    workspaceCard(input.workspace),
    durabilityCard(input.durability),
    automationCard(input.automation),
  ];
  const reviewCount = cards.filter((card) => card.tone === "attention").length;
  const watchCount = cards.filter((card) => card.tone === "setup").length;
  const tone = strongestTone(cards.map((card) => card.tone));
  const headline =
    reviewCount > 0
      ? `${reviewCount} ${pluralize(reviewCount, "area needs", "areas need")} review`
      : watchCount > 0
        ? `${watchCount} ${pluralize(watchCount, "area is", "areas are")} worth checking`
        : "Tracked shell diagnostics look healthy";
  const detail =
    reviewCount > 0
      ? "Kernel-owned runtime, authority, or integrity posture still has actionable issues before the session should be treated as fully healthy."
      : watchCount > 0
        ? "The shared runtime is stable enough to continue, but there are still setup or continuity signals worth checking."
        : "Runtime, authority, durability, and extension posture are aligned across the tracked Chat projections.";

  return {
    tone,
    headline,
    detail,
    reviewCount,
    watchCount,
    cards,
  };
}
