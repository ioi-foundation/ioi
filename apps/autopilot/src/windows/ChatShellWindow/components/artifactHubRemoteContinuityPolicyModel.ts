import type {
  ArtifactHubViewKey,
  LocalEngineManagedSettingsSnapshot,
  SessionRemoteEnvSnapshot,
  SessionServerSnapshot,
} from "../../../types";
import type { MobileOverview } from "./artifactHubMobileModel";
import { buildRemoteContinuityGovernanceOverview } from "./artifactHubRemoteContinuityGovernanceModel";
import type {
  MobileEvidenceContinuityActionState,
  ChatRemoteContinuityLaunchRequest,
} from "./artifactHubRemoteContinuityModel";

export type RemoteContinuityPolicyTone =
  | "ready"
  | "review"
  | "setup"
  | "attention";

export type RemoteContinuityPolicyAction =
  | {
      kind: "launch_repl";
      label: string;
      detail: string;
      launchRequest: ChatRemoteContinuityLaunchRequest;
    }
  | {
      kind: "open_view";
      label: string;
      detail: string;
      view: ArtifactHubViewKey;
    }
  | {
      kind: "open_studio_settings";
      label: string;
      detail: string;
    }
  | {
      kind: "refresh_server";
      label: string;
      detail: string;
    };

type RemoteContinuityPolicyLaunchAction = Extract<
  RemoteContinuityPolicyAction,
  { kind: "launch_repl" }
>;

export interface RemoteContinuityPolicyOverview {
  tone: RemoteContinuityPolicyTone;
  statusLabel: string;
  detail: string;
  checklist: string[];
  primaryAction: RemoteContinuityPolicyAction | null;
  secondaryAction: RemoteContinuityPolicyAction | null;
  queuedActions: RemoteContinuityPolicyAction[];
}

function humanizeStatus(value: string | null | undefined): string {
  const text = (value || "").trim().replace(/[_-]+/g, " ");
  if (!text) {
    return "Unknown";
  }
  return text.replace(/\b\w/g, (char) => char.toUpperCase());
}

function managedSettingsPolicyIssue(
  managedSettings: LocalEngineManagedSettingsSnapshot | null | undefined,
): { tone: RemoteContinuityPolicyTone; detail: string } | null {
  if (!managedSettings) {
    return null;
  }

  if (
    /degraded|error|failed/i.test(managedSettings.syncStatus) ||
    managedSettings.refreshError
  ) {
    return {
      tone: "attention",
      detail:
        "Signed managed settings are degraded right now, so remote continuity should confirm the governing control-plane authority before attaching remote session targets.",
    };
  }

  if (
    managedSettings.activeChannelId &&
    managedSettings.localOverrideCount > 0
  ) {
    return {
      tone: "review",
      detail:
        "A signed managed-settings channel is active and local override drift is present, so remote continuity should review the effective control plane before attaching a retained remote target.",
    };
  }

  return null;
}

function remoteEnvPolicyIssue(
  remoteEnvSnapshot: SessionRemoteEnvSnapshot | null | undefined,
): { tone: RemoteContinuityPolicyTone; detail: string } | null {
  if (!remoteEnvSnapshot) {
    return null;
  }

  if (remoteEnvSnapshot.overlappingBindingCount > 0) {
    return {
      tone: "review",
      detail:
        "Remote env posture shows control-plane versus runtime-process binding drift, so continuity should review the current environment diff before attaching a remote shell target.",
    };
  }

  if (
    remoteEnvSnapshot.secretBindingCount > 0 ||
    remoteEnvSnapshot.redactedBindingCount > 0
  ) {
    return {
      tone: "review",
      detail:
        "Remote env posture still includes secret or redacted bindings, so continuity should review the current runtime environment before attaching a remote shell target.",
    };
  }

  return null;
}

function launchAction(input: {
  label: string;
  detail: string;
  launchRequest: ChatRemoteContinuityLaunchRequest;
}): RemoteContinuityPolicyLaunchAction {
  return {
    kind: "launch_repl",
    label: input.label,
    detail: input.detail,
    launchRequest: input.launchRequest,
  };
}

function openViewAction(
  view: ArtifactHubViewKey,
  label: string,
  detail: string,
): RemoteContinuityPolicyAction {
  return {
    kind: "open_view",
    view,
    label,
    detail,
  };
}

function settingsAction(detail: string): RemoteContinuityPolicyAction {
  return {
    kind: "open_studio_settings",
    label: "Review managed settings",
    detail,
  };
}

function refreshServerAction(detail: string): RemoteContinuityPolicyAction {
  return {
    kind: "refresh_server",
    label: "Refresh server snapshot",
    detail,
  };
}

function policyActionKey(action: RemoteContinuityPolicyAction): string {
  switch (action.kind) {
    case "launch_repl":
      return `${action.kind}:${action.launchRequest.source}:${action.launchRequest.mode}:${action.launchRequest.sessionId}`;
    case "open_view":
      return `${action.kind}:${action.view}`;
    case "open_studio_settings":
    case "refresh_server":
    default:
      return `${action.kind}:${action.label}`;
  }
}

function buildActionQueue(
  ...actions: Array<RemoteContinuityPolicyAction | null | undefined>
): RemoteContinuityPolicyAction[] {
  const queue: RemoteContinuityPolicyAction[] = [];
  for (const action of actions) {
    if (!action) {
      continue;
    }
    const key = policyActionKey(action);
    if (
      queue.some((existingAction) => policyActionKey(existingAction) === key)
    ) {
      continue;
    }
    queue.push(action);
  }
  return queue;
}

function mobileLaunchAction(
  mobileAction: MobileEvidenceContinuityActionState | null | undefined,
): RemoteContinuityPolicyLaunchAction | null {
  if (!mobileAction?.launchRequest) {
    return null;
  }
  return launchAction({
    label: mobileAction.chatShellLabel,
    detail: mobileAction.detail,
    launchRequest: mobileAction.launchRequest,
  });
}

function serverPrimaryLaunchAction(
  serverSnapshot: SessionServerSnapshot | null,
): RemoteContinuityPolicyLaunchAction | null {
  const governance = buildRemoteContinuityGovernanceOverview(serverSnapshot);
  if (!governance.primaryAction) {
    return null;
  }
  return launchAction({
    label: governance.primaryAction.label,
    detail: governance.primaryAction.detail,
    launchRequest: governance.primaryAction.launchRequest,
  });
}

function serverSecondaryLaunchAction(
  serverSnapshot: SessionServerSnapshot | null,
): RemoteContinuityPolicyLaunchAction | null {
  const governance = buildRemoteContinuityGovernanceOverview(serverSnapshot);
  if (!governance.secondaryAction) {
    return null;
  }
  return launchAction({
    label: governance.secondaryAction.label,
    detail: governance.secondaryAction.detail,
    launchRequest: governance.secondaryAction.launchRequest,
  });
}

function sharedChecklist(input: {
  managedSettings: LocalEngineManagedSettingsSnapshot | null | undefined;
  remoteEnvSnapshot: SessionRemoteEnvSnapshot | null | undefined;
  serverSnapshot: SessionServerSnapshot | null | undefined;
  mobileOverview?: MobileOverview | null;
  mobileAction?: MobileEvidenceContinuityActionState | null;
}): string[] {
  const managedLabel = input.managedSettings
    ? `Managed settings: ${humanizeStatus(input.managedSettings.syncStatus)}`
    : "Managed settings: local only";
  const overrideLabel = input.managedSettings?.activeChannelId
    ? `${input.managedSettings.localOverrideCount} local overrides`
    : "No managed overrides";
  const remoteEnvLabel = input.remoteEnvSnapshot
    ? `${input.remoteEnvSnapshot.secretBindingCount} secrets · ${input.remoteEnvSnapshot.redactedBindingCount} redacted`
    : "Remote env snapshot pending";
  const serverLabel = input.serverSnapshot
    ? `${input.serverSnapshot.remoteAttachableSessionCount} server attachable · ${input.serverSnapshot.remoteHistoryOnlySessionCount} server review`
    : "Server continuity pending";
  const mobileLabel = input.mobileOverview
    ? `${input.mobileOverview.statusLabel} · ${input.mobileAction?.attachable ? "REPL ready" : "Evidence/review"}`
    : "Mobile continuity pending";

  return [
    managedLabel,
    overrideLabel,
    remoteEnvLabel,
    serverLabel,
    mobileLabel,
  ];
}

export function buildServerRemoteContinuityPolicyOverview(input: {
  serverSnapshot: SessionServerSnapshot | null;
  remoteEnvSnapshot: SessionRemoteEnvSnapshot | null;
  managedSettings: LocalEngineManagedSettingsSnapshot | null;
  mobileOverview?: MobileOverview | null;
  mobileAction?: MobileEvidenceContinuityActionState | null;
}): RemoteContinuityPolicyOverview {
  const mobilePrimary = mobileLaunchAction(input.mobileAction);
  const serverPrimary = serverPrimaryLaunchAction(input.serverSnapshot);
  const serverSecondary = serverSecondaryLaunchAction(input.serverSnapshot);
  const checklist = sharedChecklist(input);

  if (!input.serverSnapshot) {
    const primaryAction = refreshServerAction(
      "Refresh the server snapshot so remote continuity can recover its policy and attach posture.",
    );
    return {
      tone: "setup",
      statusLabel: "Remote continuity policy waiting on server posture",
      detail:
        "Load a server continuity snapshot before the shell can decide whether remote continuity should attach, review, or stay local.",
      checklist,
      primaryAction,
      secondaryAction: mobilePrimary,
      queuedActions: buildActionQueue(primaryAction, mobilePrimary),
    };
  }

  if (!input.serverSnapshot.kernelReachable) {
    const primaryAction = refreshServerAction(
      "Refresh the server snapshot before retrying remote continuity attach.",
    );
    return {
      tone: "attention",
      statusLabel: "Remote continuity must refresh policy before attach",
      detail:
        "The configured remote kernel is unreachable, so continuity should refresh server posture before it attempts another attachable session handoff.",
      checklist,
      primaryAction,
      secondaryAction: mobilePrimary,
      queuedActions: buildActionQueue(primaryAction, mobilePrimary),
    };
  }

  const managedIssue = managedSettingsPolicyIssue(input.managedSettings);
  const remoteEnvIssue = remoteEnvPolicyIssue(input.remoteEnvSnapshot);
  if (managedIssue) {
    const primaryAction = settingsAction(managedIssue.detail);
    const remoteEnvAction = remoteEnvIssue
      ? openViewAction(
          "remote_env",
          "Review remote env",
          remoteEnvIssue.detail,
        )
      : null;
    const secondaryAction = remoteEnvAction ?? serverPrimary ?? mobilePrimary;
    return {
      tone: managedIssue.tone,
      statusLabel: "Managed policy review should lead remote continuity",
      detail: managedIssue.detail,
      checklist,
      primaryAction,
      secondaryAction,
      queuedActions: buildActionQueue(
        primaryAction,
        remoteEnvAction,
        serverPrimary,
        mobilePrimary,
        serverSecondary,
      ),
    };
  }

  if (remoteEnvIssue) {
    const primaryAction = openViewAction(
      "remote_env",
      "Review remote env",
      remoteEnvIssue.detail,
    );
    const secondaryAction = serverPrimary ?? mobilePrimary;
    return {
      tone: remoteEnvIssue.tone,
      statusLabel: "Remote env review should lead remote continuity",
      detail: remoteEnvIssue.detail,
      checklist,
      primaryAction,
      secondaryAction,
      queuedActions: buildActionQueue(
        primaryAction,
        serverPrimary,
        mobilePrimary,
        serverSecondary,
      ),
    };
  }

  if (serverPrimary) {
    const secondaryAction =
      serverSecondary ??
      openViewAction(
        "mobile",
        "Open Mobile continuity",
        "Review retained mobile handoff evidence beside the current remote queue.",
      );
    return {
      tone:
        serverPrimary.launchRequest.mode === "attach" ? "ready" : "review",
      statusLabel:
        serverPrimary.launchRequest.mode === "attach"
          ? "Remote continuity can attach under current policy"
          : "Remote continuity is review-only under current policy",
      detail:
        serverPrimary.launchRequest.mode === "attach"
          ? "Managed settings and remote env posture are aligned enough that the retained remote queue can attach directly through the shared REPL."
          : "Current policy keeps continuity in review mode, so the retained remote queue should stay evidence-first until an attachable run is retained again.",
      checklist,
      primaryAction: serverPrimary,
      secondaryAction,
      queuedActions: buildActionQueue(
        serverPrimary,
        mobilePrimary,
        serverSecondary,
        secondaryAction,
      ),
    };
  }

  if (mobilePrimary) {
    const secondaryAction = openViewAction(
      "mobile",
      "Open Mobile continuity",
      "Inspect the retained handoff evidence and reopen it through the shared runtime.",
    );
    return {
      tone:
        mobilePrimary.launchRequest.mode === "attach" ? "ready" : "review",
      statusLabel: "Mobile continuity is available while the server queue is empty",
      detail:
        "Server continuity does not currently expose a governable queue, but retained mobile evidence can still reopen shared continuity without inventing shell-local state.",
      checklist,
      primaryAction: mobilePrimary,
      secondaryAction,
      queuedActions: buildActionQueue(mobilePrimary, serverPrimary, secondaryAction),
    };
  }

  const primaryAction = openViewAction(
    "mobile",
    "Open Mobile continuity",
    "Check retained mobile handoff evidence while the server queue is still empty.",
  );
  return {
    tone: "setup",
    statusLabel: "No governed remote continuity target yet",
    detail:
      "Remote continuity does not yet have an attachable or review-only retained target, so the shell is waiting on new remote or mobile evidence.",
    checklist,
    primaryAction,
    secondaryAction: null,
    queuedActions: buildActionQueue(primaryAction),
  };
}

export function buildMobileRemoteContinuityPolicyOverview(input: {
  mobileOverview: MobileOverview;
  mobileAction: MobileEvidenceContinuityActionState;
  serverSnapshot: SessionServerSnapshot | null;
  remoteEnvSnapshot: SessionRemoteEnvSnapshot | null;
  managedSettings: LocalEngineManagedSettingsSnapshot | null;
}): RemoteContinuityPolicyOverview {
  const mobilePrimary = mobileLaunchAction(input.mobileAction);
  const serverPrimary = serverPrimaryLaunchAction(input.serverSnapshot);
  const checklist = sharedChecklist(input);

  const managedIssue = managedSettingsPolicyIssue(input.managedSettings);
  const remoteEnvIssue = remoteEnvPolicyIssue(input.remoteEnvSnapshot);
  if (managedIssue) {
    const primaryAction = settingsAction(managedIssue.detail);
    const remoteEnvAction = remoteEnvIssue
      ? openViewAction(
          "remote_env",
          "Review remote env",
          remoteEnvIssue.detail,
        )
      : null;
    const secondaryAction = remoteEnvAction ?? mobilePrimary ?? serverPrimary;
    return {
      tone: managedIssue.tone,
      statusLabel: "Managed policy review should lead handoff continuity",
      detail: managedIssue.detail,
      checklist,
      primaryAction,
      secondaryAction,
      queuedActions: buildActionQueue(
        primaryAction,
        remoteEnvAction,
        mobilePrimary,
        serverPrimary,
      ),
    };
  }

  if (remoteEnvIssue) {
    const primaryAction = openViewAction(
      "remote_env",
      "Review remote env",
      remoteEnvIssue.detail,
    );
    const secondaryAction = mobilePrimary ?? serverPrimary;
    return {
      tone: remoteEnvIssue.tone,
      statusLabel: "Remote env review should lead handoff continuity",
      detail: remoteEnvIssue.detail,
      checklist,
      primaryAction,
      secondaryAction,
      queuedActions: buildActionQueue(
        primaryAction,
        mobilePrimary,
        serverPrimary,
      ),
    };
  }

  if (mobilePrimary) {
    const secondaryAction =
      serverPrimary ??
      openViewAction(
        "server",
        "Inspect Server continuity",
        "Inspect the shared remote queue and current kernel continuity posture.",
      );
    return {
      tone:
        mobilePrimary.launchRequest.mode === "attach" ? "ready" : "review",
      statusLabel:
        mobilePrimary.launchRequest.mode === "attach"
          ? "Mobile handoff can resume under current policy"
          : "Mobile handoff is review-only under current policy",
      detail:
        mobilePrimary.launchRequest.mode === "attach"
          ? "The retained handoff target is attachable and the current managed-settings plus remote-env posture does not require extra review first."
          : "The retained handoff stays review-first right now, so Chat should reopen it without attempting PTY attach.",
      checklist,
      primaryAction: mobilePrimary,
      secondaryAction,
      queuedActions: buildActionQueue(mobilePrimary, serverPrimary, secondaryAction),
    };
  }

  if (serverPrimary) {
    const secondaryAction = openViewAction(
      "server",
      "Inspect Server continuity",
      "Inspect the remote continuity queue and current kernel posture.",
    );
    return {
      tone:
        serverPrimary.launchRequest.mode === "attach" ? "ready" : "review",
      statusLabel: "Server continuity is the next shared path",
      detail:
        "No attachable mobile handoff target is retained right now, but the shared server continuity queue can still carry the next governed continuity step.",
      checklist,
      primaryAction: serverPrimary,
      secondaryAction,
      queuedActions: buildActionQueue(serverPrimary, secondaryAction),
    };
  }

  const primaryAction = openViewAction(
    "server",
    "Inspect Server continuity",
    "Inspect the shared remote queue while mobile continuity is still settling.",
  );
  return {
    tone: input.mobileOverview.status === "idle" ? "setup" : "review",
    statusLabel:
      input.mobileOverview.status === "idle"
        ? "No retained handoff target yet"
        : "Retained handoff evidence needs review",
    detail:
      input.mobileOverview.status === "idle"
        ? "The runtime has not retained a mobile handoff target yet, so continuity is waiting on the next native reply or prep workflow."
        : "Retained handoff evidence exists, but no governable REPL continuity target is ready yet.",
    checklist,
    primaryAction,
    secondaryAction: null,
    queuedActions: buildActionQueue(primaryAction),
  };
}
