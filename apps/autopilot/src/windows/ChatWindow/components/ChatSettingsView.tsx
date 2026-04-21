import { listen } from "@tauri-apps/api/event";
import { invoke } from "@tauri-apps/api/core";
import { useEffect, useMemo, useState } from "react";
import type { TauriRuntime } from "../../../services/TauriRuntime";
import { safelyDisposeTauriListener } from "../../../services/tauriListeners";
import type {
  AssistantUserProfile,
  SessionHookSnapshot,
  KnowledgeCollectionEntryContent,
  KnowledgeCollectionRecord,
  KnowledgeCollectionSearchHit,
  LocalEngineControlPlane,
  LocalEngineSnapshot,
  ResetAutopilotDataResult,
  SkillSourceRecord,
} from "../../../types";
import {
  applySessionPermissionProfileToRuntime,
  fetchShieldRememberedApprovalSnapshotFromRuntime,
  onShieldPolicyStateUpdated,
  resolveSessionPermissionProfileId,
  type CapabilityGovernanceRequest,
  type SessionPermissionProfileId,
  type ShieldPolicyState,
  type ShieldRememberedApprovalSnapshot,
} from "../chatPolicyCenter";
import { cloneLocalEngineControlPlane, humanize } from "./capabilities/model";
import { ChatSettingsViewBody } from "./ChatSettingsViewBody";
import { type SettingsSection } from "./ChatSettingsView.shared";

interface ChatSettingsViewProps {
  runtime: Pick<
    TauriRuntime,
    | "addKnowledgeCollectionSource"
    | "addKnowledgeTextEntry"
    | "addSkillSource"
    | "createKnowledgeCollection"
    | "deleteKnowledgeCollection"
    | "getKnowledgeCollectionEntryContent"
    | "getKnowledgeCollections"
    | "getSkillSources"
    | "resetAutopilotData"
    | "resetKnowledgeCollection"
    | "importKnowledgeFile"
    | "removeKnowledgeCollectionEntry"
    | "removeKnowledgeCollectionSource"
    | "removeSkillSource"
    | "searchKnowledgeCollection"
    | "setSkillSourceEnabled"
    | "syncSkillSource"
    | "updateSkillSource"
    | "getLocalEngineSnapshot"
    | "saveLocalEngineControlPlane"
    | "refreshLocalEngineManagedSettings"
    | "clearLocalEngineManagedSettingsOverrides"
  >;
  profile: AssistantUserProfile;
  profileDraft: AssistantUserProfile;
  profileSaving: boolean;
  profileError: string | null;
  policyState: ShieldPolicyState;
  governanceRequest?: CapabilityGovernanceRequest | null;
  seedSection?: SettingsSection | null;
  onConsumeSeedSection?: () => void;
  onProfileDraftChange: <K extends keyof AssistantUserProfile>(
    key: K,
    value: AssistantUserProfile[K],
  ) => void;
  onResetProfileDraft: () => void;
  onSaveProfile: () => Promise<void>;
  onPolicyChange: (next: ShieldPolicyState) => void;
  onOpenPolicySurface: () => void;
  onOpenConnections: () => void;
}

export function ChatSettingsView({
  runtime,
  profile,
  profileDraft,
  profileSaving,
  profileError,
  policyState,
  governanceRequest,
  seedSection,
  onConsumeSeedSection,
  onProfileDraftChange,
  onResetProfileDraft,
  onSaveProfile,
  onPolicyChange,
  onOpenPolicySurface,
  onOpenConnections,
}: ChatSettingsViewProps) {
  const [selectedSection, setSelectedSection] =
    useState<SettingsSection>("identity");
  const [isResetting, setIsResetting] = useState(false);
  const [resetConfirmOpen, setResetConfirmOpen] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastResult, setLastResult] = useState<ResetAutopilotDataResult | null>(
    null,
  );
  const [engineSnapshot, setEngineSnapshot] = useState<LocalEngineSnapshot | null>(
    null,
  );
  const [engineDraft, setEngineDraft] = useState<LocalEngineControlPlane | null>(
    null,
  );
  const [engineLoading, setEngineLoading] = useState(true);
  const [engineSaving, setEngineSaving] = useState(false);
  const [engineMessage, setEngineMessage] = useState<string | null>(null);
  const [engineError, setEngineError] = useState<string | null>(null);
  const [knowledgeCollections, setKnowledgeCollections] = useState<
    KnowledgeCollectionRecord[]
  >([]);
  const [knowledgeLoading, setKnowledgeLoading] = useState(true);
  const [knowledgeBusy, setKnowledgeBusy] = useState(false);
  const [knowledgeError, setKnowledgeError] = useState<string | null>(null);
  const [knowledgeMessage, setKnowledgeMessage] = useState<string | null>(null);
  const [knowledgeCollectionName, setKnowledgeCollectionName] = useState("");
  const [knowledgeCollectionDescription, setKnowledgeCollectionDescription] =
    useState("");
  const [selectedKnowledgeCollectionId, setSelectedKnowledgeCollectionId] =
    useState<string | null>(null);
  const [knowledgeEntryTitle, setKnowledgeEntryTitle] = useState("");
  const [knowledgeEntryContent, setKnowledgeEntryContent] = useState("");
  const [knowledgeImportPath, setKnowledgeImportPath] = useState("");
  const [knowledgeSourceUri, setKnowledgeSourceUri] = useState("");
  const [knowledgeSourceInterval, setKnowledgeSourceInterval] = useState("");
  const [knowledgeSearchQuery, setKnowledgeSearchQuery] = useState("");
  const [knowledgeSearchResults, setKnowledgeSearchResults] = useState<
    KnowledgeCollectionSearchHit[]
  >([]);
  const [knowledgeSearchLoading, setKnowledgeSearchLoading] = useState(false);
  const [knowledgeEntryLoading, setKnowledgeEntryLoading] = useState(false);
  const [selectedKnowledgeEntryContent, setSelectedKnowledgeEntryContent] =
    useState<KnowledgeCollectionEntryContent | null>(null);
  const [skillSources, setSkillSources] = useState<SkillSourceRecord[]>([]);
  const [skillSourcesLoading, setSkillSourcesLoading] = useState(true);
  const [skillSourcesBusy, setSkillSourcesBusy] = useState(false);
  const [skillSourcesError, setSkillSourcesError] = useState<string | null>(null);
  const [skillSourcesMessage, setSkillSourcesMessage] = useState<string | null>(
    null,
  );
  const [skillSourceLabel, setSkillSourceLabel] = useState("");
  const [skillSourceUri, setSkillSourceUri] = useState("");
  const [selectedSkillSourceId, setSelectedSkillSourceId] = useState<
    string | null
  >(null);
  const [authorityHookSnapshot, setAuthorityHookSnapshot] =
    useState<SessionHookSnapshot | null>(null);
  const [authorityRememberedApprovals, setAuthorityRememberedApprovals] =
    useState<ShieldRememberedApprovalSnapshot | null>(null);
  const [authorityStatus, setAuthorityStatus] = useState<
    "idle" | "loading" | "ready" | "error"
  >("idle");
  const [authorityError, setAuthorityError] = useState<string | null>(null);
  const [authorityApplyingProfileId, setAuthorityApplyingProfileId] =
    useState<SessionPermissionProfileId | null>(null);
  const [authorityMessage, setAuthorityMessage] = useState<string | null>(null);

  const profileDirty = JSON.stringify(profileDraft) !== JSON.stringify(profile);
  const controlPlane = engineDraft ?? engineSnapshot?.controlPlane ?? null;
  const authorityActiveOverrideCount = useMemo(
    () =>
      Object.values(policyState.overrides).filter(
        (override) => !override.inheritGlobal,
      ).length,
    [policyState.overrides],
  );
  const authorityCurrentProfileId = useMemo(
    () => resolveSessionPermissionProfileId(policyState),
    [policyState],
  );

  useEffect(() => {
    if (!seedSection) {
      return;
    }
    setSelectedSection(seedSection);
    onConsumeSeedSection?.();
  }, [onConsumeSeedSection, seedSection]);
  const engineDirty =
    !!engineSnapshot &&
    !!engineDraft &&
    JSON.stringify(engineDraft) !== JSON.stringify(engineSnapshot.controlPlane);

  const loadEngineSnapshot = async () => {
    setEngineLoading(true);
    setEngineError(null);
    try {
      const snapshot = await runtime.getLocalEngineSnapshot();
      setEngineSnapshot(snapshot);
      setEngineDraft(cloneLocalEngineControlPlane(snapshot.controlPlane));
    } catch (nextError) {
      setEngineError(String(nextError));
    } finally {
      setEngineLoading(false);
    }
  };

  const loadKnowledgeCollections = async () => {
    setKnowledgeLoading(true);
    setKnowledgeError(null);
    try {
      const collections = await runtime.getKnowledgeCollections();
      setKnowledgeCollections(collections);
      setSelectedKnowledgeCollectionId((current) => {
        if (current && collections.some((collection) => collection.collectionId === current)) {
          return current;
        }
        return collections[0]?.collectionId ?? null;
      });
    } catch (nextError) {
      setKnowledgeError(String(nextError));
    } finally {
      setKnowledgeLoading(false);
    }
  };

  const loadSkillSources = async () => {
    setSkillSourcesLoading(true);
    setSkillSourcesError(null);
    try {
      const sources = await runtime.getSkillSources();
      setSkillSources(sources);
      setSelectedSkillSourceId((current) => {
        if (current && sources.some((source) => source.sourceId === current)) {
          return current;
        }
        return sources[0]?.sourceId ?? null;
      });
    } catch (nextError) {
      setSkillSourcesError(String(nextError));
    } finally {
      setSkillSourcesLoading(false);
    }
  };

  const loadAuthorityInputs = async (showLoading = false) => {
    if (showLoading) {
      setAuthorityStatus("loading");
    }
    setAuthorityError(null);

    const [hookSnapshotResult, rememberedApprovalsResult] = await Promise.allSettled([
      invoke<SessionHookSnapshot>("get_session_hook_snapshot", {
        sessionId: null,
        workspaceRoot: null,
      }),
      fetchShieldRememberedApprovalSnapshotFromRuntime(),
    ]);

    const nextHookSnapshot =
      hookSnapshotResult.status === "fulfilled" ? hookSnapshotResult.value : null;
    const nextRememberedApprovals =
      rememberedApprovalsResult.status === "fulfilled"
        ? rememberedApprovalsResult.value
        : null;
    const failures = [hookSnapshotResult, rememberedApprovalsResult].filter(
      (result): result is PromiseRejectedResult => result.status === "rejected",
    );

    setAuthorityHookSnapshot(nextHookSnapshot);
    setAuthorityRememberedApprovals(nextRememberedApprovals);

    if (failures.length > 0) {
      setAuthorityStatus("error");
      setAuthorityError(
        failures
          .map((failure) =>
            failure.reason instanceof Error
              ? failure.reason.message
              : String(failure.reason),
          )
          .join(" | "),
      );
      return;
    }

    setAuthorityStatus("ready");
  };

  useEffect(() => {
    void loadEngineSnapshot();
    void loadKnowledgeCollections();
    void loadSkillSources();
    void loadAuthorityInputs(true);
  }, [runtime]);

  useEffect(() => {
    let cancelled = false;

    const projectionPromise = listen("session-projection-updated", () => {
      if (cancelled) {
        return;
      }
      void loadAuthorityInputs(false);
    });
    const governancePromise = listen("capability-governance-request-updated", () => {
      if (cancelled) {
        return;
      }
      void loadAuthorityInputs(false);
    });
    const unlistenPolicy = onShieldPolicyStateUpdated(() => {
      if (cancelled) {
        return;
      }
      void loadAuthorityInputs(false);
    });

    return () => {
      cancelled = true;
      safelyDisposeTauriListener(projectionPromise);
      safelyDisposeTauriListener(governancePromise);
      unlistenPolicy();
    };
  }, []);

  const selectedKnowledgeCollection = useMemo(() => {
    if (!selectedKnowledgeCollectionId) {
      return knowledgeCollections[0] ?? null;
    }
    return (
      knowledgeCollections.find(
        (collection) => collection.collectionId === selectedKnowledgeCollectionId,
      ) ?? knowledgeCollections[0] ?? null
    );
  }, [knowledgeCollections, selectedKnowledgeCollectionId]);

  const selectedSkillSource = useMemo(() => {
    if (!selectedSkillSourceId) {
      return skillSources[0] ?? null;
    }
    return (
      skillSources.find((source) => source.sourceId === selectedSkillSourceId) ??
      skillSources[0] ??
      null
    );
  }, [selectedSkillSourceId, skillSources]);

  const summary = useMemo(() => {
    if (!lastResult) return null;
    return `${lastResult.removedPaths.length} local targets reset at ${lastResult.dataDir}.`;
  }, [lastResult]);

  const diagnostics = useMemo(() => {
    return [
      {
        label: "Profile draft",
        value: profileDirty ? "Unsaved changes" : "Synced",
        tone: profileDirty ? "warning" : "normal",
      },
      {
        label: "Runtime mode",
        value: engineSnapshot
          ? humanize(engineSnapshot.controlPlane.runtime.mode)
          : engineLoading
            ? "Loading"
            : "Unavailable",
        tone: engineSnapshot ? "normal" : "muted",
      },
      {
        label: "Native tools",
        value: engineSnapshot
          ? `${engineSnapshot.totalNativeTools}`
          : engineLoading
            ? "Loading"
            : "Unavailable",
        tone: engineSnapshot ? "normal" : "muted",
      },
      {
        label: "Pending controls",
        value: engineSnapshot
          ? `${engineSnapshot.pendingControlCount}`
          : engineLoading
            ? "Loading"
            : "Unavailable",
        tone:
          engineSnapshot && engineSnapshot.pendingControlCount > 0
            ? "warning"
            : "normal",
      },
      {
        label: "Active issues",
        value: engineSnapshot
          ? `${engineSnapshot.activeIssueCount}`
          : engineLoading
            ? "Loading"
            : "Unavailable",
        tone:
          engineSnapshot && engineSnapshot.activeIssueCount > 0
            ? "warning"
            : "muted",
      },
      {
        label: "Last local reset",
        value: lastResult
          ? `${lastResult.removedPaths.length} targets removed`
          : "Not run yet",
        tone: lastResult ? "normal" : "muted",
      },
      {
        label: "Gallery sources",
        value: controlPlane
          ? `${controlPlane.galleries.filter((source) => source.enabled).length}/${controlPlane.galleries.length} enabled`
          : engineLoading
            ? "Loading"
            : "Unavailable",
        tone: controlPlane ? "normal" : "muted",
      },
      {
        label: "Environment bindings",
        value: controlPlane
          ? `${controlPlane.environment.length}`
          : engineLoading
            ? "Loading"
            : "Unavailable",
        tone: controlPlane ? "normal" : "muted",
      },
      {
        label: "Config profile",
        value: engineSnapshot
          ? engineSnapshot.controlPlaneProfileId
          : engineLoading
            ? "Loading"
            : "Unavailable",
        tone: engineSnapshot ? "normal" : "muted",
      },
      {
        label: "Config schema",
        value: engineSnapshot
          ? engineSnapshot.controlPlaneMigrations.length > 0
            ? `v${engineSnapshot.controlPlaneSchemaVersion} / ${engineSnapshot.controlPlaneMigrations.length} migration${engineSnapshot.controlPlaneMigrations.length === 1 ? "" : "s"}`
            : `v${engineSnapshot.controlPlaneSchemaVersion} / native`
          : engineLoading
            ? "Loading"
            : "Unavailable",
        tone: engineSnapshot ? "normal" : "muted",
      },
      {
        label: "Managed settings",
        value: engineSnapshot
          ? humanize(engineSnapshot.managedSettings.syncStatus)
          : engineLoading
            ? "Loading"
            : "Unavailable",
        tone:
          engineSnapshot?.managedSettings.syncStatus === "degraded"
            ? "warning"
            : engineSnapshot?.managedSettings.syncStatus === "managed"
              ? "normal"
              : "muted",
      },
      {
        label: "Managed overrides",
        value: engineSnapshot
          ? `${engineSnapshot.managedSettings.localOverrideCount}`
          : engineLoading
            ? "Loading"
            : "Unavailable",
        tone:
          engineSnapshot && engineSnapshot.managedSettings.localOverrideCount > 0
            ? "warning"
            : "normal",
      },
      {
        label: "Knowledge collections",
        value: knowledgeLoading
          ? "Loading"
          : `${knowledgeCollections.length} collections / ${knowledgeCollections.reduce(
              (total, collection) => total + collection.entries.length,
              0,
            )} entries`,
        tone: knowledgeCollections.length > 0 ? "normal" : "muted",
      },
      {
        label: "Skill sources",
        value: skillSourcesLoading
          ? "Loading"
          : `${skillSources.length} sources / ${skillSources.reduce(
              (total, source) => total + source.discoveredSkills.length,
              0,
            )} discovered skills`,
        tone: skillSources.length > 0 ? "normal" : "muted",
      },
      {
        label: "Settings drift",
        value: engineDirty ? "Draft differs" : "Synced",
        tone: engineDirty ? "warning" : "normal",
      },
    ] as const;
  }, [
    controlPlane,
    engineDirty,
    engineLoading,
    engineSnapshot,
    knowledgeCollections,
    knowledgeLoading,
    lastResult,
    profileDirty,
    skillSources,
    skillSourcesLoading,
  ]);

  const runKnowledgeAction = async (
    action: () => Promise<void>,
    successMessage: string,
  ) => {
    setKnowledgeBusy(true);
    setKnowledgeError(null);
    setKnowledgeMessage(null);
    try {
      await action();
      await loadKnowledgeCollections();
      setKnowledgeMessage(successMessage);
    } catch (nextError) {
      setKnowledgeError(String(nextError));
    } finally {
      setKnowledgeBusy(false);
    }
  };

  const runSkillSourceAction = async (
    action: () => Promise<void>,
    successMessage: string,
  ) => {
    setSkillSourcesBusy(true);
    setSkillSourcesError(null);
    setSkillSourcesMessage(null);
    try {
      await action();
      await loadSkillSources();
      setSkillSourcesMessage(successMessage);
    } catch (nextError) {
      setSkillSourcesError(String(nextError));
    } finally {
      setSkillSourcesBusy(false);
    }
  };

  const updateEngineDraft = (
    updater: (current: LocalEngineControlPlane) => LocalEngineControlPlane,
  ) => {
    setEngineDraft((current) => {
      if (!current) return current;
      return updater(current);
    });
    setEngineMessage(null);
  };

  const handleReset = async () => {
    setIsResetting(true);
    setResetConfirmOpen(false);
    setError(null);

    try {
      const result = await runtime.resetAutopilotData();
      setLastResult(result);
    } catch (nextError) {
      setError(String(nextError));
    } finally {
      setIsResetting(false);
    }
  };

  const handleSaveEngine = async () => {
    if (!engineDraft) return;
    setEngineSaving(true);
    setEngineMessage(null);
    setEngineError(null);

    try {
      await runtime.saveLocalEngineControlPlane(engineDraft);
      const snapshot = await runtime.getLocalEngineSnapshot();
      setEngineSnapshot(snapshot);
      setEngineDraft(cloneLocalEngineControlPlane(snapshot.controlPlane));
      setEngineMessage(
        "Kernel-backed runtime settings saved to the system settings plane.",
      );
    } catch (nextError) {
      setEngineError(String(nextError));
    } finally {
      setEngineSaving(false);
    }
  };

  const handleRefreshManagedSettings = async () => {
    setEngineSaving(true);
    setEngineMessage(null);
    setEngineError(null);
    try {
      await runtime.refreshLocalEngineManagedSettings();
      const snapshot = await runtime.getLocalEngineSnapshot();
      setEngineSnapshot(snapshot);
      setEngineDraft(cloneLocalEngineControlPlane(snapshot.controlPlane));
      setEngineMessage(
        "Signed managed settings channels refreshed into the kernel control plane.",
      );
    } catch (nextError) {
      setEngineError(String(nextError));
    } finally {
      setEngineSaving(false);
    }
  };

  const handleClearManagedSettingsOverrides = async () => {
    setEngineSaving(true);
    setEngineMessage(null);
    setEngineError(null);
    try {
      await runtime.clearLocalEngineManagedSettingsOverrides();
      const snapshot = await runtime.getLocalEngineSnapshot();
      setEngineSnapshot(snapshot);
      setEngineDraft(cloneLocalEngineControlPlane(snapshot.controlPlane));
      setEngineMessage(
        "Local managed-settings overrides were cleared and the signed baseline is active again.",
      );
    } catch (nextError) {
      setEngineError(String(nextError));
    } finally {
      setEngineSaving(false);
    }
  };

  const handleApplyAuthorityProfile = async (
    profileId: SessionPermissionProfileId,
  ) => {
    setAuthorityApplyingProfileId(profileId);
    setAuthorityMessage(null);
    setAuthorityError(null);

    try {
      const nextPolicy = await applySessionPermissionProfileToRuntime(
        profileId,
        policyState,
      );
      onPolicyChange(nextPolicy);
      await loadAuthorityInputs(false);
      setAuthorityMessage(
        `Applied the ${profileId.replace(/_/g, " ")} authority profile from Studio settings.`,
      );
    } catch (nextError) {
      setAuthorityError(
        nextError instanceof Error ? nextError.message : String(nextError),
      );
    } finally {
      setAuthorityApplyingProfileId(null);
    }
  };

  const renderEngineControls = () => {
    if (!controlPlane) {
      return (
        <article className="studio-settings-card">
          <div className="studio-settings-card-head">
            <div>
              <span className="studio-settings-card-eyebrow">Runtime</span>
              <h2>Local Engine settings unavailable</h2>
            </div>
            <span className="studio-settings-pill">Kernel-backed</span>
          </div>
          <p className="studio-settings-body">
            {engineLoading
              ? "Loading kernel-backed runtime settings…"
              : engineError ?? "The kernel did not publish a Local Engine snapshot."}
          </p>
        </article>
      );
    }

    return (
      <>
        <div className="studio-settings-actions studio-settings-actions--top">
          <button
            type="button"
            className="studio-settings-secondary"
            onClick={() => void loadEngineSnapshot()}
            disabled={engineLoading || engineSaving}
          >
            {engineLoading ? "Refreshing..." : "Refresh from kernel"}
          </button>
          <button
            type="button"
            className="studio-settings-secondary"
            onClick={() =>
              engineSnapshot
                ? setEngineDraft(
                    cloneLocalEngineControlPlane(engineSnapshot.controlPlane),
                  )
                : undefined
            }
            disabled={!engineDirty || engineSaving}
          >
            Reset draft
          </button>
          <button
            type="button"
            className="studio-settings-primary"
            onClick={() => {
              void handleSaveEngine();
            }}
            disabled={!engineDirty || engineSaving}
          >
            {engineSaving ? "Saving..." : "Save runtime settings"}
          </button>
        </div>

        {engineMessage ? (
          <p className="studio-settings-success">{engineMessage}</p>
        ) : null}
        {engineError ? <p className="studio-settings-error">{engineError}</p> : null}
      </>
    );
  };

  const view = { runtime, profile, profileDraft, profileSaving, profileError, policyState, governanceRequest, onProfileDraftChange, onResetProfileDraft, onSaveProfile, selectedSection, setSelectedSection, isResetting, setIsResetting, resetConfirmOpen, setResetConfirmOpen, error, setError, lastResult, setLastResult, engineSnapshot, setEngineSnapshot, engineDraft, setEngineDraft, engineLoading, setEngineLoading, engineSaving, setEngineSaving, engineMessage, setEngineMessage, engineError, setEngineError, knowledgeCollections, setKnowledgeCollections, knowledgeLoading, setKnowledgeLoading, knowledgeBusy, setKnowledgeBusy, knowledgeError, setKnowledgeError, knowledgeMessage, setKnowledgeMessage, knowledgeCollectionName, setKnowledgeCollectionName, knowledgeCollectionDescription, setKnowledgeCollectionDescription, selectedKnowledgeCollectionId, setSelectedKnowledgeCollectionId, knowledgeEntryTitle, setKnowledgeEntryTitle, knowledgeEntryContent, setKnowledgeEntryContent, knowledgeImportPath, setKnowledgeImportPath, knowledgeSourceUri, setKnowledgeSourceUri, knowledgeSourceInterval, setKnowledgeSourceInterval, knowledgeSearchQuery, setKnowledgeSearchQuery, knowledgeSearchResults, setKnowledgeSearchResults, knowledgeSearchLoading, setKnowledgeSearchLoading, knowledgeEntryLoading, setKnowledgeEntryLoading, selectedKnowledgeEntryContent, setSelectedKnowledgeEntryContent, skillSources, setSkillSources, skillSourcesLoading, setSkillSourcesLoading, skillSourcesBusy, setSkillSourcesBusy, skillSourcesError, setSkillSourcesError, skillSourcesMessage, setSkillSourcesMessage, skillSourceLabel, setSkillSourceLabel, skillSourceUri, setSkillSourceUri, selectedSkillSourceId, setSelectedSkillSourceId, authorityHookSnapshot, authorityRememberedApprovals, authorityStatus, authorityError, authorityApplyingProfileId, authorityMessage, authorityCurrentProfileId, authorityActiveOverrideCount, handleApplyAuthorityProfile, onOpenPolicySurface, onOpenConnections, profileDirty, controlPlane, engineDirty, loadEngineSnapshot, loadKnowledgeCollections, loadSkillSources, selectedKnowledgeCollection, selectedSkillSource, summary, diagnostics, runKnowledgeAction, runSkillSourceAction, updateEngineDraft, handleReset, handleSaveEngine, handleRefreshManagedSettings, handleClearManagedSettingsOverrides, renderEngineControls };

  return (
    <div className="studio-settings-view">
      <div className="studio-settings-layout">
        <ChatSettingsViewBody view={view} />
      </div>
    </div>
  );
}

export const SettingsView = ChatSettingsView;
