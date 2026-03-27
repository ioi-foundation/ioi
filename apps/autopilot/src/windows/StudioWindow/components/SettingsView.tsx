import { useEffect, useMemo, useState } from "react";
import type { TauriRuntime } from "../../../services/TauriRuntime";
import type {
  AssistantUserProfile,
  KnowledgeCollectionEntryContent,
  KnowledgeCollectionRecord,
  KnowledgeCollectionSearchHit,
  LocalEngineControlPlane,
  LocalEngineSnapshot,
  ResetAutopilotDataResult,
  SkillSourceRecord,
} from "../../../types";
import {
  cloneLocalEngineControlPlane,
  humanize,
} from "./capabilities/model";

interface SettingsViewProps {
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
  >;
  profile: AssistantUserProfile;
  profileDraft: AssistantUserProfile;
  profileSaving: boolean;
  profileError: string | null;
  onProfileDraftChange: <K extends keyof AssistantUserProfile>(
    key: K,
    value: AssistantUserProfile[K],
  ) => void;
  onResetProfileDraft: () => void;
  onSaveProfile: () => Promise<void>;
}

type SettingsSection =
  | "identity"
  | "knowledge"
  | "skill_sources"
  | "runtime"
  | "storage_api"
  | "sources"
  | "environment"
  | "local_data"
  | "repair_reset"
  | "diagnostics";

const RESET_COPY = [
  "Local conversation history, events, and artifacts in `studio-memory.db`.",
  "Connector subscription registry and control policy state.",
  "Spotlight validation artifacts and browser-side local storage for the app origin.",
  "Kernel-backed runtime settings only reset when explicitly cleared or replaced.",
];

function formatSettingsTime(timestampMs: number): string {
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  }).format(new Date(timestampMs));
}

function isEngineSection(section: SettingsSection): boolean {
  return (
    section === "runtime" ||
    section === "storage_api" ||
    section === "sources" ||
    section === "environment"
  );
}

export function SettingsView({
  runtime,
  profile,
  profileDraft,
  profileSaving,
  profileError,
  onProfileDraftChange,
  onResetProfileDraft,
  onSaveProfile,
}: SettingsViewProps) {
  const [selectedSection, setSelectedSection] =
    useState<SettingsSection>("identity");
  const [isResetting, setIsResetting] = useState(false);
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

  const profileDirty = JSON.stringify(profileDraft) !== JSON.stringify(profile);
  const controlPlane = engineDraft ?? engineSnapshot?.controlPlane ?? null;
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

  useEffect(() => {
    void loadEngineSnapshot();
    void loadKnowledgeCollections();
    void loadSkillSources();
  }, [runtime]);

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
    const confirmed = window.confirm(
      "Reset Autopilot local data?\n\nThis clears local history, cached context state, connector policy, and browser-side app storage. Identity is preserved, so remote session history may still rehydrate.",
    );
    if (!confirmed) return;

    setIsResetting(true);
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

  return (
    <div className="studio-settings-view">
      <div className="studio-settings-layout">
        <aside className="studio-settings-sidebar">
          <div className="studio-settings-sidebar-head">
            <strong>Control documents</strong>
            <span>Kernel-backed</span>
          </div>

          <button
            type="button"
            className={`studio-settings-target ${selectedSection === "identity" ? "active" : ""}`}
            onClick={() => setSelectedSection("identity")}
          >
            <strong>Identity</strong>
            <span>Display name, locale, and operator metadata.</span>
          </button>
          <button
            type="button"
            className={`studio-settings-target ${selectedSection === "knowledge" ? "active" : ""}`}
            onClick={() => setSelectedSection("knowledge")}
          >
            <strong>Knowledge</strong>
            <span>Collections, entry ingestion, search, and retrieval-ready sources.</span>
          </button>
          <button
            type="button"
            className={`studio-settings-target ${selectedSection === "skill_sources" ? "active" : ""}`}
            onClick={() => setSelectedSection("skill_sources")}
          >
            <strong>Skill sources</strong>
            <span>Repo or local skill roots, sync status, and provenance controls.</span>
          </button>
          <button
            type="button"
            className={`studio-settings-target ${selectedSection === "runtime" ? "active" : ""}`}
            onClick={() => setSelectedSection("runtime")}
          >
            <strong>Runtime</strong>
            <span>Execution posture, watchdogs, memory, launcher, and throughput.</span>
          </button>
          <button
            type="button"
            className={`studio-settings-target ${selectedSection === "storage_api" ? "active" : ""}`}
            onClick={() => setSelectedSection("storage_api")}
          >
            <strong>Storage / API</strong>
            <span>Paths, bind address, compatibility routes, and API exposure.</span>
          </button>
          <button
            type="button"
            className={`studio-settings-target ${selectedSection === "sources" ? "active" : ""}`}
            onClick={() => setSelectedSection("sources")}
          >
            <strong>Sources</strong>
            <span>Model and backend galleries plus migration import sources.</span>
          </button>
          <button
            type="button"
            className={`studio-settings-target ${selectedSection === "environment" ? "active" : ""}`}
            onClick={() => setSelectedSection("environment")}
          >
            <strong>Environment</strong>
            <span>Environment bindings and runtime-specific external inputs.</span>
          </button>
          <button
            type="button"
            className={`studio-settings-target ${selectedSection === "local_data" ? "active" : ""}`}
            onClick={() => setSelectedSection("local_data")}
          >
            <strong>Local data</strong>
            <span>What is stored in the shell and what survives resets.</span>
          </button>
          <button
            type="button"
            className={`studio-settings-target ${selectedSection === "repair_reset" ? "active" : ""}`}
            onClick={() => setSelectedSection("repair_reset")}
          >
            <strong>Repair / reset</strong>
            <span>Clear local state when builds or policies are carrying context.</span>
          </button>
          <button
            type="button"
            className={`studio-settings-target ${selectedSection === "diagnostics" ? "active" : ""}`}
            onClick={() => setSelectedSection("diagnostics")}
          >
            <strong>Diagnostics</strong>
            <span>Current shell state, runtime posture, and recent local resets.</span>
          </button>
        </aside>

        <section className="studio-settings-panel">
          {isEngineSection(selectedSection) ? renderEngineControls() : null}

          {selectedSection === "identity" ? (
            <article className="studio-settings-card">
              <div className="studio-settings-card-head">
                <div>
                  <span className="studio-settings-card-eyebrow">Identity</span>
                  <h2>Shell identity</h2>
                </div>
                <span className="studio-settings-pill">Local only</span>
              </div>

              <p className="studio-settings-body">
                This local operator profile shapes how the shell names you across
                Autopilot surfaces. It does not replace runtime, policy, or tool
                configuration.
              </p>

              <div className="studio-settings-profile-grid">
                <label className="studio-settings-field">
                  <span>Display name</span>
                  <input
                    value={profileDraft.displayName}
                    onChange={(event) =>
                      onProfileDraftChange("displayName", event.target.value)
                    }
                    placeholder="Operator"
                  />
                </label>
                <label className="studio-settings-field">
                  <span>Preferred name</span>
                  <input
                    value={profileDraft.preferredName ?? ""}
                    onChange={(event) =>
                      onProfileDraftChange(
                        "preferredName",
                        event.target.value || null,
                      )
                    }
                    placeholder="Optional"
                  />
                </label>
                <label className="studio-settings-field">
                  <span>Role label</span>
                  <input
                    value={profileDraft.roleLabel ?? ""}
                    onChange={(event) =>
                      onProfileDraftChange(
                        "roleLabel",
                        event.target.value || null,
                      )
                    }
                    placeholder="Private Operator"
                  />
                </label>
                <label className="studio-settings-field">
                  <span>Primary email</span>
                  <input
                    value={profileDraft.primaryEmail ?? ""}
                    onChange={(event) =>
                      onProfileDraftChange(
                        "primaryEmail",
                        event.target.value || null,
                      )
                    }
                    placeholder="Optional"
                  />
                </label>
                <label className="studio-settings-field">
                  <span>Timezone</span>
                  <input
                    value={profileDraft.timezone}
                    onChange={(event) =>
                      onProfileDraftChange("timezone", event.target.value)
                    }
                    placeholder="America/New_York"
                  />
                </label>
                <label className="studio-settings-field">
                  <span>Locale</span>
                  <input
                    value={profileDraft.locale}
                    onChange={(event) =>
                      onProfileDraftChange("locale", event.target.value)
                    }
                    placeholder="en-US"
                  />
                </label>
              </div>

              {profileError ? <p className="studio-settings-error">{profileError}</p> : null}

              <div className="studio-settings-actions">
                <button
                  type="button"
                  className="studio-settings-secondary"
                  onClick={onResetProfileDraft}
                  disabled={profileSaving || !profileDirty}
                >
                  Reset changes
                </button>
                <button
                  type="button"
                  className="studio-settings-primary"
                  onClick={() => {
                    void onSaveProfile();
                  }}
                  disabled={profileSaving || !profileDirty}
                >
                  {profileSaving ? "Saving..." : "Save profile"}
                </button>
              </div>
            </article>
          ) : null}

          {selectedSection === "runtime" && controlPlane ? (
            <div className="studio-settings-stack">
              <article className="studio-settings-card">
                <div className="studio-settings-card-head">
                  <div>
                    <span className="studio-settings-card-eyebrow">Runtime</span>
                    <h2>Runtime posture</h2>
                  </div>
                  <span className="studio-settings-pill">Kernel-backed</span>
                </div>
                <p className="studio-settings-body">
                  This absorbs the LocalAI-style runtime settings into a first-party
                  settings plane while keeping the kernel as planner, policy, and
                  receipt authority.
                </p>
                <div className="studio-settings-profile-grid">
                  <label className="studio-settings-field">
                    <span>Runtime mode</span>
                    <select
                      value={controlPlane.runtime.mode}
                      onChange={(event) =>
                        updateEngineDraft((current) => ({
                          ...current,
                          runtime: {
                            ...current.runtime,
                            mode: event.target.value,
                          },
                        }))
                      }
                    >
                      <option value="openai_baseline">OpenAI baseline</option>
                      <option value="http_local">HTTP local bridge</option>
                      <option value="mock">Mock substrate</option>
                    </select>
                  </label>
                  <label className="studio-settings-field">
                    <span>Endpoint</span>
                    <input
                      value={controlPlane.runtime.endpoint}
                      onChange={(event) =>
                        updateEngineDraft((current) => ({
                          ...current,
                          runtime: {
                            ...current.runtime,
                            endpoint: event.target.value,
                          },
                        }))
                      }
                    />
                  </label>
                  <label className="studio-settings-field">
                    <span>Default model</span>
                    <input
                      value={controlPlane.runtime.defaultModel}
                      onChange={(event) =>
                        updateEngineDraft((current) => ({
                          ...current,
                          runtime: {
                            ...current.runtime,
                            defaultModel: event.target.value,
                          },
                        }))
                      }
                    />
                  </label>
                  <label className="studio-settings-field studio-settings-field--wide">
                    <span>Baseline role</span>
                    <textarea
                      value={controlPlane.runtime.baselineRole}
                      onChange={(event) =>
                        updateEngineDraft((current) => ({
                          ...current,
                          runtime: {
                            ...current.runtime,
                            baselineRole: event.target.value,
                          },
                        }))
                      }
                    />
                  </label>
                </div>
              </article>

              <article className="studio-settings-card">
                <div className="studio-settings-card-head">
                  <div>
                    <span className="studio-settings-card-eyebrow">Launcher</span>
                    <h2>Shell and launch behavior</h2>
                  </div>
                  <span className="studio-settings-pill">Settings plane</span>
                </div>
                <div className="studio-settings-form-grid">
                  <label className="studio-settings-toggle">
                    <input
                      type="checkbox"
                      checked={controlPlane.launcher.autoStartOnBoot}
                      onChange={(event) =>
                        updateEngineDraft((current) => ({
                          ...current,
                          launcher: {
                            ...current.launcher,
                            autoStartOnBoot: event.target.checked,
                          },
                        }))
                      }
                    />
                    <div>
                      <strong>Start local engine on boot</strong>
                      <span>Use Settings as the launcher-parity control surface.</span>
                    </div>
                  </label>
                  <label className="studio-settings-toggle">
                    <input
                      type="checkbox"
                      checked={controlPlane.launcher.reopenStudioOnLaunch}
                      onChange={(event) =>
                        updateEngineDraft((current) => ({
                          ...current,
                          launcher: {
                            ...current.launcher,
                            reopenStudioOnLaunch: event.target.checked,
                          },
                        }))
                      }
                    />
                    <div>
                      <strong>Reopen Studio on launch</strong>
                      <span>Return operators to the same shell after relaunch.</span>
                    </div>
                  </label>
                  <label className="studio-settings-toggle">
                    <input
                      type="checkbox"
                      checked={controlPlane.launcher.autoCheckUpdates}
                      onChange={(event) =>
                        updateEngineDraft((current) => ({
                          ...current,
                          launcher: {
                            ...current.launcher,
                            autoCheckUpdates: event.target.checked,
                          },
                        }))
                      }
                    />
                    <div>
                      <strong>Check updates automatically</strong>
                      <span>Keep runtime and launcher parity visible to the operator.</span>
                    </div>
                  </label>
                  <label className="studio-settings-toggle">
                    <input
                      type="checkbox"
                      checked={controlPlane.launcher.showKernelConsole}
                      onChange={(event) =>
                        updateEngineDraft((current) => ({
                          ...current,
                          launcher: {
                            ...current.launcher,
                            showKernelConsole: event.target.checked,
                          },
                        }))
                      }
                    />
                    <div>
                      <strong>Show kernel console</strong>
                      <span>Expose low-level runtime stdout and stderr when debugging.</span>
                    </div>
                  </label>
                  <label className="studio-settings-field">
                    <span>Release channel</span>
                    <select
                      value={controlPlane.launcher.releaseChannel}
                      onChange={(event) =>
                        updateEngineDraft((current) => ({
                          ...current,
                          launcher: {
                            ...current.launcher,
                            releaseChannel: event.target.value,
                          },
                        }))
                      }
                    >
                      <option value="stable">Stable</option>
                      <option value="preview">Preview</option>
                      <option value="nightly">Nightly</option>
                    </select>
                  </label>
                </div>
              </article>

              <article className="studio-settings-card">
                <div className="studio-settings-card-head">
                  <div>
                    <span className="studio-settings-card-eyebrow">Execution</span>
                    <h2>Watchdog, memory, and throughput</h2>
                  </div>
                  <span className="studio-settings-pill">Runtime policy</span>
                </div>
                <div className="studio-settings-form-grid">
                  <label className="studio-settings-toggle">
                    <input
                      type="checkbox"
                      checked={controlPlane.watchdog.enabled}
                      onChange={(event) =>
                        updateEngineDraft((current) => ({
                          ...current,
                          watchdog: {
                            ...current.watchdog,
                            enabled: event.target.checked,
                          },
                        }))
                      }
                    />
                    <div>
                      <strong>Enable watchdog</strong>
                      <span>Keep idle and busy eviction semantics under kernel control.</span>
                    </div>
                  </label>
                  <label className="studio-settings-toggle">
                    <input
                      type="checkbox"
                      checked={controlPlane.memory.reclaimerEnabled}
                      onChange={(event) =>
                        updateEngineDraft((current) => ({
                          ...current,
                          memory: {
                            ...current.memory,
                            reclaimerEnabled: event.target.checked,
                          },
                        }))
                      }
                    />
                    <div>
                      <strong>Enable memory reclaimer</strong>
                      <span>Evict aggressively before local workloads overrun capacity.</span>
                    </div>
                  </label>
                  <label className="studio-settings-toggle">
                    <input
                      type="checkbox"
                      checked={controlPlane.watchdog.idleCheckEnabled}
                      onChange={(event) =>
                        updateEngineDraft((current) => ({
                          ...current,
                          watchdog: {
                            ...current.watchdog,
                            idleCheckEnabled: event.target.checked,
                          },
                        }))
                      }
                    />
                    <div>
                      <strong>Enable idle check</strong>
                      <span>Stop backends that stay loaded after the operator has gone quiet.</span>
                    </div>
                  </label>
                  <label className="studio-settings-toggle">
                    <input
                      type="checkbox"
                      checked={controlPlane.watchdog.busyCheckEnabled}
                      onChange={(event) =>
                        updateEngineDraft((current) => ({
                          ...current,
                          watchdog: {
                            ...current.watchdog,
                            busyCheckEnabled: event.target.checked,
                          },
                        }))
                      }
                    />
                    <div>
                      <strong>Enable busy check</strong>
                      <span>Let the kernel recover from stuck backend work that exceeds the budget.</span>
                    </div>
                  </label>
                  <label className="studio-settings-field">
                    <span>Idle timeout</span>
                    <input
                      value={controlPlane.watchdog.idleTimeout}
                      onChange={(event) =>
                        updateEngineDraft((current) => ({
                          ...current,
                          watchdog: {
                            ...current.watchdog,
                            idleTimeout: event.target.value,
                          },
                        }))
                      }
                    />
                  </label>
                  <label className="studio-settings-field">
                    <span>Busy timeout</span>
                    <input
                      value={controlPlane.watchdog.busyTimeout}
                      onChange={(event) =>
                        updateEngineDraft((current) => ({
                          ...current,
                          watchdog: {
                            ...current.watchdog,
                            busyTimeout: event.target.value,
                          },
                        }))
                      }
                    />
                  </label>
                  <label className="studio-settings-field">
                    <span>Check interval</span>
                    <input
                      value={controlPlane.watchdog.checkInterval}
                      onChange={(event) =>
                        updateEngineDraft((current) => ({
                          ...current,
                          watchdog: {
                            ...current.watchdog,
                            checkInterval: event.target.value,
                          },
                        }))
                      }
                    />
                  </label>
                  <label className="studio-settings-field">
                    <span>Eviction retries</span>
                    <input
                      type="number"
                      min={0}
                      value={controlPlane.watchdog.lruEvictionMaxRetries}
                      onChange={(event) =>
                        updateEngineDraft((current) => ({
                          ...current,
                          watchdog: {
                            ...current.watchdog,
                            lruEvictionMaxRetries: Number(event.target.value || 0),
                          },
                        }))
                      }
                    />
                  </label>
                  <label className="studio-settings-field">
                    <span>Retry interval</span>
                    <input
                      value={controlPlane.watchdog.lruEvictionRetryInterval}
                      onChange={(event) =>
                        updateEngineDraft((current) => ({
                          ...current,
                          watchdog: {
                            ...current.watchdog,
                            lruEvictionRetryInterval: event.target.value,
                          },
                        }))
                      }
                    />
                  </label>
                  <label className="studio-settings-field">
                    <span>Memory threshold (%)</span>
                    <input
                      type="number"
                      min={50}
                      max={100}
                      value={controlPlane.memory.thresholdPercent}
                      onChange={(event) =>
                        updateEngineDraft((current) => ({
                          ...current,
                          memory: {
                            ...current.memory,
                            thresholdPercent: Number(event.target.value || 80),
                          },
                        }))
                      }
                    />
                  </label>
                  <label className="studio-settings-field">
                    <span>Target resource</span>
                    <input
                      value={controlPlane.memory.targetResource}
                      onChange={(event) =>
                        updateEngineDraft((current) => ({
                          ...current,
                          memory: {
                            ...current.memory,
                            targetResource: event.target.value,
                          },
                        }))
                      }
                    />
                  </label>
                  <label className="studio-settings-field">
                    <span>Max concurrency</span>
                    <input
                      type="number"
                      min={1}
                      value={controlPlane.backendPolicy.maxConcurrency}
                      onChange={(event) =>
                        updateEngineDraft((current) => ({
                          ...current,
                          backendPolicy: {
                            ...current.backendPolicy,
                            maxConcurrency: Number(event.target.value || 1),
                          },
                        }))
                      }
                    />
                  </label>
                  <label className="studio-settings-field">
                    <span>Queued requests</span>
                    <input
                      type="number"
                      min={1}
                      value={controlPlane.backendPolicy.maxQueuedRequests}
                      onChange={(event) =>
                        updateEngineDraft((current) => ({
                          ...current,
                          backendPolicy: {
                            ...current.backendPolicy,
                            maxQueuedRequests: Number(event.target.value || 1),
                          },
                        }))
                      }
                    />
                  </label>
                  <label className="studio-settings-field">
                    <span>Parallel backend loads</span>
                    <input
                      type="number"
                      min={1}
                      value={controlPlane.backendPolicy.parallelBackendLoads}
                      onChange={(event) =>
                        updateEngineDraft((current) => ({
                          ...current,
                          backendPolicy: {
                            ...current.backendPolicy,
                            parallelBackendLoads: Number(event.target.value || 1),
                          },
                        }))
                      }
                    />
                  </label>
                  <label className="studio-settings-field">
                    <span>Health probe interval</span>
                    <input
                      value={controlPlane.backendPolicy.healthProbeInterval}
                      onChange={(event) =>
                        updateEngineDraft((current) => ({
                          ...current,
                          backendPolicy: {
                            ...current.backendPolicy,
                            healthProbeInterval: event.target.value,
                          },
                        }))
                      }
                    />
                  </label>
                  <label className="studio-settings-field">
                    <span>Log level</span>
                    <input
                      value={controlPlane.backendPolicy.logLevel}
                      onChange={(event) =>
                        updateEngineDraft((current) => ({
                          ...current,
                          backendPolicy: {
                            ...current.backendPolicy,
                            logLevel: event.target.value,
                          },
                        }))
                      }
                    />
                  </label>
                  <label className="studio-settings-field">
                    <span>Retention days</span>
                    <input
                      type="number"
                      min={1}
                      value={controlPlane.responses.retainReceiptsDays}
                      onChange={(event) =>
                        updateEngineDraft((current) => ({
                          ...current,
                          responses: {
                            ...current.responses,
                            retainReceiptsDays: Number(event.target.value || 1),
                          },
                        }))
                      }
                    />
                  </label>
                  <label className="studio-settings-toggle">
                    <input
                      type="checkbox"
                      checked={controlPlane.backendPolicy.allowParallelRequests}
                      onChange={(event) =>
                        updateEngineDraft((current) => ({
                          ...current,
                          backendPolicy: {
                            ...current.backendPolicy,
                            allowParallelRequests: event.target.checked,
                          },
                        }))
                      }
                    />
                    <div>
                      <strong>Allow parallel requests</strong>
                      <span>Keep concurrent local workloads inside the runtime budget.</span>
                    </div>
                  </label>
                  <label className="studio-settings-toggle">
                    <input
                      type="checkbox"
                      checked={controlPlane.watchdog.forceEvictionWhenBusy}
                      onChange={(event) =>
                        updateEngineDraft((current) => ({
                          ...current,
                          watchdog: {
                            ...current.watchdog,
                            forceEvictionWhenBusy: event.target.checked,
                          },
                        }))
                      }
                    />
                    <div>
                      <strong>Force eviction when busy</strong>
                      <span>Allow the kernel to reclaim residency even during active API pressure.</span>
                    </div>
                  </label>
                  <label className="studio-settings-toggle">
                    <input
                      type="checkbox"
                      checked={controlPlane.memory.preferGpu}
                      onChange={(event) =>
                        updateEngineDraft((current) => ({
                          ...current,
                          memory: {
                            ...current.memory,
                            preferGpu: event.target.checked,
                          },
                        }))
                      }
                    />
                    <div>
                      <strong>Prefer GPU memory</strong>
                      <span>Bias reclaimed workloads toward GPU residency when hardware is available.</span>
                    </div>
                  </label>
                  <label className="studio-settings-toggle">
                    <input
                      type="checkbox"
                      checked={controlPlane.backendPolicy.autoShutdownOnIdle}
                      onChange={(event) =>
                        updateEngineDraft((current) => ({
                          ...current,
                          backendPolicy: {
                            ...current.backendPolicy,
                            autoShutdownOnIdle: event.target.checked,
                          },
                        }))
                      }
                    />
                    <div>
                      <strong>Shutdown idle backends</strong>
                      <span>Collapse residency back to zero when local demand disappears.</span>
                    </div>
                  </label>
                  <label className="studio-settings-toggle">
                    <input
                      type="checkbox"
                      checked={controlPlane.responses.persistArtifacts}
                      onChange={(event) =>
                        updateEngineDraft((current) => ({
                          ...current,
                          responses: {
                            ...current.responses,
                            persistArtifacts: event.target.checked,
                          },
                        }))
                      }
                    />
                    <div>
                      <strong>Persist response artifacts</strong>
                      <span>Keep output artifacts and receipts available for later review.</span>
                    </div>
                  </label>
                  <label className="studio-settings-toggle">
                    <input
                      type="checkbox"
                      checked={controlPlane.responses.allowStreaming}
                      onChange={(event) =>
                        updateEngineDraft((current) => ({
                          ...current,
                          responses: {
                            ...current.responses,
                            allowStreaming: event.target.checked,
                          },
                        }))
                      }
                    />
                    <div>
                      <strong>Allow streaming</strong>
                      <span>Keep partial local responses visible while workloads are still running.</span>
                    </div>
                  </label>
                  <label className="studio-settings-toggle">
                    <input
                      type="checkbox"
                      checked={controlPlane.responses.storeRequestPreviews}
                      onChange={(event) =>
                        updateEngineDraft((current) => ({
                          ...current,
                          responses: {
                            ...current.responses,
                            storeRequestPreviews: event.target.checked,
                          },
                        }))
                      }
                    />
                    <div>
                      <strong>Store request previews</strong>
                      <span>Retain sanitized request previews alongside receipts for later audit.</span>
                    </div>
                  </label>
                </div>
              </article>
            </div>
          ) : null}

          {selectedSection === "storage_api" && controlPlane ? (
            <div className="studio-settings-stack">
              <article className="studio-settings-card">
                <div className="studio-settings-card-head">
                  <div>
                    <span className="studio-settings-card-eyebrow">Storage</span>
                    <h2>Filesystem and runtime paths</h2>
                  </div>
                  <span className="studio-settings-pill">Local only</span>
                </div>
                <div className="studio-settings-profile-grid">
                  <label className="studio-settings-field">
                    <span>Models path</span>
                    <input
                      value={controlPlane.storage.modelsPath}
                      onChange={(event) =>
                        updateEngineDraft((current) => ({
                          ...current,
                          storage: {
                            ...current.storage,
                            modelsPath: event.target.value,
                          },
                        }))
                      }
                    />
                  </label>
                  <label className="studio-settings-field">
                    <span>Backends path</span>
                    <input
                      value={controlPlane.storage.backendsPath}
                      onChange={(event) =>
                        updateEngineDraft((current) => ({
                          ...current,
                          storage: {
                            ...current.storage,
                            backendsPath: event.target.value,
                          },
                        }))
                      }
                    />
                  </label>
                  <label className="studio-settings-field">
                    <span>Artifacts path</span>
                    <input
                      value={controlPlane.storage.artifactsPath}
                      onChange={(event) =>
                        updateEngineDraft((current) => ({
                          ...current,
                          storage: {
                            ...current.storage,
                            artifactsPath: event.target.value,
                          },
                        }))
                      }
                    />
                  </label>
                  <label className="studio-settings-field">
                    <span>Cache path</span>
                    <input
                      value={controlPlane.storage.cachePath}
                      onChange={(event) =>
                        updateEngineDraft((current) => ({
                          ...current,
                          storage: {
                            ...current.storage,
                            cachePath: event.target.value,
                          },
                        }))
                      }
                    />
                  </label>
                </div>
              </article>

              <article className="studio-settings-card">
                <div className="studio-settings-card-head">
                  <div>
                    <span className="studio-settings-card-eyebrow">API</span>
                    <h2>API exposure and compatibility</h2>
                  </div>
                  <span className="studio-settings-pill">Kernel-backed</span>
                </div>
                <div className="studio-settings-form-grid">
                  <label className="studio-settings-field">
                    <span>Bind address</span>
                    <input
                      value={controlPlane.api.bindAddress}
                      onChange={(event) =>
                        updateEngineDraft((current) => ({
                          ...current,
                          api: {
                            ...current.api,
                            bindAddress: event.target.value,
                          },
                        }))
                      }
                    />
                  </label>
                  <label className="studio-settings-field">
                    <span>CORS mode</span>
                    <input
                      value={controlPlane.api.corsMode}
                      onChange={(event) =>
                        updateEngineDraft((current) => ({
                          ...current,
                          api: {
                            ...current.api,
                            corsMode: event.target.value,
                          },
                        }))
                      }
                    />
                  </label>
                  <label className="studio-settings-field">
                    <span>Auth mode</span>
                    <input
                      value={controlPlane.api.authMode}
                      onChange={(event) =>
                        updateEngineDraft((current) => ({
                          ...current,
                          api: {
                            ...current.api,
                            authMode: event.target.value,
                          },
                        }))
                      }
                    />
                  </label>
                  <label className="studio-settings-toggle">
                    <input
                      type="checkbox"
                      checked={controlPlane.api.remoteAccessEnabled}
                      onChange={(event) =>
                        updateEngineDraft((current) => ({
                          ...current,
                          api: {
                            ...current.api,
                            remoteAccessEnabled: event.target.checked,
                          },
                        }))
                      }
                    />
                    <div>
                      <strong>Allow remote access</strong>
                      <span>Expose runtime services beyond localhost when appropriate.</span>
                    </div>
                  </label>
                  <label className="studio-settings-toggle">
                    <input
                      type="checkbox"
                      checked={controlPlane.api.exposeCompatRoutes}
                      onChange={(event) =>
                        updateEngineDraft((current) => ({
                          ...current,
                          api: {
                            ...current.api,
                            exposeCompatRoutes: event.target.checked,
                          },
                        }))
                      }
                    />
                    <div>
                      <strong>Expose compatibility routes</strong>
                      <span>Keep OpenAI, Anthropic, and speech facades operator-controlled.</span>
                    </div>
                  </label>
                </div>
              </article>

              <article className="studio-settings-card">
                <div className="studio-settings-card-head">
                  <div>
                    <span className="studio-settings-card-eyebrow">Facades</span>
                    <h2>Compatibility routes</h2>
                  </div>
                  <span className="studio-settings-pill">
                    {engineSnapshot?.compatibilityRoutes.filter((route) => route.enabled).length ??
                      0}{" "}
                    live
                  </span>
                </div>
                <div className="studio-settings-stack studio-settings-stack--compact">
                  {(engineSnapshot?.compatibilityRoutes ?? []).map((route) => (
                    <article
                      key={route.id}
                      className={`studio-settings-subcard ${route.enabled ? "is-live" : "is-muted"}`}
                    >
                      <div className="studio-settings-subcard-head">
                        <strong>{route.label}</strong>
                        <span>{route.enabled ? "Live" : "Hidden"}</span>
                      </div>
                      <p>{route.path}</p>
                      <small>{route.url}</small>
                    </article>
                  ))}
                </div>
              </article>
            </div>
          ) : null}

          {selectedSection === "sources" && controlPlane ? (
            <div className="studio-settings-stack">
              <article className="studio-settings-card">
                <div className="studio-settings-card-head">
                  <div>
                    <span className="studio-settings-card-eyebrow">Sources</span>
                    <h2>Model and backend galleries</h2>
                  </div>
                  <span className="studio-settings-pill">
                    {controlPlane.galleries.filter((source) => source.enabled).length} enabled
                  </span>
                </div>
                <p className="studio-settings-body">
                  The gallery catalog and migration sources now live in the Settings plane
                  instead of hiding inside a capabilities-only workflow.
                </p>
                <div className="studio-settings-stack studio-settings-stack--compact">
                  {controlPlane.galleries.map((source, index) => (
                    <article key={source.id} className="studio-settings-subcard">
                      <div className="studio-settings-subcard-head">
                        <strong>{source.label}</strong>
                        <span>{humanize(source.compatibilityTier)}</span>
                      </div>
                      <div className="studio-settings-chip-row">
                        <span className="studio-settings-chip">{humanize(source.kind)}</span>
                        <span className="studio-settings-chip">
                          {humanize(source.syncStatus)}
                        </span>
                      </div>
                      <div className="studio-settings-profile-grid">
                        <label className="studio-settings-field">
                          <span>Source URI</span>
                          <input
                            value={source.uri}
                            onChange={(event) =>
                              updateEngineDraft((current) => ({
                                ...current,
                                galleries: current.galleries.map((entry, entryIndex) =>
                                  entryIndex === index
                                    ? { ...entry, uri: event.target.value }
                                    : entry,
                                ),
                              }))
                            }
                          />
                        </label>
                        <label className="studio-settings-toggle">
                          <input
                            type="checkbox"
                            checked={source.enabled}
                            onChange={(event) =>
                              updateEngineDraft((current) => ({
                                ...current,
                                galleries: current.galleries.map((entry, entryIndex) =>
                                  entryIndex === index
                                    ? { ...entry, enabled: event.target.checked }
                                    : entry,
                                ),
                              }))
                            }
                          />
                          <div>
                            <strong>Enabled</strong>
                            <span>Include this source in the first-party control plane.</span>
                          </div>
                        </label>
                        <div className="studio-settings-inline-actions">
                          <button
                            type="button"
                            className="studio-settings-secondary"
                            onClick={() =>
                              updateEngineDraft((current) => ({
                                ...current,
                                galleries: current.galleries.filter(
                                  (_entry, entryIndex) => entryIndex !== index,
                                ),
                              }))
                            }
                          >
                            Remove source
                          </button>
                        </div>
                      </div>
                    </article>
                  ))}
                </div>
                <div className="studio-settings-actions">
                  <button
                    type="button"
                    className="studio-settings-secondary"
                    onClick={() =>
                      updateEngineDraft((current) => ({
                        ...current,
                        galleries: [
                          ...current.galleries,
                          {
                            id: `custom.gallery.${current.galleries.length + 1}`,
                            kind: "model",
                            label: "Custom gallery",
                            uri: "",
                            enabled: true,
                            syncStatus: "planned",
                            compatibilityTier: "native",
                          },
                        ],
                      }))
                    }
                  >
                    Add gallery source
                  </button>
                </div>
              </article>
            </div>
          ) : null}

          {selectedSection === "environment" && controlPlane ? (
            <div className="studio-settings-stack">
              <article className="studio-settings-card">
                <div className="studio-settings-card-head">
                  <div>
                    <span className="studio-settings-card-eyebrow">Environment</span>
                    <h2>Runtime bindings</h2>
                  </div>
                  <span className="studio-settings-pill">
                    {controlPlane.environment.length} bindings
                  </span>
                </div>
                <p className="studio-settings-body">
                  Bindings are now kernel-backed settings documents so the same
                  runtime posture can later be applied from the CLI or another shell.
                </p>
                <div className="studio-settings-stack studio-settings-stack--compact">
                  {controlPlane.environment.map((binding, index) => (
                    <div key={`${binding.key}-${index}`} className="studio-settings-binding-row">
                      <input
                        value={binding.key}
                        onChange={(event) =>
                          updateEngineDraft((current) => ({
                            ...current,
                            environment: current.environment.map((entry, entryIndex) =>
                              entryIndex === index
                                ? { ...entry, key: event.target.value }
                                : entry,
                            ),
                          }))
                        }
                        placeholder="ENV_KEY"
                      />
                      <input
                        value={binding.value}
                        onChange={(event) =>
                          updateEngineDraft((current) => ({
                            ...current,
                            environment: current.environment.map((entry, entryIndex) =>
                              entryIndex === index
                                ? { ...entry, value: event.target.value }
                                : entry,
                            ),
                          }))
                        }
                        placeholder="value"
                      />
                      <label className="studio-settings-binding-secret">
                        <input
                          type="checkbox"
                          checked={binding.secret}
                          onChange={(event) =>
                            updateEngineDraft((current) => ({
                              ...current,
                              environment: current.environment.map((entry, entryIndex) =>
                                entryIndex === index
                                  ? { ...entry, secret: event.target.checked }
                                  : entry,
                              ),
                            }))
                          }
                        />
                        <span>Secret</span>
                      </label>
                      <button
                        type="button"
                        className="studio-settings-secondary"
                        onClick={() =>
                          updateEngineDraft((current) => ({
                            ...current,
                            environment: current.environment.filter(
                              (_entry, entryIndex) => entryIndex !== index,
                            ),
                          }))
                        }
                      >
                        Remove
                      </button>
                    </div>
                  ))}
                </div>
                <div className="studio-settings-actions">
                  <button
                    type="button"
                    className="studio-settings-secondary"
                    onClick={() =>
                      updateEngineDraft((current) => ({
                        ...current,
                        environment: [
                          ...current.environment,
                          { key: "", value: "", secret: false },
                        ],
                      }))
                    }
                  >
                    Add binding
                  </button>
                </div>
              </article>
            </div>
          ) : null}

          {selectedSection === "knowledge" ? (
            <div className="studio-settings-stack">
              <article className="studio-settings-card">
                <div className="studio-settings-card-head">
                  <div>
                    <span className="studio-settings-card-eyebrow">Knowledge</span>
                    <h2>Collections and retrieval scopes</h2>
                  </div>
                  <span className="studio-settings-pill">
                    {knowledgeCollections.length} collections
                  </span>
                </div>
                <p className="studio-settings-body">
                  LocalAI-style collections now land in `ioi-memory` as durable,
                  embedding-backed knowledge entries. Each entry gets its own
                  retrieval scope so agent IDE flows can target or exclude it
                  cleanly.
                </p>
                {knowledgeMessage ? (
                  <p className="studio-settings-success">{knowledgeMessage}</p>
                ) : null}
                {knowledgeError ? (
                  <p className="studio-settings-error">{knowledgeError}</p>
                ) : null}
                <div className="studio-settings-profile-grid">
                  <label className="studio-settings-field">
                    <span>Collection name</span>
                    <input
                      value={knowledgeCollectionName}
                      onChange={(event) => setKnowledgeCollectionName(event.target.value)}
                      placeholder="research-notes"
                    />
                  </label>
                  <label className="studio-settings-field studio-settings-field--wide">
                    <span>Description</span>
                    <input
                      value={knowledgeCollectionDescription}
                      onChange={(event) =>
                        setKnowledgeCollectionDescription(event.target.value)
                      }
                      placeholder="What this collection is for"
                    />
                  </label>
                </div>
                <div className="studio-settings-actions">
                  <button
                    type="button"
                    className="studio-settings-secondary"
                    disabled={knowledgeBusy || knowledgeCollectionName.trim().length === 0}
                    onClick={() =>
                      void runKnowledgeAction(async () => {
                        const created = await runtime.createKnowledgeCollection(
                          knowledgeCollectionName,
                          knowledgeCollectionDescription || null,
                        );
                        setKnowledgeCollectionName("");
                        setKnowledgeCollectionDescription("");
                        setSelectedKnowledgeCollectionId(created.collectionId);
                      }, "Knowledge collection created.")
                    }
                  >
                    {knowledgeBusy ? "Working..." : "Create collection"}
                  </button>
                </div>
              </article>

              <article className="studio-settings-card">
                <div className="studio-settings-card-head">
                  <div>
                    <span className="studio-settings-card-eyebrow">Collections</span>
                    <h2>Registry</h2>
                  </div>
                  <span className="studio-settings-pill">
                    {knowledgeLoading ? "Loading" : `${knowledgeCollections.length} live`}
                  </span>
                </div>
                {knowledgeLoading ? (
                  <p className="studio-settings-body">Loading knowledge collections...</p>
                ) : knowledgeCollections.length === 0 ? (
                  <p className="studio-settings-body">
                    No knowledge collections exist yet. Create one above to begin
                    ingesting files or durable notes.
                  </p>
                ) : (
                  <div className="studio-settings-summary-grid">
                    {knowledgeCollections.map((collection) => (
                      <button
                        key={collection.collectionId}
                        type="button"
                        className={`studio-settings-subcard ${
                          selectedKnowledgeCollection?.collectionId === collection.collectionId
                            ? "is-live"
                            : ""
                        }`}
                        onClick={() => {
                          setSelectedKnowledgeCollectionId(collection.collectionId);
                          setKnowledgeSearchResults([]);
                          setSelectedKnowledgeEntryContent(null);
                        }}
                      >
                        <strong>{collection.label}</strong>
                        <span>{collection.entries.length} entries</span>
                        <small>{collection.sources.length} sources</small>
                        <p>{collection.description || collection.collectionId}</p>
                      </button>
                    ))}
                  </div>
                )}
              </article>

              {selectedKnowledgeCollection ? (
                <article className="studio-settings-card">
                  <div className="studio-settings-card-head">
                    <div>
                      <span className="studio-settings-card-eyebrow">Selected collection</span>
                      <h2>{selectedKnowledgeCollection.label}</h2>
                    </div>
                    <span className="studio-settings-pill">
                      {selectedKnowledgeCollection.entries.length} entries
                    </span>
                  </div>
                  <p className="studio-settings-body">
                    Scope root:{" "}
                    <code>{selectedKnowledgeCollection.collectionId}</code>. Entries are
                    kept as independent retrieval scopes for clean delete/reset semantics.
                  </p>
                  <div className="studio-settings-summary-grid">
                    <article className="studio-settings-subcard">
                      <strong>Entries</strong>
                      <span>{selectedKnowledgeCollection.entries.length}</span>
                    </article>
                    <article className="studio-settings-subcard">
                      <strong>Sources</strong>
                      <span>{selectedKnowledgeCollection.sources.length}</span>
                    </article>
                    <article className="studio-settings-subcard">
                      <strong>Updated</strong>
                      <span>{formatSettingsTime(selectedKnowledgeCollection.updatedAtMs)}</span>
                    </article>
                    <article className="studio-settings-subcard">
                      <strong>Created</strong>
                      <span>{formatSettingsTime(selectedKnowledgeCollection.createdAtMs)}</span>
                    </article>
                  </div>
                  <div className="studio-settings-actions">
                    <button
                      type="button"
                      className="studio-settings-secondary"
                      disabled={knowledgeBusy}
                      onClick={() =>
                        void runKnowledgeAction(
                          () =>
                            runtime.resetKnowledgeCollection(
                              selectedKnowledgeCollection.collectionId,
                            ),
                          "Knowledge collection reset.",
                        )
                      }
                    >
                      Reset collection
                    </button>
                    <button
                      type="button"
                      className="studio-settings-danger"
                      disabled={knowledgeBusy}
                      onClick={() =>
                        void runKnowledgeAction(async () => {
                          await runtime.deleteKnowledgeCollection(
                            selectedKnowledgeCollection.collectionId,
                          );
                          setSelectedKnowledgeCollectionId(null);
                          setKnowledgeSearchResults([]);
                          setSelectedKnowledgeEntryContent(null);
                        }, "Knowledge collection removed.")
                      }
                    >
                      Delete collection
                    </button>
                  </div>
                </article>
              ) : null}

              {selectedKnowledgeCollection ? (
                <article className="studio-settings-card">
                  <div className="studio-settings-card-head">
                    <div>
                      <span className="studio-settings-card-eyebrow">Ingestion</span>
                      <h2>Add entries</h2>
                    </div>
                    <span className="studio-settings-pill">Retrieval-ready</span>
                  </div>
                  <div className="studio-settings-profile-grid">
                    <label className="studio-settings-field">
                      <span>Entry title</span>
                      <input
                        value={knowledgeEntryTitle}
                        onChange={(event) => setKnowledgeEntryTitle(event.target.value)}
                        placeholder="Q2 launch notes"
                      />
                    </label>
                    <label className="studio-settings-field studio-settings-field--wide">
                      <span>Note content</span>
                      <textarea
                        value={knowledgeEntryContent}
                        onChange={(event) => setKnowledgeEntryContent(event.target.value)}
                        placeholder="Paste durable knowledge or procedure notes here."
                        rows={6}
                      />
                    </label>
                    <div className="studio-settings-actions">
                      <button
                        type="button"
                        className="studio-settings-secondary"
                        disabled={
                          knowledgeBusy ||
                          knowledgeEntryTitle.trim().length === 0 ||
                          knowledgeEntryContent.trim().length === 0
                        }
                        onClick={() =>
                          void runKnowledgeAction(async () => {
                            await runtime.addKnowledgeTextEntry(
                              selectedKnowledgeCollection.collectionId,
                              knowledgeEntryTitle,
                              knowledgeEntryContent,
                            );
                            setKnowledgeEntryTitle("");
                            setKnowledgeEntryContent("");
                          }, "Knowledge note ingested.")
                        }
                      >
                        Add text entry
                      </button>
                    </div>
                  </div>
                  <div className="studio-settings-profile-grid">
                    <label className="studio-settings-field studio-settings-field--wide">
                      <span>Import file path</span>
                      <input
                        value={knowledgeImportPath}
                        onChange={(event) => setKnowledgeImportPath(event.target.value)}
                        placeholder="/abs/path/to/doc.md"
                      />
                    </label>
                    <div className="studio-settings-actions">
                      <button
                        type="button"
                        className="studio-settings-secondary"
                        disabled={knowledgeBusy || knowledgeImportPath.trim().length === 0}
                        onClick={() =>
                          void runKnowledgeAction(async () => {
                            await runtime.importKnowledgeFile(
                              selectedKnowledgeCollection.collectionId,
                              knowledgeImportPath,
                            );
                            setKnowledgeImportPath("");
                          }, "Knowledge file imported.")
                        }
                      >
                        Import file
                      </button>
                    </div>
                  </div>
                </article>
              ) : null}

              {selectedKnowledgeCollection ? (
                <article className="studio-settings-card">
                  <div className="studio-settings-card-head">
                    <div>
                      <span className="studio-settings-card-eyebrow">Sources</span>
                      <h2>Registered source endpoints</h2>
                    </div>
                    <span className="studio-settings-pill">
                      {selectedKnowledgeCollection.sources.length} configured
                    </span>
                  </div>
                  <div className="studio-settings-profile-grid">
                    <label className="studio-settings-field studio-settings-field--wide">
                      <span>Source URI or path</span>
                      <input
                        value={knowledgeSourceUri}
                        onChange={(event) => setKnowledgeSourceUri(event.target.value)}
                        placeholder="https://docs.example.com or /data/docs"
                      />
                    </label>
                    <label className="studio-settings-field">
                      <span>Poll interval minutes</span>
                      <input
                        value={knowledgeSourceInterval}
                        onChange={(event) => setKnowledgeSourceInterval(event.target.value)}
                        placeholder="60"
                      />
                    </label>
                  </div>
                  <div className="studio-settings-actions">
                    <button
                      type="button"
                      className="studio-settings-secondary"
                      disabled={knowledgeBusy || knowledgeSourceUri.trim().length === 0}
                      onClick={() =>
                        void runKnowledgeAction(async () => {
                          await runtime.addKnowledgeCollectionSource(
                            selectedKnowledgeCollection.collectionId,
                            knowledgeSourceUri,
                            knowledgeSourceInterval.trim().length > 0
                              ? Number(knowledgeSourceInterval)
                              : null,
                          );
                          setKnowledgeSourceUri("");
                          setKnowledgeSourceInterval("");
                        }, "Knowledge source registered.")
                      }
                    >
                      Add source
                    </button>
                  </div>
                  <div className="studio-settings-stack studio-settings-stack--compact">
                    {selectedKnowledgeCollection.sources.length === 0 ? (
                      <p className="studio-settings-body">
                        No recurring sources are registered for this collection yet.
                      </p>
                    ) : (
                      selectedKnowledgeCollection.sources.map((source) => (
                        <article key={source.sourceId} className="studio-settings-subcard">
                          <div className="studio-settings-subcard-head">
                            <strong>{source.uri}</strong>
                            <span>{humanize(source.syncStatus)}</span>
                          </div>
                          <div className="studio-settings-chip-row">
                            <span className="studio-settings-chip">{humanize(source.kind)}</span>
                            <span className="studio-settings-chip">
                              {source.enabled ? "Enabled" : "Disabled"}
                            </span>
                            {source.pollIntervalMinutes ? (
                              <span className="studio-settings-chip">
                                Every {source.pollIntervalMinutes} min
                              </span>
                            ) : null}
                          </div>
                          <div className="studio-settings-actions">
                            <button
                              type="button"
                              className="studio-settings-secondary"
                              disabled={knowledgeBusy}
                              onClick={() =>
                                void runKnowledgeAction(
                                  () =>
                                    runtime.removeKnowledgeCollectionSource(
                                      selectedKnowledgeCollection.collectionId,
                                      source.sourceId,
                                    ),
                                  "Knowledge source removed.",
                                )
                              }
                            >
                              Remove source
                            </button>
                          </div>
                        </article>
                      ))
                    )}
                  </div>
                </article>
              ) : null}

              {selectedKnowledgeCollection ? (
                <article className="studio-settings-card">
                  <div className="studio-settings-card-head">
                    <div>
                      <span className="studio-settings-card-eyebrow">Search</span>
                      <h2>Collection retrieval check</h2>
                    </div>
                    <span className="studio-settings-pill">Hybrid</span>
                  </div>
                  <div className="studio-settings-profile-grid">
                    <label className="studio-settings-field studio-settings-field--wide">
                      <span>Search query</span>
                      <input
                        value={knowledgeSearchQuery}
                        onChange={(event) => setKnowledgeSearchQuery(event.target.value)}
                        placeholder="What does this collection know about..."
                      />
                    </label>
                  </div>
                  <div className="studio-settings-actions">
                    <button
                      type="button"
                      className="studio-settings-secondary"
                      disabled={knowledgeSearchLoading || knowledgeSearchQuery.trim().length === 0}
                      onClick={async () => {
                        setKnowledgeSearchLoading(true);
                        setKnowledgeError(null);
                        try {
                          const results = await runtime.searchKnowledgeCollection(
                            selectedKnowledgeCollection.collectionId,
                            knowledgeSearchQuery,
                            8,
                          );
                          setKnowledgeSearchResults(results);
                        } catch (nextError) {
                          setKnowledgeError(String(nextError));
                        } finally {
                          setKnowledgeSearchLoading(false);
                        }
                      }}
                    >
                      {knowledgeSearchLoading ? "Searching..." : "Search collection"}
                    </button>
                  </div>
                  <div className="studio-settings-stack studio-settings-stack--compact">
                    {knowledgeSearchResults.map((result) => (
                      <article
                        key={`${result.archivalRecordId}-${result.entryId}`}
                        className="studio-settings-subcard"
                      >
                        <div className="studio-settings-subcard-head">
                          <strong>{result.title}</strong>
                          <span>{Math.round(result.score * 100)}%</span>
                        </div>
                        <div className="studio-settings-chip-row">
                          <span className="studio-settings-chip">{result.entryId}</span>
                          <span className="studio-settings-chip">{result.trustLevel}</span>
                          <span className="studio-settings-chip">{result.scope}</span>
                        </div>
                        <p>{result.snippet}</p>
                      </article>
                    ))}
                    {!knowledgeSearchLoading &&
                    knowledgeSearchQuery.trim().length > 0 &&
                    knowledgeSearchResults.length === 0 ? (
                      <p className="studio-settings-body">
                        No hits yet for this query in the selected collection.
                      </p>
                    ) : null}
                  </div>
                </article>
              ) : null}

              {selectedKnowledgeCollection ? (
                <article className="studio-settings-card">
                  <div className="studio-settings-card-head">
                    <div>
                      <span className="studio-settings-card-eyebrow">Entries</span>
                      <h2>Stored artifacts and scopes</h2>
                    </div>
                    <span className="studio-settings-pill">
                      {selectedKnowledgeCollection.entries.length} stored
                    </span>
                  </div>
                  <div className="studio-settings-stack studio-settings-stack--compact">
                    {selectedKnowledgeCollection.entries.length === 0 ? (
                      <p className="studio-settings-body">
                        This collection does not have any entries yet.
                      </p>
                    ) : (
                      selectedKnowledgeCollection.entries.map((entry) => (
                        <article key={entry.entryId} className="studio-settings-subcard">
                          <div className="studio-settings-subcard-head">
                            <strong>{entry.title}</strong>
                            <span>{humanize(entry.kind)}</span>
                          </div>
                          <div className="studio-settings-chip-row">
                            <span className="studio-settings-chip">{entry.scope}</span>
                            <span className="studio-settings-chip">
                              {entry.chunkCount} chunks
                            </span>
                            <span className="studio-settings-chip">
                              {entry.byteCount} bytes
                            </span>
                          </div>
                          <p>{entry.contentPreview}</p>
                          <div className="studio-settings-actions">
                            <button
                              type="button"
                              className="studio-settings-secondary"
                              disabled={knowledgeEntryLoading}
                              onClick={async () => {
                                setKnowledgeEntryLoading(true);
                                setKnowledgeError(null);
                                try {
                                  const content =
                                    await runtime.getKnowledgeCollectionEntryContent(
                                      selectedKnowledgeCollection.collectionId,
                                      entry.entryId,
                                    );
                                  setSelectedKnowledgeEntryContent(content);
                                } catch (nextError) {
                                  setKnowledgeError(String(nextError));
                                } finally {
                                  setKnowledgeEntryLoading(false);
                                }
                              }}
                            >
                              {knowledgeEntryLoading ? "Opening..." : "Open entry"}
                            </button>
                            <button
                              type="button"
                              className="studio-settings-danger"
                              disabled={knowledgeBusy}
                              onClick={() =>
                                void runKnowledgeAction(
                                  async () => {
                                    await runtime.removeKnowledgeCollectionEntry(
                                      selectedKnowledgeCollection.collectionId,
                                      entry.entryId,
                                    );
                                    if (
                                      selectedKnowledgeEntryContent?.entryId === entry.entryId
                                    ) {
                                      setSelectedKnowledgeEntryContent(null);
                                    }
                                  },
                                  "Knowledge entry removed.",
                                )
                              }
                            >
                              Remove entry
                            </button>
                          </div>
                        </article>
                      ))
                    )}
                  </div>
                </article>
              ) : null}

              {selectedKnowledgeEntryContent ? (
                <article className="studio-settings-card">
                  <div className="studio-settings-card-head">
                    <div>
                      <span className="studio-settings-card-eyebrow">Entry content</span>
                      <h2>{selectedKnowledgeEntryContent.title}</h2>
                    </div>
                    <span className="studio-settings-pill">
                      {selectedKnowledgeEntryContent.byteCount} bytes
                    </span>
                  </div>
                  <label className="studio-settings-field studio-settings-field--wide">
                    <span>Materialized artifact</span>
                    <textarea
                      value={selectedKnowledgeEntryContent.content}
                      readOnly
                      rows={12}
                    />
                  </label>
                </article>
              ) : null}
            </div>
          ) : null}

          {selectedSection === "skill_sources" ? (
            <div className="studio-settings-stack">
              <article className="studio-settings-card">
                <div className="studio-settings-card-head">
                  <div>
                    <span className="studio-settings-card-eyebrow">Skill sources</span>
                    <h2>Source registry and sync</h2>
                  </div>
                  <span className="studio-settings-pill">
                    {skillSources.length} sources
                  </span>
                </div>
                <p className="studio-settings-body">
                  Point the shell at local skill roots or checked-out repositories.
                  Autopilot syncs `SKILL.md` manifests into a first-party source registry
                  so runtime skills can carry provenance instead of just “starter” versus
                  “runtime” labels.
                </p>
                {skillSourcesMessage ? (
                  <p className="studio-settings-success">{skillSourcesMessage}</p>
                ) : null}
                {skillSourcesError ? (
                  <p className="studio-settings-error">{skillSourcesError}</p>
                ) : null}
                <div className="studio-settings-profile-grid">
                  <label className="studio-settings-field">
                    <span>Source label</span>
                    <input
                      value={skillSourceLabel}
                      onChange={(event) => setSkillSourceLabel(event.target.value)}
                      placeholder="Workspace skills"
                    />
                  </label>
                  <label className="studio-settings-field studio-settings-field--wide">
                    <span>Directory or checked-out repo path</span>
                    <input
                      value={skillSourceUri}
                      onChange={(event) => setSkillSourceUri(event.target.value)}
                      placeholder="/abs/path/to/skills-or-repo"
                    />
                  </label>
                </div>
                <div className="studio-settings-actions">
                  <button
                    type="button"
                    className="studio-settings-secondary"
                    disabled={skillSourcesBusy || skillSourceUri.trim().length === 0}
                    onClick={() =>
                      void runSkillSourceAction(async () => {
                        const created = await runtime.addSkillSource(
                          skillSourceUri,
                          skillSourceLabel || null,
                        );
                        setSelectedSkillSourceId(created.sourceId);
                        setSkillSourceLabel("");
                        setSkillSourceUri("");
                      }, "Skill source added and synced.")
                    }
                  >
                    {skillSourcesBusy ? "Working..." : "Add skill source"}
                  </button>
                </div>
              </article>

              <article className="studio-settings-card">
                <div className="studio-settings-card-head">
                  <div>
                    <span className="studio-settings-card-eyebrow">Registered sources</span>
                    <h2>Provenance roots</h2>
                  </div>
                  <span className="studio-settings-pill">
                    {skillSourcesLoading ? "Loading" : `${skillSources.length} tracked`}
                  </span>
                </div>
                {skillSourcesLoading ? (
                  <p className="studio-settings-body">Loading skill sources...</p>
                ) : skillSources.length === 0 ? (
                  <p className="studio-settings-body">
                    No skill sources are registered yet.
                  </p>
                ) : (
                  <div className="studio-settings-summary-grid">
                    {skillSources.map((source) => (
                      <button
                        key={source.sourceId}
                        type="button"
                        className={`studio-settings-subcard ${
                          selectedSkillSource?.sourceId === source.sourceId
                            ? "is-live"
                            : ""
                        }`}
                        onClick={() => setSelectedSkillSourceId(source.sourceId)}
                      >
                        <strong>{source.label}</strong>
                        <span>{humanize(source.syncStatus)}</span>
                        <small>{source.discoveredSkills.length} skills</small>
                        <p>{source.uri}</p>
                      </button>
                    ))}
                  </div>
                )}
              </article>

              {selectedSkillSource ? (
                <article className="studio-settings-card">
                  <div className="studio-settings-card-head">
                    <div>
                      <span className="studio-settings-card-eyebrow">Selected source</span>
                      <h2>{selectedSkillSource.label}</h2>
                    </div>
                    <span className="studio-settings-pill">
                      {humanize(selectedSkillSource.kind)}
                    </span>
                  </div>
                  <div className="studio-settings-summary-grid">
                    <article className="studio-settings-subcard">
                      <strong>Status</strong>
                      <span>{humanize(selectedSkillSource.syncStatus)}</span>
                    </article>
                    <article className="studio-settings-subcard">
                      <strong>Discovered skills</strong>
                      <span>{selectedSkillSource.discoveredSkills.length}</span>
                    </article>
                    <article className="studio-settings-subcard">
                      <strong>Enabled</strong>
                      <span>{selectedSkillSource.enabled ? "Yes" : "No"}</span>
                    </article>
                    <article className="studio-settings-subcard">
                      <strong>Last sync</strong>
                      <span>
                        {selectedSkillSource.lastSyncedAtMs
                          ? formatSettingsTime(selectedSkillSource.lastSyncedAtMs)
                          : "Never"}
                      </span>
                    </article>
                  </div>
                  <p className="studio-settings-body">
                    Path: <code>{selectedSkillSource.uri}</code>
                  </p>
                  {selectedSkillSource.lastError ? (
                    <div className="studio-settings-callout">
                      <strong>Last sync error</strong>
                      <p>{selectedSkillSource.lastError}</p>
                    </div>
                  ) : null}
                  <div className="studio-settings-actions">
                    <button
                      type="button"
                      className="studio-settings-secondary"
                      disabled={skillSourcesBusy}
                      onClick={() =>
                        void runSkillSourceAction(
                          async () => {
                            await runtime.syncSkillSource(selectedSkillSource.sourceId);
                          },
                          "Skill source synced.",
                        )
                      }
                    >
                      Sync source
                    </button>
                    <button
                      type="button"
                      className="studio-settings-secondary"
                      disabled={skillSourcesBusy}
                      onClick={() =>
                        void runSkillSourceAction(
                          async () => {
                            await runtime.setSkillSourceEnabled(
                              selectedSkillSource.sourceId,
                              !selectedSkillSource.enabled,
                            );
                          },
                          selectedSkillSource.enabled
                            ? "Skill source disabled."
                            : "Skill source enabled.",
                        )
                      }
                    >
                      {selectedSkillSource.enabled ? "Disable source" : "Enable source"}
                    </button>
                    <button
                      type="button"
                      className="studio-settings-danger"
                      disabled={skillSourcesBusy}
                      onClick={() =>
                        void runSkillSourceAction(async () => {
                          await runtime.removeSkillSource(selectedSkillSource.sourceId);
                          setSelectedSkillSourceId(null);
                        }, "Skill source removed.")
                      }
                    >
                      Remove source
                    </button>
                  </div>
                </article>
              ) : null}

              {selectedSkillSource ? (
                <article className="studio-settings-card">
                  <div className="studio-settings-card-head">
                    <div>
                      <span className="studio-settings-card-eyebrow">Discovered skills</span>
                      <h2>Indexed manifests</h2>
                    </div>
                    <span className="studio-settings-pill">
                      {selectedSkillSource.discoveredSkills.length} found
                    </span>
                  </div>
                  <div className="studio-settings-stack studio-settings-stack--compact">
                    {selectedSkillSource.discoveredSkills.length === 0 ? (
                      <p className="studio-settings-body">
                        No `SKILL.md` files were discovered under this root yet.
                      </p>
                    ) : (
                      selectedSkillSource.discoveredSkills.map((skill) => (
                        <article
                          key={`${selectedSkillSource.sourceId}:${skill.relativePath}`}
                          className="studio-settings-subcard"
                        >
                          <div className="studio-settings-subcard-head">
                            <strong>{skill.name}</strong>
                            <span>{skill.relativePath}</span>
                          </div>
                          {skill.description ? <p>{skill.description}</p> : null}
                        </article>
                      ))
                    )}
                  </div>
                </article>
              ) : null}
            </div>
          ) : null}

          {selectedSection === "local_data" ? (
            <article className="studio-settings-card">
              <div className="studio-settings-card-head">
                <div>
                  <span className="studio-settings-card-eyebrow">State</span>
                  <h2>Local data footprint</h2>
                </div>
                <span className="studio-settings-pill">Local only</span>
              </div>

              <p className="studio-settings-body">
                This shell keeps conversation history, policy state, runtime settings,
                and browser-side app storage locally so experiments remain isolated to
                this workspace.
              </p>

              <ul className="studio-settings-list">
                {RESET_COPY.map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>

              <div className="studio-settings-callout">
                <strong>Identity survives reset</strong>
                <p>
                  The local identity file is preserved so authenticated flows can rehydrate after
                  reload even when app state is cleared.
                </p>
              </div>
            </article>
          ) : null}

          {selectedSection === "repair_reset" ? (
            <article className="studio-settings-card">
              <div className="studio-settings-card-head">
                <div>
                  <span className="studio-settings-card-eyebrow">Repair</span>
                  <h2>Reset Autopilot data</h2>
                </div>
                <span className="studio-settings-pill studio-settings-pill-warning">Local only</span>
              </div>

              <p className="studio-settings-body">
                Use this when conversation history, cached context, or connector state is leaking
                between builds. The reset preserves identity so remote session history can still
                rehydrate.
              </p>

              <div className="studio-settings-callout">
                <strong>Remote history caveat</strong>
                <p>
                  Session history merged from the kernel can still reappear after reload because this
                  action only wipes local app data.
                </p>
              </div>

              {summary ? <p className="studio-settings-success">{summary}</p> : null}
              {error ? <p className="studio-settings-error">{error}</p> : null}

              <div className="studio-settings-actions">
                <button
                  type="button"
                  className="studio-settings-danger"
                  disabled={isResetting}
                  onClick={() => {
                    void handleReset();
                  }}
                >
                  {isResetting ? "Resetting..." : "Reset Autopilot data"}
                </button>
              </div>
            </article>
          ) : null}

          {selectedSection === "diagnostics" ? (
            <div className="studio-settings-stack">
              <div className="studio-settings-diagnostics">
                {diagnostics.map((item) => (
                  <article
                    key={item.label}
                    className={`studio-settings-status-card tone-${item.tone}`}
                  >
                    <span>{item.label}</span>
                    <strong>{item.value}</strong>
                  </article>
                ))}
              </div>

              {engineSnapshot ? (
                <article className="studio-settings-card">
                  <div className="studio-settings-card-head">
                    <div>
                      <span className="studio-settings-card-eyebrow">Runtime summary</span>
                      <h2>Control-plane snapshot</h2>
                    </div>
                    <span className="studio-settings-pill">
                      {formatSettingsTime(engineSnapshot.generatedAtMs)}
                    </span>
                  </div>
                  <div className="studio-settings-summary-grid">
                    <article className="studio-settings-subcard">
                      <strong>Capability families</strong>
                      <span>{engineSnapshot.capabilities.length}</span>
                    </article>
                    <article className="studio-settings-subcard">
                      <strong>Compatibility routes</strong>
                      <span>{engineSnapshot.compatibilityRoutes.length}</span>
                    </article>
                    <article className="studio-settings-subcard">
                      <strong>Live jobs</strong>
                      <span>{engineSnapshot.jobs.length}</span>
                    </article>
                    <article className="studio-settings-subcard">
                      <strong>Recent receipts</strong>
                      <span>{engineSnapshot.recentActivity.length}</span>
                    </article>
                  </div>
                </article>
              ) : null}
            </div>
          ) : null}
        </section>
      </div>
    </div>
  );
}
