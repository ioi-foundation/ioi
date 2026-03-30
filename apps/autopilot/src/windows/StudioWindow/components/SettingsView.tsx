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
import { cloneLocalEngineControlPlane, humanize } from "./capabilities/model";
import { SettingsViewBody } from "./SettingsViewBody";
import { type SettingsSection } from "./SettingsView.shared";

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

  const view = { runtime, profile, profileDraft, profileSaving, profileError, onProfileDraftChange, onResetProfileDraft, onSaveProfile, selectedSection, setSelectedSection, isResetting, setIsResetting, error, setError, lastResult, setLastResult, engineSnapshot, setEngineSnapshot, engineDraft, setEngineDraft, engineLoading, setEngineLoading, engineSaving, setEngineSaving, engineMessage, setEngineMessage, engineError, setEngineError, knowledgeCollections, setKnowledgeCollections, knowledgeLoading, setKnowledgeLoading, knowledgeBusy, setKnowledgeBusy, knowledgeError, setKnowledgeError, knowledgeMessage, setKnowledgeMessage, knowledgeCollectionName, setKnowledgeCollectionName, knowledgeCollectionDescription, setKnowledgeCollectionDescription, selectedKnowledgeCollectionId, setSelectedKnowledgeCollectionId, knowledgeEntryTitle, setKnowledgeEntryTitle, knowledgeEntryContent, setKnowledgeEntryContent, knowledgeImportPath, setKnowledgeImportPath, knowledgeSourceUri, setKnowledgeSourceUri, knowledgeSourceInterval, setKnowledgeSourceInterval, knowledgeSearchQuery, setKnowledgeSearchQuery, knowledgeSearchResults, setKnowledgeSearchResults, knowledgeSearchLoading, setKnowledgeSearchLoading, knowledgeEntryLoading, setKnowledgeEntryLoading, selectedKnowledgeEntryContent, setSelectedKnowledgeEntryContent, skillSources, setSkillSources, skillSourcesLoading, setSkillSourcesLoading, skillSourcesBusy, setSkillSourcesBusy, skillSourcesError, setSkillSourcesError, skillSourcesMessage, setSkillSourcesMessage, skillSourceLabel, setSkillSourceLabel, skillSourceUri, setSkillSourceUri, selectedSkillSourceId, setSelectedSkillSourceId, profileDirty, controlPlane, engineDirty, loadEngineSnapshot, loadKnowledgeCollections, loadSkillSources, selectedKnowledgeCollection, selectedSkillSource, summary, diagnostics, runKnowledgeAction, runSkillSourceAction, updateEngineDraft, handleReset, handleSaveEngine, renderEngineControls };

  return (
    <div className="studio-settings-view">
      <div className="studio-settings-layout">
        <SettingsViewBody view={view} />
      </div>
    </div>
  );
}
