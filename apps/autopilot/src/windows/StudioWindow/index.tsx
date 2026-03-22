// apps/autopilot/src/windows/StudioWindow/index.tsx
import { useState, useEffect, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import {
  isPermissionGranted,
  requestPermission,
  sendNotification,
} from "@tauri-apps/plugin-notification";
import type { AgentSummary } from "@ioi/agent-ide";
import { TauriRuntime } from "../../services/TauriRuntime";

// Shell Components
import { AgentInstallModal } from "../../components/AgentInstallModal";
import { CommandPalette } from "../../components/CommandPalette";
import { StatusBar } from "../../components/StatusBar";
import { LocalActivityBar } from "./components/LocalActivityBar";
import { CapabilitiesView } from "./components/CapabilitiesView";
import { MissionControlWorkflowsView } from "./components/MissionControlWorkflowsView";
import { MissionControlRunsView } from "./components/MissionControlRunsView";
import { MissionControlControlView } from "./components/MissionControlControlView";
import { NotificationsView } from "./components/NotificationsView";
import { StudioIdeHeader } from "./components/StudioIdeHeader";
import { StudioLeftUtilityPane } from "./components/StudioLeftUtilityPane";
import { StudioExplorerPane } from "./components/StudioExplorerPane";
import { type StudioEditorTab } from "./components/StudioCodeWorkbench";
import { StudioUtilityDrawer } from "./components/StudioUtilityDrawer";
import { listenForAutopilotDataReset } from "../../services/autopilotReset";
import {
  buildConnectorPolicySummary,
  fetchShieldPolicyStateFromRuntime,
  loadShieldPolicyState,
  persistShieldPolicyStateToRuntime,
  type ShieldPolicyState,
} from "./policyCenter";
import type {
  AssistantWorkbenchSession,
  AssistantNotificationRecord,
  AssistantUserProfile,
  InterventionRecord,
} from "../../types";

// Ensure shared CSS is loaded
import "@ioi/agent-ide/dist/style.css";
import "./StudioWindow.css";

// Instantiate the adapter once
const runtime = new TauriRuntime();

type ToastCandidate = Pick<
  InterventionRecord,
  "title" | "summary" | "reason" | "privacy"
>;
type PrimaryView =
  | "workflows"
  | "runs"
  | "inbox"
  | "capabilities"
  | "policy"
  | "settings";

interface ProjectScope {
  id: string;
  name: string;
  description: string;
  environment: string;
  rootPath: string;
}

interface ProjectFileDocument {
  name: string;
  path: string;
  language_hint: string | null;
  content: string;
  size_bytes: number;
  modified_at_ms: number | null;
  is_binary: boolean;
  is_too_large: boolean;
  read_only: boolean;
}

const DEFAULT_PROFILE: AssistantUserProfile = {
  version: 1,
  displayName: "Operator",
  preferredName: null,
  roleLabel: "Private Operator",
  timezone: "UTC",
  locale: "en-US",
  primaryEmail: null,
  avatarSeed: "OP",
  groundingAllowed: false,
};

const WORKSPACE_NAME = "IOI Workspace";
const PROJECT_SCOPES: ProjectScope[] = [
  {
    id: "autopilot-core",
    name: "Autopilot Core",
    description: "Worker control plane and operator shell.",
    environment: "Production",
    rootPath: ".",
  },
  {
    id: "nested-guardian",
    name: "Nested Guardian",
    description: "Consensus verification and safety protocols.",
    environment: "Research",
    rootPath: "docs/consensus/aft",
  },
  {
    id: "capability-lab",
    name: "Capability Lab",
    description: "Connections, skills, and policy experiments.",
    environment: "Staging",
    rootPath: "apps/autopilot",
  },
];

function isEditableElement(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  const tag = target.tagName.toLowerCase();
  return (
    target.isContentEditable ||
    tag === "input" ||
    tag === "textarea" ||
    tag === "select"
  );
}

async function sendNativeAutopilotNotification(
  candidate: ToastCandidate,
): Promise<void> {
  try {
    let granted = await isPermissionGranted();
    if (!granted) {
      const permission = await requestPermission();
      granted = permission === "granted";
    }
    if (!granted) return;

    const body =
      candidate.privacy.previewMode === "redacted" &&
      candidate.privacy.containsSensitiveData
        ? candidate.reason?.trim() || "Open Autopilot for details."
        : candidate.summary;

    await sendNotification({
      title: candidate.title,
      body,
    });
  } catch {
    // Native notification delivery is best-effort.
  }
}

export function StudioWindow() {
  // --- Layout State ---
  const [activeView, setActiveView] = useState<PrimaryView>("workflows");
  const [chatSurface, setChatSurface] = useState<
    "chat" | "reply-composer" | "meeting-prep"
  >("chat");
  const [chatPaneVisible, setChatPaneVisible] = useState(true);
  const [chatPaneMaximized, setChatPaneMaximized] = useState(false);
  const [workflowSurface, setWorkflowSurface] = useState<
    "home" | "code" | "canvas" | "agents" | "catalog"
  >("home");
  const [focusedPolicyConnectorId, setFocusedPolicyConnectorId] = useState<
    string | null
  >(null);
  const [assistantWorkbench, setAssistantWorkbench] =
    useState<AssistantWorkbenchSession | null>(null);
  const [autopilotSeedIntent, setAutopilotSeedIntent] = useState<string | null>(
    null,
  );
  const [notificationBadgeCount, setNotificationBadgeCount] = useState(0);
  const [shieldPolicy, setShieldPolicy] = useState<ShieldPolicyState>(() =>
    loadShieldPolicyState(),
  );
  const [profile, setProfile] = useState<AssistantUserProfile>(DEFAULT_PROFILE);
  const [profileDraft, setProfileDraft] =
    useState<AssistantUserProfile>(DEFAULT_PROFILE);
  const [profileSaving, setProfileSaving] = useState(false);
  const [profileError, setProfileError] = useState<string | null>(null);
  const [shieldPolicyHydrated, setShieldPolicyHydrated] = useState(false);
  const [currentProjectId, setCurrentProjectId] = useState(
    PROJECT_SCOPES[0]?.id ?? "autopilot-core",
  );
  const [editorTabs, setEditorTabs] = useState<StudioEditorTab[]>([]);
  const [activeEditorPath, setActiveEditorPath] = useState<string | null>(null);
  const lastPersistedShieldPolicyRef = useRef<string>(
    JSON.stringify(loadShieldPolicyState()),
  );

  // --- Feature State ---
  const [editingAgent, setEditingAgent] = useState<AgentSummary | null>(null);
  const [selectedAgent, setSelectedAgent] = useState<any>(null); // For Marketplace modal

  // --- Modals ---
  const [commandPaletteOpen, setCommandPaletteOpen] = useState(false);
  const [installModalOpen, setInstallModalOpen] = useState(false);

  const hideChatPane = () => {
    setChatPaneVisible(false);
    setChatPaneMaximized(false);
  };

  const toggleChatPaneVisibility = () => {
    if (chatPaneVisible) {
      hideChatPane();
      return;
    }
    setChatPaneVisible(true);
  };

  const openLegacyView = (view: string) => {
    switch (view) {
      case "copilot":
      case "autopilot":
        setChatSurface("chat");
        setChatPaneVisible(true);
        return;
      case "reply-composer":
        setChatSurface("reply-composer");
        setChatPaneVisible(true);
        return;
      case "meeting-prep":
        setChatSurface("meeting-prep");
        setChatPaneVisible(true);
        return;
      case "compose":
        setWorkflowSurface("canvas");
        setActiveView("workflows");
        return;
      case "agents":
        setWorkflowSurface("agents");
        setActiveView("workflows");
        return;
      case "marketplace":
        setWorkflowSurface("catalog");
        setActiveView("workflows");
        return;
      case "fleet":
      case "atlas":
        setActiveView("runs");
        return;
      case "notifications":
        setActiveView("inbox");
        return;
      case "integrations":
      case "connections":
      case "capabilities":
        setActiveView("capabilities");
        return;
      case "shield":
      case "control":
        setActiveView("policy");
        return;
      case "settings":
        setActiveView("settings");
        return;
      default:
        setChatSurface("chat");
    }
  };

  // --- Listeners ---
  useEffect(() => {
    // Allow other windows (Spotlight) to request a view change via backend event
    const unlistenPromise = listen<string>("request-studio-view", (event) => {
      openLegacyView(event.payload);
    });
    return () => {
      unlistenPromise.then((unlisten) => unlisten());
    };
  }, []);

  useEffect(() => {
    let cancelled = false;

    void invoke<AssistantUserProfile>("assistant_user_profile_get")
      .then((loadedProfile) => {
        if (cancelled) return;
        setProfile(loadedProfile);
        setProfileDraft(loadedProfile);
      })
      .catch(() => {
        // Best-effort bootstrap only.
      });

    const unlistenPromise = listen<AssistantUserProfile>(
      "assistant-user-profile-updated",
      (event) => {
        if (cancelled) return;
        setProfile(event.payload);
        setProfileDraft(event.payload);
      },
    );

    return () => {
      cancelled = true;
      void unlistenPromise.then((unlisten) => unlisten());
    };
  }, []);

  useEffect(() => {
    const resetUnlistenPromise = listenForAutopilotDataReset();

    return () => {
      resetUnlistenPromise.then((unlisten) => unlisten());
    };
  }, []);

  useEffect(() => {
    const handler = (event: KeyboardEvent) => {
      if (isEditableElement(event.target)) return;
      if (!event.metaKey && !event.ctrlKey) return;
      if (event.key.toLowerCase() !== "k") return;
      event.preventDefault();
      setCommandPaletteOpen(true);
    };

    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);

  useEffect(() => {
    setEditorTabs([]);
    setActiveEditorPath(null);
    setWorkflowSurface((surface) => (surface === "code" ? "home" : surface));
  }, [currentProjectId]);

  useEffect(() => {
    if (editorTabs.length === 0 && workflowSurface === "code") {
      setWorkflowSurface("home");
    }
  }, [editorTabs.length, workflowSurface]);

  useEffect(() => {
    let cancelled = false;

    void invoke<number>("notification_badge_count_get")
      .then((count) => {
        if (!cancelled) {
          setNotificationBadgeCount(count);
        }
      })
      .catch(() => {
        // Best-effort bootstrap only.
      });

    const badgeUnlistenPromise = listen<number>(
      "notifications-badge-updated",
      (event) => {
        setNotificationBadgeCount(event.payload);
      },
    );
    const interventionToastUnlistenPromise = listen<InterventionRecord>(
      "intervention-toast-candidate",
      (event) => {
        void sendNativeAutopilotNotification(event.payload);
      },
    );
    const assistantToastUnlistenPromise = listen<AssistantNotificationRecord>(
      "assistant-notification-toast-candidate",
      (event) => {
        void sendNativeAutopilotNotification(event.payload);
      },
    );

    return () => {
      cancelled = true;
      badgeUnlistenPromise.then((unlisten) => unlisten());
      interventionToastUnlistenPromise.then((unlisten) => unlisten());
      assistantToastUnlistenPromise.then((unlisten) => unlisten());
    };
  }, []);

  useEffect(() => {
    let cancelled = false;

    fetchShieldPolicyStateFromRuntime()
      .then((nextPolicy) => {
        if (cancelled) return;
        const serialized = JSON.stringify(nextPolicy);
        lastPersistedShieldPolicyRef.current = serialized;
        setShieldPolicy(nextPolicy);
      })
      .finally(() => {
        if (!cancelled) {
          setShieldPolicyHydrated(true);
        }
      });

    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (!shieldPolicyHydrated) return;

    const serialized = JSON.stringify(shieldPolicy);
    if (serialized === lastPersistedShieldPolicyRef.current) {
      return;
    }

    let cancelled = false;
    persistShieldPolicyStateToRuntime(shieldPolicy).then((nextPolicy) => {
      if (cancelled) return;
      const nextSerialized = JSON.stringify(nextPolicy);
      lastPersistedShieldPolicyRef.current = nextSerialized;
      if (nextSerialized !== serialized) {
        setShieldPolicy(nextPolicy);
      }
    });

    return () => {
      cancelled = true;
    };
  }, [shieldPolicy, shieldPolicyHydrated]);

  // Handler to open the Builder from the Dashboard
  const handleOpenAgent = (agent: AgentSummary | null) => {
    setEditingAgent(
      agent || {
        id: "new",
        name: "New Agent",
        description: "",
        model: "GPT-4o",
      },
    );
  };

  const openPolicyCenter = (connectorId?: string | null) => {
    setFocusedPolicyConnectorId(connectorId ?? null);
    setActiveView("policy");
  };

  const handleViewChange = (view: PrimaryView) => {
    setActiveView(view);
  };

  const loadEditorDocument = async (relativePath: string) => {
    setEditorTabs((current) =>
      current.map((tab) =>
        tab.path === relativePath
          ? {
              ...tab,
              loading: true,
              error: null,
            }
          : tab,
      ),
    );

    try {
      const document = await invoke<ProjectFileDocument>("project_read_file", {
        root: currentProject.rootPath,
        relativePath,
      });

      setEditorTabs((current) =>
        current.map((tab) =>
          tab.path === relativePath
            ? {
                ...tab,
                name: document.name,
                content: document.content,
                savedContent: document.content,
                loading: false,
                saving: false,
                error: null,
                languageHint: document.language_hint,
                sizeBytes: document.size_bytes,
                modifiedAtMs: document.modified_at_ms,
                isBinary: document.is_binary,
                isTooLarge: document.is_too_large,
                readOnly: document.read_only,
              }
            : tab,
        ),
      );
    } catch (error) {
      setEditorTabs((current) =>
        current.map((tab) =>
          tab.path === relativePath
            ? {
                ...tab,
                loading: false,
                saving: false,
                error: String(error),
              }
            : tab,
        ),
      );
    }
  };

  const openProjectFile = (relativePath: string) => {
    const existing = editorTabs.find((tab) => tab.path === relativePath);
    if (!existing) {
      const name = relativePath.split("/").pop() || relativePath;
      setEditorTabs((current) => [
        ...current,
        {
          path: relativePath,
          name,
          content: "",
          savedContent: "",
          loading: true,
          saving: false,
          error: null,
          languageHint: null,
          sizeBytes: 0,
          modifiedAtMs: null,
          isBinary: false,
          isTooLarge: false,
          readOnly: false,
        },
      ]);
      void loadEditorDocument(relativePath);
    } else if (existing.error) {
      void loadEditorDocument(relativePath);
    }

    setActiveEditorPath(relativePath);
    setActiveView("workflows");
    setWorkflowSurface("code");
  };

  const closeEditorTab = (relativePath: string) => {
    const closingTab = editorTabs.find((tab) => tab.path === relativePath);
    if (
      closingTab &&
      closingTab.content !== closingTab.savedContent &&
      !window.confirm(`Close ${closingTab.name} without saving changes?`)
    ) {
      return;
    }

    const closingIndex = editorTabs.findIndex((tab) => tab.path === relativePath);
    const nextTabs = editorTabs.filter((tab) => tab.path !== relativePath);
    setEditorTabs(nextTabs);

    if (activeEditorPath === relativePath) {
      const fallbackTab =
        nextTabs[closingIndex] ?? nextTabs[closingIndex - 1] ?? nextTabs[0] ?? null;
      setActiveEditorPath(fallbackTab?.path ?? null);
    }

    if (nextTabs.length === 0 && workflowSurface === "code") {
      setWorkflowSurface("home");
    }
  };

  const updateEditorTabContent = (relativePath: string, content: string) => {
    setEditorTabs((current) =>
      current.map((tab) =>
        tab.path === relativePath
          ? {
              ...tab,
              content,
            }
          : tab,
      ),
    );
  };

  const saveEditorTab = async (relativePath: string) => {
    const targetTab = editorTabs.find((tab) => tab.path === relativePath);
    if (
      !targetTab ||
      targetTab.loading ||
      targetTab.saving ||
      targetTab.readOnly ||
      targetTab.content === targetTab.savedContent
    ) {
      return;
    }

    setEditorTabs((current) =>
      current.map((tab) =>
        tab.path === relativePath
          ? {
              ...tab,
              saving: true,
              error: null,
            }
          : tab,
      ),
    );

    try {
      const document = await invoke<ProjectFileDocument>("project_write_file", {
        root: currentProject.rootPath,
        relativePath,
        content: targetTab.content,
      });

      setEditorTabs((current) =>
        current.map((tab) =>
          tab.path === relativePath
            ? {
                ...tab,
                name: document.name,
                content: document.content,
                savedContent: document.content,
                loading: false,
                saving: false,
                error: null,
                languageHint: document.language_hint,
                sizeBytes: document.size_bytes,
                modifiedAtMs: document.modified_at_ms,
                isBinary: document.is_binary,
                isTooLarge: document.is_too_large,
                readOnly: document.read_only,
              }
            : tab,
        ),
      );
    } catch (error) {
      setEditorTabs((current) =>
        current.map((tab) =>
          tab.path === relativePath
            ? {
                ...tab,
                saving: false,
                error: String(error),
              }
            : tab,
        ),
      );
    }
  };

  const openReplyComposer = (
    session: Extract<AssistantWorkbenchSession, { kind: "gmail_reply" }>,
  ) => {
    setAssistantWorkbench(session);
    setChatSurface("reply-composer");
    setChatPaneVisible(true);
  };

  const openMeetingPrep = (
    session: Extract<AssistantWorkbenchSession, { kind: "meeting_prep" }>,
  ) => {
    setAssistantWorkbench(session);
    setChatSurface("meeting-prep");
    setChatPaneVisible(true);
  };

  const openAutopilotWithIntent = (intent: string) => {
    setAutopilotSeedIntent(intent);
    setChatSurface("chat");
    setChatPaneVisible(true);
  };

  const updateProfileDraft = <K extends keyof AssistantUserProfile>(
    key: K,
    value: AssistantUserProfile[K],
  ) => {
    setProfileDraft((current) => ({
      ...current,
      [key]: value,
    }));
  };

  const resetProfileDraft = () => {
    setProfileDraft(profile);
    setProfileError(null);
  };

  const saveProfileDraft = async () => {
    setProfileSaving(true);
    setProfileError(null);

    try {
      const savedProfile = await invoke<AssistantUserProfile>(
        "assistant_user_profile_set",
        {
          profile: {
            ...profileDraft,
            groundingAllowed: false,
          },
        },
      );
      setProfile(savedProfile);
      setProfileDraft(savedProfile);
    } catch (nextError) {
      setProfileError(String(nextError));
    } finally {
      setProfileSaving(false);
    }
  };

  const chatFullscreen = chatPaneVisible && chatPaneMaximized;
  const showStatusBar =
    !chatFullscreen &&
    (activeView === "workflows" ||
      activeView === "runs" ||
      activeView === "policy" ||
      activeView === "settings");
  const currentProject =
    PROJECT_SCOPES.find((project) => project.id === currentProjectId) ??
    PROJECT_SCOPES[0];

  return (
    <div className="studio-window">
      <LocalActivityBar
        activeView={activeView}
        onViewChange={handleViewChange}
        notificationCount={notificationBadgeCount}
        currentProject={currentProject}
      />

      <div className="studio-main">
        <StudioIdeHeader
          workspaceName={WORKSPACE_NAME}
          currentProject={currentProject}
          projects={PROJECT_SCOPES}
          activeView={activeView}
          workflowSurface={workflowSurface}
          chatVisible={chatPaneVisible}
          notificationCount={notificationBadgeCount}
          onSelectProject={setCurrentProjectId}
          onToggleChat={toggleChatPaneVisibility}
          onOpenCommandPalette={() => setCommandPaletteOpen(true)}
        />

        <div
          className={`studio-content ${chatFullscreen ? "is-chat-fullscreen" : ""}`}
        >
          <StudioExplorerPane
            currentProject={currentProject}
            activeFilePath={activeEditorPath}
            onOpenFile={openProjectFile}
          />

          <div className="studio-center-area">
            <div className="studio-content-main">
              {activeView === "workflows" ? (
                <MissionControlWorkflowsView
                  runtime={runtime}
                  surface={workflowSurface}
                  currentProject={currentProject}
                  projects={PROJECT_SCOPES}
                  notificationCount={notificationBadgeCount}
                  editingAgent={editingAgent}
                  editorTabs={editorTabs}
                  activeEditorPath={activeEditorPath}
                  onSurfaceChange={setWorkflowSurface}
                  onSelectProject={setCurrentProjectId}
                  onOpenInbox={() => handleViewChange("inbox")}
                  onOpenCapabilities={() => handleViewChange("capabilities")}
                  onOpenPolicy={() => openPolicyCenter(null)}
                  onSelectEditorTab={setActiveEditorPath}
                  onCloseEditorTab={closeEditorTab}
                  onChangeEditorTabContent={updateEditorTabContent}
                  onSaveEditorTab={saveEditorTab}
                  onReloadEditorTab={(path) => {
                    void loadEditorDocument(path);
                  }}
                  onOpenAgent={handleOpenAgent}
                  onCloseAgent={() => setEditingAgent(null)}
                  onInstallAgent={(agent) => {
                    setSelectedAgent(agent);
                    setInstallModalOpen(true);
                  }}
                  onAddBuilderConfigToCanvas={(config) => {
                    void runtime
                      .loadBuilderConfigToCompose(config)
                      .catch((error) => {
                        console.error(
                          "Builder->Compose handoff unavailable:",
                          error,
                        );
                      });
                  }}
                />
              ) : null}

              {activeView === "runs" ? (
                <MissionControlRunsView runtime={runtime} />
              ) : null}

              {activeView === "inbox" ? (
                <NotificationsView
                  onOpenAutopilot={() => {
                    setChatSurface("chat");
                    setChatPaneVisible(true);
                  }}
                  onOpenIntegrations={() => handleViewChange("capabilities")}
                  onOpenShield={(connectorId) => openPolicyCenter(connectorId)}
                  onOpenSettings={() => handleViewChange("settings")}
                  onOpenReplyComposer={openReplyComposer}
                  onOpenMeetingPrep={openMeetingPrep}
                />
              ) : null}

              {activeView === "capabilities" ? (
                <CapabilitiesView
                  runtime={runtime}
                  getConnectorPolicySummary={(connector) =>
                    buildConnectorPolicySummary(shieldPolicy, connector.id)
                  }
                  onOpenPolicyCenter={(connector) =>
                    openPolicyCenter(connector.id)
                  }
                />
              ) : null}

              {activeView === "policy" || activeView === "settings" ? (
                <MissionControlControlView
                  runtime={runtime}
                  surface={activeView === "settings" ? "system" : "policy"}
                  policyState={shieldPolicy}
                  profile={profile}
                  profileDraft={profileDraft}
                  profileSaving={profileSaving}
                  profileError={profileError}
                  focusedConnectorId={focusedPolicyConnectorId}
                  onSurfaceChange={(surface) =>
                    handleViewChange(surface === "policy" ? "policy" : "settings")
                  }
                  onPolicyChange={setShieldPolicy}
                  onProfileDraftChange={updateProfileDraft}
                  onResetProfileDraft={resetProfileDraft}
                  onSaveProfile={saveProfileDraft}
                  onFocusConnector={setFocusedPolicyConnectorId}
                  onOpenConnections={() => handleViewChange("capabilities")}
                />
              ) : null}
            </div>

            <StudioUtilityDrawer
              activeView={activeView}
              chatSurface={chatSurface}
              operatorPaneOpen={chatPaneVisible}
              workflowSurface={workflowSurface}
              notificationCount={notificationBadgeCount}
              shieldPolicy={shieldPolicy}
              currentProject={currentProject}
              focusedPolicyConnectorId={focusedPolicyConnectorId}
              assistantWorkbench={assistantWorkbench}
              profile={profile}
            />
          </div>

          {chatPaneVisible ? (
            <StudioLeftUtilityPane
              surface={chatSurface}
              session={assistantWorkbench}
              runtime={runtime}
              maximized={chatPaneMaximized}
              seedIntent={autopilotSeedIntent}
              onConsumeSeedIntent={() => setAutopilotSeedIntent(null)}
              onClose={hideChatPane}
              onToggleMaximize={() =>
                setChatPaneMaximized((maximized) => !maximized)
              }
              onBackToInbox={() => {
                setChatSurface("chat");
                handleViewChange("inbox");
              }}
              onOpenInbox={() => handleViewChange("inbox")}
              onOpenAutopilot={openAutopilotWithIntent}
            />
          ) : null}
        </div>

        {showStatusBar ? (
          <StatusBar
            metrics={{ cost: 0.0, privacy: 0.0, risk: 0.0 }}
            status="Ready"
            onOpenShield={() => openPolicyCenter(focusedPolicyConnectorId)}
          />
        ) : null}
      </div>

      {/* --- Global Modals --- */}
      {commandPaletteOpen && (
        <CommandPalette onClose={() => setCommandPaletteOpen(false)} />
      )}

      {installModalOpen && selectedAgent && (
        <AgentInstallModal
          isOpen={installModalOpen}
          onClose={() => setInstallModalOpen(false)}
          agent={selectedAgent}
        />
      )}
    </div>
  );
}
