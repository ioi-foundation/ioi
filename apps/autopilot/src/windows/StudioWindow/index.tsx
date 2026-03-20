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
import { StudioLeftUtilityPane } from "./components/StudioLeftUtilityPane";
import { StudioInspector } from "./components/StudioInspector";
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
  const [utilityPaneOpen, setUtilityPaneOpen] = useState(true);
  const [leftUtilityTab, setLeftUtilityTab] = useState<
    "operator" | "explorer" | "artifacts"
  >("operator");
  const [workflowSurface, setWorkflowSurface] = useState<
    "canvas" | "agents" | "catalog"
  >("canvas");
  const [interfaceMode, setInterfaceMode] = useState<"GHOST" | "COMPOSE">(
    "COMPOSE",
  );
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
  const lastPersistedShieldPolicyRef = useRef<string>(
    JSON.stringify(loadShieldPolicyState()),
  );

  // --- Feature State ---
  const [editingAgent, setEditingAgent] = useState<AgentSummary | null>(null);
  const [selectedAgent, setSelectedAgent] = useState<any>(null); // For Marketplace modal

  // --- Modals ---
  const [commandPaletteOpen, setCommandPaletteOpen] = useState(false);
  const [installModalOpen, setInstallModalOpen] = useState(false);

  const openLegacyView = (view: string) => {
    switch (view) {
      case "copilot":
      case "autopilot":
        setChatSurface("chat");
        setLeftUtilityTab("operator");
        setUtilityPaneOpen(true);
        return;
      case "reply-composer":
        setChatSurface("reply-composer");
        setLeftUtilityTab("operator");
        setUtilityPaneOpen(true);
        return;
      case "meeting-prep":
        setChatSurface("meeting-prep");
        setLeftUtilityTab("operator");
        setUtilityPaneOpen(true);
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
        setLeftUtilityTab("operator");
        setUtilityPaneOpen(true);
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

  const openReplyComposer = (
    session: Extract<AssistantWorkbenchSession, { kind: "gmail_reply" }>,
  ) => {
    setAssistantWorkbench(session);
    setChatSurface("reply-composer");
    setLeftUtilityTab("operator");
    setUtilityPaneOpen(true);
  };

  const openMeetingPrep = (
    session: Extract<AssistantWorkbenchSession, { kind: "meeting_prep" }>,
  ) => {
    setAssistantWorkbench(session);
    setChatSurface("meeting-prep");
    setLeftUtilityTab("operator");
    setUtilityPaneOpen(true);
  };

  const openAutopilotWithIntent = (intent: string) => {
    setAutopilotSeedIntent(intent);
    setChatSurface("chat");
    setLeftUtilityTab("operator");
    setUtilityPaneOpen(true);
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

  const showStatusBar =
    interfaceMode === "GHOST" ||
    activeView === "workflows" ||
    activeView === "runs" ||
    activeView === "policy" ||
    activeView === "settings";
  const currentProject =
    PROJECT_SCOPES.find((project) => project.id === currentProjectId) ??
    PROJECT_SCOPES[0];

  return (
    <div className="studio-window">
      <LocalActivityBar
        activeView={activeView}
        onViewChange={handleViewChange}
        notificationCount={notificationBadgeCount}
        ghostMode={interfaceMode === "GHOST"}
        onToggleGhost={() =>
          setInterfaceMode((prev) => (prev === "GHOST" ? "COMPOSE" : "GHOST"))
        }
        utilityPaneOpen={utilityPaneOpen}
        activeUtilityTab={leftUtilityTab}
        onToggleUtilityPane={() => setUtilityPaneOpen((open) => !open)}
        workspaceName={WORKSPACE_NAME}
        currentProject={currentProject}
        projects={PROJECT_SCOPES}
        onSelectProject={setCurrentProjectId}
      />

      <div className="studio-main">
        <div className="studio-content">
          {utilityPaneOpen ? (
            <StudioLeftUtilityPane
              currentProject={currentProject}
              activeTab={leftUtilityTab}
              onTabChange={setLeftUtilityTab}
              onClose={() => setUtilityPaneOpen(false)}
              surface={chatSurface}
              session={assistantWorkbench}
              runtime={runtime}
              seedIntent={autopilotSeedIntent}
              onConsumeSeedIntent={() => setAutopilotSeedIntent(null)}
              onBackToInbox={() => {
                setChatSurface("chat");
                handleViewChange("inbox");
              }}
              onOpenInbox={() => handleViewChange("inbox")}
              onOpenAutopilot={openAutopilotWithIntent}
            />
          ) : null}

          <div className="studio-content-main">
            {activeView === "workflows" ? (
              <MissionControlWorkflowsView
                runtime={runtime}
                interfaceMode={interfaceMode}
                surface={workflowSurface}
                editingAgent={editingAgent}
                onSurfaceChange={setWorkflowSurface}
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
                  setLeftUtilityTab("operator");
                  setUtilityPaneOpen(true);
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

          <StudioInspector
            activeView={activeView}
            chatSurface={chatSurface}
            operatorPaneOpen={utilityPaneOpen && leftUtilityTab === "operator"}
            workflowSurface={workflowSurface}
            runsSurface="runtime"
            interfaceMode={interfaceMode}
            notificationCount={notificationBadgeCount}
            shieldPolicy={shieldPolicy}
            profile={profile}
            assistantWorkbench={assistantWorkbench}
            editingAgentName={editingAgent?.name ?? null}
            focusedPolicyConnectorId={focusedPolicyConnectorId}
            onOpenControl={() => openPolicyCenter(focusedPolicyConnectorId)}
          />
        </div>

        <StudioUtilityDrawer
          activeView={activeView}
          chatSurface={chatSurface}
          operatorPaneOpen={utilityPaneOpen && leftUtilityTab === "operator"}
          workflowSurface={workflowSurface}
          interfaceMode={interfaceMode}
          notificationCount={notificationBadgeCount}
          shieldPolicy={shieldPolicy}
          currentProject={currentProject}
          focusedPolicyConnectorId={focusedPolicyConnectorId}
          assistantWorkbench={assistantWorkbench}
          profile={profile}
        />

        {showStatusBar ? (
          <StatusBar
            metrics={{ cost: 0.0, privacy: 0.0, risk: 0.0 }}
            status={interfaceMode === "GHOST" ? "Recording" : "Ready"}
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
