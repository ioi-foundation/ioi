// apps/autopilot/src/windows/StudioWindow/index.tsx
import { useState, useEffect, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import {
  isPermissionGranted,
  requestPermission,
  sendNotification,
} from "@tauri-apps/plugin-notification";
import { ConnectorsView } from "@ioi/agent-ide";
import type { AgentSummary } from "@ioi/agent-ide";
import { TauriRuntime } from "../../services/TauriRuntime";

// Shell Components
import { AgentInstallModal } from "../../components/AgentInstallModal";
import { CommandPalette } from "../../components/CommandPalette";
import { StatusBar } from "../../components/StatusBar";
import { LocalActivityBar } from "./components/LocalActivityBar";
import { MissionControlChatView } from "./components/MissionControlChatView";
import { MissionControlWorkflowsView } from "./components/MissionControlWorkflowsView";
import { MissionControlRunsView } from "./components/MissionControlRunsView";
import { MissionControlControlView } from "./components/MissionControlControlView";
import { NotificationsView } from "./components/NotificationsView";
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

type ToastCandidate = Pick<InterventionRecord, "title" | "summary" | "reason" | "privacy">;
type PrimaryView = "chat" | "workflows" | "runs" | "inbox" | "connections" | "control";

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

async function sendNativeAutopilotNotification(candidate: ToastCandidate): Promise<void> {
  try {
    let granted = await isPermissionGranted();
    if (!granted) {
      const permission = await requestPermission();
      granted = permission === "granted";
    }
    if (!granted) return;

    const body =
      candidate.privacy.previewMode === "redacted" && candidate.privacy.containsSensitiveData
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
  const [activeView, setActiveView] = useState<PrimaryView>("chat");
  const [chatSurface, setChatSurface] = useState<"chat" | "reply-composer" | "meeting-prep">(
    "chat",
  );
  const [workflowSurface, setWorkflowSurface] = useState<"canvas" | "agents" | "catalog">(
    "canvas",
  );
  const [controlSurface, setControlSurface] = useState<"policy" | "system">("policy");
  const [interfaceMode, setInterfaceMode] = useState<"GHOST" | "COMPOSE">("COMPOSE");
  const [focusedPolicyConnectorId, setFocusedPolicyConnectorId] = useState<string | null>(null);
  const [assistantWorkbench, setAssistantWorkbench] = useState<AssistantWorkbenchSession | null>(null);
  const [autopilotSeedIntent, setAutopilotSeedIntent] = useState<string | null>(null);
  const [notificationBadgeCount, setNotificationBadgeCount] = useState(0);
  const [shieldPolicy, setShieldPolicy] = useState<ShieldPolicyState>(() =>
    loadShieldPolicyState(),
  );
  const [profile, setProfile] = useState<AssistantUserProfile>(DEFAULT_PROFILE);
  const [profileDraft, setProfileDraft] = useState<AssistantUserProfile>(DEFAULT_PROFILE);
  const [profileSaving, setProfileSaving] = useState(false);
  const [profileError, setProfileError] = useState<string | null>(null);
  const [shieldPolicyHydrated, setShieldPolicyHydrated] = useState(false);
  const lastPersistedShieldPolicyRef = useRef<string>(JSON.stringify(loadShieldPolicyState()));
  
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
        setActiveView("chat");
        return;
      case "reply-composer":
        setChatSurface("reply-composer");
        setActiveView("chat");
        return;
      case "meeting-prep":
        setChatSurface("meeting-prep");
        setActiveView("chat");
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
        setActiveView("connections");
        return;
      case "shield":
        setControlSurface("policy");
        setActiveView("control");
        return;
      case "settings":
        setControlSurface("system");
        setActiveView("control");
        return;
      default:
        setChatSurface("chat");
        setActiveView("chat");
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

    const unlistenPromise = listen<AssistantUserProfile>("assistant-user-profile-updated", (event) => {
      if (cancelled) return;
      setProfile(event.payload);
      setProfileDraft(event.payload);
    });

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

    const badgeUnlistenPromise = listen<number>("notifications-badge-updated", (event) => {
      setNotificationBadgeCount(event.payload);
    });
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
    setEditingAgent(agent || { id: 'new', name: 'New Agent', description: '', model: 'GPT-4o' });
  };

  const openPolicyCenter = (connectorId?: string | null) => {
    setFocusedPolicyConnectorId(connectorId ?? null);
    setControlSurface("policy");
    setActiveView("control");
  };

  const handleViewChange = (view: PrimaryView) => {
    setActiveView(view);
  };

  const openReplyComposer = (
    session: Extract<AssistantWorkbenchSession, { kind: "gmail_reply" }>,
  ) => {
    setAssistantWorkbench(session);
    setChatSurface("reply-composer");
    setActiveView("chat");
  };

  const openMeetingPrep = (
    session: Extract<AssistantWorkbenchSession, { kind: "meeting_prep" }>,
  ) => {
    setAssistantWorkbench(session);
    setChatSurface("meeting-prep");
    setActiveView("chat");
  };

  const openAutopilotWithIntent = (intent: string) => {
    setAutopilotSeedIntent(intent);
    setChatSurface("chat");
    setActiveView("chat");
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
      const savedProfile = await invoke<AssistantUserProfile>("assistant_user_profile_set", {
        profile: {
          ...profileDraft,
          groundingAllowed: false,
        },
      });
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
    activeView === "control";

  return (
    <div className="studio-window">
      <LocalActivityBar
        activeView={activeView}
        onViewChange={handleViewChange}
        notificationCount={notificationBadgeCount}
        ghostMode={interfaceMode === "GHOST"}
        onToggleGhost={() => setInterfaceMode((prev) => (prev === "GHOST" ? "COMPOSE" : "GHOST"))}
      />

      <div className="studio-main">
        <div className="studio-content">
          <div className="studio-content-main">
            {activeView === "chat" ? (
              <MissionControlChatView
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
                  void runtime.loadBuilderConfigToCompose(config).catch((error) => {
                    console.error("Builder->Compose handoff unavailable:", error);
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
                  handleViewChange("chat");
                }}
                onOpenIntegrations={() => handleViewChange("connections")}
                onOpenShield={(connectorId) => openPolicyCenter(connectorId)}
                onOpenSettings={() => {
                  setControlSurface("system");
                  handleViewChange("control");
                }}
                onOpenReplyComposer={openReplyComposer}
                onOpenMeetingPrep={openMeetingPrep}
              />
            ) : null}

            {activeView === "connections" ? (
              <ConnectorsView
                runtime={runtime}
                getConnectorPolicySummary={(connector) =>
                  buildConnectorPolicySummary(shieldPolicy, connector.id)
                }
                onOpenPolicyCenter={(connector) => openPolicyCenter(connector.id)}
              />
            ) : null}

            {activeView === "control" ? (
              <MissionControlControlView
                runtime={runtime}
                surface={controlSurface}
                policyState={shieldPolicy}
                profile={profile}
                profileDraft={profileDraft}
                profileSaving={profileSaving}
                profileError={profileError}
                focusedConnectorId={focusedPolicyConnectorId}
                onSurfaceChange={setControlSurface}
                onPolicyChange={setShieldPolicy}
                onProfileDraftChange={updateProfileDraft}
                onResetProfileDraft={resetProfileDraft}
                onSaveProfile={saveProfileDraft}
                onFocusConnector={setFocusedPolicyConnectorId}
                onOpenConnections={() => handleViewChange("connections")}
              />
            ) : null}
          </div>
        </div>

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
