import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import {
  isPermissionGranted,
  requestPermission,
  sendNotification,
} from "@tauri-apps/plugin-notification";
import type { AgentSummary } from "@ioi/agent-ide";
import { listenForAutopilotDataReset } from "../../services/autopilotReset";
import type {
  AssistantNotificationRecord,
  AssistantUserProfile,
  AssistantWorkbenchSession,
  InterventionRecord,
} from "../../types";
import {
  fetchShieldPolicyStateFromRuntime,
  loadShieldPolicyState,
  persistShieldPolicyStateToRuntime,
  type ShieldPolicyState,
} from "./policyCenter";
import {
  DEFAULT_PROFILE,
  isEditableElement,
  PROJECT_SCOPES,
  type PrimaryView,
} from "./studioWindowModel";
import type { CapabilitySurface } from "./components/capabilities/model";

type ToastCandidate = Pick<
  InterventionRecord,
  "title" | "summary" | "reason" | "privacy"
>;

type ChatSurface = "chat" | "reply-composer" | "meeting-prep";
type WorkflowSurface = "home" | "canvas" | "agents" | "catalog";
type InstallModalAgent = {
  name: string;
  requirements: string;
  image: string;
};

function normalizeInstallModalAgent(agent: {
  name: string;
  requirements?: string;
  image?: string;
  icon?: string;
}): InstallModalAgent {
  return {
    name: agent.name,
    requirements: agent.requirements ?? "Runtime resources vary by provider",
    image:
      agent.image ??
      agent.icon ??
      "linear-gradient(135deg, rgba(90, 140, 255, 0.95), rgba(35, 189, 152, 0.9))",
  };
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

export function useStudioWindowController() {
  const [activeView, setActiveView] = useState<PrimaryView>("studio");
  const [chatSurface, setChatSurface] = useState<ChatSurface>("chat");
  const [chatPaneVisible, setChatPaneVisible] = useState(true);
  const [chatPaneMaximized, setChatPaneMaximized] = useState(false);
  const [workflowSurface, setWorkflowSurface] =
    useState<WorkflowSurface>("home");
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
  const [editingAgent, setEditingAgent] = useState<AgentSummary | null>(null);
  const [selectedAgent, setSelectedAgent] = useState<InstallModalAgent | null>(
    null,
  );
  const [commandPaletteOpen, setCommandPaletteOpen] = useState(false);
  const [installModalOpen, setInstallModalOpen] = useState(false);
  const [capabilitiesSurfaceSeed, setCapabilitiesSurfaceSeed] =
    useState<CapabilitySurface | null>(null);

  const lastPersistedShieldPolicyRef = useRef<string>(
    JSON.stringify(loadShieldPolicyState()),
  );

  const currentProject =
    PROJECT_SCOPES.find((project) => project.id === currentProjectId) ??
    PROJECT_SCOPES[0];

  const hideChatPane = () => {
    setChatPaneVisible(false);
    setChatPaneMaximized(false);
  };

  const showChatPane = () => {
    setChatPaneVisible(true);
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
        setActiveView("studio");
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
        setActiveView("studio");
        return;
      case "build":
        setActiveView("studio");
        return;
      case "code":
      case "explorer":
        setActiveView("studio");
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

  useEffect(() => {
    const unlistenPromise = listen<string>("request-studio-view", (event) => {
      openLegacyView(event.payload);
    });
    return () => {
      void unlistenPromise.then((unlisten) => unlisten());
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
      void resetUnlistenPromise.then((unlisten) => unlisten());
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
      void badgeUnlistenPromise.then((unlisten) => unlisten());
      void interventionToastUnlistenPromise.then((unlisten) => unlisten());
      void assistantToastUnlistenPromise.then((unlisten) => unlisten());
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

  const openPolicyCenter = (connectorId?: string | null) => {
    setFocusedPolicyConnectorId(connectorId ?? null);
    setActiveView("policy");
  };

  const changePrimaryView = (view: PrimaryView) => {
    setActiveView(view);
  };

  const openCapabilitiesSurface = (surface: CapabilitySurface | null = null) => {
    setCapabilitiesSurfaceSeed(surface);
    setActiveView("capabilities");
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

  const openAgentBuilder = (agent: AgentSummary | null) => {
    setEditingAgent(
      agent || {
        id: "new",
        name: "New Agent",
        description: "",
        model: "GPT-4o",
      },
    );
  };

  const openInstallModalForAgent = (agent: {
    name: string;
    requirements?: string;
    image?: string;
    icon?: string;
  }) => {
    setSelectedAgent(normalizeInstallModalAgent(agent));
    setInstallModalOpen(true);
  };

  const chatFullscreen =
    activeView !== "studio" && chatPaneVisible && chatPaneMaximized;
  const showStatusBar =
    !chatFullscreen &&
    (activeView === "studio" ||
      activeView === "workflows" ||
      activeView === "runs" ||
      activeView === "policy" ||
      activeView === "settings");

  return {
    activeView,
    notificationBadgeCount,
    currentProject,
    projects: PROJECT_SCOPES,
    chatFullscreen,
    showStatusBar,
    changePrimaryView,
    chat: {
      surface: chatSurface,
      paneVisible: chatPaneVisible,
      paneMaximized: chatPaneMaximized,
      assistantWorkbench,
      seedIntent: autopilotSeedIntent,
      hidePane: hideChatPane,
      showPane: showChatPane,
      togglePaneVisibility: toggleChatPaneVisibility,
      setSurface: setChatSurface,
      toggleMaximize: () =>
        setChatPaneMaximized((maximized) => !maximized),
      consumeSeedIntent: () => setAutopilotSeedIntent(null),
      openAutopilotWithIntent,
      openReplyComposer,
      openMeetingPrep,
    },
    workflow: {
      surface: workflowSurface,
      setSurface: setWorkflowSurface,
      selectProject: setCurrentProjectId,
    },
    policy: {
      shieldPolicy,
      setShieldPolicy,
      focusedConnectorId: focusedPolicyConnectorId,
      focusConnector: setFocusedPolicyConnectorId,
      openPolicyCenter,
    },
    capabilities: {
      seedSurface: capabilitiesSurfaceSeed,
      openSurface: openCapabilitiesSurface,
      consumeSeedSurface: () => setCapabilitiesSurfaceSeed(null),
    },
    profile: {
      value: profile,
      draft: profileDraft,
      saving: profileSaving,
      error: profileError,
      updateDraft: updateProfileDraft,
      resetDraft: resetProfileDraft,
      saveDraft: saveProfileDraft,
    },
    modals: {
      commandPaletteOpen,
      openCommandPalette: () => setCommandPaletteOpen(true),
      closeCommandPalette: () => setCommandPaletteOpen(false),
      installModalOpen,
      closeInstallModal: () => setInstallModalOpen(false),
    },
    agents: {
      editingAgent,
      selectedAgent,
      openBuilder: openAgentBuilder,
      closeBuilder: () => setEditingAgent(null),
      openInstallModalForAgent,
    },
  };
}
