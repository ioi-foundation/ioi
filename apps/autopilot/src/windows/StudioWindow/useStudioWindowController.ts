import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import {
  isPermissionGranted,
  requestPermission,
  sendNotification,
} from "@tauri-apps/plugin-notification";
import type {
  AgentConfiguration,
  AgentSummary,
  ProjectFile,
  RuntimeCatalogEntry,
  StudioCapabilityDetailSection,
} from "@ioi/agent-ide";
import { useAssistantWorkbenchState } from "@ioi/agent-ide";
import { bootstrapAgentSession, useAgentStore } from "../../session/autopilotSession";
import { listenForAutopilotDataReset } from "../../services/autopilotReset";
import { safelyDisposeTauriListener } from "../../services/tauriListeners";
import {
  ackPendingStudioLaunchRequest,
  peekPendingStudioLaunchRequest,
  type PendingStudioLaunchEnvelope,
  recordStudioLaunchReceipt,
  summarizeAssistantWorkbenchSession,
  summarizePendingStudioLaunchRequest,
} from "../../services/studioLaunchState";
import type {
  AssistantNotificationRecord,
  AssistantUserProfile,
  AssistantWorkbenchSession,
  InterventionRecord,
} from "../../types";
import {
  type CapabilityGovernanceRequest,
  fetchShieldPolicyStateFromRuntime,
  loadShieldPolicyState,
  persistShieldPolicyStateToRuntime,
  type ShieldPolicyState,
} from "./policyCenter";
import {
  DEFAULT_PROFILE,
  PROJECT_SCOPES,
  type PrimaryView,
} from "./studioWindowModel";
import type { CapabilitySurface } from "./components/capabilities/model";
import type { SettingsSection } from "./components/SettingsView.shared";

type ToastCandidate = Pick<
  InterventionRecord,
  "title" | "summary" | "reason" | "privacy"
>;

type ChatSurface = "chat" | "reply-composer" | "meeting-prep";
type WorkflowSurface = "home" | "canvas" | "agents" | "catalog";
type RuntimeCatalogStageEntry = {
  id: string;
  name: string;
  description: string;
  ownerLabel: string;
  entryKind: string;
  runtimeNotes: string;
  statusLabel?: string;
  image: string;
};

function normalizeRuntimeCatalogStageEntry(
  agent: RuntimeCatalogEntry,
): RuntimeCatalogStageEntry {
  return {
    id: agent.id,
    name: agent.name,
    description: agent.description,
    ownerLabel: agent.ownerLabel,
    entryKind: agent.entryKind,
    runtimeNotes: agent.runtimeNotes,
    statusLabel: agent.statusLabel,
    image:
      agent.icon ??
      "linear-gradient(135deg, rgba(90, 140, 255, 0.95), rgba(35, 189, 152, 0.9))",
  };
}

function projectFromBuilderConfig(config: AgentConfiguration): ProjectFile {
  const generatedAt = Date.now();
  const nodeId = `builder-node-${generatedAt}`;
  const name = config.name.trim() || "Generated Agent";
  const description = config.description.trim();

  return {
    version: "1.0.0",
    nodes: [
      {
        id: nodeId,
        type: "model",
        name,
        x: 280,
        y: 180,
        config: {
          logic: {
            model: config.model,
            systemPrompt: config.instructions,
            temperature: config.temperature,
          },
          law: {},
        },
      },
    ],
    edges: [],
    global_config: {
      env: "{}",
      modelBindings: {
        reasoning: { modelId: config.model, required: false },
        vision: { modelId: "", required: false },
        embedding: { modelId: "", required: false },
        image: { modelId: "", required: false },
      },
      requiredCapabilities: {
        reasoning: { required: false, bindingKey: "reasoning" },
        vision: { required: false, bindingKey: "vision" },
        embedding: { required: false, bindingKey: "embedding" },
        image: { required: false, bindingKey: "image" },
        speech: { required: false },
        video: { required: false },
      },
      policy: {
        maxBudget: 5,
        maxSteps: 50,
        timeoutMs: 30000,
      },
      contract: {
        developerBond: 0,
        adjudicationRubric: "",
      },
      meta: {
        name,
        description,
      },
    },
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
  const [capabilityGovernanceRequest, setCapabilityGovernanceRequest] =
    useState<CapabilityGovernanceRequest | null>(null);
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
  const [selectedCatalogEntry, setSelectedCatalogEntry] =
    useState<RuntimeCatalogStageEntry | null>(
    null,
  );
  const [commandPaletteOpen, setCommandPaletteOpen] = useState(false);
  const [catalogStageModalOpen, setCatalogStageModalOpen] = useState(false);
  const [capabilitiesSurfaceSeed, setCapabilitiesSurfaceSeed] =
    useState<CapabilitySurface | null>(null);
  const [capabilitiesTargetConnectorId, setCapabilitiesTargetConnectorId] =
    useState<string | null>(null);
  const [capabilitiesTargetDetailSection, setCapabilitiesTargetDetailSection] =
    useState<StudioCapabilityDetailSection | null>(null);
  const [settingsSectionSeed, setSettingsSectionSeed] =
    useState<SettingsSection | null>(null);
  const [composeSeedProject, setComposeSeedProject] = useState<ProjectFile | null>(
    null,
  );

  const lastPersistedShieldPolicyRef = useRef<string>(
    JSON.stringify(loadShieldPolicyState()),
  );
  const studioLaunchHydrationInFlightRef = useRef(false);
  const lastAppliedStudioLaunchIdRef = useRef<string | null>(null);

  const currentProject =
    PROJECT_SCOPES.find((project) => project.id === currentProjectId) ??
    PROJECT_SCOPES[0];

  const {
    assistantWorkbench,
    activateAssistantWorkbench: activateWorkbenchSession,
    openReplyComposer: activateReplyComposer,
    openMeetingPrep: activateMeetingPrep,
  } = useAssistantWorkbenchState({
    onActivateSession: (_session, surface) => {
      setChatSurface(surface);
      setChatPaneVisible(true);
      setActiveView("inbox");
    },
  });

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
      case "catalog":
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

  const openCapabilityTarget = (
    connectorId?: string | null,
    detailSection?: StudioCapabilityDetailSection | null,
  ) => {
    const resolvedConnectorId = connectorId ?? null;
    setCapabilitiesTargetConnectorId(resolvedConnectorId);
    setCapabilitiesTargetDetailSection(resolvedConnectorId ? "setup" : null);
    if (detailSection) {
      setCapabilitiesTargetDetailSection(detailSection);
    }
    setCapabilitiesSurfaceSeed("connections");
    setActiveView("capabilities");
  };

  const openPolicyCenter = (connectorId?: string | null) => {
    setFocusedPolicyConnectorId(connectorId ?? null);
    setActiveView("policy");
  };

  const dismissCapabilityGovernanceRequest = () => {
    setCapabilityGovernanceRequest(null);
    void invoke("clear_capability_governance_request");
  };

  const applyCapabilityGovernanceRequest = (next: ShieldPolicyState) => {
    setShieldPolicy(next);
    setCapabilityGovernanceRequest(null);
    void invoke("clear_capability_governance_request");
  };

  const openAutopilotWithIntent = (intent: string) => {
    setAutopilotSeedIntent(intent);
    setChatSurface("chat");
    setChatPaneVisible(true);
  };

  const applyPendingStudioLaunchRequest = async (
    pendingLaunch: PendingStudioLaunchEnvelope | null,
    source: string,
  ) => {
    if (!pendingLaunch) {
      return;
    }

    const { launchId, request: pendingRequest } = pendingLaunch;
    if (lastAppliedStudioLaunchIdRef.current === launchId) {
      await recordStudioLaunchReceipt("studio_pending_launch_duplicate", {
        source,
        launchId,
        kind: pendingRequest.kind,
        request: summarizePendingStudioLaunchRequest(pendingRequest),
      });
      await ackPendingStudioLaunchRequest(launchId);
      return;
    }

    lastAppliedStudioLaunchIdRef.current = launchId;
    await recordStudioLaunchReceipt("studio_pending_launch_applying", {
      source,
      launchId,
      kind: pendingRequest.kind,
      request: summarizePendingStudioLaunchRequest(pendingRequest),
    });

    try {
      switch (pendingRequest.kind) {
        case "view":
          openLegacyView(pendingRequest.view);
          await recordStudioLaunchReceipt("studio_pending_launch_applied", {
            source,
            launchId,
            kind: pendingRequest.kind,
            view: pendingRequest.view,
          });
          await ackPendingStudioLaunchRequest(launchId);
          return;
        case "session-target":
          await openSessionTarget(pendingRequest.sessionId);
          await recordStudioLaunchReceipt("studio_pending_launch_applied", {
            source,
            launchId,
            kind: pendingRequest.kind,
            sessionId: pendingRequest.sessionId,
          });
          await ackPendingStudioLaunchRequest(launchId);
          return;
        case "capability":
          openCapabilityTarget(
            pendingRequest.connectorId ?? null,
            pendingRequest.detailSection ?? null,
          );
          await recordStudioLaunchReceipt("studio_pending_launch_applied", {
            source,
            launchId,
            kind: pendingRequest.kind,
            connectorId: pendingRequest.connectorId ?? null,
            detailSection: pendingRequest.detailSection ?? null,
          });
          await ackPendingStudioLaunchRequest(launchId);
          return;
        case "policy":
          openPolicyCenter(pendingRequest.connectorId ?? null);
          await recordStudioLaunchReceipt("studio_pending_launch_applied", {
            source,
            launchId,
            kind: pendingRequest.kind,
            connectorId: pendingRequest.connectorId ?? null,
          });
          await ackPendingStudioLaunchRequest(launchId);
          return;
        case "autopilot-intent":
          openAutopilotWithIntent(pendingRequest.intent);
          await recordStudioLaunchReceipt("studio_pending_launch_applied", {
            source,
            launchId,
            kind: pendingRequest.kind,
            intent: pendingRequest.intent,
          });
          await ackPendingStudioLaunchRequest(launchId);
          return;
        case "assistant-workbench":
          activateWorkbenchSession(pendingRequest.session);
          await recordStudioLaunchReceipt("studio_pending_launch_applied", {
            source,
            launchId,
            kind: pendingRequest.kind,
            session: summarizeAssistantWorkbenchSession(pendingRequest.session),
          });
          await ackPendingStudioLaunchRequest(launchId);
          return;
        default:
          return;
      }
    } catch (error) {
      lastAppliedStudioLaunchIdRef.current = null;
      await recordStudioLaunchReceipt("studio_pending_launch_failed", {
        source,
        launchId,
        kind: pendingRequest.kind,
        request: summarizePendingStudioLaunchRequest(pendingRequest),
        error: error instanceof Error ? error.message : String(error ?? ""),
      });
    }
  };

  const hydratePendingStudioLaunchRequestIfPresent = async (source: string) => {
    if (studioLaunchHydrationInFlightRef.current) {
      return;
    }
    studioLaunchHydrationInFlightRef.current = true;

    try {
      const pendingLaunch = await peekPendingStudioLaunchRequest();
      if (!pendingLaunch) {
        await recordStudioLaunchReceipt("studio_pending_launch_empty", {
          source,
        });
        return;
      }
      await applyPendingStudioLaunchRequest(pendingLaunch, source);
    } finally {
      studioLaunchHydrationInFlightRef.current = false;
    }
  };

  useEffect(() => {
    const unlistenPromise = listen<PendingStudioLaunchEnvelope>(
      "request-studio-launch",
      (event) => {
        void recordStudioLaunchReceipt("studio_launch_event_received", {
          launchId: event.payload.launchId,
          kind: event.payload.request.kind,
          request: summarizePendingStudioLaunchRequest(event.payload.request),
        });
        void applyPendingStudioLaunchRequest(event.payload, "event");
      },
    );

    return () => {
      safelyDisposeTauriListener(unlistenPromise);
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
      safelyDisposeTauriListener(unlistenPromise);
    };
  }, []);

  useEffect(() => {
    const resetUnlistenPromise = listenForAutopilotDataReset();

    return () => {
      safelyDisposeTauriListener(resetUnlistenPromise);
    };
  }, []);

  useEffect(() => {
    const handler = (event: KeyboardEvent) => {
      if (!event.metaKey && !event.ctrlKey) return;
      if (event.key.toLowerCase() !== "k") return;
      event.preventDefault();
      setCommandPaletteOpen((open) => !open);
    };

    window.addEventListener("keydown", handler, true);
    return () => window.removeEventListener("keydown", handler, true);
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
      safelyDisposeTauriListener(badgeUnlistenPromise);
      safelyDisposeTauriListener(interventionToastUnlistenPromise);
      safelyDisposeTauriListener(assistantToastUnlistenPromise);
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
    let cancelled = false;

    void invoke<CapabilityGovernanceRequest | null>(
      "get_capability_governance_request",
    )
      .then((request) => {
        if (!cancelled) {
          setCapabilityGovernanceRequest(request);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setCapabilityGovernanceRequest(null);
        }
      });

    const unlistenPromise = listen<CapabilityGovernanceRequest | null>(
      "capability-governance-request-updated",
      (event) => {
        if (!cancelled) {
          setCapabilityGovernanceRequest(event.payload);
        }
      },
    );

    return () => {
      cancelled = true;
      safelyDisposeTauriListener(unlistenPromise);
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

  const changePrimaryView = (view: PrimaryView) => {
    setActiveView(view);
  };

  const openSettingsSection = (section: SettingsSection | null = null) => {
    setSettingsSectionSeed(section);
    setActiveView("settings");
  };

  const openCapabilitiesSurface = (surface: CapabilitySurface | null = null) => {
    setCapabilitiesTargetConnectorId(null);
    setCapabilitiesTargetDetailSection(null);
    setCapabilitiesSurfaceSeed(surface);
    setActiveView("capabilities");
  };

  const openWorkflowSurface = (surface: WorkflowSurface) => {
    setWorkflowSurface(surface);
    setActiveView("workflows");
  };

  const openReplyComposer = (
    session: Extract<AssistantWorkbenchSession, { kind: "gmail_reply" }>,
  ) => {
    activateReplyComposer(session);
  };

  const openMeetingPrep = (
    session: Extract<AssistantWorkbenchSession, { kind: "meeting_prep" }>,
  ) => {
    activateMeetingPrep(session);
  };

  const openSessionTarget = async (sessionId: string) => {
    await bootstrapAgentSession({
      refreshCurrentTask: false,
    });
    const store = useAgentStore.getState();
    await store.loadSession(sessionId);
    await store.refreshSessionHistory();
    setChatSurface("chat");
    setActiveView("studio");
  };

  useEffect(() => {
    let cancelled = false;

    void hydratePendingStudioLaunchRequestIfPresent("mount").then(() => {
      if (cancelled) {
        return;
      }
    });

    return () => {
      cancelled = true;
    };
  }, []);

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

  const openStageModalForEntry = (entry: RuntimeCatalogEntry) => {
    setSelectedCatalogEntry(normalizeRuntimeCatalogStageEntry(entry));
    setCatalogStageModalOpen(true);
  };

  const queueBuilderConfigToCanvas = (config: AgentConfiguration) => {
    setComposeSeedProject(projectFromBuilderConfig(config));
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
      openSurface: openWorkflowSurface,
      selectProject: setCurrentProjectId,
      composeSeedProject,
      queueBuilderConfigToCanvas,
      consumeComposeSeedProject: () => setComposeSeedProject(null),
    },
    policy: {
      shieldPolicy,
      setShieldPolicy,
      governanceRequest: capabilityGovernanceRequest,
      focusedConnectorId: focusedPolicyConnectorId,
      focusConnector: setFocusedPolicyConnectorId,
      openPolicyCenter,
      dismissGovernanceRequest: dismissCapabilityGovernanceRequest,
      applyGovernanceRequest: applyCapabilityGovernanceRequest,
    },
    capabilities: {
      seedSurface: capabilitiesSurfaceSeed,
      targetConnectorId: capabilitiesTargetConnectorId,
      targetDetailSection: capabilitiesTargetDetailSection,
      openSurface: openCapabilitiesSurface,
      consumeSeedSurface: () => setCapabilitiesSurfaceSeed(null),
      consumeTarget: () => {
        setCapabilitiesTargetConnectorId(null);
        setCapabilitiesTargetDetailSection(null);
      },
    },
    settings: {
      seedSection: settingsSectionSeed,
      openSection: openSettingsSection,
      consumeSeedSection: () => setSettingsSectionSeed(null),
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
      catalogStageModalOpen,
      closeCatalogStageModal: () => setCatalogStageModalOpen(false),
    },
    agents: {
      editingAgent,
      openBuilder: openAgentBuilder,
      closeBuilder: () => setEditingAgent(null),
    },
    catalog: {
      selectedCatalogEntry,
      openStageModalForEntry,
    },
  };
}
