import { useEffect, useRef, useState } from "react";
import { invoke } from "../../services/hypervisorHostBridge";
import { listen } from "../../services/hypervisorHostBridge";
import {
  isPermissionGranted,
  requestPermission,
  sendNotification,
} from "../../services/hypervisorHostBridge";
import type { WorkflowComposerPreflightSeed } from "@ioi/hypervisor-workbench";
import { useAssistantWorkbenchState } from "@ioi/hypervisor-workbench";
import { bootstrapHypervisorSession, useHypervisorSessionStore } from "../../session/hypervisorSession";
import { listenForHypervisorDataReset } from "../../services/hypervisorReset";
import { safelyDisposeHostListener } from "../../services/hostListeners";
import {
  ackPendingChatLaunchRequest,
  peekPendingChatLaunchRequest,
  type PendingChatLaunchEnvelope,
  recordChatLaunchReceipt,
  summarizeAssistantWorkbenchSession,
  summarizePendingChatLaunchRequest,
} from "../../services/chatLaunchState";
import type {
  AssistantNotificationRecord,
  AssistantUserProfile,
  AssistantWorkbenchSession,
  ChatCapabilityDetailSection,
  InterventionRecord,
} from "../../types";
import {
  type CapabilityGovernanceRequest,
  fetchShieldPolicyStateFromRuntime,
  loadShieldPolicyState,
  persistShieldPolicyStateToRuntime,
  type ShieldPolicyState,
} from "../../surfaces/Policy/policyCenter";
import {
  DEFAULT_PROFILE,
  PROJECT_SCOPES,
  type PrimaryView,
} from "./hypervisorShellModel";
import {
  HYPERVISOR_REFERENCE_LAUNCHED_SESSION_PROJECTIONS,
  loadHypervisorLaunchedSessionProjections,
  mergeHypervisorLaunchedSessionProjection,
  persistHypervisorLaunchedSessionProjections,
} from "./hypervisorLaunchedSessionPersistence";
import {
  HYPERVISOR_SESSION_LAUNCH_RECIPES,
  buildHypervisorCodeEditorAdapterAdmissionFailure,
  buildHypervisorLaunchedSessionProjection,
  buildCodeEditorAdapterLaunchPlan,
  getCodeEditorAdapterPreferenceByRef,
  isHypervisorSurfaceId,
  requestCodeEditorAdapterLaunchPlanAdmission,
  type HypervisorLaunchedSessionProjection,
  type HypervisorNewSessionLaunchRequest,
} from "./hypervisorShellNavigationModel";
import type { CapabilitySurface } from "../../surfaces/Capabilities";
import type { SettingsSection } from "../../surfaces/Settings/settingsViewShared";

type ToastCandidate = Pick<
  InterventionRecord,
  "title" | "summary" | "reason" | "privacy"
> &
  Partial<
    Pick<
      InterventionRecord,
      "interventionType" | "sessionId" | "threadId" | "source"
    >
  >;

type ChatSurface = "chat" | "reply-composer" | "meeting-prep";
type NewSessionModalSeed =
  | string
  | {
      seedIntent?: string | null;
      recipeId?: string | null;
    }
  | null
  | undefined;
const appliedChatLaunchIds = new Set<string>();

const HYPERVISOR_PATH_PRIMARY_VIEWS: readonly PrimaryView[] = [
  "home",
  "sessions",
  "projects",
  "missions",
  "workbench",
  "automations",
  "insights",
  "agents",
  "models",
  "privacy",
  "providers",
  "environments",
  "foundry",
  "authority",
  "receipts",
  "settings",
];

function isSupportedInitialPrimaryView(value: string | null): value is PrimaryView {
  return Boolean(
    value &&
      HYPERVISOR_PATH_PRIMARY_VIEWS.includes(value.toLowerCase() as PrimaryView),
  );
}

function resolvePathnamePrimaryView(pathname: string): PrimaryView | null {
  const segment = pathname
    .toLowerCase()
    .replace(/^\/+/, "")
    .split("/")[0]
    ?.trim();

  if (!segment) {
    return null;
  }

  if (segment === "ai") {
    return "home";
  }

  return isSupportedInitialPrimaryView(segment) ? segment : null;
}

function resolveInitialPrimaryView(): PrimaryView {
  if (typeof window !== "undefined") {
    const requested = new URLSearchParams(window.location.search).get("view");
    if (isSupportedInitialPrimaryView(requested)) {
      return requested;
    }
  }

  const envRequestedView = (import.meta.env.VITE_HYPERVISOR_INITIAL_VIEW ?? "")
    .toString()
    .trim()
    .toLowerCase();
  if (isSupportedInitialPrimaryView(envRequestedView)) {
    return envRequestedView;
  }

  if (typeof window !== "undefined") {
    const pathnameView = resolvePathnamePrimaryView(window.location.pathname);
    if (pathnameView) {
      return pathnameView;
    }
  }

  return "home";
}

function waitForChatHypervisorSurfaceFrame(): Promise<void> {
  return new Promise((resolve) => {
    if (typeof window === "undefined") {
      resolve();
      return;
    }
    let resolved = false;
    const finish = () => {
      if (resolved) {
        return;
      }
      resolved = true;
      resolve();
    };
    const timeoutId = window.setTimeout(finish, 48);
    window.requestAnimationFrame(() => {
      window.clearTimeout(timeoutId);
      finish();
    });
  });
}

async function sendNativeHypervisorNotification(
  candidate: ToastCandidate,
): Promise<void> {
  if (
    candidate.source?.serviceName === "Hypervisor" &&
    candidate.source.workflowName === "workflow" &&
    (candidate.sessionId || candidate.threadId)
  ) {
    return;
  }

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
        ? candidate.reason?.trim() || "Open Hypervisor for details."
        : candidate.summary;

    await sendNotification({
      title: candidate.title,
      body,
    });
  } catch {
    // Native notification delivery is best-effort.
  }
}

function isHypervisorClientRuntime(): boolean {
  return typeof window !== "undefined" && "__HYPERVISOR_HOST_BRIDGE__" in window;
}

function hypervisorBrowserStorage(): Storage | null {
  return typeof window !== "undefined" ? window.localStorage : null;
}

export function useHypervisorShellController() {
  const [activeView, setActiveView] = useState<PrimaryView>(resolveInitialPrimaryView);
  const [chatSurface, setChatSurface] = useState<ChatSurface>("chat");
  const [chatPaneVisible, setChatPaneVisible] = useState(false);
  const [chatPaneMaximized, setChatPaneMaximized] = useState(false);
  const [focusedPolicyConnectorId, setFocusedPolicyConnectorId] = useState<
    string | null
  >(null);
  const [capabilityGovernanceRequest, setCapabilityGovernanceRequest] =
    useState<CapabilityGovernanceRequest | null>(null);
  const [hypervisorSeedIntent, setHypervisorSeedIntent] = useState<string | null>(
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
    PROJECT_SCOPES[0]?.id ?? "hypervisor-core",
  );
  const [commandPaletteOpen, setCommandPaletteOpen] = useState(false);
  const [commandPaletteMode, setCommandPaletteMode] =
    useState<"default" | "tools">("default");
  const [commandPaletteInitialQuery, setCommandPaletteInitialQuery] = useState("");
  const [newSessionModalOpen, setNewSessionModalOpen] = useState(false);
  const [newSessionSeedIntent, setNewSessionSeedIntent] = useState<string | null>(
    null,
  );
  const [newSessionRecipeId, setNewSessionRecipeId] = useState<string | null>(
    null,
  );
  const [launchedSessionProjections, setLaunchedSessionProjections] = useState<
    HypervisorLaunchedSessionProjection[]
  >(() => {
    const loaded = loadHypervisorLaunchedSessionProjections({
      storage: hypervisorBrowserStorage(),
    });
    return loaded.length > 0
      ? loaded
      : HYPERVISOR_REFERENCE_LAUNCHED_SESSION_PROJECTIONS;
  });
  const [capabilitiesSurfaceSeed, setCapabilitiesSurfaceSeed] =
    useState<CapabilitySurface | null>(null);
  const [capabilitiesTargetConnectorId, setCapabilitiesTargetConnectorId] =
    useState<string | null>(null);
  const [capabilitiesTargetDetailSection, setCapabilitiesTargetDetailSection] =
    useState<ChatCapabilityDetailSection | null>(null);
  const [settingsSectionSeed, setSettingsSectionSeed] =
    useState<SettingsSection | null>(null);
  const [workflowPreflightSeed, setWorkflowPreflightSeed] =
    useState<WorkflowComposerPreflightSeed | null>(null);

  const lastPersistedShieldPolicyRef = useRef<string>(
    JSON.stringify(loadShieldPolicyState()),
  );
  const chatLaunchHydrationInFlightRef = useRef(false);
  const lastAppliedChatLaunchIdRef = useRef<string | null>(null);

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
      setActiveView("missions");
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

  const openRequestedSurface = (view: string) => {
    if (isHypervisorSurfaceId(view)) {
      setActiveView(view);
      return;
    }

    switch (view) {
      case "reply-composer":
        setChatSurface("reply-composer");
        setChatPaneVisible(true);
        return;
      case "meeting-prep":
        setChatSurface("meeting-prep");
        setChatPaneVisible(true);
        return;
      case "catalog":
        setActiveView("agents");
        return;
      default:
        setChatSurface("chat");
    }
  };

  const openCapabilityTarget = (
    connectorId?: string | null,
    detailSection?: ChatCapabilityDetailSection | null,
  ) => {
    const resolvedConnectorId = connectorId ?? null;
    setCapabilitiesTargetConnectorId(resolvedConnectorId);
    setCapabilitiesTargetDetailSection(resolvedConnectorId ? "setup" : null);
    if (detailSection) {
      setCapabilitiesTargetDetailSection(detailSection);
    }
    setCapabilitiesSurfaceSeed("connections");
    setActiveView("agents");
  };

  const openPolicyCenter = (connectorId?: string | null) => {
    setFocusedPolicyConnectorId(connectorId ?? null);
    setActiveView("authority");
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

  const openHypervisorSessionWithIntent = (intent: string) => {
    setHypervisorSeedIntent(intent);
    setActiveView("sessions");
    setChatSurface("chat");
    setChatPaneVisible(true);
  };

  const launchNewSession = async (request: HypervisorNewSessionLaunchRequest) => {
    const recipe =
      HYPERVISOR_SESSION_LAUNCH_RECIPES.find(
        (candidate) => candidate.recipe_id === request.recipe_id,
      ) ?? HYPERVISOR_SESSION_LAUNCH_RECIPES[0]!;
    const project =
      PROJECT_SCOPES.find((candidate) => candidate.id === request.project_id) ??
      PROJECT_SCOPES[0]!;
    const codeEditorAdapter = getCodeEditorAdapterPreferenceByRef(
      request.adapter_preference_ref,
    );
    const codeEditorAdapterLaunchPlan =
      buildCodeEditorAdapterLaunchPlan(codeEditorAdapter);
    const codeEditorAdapterAdmission =
      await requestCodeEditorAdapterLaunchPlanAdmission(
        codeEditorAdapterLaunchPlan,
      ).catch((error: unknown) =>
        buildHypervisorCodeEditorAdapterAdmissionFailure({
          error,
          launchPlan: codeEditorAdapterLaunchPlan,
        }),
      );
    const launchedSession = buildHypervisorLaunchedSessionProjection({
      request,
      recipe,
      projectLabel: project.name,
      codeEditorAdapterAdmission,
    });

    setCurrentProjectId(project.id);
    setNewSessionModalOpen(false);
    setNewSessionSeedIntent(null);
    setNewSessionRecipeId(null);
    setLaunchedSessionProjections((current) => {
      const next = mergeHypervisorLaunchedSessionProjection(
        current,
        launchedSession,
      );
      persistHypervisorLaunchedSessionProjections({
        storage: hypervisorBrowserStorage(),
        projections: next,
      });
      return next;
    });

    if (recipe.surface_id === "sessions") {
      const summary = request.launch_summary;
      const intentPrefix = summary.seed_intent
        ? `Intent: ${summary.seed_intent}. `
        : "";
      setHypervisorSeedIntent(
        `${intentPrefix}Start ${recipe.label.toLowerCase()} for ${project.name}. Target: ${summary.target_binding.target_kind} via ${summary.target_binding.session_route_ref}. Harness: ${summary.harness_label}. Model route: ${summary.model_route_ref} (${summary.model_route_availability_state}). Code editor adapter: ${summary.code_editor_adapter_ref}. Authority: ${summary.authority_scope_refs.join(", ")}. Privacy: ${summary.privacy_posture_ref}. Receipt preview: ${summary.receipt_preview_ref}.`,
      );
      setChatSurface("chat");
      setChatPaneVisible(true);
    }

    setActiveView(recipe.surface_id);
  };

  const applyPendingChatLaunchRequest = async (
    pendingLaunch: PendingChatLaunchEnvelope | null,
    source: string,
  ) => {
    if (!pendingLaunch) {
      return;
    }

    const { launchId, request: pendingRequest } = pendingLaunch;
    if (appliedChatLaunchIds.has(launchId)) {
      await recordChatLaunchReceipt("chat_pending_launch_duplicate", {
        source,
        launchId,
        kind: pendingRequest.kind,
        request: summarizePendingChatLaunchRequest(pendingRequest),
      });
      await ackPendingChatLaunchRequest(launchId);
      return;
    }
    if (lastAppliedChatLaunchIdRef.current === launchId) {
      await recordChatLaunchReceipt("chat_pending_launch_duplicate", {
        source,
        launchId,
        kind: pendingRequest.kind,
        request: summarizePendingChatLaunchRequest(pendingRequest),
      });
      await ackPendingChatLaunchRequest(launchId);
      return;
    }

    const claimedLaunch = await ackPendingChatLaunchRequest(launchId);
    if (!claimedLaunch) {
      await recordChatLaunchReceipt("chat_pending_launch_duplicate", {
        source,
        launchId,
        kind: pendingRequest.kind,
        request: summarizePendingChatLaunchRequest(pendingRequest),
        reason: "launch_already_claimed",
      });
      return;
    }

    appliedChatLaunchIds.add(launchId);
    lastAppliedChatLaunchIdRef.current = launchId;
    await recordChatLaunchReceipt("chat_pending_launch_applying", {
      source,
      launchId,
      kind: pendingRequest.kind,
      request: summarizePendingChatLaunchRequest(pendingRequest),
    });

    try {
      switch (pendingRequest.kind) {
        case "view":
          openRequestedSurface(pendingRequest.view);
          await recordChatLaunchReceipt("chat_pending_launch_applied", {
            source,
            launchId,
            kind: pendingRequest.kind,
            view: pendingRequest.view,
          });
          return;
        case "session-target":
          await openSessionTarget(pendingRequest.sessionId);
          await recordChatLaunchReceipt("chat_pending_launch_applied", {
            source,
            launchId,
            kind: pendingRequest.kind,
            sessionId: pendingRequest.sessionId,
          });
          return;
        case "capability":
          openCapabilityTarget(
            pendingRequest.connectorId ?? null,
            pendingRequest.detailSection ?? null,
          );
          await recordChatLaunchReceipt("chat_pending_launch_applied", {
            source,
            launchId,
            kind: pendingRequest.kind,
            connectorId: pendingRequest.connectorId ?? null,
            detailSection: pendingRequest.detailSection ?? null,
          });
          return;
        case "policy":
          openPolicyCenter(pendingRequest.connectorId ?? null);
          await recordChatLaunchReceipt("chat_pending_launch_applied", {
            source,
            launchId,
            kind: pendingRequest.kind,
            connectorId: pendingRequest.connectorId ?? null,
          });
          return;
        case "hypervisor-intent":
          if (pendingRequest.sessionId) {
            await bootstrapHypervisorSession({
              refreshCurrentTask: false,
            });
            setChatSurface("chat");
            setChatPaneVisible(true);
            setActiveView("sessions");
            await waitForChatHypervisorSurfaceFrame();
            await recordChatLaunchReceipt(
              "chat_session_followup_submit_dispatching",
              {
                source,
                launchId,
                sessionId: pendingRequest.sessionId,
                intentLength: pendingRequest.intent.length,
              },
            );
            await invoke("continue_task", {
              sessionId: pendingRequest.sessionId,
              userInput: pendingRequest.intent,
            });
            void openSessionTarget(pendingRequest.sessionId).catch((error) => {
              console.error(
                "[Chat][Launch] retained session reopen after direct follow-up submit failed",
                error,
              );
            });
            await recordChatLaunchReceipt(
              "chat_session_followup_submit_resolved",
              {
                source,
                launchId,
                sessionId: pendingRequest.sessionId,
                intentLength: pendingRequest.intent.length,
              },
            );
            await recordChatLaunchReceipt("chat_pending_launch_applied", {
              source,
              launchId,
              kind: pendingRequest.kind,
              intent: pendingRequest.intent,
              sessionId: pendingRequest.sessionId,
              submissionMode: "direct_continue_task",
            });
            return;
          }
          openHypervisorSessionWithIntent(pendingRequest.intent);
          await recordChatLaunchReceipt("chat_pending_launch_applied", {
            source,
            launchId,
            kind: pendingRequest.kind,
            intent: pendingRequest.intent,
            sessionId: pendingRequest.sessionId ?? null,
            submissionMode: "seed_intent",
          });
          return;
        case "assistant-workbench":
          activateWorkbenchSession(pendingRequest.session);
          await recordChatLaunchReceipt("chat_pending_launch_applied", {
            source,
            launchId,
            kind: pendingRequest.kind,
            session: summarizeAssistantWorkbenchSession(pendingRequest.session),
          });
          return;
        default:
          return;
      }
    } catch (error) {
      appliedChatLaunchIds.delete(launchId);
      lastAppliedChatLaunchIdRef.current = null;
      await recordChatLaunchReceipt("chat_pending_launch_failed", {
        source,
        launchId,
        kind: pendingRequest.kind,
        request: summarizePendingChatLaunchRequest(pendingRequest),
        error: error instanceof Error ? error.message : String(error ?? ""),
      });
    }
  };

  const hydratePendingChatLaunchRequestIfPresent = async (source: string) => {
    if (chatLaunchHydrationInFlightRef.current) {
      return;
    }
    chatLaunchHydrationInFlightRef.current = true;

    try {
      const pendingLaunch = await peekPendingChatLaunchRequest();
      if (!pendingLaunch) {
        await recordChatLaunchReceipt("chat_pending_launch_empty", {
          source,
        });
        return;
      }
      await applyPendingChatLaunchRequest(pendingLaunch, source);
    } finally {
      chatLaunchHydrationInFlightRef.current = false;
    }
  };

  useEffect(() => {
    let active = true;
    const unlistenPromise = isHypervisorClientRuntime()
      ? listen<PendingChatLaunchEnvelope>("request-chat-launch", (event) => {
          if (!active) {
            return;
          }
          void recordChatLaunchReceipt("chat_launch_event_received", {
            launchId: event.payload.launchId,
            kind: event.payload.request.kind,
            request: summarizePendingChatLaunchRequest(event.payload.request),
          });
          void applyPendingChatLaunchRequest(event.payload, "event");
        })
      : null;

    return () => {
      active = false;
      safelyDisposeHostListener(unlistenPromise);
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

    const unlistenPromise = isHypervisorClientRuntime()
      ? listen<AssistantUserProfile>("assistant-user-profile-updated", (event) => {
          if (cancelled) return;
          setProfile(event.payload);
          setProfileDraft(event.payload);
        })
      : null;

    return () => {
      cancelled = true;
      safelyDisposeHostListener(unlistenPromise);
    };
  }, []);

  useEffect(() => {
    const resetUnlistenPromise = listenForHypervisorDataReset();

    return () => {
      safelyDisposeHostListener(resetUnlistenPromise);
    };
  }, []);

  useEffect(() => {
    const handler = (event: KeyboardEvent) => {
      if (!event.metaKey && !event.ctrlKey) return;
      if (event.key.toLowerCase() !== "k") return;
      event.preventDefault();
      setCommandPaletteMode("default");
      setCommandPaletteInitialQuery("");
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

    const badgeUnlistenPromise = isHypervisorClientRuntime()
      ? listen<number>("notifications-badge-updated", (event) => {
          setNotificationBadgeCount(event.payload);
        })
      : null;
    const interventionToastUnlistenPromise = isHypervisorClientRuntime()
      ? listen<InterventionRecord>("intervention-toast-candidate", (event) => {
          void sendNativeHypervisorNotification(event.payload);
        })
      : null;
    const assistantToastUnlistenPromise = isHypervisorClientRuntime()
      ? listen<AssistantNotificationRecord>(
          "assistant-notification-toast-candidate",
          (event) => {
            void sendNativeHypervisorNotification(event.payload);
          },
        )
      : null;

    return () => {
      cancelled = true;
      safelyDisposeHostListener(badgeUnlistenPromise);
      safelyDisposeHostListener(interventionToastUnlistenPromise);
      safelyDisposeHostListener(assistantToastUnlistenPromise);
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

    const unlistenPromise = isHypervisorClientRuntime()
      ? listen<CapabilityGovernanceRequest | null>(
          "capability-governance-request-updated",
          (event) => {
            if (!cancelled) {
              setCapabilityGovernanceRequest(event.payload);
            }
          },
        )
      : null;

    return () => {
      cancelled = true;
      safelyDisposeHostListener(unlistenPromise);
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
    setActiveView("agents");
  };

  const openWorkflowPreflight = (
    seed: WorkflowComposerPreflightSeed | null = { panel: "readiness" },
  ) => {
    setWorkflowPreflightSeed(seed ?? { panel: "readiness" });
    setActiveView("automations");
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
    await bootstrapHypervisorSession({
      refreshCurrentTask: false,
    });
    const store = useHypervisorSessionStore.getState();
    await store.loadSession(sessionId);
    await store.refreshSessionHistory();
    setChatSurface("chat");
    setActiveView("sessions");
  };

  useEffect(() => {
    let cancelled = false;

    void hydratePendingChatLaunchRequestIfPresent("mount").then(() => {
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

  const chatFullscreen =
    activeView !== "sessions" && chatPaneVisible && chatPaneMaximized;

  return {
    activeView,
    notificationBadgeCount,
    currentProject,
    projects: PROJECT_SCOPES,
    chatFullscreen,
    changePrimaryView,
    chat: {
      surface: chatSurface,
      paneVisible: chatPaneVisible,
      paneMaximized: chatPaneMaximized,
      assistantWorkbench,
      seedIntent: hypervisorSeedIntent,
      hidePane: hideChatPane,
      showPane: showChatPane,
      togglePaneVisibility: toggleChatPaneVisibility,
      setSurface: setChatSurface,
      toggleMaximize: () =>
        setChatPaneMaximized((maximized) => !maximized),
      consumeSeedIntent: () => setHypervisorSeedIntent(null),
      openHypervisorSessionWithIntent,
      openReplyComposer,
      openMeetingPrep,
    },
    workflow: {
      openPreflight: openWorkflowPreflight,
      selectProject: setCurrentProjectId,
      preflightSeed: workflowPreflightSeed,
      consumePreflightSeed: () => setWorkflowPreflightSeed(null),
    },
    sessions: {
      launchedSessionProjections,
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
      commandPaletteMode,
      commandPaletteInitialQuery,
      openCommandPalette: (
        initialQuery = "",
        mode: "default" | "tools" = "default",
      ) => {
        setCommandPaletteMode(mode);
        setCommandPaletteInitialQuery(initialQuery);
        setCommandPaletteOpen(true);
      },
      closeCommandPalette: () => setCommandPaletteOpen(false),
      newSessionModalOpen,
      newSessionSeedIntent,
      newSessionRecipeId,
      openNewSessionModal: (seed?: NewSessionModalSeed) => {
        const seedIntent =
          typeof seed === "string" ? seed : seed?.seedIntent ?? null;
        const recipeId = typeof seed === "object" ? seed?.recipeId ?? null : null;
        setNewSessionSeedIntent(
          typeof seedIntent === "string" && seedIntent.trim()
            ? seedIntent.trim()
            : null,
        );
        setNewSessionRecipeId(
          typeof recipeId === "string" && recipeId.trim() ? recipeId.trim() : null,
        );
        setNewSessionModalOpen(true);
      },
      closeNewSessionModal: () => {
        setNewSessionModalOpen(false);
        setNewSessionSeedIntent(null);
        setNewSessionRecipeId(null);
      },
      launchNewSession,
    },
  };
}
