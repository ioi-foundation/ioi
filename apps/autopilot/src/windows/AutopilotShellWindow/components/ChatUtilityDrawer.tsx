import { buildSessionReplTargets } from "@ioi/agent-ide";
import { useEffect, useMemo, useState } from "react";
import {
  countActiveOverrides,
  type ShieldPolicyState,
} from "../../../surfaces/Policy";
import type { PrimaryView } from "../autopilotShellModel";
import { type TauriRuntime } from "../../../services/TauriRuntime";
import {
  openArtifactReviewTarget,
  openEvidenceReviewSession,
} from "../../../services/reviewNavigation";
import { bootstrapAgentSession, useAgentStore } from "../../../session/autopilotSession";
import {
  buildSessionContinuityOverview,
  currentSessionIdFromTask,
  mergeCurrentTaskRootIntoTargets,
} from "../../../session/sessionContinuity";
import type {
  AssistantWorkbenchSession,
  BenchmarkTraceCaseView,
  BenchmarkTraceFeed,
} from "../../../types";
import { ArtifactEvidencePanel } from "../../ChatShellWindow/components/ArtifactEvidencePanel";
import { ChatReplView } from "../../ChatShellWindow/components/ChatReplView";
import { ChatBenchmarkTraceDeck } from "./ChatBenchmarkTraceDeck";

type UtilityTab = "logs" | "trace" | "receipts" | "sessions";

interface ProjectScope {
  id: string;
  name: string;
  description: string;
  environment: string;
  rootPath: string;
}

interface ChatUtilityDrawerProps {
  runtime: TauriRuntime;
  activeView: PrimaryView;
  chatSurface: "chat" | "reply-composer" | "meeting-prep";
  operatorPaneOpen: boolean;
  notificationCount: number;
  shieldPolicy: ShieldPolicyState;
  currentProject: ProjectScope;
  focusedPolicyConnectorId?: string | null;
  assistantWorkbench: AssistantWorkbenchSession | null;
  onOpenChatConversation: () => void;
}

interface UtilityLogItem {
  lane: string;
  title: string;
  detail: string;
}

function prettyOperatorSurface(
  surface: ChatUtilityDrawerProps["chatSurface"],
): string {
  if (surface === "reply-composer") return "reply composer";
  if (surface === "meeting-prep") return "meeting brief";
  return "conversation";
}

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

function initialTabForView(view: PrimaryView): UtilityTab {
  if (view === "chat") return "receipts";
  if (view === "inbox") return "receipts";
  if (view === "policy" || view === "settings") return "trace";
  return "logs";
}

function defaultTraceCaseId(feed: BenchmarkTraceFeed | null): string | null {
  const cases = feed?.cases ?? [];
  return cases.find((entry) => entry.result !== "pass")?.caseId ?? cases[0]?.caseId ?? null;
}

function defaultTraceSpanId(caseView: BenchmarkTraceCaseView | null): string | null {
  const failureSpan = caseView?.traceMetrics.find((metric) => metric.status !== "pass")
    ?.supportingSpanIds[0];
  if (failureSpan) return failureSpan;
  const bookmarkSpan = caseView?.trace?.bookmarks[0]?.spanId;
  if (bookmarkSpan) return bookmarkSpan;
  return caseView?.trace?.lanes.flatMap((lane) => lane.spans)[0]?.id ?? null;
}

const TABS: Array<{ id: UtilityTab; label: string }> = [
  { id: "logs", label: "Logs" },
  { id: "sessions", label: "Sessions" },
  { id: "trace", label: "Trace" },
  { id: "receipts", label: "Receipts" },
];

function utilityTabLabel(tab: UtilityTab): string {
  return TABS.find((item) => item.id === tab)?.label ?? "Panel";
}

function prettySurfaceLabel(view: PrimaryView): string {
  return view[0].toUpperCase() + view.slice(1);
}

export function ChatUtilityDrawer({
  runtime,
  activeView,
  chatSurface,
  operatorPaneOpen,
  notificationCount,
  shieldPolicy,
  currentProject,
  focusedPolicyConnectorId,
  assistantWorkbench,
  onOpenChatConversation,
}: ChatUtilityDrawerProps) {
  const [isOpen, setIsOpen] = useState(activeView !== "chat");
  const [activeTab, setActiveTab] = useState<UtilityTab>(
    initialTabForView(activeView),
  );
  const [traceFeed, setTraceFeed] = useState<BenchmarkTraceFeed | null>(null);
  const [traceLoading, setTraceLoading] = useState(false);
  const [traceError, setTraceError] = useState<string | null>(null);
  const [selectedTraceCaseId, setSelectedTraceCaseId] = useState<string | null>(null);
  const [selectedTraceSpanId, setSelectedTraceSpanId] = useState<string | null>(null);
  const [sessionSurfaceStatus, setSessionSurfaceStatus] = useState<
    "idle" | "loading" | "ready"
  >("idle");
  const [sessionSurfaceError, setSessionSurfaceError] = useState<string | null>(null);
  const activeTabName = utilityTabLabel(activeTab);
  const {
    task: sessionTask,
    sessions: sessionHistory,
  } = useAgentStore();
  const activeChatSession = sessionTask?.chat_session ?? null;
  const activeArtifactReceipts =
    sessionTask?.renderer_session?.receipts ??
    sessionTask?.build_session?.receipts ??
    [];

  useEffect(() => {
    const handler = (event: KeyboardEvent) => {
      if (isEditableElement(event.target)) return;
      if (!event.metaKey && !event.ctrlKey) return;
      if (event.key.toLowerCase() !== "j") return;
      event.preventDefault();
      setIsOpen((open) => !open);
    };

    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);

  useEffect(() => {
    if (activeView === "chat") {
      setIsOpen(false);
    }
  }, [activeView]);

  useEffect(() => {
    let cancelled = false;
    setSessionSurfaceStatus("loading");
    setSessionSurfaceError(null);

    void bootstrapAgentSession({
      refreshCurrentTask: false,
    })
      .then(async () => {
        const store = useAgentStore.getState();
        await Promise.all([store.refreshCurrentTask(), store.refreshSessionHistory()]);
      })
      .then(() => {
        if (!cancelled) {
          setSessionSurfaceStatus("ready");
        }
      })
      .catch((error) => {
        if (cancelled) {
          return;
        }
        setSessionSurfaceStatus("idle");
        setSessionSurfaceError(
          error instanceof Error ? error.message : String(error ?? ""),
        );
      });

    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (!isOpen || activeTab !== "trace") {
      return;
    }

    let cancelled = false;
    setTraceLoading(true);
    setTraceError(null);

    runtime
      .getLocalBenchmarkTraceFeed(8)
      .then((feed) => {
        if (cancelled) return;
        setTraceFeed(feed);
        setSelectedTraceCaseId((current) => {
          if (current && feed.cases.some((entry) => entry.caseId === current)) {
            return current;
          }
          return defaultTraceCaseId(feed);
        });
      })
      .catch((error) => {
        if (cancelled) return;
        setTraceFeed(null);
        setTraceError(String(error));
      })
      .finally(() => {
        if (!cancelled) {
          setTraceLoading(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [activeTab, isOpen, runtime]);
  const logItems = useMemo<UtilityLogItem[]>(() => {
    const items: UtilityLogItem[] = [
      {
        lane: "scope",
        title: `${currentProject.name} active`,
        detail: `${currentProject.environment} scope selected for ${prettySurfaceLabel(activeView)}.`,
      },
      {
        lane: "operator",
        title: operatorPaneOpen ? "Operator pane attached" : "Operator pane hidden",
        detail: operatorPaneOpen
          ? `Current lane: ${prettyOperatorSurface(chatSurface)}.`
          : "Conversation remains available on demand.",
      },
      {
        lane: "governance",
        title: `${countActiveOverrides(shieldPolicy)} policy overrides active`,
        detail: focusedPolicyConnectorId
          ? `Focused connector: ${focusedPolicyConnectorId}.`
          : `Global automations: ${shieldPolicy.global.automations.replace(/_/g, " ")}.`,
      },
      {
        lane: "queue",
        title: `${notificationCount} inbox items pending`,
        detail:
          notificationCount > 0
            ? "Approvals and ranked prompts are waiting in the project queue."
            : "No pending review items are waiting in Inbox.",
      },
    ];

    if (assistantWorkbench) {
      items.push({
        lane: "handoff",
        title: "Workbench session loaded",
        detail: `Native task: ${assistantWorkbench.kind.replace(/_/g, " ")}.`,
      });
    }

    return items;
  }, [
    activeView,
    assistantWorkbench,
    chatSurface,
    currentProject.environment,
    currentProject.name,
    focusedPolicyConnectorId,
    notificationCount,
    operatorPaneOpen,
    shieldPolicy,
  ]);

  const selectedTraceCase = useMemo(
    () =>
      traceFeed?.cases.find((entry) => entry.caseId === selectedTraceCaseId) ??
      traceFeed?.cases[0] ??
      null,
    [selectedTraceCaseId, traceFeed],
  );
  const activeSessionId = currentSessionIdFromTask(sessionTask);
  const continuityTargets = useMemo(() => {
    const targets = buildSessionReplTargets(sessionHistory, activeSessionId);
    return mergeCurrentTaskRootIntoTargets(targets, sessionTask, activeSessionId);
  }, [activeSessionId, sessionHistory, sessionTask]);
  const continuityOverview = useMemo(
    () => buildSessionContinuityOverview(continuityTargets, activeSessionId),
    [activeSessionId, continuityTargets],
  );

  const handleOpenChatSession = async (sessionId: string) => {
    setSessionSurfaceStatus("loading");
    setSessionSurfaceError(null);
    try {
      const store = useAgentStore.getState();
      await store.loadSession(sessionId);
      await store.refreshSessionHistory();
      onOpenChatConversation();
      setSessionSurfaceStatus("ready");
    } catch (error) {
      setSessionSurfaceStatus("idle");
      setSessionSurfaceError(
        error instanceof Error ? error.message : String(error ?? ""),
      );
    }
  };

  const handleStopStudioSession = async () => {
    setSessionSurfaceStatus("loading");
    setSessionSurfaceError(null);
    try {
      await runtime.stopAssistantSession();
      const store = useAgentStore.getState();
      await Promise.all([store.refreshCurrentTask(), store.refreshSessionHistory()]);
      setSessionSurfaceStatus("ready");
    } catch (error) {
      setSessionSurfaceStatus("idle");
      setSessionSurfaceError(
        error instanceof Error ? error.message : String(error ?? ""),
      );
    }
  };

  useEffect(() => {
    const availableSpanIds = new Set(
      selectedTraceCase?.trace?.lanes.flatMap((lane) => lane.spans.map((span) => span.id)) ?? [],
    );
    if (selectedTraceSpanId && availableSpanIds.has(selectedTraceSpanId)) {
      return;
    }
    setSelectedTraceSpanId(defaultTraceSpanId(selectedTraceCase));
  }, [selectedTraceCase, selectedTraceSpanId]);

  return (
    <section
      className={`chat-utility-drawer ${isOpen ? "is-open" : "is-collapsed"}`}
      aria-label="Utility drawer"
    >
      <div className="chat-utility-header">
        <div className="chat-utility-tabs" role="tablist" aria-label="Utility tabs">
          {TABS.map((tab) => (
            <button
              key={tab.id}
              type="button"
              role="tab"
              aria-selected={activeTab === tab.id}
              className={`chat-utility-tab ${
                activeTab === tab.id ? "is-active" : ""
              }`}
              onClick={() => {
                setActiveTab(tab.id);
                setIsOpen(true);
              }}
            >
              {tab.label}
            </button>
          ))}
        </div>
        <div className="chat-utility-meta">
          <span className="chat-utility-kicker">Panel</span>
          <strong>{activeTabName}</strong>
          <span className="chat-utility-context">
            {currentProject.name} · {prettySurfaceLabel(activeView)}
          </span>
        </div>
        <button
          type="button"
          className="chat-utility-toggle"
          onClick={() => setIsOpen((open) => !open)}
        >
          {isOpen ? "Collapse" : "Expand"} ⌘J
        </button>
      </div>

      {isOpen ? (
        <div className="chat-utility-body">
          {activeTab === "logs" ? (
            <div className="chat-utility-log-list">
              {logItems.map((item) => (
                <article key={`${item.lane}:${item.title}`} className="chat-utility-card">
                  <div className="chat-utility-card-head">
                    <span>{item.lane}</span>
                    <strong>{item.title}</strong>
                  </div>
                  <p>{item.detail}</p>
                </article>
              ))}
            </div>
          ) : null}

          {activeTab === "sessions" ? (
            <div className="chat-utility-log-list">
              <article className="chat-utility-card">
                <div className="chat-utility-card-head">
                  <span>continuity</span>
                  <strong>{continuityOverview.statusLabel}</strong>
                </div>
                <p>{continuityOverview.detail}</p>
                <div className="chat-utility-session-meta">
                  <span>{continuityOverview.targetCount} targets</span>
                  <span>{continuityOverview.attachableCount} attachable</span>
                  <span>{continuityOverview.liveCount} live</span>
                  <span>
                    Surface:{" "}
                    {sessionSurfaceStatus === "loading"
                      ? "Refreshing"
                      : sessionSurfaceError
                        ? "Attention"
                        : "Ready"}
                  </span>
                </div>
              </article>
              {sessionSurfaceError ? (
                <article className="chat-utility-card">
                  <div className="chat-utility-card-head">
                    <span>bridge</span>
                    <strong>Session continuity needs attention</strong>
                  </div>
                  <p>{sessionSurfaceError}</p>
                </article>
              ) : null}
              <ChatReplView
                activeSessionId={activeSessionId}
                currentTask={sessionTask}
                sessions={sessionHistory}
                onLoadSession={(sessionId) => {
                  void handleOpenChatSession(sessionId);
                }}
                onStopSession={() => {
                  void handleStopStudioSession();
                }}
              />
            </div>
          ) : null}

          {activeTab === "trace" ? (
                <ChatBenchmarkTraceDeck
              mode="trace"
              feed={traceFeed}
              loading={traceLoading}
              error={traceError}
              selectedCaseId={selectedTraceCaseId}
              selectedSpanId={selectedTraceSpanId}
              onSelectCase={setSelectedTraceCaseId}
              onSelectSpan={setSelectedTraceSpanId}
            />
          ) : null}

          {activeTab === "receipts" ? (
            activeChatSession ? (
              <div className="chat-utility-receipts">
                <ArtifactEvidencePanel
                  manifest={activeChatSession.artifactManifest}
                  chatSession={activeChatSession}
                  pipelineSteps={activeChatSession.materialization.pipelineSteps ?? []}
                  notes={activeChatSession.materialization.notes}
                  evidence={activeChatSession.verifiedReply.evidence}
                  receipts={activeArtifactReceipts}
                  onOpenArtifact={(artifactId) => {
                    void openArtifactReviewTarget(artifactId);
                  }}
                  onOpenEvidenceSession={(sessionId) => {
                    void openEvidenceReviewSession(sessionId);
                  }}
                />
              </div>
            ) : (
              <div className="chat-utility-log-list">
                <article className="chat-utility-card">
                  <div className="chat-utility-card-head">
                    <span>execution</span>
                    <strong>No active execution receipts yet</strong>
                  </div>
                  <p>
                    Start a Chat run to inspect plan, dispatch, work, merge,
                    verification, and repair evidence here.
                  </p>
                </article>
              </div>
            )
          ) : null}
        </div>
      ) : null}
    </section>
  );
}
