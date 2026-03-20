import { useEffect, useMemo, useState } from "react";
import {
  countActiveOverrides,
  type ShieldPolicyState,
} from "../policyCenter";
import type {
  AssistantUserProfile,
  AssistantWorkbenchSession,
} from "../../../types";

type PrimaryView =
  | "workflows"
  | "runs"
  | "inbox"
  | "capabilities"
  | "policy"
  | "settings";

type UtilityTab = "terminal" | "logs" | "trace" | "receipts";

interface ProjectScope {
  id: string;
  name: string;
  description: string;
  environment: string;
}

interface StudioUtilityDrawerProps {
  activeView: PrimaryView;
  chatSurface: "chat" | "reply-composer" | "meeting-prep";
  operatorPaneOpen: boolean;
  workflowSurface: "canvas" | "agents" | "catalog";
  interfaceMode: "GHOST" | "COMPOSE";
  notificationCount: number;
  shieldPolicy: ShieldPolicyState;
  currentProject: ProjectScope;
  focusedPolicyConnectorId?: string | null;
  assistantWorkbench: AssistantWorkbenchSession | null;
  profile: AssistantUserProfile;
}

interface UtilityLogItem {
  lane: string;
  title: string;
  detail: string;
}

interface UtilityTraceStep {
  title: string;
  detail: string;
  state: "done" | "active" | "queued";
}

interface UtilityReceipt {
  lane: string;
  title: string;
  summary: string;
  digest: string;
}

const TABS: Array<{ id: UtilityTab; label: string }> = [
  { id: "terminal", label: "Terminal" },
  { id: "logs", label: "Logs" },
  { id: "trace", label: "Trace" },
  { id: "receipts", label: "Receipts" },
];

function prettySurfaceLabel(view: PrimaryView): string {
  return view[0].toUpperCase() + view.slice(1);
}

function prettyWorkflowSurface(
  surface: StudioUtilityDrawerProps["workflowSurface"],
): string {
  if (surface === "agents") return "agents";
  if (surface === "catalog") return "catalog";
  return "canvas";
}

function prettyOperatorSurface(
  surface: StudioUtilityDrawerProps["chatSurface"],
): string {
  if (surface === "reply-composer") return "reply composer";
  if (surface === "meeting-prep") return "meeting brief";
  return "conversation";
}

function shortDigest(seed: string): string {
  let hash = 0;
  for (let index = 0; index < seed.length; index += 1) {
    hash = (hash * 31 + seed.charCodeAt(index)) >>> 0;
  }
  return `0x${hash.toString(16).padStart(8, "0")}`;
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
  if (view === "runs") return "logs";
  if (view === "inbox") return "receipts";
  if (view === "policy" || view === "settings") return "trace";
  return "terminal";
}

export function StudioUtilityDrawer({
  activeView,
  chatSurface,
  operatorPaneOpen,
  workflowSurface,
  interfaceMode,
  notificationCount,
  shieldPolicy,
  currentProject,
  focusedPolicyConnectorId,
  assistantWorkbench,
  profile,
}: StudioUtilityDrawerProps) {
  const [isOpen, setIsOpen] = useState(true);
  const [activeTab, setActiveTab] = useState<UtilityTab>(
    initialTabForView(activeView),
  );

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

  const terminalLines = useMemo(() => {
    const lines = [
      `$ autopilot scope use ${currentProject.id}`,
      `$ autopilot surface open ${activeView}`,
      `$ autopilot operator ${operatorPaneOpen ? "attach" : "detach"} ${prettyOperatorSurface(chatSurface)}`,
      `$ autopilot policy overrides ${countActiveOverrides(shieldPolicy)}`,
    ];

    if (activeView === "workflows") {
      lines.push(
        `$ autopilot workflows surface ${prettyWorkflowSurface(workflowSurface)}`,
      );
    }

    if (assistantWorkbench) {
      lines.push(
        `$ autopilot handoff ${assistantWorkbench.kind.replace(/_/g, "-")}`,
      );
    }

    lines.push(
      `$ autopilot profile locale ${profile.locale.toLowerCase()}`,
      `$ autopilot mode ${interfaceMode.toLowerCase()}`,
    );

    return lines;
  }, [
    activeView,
    assistantWorkbench,
    chatSurface,
    currentProject.id,
    interfaceMode,
    operatorPaneOpen,
    profile.locale,
    shieldPolicy,
    workflowSurface,
  ]);

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

  const traceSteps = useMemo<UtilityTraceStep[]>(() => {
    const surfaceDetail =
      activeView === "workflows"
        ? `Surface: ${prettyWorkflowSurface(workflowSurface)}`
        : `Surface: ${prettySurfaceLabel(activeView)}`;

    return [
      {
        title: "Scope resolution",
        detail: `${currentProject.name} in ${currentProject.environment}.`,
        state: "done",
      },
      {
        title: "Surface routing",
        detail: surfaceDetail,
        state: "active",
      },
      {
        title: "Operator lane",
        detail: operatorPaneOpen
          ? `Attached to ${prettyOperatorSurface(chatSurface)}.`
          : "Collapsed until explicitly reopened.",
        state: operatorPaneOpen ? "active" : "queued",
      },
      {
        title: "Governance check",
        detail: `Reads ${shieldPolicy.global.reads} · Writes ${shieldPolicy.global.writes} · Overrides ${countActiveOverrides(
          shieldPolicy,
        )}.`,
        state: "done",
      },
      {
        title: "Queue posture",
        detail:
          notificationCount > 0
            ? `${notificationCount} review items are waiting for operator attention.`
            : "Queue is clear.",
        state: notificationCount > 0 ? "active" : "done",
      },
    ];
  }, [
    activeView,
    chatSurface,
    currentProject.environment,
    currentProject.name,
    notificationCount,
    operatorPaneOpen,
    shieldPolicy,
    workflowSurface,
  ]);

  const receipts = useMemo<UtilityReceipt[]>(() => {
    const policyReceipt = [
      shieldPolicy.global.reads,
      shieldPolicy.global.writes,
      shieldPolicy.global.automations,
      String(countActiveOverrides(shieldPolicy)),
    ].join(":");

    return [
      {
        lane: "scope",
        title: "Project receipt",
        summary: `${currentProject.name} scoped to ${currentProject.environment}.`,
        digest: shortDigest(`${currentProject.id}:${currentProject.environment}`),
      },
      {
        lane: "operator",
        title: "Operator receipt",
        summary: operatorPaneOpen
          ? `Operator lane bound to ${prettyOperatorSurface(chatSurface)}.`
          : "Operator lane collapsed but retained in shell state.",
        digest: shortDigest(`${operatorPaneOpen}:${chatSurface}`),
      },
      {
        lane: "policy",
        title: "Policy receipt",
        summary: `Reads ${shieldPolicy.global.reads} · Writes ${shieldPolicy.global.writes} · Automations ${shieldPolicy.global.automations.replace(
          /_/g,
          " ",
        )}.`,
        digest: shortDigest(policyReceipt),
      },
      {
        lane: "queue",
        title: "Queue receipt",
        summary:
          notificationCount > 0
            ? `${notificationCount} pending items remain in the operator inbox.`
            : "No pending review items remain in the operator inbox.",
        digest: shortDigest(`queue:${notificationCount}:${activeView}`),
      },
    ];
  }, [
    activeView,
    chatSurface,
    currentProject.environment,
    currentProject.id,
    currentProject.name,
    notificationCount,
    operatorPaneOpen,
    shieldPolicy,
  ]);

  return (
    <section
      className={`studio-utility-drawer ${isOpen ? "is-open" : "is-collapsed"}`}
      aria-label="Utility drawer"
    >
      <div className="studio-utility-header">
        <div className="studio-utility-meta">
          <span className="studio-utility-kicker">Utilities</span>
          <strong>
            {currentProject.name} · {prettySurfaceLabel(activeView)}
          </strong>
        </div>
        <div className="studio-utility-tabs" role="tablist" aria-label="Utility tabs">
          {TABS.map((tab) => (
            <button
              key={tab.id}
              type="button"
              role="tab"
              aria-selected={activeTab === tab.id}
              className={`studio-utility-tab ${
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
        <button
          type="button"
          className="studio-utility-toggle"
          onClick={() => setIsOpen((open) => !open)}
        >
          {isOpen ? "Collapse" : "Expand"} ⌘J
        </button>
      </div>

      {isOpen ? (
        <div className="studio-utility-body">
          {activeTab === "terminal" ? (
            <div className="studio-utility-terminal">
              {terminalLines.map((line) => (
                <div key={line} className="studio-utility-terminal-line">
                  <span className="studio-utility-terminal-prompt">$</span>
                  <code>{line.replace(/^\$ /, "")}</code>
                </div>
              ))}
            </div>
          ) : null}

          {activeTab === "logs" ? (
            <div className="studio-utility-log-list">
              {logItems.map((item) => (
                <article key={`${item.lane}:${item.title}`} className="studio-utility-card">
                  <div className="studio-utility-card-head">
                    <span>{item.lane}</span>
                    <strong>{item.title}</strong>
                  </div>
                  <p>{item.detail}</p>
                </article>
              ))}
            </div>
          ) : null}

          {activeTab === "trace" ? (
            <div className="studio-utility-trace-list">
              {traceSteps.map((step, index) => (
                <article
                  key={`${index}:${step.title}`}
                  className={`studio-utility-card studio-utility-trace-step studio-utility-trace-step--${step.state}`}
                >
                  <div className="studio-utility-trace-index">{index + 1}</div>
                  <div className="studio-utility-trace-copy">
                    <strong>{step.title}</strong>
                    <p>{step.detail}</p>
                  </div>
                </article>
              ))}
            </div>
          ) : null}

          {activeTab === "receipts" ? (
            <div className="studio-utility-receipts">
              {receipts.map((receipt) => (
                <article
                  key={`${receipt.lane}:${receipt.digest}`}
                  className="studio-utility-card studio-utility-receipt"
                >
                  <div className="studio-utility-card-head">
                    <span>{receipt.lane}</span>
                    <strong>{receipt.title}</strong>
                  </div>
                  <p>{receipt.summary}</p>
                  <code>{receipt.digest}</code>
                </article>
              ))}
            </div>
          ) : null}
        </div>
      ) : null}
    </section>
  );
}
