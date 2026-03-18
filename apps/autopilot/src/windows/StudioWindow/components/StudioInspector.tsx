import { countActiveOverrides, type ShieldPolicyState } from "../policyCenter";
import type { AssistantUserProfile, AssistantWorkbenchSession } from "../../../types";

type PrimaryView = "chat" | "workflows" | "runs" | "inbox" | "connections" | "control";

interface StudioInspectorProps {
  activeView: PrimaryView;
  chatSurface: "chat" | "reply-composer" | "meeting-prep";
  workflowSurface: "canvas" | "agents" | "catalog";
  runsSurface: "runtime" | "evidence";
  controlSurface: "policy" | "system";
  interfaceMode: "GHOST" | "COMPOSE";
  notificationCount: number;
  shieldPolicy: ShieldPolicyState;
  profile: AssistantUserProfile;
  assistantWorkbench: AssistantWorkbenchSession | null;
  editingAgentName?: string | null;
  focusedPolicyConnectorId?: string | null;
  onOpenControl: () => void;
}

function initialsForProfile(profile: AssistantUserProfile): string {
  const source = (profile.preferredName || profile.displayName || "Operator").trim();
  const initials = source
    .split(/\s+/)
    .filter(Boolean)
    .map((part) => part[0])
    .slice(0, 2)
    .join("")
    .toUpperCase();
  return initials || profile.avatarSeed || "OP";
}

function surfaceLabel(
  activeView: PrimaryView,
  surfaces: Pick<
    StudioInspectorProps,
    "chatSurface" | "workflowSurface" | "runsSurface" | "controlSurface"
  >,
): string {
  if (activeView === "chat") {
    if (surfaces.chatSurface === "reply-composer") return "Reply composer";
    if (surfaces.chatSurface === "meeting-prep") return "Meeting prep";
    return "Conversation";
  }
  if (activeView === "workflows") {
    if (surfaces.workflowSurface === "agents") return "Agents";
    if (surfaces.workflowSurface === "catalog") return "Catalog";
    return "Canvas";
  }
  if (activeView === "runs") {
    return surfaces.runsSurface === "evidence" ? "Evidence atlas" : "Runtime";
  }
  if (activeView === "control") {
    return surfaces.controlSurface === "system" ? "System ops" : "Policy";
  }
  return activeView[0].toUpperCase() + activeView.slice(1);
}

function stageForView(activeView: PrimaryView): string {
  switch (activeView) {
    case "chat":
      return "Talk";
    case "workflows":
      return "Encode";
    case "runs":
      return "Execute / supervise";
    case "inbox":
      return "Approve";
    case "connections":
      return "Reach";
    case "control":
      return "Govern";
    default:
      return "Operate";
  }
}

function summaryForView(
  props: StudioInspectorProps,
): { title: string; body: string; items: string[] } {
  const {
    activeView,
    chatSurface,
    workflowSurface,
    runsSurface,
    notificationCount,
    interfaceMode,
    shieldPolicy,
    assistantWorkbench,
    editingAgentName,
    focusedPolicyConnectorId,
  } = props;

  switch (activeView) {
    case "chat":
      return {
        title: "Chat posture",
        body:
          chatSurface === "chat"
            ? "Steer workers conversationally, then drop into native task surfaces only when the work benefits from tighter structure."
            : "A native workbench is active so the operator can finish a precise task without losing context from the control plane.",
        items: [
          `Surface: ${surfaceLabel(activeView, props)}`,
          assistantWorkbench ? `Task: ${assistantWorkbench.kind.replace(/_/g, " ")}` : "Task: general chat",
          `Inbox backlog: ${notificationCount}`,
        ],
      };
    case "workflows":
      return {
        title: "Workflow primitives",
        body:
          "The canvas supports more than agents. Build automations out of triggers, actions, approvals, policies, evidence, logic, and queueing semantics.",
        items: [
          `Surface: ${surfaceLabel(activeView, props)}`,
          interfaceMode === "GHOST" ? "Ghost mode: recording" : "Ghost mode: idle",
          editingAgentName ? `Builder open: ${editingAgentName}` : workflowSurface === "catalog" ? "Catalog: installable assets" : "Builder: no agent selected",
        ],
      };
    case "runs":
      return {
        title: "Operational supervision",
        body:
          "This lane is for live execution and evidence. Operators should be able to inspect what happened, why it happened, and which tools or memories influenced the run.",
        items: [
          `Surface: ${surfaceLabel(activeView, props)}`,
          runsSurface === "evidence" ? "Focus: evidence graph and context receipts" : "Focus: runtime fleet and execution health",
          `Inbox backlog: ${notificationCount}`,
        ],
      };
    case "inbox":
      return {
        title: "Inbox model",
        body:
          "Inbox is a full work queue, not a notification bell. It merges approvals, interventions, and ranked prompts into one durable place to review and act.",
        items: [
          `Unresolved items: ${notificationCount}`,
          "Control items: interventions and approvals",
          "Assistant items: ranked prompts and recommendations",
        ],
      };
    case "connections":
      return {
        title: "Reachability boundary",
        body:
          "Connections answer what the system can reach. Keep capability, auth state, and subscription health here while leaving posture and approval rules to Control.",
        items: [
          `Global reads: ${shieldPolicy.global.reads}`,
          `Global writes: ${shieldPolicy.global.writes}`,
          `Policy overrides: ${countActiveOverrides(shieldPolicy)}`,
        ],
      };
    case "control":
      return {
        title: "Governance baseline",
        body:
          "Control is the sovereign plane for policy, approval posture, privacy handling, and system-level operations that shape how software workers behave.",
        items: [
          `Surface: ${surfaceLabel(activeView, props)}`,
          `Automations: ${shieldPolicy.global.automations.replace(/_/g, " ")}`,
          focusedPolicyConnectorId ? `Focused connector: ${focusedPolicyConnectorId}` : `Overrides: ${countActiveOverrides(shieldPolicy)}`,
        ],
      };
    default:
      return {
        title: "Mission control",
        body: "Operate software workers from one coherent shell.",
        items: [],
      };
  }
}

export function StudioInspector(props: StudioInspectorProps) {
  const currentSurface = surfaceLabel(props.activeView, props);
  const currentStage = stageForView(props.activeView);
  const summary = summaryForView(props);
  const visibleName = props.profile.preferredName || props.profile.displayName;

  return (
    <aside className="studio-shell-inspector" aria-label="Inspector">
      <div className="studio-shell-inspector-head">
        <span className="studio-shell-inspector-kicker">Inspector</span>
        <h2>{summary.title}</h2>
        <p>{summary.body}</p>
      </div>

      <section className="studio-shell-inspector-card">
        <div className="studio-shell-inspector-card-head">
          <strong>Operating loop</strong>
          <span>{currentStage}</span>
        </div>
        <div className="studio-shell-loop">
          <span className={props.activeView === "chat" ? "is-active" : ""}>Talk</span>
          <span className={props.activeView === "workflows" ? "is-active" : ""}>Encode</span>
          <span className={props.activeView === "runs" ? "is-active" : ""}>Execute</span>
          <span className={props.activeView === "runs" ? "is-active" : ""}>Supervise</span>
          <span className={props.activeView === "inbox" ? "is-active" : ""}>Approve</span>
          <span className={props.activeView === "control" ? "is-active" : ""}>Govern</span>
        </div>
      </section>

      <section className="studio-shell-inspector-card">
        <div className="studio-shell-inspector-card-head">
          <strong>Current surface</strong>
          <span>{currentSurface}</span>
        </div>
        <ul className="studio-shell-inspector-list">
          {summary.items.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      </section>

      <section className="studio-shell-inspector-card">
        <div className="studio-shell-inspector-profile-head">
          <span className="studio-shell-inspector-avatar">{initialsForProfile(props.profile)}</span>
          <div className="studio-shell-inspector-profile-meta">
            <strong>{visibleName}</strong>
            <span>{props.profile.roleLabel || "Local shell profile"}</span>
          </div>
        </div>
        <ul className="studio-shell-inspector-list">
          <li>Timezone: {props.profile.timezone}</li>
          <li>Locale: {props.profile.locale}</li>
          <li>Email: {props.profile.primaryEmail || "Not set"}</li>
        </ul>
        <div className="studio-shell-inspector-actions">
          <button type="button" className="studio-shell-inspector-button" onClick={props.onOpenControl}>
            Manage in Control
          </button>
        </div>
      </section>

      <section className="studio-shell-inspector-card">
        <div className="studio-shell-inspector-card-head">
          <strong>System truth</strong>
          <span>Autopilot shell</span>
        </div>
        <p className="studio-shell-inspector-quote">
          Autopilot should feel like the sovereign control plane for software workers, not merely a
          private desktop assistant.
        </p>
      </section>
    </aside>
  );
}
