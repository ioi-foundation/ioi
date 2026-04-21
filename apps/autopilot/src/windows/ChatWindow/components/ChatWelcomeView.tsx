import type { ReactNode } from "react";
import {
  AgentsIcon,
  AutopilotIcon,
  CatalogIcon,
  ComposeIcon,
  IntegrationsIcon,
  NotificationsIcon,
} from "./ChatActivityBarIcons";

interface ProjectScope {
  id: string;
  name: string;
  description: string;
  environment: string;
  rootPath: string;
}

interface ChatWelcomeViewProps {
  currentProject: ProjectScope;
  projects: ProjectScope[];
  notificationCount: number;
  onOpenCanvas: () => void;
  onOpenStudio: () => void;
  onOpenAgents: () => void;
  onOpenCatalog: () => void;
  onOpenInbox: () => void;
  onOpenCapabilities: () => void;
  onOpenPolicy: () => void;
  onSelectProject: (projectId: string) => void;
}

interface StartAction {
  id: string;
  label: string;
  detail: string;
  icon: ReactNode;
  onClick: () => void;
}

interface OperatingLayer {
  id: string;
  title: string;
  meta: string;
  detail: string;
  cta: string;
  onClick: () => void;
}

interface GraduationStep {
  id: string;
  index: string;
  title: string;
  detail: string;
}

export function ChatWelcomeView({
  currentProject,
  projects,
  notificationCount,
  onOpenCanvas,
  onOpenStudio,
  onOpenAgents,
  onOpenCatalog,
  onOpenInbox,
  onOpenCapabilities,
  onOpenPolicy,
  onSelectProject,
}: ChatWelcomeViewProps) {
  const startActions: StartAction[] = [
    {
      id: "canvas",
      label: "Open workflow canvas",
      detail: "Compose orchestration, memory boundaries, and durable execution paths.",
      icon: <ComposeIcon />,
      onClick: onOpenCanvas,
    },
    {
      id: "chat",
      label: "Return to Chat",
      detail: "Open the artifact host and let conversation route into documents, visuals, widgets, or workspace renderers only when the outcome needs them.",
      icon: <ComposeIcon />,
      onClick: onOpenStudio,
    },
    {
      id: "agents",
      label: "Inspect the agent library",
      detail: "Refine reusable workers before binding them into the operating loop.",
      icon: <AgentsIcon />,
      onClick: onOpenAgents,
    },
    {
      id: "capabilities",
      label: "Bind governed capabilities",
      detail: "Attach tools, skills, and extension manifests under explicit policy instead of ad hoc prompts.",
      icon: <IntegrationsIcon />,
      onClick: onOpenCapabilities,
    },
    {
      id: "inbox",
      label: notificationCount > 0 ? "Review pending interventions" : "Open the inbox",
      detail:
        notificationCount > 0
          ? `${notificationCount} approvals, clarifications, or ranked prompts are waiting in the operator loop.`
          : "Review approvals, anomalies, and worker results from the durable decision surface.",
      icon: <NotificationsIcon />,
      onClick: onOpenInbox,
    },
    {
      id: "catalog",
      label: "Browse the service catalog",
      detail: "Promote workflows into reusable packages that belong in the Autopilot runtime.",
      icon: <CatalogIcon />,
      onClick: onOpenCatalog,
    },
  ];

  const operatingLayers: OperatingLayer[] = [
    {
      id: "autopilot",
      title: "Autopilot",
      meta: "Operator-first",
      detail:
        "Instruct work, supervise workers, review results, handle approvals, and monitor production runs without leaving the operator shell.",
      cta: "Open inbox",
      onClick: onOpenInbox,
    },
    {
      id: "studio",
      title: "Chat",
      meta: "Builder-first",
      detail:
        "Design workers, compose workflows, bind capabilities, simulate runs, and package durable services on top of the same runtime.",
      cta: "Open canvas",
      onClick: onOpenCanvas,
    },
    {
      id: "control",
      title: "Control",
      meta: "Zero-trust",
      detail:
        "Keep budgets, approvals, and connector posture explicit as work graduates from chat to workflow to service.",
      cta: "Open policy",
      onClick: onOpenPolicy,
    },
  ];

  const graduationSteps: GraduationStep[] = [
    {
      id: "ask",
      index: "01",
      title: "Ask once",
      detail:
        "Start in chat or the operator lane and let the system execute a bounded run.",
    },
    {
      id: "inspect",
      index: "02",
      title: "Inspect the run",
      detail:
        "Review traces, receipts, artifacts, and interventions before the behavior becomes durable.",
    },
    {
      id: "extract",
      index: "03",
      title: "Extract the workflow",
      detail:
        "Move repeatable behavior into agents, governed capabilities, and workflow structure.",
    },
    {
      id: "promote",
      index: "04",
      title: "Promote the service",
      detail:
        "Deploy a bounded worker, then supervise it in production through inbox, policy, and budgets.",
    },
  ];

  return (
    <section className="studio-welcome" aria-label="Autopilot home">
      <div className="studio-welcome-grid">
        <div className="studio-welcome-primary">
          <div className="studio-welcome-hero">
            <span className="studio-welcome-mark" aria-hidden="true">
              <AutopilotIcon />
            </span>
            <div className="studio-welcome-hero-copy">
              <span className="studio-welcome-eyebrow">
                Operator shell + agent IDE layer
              </span>
              <h1>Build durable digital workers without losing the operator shell.</h1>
              <p>
                Autopilot stays operator-first. Chat is the builder-first
                surface for workflows, governed capabilities, replay, and
                promotion into durable services on the same runtime.
              </p>
            </div>
          </div>

          <div className="studio-welcome-hero-strip" aria-label="Chat posture">
            <span>Same ontology, runtime, and policy objects</span>
            <span>Chat to workflow to service</span>
            <span>{currentProject.name} in {currentProject.environment}</span>
          </div>

          <section className="studio-welcome-section">
            <div className="studio-welcome-section-head">
              <h2>Builder surfaces</h2>
              <span>{currentProject.name}</span>
            </div>

            <div className="studio-welcome-action-list">
              {startActions.map((action) => (
                <button
                  key={action.id}
                  type="button"
                  className="studio-welcome-action"
                  onClick={action.onClick}
                >
                  <span className="studio-welcome-action-icon" aria-hidden="true">
                    {action.icon}
                  </span>
                  <span className="studio-welcome-action-copy">
                    <strong>{action.label}</strong>
                    <span>{action.detail}</span>
                  </span>
                </button>
              ))}
            </div>
          </section>

          <section className="studio-welcome-section">
            <div className="studio-welcome-section-head">
              <h2>Graduation loop</h2>
              <span>{"Chat -> Workflow -> Service"}</span>
            </div>

            <div className="studio-welcome-loop">
              {graduationSteps.map((step) => (
                <div key={step.id} className="studio-welcome-loop-step">
                  <span className="studio-welcome-loop-index">{step.index}</span>
                  <div className="studio-welcome-loop-copy">
                    <strong>{step.title}</strong>
                    <p>{step.detail}</p>
                  </div>
                </div>
              ))}
            </div>
          </section>
        </div>

        <div className="studio-welcome-secondary">
          <section className="studio-welcome-section">
            <div className="studio-welcome-section-head">
              <h2>Operating split</h2>
              <span>One system, two altitudes</span>
            </div>

            <div className="studio-welcome-layer-list">
              {operatingLayers.map((layer) => (
                <div key={layer.id} className="studio-welcome-layer">
                  <div className="studio-welcome-layer-head">
                    <strong>{layer.title}</strong>
                    <span>{layer.meta}</span>
                  </div>
                  <p>{layer.detail}</p>
                  <button
                    type="button"
                    className="studio-welcome-layer-action"
                    onClick={layer.onClick}
                  >
                    {layer.cta}
                  </button>
                </div>
              ))}
            </div>
          </section>

          <section className="studio-welcome-section">
            <div className="studio-welcome-section-head">
              <h2>Current scope</h2>
              <span>{currentProject.environment}</span>
            </div>

            <div className="studio-welcome-facts">
              <div className="studio-welcome-fact">
                <span>Project</span>
                <strong>{currentProject.name}</strong>
              </div>
              <div className="studio-welcome-fact">
                <span>Boundary</span>
                <strong>{currentProject.description}</strong>
              </div>
              <div className="studio-welcome-fact">
                <span>Root</span>
                <strong>{currentProject.rootPath}</strong>
              </div>
              <div className="studio-welcome-fact">
                <span>Posture</span>
                <strong>Operator-controlled</strong>
              </div>
            </div>
          </section>

          <section className="studio-welcome-section">
            <div className="studio-welcome-section-head">
              <h2>Recent scopes</h2>
              <span>{projects.length}</span>
            </div>

            <div className="studio-welcome-recent-list">
              {projects.map((project) => (
                <button
                  key={project.id}
                  type="button"
                  className={`studio-welcome-recent ${
                    project.id === currentProject.id ? "is-active" : ""
                  }`}
                  onClick={() => onSelectProject(project.id)}
                >
                  <span className="studio-welcome-recent-name">
                    {project.name}
                  </span>
                  <span className="studio-welcome-recent-meta">
                    {project.environment} · {project.rootPath}
                  </span>
                </button>
              ))}
            </div>
          </section>
        </div>
      </div>
    </section>
  );
}
