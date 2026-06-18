import { useState } from "react";
import "./Home.css";

import type { SettingsSection } from "../Settings/settingsViewShared";

interface ProjectScope {
  id: string;
  name: string;
  description: string;
  environment: string;
  rootPath: string;
}

interface HomeNewSessionSeed {
  seedIntent?: string | null;
  recipeId?: string | null;
}

interface HomeRecentSessionProjection {
  session_ref: string;
  project_label: string;
  launch_summary: {
    seed_intent: string | null;
  };
  branch_label?: string | null;
  relative_time_label?: string | null;
  activity_count?: number | null;
  admission_state?: string | null;
}

interface HomeViewProps {
  currentProject: ProjectScope;
  recentSessions?: readonly HomeRecentSessionProjection[];
  notificationCount: number;
  onOpenChat: () => void;
  onOpenNewSession: (seed?: string | HomeNewSessionSeed | null) => void;
  onOpenWorkspace: () => void;
  onOpenRuns: () => void;
  onOpenModels: () => void;
  onOpenInbox: () => void;
  onOpenCapabilities: () => void;
  onOpenPolicy: () => void;
  onOpenSettings: (section?: SettingsSection | null) => void;
  onOpenCommandPalette: () => void;
  onOpenCockpitSurface: (surfaceRef: string) => void;
}

const HOME_AGENT_PROMPTS = [
  {
    label: "Automate env setup",
    seedIntent:
      "Create a fully working development environment as code configuration for this workspace.",
    tone: "blue",
  },
  {
    label: "Fix a bug",
    seedIntent:
      "Find an important bug in this workspace, fix it, and produce receipts for the change.",
    tone: "red",
  },
  {
    label: "Boost your test coverage",
    seedIntent:
      "Find key areas in this workspace that need stronger test coverage and implement focused tests.",
    tone: "purple",
  },
] as const;

function ProjectFocusIcon() {
  return (
    <svg
      className="chat-home-zero-control-icon"
      width="16"
      height="16"
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden="true"
    >
      <circle cx="12" cy="12" r="3" />
      <path d="M3 7V5a2 2 0 0 1 2-2h2" />
      <path d="M17 3h2a2 2 0 0 1 2 2v2" />
      <path d="M21 17v2a2 2 0 0 1-2 2h-2" />
      <path d="M7 21H5a2 2 0 0 1-2-2v-2" />
    </svg>
  );
}

function PlusIcon() {
  return (
    <svg
      className="chat-home-zero-control-icon"
      width="16"
      height="16"
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden="true"
    >
      <path d="M12 3.75V12M12 12V20.25M12 12H3.75M12 12H20.25" />
    </svg>
  );
}

function ChevronDownIcon() {
  return (
    <svg
      className="chat-home-zero-control-icon"
      width="16"
      height="16"
      viewBox="0 0 16 16"
      fill="none"
      aria-hidden="true"
    >
      <path d="M3.625 5.35 8 9.725l4.375-4.375" />
    </svg>
  );
}

function ModelGlyphIcon() {
  return (
    <svg
      className="chat-home-zero-control-icon chat-home-zero-control-icon--model"
      width="16"
      height="16"
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden="true"
    >
      <path
        d="M22.282 9.821a5.985 5.985 0 0 0-.516-4.911 6.046 6.046 0 0 0-6.51-2.9A6.065 6.065 0 0 0 4.981 4.182a5.985 5.985 0 0 0-3.998 2.9 6.046 6.046 0 0 0 .743 7.096 5.98 5.98 0 0 0 .511 4.911 6.051 6.051 0 0 0 6.515 2.9A5.985 5.985 0 0 0 13.26 24a6.056 6.056 0 0 0 5.772-4.206 5.989 5.989 0 0 0 3.998-2.9 6.056 6.056 0 0 0-.748-7.073Zm-9.022 12.608a4.476 4.476 0 0 1-2.877-1.041l.142-.08 4.778-2.758a.795.795 0 0 0 .393-.681v-6.737l2.02 1.169a.071.071 0 0 1 .038.052v5.582a4.504 4.504 0 0 1-4.494 4.494Zm-9.661-4.125a4.471 4.471 0 0 1-.535-3.014l.142.085 4.783 2.758a.771.771 0 0 0 .781 0l5.843-3.368v2.332a.08.08 0 0 1-.033.062L9.74 19.95a4.499 4.499 0 0 1-6.141-1.646ZM2.341 7.896a4.485 4.485 0 0 1 2.365-1.973V11.6a.766.766 0 0 0 .388.676l5.814 3.355-2.02 1.168a.076.076 0 0 1-.071 0l-4.83-2.786a4.504 4.504 0 0 1-1.646-6.117Zm16.596 3.855-5.833-3.387 2.02-1.164a.076.076 0 0 1 .071 0l4.83 2.791a4.494 4.494 0 0 1-.676 8.105v-5.678a.79.79 0 0 0-.412-.687Zm2.011-3.023-.142-.085-4.774-2.782a.776.776 0 0 0-.785 0L9.409 9.23V6.897a.066.066 0 0 1 .028-.061l4.83-2.787a4.499 4.499 0 0 1 6.681 4.66ZM8.306 12.863l-2.02-1.164a.08.08 0 0 1-.038-.057V6.074a4.499 4.499 0 0 1 7.376-3.453l-.142.08-4.778 2.758a.795.795 0 0 0-.393.681Zm1.098-2.362 2.603-1.506 2.603 1.506v3.012l-2.603 1.506-2.603-1.506Z"
        fill="currentColor"
      />
    </svg>
  );
}

function ArrowUpIcon() {
  return (
    <svg
      className="chat-home-zero-control-icon"
      width="18"
      height="18"
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden="true"
    >
      <path d="M12 19V5" />
      <path d="M5 12 12 5l7 7" />
    </svg>
  );
}

interface HomeDashboardViewProps {
  currentProject: ProjectScope;
  recentSessions: readonly HomeRecentSessionProjection[];
  onOpenNewSession: (seed?: string | HomeNewSessionSeed | null) => void;
  onOpenWorkspace: () => void;
  onOpenCommandPalette: () => void;
}

function HomeDashboardView({
  currentProject,
  recentSessions,
  onOpenNewSession,
  onOpenWorkspace,
  onOpenCommandPalette,
}: HomeDashboardViewProps) {
  const defaultSeedIntent =
    "Open a governed Hypervisor session for this workspace.";
  const [intentDraft, setIntentDraft] = useState("");
  const launchSession = (seedIntent = intentDraft.trim() || defaultSeedIntent) =>
    onOpenNewSession({
      seedIntent,
      recipeId: "ioi-reference-home",
    });

  return (
    <section
      className="chat-home-zero chat-home-zero--ioi-enterprise"
      aria-label="Hypervisor home"
      data-home-dashboard-variant="ioi-reference-home"
    >
      <div className="chat-home-zero-shell chat-home-zero-shell--prompt">
        <main className="chat-home-zero-prompt-stage" aria-label="Start a session">
          <div className="chat-home-zero-brand-lockup" aria-hidden="true">
            <span className="chat-home-zero-brand-mark" />
          </div>
          <h1>What do you want to get done today?</h1>

          <form
            className="chat-home-zero-composer"
            data-home-intent-composer="ioi-reference"
            onSubmit={(event) => {
              event.preventDefault();
              launchSession();
            }}
          >
            <textarea
              value={intentDraft}
              onChange={(event) => setIntentDraft(event.currentTarget.value)}
              placeholder="Describe your task or type / for commands"
              aria-label="Describe your task"
            />
            <div className="chat-home-zero-composer-controls">
              <button
                type="button"
                className="chat-home-zero-project-picker"
                data-home-intent-project={currentProject.id}
                onClick={onOpenWorkspace}
              >
                <ProjectFocusIcon />
                <span>Work in a project</span>
                <small>{currentProject.name}</small>
                <ChevronDownIcon />
              </button>
              <button
                type="button"
                className="chat-home-zero-icon-button"
                aria-label="Open command palette"
                onClick={onOpenCommandPalette}
              >
                <PlusIcon />
              </button>
              <button
                type="button"
                className="chat-home-zero-model-picker"
                data-home-intent-model="default-local"
              >
                <ModelGlyphIcon />
                <span>5.5 Medium</span>
                <ChevronDownIcon />
              </button>
              <button
                type="submit"
                className="chat-home-zero-submit"
                data-home-start-session="true"
                aria-label="Start session"
              >
                <ArrowUpIcon />
              </button>
            </div>
          </form>

          <div className="chat-home-zero-quickstarts" aria-label="Suggested actions">
            {HOME_AGENT_PROMPTS.map((prompt) => (
              <button
                type="button"
                key={prompt.label}
                data-home-agent-prompt={prompt.label}
                data-prompt-tone={prompt.tone}
                onClick={() => launchSession(prompt.seedIntent)}
              >
                <span aria-hidden="true" />
                {prompt.label}
              </button>
            ))}
          </div>

          {recentSessions.length > 0 ? (
            <section
              className="chat-home-zero-session-list"
              aria-label="Recent Sessions"
              data-home-reference-session-list="true"
            >
              <h2>Recent Sessions</h2>
              <div className="chat-home-zero-session-list__rows">
                {recentSessions.slice(0, 3).map((session, index) => {
                  const sessionTitle =
                    session.launch_summary.seed_intent ??
                    `Open ${session.project_label}`;
                  return (
                    <button
                      type="button"
                      key={session.session_ref}
                      data-home-reference-session-ref={session.session_ref}
                      data-home-reference-session-state={
                        session.admission_state ?? "pending_daemon_admission"
                      }
                      onClick={() => launchSession(sessionTitle)}
                    >
                      <span
                        className="chat-home-zero-session-list__dot"
                        data-session-dot-active={index === 0 ? "true" : "false"}
                        aria-hidden="true"
                      />
                      <span className="chat-home-zero-session-list__copy">
                        <strong>{sessionTitle}</strong>
                        <small>
                          {session.relative_time_label ??
                            session.branch_label ??
                            "recently"}
                        </small>
                      </span>
                    </button>
                  );
                })}
              </div>
            </section>
          ) : null}
        </main>
      </div>
    </section>
  );
}

export function HomeView({
  currentProject,
  recentSessions = [],
  onOpenNewSession,
  onOpenWorkspace,
  onOpenCommandPalette,
}: HomeViewProps) {
  return (
    <section
      className="chat-home"
      aria-label="Hypervisor home dashboard"
      data-home-onboarding-state="complete"
    >
      <HomeDashboardView
        currentProject={currentProject}
        recentSessions={recentSessions}
        onOpenNewSession={onOpenNewSession}
        onOpenWorkspace={onOpenWorkspace}
        onOpenCommandPalette={onOpenCommandPalette}
      />
    </section>
  );
}
