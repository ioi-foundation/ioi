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

interface HomeViewProps {
  currentProject: ProjectScope;
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

interface HomeDashboardViewProps {
  currentProject: ProjectScope;
  onOpenNewSession: (seed?: string | HomeNewSessionSeed | null) => void;
  onOpenWorkspace: () => void;
  onOpenCommandPalette: () => void;
}

function HomeDashboardView({
  currentProject,
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
                <span aria-hidden="true">+</span>
                Work in a project
                <small>{currentProject.name}</small>
              </button>
              <button
                type="button"
                className="chat-home-zero-icon-button"
                aria-label="Open command palette"
                onClick={onOpenCommandPalette}
              >
                +
              </button>
              <button
                type="button"
                className="chat-home-zero-model-picker"
                data-home-intent-model="default-local"
              >
                5.5 Medium
              </button>
              <button
                type="submit"
                className="chat-home-zero-submit"
                data-home-start-session="true"
                aria-label="Start session"
              >
                ^
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
        </main>
      </div>
    </section>
  );
}

export function HomeView({
  currentProject,
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
        onOpenNewSession={onOpenNewSession}
        onOpenWorkspace={onOpenWorkspace}
        onOpenCommandPalette={onOpenCommandPalette}
      />
    </section>
  );
}
