import { invoke } from "@tauri-apps/api/core";
import {
  formatSessionTimeAgo,
  type ConnectorActionDefinition,
  type ConnectorSummary,
  type RuntimeCatalogEntry,
} from "@ioi/agent-ide";
import {
  openCompanionAutopilotIntent,
  openCompanionCapabilityActions,
  openCompanionGate,
} from "../services/companionShellNavigation";
import {
  openChatShellSession,
  openCurrentChatShellSession,
  openNewChatShellSession,
} from "../services/chatSessionNavigation";
import { getSessionFileContext } from "../services/sessionFileContext";
import {
  useCallback,
  useEffect,
  useMemo,
  useState,
  type KeyboardEvent as ReactKeyboardEvent,
} from "react";
import { useAgentStore } from "../session/autopilotSession";
import { getSessionWorkbenchRuntime } from "../services/sessionRuntime";
import type { SessionSummary, SkillCatalogEntry } from "../types";
import { icons, type CommandMenuItem } from "./ui";
import type {
  PrimaryView,
  ProjectScope,
} from "../windows/AutopilotShellWindow/autopilotShellModel";
import {
  AUTOPILOT_ONBOARDING_STEPS,
  HOME_ONBOARDING_FOCUS_EVENT,
} from "../surfaces/Home/homeOnboardingModel";
import "./CommandPalette.css";

type WorkflowSurface = "home" | "canvas" | "agents" | "catalog";
type LoadStatus = "idle" | "loading" | "ready" | "error";
type PaletteMode = "all" | "commands" | "workspace" | "symbols" | "help";

type LiveToolRecord = {
  connector: ConnectorSummary;
  action: ConnectorActionDefinition;
};

type CommandPaletteItem = CommandMenuItem & {
  shortcut?: string[];
  suffix?: string;
};

type CommandPaletteSection = {
  id: string;
  title?: string;
  items: CommandPaletteItem[];
};

type CommandPaletteProps = {
  activeView: PrimaryView;
  workflowSurface: WorkflowSurface;
  currentProjectId: string;
  notificationCount: number;
  onClose: () => void;
  onOpenPrimaryView: (view: PrimaryView) => void;
  onOpenWorkflowSurface: (surface: WorkflowSurface) => void;
  onSelectProject: (projectId: string) => void;
  projects: ProjectScope[];
};

function humanizeLabel(value: string | null | undefined) {
  if (!value) {
    return "";
  }

  return value
    .replace(/[_-]+/g, " ")
    .replace(/\b\w/g, (match) => match.toUpperCase());
}

function matchesQuery(query: string, ...parts: Array<string | null | undefined>) {
  const normalizedQuery = query.trim().toLowerCase();
  if (!normalizedQuery) {
    return true;
  }

  return parts
    .filter(Boolean)
    .join(" ")
    .toLowerCase()
    .includes(normalizedQuery);
}

function paletteQueryState(query: string): {
  mode: PaletteMode;
  searchQuery: string;
} {
  const trimmed = query.trim();
  if (!trimmed) {
    return { mode: "all", searchQuery: "" };
  }

  const prefix = trimmed[0];
  const searchQuery = trimmed.slice(1).trim();

  if (prefix === ">") {
    return { mode: "commands", searchQuery };
  }
  if (prefix === "%") {
    return { mode: "workspace", searchQuery };
  }
  if (prefix === "@") {
    return { mode: "symbols", searchQuery };
  }
  if (prefix === "?") {
    return { mode: "help", searchQuery };
  }

  return { mode: "all", searchQuery: trimmed };
}

function basename(path: string) {
  const normalized = path.replace(/\\/g, "/");
  const parts = normalized.split("/").filter(Boolean);
  return parts[parts.length - 1] ?? path;
}

function dirname(path: string) {
  const normalized = path.replace(/\\/g, "/");
  const parts = normalized.split("/").filter(Boolean);
  if (parts.length <= 1) {
    return "";
  }
  return parts.slice(0, -1).join("/");
}

function sourceLabelForSkill(skill: SkillCatalogEntry) {
  if (skill.source_type === "starter") {
    return "System";
  }
  if (skill.source_type === "workspace") {
    return "Personal";
  }

  return humanizeLabel(skill.source_type) || "Skill";
}

function sessionLabel(session: SessionSummary) {
  const trimmedTitle = session.title.trim();
  return trimmedTitle.length > 0
    ? trimmedTitle
    : `Session ${session.session_id.slice(0, 8)}`;
}

function sessionWorkspaceLabel(session: SessionSummary) {
  const trimmed = session.workspace_root?.trim();
  if (!trimmed) {
    return null;
  }

  const normalized = trimmed.replace(/\\/g, "/");
  const segments = normalized.split("/").filter(Boolean);
  return segments[segments.length - 1] ?? normalized;
}

function uniqueSessionParts(parts: Array<string | null | undefined>): string[] {
  const seen = new Set<string>();
  const unique: string[] = [];

  parts.forEach((part) => {
    const trimmed = part?.trim();
    if (!trimmed) {
      return;
    }
    const key = trimmed.toLowerCase();
    if (seen.has(key)) {
      return;
    }
    seen.add(key);
    unique.push(trimmed);
  });

  return unique;
}

function sessionResumeContext(session: SessionSummary) {
  const parts = uniqueSessionParts([
    session.phase,
    session.current_step,
    session.resume_hint,
    sessionWorkspaceLabel(session),
  ]);
  return parts.length > 0 ? parts.join(" · ") : null;
}

function connectorStatusRank(status: ConnectorSummary["status"]) {
  switch (status) {
    case "connected":
      return 0;
    case "degraded":
      return 1;
    case "needs_auth":
      return 2;
    case "disabled":
      return 3;
    default:
      return 4;
  }
}

export function CommandPalette({
  activeView,
  workflowSurface,
  currentProjectId,
  notificationCount,
  onClose,
  onOpenPrimaryView,
  onOpenWorkflowSurface,
  onSelectProject,
  projects,
}: CommandPaletteProps) {
  const sessions = useAgentStore((state) => state.sessions);
  const refreshSessionHistory = useAgentStore(
    (state) => state.refreshSessionHistory,
  );
  const [query, setQuery] = useState("");
  const [highlightedItemId, setHighlightedItemId] = useState<string | null>(null);
  const [sessionsStatus, setSessionsStatus] = useState<LoadStatus>("idle");
  const [skillCatalog, setSkillCatalog] = useState<SkillCatalogEntry[]>([]);
  const [skillsStatus, setSkillsStatus] = useState<LoadStatus>("idle");
  const [runtimeCatalogEntries, setRuntimeCatalogEntries] = useState<
    RuntimeCatalogEntry[]
  >([]);
  const [runtimeCatalogStatus, setRuntimeCatalogStatus] =
    useState<LoadStatus>("idle");
  const [liveTools, setLiveTools] = useState<LiveToolRecord[]>([]);
  const [liveToolsStatus, setLiveToolsStatus] = useState<LoadStatus>("idle");
  const [recentFiles, setRecentFiles] = useState<string[]>([]);
  const [fileContextStatus, setFileContextStatus] = useState<LoadStatus>("idle");
  const { mode: paletteMode, searchQuery } = paletteQueryState(query);
  const normalizedQuery = searchQuery.trim().toLowerCase();
  const currentProject = projects.find((project) => project.id === currentProjectId);

  const runAction = useCallback(
    (action: () => void | Promise<void>) => {
      onClose();
      void Promise.resolve(action()).catch((error) => {
        console.error("Failed to execute Chat command palette action:", error);
      });
    },
    [onClose],
  );

  useEffect(() => {
    let cancelled = false;
    setSessionsStatus("loading");

    refreshSessionHistory()
      .then(() => {
        if (!cancelled) {
          setSessionsStatus("ready");
        }
      })
      .catch((error) => {
        console.error("Failed to load session history for command palette:", error);
        if (!cancelled) {
          setSessionsStatus("error");
        }
      });

    return () => {
      cancelled = true;
    };
  }, [refreshSessionHistory]);

  useEffect(() => {
    let cancelled = false;
    setSkillsStatus("loading");

    invoke<SkillCatalogEntry[]>("get_skill_catalog")
      .then((entries) => {
        if (cancelled) {
          return;
        }
        setSkillCatalog(entries);
        setSkillsStatus("ready");
      })
      .catch((error) => {
        console.error("Failed to load Chat command palette skills:", error);
        if (!cancelled) {
          setSkillsStatus("error");
        }
      });

    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    let cancelled = false;
    const runtime = getSessionWorkbenchRuntime();
    setRuntimeCatalogStatus("loading");

    runtime
      .getRuntimeCatalogEntries()
      .then((entries) => {
        if (cancelled) {
          return;
        }
        setRuntimeCatalogEntries(entries);
        setRuntimeCatalogStatus("ready");
      })
      .catch((error) => {
        console.error(
          "Failed to load runtime catalog entries for Chat command palette:",
          error,
        );
        if (!cancelled) {
          setRuntimeCatalogStatus("error");
        }
      });

    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    const runtime = getSessionWorkbenchRuntime();
    if (!runtime.getConnectors || !runtime.getConnectorActions) {
      setLiveToolsStatus("ready");
      return;
    }

    let cancelled = false;
    setLiveToolsStatus("loading");

    runtime
      .getConnectors()
      .then(async (connectors) => {
        const sortedConnectors = [...connectors].sort((left, right) => {
          const statusDelta =
            connectorStatusRank(left.status) - connectorStatusRank(right.status);
          if (statusDelta !== 0) {
            return statusDelta;
          }
          return left.name.localeCompare(right.name);
        });

        const actionGroups = await Promise.all(
          sortedConnectors.map(async (connector) => {
            try {
              const actions = await runtime.getConnectorActions?.(connector.id);
              return (actions ?? []).map<LiveToolRecord>((action) => ({
                connector,
                action,
              }));
            } catch (error) {
              console.error(
                `Failed to load connector actions for Chat command palette: ${connector.id}`,
                error,
              );
              return [];
            }
          }),
        );

        if (cancelled) {
          return;
        }

        setLiveTools(
          actionGroups.flat().sort((left, right) => {
            const connectorDelta =
              connectorStatusRank(left.connector.status) -
              connectorStatusRank(right.connector.status);
            if (connectorDelta !== 0) {
              return connectorDelta;
            }
            return left.action.label.localeCompare(right.action.label);
          }),
        );
        setLiveToolsStatus("ready");
      })
      .catch((error) => {
        console.error("Failed to load Chat live tools:", error);
        if (!cancelled) {
          setLiveToolsStatus("error");
        }
      });

    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    let cancelled = false;
    setFileContextStatus("loading");

    getSessionFileContext({ workspaceRoot: currentProject?.rootPath ?? null })
      .then((context) => {
        if (cancelled) {
          return;
        }
        setRecentFiles(context.recent_files);
        setFileContextStatus("ready");
      })
      .catch((error) => {
        console.error("Failed to load recent files for command palette:", error);
        if (!cancelled) {
          setFileContextStatus("error");
        }
      });

    return () => {
      cancelled = true;
    };
  }, [currentProject?.rootPath]);

  const sections = useMemo<CommandPaletteSection[]>(() => {
    const focusHomeStep = (stepId: string) => {
      window.dispatchEvent(
        new CustomEvent(HOME_ONBOARDING_FOCUS_EVENT, {
          detail: { stepId },
        }),
      );
    };

    const homeOnboardingIcon = (stepId: string) => {
      if (stepId.includes("workspace") || stepId.includes("project")) {
        return icons.code;
      }
      if (stepId.includes("policy")) {
        return icons.lock;
      }
      if (stepId.includes("runtime") || stepId.includes("appearance")) {
        return icons.settings;
      }
      if (stepId.includes("evidence")) {
        return icons.check;
      }
      return icons.sparkles;
    };

    const homeOnboardingItems: CommandPaletteItem[] = AUTOPILOT_ONBOARDING_STEPS.map(
      (step) => ({
        id: `home-onboarding-${step.id}`,
        title: step.primaryAction.commandPaletteLabel,
        description: step.body,
        meta: step.familyId === "accessibility" ? "Onboarding · Indexed" : "Onboarding",
        icon: homeOnboardingIcon(step.id),
        onSelect: () =>
          runAction(() => {
            onOpenPrimaryView("home");
            window.setTimeout(() => focusHomeStep(step.id), 50);
          }),
      }),
    );

    const quickPickItems: CommandPaletteItem[] = [
      {
        id: "quick-go-file",
        title: "Go to File",
        description: "Open the workspace file surface.",
        meta: currentProject?.name ?? "Workspace",
        shortcut: ["Ctrl", "P"],
        icon: icons.search,
        onSelect: () =>
          runAction(() => {
            onOpenPrimaryView("workspace");
          }),
      },
      {
        id: "quick-show-commands",
        title: "Show and Run Commands",
        description: "Filter this picker to actions and shell commands.",
        suffix: ">",
        shortcut: ["Ctrl", "Shift", "P"],
        icon: icons.settings,
        onSelect: () => setQuery(">"),
      },
      {
        id: "quick-search-text",
        title: "Search for Text",
        description: "Open workspace search and file context.",
        suffix: "%",
        icon: icons.search,
        onSelect: () => setQuery("%"),
      },
      {
        id: "quick-open-chat",
        title: "Open Quick Chat",
        description: "Jump to the agent conversation surface.",
        shortcut: ["Ctrl", "Shift", "Alt", "L"],
        icon: icons.sparkles,
        onSelect: () =>
          runAction(() => {
            onOpenPrimaryView("chat");
          }),
      },
      {
        id: "quick-go-workflow",
        title: "Go to Workflow",
        description: "Jump to workflow surfaces and graph topology.",
        suffix: "@",
        icon: icons.sidebar,
        onSelect: () => setQuery("@"),
      },
      {
        id: "quick-run-task",
        title: "Run Task",
        description: "Open execution supervision.",
        icon: icons.history,
        active: activeView === "runs",
        onSelect: () =>
          runAction(() => {
            onOpenPrimaryView("runs");
          }),
      },
      {
        id: "quick-more",
        title: "More",
        description: "Show palette prefixes and navigation help.",
        suffix: "?",
        icon: icons.chevron,
        onSelect: () => setQuery("?"),
      },
    ];

    const commandItems: CommandPaletteItem[] = [
      {
        id: "open-home",
        title: "Open Home",
        description:
          "Open first-run onboarding, project scope, runtime health, and next actions.",
        meta: "Home",
        icon: icons.laptop,
        active: activeView === "home",
        onSelect: () =>
          runAction(() => {
            onOpenPrimaryView("home");
          }),
      },
      {
        id: "open-chat-copilot",
        title: "Open Copilot",
        description: "Jump back to the Chat workbench and operator surface.",
        meta: "Chat",
        icon: icons.sparkles,
        active: activeView === "chat",
        onSelect: () =>
          runAction(() => {
            onOpenPrimaryView("chat");
          }),
      },
      {
        id: "open-canvas",
        title: "Open Canvas",
        description: "Jump straight into the workflow graph editor.",
        meta: "Workflows",
        icon: icons.expand,
        active: activeView === "workflows" && workflowSurface === "canvas",
        onSelect: () =>
          runAction(() => {
            onOpenWorkflowSurface("canvas");
          }),
      },
      {
        id: "open-workflow-home",
        title: "Open Workflow Home",
        description: "Review workflow entrypoints, graph posture, and builder lanes.",
        meta: "Workflows",
        icon: icons.sidebar,
        active: activeView === "workflows" && workflowSurface === "home",
        onSelect: () =>
          runAction(() => {
            onOpenWorkflowSurface("home");
          }),
      },
      {
        id: "open-agents",
        title: "Open Agents",
        description: "Review the live worker roster and agent definitions.",
        meta: "Roster",
        icon: icons.code,
        active: activeView === "workflows" && workflowSurface === "agents",
        onSelect: () =>
          runAction(() => {
            onOpenWorkflowSurface("agents");
          }),
      },
      {
        id: "open-catalog",
        title: "Open Catalog",
        description: "Inspect the live runtime catalog from Chat.",
        meta: "Catalog",
        icon: icons.globe,
        active: activeView === "workflows" && workflowSurface === "catalog",
        onSelect: () =>
          runAction(() => {
            onOpenWorkflowSurface("catalog");
          }),
      },
      {
        id: "open-runs",
        title: "Open Runs",
        description: "Inspect the fleet and execution supervision surfaces.",
        meta: "Runs",
        icon: icons.history,
        active: activeView === "runs",
        onSelect: () =>
          runAction(() => {
            onOpenPrimaryView("runs");
          }),
      },
      {
        id: "open-model-mounts",
        title: "Open Model Mounts",
        description: "Open the model mounting surface.",
        meta: "Mounts",
        icon: icons.cube,
        active: activeView === "mounts",
        onSelect: () =>
          runAction(() => {
            onOpenPrimaryView("mounts");
          }),
      },
      {
        id: "open-inbox",
        title: "Open Inbox",
        description: "Review the shared operator queue and pending actions.",
        meta: notificationCount > 0 ? `${notificationCount}` : "Queue",
        icon: icons.lock,
        active: activeView === "inbox",
        onSelect: () =>
          runAction(() => {
            onOpenPrimaryView("inbox");
          }),
      },
      {
        id: "open-capabilities",
        title: "Open Capabilities",
        description: "Inspect live connectors, extensions, and tools.",
        meta: "Capabilities",
        icon: icons.cube,
        active: activeView === "capabilities",
        onSelect: () =>
          runAction(() => {
            onOpenPrimaryView("capabilities");
          }),
      },
      {
        id: "open-policy",
        title: "Open Policy",
        description: "Jump to Shield policy and connector governance posture.",
        meta: "Governance",
        icon: icons.lock,
        active: activeView === "policy",
        onSelect: () =>
          runAction(() => {
            onOpenPrimaryView("policy");
          }),
      },
      {
        id: "open-settings",
        title: "Open Settings",
        description: "Adjust profile, models, and control-plane settings.",
        meta: "Settings",
        icon: icons.settings,
        active: activeView === "settings",
        onSelect: () =>
          runAction(() => {
            onOpenPrimaryView("settings");
          }),
      },
      {
        id: "open-chat-shell",
        title: "Open Chat",
        description: "Bring the primary session shell to the front.",
        meta: "Primary shell",
        icon: icons.search,
        onSelect: () =>
          runAction(async () => {
            await openCurrentChatShellSession();
          }),
      },
      {
        id: "new-chat-session",
        title: "New Chat Session",
        description: "Reset the shared session controller and open a fresh thread.",
        meta: "Chat",
        icon: icons.plus,
        onSelect: () =>
          runAction(async () => {
            await openNewChatShellSession();
          }),
      },
      {
        id: "open-queue-shell",
        title: "Open Queue",
        description: "Open the compact Gate shell for approvals and interventions.",
        meta: "Gate",
        icon: icons.alert,
        onSelect: () =>
          runAction(async () => {
            await openCompanionGate();
          }),
      },
    ].filter((item) =>
      matchesQuery(
        normalizedQuery,
        item.title,
        item.description,
        item.meta,
        "chat queue workers approvals catalog inbox capabilities settings primary shell session",
      ),
    );
    const workflowJumpItems = commandItems.filter((item) =>
      [
        "open-canvas",
        "open-workflow-home",
        "open-agents",
        "open-catalog",
      ].includes(item.id),
    );

    const sessionItems: CommandPaletteItem[] =
      sessionsStatus === "loading"
        ? [
            {
              id: "sessions-loading",
              title: "Loading Sessions",
              description: "Fetching saved operator threads...",
              icon: icons.history,
              disabled: true,
            },
          ]
        : sessionsStatus === "error"
          ? [
              {
                id: "sessions-error",
                title: "Session History Unavailable",
                description: "The live session controller could not load saved threads.",
                icon: icons.alert,
                disabled: true,
              },
            ]
          : [...sessions]
              .sort((left, right) => right.timestamp - left.timestamp)
              .filter((session) =>
                matchesQuery(
                  normalizedQuery,
                  sessionLabel(session),
                  session.session_id,
                  session.phase,
                  session.current_step,
                  session.resume_hint,
                  session.workspace_root,
                  formatSessionTimeAgo(session.timestamp),
                  "recent session resume chat thread history",
                ),
              )
              .slice(0, 8)
              .map<CommandPaletteItem>((session) => {
                const sessionContext = sessionResumeContext(session);
                return {
                  id: `session-${session.session_id}`,
                  title: sessionLabel(session),
                  description: sessionContext
                    ? `Resume ${sessionContext} in Chat.`
                    : `Resume session ${session.session_id.slice(0, 8)} in Chat.`,
                  meta: formatSessionTimeAgo(session.timestamp),
                  icon: icons.history,
                  onSelect: () =>
                    runAction(async () => {
                      await openChatShellSession(session.session_id);
                    }),
                };
              });

    const projectItems = [...projects]
      .sort((left, right) => {
        if (left.id === currentProjectId) {
          return -1;
        }
        if (right.id === currentProjectId) {
          return 1;
        }
        return left.name.localeCompare(right.name);
      })
      .filter((project) =>
        matchesQuery(
          normalizedQuery,
          project.name,
          project.description,
          project.environment,
          project.rootPath,
          "project workspace scope",
        ),
      )
      .map<CommandPaletteItem>((project) => ({
        id: `project-${project.id}`,
        title: project.name,
        description: `${project.description} Root: ${project.rootPath}.`,
        meta: project.environment,
        icon: icons.laptop,
        active: project.id === currentProjectId,
        onSelect: () =>
          runAction(() => {
            onSelectProject(project.id);
          }),
      }));

    const runtimeCatalogItems: CommandPaletteItem[] =
      runtimeCatalogStatus === "loading"
        ? [
            {
              id: "catalog-loading",
              title: "Loading Runtime Catalog",
              description: "Fetching live runtime catalog entries...",
              icon: icons.globe,
              disabled: true,
            },
          ]
        : runtimeCatalogStatus === "error"
          ? [
              {
                id: "catalog-error",
                title: "Catalog Unavailable",
                description: "Open the catalog surface to inspect runtime posture.",
                icon: icons.alert,
                onSelect: () =>
                  runAction(() => {
                    onOpenWorkflowSurface("catalog");
                  }),
              },
            ]
          : runtimeCatalogEntries
              .filter((entry) =>
                matchesQuery(
                  normalizedQuery,
                  entry.name,
                  entry.description,
                  entry.ownerLabel,
                  entry.entryKind,
                  entry.runtimeNotes,
                  entry.statusLabel,
                  "runtime catalog",
                ),
              )
              .slice(0, 8)
              .map<CommandPaletteItem>((entry) => ({
                id: `catalog-${entry.id}`,
                title: entry.name,
                description: entry.description || entry.runtimeNotes,
                meta:
                  entry.statusLabel ||
                  humanizeLabel(entry.entryKind) ||
                  "Catalog entry",
                icon: icons.globe,
                onSelect: () =>
                  runAction(() => {
                    onOpenWorkflowSurface("catalog");
                  }),
              }));

    const liveToolItems: CommandPaletteItem[] =
      liveToolsStatus === "loading"
        ? [
            {
              id: "live-tools-loading",
              title: "Loading Live Tools",
              description: "Querying connector-backed tool affordances...",
              icon: icons.code,
              disabled: true,
            },
          ]
        : liveToolsStatus === "error"
          ? [
              {
                id: "live-tools-error",
                title: "Live Tools Unavailable",
                description: "Open Capabilities to inspect connector posture.",
                icon: icons.alert,
                onSelect: () =>
                  runAction(() => {
                    onOpenPrimaryView("capabilities");
                  }),
              },
            ]
          : liveTools
              .filter(({ connector, action }) =>
                matchesQuery(
                  normalizedQuery,
                  action.label,
                  action.description,
                  action.toolName,
                  action.service,
                  action.serviceLabel,
                  action.kind,
                  connector.name,
                  connector.provider,
                  connector.status,
                  "tool connector capability action",
                ),
              )
              .slice(0, 10)
              .map<CommandPaletteItem>(({ connector, action }) => ({
                id: `tool-${connector.id}-${action.id}`,
                title: action.label,
                description:
                  action.description ||
                  `${connector.name} exposes this ${humanizeLabel(action.kind).toLowerCase()} action.`,
                meta: connector.name,
                icon: icons.code,
                onSelect: () =>
                  runAction(async () => {
                    await openCompanionCapabilityActions(connector.id);
                  }),
              }));

    const sortedSkills = [...skillCatalog].sort((left, right) => {
      if (left.stale !== right.stale) {
        return Number(left.stale) - Number(right.stale);
      }
      if (left.success_rate_bps !== right.success_rate_bps) {
        return right.success_rate_bps - left.success_rate_bps;
      }
      if (left.sample_size !== right.sample_size) {
        return right.sample_size - left.sample_size;
      }
      return left.name.localeCompare(right.name);
    });

    const skillItems: CommandPaletteItem[] =
      skillsStatus === "loading"
        ? [
            {
              id: "skills-loading",
              title: "Loading Skills",
              description: "Fetching runtime skill catalog...",
              icon: icons.sparkles,
              disabled: true,
            },
          ]
        : skillsStatus === "error"
          ? [
              {
                id: "skills-error",
                title: "Skills Unavailable",
                description: "The runtime skill catalog could not be loaded.",
                icon: icons.alert,
                disabled: true,
              },
            ]
          : sortedSkills
              .filter((skill) =>
                matchesQuery(
                  normalizedQuery,
                  skill.name,
                  skill.description,
                  skill.definition?.description,
                  skill.source_type,
                  skill.lifecycle_state,
                ),
              )
              .slice(0, 10)
              .map<CommandPaletteItem>((skill) => ({
                id: `skill-${skill.skill_hash}`,
                title: skill.name,
                description:
                  skill.description ||
                  skill.definition?.description ||
                  "Seed this skill into the Chat workbench.",
                meta: sourceLabelForSkill(skill),
                icon: icons.sparkles,
                onSelect: () =>
                  runAction(async () => {
                    onOpenPrimaryView("chat");
                    await openCompanionAutopilotIntent(
                      `Use the ${skill.name} skill for this request. `,
                    );
                  }),
              }));

    const onboardingItems = homeOnboardingItems.filter((item) =>
      matchesQuery(normalizedQuery, item.title, item.description, item.meta),
    );
    const recentFileItems: CommandPaletteItem[] =
      fileContextStatus === "loading"
        ? [
            {
              id: "recent-files-loading",
              title: "Loading Recent Files",
              description: "Fetching workspace file context...",
              icon: icons.history,
              disabled: true,
            },
          ]
        : recentFiles
            .filter((path) =>
              matchesQuery(
                normalizedQuery,
                path,
                basename(path),
                dirname(path),
                "recently opened file workspace",
              ),
            )
            .slice(0, 8)
            .map<CommandPaletteItem>((path) => ({
              id: `recent-file-${path}`,
              title: basename(path),
              description: dirname(path) || currentProject?.name || "Recent file",
              meta: "recently opened",
              icon: icons.code,
              onSelect: () =>
                runAction(() => {
                  onOpenPrimaryView("workspace");
                }),
            }));
    const workspaceItems: CommandPaletteItem[] = [
      {
        id: "open-workspace-search",
        title: "Open Workspace Search",
        description: "Search code, files, and retained project context.",
        meta: currentProject?.name ?? "Workspace",
        icon: icons.search,
        onSelect: () =>
          runAction(() => {
            onOpenPrimaryView("workspace");
          }),
      },
      {
        id: "open-files",
        title: "Open Files",
        description: "Browse the current workspace and recent file context.",
        meta: currentProject?.rootPath ?? "Workspace",
        icon: icons.laptop,
        onSelect: () =>
          runAction(() => {
            onOpenPrimaryView("workspace");
          }),
      },
    ].filter((item) =>
      matchesQuery(normalizedQuery, item.title, item.description, item.meta),
    );
    const helpItems: CommandPaletteItem[] = [
      {
        id: "help-prefix-commands",
        title: "Type > to run commands",
        description: "Filter the picker to application commands.",
        meta: "prefix",
        icon: icons.settings,
        onSelect: () => setQuery(">"),
      },
      {
        id: "help-prefix-files",
        title: "Type % to search workspace text",
        description: "Open workspace search and file context.",
        meta: "prefix",
        icon: icons.search,
        onSelect: () => setQuery("%"),
      },
      {
        id: "help-prefix-workflows",
        title: "Type @ to jump to workflows",
        description: "Focus workflow and autonomous-system authoring surfaces.",
        meta: "prefix",
        icon: icons.sidebar,
        onSelect: () => setQuery("@"),
      },
      {
        id: "help-escape",
        title: "Press Esc to close",
        description: "The palette does not change runtime state until a row is selected.",
        meta: "keyboard",
        icon: icons.close,
        disabled: true,
      },
    ].filter((item) =>
      matchesQuery(normalizedQuery, item.title, item.description, item.meta),
    );
    const recentlyOpenedItems = [
      ...recentFileItems,
      ...projectItems.slice(0, 4),
      ...sessionItems.slice(0, 4),
    ].slice(0, 10);

    if (!query.trim()) {
      return [
        { id: "quick-pick", items: quickPickItems },
        {
          id: "recently-opened",
          title: "Recently opened",
          items: recentlyOpenedItems,
        },
      ];
    }

    if (paletteMode === "commands") {
      return [
        { id: "commands", items: commandItems },
        { id: "onboarding", title: "Onboarding", items: onboardingItems },
      ];
    }

    if (paletteMode === "workspace") {
      return [
        { id: "workspace", items: workspaceItems },
        { id: "recent-files", title: "Recent files", items: recentFileItems },
        { id: "projects", title: "Projects", items: projectItems },
      ];
    }

    if (paletteMode === "symbols") {
      return [
        { id: "workflows", items: workflowJumpItems },
        { id: "projects", title: "Projects", items: projectItems },
      ];
    }

    if (paletteMode === "help") {
      return [
        { id: "help", items: helpItems },
        { id: "commands", title: "Commands", items: commandItems },
      ];
    }

    return [
      { id: "commands", items: commandItems },
      { id: "recent-files", title: "Recent files", items: recentFileItems },
      { id: "sessions", title: "Recent Sessions", items: sessionItems },
      { id: "projects", title: "Projects", items: projectItems },
      { id: "live-tools", title: "Live Tools", items: liveToolItems },
      { id: "runtime-catalog", title: "Runtime Catalog", items: runtimeCatalogItems },
      { id: "skills", title: "Skills", items: skillItems },
      { id: "onboarding", title: "Onboarding", items: onboardingItems },
    ];
  }, [
    activeView,
    currentProject?.name,
    currentProject?.rootPath,
    currentProjectId,
    fileContextStatus,
    liveTools,
    liveToolsStatus,
    normalizedQuery,
    notificationCount,
    onOpenPrimaryView,
    onOpenWorkflowSurface,
    onSelectProject,
    projects,
    runAction,
    runtimeCatalogEntries,
    runtimeCatalogStatus,
    paletteMode,
    query,
    recentFiles,
    sessions,
    sessionsStatus,
    skillCatalog,
    skillsStatus,
    workflowSurface,
  ]);

  const actionItems = useMemo(
    () =>
      sections.flatMap((section) =>
        section.items.filter((item) => item.onSelect && !item.disabled),
      ),
    [sections],
  );

  useEffect(() => {
    if (actionItems.length === 0) {
      setHighlightedItemId(null);
      return;
    }

    setHighlightedItemId((current) =>
      current && actionItems.some((item) => item.id === current)
        ? current
        : actionItems[0]?.id ?? null,
    );
  }, [actionItems]);

  const handleKeyDown = useCallback(
    (event: ReactKeyboardEvent<HTMLInputElement>) => {
      if (event.key === "Escape") {
        event.preventDefault();
        onClose();
        return;
      }

      if (event.key === "ArrowDown" || event.key === "ArrowUp") {
        event.preventDefault();
        if (actionItems.length === 0) {
          return;
        }

        const currentIndex = Math.max(
          0,
          actionItems.findIndex((item) => item.id === highlightedItemId),
        );
        const delta = event.key === "ArrowDown" ? 1 : -1;
        const nextIndex = (currentIndex + delta + actionItems.length) % actionItems.length;
        setHighlightedItemId(actionItems[nextIndex]?.id ?? null);
        return;
      }

      if (event.key === "Enter" && !event.shiftKey) {
        const selectedItem =
          actionItems.find((item) => item.id === highlightedItemId) ??
          actionItems[0];
        if (!selectedItem?.onSelect) {
          return;
        }

        event.preventDefault();
        selectedItem.onSelect();
      }
    },
    [actionItems, highlightedItemId, onClose],
  );

  const visibleSections = sections.filter((section) => section.items.length > 0);
  const emptyState =
    query.trim().length > 0
      ? `No Autopilot commands match "${query}".`
      : "No Autopilot commands available right now.";

  return (
    <div className="command-palette-overlay" onClick={onClose}>
      <div
        className="command-palette-shell"
        onClick={(event) => event.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-label="Command palette"
      >
        <label className="command-palette-search" aria-label="Search command palette">
          <input
            autoFocus
            className="command-palette-search-input"
            onChange={(event) => setQuery(event.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Search files by name (append : to go to line or @ to go to symbol)"
            type="text"
            value={query}
          />
        </label>

        <div className="command-palette-results" role="listbox">
          {visibleSections.length > 0 ? (
            visibleSections.map((section) => (
              <section className="command-palette-section" key={section.id}>
                {section.title ? (
                  <div className="command-palette-section-label">{section.title}</div>
                ) : null}

                {section.items.map((item) => {
                  const selected = highlightedItemId === item.id;
                  const actionable = item.onSelect && !item.disabled;
                  const RowElement = actionable ? "button" : "div";

                  return (
                    <RowElement
                      key={item.id}
                      className={`command-palette-row ${
                        selected ? "is-selected" : ""
                      } ${item.active ? "is-active" : ""} ${
                        item.disabled ? "is-disabled" : ""
                      }`}
                      data-command-palette-item-id={item.id}
                      onClick={
                        actionable
                          ? (event) => {
                              event.stopPropagation();
                              item.onSelect?.();
                            }
                          : undefined
                      }
                      onMouseEnter={
                        actionable ? () => setHighlightedItemId(item.id) : undefined
                      }
                      role="option"
                      aria-selected={selected}
                      type={actionable ? "button" : undefined}
                    >
                      {item.icon ? (
                        <span className="command-palette-row-icon" aria-hidden="true">
                          {item.icon}
                        </span>
                      ) : null}
                      <span className="command-palette-row-copy">
                        <span className="command-palette-row-title">
                          {item.title}
                          {item.suffix ? (
                            <span className="command-palette-row-suffix">
                              {" "}
                              {item.suffix}
                            </span>
                          ) : null}
                        </span>
                        {item.description ? (
                          <span className="command-palette-row-description">
                            {item.description}
                          </span>
                        ) : null}
                      </span>
                      {item.meta ? (
                        <span className="command-palette-row-meta">{item.meta}</span>
                      ) : null}
                      {item.shortcut ? (
                        <span className="command-palette-shortcut">
                          {item.shortcut.map((key, index) => (
                            <span className="command-palette-shortcut-part" key={key}>
                              {index > 0 ? (
                                <span className="command-palette-shortcut-plus">
                                  +
                                </span>
                              ) : null}
                              <span className="command-palette-shortcut-key">
                                {key}
                              </span>
                            </span>
                          ))}
                        </span>
                      ) : null}
                    </RowElement>
                  );
                })}
              </section>
            ))
          ) : (
            <div className="command-palette-empty">{emptyState}</div>
          )}
        </div>
      </div>
    </div>
  );
}
