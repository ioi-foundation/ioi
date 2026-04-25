import { formatSessionTimeAgo } from "@ioi/agent-ide";
import type { DropdownOption } from "../../../components/ui/Dropdown";
import type { CommandMenuItem } from "../../../components/ui/CommandMenu";
import { icons } from "../../../components/ui/icons";
import {
  matchesSlashQuery,
  sessionLabel,
  sessionResumeContext,
  workspaceRootFromTask,
} from "./chatInputHelpers";
import type { AgentTask, SessionSummary } from "../../../types";
import type { WorkspaceWorkflowSummary } from "../../../services/TauriRuntime";

export function buildSharedSessionCommandItems({
  commandQuery,
  hasBranchSurface,
  sessions,
  hasSessionContext,
  hasPermissionRequest,
  hasReplSurface,
  task,
  mcpContributionCount,
  capabilityRegistryStatus,
  capabilityRegistryExtensionCount,
  hookContributionCount,
  hasRewindSurface,
  planMode,
  vimModeLabel,
  hasWorkerContext,
  workerCount,
  hasFileSurface,
  hasArtifacts,
  artifactCount,
  dismissCommandSurface,
  onOpenView,
  onOpenValidationEvidence,
  onOpenSettings,
  onTogglePlanMode,
}: {
  commandQuery: string;
  hasBranchSurface: boolean;
  sessions: SessionSummary[];
  hasSessionContext: boolean;
  hasPermissionRequest: boolean;
  hasReplSurface: boolean;
  task: AgentTask | null;
  mcpContributionCount: number;
  capabilityRegistryStatus: string;
  capabilityRegistryExtensionCount: number;
  hookContributionCount: number;
  hasRewindSurface: boolean;
  planMode: boolean;
  vimModeLabel: string;
  hasWorkerContext: boolean;
  workerCount: number;
  hasFileSurface: boolean;
  hasArtifacts: boolean;
  artifactCount: number;
  dismissCommandSurface: (refocusComposer?: boolean) => void;
  onOpenView: (view: any) => void;
  onOpenValidationEvidence: () => void;
  onOpenSettings: () => void;
  onTogglePlanMode: (nextValue?: boolean) => void;
}): CommandMenuItem[] {
  const items: CommandMenuItem[] = [
    {
      id: "open-branches",
      title: "Manage Branches",
      description:
        "Inspect the current branch, upstream posture, dirty checkout state, and recent local branches.",
      meta: hasBranchSurface ? "Git" : "Unavailable",
      icon: icons.history,
      disabled: !hasBranchSurface,
      onSelect: hasBranchSurface
        ? () => {
            dismissCommandSurface(false);
            onOpenView("branch");
          }
        : undefined,
    },
    {
      id: "open-commit",
      title: "Commit Changes",
      description:
        "Stage, unstage, discard, and commit the current checkout from the shared source-control projection.",
      meta: hasBranchSurface ? "Source control" : "Unavailable",
      icon: icons.check,
      disabled: !hasBranchSurface,
      onSelect: hasBranchSurface
        ? () => {
            dismissCommandSurface(false);
            onOpenView("commit");
          }
        : undefined,
    },
    {
      id: "open-mobile",
      title: "Resume Mobile Handoff",
      description:
        "Review native reply/prep handoffs, retained evidence threads, and cross-shell continuity shortcuts.",
      meta: sessions.length > 0 ? `${sessions.length} retained sessions` : "Runtime-backed",
      icon: icons.laptop,
      onSelect: () => {
        dismissCommandSurface(false);
        onOpenView("mobile");
      },
    },
    {
      id: "open-voice",
      title: "Transcribe Voice Note",
      description:
        "Transcribe an audio clip through the shared runtime and seed the transcript back into the composer.",
      meta: "Transcription",
      icon: icons.sparkles,
      onSelect: () => {
        dismissCommandSurface(false);
        onOpenView("voice");
      },
    },
    {
      id: "open-server",
      title: "Inspect Server Mode",
      description:
        "Inspect the kernel RPC target, remote session merge posture, and server-backed continuity state for this shell.",
      meta: "Continuity",
      icon: icons.code,
      onSelect: () => {
        dismissCommandSurface(false);
        onOpenView("server");
      },
    },
    {
      id: "open-pr-comments",
      title: "Draft PR Comments",
      description:
        "Draft reviewer-facing status, review-ready, and follow-up comments from shared plan, source-control, and evidence state.",
      meta: hasBranchSurface ? "Review handoff" : "Runtime-backed",
      icon: icons.copy,
      onSelect: () => {
        dismissCommandSurface(false);
        onOpenView("pr_comments");
      },
    },
    {
      id: "open-review",
      title: "Run Review",
      description:
        "Review run readiness, reviewer handoff, privacy posture, and promotion flow from one shared workflow hub.",
      meta: hasSessionContext
        ? hasPermissionRequest
          ? "Needs review"
          : "Workflow hub"
        : "Runtime-backed",
      icon: icons.check,
      onSelect: () => {
        dismissCommandSurface(false);
        onOpenView("review");
      },
    },
    {
      id: "open-repl",
      title: "Resume in Terminal",
      description:
        "Attach a PTY-backed runtime console to the current or a recent canonical session workspace.",
      meta: hasReplSurface
        ? workspaceRootFromTask(task)
          ? "Live root"
          : `${sessions.length} retained sessions`
        : "Unavailable",
      icon: icons.code,
      disabled: !hasReplSurface,
      onSelect: hasReplSurface
        ? () => {
            dismissCommandSurface(false);
            onOpenView("repl");
          }
        : undefined,
    },
    {
      id: "open-remote-env",
      title: "Inspect Runtime Env",
      description:
        "Inspect the effective runtime and shell environment posture for this session.",
      meta: "Runtime",
      icon: icons.code,
      onSelect: () => {
        dismissCommandSurface(false);
        onOpenView("remote_env");
      },
    },
    {
      id: "open-mcp",
      title: "Inspect MCP",
      description:
        "Inspect governed MCP bridge packages, trust posture, and capability-registry-backed server contributions.",
      meta:
        mcpContributionCount > 0
          ? `${mcpContributionCount} bridge server${mcpContributionCount === 1 ? "" : "s"}`
          : capabilityRegistryStatus === "loading"
            ? "Loading"
            : "Bridge surface",
      icon: icons.code,
      onSelect: () => {
        dismissCommandSurface(false);
        onOpenView("mcp");
      },
    },
    {
      id: "open-plugins",
      title: "Manage Plugins",
      description:
        "Inspect manifest-backed plugins, governing source posture, and reloadability.",
      meta:
        capabilityRegistryExtensionCount > 0
          ? `${capabilityRegistryExtensionCount} installed`
          : capabilityRegistryStatus === "loading"
            ? "Loading"
            : "Extensions",
      icon: icons.cube,
      onSelect: () => {
        dismissCommandSurface(false);
        onOpenView("plugins");
      },
    },
    {
      id: "open-doctor",
      title: "Run Diagnostics",
      description:
        "Review kernel-backed runtime health, authority posture, durability, and extension conformance in one drawer.",
      meta: "Diagnostics",
      icon: icons.alert,
      onSelect: () => {
        dismissCommandSurface(false);
        onOpenView("doctor");
      },
    },
    {
      id: "open-export",
      title: "Export Evidence",
      description:
        "Review the canonical trace bundle export surface and export the active session evidence pack.",
      meta: hasSessionContext ? "Bundle" : "Unavailable",
      icon: icons.code,
      disabled: !hasSessionContext,
      onSelect: hasSessionContext
        ? () => {
            dismissCommandSurface(false);
            onOpenView("export");
          }
        : undefined,
    },
    {
      id: "open-share",
      title: "Share Evidence",
      description:
        "Package the active session as a local evidence pack or redacted review pack without leaving the canonical trace path.",
      meta: hasSessionContext ? "Evidence pack" : "Unavailable",
      icon: icons.externalLink,
      disabled: !hasSessionContext,
      onSelect: hasSessionContext
        ? () => {
            dismissCommandSurface(false);
            onOpenView("share");
          }
        : undefined,
    },
    {
      id: "open-vim-mode",
      title: "Review Vim Mode",
      description:
        "Review the current editor input posture and toggle the vim-style preview mode.",
      meta: vimModeLabel,
      icon: icons.code,
      onSelect: () => {
        dismissCommandSurface(false);
        onOpenView("vim");
      },
    },
    {
      id: "open-keybindings",
      title: "Inspect Keybindings",
      description:
        "Review the active keyboard shortcuts for Chat, Chat, and the global launcher.",
      meta: "Shortcuts",
      icon: icons.search,
      onSelect: () => {
        dismissCommandSurface(false);
        onOpenView("keybindings");
      },
    },
    {
      id: "open-hooks",
      title: "Inspect Hooks",
      description:
        "Inspect runtime-visible hook contributions, governing sources, and recent hook receipts.",
      meta:
        hookContributionCount > 0
          ? `${hookContributionCount} hooks`
          : capabilityRegistryStatus === "loading"
            ? "Loading"
            : "Policy",
      icon: icons.sparkles,
      onSelect: () => {
        dismissCommandSurface(false);
        onOpenView("hooks");
      },
    },
    {
      id: "open-rewind",
      title: "Rewind Session",
      description:
        "Preview retained session checkpoints and rewind shell focus to one of them.",
      meta: hasRewindSurface ? "History" : "Unavailable",
      icon: icons.history,
      disabled: !hasRewindSurface,
      onSelect: hasRewindSurface
        ? () => {
            dismissCommandSurface(false);
            onOpenView("rewind");
          }
        : undefined,
    },
    {
      id: "open-compact",
      title: "Compact Session",
      description:
        "Review retained compaction records and capture a resumable summary for the active session.",
      meta: hasSessionContext ? "Memory" : "Unavailable",
      icon: icons.history,
      disabled: !hasSessionContext,
      onSelect: hasSessionContext
        ? () => {
            dismissCommandSurface(false);
            onOpenView("compact");
          }
        : undefined,
    },
    {
      id: "open-privacy-settings",
      title: "Review Privacy Settings",
      description:
        "Review session privacy posture, redaction handling, and local export boundaries.",
      meta: hasPermissionRequest ? "Pending review" : "Privacy",
      icon: icons.lock,
      onSelect: () => {
        dismissCommandSurface(false);
        onOpenView("privacy");
      },
    },
    {
      id: "open-plan",
      title: "Review Plan",
      description:
        "Open the execution drawer on the runtime plan and session graph.",
      meta: "Drawer",
      icon: icons.sidebar,
      disabled: !hasSessionContext,
      onSelect: hasSessionContext
        ? () => {
            dismissCommandSurface(false);
            onOpenView("active_context");
          }
        : undefined,
    },
    {
      id: "toggle-plan-mode",
      title: planMode ? "Exit Plan Mode" : "Enter Plan Mode",
      description: planMode
        ? "Return the composer to normal execution mode."
        : "Keep the plan drawer in focus and turn submissions into plan-first operator requests.",
      meta: "Mode",
      icon: icons.sidebar,
      onSelect: () => {
        dismissCommandSurface(false);
        onTogglePlanMode(!planMode);
      },
    },
    {
      id: "open-permissions",
      title: "Review Permissions",
      description:
        "Inspect pending approvals, current session grants, and Shield policy posture.",
      meta: hasPermissionRequest ? "Pending request" : "Policy",
      icon: icons.lock,
      onSelect: () => {
        dismissCommandSurface(false);
        onOpenView("permissions");
      },
    },
    {
      id: "open-workers",
      title: "Review Workers",
      description:
        "Review worker cards, receipts, and delegated execution state.",
      meta: hasWorkerContext ? `${workerCount}` : "Unavailable",
      icon: icons.code,
      disabled: !hasWorkerContext,
      onSelect: hasWorkerContext
        ? () => {
            dismissCommandSurface(false);
            onOpenView("thoughts");
          }
        : undefined,
    },
    {
      id: "open-files",
      title: "Inspect Files",
      description:
        "Inspect retained file context, workspace entries, logs, and generated outputs for this session.",
      meta: hasArtifacts ? `${artifactCount} outputs` : "Session",
      icon: icons.cube,
      disabled: !hasFileSurface,
      onSelect: hasFileSurface
        ? () => {
            dismissCommandSurface(false);
            onOpenView("files");
          }
        : undefined,
    },
    {
      id: "open-validation-evidence",
      title: "Review Validation Evidence",
      description:
        "Jump to the latest retained live validation evidence and receipts.",
      meta: "Evidence",
      icon: icons.search,
      onSelect: () => {
        dismissCommandSurface(false);
        onOpenValidationEvidence();
      },
    },
    {
      id: "open-settings",
      title: "Open Settings",
      description: "Manage models, workspaces, and skill sources.",
      icon: icons.settings,
      onSelect: () => {
        dismissCommandSurface(false);
        onOpenSettings();
      },
    },
  ];

  return items.filter((item) =>
    matchesSlashQuery(
      commandQuery,
      item.title,
      item.description,
      item.meta,
      "branch branches git upstream ahead behind checkout worktree dirty clean commit pr comments pull request review comment reviewer handoff stage staged unstage discard source control mobile handoff reply composer meeting prep inbox continuity cross shell retained evidence voice audio microphone mic dictation transcription speech transcript transcribe shared runtime doctor diagnostics health conformance repl cli terminal shell attach resume server mode kernel rpc remote history remote session merge remote continuity remote env environment variables runtime bindings shell process plugin plugins extension extensions marketplace manifest reload conformance export trace bundle replay evidence keybindings shortcuts keyboard hotkeys hooks automation runtime bridge policy rewind history compact compaction memory summary prune long session plan permissions privacy redaction redact telemetry share workers files artifacts approvals receipts evidence validation zip vim vi modal normal insert editor mode plan-first planner strategy execution plan review strategy",
    ),
  );
}

export function buildModelSlashItems({
  modelOptions,
  selectedModel,
  commandQuery,
  onSelectModel,
  dismissCommandSurface,
}: {
  modelOptions: DropdownOption[];
  selectedModel: string;
  commandQuery: string;
  onSelectModel: (value: string) => void;
  dismissCommandSurface: () => void;
}): CommandMenuItem[] {
  return modelOptions
    .filter((option) =>
      matchesSlashQuery(
        commandQuery,
        option.label,
        option.desc,
        "model llm openai anthropic meta",
      ),
    )
    .map<CommandMenuItem>((option) => ({
      id: `model-${option.value}`,
      title: option.label,
      description: option.desc || "Switch active model",
      icon: option.icon ?? icons.cube,
      active: option.value === selectedModel,
      meta: option.value === selectedModel ? "Current" : "Model",
      onSelect: () => {
        onSelectModel(option.value);
        dismissCommandSurface();
      },
    }));
}

export function buildWorkspaceSlashItems({
  workspaceOptions,
  workspaceMode,
  commandQuery,
  onSelectWorkspaceMode,
  dismissCommandSurface,
}: {
  workspaceOptions: DropdownOption[];
  workspaceMode: string;
  commandQuery: string;
  onSelectWorkspaceMode: (value: string) => void;
  dismissCommandSurface: () => void;
}): CommandMenuItem[] {
  return workspaceOptions
    .filter((option) =>
      matchesSlashQuery(commandQuery, option.label, option.desc, "workspace local cloud"),
    )
    .map<CommandMenuItem>((option) => ({
      id: `workspace-${option.value}`,
      title: option.label,
      description: option.desc || "Switch workspace",
      icon: option.icon ?? icons.laptop,
      active: option.value === workspaceMode,
      meta: option.value === workspaceMode ? "Current" : "Workspace",
      onSelect: () => {
        onSelectWorkspaceMode(option.value);
        dismissCommandSurface();
      },
    }));
}

export function buildWorkspaceWorkflowItems({
  workflows,
  commandQuery,
  onSelectWorkflow,
}: {
  workflows: WorkspaceWorkflowSummary[];
  commandQuery: string;
  onSelectWorkflow: (slashCommand: string) => void;
}): CommandMenuItem[] {
  return [...workflows]
    .sort((left, right) => {
      if (left.sourceRank !== right.sourceRank) {
        return left.sourceRank - right.sourceRank;
      }
      return left.workflowId.localeCompare(right.workflowId);
    })
    .filter((workflow) =>
      matchesSlashQuery(
        commandQuery,
        workflow.slashCommand,
        workflow.description,
        workflow.relativePath,
        workflow.sourceRoot,
        workflow.filePath,
        "workflow markdown turbo",
      ),
    )
    .map<CommandMenuItem>((workflow) => ({
      id: `workflow-${workflow.workflowId}`,
      title: `Run ${workflow.slashCommand}`,
      description: workflow.description,
      icon: icons.sparkles,
      meta:
        workflow.stepCount > 0
          ? `${workflow.stepCount} step${workflow.stepCount === 1 ? "" : "s"}`
          : workflow.relativePath,
      onSelect: () => {
        onSelectWorkflow(workflow.slashCommand);
      },
    }));
}

export function buildRecentSessionItems({
  sessions,
  currentSessionId,
  commandQuery,
  dismissCommandSurface,
  onLoadSession,
}: {
  sessions: SessionSummary[];
  currentSessionId: string | null;
  commandQuery: string;
  dismissCommandSurface: (refocusComposer?: boolean) => void;
  onLoadSession: (sessionId: string) => void;
}): CommandMenuItem[] {
  return [...sessions]
    .sort((left, right) => right.timestamp - left.timestamp)
    .filter((session) => session.session_id !== currentSessionId)
    .filter((session) =>
      matchesSlashQuery(
        commandQuery,
        sessionLabel(session),
        session.session_id,
        session.phase,
        session.current_step,
        session.resume_hint,
        session.workspace_root,
        formatSessionTimeAgo(session.timestamp),
        "resume session history thread recent",
      ),
    )
    .slice(0, 6)
    .map<CommandMenuItem>((session) => {
      const sessionContext = sessionResumeContext(session);
      return {
        id: `session-${session.session_id}`,
        title: sessionLabel(session),
        description: sessionContext
          ? `Resume ${sessionContext} and continue the thread.`
          : `Resume session ${session.session_id.slice(0, 8)} and continue the thread.`,
        meta: formatSessionTimeAgo(session.timestamp),
        icon: icons.history,
        onSelect: () => {
          dismissCommandSurface(false);
          onLoadSession(session.session_id);
        },
      };
    });
}
