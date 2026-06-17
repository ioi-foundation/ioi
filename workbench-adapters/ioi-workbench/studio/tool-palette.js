"use strict";

function createStudioToolPalette({
  firstArray,
  quickPickSeparatorKind,
  stringValue,
  themeIcon,
}) {
  function normalizeStudioToolPaletteRows(rows, fallbackSection) {
    return firstArray(rows)
      .map((row, index) => {
        if (!row || typeof row !== "object") {
          return null;
        }
        const title = stringValue(row.title || row.label || row.name, "");
        if (!title) {
          return null;
        }
        return {
          id: stringValue(row.id || row.toolId || row.name, `${fallbackSection}-${index}`),
          title,
          detail: stringValue(row.detail || row.description || row.summary, ""),
          meta: stringValue(row.meta || row.status || row.provider || row.kind, ""),
          enabled: row.enabled !== false,
          selected: Boolean(row.selected),
        };
      })
      .filter(Boolean);
  }

  function studioToolPaletteSections(state = {}) {
    const liveRows = normalizeStudioToolPaletteRows(
      state.commandCenter?.liveTools || state.tools?.live || state.liveTools,
      "live",
    );
    const runtimeRows = normalizeStudioToolPaletteRows(
      state.commandCenter?.runtimeCatalog || state.runtimeCatalog?.tools || state.tools?.runtime,
      "runtime",
    );
    const substrateToolRows = [
      {
        id: "agent",
        title: "agent",
        detail: "Delegate tasks to other agents",
        meta: "Built-In",
        icon: "code",
        selected: true,
      },
      {
        id: "awaitTerminal",
        title: "awaitTerminal",
        detail: "Wait for a background terminal command to complete. Returns the output, exit code, and runtime state.",
        icon: "terminal",
        selected: true,
      },
      {
        id: "createAndRunTask",
        title: "createAndRunTask",
        detail: "Create and run a task in the workspace",
        icon: "git-pull-request-create",
        selected: true,
      },
      {
        id: "execute",
        title: "execute",
        detail: "Execute code and applications on your machine",
        icon: "terminal",
        selected: true,
      },
      {
        id: "extensions",
        title: "extensions",
        detail: "Search for VS Code extensions",
        icon: "extensions",
        selected: true,
      },
      {
        id: "getTerminalOutput",
        title: "getTerminalOutput",
        detail: "Get the output of a terminal command previously started with run_in_terminal",
        icon: "terminal",
        selected: true,
      },
      {
        id: "killTerminal",
        title: "killTerminal",
        detail: "Kill a terminal by its ID. Use this to clean up terminals that are no longer needed.",
        icon: "terminal",
        selected: true,
      },
      {
        id: "new",
        title: "new",
        detail: "Scaffold a new workspace in VS Code",
        icon: "new-folder",
        selected: true,
      },
      {
        id: "read",
        title: "read",
        detail: "Read files in your workspace",
        icon: "book",
        selected: true,
      },
      {
        id: "runInTerminal",
        title: "runInTerminal",
        detail: "Run commands in the terminal",
        icon: "terminal",
        selected: true,
      },
      {
        id: "runSubagent",
        title: "runSubagent",
        detail: "Run a task within an isolated subagent context to enable efficient organization of task work.",
        icon: "organization",
        selected: true,
      },
      {
        id: "terminalLastCommand",
        title: "terminalLastCommand",
        detail: "Get the last command run in the active terminal.",
        icon: "terminal",
        selected: true,
      },
      {
        id: "terminalSelection",
        title: "terminalSelection",
        detail: "Get the current selection in the active terminal.",
        icon: "terminal",
        selected: true,
      },
      {
        id: "todo",
        title: "todo",
        detail: "Manage and track todo items for task planning",
        icon: "list-unordered",
        selected: true,
      },
      {
        id: "vscode",
        title: "vscode",
        detail: "Use VS Code features",
        icon: "vscode",
        selected: true,
      },
      {
        id: "renderMermaidDiagram",
        title: "renderMermaidDiagram",
        detail: "Render a Mermaid.js diagram from markup.",
        meta: "Mermaid Chat Features",
        icon: "type-hierarchy",
        selected: true,
      },
    ];

    return [
      {
        id: "built-in",
        label: "",
        rows: substrateToolRows,
      },
      {
        id: "live-tools",
        label: "Live Tools",
        rows:
          liveRows.length > 0
            ? liveRows
            : [
                {
                  id: "loading-live-tools",
                  title: "Loading Live Tools",
                  detail: "Querying connector-backed tool affordances.",
                  meta: "pending",
                  enabled: false,
                },
              ],
      },
      {
        id: "runtime-catalog",
        label: "Runtime Catalog",
        rows:
          runtimeRows.length > 0
            ? runtimeRows
            : [
                {
                  id: "kernel-backend-gallery",
                  title: "Kernel backend gallery",
                  detail: "Primary daemon-backed local backend catalog.",
                  meta: "ready",
                },
                {
                  id: "localai-backend-gallery",
                  title: "LocalAI backend gallery",
                  detail: "Optional backend route when configured.",
                  meta: "disabled",
                  enabled: false,
                },
                {
                  id: "kernel-model-gallery",
                  title: "Kernel model gallery",
                  detail: "Daemon-projected local model inventory.",
                  meta: "ready",
                },
                {
                  id: "evidence-playbook",
                  title: "Evidence playbook",
                  detail: "Parent playbook for receipt and replay capture.",
                  meta: "Promotable",
                },
                {
                  id: "browser-playbook",
                  title: "Browser playbook",
                  detail: "Parent playbook for GUI and browser work.",
                  meta: "Promotable",
                },
                {
                  id: "artifact-generator",
                  title: "Artifact Generator",
                  detail: "Parent playbook for artifact work.",
                  meta: "Promotable",
                },
              ],
      },
    ];
  }

  function studioToolQuickPickItems(state = {}) {
    return studioToolPaletteSections(state).flatMap((section) => {
      const rows = section.rows.map((row) => ({
        label: row.title,
        description: row.detail,
        detail: row.meta || undefined,
        picked: row.enabled !== false && row.selected,
        alwaysShow: row.selected || section.id === "built-in",
        iconPath: row.icon ? themeIcon(row.icon) : undefined,
        row,
        sectionId: section.id,
      }));
      if (!section.label) {
        return rows;
      }
      return [
        {
          label: section.label,
          kind: quickPickSeparatorKind,
        },
        ...rows,
      ];
    });
  }

  function studioContextQuickPickItems() {
    return [
      {
        id: "files-folders",
        title: "Files & Folders...",
        icon: "folder-opened",
        requestType: "chat.attachFilesAndFolders",
      },
      {
        id: "instructions",
        title: "Instructions...",
        icon: "bookmark",
        requestType: "chat.generateAgentInstructions",
      },
      {
        id: "problems",
        title: "Problems...",
        icon: "error",
        requestType: "chat.attachProblems",
      },
      {
        id: "symbols",
        title: "Symbols...",
        icon: "symbol-field",
        requestType: "chat.attachSymbols",
      },
      {
        id: "tools",
        title: "Tools...",
        icon: "tools",
        command: "ioi.quickInput.tools.configure",
        requestType: "chat.contextTools.open",
      },
    ].map((row) => ({
      label: row.title,
      alwaysShow: true,
      iconPath: themeIcon(row.icon),
      row,
    }));
  }

  return {
    normalizeStudioToolPaletteRows,
    studioContextQuickPickItems,
    studioToolPaletteSections,
    studioToolQuickPickItems,
  };
}

module.exports = {
  createStudioToolPalette,
};
