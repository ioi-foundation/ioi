const crypto = require("crypto");

function startCodeEditorContextPublisher({
  context,
  vscode,
  buildCodeEditorContextSnapshot,
  buildCodeEditorInspectionTargetIndex,
  writeContextEnvelope,
  rememberRecentTaskLabel,
  getLastTaskExitCode,
  setLastTaskExitCode,
  reportError,
}) {
  let lastHash = "";
  let lastTargetHash = "";
  let publishing = false;

  const publish = async (reason) => {
    if (publishing) {
      return;
    }
    publishing = true;
    try {
      const snapshot = buildCodeEditorContextSnapshot(reason);
      const comparableSnapshot = {
        ...snapshot,
        snapshotId: "",
        generatedAtMs: 0,
        reason: "",
      };
      const hash = crypto
        .createHash("sha256")
        .update(JSON.stringify(comparableSnapshot))
        .digest("hex");
      if (hash !== lastHash) {
        lastHash = hash;
        await writeContextEnvelope("codeEditor.contextSnapshot", snapshot, {
          source: "ioi-code-editor-adapter",
          reason,
        });
      }

      const targetIndex = buildCodeEditorInspectionTargetIndex(reason);
      const comparableTargetIndex = {
        ...targetIndex,
        generatedAtMs: 0,
        reason: "",
      };
      const targetHash = crypto
        .createHash("sha256")
        .update(JSON.stringify(comparableTargetIndex))
        .digest("hex");
      if (targetHash !== lastTargetHash) {
        lastTargetHash = targetHash;
        await writeContextEnvelope("codeEditor.inspectionTargetIndex", targetIndex, {
          source: "ioi-code-editor-adapter",
          reason,
        });
      }
    } catch (error) {
      reportError?.(error);
    } finally {
      publishing = false;
    }
  };

  const subscriptions = [
    vscode.window.onDidChangeActiveTextEditor(() => void publish("activeEditor")),
    vscode.window.onDidChangeTextEditorSelection(() => void publish("selection")),
    vscode.languages.onDidChangeDiagnostics(() => void publish("diagnostics")),
    vscode.window.tabGroups.onDidChangeTabs(() => void publish("tabs")),
    vscode.window.onDidOpenTerminal(() => void publish("terminal")),
    vscode.window.onDidCloseTerminal(() => void publish("terminal")),
    vscode.tasks.onDidStartTask((event) => {
      rememberRecentTaskLabel(event.execution?.task?.name);
      void publish("task");
    }),
    vscode.tasks.onDidEndTaskProcess((event) => {
      rememberRecentTaskLabel(event.execution?.task?.name);
      setLastTaskExitCode(
        typeof event.exitCode === "number" ? event.exitCode : getLastTaskExitCode(),
      );
      void publish("task");
    }),
  ];
  subscriptions.forEach((subscription) => context.subscriptions.push(subscription));

  const timer = setInterval(() => void publish("poll"), 3_000);
  context.subscriptions.push({ dispose: () => clearInterval(timer) });
  void publish("activation");
}

module.exports = {
  startCodeEditorContextPublisher,
};
