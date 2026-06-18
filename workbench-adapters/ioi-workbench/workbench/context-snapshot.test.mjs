import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);

const {
  createWorkbenchContextSnapshot,
} = require("./context-snapshot.js");

function uri(path) {
  return {
    fsPath: path,
    path,
    scheme: "file",
    toString: () => `file://${path}`,
  };
}

function createMockVscode() {
  const selection = {
    isEmpty: false,
    start: { line: 2, character: 4 },
    end: { line: 2, character: 12 },
  };
  const activeUri = uri("/workspace/src/app.js");
  return {
    DiagnosticSeverity: {
      Error: 0,
      Warning: 1,
      Information: 2,
      Hint: 3,
    },
    extensions: {
      getExtension: () => ({
        exports: {
          getAPI: () => ({
            repositories: [
              {
                rootUri: uri("/workspace"),
                state: {
                  HEAD: { name: "main", ahead: 1, behind: 0 },
                  workingTreeChanges: [{ resourceUri: uri("/workspace/src/app.js") }],
                  indexChanges: [],
                  untrackedChanges: [],
                  mergeChanges: [],
                },
              },
            ],
          }),
        },
      }),
    },
    languages: {
      getDiagnostics: () => [[
        activeUri,
        [
          {
            message: "Example problem",
            severity: 1,
            source: "test",
            code: "W1",
            range: selection,
          },
        ],
      ]],
    },
    tasks: {
      taskExecutions: [{ task: { name: "npm test" } }],
    },
    window: {
      activeEditor: null,
      activeTerminal: { name: "bash" },
      activeTextEditor: {
        document: {
          fileName: "/workspace/src/app.js",
          getText: () => "selected",
          isDirty: true,
          languageId: "javascript",
          uri: activeUri,
        },
        selection,
      },
      tabGroups: {
        all: [
          {
            tabs: [
              {
                label: "app.js",
                isActive: true,
                isDirty: true,
                input: { uri: activeUri },
              },
            ],
          },
        ],
      },
      terminals: [{ name: "bash" }],
    },
  };
}

test("workbench context snapshot projects editor, scm, diagnostics, tasks, and runtime refs", () => {
  const helpers = createWorkbenchContextSnapshot({
    vscode: createMockVscode(),
    workspaceSummary: () => ({ name: "workspace", path: "/workspace" }),
    buildRuntimeRefs: () => ({ daemon: "runtime://local" }),
    refSafe: (value) => String(value || "unknown").replace(/[^a-z0-9]+/gi, "-"),
  });

  helpers.rememberRecentTaskLabel("cargo test");
  helpers.setLastTaskExitCode(0);

  const snapshot = helpers.buildWorkbenchContextSnapshot("unit");
  assert.equal(snapshot.schemaVersion, "ioi.code-editor-adapter.v1");
  assert.equal(snapshot.reason, "unit");
  assert.equal(snapshot.workspaceRoot, "/workspace");
  assert.equal(snapshot.activeEditor.filePath, "/workspace/src/app.js");
  assert.equal(snapshot.activeEditor.selection.startLineNumber, 3);
  assert.equal(snapshot.activeEditor.selectedTextHash.length, 64);
  assert.equal(snapshot.diagnostics[0].severity, "warning");
  assert.equal(snapshot.scmState.provider, "git");
  assert.equal(snapshot.scmState.branch, "main");
  assert.equal(snapshot.taskState.lastExitCode, 0);
  assert.deepEqual(snapshot.taskState.recentTaskLabels, ["npm test", "cargo test"]);
  assert.deepEqual(snapshot.runtimeRefs, { daemon: "runtime://local" });

  const index = helpers.buildWorkbenchInspectionTargetIndex("unit");
  assert.equal(index.schemaVersion, "ioi.code-editor-adapter.v1");
  assert.ok(index.targets.some((target) => target.targetId === "editor.active"));
  assert.ok(index.targets.some((target) => target.targetId === "terminal.panel"));
  assert.equal(
    index.targets.some((target) => /hypervisor|command-center/i.test(`${target.targetId} ${target.label}`)),
    false,
  );
});
