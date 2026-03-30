import type { editor as MonacoEditorApi } from "monaco-editor";

type WorkspaceEditorListener = (
  path: string,
  editor: MonacoEditorApi.IStandaloneCodeEditor,
) => void;

let activePath: string | null = null;
let activeEditor: MonacoEditorApi.IStandaloneCodeEditor | null = null;
const listeners = new Set<WorkspaceEditorListener>();

function notifyActiveEditor() {
  if (!activePath || !activeEditor) {
    return;
  }

  for (const listener of listeners) {
    listener(activePath, activeEditor);
  }
}

export function bindWorkspaceEditor(
  path: string,
  editor: MonacoEditorApi.IStandaloneCodeEditor,
) {
  activePath = path;
  activeEditor = editor;
  notifyActiveEditor();

  return () => {
    if (activeEditor === editor) {
      activeEditor = null;
      activePath = null;
    }
  };
}

export function waitForWorkspaceEditor(
  path: string,
  timeoutMs = 2500,
): Promise<MonacoEditorApi.IStandaloneCodeEditor | null> {
  if (activePath === path && activeEditor) {
    return Promise.resolve(activeEditor);
  }

  return new Promise((resolve) => {
    const timeout = window.setTimeout(() => {
      listeners.delete(listener);
      resolve(null);
    }, timeoutMs);

    const listener: WorkspaceEditorListener = (nextPath, editor) => {
      if (nextPath !== path) {
        return;
      }

      window.clearTimeout(timeout);
      listeners.delete(listener);
      resolve(editor);
    };

    listeners.add(listener);
  });
}
