import { ComponentType, useEffect, useMemo, useRef } from "react";
import { DiffEditor, Editor } from "@monaco-editor/react";
import type { editor as MonacoEditorApi } from "monaco-editor";
import { configureMonacoLoader } from "../monaco";
import { languageForPath } from "../language";
import { bindWorkspaceEditor } from "../workspaceEditorBridge";
import type { WorkspaceOpenRequest } from "../types";
import type { WorkspaceDiffTab, WorkspaceDocumentTab, WorkspaceFileTab } from "../useWorkspaceSession";
import { WorkspaceDiffPane } from "./WorkspaceDiffPane";

const MonacoEditor = Editor as unknown as ComponentType<any>;
const MonacoDiffEditor = DiffEditor as unknown as ComponentType<any>;

interface WorkspaceEditorPaneProps {
  monacoBasePath: string;
  documents: WorkspaceDocumentTab[];
  activeDocument: WorkspaceDocumentTab | null;
  activeDocumentId: string | null;
  revealRequest: WorkspaceOpenRequest | null;
  onConsumeRevealRequest: () => void;
  onSelectDocument: (id: string) => void;
  onCloseDocument: (id: string) => void;
  onChangeFileContent: (path: string, content: string) => void;
  onSaveFile: (path: string) => void;
  onAttachSelection?: (payload: { path: string; selection: string }) => void;
}

function isFileTab(tab: WorkspaceDocumentTab): tab is WorkspaceFileTab {
  return tab.kind === "file";
}

function isDiffTab(tab: WorkspaceDocumentTab): tab is WorkspaceDiffTab {
  return tab.kind === "diff";
}

function defineAutopilotTheme(monaco: any) {
  monaco.editor.defineTheme("autopilot-dark", {
    base: "vs-dark",
    inherit: true,
    rules: [],
    colors: {
      "editor.background": "#0c0f13",
      "editor.lineHighlightBackground": "#141922",
      "editorCursor.foreground": "#a8d0ff",
      "editor.selectionBackground": "#244260",
      "editorIndentGuide.background1": "#1d2330",
      "editorIndentGuide.activeBackground1": "#37516f",
    },
  });
}

export function WorkspaceEditorPane({
  monacoBasePath,
  documents,
  activeDocument,
  activeDocumentId,
  revealRequest,
  onConsumeRevealRequest,
  onSelectDocument,
  onCloseDocument,
  onChangeFileContent,
  onSaveFile,
  onAttachSelection,
}: WorkspaceEditorPaneProps) {
  const editorRef = useRef<MonacoEditorApi.IStandaloneCodeEditor | null>(null);

  useEffect(() => {
    configureMonacoLoader(monacoBasePath);
  }, [monacoBasePath]);

  const activeLanguage = useMemo(() => {
    if (!activeDocument || !isFileTab(activeDocument)) {
      return "plaintext";
    }
    return languageForPath(activeDocument.path, activeDocument.languageHint);
  }, [activeDocument]);

  useEffect(() => {
    if (
      !revealRequest ||
      !activeDocument ||
      !isFileTab(activeDocument) ||
      activeDocument.path !== revealRequest.path ||
      !editorRef.current
    ) {
      return;
    }

    const lineNumber = revealRequest.line ?? 1;
    const column = revealRequest.column ?? 1;
    editorRef.current.revealPositionInCenter({ lineNumber, column });
    editorRef.current.setPosition({ lineNumber, column });
    editorRef.current.focus();
    onConsumeRevealRequest();
  }, [activeDocument, onConsumeRevealRequest, revealRequest]);

  useEffect(() => {
    if (
      !activeDocument ||
      !isFileTab(activeDocument) ||
      activeDocument.error ||
      activeDocument.isBinary ||
      activeDocument.isTooLarge ||
      !editorRef.current
    ) {
      return;
    }

    return bindWorkspaceEditor(activeDocument.path, editorRef.current);
  }, [activeDocument]);

  return (
    <section className="workspace-editor">
      <header className="workspace-editor-tabs">
        {documents.length === 0 ? (
          <div className="workspace-editor-empty-tabs">Open a file, diff, or search result</div>
        ) : (
          documents.map((tab) => {
            const isActive = tab.id === activeDocumentId;
            const title = tab.kind === "file" ? tab.name : tab.title;
            const dirty =
              tab.kind === "file" && tab.content !== tab.savedContent && !tab.loading;
            return (
              <div
                key={tab.id}
                className={`workspace-editor-tab ${isActive ? "is-active" : ""}`}
              >
                <button type="button" onClick={() => onSelectDocument(tab.id)}>
                  <span>{title}</span>
                  {dirty ? <span className="workspace-editor-dirty" /> : null}
                </button>
                <button
                  type="button"
                  className="workspace-editor-tab-close"
                  onClick={() => onCloseDocument(tab.id)}
                  aria-label={`Close ${title}`}
                >
                  ×
                </button>
              </div>
            );
          })
        )}
      </header>

      <div className="workspace-editor-stage">
        {!activeDocument ? (
          <div className="workspace-editor-empty">
            <div>
              <span className="workspace-pane-eyebrow">Workspace</span>
              <h3>Open the operator-facing workbench</h3>
              <p>
                Browse files, search the project, or inspect source control without
                leaving the native Autopilot shell.
              </p>
            </div>
          </div>
        ) : null}

        {activeDocument && isFileTab(activeDocument) ? (
          <>
            <div className="workspace-document-meta">
              <span className="workspace-chip">{activeDocument.path}</span>
              {activeDocument.readOnly ? (
                <span className="workspace-chip">Read only</span>
              ) : null}
              {activeDocument.loading ? (
                <span className="workspace-chip">Loading</span>
              ) : null}
              {activeDocument.saving ? (
                <span className="workspace-chip">Saving</span>
              ) : null}
              {!activeDocument.readOnly && !activeDocument.loading ? (
                <button
                  type="button"
                  className="workspace-pane-button"
                  onClick={() => onSaveFile(activeDocument.path)}
                >
                  Save
                </button>
              ) : null}
              {onAttachSelection ? (
                <button
                  type="button"
                  className="workspace-pane-button"
                  onClick={() => {
                    const editor = editorRef.current;
                    if (!editor) {
                      return;
                    }
                    const currentSelection = editor.getSelection();
                    if (!currentSelection) {
                      return;
                    }
                    const selection = editor.getModel()?.getValueInRange(currentSelection);
                    if (!selection?.trim()) {
                      return;
                    }
                    onAttachSelection({
                      path: activeDocument.path,
                      selection,
                    });
                  }}
                >
                  Send Selection
                </button>
              ) : null}
            </div>

            {activeDocument.error ? (
              <div className="workspace-editor-empty">
                <div>
                  <h3>Unable to open file</h3>
                  <p>{activeDocument.error}</p>
                </div>
              </div>
            ) : null}

            {!activeDocument.error && activeDocument.isBinary ? (
              <div className="workspace-editor-empty">
                <div>
                  <h3>Binary file</h3>
                  <p>This file is binary, so the embedded workspace keeps it out of Monaco.</p>
                </div>
              </div>
            ) : null}

            {!activeDocument.error && !activeDocument.isBinary && activeDocument.isTooLarge ? (
              <div className="workspace-editor-empty">
                <div>
                  <h3>File too large for embedded editing</h3>
                  <p>Open a smaller file here or edit this one in an external tool.</p>
                </div>
              </div>
            ) : null}

            {!activeDocument.error &&
            !activeDocument.isBinary &&
            !activeDocument.isTooLarge ? (
              <MonacoEditor
                path={activeDocument.path}
                value={activeDocument.content}
                language={activeLanguage}
                theme="autopilot-dark"
                options={{
                  automaticLayout: true,
                  fontSize: 13,
                  minimap: {
                    enabled: true,
                    side: "right",
                  },
                  smoothScrolling: true,
                  wordWrap: "off",
                  readOnly: activeDocument.readOnly || activeDocument.saving,
                }}
                beforeMount={defineAutopilotTheme}
                onMount={(editor: MonacoEditorApi.IStandaloneCodeEditor, monaco: any) => {
                  editorRef.current = editor;
                  editor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyS, () => {
                    onSaveFile(activeDocument.path);
                  });
                }}
                onChange={(value: string | undefined) =>
                  onChangeFileContent(activeDocument.path, value ?? "")
                }
              />
            ) : null}
          </>
        ) : null}

        {activeDocument && isDiffTab(activeDocument) ? (
          <>
            <WorkspaceDiffPane diff={activeDocument.diff} />
            {activeDocument.diff.isBinary ? (
              <div className="workspace-editor-empty">
                <div>
                  <h3>Binary diff</h3>
                  <p>This change is binary, so the workspace renders metadata instead of a diff.</p>
                </div>
              </div>
            ) : (
              <MonacoDiffEditor
                original={activeDocument.diff.originalContent}
                modified={activeDocument.diff.modifiedContent}
                language={languageForPath(activeDocument.path, activeDocument.diff.languageHint)}
                theme="autopilot-dark"
                beforeMount={defineAutopilotTheme}
                options={{
                  automaticLayout: true,
                  renderSideBySide: true,
                  readOnly: true,
                  minimap: {
                    enabled: true,
                    side: "right",
                  },
                }}
              />
            )}
          </>
        ) : null}
      </div>
    </section>
  );
}
