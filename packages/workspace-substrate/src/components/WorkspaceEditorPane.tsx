import { ComponentType, useEffect, useMemo, useRef } from "react";
import { DiffEditor, Editor } from "@monaco-editor/react";
import type { editor as MonacoEditorApi } from "monaco-editor";
import { configureMonacoLoader } from "../monaco";
import { isWorkspaceNotebookPath } from "../notebook";
import { languageForPath } from "../language";
import { bindWorkspaceEditor } from "../workspaceEditorBridge";
import type {
  WorkspaceAdapter,
  WorkspaceLanguageCodeAction,
  WorkspaceLanguageLocation,
  WorkspaceLanguageServiceSnapshot,
  WorkspaceOpenRequest,
} from "../types";
import type { WorkspaceDiffTab, WorkspaceDocumentTab, WorkspaceFileTab } from "../useWorkspaceSession";
import { WorkspaceDiffPane } from "./WorkspaceDiffPane";
import { WorkspaceNotebookPane } from "./WorkspaceNotebookPane";

const MonacoEditor = Editor as unknown as ComponentType<any>;
const MonacoDiffEditor = DiffEditor as unknown as ComponentType<any>;

interface WorkspaceEditorPaneProps {
  adapter?: WorkspaceAdapter;
  root?: string;
  monacoBasePath: string;
  documents: WorkspaceDocumentTab[];
  activeDocument: WorkspaceDocumentTab | null;
  activeDocumentId: string | null;
  revealRequest: WorkspaceOpenRequest | null;
  languageServiceSnapshot?: WorkspaceLanguageServiceSnapshot | null;
  onConsumeRevealRequest: () => void;
  onSelectDocument: (id: string) => void;
  onCloseDocument: (id: string) => void;
  onChangeFileContent: (path: string, content: string) => void;
  onSaveFile: (path: string) => void;
  onOpenRequest?: (request: WorkspaceOpenRequest) => void;
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

function modelPathForWorkspace(model: MonacoEditorApi.ITextModel): string {
  const raw = model.uri.toString();
  if (raw.startsWith("file:///")) {
    return decodeURIComponent(raw.replace(/^file:\/\/\/+/, ""));
  }

  const path = model.uri.path?.replace(/^\/+/, "");
  if (path) {
    return decodeURIComponent(path);
  }

  return decodeURIComponent(raw.replace(/^\/+/, ""));
}

function toMonacoRange(monaco: any, location: WorkspaceLanguageLocation) {
  return new monaco.Range(
    location.line,
    location.column,
    location.endLine,
    location.endColumn,
  );
}

function toMonacoUri(monaco: any, path: string) {
  return monaco.Uri.parse(path);
}

function toMonacoSymbolKind(monaco: any, kind: string) {
  switch (kind) {
    case "class":
      return monaco.languages.SymbolKind.Class;
    case "method":
      return monaco.languages.SymbolKind.Method;
    case "property":
      return monaco.languages.SymbolKind.Property;
    case "field":
      return monaco.languages.SymbolKind.Field;
    case "constructor":
      return monaco.languages.SymbolKind.Constructor;
    case "enum":
      return monaco.languages.SymbolKind.Enum;
    case "interface":
      return monaco.languages.SymbolKind.Interface;
    case "function":
      return monaco.languages.SymbolKind.Function;
    case "variable":
      return monaco.languages.SymbolKind.Variable;
    case "constant":
      return monaco.languages.SymbolKind.Constant;
    case "module":
      return monaco.languages.SymbolKind.Module;
    case "namespace":
      return monaco.languages.SymbolKind.Namespace;
    case "struct":
      return monaco.languages.SymbolKind.Struct;
    case "event":
      return monaco.languages.SymbolKind.Event;
    case "operator":
      return monaco.languages.SymbolKind.Operator;
    case "type parameter":
      return monaco.languages.SymbolKind.TypeParameter;
    case "file":
      return monaco.languages.SymbolKind.File;
    default:
      return monaco.languages.SymbolKind.Function;
  }
}

async function openFirstDefinition(
  editor: MonacoEditorApi.IStandaloneCodeEditor,
  _monaco: any,
  adapter: WorkspaceAdapter | undefined,
  root: string | undefined,
  path: string,
  onOpenRequest: ((request: WorkspaceOpenRequest) => void) | undefined,
) {
  if (!adapter || !root || !onOpenRequest) {
    return;
  }
  const position = editor.getPosition();
  if (!position) {
    return;
  }

  const locations = await adapter.getLanguageDefinition(
    root,
    path,
    position.lineNumber,
    position.column,
    editor.getModel()?.getValue(),
  );
  const first = locations[0];
  if (!first) {
    return;
  }

  if (first.path === path) {
    editor.revealPositionInCenter({
      lineNumber: first.line,
      column: first.column,
    });
    editor.setPosition({
      lineNumber: first.line,
      column: first.column,
    });
    return;
  }

  onOpenRequest({
    path: first.path,
    line: first.line,
    column: first.column,
  });
}

export function WorkspaceEditorPane({
  adapter,
  root,
  monacoBasePath,
  documents,
  activeDocument,
  activeDocumentId,
  revealRequest,
  languageServiceSnapshot,
  onConsumeRevealRequest,
  onSelectDocument,
  onCloseDocument,
  onChangeFileContent,
  onSaveFile,
  onOpenRequest,
  onAttachSelection,
}: WorkspaceEditorPaneProps) {
  const editorRef = useRef<MonacoEditorApi.IStandaloneCodeEditor | null>(null);
  const monacoRef = useRef<any>(null);

  useEffect(() => {
    configureMonacoLoader(monacoBasePath);
  }, [monacoBasePath]);

  const activeLanguage = useMemo(() => {
    if (!activeDocument || !isFileTab(activeDocument)) {
      return "plaintext";
    }
    if (isWorkspaceNotebookPath(activeDocument.path)) {
      return "json";
    }
    return languageForPath(activeDocument.path, activeDocument.languageHint);
  }, [activeDocument]);
  const activeIsNotebook =
    !!activeDocument &&
    isFileTab(activeDocument) &&
    isWorkspaceNotebookPath(activeDocument.path);

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
      activeIsNotebook ||
      activeDocument.error ||
      activeDocument.isBinary ||
      activeDocument.isTooLarge ||
      !editorRef.current
    ) {
      return;
    }

    return bindWorkspaceEditor(activeDocument.path, editorRef.current);
  }, [activeDocument, activeIsNotebook]);

  useEffect(() => {
    if (
      !monacoRef.current ||
      !editorRef.current ||
      !activeDocument ||
      !isFileTab(activeDocument) ||
      activeIsNotebook ||
      activeDocument.error ||
      activeDocument.isBinary ||
      activeDocument.isTooLarge
    ) {
      return;
    }

    const monaco = monacoRef.current;
    const model = editorRef.current.getModel();
    if (!model) {
      return;
    }

    const markers =
      languageServiceSnapshot?.path === activeDocument.path
        ? languageServiceSnapshot.diagnostics.map((diagnostic: any) => ({
            severity:
              diagnostic.severity === "error"
                ? monaco.MarkerSeverity.Error
                : diagnostic.severity === "warning"
                  ? monaco.MarkerSeverity.Warning
                  : monaco.MarkerSeverity.Info,
            message: diagnostic.detail,
            startLineNumber: diagnostic.line,
            startColumn: diagnostic.column,
            endLineNumber: diagnostic.endLine,
            endColumn: diagnostic.endColumn,
            code: diagnostic.code ?? undefined,
            source: diagnostic.source ?? languageServiceSnapshot.serverLabel ?? "workspace-lsp",
          }))
        : [];

    monaco.editor.setModelMarkers(model, "workspace-lsp", markers);

    return () => {
      monaco.editor.setModelMarkers(model, "workspace-lsp", []);
    };
  }, [activeDocument, activeIsNotebook, languageServiceSnapshot]);

  useEffect(() => {
    if (
      !monacoRef.current ||
      !adapter ||
      !root ||
      !activeDocument ||
      !isFileTab(activeDocument) ||
      activeIsNotebook ||
      activeDocument.error ||
      activeDocument.isBinary ||
      activeDocument.isTooLarge
    ) {
      return;
    }

    const monaco = monacoRef.current;
    const language = activeLanguage;

    const definitionProvider = monaco.languages.registerDefinitionProvider(language, {
      provideDefinition: async (model: MonacoEditorApi.ITextModel, position: any) => {
        const path = modelPathForWorkspace(model);
        const locations = await adapter.getLanguageDefinition(
          root,
          path,
          position.lineNumber,
          position.column,
          model.getValue(),
        );
        return locations.map((location) => ({
          uri: toMonacoUri(monaco, location.path),
          range: toMonacoRange(monaco, location),
        }));
      },
    });

    const referenceProvider = monaco.languages.registerReferenceProvider(language, {
      provideReferences: async (model: MonacoEditorApi.ITextModel, position: any) => {
        const path = modelPathForWorkspace(model);
        const locations = await adapter.getLanguageReferences(
          root,
          path,
          position.lineNumber,
          position.column,
          model.getValue(),
        );
        return locations.map((location) => ({
          uri: toMonacoUri(monaco, location.path),
          range: toMonacoRange(monaco, location),
        }));
      },
    });

    const symbolProvider = monaco.languages.registerDocumentSymbolProvider(language, {
      provideDocumentSymbols: async (model: MonacoEditorApi.ITextModel) => {
        const path = modelPathForWorkspace(model);
        const snapshot = await adapter.getLanguageServiceSnapshot(root, path, model.getValue());
        const toDocumentSymbol = (symbol: any): any => ({
          name: symbol.name,
          detail: symbol.detail ?? "",
          kind: toMonacoSymbolKind(monaco, symbol.kind),
          range: toMonacoRange(monaco, symbol),
          selectionRange: new monaco.Range(
            symbol.line,
            symbol.column,
            symbol.line,
            symbol.column,
          ),
          children: (symbol.children ?? []).map(toDocumentSymbol),
          tags: [],
        });

        return snapshot.symbols.map(toDocumentSymbol);
      },
    });

    const codeActionProvider = monaco.languages.registerCodeActionProvider(language, {
      providedCodeActionKinds: ["quickfix", "refactor", "source"],
      provideCodeActions: async (
        model: MonacoEditorApi.ITextModel,
        range: any,
        context: any,
      ) => {
        try {
          const path = modelPathForWorkspace(model);
          const actions = await adapter.getLanguageCodeActions(
            root,
            path,
            range.startLineNumber,
            range.startColumn,
            range.endLineNumber,
            range.endColumn,
            model.getValue(),
          );

          return {
            actions: actions.map((action: WorkspaceLanguageCodeAction) => {
              const edit =
                action.edits.length > 0
                  ? {
                      edits: action.edits.map((entry) => ({
                        resource: toMonacoUri(monaco, entry.path),
                        textEdit: {
                          range: new monaco.Range(
                            entry.line,
                            entry.column,
                            entry.endLine,
                            entry.endColumn,
                          ),
                          text: entry.newText,
                        },
                      })),
                    }
                  : undefined;

              return {
                title: action.title,
                kind: action.kind ?? "quickfix",
                isPreferred: action.isPreferred,
                diagnostics: context.markers ?? [],
                edit,
                disabled: action.disabledReason
                  ? { reason: action.disabledReason }
                  : undefined,
              };
            }),
            dispose: () => {},
          };
        } catch {
          return {
            actions: [],
            dispose: () => {},
          };
        }
      },
    });

    return () => {
      definitionProvider.dispose();
      referenceProvider.dispose();
      symbolProvider.dispose();
      codeActionProvider.dispose();
    };
  }, [activeDocument, activeIsNotebook, activeLanguage, adapter, root]);

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
              {activeIsNotebook ? (
                <span className="workspace-chip">Notebook</span>
              ) : null}
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
              {onAttachSelection && !activeIsNotebook ? (
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
            !activeDocument.isTooLarge &&
            activeIsNotebook ? (
              <WorkspaceNotebookPane
                document={activeDocument}
                onChangeFileContent={onChangeFileContent}
                onAttachSelection={onAttachSelection}
              />
            ) : null}

            {!activeDocument.error &&
            !activeDocument.isBinary &&
            !activeDocument.isTooLarge &&
            !activeIsNotebook ? (
              <MonacoEditor
                path={activeDocument.path}
                value={activeDocument.content}
                language={activeLanguage}
                theme="autopilot-dark"
                options={{
                  automaticLayout: true,
                  fontSize: 13,
                  colorDecorators: true,
                  defaultColorDecorators: "always",
                  colorDecoratorsActivatedOn: "clickAndHover",
                  lightbulb: {
                    enabled: "on",
                  },
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
                  monacoRef.current = monaco;
                  editor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyS, () => {
                    onSaveFile(activeDocument.path);
                  });
                  editor.addCommand(monaco.KeyCode.F12, () => {
                    void openFirstDefinition(
                      editor,
                      monaco,
                      adapter,
                      root,
                      activeDocument.path,
                      onOpenRequest,
                    );
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
                  colorDecorators: true,
                  defaultColorDecorators: "always",
                  colorDecoratorsActivatedOn: "clickAndHover",
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
