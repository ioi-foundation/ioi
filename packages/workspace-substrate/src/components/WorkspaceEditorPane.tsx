import { useEffect, useMemo, useRef, useState } from "react";
import type { CodeOssStandaloneEditor, CodeOssTextModel } from "../codeOss";
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
import type { WorkspaceDocumentTab, WorkspaceFileTab } from "../useWorkspaceSession";
import { CodeOssDiffEditor, CodeOssEditor } from "./CodeOssEditor";
import { Codicon } from "./Codicon";
import { WorkspaceDiffPane } from "./WorkspaceDiffPane";
import { WorkspaceNotebookPane } from "./WorkspaceNotebookPane";
import workbenchEditorActionsRegion from "../assets/workbench-editor-actions-region.png";
import workbenchCenterWalkthroughStrip from "../assets/workbench-center-walkthrough-strip.png";
import workbenchCenterColumnStrip from "../assets/workbench-center-column-strip.png";
import workbenchEditorTabsStrip from "../assets/workbench-editor-tabs-strip.png";
import workbenchVsCodeMark from "../assets/workbench-vscode-mark.png";

interface WorkspaceEditorPaneProps {
  adapter?: WorkspaceAdapter;
  root?: string;
  documents: WorkspaceDocumentTab[];
  activeDocument: WorkspaceDocumentTab | null;
  activeDocumentId: string | null;
  splitView?: boolean;
  revealRequest: WorkspaceOpenRequest | null;
  languageServiceSnapshot?: WorkspaceLanguageServiceSnapshot | null;
  onConsumeRevealRequest: () => void;
  onSelectDocument: (id: string) => void;
  onCloseDocument: (id: string) => void;
  onChangeFileContent: (path: string, content: string) => void;
  onSaveFile: (path: string) => void;
  onOpenRequest?: (request: WorkspaceOpenRequest) => void;
  onAttachSelection?: (payload: { path: string; selection: string }) => void;
  canSplitEditor?: boolean;
  onToggleSplitEditor?: () => void;
  onOpenEditorActions?: () => void;
}

function isFileTab(tab: WorkspaceDocumentTab): tab is WorkspaceFileTab {
  return tab.kind === "file";
}

function modelPathForWorkspace(model: CodeOssTextModel): string {
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
  editor: CodeOssStandaloneEditor,
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
  documents,
  activeDocument,
  activeDocumentId,
  splitView = false,
  revealRequest,
  languageServiceSnapshot,
  onConsumeRevealRequest,
  onSelectDocument,
  onCloseDocument,
  onChangeFileContent,
  onSaveFile,
  onOpenRequest,
  onAttachSelection,
  canSplitEditor = false,
  onToggleSplitEditor,
  onOpenEditorActions,
}: WorkspaceEditorPaneProps) {
  const editorRef = useRef<CodeOssStandaloneEditor | null>(null);
  const monacoRef = useRef<any>(null);
  const [walkthroughHidden, setWalkthroughHidden] = useState(false);
  const [editorActionsOpen, setEditorActionsOpen] = useState(false);

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
  const shouldRenderSplitView = splitView && !!activeDocument && !activeIsNotebook;
  const showWalkthrough = !activeDocument && !walkthroughHidden;

  useEffect(() => {
    setWalkthroughHidden(false);
    setEditorActionsOpen(false);
  }, [root]);

  useEffect(() => {
    setEditorActionsOpen(false);
  }, [activeDocumentId]);

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
      provideDefinition: async (model: CodeOssTextModel, position: any) => {
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
      provideReferences: async (model: CodeOssTextModel, position: any) => {
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
      provideDocumentSymbols: async (model: CodeOssTextModel) => {
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
        model: CodeOssTextModel,
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

  const renderActiveDocumentContent = (isReplica: boolean) => {
    if (!activeDocument) {
      return null;
    }

    if (isFileTab(activeDocument)) {
      return (
        <>
          <div
            className={`workspace-document-meta${isReplica ? " workspace-document-meta--replica" : ""}`}
          >
            <span className="workspace-chip">{activeDocument.path}</span>
            {isReplica ? <span className="workspace-chip">Split editor</span> : null}
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
            {!isReplica && !activeDocument.readOnly && !activeDocument.loading ? (
              <button
                type="button"
                className="workspace-pane-button"
                onClick={() => onSaveFile(activeDocument.path)}
              >
                Save
              </button>
            ) : null}
            {!isReplica && onAttachSelection && !activeIsNotebook ? (
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
                <p>This file is binary, so the embedded workspace keeps it out of the internal editor.</p>
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
              onAttachSelection={isReplica ? undefined : onAttachSelection}
            />
          ) : null}

          {!activeDocument.error &&
          !activeDocument.isBinary &&
          !activeDocument.isTooLarge &&
          !activeIsNotebook ? (
            <CodeOssEditor
              key={`${activeDocument.path}:${isReplica ? "secondary" : "primary"}`}
              path={activeDocument.path}
              value={activeDocument.content}
              language={activeLanguage}
              theme="autopilot-light"
              options={{
                automaticLayout: true,
                fontSize: 13,
                colorDecorators: true,
                defaultColorDecorators: "always",
                colorDecoratorsActivatedOn: "clickAndHover",
                minimap: {
                  enabled: true,
                  side: "right",
                },
                smoothScrolling: true,
                wordWrap: "off",
                readOnly: isReplica || activeDocument.readOnly || activeDocument.saving,
              }}
              onMount={
                isReplica
                  ? undefined
                  : (editor: CodeOssStandaloneEditor, monaco: any) => {
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
                    }
              }
              onChange={
                isReplica
                  ? undefined
                  : (value) => {
                      onChangeFileContent(activeDocument.path, value);
                    }
              }
            />
          ) : null}
        </>
      );
    }

    return (
      <>
        <WorkspaceDiffPane diff={activeDocument.diff} />
        {isReplica ? (
          <div className="workspace-document-meta workspace-document-meta--replica">
            <span className="workspace-chip">Split editor</span>
            <span className="workspace-chip">{activeDocument.path}</span>
          </div>
        ) : null}
        {activeDocument.diff.isBinary ? (
          <div className="workspace-editor-empty">
            <div>
              <h3>Binary diff</h3>
              <p>This change is binary, so the workspace renders metadata instead of a diff.</p>
            </div>
          </div>
        ) : (
          <CodeOssDiffEditor
            key={`${activeDocument.path}:${isReplica ? "secondary" : "primary"}`}
            path={activeDocument.path}
            original={activeDocument.diff.originalContent}
            modified={activeDocument.diff.modifiedContent}
            language={languageForPath(activeDocument.path, activeDocument.diff.languageHint)}
            theme="autopilot-light"
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
    );
  };

  return (
    <section className={`workspace-editor${showWalkthrough ? " workspace-editor--walkthrough-default" : ""}`}>
      {showWalkthrough ? (
        <img
          src={workbenchCenterColumnStrip}
          alt=""
          className="workspace-editor-default-strip"
          aria-hidden="true"
        />
      ) : null}
      <header className="workspace-editor-tabs">
        <img src={workbenchEditorTabsStrip} alt="" className="workspace-editor-tabs-strip" aria-hidden="true" />
        <div className="workspace-editor-tabs-live">
          <div className="workspace-editor-tabs-list">
            {documents.length === 0 ? (
              showWalkthrough ? (
                <div className="workspace-editor-tab workspace-editor-tab--virtual is-active">
                  <button type="button" aria-current="page">
                    <span className="workspace-editor-tab-icon" aria-hidden="true">
                      <img src={workbenchVsCodeMark} alt="" className="workspace-editor-tab-mark" />
                    </span>
                    <span className="workspace-editor-tab-label workspace-editor-tab-label--virtual">
                      Walkthrough: Setup VS Code Web
                    </span>
                  </button>
                  <button
                    type="button"
                    className="workspace-editor-tab-close"
                    aria-label="Close walkthrough"
                    onClick={() => setWalkthroughHidden(true)}
                  >
                    <Codicon name="close" />
                  </button>
                </div>
              ) : null
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
                      <Codicon name="close" />
                    </button>
                  </div>
                );
              })
            )}
          </div>

          <div className="workspace-editor-tabs-actions">
            <img src={workbenchEditorActionsRegion} alt="" className="workspace-editor-tabs-actions-region" aria-hidden="true" />
            <button
              type="button"
              className="workspace-editor-tabs-action workspace-editor-tabs-action--split"
              aria-label="Split editor right"
              aria-pressed={shouldRenderSplitView}
              disabled={!canSplitEditor || !onToggleSplitEditor}
              onClick={onToggleSplitEditor}
            >
              <Codicon name="split-horizontal" />
            </button>
            <button
              type="button"
              className="workspace-editor-tabs-action workspace-editor-tabs-action--more"
              aria-label="More editor actions"
              aria-expanded={editorActionsOpen}
              onClick={() => setEditorActionsOpen((isOpen) => !isOpen)}
            >
              <Codicon name="ellipsis" />
            </button>
          </div>
        </div>
      </header>

      {editorActionsOpen ? (
        <div className="workspace-editor-actions-menu" role="menu">
          <button
            type="button"
            role="menuitem"
            disabled={!canSplitEditor || !onToggleSplitEditor}
            onClick={() => {
              setEditorActionsOpen(false);
              onToggleSplitEditor?.();
            }}
          >
            {shouldRenderSplitView ? "Close Split Editor" : "Split Editor Right"}
          </button>
          {activeDocument ? (
            <button
              type="button"
              role="menuitem"
              onClick={() => {
                setEditorActionsOpen(false);
                onCloseDocument(activeDocument.id);
              }}
            >
              Close Editor
            </button>
          ) : null}
          {onOpenEditorActions ? (
            <button
              type="button"
              role="menuitem"
              onClick={() => {
                setEditorActionsOpen(false);
                onOpenEditorActions();
              }}
            >
              Open Workspace Search
            </button>
          ) : null}
        </div>
      ) : null}

      <div className={`workspace-editor-stage${shouldRenderSplitView ? " workspace-editor-stage--split" : ""}`}>
        {showWalkthrough ? (
          <div className="workspace-editor-empty workspace-editor-empty--walkthrough">
            <img
              src={workbenchCenterWalkthroughStrip}
              alt=""
              className="workspace-editor-walkthrough-strip"
              aria-hidden="true"
            />
            <div className="workspace-editor-walkthrough-shell">
              <div className="workspace-editor-walkthrough-intro">
                <button
                  type="button"
                  className="workspace-editor-walkthrough-back"
                  aria-label="Back"
                >
                  ←
                </button>
                <div>
                  <h3>Get Started with VS Code for the Web</h3>
                  <p>Customize your editor, learn the basics, and start coding</p>
                </div>
              </div>

              <section className="workspace-editor-walkthrough-card">
                <div className="workspace-editor-walkthrough-bullet" aria-hidden="true" />
                <div>
                  <strong>Choose your theme</strong>
                  <p>
                    The right theme helps you focus on your code, is easy on your eyes,
                    and is simply more fun to use.
                  </p>
                  <button type="button" className="workspace-editor-walkthrough-primary">
                    Browse Color Themes
                  </button>
                  <p className="workspace-editor-walkthrough-shortcuts">
                    Tip: Use keyboard shortcut <kbd>Ctrl</kbd> + <kbd>K</kbd> <kbd>Ctrl</kbd> + <kbd>T</kbd>
                  </p>
                </div>
              </section>

              <div className="workspace-editor-walkthrough-list" role="list">
                <div className="workspace-editor-walkthrough-list-item" role="listitem">
                  <span className="workspace-editor-walkthrough-radio" aria-hidden="true" />
                  <strong>Just the right amount of UI</strong>
                </div>
                <div className="workspace-editor-walkthrough-list-item" role="listitem">
                  <span className="workspace-editor-walkthrough-radio" aria-hidden="true" />
                  <strong>Rich support for all your languages</strong>
                </div>
                <div className="workspace-editor-walkthrough-list-item" role="listitem">
                  <span className="workspace-editor-walkthrough-radio" aria-hidden="true" />
                  <strong>Unlock productivity with the Command Palette</strong>
                </div>
              </div>
            </div>
          </div>
        ) : null}
        {activeDocument && shouldRenderSplitView ? (
          <>
            <div className="workspace-editor-split-pane">{renderActiveDocumentContent(false)}</div>
            <div className="workspace-editor-split-divider" aria-hidden="true" />
            <div className="workspace-editor-split-pane workspace-editor-split-pane--secondary">
              {renderActiveDocumentContent(true)}
            </div>
          </>
        ) : null}

        {activeDocument && !shouldRenderSplitView ? renderActiveDocumentContent(false) : null}
      </div>
    </section>
  );
}
