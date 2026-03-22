import { useMemo } from "react";
import CodeMirror from "@uiw/react-codemirror";
import { vscodeDark } from "@uiw/codemirror-theme-vscode";
import { javascript } from "@codemirror/lang-javascript";
import { json } from "@codemirror/lang-json";
import { markdown } from "@codemirror/lang-markdown";
import { rust } from "@codemirror/lang-rust";
import { css } from "@codemirror/lang-css";
import { html } from "@codemirror/lang-html";
import { yaml } from "@codemirror/lang-yaml";
import { keymap } from "@codemirror/view";
import { indentWithTab } from "@codemirror/commands";
import type { Extension } from "@codemirror/state";

interface ProjectScope {
  id: string;
  name: string;
  description: string;
  environment: string;
  rootPath: string;
}

export interface StudioEditorTab {
  path: string;
  name: string;
  content: string;
  savedContent: string;
  loading: boolean;
  saving: boolean;
  error: string | null;
  languageHint: string | null;
  sizeBytes: number;
  modifiedAtMs: number | null;
  isBinary: boolean;
  isTooLarge: boolean;
  readOnly: boolean;
}

interface StudioCodeWorkbenchProps {
  currentProject: ProjectScope;
  tabs: StudioEditorTab[];
  activePath: string | null;
  onSelectTab: (path: string) => void;
  onCloseTab: (path: string) => void;
  onChangeTabContent: (path: string, content: string) => void;
  onSaveTab: (path: string) => void;
  onReloadTab: (path: string) => void;
}

const CodeMirrorEditor = CodeMirror as unknown as (props: Record<string, unknown>) => JSX.Element;

function extensionsForLanguage(languageHint: string | null): Extension[] {
  switch (languageHint) {
    case "typescript":
      return [javascript({ typescript: true })];
    case "tsx":
      return [javascript({ typescript: true, jsx: true })];
    case "javascript":
      return [javascript()];
    case "jsx":
      return [javascript({ jsx: true })];
    case "json":
      return [json()];
    case "markdown":
      return [markdown()];
    case "rust":
      return [rust()];
    case "css":
      return [css()];
    case "html":
      return [html()];
    case "yaml":
      return [yaml()];
    default:
      return [];
  }
}

function formatSize(sizeBytes: number): string {
  if (sizeBytes >= 1024 * 1024) {
    return `${(sizeBytes / (1024 * 1024)).toFixed(1)} MB`;
  }
  if (sizeBytes >= 1024) {
    return `${Math.round(sizeBytes / 1024)} KB`;
  }
  return `${sizeBytes} B`;
}

function formatModifiedAt(timestamp: number | null): string {
  if (!timestamp) return "Unknown";
  try {
    return new Date(timestamp).toLocaleString();
  } catch {
    return "Unknown";
  }
}

export function StudioCodeWorkbench({
  currentProject,
  tabs,
  activePath,
  onSelectTab,
  onCloseTab,
  onChangeTabContent,
  onSaveTab,
  onReloadTab,
}: StudioCodeWorkbenchProps) {
  const activeTab = tabs.find((tab) => tab.path === activePath) ?? null;
  const isDirty = activeTab
    ? activeTab.content !== activeTab.savedContent
    : false;

  const editorExtensions = useMemo<Extension[]>(() => {
    if (!activeTab) return [];
    return [
      ...extensionsForLanguage(activeTab.languageHint),
      keymap.of([
        indentWithTab,
        {
          key: "Mod-s",
          preventDefault: true,
          run: () => {
            onSaveTab(activeTab.path);
            return true;
          },
        },
      ]),
    ];
  }, [activeTab, onSaveTab]);

  if (tabs.length === 0) {
    return (
      <section className="studio-code-workbench studio-code-workbench--empty">
        <div className="studio-code-empty">
          <span className="studio-code-empty-kicker">Code</span>
          <h2>Open a file from Explorer</h2>
          <p>
            Studio keeps file reads scoped and on-demand. Select a file on the
            right to edit it here without pulling the whole workspace into the
            frontend.
          </p>
        </div>
      </section>
    );
  }

  return (
    <section className="studio-code-workbench" aria-label="Workspace code editor">
      <div className="studio-code-tabs" role="tablist" aria-label="Open files">
        {tabs.map((tab) => {
          const dirty = tab.content !== tab.savedContent;
          const active = tab.path === activePath;
          return (
            <button
              key={tab.path}
              type="button"
              role="tab"
              aria-selected={active}
              className={`studio-code-tab ${active ? "is-active" : ""}`}
              onClick={() => onSelectTab(tab.path)}
            >
              <span className="studio-code-tab-name">{tab.name}</span>
              {dirty ? <span className="studio-code-tab-dirty" aria-hidden="true" /> : null}
              <span
                className="studio-code-tab-close"
                aria-label={`Close ${tab.name}`}
                onClick={(event) => {
                  event.stopPropagation();
                  onCloseTab(tab.path);
                }}
              >
                ×
              </span>
            </button>
          );
        })}
      </div>

      {activeTab ? (
        <>
          <div className="studio-code-toolbar">
            <div className="studio-code-toolbar-copy">
              <span className="studio-code-toolbar-kicker">
                {currentProject.name}
              </span>
              <strong>{activeTab.path}</strong>
              <span className="studio-code-toolbar-meta">
                {formatSize(activeTab.sizeBytes)} · Modified {formatModifiedAt(activeTab.modifiedAtMs)}
              </span>
            </div>

            <div className="studio-code-toolbar-actions">
              {activeTab.readOnly ? (
                <span className="studio-code-toolbar-badge">Read-only</span>
              ) : null}
              <button
                type="button"
                className="studio-code-toolbar-button"
                onClick={() => onReloadTab(activeTab.path)}
                disabled={activeTab.loading || activeTab.saving}
              >
                Reload
              </button>
              <button
                type="button"
                className="studio-code-toolbar-button studio-code-toolbar-button--primary"
                onClick={() => onSaveTab(activeTab.path)}
                disabled={
                  activeTab.loading ||
                  activeTab.saving ||
                  activeTab.readOnly ||
                  !isDirty
                }
              >
                {activeTab.saving ? "Saving..." : "Save"}
              </button>
            </div>
          </div>

          {activeTab.error ? (
            <div className="studio-code-message studio-code-message--error">
              <strong>Unable to open file</strong>
              <p>{activeTab.error}</p>
            </div>
          ) : null}

          {activeTab.loading ? (
            <div className="studio-code-message">
              <strong>Loading file</strong>
              <p>Reading the current document from the project boundary.</p>
            </div>
          ) : null}

          {!activeTab.loading && !activeTab.error && activeTab.isBinary ? (
            <div className="studio-code-message">
              <strong>Binary file</strong>
              <p>
                This file looks binary, so Studio leaves it out of the embedded
                editor to keep the workbench stable.
              </p>
            </div>
          ) : null}

          {!activeTab.loading && !activeTab.error && !activeTab.isBinary && activeTab.isTooLarge ? (
            <div className="studio-code-message">
              <strong>File too large for embedded editing</strong>
              <p>
                Studio avoids pulling very large files through the UI bridge.
                Open a smaller source file here, or edit this one externally.
              </p>
            </div>
          ) : null}

          {!activeTab.loading &&
          !activeTab.error &&
          !activeTab.isBinary &&
          !activeTab.isTooLarge ? (
            <div className="studio-code-editor-shell">
              <CodeMirrorEditor
                value={activeTab.content}
                height="100%"
                theme={vscodeDark}
                basicSetup={{
                  lineNumbers: true,
                  foldGutter: true,
                  highlightActiveLine: true,
                  highlightSelectionMatches: true,
                  bracketMatching: true,
                  autocompletion: true,
                  closeBrackets: true,
                  searchKeymap: true,
                }}
                editable={!activeTab.readOnly && !activeTab.saving}
                extensions={editorExtensions}
                onChange={(nextValue: string) =>
                  onChangeTabContent(activeTab.path, nextValue)
                }
              />
            </div>
          ) : null}
        </>
      ) : null}
    </section>
  );
}
