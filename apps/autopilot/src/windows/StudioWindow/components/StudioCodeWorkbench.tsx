import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import CodeMirror from "@uiw/react-codemirror";
import { vscodeDark } from "@uiw/codemirror-theme-vscode";
import { javascript } from "@codemirror/lang-javascript";
import { json } from "@codemirror/lang-json";
import { markdown } from "@codemirror/lang-markdown";
import { rust } from "@codemirror/lang-rust";
import { css } from "@codemirror/lang-css";
import { html } from "@codemirror/lang-html";
import { yaml } from "@codemirror/lang-yaml";
import {
  Decoration,
  EditorView,
  ViewPlugin,
  keymap,
  type ViewUpdate,
} from "@codemirror/view";
import { indentWithTab } from "@codemirror/commands";
import { RangeSetBuilder, type Extension } from "@codemirror/state";
import { StudioFileTypeIcon } from "./StudioFileTypeIcon";

export interface StudioEditorTab {
  path: string;
  name: string;
  absolutePath: string;
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
  tabs: StudioEditorTab[];
  activePath: string | null;
  onSelectTab: (path: string) => void;
  onCloseTab: (path: string) => void;
  onChangeTabContent: (path: string, content: string) => void;
  onSaveTab: (path: string) => void;
}

const CodeMirrorEditor = CodeMirror as unknown as (props: Record<string, unknown>) => JSX.Element;

const markdownQuotedMark = Decoration.mark({
  class: "cm-markdown-quoted",
});

const markdownQuotedStrings = ViewPlugin.fromClass(class {
  decorations;

  constructor(view: EditorView) {
    this.decorations = buildMarkdownQuotedDecorations(view);
  }

  update(update: ViewUpdate) {
    if (update.docChanged || update.viewportChanged) {
      this.decorations = buildMarkdownQuotedDecorations(update.view);
    }
  }
}, {
  decorations: (plugin) => plugin.decorations,
});

function buildMarkdownQuotedDecorations(view: EditorView) {
  const builder = new RangeSetBuilder<Decoration>();
  const quoted = /(`[^`\n]+`)|("[^"\n]+")|('[^'\n]+')/g;

  for (const { from, to } of view.visibleRanges) {
    const text = view.state.doc.sliceString(from, to);
    quoted.lastIndex = 0;
    let match: RegExpExecArray | null;

    while ((match = quoted.exec(text))) {
      const start = from + match.index;
      const end = start + match[0].length;
      builder.add(start, end, markdownQuotedMark);
    }
  }

  return builder.finish();
}

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

type PreviewTone =
  | "base"
  | "accent"
  | "warm"
  | "muted"
  | "comment"
  | "strong";

const MINIMAP_LINE_HEIGHT_PX = 4.8;
const MINIMAP_TOP_INSET_PX = 8;

function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}

interface PreviewLine {
  text: string;
  tone: PreviewTone;
  indent: number;
}

function previewToneForLine(
  line: string,
  languageHint: string | null,
): PreviewTone {
  const trimmed = line.trim();
  if (!trimmed) return "muted";

  if (languageHint === "markdown" && trimmed.startsWith("#")) {
    return "accent";
  }

  if (
    trimmed.startsWith("//") ||
    trimmed.startsWith("/*") ||
    trimmed.startsWith("*") ||
    trimmed.startsWith("<!--") ||
    (languageHint === "markdown" && trimmed.startsWith(">"))
  ) {
    return "comment";
  }

  if (
    (languageHint === "markdown" &&
      /(`[^`\n]+`)|("[^"\n]+")|('[^'\n]+')/.test(trimmed)) ||
    /("(?:[^"\\]|\\.)*")|('(?:[^'\\]|\\.)*')/.test(trimmed)
  ) {
    return "warm";
  }

  if (
    /^(export|import|const|let|function|class|interface|type|enum|return|async|await|fn|pub|impl|struct|use)\b/.test(
      trimmed,
    )
  ) {
    return "strong";
  }

  return "base";
}

function buildPreviewLines(
  content: string,
  languageHint: string | null,
): PreviewLine[] {
  const lines = content.split("\n");
  const previewCount = Math.max(1, Math.min(lines.length, 160));
  const previewLines: PreviewLine[] = [];

  for (let index = 0; index < previewCount; index += 1) {
    const sourceIndex = Math.min(
      lines.length - 1,
      Math.floor((index / previewCount) * lines.length),
    );
    const source = lines[sourceIndex] ?? "";
    const leadingWhitespace = source.match(/^\s*/)?.[0].length ?? 0;

    previewLines.push({
      text: source.replace(/\t/g, "  ").slice(0, 160),
      tone: previewToneForLine(source, languageHint),
      indent: Math.min(18, Math.round(leadingWhitespace / 2)),
    });
  }

  return previewLines;
}

export function StudioCodeWorkbench({
  tabs,
  activePath,
  onSelectTab,
  onCloseTab,
  onChangeTabContent,
  onSaveTab,
}: StudioCodeWorkbenchProps) {
  const activeTab = tabs.find((tab) => tab.path === activePath) ?? null;
  const [editorView, setEditorView] = useState<EditorView | null>(null);
  const previousActiveTabRef = useRef<StudioEditorTab | null>(null);
  const minimapDragOffsetRef = useRef<number | null>(null);
  const [scrollMetrics, setScrollMetrics] = useState({
    scrollTop: 0,
    scrollHeight: 1,
    clientHeight: 1,
  });

  const editorExtensions = useMemo<Extension[]>(() => {
    if (!activeTab) return [];
    return [
      ...extensionsForLanguage(activeTab.languageHint),
      ...(activeTab.languageHint === "markdown"
        ? [markdownQuotedStrings]
        : []),
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

  const previewLines = useMemo(
    () =>
      activeTab
        ? buildPreviewLines(activeTab.content, activeTab.languageHint)
        : [],
    [activeTab],
  );

  const syncScrollMetrics = useCallback(() => {
    if (!editorView) return;
    const scrollDOM = editorView.scrollDOM;
    setScrollMetrics({
      scrollTop: scrollDOM.scrollTop,
      scrollHeight: scrollDOM.scrollHeight,
      clientHeight: scrollDOM.clientHeight,
    });
  }, [editorView]);

  useEffect(() => {
    if (!editorView) return;
    const scrollDOM = editorView.scrollDOM;
    const handleScroll = () => syncScrollMetrics();
    handleScroll();
    scrollDOM.addEventListener("scroll", handleScroll, { passive: true });
    window.addEventListener("resize", handleScroll);

    return () => {
      scrollDOM.removeEventListener("scroll", handleScroll);
      window.removeEventListener("resize", handleScroll);
    };
  }, [editorView, syncScrollMetrics, activeTab?.path]);

  useEffect(() => {
    syncScrollMetrics();
  }, [syncScrollMetrics, activeTab?.content, activeTab?.path]);

  useEffect(() => {
    const previousActiveTab = previousActiveTabRef.current;
    if (
      previousActiveTab &&
      previousActiveTab.path !== activeTab?.path &&
      previousActiveTab.content !== previousActiveTab.savedContent &&
      !previousActiveTab.loading &&
      !previousActiveTab.saving &&
      !previousActiveTab.readOnly
    ) {
      onSaveTab(previousActiveTab.path);
    }

    previousActiveTabRef.current = activeTab;
  }, [activeTab, onSaveTab]);

  useEffect(() => {
    if (
      !activeTab ||
      activeTab.loading ||
      activeTab.saving ||
      activeTab.readOnly ||
      activeTab.content === activeTab.savedContent
    ) {
      return;
    }

    const timeoutId = window.setTimeout(() => {
      onSaveTab(activeTab.path);
    }, 700);

    return () => window.clearTimeout(timeoutId);
  }, [
    activeTab?.content,
    activeTab?.loading,
    activeTab?.path,
    activeTab?.readOnly,
    activeTab?.savedContent,
    activeTab?.saving,
    onSaveTab,
  ]);

  const scrollEditorToRatio = useCallback((ratio: number) => {
    if (!editorView) return;
    const scrollDOM = editorView.scrollDOM;
    const maxScrollTop = Math.max(0, scrollDOM.scrollHeight - scrollDOM.clientHeight);
    scrollDOM.scrollTop = maxScrollTop * Math.min(1, Math.max(0, ratio));
    syncScrollMetrics();
  }, [editorView, syncScrollMetrics]);

  const minimapContentHeight =
    Math.max(previewLines.length * MINIMAP_LINE_HEIGHT_PX, MINIMAP_LINE_HEIGHT_PX);
  const minimapViewportHeightPx =
    scrollMetrics.scrollHeight <= scrollMetrics.clientHeight
      ? minimapContentHeight
      : Math.max(
          18,
          (scrollMetrics.clientHeight / scrollMetrics.scrollHeight) *
            minimapContentHeight,
        );
  const minimapViewportTop =
    scrollMetrics.scrollHeight <= scrollMetrics.clientHeight
      ? 0
      : (scrollMetrics.scrollTop /
          Math.max(1, scrollMetrics.scrollHeight - scrollMetrics.clientHeight)) *
        Math.max(0, minimapContentHeight - minimapViewportHeightPx);
  const minimapScrollableHeight = Math.max(
    0,
    minimapContentHeight - minimapViewportHeightPx,
  );
  const absoluteToolbarPath =
    activeTab?.absolutePath && activeTab.absolutePath.length > 0
      ? activeTab.absolutePath
      : null;

  const scrollEditorFromMinimapPointer = useCallback((
    clientY: number,
    target: HTMLElement,
  ) => {
    const rect = target.getBoundingClientRect();
    const pointerWithinContent = clamp(
      clientY - rect.top - MINIMAP_TOP_INSET_PX,
      0,
      minimapContentHeight,
    );
    const dragOffset =
      minimapDragOffsetRef.current ?? minimapViewportHeightPx / 2;
    const viewportTop = clamp(
      pointerWithinContent - dragOffset,
      0,
      minimapScrollableHeight,
    );
    const ratio =
      minimapScrollableHeight <= 0 ? 0 : viewportTop / minimapScrollableHeight;

    scrollEditorToRatio(ratio);
  }, [
    minimapContentHeight,
    minimapScrollableHeight,
    minimapViewportHeightPx,
    scrollEditorToRatio,
  ]);

  if (tabs.length === 0) {
    return (
      <section className="studio-code-workbench studio-code-workbench--empty">
        <div className="studio-code-empty">
          <span className="studio-code-empty-kicker">Explorer</span>
          <h2>Open a file from Explorer</h2>
          <p>
            Studio keeps file reads scoped and on-demand. Select a file in
            Explorer to edit it here without pulling the whole workspace into the
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
              <StudioFileTypeIcon name={tab.name} context="tab" />
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
            <div
              className="studio-code-toolbar-copy"
              title={absoluteToolbarPath ?? "Resolving absolute path"}
            >
              <strong>
                {absoluteToolbarPath ?? "Resolving absolute path..."}
              </strong>
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
            <div className="studio-code-editor-layout">
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
                  onCreateEditor={(view: EditorView) => {
                    setEditorView(view);
                    requestAnimationFrame(() => syncScrollMetrics());
                  }}
                  onUpdate={() => {
                    requestAnimationFrame(() => syncScrollMetrics());
                  }}
                  onChange={(nextValue: string) =>
                    onChangeTabContent(activeTab.path, nextValue)
                  }
                />
              </div>

              <aside
                className="studio-code-minimap"
                aria-label="File preview"
                onPointerDown={(event) => {
                  const target = event.currentTarget;
                  event.preventDefault();
                  target.setPointerCapture(event.pointerId);
                  const rect = target.getBoundingClientRect();
                  const pointerWithinContent = clamp(
                    event.clientY - rect.top - MINIMAP_TOP_INSET_PX,
                    0,
                    minimapContentHeight,
                  );
                  const viewportBottom =
                    minimapViewportTop + minimapViewportHeightPx;

                  minimapDragOffsetRef.current =
                    pointerWithinContent >= minimapViewportTop &&
                    pointerWithinContent <= viewportBottom
                      ? pointerWithinContent - minimapViewportTop
                      : minimapViewportHeightPx / 2;

                  scrollEditorFromMinimapPointer(event.clientY, target);
                }}
                onPointerMove={(event) => {
                  if ((event.buttons & 1) !== 1) return;
                  scrollEditorFromMinimapPointer(
                    event.clientY,
                    event.currentTarget,
                  );
                }}
                onPointerUp={(event) => {
                  minimapDragOffsetRef.current = null;
                  if (event.currentTarget.hasPointerCapture(event.pointerId)) {
                    event.currentTarget.releasePointerCapture(event.pointerId);
                  }
                }}
                onPointerCancel={() => {
                  minimapDragOffsetRef.current = null;
                }}
                onLostPointerCapture={() => {
                  minimapDragOffsetRef.current = null;
                }}
              >
                <div className="studio-code-minimap-track">
                  <div
                    className="studio-code-minimap-content"
                    style={{
                      height: `${minimapContentHeight}px`,
                    }}
                  >
                    {previewLines.map((line, index) => (
                      <span
                        key={`${index}-${line.tone}`}
                        className={`studio-code-minimap-text is-${line.tone}`}
                        style={{
                          paddingInlineStart: `${line.indent * 0.45}ch`,
                          height: `${MINIMAP_LINE_HEIGHT_PX}px`,
                          lineHeight: `${MINIMAP_LINE_HEIGHT_PX}px`,
                        }}
                      >
                        {line.text || "\u00a0"}
                      </span>
                    ))}
                  </div>
                  <div
                    className="studio-code-minimap-viewport"
                    style={{
                      top: `${MINIMAP_TOP_INSET_PX + minimapViewportTop}px`,
                      height: `${minimapViewportHeightPx}px`,
                    }}
                  />
                </div>
              </aside>
            </div>
          ) : null}
        </>
      ) : null}
    </section>
  );
}
