import { useEffect, useMemo, useRef, useState } from "react";
import { CodeOssEditor } from "@ioi/workspace-substrate";
import type { CodeOssStandaloneEditor } from "@ioi/workspace-substrate";
import type {
  ArtifactContentPayload,
  ChatArtifactManifestFile,
} from "../../../types";
import { markWorkspaceMetric } from "../../../services/workspacePerf";

function languageFromHint(hint: string): string | null {
  const normalized = hint.trim().toLowerCase();
  if (!normalized) {
    return null;
  }

  switch (normalized) {
    case "tsx":
    case "typescript":
      return "typescript";
    case "jsx":
    case "javascript":
      return "javascript";
    case "json":
    case "markdown":
    case "rust":
    case "css":
    case "html":
    case "yaml":
    case "xml":
    case "shell":
      return normalized;
    case "toml":
      return "ini";
    default:
      break;
  }

  const mime = normalized.split(";")[0].trim();
  if (!mime.includes("/")) {
    return null;
  }

  if (mime.includes("html")) {
    return "html";
  }
  if (mime.includes("css")) {
    return "css";
  }
  if (mime.includes("json")) {
    return "json";
  }
  if (mime.includes("markdown")) {
    return "markdown";
  }
  if (mime.includes("yaml") || mime.includes("yml")) {
    return "yaml";
  }
  if (mime.includes("xml") || mime.includes("svg")) {
    return "xml";
  }
  if (mime.includes("javascript") || mime.includes("ecmascript")) {
    return "javascript";
  }
  if (mime.includes("typescript")) {
    return "typescript";
  }
  if (mime.includes("shell") || mime.includes("bash") || mime.includes("sh")) {
    return "shell";
  }
  if (mime.includes("toml")) {
    return "ini";
  }
  if (mime.includes("rust")) {
    return "rust";
  }

  return null;
}

function languageForSourcePath(path: string, hint?: string | null): string {
  if (hint) {
    const language = languageFromHint(hint);
    if (language) {
      return language;
    }
  }

  const extension = path.split(".").pop()?.toLowerCase();
  switch (extension) {
    case "ts":
    case "tsx":
      return "typescript";
    case "js":
    case "jsx":
      return "javascript";
    case "json":
      return "json";
    case "md":
      return "markdown";
    case "rs":
      return "rust";
    case "css":
      return "css";
    case "html":
    case "htm":
      return "html";
    case "yaml":
    case "yml":
      return "yaml";
    case "sh":
    case "bash":
      return "shell";
    case "toml":
      return "ini";
    default:
      return "plaintext";
  }
}

interface ArtifactSourceWorkbenchProps {
  artifactId: string;
  files: ChatArtifactManifestFile[];
  selectedFile: ChatArtifactManifestFile | null;
  payload: ArtifactContentPayload | null;
  loading: boolean;
  error: string | null;
  onSelectPath: (path: string) => void;
  onAttachSelection?: (payload: { path: string; selection: string }) => void;
  showExplorer?: boolean;
  sourceTextOverride?: string | null;
  binaryOverride?: boolean;
  tooLargeOverride?: boolean;
}

function decodePayloadText(
  payload: ArtifactContentPayload | null,
  sourceTextOverride?: string | null,
): string {
  if (typeof sourceTextOverride === "string") {
    return sourceTextOverride;
  }
  if (!payload) {
    return "";
  }
  if (payload.encoding === "base64") {
    try {
      return window.atob(payload.content);
    } catch {
      return "";
    }
  }
  return payload.content;
}

function decodeExternalUrlText(url?: string | null): string | null {
  if (!url || !url.startsWith("data:")) {
    return null;
  }
  const commaIndex = url.indexOf(",");
  if (commaIndex < 0) {
    return null;
  }
  const meta = url.slice(5, commaIndex);
  const content = url.slice(commaIndex + 1);
  try {
    if (meta.includes(";base64")) {
      return window.atob(content);
    }
    return decodeURIComponent(content);
  } catch {
    return null;
  }
}

function isBinaryMime(mime: string): boolean {
  const normalized = mime.trim().toLowerCase();
  if (!normalized) {
    return false;
  }

  if (normalized.startsWith("text/")) {
    return false;
  }

  if (
    normalized.includes("json") ||
    normalized.includes("javascript") ||
    normalized.includes("typescript") ||
    normalized.includes("xml") ||
    normalized.includes("yaml") ||
    normalized.includes("svg") ||
    normalized.includes("html") ||
    normalized.includes("markdown")
  ) {
    return false;
  }

  return true;
}

function syncSelectionText(setSelectionText: (value: string) => void) {
  const nextSelection = window.getSelection()?.toString().trim() ?? "";
  setSelectionText(nextSelection);
}

export function ArtifactSourceWorkbench({
  artifactId,
  files,
  selectedFile,
  payload,
  loading,
  error,
  onAttachSelection,
  sourceTextOverride,
  binaryOverride,
  tooLargeOverride,
}: ArtifactSourceWorkbenchProps) {
  const [selectionText, setSelectionText] = useState("");
  const editorRef = useRef<CodeOssStandaloneEditor | null>(null);
  const requestedMetricPathRef = useRef<string | null>(null);

  const sourceText = useMemo(
    () =>
      decodePayloadText(
        payload,
        sourceTextOverride ?? decodeExternalUrlText(selectedFile?.externalUrl),
      ),
    [payload, selectedFile?.externalUrl, sourceTextOverride],
  );
  const fileCount = files.length;
  const mime = selectedFile?.mime ?? "text/plain";
  const sourceLanguage = selectedFile
    ? languageForSourcePath(selectedFile.path, mime)
    : "plaintext";
  const isBinary = binaryOverride ?? (selectedFile ? isBinaryMime(mime) : false);
  const canAttachSelection =
    Boolean(onAttachSelection) &&
    Boolean(selectedFile?.path) &&
    !isBinary &&
    !tooLargeOverride &&
    selectionText.trim().length > 0;
  const pathSegments = selectedFile?.path.split("/").filter(Boolean) ?? [];

  useEffect(() => {
    if (!selectedFile?.path || requestedMetricPathRef.current === selectedFile.path) {
      return;
    }

    requestedMetricPathRef.current = selectedFile.path;
    markWorkspaceMetric("artifact_editor_requested", {
      artifactId,
      path: selectedFile.path,
      mime,
      runtime: "code-oss",
    });
  }, [artifactId, mime, selectedFile?.path]);

  const syncEditorSelection = () => {
    const editor = editorRef.current;
    const model = editor?.getModel();
    const selection = editor?.getSelection();
    if (!editor || !model || !selection) {
      syncSelectionText(setSelectionText);
      return;
    }
    const selected = model.getValueInRange(selection).trim();
    setSelectionText(selected || window.getSelection()?.toString().trim() || "");
  };

  return (
    <section className="chat-artifact-source-workbench">
      <div className="chat-artifact-source-surface">
        <div className="chat-artifact-source-editor-shell">
          <header className="chat-artifact-source-editor-tabs" aria-label="Source tabs">
            <div className="chat-artifact-source-editor-tab is-active">
              <span className="chat-artifact-source-editor-tab-icon">&lt;&gt;</span>
              <span className="chat-artifact-source-editor-tab-label">
                {selectedFile?.path ?? "Source unavailable"}
              </span>
            </div>
            {onAttachSelection ? (
              <button
                type="button"
                className="chat-artifact-source-action"
                onClick={() => {
                  if (!selectedFile || !selectionText.trim()) {
                    return;
                  }
                  onAttachSelection({
                    path: selectedFile.path,
                    selection: selectionText.trim(),
                  });
                }}
                disabled={!canAttachSelection}
              >
                Attach selection
              </button>
            ) : null}
          </header>

          <div className="chat-artifact-source-breadcrumbs" aria-label="Source breadcrumbs">
            {pathSegments.length ? (
              pathSegments.map((segment, index) => (
                <span key={`${segment}-${index}`} className="chat-artifact-source-breadcrumb">
                  {segment}
                </span>
              ))
            ) : (
              <span className="chat-artifact-source-breadcrumb">Source</span>
            )}
          </div>

          <div className="chat-artifact-source-surface-main">
            {error ? (
              <div className="chat-artifact-banner is-error">{error}</div>
            ) : loading ? (
              <div className="chat-artifact-renderer-empty">
                <strong>Loading source…</strong>
              </div>
            ) : !selectedFile ? (
              <div className="chat-artifact-renderer-empty">
                <strong>No source file selected.</strong>
              </div>
            ) : isBinary ? (
              <div className="chat-artifact-renderer-empty">
                <strong>Binary source</strong>
                <p>{selectedFile.path} is binary, so Chat keeps it as metadata only.</p>
              </div>
            ) : tooLargeOverride ? (
              <div className="chat-artifact-renderer-empty">
                <strong>Source preview too large</strong>
                <p>{selectedFile.path} is too large for inline viewing in Chat.</p>
              </div>
            ) : (
              <div className="chat-artifact-source-editor-stage">
                <CodeOssEditor
                  key={selectedFile.path}
                  path={selectedFile.path}
                  value={sourceText}
                  language={sourceLanguage}
                  options={{
                    automaticLayout: true,
                    readOnly: true,
                    fontSize: 13,
                    lineHeight: 21,
                    colorDecorators: true,
                    defaultColorDecorators: "always",
                    colorDecoratorsActivatedOn: "clickAndHover",
                    wordWrap: "off",
                    minimap: {
                      enabled: true,
                      side: "right",
                    },
                    scrollBeyondLastLine: false,
                    renderWhitespace: "selection",
                    smoothScrolling: true,
                    glyphMargin: false,
                    folding: true,
                    rulers: [],
                    padding: {
                      top: 12,
                      bottom: 12,
                    },
                    stickyScroll: {
                      enabled: false,
                    },
                  }}
                  onMount={(editor: CodeOssStandaloneEditor) => {
                    editorRef.current = editor;
                    markWorkspaceMetric("artifact_editor_ready", {
                      artifactId,
                      path: selectedFile.path,
                      runtime: "code-oss",
                    });
                    const selectionDisposable = editor.onDidChangeCursorSelection(() => {
                      syncEditorSelection();
                    });
                    const blurDisposable = editor.onDidBlurEditorWidget(() => {
                      syncEditorSelection();
                    });
                    return () => {
                      selectionDisposable.dispose();
                      blurDisposable.dispose();
                    };
                  }}
                />
              </div>
            )}
          </div>

          <footer className="chat-artifact-source-statusbar">
            <span>{artifactId.slice(0, 12)}</span>
            <span>{mime}</span>
            <span>
              {fileCount} {fileCount === 1 ? "file" : "files"}
            </span>
          </footer>
        </div>
      </div>
    </section>
  );
}
