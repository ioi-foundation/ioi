import { invoke } from "@tauri-apps/api/core";
import { save } from "@tauri-apps/plugin-dialog";
import { openPath } from "@tauri-apps/plugin-opener";
import { useEffect, useMemo, useState } from "react";
import {
  type WorkspaceActivityEntry,
  type WorkspaceOpenRequest,
} from "@ioi/workspace-substrate";
import type {
  ArtifactContentPayload,
  ChatArtifactManifestFile,
  ChatRendererKind,
  ChatRendererSession,
} from "../../../types";
import { MarkdownMessage } from "./MarkdownMessage";

export interface ArtifactRendererHostProps {
  renderer: ChatRendererKind;
  title: string;
  file?: ChatArtifactManifestFile | null;
  files?: ChatArtifactManifestFile[];
  payload?: ArtifactContentPayload | null;
  rendererSession?: ChatRendererSession | null;
  requestedOpen?: WorkspaceOpenRequest | null;
  onWorkspaceActivityChange?: (activity: WorkspaceActivityEntry[]) => void;
  onWorkspacePathChange?: (path: string | null) => void;
  onAttachSelection?: (payload: { path: string; selection: string }) => void;
}

function payloadText(payload?: ArtifactContentPayload | null): string {
  if (!payload) return "";
  if (payload.encoding === "base64") {
    try {
      return window.atob(payload.content);
    } catch {
      return "";
    }
  }
  return payload.content;
}

function decodeDataUriText(uri?: string | null): string {
  if (!uri || !uri.startsWith("data:")) {
    return "";
  }
  const commaIndex = uri.indexOf(",");
  if (commaIndex < 0) {
    return "";
  }
  const meta = uri.slice(5, commaIndex);
  const content = uri.slice(commaIndex + 1);
  try {
    if (meta.includes(";base64")) {
      return window.atob(content);
    }
    return decodeURIComponent(content);
  } catch {
    return "";
  }
}

function payloadDataUri(
  payload: ArtifactContentPayload | null | undefined,
  mime: string | undefined,
): string | null {
  if (!payload) return null;
  const resolvedMime = mime || "application/octet-stream";
  if (payload.encoding === "base64") {
    return `data:${resolvedMime};base64,${payload.content}`;
  }
  return `data:${resolvedMime};charset=utf-8,${encodeURIComponent(payload.content)}`;
}

function isTextLikeMime(mime: string | undefined): boolean {
  if (!mime) {
    return true;
  }
  const normalized = mime.toLowerCase();
  return (
    normalized.startsWith("text/") ||
    normalized.includes("json") ||
    normalized.includes("javascript") ||
    normalized.includes("xml") ||
    normalized === "image/svg+xml"
  );
}

function clampSelection(selection: string): string {
  const trimmed = selection.trim().replace(/\s+/g, " ");
  if (trimmed.length <= 320) {
    return trimmed;
  }
  return `${trimmed.slice(0, 317).trimEnd()}...`;
}

function selectionBridgeSrcDoc(srcDoc: string, artifactPath: string) {
  const bridge = `
<script>
(() => {
  let timeoutId = null;
  const publish = () => {
    const text = (window.getSelection && window.getSelection()) ? window.getSelection().toString().trim() : "";
    window.parent.postMessage({
      __studioArtifactSelection: true,
      artifactPath: ${JSON.stringify(artifactPath)},
      selection: text,
    }, "*");
  };
  const queuePublish = () => {
    window.clearTimeout(timeoutId);
    timeoutId = window.setTimeout(publish, 60);
  };
  document.addEventListener("mouseup", queuePublish);
  document.addEventListener("keyup", queuePublish);
  document.addEventListener("selectionchange", queuePublish);
})();
</script>`;

  if (srcDoc.includes("</body>")) {
    return srcDoc.replace("</body>", `${bridge}</body>`);
  }
  return `${srcDoc}${bridge}`;
}

function JsxSandboxFrame({
  source,
  title,
  artifactPath,
}: {
  source: string;
  title: string;
  artifactPath: string;
}) {
  const srcDoc = useMemo(
    () => `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${title}</title>
    <style>
      html, body, #root { height: 100%; margin: 0; }
      body { font-family: system-ui, sans-serif; background: #0f172a; color: white; }
    </style>
  </head>
  <body>
    <div id="root"></div>
    <script crossorigin src="https://unpkg.com/react@18/umd/react.production.min.js"></script>
    <script crossorigin src="https://unpkg.com/react-dom@18/umd/react-dom.production.min.js"></script>
    <script src="https://unpkg.com/@babel/standalone/babel.min.js"></script>
    <script type="text/babel" data-presets="react">
${source}
const candidate = typeof Artifact === "function" ? Artifact : (typeof App === "function" ? App : (typeof exports !== "undefined" && exports.default ? exports.default : null));
if (candidate) {
  ReactDOM.createRoot(document.getElementById("root")).render(React.createElement(candidate));
} else {
  document.getElementById("root").innerHTML = "<pre style=\\"padding:16px;white-space:pre-wrap;\\">JSX source is available in the Source tab, but no default export could be mounted.</pre>";
}
    </script>
  </body>
</html>`,
    [source, title],
  );

  return (
    <iframe
      className="chat-artifact-embed-frame"
      title={title}
      srcDoc={selectionBridgeSrcDoc(srcDoc, artifactPath)}
    />
  );
}

function MermaidFrame({
  code,
  title,
  artifactPath,
}: {
  code: string;
  title: string;
  artifactPath: string;
}) {
  const srcDoc = useMemo(
    () => `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${title}</title>
    <style>
      body { margin: 0; padding: 24px; font-family: system-ui, sans-serif; background: white; color: #0f172a; }
      pre { white-space: pre-wrap; }
    </style>
  </head>
  <body>
    <div class="mermaid">
${code}
    </div>
    <script type="module">
      import mermaid from "https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs";
      mermaid.initialize({ startOnLoad: true, securityLevel: "loose", theme: "default" });
    </script>
  </body>
</html>`,
    [code, title],
  );

  return (
    <iframe
      className="chat-artifact-embed-frame"
      title={title}
      srcDoc={selectionBridgeSrcDoc(srcDoc, artifactPath)}
    />
  );
}

export function ArtifactRendererHost({
  renderer,
  title,
  file,
  files = [],
  payload,
  rendererSession,
  onAttachSelection,
}: ArtifactRendererHostProps) {
  const text = payloadText(payload) || decodeDataUriText(file?.externalUrl);
  const dataUri = payloadDataUri(payload, file?.mime) || file?.externalUrl || null;
  const downloadFiles = files.filter((entry) => entry.downloadable);
  const renderableFiles = files.filter((entry) => entry.renderable);
  const artifactPath = file?.path ?? renderableFiles[0]?.path ?? `${renderer}.render`;
  const [selection, setSelection] = useState("");
  const [downloadActionPending, setDownloadActionPending] = useState<
    "save" | "open" | null
  >(null);
  const [downloadActionError, setDownloadActionError] = useState<string | null>(null);
  const selectedDownloadArtifactId = file?.artifactId ?? null;
  const selectedDownloadPath = file?.path ?? `${title}.bin`;
  const selectedDownloadIsBinary =
    renderer === "download_card" &&
    Boolean(file?.downloadable) &&
    !isTextLikeMime(file?.mime);

  useEffect(() => {
    setSelection("");
  }, [artifactPath, renderer, payload?.content]);

  useEffect(() => {
    setDownloadActionPending(null);
    setDownloadActionError(null);
  }, [file?.artifactId, file?.path, payload?.artifact_id, renderer]);

  useEffect(() => {
    if (!onAttachSelection) {
      return;
    }
    const listener = (event: MessageEvent) => {
      const payload = event.data;
      if (
        !payload ||
        payload.__studioArtifactSelection !== true ||
        payload.artifactPath !== artifactPath
      ) {
        return;
      }
      setSelection(clampSelection(String(payload.selection ?? "")));
    };
    window.addEventListener("message", listener);
    return () => window.removeEventListener("message", listener);
  }, [artifactPath, onAttachSelection]);

  useEffect(() => {
    const listener = (event: MessageEvent) => {
      const payload = event.data;
      if (!payload || payload.__studioWidgetState !== true) {
        return;
      }
      const widgetState = payload.widgetState;
      if (!widgetState || typeof widgetState !== "object" || Array.isArray(widgetState)) {
        return;
      }
      void invoke("chat_attach_widget_state", { widgetState });
    };
    window.addEventListener("message", listener);
    return () => window.removeEventListener("message", listener);
  }, []);

  const selectionAction =
    selection && onAttachSelection ? (
      <div className="chat-artifact-render-selection">
        <p>{selection}</p>
        <button
          type="button"
          className="chat-artifact-stage-button"
          onClick={() => onAttachSelection({ path: artifactPath, selection })}
        >
          Attach render selection
        </button>
      </div>
    ) : null;

  const handleSaveDownload = async () => {
    if (!selectedDownloadArtifactId) {
      return;
    }
    const outputPath = await save({
      title: `Save ${selectedDownloadPath}`,
      defaultPath: selectedDownloadPath,
    });
    if (!outputPath) {
      return;
    }
    setDownloadActionPending("save");
    setDownloadActionError(null);
    try {
      await invoke<string>("save_artifact_content", {
        artifactId: selectedDownloadArtifactId,
        artifact_id: selectedDownloadArtifactId,
        outputPath,
        output_path: outputPath,
      });
    } catch (error) {
      setDownloadActionError(
        error instanceof Error ? error.message : "Failed to save artifact.",
      );
    } finally {
      setDownloadActionPending(null);
    }
  };

  const handleOpenDownload = async () => {
    if (!selectedDownloadArtifactId) {
      return;
    }
    setDownloadActionPending("open");
    setDownloadActionError(null);
    try {
      const tempPath = await invoke<string>("materialize_artifact_content_to_temp", {
        artifactId: selectedDownloadArtifactId,
        artifact_id: selectedDownloadArtifactId,
        suggestedName: selectedDownloadPath,
        suggested_name: selectedDownloadPath,
      });
      await openPath(tempPath);
    } catch (error) {
      setDownloadActionError(
        error instanceof Error ? error.message : "Failed to open artifact.",
      );
    } finally {
      setDownloadActionPending(null);
    }
  };

  if (renderer === "workspace_surface") {
    if (rendererSession?.previewUrl) {
      return (
        <iframe
          className="chat-artifact-embed-frame"
          title={title}
          src={rendererSession.previewUrl}
        />
      );
    }

    if (!rendererSession?.workspaceRoot) {
      return (
        <div className="chat-artifact-renderer-empty">
          <strong>Workspace renderer unavailable.</strong>
          <p>Chat has not finished materializing the workspace session yet.</p>
        </div>
      );
    }

    return (
      <div className="chat-artifact-renderer-empty">
        <strong>Render surface pending verification.</strong>
        <p>
          Chat has the workspace session, but preview is not verified yet. Switch to
          Source to inspect the materialized code while verification continues.
        </p>
      </div>
    );
  }

  if (renderer === "markdown") {
    return (
      <div
        className="chat-artifact-renderer-panel"
        onMouseUp={() => setSelection(clampSelection(window.getSelection?.()?.toString() ?? ""))}
      >
        <MarkdownMessage text={text || "No markdown content available."} />
        {selectionAction}
      </div>
    );
  }

  if (renderer === "html_iframe") {
    return (
      <div className="chat-artifact-renderer-panel">
        <iframe
          className="chat-artifact-embed-frame"
          title={title}
          srcDoc={selectionBridgeSrcDoc(text || "<p>No HTML content available.</p>", artifactPath)}
        />
        {selectionAction}
      </div>
    );
  }

  if (renderer === "jsx_sandbox") {
    return (
      <div className="chat-artifact-renderer-panel">
        <JsxSandboxFrame
          source={text || "export default function Artifact() { return null; }"}
          title={title}
          artifactPath={artifactPath}
        />
        {selectionAction}
      </div>
    );
  }

  if (renderer === "svg") {
    return (
      <div className="chat-artifact-renderer-panel">
        <div
          className="chat-artifact-renderer-svg"
          onMouseUp={() => setSelection(clampSelection(window.getSelection?.()?.toString() ?? ""))}
          dangerouslySetInnerHTML={{ __html: text || "<svg></svg>" }}
        />
        {selectionAction}
      </div>
    );
  }

  if (renderer === "mermaid") {
    return (
      <div className="chat-artifact-renderer-panel">
        <MermaidFrame code={text || "flowchart TD\nA[Empty]"} title={title} artifactPath={artifactPath} />
        {selectionAction}
      </div>
    );
  }

  if (renderer === "pdf_embed") {
    if (!dataUri) {
      return (
        <div className="chat-artifact-renderer-empty">
          <strong>PDF not available.</strong>
        </div>
      );
    }
    return <iframe className="chat-artifact-embed-frame" title={title} src={dataUri} />;
  }

  if (renderer === "bundle_manifest") {
    return (
      <div className="chat-artifact-renderer-panel">
        <div className="chat-artifact-download-card">
          <header className="chat-artifact-download-card-head">
            <div>
              <span className="chat-artifact-panel-label">Bundle manifest</span>
              <h3>{title}</h3>
            </div>
            <div className="chat-artifact-chip-row">
              <span className="chat-artifact-chip">
                {files.length} {files.length === 1 ? "file" : "files"}
              </span>
              <span className="chat-artifact-chip">
                {renderableFiles.length} renderable
              </span>
            </div>
          </header>

          <div className="chat-artifact-download-card-grid">
            <section className="chat-artifact-download-card-list">
              {files.map((entry) => (
                <article key={entry.path} className="chat-artifact-download-row">
                  <strong>{entry.path}</strong>
                  <span>{entry.mime}</span>
                </article>
              ))}
            </section>

            <section className="chat-artifact-download-preview">
              <pre>{text || "No bundle manifest content available."}</pre>
            </section>
          </div>
        </div>
      </div>
    );
  }

  if (renderer === "download_card") {
    return (
      <div className="chat-artifact-renderer-panel">
        <div className="chat-artifact-download-card">
          <header className="chat-artifact-download-card-head">
            <div>
              <span className="chat-artifact-panel-label">Downloadable artifact</span>
              <h3>{title}</h3>
              <p>
                Chat surfaced the files that actually exist for this artifact. Select a file
                in the explorer to preview its source without replacing the primary download view.
              </p>
            </div>
            <div className="chat-artifact-chip-row">
              <span className="chat-artifact-chip">
                {downloadFiles.length} download{downloadFiles.length === 1 ? "" : "s"}
              </span>
              {file?.path ? <span className="chat-artifact-chip">{file.path}</span> : null}
              {selectedDownloadArtifactId ? (
                <button
                  type="button"
                  className="chat-artifact-stage-button"
                  disabled={downloadActionPending !== null}
                  onClick={() => void handleSaveDownload()}
                >
                  {downloadActionPending === "save" ? "Saving..." : "Save As..."}
                </button>
              ) : null}
              {selectedDownloadArtifactId ? (
                <button
                  type="button"
                  className="chat-artifact-stage-button"
                  disabled={downloadActionPending !== null}
                  onClick={() => void handleOpenDownload()}
                >
                  {downloadActionPending === "open" ? "Opening..." : "Open In Default App"}
                </button>
              ) : null}
            </div>
          </header>

          <div className="chat-artifact-download-card-grid">
            <section className="chat-artifact-download-card-list">
              {downloadFiles.map((entry) => (
                <article key={entry.path} className="chat-artifact-download-row">
                  <strong>{entry.path}</strong>
                  <span>{entry.mime}</span>
                </article>
              ))}
            </section>

            <section className="chat-artifact-download-preview">
              {selectedDownloadIsBinary && file ? (
                <div className="chat-artifact-renderer-empty">
                  <strong>{file.path}</strong>
                  <p>
                    Chat is keeping this file as a real binary artifact instead of forcing a text
                    preview. Save it or open it in the default desktop app.
                  </p>
                  <p>{file.mime}</p>
                </div>
              ) : text ? (
                <pre>{text}</pre>
              ) : (
                <div className="chat-artifact-renderer-empty">
                  <strong>Preview a file from the explorer.</strong>
                  <p>Source previews open in the stage while the download surface stays primary.</p>
                </div>
              )}
              {downloadActionError ? (
                <div className="chat-artifact-renderer-empty">
                  <strong>Artifact action failed.</strong>
                  <p>{downloadActionError}</p>
                </div>
              ) : null}
            </section>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="chat-artifact-renderer-empty">
      <strong>Renderer unavailable.</strong>
      <p>{renderer}</p>
    </div>
  );
}
