import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import type {
  Artifact,
  ArtifactContentPayload,
  ChatArtifactManifestFile,
  ChatRendererKind,
} from "../../../types";
import { icons } from "./Icons";
import { ArtifactRendererHost } from "./ArtifactRendererHost";

interface ArtifactSidebarProps {
  artifact: Artifact | null;
  onClose: () => void;
}

function inferRenderer(artifact: Artifact): ChatRendererKind {
  const path = String(artifact.metadata?.path ?? "").toLowerCase();
  const mime = String(artifact.metadata?.mime ?? "").toLowerCase();

  if (path.endsWith(".md") || mime.includes("markdown")) return "markdown";
  if (path.endsWith(".html") || mime.includes("text/html")) return "html_iframe";
  if (path.endsWith(".jsx") || path.endsWith(".tsx") || mime.includes("jsx")) {
    return "jsx_sandbox";
  }
  if (path.endsWith(".svg") || mime.includes("svg")) return "svg";
  if (path.endsWith(".mermaid") || mime.includes("mermaid")) return "mermaid";
  if (path.endsWith(".pdf") || mime.includes("application/pdf")) return "pdf_embed";
  if (artifact.artifact_type === "RUN_BUNDLE" || artifact.artifact_type === "REPORT") {
    return "bundle_manifest";
  }
  return "download_card";
}

export function ArtifactSidebar({ artifact, onClose }: ArtifactSidebarProps) {
  const [payload, setPayload] = useState<ArtifactContentPayload | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      if (!artifact) {
        setPayload(null);
        setError(null);
        return;
      }
      try {
        const nextPayload = await invoke<ArtifactContentPayload | null>("get_artifact_content", {
          artifactId: artifact.artifact_id,
          artifact_id: artifact.artifact_id,
        });
        if (!cancelled) {
          setPayload(nextPayload);
          setError(null);
        }
      } catch (loadError) {
        if (!cancelled) {
          setPayload(null);
          setError(String(loadError));
        }
      }
    };

    void load();
    return () => {
      cancelled = true;
    };
  }, [artifact]);

  const file = useMemo<ChatArtifactManifestFile | null>(() => {
    if (!artifact) {
      return null;
    }
    return {
      path: String(artifact.metadata?.path ?? artifact.title),
      mime: String(artifact.metadata?.mime ?? "text/plain"),
      role: "primary",
      renderable: true,
      downloadable: true,
      artifactId: artifact.artifact_id,
      externalUrl: null,
    };
  }, [artifact]);

  if (!artifact) return null;

  return (
    <div className="artifact-panel">
      <div className="artifact-header">
        <div className="artifact-meta">
          <div className="artifact-icon">{icons.code}</div>
          <span className="artifact-filename">{artifact.title}</span>
          <span className="artifact-tag">{artifact.artifact_type}</span>
        </div>
        <div className="artifact-actions">
          <button className="artifact-action-btn close" onClick={onClose} title="Close panel">
            {icons.close}
          </button>
        </div>
      </div>
      <div className="artifact-content">
        {error ? <div className="chat-artifact-banner is-error">{error}</div> : null}
        <ArtifactRendererHost
          renderer={inferRenderer(artifact)}
          title={artifact.title}
          file={file}
          payload={payload}
        />
      </div>
    </div>
  );
}
