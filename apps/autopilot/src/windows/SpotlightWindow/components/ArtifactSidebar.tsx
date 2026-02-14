import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { Artifact, ArtifactContentPayload } from "../../../types";
import { icons } from "./Icons";
import { DiffArtifactView } from "./artifacts/DiffArtifactView";
import { FileArtifactView } from "./artifacts/FileArtifactView";
import { WebArtifactView } from "./artifacts/WebArtifactView";
import { RunBundleView } from "./artifacts/RunBundleView";
import { LogArtifactView } from "./artifacts/LogArtifactView";

interface ArtifactSidebarProps {
  artifact: Artifact | null;
  onClose: () => void;
}

export function ArtifactSidebar({ artifact, onClose }: ArtifactSidebarProps) {
  const [content, setContent] = useState<string>("");

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      if (!artifact) {
        setContent("");
        return;
      }
      try {
        const payload = await invoke<ArtifactContentPayload | null>("get_artifact_content", {
          artifactId: artifact.artifact_id,
          artifact_id: artifact.artifact_id,
        });
        if (!cancelled) {
          setContent(payload?.content || "");
        }
      } catch (e) {
        if (!cancelled) setContent(`Failed to load artifact content: ${e}`);
      }
    };
    void load();
    return () => {
      cancelled = true;
    };
  }, [artifact]);

  const viewer = useMemo(() => {
    if (!artifact) return null;
    switch (artifact.artifact_type) {
      case "DIFF":
        return <DiffArtifactView content={content} />;
      case "FILE":
        return <FileArtifactView content={content} />;
      case "WEB":
        return <WebArtifactView content={content} />;
      case "RUN_BUNDLE":
      case "REPORT":
        return <RunBundleView content={content} />;
      case "LOG":
      default:
        return <LogArtifactView content={content} />;
    }
  }, [artifact, content]);

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
      <div className="artifact-content">{viewer}</div>
    </div>
  );
}
