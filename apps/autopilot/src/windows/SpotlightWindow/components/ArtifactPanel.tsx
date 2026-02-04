import React, { useMemo } from "react";
import { icons } from "./Icons";
import "../styles/ArtifactPanel.css";

interface ArtifactPanelProps {
  fileName?: string;
  language?: string;
  content?: string;
  onClose: () => void;
}

export function ArtifactPanel({ 
  fileName = "main.tsx", 
  language = "typescript", 
  content = "// Code content goes here...", 
  onClose 
}: ArtifactPanelProps) {
  
  // Split content into lines for line numbers
  const lines = useMemo(() => content.split('\n'), [content]);
  
  const handleCopy = async () => {
    await navigator.clipboard.writeText(content);
    // Could add a toast notification here
  };

  return (
    <div className="artifact-panel">
      <div className="artifact-header">
        <div className="artifact-meta">
          <div className="artifact-icon">{icons.code}</div>
          <span className="artifact-filename">{fileName}</span>
          <span className="artifact-tag">Generated</span>
        </div>
        <div className="artifact-actions">
          <button 
            className="artifact-action-btn" 
            title="Copy code"
            onClick={handleCopy}
          >
            {icons.copy}
          </button>
          <button 
            className="artifact-action-btn close" 
            onClick={onClose} 
            title="Close panel"
          >
            {icons.close}
          </button>
        </div>
      </div>
      
      <div className="artifact-content">
        <div className="code-block">
          <pre>
            <code>
              {lines.map((line, i) => (
                <div key={i} className="code-line">
                  <span className="line-number">{i + 1}</span>
                  <span className="line-content">{line}</span>
                </div>
              ))}
            </code>
          </pre>
        </div>
      </div>
    </div>
  );
}