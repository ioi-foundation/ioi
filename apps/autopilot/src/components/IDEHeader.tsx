import { useState } from "react";
import "./IDEHeader.css";

export type InterfaceMode = "GHOST" | "AGENT" | "COMPOSE";

interface IDEHeaderProps {
  projectPath: string;
  projectName: string;
  branch?: string;
  mode: InterfaceMode;
  onModeChange: (mode: InterfaceMode) => void;
  isComposeView: boolean;
  onSave?: () => void;
  onDiscard?: () => void;
  onShare?: () => void;
  onRun?: () => void;
  hasUnsavedChanges?: boolean;
  
  // New props for canvas control linking
  onZoomIn?: () => void;
  onZoomOut?: () => void;
  onFit?: () => void;
}

// Mixed case strings, CSS will strictly respect this now
const MENU_ITEMS = ["File", "Edit", "View", "Insert", "Tools", "Window", "Help"];

export function IDEHeader({
  projectPath,
  projectName,
  branch = "main",
  mode,
  onModeChange,
  isComposeView,
  onSave,
  onRun,
  onZoomIn,
  onZoomOut,
  onFit,
}: IDEHeaderProps) {
  const [liability, setLiability] = useState("Optional");
  const [receipts, setReceipts] = useState(true);

  return (
    <header className="ide-header">
      {/* Row 1: Menu Bar */}
      <div className="header-row header-nav">
        <div className="header-left">
          <div className="menubar">
            {MENU_ITEMS.map(item => (
              <div key={item} className="menu-item">{item}</div>
            ))}
          </div>
        </div>
      </div>

      {/* Row 2: Toolbar - Only in Compose view */}
      {isComposeView && (
      <div className="header-row header-toolbar">
        <div className="toolbar-section">
          {/* File Operations */}
          <ToolbarGroup>
            <ToolbarButton icon="📄" label="New" />
            <ToolbarButton icon="📂" label="Open" />
            <ToolbarButton icon="💾" label="Save" onClick={onSave} />
          </ToolbarGroup>
          
          {/* Edit Operations */}
          <ToolbarGroup>
            <ToolbarButton icon="✂️" label="Cut" />
            <ToolbarButton icon="📋" label="Copy" />
            <ToolbarButton icon="📋" label="Paste" />
          </ToolbarGroup>

          {/* View/Zoom - Linked to Canvas */}
          <ToolbarGroup>
            <ToolbarButton icon="➕" label="Zoom In" onClick={onZoomIn} />
            <ToolbarButton icon="➖" label="Zoom Out" onClick={onZoomOut} />
            <ToolbarButton icon="⤢" label="Fit" onClick={onFit} />
          </ToolbarGroup>

          {/* Config Controls */}
          <ToolbarGroup>
            <div className="toolbar-combo">
              <label>Liability:</label>
              <select value={liability} onChange={(e) => setLiability(e.target.value)}>
                <option>None</option>
                <option>Optional</option>
                <option>Required</option>
              </select>
            </div>
            <ToolbarButton 
              icon={receipts ? "☑️" : "☐"} 
              label="Receipts" 
              onClick={() => setReceipts(!receipts)} 
              active={receipts}
            />
          </ToolbarGroup>
        </div>

        <div className="toolbar-section toolbar-right">
          <ToolbarGroup>
            {/* Mode Switcher */}
            <div className="mode-pills" style={{ marginRight: 8 }}>
              <button 
                className={`mode-pill ${mode === "GHOST" ? "active ghost" : ""}`}
                onClick={() => onModeChange("GHOST")}
                title="Ghost Mode"
              >
                <span className="mode-dot" />
                Ghost
              </button>
              <button 
                className={`mode-pill ${mode === "AGENT" ? "active" : ""}`}
                onClick={() => onModeChange("AGENT")}
              >
                Agent
              </button>
              <button 
                className={`mode-pill ${mode === "COMPOSE" ? "active" : ""}`}
                onClick={() => onModeChange("COMPOSE")}
              >
                Compose
              </button>
            </div>
          </ToolbarGroup>

          {/* Run Button */}
          <div className="run-controls">
            <button className="run-btn" onClick={onRun} title="Run Workflow (F5)">
              <svg width="10" height="10" viewBox="0 0 24 24" fill="currentColor">
                <polygon points="5,3 19,12 5,21" />
              </svg>
              Run
            </button>
          </div>
        </div>
      </div>
      )}
    </header>
  );
}

// Toolbar Sub-components
function ToolbarGroup({ children }: { children: React.ReactNode }) {
  return <div className="toolbar-group">{children}</div>;
}

interface ToolbarButtonProps {
  icon: string;
  label: string;
  shortcut?: string;
  active?: boolean;
  onClick?: () => void;
}

function ToolbarButton({ icon, label, shortcut, active, onClick }: ToolbarButtonProps) {
  return (
    <button 
      className={`toolbar-btn ${active ? "active" : ""}`}
      onClick={onClick}
      title={shortcut ? `${label} (${shortcut})` : label}
    >
      <span className="toolbar-icon">{icon}</span>
    </button>
  );
}