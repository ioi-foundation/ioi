import { useState, useEffect, useRef } from "react";
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
  onOpen?: () => void;
  onRun?: () => void;
  onZoomIn?: () => void;
  onZoomOut?: () => void;
  onFit?: () => void;
}

const MENU_LABELS = ["File", "Edit", "View", "Tools", "Window", "Help"];

export function IDEHeader({
  projectPath,
  projectName,
  mode,
  onModeChange,
  isComposeView,
  onSave,
  onOpen,
  onRun,
  onZoomIn,
  onZoomOut,
  onFit,
}: IDEHeaderProps) {
  const [liability, setLiability] = useState("Optional");
  const [receipts, setReceipts] = useState(true);
  const [activeMenu, setActiveMenu] = useState<string | null>(null);
  const menuRef = useRef<HTMLDivElement>(null);

  // Close menu when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(event.target as Node)) {
        setActiveMenu(null);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  const handleMenuClick = (menu: string) => {
    setActiveMenu(activeMenu === menu ? null : menu);
  };

  const toggleGhostMode = () => {
    // Toggle between GHOST and the previous mode (defaulting to COMPOSE)
    onModeChange(mode === "GHOST" ? "COMPOSE" : "GHOST");
    setActiveMenu(null);
  };

  return (
    <header className="ide-header">
      {/* Row 1: Menu Bar */}
      <div className="header-row header-nav">
        <div className="header-left">
          <div className="menubar" ref={menuRef}>
            {MENU_LABELS.map((item) => (
              <div key={item} className="menu-wrapper">
                <div
                  className={`menu-item ${activeMenu === item ? "active" : ""}`}
                  onClick={() => handleMenuClick(item)}
                >
                  {item}
                </div>
                
                {/* Tools Dropdown */}
                {activeMenu === item && item === "Tools" && (
                  <div className="menu-dropdown">
                    <button className="menu-dropdown-item" onClick={toggleGhostMode}>
                      <span className="menu-icon">{mode === "GHOST" ? "✓" : ""}</span>
                      <span>Ghost Mode (Record)</span>
                      <span className="menu-shortcut">Ctrl+G</span>
                    </button>
                    <div className="menu-separator" />
                    <button className="menu-dropdown-item">
                      <span className="menu-icon"></span>
                      <span>Generate API Key...</span>
                    </button>
                    <button className="menu-dropdown-item">
                      <span className="menu-icon"></span>
                      <span>Manage Drivers...</span>
                    </button>
                  </div>
                )}

                {/* File Dropdown (Stub) */}
                {activeMenu === item && item === "File" && (
                  <div className="menu-dropdown">
                    <button className="menu-dropdown-item" onClick={onSave}>
                      <span className="menu-icon">💾</span>
                      <span>Save Project</span>
                      <span className="menu-shortcut">⌘S</span>
                    </button>
                    <button className="menu-dropdown-item" onClick={onOpen}>
                      <span className="menu-icon">📂</span>
                      <span>Open...</span>
                      <span className="menu-shortcut">⌘O</span>
                    </button>
                  </div>
                )}
                
                 {/* View Dropdown (Stub) */}
                 {activeMenu === item && item === "View" && (
                  <div className="menu-dropdown">
                    <button className="menu-dropdown-item" onClick={onZoomIn}>
                      <span className="menu-icon">➕</span>
                      <span>Zoom In</span>
                      <span className="menu-shortcut">⌘+</span>
                    </button>
                    <button className="menu-dropdown-item" onClick={onZoomOut}>
                      <span className="menu-icon">➖</span>
                      <span>Zoom Out</span>
                      <span className="menu-shortcut">⌘-</span>
                    </button>
                     <button className="menu-dropdown-item" onClick={onFit}>
                      <span className="menu-icon">⤢</span>
                      <span>Fit Canvas</span>
                      <span className="menu-shortcut">⌘1</span>
                    </button>
                  </div>
                )}
              </div>
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
              <ToolbarButton icon="📂" label="Open" onClick={onOpen} />
              <ToolbarButton icon="💾" label="Save" onClick={onSave} />
            </ToolbarGroup>

            {/* View/Zoom */}
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
              {/* Mode Switcher - Ghost is removed from here */}
              <div className="mode-pills" style={{ marginRight: 8 }}>
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
                
                {/* Visual Indicator if Ghost is active via Tools menu */}
                {mode === "GHOST" && (
                    <div style={{
                        fontSize: 10, 
                        color: '#ef4444', 
                        padding: '0 8px', 
                        display: 'flex', 
                        alignItems: 'center', 
                        gap: 4, 
                        fontWeight: 600,
                        borderLeft: '1px solid #ccc',
                        marginLeft: 4
                    }}>
                        <span style={{
                            width: 6, height: 6, borderRadius: '50%', background: '#ef4444',
                            animation: 'pulse 1s infinite'
                        }}/>
                        REC
                    </div>
                )}
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