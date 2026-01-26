import { useState, useEffect, useRef } from "react";
import "./IDEHeader.css";

interface IDEHeaderProps {
  projectPath?: string;
  projectName?: string;
  onSave?: () => void;
  onOpen?: () => void;
  onRun?: () => void;
  onZoomIn?: () => void;
  onZoomOut?: () => void;
  onFit?: () => void;
  onBack?: () => void;
}

const MENU_LABELS = ["File", "Edit", "View", "Tools", "Window", "Help"];

export function IDEHeader({
  projectPath,
  projectName,
  onSave,
  onOpen,
  onRun,
  onZoomIn,
  onZoomOut,
  onFit,
  onBack,
}: IDEHeaderProps) {
  const [receipts, setReceipts] = useState(true);
  const [activeMenu, setActiveMenu] = useState<string | null>(null);
  const menuRef = useRef<HTMLDivElement>(null);

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

  return (
    <header className="ide-header">
      {/* Row 1: Menu Bar & Breadcrumbs */}
      <div className="header-row header-nav">
        <div className="header-left">
          
          <div className="menubar" ref={menuRef} style={{ marginRight: 24, paddingLeft: 8 }}>
            {MENU_LABELS.map((item) => (
              <div key={item} className="menu-wrapper">
                <div
                  className={`menu-item ${activeMenu === item ? "active" : ""}`}
                  onClick={() => handleMenuClick(item)}
                >
                  {item}
                </div>
                
                {/* File Dropdown */}
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
                
                 {/* View Dropdown */}
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

          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            {/* Only render breadcrumb path if provided */}
            {projectPath && (
              <button 
                className="topbar-path" 
                onClick={onBack}
                style={{
                  background: 'transparent',
                  border: 'none',
                  padding: 0,
                  cursor: onBack ? 'pointer' : 'default',
                  fontFamily: 'inherit',
                  fontSize: 12,
                  color: onBack ? 'inherit' : '#666',
                  textDecoration: onBack ? 'underline' : 'none',
                  textDecorationColor: 'rgba(0,0,0,0.2)'
                }}
                title={onBack ? "Go Back" : undefined}
              >
                {projectPath}
              </button>
            )}

            {projectName && (
              <>
                {projectPath && <span className="topbar-sep">▸</span>}
                <span className="topbar-project">"{projectName}"</span>
              </>
            )}
          </div>
        </div>
        
        <div className="header-right">
           <div className="topbar-status">
            <span className="status-dot status-ready"></span>
            <span className="status-text">Ready</span>
          </div>
        </div>
      </div>

      {/* Row 2: Toolbar */}
      <div className="header-row header-toolbar">
        <div className="toolbar-section">
          {/* File Ops */}
          <ToolbarGroup>
            <ToolbarButton icon="📄" label="New" />
            <ToolbarButton icon="📂" label="Open" onClick={onOpen} />
            <ToolbarButton icon="💾" label="Save" onClick={onSave} />
          </ToolbarGroup>

          {/* Zoom Ops */}
          <ToolbarGroup>
            <ToolbarButton icon="➕" label="Zoom In" onClick={onZoomIn} />
            <ToolbarButton icon="➖" label="Zoom Out" onClick={onZoomOut} />
            <ToolbarButton icon="⤢" label="Fit" onClick={onFit} />
          </ToolbarGroup>

          {/* Config Ops */}
          <ToolbarGroup>
            <ToolbarButton
              icon={receipts ? "☑️" : "☐"}
              label="Receipts"
              onClick={() => setReceipts(!receipts)}
              active={receipts}
            />
          </ToolbarGroup>
        </div>

        <div className="toolbar-section toolbar-right">
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
    </header>
  );
}

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