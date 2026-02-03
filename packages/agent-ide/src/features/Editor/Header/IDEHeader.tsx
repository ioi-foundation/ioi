import { useState, useRef, useEffect } from "react";
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
}

const MENU_LABELS = ["File", "Edit", "View", "Tools", "Window", "Help"];

// Removed unused 'projectPath' from destructuring
export function IDEHeader({
  projectName,
  onSave,
  onOpen,
  onRun,
  onZoomIn,
  onZoomOut,
  onFit,
}: IDEHeaderProps) {
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

  return (
    <header className="ide-header">
      <div className="header-row header-nav">
        <div className="header-left">
          <div className="menubar" ref={menuRef}>
            {MENU_LABELS.map((item) => (
              <div key={item} className="menu-wrapper">
                <div
                  className={`menu-item ${activeMenu === item ? "active" : ""}`}
                  onClick={() => setActiveMenu(activeMenu === item ? null : item)}
                >
                  {item}
                </div>
                {/* File Dropdown */}
                {activeMenu === item && item === "File" && (
                  <div className="menu-dropdown">
                    <button className="menu-dropdown-item" onClick={onSave}>
                      <span>Save Project</span><span className="menu-shortcut">⌘S</span>
                    </button>
                    <button className="menu-dropdown-item" onClick={onOpen}>
                      <span>Open...</span><span className="menu-shortcut">⌘O</span>
                    </button>
                  </div>
                )}
                 {/* View Dropdown */}
                 {activeMenu === item && item === "View" && (
                  <div className="menu-dropdown">
                    <button className="menu-dropdown-item" onClick={onZoomIn}>
                      <span>Zoom In</span><span className="menu-shortcut">⌘+</span>
                    </button>
                    <button className="menu-dropdown-item" onClick={onZoomOut}>
                      <span>Zoom Out</span><span className="menu-shortcut">⌘-</span>
                    </button>
                     <button className="menu-dropdown-item" onClick={onFit}>
                      <span>Fit Canvas</span><span className="menu-shortcut">⌘1</span>
                    </button>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      </div>
      
      {/* Toolbar Row */}
      <div className="header-row header-toolbar">
         <div className="toolbar-section">
            <button className="toolbar-btn" title="Save" onClick={onSave}>💾</button>
            <button className="toolbar-btn" title="Open" onClick={onOpen}>📂</button>
            <div className="toolbar-sep" />
            <button className="toolbar-btn" title="Run" onClick={onRun}>▶</button>
         </div>
         <div className="toolbar-section right">
            <span className="project-meta">{projectName || "Untitled"}</span>
         </div>
      </div>
    </header>
  );
}