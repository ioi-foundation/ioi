// apps/autopilot/src/components/ActivityBar.tsx
import React, { useState, useEffect } from "react";
import { Logo } from "./Logo";
import "./ActivityBar.css";

interface ActivityBarProps {
  activeView: string;
  onViewChange: (view: string) => void;
}

const mainNavItems = [
  { 
    id: "copilot", 
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z" />
      </svg>
    ), 
    label: "Copilot" 
  },
  { 
    id: "agent-builder", 
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/>
      </svg>
    ), 
    label: "Agent Builder" 
  },
  { 
    id: "compose", 
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/>
        <polyline points="3.27 6.96 12 12.01 20.73 6.96"/>
        <line x1="12" y1="22.08" x2="12" y2="12"/>
      </svg>
    ), 
    label: "Graph Compose" 
  },
];

const workspaceItems = [
  { 
    id: "marketplace", 
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M6 2L3 6v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V6l-3-4z" />
        <line x1="3" y1="6" x2="21" y2="6" />
        <path d="M16 10a4 4 0 0 1-8 0" />
      </svg>
    ),
    label: "Marketplace"
  },
  // [NEW] Fleet Management Tab
  {
    id: "fleet",
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M2 20h20M2 4h20M2 12h20M6 12v8M18 4v8M10 4v8" />
        <rect x="2" y="4" width="20" height="8" />
        <rect x="2" y="12" width="20" height="8" />
      </svg>
    ),
    label: "Fleet Management"
  },
  { 
    id: "my-agents", 
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <rect x="3" y="11" width="18" height="10" rx="2" />
        <circle cx="12" cy="5" r="2" />
        <path d="M12 7v4" />
      </svg>
    ),
    label: "My Agents", 
    badge: "3" 
  },
  { 
    id: "templates", 
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2" />
        <rect x="8" y="2" width="8" height="4" rx="1" ry="1" />
      </svg>
    ),
    label: "Templates" 
  },
];

const observabilityItems = [
  {
    id: "monitoring",
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M22 12h-4l-3 9L9 3l-3 9H2" />
      </svg>
    ),
    label: "Monitoring"
  }
];

// [NEW] User Menu Component
function UserMenu({ onLogout, onSettings }: any) {
  return (
    <div className="user-menu-popover">
        <div className="menu-header">
            <div className="user-name">Local User</div>
            <div className="user-role">Administrator</div>
        </div>
        <div className="menu-divider" />
        <button className="menu-option" onClick={onSettings}>Settings</button>
        <button className="menu-option" onClick={() => console.log("Workspaces")}>Switch Workspace</button>
        <div className="menu-divider" />
        <button className="menu-option danger" onClick={onLogout}>Log Out</button>
    </div>
  );
}

export function ActivityBar({ 
  activeView, 
  onViewChange, 
}: ActivityBarProps) {
  const [showUserMenu, setShowUserMenu] = useState(false);

  // Close menu on click outside
  useEffect(() => {
    const close = () => setShowUserMenu(false);
    if (showUserMenu) window.addEventListener('click', close);
    return () => window.removeEventListener('click', close);
  }, [showUserMenu]);

  return (
    <div className="activity-bar">
      <div className="activity-top">
        {/* Logo */}
        <div className="activity-logo">
          <div className="logo-icon">
            <Logo style={{ width: 28, height: 28 }} />
          </div>
        </div>

        {/* Builder & Graph */}
        <div className="activity-nav">
          <NavGroup items={mainNavItems} activeView={activeView} onViewChange={onViewChange} />
        </div>
        
        {/* Workspace Spacer */}
        <div className="activity-nav" style={{ marginTop: 'auto' }}></div>
        
        <div className="activity-nav">
          <NavGroup items={workspaceItems} activeView={activeView} onViewChange={onViewChange} />
          <NavGroup items={observabilityItems} activeView={activeView} onViewChange={onViewChange} />
        </div>
      </div>

      <div className="activity-bottom">
        <button className="activity-item" title="Documentation">
          <span className="activity-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z"/><path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z"/></svg>
          </span>
        </button>
        <button className="activity-item" title="Settings">
          <span className="activity-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
          </span>
        </button>
        
        {/* User Section */}
        <div className="user-section">
          <div 
            className="user-avatar" 
            onClick={(e) => { e.stopPropagation(); setShowUserMenu(!showUserMenu); }}
          >
            L
          </div>
          {/* Menu Popover */}
          {showUserMenu && (
             <UserMenu onSettings={() => console.log("Settings")} onLogout={() => console.log("Logout")} />
          )}
        </div>
      </div>
    </div>
  );
}

interface NavGroupProps {
  items: { id: string; icon: React.ReactNode; label: string; badge?: string }[];
  activeView: string;
  onViewChange: (view: string) => void;
}

function NavGroup({ items, activeView, onViewChange }: NavGroupProps) {
  return (
    <>
      {items.map((item) => (
        <button
          key={item.id}
          className={`activity-item ${activeView === item.id ? "active" : ""}`}
          onClick={() => onViewChange(item.id)}
          title={item.label}
        >
          <span className="activity-icon">{item.icon}</span>
          {item.badge && <span className="activity-badge">{item.badge}</span>}
        </button>
      ))}
    </>
  );
}