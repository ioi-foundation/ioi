import { Logo } from "./Logo";
import "./ActivityBar.css";

interface ActivityBarProps {
  activeView: string;
  onViewChange: (view: string) => void;
}

const mainNavItems = [
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

export function ActivityBar({ 
  activeView, 
  onViewChange, 
}: ActivityBarProps) {
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
          <div className="user-avatar">L</div>
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