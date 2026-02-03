// packages/agent-ide/src/features/Shell/ActivityBar.tsx
import { useState, useEffect } from "react";
import { Icons } from "../../ui/icons";
import "./ActivityBar.css";

interface ActivityBarProps {
  activeView: string;
  onViewChange: (view: string) => void;
  // Optional for web
  ghostMode?: boolean;
  onToggleGhost?: () => void;
}

// ... nav items definitions ...
const mainNavItems = [
  { id: "copilot", icon: <Icons.Brain />, label: "Copilot" },
  { id: "compose", icon: <Icons.Action />, label: "Graph Compose" },
];

const workspaceItems = [
  { id: "marketplace", icon: <Icons.Folder />, label: "Marketplace" },
  { id: "fleet", icon: <Icons.Trigger />, label: "Fleet Management" },
  { id: "agents", icon: <Icons.Cards />, label: "Agents", badge: "3" },
];


export function ActivityBar({ activeView, onViewChange, ghostMode, onToggleGhost }: ActivityBarProps) {
  const [showUserMenu, setShowUserMenu] = useState(false);

  useEffect(() => {
    const close = () => setShowUserMenu(false);
    if (showUserMenu) window.addEventListener('click', close);
    return () => window.removeEventListener('click', close);
  }, [showUserMenu]);

  return (
    <div className="shell-activity-bar">
      <div className="activity-top">
        {/* Logo */}
        <div className="activity-logo" style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: 48, marginBottom: 8 }}>
           <Icons.Logo width="28" height="28" style={{color: 'var(--accent-blue)'}} />
        </div>

        <div className="activity-nav">
          <NavGroup items={mainNavItems} activeView={activeView} onViewChange={onViewChange} />
        </div>
        
        {/* REMOVED spacer style to stack icons at top */}
        <div className="activity-nav">
          <NavGroup items={workspaceItems} activeView={activeView} onViewChange={onViewChange} />
        </div>
      </div>

      <div className="activity-bottom">
        {onToggleGhost && (
            <button 
                className={`shell-activity-item ${ghostMode ? 'active' : ''}`} 
                title="Ghost Mode (Record)"
                onClick={onToggleGhost}
                style={{color: ghostMode ? '#EF4444' : 'var(--text-tertiary)'}}
            >
            <span className="activity-icon">
                <Icons.Record fill={ghostMode ? "currentColor" : "none"} />
            </span>
            {ghostMode && <span className="activity-badge" style={{background:'#EF4444'}}>REC</span>}
            </button>
        )}

        <button className="shell-activity-item" title="Settings">
          <span className="activity-icon">
            <Icons.Settings />
          </span>
        </button>
        
        <div className="user-section">
          <div 
            className="user-avatar" 
            onClick={(e) => { e.stopPropagation(); setShowUserMenu(!showUserMenu); }}
          >
            L
          </div>
          {showUserMenu && <UserMenu />}
        </div>
      </div>
    </div>
  );
}

function NavGroup({ items, activeView, onViewChange }: any) {
  return (
    <>
      {items.map((item: any) => (
        <button
          key={item.id}
          className={`shell-activity-item ${activeView === item.id ? "active" : ""}`}
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

function UserMenu() {
    return <div style={{position:'absolute', bottom:0, left:60, width:180, background:'var(--surface-2)', border:'1px solid var(--border-default)', borderRadius:8, padding:4, color:'var(--text-primary)', fontSize:12, zIndex: 1000}}>
        <div style={{padding:8}}>Local User</div>
    </div>;
}