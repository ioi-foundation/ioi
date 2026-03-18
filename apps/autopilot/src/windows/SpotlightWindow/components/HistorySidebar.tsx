import { SessionSummary } from "../../../types";
import { formatTimeAgo, groupSessionsByDate } from "../utils";
import { icons } from "./Icons";
import "../styles/Sidebar.css";

interface HistorySidebarProps {
  sessions: SessionSummary[];
  onSelectSession: (id: string) => void;
  onNewChat: () => void;
  searchQuery: string;
  onSearchChange: (q: string) => void;
  onToggleSidebar: () => void;
}

export function HistorySidebar({ 
  sessions, 
  onSelectSession, 
  onNewChat, 
  searchQuery, 
  onSearchChange,
  onToggleSidebar,
}: HistorySidebarProps) {
  const filtered = sessions.filter(s => 
    s.title.toLowerCase().includes(searchQuery.toLowerCase())
  );
  const grouped = groupSessionsByDate(filtered);

  return (
    <aside className="history-sidebar">
      <div className="sidebar-header">
        <div className="sidebar-header-copy">
          <span className="sidebar-title">Chats</span>
          <span className="sidebar-title-meta">
            {filtered.length === sessions.length
              ? `${sessions.length} total`
              : `${filtered.length} of ${sessions.length}`}
          </span>
        </div>
        <div className="sidebar-header-actions">
          <button className="sidebar-new-btn" onClick={onNewChat} title="Start a new chat">
            {icons.plus}
            <span>New</span>
          </button>
          <button 
            className="sidebar-toggle-btn" 
            onClick={onToggleSidebar}
            title="Hide sidebar (⌘K)"
          >
            {icons.sidebar}
          </button>
        </div>
      </div>

      <div className="sidebar-search">
        <div className="search-box">
          {icons.search}
          <input
            placeholder="Search conversations"
            value={searchQuery}
            onChange={(e) => onSearchChange(e.target.value)}
          />
        </div>
      </div>

      <div className="sidebar-history">
        {grouped.map((group) => (
          <div key={group.label} className="history-group">
            <div className="history-label">{group.label}</div>
            {group.sessions.map((s) => (
              <button
                key={s.session_id}
                className="history-item"
                onClick={() => onSelectSession(s.session_id)}
              >
                <span className="history-title">{s.title}</span>
                <span className="history-time">{formatTimeAgo(s.timestamp)}</span>
              </button>
            ))}
          </div>
        ))}
        
        {filtered.length === 0 && (
          <div className="history-empty">
            {searchQuery ? "No matches found" : "No chats yet"}
          </div>
        )}
      </div>
    </aside>
  );
}
