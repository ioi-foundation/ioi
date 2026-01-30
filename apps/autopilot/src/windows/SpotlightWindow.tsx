// apps/autopilot/src/windows/SpotlightWindow.tsx

import React, { useState, useEffect, useRef, useMemo, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { emit } from "@tauri-apps/api/event";
import { useAgentStore, initEventListeners } from "../store/agentStore";
import { AgentTask, ChatMessage, SessionSummary } from "../types";
import "./SpotlightWindow.css";

// --- Thinking Orb Animation ---
const ThinkingOrb = ({ isActive = false }: { isActive?: boolean }) => (
  <div className={`thinking-orb ${isActive ? "active" : ""}`}>
    <div className="orb-ring" />
    <div className="orb-ring" />
    <div className="orb-ring" />
    <div className="orb-core" />
  </div>
);

// --- Icon System ---
const icons = {
  close: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"><path d="M18 6L6 18M6 6l12 12" /></svg>,
  expand: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"><path d="M15 3h6v6M9 21H3v-6M21 3l-7 7M3 21l7-7" /></svg>,
  history: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><circle cx="12" cy="12" r="9" /><polyline points="12 7 12 12 15 14" strokeLinecap="round" strokeLinejoin="round" /></svg>,
  settings: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"><path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z" /><circle cx="12" cy="12" r="3" /></svg>,
  plus: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"><path d="M12 5v14M5 12h14" /></svg>,
  slash: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"><path d="M7 4l10 16" /></svg>,
  sparkles: <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M9.937 15.5A2 2 0 0 0 8.5 14.063l-6.135-1.582a.5.5 0 0 1 0-.962L8.5 9.936A2 2 0 0 0 9.937 8.5l1.582-6.135a.5.5 0 0 1 .963 0L14.063 8.5A2 2 0 0 0 15.5 9.937l6.135 1.581a.5.5 0 0 1 0 .964L15.5 14.063a2 2 0 0 0-1.437 1.437l-1.582 6.135a.5.5 0 0 1-.963 0z" /><path d="M20 3v4M22 5h-4M4 17v2M5 18H3" /></svg>,
  send: <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M5 12h14M12 5l7 7-7 7" /></svg>,
  laptop: <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M20 16V7a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v9m16 0H4m16 0 1.28 2.55a1 1 0 0 1-.9 1.45H3.62a1 1 0 0 1-.9-1.45L4 16" /></svg>,
  cloud: <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round" strokeLinecap="round"><path d="M17.5 19H9a7 7 0 1 1 6.71-9h1.79a4.5 4.5 0 1 1 0 9Z" /></svg>,
  chevron: <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M6 9l6 6 6-6" /></svg>,
  chevronDown: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M6 9l6 6 6-6" /></svg>,
  cube: <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z" /><path d="M3.27 6.96L12 12.01l8.73-5.05M12 22.08V12" /></svg>,
  check: <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M20 6L9 17l-5-5" /></svg>,
  x: <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round"><path d="M18 6L6 18M6 6l12 12" /></svg>,
  alert: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" /><line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" /></svg>,
  lock: <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>,
  search: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg>,
  sidebar: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M9 3v18"/></svg>,
  globe: <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"><circle cx="12" cy="12" r="10"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/><path d="M2 12h20"/></svg>,
  externalLink: <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>,
  copy: <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect width="14" height="14" x="8" y="8" rx="2" ry="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/></svg>,
  retry: <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"/><path d="M3 21v-5h5"/></svg>,
  stop: <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="6" y="6" width="12" height="12" rx="2"/></svg>,
  paperclip: <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="m21.44 11.05-9.19 9.19a6 6 0 0 1-8.49-8.49l8.57-8.57A4 4 0 1 1 18 8.84l-8.59 8.57a2 2 0 0 1-2.83-2.83l8.49-8.48"/></svg>,
  thumbUp: <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M7 10v12"/><path d="M15 5.88 14 10h5.83a2 2 0 0 1 1.92 2.56l-2.33 8A2 2 0 0 1 17.5 22H4a2 2 0 0 1-2-2v-8a2 2 0 0 1 2-2h2.76a2 2 0 0 0 1.79-1.11L12 2a3.13 3.13 0 0 1 3 3.88Z"/></svg>,
  thumbDown: <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M17 14V2"/><path d="M9 18.12 10 14H4.17a2 2 0 0 1-1.92-2.56l2.33-8A2 2 0 0 1 6.5 2H20a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2h-2.76a2 2 0 0 0-1.79 1.11L12 22a3.13 3.13 0 0 1-3-3.88Z"/></svg>,
  calendar: <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><rect width="18" height="18" x="3" y="4" rx="2" ry="2"/><line x1="16" x2="16" y1="2" y2="6"/><line x1="8" x2="8" y1="2" y2="6"/><line x1="3" x2="21" y1="10" y2="10"/></svg>,
  terminal: <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="4 17 10 11 4 5"/><line x1="12" x2="20" y1="19" y2="19"/></svg>,
  trash: <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M3 6h18"/><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"/><path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/></svg>,
  pin: <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="12" x2="12" y1="17" y2="22"/><path d="M5 17h14v-1.76a2 2 0 0 0-1.11-1.79l-1.78-.9A2 2 0 0 1 15 10.76V6h1a2 2 0 0 0 0-4H8a2 2 0 0 0 0 4h1v4.76a2 2 0 0 1-1.11 1.79l-1.78.9A2 2 0 0 0 5 15.24Z"/></svg>,
  moreH: <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="1"/><circle cx="19" cy="12" r="1"/><circle cx="5" cy="12" r="1"/></svg>,
};

// IOI Logo Watermark with Suggested Prompts
const IOIWatermark = ({ onSuggestionClick }: { onSuggestionClick?: (text: string) => void }) => {
  const suggestions = [
    { icon: icons.globe, text: "Search the web for..." },
    { icon: icons.laptop, text: "Open an app..." },
    { icon: icons.cube, text: "Analyze this data..." },
  ];

  return (
    <div className="spot-watermark-container">
      <svg className="spot-watermark" viewBox="108.97 89.47 781.56 706.06" fill="none">
        <g stroke="currentColor" strokeWidth="1" strokeLinejoin="round" strokeLinecap="round">
          <path d="M295.299 434.631L295.299 654.116 485.379 544.373z" />
          <path d="M500 535.931L697.39 421.968 500 308.005 302.61 421.968z" />
          <path d="M514.621 544.373L704.701 654.115 704.701 434.631z" />
          <path d="M280.678 662.557L280.678 425.086 123.957 695.903 145.513 740.594z" />
          <path d="M719.322 662.557L854.487 740.594 876.043 695.903 719.322 425.085z" />
          <path d="M287.988 675.22L151.883 753.8 164.878 780.741 470.757 780.741 287.988 675.22z" />
          <path d="M712.012 675.219L529.242 780.741 835.122 780.741 848.117 753.8 712.012 675.219z" />
          <path d="M492.689 295.343L492.689 104.779 466.038 104.779 287.055 414.066z" />
          <path d="M507.31 295.342L712.945 414.066 533.962 104.779 507.31 104.779z" />
          <path d="M302.61 666.778L500 780.741 500 552.815z" />
          <path d="M500 552.815L500 780.741 697.39 666.778z" />
        </g>
      </svg>
      <span className="spot-watermark-hint">What can I help you with?</span>
      
      {onSuggestionClick && (
        <div className="spot-suggestions">
          {suggestions.map((s, i) => (
            <button key={i} className="spot-suggestion" onClick={() => onSuggestionClick(s.text)}>
              <span className="suggestion-icon">{s.icon}</span>
              <span className="suggestion-text">{s.text}</span>
            </button>
          ))}
        </div>
      )}
      
      <div className="spot-shortcut-hint">
        <kbd>⌘</kbd><kbd>K</kbd> to open anytime
      </div>
    </div>
  );
};

// Message Actions (copy, retry, feedback)
function MessageActions({ text, onRetry, showRetry = false }: { text: string; onRetry?: () => void; showRetry?: boolean }) {
  const [copied, setCopied] = useState(false);
  const [feedback, setFeedback] = useState<'up' | 'down' | null>(null);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="message-actions">
      <button className={`message-action-btn ${copied ? "success" : ""}`} onClick={handleCopy} title="Copy (⌘C)">
        {copied ? icons.check : icons.copy}
      </button>
      {showRetry && onRetry && (
        <button className="message-action-btn" onClick={onRetry} title="Retry (⌘R)">
          {icons.retry}
        </button>
      )}
      <button 
        className={`message-action-btn ${feedback === 'up' ? "active" : ""}`} 
        onClick={() => setFeedback(f => f === 'up' ? null : 'up')}
        title="Good response"
      >
        {icons.thumbUp}
      </button>
      <button 
        className={`message-action-btn ${feedback === 'down' ? "active" : ""}`}
        onClick={() => setFeedback(f => f === 'down' ? null : 'down')}
        title="Bad response"
      >
        {icons.thumbDown}
      </button>
    </div>
  );
}

// Scroll to Bottom FAB
function ScrollToBottom({ visible, onClick }: { visible: boolean; onClick: () => void }) {
  if (!visible) return null;
  return (
    <button className="scroll-to-bottom" onClick={onClick} title="Scroll to bottom">
      {icons.chevronDown}
    </button>
  );
}

// --- Visual Artifact (Inline Browser Preview) ---
interface VisualArtifactProps {
  url?: string;
  title?: string;
  isActive?: boolean;
  screenshot?: string;
}

function VisualArtifact({ url = "browsing...", title, isActive = false, screenshot }: VisualArtifactProps) {
  const [cursorPos, setCursorPos] = useState({ x: 50, y: 40 });
  const [isClicking, setIsClicking] = useState(false);

  useEffect(() => {
    if (!isActive) return;
    const interval = setInterval(() => {
      setCursorPos({ x: 25 + Math.random() * 55, y: 25 + Math.random() * 50 });
      if (Math.random() > 0.6) {
        setIsClicking(true);
        setTimeout(() => setIsClicking(false), 150);
      }
    }, 1200);
    return () => clearInterval(interval);
  }, [isActive]);

  return (
    <div className={`visual-artifact ${isActive ? "active" : ""}`}>
      {/* Browser Chrome */}
      <div className="artifact-browser-bar">
        <div className="artifact-traffic-dots">
          <span className="dot close" />
          <span className="dot minimize" />
          <span className="dot maximize" />
        </div>
        <div className="artifact-url-bar">
          <span className="artifact-lock">{icons.lock}</span>
          <span className="artifact-url">{url}</span>
        </div>
        <button className="artifact-external" title="Open in browser">
          {icons.externalLink}
        </button>
      </div>

      {/* Viewport */}
      <div className="artifact-viewport">
        {screenshot ? (
          <img src={screenshot} alt="Page screenshot" className="artifact-screenshot" />
        ) : (
          <div className="artifact-skeleton">
            <div className="skel-header">
              <div className="skel-logo" />
              <div className="skel-nav"><span /><span /><span /></div>
            </div>
            <div className="skel-hero">
              <div className="skel-title" />
              <div className="skel-subtitle" />
              <div className="skel-cta" />
            </div>
            <div className="skel-cards"><span /><span /><span /></div>
          </div>
        )}

        {/* Animated Cursor */}
        {isActive && (
          <svg
            className={`artifact-cursor ${isClicking ? "clicking" : ""}`}
            style={{ left: `${cursorPos.x}%`, top: `${cursorPos.y}%` }}
            width="20" height="20" viewBox="0 0 24 24" fill="none"
          >
            <path d="M5.5 3.2L11.5 19.5L14.5 13L21 12L5.5 3.2Z" fill="#000" stroke="#fff" strokeWidth="1.5"/>
          </svg>
        )}
      </div>

      {/* Activity Footer */}
      {isActive && title && (
        <div className="artifact-activity">
          <div className="activity-pulse" />
          <span>{title}</span>
        </div>
      )}
    </div>
  );
}

// --- Resize Handle ---
function ResizeHandle({ onResize }: { onResize: (delta: number) => void }) {
  const isDragging = useRef(false);
  const startX = useRef(0);

  const handleMouseDown = useCallback((e: React.MouseEvent) => {
    isDragging.current = true;
    startX.current = e.clientX;
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';
  }, []);

  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      if (!isDragging.current) return;
      const delta = e.clientX - startX.current;
      startX.current = e.clientX;
      onResize(delta);
    };
    const handleMouseUp = () => {
      isDragging.current = false;
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
    };
    document.addEventListener('mousemove', handleMouseMove);
    document.addEventListener('mouseup', handleMouseUp);
    return () => {
      document.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('mouseup', handleMouseUp);
    };
  }, [onResize]);

  return (
    <div className="resize-handle" onMouseDown={handleMouseDown}>
      <div className="resize-line" />
      <div className="resize-grip" />
    </div>
  );
}

// --- History Sidebar (for wide mode) ---
interface HistorySidebarProps {
  sessions: SessionSummary[];
  onSelectSession: (id: string) => void;
  onNewChat: () => void;
  searchQuery: string;
  onSearchChange: (q: string) => void;
}

function groupSessionsByDate(sessions: SessionSummary[]): { label: string; sessions: SessionSummary[] }[] {
  const now = Date.now();
  const today = new Date().setHours(0, 0, 0, 0);
  const yesterday = today - 86400000;
  const lastWeek = today - 7 * 86400000;

  const groups: { label: string; sessions: SessionSummary[] }[] = [
    { label: "Today", sessions: [] },
    { label: "Yesterday", sessions: [] },
    { label: "Last 7 days", sessions: [] },
    { label: "Older", sessions: [] },
  ];

  sessions.forEach((s) => {
    if (s.timestamp >= today) groups[0].sessions.push(s);
    else if (s.timestamp >= yesterday) groups[1].sessions.push(s);
    else if (s.timestamp >= lastWeek) groups[2].sessions.push(s);
    else groups[3].sessions.push(s);
  });

  return groups.filter((g) => g.sessions.length > 0);
}

function HistorySidebar({ sessions, onSelectSession, onNewChat, searchQuery, onSearchChange }: HistorySidebarProps) {
  const filtered = sessions.filter(s => 
    s.title.toLowerCase().includes(searchQuery.toLowerCase())
  );
  const grouped = groupSessionsByDate(filtered);

  return (
    <div className="history-sidebar">
      <div className="sidebar-header">
        <button className="sidebar-new-btn" onClick={onNewChat}>
          {icons.plus}
          <span>New Chat</span>
        </button>
        <button className="sidebar-dock-btn" title="Collapse sidebar">
          {icons.sidebar}
        </button>
      </div>

      <div className="sidebar-search">
        <div className="search-box">
          {icons.search}
          <input
            placeholder="Search chats..."
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
    </div>
  );
}

// --- Approval Card (Gate) ---
function SpotlightApprovalCard({ title, description, risk, onApprove, onDeny }: any) {
  const riskConfig = {
    high: { color: "#EF4444", bg: "rgba(239, 68, 68, 0.08)", label: "HIGH RISK" },
    medium: { color: "#F59E0B", bg: "rgba(245, 158, 11, 0.08)", label: "MEDIUM" },
    low: { color: "#10B981", bg: "rgba(16, 185, 129, 0.08)", label: "LOW RISK" },
  }[risk] || { color: "#6B7280", bg: "rgba(107, 114, 128, 0.08)", label: "UNKNOWN" };

  return (
    <div className="spot-gate-card" style={{ "--gate-color": riskConfig.color, "--gate-bg": riskConfig.bg } as React.CSSProperties}>
      <div className="gate-indicator" />
      <div className="gate-content">
        <div className="gate-header">
          <div className="gate-title-row">
            <span className="gate-icon">{icons.alert}</span>
            <span className="gate-title">{title}</span>
          </div>
          <span className="gate-badge">{riskConfig.label}</span>
        </div>
        <p className="gate-desc">{description}</p>
        <div className="gate-actions">
          <button onClick={onApprove} className="gate-btn primary">{icons.check}<span>Authorize</span></button>
          <button onClick={onDeny} className="gate-btn secondary">{icons.x}<span>Deny</span></button>
        </div>
      </div>
    </div>
  );
}

// --- Thought Chain ---
function ThoughtChain({ messages, isThinking = false }: { messages: ChatMessage[]; isThinking?: boolean }) {
  const [expanded, setExpanded] = useState(false);
  const hasError = messages.some((m) => m.text.toLowerCase().includes("error") || m.text.toLowerCase().includes("fail"));

  useEffect(() => { if (hasError) setExpanded(true); }, [hasError]);

  return (
    <div className={`thought-chain ${expanded ? "expanded" : ""} ${hasError ? "has-error" : ""} ${isThinking ? "thinking" : ""}`}>
      <button className="thought-header" onClick={() => setExpanded(!expanded)} type="button">
        <div className="thought-title-group">
          {isThinking ? <ThinkingOrb isActive /> : hasError ? <span className="thought-icon error">{icons.alert}</span> : <span className="thought-icon success">{icons.check}</span>}
          <span className="thought-title">{isThinking ? "Thinking..." : hasError ? "Error" : "Reasoning"}</span>
        </div>
        <div className="thought-meta-group">
          <span className="thought-meta">{messages.length} steps</span>
          <span className={`thought-chevron ${expanded ? "open" : ""}`}>{icons.chevron}</span>
        </div>
      </button>
      <div className="thought-content">
        <div className="thought-timeline">
          {messages.map((m, i) => (
            <div key={i} className="thought-step">
              <div className="step-connector">
                <div className="step-dot" />
                {i < messages.length - 1 && <div className="step-line" />}
              </div>
              <div className="step-content">
                <span className="step-role">{m.role}</span>
                <span className="step-text">{m.text}</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// --- Dropdown ---
interface DropdownOption { value: string; label: string; desc?: string; icon?: React.ReactNode; }
interface DropdownProps { icon: React.ReactNode; options: DropdownOption[]; selected: string; onSelect: (val: string) => void; isOpen: boolean; onToggle: () => void; }

function Dropdown({ icon, options, selected, onSelect, isOpen, onToggle }: DropdownProps) {
  const selectedOption = options.find((opt) => opt.value === selected);
  return (
    <div className="spot-dropdown">
      <button className={`spot-toggle ${isOpen ? "open" : ""}`} onClick={(e) => { e.stopPropagation(); onToggle(); }} type="button">
        <span className="toggle-icon">{selectedOption?.icon || icon}</span>
        <span className="toggle-label">{selectedOption?.label}</span>
        <span className="toggle-chevron">{icons.chevron}</span>
      </button>
      {isOpen && (
        <div className="spot-dropdown-menu">
          {options.map((opt) => (
            <button key={opt.value} className={`spot-dropdown-item ${selected === opt.value ? "selected" : ""}`} onClick={() => { onSelect(opt.value); onToggle(); }} type="button">
              {opt.icon && <span className="spot-dropdown-icon">{opt.icon}</span>}
              <div className="spot-dropdown-content">
                <span className="spot-dropdown-label">{opt.label}</span>
                {opt.desc && <span className="spot-dropdown-desc">{opt.desc}</span>}
              </div>
              {selected === opt.value && <span className="spot-dropdown-check">{icons.check}</span>}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

const workspaceOptions: DropdownOption[] = [
  { value: "local", label: "Local", desc: "On-device", icon: icons.laptop },
  { value: "cloud", label: "Cloud", desc: "Remote", icon: icons.cloud },
];

const modelOptions: DropdownOption[] = [
  { value: "GPT-4o", label: "GPT-4o", desc: "OpenAI" },
  { value: "Claude 3.5", label: "Claude 3.5", desc: "Anthropic" },
  { value: "Llama 3", label: "Llama 3", desc: "Meta" },
];

function formatTimeAgo(ms: number): string {
  const diff = Date.now() - ms;
  const min = Math.floor(diff / 60000);
  if (min < 1) return "now";
  if (min < 60) return `${min}m ago`;
  const hours = Math.floor(min / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

type ChatEvent = ChatMessage & { isGate?: boolean; gateData?: any; isArtifact?: boolean; artifactData?: any; };

// Layout breakpoints (container width in px)
const LAYOUT_WIDE_THRESHOLD = 600;

export function SpotlightWindow() {
  const [intent, setIntent] = useState("");
  const [localHistory, setLocalHistory] = useState<ChatMessage[]>([]);
  const [autoContext, setAutoContext] = useState(true);
  const [activeDropdown, setActiveDropdown] = useState<string | null>(null);
  const [sessions, setSessions] = useState<SessionSummary[]>([]);
  const [workspaceMode, setWorkspaceMode] = useState("local");
  const [selectedModel, setSelectedModel] = useState("GPT-4o");
  const [chatEvents, setChatEvents] = useState<ChatEvent[]>([]);
  const [inputFocused, setInputFocused] = useState(false);
  const [containerWidth, setContainerWidth] = useState(400);
  const [searchQuery, setSearchQuery] = useState("");
  const [showScrollButton, setShowScrollButton] = useState(false);
  const [isDraggingFile, setIsDraggingFile] = useState(false);

  const inputRef = useRef<HTMLTextAreaElement>(null);
  const chatAreaRef = useRef<HTMLDivElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  const { task, startTask, continueTask, resetSession } = useAgentStore();

  // Track container width
  useEffect(() => {
    if (!containerRef.current) return;
    const observer = new ResizeObserver((entries) => {
      for (const entry of entries) setContainerWidth(entry.contentRect.width);
    });
    observer.observe(containerRef.current);
    return () => observer.disconnect();
  }, []);

  // Scroll detection
  useEffect(() => {
    const chatArea = chatAreaRef.current;
    if (!chatArea) return;

    const handleScroll = () => {
      const { scrollTop, scrollHeight, clientHeight } = chatArea;
      const isNearBottom = scrollHeight - scrollTop - clientHeight < 100;
      setShowScrollButton(!isNearBottom);
    };

    chatArea.addEventListener("scroll", handleScroll);
    return () => chatArea.removeEventListener("scroll", handleScroll);
  }, []);

  const scrollToBottom = useCallback(() => {
    if (chatAreaRef.current) {
      chatAreaRef.current.scrollTo({ top: chatAreaRef.current.scrollHeight, behavior: "smooth" });
    }
  }, []);

  const isWideMode = containerWidth >= LAYOUT_WIDE_THRESHOLD;

  useEffect(() => {
    initEventListeners();
    invoke("set_spotlight_mode", { mode: "sidebar" }).catch(console.error);
    setTimeout(() => inputRef.current?.focus(), 150);

    const loadHistory = async () => {
      try {
        const history = await invoke<SessionSummary[]>("get_session_history");
        setSessions(history);
      } catch (e) { console.error("Failed to load history:", e); }
    };
    loadHistory();
    const interval = setInterval(loadHistory, 5000);
    return () => clearInterval(interval);
  }, []);

  // Listen for gate events and artifact events
  useEffect(() => {
    if (task && task.phase === "Gate" && task.gate_info) {
      const last = chatEvents[chatEvents.length - 1];
      if (!last || !last.isGate) {
        setChatEvents((prev) => [...prev, { role: "system", text: "", timestamp: Date.now(), isGate: true, gateData: task.gate_info }]);
      }
    }
    // Add artifact when browsing
    if (task && task.phase === "Running" && task.current_step?.toLowerCase().includes("brows")) {
      const hasArtifact = chatEvents.some(e => e.isArtifact);
      if (!hasArtifact) {
        setChatEvents((prev) => [...prev, { 
          role: "system", text: "", timestamp: Date.now(), 
          isArtifact: true, 
          artifactData: { url: "loading...", isActive: true } 
        }]);
      }
    }
  }, [task?.phase, task?.gate_info, task?.current_step]);

  // Update artifact when step changes
  useEffect(() => {
    if (task?.current_step) {
      setChatEvents((prev) => prev.map(e => 
        e.isArtifact ? { ...e, artifactData: { ...e.artifactData, url: task.current_step, title: task.current_step, isActive: task.phase === "Running" } } : e
      ));
    }
  }, [task?.current_step, task?.phase]);

  const activeHistory: ChatMessage[] = (task as AgentTask | null)?.history || localHistory;

  useEffect(() => {
    if (chatAreaRef.current) chatAreaRef.current.scrollTop = chatAreaRef.current.scrollHeight;
  }, [activeHistory, chatEvents]);

  const handleResize = useCallback((delta: number) => {
    setContainerWidth((prev) => Math.max(320, Math.min(1200, prev + delta)));
    invoke("resize_spotlight", { width: containerWidth + delta }).catch(console.error);
  }, [containerWidth]);

  const openStudio = useCallback(async (targetView: string = "compose") => {
    await emit("request-studio-view", targetView);
    await invoke("hide_spotlight");
    await invoke("show_studio");
  }, []);

  const handleLoadSession = useCallback(async (id: string) => {
    try { await invoke("load_session", { sessionId: id }); } catch (e) { console.error("Failed to load session:", e); }
  }, []);

  const handleSubmit = useCallback(async () => {
    if (!intent.trim()) return;
    const text = intent;
    setIntent("");
    if (task && task.phase === "Running") return;
    try {
      if (task && task.id && task.phase !== "Failed") {
        await continueTask(task.id, text);
      } else {
        if (text.toLowerCase().includes("swarm") || text.toLowerCase().includes("team")) await openStudio("copilot");
        await startTask(text);
      }
    } catch (e) { console.error(e); }
  }, [intent, task, continueTask, startTask, openStudio]);

  const handleApprove = useCallback(async () => {
    await invoke("gate_respond", { approved: true });
    setChatEvents((prev) => prev.map((m) => (m.isGate ? { ...m, isGate: false, text: "✓ Authorized" } : m)));
  }, []);

  const handleDeny = useCallback(async () => {
    await invoke("gate_respond", { approved: false });
    setChatEvents((prev) => prev.map((m) => (m.isGate ? { ...m, isGate: false, text: "✗ Denied" } : m)));
  }, []);

  const handleNewChat = useCallback(() => {
    resetSession();
    setLocalHistory([]);
    setChatEvents([]);
    setTimeout(() => inputRef.current?.focus(), 50);
  }, [resetSession]);

  const handleGlobalClick = useCallback(() => {
    if (activeDropdown) setActiveDropdown(null);
  }, [activeDropdown]);

  // Render chat stream
  const renderChatStream = useMemo(() => {
    const combined: ChatEvent[] = [...activeHistory.map((m) => ({ ...m, isGate: false, gateData: null })), ...chatEvents];
    const groups: Array<{ type: "message" | "chain" | "gate" | "artifact"; content: any }> = [];
    let currentChain: ChatMessage[] = [];

    combined.forEach((msg) => {
      if (msg.isArtifact) {
        if (currentChain.length > 0) { groups.push({ type: "chain", content: [...currentChain] }); currentChain = []; }
        groups.push({ type: "artifact", content: msg.artifactData });
      } else if (msg.role === "tool" || (msg.role === "system" && !msg.isGate)) {
        currentChain.push(msg);
      } else if (msg.isGate) {
        if (currentChain.length > 0) { groups.push({ type: "chain", content: [...currentChain] }); currentChain = []; }
        groups.push({ type: "gate", content: msg.gateData });
      } else {
        if (currentChain.length > 0) { groups.push({ type: "chain", content: [...currentChain] }); currentChain = []; }
        groups.push({ type: "message", content: msg });
      }
    });
    if (currentChain.length > 0) groups.push({ type: "chain", content: currentChain });

    return groups.map((g, i) => (
      <React.Fragment key={i}>
        {g.type === "message" && (
          <div className={`spot-message ${g.content.role === "user" ? "user" : "agent"}`}>
            <div className="message-content">{g.content.text}</div>
            {g.content.role !== "user" && (
              <MessageActions text={g.content.text} showRetry={true} onRetry={() => {}} />
            )}
          </div>
        )}
        {g.type === "chain" && <ThoughtChain messages={g.content} isThinking={false} />}
        {g.type === "gate" && <SpotlightApprovalCard title={g.content.title} description={g.content.description} risk={g.content.risk} onApprove={handleApprove} onDeny={handleDeny} />}
        {g.type === "artifact" && <VisualArtifact url={g.content.url} title={g.content.title} isActive={g.content.isActive} screenshot={g.content.screenshot} />}
      </React.Fragment>
    ));
  }, [activeHistory, chatEvents, handleApprove, handleDeny]);

  const isRunning = task?.phase === "Running";
  const isGated = task?.phase === "Gate";
  const hasContent = task || localHistory.length > 0 || chatEvents.length > 0;
  const progressPercent = task ? (task.progress / Math.max(task.total_steps, 1)) * 100 : 0;

  return (
    <div className="spot-window" onClick={handleGlobalClick} ref={containerRef}>
      <div className={`spot-container ${isWideMode ? "wide-mode" : ""}`}>
        
        {/* History Sidebar (wide mode only) */}
        {isWideMode && (
          <HistorySidebar
            sessions={sessions}
            onSelectSession={handleLoadSession}
            onNewChat={handleNewChat}
            searchQuery={searchQuery}
            onSearchChange={setSearchQuery}
          />
        )}

        {/* Resize Handle */}
        <ResizeHandle onResize={handleResize} />

        {/* Main Chat Panel */}
        <div className="spot-main">
          {/* Header Actions */}
          <div className="spot-header-actions">
            {!isWideMode && <button className="spot-icon-btn" onClick={handleNewChat} title="New Chat">{icons.plus}</button>}
            {!isWideMode && <div className="divider-vertical" />}
            <button className="spot-icon-btn" onClick={() => openStudio("history")} title="History">{icons.history}</button>
            <button className="spot-icon-btn" onClick={() => openStudio("settings")} title="Settings">{icons.settings}</button>
            <button className="spot-icon-btn" onClick={() => openStudio("copilot")} title="Expand">{icons.expand}</button>
            <button className="spot-icon-btn close" onClick={() => invoke("hide_spotlight")} title="Close">{icons.close}</button>
          </div>

          {/* Tasks Section (narrow mode only) */}
          {!isWideMode && (
            <div className="spot-tasks-section">
              <div className="spot-tasks-bar">
                <span className="spot-tasks-title">Recent</span>
                {sessions.length > 3 && <button className="spot-tasks-more" onClick={() => openStudio("history")}>View all</button>}
              </div>
              <div className="spot-tasks-list">
                {sessions.slice(0, 3).map((s) => (
                  <button key={s.session_id} className="spot-task-item" onClick={() => handleLoadSession(s.session_id)}>
                    <span className="spot-task-title">{s.title}</span>
                    <span className="spot-task-age">{formatTimeAgo(s.timestamp)}</span>
                  </button>
                ))}
                {sessions.length === 0 && <div className="spot-task-empty">No recent tasks</div>}
              </div>
            </div>
          )}

          {/* Status Header */}
          {task && task.phase !== "Idle" && (
            <div className={`spot-status-header ${task.phase.toLowerCase()}`}>
              <div className="status-progress-rail"><div className="status-progress-fill" style={{ width: `${progressPercent}%` }} /></div>
              <div className="status-content">
                <div className={`status-beacon ${isRunning ? "pulse" : ""} ${task.phase === "Failed" ? "error" : ""} ${task.phase === "Complete" ? "success" : ""}`} />
                <div className="status-info">
                  <span className="status-step">{task.current_step}</span>
                  <span className="status-meta">{task.agent} · Gen {task.generation} · {task.progress}/{task.total_steps}</span>
                </div>
              </div>
            </div>
          )}

          {/* Chat Area */}
          <div className="spot-chat" ref={chatAreaRef}>
            {!hasContent && <IOIWatermark onSuggestionClick={(text) => setIntent(text)} />}
            {renderChatStream}
            {isRunning && !chatEvents.some(e => e.isArtifact) && (
              <div className="spot-thinking-indicator"><ThinkingOrb isActive /><span className="thinking-label">Processing...</span></div>
            )}
            <ScrollToBottom visible={showScrollButton} onClick={scrollToBottom} />
          </div>

          {/* Input Section */}
          <div className={`spot-input-section ${inputFocused ? "focused" : ""} ${isDraggingFile ? "drag-active" : ""}`}>
            <div className="spot-input-wrapper">
              <textarea
                ref={inputRef}
                className="spot-input"
                placeholder="How can I help you today?"
                value={intent}
                onChange={(e) => {
                  setIntent(e.target.value);
                  // Auto-resize
                  e.target.style.height = 'auto';
                  e.target.style.height = Math.min(e.target.scrollHeight, 120) + 'px';
                }}
                onKeyDown={(e) => {
                  if (e.key === "Enter" && !e.shiftKey) {
                    e.preventDefault();
                    handleSubmit();
                  }
                }}
                onFocus={() => setInputFocused(true)}
                onBlur={() => setInputFocused(false)}
                disabled={isGated}
                rows={1}
              />
            </div>
            <div className="spot-controls">
              <div className="spot-controls-left">
                <button className="spot-action-btn" title="Attach (⌘U)">{icons.paperclip}</button>
                <button className="spot-action-btn" title="Commands (/)">{icons.slash}</button>
                <button className={`spot-context-btn ${autoContext ? "active" : ""}`} onClick={() => setAutoContext(!autoContext)} title="Auto context (⌘.)">
                  {icons.sparkles}<span>Context</span>
                </button>
              </div>
              {isRunning ? (
                <button 
                  className="spot-stop-btn" 
                  onClick={() => invoke("cancel_task").catch(console.error)} 
                  title="Stop (Esc)"
                >
                  {icons.stop}
                  <span>Stop</span>
                </button>
              ) : (
                <button className="spot-send-btn" onClick={handleSubmit} disabled={!intent.trim()} title="Send (⏎)">
                  {icons.send}
                </button>
              )}
            </div>
            <div className="spot-toggles">
              <Dropdown icon={icons.laptop} options={workspaceOptions} selected={workspaceMode} onSelect={setWorkspaceMode} isOpen={activeDropdown === "workspace"} onToggle={() => setActiveDropdown(activeDropdown === "workspace" ? null : "workspace")} />
              <Dropdown icon={icons.cube} options={modelOptions} selected={selectedModel} onSelect={setSelectedModel} isOpen={activeDropdown === "model"} onToggle={() => setActiveDropdown(activeDropdown === "model" ? null : "model")} />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}