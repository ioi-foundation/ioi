import { useMemo } from "react";
import type { SessionSummary } from "../../../types";
import { icons } from "./Icons";

type ChatConversationSidebarProps = {
  sessions: SessionSummary[];
  activeSessionId: string | null;
  searchQuery: string;
  onSearchChange: (value: string) => void;
  onNewSession: () => void;
  onSelectSession: (sessionId: string) => void;
  showArtifactNav: boolean;
  artifactVisible: boolean;
  artifactCount: number;
  onToggleArtifacts: () => void;
};

type SessionGroup = {
  label: string;
  sessions: SessionSummary[];
};

function startOfDay(input: Date): number {
  const date = new Date(input);
  date.setHours(0, 0, 0, 0);
  return date.getTime();
}

function formatSessionMeta(timestamp: number): string {
  const date = new Date(timestamp);
  const now = new Date();
  const todayStart = startOfDay(now);
  const yesterdayStart = todayStart - 24 * 60 * 60 * 1000;
  if (timestamp >= todayStart) {
    return new Intl.DateTimeFormat(undefined, {
      hour: "numeric",
      minute: "2-digit",
    }).format(date);
  }
  if (timestamp >= yesterdayStart) {
    return "Yesterday";
  }
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
  }).format(date);
}

function groupSessions(sessions: SessionSummary[]): SessionGroup[] {
  const now = new Date();
  const todayStart = startOfDay(now);
  const yesterdayStart = todayStart - 24 * 60 * 60 * 1000;
  const groups = new Map<string, SessionSummary[]>();

  for (const session of sessions) {
    const label =
      session.timestamp >= todayStart
        ? "Today"
        : session.timestamp >= yesterdayStart
          ? "Yesterday"
          : "Earlier";
    const current = groups.get(label) ?? [];
    current.push(session);
    groups.set(label, current);
  }

  return ["Today", "Yesterday", "Earlier"]
    .map((label) => ({
      label,
      sessions: groups.get(label) ?? [],
    }))
    .filter((group) => group.sessions.length > 0);
}

export function ChatConversationSidebar({
  sessions,
  activeSessionId,
  searchQuery,
  onSearchChange,
  onNewSession,
  onSelectSession,
  showArtifactNav,
  artifactVisible,
  artifactCount,
  onToggleArtifacts,
}: ChatConversationSidebarProps) {
  const filteredGroups = useMemo(() => {
    const normalizedQuery = searchQuery.trim().toLowerCase();
    const filteredSessions = [...sessions]
      .sort((left, right) => right.timestamp - left.timestamp)
      .filter((session) => {
        if (!normalizedQuery) {
          return true;
        }
        const haystack = [
          session.title,
          session.resume_hint,
          session.current_step,
          session.phase,
        ]
          .filter(Boolean)
          .join(" ")
          .toLowerCase();
        return haystack.includes(normalizedQuery);
      });
    return groupSessions(filteredSessions);
  }, [searchQuery, sessions]);

  const hasResults = filteredGroups.length > 0;

  return (
    <aside className="spot-chat-sidebar" aria-label="Chat sidebar">
      <div className="spot-chat-sidebar-head">
        <div className="spot-chat-sidebar-title-block">
          <strong className="spot-chat-sidebar-title">Chat</strong>
          <span className="spot-chat-sidebar-subtitle">
            Outcome-first workspace
          </span>
        </div>

        <button
          type="button"
          className="spot-chat-sidebar-head-action"
          onClick={onNewSession}
          aria-label="Start a new Chat request"
          title="New outcome"
        >
          {icons.plus}
        </button>
      </div>

      <label className="spot-chat-sidebar-search" aria-label="Search Chat sessions">
        <span className="spot-chat-sidebar-search-icon" aria-hidden="true">
          {icons.search}
        </span>
        <input
          type="text"
          value={searchQuery}
          onChange={(event) => onSearchChange(event.target.value)}
          placeholder="Search sessions"
        />
      </label>

      <div className="spot-chat-sidebar-actions">
        <button
          type="button"
          className="spot-chat-sidebar-utility"
          onClick={onNewSession}
        >
          <span className="spot-chat-sidebar-utility-icon" aria-hidden="true">
            {icons.plus}
          </span>
          <span>New outcome</span>
        </button>

        {showArtifactNav ? (
          <button
            type="button"
            className={`spot-chat-sidebar-utility ${
              artifactVisible ? "is-active" : ""
            }`}
            onClick={onToggleArtifacts}
          >
            <span className="spot-chat-sidebar-utility-icon" aria-hidden="true">
              {icons.artifacts}
            </span>
            <span className="spot-chat-sidebar-utility-label">Artifacts</span>
            <span className="spot-chat-sidebar-utility-badge">
              {Math.max(1, artifactCount)}
            </span>
          </button>
        ) : null}
      </div>

      <div className="spot-chat-sidebar-history">
        <div className="spot-chat-sidebar-section-head">
          <span>Recent</span>
        </div>

        {hasResults ? (
          filteredGroups.map((group) => (
            <section key={group.label} className="spot-chat-sidebar-group">
              <div className="spot-chat-sidebar-group-label">{group.label}</div>
              <div className="spot-chat-sidebar-group-items">
                {group.sessions.map((session) => {
                  const isActive = activeSessionId === session.session_id;
                  const secondary =
                    session.resume_hint || session.current_step || session.phase;
                  const sessionTooltip = [
                    session.title,
                    secondary,
                    formatSessionMeta(session.timestamp),
                  ]
                    .filter(Boolean)
                    .join(" • ");
                  return (
                    <button
                      key={session.session_id}
                      type="button"
                      className={`spot-chat-sidebar-session ${
                        isActive ? "is-active" : ""
                      }`}
                      onClick={() => onSelectSession(session.session_id)}
                      title={sessionTooltip}
                    >
                      <span className="spot-chat-sidebar-session-copy">
                        <strong>{session.title}</strong>
                        {isActive && secondary ? <span>{secondary}</span> : null}
                      </span>
                    </button>
                  );
                })}
              </div>
            </section>
          ))
        ) : (
          <div className="spot-chat-sidebar-empty">
            {searchQuery.trim()
              ? "No Chat sessions match that search."
              : "Start a Chat request to build a recent history."}
          </div>
        )}
      </div>
    </aside>
  );
}
