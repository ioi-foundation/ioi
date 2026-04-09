import { useMemo } from "react";

export interface SessionHistorySummaryLike {
  session_id: string;
  title: string;
  timestamp: number;
  phase?: string | null;
  current_step?: string | null;
  resume_hint?: string | null;
  workspace_root?: string | null;
}

export interface SessionHistoryGroup<TSession extends SessionHistorySummaryLike> {
  label: string;
  sessions: TSession[];
}

export function formatSessionTimeAgo(ms: number): string {
  const diff = Date.now() - ms;
  const min = Math.floor(diff / 60_000);
  if (min < 1) return "now";
  if (min < 60) return `${min}m ago`;
  const hours = Math.floor(min / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

export function groupSessionHistoryByDate<TSession extends SessionHistorySummaryLike>(
  sessions: TSession[],
): SessionHistoryGroup<TSession>[] {
  const today = new Date().setHours(0, 0, 0, 0);
  const yesterday = today - 86_400_000;
  const lastWeek = today - 7 * 86_400_000;

  const groups: SessionHistoryGroup<TSession>[] = [
    { label: "Today", sessions: [] },
    { label: "Yesterday", sessions: [] },
    { label: "Last 7 days", sessions: [] },
    { label: "Older", sessions: [] },
  ];

  sessions.forEach((session) => {
    if (session.timestamp >= today) {
      groups[0].sessions.push(session);
      return;
    }
    if (session.timestamp >= yesterday) {
      groups[1].sessions.push(session);
      return;
    }
    if (session.timestamp >= lastWeek) {
      groups[2].sessions.push(session);
      return;
    }
    groups[3].sessions.push(session);
  });

  return groups.filter((group) => group.sessions.length > 0);
}

export interface UseSessionHistoryBrowserOptions<
  TSession extends SessionHistorySummaryLike,
> {
  sessions: TSession[];
  searchQuery: string;
}

export function useSessionHistoryBrowser<
  TSession extends SessionHistorySummaryLike,
>({ sessions, searchQuery }: UseSessionHistoryBrowserOptions<TSession>) {
  const normalizedQuery = searchQuery.trim().toLowerCase();

  const filteredSessions = useMemo(() => {
    if (!normalizedQuery) {
      return sessions;
    }

    return sessions.filter((session) =>
      [
        session.title,
        session.phase,
        session.current_step,
        session.resume_hint,
        session.workspace_root,
        session.session_id,
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase()
        .includes(normalizedQuery),
    );
  }, [normalizedQuery, sessions]);

  const groupedSessions = useMemo(
    () => groupSessionHistoryByDate(filteredSessions),
    [filteredSessions],
  );

  return {
    filteredSessions,
    groupedSessions,
  };
}
