import { SessionSummary } from "../../types";

export function formatTimeAgo(ms: number): string {
  const diff = Date.now() - ms;
  const min = Math.floor(diff / 60000);
  if (min < 1) return "now";
  if (min < 60) return `${min}m ago`;
  const hours = Math.floor(min / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

export function groupSessionsByDate(sessions: SessionSummary[]): { label: string; sessions: SessionSummary[] }[] {
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