// Threads (sessions) data client — source-owned, native daemon boundary (/v1/threads).
// Source-derived from the product-ui projection (threadToAgentExecution): the daemon's thread
// record is the canonical session object; surfaces render it directly.
import { daemon } from "./daemon";

export type Thread = {
  thread_id?: string;
  id?: string;
  title?: string;
  status?: string;
  session_id?: string;
  created_at?: string;
  updated_at?: string;
  workspace?: string;
};

export type Session = {
  id: string;
  title: string;
  running: boolean;
  createdAt?: string;
  updatedAt?: string;
};

export function toSession(t: Thread): Session {
  const id = t.thread_id || t.id || "";
  const title = t.title && t.title.trim() && t.title.trim() !== "." ? t.title.trim() : "Untitled session";
  return {
    id,
    title,
    running: (t.status || "active") === "active",
    createdAt: t.created_at,
    updatedAt: t.updated_at || t.created_at,
  };
}

export async function listSessions(): Promise<Session[]> {
  const r = await daemon.get<{ threads?: Thread[] } | Thread[]>("/threads").catch(() => ({}) as { threads?: Thread[] });
  const threads = Array.isArray(r) ? r : r.threads || [];
  return threads
    .map(toSession)
    .sort((a, b) => Date.parse(b.updatedAt || "") - Date.parse(a.updatedAt || ""));
}

export async function createSession(title?: string): Promise<{ id: string }> {
  const r = await daemon.post<{ thread_id?: string; id?: string }>("/threads", title ? { title } : {});
  return { id: r.thread_id || r.id || "" };
}

export function relativeTime(iso?: string): string {
  if (!iso) return "";
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return "";
  const secs = Math.max(0, Math.round((Date.now() - then) / 1000));
  if (secs < 60) return `${secs}s ago`;
  const mins = Math.round(secs / 60);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.round(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.round(hrs / 24);
  if (days < 7) return `${days}d ago`;
  return `${Math.round(days / 7)}w ago`;
}
