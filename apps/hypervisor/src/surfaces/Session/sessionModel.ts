// Session detail model — source-owned, native daemon boundary (cut 4: Session / Workspace).
//
// Source-derived from the product-ui working surface (the conversation/run-timeline + workspace
// split): the daemon's thread record is the canonical session, and the daemon's own runtime event
// stream (GET /v1/threads/:id/events, server-sent events) is the canonical turn timeline. We fold
// the runtime events into turns (bounded by turn.started / turn.completed) and render them directly.
// No upstream-namespace wire — every call is the daemon's own /v1 contract.
import { daemon, DaemonError } from "../../data/daemon";
import { type Thread, toSession, type Session } from "../../data/threads";

// ── Timeline model (typed to the daemon runtime event JSON) ─────────────────────────────────────
// A runtime event as emitted on the thread event stream. Field names track the daemon JSON exactly;
// both camel/snake variants appear in the wire, so the parser is defensive.
export type RuntimeEvent = {
  seq?: number;
  actor?: string; // "runtime" | "assistant" | "user" | …
  event_kind?: string; // "thread.started" | "turn.started" | "item.delta" | "turn.completed" | …
  event?: string;
  turn_id?: string | null;
  created_at?: string;
  payload_summary?: Record<string, unknown> | null;
  payload?: Record<string, unknown> | null;
};

export type TimelineItem = {
  seq: number;
  kind: string; // normalized event_kind
  actor: string; // "runtime" | "assistant" | "user" | "system"
  text: string | null; // human-meaningful line, when the event carries one
  at?: string;
};

export type Turn = {
  id: string; // turn_id (or a synthetic id for stray events)
  index: number; // 1-based turn ordinal
  prompt: string | null; // the user/run prompt that opened the turn, when present
  reply: string | null; // the assistant's completed reply, when present
  status: "running" | "completed" | "active"; // derived from turn.started/turn.completed
  items: TimelineItem[]; // the activity within the turn
};

export type SessionTimeline = {
  session: Session;
  thread: Thread;
  turns: Turn[];
};

// ── Helpers ─────────────────────────────────────────────────────────────────────────────────────
function str(v: unknown): string | null {
  return typeof v === "string" && v.trim() ? v.trim() : null;
}

// Pull a human-meaningful line from an event's payload, when one exists. The daemon's runtime
// events carry assistant text under text/result/prompt; everything else is structured activity.
function eventText(ev: RuntimeEvent): string | null {
  const p = ev.payload_summary || ev.payload || {};
  return str(p["text"]) || str(p["result"]) || str(p["prompt"]) || null;
}

function normalizeActor(ev: RuntimeEvent): string {
  const a = (ev.actor || "").toLowerCase();
  if (a === "assistant" || a === "user" || a === "runtime") return a;
  return "system";
}

function prettyKind(kind: string): string {
  return kind.replace(/^(item|runtime|turn|thread|usage)\./, "").replace(/[._]/g, " ").trim() || kind;
}

// Parse a server-sent-events body into runtime event objects. Each SSE record is a blank-line
// separated block with `data:` line(s) carrying the JSON event.
export function parseEventStream(body: string): RuntimeEvent[] {
  const out: RuntimeEvent[] = [];
  for (const block of body.split(/\n\n+/)) {
    if (!block.trim()) continue;
    let data = "";
    for (const line of block.split(/\n/)) {
      if (line.startsWith("data:")) data += line.slice(5).trim();
    }
    if (!data) continue;
    try {
      out.push(JSON.parse(data) as RuntimeEvent);
    } catch {
      /* skip non-JSON keepalive frames */
    }
  }
  return out;
}

// Fold a flat runtime-event list into ordered turns. turn.started opens a turn, turn.completed
// closes it; events that carry assistant text become the reply, the run prompt becomes the prompt,
// and the remaining structured events are kept as activity items.
export function eventsToTurns(events: RuntimeEvent[]): Turn[] {
  const byId = new Map<string, Turn>();
  const order: string[] = [];
  let loose: Turn | null = null;

  const ensure = (id: string): Turn => {
    let t = byId.get(id);
    if (!t) {
      t = { id, index: 0, prompt: null, reply: null, status: "active", items: [] };
      byId.set(id, t);
      order.push(id);
    }
    return t;
  };

  for (const ev of [...events].sort((a, b) => (a.seq ?? 0) - (b.seq ?? 0))) {
    const kind = ev.event_kind || ev.event || "";
    const actor = normalizeActor(ev);
    const text = eventText(ev);
    const turnId = str(ev.turn_id ?? undefined);

    if (!turnId) {
      // Thread-level events (e.g. thread.started) — keep as a synthetic leading turn's activity.
      if (kind === "thread.started") continue; // implicit; the header conveys this
      loose = loose || ensure("__thread__");
      loose.items.push({ seq: ev.seq ?? 0, kind: prettyKind(kind), actor, text, at: ev.created_at });
      continue;
    }

    const turn = ensure(turnId);
    if (kind === "turn.started") {
      turn.status = "running";
      const p = ev.payload_summary || ev.payload || {};
      turn.prompt = str(p["prompt"]) || turn.prompt;
    } else if (kind === "turn.completed") {
      turn.status = "completed";
      const p = ev.payload_summary || ev.payload || {};
      turn.reply = str(p["result"]) || turn.reply;
    } else if (actor === "assistant" && text) {
      // Streamed assistant text (item.delta) — accumulate into the reply.
      turn.reply = turn.reply ? `${turn.reply}${text}` : text;
    } else {
      turn.items.push({ seq: ev.seq ?? 0, kind: prettyKind(kind), actor, text, at: ev.created_at });
    }
  }

  const turns = order.filter((id) => id !== "__thread__" || (byId.get(id)?.items.length ?? 0) > 0).map((id) => byId.get(id)!);
  turns.forEach((t, i) => (t.index = i + 1));
  return turns;
}

// ── Data boundary ────────────────────────────────────────────────────────────────────────────────
// Fetch the thread record (native /v1/threads/:id).
export async function fetchThread(id: string): Promise<Thread> {
  return daemon.get<Thread>(`/threads/${encodeURIComponent(id)}`);
}

// Fetch the runtime event stream for a thread and fold it into turns. The events route is SSE
// (text/event-stream), so we read it as text and parse rather than via the JSON client. Same /v1
// origin / proxy — still the daemon's own contract, no upstream-namespace bridge.
export async function fetchTurns(id: string): Promise<Turn[]> {
  const res = await fetch(`/v1/threads/${encodeURIComponent(id)}/events`, {
    headers: { accept: "text/event-stream" },
  });
  if (!res.ok) {
    if (res.status === 404) return [];
    throw new DaemonError(res.status, `events HTTP ${res.status}`);
  }
  const body = await res.text();
  return eventsToTurns(parseEventStream(body));
}

// Load the full session timeline: the thread record + its folded turns.
export async function fetchSessionTimeline(id: string): Promise<SessionTimeline> {
  const thread = await fetchThread(id);
  const turns = await fetchTurns(id).catch(() => [] as Turn[]);
  return { session: toSession(thread), thread, turns };
}
