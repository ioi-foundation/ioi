// Session detail / Workspace — source-owned React (cut 4). Route: /sessions/:id.
//
// A split between the agent conversation / run-timeline (left) and the workspace — files / editor /
// terminal (right). The conversation renders the daemon's REAL turns, folded from its runtime event
// stream (GET /v1/threads/:id/events). The workspace mounts the source-owned VS Code-like workbench
// (@ioi/workspace-substrate WorkspaceHost) bound to the session's LIVE environment via the daemon's
// own env-ops contracts (daemonWorkspaceAdapter): real files, real editor, a real openpty terminal.
// When the thread carries no environment, the workspace shows an honest "no environment bound"
// state instead of a scaffold. Both panes are wired to real daemon data.
import { useEffect, useMemo, useState } from "react";
import { useParams } from "react-router-dom";
import { MessageSquare, Layers, User, Bot, Cog, Circle, RefreshCw } from "lucide-react";
import { WorkspaceHost } from "@ioi/workspace-substrate";
import "./Session.css";
import { relativeTime, type Thread } from "../../data/threads";
import { daemonWorkspaceAdapter } from "../../data/workspaceAdapter";
import { fetchSessionTimeline, type SessionTimeline, type Turn } from "./sessionModel";

// Resolve the session's bound environment id from the daemon thread record. The thread's workspace
// field carries the environment id when the session is bound to one (e.g. "env_…"); anything else
// (a plain ".", a path, or absent) means no environment is bound to this session.
function resolveEnvironmentId(thread: Thread | undefined): string | null {
  const candidate = (thread?.workspace || thread?.workspace_root || "").trim();
  return /^env_[A-Za-z0-9_-]+$/.test(candidate) ? candidate : null;
}

// ── Conversation / run-timeline ──────────────────────────────────────────────────────────────────
function ActorIcon({ actor }: { actor: string }) {
  if (actor === "user") return <User size={14} />;
  if (actor === "assistant") return <Bot size={14} />;
  return <Cog size={14} />;
}

function TurnCard({ turn }: { turn: Turn }) {
  return (
    <article className="se-turn" data-testid="session-turn">
      <header className="se-turnhead">
        <span className="se-turnno">Turn {turn.index}</span>
        <span className={`se-turnstatus is-${turn.status}`}>
          <Circle size={8} /> {turn.status}
        </span>
      </header>

      {turn.prompt && (
        <div className="se-msg is-user" data-testid="session-turn-prompt">
          <span className="se-msgicon"><User size={14} /></span>
          <div className="se-msgbody">{turn.prompt}</div>
        </div>
      )}

      {turn.items.length > 0 && (
        <ul className="se-activity">
          {turn.items.map((it) => (
            <li key={it.seq} className="se-act">
              <span className="se-acticon"><ActorIcon actor={it.actor} /></span>
              <span className="se-actkind">{it.kind}</span>
              {it.text && <span className="se-acttext">{it.text}</span>}
            </li>
          ))}
        </ul>
      )}

      {turn.reply && (
        <div className="se-msg is-agent" data-testid="session-turn-reply">
          <span className="se-msgicon"><Bot size={14} /></span>
          <div className="se-msgbody">{turn.reply}</div>
        </div>
      )}
    </article>
  );
}

// ── Surface ──────────────────────────────────────────────────────────────────────────────────────
export function SessionView() {
  const { id = "" } = useParams<{ id: string }>();
  const [data, setData] = useState<SessionTimeline | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    let live = true;
    setData(null);
    setError(null);
    fetchSessionTimeline(id)
      .then((d) => live && setData(d))
      .catch((e) => live && setError(String(e?.message || e)));
    return () => {
      live = false;
    };
  }, [id, reloadKey]);

  const session = data?.session;
  const turns = data?.turns ?? [];
  const envId = resolveEnvironmentId(data?.thread);
  // Build the live env-ops adapter once per bound environment (it owns the env's capability lease).
  const adapter = useMemo(() => (envId ? daemonWorkspaceAdapter(envId) : null), [envId]);

  return (
    <div className="se">
      {/* Session header */}
      <header className="se-header" data-testid="session-header">
        <div className="se-headmain">
          <span className={"se-headdot" + (session?.running ? " is-running" : "")} />
          <h1 className="se-title">{session?.title || (error ? "Session" : "Loading session…")}</h1>
          {session && <span className="se-status">{session.running ? "active" : "stopped"}</span>}
        </div>
        <div className="se-headmeta">
          {session?.updatedAt && <span className="se-updated">updated {relativeTime(session.updatedAt)}</span>}
          <button className="se-refresh" onClick={() => setReloadKey((k) => k + 1)} title="Refresh">
            <RefreshCw size={14} />
          </button>
        </div>
      </header>

      <div className="se-split">
        {/* Conversation / run timeline */}
        <section className="se-pane se-convo">
          <div className="se-panehead">
            <MessageSquare size={15} /> Conversation
          </div>
          <div className="se-timeline" data-testid="session-timeline">
            {error && (
              <div className="se-state" data-testid="session-error">
                Daemon unavailable: {error}
              </div>
            )}
            {!error && data === null && (
              <div className="se-state" data-testid="session-loading">
                Loading conversation…
              </div>
            )}
            {!error && data !== null && turns.length === 0 && (
              <div className="se-state" data-testid="session-empty">
                No turns yet. This session has not run the agent.
              </div>
            )}
            {!error && data !== null && turns.map((t) => <TurnCard key={t.id} turn={t} />)}
          </div>
        </section>

        {/* Workspace — source-owned workbench bound to the session's live environment */}
        <section className="se-pane se-workspace" data-testid="session-workspace">
          <div className="se-panehead">
            <Layers size={15} /> Workspace
            {envId && <code className="se-workenv" data-testid="session-workspace-env">{envId}</code>}
          </div>
          <div className="se-workhost">
            {adapter && envId ? (
              <WorkspaceHost
                key={envId}
                adapter={adapter}
                root={envId}
                title={`Workspace · ${envId}`}
                showHeader={false}
                showBottomPanel
                terminalAutoStart
                initialState={{
                  activePane: "files",
                  activeBottomPanel: "terminal",
                  bottomPanelOpen: true,
                  // Expand the workspace root so the env's real files are visible on open.
                  expandedPaths: { ".": true },
                  documents: [],
                  activeDocumentPath: null,
                }}
              />
            ) : (
              <div className="se-state" data-testid="session-no-env">
                No environment bound to this session. Bind a running environment to open its files
                and terminal here.
              </div>
            )}
          </div>
        </section>
      </div>
    </div>
  );
}
