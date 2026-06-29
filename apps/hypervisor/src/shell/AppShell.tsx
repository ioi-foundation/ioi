// Source-owned app shell — the persistent rail + main outlet. Source-derived from the
// product-ui sidebar anatomy (New Session, primary nav, Applications, Sessions tree, org
// switcher) with the data boundary on /v1/threads. Clean, IOI-owned; no harvested markup.
import { useEffect, useState } from "react";
import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { Home, FolderGit2, Workflow, LayoutGrid, Plug, Plus, Settings, ChevronsUpDown } from "lucide-react";
import "./AppShell.css";
import { createSession, listSessions, type Session } from "../data/threads";

const NAV = [
  { to: "/", label: "Home", icon: Home, end: true },
  { to: "/projects", label: "Projects", icon: FolderGit2 },
  { to: "/automations", label: "Automations", icon: Workflow },
  { to: "/applications", label: "Applications", icon: LayoutGrid },
  { to: "/connections", label: "Connections", icon: Plug },
];

function IoiMark() {
  return (
    <svg className="sh-mark" viewBox="0 0 24 24" width="20" height="20" aria-hidden="true">
      <path d="M12 2 22 12 12 22 2 12Z" fill="none" stroke="currentColor" strokeWidth="1.6" />
      <circle cx="12" cy="12" r="2.4" fill="currentColor" />
    </svg>
  );
}

export function AppShell() {
  const [sessions, setSessions] = useState<Session[] | null>(null);
  const navigate = useNavigate();

  useEffect(() => {
    let live = true;
    listSessions().then((s) => live && setSessions(s)).catch(() => live && setSessions([]));
    return () => {
      live = false;
    };
  }, []);

  async function newSession() {
    try {
      const { id } = await createSession();
      if (id) navigate(`/sessions/${id}`);
    } catch {
      /* daemon down — no-op */
    }
  }

  return (
    <div className="sh">
      <aside className="sh-rail" data-testid="app-rail">
        <div className="sh-railhead">
          <span className="sh-brand"><IoiMark /></span>
        </div>

        <button className="sh-new" onClick={newSession} data-testid="new-session">
          <Plus size={16} />
          <span>New Session</span>
          <kbd className="sh-kbd">Ctrl O</kbd>
        </button>

        <nav className="sh-nav" data-testid="rail-nav">
          {NAV.map((n) => (
            <NavLink
              key={n.to}
              to={n.to}
              end={n.end}
              className={({ isActive }) => "sh-navitem" + (isActive ? " is-active" : "")}
            >
              <n.icon size={17} />
              <span>{n.label}</span>
            </NavLink>
          ))}
        </nav>

        <div className="sh-sec">
          <div className="sh-sechead"><LayoutGrid size={14} /> Applications</div>
          <div className="sh-secempty">Your favorite apps will appear here</div>
        </div>

        <div className="sh-sessions" data-testid="rail-sessions">
          <div className="sh-sechead sh-sessionhead">Sessions</div>
          {sessions === null && <div className="sh-secempty">Loading…</div>}
          {sessions !== null && sessions.length === 0 && <div className="sh-secempty">No sessions yet</div>}
          <div className="sh-sesslist">
            {(sessions || []).slice(0, 40).map((s) => (
              <NavLink
                key={s.id}
                to={`/sessions/${s.id}`}
                className={({ isActive }) => "sh-sess" + (isActive ? " is-active" : "")}
                title={s.title}
                data-testid="rail-session"
              >
                <span className={"sh-dot" + (s.running ? " is-running" : "")} />
                <span className="sh-sesstitle">{s.title}</span>
              </NavLink>
            ))}
          </div>
        </div>

        <div className="sh-foot">
          <NavLink to="/settings" className="sh-footitem"><Settings size={16} /> Organization settings</NavLink>
          <div className="sh-ws">
            <span className="sh-wsmark">IW</span>
            <span className="sh-wsname">IOI Workspace</span>
            <ChevronsUpDown size={14} className="sh-wschev" />
          </div>
        </div>
      </aside>

      <main className="sh-main" data-testid="app-main">
        <Outlet />
      </main>
    </div>
  );
}
