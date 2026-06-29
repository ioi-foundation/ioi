// Source-owned app shell — the persistent rail + main outlet. Source-derived from the
// product-ui sidebar anatomy (New Session, primary nav, Applications, Sessions tree, org
// switcher + account popover) with the data boundary on /v1/threads + /v1/hypervisor/auth.
import { useEffect, useRef, useState } from "react";
import { NavLink, Outlet, useNavigate } from "react-router-dom";
import {
  Home, FolderGit2, Workflow, LayoutGrid, Plug, Plus, Settings, ChevronsUpDown,
  ExternalLink, MessageSquare, LogOut, Check,
} from "lucide-react";
import "./AppShell.css";
import { createSession, listSessions, type Session } from "../data/threads";
import { fetchAccount, fetchOrgs, initials, type Account, type Org } from "../data/account";
import { daemon } from "../data/daemon";
import { SkeletonRows } from "../components/Skeleton";

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

function AccountMenu({ account, orgs, onClose }: { account: Account | null; orgs: Org[]; onClose: () => void }) {
  const navigate = useNavigate();
  async function logout() {
    await daemon.post("/hypervisor/auth/logout").catch(() => {});
    onClose();
    window.location.reload();
  }
  return (
    <div className="sh-menu" role="menu" data-testid="account-menu">
      <div className="sh-menu-head">
        <div className="sh-menu-id">
          <div className="sh-menu-name">{account?.name || "Operator"}</div>
          <div className="sh-menu-email">{account?.email || ""}</div>
        </div>
        <button className="sh-menu-gear" title="Settings" onClick={() => { onClose(); navigate("/settings"); }}>
          <Settings size={15} />
        </button>
      </div>
      <div className="sh-menu-sec">
        <div className="sh-menu-label">Organizations</div>
        {orgs.map((o) => (
          <div className="sh-menu-org" key={o.name}>
            <span className="sh-wsmark sh-wsmark-sm">{initials(o.name)}</span>
            <span className="sh-menu-orgname">{o.name}</span>
            <span className="sh-menu-tier">{o.tier}</span>
            {o.current && <Check size={15} className="sh-menu-check" />}
          </div>
        ))}
        <button className="sh-menu-join" role="menuitem"><Plus size={15} /> Join or create an organization</button>
      </div>
      <div className="sh-menu-div" />
      <a className="sh-menu-item" href="https://ioi.com/docs" target="_blank" rel="noopener" role="menuitem">
        Docs <ExternalLink size={14} className="sh-menu-trail" />
      </a>
      <a className="sh-menu-item" href="https://ioi.com/support" target="_blank" rel="noopener" role="menuitem">
        Support <MessageSquare size={14} className="sh-menu-trail" />
      </a>
      <div className="sh-menu-item sh-menu-static" role="menuitem">
        Keyboard shortcuts <kbd className="sh-kbd sh-menu-trail">Ctrl /</kbd>
      </div>
      <button className="sh-menu-item" role="menuitem" onClick={logout} data-testid="logout">
        Log out <LogOut size={14} className="sh-menu-trail" />
      </button>
    </div>
  );
}

export function AppShell() {
  const [sessions, setSessions] = useState<Session[] | null>(null);
  const [account, setAccount] = useState<Account | null>(null);
  const [orgs, setOrgs] = useState<Org[]>([]);
  const [menuOpen, setMenuOpen] = useState(false);
  const footerRef = useRef<HTMLDivElement>(null);
  const navigate = useNavigate();

  useEffect(() => {
    let live = true;
    listSessions().then((s) => live && setSessions(s)).catch(() => live && setSessions([]));
    fetchAccount().then((a) => live && setAccount(a)).catch(() => {});
    fetchOrgs().then((o) => live && setOrgs(o)).catch(() => {});
    return () => { live = false; };
  }, []);

  useEffect(() => {
    if (!menuOpen) return;
    const onDoc = (e: MouseEvent) => { if (footerRef.current && !footerRef.current.contains(e.target as Node)) setMenuOpen(false); };
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") setMenuOpen(false); };
    document.addEventListener("mousedown", onDoc);
    document.addEventListener("keydown", onKey);
    return () => { document.removeEventListener("mousedown", onDoc); document.removeEventListener("keydown", onKey); };
  }, [menuOpen]);

  async function newSession() {
    try { const { id } = await createSession(); if (id) navigate(`/sessions/${id}`); } catch { /* daemon down */ }
  }

  return (
    <div className="sh">
      <aside className="sh-rail" data-testid="app-rail">
        <div className="sh-railhead"><span className="sh-brand"><IoiMark /></span></div>

        <button className="sh-new" onClick={newSession} data-testid="new-session">
          <Plus size={16} /><span>New Session</span><kbd className="sh-kbd">Ctrl O</kbd>
        </button>

        <nav className="sh-nav" data-testid="rail-nav">
          {NAV.map((n) => (
            <NavLink key={n.to} to={n.to} end={n.end} className={({ isActive }) => "sh-navitem" + (isActive ? " is-active" : "")}>
              <n.icon size={17} /><span>{n.label}</span>
            </NavLink>
          ))}
        </nav>

        <div className="sh-sec">
          <div className="sh-sechead"><LayoutGrid size={14} /> Applications</div>
          <div className="sh-secempty">Your favorite apps will appear here</div>
        </div>

        <div className="sh-sessions" data-testid="rail-sessions">
          <div className="sh-sechead sh-sessionhead">Sessions</div>
          {sessions === null && <SkeletonRows rows={6} className="sh-sessskel" />}
          {sessions !== null && sessions.length === 0 && <div className="sh-secempty">No sessions yet</div>}
          <div className="sh-sesslist">
            {(sessions || []).slice(0, 40).map((s) => (
              <NavLink key={s.id} to={`/sessions/${s.id}`} className={({ isActive }) => "sh-sess" + (isActive ? " is-active" : "")} title={s.title} data-testid="rail-session">
                <span className={"sh-dot" + (s.running ? " is-running" : "")} />
                <span className="sh-sesstitle">{s.title}</span>
              </NavLink>
            ))}
          </div>
        </div>

        <div className="sh-foot" ref={footerRef}>
          <NavLink to="/settings" className="sh-footitem"><Settings size={16} /> Organization settings</NavLink>
          <div className="sh-ws-wrap">
            {menuOpen && <AccountMenu account={account} orgs={orgs} onClose={() => setMenuOpen(false)} />}
            <button className={"sh-ws" + (menuOpen ? " is-open" : "")} onClick={() => setMenuOpen((o) => !o)} data-testid="workspace-switcher">
              <span className="sh-wsmark">{initials(orgs[0]?.name || "IOI Workspace")}</span>
              <span className="sh-wsmeta">
                <span className="sh-wsname">{orgs[0]?.name || "IOI Workspace"}</span>
                <span className="sh-wsuser">{account?.name || ""}</span>
              </span>
              <ChevronsUpDown size={14} className="sh-wschev" />
            </button>
          </div>
        </div>
      </aside>

      <main className="sh-main" data-testid="app-main"><Outlet /></main>
    </div>
  );
}
