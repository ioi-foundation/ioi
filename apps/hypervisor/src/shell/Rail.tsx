// Layer 3 — the canonical global rail (foundations/01-ux-shell-and-ia.md), product-grade: brand
// mark, icons, primary New Session with shortcut hint, Sessions section, org/account footer.
// Stable + minimal. Providers/Environments are NOT rail items — they are catalog surfaces.
import { useEffect, useState } from "react";
import { Link, useLocation } from "react-router-dom";
import {
  BrandMark, IconHome, IconProjects, IconAutomations, IconApplications, IconSessions,
  IconSettings, IconPlus, StatusDot,
} from "../ui";
import { createHypervisorDaemonClient, type EnvironmentSummary } from "../services/hypervisorDaemonClient";

const cx = (...c: Array<string | false | undefined>) => c.filter(Boolean).join(" ");
const client = createHypervisorDaemonClient();
const shortId = (id: string) => id.replace(/^env_/, "").slice(0, 8);

const NAV = [
  { to: "/", label: "Home", Icon: IconHome },
  { to: "/projects", label: "Projects", Icon: IconProjects },
  { to: "/automations", label: "Automations", Icon: IconAutomations },
] as const;

export function Rail({ onOpenApplications }: { onOpenApplications: () => void }) {
  const { pathname } = useLocation();
  const active = (to: string) => (to === "/" ? pathname === "/" : pathname.startsWith(to));
  const [sessions, setSessions] = useState<EnvironmentSummary[]>([]);
  useEffect(() => {
    let on = true;
    const load = () => client.listEnvironments().then((r) => { if (on) setSessions((r.environments ?? []).filter((e) => e.status?.phase === "running")); }).catch(() => {});
    void load();
    const t = setInterval(load, 5000); // live-ish without ceremony
    return () => { on = false; clearInterval(t); };
  }, [pathname]);
  return (
    <nav className="hv-rail" data-testid="hv-rail">
      <div className="hv-rail__brand"><BrandMark size={18} /><span>Hypervisor</span></div>

      <Link to="/new" className="hv-rail__cta" data-testid="rail-new-session">
        <span className="hv-row"><IconPlus size={15} /> New Session</span>
        <kbd className="hv-kbd">⌘O</kbd>
      </Link>

      {NAV.map(({ to, label, Icon }) => (
        <Link key={to} to={to} className={cx("hv-rail__item", active(to) && "hv-rail__item--active")} data-testid={`rail-${label.toLowerCase()}`}>
          <Icon size={16} /><span>{label}</span>
        </Link>
      ))}
      <button className="hv-rail__item" onClick={onOpenApplications} data-testid="rail-applications">
        <IconApplications size={16} /><span>Applications</span>
      </button>

      <div className="hv-rail__group">Sessions</div>
      <Link to="/sessions" className={cx("hv-rail__item", active("/sessions") && "hv-rail__item--active")} data-testid="rail-sessions">
        <IconSessions size={16} /><span>All sessions</span>
      </Link>
      {sessions.slice(0, 4).map((e) => (
        <Link key={e.id} to={`/workbench/${e.id}`} className="hv-rail__session" data-testid="rail-live-session">
          <StatusDot tone="success" /><span className="hv-mono">{shortId(e.id)}</span><span className="hv-tertiary">running</span>
        </Link>
      ))}
      {sessions.length === 0 && <div className="hv-rail__session"><span className="hv-tertiary">No active sessions</span></div>}

      <span className="hv-spacer" />
      <div className="hv-rail__sep" />
      <Link to="/settings" className="hv-rail__item" data-testid="rail-settings"><IconSettings size={16} /><span>Organization settings</span></Link>
      <div className="hv-rail__account">
        <span className="hv-avatar">HV</span>
        <div className="hv-col" style={{ gap: 0 }}><span className="hv-rail__account-name">Operator</span><span className="hv-tertiary">Workspace</span></div>
      </div>
    </nav>
  );
}
