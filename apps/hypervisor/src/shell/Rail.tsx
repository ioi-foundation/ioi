// Layer 3 — the canonical global rail (foundations/01-ux-shell-and-ia.md). Stable + minimal:
// + New Session · Home · Projects · Automations · Applications · Sessions, then org/account.
// Providers/Environments are NOT rail items — they are Applications-catalog surfaces opened into
// the singular Open Application frame.
import { Link, useLocation } from "react-router-dom";

const cx = (...c: Array<string | false | undefined>) => c.filter(Boolean).join(" ");

const NAV: Array<{ to: string; label: string }> = [
  { to: "/", label: "Home" },
  { to: "/projects", label: "Projects" },
  { to: "/automations", label: "Automations" },
];

export function Rail({ onOpenApplications }: { onOpenApplications: () => void }) {
  const { pathname } = useLocation();
  const active = (to: string) => (to === "/" ? pathname === "/" : pathname.startsWith(to));
  return (
    <nav className="hv-rail" data-testid="hv-rail">
      <Link to="/new" className="hv-rail__item hv-rail__item--cta" data-testid="rail-new-session">+ New Session</Link>
      {NAV.map((n) => (
        <Link key={n.to} to={n.to} className={cx("hv-rail__item", active(n.to) && "hv-rail__item--active")} data-testid={`rail-${n.label.toLowerCase()}`}>
          {n.label}
        </Link>
      ))}
      <button className="hv-rail__item" onClick={onOpenApplications} data-testid="rail-applications">Applications</button>
      <div className="hv-rail__group">Sessions</div>
      <Link to="/sessions" className={cx("hv-rail__item", active("/sessions") && "hv-rail__item--active")} data-testid="rail-sessions">
        All sessions
      </Link>
      <span className="hv-spacer" />
      <div className="hv-rail__sep" />
      <Link to="/settings" className="hv-rail__item" data-testid="rail-settings">Organization settings</Link>
      <span className="hv-rail__item hv-tertiary">Workspace / account</span>
    </nav>
  );
}
