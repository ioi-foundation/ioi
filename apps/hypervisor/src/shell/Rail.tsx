import { Link, useLocation } from "react-router-dom";
import { BrandMark, IconApplications, IconAutomations, IconHome, IconPlus, IconProjects, IconSettings } from "../ui";

const NAV = [
  { to: "/home", label: "Home", Icon: IconHome },
  { to: "/systems", label: "Systems", Icon: IconProjects },
  { to: "/projects", label: "Projects", Icon: IconProjects },
  { to: "/work", label: "Work", Icon: IconApplications },
  { to: "/automations", label: "Automations", Icon: IconAutomations },
] as const;

export function Rail({ onOpenApplications }: { onOpenApplications: () => void }) {
  const { pathname } = useLocation();
  return <nav className="hv-rail" data-testid="hv-rail" aria-label="Primary">
    <Link to="/home" className="hv-rail__brand"><BrandMark size={18} /><span>Hypervisor</span></Link>
    <Link to="/work/new-session" className="hv-rail__cta"><span className="hv-row"><IconPlus size={15} /> New Session</span><kbd className="hv-kbd">⌘O</kbd></Link>
    {NAV.map(({ to, label, Icon }) => <Link key={to} to={to} className={`hv-rail__item ${pathname === to || pathname.startsWith(to + "/") ? "hv-rail__item--active" : ""}`}><Icon size={16} /><span>{label}</span></Link>)}
    <button className={`hv-rail__item ${pathname === "/applications" ? "hv-rail__item--active" : ""}`} onClick={onOpenApplications}><IconApplications size={16} /><span>Applications</span></button>
    <div className="hv-rail__group">Work</div>
    <Link to="/work/sessions" className="hv-rail__item">Sessions</Link>
    <span className="hv-spacer" />
    <div className="hv-rail__sep" />
    <Link to="/settings" className="hv-rail__item"><IconSettings size={16} /><span>Settings</span></Link>
    <div className="hv-rail__account"><span className="hv-avatar">IO</span><div className="hv-col"><strong>Local operator</strong><span className="hv-tertiary">org://local</span></div></div>
  </nav>;
}
