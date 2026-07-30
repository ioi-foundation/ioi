import { useEffect, useMemo, useState, type ReactNode } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import "../ui";
import { Rail } from "./Rail";
import { ApplicationsModal } from "./ApplicationsModal";
import { loadProductSurfaceProjection, type ProductSurfaceProjection } from "../data/productSurface";

export function AppShell({ children }: { children: ReactNode }) {
  const [appsOpen, setAppsOpen] = useState(false);
  const [projection, setProjection] = useState<ProductSurfaceProjection | null>(null);
  const location = useLocation();
  const navigate = useNavigate();
  useEffect(() => { void loadProductSurfaceProjection().then((result) => setProjection(result.projection)); }, []);
  useEffect(() => {
    const handler = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") { event.preventDefault(); setAppsOpen(true); }
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "o") { event.preventDefault(); navigate("/work/new-session"); }
    };
    window.addEventListener("keydown", handler); return () => window.removeEventListener("keydown", handler);
  }, [navigate]);
  const crumbs = useMemo(() => location.pathname.split("/").filter(Boolean), [location.pathname]);
  return <div className="hv-shell" data-testid="app-shell">
    <Rail onOpenApplications={() => setAppsOpen(true)} />
    <section className="hv-frame">
      <header className="hv-frame__bar">
        <button className="hv-back" onClick={() => navigate(-1)} aria-label="Back">←</button>
        <nav className="hv-breadcrumb" aria-label="Breadcrumb"><Link to="/home">Hypervisor</Link>{crumbs.map((crumb, index) => <span key={index}>/ {crumb.replace(/-/g, " ")}</span>)}</nav>
        <span className="hv-spacer" />
        <button className="hv-command" onClick={() => setAppsOpen(true)}>Search or open <kbd>⌘K</kbd></button>
      </header>
      <main className="hv-main" data-testid="open-application">{children}</main>
    </section>
    {appsOpen ? <ApplicationsModal projection={projection} onClose={() => setAppsOpen(false)} /> : null}
  </div>;
}
