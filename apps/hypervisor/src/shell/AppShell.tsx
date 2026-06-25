// Layer 3 — the AppShell: rail + the singular Open Application frame, with the Applications catalog
// modal hosted at the shell level. Every route renders inside <main> (the Open Application frame).
import { useState, type ReactNode } from "react";
import "../ui"; // ensure the kit stylesheet loads at the shell root
import { Rail } from "./Rail";
import { ApplicationsModal } from "./ApplicationsModal";

export function AppShell({ children }: { children: ReactNode }) {
  const [appsOpen, setAppsOpen] = useState(false);
  return (
    <div className="hv-shell" data-testid="app-shell">
      <Rail onOpenApplications={() => setAppsOpen(true)} />
      <main className="hv-main" data-testid="open-application">{children}</main>
      {appsOpen && <ApplicationsModal onClose={() => setAppsOpen(false)} />}
    </div>
  );
}
