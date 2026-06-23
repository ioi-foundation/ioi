import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter, Routes, Route, useNavigate } from "react-router-dom";
import { useEffect } from "react";
import type { ReactNode } from "react";

import "@ioi/hypervisor-workbench/dist/style.css"; // Use shared theme
import "@ioi/workspace-substrate/style.css";
// Parity foundation: vendored IOI demo-reference design tokens (Phase A). Imported
// before global.css so the 8 overlapping token names keep current values until
// surfaces are ported; the other reference tokens become available for parity work.
import "./styles/reference/tokens.css";
import "./styles/global.css"; // Hypervisor client theme overrides (retired per surface as parity ports land)
// Import order mirrors the reference's CSS layer order (base -> components ->
// utilities) so utilities win element-level conflicts exactly as on :9228. Notably
// .h-8 must beat .hypervisor-wordmark-brand-host{height:100%} (equal specificity,
// later wins) or the Home wordmark host collapses via its aspect-ratio.
// 1) base: scoped preflight reset (under `.ona`, set by the parity shell) re-adding
//    the reference's anchor/heading/form resets that the utility bundle strips.
import "./styles/reference/parity-preflight.css";
// 2) components: vendored hypervisor-* brand/Applications rules the reference server
//    injects at serve time (logo mark, Applications sidebar section, launcher modal).
import "./styles/reference/hypervisor-brand.css";
// 3) utilities: reference utility/component classes (class-scoped, preflight-stripped)
//    — additive and non-breaking (no current surface uses these names; zero collision).
import "./styles/reference/utilities.css";
// 3b) supplement: arbitrary utilities used by ported surfaces but absent from the
//     Home-harvested utilities subset (verbatim from the reference's full bundle).
import "./styles/reference/parity-supplement.css";
import "./services/sessionRuntime";
import {
  applyHypervisorAppearance,
  loadHypervisorAppearance,
} from "./services/hypervisorAppearance";
import { markHypervisorMetric } from "./services/workspacePerf";

import { WorkspaceSessionPreview } from "./dev/WorkspaceSessionPreview";
import { HypervisorReferenceNotFound } from "./surfaces/NotFound/HypervisorReferenceNotFound";
import { HypervisorReferenceHome } from "./surfaces/Home/HypervisorReferenceHome";
import { HypervisorReferenceShell } from "./surfaces/Home/HypervisorReferenceShell";
import { HypervisorReferenceProjects } from "./surfaces/Projects/HypervisorReferenceProjects";
import { HypervisorReferenceProjectDetail } from "./surfaces/Projects/HypervisorReferenceProjectDetail";
import { HypervisorReferenceAutomations } from "./surfaces/Automations/HypervisorReferenceAutomations";
import { HypervisorReferenceWorkspace } from "./surfaces/Workspace/HypervisorReferenceWorkspace";
import { HypervisorReferenceSettings } from "./surfaces/Settings/HypervisorReferenceSettings";
import type { PrimaryView } from "./surfaces/parityShellTypes";
import { bootstrapHypervisorDevReplayClient } from "./dev/hypervisorDevReplayClient";

applyHypervisorAppearance(loadHypervisorAppearance());

// The reference-parity surfaces are the app's primary UX and own the root routes
// (the reference IA). The sidebar navigates between them via real routes; Applications
// opens the launcher modal (handled inside the shell). The legacy HypervisorShellWindow
// has been removed: any route not owned here renders the reference-style 404
// (unported surfaces — sessions, workbench, agents, models, etc. — until ported).
const PRIMARY_ROUTE_FOR_VIEW: Partial<Record<PrimaryView, string>> = {
  home: "/",
  projects: "/projects",
  automations: "/automations",
  settings: "/settings",
};
function ParityShellRoute({ view, children }: { view: PrimaryView; children: ReactNode }) {
  const navigate = useNavigate();
  return (
    <HypervisorReferenceShell
      activeView={view}
      onViewChange={(v) => navigate(PRIMARY_ROUTE_FOR_VIEW[v] ?? `/${v}`)}
    >
      {children}
    </HypervisorReferenceShell>
  );
}

function AppMetricsBeacon() {
  useEffect(() => {
    markHypervisorMetric("react_router_mounted");
    const frame = window.requestAnimationFrame(() => {
      markHypervisorMetric("app_first_paint");
    });
    return () => window.cancelAnimationFrame(frame);
  }, []);

  return null;
}

function renderHypervisorApp() {
  ReactDOM.createRoot(document.getElementById("root")!).render(
    <React.StrictMode>
      <BrowserRouter>
        <AppMetricsBeacon />
        <Routes>
          <Route path="/workspace-preview" element={<WorkspaceSessionPreview />} />
          {/* Reference-parity UX at the app root (the reference IA). */}
          <Route path="/" element={<ParityShellRoute view="home"><HypervisorReferenceHome /></ParityShellRoute>} />
          <Route path="/home" element={<ParityShellRoute view="home"><HypervisorReferenceHome /></ParityShellRoute>} />
          <Route path="/ai" element={<ParityShellRoute view="home"><HypervisorReferenceHome /></ParityShellRoute>} />
          <Route path="/projects" element={<ParityShellRoute view="projects"><HypervisorReferenceProjects /></ParityShellRoute>} />
          <Route path="/projects/:projectId" element={<ParityShellRoute view="projects"><HypervisorReferenceProjectDetail /></ParityShellRoute>} />
          <Route path="/automations" element={<ParityShellRoute view="automations"><HypervisorReferenceAutomations /></ParityShellRoute>} />
          <Route path="/details/:sessionId" element={<ParityShellRoute view="workbench"><HypervisorReferenceWorkspace /></ParityShellRoute>} />
          <Route path="/settings" element={<HypervisorReferenceSettings />} />
          <Route path="/settings/*" element={<HypervisorReferenceSettings />} />
          {/* Reference-style 404 for any route the parity UX does not own (sessions,
              workbench, agents, models, etc.). The legacy shell has been removed. */}
          <Route path="*" element={<HypervisorReferenceNotFound />} />
        </Routes>
      </BrowserRouter>
    </React.StrictMode>,
  );
}

void bootstrapHypervisorDevReplayClient().finally(renderHypervisorApp);
