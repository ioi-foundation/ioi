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

import { HypervisorShellWindow } from "./windows/HypervisorShellWindow";
import { WorkspaceSessionPreview } from "./dev/WorkspaceSessionPreview";
import { HypervisorReferenceHome } from "./surfaces/Home/HypervisorReferenceHome";
import { HypervisorReferenceShell } from "./surfaces/Home/HypervisorReferenceShell";
import { HypervisorReferenceProjects } from "./surfaces/Projects/HypervisorReferenceProjects";
import { HypervisorReferenceAutomations } from "./surfaces/Automations/HypervisorReferenceAutomations";
import type { PrimaryView } from "./windows/HypervisorShellWindow/hypervisorShellModel";
import { bootstrapHypervisorDevReplayClient } from "./dev/hypervisorDevReplayClient";

applyHypervisorAppearance(loadHypervisorAppearance());

// Additive parity surfaces (Phase B/C) live on /parity-* routes. The reference
// sidebar navigates between them; views without a ported route yet are inert.
const PARITY_ROUTES: Partial<Record<PrimaryView, string>> = {
  home: "/parity-home",
  projects: "/parity-projects",
  automations: "/parity-automations",
};
function ParityShellRoute({ view, children }: { view: PrimaryView; children: ReactNode }) {
  const navigate = useNavigate();
  return (
    <HypervisorReferenceShell
      activeView={view}
      onViewChange={(v) => {
        const route = PARITY_ROUTES[v];
        if (route) navigate(route);
      }}
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

const HYPERVISOR_PRIMARY_ROUTES = [
  "/",
  "/home",
  "/ai",
  "/workspaces",
  "/sessions",
  "/details/:sessionId",
  "/details/:sessionId/logs",
  "/projects",
  "/applications",
  "/missions",
  "/workbench",
  "/automations",
  "/insights",
  "/agents",
  "/models",
  "/privacy",
  "/providers",
  "/environments",
  "/foundry",
  "/authority",
  "/receipts",
  "/settings",
];

function renderHypervisorApp() {
  ReactDOM.createRoot(document.getElementById("root")!).render(
    <React.StrictMode>
      <BrowserRouter>
        <AppMetricsBeacon />
        <Routes>
          <Route path="/workspace-preview" element={<WorkspaceSessionPreview />} />
          <Route path="/parity-home" element={<ParityShellRoute view="home"><HypervisorReferenceHome /></ParityShellRoute>} />
          <Route path="/parity-projects" element={<ParityShellRoute view="projects"><HypervisorReferenceProjects /></ParityShellRoute>} />
          <Route path="/parity-automations" element={<ParityShellRoute view="automations"><HypervisorReferenceAutomations /></ParityShellRoute>} />
          {HYPERVISOR_PRIMARY_ROUTES.map((path) => (
            <Route key={path} path={path} element={<HypervisorShellWindow />} />
          ))}
          <Route path="*" element={<HypervisorShellWindow />} />
        </Routes>
      </BrowserRouter>
    </React.StrictMode>,
  );
}

void bootstrapHypervisorDevReplayClient().finally(renderHypervisorApp);
