import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { useEffect } from "react";

// The reference-parity UX is no longer rendered by this React app — it is served as the
// LIVE reference (real bundle + IOI /api adapter) via
// `npm run serve:reference --workspace=@ioi/hypervisor-app`
// (apps/hypervisor/scripts/serve-live-reference.mjs). This Vite app now only hosts the
// workbench dev preview + runtime services.
import "@ioi/hypervisor-workbench/dist/style.css";
import "@ioi/workspace-substrate/style.css";
import "./styles/global.css";
import "./services/sessionRuntime";
import {
  applyHypervisorAppearance,
  loadHypervisorAppearance,
} from "./services/hypervisorAppearance";
import { markHypervisorMetric } from "./services/workspacePerf";

import { WorkspaceSessionPreview } from "./dev/WorkspaceSessionPreview";
import { bootstrapHypervisorDevReplayClient } from "./dev/hypervisorDevReplayClient";
// T7 (hybrid UX) — native operator surfaces projecting daemon truth over the Session Execution
// Binding. The served reference is now dev_reference_only; these React routes are the product
// projection. See internal-docs/implementation/hypervisor-ux-strategy-decision.md.
import {
  HomeSurface,
  SessionsSurface,
  SessionDetailSurface,
  ProvidersSurface,
  EnvironmentsSurface,
} from "./surfaces/NativeCockpit";
import { NativeWorkbench } from "./surfaces/NativeWorkbench";

applyHypervisorAppearance(loadHypervisorAppearance());

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

// The hypervisor product UI is the live reference (served by serve-live-reference.mjs);
// this placeholder only shows if someone opens the bare Vite app directly.
function ServedElsewhereNotice() {
  return (
    <div style={{ font: "14px/1.6 system-ui, sans-serif", padding: "2rem", color: "#1c1c1c" }}>
      <h1 style={{ fontSize: "1.25rem", margin: "0 0 .5rem" }}>Hypervisor</h1>
      <p style={{ margin: 0 }}>
        The product UI is served as the live reference. Run{" "}
        <code>npm run serve:reference --workspace=@ioi/hypervisor-app</code>.
      </p>
    </div>
  );
}

function renderHypervisorApp() {
  ReactDOM.createRoot(document.getElementById("root")!).render(
    <React.StrictMode>
      <BrowserRouter>
        <AppMetricsBeacon />
        <Routes>
          <Route path="/" element={<HomeSurface />} />
          <Route path="/sessions" element={<SessionsSurface />} />
          <Route path="/sessions/:id" element={<SessionDetailSurface />} />
          <Route path="/providers" element={<ProvidersSurface />} />
          <Route path="/environments" element={<EnvironmentsSurface />} />
          <Route path="/workbench/:id" element={<NativeWorkbench />} />
          <Route path="/workspace-preview" element={<WorkspaceSessionPreview />} />
          <Route path="*" element={<ServedElsewhereNotice />} />
        </Routes>
      </BrowserRouter>
    </React.StrictMode>,
  );
}

void bootstrapHypervisorDevReplayClient().finally(renderHypervisorApp);
