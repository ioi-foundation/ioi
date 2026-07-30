import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { useEffect } from "react";

// The canonical Hypervisor product UI is the tracked product-ui bundle + IOI /api adapter,
// served by `npm run serve:product-ui --workspace=@ioi/hypervisor-app`
// (apps/hypervisor/scripts/serve-product-ui.mjs + ioi-api-adapter.mjs → http://localhost:4173).
// This Vite entry only hosts the workbench dev preview + runtime services; it is NOT a second
// product UI — evolve the served app in place, never build a parallel runtime.
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

function ServedElsewhereNotice() {
  return (
    <div style={{ font: "14px/1.6 system-ui, sans-serif", padding: "2rem" }}>
      <h1 style={{ fontSize: "1.25rem", margin: "0 0 .5rem" }}>Hypervisor</h1>
      <p style={{ margin: 0 }}>
        The product UI is served by the IOI /api adapter. Run{" "}
        <code>npm run serve:product-ui --workspace=@ioi/hypervisor-app</code> and open{" "}
        <code>http://localhost:4173</code>.
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
          <Route path="/workspace-preview" element={<WorkspaceSessionPreview />} />
          <Route path="*" element={<ServedElsewhereNotice />} />
        </Routes>
      </BrowserRouter>
    </React.StrictMode>,
  );
}

void bootstrapHypervisorDevReplayClient().finally(renderHypervisorApp);
