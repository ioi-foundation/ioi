import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { useEffect } from "react";

import "@ioi/hypervisor-workbench/dist/style.css"; // Use shared theme
import "@ioi/workspace-substrate/style.css";
import "./styles/global.css"; // Hypervisor client theme overrides
import "./services/sessionRuntime";
import {
  applyHypervisorAppearance,
  loadHypervisorAppearance,
} from "./services/hypervisorAppearance";
import { markHypervisorMetric } from "./services/workspacePerf";

import { HypervisorShellWindow } from "./windows/HypervisorShellWindow";
import { WorkspaceSessionPreview } from "./dev/WorkspaceSessionPreview";

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

const HYPERVISOR_PRIMARY_ROUTES = [
  "/",
  "/home",
  "/ai",
  "/workspaces",
  "/sessions",
  "/details/:sessionId",
  "/details/:sessionId/logs",
  "/projects",
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

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <BrowserRouter>
      <AppMetricsBeacon />
      <Routes>
        <Route path="/workspace-preview" element={<WorkspaceSessionPreview />} />
        {HYPERVISOR_PRIMARY_ROUTES.map((path) => (
          <Route key={path} path={path} element={<HypervisorShellWindow />} />
        ))}
        <Route path="*" element={<HypervisorShellWindow />} />
      </Routes>
    </BrowserRouter>
  </React.StrictMode>
);
