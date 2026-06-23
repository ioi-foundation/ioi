import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { useEffect } from "react";

import "@ioi/hypervisor-workbench/dist/style.css"; // Use shared theme
import "@ioi/workspace-substrate/style.css";
// Parity foundation: vendored IOI demo-reference design tokens (Phase A). Imported
// before global.css so the 8 overlapping token names keep current values until
// surfaces are ported; the other reference tokens become available for parity work.
import "./styles/reference/tokens.css";
import "./styles/global.css"; // Hypervisor client theme overrides (retired per surface as parity ports land)
// Reference utility/component classes (class-scoped, preflight-stripped) — additive
// and non-breaking: no current surface uses these class names (verified zero
// collision). Ported surfaces emit these reference classes for bit-for-bit parity.
import "./styles/reference/utilities.css";
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
          <Route path="/parity-home" element={<HypervisorReferenceShell><HypervisorReferenceHome /></HypervisorReferenceShell>} />
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
