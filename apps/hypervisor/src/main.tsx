import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter, Navigate, Routes, Route } from "react-router-dom";
import { useEffect } from "react";

import "@ioi/hypervisor-workbench/dist/style.css";
import "@ioi/workspace-substrate/style.css";
import "./styles/global.css";
import "./services/sessionRuntime";
import {
  applyHypervisorAppearance,
  loadHypervisorAppearance,
} from "./services/hypervisorAppearance";
import { markHypervisorMetric } from "./services/workspacePerf";

import { AppShell } from "./shell/AppShell";
import { HomeSurface } from "./surfaces/HomeSurface";
import { ApplicationsSurface } from "./surfaces/ApplicationsSurface";
import { OperationalSurface } from "./surfaces/OperationalSurface";
import { WorkSurface } from "./surfaces/WorkSurface";
import { SessionsSurface } from "./surfaces/SessionsSurface";
import { SettingsSurface } from "./surfaces/SettingsSurface";
import { RouteRefusalSurface } from "./surfaces/RouteRefusalSurface";

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

function renderHypervisorApp() {
  ReactDOM.createRoot(document.getElementById("root")!).render(
    <React.StrictMode>
      <BrowserRouter>
        <AppMetricsBeacon />
        <Routes>
          <Route path="/sessions" element={<RouteRefusalSurface />} />
          <Route path="/missions" element={<RouteRefusalSurface />} />
          <Route path="/__ioi/*" element={<RouteRefusalSurface />} />
          <Route path="*" element={<AppShell><Routes>
            <Route path="/" element={<Navigate to="/home" replace />} />
            <Route path="/home" element={<HomeSurface />} />
            <Route path="/applications" element={<ApplicationsSurface />} />
            <Route path="/work" element={<WorkSurface />} />
            <Route path="/work/new-session" element={<SessionsSurface create />} />
            <Route path="/work/sessions" element={<SessionsSurface />} />
            <Route path="/work/sessions/:id" element={<SessionsSurface />} />
            <Route path="/settings" element={<SettingsSurface />} />
            <Route path="/systems/:systemId/interfaces/:bindingId" element={<OperationalSurface />} />
            <Route path="/:surface" element={<OperationalSurface />} />
            <Route path="*" element={<div className="hv-page"><h1>Not found</h1><p>No canonical product-surface registration owns this route.</p></div>} />
          </Routes></AppShell>} />
        </Routes>
      </BrowserRouter>
    </React.StrictMode>,
  );
}

renderHypervisorApp();
