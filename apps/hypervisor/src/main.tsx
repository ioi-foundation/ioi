import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter, Routes, Route, Link } from "react-router-dom";
import { useEffect } from "react";

// Native Hypervisor product UI (v2 estate). The served reference (serve-live-reference.mjs) is now
// the dev_reference_only design oracle; this app is the source-neutral product over daemon truth.
import "@ioi/hypervisor-workbench/dist/style.css";
import "@ioi/workspace-substrate/style.css";
import "./styles/global.css";
import "./ui"; // UX kit stylesheet (design system)
import "./services/sessionRuntime";
import {
  applyHypervisorAppearance,
  loadHypervisorAppearance,
} from "./services/hypervisorAppearance";
import { markHypervisorMetric } from "./services/workspacePerf";

import { WorkspaceSessionPreview } from "./dev/WorkspaceSessionPreview";
import { bootstrapHypervisorDevReplayClient } from "./dev/hypervisorDevReplayClient";
import { AppShell } from "./shell/AppShell";
import { HomeCockpit } from "./shell/HomeCockpit";
import { AppStatusFrame } from "./shell/AppStatusFrame";
import {
  SessionsSurface,
  SessionDetailSurface,
  EnvironmentsSurface,
} from "./surfaces/NativeCockpit";
import { NativeWorkbench } from "./surfaces/NativeWorkbench";
import { Heading, Muted } from "./ui";

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

function NotFound() {
  return (
    <div className="hv-page" data-testid="not-found">
      <Heading level={1}>Not found</Heading>
      <Muted>That route isn't part of the current estate.</Muted>
      <Link to="/" className="hv-link">← Home</Link>
    </div>
  );
}

function renderHypervisorApp() {
  ReactDOM.createRoot(document.getElementById("root")!).render(
    <React.StrictMode>
      <BrowserRouter>
        <AppMetricsBeacon />
        <AppShell>
          <Routes>
            <Route path="/" element={<HomeCockpit />} />
            <Route path="/new" element={<HomeCockpit />} />
            <Route path="/projects" element={<AppStatusFrame surfaceId="projects" />} />
            <Route path="/automations" element={<AppStatusFrame surfaceId="automations" />} />
            <Route path="/settings" element={<AppStatusFrame surfaceId="settings" />} />
            <Route path="/environments" element={<EnvironmentsSurface />} />
            <Route path="/workbench/:id" element={<NativeWorkbench />} />
            <Route path="/sessions" element={<SessionsSurface />} />
            <Route path="/sessions/:id" element={<SessionDetailSurface />} />
            <Route path="/app/:id" element={<AppStatusFrame />} />
            <Route path="/workspace-preview" element={<WorkspaceSessionPreview />} />
            <Route path="*" element={<NotFound />} />
          </Routes>
        </AppShell>
      </BrowserRouter>
    </React.StrictMode>,
  );
}

void bootstrapHypervisorDevReplayClient().finally(renderHypervisorApp);
