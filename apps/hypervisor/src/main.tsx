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
// Source-owned surfaces + shell (cut 4: migrating the product UI from the seed bundle into source).
import { AppShell } from "./shell/AppShell";
import { HomeView } from "./surfaces/Home/HomeView";
import { ConnectionsView } from "./surfaces/Connections/ConnectionsView";
import { ProjectsView } from "./surfaces/Projects/ProjectsView";
import { ProjectDetailView } from "./surfaces/Projects/ProjectDetailView";
import { AutomationsView } from "./surfaces/Automations/AutomationsView";
import { AutomationNewView } from "./surfaces/Automations/AutomationNewView";
import { ApplicationsView } from "./surfaces/Applications/ApplicationsView";
import { SettingsView } from "./surfaces/Settings/SettingsView";
import { SessionView } from "./surfaces/Session/SessionView";
import { ConnectionAddView } from "./surfaces/Connections/ConnectionAddView";

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

// Fallback for routes/sub-flows not yet built as source surfaces (e.g. some create/detail
// flows). The app is fully source-owned; there is no bundle fallback.
function SurfacePending({ name }: { name: string }) {
  return (
    <div style={{ padding: "64px 32px", color: "#9a9da6", maxWidth: 640, margin: "0 auto" }}>
      <h1 style={{ fontSize: "1.4rem", margin: "0 0 .5rem", color: "#e6e7ea" }}>{name}</h1>
      <p style={{ margin: 0, lineHeight: 1.6 }}>This view isn’t built yet.</p>
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
          {/* Source-owned shell + surfaces (cut 4). As surfaces land, the vite app becomes the
              canonical shell and the seed bundle is retired (cuts 5-6). */}
          <Route element={<AppShell />}>
            <Route index element={<HomeView />} />
            <Route path="connections" element={<ConnectionsView />} />
            <Route path="__ioi/connections" element={<ConnectionsView />} />
            <Route path="connections/add" element={<ConnectionAddView />} />
            <Route path="__ioi/connections/add" element={<ConnectionAddView />} />
            <Route path="projects" element={<ProjectsView />} />
            <Route path="projects/:id" element={<ProjectDetailView />} />
            <Route path="automations" element={<AutomationsView />} />
            <Route path="automations/new" element={<AutomationNewView />} />
            <Route path="applications" element={<ApplicationsView />} />
            <Route path="settings/*" element={<SettingsView />} />
            <Route path="sessions/:id" element={<SessionView />} />
            <Route path="*" element={<SurfacePending name="This surface" />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </React.StrictMode>,
  );
}

void bootstrapHypervisorDevReplayClient().finally(renderHypervisorApp);
