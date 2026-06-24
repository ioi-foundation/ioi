import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { useEffect } from "react";

// The whole app now renders the reference verbatim, so we vendor the reference's
// COMPLETE CSS bundle (the single stylesheet :9228 links) rather than a Home-harvested
// subset — every route is styled exactly as the reference, with no curated seam to drift.
// hypervisor-brand.css (the server-injected brand rules, not part of the bundle) loads
// first so the bundle's utilities still win element conflicts (e.g. .h-8 beating
// .hypervisor-wordmark-brand-host). The .ona/light scope on <html> (useReferenceTheme)
// activates the bundle's :root[class~=ona] token layer exactly as on :9228.
import "./styles/reference/hypervisor-brand.css";
import "./styles/reference/reference-bundle.css";
import "./services/sessionRuntime";
import {
  applyHypervisorAppearance,
  loadHypervisorAppearance,
} from "./services/hypervisorAppearance";
import { markHypervisorMetric } from "./services/workspacePerf";

import { WorkspaceSessionPreview } from "./dev/WorkspaceSessionPreview";
import { VerbatimRoute } from "./reference/VerbatimRoute";
import { bootstrapHypervisorDevReplayClient } from "./dev/hypervisorDevReplayClient";

applyHypervisorAppearance(loadHypervisorAppearance());

// The reference-parity UX is rendered verbatim from captured reference DOM (the IOI
// demo snapshot, brand-transformed Ona -> IOI), styled by the vendored reference CSS,
// with client-side behavior attached by delegation. A single VerbatimRoute resolves the
// current path to its capture (see reference/captures.ts) and renders it; unknown paths
// fall back to the reference-style 404. The previous hand-ported JSX surfaces are
// retained as modules (their menu/dialog components become overlay islands) but no longer
// own routes.
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
          {/* Every reference route renders verbatim from its capture; VerbatimRoute
              resolves the path (including /projects/:id, /details/:id, /settings/*). */}
          <Route path="*" element={<VerbatimRoute />} />
        </Routes>
      </BrowserRouter>
    </React.StrictMode>,
  );
}

void bootstrapHypervisorDevReplayClient().finally(renderHypervisorApp);
