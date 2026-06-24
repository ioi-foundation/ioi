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
