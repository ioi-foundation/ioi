import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { useEffect } from "react";

import "@ioi/agent-ide/dist/style.css"; // Use shared theme
import "@ioi/workspace-substrate/style.css";
import "./styles/global.css"; // Autopilot theme overrides
import "./services/sessionRuntime";
import { markAutopilotMetric } from "./services/workspacePerf";

import { GateWindow } from "./windows/GateWindow/index";
import { AutopilotShellWindow } from "./windows/AutopilotShellWindow";
import { WorkspaceWorkbenchPreview } from "./dev/WorkspaceWorkbenchPreview";
import { hideChatSessionShell, hidePillShell, showChatShell } from "@ioi/agent-ide";

function AppMetricsBeacon() {
  useEffect(() => {
    markAutopilotMetric("react_router_mounted");
    const frame = window.requestAnimationFrame(() => {
      markAutopilotMetric("app_first_paint");
    });
    return () => window.cancelAnimationFrame(frame);
  }, []);

  return null;
}

function LegacyChatSessionRedirect() {
  useEffect(() => {
    void showChatShell()
      .catch(() => undefined)
      .finally(() => {
        void hideChatSessionShell().catch(() => undefined);
      });
  }, []);

  return null;
}

function DisabledPillRoute() {
  useEffect(() => {
    void hidePillShell().catch(() => undefined);
  }, []);

  return null;
}

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <BrowserRouter>
      <AppMetricsBeacon />
      <Routes>
        <Route path="/pill" element={<DisabledPillRoute />} />
        <Route path="/workspace-preview" element={<WorkspaceWorkbenchPreview />} />
        <Route path="/chat-session" element={<LegacyChatSessionRedirect />} />
        <Route path="/gate" element={<GateWindow />} />
        <Route path="/chat" element={<AutopilotShellWindow />} />
        <Route path="/" element={<AutopilotShellWindow />} />
        <Route path="*" element={<AutopilotShellWindow />} />
      </Routes>
    </BrowserRouter>
  </React.StrictMode>
);
