import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter, Routes, Route } from "react-router-dom";

import "@ioi/agent-ide/dist/style.css"; // Use shared theme
import "@ioi/workspace-substrate/style.css";
import "./styles/global.css"; // Autopilot theme overrides
import "./services/sessionRuntime";

import { GateWindow } from "./windows/GateWindow/index";
import { PillWindow } from "./windows/PillWindow";
import { ChatWindow } from "./windows/ChatWindow";
import { SpotlightWindow } from "./windows/SpotlightWindow";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <BrowserRouter>
      <Routes>
        <Route path="/pill" element={<PillWindow />} />
        <Route path="/spotlight" element={<SpotlightWindow />} />
        <Route path="/gate" element={<GateWindow />} />
        <Route path="/chat" element={<ChatWindow />} />
        <Route path="/" element={<ChatWindow />} />
      </Routes>
    </BrowserRouter>
  </React.StrictMode>
);
