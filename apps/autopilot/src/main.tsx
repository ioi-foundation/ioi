import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter, Routes, Route } from "react-router-dom";

import "@ioi/agent-ide/dist/style.css"; // Use shared theme
import "@ioi/workspace-substrate/style.css";
import "./styles/global.css"; // Autopilot theme overrides
import "./services/sessionRuntime";

import { GateWindow } from "./windows/GateWindow/index";
import { PillWindow } from "./windows/PillWindow";
import { SpotlightWindow } from "./windows/SpotlightWindow";
import { StudioWindow } from "./windows/StudioWindow";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <BrowserRouter>
      <Routes>
        <Route path="/pill" element={<PillWindow />} />
        <Route path="/spotlight" element={<SpotlightWindow />} />
        <Route path="/gate" element={<GateWindow />} />
        <Route path="/studio" element={<StudioWindow />} />
        <Route path="/" element={<StudioWindow />} />
      </Routes>
    </BrowserRouter>
  </React.StrictMode>
);
