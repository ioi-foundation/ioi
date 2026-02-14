import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter, Routes, Route } from "react-router-dom";

import "@ioi/agent-ide/dist/style.css"; // Use shared theme

// [REMOVED] import { PillWindow } from "./windows/PillWindow";
// [REMOVED] import { GateWindow } from "./windows/GateWindow";
import { StudioWindow } from "./windows/StudioWindow";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <BrowserRouter>
      <Routes>
        <Route path="/spotlight" element={<StudioWindow />} />
        {/* [REMOVED] <Route path="/pill" element={<PillWindow />} /> */}
        {/* [REMOVED] <Route path="/gate" element={<GateWindow />} /> */}
        <Route path="/studio" element={<StudioWindow />} />
        <Route path="/" element={<StudioWindow />} />
      </Routes>
    </BrowserRouter>
  </React.StrictMode>
);
