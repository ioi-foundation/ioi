import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter, Routes, Route } from "react-router-dom";

import "./styles/global.css";

import { SpotlightWindow } from "./windows/SpotlightWindow";
import { PillWindow } from "./windows/PillWindow";
import { GateWindow } from "./windows/GateWindow";
import { StudioWindow } from "./windows/StudioWindow";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <BrowserRouter>
      <Routes>
        <Route path="/spotlight" element={<SpotlightWindow />} />
        <Route path="/pill" element={<PillWindow />} />
        <Route path="/gate" element={<GateWindow />} />
        <Route path="/studio" element={<StudioWindow />} />
        {/* Default to spotlight for dev */}
        <Route path="/" element={<SpotlightWindow />} />
      </Routes>
    </BrowserRouter>
  </React.StrictMode>
);