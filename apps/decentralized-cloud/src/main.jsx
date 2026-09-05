import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App.jsx";
// The stylesheet is imported from where it already lives, not copied into src/. I
// copied it first and deleted the copy: two stylesheets that must agree are two
// sources and a wish, which is the fault the wordmark's one-source gate exists to
// catch. When the vanilla surface is retired this file moves; until then there is
// exactly one of it.
import "../public/face.css";

// StrictMode is ON, and it is load-bearing rather than boilerplate on this surface.
// In development it double-invokes effects, which is exactly the condition the
// paint-door guard exists for: two reads in flight for the same surface, one of them
// superseded. If the guard were wrong, StrictMode would show it here rather than in
// front of a reader.
createRoot(document.getElementById("root")).render(
  <StrictMode>
    <App />
  </StrictMode>
);
