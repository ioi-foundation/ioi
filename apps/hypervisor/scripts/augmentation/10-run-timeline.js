  // ---- Owned Run Timeline as the default workbench transcript (replaces the seeded pane) ----
  const CONV_SEL = '[data-testid="environment-agent-execution-conversation"]';
  const runGate = {}; // envId -> { has, at } — throttled "does this env have a run yet" check
  function envHasRun(envId) {
    const g = runGate[envId];
    const now = Date.now();
    if (!g || now - g.at >= 5000) {
      runGate[envId] = { has: g ? g.has : false, at: now };
      fetch("/__ioi/env-latest-run/" + encodeURIComponent(envId))
        .then((r) => r.json())
        .then((d) => { runGate[envId] = { has: !!(d && d.runId), at: Date.now() }; })
        .catch(() => {});
    }
    return runGate[envId].has;
  }
  function mountTimelineInWorkbench() {
    const m = location.pathname.match(/\/details\/([^/?#]+)/);
    const C = document.querySelector(CONV_SEL);
    if (!m || !C) return;
    // Only take over the pane once the env actually has a run — otherwise leave the native composer
    // so the user can start one (the owned follow-up composer needs an existing run to post to).
    if (!envHasRun(m[1])) return;
    const want = "/__ioi/run-timeline/env/" + encodeURIComponent(m[1]) + "?embed=1";
    let frame = C.querySelector("#ioi-timeline-frame");
    if (!frame) {
      frame = document.createElement("iframe");
      frame.id = "ioi-timeline-frame";
      frame.title = "Run Timeline";
      frame.setAttribute("src", want);
      frame.style.cssText = "flex:1 1 auto;width:100%;min-height:0;border:0;background:transparent;";
      if (!getComputedStyle(C).display.includes("flex")) C.style.display = "flex";
      C.style.flexDirection = "column";
      C.appendChild(frame);
    } else if (frame.getAttribute("src") !== want) {
      frame.setAttribute("src", want); // env changed (SPA nav) → repoint
    }
    // Full replacement: hide ALL seeded pane children (transcript + the SPA's empty-state hero +
    // its composer), leaving only our owned timeline. The owned surface carries its own follow-up
    // composer, so it owns the whole conversation (transcript + send). Re-applied each tick because
    // React re-creates these children on its own renders.
    Array.prototype.forEach.call(C.children, function (ch) {
      ch.style.display = ch === frame ? "" : "none";
    });
  }

