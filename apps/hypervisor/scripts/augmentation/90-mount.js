  function applyAugmentation() {
    const p = location.pathname;
    if (/\/details\//.test(p)) mountTimelineInWorkbench(); // workbench timeline only on /details/*
    mountProjectAutomations(); // self-guards /projects/:id + self-removes its panel off-route
    if (/\/settings\//.test(p)) { mountGitAppButton(); wireIntegrationConnect(); } // settings only
    fetchAppCatalog(); // ported-app registry for the launcher lanes (self-guarded, one fetch)
    mountOntologyNav(); // the permanent Ontology rail item (self-guarded; React re-renders the rail)
    applyAiViews(); // /ai view router: explorer Home (no hash) vs New Session composer (#new-session)
    updateOpenAppRail(); // reflect the Open Application slot state in the rail
  }
  function mount() {
    style();
    matchMedia("(prefers-color-scheme: dark)").addEventListener?.("change", style);
    // One-time, self-guarded installers: demote the old rail item + the click interceptors.
    removeConnectionsNav();
    wireApplicationsLauncher();
    wireAutomationsNav();
    // Event-driven apply: a debounced MutationObserver + SPA route hooks replace the old polling loops.
    let pending = null;
    const schedule = () => { if (pending) return; pending = setTimeout(() => { pending = null; applyAugmentation(); }, 250); };
    new MutationObserver(schedule).observe(document.body, { childList: true, subtree: true });
    ["pushState", "replaceState"].forEach((m) => {
      const orig = history[m];
      if (typeof orig === "function") history[m] = function () { const r = orig.apply(this, arguments); schedule(); return r; };
    });
    window.addEventListener("popstate", schedule);
    window.addEventListener("hashchange", schedule); // /ai explorer ↔ #new-session composer
    // Ctrl+O = New Session (the composer page) — beat the SPA's native shortcut handler.
    document.addEventListener("keydown", (e) => {
      if ((e.ctrlKey || e.metaKey) && !e.shiftKey && !e.altKey && String(e.key).toLowerCase() === "o") {
        e.preventDefault(); e.stopPropagation(); goComposer();
      }
    }, true);
    applyAugmentation(); // initial
  }

  if (document.body) mount();
  else document.addEventListener("DOMContentLoaded", mount);
})();
