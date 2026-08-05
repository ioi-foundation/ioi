  // ---- Compiled product-surface projection (W0.2). ----
  // ONE projection feeds every launcher lane: workspaces + applications (registration records
  // compiled by the daemon via POST /v1/hypervisor/product-surface-projections, decorated by
  // scripts/surface-compiler.mjs) plus the demoted evidence band of ported tool surfaces
  // (`apps`). This module never hardcodes an app list; served at /__ioi/api/applications.
  // Fetched once per shell load; on arrival the launcher modal and the Home explorer repaint.
  // Until it arrives — or when the daemon is down — consumers render a named honest state,
  // never a frozen fake catalog.
  let appCatalogData = null, appCatalogInflight = false, appCatalogLastTry = 0;
  function catalogApps() {
    // Evidence band (ported tool surfaces) — implementation evidence, zero catalog authority.
    return appCatalogData && Array.isArray(appCatalogData.apps) ? appCatalogData.apps : [];
  }
  function compiledApps() {
    return appCatalogData && Array.isArray(appCatalogData.applications) ? appCatalogData.applications : [];
  }
  function compiledWorkspaces() {
    return appCatalogData && Array.isArray(appCatalogData.workspaces) ? appCatalogData.workspaces : [];
  }
  function compiledDaemonOk() {
    return !!(appCatalogData && appCatalogData.daemon && appCatalogData.daemon.available === true);
  }
  function compiledDaemonCode() {
    return (appCatalogData && appCatalogData.daemon && appCatalogData.daemon.code) || "daemon_unavailable";
  }
  function compiledAppByName(name) {
    return compiledApps().find(function (a) { return a.name === name; }) || null;
  }
  function catalogAppByTitle(title) {
    return catalogApps().find((a) => a.title === title) || null;
  }
  function catalogIcon(a, size) {
    return a.icon
      ? '<img src="' + a.icon + '" alt="" style="width:' + size + "px;height:" + size + 'px;border-radius:4px;display:block">'
      : '<span aria-hidden="true">◳</span>';
  }
  function fetchAppCatalog() {
    if (appCatalogData || appCatalogInflight || Date.now() - appCatalogLastTry < 30000) return;
    appCatalogLastTry = Date.now();
    appCatalogInflight = true;
    fetch("/__ioi/api/applications")
      .then((r) => r.json())
      .then((c) => {
        appCatalogData = c && (Array.isArray(c.applications) || Array.isArray(c.apps)) ? c : { apps: [], applications: [], workspaces: [] };
        const modal = document.getElementById("ioi-apps-modal");
        if (modal) { modal.removeAttribute("data-catalog"); if (modal.classList.contains("open")) appsModal(); }
        renderExplorer();
      })
      .catch(() => {})
      .finally(() => { appCatalogInflight = false; });
  }
