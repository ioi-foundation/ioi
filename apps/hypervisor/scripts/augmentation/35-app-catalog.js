  // ---- App catalog — ported application surfaces. ----
  // Membership is parity-matrix truth served at /__ioi/api/applications (the serve derives it
  // from harvest-app-parity-matrix.json via app-catalog.mjs); this module never hardcodes an app
  // list. Fetched once per shell load; on arrival the launcher modal and the Home explorer grid
  // repaint. Family surfaces stay the IOI_APPS constant — the catalog lists the concrete ported
  // apps inside those families.
  let appCatalogData = null, appCatalogInflight = false, appCatalogLastTry = 0;
  function catalogApps() {
    return appCatalogData && Array.isArray(appCatalogData.apps) ? appCatalogData.apps : [];
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
        appCatalogData = c && Array.isArray(c.apps) ? c : { apps: [] };
        const modal = document.getElementById("ioi-apps-modal");
        if (modal) { modal.removeAttribute("data-catalog"); if (modal.classList.contains("open")) appsModal(); }
        renderExplorer();
      })
      .catch(() => {})
      .finally(() => { appCatalogInflight = false; });
  }
