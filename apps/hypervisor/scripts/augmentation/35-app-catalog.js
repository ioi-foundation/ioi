  // ---- Product-surface catalog. ----
  // Peer membership is typed registration truth served at /__ioi/api/applications. Certified
  // runtime surfaces arrive separately as owner-bound tools or workspace views; UX evidence
  // never creates an application. The bundle carries a safe static first-party baseline so a
  // projection outage cannot erase the estate; a valid request projection replaces that baseline.
  let appCatalogData = window.__ioiStaticProductSurfaceCatalog || { applications: [], core_workspaces: [], tools: [], workspace_views: [] };
  let appCatalogResolved = false, appCatalogInflight = false, appCatalogLastTry = 0;
  function catalogApplications() {
    return appCatalogData && Array.isArray(appCatalogData.applications) ? appCatalogData.applications : [];
  }
  function catalogCoreWorkspaces() {
    return appCatalogData && Array.isArray(appCatalogData.core_workspaces) ? appCatalogData.core_workspaces : [];
  }
  function catalogOwnerApplications() {
    return catalogApplications().filter((entry) => entry.registration_kind === "owner_application" && entry.owner_cohort === "enduring");
  }
  function catalogSubstrateApplications() {
    return catalogApplications().filter((entry) => entry.registration_kind === "substrate_application");
  }
  function catalogSpecialistApplications() {
    return catalogApplications().filter((entry) => entry.registration_kind === "owner_application" && entry.owner_cohort === "conditional");
  }
  function catalogTools() {
    return appCatalogData && Array.isArray(appCatalogData.tools) ? appCatalogData.tools : [];
  }
  function catalogWorkspaceViews() {
    return appCatalogData && Array.isArray(appCatalogData.workspace_views) ? appCatalogData.workspace_views : [];
  }
  function catalogContextSurfaces() {
    return catalogTools().concat(catalogWorkspaceViews());
  }
  function catalogContextSurfaceByTitle(title) {
    return catalogContextSurfaces().find((entry) => entry.title === title) || null;
  }
  function catalogEntryByRef(ref) {
    return catalogApplications().concat(catalogCoreWorkspaces()).find((entry) => entry.ref === ref) || null;
  }
  function catalogStamp() {
    return [appCatalogData && appCatalogData.taxonomy_version || "", catalogApplications().length, catalogContextSurfaces().length].join(":");
  }
  function catalogIcon(a, size) {
    return a.icon
      ? '<img src="' + a.icon + '" alt="" style="width:' + size + "px;height:" + size + 'px;border-radius:4px;display:block">'
      : '<span aria-hidden="true">◳</span>';
  }
  function validCatalogEntry(entry, kinds) {
    const canonicalRoute = entry && (entry.canonical_route || entry.canonical_target_route);
    const label = entry && (entry.name || entry.title);
    return entry && typeof entry.ref === "string" && entry.ref.length > 0 &&
      typeof entry.surface_key === "string" && /^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(entry.surface_key) &&
      typeof label === "string" && label.length > 0 &&
      typeof canonicalRoute === "string" && canonicalRoute.indexOf("/") === 0 &&
      typeof entry.launchable === "boolean" &&
      (entry.launchable === false || (typeof entry.launch_route === "string" && entry.launch_route.indexOf("/") === 0)) &&
      kinds.indexOf(entry.registration_kind) !== -1;
  }
  function isValidProductSurfaceCatalog(candidate) {
    const baseline = window.__ioiStaticProductSurfaceCatalog;
    if (!candidate || candidate.schema !== "ioi.hypervisor.application-catalog.v2" ||
        !baseline || candidate.taxonomy_version !== baseline.taxonomy_version ||
        candidate.projection_state !== "transitional_static" ||
        candidate.membership_source !== "typed_product_registration" ||
        candidate.evidence_membership_independent !== true ||
        candidate.policy_filtering_state !== "not_connected" ||
        candidate.extension_inventory_state !== "not_connected" ||
        !Array.isArray(candidate.applications) || !Array.isArray(candidate.core_workspaces) ||
        !Array.isArray(candidate.tools) || !Array.isArray(candidate.workspace_views) ||
        !Array.isArray(candidate.extension_applications)) return false;
    if (!candidate.core_workspaces.every((entry) => validCatalogEntry(entry, ["core_workspace"])) ||
        !candidate.applications.every((entry) => validCatalogEntry(entry, ["owner_application", "substrate_application"])) ||
        !candidate.tools.every((entry) => validCatalogEntry(entry, ["tool_surface"])) ||
        !candidate.workspace_views.every((entry) => validCatalogEntry(entry, ["workspace_view"])) ||
        !candidate.extension_applications.every((entry) => validCatalogEntry(entry, ["extension_application"]))) return false;
    const entries = candidate.core_workspaces.concat(candidate.applications, candidate.tools, candidate.workspace_views, candidate.extension_applications);
    const refs = entries.map((entry) => entry.ref);
    const keys = entries.map((entry) => entry.surface_key);
    if (new Set(refs).size !== refs.length || new Set(keys).size !== keys.length) return false;
    const owners = new Set(candidate.core_workspaces.concat(candidate.applications).map((entry) => entry.ref));
    if (!candidate.tools.concat(candidate.workspace_views).every((entry) => entry.peer_application === false && owners.has(entry.placement_owner_ref))) return false;
    // Only the currently implemented transitional projection is accepted. A future request-scoped
    // projection must land its own client contract and tests before it may replace this baseline.
    if (candidate.extension_applications.length !== 0 ||
        candidate.core_workspaces.length !== baseline.core_workspaces.length ||
        candidate.applications.length !== baseline.applications.length ||
        candidate.tools.length !== baseline.tools.length ||
        candidate.workspace_views.length !== baseline.workspace_views.length) return false;
    const identityFields = ["surface_key", "registration_kind", "name", "title", "owner_cohort", "canonical_route", "canonical_target_route", "launch_route", "route_posture", "placement_owner_ref", "placement", "launchable"];
    const baselineEntries = baseline.core_workspaces.concat(baseline.applications, baseline.tools, baseline.workspace_views);
    const byRef = new Map(entries.map((entry) => [entry.ref, entry]));
    if (!baselineEntries.every((expected) => {
      const actual = byRef.get(expected.ref);
      return actual && identityFields.every((field) => (actual[field] == null ? null : actual[field]) === (expected[field] == null ? null : expected[field]));
    })) return false;
    const ownerLaunchRoutes = candidate.core_workspaces.concat(candidate.applications).filter((entry) => entry.launchable).map((entry) => entry.launch_route);
    const contextualLaunchRoutes = candidate.tools.concat(candidate.workspace_views).map((entry) => entry.launch_route);
    if (new Set(ownerLaunchRoutes).size !== ownerLaunchRoutes.length ||
        new Set(contextualLaunchRoutes).size !== contextualLaunchRoutes.length) return false;
    return true;
  }
  function fetchAppCatalog() {
    if (appCatalogResolved || appCatalogInflight || Date.now() - appCatalogLastTry < 30000) return;
    appCatalogLastTry = Date.now();
    appCatalogInflight = true;
    fetch("/__ioi/api/applications")
      .then((r) => r.json())
      .then((c) => {
        if (!isValidProductSurfaceCatalog(c)) return;
        appCatalogData = c;
        appCatalogResolved = true;
        const modal = document.getElementById("ioi-apps-modal");
        if (modal) { modal.removeAttribute("data-catalog"); if (modal.classList.contains("open")) appsModal(); }
        renderExplorer();
      })
      .catch(() => {})
      .finally(() => { appCatalogInflight = false; });
  }
