  // ---- W0.5 identity truth — named degraded states for settings panes whose backing RPCs now
  // refuse typed instead of serving local-constant placeholder data (adapter: GetOrganization,
  // GetTermsOfService, GetOrganizationPolicies, ListServiceAccounts, ListAvailableRunnerManagers,
  // CreateRunnerLogsToken). The vendor pane keeps its own error rendering; this banner names the
  // gap in product language so the degraded state is explicit, not a bare failure. Zero
  // placeholder data; self-removes off-route. --------------------------------------------------
  const SETTINGS_GAP_BANNERS = {
    "manage-organization": {
      code: "org_display_identity_absent",
      title: "Organization identity is a daemon projection",
      text: "This pane projects the daemon organization read; no display-name/tier record exists in the daemon yet, so those fields render empty (named absent, never fabricated) and the organization update action refuses typed.",
    },
    "terms-of-service": {
      code: "terms_of_service_unowned",
      title: "Not served",
      text: "No canonical owner defines a Terms-of-Service record; nothing is displayed here.",
    },
    policies: {
      code: "org_policy_family_route_missing",
      title: "Organization policy defaults unavailable",
      text: "The org-policy record family does not exist in the daemon yet (Wave 3 build); no fabricated quotas, archive windows, or sharing policies are shown.",
    },
    "agent-policies": {
      code: "org_policy_family_route_missing",
      title: "Agent policy defaults unavailable",
      text: "Agent-policy defaults belong to the missing org-policy record family (Wave 3 build); nothing is fabricated in their place.",
    },
    runners: {
      code: "runner_manager_route_missing",
      title: "Partially served",
      text: "Runner rows project live daemon providers. Runner managers and runner log tokens have no daemon routes and refuse typed.",
    },
  };
  function mountSettingsGapBanner() {
    const bannerId = "ioi-settings-gap-banner";
    const m = location.pathname.match(/^\/settings\/([^/?#]+)/);
    const gap = m && SETTINGS_GAP_BANNERS[m[1]];
    const existing = document.getElementById(bannerId);
    if (!gap) {
      if (existing) existing.remove();
      return;
    }
    if (existing && existing.dataset.pane === m[1] && existing.isConnected) return;
    const host = document.querySelector("main") || document.body;
    const el = existing || document.createElement("div");
    el.id = bannerId;
    el.dataset.pane = m[1];
    el.className = "rounded-xl border border-border-warning bg-surface-warning-subtle px-4 py-3 text-sm text-content-warning";
    el.style.margin = "12px 16px 0";
    el.innerHTML =
      "<b>" + esc(gap.title) + "</b> — " + esc(gap.text) +
      ' <code style="opacity:.75">' + esc(gap.code) + "</code>";
    if (el.parentElement !== host) host.prepend(el);
  }
