  // ---- W0.5 identity truth — named degraded states for settings panes whose backing RPCs now
  // refuse typed instead of serving local-constant placeholder data (adapter: GetOrganization,
  // GetTermsOfService, GetOrganizationPolicies, ListServiceAccounts, ListAvailableRunnerManagers,
  // CreateRunnerLogsToken). The vendor pane keeps its own error rendering; this banner names the
  // gap in product language so the degraded state is explicit, not a bare failure. Zero
  // placeholder data; self-removes off-route. --------------------------------------------------
  const SETTINGS_GAP_BANNERS = {
    // Only when the roster is actually empty: an administrator's roster renders (R-240), and a banner
    // claiming "the roster renders empty" above a listed roster was false.
    "members": {
      code: "org_roster_admin_gated",
      title: "The member roster is readable by administrators only",
      text: "The daemon's principals plane answers the roster to an organization administrator; this session is not one, so the list below is a refusal, not an empty organization.",
      when: () => !document.querySelector("main tbody tr"),
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
  // Manage organization, self-hosted (R-240). The vendor pane offers a commercial Tier (Core vs
  // Enterprise, "Request free trial") and "Delete this organization". A self-hosted deployment has no
  // tier and no trial, and hosts ONE organization that is removed with the deployment — the delete
  // RPC has no lane and refused with an adapter message. The tier cards become one line saying so;
  // the delete button is disabled with its reason, in place.
  function updateManageOrganization() {
    if (!/^\/settings\/manage-organization\/?$/.test(location.pathname)) return;
    const main = document.querySelector("main"); if (!main) return;
    const label = Array.prototype.find.call(main.querySelectorAll("*"), (e) => !e.children.length && e.textContent.trim() === "Tier");
    // "Tier" labels a row of its own; the cards and the "Under Billing…" line are the rows that follow
    // it, up to the Organization ID row.
    const row = label && (label.parentElement && label.parentElement.children.length <= 2 ? label.parentElement : label);
    if (row && !document.getElementById("ioi-selfhosted-tier")) {
      for (let n = row.nextElementSibling; n && !/Organization ID/.test(n.textContent || ""); n = n.nextElementSibling) n.style.display = "none";
      const note = document.createElement("p");
      note.id = "ioi-selfhosted-tier";
      note.style.cssText = "margin:6px 0 16px;font-size:14px;opacity:.8";
      note.textContent = "Self-hosted — this deployment runs every capability it has; there is no commercial tier and nothing to upgrade or trial.";
      row.insertAdjacentElement("afterend", note);
    }
    const del = Array.prototype.find.call(main.querySelectorAll("button"), (b) => b.textContent.trim() === "Delete this organization");
    if (del && !del.hasAttribute("data-ioi-disabled-reason")) {
      const why = "This deployment hosts one organization; it is removed with the deployment itself, not from this page.";
      del.disabled = true; del.setAttribute("aria-disabled", "true"); del.setAttribute("title", why); del.setAttribute("data-ioi-disabled-reason", why);
      del.style.cursor = "not-allowed"; del.style.opacity = ".5";
      const note = document.createElement("p"); note.style.cssText = "margin:8px 0 0;font-size:13px;opacity:.75"; note.textContent = why;
      del.insertAdjacentElement("afterend", note);
    }
  }
  function mountSettingsGapBanner() {
    const bannerId = "ioi-settings-gap-banner";
    const m = location.pathname.match(/^\/settings\/([^/?#]+)/);
    const entry = m && SETTINGS_GAP_BANNERS[m[1]];
    // An entry with a `when` names a state, not a page: it mounts only while that state holds.
    const gap = entry && (!entry.when || entry.when()) ? entry : null;
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
