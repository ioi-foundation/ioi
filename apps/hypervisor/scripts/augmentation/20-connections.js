  // ---- BYOA "Create & connect GitHub App" affordance on the Git authentications surface ----------
  // The product-ui bundle's native connect modal only knows PAT/OAuth; GitHub App is a method it can't
  // render, so we add it ourselves — below the connections list, styled with the SPA's own design
  // tokens. It LAUNCHES IN A NEW TAB so the settings dialog stays put; the flow's success page tells
  // the user to close that tab. Idempotent + re-applied each tick (React re-renders the panel).
  function mountGitAppButton() {
    const panel = document.querySelector('[data-testid="git-authentications"]');
    if (!panel || document.getElementById("ioi-ghapp-connect")) return;
    const btn = document.createElement("button");
    btn.id = "ioi-ghapp-connect";
    btn.type = "button";
    btn.className =
      "mt-3 flex w-full items-center justify-between gap-3 rounded-xl border border-dashed " +
      "border-border-base bg-surface-secondary px-4 py-3.5 text-left transition-colors " +
      "hover:bg-surface-button-clear-accent hover:border-border-brand";
    btn.innerHTML =
      '<span class="flex min-w-0 flex-col gap-0.5">' +
      '<span class="text-base font-medium text-content-primary">Create &amp; connect GitHub App</span>' +
      '<span class="text-sm text-content-secondary">Bring your own — created in your account, no shared secret. Fine-grained, auto-refreshing access.</span>' +
      "</span>" +
      '<span class="shrink-0 text-content-secondary" aria-hidden="true">↗</span>';
    btn.addEventListener("click", function () {
      window.open("/__ioi/github-app/start", "_blank", "noopener");
    });
    panel.appendChild(btn);
  }

  // ---- Native Integrations "Connect" → OAuth-native Connect (authorize, not paste) --------------
  // Each integration row's Connect button carries data-testid="connect-<connectorId>". Override its
  // click to open our launcher in a popup: discover+DCR if needed, then redirect to the provider
  // authorize. The agent only ever gets scoped leases; the provider credential stays in the daemon.
  function wireIntegrationConnect() {
    document.querySelectorAll('button[data-testid^="connect-conn_"]').forEach((btn) => {
      if (btn.dataset.ioiWired === "1") return;
      btn.dataset.ioiWired = "1";
      btn.addEventListener(
        "click",
        function (ev) {
          const id = btn.getAttribute("data-testid").slice("connect-".length);
          if (!id) return;
          ev.preventDefault();
          ev.stopPropagation();
          ev.stopImmediatePropagation();
          window.open("/__ioi/integrations/connect/" + encodeURIComponent(id), "_blank", "noopener");
        },
        true, // capture — run before the SPA's own handler
      );
    });
  }

  // ---- Developer & Integrations IA: Connections is DEMOTED from the permanent rail and re-homed as
  // the "Developer & Integrations" surface inside the Applications estate. The "Applications" rail
  // launcher (#applications) opens the owned estate at /__ioi/applications, where Developer &
  // Integrations routes to the existing Connections cockpit (/__ioi/connections) — NOT rebuilt.
  // (Settings > Integrations projections + git-auth wiring below are untouched.) ----
  function removeConnectionsNav() {
    document.querySelectorAll(".ioi-connections-nav").forEach((e) => e.remove()); // drop the old permanent rail item
  }
  // Applications = a MODAL launcher; an opened application renders IN-SHELL (left rail intact) in a
  // single "Open Application" slot — an iframe positioned right of the rail. /__ioi/applications stays
  // a deep-link fallback. Live entries open owned surfaces; planned/contextual shown honestly.
