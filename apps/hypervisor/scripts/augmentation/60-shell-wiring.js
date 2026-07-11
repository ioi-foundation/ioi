  // ---- Native Ontology rail item (operational wave PR61) — the ONE missing permanent rail
  // destination: after Automations, before Applications; routes to the Ontology MANAGER (the
  // owner surface; /__ioi/odk stays the substrate linked from within) and opens in the singular
  // Open Application slot in EMBEDDED mode. Cloned from the native Automations item so it keeps
  // the SPA's own rail styling; self-guarded + re-applied per tick (React re-renders the rail).
  function mountOntologyNav() {
    if (document.getElementById("ioi-ontology-rail")) return;
    const sidebar = document.querySelector('[data-testid="sidebar"]');
    if (!sidebar) return;
    const auto = sidebar.querySelector('a[href="/automations"]');
    if (!auto) return;
    const item = auto.cloneNode(true);
    item.id = "ioi-ontology-rail";
    item.setAttribute("href", "/__ioi/ontology/manager?embed=1");
    item.setAttribute("data-ioi-app", "Ontology");
    item.removeAttribute("aria-current");
    const label = Array.prototype.find.call(item.querySelectorAll("*"), (el) => el.childElementCount === 0 && /automations/i.test(el.textContent || ""));
    if (label) label.textContent = "Ontology"; else item.textContent = "Ontology";
    const svg = item.querySelector("svg");
    if (svg) {
      const ico = document.createElement("span");
      ico.textContent = "🧬";
      ico.setAttribute("aria-hidden", "true");
      ico.style.cssText = "font-size:15px;line-height:16px;display:inline-flex;align-items:center;justify-content:center;width:16px;height:16px";
      svg.replaceWith(ico);
    }
    auto.insertAdjacentElement("afterend", item);
  }

  function wireApplicationsLauncher() {
    if (window.__ioiAppsLauncherWired) return;
    window.__ioiAppsLauncherWired = true;
    window.addEventListener("resize", positionOpenApp);
    document.addEventListener(
      "click",
      (e) => {
        const t = e.target;
        if (!t || !t.closest) return;
        // Active "Open Application" rail row: ✕ closes; the row refocuses the slot WITHOUT reloading.
        const oar = t.closest("#ioi-openapp-rail");
        if (oar) {
          e.preventDefault(); e.stopPropagation();
          if (t.closest(".ioi-oar-x")) { closeApplication(); }
          else { const el = document.getElementById("ioi-open-app"); if (el) { el.style.display = "block"; positionOpenApp(); } }
          return;
        }
        // New Session (the rail create-session action) → the composer page (its true identity).
        // The owned governed modal stays one click away via the composer's Advanced-launch link.
        if (t.closest('[data-testid="create-session-button"]')) {
          e.preventDefault(); e.stopPropagation(); closeApplication(); goComposer(); return;
        }
        // Applications launcher (rail #applications, the SPA's native launcher attr, or the estate deep-link) → MODAL.
        if (t.closest('a[href="#applications"], [data-hypervisor-applications-launcher], a[href="/__ioi/applications"]')) {
          e.preventDefault(); e.stopPropagation(); appsModal(); return;
        }
        // Catalog app tiles (data-ioi-app carries the display title) → the Open Application slot.
        const catLink = t.closest("a[data-ioi-app]");
        if (catLink) {
          e.preventDefault(); e.stopPropagation();
          openApplication(catLink.getAttribute("href"), catLink.getAttribute("data-ioi-app"));
          return;
        }
        // Live application links → open IN-SHELL in the Open Application slot (left rail stays).
        const appLink = t.closest('a[href^="/__ioi/connections"], a[href^="/__ioi/work-ledger"], a[href^="/__ioi/operations"], a[href^="/__ioi/environments"], a[href^="/__ioi/workbench"], a[href^="/__ioi/agent-studio"], a[href^="/__ioi/foundry"], a[href^="/__ioi/feedback"], a[href^="/__ioi/sessions"], a[href^="/__ioi/domain-apps"], a[href^="/__ioi/domain-app-runtime"], a[href^="/__ioi/governance"], a[href^="/__ioi/marketplace"], a[href^="/__ioi/ontology"], a[href^="/__ioi/odk"], a[href^="/__ioi/home"]');
        if (appLink) {
          e.preventDefault(); e.stopPropagation();
          const href = appLink.getAttribute("href");
          const name = /work-ledger/.test(href) ? "Provenance" : /operations/.test(href) ? "Operations" : /environments/.test(href) ? "Environments" : /workbench/.test(href) ? "Workbench" : /agent-studio/.test(href) ? "Studio" : /foundry/.test(href) ? "Foundry" : /feedback/.test(href) ? "Evaluations" : /\/__ioi\/sessions/.test(href) ? "Missions" : /domain-app-runtime/.test(href) ? "Domain App" : /domain-apps/.test(href) ? "Generated Apps" : /governance/.test(href) ? "Governance" : /marketplace/.test(href) ? "Marketplace" : /\/__ioi\/ontology\/explorer/.test(href) ? "Object Explorer" : /\/__ioi\/ontology/.test(href) ? "Ontology" : /\/__ioi\/odk.*#data-planes/.test(href) ? "Data" : /\/__ioi\/odk/.test(href) ? "Ontology" : /\/__ioi\/home/.test(href) ? "Governed Work" : "Developer Console";
          openApplication(href, name);
          return;
        }
        // Rail Home (a[href="/ai"], incl. the brand mark) → the explorer Home. If already on /ai
        // the SPA router would no-op and leave a stale #new-session hash, so route ourselves.
        const homeLink = t.closest('[data-testid="sidebar"] a[href="/ai"]');
        if (homeLink) {
          closeApplication();
          if (location.pathname === "/ai") { e.preventDefault(); e.stopPropagation(); goHome(); }
          return; // else: native SPA nav lands on /ai hashless → explorer
        }
        // Any other left-rail nav (Projects/Automations) → close the open app, let the SPA navigate.
        if (t.closest('[data-testid="sidebar"] a')) closeApplication();
      },
      true, // capture — beat the SPA's native (empty) Applications modal + client router
    );
  }

