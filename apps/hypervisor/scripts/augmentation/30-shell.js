  // The autonomous-systems suite (canon: core-clients-surfaces.md "The Autonomous-Systems
  // Application Suite"; detail: internal-docs/prompts/autonomous-systems-suite/suite-guide.md),
  // then the substrate lane (type 1+2 face). Every href opens a REAL surface today; where a
  // suite identity is wider than its current surface, the copy names what is live.
  const IOI_APPS = [
    { icon: "🎨", name: "Studio", desc: "Compose systems & agents — agent lens live (inventory, model routes, adapters); system canvas adopting.", href: "/__ioi/agent-studio", status: "live", lane: "suite" },
    { icon: "⚡", name: "Automations", desc: "Durable triggers, schedules, monitors, services — condition → governed effect.", href: "/__ioi/automations", status: "live", lane: "suite" },
    { icon: "🧬", name: "Ontology", desc: "The semantic world-model — Ontology Manager over the typed COM; Explorer + ODK substrate linked within.", href: "/__ioi/ontology/manager", status: "live", lane: "suite" },
    { icon: "🌐", name: "Data", desc: "Supply the world-model — sources, syncs, recipes, datasets, media sets, consent.", href: "/__ioi/odk#data-planes", status: "live", lane: "suite" },
    { icon: "🛡", name: "Governance", desc: "Authority — approvals, leases, release gates, kill switches, budgets, gaps.", href: "/__ioi/governance", status: "live", lane: "suite" },
    { icon: "🚀", name: "Missions", desc: "Fleet of running systems — sessions root live; dedicated fleet console adopting.", href: "/__ioi/sessions", status: "live", lane: "suite" },
    { icon: "📒", name: "Provenance", desc: "Proof plane — receipts stream, state roots, timelines live; lineage canvas adopting.", href: "/__ioi/work-ledger", status: "live", lane: "suite" },
    { icon: "🧪", name: "Evaluations", desc: "Feedback with consent + eval handoffs live; suites & scorecards adopting.", href: "/__ioi/feedback", status: "live", lane: "suite" },
    { icon: "📈", name: "Improvement", desc: "Proposals, what-if simulation, apply-under-gates — proposal lane live; change inbox adopting.", href: "/__ioi/agent-studio#improvement-proposals", status: "live", lane: "suite" },
    { icon: "🏗", name: "Foundry", desc: "Model substrate — catalog, routes, draft specs, run plans, promotion previews.", href: "/__ioi/foundry", status: "live", lane: "suite" },
    { icon: "🛒", name: "Marketplace", desc: "Distribution — listings, publish candidates, admission reviews (admission-only).", href: "/__ioi/marketplace", status: "live", lane: "suite" },
    { icon: "🧰", name: "Workbench", desc: "Enter an environment's live console — files, terminal, ports, tasks.", href: "/__ioi/workbench", status: "live", lane: "suite" },
    { icon: "🔌", name: "Developer Console", desc: "Extend the environment — connectors, MCP, credentials, SDK on-ramps.", href: "/__ioi/connections", status: "live", lane: "suite" },
    { icon: "🖥", name: "Environments", desc: "Substrate — lifecycle, readiness, services/ports/tasks, kernel boundary.", href: "/__ioi/environments", status: "live", lane: "substrate" },
    { icon: "⚙", name: "Operations", desc: "Substrate — scheduler health, providers, placement/failover, custody, spend.", href: "/__ioi/operations", status: "live", lane: "substrate" },
  ];
  function railRight() {
    const s = document.querySelector('[data-testid="sidebar"]');
    if (s) { const r = s.getBoundingClientRect(); if (r.width > 0 && r.left < 40) return Math.round(r.right); }
    return 0;
  }
  function positionOpenApp() {
    const el = document.getElementById("ioi-open-app");
    if (el && el.style.display !== "none") el.style.left = railRight() + "px";
  }
  function appIconFor(name) {
    const c = catalogAppByTitle(name); // ported app → its family's emoji for the rail row
    const a = IOI_APPS.find((x) => x.name === (c ? c.family : name));
    return a ? a.icon : "◳";
  }
  function findAppsNavItem() {
    return Array.prototype.find.call(
      document.querySelectorAll('a[href="#applications"]'),
      (s) => { const r = s.getBoundingClientRect(); return r.width > 0 && r.top > 0 && r.top < 1500; },
    );
  }
  // Render ONE active "Open Application" rail row right after Applications (no pinned region).
  function updateOpenAppRail() {
    const el = document.getElementById("ioi-open-app");
    const isOpen = !!el && el.style.display !== "none";
    let row = document.getElementById("ioi-openapp-rail");
    if (!isOpen) { if (row) row.remove(); return; }
    const sib = findAppsNavItem();
    if (!sib) { if (row) row.remove(); return; }
    const name = el.getAttribute("data-app-name") || "Application";
    const icon = el.getAttribute("data-app-icon") || "◳";
    if (!row) {
      row = document.createElement("a");
      row.id = "ioi-openapp-rail";
      row.className = "ioi-openapp-rail";
      row.setAttribute("href", "#open-application");
    }
    if (row.previousElementSibling !== sib) sib.insertAdjacentElement("afterend", row); // keep right after Applications
    if (row.getAttribute("data-name") !== name) {
      row.setAttribute("data-name", name);
      row.innerHTML = '<span class="ioi-oar-ico">' + icon + '</span><span class="ioi-oar-txt"><span class="ioi-oar-l">Open Application</span><span class="ioi-oar-n">' + esc(name) + '</span></span><button class="ioi-oar-x" title="Close">✕</button>';
    }
  }
  function closeApplication() {
    const el = document.getElementById("ioi-open-app");
    if (el) el.style.display = "none";
    updateOpenAppRail();
  }
  function embeddedAppSrc(href) {
    // Stack correction (#61 amendment): the Open Application slot always renders /__ioi/
    // applications EMBEDDED (embed=1; query/hash preserved) — the native rail outside the
    // iframe is the one platform rail. Non-/__ioi/ hrefs pass through untouched.
    try {
      if (!String(href).startsWith("/__ioi/")) return href;
      const u = new URL(href, location.origin);
      u.searchParams.set("embed", "1");
      return u.pathname + u.search + u.hash;
    } catch (e) { return href; }
  }
  function openApplication(href, title) {
    let el = document.getElementById("ioi-open-app");
    if (!el) {
      el = document.createElement("div");
      el.id = "ioi-open-app";
      el.innerHTML = '<div class="ioi-oa-bar"><span class="ioi-oa-title"></span><button class="ioi-oa-close" title="Close">Close ✕</button></div><iframe title="application"></iframe>';
      document.body.appendChild(el);
      el.querySelector(".ioi-oa-close").addEventListener("click", closeApplication);
    }
    el.querySelector(".ioi-oa-title").textContent = title || "Application";
    el.setAttribute("data-app-name", title || "Application");
    el.setAttribute("data-app-icon", appIconFor(title));
    const f = el.querySelector("iframe");
    const src = embeddedAppSrc(href);
    if (f.getAttribute("src") !== src) f.setAttribute("src", src); // singular slot: reuse, replace src (no reload if same href)
    el.style.display = "block";
    positionOpenApp();
    updateOpenAppRail();
  }
  function appsModalRows() {
    // Ported apps (catalog projection, arrives async) first, then the suite family surfaces.
    const ported = catalogApps().map((a) =>
      '<div class="ioi-mrow" data-href="' + a.route + '" data-name="' + esc(a.title) + '"><span>' + catalogIcon(a, 20) +
      '</span><span><div class="ioi-mname">' + esc(a.title) + '</div><div class="ioi-mdesc">' + esc(a.family) + " · " + esc(a.route) +
      '</div></span><span class="ioi-mpill">open</span></div>').join("");
    const families = IOI_APPS.map((a) => {
      const pill = a.status === "live" ? "open" : a.status === "contextual" ? "in a session" : "planned";
      const live = a.status === "live";
      return '<div class="ioi-mrow' + (live ? "" : " disabled") + '"' + (live ? ' data-href="' + a.href + '" data-name="' + esc(a.name) + '"' : "") +
        '><span>' + a.icon + '</span><span><div class="ioi-mname">' + esc(a.name) + '</div><div class="ioi-mdesc">' + esc(a.desc) + '</div></span><span class="ioi-mpill">' + pill + "</span></div>";
    }).join("");
    return (ported ? '<div class="ioi-mgrp">Apps</div>' + ported + '<div class="ioi-mgrp">Suite</div>' : "") + families;
  }
  function appsModal() {
    let el = document.getElementById("ioi-apps-modal");
    if (!el) {
      el = document.createElement("div");
      el.id = "ioi-apps-modal";
      document.body.appendChild(el);
      el.addEventListener("click", (e) => {
        if (e.target === el || e.target.closest(".ioi-mh button")) { el.classList.remove("open"); return; } // backdrop / ✕
        const row = e.target.closest(".ioi-mrow[data-href]");
        if (row) { el.classList.remove("open"); openApplication(row.getAttribute("data-href"), row.getAttribute("data-name")); }
      });
    }
    // Rebuild when the catalog projection lands (data-catalog stamps the rendered app count).
    const stamp = String(catalogApps().length);
    if (el.getAttribute("data-catalog") !== stamp) {
      el.setAttribute("data-catalog", stamp);
      el.innerHTML = '<div class="ioi-modal"><div class="ioi-mh"><span>Applications</span><button title="Close">✕</button></div>' + appsModalRows() + "</div>";
    }
    el.classList.add("open");
  }
