  const IOI_APPS = [
    { icon: "🧰", name: "Workbench", desc: "Enter an environment's live console — files, terminal, ports, tasks.", href: "/__ioi/workbench", status: "live" },
    { icon: "🖥", name: "Environments", desc: "Lifecycle, readiness, services/ports/tasks, substrate posture.", href: "/__ioi/environments", status: "live" },
    { icon: "🧪", name: "Agent Studio", desc: "Agent inventory, model routes, runner adapters, activity.", href: "/__ioi/agent-studio", status: "live" },
    { icon: "🏗", name: "Foundry", desc: "Capability factory — draft specs, run plans, promotion previews.", href: "/__ioi/foundry", status: "live" },
    { icon: "📦", name: "ODK", desc: "Ontology Development Kit — ontologies, data recipes, surface descriptors, manifests.", href: "/__ioi/odk", status: "live" },
    { icon: "🧩", name: "Domain Apps", desc: "Draft app candidates over ODK domain_app descriptors (no runtime yet).", href: "/__ioi/domain-apps", status: "live" },
    { icon: "🔌", name: "Developer & Integrations", desc: "Connectors, MCP, credentials, dev tools.", href: "/__ioi/connections", status: "live" },
    { icon: "🛡", name: "Governance", desc: "Control lens — authority, identity, leases, revocation, gaps.", href: "/__ioi/governance", status: "live" },
    { icon: "⚙", name: "Operations", desc: "Execution health — scheduler, runs, failures, webhooks.", href: "/__ioi/operations", status: "live" },
    { icon: "📒", name: "Work Ledger", desc: "Runs, receipts, state roots, timelines.", href: "/__ioi/work-ledger", status: "live" },
    { icon: "🛒", name: "Marketplace", desc: "Catalog & admission — listings, publish candidates, admission reviews (admission-only).", href: "/__ioi/marketplace", status: "live" },
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
    const a = IOI_APPS.find((x) => x.name === name);
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
    if (f.getAttribute("src") !== href) f.setAttribute("src", href); // singular slot: reuse, replace src (no reload if same href)
    el.style.display = "block";
    positionOpenApp();
    updateOpenAppRail();
  }
  function appsModal() {
    let el = document.getElementById("ioi-apps-modal");
    if (!el) {
      el = document.createElement("div");
      el.id = "ioi-apps-modal";
      const rows = IOI_APPS.map((a) => {
        const pill = a.status === "live" ? "open" : a.status === "contextual" ? "in a session" : "planned";
        const live = a.status === "live";
        return '<div class="ioi-mrow' + (live ? "" : " disabled") + '"' + (live ? ' data-href="' + a.href + '" data-name="' + esc(a.name) + '"' : "") +
          '><span>' + a.icon + '</span><span><div class="ioi-mname">' + esc(a.name) + '</div><div class="ioi-mdesc">' + esc(a.desc) + '</div></span><span class="ioi-mpill">' + pill + "</span></div>";
      }).join("");
      el.innerHTML = '<div class="ioi-modal"><div class="ioi-mh"><span>Applications</span><button title="Close">✕</button></div>' + rows + "</div>";
      document.body.appendChild(el);
      el.addEventListener("click", (e) => {
        if (e.target === el || e.target.closest(".ioi-mh button")) { el.classList.remove("open"); return; } // backdrop / ✕
        const row = e.target.closest(".ioi-mrow[data-href]");
        if (row) { el.classList.remove("open"); openApplication(row.getAttribute("data-href"), row.getAttribute("data-name")); }
      });
    }
    el.classList.add("open");
  }
