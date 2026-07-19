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
    const contextual = catalogContextSurfaceByTitle(name);
    const owner = contextual ? catalogEntryByRef(contextual.placement_owner_ref) : null;
    const direct = catalogApplications().concat(catalogCoreWorkspaces()).find((entry) => entry.name === name || name.indexOf(entry.name + " /") === 0);
    return (owner && owner.icon) || (direct && direct.icon) || "◳";
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
  // Native container contract (#65): everything opened in the Open Application slot renders in
  // EMBEDDED mode — the native rail outside the iframe is the ONE platform rail, so every estate
  // route is normalized through URL and carries embed=1 (query params and hash preserved).
  function embeddedAppSrc(href) {
    try {
      const u = new URL(href, location.origin);
      if (u.origin !== location.origin || !u.pathname.startsWith("/__ioi/")) return href;
      u.searchParams.set("embed", "1");
      return u.pathname + u.search + u.hash;
    } catch { return href; }
  }
  function openApplication(href, title) {
    href = embeddedAppSrc(href);
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
    const applicationRows = (entries) => entries.map((entry) => {
      const live = entry.launchable === true;
      const pill = live ? (entry.route_posture === "canonical" ? entry.implementation_state : "compatibility") : "planned";
      return '<div class="ioi-mrow' + (live ? "" : " disabled") + '" data-registration-ref="' + esc(entry.ref) + '"' + (live ? ' data-href="' + entry.launch_route + '" data-name="' + esc(entry.name) + '"' : "") +
        '><span>' + entry.icon + '</span><span><div class="ioi-mname">' + esc(entry.name) + '</div><div class="ioi-mdesc">' + esc(entry.description) + '</div></span><span class="ioi-mpill">' + pill + "</span></div>";
    }).join("");
    const owners = applicationRows(catalogOwnerApplications());
    const substrate = applicationRows(catalogSubstrateApplications());
    const specialists = applicationRows(catalogSpecialistApplications());
    const contextual = catalogContextSurfaces().map((entry) =>
      '<div class="ioi-mrow" data-surface-key="' + esc(entry.surface_key) + '" data-href="' + entry.launch_route + '" data-name="' + esc(entry.title) + '"><span>' + catalogIcon(entry, 20) +
      '</span><span><div class="ioi-mname">' + esc(entry.title) + '</div><div class="ioi-mdesc">' + esc(entry.placement) +
      '</div></span><span class="ioi-mpill">' + esc(entry.implementation_state) + "</span></div>").join("");
    return '<div class="ioi-mgrp">Applications</div>' + owners +
      (substrate ? '<div class="ioi-mgrp">Substrate</div>' + substrate : "") +
      (specialists ? '<div class="ioi-mgrp">Specialist applications</div>' + specialists : "") +
      (contextual ? '<div class="ioi-mgrp">Tools and views</div>' + contextual : "");
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
    // Rebuild when the typed catalog projection lands.
    const stamp = catalogStamp();
    if (el.getAttribute("data-catalog") !== stamp) {
      el.setAttribute("data-catalog", stamp);
      el.innerHTML = '<div class="ioi-modal"><div class="ioi-mh"><span>Applications</span><button title="Close">✕</button></div>' + appsModalRows() + "</div>";
    }
    el.classList.add("open");
  }
