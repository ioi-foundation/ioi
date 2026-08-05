  // W0.2: the launcher renders the COMPILED PRODUCT-SURFACE PROJECTION (fetched by
  // 35-app-catalog.js from /__ioi/api/applications — daemon registration records compiled by
  // scripts/surface-compiler.mjs). The former hand-maintained IOI_APPS constant is deleted;
  // this module never hardcodes an app list. Until the projection arrives — or when the daemon
  // is down — the modal states that honestly instead of showing a frozen fake catalog.
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
    const c = catalogAppByTitle(name); // ported app → its owner family's compiled emoji for the rail row
    const a = compiledAppByName(c ? c.family : name);
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
    // Everything below renders the ONE compiled product-surface projection (W0.2) — the
    // applications + workspaces bands are daemon registration records; the ported band is the
    // demoted evidence lane (implementation evidence, zero catalog authority).
    const compiledRow = (s) => {
      // Prefer the legacy lane that serves this surface today (embedded open); else the
      // canonical route (top navigation). No target → disabled row with the named reason.
      const target = (s.open_today && s.open_today.href) || (s.launchable ? (s.launch_route || s.route) : "") || "";
      const pill = s.launchable ? "open" : esc((s.disabled_reason_codes || [])[0] || "not launchable");
      const top = target && target.indexOf("/__ioi/") !== 0 ? ' data-nav="top"' : "";
      return '<div class="ioi-mrow' + (target ? "" : " disabled") + '"' + (target ? ' data-href="' + target + '" data-name="' + esc(s.name) + '"' + top : "") +
        '><span>' + (s.icon || "◳") + '</span><span><div class="ioi-mname">' + esc(s.name) + '</div><div class="ioi-mdesc">' + esc(s.desc || "") + (s.route ? " · " + esc(s.route) : "") + '</div></span><span class="ioi-mpill">' + pill + "</span></div>";
    };
    const ported = catalogApps().map((a) =>
      '<div class="ioi-mrow" data-href="' + a.route + '" data-name="' + esc(a.title) + '"><span>' + catalogIcon(a, 20) +
      '</span><span><div class="ioi-mname">' + esc(a.title) + '</div><div class="ioi-mdesc">' + esc(a.family) + " · " + esc(a.route) +
      '</div></span><span class="ioi-mpill">open</span></div>').join("");
    const apps = compiledApps().map(compiledRow).join("");
    const wsp = compiledWorkspaces().map(compiledRow).join("");
    if (!apps && !ported) {
      return '<div class="ioi-mgrp">Compiled product-surface projection not loaded yet — no catalog is shown rather than a stale hand list.</div>';
    }
    const down = compiledApps().length && !compiledDaemonOk()
      ? '<div class="ioi-mgrp">Daemon unavailable (' + esc(compiledDaemonCode()) + ') — static first-party inventory; launch state unknown</div>'
      : "";
    return down +
      (apps ? '<div class="ioi-mgrp">Applications</div>' + apps : "") +
      (wsp ? '<div class="ioi-mgrp">Workspaces</div>' + wsp : "") +
      (ported ? '<div class="ioi-mgrp">Ported tool surfaces (evidence lane)</div>' + ported : "");
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
        if (row) {
          el.classList.remove("open");
          // Canonical (non-/__ioi/) routes navigate top-level; legacy estate lanes open embedded.
          if (row.getAttribute("data-nav") === "top") location.assign(row.getAttribute("data-href"));
          else openApplication(row.getAttribute("data-href"), row.getAttribute("data-name"));
        }
      });
    }
    // Rebuild when the compiled projection lands (the stamp covers every band + daemon state).
    const stamp = catalogApps().length + "/" + compiledApps().length + "/" + compiledWorkspaces().length + "/" + (compiledDaemonOk() ? "up" : "down");
    if (el.getAttribute("data-catalog") !== stamp) {
      el.setAttribute("data-catalog", stamp);
      el.innerHTML = '<div class="ioi-modal"><div class="ioi-mh"><span>Applications</span><button title="Close">✕</button></div>' + appsModalRows() + "</div>";
    }
    el.classList.add("open");
  }
