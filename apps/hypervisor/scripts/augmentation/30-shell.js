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
    watchRailWidth();
  }
  // THE SLOT FOLLOWS THE RAIL (R-240, owner: "still buggy if you open close with a collapsed
  // sidebar"). The slot's left edge was set once, when an app opened; collapsing or expanding the
  // sidebar afterwards left it covering the expanded rail or leaving a gap. A ResizeObserver on the
  // sidebar re-places it whenever the rail's width changes (re-attached if the shell re-creates it).
  let railObserved = null, railObserver = null;
  function watchRailWidth() {
    const s = document.querySelector('[data-testid="sidebar"]');
    if (!s || s === railObserved || typeof ResizeObserver !== "function") return;
    if (railObserver) railObserver.disconnect();
    railObserver = new ResizeObserver(() => { const el = document.getElementById("ioi-open-app"); if (el && el.style.display !== "none") el.style.left = railRight() + "px"; });
    railObserver.observe(s);
    railObserved = s;
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
  // THE ACCOUNT MENU'S "Support" DID NOTHING (R-240). It calls `window.Pylon("show")`, a vendor
  // support-chat widget this product never loads; the product-ui server pins `window.Pylon` to a no-op
  // (a getter, and a setter that discards writes — so a plain assignment here is silently ignored) so
  // the call cannot throw, and the click only closed the menu. The property is configurable, so it is
  // redefined: "show" opens the help page's support topic in a new tab, the way "Docs" opens help.
  (function () {
    const showSupport = function () { window.open("/__ioi/help?topic=support", "_blank", "noopener"); };
    const pylon = Object.assign(function (command) { if (command === "show") showSupport(); }, { boot() {}, update() {}, shutdown() {}, hide() {}, show: showSupport });
    try { Object.defineProperty(window, "Pylon", { configurable: true, get: () => pylon, set: () => {} }); } catch (e) { /* a non-configurable stub keeps its no-op */ }
  })();
  // A SERVE-RENDERED PAGE IS NOT A SHELL ROUTE (R-240). The shell routes its links client-side, and
  // for a path the serve renders — /join-organization, /changelog, any /__ioi/ surface, the sign-in
  // page — that draws the shell's not-found page (or, for Join, a blank layout). Settings' "Back to
  // IOI" links to wherever you were before, which after signing in with a `next` IS the sign-in page.
  // Such a link gets a full navigation; a "Back to" link that would return to sign-in goes Home.
  const SERVE_RENDERED = /^\/(__ioi|__apps|v1|api|auth|scim|changelog|join-organization)(\/|$|\?)/;
  document.addEventListener("click", function (e) {
    const a = e.target && e.target.closest && e.target.closest("a[href]");
    if (!a || e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    if (a.target && a.target !== "_self") return; // a new tab or the top frame is already a full navigation
    let u;
    try { u = new URL(a.getAttribute("href"), location.href); } catch (err) { return; }
    if (u.origin !== location.origin || !SERVE_RENDERED.test(u.pathname)) return;
    e.preventDefault(); e.stopPropagation();
    const backToSignIn = /^Back to\b/.test((a.innerText || "").trim()) && /^\/__ioi\/(login|bootstrap|logout)/.test(u.pathname);
    if (backToSignIn) { window.location.assign("/ai"); return; }
    // AN APPLICATION OPENS INSIDE THE SHELL (R-240, owner: "once engaged in an application, we lose
    // our black rail sidebar"). This listener used to send EVERY estate page to a full navigation,
    // which replaced the shell — rail and all. An estate application page opens in the embedded slot
    // instead (embed=1: the page drops its own rail, the shell's stays); sign-in, help, reference
    // lanes and the API paths keep their full navigation.
    if (/^\/__ioi\//.test(u.pathname) && !/^\/__ioi\/(login|logout|bootstrap|help|invite)(\/|$)/.test(u.pathname)) {
      const name = a.getAttribute("data-ioi-app") || a.getAttribute("data-app") || ((a.textContent || "").trim().split(/\s{2,}|\n/)[0] || "Application").slice(0, 60);
      openApplication(u.pathname + u.search + u.hash, name);
      return;
    }
    window.location.assign(u.pathname + u.search + u.hash);
  }, true);
  // ESC LEFT SETTINGS FOR A PAGE THE SHELL CANNOT DRAW (R-240, measured). Settings' Esc goes where
  // "Back to IOI" goes — the newest history entry outside /settings — but through the shell's own
  // router, so the click rule above never sees it: after signing in with a `next`, Esc pushed
  // /__ioi/login and drew "This page doesn't exist". When that return target is serve-rendered, Esc
  // leaves the way the link does: the sign-in page returns Home, any other page loads in full.
  window.addEventListener("keydown", function (e) {
    if (e.key !== "Escape" || e.defaultPrevented || !/^\/settings(\/|$)/.test(location.pathname)) return;
    const overlayOpen = Array.prototype.some.call(document.querySelectorAll('[role="dialog"],[role="alertdialog"],[role="menu"],[role="listbox"]'), (x) => { const r = x.getBoundingClientRect(); return r.width > 0 && r.height > 0; });
    if (overlayOpen) return; // Esc closes that first
    const entries = window.navigation && typeof window.navigation.entries === "function" ? window.navigation.entries().slice().reverse() : [];
    let back = null;
    for (const entry of entries) {
      try { const u = new URL(entry.url); if (!u.pathname.startsWith("/settings")) { back = u; break; } } catch (err) { /* the shell skips it too */ }
    }
    if (!back || back.origin !== location.origin || !SERVE_RENDERED.test(back.pathname)) return; // the shell draws it
    e.preventDefault(); e.stopImmediatePropagation();
    window.location.assign(/^\/__ioi\/(login|bootstrap|logout)/.test(back.pathname) ? "/ai" : back.pathname + back.search + back.hash);
  }, true);
  // Signed-out honesty (R-240). A local browser reads as the local operator — whoami answers with that
  // display principal AND `authenticated: false` — while the daemon lists and admits Sessions only for
  // an authenticated principal. The adapter used to report that refusal as the daemon "not answering",
  // so the rail's Sessions skeleton spun forever; now that it is a typed refusal, the section would
  // simply read as empty. One row under the Sessions header says what is true, and where to go.
  let ioiSignedIn = null; // null unknown · "pending" · true · false — whoami is asked once per page load
  function updateSignedOutRail() {
    if (ioiSignedIn === null) {
      ioiSignedIn = "pending";
      fetch("/v1/hypervisor/auth/whoami", { credentials: "same-origin" })
        .then((r) => r.json())
        .then((w) => { ioiSignedIn = !(w && w.authenticated === false); updateSignedOutRail(); })
        .catch(() => { ioiSignedIn = true; }); // unknown: say nothing rather than guess
      return;
    }
    let row = document.getElementById("ioi-signedout-rail");
    if (ioiSignedIn !== false) { if (row) row.remove(); return; }
    const label = Array.prototype.find.call(document.querySelectorAll("span"), (e) => {
      if (e.children.length || e.textContent.trim() !== "Sessions") return false;
      const r = e.getBoundingClientRect(); return r.width > 0 && r.left < 320;
    });
    const header = label && label.closest("div.justify-between");
    if (!header) { if (row) row.remove(); return; }
    if (!row) {
      row = document.createElement("a");
      row.id = "ioi-signedout-rail";
      row.className = "ioi-openapp-rail";
      row.setAttribute("href", "/__ioi/login");
      row.setAttribute("target", "_top");
      row.innerHTML = '<span class="ioi-oar-ico">🔒</span><span class="ioi-oar-txt"><span class="ioi-oar-l">Signed out</span><span class="ioi-oar-n">Sign in to see and start Sessions</span></span>';
    }
    if (row.previousElementSibling !== header) header.insertAdjacentElement("afterend", row);
  }
  // Organization settings are read for a signed-in administrator; the bundle draws a REFUSED read as
  // an EMPTY one — signed out, Sessions said "It's quiet here · there are no environments in your
  // organization" over a daemon holding dozens (R-240). The layout says what is true above the pane.
  // A FILTER OVER A REFUSED LIST IS A DEAD CONTROL (R-240, the M6b+c census): signed out, the Sessions
  // pane still offered live project / environment / status filters — populated from reads that answer
  // anyone — over a list the daemon refused, so choosing one moved nothing. While signed out the pane's
  // filters are disabled with a reason that says why and what to do; signing in restores them.
  const SIGNEDOUT_FILTER_ATTR = "data-ioi-signedout-filter";
  const SIGNEDOUT_FILTER_REASON = "Sign in to filter: the daemon lists organization settings only to a signed-in administrator, so there is nothing here to filter yet";
  function releaseSignedOutFilters() {
    Array.prototype.forEach.call(document.querySelectorAll("[" + SIGNEDOUT_FILTER_ATTR + "]"), (s) => {
      s.disabled = false; s.removeAttribute("aria-disabled"); s.removeAttribute("data-ioi-disabled-reason"); s.removeAttribute("title"); s.removeAttribute(SIGNEDOUT_FILTER_ATTR);
    });
  }
  function holdSignedOutFilters(main) {
    Array.prototype.forEach.call(main.querySelectorAll("select"), (s) => {
      if (s.getAttribute(SIGNEDOUT_FILTER_ATTR) === "1" && s.disabled) return;
      s.disabled = true; s.setAttribute("aria-disabled", "true"); s.setAttribute("title", SIGNEDOUT_FILTER_REASON);
      s.setAttribute("data-ioi-disabled-reason", SIGNEDOUT_FILTER_REASON); s.setAttribute(SIGNEDOUT_FILTER_ATTR, "1");
    });
  }
  function updateSignedOutSettings() {
    let bar = document.getElementById("ioi-signedout-settings");
    const main = /^\/settings(\/|$)/.test(location.pathname) ? document.querySelector("main") : null;
    if (ioiSignedIn !== false || !main) { if (bar) bar.remove(); releaseSignedOutFilters(); return; }
    holdSignedOutFilters(main);
    if (!bar) {
      bar = document.createElement("div");
      bar.id = "ioi-signedout-settings";
      bar.setAttribute("role", "status");
      bar.style.cssText = "margin:0 0 16px;padding:10px 14px;border:1px solid rgba(209,152,11,.5);border-radius:8px;background:rgba(209,152,11,.08);color:inherit;font-size:13px;line-height:1.5";
    }
    const next = encodeURIComponent(location.pathname + location.search);
    if (bar.getAttribute("data-next") !== next) { // rewrite only on a route change — every write re-fires the observer
      bar.setAttribute("data-next", next);
      bar.innerHTML = "<b>Signed out.</b> The daemon shows organization settings only to a signed-in administrator, so an empty list on this page is not an empty organization. " +
        '<a href="/__ioi/login?next=' + next + '" target="_top" style="text-decoration:underline">Sign in</a>';
    }
    if (main.firstElementChild !== bar) main.insertBefore(bar, main.firstElementChild);
  }
  // The account menu, signed out (R-240). The bundle draws it for a signed-in member whatever the
  // session says: an empty name header with a user-settings gear, "Organizations" with a blank "?"
  // row carrying a checkmark, "Join or create an organization", and "Log out" — which signs nobody
  // out, because nobody is signed in — directly under a rail that says SIGNED OUT. A signed-out
  // visitor belongs to no organization and has no account to open, so the menu says that, and its
  // last item is the way in. Patched as the menu mounts, so the member's version never flashes.
  const SIGNIN_ITEM_ATTR = "data-ioi-signin";
  function signInHref() { return "/__ioi/login?next=" + encodeURIComponent(location.pathname + location.search + location.hash); }
  function updateSignedOutAccountMenu() {
    if (ioiSignedIn !== false) return;
    const menu = Array.prototype.find.call(document.querySelectorAll('[role="menu"][data-radix-menu-content]'), (m) =>
      m.querySelector('[data-tracking-id="org-switcher-user-settings"]') || Array.prototype.some.call(m.querySelectorAll('[role="menuitem"]'), (i) => i.textContent.trim() === "Log out"));
    if (!menu || menu.getAttribute("data-ioi-signedout") === "1") return;
    menu.setAttribute("data-ioi-signedout", "1");
    const gear = menu.querySelector('[data-tracking-id="org-switcher-user-settings"]');
    const header = gear ? gear.parentElement : null;
    if (header) {
      const note = document.createElement("div");
      note.id = "ioi-signedout-menu-head";
      note.style.cssText = "display:flex;flex-direction:column;gap:2px;padding:2px 0";
      note.innerHTML = '<span style="font-weight:600">Signed out</span><span style="font-size:12px;opacity:.7">Sign in to see your account and organization</span>';
      header.replaceChildren(note);
    }
    // "Organizations", the organization row and "Join or create an organization" — nothing a signed-out
    // visitor is a member of or can act on.
    for (const el of Array.prototype.slice.call(menu.children)) {
      const isLabel = !el.getAttribute("role") && el.textContent.trim() === "Organizations";
      const isOrgRow = el.getAttribute("role") === "menuitem" && (el.hasAttribute("aria-current") || /organization/i.test(el.getAttribute("aria-label") || ""));
      if (isLabel || isOrgRow) el.style.display = "none";
    }
    const logout = Array.prototype.find.call(menu.querySelectorAll('[role="menuitem"]'), (i) => i.textContent.trim() === "Log out");
    if (logout) {
      logout.setAttribute(SIGNIN_ITEM_ATTR, "1");
      const label = Array.prototype.find.call(logout.querySelectorAll("*"), (e) => !e.children.length && e.textContent.trim() === "Log out");
      if (label) label.textContent = "Sign in"; else logout.textContent = "Sign in";
    }
    // The separator the hidden organization block leaves doubled.
    const seps = menu.querySelectorAll(':scope > [role="separator"]');
    if (seps.length > 1) seps[0].style.display = "none";
  }
  // The item keeps the bundle's menu semantics (focus, keyboard) but its action is navigation: every
  // event Radix would select on is taken before the bundle sees it.
  ["pointerdown", "pointerup", "click"].forEach((type) => document.addEventListener(type, (e) => {
    const item = e.target && e.target.closest && e.target.closest("[" + SIGNIN_ITEM_ATTR + "]");
    if (!item) return;
    e.preventDefault(); e.stopImmediatePropagation();
    if (type === "click") window.top.location.assign(signInHref());
  }, true));
  document.addEventListener("keydown", (e) => {
    if ((e.key !== "Enter" && e.key !== " ") || !document.activeElement || !document.activeElement.closest("[" + SIGNIN_ITEM_ATTR + "]")) return;
    e.preventDefault(); e.stopImmediatePropagation();
    window.top.location.assign(signInHref());
  }, true);
  new MutationObserver(() => updateSignedOutAccountMenu()).observe(document.documentElement, { childList: true, subtree: true });
  // /projects?new=1 opens New project (R-240). Other surfaces' "+ New" for a project point here, and
  // the bundle's create dialog has no address of its own; the page's own button is pressed once and
  // the parameter dropped, so Back and a reload do not reopen it.
  let ioiNewProjectOpened = false;
  function openNewProjectFromUrl() {
    if (ioiNewProjectOpened || location.pathname !== "/projects" || new URLSearchParams(location.search).get("new") !== "1") return;
    const btn = document.querySelector('[data-tracking-id="new-project-projects-page"]');
    if (!btn) return;
    ioiNewProjectOpened = true;
    const u = new URL(location.href); u.searchParams.delete("new");
    history.replaceState(history.state, "", u.pathname + u.search + u.hash);
    btn.click();
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
      el.innerHTML = '<div class="ioi-oa-bar"><span class="ioi-oa-title"></span><button class="ioi-oa-close" title="Close">Close ✕</button></div><iframe title="application"></iframe><div class="ioi-oa-loading" role="status" aria-live="polite"><span class="ioi-oa-spin" aria-hidden="true"></span><span class="ioi-oa-loadtext">Loading…</span></div>';
      document.body.appendChild(el);
      el.querySelector(".ioi-oa-close").addEventListener("click", closeApplication);
      // THE LOADING STATE (R-240): an application page reads its planes before it answers — measured
      // 2–8s for the Solution Designer — and the slot showed an empty dark rectangle meanwhile. It
      // says it is loading until the frame's document has arrived.
      el.querySelector("iframe").addEventListener("load", () => { if (el.querySelector("iframe").getAttribute("src")) el.classList.remove("ioi-oa-busy"); });
    }
    el.querySelector(".ioi-oa-title").textContent = title || "Application";
    el.setAttribute("data-app-name", title || "Application");
    el.setAttribute("data-app-icon", appIconFor(title));
    const f = el.querySelector("iframe");
    const src = embeddedAppSrc(href);
    if (f.getAttribute("src") !== src) {
      el.querySelector(".ioi-oa-loadtext").textContent = "Loading " + (title || "the application") + "…";
      el.classList.add("ioi-oa-busy");
      f.setAttribute("src", src); // singular slot: reuse, replace src (no reload if same href)
    }
    el.style.display = "block";
    positionOpenApp();
    updateOpenAppRail();
  }
  function appsModalRows() {
    // Everything below renders the ONE compiled product-surface projection (W0.2) — the
    // applications + workspaces bands are daemon registration records; the ported band is the
    // demoted evidence lane (implementation evidence, zero catalog authority).
    const compiledRow = (s) => {
      // GRE-2 (owner ruling 2026-08-20): CONTAINER-FIRST — the platform session rail is the ONE
      // rail, so applications open in the embedded container. The seeded canonical routes now
      // serve raw railless documents (family landings / tagged 302s to the designated shells),
      // which embed cleanly. Top navigation is reserved for the SPA shell itself (/ai) — the one
      // target that cannot nest.
      const target = (s.open_today && s.open_today.href) || (s.launchable ? (s.launch_route || s.route) : "") || "";
      const pill = s.launchable ? "open" : esc((s.disabled_reason_codes || [])[0] || "not launchable");
      const top = (target === "/ai" || target === "/projects") ? ' data-nav="top"' : ""; // /projects IS the shell — embedding it nests the SPA into itself (blank frame; stage-2 sweep find)
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
      // IT IS A DIALOG (R-240): it covers the page and takes every click, yet it carried no dialog
      // role, so a screen reader never heard it open and Esc did not close it.
      el.setAttribute("role", "dialog");
      el.setAttribute("aria-modal", "true");
      el.setAttribute("aria-label", "Applications");
      document.body.appendChild(el);
      document.addEventListener("keydown", (e) => {
        if (e.key === "Escape" && el.classList.contains("open")) { e.preventDefault(); e.stopPropagation(); el.classList.remove("open"); }
      }, true);
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
