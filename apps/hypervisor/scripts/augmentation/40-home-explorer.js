  // ---- Home explorer + New Session composer identities (03-home port · 02-new-session). ----
  // THE Home (rail Home, /ai with no hash) is an owned EXPLORER ported from the reference
  // command-home grammar — welcome / get-started / governed work / recents / applications — built
  // from the SPA's own design tokens over live daemon truth. The SPA's polished composer page keeps
  // its UX but under its TRUE identity: New Session, at /ai#new-session (the rail's create-session
  // button and Ctrl+O land there; an Advanced-launch affordance opens the owned governed modal —
  // one daemon-backed launch lane, no forked truth). The explorer owns no truth: every affordance
  // routes to the owning surface, missing projections are named, nothing is fabricated.
  let hbData = null, hbFetchedAt = 0, hbInflight = false, hbTab = "sessions";
  function hbFetch() {
    if (hbInflight || Date.now() - hbFetchedAt < 15000) return;
    hbInflight = true;
    const J = (p) => fetch(p).then((r) => r.json()).catch(() => null);
    Promise.all([
      J("/v1/hypervisor/governance/approval-requests"),
      J("/v1/hypervisor/failover/runs"),
      J("/v1/hypervisor/operations"),
      J("/v1/hypervisor/work-ledger"),
      J("/v1/hypervisor/sessions"),
      J("/v1/hypervisor/projects"),
      J("/v1/hypervisor/auth/whoami"),
    ]).then(([appr, fo, ops, led, sess, proj, who]) => {
      hbData = { appr, fo, ops, led, sess, proj, who };
      hbFetchedAt = Date.now();
      hbInflight = false;
      renderExplorer();
    });
  }
  function hbRow(href, appName, icon, title, meta, pill, pillCls) {
    return '<a href="' + href + '" data-app="' + esc(appName) + '" class="ioi-hb-row flex items-center justify-between gap-3 rounded-xl border border-border-base bg-surface-secondary px-4 py-3 text-left transition-colors hover:bg-surface-hover" style="text-decoration:none">' +
      '<span class="flex min-w-0 items-center gap-3">' +
      '<span class="shrink-0" aria-hidden="true">' + icon + "</span>" +
      '<span class="flex min-w-0 flex-col">' +
      '<span class="truncate text-sm font-medium text-content-primary">' + title + "</span>" +
      (meta ? '<span class="truncate text-xs text-content-tertiary">' + meta + "</span>" : "") +
      "</span></span>" +
      '<span class="flex shrink-0 items-center gap-2">' +
      (pill ? '<span class="rounded-full border ' + pillCls + ' text-xs whitespace-nowrap" style="padding:2px 10px">' + pill + "</span>" : "") +
      '<span class="text-content-muted" aria-hidden="true">→</span>' +
      "</span></a>";
  }
  const hbSection = (title, right) =>
    '<div class="mb-2 flex items-center justify-between px-1" style="margin-top:28px">' +
    '<span class="text-xs font-medium uppercase tracking-wide text-content-tertiary">' + title + "</span>" + (right || "") + "</div>";
  function hbGovernedRows() {
    const { appr, fo, ops } = hbData || {};
    const pend = appr ? (appr.approval_requests || []).filter((a) => a.status === "pending") : null;
    const parked = fo ? (fo.runs || []).filter((r) => String(r.status || "").startsWith("awaiting_authority")) : null;
    const fails = ops ? ((ops.runs || {}).failures || []) : null;
    const rows = [];
    (pend || []).slice(0, 3).forEach((a) => rows.push(hbRow("/__ioi/governance?tab=approvals", "Governance", "🛡",
      "Approval waiting — " + esc(a.request_kind || "approval"), esc(a.subject_ref || ""),
      "pending", "border-border-warning bg-surface-warning-subtle text-content-warning")));
    (parked || []).slice(0, 3).forEach((r) => rows.push(hbRow("/__ioi/operations", "Operations", "⛔",
      "Failover parked at the wallet gate — " + esc(String(r.status).replace("awaiting_authority_", "")),
      esc((r.failure_condition || "run") + " · " + (r.environment_ref || "")),
      "blocked", "border-border-warning bg-surface-warning-subtle text-content-warning")));
    (fails || []).slice(0, 2).forEach((r) => rows.push(hbRow("/__ioi/operations", "Operations", "✖",
      "Run failed — " + esc(r.name || r.automation_id || ""), esc((r.project_id || "—") + " · " + (r.finished_at || "")),
      "failed", "border-border-error bg-surface-destructive-subtle text-content-destructive")));
    return { rows, pend, parked, fails };
  }
  // A get-started action card (the reference home's onboarding strip, re-aimed at real IOI acts).
  const hbActCard = (attrs, icon, title, sub) =>
    "<a " + attrs + ' class="flex flex-1 min-w-0 items-center gap-3 rounded-xl border border-border-base bg-surface-secondary px-4 py-3 transition-colors hover:bg-surface-hover" style="text-decoration:none;cursor:pointer">' +
    '<span class="shrink-0" aria-hidden="true" style="font-size:18px">' + icon + "</span>" +
    '<span class="flex min-w-0 flex-col"><span class="truncate text-sm font-medium text-content-primary">' + title + "</span>" +
    '<span class="truncate text-xs text-content-tertiary">' + sub + "</span></span></a>";
  const hbListRow = (main, meta, right) =>
    '<div class="flex items-center justify-between gap-3 px-1" style="padding-top:9px;padding-bottom:9px;border-bottom:1px solid var(--ioi-hb-line, rgba(128,128,128,.14))">' +
    '<span class="flex min-w-0 flex-col"><span class="truncate text-sm text-content-primary">' + main + "</span>" +
    (meta ? '<span class="truncate text-xs text-content-tertiary">' + meta + "</span>" : "") + "</span>" +
    '<span class="flex shrink-0 items-center gap-2 text-xs">' + (right || "") + "</span></div>";
  const hbPill = (txt, cls) => '<span class="rounded-full border ' + cls + ' text-xs whitespace-nowrap" style="padding:1px 9px">' + esc(txt) + "</span>";
  function hbRecentBody() {
    const { sess, proj, ops } = hbData || {};
    if (hbTab === "projects") {
      const rows = (proj ? proj.projects || [] : []).slice(0, 8).map((p) =>
        hbListRow('<a href="/projects/' + encodeURIComponent(p.project_id || p.id || "") + '" class="text-content-primary" style="text-decoration:none">' + esc(p.name || p.project_id || p.id || "project") + "</a>",
          esc(p.project_id || p.id || ""), ""));
      if (proj === null || proj === undefined) return '<div class="px-1 text-sm text-content-tertiary" style="padding:14px 4px">Projection unavailable — the daemon did not answer.</div>';
      return rows.length ? rows.join("") : '<div class="px-1 text-sm text-content-tertiary" style="padding:14px 4px">No projects yet — start a session in a new project and it will appear here.</div>';
    }
    if (hbTab === "runs") {
      const recent = ops ? ((ops.runs || {}).recent || []) : null;
      if (recent === null) return '<div class="px-1 text-sm text-content-tertiary" style="padding:14px 4px">Projection unavailable — the daemon did not answer.</div>';
      const rows = recent.slice(0, 8).map((r) => hbListRow(esc(r.name || r.automation_id || "run"),
        esc((r.project_id || "—") + " · " + (r.started_at || "")),
        hbPill(r.status || "—", r.status === "done" ? "border-border-success bg-surface-success-subtle text-content-positive" : r.status === "failed" ? "border-border-error bg-surface-destructive-subtle text-content-destructive" : "border-border-base text-content-secondary") +
        (r.timeline_ref ? ' <a href="' + r.timeline_ref + '" target="_blank" rel="noopener" class="text-content-secondary hover:text-content-primary" style="text-decoration:none">timeline ↗</a>' : "")));
      return rows.length ? rows.join("") : '<div class="px-1 text-sm text-content-tertiary" style="padding:14px 4px">No runs yet — governed work lands here with its receipts.</div>';
    }
    const sessions = sess ? (sess.sessions || []).slice().sort((a, b) => String(b.created_at || "").localeCompare(String(a.created_at || ""))) : null;
    if (sessions === null) return '<div class="px-1 text-sm text-content-tertiary" style="padding:14px 4px">Projection unavailable — the daemon did not answer.</div>';
    const rows = sessions.slice(0, 8).map((s) => {
      const envId = String(s.environment_ref || "").replace(/^environment:/, "");
      return hbListRow('<span class="font-mono" style="font-size:12.5px">' + esc(s.session_ref || "") + "</span>",
        esc((s.project_ref || "no project") + " · " + (s.created_at || "")),
        hbPill(s.lifecycle_state || "—", "border-border-base text-content-secondary") +
        (envId ? ' <a href="/workspaces/' + encodeURIComponent(envId) + '" class="text-content-secondary hover:text-content-primary" style="text-decoration:none">developer workspace</a> <a href="/__ioi/run-timeline/env/' + encodeURIComponent(envId) + '" target="_blank" rel="noopener" class="text-content-secondary hover:text-content-primary" style="text-decoration:none">timeline ↗</a>' : ""));
    });
    return rows.length ? rows.join("") : '<div class="px-1 text-sm text-content-tertiary" style="padding:14px 4px">No sessions yet — start one and resume it from here.</div>';
  }
  function renderExplorer() {
    const root = document.getElementById("ioi-home-explorer");
    if (!root) return;
    if (!hbData) { root.innerHTML = '<div class="px-1 text-sm text-content-tertiary" style="padding:24px 4px">Loading daemon truth…</div>'; return; }
    const { appr, fo, ops, led, who } = hbData;
    const name = who && who.principal && who.principal.name ? String(who.principal.name).split(" ")[0] : "";
    const { rows: govRows, pend, parked, fails } = hbGovernedRows();
    const ledN = led ? (led.entries || []).length : null;
    const allNull = !appr && !fo && !ops && !led;
    const summary = allNull ? "" :
      '<span>' + (parked ? parked.length : "?") + " blocked</span><span aria-hidden=\"true\"> · </span><span>" + (pend ? pend.length : "?") + " waiting on you</span><span aria-hidden=\"true\"> · </span><span>" + (ledN === null ? "?" : ledN) + " receipts</span>";
    const tabChip = (key, label) =>
      '<button data-hb-tab="' + key + '" class="rounded-full border text-xs ' + (hbTab === key ? "border-border-strong text-content-primary bg-surface-hover" : "border-border-base text-content-secondary") + '" style="padding:3px 12px;background:' + (hbTab === key ? "" : "transparent") + ';cursor:pointer">' + label + "</button>";
    let gov;
    if (allNull) {
      gov = '<div class="rounded-xl border border-border-warning bg-surface-warning-subtle px-4 py-3 text-sm text-content-warning">Daemon unreachable — governed-work status unavailable. Nothing is shown rather than fixtures.</div>';
    } else if (!govRows.length) {
      gov = '<div class="flex items-center justify-between gap-3 rounded-xl border border-border-base bg-surface-secondary px-4 py-3">' +
        '<span class="flex items-center gap-3"><span class="text-content-positive" aria-hidden="true">●</span>' +
        '<span class="text-sm text-content-secondary">All clear — nothing blocked, nothing waiting on you.</span></span></div>';
    } else {
      gov = '<div class="flex flex-col gap-2">' + govRows.join("") + "</div>" +
        ([appr, fo, ops, led].some((x) => !x) ? '<div class="mt-2 px-1 text-xs text-content-tertiary">Some projections did not answer — this view may be incomplete.</div>' : "");
    }
    const applicationCard = (entry) =>
      '<a href="' + entry.launch_route + '" data-ioi-app="' + esc(entry.name) + '" class="flex items-center gap-3 rounded-xl border border-border-base bg-surface-secondary px-4 py-3 transition-colors hover:bg-surface-hover" style="text-decoration:none">' +
      '<span aria-hidden="true" style="font-size:17px">' + entry.icon + "</span>" +
      '<span class="flex min-w-0 flex-col"><span class="truncate text-sm font-medium text-content-primary">' + esc(entry.name) + "</span>" +
      '<span class="truncate text-xs text-content-tertiary">' + esc(entry.description) + "</span></span></a>";
    const apps = catalogOwnerApplications().filter((entry) => entry.launchable).map(applicationCard).join("");
    const substrateApps = catalogSubstrateApplications().filter((entry) => entry.launchable).map(applicationCard).join("");
    // Contextual tools and Work views are independently discoverable without becoming peer apps.
    // data-ioi-app carries the product title for the Open-Application interceptor.
    const contextual = catalogContextSurfaces().map((entry) =>
      '<a href="' + entry.launch_route + '" data-ioi-app="' + esc(entry.title) + '" class="flex items-center gap-3 rounded-xl border border-border-base bg-surface-secondary px-4 py-3 transition-colors hover:bg-surface-hover" style="text-decoration:none">' +
      '<span aria-hidden="true" class="shrink-0">' + catalogIcon(entry, 20) + "</span>" +
      '<span class="flex min-w-0 flex-col"><span class="truncate text-sm font-medium text-content-primary">' + esc(entry.title) + "</span>" +
      '<span class="truncate text-xs text-content-tertiary">' + esc(entry.placement) + "</span></span></a>").join("");
    root.innerHTML = '<div style="max-width:66rem;margin:0 auto;padding:40px 28px 64px">' +
      '<h1 class="text-2xl font-semibold text-content-primary" style="letter-spacing:-.2px">Welcome back' + (name ? ", " + esc(name) : "") + "</h1>" +
      '<div class="text-sm text-content-tertiary" style="margin-top:4px">' + (summary || "&nbsp;") + "</div>" +
      '<div class="flex gap-3" style="margin-top:22px;flex-wrap:wrap">' +
      hbActCard('href="/ai#new-session" data-hb-act="new-session"', "✳", "New Session", "Describe a task; launch a governed session") +
      hbActCard('href="#applications"', "◳", "Applications", "Open any surface in the estate") +
      hbActCard('href="/automations"', "⟳", "Automations", "Recurring governed work on the daemon") +
      "</div>" +
      hbSection("Governed work", '<a href="/__ioi/home" class="text-xs text-content-secondary hover:text-content-primary" style="text-decoration:none">Full readout →</a>') + gov +
      hbSection("Recent", '<span class="flex items-center gap-2">' + tabChip("sessions", "Sessions") + tabChip("projects", "Projects") + tabChip("runs", "Runs") + "</span>") +
      '<div id="ioi-hb-recent">' + hbRecentBody() + "</div>" +
      hbSection("Applications", '<a href="#applications" class="text-xs text-content-secondary hover:text-content-primary" style="text-decoration:none">View all →</a>') +
      '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:10px">' + apps + "</div>" +
      (substrateApps
        ? '<div class="px-1 text-xs text-content-tertiary" style="margin:14px 0 8px">Substrate</div>' +
          '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:10px">' + substrateApps + "</div>"
        : "") +
      (contextual
        ? '<div class="px-1 text-xs text-content-tertiary" style="margin:14px 0 8px">Tools and views</div>' +
          '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:10px">' + contextual + "</div>"
        : "") +
      "</div>";
  }
  function goComposer() {
    if (location.pathname !== "/ai") { location.assign("/ai#new-session"); return; }
    if (location.hash !== "#new-session") history.replaceState(null, "", "/ai#new-session");
    applyAiViews();
    setTimeout(() => { const ta = document.querySelector('[data-testid="prompt-input-textarea"]'); if (ta) ta.focus(); }, 80);
  }
  function goHome() {
    if (location.pathname !== "/ai") { location.assign("/ai"); return; }
    if (location.hash) history.replaceState(null, "", "/ai");
    applyAiViews();
  }
  // Advanced-launch affordance on the New Session composer view — opens the owned governed modal
  // (registry-fed harness/model with disabled-reasons, venue picker, placement preview) so the
  // full admitted lane stays one click away from the polished composer.
  function mountAdvancedLaunch(contents) {
    if (document.getElementById("ioi-ns-advanced")) return;
    const wrap = document.createElement("div");
    wrap.id = "ioi-ns-advanced-wrap";
    wrap.className = "w-full";
    wrap.style.cssText = "display:flex;justify-content:center;margin-top:10px";
    wrap.innerHTML = '<button id="ioi-ns-advanced" type="button" class="text-xs text-content-tertiary hover:text-content-primary" style="background:transparent;border:0;cursor:pointer;padding:6px 10px">Advanced launch — harness · venue · placement preview</button>';
    contents.appendChild(wrap);
    wrap.querySelector("#ioi-ns-advanced").addEventListener("click", (e) => { e.preventDefault(); newSessionModal(); });
  }
  // View router for /ai: no hash → explorer Home (native composer hidden, state preserved);
  // #new-session → the native composer (New Session). Re-applied every tick because React
  // re-renders its own children (same contract as the workbench timeline takeover).
  function applyAiViews() {
    const pageEl = document.querySelector('[data-testid="ioi-ai-page"]');
    const contents = document.querySelector('[data-testid="ioi-ai-page-contents"]');
    if (!pageEl || !contents) return;
    // Toggle the page's DIRECT child that wraps the composer (hiding only the inner column would
    // leave its flex wrapper occupying half the row beside the explorer).
    let native = contents;
    while (native.parentElement && native.parentElement !== pageEl) native = native.parentElement;
    const composerMode = location.hash === "#new-session";
    let root = document.getElementById("ioi-home-explorer");
    if (composerMode) {
      if (root) root.style.display = "none";
      native.style.display = "";
      mountAdvancedLaunch(contents);
      return;
    }
    if (!root) {
      root = document.createElement("div");
      root.id = "ioi-home-explorer";
      root.setAttribute("data-testid", "ioi-home-explorer");
      root.style.cssText = "flex:1 1 auto;width:100%;overflow-y:auto";
      root.addEventListener("click", (e) => {
        const tab = e.target.closest && e.target.closest("[data-hb-tab]");
        if (tab) { hbTab = tab.getAttribute("data-hb-tab"); renderExplorer(); return; }
        const act = e.target.closest && e.target.closest('[data-hb-act="new-session"]');
        if (act) { e.preventDefault(); goComposer(); }
      });
      pageEl.appendChild(root);
      renderExplorer(); // paint loading/cached state immediately
    }
    root.style.display = "";
    native.style.display = "none";
    hbFetch();
  }
