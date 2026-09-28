  // ---- Home explorer + New Session composer identities (03-home port · 02-new-session). ----
  // THE Home (rail Home, /ai with no hash) is an owned EXPLORER ported from the reference
  // command-home grammar — welcome / get-started / governed work / recents / applications — built
  // from the SPA's own design tokens over live daemon truth. The SPA's polished composer page keeps
  // its UX but under its TRUE identity: New Session, at /ai#new-session (the rail's create-session
  // button and Ctrl+O land there; an Advanced-launch affordance opens the owned governed modal —
  // one daemon-backed launch lane, no forked truth). The explorer owns no truth: every affordance
  // routes to the owning surface, missing projections are named, nothing is fabricated.
  let hbData = null, hbFetchedAt = 0, hbInflight = false, hbTab = "sessions", hbTrailing = null;
  function hbFetch() {
    if (hbInflight) return;
    // A request inside the 15 s window is deferred to its end, never dropped: the page is event-driven, so a dropped
    // request (the sidebar losing a deleted session) left Home's Recent stale until some unrelated DOM change. The
    // deferred fetch runs only while Home is on screen.
    const wait = 15000 - (Date.now() - hbFetchedAt);
    if (wait > 0) {
      if (!hbTrailing) hbTrailing = setTimeout(() => { hbTrailing = null; const r = document.getElementById("ioi-home-explorer"); if (r && r.isConnected && r.style.display !== "none") hbFetch(); }, wait);
      return;
    }
    hbInflight = true;
    const J = (p) => fetch(p).then((r) => r.json()).catch(() => null);
    // Recent sessions read what the sidebar reads — the shell's own session list (environments) and agent runs — so
    // Home and the sidebar cannot disagree. It read the daemon's harness-session records: raw `session:ai-agent_…`
    // refs, only sessions an agent run had bound, "No sessions yet" beside a sidebar listing two (R-240 Arm A).
    const RPC = (m, b) => fetch("/api/ioi.v1." + m, { method: "POST", headers: { "content-type": "application/json", "connect-protocol-version": "1" }, body: JSON.stringify(b || {}) })
      .then((r) => (r.ok ? r.json() : null)).catch(() => null);
    Promise.all([
      J("/v1/hypervisor/governance/approval-requests"),
      J("/v1/hypervisor/failover/runs"),
      J("/v1/hypervisor/operations"),
      J("/v1/hypervisor/work-ledger"),
      RPC("EnvironmentService/ListEnvironments", { filter: { archivalStatus: "ARCHIVAL_STATUS_ACTIVE" } }),
      J("/v1/hypervisor/projects"),
      J("/v1/hypervisor/auth/whoami"),
      RPC("AgentService/ListAgentExecutions", {}),
    ]).then(([appr, fo, ops, led, envs, proj, who, agents]) => {
      const sess = envs ? { environments: envs.environments || [], agentExecutions: (agents && agents.agentExecutions) || [] } : null;
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
    if (!sess) return '<div class="px-1 text-sm text-content-tertiary" style="padding:14px 4px">Projection unavailable — the daemon did not answer.</div>';
    const whenOf = (e) => String((e.metadata && (e.metadata.lastStartedAt || e.metadata.createdAt)) || "");
    const sessions = sess.environments.slice().sort((a, b) => whenOf(b).localeCompare(whenOf(a)));
    const projectName = (id) => { const p = (proj ? proj.projects || [] : []).find((x) => (x.project_id || x.id) === id); return p ? p.name || id : id || ""; };
    const latestRun = (envId) => sess.agentExecutions.filter((x) => x.spec && x.spec.codeContext && x.spec.codeContext.environmentId === envId)
      .sort((a, b) => String((b.metadata && b.metadata.updatedAt) || "").localeCompare(String((a.metadata && a.metadata.updatedAt) || "")))[0];
    const ago = (iso) => { const t = Date.parse(iso); if (!t) return ""; const m = Math.max(0, Math.round((Date.now() - t) / 60000)); return m < 1 ? "just now" : m < 60 ? m + "m ago" : m < 1440 ? Math.round(m / 60) + "h ago" : Math.round(m / 1440) + "d ago"; };
    const PHASE = { ENVIRONMENT_PHASE_RUNNING: "Running", ENVIRONMENT_PHASE_STARTING: "Starting", ENVIRONMENT_PHASE_STOPPING: "Stopping", ENVIRONMENT_PHASE_STOPPED: "Stopped", ENVIRONMENT_PHASE_CREATING: "Creating", ENVIRONMENT_PHASE_DELETING: "Deleting" };
    const rows = sessions.slice(0, 8).map((e) => {
      const envId = String(e.id || "");
      const run = latestRun(envId);
      const project = projectName(e.metadata && e.metadata.projectId);
      const title = (run && run.metadata && run.metadata.name) || project || "Session";
      return hbListRow('<a href="/details/' + encodeURIComponent(envId) + '" class="text-content-primary" style="text-decoration:none">' + esc(title) + "</a>",
        esc([title === project ? "" : project, ago(whenOf(e))].filter(Boolean).join(" · ")),
        hbPill(PHASE[e.status && e.status.phase] || "—", "border-border-base text-content-secondary") +
        // "workbench" opens the session view — the ported session landing (M13.4). It linked
        // /workspaces/<env>, a route this shell does not have: every recent session's workbench link
        // opened "This page doesn't exist" (R-240, found by check:dead-controls' shell leg).
        (envId ? ' <a href="/details/' + encodeURIComponent(envId) + '" class="text-content-secondary hover:text-content-primary" style="text-decoration:none">workbench</a> <a href="/__ioi/run-timeline/env/' + encodeURIComponent(envId) + '" target="_blank" rel="noopener" class="text-content-secondary hover:text-content-primary" style="text-decoration:none">timeline ↗</a>' : ""));
    });
    return rows.length ? rows.join("") : '<div class="px-1 text-sm text-content-tertiary" style="padding:14px 4px">No sessions yet — start one and resume it from here.</div>';
  }
  function renderExplorer() {
    const root = document.getElementById("ioi-home-explorer");
    if (!root) return;
    if (!hbData) { root.innerHTML = '<div class="px-1 text-sm text-content-tertiary" style="padding:24px 4px">Loading daemon truth…</div>'; return; }
    const { appr, fo, ops, led, who } = hbData;
    // Only a signed-in principal is greeted by name — whoami's authenticated:false display principal
    // is the deployment's placeholder, not the visitor (R-240).
    const name = who && who.authenticated === true && who.principal && who.principal.name ? String(who.principal.name).split(" ")[0] : "";
    const { rows: govRows, pend, parked, fails } = hbGovernedRows();
    const ledN = led ? (led.entries || []).length : null;
    const allNull = !appr && !fo && !ops && !led;
    const summary = allNull ? "" :
      '<span>' + (parked ? parked.length : "?") + " blocked</span><span aria-hidden=\"true\"> · </span><span>" + (pend ? pend.length : "?") + " waiting on you</span><span aria-hidden=\"true\"> · </span><span>" + (ledN === null ? "?" : ledN) + " receipts</span>";
    const tabChip = (key, label) =>
      // A tab says it is one, and which is current — without role/aria-selected neither assistive
      // technology nor check:dead-controls could tell the current tab from a control that did nothing.
      '<button role="tab" aria-selected="' + (hbTab === key ? "true" : "false") + '" data-hb-tab="' + key + '" class="rounded-full border text-xs ' + (hbTab === key ? "border-border-strong text-content-primary bg-surface-hover" : "border-border-base text-content-secondary") + '" style="padding:3px 12px;background:' + (hbTab === key ? "" : "transparent") + ';cursor:pointer">' + label + "</button>";
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
    // W0.2: the estate grid renders the compiled product-surface projection (owner applications
    // + substrate lane) — daemon registration records via 35-app-catalog.js, never a hand list.
    const apps = compiledApps().map((a) => {
      const href = (a.open_today && a.open_today.href) || (a.launchable ? (a.launch_route || a.route) : "") || "";
      const reason = a.launchable ? "" : (a.disabled_reason_codes || []).join(", ") || "not launchable";
      return '<a href="' + (href || "#applications") + '" title="' + esc(a.route + (reason ? " — " + reason : "")) + '" class="flex items-center gap-3 rounded-xl border border-border-base bg-surface-secondary px-4 py-3 transition-colors hover:bg-surface-hover" style="text-decoration:none' + (a.launchable || href ? "" : ";opacity:.55") + '">' +
        '<span aria-hidden="true" style="font-size:17px">' + (a.icon || "◳") + "</span>" +
        '<span class="flex min-w-0 flex-col"><span class="truncate text-sm font-medium text-content-primary">' + esc(a.name) + "</span>" +
        '<span class="truncate text-xs text-content-tertiary">' + esc(a.desc || a.route || "") + "</span></span></a>";
    }).join("");
    const appsBand = apps ||
      '<div class="px-1 text-sm text-content-tertiary" style="padding:14px 4px">Compiled product-surface projection not loaded — no catalog is shown rather than a stale hand list.</div>';
    const appsDown = compiledApps().length && !compiledDaemonOk()
      ? '<div class="px-1 text-xs text-content-tertiary" style="margin:8px 0 0">Daemon unavailable (' + esc(compiledDaemonCode()) + ') — static first-party inventory; launch state unknown.</div>'
      : "";
    // Ported application surfaces (app-catalog projection) render ahead of the family tiles;
    // data-ioi-app carries the display title for the Open-Application interceptor.
    const portedApps = catalogApps().map((a) =>
      '<a href="' + a.route + '" data-ioi-app="' + esc(a.title) + '" class="flex items-center gap-3 rounded-xl border border-border-base bg-surface-secondary px-4 py-3 transition-colors hover:bg-surface-hover" style="text-decoration:none">' +
      '<span aria-hidden="true" class="shrink-0">' + catalogIcon(a, 20) + "</span>" +
      '<span class="flex min-w-0 flex-col"><span class="truncate text-sm font-medium text-content-primary">' + esc(a.title) + "</span>" +
      '<span class="truncate text-xs text-content-tertiary">' + esc(a.family) + "</span></span></a>").join("");
    root.innerHTML = '<div style="max-width:66rem;margin:0 auto;padding:40px 28px 64px">' +
      '<h1 class="text-2xl font-semibold text-content-primary" style="letter-spacing:-.2px">Welcome back' + (name ? ", " + esc(name) : "") + "</h1>" +
      '<div class="text-sm text-content-tertiary" style="margin-top:4px">' + (summary || "&nbsp;") + "</div>" +
      '<div class="flex gap-3" style="margin-top:22px;flex-wrap:wrap">' +
      hbActCard('href="/ai#new-session" data-hb-act="new-session"', "✳", "New Session", "Describe a task; launch a governed session") +
      hbActCard('href="#applications"', "◳", "Applications", "Open any surface in the estate") +
      hbActCard('href="/automations"', "⟳", "Automations", "Recurring governed work on the daemon") +
      "</div>" +
      hbSection("Governed work", '<a href="/__ioi/home" class="text-xs text-content-secondary hover:text-content-primary" style="text-decoration:none">Full readout →</a>') + gov +
      hbSection("Recent", '<span class="flex items-center gap-2" role="tablist" aria-label="Recent">' + tabChip("sessions", "Sessions") + tabChip("projects", "Projects") + tabChip("runs", "Runs") + "</span>") +
      '<div id="ioi-hb-recent">' + hbRecentBody() + "</div>" +
      hbSection("Applications", '<a href="#applications" class="text-xs text-content-secondary hover:text-content-primary" style="text-decoration:none">View all →</a>') +
      (portedApps
        ? '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:10px">' + portedApps + "</div>" +
          '<div class="px-1 text-xs text-content-tertiary" style="margin:14px 0 8px">Owner applications + substrate (compiled projection)</div>'
        : "") +
      '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:10px">' + appsBand + "</div>" + appsDown +
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
  // R-192 (S5-1): a two-step Goal-activation act stood here — draft the daemon-derived crossing,
  // review it, then explicitly confirm admission, with its own wallet-authority challenge lane.
  // It drove the GoalRun activation plane, which is gone: goal runs are ioi.ai compositions over
  // the Hypervisor's thread orchestration primitives, not Hypervisor objects. The composer stays
  // Session-first, which is what it always was; nothing here turns a session into a pursuit.
  // R-240 Arm A on Sessions: the composer's submit is the shell's OWN (AgentService/CreateAgentSession, with the project,
  // environment class and mode the composer chose). An intercept used to rebind it, only to skip the vendor's payment
  // verification, and sent the prompt alone — every session was filed under no project and Plan reached the harness
  // as an Agent turn. The payment check needs no skipping (a self-hosted deployment's billing answers verified), so
  // nothing here touches the submit.
  // Advanced-launch affordance on the New Session composer view — opens the owned governed modal
  // (registry-fed harness/model with disabled-reasons, venue picker, placement preview) so the
  // full admitted lane stays one click away from the polished composer. The "Activate Goal"
  // button that stood beside it retired with the GoalRun activation plane (R-192, S5-1); no
  // affordance here turns a session into a pursuit.
  function mountAdvancedLaunch(contents) {
    if (document.getElementById("ioi-ns-advanced")) return;
    const wrap = document.createElement("div");
    wrap.id = "ioi-ns-advanced-wrap";
    wrap.className = "w-full";
    wrap.style.cssText = "display:flex;flex-direction:column;align-items:center;margin-top:10px";
    wrap.innerHTML = '<div class="flex items-center justify-center gap-2"><button id="ioi-ns-advanced" type="button" class="text-xs text-content-tertiary hover:text-content-primary" style="background:transparent;border:0;cursor:pointer;padding:6px 10px">Advanced launch — harness · venue · placement preview</button></div><div id="ioi-session-panel" class="w-full" role="status" aria-live="polite" style="display:none;max-width:720px;margin-top:10px"></div>';
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
