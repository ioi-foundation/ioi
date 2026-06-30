// WS-I / WS-F — injected IOI-native surface (the IOI-native cockpit panel + owned Run Timeline).
//
// The seeded reference cockpit has no slot for IOI-native objects (operator authority, environment
// lifecycle/isolation posture + services/tasks/ports, the WorkRun patch branch + its
// model-driven turns, the scoped terminal, receipts). This vanilla script mounts an IOI-native
// panel beside the cockpit (same mechanism as the brand boot-guard) that reads AND drives the
// daemon via /api/ioi/*. It owns no truth — the daemon is the source.
//
// CANONICAL OWNERSHIP: Hypervisor owns its conversation surface. On the workbench we REPLACE the
// seeded transcript in-pane with our Run Timeline (mounted as an iframe to /__ioi/run-timeline,
// the owned governed-work surface), keeping the native composer so follow-ups still post through
// the adapter. This is the one place we deliberately edit the seeded SPA's DOM (the transcript region of
// [data-testid=environment-agent-execution-conversation]); everything else stays hands-off.
//
// Boundary: daemon EXECUTES · wallet AUTHORIZES crossings · agentgres RECORDS (receipts).
(function () {
  if (window.__ioiAugmentationMounted) return;
  window.__ioiAugmentationMounted = true;

  // ---- Owned Run Timeline as the default workbench transcript (replaces the seeded pane) ----
  const CONV_SEL = '[data-testid="environment-agent-execution-conversation"]';
  const runGate = {}; // envId -> { has, at } — throttled "does this env have a run yet" check
  function envHasRun(envId) {
    const g = runGate[envId];
    const now = Date.now();
    if (!g || now - g.at >= 5000) {
      runGate[envId] = { has: g ? g.has : false, at: now };
      fetch("/__ioi/env-latest-run/" + encodeURIComponent(envId))
        .then((r) => r.json())
        .then((d) => { runGate[envId] = { has: !!(d && d.runId), at: Date.now() }; })
        .catch(() => {});
    }
    return runGate[envId].has;
  }
  function mountTimelineInWorkbench() {
    const m = location.pathname.match(/\/details\/([^/?#]+)/);
    const C = document.querySelector(CONV_SEL);
    if (!m || !C) return;
    // Only take over the pane once the env actually has a run — otherwise leave the native composer
    // so the user can start one (the owned follow-up composer needs an existing run to post to).
    if (!envHasRun(m[1])) return;
    const want = "/__ioi/run-timeline/env/" + encodeURIComponent(m[1]) + "?embed=1";
    let frame = C.querySelector("#ioi-timeline-frame");
    if (!frame) {
      frame = document.createElement("iframe");
      frame.id = "ioi-timeline-frame";
      frame.title = "Run Timeline";
      frame.setAttribute("src", want);
      frame.style.cssText = "flex:1 1 auto;width:100%;min-height:0;border:0;background:transparent;";
      if (!getComputedStyle(C).display.includes("flex")) C.style.display = "flex";
      C.style.flexDirection = "column";
      C.appendChild(frame);
    } else if (frame.getAttribute("src") !== want) {
      frame.setAttribute("src", want); // env changed (SPA nav) → repoint
    }
    // Full replacement: hide ALL seeded pane children (transcript + the SPA's empty-state hero +
    // its composer), leaving only our owned timeline. The owned surface carries its own follow-up
    // composer, so it owns the whole conversation (transcript + send). Re-applied each tick because
    // React re-creates these children on its own renders.
    Array.prototype.forEach.call(C.children, function (ch) {
      ch.style.display = ch === frame ? "" : "none";
    });
  }

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
  const IOI_APPS = [
    { icon: "🧰", name: "Workbench", desc: "Code editor, terminal, ports & tasks.", status: "contextual" },
    { icon: "🖥", name: "Environments", desc: "Lifecycle, readiness, services/ports/tasks, substrate posture.", href: "/__ioi/environments", status: "live" },
    { icon: "🧪", name: "Agent Studio", desc: "Author, tune, and evaluate agents.", status: "planned" },
    { icon: "🏗", name: "Foundry", desc: "Build and publish models and tools.", status: "planned" },
    { icon: "📦", name: "ODK", desc: "Operational data kits and recipes.", status: "planned" },
    { icon: "🧩", name: "Domain Apps", desc: "Vertical app surfaces.", status: "planned" },
    { icon: "🔌", name: "Developer & Integrations", desc: "Connectors, MCP, credentials, dev tools.", href: "/__ioi/connections", status: "live" },
    { icon: "🛡", name: "Governance", desc: "Permissions, controls, release gates.", status: "planned" },
    { icon: "⚙", name: "Operations", desc: "Execution health — scheduler, runs, failures, webhooks.", href: "/__ioi/operations", status: "live" },
    { icon: "📒", name: "Work Ledger", desc: "Runs, receipts, state roots, timelines.", href: "/__ioi/work-ledger", status: "live" },
    { icon: "🛒", name: "Marketplace", desc: "Apps, training, walkthroughs.", status: "planned" },
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
        // Applications launcher (rail #applications, the SPA's native launcher attr, or the estate deep-link) → MODAL.
        if (t.closest('a[href="#applications"], [data-hypervisor-applications-launcher], a[href="/__ioi/applications"]')) {
          e.preventDefault(); e.stopPropagation(); appsModal(); return;
        }
        // Live application links → open IN-SHELL in the Open Application slot (left rail stays).
        const appLink = t.closest('a[href^="/__ioi/connections"], a[href^="/__ioi/work-ledger"], a[href^="/__ioi/operations"], a[href^="/__ioi/environments"]');
        if (appLink) {
          e.preventDefault(); e.stopPropagation();
          const href = appLink.getAttribute("href");
          const name = /work-ledger/.test(href) ? "Work Ledger" : /operations/.test(href) ? "Operations" : /environments/.test(href) ? "Environments" : "Developer & Integrations";
          openApplication(href, name);
          return;
        }
        // Any other left-rail nav (Home/Projects/Automations) → close the open app, let the SPA navigate.
        if (t.closest('[data-testid="sidebar"] a')) closeApplication();
      },
      true, // capture — beat the SPA's native (empty) Applications modal + client router
    );
  }

  let activeEnvId = null;
  let lastExec = null;

  const isDark = () =>
    document.documentElement.classList.contains("dark") ||
    matchMedia("(prefers-color-scheme: dark)").matches;

  const css = `
  #ioi-aug-btn{position:fixed;right:14px;bottom:14px;z-index:2147483646;font:600 12px system-ui,sans-serif;
    padding:7px 12px;border-radius:8px;cursor:pointer;border:1px solid;}
  #ioi-aug-panel{position:fixed;right:14px;bottom:52px;z-index:2147483646;width:380px;max-height:78vh;overflow:auto;
    border-radius:10px;border:1px solid;box-shadow:0 8px 30px rgba(0,0,0,.35);font:12px/1.5 system-ui,sans-serif;display:none;}
  #ioi-aug-panel.open{display:block;}
  #ioi-aug-panel h3{margin:0;padding:10px 12px;font-size:13px;border-bottom:1px solid;}
  #ioi-aug-panel section{padding:10px 12px;border-bottom:1px solid;}
  #ioi-aug-panel .k{opacity:.65;} #ioi-aug-panel .row{display:flex;justify-content:space-between;gap:8px;align-items:center;}
  #ioi-aug-panel .pill{display:inline-block;padding:1px 7px;border-radius:999px;font-size:11px;border:1px solid;white-space:nowrap;}
  #ioi-aug-panel code{font-size:11px;word-break:break-all;}
  #ioi-aug-panel button.act{cursor:pointer;border-radius:6px;border:1px solid;padding:2px 8px;font:600 11px system-ui;background:transparent;color:inherit;}
  #ioi-aug-panel input.cmd{flex:1;border-radius:6px;border:1px solid;padding:4px 8px;font:12px ui-monospace,monospace;background:transparent;color:inherit;}
  #ioi-aug-panel pre.term{margin:6px 0 0;padding:8px;border-radius:6px;border:1px solid;max-height:160px;overflow:auto;
    font:11px/1.45 ui-monospace,monospace;white-space:pre-wrap;word-break:break-all;}
  #ioi-aug-panel .mini{font-size:11px;}
  /* Applications: in-shell "Open Application" slot (right of the rail) + the modal launcher. */
  #ioi-open-app{position:fixed;top:0;right:0;bottom:0;left:0;z-index:2147483600;display:none;background:#0c0d10;}
  #ioi-open-app .ioi-oa-bar{height:40px;display:flex;align-items:center;justify-content:space-between;padding:0 14px;background:#15171c;border-bottom:1px solid #2a2c33;color:#e6e7ea;font:600 13px system-ui,sans-serif;}
  #ioi-open-app .ioi-oa-close{background:transparent;border:1px solid #2a2c33;color:#cbd0da;border-radius:6px;cursor:pointer;padding:3px 10px;font:inherit;}
  #ioi-open-app .ioi-oa-close:hover{color:#fff;border-color:#3a3d45;}
  #ioi-open-app iframe{width:100%;height:calc(100% - 40px);border:0;background:#0c0d10;display:block;}
  #ioi-apps-modal{position:fixed;inset:0;z-index:2147483640;display:none;align-items:flex-start;justify-content:center;background:rgba(0,0,0,.55);}
  #ioi-apps-modal.open{display:flex;}
  #ioi-apps-modal .ioi-modal{margin-top:8vh;width:560px;max-width:92vw;max-height:80vh;overflow:auto;background:#101216;border:1px solid #24262d;border-radius:14px;box-shadow:0 20px 60px rgba(0,0,0,.5);font:13px/1.5 system-ui,sans-serif;color:#e6e7ea;}
  #ioi-apps-modal .ioi-mh{display:flex;align-items:center;justify-content:space-between;padding:14px 18px;border-bottom:1px solid #24262d;font-weight:600;font-size:15px;color:#fff;}
  #ioi-apps-modal .ioi-mh button{background:transparent;border:1px solid #2a2c33;color:#cbd0da;border-radius:6px;cursor:pointer;padding:3px 10px;font:inherit;}
  #ioi-apps-modal .ioi-mrow{display:flex;align-items:center;gap:12px;padding:12px 18px;border-bottom:1px solid #1b1d23;cursor:pointer;}
  #ioi-apps-modal .ioi-mrow.disabled{opacity:.5;cursor:default;}
  #ioi-apps-modal .ioi-mrow:not(.disabled):hover{background:#15171c;}
  #ioi-apps-modal .ioi-mname{font-weight:600;color:#fff;}
  #ioi-apps-modal .ioi-mdesc{color:#878a93;font-size:12px;}
  #ioi-apps-modal .ioi-mpill{margin-left:auto;font-size:11px;border:1px solid #2a2c33;border-radius:999px;padding:1px 9px;color:#9a9da6;white-space:nowrap;}
  /* Active "Open Application" rail row (one only; no pinned region). */
  .ioi-openapp-rail{display:flex;align-items:center;gap:8px;margin:2px 8px;padding:6px 10px;border-radius:8px;background:#15315c;border:1px solid #3a82f6;color:#fff;text-decoration:none;font:600 12px system-ui,sans-serif;cursor:pointer;}
  .ioi-openapp-rail .ioi-oar-ico{flex:0 0 auto;font-size:14px;}
  .ioi-openapp-rail .ioi-oar-txt{display:flex;flex-direction:column;min-width:0;flex:1;line-height:1.25;}
  .ioi-openapp-rail .ioi-oar-l{font-size:9px;text-transform:uppercase;letter-spacing:.06em;opacity:.65;font-weight:600;}
  .ioi-openapp-rail .ioi-oar-n{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
  .ioi-openapp-rail .ioi-oar-x{flex:0 0 auto;background:transparent;border:0;color:#cbd0da;cursor:pointer;font:inherit;padding:0 2px;}
  .ioi-openapp-rail .ioi-oar-x:hover{color:#fff;}
  `;
  const theme = () =>
    isDark()
      ? { bg: "#161515", fg: "#fafafa", line: "#333", accent: "#5e8afd", btnBg: "#1f1f1f", term: "#0d0d0d" }
      : { bg: "#ffffff", fg: "#1f1f1f", line: "#e1e1e1", accent: "#2f69fd", btnBg: "#fafafa", term: "#f4f4f4" };

  function style() {
    const t = theme();
    let s = document.getElementById("ioi-aug-style");
    if (!s) {
      s = document.createElement("style");
      s.id = "ioi-aug-style";
      document.head.appendChild(s);
    }
    s.textContent =
      css +
      `#ioi-aug-btn{background:${t.btnBg};color:${t.fg};border-color:${t.line};}
       #ioi-aug-panel{background:${t.bg};color:${t.fg};border-color:${t.line};}
       #ioi-aug-panel h3,#ioi-aug-panel section{border-color:${t.line};}
       #ioi-aug-panel .pill,#ioi-aug-panel button.act,#ioi-aug-panel input.cmd{border-color:${t.line};}
       #ioi-aug-panel pre.term{border-color:${t.line};background:${t.term};}
       #ioi-aug-panel .accent{color:${t.accent};}`;
  }

  const get = (p) => fetch(p).then((r) => r.json()).catch((e) => ({ error: String(e) }));
  const post = (p, b) =>
    fetch(p, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(b || {}) })
      .then((r) => r.json())
      .catch((e) => ({ error: String(e) }));
  const esc = (s) => String(s == null ? "" : s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));

  function pickActiveEnv(envs) {
    // Prefer the environment the user is actually viewing (/details/:envId) so the panel + the Run
    // Timeline launcher target the env in view, not just the latest running one.
    const m = location.pathname.match(/\/details\/([^/?#]+)/);
    if (m) { const urlEnv = envs.find((e) => e.id === m[1]); if (urlEnv) return urlEnv.id; }
    const running = envs.filter((e) => e.status?.phase === "running");
    return (running[running.length - 1] || envs[envs.length - 1] || null)?.id || null;
  }

  function chips(list, label) {
    if (!list || !list.length) return `<span class="k mini">no ${label}</span>`;
    return list
      .map((x) => `<span class="pill mini">${esc(x.name || x.port || x)}${x.phase ? " · " + esc(x.phase) : ""}</span>`)
      .join(" ");
  }

  async function render(panel) {
    const [auth, envs, wrs, rcpt, inc] = await Promise.all([
      get("/api/ioi/authority/posture"),
      get("/api/ioi/environments"),
      get("/api/ioi/workruns"),
      get("/api/ioi/receipts"),
      get("/api/ioi/incidents"),
    ]);
    const envList = envs.environments || [];
    const wrList = wrs.workRuns || [];
    const receipts = rcpt.receipts || rcpt.items || (Array.isArray(rcpt) ? rcpt : []);
    const incidents = inc.incidents || [];
    activeEnvId = pickActiveEnv(envList);
    const active = envList.find((e) => e.id === activeEnvId);
    const st = active?.status || {};

    // WS-12 — component-phase grid + readiness + monitor (Phase 1 daemon truth).
    const COMP = ["recipe", "provisioner", "workspace_content", "sandbox", "resource_isolation", "connectivity", "secrets", "automations", "agent_work", "model_mount", "harness"];
    const compDot = (p) => ({ ready: "●", running: "●", creating: "◐", initializing: "◐", degraded: "◑", recovering: "◑", failed: "✕", pending: "○" }[p] || "○");
    const compGrid = (status) =>
      COMP.map((c) => {
        const p = status.components?.[c]?.phase || "pending";
        return `<span class="pill mini" title="${c}: ${p}">${compDot(p)} ${esc(c.replace(/_/g, " ").slice(0, 10))}</span>`;
      }).join(" ");
    const readinessMode = st.readiness?.mode || "-";

    const envSummary = envList
      .slice(-4)
      .map(
        (e) =>
          `<div class="row"><code>${esc(e.id)}</code><span class="pill accent">${esc(e.status?.phase)}</span></div>`
      )
      .join("") || "<span class='k mini'>none</span>";

    const activeBlock = active
      ? `<div class="row"><span class="k">active env</span><code>${esc(active.id)}</code></div>
         <div class="row"><span class="k">readiness</span><span class="pill accent">${esc(readinessMode)}</span></div>
         <div class="row"><span class="k">isolation</span><span class="mini">${esc(st.isolation_claim || "-")}${st.vm?.monitor ? " · " + esc(st.vm.monitor) : ""}</span></div>
         <div style="margin-top:6px"><span class="k mini">components</span><div style="margin-top:3px;line-height:1.8">${compGrid(st)}</div></div>
         <div style="margin-top:6px"><span class="k mini">services </span>${chips(st.services, "services")}</div>
         <div style="margin-top:3px"><span class="k mini">tasks </span>${chips(st.tasks, "tasks")}</div>
         <div style="margin-top:3px"><span class="k mini">ports </span>${chips(st.ports, "ports")}</div>
         <div class="row" style="margin-top:8px"><span class="k mini">run timeline</span>
           <a class="act" href="/__ioi/run-timeline/env/${esc(active.id)}" target="_blank" rel="noopener" style="text-decoration:none">↗ Open Run Timeline</a></div>`
      : "<span class='k mini'>no running environment</span>";

    const recoveryBlock =
      incidents
        .slice(-3)
        .map(
          (i) =>
            `<div class="row mini"><code>${esc(i.failure_kind)}</code><span class="pill">${esc(i.status)}</span></div>`
        )
        .join("") || "<span class='k mini'>no incidents</span>";

    const termOut = lastExec
      ? `<pre class="term">${esc(lastExec)}</pre>`
      : `<pre class="term k">scoped to the active env workspace · local.exec (no wallet crossing)</pre>`;

    const wrBlock =
      wrList
        .slice(-4)
        .map((w) => {
          const turns = (w.turns || []).length;
          const last = (w.turns || [])[turns - 1];
          return `<div class="row"><code>${esc(w.branch)}</code><span class="pill mini">${w.host_mutation ? "host!" : "scoped"}</span></div>
            <div class="row mini"><span class="k">${esc(w.review_state || w.status || "-")} · ${turns} turn${turns === 1 ? "" : "s"}${
            last ? " · " + esc(last.model_route || "") : ""
          }</span><button class="act" data-act="turn" data-id="${esc(w.id)}">▶ turn</button></div>${
            last ? `<div class="k mini" style="margin:2px 0 6px">${esc((last.output_preview || "").slice(0, 90))}</div>` : ""
          }`;
        })
        .join("") || "<span class='k mini'>none</span>";

    panel.innerHTML = `
      <h3>IOI Runtime <span class="k" style="font-weight:400">(daemon truth)</span></h3>
      <section>
        <div class="row"><span class="k">authority</span><span class="accent">${esc(auth.mode || auth.error || "?")}</span></div>
        <div class="row"><span class="k">wallet.network</span><span class="mini">${auth.wallet_network_live ? "live" : "represented (not live)"}</span></div>
      </section>
      <section>
        <div class="k" style="margin-bottom:6px">Environments</div>${envSummary}
        <div style="margin-top:8px">${activeBlock}</div>
      </section>
      <section>
        <div class="row"><span class="k">Terminal <span class="mini">(scoped exec)</span></span></div>
        <div class="row" style="margin-top:6px">
          <input class="cmd" id="ioi-aug-cmd" placeholder="${activeEnvId ? "command in workspace…" : "start an environment first"}" ${
      activeEnvId ? "" : "disabled"
    }/>
          <button class="act" data-act="exec" ${activeEnvId ? "" : "disabled"}>Run</button>
        </div>${termOut}
      </section>
      <section>
        <div class="row"><span class="k">WorkRuns <span class="mini">(patch branches · model turns)</span></span>
          <button class="act" data-act="newwr" ${activeEnvId ? "" : "disabled"}>＋ WorkRun</button></div>
        <div style="margin-top:6px">${wrBlock}</div>
      </section>
      <section>
        <div class="row"><span class="k">Recovery <span class="mini">(provider failure incidents)</span></span><span class="pill">${incidents.length}</span></div>
        <div style="margin-top:6px">${recoveryBlock}</div>
      </section>
      <section><div class="row"><span class="k">Receipts / replay</span><span class="pill">${receipts.length}</span></div>
        <div class="k mini" style="margin-top:4px">agentgres-recorded; model invocations replayable</div></section>`;
  }

  async function runExec(panel) {
    const input = panel.querySelector("#ioi-aug-cmd");
    const cmd = (input?.value || "").trim();
    if (!cmd || !activeEnvId) return;
    lastExec = "… running";
    const out = panel.querySelector("pre.term");
    if (out) out.textContent = lastExec;
    const r = await post("/api/ioi/exec", { environment_id: activeEnvId, command: cmd });
    lastExec = r.error
      ? "error: " + r.error
      : `$ ${cmd}\n${r.stdout || ""}${r.stderr ? "\n" + r.stderr : ""}\n[exit ${r.exit_code}] (${r.authority || ""})`;
    if (out) out.textContent = lastExec;
  }

  // ---- Automations are PROJECT-FIRST and owned: route the top-nav "Automations" to the owned
  // surface (the SPA's org-scoped WorkflowService page is not canonical), and show a project's
  // automations on its detail page with a create entry that pre-fills the project. ----------------
  function wireAutomationsNav() {
    if (window.__ioiAutomationsNavWired) return;
    window.__ioiAutomationsNavWired = true;
    document.addEventListener(
      "click",
      (e) => {
        const a = e.target && e.target.closest && e.target.closest('a[href="/automations"]');
        if (!a || a.classList.contains("ioi-connections-nav")) return; // not our Connections clone
        e.preventDefault();
        e.stopPropagation();
        window.location.assign("/__ioi/automations");
      },
      true, // capture — beat the SPA router
    );
  }

  let projectAutoFor = null;
  async function mountProjectAutomations() {
    const panelId = "ioi-project-automations";
    const m = location.pathname.match(/^\/projects\/([^/?#]+)$/); // project detail (not /projects)
    if (!m) {
      const ex = document.getElementById(panelId);
      if (ex) ex.remove();
      projectAutoFor = null;
      return;
    }
    const projectId = decodeURIComponent(m[1]);
    if (projectAutoFor === projectId && document.getElementById(panelId)) return; // already mounted
    projectAutoFor = projectId;
    const data = await get("/__ioi/automations.json?project=" + encodeURIComponent(projectId));
    if (projectAutoFor !== projectId) return; // navigated away mid-fetch
    const t = theme();
    let el = document.getElementById(panelId);
    if (!el) {
      el = document.createElement("div");
      el.id = panelId;
      document.body.appendChild(el);
    }
    el.setAttribute(
      "style",
      `position:fixed;left:14px;bottom:14px;z-index:2147483646;width:300px;max-height:60vh;overflow:auto;background:${t.bg};color:${t.fg};border:1px solid ${t.line};border-radius:10px;box-shadow:0 8px 30px rgba(0,0,0,.35);font:12px/1.5 system-ui,sans-serif`,
    );
    const list = (data.automations || [])
      .map(
        (a) =>
          `<div style="display:flex;justify-content:space-between;gap:8px;padding:7px 12px;border-top:1px solid ${t.line}"><a href="/__ioi/automations/${encodeURIComponent(a.automation_id)}" style="color:${t.accent};text-decoration:none;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(a.name || a.automation_id)}</a><span style="opacity:.6;white-space:nowrap">${a.enabled ? "on" : "off"}</span></div>`,
      )
      .join("") || `<div style="padding:10px 12px;opacity:.6">No automations yet.</div>`;
    el.innerHTML =
      `<div style="display:flex;justify-content:space-between;align-items:center;padding:9px 12px;font-weight:600"><span>⚙ Project automations</span><a href="/__ioi/automations?project=${encodeURIComponent(projectId)}" style="color:${t.accent};text-decoration:none;font-size:11px">open →</a></div>` +
      list +
      // Footer: create an automation + jump to this project's Work Ledger (the proof stream scoped
      // to this project) — closes the loop Project → Automations → Runs → Ledger → Timeline.
      `<div style="display:flex;justify-content:space-between;align-items:center;gap:8px;padding:9px 12px;border-top:1px solid ${t.line}"><a href="/__ioi/automations/new?project=${encodeURIComponent(projectId)}" style="display:inline-block;padding:6px 12px;border-radius:7px;background:${t.accent};color:#fff;text-decoration:none;font-weight:600">+ New automation</a><a href="/__ioi/work-ledger?project=${encodeURIComponent(projectId)}" style="color:${t.accent};text-decoration:none;font-size:11px;white-space:nowrap">📒 Work Ledger →</a></div>`;
  }

  // Route-scoped, idempotent wiring. Runs on DOM mutations (debounced) + SPA route changes — NOT on
  // a fixed 700ms poll — so it costs nothing when the shell is idle. Each affordance is guarded to
  // the route where its controls exist; all are idempotent (existence/route checks), so re-applying
  // on a re-render never duplicates or leaks.
  function applyAugmentation() {
    const p = location.pathname;
    if (/\/details\//.test(p)) mountTimelineInWorkbench(); // workbench timeline only on /details/*
    mountProjectAutomations(); // self-guards /projects/:id + self-removes its panel off-route
    if (/\/settings\//.test(p)) { mountGitAppButton(); wireIntegrationConnect(); } // settings only
    updateOpenAppRail(); // reflect the Open Application slot state in the rail
  }
  function mount() {
    style();
    matchMedia("(prefers-color-scheme: dark)").addEventListener?.("change", style);
    // One-time, self-guarded installers: demote the old rail item + the click interceptors.
    removeConnectionsNav();
    wireApplicationsLauncher();
    wireAutomationsNav();
    // Event-driven apply: a debounced MutationObserver + SPA route hooks replace the old polling loops.
    let pending = null;
    const schedule = () => { if (pending) return; pending = setTimeout(() => { pending = null; applyAugmentation(); }, 250); };
    new MutationObserver(schedule).observe(document.body, { childList: true, subtree: true });
    ["pushState", "replaceState"].forEach((m) => {
      const orig = history[m];
      if (typeof orig === "function") history[m] = function () { const r = orig.apply(this, arguments); schedule(); return r; };
    });
    window.addEventListener("popstate", schedule);
    applyAugmentation(); // initial
  }

  if (document.body) mount();
  else document.addEventListener("DOMContentLoaded", mount);
})();
