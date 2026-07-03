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
  // ---- New Session launcher (02-new-session graft). The rail's create-session action opens an
  // OWNED modal: three intake branches (project / URL / scratch), registry-fed harness + model
  // controls where an unavailable option is DISABLED WITH ITS REASON (never hidden, never a
  // silent admission failure), and a launch preview naming the admission, receipts, isolation,
  // and restore path BEFORE the effectful call. Launch = daemon session create (harness selection
  // admitted before provisioning) + the capability-admitted knob binding.
  let nsCtx = null;
  function nsProfile() {
    const sel = document.getElementById("ioi-ns-harness");
    if (!sel || !sel.value || !nsCtx) return null;
    return (nsCtx.harness_profiles || []).find((p) => p.profile_ref === sel.value) || null;
  }
  function nsHarnessReason(p) {
    if (p.lifecycle_status !== "active") return "not enabled — run the admitted enable in Agent Studio";
    if (p.execution_wiring === "terminal_pty") return "terminal lane — not an execution binding target";
    if (p.execution_wiring !== "lane_a_host_spawn") return "adapter slot — execution wiring not built";
    if (p.runnability_state !== "runnable" && p.runnability_state !== "not_probed") return "not runnable on this host (" + p.runnability_state + ")";
    return "";
  }
  function nsRouteReason(r) {
    if (r.lifecycle !== "active") return "not enabled";
    if (r.availability !== "available") return "not available (" + (r.availability || "declared") + ")";
    return "";
  }
  function newSessionModal() {
    let el = document.getElementById("ioi-ns-modal");
    if (!el) {
      el = document.createElement("div");
      el.id = "ioi-ns-modal";
      el.innerHTML = '<div class="ioi-modal ioi-ns"><div class="ioi-mh"><span>New Session — IOI Agent</span><button title="Close">✕</button></div><div id="ioi-ns-body"><div class="ioi-ns-empty">Loading daemon context…</div></div></div>';
      document.body.appendChild(el);
      el.addEventListener("click", (e) => {
        if (e.target === el || e.target.closest(".ioi-mh button")) { el.classList.remove("open"); return; }
        const tab = e.target.closest("[data-ns-branch]");
        if (tab) { el.setAttribute("data-branch", tab.getAttribute("data-ns-branch")); renderNsPreview(); return; }
        if (e.target.closest("#ioi-ns-launch")) { nsLaunch(); return; }
        if (e.target.closest("#ioi-ns-retry")) { nsCtx = null; loadNsContext(); return; }
        if (e.target.closest('a[href^="/__ioi/"]')) { el.classList.remove("open"); } // handoff opens in-shell via the capture handler
      });
      el.addEventListener("change", (e) => {
        if (!e.target || !e.target.id) return;
        if (e.target.id === "ioi-ns-harness") { nsHarnessTouched = true; renderNsKnobs(); }
        if (e.target.id === "ioi-ns-strategy") nsStrategyTouched = true;
        if (e.target.id === "ioi-ns-policy") {
          // The policy sets the strategy default (still user-overridable afterwards).
          var pol = nsPolicy();
          var strat = document.getElementById("ioi-ns-strategy");
          if (pol && strat && pol.strategy_preference) { strat.value = pol.strategy_preference; }
          nsStrategyTouched = false;
        }
        if (e.target.id.indexOf("ioi-ns-") === 0) renderNsPreview();
      });
      el.addEventListener("input", (e) => { if (e.target && (e.target.id === "ioi-ns-url" || e.target.id === "ioi-ns-goal")) renderNsPreview(); });
    }
    if (!el.getAttribute("data-branch")) el.setAttribute("data-branch", "project");
    el.classList.add("open");
    loadNsContext();
  }
  function loadNsContext() {
    const body = document.getElementById("ioi-ns-body");
    if (nsCtx) { renderNs(); return; }
    fetch("/__ioi/api/new-session/context").then((r) => r.json()).then((ctx) => { nsCtx = ctx; renderNs(); }).catch(() => {
      if (body) body.innerHTML = '<div class="ioi-ns-empty">Context unavailable — the daemon did not answer. The launcher offers no fabricated options.<br><button id="ioi-ns-retry" class="ioi-ns-btn" style="margin-top:10px">Retry</button></div>';
    });
  }
  function renderNs() {
    const body = document.getElementById("ioi-ns-body");
    if (!body || !nsCtx) return;
    const projects = nsCtx.projects || [];
    const envs = nsCtx.environments || [];
    const profiles = nsCtx.harness_profiles || [];
    const routes = nsCtx.model_routes || [];
    const projOpts = projects.length
      ? projects.map((p) => '<option value="' + esc(p.project_id) + '">' + esc(p.name || p.project_id) + (p.repository_url ? " — " + esc(p.repository_url) : "") + "</option>").join("")
      : '<option value="">(no projects in the estate yet)</option>';
    const envOpts = ['<option value="">Fresh isolated workspace (daemon-provisioned)</option>']
      .concat(envs.map((e) => '<option value="' + esc(e.id) + '">' + esc(e.id) + " — provisioner " + esc(e.provisioner_phase) + ", workspace " + esc(e.workspace_phase) + "</option>")).join("");
    const hpOpts = ['<option value="">None — defer to execute-time default (no binding)</option>']
      .concat(profiles.map((p) => {
        const reason = nsHarnessReason(p);
        const label = (p.display_name || p.harness) + (p.default ? " · default" : "") + (reason ? " — " + reason : (p.runnability_state === "not_probed" ? " — runnability not probed yet" : " — runnable · lane A"));
        return '<option value="' + esc(p.profile_ref) + '"' + (reason ? " disabled" : "") + ">" + esc(label) + "</option>";
      })).join("");
    const mrOpts = routes.map((r) => {
      const reason = nsRouteReason(r);
      const label = (r.display_name || r.route_ref) + " · " + (r.model_id || "?") + (r.default_route ? " · default" : "") + (reason ? " — " + reason : " — available");
      return '<option value="' + esc(r.route_ref) + '"' + (reason ? " disabled" : "") + (r.default_route && !reason ? " selected" : "") + ">" + esc(label) + "</option>";
    }).join("");
    const editors = nsCtx.editor_targets || [];
    const etOpts = editors.map((t) => {
      const label = t.display_name + " — " + (t.openable ? (t.open_kind || "").replace(/_/g, " ") : ("unavailable" + (t.reason ? " · " + t.reason : "")));
      return '<option value="editor-target:' + esc(t.target_id) + '"' + (t.openable ? "" : " disabled") + (t.target_id === "workbench-native" ? " selected" : "") + ">" + esc(label) + "</option>";
    }).join("");
    body.innerHTML =
      '<div class="ioi-ns-field"><label>What should IOI Agent do?</label><textarea id="ioi-ns-goal" rows="2" placeholder="Describe the goal — IOI Agent will coordinate the work. Leave empty to only create a session."></textarea></div>' +
      '<div class="ioi-ns-grid" style="grid-template-columns:1fr 1fr">' +
      '<div class="ioi-ns-field"><label>Launch policy (saved preset)</label><select id="ioi-ns-policy">' +
      '<option value="">No policy — manual choices</option>' +
      (nsCtx.launch_policies || []).map(function (p) {
        return '<option value="' + esc(p.policy_ref) + '"' + (p.policy_id === "pol_auto_default" ? " selected" : "") + ">" + esc(p.display_name) + " — " + esc(p.strategy_preference) + (p.protected ? " · default" : "") + "</option>";
      }).join("") +
      "</select></div>" +
      '<div class="ioi-ns-field"><label>Execution strategy</label><select id="ioi-ns-strategy">' +
      '<option value="auto" selected>Auto — IOI Agent decides</option>' +
      '<option value="direct">Direct — one harness</option>' +
      '<option value="compare">Compare — multiple harnesses, reconciled</option>' +
      '<option value="private_local">Private local — local models and harnesses only</option>' +
      "</select></div>" +
      '<div class="ioi-ns-field"><label>On failure</label><select id="ioi-ns-failure"><option value="continue_partial" selected>Continue with explicit partial result</option><option value="block">Block and report</option></select></div>' +
      "</div>" +
      '<div class="ioi-ns-tabs"><button class="ioi-ns-tab" data-ns-branch="project">Start from project</button><button class="ioi-ns-tab" data-ns-branch="url">Start from URL</button><button class="ioi-ns-tab" data-ns-branch="scratch">Start from scratch</button></div>' +
      '<div class="ioi-ns-pane project"><div class="ioi-ns-field"><label>Project</label><select id="ioi-ns-project">' + projOpts + "</select></div></div>" +
      '<div class="ioi-ns-pane url"><div class="ioi-ns-field"><label>Repository / PR / issue URL</label><input id="ioi-ns-url" placeholder="https://…"></div></div>' +
      '<div class="ioi-ns-pane scratch"><div class="ioi-ns-field"><label>Workspace</label><select id="ioi-ns-env">' + envOpts + "</select></div></div>" +
      '<div class="ioi-ns-grid">' +
      '<div class="ioi-ns-field"><label>Preferred harness (advanced · daemon registry)</label><select id="ioi-ns-harness">' + hpOpts + "</select></div>" +
      '<div class="ioi-ns-field"><label>Model route (daemon registry)</label><select id="ioi-ns-model">' + mrOpts + "</select></div>" +
      '<div class="ioi-ns-field"><label>Editor target (daemon registry)</label><select id="ioi-ns-editor">' + etOpts + "</select></div>" +
      '<div class="ioi-ns-field"><label>Reasoning</label><select id="ioi-ns-reasoning"></select></div>' +
      '<div class="ioi-ns-field"><label>Speed</label><select id="ioi-ns-speed"></select></div>' +
      "</div>" +
      '<div class="ioi-ns-preview" id="ioi-ns-preview"></div>' +
      '<button class="ioi-ns-btn" id="ioi-ns-launch">Start with IOI Agent</button>' +
      '<div id="ioi-ns-result" style="display:none"></div>';
    // Preselect the registry default profile when it is actually selectable.
    const hp = document.getElementById("ioi-ns-harness");
    const def = profiles.find((p) => p.default && !nsHarnessReason(p));
    if (def) hp.value = def.profile_ref;
    nsHarnessTouched = false;
    renderNsKnobs();
  }
  function renderNsKnobs() {
    const p = nsProfile();
    const reasoning = document.getElementById("ioi-ns-reasoning");
    const speed = document.getElementById("ioi-ns-speed");
    const model = document.getElementById("ioi-ns-model");
    const fill = (sel, values, preferred) => {
      sel.innerHTML = (values || []).map((v) => '<option value="' + esc(v) + '"' + (v === preferred ? " selected" : "") + ">" + esc(v) + "</option>").join("");
      sel.disabled = !values || !values.length;
    };
    if (!p) {
      reasoning.innerHTML = '<option value="">(no harness binding)</option>'; reasoning.disabled = true;
      speed.innerHTML = '<option value="">(no harness binding)</option>'; speed.disabled = true;
      model.disabled = true;
    } else {
      // The knob options come from the REGISTRY capability matrix of the chosen harness —
      // no universal dropdown lies.
      fill(reasoning, p.reasoning, p.reasoning && p.reasoning.indexOf("medium") >= 0 ? "medium" : (p.reasoning || [])[0]);
      fill(speed, p.speed, p.speed && p.speed.indexOf("balanced") >= 0 ? "balanced" : (p.speed || [])[0]);
      model.disabled = false;
    }
    renderNsPreview();
  }
  var nsPreviewTimer = null;
  var nsPreviewSeq = 0;
  // The preferred-harness select auto-preselects the registry default for the legacy
  // create-session path; that is NOT a user preference for IOI Agent (it would silently
  // force direct-native and starve Auto/Compare). Only an explicit user selection counts.
  var nsHarnessTouched = false;
  // Strategy is sent only when the user explicitly picked one — otherwise the selected
  // policy's preference (or auto) decides daemon-side.
  var nsStrategyTouched = false;
  function nsPolicy() {
    var sel = document.getElementById("ioi-ns-policy");
    if (!sel || !sel.value) return null;
    return (nsCtx.launch_policies || []).find(function (p) { return p.policy_ref === sel.value; }) || null;
  }
  function nsGoal() { var g = document.getElementById("ioi-ns-goal"); return g ? g.value.trim() : ""; }
  function nsStrategy() { var sel = document.getElementById("ioi-ns-strategy"); return sel && sel.value ? sel.value : "auto"; }
  function renderNsAgentPreview() {
    // Daemon-backed IOI Agent preview — the plan (direct vs internal coordination), eligible/
    // excluded harnesses with reasons, isolation and receipt classes. Never fabricated locally.
    var box = document.getElementById("ioi-ns-preview");
    if (!box) return;
    var seq = ++nsPreviewSeq;
    var payload = { goal: nsGoal() };
    if (nsStrategyTouched) payload.strategy = nsStrategy();
    var pol = nsPolicy();
    if (pol) payload.policy_ref = pol.policy_ref;
    var routeSel = document.getElementById("ioi-ns-model");
    if (routeSel && routeSel.value) payload.model_route_ref = routeSel.value;
    var hp = nsProfile();
    if (nsHarnessTouched && hp) payload.preferred_harness_refs = [hp.profile_ref];
    fetch("/__ioi/api/ioi-agent/preview", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload) })
      .then(function (r) { return r.json(); })
      .then(function (j) {
        if (seq !== nsPreviewSeq) return;
        if (j.error) { box.innerHTML = '<span class="nsp-k nsp-warn">Preview</span> <span class="nsp-warn">' + esc(j.error.code || "unavailable") + (j.error.message ? " — " + esc(j.error.message) : "") + "</span>"; return; }
        var lines = [];
        lines.push('<span class="nsp-k">IOI Agent</span> <b>' + esc(j.coordination || "IOI Agent will coordinate this work") + "</b>");
        if (j.policy_effective_summary) lines.push('<span class="nsp-k">Policy</span> ' + esc(j.policy_effective_summary) + ((j.policy_constraints_applied || []).length ? ' <span style="color:#6f7280">(applies: ' + esc(j.policy_constraints_applied.join(", ")) + ")</span>" : "") + ((j.policy_constraints_relaxed_or_blocked || []).length ? ' <span class="nsp-warn">relaxed: ' + esc(j.policy_constraints_relaxed_or_blocked.join(", ")) + "</span>" : ""));
        lines.push('<span class="nsp-k">Plan</span> strategy <b>' + esc(j.strategy) + "</b> → " + (j.planned_execution_kind === "goal_run" ? "<b>compare across harnesses, verified and reconciled</b>" : "<b>direct — one admitted harness</b>") + ' <span style="color:#6f7280">(' + esc((j.reason_codes || []).join(", ")) + ")</span>");
        lines.push('<span class="nsp-k">Harnesses</span> ' + (j.eligible_harnesses || []).map(function (r) { return "<code>" + esc(String(r).replace("harness-profile:hp_", "")) + "</code>"; }).join(" ") + ((j.excluded_harnesses || []).length ? ' · excluded: ' + j.excluded_harnesses.map(function (x) { return '<span class="nsp-warn">' + esc(x.harness || x.profile_ref || "") + " (" + esc(x.reason_code || "") + ")</span>"; }).join(", ") : ""));
        lines.push('<span class="nsp-k">Model route</span> <code>' + esc(j.model_route_ref || "") + "</code> · " + esc(j.model_route_state || ""));
        if (j.remote_slots_disabled) lines.push('<span class="nsp-k">Privacy</span> private local — remote/provider-gated slots disabled');
        var intel = j.intelligence_projection_preview;
        if (intel && intel.counts) {
          var aff = intel.automation_affinity_match;
          lines.push('<span class="nsp-k">Intelligence</span> memory space <code>' + esc((j.memory_space_refs || [])[0] || "") + '</code> — ' + intel.counts.included_entries + ' entr' + (intel.counts.included_entries === 1 ? "y" : "ies") + ' + ' + intel.counts.included_skills + ' skill' + (intel.counts.included_skills === 1 ? "" : "s") + ' projected · ' + intel.counts.redacted + ' redacted · ' + intel.counts.excluded + ' excluded' + ((intel.connector_context_refs || []).length ? ' · connector context: ' + intel.connector_context_refs.length + ' ref(s)' : ' · no connector context') + (aff ? ' · affinity: <b>' + esc(aff.title || "") + '</b>' : ""));
        }
        lines.push('<span class="nsp-k">Isolation</span> ' + esc(j.expected_isolation || ""));
        lines.push('<span class="nsp-k">Receipts</span> ' + (j.expected_receipt_refs || []).map(function (r) { return "<code>" + esc(r) + "</code>"; }).join(" "));
        lines.push('<span class="nsp-k">Admission</span> ' + esc(((j.admission_preview || {}).kinds || []).join(" · ")) + " — " + esc((j.admission_preview || {}).authority || ""));
        box.innerHTML = lines.join("<br>");
      })
      .catch(function () { if (seq === nsPreviewSeq) box.innerHTML = '<span class="nsp-k nsp-warn">Preview</span> <span class="nsp-warn">daemon unavailable</span>'; });
  }
  function renderNsPreview() {
    const box = document.getElementById("ioi-ns-preview");
    const el = document.getElementById("ioi-ns-modal");
    if (!box || !el) return;
    if (nsGoal().length >= 4) {
      // IOI Agent path: the preview is DAEMON truth (debounced).
      if (nsPreviewTimer) clearTimeout(nsPreviewTimer);
      box.innerHTML = '<span class="nsp-k">IOI Agent</span> planning…';
      nsPreviewTimer = setTimeout(renderNsAgentPreview, 250);
      return;
    }
    const branch = el.getAttribute("data-branch") || "project";
    const p = nsProfile();
    const routeSel = document.getElementById("ioi-ns-model");
    const route = (nsCtx.model_routes || []).find((r) => r.route_ref === (routeSel && routeSel.value));
    const lines = [];
    const intake = branch === "project"
      ? "project " + ((document.getElementById("ioi-ns-project") || {}).value || "(none selected)")
      : branch === "url"
        ? "context URL " + (((document.getElementById("ioi-ns-url") || {}).value || "").trim() || "(none entered)")
        : ((document.getElementById("ioi-ns-env") || {}).value ? "bound environment " + document.getElementById("ioi-ns-env").value + " (session shares its workspace)" : "fresh isolated workspace");
    lines.push('<span class="nsp-k">Creates</span> a governed session record (<code>session:hyp-…</code>) with a daemon-provisioned workspace — ' + esc(intake));
    lines.push('<span class="nsp-k">Isolation</span> process-scoped sandbox under the daemon data dir; no external ingress');
    var editorSel = document.getElementById("ioi-ns-editor");
    var editor = (nsCtx.editor_targets || []).find(function (t) { return "editor-target:" + t.target_id === (editorSel && editorSel.value); });
    if (editor) lines.push('<span class="nsp-k">Editor</span> <b>' + esc(editor.display_name) + "</b> · " + esc((editor.open_kind || "").replace(/_/g, " ")) + " (validated openable at create)");
    if (p) {
      lines.push('<span class="nsp-k">Harness</span> <b>' + esc(p.display_name || p.harness) + "</b> · " + esc(p.provider_trust) + " trust · lane A execution over <b>" + esc(route ? (route.display_name || route.route_ref) : "(no route selected)") + "</b>");
      lines.push('<span class="nsp-k">Admission</span> <code>bind_session_profile</code> under <code>scope:harness.profile.mutate</code> (pure planner) + a LIVE runnability probe at bind — the create fails closed if either rejects; knobs compile a capability-admitted binding');
      lines.push('<span class="nsp-k">Receipts</span> <code>receipt://hypervisor/session-provision/*</code> + <code>agentgres://harness-profile-receipt/*</code>; ops carry transcript state_roots (Work Ledger)');
      if (p.runnability_state === "not_probed") lines.push('<span class="nsp-k nsp-warn">Warning</span> <span class="nsp-warn">runnability not probed yet — the launch will live-probe and fail closed if the host cannot run it</span>');
    } else {
      lines.push('<span class="nsp-k">Harness</span> none — the session records no binding; execution uses the daemon\'s Lane A default at execute time');
      lines.push('<span class="nsp-k">Receipts</span> <code>receipt://hypervisor/session-provision/*</code>');
    }
    lines.push('<span class="nsp-k">Restore</span> the session persists in the daemon estate; reopen it from Workbench — nothing here is UI-only state');
    box.innerHTML = lines.join("<br>");
  }
  function nsAgentLaunch(result, btn) {
    // IOI Agent launch: serve composes the daemon's two-phase wallet contract (challenge →
    // grant → execute) and returns the coordinated result with proof links.
    var el = document.getElementById("ioi-ns-modal");
    var branch = el.getAttribute("data-branch") || "project";
    var body = { goal: nsGoal() };
    if (nsStrategyTouched) body.strategy = nsStrategy();
    var pol = nsPolicy();
    if (pol) body.policy_ref = pol.policy_ref;
    if (branch === "project") { var pv = (document.getElementById("ioi-ns-project") || {}).value; if (pv) body.project_ref = pv; }
    if (branch === "url") {
      var u = ((document.getElementById("ioi-ns-url") || {}).value || "").trim();
      if (u && !/^https?:\/\/.+/.test(u)) { result.style.display = "block"; result.innerHTML = '<div class="ioi-ns-err">Enter a valid http(s) repository / PR / issue URL.</div>'; return; }
      if (u) body.context_url = u;
    }
    if (branch === "scratch") { var ev = (document.getElementById("ioi-ns-env") || {}).value; if (ev) body.environment_id = ev; }
    var etSel = document.getElementById("ioi-ns-editor");
    if (etSel && etSel.value) body.editor_target_ref = etSel.value;
    var routeSel = document.getElementById("ioi-ns-model");
    if (routeSel && routeSel.value) body.model_route_ref = routeSel.value;
    var hp = nsProfile();
    if (nsHarnessTouched && hp) body.preferred_harness_refs = [hp.profile_ref];
    var failSel = document.getElementById("ioi-ns-failure");
    if (failSel && failSel.value) body.failure_policy = failSel.value;
    if (btn) { btn.disabled = true; btn.textContent = "IOI Agent working…"; }
    fetch("/__ioi/api/ioi-agent/launch", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) })
      .then(function (r) { return r.json().then(function (j) { return { status: r.status, j: j }; }); })
      .then(function (rr) {
        var j = rr.j || {};
        result.style.display = "block";
        if (rr.status >= 400 || (j.error && j.error.code)) {
          var err = j.error || {};
          result.innerHTML = '<div class="ioi-ns-err"><b>Launch rejected fail-closed</b> — <code>' + esc(err.code || "HTTP " + rr.status) + "</code>" + (err.message ? "<br>" + esc(err.message) : "") + "</div>";
          return;
        }
        var files = (j.final_changed_files || []).map(function (f) { return "<code>" + esc(f) + "</code>"; }).join(" ") || "—";
        var adv = j.advanced || {};
        result.innerHTML =
          '<div class="ioi-ns-ok"><b>' + esc(j.headline || "IOI Agent coordinated this work") + "</b>" +
          (j.partial_result ? ' <span class="nsp-warn">(explicit partial — see blockers in proof)</span>' : "") +
          "<br>Changed files: " + files +
          '<br><a href="' + esc((j.links || {}).workbench_url || "/__ioi/workbench") + '" target="_top">Open Workbench →</a> · ' +
          '<a href="' + esc((j.links || {}).run_timeline_url || "#") + '" target="_blank" rel="noopener">Run Timeline ↗</a> · ' +
          '<a href="' + esc((j.links || {}).work_ledger_url || "/__ioi/work-ledger") + '" target="_top">Work Ledger →</a>' +
          '<details style="margin-top:8px"><summary style="cursor:pointer">Advanced / proof details</summary>' +
          '<div style="font-size:12px;margin-top:6px">execution: <code>' + esc(j.execution_kind || "") + "</code> · strategy <code>" + esc(j.strategy || "") + "</code>" +
          "<br>session: <code>" + esc(j.session_ref || "") + "</code>" +
          (adv.policy_ref ? "<br>launch policy: <code>" + esc(adv.policy_ref) + "</code>" : "") +
          ((adv.memory_projection_refs || []).length ? "<br>memory projections: " + adv.memory_projection_refs.map(function (r) { return "<code>" + esc(r) + "</code>"; }).join(" ") : "") +
          (adv.goal_run_ref ? "<br>GoalRun (internal orchestration): <code>" + esc(adv.goal_run_ref) + "</code>" : "") +
          (adv.harness_profile_ref ? "<br>harness: <code>" + esc(adv.harness_profile_ref) + "</code>" : "") +
          (adv.model_route_ref ? "<br>model route: <code>" + esc(adv.model_route_ref) + "</code>" : "") +
          "</div></details></div>";
      })
      .catch(function () {
        result.style.display = "block";
        result.innerHTML = '<div class="ioi-ns-err">IOI Agent launch failed — the daemon did not answer.</div>';
      })
      .finally(function () { if (btn) { btn.disabled = false; btn.textContent = "Start with IOI Agent"; } });
  }
  function nsLaunch() {
    const el = document.getElementById("ioi-ns-modal");
    const result = document.getElementById("ioi-ns-result");
    const btn = document.getElementById("ioi-ns-launch");
    if (!el || !result) return;
    if (nsGoal().length >= 4) { nsAgentLaunch(result, btn); return; }
    const branch = el.getAttribute("data-branch") || "project";
    const body = {};
    if (branch === "project") {
      body.project_ref = (document.getElementById("ioi-ns-project") || {}).value || "";
      if (!body.project_ref) { result.style.display = "block"; result.innerHTML = '<div class="ioi-ns-err">Select a project (or use another intake branch).</div>'; return; }
    } else if (branch === "url") {
      const u = ((document.getElementById("ioi-ns-url") || {}).value || "").trim();
      if (!/^https?:\/\/.+/.test(u)) { result.style.display = "block"; result.innerHTML = '<div class="ioi-ns-err">Enter a valid http(s) repository / PR / issue URL.</div>'; return; }
      body.context_url = u;
    } else {
      const envId = (document.getElementById("ioi-ns-env") || {}).value || "";
      if (envId) body.environment_id = envId;
    }
    var editorSel = document.getElementById("ioi-ns-editor");
    if (editorSel && editorSel.value) body.editor_target_ref = editorSel.value;
    const p = nsProfile();
    if (p) {
      body.harness_profile_ref = p.profile_ref;
      body.model_route_ref = (document.getElementById("ioi-ns-model") || {}).value || "";
      body.harness_key = p.harness;
      body.matrix_model = (p.models || [])[0] || "hypervisor:native-local";
      body.reasoning = (document.getElementById("ioi-ns-reasoning") || {}).value || "medium";
      body.speed = (document.getElementById("ioi-ns-speed") || {}).value || "balanced";
    }
    if (btn) { btn.disabled = true; btn.textContent = "Launching…"; }
    fetch("/__ioi/api/new-session/launch", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) })
      .then(async (r) => ({ status: r.status, j: await r.json().catch(() => ({})) }))
      .then(({ status, j }) => {
        result.style.display = "block";
        if (status >= 400 || (j.error && j.error.code)) {
          const err = j.error || {};
          result.innerHTML = '<div class="ioi-ns-err"><b>Launch rejected fail-closed</b> — <code>' + esc(err.code || "HTTP " + status) + "</code>" + (err.message ? "<br>" + esc(err.message) : "") + "</div>";
          return;
        }
        const hb = j.harness_binding;
        const kb = j.knob_binding && j.knob_binding.harnessBinding;
        const kbFail = j.knob_binding && j.knob_binding.fail_closed;
        result.innerHTML =
          "<b>Session created.</b><br>" +
          '<span class="nsp-k">Session</span> <code>' + esc(j.session_ref || "?") + "</code><br>" +
          '<span class="nsp-k">Environment</span> <code>' + esc(j.environment_ref || "?") + "</code><br>" +
          '<span class="nsp-k">Receipt</span> <code>' + esc(j.receipt_ref || "?") + "</code><br>" +
          (j.editor_target_ref ? '<span class="nsp-k">Editor</span> <code>' + esc(j.editor_target_ref) + "</code><br>" : "") +
          (hb ? '<span class="nsp-k">Harness</span> <code>' + esc(hb.profile_ref || "") + "</code> admitted <code>" + esc(hb.admission_id || "") + "</code><br>" : '<span class="nsp-k">Harness</span> no binding (execute-time default)<br>') +
          (kb ? '<span class="nsp-k">Knobs</span> reasoning <b>' + esc(kb.reasoning) + "</b> · speed <b>" + esc(kb.speed) + "</b> · <code>" + esc(kb.evidence_ref || "") + "</code><br>" : "") +
          (kbFail ? '<span class="nsp-k nsp-warn">Knobs</span> <span class="nsp-warn">rejected fail-closed: ' + esc(j.knob_binding.reason || "capability violation") + "</span><br>" : "") +
          '<div style="margin-top:8px"><a href="/__ioi/workbench">Open Workbench →</a> · <a href="/__ioi/work-ledger">Work Ledger →</a></div>';
      })
      .catch(() => { result.style.display = "block"; result.innerHTML = '<div class="ioi-ns-err">The launch request did not reach the daemon.</div>'; })
      .finally(() => { if (btn) { btn.disabled = false; btn.textContent = "Launch session"; } });
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
        // New Session (the rail create-session action) → the OWNED launcher modal.
        if (t.closest('[data-testid="create-session-button"]')) {
          e.preventDefault(); e.stopPropagation(); newSessionModal(); return;
        }
        // Applications launcher (rail #applications, the SPA's native launcher attr, or the estate deep-link) → MODAL.
        if (t.closest('a[href="#applications"], [data-hypervisor-applications-launcher], a[href="/__ioi/applications"]')) {
          e.preventDefault(); e.stopPropagation(); appsModal(); return;
        }
        // Live application links → open IN-SHELL in the Open Application slot (left rail stays).
        const appLink = t.closest('a[href^="/__ioi/connections"], a[href^="/__ioi/work-ledger"], a[href^="/__ioi/operations"], a[href^="/__ioi/environments"], a[href^="/__ioi/workbench"], a[href^="/__ioi/agent-studio"], a[href^="/__ioi/foundry"], a[href^="/__ioi/domain-apps"], a[href^="/__ioi/domain-app-runtime"], a[href^="/__ioi/governance"], a[href^="/__ioi/marketplace"], a[href^="/__ioi/odk"]');
        if (appLink) {
          e.preventDefault(); e.stopPropagation();
          const href = appLink.getAttribute("href");
          const name = /work-ledger/.test(href) ? "Work Ledger" : /operations/.test(href) ? "Operations" : /environments/.test(href) ? "Environments" : /workbench/.test(href) ? "Workbench" : /agent-studio/.test(href) ? "Agent Studio" : /foundry/.test(href) ? "Foundry" : /domain-app-runtime/.test(href) ? "Domain App" : /domain-apps/.test(href) ? "Domain Apps" : /governance/.test(href) ? "Governance" : /marketplace/.test(href) ? "Marketplace" : /\/__ioi\/odk/.test(href) ? "ODK" : "Developer & Integrations";
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
  /* New Session launcher modal (02-new-session graft): branches / registry controls / preview. */
  #ioi-ns-modal{position:fixed;inset:0;z-index:2147483645;display:none;align-items:flex-start;justify-content:center;background:rgba(0,0,0,.55);}
  #ioi-ns-modal.open{display:flex;}
  #ioi-ns-modal .ioi-ns{margin-top:5vh;width:760px;max-width:94vw;max-height:88vh;overflow:auto;background:#101216;border:1px solid #24262d;border-radius:14px;box-shadow:0 20px 60px rgba(0,0,0,.5);font:13px/1.5 system-ui,sans-serif;color:#e6e7ea;}
  #ioi-ns-modal .ioi-mh{display:flex;align-items:center;justify-content:space-between;padding:14px 18px;border-bottom:1px solid #24262d;font-weight:600;font-size:15px;color:#fff;}
  #ioi-ns-modal .ioi-mh button{background:transparent;border:1px solid #2a2c33;color:#cbd0da;border-radius:6px;cursor:pointer;padding:3px 10px;font:inherit;}
  #ioi-ns-body{padding:14px 18px 18px;}
  .ioi-ns-tabs{display:flex;gap:6px;margin-bottom:12px;}
  .ioi-ns-tab{border:1px solid #2a2c33;background:transparent;color:#cbd0da;border-radius:8px;padding:5px 12px;cursor:pointer;font:600 12px system-ui,sans-serif;}
  #ioi-ns-modal[data-branch="project"] .ioi-ns-tab[data-ns-branch="project"],#ioi-ns-modal[data-branch="url"] .ioi-ns-tab[data-ns-branch="url"],#ioi-ns-modal[data-branch="scratch"] .ioi-ns-tab[data-ns-branch="scratch"]{background:#15315c;border-color:#3a82f6;color:#fff;}
  .ioi-ns-pane{display:none;margin-bottom:12px;}
  #ioi-ns-modal[data-branch="project"] .ioi-ns-pane.project,#ioi-ns-modal[data-branch="url"] .ioi-ns-pane.url,#ioi-ns-modal[data-branch="scratch"] .ioi-ns-pane.scratch{display:block;}
  .ioi-ns-field{margin:0 0 10px;}
  .ioi-ns-field label{display:block;font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:#878a93;margin-bottom:4px;font-weight:600;}
  .ioi-ns-field select,.ioi-ns-field input,.ioi-ns-field textarea{width:100%;box-sizing:border-box;background:#0c0d10;border:1px solid #2a2c33;color:#e6e7ea;border-radius:8px;padding:7px 10px;font:12.5px system-ui,sans-serif;resize:vertical;}
  .ioi-ns-grid{display:grid;grid-template-columns:1fr 1fr;gap:0 14px;}
  .ioi-ns-preview{border:1px solid #24262d;border-radius:10px;background:#0c0d10;padding:12px 14px;margin:6px 0 12px;font-size:12.5px;}
  .ioi-ns-preview b{color:#fff;}
  .ioi-ns-preview .nsp-k{color:#878a93;display:inline-block;min-width:96px;}
  .ioi-ns-preview .nsp-warn{color:#e2b93d;}
  .ioi-ns-btn{background:#15315c;border:1px solid #3a82f6;color:#fff;border-radius:8px;padding:8px 18px;cursor:pointer;font:600 13px system-ui,sans-serif;}
  .ioi-ns-btn[disabled]{opacity:.5;cursor:default;}
  .ioi-ns-empty{color:#878a93;padding:18px 4px;}
  .ioi-ns-err{color:#e2726b;margin:6px 0;}
  #ioi-ns-result{border:1px solid #24262d;border-radius:10px;background:#0c0d10;padding:12px 14px;margin-top:12px;font-size:12.5px;}
  #ioi-ns-result a{color:#7fb0ff;}
  #ioi-ns-result code{font:11.5px ui-monospace,monospace;color:#cbd0da;word-break:break-all;}
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
