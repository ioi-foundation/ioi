// WS-I / WS-F — injected IOI-native surface (the IOI-native cockpit panel + owned Run Timeline).
//
// The borrowed reference cockpit has no slot for IOI-native objects (operator authority, environment
// lifecycle/isolation posture + services/tasks/ports, the WorkRun patch branch + its
// model-driven turns, the scoped terminal, receipts). This vanilla script mounts an IOI-native
// panel beside the cockpit (same mechanism as the brand boot-guard) that reads AND drives the
// daemon via /api/ioi/*. It owns no truth — the daemon is the source.
//
// CANONICAL OWNERSHIP: Hypervisor owns its conversation surface. On the workbench we REPLACE the
// borrowed transcript in-pane with our Run Timeline (mounted as an iframe to /__ioi/run-timeline,
// the owned governed-work surface), keeping the native composer so follow-ups still post through
// the adapter. This is the one place we deliberately edit the borrowed SPA's DOM (the transcript region of
// [data-testid=environment-agent-execution-conversation]); everything else stays hands-off.
//
// Boundary: daemon EXECUTES · wallet AUTHORIZES crossings · agentgres RECORDS (receipts).
(function () {
  if (window.__ioiAugmentationMounted) return;
  window.__ioiAugmentationMounted = true;

  // ---- Owned Run Timeline as the default workbench transcript (replaces the borrowed pane) ----
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
    // Full replacement: hide ALL borrowed pane children (transcript + the SPA's empty-state hero +
    // its composer), leaving only our owned timeline. The owned surface carries its own follow-up
    // composer, so it owns the whole conversation (transcript + send). Re-applied each tick because
    // React re-creates these children on its own renders.
    Array.prototype.forEach.call(C.children, function (ch) {
      ch.style.display = ch === frame ? "" : "none";
    });
  }

  // ---- BYOA "Create & connect GitHub App" affordance on the Git authentications surface ----------
  // The harvested SPA's native connect modal only knows PAT/OAuth; GitHub App is a method it can't
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

  // ---- "Connections" top-level nav → the owned cockpit for the whole connector estate -----------
  // Connections is the full-control surface (MCP + communication + OAuth + bearer + cloud + service
  // accounts); Settings > Integrations are thin projections. Clone a sibling nav item so it matches.
  function mountConnectionsNav() {
    if (document.querySelector(".ioi-connections-nav")) return; // already in the nav (re-added if React drops it)
    // The nav links + the sessions list share one container, so insert RIGHT AFTER the on-screen
    // Automations link (not appendChild, which lands at the container's end below all sessions).
    const sib = Array.prototype.find.call(
      document.querySelectorAll('a[href="/automations"]'),
      (s) => { const r = s.getBoundingClientRect(); return r.width > 0 && r.top > 0 && r.top < 1500; },
    );
    if (!sib) return;
    const item = sib.cloneNode(true);
    item.classList.add("ioi-connections-nav");
    item.setAttribute("href", "/__ioi/connections");
    item.removeAttribute("aria-current");
    const label = Array.prototype.find.call(item.querySelectorAll("div"), (d) => d.children.length === 0 && d.textContent.trim());
    if (label) label.textContent = "Connections";
    sib.insertAdjacentElement("afterend", item);
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

  function mount() {
    style();
    // (The bottom-right "IOI" cockpit launcher was removed — the Run Timeline mounts directly in the
    // workbench, so the floating button was redundant. The augmentation now only injects in-surface
    // affordances: the workbench timeline, the Git-auth GitHub-App button, and Integrations Connect.)
    matchMedia("(prefers-color-scheme: dark)").addEventListener?.("change", style);
    // Keep the owned Run Timeline mounted as the workbench transcript across SPA navigation + the
    // SPA's own re-renders (cheap idempotent re-apply; the SPA is a client-router, no full reloads).
    setInterval(mountTimelineInWorkbench, 700);
    mountTimelineInWorkbench();
    // Keep the BYOA GitHub App affordance present on the Git authentications surface.
    setInterval(mountGitAppButton, 700);
    mountGitAppButton();
    // Route native Integrations "Connect" clicks through the OAuth-native launcher.
    setInterval(wireIntegrationConnect, 700);
    wireIntegrationConnect();
    // Surface the owned Connections cockpit as a top-level nav item.
    setInterval(mountConnectionsNav, 700);
    mountConnectionsNav();
  }

  if (document.body) mount();
  else document.addEventListener("DOMContentLoaded", mount);
})();
