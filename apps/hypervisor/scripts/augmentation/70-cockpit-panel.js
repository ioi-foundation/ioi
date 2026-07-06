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
  #ioi-ns-venues{display:flex;gap:8px;flex-wrap:wrap;margin:4px 0 2px;}
  .ioi-ns-venue-opt{border:1px solid #2a2c33;border-radius:9px;background:#101116;color:#c9ccd4;padding:7px 12px;font-size:12.5px;cursor:pointer;}
  .ioi-ns-venue-opt:hover{background:#15171c;}
  .ioi-ns-venue-opt.sel{border-color:#3c9d64;background:#10241a;color:#fff;}
  .ioi-ns-venue-opt.planned{opacity:.65;border-style:dashed;}
  .ioi-ns-venue-badge{font-size:10px;letter-spacing:.05em;text-transform:uppercase;color:#8f939d;border:1px solid #2a2c33;border-radius:6px;padding:1px 5px;margin-left:4px;}
  .ioi-ns-venue-badge.warn{color:#e2b93d;border-color:#4c4322;}
  .ioi-ns-venue-fee{border-left:2px solid #2a2c33;margin-top:6px;padding:4px 0 4px 10px;font-size:12px;color:#9a9da6;}
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

