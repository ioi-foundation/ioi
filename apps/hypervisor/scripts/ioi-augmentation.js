// WS-I / WS-F — injected IOI-native surface (the IOI-native cockpit panel).
//
// The Ona cockpit has no slot for IOI-native objects (operator authority, environment
// lifecycle/isolation posture + services/tasks/ports, the WorkRun patch branch + its
// model-driven turns, the scoped terminal, receipts). Deep injection into Ona's frozen
// minified terminal/bottom-panel is out of scope; instead this vanilla script mounts an
// IOI-native panel beside the cockpit (same mechanism as the brand boot-guard) that reads
// AND drives the daemon via /api/ioi/*. It owns no truth — the daemon is the source; the
// panel only renders daemon state and posts intents (exec / WorkRun turn) the daemon executes.
//
// Boundary: daemon EXECUTES · wallet AUTHORIZES crossings · agentgres RECORDS (receipts).
(function () {
  if (window.__ioiAugmentationMounted) return;
  window.__ioiAugmentationMounted = true;

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
         <div style="margin-top:3px"><span class="k mini">ports </span>${chips(st.ports, "ports")}</div>`
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
    const btn = document.createElement("button");
    btn.id = "ioi-aug-btn";
    btn.textContent = "IOI";
    const panel = document.createElement("div");
    panel.id = "ioi-aug-panel";
    document.body.appendChild(panel);
    document.body.appendChild(btn);

    btn.addEventListener("click", () => {
      const open = panel.classList.toggle("open");
      if (open) render(panel);
    });
    // Event delegation survives full re-renders (innerHTML is replaced each render).
    panel.addEventListener("click", async (ev) => {
      const b = ev.target.closest("[data-act]");
      if (!b || b.disabled) return;
      ev.preventDefault();
      const act = b.dataset.act;
      if (act === "exec") {
        await runExec(panel);
      } else if (act === "newwr") {
        await post("/api/ioi/workruns", { environment_id: activeEnvId, objective: "Panel-created WorkRun" });
        render(panel);
      } else if (act === "turn") {
        b.textContent = "…";
        await post(`/api/ioi/workruns/${b.dataset.id}/execute`, {});
        render(panel);
      }
    });
    panel.addEventListener("keydown", (ev) => {
      if (ev.target.id === "ioi-aug-cmd" && ev.key === "Enter") {
        ev.preventDefault();
        runExec(panel);
      }
    });
    matchMedia("(prefers-color-scheme: dark)").addEventListener?.("change", style);
  }

  if (document.body) mount();
  else document.addEventListener("DOMContentLoaded", mount);
})();
