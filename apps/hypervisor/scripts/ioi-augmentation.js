// WS-I — injected IOI-native surface.
//
// The Ona cockpit has no slot for IOI-native objects (operator authority, environment
// lifecycle/isolation posture, WorkRun patch-branch binding, receipts). This vanilla script
// is injected beside the cockpit by the serve layer (the same mechanism as the brand
// boot-guard) and mounts a non-authoritative panel that reads the daemon via /api/ioi/*.
// It never edits Ona's surfaces and owns no truth — the daemon is the source.
(function () {
  if (window.__ioiAugmentationMounted) return;
  window.__ioiAugmentationMounted = true;

  const isDark = () =>
    document.documentElement.classList.contains("dark") ||
    matchMedia("(prefers-color-scheme: dark)").matches;

  const css = `
  #ioi-aug-btn{position:fixed;right:14px;bottom:14px;z-index:2147483646;font:600 12px system-ui,sans-serif;
    padding:7px 12px;border-radius:8px;cursor:pointer;border:1px solid;}
  #ioi-aug-panel{position:fixed;right:14px;bottom:52px;z-index:2147483646;width:340px;max-height:70vh;overflow:auto;
    border-radius:10px;border:1px solid;box-shadow:0 8px 30px rgba(0,0,0,.35);font:12px/1.5 system-ui,sans-serif;display:none;}
  #ioi-aug-panel.open{display:block;}
  #ioi-aug-panel h3{margin:0;padding:10px 12px;font-size:13px;border-bottom:1px solid;}
  #ioi-aug-panel section{padding:10px 12px;border-bottom:1px solid;}
  #ioi-aug-panel .k{opacity:.65;} #ioi-aug-panel .row{display:flex;justify-content:space-between;gap:8px;}
  #ioi-aug-panel .pill{display:inline-block;padding:1px 7px;border-radius:999px;font-size:11px;border:1px solid;}
  #ioi-aug-panel code{font-size:11px;word-break:break-all;}
  `;
  const theme = () =>
    isDark()
      ? { bg: "#161515", fg: "#fafafa", line: "#333", accent: "#5e8afd", btnBg: "#1f1f1f" }
      : { bg: "#ffffff", fg: "#1f1f1f", line: "#e1e1e1", accent: "#2f69fd", btnBg: "#fafafa" };

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
       #ioi-aug-panel .pill{border-color:${t.line};}
       #ioi-aug-panel .accent{color:${t.accent};}`;
  }

  const get = (p) => fetch(p).then((r) => r.json()).catch((e) => ({ error: String(e) }));
  const esc = (s) => String(s == null ? "" : s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));

  async function render(panel) {
    const [auth, envs, wrs, rcpt] = await Promise.all([
      get("/api/ioi/authority/posture"),
      get("/api/ioi/environments"),
      get("/api/ioi/workruns"),
      get("/api/ioi/receipts"),
    ]);
    const receipts = rcpt.receipts || rcpt.items || (Array.isArray(rcpt) ? rcpt : []);
    const envList = (envs.environments || [])
      .slice(-5)
      .map(
        (e) =>
          `<div class="row"><code>${esc(e.id)}</code><span class="pill accent">${esc(e.status?.phase)}</span></div>
           <div class="row"><span class="k">isolation</span><span>${esc(e.status?.isolation_claim || "-")}</span></div>`
      )
      .join("<hr style='border:0'/>") || "<span class='k'>none</span>";
    const wrList = (wrs.workRuns || [])
      .slice(-5)
      .map(
        (w) =>
          `<div class="row"><code>${esc(w.branch)}</code><span class="pill">${w.host_mutation ? "host!" : "scoped"}</span></div>
           <div class="row"><span class="k">patch</span><code>${esc(w.patch_branch_ref || "-")}</code></div>`
      )
      .join("<hr style='border:0'/>") || "<span class='k'>none</span>";
    panel.innerHTML = `
      <h3>IOI Runtime <span class="k" style="font-weight:400">(daemon truth)</span></h3>
      <section>
        <div class="row"><span class="k">authority</span><span class="accent">${esc(auth.mode || auth.error || "?")}</span></div>
        <div class="row"><span class="k">wallet.network</span><span>${auth.wallet_network_live ? "live" : "represented (not live)"}</span></div>
      </section>
      <section><div class="k" style="margin-bottom:6px">Environments</div>${envList}</section>
      <section><div class="k" style="margin-bottom:6px">WorkRuns (patch branches)</div>${wrList}</section>
      <section><div class="row"><span class="k">Receipts / replay</span><span class="pill">${receipts.length}</span></div>
        <div class="k" style="margin-top:4px">agentgres-recorded; daemon truth window</div></section>`;
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
    matchMedia("(prefers-color-scheme: dark)").addEventListener?.("change", style);
  }

  if (document.body) mount();
  else document.addEventListener("DOMContentLoaded", mount);
})();
