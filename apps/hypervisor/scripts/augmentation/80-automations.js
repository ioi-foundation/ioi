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
      `<div style="display:flex;justify-content:space-between;align-items:center;gap:8px;padding:9px 12px;border-top:1px solid ${t.line}"><a href="/__ioi/automations/new?project=${encodeURIComponent(projectId)}" style="display:inline-block;padding:6px 12px;border-radius:7px;background:${t.accent};color:#fff;text-decoration:none;font-weight:600">+ New automation</a><a href="/__ioi/work-ledger?project=${encodeURIComponent(projectId)}" style="color:${t.accent};text-decoration:none;font-size:11px;white-space:nowrap">📒 Provenance →</a></div>`;
  }

  // Route-scoped, idempotent wiring. Runs on DOM mutations (debounced) + SPA route changes — NOT on
  // a fixed 700ms poll — so it costs nothing when the shell is idle. Each affordance is guarded to
  // the route where its controls exist; all are idempotent (existence/route checks), so re-applying
  // on a re-render never duplicates or leaks.
