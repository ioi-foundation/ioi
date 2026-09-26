
  // ---- The notification inbox (ADR 0056 P1) ----
  // A bell beside What's new opens a panel over GET /v1/hypervisor/notifications: the caller's inbox,
  // which the daemon re-derives on every read from the owners' own records (sessions, automation runs,
  // approval requests, filed issues) under the caller's own policy. The panel keeps no state and claims
  // nothing the daemon did not say: nothing is "unread" (by canon the daemon keeps no read state), each
  // item carries ONE link back to the record that owns it, the count is "in the last N days", and a
  // refusal or an outage is said as what it is — never drawn as an empty inbox. /ai#notifications
  // opens it too (the certified rail's Notifications item links there).
  let notifFamily = "";
  let notifOpenedForHash = false;
  const notifAttr = (s) =>
    String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const NOTIF_BELL =
    '<svg width="18" height="18" viewBox="0 0 16 16" fill="none" aria-hidden="true"><path d="M8 1.5a4 4 0 0 0-4 4v2.2c0 .5-.2 1-.5 1.4L2.7 10.4c-.4.5 0 1.1.6 1.1h9.4c.6 0 1-.6.6-1.1l-.8-1.3c-.3-.4-.5-.9-.5-1.4V5.5a4 4 0 0 0-4-4Z" stroke="currentColor" stroke-width="1.3" stroke-linejoin="round"/><path d="M6.3 13a1.8 1.8 0 0 0 3.4 0" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/></svg>';

  function mountNotificationBell() {
    const anchor = document.querySelector('[data-testid="changelog-button"]');
    if (!anchor || !anchor.parentElement || document.getElementById("ioi-notif-bell")) return;
    const bell = document.createElement("button");
    bell.id = "ioi-notif-bell";
    bell.type = "button";
    bell.title = "Notifications";
    bell.setAttribute("aria-label", "Notifications");
    bell.setAttribute("aria-haspopup", "dialog");
    bell.setAttribute("data-testid", "ioi-notifications-button");
    bell.className = anchor.className; // the footer's own button look
    bell.innerHTML = '<span style="display:flex;width:32px;height:32px;align-items:center;justify-content:center">' + NOTIF_BELL + "</span>";
    bell.addEventListener("click", (e) => { e.preventDefault(); openNotifications(); });
    // Beside What's new, in the footer row — not inside its wrapper, which would stack it.
    const wrap = document.createElement("div");
    wrap.appendChild(bell);
    anchor.parentElement.parentElement.insertBefore(wrap, anchor.parentElement);
  }

  function notificationsPanel() {
    let el = document.getElementById("ioi-notif-panel");
    if (el) return el;
    el = document.createElement("div");
    el.id = "ioi-notif-panel";
    el.setAttribute("role", "dialog");
    el.setAttribute("aria-modal", "true");
    el.setAttribute("aria-label", "Notifications");
    document.body.appendChild(el);
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && el.classList.contains("open")) { e.preventDefault(); e.stopPropagation(); closeNotifications(); }
    }, true);
    el.addEventListener("click", (e) => {
      if (e.target === el || e.target.closest("[data-ioi-notif-close]")) { closeNotifications(); return; }
      const fam = e.target.closest("[data-ioi-notif-family]");
      if (fam) { notifFamily = fam.getAttribute("data-ioi-notif-family"); loadNotifications(); return; }
      const link = e.target.closest("a[data-ioi-notif-link]");
      if (link) {
        e.preventDefault();
        closeNotifications();
        const href = link.getAttribute("href");
        // The shell itself cannot nest; everything else opens in the application container.
        if (/^\/(ai|projects)(\/|$|[?#])/.test(href)) location.assign(href);
        else openApplication(href, link.getAttribute("data-title") || "Notification");
      }
    });
    return el;
  }

  function openNotifications() {
    const el = notificationsPanel();
    el.classList.add("open");
    loadNotifications();
    const close = el.querySelector("[data-ioi-notif-close]");
    if (close) close.focus();
  }

  function closeNotifications() {
    const el = document.getElementById("ioi-notif-panel");
    if (el) el.classList.remove("open");
    if (location.hash === "#notifications") history.replaceState(null, "", location.pathname + location.search);
  }

  // /ai#notifications opens the panel once per arrival at that hash.
  function openNotificationsFromHash() {
    if (location.pathname === "/ai" && location.hash === "#notifications") {
      if (!notifOpenedForHash) { notifOpenedForHash = true; openNotifications(); }
    } else {
      notifOpenedForHash = false;
    }
  }

  function loadNotifications() {
    renderNotifications({ state: "loading" });
    const query = "/v1/hypervisor/notifications?limit=25" + (notifFamily ? "&family=" + encodeURIComponent(notifFamily) : "");
    fetch(query, { credentials: "same-origin", headers: { accept: "application/json" } })
      .then((r) => r.json().then((j) => ({ status: r.status, j }), () => ({ status: r.status, j: null })))
      .then(({ status, j }) => renderNotifications({ status, j }))
      .catch((error) => renderNotifications({ status: 0, error: String(error) }));
  }

  function notifDay(iso) {
    const d = new Date(iso);
    return isNaN(d) ? "Undated" : d.toLocaleDateString(undefined, { weekday: "short", month: "short", day: "numeric", year: "numeric" });
  }

  function renderNotifications(r) {
    const el = notificationsPanel();
    const t = theme();
    const head =
      '<div class="ioi-notif-h"><span>Notifications</span><button type="button" data-ioi-notif-close title="Close" aria-label="Close notifications">✕</button></div>';
    const body = (state, inner) => '<div class="ioi-notif-body" data-ioi-notif-state="' + state + '">' + inner + "</div>";
    let html;
    if (r.state === "loading") {
      html = body("loading", '<div class="ioi-notif-note">Reading your inbox from the daemon…</div>');
    } else if (r.status === 401) {
      html = body("signed_out", '<div class="ioi-notif-note">Sign in to see your notifications — the inbox is re-derived for whoever is signed in, and nobody is. <a href="/__ioi/login?next=' + encodeURIComponent("/ai#notifications") + '" target="_top">Sign in</a></div>');
    } else if (!r.status || r.status === 502 || r.status === 503 || r.status === 504) {
      html = body("unavailable", '<div class="ioi-notif-note">The daemon did not answer (' + esc(r.status ? "HTTP " + r.status : r.error || "no response") + ") — no notifications are shown, and none are substituted.</div>");
    } else if (r.status !== 200 || !r.j || r.j.ok !== true) {
      const code = (r.j && (r.j.code || (r.j.error && r.j.error.code))) || "notification_read_refused";
      html = body("refused", '<div class="ioi-notif-note">The inbox read was refused — <code>' + esc(code) + "</code>" + (r.j && (r.j.message || (r.j.error && r.j.error.message)) ? ": " + esc(r.j.message || r.j.error.message) : "") + "</div>");
    } else {
      const j = r.j;
      const counts = j.counts || {};
      const fams = Object.entries(counts.by_family || {});
      const chips =
        '<div class="ioi-notif-chips"><button type="button" data-ioi-notif-family=""' + (notifFamily ? "" : ' aria-pressed="true"') + ">All</button>" +
        fams.map(([f, n]) => '<button type="button" data-ioi-notif-family="' + notifAttr(f) + '"' + (notifFamily === f ? ' aria-pressed="true"' : "") + ">" + esc(f.replace(/_/g, " ")) + " · " + esc(n) + "</button>").join("") + "</div>";
      const summary =
        '<div class="ioi-notif-note" data-ioi-notif-counts="' + notifAttr(counts.shown) + "/" + notifAttr(counts.total) + '">Showing ' + esc(counts.shown) + " of " + esc(counts.total) + " in the last " + esc(j.window_days) + " days" + (notifFamily ? " · " + esc(notifFamily.replace(/_/g, " ")) : "") + ". Nothing here is marked read or unread: the daemon keeps no read state.</div>";
      const items = j.items || [];
      let list = "";
      if (!items.length) {
        list = '<div class="ioi-notif-note" data-ioi-notif-empty="1">No notifications in the last ' + esc(j.window_days) + " days.</div>";
      } else {
        let day = null;
        for (const it of items) {
          const d = notifDay(it.occurred_at);
          if (d !== day) { day = d; list += '<div class="ioi-notif-day">' + esc(d) + "</div>"; }
          const time = isNaN(new Date(it.occurred_at)) ? "" : new Date(it.occurred_at).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
          list +=
            '<div class="ioi-notif-item" data-ioi-notif-item="' + notifAttr(it.notification_projection_id) + '">' +
            '<div class="ioi-notif-title">' + esc(it.title || it.event_kind) + "</div>" +
            (it.body ? '<div class="ioi-notif-text">' + esc(it.body) + "</div>" : "") +
            '<div class="ioi-notif-meta"><span>' + esc((it.owner_event_family || "").replace(/_/g, " ")) + " · " + esc(it.event_kind) + (time ? " · " + esc(time) : "") + "</span>" +
            (it.canonical_detail_route ? '<a data-ioi-notif-link href="' + notifAttr(it.canonical_detail_route) + '" data-title="' + notifAttr(it.title || "Notification") + '">Open →</a>' : "") +
            "</div></div>";
        }
      }
      const absences = (j.typed_absences || []).map((a) => "<li><b>" + esc(a.family.replace(/_/g, " ")) + "</b> — " + esc(a.message) + " <code>" + esc(a.code) + "</code></li>").join("");
      const email = j.delivery && j.delivery.email_absence ? "<li><b>email</b> — " + esc(j.delivery.email_absence) + "</li>" : "";
      const foot =
        '<div class="ioi-notif-foot"><div class="ioi-notif-note">Not in this inbox yet (named, not hidden):</div><ul>' + absences + email +
        '<li><b>configure notifications</b> — a named gap: the subscription is a registered contract, and its write plane is not built.</li></ul></div>';
      html = body(items.length ? "ready" : "empty", chips + summary + list + foot);
    }
    el.innerHTML = '<div class="ioi-notif" style="background:' + t.bg + ";color:" + t.fg + ";border-color:" + t.line + '">' + head + html + "</div>";
    el.querySelectorAll(".ioi-notif a").forEach((a) => { a.style.color = t.accent; });
  }
