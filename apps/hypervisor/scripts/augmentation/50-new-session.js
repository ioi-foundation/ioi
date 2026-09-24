  // ---- New Session launcher (02-new-session graft). The rail's create-session action opens an
  // OWNED modal: three intake branches (project / URL / scratch), registry-fed harness + model
  // controls where an unavailable option is DISABLED WITH ITS REASON (never hidden, never a
  // silent admission failure), and a launch preview naming the admission, receipts, isolation,
  // and restore path BEFORE the effectful call. Launch = daemon session create (harness selection
  // admitted before provisioning) + the capability-admitted knob binding.
  //
  // R-240: the modal carried the IOI Agent goal-pursuit lane — a goal box, a launch policy, an
  // execution strategy (auto / direct / compare / private-local), an on-failure choice, and a preview
  // and launch that called the IOI Agent routes. R-192 took goal pursuit out of the Hypervisor and
  // those routes answer 410, so typing a goal turned Start into "Launch rejected fail-closed" and the
  // chosen VENUE stopped appearing in any preview. The strategy controls are gone; the "what should it
  // do" box stays and becomes the session's first instruction (`initial_input`, the same field the
  // composer's own prompt sends); and the preview reads the daemon's placement preview, so the venue,
  // fee basis, advisory and venue receipts are named before launch again.
  let nsCtx = null;
  function nsProfile() {
    const sel = document.getElementById("ioi-ns-harness");
    if (!sel || !sel.value || !nsCtx) return null;
    return (nsCtx.harness_profiles || []).find((p) => p.profile_ref === sel.value) || null;
  }
  function nsHarnessReason(p) {
    if (p.lifecycle_status !== "active") return "not enabled — run the admitted enable in Studio";
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
      el.innerHTML = '<div class="ioi-modal ioi-ns"><div class="ioi-mh"><span>New Session</span><button title="Close">✕</button></div><div id="ioi-ns-body"><div class="ioi-ns-empty">Loading daemon context…</div></div></div>';
      document.body.appendChild(el);
      el.addEventListener("click", (e) => {
        if (e.target === el || e.target.closest(".ioi-mh button")) { el.classList.remove("open"); return; }
        const tab = e.target.closest("[data-ns-branch]");
        if (tab) { el.setAttribute("data-branch", tab.getAttribute("data-ns-branch")); renderNsPreview(); return; }
        const venueBtn = e.target.closest(".ioi-ns-venue-opt");
        if (venueBtn) { nsChooseVenue(venueBtn.getAttribute("data-venue")); return; }
        if (e.target.closest("#ioi-ns-launch")) { nsLaunch(); return; }
        if (e.target.closest("#ioi-ns-retry")) { nsCtx = null; loadNsContext(); return; }
        if (e.target.closest('a[href^="/__ioi/"]')) { el.classList.remove("open"); } // handoff opens in-shell via the capture handler
      });
      el.addEventListener("change", (e) => {
        if (!e.target || !e.target.id) return;
        if (e.target.id === "ioi-ns-harness") renderNsKnobs();
        if (e.target.id === "ioi-ns-venue-provider") { nsChooseVenue(nsCurrentVenue()); return; }
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
  // ── Connections this session may use — the session's CLOSED authority profile (ADR 0052
  // Decision 3). Nothing is selected by default: a session names only what the operator ticks
  // here, the daemon binds that set at create, and a connector outside it refuses at admission.
  // Widening later means a new session or a new Connections binding, never an in-run change.
  function nsConnectionsSection() {
    const cx = (nsCtx && nsCtx.connections) || [];
    const rows = cx.length
      ? cx.map(function (c) {
        return '<label class="ioi-ns-cx' + (c.selectable ? "" : " ioi-ns-cx-off") + '" title="' + esc(c.connection_ref) + '">' +
          '<input type="checkbox" class="ioi-ns-cx-box" value="' + esc(c.connection_ref) + '"' + (c.selectable ? "" : " disabled") + "> " +
          "<b>" + esc(c.name) + "</b> <span>" + esc(c.service || c.kind || "") + (c.reason ? " — " + esc(c.reason) : "") + "</span></label>";
      }).join("")
      : '<div class="ioi-ns-cx-empty">No connections in this workspace yet. The session will have none — add one under <a href="/__ioi/connections" target="_top">Connections</a> when the work needs it.</div>';
    return '<div class="ioi-ns-field"><label>Connections this session may use <span style="font-weight:400;opacity:.75">(none by default; closed once the session starts)</span></label>' +
      '<div class="ioi-ns-cx-list">' + rows + "</div></div>";
  }
  function nsSelectedConnections() {
    return Array.prototype.slice.call(document.querySelectorAll(".ioi-ns-cx-box:checked")).map(function (b) { return b.value; });
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
      '<div class="ioi-ns-field"><label>What should this session do? <span style="font-weight:400;opacity:.75">(optional — becomes the session\'s first instruction)</span></label><textarea id="ioi-ns-goal" rows="2" placeholder="Describe the task. Leave empty to only create a session."></textarea></div>' +
      nsVenueSection() +
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
      nsConnectionsSection() +
      '<div class="ioi-ns-preview" id="ioi-ns-preview"></div>' +
      '<button class="ioi-ns-btn" id="ioi-ns-launch">Start session</button>' +
      '<div id="ioi-ns-result" style="display:none"></div>';
    // Preselect the registry default profile when it is actually selectable.
    const hp = document.getElementById("ioi-ns-harness");
    const def = profiles.find((p) => p.default && !nsHarnessReason(p));
    if (def) hp.value = def.profile_ref;
    nsRenderVenueDetail();
    renderNsKnobs();
  }
  // ── Placement venue picker — DAEMON truth (placement/venues + venue-policy); the choice is
  // durable, explicit, and never hidden behind auto. Fee bases are declared copy, never fee
  // objects; "Let Hypervisor choose" renders planned/disabled-looking until the
  // cloud-candidate plane returns an admissible candidate from a connected provider adapter
  // (choosing it records an advisory preference).
  function nsPlacement() { return (nsCtx && nsCtx.placement) || { venues: [], policy: null }; }
  function nsVenueFor(id) { return (nsPlacement().venues || []).find(function (v) { return v.venue === id; }) || null; }
  function nsCurrentVenue() {
    var pol = nsPlacement().policy;
    return (pol && pol.venue) || "run_local";
  }
  function nsVenueSection() {
    var pl = nsPlacement();
    if (!pl.venues || !pl.venues.length) return "";
    var current = nsCurrentVenue();
    var btns = pl.venues.map(function (v) {
      var advisory = v.status === "advisory";
      var planned = v.status === "planned";
      var cls = "ioi-ns-venue-opt" + (v.venue === current ? " sel" : "") + (planned ? " planned" : "");
      var badge = planned ? ' <span class="ioi-ns-venue-badge">planned</span>'
        : advisory ? ' <span class="ioi-ns-venue-badge">advisory</span>'
        : (v.available === false ? ' <span class="ioi-ns-venue-badge warn">unavailable</span>' : "");
      return '<button type="button" class="' + cls + '" data-venue="' + esc(v.venue) + '" title="' + esc(v.summary || "") + '">' + esc(v.display_name) + badge + "</button>";
    }).join("");
    return '<div class="ioi-ns-field" id="ioi-ns-placement"><label>Where should this run? (placement venue — explicit, never hidden)</label>' +
      '<div id="ioi-ns-venues">' + btns + "</div>" +
      '<div id="ioi-ns-venue-provider-wrap" style="display:none;margin-top:6px"><select id="ioi-ns-venue-provider"></select></div>' +
      '<div id="ioi-ns-venue-fee" class="ioi-ns-venue-fee"></div></div>';
  }
  function nsRenderVenueDetail() {
    var current = nsCurrentVenue();
    var v = nsVenueFor(current);
    var fee = document.getElementById("ioi-ns-venue-fee");
    var wrap = document.getElementById("ioi-ns-venue-provider-wrap");
    var sel = document.getElementById("ioi-ns-venue-provider");
    document.querySelectorAll(".ioi-ns-venue-opt").forEach(function (b) { b.classList.toggle("sel", b.getAttribute("data-venue") === current); });
    if (!v || !fee) return;
    var f = v.fee || {};
    var lines = ['<b>' + esc((f.fee_basis || "none")) + "</b> — " + esc(f.fee_explanation || "")];
    if (v.availability_note) lines.push('<span class="nsp-warn">' + esc(v.availability_note) + "</span>");
    if (v.status === "planned") lines.push('<span class="nsp-warn">' + esc(v.planned_reason || "planned") + "</span>");
    if (v.quote_policy) lines.push('<span style="color:#6f7280">' + esc(v.quote_policy) + "</span>");
    if (v.status === "advisory") {
      var cands = (v.candidates || []).filter(function (c) { return c.placement_eligible; });
      var rec = v.recommendation;
      if (rec) lines.push('Advisory recommends <b>' + esc(rec.venue || "") + "</b>" + (rec.display_name ? " · " + esc(rec.display_name) : "") + ' <span style="color:#6f7280">(' + esc((rec.reason_codes || []).join(", ")) + ")</span>");
      if (cands.length) {
        lines.push('<span style="color:#6f7280">Candidates (evidence-bound, expiring — never authority):</span>');
        cands.slice(0, 6).forEach(function (c) {
          var rel = c.reliability || {};
          var q = c.quote || {};
          lines.push("· <b>" + esc(c.display_name || c.provider_kind) + "</b> · " + esc(c.runtime_class || "") +
            (c.gpu ? " · " + esc(String(c.gpu.count || 1)) + "x " + esc(c.gpu.model || "GPU") + (c.gpu.vram_gb ? " " + esc(String(c.gpu.vram_gb)) + "GB" : "") : "") +
            (q.usd_per_hour !== undefined ? " · <b>$" + esc(String(q.usd_per_hour)) + "/hr</b>" : "") +
            (c.region ? " · " + esc(c.region) : "") +
            " · custody " + esc(((c.custody_plan || {}).supported_postures || []).join("/")) +
            " · spend owner " + esc(((c.spend_estimate || {}).cost_owner) || "customer") +
            " · " + esc(c.coverage_state || "") +
            (rel.ops_ok !== undefined ? " · ops " + rel.ops_ok + "✓/" + (rel.ops_failed || 0) + "✗" : "") +
            (c.evidence_mode === "fixture_evidence" ? ' · <span class="nsp-warn">fixture_evidence (not live)</span>' : "") +
            ((c.custody_plan || {}).privacy === "marketplace_host_NOT_private" ? ' · <span class="nsp-warn">not private custody</span>' : ""));
        });
      } else {
        lines.push('<span class="nsp-warn">' + esc(v.no_eligible_candidate || "no eligible candidate — effective venue stays run_local") + "</span>");
      }
    }
    fee.innerHTML = lines.join("<br>");
    var needsProvider = current === "use_my_infrastructure" || current === "pick_provider";
    if (wrap) wrap.style.display = needsProvider ? "block" : "none";
    if (needsProvider && sel) {
      var pol = nsPlacement().policy || {};
      var cards = (v.providers || []).filter(function (p) { return p.connected; });
      sel.innerHTML = cards.length
        ? cards.map(function (p) {
            return '<option value="' + esc(p.account_ref) + '"' + (pol.provider_account_ref === p.account_ref ? " selected" : "") + ">" + esc(p.display_name || p.account_ref) + " · " + esc(p.kind) + " — " + esc(p.status) + "</option>";
          }).join("")
        : '<option value="">(no connected account for this venue yet)</option>';
    }
  }
  function nsChooseVenue(venue) {
    var body = { venue: venue };
    var v = nsVenueFor(venue);
    var sel = document.getElementById("ioi-ns-venue-provider");
    var needsProvider = venue === "use_my_infrastructure" || venue === "pick_provider";
    if (needsProvider) {
      var cards = ((v && v.providers) || []).filter(function (p) { return p.connected; });
      var selBelongs = sel && sel.value && cards.some(function (p) { return p.account_ref === sel.value; });
      var ref = (selBelongs ? sel.value : "") || (cards[0] && cards[0].account_ref) || "";
      if (!ref) {
        var fee = document.getElementById("ioi-ns-venue-fee");
        if (fee) fee.innerHTML = '<span class="nsp-warn">This venue pins a ProviderAccount — connect one under Environments → Provider accounts first.</span>';
        return;
      }
      body.provider_account_ref = ref;
    }
    fetch("/__ioi/api/placement/venue-policy", { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify(body) })
      .then(function (r) { return r.json(); })
      .then(function (j) {
        if (j && j.policy) { nsCtx.placement.policy = j.policy; }
        nsRenderVenueDetail();
        renderNsPreview();
      })
      .catch(function () {});
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
  var nsPreviewSeq = 0;
  function nsGoal() { var g = document.getElementById("ioi-ns-goal"); return g ? g.value.trim() : ""; }
  // The chosen venue, read back from the daemon's placement preview — DAEMON truth, never composed
  // here. Appended to the session preview so the venue, fee basis, advisory and venue receipts are
  // named BEFORE the effectful call.
  function renderNsPlacementPreview(box, seq) {
    fetch("/v1/hypervisor/placement/preview").then(function (r) { return r.json(); }).then(function (j) {
      if (seq !== nsPreviewSeq || !box) return;
      var pol = j.policy || {};
      var f = j.fee || {};
      var lines = [];
      lines.push('<span class="nsp-k">Placement</span> venue <b>' + esc(j.venue || pol.venue || "run_local") + "</b>"
        + (pol.provider_account_ref ? " · pinned <code>" + esc(pol.provider_account_ref) + "</code>" : "")
        + (pol.advisory ? ' <span class="nsp-warn">(advisory — effective venue ' + esc(pol.effective_venue || "run_local") + ")</span>" : "")
        + " · fee basis <b>" + esc(f.fee_basis || "none") + '</b> <span style="color:#6f7280">(' + esc(f.fee_explanation || "") + ")</span>");
      if (pol.advisory_ref) lines.push('<span class="nsp-k">Advisory</span> <code>' + esc(pol.advisory_ref) + "</code>" + (pol.advisory_recommendation ? " → <b>" + esc(pol.advisory_recommendation.venue || "") + "</b>" : "") + ((pol.advisory_candidate_refs || []).length ? " · candidates " + pol.advisory_candidate_refs.map(function (r) { return "<code>" + esc(String(r).slice(0, 46)) + "</code>"; }).join(" ") : ""));
      if ((j.receipts_expected || []).length) lines.push('<span class="nsp-k">Venue receipts</span> ' + j.receipts_expected.map(function (r) { return "<code>" + esc(r) + "</code>"; }).join(" "));
      var slot = box.querySelector("[data-nsp-placement]");
      if (slot) slot.innerHTML = lines.join("<br>");
    }).catch(function () {
      var slot = box && box.querySelector("[data-nsp-placement]");
      if (seq === nsPreviewSeq && slot) slot.innerHTML = '<span class="nsp-k nsp-warn">Placement</span> <span class="nsp-warn">the daemon placement preview did not answer — the launch still applies the durable venue policy</span>';
    });
  }
  function renderNsPreview() {
    const box = document.getElementById("ioi-ns-preview");
    const el = document.getElementById("ioi-ns-modal");
    if (!box || !el) return;
    var seq = ++nsPreviewSeq;
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
      lines.push('<span class="nsp-k">Receipts</span> <code>receipt://hypervisor/session-provision/*</code> + <code>agentgres://harness-profile-receipt/*</code>; ops carry transcript state_roots (Provenance)');
      if (p.runnability_state === "not_probed") lines.push('<span class="nsp-k nsp-warn">Warning</span> <span class="nsp-warn">runnability not probed yet — the launch will live-probe and fail closed if the host cannot run it</span>');
    } else {
      lines.push('<span class="nsp-k">Harness</span> none — the session records no binding; execution uses the daemon\'s Lane A default at execute time');
      lines.push('<span class="nsp-k">Receipts</span> <code>receipt://hypervisor/session-provision/*</code>');
    }
    if (nsGoal()) lines.push('<span class="nsp-k">Instruction</span> the session starts with: <i>' + esc(nsGoal().slice(0, 160)) + (nsGoal().length > 160 ? "…" : "") + "</i>");
    lines.push('<span class="nsp-k">Restore</span> the session persists in the daemon estate; reopen it from Workbench — nothing here is UI-only state');
    box.innerHTML = lines.join("<br>") + '<div data-nsp-placement><span class="nsp-k">Placement</span> reading the venue policy…</div>';
    renderNsPlacementPreview(box, seq);
  }
  function nsLaunch() {
    const el = document.getElementById("ioi-ns-modal");
    const result = document.getElementById("ioi-ns-result");
    const btn = document.getElementById("ioi-ns-launch");
    if (!el || !result) return;
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
    body.authority_profile = { connection_refs: nsSelectedConnections() };
    if (nsGoal()) body.initial_input = nsGoal();
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
          '<div style="margin-top:8px"><a href="/__ioi/workbench">Open Workbench →</a> · <a href="/__ioi/work-ledger">Provenance →</a></div>';
      })
      .catch(() => { result.style.display = "block"; result.innerHTML = '<div class="ioi-ns-err">The launch request did not reach the daemon.</div>'; })
      .finally(() => { if (btn) { btn.disabled = false; btn.textContent = "Launch session"; } });
  }

