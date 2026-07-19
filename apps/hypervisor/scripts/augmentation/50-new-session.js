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
      el.innerHTML = '<div class="ioi-modal ioi-ns"><div class="ioi-mh"><span>New Session — IOI Agent</span><button title="Close">✕</button></div><div id="ioi-ns-body"><div class="ioi-ns-empty">Loading daemon context…</div></div></div>';
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
        if (e.target.id === "ioi-ns-harness") { nsHarnessTouched = true; renderNsKnobs(); }
        if (e.target.id === "ioi-ns-venue-provider") { nsChooseVenue(nsCurrentVenue()); return; }
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
      '<div class="ioi-ns-preview" id="ioi-ns-preview"></div>' +
      '<button class="ioi-ns-btn" id="ioi-ns-launch">Start with IOI Agent</button>' +
      '<div id="ioi-ns-result" style="display:none"></div>';
    // Preselect the registry default profile when it is actually selectable.
    const hp = document.getElementById("ioi-ns-harness");
    const def = profiles.find((p) => p.default && !nsHarnessReason(p));
    if (def) hp.value = def.profile_ref;
    nsHarnessTouched = false;
    nsRenderVenueDetail();
    renderNsKnobs();
  }
  // ── Placement venue picker — DAEMON truth (placement/venues + venue-policy); the choice is
  // durable, explicit, and never hidden behind auto. Fee bases are declared copy, never fee
  // objects; "Let Hypervisor choose" renders planned/disabled-looking until the
  // decentralized.cloud candidate plane exists (choosing it records an advisory preference).
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
        if (j.policy_rollout) lines.push('<span class="nsp-k">Rollout</span> policy via <b>' + esc((j.policy_rollout.rollout_mode || "") + (j.policy_rollout.rollout_state === "promoted" ? " (promoted)" : "")) + '</b> overlay ' + esc(String(j.policy_rollout.variant_policy_ref || "").replace("ioi-agent-policy://", "")) + (j.policy_rollout.cohort_display_name ? ' for cohort <b>' + esc(j.policy_rollout.cohort_display_name) + '</b>' : '') + ' <span style="color:#6f7280">(' + esc(j.policy_rollout.reason_code || "") + ' · context: ' + esc(j.policy_rollout.rollout_context_source || "") + (j.policy_rollout.override ? ' — EXPLICIT OVERRIDE, not authenticated identity' : '') + ' · base ' + esc(String(j.policy_rollout.base_policy_ref || "").replace("ioi-agent-policy://", "")) + ')</span>');
        if (!j.policy_rollout && (j.policy_rollout_skipped || []).length) lines.push('<span class="nsp-k">Rollout</span> <span style="color:#6f7280">not applied — ' + esc(j.policy_rollout_skipped.map(function (x) { return String(x.variant_policy_ref || "").replace("ioi-agent-policy://", "") + ": " + (x.reason_code || ""); }).join("; ")) + ' (context: ' + esc(j.rollout_context_source || "") + ')</span>' + (j.policy_rollout_skipped.some(function (x) { return x.reason_code === "rollout_explicit_override_disallowed"; }) ? ' <span class="nsp-warn">explicit override rejected — not valid outside local development</span>' : ''));
        if (j.deployment_auth_posture === "local_development" && j.rollout_context_source === "anonymous") lines.push('<span class="nsp-k">Identity</span> <span style="color:#6f7280">deterministic local principal — <b>local-development posture only</b>; exposed deployments require authenticated identity</span>');
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
        if (j.placement) {
          var pf = j.placement.fee || {};
          lines.push('<span class="nsp-k">Placement</span> venue <b>' + esc(j.placement.venue || "run_local") + "</b>"
            + (j.placement.provider_account_ref ? " · pinned <code>" + esc(j.placement.provider_account_ref) + "</code>" : "")
            + (j.placement.advisory ? ' <span class="nsp-warn">(advisory placeholder — effective venue ' + esc(j.placement.effective_venue || "run_local") + ")</span>" : "")
            + ' · fee basis <b>' + esc(pf.fee_basis || "none") + "</b> <span style=\"color:#6f7280\">(" + esc(pf.fee_explanation || "") + ")</span>");
          if (j.placement.decision_mode) lines.push('<span class="nsp-k">Placement</span> ' + (j.placement.decision_mode.mode === "decision_available" ? '<b>decision</b> <code>' + esc(String(j.placement.decision_mode.decision_ref || "").slice(0, 44)) + "</code>" : "advisory mode (no explicit decision yet)"));
          if (j.placement.advisory_ref) lines.push('<span class="nsp-k">Advisory</span> <code>' + esc(j.placement.advisory_ref) + "</code>" + (j.placement.advisory_recommendation ? " → <b>" + esc(j.placement.advisory_recommendation.venue || "") + "</b>" : "") + ((j.placement.advisory_candidate_refs || []).length ? " · candidates " + j.placement.advisory_candidate_refs.map(function (r) { return "<code>" + esc(String(r).slice(0, 46)) + "</code>"; }).join(" ") : "") + (j.placement.no_eligible_candidate ? ' <span class="nsp-warn">' + esc(j.placement.no_eligible_candidate) + "</span>" : ""));
          if ((j.placement.receipts_expected || []).length) lines.push('<span class="nsp-k">Venue receipts</span> ' + j.placement.receipts_expected.map(function (r) { return "<code>" + esc(r) + "</code>"; }).join(" "));
        }
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
      lines.push('<span class="nsp-k">Receipts</span> <code>receipt://hypervisor/session-provision/*</code> + <code>agentgres://harness-profile-receipt/*</code>; ops carry transcript state_roots (Provenance)');
      if (p.runnability_state === "not_probed") lines.push('<span class="nsp-k nsp-warn">Warning</span> <span class="nsp-warn">runnability not probed yet — the launch will live-probe and fail closed if the host cannot run it</span>');
    } else {
      lines.push('<span class="nsp-k">Harness</span> none — the session records no binding; execution uses the daemon\'s Lane A default at execute time');
      lines.push('<span class="nsp-k">Receipts</span> <code>receipt://hypervisor/session-provision/*</code>');
    }
    lines.push('<span class="nsp-k">Restore</span> the session persists in the daemon estate; reopen it from Developer Workspace — nothing here is UI-only state');
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
          '<br><a href="' + esc((j.links || {}).workbench_url || "/__ioi/workbench") + '" target="_top">Open Developer Workspace →</a> · ' +
          '<a href="' + esc((j.links || {}).run_timeline_url || "#") + '" target="_blank" rel="noopener">Run Timeline ↗</a> · ' +
          '<a href="' + esc((j.links || {}).work_ledger_url || "/__ioi/work-ledger") + '" target="_top">Provenance →</a>' +
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
          '<div style="margin-top:8px"><a href="/__ioi/workbench">Open Developer Workspace →</a> · <a href="/__ioi/work-ledger">Provenance →</a></div>';
      })
      .catch(() => { result.style.display = "block"; result.innerHTML = '<div class="ioi-ns-err">The launch request did not reach the daemon.</div>'; })
      .finally(() => { if (btn) { btn.disabled = false; btn.textContent = "Launch session"; } });
  }
