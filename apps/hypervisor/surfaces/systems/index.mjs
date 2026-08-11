// Systems — the canonical /systems greenfield workspace (next-legs III Leg 4).
//
// GREENFIELD, TYPED NON-PARITY: no provenance-qualified seed exists for this surface — two
// recovery passes promoted zero candidates — so this build rides the owner-authorized
// greenfield-authorized-non-parity lane recorded in apps/hypervisor/seed-ux-provenance.v1.json.
// It claims no seed preservation and no parity; it is canon-first over
// docs/architecture/components/hypervisor/core-clients-surfaces.md ("no fabricated System rows
// before honest read models", § Systems workspace).
//
// PROJECTION TRUTH, VERBATIM: the inventory is the daemon's own compact read projection
// (GET /v1/hypervisor/autonomous-systems/projection — ioi.hypervisor.autonomous-system-read-
// projection.v1). Its `honest_empty` state and its fail-closed
// `system_projection_source_incomplete` refusal pass through VERBATIM: an empty estate renders
// the daemon's own nonclaims block, a local/Agentgres divergence renders as a census-level stop,
// and NEVER as a partial or plausible list. This module fabricates no System row, ever.
//
// AUTHORITY CROSSINGS through the ONE gateway client: exactly TWO verbs are wired in this cut —
// genesis compose (POST /v1/hypervisor/autonomous-systems) and sequence-zero materialization
// (POST :id/sequence-zero-materialization) — and both cross through the shared CapabilityLease
// authority client (surfaces/authority-client.mjs) on the request-scoped daemon capability, so
// the pane speaks the uniform gateway vocabulary: a 403 renders the daemon's wallet challenge
// with its hash-shaped public commitments (policy/request/effect), a 428 renders the sealed-
// credential lane as a named state, a 2xx without the declared receipt fails CLOSED
// (receipt_missing), and every other typed refusal renders its exact code verbatim. Every OTHER
// authority-crossing verb of the autonomous-systems family (initialize, activate, protected
// transitions, continuity, membership ops, desired topology, writer transitions, amendment
// execution) is deliberately NOT wired here: those panes are read-first, and their controls are
// disabled with a named reason until they land on the same lease client (W2 continuation).
// Rendering a disabled control grants nothing; wiring a verb outside the lease client would
// mint a second mutation path — refused by design.
//
// Interfaces mode is a disabled-named-gap (OQ-9): HypervisorSystemInterfaceBinding has a
// registered schema and ZERO rows and ZERO routes — no durable binding plane exists, so
// interface launch stays disabled (with the gap named on the control) until the W3
// interface-binding plane lands. No launch affordance is fabricated before the plane exists.
import { escHtml } from "../kit.mjs";

const esc = escHtml;
const LEGACY_ROUTE = "/__ioi/systems-workspace";
const CANONICAL_ROUTE = "/systems";
const API = "/v1/hypervisor/autonomous-systems";
const PROJECTION_SCHEMA = "ioi.hypervisor.autonomous-system-read-projection.v1";
const KEY_RE = /^asg_[0-9a-f]{64}$/;
const HASH_RE = /^sha256:[0-9a-f]{64}$/;

export const meta = {
  slug: "systems",
  route: LEGACY_ROUTE,
  verifier: "scripts/verify-hypervisor-systems-journey.mjs",
  certification: "n/a",
};

// The two wired authority crossings. `bodyMax`/`fieldMax` are DECLARED bounds (the governed
// action runtime's declared-bound idiom): a genesis declaration is hash-committed end to end
// (proposal_root is computed over its exact bytes), so silently truncating it would forward a
// corrupt artifact — the bound is declared, never lucked into. The wallet grant rides its own
// declared field exactly once and is never retained or echoed.
export const actions = [
  {
    id: "genesis-compose",
    method: "POST",
    route: "/actions/genesis-compose",
    fields: ["declaration", "wallet_approval_grant"],
    fieldMax: 40960,
    bodyMax: 49152,
    context: [],
    authority: { plane: "autonomous-system.genesis", operation: `POST ${API}` },
    receipt: "autonomous_system_genesis_receipt.receipt_ref",
    confirm: false,
    success: "return-to-surface",
    refusal: "typed-banner",
  },
  {
    id: "sequence-zero",
    method: "POST",
    route: "/actions/sequence-zero",
    fields: [
      "system",
      "expected_genesis_admission_record_root",
      "expected_genesis_admission_receipt_root",
      "wallet_approval_grant",
    ],
    fieldMax: 4096,
    context: ["system"],
    authority: { plane: "autonomous-system.lifecycle", operation: `POST ${API}/:id/sequence-zero-materialization` },
    receipt: "autonomous_system_sequence_zero_materialization_receipt.receipt_ref",
    confirm: false,
    success: "return-to-surface",
    refusal: "typed-banner",
  },
];

// ---------------------------------------------------------------------------------------------
// load — every fact on the page is a live read through the shared read client on the request-
// scoped daemon capability (typed degradation, no caching, refusals verbatim). One down plane
// never poisons another: the detail panes fan out independently.
export async function load(ctx) {
  const { createReadClient } = await import("../read-client.mjs");
  const client = typeof ctx.daemonFetch === "function"
    ? createReadClient({ daemon: "", fetchImpl: ctx.daemonFetch })
    : createReadClient({ daemon: ctx.daemon });
  const rawSystem = (ctx.url.searchParams.get("system") || "").trim();
  const system = KEY_RE.test(rawSystem) ? rawSystem : "";
  const inventory = await client.read(`${API}/projection?view=compact`, { expectSchema: PROJECTION_SCHEMA });
  const model = {
    inventory,
    system,
    systemInvalid: rawSystem !== "" && system === "",
    rawSystem: rawSystem.slice(0, 80),
    banner: bannerFromQuery(ctx.url.searchParams),
  };
  if (system) {
    model.detail = await client.readMany({
      admission: `${API}/${system}`,
      sequenceZero: `${API}/${system}/sequence-zero-materialization`,
      initialize: `${API}/${system}/initialize`,
      activate: `${API}/${system}/activate`,
      membership: `${API}/${system}/membership/projection`,
      topology: `${API}/${system}/topology/minimum`,
      writerEpoch: `${API}/${system}/writer/epoch`,
      writerLostSuffixes: `${API}/${system}/writer/lost-suffixes`,
      amendments: `${API}/${system}/amendments`,
    });
    const systemId = model.detail.admission?.ok
      ? String(model.detail.admission.payload?.autonomous_system_genesis_admission?.system_id || "")
      : "";
    if (systemId) {
      model.advanced = await client.read(
        `${API}/projection?view=advanced&system_id=${encodeURIComponent(systemId)}`,
        { expectSchema: PROJECTION_SCHEMA },
      );
    }
  }
  return model;
}

// PRG banner facts. `refused`/`reason`/`acted`/`receipt` are the governed action runtime's own
// redirect vocabulary; the short ch* params are this module's typed-refusal ladder carriage
// (set only by handleAction below; short names keep a full challenge inside the runtime's
// bounded same-origin return path) — hash params are shape-checked again before rendering so
// the banner never renders a non-commitment as one.
function bannerFromQuery(params) {
  const pick = (name, max = 200) => String(params.get(name) || "").slice(0, max);
  const hash = (name) => (HASH_RE.test(params.get(name) || "") ? params.get(name) : "");
  return {
    acted: pick("acted", 60),
    receipt: pick("receipt"),
    record: pick("record"),
    result: pick("result"),
    refused: pick("refused", 120),
    reason: pick("reason", 220),
    chStage: pick("chS", 40),
    chStatus: pick("chH", 8),
    chCode: pick("chC", 120),
    chScope: pick("chSc", 160),
    chAuthority: pick("chA", 160),
    chPolicy: hash("chP"),
    chRequest: hash("chR"),
    chEffect: hash("chE"),
  };
}

// ---------------------------------------------------------------------------------------------
// handleAction — the two wired crossings. Both ride createAuthorityClient on the request-scoped
// daemon capability (post-#236 form): daemon "" keeps every path daemon-relative, the caller's
// own identity envelope rides the crossing, and the client's typed-result contract holds — one
// typed outcome per call, no silent no-op, receipts required for success.
export async function handleAction({ action, fields, daemonFetch }) {
  if (typeof daemonFetch !== "function") {
    return { kind: "failure", http: 500, code: "identity_capability_missing", message: "the action runtime supplied no request-scoped daemon capability — refusing to cross authority without the caller's identity" };
  }
  const { createAuthorityClient } = await import("../authority-client.mjs");
  const authority = createAuthorityClient({ daemon: "", fetchImpl: daemonFetch });

  if (action.id === "genesis-compose") {
    let declaration;
    try {
      declaration = JSON.parse(fields.declaration || "");
    } catch (error) {
      return { kind: "refusal", http: 400, code: "system_declaration_unparseable", message: `the declaration is not valid JSON (${String(error.message).slice(0, 120)}) — nothing was sent to the daemon`, redirect: `${LEGACY_ROUTE}?chS=input&chC=system_declaration_unparseable` };
    }
    if (!declaration || typeof declaration !== "object" || Array.isArray(declaration)) {
      return { kind: "refusal", http: 400, code: "system_declaration_invalid", message: "the declaration must be a JSON object carrying release + proposed_instantiation", redirect: `${LEGACY_ROUTE}?chS=input&chC=system_declaration_invalid` };
    }
    // Authority rides the DECLARED grant field only — a grant embedded in the pasted
    // declaration is stripped so the surface never forwards ambient authority.
    delete declaration.wallet_approval_grant;
    const crossed = await authority.cross(API, {
      method: "POST",
      body: declaration,
      grant: fields.wallet_approval_grant,
      extractReceiptRef: (payload) => payload?.autonomous_system_genesis_receipt?.receipt_ref || "",
    });
    return fromCrossing(crossed, {
      onSuccess: (c) => {
        const tail = String(c.payload?.autonomous_system_genesis_admission?.admission_id || "")
          .replace("system-genesis-admission://", "");
        return {
          kind: "success",
          receipt_ref: c.receipt_ref,
          created: c.payload?.autonomous_system_genesis_admission?.admission_id || "",
          status: "genesis_admitted",
          redirect: KEY_RE.test(tail) ? `${LEGACY_ROUTE}?system=${tail}` : LEGACY_ROUTE,
        };
      },
    });
  }

  if (action.id === "sequence-zero") {
    const system = (fields.system || "").trim();
    if (!KEY_RE.test(system)) {
      return { kind: "refusal", http: 400, code: "system_key_invalid", message: "sequence-zero needs a canonical asg_<64 hex> System key — nothing was sent to the daemon", redirect: `${LEGACY_ROUTE}?chS=input&chC=system_key_invalid` };
    }
    const body = {
      expected_genesis_admission_record_root: (fields.expected_genesis_admission_record_root || "").trim(),
      expected_genesis_admission_receipt_root: (fields.expected_genesis_admission_receipt_root || "").trim(),
    };
    const crossed = await authority.cross(`${API}/${system}/sequence-zero-materialization`, {
      method: "POST",
      body,
      grant: fields.wallet_approval_grant,
      extractReceiptRef: (payload) => payload?.autonomous_system_sequence_zero_materialization_receipt?.receipt_ref || "",
    });
    return fromCrossing(crossed, {
      system,
      onSuccess: (c) => ({
        kind: "success",
        receipt_ref: c.receipt_ref,
        status: "sequence_zero_materialized",
        redirect: `${LEGACY_ROUTE}?system=${system}`,
      }),
    });
  }

  return { kind: "refusal", http: 400, code: "action_unknown", message: "undeclared action" };
}

// One typed mapping from a crossWithLease outcome to the action-runtime result. Refusals carry
// the ladder facts through the PRG redirect (chStage/chCode + the challenge's hash-shaped
// public commitments) so the surface renders the daemon's exact refusal — commitments are
// shape-checked before carriage, never invented, never secret.
function fromCrossing(crossed, { system = "", onSuccess }) {
  if (crossed.ok) return onSuccess(crossed);
  // The action runtime re-validates the module's return path as a bounded same-origin path
  // (512 chars). A full challenge fits under the short param names; if an unusually long
  // scope/authority would overflow the bound, the OPTIONAL context params are dropped in
  // declared priority order (authority, then scope, then status) — the hash commitments and
  // the typed code are never the ones dropped.
  const back = (params) => {
    const query = new URLSearchParams(system ? { system } : {});
    for (const [key, value] of Object.entries(params)) if (value) query.set(key, value);
    for (const droppable of ["chA", "chSc", "chH"]) {
      if (`${LEGACY_ROUTE}?${query.toString()}`.length <= 500) break;
      query.delete(droppable);
    }
    return `${LEGACY_ROUTE}?${query.toString()}`;
  };
  if (crossed.kind === "failure") {
    return {
      kind: "failure",
      http: 502,
      code: crossed.code,
      message: crossed.message,
      redirect: back({ chS: "failure", chC: crossed.code }),
    };
  }
  // Refusal. The autonomous-systems family speaks its challenge as error.approval
  // {policy_hash, request_hash, effect_hash} + error.required_scope/required_authority_ref;
  // the lease gateway speaks required_authority_scope + approval{...} at the top level — the
  // shared client surfaces the latter as `challenge` and the verbatim body as `refusal`.
  // Read both, shape-check, carry verbatim.
  const err = (crossed.refusal && typeof crossed.refusal === "object" ? crossed.refusal.error : null) || {};
  const approval = (err.approval && typeof err.approval === "object" ? err.approval : null) || {};
  const gateway = crossed.challenge || {};
  const pickHash = (...candidates) => candidates.find((v) => HASH_RE.test(String(v || ""))) || "";
  const code = String(err.code || crossed.code || "").slice(0, 120);
  return {
    kind: "refusal",
    http: crossed.status || 400,
    code,
    message: crossed.message,
    redirect: back({
      chS: crossed.stage,
      chH: String(crossed.status || ""),
      chC: code,
      chSc: String(err.required_scope || gateway.required_authority_scope || "").slice(0, 120),
      chA: String(err.required_authority_ref || "").slice(0, 120),
      chP: pickHash(approval.policy_hash, gateway.policy_hash),
      chR: pickHash(approval.request_hash, gateway.request_hash),
      chE: pickHash(approval.effect_hash),
    }),
  };
}

// ---------------------------------------------------------------------------------------------
const pill = (cls, label) => `<span class="pill ${cls}">${esc(label)}</span>`;
const jsonPre = (value) => `<pre>${esc(JSON.stringify(value ?? null, null, 2))}</pre>`;

// A degraded read as a typed band — the read client's code/message verbatim, plus the daemon's
// own refusal body when one exists. Never a fabricated default.
function degradedBand(result, label) {
  const code = result?.code || "daemon_unavailable";
  return `<div class="empty" data-ioi-degraded="${esc(code)}">
      <b>${esc(label)} unavailable</b> — <code>${esc(code)}</code>
      <div style="margin-top:6px">${esc(result?.message || "the daemon did not answer")}</div>
    </div>${result?.refusal ? jsonPre(result.refusal) : ""}`;
}

// The PRG banner: one region (#ap-result) that renders the last crossing's typed outcome —
// receipted success, the wallet challenge with its public commitments, the sealed-credential
// lane, or any other typed refusal verbatim.
function bannerBlock(banner) {
  if (banner.acted && banner.receipt) {
    return `<div class="band-result ok-band" id="ap-result" data-ioi-crossing="crossed" data-ioi-crossing-action="${esc(banner.acted)}">
        <b>Crossed with receipt</b> — <code>${esc(banner.acted)}</code>${banner.result ? ` · ${esc(banner.result)}` : ""}
        <div class="meta">receipt <code data-ioi-receipt-ref="${esc(banner.receipt)}">${esc(banner.receipt)}</code>${banner.record ? ` · <code>${esc(banner.record)}</code>` : ""}</div>
        <div class="meta">The crossing happened iff this receipt names it (fail-closed on the shared CapabilityLease client); the record truth below is a fresh read, not this banner.</div>
      </div>`;
  }
  if (!banner.refused && !banner.chStage) return "";
  const stage = banner.chStage || "gateway";
  if (stage === "wallet_challenge") {
    return `<div class="band-result warn-band" id="ap-result" data-ioi-refusal-stage="wallet_challenge" data-ioi-refusal-code="${esc(banner.chCode || banner.refused)}">
        <b>Authority required — wallet challenge (HTTP ${esc(banner.chStatus || "403")})</b> — <code>${esc(banner.chCode || banner.refused)}</code>
        <div class="meta">The daemon computed the exact governed effect and refused it pending independently resolved, atomically consumed owner authority. Nothing was admitted or mutated; this is the challenge's PUBLIC commitments verbatim — sign externally, then resubmit the one-use grant.</div>
        <dl class="grid">
          <dt>required_scope</dt><dd><code>${esc(banner.chScope)}</code></dd>
          <dt>required_authority_ref</dt><dd><code>${esc(banner.chAuthority)}</code></dd>
          <dt>policy_hash</dt><dd><code data-ioi-challenge="policy_hash">${esc(banner.chPolicy)}</code></dd>
          <dt>request_hash</dt><dd><code data-ioi-challenge="request_hash">${esc(banner.chRequest)}</code></dd>
          <dt>effect_hash</dt><dd><code data-ioi-challenge="effect_hash">${esc(banner.chEffect)}</code></dd>
        </dl>
        <div class="meta">${esc(banner.reason)}</div>
      </div>`;
  }
  if (stage === "credential") {
    return `<div class="band-result warn-band" id="ap-result" data-ioi-refusal-stage="credential" data-ioi-refusal-code="${esc(banner.chCode || banner.refused)}">
        <b>Sealed credential unresolved (HTTP ${esc(banner.chStatus || "428")})</b> — <code>${esc(banner.chCode || banner.refused)}</code>
        <div class="meta">The gateway's first step refused: this crossing needs a resolvable sealed backing credential before any authority is weighed. Resolve custody, then retry — nothing crossed. ${esc(banner.reason)}</div>
      </div>`;
  }
  const stageLabel = { input: "Surface input refused (nothing sent to the daemon)", grant: "Grant intake refused (nothing sent to the daemon)", failure: "Crossing failed closed", gateway: "Daemon refusal" }[stage] || "Daemon refusal";
  return `<div class="band-result warn-band" id="ap-result" data-ioi-refusal-stage="${esc(stage)}" data-ioi-refusal-code="${esc(banner.chCode || banner.refused)}">
      <b>${esc(stageLabel)}${banner.chStatus ? ` (HTTP ${esc(banner.chStatus)})` : ""}</b> — <code>${esc(banner.chCode || banner.refused)}</code>
      <div class="meta">${esc(banner.reason)} The refusal is typed and rendered verbatim; nothing advanced and no success is inferred.</div>
    </div>`;
}

// Inventory over the compact projection — the daemon's own states pass through VERBATIM.
function inventoryBlock(inventory, base) {
  if (!inventory) return "";
  if (!inventory.ok) {
    if (inventory.kind === "refusal" || inventory.kind === "not_found") {
      const code = inventory.code || "untyped";
      const stop = code === "system_projection_source_incomplete"
        ? `<div class="meta">The local and Agentgres admission censuses disagree, so the projection fails CLOSED: no partial or plausible list is rendered until the owners reconcile. This stop is the daemon's own refusal, verbatim.</div>`
        : "";
      return `<div class="empty" data-ioi-projection-state="${esc(code)}">
          <b>Projection refused (HTTP ${esc(String(inventory.status || 0))})</b> — <code>${esc(code)}</code>
          <div style="margin-top:6px">${esc(inventory.message || "")}</div>${stop}
        </div>${inventory.refusal ? jsonPre(inventory.refusal) : ""}`;
    }
    return `<div data-ioi-projection-state="unavailable">${degradedBand(inventory, "Systems inventory")}
      <p class="sub" style="margin-top:10px">Zero rows are rendered. Inventory membership comes only from the daemon's read projection; nothing is cached or substituted while it is unreachable.</p></div>`;
  }
  const payload = inventory.payload || {};
  if (payload.state === "honest_empty") {
    return `<div class="empty" data-ioi-projection-state="honest_empty">
        <b>No admitted Systems exist</b> — the projection reports <code>honest_empty</code> from <code>${esc(payload.projection_source || "")}</code>. Nothing is fixtured or defaulted; a System exists only after a receipted genesis admission reaches its live chain.
      </div>
      <div class="meta" style="margin:8px 0 0">The projection's own response, verbatim (its nonclaims are daemon-declared):</div>${jsonPre(payload)}`;
  }
  const systems = Array.isArray(payload.systems) ? payload.systems : [];
  const rows = systems.map((system) => {
    const tail = String(system.source_record_tail || "");
    const link = KEY_RE.test(tail)
      ? `<a href="${esc(`${base}?system=${tail}`)}">${esc(system.system_id || "")}</a>`
      : esc(system.system_id || "");
    return `<tr data-ioi-system-row="${esc(system.system_id || "")}">
        <td>${link}</td>
        <td>${pill(system.status === "active" ? "ok" : "warn", String(system.status || "unknown"))}</td>
        <td><code>${esc(String(system.latest_sequence ?? ""))}</code></td>
        <td><code>${esc(system.genesis_ref || "")}</code></td>
        <td><code>${esc(system.evidence_refs?.latest_receipt_ref || "")}</code></td>
      </tr>`;
  }).join("");
  return `<div data-ioi-projection-state="${esc(String(payload.state || ""))}">
      <p class="sub">${systems.length} System${systems.length === 1 ? "" : "s"} — rebuilt per request from <code>${esc(payload.projection_source || "")}</code> (<code>${esc(payload.schema_version || "")}</code>).</p>
      <table><thead><tr><th>System</th><th>Status</th><th>Seq</th><th>Genesis</th><th>Latest receipt</th></tr></thead><tbody>${rows}</tbody></table>
    </div>`;
}

// One disabled authority verb with its named reason — a disabled control grants nothing and
// hides nothing: the reason states exactly why the verb does not cross here yet.
function disabledVerb(label, reason) {
  return `<button class="act" disabled data-ioi-disabled-reason="${esc(reason)}">${esc(label)}</button>`;
}

const W2_VERB_REASON = "authority-crossing verb not wired in this cut: only genesis compose and sequence-zero cross through the shared CapabilityLease client today; this verb lands on the same client in the W2 continuation — read-first until then, never a second mutation path";

const OQ9_REASON = "OQ-9: HypervisorSystemInterfaceBinding has a registered schema and zero rows and zero routes — no durable System interface binding plane exists, so interface launch stays disabled until the W3 interface-binding plane lands; /systems/{system_id}/interfaces/{system_binding_id} is unresolvable today";

function interfacesPane() {
  return `<h2 id="interfaces">Interfaces</h2>
    <div class="card" style="display:block" data-ioi-pane="interfaces" data-ioi-pane-state="disabled_named_gap">
      <div class="meta">A System-bound interface resolves under <code>/systems/{system_id}/interfaces/{system_binding_id}</code> and must bind an admitted package release, installation, System/context, allowed-action, and authority-preview contract before launch. That binding plane does not exist yet — the schema is registered, the record set carries zero rows, and no route serves or resolves a binding — so this mode is a disabled named gap, not an empty list.</div>
      <div style="margin-top:8px">${disabledVerb("Launch System interface", OQ9_REASON)}</div>
    </div>`;
}

// A read-first pane over one daemon read: payload verbatim on success, typed code verbatim on
// refusal. `state` stamps machine-readably what this render is.
function readPane(name, result, { title, note, disabled = [] }) {
  let body;
  let state;
  if (!result) {
    state = "not_loaded";
    body = `<div class="empty">not loaded</div>`;
  } else if (result.ok) {
    state = "read";
    body = jsonPre(result.payload);
  } else if (result.kind === "unavailable" || result.kind === "cancelled") {
    state = "unavailable";
    body = degradedBand(result, title);
  } else {
    state = result.code || "untyped_refusal";
    body = `<div class="empty"><b>${esc(title)}</b> — the daemon refused this read (HTTP ${esc(String(result.status || 0))}): <code>${esc(result.code || "untyped")}</code> ${esc(result.message || "")}. Refusal verbatim; nothing substituted.</div>${result.refusal ? jsonPre(result.refusal) : ""}`;
  }
  const controls = disabled.length
    ? `<div style="margin-top:8px">${disabled.map(([label, reason]) => disabledVerb(label, reason)).join(" ")}</div>`
    : "";
  return `<div class="card" style="display:block" data-ioi-pane="${esc(name)}" data-ioi-pane-state="${esc(state)}">
      <div class="row"><b>${esc(title)}</b></div>
      ${note ? `<div class="meta">${note}</div>` : ""}
      ${body}${controls}
    </div>`;
}

// The Govern-mode preview: where each governed stage of THIS System stands, as live reads.
// Preview, not authority — a refusal renders verbatim and never implies progress; approvals
// are wallet acts consumed by the daemon routes, never a surface act.
function governPreview(detail) {
  const stages = [
    ["admission", "Genesis admission", detail.admission, (b) => b?.autonomous_system_genesis_receipt?.receipt_ref],
    ["sequence_zero", "Sequence-zero materialization", detail.sequenceZero, (b) => b?.autonomous_system_sequence_zero_materialization_receipt?.receipt_ref],
    ["initialize", "Initialize (sequence 1)", detail.initialize, (b) => b?.lifecycle_receipt?.receipt_ref || b?.receipt?.receipt_ref],
    ["activate", "Activate (sequence 2)", detail.activate, (b) => b?.activation_receipt?.receipt_ref || b?.lifecycle_receipt?.receipt_ref || b?.receipt?.receipt_ref],
  ];
  const rows = stages.map(([key, label, result, receiptOf]) => {
    if (!result) return "";
    if (result.ok) {
      return `<tr data-ioi-ladder-stage="${key}" data-ioi-ladder-state="admitted"><td>${esc(label)}</td><td>${pill("ok", "admitted")}</td><td><code>${esc(receiptOf(result.payload) || "")}</code></td></tr>`;
    }
    if (result.kind === "unavailable") {
      return `<tr data-ioi-ladder-stage="${key}" data-ioi-ladder-state="unavailable"><td>${esc(label)}</td><td>${pill("warn", "daemon unreachable")}</td><td><code>${esc(result.code)}</code></td></tr>`;
    }
    return `<tr data-ioi-ladder-stage="${key}" data-ioi-ladder-state="refused"><td>${esc(label)}</td><td>${pill("muted", "not admitted")}</td><td><code>${esc(result.code || "untyped")}</code> ${esc(result.message || "")}</td></tr>`;
  }).join("");
  return `<h2 id="govern">Govern — preview</h2>
    <div class="card" style="display:block" data-ioi-pane="govern-preview" data-ioi-pane-state="read">
      <div class="meta"><b>Preview, not authority.</b> Each row is a live daemon read of one governed stage; a refusal renders verbatim and never implies progress. Approval is a wallet grant consumed by the owning daemon route — Governance holds the approval verbs, this workspace only surfaces where the ladder stands.</div>
      <table><thead><tr><th>Governed stage</th><th>State</th><th>Owner evidence / refusal</th></tr></thead><tbody>${rows}</tbody></table>
    </div>`;
}

function sequenceZeroForm(system, base) {
  return `<details class="card" style="display:block"><summary style="cursor:pointer"><b>Materialize sequence zero</b> <span class="meta" style="display:inline">crosses through the shared CapabilityLease client — 403 challenge / 428 credential / receipted crossing render above</span></summary>
      <form method="post" action="${esc(`${LEGACY_ROUTE}/actions/sequence-zero`)}" style="margin-top:10px">
        <input type="hidden" name="system" value="${esc(system)}">
        <input type="hidden" name="return" value="${esc(`${LEGACY_ROUTE}?system=${system}`)}">
        <div class="field"><label>expected_genesis_admission_record_root (owner fact from the admission you inspected)</label>
          <input name="expected_genesis_admission_record_root" placeholder="sha256:…"></div>
        <div class="field"><label>expected_genesis_admission_receipt_root</label>
          <input name="expected_genesis_admission_receipt_root" placeholder="sha256:…"></div>
        <div class="field"><label>wallet_approval_grant (optional JSON — omit to receive the authority challenge)</label>
          <textarea name="wallet_approval_grant"></textarea></div>
        <button class="act" type="submit">Submit crossing</button>
      </form>
      <div class="meta">Deep link: <a href="${esc(`${base}?system=${system}`)}">${esc(`${base}?system=${system}`)}</a></div>
    </details>`;
}

function genesisComposeForm() {
  return `<h2 id="compose">Blank-to-genesis — compose</h2>
    <details class="card" style="display:block" open><summary style="cursor:pointer"><b>Genesis compose</b> <span class="meta" style="display:inline">POST ${esc(API)} through the shared CapabilityLease client</span></summary>
      <form method="post" action="${esc(`${LEGACY_ROUTE}/actions/genesis-compose`)}" style="margin-top:10px">
        <input type="hidden" name="return" value="${esc(LEGACY_ROUTE)}">
        <div class="field"><label>Package + genesis declaration (JSON: <code>{"release": …, "proposed_instantiation": …}</code>)</label>
          <textarea name="declaration" style="min-height:180px" placeholder='{"release": { … manifest release … }, "proposed_instantiation": { "schema_version": "ioi.autonomous-system-genesis-proposal-input.v1", … }}'></textarea></div>
        <div class="field"><label>wallet_approval_grant (optional JSON — omit to receive the daemon's authority challenge as an inspectable preview)</label>
          <textarea name="wallet_approval_grant"></textarea></div>
        <button class="act" type="submit">Submit crossing</button>
      </form>
      <div class="meta">Three honest outcomes, all rendered in the result band: a 403 wallet challenge with its hash-shaped public commitments (sign externally, resubmit the one-use grant), a typed refusal verbatim (blocker report, wallet-consumption stop, 428 sealed-credential lane), or a receipted admission. A success without its declared receipt fails closed.</div>
    </details>`;
}

function detailView(model, base) {
  const detail = model.detail || {};
  const admission = detail.admission;
  let overviewBody;
  let detailState;
  if (!admission) {
    detailState = "not_loaded";
    overviewBody = `<div class="empty">not loaded</div>`;
  } else if (admission.ok) {
    detailState = "admitted";
    const record = admission.payload?.autonomous_system_genesis_admission || {};
    const receipt = admission.payload?.autonomous_system_genesis_receipt || {};
    const advanced = model.advanced;
    let advancedBlock;
    if (!advanced) {
      advancedBlock = "";
    } else if (advanced.ok) {
      const row = (advanced.payload?.systems || [])[0];
      advancedBlock = row
        ? `<div class="meta" style="margin-top:10px">Advanced projection row (revision / lifecycle / profile refs — daemon truth, verbatim):</div>${jsonPre(row)}`
        : `<div class="empty" data-ioi-advanced-state="honest_empty" style="margin-top:10px">The advanced projection carries no row for this System — nothing substituted.</div>`;
    } else {
      advancedBlock = `<div class="empty" data-ioi-advanced-state="${esc(advanced.code || "untyped")}" style="margin-top:10px">Advanced projection refused — <code>${esc(advanced.code || "untyped")}</code>: ${esc(advanced.message || "")}. Verbatim; identity facts above come from the admission record only.</div>`;
    }
    overviewBody = `<dl class="grid">
        <dt>system_id</dt><dd><code data-ioi-detail-system-id="${esc(record.system_id || "")}">${esc(record.system_id || "")}</code></dd>
        <dt>package_id</dt><dd><code>${esc(record.package_id || "")}</code></dd>
        <dt>manifest_ref</dt><dd><code>${esc(record.manifest_ref || "")}</code></dd>
        <dt>genesis_ref</dt><dd><code>${esc(record.genesis_ref || "")}</code></dd>
        <dt>constitution_ref</dt><dd><code>${esc(record.authorized_genesis?.constitution_ref || "")}</code></dd>
        <dt>proposal_root</dt><dd><code>${esc(record.proposal_root || "")}</code></dd>
        <dt>admission receipt</dt><dd><code>${esc(receipt.receipt_ref || "")}</code></dd>
        <dt>governing authority</dt><dd><code>${esc(record.governing_authority_ref || "")}</code></dd>
      </dl>${advancedBlock}`;
  } else if (admission.kind === "unavailable") {
    detailState = "unavailable";
    overviewBody = degradedBand(admission, "System admission record");
  } else {
    detailState = admission.code || "untyped_refusal";
    overviewBody = `<div class="empty">No verified admission renders at this key — <code>${esc(admission.code || "untyped")}</code> (HTTP ${esc(String(admission.status || 0))}): ${esc(admission.message || "")}. The refusal is the daemon's own, verbatim; nothing is substituted and no plausible System is invented.</div>${admission.refusal ? jsonPre(admission.refusal) : ""}`;
  }

  return `<p class="sub"><a href="${esc(base)}">← Systems inventory</a></p>
    <h2 id="overview">Overview</h2>
    <div class="card" style="display:block" data-ioi-pane="overview" data-ioi-detail-state="${esc(detailState)}">
      <div class="row"><b>System <code>${esc(model.system.slice(0, 20))}…</code></b></div>
      ${overviewBody}
    </div>
    ${governPreview(detail)}
    <h2 id="operate">Operate — desired vs observed</h2>
    ${readPane("membership-projection", detail.membership, {
      title: "Observed membership (live projection)",
      note: "The daemon's membership projection for this System — observed truth, verbatim.",
      disabled: [["Membership operation (join / fence / remove)", W2_VERB_REASON]],
    })}
    ${readPane("topology-minimum", detail.topology, {
      title: "Desired topology (declared minimum)",
      note: "The declared minimum topology this System must hold — desired truth, verbatim. Divergence between the two panes is the operator's signal; this surface computes no reconciliation of its own.",
      disabled: [["Declare desired topology", W2_VERB_REASON]],
    })}
    <h2 id="writer">Writer / failover</h2>
    ${readPane("writer-epoch", detail.writerEpoch, {
      title: "Writer epoch",
      note: "The chain writer's epoch state, read-first.",
      disabled: [["Writer transition (failover / handoff)", W2_VERB_REASON], ["Declare failover profile", W2_VERB_REASON]],
    })}
    ${readPane("writer-lost-suffixes", detail.writerLostSuffixes, {
      title: "Lost suffixes",
      note: "Suffix loss evidence and resolution state, read-first.",
    })}
    <h2 id="amendments">Amendments</h2>
    ${readPane("amendments", detail.amendments, {
      title: "Constitutional amendments",
      note: "The amendment history for this System's constitution, read-first.",
      disabled: [["Execute approved amendment", W2_VERB_REASON]],
    })}
    ${interfacesPane()}
    <h2 id="actions">Governed actions</h2>
    ${sequenceZeroForm(model.system, base)}
    <div class="card" style="display:block"><div class="meta">Remaining ladder verbs, disabled with their named reason (never hidden, never a second mutation path):</div>
      <div style="margin-top:8px">${disabledVerb("Initialize (sequence 1)", W2_VERB_REASON)} ${disabledVerb("Activate (sequence 2)", W2_VERB_REASON)} ${disabledVerb("Protected transition", W2_VERB_REASON)} ${disabledVerb("Continuity transition", W2_VERB_REASON)} ${disabledVerb("Amendment execution", W2_VERB_REASON)}</div>
    </div>`;
}

// ---------------------------------------------------------------------------------------------
export function render(model, ctx) {
  const onLegacyMount = ctx.url.pathname.startsWith("/__ioi/");
  const base = onLegacyMount ? LEGACY_ROUTE : CANONICAL_ROUTE;
  let bodyHtml;
  if (model.systemInvalid) {
    bodyHtml = `<p class="sub"><a href="${esc(base)}">← Systems inventory</a></p>
      <div class="empty" data-ioi-detail-state="system_key_invalid"><b>Not a canonical System key</b> — '<code>${esc(model.rawSystem)}</code>' is not <code>asg_&lt;64 hex&gt;</code>. Nothing is looked up and nothing is substituted; this is a surface-owned input refusal, not daemon truth.</div>`;
  } else if (model.system) {
    bodyHtml = detailView(model, base);
  } else {
    bodyHtml = `<h2 id="inventory">Systems inventory</h2>
      ${inventoryBlock(model.inventory, base)}
      ${genesisComposeForm()}
      ${interfacesPane()}`;
  }
  const head = `<h1>Systems</h1>
    <p class="sub">The stable inventory and contextual workspace for live constitution-bound autonomous institutions. Every fact below is a live read of daemon-owned truth — no fabricated System rows before honest read models, and presentation grants no authority, admission, activation, membership, network assurance, or runtime effect. This surface is a greenfield build on the typed non-parity lane (<code>seed-ux-provenance.v1.json</code>): it claims no seed preservation and no parity.</p>`;
  const css = `:root{color-scheme:dark}
  body{margin:0;background:#0c0d10;color:#e6e7ea;font:14px/1.55 -apple-system,Segoe UI,Roboto,sans-serif}
  .wrap{max-width:1020px;margin:0 auto;padding:32px 24px 80px}
  a{color:#8ab4ff}
  h1{font-size:26px;margin:0 0 6px;letter-spacing:-.02em}
  .sub{color:#9a9da6;margin:0 0 18px;max-width:860px}
  h2{font-size:13px;letter-spacing:.04em;text-transform:uppercase;color:#878a93;margin:26px 0 10px;font-weight:600}
  .card{padding:13px 16px;border:1px solid #24262d;border-radius:12px;background:#15171c;margin-bottom:10px;color:inherit}
  .card .row{font-weight:600;color:#fff;margin-bottom:4px}
  .meta{color:#878a93;font-size:12.5px;margin-top:3px;overflow-wrap:anywhere}
  .pill{display:inline-block;padding:2px 9px;border-radius:999px;font-size:11px;border:1px solid;white-space:nowrap}
  .ok{color:#46c277;border-color:#235c3b;background:#11281b}
  .warn{color:#d6a13a;border-color:#5c4a23;background:#28220f}
  .muted{color:#9a9da6;border-color:#2a2c33}
  .empty{color:#8a8d96;padding:16px;border:1px dashed #24262d;border-radius:12px}
  code{font-size:11.5px;color:#aab;background:#0e0f13;padding:1px 5px;border-radius:4px;overflow-wrap:anywhere}
  pre{background:#0e0f13;border:1px solid #24262d;border-radius:8px;padding:12px;overflow:auto;font:11.5px/1.5 ui-monospace,monospace;color:#cdd1d8;white-space:pre-wrap;word-break:break-all;max-height:340px}
  table{width:100%;border-collapse:collapse;font-size:12.5px;margin-top:6px}
  th{color:#6f7280;text-align:left;font-weight:600;padding:6px 8px;border-bottom:1px solid #24262d;font-size:11.5px;text-transform:uppercase;letter-spacing:.03em}
  td{padding:7px 8px;border-bottom:1px solid #1b1d23;vertical-align:top}
  dl.grid{display:grid;grid-template-columns:minmax(150px,220px) 1fr;gap:4px 14px;margin:10px 0 0}
  dl.grid dt{color:#6f7280;font-size:12px}
  dl.grid dd{margin:0;overflow-wrap:anywhere}
  .field{margin:0 0 10px}
  .field label{display:block;color:#878a93;font-size:12px;margin-bottom:4px}
  .field input,.field textarea{width:100%;box-sizing:border-box;background:#0e0f13;border:1px solid #24262d;border-radius:8px;color:#e6e7ea;padding:8px 10px;font:12.5px/1.5 ui-monospace,monospace;min-height:34px}
  .field textarea{min-height:64px;resize:vertical}
  button.act{background:#1d2f52;border:1px solid #3a82f6;color:#cfe0ff;border-radius:8px;padding:7px 14px;font-size:13px;cursor:pointer}
  button.act[disabled]{background:#15171c;border-color:#2a2c33;color:#6f7280;cursor:not-allowed}
  .band-result{border:1px solid;border-radius:12px;padding:13px 16px;margin:0 0 16px}
  .ok-band{border-color:#235c3b;background:#0f2015}
  .warn-band{border-color:#5c4a23;background:#1f1a0d}
  .foot{color:#6f7280;font-size:12.5px;margin-top:28px;border-top:1px solid #1b1d23;padding-top:14px}
  @media(max-width:700px){.wrap{padding:24px 14px 56px}dl.grid{grid-template-columns:1fr}}`;
  const foot = `<div class="foot">Truth sources: inventory + detail projections <code>GET ${esc(API)}/projection</code> (<code>${esc(PROJECTION_SCHEMA)}</code>, honest-empty and fail-closed stops verbatim); admission/ladder/membership/topology/writer/amendment reads on <code>${esc(API)}/:id/*</code>. Authority crossings ride the shared CapabilityLease client only — receipts prove crossings, refusals render typed, disabled verbs name their gap.</div>`;
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Systems · Hypervisor</title><style>${css}</style></head>
<body><div class="wrap">${head}${bannerBlock(model.banner || {})}${bodyHtml}${foot}</div></body></html>`;
}
