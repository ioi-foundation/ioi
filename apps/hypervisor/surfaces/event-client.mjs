// W0.4 — the event client on the M5 durable plane. ONE way for product surfaces to
// consume events. New consumption rides `/v1/subscriptions` (+ the `/v1/event-streams`
// plane those leases are issued over); per-resource SSE is LEGACY — wrapped by
// `wrapLegacySse` below, never extended. Wave 1/2 surfaces consume ONE interface in
// both lanes and legacy call sites migrate by swapping the constructor.
//
// The daemon contract this binds to, at the bytes
// (crates/node/src/bin/hypervisor_daemon_routes/event_stream_routes.rs; registrations
// crates/node/src/bin/hypervisor-daemon.rs:2350-2381):
//   POST /v1/subscriptions
//     { owner_namespace, stream_tail, subscriber_ref, lease_tail,
//       permitted_event_class_ids[], max_undelivered_events, expires_at_ms? }
//     → the lease view (projection-subscription-lease.v1): lease_state,
//       acknowledged_checkpoint { acknowledged_seq, acknowledged_head_ref }, backpressure.
//   GET  /v1/subscriptions/:ns/:lease_tail            → the lease, exactly (404 typed).
//   GET  /v1/subscriptions/:ns/:lease_tail/delivery   → pull delivery from the DURABLE
//     acknowledged checkpoint forward: { events:[{seq, head_ref, payload:{class_id,
//     payload_schema_ref, payload}}], pending_total, backpressure_window,
//     delivery_outcome: "drained"|"bounded_by_backpressure_window", resume_after_seq }.
//   POST /v1/subscriptions/:ns/:lease_tail/checkpoint { acknowledged_seq } — forward-only,
//     admitted-seqs-only; rewind and substitution are typed daemon refusals.
//   POST /v1/subscriptions/:ns/:lease_tail/revoke     → lease_state "revoked".
// Delivery on the durable plane is PULL: resume needs no client-held cursor — the
// daemon re-delivers from the admitted checkpoint (event_stream_routes.rs:691-706).
//
// The contract (honesty first, same taxonomy discipline as the W0.3 clients):
//   - EVERY event handed to `onEvent` is one shape in BOTH lanes:
//       { lane, delivery, seq, head_ref, class_id, payload_schema_ref, payload, at }
//     Durable events carry the admitted seq/head; legacy SSE events carry seq:null,
//     head_ref:null, delivery:"legacy_sse" — absence stays absent, never invented.
//   - Connection state is TYPED and always visible: `onState` fires on every
//     transition and `state()` returns the current one:
//       { state:"live",               at, lane, checkpoint, delivery_outcome?, pending_total? }
//       { state:"resuming",           at, lane, attempt, reason, last_live_at }
//       { state:"daemon_unavailable", at, lane, code, message, attempt, retry_in_ms, last_live_at }
//       { state:"refused",            at, lane, status, code, message, refusal, last_live_at }
//       { state:"stopped",            at, lane, last_live_at }
//     NO silent retry loop: while the daemon is down the state says so (with the
//     bounded backoff delay visible) and `last_live_at` dates what the consumer
//     holds — stale is never presented as live.
//   - `refused` is TERMINAL: a typed daemon refusal (revoked/expired lease, refused
//     checkpoint, 4xx) is a fact to surface, not a condition to retry through.
//   - Checkpoints are the daemon's own coordinates ({acknowledged_seq,
//     acknowledged_head_ref}). `subscribe` ACCEPTS a previously persisted token and
//     advances the lease to it before first delivery; `onCheckpoint`/`checkpoint()`
//     hand every advance back for persistence. The legacy lane has NO checkpoint —
//     `checkpoint()` is null there; grafting one on would be extending SSE.
//   - At-least-once delivery is deduplicated by admitted seq client-side, so a
//     checkpoint POST lost to the network never double-dispatches an event.
//
// Usable from BOTH lanes like the W0.3 clients: no node: imports; fetch and the
// daemon base are injectable. The legacy wrap parses text/event-stream off an
// injectable fetch (the same idiom the vendored conversation-stream consumer uses)
// instead of holding a browser EventSource, so its lifecycle stays typed here.
import { readJsonWithDeadline } from "./plane-read.mjs";
import { defaultDaemonBase } from "./read-client.mjs";

const DEFAULT_TIMEOUT_MS = 8000; // matches the read client's daemon deadline
const DEFAULT_POLL_MS = 2000; // idle delivery-poll cadence on the durable plane
const DEFAULT_BACKOFF_BASE_MS = 1000;
const DEFAULT_BACKOFF_MAX_MS = 30000; // the bound in "bounded backoff"

const iso = () => new Date().toISOString();
const trim = (value, max = 300) => String(value == null ? "" : value).slice(0, max);

const refusalCode = (payload, status) =>
  payload?.error?.code || payload?.reason || payload?.code || `http_${status}`;
const refusalMessage = (payload, status) =>
  trim(payload?.error?.message || payload?.message || payload?.reason
    || `the daemon answered ${status} without a typed body`);

// Accept a persisted checkpoint token as the daemon's own object or a bare seq.
function normalizeCheckpoint(token) {
  if (token == null) return null;
  if (typeof token === "number" && Number.isFinite(token) && token >= 0) {
    return { acknowledged_seq: token, acknowledged_head_ref: null };
  }
  if (typeof token === "object" && Number.isFinite(token.acknowledged_seq)) {
    return {
      acknowledged_seq: token.acknowledged_seq,
      acknowledged_head_ref: token.acknowledged_head_ref ?? null,
    };
  }
  return null;
}

// One subscription lifecycle (shared by both constructors): typed state, bounded
// backoff arithmetic, and the no-stale-as-live invariant live here exactly once.
function lifecycle(lane, handlers, { backoffBaseMs, backoffMaxMs }) {
  let current = { state: "resuming", at: iso(), lane, attempt: 0, reason: "subscribing", last_live_at: null };
  let lastLiveAt = null;
  let attempt = 0;
  const emit = (next) => {
    current = next;
    try { handlers.onState?.(next); } catch { /* a consumer's handler fault never breaks the loop */ }
  };
  return {
    state: () => current,
    isTerminal: () => current.state === "refused" || current.state === "stopped",
    live(extra = {}) {
      attempt = 0;
      lastLiveAt = iso();
      emit({ state: "live", at: lastLiveAt, lane, ...extra });
    },
    resuming(reason) {
      emit({ state: "resuming", at: iso(), lane, attempt, reason: trim(reason, 120), last_live_at: lastLiveAt });
    },
    // Bounded backoff: the delay doubles per consecutive failure and is capped at
    // backoffMaxMs; the scheduled delay is IN the state so no retry is silent.
    unavailable(code, message) {
      attempt += 1;
      const retry_in_ms = Math.min(backoffBaseMs * 2 ** (attempt - 1), backoffMaxMs);
      emit({
        state: "daemon_unavailable", at: iso(), lane,
        code, message: trim(message), attempt, retry_in_ms, last_live_at: lastLiveAt,
      });
      return retry_in_ms;
    },
    refused(status, payload) {
      emit({
        state: "refused", at: iso(), lane, status,
        code: refusalCode(payload, status),
        message: refusalMessage(payload, status),
        refusal: payload && typeof payload === "object" ? payload : null,
        last_live_at: lastLiveAt,
      });
    },
    stopped() {
      if (current.state === "refused") return; // a terminal refusal stays visible
      emit({ state: "stopped", at: iso(), lane, last_live_at: lastLiveAt });
    },
  };
}

/// Subscribe on the M5 durable plane. Adopts the lease at
/// `/v1/subscriptions/{owner_namespace}/{lease_tail}` when it already exists
/// (the restart path), creates it otherwise, then pulls `/delivery` from the
/// admitted checkpoint forward and acknowledges via `/checkpoint`.
///
/// spec: { owner_namespace, stream_tail, subscriber_ref, lease_tail,
///         permitted_event_class_ids, max_undelivered_events, expires_at_ms?,
///         checkpoint?,                    — persisted token to resume from
///         onEvent(event), onState(state), onCheckpoint(token)? }
/// Returns synchronously: { lane:"durable", state(), checkpoint(), stop(), revoke() }.
export function subscribeDurable(
  {
    daemon = defaultDaemonBase(),
    fetchImpl = globalThis.fetch,
    timeoutMs = DEFAULT_TIMEOUT_MS,
    pollMs = DEFAULT_POLL_MS,
    backoffBaseMs = DEFAULT_BACKOFF_BASE_MS,
    backoffMaxMs = DEFAULT_BACKOFF_MAX_MS,
  } = {},
  spec,
) {
  const { owner_namespace, stream_tail, lease_tail } = spec;
  const base = `${daemon}/v1/subscriptions`;
  const leasePath = `${base}/${owner_namespace}/${lease_tail}`;
  const life = lifecycle("durable", spec, { backoffBaseMs, backoffMaxMs });

  let stopped = false;
  let timer = null;
  let checkpoint = normalizeCheckpoint(spec.checkpoint);
  let dispatchedThrough = checkpoint?.acknowledged_seq ?? -1;

  const call = async (method, url, body) => {
    try {
      const init = method === "GET"
        ? {}
        : { method, headers: { "content-type": "application/json" }, body: JSON.stringify(body ?? {}) };
      const { response, payload } = await readJsonWithDeadline(fetchImpl, url, timeoutMs, init);
      return { status: response.status, payload };
    } catch (error) {
      return {
        status: 0,
        code: error?.code === "plane_timeout" ? "delivery_timeout" : "daemon_unavailable",
        message: error?.code === "plane_timeout"
          ? `the daemon did not answer within ${timeoutMs}ms`
          : "the daemon could not be reached",
      };
    }
  };

  const wait = (ms) => new Promise((resolve) => { timer = setTimeout(resolve, ms); });
  const backoff = (r) => wait(life.unavailable(r.code, r.message));

  const acknowledge = (leaseView) => {
    const ack = normalizeCheckpoint(leaseView?.acknowledged_checkpoint);
    if (!ack) return;
    if (!checkpoint || ack.acknowledged_seq > checkpoint.acknowledged_seq) {
      checkpoint = ack;
      dispatchedThrough = Math.max(dispatchedThrough, ack.acknowledged_seq);
      try { spec.onCheckpoint?.(checkpoint); } catch { /* consumer persistence fault stays theirs */ }
    }
  };

  // Phase 1 — adopt or create the lease, then advance it to an accepted token.
  const establish = async () => {
    while (!stopped) {
      life.resuming("establishing subscription lease");
      let r = await call("GET", leasePath);
      if (r.status === 404) {
        r = await call("POST", base, {
          owner_namespace,
          stream_tail,
          subscriber_ref: spec.subscriber_ref,
          lease_tail,
          permitted_event_class_ids: spec.permitted_event_class_ids,
          max_undelivered_events: spec.max_undelivered_events,
          ...(spec.expires_at_ms != null ? { expires_at_ms: spec.expires_at_ms } : {}),
        });
      }
      if (r.status === 0) { await backoff(r); continue; }
      if (r.status >= 400) { life.refused(r.status, r.payload); return false; }
      acknowledge(r.payload);
      // Resume from an ACCEPTED persisted token: advance the durable checkpoint
      // forward to it before first delivery. The daemon refuses rewinds and
      // never-admitted seqs by name — those refusals surface, they are not eaten.
      const target = normalizeCheckpoint(spec.checkpoint);
      if (target && target.acknowledged_seq > (normalizeCheckpoint(r.payload?.acknowledged_checkpoint)?.acknowledged_seq ?? -1)) {
        const adv = await call("POST", `${leasePath}/checkpoint`, { acknowledged_seq: target.acknowledged_seq });
        if (adv.status === 0) { await backoff(adv); continue; }
        if (adv.status >= 400) { life.refused(adv.status, adv.payload); return false; }
        acknowledge(adv.payload);
      }
      return true;
    }
    return false;
  };

  // Phase 2 — pull delivery from the durable checkpoint, dispatch in admitted
  // order (deduplicated by seq), acknowledge what was dispatched.
  const consume = async () => {
    while (!stopped) {
      const r = await call("GET", `${leasePath}/delivery`);
      if (stopped) return;
      if (r.status === 0) { await backoff(r); life.resuming("re-polling delivery after outage"); continue; }
      if (r.status >= 400) { life.refused(r.status, r.payload); return; }

      const events = Array.isArray(r.payload?.events) ? r.payload.events : [];
      let dispatchedTo = null;
      for (const entry of events) {
        if (!Number.isFinite(entry?.seq) || entry.seq <= dispatchedThrough) continue;
        dispatchedThrough = entry.seq;
        dispatchedTo = entry.seq;
        const envelope = entry.payload && typeof entry.payload === "object" ? entry.payload : {};
        try {
          spec.onEvent?.({
            lane: "durable",
            delivery: "admitted",
            seq: entry.seq,
            head_ref: entry.head_ref ?? null,
            class_id: envelope.class_id ?? null,
            payload_schema_ref: envelope.payload_schema_ref ?? null,
            payload: "payload" in envelope ? envelope.payload : null,
            at: iso(),
          });
        } catch { /* a consumer's handler fault never breaks the loop */ }
      }
      if (dispatchedTo != null) {
        const adv = await call("POST", `${leasePath}/checkpoint`, { acknowledged_seq: dispatchedTo });
        if (adv.status === 0) {
          // The acknowledgement was lost, not the events: seq-dedupe absorbs the
          // re-delivery and the advance is retried on the next dispatch.
          await backoff(adv);
          life.resuming("retrying checkpoint acknowledgement");
          continue;
        }
        if (adv.status >= 400) { life.refused(adv.status, adv.payload); return; }
        acknowledge(adv.payload);
      }
      life.live({
        checkpoint,
        delivery_outcome: r.payload?.delivery_outcome ?? null,
        pending_total: r.payload?.pending_total ?? null,
      });
      // A window-bounded delivery has admitted events still pending: drain now
      // rather than idling a poll interval on top of declared backpressure.
      if (r.payload?.delivery_outcome !== "bounded_by_backpressure_window") await wait(pollMs);
    }
  };

  (async () => { if (await establish()) await consume(); })();

  return {
    lane: "durable",
    state: () => life.state(),
    checkpoint: () => checkpoint,
    stop: () => {
      stopped = true;
      clearTimeout(timer);
      life.stopped(); // the durable lease outlives the handle — that is what resumable means
    },
    // The plane's fourth operation, for Wave 2 consumers that retire a lease.
    revoke: async () => {
      stopped = true;
      clearTimeout(timer);
      const r = await call("POST", `${leasePath}/revoke`, {});
      if (r.status === 0) { life.unavailable(r.code, r.message); return { ok: false, code: r.code }; }
      if (r.status >= 400) { life.refused(r.status, r.payload); return { ok: false, code: refusalCode(r.payload, r.status) }; }
      life.stopped();
      return { ok: true, lease_state: r.payload?.lease_state ?? "revoked" };
    },
  };
}

// Minimal SSE frame parser: `event:`/`data:` fields, multi-line data, comment
// keepalives. Frames are split on blank lines per the wire format.
function parseSseFrame(block) {
  let event = "message";
  const data = [];
  for (const line of block.split(/\r?\n/)) {
    if (line === "" || line.startsWith(":")) continue; // comment = keepalive, not an event
    if (line.startsWith("event:")) event = line.slice(6).trim();
    else if (line.startsWith("data:")) data.push(line.slice(5).replace(/^ /, ""));
  }
  if (data.length === 0) return null;
  const raw = data.join("\n");
  let payload;
  try { payload = JSON.parse(raw); } catch { payload = raw; }
  return { event, payload };
}

/**
 * Wrap ONE existing per-resource SSE endpoint (e.g. the serve layer's
 * `/__ioi/agent-runs/:id/conversation/live`, serve-product-ui.mjs:10298) behind
 * the SAME consumer interface as `subscribeDurable`: identical event shape,
 * identical typed lifecycle states, identical handle. The legacy lane has no
 * admitted seq, no head, and no durable checkpoint — those are null here, not
 * imitated, because grafting them on would be extending SSE.
 *
 * @deprecated Legacy per-resource SSE is wrapped, not extended (master guide §2
 * W0.4; run charter ground truths). New consumption rides the durable plane —
 * migrate a call site by swapping this constructor for `subscribeDurable`; the
 * consumer never changes.
 *
 * handlers: { onEvent(event), onState(state) }
 * Returns synchronously: { lane:"legacy_sse", state(), checkpoint():null, stop() }.
 */
export function wrapLegacySse(
  url,
  handlers = {},
  {
    fetchImpl = globalThis.fetch,
    backoffBaseMs = DEFAULT_BACKOFF_BASE_MS,
    backoffMaxMs = DEFAULT_BACKOFF_MAX_MS,
  } = {},
) {
  const life = lifecycle("legacy_sse", handlers, { backoffBaseMs, backoffMaxMs });
  let stopped = false;
  let timer = null;
  let controller = null;

  const dispatch = (frame) => {
    try {
      handlers.onEvent?.({
        lane: "legacy_sse",
        delivery: "legacy_sse",
        seq: null,
        head_ref: null,
        class_id: frame.event,
        payload_schema_ref: null,
        payload: frame.payload,
        at: iso(),
      });
    } catch { /* a consumer's handler fault never breaks the loop */ }
  };

  (async () => {
    while (!stopped) {
      controller = new AbortController();
      let response;
      try {
        response = await fetchImpl(url, {
          headers: { accept: "text/event-stream" },
          signal: controller.signal,
        });
      } catch {
        if (stopped) return;
        await new Promise((resolve) => { timer = setTimeout(resolve, life.unavailable("daemon_unavailable", "the legacy SSE endpoint could not be reached")); });
        continue;
      }
      if (!response.ok) {
        // A typed HTTP answer is a refusal, terminal — retrying a 4xx forever is
        // the silent loop this client exists to make impossible.
        let payload = null;
        try { payload = await response.json(); } catch { /* refusal body optional on the legacy lane */ }
        life.refused(response.status, payload);
        return;
      }
      life.live({ checkpoint: null });
      try {
        const reader = response.body.getReader();
        const decoder = new TextDecoder("utf-8");
        let buffer = "";
        for (;;) {
          const { done, value } = await reader.read();
          if (done || stopped) break;
          buffer += decoder.decode(value, { stream: true });
          let cut;
          while ((cut = buffer.search(/\r?\n\r?\n/)) !== -1) {
            const block = buffer.slice(0, cut);
            buffer = buffer.slice(cut).replace(/^\r?\n\r?\n/, "");
            const frame = parseSseFrame(block);
            if (frame) dispatch(frame);
          }
        }
      } catch { /* stream broke mid-read: fall through to the typed resume below */ }
      if (stopped) return;
      // EOF on the legacy lane means reconnect (the serve layer's own note:
      // "V2 live subscriptions reconnect on EOF") — visibly, with bounded backoff.
      await new Promise((resolve) => { timer = setTimeout(resolve, life.unavailable("stream_ended", "the legacy SSE stream ended; reconnecting")); });
      if (!stopped) life.resuming("reconnecting to the legacy SSE endpoint");
    }
  })();

  return {
    lane: "legacy_sse",
    state: () => life.state(),
    checkpoint: () => null, // SSE has no durable checkpoint; pretending otherwise would extend it
    stop: () => {
      stopped = true;
      clearTimeout(timer);
      try { controller?.abort(); } catch { /* already closed */ }
      life.stopped();
    },
  };
}

/// Bound-client convenience mirroring createReadClient/createAuthorityClient.
export function createEventClient(options = {}) {
  const client = {
    daemon: options.daemon ?? defaultDaemonBase(),
    fetchImpl: options.fetchImpl ?? globalThis.fetch,
    timeoutMs: options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    pollMs: options.pollMs ?? DEFAULT_POLL_MS,
    backoffBaseMs: options.backoffBaseMs ?? DEFAULT_BACKOFF_BASE_MS,
    backoffMaxMs: options.backoffMaxMs ?? DEFAULT_BACKOFF_MAX_MS,
  };
  return {
    ...client,
    subscribe: (spec) => subscribeDurable(client, spec),
    wrapLegacySse: (url, handlers) => wrapLegacySse(url, handlers, client),
  };
}
