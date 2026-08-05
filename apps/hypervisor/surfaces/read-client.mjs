// W0.3 — the uniform read-projection client. ONE way to read daemon truth (the ~20
// `/overview` + projection endpoints and every other GET the product surfaces render).
// Usable from BOTH lanes: the serve-side readout lane (Node) and browser augmentation
// modules — no node: imports, fetch/daemon base are injectable, defaults resolve per lane.
//
// The contract (honesty first):
//   - EVERY result is one of four kinds, always with `fetched_at`:
//       { ok: true,  kind: "read",        status, payload, fetched_at }
//       { ok: false, kind: "not_found",   status (404|410), code, message, fetched_at }
//       { ok: false, kind: "refusal",     status (other 4xx/5xx), code, message, refusal, fetched_at }
//       { ok: false, kind: "unavailable", status: 0, code ("daemon_unavailable"|"read_timeout"), message, fetched_at }
//   - Degraded results carry NO data field — never a fabricated `[]`/`{}` default. A
//     renderer that wants rows must check `ok` first; absence stays absent.
//   - NO caching. Every result is a live fetch, stamped `fetched_at` (ISO). If a cache
//     is ever added it must ride the result shape explicitly (its own kind + fetched_at),
//     never silently re-serve a stale payload as live.
//   - `refusal` on typed refusals is the daemon's own body VERBATIM (already-parsed JSON)
//     so panes can render the daemon's reason/message instead of inventing one.
//
// Deadline mechanics live in plane-read.mjs (one deadline over headers AND body) — this
// module owns the error taxonomy and result shape on top of it.
import { readJsonWithDeadline } from "./plane-read.mjs";

const DEFAULT_TIMEOUT_MS = 8000; // matches the estate's adapter/serve daemon deadline

// Per-lane daemon base: serve lane honors IOI_HYPERVISOR_DAEMON_URL (adapter default
// http://127.0.0.1:8765); the browser lane uses same-origin "" so reads ride the serve
// layer's proxy exactly like the existing augmentation modules do.
export function defaultDaemonBase() {
  const env = globalThis.process?.env?.IOI_HYPERVISOR_DAEMON_URL;
  if (typeof env === "string" && env.length > 0) return env.replace(/\/$/, "");
  return typeof globalThis.window === "undefined" ? "http://127.0.0.1:8765" : "";
}

const iso = () => new Date().toISOString();
const trim = (value, max = 300) => String(value == null ? "" : value).slice(0, max);

function refusalCode(payload, status) {
  return (
    payload?.error?.code
    || payload?.reason
    || payload?.code
    || `http_${status}`
  );
}

function refusalMessage(payload, status) {
  return trim(
    payload?.error?.message
    || payload?.message
    || payload?.reason
    || `the daemon answered ${status} without a typed body`,
  );
}

/// One projection read. `path` is the daemon route (e.g. "/v1/hypervisor/operations").
export async function readProjection(
  { daemon = defaultDaemonBase(), fetchImpl = globalThis.fetch, timeoutMs = DEFAULT_TIMEOUT_MS } = {},
  path,
  init = {},
) {
  let response;
  let payload;
  try {
    ({ response, payload } = await readJsonWithDeadline(fetchImpl, `${daemon}${path}`, timeoutMs, init));
  } catch (error) {
    const timedOut = error?.code === "plane_timeout";
    return {
      ok: false,
      kind: "unavailable",
      status: 0,
      code: timedOut ? "read_timeout" : "daemon_unavailable",
      message: timedOut
        ? `the daemon did not answer ${path} within ${timeoutMs}ms`
        : `the daemon could not be reached for ${path}`,
      fetched_at: iso(),
    };
  }
  const status = response.status;
  if (response.ok) {
    return { ok: true, kind: "read", status, payload, fetched_at: iso() };
  }
  if (status === 404 || status === 410) {
    return {
      ok: false,
      kind: "not_found",
      status,
      code: refusalCode(payload, status),
      message: refusalMessage(payload, status),
      fetched_at: iso(),
    };
  }
  return {
    ok: false,
    kind: "refusal",
    status,
    code: refusalCode(payload, status),
    message: refusalMessage(payload, status),
    refusal: payload && typeof payload === "object" ? payload : null,
    fetched_at: iso(),
  };
}

/// Fan-out over named paths — the composed-readout idiom (a cockpit that renders six
/// planes). Each entry degrades INDEPENDENTLY: one down plane never poisons the others,
/// and a down plane is a typed absence in the map, never an empty default.
export async function readProjections(client, paths) {
  const entries = Object.entries(paths);
  const results = await Promise.all(entries.map(([, path]) => readProjection(client, path)));
  return Object.fromEntries(entries.map(([key], index) => [key, results[index]]));
}

/// Bound-client convenience so call sites carry one handle, not three parameters.
export function createReadClient(options = {}) {
  const client = {
    daemon: options.daemon ?? defaultDaemonBase(),
    fetchImpl: options.fetchImpl ?? globalThis.fetch,
    timeoutMs: options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
  };
  return {
    ...client,
    read: (path, init) => readProjection(client, path, init),
    readMany: (paths) => readProjections(client, paths),
  };
}
