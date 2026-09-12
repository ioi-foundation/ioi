// DEF-SPA-WATCHEVENTS-1 — the typed WatchEvents fence (next-legs IV Leg 1).
//
// THE DEFECT: the vendored SPA served on the Hypervisor product lane tears down its
// event stream nondeterministically during navigation, and the browser records
//   POST http://<served-origin>/api/gitpod.v1.EventService/WatchEvents (net::ERR_ABORTED)
// as a request failure. The product browser smoke treats every request failure as
// fatal, so this single teardown race intermittently kills otherwise-green runs.
//
// RECORDED REPRODUCTIONS (all on untouched master): PR #235, PR #237 (twice),
// PR #241 — four local reproductions — plus one full CI cycle lost
// (run 31444686784). Filed as DEF-SPA-WATCHEVENTS-1 in
// docs/architecture/_meta/canon-to-code-delta.md.
//
// THE FENCE: this predicate admits EXACTLY the recorded failure tuple and nothing
// else. Every element must match:
//   1. product lane  — the Hypervisor served-UI target ("hypervisor-owned-served-ui");
//   2. SPA shell    — the DELIVERED DOCUMENT is the vendored SPA shell, measured from
//                      the bytes the page actually returned rather than from a label.
//                      WIDENED 2026-09-12, and the widening is a correction: this element
//                      used to read the V2_ROUTE_TABLE row disposition of the final route
//                      and admit only `vendor_spa`. That proxy does not hold. `/ai` is
//                      dispositioned "shell" and `/projects` is dispositioned "vendor_spa",
//                      and the two serve BYTE-EQUIVALENT shells: both reference exactly one
//                      `/static/assets/` entry and carry `id="root"`, while genuinely owned
//                      surfaces such as `/__ioi/ontology/manager` reference neither. The
//                      route table records who OWNS the route; the fence needs to know which
//                      BUNDLE opened the stream, and the estate serves the vendored bundle at
//                      owned routes. Reproduced deterministically TWICE on the narrow context
//                      at /work/new-session, whose declared final route is /ai. The old
//                      element was not a safety property, it was a label the product does not
//                      honour — and while it stood, this abort was fatal on /ai and fenced on
//                      /projects for the same bundle doing the same thing.
//   3. same origin   — the failed request targets the served origin itself;
//   4. exact pathname — /api/gitpod.v1.EventService/WatchEvents;
//   5. method        — POST;
//   6. failure class — exactly "net::ERR_ABORTED".
// A failure missing ANY element still fails the smoke. The fence is an allowance
// for ONE known teardown race, never a blanket request-failure waiver.
//
// REMOVAL CONDITION: the real repair is the vendored SPA's event-stream teardown
// (out of scope here). The PR that lands that teardown fix MUST, in the same cut:
// delete this module and the smoke's use of it, flip the retained predicate test
// (scripts/lib/watchevents-fence.test.mjs) to assert the WatchEvents abort no
// longer occurs, and delete the DEF-SPA-WATCHEVENTS-1 ledger row.

/** The one product lane the fence applies to — the Hypervisor served-UI target. */
export const FENCED_PRODUCT_LANE = "hypervisor-owned-served-ui";

/** The exact pathname of the fenced endpoint. */
export const FENCED_WATCHEVENTS_PATHNAME =
  "/api/gitpod.v1.EventService/WatchEvents";

/** The exact browser failure class the fence admits. */
export const FENCED_FAILURE_TEXT = "net::ERR_ABORTED";

/**
 * Full-tuple allowance for DEF-SPA-WATCHEVENTS-1. Pure — no I/O, no ambient state.
 *
 * @param {{ url?: string, method?: string, error_text?: string }} failure
 *   One collected browser request failure: the request URL, its HTTP method, and
 *   the Playwright failure errorText.
 * @param {{ product_lane?: string, spa_shell_document?: boolean, served_origin?: string }} routeContext
 *   The smoke's own classification of the inspected page: the target lane name,
 *   whether the DELIVERED DOCUMENT is the vendored SPA shell (measured from the
 *   returned bytes, never from a route label), and the origin it is served from.
 * @returns {boolean} true ONLY when every tuple element matches the recorded defect.
 */
export function isFencedWatchEventsAbort(failure, routeContext) {
  if (!failure || !routeContext) return false;
  if (routeContext.product_lane !== FENCED_PRODUCT_LANE) return false;
  if (routeContext.spa_shell_document !== true) return false;
  if (typeof routeContext.served_origin !== "string") return false;
  if (failure.method !== "POST") return false;
  if (failure.error_text !== FENCED_FAILURE_TEXT) return false;
  if (typeof failure.url !== "string") return false;
  let requestUrl;
  try {
    requestUrl = new URL(failure.url);
  } catch {
    return false;
  }
  if (requestUrl.origin !== routeContext.served_origin) return false;
  if (requestUrl.pathname !== FENCED_WATCHEVENTS_PATHNAME) return false;
  return true;
}
