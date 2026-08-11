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
//   2. route class   — the FINAL route (after any redirect) is a vendored-SPA route,
//                      classified by the smoke's own route authority: the
//                      V2_ROUTE_TABLE row disposition === "vendor_spa"
//                      (apps/hypervisor/scripts/v2-route-shell.mjs);
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
 * @param {{ product_lane?: string, final_route_disposition?: string, served_origin?: string }} routeContext
 *   The smoke's own classification of the inspected route: the target lane name,
 *   the V2_ROUTE_TABLE disposition of the FINAL route the page landed on, and the
 *   origin the target is served from.
 * @returns {boolean} true ONLY when every tuple element matches the recorded defect.
 */
export function isFencedWatchEventsAbort(failure, routeContext) {
  if (!failure || !routeContext) return false;
  if (routeContext.product_lane !== FENCED_PRODUCT_LANE) return false;
  if (routeContext.final_route_disposition !== "vendor_spa") return false;
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
