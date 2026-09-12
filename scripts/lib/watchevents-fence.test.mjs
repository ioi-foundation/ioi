// DEF-SPA-WATCHEVENTS-1 near-miss boundary test — RETAINED while the fence stands.
// The full-tuple allowance in scripts/lib/watchevents-fence.mjs admits exactly ONE
// recorded browser failure (the vendored SPA's WatchEvents teardown race:
// reproductions #235, #237 ×2, #241 + CI run 31444686784); every near-miss below
// proves a failure missing ANY tuple element still fails the product smoke.
// Run: npm run test:smoke-fence
// REMOVAL CONDITION: the PR that lands the vendored SPA event-stream teardown fix
// deletes the fence and FLIPS this file to assert the WatchEvents abort no longer
// occurs in the smoke.
import test from "node:test";
import assert from "node:assert/strict";
import {
  FENCED_FAILURE_TEXT,
  FENCED_PRODUCT_LANE,
  FENCED_WATCHEVENTS_PATHNAME,
  isFencedWatchEventsAbort,
} from "./watchevents-fence.mjs";
import { V2_ROUTE_TABLE } from "../../apps/hypervisor/scripts/v2-route-shell.mjs";

const SERVED_ORIGIN = "http://127.0.0.1:44173";

const recordedFailure = () => ({
  url: `${SERVED_ORIGIN}${FENCED_WATCHEVENTS_PATHNAME}`,
  method: "POST",
  error_text: FENCED_FAILURE_TEXT,
});

const recordedContext = () => ({
  product_lane: FENCED_PRODUCT_LANE,
  spa_shell_document: true,
  served_origin: SERVED_ORIGIN,
});

// ------------------------------ the recorded tuple ------------------------------

test("the exact recorded tuple PASSES the fence", () => {
  assert.equal(isFencedWatchEventsAbort(recordedFailure(), recordedContext()), true);
});

// ------------------------------ near misses: the request ------------------------------

test("wrong endpoint pathname FAILS (a different EventService verb)", () => {
  const failure = recordedFailure();
  failure.url = `${SERVED_ORIGIN}/api/gitpod.v1.EventService/ListEvents`;
  assert.equal(isFencedWatchEventsAbort(failure, recordedContext()), false);
});

test("a pathname EXTENDING the fenced endpoint FAILS (exact match, not prefix)", () => {
  const failure = recordedFailure();
  failure.url = `${SERVED_ORIGIN}${FENCED_WATCHEVENTS_PATHNAME}/extra`;
  assert.equal(isFencedWatchEventsAbort(failure, recordedContext()), false);
});

test("wrong method FAILS (GET to the same endpoint)", () => {
  const failure = recordedFailure();
  failure.method = "GET";
  assert.equal(isFencedWatchEventsAbort(failure, recordedContext()), false);
});

test("wrong failure class FAILS (net::ERR_CONNECTION_REFUSED is a real outage, never fenced)", () => {
  const failure = recordedFailure();
  failure.error_text = "net::ERR_CONNECTION_REFUSED";
  assert.equal(isFencedWatchEventsAbort(failure, recordedContext()), false);
});

test("a different origin FAILS (cross-origin WatchEvents is not the recorded defect)", () => {
  const failure = recordedFailure();
  failure.url = `http://127.0.0.1:9999${FENCED_WATCHEVENTS_PATHNAME}`;
  assert.equal(isFencedWatchEventsAbort(failure, recordedContext()), false);
});

test("a host-spelling origin mismatch FAILS (localhost is not the served 127.0.0.1 origin)", () => {
  const failure = recordedFailure();
  failure.url = `http://localhost:44173${FENCED_WATCHEVENTS_PATHNAME}`;
  assert.equal(isFencedWatchEventsAbort(failure, recordedContext()), false);
});

test("an unparseable request URL FAILS closed", () => {
  const failure = recordedFailure();
  failure.url = "not a url";
  assert.equal(isFencedWatchEventsAbort(failure, recordedContext()), false);
});

// ------------------------------ near misses: the route context ------------------------------

test("a page that is NOT the vendored SPA shell FAILS — an owned surface's own document", () => {
  const context = recordedContext();
  context.spa_shell_document = false;
  assert.equal(isFencedWatchEventsAbort(recordedFailure(), context), false);
});

test("an unmeasured shell flag FAILS closed (absent, not assumed)", () => {
  const context = recordedContext();
  delete context.spa_shell_document;
  assert.equal(isFencedWatchEventsAbort(recordedFailure(), context), false);
});

test("a TRUTHY-but-not-true shell flag FAILS closed — the element is a measurement, not a hint", () => {
  const context = recordedContext();
  context.spa_shell_document = "vendor_spa";
  assert.equal(isFencedWatchEventsAbort(recordedFailure(), context), false);
});

test("a different product lane FAILS (only the Hypervisor served UI is fenced)", () => {
  const context = recordedContext();
  context.product_lane = "aiagent-xyz";
  assert.equal(isFencedWatchEventsAbort(recordedFailure(), context), false);
});

test("a missing served origin FAILS closed", () => {
  const context = recordedContext();
  delete context.served_origin;
  assert.equal(isFencedWatchEventsAbort(recordedFailure(), context), false);
});

// ------------------------------ the classification source ------------------------------

// WHY THE ROUTE TABLE IS NO LONGER THE CLASSIFIER (2026-09-12). The fence used to read this
// table's disposition for the final route and admit only `vendor_spa`. The table is still the
// right authority for who OWNS a route — and this test keeps proving it says so — but it is the
// wrong authority for which BUNDLE is on the page, which is what makes this abort benign. `/ai`
// is a `shell` row and `/projects` is a `vendor_spa` row, and both serve the same vendored SPA
// shell; the abort was therefore fatal on one and fenced on the other for identical behaviour.
// The fence now takes a measurement of the delivered document instead, and this row records the
// table fact that made the old proxy unsound rather than deleting the evidence for it.
test("the route table still classifies OWNERSHIP, which is why it could not classify the bundle", () => {
  const dispositionByRoute = Object.fromEntries(
    V2_ROUTE_TABLE.map((surface) => [
      surface.route,
      surface.disposition ?? "shell",
    ]),
  );
  assert.equal(
    dispositionByRoute["/projects"],
    "vendor_spa",
    "the '/' route's declared final path /projects is the one vendor_spa row",
  );
  assert.equal(
    dispositionByRoute["/governance"],
    "shell",
    "an owned surface row is a shell row",
  );
  assert.equal(
    dispositionByRoute["/ai"] ?? "shell",
    "shell",
    "and /ai is a shell row while serving the same vendored bundle as /projects — the exact case that made the disposition an unsound proxy for the fence",
  );
});
