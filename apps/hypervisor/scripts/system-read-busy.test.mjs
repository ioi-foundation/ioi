// BUILD-DELTA #48 FIX-3 (MAJOR 2, the UI side): a System read the daemon answers BUSY (503,
// `system_source_read_busy`, Retry-After) is asked again by the surfaces' daemon transport, never
// sooner than Retry-After and within a total budget of at most 10 s; past that budget the page shows a
// TYPED busy state (and the workspace page answers 503 with Retry-After), never a silent degraded
// page and never a "refused". Only reads are asked again: a governed POST is sent exactly once.
// Against a stand-in daemon that records every call and its time, so what the transport DOES is
// checked, never assumed.
//
//   node --test apps/hypervisor/scripts/system-read-busy.test.mjs
import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { handleSystemGenesisSurfaces, handleSystemWorkspace } from "./system-genesis-surfaces.mjs";

const SYSTEM = "system://acme/lending";
const PROJECTION = "/v1/hypervisor/autonomous-systems/projection";
const GENESIS = "/v1/hypervisor/autonomous-systems";
const BUSY = { error: { code: "system_source_read_busy", message: "the System source reads are at their admission bound", runtimeTruthSource: "daemon-runtime" } };

// `busyFor`: how many projection reads are answered busy before one is answered ready
// (Infinity: always busy); `retryAfter`: the Retry-After the busy answers carry, in seconds.
async function standIn({ busyFor, retryAfter }) {
  const calls = [];
  const server = http.createServer((req, res) => {
    req.resume();
    req.on("end", () => {
      const url = new URL(req.url, "http://x");
      calls.push({ method: req.method, path: url.pathname, at: Date.now() });
      const busy = () => {
        res.writeHead(503, { "content-type": "application/json", "retry-after": String(retryAfter) });
        res.end(JSON.stringify(BUSY));
      };
      if (url.pathname === PROJECTION && req.method === "GET") {
        if (calls.filter((c) => c.path === PROJECTION).length <= busyFor) return busy();
        res.writeHead(200, { "content-type": "application/json" });
        return res.end(JSON.stringify({ state: "ready", systems: [{ system_id: SYSTEM, status: "active", source_record_tail: `asg_${"a".repeat(64)}` }] }));
      }
      if (url.pathname === GENESIS && req.method === "POST") return busy();
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: { code: "stand_in_route_absent", message: url.pathname } }));
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { url: `http://127.0.0.1:${server.address().port}`, calls, close: () => new Promise((resolve) => server.close(resolve)) };
}

function response() {
  const out = { status: 0, headers: {}, body: "" };
  return { out, res: { writeHead(status, headers = {}) { out.status = status; out.headers = headers; }, end(body = "") { out.body = String(body); } } };
}
const shell = (title, body) => `<title>${title}</title>${body}`;

// The Interfaces mode reads nothing past the gate, so every daemon call is the gate's.
async function interfacesPage(daemon) {
  const { out, res } = response();
  const pathname = "/__ioi/system-workspace/acme/lending/interfaces";
  const started = Date.now();
  await handleSystemWorkspace({ method: "GET", url: pathname, headers: {} }, res, pathname, { daemonUrl: daemon.url, shell });
  return { ...out, elapsed: Date.now() - started };
}

const projectionCalls = (daemon) => daemon.calls.filter((c) => c.path === PROJECTION);
const gaps = (calls) => calls.slice(1).map((c, i) => c.at - calls[i].at);
const header = (headers, name) => Object.entries(headers).find(([k]) => k.toLowerCase() === name)?.[1];
const typedBusy = (html) => html.includes('data-journey-state="unavailable_or_degraded" data-truth-code="system_source_read_busy"') && html.includes("data-daemon-busy=");

test("a busy gate read is asked again after Retry-After, and the workspace renders once a read is admitted", async () => {
  const daemon = await standIn({ busyFor: 2, retryAfter: 1 });
  try {
    const page = await interfacesPage(daemon);
    const calls = projectionCalls(daemon);
    assert.equal(calls.length, 3, "two busy answers, then the admitted read");
    assert.ok(gaps(calls).every((gap) => gap >= 950), `each read waits Retry-After (1 s) first: gaps ${gaps(calls)}`);
    assert.equal(page.status, 200);
    assert.ok(page.body.includes(`data-system-workspace-id="${SYSTEM}"`), "the workspace renders the admitted System");
    assert.ok(!page.body.includes("system_source_read_busy"), "nothing busy is left on the page");
  } finally {
    await daemon.close();
  }
});

test("a gate that stays busy past the 10 s budget renders a typed busy state, and the page answers 503 with Retry-After", async () => {
  const daemon = await standIn({ busyFor: Infinity, retryAfter: 1 });
  try {
    const page = await interfacesPage(daemon);
    const calls = projectionCalls(daemon);
    assert.ok(calls.length >= 2, `the read is asked again within the budget (${calls.length} asks)`);
    assert.ok(gaps(calls).every((gap) => gap >= 950), `never sooner than Retry-After: gaps ${gaps(calls)}`);
    assert.ok(calls.at(-1).at - calls[0].at <= 10_000, "no ask starts past the 10 s budget");
    assert.ok(page.elapsed <= 11_000, `the page answers within the budget (${page.elapsed} ms)`);
    assert.equal(page.status, 503, "the page itself says busy");
    assert.equal(header(page.headers, "retry-after"), "1", "and passes the daemon's Retry-After on");
    assert.ok(typedBusy(page.body), "a TYPED busy state, by code");
    assert.ok(!page.body.includes("refused"), "busy is never rendered as a refusal");
    assert.ok(!page.body.includes(`data-system-workspace-id=`), "no System fact is shown");
  } finally {
    await daemon.close();
  }
});

test("a Retry-After beyond the budget is honoured, not cut short: one ask, then the typed busy state at once", async () => {
  const daemon = await standIn({ busyFor: Infinity, retryAfter: 30 });
  try {
    const page = await interfacesPage(daemon);
    assert.equal(projectionCalls(daemon).length, 1, "never asked again sooner than Retry-After");
    assert.ok(page.elapsed < 2_000, `no wait the budget cannot finish (${page.elapsed} ms)`);
    assert.equal(page.status, 503);
    assert.equal(header(page.headers, "retry-after"), "30");
    assert.ok(typedBusy(page.body), "a TYPED busy state, by code");
  } finally {
    await daemon.close();
  }
});

test("the packages census names a busy daemon as busy, never as a refusal", async () => {
  const daemon = await standIn({ busyFor: Infinity, retryAfter: 30 });
  try {
    const { out, res } = response();
    const pathname = "/__ioi/systems/packages";
    await handleSystemGenesisSurfaces({ method: "GET", url: pathname, headers: {} }, res, pathname, Buffer.alloc(0), { daemonUrl: daemon.url, shell });
    assert.ok(typedBusy(out.body), "a TYPED busy state, by code");
    assert.ok(!out.body.includes("Projection refused"), "busy is never rendered as a refusal");
  } finally {
    await daemon.close();
  }
});

test("CONTROL: a governed POST answered busy is sent exactly once (only reads are asked again)", async () => {
  const daemon = await standIn({ busyFor: Infinity, retryAfter: 1 });
  try {
    const { out, res } = response();
    const pathname = "/__ioi/systems/compose";
    const body = Buffer.from(new URLSearchParams({ lane: "advanced", declaration: "{}" }).toString());
    await handleSystemGenesisSurfaces({ method: "POST", url: pathname, headers: {} }, res, pathname, body, { daemonUrl: daemon.url, shell });
    assert.equal(daemon.calls.filter((c) => c.method === "POST").length, 1, "the POST is sent once");
    assert.ok(out.body.includes("system_source_read_busy"), "its busy answer is rendered verbatim");
  } finally {
    await daemon.close();
  }
});
