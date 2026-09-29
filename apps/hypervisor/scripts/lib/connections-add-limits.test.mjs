// R-240 Arm A — the Connections "Add API key" form never leaves a half-done write.
//
// The form offered limit fields on a deployment with no authority node to record them, and a submission carrying
// limits was refused only AFTER the connector had registered and its token had been sealed: the person was told
// "Limits not set" and a connection they did not ask for (an unbounded one) stayed on Connections. Now the daemon's
// own answer (GET /v1/hypervisor/authority/standing-envelopes → `decidable`) decides: with no recorder the limit
// fields render disabled with the reason (the unified gap contract) and are never sent, and a submission that
// carries limits anyway is refused as a whole, by name, before anything is written.
//
//   PURE — attachLimitsPlan / standingRecorderOf over every posture.
//   LIVE — an isolated daemon + serve with no authority node: the form's fields, the connector and credential
//          record counts before and after a submission with limits (unchanged) and one without (one added).
//
//   IOI_HYPERVISOR_DAEMON_BINARY=<daemon> node --test apps/hypervisor/scripts/lib/connections-add-limits.test.mjs
import test, { after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { isolatedOperatorSession, sanitizedVerifierBaseEnv, startIsolatedPlane } from "./isolated-daemon.mjs";

const planes = [];
after(async () => { for (const plane of planes) await plane.stop().catch(() => {}); });

// ---- PURE (imported inside each test, so the LIVE leg still runs against a serve that predates these helpers)
const lib = () => import("./wallet-authority.mjs");
const reply = (status, body) => async () => ({ status, text: async () => JSON.stringify(body) });

test("PURE: no limit asked for is no limit to refuse, whatever the recorder", async () => {
  const { attachLimitsPlan } = await lib();
  for (const mode of ["none", "daemon", "fixture"]) {
    assert.deepEqual(attachLimitsPlan({ name: "x", standing_max_usages: "", standing_budget_usd: " " }, { mode, reason: "r" }), { ok: true, limits: null }, mode);
  }
});

test("PURE: limits on a deployment that cannot record them refuse the WHOLE submission by name", async () => {
  const { attachLimitsPlan } = await lib();
  const plan = attachLimitsPlan({ standing_max_usages: "5" }, { mode: "none", reason: "no authority node here" });
  assert.equal(plan.ok, false);
  assert.equal(plan.code, "standing_lease_recorder_not_configured");
  assert.equal(plan.message, "no authority node here");
  // a budget or an expiry alone is still a limit asked for — never silently dropped
  assert.equal(attachLimitsPlan({ standing_budget_usd: "1" }, { mode: "none", reason: "r" }).code, "standing_lease_recorder_not_configured");
});

test("PURE: a bound that cannot be one, or a missing passphrase, refuses before any write", async () => {
  const { attachLimitsPlan } = await lib();
  const daemon = { mode: "daemon", reason: "" };
  assert.equal(attachLimitsPlan({ standing_budget_usd: "1", operator_passphrase: "p" }, daemon).code, "standing_lease_bounds_invalid");
  assert.equal(attachLimitsPlan({ standing_max_usages: "0", operator_passphrase: "p" }, daemon).code, "standing_lease_bounds_invalid");
  assert.equal(attachLimitsPlan({ standing_max_usages: "2.5", operator_passphrase: "p" }, daemon).code, "standing_lease_bounds_invalid");
  assert.equal(attachLimitsPlan({ standing_max_usages: "3", standing_expires_hours: "9999", operator_passphrase: "p" }, daemon).code, "standing_lease_bounds_invalid");
  assert.equal(attachLimitsPlan({ standing_max_usages: "3" }, daemon).code, "operator_passphrase_required");
  assert.deepEqual(attachLimitsPlan({ standing_max_usages: "3", standing_budget_usd: "1.50", operator_passphrase: "p" }, daemon), { ok: true, limits: { max_usages: "3", budget_usd: "1.50" } });
  // the fixture approver records serve-side and takes no passphrase
  assert.deepEqual(attachLimitsPlan({ standing_max_usages: "3" }, { mode: "fixture", reason: "" }), { ok: true, limits: { max_usages: "3" } });
});

test("PURE: whether limits can be recorded is the DAEMON's answer, never the serve's environment", async () => {
  const { standingRecorderOf } = await lib();
  const saved = process.env.IOI_HYPERVISOR_AUTHORITY_PRINCIPAL_REF;
  process.env.IOI_HYPERVISOR_AUTHORITY_PRINCIPAL_REF = "principal://a-serve-that-names-one";
  try {
    assert.equal((await standingRecorderOf(reply(200, { ok: true, decidable: true }))).mode, "daemon");
    const none = await standingRecorderOf(reply(200, { ok: true, decidable: false }));
    assert.equal(none.mode, "none");
    assert.match(none.reason, /authority node/u);
    const refused = await standingRecorderOf(reply(401, { ok: false, code: "hypervisor.authentication_required" }));
    assert.equal(refused.mode, "none");
    assert.match(refused.reason, /hypervisor\.authentication_required/u);
    const gone = await standingRecorderOf(async () => { throw new Error("ECONNREFUSED"); });
    assert.equal(gone.mode, "none");
    assert.match(gone.reason, /daemon_unreachable/u);
  } finally {
    if (saved === undefined) delete process.env.IOI_HYPERVISOR_AUTHORITY_PRINCIPAL_REF;
    else process.env.IOI_HYPERVISOR_AUTHORITY_PRINCIPAL_REF = saved;
  }
});

// ---- LIVE
const records = (dataDir, family) => {
  try { return fs.readdirSync(path.join(dataDir, family)).filter((n) => n.endsWith(".json")).length; } catch { return 0; }
};
async function form(serve, route, fields, cookie) {
  const res = await fetch(`${serve}${route}`, {
    method: "POST", redirect: "manual",
    headers: { "content-type": "application/x-www-form-urlencoded", cookie },
    body: new URLSearchParams(fields).toString(),
  });
  return { status: res.status, location: res.headers.get("location") || "", text: await res.text() };
}

test("LIVE: with no authority node, the form tells the truth and a submission with limits writes nothing", { timeout: 600_000 }, async (t) => {
  const baseEnv = sanitizedVerifierBaseEnv(Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith("IOI_") || k === "IOI_HYPERVISOR_DAEMON_BINARY")));
  // no authority binary, no node state, no fixture approver — and a serve that DOES name an authority
  // principal, which is exactly the environment that used to offer limits the daemon could not record
  const plane = await startIsolatedPlane({ serve: true, baseEnv, env: { IOI_PRODUCT_SIGNIN_REQUIRED: "0", IOI_HYPERVISOR_AUTHORITY_PRINCIPAL_REF: "principal://serve-env-only" } });
  if (!plane) { t.skip("BLOCKED: no daemon binary"); return; }
  planes.push(plane);
  const cookie = `ioi_session=${await isolatedOperatorSession(plane)}`;
  const decidable = await fetch(`${plane.daemonUrl}/v1/hypervisor/authority/standing-envelopes`, { headers: { cookie } }).then((r) => r.json());
  assert.equal(decidable.decidable, false, "this plane's daemon has no deployment authority");

  // THE FORM: the limit fields are disabled with the reason, and there is no passphrase to ask for.
  const page = await fetch(`${plane.serveUrl}/__ioi/connections/add?type=bearer`, { headers: { cookie } }).then((r) => r.text());
  for (const name of ["standing_max_usages", "standing_budget_usd", "standing_expires_hours"]) {
    const input = (page.match(new RegExp(`<input name="${name}"[^>]*>`, "u")) || [""])[0];
    assert.match(input, / disabled /u, `${name} is natively disabled, so it is never sent`);
    assert.match(input, /aria-disabled="true"/u, `${name} declares the gap`);
    assert.match(input, /data-ioi-disabled-reason="[^"]*authority node[^"]*"/u, `${name} says why`);
  }
  assert.match(page, /data-ioi-standing-recorder="none"/u);
  assert.doesNotMatch(page, /name="operator_passphrase"/u, "no passphrase is asked for a limit that cannot be set");

  // A SUBMISSION CARRYING LIMITS ANYWAY (a crafted post, or a stale page): refused whole, nothing written.
  const before = { connectors: records(plane.dataDir, "connectors"), credentials: records(plane.dataDir, "connector-credentials") };
  const listed = async () => ((await fetch(`${plane.daemonUrl}/v1/hypervisor/connectors`, { headers: { cookie } }).then((r) => r.json())).connectors || []);
  const listedBefore = (await listed()).length;
  const base = { name: "armA limits", base_url: "https://example.invalid/api", tool_name: "list_loans", tool_path: "/v1/loans", token: "arm-a-sealed-token" };
  const refused = await form(plane.serveUrl, "/__ioi/connections/add?type=bearer", { ...base, standing_max_usages: "5", standing_budget_usd: "1.00", standing_expires_hours: "24" }, cookie);
  assert.equal(refused.status, 200, `refused in place, not redirected (${refused.status} → ${refused.location})`);
  assert.match(refused.text, /standing_lease_recorder_not_configured/u);
  assert.match(refused.text, /Nothing was registered/u);
  assert.deepEqual({ connectors: records(plane.dataDir, "connectors"), credentials: records(plane.dataDir, "connector-credentials") }, before, "no connector and no sealed credential was written");
  assert.equal((await listed()).length, listedBefore, "the daemon lists no new connection");

  // THE SAME SUBMISSION WITHOUT LIMITS lands: registered, token sealed, back on Connections, which names the gap on its card.
  const added = await form(plane.serveUrl, "/__ioi/connections/add?type=bearer", { ...base, name: "armA no limits" }, cookie);
  assert.equal(added.status, 302);
  assert.equal(added.location, "/__ioi/connections");
  assert.equal(records(plane.dataDir, "connectors"), before.connectors + 1);
  assert.equal(records(plane.dataDir, "connector-credentials"), before.credentials + 1);
  const mine = (await listed()).find((c) => c.name === "armA no limits");
  assert.equal(mine?.auth_posture, "token-lease:bound");
  const cockpit = await fetch(`${plane.serveUrl}/__ioi/connections`, { headers: { cookie } }).then((r) => r.text());
  assert.match(cockpit, /data-ioi-standing-recorder="none"/u, "the connection's card names the gap where Set limits would be");
});
