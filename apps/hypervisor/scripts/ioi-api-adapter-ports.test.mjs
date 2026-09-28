// An environment update narrows port exposure; it never widens it (R-240 Arm B, ioi-api-adapter.mjs).
//
// The session page sends `UpdateEnvironment {spec.ports:[{…, admission: EVERYONE}]}` by itself every time a
// session's detail opens. The adapter used to turn every listed port into an expose call, so merely looking
// at a session exposed its port. This drives the adapter against a fake daemon that records each call.
import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";

const calls = [];
const fake = http.createServer((req, res) => {
  let body = "";
  req.on("data", (c) => { body += c; });
  req.on("end", () => {
    calls.push(`${req.method} ${req.url}`);
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify(req.url.includes("/ports/") ? { ok: true } : { environment: { id: "env_1", spec: {}, status: { ports: [{ port: 50432, protocol: "tcp" }] } } }));
  });
});
await new Promise((r) => fake.listen(0, "127.0.0.1", r));
process.env.IOI_HYPERVISOR_DAEMON_URL = `http://127.0.0.1:${fake.address().port}`;
const { handle } = await import("./ioi-api-adapter.mjs");
const update = (ports) => handle("/api/ioi.v1.EnvironmentService/UpdateEnvironment", JSON.stringify({ environmentId: "env_1", spec: { ports } }), { "content-type": "application/json" });

test("the page's own port sync (admission EVERYONE) exposes nothing and is refused by name", async () => {
  calls.length = 0;
  const out = await update([{ port: 50432, admission: "ADMISSION_LEVEL_EVERYONE", name: "agent" }]);
  assert.equal(out.status, 403);
  assert.match(out.body, /port_exposure_not_by_update/u);
  assert.equal(calls.filter((c) => /\/expose$/u.test(c)).length, 0, "no expose call reached the daemon");
});

test("the Add port dialog's new port is refused naming the real rule (declared ports only, behind the opener's lease) and exposes nothing", async () => {
  calls.length = 0;
  const out = await update([{ port: 3000, admission: "ADMISSION_LEVEL_EVERYONE", name: "web" }]);
  assert.equal(out.status, 403);
  const body = JSON.parse(out.body);
  assert.match(body.message, /^environment_port_not_declared: port 3000 is not one of this environment's declared ports \(50432\)/u);
  assert.equal(body.details?.[0]?.type, "gitpod.v1.ActionableErrorDetails");
  assert.match(Buffer.from(body.details[0].value, "base64").toString("utf8"), /Port 3000 can't be opened/u);
  assert.equal(calls.filter((c) => /\/expose$/u.test(c)).length, 0, "no expose call reached the daemon");
});

test("un-exposing a port through an update still applies (an update may narrow)", async () => {
  calls.length = 0;
  const out = await update([{ port: 50432, admission: "ADMISSION_LEVEL_UNSPECIFIED" }]);
  assert.equal(out.status ?? 200, 200);
  assert.deepEqual(calls.filter((c) => /\/ports\//u.test(c)), ["POST /v1/hypervisor/environments/env_1/ports/50432/unexpose"]);
});

test.after(() => fake.close());
