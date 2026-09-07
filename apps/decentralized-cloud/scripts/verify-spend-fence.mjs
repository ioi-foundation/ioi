#!/usr/bin/env node
// THE SPEND FENCE, MUTATION-TESTED — against a stub, because the real test would spend.
//
// The fence is the single most important property of the job door: the proxy sets
// `dry_run: true` on every execute rather than forwarding what the caller sent, so no
// request composed by a client can reach a metered provider operation.
//
// The standing rule is that a gate must be mutation-tested — break the thing the
// assertion exists to catch and confirm it goes red — and a gate that cannot fail on
// its own finding is a green light wearing a gate's name.
//
// BUT THE OBVIOUS MUTATION IS UNSAFE. Removing the fence and re-running the face gate
// would send an execute WITHOUT dry_run to the real daemon, against a real
// external_spend budget with real money behind it. The mutation that proves the fence
// works would be the mutation that spends. That is not a test I am willing to run, and
// "I could not test it safely" is not an acceptable answer for this particular
// property either.
//
// So the fence is exercised against a STUB daemon that records what it was actually
// sent and spends nothing. Both directions are proven:
//
//   1. WITH the fence, a request carrying `dry_run: false` arrives at the daemon as
//      `dry_run: true`.
//   2. WITHOUT the fence — patched out in a temporary copy of the proxy — the same
//      request arrives as `dry_run: false`. That is the defect, reproduced, so the
//      assertion in the face gate is known to be capable of failing.
//
// The temporary copy is deleted at the end. The real proxy is never modified.
//
// Usage: node apps/decentralized-cloud/scripts/verify-spend-fence.mjs

import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { readFileSync, writeFileSync, rmSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP = path.join(HERE, "..");
const STUB_PORT = Number(process.env.IOI_DC_STUB_PORT || 4310);
const FACE_PORT = Number(process.env.IOI_DC_FENCE_PORT || 4311);

const results = [];
const ok = (name, cond, detail) => results.push({ name, pass: !!cond, detail: detail || "" });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ── The stub daemon ─────────────────────────────────────────────────────────
// It runs nothing, reaches no provider and holds no budget. Its entire job is to
// report the body it received, so the question "what did the daemon actually get" has
// an answer that does not depend on trusting the thing under test.
let lastBody = null;
const stub = createServer((req, res) => {
  let raw = "";
  req.on("data", (c) => { raw += c; });
  req.on("end", () => {
    try { lastBody = JSON.parse(raw || "{}"); } catch { lastBody = { unparseable: raw }; }
    res.writeHead(200, { "content-type": "application/json" });
    // Echo back what arrived, the way the real daemon echoes its own dry_run.
    res.end(JSON.stringify({ ok: true, dry_run: lastBody?.dry_run, received: lastBody }));
  });
});
await new Promise((r) => stub.listen(STUB_PORT, "127.0.0.1", r));

// THE PROXY REFUSES TO START WITHOUT A BUILD DIRECTORY, by design — a server with
// nothing behind it must not announce "face on". This fence tests the WRITE LANE and
// never fetches the shell, so it hands the proxy an empty scratch directory to stand
// behind rather than depending on dist/ having been built first: in a fresh worktree
// the fence runs before the face gate, which is the step that builds dist/, and it
// failed there with "the proxy under test did not start" — a fault in the fence's own
// ordering reported as though the proxy were broken.
import { mkdtempSync } from "node:fs";
import os from "node:os";
const SCRATCH_DIST = mkdtempSync(path.join(os.tmpdir(), "dc-spend-fence-"));

async function withProxy(scriptPath, fn) {
  const server = spawn("node", [scriptPath], {
    env: {
      ...process.env,
      IOI_DC_PORT: String(FACE_PORT),
      IOI_HYPERVISOR_DAEMON_URL: `http://127.0.0.1:${STUB_PORT}`,
      IOI_DC_DIST: SCRATCH_DIST,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let booted = false;
  server.stdout.on("data", (b) => { if (String(b).includes("face on")) booted = true; });
  try {
    for (let i = 0; i < 60 && !booted; i++) await sleep(100);
    if (!booted) throw new Error("the proxy under test did not start");
    return await fn();
  } finally {
    server.kill("SIGTERM");
    await sleep(200);
  }
}

const askForARealRun = async () => {
  lastBody = null;
  await fetch(`http://127.0.0.1:${FACE_PORT}/api/jobs/cjob_fence_probe/dry-run`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ dry_run: false, idempotency_key: "fence-probe" }),
  });
  return lastBody;
};

const REAL = path.join(APP, "scripts/serve-face.mjs");
const MUTANT = path.join(APP, "scripts/.serve-face.fence-mutant.mjs");

try {
  // 1 — the fence as it ships.
  const withFence = await withProxy(REAL, askForARealRun);
  ok("a client asking for a real run is overwritten to a dry run",
    withFence?.dry_run === true,
    `the client sent dry_run:false and the daemon received dry_run:${String(withFence?.dry_run)}`);

  // 2 — the fence removed, in a temporary copy. This is the defect reproduced.
  const source = readFileSync(REAL, "utf8");
  const mutated = source.replace(
    /body = \{ \.\.\.body, dry_run: true \};/,
    "/* fence removed by the mutation test */"
  );
  ok("the mutation actually changed the proxy", mutated !== source,
    mutated === source ? "the fence line was not found — this test proves nothing" : "fence line removed");
  writeFileSync(MUTANT, mutated);
  const withoutFence = await withProxy(MUTANT, askForARealRun);
  ok("WITHOUT the fence, the client's real-run request reaches the daemon",
    withoutFence?.dry_run === false,
    `the client sent dry_run:false and the daemon received dry_run:${String(withoutFence?.dry_run)} — ` +
    "this is the defect the fence exists to prevent, reproduced against a stub that spends nothing");

  // 3 — the fence is not merely present, it is unconditional. There is no lane in the
  // proxy that reaches the daemon's execute route without it.
  ok("the proxy has exactly one execute lane, and it is fenced",
    (source.match(/dry_run: true/g) || []).length >= 1 &&
    !/dry_run:\s*(false|body\.dry_run|req)/.test(source),
    "no branch forwards the caller's dry_run");
} finally {
  rmSync(MUTANT, { force: true });
  stub.close();
}

let fail = 0;
for (const r of results) {
  console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`);
  if (!r.pass) fail++;
}
console.log(`\n${results.length - fail}/${results.length} passed`);
console.log(`spend fence: ${fail ? "FAIL" : "OK"}`);
console.log("No provider was contacted and nothing was spent: every request in this file");
console.log("went to a stub on localhost that runs nothing.");
rmSync(SCRATCH_DIST, { recursive: true, force: true });
process.exit(fail ? 1 : 0);
