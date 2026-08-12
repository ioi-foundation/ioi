#!/usr/bin/env node
// verify-hypervisor-provider-transport — W3.2 first cut (check:provider-transport).
//
// Proves, against an ISOLATED real daemon, that the ProviderTransport boundary is composed and not
// shadowed: the invocation route resolves its endpoint from the model-route REGISTRY, refuses every
// non-executable posture with a typed code, keeps credential custody with the CapabilityLease
// gateway instead of reading a provider key from the process environment, and fabricates no
// invocation record when it refuses.
//
// TWO LANES, and the split is deliberate:
//   default (CI)  — the refusal ladder and non-fabrication. Needs no model provider, so it runs
//                   anywhere and its assertion count is DETERMINISTIC (the verifier-floors pin
//                   depends on that).
//   --live        — the native-first e2e against a REAL provider: success, streaming, observed
//                   token mix, latency, the typed kernel receipt, readback, and idempotent replay.
//                   NOT run in CI: GitHub Actions has no model provider. That absence is a named
//                   residual, never a silent skip — the live lane is the evidence a human runs and
//                   records, exactly like check:ported-seed:live.
//
// The live lane does NOT emit a verifier census: it executes more assertions than the CI lane, and
// a census from it would collide with the floor pinned for the lane CI actually runs.
//
// Exit: 0 pass · 1 fail · 2 blocked (daemon binary missing, or --live with no reachable provider).
//   IOI_HYPERVISOR_DAEMON_BINARY  default target/debug/hypervisor-daemon
//   IOI_PROVIDER_TRANSPORT_LIVE_BASE_URL  default http://127.0.0.1:11434
//   IOI_PROVIDER_TRANSPORT_LIVE_MODEL     default qwen2.5:7b

import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import net from "node:net";
import { fileURLToPath } from "node:url";
import { emitVerifierCensus } from "./lib/verifier-census.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP = path.resolve(HERE, "..");
const ROOT = path.resolve(APP, "..", "..");
const LIVE = process.argv.includes("--live");
const LIVE_BASE = process.env.IOI_PROVIDER_TRANSPORT_LIVE_BASE_URL ?? "http://127.0.0.1:11434";
const LIVE_MODEL = process.env.IOI_PROVIDER_TRANSPORT_LIVE_MODEL ?? "qwen2.5:7b";

let OWNER = "";
const code = (j) => j?.code ?? j?.error?.code ?? "";

const results = [];
const ok = (name, cond, detail) => results.push({ name, pass: !!cond, detail: detail || "" });

const freePort = () => new Promise((resolve, reject) => {
  const srv = net.createServer();
  srv.listen(0, "127.0.0.1", () => {
    const { port } = srv.address();
    srv.close(() => resolve(port));
  });
  srv.on("error", reject);
});

const waitFor = async (url, ms) => {
  const until = Date.now() + ms;
  while (Date.now() < until) {
    try {
      const r = await fetch(url);
      if (r.status < 500) return;
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 400));
  }
  throw new Error(`timeout waiting for ${url}`);
};

const daemonBinary = path.resolve(ROOT, process.env.IOI_HYPERVISOR_DAEMON_BINARY ?? "target/debug/hypervisor-daemon");
try {
  fs.accessSync(daemonBinary, fs.constants.X_OK);
} catch {
  console.error(`BLOCKED: daemon binary not executable at ${daemonBinary}`);
  process.exit(2);
}

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-provider-transport-"));
let daemon = null;
let daemonPort = 0;
let DAEMON = "";
let SESSION = "";

const jd = (method, p, body, { auth = true, idem = null } = {}) => fetch(`${DAEMON}${p}`, {
  method,
  headers: {
    ...(body ? { "content-type": "application/json" } : {}),
    ...(auth && SESSION ? { cookie: `ioi_session=${SESSION}` } : {}),
  },
  // The shared write path reads owner_ref and idempotency_key from the BODY, not from headers.
  ...(body ? { body: JSON.stringify(idem ? { owner_ref: OWNER, idempotency_key: idem, ...body } : body) } : {}),
}).then(async (r) => ({ status: r.status, j: await r.json().catch(() => ({})) }))
  .catch((e) => ({ status: 0, j: { transport_error: String(e) } }));

/** Count durable invocation records on disk — the daemon's own answer never certifies absence. */
const invocationFiles = () => {
  try {
    return fs.readdirSync(path.join(dataDir, "model-invocations")).filter((f) => f.endsWith(".json"));
  } catch {
    return [];
  }
};

function cleanup() {
  try { daemon?.kill("SIGTERM"); } catch { /* already gone */ }
  try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch { /* best effort */ }
}

async function run() {
  daemonPort = await freePort();
  DAEMON = `http://127.0.0.1:${daemonPort}`;
  daemon = spawn(daemonBinary, [], {
    cwd: ROOT,
    env: {
      ...process.env,
      IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${daemonPort}`,
      IOI_HYPERVISOR_DATA_DIR: dataDir,
      // Deliberately dead: nothing in this verifier may reach a provider through the boot-time
      // environment singleton. Every successful call below must come from a REGISTRY record.
      IOI_HYPERVISOR_MODEL_UPSTREAM: "http://127.0.0.1:1/v1",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let log = "";
  daemon.stdout.on("data", (c) => { log = `${log}${c}`.slice(-64000); });
  daemon.stderr.on("data", (c) => { log = `${log}${c}`.slice(-64000); });
  await waitFor(`${DAEMON}/healthz`, 30000);

  const token = log.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
  if (token) {
    const boot = await jd("POST", "/v1/hypervisor/auth/bootstrap", {
      token, password: "provider-transport-bootstrap-v1", email: "provider-transport@ioi.local",
    }, { auth: false });
    SESSION = boot.j?.session_token ?? "";
  }
  ok("operator bootstrap yields an authenticated session", SESSION.startsWith("ioi_sess_"), SESSION.slice(0, 12));

  const who = (await jd("GET", "/v1/hypervisor/auth/whoami")).j || {};
  OWNER = (who.principal?.tenant_refs || []).find((t) => typeof t === "string" && t.startsWith("org://")) || "";
  ok("the session authenticates a principal with an org:// owner tenant to admit under", !!OWNER, OWNER || "no owner tenant");

  // ---------------------------------------------------------------- identity first (rule E)
  const anon = await jd("POST", "/v1/hypervisor/model-routes/mrt_local_default/invoke",
    { prompt: "hello" }, { auth: false, idem: "anon-must-401" });
  ok("rule E: an anonymous invoke is refused BEFORE any record read (401, never 404)",
    anon.status === 401, `status ${anon.status} code ${code(anon.j)}`);

  const anonRead = await jd("GET", "/v1/hypervisor/model-invocations/does-not-exist", null, { auth: false });
  ok("rule E: an anonymous readback is refused before the existence question is answered",
    anonRead.status === 401, `status ${anonRead.status}`);

  ok("no invocation record exists after the anonymous attempts (nothing fabricated)",
    invocationFiles().length === 0, `${invocationFiles().length} record(s)`);

  // ---------------------------------------------------------------- INV-37: WHO is server-resolved
  const whoSupplied = await jd("POST", "/v1/hypervisor/model-routes/mrt_local_default/invoke",
    { prompt: "hello", acting_principal_ref: "user://someone-else" }, { idem: "inv37-must-refuse" });
  ok("INV-37: a body carrying an actor field is refused, not honoured",
    whoSupplied.status === 400 && code(whoSupplied.j) === "identity_not_client_settable",
    `status ${whoSupplied.status} code ${code(whoSupplied.j)}`);

  // ---------------------------------------------------------------- the refusal ladder
  const unknown = await jd("POST", "/v1/hypervisor/model-routes/mrt_does_not_exist/invoke",
    { prompt: "hello" }, { idem: "unknown-route" });
  ok("an unknown route 404s and executes nothing",
    unknown.status === 404 && code(unknown.j) === "model_route_not_found",
    `status ${unknown.status} code ${code(unknown.j)}`);

  const emptyPrompt = await jd("POST", "/v1/hypervisor/model-routes/mrt_local_default/invoke",
    { prompt: "   " }, { idem: "empty-prompt" });
  ok("an empty prompt is refused typed before any provider contact",
    emptyPrompt.status === 400 && code(emptyPrompt.j) === "model_invocation_prompt_required",
    `status ${emptyPrompt.status} code ${code(emptyPrompt.j)}`);

  // A declared (never probed) route is not executable: availability is proof, not a default.
  const declared = await jd("POST", "/v1/hypervisor/model-routes", {
    model_id: "verify-transport:none", transport: "ollama",
    base_url: "http://127.0.0.1:1", display_name: "unreachable transport route",
  }, { idem: "declared-route" });
  const declaredId = declared.j?.route?.route_id ?? "";
  ok("a route can be declared for the refusal proofs", declared.status === 201 && declaredId.length > 0, declaredId);

  const notExecutable = await jd("POST", `/v1/hypervisor/model-routes/${declaredId}/invoke`,
    { prompt: "hello" }, { idem: "declared-not-executable" });
  ok("a declared-but-unprobed route refuses typed: availability is never assumed",
    notExecutable.status === 409 && code(notExecutable.j) === "model_route_not_executable",
    `status ${notExecutable.status} code ${code(notExecutable.j)}`);

  // openai_compatible is admitted by the REGISTRY but has no transport implementation. The honest
  // answer is 501, not a silent fallback onto the one transport that does exist.
  const oai = await jd("POST", "/v1/hypervisor/model-routes", {
    model_id: "gpt-4o-mini", transport: "openai_compatible",
    base_url: "https://example.invalid/v1", display_name: "no transport implementation",
    api_key_env: "VERIFY_TRANSPORT_KEY_NAME",
  }, { idem: "oai-route" });
  const oaiId = oai.j?.route?.route_id ?? "";
  if (oaiId) {
    const oaiInvoke = await jd("POST", `/v1/hypervisor/model-routes/${oaiId}/invoke`,
      { prompt: "hello" }, { idem: "oai-invoke" });
    // Exactly 501 and exactly this code. An earlier revision of this assertion also accepted 409,
    // and passed on the 409 — the label claimed a refusal the assertion never observed. The handler
    // now checks transport support before availability so the claimed refusal is the reachable one.
    ok("a transport with no implementation refuses 501 — it never falls back to another provider",
      oaiInvoke.status === 501 && code(oaiInvoke.j) === "provider_transport_unimplemented",
      `status ${oaiInvoke.status} code ${code(oaiInvoke.j)}`);
  } else {
    ok("a transport with no implementation refuses 501 — it never falls back to another provider",
      false, `route create failed: ${oai.status} ${JSON.stringify(oai.j?.error ?? {})}`);
  }

  ok("the whole refusal ladder fabricated NO invocation record on disk",
    invocationFiles().length === 0, `${invocationFiles().length} record(s)`);

  ok("the daemon never reached the boot-time env upstream (127.0.0.1:1) for any of the above",
    !log.includes("127.0.0.1:1/v1 responded"), "env singleton unused");

  // ---------------------------------------------------------------- live native-first e2e
  if (LIVE) {
    let reachable = false;
    try {
      const tags = await fetch(`${LIVE_BASE}/api/tags`, { signal: AbortSignal.timeout(2000) });
      reachable = tags.ok;
    } catch { reachable = false; }
    if (!reachable) {
      console.error(`BLOCKED: --live requires a reachable provider at ${LIVE_BASE}`);
      cleanup();
      process.exit(2);
    }

    const liveRoute = await jd("POST", "/v1/hypervisor/model-routes", {
      model_id: LIVE_MODEL, transport: "ollama", base_url: LIVE_BASE, display_name: "live native route",
    }, { idem: "live-route" });
    const liveId = liveRoute.j?.route?.route_id ?? "";
    ok("live: a native route is declared from the registry", liveRoute.status === 201 && liveId.length > 0, liveId);

    const probe = await jd("POST", `/v1/hypervisor/model-routes/${liveId}/probe`, null, { idem: "live-probe" });
    ok("live: the probe reports the REAL provider catalog as available",
      probe.j?.availability?.state === "available", probe.j?.availability?.state);

    const enabled = await jd("POST", `/v1/hypervisor/model-routes/${liveId}/enable`, {}, { idem: "live-enable" });
    ok("live: the route is activated", enabled.status === 200, `status ${enabled.status}`);

    const invoked = await jd("POST", `/v1/hypervisor/model-routes/${liveId}/invoke`,
      { prompt: "Reply with exactly the word: composed" }, { idem: "live-invoke-1" });
    const inv = invoked.j?.invocation ?? {};
    const receipt = inv.model_invocation_receipt ?? {};
    const evidence = inv.evidence ?? {};
    ok("live: a real model invocation succeeds through the REGISTRY endpoint",
      invoked.status === 200 && inv.outcome === "succeeded", `status ${invoked.status} outcome ${inv.outcome}`);
    ok("live: the receipt is the TYPED kernel ModelInvocationReceipt shape",
      typeof receipt.model_id === "string" && typeof receipt.provider === "string"
        && typeof receipt.latency_ms === "number" && Array.isArray(receipt.output_hash),
      `model ${receipt.model_id} provider ${receipt.provider} latency ${receipt.latency_ms}ms`);
    ok("live: the observed token mix carries REAL provider counts",
      (evidence.token_mix?.input ?? 0) > 0 && (evidence.token_mix?.output ?? 0) > 0,
      `in ${evidence.token_mix?.input} out ${evidence.token_mix?.output}`);
    ok("live: unreported token classes are typed gaps, never zero-filled",
      evidence.token_mix?.cache_read === null && evidence.token_mix?.reasoning === null
        && (evidence.token_mix?.unreported ?? []).includes("cache_read"),
      JSON.stringify(evidence.token_mix?.unreported ?? []));
    ok("live: attempt lineage is recorded with a classified outcome",
      Array.isArray(evidence.attempts) && evidence.attempts.length === 1
        && evidence.attempts[0].outcome === "succeeded" && evidence.attempts[0].error_class === null,
      JSON.stringify(evidence.attempts?.[0] ?? {}));
    ok("live: latency is observed, not declared",
      (evidence.latency?.total_ms ?? 0) > 0, `${evidence.latency?.total_ms}ms`);
    ok("live: the W4-F evidence gaps this cut cannot fill are NAMED in the record",
      (evidence.evidence_gaps ?? []).includes("economics.usage_record"),
      JSON.stringify(evidence.evidence_gaps ?? []));

    const readback = await jd("GET", `/v1/hypervisor/model-invocations/${inv.invocation_id}`);
    ok("live: the invocation reads back durably with its receipt intact",
      readback.status === 200 && readback.j?.invocation?.model_invocation_receipt?.output_hash?.length === 32,
      `status ${readback.status}`);

    const replay = await jd("POST", `/v1/hypervisor/model-routes/${liveId}/invoke`,
      { prompt: "Reply with exactly the word: composed" }, { idem: "live-invoke-1" });
    ok("live: an idempotent replay returns the STORED record and spends no second provider call",
      replay.status === 200 && replay.j?.replayed === true
        && replay.j?.invocation?.invocation_id === inv.invocation_id,
      `replayed ${replay.j?.replayed}`);

    const streamed = await jd("POST", `/v1/hypervisor/model-routes/${liveId}/invoke`,
      { prompt: "Count: one two three", stream: true }, { idem: "live-invoke-stream" });
    const sEvidence = streamed.j?.invocation?.evidence ?? {};
    ok("live: the streaming lane completes and times its FIRST token separately from the total",
      streamed.status === 200 && streamed.j?.invocation?.outcome === "succeeded"
        && typeof sEvidence.latency?.first_token_ms === "number"
        && sEvidence.latency.first_token_ms <= sEvidence.latency.total_ms,
      `first ${sEvidence.latency?.first_token_ms}ms total ${sEvidence.latency?.total_ms}ms`);

    // The failure path, executed for real. The route must be active AND available before the
    // provider disappears — patching base_url would invalidate the probe and refuse at 409, which
    // proves route hygiene rather than transport failure handling.
    //
    // So the route points at a TCP forwarder to the real provider. Every byte the daemon sees
    // during the probe is the genuine provider's; nothing here fabricates a provider response.
    // Killing the forwarder makes a healthy provider vanish exactly as a network partition would.
    const forwardPort = await freePort();
    const upstream = new URL(LIVE_BASE);
    const forwarder = net.createServer((client) => {
      const target = net.connect(Number(upstream.port || 80), upstream.hostname, () => client.pipe(target).pipe(client));
      target.on("error", () => client.destroy());
      client.on("error", () => target.destroy());
    });
    await new Promise((resolve) => forwarder.listen(forwardPort, "127.0.0.1", resolve));

    const deadRoute = await jd("POST", "/v1/hypervisor/model-routes", {
      model_id: LIVE_MODEL, transport: "ollama",
      base_url: `http://127.0.0.1:${forwardPort}`, display_name: "provider vanishes",
    }, { idem: "dead-route" });
    const deadId = deadRoute.j?.route?.route_id ?? "";
    const deadProbe = await jd("POST", `/v1/hypervisor/model-routes/${deadId}/probe`, null, { idem: "dead-probe" });
    ok("live: the forwarded route probes available from the REAL provider catalog",
      deadProbe.j?.availability?.state === "available", deadProbe.j?.availability?.state);
    await jd("POST", `/v1/hypervisor/model-routes/${deadId}/enable`, {}, { idem: "dead-enable" });

    await new Promise((resolve) => forwarder.close(resolve));
    const failed = await jd("POST", `/v1/hypervisor/model-routes/${deadId}/invoke`,
      { prompt: "this provider is gone" }, { idem: "dead-invoke" });
    const fInv = failed.j?.invocation ?? {};
    ok("live: a vanished provider produces an HONEST failure record, never a fabricated completion",
      fInv.outcome === "failed"
        && fInv.model_invocation_receipt?.error_class === "ProviderUnavailable"
        && fInv.evidence?.attempts?.[0]?.retryable === true,
      `outcome ${fInv.outcome} class ${fInv.model_invocation_receipt?.error_class}`);
  }

  const fails = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
  console.log(`\n${results.length - fails.length}/${results.length} passed${LIVE ? " (live)" : ""}`);
  // The live lane runs MORE assertions than CI does; emitting its census would collide with the
  // floor pinned for the CI lane.
  if (!LIVE) emitVerifierCensus({ verifierId: "provider-transport", sourceUrl: import.meta.url, results });
  cleanup();
  process.exit(fails.length ? 1 : 0);
}

run().catch((error) => {
  console.error(`FAIL provider-transport — ${error?.stack || error}`);
  cleanup();
  process.exit(1);
});
