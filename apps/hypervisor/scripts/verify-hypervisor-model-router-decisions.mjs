#!/usr/bin/env node
// Model-router DECISION verifier — retry, fallback, and what each one costs.
//
// The separation this proves: a transport CLASSIFIES an error (`ModelRuntimeErrorClass` +
// `retryable`); only the ROUTER decides what to do about it. Before this cut nothing decided —
// `retryable` was a field no code read, and attempt lineage was a one-element list under every
// spelling. W4-F's cost-per-successful-unit and failure-rate fields had no data to be computed from
// because no invocation could record more than one attempt.
//
// WHAT THE PROVIDER HERE IS, AND IS NOT. Each "provider" below is a real local HTTP server the
// daemon really connects to over a real socket, speaking the real Ollama wire shapes (`/api/tags`
// for the probe, `/api/chat` for the invoke). It is a controllable counterpart, not a fixture
// corpus: nothing here feeds the daemon canned records of its own, and every assertion reads either
// the daemon's durable record or the provider's own request tally. A controllable provider is the
// only way to observe a RETRY at all — a retry is by definition a second request after a first one
// failed, and that requires a first failure you can cause on purpose.
//
// The discipline: COUNT THE THING ITSELF. "Did it retry?" is not answered by a status code or by an
// attempt array the daemon wrote about itself — it is answered by how many times the provider was
// actually contacted. Every retry and fallback assertion below is anchored on that tally.
//
// Exit: 0 pass · 1 fail · 2 blocked (daemon binary missing).
//   IOI_HYPERVISOR_DAEMON_BINARY  default target/debug/hypervisor-daemon

import { spawn } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import net from "node:net";
import { fileURLToPath } from "node:url";
import { emitVerifierCensus } from "./lib/verifier-census.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP = path.resolve(HERE, "..");
const ROOT = path.resolve(APP, "..", "..");
const MODEL = "router-test-model";

const results = [];
const ok = (name, cond, detail) => results.push({ name, pass: !!cond, detail: detail || "" });
const code = (j) => j?.code ?? j?.error?.code ?? "";

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
    try { const r = await fetch(url); if (r.status < 500) return; } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 300));
  }
  throw new Error(`timeout waiting for ${url}`);
};

/**
 * A controllable provider.
 *
 * `plan` is consumed one entry per /api/chat request: "ok" answers a well-formed Ollama completion,
 * a number answers that HTTP status. When the plan runs out the last entry repeats, so a test can
 * say "fail forever" with one entry. `chatHits` is the tally every retry assertion reads.
 */
async function startProvider(plan) {
  const port = await freePort();
  const state = { chatHits: 0, tagHits: 0, plan: [...plan] };
  const server = http.createServer((req, res) => {
    if (req.url.startsWith("/api/tags")) {
      state.tagHits += 1;
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ models: [{ name: MODEL }, { name: `${MODEL}:latest` }] }));
      return;
    }
    if (req.url.startsWith("/api/chat")) {
      const index = Math.min(state.chatHits, state.plan.length - 1);
      const step = state.plan[index];
      state.chatHits += 1;
      req.resume();
      req.on("end", () => {
        if (step === "ok") {
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify({
            message: { role: "assistant", content: "router-ok" },
            done: true, done_reason: "stop",
            prompt_eval_count: 7, eval_count: 3,
          }));
        } else {
          res.writeHead(step, { "content-type": "application/json" });
          res.end(JSON.stringify({ error: `scripted ${step}` }));
        }
      });
      return;
    }
    res.writeHead(404); res.end("{}");
  });
  await new Promise((resolve) => server.listen(port, "127.0.0.1", resolve));
  return {
    url: `http://127.0.0.1:${port}`,
    get chatHits() { return state.chatHits; },
    reset() { state.chatHits = 0; },
    setPlan(next) { state.plan = [...next]; state.chatHits = 0; },
    stop() { try { server.close(); } catch { /* best effort */ } },
  };
}

/**
 * An OpenAI-compatible provider that answers a metered `content_filter` finish.
 *
 * This exists because ollama's failure shapes carry NO token mix, so a retry there cannot
 * distinguish "charge the accumulated mix" from "charge the last attempt's mix" — the two are equal
 * and any assertion about accumulation would pass against its own defect. A `content_filter` finish
 * is receipted as a typed FAILURE that DOES carry its observed usage, which is exactly the case
 * where dropping earlier attempts becomes a silent undercharge.
 */
async function startFilteringProvider(promptTokens, completionTokens) {
  const port = await freePort();
  const state = { hits: 0 };
  const server = http.createServer((req, res) => {
    state.hits += 1;
    req.resume();
    req.on("end", () => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({
        choices: [{ index: 0, message: { role: "assistant", content: "" }, finish_reason: "content_filter" }],
        usage: { prompt_tokens: promptTokens, completion_tokens: completionTokens },
      }));
    });
  });
  await new Promise((resolve) => server.listen(port, "127.0.0.1", resolve));
  return {
    url: `http://127.0.0.1:${port}`,
    get chatHits() { return state.hits; },
    reset() { state.hits = 0; },
    stop() { try { server.close(); } catch { /* best effort */ } },
  };
}

const daemonBinary = path.resolve(ROOT, process.env.IOI_HYPERVISOR_DAEMON_BINARY ?? "target/debug/hypervisor-daemon");
try {
  fs.accessSync(daemonBinary, fs.constants.X_OK);
} catch {
  console.error(`BLOCKED: daemon binary not executable at ${daemonBinary}`);
  process.exit(2);
}

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-router-decisions-"));
let daemon = null;
let DAEMON = "";
const P = { A: { session: "", owner: "" }, B: { session: "", owner: "" } };
const providers = [];

const jd = (method, p, body, { as = "A", idem = null } = {}) => {
  const session = as ? P[as]?.session ?? "" : "";
  const payload = body && idem ? { owner_ref: P[as]?.owner ?? "", idempotency_key: idem, ...body } : body;
  return fetch(`${DAEMON}${p}`, {
    method,
    headers: {
      ...(payload ? { "content-type": "application/json" } : {}),
      ...(session ? { cookie: `ioi_session=${session}` } : {}),
    },
    ...(payload ? { body: JSON.stringify(payload) } : {}),
  }).then(async (r) => {
    const text = await r.text();
    let j = null; try { j = JSON.parse(text); } catch { /* non-json */ }
    return { status: r.status, j, text };
  }).catch((e) => ({ status: 0, j: { transport_error: String(e) }, text: String(e) }));
};

/** Create + probe + enable a route pointing at `providerUrl`, as principal `as`. */
async function liveRoute(providerUrl, as, tag) {
  const created = await jd("POST", "/v1/hypervisor/model-routes", {
    model_id: MODEL, transport: "ollama", base_url: providerUrl, display_name: `router ${tag}`,
  }, { as, idem: `router-create-${tag}` });
  const id = created.j?.route?.route_id ?? "";
  await jd("POST", `/v1/hypervisor/model-routes/${id}/probe`, null, { as });
  await jd("POST", `/v1/hypervisor/model-routes/${id}/enable`, null, { as });
  return id;
}

const invocation = (j) => j?.invocation ?? {};
const lineageOf = (j) => invocation(j).evidence?.attempts ?? [];

function cleanup() {
  for (const p of providers) p.stop();
  try { daemon?.kill("SIGTERM"); } catch { /* already gone */ }
  try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch { /* best effort */ }
}

async function run() {
  const daemonPort = await freePort();
  DAEMON = `http://127.0.0.1:${daemonPort}`;
  daemon = spawn(daemonBinary, [], {
    cwd: ROOT,
    env: {
      ...process.env,
      IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${daemonPort}`,
      IOI_HYPERVISOR_DATA_DIR: dataDir,
      // Deliberately dead: nothing here may reach a provider through the boot-time env singleton.
      IOI_HYPERVISOR_MODEL_UPSTREAM: "http://127.0.0.1:1",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let log = "";
  daemon.stdout.on("data", (c) => { log = `${log}${c}`.slice(-64000); });
  daemon.stderr.on("data", (c) => { log = `${log}${c}`.slice(-64000); });
  await waitFor(`${DAEMON}/healthz`, 30000);

  const bootToken = log.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
  P.A.session = (await jd("POST", "/v1/hypervisor/auth/bootstrap",
    { token: bootToken, password: "router-decisions-v1" }, { as: null })).j?.session_token ?? "";
  const whoA = (await jd("GET", "/v1/hypervisor/auth/whoami", null, { as: "A" })).j || {};
  P.A.owner = (whoA.principal?.tenant_refs || []).find((t) => t === "org://local") || "";
  ok("the verifier holds a real authenticated admin session",
    whoA.authenticated === true && !!P.A.owner, P.A.owner);

  // A second principal, for the fallback-ownership proof. Same tenant — the product shape.
  const bEmail = "router-b@ioi.local";
  const bId = (await jd("POST", "/v1/hypervisor/principals",
    { email: bEmail, name: "Router B", role: "member", password: "router-b-v1" }, { as: "A" })).j?.principal?.principal_id ?? "";
  await jd("POST", `/v1/hypervisor/principals/${bId}/tenant-memberships`, {
    tenant_ref: "org://local", expected_revision: 0,
    idempotency_key: "router-grant-b-1", reason: "verifier fixture: an ordinary member",
  }, { as: "A" });
  P.B.session = (await jd("POST", "/v1/hypervisor/auth/login",
    { email: bEmail, password: "router-b-v1" }, { as: null })).j?.session_token ?? "";
  P.B.owner = "org://local";

  const failing = await startProvider([503]);       // retryable forever
  const succeeding = await startProvider(["ok"]);
  providers.push(failing, succeeding);

  const failId = await liveRoute(failing.url, "A", "failing");
  const okId = await liveRoute(succeeding.url, "A", "succeeding");
  ok("a route pointing at a controllable provider probes executable and can be invoked",
    !!failId && !!okId, `${failId} / ${okId}`);

  // ---------------------------------------------------------------- A. one attempt by default
  failing.reset();
  const plain = await jd("POST", `/v1/hypervisor/model-routes/${failId}/invoke`,
    { prompt: "hello" }, { as: "A", idem: "router-default" });
  const plainLineage = lineageOf(plain.j);
  ok("DEFAULT IS ONE ATTEMPT: an invocation that does not ask for retries records exactly one",
    plainLineage.length === 1, `${plainLineage.length} attempt(s)`);
  // The tally, not the record's own account of itself.
  ok("DEFAULT (contact): the provider was contacted exactly ONCE — retries are off unless asked for",
    failing.chatHits === 1, `${failing.chatHits} request(s)`);
  ok("the single attempt records the router's decision to give up rather than leaving it unstated",
    plainLineage[0]?.router_decision === "give_up", plainLineage[0]?.router_decision);
  ok("the attempt carries the ROUTER's own columns beside the transport's classification",
    plainLineage[0]?.route_id === failId && plainLineage[0]?.attempt_on_route === 1
      && plainLineage[0]?.retryable === true && plainLineage[0]?.error_class === "ProviderUnavailable",
    JSON.stringify(plainLineage[0] ?? {}).slice(0, 160));

  // ---------------------------------------------------------------- B. retry is opt-in and bounded
  failing.reset();
  const retried = await jd("POST", `/v1/hypervisor/model-routes/${failId}/invoke`,
    { prompt: "hello", retry: { max_attempts: 3 } }, { as: "A", idem: "router-retry-3" });
  const retryLineage = lineageOf(retried.j);
  ok("A RETRY MINTS A NEW ATTEMPT: three authorized attempts record three lineage entries",
    retryLineage.length === 3, `${retryLineage.length} attempt(s)`);
  ok("RETRY (contact): the provider was contacted exactly three times — the lineage is not a story about one call",
    failing.chatHits === 3, `${failing.chatHits} request(s)`);
  ok("the lineage numbers the attempts against their route and records the decision that produced each",
    retryLineage.map((a) => a.attempt_on_route).join(",") === "1,2,3"
      && retryLineage.slice(0, 2).every((a) => a.router_decision === "retry_same_route")
      && retryLineage[2]?.router_decision === "give_up",
    retryLineage.map((a) => `${a.attempt_on_route}:${a.router_decision}`).join(" "));
  ok("the invocation reports its attempt count and how many routes it touched",
    invocation(retried.j).evidence?.attempt_count === 3
      && invocation(retried.j).evidence?.routes_attempted === 1,
    `count ${invocation(retried.j).evidence?.attempt_count} routes ${invocation(retried.j).evidence?.routes_attempted}`);

  const tooMany = await jd("POST", `/v1/hypervisor/model-routes/${failId}/invoke`,
    { prompt: "hello", retry: { max_attempts: 99 } }, { as: "A", idem: "router-retry-99" });
  ok("an unbounded retry request REFUSES rather than silently clamping — the caller is told what an attempt costs",
    tooMany.status === 400 && code(tooMany.j) === "model_invocation_retry_policy_invalid",
    `status ${tooMany.status} code ${code(tooMany.j)}`);
  const zero = await jd("POST", `/v1/hypervisor/model-routes/${failId}/invoke`,
    { prompt: "hello", retry: { max_attempts: 0 } }, { as: "A", idem: "router-retry-0" });
  ok("a zero-attempt policy refuses", zero.status === 400, `status ${zero.status}`);

  // ---------------------------------------------------------------- C. retry stops on success
  const flaky = await startProvider([503, "ok"]);
  providers.push(flaky);
  const flakyId = await liveRoute(flaky.url, "A", "flaky");
  flaky.reset();
  const recovered = await jd("POST", `/v1/hypervisor/model-routes/${flakyId}/invoke`,
    { prompt: "hello", retry: { max_attempts: 3 } }, { as: "A", idem: "router-recover" });
  const recoveredLineage = lineageOf(recovered.j);
  ok("A RETRY THAT SUCCEEDS STOPS: a fail-then-succeed provider yields a succeeded invocation in two attempts",
    recovered.status === 200 && invocation(recovered.j).outcome === "succeeded"
      && recoveredLineage.length === 2,
    `status ${recovered.status} outcome ${invocation(recovered.j).outcome} attempts ${recoveredLineage.length}`);
  ok("RECOVERY (contact): the provider was contacted twice and not a third time — the router stopped when it had an answer",
    flaky.chatHits === 2, `${flaky.chatHits} request(s)`);
  ok("the successful attempt is not decorated with a decision, because none was needed",
    recoveredLineage[1]?.router_decision === null && recoveredLineage[1]?.outcome === "succeeded",
    `${recoveredLineage[1]?.router_decision} / ${recoveredLineage[1]?.outcome}`);

  // ---------------------------------------------------------------- D. non-retryable is not retried
  const hard = await startProvider([413]); // ContextOverflow — classified NOT retryable
  providers.push(hard);
  const hardId = await liveRoute(hard.url, "A", "hard");
  hard.reset();
  const hardFail = await jd("POST", `/v1/hypervisor/model-routes/${hardId}/invoke`,
    { prompt: "hello", retry: { max_attempts: 3 } }, { as: "A", idem: "router-hard" });
  const hardLineage = lineageOf(hardFail.j);
  ok("THE CLASSIFICATION IS OBEYED: a NON-retryable failure is not retried even when retries are authorized",
    hardLineage.length === 1 && hardLineage[0]?.retryable === false
      && hardLineage[0]?.error_class === "ContextOverflow",
    `${hardLineage.length} attempt(s) retryable ${hardLineage[0]?.retryable} class ${hardLineage[0]?.error_class}`);
  ok("NON-RETRYABLE (contact): the provider was contacted exactly once despite a 3-attempt budget",
    hard.chatHits === 1, `${hard.chatHits} request(s)`);

  // ---------------------------------------------------------------- E. fallback
  failing.reset();
  succeeding.reset();
  const fellBack = await jd("POST", `/v1/hypervisor/model-routes/${failId}/invoke`, {
    prompt: "hello", fallback_route_refs: [`model-route:${okId}`],
  }, { as: "A", idem: "router-fallback" });
  const fbLineage = lineageOf(fellBack.j);
  ok("A FALLBACK IS TAKEN: a failing primary with a declared alternative yields a succeeded invocation",
    fellBack.status === 200 && invocation(fellBack.j).outcome === "succeeded",
    `status ${fellBack.status} outcome ${invocation(fellBack.j).outcome}`);
  ok("FALLBACK (contact): BOTH providers were contacted — the primary once, then the alternative once",
    failing.chatHits === 1 && succeeding.chatHits === 1,
    `primary ${failing.chatHits} fallback ${succeeding.chatHits}`);
  ok("the lineage spans TWO routes and names which route each attempt hit",
    invocation(fellBack.j).evidence?.routes_attempted === 2
      && fbLineage.length === 2 && fbLineage[0]?.route_id === failId && fbLineage[1]?.route_id === okId,
    fbLineage.map((a) => a.route_id).join(" -> "));
  ok("the primary's exhausted attempt records the decision to move on, not merely that it failed",
    fbLineage[0]?.router_decision === "fallback_next_route", fbLineage[0]?.router_decision);
  // The record must describe the route that ANSWERED, not the one that was asked first.
  ok("the invocation record names the route that actually answered, not the primary it started from",
    invocation(fellBack.j).route_id === okId && invocation(fellBack.j).base_url === succeeding.url,
    `${invocation(fellBack.j).route_id} @ ${invocation(fellBack.j).base_url}`);

  // ---------------------------------------------------------------- F. a fallback is GATED
  // THE ATTACKER MUST BE THE UNPRIVILEGED PRINCIPAL. An earlier revision had principal A — the
  // deployment ADMIN — declare B's route as a fallback and expected a refusal; it got a 200, and
  // correctly so, because an admin may administer any route. The assertion was measuring nothing.
  // B is an ordinary member, so only ownership can decide the case.
  const bFailing = await startProvider([503]);
  providers.push(bFailing);
  const bFailId = await liveRoute(bFailing.url, "B", "b-owned-failing");
  bFailing.reset();
  succeeding.reset();
  const stolen = await jd("POST", `/v1/hypervisor/model-routes/${bFailId}/invoke`, {
    prompt: "hello", fallback_route_refs: [`model-route:${okId}`],
  }, { as: "B", idem: "router-fallback-steal" });
  ok("A FALLBACK THE CALLER DOES NOT OWN IS REFUSED — a declared alternative is not a way around ownership",
    stolen.status === 403 && code(stolen.j) === "model_route_owner_mismatch",
    `status ${stolen.status} code ${code(stolen.j)}`);
  ok("the refused fallback contacted NEITHER provider: the target list is validated before anything executes",
    bFailing.chatHits === 0 && succeeding.chatHits === 0,
    `primary ${bFailing.chatHits} victim ${succeeding.chatHits}`);

  const unprobed = await jd("POST", "/v1/hypervisor/model-routes", {
    model_id: MODEL, transport: "ollama", base_url: succeeding.url, display_name: "declared only",
  }, { as: "A", idem: "router-unprobed" });
  const unprobedId = unprobed.j?.route?.route_id ?? "";
  const notExecutable = await jd("POST", `/v1/hypervisor/model-routes/${failId}/invoke`, {
    prompt: "hello", fallback_route_refs: [`model-route:${unprobedId}`],
  }, { as: "A", idem: "router-fallback-unprobed" });
  ok("a NON-EXECUTABLE fallback is refused typed, never silently skipped — a backup is admitted by the same rules as a primary",
    notExecutable.status === 409 && code(notExecutable.j) === "model_route_not_executable",
    `status ${notExecutable.status} code ${code(notExecutable.j)}`);

  const dup = await jd("POST", `/v1/hypervisor/model-routes/${failId}/invoke`, {
    prompt: "hello", fallback_route_refs: [`model-route:${failId}`],
  }, { as: "A", idem: "router-fallback-dup" });
  ok("naming the primary as its own fallback refuses, and says to use retry instead",
    dup.status === 400 && code(dup.j) === "model_invocation_fallback_routes_invalid",
    `status ${dup.status} code ${code(dup.j)}`);

  const tooManyHops = await jd("POST", `/v1/hypervisor/model-routes/${failId}/invoke`, {
    prompt: "hello",
    fallback_route_refs: [`model-route:${okId}`, `model-route:${flakyId}`, `model-route:${hardId}`, `model-route:${unprobedId}`],
  }, { as: "A", idem: "router-fallback-many" });
  ok("an unbounded fallback chain refuses — every hop is its own authority crossing",
    tooManyHops.status === 400 && code(tooManyHops.j) === "model_invocation_fallback_routes_invalid",
    `status ${tooManyHops.status}`);

  // ---------------------------------------------------------------- G. credentialed routes REFUSE
  // A credential crossing is deterministic: same route, same grant, same facets means the second
  // crossing is byte-identical to the first and the substrate reads it as a replay. Rather than
  // weaken that, the router refuses multi-attempt and multi-target invocations on credentialed
  // routes, typed and before anything executes.
  const credRoute = await jd("POST", "/v1/hypervisor/model-routes", {
    model_id: MODEL, transport: "openai_compatible", base_url: succeeding.url,
    display_name: "credentialed", credential_posture: "provider_vault_token", env_key_name: "PATH",
  }, { as: "A", idem: "router-cred-create" });
  const credId = credRoute.j?.route?.route_id ?? "";
  await jd("POST", `/v1/hypervisor/model-routes/${credId}/probe`, null, { as: "A" });
  await jd("POST", `/v1/hypervisor/model-routes/${credId}/enable`, null, { as: "A" });
  succeeding.reset();
  const credRetry = await jd("POST", `/v1/hypervisor/model-routes/${credId}/invoke`,
    { prompt: "hello", retry: { max_attempts: 2 } }, { as: "A", idem: "router-cred-retry" });
  ok("A CREDENTIALED ROUTE REFUSES RETRIES, typed — a second crossing would read as a replay of the first, and reusing one grant across attempts is the weakening the spend gate exists to prevent",
    credRetry.status === 501 && code(credRetry.j) === "model_invocation_multi_attempt_credentialed_unsupported",
    `status ${credRetry.status} code ${code(credRetry.j)}`);
  const credFallback = await jd("POST", `/v1/hypervisor/model-routes/${credId}/invoke`,
    { prompt: "hello", fallback_route_refs: [`model-route:${okId}`] }, { as: "A", idem: "router-cred-fb" });
  ok("A CREDENTIALED ROUTE REFUSES A FALLBACK CHAIN — one grant is bound to one destination, so a second hop could never authorize",
    credFallback.status === 501 && code(credFallback.j) === "model_invocation_multi_attempt_credentialed_unsupported",
    `status ${credFallback.status} code ${code(credFallback.j)}`);
  ok("the refusal happens BEFORE execution: the provider was never contacted",
    succeeding.chatHits === 0, `${succeeding.chatHits} request(s)`);

  const badType = await jd("POST", `/v1/hypervisor/model-routes/${failId}/invoke`,
    { prompt: "hello", retry: { max_attempts: "3" } }, { as: "A", idem: "router-retry-typed" });
  ok("a PRESENT-but-unreadable retry budget refuses rather than silently falling back to one attempt",
    badType.status === 400 && code(badType.j) === "model_invocation_retry_policy_invalid",
    `status ${badType.status} code ${code(badType.j)}`);

  // ---------------------------------------------------------------- H. backoff is the router's
  failing.reset();
  const backoffStart = Date.now();
  await jd("POST", `/v1/hypervisor/model-routes/${failId}/invoke`,
    { prompt: "hello", retry: { max_attempts: 3 } }, { as: "A", idem: "router-backoff" });
  const backoffElapsed = Date.now() - backoffStart;
  // 250ms before the 2nd attempt + 1000ms before the 3rd. Without backoff a 429 is answered with
  // immediate re-hits under the owner's key, which turns throttling into a ban.
  ok("A RETRY BACKS OFF: three attempts take at least the two backoff steps, so a rate limit is not answered with immediate re-hits",
    backoffElapsed >= 1250 && failing.chatHits === 3, `${backoffElapsed}ms over ${failing.chatHits} attempts`);

  // ---------------------------------------------------------------- I. the charge follows the lineage
  const card = await jd("POST", "/v1/hypervisor/economics/rate-cards", {
    currency_code: "USD", ioi_fee_policy_ref: "policy://ioi/fees", validity_seconds: 3600,
    meter_rates: [{ meter_class: "model_tokens", work_credit_micro_units_per_meter_unit: 5, charge_component: "managed_model" }],
  }, { as: "A", idem: "router-card" });
  const cardRef = card.j?.rate_card?.object?.rate_card_ref ?? "";
  const plan = await jd("POST", "/v1/hypervisor/economics/plans", {
    rate_card_ref: cardRef, included_work_credit_units: 0, reset_policy: "non_resetting", validity_seconds: 3600,
  }, { as: "A", idem: "router-plan" });
  const quote = await jd("POST", "/v1/hypervisor/economics/quotes", {
    rate_card_ref: cardRef, plan_ref: plan.j?.plan?.object?.plan_ref ?? "", work_ref: "work://ioi/router-decisions",
    estimated_work_credit_units: 1_000_000, overrun_policy: "exact_additional_hold", max_attempt_count: 3,
    allowed_commercial_postures: ["managed", "local"], validity_seconds: 600,
  }, { as: "A", idem: "router-quote" });
  const quoteRef = quote.j?.quote?.object?.quote_ref ?? "";
  await jd("POST", "/v1/hypervisor/economics/holds",
    { quote_ref: quoteRef, amount_units: 1_000_000, hold_kind: "initial" }, { as: "A", idem: "router-hold" });

  // A METERED FAILURE, then a success. The first attempt really consumes 9000+400 tokens and fails;
  // the second consumes 7+3 and succeeds. Charging only the final attempt would bill 10 for a call
  // that consumed 9410 — and because the final mix is complete, `evidence_gaps` would be empty and
  // nothing would mark the measurement short.
  const filtering = await startFilteringProvider(9000, 400);
  providers.push(filtering);
  const filteredCreate = await jd("POST", "/v1/hypervisor/model-routes", {
    model_id: MODEL, transport: "openai_compatible", base_url: filtering.url,
    display_name: "metered filter", credential_posture: "no_credentials_required",
  }, { as: "A", idem: "router-filtered-create" });
  const filteredId = filteredCreate.j?.route?.route_id ?? "";
  await jd("POST", `/v1/hypervisor/model-routes/${filteredId}/probe`, null, { as: "A" });
  await jd("POST", `/v1/hypervisor/model-routes/${filteredId}/enable`, null, { as: "A" });
  succeeding.reset();
  filtering.reset();
  const billed = await jd("POST", `/v1/hypervisor/model-routes/${filteredId}/invoke`, {
    prompt: "hello", fallback_route_refs: [`model-route:${okId}`],
    economics: { quote_ref: quoteRef, commercial_posture: "managed" },
  }, { as: "A", idem: "router-billed" });
  const billedEvidence = invocation(billed.j).evidence ?? {};
  const billedRows = lineageOf(billed.j) || [];
  const lineageSum = billedRows.reduce((acc, row) => acc + (row?.token_mix?.total ?? 0), 0);
  const finalOnly = billedRows.at(-1)?.token_mix?.total ?? 0;
  ok("the failed attempt really METERED tokens, so accumulation is distinguishable from charging the last attempt",
    lineageSum > finalOnly && finalOnly > 0,
    `lineage sum ${lineageSum} vs final-only ${finalOnly}`);
  ok("THE CHARGE FOLLOWS THE WHOLE LINEAGE: what the ledger is handed is the sum of every attempt's metered tokens, not just the last one's",
    billedEvidence.billed_token_mix?.total === lineageSum,
    `billed ${billedEvidence.billed_token_mix?.total} vs lineage sum ${lineageSum}`);
  // The ledger row itself, not the daemon's account of what it meant to charge.
  const quoteId = quoteRef.split("/").pop() ?? "";
  const bundle = await jd("GET", `/v1/hypervisor/economics/quotes/${quoteId}/ledger-bundle`, null, { as: "A" });
  const lastRow = (bundle.j?.ledger_bundle?.usage_records ?? []).at(-1) ?? {};
  ok("the LEDGER ROW carries the accumulated quantity, so a dropped attempt would be an undercharge on the durable record",
    lastRow.quantity_units === lineageSum && lastRow.meter_class === "model_tokens",
    `row ${lastRow.quantity_units} vs ${lineageSum}`);
  ok("every attempt records what IT metered, so an undercharge would be visible rather than silent",
    billedRows.every((row) => row?.token_mix !== undefined), `${billedRows.length} row(s)`);

  // ---------------------------------------------------------------- J. no spend gate weakened
  // Against a REAL quote. An earlier revision posted a nonexistent quote_ref and accepted 403-or-404
  // — which `mint_final_debit` answers by resolving the quote, long before `require_spend_authority`
  // is reached. That assertion would have passed with the spend gate deleted from the file.
  const debit = await jd("POST", "/v1/hypervisor/economics/final-debits",
    { quote_ref: quoteRef }, { as: "A", idem: "router-debit" });
  ok("NO SPEND WITHOUT AUTHORITY: a debit over a REAL, held, billed quote still refuses without a live grant",
    debit.status === 403 && code(debit.j) === "economics_spend_authority_required",
    `status ${debit.status} code ${code(debit.j)}`);

  // ---------------------------------------------------------------- H. named residual
  // Every attempt resolves its own credential crossing, and for a CREDENTIALED route that means one
  // `authorize_capability_lease` per attempt — a wallet-owned grant use per try. That is the whole
  // reason retries default to off. It cannot be counted in this lane: these routes are
  // `no_credentials_required`, so they mint no lease, and proving the per-attempt crossing needs the
  // real one-validator wallet.network cluster the `--live-authority` lane stands up. Recorded as a
  // named residual rather than asserted here on evidence this lane does not have.
  // Anchored on the reason itself — the crossing these routes actually record — rather than on
  // another assertion's condition. Re-using the retry lineage here would have been a weaker
  // duplicate that goes red for a defect its label does not claim, which is exactly what it did in
  // one mutation before being re-aimed.
  ok("RESIDUAL, recorded not hidden: these routes cross NOTHING (`none_required`), so per-attempt credential crossings are countable only in the --live-authority lane",
    invocation(retried.j).credential?.crossing === "none_required",
    invocation(retried.j).credential?.crossing);

  const fails = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
  console.log(`\n${results.length - fails.length}/${results.length} passed`);
  emitVerifierCensus({ verifierId: "model-router-decisions", sourceUrl: import.meta.url, results });
  cleanup();
  process.exit(fails.length ? 1 : 0);
}

run().catch((error) => {
  console.error(`FAIL model-router-decisions — ${error?.stack || error}`);
  cleanup();
  process.exit(1);
});
