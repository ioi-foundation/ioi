#!/usr/bin/env node
// verify-hypervisor-provider-transport — W3.2 (check:provider-transport).
//
// Proves, against an ISOLATED real daemon, that the ProviderTransport boundary is composed and not
// shadowed: the invocation route resolves its endpoint from the model-route REGISTRY, refuses every
// non-executable posture with a typed code, keeps credential custody with the CapabilityLease
// gateway instead of reading a provider key from the process environment, fabricates no invocation
// record when it refuses, and — since the economics join landed — meters what it observed onto the
// ledger that prices it, or names the absence.
//
// WHAT THE JOIN ASSERTIONS ARE GUARDING AGAINST, stated so a later edit cannot quietly relax them:
//   * a charge nobody can audit — the row must cite the invocation ref, and that ref must resolve;
//   * a quantity the caller chose — the charged number is compared against the RECEIPT's observed
//     counts, not against the join's own report of itself;
//   * a zero that reads as free — an unmetered call mints NO row and says why;
//   * a double charge on retry — the replayed invocation must leave the chain's head hash intact;
//   * usage quietly becoming spend — a FinalDebit over the billed quote must still refuse.
//
// TWO LANES, and the split is deliberate:
//   default (CI)  — the refusal ladder, non-fabrication, and the billing block's request-SHAPE
//                   half. Needs no model provider, so it runs anywhere and its assertion count is
//                   DETERMINISTIC (the verifier-floors pin depends on that).
//   --live        — the native-first e2e against a REAL provider: success, streaming, observed
//                   token mix, latency, the typed kernel receipt, readback, idempotent replay, and
//                   the economics join end to end over a real quote and rate card.
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

  // ---------------------------------------------------------------- the billing block is REQUEST SHAPE
  // These run with no provider ON PURPOSE. The economics join's world-state half (does this quote
  // resolve, does it price model_tokens) needs a route that can actually execute, so it is proven
  // in the live lane — but a join whose ONLY proof needs a model provider is a claim CI never
  // checks. The shape half below is a pure function of the request, so it gates every commit.
  const econInvoke = (economics, idem, route = "mrt_local_default") =>
    jd("POST", `/v1/hypervisor/model-routes/${route}/invoke`, { prompt: "hello", economics }, { idem });

  const econScalar = await econInvoke("work-quote://eqt_scalar", "econ-not-object");
  ok("a non-object economics block is refused typed rather than coerced into a billing target",
    econScalar.status === 400 && code(econScalar.j) === "model_invocation_economics_invalid",
    `status ${econScalar.status} code ${code(econScalar.j)}`);

  const econNoQuote = await econInvoke({ commercial_posture: "managed" }, "econ-no-quote");
  ok("a billing block naming no quote is refused: a charge binds to exactly one quote",
    econNoQuote.status === 400 && code(econNoQuote.j) === "model_invocation_economics_quote_ref_required",
    `status ${econNoQuote.status} code ${code(econNoQuote.j)}`);

  const econNoPosture = await econInvoke({ quote_ref: "work-quote://eqt_x" }, "econ-no-posture");
  ok("a billing block naming no commercial posture is refused before anything is metered",
    econNoPosture.status === 400 && code(econNoPosture.j) === "model_invocation_economics_posture_required",
    `status ${econNoPosture.status} code ${code(econNoPosture.j)}`);

  // The INV-37 idiom applied to HOW MUCH. A caller who can name their own token count can name
  // their own bill, so every field that describes a charge rather than names a target is refused.
  const econQuantity = await econInvoke(
    { quote_ref: "work-quote://eqt_x", commercial_posture: "managed", quantity_units: 1 }, "econ-quantity");
  ok("a caller-supplied charge quantity is refused — the amount billed is the amount OBSERVED",
    econQuantity.status === 400
      && code(econQuantity.j) === "model_invocation_economics_quantity_not_client_settable",
    `status ${econQuantity.status} code ${code(econQuantity.j)}`);

  // Same typed 400 on a route that does not exist. That is the proof the block is validated as
  // request shape rather than after route resolution: it answers nothing about which routes exist,
  // and it stays reachable on a machine where no route could ever execute.
  const econUnknownRoute = await econInvoke(
    { commercial_posture: "managed" }, "econ-unknown-route", "mrt_does_not_exist");
  ok("the billing block is validated as request SHAPE — an unknown route answers the same typed 400, so it is neither an existence oracle nor gated on route health",
    econUnknownRoute.status === 400
      && code(econUnknownRoute.j) === "model_invocation_economics_quote_ref_required",
    `status ${econUnknownRoute.status} code ${code(econUnknownRoute.j)}`);

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

    // ------------------------------------------------------------ the economics chain to bill against
    // Built through the ledger's OWN routes, not seeded on disk: the join has to survive the same
    // quote/rate-card/hold admission every other charge does, including the `model_tokens` meter
    // class — which until this cut existed only in #[cfg(test)] rate-card fixtures.
    const card = await jd("POST", "/v1/hypervisor/economics/rate-cards", {
      currency_code: "USD", ioi_fee_policy_ref: "policy://ioi/fees", validity_seconds: 3600,
      meter_rates: [{ meter_class: "model_tokens", work_credit_micro_units_per_meter_unit: 5, charge_component: "managed_model" }],
    }, { idem: "econ-card" });
    const cardRef = card.j?.rate_card?.object?.rate_card_ref ?? "";
    const plan = await jd("POST", "/v1/hypervisor/economics/plans", {
      rate_card_ref: cardRef, included_work_credit_units: 0, reset_policy: "non_resetting", validity_seconds: 3600,
    }, { idem: "econ-plan" });
    const planRef = plan.j?.plan?.object?.plan_ref ?? "";
    const quote = await jd("POST", "/v1/hypervisor/economics/quotes", {
      rate_card_ref: cardRef, plan_ref: planRef, work_ref: "work://ioi/provider-transport-live",
      estimated_work_credit_units: 1_000_000, overrun_policy: "exact_additional_hold", max_attempt_count: 3,
      allowed_commercial_postures: ["managed", "local"], validity_seconds: 600,
    }, { idem: "econ-quote" });
    const quoteRef = quote.j?.quote?.object?.quote_ref ?? "";
    const quoteId = quoteRef.split("/").pop() ?? "";
    const hold = await jd("POST", "/v1/hypervisor/economics/holds",
      { quote_ref: quoteRef, amount_units: 1_000_000, hold_kind: "initial" }, { idem: "econ-hold" });
    ok("live: a real rate card priced for `model_tokens` carries a quote and a covering hold",
      card.status === 201 && plan.status === 201 && quote.status === 201 && hold.status === 201 && quoteId.startsWith("eqt_"),
      `card ${card.status} plan ${plan.status} quote ${quote.status} hold ${hold.status} ${quoteId}`);

    /** The DURABLE usage chain, read from the contract-validated ledger bundle — never self-report. */
    const usageRows = async () => {
      const bundle = await jd("GET", `/v1/hypervisor/economics/quotes/${quoteId}/ledger-bundle`);
      return bundle.j?.ledger_bundle?.usage_records ?? [];
    };
    ok("live: the quote's usage chain is empty before any invocation bills against it",
      (await usageRows()).length === 0, "0 rows");

    const invoked = await jd("POST", `/v1/hypervisor/model-routes/${liveId}/invoke`,
      { prompt: "Reply with exactly the word: composed", economics: { quote_ref: quoteRef, commercial_posture: "managed" } },
      { idem: "live-invoke-1" });
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
    // The gap list is TRANSPORT-scoped now that the join exists. It used to carry
    // `economics.usage_record` unconditionally — correct while nothing could be metered, and a lie
    // on a metered call. Whether the charge landed is answered by `economics`, its only owner.
    ok("live: the evidence gaps name only what the TRANSPORT could not observe, and no longer duplicate the join's answer",
      (evidence.evidence_gaps ?? []).includes("token_mix.cache_read")
        && !(evidence.evidence_gaps ?? []).includes("economics.usage_record"),
      JSON.stringify(evidence.evidence_gaps ?? []));

    // ------------------------------------------------------------ THE ECONOMICS JOIN
    const econ = inv.economics ?? {};
    const rows = await usageRows();
    const row = rows[0] ?? {};
    ok("live: the invocation MINTED a UsageRecord on the quote's hash-chained usage ledger",
      econ.joined === true && rows.length === 1 && typeof econ.usage_ref === "string"
        && row.usage_ref === econ.usage_ref && row.meter_class === "model_tokens",
      `joined ${econ.joined} rows ${rows.length} ${row.usage_ref} ${row.meter_class}`);

    // The quantity is not "a number the daemon reported"; it is arithmetic over the receipt's own
    // observed counts. Comparing against the receipt rather than against the join's self-report is
    // what makes this a check instead of an echo.
    const observedTotal = (receipt.prompt_tokens ?? -1) + (receipt.completion_tokens ?? -1);
    ok("live: the charged quantity EQUALS the receipt's observed token mix — input + output, not a declared number",
      receipt.prompt_tokens > 0 && receipt.completion_tokens > 0
        && row.quantity_units === observedTotal && econ.quantity_units === observedTotal
        && row.quantity_units === evidence.token_mix.total,
      `receipt ${receipt.prompt_tokens}+${receipt.completion_tokens}=${observedTotal} charged ${row.quantity_units}`);

    // Pricing, checked against the quantity the row ACTUALLY carries — not against the expected
    // one. Folding the expected quantity in here made this assertion fire whenever the quantity
    // was wrong, which its label does not claim and which the assertion above already owns.
    ok("live: the ledger priced the row from the QUOTE's rate card, and the daemon computed no charge of its own",
      row.rate_work_credit_micro_units_per_meter_unit === 5
        && row.charged_work_credits?.units === row.quantity_units * 5
        && row.sequence === 1 && row.previous_usage_hash === null,
      `rate ${row.rate_work_credit_micro_units_per_meter_unit} charged ${row.charged_work_credits?.units} seq ${row.sequence}`);

    // Both directions, each resolved through a real route rather than by string comparison.
    const joinKey = `model-invocation://${inv.invocation_id}`;
    const backFromCharge = await jd("GET", `/v1/hypervisor/model-invocations/${inv.invocation_id}`);
    ok("live: the join key resolves BOTH ways — the charge cites the invocation ref, and that ref reads back as the invocation",
      (row.runtime_receipt_refs ?? []).includes(joinKey)
        && econ.runtime_receipt_ref === joinKey
        && backFromCharge.status === 200
        && backFromCharge.j?.invocation?.economics?.usage_ref === row.usage_ref
        && econ.chain_ref === `usage-chain://${quoteId}`,
      `${joinKey} <-> ${row.usage_ref}`);

    const readback = backFromCharge;
    ok("live: the invocation reads back durably with its receipt intact",
      readback.status === 200 && readback.j?.invocation?.model_invocation_receipt?.output_hash?.length === 32,
      `status ${readback.status}`);

    // Each "no row was added" assertion below measures the DELTA it is responsible for. An earlier
    // revision compared against an absolute chain length, so a double charge minted anywhere made
    // all three go red and only one of them owned the defect.
    const beforeReplay = (await usageRows()).length;
    const replay = await jd("POST", `/v1/hypervisor/model-routes/${liveId}/invoke`,
      { prompt: "Reply with exactly the word: composed", economics: { quote_ref: quoteRef, commercial_posture: "managed" } },
      { idem: "live-invoke-1" });
    ok("live: an idempotent replay returns the STORED record and spends no second provider call",
      replay.status === 200 && replay.j?.replayed === true
        && replay.j?.invocation?.invocation_id === inv.invocation_id,
      `replayed ${replay.j?.replayed}`);
    const afterReplay = await usageRows();
    ok("live: the replay billed NOTHING — it added no row and the chain head still hashes to the first one",
      afterReplay.length === beforeReplay && afterReplay.at(-1).body_hash === row.body_hash,
      `${beforeReplay} -> ${afterReplay.length} row(s)`);

    // No billing block at all: an absent charge, named as absent. This is the distinction the whole
    // join exists to preserve — W4-F must be able to tell "not metered" from "metered at zero".
    const beforeStream = (await usageRows()).length;
    const streamed = await jd("POST", `/v1/hypervisor/model-routes/${liveId}/invoke`,
      { prompt: "Count: one two three", stream: true }, { idem: "live-invoke-stream" });
    const sEvidence = streamed.j?.invocation?.evidence ?? {};
    ok("live: the streaming lane completes and times its FIRST token separately from the total",
      streamed.status === 200 && streamed.j?.invocation?.outcome === "succeeded"
        && typeof sEvidence.latency?.first_token_ms === "number"
        && sEvidence.latency.first_token_ms <= sEvidence.latency.total_ms,
      `first ${sEvidence.latency?.first_token_ms}ms total ${sEvidence.latency?.total_ms}ms`);
    const sEcon = streamed.j?.invocation?.economics ?? {};
    ok("live: an invocation naming no quote records a TYPED GAP and mints no row — absent cost never reads as zero cost",
      sEcon.joined === false && sEcon.reason_code === "economics_join_not_requested"
        && sEcon.gap === "economics.usage_record" && sEcon.usage_ref === undefined
        && (await usageRows()).length === beforeStream,
      `${sEcon.reason_code} · chain ${beforeStream} -> ${(await usageRows()).length}`);

    // The failure path, executed for real. The route must be active AND available before the
    // provider disappears — patching base_url would invalidate the probe and refuse at 409, which
    // proves route hygiene rather than transport failure handling.
    //
    // So the route points at a TCP forwarder to the real provider. Every byte the daemon sees
    // during the probe is the genuine provider's; nothing here fabricates a provider response.
    // Killing the forwarder makes a healthy provider vanish exactly as a network partition would.
    //
    // It also COUNTS connections, which is how the ordering proof below is made observable rather
    // than asserted: the daemon reaching this provider is a TCP connection here, and a step that
    // must not spend a provider call must not produce one.
    const forwardPort = await freePort();
    const upstream = new URL(LIVE_BASE);
    let forwardConnections = 0;
    const forwarder = net.createServer((client) => {
      forwardConnections += 1;
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

    // ORDERING, OBSERVED. The route is active, available, and its provider is still reachable, so
    // an invocation that reaches execution WILL open a connection here. Naming an unresolvable
    // quote must refuse without opening one.
    //
    // An earlier revision of this assertion checked only that the answer was the ledger's 404 —
    // and it passed with the preflight moved AFTER execution, because the refusal returns 404
    // either way. That version proved nothing about ordering; the connection count does.
    const beforePreflight = forwardConnections;
    const preflight = await jd("POST", `/v1/hypervisor/model-routes/${deadId}/invoke`,
      { prompt: "never sent", economics: { quote_ref: "work-quote://eqt_nonexistent", commercial_posture: "managed" } },
      { idem: "dead-preflight" });
    await new Promise((r) => setTimeout(r, 250));
    ok("live: an unresolvable quote refuses typed WITHOUT opening a provider connection — the billing target resolves before the call is spent",
      preflight.status === 404 && code(preflight.j) === "economics_quote_not_found"
        && forwardConnections === beforePreflight,
      `status ${preflight.status} code ${code(preflight.j)} · provider connections ${beforePreflight} -> ${forwardConnections}`);

    await new Promise((resolve) => forwarder.close(resolve));

    const beforeFailed = (await usageRows()).length;
    const failed = await jd("POST", `/v1/hypervisor/model-routes/${deadId}/invoke`,
      { prompt: "this provider is gone", economics: { quote_ref: quoteRef, commercial_posture: "managed" } },
      { idem: "dead-invoke" });
    const fInv = failed.j?.invocation ?? {};
    ok("live: a vanished provider produces an HONEST failure record, never a fabricated completion",
      fInv.outcome === "failed"
        && fInv.model_invocation_receipt?.error_class === "ProviderUnavailable"
        && fInv.evidence?.attempts?.[0]?.retryable === true,
      `outcome ${fInv.outcome} class ${fInv.model_invocation_receipt?.error_class}`);
    // A failure the provider metered IS usage. This provider metered nothing, so the honest answer
    // is a typed gap and no row — not a zero-quantity charge that would read as a free call.
    ok("live: a failed invocation the provider metered NOTHING for records a typed gap and bills no row",
      fInv.economics?.joined === false
        && fInv.economics?.reason_code === "economics_join_token_mix_absent"
        && (fInv.economics?.unreported ?? []).includes("input")
        && fInv.economics?.outcome === "failed"
        && (await usageRows()).length === beforeFailed,
      `${fInv.economics?.reason_code} · chain ${beforeFailed} -> ${(await usageRows()).length}`);

    // NO SPEND WITHOUT AUTHORITY. The join makes a charge real; it does not make it spendable. A
    // FinalDebit over this exact billed quote still refuses without a live grant — asserted here,
    // bound to the row the join actually minted, rather than in the abstract.
    const debit = await jd("POST", "/v1/hypervisor/economics/final-debits",
      { quote_ref: quoteRef }, { idem: "econ-debit-no-grant" });
    // Subject: the REFUSAL. Chain length is asserted by the three assertions that own it; repeating
    // it here would make this one go red for reasons its label does not claim.
    ok("live: a metered UsageRecord authorizes NO spend — the FinalDebit over it still refuses without a live grant",
      debit.status === 403 && code(debit.j) === "economics_spend_authority_required",
      `status ${debit.status} code ${code(debit.j)}`);
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
