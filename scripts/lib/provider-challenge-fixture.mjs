// Minting a direct-Akash `deployment_intent` capability-lease challenge from an ISOLATED daemon,
// spend-free (M03.9, register R-212). Nothing here can spend: the provider account carries a sealed
// FAKE credential, its endpoint is set to live mode at a dead loopback address, and no provider
// call precedes the authority challenge — the daemon refuses the create at the wallet gate and
// echoes the challenge (with `lease_request_facets` and, since R-212, the two preimages) before it
// would ever reach a provider. No grant is ever presented, so nothing is admitted or cast.
//
// Used by scripts/mint-provider-challenge-fixture.mjs (the tracked fixture, minted once) and by
// check:approval-card-facets in full mode (a fresh challenge, cross-checked against the fixture).
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

export const FIXTURE_SCHEMA = "ioi.evidence.provider-challenge-fixture.v1";
export const DEAD_ENDPOINT = "http://127.0.0.1:9";
export const PLAN_SDL = "version: \"2.0\"\nservices:\n  web:\n    image: nginx:alpine\n    expose:\n      - port: 80\n        as: 80\n        to:\n          - global: true\nprofiles:\n  compute:\n    web:\n      resources:\n        cpu:\n          units: 0.1\n        memory:\n          size: 128Mi\n        storage:\n          size: 128Mi\n  placement:\n    dcloud:\n      pricing:\n        web:\n          denom: uact\n          amount: 1000\ndeployment:\n  web:\n    dcloud:\n      profile: web\n      count: 1\n";
const SECRET = /(password|session_token|sealed_token|api[_-]?key|secret|private[_-]?key|mnemonic|bearer|authorization)/iu;
const stable = (v) => JSON.stringify(v, (k, x) => (x && typeof x === "object" && !Array.isArray(x) ? Object.fromEntries(Object.keys(x).sort().map((key) => [key, x[key]])) : x));
export const sha = (v) => `sha256:${crypto.createHash("sha256").update(typeof v === "string" ? v : stable(v), "utf8").digest("hex")}`;
export function redact(value, redacted, at = "$") {
  if (Array.isArray(value)) return value.map((x, i) => redact(x, redacted, `${at}[${i}]`));
  if (value && typeof value === "object") {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      if (SECRET.test(k)) { redacted.push(`${at}.${k}`); continue; }
      out[k] = redact(v, redacted, `${at}.${k}`);
    }
    return out;
  }
  if (typeof value === "string" && /ioi_(sess|bootstrap)_[A-Za-z0-9_-]+|(?:^|[^A-Za-z0-9])sk-[A-Za-z0-9_-]{12,}/u.test(value)) { redacted.push(at); return "<redacted>"; }
  return value;
}

export function bootstrapToken(dataDir) {
  const log = fs.readFileSync(path.join(dataDir, "isolated-daemon.log"), "utf8");
  return log.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
}

/**
 * Drive the isolated daemon to the challenge. Returns the request body that was posted (no secret),
 * the daemon's reply status and the challenge JSON, plus the steps taken (each with its status).
 */
function daemonCalls({ daemonUrl, cookie }) {
  const steps = [];
  const jd = async (method, route, body) => {
    const r = await fetch(`${daemonUrl}${route}`, { method, headers: { "content-type": "application/json", ...(cookie ? { cookie } : {}) }, body: body ? JSON.stringify(body) : undefined });
    const j = await r.json().catch(() => ({}));
    steps.push({ method, route, status: r.status, reason: j?.reason ?? j?.error?.code ?? null });
    return { status: r.status, j };
  };
  return { jd, steps };
}

/**
 * The spend-free LIVE deployment_intent setup: an Akash account with a sealed FAKE credential, live mode at
 * a dead loopback endpoint, an external-spend budget — and the request body the wallet gate will refuse
 * with its challenge before any provider call. Used by the fixture mint and by M08.11's lane (which posts
 * the body through the App instead of straight at the daemon).
 */
export async function prepareProviderAccount({ daemonUrl, cookie, tag = "m03-9", environment = `env-approval-card-${tag}` }) {
  const { jd, steps } = daemonCalls({ daemonUrl, cookie });
  const account = (await jd("POST", "/v1/hypervisor/provider-accounts", { kind: "akash", display_name: `Akash approval-card ${tag}` })).j.account ?? {};
  const accountId = account.account_id;
  if (!accountId) throw new Error(`provider account was not created: ${JSON.stringify(steps.at(-1))}`);
  await jd("POST", `/v1/hypervisor/provider-accounts/${accountId}/credential`, { api_key: `FAKE-AKASH-KEY-${tag}-never-valid` });
  await jd("POST", `/v1/hypervisor/provider-accounts/${accountId}/preflight`);
  await jd("PATCH", `/v1/hypervisor/provider-accounts/${accountId}`, { endpoint: { mode: "live", endpoint: DEAD_ENDPOINT } });
  await jd("POST", `/v1/hypervisor/provider-accounts/${accountId}/preflight`);
  await jd("POST", "/v1/hypervisor/resource/budgets", { budget_id: `approval-card-${tag}`, name: `Approval card ${tag}`, scope: "external_spend", limit: 5, spent: 0, currency: "USD" });
  const body = { provider_id: accountId, op: "create", environment_ref: environment, plan: { sdl_yaml: PLAN_SDL, deposit_usd: 1.0, ceiling_amount: "1000", ceiling_denom: "uact", auto_topup: false, provider_selector: { mode: "any_marketplace", selection: "lowest_qualified_bid" } }, owner_ref: "org://local", idempotency_key: `approval-card-${tag}`, teardown_policy: "always_teardown_required" };
  return { account: { account_id: accountId, account_ref: account.account_ref ?? null }, body, steps, jd };
}

export async function mintProviderChallenge({ daemonUrl, cookie, tag = "m03-9", environment = `env-approval-card-${tag}` }) {
  const prepared = await prepareProviderAccount({ daemonUrl, cookie, tag, environment });
  const reply = await prepared.jd("POST", "/v1/hypervisor/provider-ops", prepared.body);
  return { account: prepared.account, request_body: prepared.body, status: reply.status, challenge: reply.j, steps: prepared.steps };
}

// REAL Akash bid shapes for the daemon's fixture candidate source (the adapter done-bar's), so the simulator
// lane quotes a real-shaped bid; one bid carries no source-quoted USD and must be skipped, never converted.
export const SIMULATOR_BIDS = { bids: [
  { provider: "akash1gpuprov4090xq", region: "us-west", attributes: { tier: "community", auditor: "none" }, deployment_class: "compute.gpu_runtime", gpu: { model: "RTX 4090", count: 1, vram_gb: 24 }, cpu_milli: 8000, memory_gb: 32, storage_gb: 200, persistent_storage: true, price: { uakt_per_block: 145, usd_per_hour_quoted: 0.38, rate_basis: "console-quoted USD (uakt × oracle rate at quote time)" } },
  { provider: "akash1cpuprovzz7e", region: "eu-central", attributes: { tier: "datacenter" }, deployment_class: "compute.container", cpu_milli: 4000, memory_gb: 16, storage_gb: 100, persistent_storage: false, price: { uakt_per_block: 40, usd_per_hour_quoted: 0.11, rate_basis: "console-quoted USD (uakt × oracle rate at quote time)" } },
  { provider: "akash1unpricedbid", region: "ap-south", cpu_milli: 2000, memory_gb: 8, storage_gb: 50, price: { uakt_per_block: 99 } },
] };

/**
 * The spend-free SIMULATOR-mode setup (quote-gated facets): an Akash account with a sealed fake credential, a
 * fixture bids file the daemon quotes from, a candidate intent refreshed against it, the endpoint switched to
 * simulator mode with an ssh object (create records a simulated deployment and never connects), an
 * external-spend budget — and the quote-gated request body the wallet gate refuses with its challenge.
 */
export async function prepareSimulatorAccount({ daemonUrl, cookie, tag = "sim", scratch, environment = `env-approval-lane-${tag}` }) {
  const { jd, steps } = daemonCalls({ daemonUrl, cookie });
  const bidsFile = path.join(scratch, `akash-bids-${tag}.json`);
  fs.writeFileSync(bidsFile, JSON.stringify(SIMULATOR_BIDS));
  const keyFile = path.join(scratch, `sim-ssh-${tag}.key`);
  fs.writeFileSync(keyFile, "-----BEGIN OPENSSH PRIVATE KEY-----\nnot-a-key-the-simulator-create-never-connects\n-----END OPENSSH PRIVATE KEY-----\n", { mode: 0o600 });
  const account = (await jd("POST", "/v1/hypervisor/provider-accounts", { kind: "akash", display_name: `Akash approval-lane ${tag}` })).j.account ?? {};
  const accountId = account.account_id;
  if (!accountId) return { error: `provider account was not created: ${JSON.stringify(steps.at(-1))}`, steps };
  await jd("POST", `/v1/hypervisor/provider-accounts/${accountId}/credential`, { api_key: `FAKE-AKASH-KEY-${tag}-never-valid` });
  await jd("PATCH", `/v1/hypervisor/provider-accounts/${accountId}`, { endpoint: { mode: "fixture", fixture_file: bidsFile } });
  await jd("POST", `/v1/hypervisor/provider-accounts/${accountId}/preflight`);
  const intent = (await jd("POST", "/v1/hypervisor/cloud-candidates/intents", { runtime_class: "compute.gpu_runtime", resource_classes: ["compute.gpu_runtime", "compute.container"], gpu: { required: true } })).j.intent ?? {};
  await jd("POST", "/v1/hypervisor/cloud-candidates/candidates/refresh", { intent_ref: intent.intent_ref });
  await jd("PATCH", `/v1/hypervisor/provider-accounts/${accountId}`, { endpoint: { mode: "simulator", fixture_file: bidsFile, ssh: { host: "127.0.0.1", port: 2222, user: "ioi-simulator", key_file: keyFile } } });
  await jd("POST", `/v1/hypervisor/provider-accounts/${accountId}/preflight`);
  await jd("POST", "/v1/hypervisor/resource/budgets", { budget_id: `approval-lane-${tag}`, name: `Approval lane ${tag}`, scope: "external_spend", limit: 1, spent: 0, currency: "USD" });
  const refreshed = (await jd("POST", "/v1/hypervisor/cloud-candidates/candidates/refresh", { intent_ref: intent.intent_ref })).j;
  const candidate = (refreshed.candidates ?? []).find((c) => c.provider_kind === "akash" && c.provider_address === "akash1gpuprov4090xq");
  if (!candidate?.candidate_ref) return { error: `no simulator candidate: ${JSON.stringify(refreshed).slice(0, 200)}`, steps };
  const body = { provider_id: accountId, op: "create", environment_ref: environment, candidate_ref: candidate.candidate_ref, max_hourly_usd: 0.4, teardown_policy: "always_teardown_required", owner_ref: "org://local", idempotency_key: `approval-lane-${tag}` };
  return { account: { account_id: accountId, account_ref: account.account_ref ?? null }, candidate: { candidate_ref: candidate.candidate_ref, quote_ref: candidate.quote_ref ?? null, bid_ref: candidate.bid_ref ?? null }, body, steps, jd };
}

export function fixtureFrom({ minted, basis }) {
  const redacted = [];
  const challenge = redact(minted.challenge, redacted, "$.challenge");
  const fixture = {
    schema_version: FIXTURE_SCHEMA,
    minted_at: new Date().toISOString(),
    basis,
    what_this_is: "one direct-Akash deployment_intent capability-lease challenge minted by an ISOLATED daemon against a provider account holding a sealed FAKE credential, in live mode at a dead loopback endpoint, with an external-spend budget — the wallet gate refused the create and echoed the challenge before any provider call; no grant was presented, nothing was admitted or cast, nothing was spent",
    what_this_is_not: "not a grant, not an admitted lease and not a live run: the bytes a signing surface renders from and re-derives the request hash over; the runner cross-checks a fresh challenge from an isolated daemon against it in full mode",
    request_body: minted.request_body,
    status: minted.status,
    challenge,
    challenge_sha256: sha(challenge),
    redacted_members: redacted,
    steps: minted.steps,
  };
  return fixture;
}
