#!/usr/bin/env node
/**
 * Two-phase certified Akash campaign driver.
 *
 * Phase 1 (`--prepare-only`) performs no provider mutation and emits the exact
 * challenge. Phase 2 requires an owner-authored approval file binding those
 * exact hashes and facets before it can mint or cast the one-shot grant.
 */
import crypto from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import {
  appendFileSync,
  existsSync,
  mkdirSync,
  openSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { startRealWalletNetworkPrincipalAuthorityFixture } from "./lib/wallet-network-principal-authority-fixture.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const repo = path.resolve(here, "..", "..", "..");
const arg = (name) => {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : null;
};
const prepareOnly = process.argv.includes("--prepare-only");
const configArg = arg("--config");
const artifactsArg = arg("--artifacts");
const configPath = configArg ? path.resolve(configArg) : null;
const artifactDir = artifactsArg ? path.resolve(artifactsArg) : null;
const approvalPath = arg("--approval-file") ? path.resolve(arg("--approval-file")) : null;
if (!configPath || !artifactDir || (!prepareOnly && !approvalPath)) {
  throw new Error("usage: --config <json> --artifacts <dir> (--prepare-only | --approval-file <json>)");
}
mkdirSync(artifactDir, { recursive: true, mode: 0o700 });
const config = JSON.parse(readFileSync(configPath, "utf8"));
const daemonUrl = config.daemon_url || "http://127.0.0.1:8765";
const operatorEmail = process.env.IOI_C7_EMAIL || "";
const operatorPassword = process.env.IOI_C7_PASSWORD_FILE
  ? readFileSync(process.env.IOI_C7_PASSWORD_FILE, "utf8").trimEnd()
  : "";
const walletPass = process.env.IOI_WALLET_SECRET_PASS_FILE
  ? readFileSync(process.env.IOI_WALLET_SECRET_PASS_FILE, "utf8").trimEnd()
  : (process.env.IOI_WALLET_SECRET_PASS || "");
if (!operatorEmail || !operatorPassword || !walletPass) {
  throw new Error("IOI_C7_EMAIL, IOI_C7_PASSWORD_FILE, and an ephemeral IOI_WALLET_SECRET_PASS (or file) are required");
}
if (config.schema_version !== "ioi.hypervisor.certified-provider-campaign.v1") {
  throw new Error("unsupported campaign config schema");
}
if (!String(config.environment_ref || "").startsWith("env-")) throw new Error("environment_ref must start with env-");
if (!String(config.idempotency_key || "").trim()) throw new Error("idempotency_key is required");

const sha256 = (value) => `sha256:${crypto.createHash("sha256").update(value).digest("hex")}`;
const save = (name, value) => writeFileSync(path.join(artifactDir, name), `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
const log = (message) => {
  const line = `[certified-campaign] ${message}`;
  console.log(line);
  appendFileSync(path.join(artifactDir, "run.log"), `${line}\n`, { mode: 0o600 });
};
const headers = (session = "") => ({
  "Content-Type": "application/json",
  ...(session ? { cookie: `ioi_session=${session}` } : {}),
});
const request = {
  provider_id: config.provider_id,
  op: "create",
  environment_ref: config.environment_ref,
  owner_ref: config.owner_ref,
  idempotency_key: config.idempotency_key,
  plan: { ...config.plan, sdl_yaml: readFileSync(path.resolve(config.sdl_path), "utf8") },
};
const expectedSdlHash = sha256(request.plan.sdl_yaml);

async function daemonReady(timeoutMs = 90_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      if ((await fetch(`${daemonUrl}/v1/hypervisor/auth/bootstrap-status`)).status < 500) return;
    } catch {}
    await sleep(1_000);
  }
  throw new Error("daemon did not become ready");
}

async function postProvider(session, op, suffix = op) {
  const response = await fetch(`${daemonUrl}/v1/hypervisor/provider-ops`, {
    method: "POST",
    headers: headers(session),
    body: JSON.stringify({
      provider_id: config.provider_id,
      op,
      environment_ref: config.environment_ref,
      owner_ref: config.owner_ref,
      idempotency_key: `${config.idempotency_key}.${suffix}`,
    }),
  });
  const value = await response.json();
  save(`${op}-${suffix.replaceAll(".", "-")}.json`, value);
  log(`${op}: HTTP ${response.status}, ok=${value.ok === true}`);
  return { response, value };
}

async function capture(session) {
  for (const [name, endpoint] of [
    ["reconciliation", "/v1/hypervisor/provider-spend/reconciliation"],
    ["receipts", "/v1/hypervisor/provider-receipts"],
    ["deployments", "/v1/hypervisor/akash-deployments"],
    ["operations", "/v1/hypervisor/provider-operations"],
  ]) {
    const value = await fetch(`${daemonUrl}${endpoint}`, { headers: headers(session) }).then((response) => response.json());
    save(`${name}.json`, value);
  }
}

function verifyFacets(challenge) {
  const facets = challenge.lease_request_facets || {};
  const expected = {
    deposit_usd: request.plan.deposit_usd,
    ceiling_amount: request.plan.ceiling_amount,
    ceiling_denom: request.plan.ceiling_denom,
    provider_selector: request.plan.provider_selector,
    teardown_policy: request.plan.teardown_policy,
    execution_mode: "live",
    sdl_hash: expectedSdlHash,
    registry_credential_ref: request.plan.registry_credential_ref ?? null,
    result_credential_ref: request.plan.result_credential_ref ?? null,
  };
  for (const [key, value] of Object.entries(expected)) {
    if (JSON.stringify(facets[key] ?? null) !== JSON.stringify(value)) {
      throw new Error(`facet checkpoint refused ${key}`);
    }
  }
  return { facets, expected };
}

let fixture;
let session = "";
let dseq = "";
let terminal = false;
try {
  fixture = await startRealWalletNetworkPrincipalAuthorityFixture({
    baseEnv: { ...process.env, IOI_WALLET_SECRET_PASS: walletPass },
  });
  const portOwner = spawnSync("bash", ["-lc", "ss -tlnp 2>/dev/null | awk '/:8765 / {match($0,/pid=[0-9]+/); if (RSTART) print substr($0,RSTART+4,RLENGTH-4)}'"], { encoding: "utf8" }).stdout.trim();
  if (portOwner && /^\d+$/u.test(portOwner)) process.kill(Number(portOwner), "SIGTERM");
  await sleep(2_000);
  const daemonLog = openSync(path.join(artifactDir, "daemon.log"), "a", 0o600);
  const daemon = spawn(path.join(repo, "target/debug/hypervisor-daemon"), [], {
    detached: true,
    env: {
      ...process.env,
      ...fixture.env,
      IOI_WALLET_SECRET_PASS: walletPass,
      IOI_HYPERVISOR_DATA_DIR: config.data_dir,
      IOI_HYPERVISOR_DAEMON_ADDR: "127.0.0.1:8765",
      IOI_HYPERVISOR_AUTHORITY_PRINCIPAL_REF: config.authority_principal_ref,
    },
    stdio: ["ignore", daemonLog, daemonLog],
  });
  daemon.unref();
  await daemonReady();

  const login = await fetch(`${daemonUrl}/v1/hypervisor/auth/login`, {
    method: "POST",
    headers: headers(),
    body: JSON.stringify({ email: operatorEmail, password: operatorPassword }),
  });
  const loginBody = await login.json();
  session = loginBody.session_token || "";
  if (!session.startsWith("ioi_sess_")) throw new Error(`operator login refused: HTTP ${login.status}`);
  save("operator.json", { principal_ref: loginBody.principal_ref || null, email_hash: sha256(operatorEmail) });

  const dryResponse = await fetch(`${daemonUrl}/v1/hypervisor/provider-ops`, {
    method: "POST",
    headers: headers(session),
    body: JSON.stringify(request),
  });
  const challenge = await dryResponse.json();
  save("challenge.json", challenge);
  const policyHash = challenge.approval?.policy_hash;
  const requestHash = challenge.approval?.request_hash;
  if (!policyHash || !requestHash || challenge.host_mutation !== false) throw new Error("dry challenge was not a spend-free authority refusal");
  const { facets } = verifyFacets(challenge);
  const reviewBundle = {
    policy_hash: policyHash,
    request_hash: requestHash,
    environment_ref: config.environment_ref,
    provider_id: request.provider_id,
    operation: request.op,
    owner_ref: request.owner_ref,
    idempotency_key: request.idempotency_key,
    reviewed_facets: facets,
  };
  const approvalRequest = {
    schema_version: "ioi.hypervisor.certified-provider-approval.v1",
    approved: false,
    ...reviewBundle,
    review_bundle_sha256: sha256(JSON.stringify(reviewBundle)),
  };
  save("approval-request.json", approvalRequest);
  if (prepareOnly) {
    log("prepare-only complete; no grant minted and no provider mutation attempted");
  } else {
    const approval = JSON.parse(readFileSync(approvalPath, "utf8"));
    for (const key of [
      "policy_hash",
      "request_hash",
      "environment_ref",
      "provider_id",
      "operation",
      "owner_ref",
      "idempotency_key",
      "review_bundle_sha256",
    ]) {
      if (approval[key] !== approvalRequest[key]) throw new Error(`approval does not bind exact ${key}`);
    }
    if (JSON.stringify(approval.reviewed_facets) !== JSON.stringify(approvalRequest.reviewed_facets)) {
      throw new Error("approval does not bind exact reviewed_facets");
    }
    if (approval.schema_version !== approvalRequest.schema_version || approval.approved !== true) {
      throw new Error("approval file does not carry approved=true under the expected schema");
    }
    const grant = await fixture.mintRecorded(
      config.authority_principal_ref,
      policyHash,
      requestHash,
      "scope:hypervisor.live-route.hypervisor-provider-op",
    );
    save("grant.json", grant);
    const admitted = { ...request, wallet_approval_grant: grant };
    const proposalResponse = await fetch(`${daemonUrl}/v1/hypervisor/provider-operation-proposals`, {
      method: "POST",
      headers: headers(session),
      body: JSON.stringify(admitted),
    });
    const proposal = await proposalResponse.json();
    save("proposal.json", proposal);
    if (!proposalResponse.ok || proposal.ok !== true) throw new Error("daemon proposal issuance refused");
    const castResponse = await fetch(`${daemonUrl}/v1/hypervisor/provider-ops`, {
      method: "POST",
      headers: headers(session),
      body: JSON.stringify({ ...admitted, operation_proposal_ref: proposal.proposal_ref }),
    });
    const cast = await castResponse.json();
    save("cast.json", cast);
    dseq = String(
      cast.evidence?.dseq
      || cast.evidence?.provider_native?.dseq
      || String(cast.reason || "").match(/dseq=(\d+)/u)?.[1]
      || "",
    );
    if (!castResponse.ok || cast.ok !== true || !dseq) throw new Error(`cast refused: ${cast.reason || cast.code || castResponse.status}`);

    const started = await postProvider(session, "start");
    if (started.value.ok !== true || started.value.evidence?.endpoint_discovered !== true) throw new Error("provider endpoint was not discovered");
    let proof;
    for (let attempt = 1; attempt <= Number(config.result_poll_attempts || 1); attempt += 1) {
      proof = await postProvider(session, "logs", `logs.${attempt}`);
      if (proof.value.ok === true && (!request.plan.result_credential_ref || proof.value.evidence?.workload_result?.retrieved_live === true)) break;
      await sleep(Number(config.result_poll_interval_ms || 15_000));
    }
    if (proof?.value.ok !== true || proof.value.evidence?.lease_state_proof?.retrieved_live !== true) throw new Error("provider-native proof was not retrieved");
    if (request.plan.result_credential_ref && proof.value.evidence?.workload_result?.retrieved_live !== true) throw new Error("authenticated workload result was not retrieved");

    let closed = await postProvider(session, "delete");
    for (let attempt = 1; attempt <= 20 && closed.value.evidence?.settlement?.provider_terminal !== true; attempt += 1) {
      await sleep(6_000);
      closed = await postProvider(session, "reconcile", `reconcile.${attempt}`);
    }
    terminal = closed.value.evidence?.settlement?.provider_terminal === true;
    if (!terminal) throw new Error("provider settlement did not reach terminal readback");
    await capture(session);
    log(`campaign complete, dseq=${dseq}, provider settlement terminal`);
  }
} catch (error) {
  log(`ERROR: ${error.message}`);
  save("error.json", { message: error.message, stack: error.stack });
  process.exitCode = 1;
  if (session && dseq && !terminal) {
    try {
      let closed = await postProvider(session, "delete", "compensation-delete");
      for (let attempt = 1; attempt <= 20 && closed.value.evidence?.settlement?.provider_terminal !== true; attempt += 1) {
        await sleep(6_000);
        closed = await postProvider(session, "reconcile", `compensation-reconcile.${attempt}`);
      }
      terminal = closed.value.evidence?.settlement?.provider_terminal === true;
    } catch (cleanupError) {
      log(`COMPENSATION ERROR: ${cleanupError.message}`);
    }
  }
  if (session) await capture(session).catch(() => {});
} finally {
  if (fixture) await fixture.stop().catch(() => {});
}
