#!/usr/bin/env node
// Model-route registry done-bar verifier.
//
// Drives the model-route registry plane against the running daemon (:8765) and asserts:
// seed honesty (env-default route, real probe), fail-closed create (unresolved substrate refs,
// plaintext-secret rejection), receipt + admission linkage on every mutation, honest availability
// postures (available / model_not_present / unreachable / credentials_missing /
// credentials_present — never fabricated; openai_compatible is POSTURE-ONLY: the daemon never
// resolves an environment secret and sends it to a caller-supplied base_url),
// planner-composed enable/disable/select-default with the exactly-one-default invariant,
// fail-closed session binding (412 non-available, 409 non-ollama transport), transcript proof
// (model-route ops appear in the agent-run-transcript plane with a state_root), and no shadowing
// of the pre-existing /v1/model-mount/* family.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-model-route-registry.mjs
// Exit 0 = all assertions pass; exit 1 = one or more failed. Mutable test routes are cleaned up;
// immutable proof records (receipts, transcripts) are intentionally retained.

import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import net from "node:net";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..", "..", "..");

// This verifier BOOTS ITS OWN DAEMON. It used to drive whatever happened to be listening on :8765
// with no credential at all, which stopped being runnable the moment the registry's mutations
// became owner-scoped: there is no way to authenticate against a daemon whose bootstrap token was
// printed to a log this process never saw. An isolated daemon is also the only way the seed
// assertions below mean anything, since they describe a registry no earlier run has mutated.
const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };

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

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-model-route-registry-"));
let daemon = null;
let DAEMON = "";
let SESSION = "";
let OWNER = "";
let idemSeq = 0;

async function jd(method, path, body) {
  // The shared write path reads owner_ref and idempotency_key from the BODY. They are injected on
  // every request that carries one: harmless where the handler ignores them, required by create.
  const payload = body ? { owner_ref: OWNER, idempotency_key: `mrr-${idemSeq += 1}`, ...body } : undefined;
  const r = await fetch(`${DAEMON}${path}`, {
    method,
    headers: {
      "content-type": "application/json",
      ...(SESSION ? { cookie: `ioi_session=${SESSION}` } : {}),
    },
    body: payload ? JSON.stringify(payload) : undefined,
  });
  const t = await r.text();
  let j = null; try { j = JSON.parse(t); } catch { /* non-json */ }
  return { status: r.status, j, t };
}

const cleanup = [];

function shutdown() {
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
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let log = "";
  daemon.stdout.on("data", (c) => { log = `${log}${c}`.slice(-64000); });
  daemon.stderr.on("data", (c) => { log = `${log}${c}`.slice(-64000); });
  await waitFor(`${DAEMON}/healthz`, 30000);

  const bootToken = log.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
  const boot = await jd("POST", "/v1/hypervisor/auth/bootstrap", { token: bootToken, password: "model-route-registry-v1" });
  SESSION = boot.j?.session_token ?? "";
  const who = (await jd("GET", "/v1/hypervisor/auth/whoami")).j || {};
  OWNER = (who.principal?.tenant_refs || []).find((t) => typeof t === "string" && t.startsWith("org://")) || "";
  ok("the verifier holds an authenticated admin session to drive the owner-scoped registry",
    who.authenticated === true && who.principal?.role === "admin" && !!OWNER, `owner ${OWNER}`);

  // 1. Seed honesty: the env-default route exists, is seeded, is the default, and its overview
  //    env_execution posture reflects a REAL probe of the configured upstream.
  const overview = await jd("GET", "/v1/hypervisor/model-routes/overview");
  ok("overview schema", overview.j?.schema_version === "ioi.hypervisor.model-routes-overview.v1");
  ok("overview names env execution posture (source: env)", overview.j?.env_execution?.source === "env" && typeof overview.j?.env_execution?.model === "string", overview.j?.env_execution?.model);
  ok("overview env availability is probe-backed", ["available", "unreachable", "model_not_present"].includes(overview.j?.env_execution?.availability?.state), overview.j?.env_execution?.availability?.state);
  ok("overview names governance gaps plainly", Array.isArray(overview.j?.governance_gaps) && overview.j.governance_gaps.length > 0);

  const list = await jd("GET", "/v1/hypervisor/model-routes");
  const seed = (list.j?.routes || []).find((r) => r.route_id === "mrt_local_default");
  ok("seeded mrt_local_default exists (origin seeded)", seed && seed.origin === "seeded");
  ok("exactly one default route", (list.j?.routes || []).filter((r) => r.default_route === true).length === 1, list.j?.default_route_ref);
  ok("seed carries planner admission linkage", typeof seed?.admission?.last_admission_id === "string" && seed.admission.last_admission_id.startsWith("model-route-mutation-admission:"), seed?.admission?.last_admission_id);
  ok("seed custody admission recorded", typeof seed?.custody?.custody_admission_ref === "string" && seed.custody.custody_admission_ref.startsWith("model-weight-custody-admission:"));

  // 2. Probe the seed: availability must reflect the REAL local upstream (whatever it is — the
  //    assertion is posture honesty, not a specific state).
  const probe = await jd("POST", "/v1/hypervisor/model-routes/mrt_local_default/probe");
  const pState = probe.j?.availability?.state;
  ok("seed probe returns an honest posture", ["available", "unreachable", "model_not_present"].includes(pState), pState);
  ok("probe evidence present (never a bare claim)", probe.j?.availability?.probe?.kind === "ollama_tags" && probe.j?.availability?.probe?.evidence, JSON.stringify(probe.j?.availability?.probe?.evidence || {}));
  ok("probe emits receipt", typeof probe.j?.receipt_ref === "string" && probe.j.receipt_ref.startsWith("agentgres://model-route-receipt/"));
  ok("probe records transcript proof", probe.j?.transcript_recorded === true, probe.j?.transcript_run_id);

  // 3. Create FAIL-CLOSED: unresolved substrate ref persists nothing.
  const badRef = await jd("POST", "/v1/hypervisor/model-routes", { model_id: "x", transport: "ollama", base_url: "http://127.0.0.1:11434", provider_ref: "provider:verify-does-not-exist" });
  ok("create with unresolved provider_ref fails closed", badRef.status === 422 && badRef.j?.error?.code === "model_route_ref_unresolved", badRef.j?.error?.code);
  const badSecret = await jd("POST", "/v1/hypervisor/model-routes", { model_id: "x", transport: "openai_compatible", base_url: "https://example.invalid/v1", api_key: "sk-plaintext" });
  ok("create with plaintext credential rejected", badSecret.status === 400 && badSecret.j?.error?.code === "model_route_plaintext_secret_rejected", badSecret.j?.error?.code);

  // 4. Create + receipt + custody admission on the record.
  const created = await jd("POST", "/v1/hypervisor/model-routes", { model_id: "verify-model:none", transport: "ollama", base_url: "http://127.0.0.1:11434", display_name: "Verifier route" });
  const route = created.j?.route;
  const rid = route?.route_id;
  ok("valid create persists declared route", created.status === 201 && route?.schema_version === "ioi.hypervisor.model-route.v1" && route?.lifecycle?.status === "declared", rid);
  ok("created route carries receipt + custody admission", (route?.receipt_refs || []).length > 0 && String(route?.custody?.custody_admission_ref || "").startsWith("model-weight-custody-admission:"));
  cleanup.push(rid);

  // 5. Availability never fabricated: live catalog without the tag => model_not_present;
  //    dead upstream => unreachable; missing credential => credentials_missing WITHOUT a network call.
  const p2 = await jd("POST", `/v1/hypervisor/model-routes/${rid}/probe`);
  ok("unpulled tag probes to model_not_present (live upstream) or unreachable (no upstream)", ["model_not_present", "unreachable"].includes(p2.j?.availability?.state), p2.j?.availability?.state);

  const dead = await jd("POST", "/v1/hypervisor/model-routes", { model_id: "x:y", transport: "ollama", base_url: "http://127.0.0.1:19999" });
  const deadId = dead.j?.route?.route_id;
  cleanup.push(deadId);
  const p3 = await jd("POST", `/v1/hypervisor/model-routes/${deadId}/probe`);
  ok("dead upstream probes to unreachable", p3.j?.availability?.state === "unreachable", p3.j?.availability?.state);

  const cred = await jd("POST", "/v1/hypervisor/model-routes", { model_id: "any", transport: "openai_compatible", base_url: "https://example.invalid/v1", env_key_name: "IOI_VERIFY_ABSENT_KEY", credential_posture: "provider_vault_token" });
  const credId = cred.j?.route?.route_id;
  cleanup.push(credId);
  const p4 = await jd("POST", `/v1/hypervisor/model-routes/${credId}/probe`);
  ok("missing credential probes to credentials_missing without a network call", p4.j?.availability?.state === "credentials_missing" && /no network call/.test(JSON.stringify(p4.j?.availability?.probe?.evidence || {})), p4.j?.availability?.state);

  // 5b. openai_compatible is POSTURE-ONLY: a resolvable env key reports credentials_present —
  //     never `available`, and never an authenticated request to the caller-supplied base_url
  //     (that would be a secret-exfiltration primitive).
  const credOk = await jd("POST", "/v1/hypervisor/model-routes", { model_id: "any", transport: "openai_compatible", base_url: "https://example.invalid/v1", env_key_name: "PATH", credential_posture: "provider_vault_token" });
  const credOkId = credOk.j?.route?.route_id;
  cleanup.push(credOkId);
  const p5 = await jd("POST", `/v1/hypervisor/model-routes/${credOkId}/probe`);
  ok("resolvable credential reports credentials_present, never available (posture-only)", p5.j?.availability?.state === "credentials_present" && p5.j?.availability?.probe?.kind === "openai_compatible_posture", p5.j?.availability?.state);
  ok("posture-only probe names the deferral honestly (no secret sent to caller URL)", /never sends a secret/.test(JSON.stringify(p5.j?.availability?.probe?.evidence || {})), JSON.stringify(p5.j?.availability?.probe?.evidence || {}).slice(0, 120));

  // 6. Admission composition: enable round-trips the real planner; a credentialed posture without
  //    a lease is REJECTED by the planner and the record stays unchanged on disk.
  const en = await jd("POST", `/v1/hypervisor/model-routes/${rid}/enable`);
  ok("enable is planner-admitted", en.status === 200 && String(en.j?.admission_id || "").startsWith("model-route-mutation-admission:") && en.j?.route?.lifecycle?.status === "active", en.j?.admission_id);
  const credEn = await jd("POST", `/v1/hypervisor/model-routes/${credId}/enable`);
  ok("credentialed enable without lease rejected by planner (403)", credEn.status === 403 && String(credEn.j?.error?.code || "").startsWith("model_route_mutation_"), credEn.j?.error?.code);
  const credAfter = await jd("GET", `/v1/hypervisor/model-routes/${credId}`);
  ok("rejected mutation left record unchanged", credAfter.j?.route?.lifecycle?.status === "declared");

  // 7. Default invariant: select-default on the verifier route atomically clears the seed; restore.
  const sel = await jd("POST", `/v1/hypervisor/model-routes/${rid}/select-default`);
  ok("select-default admitted", sel.status === 200 && sel.j?.route?.default_route === true);
  const afterSel = await jd("GET", "/v1/hypervisor/model-routes");
  ok("exactly one default after select", (afterSel.j?.routes || []).filter((r) => r.default_route === true).length === 1 && afterSel.j?.default_route_ref === `model-route:${rid}`);
  await jd("POST", "/v1/hypervisor/model-routes/mrt_local_default/select-default");
  const restored = await jd("GET", "/v1/hypervisor/model-routes");
  ok("default restored to seed", restored.j?.default_route_ref === "model-route:mrt_local_default");

  // 8. Session binding FAIL-CLOSED: non-available route => 412; non-ollama transport => 409.
  const bindBad = await jd("POST", `/v1/hypervisor/model-routes/${rid}/session-bindings`, { session_ref: "sess_verify_mrr" });
  ok("binding a non-available route fails closed (412)", bindBad.status === 412 && bindBad.j?.error?.code === "model_route_not_available", bindBad.j?.error?.code);
  const bindOai = await jd("POST", `/v1/hypervisor/model-routes/${credId}/session-bindings`, { session_ref: "sess_verify_mrr" });
  ok("binding a non-ollama transport fails closed (409)", bindOai.status === 409 && bindOai.j?.error?.code === "transport_unsupported_for_execution", bindOai.j?.error?.code);

  // 8b. When the seed route is live-available, a binding mints with admission + receipt and the
  //     binding projection exposes it. (Skipped honestly when no local model is up.)
  const seedProbe = await jd("POST", "/v1/hypervisor/model-routes/mrt_local_default/probe");
  if (seedProbe.j?.availability?.state === "available" && seed?.lifecycle?.status === "active") {
    const bind = await jd("POST", "/v1/hypervisor/model-routes/mrt_local_default/session-bindings", { session_ref: "sess_verify_mrr" });
    ok("available+active route binds session (201, admitted, receipted)", bind.status === 201 && String(bind.j?.binding?.admission_id || "").startsWith("model-route-mutation-admission:") && String(bind.j?.binding?.receipt_ref || "").startsWith("agentgres://model-route-receipt/"), bind.j?.binding?.binding_id);
    ok("binding carries availability evidence at bind time", bind.j?.binding?.availability_at_bind?.state === "available");
    const bl = await jd("GET", "/v1/hypervisor/model-route-session-bindings?session_ref=sess_verify_mrr");
    ok("binding projection filters by session_ref", (bl.j?.bindings || []).some((b) => b.binding_id === bind.j?.binding?.binding_id));
  } else {
    ok("available-route binding lane skipped honestly (no live local model)", true, seedProbe.j?.availability?.state);
    ok("binding evidence assertion skipped with the lane", true);
    ok("binding projection assertion skipped with the lane", true);
  }

  // 9. Transcript proof: model-route ops surface in the agent-run-transcript plane with state_roots.
  const transcripts = await jd("GET", "/v1/hypervisor/agent-run-transcripts");
  const tList = Array.isArray(transcripts.j) ? transcripts.j : Object.values(transcripts.j || {}).find(Array.isArray) || [];
  const mro = tList.filter((t) => t?.kind === "model-route-op");
  ok("model-route ops appear in the transcript plane", mro.length > 0, `count=${mro.length}`);
  ok("model-route transcripts carry a state_root", mro.some((t) => JSON.stringify(t).includes("state_root")));

  // 10. Delete fail-closed lanes + cleanup.
  const delSeed = await jd("DELETE", "/v1/hypervisor/model-routes/mrt_local_default");
  ok("seed route is undeletable (409)", delSeed.status === 409 && delSeed.j?.error?.code === "model_route_seed_undeletable");
  for (const id of cleanup) {
    if (id) await jd("DELETE", `/v1/hypervisor/model-routes/${id}`);
  }
  const finalList = await jd("GET", "/v1/hypervisor/model-routes");
  ok("verifier routes cleaned up", !(finalList.j?.routes || []).some((r) => cleanup.includes(r.route_id)));

  // 11. No shadowing: the pre-existing model-mount family still answers.
  const mount = await jd("GET", "/v1/model-mount/routes");
  ok("/v1/model-mount/routes unshadowed", mount.status === 200);
}

run()
  .catch((e) => ok("verifier ran to completion", false, String(e)))
  .finally(() => {
    shutdown();
    let failed = 0;
    for (const r of results) {
      if (!r.pass) failed += 1;
      console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`);
    }
    console.log(`\n${results.length - failed}/${results.length} passed`);
    console.log(failed === 0 ? "model-route registry readiness: OK" : "model-route registry readiness: FAILED");
    process.exit(failed === 0 ? 0 : 1);
  });
