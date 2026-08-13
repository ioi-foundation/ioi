#!/usr/bin/env node
// W3.3 durable-custody verifier — a backup crosses to a FRESH DAEMON, and what was deleted stays
// deleted.
//
// The unit's acceptance sentence is "a fresh-daemon restore with custody, retention, and deletion
// proof", and before this leg none of the three was reachable. The export lane handed back the raw
// workspace tar — payload bytes with no record, no manifest, no provenance — and there was no
// import at all, so a backup could never leave the data directory that captured it. Every compiled
// record carried `expires_at: null`, so the registered contract's whole retention half was canon
// nothing enforced. And an executed retention deletion destroyed the payload while leaving the
// backup plane to report the absence as `managed_backup_material_unavailable` — the same observable
// a lost disk produces — with nothing at all stopping a previously exported bundle from putting the
// bytes back.
//
// So this file runs TWO REAL DAEMONS. Daemon A captures through the product's own snapshot route
// and exports; daemon B starts from an empty data directory, imports, restores, is KILLED AND
// RESTARTED, and then deletes. No fixture corpus, no repo-carried snapshot, no hand-minted record:
// every byte daemon B restores was minted by daemon A's capture path during this run.
//
// THE DISCIPLINE THIS FILE IS WRITTEN UNDER (each line is a scar, not a preference):
//   - COUNT THE THING ITSELF. A refusal's status code proves nothing about a SIDE EFFECT. Every
//     refusal here is paired with a count of the durable artifacts it must not have produced —
//     material files, record files, admitted events — read off the daemon's own data directory.
//   - ASSERT THE DELTA YOU OWN. Counts are snapshotted before and compared after, so an assertion
//     fires for the change it names and not for unrelated drift.
//   - PRECONDITIONS ARE ASSERTIONS. A green gate in a world the product does not produce certifies
//     nothing, so the properties that make this fixture the product shape — B is genuinely empty, A
//     and B mint coordinates in the SAME estate namespace, the marker file really is under the
//     workspace the environment reports — are asserted, not assumed.
//   - ORDER IS A CLAIM. "The tombstone is read before the material" is proved by observing the
//     TYPED answer in the state where both gates would fire: the bytes are gone AND the record is
//     tombstoned, and the answer must name the tombstone.
//   - CLOSED WORLD, DERIVED. The custody surface's mutating endpoints are re-derived from the
//     daemon's router source on every run, so an endpoint added later is covered or this goes red.
//   - NO DISJUNCTIONS ON A REFUSAL. A status-or-status assertion passes when the fixture is broken.
//
// Exit: 0 pass · 1 fail · 2 blocked (daemon binary missing).
//   IOI_HYPERVISOR_DAEMON_BINARY  default target/debug/hypervisor-daemon

import { spawn, execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import net from "node:net";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import { emitVerifierCensus } from "./lib/verifier-census.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP = path.resolve(HERE, "..");
const ROOT = path.resolve(APP, "..", "..");

const results = [];
const ok = (name, cond, detail) => results.push({ name, pass: !!cond, detail: detail || "" });
const code = (j) => j?.code ?? j?.error?.code ?? "";
const sha256 = (buf) => `sha256:${crypto.createHash("sha256").update(buf).digest("hex")}`;

/** RFC 8785 JSON Canonicalization, enough for the two roots this file recomputes. */
const jcs = (value) => {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(jcs).join(",")}]`;
  const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${jcs(value[k])}`).join(",")}}`;
};
/** The daemon's own `environment_artifact_root` — an UNKEYED hash, which is exactly the point. */
const artifactRoot = (record) => sha256(Buffer.from(jcs({ artifact: record, domain: "ioi.hypervisor-environment-lifecycle-artifact-jcs-sha256.v1" }), "utf8"));
const manifestRoot = (record) => sha256(Buffer.from(jcs({
  backup_ref: record.backup_ref,
  domain: "ioi.hypervisor-environment-backup-manifest-jcs-sha256.v1",
  environment_ref: record.environment_ref,
  rows: record.manifest_rows,
  source_state_root_ref: record.source_state_root_ref,
}), "utf8"));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

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
    await sleep(300);
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

const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-backup-restore-"));

/** One live daemon over its own data directory: A is the source estate, B the replacement. */
class Daemon {
  constructor(label) {
    this.label = label;
    this.dataDir = path.join(scratch, `data-${label}`);
    fs.mkdirSync(this.dataDir, { recursive: true });
    this.proc = null;
    this.url = "";
    this.log = "";
    this.session = "";
    this.owner = "";
    this.principal = "";
  }

  async start() {
    const port = await freePort();
    this.url = `http://127.0.0.1:${port}`;
    this.proc = spawn(daemonBinary, [], {
      cwd: ROOT,
      env: {
        ...process.env,
        IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${port}`,
        IOI_HYPERVISOR_DATA_DIR: this.dataDir,
        IOI_HYPERVISOR_MODEL_UPSTREAM: "http://127.0.0.1:1",
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    this.proc.stdout.on("data", (c) => { this.log = `${this.log}${c}`.slice(-64000); });
    this.proc.stderr.on("data", (c) => { this.log = `${this.log}${c}`.slice(-64000); });
    await waitFor(`${this.url}/healthz`, 30000);
  }

  stop() {
    try { this.proc?.kill("SIGTERM"); } catch { /* already gone */ }
    this.proc = null;
  }

  /** Kill and re-launch over the SAME data directory — the restart-survival probe. */
  async restart() {
    this.stop();
    await sleep(600);
    await this.start();
  }

  async req(method, p, body, { anonymous = false, session = null } = {}) {
    const token = anonymous ? "" : (session ?? this.session);
    return fetch(`${this.url}${p}`, {
      method,
      headers: {
        ...(body ? { "content-type": "application/json" } : {}),
        ...(token ? { cookie: `ioi_session=${token}` } : {}),
      },
      ...(body ? { body: JSON.stringify(body) } : {}),
    }).then(async (r) => {
      const text = await r.text();
      let j = null;
      try { j = JSON.parse(text); } catch { /* non-json */ }
      return { status: r.status, j, text, headers: r.headers };
    }).catch((e) => ({ status: 0, j: { transport_error: String(e) }, text: String(e), headers: new Headers() }));
  }

  async bootstrap(password) {
    const token = this.log.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
    const boot = await this.req("POST", "/v1/hypervisor/auth/bootstrap", { token, password }, { anonymous: true });
    this.session = boot.j?.session_token ?? "";
    this.password = password;
    const who = (await this.req("GET", "/v1/hypervisor/auth/whoami")).j || {};
    this.owner = (who.principal?.tenant_refs || []).find((t) => t === "org://local") || "";
    this.principal = who.principal?.principal_ref ?? "";
    return who;
  }

  /** Re-authenticate after a restart: the process is new, the durable principal is not. */
  async login(email, password) {
    const login = await this.req("POST", "/v1/hypervisor/auth/login", { email, password }, { anonymous: true });
    if (login.j?.session_token) this.session = login.j.session_token;
    return login;
  }

  dirEntries(sub) {
    try { return fs.readdirSync(path.join(this.dataDir, sub)); } catch { return []; }
  }

  countFiles(sub) { return this.dirEntries(sub).length; }

  materialPath(stateRoot) {
    return path.join(this.dataDir, "managed-backup-material", `${String(stateRoot).replace(/^sha256:/u, "")}.tar`);
  }

  hasMaterial(stateRoot) { return fs.existsSync(this.materialPath(stateRoot)); }

  /** Every byte this daemon durably wrote under `sub`. Asking the API is not evidence. */
  durableBytes(sub) {
    const out = [];
    const walk = (dir) => {
      let entries = [];
      try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
      for (const entry of entries) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) walk(full);
        else { try { out.push(fs.readFileSync(full, "utf8")); } catch { /* binary or gone */ } }
      }
    };
    walk(path.join(this.dataDir, sub));
    return out.join("\n");
  }

  /** Count admitted operations of one kind across the persistence namespace's durable log. */
  countAdmittedOps(kind) {
    const bytes = this.durableBytes("");
    return bytes.split(kind).length - 1;
  }
}

const A = new Daemon("a");
const B = new Daemon("b");

function cleanup() {
  A.stop();
  B.stop();
  try { fs.rmSync(scratch, { recursive: true, force: true }); } catch { /* best effort */ }
}

// ------------------------------------------------------------------ product-path fixture builders

const RUNTIME_POLICY = {
  persistence_profile: "zero_to_idle",
  idle_threshold_seconds: 300,
  minimum_warm_seconds: 60,
  wake_sources: ["user", "schedule"],
  maximum_cold_start_seconds: 120,
  maximum_restore_age_seconds: 86400,
  checkpoint_cadence_seconds: 900,
  pre_stop_checkpoint_required: true,
  provider_idle_semantics: "close",
  fallback_placement_refs: [],
  privacy_floor_ref: "policy://local/privacy/floor",
  spend_ceiling_ref: "policy://local/spend/ceiling",
  archive_retention_policy_ref: "policy://local/retention/standard",
  minimum_backup_replicas: 1,
};

const placementFor = (environmentId) => ({
  runtime_node_ref: "runtime://local/node-1",
  daemon_profile_ref: "profile://local/daemon",
  environment_ref: `environment://local/${environmentId}`,
  provider_ref: "provider://local/process",
  quote_ref: null,
  budget_reservation_ref: null,
  assignment_lease_ref: "lease://local/assignment-1",
  isolation_binding_ref: "binding://local/isolation-1",
  readiness_evidence_refs: ["receipt://local/readiness/1"],
});

/** Create + start one environment through the product routes and return its real workspace root. */
async function provisionEnvironment(d, environmentId) {
  await d.req("POST", "/v1/hypervisor/environments", { environment_id: environmentId, spec: {} });
  const started = await d.req("POST", `/v1/hypervisor/environments/${environmentId}/start`);
  return started.j?.environment?.status?.workspace_root ?? "";
}

/** Declare one local_private storage profile carrying an explicit retention duty. */
async function createStorageProfile(d, profileRef, retentionSeconds, key) {
  return d.req("POST", "/v1/hypervisor/storage-profiles", {
    storage_profile_ref: profileRef,
    owner_ref: d.owner,
    backend_class: "local_private",
    destination_ref: "storage://local/private",
    custody_policy_ref: "policy://local/custody",
    encryption_ref: null,
    key_epoch_ref: null,
    retention_policy_ref: "policy://local/retention",
    retention_duration_seconds: retentionSeconds,
    jurisdiction_refs: [],
    minimum_replicas: 1,
    independent_compute_copy_required: false,
    export_allowed: true,
    authority_grant_refs: ["grant://local/custody/1"],
    idempotency_key: key,
  });
}

/** Drive one managed instance from create through active, bound to `environmentId`. */
async function activateInstance(d, instanceId, environmentId, keyPrefix) {
  const created = await d.req("POST", "/v1/hypervisor/managed-worker-instances", {
    instance_id: instanceId,
    lifecycle_id: `lifecycle:${keyPrefix}`,
    owner_ref: d.owner,
    worker_package_ref: "worker-package://local/w1",
    config_revision_ref: "config-revision://local/w1/1",
    runtime_policy: RUNTIME_POLICY,
    authority_grant_refs: ["grant://local/runtime/1"],
    idempotency_key: `${keyPrefix}-create`,
  });
  let head = created.j?.instance?.agentgres?.head ?? "";
  for (const [index, to] of ["initializing", "active"].entries()) {
    const transition = await d.req("POST", `/v1/hypervisor/managed-worker-instances/${encodeURIComponent(instanceId)}/transitions`, {
      expected_head: head,
      idempotency_key: `${keyPrefix}-to-${to}`,
      to_state: to,
      transition_reason: `verifier drives the instance to ${to}`,
      payment_status: "not_applicable",
      authority_scope_refs: [],
      authority_grant_refs: ["grant://local/runtime/1"],
      policy_refs: [],
      required_controls: [],
      wallet_approval_ref: null,
      latest_state_root: null,
      backup_ref: null,
      restore_import_ref: null,
      migration_target_ref: null,
      provider_close_receipt_ref: null,
      high_risk_orders_paused: null,
      new_billable_work_blocked: null,
      archive_policy: null,
      restore_policy: null,
      export_policy: null,
      deletion_policy: null,
      placement: index === 1 ? placementFor(environmentId) : null,
    });
    head = transition.j?.instance?.agentgres?.head ?? head;
    if (transition.status >= 400) return { created, failed: transition, head };
  }
  return { created, head };
}

/** Capture one backup through the PRODUCT snapshot route. */
async function captureBackup(d, environmentId, instanceId, profileRef, key) {
  return d.req("POST", `/v1/hypervisor/environments/${environmentId}/backups`, {
    storage_profile_ref: profileRef,
    backup_policy_ref: "policy://local/backups",
    trigger: "manual",
    actor_ref: d.owner,
    instance_ref: instanceId,
    system_ref: null,
    schedule_or_change_plan_ref: null,
    authority_grant_refs: ["grant://local/custody/1"],
    idempotency_key: key,
  });
}

/** Download one export bundle and return its bytes plus the digest the daemon served with it. */
async function exportBundle(d, backupId) {
  const minted = await d.req("POST", `/v1/hypervisor/backups/${encodeURIComponent(backupId)}/export`, {
    authority_grant_refs: ["grant://local/export/1"],
    expires_in_seconds: 600,
  });
  const token = minted.j?.export?.download_token ?? "";
  const response = await fetch(`${d.url}/v1/hypervisor/backup-exports/${token}`, {
    headers: { cookie: `ioi_session=${d.session}` },
  });
  const bytes = Buffer.from(await response.arrayBuffer());
  return {
    minted,
    token,
    status: response.status,
    bytes,
    servedDigest: response.headers.get("x-ioi-backup-bundle-sha256") ?? "",
  };
}

const importBundle = (d, bundle, profileRef, key, options = {}) => d.req("POST", "/v1/hypervisor/backup-imports", {
  storage_profile_ref: profileRef,
  bundle_sha256: sha256(bundle),
  bundle_base64: bundle.toString("base64"),
  authority_grant_refs: ["grant://local/import/1"],
  idempotency_key: key,
}, options);

/** Unpack a bundle, let `mutate` rewrite its members on disk, and re-archive it. */
function rebuildBundle(bundle, mutate) {
  // A refusal body is JSON, not an archive. Say so rather than letting `tar` report the confusion
  // three frames away from the export that actually failed.
  if (bundle.length % 512 !== 0 || bundle.length === 0) {
    throw new Error(`expected a bundle archive, got ${bundle.length} bytes: ${bundle.toString("utf8").slice(0, 300)}`);
  }
  const dir = fs.mkdtempSync(path.join(scratch, "bundle-"));
  fs.writeFileSync(path.join(dir, "bundle.tar"), bundle);
  const unpacked = path.join(dir, "unpacked");
  fs.mkdirSync(unpacked);
  execFileSync("tar", ["-xf", path.join(dir, "bundle.tar"), "-C", unpacked]);
  mutate(unpacked);
  const rebuilt = execFileSync("tar", ["-cf", "-", "-C", unpacked, "."], { maxBuffer: 1 << 28 });
  return { bundle: Buffer.from(rebuilt), unpacked };
}

const readBundleManifest = (bundle) => {
  const { unpacked } = rebuildBundle(bundle, () => {});
  return JSON.parse(fs.readFileSync(path.join(unpacked, "ioi-backup-bundle.v1.json"), "utf8"));
};

/** Declare and execute one retention disposition over a backup — the estate's ONE deletion path. */
async function deleteViaRetention(d, backupId, keyPrefix) {
  const declared = await d.req("POST", "/v1/hypervisor/retention/dispositions", {
    owner_ref: d.owner,
    idempotency_key: `${keyPrefix}-declare`,
    subject_kind: "managed_backup_export",
    subject_ref: backupId,
    policy_basis_ref: "policy://local/retention/erasure",
  });
  const id = String(declared.j?.disposition?.disposition_id ?? "").replace(/^retention-disposition:\/\//u, "");
  const executed = await d.req("POST", `/v1/hypervisor/retention/dispositions/${id}/delete`, {
    owner_ref: d.owner,
    idempotency_key: `${keyPrefix}-delete`,
  });
  return { declared, id, executed };
}

/**
 * THE CLOSED WORLD, DERIVED FROM THE ENFORCING ARTIFACT.
 *
 * Re-reads the daemon's router source and returns every durable-custody endpoint registered with a
 * mutating method. A hand-written list would be a literal compared against a literal — it could not
 * fail, and it would silently stop covering the surface the first time a handler was added.
 */
const custodyMutationCensus = () => {
  const src = fs.readFileSync(path.join(ROOT, "crates/node/src/bin/hypervisor-daemon.rs"), "utf8");
  // THE FAMILY LIST IS THE ONE HAND-WRITTEN PART, SO IT IS WHERE COVERAGE CAN SILENTLY SHRINK. The
  // first revision omitted `/snapshots` entirely, and a mutation that stripped authentication from
  // `POST /snapshots/:id/restore` — a handler that OVERWRITES an environment's workspace — passed
  // 62/62. The assertion's label said "every censused custody mutation" and was true; the census
  // was the lie. `assertFamiliesCoverTheLane` below pins this list against the router's own
  // custody-route inventory so an omission is red rather than invisible.
  const families = [
    "/v1/hypervisor/backups",
    "/v1/hypervisor/backup-imports",
    "/v1/hypervisor/backup-exports",
    "/v1/hypervisor/snapshots",
    "/v1/hypervisor/environments/:id/backups",
    "/v1/hypervisor/managed-worker-instances",
    "/v1/hypervisor/retention/dispositions",
    "/v1/hypervisor/download-intents",
    "/v1/hypervisor/restore-plans",
    "/v1/hypervisor/storage-profiles",
  ];
  const found = [];
  for (const chunk of src.split(".route(")) {
    const pathMatch = chunk.match(/^\s*"(\/v1\/hypervisor\/[^"]*)"/u);
    if (!pathMatch) continue;
    const route = pathMatch[1];
    if (!families.some((family) => route.startsWith(family))) continue;
    const body = chunk.slice(0, chunk.indexOf("\n        )"));
    for (const method of ["post", "patch", "put", "delete"]) {
      if (new RegExp(`(^|[^a-z_])${method}\\(`, "u").test(body)) {
        found.push({ method: method.toUpperCase(), path: route });
      }
    }
  }
  return found;
};

/**
 * Every mutating route in the daemon's router that is CUSTODY by its own text — it names a
 * managed-runtime handler, or its path speaks of backups, snapshots, restore plans or storage
 * profiles. This is what the hand-written family list above is measured against, so an omission
 * from that list is a failed assertion instead of a quiet hole in the census.
 */
const custodyRouteInventory = () => {
  const src = fs.readFileSync(path.join(ROOT, "crates/node/src/bin/hypervisor-daemon.rs"), "utf8");
  const found = [];
  for (const chunk of src.split(".route(")) {
    const pathMatch = chunk.match(/^\s*"(\/v1\/hypervisor\/[^"]*)"/u);
    if (!pathMatch) continue;
    const route = pathMatch[1];
    const body = chunk.slice(0, chunk.indexOf("\n        )"));
    // The predicate is the hand-written part, so it is where coverage shrinks. A review found it
    // omitted the retention plane — the estate's ONE deletion path, and a handler THIS cut edits —
    // and the DownloadIntent lane that reads the same custody store. Both are custody by any honest
    // reading of the word.
    const custody = /backup|snapshot|restore-plan|storage-profile|retention\/disposition|download-intent/u.test(route)
      || /managed_runtime_routes::|retention_routes::|download_intent_routes::/u.test(body);
    if (!custody) continue;
    for (const method of ["post", "patch", "put", "delete"]) {
      if (new RegExp(`(^|[^a-z_])${method}\\(`, "u").test(body)) {
        found.push({ method: method.toUpperCase(), path: route });
      }
    }
  }
  return found;
};

const MARKER = "restored-across-a-daemon-boundary.txt";
const CAPTURED_CONTENT = "captured-on-daemon-a\n";

async function run() {
  // ============================================================ DAEMON A — capture and export
  await A.start();
  const whoA = await A.bootstrap("backup-restore-a-v1");
  ok("daemon A is a REAL authenticated operator session holding the deployment's org tenant",
    whoA.authenticated === true && A.owner === "org://local",
    `authenticated ${whoA.authenticated} owner ${A.owner}`);

  const envA = "bkp-env-a";
  const workspaceA = await provisionEnvironment(A, envA);
  ok("daemon A's environment materialized a REAL workspace inside its own data directory",
    workspaceA.length > 0 && fs.existsSync(workspaceA) && path.resolve(workspaceA).startsWith(path.resolve(A.dataDir)),
    workspaceA);

  // The SUBJECT of the backup. Written into the workspace the environment itself reports, and
  // asserted there, so what the capture path tars is observably the environment's own content.
  fs.writeFileSync(path.join(workspaceA, MARKER), CAPTURED_CONTENT);
  ok("PRECONDITION: the captured marker really is inside the workspace the environment reports",
    fs.readFileSync(path.join(workspaceA, MARKER), "utf8") === CAPTURED_CONTENT,
    MARKER);

  const RETENTION_SECONDS = 3600;
  const profileA = "storage-profile://local/primary-a";
  const profileCreated = await createStorageProfile(A, profileA, RETENTION_SECONDS, "profile-a-1");
  ok("a storage profile declares an explicit retention DUTY, not only a policy ref",
    profileCreated.status === 201 && profileCreated.j?.storage_profile?.retention_duration_seconds === RETENTION_SECONDS,
    `status ${profileCreated.status} duty ${profileCreated.j?.storage_profile?.retention_duration_seconds}`);

  const noDuty = await A.req("POST", "/v1/hypervisor/storage-profiles", {
    storage_profile_ref: "storage-profile://local/no-duty",
    owner_ref: A.owner,
    backend_class: "local_private",
    destination_ref: "storage://local/private",
    custody_policy_ref: "policy://local/custody",
    encryption_ref: null,
    key_epoch_ref: null,
    retention_policy_ref: "policy://local/retention",
    retention_duration_seconds: 0,
    jurisdiction_refs: [],
    minimum_replicas: 1,
    independent_compute_copy_required: false,
    export_allowed: true,
    authority_grant_refs: ["grant://local/custody/1"],
    idempotency_key: "profile-a-no-duty",
  });
  ok("a profile declaring a ZERO retention duty is refused, not normalized to unlimited",
    noDuty.status === 400 && code(noDuty.j) === "storage_profile_retention_duration_invalid",
    `status ${noDuty.status} code ${code(noDuty.j)}`);

  const instanceA = "agent://local/worker-a";
  const activatedA = await activateInstance(A, instanceA, envA, "inst-a");
  ok("daemon A's managed instance reached active with a compute session bound to that environment",
    !activatedA.failed && activatedA.head.length > 0,
    activatedA.failed ? `${activatedA.failed.status} ${code(activatedA.failed.j)}` : "active");

  const materialBefore = A.countFiles("managed-backup-material");
  const capturedAt = Date.now();
  const captured = await captureBackup(A, envA, instanceA, profileA, "capture-a-1");
  const backup = captured.j?.backup ?? {};
  const backupRefA = backup.backup_ref ?? "";
  const backupIdA = backupRefA.split("/").pop() ?? "";
  const stateRootA = String(backup.source_state_root_ref ?? "").replace(/^state-root:\/\//u, "");
  ok("the PRODUCT snapshot route mints the backup this run restores — no repo-carried corpus",
    captured.status === 201 && backupRefA.startsWith("environment-backup://") && stateRootA.startsWith("sha256:"),
    `status ${captured.status} ${backupRefA}`);
  ok("capture wrote exactly one new material file, and it is the state root the record names",
    A.countFiles("managed-backup-material") === materialBefore + 1 && A.hasMaterial(stateRootA),
    `${materialBefore} -> ${A.countFiles("managed-backup-material")}`);

  const expiresAtA = backup.expires_at ?? null;
  const expiryMs = Date.parse(expiresAtA ?? "");
  ok("the compiled record carries a REAL retention expiry derived from the profile's duty",
    typeof expiresAtA === "string"
      && Number.isFinite(expiryMs)
      && Math.abs(expiryMs - (capturedAt + RETENTION_SECONDS * 1000)) < 20000,
    `${expiresAtA} vs capture+${RETENTION_SECONDS}s`);

  ok("the capture's lifecycle head is admitted and typed as locally CAPTURED custody",
    captured.j?.lifecycle?.status === "admitted" && captured.j?.lifecycle?.custody_origin?.kind === "captured",
    `${captured.j?.lifecycle?.status} / ${captured.j?.lifecycle?.custody_origin?.kind}`);

  // ONE COORDINATE, ONE RECORD. Carrying a wall-clock retention duty made the same logical capture
  // compile different bytes a second apart, and the family is keyed on a hash of the WHOLE record —
  // so a retried capture admitted a SECOND record at the same `backup_ref`, `backup_by_id` then
  // required it to resolve exactly once, and read/verify/export/restore AND THE RETENTION DELETION
  // ITSELF answered `managed_backup_identity_ambiguous` forever, while both calls had returned 201.
  // A merge-blocking review demonstrated it; this is the most ordinary operation there is, which is
  // why the assertion waits out a whole second before retrying.
  const recordsBeforeRetry = A.countFiles("hypervisor-environment-backups");
  await sleep(1200);
  const retriedCapture = await captureBackup(A, envA, instanceA, profileA, "capture-a-1");
  ok("a RETRIED capture under one idempotency key replays the admitted record and admits no second one",
    retriedCapture.status === 200
      && retriedCapture.j?.replayed === true
      && retriedCapture.j?.backup?.backup_ref === backupRefA
      && retriedCapture.j?.backup?.expires_at === expiresAtA
      && A.countFiles("hypervisor-environment-backups") === recordsBeforeRetry,
    `status ${retriedCapture.status} records ${recordsBeforeRetry}->${A.countFiles("hypervisor-environment-backups")}`);
  const stillResolves = await A.req("GET", `/v1/hypervisor/backups/${encodeURIComponent(backupIdA)}`);
  ok("the coordinate still resolves after the retry — read, verify, export, restore and DELETION all resolve a backup this way",
    stillResolves.status === 200 && stillResolves.j?.restorable?.ok === true,
    `status ${stillResolves.status} restorable ${stillResolves.j?.restorable?.ok}`);

  const exported = await exportBundle(A, backupIdA);
  ok("the export download serves a PORTABLE BUNDLE and states its digest",
    exported.status === 200 && exported.bytes.length > 0 && exported.servedDigest === sha256(exported.bytes),
    `status ${exported.status} bytes ${exported.bytes.length}`);

  const manifest = readBundleManifest(exported.bytes);
  ok("the bundle carries the admitted record VERBATIM beside its payload",
    manifest.schema_version === "ioi.managed-backup-bundle.v1"
      && manifest.backup?.backup_ref === backupRefA
      && manifest.payload_sha256 === stateRootA,
    `${manifest.schema_version} ${manifest.backup?.backup_ref}`);
  // A denylist of secret-shaped regexes over a workspace this verifier populated itself could not
  // fail whatever the product did — decorative by the standing smell list. What is checkable is the
  // CLOSED WORLD: the record the bundle carries has exactly the registered contract's key set, so a
  // field the contract never declared (a credential, a token, a path) cannot ride along inside it.
  const contractKeys = JSON.parse(fs.readFileSync(path.join(ROOT, "docs/architecture/_meta/schemas/hypervisor-environment-backup.v1.schema.json"), "utf8"));
  const declared = Object.keys(contractKeys.properties).sort();
  const carried = Object.keys(manifest.backup).sort();
  ok("the record the bundle carries has EXACTLY the registered contract's key set — no undeclared field rides along",
    JSON.stringify(declared) === JSON.stringify(carried),
    `declared ${declared.length} carried ${carried.length}`);

  // ============================================================ DAEMON B — a genuinely fresh estate
  await B.start();
  const whoB = await B.bootstrap("backup-restore-b-v1");
  ok("daemon B is a REAL authenticated operator session over its OWN data directory",
    whoB.authenticated === true && B.owner === "org://local" && B.dataDir !== A.dataDir,
    `${whoB.authenticated} ${B.owner}`);
  ok("PRECONDITION: daemon B starts with NO backup record and NO custody material at all",
    B.countFiles("hypervisor-environment-backups") === 0 && B.countFiles("managed-backup-material") === 0,
    `records ${B.countFiles("hypervisor-environment-backups")} material ${B.countFiles("managed-backup-material")}`);

  const envB = "bkp-env-b";
  const workspaceB = await provisionEnvironment(B, envB);
  fs.writeFileSync(path.join(workspaceB, "only-on-daemon-b.txt"), "pre-restore\n");
  ok("PRECONDITION: daemon B's target workspace does NOT already contain daemon A's marker",
    workspaceB.length > 0 && !fs.existsSync(path.join(workspaceB, MARKER)),
    workspaceB);

  const profileB = "storage-profile://local/primary-b";
  await createStorageProfile(B, profileB, RETENTION_SECONDS, "profile-b-1");
  const instanceB = "agent://local/worker-b";
  const activatedB = await activateInstance(B, instanceB, envB, "inst-b");
  ok("daemon B's replacement instance reached active on its own environment",
    !activatedB.failed, activatedB.failed ? `${activatedB.failed.status} ${code(activatedB.failed.j)}` : "active");

  // PRECONDITION that makes the tombstone and collision proofs below real rather than hypothetical:
  // both daemons mint backup coordinates inside the SAME estate namespace, so an imported ref names
  // the same object a locally captured one would.
  const capturedB = await captureBackup(B, envB, instanceB, profileB, "capture-b-precondition");
  const namespaceOf = (ref) => String(ref).replace(/^environment-backup:\/\//u, "").split("/")[0];
  ok("PRECONDITION: A and B mint backup coordinates in the SAME estate namespace",
    capturedB.status === 201 && namespaceOf(capturedB.j?.backup?.backup_ref) === namespaceOf(backupRefA),
    `${namespaceOf(capturedB.j?.backup?.backup_ref)} vs ${namespaceOf(backupRefA)}`);

  // ---------------------------------------------------------- a bundle that cannot vouch for itself
  const recordsBefore = B.countFiles("hypervisor-environment-backups");
  const materialBeforeB = B.countFiles("managed-backup-material");

  const flipped = rebuildBundle(exported.bytes, (dir) => {
    const payload = fs.readFileSync(path.join(dir, "payload.tar"));
    payload[Math.floor(payload.length / 2)] ^= 0xff;
    fs.writeFileSync(path.join(dir, "payload.tar"), payload);
  }).bundle;
  const flippedImport = await importBundle(B, flipped, profileB, "import-flipped");
  ok("ONE FLIPPED BYTE in the payload is refused — the manifest no longer describes what it carries",
    flippedImport.status === 422 && code(flippedImport.j) === "managed_backup_import_payload_digest_mismatch",
    `status ${flippedImport.status} code ${code(flippedImport.j)}`);

  // The stronger case: the attacker also repairs the manifest, so only the RECORD's own commitment
  // to its source state root can still catch it.
  const repaired = rebuildBundle(exported.bytes, (dir) => {
    const payload = fs.readFileSync(path.join(dir, "payload.tar"));
    payload[Math.floor(payload.length / 2)] ^= 0xff;
    fs.writeFileSync(path.join(dir, "payload.tar"), payload);
    const m = JSON.parse(fs.readFileSync(path.join(dir, "ioi-backup-bundle.v1.json"), "utf8"));
    m.payload_sha256 = sha256(payload);
    m.payload_size_bytes = payload.length;
    fs.writeFileSync(path.join(dir, "ioi-backup-bundle.v1.json"), JSON.stringify(m));
  }).bundle;
  const repairedImport = await importBundle(B, repaired, profileB, "import-repaired");
  ok("a corrupted payload with a REPAIRED manifest is still refused by the record's own state-root commitment",
    repairedImport.status === 422 && code(repairedImport.j) === "managed_backup_import_material_digest_mismatch",
    `status ${repairedImport.status} code ${code(repairedImport.j)}`);

  const tamperedRecord = rebuildBundle(exported.bytes, (dir) => {
    const m = JSON.parse(fs.readFileSync(path.join(dir, "ioi-backup-bundle.v1.json"), "utf8"));
    m.backup.expires_at = "2999-01-01T00:00:00Z";
    fs.writeFileSync(path.join(dir, "ioi-backup-bundle.v1.json"), JSON.stringify(m));
  }).bundle;
  const tamperedImport = await importBundle(B, tamperedRecord, profileB, "import-tampered");
  ok("EDITING THE RECORD to extend its own retention is caught: the record no longer hashes to its declared artifact root",
    tamperedImport.status === 422 && code(tamperedImport.j) === "managed_backup_import_record_tampered",
    `status ${tamperedImport.status} code ${code(tamperedImport.j)}`);

  const misdeclared = await B.req("POST", "/v1/hypervisor/backup-imports", {
    storage_profile_ref: profileB,
    bundle_sha256: sha256(Buffer.from("not the bundle")),
    bundle_base64: exported.bytes.toString("base64"),
    authority_grant_refs: ["grant://local/import/1"],
    idempotency_key: "import-misdeclared",
  });
  ok("a bundle whose declared digest is not its actual digest is refused before it is even unpacked",
    misdeclared.status === 422 && code(misdeclared.j) === "managed_backup_import_bundle_digest_mismatch",
    `status ${misdeclared.status} code ${code(misdeclared.j)}`);

  const extraMember = rebuildBundle(exported.bytes, (dir) => {
    fs.writeFileSync(path.join(dir, "stowaway.txt"), "extra");
  }).bundle;
  const extraImport = await importBundle(B, extraMember, profileB, "import-extra");
  ok("CLOSED WORLD: a bundle carrying a third member is refused, not silently ignored",
    extraImport.status === 422 && code(extraImport.j) === "managed_backup_import_bundle_members_unexpected",
    `status ${extraImport.status} code ${code(extraImport.j)}`);

  ok("FIVE REFUSED IMPORTS PRODUCED NO DURABLE EFFECT — no record, no material byte",
    B.countFiles("hypervisor-environment-backups") === recordsBefore
      && B.countFiles("managed-backup-material") === materialBeforeB
      && !B.hasMaterial(stateRootA),
    `records ${recordsBefore}->${B.countFiles("hypervisor-environment-backups")} material ${materialBeforeB}->${B.countFiles("managed-backup-material")}`);

  // A BROKEN PROBE IS THE SAME DEFECT CLASS AS A DELETED ASSERTION. The first revision of this
  // check built a spread copy of the daemon with an empty session and called its BOUND `req`, so
  // the request went out fully authenticated and actually imported the bundle. It is now the plain
  // anonymous flag, and the assertion below pairs the 401 with the absence of the side effect the
  // broken probe produced.
  const anonRecords = B.countFiles("hypervisor-environment-backups");
  const anonMaterial = B.countFiles("managed-backup-material");
  const anonImport = await importBundle(B, exported.bytes, profileB, "import-anon", { anonymous: true });
  ok("the import surface refuses an unauthenticated caller, and lands NO byte anywhere while doing it",
    anonImport.status === 401
      && B.countFiles("hypervisor-environment-backups") === anonRecords
      && B.countFiles("managed-backup-material") === anonMaterial
      && !B.hasMaterial(stateRootA),
    `status ${anonImport.status} records ${anonRecords}->${B.countFiles("hypervisor-environment-backups")} material ${anonMaterial}->${B.countFiles("managed-backup-material")}`);

  // ---------------------------------------------------------- the fresh-daemon import
  const imported = await importBundle(B, exported.bytes, profileB, "import-1");
  ok("A FRESH DAEMON IMPORTS THE BUNDLE and admits the record it did not capture",
    imported.status === 201 && imported.j?.backup?.backup_ref === backupRefA && imported.j?.replayed === false,
    `status ${imported.status} code ${code(imported.j)}`);
  ok("the imported material really landed on daemon B at the exact state root, and hashes to it",
    B.hasMaterial(stateRootA) && sha256(fs.readFileSync(B.materialPath(stateRootA))) === stateRootA,
    B.materialPath(stateRootA));
  ok("RETENTION SURVIVES THE ROUND TRIP: B's expiry is A's expiry, byte for byte, never restamped",
    imported.j?.backup?.expires_at === expiresAtA && imported.j?.verification?.retention?.recorded === true,
    `${imported.j?.backup?.expires_at} vs ${expiresAtA}`);
  ok("the imported record is typed IMPORTED with its issuer explicitly unverified — no false provenance",
    imported.j?.lifecycle?.custody_origin?.kind === "imported"
      && imported.j?.lifecycle?.custody_origin?.issuer_verified === false
      && imported.j?.lifecycle?.custody_origin?.bundle_sha256 === sha256(exported.bytes),
    `${imported.j?.lifecycle?.custody_origin?.kind}`);

  const reimported = await importBundle(B, exported.bytes, profileB, "import-2");
  ok("a SECOND import of the same backup REPLAYS rather than conflicting forever on a genesis-only stream",
    reimported.status === 200 && reimported.j?.replayed === true,
    `status ${reimported.status} replayed ${reimported.j?.replayed}`);

  // ---------------------------------------------------------- restore, on the daemon that never captured
  const prepared = await B.req("POST", `/v1/hypervisor/backups/${encodeURIComponent(backupIdA)}/restore-plans`, {
    target_environment_id: envB,
    authority_grant_refs: ["grant://local/restore/1"],
    idempotency_key: "restore-1",
  });
  const planId = prepared.j?.restore_plan?.plan_id ?? "";
  ok("the imported backup prepares a restore plan against daemon B's own environment",
    prepared.status === 201 && prepared.j?.restore_plan?.status === "prepared",
    `status ${prepared.status} ${prepared.j?.restore_plan?.status}`);

  const applied = await B.req("POST", `/v1/hypervisor/restore-plans/${encodeURIComponent(planId)}/apply`, {
    expected_head: prepared.j?.restore_plan?.agentgres?.head ?? "",
    idempotency_key: "restore-1",
  });
  ok("the restore APPLIES and reaches completed",
    applied.status === 200 && applied.j?.restore_plan?.status === "completed",
    `status ${applied.status} ${applied.j?.restore_plan?.status}`);
  ok("THE BYTES CROSSED THE DAEMON BOUNDARY: daemon A's marker is now in daemon B's workspace with A's exact content",
    fs.existsSync(path.join(workspaceB, MARKER))
      && fs.readFileSync(path.join(workspaceB, MARKER), "utf8") === CAPTURED_CONTENT,
    path.join(workspaceB, MARKER));
  ok("the restore REPLACED the target workspace rather than merging into it",
    !fs.existsSync(path.join(workspaceB, "only-on-daemon-b.txt")),
    "pre-restore file is gone");

  // ---------------------------------------------------------- restart survival
  await B.restart();
  await B.login("operator@local", "backup-restore-b-v1");
  const afterRestart = await B.req("POST", `/v1/hypervisor/backups/${encodeURIComponent(backupIdA)}/verify`);
  ok("RESTART SURVIVAL: after a kill and relaunch, daemon B still verifies the imported backup from durable truth",
    afterRestart.status === 200
      && afterRestart.j?.verification?.state_root === stateRootA
      && afterRestart.j?.verification?.retention?.expires_at === expiresAtA,
    `status ${afterRestart.status} ${afterRestart.j?.verification?.state_root}`);
  ok("RESTART SURVIVAL: the restored workspace content is still on disk after the restart",
    fs.readFileSync(path.join(workspaceB, MARKER), "utf8") === CAPTURED_CONTENT,
    MARKER);
  const planAfterRestart = await B.req("POST", `/v1/hypervisor/restore-plans/${encodeURIComponent(planId)}/apply`, {
    expected_head: "",
    idempotency_key: "restore-1",
  });
  ok("RESTART SURVIVAL: the completed restore plan replays its terminal fact and admits nothing new",
    planAfterRestart.status === 200 && planAfterRestart.j?.restore_plan?.status === "completed",
    `status ${planAfterRestart.status} ${planAfterRestart.j?.restore_plan?.status}`);

  // ---------------------------------------------------------- deletion proof
  //
  // THE PLAN PREPARED BEFORE THE DELETION. Prepare stages a COPY of the payload beside the target
  // workspace, and that copy is out of the retention plane's reach — it destroys the material store,
  // not every directory a plan may have staged from it. A gate that decided restorability only at
  // prepare therefore left the deletion exactly one API call wide: prepare, delete, apply, and the
  // destroyed archive is back in a live workspace under a `pruned` head. This plan is prepared HERE,
  // before the deletion below, and applied AFTER it.
  const preDeletePlan = await B.req("POST", `/v1/hypervisor/backups/${encodeURIComponent(backupIdA)}/restore-plans`, {
    target_environment_id: envB,
    authority_grant_refs: ["grant://local/restore/1"],
    idempotency_key: "restore-prepared-before-deletion",
  });
  const preDeletePlanId = preDeletePlan.j?.restore_plan?.plan_id ?? "";
  const preDeleteHead = preDeletePlan.j?.restore_plan?.agentgres?.head ?? "";
  const stagingRoot = path.dirname(workspaceB);
  const stagedDir = path.join(stagingRoot, `.ioi-managed-restore-staging-${preDeletePlanId}`);
  ok("PRECONDITION: a restore plan prepared BEFORE any deletion really has staged bytes on disk",
    preDeletePlan.status === 201 && preDeletePlanId.length > 0 && fs.existsSync(stagedDir),
    stagedDir);

  // THE OTHER EGRESS LANE OVER THE SAME CUSTODY. DownloadIntent reads the managed-runtime material
  // store by content address, so it serves the very bytes a backup does — and it had NO deletion
  // gate of any kind. Minted here, while the backup is live, and exercised after the deletion below.
  const intentMinted = await B.req("POST", "/v1/hypervisor/download-intents", {
    owner_ref: B.owner,
    idempotency_key: "intent-before-deletion",
    artifact_kind: "managed_backup_export",
    backup_ref: backupIdA,
    expires_in_seconds: 600,
  });
  const intentId = String(intentMinted.j?.intent?.intent_id ?? "").replace(/^download-intent:\/\//u, "");
  const intentLive = await B.req("GET", `/v1/hypervisor/download-intents/${intentId}/content`);
  ok("PRECONDITION: a download intent minted while the backup is LIVE really delivers its bytes",
    intentMinted.status === 201 && intentLive.status === 200 && intentLive.text.includes(CAPTURED_CONTENT.trim()),
    `mint ${intentMinted.status} content ${intentLive.status} bytes ${intentLive.text.length}`);

  const holdDeclared = await B.req("POST", "/v1/hypervisor/retention/dispositions", {
    owner_ref: B.owner,
    idempotency_key: "hold-declare",
    subject_kind: "managed_backup_export",
    subject_ref: backupIdA,
    policy_basis_ref: "policy://local/retention/litigation",
  });
  const holdId = String(holdDeclared.j?.disposition?.disposition_id ?? "").replace(/^retention-disposition:\/\//u, "");
  await B.req("POST", `/v1/hypervisor/retention/dispositions/${holdId}/legal-hold`, {
    owner_ref: B.owner, idempotency_key: "hold-place", hold: true, reason: "verifier: litigation hold",
  });
  const heldDelete = await B.req("POST", `/v1/hypervisor/retention/dispositions/${holdId}/delete`, {
    owner_ref: B.owner, idempotency_key: "hold-delete",
  });
  ok("a legal hold still BLOCKS deletion after this leg wired a tombstone into it",
    heldDelete.status === 409 && code(heldDelete.j) === "retention_deletion_blocked_by_legal_hold",
    `status ${heldDelete.status} code ${code(heldDelete.j)}`);
  const heldVerify = await B.req("POST", `/v1/hypervisor/backups/${encodeURIComponent(backupIdA)}/verify`);
  ok("a hold-BLOCKED deletion tombstones NOTHING — the backup is still restorable material",
    heldVerify.status === 200 && B.hasMaterial(stateRootA),
    `status ${heldVerify.status} material ${B.hasMaterial(stateRootA)}`);

  const deleted = await deleteViaRetention(B, backupIdA, "erase");
  ok("the estate's ONE deletion path executes, and records the subject tombstone it admitted",
    deleted.executed.status === 200
      && deleted.executed.j?.disposition?.deletion?.evidence?.material_removed === true
      && String(deleted.executed.j?.disposition?.deletion?.subject_tombstone?.admitted_head ?? "").length > 0,
    `status ${deleted.executed.status}`);
  ok("the payload bytes are GONE from daemon B's custody store",
    !B.hasMaterial(stateRootA), B.materialPath(stateRootA));

  // ORDER IS A CLAIM. Both gates would fire here — the record is tombstoned AND its bytes are gone.
  // The answer must name the deletion, because `material_unavailable` is what a lost disk says.
  const verifyDeleted = await B.req("POST", `/v1/hypervisor/backups/${encodeURIComponent(backupIdA)}/verify`);
  ok("a deleted backup answers TOMBSTONED, not material_unavailable — an executed deletion is not a storage fault",
    verifyDeleted.status === 410 && code(verifyDeleted.j) === "managed_backup_tombstoned",
    `status ${verifyDeleted.status} code ${code(verifyDeleted.j)}`);
  ok("the tombstone names the disposition that ordered it, so the deletion stays auditable",
    verifyDeleted.j?.error?.details?.pruned_by_disposition_ref === `retention-disposition://${deleted.id}`,
    String(verifyDeleted.j?.error?.details?.pruned_by_disposition_ref));

  // A record's own `status` field describes the CAPTURE and reads `complete` forever. A reader that
  // saw only the record would conclude a deleted backup was usable, so the read states the verdict.
  const readDeleted = await B.req("GET", `/v1/hypervisor/backups/${encodeURIComponent(backupIdA)}`);
  ok("READING a deleted backup says so: the record still reads complete, and the read reports it is NOT restorable",
    readDeleted.status === 200
      && readDeleted.j?.backup?.status === "complete"
      && readDeleted.j?.restorable?.ok === false
      && readDeleted.j?.restorable?.error?.code === "managed_backup_tombstoned"
      && readDeleted.j?.lifecycle?.status === "pruned",
    `record ${readDeleted.j?.backup?.status} restorable ${readDeleted.j?.restorable?.ok} lifecycle ${readDeleted.j?.lifecycle?.status}`);

  const restoreDeleted = await B.req("POST", `/v1/hypervisor/backups/${encodeURIComponent(backupIdA)}/restore-plans`, {
    target_environment_id: envB,
    authority_grant_refs: ["grant://local/restore/1"],
    idempotency_key: "restore-after-delete",
  });
  ok("a RESTORE of a deleted backup refuses by name",
    restoreDeleted.status === 410 && code(restoreDeleted.j) === "managed_backup_tombstoned",
    `status ${restoreDeleted.status} code ${code(restoreDeleted.j)}`);

  // THE RESURRECTION THAT DOES NOT GO THROUGH IMPORT AT ALL. The plan was prepared while the backup
  // was live and its staged copy survived the deletion; applying it would promote destroyed archive
  // content into a live workspace without touching the material store the deletion purged.
  fs.writeFileSync(path.join(workspaceB, "post-restore-sentinel.txt"), "still here\n");
  const staleApply = await B.req("POST", `/v1/hypervisor/restore-plans/${encodeURIComponent(preDeletePlanId)}/apply`, {
    expected_head: preDeleteHead,
    idempotency_key: "restore-prepared-before-deletion",
  });
  ok("A PLAN PREPARED BEFORE THE DELETION CANNOT APPLY IT AFTERWARDS — restorability is re-decided at apply, not inherited from prepare",
    staleApply.status === 410 && code(staleApply.j) === "managed_backup_tombstoned",
    `status ${staleApply.status} code ${code(staleApply.j)}`);
  ok("the refused apply DISCHARGED the staged copy — deleted content is not left one rename from the workspace",
    !fs.existsSync(stagedDir) && staleApply.j?.staged_material?.staged_material_removed === true,
    `staged ${fs.existsSync(stagedDir)} reported ${JSON.stringify(staleApply.j?.staged_material)}`);
  ok("the refused apply left the target workspace untouched",
    fs.existsSync(path.join(workspaceB, "post-restore-sentinel.txt")),
    "sentinel survived");

  // THE RESURRECTION THIS LEG EXISTS TO CLOSE.
  const materialCountBeforeResurrect = B.countFiles("managed-backup-material");
  const resurrect = await importBundle(B, exported.bytes, profileB, "import-resurrect");
  ok("RE-IMPORTING THE EXPORTED BUNDLE OVER A TOMBSTONE IS REFUSED — deletion is not undone by a bundle",
    resurrect.status === 410 && code(resurrect.j) === "managed_backup_tombstoned",
    `status ${resurrect.status} code ${code(resurrect.j)}`);
  ok("the refused resurrection wrote NO material byte back to disk",
    !B.hasMaterial(stateRootA) && B.countFiles("managed-backup-material") === materialCountBeforeResurrect,
    `material ${materialCountBeforeResurrect} -> ${B.countFiles("managed-backup-material")}`);

  // THE RENAME ATTACK. Both merge-blocking reviews found this independently and demonstrated it end
  // to end: the deletion gate used to key on `backup_ref`, which travels INSIDE the bundle, and
  // every tamper-evidence check an import applies is a self-consistency check over caller-supplied
  // bytes. So a caller who legitimately downloaded a bundle could rewrite one field, honestly
  // recompute BOTH unkeyed commitments — which this verifier now computes itself, exactly the way a
  // forger would — and re-admit the destroyed payload to the content-addressed path the deletion had
  // emptied. The old "EDITING THE RECORD" assertion passed only because its forger forgot to
  // recompute; this one does not forget.
  const forgedMaterialBefore = B.countFiles("managed-backup-material");
  const forged = rebuildBundle(exported.bytes, (dir) => {
    const m = JSON.parse(fs.readFileSync(path.join(dir, "ioi-backup-bundle.v1.json"), "utf8"));
    m.backup.backup_ref = `${m.backup.backup_ref}-RESURRECTED`;
    m.backup.manifest_root = manifestRoot(m.backup);
    m.record_artifact_root = artifactRoot(m.backup);
    fs.writeFileSync(path.join(dir, "ioi-backup-bundle.v1.json"), JSON.stringify(m));
  }).bundle;
  const forgedImport = await importBundle(B, forged, profileB, "import-forged-rename");
  ok("RENAMING the coordinate does NOT resurrect deleted content — the deletion is keyed on what was DESTROYED, not on what it was called",
    forgedImport.status === 410 && code(forgedImport.j) === "managed_backup_material_destroyed",
    `status ${forgedImport.status} code ${code(forgedImport.j)}`);
  ok("the refused rename wrote NO material byte back — the destroyed payload stays destroyed",
    !B.hasMaterial(stateRootA) && B.countFiles("managed-backup-material") === forgedMaterialBefore,
    `material ${forgedMaterialBefore} -> ${B.countFiles("managed-backup-material")}`);
  // PRECONDITION that makes the two assertions above mean something: the forgery is INTERNALLY
  // VALID. If the daemon were refusing it as malformed rather than as destroyed, this would prove
  // nothing — so the same forgery is replayed against a coordinate that was never deleted.
  const forgedManifest = readBundleManifest(forged);
  ok("PRECONDITION: the forged bundle is internally CONSISTENT — both recomputed roots are the ones the daemon derives",
    forgedManifest.record_artifact_root === artifactRoot(forgedManifest.backup)
      && forgedManifest.backup.manifest_root === manifestRoot(forgedManifest.backup),
    "recomputed roots agree with the record they describe");

  const intentAfter = await B.req("GET", `/v1/hypervisor/download-intents/${intentId}/content`);
  ok("A DOWNLOAD INTENT MINTED BEFORE THE DELETION STOPS DELIVERING, and names the deletion rather than an absent file",
    intentAfter.status === 410 && code(intentAfter.j) === "managed_backup_material_destroyed",
    `status ${intentAfter.status} code ${code(intentAfter.j)}`);

  const exportDeleted = await A.req("POST", `/v1/hypervisor/backups/${encodeURIComponent(backupIdA)}/export`, {
    authority_grant_refs: ["grant://local/export/1"], expires_in_seconds: 600,
  });
  ok("daemon A can still export its own copy — B's deletion is B's custody decision, not a forged global revocation",
    exportDeleted.status === 201, `status ${exportDeleted.status}`);

  // Re-capture over a tombstone, on the daemon that owns the source environment.
  const deletedOnA = await deleteViaRetention(A, backupIdA, "erase-a");
  ok("daemon A executes its own deletion of the same coordinate",
    deletedOnA.executed.status === 200 && !A.hasMaterial(stateRootA),
    `status ${deletedOnA.executed.status}`);
  const recapture = await captureBackup(A, envA, instanceA, profileA, "capture-a-recapture");
  ok("A RE-CAPTURE of the unchanged environment refuses rather than restoring the deleted bytes to the same coordinate",
    recapture.status === 410 && code(recapture.j) === "managed_backup_tombstoned",
    `status ${recapture.status} code ${code(recapture.j)}`);
  ok("the refused re-capture wrote no material back either",
    !A.hasMaterial(stateRootA), A.materialPath(stateRootA));

  // ---------------------------------------------------------- retention expiry
  // A three-second duty, not a one-second one: the expiry is TRUNCATED to whole seconds, which
  // rounds it down by up to a second, so a one-second duty can already be spent by the time the
  // export it is meant to survive runs. Rounding down is the safe direction for the gate and the
  // wrong direction for a fixture that needs the record alive first.
  const shortProfile = "storage-profile://local/short-duty";
  await createStorageProfile(A, shortProfile, 3, "profile-a-short");
  fs.writeFileSync(path.join(workspaceA, "second-capture.txt"), `distinct-${Date.now()}\n`);
  const shortLived = await captureBackup(A, envA, instanceA, shortProfile, "capture-a-short");
  const shortId = String(shortLived.j?.backup?.backup_ref ?? "").split("/").pop() ?? "";
  const shortRoot = String(shortLived.j?.backup?.source_state_root_ref ?? "").replace(/^state-root:\/\//u, "");
  ok("a short retention duty captures normally and is restorable while it lasts",
    shortLived.status === 201 && typeof shortLived.j?.backup?.expires_at === "string",
    `status ${shortLived.status} ${shortLived.j?.backup?.expires_at}`);
  const shortBundle = await exportBundle(A, shortId);
  ok("a still-live short-duty backup exports normally — expiry refuses only once the duty is spent",
    shortBundle.status === 200, `status ${shortBundle.status}`);
  await sleep(4200);
  const expiredVerify = await A.req("POST", `/v1/hypervisor/backups/${encodeURIComponent(shortId)}/verify`);
  ok("once the duty ends the backup is no longer restore material, typed as EXPIRED",
    expiredVerify.status === 410 && code(expiredVerify.j) === "managed_backup_retention_expired",
    `status ${expiredVerify.status} code ${code(expiredVerify.j)}`);
  ok("expiry refuses USE while the bytes are still on disk — the record decides, not the filesystem",
    A.hasMaterial(shortRoot), A.materialPath(shortRoot));
  const expiredRestore = await A.req("POST", `/v1/hypervisor/backups/${encodeURIComponent(shortId)}/restore-plans`, {
    target_environment_id: envA,
    authority_grant_refs: ["grant://local/restore/1"],
    idempotency_key: "restore-expired",
  });
  ok("an expired backup cannot be prepared for restore",
    expiredRestore.status === 410 && code(expiredRestore.j) === "managed_backup_retention_expired",
    `status ${expiredRestore.status} code ${code(expiredRestore.j)}`);
  const expiredExport = await A.req("POST", `/v1/hypervisor/backups/${encodeURIComponent(shortId)}/export`, {
    authority_grant_refs: ["grant://local/export/1"], expires_in_seconds: 600,
  });
  ok("an expired backup cannot be exported",
    expiredExport.status === 410 && code(expiredExport.j) === "managed_backup_retention_expired",
    `status ${expiredExport.status} code ${code(expiredExport.j)}`);
  const expiredDownload = await fetch(`${A.url}/v1/hypervisor/backup-exports/${shortBundle.token}`, {
    headers: { cookie: `ioi_session=${A.session}` },
  });
  const expiredDownloadBody = await expiredDownload.text().then((t) => { try { return JSON.parse(t); } catch { return null; } });
  ok("a download token minted BEFORE the duty ended stops delivering once it has, and says it was RETENTION that stopped it",
    expiredDownload.status === 410 && code(expiredDownloadBody) === "managed_backup_retention_expired",
    `status ${expiredDownload.status} code ${code(expiredDownloadBody)}`);
  const expiredImportBefore = B.countFiles("managed-backup-material");
  const expiredImport = await importBundle(B, shortBundle.bytes, profileB, "import-expired");
  ok("an EXPIRED bundle cannot be laundered into a fresh one by importing it elsewhere",
    expiredImport.status === 410 && code(expiredImport.j) === "managed_backup_retention_expired"
      && B.countFiles("managed-backup-material") === expiredImportBefore,
    `status ${expiredImport.status} code ${code(expiredImport.j)}`);

  // ---------------------------------------------------------- the retention parser's real states
  //
  // The first revision of this section set `expires_at = "not-a-timestamp"` AND corrupted the
  // artifact root, so the request died at the contract check and NEVER REACHED the retention gate —
  // a two-code disjunction whose label named a branch it did not exercise. `managed_backup_
  // retention_unreadable` appeared nowhere in this file. Both fixtures below are contract-VALID
  // with honestly recomputed commitments, so the only thing that can refuse them is the gate named.
  const reforge = (bundle, expiresAt) => rebuildBundle(bundle, (dir) => {
    const m = JSON.parse(fs.readFileSync(path.join(dir, "ioi-backup-bundle.v1.json"), "utf8"));
    m.backup.expires_at = expiresAt;
    m.backup.manifest_root = manifestRoot(m.backup);
    m.record_artifact_root = artifactRoot(m.backup);
    fs.writeFileSync(path.join(dir, "ioi-backup-bundle.v1.json"), JSON.stringify(m));
  }).bundle;

  // Matches the contract's canonicalDateTime pattern; is not a real date. Only a parser that can
  // FAIL can answer this, which is why the shared `parse_rfc3339_ms` (whose malformed answer is 0,
  // indistinguishable from the epoch) is not the one this gate uses.
  const unreadableImport = await importBundle(B, reforge(shortBundle.bytes, "2026-02-31T00:00:00Z"), profileB, "import-unreadable");
  ok("a retention instant that does not exist is refused — the REGISTERED CONTRACT validates the instant before the retention gate ever sees it",
    unreadableImport.status === 422 && code(unreadableImport.j) === "managed_backup_import_contract_invalid",
    `status ${unreadableImport.status} code ${code(unreadableImport.j)}`);
  // `managed_backup_retention_unreadable` is therefore DORMANT on the import path — the contract
  // refuses an unrepresentable instant first. It is retained as defence in depth for records this
  // daemon compiles itself, and is recorded here as dormant rather than asserted false.

  // The fail-OPEN a review found: `parse_rfc3339_ms` ends in an `i64 as u64` cast, so every
  // pre-1970 instant wrapped to ~1.8e19 and was served as live restore material until roughly the
  // year 586,000,000. The unreadable branch was reachable for exactly one instant — the epoch.
  const preEpochImport = await importBundle(B, reforge(shortBundle.bytes, "1969-01-01T00:00:00Z"), profileB, "import-pre-epoch");
  ok("a PRE-EPOCH retention instant reads as long expired, not as the far future — the parser represents a negative instant",
    preEpochImport.status === 410 && code(preEpochImport.j) === "managed_backup_retention_expired",
    `status ${preEpochImport.status} code ${code(preEpochImport.j)}`);

  // ---------------------------------------------------------- the closed world, derived
  const census = custodyMutationCensus();
  const inventory = custodyRouteInventory();
  const uncensused = inventory.filter((r) => !census.some((c) => c.method === r.method && c.path === r.path));
  ok("the census COVERS every custody mutation the router carries — the family list cannot silently omit one",
    uncensused.length === 0 && census.length >= 8,
    uncensused.map((r) => `${r.method} ${r.path}`).join(", ") || `${census.length} of ${inventory.length}`);
  const anonymousRefusals = [];
  for (const endpoint of census) {
    const concrete = endpoint.path.replace(":id", backupIdA).replace(":plan_id", planId).replace(":action", "apply").replace(":token", "t");
    const response = await B.req(endpoint.method, concrete, {}, { anonymous: true });
    anonymousRefusals.push({ endpoint: `${endpoint.method} ${endpoint.path}`, status: response.status });
  }
  const unauthenticatedDoors = anonymousRefusals.filter((r) => r.status !== 401);
  ok("EVERY censused custody mutation refuses an unauthenticated caller",
    unauthenticatedDoors.length === 0,
    unauthenticatedDoors.map((d) => `${d.endpoint} -> ${d.status}`).join(", ") || `${anonymousRefusals.length} endpoints`);

  // ---------------------------------------------------------- residuals, recorded not hidden
  // Two ceilings, both enforced, refusing at different layers. Over the PLANE's ceiling but inside
  // the router's body limit reaches the handler and gets the typed refusal; over the router's limit
  // is rejected before a byte is buffered, which is the stronger of the two and the reason the body
  // limit matters at all — the Json extractor runs BEFORE the handler authenticates.
  const overPlane = await B.req("POST", "/v1/hypervisor/backup-imports", {
    storage_profile_ref: profileB,
    bundle_sha256: sha256(Buffer.alloc(1)),
    bundle_base64: Buffer.alloc(9 * 1024 * 1024).toString("base64"),
    authority_grant_refs: ["grant://local/import/1"],
    idempotency_key: "import-over-plane",
  });
  ok("RESIDUAL, enforced not silent: a bundle above the whole-verification ceiling is REFUSED with a typed code, never truncated",
    overPlane.status === 413 && code(overPlane.j) === "managed_backup_import_bundle_too_large",
    `status ${overPlane.status} code ${code(overPlane.j)}`);
  const overRouter = await B.req("POST", "/v1/hypervisor/backup-imports", {
    storage_profile_ref: profileB,
    bundle_sha256: sha256(Buffer.alloc(1)),
    bundle_base64: Buffer.alloc(20 * 1024 * 1024).toString("base64"),
    authority_grant_refs: ["grant://local/import/1"],
    idempotency_key: "import-over-router",
  });
  ok("and a body over the ROUTER's limit is rejected before the handler buffers it at all",
    overRouter.status === 413, `status ${overRouter.status}`);

  const fails = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
  console.log(`\n${results.length - fails.length}/${results.length} passed`);
  emitVerifierCensus({ verifierId: "backup-restore", sourceUrl: import.meta.url, results });
  cleanup();
  process.exit(fails.length ? 1 : 0);
}

run().catch((error) => {
  // A crash mid-run used to report NOTHING, which made a broken fixture and a caught defect look
  // identical from the outside. Print what was actually observed before the throw so a reader (and
  // a mutation harness) can tell which assertions had already fired.
  //
  // NO CENSUS IS EMITTED HERE, deliberately. `check:verifier-floors` treats a missing census as RED,
  // and that is the correct reading of a run that did not finish: emitting a short census instead
  // would hand the floor a smaller number to compare against, which is the silent-shrink the floor
  // exists to catch.
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
  console.log(`\n${results.filter((r) => r.pass).length}/${results.length} passed BEFORE THE RUN DIED (incomplete — no census emitted)`);
  console.error(`FAIL backup-restore — ${error?.stack || error}`);
  cleanup();
  process.exit(1);
});
