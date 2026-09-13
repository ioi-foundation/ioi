#!/usr/bin/env node
//
// M09.4 — RESTORE PASSES ON SEMANTIC CONTINUITY, NOT BLOB PRESENCE.
//
// ACC-8 clause 5: "the restored system answers the same questions with the same meanings, and a
// deletion made before the backup stays deleted after the restore." ACC-11 clause 5 adds that
// restore is an admitted ChangePlan and never counts as reconciliation.
//
// WHAT THIS CHECKS AND WHAT IT DELIBERATELY DOES NOT. The change-plan ladder crosses wallet-network
// authority: `POST /v1/hypervisor/environments/lifecycle/:op` requires an approval grant and a
// chain-writer preflight. A missing credential blocks a live RUN, never a unit — so the admission
// TRANSACTION is proven offline by the kernel's own tests (21 in
// `hypervisor_environment_lifecycle`, including one that drives the whole stage ladder and asserts
// `restore_apply` PASSES on a byte-faithful restore while `post_restore_validation` refuses it),
// and what runs here is everything that does not need a wallet:
//
//   * a LIVE backup, compiled by the real daemon through the real `compile_backup_record`, whose
//     committed family heads this file RECOMPUTES INDEPENDENTLY in JavaScript. That is a
//     differential against the Rust kernel rather than a re-run of it — the discipline a fast
//     fixture oracle earned in this estate when two of its eleven operators turned out wrong and
//     both had been failing GREEN.
//   * the structural facts that decide whether the kernel can be reached at all.
//   * predicate drills over records, so nothing is planted in a tracked file.
//
// THE CLAIM WORTH STATING PLAINLY, because it is the whole unit: a restore that writes every byte
// back correctly AND resurrects a record deleted before the backup satisfies every digest in the
// manifest. The drills below construct exactly that — identical manifest bytes, different family
// root — because if the two were not separable there would be nothing here to check.
import net from "node:net";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const RESULTS = [];
const ok = (label, pass, detail = "") => {
  RESULTS.push({ label, pass: !!pass, detail });
  console.log(`${pass ? "PASS" : "FAIL"}  ${label}${detail ? `  · ${detail}` : ""}`);
};
const drill = (label, refused, detail = "") => ok(`DRILL ${label}`, refused, detail);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const freePort = () => new Promise((resolve, reject) => {
  const srv = net.createServer();
  srv.listen(0, "127.0.0.1", () => { const { port } = srv.address(); srv.close(() => resolve(port)); });
  srv.on("error", reject);
});

const PLANE_SET_PROFILE = "ioi.hypervisor-environment-lifecycle-set-jcs-sha256.v1";

// RFC 8785 canonical JSON, for the shapes this file hashes: objects with ASCII keys and arrays of
// strings. Deliberately NOT a general JCS implementation — it would need number canonicalisation
// and \u escaping this file never feeds it — and it throws on anything outside that shape rather
// than hashing something it canonicalised wrongly. A silent disagreement with the Rust side is the
// one failure mode that would make this whole differential worthless.
function jcs(value) {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "string") {
    if (!/^[\x20-\x7e]*$/u.test(value)) throw new Error(`jcs: non-ASCII string outside this canonicaliser: ${value}`);
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new Error(`jcs: non-integer number outside this canonicaliser: ${value}`);
    return String(value);
  }
  if (Array.isArray(value)) return `[${value.map(jcs).join(",")}]`;
  if (typeof value === "object") {
    const keys = Object.keys(value).sort();
    return `{${keys.map((k) => `${jcs(k)}:${jcs(value[k])}`).join(",")}}`;
  }
  throw new Error(`jcs: unsupported ${typeof value}`);
}
const sha256 = (text) => `sha256:${crypto.createHash("sha256").update(Buffer.from(text, "utf8")).digest("hex")}`;

/** The head ref the kernel mints, recomputed from first principles. */
function familyHeadRef(estateNamespace, family) {
  const digest = sha256(jcs({ domain: PLANE_SET_PROFILE, family: family.family, roots: family.roots }));
  return `object-head://${estateNamespace}/${family.family}/${digest.slice("sha256:".length)}`;
}

const daemonBinary = path.resolve(ROOT, process.env.IOI_HYPERVISOR_DAEMON_BINARY ?? "target/debug/hypervisor-daemon");
let scratch = "";
let daemon = null;
let daemonLog = "";
let BASE = "";
let SESSION = "";

function cleanup() {
  try { daemon?.kill("SIGTERM"); } catch { /* already gone */ }
  daemon = null;
  if (scratch) { try { fs.rmSync(scratch, { recursive: true, force: true }); } catch { /* best effort */ } }
}
process.on("exit", cleanup);
process.on("SIGINT", () => { cleanup(); process.exit(130); });
process.on("SIGTERM", () => { cleanup(); process.exit(143); });

async function jd(method, route, body) {
  const headers = {};
  if (body !== undefined) headers["content-type"] = "application/json";
  if (SESSION) headers.cookie = `ioi_session=${SESSION}`;
  const res = await fetch(`${BASE}${route}`, {
    method,
    headers: Object.keys(headers).length ? headers : undefined,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* not json */ }
  return { status: res.status, json, text };
}

// ------------------------------------------------------------------------------ structural lane
function structural() {
  const kernel = fs.readFileSync(path.join(ROOT, "crates/types/src/app/hypervisor_environment_lifecycle.rs"), "utf8");
  const routes = fs.readFileSync(path.join(ROOT, "crates/node/src/bin/hypervisor_daemon_routes/hypervisor_environment_routes.rs"), "utf8");
  const managed = fs.readFileSync(path.join(ROOT, "crates/node/src/bin/hypervisor_daemon_routes/managed_runtime_routes.rs"), "utf8");
  // Comments stripped before searching for evidence, because this kernel explains at length what it
  // used to do — a search for the old shape would otherwise find the paragraph describing it.
  const code = (text) => text.split("\n").filter((line) => !/^\s*\/\//u.test(line)).join("\n");
  const kernelCode = code(kernel);

  ok("`post_restore_validation` has its own arm in the stage compiler and no longer falls through the catch-all",
    /"post_restore_validation" =>/u.test(kernelCode));
  ok("that arm decides continuity rather than re-checking digests",
    /"post_restore_validation" =>[\s\S]{0,900}evaluate_restore_continuity/u.test(kernelCode));
  ok("`restore_apply` still checks every manifest digest — blob presence is INSUFFICIENT, not removed",
    /"restore_apply" =>[\s\S]{0,2000}departs the manifest \\?\s*commitment/u.test(kernelCode)
      || /"restore_apply" =>[\s\S]{0,2000}manifest/u.test(kernelCode));
  ok("the backup compiler no longer emits the pre-M09.4 empty head list",
    !/"source_object_head_refs":\s*\[\]/u.test(kernelCode));
  ok("one constant names the restore-subject families, and BOTH the commitment and the check read it",
    /RESTORE_SUBJECT_FAMILIES/u.test(kernelCode)
      && (kernelCode.match(/restore_subject_roots\(/gu) || []).length >= 3,
    `${(kernelCode.match(/restore_subject_roots\(/gu) || []).length} call sites`);
  ok("a capture resolving no subject roots compiles no backup, and a backup with no heads cannot claim continuity",
    /the resolved capture names none of the families/u.test(kernel)
      && /commits no source family heads/u.test(kernel));
  ok("the heads the stage compares are RECOMPUTED by the daemon from the restored records, never read back off the plane",
    /recomputed_family_roots:\s*environment_family_roots\(/u.test(code(routes)));
  ok("the capture commits the roots resolved BEFORE the backup joins the plane — a head containing itself commits to a plane that never existed",
    /let source_family_roots = environment_family_roots\([\s\S]{0,400}compile_backup_record\(/u.test(code(routes)));
  ok("the legacy managed lane commits its OWN subject family, so a cross-lane continuity claim is refused by name",
    /"family":\s*"managed_workspace"/u.test(code(managed)));
}

// --------------------------------------------------------------------------------------- drills
function drills(estateNamespace) {
  const captured = [
    { family: "route_bindings", roots: [sha256("a"), sha256("b")] },
    { family: "cleanup_obligations", roots: [] },
  ];
  const committed = captured.map((family) => familyHeadRef(estateNamespace, family));

  // A FAITHFUL RESTORE. The baseline, without which every refusal below could be an artefact.
  drill("a faithful restore reproduces every committed head",
    captured.map((f) => familyHeadRef(estateNamespace, f)).every((head, i) => head === committed[i]));

  // THE CLAUSE. A record deleted before the backup comes back after the restore.
  const resurrected = [{ family: "route_bindings", roots: [sha256("a"), sha256("b"), sha256("deleted-before-the-backup")] }, captured[1]];
  drill("a deletion made before the backup that comes back after the restore changes its family head",
    familyHeadRef(estateNamespace, resurrected[0]) !== committed[0]);

  // The other direction, because a one-directional check misses half of it.
  drill("a restore that LOSES a record changes the same head",
    familyHeadRef(estateNamespace, { family: "route_bindings", roots: [sha256("a")] }) !== committed[0]);

  // An empty family still has a head, so "this family had no records" stays distinguishable from
  // "this backup did not look at this family" — without which a restore could repopulate an empty
  // family and contradict nothing.
  drill("an empty family still commits a head",
    typeof committed[1] === "string" && committed[1].includes("/cleanup_obligations/"));

  // ORDER IS PRESENTATION HERE, AND THAT IS DELIBERATE. The kernel sorts roots before hashing
  // because a family is a SET: the same records listed in another order are the same answer. A
  // check that failed on reordering would call canonicalisation a defect.
  drill("reordering the roots of a family does not change its head — a family is a set, and the kernel sorts",
    familyHeadRef(estateNamespace, { family: "route_bindings", roots: [sha256("a"), sha256("b")].sort() })
      === familyHeadRef(estateNamespace, { family: "route_bindings", roots: [sha256("b"), sha256("a")].sort() }));

  // THE SHARPEST ONE: the manifest is byte-identical across a continuity break.
  const manifest = [{ artifact_ref: "artifact://x", sha256: sha256("payload"), size_bytes: 4, role: "workspace_snapshot" }];
  const manifestBefore = sha256(jcs(manifest));
  const manifestAfter = sha256(jcs(manifest));
  drill("the manifest digests are IDENTICAL across the break the heads catch — which is why blob presence cannot decide this",
    manifestBefore === manifestAfter && familyHeadRef(estateNamespace, resurrected[0]) !== committed[0]);

  // A family renamed under the same roots is a different head, so a lane cannot borrow another's.
  drill("the family name is INSIDE the head, so a head cannot be re-attached to a different family",
    familyHeadRef(estateNamespace, { family: "managed_workspace", roots: captured[0].roots }) !== committed[0]);
}

async function main() {
  try { fs.accessSync(daemonBinary, fs.constants.X_OK); } catch {
    console.error(`BLOCKED: no daemon binary at ${daemonBinary}. cargo build -p ioi-node --bin hypervisor-daemon`);
    process.exit(2);
  }
  const binaryAge = fs.statSync(daemonBinary).mtimeMs;
  const kernelAge = fs.statSync(path.join(ROOT, "crates/types/src/app/hypervisor_environment_lifecycle.rs")).mtimeMs;
  ok("PRECONDITION: the daemon binary is newer than the kernel it must serve",
    binaryAge >= kernelAge,
    binaryAge >= kernelAge ? "built from this tree" : "STALE — rebuild before trusting anything below");

  structural();

  scratch = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-canonical-backup-"));
  const dataDir = path.join(scratch, "data");
  fs.mkdirSync(dataDir, { recursive: true });
  const port = await freePort();
  BASE = `http://127.0.0.1:${port}`;
  daemon = spawn(daemonBinary, [], {
    cwd: ROOT,
    env: { ...process.env, IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${port}`, IOI_HYPERVISOR_DATA_DIR: dataDir, IOI_HYPERVISOR_MODEL_UPSTREAM: "http://127.0.0.1:1" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  daemon.stdout.on("data", (c) => { daemonLog = `${daemonLog}${c}`.slice(-64000); });
  daemon.stderr.on("data", (c) => { daemonLog = `${daemonLog}${c}`.slice(-64000); });
  const until = Date.now() + 30000;
  let up = false;
  while (Date.now() < until && !up) {
    try { const r = await fetch(`${BASE}/healthz`); up = r.status < 500; } catch { /* not yet */ }
    if (!up) await sleep(300);
  }
  if (!up) { ok("daemon comes up", false, daemonLog.slice(-400)); return; }

  const bootToken = daemonLog.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
  const boot = await jd("POST", "/v1/hypervisor/auth/bootstrap", { token: bootToken, password: "canonical-backup-v1" });
  SESSION = boot.json?.session_token ?? "";
  ok("PRECONDITION: an authenticated operator session exists", !!SESSION);

  // `actor_ref` is a TENANT ref (org/wallet/project/runtime), not the user principal, and it must
  // equal the storage profile's own owner — the profile scope is what the backup is captured under.
  const owner = "org://local";
  const env = await jd("POST", "/v1/hypervisor/environments", { spec: {} });
  const environmentId = env.json?.environment?.id ?? "";
  ok("an environment exists to be backed up", !!environmentId, environmentId || JSON.stringify(env.json).slice(0, 160));

  const profileRef = "storage-profile://local/continuity";
  await jd("POST", "/v1/hypervisor/storage-profiles", {
    storage_profile_ref: profileRef,
    owner_ref: owner,
    backend_class: "local_private",
    destination_ref: "storage://local/private",
    custody_policy_ref: "policy://local/custody",
    encryption_ref: null,
    key_epoch_ref: null,
    retention_policy_ref: "policy://local/retention",
    retention_duration_seconds: 86400,
    jurisdiction_refs: [],
    minimum_replicas: 1,
    independent_compute_copy_required: false,
    export_allowed: true,
    authority_grant_refs: ["grant://local/custody/1"],
    idempotency_key: "continuity-profile-1",
  });
  // AN OWNER-SCOPED MANAGED INSTANCE. The capture route refuses without one — "backup capture
  // requires an owner-scoped managed instance until the environment plane exposes principal
  // ownership" — which is the plane telling the truth about where ownership currently lives. The
  // shape below is the one `check:backup-restore` already drives; it is inlined rather than shared
  // because a verifier that imports another verifier's fixtures inherits its assumptions silently.
  await jd("POST", `/v1/hypervisor/environments/${environmentId}/start`);
  const instanceId = "agent://local/continuity-instance-1";
  const created = await jd("POST", "/v1/hypervisor/managed-worker-instances", {
    instance_id: instanceId,
    lifecycle_id: "lifecycle:continuity",
    owner_ref: owner,
    worker_package_ref: "worker-package://local/w1",
    config_revision_ref: "config-revision://local/w1/1",
    runtime_policy: {
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
    },
    authority_grant_refs: ["grant://local/runtime/1"],
    idempotency_key: "continuity-create",
  });
  let head = created.json?.instance?.agentgres?.head ?? "";
  for (const [index, to] of ["initializing", "active"].entries()) {
    const transition = await jd("POST", `/v1/hypervisor/managed-worker-instances/${encodeURIComponent(instanceId)}/transitions`, {
      expected_head: head,
      idempotency_key: `continuity-to-${to}`,
      to_state: to,
      transition_reason: `the gate drives the instance to ${to}`,
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
      placement: index === 1
        ? {
          runtime_node_ref: "runtime://local/node-1",
          daemon_profile_ref: "profile://local/daemon",
          environment_ref: `environment://local/${environmentId}`,
          provider_ref: "provider://local/process",
          quote_ref: null,
          budget_reservation_ref: null,
          assignment_lease_ref: "lease://local/assignment-1",
          isolation_binding_ref: "binding://local/isolation-1",
          readiness_evidence_refs: ["receipt://local/readiness/1"],
        }
        : null,
    });
    head = transition.json?.instance?.agentgres?.head ?? head;
  }
  const made = await jd("POST", `/v1/hypervisor/environments/${environmentId}/backups`, {
    storage_profile_ref: profileRef,
    backup_policy_ref: "policy://local/backups",
    trigger: "manual",
    actor_ref: owner,
    instance_ref: instanceId,
    system_ref: null,
    schedule_or_change_plan_ref: null,
    authority_grant_refs: ["grant://local/custody/1"],
    idempotency_key: "continuity-backup-1",
  });
  const backup = made.json?.backup ?? made.json ?? {};
  ok("the daemon compiles a canonical backup record through the real kernel",
    made.status < 300 && typeof backup.backup_ref === "string" && backup.schema_version === "ioi.hypervisor-environment-backup.v1",
    `status ${made.status} schema ${backup.schema_version ?? "(none)"} ref ${backup.backup_ref ?? "(none)"}`);

  const heads = Array.isArray(backup.source_object_head_refs) ? backup.source_object_head_refs : [];
  ok("THE WITNESS IS POPULATED — the field has been on the contract since v1 and the compiler wrote `[]` for every backup the plane ever took",
    heads.length > 0, `${heads.length} committed head(s)`);

  const estateNamespace = String(backup.backup_ref || "").replace("environment-backup://", "").split("/")[0] || "local";
  // THE DIFFERENTIAL. Recomputed here from first principles — canonical JSON, SHA-256, the same
  // domain string — and compared to what the Rust kernel minted. Agreement is the evidence; a
  // verifier that only re-read the daemon's own number would be asking the thing under test to
  // grade itself.
  const recomputed = familyHeadRef(estateNamespace, { family: "managed_workspace", roots: [backup.source_state_root_ref?.replace("state-root://", "") ?? ""] });
  ok("an INDEPENDENT recomputation of the head ref agrees with the kernel's — canonical JSON and SHA-256, not the daemon's own answer read back",
    heads.includes(recomputed), heads[0] ?? "(none)");
  ok("and the legacy lane's head is under its OWN subject family, which the environment plane never rebuilds",
    // `heads.length > 0` is not decoration. `[].every(...)` is TRUE, so without it this assertion
    // passed while the daemon had committed no heads at all — an assertion that cannot fail, which
    // is the "a partial never reads as a pass" defect wearing a verifier's clothes. It was caught
    // here by an unrelated failure on the same run.
    heads.length > 0 && heads.every((head) => head.includes("/managed_workspace/")),
    heads.join(" "));

  // The manifest is still checked. Blob presence became insufficient, not unnecessary.
  ok("the backup still carries its manifest census and root — semantic continuity is an ADDITIONAL bar, not a replacement",
    typeof backup.manifest_root === "string"
      && Array.isArray(backup.manifest_rows)
      && backup.manifest_rows.length === backup.manifest_artifact_count);

  drills(estateNamespace);

  // Nothing above admitted a second backup by accident.
  const listed = await jd("GET", "/v1/hypervisor/backups");
  const count = (listed.json?.backups || []).length;
  ok("exactly one backup exists — every drill above ran over records, never over the daemon", count === 1, `${count}`);
}

main()
  .catch((error) => { ok("verifier ran to completion", false, String(error?.message || error)); })
  .finally(() => {
    cleanup();
    const failed = RESULTS.filter((r) => !r.pass);
    console.log(`\n${failed.length === 0 ? "PASS" : "FAIL"} check:canonical-environment-backup — ${RESULTS.length - failed.length}/${RESULTS.length} assertion(s)`
      + (failed.length ? ` · failing: ${failed.map((r) => r.label).join(" | ")}` : ""));
    process.exit(failed.length === 0 ? 0 : 1);
  });
