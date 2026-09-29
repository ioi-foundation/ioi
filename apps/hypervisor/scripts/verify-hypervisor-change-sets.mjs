#!/usr/bin/env node
// CHANGE SETS — CANON'S PATCH BRANCH FOR AN OBJECT FAMILY (ADR 0056 P4, R-241).
//
// Proves, against an ISOLATED real daemon (never the shared dev processes), that a Hypervisor object
// family changes only through a change set merged by the family's own admission: a change set founding
// a DataRecipe family pins no head and carries its first draft; merging before validation is refused;
// validation runs admission's own checks without writing, and an incomplete draft is judged invalid with
// admission's own refusal code; a proposed, validated change set merges as the family's revision 1 and
// records a BranchMergePlan; two successors pinned to revision 1 race and the second is refused because
// the head moved (never silently rebased); a rejection needs a note, an abandoned change set takes no
// more drafts; a draft cannot carry the fields its merge supplies; the list and the detail read back,
// the detail with its plan; and an anonymous caller is refused. A proposal carries its own name and
// description: propose sets both, a propose naming neither keeps the ones the change set was opened
// with, and a proposal title over 200 characters is refused by name with the change set left open.
// Every record the daemon returns is re-validated HERE against its registered schema.
//
// Exit: 0 pass · 1 fail · 2 blocked (daemon binary missing).
//
//   IOI_HYPERVISOR_DAEMON_BINARY  default target/debug/hypervisor-daemon
//   node apps/hypervisor/scripts/verify-hypervisor-change-sets.mjs

import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import net from "node:net";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { emitVerifierCensus } from "./lib/verifier-census.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP = path.resolve(HERE, "..");
const ROOT = path.resolve(APP, "..", "..");
const SCHEMAS = path.join(ROOT, "docs", "architecture", "_meta", "schemas");

const results = [];
const ok = (name, cond, detail) => results.push({ name, pass: !!cond, detail: detail || "" });

const ajv = new Ajv2020({ strict: false, allErrors: true });
addFormats(ajv);
// Every change set the daemon opens is v2 (R-240 journey WP-C2: the generic subject kinds and the
// reserved basis_refs); a v1 record keeps reading as v1. Each record is judged by its OWN version.
const changeSetSchemas = {
  "ioi.change-set.v1": ajv.compile(JSON.parse(fs.readFileSync(path.join(SCHEMAS, "change-set.v1.schema.json"), "utf8"))),
  "ioi.change-set.v2": ajv.compile(JSON.parse(fs.readFileSync(path.join(SCHEMAS, "change-set.v2.schema.json"), "utf8"))),
};
const validChangeSet = (record) => {
  const validator = changeSetSchemas[record?.schema_version];
  validChangeSet.errors = validator ? null : [{ message: `no registered change-set schema ${record?.schema_version}` }];
  if (!validator) return false;
  const valid = validator(record);
  validChangeSet.errors = validator.errors;
  return valid;
};
const validPlan = ajv.compile(JSON.parse(fs.readFileSync(path.join(SCHEMAS, "branch-merge-plan.v1.schema.json"), "utf8")));
const schemaErrors = (validator) => JSON.stringify(validator.errors || []).slice(0, 200);

const freePort = () => new Promise((resolve, reject) => {
  const srv = net.createServer();
  srv.listen(0, "127.0.0.1", () => { const { port } = srv.address(); srv.close(() => resolve(port)); });
  srv.on("error", reject);
});
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const daemonBinary = path.resolve(ROOT, process.env.IOI_HYPERVISOR_DAEMON_BINARY ?? "target/debug/hypervisor-daemon");
try { fs.accessSync(daemonBinary, fs.constants.X_OK); } catch {
  console.error(`BLOCKED: daemon binary not executable at ${daemonBinary}`);
  process.exit(2);
}

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-change-sets-"));
let daemon = null;

async function run() {
  const port = await freePort();
  const DAEMON = `http://127.0.0.1:${port}`;
  let log = "";
  daemon = spawn(daemonBinary, [], {
    cwd: ROOT,
    env: { ...process.env, IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${port}`, IOI_HYPERVISOR_DATA_DIR: dataDir, IOI_HYPERVISOR_MODEL_UPSTREAM: "http://127.0.0.1:1/v1" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  daemon.stdout.on("data", (c) => { log = `${log}${c}`.slice(-64000); });
  daemon.stderr.on("data", (c) => { log = `${log}${c}`.slice(-64000); });
  for (let i = 0; i < 150; i++) { try { if ((await fetch(`${DAEMON}/healthz`)).ok) break; } catch { /* not up */ } await sleep(300); }
  const token = log.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
  const boot = token ? await fetch(`${DAEMON}/v1/hypervisor/auth/bootstrap`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token, password: "change-sets-bootstrap-v1", email: "changes@ioi.local" }) }).then((r) => r.json()).catch(() => ({})) : {};
  const cookie = boot.session_token ? `ioi_session=${boot.session_token}` : "";
  ok("operator bootstrap yields an authenticated session", cookie.startsWith("ioi_session=ioi_sess_"), cookie.slice(0, 24));
  const req = async (method, route, body) => {
    const r = await fetch(`${DAEMON}${route}`, { method, headers: { cookie, "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined }).catch(() => null);
    return { status: r?.status ?? 0, j: r ? await r.json().catch(() => ({})) : {} };
  };
  const who = (await req("GET", "/v1/hypervisor/auth/whoami")).j;
  const OWNER = (who.principal?.tenant_refs || []).find((t) => String(t).startsWith("org://")) || "";
  const POLICY = `sha256:${"3c".repeat(32)}`;
  const w = (key, extra = {}) => ({ owner_ref: OWNER, idempotency_key: key, ...extra });

  // ---- the members a recipe binds: an exact ontology revision and a connector-mapping revision
  const ontology = await req("POST", "/v1/hypervisor/ontology-versions", w("cs-ontology", { namespace: "acme-clinic", name: "patient-intake", governing_scope_ref: "domain://acme-clinic/intake", policy_hash: POLICY, entity_types: [{ term_id: "ontology://acme-clinic/patient-intake/term/patient", label: "patient" }], valid_time: { starts_at: "2026-01-01T00:00:00Z", ends_at: null } }));
  const ONT1 = ontology.j?.ontology_version?.ontology_id ?? "";
  const mapping = await req("POST", "/v1/hypervisor/connector-mapping-revisions", w("cs-mapping", { family: "acme.intake-form", name: "intake-form", connector_id: "connector://google-drive", ontology_revision_ref: ONT1, source_schema_ref: "artifact://acme/intake-form/provider-schema/2026-09", target_object_model_refs: ["object-model://om_patient_intake"], field_mappings: [{ role: "key", source_field: "record_id", target_property_ref: "object-model://om_patient_intake#intake_id", source_type: "string", source_cardinality: "one" }], action_mappings: [], authority_scopes_required: ["scope:connector.google_drive.read"], redaction_policy_ref: "policy://acme-clinic/intake-redaction", evidence_required: ["evidence-contract://acme-clinic/intake-consent"], effective_policy_hash: POLICY, registry_status: "active" }));
  const MAP1 = mapping.j?.connector_mapping?.revision_ref ?? "";
  ok("PRECONDITION: an exact admitted ontology revision and connector-mapping revision exist for a recipe to bind", !!ONT1 && !!MAP1, `${ontology.status} ${ONT1} · ${mapping.status} ${MAP1}`);
  const draft = (extra = {}) => ({ name: "intake-normalise", ontology_revision_refs: [ONT1], input_source_types: ["connector", "document"], connector_mapping_revision_refs: [MAP1], output_object_model_refs: ["object-model://om_patient_intake"], output_dataset_contract_refs: ["schema://acme-clinic/patient-intake-row/v2"], transformation_steps: ["extract", "redact", "normalize", "validate", "map"], policy_bound_data_view_refs: [], receipt_obligations: ["data_recipe_run", "transformation"], effective_policy_hash: POLICY, registry_status: "active", ...extra });
  const idOf = (r) => String(r.j?.change_set?.change_set_ref || "").replace("change://", "");
  const FAMILY = "acme.intake-normalise";

  // ---- 1. found the family through a change set
  const open = await req("POST", "/v1/hypervisor/change-sets", w("cs-open-1", { subject: { kind: "data_recipe", family: FAMILY }, title: "Normalise intake", draft: draft() }));
  const cs1 = idOf(open);
  ok("a change set founding a DataRecipe family pins no head, carries its first draft, and satisfies its registered contract",
    open.status === 201 && open.j.change_set?.subject?.base_head_ref === null && open.j.change_set?.drafts?.length === 1 && open.j.change_set?.status === "open" && validChangeSet(open.j.change_set),
    `${open.status} ${cs1} · ${schemaErrors(validChangeSet)}`);
  await req("POST", `/v1/hypervisor/change-sets/${cs1}/propose`, w("cs-propose-1"));
  const early = await req("POST", `/v1/hypervisor/change-sets/${cs1}/merge`, w("cs-merge-early"));
  ok("merging a change set whose latest draft has not validated is refused, and nothing is admitted",
    early.status === 409 && early.j.error?.code === "change_set_unvalidated", `${early.status} ${early.j.error?.code}`);
  const validated = await req("POST", `/v1/hypervisor/change-sets/${cs1}/validate`, w("cs-validate-1"));
  const beforeMerge = await req("GET", `/v1/hypervisor/data-recipe-revisions?family=${FAMILY}`);
  ok("validation runs admission's own checks against the draft and writes no revision: a complete draft is valid and the family still has none",
    validated.j.change_set?.validation?.outcome === "valid" && validated.j.change_set.validation.findings.length === 0 && !JSON.stringify(beforeMerge.j).includes(`data-recipe://${FAMILY}/revision/`),
    `${validated.j.change_set?.validation?.outcome} · revisions before merge ${JSON.stringify(beforeMerge.j).includes("/revision/")}`);
  const merged = await req("POST", `/v1/hypervisor/change-sets/${cs1}/merge`, w("cs-merge-1"));
  const afterMerge = await req("GET", `/v1/hypervisor/data-recipe-revisions?family=${FAMILY}`);
  ok("a proposed, validated change set merges through the family's own admission: revision 1 exists, the change set names it, and a BranchMergePlan records the admit decision",
    merged.status === 200 && merged.j.change_set?.status === "merged" && merged.j.change_set?.merge?.resulting_revision_ref === `data-recipe://${FAMILY}/revision/1`
      && JSON.stringify(afterMerge.j).includes(`data-recipe://${FAMILY}/revision/1`) && merged.j.branch_merge_plan?.decision === "admit"
      && validPlan(merged.j.branch_merge_plan) && validChangeSet(merged.j.change_set),
    `${merged.status} ${merged.j.change_set?.merge?.resulting_revision_ref} · plan ${merged.j.branch_merge_plan?.decision} ${schemaErrors(validPlan)}`);

  // ---- 2. two successors pinned to revision 1: the first merges, the second is refused
  const a = await req("POST", "/v1/hypervisor/change-sets", w("cs-open-a", { subject: { kind: "data_recipe", family: FAMILY }, title: "Add a dedupe step", draft: draft({ transformation_steps: ["extract", "redact", "normalize", "dedupe", "validate", "map"], succession_reason: "transformation_step_change" }) }));
  const b = await req("POST", "/v1/hypervisor/change-sets", w("cs-open-b", { subject: { kind: "data_recipe", family: FAMILY }, title: "Correct the name", draft: draft({ name: "intake-normalise-v2", succession_reason: "correction" }) }));
  const ida = idOf(a), idb = idOf(b);
  for (const [id, k] of [[ida, "a"], [idb, "b"]]) {
    await req("POST", `/v1/hypervisor/change-sets/${id}/validate`, w(`cs-validate-${k}`));
    await req("POST", `/v1/hypervisor/change-sets/${id}/propose`, w(`cs-propose-${k}`));
  }
  const mergedA = await req("POST", `/v1/hypervisor/change-sets/${ida}/merge`, w("cs-merge-a"));
  const mergedB = await req("POST", `/v1/hypervisor/change-sets/${idb}/merge`, w("cs-merge-b"));
  ok("two successors pin revision 1; the first to merge becomes revision 2 and the second is refused because the family's head moved — never rebased silently",
    a.j.change_set?.subject?.base_revision_ref === `data-recipe://${FAMILY}/revision/1` && mergedA.status === 200
      && mergedA.j.change_set?.merge?.resulting_revision_ref === `data-recipe://${FAMILY}/revision/2`
      && mergedB.status === 409 && mergedB.j.error?.code === "change_set_base_moved",
    `a ${mergedA.status} ${mergedA.j.change_set?.merge?.resulting_revision_ref} · b ${mergedB.status} ${mergedB.j.error?.code}`);

  // ---- 3. an incomplete draft is judged invalid with admission's own refusal
  const empty = await req("POST", "/v1/hypervisor/change-sets", w("cs-open-empty", { subject: { kind: "data_recipe", family: "acme.other" }, title: "An empty pipeline", draft: { name: "empty" } }));
  const idEmpty = idOf(empty);
  const invalid = await req("POST", `/v1/hypervisor/change-sets/${idEmpty}/validate`, w("cs-validate-empty"));
  ok("an incomplete draft validates invalid, with the refusal code admission itself gives",
    invalid.j.change_set?.validation?.outcome === "invalid" && invalid.j.change_set.validation.findings[0]?.code === "data_recipe_ontology_revisions_required",
    JSON.stringify(invalid.j.change_set?.validation?.findings || invalid.j.error).slice(0, 200));

  // ---- 4. rejection needs a note; an abandoned change set takes no more drafts; minted fields refused
  const noNote = await req("POST", `/v1/hypervisor/change-sets/${idb}/reject`, w("cs-reject-no-note"));
  const rejected = await req("POST", `/v1/hypervisor/change-sets/${idb}/reject`, w("cs-reject-b", { note: "superseded by the dedupe step" }));
  const abandoned = await req("POST", `/v1/hypervisor/change-sets/${idEmpty}/abandon`, w("cs-abandon-empty"));
  const lateDraft = await req("POST", `/v1/hypervisor/change-sets/${idEmpty}/drafts`, w("cs-late-draft", { draft: { name: "late" } }));
  ok("a rejection needs a note, a rejected and an abandoned change set are terminal, and a terminal change set takes no more drafts",
    noNote.status === 400 && rejected.j.change_set?.status === "rejected" && rejected.j.change_set?.decision_note === "superseded by the dedupe step"
      && abandoned.j.change_set?.status === "abandoned" && lateDraft.status === 409,
    `${noNote.status} · ${rejected.j.change_set?.status} · ${abandoned.j.change_set?.status} · late draft ${lateDraft.status}`);
  const minted = await req("POST", "/v1/hypervisor/change-sets", w("cs-open-minted", { subject: { kind: "data_recipe", family: "acme.minted" }, title: "Minted", draft: { name: "x", expected_head: `sha256:${"0".repeat(64)}` } }));
  const foreign = await req("POST", "/v1/hypervisor/change-sets", w("cs-open-foreign", { subject: { kind: "ontology", family: "acme" }, title: "Not yet" }));
  ok("a draft cannot carry what its merge supplies (expected_head), and a subject kind the plane does not carry is refused by name",
    minted.status === 400 && minted.j.error?.code === "change_set_draft_field_minted" && foreign.status === 400 && foreign.j.error?.code === "change_set_subject_unsupported",
    `${minted.status} ${minted.j.error?.code} · ${foreign.status} ${foreign.j.error?.code}`);

  // ---- 5. reads
  const list = await req("GET", `/v1/hypervisor/change-sets?family=${FAMILY}`);
  const detail = await req("GET", `/v1/hypervisor/change-sets/${cs1}`);
  const anonymous = await fetch(`${DAEMON}/v1/hypervisor/change-sets`).then((r) => r.status).catch(() => 0);
  ok("the family's change sets list back, one opens with its merge plan, and an anonymous caller is refused",
    list.j.change_sets?.length === 3 && detail.j.branch_merge_plan?.branch_merge_ref === merged.j.change_set?.merge?.branch_merge_plan_ref && anonymous === 401,
    `list ${list.j.change_sets?.length} · plan ${detail.j.branch_merge_plan?.status} · anonymous ${anonymous}`);

  // ---- 6. a proposal carries its own name and description (the Pipeline Builder's "Create proposal")
  const NAMED = "acme.proposal-named";
  const openNamed = (key, title) => req("POST", "/v1/hypervisor/change-sets", w(key, { subject: { kind: "data_recipe", family: NAMED }, title, description: "the description it was opened with", draft: draft({ name: "proposal-named" }) }));
  const named = await openNamed("cs-open-named", "Untitled proposal");
  const idNamed = idOf(named);
  const proposedNamed = await req("POST", `/v1/hypervisor/change-sets/${idNamed}/propose`, w("cs-propose-named", { title: "Add a dedupe step", description: "Dedupe rows before mapping them to patients." }));
  const readNamed = await req("GET", `/v1/hypervisor/change-sets/${idNamed}`);
  ok("proposing with a title and a description sets both on the change set, and the read-back shows them on a record that satisfies its contract",
    proposedNamed.status === 200 && readNamed.j.change_set?.status === "proposed" && readNamed.j.change_set?.title === "Add a dedupe step"
      && readNamed.j.change_set?.description === "Dedupe rows before mapping them to patients." && validChangeSet(readNamed.j.change_set),
    `${proposedNamed.status} ${proposedNamed.j.error?.code ?? ""} · ${readNamed.j.change_set?.status} "${readNamed.j.change_set?.title}" · ${schemaErrors(validChangeSet)}`);
  const kept = await openNamed("cs-open-kept", "Keep this title");
  const idKept = idOf(kept);
  const proposedKept = await req("POST", `/v1/hypervisor/change-sets/${idKept}/propose`, w("cs-propose-kept"));
  const readKept = await req("GET", `/v1/hypervisor/change-sets/${idKept}`);
  ok("proposing with no title or description keeps the ones the change set was opened with",
    proposedKept.status === 200 && readKept.j.change_set?.status === "proposed" && readKept.j.change_set?.title === "Keep this title"
      && readKept.j.change_set?.description === "the description it was opened with",
    `${proposedKept.status} · ${readKept.j.change_set?.status} "${readKept.j.change_set?.title}" · "${readKept.j.change_set?.description}"`);
  const long = await openNamed("cs-open-long", "Still open");
  const idLong = idOf(long);
  const proposedLong = await req("POST", `/v1/hypervisor/change-sets/${idLong}/propose`, w("cs-propose-long", { title: "t".repeat(201) }));
  const readLong = await req("GET", `/v1/hypervisor/change-sets/${idLong}`);
  ok("a proposal title over 200 characters is refused change_set_title_required, and the change set stays open under its old title",
    proposedLong.status === 400 && proposedLong.j.error?.code === "change_set_title_required" && readLong.j.change_set?.status === "open" && readLong.j.change_set?.title === "Still open",
    `${proposedLong.status} ${proposedLong.j.error?.code} · ${readLong.j.change_set?.status} "${readLong.j.change_set?.title}"`);
}

run().then(() => {
  const fails = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
  console.log(`\n${results.length - fails.length}/${results.length} passed`);
  emitVerifierCensus({ verifierId: "change-sets", sourceUrl: import.meta.url, results });
  cleanup();
  process.exit(fails.length ? 1 : 0);
}).catch((e) => {
  console.error("verifier crashed:", e);
  cleanup();
  process.exit(1);
});

function cleanup() {
  try { daemon?.kill("SIGTERM"); } catch { /* gone */ }
  try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch { /* keep */ }
}
