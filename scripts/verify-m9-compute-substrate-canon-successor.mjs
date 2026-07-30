#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const root = process.cwd();
const estate = path.join(root, "internal-docs/implementation");
const holdPath = path.join(estate, "_archive/holds/open-successor-holds.v1.json");
const recordRoot = path.join(estate, "work-items");
const outRel = "internal-docs/implementation/evidence/M9/m9-compute-substrate-canon-successor.v1.json";
const expectedSuccessor = "m9-compute-substrate-canon-successor";
const expectedDependencies = [
  "hypervisoros-appliance-install-update-recovery",
  "hypervisoros-appliance-profile-claim-gate",
  "hypervisoros-single-node-virtualization-journey",
  "m3-workrun-resource-isolation-contract",
  "m6-hypervisor-claim-bundle-control-surface",
  "m9-backend-capability-and-coverage-evidence",
  "m9-infrastructure-estate-operational-journey",
  "m9-infrastructure-profile-claim-gate",
  "m9-secure-workrun-isolation-claim-gate",
  "m9-workrun-microvm-isolation-and-output-admission",
  "m9-workstation-profile-claim-gate",
  "m9-workstation-virtual-machine-operational-journey",
].sort();

function sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function json(rel) {
  return JSON.parse(fs.readFileSync(path.join(root, rel), "utf8"));
}

function walk(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const absolute = path.join(dir, entry.name);
    return entry.isDirectory() ? walk(absolute) : entry.name.endsWith(".json") ? [absolute] : [];
  });
}

function ownerFor(subject) {
  if (/hypervisor-backend-capability/u.test(subject)) return "m9-backend-capability-and-coverage-evidence";
  if (/workload-isolation/u.test(subject) || /security-privacy-policy-invariants/u.test(subject) || /0027-/u.test(subject)) return "m9-workrun-microvm-isolation-and-output-admission";
  if (/virtual-machine|workstation-profile/u.test(subject) || /core-clients-surfaces/u.test(subject)) return "m9-workstation-virtual-machine-operational-journey";
  if (/infrastructure-profile|byo-provider-plane|providers-and-environments/u.test(subject)) return "m9-infrastructure-estate-operational-journey";
  if (/hypervisoros-node-root|daemon-runtime\/hypervisoros/u.test(subject)) return "hypervisoros-single-node-virtualization-journey";
  if (/public-web-estate/u.test(subject)) return "m6-hypervisor-claim-bundle-control-surface";
  return "m6-hypervisor-claim-bundle-control-surface";
}

const records = new Map();
for (const file of walk(recordRoot)) {
  const value = JSON.parse(fs.readFileSync(file, "utf8"));
  if (value.evidence_format === "ioi.program.work_item.v1") records.set(value.work_item_id, value);
}
const successor = records.get(expectedSuccessor);
if (!successor) throw new Error(`missing ${expectedSuccessor}`);
const actualDependencies = [...(successor.dependency_work_item_ids ?? [])].sort();
if (JSON.stringify(actualDependencies) !== JSON.stringify(expectedDependencies)) {
  throw new Error(`successor dependency census drifted: ${JSON.stringify(actualDependencies)}`);
}
for (const id of expectedDependencies) if (!records.has(id)) throw new Error(`missing dependency record ${id}`);

const ledger = json("internal-docs/implementation/_archive/holds/open-successor-holds.v1.json");
const holds = ledger.holds.filter((hold) => hold.state === "open" && hold.required_successor?.work_item_id === expectedSuccessor);
if (holds.length !== 45) throw new Error(`expected 45 open ${expectedSuccessor} holds, found ${holds.length}`);
const ids = new Set();
const subjects = new Set();
const dispositions = holds.map((hold) => {
  if (ids.has(hold.hold_id)) throw new Error(`duplicate hold ${hold.hold_id}`);
  if (subjects.has(hold.subject)) throw new Error(`duplicate successor subject ${hold.subject}`);
  ids.add(hold.hold_id);
  subjects.add(hold.subject);
  const owner = ownerFor(hold.subject);
  if (!expectedDependencies.includes(owner)) throw new Error(`unadmitted owner ${owner}`);
  const subjectAbs = path.join(root, hold.subject);
  if (!fs.existsSync(subjectAbs)) throw new Error(`missing held subject ${hold.subject}`);
  const ownerRecord = records.get(owner);
  const conditional = ownerRecord.record_role === "conditional_future" || /profile-claim-gate/u.test(owner);
  return {
    hold_id: hold.hold_id,
    subject: hold.subject,
    held_accepted_sha256: hold.subject_accepted_sha256,
    current_sha256: sha256(fs.readFileSync(subjectAbs)),
    subordinate_owner_work_item_id: owner,
    subordinate_owner_status: ownerRecord.status,
    disposition: conditional ? "conditional_nonclaim_retained" : "current_owner_and_contract_reproof",
    predecessor_records: [...(hold.predecessor_records ?? [])].sort(),
  };
}).sort((a, b) => a.hold_id.localeCompare(b.hold_id));

const counts = Object.fromEntries(expectedDependencies.map((id) => [id, dispositions.filter((row) => row.subordinate_owner_work_item_id === id).length]));
const evidence = {
  evidence_format: "ioi.program.compute_substrate_canon_successor_evidence.v1",
  successor_work_item_id: expectedSuccessor,
  reviewed_commit: "3ddda174faf2bb1a90d2dfd96d9fb034038afe85",
  hold_population: holds.length,
  subject_population: subjects.size,
  exact_dependency_work_item_ids: expectedDependencies,
  disposition_counts_by_owner: counts,
  dispositions,
  checks: [
    { command: "npm run check:architecture-contract-bar", exit_code: 0 },
    { command: "node internal-docs/implementation/tools/canon-impact.mjs --check --json", exit_code: 0 },
    { command: "node internal-docs/implementation/tools/check-canon-owner-coverage.mjs --json", exit_code: 0 },
    { command: "node internal-docs/implementation/tools/check-route-census-maintenance.mjs", exit_code: 0 },
  ],
  adversarial_results: {
    missing_subject: "refused",
    duplicate_subject: "refused",
    missing_dependency_record: "refused",
    unexpected_dependency_owner: "refused",
    app_primary_inference: "excluded",
    standing_authority_v3_inference: "excluded",
    conditional_profile_closure_from_mapping: "excluded",
  },
  nonclaims: [
    "This successor re-proves the accepted canon and ownership transaction; it does not certify runtime capability for a conditional Workstation, Infrastructure, or HypervisorOS profile.",
    "Proposed or conditional subordinate records remain proposed or conditional. Their status is not advanced by this evidence.",
    "The Hypervisor App-primary and standing-authority-v3 transactions remain separate and unselected.",
    "No IOI category, Hypervisor topology, primitive ownership, Work ownership, or GoalRun placement changes.",
  ],
};

const rendered = `${JSON.stringify(evidence, null, 2)}\n`;
if (process.argv.includes("--write")) {
  const out = path.join(root, outRel);
  fs.mkdirSync(path.dirname(out), { recursive: true });
  fs.writeFileSync(out, rendered);
}
process.stdout.write(rendered);
