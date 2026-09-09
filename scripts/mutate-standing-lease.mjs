#!/usr/bin/env node
// Source-mutation drill for the standing-lease units (M03.10 template bounds, M03.11 draw-down
// metering, M03.12 lifecycle). Each mutation plants one defect in production source — a bound
// check disabled, a divergence check skipped, a revoke that leaves the lease active, a
// projection that stops subtracting — then runs the unit's population check and requires it to
// go RED. The original bytes are restored from a backup in every exit path; a backup left by a
// killed run is restored first, so a planted defect cannot outlive the drill.
//
//   node scripts/mutate-standing-lease.mjs --unit standing-envelope-template
//   node scripts/mutate-standing-lease.mjs --unit standing-drawdown-metering
//   node scripts/mutate-standing-lease.mjs --unit standing-lease-lifecycle

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const unit = process.argv[process.argv.indexOf("--unit") + 1];
const HANDLER = "crates/services/src/wallet_network/handlers/standing_authority.rs";
const GOVERNED = "crates/node/src/bin/hypervisor_daemon_routes/governed_authority.rs";
const PROVIDER = "crates/node/src/bin/hypervisor_daemon_routes/provider_routes.rs";
const LEASE = "crates/services/src/agentic/runtime/policy_lease.rs";
const ONTOLOGY = "crates/node/src/bin/hypervisor_daemon_routes/ontology_action_contract_routes.rs";

const MUTATIONS = {
  "standing-envelope-template": [
    { label: "the max_usages template bound is disabled in the live gate", file: GOVERNED, find: "    if grant.max_usages > bounds.max_usages {\n        return Err(\"max_usages\");\n    }\n", replace: "    // planted: usage bound disabled\n" },
    { label: "the per-operation deposit facet bound is disabled at the provider route", file: PROVIDER, find: "        return Err(\"standing_deposit_outside_envelope\".to_string());\n", replace: "        // planted: deposit bound disabled\n" },
    { label: "the standing grant ABI accepts an exact request_hash field", file: GOVERNED, find: "    \"auth_factor_receipt_hash\",\n    \"approver_public_key\",\n    \"approver_sig\",\n    \"approver_suite\",\n];", replace: "    \"auth_factor_receipt_hash\",\n    \"approver_public_key\",\n    \"approver_sig\",\n    \"approver_suite\",\n    \"request_hash\",\n];" },
  ],
  "standing-drawdown-metering": [
    { label: "the cumulative spend ceiling is disabled in the wallet draw", file: HANDLER, find: "    if next_spend > grant_state.grant.max_cumulative_spend_microusd {\n", replace: "    if false && next_spend > grant_state.grant.max_cumulative_spend_microusd {\n" },
    { label: "the journal re-derivation is skipped (a rotted counter authorises)", file: HANDLER, find: "    if derived\n        != (StandingApprovalLedgerTotals {", replace: "    if false && derived\n        != (StandingApprovalLedgerTotals {" },
    { label: "a refused draw still appends to the journal (double accounting)", file: HANDLER, find: "    journal.consumption_ids.push(params.consumption_id);\n", replace: "    journal.consumption_ids.push(params.consumption_id);\n    journal.consumption_ids.push(params.consumption_id);\n" },
  ],
  "typed-effect-recovery": [
    { label: "the recovery class defaults instead of refusing an undeclared effect", file: GOVERNED, find: "            _ => Err(\n                \"this action declares no recovery class", replace: "            _ => Ok(Self::Replayable), #[allow(unreachable_patterns)] None => Err(\n                \"this action declares no recovery class" },
    { label: "ambiguity stops blocking the retry of a reconciliation_required effect", file: GOVERNED, find: "    if prior == FinalInvocationDisposition::ReconciliationRequired && !reconciled {", replace: "    if false && prior == FinalInvocationDisposition::ReconciliationRequired && !reconciled {" },
    { label: "a restore satisfies reconciliation (any source counts)", file: GOVERNED, find: "                .is_some_and(|source| source == \"external_system_readback\")", replace: "                .is_some_and(|source| !source.is_empty())" },
    { label: "RESTART: an orphaned claim from a dead incarnation is re-granted instead of reconciled", file: GOVERNED, find: "            } else {\n                ClaimTransition::ReconcileOrphanedClaim\n            }", replace: "            } else {\n                ClaimTransition::Grant\n            }" },
    { label: "NO SECOND SPINE: the frozen canonical member set is widened on one side only", file: ONTOLOGY, find: "pub(crate) const EFFECT_RECOVERY_CLASSES: &[&str] = &[\n    \"replayable\",", replace: "pub(crate) const EFFECT_RECOVERY_CLASSES: &[&str] = &[\n    \"best_effort\",\n    \"replayable\"," },
    { label: "the declared class stops narrowing the claim (the module becomes uncalled)", file: GOVERNED, find: "    let base = evaluate_claim_transition_substrate(disposition, record, incarnation_id);\n    if !matches!(base, ClaimTransition::Grant) {\n        return base;\n    }", replace: "    return evaluate_claim_transition_substrate(disposition, record, incarnation_id);\n    #[allow(unreachable_code)]\n    let base = evaluate_claim_transition_substrate(disposition, record, incarnation_id);\n    #[allow(unreachable_code)]\n    if !matches!(base, ClaimTransition::Grant) {\n        return base;\n    }" },
  ],
  "standing-lease-lifecycle": [
    { label: "revoke leaves the lease Active", file: HANDLER, find: "    record.status = StandingApprovalGrantStatus::Revoked;\n", replace: "    record.status = StandingApprovalGrantStatus::Active;\n" },
    { label: "the projection reports the full usage allowance after draws (widening on render)", file: LEASE, find: "            remaining_usages: grant.max_usages.saturating_sub(state.uses_consumed),\n", replace: "            remaining_usages: grant.max_usages,\n" },
    { label: "a byte-identical record replay resets the counters", file: HANDLER, find: "            && existing.auth_factor_receipt_json == auth_factor_receipt_json\n        {\n            return Ok(());\n        }", replace: "            && existing.auth_factor_receipt_json == auth_factor_receipt_json\n        {\n            let mut reset = existing.clone();\n            reset.uses_consumed = 0;\n            reset.cumulative_spend_reserved_microusd = 0;\n            reset.cumulative_deposit_reserved_microusd = 0;\n            state.insert(&key, &ioi_types::codec::to_bytes_canonical(&reset)?)?;\n            return Ok(());\n        }" },
  ],
};

if (!MUTATIONS[unit]) {
  console.error(`usage: --unit <${Object.keys(MUTATIONS).join("|")}>`);
  process.exit(2);
}

const backupDir = path.join(ROOT, ".artifacts", "mutate-standing-lease");
fs.mkdirSync(backupDir, { recursive: true });
const backupPath = (file) => path.join(backupDir, `${file.replaceAll("/", "__")}.orig`);

// A backup left behind by a killed drill is a planted defect still in the tree: restore first.
for (const name of fs.readdirSync(backupDir)) {
  if (!name.endsWith(".orig")) continue;
  const file = name.slice(0, -".orig".length).replaceAll("__", "/");
  fs.copyFileSync(path.join(backupDir, name), path.join(ROOT, file));
  fs.rmSync(path.join(backupDir, name));
  console.log(`restored ${file} from a previous drill's backup`);
}

if (process.argv.includes("--check-anchors")) {
  // Fast, mutation-free: every planted defect's anchor must still exist in source, otherwise the
  // drill has silently stopped drilling (a reformat or refactor moved the bytes it aims at).
  let missing = 0;
  for (const m of MUTATIONS[unit]) {
    const present = fs.readFileSync(path.join(ROOT, m.file), "utf8").includes(m.find);
    if (!present) missing += 1;
    console.log(`${present ? "PASS" : "FAIL"} anchor for "${m.label}" in ${m.file}`);
  }
  process.exit(missing === 0 ? 0 : 1);
}

const population = `scripts/test-populations/${unit}.v1.json`;
let allOk = true;
const check = () => spawnSync(process.execPath, ["scripts/check-cargo-test-population.mjs", "--population", population], { cwd: ROOT, encoding: "utf8", maxBuffer: 256 * 1024 * 1024 });

// The drill is only meaningful over a green baseline.
const baseline = check();
if (baseline.status !== 0) {
  console.log(`FAIL baseline ${population} is not green; a drill over a red check proves nothing\n${baseline.stdout.split("\n").filter((l) => l.startsWith("FAIL")).join("\n")}`);
  process.exit(1);
}
console.log(`PASS baseline ${population} is green`);

for (const m of MUTATIONS[unit]) {
  const target = path.join(ROOT, m.file);
  const original = fs.readFileSync(target, "utf8");
  if (!original.includes(m.find)) {
    allOk = false;
    console.log(`FAIL mutation "${m.label}": anchor not found in ${m.file} (re-aim the drill)`);
    continue;
  }
  fs.writeFileSync(backupPath(m.file), original);
  const restore = () => {
    try { fs.writeFileSync(target, original); fs.rmSync(backupPath(m.file), { force: true }); } catch { /* best effort */ }
  };
  const onSignal = () => { restore(); process.exit(130); };
  process.once("SIGINT", onSignal);
  process.once("SIGTERM", onSignal);
  try {
    fs.writeFileSync(target, original.replace(m.find, m.replace));
    const out = check();
    const red = out.status !== 0;
    const failing = out.stdout.split("\n").filter((l) => l.startsWith("FAIL")).map((l) => l.slice(0, 160));
    allOk &= red;
    console.log(`${red ? "PASS" : "FAIL"} mutation "${m.label}" → ${red ? "RED as required" : "still GREEN (the check cannot see this defect)"}${failing.length ? `\n  ${failing.join("\n  ")}` : ""}`);
  } finally {
    restore();
    if (fs.readFileSync(target, "utf8") !== original) {
      allOk = false;
      console.log(`FAIL restore of ${m.file} did not reproduce the original bytes`);
    }
    process.off("SIGINT", onSignal);
    process.off("SIGTERM", onSignal);
  }
}
const leftovers = fs.readdirSync(backupDir).filter((n) => n.endsWith(".orig"));
allOk &= leftovers.length === 0;
console.log(`${leftovers.length === 0 ? "PASS" : "FAIL"} restore: every mutated file was written back from its backup (${leftovers.length} backup(s) remain)`);
console.log(`${allOk ? "PASS" : "FAIL"} mutate:${unit}: ${MUTATIONS[unit].length} planted defects`);
process.exit(allOk ? 0 : 1);
