#!/usr/bin/env node
// Rebuild one private aggregate record's exact child/dependency/evidence join.
//
//   node tools/refresh-aggregate-verification-binding.mjs <work-item-id>
//   node tools/refresh-aggregate-verification-binding.mjs <work-item-id> --apply
//
// This command changes no status and promotes no proof. It is the explicit
// tool-owned replacement for hand-editing aggregate_verification_binding after
// a child transition or after new aggregate evidence is retained.
import path from "node:path";
import process from "node:process";
import fs from "node:fs";
import {
  ESTATE_ROOT,
  finding,
  readJson,
  report,
  writeJsonDeterministic,
} from "./lib/estate.mjs";
import {
  blockingAggregateBindingRefreshRefusals,
  deriveAggregateVerificationBinding,
  validateAggregateVerificationBinding,
} from "./lib/aggregate-verification-binding.mjs";
import { loadWorkItems, statusAuthority } from "./generate-now.mjs";

function main() {
  const workItemId = process.argv.slice(2).find((arg) => !arg.startsWith("-"));
  const apply = process.argv.includes("--apply");
  if (!workItemId) {
    process.stderr.write(
      "usage: refresh-aggregate-verification-binding.mjs <work-item-id> [--apply]\n",
    );
    process.exit(2);
  }

  const findings = [];
  const records = loadWorkItems();
  const aggregate = records.find((record) => record.work_item_id === workItemId);
  if (!aggregate) {
    findings.push(finding("error", "aggregate-binding-record", `unknown work item: ${workItemId}`));
  } else if (aggregate.record_role !== "aggregate_exit") {
    findings.push(finding(
      "error",
      "aggregate-binding-role",
      `${workItemId} is ${aggregate.record_role}, not aggregate_exit`,
    ));
  } else {
    const authority = statusAuthority(aggregate);
    if (authority.owner !== "private_record") {
      findings.push(finding(
        "error",
        "aggregate-binding-authority",
        `${workItemId} is owned by ${authority.ref}; this private refresher cannot mutate it`,
      ));
    }
    if (authority.status === "verified" && apply) {
      findings.push(finding(
        "error",
        "aggregate-binding-verified",
        `${workItemId} is already verified; refreshing its historical binding in place would rewrite an admitted closure`,
      ));
    }
  }
  if (findings.some((entry) => entry.level === "error")) {
    process.exit(report("refresh-aggregate-verification-binding", findings));
  }

  const derived = deriveAggregateVerificationBinding(aggregate, { records });
  const childValidity = derived.child_bindings.map((binding) =>
    `${binding.work_item_id}:${binding.status_at_binding}/${binding.evidence_binding.literal_valid ? "literal-valid" : "literal-invalid"}`
  ).join(", ");
  const ownValidity = derived.aggregate_evidence_binding.literal_valid
    ? "literal-valid"
    : "literal-invalid";
  const bindingCurrent = JSON.stringify(aggregate.aggregate_verification_binding) ===
    JSON.stringify(derived);

  if (!apply) {
    if (aggregate.status === "verified") {
      for (const refusal of validateAggregateVerificationBinding(aggregate, {
        records,
      })) {
        findings.push(finding("error", refusal.check, refusal.message));
      }
    }
    process.stdout.write(
      `${workItemId}: binding ${bindingCurrent ? "current" : "would refresh"} at ${derived.binding_payload_sha256}; children [${childValidity}]; aggregate ${ownValidity}; status unchanged (${aggregate.status})\n`,
    );
    process.exit(report("refresh-aggregate-verification-binding", findings));
  }

  const absolute = path.join(ESTATE_ROOT, aggregate.file);
  const originalBytes = fs.readFileSync(absolute);
  const full = readJson(absolute);
  full.aggregate_verification_binding = derived;
  try {
    writeJsonDeterministic(absolute, full);
    const refreshedRecords = loadWorkItems();
    const refreshed = refreshedRecords.find((record) => record.work_item_id === workItemId);
    const refusals = blockingAggregateBindingRefreshRefusals(
      statusAuthority(refreshed).status,
      validateAggregateVerificationBinding(refreshed, {
        records: refreshedRecords,
      }),
    );
    for (const refusal of refusals) {
      findings.push(finding("error", refusal.check, refusal.message));
    }
  } catch (error) {
    findings.push(finding(
      "error",
      "aggregate-binding-refresh",
      `${workItemId} refresh failed validation: ${error.message}`,
    ));
  }
  if (findings.some((entry) => entry.level === "error")) {
    fs.writeFileSync(absolute, originalBytes);
    process.exit(report("refresh-aggregate-verification-binding", findings));
  }

  process.stdout.write(
    `${workItemId}: refreshed binding ${derived.binding_payload_sha256}; children [${childValidity}]; aggregate ${ownValidity}; status unchanged (${aggregate.status}); no proof promoted\n`,
  );
  process.exit(report("refresh-aggregate-verification-binding", findings));
}

main();
