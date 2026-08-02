#!/usr/bin/env node

// The approved reconciliation is permanently finalized. The byte-identical,
// replay-capable implementation is retained only under _archive for audit.
// This live path is deliberately read-only and can only verify that seal.

import process from "node:process";
import {
  printWorkItemMigrationFinalizationResult,
  validateWorkItemMigrationFinalization,
} from "./check-work-item-migration-finalization.mjs";

const argument = process.argv[2];
if (process.argv.length === 3 && argument === "--check-finalization") {
  printWorkItemMigrationFinalizationResult(validateWorkItemMigrationFinalization());
} else if (argument === "--replay-approved-transaction") {
  process.stderr.write(
    "work-item migration permanently refused: the approved one-time reconciliation is finalized; the archived replay-capable bytes are audit evidence only\n",
  );
  process.exit(1);
} else {
  process.stderr.write(
    "usage: migrate-work-items.mjs --check-finalization\n"
    + "replay is permanently refused at the live path\n",
  );
  process.exit(2);
}
