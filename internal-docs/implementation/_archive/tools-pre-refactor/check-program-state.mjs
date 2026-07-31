#!/usr/bin/env node

// Stable compatibility entry point required by the sole master guide. The
// implementation lives with the other private tools; this wrapper is read-only
// and cannot change status or close a stage.

import process from "node:process";
import { checkProgramState } from "./tools/generate-program-state.mjs";

if (process.argv.length !== 2) {
  process.stderr.write("program-state check failed: this stable wrapper accepts no arguments\n");
  process.exit(1);
}

try {
  const state = checkProgramState();
  process.stdout.write(
    `program-state compatibility check passed: ${state.status_integrity.total_record_count} records, ${state.stages.length} stages, M0 evidence ${state.evidence_validation.m0.result}. The projection emitted no status transaction, literal exit, or stage-close artifact.\n`,
  );
} catch (error) {
  process.stderr.write(`program-state compatibility check failed: ${error.message}\n`);
  process.exit(1);
}
