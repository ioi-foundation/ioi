#!/usr/bin/env node
// Header discipline for internal-docs/architecture/: every .md file there is
// a proposal, synthesis, or private protocol note — never canon. Each must
// declare that in its own header so the directory cannot drift into a shadow
// canon. Standing liaison rule recorded 2026-08-04 alongside the canon-agenda
// ratification; the register set the idiom, this bar keeps it.
//
// The bar, per tracked .md file under internal-docs/architecture/:
//   1. a `Status:` line within the first 15 lines; and
//   2. within the first 25 lines, one line naming canon authority — the line
//      must contain "canonical" together with "win", "only", or "remain"
//      (covers the three existing idioms: "…ADRs win if this document later
//      drifts", "…are canonical; this file is private protocol context only",
//      "…accepted ADRs remain canonical").
//
// A file that cannot honestly carry the header does not belong in the
// directory; move it, do not exempt it. There is deliberately no disposition
// table here.

import { execSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SCOPE = "internal-docs/architecture/";

const files = execSync("git ls-files -- " + SCOPE, { cwd: REPO, maxBuffer: 1e8 })
  .toString().split("\n").filter((p) => p.endsWith(".md"));

const errors = [];
for (const rel of files) {
  const lines = readFileSync(resolve(REPO, rel), "utf8").split("\n");
  const hasStatus = lines.slice(0, 15).some((l) => /^Status:/.test(l));
  const hasAuthority = lines.slice(0, 25).some(
    (l) => /canonical/i.test(l) && /(win|only|remain)/i.test(l),
  );
  if (!hasStatus) {
    errors.push(`${rel}: no "Status:" line in the first 15 lines`);
  }
  if (!hasAuthority) {
    errors.push(
      `${rel}: no canon-authority line in the first 25 lines ` +
        `(needs "canonical" with "win"/"only"/"remain" — owners win on drift)`,
    );
  }
}

for (const e of errors) console.log(`[ERROR] internal-architecture-header: ${e}`);
console.log(
  `internal-architecture headers: ${files.length} file(s) under ${SCOPE}; ${errors.length} violation(s)`,
);
console.log(
  `check-internal-architecture-headers: ${errors.length === 0 ? "PASS" : "FAIL"} (${errors.length} error, 0 warn, 0 skip)`,
);
process.exit(errors.length === 0 ? 0 : 1);
