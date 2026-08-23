#!/usr/bin/env node
// Source-neutrality / IOI-ownership audit (regression gate).
//
// The Hypervisor app must stay IOI-owned: no borrowed upstream brand and no
// "borrowed reference / mirror" framing in durable product source. This blocks
// regressions while preserving explicitly bounded comparison/provenance tools.
//
//   BRAND (hard line, everywhere in the app incl. the seed bundle):
//     - zero `gitpod` (any case)
//     - zero word-boundary `ona` (any case)  [the upstream brand, not "additional"]
//   BORROWED LANGUAGE (in the authored lane: scripts/src/docs/*.md/package.json):
//     - zero "live reference"
//     - zero word-boundary "borrowed"
//     - zero word-boundary "mirror"
//
// Replaceable comparison/provenance harnesses are exempt from the framing-word
// check only. The ported product seed is not temporary and is never exempt from
// the brand line.
//
// Run: npm run check:source-neutral --workspace=@ioi/hypervisor-app
import { execSync } from "node:child_process";

const ROOT = execSync("git rev-parse --show-toplevel").toString().trim();
const SELF = "apps/hypervisor/scripts/check-source-neutral.mjs";
const AUTHORED = [
  "apps/hypervisor/scripts",
  "apps/hypervisor/src",
  "apps/hypervisor/docs",
  "apps/hypervisor/*.md",
  "apps/hypervisor/package.json",
];
const COMPARATIVE_PROVENANCE = [
  "apps/hypervisor/scripts/build-app-parity-matrix.mjs",
  "apps/hypervisor/scripts/harness-reference-clean-sweep.mjs",
  "apps/hypervisor/scripts/harness-reference-parity.mjs",
  "apps/hypervisor/scripts/pipeline-reference-atlas.mjs",
  "apps/hypervisor/scripts/reharvest-pipeline-builder.mjs",
  "apps/hypervisor/scripts/record-live-tenant-atlas.mjs",
  "apps/hypervisor/scripts/record-reference-subroute-census.mjs",
  "apps/hypervisor/scripts/verify-hypervisor-app-parity-domain-landings.mjs",
  "apps/hypervisor/scripts/verify-hypervisor-app-parity-foundry-models.mjs",
  "apps/hypervisor/scripts/verify-hypervisor-app-parity-pipeline.mjs",
  "apps/hypervisor/scripts/verify-hypervisor-pipeline-interaction.mjs",
  "apps/hypervisor/scripts/verify-hypervisor-reference-clean-sweep.mjs",
  "apps/hypervisor/scripts/verify-hypervisor-reference-parity-reset.mjs",
  "apps/hypervisor/scripts/verify-pipeline-reference-data-clean.mjs",
  "apps/hypervisor/scripts/verify-pipeline-stub-detector.mjs",
];

// git grep over the working tree's tracked files; exit 1 == "no match" == pass.
function grep(flags, pattern, pathspecs, exclusions = []) {
  const ps = [
    ...pathspecs,
    `:(exclude)${SELF}`,
    ...exclusions.map((entry) => `:(exclude)${entry}`),
  ].map((p) => `'${p}'`).join(" ");
  try {
    // --untracked: also scan new, not-yet-committed files (e.g. freshly extracted surfaces)
    // so the gate catches regressions before they are committed, not only tracked content.
    return execSync(`git -C ${ROOT} grep --untracked -nI ${flags} -e '${pattern}' -- ${ps}`, { encoding: "utf8" });
  } catch (e) {
    if (e.status === 1) return ""; // no match
    throw e;
  }
}

const checks = [
  { name: "gitpod (brand, app-wide)", flags: "-i", pattern: "gitpod", paths: ["apps/hypervisor"] },
  { name: "ona (brand word, app-wide)", flags: "-iw", pattern: "ona", paths: ["apps/hypervisor"] },
  { name: "'live reference' (durable authored)", flags: "-i", pattern: "live reference", paths: AUTHORED, exclusions: COMPARATIVE_PROVENANCE },
  { name: "borrowed (durable authored word)", flags: "-iw", pattern: "borrowed", paths: AUTHORED, exclusions: COMPARATIVE_PROVENANCE },
  { name: "mirror (durable authored word)", flags: "-iw", pattern: "mirror", paths: AUTHORED, exclusions: COMPARATIVE_PROVENANCE },
];

let failed = false;
for (const c of checks) {
  const lines = grep(c.flags, c.pattern, c.paths, c.exclusions).split("\n").filter(Boolean);
  if (lines.length) {
    failed = true;
    console.error(`✗ ${c.name}: ${lines.length} hit(s)`);
    for (const l of lines.slice(0, 12)) console.error("    " + l);
    if (lines.length > 12) console.error(`    … +${lines.length - 12} more`);
  } else {
    console.log(`✓ ${c.name}: clean`);
  }
}

if (failed) {
  console.error("\nsource-neutrality audit FAILED — keep the app IOI-owned (no borrowed brand/framing).");
  process.exit(1);
}
console.log("\nsource-neutrality audit PASSED — the app is IOI-owned at the source/brand layer.");
