#!/usr/bin/env node
// Source-neutrality / IOI-ownership audit (regression gate).
//
// The Hypervisor app must stay IOI-owned: no borrowed upstream brand and no
// "borrowed reference / mirror" framing in durable product source. This blocks
// regressions while preserving explicitly bounded comparison/provenance tools.
//
//   BRAND (hard line, everywhere in the app incl. the seed bundle):
//     - zero `gitpod` (any case), outside the reviewed external wire tokens (ALLOWED_WIRE_TOKENS)
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

// EXTERNAL WIRE TOKENS, the reviewed exclusion list (2026-10-11). A token here is an identifier a
// third party's protocol fixes, which this app must emit or read byte for byte; it is never prose. It
// is stripped from a hit line BEFORE the pattern is re-tested, so a line that also carries the brand
// or framing in prose stays caught. Each entry names its reason. Our own names are never listed here:
// they are renamed instead (the passthrough header became `x-ioi-capture-passthrough`).
const ALLOWED_WIRE_TOKENS = {
  gitpod: [
    // The adopted Sessions SPA's error-message component renders `user_message` only from an error
    // detail of exactly this protobuf type (ioi-api-adapter.mjs emits it; its port test asserts it).
    "gitpod.v1.ActionableErrorDetails",
  ],
};

const checks = [
  { name: "gitpod (brand, app-wide)", flags: "-i", pattern: "gitpod", paths: ["apps/hypervisor"], allowedTokens: ALLOWED_WIRE_TOKENS.gitpod },
  { name: "ona (brand word, app-wide)", flags: "-iw", pattern: "ona", paths: ["apps/hypervisor"] },
  { name: "'live reference' (durable authored)", flags: "-i", pattern: "live reference", paths: AUTHORED, exclusions: COMPARATIVE_PROVENANCE },
  { name: "borrowed (durable authored word)", flags: "-iw", pattern: "borrowed", paths: AUTHORED, exclusions: COMPARATIVE_PROVENANCE },
  { name: "mirror (durable authored word)", flags: "-iw", pattern: "mirror", paths: AUTHORED, exclusions: COMPARATIVE_PROVENANCE },
];

// A hit survives the wire-token list unless the pattern no longer occurs once the listed tokens are
// removed from the line's CONTENT (`path:line:content`, the content being everything after the second colon).
function survivesAllowedTokens(check, hitLine) {
  if (!check.allowedTokens?.length) return true;
  const first = hitLine.indexOf(":");
  const second = hitLine.indexOf(":", first + 1);
  let content = second >= 0 ? hitLine.slice(second + 1) : hitLine;
  for (const token of check.allowedTokens) content = content.split(token).join(" ");
  const word = check.flags.includes("w");
  const escaped = check.pattern.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
  return new RegExp(word ? `(?<![A-Za-z0-9_])${escaped}(?![A-Za-z0-9_])` : escaped, "iu").test(content);
}

let failed = false;
for (const c of checks) {
  const lines = grep(c.flags, c.pattern, c.paths, c.exclusions).split("\n").filter(Boolean)
    .filter((line) => survivesAllowedTokens(c, line));
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
