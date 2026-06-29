#!/usr/bin/env node
// Source-neutrality / IOI-ownership audit (regression gate).
//
// The Hypervisor app must stay IOI-owned: no borrowed upstream brand and no
// "borrowed reference / mirror" framing in the source we author. This blocks
// regressions while cuts 3-6 retire the seeded product-ui bundle.
//
//   BRAND (hard line, everywhere in the app incl. the seed bundle):
//     - zero `gitpod` (any case)
//     - zero word-boundary `ona` (any case)  [the upstream brand, not "additional"]
//   BORROWED LANGUAGE (in the authored lane: scripts/src/docs/*.md/package.json):
//     - zero "live reference"
//     - zero word-boundary "borrowed"
//     - zero word-boundary "mirror"
//
// The seed bundle (apps/hypervisor/product-ui/**) is exempt from the borrowed-language
// check only — it is a temporary shell; cuts 4-6 extract it to source-owned React and
// delete it. Brand stays a hard line even there.
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

// git grep over the working tree's tracked files; exit 1 == "no match" == pass.
function grep(flags, pattern, pathspecs) {
  const ps = [...pathspecs, `:(exclude)${SELF}`].map((p) => `'${p}'`).join(" ");
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
  { name: "'live reference' (authored)", flags: "-i", pattern: "live reference", paths: AUTHORED },
  { name: "borrowed (authored word)", flags: "-iw", pattern: "borrowed", paths: AUTHORED },
  { name: "mirror (authored word)", flags: "-iw", pattern: "mirror", paths: AUTHORED },
];

let failed = false;
for (const c of checks) {
  const lines = grep(c.flags, c.pattern, c.paths).split("\n").filter(Boolean);
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
