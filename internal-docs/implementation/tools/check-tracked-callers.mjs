#!/usr/bin/env node
// Tracked-caller census: every check-* executable has a tracked caller, or an
// explicit disposition saying it deliberately has none.
//
// WHY THIS EXISTS. A bar with no tracked caller is documentation. This program
// filed m0-nonenforcing-check-closure-successor about exactly that class — and
// then recurred on it twice inside one cut: check-attestation-chain.mjs ran by
// hand for three rounds with no caller, and the gate pin that was supposed to
// protect the caller list derived its expectations from that list, so a gate
// redirected to a successful no-op passed.
//
// The point of a census is that an uncalled bar becomes a finding THE DAY IT
// IS BUILT rather than three rounds later, when someone happens to look.
//
// A DISPOSITION IS NOT A WAIVER. Declaring an executable deliberately unwired
// requires a stated reason, and the reason is displayed on every run. The cost
// of leaving something uncalled should be visible, not silent — that is the
// difference between a disposition and an exemption, and this program has
// already learned it once at the anchor chain.

import { execSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { basename, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, "..", "..", "..");

/// Surfaces a caller can legitimately live in. A "caller" is a TRACKED file
/// that names the executable — a wired gate list, an npm script, or CI.
/// Untracked callers do not count: a caller nobody else can see is the
/// invisible-evidence class wearing different clothes.
const CALLER_GLOBS = Object.freeze([
  "package.json",
  ".github/workflows/",
  "scripts/check-pre-next-leg.mjs",
  "scripts/check-pre-next-leg-readiness.mjs",
  "internal-docs/implementation/tools/",
  "scripts/",
]);

/// Deliberately unwired executables, each with the reason displayed on every
/// run. Pinned literal data — never derived from what happens to be uncalled,
/// because a census computed from its subject restates it.
export const UNWIRED_DISPOSITIONS = Object.freeze({
  // STATE ONLY. Each line records what is observable — uncalled as of the
  // census date, owning program named, intent UNKNOWN — and claims nothing
  // about whether the executable is dormant by design. Saying "deliberately
  // dormant" would be asserting an owner's intent nobody has stated on the
  // record; the disposition's job is to say exactly that nobody has.
  "apps/hypervisor/scripts/check-augmentation-tokens.mjs":
    "uncalled as of 2026-08-04; owning program: shell-ownership; intent UNKNOWN; pending owner ruling",
  "apps/hypervisor/scripts/check-source-neutral.mjs":
    "uncalled as of 2026-08-04; owning program: shell-ownership; intent UNKNOWN; pending owner ruling",
  "apps/developers-ioi-ai/scripts/check-live-readiness.mjs":
    "uncalled as of 2026-08-04; owning program: web-estate; intent UNKNOWN; pending owner ruling",
  "apps/developers-ioi-ai/scripts/check-seo-routing.mjs":
    "uncalled as of 2026-08-04; owning program: web-estate; intent UNKNOWN; pending owner ruling",
});

export function evaluate({ executables, callerText, dispositions }) {
  const findings = [];
  let called = 0;
  const uncalled = [];
  for (const exe of executables) {
    const name = basename(exe);
    // A file naming ITSELF is not a caller.
    const namedBySomeoneElse = callerText.some(
      ({ path, text }) => path !== exe && text.includes(name),
    );
    if (namedBySomeoneElse) {
      called += 1;
      continue;
    }
    const disposition = dispositions[exe];
    if (disposition === undefined) {
      findings.push({
        severity: "error",
        message:
          `${exe} has NO tracked caller and no disposition — a bar nobody runs is documentation. ` +
          `Wire it, or declare it deliberately unwired with a reason.`,
      });
      uncalled.push(exe);
    } else {
      findings.push({
        severity: "warn",
        message: `${exe} is deliberately unwired: ${disposition}`,
      });
    }
  }
  return { findings, called, uncalled };
}

function main() {
  const tracked = execSync("git ls-files", { cwd: REPO, maxBuffer: 1e9 })
    .toString().split("\n").filter(Boolean);
  const executables = tracked.filter((p) => /(^|\/)check-[a-z0-9-]+\.mjs$/.test(p));
  // THE CENSUS'S OWN FILE IS NOT A CALLER SURFACE. Its disposition table names
  // every deliberately-unwired executable, so counting it would make listing a
  // file as unwired the very thing that marks it called — the dispositions
  // would silently stop printing and the count would read 0 unwired. Caught on
  // the first run after wiring: 61/61 called, 0 warn. A registry is not a
  // caller, and a census that vouches for its own subjects restates itself.
  const SELF = "internal-docs/implementation/tools/check-tracked-callers.mjs";
  const callerText = tracked
    .filter((p) => p !== SELF)
    .filter((p) => CALLER_GLOBS.some((glob) => p.startsWith(glob) || p === glob))
    .filter((p) => existsSync(resolve(REPO, p)))
    .map((p) => ({ path: p, text: readFileSync(resolve(REPO, p), "utf8") }));

  const { findings, called, uncalled } = evaluate({
    executables,
    callerText,
    dispositions: UNWIRED_DISPOSITIONS,
  });

  for (const f of findings) console.log(`[${f.severity.toUpperCase()}] tracked-caller: ${f.message}`);
  const errors = findings.filter((f) => f.severity === "error");
  console.log(
    `tracked-caller census: ${executables.length} check-* executable(s); ${called} with a tracked caller; ` +
      `${uncalled.length} uncalled and undispositioned; ${Object.keys(UNWIRED_DISPOSITIONS).length} deliberately unwired`,
  );
  console.log(
    `check-tracked-callers: ${errors.length === 0 ? "PASS" : "FAIL"} (${errors.length} error, ${findings.length - errors.length} warn, 0 skip)`,
  );
  process.exit(errors.length === 0 ? 0 : 1);
}

if (import.meta.url === `file://${process.argv[1]}`) main();
