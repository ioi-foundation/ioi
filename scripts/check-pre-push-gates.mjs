#!/usr/bin/env node
//
// THE PRE-PUSH GATE SWEEP, AS A LIST RATHER THAN AS A MEMORY.
//
// WHY THIS FILE EXISTS, stated plainly because the reason is a repeated mistake and not a
// convenience. Three times in one program leg a pinned population moved and the pin followed one
// commit late — caught by CI rather than before the push — and the cause was the same every time:
// a sweep run from recollection, which was complete for the gates I happened to remember and blind
// to the rest.
//
//   * Two gates pin a ROUTE count and they measure different populations — distinct paths against
//     all registered handlers — so their numbers differ and moving one gives no hint the other
//     needs moving. I ran one.
//   * The ontology census moves on modules, tokens, opaque initialisers, foreign-qualified names
//     AND writer buckets, so adding a helper function and two `const` strings moves it. That is
//     not a change that makes an author think "census". I skipped it.
//   * `check:named-gap-truth` counts absence-worded assertions across ALL verifiers, so AUTHORING
//     A GATE moves it even when no daemon code changed at all.
//
// Three different triggers, none of which announce themselves. The estate's own censuses work
// because they DERIVE their population instead of listing it; this applies the same principle to
// the habit that guards them.
//
// WHAT THIS IS NOT. It is not a replacement for CI, and it deliberately does not run the slow
// live-daemon verifiers — a sweep nobody runs because it takes twenty minutes is worse than a
// short one that is actually run. It covers the gates whose populations move on ORDINARY edits:
// contracts, docs, route counts, censuses and the guide's own structure.
//
//   --fast   skip the two mutation batteries (they restore the tree; they are simply slower)
import { execFileSync } from "node:child_process";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";

const repo = dirname(dirname(fileURLToPath(import.meta.url)));
const fast = process.argv.includes("--fast");

// Each row: [label, command, argv, {battery}] — `battery` marks a gate that plants defects and
// restores the tree, which is slower and skippable with --fast but never skipped by default.
const GATES = [
  ["guide structure", "node", ["scripts/implementation-program.mjs", "--check"]],
  ["release-readiness scope", "node", ["scripts/check-release-readiness-scope.mjs"]],
  ["architecture contracts", "node", ["scripts/generate-architecture-contracts.mjs", "--check"]],
  ["surface records", "node", ["scripts/generate-hypervisor-surface-records.mjs", "--check"]],
  ["architecture docs + work items", "npm", ["run", "check:architecture-docs", "--silent"]],
  // Brings up its OWN debug daemon on a free port and reaps it — never the shared dev daemon. It
  // reads `target/debug/hypervisor-daemon` without building it, so it refuses outright when that
  // binary is older than the sources it claims to measure rather than reporting on code that is
  // not there.
  ["product-surface compiler (M08.8)", "npm", ["run", "check:product-surface-compiler", "--silent"], { slow: true }],
  // ROUTE COUNTS — two gates, two populations. Both, always.
  [
    "route count A (distinct paths)",
    "npm",
    ["run", "check:named-gap-truth", "--workspace=@ioi/hypervisor-app", "--silent"],
    { battery: true },
  ],
  [
    "route count B (registered handlers)",
    "npm",
    ["run", "check:env-lease-authority", "--workspace=@ioi/hypervisor-app", "--silent"],
    { slow: true },
  ],
  // CENSUS — moves on modules, tokens, initialisers, qualified names and writer buckets.
  [
    "ontology admission census",
    "npm",
    ["run", "check:ontology-admission-census", "--workspace=@ioi/hypervisor-app", "--silent"],
  ],
  // The census's own battery. It is listed because it BLOCKS rather than scores when the census is
  // red on the unmutated tree, so a stale census pin fails here as a blocked battery rather than as
  // a mismatched count — a different symptom for the same cause, and one CI reported twice in this
  // leg while the sweep stayed silent. Omitting it was the same recollection failure this file
  // exists to end, committed inside the file itself.
  //
  // RUN IT ALONE. Two mutation batteries against one tree plant and restore against each other:
  // that happened here, produced a phantom "stranded defect", an 18/27 census read mid-plant and a
  // 45/46 anchor score, and none of the three were real — run by itself the same battery scores
  // 46/46. This sweep is sequential for that reason and must stay sequential.
  [
    "admission census battery",
    "npm",
    ["run", "mutate:ontology-admission-census", "--workspace=@ioi/hypervisor-app", "--silent"],
    { battery: true },
  ],
];

const failures = [];
for (const [label, command, argv, options = {}] of GATES) {
  if (fast && options.battery) {
    console.log(`SKIP  ${label}  (--fast: mutation battery)`);
    continue;
  }
  process.stdout.write(`....  ${label}`);
  try {
    execFileSync(command, argv, { cwd: repo, stdio: "pipe" });
    process.stdout.write(`\rPASS  ${label}${" ".repeat(20)}\n`);
  } catch (error) {
    process.stdout.write(`\rFAIL  ${label}${" ".repeat(20)}\n`);
    const output = `${error.stdout ?? ""}${error.stderr ?? ""}`
      .split("\n")
      .filter((line) => /FAIL|pinned|expected|Error/i.test(line))
      .slice(0, 3);
    for (const line of output) console.log(`        ${line.trim().slice(0, 200)}`);
    failures.push(label);
  }
}

console.log(
  `\n${failures.length === 0 ? "PASS" : "FAIL"} pre-push gate sweep — ` +
    `${GATES.length - failures.length}/${GATES.length} gate(s)` +
    (failures.length ? ` · failing: ${failures.join(", ")}` : ""),
);
if (failures.length === 0) {
  console.log(
    "A green sweep is not a green CI. It covers the gates whose populations move on ordinary " +
      "edits; the live-daemon journeys, the library floor and the browser smoke still run there.",
  );
}
process.exit(failures.length === 0 ? 0 : 1);
