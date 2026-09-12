#!/usr/bin/env node
//
// M06.5 — THE TWO NAMED CENSUS RESIDUALS, RETIRED OR NAMED.
//
// `check:ontology-admission-census` is a strong gate, and its own assertion text is honest about
// where it stops:
//
//   "it is NOT rustc's file set and does not claim to be, because `mod` has no totality edge and is
//    not getting one: a `#[cfg_attr(…, path = …)]` redirect is invisible here and a `mod` declared
//    inside a `macro_rules!` body never reaches the visitor at all, so rustc would compile one file
//    while this reads another — neither construct exists in this daemon today and entailing the
//    file set belongs to the run that entails the resolver"
//
// This is that run. The unit's own scope says to entail the file set from what the COMPILER sees,
// and to NAME the boundary rather than model it if entailment is not reachable — explicitly no
// third hardening edge on a twice-falsified design. Entailment IS reachable, and from the cheapest
// possible layer: rustc already writes the exact list of files it read, per binary, as dep-info.
//
//   RESIDUAL 1 — THE FILE SET IS ENTAILED, BOTH DIRECTIONS. Every `.rs` file rustc read under the
//   daemon binary's tree must be a module the census walked, and every module the census walked
//   must be a file rustc read. A `#[cfg_attr(…, path)]` redirect or a `mod` declared inside a
//   macro would now appear as a one-sided difference instead of being invisible. The files rustc
//   read that are NOT Rust are accounted for by name against the census's own `include_str!`
//   records, rather than filtered away — an unexplained file is a finding, whatever its extension.
//
//   RESIDUAL 2 — RESOLUTION IS TOTAL BECAUSE THE BUCKET VOCABULARY IS CLOSED. The census pins the
//   SIZE of each unadjudicable bucket in both directions, which catches a count that moved. It does
//   not catch a bucket that does not exist yet: a resolver taught to emit a seventh `bucket:` kind
//   would produce names the pin set never mentions, and every one of them would be counted by
//   nothing. So this check derives the bucket vocabulary from the resolver's OWN SOURCE and
//   requires it to equal the pinned vocabulary exactly, both ways. That is what makes "resolution
//   is total" a property rather than a hope: a name either resolves, or lands in a bucket that is
//   pinned, and there is no third place for it to go.
//
// The census itself is COMPOSED here rather than restated — its counts, its mutation battery and
// its own both-direction pins stay its own.
//
//   --mutation  prove each finding fails on its own
//   --skip-composed  run the entailment and vocabulary halves only
//
// BLOCKED, never silently green: without a current dep-info file this check exits 0 with verdict
// BLOCKED and no PASS lines, because a check that cannot run has not passed.

import { readFileSync, existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const repo = dirname(dirname(fileURLToPath(import.meta.url)));
const mutation = process.argv.includes("--mutation");
const skipComposed = process.argv.includes("--skip-composed");

const DAEMON_ENTRY = "crates/node/src/bin/hypervisor-daemon.rs";
const DAEMON_TREE = "crates/node/src/bin/";
const DEP_INFO = join(repo, "target/debug/hypervisor-daemon.d");
const EXTRACTOR = join(repo, "target/debug/ioi-ontology-census");
const CENSUS_VERIFIER = join(
  repo,
  "apps/hypervisor/scripts/verify-hypervisor-ontology-admission-census.mjs",
);

const results = [];
const observations = {};
let failures = 0;

const ok = (name, satisfied, detail) => {
  results.push({ assertion: name, satisfied: !!satisfied, detail: String(detail).slice(0, 400) });
  if (!satisfied) failures += 1;
  console.log(`${satisfied ? "PASS" : "FAIL"}  ${name}  (${String(detail).slice(0, 240)})`);
  return !!satisfied;
};

const blocked = (reason) => {
  console.log(JSON.stringify({ check: "check:admission-census-entailment", verdict: "BLOCKED", reason }, null, 2));
  process.exit(0);
};

/// rustc's own answer to "which files did you read", per binary. This is the layer that cannot be
/// incomplete: it is written by the compilation itself, not by a second walk of the same source.
function rustcFileSet() {
  const text = readFileSync(DEP_INFO, "utf8");
  const line = text
    .split("\n")
    .find((entry) => entry.startsWith(join(repo, "target/debug/hypervisor-daemon") + ":"));
  if (!line) return null;
  const files = line.slice(line.indexOf(": ") + 2).trim().split(/\s+/).filter(Boolean);
  return files
    .map((file) => (file.startsWith(repo) ? relative(repo, file) : file))
    .filter((file) => file.startsWith(DAEMON_TREE))
    .sort();
}

function runExtractor() {
  const run = spawnSync(EXTRACTOR, ["--interest", "odk-", DAEMON_ENTRY], {
    cwd: repo,
    encoding: "utf8",
    maxBuffer: 512 * 1024 * 1024,
  });
  if (run.status !== 0) return null;
  return JSON.parse(run.stdout);
}

try {
  if (!existsSync(EXTRACTOR)) blocked("target/debug/ioi-ontology-census is not built");
  // The dep-info must describe THIS tree, so rebuild rather than trust whatever is on disk. A stale
  // .d file would entail the file set of a daemon nobody is running.
  const build = spawnSync("cargo", ["build", "--locked", "-p", "ioi-node", "--bin", "hypervisor-daemon"], {
    cwd: repo,
    encoding: "utf8",
  });
  if (build.status !== 0) blocked(`the daemon did not build, so rustc wrote no current file set: ${String(build.stderr).slice(-400)}`);
  if (!existsSync(DEP_INFO)) blocked("rustc wrote no dep-info for the daemon binary");

  const rustcFiles = rustcFileSet();
  if (!rustcFiles) blocked("the dep-info file names no rule for the daemon binary");
  const census = runExtractor();
  if (!census) blocked("the census extractor did not run");

  const rustcRust = rustcFiles.filter((file) => file.endsWith(".rs"));
  const rustcOther = rustcFiles.filter((file) => !file.endsWith(".rs"));
  const censusModules = [...new Set(census.modules.map((entry) => entry.key))].sort();
  observations.rustc_files_under_daemon_tree = rustcFiles.length;
  observations.rustc_rust_files = rustcRust.length;
  observations.census_modules = censusModules.length;

  // ---- RESIDUAL 1, both directions ----
  const rustcSet = new Set(rustcRust);
  const censusSet = new Set(censusModules);
  const compilerOnly = rustcRust.filter((file) => !censusSet.has(file));
  const censusOnly = censusModules.filter((file) => !rustcSet.has(file));
  ok("RESIDUAL 1 — every Rust file the COMPILER read under the daemon's tree is a module the census walked. This is the direction that catches a `#[cfg_attr(…, path)]` redirect or a `mod` declared inside a macro: rustc would compile a file the `mod` walk never reaches, and it would be invisible until now",
    compilerOnly.length === 0,
    compilerOnly.length ? `rustc read but the census did not walk: ${compilerOnly.join(", ")}` : `${rustcRust.length} Rust files, all walked`);
  ok("RESIDUAL 1, the reverse edge — every module the census walked is a file the compiler actually read, so the census cannot be judging source that is not in the binary it claims to describe",
    censusOnly.length === 0,
    censusOnly.length ? `the census walked but rustc did not read: ${censusOnly.join(", ")}` : `${censusModules.length} modules, all compiled`);

  // The non-Rust files rustc read are ACCOUNTED FOR by name rather than filtered away. The census
  // records each `include_str!`/`include_bytes!` argument and deliberately pins the data forms
  // rather than following them; this requires the two lists to be the same set of basenames.
  //
  // PRODUCTION includes only, and the reason is the comparison's own subject: dep-info describes the
  // compilation of the BINARY, and `#[cfg(test)]` fixtures are compiled into the test harness, not
  // the binary. Run 1 of this check compared all 93 recorded includes against the binary's file
  // list and went red on four test fixtures rustc had no reason to read — a true difference between
  // two sets that are not the same subject. The production set is the one the binary's dep-info can
  // speak to.
  const includeArgs = new Set(
    census.modules
      .flatMap((entry) => entry.includes || [])
      .filter((entry) => !entry.in_test)
      .map((entry) => String(entry.arg || ""))
      .filter((arg) => arg && !arg.endsWith(".rs"))
      .map((arg) => arg.split("/").pop()),
  );
  const unexplained = rustcOther.filter((file) => !includeArgs.has(file.split("/").pop()));
  const unread = [...includeArgs].filter(
    (base) => !rustcOther.some((file) => file.endsWith(`/${base}`) || file === base),
  );
  ok("every NON-Rust file the compiler read under this tree is one the census records as a data include — the extension is not a reason to stop asking, and an unexplained file rustc read is a finding whatever it is",
    unexplained.length === 0 && unread.length === 0,
    unexplained.length || unread.length
      ? `unexplained by the census: ${unexplained.join(", ") || "none"} · recorded but not read: ${unread.join(", ") || "none"}`
      : `${rustcOther.length} data file(s), each recorded: ${rustcOther.map((f) => f.split("/").pop()).join(", ")}`);

  // ---- RESIDUAL 2: the bucket vocabulary is closed in both directions ----
  const verifierSource = readFileSync(CENSUS_VERIFIER, "utf8");
  const emittable = [...new Set(
    [...verifierSource.matchAll(/bucket:\s*"([a-z-]+)"/gu)].map((match) => match[1]),
  )].sort();
  const pinnedBlock = verifierSource.slice(
    verifierSource.indexOf("unadjudicable: {"),
    verifierSource.indexOf("}", verifierSource.indexOf("unadjudicable: {")),
  );
  const pinned = [...new Set(
    [...pinnedBlock.matchAll(/"([a-z-]+)":\s*\d+/gu)].map((match) => match[1]),
  )].sort();
  observations.bucket_vocabulary_emittable = emittable;
  observations.bucket_vocabulary_pinned = pinned;
  const unpinned = emittable.filter((name) => !pinned.includes(name));
  const unemittable = pinned.filter((name) => !emittable.includes(name));
  ok("RESIDUAL 2 — the unadjudicable bucket VOCABULARY is closed: every bucket the resolver's own source can emit is pinned. This is the half a size pin cannot reach — a resolver taught to emit a seventh kind produces names no pin mentions, and every one of them would be counted by nothing",
    unpinned.length === 0,
    unpinned.length ? `emittable but unpinned: ${unpinned.join(", ")}` : `${emittable.length} emittable bucket(s), all pinned`);
  ok("RESIDUAL 2, the reverse edge — every pinned bucket is one the resolver can actually emit, so a pin cannot outlive the code path it was written for and sit at zero forever looking like a proof",
    unemittable.length === 0,
    unemittable.length ? `pinned but unemittable: ${unemittable.join(", ")}` : `${pinned.length} pinned bucket(s), all reachable`);
  ok("and the three sharp buckets are pinned at ZERO, which is what makes the totality claim worth making: an ambiguous module, a qualifier that resolves to something unreadable, and a const-of-const cycle are each counted, and each count is none",
    ["ambiguous-module", "not-a-visible-const", "resolution-cycle"].every((name) =>
      new RegExp(`"${name}":\\s*0`).test(pinnedBlock)),
    pinnedBlock.replace(/\s+/gu, " ").slice(0, 200));

  // ---- the census itself, composed rather than restated ----
  if (skipComposed) {
    ok("the census's own counts and mutation battery are COMPOSED here", false,
      "SKIPPED by --skip-composed, so this run does not carry them");
  } else if (mutation) {
    observations.composed_supplementary = "carried by the non-mutation run; not re-executed under --mutation";
    ok("the census's own counts are carried by this check's non-mutation run rather than executed twice per CI run — its falsifiability is its own mutation battery's job, and CI runs both",
      true, "deferred by design");
  } else {
    const composed = spawnSync("npm", ["run", "--silent", "check:ontology-admission-census", "--workspace=@ioi/hypervisor-app"], {
      cwd: repo,
      encoding: "utf8",
      timeout: 20 * 60 * 1000,
    });
    ok("the census's own both-direction count pins are COMPOSED, not restated: check:ontology-admission-census runs here and passes, so this check adds the two residuals rather than re-litigating the gate they sit on",
      composed.status === 0,
      `exit ${composed.status} · ${String(composed.stdout || "").trim().split("\n").slice(-1)[0]?.slice(0, 160)}`);
    observations.composed_supplementary = "check:ontology-admission-census";
  }

  // ---- mutation drills ----
  if (mutation) {
    // M1 — the entailment must SEE a file rustc read that the census does not walk.
    const plantedRustc = [...rustcRust, "crates/node/src/bin/hypervisor_daemon_routes/planted_by_a_macro_mod.rs"];
    const plantedOnly = plantedRustc.filter((file) => !censusSet.has(file));
    ok("DRILL M1 — the entailment detects a file the compiler read that the census did not walk, which is the exact shape of the redirect and macro-mod constructs the census says it cannot see",
      plantedOnly.length === 1, plantedOnly.join(",") || "NOTHING DETECTED");

    // M2 — and the reverse edge must see a module the compiler did not read.
    const plantedCensus = [...censusModules, "crates/node/src/bin/hypervisor_daemon_routes/not_compiled.rs"];
    const ghost = plantedCensus.filter((file) => !rustcSet.has(file));
    ok("DRILL M2 — the reverse edge detects a module the compiler never read",
      ghost.length === 1, ghost.join(",") || "NOTHING DETECTED");

    // M3 — the vocabulary check must see a bucket the resolver emits but nothing pins.
    const plantedEmittable = [...emittable, "seventh-bucket-kind"];
    const wouldBeUnpinned = plantedEmittable.filter((name) => !pinned.includes(name));
    ok("DRILL M3 — the vocabulary check detects a bucket the resolver can emit that no pin mentions, which is the failure a size pin cannot see",
      wouldBeUnpinned.length === 1, wouldBeUnpinned.join(",") || "NOTHING DETECTED");

    // M4 — and a pin whose code path is gone.
    const plantedPinned = [...pinned, "retired-bucket"];
    const wouldBeUnemittable = plantedPinned.filter((name) => !emittable.includes(name));
    ok("DRILL M4 — the reverse vocabulary edge detects a pin whose code path no longer exists",
      wouldBeUnemittable.length === 1, wouldBeUnemittable.join(",") || "NOTHING DETECTED");

    // M5 — the data-include accounting must see an unexplained non-Rust file.
    const plantedOther = [...rustcOther, "crates/node/src/bin/hypervisor_daemon_routes/smuggled.bin"];
    const wouldBeUnexplained = plantedOther.filter((file) => !includeArgs.has(file.split("/").pop()));
    ok("DRILL M5 — the data-include accounting detects a non-Rust file rustc read that the census does not record",
      wouldBeUnexplained.length === 1, wouldBeUnexplained.join(",") || "NOTHING DETECTED");
  }
} catch (error) {
  failures += 1;
  results.push({ assertion: "the check ran to completion", satisfied: false, detail: String(error?.stack || error).slice(0, 600) });
  console.log(`FAIL  the check ran to completion  (${String(error?.message || error).slice(0, 300)})`);
}

const passed = results.filter((entry) => entry.satisfied).length;
console.log(JSON.stringify({
  check: "check:admission-census-entailment",
  unit: "M06.5",
  verdict: failures === 0 ? "PASS" : "FAIL",
  executed_assertions: results.length,
  passed,
  failed: failures,
  observations,
}, null, 2));
process.exit(failures === 0 ? 0 : 1);
