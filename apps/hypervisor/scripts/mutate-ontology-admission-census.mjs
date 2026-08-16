#!/usr/bin/env node
// THE ADMISSION CENSUS'S MUTATION BATTERY — replayable, committed, and counted by running.
//
// WHY IT IS A TRACKED ARTIFACT AND NOT A SESSION HABIT. A green verifier certifies nothing until a
// mutation proves it red on its own finding; that has been standing discipline here for several
// runs, and every run's mutation count nonetheless lived in a commit message and reproduced
// nowhere. A count that reproduces nowhere is the same falsified-claim class this program keeps
// finding in ledgers — applied to the evidence for the gates themselves. So the anchors are
// committed beside the gate, and the count is whatever this harness prints when it runs.
//
// WHAT MAKES AN ANCHOR PASS, AND WHY MERE RED IS NOT IT. Each anchor names the assertion whose
// CLAIM it violates. Before scoring, this harness re-derives every population pin the mutant moved
// — precisely what the commit that introduced the mutant would have done on its way to landing.
// That step is the whole finding that rebuilt this census: ten silence-class mutants were planted
// against the previous gate, three were caught, and SEVEN of the remaining went from "red" to fully
// green the moment their pins were re-derived. A pin bump is a ratchet, not a property.
//
// AND RESIDUALS ARE ASSERTED IN BOTH DIRECTIONS. An anchor marked `expect: "survives"` is a limit
// the gate does not claim to reach. If it starts being caught, the gate's stated limits are stale
// and its header is over-claiming by omission — so this harness fails on that too.
//
// THE HARNESS REWRITES THE SOURCE IT CERTIFIES. Every file it touches is restored, including on
// failure. It does NOT install signal handlers, so a battery killed mid-run can leave a mutant in
// the tree — verify a commit by replaying the anchors against it, never by grepping for markers.

import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP = path.resolve(HERE, "..");
const ROOT = path.resolve(APP, "..", "..");
const GATE = path.join(APP, "scripts/verify-hypervisor-ontology-admission-census.mjs");
const MANIFEST = path.join(APP, "ontology-admission-census.mutants.v1.json");

const manifest = JSON.parse(fs.readFileSync(MANIFEST, "utf8"));
const ANCHOR_FILE = path.join(ROOT, manifest.anchor_file);

/**
 * Every pin the gate reports in a FAIL detail, and the `PINNED` keys that re-derive it. Keeping the
 * mapping here rather than mutating the gate blindly is what keeps the re-derivation honest: this
 * harness may move a POPULATION COUNT and nothing else. It cannot relax a claim.
 */
/**
 * THE HARNESS MAY MOVE A POPULATION COUNT AND NOTHING ELSE. Every entry below is a measurement of
 * the census's REACH. `PINNED.unadjudicable` — the per-cause buckets of names this census cannot
 * resolve — is deliberately absent: those are a CLAIM about the gate's boundary, and a new
 * unadjudicable name is a name that entered the daemon which the census cannot tell apart from a
 * second admitter. The keys below are bare identifiers and the bucket keys are quoted strings, so
 * this holds by construction as well as by rule.
 */
const REPIN = [
  [/^(\d+) modules reached, \d+ distinct paths \(pinned \d+\)$/, (m) => [["modules", m[1]]]],
  [/^(\d+)\/\d+ tokens, (\d+)\/\d+ of them family-resolving$/, (m) => [["tokenMentions", m[1]], ["judgedTokenPositions", m[2]]]],
  [/^family=(\d+)\/\d+ non-ODK=(\d+)\/\d+ runtime=(\d+)\/\d+$/, (m) => [["family", m[1]], ["nonFamilyLiteral", m[2]], ["runtimeParameter", m[3]]]],
  [/^(\d+)\/\d+ family mentions, (\d+)\/\d+ production filesystem calls$/, (m) => [["familyMentions", m[1]], ["productionFsCalls", m[2]]]],
  [/^(\d+)\/\d+ spliced code includes$/, (m) => [["splicedCode", m[1]]]],
  [/^include_str!=(\d+)\/\d+ include_bytes!=(\d+)\/\d+ with (\d+)\/\d+ non-literal arguments$/, (m) => [["dataStr", m[1]], ["dataBytes", m[2]], ["dataOpaqueArg", m[3]]]],
  [/^(\d+)\/\d+ production, (\d+)\/\d+ under a bare #\[cfg\(test\)\]$/, (m) => [["production", m[1]], ["test", m[2]]]],
];

const runGate = () =>
  spawnSync("node", [GATE], { cwd: APP, encoding: "utf8", maxBuffer: 128 * 1024 * 1024 });

const failLines = (stdout) => (stdout || "").split("\n").filter((l) => l.startsWith("FAIL"));

function rederivePins(stdout) {
  let src = fs.readFileSync(GATE, "utf8");
  const moved = [];
  for (const line of failLines(stdout)) {
    const d = line.match(/ {2}\((.*)\)$/);
    if (!d) continue;
    for (const [re, keys] of REPIN) {
      const m = d[1].match(re);
      if (!m) continue;
      for (const [key, val] of keys(m)) {
        const kre = new RegExp(`(\\b${key}: )\\d+`);
        if (kre.test(src)) {
          src = src.replace(kre, `$1${val}`);
          moved.push(`${key}=${val}`);
        }
      }
    }
  }
  if (moved.length) fs.writeFileSync(GATE, src);
  return moved;
}

function plant(anchor) {
  const saved = new Map([[GATE, fs.readFileSync(GATE, "utf8")]]);
  const created = [];
  const dirsMade = [];
  const restore = () => {
    for (const [f, s] of saved) fs.writeFileSync(f, s);
    for (const f of created) fs.rmSync(f, { force: true });
    // AND THE DIRECTORIES. git ignores empty directories, so a leaked one is invisible to
    // `git status` AND to this harness's own tree-restored check — which is exactly how the
    // previous fix for the file leak left a directory behind and reported a clean tree.
    for (const d of dirsMade.slice().reverse()) { try { fs.rmdirSync(d); } catch { /* not empty: not ours to remove */ } }
  };
  // THE ANCHOR POINT IS CHECKED BEFORE ANYTHING IS WRITTEN. Creating a file and then throwing on a
  // missing anchor leaks that file and over-claims the restore_always rule — a review found exactly
  // that ordering here.
  // AN ANCHOR MAY NAME ITS OWN SITE. Some properties only hold in a particular module — the
  // one-hop-indirection residual is only green in a module already RECORDED as touching the family,
  // and planted anywhere else the toucher ratchet catches it for a reason that has nothing to do
  // with the residual. An anchor that cannot be planted where it means something is a mis-aimed
  // mutation, which is worse than none.
  const anchorFile = anchor.anchor_file ? path.join(ROOT, anchor.anchor_file) : ANCHOR_FILE;
  const anchorFind = anchor.anchor_find ?? manifest.anchor_find;
  const before = fs.readFileSync(anchorFile, "utf8");
  saved.set(anchorFile, before);
  if (!before.includes(anchorFind)) {
    throw new Error(`anchor point absent from ${anchor.anchor_file ?? manifest.anchor_file} — the battery cannot plant anything`);
  }
  try {
    for (const spec of [anchor.create, anchor.create2].filter(Boolean)) {
      const p = path.join(ROOT, spec.path);
      if (fs.existsSync(p)) throw new Error(`anchor ${anchor.id} would overwrite ${spec.path}`);
      const dir = path.dirname(p);
      if (!fs.existsSync(dir)) { fs.mkdirSync(dir, { recursive: true }); dirsMade.push(dir); }
      fs.writeFileSync(p, spec.content);
      created.push(p);
    }
    // A REPLACER FUNCTION, NEVER A REPLACEMENT STRING. `String.replace` reads `$&`, `` $` ``, `$'`
    // and `$1` in the replacement, so an anchor's own text could plant something other than what
    // this manifest records — the battery lying about what it tested.
    fs.writeFileSync(anchorFile, before.replace(anchorFind, () => `${anchor.insert}${anchorFind}`));
  } catch (error) {
    restore();
    throw error;
  }
  return restore;
}

/**
 * DOES THE MUTATED DAEMON STILL COMPILE? An anchor that cannot exist is not a mutant — it is a
 * fiction that scores as caught, because the gate reads source and a nonsensical mutant still moves
 * the census. A review demonstrated one: `NOT_A_REAL_ARG` scored RED-ON-TARGET. Anchors rot this way
 * when a signature or a visibility changes under them, and the battery keeps printing its total.
 */
function compiles() {
  // `-p ioi-node` matches the invocation CI already uses to build this binary, so the target
  // resolves the same way here as it does there.
  const r = spawnSync("cargo", ["check", "--locked", "-q", "-p", "ioi-node", "--bin", "hypervisor-daemon"], {
    cwd: ROOT, encoding: "utf8", maxBuffer: 256 * 1024 * 1024,
  });
  // THREE OUTCOMES, NEVER TWO. A check that COULD NOT RUN is not an anchor that is fiction, and
  // conflating them is the same class this battery exists to police: CI reported forty anchors as
  // "fiction" with an EMPTY error detail, because the failure was the spawn and not the compile.
  if (r.error || r.status === null) {
    return { ran: false, detail: `cargo check could not run: ${r.error?.message ?? "no exit status"}` };
  }
  const errs = (r.stderr || "").split("\n").filter((l) => l.startsWith("error")).slice(0, 3).join(" ; ");
  return { ran: true, ok: r.status === 0, detail: errs || `exit ${r.status} with no error line` };
}

function main() {
  // Refuse to start against a tree the gate already fails on: a mutant scored against a red gate
  // proves nothing, and "it went red" would be true before anything was planted.
  const base = runGate();
  if (base.status !== 0) {
    console.error("BLOCKED — the census gate is already failing on the unmutated tree:");
    for (const l of failLines(base.stdout)) console.error(`  ${l}`);
    process.exit(2);
  }
  const baseline = (base.stdout || "").trim().split("\n").pop();
  // WARM THE COMPILE CHECK ONCE, BEFORE ANY ANCHOR. If `cargo check` cannot run at all, that is one
  // systemic failure and it must be reported once and plainly — not discovered forty times over as
  // forty anchors mislabelled "fiction", which is what a CI run actually printed.
  const warm = compiles();
  if (!warm.ran || !warm.ok) {
    console.error(`BLOCKED — the compile check is unusable on this tree, so no anchor can be scored: ${warm.detail}`);
    process.exit(2);
  }
  console.log(`baseline: ${baseline}  ·  compile check usable\n`);

  const verdicts = [];
  for (const anchor of manifest.anchors) {
    let restore = () => {};
    try {
      restore = plant(anchor);
      const build = compiles();
      if (!build.ran) throw new Error(build.detail);
      if (!build.ok) {
        verdicts.push({ id: anchor.id, class: anchor.class, pass: false, verdict: "INVALID" });
        console.log(` FAIL  ${"INVALID".padEnd(15)} ${anchor.id.padEnd(32)} the mutated daemon does not compile — this anchor is fiction`);
        console.log(`          ${build.detail}`);
        continue;
      }
      let r = runGate();
      const moved = [];
      // Re-derive pins the way a landing commit would, until only property assertions remain.
      for (let round = 0; round < 4 && r.status !== 0; round++) {
        const mv = rederivePins(r.stdout || "");
        if (!mv.length) break;
        moved.push(...mv);
        r = runGate();
      }
      const fails = failLines(r.stdout);
      const survives = anchor.expect === "survives";
      const onTarget = anchor.red_on ? fails.some((f) => f.includes(anchor.red_on)) : false;
      const pass = survives ? r.status === 0 : onTarget;
      const verdict = survives
        ? r.status === 0
          ? "RESIDUAL"
          : "RESIDUAL-CLOSED"
        : onTarget
          ? "RED-ON-TARGET"
          : r.status === 0
            ? "GREEN"
            : "RED-OFF-TARGET";
      verdicts.push({ id: anchor.id, class: anchor.class, pass, verdict });
      console.log(
        `${pass ? "  ok  " : " FAIL "} ${verdict.padEnd(15)} ${anchor.id.padEnd(32)}` +
          `${moved.length ? ` [repinned ${[...new Set(moved)].length}]` : ""}`,
      );
      if (!pass) {
        for (const f of fails) console.log(`          ${f.slice(0, 150)}`);
        if (survives) console.log(`          this anchor is documented as a NAMED RESIDUAL — the gate's header now under-claims`);
      }
    } finally {
      restore();
    }
  }

  // THE TREE MUST BE AS IT WAS FOUND. Next-legs XIII killed a battery mid-run and left a mutant in
  // the tree; a marker sweep would not have seen it. Re-running the gate on the restored tree proves
  // restoration by the same instrument that scored the anchors, and leaves the verifier-census
  // artifact matching the file on disk so the floors gate does not read a mutated digest.
  const after = runGate();
  const restored = after.status === 0;
  console.log(`\n${restored ? "  ok  " : " FAIL "} tree restored — the gate is green again on the tree this battery was handed`);
  if (!restored) for (const l of failLines(after.stdout)) console.log(`          ${l.slice(0, 150)}`);
  verdicts.push({ id: "tree-restored", class: "harness", pass: restored, verdict: restored ? "RESTORED" : "DIRTY" });

  const failed = verdicts.filter((v) => !v.pass);
  const red = verdicts.filter((v) => v.verdict === "RED-ON-TARGET").length;
  const residual = verdicts.filter((v) => v.verdict === "RESIDUAL").length;
  console.log(
    `\n${red} anchors RED-ON-TARGET, ${residual} named residual${residual === 1 ? "" : "s"} still open, ` +
      `${verdicts.length - failed.length}/${verdicts.length} anchors as recorded`,
  );
  if (failed.length) process.exit(1);
}

try {
  main();
} catch (error) {
  console.error(`FAIL ontology-admission-census mutation battery — ${error?.stack || error}`);
  process.exit(1);
}
