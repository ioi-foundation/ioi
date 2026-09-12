#!/usr/bin/env node
//
// M01.7 — DOES THE RETAINED T7 CAPSTONE STILL APPLY TO THIS TREE?
//
// M01.7's acceptance is ACC-4 run LIVE once: an intent root, an outcome root, reconciliation on
// ambiguity, and a readback against the counterparty's own record. That run happened. Its evidence
// is retained at docs/architecture/_meta/evidence/governed-effect-t7-integrated-capstone.v1.json,
// and three gates already prove things ABOUT it without contacting a provider — the claim manifest,
// the assurance floor, and the capstone bundle.
//
// What none of them answers is the only question that matters for a tree that has moved on since:
// DOES THAT EVIDENCE STILL DESCRIBE THIS TREE? A retained live proof is not a standing one. Without
// an applicability gate, "ACC-4 ran live" degrades silently into "ACC-4 ran live against something",
// and the three existing gates would stay green the whole way down, because each of them judges the
// evidence's own internal consistency rather than its relationship to HEAD.
//
// THE THREE THINGS THIS GATE ANSWERS, as one command:
//
//   1. ANCESTRY — the commit the integrated capstone was performed on resolves in THIS repository
//      and is an ancestor of HEAD. That is the applicability claim, and it is the one that decays:
//      a rebase, a squash, or a re-clone from a different lineage all break it, and all of them are
//      silent everywhere else.
//
//   2. THE ATTESTED COORDINATES — every field the applicability claim rests on is present and
//      well-formed, including the certificate hash, so a truncated or re-serialised evidence file
//      cannot pass as a live proof.
//
//   3. THE MUTATION BATTERY, RUN, NOT CITED — the capstone's own 22 structural mutations execute
//      here as part of this one command, and their population is pinned. A battery whose cases are
//      quietly deleted is the classic way a green gate stops meaning anything, and citing a count
//      from a comment would reproduce exactly that.
//
// WHAT "THE COMMITTED CERTIFICATE HASH" HAD TO BECOME, AND WHY (re-scoped 2026-09-12, recorded).
// The unit's text asks this gate to verify the committed certificate hash. MEASURED FIRST: the
// certificate is NOT committed. It lives at internal-docs/prompts/c7-c8-capstone/evidence/…, and
// `.gitignore` ignores internal-docs/prompts/ entirely — `git ls-files` over that tree returns
// zero. On a fresh clone the bytes do not exist, so a gate that hashed them would pass vacuously in
// CI, which is the same defect ruled on for M08.7's corpus. The hash is therefore ATTESTED by the
// tracked evidence rather than RECOMPUTED from bytes this gate can see, that reduction is an
// assertion here rather than a footnote, and the nonclaims below say exactly what is left unproven.
//
//   --mutation  prove each finding fails on its own
//   --skip-composed  run the local assertions only, without the three composed gates
import { readFileSync } from "node:fs";
import { dirname, isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync, spawnSync } from "node:child_process";

const repo = dirname(dirname(fileURLToPath(import.meta.url)));
const mutation = process.argv.includes("--mutation");
const skipComposed = process.argv.includes("--skip-composed");
const findings = [];
const observations = {};

const ok = (name, satisfied, detail) => {
  findings.push({ name, satisfied: !!satisfied, detail: detail ?? "" });
  console.log(`${satisfied ? "PASS" : "FAIL"}  ${name}${detail ? `  (${detail})` : ""}`);
};

const SHA256 = /^sha256:[0-9a-f]{64}$/u;
const COMMIT = /^[0-9a-f]{40}$/u;
// THE TRACKED SUBJECTS, and the one seam the battery below needs.
//
// A gate that can be pointed at different evidence is a gate that can be pointed at FAKE evidence,
// so the two overrides are honoured ONLY under `--mutation` and the run refuses outright if they
// are set without it. That keeps the battery able to plant a defect and watch this gate go red —
// which is the only way a drill proves anything — without leaving a way to aim the real run
// somewhere friendlier.
const OVERRIDES_REQUESTED = !!(process.env.IOI_T7_EVIDENCE_PATH || process.env.IOI_T7_CAPSTONE_PATH);
if (OVERRIDES_REQUESTED && !mutation) {
  console.error("FAIL  the evidence and capstone paths may only be overridden by this gate's own mutation battery; a non-mutation run reads the tracked paths and nothing else");
  process.exit(2);
}
const EVIDENCE_PATH = process.env.IOI_T7_EVIDENCE_PATH
  || "docs/architecture/_meta/evidence/governed-effect-t7-integrated-capstone.v1.json";
const EVIDENCE_FORMAT = "ioi.architecture.capstone-evidence.v1";
// The capstone's two batteries, pinned by SIZE in the source that owns them. The self-test one is
// EXECUTED below; this pin is what makes the other one — which needs a daemon and the untracked
// certificate, so it cannot run here — fail closed when a case is deleted rather than shrink in
// silence. Both are 22 today and they are DIFFERENT twenty-twos: the self-test mutates a synthetic
// certificate structurally, the durable one also reaches a live record store.
const SELF_TEST_MUTATIONS = 22;
const DURABLE_MUTATIONS = 22;

// AN OVERRIDE PATH IS ABSOLUTE, AND `join(repo, "/abs")` IS NOT `/abs` (2026-09-12). The first cut
// of this battery joined both override paths onto the repository root, which produced a path that
// does not exist — so every evidence drill went red because the file could not be READ, not because
// of the defect it planted. Each drill passed while proving nothing about the assertion it named:
// the exact failure mode this gate's own drills exist to prevent, reproduced inside them.
const resolveSubject = (relativeOrAbsolute) =>
  (isAbsolute(relativeOrAbsolute) ? relativeOrAbsolute : join(repo, relativeOrAbsolute));

const git = (args) => {
  try {
    return execFileSync("git", args, { cwd: repo, encoding: "utf8" }).trim();
  } catch {
    return null;
  }
};

const run = (script, args) => {
  const result = spawnSync("node", [resolveSubject(script), ...args], {
    cwd: repo, encoding: "utf8", timeout: 10 * 60 * 1000,
  });
  return { status: result.status, out: `${result.stdout || ""}${result.stderr || ""}` };
};

// ---------------------------------------------------------------- the retained evidence itself
let evidence = null;
let parsed = false;
try {
  evidence = JSON.parse(readFileSync(resolveSubject(EVIDENCE_PATH), "utf8"));
  parsed = true;
} catch (error) {
  evidence = null;
  observations.parse_error = String(error.message).slice(0, 160);
}
ok("the retained T7 evidence is TRACKED, parses, and declares the registered capstone-evidence format — a live proof that cannot be read on a fresh clone is not retained evidence, it is a memory",
  parsed && evidence?.evidence_format === EVIDENCE_FORMAT,
  parsed ? `${EVIDENCE_PATH} · ${evidence?.evidence_format}` : observations.parse_error);

const hashFields = ["certificate_hash", "daemon_binary_hash", "request_hash"];
const badHashes = hashFields.filter((field) => !SHA256.test(String(evidence?.[field] ?? "")));
ok("every attested coordinate the applicability claim rests on is present and WELL-FORMED — a truncated or re-serialised evidence file must not read as a live proof, and the certificate hash in particular is the one field a later edit would be tempted to leave behind",
  badHashes.length === 0,
  badHashes.length ? `malformed: ${badHashes.join(", ")}` : `${hashFields.length} sha256 coordinates, certificate ${String(evidence?.certificate_hash).slice(0, 22)}…`);

// ---------------------------------------------------------------- ANCESTRY, the applicability claim
const integrated = String(evidence?.integrated_source_commit ?? "");
const benchmark = String(evidence?.benchmark_source_commit ?? "");
// A SHALLOW CLONE IS NOT A FAILED ANCESTRY, AND CONFLATING THEM IS HOW THIS GATE WENT RED IN CI
// WHILE PASSING EVERYWHERE ELSE (2026-09-12). The runner checks out with depth 1, so the commit the
// live run was performed on is simply absent from its history — and "absent" was being reported as
// "not an ancestor", which is a different fact with a different owner and a different fix. The gate
// needs exactly one commit, so it fetches exactly that one before concluding anything, and if the
// fetch cannot get it the finding says HISTORY UNAVAILABLE rather than accusing the tree.
const haveCommit = (sha) => git(["cat-file", "-t", sha]) === "commit";
const fetchIfShallow = (sha) => {
  if (!COMMIT.test(sha) || haveCommit(sha)) return;
  // `--depth=1` on a single object: enough to answer ancestry, and it costs one object rather than
  // the whole history a `fetch-depth: 0` checkout would pull on every run of every job.
  spawnSync("git", ["fetch", "--depth=1", "origin", sha], { cwd: repo, encoding: "utf8", timeout: 120000 });
  if (!haveCommit(sha)) {
    spawnSync("git", ["fetch", "--unshallow"], { cwd: repo, encoding: "utf8", timeout: 300000 });
  }
};
fetchIfShallow(integrated);
observations.shallow_clone = git(["rev-parse", "--is-shallow-repository"]) === "true";
const integratedResolves = COMMIT.test(integrated) && haveCommit(integrated);
// ANCESTRY IS NOT ANSWERABLE ON A SHALLOW REPOSITORY, and a targeted fetch does not make it so: a
// `--depth=1` fetch of one sha hands you the OBJECT with no parent chain, so `merge-base` cannot
// walk the path between it and HEAD and answers "no" for a commit that is in fact an ancestor.
// Measured against a real `git clone --depth 1` of this repository, which is what the runner does.
// So a negative answer on a shallow clone is not an answer: deepen, then ask again, and only then
// is a "no" a finding about the tree rather than about the checkout.
const isAncestor = (sha) =>
  spawnSync("git", ["merge-base", "--is-ancestor", sha, "HEAD"], { cwd: repo }).status === 0;
let integratedIsAncestor = integratedResolves && isAncestor(integrated);
if (integratedResolves && !integratedIsAncestor && git(["rev-parse", "--is-shallow-repository"]) === "true") {
  spawnSync("git", ["fetch", "--unshallow"], { cwd: repo, encoding: "utf8", timeout: 600000 });
  integratedIsAncestor = isAncestor(integrated);
}
observations.integrated_source_commit = integrated;
observations.head = git(["rev-parse", "HEAD"]) || "";
ok("THE RETAINED RUN'S SOURCE IS AN ANCESTOR OF THIS TREE — the whole applicability question, and the only one that decays silently. The three gates beside this one judge the evidence's internal consistency, so all of them stay green on a tree the run never touched; a rebase, a squash, or a clone from a different lineage breaks exactly this and nothing else",
  integratedIsAncestor,
  integratedIsAncestor
    ? `${integrated.slice(0, 12)} is an ancestor of ${observations.head.slice(0, 12)}`
    : integratedResolves
      ? `${integrated.slice(0, 12)} resolves here but is NOT an ancestor of HEAD — the retained evidence describes a lineage this tree does not descend from`
      : `HISTORY UNAVAILABLE: ${integrated.slice(0, 12) || "absent"} is not in this checkout even after a targeted fetch${observations.shallow_clone ? " (the clone is shallow)" : ""} — this is a fact about the checkout, not about the evidence`);

// The benchmark lineage is RECORDED, not required. Measured 2026-09-12: it resolves as a commit
// object here and is NOT an ancestor of HEAD — the benchmark ran on its own branch and was never
// merged. Requiring ancestry of it would fail honestly-retained evidence; ignoring it entirely
// would hide the day it silently stops resolving at all, so it is asserted to RESOLVE and its
// ancestry is reported as a measurement rather than a bar.
fetchIfShallow(benchmark);
const benchmarkResolves = COMMIT.test(benchmark) && haveCommit(benchmark);
const benchmarkIsAncestor = benchmarkResolves && isAncestor(benchmark);
observations.benchmark_source_commit = benchmark;
observations.benchmark_is_ancestor_of_head = benchmarkIsAncestor;
ok("and the benchmark lineage still RESOLVES in this repository, with its ancestry reported rather than demanded — the benchmark ran on its own branch and was never merged, so requiring ancestry would fail honestly-retained evidence while ignoring it would hide the day the object disappears",
  benchmarkResolves,
  `${benchmark.slice(0, 12) || "absent"} resolves=${benchmarkResolves} ancestor_of_head=${benchmarkIsAncestor}`);

// ---------------------------------------------------------------- the terminal claims it rests on
const terminal = {
  result: evidence?.result === "success",
  teardown_verified: evidence?.teardown_verified === true,
  provider_terminal: evidence?.provider_terminal === true,
  workload_result_retrieved: evidence?.workload_result_retrieved === true,
  active_lease_count: evidence?.active_lease_count === 0,
  open_exposure_count: evidence?.open_exposure_count === 0,
  unknown_exposure_count: evidence?.unknown_exposure_count === 0,
};
const unmet = Object.entries(terminal).filter(([, value]) => !value).map(([key]) => key);
ok("the evidence's own terminal claims are the ones a completed bounded effect must carry: the run succeeded, the result was retrieved, the provider is terminal, teardown is verified, and NOTHING is left open or unknown — an effect that ended with open exposure is not a bounded effect that completed, it is one still running",
  unmet.length === 0,
  unmet.length ? `unmet: ${unmet.join(", ")}` : "7/7 terminal claims carried");

ok("and the evidence carries its own remaining nonclaims rather than reading as unqualified — a capstone that lists nothing it failed to prove is claiming more than any single run can",
  Array.isArray(evidence?.remaining_nonclaims) && evidence.remaining_nonclaims.length > 0,
  `${(evidence?.remaining_nonclaims || []).length} declared nonclaims`);

// ---------------------------------------------------------------- the battery, RUN not cited
const capstone = process.env.IOI_T7_CAPSTONE_PATH || "apps/hypervisor/scripts/verify-c7-c8-capstone.mjs";
let selfTest = null;
if (!mutation) {
  const executed = run(capstone, ["--self-test"]);
  try {
    selfTest = JSON.parse(executed.out.slice(executed.out.indexOf("{")));
  } catch {
    selfTest = null;
  }
  observations.self_test_status = executed.status;
  ok("THE 22 MUTATIONS EXECUTE HERE, AS PART OF THIS ONE COMMAND, and their population is pinned — a battery cited from a comment proves nothing, and a battery whose cases are quietly deleted is the classic way a green gate stops meaning anything. Every case must go red on its own planted defect and the count must be exactly what is pinned",
    executed.status === 0 && selfTest?.ok === true
      && selfTest?.mutation_count === SELF_TEST_MUTATIONS
      && (selfTest?.cases || []).length === SELF_TEST_MUTATIONS
      && (selfTest?.failures || []).length === 0,
    selfTest
      ? `exit ${executed.status} · ${selfTest.mutation_count}/${SELF_TEST_MUTATIONS} cases, ${(selfTest.failures || []).length} false green(s)`
      : `exit ${executed.status} · the self-test printed no readable result`);
} else {
  ok("the executed battery is carried by the non-mutation run — its own falsifiability is the battery itself, which is what it already is",
    true, "deferred by design, and CI runs both");
}

// The OTHER battery cannot run here: it needs a live daemon and the untracked certificate. Pinning
// its size in the source that owns it is what keeps a deleted case from shrinking it in silence.
const capstoneSource = readFileSync(resolveSubject(capstone), "utf8");
const durableBlock = capstoneSource.slice(capstoneSource.indexOf("async function mutationTest"));
const durableCases = (durableBlock.slice(0, durableBlock.indexOf("\n  ];")).match(/^\s*\["/gmu) || []).length;
ok("and the DURABLE battery's population is pinned in the source that owns it — it needs a live daemon and the certificate this repository does not track, so it cannot run here; what can be checked is that nobody deleted a case from it, which is the failure mode a size pin exists for",
  durableCases === DURABLE_MUTATIONS,
  `${durableCases}/${DURABLE_MUTATIONS} durable mutation cases`);

// ---------------------------------------------------------------- the three gates, COMPOSED
if (!skipComposed && !mutation) {
  // COMPOSED, NOT RESTATED — and the composition says which of the three it can actually run.
  // The assurance floor and the claim manifest run here whole. The capstone bundle's OTHER half
  // takes `--evidence <certificate>`, which this repository does not track, so what is runnable of
  // it is its self-test — and that is EXECUTED above rather than counted here, so this assertion
  // does not get to imply it ran three things when it ran two.
  const composed = [
    ["check:governed-effect-assurance-floor",
      ["apps/hypervisor/scripts/verify-governed-effect-assurance-floor.mjs"]],
    ["check:governed-effect-claims",
      ["--test",
        "apps/hypervisor/scripts/lib/governed-effect-claim-manifest.test.mjs",
        "apps/hypervisor/scripts/lib/c7-public-evidence.test.mjs"]],
  ];
  const results = [];
  for (const [name, argv] of composed) {
    const executed = spawnSync("node", argv, { cwd: repo, encoding: "utf8", timeout: 15 * 60 * 1000 });
    results.push({ name, status: executed.status });
  }
  const failed = results.filter((entry) => entry.status !== 0);
  observations.composed_gates = results.map((entry) => `${entry.name}=${entry.status}`);
  ok("the two gates that CAN run whole are composed here rather than restated — this gate answers applicability and leaves the evidence's own internal proofs to their owners; the capstone bundle's third gate takes a certificate this repository does not track, so its runnable half is the self-test executed above and is not counted twice",
    failed.length === 0,
    failed.length ? failed.map((entry) => `${entry.name} exit ${entry.status}`).join("; ") : `${results.length} composed gate(s) green, capstone self-test executed separately`);
} else {
  ok("the composed gates are carried by the full run", true, "deferred by flag");
}

// ---------------------------------------------------------------- drills
if (mutation) {
  // EVERY DRILL PLANTS A DEFECT AND RE-RUNS THIS GATE. An earlier cut of this battery asserted the
  // PREDICATES in isolation — that a malformed hash fails a regex, that an all-zero commit does not
  // resolve — which is true, trivially, and proves nothing about whether the gate would go red. A
  // drill that cannot fail while the gate is broken is not a drill. Each case below writes a
  // mutated copy, runs this script against it, and requires a non-zero exit naming that assertion.
  const { mkdtempSync, writeFileSync, readFileSync: read } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const scratch = mkdtempSync(join(tmpdir(), "t7-applicability-drill-"));
  const drill = (name, planted, expectFragment) => {
    const path = join(scratch, `evidence-${findings.length}.json`);
    writeFileSync(path, JSON.stringify(planted, null, 2));
    const executed = spawnSync("node", [join(repo, "scripts", "check-t7-retained-capstone-applicability.mjs"),
      "--mutation", "--skip-composed"], {
      cwd: repo, encoding: "utf8", timeout: 5 * 60 * 1000,
      env: { ...process.env, IOI_T7_EVIDENCE_PATH: path, IOI_T7_DRILL_CHILD: "1" },
    });
    const output = `${executed.stdout || ""}${executed.stderr || ""}`;
    const red = executed.status !== 0;
    const named = output.split("\n").some((line) => line.startsWith("FAIL") && line.includes(expectFragment));
    ok(`DRILL — ${name}`, red && named, `exit ${executed.status} · the finding names "${expectFragment}": ${named}`);
  };

  if (process.env.IOI_T7_DRILL_CHILD !== "1") {
    drill("a malformed certificate hash goes RED, it is not shrugged at",
      { ...evidence, certificate_hash: "sha256:not-a-hash" }, "WELL-FORMED");
    drill("evidence whose source commit this repository does not have goes RED",
      { ...evidence, integrated_source_commit: "0".repeat(40) }, "ANCESTOR OF THIS TREE");
    drill("evidence whose source commit exists but is NOT an ancestor goes RED — ancestry is directional, and two commits both existing is not applicability",
      { ...evidence, integrated_source_commit: evidence.benchmark_source_commit }, "ANCESTOR OF THIS TREE");
    drill("an effect that ended with unknown exposure goes RED as incomplete",
      { ...evidence, unknown_exposure_count: 1 }, "NOTHING is left open or unknown");
    drill("a capstone declaring no remaining nonclaims goes RED as claiming more than one run can",
      { ...evidence, remaining_nonclaims: [] }, "remaining nonclaims");
    drill("a benchmark lineage that no longer resolves goes RED, so the day the object disappears is not silent",
      { ...evidence, benchmark_source_commit: "1".repeat(40) }, "still RESOLVES");

    // The durable pin's drill needs the capstone SOURCE, not the evidence: a copy with one case
    // deleted must make the size pin red.
    const capstoneSrc = read(join(repo, "apps/hypervisor/scripts/verify-c7-c8-capstone.mjs"), "utf8");
    const shrunkPath = join(scratch, "capstone-one-case-short.mjs");
    const marker = capstoneSrc.indexOf("async function mutationTest");
    const firstCase = capstoneSrc.indexOf('    ["', marker);
    const lineEnd = capstoneSrc.indexOf("\n", firstCase) + 1;
    writeFileSync(shrunkPath, capstoneSrc.slice(0, firstCase) + capstoneSrc.slice(lineEnd));
    const executed = spawnSync("node", [join(repo, "scripts", "check-t7-retained-capstone-applicability.mjs"),
      "--mutation", "--skip-composed"], {
      cwd: repo, encoding: "utf8", timeout: 5 * 60 * 1000,
      env: { ...process.env, IOI_T7_CAPSTONE_PATH: shrunkPath, IOI_T7_DRILL_CHILD: "1" },
    });
    const output = `${executed.stdout || ""}${executed.stderr || ""}`;
    ok("DRILL — a deleted durable mutation case goes RED, it is not a smaller number nobody reads",
      executed.status !== 0 && output.split("\n").some((line) => line.startsWith("FAIL") && line.includes("durable mutation cases")),
      `exit ${executed.status}`);

    // And the seam itself fails closed outside the battery.
    const leaked = spawnSync("node", [join(repo, "scripts", "check-t7-retained-capstone-applicability.mjs")], {
      cwd: repo, encoding: "utf8", timeout: 2 * 60 * 1000,
      env: { ...process.env, IOI_T7_EVIDENCE_PATH: join(scratch, "evidence-0.json") },
    });
    ok("DRILL — the override seam FAILS CLOSED outside this battery: a non-mutation run pointed at other evidence refuses rather than judging it",
      leaked.status === 2, `exit ${leaked.status}`);
  }
}

const failed = findings.filter((finding) => !finding.satisfied);
console.log(JSON.stringify({
  check: "check:t7-retained-capstone-applicability",
  unit: "M01.7",
  verdict: failed.length === 0 ? "PASS" : "FAIL",
  executed_assertions: findings.length,
  passed: findings.length - failed.length,
  failed: failed.length,
  observations,
  remaining_nonclaims: [
    "THE CERTIFICATE BYTES ARE NOT TRACKED. internal-docs/prompts/ is gitignored, so the certificate this evidence attests lives outside anything CI can read. The hash is verified as ATTESTED and well-formed, never recomputed from bytes; a certificate edited in place on one machine would not be caught here, and could not be caught by any gate over this repository.",
    "ANCESTRY IS NOT EQUIVALENCE. An ancestor commit proves this tree DESCENDS from the one the live run used. It does not prove the code paths that run exercised are unchanged since, and deliberately does not try: a file-level claim would be either trivially red on an active tree or so narrow it proved nothing.",
    "NO EXTERNAL EFFECT IS PERFORMED OR AUTHORISED HERE. This gate contacts no provider, spends nothing, and re-runs nothing. It answers whether a retained proof still applies; the proof itself remains the one recorded run.",
  ],
}, null, 2));
process.exit(failed.length === 0 ? 0 : 1);
