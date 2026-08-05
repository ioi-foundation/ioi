#!/usr/bin/env node
// Claims-coverage gate.
//
// WHY THIS EXISTS. On 2026-08-02 a cut was reported implementation-complete
// with every landing gate green. An independent reviewer then found that the
// record's own falsifiable claim was never covered: the lease plane was a stub
// (three routes, no lease read / checkpoint / revoke) and delivery was still
// lossy. The gates were REGRESSION gates — they proved nothing had broken —
// and nothing in the estate demanded a mapping from the record's claims to
// executed checks. A cut can therefore be green on every bar and still not
// have done what its record says.
//
// This gate closes that. Every `positive_proof` and `adversarial_or_fault_proof`
// entry in an owning record must map to a NAMED EXECUTED CHECK WITH RETAINED
// BYTES, and an unmapped claim fails closed.
//
// THREE THINGS IT REFUSES, each chosen against a defect class already in this
// program's ledger:
//
//  1. An unmapped claim. The default is REFUSAL, not silence — an include-list
//     of "claims we decided to cover" would fail open exactly the way the
//     logical-identity include-list did (a field nobody listed silently left
//     the comparison).
//
//  2. A mapping whose retained bytes are missing. A coverage table that names
//     evidence nobody produced is a claim about a claim.
//
//  3. A mapping whose retained bytes do NOT contain the named check passing.
//     This is the load-bearing one. Asserting "check X covers claim Y" proves
//     nothing unless X actually ran and passed in the retained transcript;
//     otherwise the table is prose, and prose matching prose is already in the
//     ledger too.
//
// The bytes must come from a real run. This gate does not run verifiers — it
// reads what a run left behind, so it cannot be satisfied by a verifier that
// was never executed.

import { execSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, "..", "..", "..");
const COVERAGE_DIR = join(REPO, "internal-docs", "implementation", "claims-coverage");
const CLAIM_FIELDS = ["positive_proof", "adversarial_or_fault_proof"];

function finding(severity, kind, message) {
  return { severity, kind, message };
}

/// Evaluate one record against one coverage manifest.
///
/// Pure: takes already-read values and a byte-reader, so the self-test below
/// drives the SAME predicate the real run drives. A self-test against a
/// reimplementation would prove the reimplementation.
/// The commit a retained log says it measured.
///
/// Retained bytes must state their own provenance IN the bytes. Twice now a
/// packet has reported gates "at the exact commit" while a retained log
/// actually measured an earlier one -- the report was a false statement and
/// nothing mechanical contradicted it. A log that does not declare its commit
/// is refused. A declared commit is accepted only when it equals the packet
/// HEAD, or is an ANCESTOR of HEAD whose entire measured-to-HEAD delta is
/// retained evidence -- both clauses, because tree equality is not history.
/// The claim can no longer be made by prose.
export function measuredCommit(bytes) {
  const match = /^IOI_MEASURED_COMMIT=([0-9a-f]{40})$/m.exec(bytes ?? "");
  return match === null ? null : match[1];
}

/// Real git operations. Injectable so the self-test drives the SAME predicate
/// production drives — a self-test against a reimplementation proves the
/// reimplementation.
export const REAL_GIT = {
  isAncestor(measured) {
    try {
      execSync(`git merge-base --is-ancestor ${measured} HEAD`, { cwd: REPO, stdio: "ignore" });
      return true;
    } catch { return false; }
  },
  evidenceOnlyDelta(measured) {
    try {
      const changed = execSync(`git diff --name-only ${measured} HEAD`, { cwd: REPO })
        .toString().trim().split("\n").filter(Boolean);
      return changed.length > 0 && changed.every((f) => f.startsWith("docs/evidence/"));
    } catch { return false; }
  },
};

export function evaluate({ recordId, record, manifest, readBytes, packetHead, git = REAL_GIT }) {
  const findings = [];
  const claims = [];
  for (const field of CLAIM_FIELDS) {
    const value = record?.[field];
    if (!Array.isArray(value)) {
      findings.push(
        finding("error", "claims-coverage", `${recordId}: "${field}" is not an array of claims`),
      );
      continue;
    }
    value.forEach((text, index) => claims.push({ field, index, text }));
  }

  const mappings = Array.isArray(manifest?.claim_coverage) ? manifest.claim_coverage : null;
  if (mappings === null) {
    findings.push(
      finding(
        "error",
        "claims-coverage",
        `${recordId}: no coverage manifest — every claim is unmapped and this gate fails closed`,
      ),
    );
    return { findings, claims, covered: 0 };
  }

  const byKey = new Map();
  for (const mapping of mappings) {
    byKey.set(`${mapping.claim_field}[${mapping.claim_index}]`, mapping);
  }

  let covered = 0;
  for (const claim of claims) {
    const key = `${claim.field}[${claim.index}]`;
    const mapping = byKey.get(key);
    const excerpt = String(claim.text).slice(0, 70);

    if (mapping === undefined) {
      findings.push(
        finding(
          "error",
          "claims-coverage",
          `${recordId}: ${key} is UNMAPPED — "${excerpt}…" has no named executed check`,
        ),
      );
      continue;
    }
    // A mapping may declare the claim not-yet-covered. That is honest and it
    // still FAILS — it does not silence the gate, it names the gap.
    if (mapping.coverage_state === "not_covered") {
      findings.push(
        finding(
          "error",
          "claims-coverage",
          `${recordId}: ${key} is declared NOT COVERED (${mapping.why ?? "no reason given"}) — "${excerpt}…"`,
        ),
      );
      continue;
    }
    if (!mapping.check_name || !mapping.retained_bytes) {
      findings.push(
        finding(
          "error",
          "claims-coverage",
          `${recordId}: ${key} names no check_name/retained_bytes pair`,
        ),
      );
      continue;
    }
    const bytes = readBytes(mapping.retained_bytes);
    if (bytes === null) {
      findings.push(
        finding(
          "error",
          "claims-coverage",
          `${recordId}: ${key} points at retained bytes that do not exist (${mapping.retained_bytes})`,
        ),
      );
      continue;
    }
    if (!bytes.includes(mapping.check_name)) {
      findings.push(
        finding(
          "error",
          "claims-coverage",
          `${recordId}: ${key} names check "${mapping.check_name}" which does NOT appear in its retained bytes (${mapping.retained_bytes}) — the mapping is prose`,
        ),
      );
      continue;
    }
    // The bytes must declare which commit produced them, and it must be the
    // commit the packet claims. This is the mechanism that retires
    // evidence-at-the-wrong-HEAD.
    if (packetHead !== undefined) {
      const measured = measuredCommit(bytes);
      if (measured === null) {
        findings.push(finding("error","claims-coverage",
          `${recordId}: ${key} retained bytes (${mapping.retained_bytes}) declare no IOI_MEASURED_COMMIT — a log that cannot state its own commit cannot support a claim about one`));
        continue;
      }
      // FIXPOINT, BOTH CLAUSES. Evidence measuring HEAD cannot be committed
      // without moving HEAD, so "embedded sha == HEAD" is unsatisfiable at the
      // moment bytes land. The rule is therefore: the embedded sha is accepted
      // when it is an ANCESTOR of HEAD **and** the entire measured→HEAD delta
      // is retained evidence.
      //
      // Both clauses are enforced. Checking only the delta was a real hole:
      // `git diff --name-only A HEAD` compares TREES, so any commit with the
      // right tree difference satisfied it — ancestor or not, and a commit
      // AHEAD of HEAD satisfies it too. Codex demonstrated it with a synthetic
      // non-ancestor producing an identical eight-file delta. Tree equality is
      // not history; the ancestry clause is what ties the bytes to this line
      // of development.
      if (measured !== packetHead && !(git.isAncestor(measured) && git.evidenceOnlyDelta(measured))) {
        findings.push(finding("error","claims-coverage",
          `${recordId}: ${key} retained bytes measured ${measured.slice(0,9)} but the packet HEAD is ${packetHead.slice(0,9)} — the evidence is for a different commit`));
        continue;
      }
    }
    // The named check must appear PASSING. Presence alone would let a failing
    // check satisfy the claim it was supposed to prove.
    // Recognise the PASS forms the estate's runners actually emit. A verifier
    // prints "PASS <label>"; cargo prints "test <name> ... ok". Accepting both
    // is recognising real transcript formats -- it is NOT loosening the bar,
    // because a FAILING line in either format still does not match.
    // A DECLARED NEGATIVE CONTROL IS COVERED BY ITS REFUSAL, NOT BY A PASS.
    //
    // An adversarial proof's whole value is that the bar went RED on a real
    // subject. Demanding PASS bytes makes every such proof unmappable, which
    // pushes the strongest evidence in a cut OUT of this gate entirely -- the
    // same include-list fail-open this gate exists to close, one level down.
    //
    // The bar for a negative control is STRICTLY STRONGER than for a positive
    // one, not weaker. It must show a refusal, and the transcript must have
    // DECLARED that refusal in advance: IOI_EXPECTED_EXIT set, a non-zero
    // IOI_EXIT_CODE, and IOI_VERDICT=as-declared. A proof that merely happened
    // to fail proves nothing -- it is indistinguishable from a broken gate,
    // which is exactly how a no-op synthetic edge once passed for evidence.
    if (mapping.expected_verdict === "refusal") {
      const declared = /^IOI_EXPECTED_EXIT=(?!any$)\S+$/m.test(bytes);
      const nonZero = /^IOI_EXIT_CODE=(?!0$)\d+$/m.test(bytes);
      const asDeclared = /^IOI_VERDICT=as-declared$/m.test(bytes);
      const named = bytes.includes(mapping.check_name);
      if (!(declared && nonZero && asDeclared && named)) {
        findings.push(finding("error", "claims-coverage",
          `${recordId}: ${key} is declared a NEGATIVE CONTROL but its retained bytes do not show a ` +
          `pre-declared refusal (need IOI_EXPECTED_EXIT set to a specific code, a non-zero IOI_EXIT_CODE, ` +
          `IOI_VERDICT=as-declared, and the named check present; got declared=${declared} ` +
          `nonZero=${nonZero} asDeclared=${asDeclared} named=${named}) — a proof that merely happened to ` +
          `fail is indistinguishable from a broken gate`));
        continue;
      }
      covered += 1;
      continue;
    }
    const passing = bytes.split("\n").some((line) => {
      if (!line.includes(mapping.check_name)) return false;
      // Three real transcript formats: a verifier's "PASS <label>", cargo's
      // "test <name> ... ok", and the form every check-* executable in this
      // estate prints -- "<name>: PASS (0 error, ...)". The third was missing,
      // which meant the gate could not read the output of the runners it was
      // built to gate. A FAIL line still matches none of them.
      return /^\s*PASS\b/.test(line) || /\.\.\.\s*ok\s*$/.test(line) || /:\s*PASS\b/.test(line);
    });
    if (!passing) {
      findings.push(
        finding(
          "error",
          "claims-coverage",
          `${recordId}: ${key} names check "${mapping.check_name}" which appears in the retained bytes but NOT as PASS`,
        ),
      );
      continue;
    }
    covered += 1;
  }

  for (const [key] of byKey) {
    if (!claims.some((claim) => `${claim.field}[${claim.index}]` === key)) {
      findings.push(
        finding(
          "error",
          "claims-coverage",
          `${recordId}: coverage manifest maps ${key}, which is not a claim in the record`,
        ),
      );
    }
  }

  return { findings, claims, covered };
}

let SELF_TEST_CASE_COUNT = 0;

/// Drive the real predicate over predeclared malformed inputs. Each case must
/// be REJECTED; a case that passes means the gate stopped refusing something
/// it was built to refuse.
function selfTest() {
  const failures = [];
  const record = {
    positive_proof: ["a claim that must be covered by an executed check"],
    adversarial_or_fault_proof: ["a second claim that must be covered too"],
  };
  const goodBytes = "PASS covers-claim-one — detail\nPASS covers-claim-two — detail\n";
  const reader = (path) => (path === "good.log" ? goodBytes : null);
  const map = (over) => ({
    claim_coverage: [
      { claim_field: "positive_proof", claim_index: 0, check_name: "covers-claim-one", retained_bytes: "good.log" },
      { claim_field: "adversarial_or_fault_proof", claim_index: 0, check_name: "covers-claim-two", retained_bytes: "good.log" },
      ...(over ?? []),
    ],
  });
  const cases = [
    ["a fully mapped record is ACCEPTED", { manifest: map(), readBytes: reader }, false],
    ["no manifest at all", { manifest: null, readBytes: reader }, true],
    ["an unmapped claim", {
      manifest: { claim_coverage: map().claim_coverage.slice(0, 1) },
      readBytes: reader,
    }, true],
    ["a claim declared not_covered", {
      manifest: { claim_coverage: [map().claim_coverage[0], { claim_field: "adversarial_or_fault_proof", claim_index: 0, coverage_state: "not_covered", why: "stub" }] },
      readBytes: reader,
    }, true],
    ["retained bytes that do not exist", {
      manifest: { claim_coverage: [map().claim_coverage[0], { ...map().claim_coverage[1], retained_bytes: "missing.log" }] },
      readBytes: reader,
    }, true],
    ["a check name absent from its retained bytes", {
      manifest: { claim_coverage: [map().claim_coverage[0], { ...map().claim_coverage[1], check_name: "never-ran" }] },
      readBytes: reader,
    }, true],
    ["a check present but NOT passing", {
      manifest: map(),
      readBytes: (p) => (p === "good.log" ? "PASS covers-claim-one\nFAIL covers-claim-two — broke\n" : null),
    }, true],
    ["retained bytes that declare no measured commit", {
      manifest: map(), readBytes: reader, packetHead: "a".repeat(40),
    }, true],
    ["retained bytes measured at a DIFFERENT commit", {
      manifest: map(),
      readBytes: () => `IOI_MEASURED_COMMIT=${"b".repeat(40)}\n` + goodBytes,
      packetHead: "a".repeat(40),
    }, true],
    ["retained bytes measured at the packet HEAD", {
      manifest: map(),
      readBytes: () => `IOI_MEASURED_COMMIT=${"a".repeat(40)}\n` + goodBytes,
      packetHead: "a".repeat(40),
    }, false],
    // The fixpoint rule has TWO clauses and both are load-bearing. Codex's
    // attack shape is the first case: a non-ancestor whose tree delta against
    // HEAD is evidence-only. Tree equality is not history.
    ["Codex's attack shape: a NON-ANCESTOR with an evidence-only delta", {
      manifest: map(),
      readBytes: () => `IOI_MEASURED_COMMIT=${"c".repeat(40)}\n` + goodBytes,
      packetHead: "a".repeat(40),
      git: { isAncestor: () => false, evidenceOnlyDelta: () => true },
    }, true],
    // A commit AHEAD of HEAD also has a tree delta and is also not an ancestor.
    ["a DESCENDANT of HEAD with an evidence-only delta", {
      manifest: map(),
      readBytes: () => `IOI_MEASURED_COMMIT=${"d".repeat(40)}\n` + goodBytes,
      packetHead: "a".repeat(40),
      git: { isAncestor: () => false, evidenceOnlyDelta: () => true },
    }, true],
    ["a valid ANCESTOR with an evidence-only delta is ACCEPTED", {
      manifest: map(),
      readBytes: () => `IOI_MEASURED_COMMIT=${"e".repeat(40)}\n` + goodBytes,
      packetHead: "a".repeat(40),
      git: { isAncestor: () => true, evidenceOnlyDelta: () => true },
    }, false],
    ["an ancestor whose delta carries NON-evidence", {
      manifest: map(),
      readBytes: () => `IOI_MEASURED_COMMIT=${"f".repeat(40)}\n` + goodBytes,
      packetHead: "a".repeat(40),
      git: { isAncestor: () => true, evidenceOnlyDelta: () => false },
    }, true],
    ["a mapping for a claim the record does not have", {
      manifest: { claim_coverage: [...map().claim_coverage, { claim_field: "positive_proof", claim_index: 9, check_name: "covers-claim-one", retained_bytes: "good.log" }] },
      readBytes: reader,
    }, true],
  ];
  for (const [label, input, mustReject] of cases) {
    SELF_TEST_CASE_COUNT += 1;
    const { findings } = evaluate({ recordId: "self-test", record, ...input });
    const rejected = findings.length > 0;
    if (rejected !== mustReject) {
      failures.push(`self-test case "${label}" expected ${mustReject ? "rejection" : "acceptance"}`);
    }
  }
  return failures;
}

function main() {
  const selfTestFailures = selfTest();
  const findings = selfTestFailures.map((message) =>
    finding("error", "claims-coverage", message),
  );

  const manifests = existsSync(COVERAGE_DIR)
    ? readdirSync(COVERAGE_DIR).filter((name) => name.endsWith(".v1.json"))
    : [];
  if (manifests.length === 0) {
    findings.push(
      finding(
        "error",
        "claims-coverage",
        `no coverage manifests under ${COVERAGE_DIR}; a cut under review must map its claims`,
      ),
    );
  }

  let totalClaims = 0;
  let totalCovered = 0;
  for (const name of manifests) {
    const manifest = JSON.parse(readFileSync(join(COVERAGE_DIR, name), "utf8"));
    const recordPath = join(REPO, manifest.record_path ?? "");
    if (!existsSync(recordPath)) {
      findings.push(
        finding("error", "claims-coverage", `${name}: record_path does not exist (${manifest.record_path})`),
      );
      continue;
    }
    const record = JSON.parse(readFileSync(recordPath, "utf8"));
    // Packet HEAD comes from git, not from a file anyone can edit.
    let packetHead;
    try {
      packetHead = execSync("git rev-parse HEAD", { cwd: REPO }).toString().trim();
    } catch {
      packetHead = undefined;
    }
    const result = evaluate({
      packetHead,
      recordId: manifest.work_item_id ?? name,
      record,
      manifest,
      readBytes: (relative) => {
        const path = join(REPO, relative);
        return existsSync(path) ? readFileSync(path, "utf8") : null;
      },
    });
    findings.push(...result.findings);
    totalClaims += result.claims.length;
    totalCovered += result.covered;
  }

  // CONVERSE BAR: every published packet must be NAMED by a claims manifest.
  //
  // The gate above checks that MAPPED claims have evidence. It said nothing
  // about a cut with no manifest at all -- which is invisible to it by
  // construction. That is include-list fail-open, the oldest class in this
  // ledger, and it does not get to survive its own rediscovery.
  //
  // THE NAMING IS EXPLICIT, NOT INFERRED. A first version matched packet slug
  // words against work_item_id by substring, which is the same fail-open shape
  // one layer down: a manifest would silently vouch for a packet it never
  // mentions, purely because the words overlap. A manifest must LIST the
  // packets it covers, and the match is an exact path.
  //
  // THE SURFACE SIZE PRINTS ON EVERY RUN. `PACKET.md` is a convention this
  // program is only now adopting: 1 of 52 directories under docs/evidence/
  // carries one. A bar that inspects one directory must not read as though it
  // inspected fifty-two, so the count is stated rather than implied.
  const EVIDENCE = join(REPO, "docs", "evidence");
  const BASELINE_PATH = join(REPO, "scripts", "packet-convention-baseline.v1.json");
  // ENUMERATE FROM TRACKED BYTES, NOT FROM THE WORKING COPY. .gitignore line 58
  // ignores docs/evidence/* wholesale and individual directories are force-added,
  // so a working copy holds evidence trees that exist on ONE machine and in no
  // commit -- 52 directories on this disk, 6 in the repository.
  //
  // The first version of this ratchet read the disk. Its baseline pinned 46
  // directories that no reviewer, no other machine, and no CI run can see, and
  // the gate's OWN stale-pin tooth refused all 46 the moment it ran detached.
  // The enumerator and the baseline must read the same source, or the bar
  // reports a different world depending on where it runs.
  const allDirs = [...new Set(
    execSync("git ls-files docs/evidence", { cwd: REPO, maxBuffer: 1e9 })
      .toString().split("\n").filter(Boolean)
      .map((p) => p.split("/")[2]).filter(Boolean),
  )].sort();
  // THE RATCHET. Directories predating the convention are pinned in a baseline
  // that may only SHRINK -- the same idiom as the agentgres ref-minting pin.
  // Everything NOT on it must carry PACKET.md and be named by a manifest.
  const baseline = existsSync(BASELINE_PATH)
    ? new Set(JSON.parse(readFileSync(BASELINE_PATH, "utf8")).directories ?? [])
    : new Set();
  // SHRINK-ONLY, ENFORCED AGAINST THE COMMITTED BASELINE.
  //
  // The rule was prose in the ruling and prose in the file's own `monotone`
  // field, and prose loses to a default -- this program has the ledger entry to
  // prove it. Measured: appending a directory to the baseline silenced the bar
  // completely. A convention that can be escaped by declaring the escape is not
  // a ratchet; it is a comment.
  //
  // Entries may only be REMOVED relative to the committed version. On the commit
  // that introduces the file there is no previous version, and bootstrap is
  // allowed -- the same shape as the attestation chain's first-parent handling.
  let committedBaseline = null;
  try {
    // HEAD^, NEVER HEAD. The commit under evaluation may not vouch for its own
    // bytes -- the exact sentence already written in check-attestation-chain,
    // which fixed this class at the git layer weeks ago.
    //
    // Reading HEAD made the ratchet self-attesting: once a commit added a
    // directory to the baseline AND committed it, the "committed baseline" the
    // check consulted was the very commit under evaluation, so the addition
    // proved itself legal by pointing at itself. The shrink-only rule held only
    // for uncommitted edits, which is the one case nobody ships.
    //
    // FOURTH APPEARANCE of self-attestation in this program. It is not a bug
    // that keeps being reintroduced; it is a default that keeps winning, which
    // is why the cure is a precedent to copy rather than a lesson to remember.
    committedBaseline = new Set(JSON.parse(
      execSync("git show HEAD^:scripts/packet-convention-baseline.v1.json", { cwd: REPO }).toString(),
    ).directories ?? []);
  } catch { committedBaseline = null; }
  if (committedBaseline !== null) {
    for (const name of baseline) {
      if (!committedBaseline.has(name)) {
        findings.push(finding("error", "claims-coverage",
          `packet-convention baseline ADDS ${name}, which the committed baseline does not hold — the ratchet ` +
          `is shrink-only. A directory postdating the convention cannot be exempted from it by being ` +
          `written into the exemption list.`));
      }
    }
  }
  for (const name of baseline) {
    if (!allDirs.includes(name)) {
      findings.push(finding("error", "claims-coverage",
        `packet-convention baseline pins ${name}, which no longer exists under docs/evidence/ — ` +
        `a ratchet that names nothing cannot shrink honestly`));
    }
  }
  const trackedPackets = new Set(
    execSync("git ls-files docs/evidence", { cwd: REPO, maxBuffer: 1e9 })
      .toString().split("\n").filter((p) => p.endsWith("/PACKET.md")),
  );
  const governed = allDirs.filter((name) => !baseline.has(name));
  const declaredPackets = new Set(
    manifests.flatMap((name) =>
      JSON.parse(readFileSync(join(COVERAGE_DIR, name), "utf8")).packets ?? []),
  );
  for (const name of governed) {
    const packet = `docs/evidence/${name}/PACKET.md`;
    if (!trackedPackets.has(packet)) {
      findings.push(finding("error", "claims-coverage",
        `docs/evidence/${name}/ postdates the PACKET.md convention and carries NO PACKET.md — ` +
        `the baseline is shrink-only, so a new directory cannot be added to it`));
      continue;
    }
    if (!declaredPackets.has(packet)) {
      findings.push(finding("error", "claims-coverage",
        `${packet} is published but NO claims manifest declares it in its "packets" list — a packet the ` +
        `claims gate cannot see is unmapped by construction, which is include-list fail-open`));
    }
  }
  for (const declared of declaredPackets) {
    if (!existsSync(join(REPO, declared))) {
      findings.push(finding("error", "claims-coverage",
        `a claims manifest declares packet ${declared}, which does not exist — a declaration that names ` +
        `nothing cannot be discharged by anything`));
    }
  }
  console.log(
    `[WARN] claims-coverage: packet convention — ${governed.length} governed directory(ies) of ${allDirs.length}; ` +
    `${baseline.size} pinned as pre-convention (shrink-only); ${declaredPackets.size} packet(s) declared by a manifest`,
  );

  const errors = findings.filter((f) => f.severity === "error");
  for (const f of findings) {
    console.log(`[${f.severity.toUpperCase()}] ${f.kind}: ${f.message}`);
  }
  console.log(
    `claims-coverage: ${totalCovered}/${totalClaims} claim(s) covered by an executed check with retained passing bytes; ${
      selfTestFailures.length === 0
        ? `${SELF_TEST_CASE_COUNT} predeclared cases self-tested`
        : "SELF-TEST FAILING"
    }`,
  );
  console.log(
    `check-claims-coverage: ${errors.length === 0 ? "PASS" : "FAIL"} (${errors.length} error, 0 warn, 0 skip)`,
  );
  process.exit(errors.length === 0 ? 0 : 1);
}

if (import.meta.url === `file://${process.argv[1]}`) main();
