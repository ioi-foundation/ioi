#!/usr/bin/env node
// Attestation-chain integrity: append-only across history, bindings resolve.
//
// WHY THIS EXISTS. The standing rule is "extend within a review date, append
// across dates". It was violated twice, one sequence apart, and not because
// anyone decided to violate it: the fixpoint loop that closes M0 commitments
// rewrites the LAST anchor entry every iteration, so under fixpoint pressure
// the tool's default — head extension — silently won over the rule. A rule
// that contradicts a default loses to the default.
//
// So the default now refuses. Two bars, both cheap enough to run per push:
//
//  1. APPEND-ONLY ACROSS HISTORY. Every anchor entry present in the
//     first-parent commit's anchor must be byte-identical in this one. Only
//     appends are legal. This fires on the commit that contains the rewrite,
//     not on a review two days later — which is the whole difference between
//     a control and a post-mortem.
//
//  2. BINDINGS RESOLVE. Every digest-bound sidecar must resolve against the
//     current anchor. A sidecar that names an entry digest no longer in the
//     chain is evidence describing something that no longer exists.
//
// Only the head entry of a hash chain can be rewritten without breaking a
// predecessor's hash — which is exactly why the head is the one thing that
// must never be edited. The chain protects everything except the place the
// pressure lands.

import { execSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, "..");
const ANCHOR = "docs/evidence/m0-program-control/review-epoch-anchor.json";
const SIDECAR_DIR = join(REPO, "docs", "evidence", "m5-event-substrate");

function stableStringify(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${stableStringify(value[k])}`).join(",")}}`;
}

/// Pure so the self-test drives the same predicate the run drives.
/// `wasHeldBefore(sequence, bytes)` answers whether this entry ever held these
/// exact bytes earlier in history. It is what distinguishes a RESTORE from a
/// rewrite — and it is checkable, not a declared exemption. A repair that puts
/// a corrupted entry back to bytes it demonstrably held is the only legal
/// non-append, because it removes a mutation rather than adding one.
export function evaluateAppendOnly(previousEpochs, currentEpochs, wasHeldBefore = () => false) {
  const findings = [];
  const current = new Map((currentEpochs ?? []).map((e) => [e.sequence, e]));
  for (const before of previousEpochs ?? []) {
    const after = current.get(before.sequence);
    if (after === undefined) {
      findings.push(`anchor entry sequence ${before.sequence} was DELETED; the chain is append-only`);
      continue;
    }
    if (stableStringify(before) !== stableStringify(after)) {
      if (wasHeldBefore(before.sequence, stableStringify(after))) {
        continue; // RESTORE: these exact bytes are what this entry held earlier.
      }
      const fields = [...new Set([...Object.keys(before), ...Object.keys(after)])]
        .filter((k) => stableStringify(before[k]) !== stableStringify(after[k]));
      findings.push(
        `anchor entry sequence ${before.sequence} was REWRITTEN in place (fields: ${fields.join(", ")}); ` +
        `an across-dates review requires an APPEND, and only the head is rewritable without breaking a predecessor — ` +
        `which is why the head must never be edited`,
      );
    }
  }
  return findings;
}

export function evaluateBindings(anchorEpochs, sidecars, digestOf) {
  const findings = [];
  const digests = new Set((anchorEpochs ?? []).map((e) => digestOf(e)));
  for (const { name, bound, sequence } of sidecars) {
    if (!digests.has(bound)) {
      findings.push(
        `${name} binds entry digest ${String(bound).slice(0, 12)} (sequence ${sequence}) which resolves against NO entry in the current anchor; ` +
        `the evidence describes an entry that no longer exists`,
      );
    }
  }
  return findings;
}

let SELF_TEST_CASES = 0;
function selfTest() {
  const failures = [];
  const base = [{ sequence: 1, a: "x" }, { sequence: 2, a: "y" }];
  const cases = [
    ["an append is legal", () => evaluateAppendOnly(base, [...base, { sequence: 3, a: "z" }]).length === 0],
    ["an unchanged chain is legal", () => evaluateAppendOnly(base, base).length === 0],
    ["a head rewrite is REFUSED", () => evaluateAppendOnly(base, [{ sequence: 1, a: "x" }, { sequence: 2, a: "CHANGED" }]).length === 1],
    ["a mid-chain rewrite is REFUSED", () => evaluateAppendOnly(base, [{ sequence: 1, a: "CHANGED" }, { sequence: 2, a: "y" }]).length === 1],
    ["a deletion is REFUSED", () => evaluateAppendOnly(base, [{ sequence: 1, a: "x" }]).length === 1],
    ["a RESTORE to bytes the entry demonstrably held is legal", () =>
      evaluateAppendOnly(base, [{ sequence: 1, a: "x" }, { sequence: 2, a: "ORIG" }],
        (seq, bytes) => seq === 2 && bytes === stableStringify({ sequence: 2, a: "ORIG" })).length === 0],
    ["a rewrite to bytes never held is still REFUSED", () =>
      evaluateAppendOnly(base, [{ sequence: 1, a: "x" }, { sequence: 2, a: "NOVEL" }],
        (seq, bytes) => seq === 2 && bytes === stableStringify({ sequence: 2, a: "ORIG" })).length === 1],
    ["a resolving binding is legal", () => evaluateBindings([{ sequence: 1 }], [{ name: "s", bound: "D1", sequence: 1 }], () => "D1").length === 0],
    ["a dangling binding is REFUSED", () => evaluateBindings([{ sequence: 1 }], [{ name: "s", bound: "GONE", sequence: 1 }], () => "D1").length === 1],
  ];
  for (const [label, run] of cases) {
    SELF_TEST_CASES += 1;
    let ok = false;
    try { ok = run(); } catch { ok = false; }
    if (!ok) failures.push(`self-test case "${label}" did not behave as declared`);
  }
  return failures;
}

async function main() {
  const findings = selfTest();

  const anchorPath = join(REPO, ANCHOR);
  if (!existsSync(anchorPath)) {
    console.log("check-attestation-chain: PASS (no anchor present)");
    process.exit(0);
  }
  const current = JSON.parse(readFileSync(anchorPath, "utf8"));

  // Append-only against the FIRST PARENT, so the bar fires on the commit that
  // contains the rewrite.
  let previous = null;
  try {
    previous = JSON.parse(execSync(`git show HEAD^:${ANCHOR}`, { cwd: REPO }).toString());
  } catch { previous = null; }
  if (previous !== null) {
    const heldBefore = (sequence, bytes) => {
      try {
        // HEAD^ AND ITS ANCESTORS — never HEAD. The commit under evaluation
        // may not vouch for its own bytes. Searching from HEAD let a commit
        // containing novel rewritten bytes prove they "were held before" by
        // pointing at itself: self-attestation, the invisible-evidence class
        // at the git layer. Restoration legality is a fact about history
        // BEFORE this commit, so that is the only history consulted.
        const revs = execSync(`git rev-list --max-count=60 HEAD^ -- ${ANCHOR}`, { cwd: REPO })
          .toString().trim().split("\n").filter(Boolean);
        return revs.some((rev) => {
          try {
            const epochs = JSON.parse(execSync(`git show ${rev}:${ANCHOR}`, { cwd: REPO, maxBuffer: 1e9 }).toString()).epochs ?? [];
            const found = epochs.find((e) => e.sequence === sequence);
            return found !== undefined && stableStringify(found) === bytes;
          } catch { return false; }
        });
      } catch { return false; }
    };
    findings.push(...evaluateAppendOnly(previous.epochs, current.epochs, heldBefore));
  }

  // Bindings resolve, using the model's own digest function.
  const { reviewAnchorEntrySha256 } = await import(
    join(REPO, "scripts", "lib", "m0-program-control-model.mjs")
  );
  const sidecars = existsSync(SIDECAR_DIR)
    ? readdirSync(SIDECAR_DIR)
        .filter((n) => n.includes("split") && n.endsWith(".json"))
        .map((n) => {
          const body = JSON.parse(readFileSync(join(SIDECAR_DIR, n), "utf8"));
          return { name: n, bound: body.bound_entry_sha256, sequence: body.sequence };
        })
    : [];
  findings.push(...evaluateBindings(current.epochs, sidecars, reviewAnchorEntrySha256));

  for (const f of findings) console.log(`[ERROR] attestation-chain: ${f}`);
  console.log(
    `attestation-chain: ${current.epochs.length} anchor entries, ${sidecars.length} bound sidecar(s); ${SELF_TEST_CASES} predeclared cases self-tested`,
  );
  console.log(
    `check-attestation-chain: ${findings.length === 0 ? "PASS" : "FAIL"} (${findings.length} error, 0 warn, 0 skip)`,
  );
  process.exit(findings.length === 0 ? 0 : 1);
}

main();
