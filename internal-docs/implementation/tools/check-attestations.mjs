#!/usr/bin/env node
// Every digest recorded in an attestation must resolve against a file that
// exists. An attestation that cannot be re-derived is worse than no
// attestation: it asserts provenance nobody can check.
//
// Two kinds of attestation are checked differently, and conflating them is what
// made an earlier repair edit history:
//
//   CURRENT  — the digest a record is expected to carry right now. Verified
//              against the file's actual bytes.
//   HISTORICAL — a digest that was current at some past moment and has since
//              been superseded. It is NOT checked against today's bytes (it
//              would always fail); it is checked as a link in the
//              re-attestation chain that supersedes it.
//
// A historical attestation is only excused from the byte check when a
// re-attestation explicitly names it as superseded. There is no way to retire a
// claim by simply asserting it is old.
//
//   node tools/check-attestations.mjs [--json]
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import {
  ESTATE_ROOT,
  finding,
  progress,
  readJson,
  REPO_ROOT,
  report,
  sha256File,
} from "./lib/estate.mjs";

const CLAIM_CORRECTIONS_REL = "_archive/attestations/claim-corrections.v1.json";
const CLAIM_CORRECTIONS_FORMAT = "ioi.program.claim_corrections.v1";

const DIGEST_FIELDS = [
  ["private_record", "private_record_sha256_after"],
  ["source_of_record", "source_sha256"],
];

function resolve(rel) {
  for (const base of [REPO_ROOT, ESTATE_ROOT]) {
    const p = path.join(base, rel);
    if (fs.existsSync(p)) return p;
  }
  const stripped = rel.replace(/^internal-docs\/implementation\//, "");
  const p = path.join(ESTATE_ROOT, stripped);
  return fs.existsSync(p) ? p : null;
}

// Chains of re-attestation, keyed by the record path they bind. Each chain is
// ordered and each link names the digest it supersedes.
function loadReattestationChains(findings) {
  const ledgerPath = path.join(
    ESTATE_ROOT,
    "_archive",
    "attestations",
    "record-reattestations.v1.json",
  );
  const chains = new Map();
  if (!fs.existsSync(ledgerPath)) return chains;

  const ledger = readJson(ledgerPath);
  const entries = [...(ledger.entries ?? [])];

  // The ledger is append-only; a gap or reordering means an entry was rewritten
  // or removed, which is exactly the history edit this mechanism exists to stop.
  entries.forEach((entry, index) => {
    if (entry.sequence !== index + 1) {
      findings.push(
        finding(
          "error",
          "reattestation-sequence",
          `re-attestation ledger entry ${index + 1} carries sequence ${entry.sequence}; the ledger is append-only and its sequence must be dense and ordered`,
        ),
      );
    }
    if (entry.claim !== "record_integrity_only") {
      findings.push(
        finding(
          "error",
          "reattestation-claim",
          `re-attestation ${entry.sequence} claims "${entry.claim}"; a re-attestation binds record integrity only and may not claim implementation proof`,
        ),
      );
    }
  });

  for (const entry of entries) {
    const chain = chains.get(entry.private_record) ?? [];
    chain.push(entry);
    chains.set(entry.private_record, chain);
  }

  // Each link must supersede the digest the previous link established, and the
  // last link must match the record's bytes as they stand.
  for (const [rel, chain] of chains) {
    for (let i = 1; i < chain.length; i += 1) {
      if (chain[i].supersedes_sha256 !== chain[i - 1].private_record_sha256) {
        findings.push(
          finding(
            "error",
            "reattestation-chain",
            `${rel}: re-attestation ${chain[i].sequence} supersedes ${chain[i].supersedes_sha256}, but the previous link established ${chain[i - 1].private_record_sha256}`,
          ),
        );
      }
    }
    const head = chain[chain.length - 1];
    const absolute = resolve(rel);
    if (!absolute) {
      findings.push(
        finding(
          "error",
          "reattestation-path",
          `${rel} is re-attested but does not resolve`,
        ),
      );
      continue;
    }
    const actual = sha256File(absolute);
    if (actual !== head.private_record_sha256) {
      findings.push(
        finding(
          "error",
          "reattestation-head",
          `${rel}: the newest re-attestation binds ${head.private_record_sha256} but the file digests to ${actual}`,
        ),
      );
    }
  }
  return chains;
}


// --- CLAIM CORRECTIONS -----------------------------------------------------
//
// Some wrong claims live in bytes that must NOT change. A withdrawn record's
// retained log is the evidence that the claim was made; editing the line would
// destroy exactly what the withdrawal preserves. So "supersede in place" means
// the text stays and a dated correction is recorded beside it — and a recorded
// correction that nothing checks is a note.
//
// This checks the two ways such a correction rots: the superseded text quietly
// disappearing from the location it names (a correction about nothing), and the
// cited derived artifact going missing or ceasing to reconcile (a correction
// with no truth behind it).
export function evaluateClaimCorrections({ ledger, readLocation, readDerived }) {
  const out = [];
  if (ledger === null) return out;
  if (ledger.evidence_format !== CLAIM_CORRECTIONS_FORMAT) {
    out.push(
      finding("error", "claim-correction", `${CLAIM_CORRECTIONS_REL} declares format "${ledger.evidence_format}"; expected "${CLAIM_CORRECTIONS_FORMAT}"`),
    );
    return out;
  }
  for (const c of ledger.corrections ?? []) {
    const id = c.correction_id ?? "(unnamed)";
    const location = c.superseded_claim?.location ?? null;
    const text = c.superseded_claim?.exact_text ?? null;
    if (!location || !text || !c.dated || !c.derived_from) {
      out.push(
        finding("error", "claim-correction", `${id}: a correction must name a location, the exact superseded text, a date, and the derived artifact its ratified truth comes from`),
      );
      continue;
    }
    const body = readLocation(location);
    if (body === null) {
      out.push(
        finding("error", "claim-correction-location", `${id}: names location ${location}, which does not resolve`),
      );
    } else if (!body.includes(text)) {
      out.push(
        finding(
          "error",
          "claim-correction-location",
          `${id}: the superseded text is no longer present at ${location}. Either the bytes were edited — which this correction exists precisely to avoid — or the correction is pointing at something that no longer says what it corrects.`,
        ),
      );
    }
    const derived = readDerived(c.derived_from);
    if (derived === null) {
      out.push(
        finding("error", "claim-correction-derivation", `${id}: cites derived artifact ${c.derived_from}, which does not resolve`),
      );
      continue;
    }
    const truth = c.ratified_truth ?? {};
    for (const [key, value] of Object.entries(truth)) {
      if (key === "total_after") continue;
      if (derived.counts?.[key] !== value) {
        out.push(
          finding(
            "error",
            "claim-correction-derivation",
            `${id}: ratified ${key} is ${value} and the derived artifact reports ${derived.counts?.[key]}. A correction may cite a derivation; it may not disagree with it.`,
          ),
        );
      }
    }
    const partition = ["admitted_identity", "retired_identity", "locator_rebind", "judgment_change", "unchanged", "review_provenance_restamped_only"]
      .reduce((a, k) => a + (truth[k] ?? 0), 0);
    if (truth.total_after !== undefined && partition !== truth.total_after) {
      out.push(
        finding(
          "error",
          "claim-correction-derivation",
          `${id}: the ratified partition sums to ${partition} and declares total_after ${truth.total_after}. An exhaustive population reconciliation that does not reconcile is not exhaustive.`,
        ),
      );
    }
  }
  return out;
}

// Fail-closed self-test: a correction bar whose refusals never fire cannot tell
// a live correction from a forgotten one.
function claimCorrectionSelfTest() {
  const out = [];
  const good = {
    evidence_format: CLAIM_CORRECTIONS_FORMAT,
    corrections: [{
      correction_id: "cc-test",
      dated: "2026-07-29",
      superseded_claim: { location: "a.txt", exact_text: "six" },
      derived_from: "d.json",
      ratified_truth: { admitted_identity: 1, retired_identity: 0, locator_rebind: 1, judgment_change: 1, unchanged: 1, review_provenance_restamped_only: 1, total_after: 5 },
    }],
  };
  const derived = { counts: { admitted_identity: 1, retired_identity: 0, locator_rebind: 1, judgment_change: 1, unchanged: 1, review_provenance_restamped_only: 1 } };
  const cases = [
    ["claim-correction", { ...good, evidence_format: "other" }, () => "six", () => derived],
    ["claim-correction", { ...good, corrections: [{ correction_id: "x" }] }, () => "six", () => derived],
    ["claim-correction-location", good, () => null, () => derived],
    ["claim-correction-location", good, () => "the text was edited away", () => derived],
    ["claim-correction-derivation", good, () => "six", () => null],
    ["claim-correction-derivation", good, () => "six", () => ({ counts: { ...derived.counts, judgment_change: 6 } })],
    ["claim-correction-derivation", { ...good, corrections: [{ ...good.corrections[0], ratified_truth: { ...good.corrections[0].ratified_truth, total_after: 99 } }] }, () => "six", () => derived],
  ];
  for (const [expected, ledger, readLocation, readDerived] of cases) {
    const checks = evaluateClaimCorrections({ ledger, readLocation, readDerived }).map((f) => f.check);
    if (!checks.includes(expected)) {
      out.push(
        finding("error", "self-test", `the ${expected} refusal did not fire against its synthetic bad input (got: ${[...new Set(checks)].join(", ") || "nothing"})`),
      );
    }
  }
  if (evaluateClaimCorrections({ ledger: good, readLocation: () => "six", readDerived: () => derived }).length !== 0) {
    out.push(finding("error", "self-test", "well-formed claim corrections were rejected"));
  }
  return out;
}

function main() {
  const findings = [];
  const chains = loadReattestationChains(findings);
  const dir = path.join(ESTATE_ROOT, "_archive", "migrations");
  const files = fs.existsSync(dir)
    ? fs.readdirSync(dir).filter((f) => f.endsWith(".json"))
    : [];
  let checked = 0;

  for (const file of files) {
    let doc;
    try {
      doc = readJson(path.join(dir, file));
    } catch {
      findings.push(
        finding("error", "attestation-unreadable", `_archive/migrations/${file} is not valid JSON`),
      );
      continue;
    }
    for (const entry of doc.entries ?? []) {
      for (const [pathField, digestField] of DIGEST_FIELDS) {
        const rel = entry[pathField];
        const expected = entry[digestField];
        if (!rel || !expected) continue;
        checked += 1;
        const absolute = resolve(rel);
        if (!absolute) {
          findings.push(
            finding(
              "error",
              "attestation-path",
              `${file}: ${pathField} does not resolve: ${rel}`,
            ),
          );
          continue;
        }
        const actual = sha256File(absolute);
        if (actual === expected) continue;

        // A superseded claim is verified as a chain link, not against today's
        // bytes — but ONLY if a re-attestation names this exact digest as the
        // one it supersedes. Anything else is still a broken attestation.
        const chain = chains.get(rel);
        if (chain && chain[0].supersedes_sha256 === expected) continue;

        findings.push(
          finding(
            "error",
            "attestation-digest",
            chain
              ? `${file}: ${digestField} for ${rel} is ${expected} but the file digests to ${actual}, and the re-attestation chain supersedes ${chain[0].supersedes_sha256}, not ${expected}`
              : `${file}: ${digestField} for ${rel} is ${expected} but the file digests to ${actual}`,
          ),
        );
      }
    }
  }

  // The migration manifest's move entries must land where they say they landed.
  const manifest = path.join(ESTATE_ROOT, "_archive", "manifests", "migration-manifest.v1.json");
  if (fs.existsSync(manifest)) {
    for (const e of readJson(manifest).entries ?? []) {
      if (e.action !== "move" || e.is_directory || !e.new_path) continue;
      checked += 1;
      // A work-item record legitimately relocates between the proposed/ and
      // active/ status directories via sort-work-items.mjs as its status
      // advances; the manifest is a historical record and is never rewritten
      // to follow. Accept the sanctioned sibling location, nothing else.
      const statusSibling = /work-items\/(proposed|active)\//u.test(e.new_path)
        ? e.new_path.replace(
          /work-items\/(proposed|active)\//u,
          (m, dir) => `work-items/${dir === "proposed" ? "active" : "proposed"}/`,
        )
        : null;
      if (!resolve(e.new_path) && !(statusSibling && resolve(statusSibling))) {
        findings.push(
          finding(
            "error",
            "manifest-move",
            `migration manifest records a move to ${e.new_path}, which does not exist`,
          ),
        );
      }
    }
    for (const e of readJson(manifest).entries ?? []) {
      if (e.action !== "delete" || !e.recovery_source) continue;
      checked += 1;
      const src = e.recovery_source.split(" (")[0];
      if (src.startsWith("internal-docs/implementation/") && !resolve(src)) {
        findings.push(
          finding(
            "error",
            "manifest-recovery",
            `deletion of ${e.old_path} names recovery source ${src}, which does not exist`,
          ),
        );
      }
    }
  }

  findings.push(...claimCorrectionSelfTest());
  const correctionsAbs = path.join(ESTATE_ROOT, CLAIM_CORRECTIONS_REL);
  const corrections = fs.existsSync(correctionsAbs) ? readJson(correctionsAbs) : null;
  findings.push(
    ...evaluateClaimCorrections({
      ledger: corrections,
      readLocation: (rel) => {
        const abs = resolve(rel);
        return abs ? fs.readFileSync(abs, "utf8") : null;
      },
      readDerived: (rel) => {
        const abs = resolve(rel);
        return abs ? readJson(abs) : null;
      },
    }),
  );

  progress(
    `checked ${checked} attestation binding(s); ${(corrections?.corrections ?? []).length} superseded claim correction(s) re-checked at source`,
  );
  process.exit(
    report("check-attestations", findings, { json: process.argv.includes("--json") }),
  );
}

if (import.meta.url === `file://${process.argv[1]}`) main();
