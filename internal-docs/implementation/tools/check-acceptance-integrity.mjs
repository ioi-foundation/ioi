#!/usr/bin/env node
// Acceptance-ledger integrity bar.
//
//   node tools/check-acceptance-integrity.mjs [--check]
//
// Every entry in _archive/attestations/canon-acceptances.v1.json claims that a
// named reviewer enumerated and dispositioned a set of drifted canon subjects,
// and binds that claim to a review manifest BY DIGEST. Until 2026-07-29 the
// path it recorded was volatile (`/tmp/review-manifest.json`): the digest was
// bound to a body that no later reader could produce. An attestation whose
// evidence cannot be re-read is a claim, not an attestation.
//
// This bar resolves every ledger entry to a RETAINED manifest body and checks
// that the body still digests to what the ledger recorded:
//
//   1. RESOLUTION — content address first, then the content-addressed
//      directory, then the preservation sidecar. An entry that resolves through
//      none of them is `manifest-unresolvable`.
//   2. DIGEST — the retained body must digest to the ledger's
//      review_manifest_sha256. A mismatch is `manifest-digest-mismatch`: the
//      body on disk is not the body that was reviewed.
//   3. CONTENT — the retained body must be a conforming review manifest, and
//      its subject ids and dispositions must be exactly what the ledger
//      recorded. A body that disagrees with the ledger entry that binds it is
//      `manifest-ledger-divergence`.
//   4. VOLATILE PATH — an entry whose only recorded location is a mutable path
//      is reported even when it resolves, because the remediation is a sidecar
//      and the fix is the content address.
//   5. SEQUENCE — dense and ordered, or the append-only ledger was rewritten.
//
// It proves that the review evidence still exists and still matches. It proves
// nothing about whether the review was correct.
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import {
  ESTATE_ROOT,
  finding,
  readJson,
  report,
  sha256File,
} from "./lib/estate.mjs";

const LEDGER_REL = "_archive/attestations/canon-acceptances.v1.json";
const MANIFEST_DIR_REL = "_archive/attestations/review-manifests";
const SIDECAR_REL = `${MANIFEST_DIR_REL}/preservation-attestation.v1.json`;
const MANIFEST_FORMAT = "ioi.program.canon_review_manifest.v1";
const REVIEW_CLAIM = "canon_drift_reviewed_only";
const VOLATILE = /^(?:\/tmp\/|\/var\/tmp\/|\/private\/var\/folders\/|[^/]*$)/u;

// Resolution order is deliberate: the content address the acceptance itself
// recorded, then the content-addressed directory keyed by the ledgered digest,
// then the preservation sidecar that remediated the two historical entries.
function resolveManifest(entry, sidecar) {
  const candidates = [];
  if (entry.review_manifest_content_address) {
    candidates.push([entry.review_manifest_content_address, "content_address"]);
  }
  if (entry.review_manifest_sha256) {
    candidates.push([
      `${MANIFEST_DIR_REL}/${entry.review_manifest_sha256}.json`,
      "content_addressed_directory",
    ]);
  }
  const preserved = (sidecar?.manifests ?? []).find((m) =>
    m.acceptance_sequence === entry.sequence
  );
  if (preserved?.preserved_body_path) {
    candidates.push([preserved.preserved_body_path, "preservation_sidecar"]);
  }
  for (const [rel, via] of candidates) {
    const abs = path.join(ESTATE_ROOT, rel);
    if (fs.existsSync(abs)) return { rel, abs, via };
  }
  return null;
}

function main() {
  const findings = [];
  const ledgerAbs = path.join(ESTATE_ROOT, LEDGER_REL);
  if (!fs.existsSync(ledgerAbs)) {
    findings.push(
      finding("error", "ledger-missing", `acceptance ledger does not exist: ${LEDGER_REL}`),
    );
    process.exit(report("check-acceptance-integrity", findings));
  }
  const ledger = readJson(ledgerAbs);
  const sidecarAbs = path.join(ESTATE_ROOT, SIDECAR_REL);
  const sidecar = fs.existsSync(sidecarAbs) ? readJson(sidecarAbs) : null;

  const entries = ledger.entries ?? [];
  let resolved = 0;
  const resolvedBodies = new Set();

  entries.forEach((entry, index) => {
    const where = `acceptance ${entry.sequence ?? `[${index}]`}`;
    if (entry.sequence !== index + 1) {
      findings.push(
        finding(
          "error",
          "ledger-sequence",
          `${where} is at position ${index + 1}; an append-only ledger's sequence is dense and ordered, so this entry was rewritten, reordered, or removed`,
        ),
      );
    }
    if (!entry.review_manifest_sha256) {
      findings.push(
        finding(
          "error",
          "manifest-unbound",
          `${where} binds no review_manifest_sha256; the acceptance is bound to nothing`,
        ),
      );
      return;
    }

    const found = resolveManifest(entry, sidecar);
    if (!found) {
      findings.push(
        finding(
          "error",
          "manifest-unresolvable",
          `${where} names review manifest ${entry.review_manifest_sha256} and no retained body resolves for it (looked for a content address, ${MANIFEST_DIR_REL}/<digest>.json, and the preservation sidecar). An acceptance whose review evidence cannot be produced substantiates nothing.`,
          { sequence: entry.sequence },
        ),
      );
      return;
    }
    resolved += 1;
    resolvedBodies.add(found.rel);

    const digest = sha256File(found.abs);
    if (digest !== entry.review_manifest_sha256) {
      findings.push(
        finding(
          "error",
          "manifest-digest-mismatch",
          `${where}: retained body ${found.rel} digests to ${digest} but the ledger recorded ${entry.review_manifest_sha256}; the body on disk is not the body that was reviewed`,
          { sequence: entry.sequence },
        ),
      );
      return;
    }

    let body = null;
    try {
      body = readJson(found.abs);
    } catch {
      findings.push(
        finding("error", "manifest-unreadable", `${where}: retained body ${found.rel} is not valid JSON`),
      );
      return;
    }
    if (body.evidence_format !== MANIFEST_FORMAT) {
      findings.push(
        finding(
          "error",
          "manifest-format",
          `${where}: retained body declares evidence_format "${body.evidence_format}"; expected "${MANIFEST_FORMAT}"`,
        ),
      );
    }
    if (body.claim !== REVIEW_CLAIM) {
      findings.push(
        finding(
          "error",
          "manifest-claim",
          `${where}: retained body claims "${body.claim}"; a review manifest binds "${REVIEW_CLAIM}"`,
        ),
      );
    }

    // The ledger's copy of the dispositions must be exactly the manifest's.
    const bodyById = new Map(
      (body.subjects ?? []).map((s) => [s.id, s.disposition]),
    );
    const ledgerById = new Map(
      (entry.subjects_reviewed ?? []).map((s) => [s.id, s.disposition]),
    );
    for (const [id, disposition] of ledgerById) {
      if (!bodyById.has(id)) {
        findings.push(
          finding(
            "error",
            "manifest-ledger-divergence",
            `${where}: the ledger records subject ${id} that the retained manifest never names`,
            { sequence: entry.sequence, subject: id },
          ),
        );
      } else if (bodyById.get(id) !== disposition) {
        findings.push(
          finding(
            "error",
            "manifest-ledger-divergence",
            `${where}: ${id} is "${disposition}" in the ledger and "${bodyById.get(id)}" in the retained manifest`,
            { sequence: entry.sequence, subject: id },
          ),
        );
      }
    }
    for (const id of bodyById.keys()) {
      if (!ledgerById.has(id)) {
        findings.push(
          finding(
            "error",
            "manifest-ledger-divergence",
            `${where}: the retained manifest names subject ${id} that the ledger never recorded`,
            { sequence: entry.sequence, subject: id },
          ),
        );
      }
    }

    // A resolved body does not retroactively make a volatile path acceptable.
    const recordedPath = entry.review_manifest_content_address ??
      entry.review_manifest_path_at_acceptance ?? entry.review_manifest ?? null;
    if (
      !entry.review_manifest_content_address && recordedPath &&
      VOLATILE.test(recordedPath)
    ) {
      findings.push(
        finding(
          "warn",
          "volatile-manifest-path",
          `${where} recorded its review manifest at the mutable path ${recordedPath} and carries no content address; it resolves today only through ${found.via}. Acceptances written after this bar record a content address.`,
          { sequence: entry.sequence },
        ),
      );
    }
  });

  // --- the sidecar itself must be true
  for (const preserved of sidecar?.manifests ?? []) {
    const abs = path.join(ESTATE_ROOT, preserved.preserved_body_path ?? "");
    if (!preserved.preserved_body_path || !fs.existsSync(abs)) {
      findings.push(
        finding(
          "error",
          "sidecar-body-missing",
          `preservation sidecar names a body that does not exist: ${preserved.preserved_body_path ?? "(none)"}`,
        ),
      );
      continue;
    }
    const digest = sha256File(abs);
    if (preserved.ledgered_sha256 && digest !== preserved.ledgered_sha256) {
      findings.push(
        finding(
          "error",
          "sidecar-digest-mismatch",
          `preservation sidecar claims ${preserved.preserved_body_path} digests to ${preserved.ledgered_sha256}; it digests to ${digest}`,
        ),
      );
    }
    if (!entries.some((e) => e.sequence === preserved.acceptance_sequence)) {
      findings.push(
        finding(
          "error",
          "sidecar-orphan",
          `preservation sidecar preserves a manifest for acceptance sequence ${preserved.acceptance_sequence}, which the ledger does not contain`,
        ),
      );
    }
  }

  // --- a retained body nobody references is unexplained retention
  const dirAbs = path.join(ESTATE_ROOT, MANIFEST_DIR_REL);
  if (fs.existsSync(dirAbs)) {
    for (const file of fs.readdirSync(dirAbs).sort()) {
      if (!file.endsWith(".json") || file === path.basename(SIDECAR_REL)) continue;
      const rel = `${MANIFEST_DIR_REL}/${file}`;
      if (!resolvedBodies.has(rel)) {
        findings.push(
          finding(
            "warn",
            "unreferenced-manifest-body",
            `${rel} is retained but no acceptance entry resolves to it`,
          ),
        );
      }
    }
  }

  process.stdout.write(
    `acceptance integrity: ${entries.length} entr(ies), ${resolved} resolved to a retained manifest body\n`,
  );
  process.exit(report("check-acceptance-integrity", findings));
}

if (import.meta.url === `file://${process.argv[1]}`) main();
