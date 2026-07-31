#!/usr/bin/env node
// Fixture test for the architecture-impact mechanism.
//
//   node tools/test-canon-impact.mjs
//
// Proves, against a throwaway fixture repository, that:
//   1. a clean fixture reports no impact and no orphans;
//   2. ADDING a canon file produces a BOUNDED report — the new subject is
//      reported as an orphan, and no unrelated stage, module, or work item is
//      named;
//   3. MODIFYING a mapped canon file names exactly the stages, modules, and work
//      items bound to that subject, and nothing else;
//   4. REMOVING a mapped canon file fails closed rather than silently passing;
//   5. a superseded ADR cannot satisfy an obligation;
//   6. a module that no stage pulls is reported as unbound doctrine;
//   7. historical evidence in the fixture is untouched by any of the above;
//   8. --accept retains the reviewed manifest BODY under its content address
//      and records that address in the ledger and the baseline, never a
//      volatile path;
//   9. an admitted overlay removes an orphan only when baseline, manifest,
//      disposition, identity, and digest all agree.
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { execFileSync } from "node:child_process";
import { computeImpact } from "./canon-impact.mjs";

const TOOL = path.join(
  path.dirname(new URL(import.meta.url).pathname),
  "canon-impact.mjs",
);

function runCli(args) {
  try {
    return {
      exit: 0,
      out: execFileSync("node", [TOOL, ...args], {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      }),
    };
  } catch (error) {
    return { exit: error.status ?? 1, out: `${error.stdout ?? ""}${error.stderr ?? ""}` };
  }
}

let failures = 0;
function check(name, condition, detail = "") {
  if (condition) {
    process.stdout.write(`  ok   ${name}\n`);
  } else {
    failures += 1;
    process.stdout.write(`  FAIL ${name}${detail ? ` — ${detail}` : ""}\n`);
  }
}

function write(root, rel, content) {
  const absolute = path.join(root, rel);
  fs.mkdirSync(path.dirname(absolute), { recursive: true });
  fs.writeFileSync(absolute, content);
}

function buildFixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-canon-impact-"));
  const estate = path.join(root, "internal-docs", "implementation");

  write(root, "docs/architecture/foundations/alpha.md", "# Alpha\n\nAlpha doctrine.\n");
  write(root, "docs/architecture/foundations/beta.md", "# Beta\n\nBeta doctrine.\n");
  write(root, "docs/architecture/README.md", "# Index\n");
  write(
    root,
    "docs/decisions/0001-accepted-thing.md",
    "# ADR 0001\n\n- Status: Accepted (2026-01-01)\n",
  );
  write(
    root,
    "docs/decisions/0002-old-thing.md",
    "# ADR 0002\n\n- Status: Superseded by ADR 0001\n",
  );
  write(root, "docs/decisions/README.md", "# ADRs\n");
  write(root, "docs/conformance/README.md", "# Conformance\n");
  write(root, "docs/conformance/core/alpha-lifecycle.md", "# Alpha lifecycle\n");
  // historical evidence that must never be disturbed
  write(
    root,
    "internal-docs/implementation/_archive/evidence/2026-01-01-retained.json",
    '{"retained":true}\n',
  );

  write(
    estate,
    "program/sequence.v1.json",
    `${
      JSON.stringify(
        {
          format: "ioi.program.sequence.v1",
          stages: [
            {
              id: "S1",
              title: "One",
              depends_on: [],
              module: "stages/s1.md",
              pulled_modules: ["method-a"],
              exit_gate: { aggregate_work_item_id: "s1-exit" },
            },
            {
              id: "S2",
              title: "Two",
              depends_on: ["S1"],
              module: "stages/s2.md",
              pulled_modules: ["method-a"],
              exit_gate: { aggregate_work_item_id: "s2-exit" },
            },
          ],
          modules: [
            { id: "method-a", path: "modules/method-a.md", applies_to_stages: ["S1", "S2"] },
          ],
        },
        null,
        2,
      )
    }\n`,
  );
  write(estate, "stages/s1.md", "# S1\n");
  write(estate, "stages/s2.md", "# S2\n");
  write(estate, "modules/method-a.md", "# Method A\n");
  write(estate, "work-items/s1-exit.v1.json", '{"work_item_id":"s1-exit"}\n');
  write(estate, "work-items/s2-exit.v1.json", '{"work_item_id":"s2-exit"}\n');
  write(estate, "work-items/alpha-cut.v1.json", '{"work_item_id":"alpha-cut"}\n');
  write(estate, "work-items/beta-cut.v1.json", '{"work_item_id":"beta-cut"}\n');

  const subjects = [
    {
      id: "docs/architecture/foundations/alpha.md",
      kind: "architecture_doc",
      classification: "actively_sequenced",
      stages: ["S1"],
      modules: ["method-a"],
      work_items: ["alpha-cut"],
      contract_families: [],
      conformance_targets: ["docs/conformance/core/alpha-lifecycle.md"],
      code_anchors: [],
      proof_gates: [],
      reason: "fixture",
    },
    {
      id: "docs/architecture/foundations/beta.md",
      kind: "architecture_doc",
      classification: "planned",
      stages: ["S2"],
      modules: ["method-a"],
      work_items: ["beta-cut"],
      contract_families: [],
      conformance_targets: [],
      code_anchors: [],
      proof_gates: [],
      reason: "fixture",
    },
    {
      id: "docs/architecture/README.md",
      kind: "architecture_doc",
      classification: "non_build_doctrine",
      stages: [],
      modules: [],
      work_items: [],
      contract_families: [],
      conformance_targets: [],
      code_anchors: [],
      proof_gates: [],
      reason: "index",
    },
    {
      id: "docs/decisions/0001-accepted-thing.md",
      kind: "adr",
      classification: "actively_sequenced",
      stages: ["S1"],
      modules: ["method-a"],
      work_items: ["alpha-cut"],
      contract_families: [],
      conformance_targets: [],
      code_anchors: [],
      proof_gates: [],
      reason: "fixture",
    },
    {
      id: "docs/decisions/0002-old-thing.md",
      kind: "adr",
      classification: "non_build_doctrine",
      stages: [],
      modules: [],
      work_items: [],
      contract_families: [],
      conformance_targets: [],
      code_anchors: [],
      proof_gates: [],
      reason: "superseded",
    },
    {
      id: "docs/decisions/README.md",
      kind: "adr_index",
      classification: "non_build_doctrine",
      stages: [],
      modules: [],
      work_items: [],
      contract_families: [],
      conformance_targets: [],
      code_anchors: [],
      proof_gates: [],
      reason: "index",
    },
    {
      id: "docs/conformance/README.md",
      kind: "conformance_target",
      classification: "non_build_doctrine",
      stages: [],
      modules: [],
      work_items: [],
      contract_families: [],
      conformance_targets: [],
      code_anchors: [],
      proof_gates: [],
      reason: "index",
    },
    {
      id: "docs/conformance/core/alpha-lifecycle.md",
      kind: "conformance_target",
      classification: "conformance_only",
      stages: [],
      modules: [],
      work_items: [],
      contract_families: [],
      conformance_targets: [],
      code_anchors: [],
      proof_gates: [],
      reason: "fixture",
    },
  ];
  write(
    estate,
    "program/canon-map.v1.json",
    `${JSON.stringify({ format: "ioi.program.canon_map.v1", subjects }, null, 2)}\n`,
  );
  return { root, estate };
}

function accept({ root, estate }) {
  const { subjects } = computeImpact({ repoRoot: root, estateRoot: estate });
  const map = {};
  for (const s of subjects) map[s.id] = s.sha256;
  write(
    estate,
    "generated/canon-baseline.v1.json",
    `${JSON.stringify({ subjects: map }, null, 2)}\n`,
  );
}

function main() {
  const fixture = buildFixture();
  const { root, estate } = fixture;
  const archived = path.join(
    estate,
    "_archive/evidence/2026-01-01-retained.json",
  );
  const archivedBefore = fs.readFileSync(archived, "utf8");

  process.stdout.write("canon-impact fixture test\n");

  // --- 1. clean baseline
  accept(fixture);
  let r = computeImpact({ repoRoot: root, estateRoot: estate });
  check(
    "clean fixture reports no errors",
    r.findings.filter((f) => f.level === "error").length === 0,
    JSON.stringify(r.findings.filter((f) => f.level === "error").map((f) => f.message)),
  );
  check("clean fixture reports no impact", r.impact.changed.length === 0);

  // --- 2. ADD a canon file -> bounded orphan report
  write(root, "docs/architecture/foundations/gamma.md", "# Gamma\n");
  r = computeImpact({ repoRoot: root, estateRoot: estate });
  const orphans = r.findings.filter((f) => f.check === "canon-orphan");
  check("added canon file is reported as exactly one orphan", orphans.length === 1);
  check(
    "the orphan names the added file",
    orphans[0]?.subject === "docs/architecture/foundations/gamma.md",
    orphans[0]?.subject,
  );
  check(
    "adding an unmapped file names no stage for review",
    r.affected.stages.length === 0,
    JSON.stringify(r.affected.stages),
  );
  check(
    "adding an unmapped file names no work item for review",
    r.affected.work_items.length === 0,
    JSON.stringify(r.affected.work_items),
  );
  fs.rmSync(path.join(root, "docs/architecture/foundations/gamma.md"));

  // --- 3. MODIFY a mapped canon file -> bounded review assignment
  accept(fixture);
  write(root, "docs/architecture/foundations/alpha.md", "# Alpha\n\nAlpha doctrine, revised.\n");
  r = computeImpact({ repoRoot: root, estateRoot: estate });
  check("modification reports exactly one changed subject", r.impact.changed.length === 1);
  check(
    "review is assigned to S1 only",
    JSON.stringify(r.affected.stages) === JSON.stringify(["S1"]),
    JSON.stringify(r.affected.stages),
  );
  check(
    "review is assigned to alpha-cut only",
    JSON.stringify(r.affected.work_items) === JSON.stringify(["alpha-cut"]),
    JSON.stringify(r.affected.work_items),
  );
  check(
    "the unrelated S2 / beta-cut binding is NOT named",
    !r.affected.stages.includes("S2") && !r.affected.work_items.includes("beta-cut"),
  );
  check(
    "the bound conformance target is carried into the report",
    r.affected.conformance_targets.includes("docs/conformance/core/alpha-lifecycle.md"),
    JSON.stringify(r.affected.conformance_targets),
  );

  // --- 4. REMOVE a mapped canon file -> fails closed
  accept(fixture);
  fs.rmSync(path.join(root, "docs/architecture/foundations/beta.md"));
  r = computeImpact({ repoRoot: root, estateRoot: estate });
  check(
    "removing a mapped subject fails closed",
    r.findings.some((f) => f.check === "canon-removed"),
  );
  check(
    "removal names the stage that owned it",
    r.affected.stages.includes("S2"),
    JSON.stringify(r.affected.stages),
  );
  write(root, "docs/architecture/foundations/beta.md", "# Beta\n\nBeta doctrine.\n");

  // --- 5. superseded ADR cannot satisfy an obligation
  accept(fixture);
  const mapPath = path.join(estate, "program/canon-map.v1.json");
  const map = JSON.parse(fs.readFileSync(mapPath, "utf8"));
  const superseded = map.subjects.find((s) =>
    s.id === "docs/decisions/0002-old-thing.md"
  );
  superseded.classification = "actively_sequenced";
  superseded.stages = ["S1"];
  superseded.work_items = ["alpha-cut"];
  fs.writeFileSync(mapPath, `${JSON.stringify(map, null, 2)}\n`);
  r = computeImpact({ repoRoot: root, estateRoot: estate });
  check(
    "a superseded ADR cannot satisfy an obligation",
    r.findings.some((f) => f.check === "adr-superseded"),
  );
  superseded.classification = "non_build_doctrine";
  superseded.stages = [];
  superseded.work_items = [];
  fs.writeFileSync(mapPath, `${JSON.stringify(map, null, 2)}\n`);

  // --- 6. unbound module is reported
  const seqPath = path.join(estate, "program/sequence.v1.json");
  const seq = JSON.parse(fs.readFileSync(seqPath, "utf8"));
  seq.modules.push({
    id: "method-orphan",
    path: "modules/method-a.md",
    applies_to_stages: [],
  });
  fs.writeFileSync(seqPath, `${JSON.stringify(seq, null, 2)}\n`);
  r = computeImpact({ repoRoot: root, estateRoot: estate });
  check(
    "a module no stage pulls is reported as unbound doctrine",
    r.findings.some((f) => f.check === "module-orphan" && f.module === "method-orphan"),
  );
  seq.modules.pop();
  fs.writeFileSync(seqPath, `${JSON.stringify(seq, null, 2)}\n`);

  // --- 7. historical evidence untouched throughout
  check(
    "retained historical evidence is byte-identical after every case",
    fs.readFileSync(archived, "utf8") === archivedBefore,
  );

  // --- 8. --accept RETAINS the reviewed manifest body under its content
  // address and records that address, never a volatile path. The first two
  // acceptances in the real ledger recorded `/tmp/...`: a digest bound to a
  // body no later reader could produce.
  accept(fixture);
  write(
    root,
    "docs/architecture/foundations/alpha.md",
    "# Alpha\n\nAlpha doctrine, revised again for the acceptance case.\n",
  );
  const manifestPath = path.join(root, "review-manifest.json");
  runCli([
    "--root", root, "--estate", estate,
    "--emit-review-manifest", manifestPath,
  ]);
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  const reviewerRef = "agent://fixture/test-canon-impact/acceptance-retention";
  manifest.reviewer_ref = reviewerRef;
  manifest.subjects = manifest.subjects.map((s) => ({
    ...s,
    disposition: "successor_required",
    review_note:
      "Fixture review: this subject's change reaches a closure that was already proven, so a successor is required rather than a rewrite.",
  }));
  fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  const manifestDigest = crypto
    .createHash("sha256")
    .update(fs.readFileSync(manifestPath))
    .digest("hex");

  const accepted = runCli([
    "--root", root, "--estate", estate, "--accept",
    "--review-manifest", manifestPath,
    "--reviewer-ref", reviewerRef,
  ]);
  check("--accept against a filled manifest succeeds", accepted.exit === 0, accepted.out.slice(0, 300));

  const retainedRel = `_archive/attestations/review-manifests/${manifestDigest}.json`;
  const retainedAbs = path.join(estate, retainedRel);
  check(
    "--accept retains the reviewed manifest BODY under its content address",
    fs.existsSync(retainedAbs),
    retainedRel,
  );
  if (fs.existsSync(retainedAbs)) {
    check(
      "the retained body is byte-identical to the manifest that was reviewed",
      fs.readFileSync(retainedAbs, "utf8") ===
        fs.readFileSync(manifestPath, "utf8"),
    );
  }
  const ledger = JSON.parse(
    fs.readFileSync(
      path.join(estate, "_archive/attestations/canon-acceptances.v1.json"),
      "utf8",
    ),
  );
  const entry = ledger.entries.at(-1);
  check(
    "the acceptance entry records the CONTENT ADDRESS of the manifest",
    entry.review_manifest_content_address === retainedRel,
    entry.review_manifest_content_address,
  );
  check(
    "the acceptance entry's digest matches the retained body",
    entry.review_manifest_sha256 === manifestDigest,
  );
  check(
    "the volatile path is retained only as explicitly non-authoritative",
    entry.review_manifest === undefined &&
      entry.review_manifest_path_is_not_authoritative === true,
    JSON.stringify({
      review_manifest: entry.review_manifest,
      not_authoritative: entry.review_manifest_path_is_not_authoritative,
    }),
  );
  check(
    "an acceptance carrying successor_required says the hold is owed",
    accepted.out.includes("check-open-successor-holds"),
    accepted.out.slice(0, 300),
  );
  const baseline = JSON.parse(
    fs.readFileSync(path.join(estate, "generated/canon-baseline.v1.json"), "utf8"),
  );
  check(
    "the advanced baseline is bound to the content address too",
    baseline.accepted_under_review_manifest_content_address === retainedRel,
    baseline.accepted_under_review_manifest_content_address,
  );

  // --- 9. admitted durable-overlay evidence is governed outside canon-map
  const overlayRel = "docs/evidence/fixture/local-proof.json";
  write(root, overlayRel, '{"local":true}\n');
  const overlaySha = crypto.createHash("sha256")
    .update(fs.readFileSync(path.join(root, overlayRel)))
    .digest("hex");
  const overlayManifest = {
    evidence_format: "ioi.program.canon_overlay_manifest.v2",
    state: "admitted",
    consumed_by_no_tool: false,
    identities: [{
      id: overlayRel,
      sha256: overlaySha,
      classification: "host_local_durable_evidence",
      lifecycle: "active",
    }],
  };
  overlayManifest.manifest_sha256 = crypto.createHash("sha256")
    .update(JSON.stringify(overlayManifest, null, 2))
    .digest("hex");
  write(estate, "program/canon-overlay-manifest.v2.json", `${JSON.stringify(overlayManifest, null, 2)}\n`);
  write(estate, "program/canon-baseline-successor.v1.json", `${JSON.stringify({
    state: "admitted",
    consumed_by_no_tool: false,
    overlay: {
      manifest: "program/canon-overlay-manifest.v2.json",
      manifest_sha256: overlayManifest.manifest_sha256,
    },
  }, null, 2)}\n`);
  write(estate, "program/canon-overlay-dispositions.v1.json", `${JSON.stringify({
    counts: { by_disposition: { unattributed: 0 } },
    entries: [{
      id: overlayRel,
      sha256: overlaySha,
      disposition: "retained_nonclaim_evidence",
    }],
  }, null, 2)}\n`);
  r = computeImpact({ repoRoot: root, estateRoot: estate });
  check(
    "admitted exact overlay evidence is not reported as a canon orphan",
    !r.findings.some((f) => f.check === "canon-orphan" && f.subject === overlayRel),
  );
  write(root, overlayRel, '{"local":false}\n');
  r = computeImpact({ repoRoot: root, estateRoot: estate });
  check(
    "overlay digest drift restores the orphan finding",
    r.findings.some((f) => f.check === "canon-orphan" && f.subject === overlayRel),
  );

  fs.rmSync(root, { recursive: true, force: true });
  process.stdout.write(
    failures === 0
      ? "canon-impact fixture test: PASS\n"
      : `canon-impact fixture test: FAIL (${failures})\n`,
  );
  process.exit(failures === 0 ? 0 : 1);
}

main();
