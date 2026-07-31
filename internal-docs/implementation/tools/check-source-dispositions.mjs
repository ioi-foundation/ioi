#!/usr/bin/env node
// Source-disposition ledger and single-sequencer bar
// (m0-source-disposition-and-single-sequencer-verifier).
//
// The durable form of M0.5 is this machine-readable ledger plus this
// verifier, not prose in a guide. The ledger (source-dispositions.v1.json)
// carries one SourceDispositionEntry per classified program source: role,
// path, digest (or a tombstone for an honest deletion), and inbound links.
//
// Predeclared rejections, each self-tested on every run:
//   deletion            a classified source absent from disk with no tombstone
//   archive-as-owner    an archived source carrying a canon/sequencer role
//   plan-status-voice   active implementation guidance living outside the
//                       estate, or any ledger entry claiming status authority
//   second-sequencer    more than one sequencer voice: a stage module that
//                       does not defer to program/sequence.v1.json, a second
//                       sequence file, or a competing-guides failure
//
//   node tools/check-source-dispositions.mjs [--write]
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { execFileSync } from "node:child_process";
import {
  ESTATE_ROOT,
  REPO_ROOT,
  finding,
  readJson,
  report,
  sha256File,
} from "./lib/estate.mjs";

const LEDGER_ABS = path.join(ESTATE_ROOT, "source-dispositions.v1.json");
const REGISTRY_ABS = path.join(ESTATE_ROOT, "program", "guide-registry.v1.json");
const SEQUENCE_REL = "program/sequence.v1.json";

function buildLedger(registry) {
  const entries = [];
  for (const source of registry.classified) {
    const abs = path.join(REPO_ROOT, source.path);
    const exists = fs.existsSync(abs);
    const isFile = exists && fs.statSync(abs).isFile();
    entries.push({
      path: source.path,
      role: source.classification,
      disposition: source.disposition ?? null,
      sha256: isFile ? sha256File(abs) : null,
      tombstone: exists ? null : {
        recorded_in: source.tombstoned_in ?? null,
        note: source.note ?? null,
      },
      inbound_refs: source.inbound_refs ?? [],
      status_authority: source.classification === "tracked-status-record",
    });
  }
  const archiveRoot = path.join(ESTATE_ROOT, "_archive");
  if (fs.existsSync(archiveRoot)) {
    for (const dir of fs.readdirSync(archiveRoot).sort()) {
      const abs = path.join(archiveRoot, dir);
      if (!fs.statSync(abs).isDirectory()) continue;
      entries.push({
        path: `internal-docs/implementation/_archive/${dir}/`,
        role: "archived-terminal-record",
        disposition: "retained-history",
        sha256: null,
        tombstone: null,
        inbound_refs: [],
        status_authority: false,
      });
    }
  }
  entries.sort((a, b) => (a.path < b.path ? -1 : 1));
  return {
    format: "ioi.program.source_dispositions.v1",
    role: "Machine-readable source-disposition ledger (M0.5 durable form). One entry per classified program source: role, digest or tombstone, inbound links. Derived from program/guide-registry.v1.json plus the _archive tree; never authority and never status truth.",
    entry_count: entries.length,
    entries,
  };
}

// Pure rejection core over a ledger + estate facts, so self-tests can feed it
// synthetic inputs.
export function evaluate({ ledger, stageFiles, sequenceFiles, competingGuidesPass }) {
  const findings = [];
  for (const entry of ledger.entries) {
    const abs = path.join(REPO_ROOT, entry.path);
    const gone = !fs.existsSync(abs) && !entry.path.endsWith("/");
    if (gone && !entry.tombstone) {
      findings.push(
        finding("error", "deletion", `classified source deleted with no tombstone: ${entry.path}`),
      );
    }
    const archived = entry.role === "archived-terminal-record" ||
      entry.role === "already-archived" ||
      entry.path.includes("/_archive/");
    if (archived && ["architecture-canon", "sole-sequencer"].includes(entry.disposition)) {
      findings.push(
        finding("error", "archive-as-owner", `archived source carries an owner role: ${entry.path}`),
      );
    }
    if (
      entry.role === "active-implementation-guidance" &&
      !entry.tombstone &&
      !entry.path.startsWith("internal-docs/implementation/")
    ) {
      findings.push(
        finding("error", "plan-status-voice", `active implementation guidance outside the estate: ${entry.path}`),
      );
    }
    if (entry.status_authority && entry.role !== "tracked-status-record") {
      findings.push(
        finding("error", "plan-status-voice", `non-status-record source claims status authority: ${entry.path}`),
      );
    }
  }

  if (sequenceFiles.length !== 1) {
    findings.push(
      finding("error", "second-sequencer", `expected exactly one sequence file, found ${sequenceFiles.length}: ${sequenceFiles.join(", ")}`),
    );
  }
  for (const stage of stageFiles) {
    const text = fs.existsSync(stage.abs) ? fs.readFileSync(stage.abs, "utf8") : stage.text ?? "";
    const m = /^sequencer:\s*(.+)$/mu.exec(text);
    if (!m || m[1].trim() !== SEQUENCE_REL) {
      findings.push(
        finding("error", "second-sequencer", `stage module does not defer to the sole sequencer: ${stage.rel} (sequencer: ${m ? m[1].trim() : "absent"})`),
      );
    }
  }
  if (!competingGuidesPass) {
    findings.push(
      finding("error", "second-sequencer", "check-no-competing-guides FAILED; a competing plan voice is live"),
    );
  }
  return findings;
}

function selfTest() {
  const out = [];
  const okLedger = { entries: [] };
  const cases = [
    {
      rejection: "deletion",
      args: {
        ledger: { entries: [{ path: "internal-docs/implementation/does-not-exist.md", role: "historical-evidence", disposition: "leave-as-is", tombstone: null, status_authority: false }] },
        stageFiles: [],
        sequenceFiles: [SEQUENCE_REL],
        competingGuidesPass: true,
      },
    },
    {
      rejection: "archive-as-owner",
      args: {
        ledger: { entries: [{ path: "internal-docs/implementation/_archive/guides/x.md", role: "already-archived", disposition: "architecture-canon", tombstone: null, status_authority: false }] },
        stageFiles: [],
        sequenceFiles: [SEQUENCE_REL],
        competingGuidesPass: true,
      },
    },
    {
      rejection: "plan-status-voice",
      args: {
        ledger: { entries: [{ path: "docs/some-external-plan.md", role: "active-implementation-guidance", disposition: null, tombstone: null, status_authority: false }] },
        stageFiles: [],
        sequenceFiles: [SEQUENCE_REL],
        competingGuidesPass: true,
      },
    },
    {
      rejection: "second-sequencer",
      args: {
        ledger: okLedger,
        stageFiles: [],
        sequenceFiles: [SEQUENCE_REL, "program/sequence.v2.json"],
        competingGuidesPass: true,
      },
    },
    {
      rejection: "second-sequencer",
      args: {
        ledger: okLedger,
        stageFiles: [{ rel: "stages/fixture.md", abs: "/nonexistent", text: "---\nsequencer: my-own-order.json\n---\n" }],
        sequenceFiles: [SEQUENCE_REL],
        competingGuidesPass: true,
      },
    },
  ];
  for (const testCase of cases) {
    const findings = evaluate(testCase.args);
    if (!findings.some((f) => f.level === "error" && f.check === testCase.rejection)) {
      out.push(
        finding("error", "self-test", `synthetic ${testCase.rejection} input was ACCEPTED; the rejection has no teeth`),
      );
    }
  }
  return out;
}

function main() {
  const write = process.argv.includes("--write");
  const outputIndex = process.argv.indexOf("--output");
  const outputAbs = outputIndex >= 0
    ? path.resolve(process.argv[outputIndex + 1] ?? "")
    : LEDGER_ABS;
  const findings = selfTest();

  const registry = readJson(REGISTRY_ABS);
  if (write) {
    const ledger = buildLedger(registry);
    fs.mkdirSync(path.dirname(outputAbs), { recursive: true });
    fs.writeFileSync(outputAbs, `${JSON.stringify(ledger, null, 2)}\n`);
    if (outputAbs !== LEDGER_ABS) {
      report("check-source-dispositions", findings);
      process.exit(findings.some((f) => f.level === "error") ? 1 : 0);
    }
  }
  if (!fs.existsSync(LEDGER_ABS)) {
    findings.push(finding("error", "ledger", "no ledger on disk; run --write"));
    report("check-source-dispositions", findings);
    process.exit(1);
  }
  const ledger = readJson(LEDGER_ABS);

  // The ledger must reproduce from the registry + archive tree: a hand edit
  // that diverges from a fresh derivation fails closed.
  const fresh = `${JSON.stringify(buildLedger(registry), null, 2)}\n`;
  const onDisk = fs.readFileSync(LEDGER_ABS, "utf8");
  if (fresh !== onDisk) {
    findings.push(
      finding("error", "ledger", "ledger does not reproduce from a fresh derivation; regenerate with --write after registry changes"),
    );
  }

  const stagesDir = path.join(ESTATE_ROOT, "stages");
  const stageFiles = fs.readdirSync(stagesDir)
    .filter((f) => f.endsWith(".md"))
    .map((f) => ({ rel: `stages/${f}`, abs: path.join(stagesDir, f) }));
  const sequenceFiles = fs.readdirSync(path.join(ESTATE_ROOT, "program"))
    .filter((f) => /^sequence\.v\d+\.json$/.test(f))
    .map((f) => `program/${f}`);

  let competingGuidesPass = false;
  try {
    execFileSync(
      process.execPath,
      [path.join(ESTATE_ROOT, "tools", "check-no-competing-guides.mjs")],
      { stdio: "pipe" },
    );
    competingGuidesPass = true;
  } catch {
    competingGuidesPass = false;
  }

  findings.push(
    ...evaluate({ ledger, stageFiles, sequenceFiles, competingGuidesPass }),
  );

  report("check-source-dispositions", findings);
  process.exit(findings.some((f) => f.level === "error") ? 1 : 0);
}

main();
