#!/usr/bin/env node
// Route / final-invoker / PG census maintenance bar
// (m0-route-final-invoker-pg-census-maintenance).
//
// The census itself is owned by scripts/m0-program-control.mjs and its
// retained evidence under docs/evidence/m0-program-control/. This bar is the
// MAINTENANCE join over that evidence:
//
//   1. The authoritative currency check (`node scripts/m0-program-control.mjs
//      --check`) must pass: census, reviewed-entry lock, and anchors cohere.
//   2. Bypass/retirement diff: the live census and the reviewed lock must
//      cover the same entry identities. An entry in the census but not the
//      lock is a would-be bypass (census re-entry required); an entry in the
//      lock but not the census is an unretired ghost.
//   3. Every consequential entry names a final invoker or carries an explicit
//      blocker/nonclaim ref — an effect without an invoker is a census
//      defect (Final-Invoker Invariants, security-privacy-policy-invariants.md).
//   4. Every PG id in the private mechanism-gates registry maps exactly once
//      in the gate map, and the gate map introduces no id of its own — gates
//      are mapped, never redefined. Both counts are derived, never
//      hand-written.
//
// Every rejection is self-tested against synthetic bad inputs on every run.
//
//   node tools/check-route-census-maintenance.mjs [--write]
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import {
  ESTATE_ROOT,
  REPO_ROOT,
  finding,
  readJson,
  report,
} from "./lib/estate.mjs";

const EVIDENCE_DIR = path.join(REPO_ROOT, "docs", "evidence", "m0-program-control");
const GATES_MODULE = path.join(ESTATE_ROOT, "modules", "mechanism-gates.md");
const OUT_ABS = path.join(ESTATE_ROOT, "generated", "route-census-maintenance.v1.json");

const NONCONSEQUENTIAL = new Set([
  "read_only",
  "plan_only",
  "compatibility",
  "internal_only",
]);

export function evaluate({ censusEntries, lockEntries, pgEntries, registryPgIds }) {
  const findings = [];

  const censusIds = new Set(censusEntries.map((e) => e.identity));
  const lockIds = new Set(lockEntries.map((e) => e.identity));
  const added = [...censusIds].filter((id) => !lockIds.has(id)).sort();
  const removed = [...lockIds].filter((id) => !censusIds.has(id)).sort();
  for (const id of added) {
    findings.push(
      finding("error", "bypass", `census entry not in the reviewed lock (census re-entry required): ${id}`),
    );
  }
  for (const id of removed) {
    findings.push(
      finding("error", "retirement", `reviewed lock entry no longer in the census (unretired ghost): ${id}`),
    );
  }

  for (const entry of lockEntries) {
    if (NONCONSEQUENTIAL.has(entry.classification)) continue;
    if (!entry.final_invoker && !entry.blocker_or_nonclaim_ref) {
      findings.push(
        finding("error", "final-invoker", `consequential entry with no final invoker and no blocker ref: ${entry.identity}`),
      );
    }
  }

  const mapped = new Map();
  for (const entry of pgEntries) {
    mapped.set(entry.pg_id, (mapped.get(entry.pg_id) ?? 0) + 1);
  }
  for (const [id, n] of mapped) {
    if (n > 1) {
      findings.push(finding("error", "pg-map", `gate mapped ${n} times: ${id}`));
    }
    if (!registryPgIds.has(id)) {
      findings.push(
        finding("error", "pg-map", `gate map introduces an id the registry does not define: ${id}`),
      );
    }
  }
  for (const id of registryPgIds) {
    if (!mapped.has(id)) {
      findings.push(finding("error", "pg-map", `registry gate unmapped: ${id}`));
    }
  }

  return { findings, added, removed };
}

function selfTest() {
  const out = [];
  const entry = (identity, extra = {}) => ({
    identity,
    classification: "consequential",
    final_invoker: "daemon::invoke",
    blocker_or_nonclaim_ref: null,
    ...extra,
  });
  const cases = [
    {
      rejection: "bypass",
      args: {
        censusEntries: [entry("a"), entry("b")],
        lockEntries: [entry("a")],
        pgEntries: [],
        registryPgIds: new Set(),
      },
    },
    {
      rejection: "retirement",
      args: {
        censusEntries: [entry("a")],
        lockEntries: [entry("a"), entry("ghost")],
        pgEntries: [],
        registryPgIds: new Set(),
      },
    },
    {
      rejection: "final-invoker",
      args: {
        censusEntries: [],
        lockEntries: [entry("c", { final_invoker: null })],
        pgEntries: [],
        registryPgIds: new Set(),
      },
    },
    {
      rejection: "pg-map",
      args: {
        censusEntries: [],
        lockEntries: [],
        pgEntries: [{ pg_id: "PG-0.1" }, { pg_id: "PG-0.1" }],
        registryPgIds: new Set(["PG-0.1"]),
      },
    },
    {
      rejection: "pg-map",
      args: {
        censusEntries: [],
        lockEntries: [],
        pgEntries: [{ pg_id: "PG-0.1" }],
        registryPgIds: new Set(["PG-0.1", "PG-9.9"]),
      },
    },
  ];
  for (const testCase of cases) {
    const { findings } = evaluate(testCase.args);
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
  const findings = selfTest();

  // 1. Authoritative currency: the program-control model itself.
  let currencyPass = false;
  try {
    execFileSync(
      process.execPath,
      [path.join(REPO_ROOT, "scripts", "m0-program-control.mjs"), "--check"],
      { stdio: "pipe", cwd: REPO_ROOT },
    );
    currencyPass = true;
  } catch {
    findings.push(
      finding("error", "currency", "scripts/m0-program-control.mjs --check FAILED; census, lock, and anchors do not cohere"),
    );
  }

  const census = readJson(path.join(EVIDENCE_DIR, "effect-census.json"));
  const lock = readJson(path.join(EVIDENCE_DIR, "reviewed-entry-lock.json"));
  const pgMapAbs = path.join(EVIDENCE_DIR, "pg-gate-map.json");
  const pgMap = readJson(pgMapAbs);
  const pgSuccessorAbs = path.join(ESTATE_ROOT, "program", "pg-gate-map-successor.v1.json");
  let pgSuccessorEntries = [];
  if (fs.existsSync(pgSuccessorAbs)) {
    const successor = readJson(pgSuccessorAbs);
    const actualBaseSha256 = crypto.createHash("sha256").update(fs.readFileSync(pgMapAbs)).digest("hex");
    if (successor.format !== "ioi.program.pg-gate-map-successor.v1") {
      findings.push(finding("error", "pg-map", "PG map successor has an unknown format"));
    } else if (successor.base_map_sha256 !== actualBaseSha256) {
      findings.push(finding("error", "pg-map", "PG map successor does not bind the reviewed predecessor bytes"));
    } else if (!Array.isArray(successor.entries)) {
      findings.push(finding("error", "pg-map", "PG map successor entries are not an array"));
    } else {
      pgSuccessorEntries = successor.entries;
    }
  }
  if (lock.lock_state !== "reviewed") {
    findings.push(
      finding("error", "currency", `reviewed-entry lock is not in the reviewed state: ${lock.lock_state}`),
    );
  }

  const gatesText = fs.readFileSync(GATES_MODULE, "utf8");
  const registryPgIds = new Set(gatesText.match(/\bPG-[0-9]+[A-Z]?\.[0-9]+\b/gu) ?? []);
  if (registryPgIds.size === 0) {
    findings.push(
      finding("error", "pg-map", "the private mechanism-gates registry parsed to zero PG ids; fails closed"),
    );
  }

  const { findings: liveFindings, added, removed } = evaluate({
    censusEntries: census.entries,
    lockEntries: lock.entries,
    pgEntries: [...pgMap.entries, ...pgSuccessorEntries],
    registryPgIds,
  });
  findings.push(...liveFindings);

  if (write) {
    fs.mkdirSync(path.dirname(OUT_ABS), { recursive: true });
    fs.writeFileSync(
      OUT_ABS,
      `${
        JSON.stringify(
          {
            format: "ioi.program.route_census_maintenance.v1",
            role: "Generated bypass/retirement diff and PG-map join over the retained program-control evidence. Derived output; never authority.",
            currency_check_pass: currencyPass,
            census_entry_count: census.entries.length,
            lock_entry_count: lock.entries.length,
            bypass_candidates: added,
            unretired_ghosts: removed,
            registry_pg_id_count: registryPgIds.size,
            mapped_pg_id_count: pgMap.entries.length + pgSuccessorEntries.length,
            consequential_without_invoker_or_blocker: lock.entries.filter(
              (e) =>
                !NONCONSEQUENTIAL.has(e.classification) &&
                !e.final_invoker &&
                !e.blocker_or_nonclaim_ref,
            ).length,
          },
          null,
          2,
        )
      }\n`,
    );
    findings.push(finding("skip", "maintenance", "wrote the bypass/retirement diff"));
  }

  report("check-route-census-maintenance", findings);
  process.exit(findings.some((f) => f.level === "error") ? 1 : 0);
}

main();
