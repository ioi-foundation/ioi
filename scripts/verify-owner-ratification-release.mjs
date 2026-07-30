#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { writeLiteralExitLog } from "../internal-docs/implementation/tools/lib/literal-exit.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const artifactRel = "internal-docs/implementation/evidence/M3/owner-ratification-authority-and-scm-release.v1.log";
const artifactAbs = join(root, artifactRel);
const checks = [
  ["affected-route-census", "node", ["scripts/verify-affected-route-authority-census.mjs"]],
  ["raw-verifier-source-fence", "cargo", ["test", "-p", "ioi-types", "--test", "live_authority_source_policy"]],
  ["fixture-minter-link-fence", "cargo", ["test", "-p", "ioi-node", "--test", "production_authority_fixture_symbols"]],
  ["approval-v1-v2-history", "cargo", ["test", "-p", "ioi-services", "agentic::runtime::kernel::approval", "--lib"]],
  ["daemon-route-and-recovery-suite", "cargo", ["test", "-p", "ioi-node", "--bin", "hypervisor-daemon"]],
  ["scm-v2-operation-suite", "cargo", ["test", "-p", "ioi-node", "--bin", "hypervisor-daemon", "scm_publication_routes::tests"]],
];

const sections = [
  "IOI_OWNER_RATIFICATION_RELEASE_EVIDENCE=v1",
  "CLAIM_BOUNDARY=Immediate source-neutral authorized-issuer, atomic consumption, affected-route fence, recovery reuse, and SCM v2 implementation proof only. This artifact does not activate standing-authority v3 or make the Hypervisor App primary.",
];
let failed = false;
for (const [id, command, args] of checks) {
  const result = spawnSync(command, args, {
    cwd: root,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    timeout: 20 * 60 * 1000,
    env: process.env,
  });
  const status = result.status ?? 1;
  sections.push(`\nCHECK=${id}\nCOMMAND=${command} ${args.join(" ")}\nSTATUS=${status}`);
  if (result.stdout) sections.push(`STDOUT_BEGIN\n${result.stdout.trimEnd()}\nSTDOUT_END`);
  if (result.stderr) sections.push(`STDERR_BEGIN\n${result.stderr.trimEnd()}\nSTDERR_END`);
  if (status !== 0) failed = true;
}
sections.push(`\nOWNER_RATIFICATION_IMMEDIATE_RELEASE=${failed ? "FAIL" : "PASS"}`);
mkdirSync(dirname(artifactAbs), { recursive: true });
writeFileSync(artifactAbs, `${sections.join("\n")}\n`);

if (!failed) {
  const exits = [
    [
      "m3-affected-route-authority-census-and-fence",
      "M3_AFFECTED_ROUTE_AUTHORITY_CENSUS_AND_FENCE_EXIT=0",
      "internal-docs/implementation/evidence/M3/m3-affected-route-authority-census-and-fence.exit.v1.txt",
    ],
    [
      "m3-authorized-issuer-and-atomic-authority-consumption",
      "M3_AUTHORIZED_ISSUER_AND_ATOMIC_AUTHORITY_CONSUMPTION_EXIT=0",
      "internal-docs/implementation/evidence/M3/m3-authorized-issuer-and-atomic-authority-consumption.exit.v1.txt",
    ],
    [
      "scm-publication-effect-and-route-rebuild",
      "SCM_PUBLICATION_EFFECT_AND_ROUTE_REBUILD_EXIT=0",
      "internal-docs/implementation/evidence/M9/scm-publication-effect-and-route-rebuild.exit.v1.txt",
    ],
  ];
  for (const [bar, literal, outRel] of exits) {
    writeLiteralExitLog({
      bar,
      literal,
      artifactRel,
      outRel,
      nonclaim: "This content-bound implementation proof preserves authority and SCM v1/v2 history, activates no standing-authority v3 profile, and does not make the Hypervisor App primary.",
    });
  }
}

process.stdout.write(`owner-ratification immediate release: ${failed ? "FAIL" : "PASS"}; retained ${artifactRel}\n`);
process.exitCode = failed ? 1 : 0;
