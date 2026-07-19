import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

import {
  SYSTEM_GENESIS_EFFECT_GUARDS,
  compilerEffectViolations,
} from "./lib/system-genesis-compiler-effect-guard.mjs";

const root = path.resolve(import.meta.dirname, "..");
const compilerPath = path.join(root, "crates/types/src/app/system_genesis.rs");

test("production genesis compiler has no effect-capable API", () => {
  const source = fs.readFileSync(compilerPath, "utf8");
  assert.deepEqual(compilerEffectViolations(source), []);
});

test("effect guard rejects every prohibited capability class", () => {
  for (const { id, pattern } of SYSTEM_GENESIS_EFFECT_GUARDS) {
    const token = {
      filesystem: "std::fs::write",
      network: "std::net::TcpStream",
      clock: "std::time::SystemTime",
      random: "rand::random::<u64>",
      environment: "std::env::var",
      process: "std::process::Command::new",
      daemon: "DaemonClient",
      wallet: "wallet_network::WalletClient",
      agentgres: "agentgres::Agentgres",
    }[id];
    assert.match(token, pattern, `${id}: probe must exercise its pattern`);
    const source = `fn compile() { ${token}; }\n#[cfg(test)]\nmod tests {}`;
    assert.deepEqual(
      compilerEffectViolations(source),
      [id],
      `${id}: effect probe escaped`,
    );
  }
});

test("test-only instrumentation is outside the production effect surface", () => {
  const source =
    'fn compile() {}\n#[cfg(test)]\nmod tests { fn probe() { std::fs::read("fixture"); } }';
  assert.deepEqual(compilerEffectViolations(source), []);
});

test("compiler verifier accepts only explicit check mode", () => {
  const verifier = "scripts/check-system-genesis-compiler.mjs";
  for (const args of [[], ["--write"], ["--check", "--bogus"]]) {
    const result = spawnSync(process.execPath, [verifier, ...args], {
      cwd: root,
      encoding: "utf8",
    });
    assert.equal(result.status, 2, `unexpected status for ${args.join(" ")}`);
    assert.match(result.stderr, /Usage:/u);
  }
  const checked = spawnSync(process.execPath, [verifier, "--check"], {
    cwd: root,
    encoding: "utf8",
  });
  assert.equal(checked.status, 0, checked.stderr);
  assert.match(checked.stdout, /"adversarial_cases": 77/u);
});
