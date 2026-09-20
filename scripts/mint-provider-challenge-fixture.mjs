#!/usr/bin/env node
// mint-provider-challenge-fixture — M03.9 (register R-212): mint ONE direct-Akash deployment_intent
// capability-lease challenge from an isolated daemon, spend-free, and write it as the tracked,
// hash-committed fixture check:approval-card-facets drills against on every run.
//
//   node scripts/mint-provider-challenge-fixture.mjs [--output <file>]
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { startIsolatedPlane } from "../apps/hypervisor/scripts/lib/isolated-daemon.mjs";
import { bootstrapToken, fixtureFrom, mintProviderChallenge } from "./lib/provider-challenge-fixture.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..");
const arg = (name) => { const i = process.argv.indexOf(name); return i >= 0 ? process.argv[i + 1] : null; };
const output = path.resolve(ROOT, arg("--output") || "docs/architecture/_meta/evidence/m03-9-provider-challenge-fixture-2026-09-20.v1.json");
const binary = path.resolve(ROOT, process.env.IOI_HYPERVISOR_DAEMON_BINARY || "target/debug/hypervisor-daemon");
if (!fs.existsSync(binary)) { console.error(`daemon binary absent at ${binary}`); process.exit(2); }

const plane = await startIsolatedPlane({ baseEnv: process.env, env: { IOI_HYPERVISOR_DAEMON_BINARY: binary } });
if (!plane) { console.error("the isolated plane did not start"); process.exit(2); }
try {
  const token = bootstrapToken(plane.dataDir);
  const boot = await fetch(`${plane.daemonUrl}/v1/hypervisor/auth/bootstrap`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token, password: "approval-card-fixture-pass-1", email: "approval-card@ioi.local" }) });
  const bootBody = await boot.json().catch(() => ({}));
  const cookie = bootBody.session_token ? `ioi_session=${bootBody.session_token}` : "";
  const minted = await mintProviderChallenge({ daemonUrl: plane.daemonUrl, cookie, tag: "fixture" });
  if (!(typeof minted.challenge?.approval?.request_hash === "string" && typeof minted.challenge?.approval?.request_preimage === "string")) { console.error(JSON.stringify({ refused: "the reply is not a capability-lease challenge with a preimage; no fixture written", status: minted.status, body: minted.challenge, steps: minted.steps })); process.exit(1); }
  const basis = {
    commit: execFileSync("git", ["rev-parse", "HEAD"], { cwd: ROOT, encoding: "utf8" }).trim(),
    daemon_binary_sha256: `sha256:${crypto.createHash("sha256").update(fs.readFileSync(binary)).digest("hex")}`,
    daemon: "an isolated hypervisor-daemon started by apps/hypervisor/scripts/lib/isolated-daemon.mjs (no wallet client configured: the challenge's audience is null and its status is the not-configured form)",
  };
  const fixture = fixtureFrom({ minted, basis });
  fs.mkdirSync(path.dirname(output), { recursive: true });
  fs.writeFileSync(output, `${JSON.stringify(fixture, null, 2)}\n`);
  console.log(JSON.stringify({ output: path.relative(ROOT, output), status: minted.status, reason: minted.challenge?.reason ?? null, has_request_preimage: typeof minted.challenge?.approval?.request_preimage === "string", facets: Object.keys(minted.challenge?.lease_request_facets ?? {}), challenge_sha256: fixture.challenge_sha256, steps: minted.steps.map((s) => `${s.method} ${s.route.split("/").slice(-1)[0]}=${s.status}`) }));
} finally {
  await plane.stop();
}
