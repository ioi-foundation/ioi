#!/usr/bin/env node
// wallet-network-authority — operator entry point for the Hypervisor bounded alpha's
// deployment-local wallet.network authority node (ADR 0052; bounded-alpha-profile.md step 2b).
//
//   node scripts/wallet-network-authority.mjs up --state-dir <dir> --principal-ref domain://<host> [--wall-clock]
//   node scripts/wallet-network-authority.mjs approve --state-dir <dir> --policy-hash <h> --request-hash <h> \
//        --audience <capability-account> --target-scope <scope> [--expires-in-secs <n>] [--reason "..."]
//   node scripts/wallet-network-authority.mjs rotate --state-dir <dir>
//   node scripts/wallet-network-authority.mjs revoke --state-dir <dir> [--reason "..."]
//   node scripts/wallet-network-authority.mjs seal-keys --state-dir <dir>
//   node scripts/wallet-network-authority.mjs status --state-dir <dir>
//
// `up` stays in the foreground (run it under your supervisor or a terminal). On first run it
// generates the deployment's control root and the operator's approver key SEALED under the
// operator passphrase (keys/root.seed.sealed, keys/approver.seed.sealed, 0600; public halves in
// keys/root.pub, keys/approver.pub), the daemon's capability key sealed under the guardian pass,
// starts the single-validator node with durable chain state under <dir>/chain-state, issues the
// control-plane records, and writes:
//   <dir>/daemon.env  — export these into the hypervisor-daemon's environment
//   <dir>/serve.env   — export this into serve-product-ui.mjs's environment (public refs only;
//                       the served App holds no signing key)
// A later `up` resumes the same chain WITHOUT the passphrase and refuses to serve a substituted
// root or a binding that does not match the custodied approver key. Ctrl-C / SIGTERM shuts the
// node down in order.
//
// THE OPERATOR PASSPHRASE. `up` (first run only), `approve`, `rotate`, `revoke` and `seal-keys`
// need it. Give it as IOI_AUTHORITY_OPERATOR_PASS on that one command, or run on a terminal and be
// prompted (preferred for `up`: this launcher stays in the foreground, and a variable in its own
// environment would stay readable in /proc/<pid>/environ until it exits). It is never a flag,
// never written to a file, never in daemon.env or serve.env, and it must differ from
// IOI_GUARDIAN_KEY_PASS. This launcher forwards it only to the one child act that opens a sealed
// key; the node never receives it on a resume.
//
// `approve` is the operator's approval act and the one place a grant is minted: it takes the exact
// coordinates the daemon's challenge names (policy hash, request hash, the daemon's capability
// account as audience, the governed scope), unseals the approver key in memory, mints one one-use
// grant with a short expiry, records it on the node and prints it (never the seed).
//
// `seal-keys` converts a plaintext state dir (one brought up before sealing, or a dev/test node)
// in place; deployment mode refuses to serve a plaintext state dir until it has run.

import path from "node:path";
import { approveGrant, authorityAct, OPERATOR_PASS_ENV, startLocalAuthority } from "./lib/wallet-network-local-authority.mjs";

function parseArgs(argv) {
  const [command, ...rest] = argv;
  const options = {};
  for (let i = 0; i < rest.length; i += 1) {
    const arg = rest[i];
    if (!arg.startsWith("--")) throw new Error(`unexpected argument ${arg}`);
    const key = arg.slice(2);
    if (key === "wall-clock") { options.wallClock = true; continue; }
    // The passphrase is never an argument: argv is readable by every process on the host.
    if (/pass|seed|secret/iu.test(key)) throw new Error(`--${key} is refused: the operator passphrase comes only from ${OPERATOR_PASS_ENV} or a terminal prompt, and no key ever rides argv`);
    const value = rest[i + 1];
    if (value === undefined) throw new Error(`--${key} needs a value`);
    options[key] = value;
    i += 1;
  }
  return { command, options };
}

let parsed;
try { parsed = parseArgs(process.argv.slice(2)); } catch (error) { console.error(error.message); process.exit(2); }
const { command, options } = parsed;
if (!command || !options["state-dir"]) {
  console.error("usage: wallet-network-authority.mjs <up|approve|rotate|revoke|seal-keys|status> --state-dir <dir> [--principal-ref <ref>] [--policy-hash <h> --request-hash <h> --audience <a> --target-scope <s> [--expires-in-secs <n>]] [--reason <text>] [--binary <path>] [--wall-clock]");
  process.exit(2);
}
const stateDir = path.resolve(options["state-dir"]);
// Take the passphrase out of this process's environment at once, so no child this launcher
// spawns inherits it except the one act it is explicitly forwarded to.
const operatorPass = process.env[OPERATOR_PASS_ENV] || "";
delete process.env[OPERATOR_PASS_ENV];

if (command === "up") {
  if (!options["principal-ref"]) { console.error("up requires --principal-ref (e.g. domain://alpha-host)"); process.exit(2); }
  let node;
  try {
    node = await startLocalAuthority({ stateDir, principalRef: options["principal-ref"], binary: options.binary, wallClock: !!options.wallClock, operatorPass });
  } catch (error) {
    console.error(error.message);
    process.exit(1);
  }
  console.log(`READY  principal=${node.ready.principal_ref}  rpc=${node.daemonEnv.IOI_WALLET_NETWORK_RPC_ADDR}`);
  console.log(`daemon env: ${path.join(stateDir, "daemon.env")}`);
  console.log(`serve env:  ${path.join(stateDir, "serve.env")}`);
  console.log(`approver key: ${node.keyCustody} under the operator passphrase (public half ${node.approverPublicKeyPath}); approve a challenge with: wallet-network-authority.mjs approve --state-dir ${stateDir} …`);
  const shutdown = async (why) => { console.log(`stopping (${why})…`); await node.stop(); process.exit(0); };
  process.on("SIGINT", () => shutdown("SIGINT"));
  process.on("SIGTERM", () => shutdown("SIGTERM"));
  await node.exitPromise;
  await node.stop();
} else if (command === "approve") {
  const missing = ["policy-hash", "request-hash", "audience", "target-scope"].filter((key) => !options[key]);
  if (missing.length) { console.error(`approve requires ${missing.map((key) => `--${key}`).join(", ")} (the daemon challenge's exact coordinates)`); process.exit(2); }
  const result = approveGrant({
    stateDir, binary: options.binary, operatorPass,
    policyHash: options["policy-hash"], requestHash: options["request-hash"], audience: options.audience, targetScope: options["target-scope"],
    expiresInSecs: options["expires-in-secs"], reason: options.reason,
  });
  process.stdout.write(result.stdout);
  process.stderr.write(result.stderr);
  process.exit(result.ok ? 0 : 1);
} else if (["rotate", "revoke", "seal-keys", "status"].includes(command)) {
  const result = authorityAct(command, { stateDir, binary: options.binary, reason: options.reason, operatorPass });
  process.stdout.write(result.stdout);
  process.stderr.write(result.stderr);
  process.exit(result.ok ? 0 : 1);
} else {
  console.error(`unknown command ${command}`);
  process.exit(2);
}
