#!/usr/bin/env node
// wallet-network-authority — operator entry point for the Hypervisor bounded alpha's
// deployment-local wallet.network authority node (ADR 0052; bounded-alpha-profile.md step 2b).
//
//   node scripts/wallet-network-authority.mjs up --state-dir <dir> --principal-ref domain://<host> [--wall-clock]
//   node scripts/wallet-network-authority.mjs rotate --state-dir <dir>
//   node scripts/wallet-network-authority.mjs revoke --state-dir <dir> [--reason "..."]
//   node scripts/wallet-network-authority.mjs status --state-dir <dir>
//
// `up` stays in the foreground (run it under your supervisor or a terminal). On first run it
// generates and custodies the deployment's control root, the daemon's capability key and the
// operator's approver key under <dir>/keys (0600), starts the single-validator node with durable
// chain state under <dir>/chain-state, issues the control-plane records, and writes:
//   <dir>/daemon.env  — export these into the hypervisor-daemon's environment
//   <dir>/serve.env   — export this into serve-product-ui.mjs's environment
// A later `up` resumes the same chain and refuses to serve a substituted root or a binding that
// does not match the custodied approver key. Ctrl-C / SIGTERM shuts the node down in order.

import path from "node:path";
import { authorityAct, startLocalAuthority } from "./lib/wallet-network-local-authority.mjs";

function parseArgs(argv) {
  const [command, ...rest] = argv;
  const options = {};
  for (let i = 0; i < rest.length; i += 1) {
    const arg = rest[i];
    if (!arg.startsWith("--")) throw new Error(`unexpected argument ${arg}`);
    const key = arg.slice(2);
    if (key === "wall-clock") { options.wallClock = true; continue; }
    const value = rest[i + 1];
    if (value === undefined) throw new Error(`--${key} needs a value`);
    options[key] = value;
    i += 1;
  }
  return { command, options };
}

const { command, options } = parseArgs(process.argv.slice(2));
if (!command || !options["state-dir"]) {
  console.error("usage: wallet-network-authority.mjs <up|rotate|revoke|status> --state-dir <dir> [--principal-ref <ref>] [--reason <text>] [--binary <path>] [--wall-clock]");
  process.exit(2);
}
const stateDir = path.resolve(options["state-dir"]);

if (command === "up") {
  if (!options["principal-ref"]) { console.error("up requires --principal-ref (e.g. domain://alpha-host)"); process.exit(2); }
  const node = await startLocalAuthority({ stateDir, principalRef: options["principal-ref"], binary: options.binary, wallClock: !!options.wallClock });
  console.log(`READY  principal=${node.ready.principal_ref}  rpc=${node.daemonEnv.IOI_WALLET_NETWORK_RPC_ADDR}`);
  console.log(`daemon env: ${path.join(stateDir, "daemon.env")}`);
  console.log(`serve env:  ${path.join(stateDir, "serve.env")}`);
  console.log(`approver key (operator-custodied, 0600): ${node.approverKeyPath}`);
  const shutdown = async (why) => { console.log(`stopping (${why})…`); await node.stop(); process.exit(0); };
  process.on("SIGINT", () => shutdown("SIGINT"));
  process.on("SIGTERM", () => shutdown("SIGTERM"));
  await node.exitPromise;
  await node.stop();
} else if (command === "rotate" || command === "revoke" || command === "status") {
  const result = authorityAct(command, { stateDir, binary: options.binary, reason: options.reason });
  process.stdout.write(result.stdout);
  process.stderr.write(result.stderr);
  process.exit(result.ok ? 0 : 1);
} else {
  console.error(`unknown command ${command}`);
  process.exit(2);
}
