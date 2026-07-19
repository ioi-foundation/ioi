import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawn, spawnSync } from "node:child_process";
import { connect as connectTcp } from "node:net";
import { createServer as createTlsServer } from "node:tls";

import { mintApprovalGrant } from "../../../../scripts/lib/mint-approval-grant.mjs";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../..");
const seeds = new Map([
  ["domain://acme-host", "07".repeat(32)],
  ["org://acme/research", "07".repeat(32)],
  ["worker://independent-alloy-lab", "09".repeat(32)],
  ["worker://replication-lab-two", "0a".repeat(32)],
  ["worker://replication-lab-three", "0b".repeat(32)],
  ["worker://frontier-only-lab", "0c".repeat(32)],
]);

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function runOpenSsl(args, fixtureDir) {
  const result = spawnSync("openssl", args, { cwd: fixtureDir, encoding: "utf8" });
  if (result.error || result.status !== 0) {
    throw new Error(`openssl ${args[0]} failed: ${result.error?.message || result.stderr || `exit ${result.status}`}`);
  }
}

async function startPinnedTlsProxy(upstreamAddr, fixtureDir) {
  runOpenSsl([
    "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
    "-keyout", "wallet-network-ca.key", "-out", "wallet-network-ca.pem",
    "-subj", "/CN=IOI Hypervisor wallet.network fixture CA",
    "-addext", "basicConstraints=critical,CA:TRUE",
    "-addext", "keyUsage=critical,keyCertSign,cRLSign",
  ], fixtureDir);
  runOpenSsl([
    "req", "-new", "-newkey", "rsa:2048", "-nodes",
    "-keyout", "wallet-network-server.key", "-out", "wallet-network-server.csr",
    "-subj", "/CN=wallet-network.fixture",
  ], fixtureDir);
  writeFileSync(path.join(fixtureDir, "wallet-network-server.ext"), [
    "basicConstraints=critical,CA:FALSE",
    "keyUsage=critical,digitalSignature,keyEncipherment",
    "extendedKeyUsage=serverAuth",
    "subjectAltName=DNS:wallet-network.fixture",
    "",
  ].join("\n"));
  runOpenSsl([
    "x509", "-req", "-days", "1",
    "-in", "wallet-network-server.csr",
    "-CA", "wallet-network-ca.pem", "-CAkey", "wallet-network-ca.key", "-CAcreateserial",
    "-out", "wallet-network-server.pem", "-extfile", "wallet-network-server.ext",
  ], fixtureDir);

  const upstream = new URL(upstreamAddr.includes("://") ? upstreamAddr : `http://${upstreamAddr}`);
  const sockets = new Set();
  const server = createTlsServer({
    key: readFileSync(path.join(fixtureDir, "wallet-network-server.key")),
    cert: readFileSync(path.join(fixtureDir, "wallet-network-server.pem")),
    ALPNProtocols: ["h2"],
  }, (client) => {
    sockets.add(client);
    const target = connectTcp({ host: upstream.hostname, port: Number(upstream.port) });
    sockets.add(target);
    client.on("close", () => { sockets.delete(client); target.destroy(); });
    target.on("close", () => { sockets.delete(target); client.destroy(); });
    client.on("error", () => target.destroy());
    target.on("error", () => client.destroy());
    client.pipe(target);
    target.pipe(client);
  });
  server.on("tlsClientError", () => {});
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  server.on("error", () => {});
  return {
    rpcAddr: `https://127.0.0.1:${server.address().port}`,
    caPath: path.join(fixtureDir, "wallet-network-ca.pem"),
    serverName: "wallet-network.fixture",
    async stop() {
      for (const socket of sockets) socket.destroy();
      await new Promise((resolve) => server.close(resolve));
    },
  };
}

export async function startRealWalletNetworkPrincipalAuthorityFixture() {
  const fixtureDir = mkdtempSync(path.join(tmpdir(), "ioi-wallet-network-pa-"));
  let output = "";
  let exited = null;
  const child = spawn(
    "cargo",
    [
      "test", "-p", "ioi-cli",
      "--test", "hypervisor_wallet_network_fixture",
      "wallet_network_principal_authority_fixture",
      "--", "--ignored", "--nocapture",
    ],
    {
      cwd: repoRoot,
      env: {
        ...process.env,
        CARGO_TERM_COLOR: "never",
        IOI_HYPERVISOR_WALLET_FIXTURE_DIR: fixtureDir,
        IOI_GUARDIAN_KEY_PASS: "hypervisor-held-bar",
      },
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  const capture = (chunk) => {
    output = `${output}${chunk}`;
    if (output.length > 32_000) output = output.slice(-32_000);
  };
  child.stdout.on("data", capture);
  child.stderr.on("data", capture);
  child.once("exit", (code, signal) => { exited = { code, signal }; });
  const exitCleanup = () => {
    if (!exited) {
      try { writeFileSync(path.join(fixtureDir, "shutdown"), "parent-exit\n"); } catch { /* best effort */ }
    }
  };
  process.on("exit", exitCleanup);

  const readyPath = path.join(fixtureDir, "ready.json");
  const deadline = Date.now() + 600_000;
  while (!existsSync(readyPath)) {
    if (exited) {
      process.off("exit", exitCleanup);
      rmSync(fixtureDir, { recursive: true, force: true });
      throw new Error(`real wallet.network fixture exited before readiness (${JSON.stringify(exited)}):\n${output}`);
    }
    if (Date.now() >= deadline) {
      process.off("exit", exitCleanup);
      child.kill("SIGKILL");
      rmSync(fixtureDir, { recursive: true, force: true });
      throw new Error(`real wallet.network fixture did not become ready:\n${output}`);
    }
    await delay(50);
  }
  const manifest = JSON.parse(readFileSync(readyPath, "utf8"));
  let tlsProxy;
  try {
    tlsProxy = await startPinnedTlsProxy(manifest.rpc_addr, fixtureDir);
  } catch (error) {
    process.off("exit", exitCleanup);
    child.kill("SIGKILL");
    rmSync(fixtureDir, { recursive: true, force: true });
    throw error;
  }
  return {
    env: {
      IOI_WALLET_NETWORK_URL: "",
      IOI_WALLET_NETWORK_RPC_ADDR: tlsProxy.rpcAddr,
      IOI_WALLET_NETWORK_CHAIN_ID: String(manifest.chain_id),
      IOI_HYPERVISOR_WALLET_CLIENT_KEY_PATH: manifest.capability_key_path,
      IOI_WALLET_NETWORK_ROOT_RECORD_PATH: manifest.root_record_path,
      IOI_WALLET_NETWORK_TLS_CA_PATH: tlsProxy.caPath,
      IOI_WALLET_NETWORK_TLS_SERVER_NAME: tlsProxy.serverName,
      IOI_GUARDIAN_KEY_PASS: manifest.guardian_key_pass,
      // The in-process one-validator fixture intentionally executes and commits every lookup;
      // leave production's five-second default untouched, but do not make the positive held bar
      // flaky when the debug cluster is saturated by the full lifecycle journey.
      IOI_WALLET_NETWORK_RESOLUTION_TIMEOUT_MS: "180000",
      IOI_HYPERVISOR_GOVERNED_REPLAY_TIMEOUT_MS: "45000",
    },
    mint(principalRef, policyHash, requestHash) {
      const seed = seeds.get(principalRef);
      if (!seed) throw new Error(`real wallet.network fixture has no approver for ${principalRef}`);
      return mintApprovalGrant({ seed, policyHash, requestHash });
    },
    async stop() {
      process.off("exit", exitCleanup);
      await tlsProxy.stop();
      if (!exited) writeFileSync(path.join(fixtureDir, "shutdown"), "stop\n");
      const stopDeadline = Date.now() + 30_000;
      while (!exited && Date.now() < stopDeadline) await delay(25);
      if (!exited) child.kill("SIGKILL");
      rmSync(fixtureDir, { recursive: true, force: true });
    },
  };
}
