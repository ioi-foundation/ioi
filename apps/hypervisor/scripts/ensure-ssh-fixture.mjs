// Loopback SSH fixture for the BYO provider plane — a REAL sshd on 127.0.0.1 (port 2222 when free) with its
// own host/client keypair, so the baremetal_ssh adapter is exercised over a genuine ssh transport
// (credential sealing, preflight, remote exec, tar snapshot streaming) without needing a second
// machine in CI. Idempotent: keys/config are created once, sshd is started only if this fixture's own
// sshd is not already listening. Usage: `node ensure-ssh-fixture.mjs` prints the fixture JSON, or import
// { ensureSshFixture } from a verifier.
//
// NEVER THE OWNER'S HOME (R-240, verifier hygiene, 2026-09-29): the fixture lived in ~/.ioi/hypervisor/ssh-fixture,
// beside the owner's daemon data. It now lives in IOI_SSH_FIXTURE_DIR or a per-user dir under the temp root, and a
// dir under ~/.ioi/hypervisor is refused by name. Port 2222 answered by an sshd that is not this fixture's (keys it
// does not hold) is never adopted: the fixture starts its own on a free port and records it.
import { execFileSync, spawn } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync, chmodSync } from "node:fs";
import { connect, createServer } from "node:net";
import os from "node:os";
import path from "node:path";
import { refuseOwnerPath } from "./lib/verifier-stack.mjs";

export function sshFixtureDir(env = process.env) {
  const dir = env.IOI_SSH_FIXTURE_DIR || path.join(os.tmpdir(), `ioi-verifier-ssh-fixture-${os.userInfo().uid}`);
  return refuseOwnerPath(path.resolve(dir), "ssh fixture dir");
}
const PREFERRED_PORT = Number(process.env.IOI_SSH_FIXTURE_PORT || 2222);

function listening(port) {
  return new Promise((resolve) => {
    const s = connect({ host: "127.0.0.1", port, timeout: 1500 }, () => { s.destroy(); resolve(true); });
    s.on("error", () => resolve(false));
    s.on("timeout", () => { s.destroy(); resolve(false); });
  });
}

function freePort() {
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
    srv.on("error", reject);
  });
}

// This fixture's own sshd, when it is alive and listening on the port it recorded; otherwise the port to start one on.
async function fixturePort(dir) {
  try {
    const pid = Number(readFileSync(path.join(dir, "sshd.pid"), "utf8").trim());
    const port = Number(readFileSync(path.join(dir, "port"), "utf8").trim());
    process.kill(pid, 0); // existence probe only
    if (port > 0 && (await listening(port))) return { port, running: true };
  } catch { /* not started, or gone */ }
  if (!(await listening(PREFERRED_PORT))) return { port: PREFERRED_PORT, running: false };
  return { port: await freePort(), running: false };
}

function findSshd() {
  const candidates = [
    path.join(os.homedir(), ".local/opt/openssh-userland/usr/sbin/sshd"),
    "/usr/sbin/sshd",
    "/usr/local/sbin/sshd",
  ];
  try {
    const p = execFileSync("sh", ["-c", "command -v sshd"], { encoding: "utf8" }).trim();
    if (p) candidates.unshift(p);
  } catch { /* not on PATH */ }
  const found = candidates.find((c) => existsSync(c));
  if (!found) throw new Error("no sshd binary found — install openssh-server (or the userland build) to run the SSH fixture");
  return found;
}

export async function ensureSshFixture({ dir: FIXTURE_DIR = sshFixtureDir() } = {}) {
  refuseOwnerPath(FIXTURE_DIR, "ssh fixture dir");
  mkdirSync(FIXTURE_DIR, { recursive: true, mode: 0o700 });
  const hostKey = path.join(FIXTURE_DIR, "host_key");
  const clientKey = path.join(FIXTURE_DIR, "client_key");
  for (const key of [hostKey, clientKey]) {
    if (!existsSync(key)) execFileSync("ssh-keygen", ["-t", "ed25519", "-N", "", "-q", "-f", key]);
  }
  const authKeys = path.join(FIXTURE_DIR, "authorized_keys");
  writeFileSync(authKeys, readFileSync(`${clientKey}.pub`));
  chmodSync(authKeys, 0o600);
  const sshdBin = findSshd();
  // The sftp subsystem is optional for this fixture (the adapter uses exec + tar streams); declare
  // it only when the companion binary exists so sshd config validation never fails on its absence.
  const sftpCandidates = [
    path.join(path.dirname(sshdBin), "../lib/openssh/sftp-server"),
    "/usr/lib/openssh/sftp-server",
    "/usr/libexec/sftp-server",
  ];
  const sftp = sftpCandidates.find((c) => existsSync(c));
  const { port: PORT, running } = await fixturePort(FIXTURE_DIR);
  const config = [
    `Port ${PORT}`,
    "ListenAddress 127.0.0.1",
    `HostKey ${hostKey}`,
    `AuthorizedKeysFile ${authKeys}`,
    "PasswordAuthentication no",
    "KbdInteractiveAuthentication no",
    "PubkeyAuthentication yes",
    "UsePAM no",
    `PidFile ${path.join(FIXTURE_DIR, "sshd.pid")}`,
    ...(sftp ? [`Subsystem sftp ${sftp}`] : []),
    "StrictModes no",
    "",
  ].join("\n");
  const configPath = path.join(FIXTURE_DIR, "sshd_config");
  writeFileSync(configPath, config);
  if (!running) {
    writeFileSync(path.join(FIXTURE_DIR, "port"), `${PORT}\n`);
    const log = path.join(FIXTURE_DIR, "sshd.log");
    // -E: append to our log; detached so the fixture outlives the verifier process.
    const child = spawn(sshdBin, ["-f", configPath, "-E", log], { detached: true, stdio: "ignore" });
    child.unref();
    for (let i = 0; i < 20 && !(await listening(PORT)); i++) await new Promise((r) => setTimeout(r, 250));
    if (!(await listening(PORT))) throw new Error(`sshd did not come up on 127.0.0.1:${PORT} — see ${log}`);
  }
  return {
    host: "127.0.0.1",
    port: PORT,
    user: os.userInfo().username,
    client_key_path: clientKey,
    client_key: readFileSync(clientKey, "utf8"),
  };
}

if (process.argv[1] && import.meta.url.endsWith(path.basename(process.argv[1]))) {
  ensureSshFixture()
    .then((f) => console.log(JSON.stringify({ ...f, client_key: `<${f.client_key.length} bytes sealed-at-bind>` }, null, 2)))
    .catch((e) => { console.error(String(e)); process.exit(1); });
}
