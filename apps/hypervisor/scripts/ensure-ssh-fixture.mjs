// Loopback SSH fixture for the BYO provider plane — a REAL sshd on 127.0.0.1:2222 with its own
// host/client keypair, so the baremetal_ssh adapter is exercised over a genuine ssh transport
// (credential sealing, preflight, remote exec, tar snapshot streaming) without needing a second
// machine in CI. Idempotent: keys/config are created once, sshd is started only if 2222 is not
// already listening. Usage: `node ensure-ssh-fixture.mjs` prints the fixture JSON, or import
// { ensureSshFixture } from a verifier.
import { execFileSync, spawn } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync, chmodSync } from "node:fs";
import { connect } from "node:net";
import os from "node:os";
import path from "node:path";

const FIXTURE_DIR = path.join(os.homedir(), ".ioi", "hypervisor", "ssh-fixture");
const PORT = 2222;

function listening(port) {
  return new Promise((resolve) => {
    const s = connect({ host: "127.0.0.1", port, timeout: 1500 }, () => { s.destroy(); resolve(true); });
    s.on("error", () => resolve(false));
    s.on("timeout", () => { s.destroy(); resolve(false); });
  });
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

export async function ensureSshFixture() {
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
  if (!(await listening(PORT))) {
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
