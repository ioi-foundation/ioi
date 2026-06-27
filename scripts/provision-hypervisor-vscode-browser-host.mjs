#!/usr/bin/env node
// WS-2 — reproducible OSS browser-IDE runtime provisioner (openvscode-server).
//
// The Phase 1 (~/.ioi/vm-toolchain) supply-manifest pattern, applied to the editor host: a pinned
// version + URL + sha256, a fetch-once cache, checksum verification, and FAIL-CLOSED behavior. The
// OSS lane is reproducible — NOT a permitted host-gap (a vendor VS Code Server variant may be
// license-gated, the OSS openvscode runtime is not). The upstream stripped reference binary is never vendored.
//
// Installs into ~/.ioi/editor-toolchain/openvscode-server (override IOI_HYPERVISOR_EDITOR_TOOLCHAIN_DIR).
// Idempotent: reuses an installed runtime whose checksum still matches the pin.
// Usage: node scripts/provision-hypervisor-vscode-browser-host.mjs [--json] [--force]
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, statSync, createWriteStream, rmSync, symlinkSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

const REPO = new URL("..", import.meta.url).pathname;
const args = process.argv.slice(2);
const JSON_OUT = args.includes("--json");
const FORCE = args.includes("--force");
const MANIFEST = join(REPO, "scripts/editor-host/openvscode-supply-manifest.json");
const DEST = process.env.IOI_HYPERVISOR_EDITOR_TOOLCHAIN_DIR || join(homedir(), ".ioi/editor-toolchain");
const CACHE = join(DEST, "cache");

const log = (m) => { if (!JSON_OUT) console.log(m); };
const fail = (reason) => { console.log(JSON_OUT ? JSON.stringify({ ok: false, reason }, null, 2) : `[ws-2] FAIL: ${reason}`); process.exit(1); };

if (!existsSync(MANIFEST)) fail(`supply manifest missing: ${MANIFEST}`);
const m = JSON.parse(readFileSync(MANIFEST, "utf8"));
const { version, linux_x64 } = m;
// Operator-supplied artifact URL (env first; an operator may add a local linux_x64.url override).
// The product tree carries NO vendor-origin URL — only the sha256 pin that the artifact must match.
const runtimeUrl = process.env[m.urlEnv || "IOI_EDITOR_RUNTIME_URL"] || linux_x64?.url;
if (!runtimeUrl || !linux_x64?.sha256) fail(`set ${m.urlEnv || "IOI_EDITOR_RUNTIME_URL"} to a pinned OpenVSCode-protocol runtime tarball (operator-supplied, verified against the manifest sha256; never vendored)`);

const sha = (p) => createHash("sha256").update(readFileSync(p)).digest("hex");
const installRoot = join(DEST, `openvscode-server-v${version}-linux-x64`);
const stableLink = join(DEST, "openvscode-server");
const serverBin = join(stableLink, "bin/openvscode-server");

// Idempotent reuse: a present, executable runtime whose tarball still checksums to the pin.
const tarball = join(CACHE, `openvscode-server-v${version}-linux-x64.tar.gz`);
if (!FORCE && existsSync(serverBin) && (statSync(serverBin).mode & 0o111)) {
  if (existsSync(tarball) && sha(tarball) === linux_x64.sha256) {
    const out = { ok: true, reused: true, version, install_root: installRoot, server_bin: serverBin, sha256: linux_x64.sha256 };
    console.log(JSON_OUT ? JSON.stringify(out, null, 2) : `[ws-2] reused pinned openvscode-server v${version} (checksum verified) at ${serverBin}`);
    process.exit(0);
  }
  log(`[ws-2] runtime present but cache tarball missing/mismatched — re-verifying via fresh fetch`);
}

mkdirSync(CACHE, { recursive: true });

async function download(url, dest) {
  log(`[ws-2] fetching ${url}`);
  const res = await fetch(url, { redirect: "follow" });
  if (!res.ok) fail(`download failed: HTTP ${res.status}`);
  const file = createWriteStream(dest);
  const reader = res.body.getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    file.write(Buffer.from(value));
  }
  await new Promise((r) => file.end(r));
}

// fetch-once cache: only download if the cached tarball is absent or fails the checksum.
if (FORCE || !existsSync(tarball) || sha(tarball) !== linux_x64.sha256) {
  await download(runtimeUrl, tarball);
}
const got = sha(tarball);
if (got !== linux_x64.sha256) fail(`checksum_mismatch: expected ${linux_x64.sha256}, got ${got} (fail-closed; not installing)`);
log(`[ws-2] checksum verified (${got.slice(0, 16)}…)`);

// extract + stable symlink.
rmSync(installRoot, { recursive: true, force: true });
const tar = spawnSync("tar", ["-xzf", tarball, "-C", DEST], { encoding: "utf8" });
if (tar.status !== 0) fail(`extract failed: ${tar.stderr}`);
try { rmSync(stableLink, { force: true }); } catch { /* not a file */ }
try { rmSync(stableLink, { recursive: true, force: true }); } catch { /* not a dir */ }
symlinkSync(installRoot, stableLink);
if (!existsSync(serverBin) || !(statSync(serverBin).mode & 0o111)) fail(`server binary missing/not executable after extract: ${serverBin}`);

const out = { ok: true, reused: false, version, install_root: installRoot, server_bin: serverBin, sha256: got };
console.log(JSON_OUT ? JSON.stringify(out, null, 2) : `[ws-2] provisioned reproducible openvscode-server v${version} (sha256 ${got.slice(0, 16)}…) at ${serverBin}`);
