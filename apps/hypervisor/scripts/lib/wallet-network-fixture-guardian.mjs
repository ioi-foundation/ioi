#!/usr/bin/env node

import { spawn } from "node:child_process";
import {
  closeSync,
  fsyncSync,
  openSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";

function requiredEnv(name) {
  const value = process.env[name];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${name} is required`);
  }
  return value;
}

function processStartTimeTicks(pid) {
  const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
  const commandEnd = stat.lastIndexOf(") ");
  if (commandEnd < 0) {
    throw new Error(`process stat for ${pid} has no command terminator`);
  }
  const startTimeTicks = stat
    .slice(commandEnd + 2)
    .trim()
    .split(/\s+/)[19];
  if (!/^[0-9]+$/.test(startTimeTicks || "")) {
    throw new Error(`process stat for ${pid} has no start-time field`);
  }
  return startTimeTicks;
}

function processGroupId(pid) {
  const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
  const commandEnd = stat.lastIndexOf(") ");
  if (commandEnd < 0) {
    throw new Error(`process stat for ${pid} has no command terminator`);
  }
  const groupId = stat
    .slice(commandEnd + 2)
    .trim()
    .split(/\s+/)[2];
  if (!/^[0-9]+$/.test(groupId || "")) {
    throw new Error(`process stat for ${pid} has no process-group field`);
  }
  return Number(groupId);
}

function processIdentityMatches(pid, expectedStartTimeTicks) {
  try {
    return processStartTimeTicks(pid) === expectedStartTimeTicks;
  } catch (error) {
    if (error?.code === "ENOENT") return false;
    throw error;
  }
}

function publishOwnerMarker(fixtureDir, ownerPid, ownerStartTimeTicks) {
  const markerPath = path.join(fixtureDir, ".ioi-verifier-owner.json");
  const temporary = `${markerPath}.${process.pid}.tmp`;
  const marker = JSON.stringify({
    schema_version: 2,
    owner_pid: ownerPid,
    owner_start_time_ticks: ownerStartTimeTicks,
    owner_kind: "wallet-network-principal-authority-fixture",
    process_group_id: process.pid,
    process_group_start_time_ticks: processStartTimeTicks(process.pid),
  });
  writeFileSync(temporary, marker, {
    encoding: "utf8",
    flag: "wx",
    mode: 0o600,
  });
  const temporaryFd = openSync(temporary, "r");
  try {
    fsyncSync(temporaryFd);
  } finally {
    closeSync(temporaryFd);
  }
  renameSync(temporary, markerPath);
  const directoryFd = openSync(fixtureDir, "r");
  try {
    fsyncSync(directoryFd);
  } finally {
    closeSync(directoryFd);
  }
}

function run() {
  const fixtureDir = requiredEnv("IOI_HYPERVISOR_WALLET_FIXTURE_DIR");
  const ownerPid = Number(
    requiredEnv("IOI_HYPERVISOR_WALLET_FIXTURE_OWNER_PID"),
  );
  if (!Number.isInteger(ownerPid) || ownerPid <= 0) {
    throw new Error(
      "IOI_HYPERVISOR_WALLET_FIXTURE_OWNER_PID must be a positive integer",
    );
  }
  const ownerStartTimeTicks = requiredEnv(
    "IOI_HYPERVISOR_WALLET_FIXTURE_OWNER_START_TIME_TICKS",
  );
  if (!/^[0-9]+$/.test(ownerStartTimeTicks)) {
    throw new Error(
      "IOI_HYPERVISOR_WALLET_FIXTURE_OWNER_START_TIME_TICKS must be numeric",
    );
  }
  if (processGroupId(process.pid) !== process.pid) {
    throw new Error("wallet fixture guardian must be its process-group leader");
  }
  const cargoCwd = requiredEnv("IOI_WALLET_FIXTURE_GUARDIAN_CARGO_CWD");
  const cargoArgs = JSON.parse(
    requiredEnv("IOI_WALLET_FIXTURE_GUARDIAN_CARGO_ARGS"),
  );
  if (
    !Array.isArray(cargoArgs) ||
    cargoArgs.length === 0 ||
    cargoArgs.some((value) => typeof value !== "string")
  ) {
    throw new Error(
      "IOI_WALLET_FIXTURE_GUARDIAN_CARGO_ARGS must be a nonempty string array",
    );
  }

  if (!processIdentityMatches(ownerPid, ownerStartTimeTicks)) {
    throw new Error("wallet fixture owner exited before guardian startup");
  }
  publishOwnerMarker(fixtureDir, ownerPid, ownerStartTimeTicks);
  if (!processIdentityMatches(ownerPid, ownerStartTimeTicks)) {
    throw new Error("wallet fixture owner exited before cargo startup");
  }
  const cargo = spawn("cargo", cargoArgs, {
    cwd: cargoCwd,
    env: process.env,
    stdio: ["ignore", "inherit", "inherit"],
  });
  const ownerWatch = setInterval(() => {
    let ownerMatches = false;
    try {
      ownerMatches = processIdentityMatches(ownerPid, ownerStartTimeTicks);
    } catch {
      // An unverifiable owner is not authority to keep the fixture alive.
    }
    if (ownerMatches) return;
    try {
      process.kill(-process.pid, "SIGKILL");
    } catch {
      process.exit(1);
    }
  }, 25);
  cargo.once("error", (error) => {
    clearInterval(ownerWatch);
    process.stderr.write(`wallet fixture cargo spawn failed: ${error.message}\n`);
    process.exit(1);
  });
  cargo.once("exit", (code, signal) => {
    clearInterval(ownerWatch);
    if (signal) {
      process.stderr.write(`wallet fixture cargo exited on ${signal}\n`);
      process.exit(1);
    }
    process.exit(code ?? 1);
  });
}

try {
  run();
} catch (error) {
  process.stderr.write(`${error.stack || error.message || error}\n`);
  process.exit(1);
}
