#!/usr/bin/env node

// M4 canonical-route retirement proof for the predecessor OutcomeRoom v1 aggregate.
// The historical fixture is planted directly into an isolated throwaway data directory: no
// public compatibility mutation route exists, and the canonical family must never surface or
// mutate it. This verifier creates no retained evidence and makes no product/release claim.

import { createHash } from "node:crypto";
import {
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readlinkSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  isIsolatedDaemonLogName,
  sanitizedVerifierBaseEnv,
  startIsolatedPlane,
} from "./lib/isolated-daemon.mjs";

const ROOM_BASE = "/v1/goal-orchestration/outcome-rooms";
const LEGACY_TAIL = "or_deadbeef";
const LEGACY_PATH = `${ROOM_BASE}/${LEGACY_TAIL}`;
const results = [];
const EXPECTED_CHECKS = 23;
const CLEAN_BASE_ENV = sanitizedVerifierBaseEnv();
const check = (name, pass, detail = "") => results.push({ name, pass: !!pass, detail });
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

const legacyRoom = {
  schema_version: "ioi.hypervisor.outcome-room.v1",
  outcome_room_id: `outcome-room://${LEGACY_TAIL}`,
  owner_or_sponsor_ref: "org://historical-fixture",
  objective_ref: "goal://historical-fixture",
  objective: "Historical predecessor fixture; never canonical M4 truth.",
  room_mode: "permissioned_team",
  coordination_topology: "hosted_admission",
  host_domain_ref: "domain://historical-fixture",
  status: "open",
  revision: 1,
  member_goal_run_refs: [],
  admission_and_replay_refs: [],
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
};

function wireTokenVariants(values) {
  const variants = new Set();
  const htmlAttributeEscape = (value) =>
    value
      .replaceAll("&", "&amp;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#39;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;");
  for (const candidate of values) {
    if (typeof candidate !== "string" || candidate.length === 0) continue;
    const bytes = Buffer.from(candidate, "utf8");
    for (const variant of [
      candidate,
      encodeURIComponent(candidate),
      bytes.toString("base64"),
      bytes.toString("base64url"),
      htmlAttributeEscape(candidate),
      [...candidate].map((character) => `&#${character.codePointAt(0)};`).join(""),
      [...candidate]
        .map((character) => `&#x${character.codePointAt(0).toString(16)};`)
        .join(""),
    ]) {
      if (variant.length > 0) variants.add(variant);
    }
  }
  return [...variants].map((value) => Buffer.from(value, "utf8"));
}

const legacyNonleakTokens = wireTokenVariants([
  legacyRoom.schema_version,
  legacyRoom.objective,
  legacyRoom.outcome_room_id,
  legacyRoom.owner_or_sponsor_ref,
  legacyRoom.objective_ref,
  legacyRoom.host_domain_ref,
  LEGACY_TAIL,
  JSON.stringify(legacyRoom),
]);

async function boundedResponseBytes(response, limit = 4 * 1024 * 1024) {
  const chunks = [];
  let bytes = 0;
  if (!response.body) return Buffer.alloc(0);
  const reader = response.body.getReader();
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    bytes += value.byteLength;
    if (bytes > limit) {
      await reader.cancel("response_oversize").catch(() => {});
      throw new Error(`daemon_response_oversize:${response.url}`);
    }
    chunks.push(Buffer.from(value));
  }
  return Buffer.concat(chunks);
}

function responseDoesNotLeakLegacyTruth(response) {
  if (!Buffer.isBuffer(response?.raw)) return false;
  const wire = Buffer.concat([
    Buffer.from(JSON.stringify(response.headers || {}), "utf8"),
    Buffer.from("\n", "utf8"),
    response.raw,
  ]);
  return legacyNonleakTokens.every((token) => !wire.includes(token));
}

async function call(base, method, path, body) {
  const response = await fetch(`${base}${path}`, {
    method,
    headers: { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(60_000),
  });
  const raw = await boundedResponseBytes(response);
  return {
    status: response.status,
    headers: Object.fromEntries(response.headers.entries()),
    raw,
    body: (() => {
      try {
        return JSON.parse(raw.toString("utf8"));
      } catch {
        return {};
      }
    })(),
  };
}

function durableSnapshot(root, { includeRootMetadata = true } = {}) {
  const metadataFields = (metadata, type) => ({
    type,
    inode: String(metadata.ino),
    mode: Number(metadata.mode),
    nlink: String(metadata.nlink),
    mtime_ns: String(metadata.mtimeNs),
    ctime_ns: String(metadata.ctimeNs),
  });
  const rootMetadata = lstatSync(root, { bigint: true });
  const entries = includeRootMetadata
    ? [["", metadataFields(rootMetadata, "directory")]]
    : [];
  const visit = (directory, prefix = "") => {
    for (const name of readdirSync(directory).sort()) {
      // Only verifier-owned transport logs are outside durable product state.
      if (!prefix && isIsolatedDaemonLogName(name)) continue;
      const path = join(directory, name);
      const relative = prefix ? `${prefix}/${name}` : name;
      const metadata = lstatSync(path, { bigint: true });
      if (metadata.isSymbolicLink()) {
        entries.push([
          relative,
          { ...metadataFields(metadata, "symlink"), target: readlinkSync(path) },
        ]);
      } else if (metadata.isDirectory()) {
        entries.push([relative, metadataFields(metadata, "directory")]);
        visit(path, relative);
      } else if (metadata.isFile()) {
        entries.push([
          relative,
          {
            ...metadataFields(metadata, "file"),
            size: String(metadata.size),
            root: `sha256:${sha256(readFileSync(path))}`,
          },
        ]);
      } else {
        entries.push([relative, metadataFields(metadata, "non-regular")]);
      }
    }
  };
  visit(root);
  return JSON.stringify(entries);
}
const snapshotHash = (root) => sha256(durableSnapshot(root));

function durableProductContentSnapshot(root) {
  const entries = JSON.parse(
    durableSnapshot(root, { includeRootMetadata: false }),
  );
  return JSON.stringify(
    entries.map(([path, metadata]) => {
      const { inode: _inode, mtime_ns: _mtime, ctime_ns: _ctime, ...stable } = metadata;
      return [path, stable];
    }),
  );
}

function snapshotDelta(before, after) {
  const beforeByPath = new Map(JSON.parse(before));
  const afterByPath = new Map(JSON.parse(after));
  return [...new Set([...beforeByPath.keys(), ...afterByPath.keys()])]
    .sort()
    .filter(
      (path) =>
        JSON.stringify(beforeByPath.get(path) ?? null) !==
        JSON.stringify(afterByPath.get(path) ?? null),
    )
    .slice(0, 8)
    .map(
      (path) =>
        `${path || "."}:before=${JSON.stringify(beforeByPath.get(path) ?? null)};after=${JSON.stringify(afterByPath.get(path) ?? null)}`,
    )
    .join("|");
}

async function assertRetired(base, expectedBytes, phase) {
  const list = await call(base, "GET", ROOM_BASE);
  check(
    `${phase}: canonical list is v2-only and excludes the historical v1 record`,
    list.status === 200 &&
      list.body.schema_version === "ioi.foundations.outcome-room.v2" &&
      Array.isArray(list.body.outcome_rooms) &&
      list.body.outcome_rooms.length === 0 &&
      responseDoesNotLeakLegacyTruth(list),
    `${list.status}/${list.body.schema_version}/${list.body.outcome_rooms?.length}/wire_nonleak=${responseDoesNotLeakLegacyTruth(list)}`,
  );
  const overview = await call(base, "GET", `${ROOM_BASE}/overview`);
  check(
    `${phase}: canonical overview counts only v2 rooms`,
      overview.status === 200 &&
      overview.body.room_contract_version === "v2" &&
      overview.body.outcome_rooms === 0 &&
      responseDoesNotLeakLegacyTruth(overview),
    `${overview.status}/${overview.body.room_contract_version}/${overview.body.outcome_rooms}/wire_nonleak=${responseDoesNotLeakLegacyTruth(overview)}`,
  );
  const get = await call(base, "GET", LEGACY_PATH);
  check(
    `${phase}: canonical GET returns the stable v1 read-retired refusal`,
    get.status === 410 &&
      get.body.error?.code === "outcome_room_v1_read_retired" &&
      responseDoesNotLeakLegacyTruth(get),
    `${get.status}/${get.body.error?.code}/wire_nonleak=${responseDoesNotLeakLegacyTruth(get)}`,
  );
  for (const [requests, label] of [
    [
      [
        [
          "/lifecycle/transitions",
          { transition: "pause", expected_revision: 1 },
          "outcome_room_v1_write_retired",
        ],
        [
          "/transition",
          { transition: "pause", expected_revision: 1 },
          "outcome_room_transition_route_retired",
        ],
      ],
      "canonical and retired lifecycle",
    ],
    [
      [
        [
          "/attach-goal-run",
          { goal_run_ref: "goal://ghost", expected_revision: 1 },
          "outcome_room_v1_write_retired",
        ],
        [
          "/detach-goal-run",
          { goal_run_ref: "goal://ghost", expected_revision: 1 },
          "outcome_room_v1_write_retired",
        ],
      ],
      "membership attach and detach",
    ],
  ]) {
    const responses = await Promise.all(
      requests.map(async ([suffix, body, expectedCode]) => ({
        expectedCode,
        response: await call(base, "POST", `${LEGACY_PATH}${suffix}`, body),
      })),
    );
    check(
      `${phase}: ${label} writes return their stable typed retirement refusals`,
      responses.every(
        ({ response, expectedCode }) =>
          response.status === 410 &&
          response.body.error?.code === expectedCode &&
          responseDoesNotLeakLegacyTruth(response),
      ),
      responses
        .map(
          ({ response, expectedCode }) =>
            `${response.status}/${response.body.error?.code}/expected=${expectedCode}/wire_nonleak=${responseDoesNotLeakLegacyTruth(response)}`,
        )
        .join(","),
    );
  }
  for (const suffix of [
    "/replay",
    "/collaborative-work-graph",
    "/discussion-projection",
    "/product-projection",
  ]) {
    const response = await call(base, "GET", `${LEGACY_PATH}${suffix}`);
    check(
      `${phase}: canonical ${suffix.slice(1)} returns the stable v1 read-retired refusal`,
      response.status === 410 &&
        response.body.error?.code === "outcome_room_v1_read_retired" &&
        responseDoesNotLeakLegacyTruth(response),
      `${response.status}/${response.body.error?.code}/wire_nonleak=${responseDoesNotLeakLegacyTruth(response)}`,
    );
  }
  const currentBytes = readFileSync(expectedBytes.path);
  check(
    `${phase}: every retirement refusal leaves all durable bytes unchanged`,
    sha256(currentBytes) === expectedBytes.hash &&
      durableSnapshot(expectedBytes.root) === expectedBytes.snapshot,
    `${sha256(currentBytes)}/${snapshotHash(expectedBytes.root)}`,
  );
}

async function run() {
  const dataDir = mkdtempSync(join(tmpdir(), "ioi-m4-room-v1-retired-"));
  let plane = null;
  try {
    plane = await startIsolatedPlane({
      serve: false,
      dataDir,
      baseEnv: CLEAN_BASE_ENV,
    });
    if (!plane) {
      console.error("BLOCKED: target/debug/hypervisor-daemon is not built");
      process.exit(2);
    }
    const initial = durableSnapshot(dataDir);
    const retiredCreate = await call(plane.daemonUrl, "POST", ROOM_BASE, legacyRoom);
    check(
      "non-v2 canonical create returns 410 outcome_room_v1_write_retired",
      retiredCreate.status === 410 &&
        retiredCreate.body.error?.code === "outcome_room_v1_write_retired" &&
        responseDoesNotLeakLegacyTruth(retiredCreate),
      `${retiredCreate.status}/${retiredCreate.body.error?.code}/wire_nonleak=${responseDoesNotLeakLegacyTruth(retiredCreate)}`,
    );
    check(
      "retired create writes no durable product state",
      durableSnapshot(dataDir) === initial,
      snapshotHash(dataDir),
    );

    const roomDirectory = join(dataDir, "outcome-room-registry");
    mkdirSync(roomDirectory, { recursive: true });
    const legacyFile = join(roomDirectory, `${LEGACY_TAIL}.json`);
    writeFileSync(legacyFile, `${JSON.stringify(legacyRoom)}\n`, { flag: "wx" });
    const expectedBytes = {
      path: legacyFile,
      hash: sha256(readFileSync(legacyFile)),
      root: dataDir,
      snapshot: durableSnapshot(dataDir),
    };
    await assertRetired(plane.daemonUrl, expectedBytes, "live");

    await plane.stop();
    plane = null;
    const beforeRestartProductState = durableProductContentSnapshot(dataDir);
    const restarted = await startIsolatedPlane({
      serve: false,
      dataDir,
      baseEnv: CLEAN_BASE_ENV,
    });
    if (!restarted) throw new Error("daemon binary disappeared before restart proof");
    plane = restarted;
    const afterRestartProductState = durableProductContentSnapshot(dataDir);
    if (afterRestartProductState !== beforeRestartProductState) {
      throw new Error(
        `daemon restart changed retired-room product state:${snapshotDelta(beforeRestartProductState, afterRestartProductState)}`,
      );
    }
    // A reused isolated plane creates a verifier-owned root log. After proving startup changed
    // no product entry, bind request assertions to the new exact root metadata as well.
    expectedBytes.snapshot = durableSnapshot(dataDir);
    await assertRetired(plane.daemonUrl, expectedBytes, "restart");

    const beforeRetry = durableSnapshot(dataDir);
    const retry = await call(plane.daemonUrl, "POST", ROOM_BASE, legacyRoom);
    check(
      "restart preserves non-v2 create retirement with zero additional durable records",
      retry.status === 410 &&
        retry.body.error?.code === "outcome_room_v1_write_retired" &&
        responseDoesNotLeakLegacyTruth(retry) &&
        durableSnapshot(dataDir) === beforeRetry,
      `${retry.status}/${retry.body.error?.code}/wire_nonleak=${responseDoesNotLeakLegacyTruth(retry)}/${snapshotHash(dataDir)}`,
    );
  } finally {
    if (plane) await plane.stop();
    rmSync(dataDir, { recursive: true, force: true });
  }
}

run()
  .then(() => {
    let failed = 0;
    for (const result of results) {
      console.log(
        `  ${result.pass ? "PASS" : "FAIL"}  ${result.name}${result.detail ? `  (${result.detail})` : ""}`,
      );
      if (!result.pass) failed += 1;
    }
    console.log(`\n${results.length - failed}/${results.length} passed`);
    const coverageMismatch = results.length !== EXPECTED_CHECKS;
    if (coverageMismatch) {
      console.error(`FAIL verifier coverage changed: expected ${EXPECTED_CHECKS}, got ${results.length}`);
    }
    console.log(
      `M4 OutcomeRoom v1 retirement: ${failed || coverageMismatch ? "FAIL" : "OK"}`,
    );
    process.exit(failed || coverageMismatch ? 1 : 0);
  })
  .catch((error) => {
    console.error("verifier crashed:", error);
    process.exit(1);
  });
