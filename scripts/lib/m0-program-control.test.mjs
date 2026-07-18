import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  assertUniqueIdentities,
  discoverAxumRoutes,
  discoverJsStorageMutations,
  discoverJsSystemEffects,
  discoverRustMatchServiceMethods,
} from "./m0-program-control.mjs";
import {
  EVIDENCE_DIR,
  PG_IDS,
  assertRenderedArtifactsCurrent,
  createInitialReview,
  discoverRepositorySurface,
  loadM0Sources,
  validateProgramSource,
  validateReviewLock,
} from "./m0-program-control-model.mjs";

const testFile = fileURLToPath(import.meta.url);
const repoRoot = path.resolve(path.dirname(testFile), "../..");
const cli = "scripts/m0-program-control.mjs";
const discoveredEntries = discoverRepositorySurface(repoRoot);
const { reviewLock, programSource } = loadM0Sources(repoRoot);

function temporaryRepository(files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-m0-fixture-"));
  for (const [relativePath, source] of Object.entries(files)) {
    const target = path.join(root, relativePath);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, source);
  }
  return root;
}

function hashEvidenceTree() {
  const root = path.join(repoRoot, EVIDENCE_DIR);
  return Object.fromEntries(
    fs.readdirSync(root)
      .sort()
      .map((name) => {
        const source = fs.readFileSync(path.join(root, name));
        const stat = fs.statSync(path.join(root, name), { bigint: true });
        return [
          name,
          {
            sha256: crypto.createHash("sha256").update(source).digest("hex"),
            mtime_ns: stat.mtimeNs.toString(),
          },
        ];
      }),
  );
}

function expectReviewFailure(mutator, pattern) {
  const fixture = structuredClone(reviewLock);
  mutator(fixture);
  assert.throws(
    () => validateReviewLock(repoRoot, discoveredEntries, fixture),
    pattern,
  );
}

function expectProgramFailure(mutator, pattern) {
  const fixture = structuredClone(programSource);
  mutator(fixture);
  assert.throws(
    () => validateProgramSource(
      repoRoot,
      discoveredEntries,
      reviewLock,
      fixture,
    ),
    pattern,
  );
}

test("structured discovery finds every literal Axum method and route identity", () => {
  const root = temporaryRepository({
    "routes.rs": `
      fn app() {
        Router::new()
          .route("/v1/items", get(list_items).post(create_item))
          .route("/v1/items/:id", patch(update_item).delete(delete_item));
      }
    `,
  });
  try {
    const entries = discoverAxumRoutes({
      repoRoot: root,
      relativePath: "routes.rs",
      surface: "fixture",
    });
    assert.deepEqual(
      entries.map((entry) => entry.identity),
      [
        "http:fixture:GET /v1/items",
        "http:fixture:POST /v1/items",
        "http:fixture:PATCH /v1/items/:id",
        "http:fixture:DELETE /v1/items/:id",
      ],
    );
  } finally {
    fs.rmSync(root, { force: true, recursive: true });
  }
});

test("Rust service discovery stops the last literal arm before the wildcard", () => {
  const root = temporaryRepository({
    "service.rs": `
      impl BlockchainService for FixtureService {
        fn id(&self) -> &str { "fixture" }
        async fn handle_service_call(&self, state: &mut State, method: &str) {
          match method {
            "first@v1" => { state.insert(b"first", b"value"); }
            "last@v1" => { state.delete(b"last"); }
            _ => Err(TransactionError::Unsupported(format!("unsupported {}", method))),
          }
        }
      }
    `,
  });
  try {
    const entries = discoverRustMatchServiceMethods({
      repoRoot: root,
      relativePath: "service.rs",
      serviceId: "fixture",
      serviceType: "FixtureService",
      activeState: "fixture",
    });
    assert.deepEqual(entries.map((entry) => entry.service_method), [
      "first@v1",
      "last@v1",
    ]);
    assert.ok(entries[0].handler_call_sequence.includes("state.insert"));
    assert.ok(entries[1].handler_call_sequence.includes("state.delete"));
    assert.equal(entries[1].handler_call_sequence.includes("format"), false);
  } finally {
    fs.rmSync(root, { force: true, recursive: true });
  }
});

test("JavaScript discovery finds process, filesystem, and all-key storage effects", () => {
  const root = temporaryRepository({
    "effect.mjs": `
      function executeEffect() {
        spawn("fixture");
        writeFileSync("receipt.json", "{}");
        sessionStorage.clear();
      }
    `,
  });
  try {
    const system = discoverJsSystemEffects({
      repoRoot: root,
      relativePaths: ["effect.mjs"],
    });
    assert.equal(system.length, 1);
    assert.deepEqual(system[0].handler_call_sequence, ["spawn", "writeFileSync"]);
    const storage = discoverJsStorageMutations({
      repoRoot: root,
      relativePaths: ["effect.mjs"],
    });
    assert.equal(storage.length, 1);
    assert.equal(storage[0].storage_method, "sessionStorage.clear");
    assert.equal(storage[0].storage_key_expression, "<all-keys>");
  } finally {
    fs.rmSync(root, { force: true, recursive: true });
  }
});

test("discovery and the committed review lock are complete and explicitly reviewed", () => {
  assert.equal(discoveredEntries.length, reviewLock.entries.length);
  assert.doesNotThrow(
    () => validateReviewLock(repoRoot, discoveredEntries, reviewLock),
  );
});

test("a newly discovered or changed mutation fails until explicitly classified", () => {
  const changedDiscovery = structuredClone(discoveredEntries);
  const targetIndex = changedDiscovery.findIndex((entry) => (
    entry.kind === "http" && entry.method === "POST"
  ));
  const target = changedDiscovery[targetIndex];
  changedDiscovery[targetIndex] = {
    ...target,
    identity: `${target.identity}-changed-fixture`,
    path: `${target.path}-changed-fixture`,
    operation: `${target.operation}-changed-fixture`,
  };
  assert.throws(
    () => validateReviewLock(repoRoot, changedDiscovery, reviewLock),
    /discovered identity is unclassified/u,
  );
});

test("omission and duplicate identities fail closed", () => {
  expectReviewFailure(
    (fixture) => fixture.entries.pop(),
    /discovered identity is unclassified/u,
  );
  expectReviewFailure(
    (fixture) => fixture.entries.push(structuredClone(fixture.entries[0])),
    /duplicate identity/u,
  );
  assert.throws(
    () => assertUniqueIdentities(
      [discoveredEntries[0], structuredClone(discoveredEntries[0])],
      "adversarial fixture",
    ),
    /duplicate identity/u,
  );
});

test("missing or laundered final invokers fail closed", () => {
  const effectIndex = reviewLock.entries.findIndex((entry) => (
    entry.classification === "consequential"
  ));
  expectReviewFailure(
    (fixture) => {
      fixture.entries[effectIndex].final_invoker = null;
    },
    /lacks a final invoker/u,
  );

  const candidateIndex = reviewLock.entries.findIndex((entry) => (
    entry.final_invoker?.claim_state === "candidate_or_handler_boundary_not_final"
  ));
  expectReviewFailure(
    (fixture) => {
      fixture.entries[candidateIndex].blocker_or_nonclaim_ref = null;
    },
    /launders a candidate boundary|non-terminal without a typed blocker/u,
  );
});

test("stale anchors, unsafe defaults, and heuristic review provenance fail closed", () => {
  expectReviewFailure(
    (fixture) => {
      fixture.entries[0].registration_anchor_sha256 = "0".repeat(64);
    },
    /stale registration anchor/u,
  );
  expectReviewFailure(
    (fixture) => {
      fixture.default_classification = "allow_by_default";
    },
    /fail_closed_unclassified/u,
  );
  expectReviewFailure(
    (fixture) => {
      fixture.entries[0].review_origin = "heuristic_suggestion";
    },
    /heuristic or unresolved review provenance/u,
  );
  assert.throws(
    () => validateReviewLock(
      repoRoot,
      discoveredEntries,
      createInitialReview(repoRoot, discoveredEntries),
    ),
    /not in reviewed state|heuristic or unresolved review provenance/u,
  );
});

test("false terminal claims fail without leaf, gates, evidence, and recovery proof", () => {
  const candidateIndex = reviewLock.entries.findIndex((entry) => (
    entry.final_invoker?.claim_state === "candidate_or_handler_boundary_not_final"
  ));
  expectReviewFailure(
    (fixture) => {
      const entry = fixture.entries[candidateIndex];
      entry.implementation_state = "terminal";
      entry.blocker_or_nonclaim_ref = null;
    },
    /falsely claims terminality without a verified effect leaf/u,
  );
});

test("PG and baseline incompleteness or fabricated zeros fail closed", () => {
  expectProgramFailure(
    (fixture) => fixture.pg_gate_map.entries.pop(),
    /PG map must contain exactly 58 entries|PG map omits/u,
  );
  expectProgramFailure(
    (fixture) => {
      fixture.pg_gate_map.entries.push(
        structuredClone(fixture.pg_gate_map.entries[0]),
      );
    },
    /PG map duplicates/u,
  );
  expectProgramFailure(
    (fixture) => {
      fixture.baselines[0].observed_value = 0;
    },
    /fabricates an observed value/u,
  );
  assert.equal(PG_IDS.length, 58);
});

test("bare invocation exits 2 with usage and writes nothing", () => {
  const before = hashEvidenceTree();
  const result = spawnSync(process.execPath, [cli], {
    cwd: repoRoot,
    encoding: "utf8",
  });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /^Usage:/u);
  assert.deepEqual(hashEvidenceTree(), before);
});

test("stale generated artifacts fail before consumption", () => {
  const root = temporaryRepository({
    [`${EVIDENCE_DIR}/fixture.json`]: "stale\n",
  });
  try {
    assert.throws(
      () => assertRenderedArtifactsCurrent(
        root,
        new Map([["fixture.json", "expected\n"]]),
        ["fixture.json"],
      ),
      /stale generated artifact/u,
    );
  } finally {
    fs.rmSync(root, { force: true, recursive: true });
  }
});

test("--check accepts current artifacts and remains read-only", () => {
  const before = hashEvidenceTree();
  const result = spawnSync(process.execPath, [cli, "--check"], {
    cwd: repoRoot,
    encoding: "utf8",
  });
  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  assert.match(result.stdout, /M0 check passed/u);
  assert.deepEqual(hashEvidenceTree(), before);
});
