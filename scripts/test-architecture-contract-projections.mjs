#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import {
  ARCHITECTURE_CONTRACT_ASSERTION_KEYWORDS,
  ARCHITECTURE_CONTRACT_DIFFERENTIAL_CASES,
  ARCHITECTURE_CONTRACT_FIXTURES,
  ARCHITECTURE_CONTRACT_MUTATIONS,
  ARCHITECTURE_CONTRACT_ORACLE_PROFILE,
  ARCHITECTURE_CONTRACT_PATTERN_SOURCES,
  ARCHITECTURE_CONTRACT_PORTABLE_DATE_TIME_PATTERN,
  ARCHITECTURE_CONTRACT_PORTABLE_INTEGER_MAXIMUM,
  ARCHITECTURE_CONTRACT_PORTABLE_INTEGER_MINIMUM,
  architectureContractInvariantErrors,
  architectureContractSchemaDocument,
  validateArchitectureContract,
} from "../packages/hypervisor-workbench/src/runtime/architecture-contracts.ts";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const CANONICAL_TYPESCRIPT_TARGET =
  "packages/hypervisor-workbench/src/runtime/generated/architecture-contracts.ts";
const CANONICAL_TYPESCRIPT_BARREL =
  "packages/hypervisor-workbench/src/runtime/architecture-contracts.ts";
const CANONICAL_TYPESCRIPT_PUBLIC_INDEX =
  "packages/hypervisor-workbench/src/index.ts";
const CANONICAL_RUST_TARGET =
  "crates/types/src/app/generated/architecture_contracts.rs";
const CANONICAL_RUST_MODULE_ROOT = "crates/types/src/app/mod.rs";
assert.equal(ARCHITECTURE_CONTRACT_PORTABLE_INTEGER_MINIMUM, 0);
assert.equal(
  ARCHITECTURE_CONTRACT_PORTABLE_INTEGER_MAXIMUM,
  Number.MAX_SAFE_INTEGER,
);
assert.equal(
  ARCHITECTURE_CONTRACT_ORACLE_PROFILE,
  "ajv-2020-12-plus-portable-invariants-and-canonical-rfc3339",
);
assert.equal(
  new RegExp(ARCHITECTURE_CONTRACT_PORTABLE_DATE_TIME_PATTERN, "u").test(
    "2025-01-01T23:59:60Z",
  ),
  true,
);
const ajv = new Ajv2020({
  allErrors: true,
  strict: true,
  validateFormats: true,
});
ajv.addKeyword({ keyword: "x-ioi-schema-version", schemaType: "string" });
addFormats(ajv);

const ajvValidators = new Map();
function ajvValidator(contractId) {
  let validator = ajvValidators.get(contractId);
  if (validator) return validator;
  const schema = architectureContractSchemaDocument(contractId);
  assert.ok(schema, `missing generated schema document for ${contractId}`);
  validator = ajv.compile(schema);
  ajvValidators.set(contractId, validator);
  return validator;
}

function mutationValue(mutation) {
  const value = JSON.parse(
    fs.readFileSync(path.join(root, mutation.source_fixture_path), "utf8"),
  );
  const parts = mutation.patch.pointer
    .slice(1)
    .split("/")
    .map((part) => part.replaceAll("~1", "/").replaceAll("~0", "~"));
  const name = parts.pop();
  const parent = parts.reduce((current, part) => current[part], value);
  assert.ok(
    parent !== null && typeof parent === "object" && !Array.isArray(parent),
    `${mutation.id}: patch parent must be an object`,
  );
  if (mutation.patch.operation === "set") {
    parent[name] = structuredClone(mutation.patch.value);
  } else if (mutation.patch.operation === "remove") {
    assert.ok(Object.hasOwn(parent, name), `${mutation.id}: removed field exists`);
    delete parent[name];
  } else {
    assert.fail(`${mutation.id}: unsupported patch operation`);
  }
  return value;
}

function differentialValue(candidate) {
  if (candidate.value_json !== null) return JSON.parse(candidate.value_json);
  if (candidate.mutation_id !== null) {
    const mutation = ARCHITECTURE_CONTRACT_MUTATIONS.find(
      (entry) => entry.id === candidate.mutation_id,
    );
    assert.ok(
      mutation,
      `${candidate.id}: missing mutation ${candidate.mutation_id}`,
    );
    return mutationValue(mutation);
  }
  assert.notEqual(
    candidate.source_fixture_path,
    null,
    `${candidate.id}: differential case has no value source`,
  );
  return JSON.parse(
    fs.readFileSync(path.join(root, candidate.source_fixture_path), "utf8"),
  );
}

for (const fixture of ARCHITECTURE_CONTRACT_FIXTURES) {
  const value = JSON.parse(fs.readFileSync(path.join(root, fixture.path), "utf8"));
  const validateWithAjv = ajvValidator(fixture.contract_id);
  const schemaAccepted = validateWithAjv(value);
  assert.equal(
    schemaAccepted,
    fixture.expected_schema_accept,
    `${fixture.path}: Ajv schema result differed: ${ajv.errorsText(validateWithAjv.errors)}`,
  );
  const oracleAccepted =
    schemaAccepted &&
    architectureContractInvariantErrors(fixture.contract_id, value).length === 0;
  const result = validateArchitectureContract(fixture.contract_id, value);
  assert.equal(
    result.ok,
    oracleAccepted,
    `${fixture.path}: generated TypeScript validator disagreed with Ajv plus portable invariants: ${result.errors.join(", ")}`,
  );
  assert.equal(
    result.ok,
    fixture.expected === "accept",
    `${fixture.path}: ${result.errors.join(", ")}`,
  );
  if (fixture.expected_rule_id !== null) {
    assert.ok(
      result.errors.some((error) => error.includes(fixture.expected_rule_id)),
      `${fixture.path}: missing ${fixture.expected_rule_id}`,
    );
  }
}

const coveredKeywords = new Set();
for (const mutation of ARCHITECTURE_CONTRACT_MUTATIONS) {
  for (const keyword of mutation.covered_keywords) coveredKeywords.add(keyword);
  const value = mutationValue(mutation);
  const validateWithAjv = ajvValidator(mutation.contract_id);
  const ajvAccepted = validateWithAjv(value);
  assert.equal(
    ajvAccepted,
    mutation.ajv_expected_accept,
    `${mutation.id}: Ajv expectation differed: ${ajv.errorsText(validateWithAjv.errors)}`,
  );
  const result = validateArchitectureContract(
    mutation.contract_id,
    value,
  );
  assert.equal(
    result.ok,
    ajvAccepted,
    `${mutation.id}: generated TypeScript validator disagreed with Ajv: ${result.errors.join(", ")}`,
  );
}
assert.deepEqual(
  [...coveredKeywords].sort(),
  [...ARCHITECTURE_CONTRACT_ASSERTION_KEYWORDS].sort(),
  "adversarial mutation corpus must cover every used semantic keyword",
);

for (const requiredRegression of [
  "maximum-safe-integer-violated",
  "nested-all-of-contains-member-missing",
  "deep-unique-items-key-order-duplicate",
  "impossible-rfc3339-calendar-date",
  "type-less-if-then-max-items-violated",
  "ecma-whitespace-byte-order-mark-rejected",
  "ecma-non-whitespace-next-line-accepted",
  "required-nullable-claim-scope-missing",
  "optional-non-nullable-input-hash-null",
]) {
  assert.ok(
    ARCHITECTURE_CONTRACT_MUTATIONS.some(
      (mutation) => mutation.id === requiredRegression,
    ),
    `missing adversarial regression ${requiredRegression}`,
  );
}

function authorityKeySetWithNotBeforeValues(first, second) {
  const value = JSON.parse(
    fs.readFileSync(
      path.join(
        root,
        "docs/architecture/_meta/schemas/fixtures/authority-key-set-v1/positive-active.json",
      ),
      "utf8",
    ),
  );
  const key = value.keys[0];
  value.keys = [
    { ...key, not_before: first },
    { ...key, not_before: second },
  ];
  return value;
}

const authorityKeySetContract =
  "schema://ioi/foundations/authority-key-set/v1";
for (const numericEqualityCase of [
  {
    id: "distinct-exact-safe-integers-remain-unique",
    value: authorityKeySetWithNotBeforeValues(
      Number.MAX_SAFE_INTEGER - 1,
      Number.MAX_SAFE_INTEGER,
    ),
    expected: true,
  },
  {
    id: "integer-and-decimal-spellings-are-equal",
    value: authorityKeySetWithNotBeforeValues(1, 1.0),
    expected: false,
  },
]) {
  const validateWithAjv = ajvValidator(authorityKeySetContract);
  assert.equal(
    validateWithAjv(numericEqualityCase.value),
    numericEqualityCase.expected,
    `${numericEqualityCase.id}: Ajv uniqueItems result`,
  );
  assert.equal(
    validateArchitectureContract(
      authorityKeySetContract,
      numericEqualityCase.value,
    ).ok,
    numericEqualityCase.expected,
    `${numericEqualityCase.id}: TypeScript uniqueItems result`,
  );
}

const canonicalDateTimeContract =
  "schema://ioi/foundations/authority-grant-envelope/v1";
for (const [dateTime, expected] of [
  ["2025-01-01T23:59:60Z", true],
  ["2025-01-02T00:59:60+01:00", true],
  ["2025-01-01 23:59:59Z", false],
  ["2025-01-01T23:59:59+0100", false],
  ["2025-01-01T23:59:59+01", false],
  ["2025-01-01T24:59:60+01:00", false],
  ["2025-01-01T23:60:60+00:01", false],
]) {
  const value = JSON.parse(
    fs.readFileSync(
      path.join(
        root,
        "docs/architecture/_meta/schemas/fixtures/authority-grant-envelope-v1/positive-active.json",
      ),
      "utf8",
    ),
  );
  value.constraints.expires_at = dateTime;
  const validateWithAjv = ajvValidator(canonicalDateTimeContract);
  assert.equal(
    validateWithAjv(value),
    expected,
    `${dateTime}: Ajv canonical RFC3339 profile`,
  );
  assert.equal(
    validateArchitectureContract(canonicalDateTimeContract, value).ok,
    expected,
    `${dateTime}: generated TypeScript canonical RFC3339 profile`,
  );
}

{
  const sparse = authorityKeySetWithNotBeforeValues(1, 2);
  delete sparse.keys[0];
  const validateWithAjv = ajvValidator(authorityKeySetContract);
  assert.equal(validateWithAjv(sparse), false, "Ajv rejects a sparse array hole");
  assert.equal(
    validateArchitectureContract(authorityKeySetContract, sparse).ok,
    false,
    "generated TypeScript validator must inspect every sparse array index",
  );
}

{
  const contractId = "schema://ioi/foundations/receipt-envelope/v1";
  const plain = JSON.parse(
    fs.readFileSync(
      path.join(
        root,
        "docs/architecture/_meta/schemas/fixtures/receipt-envelope-v1/positive-minimal.json",
      ),
      "utf8",
    ),
  );
  const inherited = Object.assign(
    Object.create({ inherited_unknown_property: true }),
    plain,
  );
  const validateWithAjv = ajvValidator(contractId);
  assert.equal(
    validateWithAjv(inherited),
    false,
    "configured Ajv rejects inherited enumerable additional properties",
  );
  assert.equal(
    validateArchitectureContract(contractId, inherited).ok,
    false,
    "generated TypeScript validator must match Ajv inherited-property semantics",
  );
}

for (const requiredDifferential of [
  "differential:portable-integer-boundary",
  "differential:portable-integer-over-bound",
  "differential:portable-integer-over-u64",
  "differential:portable-integer-negative",
  "differential:portable-integer-integral-decimal",
  "differential:canonical-leap-second-z",
  "differential:canonical-leap-second-offset",
  "differential:noncanonical-space-separator",
  "differential:noncanonical-compact-offset",
  "differential:noncanonical-hour-offset",
]) {
  assert.ok(
    ARCHITECTURE_CONTRACT_DIFFERENTIAL_CASES.some(
      (candidate) => candidate.id === requiredDifferential,
    ),
    `missing differential regression ${requiredDifferential}`,
  );
}

function runLiveAjvToRustDifferential() {
  const temporaryDirectory = fs.mkdtempSync(
    path.join(os.tmpdir(), "ioi-architecture-ajv-rust-"),
  );
  const oraclePath = path.join(temporaryDirectory, "ajv-oracle.json");
  try {
    const cases = ARCHITECTURE_CONTRACT_DIFFERENTIAL_CASES.map((candidate) => {
      const value = differentialValue(candidate);
      const validateWithAjv = ajvValidator(candidate.contract_id);
      const ajvSchemaAccept = Boolean(validateWithAjv(value));
      return {
        id: candidate.id,
        ajv_schema_accept: ajvSchemaAccept,
        oracle_contract_accept:
          ajvSchemaAccept &&
          architectureContractInvariantErrors(candidate.contract_id, value)
            .length === 0,
      };
    });
    fs.writeFileSync(
      oraclePath,
      `${JSON.stringify(
        {
          schema_version: "ioi.architecture-contract-ajv-differential.v1",
          cases,
        },
        null,
        2,
      )}\n`,
    );
    const rustDifferential = spawnSync(
      "cargo",
      [
        "test",
        "--locked",
        "-p",
        "ioi-types",
        "--lib",
        "app::generated::architecture_contracts::tests::live_ajv_differential_corpus_matches_rust_validator_and_deserializer",
        "--",
        "--exact",
      ],
      {
        cwd: root,
        encoding: "utf8",
        env: {
          ...process.env,
          IOI_ARCHITECTURE_CONTRACT_AJV_ORACLE: oraclePath,
        },
        maxBuffer: 10 * 1024 * 1024,
      },
    );
    assertOneRustTestRan(rustDifferential, "live Ajv-to-Rust differential");

    const renamedFilter = spawnSync(
      "cargo",
      [
        "test",
        "--locked",
        "-p",
        "ioi-types",
        "--lib",
        "app::generated::architecture_contracts::tests::renamed_or_missing_differential_test",
        "--",
        "--exact",
      ],
      {
        cwd: root,
        encoding: "utf8",
        env: {
          ...process.env,
          IOI_ARCHITECTURE_CONTRACT_AJV_ORACLE: oraclePath,
        },
        maxBuffer: 10 * 1024 * 1024,
      },
    );
    assert.equal(
      renamedFilter.status,
      0,
      "Cargo changed its zero-match behavior; update the launcher regression",
    );
    assert.throws(
      () => assertOneRustTestRan(renamedFilter, "renamed Rust differential"),
      /did not execute exactly one passing Rust test/u,
      "a nonexistent Rust differential filter must fail the launcher",
    );
  } finally {
    fs.rmSync(temporaryDirectory, { force: true, recursive: true });
  }
}

function assertOneRustTestRan(result, label) {
  const output = `${result.stdout}\n${result.stderr}`;
  assert.equal(
    result.status,
    0,
    `${label} failed:\n${output}`,
  );
  assert.match(
    output,
    /running 1 test[\s\S]*test result: ok\. 1 passed; 0 failed;/u,
    `${label} did not execute exactly one passing Rust test:\n${output}`,
  );
  assert.doesNotMatch(
    output,
    /running 0 tests/u,
    `${label} matched zero Rust tests`,
  );
}

runLiveAjvToRustDifferential();

function runTypeScriptCompileRegression(source, expectedSuccess) {
  const temporaryDirectory = fs.mkdtempSync(
    path.join(os.tmpdir(), "ioi-architecture-contract-types-"),
  );
  const sourcePath = path.join(temporaryDirectory, "literal-regression.ts");
  try {
    fs.writeFileSync(sourcePath, source);
    const result = spawnSync(
      process.execPath,
      [
        path.join(root, "node_modules", "typescript", "bin", "tsc"),
        "--noEmit",
        "--strict",
        "--skipLibCheck",
        "--target",
        "ES2022",
        "--module",
        "ESNext",
        "--moduleResolution",
        "Bundler",
        "--allowImportingTsExtensions",
        sourcePath,
      ],
      { cwd: root, encoding: "utf8" },
    );
    assert.equal(
      result.status === 0,
      expectedSuccess,
      `${sourcePath}: unexpected TypeScript compile result\n${result.stdout}\n${result.stderr}`,
    );
  } finally {
    fs.rmSync(temporaryDirectory, { force: true, recursive: true });
  }
}

const generatedTypePath = path
  .join(root, CANONICAL_TYPESCRIPT_BARREL)
  .replaceAll("\\", "/");
runTypeScriptCompileRegression(
  `import type { AuthorityGrantEnvelopeV1, AuthorityGrantEnvelopeV2 } from ${JSON.stringify(generatedTypePath)};\n` +
    `const schemaVersion: AuthorityGrantEnvelopeV2["schema_version"] = "ioi.foundations.authority-grant-envelope.v2";\n` +
    `const status: AuthorityGrantEnvelopeV1["status"] = "active";\n` +
    "void schemaVersion;\nvoid status;\n",
  true,
);
runTypeScriptCompileRegression(
  `import type { AuthorityGrantEnvelopeV1, AuthorityGrantEnvelopeV2 } from ${JSON.stringify(generatedTypePath)};\n` +
    `const schemaVersion: AuthorityGrantEnvelopeV2["schema_version"] = "invalid-const";\n` +
    `const status: AuthorityGrantEnvelopeV1["status"] = "invalid-enum";\n` +
    "void schemaVersion;\nvoid status;\n",
  false,
);

const registry = JSON.parse(
  fs.readFileSync(
    path.join(
      root,
      "docs/architecture/_meta/schemas/architecture-contract-registry.v1.json",
    ),
    "utf8",
  ),
);
for (const contract of registry.contracts) {
  for (const target of contract.generated_targets) {
    const canonicalPath = new Map([
      ["typescript_projection", CANONICAL_TYPESCRIPT_TARGET],
      ["rust_projection", CANONICAL_RUST_TARGET],
    ]).get(target.kind);
    assert.ok(
      canonicalPath,
      `${contract.contract_id}: unknown consumer target kind`,
    );
    assert.equal(
      target.path,
      canonicalPath,
      `${contract.contract_id}: registry target is redirected away from its consumer`,
    );
  }
}
assert.match(
  fs.readFileSync(path.join(root, CANONICAL_TYPESCRIPT_PUBLIC_INDEX), "utf8"),
  /export \* from "\.\/runtime\/architecture-contracts";/u,
  "public TypeScript index must export the architecture-contract barrel",
);
assert.match(
  fs.readFileSync(path.join(root, CANONICAL_TYPESCRIPT_BARREL), "utf8"),
  /export \* from "\.\/generated\/architecture-contracts\.ts";/u,
  "TypeScript barrel must export the canonical generated projection",
);
assert.match(
  fs.readFileSync(path.join(root, CANONICAL_RUST_MODULE_ROOT), "utf8"),
  /pub mod generated \{[\s\S]*pub mod architecture_contracts;/u,
  "Rust app module must bind the canonical generated projection",
);
assert.equal(
  generatedTypePath,
  path.join(root, CANONICAL_TYPESCRIPT_BARREL),
  "TypeScript compile regression must import the canonical public barrel",
);
const generatedTargetPaths = [
  CANONICAL_TYPESCRIPT_TARGET,
  CANONICAL_RUST_TARGET,
];
const generatedTargetBytes = new Map(
  generatedTargetPaths.map((targetPath) => [
    targetPath,
    fs.readFileSync(path.join(root, targetPath)),
  ]),
);
for (const rejectedArgs of [
  [],
  ["--chekc"],
  ["--help"],
  ["--help", "--bogus"],
  ["--write", "--check"],
  ["--write", "--write"],
  ["--check", "--self-test"],
  ["--check", "--check"],
  ["--self-test", "--self-test"],
]) {
  const rejected = spawnSync(
    process.execPath,
    ["scripts/generate-architecture-contracts.mjs", ...rejectedArgs],
    { cwd: root, encoding: "utf8" },
  );
  assert.notEqual(
    rejected.status,
    0,
    `generator accepted unsupported CLI arguments ${JSON.stringify(rejectedArgs)}`,
  );
  assert.match(
    rejected.stderr,
    /Supported invocations are exactly --write, --check, or --self-test/u,
  );
  for (const [targetPath, before] of generatedTargetBytes) {
    assert.deepEqual(
      fs.readFileSync(path.join(root, targetPath)),
      before,
      `${targetPath} changed after rejected CLI arguments`,
    );
  }
}

function copyCanonicalConsumerBindings(temporaryRoot) {
  for (const relativePath of [
    CANONICAL_TYPESCRIPT_PUBLIC_INDEX,
    CANONICAL_TYPESCRIPT_BARREL,
    CANONICAL_RUST_MODULE_ROOT,
    "scripts/test-architecture-contract-projections.mjs",
  ]) {
    const target = path.join(temporaryRoot, relativePath);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.copyFileSync(path.join(root, relativePath), target);
  }
}

function runRejectedRegistryProbe(
  id,
  mutate,
  expectedMessage,
  outsideName = null,
  mutateManifest = null,
  prepareProbe = null,
  verifyProbe = null,
) {
  const temporaryParent = fs.mkdtempSync(
    path.join(os.tmpdir(), "ioi-architecture-target-regression-"),
  );
  const temporaryRoot = path.join(temporaryParent, "repo");
  const temporarySchemaRoot = path.join(
    temporaryRoot,
    "docs/architecture/_meta/schemas",
  );
  try {
    fs.mkdirSync(path.join(temporaryRoot, "scripts/lib"), { recursive: true });
    fs.mkdirSync(path.dirname(temporarySchemaRoot), { recursive: true });
    fs.cpSync(
      path.join(root, "docs/architecture/_meta/schemas"),
      temporarySchemaRoot,
      { recursive: true },
    );
    fs.copyFileSync(
      path.join(root, "scripts/generate-architecture-contracts.mjs"),
      path.join(temporaryRoot, "scripts/generate-architecture-contracts.mjs"),
    );
    fs.copyFileSync(
      path.join(root, "scripts/check-architecture-contracts.mjs"),
      path.join(temporaryRoot, "scripts/check-architecture-contracts.mjs"),
    );
    for (const helper of [
      "architecture-contract-consumer-bindings.mjs",
      "architecture-contract-consumer-targets.mjs",
      "repository-path-boundary.mjs",
    ]) {
      fs.copyFileSync(
        path.join(root, "scripts/lib", helper),
        path.join(temporaryRoot, "scripts/lib", helper),
      );
    }
    copyCanonicalConsumerBindings(temporaryRoot);
    fs.copyFileSync(
      path.join(root, "rust-toolchain.toml"),
      path.join(temporaryRoot, "rust-toolchain.toml"),
    );
    fs.symlinkSync(
      path.join(root, "node_modules"),
      path.join(temporaryRoot, "node_modules"),
      "dir",
    );
    if (mutateManifest) {
      const manifestPath = path.join(
        temporaryRoot,
        "scripts/lib/architecture-contract-consumer-targets.mjs",
      );
      fs.writeFileSync(
        manifestPath,
        mutateManifest(fs.readFileSync(manifestPath, "utf8")),
      );
    }
    const attackedRegistry = structuredClone(registry);
    mutate(attackedRegistry);
    fs.writeFileSync(
      path.join(
        temporarySchemaRoot,
        "architecture-contract-registry.v1.json",
      ),
      `${JSON.stringify(attackedRegistry, null, 2)}\n`,
    );
    const probeState = prepareProbe?.({ temporaryParent, temporaryRoot });
    for (const [label, invocation] of [
      [
        "generator",
        ["scripts/generate-architecture-contracts.mjs", "--check"],
      ],
      ["checker", ["scripts/check-architecture-contracts.mjs"]],
    ]) {
      const rejected = spawnSync(process.execPath, invocation, {
        cwd: temporaryRoot,
        encoding: "utf8",
      });
      assert.notEqual(
        rejected.status,
        0,
        `${id}: ${label} accepted the attacked registry`,
      );
      assert.match(
        `${rejected.stdout}\n${rejected.stderr}`,
        expectedMessage,
        `${id}: ${label}`,
      );
      if (outsideName) {
        assert.equal(
          fs.existsSync(path.join(temporaryParent, outsideName)),
          false,
          `${id}: ${label} wrote outside its repository root`,
        );
      }
      verifyProbe?.({
        label,
        probeState,
        temporaryParent,
        temporaryRoot,
      });
    }
  } finally {
    fs.rmSync(temporaryParent, { force: true, recursive: true });
  }
}

runRejectedRegistryProbe(
  "escaping generated target",
  (attacked) => {
    attacked.contracts[0].generated_targets[0].path =
      "../ioi-pr81-outside-generated.ts";
  },
  /must match canonical typescript_projection consumer|path escapes/u,
  "ioi-pr81-outside-generated.ts",
);
runRejectedRegistryProbe(
  "redirected in-repository generated target",
  (attacked) => {
    attacked.contracts[0].generated_targets[0].path =
      "packages/hypervisor-workbench/src/runtime/generated/architecture-contracts-copy.ts";
  },
  /must match canonical typescript_projection consumer/u,
);
runRejectedRegistryProbe(
  "joint registry and consumer-manifest redirection",
  (attacked) => {
    for (const contract of attacked.contracts) {
      for (const target of contract.generated_targets) {
        target.path =
          target.kind === "typescript_projection"
            ? "packages/hypervisor-workbench/src/runtime/generated/alternate-architecture-contracts.ts"
            : "crates/types/src/app/generated/alternate_architecture_contracts.rs";
      }
    }
  },
  /declaration manifest differs from independently pinned canonical consumers|must match canonical (?:typescript|rust)_projection consumer/u,
  null,
  (manifest) =>
    manifest
      .replaceAll(
        CANONICAL_TYPESCRIPT_TARGET,
        "packages/hypervisor-workbench/src/runtime/generated/alternate-architecture-contracts.ts",
      )
      .replaceAll(
        CANONICAL_RUST_TARGET,
        "crates/types/src/app/generated/alternate_architecture_contracts.rs",
      ),
  ({ temporaryRoot }) => {
    const staleBytes = Buffer.from(
      "intentionally stale canonical consumed projection\n",
    );
    for (const relativePath of [
      CANONICAL_TYPESCRIPT_TARGET,
      CANONICAL_RUST_TARGET,
    ]) {
      const target = path.join(temporaryRoot, relativePath);
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.writeFileSync(target, staleBytes);
    }
    for (const [canonical, alternate] of [
      [
        CANONICAL_TYPESCRIPT_TARGET,
        "packages/hypervisor-workbench/src/runtime/generated/alternate-architecture-contracts.ts",
      ],
      [
        CANONICAL_RUST_TARGET,
        "crates/types/src/app/generated/alternate_architecture_contracts.rs",
      ],
    ]) {
      const target = path.join(temporaryRoot, alternate);
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.copyFileSync(path.join(root, canonical), target);
    }
    return staleBytes;
  },
  ({ label, probeState: staleBytes, temporaryRoot }) => {
    for (const relativePath of [
      CANONICAL_TYPESCRIPT_TARGET,
      CANONICAL_RUST_TARGET,
    ]) {
      assert.deepEqual(
        fs.readFileSync(path.join(temporaryRoot, relativePath)),
        staleBytes,
        `joint redirection: ${label} changed stale canonical consumer ${relativePath}`,
      );
    }
  },
);
runRejectedRegistryProbe(
  "unknown generated target kind",
  (attacked) => {
    attacked.contracts[0].generated_targets[0].kind = "ambient_projection";
  },
  /unknown generated target kind/u,
);
runRejectedRegistryProbe(
  "missing generated target",
  (attacked) => {
    attacked.contracts[0].generated_targets.pop();
  },
  /missing required generated target kind rust_projection/u,
);
runRejectedRegistryProbe(
  "duplicate generated target",
  (attacked) => {
    attacked.contracts[0].generated_targets.push(
      structuredClone(attacked.contracts[0].generated_targets[0]),
    );
  },
  /duplicate generated target kind typescript_projection/u,
);

function runSymlinkBoundaryProbe(id, setup, generatorMode = "--check") {
  const temporaryParent = fs.mkdtempSync(
    path.join(os.tmpdir(), "ioi-architecture-symlink-regression-"),
  );
  const temporaryRoot = path.join(temporaryParent, "repo");
  const temporarySchemaRoot = path.join(
    temporaryRoot,
    "docs/architecture/_meta/schemas",
  );
  try {
    fs.mkdirSync(path.join(temporaryRoot, "scripts/lib"), { recursive: true });
    fs.cpSync(
      path.join(root, "docs/architecture/_meta/schemas"),
      temporarySchemaRoot,
      { recursive: true },
    );
    for (const script of [
      "generate-architecture-contracts.mjs",
      "check-architecture-contracts.mjs",
    ]) {
      fs.copyFileSync(
        path.join(root, "scripts", script),
        path.join(temporaryRoot, "scripts", script),
      );
    }
    for (const helper of [
      "architecture-contract-consumer-bindings.mjs",
      "architecture-contract-consumer-targets.mjs",
      "repository-path-boundary.mjs",
    ]) {
      fs.copyFileSync(
        path.join(root, "scripts/lib", helper),
        path.join(temporaryRoot, "scripts/lib", helper),
      );
    }
    copyCanonicalConsumerBindings(temporaryRoot);
    fs.copyFileSync(
      path.join(root, "rust-toolchain.toml"),
      path.join(temporaryRoot, "rust-toolchain.toml"),
    );
    fs.symlinkSync(
      path.join(root, "node_modules"),
      path.join(temporaryRoot, "node_modules"),
      "dir",
    );
    const assertOutsideUnchanged = setup({
      temporaryParent,
      temporaryRoot,
      temporarySchemaRoot,
    });
    for (const [label, invocation] of [
      [
        "generator",
        ["scripts/generate-architecture-contracts.mjs", generatorMode],
      ],
      ["checker", ["scripts/check-architecture-contracts.mjs"]],
    ]) {
      const rejected = spawnSync(process.execPath, invocation, {
        cwd: temporaryRoot,
        encoding: "utf8",
      });
      assert.notEqual(
        rejected.status,
        0,
        `${id}: ${label} accepted an external symlink`,
      );
      assert.match(
        `${rejected.stdout}\n${rejected.stderr}`,
        /symlink component|resolves outside .* boundary through a symlink/u,
        `${id}: ${label}`,
      );
      assertOutsideUnchanged(`${id}: ${label}`);
    }
  } finally {
    fs.rmSync(temporaryParent, { force: true, recursive: true });
  }
}

runSymlinkBoundaryProbe(
  "generated target parent symlink",
  ({ temporaryParent, temporaryRoot }) => {
    const outside = path.join(temporaryParent, "outside-generated");
    const sentinel = path.join(outside, "architecture-contracts.ts");
    const expected = "external-target-sentinel\n";
    fs.mkdirSync(outside, { recursive: true });
    fs.writeFileSync(sentinel, expected);
    const runtime = path.join(
      temporaryRoot,
      "packages/hypervisor-workbench/src/runtime",
    );
    fs.mkdirSync(runtime, { recursive: true });
    fs.symlinkSync(outside, path.join(runtime, "generated"), "dir");
    return (at) =>
      assert.equal(fs.readFileSync(sentinel, "utf8"), expected, at);
  },
);

runSymlinkBoundaryProbe(
  "dangling final generated target symlink",
  ({ temporaryParent, temporaryRoot }) => {
    const outside = path.join(
      temporaryParent,
      "outside-dangling-architecture-contracts.ts",
    );
    const generatedTarget = path.join(
      temporaryRoot,
      CANONICAL_TYPESCRIPT_TARGET,
    );
    fs.mkdirSync(path.dirname(generatedTarget), { recursive: true });
    fs.symlinkSync(outside, generatedTarget, "file");
    return (at) => {
      assert.equal(
        fs.existsSync(outside),
        false,
        `${at}: dangling final symlink created an external target`,
      );
      assert.equal(
        fs.lstatSync(generatedTarget).isSymbolicLink(),
        true,
        `${at}: dangling final symlink was replaced`,
      );
    };
  },
  "--write",
);

for (const [id, relativePath] of [
  ["schema ref symlink", "receipt-envelope.v1.schema.json"],
  [
    "invariant ref symlink",
    "invariants/receipt-envelope.v1.invariants.json",
  ],
  [
    "fixture ref symlink",
    "fixtures/receipt-envelope-v1/positive-minimal.json",
  ],
]) {
  runSymlinkBoundaryProbe(
    id,
    ({ temporaryParent, temporarySchemaRoot }) => {
      const target = path.join(temporarySchemaRoot, relativePath);
      const outside = path.join(
        temporaryParent,
        `outside-${relativePath.replaceAll("/", "-")}`,
      );
      const expected = fs.readFileSync(target);
      fs.writeFileSync(outside, expected);
      fs.rmSync(target);
      fs.symlinkSync(outside, target, "file");
      return (at) => assert.deepEqual(fs.readFileSync(outside), expected, at);
    },
  );
}

const generatorSelfTest = spawnSync(
  process.execPath,
  ["scripts/generate-architecture-contracts.mjs", "--self-test"],
  { cwd: root, encoding: "utf8" },
);
assert.equal(
  generatorSelfTest.status,
  0,
  `generator fail-closed/raw-literal self-test failed:\n${generatorSelfTest.stdout}\n${generatorSelfTest.stderr}`,
);

console.log(
  JSON.stringify(
    {
      ok: true,
      runtime: "typescript",
      fixtures: ARCHITECTURE_CONTRACT_FIXTURES.length,
      mutations: ARCHITECTURE_CONTRACT_MUTATIONS.length,
      differential_cases: ARCHITECTURE_CONTRACT_DIFFERENTIAL_CASES.length,
      assertion_keywords: ARCHITECTURE_CONTRACT_ASSERTION_KEYWORDS.length,
      pattern_sources: ARCHITECTURE_CONTRACT_PATTERN_SOURCES.length,
      oracle: ARCHITECTURE_CONTRACT_ORACLE_PROFILE,
      rust_oracle: "live-ajv-subprocess",
    },
    null,
    2,
  ),
);
