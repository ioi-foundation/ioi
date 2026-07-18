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
  ARCHITECTURE_CONTRACT_PATTERN_SOURCES,
  architectureContractInvariantErrors,
  architectureContractSchemaDocument,
  validateArchitectureContract,
} from "../packages/hypervisor-workbench/src/runtime/generated/architecture-contracts.ts";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
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

const strictDateTimeContract =
  "schema://ioi/foundations/authority-grant-envelope/v1";
for (const invalidDateTime of [
  "2025-01-01T24:59:60+01:00",
  "2025-01-01T23:60:60+00:01",
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
  value.constraints.expires_at = invalidDateTime;
  const validateWithAjv = ajvValidator(strictDateTimeContract);
  assert.equal(
    validateWithAjv(value),
    true,
    `${invalidDateTime}: documents the ajv-formats leap-second clock-range quirk`,
  );
  assert.equal(
    validateArchitectureContract(strictDateTimeContract, value).ok,
    true,
    `${invalidDateTime}: generated TypeScript must share the ajv-formats leap-second oracle`,
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
    assert.equal(
      rustDifferential.status,
      0,
      `live Ajv-to-Rust differential failed:\n${rustDifferential.stdout}\n${rustDifferential.stderr}`,
    );
  } finally {
    fs.rmSync(temporaryDirectory, { force: true, recursive: true });
  }
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
        "NodeNext",
        "--moduleResolution",
        "NodeNext",
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
  .join(
    root,
    "packages",
    "hypervisor-workbench",
    "src",
    "runtime",
    "generated",
    "architecture-contracts.ts",
  )
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
const generatedTargetPaths = [
  ...new Set(
    registry.contracts.flatMap((contract) =>
      contract.generated_targets.map((target) => target.path),
    ),
  ),
];
const generatedTargetBytes = new Map(
  generatedTargetPaths.map((targetPath) => [
    targetPath,
    fs.readFileSync(path.join(root, targetPath)),
  ]),
);
for (const rejectedArgs of [
  ["--chekc"],
  ["--help"],
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
    /Supported invocations are bare generation, --check, or --self-test/u,
  );
  for (const [targetPath, before] of generatedTargetBytes) {
    assert.deepEqual(
      fs.readFileSync(path.join(root, targetPath)),
      before,
      `${targetPath} changed after rejected CLI arguments`,
    );
  }
}

function runRejectedRegistryProbe(id, mutate, expectedMessage, outsideName = null) {
  const temporaryParent = fs.mkdtempSync(
    path.join(os.tmpdir(), "ioi-architecture-target-regression-"),
  );
  const temporaryRoot = path.join(temporaryParent, "repo");
  const temporarySchemaRoot = path.join(
    temporaryRoot,
    "docs/architecture/_meta/schemas",
  );
  try {
    fs.mkdirSync(path.join(temporaryRoot, "scripts"), { recursive: true });
    fs.mkdirSync(temporarySchemaRoot, { recursive: true });
    fs.copyFileSync(
      path.join(root, "scripts/generate-architecture-contracts.mjs"),
      path.join(temporaryRoot, "scripts/generate-architecture-contracts.mjs"),
    );
    fs.copyFileSync(
      path.join(root, "scripts/check-architecture-contracts.mjs"),
      path.join(temporaryRoot, "scripts/check-architecture-contracts.mjs"),
    );
    fs.symlinkSync(
      path.join(root, "node_modules"),
      path.join(temporaryRoot, "node_modules"),
      "dir",
    );
    const attackedRegistry = structuredClone(registry);
    mutate(attackedRegistry);
    fs.writeFileSync(
      path.join(
        temporarySchemaRoot,
        "architecture-contract-registry.v1.json",
      ),
      `${JSON.stringify(attackedRegistry, null, 2)}\n`,
    );
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
  /generated target path escapes/u,
  "ioi-pr81-outside-generated.ts",
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
      oracle: "ajv-2020-12-plus-portable-invariants",
      rust_oracle: "live-ajv-subprocess",
    },
    null,
    2,
  ),
);
