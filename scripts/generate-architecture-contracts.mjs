#!/usr/bin/env node
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

function parseCliMode(args) {
  if (args.length === 1 && args[0] === "--write") return "write";
  if (args.length === 1 && args[0] === "--check") return "check";
  if (args.length === 1 && args[0] === "--self-test") return "self-test";
  throw new Error(
    `Unsupported architecture-contract generator arguments: ${JSON.stringify(args)}. ` +
      "Supported invocations are exactly --write, --check, or --self-test.",
  );
}

let cliMode;
try {
  cliMode = parseCliMode(process.argv.slice(2));
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(2);
}

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const { ARCHITECTURE_CONTRACT_CONSUMER_TARGETS } =
  await import("./lib/architecture-contract-consumer-targets.mjs");
const { architectureContractConsumerBindingFailures } =
  await import("./lib/architecture-contract-consumer-bindings.mjs");
const { invariantPathFiniteDomain, validateInvariantProfile } =
  await import("./lib/architecture-invariant-dsl.mjs");
const { safeRepositoryPath } =
  await import("./lib/repository-path-boundary.mjs");
const PINNED_CONSUMER_TARGETS = Object.freeze([
  Object.freeze({
    kind: "typescript_projection",
    path: "packages/hypervisor-workbench/src/runtime/generated/architecture-contracts.ts",
    consumer_path: "packages/hypervisor-workbench/src/index.ts",
    consumer_marker: 'export * from "./runtime/architecture-contracts";',
    typescript_bindings: Object.freeze([
      Object.freeze({
        binding_kind: "exports",
        consumer_path: "packages/hypervisor-workbench/src/index.ts",
        module_specifier: "./runtime/architecture-contracts",
      }),
      Object.freeze({
        binding_kind: "exports",
        consumer_path:
          "packages/hypervisor-workbench/src/runtime/architecture-contracts.ts",
        module_specifier: "./generated/architecture-contracts.ts",
      }),
      Object.freeze({
        binding_kind: "imports",
        consumer_path: "scripts/test-architecture-contract-projections.mjs",
        module_specifier:
          "../packages/hypervisor-workbench/src/runtime/architecture-contracts.ts",
      }),
    ]),
  }),
  Object.freeze({
    kind: "rust_projection",
    path: "crates/types/src/app/generated/architecture_contracts.rs",
    consumer_path: "crates/types/src/app/mod.rs",
    consumer_marker: "pub mod architecture_contracts;",
    module_root_path: "crates/types/src/app/mod.rs",
  }),
]);
const PINNED_CONSUMER_TARGET_BY_KIND = new Map(
  PINNED_CONSUMER_TARGETS.map((target) => [target.kind, target]),
);
const declaredConsumerTargets = ARCHITECTURE_CONTRACT_CONSUMER_TARGETS.map(
  ({ kind, path: targetPath, consumer_path, consumer_marker }) => ({
    kind,
    path: targetPath,
    consumer_path,
    consumer_marker,
  }),
);
const expectedConsumerTargets = PINNED_CONSUMER_TARGETS.map(
  ({ kind, path: targetPath, consumer_path, consumer_marker }) => ({
    kind,
    path: targetPath,
    consumer_path,
    consumer_marker,
  }),
);
if (
  JSON.stringify(declaredConsumerTargets) !==
  JSON.stringify(expectedConsumerTargets)
) {
  throw new Error(
    "Architecture contract consumer declaration manifest differs from independently pinned canonical consumers",
  );
}
const schemaRoot = path.join(root, "docs", "architecture", "_meta", "schemas");
const SUPPORTED_TARGET_KINDS = new Set(
  PINNED_CONSUMER_TARGETS.map((target) => target.kind),
);
const consumerBindingFailures = architectureContractConsumerBindingFailures({
  root,
  targets: PINNED_CONSUMER_TARGETS,
  safeRepositoryPath,
});
if (consumerBindingFailures.length > 0) {
  throw new Error(consumerBindingFailures.join("\n"));
}
const registryPath = safeSchemaPath(
  "architecture-contract-registry.v1.json",
  "architecture contract registry",
);
const registry = readJson(registryPath);
const declaredTargets = validateGeneratedTargets(registry);
const contracts = registry.contracts.map((entry) => ({
  entry,
  schema: readJson(
    safeSchemaPath(entry.schema_ref, `${entry.contract_id}: schema_ref`),
  ),
  invariants: entry.cross_field_invariant_refs.map((ref) =>
    readJson(
      safeSchemaPath(
        ref.path,
        `${entry.contract_id}: invariant ${ref.invariant_id}`,
      ),
    ),
  ),
}));
for (const { entry, schema, invariants } of contracts) {
  for (const profile of invariants) {
    const errors = validateInvariantProfile(schema, profile);
    if (errors.length > 0) {
      throw new Error(
        `${entry.contract_id}: malformed invariant profile ${profile.$id}:\n${errors.join("\n")}`,
      );
    }
  }
}

const SCHEMA_METADATA_KEYWORDS = new Set([
  "$defs",
  "$id",
  "$schema",
  "description",
  "title",
  "x-ioi-schema-version",
]);
const SCHEMA_SEMANTIC_KEYWORDS = new Set([
  "$ref",
  "additionalProperties",
  "allOf",
  "anyOf",
  "const",
  "contains",
  "else",
  "enum",
  "format",
  "if",
  "items",
  "maximum",
  "maxLength",
  "maxItems",
  "minimum",
  "minItems",
  "minLength",
  "oneOf",
  "pattern",
  "properties",
  "required",
  "then",
  "type",
  "uniqueItems",
]);
const SUPPORTED_SCHEMA_KEYWORDS = new Set([
  ...SCHEMA_METADATA_KEYWORDS,
  ...SCHEMA_SEMANTIC_KEYWORDS,
]);
const registeredPatternTranslations = new Map();
const RUST_ECMA_WHITESPACE_CLASS =
  "\\u{0009}-\\u{000D}\\u{0020}\\u{00A0}\\u{1680}" +
  "\\u{2000}-\\u{200A}\\u{2028}\\u{2029}\\u{202F}\\u{205F}" +
  "\\u{3000}\\u{FEFF}";
const PORTABLE_INTEGER_MINIMUM = 0;
const PORTABLE_INTEGER_MAXIMUM = Number.MAX_SAFE_INTEGER;
const PORTABLE_SIGNED_INTEGER_MINIMUM = -Number.MAX_SAFE_INTEGER;
const PORTABLE_CANONICAL_DATE_TIME_PATTERN =
  "^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])T(?:[01][0-9]|2[0-3]):[0-5][0-9]:(?:[0-5][0-9]|60)(?:[.][0-9]+|)(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])$";

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function safeSchemaPath(relativePath, at) {
  return safeRepositoryPath({
    root,
    boundaryRoot: schemaRoot,
    relativePath,
    at,
    mustExist: true,
  });
}

function codePointCompare(left, right) {
  const leftPoints = [...left].map((character) => character.codePointAt(0));
  const rightPoints = [...right].map((character) => character.codePointAt(0));
  const length = Math.min(leftPoints.length, rightPoints.length);
  for (let index = 0; index < length; index += 1) {
    if (leftPoints[index] !== rightPoints[index]) {
      return leftPoints[index] - rightPoints[index];
    }
  }
  return leftPoints.length - rightPoints.length;
}

function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
    .join(",")}}`;
}

const JCS_DIFFERENTIAL_CASES = Object.freeze([
  Object.freeze({
    id: "jcs-non-bmp-key-order",
    value: Object.freeze({
      "\uE000": "private-use-bmp",
      "\u{1F600}": "astral",
    }),
  }),
].map((candidate) =>
  Object.freeze({
    ...candidate,
    value_json: JSON.stringify(candidate.value),
    expected_canonical: canonicalJson(candidate.value),
  })
));

function schemaHash(schema) {
  return `sha256:${createHash("sha256").update(canonicalJson(schema)).digest("hex")}`;
}

function contractVersion(entry) {
  const match = entry.contract_id.match(/\/v([1-9][0-9]*)$/u);
  if (!match)
    throw new Error(
      `Contract id has no terminal version: ${entry.contract_id}`,
    );
  return Number.parseInt(match[1], 10);
}

function projectionSymbol(entry) {
  return `${entry.canonical_name}V${contractVersion(entry)}`;
}

function safeGeneratedTargetPath(targetPath, at, mustExist = false) {
  return safeRepositoryPath({
    root,
    relativePath: targetPath,
    at,
    mustExist,
  });
}

function validateGeneratedTargets(registryDocument) {
  if (!Array.isArray(registryDocument?.contracts)) {
    throw new Error("Architecture contract registry has no contracts array");
  }
  const targets = [];
  for (const entry of registryDocument.contracts) {
    const at = `registry:${entry?.contract_id ?? "unknown"}.generated_targets`;
    if (!Array.isArray(entry?.generated_targets)) {
      throw new Error(`${at}: expected a generated target array`);
    }
    const expectedSymbol = projectionSymbol(entry);
    const seenKinds = new Set();
    const seenDefinitions = new Set();
    for (const [index, target] of entry.generated_targets.entries()) {
      const targetAt = `${at}[${index}]`;
      if (!isPlainObject(target)) {
        throw new Error(`${targetAt}: expected a generated target object`);
      }
      if (!SUPPORTED_TARGET_KINDS.has(target.kind)) {
        throw new Error(
          `${targetAt}: unknown generated target kind ${JSON.stringify(target.kind)}`,
        );
      }
      const consumerTarget = PINNED_CONSUMER_TARGET_BY_KIND.get(target.kind);
      if (target.path !== consumerTarget.path) {
        throw new Error(
          `${targetAt}: generated target path must match canonical ${target.kind} consumer ${consumerTarget.path}`,
        );
      }
      if (seenKinds.has(target.kind)) {
        throw new Error(
          `${at}: duplicate generated target kind ${target.kind}`,
        );
      }
      seenKinds.add(target.kind);
      if (target.symbol !== expectedSymbol) {
        throw new Error(
          `${targetAt}: generated target symbol must be ${expectedSymbol}`,
        );
      }
      const absolutePath = safeGeneratedTargetPath(target.path, targetAt);
      const definition = `${target.kind}\u0000${target.path}\u0000${target.symbol}`;
      if (seenDefinitions.has(definition)) {
        throw new Error(`${at}: duplicate generated target definition`);
      }
      seenDefinitions.add(definition);
      targets.push({ ...target, absolutePath, contractId: entry.contract_id });
    }
    for (const kind of SUPPORTED_TARGET_KINDS) {
      if (!seenKinds.has(kind)) {
        throw new Error(
          `${at}: missing required generated target kind ${kind}`,
        );
      }
    }
  }
  return targets;
}

function resolveLocalRef(rootSchema, ref) {
  if (!ref.startsWith("#/")) {
    throw new Error(
      `Only local JSON Schema refs are supported by the pilot: ${ref}`,
    );
  }
  return ref
    .slice(2)
    .split("/")
    .map((part) => part.replaceAll("~1", "/").replaceAll("~0", "~"))
    .reduce((value, part) => value?.[part], rootSchema);
}

function isPlainObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function assertSchemaObject(value, at) {
  if (!isPlainObject(value)) {
    throw new Error(
      `${at}: boolean and non-object JSON Schemas are unsupported by architecture projections`,
    );
  }
}

function rustEcmaPattern(pattern, at) {
  if (
    typeof pattern !== "string" ||
    !pattern.startsWith("^") ||
    !pattern.endsWith("$") ||
    /[^\x20-\x7e]/u.test(pattern)
  ) {
    throw new Error(
      `${at}: patterns must use the anchored ASCII architecture-contract subset`,
    );
  }
  try {
    new RegExp(pattern, "u");
  } catch (error) {
    throw new Error(`${at}: invalid ECMA-262 pattern: ${error.message}`);
  }

  let inEscapedClass = false;
  let grammarProbe = "";
  let translated = "";
  for (let index = 0; index < pattern.length; index += 1) {
    const character = pattern[index];
    if (character === "\\") {
      const escaped = pattern[index + 1];
      if (!inEscapedClass && escaped === "S") {
        grammarProbe += "X";
        translated += `[^${RUST_ECMA_WHITESPACE_CLASS}]`;
      } else if (inEscapedClass && escaped === "s") {
        grammarProbe += "X";
        translated += RUST_ECMA_WHITESPACE_CLASS;
      } else if (inEscapedClass && escaped === "\\") {
        grammarProbe += "X";
        translated += "\\\\";
      } else {
        throw new Error(
          `${at}: unsupported ECMA-262 escape; only out-of-class \\S and negated-class \\s or \\\\ are supported`,
        );
      }
      index += 1;
      continue;
    }
    grammarProbe += character;
    translated += character;
    if (character === "[") inEscapedClass = true;
    if (character === "]") inEscapedClass = false;
  }
  let inClass = false;
  let groupDepth = 0;
  for (let index = 1; index < grammarProbe.length - 1; index += 1) {
    const character = grammarProbe[index];
    if (character === "[") {
      if (inClass)
        throw new Error(`${at}: nested character classes are unsupported`);
      inClass = true;
      continue;
    }
    if (character === "]") {
      if (!inClass) throw new Error(`${at}: unmatched character-class close`);
      inClass = false;
      continue;
    }
    if (inClass) continue;
    if (character === ".") {
      throw new Error(`${at}: ECMA wildcard semantics are unsupported`);
    }
    if (character === "^" || character === "$") {
      throw new Error(`${at}: internal anchors are unsupported`);
    }
    if (character === "(") {
      if (grammarProbe.slice(index, index + 3) !== "(?:") {
        throw new Error(`${at}: only non-capturing groups are supported`);
      }
      groupDepth += 1;
      continue;
    }
    if (character === ")") {
      groupDepth -= 1;
      if (groupDepth < 0) throw new Error(`${at}: unmatched group close`);
      continue;
    }
    if (
      character === "?" &&
      grammarProbe.slice(index - 1, index + 2) !== "(?:"
    ) {
      throw new Error(`${at}: unsupported question-mark construct`);
    }
  }
  if (inClass || groupDepth !== 0) {
    throw new Error(`${at}: unterminated character class or group`);
  }

  return translated;
}

function inventorySchemaKeywords(schema, at) {
  assertSchemaObject(schema, at);
  const inventory = new Set();
  for (const [keyword, value] of Object.entries(schema)) {
    if (!SUPPORTED_SCHEMA_KEYWORDS.has(keyword)) {
      throw new Error(
        `${at}: unsupported JSON Schema keyword ${JSON.stringify(keyword)}; ` +
          "architecture contract generation fails closed until both validators and projections implement it",
      );
    }
    if (SCHEMA_SEMANTIC_KEYWORDS.has(keyword)) inventory.add(keyword);
    if (keyword === "$ref") {
      if (typeof value !== "string" || !value.startsWith("#/")) {
        throw new Error(`${at}.$ref: only local references are supported`);
      }
    } else if (keyword === "type") {
      if (
        typeof value !== "string" ||
        ![
          "null",
          "string",
          "integer",
          "number",
          "boolean",
          "array",
          "object",
        ].includes(value)
      ) {
        throw new Error(`${at}.type: unsupported type declaration`);
      }
    } else if (keyword === "format" && value !== "date-time") {
      throw new Error(
        `${at}.format: unsupported format ${JSON.stringify(value)}`,
      );
    } else if (
      [
        "minimum",
        "maximum",
        "minLength",
        "maxLength",
        "minItems",
        "maxItems",
      ].includes(keyword) &&
      (typeof value !== "number" || !Number.isFinite(value))
    ) {
      throw new Error(`${at}.${keyword}: expected a finite number`);
    } else if (keyword === "uniqueItems" && typeof value !== "boolean") {
      throw new Error(`${at}.uniqueItems: expected a boolean`);
    } else if (
      keyword === "additionalProperties" &&
      typeof value !== "boolean"
    ) {
      throw new Error(
        `${at}.additionalProperties: schema-valued additionalProperties is unsupported`,
      );
    } else if (keyword === "required" && !Array.isArray(value)) {
      throw new Error(`${at}.${keyword}: expected an array`);
    } else if (keyword === "enum") {
      const strings =
        Array.isArray(value) &&
        value.length > 0 &&
        value.every((candidate) => typeof candidate === "string");
      const integers =
        Array.isArray(value) &&
        value.length > 0 &&
        value.every((candidate) => Number.isSafeInteger(candidate));
      if (
        (!strings && !integers) ||
        new Set(value.map((candidate) => JSON.stringify(candidate))).size !==
          value.length
      ) {
        throw new Error(
          `${at}.enum: architecture projections require unique, non-empty string or portable-integer enums`,
        );
      }
    } else if (
      keyword === "const" &&
      !(typeof value === "string" || typeof value === "boolean")
    ) {
      throw new Error(
        `${at}.const: architecture projections require a string or boolean literal`,
      );
    } else if (keyword === "pattern") {
      const translated = rustEcmaPattern(value, `${at}.pattern`);
      const existing = registeredPatternTranslations.get(value);
      if (existing !== undefined && existing !== translated) {
        throw new Error(`${at}.pattern: non-deterministic Rust translation`);
      }
      registeredPatternTranslations.set(value, translated);
    }
  }
  if (schema.type === "integer") {
    const finiteEnum =
      Array.isArray(schema.enum) &&
      schema.enum.length > 0 &&
      schema.enum.every(
        (candidate) =>
          Number.isSafeInteger(candidate) &&
          candidate >= PORTABLE_SIGNED_INTEGER_MINIMUM &&
          candidate <= PORTABLE_INTEGER_MAXIMUM,
      );
    if (
      !finiteEnum &&
      (!Number.isSafeInteger(schema.minimum) ||
        !Number.isSafeInteger(schema.maximum) ||
        schema.minimum < PORTABLE_SIGNED_INTEGER_MINIMUM ||
        schema.maximum > PORTABLE_INTEGER_MAXIMUM ||
        schema.minimum > schema.maximum)
    ) {
      throw new Error(
        `${at}: integer schemas must declare a finite enum or semantic minimum/maximum within the portable JS-safe domain ` +
          `${PORTABLE_SIGNED_INTEGER_MINIMUM}..${PORTABLE_INTEGER_MAXIMUM}`,
      );
    }
  }
  if (
    schema.format === "date-time" &&
    schema.pattern !== PORTABLE_CANONICAL_DATE_TIME_PATTERN
  ) {
    throw new Error(
      `${at}: date-time schemas must declare the portable canonical RFC3339 pattern ${PORTABLE_CANONICAL_DATE_TIME_PATTERN}`,
    );
  }

  for (const keyword of ["$defs", "properties"]) {
    const values = schema[keyword];
    if (values === undefined) continue;
    if (!isPlainObject(values)) {
      throw new Error(`${at}.${keyword}: expected an object of schemas`);
    }
    for (const [name, child] of Object.entries(values)) {
      for (const used of inventorySchemaKeywords(
        child,
        `${at}.${keyword}.${name}`,
      )) {
        inventory.add(used);
      }
    }
  }
  for (const keyword of ["items", "contains", "if", "then", "else"]) {
    const child = schema[keyword];
    if (child === undefined) continue;
    for (const used of inventorySchemaKeywords(child, `${at}.${keyword}`)) {
      inventory.add(used);
    }
  }
  for (const keyword of ["allOf", "anyOf", "oneOf"]) {
    const children = schema[keyword];
    if (children === undefined) continue;
    if (!Array.isArray(children) || children.length === 0) {
      throw new Error(`${at}.${keyword}: expected a non-empty schema array`);
    }
    for (const [index, child] of children.entries()) {
      for (const used of inventorySchemaKeywords(
        child,
        `${at}.${keyword}[${index}]`,
      )) {
        inventory.add(used);
      }
    }
  }
  return inventory;
}

function indent(text, spaces) {
  const prefix = " ".repeat(spaces);
  return text
    .split("\n")
    .map((line) => `${prefix}${line}`)
    .join("\n");
}

function closedStringValues(schema, rootSchema) {
  if (schema.$ref) {
    return closedStringValues(
      resolveLocalRef(rootSchema, schema.$ref),
      rootSchema,
    );
  }
  if (typeof schema.const === "string") return [schema.const];
  if (
    Array.isArray(schema.enum) &&
    schema.enum.length > 0 &&
    schema.enum.every((value) => typeof value === "string")
  ) {
    return [...new Set(schema.enum)];
  }
  const union = schema.oneOf ?? schema.anyOf;
  if (!union) return null;
  const branchValues = union.map((branch) =>
    closedStringValues(branch, rootSchema),
  );
  if (branchValues.some((values) => values === null)) return null;
  return [...new Set(branchValues.flat())];
}

function closedIntegerValues(schema, rootSchema) {
  if (schema.$ref) {
    return closedIntegerValues(
      resolveLocalRef(rootSchema, schema.$ref),
      rootSchema,
    );
  }
  if (
    Array.isArray(schema.enum) &&
    schema.enum.length > 0 &&
    schema.enum.every((value) => Number.isSafeInteger(value))
  ) {
    return [...new Set(schema.enum)];
  }
  return null;
}

function tsLiteralType(value) {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean"
  ) {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(tsLiteralType).join(", ")}]`;
  }
  if (isPlainObject(value)) {
    return `{ ${Object.entries(value)
      .map(([key, child]) => `${JSON.stringify(key)}: ${tsLiteralType(child)}`)
      .join("; ")} }`;
  }
  throw new Error(
    `Unsupported JSON literal in TypeScript projection: ${value}`,
  );
}

function tsType(schema, rootSchema, depth = 0) {
  if (schema.$ref) {
    return tsType(resolveLocalRef(rootSchema, schema.$ref), rootSchema, depth);
  }
  if (Object.hasOwn(schema, "const")) {
    return tsLiteralType(schema.const);
  }
  const closedStrings = closedStringValues(schema, rootSchema);
  if (closedStrings !== null) {
    return closedStrings.map((value) => JSON.stringify(value)).join(" | ");
  }
  const union = schema.oneOf ?? schema.anyOf;
  if (union) {
    return union.map((branch) => tsType(branch, rootSchema, depth)).join(" | ");
  }
  if (schema.enum) {
    return schema.enum.map(tsLiteralType).join(" | ");
  }
  switch (schema.type) {
    case "string":
      return "string";
    case "integer":
    case "number":
      return "number";
    case "boolean":
      return "boolean";
    case "null":
      return "null";
    case "array":
      return `Array<${tsType(schema.items ?? {}, rootSchema, depth + 1)}>`;
    case "object": {
      if (!schema.properties) {
        return "Record<string, unknown>";
      }
      const required = new Set(schema.required ?? []);
      const fields = Object.entries(schema.properties).map(
        ([name, property]) =>
          `${name}${required.has(name) ? "" : "?"}: ${tsType(property, rootSchema, depth + 1)};`,
      );
      return `{\n${indent(fields.join("\n"), (depth + 1) * 2)}\n${" ".repeat(depth * 2)}}`;
    }
    default:
      return "unknown";
  }
}

function fixtureMetadata() {
  return contracts.flatMap(({ entry }) => [
    ...entry.positive_fixture_refs.map((fixturePath) => ({
      contract_id: entry.contract_id,
      path: `docs/architecture/_meta/schemas/${fixturePath}`,
      expected: "accept",
      expected_schema_accept: true,
      expected_failure: null,
      expected_rule_id: null,
    })),
    ...entry.negative_fixture_refs.map((fixture) => ({
      contract_id: entry.contract_id,
      path: `docs/architecture/_meta/schemas/${fixture.path}`,
      expected: "reject",
      expected_schema_accept: fixture.expected_failure !== "schema",
      expected_failure: fixture.expected_failure,
      expected_rule_id: fixture.expected_rule_id ?? null,
    })),
  ]);
}

const COMPONENT_LANE_SCHEMES = Object.freeze([
  Object.freeze(["goal_run_profiles", "goal-run-profile"]),
  Object.freeze(["workflow_templates", "workflow-template"]),
  Object.freeze(["automation_specs", "automation"]),
  Object.freeze(["harness_profiles", "harness-profile"]),
  Object.freeze(["agent_harness_adapters", "agent-harness-adapter"]),
  Object.freeze(["skill_manifests", "skill"]),
  Object.freeze(["data_recipes", "data-recipe"]),
  Object.freeze(["runtime_tool_contracts", "tool"]),
  Object.freeze(["mcp_gateway_requirements", "mcp-gateway-requirement"]),
]);

function crossCategoryRevisionRef(scheme) {
  const wrongScheme =
    scheme === "workflow-template" ? "goal-run-profile" : "workflow-template";
  return `${wrongScheme}://acme/cross-category/revision/sha256:${"a".repeat(64)}`;
}

const componentLaneSchemeMutationDefinitions = [
  ...COMPONENT_LANE_SCHEMES.map(([field, scheme]) => ({
    id: `manifest-${field.replaceAll("_", "-")}-cross-category-ref`,
    contractId: "schema://ioi/foundations/autonomous-system-manifest/v1",
    fixture:
      "fixtures/autonomous-system-manifest-v1/positive-reusable-release.json",
    keywords: ["$ref", "items", "pattern"],
    directProjectionRejection: true,
    patch: {
      operation: "set",
      pointer: `/typed_components/${field}`,
      value: [
        {
          revision_ref: crossCategoryRevisionRef(scheme),
          content_hash: `sha256:${"b".repeat(64)}`,
        },
      ],
    },
  })),
  ...COMPONENT_LANE_SCHEMES.filter(
    ([field]) =>
      field !== "skill_manifests" && field !== "mcp_gateway_requirements",
  ).map(([field, scheme]) => ({
    id: `genesis-${field.replaceAll("_", "-")}-cross-category-ref`,
    contractId: "schema://ioi/foundations/autonomous-system-genesis/v1",
    fixture: "fixtures/autonomous-system-genesis-v1/positive-proposed.json",
    keywords: ["$ref", "items", "pattern"],
    directProjectionRejection: true,
    patch: {
      operation: "set",
      pointer: `/initial_component_bindings/${field}`,
      value: [
        {
          revision_ref: crossCategoryRevisionRef(scheme),
          content_hash: `sha256:${"b".repeat(64)}`,
        },
      ],
    },
  })),
];

const CHAIN_ACTIVATION_FIXTURE =
  "fixtures/autonomous-system-chain-v1/positive-active-sequence-two.json";

const mutationDefinitions = [
  {
    id: "sequence-zero-receipt-timestamp-detached",
    contractId:
      "schema://ioi/foundations/autonomous-system-sequence-zero-materialization-receipt/v2",
    fixture:
      "fixtures/autonomous-system-sequence-zero-materialization-receipt-v2/positive-materialized-pending-activation.json",
    keywords: [],
    patch: {
      operation: "set",
      pointer: "/at",
      value: "2026-07-19T12:00:01Z",
    },
  },
  {
    id: "sequence-zero-receipt-authorized-materialization-id-detached",
    contractId:
      "schema://ioi/foundations/autonomous-system-sequence-zero-materialization-receipt/v2",
    fixture:
      "fixtures/autonomous-system-sequence-zero-materialization-receipt-v2/positive-materialized-pending-activation.json",
    keywords: [],
    patch: {
      operation: "set",
      pointer: "/authorized_effect/materialization/materialization_id",
      value:
        "system-materialization://sequence-zero/sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    },
  },
  {
    id: "sequence-zero-receipt-authority-principal-detached",
    contractId:
      "schema://ioi/foundations/autonomous-system-sequence-zero-materialization-receipt/v2",
    fixture:
      "fixtures/autonomous-system-sequence-zero-materialization-receipt-v2/positive-materialized-pending-activation.json",
    keywords: [],
    patch: {
      operation: "set",
      pointer: "/principal_authority_binding/principal_ref",
      value: "agentgres://domain/acme/foreign",
    },
  },
  {
    id: "sequence-zero-receipt-grant-authority-detached",
    contractId:
      "schema://ioi/foundations/autonomous-system-sequence-zero-materialization-receipt/v2",
    fixture:
      "fixtures/autonomous-system-sequence-zero-materialization-receipt-v2/positive-materialized-pending-activation.json",
    keywords: [],
    buildPatch(value) {
      const authorityId = [...value.wallet_approval_grant.authority_id];
      authorityId[0] ^= 1;
      return {
        operation: "set",
        pointer: "/wallet_approval_grant/authority_id",
        value: authorityId,
      };
    },
  },
  {
    id: "sequence-zero-receipt-grant-key-detached",
    contractId:
      "schema://ioi/foundations/autonomous-system-sequence-zero-materialization-receipt/v2",
    fixture:
      "fixtures/autonomous-system-sequence-zero-materialization-receipt-v2/positive-materialized-pending-activation.json",
    keywords: [],
    buildPatch(value) {
      const publicKey = [...value.wallet_approval_grant.approver_public_key];
      publicKey[0] ^= 1;
      return {
        operation: "set",
        pointer: "/wallet_approval_grant/approver_public_key",
        value: publicKey,
      };
    },
  },
  {
    id: "sequence-zero-receipt-effect-receipt-ref-detached",
    contractId:
      "schema://ioi/foundations/autonomous-system-sequence-zero-materialization-receipt/v2",
    fixture:
      "fixtures/autonomous-system-sequence-zero-materialization-receipt-v2/positive-materialized-pending-activation.json",
    keywords: [],
    patch: {
      operation: "set",
      pointer:
        "/authorized_effect/materialization/materialization_receipt_ref",
      value:
        "receipt://aszmr_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    },
  },
  {
    id: "sequence-zero-receipt-effect-registry-ref-detached",
    contractId:
      "schema://ioi/foundations/autonomous-system-sequence-zero-materialization-receipt/v2",
    fixture:
      "fixtures/autonomous-system-sequence-zero-materialization-receipt-v2/positive-materialized-pending-activation.json",
    keywords: [],
    patch: {
      operation: "set",
      pointer:
        "/authorized_effect/materialization/component_registry_ref",
      value:
        "agentgres://object-set/autonomous-system-components/sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    },
  },
  {
    id: "sequence-zero-receipt-policy-hash-self-attestation",
    contractId:
      "schema://ioi/foundations/autonomous-system-sequence-zero-materialization-receipt/v2",
    fixture:
      "fixtures/autonomous-system-sequence-zero-materialization-receipt-v2/positive-materialized-pending-activation.json",
    keywords: [],
    patch: {
      operation: "set",
      pointer: "/policy_hash",
      value:
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    },
  },
  {
    id: "sequence-zero-receipt-wallet-consumption-request-detached",
    contractId:
      "schema://ioi/foundations/autonomous-system-sequence-zero-materialization-receipt/v2",
    fixture:
      "fixtures/autonomous-system-sequence-zero-materialization-receipt-v2/positive-materialized-pending-activation.json",
    keywords: [],
    patch: {
      operation: "set",
      pointer: "/bound_facts/wallet_grant_consumption_ref",
      value:
        "wallet.network://approval-effect-consumption/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/2020202020202020202020202020202020202020202020202020202020202020",
    },
  },
  {
    id: "sequence-zero-receipt-coordinates-ref-detached",
    contractId:
      "schema://ioi/foundations/autonomous-system-sequence-zero-materialization-receipt/v2",
    fixture:
      "fixtures/autonomous-system-sequence-zero-materialization-receipt-v2/positive-materialized-pending-activation.json",
    keywords: [],
    patch: {
      operation: "set",
      pointer: "/principal_authority_binding/coordinates/binding_ref",
      value:
        "wallet.network://principal-authority-binding/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    },
  },
  {
    id: "sequence-zero-receipt-authority-key-statement-detached",
    contractId:
      "schema://ioi/foundations/autonomous-system-sequence-zero-materialization-receipt/v2",
    fixture:
      "fixtures/autonomous-system-sequence-zero-materialization-receipt-v2/positive-materialized-pending-activation.json",
    keywords: [],
    buildPatch(value) {
      const publicKey = [
        ...value.principal_authority_binding.binding_proof.statement
          .authority_public_key,
      ];
      publicKey[0] ^= 1;
      return {
        operation: "set",
        pointer:
          "/principal_authority_binding/binding_proof/statement/authority_public_key",
        value: publicKey,
      };
    },
  },
  {
    id: "sequence-zero-receipt-authority-id-self-attestation",
    contractId:
      "schema://ioi/foundations/autonomous-system-sequence-zero-materialization-receipt/v2",
    fixture:
      "fixtures/autonomous-system-sequence-zero-materialization-receipt-v2/positive-materialized-pending-activation.json",
    keywords: [],
    buildPatch(value) {
      const authorityId = [
        ...value.principal_authority_binding.approval_authority.authority_id,
      ];
      authorityId[0] ^= 1;
      return {
        operation: "set",
        pointer:
          "/principal_authority_binding/approval_authority/authority_id",
        value: authorityId,
      };
    },
  },
  {
    id: "sequence-zero-receipt-issuer-root-id-self-attestation",
    contractId:
      "schema://ioi/foundations/autonomous-system-sequence-zero-materialization-receipt/v2",
    fixture:
      "fixtures/autonomous-system-sequence-zero-materialization-receipt-v2/positive-materialized-pending-activation.json",
    keywords: [],
    buildPatch(value) {
      const issuerId = [
        ...value.principal_authority_binding.binding_proof.statement
          .issuer_root_account_id,
      ];
      issuerId[0] ^= 1;
      return {
        operation: "set",
        pointer:
          "/principal_authority_binding/binding_proof/statement/issuer_root_account_id",
        value: issuerId,
      };
    },
  },
  {
    id: "sequence-zero-receipt-unsupported-signature-suite",
    contractId:
      "schema://ioi/foundations/autonomous-system-sequence-zero-materialization-receipt/v2",
    fixture:
      "fixtures/autonomous-system-sequence-zero-materialization-receipt-v2/positive-materialized-pending-activation.json",
    keywords: ["enum"],
    directProjectionRejection: true,
    patch: {
      operation: "set",
      pointer: "/wallet_approval_grant/approver_suite",
      value: -100,
    },
  },
  {
    id: "sequence-zero-receipt-grant-suite-mismatch",
    contractId:
      "schema://ioi/foundations/autonomous-system-sequence-zero-materialization-receipt/v2",
    fixture:
      "fixtures/autonomous-system-sequence-zero-materialization-receipt-v2/positive-materialized-pending-activation.json",
    keywords: [],
    patch: {
      operation: "set",
      pointer: "/wallet_approval_grant/approver_suite",
      value: -17,
    },
  },
  {
    id: "sequence-zero-receipt-authority-suite-mismatch",
    contractId:
      "schema://ioi/foundations/autonomous-system-sequence-zero-materialization-receipt/v2",
    fixture:
      "fixtures/autonomous-system-sequence-zero-materialization-receipt-v2/positive-materialized-pending-activation.json",
    keywords: [],
    patch: {
      operation: "set",
      pointer:
        "/principal_authority_binding/approval_authority/signature_suite",
      value: -17,
    },
  },
  {
    id: "sequence-zero-receipt-oversized-principal",
    contractId:
      "schema://ioi/foundations/autonomous-system-sequence-zero-materialization-receipt/v2",
    fixture:
      "fixtures/autonomous-system-sequence-zero-materialization-receipt-v2/positive-materialized-pending-activation.json",
    keywords: ["maxLength"],
    directProjectionRejection: true,
    patch: {
      operation: "set",
      pointer: "/principal_authority_binding/principal_ref",
      value: `domain://${"a".repeat(301)}`,
    },
  },
  {
    id: "sequence-zero-receipt-nested-authority-claim",
    contractId:
      "schema://ioi/foundations/autonomous-system-sequence-zero-materialization-receipt/v2",
    fixture:
      "fixtures/autonomous-system-sequence-zero-materialization-receipt-v2/positive-materialized-pending-activation.json",
    keywords: ["additionalProperties"],
    directProjectionRejection: true,
    patch: {
      operation: "set",
      pointer: "/wallet_approval_grant/scoped_exception",
      value: {
        exception_id: "exception-1",
        allowed_classes: ["email"],
        destination_hash: Array(32).fill(7),
        action_hash: Array(32).fill(8),
        expires_at: 1,
        max_uses: 1,
        justification_hash: Array(32).fill(9),
        forged_context: "claim-inflation",
      },
    },
  },
  {
    id: "sequence-zero-receipt-truncated-grant-signature",
    contractId:
      "schema://ioi/foundations/autonomous-system-sequence-zero-materialization-receipt/v2",
    fixture:
      "fixtures/autonomous-system-sequence-zero-materialization-receipt-v2/positive-materialized-pending-activation.json",
    keywords: ["allOf", "if", "then", "minItems"],
    directProjectionRejection: true,
    patch: {
      operation: "set",
      pointer: "/wallet_approval_grant/approver_sig",
      value: [3],
    },
  },
  {
    id: "sequence-zero-receipt-truncated-root-signature",
    contractId:
      "schema://ioi/foundations/autonomous-system-sequence-zero-materialization-receipt/v2",
    fixture:
      "fixtures/autonomous-system-sequence-zero-materialization-receipt-v2/positive-materialized-pending-activation.json",
    keywords: ["allOf", "if", "then", "minItems"],
    directProjectionRejection: true,
    patch: {
      operation: "set",
      pointer:
        "/principal_authority_binding/binding_proof/issuer_signature_proof/signature",
      value: [12],
    },
  },
  {
    id: "sequence-zero-receipt-duplicated-materialization-field-detached",
    contractId:
      "schema://ioi/foundations/autonomous-system-sequence-zero-materialization-receipt/v2",
    fixture:
      "fixtures/autonomous-system-sequence-zero-materialization-receipt-v2/positive-materialized-pending-activation.json",
    keywords: [],
    patch: {
      operation: "set",
      pointer: "/bound_facts/package_id",
      value: "package://acme/detached-package",
    },
  },
  {
    id: "sequence-zero-receipt-embedded-component-count-detached",
    contractId:
      "schema://ioi/foundations/autonomous-system-sequence-zero-materialization-receipt/v2",
    fixture:
      "fixtures/autonomous-system-sequence-zero-materialization-receipt-v2/positive-materialized-pending-activation.json",
    keywords: [],
    buildPatch(value) {
      return {
        operation: "set",
        pointer: "/authorized_effect/materialization/component_bindings",
        value: value.authorized_effect.materialization.component_bindings.slice(
          0,
          -1,
        ),
      };
    },
  },
  {
    id: "sequence-zero-receipt-embedded-component-identity-duplicate",
    contractId:
      "schema://ioi/foundations/autonomous-system-sequence-zero-materialization-receipt/v2",
    fixture:
      "fixtures/autonomous-system-sequence-zero-materialization-receipt-v2/positive-materialized-pending-activation.json",
    keywords: [],
    buildPatch(value) {
      const bindings = structuredClone(
        value.authorized_effect.materialization.component_bindings,
      );
      bindings[1].kind = bindings[0].kind;
      bindings[1].binding_ref = bindings[0].binding_ref;
      return {
        operation: "set",
        pointer: "/authorized_effect/materialization/component_bindings",
        value: bindings,
      };
    },
  },
  {
    id: "sequence-zero-receipt-embedded-component-kind-ref-substitution",
    contractId:
      "schema://ioi/foundations/autonomous-system-sequence-zero-materialization-receipt/v2",
    fixture:
      "fixtures/autonomous-system-sequence-zero-materialization-receipt-v2/positive-materialized-pending-activation.json",
    keywords: ["allOf", "if", "then", "$ref", "pattern"],
    directProjectionRejection: true,
    patch: {
      operation: "set",
      pointer:
        "/authorized_effect/materialization/component_bindings/0/binding_ref",
      value:
        "workflow-template://acme/system-alpha/default/revision/sha256:1111111111111111111111111111111111111111111111111111111111111111",
    },
  },
  {
    id: "sequence-zero-receipt-embedded-deployment-root-detached",
    contractId:
      "schema://ioi/foundations/autonomous-system-sequence-zero-materialization-receipt/v2",
    fixture:
      "fixtures/autonomous-system-sequence-zero-materialization-receipt-v2/positive-materialized-pending-activation.json",
    keywords: [],
    patch: {
      operation: "set",
      pointer:
        "/authorized_effect/materialization/profile_refs/deployment_profile_ref",
      value:
        "deployment-profile://acme/system-alpha/local/revision/sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
    },
  },
  {
    id: "sequence-zero-receipt-legacy-deployment-compatibility-root-detached",
    contractId:
      "schema://ioi/foundations/autonomous-system-sequence-zero-materialization-receipt/v2",
    fixture:
      "fixtures/autonomous-system-sequence-zero-materialization-receipt-v2/positive-materialized-pending-activation.json",
    keywords: [],
    patch: {
      operation: "set",
      pointer:
        "/authorized_effect/materialization/profile_refs/deployment_profile_ref",
      value:
        "deployment-profile://acme/system-alpha/local",
    },
  },
  {
    id: "sequence-zero-receipt-grant-request-detached",
    contractId:
      "schema://ioi/foundations/autonomous-system-sequence-zero-materialization-receipt/v2",
    fixture:
      "fixtures/autonomous-system-sequence-zero-materialization-receipt-v2/positive-materialized-pending-activation.json",
    keywords: [],
    buildPatch(value) {
      const requestHash = [...value.wallet_approval_grant.request_hash];
      requestHash[0] ^= 1;
      return {
        operation: "set",
        pointer: "/wallet_approval_grant/request_hash",
        value: requestHash,
      };
    },
  },
  {
    id: "sequence-zero-receipt-consumption-evidence-id-detached",
    contractId:
      "schema://ioi/foundations/autonomous-system-sequence-zero-materialization-receipt/v2",
    fixture:
      "fixtures/autonomous-system-sequence-zero-materialization-receipt-v2/positive-materialized-pending-activation.json",
    keywords: [],
    patch: {
      operation: "set",
      pointer: "/bound_facts/wallet_grant_consumption_evidence_ref",
      value:
        "system-sequence-zero-authority-consumption://aszmc_2121212121212121212121212121212121212121212121212121212121212121",
    },
  },
  {
    id: "sequence-zero-receipt-grant-policy-detached",
    contractId:
      "schema://ioi/foundations/autonomous-system-sequence-zero-materialization-receipt/v2",
    fixture:
      "fixtures/autonomous-system-sequence-zero-materialization-receipt-v2/positive-materialized-pending-activation.json",
    keywords: [],
    buildPatch(value) {
      const policyHash = [...value.wallet_approval_grant.policy_hash];
      policyHash[0] ^= 1;
      return {
        operation: "set",
        pointer: "/wallet_approval_grant/policy_hash",
        value: policyHash,
      };
    },
  },
  {
    id: "sequence-zero-receipt-effect-hash-self-attestation",
    contractId:
      "schema://ioi/foundations/autonomous-system-sequence-zero-materialization-receipt/v2",
    fixture:
      "fixtures/autonomous-system-sequence-zero-materialization-receipt-v2/positive-materialized-pending-activation.json",
    keywords: [],
    patch: {
      operation: "set",
      pointer: "/effect_hash",
      value:
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    },
  },
  {
    id: "sequence-zero-receipt-grant-identity-detached",
    contractId:
      "schema://ioi/foundations/autonomous-system-sequence-zero-materialization-receipt/v2",
    fixture:
      "fixtures/autonomous-system-sequence-zero-materialization-receipt-v2/positive-materialized-pending-activation.json",
    keywords: [],
    patch: {
      operation: "set",
      pointer: "/authority_grant_id",
      value:
        "grant://wallet.network/approval/sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    },
  },
  {
    id: "sequence-zero-receipt-snapshot-hash-self-attestation",
    contractId:
      "schema://ioi/foundations/autonomous-system-sequence-zero-materialization-receipt/v2",
    fixture:
      "fixtures/autonomous-system-sequence-zero-materialization-receipt-v2/positive-materialized-pending-activation.json",
    keywords: [],
    buildPatch(value) {
      const snapshotHash = [
        ...value.principal_authority_binding.approval_authority_snapshot_hash,
      ];
      snapshotHash[0] ^= 1;
      return {
        operation: "set",
        pointer:
          "/principal_authority_binding/approval_authority_snapshot_hash",
        value: snapshotHash,
      };
    },
  },
  {
    id: "sequence-zero-receipt-statement-hash-self-attestation",
    contractId:
      "schema://ioi/foundations/autonomous-system-sequence-zero-materialization-receipt/v2",
    fixture:
      "fixtures/autonomous-system-sequence-zero-materialization-receipt-v2/positive-materialized-pending-activation.json",
    keywords: [],
    buildPatch(value) {
      const statementHash = [
        ...value.principal_authority_binding.binding_proof.statement_hash,
      ];
      statementHash[0] ^= 1;
      return {
        operation: "set",
        pointer:
          "/principal_authority_binding/binding_proof/statement_hash",
        value: statementHash,
      };
    },
  },
  {
    id: "sequence-zero-receipt-binding-hash-self-attestation",
    contractId:
      "schema://ioi/foundations/autonomous-system-sequence-zero-materialization-receipt/v2",
    fixture:
      "fixtures/autonomous-system-sequence-zero-materialization-receipt-v2/positive-materialized-pending-activation.json",
    keywords: [],
    buildPatch(value) {
      const bindingHash = [
        ...value.principal_authority_binding.binding_proof.binding_hash,
      ];
      bindingHash[0] ^= 1;
      return {
        operation: "set",
        pointer: "/principal_authority_binding/binding_proof/binding_hash",
        value: bindingHash,
      };
    },
  },
  {
    id: "sequence-zero-receipt-binding-coordinates-detached",
    contractId:
      "schema://ioi/foundations/autonomous-system-sequence-zero-materialization-receipt/v2",
    fixture:
      "fixtures/autonomous-system-sequence-zero-materialization-receipt-v2/positive-materialized-pending-activation.json",
    keywords: [],
    patch: {
      operation: "set",
      pointer: "/principal_authority_binding/coordinates/binding_version",
      value: 2,
    },
  },
  {
    id: "sequence-zero-receipt-authority-tuple-detached",
    contractId:
      "schema://ioi/foundations/autonomous-system-sequence-zero-materialization-receipt/v2",
    fixture:
      "fixtures/autonomous-system-sequence-zero-materialization-receipt-v2/positive-materialized-pending-activation.json",
    keywords: [],
    buildPatch(value) {
      const authorityId = [
        ...value.principal_authority_binding.binding_proof.statement
          .authority_id,
      ];
      authorityId[0] ^= 1;
      return {
        operation: "set",
        pointer:
          "/principal_authority_binding/binding_proof/statement/authority_id",
        value: authorityId,
      };
    },
  },
  {
    id: "sequence-zero-receipt-scope-uncovered",
    contractId:
      "schema://ioi/foundations/autonomous-system-sequence-zero-materialization-receipt/v2",
    fixture:
      "fixtures/autonomous-system-sequence-zero-materialization-receipt-v2/positive-materialized-pending-activation.json",
    keywords: [],
    patch: {
      operation: "set",
      pointer:
        "/principal_authority_binding/approval_authority/scope_allowlist",
      value: ["scope:unrelated"],
    },
  },
  {
    id: "sequence-zero-receipt-matched-scope-does-not-cover",
    contractId:
      "schema://ioi/foundations/autonomous-system-sequence-zero-materialization-receipt/v2",
    fixture:
      "fixtures/autonomous-system-sequence-zero-materialization-receipt-v2/positive-materialized-pending-activation.json",
    keywords: [],
    patch: {
      operation: "set",
      pointer: "/principal_authority_binding/matched_scope",
      value: "scope:unrelated.*",
    },
  },
  {
    id: "sequence-zero-receipt-binding-signed-after-resolution",
    contractId:
      "schema://ioi/foundations/autonomous-system-sequence-zero-materialization-receipt/v2",
    fixture:
      "fixtures/autonomous-system-sequence-zero-materialization-receipt-v2/positive-materialized-pending-activation.json",
    keywords: [],
    patch: {
      operation: "set",
      pointer:
        "/principal_authority_binding/binding_proof/statement/signed_at_ms",
      value: 1784462400001,
    },
  },
  {
    id: "sequence-zero-receipt-binding-expired-at-resolution",
    contractId:
      "schema://ioi/foundations/autonomous-system-sequence-zero-materialization-receipt/v2",
    fixture:
      "fixtures/autonomous-system-sequence-zero-materialization-receipt-v2/positive-materialized-pending-activation.json",
    keywords: [],
    patch: {
      operation: "set",
      pointer:
        "/principal_authority_binding/binding_proof/statement/expires_at_ms",
      value: 1784462399999,
    },
  },
  {
    id: "sequence-zero-receipt-authority-expired-at-resolution",
    contractId:
      "schema://ioi/foundations/autonomous-system-sequence-zero-materialization-receipt/v2",
    fixture:
      "fixtures/autonomous-system-sequence-zero-materialization-receipt-v2/positive-materialized-pending-activation.json",
    keywords: [],
    patch: {
      operation: "set",
      pointer: "/principal_authority_binding/approval_authority/expires_at",
      value: 1784462399999,
    },
  },
  {
    id: "sequence-zero-receipt-grant-expired-at-resolution",
    contractId:
      "schema://ioi/foundations/autonomous-system-sequence-zero-materialization-receipt/v2",
    fixture:
      "fixtures/autonomous-system-sequence-zero-materialization-receipt-v2/positive-materialized-pending-activation.json",
    keywords: [],
    patch: {
      operation: "set",
      pointer: "/wallet_approval_grant/expires_at",
      value: 1784462399999,
    },
  },
  {
    id: "sequence-zero-receipt-boundary-required-ref-missing",
    contractId:
      "schema://ioi/foundations/autonomous-system-sequence-zero-materialization-receipt/v2",
    fixture:
      "fixtures/autonomous-system-sequence-zero-materialization-receipt-v2/positive-materialized-pending-activation.json",
    keywords: [],
    buildPatch(value) {
      return {
        operation: "set",
        pointer: "/attested_boundary_fact_refs",
        value: value.attested_boundary_fact_refs.filter(
          (reference) =>
            reference !== value.bound_facts.wallet_grant_consumption_ref,
        ),
      };
    },
  },
  {
    id: "sequence-zero-receipt-boundary-extra-ref-injected",
    contractId:
      "schema://ioi/foundations/autonomous-system-sequence-zero-materialization-receipt/v2",
    fixture:
      "fixtures/autonomous-system-sequence-zero-materialization-receipt-v2/positive-materialized-pending-activation.json",
    keywords: [],
    buildPatch(value) {
      return {
        operation: "set",
        pointer: "/attested_boundary_fact_refs",
        value: [
          ...value.attested_boundary_fact_refs,
          "policy://acme/injected-boundary",
        ],
      };
    },
  },
  {
    id: "sequence-zero-materialization-broad-receipt-ref",
    contractId:
      "schema://ioi/foundations/autonomous-system-sequence-zero-materialization/v1",
    fixture:
      "fixtures/autonomous-system-sequence-zero-materialization-v1/positive-materialized-pending-activation.json",
    keywords: ["$ref", "pattern"],
    directProjectionRejection: true,
    patch: {
      operation: "set",
      pointer: "/materialization_receipt_ref",
      value: "receipt://broad-but-no-longer-valid",
    },
  },
  {
    id: "type-number-for-string",
    contractId: "schema://ioi/foundations/receipt-envelope/v1",
    fixture: "fixtures/receipt-envelope-v1/positive-assured.json",
    keywords: ["type", "properties"],
    patch: { operation: "set", pointer: "/timestamp", value: 42 },
  },
  {
    id: "required-property-removed",
    contractId: "schema://ioi/foundations/receipt-envelope/v1",
    fixture: "fixtures/receipt-envelope-v1/positive-assured.json",
    keywords: ["required"],
    patch: { operation: "remove", pointer: "/actor_id" },
  },
  {
    id: "required-nullable-claim-scope-missing",
    contractId: "schema://ioi/foundations/receipt-envelope/v1",
    fixture: "fixtures/receipt-envelope-v1/positive-minimal.json",
    keywords: ["required"],
    directProjectionRejection: true,
    patch: { operation: "remove", pointer: "/claim_scope_ref" },
  },
  {
    id: "additional-property-injected",
    contractId: "schema://ioi/foundations/receipt-envelope/v1",
    fixture: "fixtures/receipt-envelope-v1/positive-assured.json",
    keywords: ["additionalProperties"],
    patch: { operation: "set", pointer: "/unregistered_field", value: true },
  },
  {
    id: "referenced-pattern-violated",
    contractId: "schema://ioi/foundations/receipt-envelope/v1",
    fixture: "fixtures/receipt-envelope-v1/positive-assured.json",
    keywords: ["$ref", "pattern"],
    patch: {
      operation: "set",
      pointer: "/receipt_profile_ref",
      value: "not-a-schema-ref",
    },
  },
  {
    id: "ecma-whitespace-byte-order-mark-rejected",
    contractId: "schema://ioi/foundations/receipt-envelope/v1",
    fixture: "fixtures/receipt-envelope-v1/positive-assured.json",
    keywords: ["pattern"],
    patch: {
      operation: "set",
      pointer: "/receipt_profile_ref",
      value: "schema://ioi/test/\uFEFF",
    },
  },
  {
    id: "ecma-non-whitespace-next-line-accepted",
    contractId: "schema://ioi/foundations/receipt-envelope/v1",
    fixture: "fixtures/receipt-envelope-v1/positive-assured.json",
    keywords: ["pattern"],
    ajvExpectedAccept: true,
    patch: {
      operation: "set",
      pointer: "/receipt_profile_ref",
      value: "schema://ioi/test/\u0085",
    },
  },
  {
    id: "nullable-any-of-violated",
    contractId: "schema://ioi/foundations/receipt-envelope/v1",
    fixture: "fixtures/receipt-envelope-v1/positive-assured.json",
    keywords: ["anyOf"],
    patch: { operation: "set", pointer: "/claim_scope_ref", value: 42 },
  },
  {
    id: "optional-non-nullable-input-hash-null",
    contractId: "schema://ioi/foundations/receipt-envelope/v1",
    fixture: "fixtures/receipt-envelope-v1/positive-minimal.json",
    keywords: ["type", "$ref"],
    directProjectionRejection: true,
    patch: { operation: "set", pointer: "/input_hash", value: null },
  },
  {
    id: "unicode-aware-min-length-violated",
    contractId:
      "schema://ioi/components/connectors-tools/runtime-tool-contract/v1",
    fixture: "fixtures/runtime-tool-contract-v1/positive-declared-egress.json",
    keywords: ["minLength"],
    patch: { operation: "set", pointer: "/display_name", value: "" },
  },
  {
    id: "closed-enum-violated-with-raw-string-sentinel",
    contractId: "schema://ioi/foundations/authority-grant-envelope/v1",
    fixture: "fixtures/authority-grant-envelope-v1/positive-active.json",
    keywords: ["enum"],
    directProjectionRejection: true,
    patch: {
      operation: "set",
      pointer: "/status",
      value: 'retired"###schema-controlled',
    },
  },
  {
    id: "minimum-violated",
    contractId: "schema://ioi/foundations/authority-grant-envelope/v1",
    fixture: "fixtures/authority-grant-envelope-v1/positive-active.json",
    keywords: ["minimum"],
    patch: { operation: "set", pointer: "/revocation_epoch", value: -1 },
  },
  {
    id: "array-items-schema-violated",
    contractId: "schema://ioi/foundations/authority-grant-envelope/v1",
    fixture: "fixtures/authority-grant-envelope-v1/positive-active.json",
    keywords: ["items"],
    patch: { operation: "set", pointer: "/authority_scopes", value: [42] },
  },
  {
    id: "deep-unique-items-key-order-duplicate",
    contractId: "schema://ioi/foundations/authority-key-set/v1",
    fixture: "fixtures/authority-key-set-v1/positive-active.json",
    keywords: ["uniqueItems"],
    buildPatch(value) {
      const original = value.keys[0];
      const reverseKeyOrder = Object.fromEntries(
        Object.entries(original).reverse(),
      );
      return {
        operation: "set",
        pointer: "/keys",
        value: [original, reverseKeyOrder],
      };
    },
  },
  {
    id: "impossible-rfc3339-calendar-date",
    contractId: "schema://ioi/foundations/authority-grant-envelope/v1",
    fixture: "fixtures/authority-grant-envelope-v1/positive-active.json",
    keywords: ["format"],
    patch: {
      operation: "set",
      pointer: "/constraints/expires_at",
      value: "2025-02-30T00:00:00Z",
    },
  },
  {
    id: "closed-const-violated",
    contractId: "schema://ioi/foundations/authority-grant-envelope/v2",
    fixture: "fixtures/authority-grant-envelope-v2/positive-root.json",
    keywords: ["const"],
    directProjectionRejection: true,
    patch: {
      operation: "set",
      pointer: "/schema_version",
      value: "ioi.foundations.authority-grant-envelope.v999",
    },
  },
  {
    id: "one-of-violated",
    contractId: "schema://ioi/foundations/authority-grant-envelope/v2",
    fixture: "fixtures/authority-grant-envelope-v2/positive-root.json",
    keywords: ["oneOf"],
    patch: { operation: "set", pointer: "/parent_grant", value: 42 },
  },
  {
    id: "maximum-safe-integer-violated",
    contractId:
      "schema://ioi/foundations/managed-work-billing-ledger-bundle/v1",
    fixture:
      "fixtures/managed-work-billing-ledger-bundle-v1/positive-complete.json",
    keywords: ["maximum"],
    patch: {
      operation: "set",
      pointer: "/plan/included_work_credits/units",
      value: 9_007_199_254_740_992,
    },
  },
  {
    id: "minimum-array-size-violated",
    contractId: "schema://ioi/foundations/authority-grant-envelope/v1",
    fixture: "fixtures/authority-grant-envelope-v1/positive-active.json",
    keywords: ["minItems"],
    patch: { operation: "set", pointer: "/resources", value: [] },
  },
  {
    id: "type-less-if-then-max-items-violated",
    contractId: "schema://ioi/foundations/physical-action-execution-receipt/v1",
    fixture:
      "fixtures/physical-action-execution-receipt-v1/positive-committed.json",
    keywords: ["allOf", "if", "then", "maxItems"],
    patch: {
      operation: "set",
      pointer: "/body/outcome_normalization_error_codes",
      value: ["unexpected_error"],
    },
  },
  {
    id: "nested-all-of-contains-member-missing",
    contractId: "schema://ioi/foundations/dispute-rail-bundle/v1",
    fixture:
      "fixtures/dispute-rail-bundle-v1/positive-marketplace-resolution.json",
    keywords: ["contains"],
    patch: {
      operation: "set",
      pointer: "/resolution/required_receipt_kinds",
      value: ["dispute_resolution", "dispute_remedy_execution"],
    },
  },
  {
    id: "type-less-if-else-required-hash-violated",
    contractId: "schema://ioi/foundations/autonomous-system-manifest/v1",
    fixture:
      "fixtures/autonomous-system-manifest-v1/positive-reusable-release.json",
    keywords: ["allOf", "if", "else"],
    patch: {
      operation: "set",
      pointer: "/workflow_compatibility/default_workflow_template_content_hash",
      value: null,
    },
  },
  {
    id: "boolean-const-self-authority-violated",
    contractId: "schema://ioi/foundations/autonomous-system-constitution/v1",
    fixture: "fixtures/autonomous-system-constitution-v1/positive-draft.json",
    keywords: ["const"],
    directProjectionRejection: true,
    patch: {
      operation: "set",
      pointer: "/governance/agent_may_commit_amendment",
      value: true,
    },
  },
  {
    id: "genesis-authorized-without-admission-authority-status-evidence",
    contractId: "schema://ioi/foundations/autonomous-system-genesis/v1",
    fixture: "fixtures/autonomous-system-genesis-v1/positive-proposed.json",
    keywords: ["allOf", "if", "then", "minItems"],
    directProjectionRejection: true,
    patch: { operation: "set", pointer: "/status", value: "authorized" },
  },
  {
    id: "genesis-activated-without-activation-lifecycle-evidence",
    contractId: "schema://ioi/foundations/autonomous-system-genesis/v1",
    fixture: "fixtures/autonomous-system-genesis-v1/positive-proposed.json",
    keywords: ["allOf", "if", "then", "minItems"],
    directProjectionRejection: true,
    patch: { operation: "set", pointer: "/status", value: "activated" },
  },
  {
    id: "constitution-active-without-activation-receipt",
    contractId: "schema://ioi/foundations/autonomous-system-constitution/v1",
    fixture: "fixtures/autonomous-system-constitution-v1/positive-draft.json",
    keywords: ["allOf", "if", "then"],
    directProjectionRejection: true,
    patch: { operation: "set", pointer: "/status", value: "active" },
  },
  {
    id: "constitution-draft-with-activation-residue",
    contractId: "schema://ioi/foundations/autonomous-system-constitution/v1",
    fixture: "fixtures/autonomous-system-constitution-v1/positive-draft.json",
    keywords: ["allOf", "if", "then"],
    directProjectionRejection: true,
    patch: {
      operation: "set",
      pointer: "/activation_receipt_ref",
      value: "receipt://acme/system-alpha/activation",
    },
  },
  {
    id: "constitution-draft-with-public-commitment-residue",
    contractId: "schema://ioi/foundations/autonomous-system-constitution/v1",
    fixture: "fixtures/autonomous-system-constitution-v1/positive-draft.json",
    keywords: ["allOf", "if", "then"],
    directProjectionRejection: true,
    patch: {
      operation: "set",
      pointer: "/public_commitment_ref",
      value: "commitment://acme/system-alpha/constitution",
    },
  },
  {
    id: "ordering-active-without-conformance-evidence",
    contractId:
      "schema://ioi/foundations/ordering-admission-finality-profile/v1",
    fixture:
      "fixtures/ordering-admission-finality-profile-v1/positive-single-authority.json",
    keywords: ["allOf", "if", "then", "minItems"],
    directProjectionRejection: true,
    patch: { operation: "set", pointer: "/status", value: "active" },
  },
  {
    id: "ordering-draft-with-conformance-residue",
    contractId:
      "schema://ioi/foundations/ordering-admission-finality-profile/v1",
    fixture:
      "fixtures/ordering-admission-finality-profile-v1/positive-single-authority.json",
    keywords: ["allOf", "if", "then", "maxItems"],
    directProjectionRejection: true,
    patch: {
      operation: "set",
      pointer: "/conformance_receipt_refs",
      value: ["receipt://acme/system-alpha/ordering-conformance"],
    },
  },
  {
    id: "lifecycle-committed-without-terminal-proof-set",
    contractId: "schema://ioi/foundations/lifecycle-transition/v1",
    fixture:
      "fixtures/lifecycle-transition-v1/positive-initialize-proposal.json",
    keywords: ["allOf", "if", "then", "minItems"],
    directProjectionRejection: true,
    patch: { operation: "set", pointer: "/status", value: "committed" },
  },
  {
    id: "lifecycle-proposed-with-decision-residue",
    contractId: "schema://ioi/foundations/lifecycle-transition/v1",
    fixture:
      "fixtures/lifecycle-transition-v1/positive-initialize-proposal.json",
    keywords: ["allOf", "if", "then"],
    directProjectionRejection: true,
    patch: {
      operation: "set",
      pointer: "/decision_ref",
      value: "decision://acme/system-alpha/initialize",
    },
  },
  {
    id: "lifecycle-transition-receipt-initialize-wrong-sequence",
    contractId:
      "schema://ioi/foundations/lifecycle-transition-receipt/v1",
    fixture:
      "fixtures/lifecycle-transition-receipt-v1/positive-initialize.json",
    keywords: ["allOf", "if", "then", "enum"],
    directProjectionRejection: true,
    patch: { operation: "set", pointer: "/sequence", value: 3 },
  },
  {
    id: "lifecycle-transition-receipt-initialize-missing-source-artifact",
    contractId:
      "schema://ioi/foundations/lifecycle-transition-receipt/v1",
    fixture:
      "fixtures/lifecycle-transition-receipt-v1/positive-initialize.json",
    keywords: ["allOf", "if", "then", "required"],
    directProjectionRejection: true,
    patch: {
      operation: "remove",
      pointer: "/bound_facts/sequence_zero_receipt_artifact_root",
    },
  },
  {
    id: "lifecycle-transition-receipt-initialize-detached-subject",
    contractId:
      "schema://ioi/foundations/lifecycle-transition-receipt/v1",
    fixture:
      "fixtures/lifecycle-transition-receipt-v1/positive-initialize.json",
    keywords: [],
    patch: {
      operation: "set",
      pointer: "/subject_ref",
      value: "lifecycle-transition://acme/system-alpha/sequence/99",
    },
  },
  {
    id: "lifecycle-transition-receipt-initialize-wrong-scope",
    contractId:
      "schema://ioi/foundations/lifecycle-transition-receipt/v1",
    fixture:
      "fixtures/lifecycle-transition-receipt-v1/positive-initialize.json",
    keywords: ["allOf", "if", "then", "const"],
    directProjectionRejection: true,
    patch: {
      operation: "set",
      pointer: "/required_scope",
      value: "scope:autonomous_system.lifecycle.pause",
    },
  },
  {
    id: "lifecycle-transition-receipt-cannot-claim-activation",
    contractId:
      "schema://ioi/foundations/lifecycle-transition-receipt/v1",
    fixture:
      "fixtures/lifecycle-transition-receipt-v1/positive-initialize.json",
    keywords: ["enum"],
    directProjectionRejection: true,
    patch: { operation: "set", pointer: "/op", value: "activate" },
  },
  {
    id: "chain-operation-log-required",
    contractId: "schema://ioi/foundations/autonomous-system-chain/v1",
    fixture: CHAIN_ACTIVATION_FIXTURE,
    keywords: ["required", "pattern"],
    directProjectionRejection: true,
    patch: {
      operation: "set",
      pointer: "/operation_log_ref",
      value: null,
    },
  },
  {
    id: "chain-operation-log-root-required",
    contractId: "schema://ioi/foundations/autonomous-system-chain/v1",
    fixture: CHAIN_ACTIVATION_FIXTURE,
    keywords: ["required", "pattern"],
    directProjectionRejection: true,
    patch: {
      operation: "set",
      pointer: "/operation_log_root",
      value: null,
    },
  },
  {
    id: "proposal-home-domain-must-be-derived-form",
    contractId: "schema://ioi/foundations/autonomous-system-activation-proposal/v1",
    fixture: "fixtures/autonomous-system-activation-proposal-v1/positive-initialize.json",
    keywords: ["pattern"],
    directProjectionRejection: true,
    patch: {
      operation: "set",
      pointer: "/authority_effect/home_domain_ref",
      value: "agentgres://domain/acme/unrelated",
    },
  },
  {
    id: "chain-home-domain-must-be-derived-form",
    contractId: "schema://ioi/foundations/autonomous-system-chain/v1",
    fixture: CHAIN_ACTIVATION_FIXTURE,
    keywords: ["pattern"],
    directProjectionRejection: true,
    patch: {
      operation: "set",
      pointer: "/home_domain_ref",
      value: "agentgres://domain/acme/unrelated",
    },
  },
  {
    id: "chain-home-domain-binding-must-be-content-addressed",
    contractId: "schema://ioi/foundations/autonomous-system-chain/v1",
    fixture: CHAIN_ACTIVATION_FIXTURE,
    keywords: ["pattern"],
    directProjectionRejection: true,
    patch: {
      operation: "set",
      pointer: "/home_domain_binding_ref",
      value: "system-home-domain-binding://acme/system-alpha/unhashed",
    },
  },
  ...componentLaneSchemeMutationDefinitions,
];

const MUTATION_SCHEMA_REJECTIONS = new Set([
  "lifecycle-transition-receipt-initialize-wrong-sequence",
  "lifecycle-transition-receipt-initialize-missing-source-artifact",
  "lifecycle-transition-receipt-initialize-wrong-scope",
  "lifecycle-transition-receipt-cannot-claim-activation",
  "chain-operation-log-required",
  "chain-operation-log-root-required",
  "proposal-home-domain-must-be-derived-form",
  "chain-home-domain-must-be-derived-form",
  "chain-home-domain-binding-must-be-content-addressed",
  "sequence-zero-receipt-unsupported-signature-suite",
  "sequence-zero-receipt-oversized-principal",
  "sequence-zero-receipt-nested-authority-claim",
  "sequence-zero-receipt-truncated-grant-signature",
  "sequence-zero-receipt-truncated-root-signature",
  "sequence-zero-receipt-embedded-component-kind-ref-substitution",
  "sequence-zero-materialization-broad-receipt-ref",
  "type-number-for-string",
  "required-property-removed",
  "required-nullable-claim-scope-missing",
  "additional-property-injected",
  "referenced-pattern-violated",
  "ecma-whitespace-byte-order-mark-rejected",
  "nullable-any-of-violated",
  "optional-non-nullable-input-hash-null",
  "unicode-aware-min-length-violated",
  "closed-enum-violated-with-raw-string-sentinel",
  "minimum-violated",
  "array-items-schema-violated",
  "deep-unique-items-key-order-duplicate",
  "impossible-rfc3339-calendar-date",
  "closed-const-violated",
  "one-of-violated",
  "maximum-safe-integer-violated",
  "minimum-array-size-violated",
  "type-less-if-then-max-items-violated",
  "nested-all-of-contains-member-missing",
  "type-less-if-else-required-hash-violated",
  "boolean-const-self-authority-violated",
  "genesis-authorized-without-admission-authority-status-evidence",
  "genesis-activated-without-activation-lifecycle-evidence",
  "constitution-active-without-activation-receipt",
  "constitution-draft-with-activation-residue",
  "constitution-draft-with-public-commitment-residue",
  "ordering-active-without-conformance-evidence",
  "ordering-draft-with-conformance-residue",
  "lifecycle-committed-without-terminal-proof-set",
  "lifecycle-proposed-with-decision-residue",
  "manifest-goal-run-profiles-cross-category-ref",
  "manifest-workflow-templates-cross-category-ref",
  "manifest-automation-specs-cross-category-ref",
  "manifest-harness-profiles-cross-category-ref",
  "manifest-agent-harness-adapters-cross-category-ref",
  "manifest-skill-manifests-cross-category-ref",
  "manifest-data-recipes-cross-category-ref",
  "manifest-runtime-tool-contracts-cross-category-ref",
  "manifest-mcp-gateway-requirements-cross-category-ref",
  "genesis-goal-run-profiles-cross-category-ref",
  "genesis-workflow-templates-cross-category-ref",
  "genesis-automation-specs-cross-category-ref",
  "genesis-harness-profiles-cross-category-ref",
  "genesis-agent-harness-adapters-cross-category-ref",
  "genesis-data-recipes-cross-category-ref",
  "genesis-runtime-tool-contracts-cross-category-ref",
]);
const MUTATION_INVARIANT_REJECTIONS = new Map([
  ["lifecycle-transition-receipt-initialize-detached-subject", [
    "lifecycle_transition_receipt.subject.matches_transition",
  ]],
  ["sequence-zero-receipt-grant-suite-mismatch", [
    "sequence_zero_materialization_receipt.grant_suite.matches_snapshot",
    "sequence_zero_materialization_receipt.grant_identity.recomputes",
  ]],
  ["sequence-zero-receipt-authority-suite-mismatch", [
    "sequence_zero_materialization_receipt.grant_suite.matches_snapshot",
    "sequence_zero_materialization_receipt.authority_suite.matches_statement",
    "sequence_zero_materialization_receipt.approval_snapshot_hash.recomputes",
    "sequence_zero_materialization_receipt.authority_id.derives_from_key",
  ]],
  ["sequence-zero-receipt-timestamp-detached", [
    "sequence_zero_materialization_receipt.timestamp.matches_at",
  ]],
  ["sequence-zero-receipt-authorized-materialization-id-detached", [
    "sequence_zero_materialization_receipt.subject.matches_authorized_effect",
    "sequence_zero_materialization_receipt.materialization_facts.match_effect",
    "sequence_zero_materialization_receipt.effect_materialization_id.binds_genesis_root",
    "sequence_zero_materialization_receipt.effect_hash.recomputes",
  ]],
  ["sequence-zero-receipt-authority-principal-detached", [
    "sequence_zero_materialization_receipt.authority.matches_binding",
    "sequence_zero_materialization_receipt.binding_principal.matches_statement",
  ]],
  ["sequence-zero-receipt-grant-authority-detached", [
    "sequence_zero_materialization_receipt.grant_authority.matches_snapshot",
    "sequence_zero_materialization_receipt.grant_identity.recomputes",
  ]],
  ["sequence-zero-receipt-grant-key-detached", [
    "sequence_zero_materialization_receipt.grant_key.matches_snapshot",
    "sequence_zero_materialization_receipt.grant_identity.recomputes",
  ]],
  ["sequence-zero-receipt-effect-receipt-ref-detached", [
    "sequence_zero_materialization_receipt.effect_receipt_ref.matches_receipt",
    "sequence_zero_materialization_receipt.effect_hash.recomputes",
  ]],
  ["sequence-zero-receipt-effect-registry-ref-detached", [
    "sequence_zero_materialization_receipt.materialization_facts.match_effect",
    "sequence_zero_materialization_receipt.effect_registry_ref.binds_registry_root",
    "sequence_zero_materialization_receipt.effect_hash.recomputes",
  ]],
  ["sequence-zero-receipt-policy-hash-self-attestation", [
    "sequence_zero_materialization_receipt.policy_hash.recomputes",
  ]],
  ["sequence-zero-receipt-wallet-consumption-request-detached", [
    "sequence_zero_materialization_receipt.wallet_consumption.binds_request",
    "sequence_zero_materialization_receipt.boundary_fact.exact_coverage",
  ]],
  ["sequence-zero-receipt-coordinates-ref-detached", [
    "sequence_zero_materialization_receipt.coordinates_ref.matches_proof",
  ]],
  ["sequence-zero-receipt-authority-key-statement-detached", [
    "sequence_zero_materialization_receipt.statement_hash.recomputes",
    "sequence_zero_materialization_receipt.binding_hash.recomputes",
    "sequence_zero_materialization_receipt.binding_ref.recomputes",
    "sequence_zero_materialization_receipt.authority_key.matches_statement",
  ]],
  ["sequence-zero-receipt-authority-id-self-attestation", [
    "sequence_zero_materialization_receipt.grant_authority.matches_snapshot",
    "sequence_zero_materialization_receipt.approval_snapshot_hash.recomputes",
    "sequence_zero_materialization_receipt.authority_id.matches_statement",
    "sequence_zero_materialization_receipt.authority_id.derives_from_key",
  ]],
  ["sequence-zero-receipt-issuer-root-id-self-attestation", [
    "sequence_zero_materialization_receipt.statement_hash.recomputes",
    "sequence_zero_materialization_receipt.binding_hash.recomputes",
    "sequence_zero_materialization_receipt.binding_ref.recomputes",
    "sequence_zero_materialization_receipt.issuer_root_id.derives_from_key",
  ]],
  ["sequence-zero-receipt-duplicated-materialization-field-detached", [
    "sequence_zero_materialization_receipt.materialization_facts.match_effect",
  ]],
  ["sequence-zero-receipt-embedded-component-count-detached", [
    "sequence_zero_materialization_receipt.effect_component_count.matches_array",
    "sequence_zero_materialization_receipt.effect_hash.recomputes",
  ]],
  ["sequence-zero-receipt-embedded-component-identity-duplicate", [
    "sequence_zero_materialization_receipt.effect_component_identities.unique",
    "sequence_zero_materialization_receipt.effect_hash.recomputes",
  ]],
  ["sequence-zero-receipt-embedded-deployment-root-detached", [
    "sequence_zero_materialization_receipt.materialization_facts.match_effect",
    "sequence_zero_materialization_receipt.effect_deployment_ref.binds_root",
    "sequence_zero_materialization_receipt.effect_hash.recomputes",
  ]],
  ["sequence-zero-receipt-legacy-deployment-compatibility-root-detached", [
    "sequence_zero_materialization_receipt.materialization_facts.match_effect",
    "sequence_zero_materialization_receipt.effect_deployment_ref.binds_root",
    "sequence_zero_materialization_receipt.effect_hash.recomputes",
  ]],
  ["sequence-zero-receipt-grant-request-detached", [
    "sequence_zero_materialization_receipt.grant_request_hash.recomputes",
    "sequence_zero_materialization_receipt.grant_identity.recomputes",
  ]],
  ["sequence-zero-receipt-consumption-evidence-id-detached", [
    "sequence_zero_materialization_receipt.wallet_consumption.matches_evidence_id",
    "sequence_zero_materialization_receipt.boundary_fact.exact_coverage",
  ]],
  ["sequence-zero-receipt-grant-policy-detached", [
    "sequence_zero_materialization_receipt.grant_policy_hash.recomputes",
    "sequence_zero_materialization_receipt.grant_identity.recomputes",
  ]],
  ["sequence-zero-receipt-effect-hash-self-attestation", [
    "sequence_zero_materialization_receipt.effect_hash.matches_bound_effect",
    "sequence_zero_materialization_receipt.effect_hash.recomputes",
    "sequence_zero_materialization_receipt.request_hash.recomputes",
    "sequence_zero_materialization_receipt.grant_request_hash.recomputes",
  ]],
  ["sequence-zero-receipt-grant-identity-detached", [
    "sequence_zero_materialization_receipt.grant_identity.recomputes",
    "sequence_zero_materialization_receipt.boundary_fact.exact_coverage",
  ]],
  ["sequence-zero-receipt-snapshot-hash-self-attestation", [
    "sequence_zero_materialization_receipt.binding_snapshot.matches_statement",
    "sequence_zero_materialization_receipt.approval_snapshot_hash.recomputes",
  ]],
  ["sequence-zero-receipt-statement-hash-self-attestation", [
    "sequence_zero_materialization_receipt.statement_hash.recomputes",
    "sequence_zero_materialization_receipt.binding_hash.recomputes",
    "sequence_zero_materialization_receipt.binding_ref.recomputes",
  ]],
  ["sequence-zero-receipt-binding-hash-self-attestation", [
    "sequence_zero_materialization_receipt.binding_hash.recomputes",
    "sequence_zero_materialization_receipt.coordinates_hash.matches_proof",
  ]],
  ["sequence-zero-receipt-binding-coordinates-detached", [
    "sequence_zero_materialization_receipt.coordinates_version.matches_statement",
  ]],
  ["sequence-zero-receipt-authority-tuple-detached", [
    "sequence_zero_materialization_receipt.statement_hash.recomputes",
    "sequence_zero_materialization_receipt.binding_hash.recomputes",
    "sequence_zero_materialization_receipt.binding_ref.recomputes",
    "sequence_zero_materialization_receipt.authority_id.matches_statement",
  ]],
  ["sequence-zero-receipt-scope-uncovered", [
    "sequence_zero_materialization_receipt.approval_snapshot_hash.recomputes",
    "sequence_zero_materialization_receipt.scope.covered_by_authority",
  ]],
  ["sequence-zero-receipt-matched-scope-does-not-cover", [
    "sequence_zero_materialization_receipt.scope.required_matches_resolution",
    "sequence_zero_materialization_receipt.scope.covered_by_authority",
  ]],
  ["sequence-zero-receipt-binding-signed-after-resolution", [
    "sequence_zero_materialization_receipt.statement_hash.recomputes",
    "sequence_zero_materialization_receipt.binding_hash.recomputes",
    "sequence_zero_materialization_receipt.binding_ref.recomputes",
    "sequence_zero_materialization_receipt.binding.signed_before_resolution",
  ]],
  ["sequence-zero-receipt-binding-expired-at-resolution", [
    "sequence_zero_materialization_receipt.statement_hash.recomputes",
    "sequence_zero_materialization_receipt.binding_hash.recomputes",
    "sequence_zero_materialization_receipt.binding_ref.recomputes",
    "sequence_zero_materialization_receipt.binding.unexpired_at_resolution",
  ]],
  ["sequence-zero-receipt-authority-expired-at-resolution", [
    "sequence_zero_materialization_receipt.approval_snapshot_hash.recomputes",
    "sequence_zero_materialization_receipt.authority.unexpired_at_resolution",
  ]],
  ["sequence-zero-receipt-grant-expired-at-resolution", [
    "sequence_zero_materialization_receipt.grant_identity.recomputes",
    "sequence_zero_materialization_receipt.grant.unexpired_at_resolution",
  ]],
  ["sequence-zero-receipt-boundary-required-ref-missing", [
    "sequence_zero_materialization_receipt.boundary_fact.exact_coverage",
  ]],
  ["sequence-zero-receipt-boundary-extra-ref-injected", [
    "sequence_zero_materialization_receipt.boundary_fact.exact_coverage",
  ]],
]);
const MUTATION_ACCEPTS = new Set([
  "ecma-non-whitespace-next-line-accepted",
]);

function declaredMutationExpectation(id) {
  if (MUTATION_SCHEMA_REJECTIONS.has(id)) {
    return { schemaAccept: false, contractAccept: false, ruleIds: [] };
  }
  if (MUTATION_INVARIANT_REJECTIONS.has(id)) {
    return {
      schemaAccept: true,
      contractAccept: false,
      ruleIds: MUTATION_INVARIANT_REJECTIONS.get(id),
    };
  }
  if (MUTATION_ACCEPTS.has(id)) {
    return { schemaAccept: true, contractAccept: true, ruleIds: [] };
  }
  throw new Error(`Mutation ${id} has no independent declared expectation`);
}

const declaredMutationIds = new Set([
  ...MUTATION_SCHEMA_REJECTIONS,
  ...MUTATION_INVARIANT_REJECTIONS.keys(),
  ...MUTATION_ACCEPTS,
]);
if (
  declaredMutationIds.size !== mutationDefinitions.length ||
  mutationDefinitions.some(({ id }) => !declaredMutationIds.has(id))
) {
  throw new Error(
    "Architecture mutation expectations do not exactly cover the mutation definitions",
  );
}

const SEQUENCE_ZERO_RECEIPT_CONTRACT_ID =
  "schema://ioi/foundations/autonomous-system-sequence-zero-materialization-receipt/v2";
const SEQUENCE_ZERO_RECEIPT_SCHEMA_ENTAILMENTS = new Map([
  [
    "sequence_zero_materialization_receipt.authority_kind.matches_statement",
    {
      paths: [
        "$.principal_authority_binding.authority_kind",
        "$.principal_authority_binding.binding_proof.statement.authority_kind",
      ],
      domain: ["approval"],
    },
  ],
  [
    "sequence_zero_materialization_receipt.scope.covered_by_receipt",
    {
      paths: [
        { pointer: "$.authority_scopes", arrayItems: true },
        "$.principal_authority_binding.required_scope",
      ],
      domain: ["scope:autonomous_system.genesis_materialize"],
    },
  ],
]);
{
  const contract = contracts.find(
    ({ entry }) => entry.contract_id === SEQUENCE_ZERO_RECEIPT_CONTRACT_ID,
  );
  if (!contract) {
    throw new Error("Sequence-zero receipt contract is absent from the registry");
  }
  const ruleIds = contract.invariants.flatMap((profile) =>
    profile.rules.map((rule) => rule.rule_id)
  );
  if (new Set(ruleIds).size !== ruleIds.length) {
    throw new Error("Sequence-zero receipt invariant rule ids are not unique");
  }
  const coveredRuleIds = new Set([
    ...contract.entry.negative_fixture_refs
      .map((fixture) => fixture.expected_rule_id)
      .filter((ruleId) => typeof ruleId === "string"),
    ...mutationDefinitions
      .filter(
        (definition) =>
          definition.contractId === SEQUENCE_ZERO_RECEIPT_CONTRACT_ID,
      )
      .flatMap(
        (definition) =>
          declaredMutationExpectation(definition.id).ruleIds,
      ),
  ]);
  for (const [ruleId, entailment] of SEQUENCE_ZERO_RECEIPT_SCHEMA_ENTAILMENTS) {
    if (!ruleIds.includes(ruleId)) {
      throw new Error(`Schema entailment names an unknown invariant ${ruleId}`);
    }
    for (const pathSpec of entailment.paths) {
      const pointer = typeof pathSpec === "string"
        ? pathSpec
        : pathSpec.pointer;
      const domain = invariantPathFiniteDomain(contract.schema, pointer, {
        arrayItems:
          typeof pathSpec === "object" && pathSpec.arrayItems === true,
      });
      if (canonicalJson(domain) !== canonicalJson(entailment.domain)) {
        throw new Error(
          `${ruleId}: schema entailment at ${pointer} drifted: ` +
            `expected=${canonicalJson(entailment.domain)} observed=${canonicalJson(domain)}`,
        );
      }
    }
    coveredRuleIds.add(ruleId);
  }
  const unknownCoveredRuleIds = [...coveredRuleIds].filter(
    (ruleId) => !ruleIds.includes(ruleId),
  );
  const uncoveredRuleIds = ruleIds.filter(
    (ruleId) => !coveredRuleIds.has(ruleId),
  );
  if (unknownCoveredRuleIds.length > 0 || uncoveredRuleIds.length > 0) {
    throw new Error(
      "Sequence-zero receipt invariant coverage is not exact: " +
        `unknown=${canonicalJson(unknownCoveredRuleIds)} ` +
        `uncovered=${canonicalJson(uncoveredRuleIds)}`,
    );
  }
}

const generatorAjv = new Ajv2020({
  allErrors: true,
  strict: true,
  validateFormats: true,
});
generatorAjv.addKeyword({
  keyword: "x-ioi-schema-version",
  schemaType: "string",
});
addFormats(generatorAjv);
const generatorAjvValidators = new Map(
  contracts.map(({ entry, schema }) => [
    entry.contract_id,
    generatorAjv.compile(schema),
  ]),
);

function applyMutation(value, patch) {
  const parts = patch.pointer
    .slice(1)
    .split("/")
    .map((part) => part.replaceAll("~1", "/").replaceAll("~0", "~"));
  const name = parts.pop();
  const parent = parts.reduce((current, part) => current?.[part], value);
  if (!isPlainObject(parent) || typeof name !== "string") {
    throw new Error(`Mutation pointer has no object parent: ${patch.pointer}`);
  }
  if (patch.operation === "set") {
    parent[name] = structuredClone(patch.value);
  } else if (patch.operation === "remove") {
    if (!Object.hasOwn(parent, name)) {
      throw new Error(`Mutation pointer does not exist: ${patch.pointer}`);
    }
    delete parent[name];
  } else {
    throw new Error(`Unsupported mutation operation: ${patch.operation}`);
  }
  return value;
}

function generatorValueAtPath(value, pointer) {
  if (typeof pointer !== "string" || !pointer.startsWith("$."))
    return undefined;
  let current = value;
  for (const segment of pointer.slice(2).split(".")) {
    const match = /^([a-z][a-z0-9_]*)(?:\[(0|[1-9][0-9]*)\])?$/u.exec(segment);
    if (match === null || !isPlainObject(current)) return undefined;
    current = current[match[1]];
    if (match[2] !== undefined) {
      if (!Array.isArray(current)) return undefined;
      current = current[Number(match[2])];
    }
  }
  return current;
}

function generatorNonEmpty(value) {
  return (
    (Array.isArray(value) && value.length > 0) ||
    (typeof value === "string" && value.length > 0)
  );
}

function generatorInvariantMaterial(value, expression) {
  if (typeof expression.material_path === "string") {
    return generatorValueAtPath(value, expression.material_path);
  }
  if (!isPlainObject(expression.material_fields)) return undefined;
  const material = Object.create(null);
  for (const [field, descriptor] of Object.entries(
    expression.material_fields,
  )) {
    if (!isPlainObject(descriptor)) return undefined;
    if (typeof descriptor.path === "string") {
      const candidate = generatorValueAtPath(value, descriptor.path);
      if (candidate === undefined) return undefined;
      material[field] = candidate;
    } else if (Object.hasOwn(descriptor, "value")) {
      material[field] = descriptor.value;
    } else {
      return undefined;
    }
  }
  return material;
}

function generatorBytesFromValue(value) {
  return Array.isArray(value) &&
    value.every(
      (byte) =>
        typeof byte === "number" &&
        Number.isInteger(byte) &&
        byte >= 0 &&
        byte <= 255,
    )
    ? Buffer.from(value)
    : null;
}

function generatorDigestMatches(value, expression, digest) {
  const expected = generatorValueAtPath(value, expression.expected_path);
  const hex = digest.toString("hex");
  if (expression.expected_encoding === "bytes32") {
    const expectedBytes = generatorBytesFromValue(expected);
    return expectedBytes !== null && expectedBytes.equals(digest);
  }
  if (expression.expected_encoding === "sha256_string") {
    return expected === `sha256:${hex}`;
  }
  if (
    expression.expected_encoding === "prefixed_ref" &&
    typeof expression.prefix === "string"
  ) {
    return expected === `${expression.prefix}${hex}`;
  }
  return false;
}

function generatorJcsSha256Matches(value, expression) {
  const material = generatorInvariantMaterial(value, expression);
  if (material === undefined) return false;
  let digest = createHash("sha256").update(canonicalJson(material)).digest();
  if (expression.algorithm === "jcs_sha256_then_utf8_sha256") {
    if (typeof expression.intermediate_prefix !== "string") return false;
    digest = createHash("sha256")
      .update(`${expression.intermediate_prefix}${digest.toString("hex")}`)
      .digest();
  } else if (
    expression.algorithm !== undefined &&
    expression.algorithm !== "jcs_sha256"
  ) {
    return false;
  }
  return generatorDigestMatches(value, expression, digest);
}

function generatorSha256PartsMatch(value, expression) {
  if (!Array.isArray(expression.parts)) return false;
  const parts = [];
  for (const part of expression.parts) {
    if (!isPlainObject(part)) return false;
    if (typeof part.utf8 === "string") {
      parts.push(Buffer.from(part.utf8, "utf8"));
    } else if (typeof part.signed_i32_be_path === "string") {
      const integer = generatorValueAtPath(value, part.signed_i32_be_path);
      if (
        typeof integer !== "number" ||
        !Number.isInteger(integer) ||
        integer < -2147483648 ||
        integer > 2147483647
      ) {
        return false;
      }
      const encoded = Buffer.alloc(4);
      encoded.writeInt32BE(integer);
      parts.push(encoded);
    } else if (typeof part.bytes_path === "string") {
      const encoded = generatorBytesFromValue(
        generatorValueAtPath(value, part.bytes_path),
      );
      if (encoded === null) return false;
      parts.push(encoded);
    } else {
      return false;
    }
  }
  const digest = createHash("sha256").update(Buffer.concat(parts)).digest();
  return generatorDigestMatches(value, expression, digest);
}

function generatorExactRefCoverage(value, expression) {
  const actual = generatorValueAtPath(value, expression.array_path);
  if (!Array.isArray(actual) || actual.some((item) => typeof item !== "string"))
    return false;
  const required = [];
  for (const pointer of expression.required_paths ?? []) {
    const candidate = generatorValueAtPath(value, pointer);
    if (candidate === null) continue;
    if (typeof candidate !== "string") return false;
    required.push(candidate);
  }
  for (const pointer of expression.required_array_paths ?? []) {
    const candidates = generatorValueAtPath(value, pointer);
    if (
      !Array.isArray(candidates) ||
      candidates.some((candidate) => typeof candidate !== "string")
    ) {
      return false;
    }
    required.push(...candidates);
  }
  for (const derived of expression.required_derived_refs ?? []) {
    if (
      !isPlainObject(derived) ||
      typeof derived.path !== "string" ||
      typeof derived.prefix !== "string"
    ) {
      return false;
    }
    const candidate = generatorValueAtPath(value, derived.path);
    if (typeof candidate !== "string") return false;
    const suffix =
      typeof derived.strip_prefix === "string"
        ? candidate.startsWith(derived.strip_prefix)
          ? candidate.slice(derived.strip_prefix.length)
          : null
        : candidate;
    if (suffix === null) return false;
    required.push(`${derived.prefix}${suffix}`);
  }
  return (
    actual.length === required.length &&
    canonicalJson([...actual].sort(codePointCompare)) ===
      canonicalJson([...required].sort(codePointCompare))
  );
}

function generatorScopePatternMatches(pattern, value) {
  if (typeof pattern !== "string" || typeof value !== "string") return false;
  const normalizedPattern = pattern.trim().toLowerCase();
  const normalizedValue = value.trim().toLowerCase();
  if (normalizedPattern === "*" || normalizedPattern === normalizedValue)
    return true;
  for (const suffix of ["::*", ":*", "*"]) {
    if (!normalizedPattern.endsWith(suffix)) continue;
    return normalizedValue.startsWith(normalizedPattern.slice(0, -1));
  }
  return false;
}

function generatorInvariantErrors(contract, value) {
  const expectedSchemaHash = schemaHash(contract.schema);
  return contract.invariants.flatMap((profile) =>
    (profile.rules ?? []).flatMap((rule) => {
      const expression = rule.expression ?? {};
      let valid = false;
      if (
        expression.operator === "any_of" &&
        Array.isArray(expression.expressions) &&
        expression.expressions.length > 0
      ) {
        valid =
          expression.expressions.every(isPlainObject) &&
          expression.expressions.some(
            (candidate) =>
              generatorInvariantErrors(
                {
                  ...contract,
                  invariants: [
                    {
                      rules: [{ rule_id: rule.rule_id, expression: candidate }],
                    },
                  ],
                },
                value,
              ).length === 0,
          );
      } else if (expression.operator === "non_empty") {
        valid = generatorNonEmpty(generatorValueAtPath(value, expression.path));
      } else if (
        expression.operator === "any_non_empty" &&
        Array.isArray(expression.paths)
      ) {
        valid = expression.paths.some((pointer) =>
          generatorNonEmpty(generatorValueAtPath(value, pointer)),
        );
      } else if (
        expression.operator === "non_empty_when_in" &&
        Array.isArray(expression.values)
      ) {
        const actual = generatorValueAtPath(value, expression.when_path);
        valid =
          !expression.values.some(
            (expected) => canonicalJson(actual) === canonicalJson(expected),
          ) ||
          generatorNonEmpty(generatorValueAtPath(value, expression.path));
      } else if (
        expression.operator === "fields_equal" &&
        Array.isArray(expression.paths) &&
        expression.paths.length === 2
      ) {
        const left = generatorValueAtPath(value, expression.paths[0]);
        const right = generatorValueAtPath(value, expression.paths[1]);
        valid =
          left !== undefined &&
          right !== undefined &&
          canonicalJson(left) === canonicalJson(right);
      } else if (
        expression.operator === "array_field_equals" &&
        typeof expression.array_path === "string" &&
        typeof expression.field === "string" &&
        typeof expression.expected_path === "string"
      ) {
        const values = generatorValueAtPath(value, expression.array_path);
        const expected = generatorValueAtPath(value, expression.expected_path);
        valid =
          Array.isArray(values) &&
          expected !== undefined &&
          values.every(
            (item) =>
              isPlainObject(item) &&
              canonicalJson(item[expression.field]) === canonicalJson(expected),
          );
      } else if (
        expression.operator === "optional_field_equals" &&
        typeof expression.optional_object_path === "string" &&
        typeof expression.field === "string" &&
        typeof expression.expected_path === "string"
      ) {
        const optional = generatorValueAtPath(
          value,
          expression.optional_object_path,
        );
        const expected = generatorValueAtPath(value, expression.expected_path);
        valid =
          optional === null ||
          (isPlainObject(optional) &&
            expected !== undefined &&
            canonicalJson(optional[expression.field]) ===
              canonicalJson(expected));
      } else if (
        expression.operator === "prefixed_field_equals" &&
        typeof expression.path === "string" &&
        typeof expression.prefix === "string" &&
        typeof expression.expected_path === "string"
      ) {
        const actual = generatorValueAtPath(value, expression.path);
        const expected = generatorValueAtPath(value, expression.expected_path);
        valid =
          typeof actual === "string" &&
          typeof expected === "string" &&
          actual === `${expression.prefix}${expected}`;
      } else if (
        expression.operator === "field_ends_with" &&
        typeof expression.path === "string" &&
        typeof expression.expected_path === "string"
      ) {
        const actual = generatorValueAtPath(value, expression.path);
        const expected = generatorValueAtPath(value, expression.expected_path);
        valid =
          typeof actual === "string" &&
          typeof expected === "string" &&
          expected.length > 0 &&
          actual.endsWith(expected);
      } else if (
        expression.operator === "array_length_equals" &&
        typeof expression.array_path === "string" &&
        typeof expression.count_path === "string"
      ) {
        const values = generatorValueAtPath(value, expression.array_path);
        const count = generatorValueAtPath(value, expression.count_path);
        valid =
          Array.isArray(values) &&
          typeof count === "number" &&
          Number.isSafeInteger(count) &&
          count >= 0 &&
          values.length === count;
      } else if (
        expression.operator === "array_unique_by_fields" &&
        typeof expression.array_path === "string" &&
        Array.isArray(expression.fields) &&
        expression.fields.length > 0
      ) {
        const values = generatorValueAtPath(value, expression.array_path);
        valid =
          Array.isArray(values) &&
          values.every(
            (item, index) =>
              isPlainObject(item) &&
              expression.fields.every((field) =>
                Object.hasOwn(item, field),
              ) &&
              !values.slice(0, index).some(
                (previous) =>
                  isPlainObject(previous) &&
                  expression.fields.every(
                    (field) =>
                      canonicalJson(previous[field]) ===
                      canonicalJson(item[field]),
                  ),
              ),
          );
      } else if (
        expression.operator === "object_fields_equal" &&
        Array.isArray(expression.object_paths) &&
        expression.object_paths.length === 2 &&
        Array.isArray(expression.fields) &&
        expression.fields.length > 0
      ) {
        const left = generatorValueAtPath(value, expression.object_paths[0]);
        const right = generatorValueAtPath(value, expression.object_paths[1]);
        valid =
          isPlainObject(left) &&
          isPlainObject(right) &&
          expression.fields.every(
            (field) =>
              typeof field === "string" &&
              Object.hasOwn(left, field) &&
              Object.hasOwn(right, field) &&
              canonicalJson(left[field]) === canonicalJson(right[field]),
          );
      } else if (expression.operator === "jcs_sha256_equals") {
        valid = generatorJcsSha256Matches(value, expression);
      } else if (expression.operator === "sha256_parts_equals") {
        valid = generatorSha256PartsMatch(value, expression);
      } else if (
        expression.operator === "array_contains_value" &&
        typeof expression.array_path === "string" &&
        typeof expression.expected_path === "string"
      ) {
        const values = generatorValueAtPath(value, expression.array_path);
        const expected = generatorValueAtPath(value, expression.expected_path);
        valid =
          Array.isArray(values) &&
          expected !== undefined &&
          values.some(
            (candidate) => canonicalJson(candidate) === canonicalJson(expected),
          );
      } else if (expression.operator === "array_exact_ref_coverage") {
        valid = generatorExactRefCoverage(value, expression);
      } else if (
        expression.operator === "scope_pattern_matches" &&
        typeof expression.pattern_path === "string" &&
        typeof expression.value_path === "string"
      ) {
        valid = generatorScopePatternMatches(
          generatorValueAtPath(value, expression.pattern_path),
          generatorValueAtPath(value, expression.value_path),
        );
      } else if (
        expression.operator === "field_starts_with_path" &&
        typeof expression.path === "string" &&
        typeof expression.expected_path === "string" &&
        typeof expression.prefix === "string"
      ) {
        const actual = generatorValueAtPath(value, expression.path);
        const expected = generatorValueAtPath(value, expression.expected_path);
        const stripped =
          typeof expected === "string" &&
          typeof expression.strip_prefix === "string"
            ? expected.startsWith(expression.strip_prefix)
              ? expected.slice(expression.strip_prefix.length)
              : null
            : expected;
        valid =
          typeof actual === "string" &&
          typeof stripped === "string" &&
          actual.startsWith(
            `${expression.prefix}${stripped}${expression.suffix ?? ""}`,
          );
      } else if (
        expression.operator === "field_suffix_equals_prefixed_field" &&
        typeof expression.source_path === "string" &&
        typeof expression.delimiter === "string" &&
        expression.delimiter.length > 0 &&
        typeof expression.target_path === "string" &&
        typeof expression.target_prefix === "string"
      ) {
        const source = generatorValueAtPath(value, expression.source_path);
        const target = generatorValueAtPath(value, expression.target_path);
        const delimiterIndex =
          typeof source === "string"
            ? source.lastIndexOf(expression.delimiter)
            : -1;
        const suffix =
          typeof source === "string" && delimiterIndex >= 0
            ? source.slice(delimiterIndex + expression.delimiter.length)
            : "";
        valid =
          suffix.length > 0 &&
          typeof target === "string" &&
          target === `${expression.target_prefix}${suffix}`;
      } else if (expression.operator === "matches_contract_schema_hash") {
        valid =
          generatorValueAtPath(value, expression.path) === expectedSchemaHash;
      } else if (
        ["numbers_lte", "numbers_lt"].includes(expression.operator) &&
        Array.isArray(expression.paths) &&
        expression.paths.length === 2
      ) {
        const left = generatorValueAtPath(value, expression.paths[0]);
        const right = generatorValueAtPath(value, expression.paths[1]);
        valid =
          typeof left === "number" &&
          typeof right === "number" &&
          (expression.operator === "numbers_lte"
            ? left <= right
            : left < right);
      } else {
        throw new Error(
          `${profile.$id}: unsupported invariant operator ${expression.operator}`,
        );
      }
      return valid ? [] : [rule.rule_id];
    }),
  );
}

function mutationValue(definition) {
  const fixturePath = safeSchemaPath(
    definition.fixture,
    `mutation ${definition.id}: source fixture`,
  );
  const sourceValue = readJson(fixturePath);
  const patch = definition.patch ?? definition.buildPatch?.(sourceValue);
  if (
    !isPlainObject(patch) ||
    !["set", "remove"].includes(patch.operation) ||
    typeof patch.pointer !== "string" ||
    !patch.pointer.startsWith("/") ||
    (patch.operation === "set" && !Object.hasOwn(patch, "value"))
  ) {
    throw new Error(`Invalid mutation patch ${definition.id}`);
  }
  return {
    patch,
    value: applyMutation(structuredClone(sourceValue), patch),
  };
}

function mutationCorpus() {
  return mutationDefinitions.map((definition) => {
    const { patch, value } = mutationValue(definition);
    const validate = generatorAjvValidators.get(definition.contractId);
    if (!validate) {
      throw new Error(`Mutation ${definition.id} names an unknown contract`);
    }
    const expectation = declaredMutationExpectation(definition.id);
    const observedSchemaAccept = Boolean(validate(value));
    const evaluatedRuleIds = generatorInvariantErrors(
      contracts.find(
        (contract) =>
          contract.entry.contract_id === definition.contractId,
      ),
      value,
    );
    const observedRuleIds = observedSchemaAccept ? evaluatedRuleIds : [];
    const observedContractAccept =
      observedSchemaAccept && observedRuleIds.length === 0;
    if (
      observedSchemaAccept !== expectation.schemaAccept ||
      observedContractAccept !== expectation.contractAccept ||
      canonicalJson([...observedRuleIds].sort(codePointCompare)) !==
        canonicalJson([...expectation.ruleIds].sort(codePointCompare))
    ) {
      throw new Error(
        `Mutation ${definition.id} differs from its independent declared expectation: ` +
          `expected=${canonicalJson(expectation)} observed=${canonicalJson({
            schemaAccept: observedSchemaAccept,
            contractAccept: observedContractAccept,
            ruleIds: observedRuleIds,
          })}`,
      );
    }
    return {
      id: definition.id,
      contract_id: definition.contractId,
      source_fixture_path: `docs/architecture/_meta/schemas/${definition.fixture}`,
      covered_keywords: definition.keywords,
      ajv_expected_accept: expectation.schemaAccept,
      oracle_contract_accept: expectation.contractAccept,
      expected_rule_ids: expectation.ruleIds,
      direct_projection_rejection:
        definition.directProjectionRejection === true,
      patch,
    };
  });
}

function replaceOnce(text, search, replacement, at) {
  const first = text.indexOf(search);
  if (first === -1 || text.indexOf(search, first + search.length) !== -1) {
    throw new Error(`${at}: expected exactly one ${JSON.stringify(search)}`);
  }
  return `${text.slice(0, first)}${replacement}${text.slice(first + search.length)}`;
}

function differentialCorpus() {
  const cases = fixtureMetadata().map((fixture) => ({
    id: `fixture:${fixture.path}`,
    contract_id: fixture.contract_id,
    source_fixture_path: fixture.path,
    mutation_id: null,
    value_json: null,
    value: readJson(
      safeRepositoryPath({
        root,
        relativePath: fixture.path,
        at: `differential ${fixture.path}`,
        mustExist: true,
      }),
    ),
  }));
  for (const definition of mutationDefinitions) {
    const { value } = mutationValue(definition);
    cases.push({
      id: `mutation:${definition.id}`,
      contract_id: definition.contractId,
      source_fixture_path: null,
      mutation_id: definition.id,
      value_json: null,
      value,
    });
  }

  const authorityTimestampPath = safeSchemaPath(
    "fixtures/authority-grant-envelope-v2/positive-root.json",
    "authority timestamp differential fixture",
  );
  const authorityTimestamp = fs.readFileSync(authorityTimestampPath, "utf8");
  cases.push({
    id: "differential:authority-timestamp-integral-decimal",
    contract_id: "schema://ioi/foundations/authority-grant-envelope/v2",
    source_fixture_path: null,
    mutation_id: null,
    value_json: replaceOnce(
      authorityTimestamp,
      '"issued_at": 1784203200',
      '"issued_at": 1784203200.0',
      "authority timestamp differential",
    ),
  });

  const authorityV1Path = safeSchemaPath(
    "fixtures/authority-grant-envelope-v1/positive-active.json",
    "portable integer differential fixture",
  );
  const authorityV1 = fs.readFileSync(authorityV1Path, "utf8");
  for (const [id, rendered] of [
    ["portable-integer-boundary", "9007199254740991"],
    ["portable-integer-over-bound", "9007199254740992"],
    ["portable-integer-over-u64", "18446744073709551616"],
    ["portable-integer-negative", "-1"],
    ["portable-integer-integral-decimal", "1.0"],
  ]) {
    cases.push({
      id: `differential:${id}`,
      contract_id: "schema://ioi/foundations/authority-grant-envelope/v1",
      source_fixture_path: null,
      mutation_id: null,
      value_json: replaceOnce(
        authorityV1,
        '"revocation_epoch": 7',
        `"revocation_epoch": ${rendered}`,
        `${id} differential`,
      ),
    });
  }

  const proofIndexPath = safeSchemaPath(
    "fixtures/receipt-proof-bundle-v1/positive-offline.json",
    "proof-index differential fixture",
  );
  const proofIndex = fs.readFileSync(proofIndexPath, "utf8");
  cases.push({
    id: "differential:proof-index-integral-decimal-equality",
    contract_id: "schema://ioi/foundations/receipt-proof-bundle/v1",
    source_fixture_path: null,
    mutation_id: null,
    value_json: replaceOnce(
      proofIndex,
      '    "leaf_index": 1,\n    "leaf_hash"',
      '    "leaf_index": 1.0,\n    "leaf_hash"',
      "proof-index differential",
    ),
  });

  const leapSecondFixture = readJson(
    safeSchemaPath(
      "fixtures/authority-grant-envelope-v1/positive-active.json",
      "date-time profile differential fixture",
    ),
  );
  for (const [id, dateTime] of [
    ["canonical-leap-second-z", "2025-01-01T23:59:60Z"],
    ["canonical-leap-second-offset", "2025-01-02T00:59:60+01:00"],
    ["noncanonical-space-separator", "2025-01-01 23:59:59Z"],
    ["noncanonical-compact-offset", "2025-01-01T23:59:59+0100"],
    ["noncanonical-hour-offset", "2025-01-01T23:59:59+01"],
    ["noncanonical-hour-24-leap", "2025-01-01T24:59:60+01:00"],
    ["noncanonical-minute-60-leap", "2025-01-01T23:60:60+00:01"],
  ]) {
    const value = structuredClone(leapSecondFixture);
    value.constraints.expires_at = dateTime;
    cases.push({
      id: `differential:${id}`,
      contract_id: "schema://ioi/foundations/authority-grant-envelope/v1",
      source_fixture_path: null,
      mutation_id: null,
      value_json: JSON.stringify(value),
    });
  }

  const objectEqualityFixture = readJson(
    safeSchemaPath(
      "fixtures/autonomous-system-sequence-zero-materialization-receipt-v2/positive-materialized-pending-activation.json",
      "object-valued invariant differential fixture",
    ),
  );
  const profileRefs =
    objectEqualityFixture.authorized_effect.materialization.profile_refs;
  objectEqualityFixture.authorized_effect.materialization.profile_refs =
    Object.fromEntries(Object.entries(profileRefs).reverse());
  cases.push({
    id: "differential:object-valued-invariant-key-order",
    contract_id: SEQUENCE_ZERO_RECEIPT_CONTRACT_ID,
    source_fixture_path: null,
    mutation_id: null,
    value_json: JSON.stringify(objectEqualityFixture),
  });

  const contractsById = new Map(
    contracts.map((contract) => [contract.entry.contract_id, contract]),
  );
  return cases.map((candidate) => {
    const contract = contractsById.get(candidate.contract_id);
    const validate = generatorAjvValidators.get(candidate.contract_id);
    if (!contract || !validate) {
      throw new Error(
        `Differential case ${candidate.id} names an unknown contract`,
      );
    }
    const value = candidate.value ?? JSON.parse(candidate.value_json);
    const ajvSchemaAccept = Boolean(validate(value));
    const declaredMutation = candidate.mutation_id === null
      ? null
      : declaredMutationExpectation(candidate.mutation_id);
    if (
      declaredMutation !== null &&
      (
        ajvSchemaAccept !== declaredMutation.schemaAccept ||
        (
          ajvSchemaAccept &&
          generatorInvariantErrors(contract, value).length === 0
        ) !== declaredMutation.contractAccept
      )
    ) {
      throw new Error(
        `Differential mutation ${candidate.mutation_id} differs from its declared expectation`,
      );
    }
    const { value: _value, ...serializable } = candidate;
    return {
      ...serializable,
      ajv_schema_accept:
        declaredMutation?.schemaAccept ?? ajvSchemaAccept,
      oracle_contract_accept:
        declaredMutation?.contractAccept ??
        (
          ajvSchemaAccept &&
          generatorInvariantErrors(contract, value).length === 0
        ),
    };
  });
}

const usedSchemaKeywords = new Set();
for (const { entry, schema } of contracts) {
  for (const keyword of inventorySchemaKeywords(
    schema,
    `schema:${entry.contract_id}`,
  )) {
    usedSchemaKeywords.add(keyword);
  }
}
const mutationCoveredKeywords = new Set(
  mutationDefinitions.flatMap((definition) => definition.keywords),
);
const uncoveredMutationKeywords = [...usedSchemaKeywords].filter(
  (keyword) => !mutationCoveredKeywords.has(keyword),
);
if (uncoveredMutationKeywords.length > 0) {
  throw new Error(
    `Architecture contract mutation corpus does not cover used semantic keywords: ${uncoveredMutationKeywords.sort(codePointCompare).join(", ")}`,
  );
}
const staleMutationKeywords = [...mutationCoveredKeywords].filter(
  (keyword) => !usedSchemaKeywords.has(keyword),
);
if (staleMutationKeywords.length > 0) {
  throw new Error(
    `Architecture contract mutation corpus claims unused semantic keywords: ${staleMutationKeywords.sort(codePointCompare).join(", ")}`,
  );
}

function renderTypescript() {
  const interfaces = contracts
    .map(
      ({ entry, schema }) =>
        `export type ${projectionSymbol(entry)} = ${tsType(schema, schema)};`,
    )
    .join("\n\n");
  const schemas = Object.fromEntries(
    contracts.map(({ entry, schema }) => [entry.contract_id, schema]),
  );
  const invariants = Object.fromEntries(
    contracts.map(({ entry, invariants: values }) => [
      entry.contract_id,
      values.flatMap((profile) => profile.rules),
    ]),
  );
  const schemaHashes = Object.fromEntries(
    contracts.map(({ entry, schema }) => [
      entry.contract_id,
      schemaHash(schema),
    ]),
  );
  const mutations = mutationCorpus();
  const differentialCases = differentialCorpus().map((candidate) => ({
    id: candidate.id,
    contract_id: candidate.contract_id,
    source_fixture_path: candidate.source_fixture_path,
    mutation_id: candidate.mutation_id,
    value_json: candidate.value_json,
  }));
  const jcsDifferentialCases = JCS_DIFFERENTIAL_CASES.map(
    ({ id, value_json, expected_canonical }) => ({
      id,
      value_json,
      expected_canonical,
    }),
  );
  const wrappers = contracts
    .map(
      ({ entry }) => `export function validate${projectionSymbol(entry)}(
  value: unknown,
): value is ${projectionSymbol(entry)} {
  return validateArchitectureContract(${JSON.stringify(entry.contract_id)}, value).ok;
}`,
    )
    .join("\n\n");

  return `// Generated by scripts/generate-architecture-contracts.mjs. Do not edit.

${interfaces}

export const ARCHITECTURE_CONTRACT_REGISTRY_VERSION = ${JSON.stringify(registry.registry_version)} as const;

export const ARCHITECTURE_CONTRACT_PORTABLE_INTEGER_MINIMUM = ${PORTABLE_INTEGER_MINIMUM} as const;
export const ARCHITECTURE_CONTRACT_PORTABLE_INTEGER_MAXIMUM = ${PORTABLE_INTEGER_MAXIMUM} as const;
export const ARCHITECTURE_CONTRACT_PORTABLE_SIGNED_INTEGER_MINIMUM = ${PORTABLE_SIGNED_INTEGER_MINIMUM} as const;
export const ARCHITECTURE_CONTRACT_PORTABLE_SIGNED_INTEGER_MAXIMUM = ${PORTABLE_INTEGER_MAXIMUM} as const;
export const ARCHITECTURE_CONTRACT_PORTABLE_DATE_TIME_PATTERN = ${JSON.stringify(PORTABLE_CANONICAL_DATE_TIME_PATTERN)} as const;
export const ARCHITECTURE_CONTRACT_ORACLE_PROFILE = "ajv-2020-12-plus-portable-invariants-and-canonical-rfc3339" as const;

export const ARCHITECTURE_CONTRACT_FIXTURES = ${JSON.stringify(fixtureMetadata(), null, 2)} as const;

export type ArchitectureContractMutation = {
  id: string;
  contract_id: string;
  source_fixture_path: string;
  covered_keywords: string[];
  ajv_expected_accept: boolean;
  oracle_contract_accept: boolean;
  expected_rule_ids: string[];
  direct_projection_rejection: boolean;
  patch: {
    operation: "set" | "remove";
    pointer: string;
    value?: unknown;
  };
};

export const ARCHITECTURE_CONTRACT_MUTATIONS: ReadonlyArray<ArchitectureContractMutation> = ${JSON.stringify(mutations, null, 2)};

export type ArchitectureContractDifferentialCase = {
  id: string;
  contract_id: string;
  source_fixture_path: string | null;
  mutation_id: string | null;
  value_json: string | null;
};

export const ARCHITECTURE_CONTRACT_DIFFERENTIAL_CASES: ReadonlyArray<ArchitectureContractDifferentialCase> = ${JSON.stringify(differentialCases, null, 2)};

export type ArchitectureContractJcsDifferentialCase = {
  id: string;
  value_json: string;
  expected_canonical: string;
};

export const ARCHITECTURE_CONTRACT_JCS_DIFFERENTIAL_CASES: ReadonlyArray<ArchitectureContractJcsDifferentialCase> = ${JSON.stringify(jcsDifferentialCases, null, 2)};

export const ARCHITECTURE_CONTRACT_ASSERTION_KEYWORDS = ${JSON.stringify([...usedSchemaKeywords].sort(codePointCompare), null, 2)} as const;

export const ARCHITECTURE_CONTRACT_PATTERN_SOURCES = ${JSON.stringify([...registeredPatternTranslations.keys()].sort(codePointCompare), null, 2)} as const;

export const ARCHITECTURE_CONTRACT_SCHEMA_HASHES = ${JSON.stringify(schemaHashes, null, 2)} as const;

type JsonObject = Record<string, unknown>;
type ValidationResult = { ok: boolean; errors: string[] };

const CONTRACT_SCHEMAS: Record<string, JsonObject> = ${JSON.stringify(schemas, null, 2)};
const CONTRACT_INVARIANTS: Record<string, Array<JsonObject>> = ${JSON.stringify(invariants, null, 2)};

export function architectureContractSchemaHash(contractId: string): string | null {
  return (ARCHITECTURE_CONTRACT_SCHEMA_HASHES as Record<string, string>)[contractId] ?? null;
}

export function architectureContractSchemaDocument(contractId: string): JsonObject | null {
  return CONTRACT_SCHEMAS[contractId] ?? null;
}

function isObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function jsonSchemaEqual(left: unknown, right: unknown): boolean {
  if (Object.is(left, right)) return true;
  if (typeof left === "number" && typeof right === "number") {
    return left === right;
  }
  if (Array.isArray(left) && Array.isArray(right)) {
    return (
      left.length === right.length &&
      left.every((value, index) => jsonSchemaEqual(value, right[index]))
    );
  }
  if (isObject(left) && isObject(right)) {
    const leftKeys = Object.keys(left);
    const rightKeys = Object.keys(right);
    return (
      leftKeys.length === rightKeys.length &&
      leftKeys.every(
        (key) =>
          Object.prototype.hasOwnProperty.call(right, key) &&
          jsonSchemaEqual(left[key], right[key]),
      )
    );
  }
  return false;
}

function isLeapYear(year: number): boolean {
  return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
}

function isRfc3339DateTime(value: string): boolean {
  const match = /^(\\d{4})-(\\d{2})-(\\d{2})[Tt](\\d{2}):(\\d{2}):(\\d{2}(?:\\.\\d+)?)(Z|z|([+-])(\\d{2}):(\\d{2}))$/u.exec(
    value,
  );
  if (!match) return false;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  const zoneSign = match[8] === "-" ? -1 : 1;
  const zoneHour = Number(match[9] ?? 0);
  const zoneMinute = Number(match[10] ?? 0);
  const monthDays = [
    0,
    31,
    isLeapYear(year) ? 29 : 28,
    31,
    30,
    31,
    30,
    31,
    31,
    30,
    31,
    30,
    31,
  ];
  if (
    month < 1 ||
    month > 12 ||
    day < 1 ||
    day > monthDays[month] ||
    zoneHour > 23 ||
    zoneMinute > 59
  ) {
    return false;
  }
  if (hour <= 23 && minute <= 59 && second < 60) return true;
  const utcMinute = minute - zoneMinute * zoneSign;
  const utcHour =
    hour - zoneHour * zoneSign - (utcMinute < 0 ? 1 : 0);
  return (
    (utcHour === 23 || utcHour === -1) &&
    (utcMinute === 59 || utcMinute === -1) &&
    second < 61
  );
}

function resolveRef(root: JsonObject, ref: string): JsonObject | null {
  if (!ref.startsWith("#/")) return null;
  let value: unknown = root;
  for (const encoded of ref.slice(2).split("/")) {
    const key = encoded.replace(/~1/g, "/").replace(/~0/g, "~");
    if (!isObject(value) || !(key in value)) return null;
    value = value[key];
  }
  return isObject(value) ? value : null;
}

function schemaMatches(root: JsonObject, schema: JsonObject, value: unknown, at: string): string[] {
  if (typeof schema.$ref === "string") {
    const resolved = resolveRef(root, schema.$ref);
    if (!resolved) return [at + ": unresolved $ref"];
    const errors = schemaMatches(root, resolved, value, at);
    if (errors.length > 0) return errors;
  }
  if (Array.isArray(schema.allOf)) {
    for (const branch of schema.allOf) {
      if (isObject(branch)) {
        const errors = schemaMatches(root, branch, value, at);
        if (errors.length > 0) return errors;
      }
    }
  }
  if (isObject(schema["if"])) {
    const conditionMatches = schemaMatches(root, schema["if"], value, at).length === 0;
    const selected = conditionMatches ? schema.then : schema.else;
    if (isObject(selected)) {
      const errors = schemaMatches(root, selected, value, at);
      if (errors.length > 0) return errors;
    }
  }
  for (const keyword of ["oneOf", "anyOf"] as const) {
    const branches = schema[keyword];
    if (Array.isArray(branches)) {
      const matches = branches.filter(
        (branch) => isObject(branch) && schemaMatches(root, branch, value, at).length === 0,
      ).length;
      const valid = keyword === "oneOf" ? matches === 1 : matches > 0;
      if (!valid) return [at + ": failed " + keyword];
    }
  }
  if (Array.isArray(schema.enum) && !schema.enum.some((candidate) => jsonSchemaEqual(candidate, value))) {
    return [at + ": value is outside enum"];
  }
  if ("const" in schema && !jsonSchemaEqual(schema.const, value)) {
    return [at + ": value does not match const"];
  }
  const type = schema.type;
  if (type === "null" && value !== null) return [at + ": expected null"];
  if (type === "string" && typeof value !== "string") return [at + ": expected string"];
  if (
    (type === "number" || type === "integer") &&
    (typeof value !== "number" || !Number.isFinite(value))
  ) {
    return [at + ": expected number"];
  }
  if (type === "integer" && !Number.isInteger(value)) {
    return [at + ": expected integer"];
  }
  if (type === "boolean" && typeof value !== "boolean") return [at + ": expected boolean"];
  if (type === "array" && !Array.isArray(value)) return [at + ": expected array"];
  if (type === "object" && !isObject(value)) return [at + ": expected object"];
  if (typeof value === "string") {
    if (typeof schema.minLength === "number" && [...value].length < schema.minLength) {
      return [at + ": string shorter than minLength"];
    }
    if (typeof schema.maxLength === "number" && [...value].length > schema.maxLength) {
      return [at + ": string longer than maxLength"];
    }
    if (typeof schema.pattern === "string" && !new RegExp(schema.pattern, "u").test(value)) {
      return [at + ": string failed pattern"];
    }
    if (schema.format === "date-time") {
      if (!isRfc3339DateTime(value)) {
        return [at + ": invalid date-time"];
      }
    }
  }
  if (typeof value === "number" && Number.isFinite(value)) {
    if (typeof schema.minimum === "number" && value < schema.minimum) {
      return [at + ": number below minimum"];
    }
    if (typeof schema.maximum === "number" && value > schema.maximum) {
      return [at + ": number above maximum"];
    }
  }
  if (Array.isArray(value)) {
    if (typeof schema.minItems === "number" && value.length < schema.minItems) {
      return [at + ": array shorter than minItems"];
    }
    if (typeof schema.maxItems === "number" && value.length > schema.maxItems) {
      return [at + ": array longer than maxItems"];
    }
    if (schema.uniqueItems === true) {
      for (let index = 0; index < value.length; index += 1) {
        for (let previous = 0; previous < index; previous += 1) {
          if (jsonSchemaEqual(value[previous], value[index])) {
            return [at + ": array items are not unique"];
          }
        }
      }
    }
    if (isObject(schema.items)) {
      for (let index = 0; index < value.length; index += 1) {
        const errors = schemaMatches(
          root,
          schema.items as JsonObject,
          value[index],
          at + "[" + index + "]",
        );
        if (errors.length > 0) return errors;
      }
    }
    if (isObject(schema.contains)) {
      let containsMatch = false;
      for (let index = 0; index < value.length; index += 1) {
        if (
          schemaMatches(
            root,
            schema.contains as JsonObject,
            value[index],
            at + "[" + index + "]",
          ).length === 0
        ) {
          containsMatch = true;
          break;
        }
      }
      if (!containsMatch) return [at + ": array has no item matching contains"];
    }
  }
  if (isObject(value)) {
    const properties = isObject(schema.properties) ? schema.properties : {};
    const required = Array.isArray(schema.required) ? schema.required : [];
    const missing = required.filter((name) => typeof name === "string" && !(name in value));
    if (missing.length > 0) return [at + ": missing " + missing.join(", ")];
    if (schema.additionalProperties === false) {
      const unknown: string[] = [];
      for (const name in value) {
        if (!Object.prototype.hasOwnProperty.call(properties, name)) unknown.push(name);
      }
      if (unknown.length > 0) return [at + ": unknown " + unknown.join(", ")];
    }
    for (const [name, propertySchema] of Object.entries(properties)) {
      if (name in value && isObject(propertySchema)) {
        const errors = schemaMatches(root, propertySchema, value[name], at + "." + name);
        if (errors.length > 0) return errors;
      }
    }
  }
  return [];
}

function valueAtPath(value: unknown, path: unknown): unknown {
  if (typeof path !== "string" || !path.startsWith("$.")) return undefined;
  let current: unknown = value;
  for (const segment of path.slice(2).split(".")) {
    const match = /^([a-z][a-z0-9_]*)(?:\\[(0|[1-9][0-9]*)\\])?$/u.exec(segment);
    if (match === null || !isObject(current)) return undefined;
    current = current[match[1]];
    if (match[2] !== undefined) {
      if (!Array.isArray(current)) return undefined;
      current = current[Number(match[2])];
    }
  }
  return current;
}

function canonicalJsonForHash(value: unknown): string {
  if (value === null || typeof value !== "object") {
    const encoded = JSON.stringify(value);
    return encoded === undefined ? "" : encoded;
  }
  if (Array.isArray(value)) {
    return "[" + value.map(canonicalJsonForHash).join(",") + "]";
  }
  const object = value as JsonObject;
  return (
    "{" +
    Object.keys(object)
      .sort()
      .map((key) => JSON.stringify(key) + ":" + canonicalJsonForHash(object[key]))
      .join(",") +
    "}"
  );
}

const SHA256_ROUND_CONSTANTS = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

function rotateRight(value: number, amount: number): number {
  return (value >>> amount) | (value << (32 - amount));
}

function sha256Bytes(input: Uint8Array): Uint8Array {
  const bitLength = input.length * 8;
  const paddedLength = Math.ceil((input.length + 9) / 64) * 64;
  const message = new Uint8Array(paddedLength);
  message.set(input);
  message[input.length] = 0x80;
  const messageView = new DataView(message.buffer);
  messageView.setUint32(paddedLength - 8, Math.floor(bitLength / 0x100000000));
  messageView.setUint32(paddedLength - 4, bitLength >>> 0);

  const state = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ]);
  const words = new Uint32Array(64);
  for (let offset = 0; offset < message.length; offset += 64) {
    for (let index = 0; index < 16; index += 1) {
      words[index] = messageView.getUint32(offset + index * 4);
    }
    for (let index = 16; index < 64; index += 1) {
      const left =
        rotateRight(words[index - 15], 7) ^
        rotateRight(words[index - 15], 18) ^
        (words[index - 15] >>> 3);
      const right =
        rotateRight(words[index - 2], 17) ^
        rotateRight(words[index - 2], 19) ^
        (words[index - 2] >>> 10);
      words[index] =
        (words[index - 16] + left + words[index - 7] + right) >>> 0;
    }
    let [a, b, c, d, e, f, g, h] = state;
    for (let index = 0; index < 64; index += 1) {
      const upper =
        rotateRight(e, 6) ^ rotateRight(e, 11) ^ rotateRight(e, 25);
      const choose = (e & f) ^ (~e & g);
      const first =
        (h + upper + choose + SHA256_ROUND_CONSTANTS[index] + words[index]) >>>
        0;
      const lower =
        rotateRight(a, 2) ^ rotateRight(a, 13) ^ rotateRight(a, 22);
      const majority = (a & b) ^ (a & c) ^ (b & c);
      const second = (lower + majority) >>> 0;
      h = g;
      g = f;
      f = e;
      e = (d + first) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (first + second) >>> 0;
    }
    state[0] = (state[0] + a) >>> 0;
    state[1] = (state[1] + b) >>> 0;
    state[2] = (state[2] + c) >>> 0;
    state[3] = (state[3] + d) >>> 0;
    state[4] = (state[4] + e) >>> 0;
    state[5] = (state[5] + f) >>> 0;
    state[6] = (state[6] + g) >>> 0;
    state[7] = (state[7] + h) >>> 0;
  }
  const digest = new Uint8Array(32);
  const digestView = new DataView(digest.buffer);
  state.forEach((word, index) => digestView.setUint32(index * 4, word));
  return digest;
}

function bytesFromValue(value: unknown): Uint8Array | null {
  return Array.isArray(value) &&
    value.every(
      (byte) =>
        typeof byte === "number" &&
        Number.isInteger(byte) &&
        byte >= 0 &&
        byte <= 255,
    )
    ? Uint8Array.from(value)
    : null;
}

function digestHex(digest: Uint8Array): string {
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function invariantMaterial(value: unknown, expression: JsonObject): unknown {
  if (typeof expression.material_path === "string") {
    return valueAtPath(value, expression.material_path);
  }
  if (!isObject(expression.material_fields)) return undefined;
  const material: JsonObject = Object.create(null);
  for (const [field, descriptor] of Object.entries(expression.material_fields)) {
    if (!isObject(descriptor)) return undefined;
    if (typeof descriptor.path === "string") {
      const candidate = valueAtPath(value, descriptor.path);
      if (candidate === undefined) return undefined;
      material[field] = candidate;
    } else if (Object.prototype.hasOwnProperty.call(descriptor, "value")) {
      material[field] = descriptor.value;
    } else {
      return undefined;
    }
  }
  return material;
}

function digestMatchesExpression(
  value: unknown,
  expression: JsonObject,
  digest: Uint8Array,
): boolean {
  const expected = valueAtPath(value, expression.expected_path);
  const hex = digestHex(digest);
  if (expression.expected_encoding === "bytes32") {
    const expectedBytes = bytesFromValue(expected);
    return (
      expectedBytes !== null &&
      expectedBytes.every((byte, index) => byte === digest[index])
    );
  }
  if (expression.expected_encoding === "sha256_string") {
    return expected === "sha256:" + hex;
  }
  return (
    expression.expected_encoding === "prefixed_ref" &&
    typeof expression.prefix === "string" &&
    expected === expression.prefix + hex
  );
}

function jcsSha256Matches(value: unknown, expression: JsonObject): boolean {
  const material = invariantMaterial(value, expression);
  if (material === undefined) return false;
  const encoder = new TextEncoder();
  let digest = sha256Bytes(encoder.encode(canonicalJsonForHash(material)));
  if (expression.algorithm === "jcs_sha256_then_utf8_sha256") {
    if (typeof expression.intermediate_prefix !== "string") return false;
    digest = sha256Bytes(
      encoder.encode(expression.intermediate_prefix + digestHex(digest)),
    );
  } else if (
    expression.algorithm !== undefined &&
    expression.algorithm !== "jcs_sha256"
  ) {
    return false;
  }
  return digestMatchesExpression(value, expression, digest);
}

function sha256PartsMatch(value: unknown, expression: JsonObject): boolean {
  if (!Array.isArray(expression.parts)) return false;
  const encodedParts: Uint8Array[] = [];
  for (const part of expression.parts) {
    if (!isObject(part)) return false;
    if (typeof part.utf8 === "string") {
      encodedParts.push(new TextEncoder().encode(part.utf8));
    } else if (typeof part.signed_i32_be_path === "string") {
      const integer = valueAtPath(value, part.signed_i32_be_path);
      if (
        typeof integer !== "number" ||
        !Number.isInteger(integer) ||
        integer < -2147483648 ||
        integer > 2147483647
      ) {
        return false;
      }
      const encoded = new Uint8Array(4);
      new DataView(encoded.buffer).setInt32(0, integer);
      encodedParts.push(encoded);
    } else if (typeof part.bytes_path === "string") {
      const encoded = bytesFromValue(valueAtPath(value, part.bytes_path));
      if (encoded === null) return false;
      encodedParts.push(encoded);
    } else {
      return false;
    }
  }
  const input = new Uint8Array(
    encodedParts.reduce((length, part) => length + part.length, 0),
  );
  let offset = 0;
  for (const part of encodedParts) {
    input.set(part, offset);
    offset += part.length;
  }
  return digestMatchesExpression(value, expression, sha256Bytes(input));
}

function exactRefCoverage(value: unknown, expression: JsonObject): boolean {
  const actual = valueAtPath(value, expression.array_path);
  if (!Array.isArray(actual) || actual.some((item) => typeof item !== "string")) {
    return false;
  }
  const required: string[] = [];
  const requiredPaths = Array.isArray(expression.required_paths)
    ? expression.required_paths
    : [];
  for (const pointer of requiredPaths) {
    const candidate = valueAtPath(value, pointer);
    if (candidate === null) continue;
    if (typeof candidate !== "string") return false;
    required.push(candidate);
  }
  const arrayPaths = Array.isArray(expression.required_array_paths)
    ? expression.required_array_paths
    : [];
  for (const pointer of arrayPaths) {
    const candidates = valueAtPath(value, pointer);
    if (
      !Array.isArray(candidates) ||
      candidates.some((candidate) => typeof candidate !== "string")
    ) {
      return false;
    }
    required.push(...candidates);
  }
  const derivedRefs = Array.isArray(expression.required_derived_refs)
    ? expression.required_derived_refs
    : [];
  for (const derived of derivedRefs) {
    if (
      !isObject(derived) ||
      typeof derived.path !== "string" ||
      typeof derived.prefix !== "string"
    ) {
      return false;
    }
    const candidate = valueAtPath(value, derived.path);
    if (typeof candidate !== "string") return false;
    const suffix =
      typeof derived.strip_prefix === "string"
        ? candidate.startsWith(derived.strip_prefix)
          ? candidate.slice(derived.strip_prefix.length)
          : null
        : candidate;
    if (suffix === null) return false;
    required.push(derived.prefix + suffix);
  }
  return (
    actual.length === required.length &&
    jsonSchemaEqual([...actual].sort(), [...required].sort())
  );
}

function scopePatternMatches(pattern: unknown, value: unknown): boolean {
  if (typeof pattern !== "string" || typeof value !== "string") return false;
  const normalizedPattern = pattern.trim().toLowerCase();
  const normalizedValue = value.trim().toLowerCase();
  if (normalizedPattern === "*" || normalizedPattern === normalizedValue) {
    return true;
  }
  for (const suffix of ["::*", ":*", "*"]) {
    if (!normalizedPattern.endsWith(suffix)) continue;
    return normalizedValue.startsWith(normalizedPattern.slice(0, -1));
  }
  return false;
}

function invariantErrors(contractId: string, rules: Array<JsonObject>, value: unknown): string[] {
  return rules.flatMap((rule) => {
    const expression = isObject(rule.expression) ? rule.expression : {};
    const operator = expression.operator;
    let valid = false;
    if (
      operator === "any_of" &&
      Array.isArray(expression.expressions) &&
      expression.expressions.length > 0
    ) {
      valid =
        expression.expressions.every(isObject) &&
        expression.expressions.some(
          (candidate) =>
            invariantErrors(
              contractId,
              [{ rule_id: rule.rule_id, expression: candidate }],
              value,
            ).length === 0,
        );
    } else if (operator === "non_empty") {
      const candidate = valueAtPath(value, expression.path);
      valid = Array.isArray(candidate) ? candidate.length > 0 : typeof candidate === "string" && candidate.length > 0;
    } else if (operator === "any_non_empty" && Array.isArray(expression.paths)) {
      valid = expression.paths.some((path) => {
        const candidate = valueAtPath(value, path);
        return Array.isArray(candidate) ? candidate.length > 0 : typeof candidate === "string" && candidate.length > 0;
      });
    } else if (
      operator === "non_empty_when_in" &&
      typeof expression.path === "string" &&
      typeof expression.when_path === "string" &&
      Array.isArray(expression.values)
    ) {
      const applies = expression.values.some((expected) =>
        jsonSchemaEqual(valueAtPath(value, expression.when_path), expected),
      );
      const candidate = valueAtPath(value, expression.path);
      valid =
        !applies ||
        (Array.isArray(candidate)
          ? candidate.length > 0
          : typeof candidate === "string" && candidate.length > 0);
    } else if (operator === "fields_equal" && Array.isArray(expression.paths) && expression.paths.length === 2) {
      const left = valueAtPath(value, expression.paths[0]);
      const right = valueAtPath(value, expression.paths[1]);
      valid =
        left !== undefined &&
        right !== undefined &&
        jsonSchemaEqual(left, right);
    } else if (
      operator === "array_field_equals" &&
      typeof expression.array_path === "string" &&
      typeof expression.field === "string" &&
      typeof expression.expected_path === "string"
    ) {
      const values = valueAtPath(value, expression.array_path);
      const expected = valueAtPath(value, expression.expected_path);
      const field = expression.field;
      valid =
        Array.isArray(values) &&
        expected !== undefined &&
        values.every(
          (item) =>
            isObject(item) &&
            jsonSchemaEqual(item[field], expected),
        );
    } else if (
      operator === "optional_field_equals" &&
      typeof expression.optional_object_path === "string" &&
      typeof expression.field === "string" &&
      typeof expression.expected_path === "string"
    ) {
      const optional = valueAtPath(value, expression.optional_object_path);
      const expected = valueAtPath(value, expression.expected_path);
      const field = expression.field;
      valid =
        optional === null ||
        (isObject(optional) &&
          expected !== undefined &&
          jsonSchemaEqual(optional[field], expected));
    } else if (
      operator === "prefixed_field_equals" &&
      typeof expression.path === "string" &&
      typeof expression.prefix === "string" &&
      typeof expression.expected_path === "string"
    ) {
      const actual = valueAtPath(value, expression.path);
      const expected = valueAtPath(value, expression.expected_path);
      valid =
        typeof actual === "string" &&
        typeof expected === "string" &&
        actual === expression.prefix + expected;
    } else if (
      operator === "field_ends_with" &&
      typeof expression.path === "string" &&
      typeof expression.expected_path === "string"
    ) {
      const actual = valueAtPath(value, expression.path);
      const expected = valueAtPath(value, expression.expected_path);
      valid =
        typeof actual === "string" &&
        typeof expected === "string" &&
        expected.length > 0 &&
        actual.endsWith(expected);
    } else if (
      operator === "array_length_equals" &&
      typeof expression.array_path === "string" &&
      typeof expression.count_path === "string"
    ) {
      const values = valueAtPath(value, expression.array_path);
      const count = valueAtPath(value, expression.count_path);
      valid =
        Array.isArray(values) &&
        typeof count === "number" &&
        Number.isSafeInteger(count) &&
        count >= 0 &&
        values.length === count;
    } else if (
      operator === "array_unique_by_fields" &&
      typeof expression.array_path === "string" &&
      Array.isArray(expression.fields) &&
      expression.fields.length > 0
    ) {
      const values = valueAtPath(value, expression.array_path);
      const fields = expression.fields;
      valid =
        Array.isArray(values) &&
        values.every(
          (item, index) =>
            isObject(item) &&
            fields.every(
              (field) =>
                typeof field === "string" &&
                Object.prototype.hasOwnProperty.call(item, field),
            ) &&
            !values.slice(0, index).some(
              (previous) =>
                isObject(previous) &&
                fields.every(
                  (field) =>
                    typeof field === "string" &&
                    jsonSchemaEqual(previous[field], item[field]),
                ),
            ),
        );
    } else if (
      operator === "object_fields_equal" &&
      Array.isArray(expression.object_paths) &&
      expression.object_paths.length === 2 &&
      Array.isArray(expression.fields) &&
      expression.fields.length > 0
    ) {
      const left = valueAtPath(value, expression.object_paths[0]);
      const right = valueAtPath(value, expression.object_paths[1]);
      valid =
        isObject(left) &&
        isObject(right) &&
        expression.fields.every(
          (field) =>
            typeof field === "string" &&
            Object.prototype.hasOwnProperty.call(left, field) &&
            Object.prototype.hasOwnProperty.call(right, field) &&
            jsonSchemaEqual(left[field], right[field]),
        );
    } else if (operator === "jcs_sha256_equals") {
      valid = jcsSha256Matches(value, expression);
    } else if (operator === "sha256_parts_equals") {
      valid = sha256PartsMatch(value, expression);
    } else if (
      operator === "array_contains_value" &&
      typeof expression.array_path === "string" &&
      typeof expression.expected_path === "string"
    ) {
      const values = valueAtPath(value, expression.array_path);
      const expected = valueAtPath(value, expression.expected_path);
      valid =
        Array.isArray(values) &&
        expected !== undefined &&
        values.some((candidate) => jsonSchemaEqual(candidate, expected));
    } else if (operator === "array_exact_ref_coverage") {
      valid = exactRefCoverage(value, expression);
    } else if (
      operator === "scope_pattern_matches" &&
      typeof expression.pattern_path === "string" &&
      typeof expression.value_path === "string"
    ) {
      valid = scopePatternMatches(
        valueAtPath(value, expression.pattern_path),
        valueAtPath(value, expression.value_path),
      );
    } else if (
      operator === "field_starts_with_path" &&
      typeof expression.path === "string" &&
      typeof expression.expected_path === "string" &&
      typeof expression.prefix === "string"
    ) {
      const actual = valueAtPath(value, expression.path);
      const expected = valueAtPath(value, expression.expected_path);
      const stripped =
        typeof expected === "string" &&
        typeof expression.strip_prefix === "string"
          ? expected.startsWith(expression.strip_prefix)
            ? expected.slice(expression.strip_prefix.length)
            : null
          : expected;
      valid =
        typeof actual === "string" &&
        typeof stripped === "string" &&
        actual.startsWith(
          expression.prefix + stripped + String(expression.suffix ?? ""),
        );
    } else if (
      operator === "field_suffix_equals_prefixed_field" &&
      typeof expression.source_path === "string" &&
      typeof expression.delimiter === "string" &&
      expression.delimiter.length > 0 &&
      typeof expression.target_path === "string" &&
      typeof expression.target_prefix === "string"
    ) {
      const source = valueAtPath(value, expression.source_path);
      const target = valueAtPath(value, expression.target_path);
      const delimiterIndex =
        typeof source === "string"
          ? source.lastIndexOf(expression.delimiter)
          : -1;
      const suffix =
        typeof source === "string" && delimiterIndex >= 0
          ? source.slice(delimiterIndex + expression.delimiter.length)
          : "";
      valid =
        suffix.length > 0 &&
        typeof target === "string" &&
        target === expression.target_prefix + suffix;
    } else if (operator === "matches_contract_schema_hash") {
      valid = valueAtPath(value, expression.path) === architectureContractSchemaHash(contractId);
    } else if (
      (operator === "numbers_lte" || operator === "numbers_lt") &&
      Array.isArray(expression.paths) &&
      expression.paths.length === 2
    ) {
      const left = valueAtPath(value, expression.paths[0]);
      const right = valueAtPath(value, expression.paths[1]);
      valid =
        typeof left === "number" &&
        typeof right === "number" &&
        (operator === "numbers_lte" ? left <= right : left < right);
    }
    return valid ? [] : ["invariant:" + String(rule.rule_id ?? "unknown")];
  });
}

export function architectureContractInvariantErrors(
  contractId: string,
  value: unknown,
): string[] {
  return invariantErrors(contractId, CONTRACT_INVARIANTS[contractId] ?? [], value);
}

export function validateArchitectureContract(contractId: string, value: unknown): ValidationResult {
  const schema = CONTRACT_SCHEMAS[contractId];
  if (!schema) return { ok: false, errors: ["unknown contract: " + contractId] };
  const errors = schemaMatches(schema, schema, value, "$");
  if (errors.length === 0) errors.push(...architectureContractInvariantErrors(contractId, value));
  return { ok: errors.length === 0, errors };
}

${wrappers}
`;
}

function nullableBranch(schema, rootSchema) {
  const branches = schema.oneOf ?? schema.anyOf;
  if (!branches) return null;
  const nullIndex = branches.findIndex((branch) => branch.type === "null");
  if (nullIndex === -1 || branches.length !== 2) return null;
  return branches[nullIndex === 0 ? 1 : 0];
}

function rustStructsFor(entry, schema) {
  const definitions = new Map();
  const topName = projectionSymbol(entry);
  function rustFieldName(name) {
    return name === "ref" ? "r#ref" : name;
  }
  function rustVariantName(value, index, used) {
    const words = value
      .split(/[^A-Za-z0-9]+/u)
      .filter(Boolean)
      .map((part) => part.charAt(0).toUpperCase() + part.slice(1));
    let candidate = words.join("") || "Value";
    if (/^[0-9]/u.test(candidate)) candidate = `Value${candidate}`;
    if (used.has(candidate)) candidate = `${candidate}Value${index + 1}`;
    used.add(candidate);
    return candidate;
  }
  function rustClosedStringEnum(nameHint, values) {
    if (!definitions.has(nameHint)) {
      const usedVariants = new Set();
      const variants = values.map((value, index) => {
        const variant = rustVariantName(value, index, usedVariants);
        return `    #[serde(rename = ${rustString(value)})]\n    ${variant},`;
      });
      definitions.set(
        nameHint,
        `#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]\npub enum ${nameHint} {\n${variants.join("\n")}\n}`,
      );
    }
    return nameHint;
  }
  function rustClosedIntegerEnum(nameHint, values) {
    if (!definitions.has(nameHint)) {
      const variantFor = (value) =>
        value < 0
          ? `Negative${Math.abs(value)}`
          : value === 0
            ? "Zero"
            : `Positive${value}`;
      const variants = values
        .map((value) => `    ${variantFor(value)},`)
        .join("\n");
      const serializeArms = values
        .map(
          (value) =>
            `            Self::${variantFor(value)} => ${value}_i64,`,
        )
        .join("\n");
      const deserializeArms = values
        .map(
          (value) =>
            `            ${value}_i64 => Ok(Self::${variantFor(value)}),`,
        )
        .join("\n");
      definitions.set(
        nameHint,
        `#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ${nameHint} {
${variants}
}

impl ${nameHint} {
    pub const fn as_i64(self) -> i64 {
        match self {
${serializeArms}
        }
    }
}

impl serde::Serialize for ${nameHint} {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_i64(self.as_i64())
    }
}

impl<'de> serde::Deserialize<'de> for ${nameHint} {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value =
            <ArchitectureContractSignedInteger as serde::Deserialize>::deserialize(deserializer)?;
        match value.0 {
${deserializeArms}
            _ => Err(serde::de::Error::custom(${rustString(
              `expected one of the closed integer values ${values.join(", ")}`,
            )})),
        }
    }
}`,
      );
    }
    return nameHint;
  }
  function rustDisjointAnyOf(nameHint, branches, rootSchema) {
    function branchJsonType(branch) {
      if (branch.$ref) {
        return branchJsonType(resolveLocalRef(rootSchema, branch.$ref));
      }
      if (Object.hasOwn(branch, "const")) {
        return branch.const === null ? "null" : typeof branch.const;
      }
      if (Array.isArray(branch.enum) && branch.enum.length > 0) {
        const types = new Set(
          branch.enum.map((value) => (value === null ? "null" : typeof value)),
        );
        return types.size === 1 ? [...types][0] : null;
      }
      if (branch.type === "integer") return "number";
      return typeof branch.type === "string" ? branch.type : null;
    }

    const jsonTypes = branches.map(branchJsonType);
    if (
      jsonTypes.some((value) => value === null) ||
      new Set(jsonTypes).size !== jsonTypes.length
    ) {
      throw new Error(
        `${entry.contract_id}:${nameHint}: Rust projection requires anyOf branches with distinct JSON types`,
      );
    }
    if (!definitions.has(nameHint)) {
      definitions.set(nameHint, null);
      const variants = branches.map((branch, index) => {
        const fieldType = rustType(
          branch,
          rootSchema,
          `${nameHint}Branch${index + 1}`,
        );
        return `    Branch${index + 1}(${fieldType}),`;
      });
      definitions.set(
        nameHint,
        `#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum ${nameHint} {
${variants.join("\n")}
}`,
      );
    }
    return nameHint;
  }
  function rustBooleanLiteral(nameHint, value) {
    if (!definitions.has(nameHint)) {
      const variant = value ? "True" : "False";
      definitions.set(
        nameHint,
        `#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ${nameHint} {
    ${variant},
}

impl serde::Serialize for ${nameHint} {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bool(${value})
    }
}

impl<'de> serde::Deserialize<'de> for ${nameHint} {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = <bool as serde::Deserialize>::deserialize(deserializer)?;
        if value == ${value} {
            Ok(Self::${variant})
        } else {
            Err(serde::de::Error::custom(${rustString(`expected boolean literal ${value}`)}))
        }
    }
}`,
      );
    }
    return nameHint;
  }
  function rustType(node, rootSchema, nameHint) {
    if (node.$ref)
      return rustType(
        resolveLocalRef(rootSchema, node.$ref),
        rootSchema,
        nameHint,
      );
    const nullable = nullableBranch(node, rootSchema);
    if (nullable) return `Option<${rustType(nullable, rootSchema, nameHint)}>`;
    if (typeof node.const === "boolean") {
      return rustBooleanLiteral(nameHint, node.const);
    }
    const closedStrings = closedStringValues(node, rootSchema);
    if (closedStrings !== null) {
      return rustClosedStringEnum(nameHint, closedStrings);
    }
    const closedIntegers = closedIntegerValues(node, rootSchema);
    if (closedIntegers !== null) {
      return rustClosedIntegerEnum(nameHint, closedIntegers);
    }
    if (node.anyOf) {
      return rustDisjointAnyOf(nameHint, node.anyOf, rootSchema);
    }
    if (node.oneOf) {
      throw new Error(
        `${entry.contract_id}:${nameHint}: Rust projection cannot represent this union exactly`,
      );
    }
    switch (node.type) {
      case "string":
        return "String";
      case "integer":
        return node.minimum < 0
          ? "ArchitectureContractSignedInteger"
          : "ArchitectureContractInteger";
      case "number":
        return "f64";
      case "boolean":
        return "bool";
      case "null":
        return "()";
      case "array":
        return `Vec<${rustType(node.items ?? {}, rootSchema, `${nameHint}Item`)}>`;
      case "object": {
        if (!node.properties) return "serde_json::Value";
        if (!definitions.has(nameHint)) {
          definitions.set(nameHint, null);
          const required = new Set(node.required ?? []);
          const fields = Object.entries(node.properties).map(
            ([name, property]) => {
              let fieldType = rustType(
                property,
                rootSchema,
                `${nameHint}${name
                  .split("_")
                  .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
                  .join("")}`,
              );
              if (!required.has(name) && !fieldType.startsWith("Option<")) {
                fieldType = `Option<${fieldType}>`;
              }
              return {
                fieldType,
                jsonName: name,
                required: required.has(name),
                rustName: rustFieldName(name),
              };
            },
          );
          const publicFields = fields
            .map(
              ({ rustName, fieldType, required }) =>
                `${required ? "" : '    #[serde(skip_serializing_if = "Option::is_none")]\n'}    pub ${rustName}: ${fieldType},`,
            )
            .join("\n");
          const assignments = fields
            .map(({ fieldType, jsonName, required, rustName }) =>
              required
                ? `            ${rustName}: serde_json::from_value::<${fieldType}>(
                object
                    .remove(${rustString(jsonName)})
                    .ok_or_else(|| serde::de::Error::missing_field(${rustString(jsonName)}))?,
            )
            .map_err(serde::de::Error::custom)?,`
                : `            ${rustName}: match object.remove(${rustString(jsonName)}) {
                Some(field_value) => serde_json::from_value::<${fieldType}>(field_value)
                    .map_err(serde::de::Error::custom)?,
                None => None,
            },`,
            )
            .join("\n");
          definitions.set(
            nameHint,
            `#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct ${nameHint} {
${publicFields}
}

impl<'de> serde::Deserialize<'de> for ${nameHint} {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = <serde_json::Value as serde::Deserialize>::deserialize(deserializer)?;
        validate_projection_subschema(
            ${rustString(entry.contract_id)},
            ${rustRaw(node)},
            &value,
        )
            .map_err(serde::de::Error::custom)?;
        let mut object = value
            .as_object()
            .cloned()
            .ok_or_else(|| serde::de::Error::custom("validated projection is not an object"))?;
        Ok(Self {
${assignments}
        })
    }
}`,
          );
        }
        return nameHint;
      }
      default:
        return "serde_json::Value";
    }
  }
  rustType(schema, schema, topName);
  return [...definitions.values()].join("\n\n");
}

function rustRawText(value) {
  let hashes = "#";
  while (value.includes(`"${hashes}`)) hashes += "#";
  return `r${hashes}"${value}"${hashes}`;
}

function rustRaw(value) {
  return rustRawText(JSON.stringify(value));
}

function rustString(value) {
  return rustRawText(value);
}

function renderRust() {
  const structs = contracts
    .map(({ entry, schema }) => rustStructsFor(entry, schema))
    .join("\n\n");
  const schemaEntries = contracts
    .map(
      ({ entry, schema }) =>
        `    (${JSON.stringify(entry.contract_id)}, ${rustRaw(schema)}),`,
    )
    .join("\n");
  const invariantEntries = contracts
    .map(
      ({ entry, invariants }) =>
        `    (${JSON.stringify(entry.contract_id)}, ${rustRaw(invariants.flatMap((profile) => profile.rules))}),`,
    )
    .join("\n");
  const differentialCases = differentialCorpus();
  const differentialEntries = differentialCases
    .map(
      (candidate) => `    ArchitectureContractDifferentialCase {
        id: ${rustString(candidate.id)},
        contract_id: ${rustString(candidate.contract_id)},
        source_fixture_path: ${candidate.source_fixture_path === null ? "None" : `Some(${rustString(candidate.source_fixture_path)})`},
        mutation_id: ${candidate.mutation_id === null ? "None" : `Some(${rustString(candidate.mutation_id)})`},
        value_json: ${candidate.value_json === null ? "None" : `Some(${rustRawText(candidate.value_json)})`},
        ajv_schema_accept: ${candidate.ajv_schema_accept},
        oracle_contract_accept: ${candidate.oracle_contract_accept},
    },`,
    )
    .join("\n");
  const jcsDifferentialEntries = JCS_DIFFERENTIAL_CASES
    .map(
      (candidate) => `    ArchitectureContractJcsDifferentialCase {
        id: ${rustString(candidate.id)},
        value_json: ${rustRawText(candidate.value_json)},
        expected_canonical: ${rustRawText(candidate.expected_canonical)},
    },`,
    )
    .join("\n");
  const patternTranslationEntries = [...registeredPatternTranslations]
    .sort(([left], [right]) => codePointCompare(left, right))
    .map(
      ([ecmaPattern, rustPattern]) =>
        `    (${rustString(ecmaPattern)}, ${rustString(rustPattern)}),`,
    )
    .join("\n");
  const schemaHashEntries = contracts
    .map(
      ({ entry, schema }) =>
        `    (${JSON.stringify(entry.contract_id)}, ${JSON.stringify(schemaHash(schema))}),`,
    )
    .join("\n");
  const fixtures = fixtureMetadata();
  const fixtureEntries = fixtures
    .map(
      (fixture) => `    GoldenFixture {
        contract_id: ${JSON.stringify(fixture.contract_id)},
        path: ${JSON.stringify(fixture.path)},
        expected_accept: ${fixture.expected === "accept"},
        expected_schema_accept: ${fixture.expected_schema_accept},
        expected_failure: ${fixture.expected_failure === null ? "None" : `Some(${JSON.stringify(fixture.expected_failure)})`},
        expected_rule_id: ${fixture.expected_rule_id === null ? "None" : `Some(${JSON.stringify(fixture.expected_rule_id)})`},
    },`,
    )
    .join("\n");
  const fixtureBodies = fixtures
    .map(
      (fixture) =>
        `    (${JSON.stringify(fixture.path)}, include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../", ${JSON.stringify(fixture.path)}))),`,
    )
    .join("\n");
  const mutations = mutationCorpus();
  const mutationEntries = mutations
    .map(
      (mutation) => `    ArchitectureContractMutation {
        id: ${rustString(mutation.id)},
        contract_id: ${rustString(mutation.contract_id)},
        source_fixture_path: ${rustString(mutation.source_fixture_path)},
        covered_keywords: &[${mutation.covered_keywords.map(rustString).join(", ")}],
        ajv_expected_accept: ${mutation.ajv_expected_accept},
        oracle_contract_accept: ${mutation.oracle_contract_accept},
        expected_rule_ids: &[${mutation.expected_rule_ids.map(rustString).join(", ")}],
        direct_projection_rejection: ${mutation.direct_projection_rejection},
        patch_operation: ${rustString(mutation.patch.operation)},
        patch_pointer: ${rustString(mutation.patch.pointer)},
        patch_value_json: ${Object.hasOwn(mutation.patch, "value") ? `Some(${rustRaw(mutation.patch.value)})` : "None"},
    },`,
    )
    .join("\n");
  const parseArms = contracts
    .map(
      ({ entry }) => `        ${JSON.stringify(entry.contract_id)} => {
            serde_json::from_value::<${projectionSymbol(entry)}>(value.clone())
                .map(|_| ())
                .map_err(|error| error.to_string())
        }`,
    )
    .join(",\n");
  const roundTripArms = contracts
    .map(
      ({ entry }) => `        ${JSON.stringify(entry.contract_id)} => {
            let projection = serde_json::from_value::<${projectionSymbol(entry)}>(value.clone())
                .map_err(|error| error.to_string())?;
            serde_json::to_value(projection).map_err(|error| error.to_string())
        }`,
    )
    .join(",\n");
  const rawStringRegressionSchema = rustRaw({
    const: 'schema-controlled"###literal',
  });

  return `//! Generated by scripts/generate-architecture-contracts.mjs. Do not edit.
#![allow(missing_docs)]

use dcrypt::algorithms::hash::{HashFunction, Sha256};
use regex::Regex;
use serde_json::Value;
use std::cmp::Ordering;

pub const ARCHITECTURE_CONTRACT_REGISTRY_VERSION: &str = ${JSON.stringify(registry.registry_version)};
pub const ARCHITECTURE_CONTRACT_PORTABLE_INTEGER_MINIMUM: u64 = ${PORTABLE_INTEGER_MINIMUM};
pub const ARCHITECTURE_CONTRACT_PORTABLE_INTEGER_MAXIMUM: u64 = ${PORTABLE_INTEGER_MAXIMUM};
pub const ARCHITECTURE_CONTRACT_PORTABLE_SIGNED_INTEGER_MINIMUM: i64 = ${PORTABLE_SIGNED_INTEGER_MINIMUM};
pub const ARCHITECTURE_CONTRACT_PORTABLE_SIGNED_INTEGER_MAXIMUM: i64 = ${PORTABLE_INTEGER_MAXIMUM};
pub const ARCHITECTURE_CONTRACT_PORTABLE_DATE_TIME_PATTERN: &str = ${rustString(PORTABLE_CANONICAL_DATE_TIME_PATTERN)};
pub const ARCHITECTURE_CONTRACT_ORACLE_PROFILE: &str =
    "ajv-2020-12-plus-portable-invariants-and-canonical-rfc3339";

pub const ARCHITECTURE_CONTRACT_ASSERTION_KEYWORDS: &[&str] = &[
${[...usedSchemaKeywords]
  .sort(codePointCompare)
  .map((keyword) => `    ${rustString(keyword)},`)
  .join("\n")}
];

pub const ARCHITECTURE_CONTRACT_SCHEMA_HASHES: &[(&str, &str)] = &[
${schemaHashEntries}
];

pub fn architecture_contract_schema_hash(contract_id: &str) -> Option<&'static str> {
    ARCHITECTURE_CONTRACT_SCHEMA_HASHES
        .iter()
        .find_map(|(id, hash)| (*id == contract_id).then_some(*hash))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ArchitectureContractInteger(pub u64);

impl serde::Serialize for ArchitectureContractInteger {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u64(self.0)
    }
}

impl<'de> serde::Deserialize<'de> for ArchitectureContractInteger {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = <serde_json::Value as serde::Deserialize>::deserialize(deserializer)?;
        let number = value
            .as_number()
            .and_then(json_number_as_u64)
            .filter(|number| *number <= ARCHITECTURE_CONTRACT_PORTABLE_INTEGER_MAXIMUM)
            .ok_or_else(|| {
                serde::de::Error::custom(
                    "expected an integral JSON number in the portable unsigned JS-safe domain",
                )
            })?;
        Ok(Self(number))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ArchitectureContractSignedInteger(pub i64);

impl serde::Serialize for ArchitectureContractSignedInteger {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_i64(self.0)
    }
}

impl<'de> serde::Deserialize<'de> for ArchitectureContractSignedInteger {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = <serde_json::Value as serde::Deserialize>::deserialize(deserializer)?;
        let number = value
            .as_number()
            .and_then(json_number_as_i64)
            .filter(|number| {
                *number >= ARCHITECTURE_CONTRACT_PORTABLE_SIGNED_INTEGER_MINIMUM
                    && *number <= ARCHITECTURE_CONTRACT_PORTABLE_SIGNED_INTEGER_MAXIMUM
            })
            .ok_or_else(|| {
                serde::de::Error::custom(
                    "expected an integral JSON number in the portable signed JS-safe domain",
                )
            })?;
        Ok(Self(number))
    }
}

${structs}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GoldenFixture {
    pub contract_id: &'static str,
    pub path: &'static str,
    pub expected_accept: bool,
    pub expected_schema_accept: bool,
    pub expected_failure: Option<&'static str>,
    pub expected_rule_id: Option<&'static str>,
}

pub const ARCHITECTURE_CONTRACT_FIXTURES: &[GoldenFixture] = &[
${fixtureEntries}
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArchitectureContractMutation {
    pub id: &'static str,
    pub contract_id: &'static str,
    pub source_fixture_path: &'static str,
    pub covered_keywords: &'static [&'static str],
    pub ajv_expected_accept: bool,
    pub oracle_contract_accept: bool,
    pub expected_rule_ids: &'static [&'static str],
    pub direct_projection_rejection: bool,
    pub patch_operation: &'static str,
    pub patch_pointer: &'static str,
    pub patch_value_json: Option<&'static str>,
}

pub const ARCHITECTURE_CONTRACT_MUTATIONS: &[ArchitectureContractMutation] = &[
${mutationEntries}
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArchitectureContractDifferentialCase {
    pub id: &'static str,
    pub contract_id: &'static str,
    pub source_fixture_path: Option<&'static str>,
    pub mutation_id: Option<&'static str>,
    pub value_json: Option<&'static str>,
    pub ajv_schema_accept: bool,
    pub oracle_contract_accept: bool,
}

pub const ARCHITECTURE_CONTRACT_DIFFERENTIAL_CASES: &[ArchitectureContractDifferentialCase] = &[
${differentialEntries}
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArchitectureContractJcsDifferentialCase {
    pub id: &'static str,
    pub value_json: &'static str,
    pub expected_canonical: &'static str,
}

pub const ARCHITECTURE_CONTRACT_JCS_DIFFERENTIAL_CASES: &[ArchitectureContractJcsDifferentialCase] = &[
${jcsDifferentialEntries}
];

const CONTRACT_SCHEMAS: &[(&str, &str)] = &[
${schemaEntries}
];

const CONTRACT_INVARIANTS: &[(&str, &str)] = &[
${invariantEntries}
];

const CONTRACT_PATTERN_TRANSLATIONS: &[(&str, &str)] = &[
${patternTranslationEntries}
];

fn resolve_ref<'a>(root: &'a Value, reference: &str) -> Option<&'a Value> {
    let pointer = reference.strip_prefix('#')?;
    root.pointer(pointer)
}

fn type_matches(expected: &str, value: &Value) -> bool {
    match expected {
        "null" => value.is_null(),
        "string" => value.is_string(),
        "integer" => value
            .as_number()
            .is_some_and(json_number_is_integral),
        "number" => value.is_number(),
        "boolean" => value.is_boolean(),
        "array" => value.is_array(),
        "object" => value.is_object(),
        _ => false,
    }
}

fn normalized_json_number(number: &serde_json::Number) -> (bool, String, i32) {
    let rendered = number.to_string();
    let (negative, unsigned) = rendered
        .strip_prefix('-')
        .map_or((false, rendered.as_str()), |unsigned| (true, unsigned));
    let (mantissa, explicit_exponent) = unsigned
        .split_once(['e', 'E'])
        .map_or((unsigned, 0_i32), |(mantissa, exponent)| {
            (
                mantissa,
                exponent
                    .parse::<i32>()
                    .expect("serde_json rendered a valid number exponent"),
            )
        });
    let (whole, fraction) = mantissa
        .split_once('.')
        .map_or((mantissa, ""), |(whole, fraction)| (whole, fraction));
    let mut digits = format!("{whole}{fraction}")
        .trim_start_matches('0')
        .to_owned();
    if digits.is_empty() {
        return (false, "0".to_owned(), 0);
    }
    let mut decimal_exponent = explicit_exponent - fraction.len() as i32;
    while digits.ends_with('0') {
        digits.pop();
        decimal_exponent += 1;
    }
    (negative, digits, decimal_exponent)
}

fn json_number_is_integral(number: &serde_json::Number) -> bool {
    let (_, _, decimal_exponent) = normalized_json_number(number);
    decimal_exponent >= 0
}

fn json_number_as_u64(number: &serde_json::Number) -> Option<u64> {
    let (negative, digits, decimal_exponent) = normalized_json_number(number);
    if negative || decimal_exponent < 0 {
        return None;
    }
    let zero_count = usize::try_from(decimal_exponent).ok()?;
    let total_length = digits.len().checked_add(zero_count)?;
    if total_length > 20 {
        return None;
    }
    let mut integer = digits;
    integer.extend(std::iter::repeat_n('0', zero_count));
    integer.parse::<u64>().ok()
}

fn json_number_as_i64(number: &serde_json::Number) -> Option<i64> {
    let (negative, digits, decimal_exponent) = normalized_json_number(number);
    if decimal_exponent < 0 {
        return None;
    }
    let zero_count = usize::try_from(decimal_exponent).ok()?;
    let total_length = digits.len().checked_add(zero_count)?;
    if total_length > 19 {
        return None;
    }
    let mut integer = digits;
    integer.extend(std::iter::repeat_n('0', zero_count));
    let magnitude = integer.parse::<i128>().ok()?;
    let signed = if negative { -magnitude } else { magnitude };
    i64::try_from(signed).ok()
}

fn compare_json_numbers(
    left: &serde_json::Number,
    right: &serde_json::Number,
) -> Ordering {
    let (left_negative, left_digits, left_exponent) = normalized_json_number(left);
    let (right_negative, right_digits, right_exponent) = normalized_json_number(right);
    if left_negative != right_negative {
        return if left_negative {
            Ordering::Less
        } else {
            Ordering::Greater
        };
    }
    let left_magnitude = left_digits.len() as i64 + i64::from(left_exponent);
    let right_magnitude = right_digits.len() as i64 + i64::from(right_exponent);
    let magnitude_order = left_magnitude.cmp(&right_magnitude).then_with(|| {
        let width = left_digits.len().max(right_digits.len());
        (0..width)
            .map(|index| left_digits.as_bytes().get(index).copied().unwrap_or(b'0'))
            .cmp(
                (0..width)
                    .map(|index| right_digits.as_bytes().get(index).copied().unwrap_or(b'0')),
            )
    });
    if left_negative {
        magnitude_order.reverse()
    } else {
        magnitude_order
    }
}

fn json_schema_equal(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Null, Value::Null) => true,
        (Value::Bool(left), Value::Bool(right)) => left == right,
        (Value::Number(left), Value::Number(right)) => {
            compare_json_numbers(left, right) == Ordering::Equal
        }
        (Value::String(left), Value::String(right)) => left == right,
        (Value::Array(left), Value::Array(right)) => {
            left.len() == right.len()
                && left
                    .iter()
                    .zip(right)
                    .all(|(left, right)| json_schema_equal(left, right))
        }
        (Value::Object(left), Value::Object(right)) => {
            left.len() == right.len()
                && left.iter().all(|(key, left)| {
                    right
                        .get(key)
                        .is_some_and(|right| json_schema_equal(left, right))
                })
        }
        _ => false,
    }
}

fn canonical_json_for_hash(value: &Value) -> Option<String> {
    match value {
        Value::Array(items) => {
            let items = items
                .iter()
                .map(canonical_json_for_hash)
                .collect::<Option<Vec<_>>>()?;
            Some(format!("[{}]", items.join(",")))
        }
        Value::Object(object) => {
            let mut keys = object.keys().collect::<Vec<_>>();
            keys.sort_by(|left, right| left.encode_utf16().cmp(right.encode_utf16()));
            let mut fields = Vec::with_capacity(keys.len());
            for key in keys {
                let encoded_key = serde_jcs::to_string(key).ok()?;
                let encoded_value = canonical_json_for_hash(object.get(key)?)?;
                fields.push(format!("{encoded_key}:{encoded_value}"));
            }
            Some(format!("{{{}}}", fields.join(",")))
        }
        _ => serde_jcs::to_string(value).ok(),
    }
}

fn is_leap_year(year: u32) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn is_rfc3339_date_time(text: &str) -> bool {
    let regex = Regex::new(
        r"(?i)^(\\d{4})-(\\d{2})-(\\d{2})t(\\d{2}):(\\d{2}):(\\d{2}(?:\\.\\d+)?)(z|([+-])(\\d{2}):(\\d{2}))$",
    )
    .expect("generated RFC3339 regex is valid");
    let Some(captures) = regex.captures(text) else {
        return false;
    };
    let parse = |index| {
        captures
            .get(index)
            .and_then(|value| value.as_str().parse::<u32>().ok())
    };
    let (Some(year), Some(month), Some(day), Some(hour), Some(minute)) =
        (parse(1), parse(2), parse(3), parse(4), parse(5))
    else {
        return false;
    };
    let Some(second) = captures
        .get(6)
        .and_then(|value| value.as_str().parse::<f64>().ok())
    else {
        return false;
    };
    let zone_sign = if captures.get(8).is_some_and(|value| value.as_str() == "-") {
        -1_i32
    } else {
        1_i32
    };
    let zone_hour = parse(9).unwrap_or(0);
    let zone_minute = parse(10).unwrap_or(0);
    let month_days = [
        0,
        31,
        if is_leap_year(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if !(1..=12).contains(&month)
        || day == 0
        || day > month_days[month as usize]
        || zone_hour > 23
        || zone_minute > 59
    {
        return false;
    }
    if hour <= 23 && minute <= 59 && second < 60.0 {
        return true;
    }
    let utc_minute = minute as i32 - zone_minute as i32 * zone_sign;
    let utc_hour =
        hour as i32 - zone_hour as i32 * zone_sign - i32::from(utc_minute < 0);
    (utc_hour == 23 || utc_hour == -1)
        && (utc_minute == 59 || utc_minute == -1)
        && second < 61.0
}

fn validate_node(root: &Value, schema: &Value, value: &Value, at: &str) -> Result<(), String> {
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        let resolved = resolve_ref(root, reference)
            .ok_or_else(|| format!("{at}: unresolved $ref {reference}"))?;
        validate_node(root, resolved, value, at)?;
    }
    if let Some(branches) = schema.get("allOf").and_then(Value::as_array) {
        for branch in branches {
            validate_node(root, branch, value, at)?;
        }
    }
    if let Some(condition) = schema.get("if") {
        let selected = if validate_node(root, condition, value, at).is_ok() {
            schema.get("then")
        } else {
            schema.get("else")
        };
        if let Some(selected) = selected {
            validate_node(root, selected, value, at)?;
        }
    }
    for keyword in ["oneOf", "anyOf"] {
        if let Some(branches) = schema.get(keyword).and_then(Value::as_array) {
            let matches = branches
                .iter()
                .filter(|branch| validate_node(root, branch, value, at).is_ok())
                .count();
            let valid = if keyword == "oneOf" { matches == 1 } else { matches > 0 };
            if !valid {
                return Err(format!("{at}: failed {keyword}"));
            }
        }
    }
    if let Some(values) = schema.get("enum").and_then(Value::as_array) {
        if !values
            .iter()
            .any(|candidate| json_schema_equal(candidate, value))
        {
            return Err(format!("{at}: value is outside enum"));
        }
    }
    if let Some(expected) = schema.get("const") {
        if !json_schema_equal(expected, value) {
            return Err(format!("{at}: value does not match const"));
        }
    }
    let expected_type = schema.get("type").and_then(Value::as_str);
    if let Some(expected) = expected_type {
        if !type_matches(expected, value) {
            return Err(format!("{at}: expected {expected}"));
        }
    }
    if let Some(text) = value.as_str() {
        if let Some(min_length) = schema.get("minLength").and_then(Value::as_u64) {
            if text.chars().count() < min_length as usize {
                return Err(format!("{at}: string shorter than minLength"));
            }
        }
        if let Some(max_length) = schema.get("maxLength").and_then(Value::as_u64) {
            if text.chars().count() > max_length as usize {
                return Err(format!("{at}: string longer than maxLength"));
            }
        }
        if let Some(pattern) = schema.get("pattern").and_then(Value::as_str) {
            let translated = CONTRACT_PATTERN_TRANSLATIONS
                .iter()
                .find_map(|(ecma, rust)| (*ecma == pattern).then_some(*rust))
                .ok_or_else(|| format!("unsupported ECMA-262 schema pattern: {pattern}"))?;
            let regex = Regex::new(translated)
                .map_err(|error| format!("invalid translated schema regex: {error}"))?;
            if !regex.is_match(text) {
                return Err(format!("{at}: string failed pattern"));
            }
        }
        if schema.get("format").and_then(Value::as_str) == Some("date-time") {
            if !is_rfc3339_date_time(text) {
                return Err(format!("{at}: invalid date-time"));
            }
        }
    }
    if let Some(minimum) = schema.get("minimum").and_then(Value::as_number) {
        if value
            .as_number()
            .is_some_and(|number| compare_json_numbers(number, minimum) == Ordering::Less)
        {
            return Err(format!("{at}: number below minimum"));
        }
    }
    if let Some(maximum) = schema.get("maximum").and_then(Value::as_number) {
        if value
            .as_number()
            .is_some_and(|number| compare_json_numbers(number, maximum) == Ordering::Greater)
        {
            return Err(format!("{at}: number above maximum"));
        }
    }
    if let Some(items) = value.as_array() {
        if let Some(min_items) = schema.get("minItems").and_then(Value::as_u64) {
            if items.len() < min_items as usize {
                return Err(format!("{at}: array shorter than minItems"));
            }
        }
        if let Some(max_items) = schema.get("maxItems").and_then(Value::as_u64) {
            if items.len() > max_items as usize {
                return Err(format!("{at}: array longer than maxItems"));
            }
        }
        if schema.get("uniqueItems").and_then(Value::as_bool) == Some(true) {
            for (index, item) in items.iter().enumerate() {
                if items[..index]
                    .iter()
                    .any(|candidate| json_schema_equal(candidate, item))
                {
                    return Err(format!("{at}: array items are not unique"));
                }
            }
        }
        if let Some(item_schema) = schema.get("items") {
            for (index, item) in items.iter().enumerate() {
                validate_node(root, item_schema, item, &format!("{at}[{index}]"))?;
            }
        }
        if let Some(contains_schema) = schema.get("contains") {
            if !items
                .iter()
                .any(|item| validate_node(root, contains_schema, item, at).is_ok())
            {
                return Err(format!("{at}: array has no item matching contains"));
            }
        }
    }
    if let Some(object) = value.as_object() {
        let properties = schema.get("properties").and_then(Value::as_object);
        if let Some(required) = schema.get("required").and_then(Value::as_array) {
            for name in required.iter().filter_map(Value::as_str) {
                if !object.contains_key(name) {
                    return Err(format!("{at}: missing {name}"));
                }
            }
        }
        if schema.get("additionalProperties").and_then(Value::as_bool) == Some(false) {
            let properties = properties.ok_or_else(|| format!("{at}: schema has no properties"))?;
            if let Some(unknown) = object.keys().find(|name| !properties.contains_key(*name)) {
                return Err(format!("{at}: unknown {unknown}"));
            }
        }
        if let Some(properties) = properties {
            for (name, property_schema) in properties {
                if let Some(property_value) = object.get(name) {
                    validate_node(root, property_schema, property_value, &format!("{at}.{name}"))?;
                }
            }
        }
    }
    Ok(())
}

fn value_at_path<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = value;
    for segment in path.strip_prefix("$.")?.split('.') {
        let (key, index) = match segment.split_once('[') {
            Some((key, suffix)) => {
                let digits = suffix.strip_suffix(']')?;
                if digits.is_empty()
                    || !digits.bytes().all(|byte| byte.is_ascii_digit())
                    || (digits.len() > 1 && digits.starts_with('0'))
                {
                    return None;
                }
                let index = digits.parse::<usize>().ok()?;
                (key, Some(index))
            }
            None => (segment, None),
        };
        if key.is_empty()
            || !key.as_bytes()[0].is_ascii_lowercase()
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return None;
        }
        current = current.get(key)?;
        if let Some(index) = index {
            current = current.get(index)?;
        }
    }
    Some(current)
}

fn non_empty(value: Option<&Value>) -> bool {
    value.is_some_and(|candidate| match candidate {
        Value::Array(items) => !items.is_empty(),
        Value::String(text) => !text.is_empty(),
        _ => false,
    })
}

fn bytes_from_value(value: Option<&Value>) -> Option<Vec<u8>> {
    value?
        .as_array()?
        .iter()
        .map(|byte| u8::try_from(byte.as_u64()?).ok())
        .collect()
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn invariant_material(value: &Value, expression: &Value) -> Option<Value> {
    if let Some(path) = expression.get("material_path").and_then(Value::as_str) {
        return value_at_path(value, path).cloned();
    }
    let fields = expression.get("material_fields")?.as_object()?;
    let mut material = serde_json::Map::new();
    for (field, descriptor) in fields {
        let descriptor = descriptor.as_object()?;
        let candidate = if let Some(path) = descriptor.get("path").and_then(Value::as_str) {
            value_at_path(value, path)?.clone()
        } else {
            descriptor.get("value")?.clone()
        };
        material.insert(field.clone(), candidate);
    }
    Some(Value::Object(material))
}

fn sha256_digest(bytes: &[u8]) -> Option<Vec<u8>> {
    Sha256::digest(bytes).ok().map(|digest| digest.as_ref().to_vec())
}

fn digest_matches_expression(value: &Value, expression: &Value, digest: &[u8]) -> bool {
    let expected = expression
        .get("expected_path")
        .and_then(Value::as_str)
        .and_then(|path| value_at_path(value, path));
    match expression.get("expected_encoding").and_then(Value::as_str) {
        Some("bytes32") => bytes_from_value(expected).is_some_and(|bytes| bytes == digest),
        Some("sha256_string") => expected
            .and_then(Value::as_str)
            .is_some_and(|actual| actual == format!("sha256:{}", lower_hex(digest))),
        Some("prefixed_ref") => expression
            .get("prefix")
            .and_then(Value::as_str)
            .zip(expected.and_then(Value::as_str))
            .is_some_and(|(prefix, actual)| actual == format!("{prefix}{}", lower_hex(digest))),
        _ => false,
    }
}

fn jcs_sha256_matches(value: &Value, expression: &Value) -> bool {
    let Some(material) = invariant_material(value, expression) else {
        return false;
    };
    let Some(canonical) = canonical_json_for_hash(&material) else {
        return false;
    };
    let Some(mut digest) = sha256_digest(canonical.as_bytes()) else {
        return false;
    };
    match expression.get("algorithm").and_then(Value::as_str) {
        None | Some("jcs_sha256") => {}
        Some("jcs_sha256_then_utf8_sha256") => {
            let Some(prefix) = expression.get("intermediate_prefix").and_then(Value::as_str) else {
                return false;
            };
            let intermediate = format!("{prefix}{}", lower_hex(&digest));
            let Some(next) = sha256_digest(intermediate.as_bytes()) else {
                return false;
            };
            digest = next;
        }
        _ => return false,
    }
    digest_matches_expression(value, expression, &digest)
}

fn sha256_parts_match(value: &Value, expression: &Value) -> bool {
    let Some(parts) = expression.get("parts").and_then(Value::as_array) else {
        return false;
    };
    let mut bytes = Vec::new();
    for part in parts {
        let Some(part) = part.as_object() else {
            return false;
        };
        if let Some(text) = part.get("utf8").and_then(Value::as_str) {
            bytes.extend_from_slice(text.as_bytes());
        } else if let Some(path) = part.get("signed_i32_be_path").and_then(Value::as_str) {
            let Some(integer) = value_at_path(value, path)
                .and_then(Value::as_i64)
                .and_then(|integer| i32::try_from(integer).ok())
            else {
                return false;
            };
            bytes.extend_from_slice(&integer.to_be_bytes());
        } else if let Some(path) = part.get("bytes_path").and_then(Value::as_str) {
            let Some(part_bytes) = bytes_from_value(value_at_path(value, path)) else {
                return false;
            };
            bytes.extend_from_slice(&part_bytes);
        } else {
            return false;
        }
    }
    sha256_digest(&bytes)
        .is_some_and(|digest| digest_matches_expression(value, expression, &digest))
}

fn exact_ref_coverage(value: &Value, expression: &Value) -> bool {
    let Some(actual) = expression
        .get("array_path")
        .and_then(Value::as_str)
        .and_then(|path| value_at_path(value, path))
        .and_then(Value::as_array)
        .and_then(|items| {
            items
                .iter()
                .map(Value::as_str)
                .collect::<Option<Vec<_>>>()
        })
    else {
        return false;
    };
    let mut required = Vec::new();
    for pointer in expression
        .get("required_paths")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(pointer) = pointer.as_str() else {
            return false;
        };
        let Some(candidate) = value_at_path(value, pointer) else {
            return false;
        };
        if candidate.is_null() {
            continue;
        }
        let Some(candidate) = candidate.as_str() else {
            return false;
        };
        required.push(candidate.to_owned());
    }
    for pointer in expression
        .get("required_array_paths")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(candidates) = pointer
            .as_str()
            .and_then(|path| value_at_path(value, path))
            .and_then(Value::as_array)
        else {
            return false;
        };
        let Some(candidates) = candidates
            .iter()
            .map(Value::as_str)
            .collect::<Option<Vec<_>>>()
        else {
            return false;
        };
        required.extend(candidates.into_iter().map(str::to_owned));
    }
    for derived in expression
        .get("required_derived_refs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(path) = derived.get("path").and_then(Value::as_str) else {
            return false;
        };
        let Some(prefix) = derived.get("prefix").and_then(Value::as_str) else {
            return false;
        };
        let Some(candidate) = value_at_path(value, path).and_then(Value::as_str) else {
            return false;
        };
        let suffix = match derived.get("strip_prefix").and_then(Value::as_str) {
            Some(strip_prefix) => {
                let Some(suffix) = candidate.strip_prefix(strip_prefix) else {
                    return false;
                };
                suffix
            }
            None => candidate,
        };
        required.push(format!("{prefix}{suffix}"));
    }
    let mut actual = actual;
    actual.sort_unstable();
    required.sort_unstable();
    actual.len() == required.len()
        && actual
            .iter()
            .zip(required.iter())
            .all(|(left, right)| *left == right)
}

fn scope_pattern_matches(pattern: Option<&Value>, value: Option<&Value>) -> bool {
    let Some(pattern) = pattern.and_then(Value::as_str) else {
        return false;
    };
    let Some(value) = value.and_then(Value::as_str) else {
        return false;
    };
    let pattern = pattern.trim().to_ascii_lowercase();
    let value = value.trim().to_ascii_lowercase();
    if pattern == "*" || pattern == value {
        return true;
    }
    for suffix in ["::*", ":*", "*"] {
        if let Some(prefix) = pattern.strip_suffix(suffix) {
            return value.starts_with(&format!("{prefix}{}", &suffix[..suffix.len() - 1]));
        }
    }
    false
}

fn portable_array_length(value: Option<&Value>) -> Option<usize> {
    let number = value?.as_number()?;
    if let Some(value) = number.as_u64() {
        return usize::try_from(value).ok();
    }
    let value = number.as_f64()?;
    (value.is_finite()
        && value >= 0.0
        && value <= 9_007_199_254_740_991.0
        && value.fract() == 0.0)
        .then(|| value as usize)
}

fn array_unique_by_fields(value: Option<&Value>, fields: &[&str]) -> bool {
    let Some(items) = value.and_then(Value::as_array) else {
        return false;
    };
    if fields.is_empty() {
        return false;
    }
    let mut identities = std::collections::BTreeSet::new();
    for item in items {
        let Some(object) = item.as_object() else {
            return false;
        };
        let Some(identity) = fields
            .iter()
            .map(|field| object.get(*field).cloned())
            .collect::<Option<Vec<_>>>()
        else {
            return false;
        };
        let Some(encoded) = canonical_json_for_hash(&Value::Array(identity)) else {
            return false;
        };
        if !identities.insert(encoded) {
            return false;
        }
    }
    true
}

fn validate_invariants(contract_id: &str, rules: &Value, value: &Value) -> Result<(), String> {
    let mut errors = Vec::new();
    for rule in rules.as_array().into_iter().flatten() {
        let expression = &rule["expression"];
        let valid = match expression.get("operator").and_then(Value::as_str) {
            Some("any_of") => expression
                .get("expressions")
                .and_then(Value::as_array)
                .filter(|expressions| !expressions.is_empty())
                .is_some_and(|expressions| {
                    expressions.iter().all(Value::is_object)
                        && expressions.iter().any(|candidate| {
                            let nested_rules = serde_json::json!([{
                                "rule_id": rule.get("rule_id"),
                                "expression": candidate,
                            }]);
                            validate_invariants(contract_id, &nested_rules, value).is_ok()
                        })
                }),
            Some("non_empty") => expression
                .get("path")
                .and_then(Value::as_str)
                .is_some_and(|path| non_empty(value_at_path(value, path))),
            Some("any_non_empty") => expression
                .get("paths")
                .and_then(Value::as_array)
                .is_some_and(|paths| {
                    paths
                        .iter()
                        .filter_map(Value::as_str)
                        .any(|path| non_empty(value_at_path(value, path)))
                }),
            Some("non_empty_when_in") => {
                let applies = expression
                    .get("when_path")
                    .and_then(Value::as_str)
                    .and_then(|path| value_at_path(value, path))
                    .zip(expression.get("values").and_then(Value::as_array))
                    .is_some_and(|(actual, expected)| {
                        expected
                            .iter()
                            .any(|candidate| json_schema_equal(actual, candidate))
                    });
                !applies
                    || expression
                        .get("path")
                        .and_then(Value::as_str)
                        .is_some_and(|path| non_empty(value_at_path(value, path)))
            }
            Some("fields_equal") => expression
                .get("paths")
                .and_then(Value::as_array)
                .filter(|paths| paths.len() == 2)
                .and_then(|paths| {
                    Some((
                        value_at_path(value, paths.first()?.as_str()?)?,
                        value_at_path(value, paths.get(1)?.as_str()?)?,
                    ))
                })
                .is_some_and(|(left, right)| json_schema_equal(left, right)),
            Some("array_field_equals") => expression
                .get("array_path")
                .and_then(Value::as_str)
                .and_then(|path| value_at_path(value, path))
                .and_then(Value::as_array)
                .zip(
                    expression
                        .get("field")
                        .and_then(Value::as_str)
                        .zip(
                            expression
                                .get("expected_path")
                                .and_then(Value::as_str)
                                .and_then(|path| value_at_path(value, path)),
                        ),
                )
                .is_some_and(|(items, (field, expected))| {
                    items.iter().all(|item| {
                        item.get(field)
                            .is_some_and(|actual| json_schema_equal(actual, expected))
                    })
                }),
            Some("optional_field_equals") => expression
                .get("optional_object_path")
                .and_then(Value::as_str)
                .and_then(|path| value_at_path(value, path))
                .zip(
                    expression
                        .get("field")
                        .and_then(Value::as_str)
                        .zip(
                            expression
                                .get("expected_path")
                                .and_then(Value::as_str)
                                .and_then(|path| value_at_path(value, path)),
                        ),
                )
                .is_some_and(|(optional, (field, expected))| {
                    optional.is_null()
                        || optional
                            .get(field)
                            .is_some_and(|actual| json_schema_equal(actual, expected))
                }),
            Some("prefixed_field_equals") => expression
                .get("path")
                .and_then(Value::as_str)
                .and_then(|path| value_at_path(value, path))
                .and_then(Value::as_str)
                .zip(
                    expression
                        .get("prefix")
                        .and_then(Value::as_str)
                        .zip(
                            expression
                                .get("expected_path")
                                .and_then(Value::as_str)
                                .and_then(|path| value_at_path(value, path))
                                .and_then(Value::as_str),
                        ),
                )
                .is_some_and(|(actual, (prefix, expected))| {
                    actual.len() == prefix.len() + expected.len()
                        && actual.starts_with(prefix)
                        && actual.ends_with(expected)
                }),
            Some("field_ends_with") => expression
                .get("path")
                .and_then(Value::as_str)
                .and_then(|path| value_at_path(value, path))
                .and_then(Value::as_str)
                .zip(
                    expression
                        .get("expected_path")
                        .and_then(Value::as_str)
                        .and_then(|path| value_at_path(value, path))
                        .and_then(Value::as_str),
                )
                .is_some_and(|(actual, expected)| {
                    !expected.is_empty() && actual.ends_with(expected)
                }),
            Some("array_length_equals") => expression
                .get("array_path")
                .and_then(Value::as_str)
                .and_then(|path| value_at_path(value, path))
                .and_then(Value::as_array)
                .zip(
                    expression
                        .get("count_path")
                        .and_then(Value::as_str)
                        .and_then(|path| portable_array_length(value_at_path(value, path))),
                )
                .is_some_and(|(items, count)| items.len() == count),
            Some("array_unique_by_fields") => expression
                .get("array_path")
                .and_then(Value::as_str)
                .map(|path| value_at_path(value, path))
                .zip(
                    expression
                        .get("fields")
                        .and_then(Value::as_array)
                        .and_then(|fields| {
                            fields
                                .iter()
                                .map(Value::as_str)
                                .collect::<Option<Vec<_>>>()
                        }),
                )
                .is_some_and(|(items, fields)| array_unique_by_fields(items, &fields)),
            Some("object_fields_equal") => expression
                .get("object_paths")
                .and_then(Value::as_array)
                .filter(|paths| paths.len() == 2)
                .and_then(|paths| {
                    Some((
                        value_at_path(value, paths.first()?.as_str()?)?.as_object()?,
                        value_at_path(value, paths.get(1)?.as_str()?)?.as_object()?,
                        expression
                            .get("fields")?
                            .as_array()?
                            .iter()
                            .map(Value::as_str)
                            .collect::<Option<Vec<_>>>()?,
                    ))
                })
                .is_some_and(|(left, right, fields)| {
                    !fields.is_empty()
                        && fields.iter().all(|field| {
                            left.get(*field)
                                .zip(right.get(*field))
                                .is_some_and(|(left, right)| json_schema_equal(left, right))
                        })
                }),
            Some("jcs_sha256_equals") => jcs_sha256_matches(value, expression),
            Some("sha256_parts_equals") => sha256_parts_match(value, expression),
            Some("array_contains_value") => expression
                .get("array_path")
                .and_then(Value::as_str)
                .and_then(|path| value_at_path(value, path))
                .and_then(Value::as_array)
                .zip(
                    expression
                        .get("expected_path")
                        .and_then(Value::as_str)
                        .and_then(|path| value_at_path(value, path)),
                )
                .is_some_and(|(items, expected)| {
                    items
                        .iter()
                        .any(|candidate| json_schema_equal(candidate, expected))
                }),
            Some("array_exact_ref_coverage") => exact_ref_coverage(value, expression),
            Some("scope_pattern_matches") => expression
                .get("pattern_path")
                .and_then(Value::as_str)
                .map(|path| value_at_path(value, path))
                .zip(
                    expression
                        .get("value_path")
                        .and_then(Value::as_str)
                        .map(|path| value_at_path(value, path)),
                )
                .is_some_and(|(pattern, value)| scope_pattern_matches(pattern, value)),
            Some("field_starts_with_path") => expression
                .get("path")
                .and_then(Value::as_str)
                .and_then(|path| value_at_path(value, path))
                .and_then(Value::as_str)
                .zip(
                    expression
                        .get("expected_path")
                        .and_then(Value::as_str)
                        .and_then(|path| value_at_path(value, path))
                        .and_then(Value::as_str),
                )
                .zip(expression.get("prefix").and_then(Value::as_str))
                .is_some_and(|((actual, expected), prefix)| {
                    let stripped = match expression
                        .get("strip_prefix")
                        .and_then(Value::as_str)
                    {
                        Some(strip_prefix) => expected.strip_prefix(strip_prefix),
                        None => Some(expected),
                    };
                    stripped.is_some_and(|stripped| {
                        let suffix = expression
                            .get("suffix")
                            .and_then(Value::as_str)
                            .unwrap_or_default();
                        actual.starts_with(&format!("{prefix}{stripped}{suffix}"))
                    })
                }),
            Some("field_suffix_equals_prefixed_field") => expression
                .get("source_path")
                .and_then(Value::as_str)
                .and_then(|path| value_at_path(value, path))
                .and_then(Value::as_str)
                .zip(expression.get("delimiter").and_then(Value::as_str))
                .and_then(|(source, delimiter)| {
                    (!delimiter.is_empty())
                        .then(|| source.rsplit_once(delimiter))
                        .flatten()
                        .map(|(_, suffix)| suffix)
                })
                .filter(|suffix| !suffix.is_empty())
                .zip(
                    expression
                        .get("target_path")
                        .and_then(Value::as_str)
                        .and_then(|path| value_at_path(value, path))
                        .and_then(Value::as_str),
                )
                .zip(expression.get("target_prefix").and_then(Value::as_str))
                .is_some_and(|((suffix, target), prefix)| {
                    target == format!("{prefix}{suffix}")
                }),
            Some("matches_contract_schema_hash") => expression
                .get("path")
                .and_then(Value::as_str)
                .and_then(|path| value_at_path(value, path))
                .and_then(Value::as_str)
                .zip(architecture_contract_schema_hash(contract_id))
                .is_some_and(|(actual, expected)| actual == expected),
            Some(operator @ ("numbers_lte" | "numbers_lt")) => expression
                .get("paths")
                .and_then(Value::as_array)
                .filter(|paths| paths.len() == 2)
                .and_then(|paths| {
                    Some((
                        value_at_path(value, paths.first()?.as_str()?)?.as_number()?,
                        value_at_path(value, paths.get(1)?.as_str()?)?.as_number()?,
                    ))
                })
                .is_some_and(|(left, right)| {
                    let ordering = compare_json_numbers(left, right);
                    if operator == "numbers_lte" {
                        ordering != Ordering::Greater
                    } else {
                        ordering == Ordering::Less
                    }
                }),
            _ => false,
        };
        if !valid {
            let rule_id = rule
                .get("rule_id")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            errors.push(format!("invariant:{rule_id}"));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("\\n"))
    }
}

fn validate_projection_schema(contract_id: &str, value: &Value) -> Result<(), String> {
    let schema_text = CONTRACT_SCHEMAS
        .iter()
        .find_map(|(id, schema)| (*id == contract_id).then_some(*schema))
        .ok_or_else(|| format!("unknown contract: {contract_id}"))?;
    let schema: Value = serde_json::from_str(schema_text).map_err(|error| error.to_string())?;
    validate_node(&schema, &schema, value, "$")
}

fn validate_projection_subschema(
    contract_id: &str,
    subschema_text: &str,
    value: &Value,
) -> Result<(), String> {
    let root_text = CONTRACT_SCHEMAS
        .iter()
        .find_map(|(id, schema)| (*id == contract_id).then_some(*schema))
        .ok_or_else(|| format!("unknown contract: {contract_id}"))?;
    let root: Value = serde_json::from_str(root_text).map_err(|error| error.to_string())?;
    let subschema: Value =
        serde_json::from_str(subschema_text).map_err(|error| error.to_string())?;
    validate_node(&root, &subschema, value, "$")
}

pub fn validate_architecture_contract(contract_id: &str, value: &Value) -> Result<(), String> {
    let invariant_text = CONTRACT_INVARIANTS
        .iter()
        .find_map(|(id, rules)| (*id == contract_id).then_some(*rules))
        .unwrap_or("[]");
    let invariants: Value = serde_json::from_str(invariant_text).map_err(|error| error.to_string())?;
    validate_projection_schema(contract_id, value)?;
    validate_invariants(contract_id, &invariants, value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    const FIXTURE_BODIES: &[(&str, &str)] = &[
${fixtureBodies}
    ];
    const RAW_STRING_DELIMITER_REGRESSION_SCHEMA: &str = ${rawStringRegressionSchema};

    fn parse_projection(contract_id: &str, value: &Value) -> Result<(), String> {
        match contract_id {
${parseArms},
            _ => Err(format!("unknown projection: {contract_id}")),
        }
    }

    fn round_trip_projection(contract_id: &str, value: &Value) -> Result<Value, String> {
        match contract_id {
${roundTripArms},
            _ => Err(format!("unknown projection: {contract_id}")),
        }
    }

    fn validate_schema_only(contract_id: &str, value: &Value) -> Result<(), String> {
        validate_projection_schema(contract_id, value)
    }

    fn mutation_value(mutation: &ArchitectureContractMutation) -> Value {
        let body = FIXTURE_BODIES
            .iter()
            .find_map(|(path, body)| {
                (*path == mutation.source_fixture_path).then_some(*body)
            })
            .expect("mutation source fixture is generated");
        let mut value: Value =
            serde_json::from_str(body).expect("mutation source fixture contains JSON");
        let (parent_pointer, encoded_name) = mutation
            .patch_pointer
            .rsplit_once('/')
            .expect("mutation uses a JSON pointer");
        let name = encoded_name.replace("~1", "/").replace("~0", "~");
        let object = value
            .pointer_mut(parent_pointer)
            .and_then(Value::as_object_mut)
            .expect("mutation pointer parent is an object");
        match mutation.patch_operation {
            "set" => {
                let replacement = serde_json::from_str(
                    mutation
                        .patch_value_json
                        .expect("set mutation has a replacement"),
                )
                .expect("mutation replacement contains JSON");
                object.insert(name, replacement);
            }
            "remove" => {
                object.remove(&name).expect("removed mutation field exists");
            }
            operation => panic!("unsupported mutation operation {operation}"),
        }
        value
    }

    fn fixture_value(path: &str) -> Value {
        let body = FIXTURE_BODIES
            .iter()
            .find_map(|(candidate, body)| (*candidate == path).then_some(*body))
            .expect("fixture body is generated");
        serde_json::from_str(body).expect("fixture contains JSON")
    }

    fn set_json_pointer(value: &mut Value, pointer: &str, replacement: Value) {
        let (parent_pointer, encoded_name) =
            pointer.rsplit_once('/').expect("pointer has a parent");
        let name = encoded_name.replace("~1", "/").replace("~0", "~");
        value
            .pointer_mut(parent_pointer)
            .and_then(Value::as_object_mut)
            .expect("pointer parent is an object")
            .insert(name, replacement);
    }

    fn differential_expectations() -> (BTreeMap<String, (bool, bool)>, bool) {
        let oracle_path = match std::env::var("IOI_ARCHITECTURE_CONTRACT_AJV_ORACLE") {
            Ok(path) => path,
            Err(std::env::VarError::NotPresent) => {
                return (
                    ARCHITECTURE_CONTRACT_DIFFERENTIAL_CASES
                        .iter()
                        .map(|candidate| {
                            (
                                candidate.id.to_owned(),
                                (
                                    candidate.ajv_schema_accept,
                                    candidate.oracle_contract_accept,
                                ),
                            )
                        })
                        .collect(),
                    false,
                );
            }
            Err(error) => panic!("invalid Ajv oracle environment: {error}"),
        };
        let body = std::fs::read_to_string(&oracle_path)
            .unwrap_or_else(|error| panic!("{oracle_path}: {error}"));
        let document: Value = serde_json::from_str(&body)
            .unwrap_or_else(|error| panic!("{oracle_path}: {error}"));
        assert_eq!(
            document.get("schema_version").and_then(Value::as_str),
            Some("ioi.architecture-contract-ajv-differential.v1"),
            "{oracle_path}: unexpected live Ajv oracle schema",
        );
        let cases = document
            .get("cases")
            .and_then(Value::as_array)
            .unwrap_or_else(|| panic!("{oracle_path}: cases must be an array"));
        let mut expectations = BTreeMap::new();
        for case in cases {
            let id = case
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("{oracle_path}: differential case has no id"));
            let schema_accept = case
                .get("ajv_schema_accept")
                .and_then(Value::as_bool)
                .unwrap_or_else(|| panic!("{oracle_path}: {id} has no Ajv schema result"));
            let contract_accept = case
                .get("oracle_contract_accept")
                .and_then(Value::as_bool)
                .unwrap_or_else(|| panic!("{oracle_path}: {id} has no contract result"));
            assert!(
                expectations
                    .insert(id.to_owned(), (schema_accept, contract_accept))
                    .is_none(),
                "{oracle_path}: duplicate differential case {id}",
            );
        }
        assert_eq!(
            expectations.len(),
            ARCHITECTURE_CONTRACT_DIFFERENTIAL_CASES.len(),
            "{oracle_path}: live Ajv corpus size differs from the generated Rust corpus",
        );
        for candidate in ARCHITECTURE_CONTRACT_DIFFERENTIAL_CASES {
            assert!(
                expectations.contains_key(candidate.id),
                "{oracle_path}: live Ajv corpus is missing {}",
                candidate.id,
            );
        }
        (expectations, true)
    }

    #[test]
    fn golden_fixtures_match_generated_rust_contracts() {
        assert_eq!(
            ARCHITECTURE_CONTRACT_FIXTURES.len(),
            ${fixtures.length},
            "the registered golden corpus must remain the explicit ${fixtures.length}-fixture bar",
        );
        for fixture in ARCHITECTURE_CONTRACT_FIXTURES {
            let body = FIXTURE_BODIES
                .iter()
                .find_map(|(path, body)| (*path == fixture.path).then_some(*body))
                .expect("fixture body is generated");
            let value: Value = serde_json::from_str(body).expect("fixture contains JSON");
            let schema_result = validate_schema_only(fixture.contract_id, &value);
            assert_eq!(
                schema_result.is_ok(),
                fixture.expected_schema_accept,
                "fixture {} expected_schema_accept={} schema_result={schema_result:?}",
                fixture.path,
                fixture.expected_schema_accept,
            );
            let result = validate_architecture_contract(fixture.contract_id, &value)
                .and_then(|_| round_trip_projection(fixture.contract_id, &value))
                .and_then(|serialized| {
                    validate_architecture_contract(fixture.contract_id, &serialized)
                        .map(|_| serialized)
                });
            assert_eq!(
                result.is_ok(),
                fixture.expected_accept,
                "fixture {} expected_accept={} result={result:?}",
                fixture.path,
                fixture.expected_accept,
            );
            if let (Some(expected_rule), Err(error)) = (fixture.expected_rule_id, &result) {
                assert!(error.contains(expected_rule), "{}: {error}", fixture.path);
            }
        }
    }

    #[test]
    fn adversarial_mutations_match_ajv_expectations_and_cover_every_keyword() {
        let expected_keywords = ARCHITECTURE_CONTRACT_ASSERTION_KEYWORDS
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let covered_keywords = ARCHITECTURE_CONTRACT_MUTATIONS
            .iter()
            .flat_map(|mutation| mutation.covered_keywords.iter().copied())
            .collect::<BTreeSet<_>>();
        assert_eq!(covered_keywords, expected_keywords);

        for mutation in ARCHITECTURE_CONTRACT_MUTATIONS {
            let value = mutation_value(mutation);
            let schema_result = validate_schema_only(mutation.contract_id, &value);
            assert_eq!(
                schema_result.is_ok(),
                mutation.ajv_expected_accept,
                "mutation {} from {} expected Ajv acceptance={} result={schema_result:?}",
                mutation.id,
                mutation.source_fixture_path,
                mutation.ajv_expected_accept,
            );
            let contract_result = validate_architecture_contract(mutation.contract_id, &value);
            assert_eq!(
                contract_result.is_ok(),
                mutation.oracle_contract_accept,
                "mutation {} contract result={contract_result:?}",
                mutation.id,
            );
            if let Err(error) = &contract_result {
                for expected_rule in mutation.expected_rule_ids {
                    assert!(
                        error.contains(expected_rule),
                        "mutation {} missing declared rule {}: {error}",
                        mutation.id,
                        expected_rule,
                    );
                }
            }
        }
    }

    #[test]
    fn live_ajv_differential_corpus_matches_rust_validator_and_deserializer() {
        let (expectations, live_oracle) = differential_expectations();
        let oracle_label = if live_oracle {
            "live Ajv subprocess oracle"
        } else {
            "generation-time Ajv oracle"
        };
        for candidate in ARCHITECTURE_CONTRACT_DIFFERENTIAL_CASES {
            let (expected_schema_accept, expected_contract_accept) = expectations
                .get(candidate.id)
                .copied()
                .unwrap_or_else(|| panic!("missing Ajv expectation for {}", candidate.id));
            let value: Value = if let Some(value_json) = candidate.value_json {
                serde_json::from_str(value_json)
                    .unwrap_or_else(|error| panic!("{}: {error}", candidate.id))
            } else if let Some(mutation_id) = candidate.mutation_id {
                let mutation = ARCHITECTURE_CONTRACT_MUTATIONS
                    .iter()
                    .find(|mutation| mutation.id == mutation_id)
                    .unwrap_or_else(|| panic!("{}: missing mutation {mutation_id}", candidate.id));
                mutation_value(mutation)
            } else {
                fixture_value(
                    candidate
                        .source_fixture_path
                        .unwrap_or_else(|| panic!("{}: missing differential source", candidate.id)),
                )
            };
            let schema_result = validate_schema_only(candidate.contract_id, &value);
            assert_eq!(
                schema_result.is_ok(),
                expected_schema_accept,
                "{}: Rust schema result={schema_result:?} disagreed with {oracle_label}",
                candidate.id,
            );
            let projection_result = parse_projection(candidate.contract_id, &value);
            assert_eq!(
                projection_result.is_ok(),
                expected_schema_accept,
                "{}: direct Rust projection result={projection_result:?} disagreed with {oracle_label}",
                candidate.id,
            );
            let contract_result = validate_architecture_contract(candidate.contract_id, &value);
            assert_eq!(
                contract_result.is_ok(),
                expected_contract_accept,
                "{}: Rust contract result={contract_result:?} disagreed with {oracle_label} plus portable invariants",
                candidate.id,
            );
        }
        for candidate in ARCHITECTURE_CONTRACT_JCS_DIFFERENTIAL_CASES {
            let value: Value = serde_json::from_str(candidate.value_json)
                .unwrap_or_else(|error| panic!("{}: {error}", candidate.id));
            let canonical = canonical_json_for_hash(&value)
                .unwrap_or_else(|| panic!("{}: canonicalization failed", candidate.id));
            assert_eq!(
                canonical,
                candidate.expected_canonical,
                "{}: Rust JCS key ordering differs from the ECMAScript UTF-16 oracle",
                candidate.id,
            );
        }
    }

    #[test]
    fn exact_json_number_equality_preserves_unique_items_semantics() {
        const CONTRACT_ID: &str =
            "schema://ioi/foundations/authority-key-set/v1";
        const FIXTURE_PATH: &str =
            "docs/architecture/_meta/schemas/fixtures/authority-key-set-v1/positive-active.json";

        let with_not_before_numbers = |first: &str, second: &str| {
            let mut value = fixture_value(FIXTURE_PATH);
            let key = value["keys"][0].clone();
            let mut first_key = key.clone();
            first_key["not_before"] =
                serde_json::from_str(first).expect("first exact JSON number");
            let mut second_key = key;
            second_key["not_before"] =
                serde_json::from_str(second).expect("second exact JSON number");
            value["keys"] = Value::Array(vec![first_key, second_key]);
            value
        };

        let distinct_portable_boundary = with_not_before_numbers(
            "9007199254740990",
            "9007199254740991",
        );
        assert!(
            validate_schema_only(CONTRACT_ID, &distinct_portable_boundary)
                .is_ok(),
            "adjacent exact integers at the portable boundary remain unique",
        );
        assert!(
            validate_architecture_contract(
                CONTRACT_ID,
                &distinct_portable_boundary,
            )
                .and_then(|_| {
                    parse_projection(
                        CONTRACT_ID,
                        &distinct_portable_boundary,
                    )
                })
                .is_ok(),
            "registered Rust validator and projection accept distinct portable integers",
        );

        let equal_integer_decimal = with_not_before_numbers("1", "1.0");
        assert!(
            validate_schema_only(CONTRACT_ID, &equal_integer_decimal).is_err(),
            "JSON numbers 1 and 1.0 are mathematically equal for uniqueItems",
        );
        assert!(json_schema_equal(
            &serde_json::from_str("1").expect("integer JSON number"),
            &serde_json::from_str("1.0").expect("decimal JSON number"),
        ));
        assert!(!json_schema_equal(
            &serde_json::from_str("9007199254740990")
                .expect("first portable JSON number"),
            &serde_json::from_str("9007199254740991")
                .expect("second portable JSON number"),
        ));
    }

    #[test]
    fn canonical_rfc3339_profile_is_shared_by_rust_projection() {
        const CONTRACT_ID: &str =
            "schema://ioi/foundations/authority-grant-envelope/v1";
        const FIXTURE_PATH: &str =
            "docs/architecture/_meta/schemas/fixtures/authority-grant-envelope-v1/positive-active.json";
        for (candidate, expected) in [
            ("2025-01-01T23:59:60Z", true),
            ("2025-01-02T00:59:60+01:00", true),
            ("2025-01-01 23:59:59Z", false),
            ("2025-01-01T23:59:59+0100", false),
            ("2025-01-01T23:59:59+01", false),
            ("2025-01-01T24:59:60+01:00", false),
            ("2025-01-01T23:60:60+00:01", false),
        ] {
            let mut value = fixture_value(FIXTURE_PATH);
            value["constraints"]["expires_at"] =
                Value::String(candidate.to_owned());
            assert_eq!(
                validate_schema_only(CONTRACT_ID, &value).is_ok(),
                expected,
                "Rust validator diverged from the portable canonical RFC3339 oracle for {candidate}",
            );
            assert_eq!(
                parse_projection(CONTRACT_ID, &value).is_ok(),
                expected,
                "direct Rust projection diverged from the portable canonical RFC3339 oracle for {candidate}",
            );
        }
    }

    #[test]
    fn registered_ecma_pattern_translations_compile_and_match_whitespace() {
        assert_eq!(
            CONTRACT_PATTERN_TRANSLATIONS.len(),
            ${registeredPatternTranslations.size},
        );
        for (ecma, translated) in CONTRACT_PATTERN_TRANSLATIONS {
            Regex::new(translated)
                .unwrap_or_else(|error| panic!("{ecma}: {error}"));
        }
        let translated = CONTRACT_PATTERN_TRANSLATIONS
            .iter()
            .find_map(|(ecma, translated)| {
                (*ecma == r"^schema://[^\\s]+$").then_some(*translated)
            })
            .expect("registered schema-ref pattern is translated");
        let regex = Regex::new(translated).expect("translated pattern compiles");
        assert!(!regex.is_match("schema://ioi/test/\\u{feff}"));
        assert!(regex.is_match("schema://ioi/test/\\u{0085}"));
    }

    #[test]
    fn schema_invalid_values_refuse_direct_projection_deserialization() {
        for mutation in ARCHITECTURE_CONTRACT_MUTATIONS
            .iter()
            .filter(|mutation| mutation.direct_projection_rejection)
        {
            let value = mutation_value(mutation);
            let result = parse_projection(mutation.contract_id, &value);
            assert!(
                result.is_err(),
                "closed literal mutation {} deserialized directly",
                mutation.id,
            );
        }
    }

    #[test]
    fn required_nulls_and_closed_integer_enums_have_non_forgeable_rust_shapes() {
        let materialization = fixture_value(
            "docs/architecture/_meta/schemas/fixtures/autonomous-system-sequence-zero-materialization-v1/positive-materialized-pending-activation.json",
        );
        let projected_materialization =
            serde_json::from_value::<AutonomousSystemSequenceZeroMaterializationV1>(
                materialization,
            )
            .expect("standalone materialization projection accepts the positive fixture");
        assert_eq!(
            projected_materialization.predecessor_transition_commitment_ref,
            (),
        );
        assert_eq!(projected_materialization.activation_receipt_ref, ());
        assert_eq!(
            projected_materialization
                .profile_refs
                .deployment_profile_ref,
            "deployment-profile://acme/system-alpha/local",
            "the generated contract keeps the positive M1.3 unversioned deployment-ref compatibility lane",
        );
        assert_eq!(
            projected_materialization.deployment_profile_root,
            "sha256:ee5ab54256128a684db83aee604c9fb21c5725af3eeccd95d8a867693b8ec9f9",
            "the legacy deployment ref binds its domain-separated compatibility root",
        );

        let receipt = fixture_value(
            "docs/architecture/_meta/schemas/fixtures/autonomous-system-sequence-zero-materialization-receipt-v2/positive-materialized-pending-activation.json",
        );
        let projected_receipt =
            serde_json::from_value::<AutonomousSystemSequenceZeroMaterializationReceiptV2>(
                receipt,
            )
            .expect("receipt projection accepts the positive fixture");
        assert_eq!(projected_receipt.verification_ref, ());
        assert_eq!(projected_receipt.acceptance_ref, ());

        let suite =
            AutonomousSystemSequenceZeroMaterializationReceiptV2WalletApprovalGrantApproverSuite::Negative8;
        assert_eq!(
            serde_json::to_value(suite).expect("closed suite serializes"),
            serde_json::json!(-8),
        );
        assert!(
            serde_json::from_value::<
                AutonomousSystemSequenceZeroMaterializationReceiptV2WalletApprovalGrantApproverSuite,
            >(serde_json::json!(-100))
            .is_err(),
            "closed integer enum refuses an invalid wire value",
        );
    }

    #[test]
    fn nested_public_projection_deserialization_preserves_nullability() {
        let physical = fixture_value(
            "docs/architecture/_meta/schemas/fixtures/physical-action-execution-receipt-v1/positive-committed.json",
        );
        let mut receipt_envelope = physical["receipt_envelope"].clone();
        serde_json::from_value::<PhysicalActionExecutionReceiptV1ReceiptEnvelope>(
            receipt_envelope.clone(),
        )
        .expect("nested required-nullable projection accepts a present value");
        receipt_envelope["claim_scope_ref"] = Value::Null;
        let nested_receipt =
            serde_json::from_value::<PhysicalActionExecutionReceiptV1ReceiptEnvelope>(
                receipt_envelope.clone(),
            )
            .expect("nested required-nullable projection accepts explicit null");
        let serialized_receipt =
            serde_json::to_value(nested_receipt).expect("nested receipt serializes");
        assert!(
            serialized_receipt
                .as_object()
                .is_some_and(|object| object.contains_key("claim_scope_ref")),
            "required nullable nested field must serialize explicitly",
        );
        assert!(serialized_receipt["claim_scope_ref"].is_null());
        serde_json::from_value::<PhysicalActionExecutionReceiptV1ReceiptEnvelope>(
            serialized_receipt,
        )
        .expect("serialized required-nullable nested projection remains schema-valid");
        receipt_envelope
            .as_object_mut()
            .expect("receipt envelope is an object")
            .remove("claim_scope_ref");
        assert!(
            serde_json::from_value::<PhysicalActionExecutionReceiptV1ReceiptEnvelope>(
                receipt_envelope,
            )
            .is_err(),
            "nested required-nullable projection accepted a missing field",
        );

        let authority = fixture_value(
            "docs/architecture/_meta/schemas/fixtures/authority-grant-envelope-v1/positive-active.json",
        );
        let mut constraints = authority["constraints"].clone();
        serde_json::from_value::<AuthorityGrantEnvelopeV1Constraints>(constraints.clone())
            .expect("nested optional-non-nullable projection accepts a present value");
        constraints
            .as_object_mut()
            .expect("constraints are an object")
            .remove("max_calls");
        let nested_constraints =
            serde_json::from_value::<AuthorityGrantEnvelopeV1Constraints>(
                constraints.clone(),
            )
            .expect("nested optional-non-nullable projection accepts absence");
        let serialized_constraints =
            serde_json::to_value(nested_constraints).expect("nested constraints serialize");
        assert!(
            serialized_constraints.get("max_calls").is_none(),
            "optional non-nullable max_calls must stay omitted when None",
        );
        serde_json::from_value::<AuthorityGrantEnvelopeV1Constraints>(
            serialized_constraints,
        )
        .expect("serialized optional nested projection remains schema-valid");
        constraints["max_calls"] = Value::Null;
        assert!(
            serde_json::from_value::<AuthorityGrantEnvelopeV1Constraints>(constraints).is_err(),
            "nested optional-non-nullable projection accepted explicit null",
        );
    }

    #[test]
    fn system_status_claims_require_their_exact_evidence_sets() {
        let assert_rejected = |contract: &str, value: &Value, label: &str| {
            assert!(
                validate_architecture_contract(contract, value).is_err(),
                "{label}",
            );
        };
        let manifest_contract =
            "schema://ioi/foundations/autonomous-system-manifest/v1";
        let mut draft_manifest = fixture_value(
            "docs/architecture/_meta/schemas/fixtures/autonomous-system-manifest-v1/positive-reusable-release.json",
        );
        draft_manifest["registry_status"] = Value::String("draft".to_owned());
        draft_manifest["receipts"]["package_readiness_receipt_ref"] = Value::Null;
        draft_manifest["release"]["publisher_signature_ref"] = Value::Null;
        draft_manifest["release"]["registry_published_at"] = Value::Null;
        validate_architecture_contract(manifest_contract, &draft_manifest)
            .expect("draft manifest is free of terminal registry proof");
        for (pointer, residue) in [
            (
                "/receipts/package_readiness_receipt_ref",
                Value::String("receipt://acme/package-ready/v1".to_owned()),
            ),
            (
                "/release/publisher_signature_ref",
                Value::String("evidence://acme/package-signature/v1".to_owned()),
            ),
            (
                "/release/registry_published_at",
                Value::String("2026-07-18T12:00:00Z".to_owned()),
            ),
        ] {
            let mut residue_manifest = draft_manifest.clone();
            set_json_pointer(&mut residue_manifest, pointer, residue);
            assert_rejected(
                manifest_contract,
                &residue_manifest,
                "draft manifest carried terminal registry proof residue",
            );
        }

        let genesis_contract =
            "schema://ioi/foundations/autonomous-system-genesis/v1";
        let mut authorized = fixture_value(
            "docs/architecture/_meta/schemas/fixtures/autonomous-system-genesis-v1/positive-proposed.json",
        );
        authorized["status"] = Value::String("authorized".to_owned());
        authorized["cryptographic_origin"]["admission_proof_ref"] =
            Value::String("receipt://acme/system-alpha/admission".to_owned());
        authorized["instantiation"]["authority_grant_refs"] =
            serde_json::json!(["grant://acme/system-alpha/genesis"]);
        authorized["status_source_receipt_refs"] =
            serde_json::json!(["receipt://acme/system-alpha/authorized-status"]);
        validate_architecture_contract(genesis_contract, &authorized)
            .expect("authorized genesis carries admission, authority, and status evidence");
        for (label, pointer, replacement) in [
            (
                "authorized genesis omitted admission proof",
                "/cryptographic_origin/admission_proof_ref",
                Value::Null,
            ),
            (
                "authorized genesis omitted authority evidence",
                "/instantiation/authority_grant_refs",
                serde_json::json!([]),
            ),
            (
                "authorized genesis omitted status evidence",
                "/status_source_receipt_refs",
                serde_json::json!([]),
            ),
        ] {
            let mut missing = authorized.clone();
            set_json_pointer(&mut missing, pointer, replacement);
            assert_rejected(genesis_contract, &missing, label);
        }

        let mut activated = authorized.clone();
        activated["status"] = Value::String("activated".to_owned());
        activated["activation_receipt_ref"] =
            Value::String("receipt://acme/system-alpha/activation".to_owned());
        activated["lifecycle_transition_refs"] =
            serde_json::json!(["lifecycle-transition://acme/system-alpha/activate"]);
        validate_architecture_contract(genesis_contract, &activated)
            .expect("activated genesis carries activation and lifecycle evidence");
        for (label, pointer, replacement) in [
            (
                "activated genesis omitted activation receipt",
                "/activation_receipt_ref",
                Value::Null,
            ),
            (
                "activated genesis omitted lifecycle receipt",
                "/lifecycle_transition_refs",
                serde_json::json!([]),
            ),
        ] {
            let mut missing = activated.clone();
            set_json_pointer(&mut missing, pointer, replacement);
            assert_rejected(genesis_contract, &missing, label);
        }

        let proposed_genesis = fixture_value(
            "docs/architecture/_meta/schemas/fixtures/autonomous-system-genesis-v1/positive-proposed.json",
        );
        for (label, pointer, replacement) in [
            (
                "proposed genesis carried admission residue",
                "/cryptographic_origin/admission_proof_ref",
                Value::String("receipt://acme/system-alpha/admission".to_owned()),
            ),
            (
                "proposed genesis carried activation residue",
                "/activation_receipt_ref",
                Value::String("receipt://acme/system-alpha/activation".to_owned()),
            ),
            (
                "proposed genesis carried authority residue",
                "/instantiation/authority_grant_refs",
                serde_json::json!(["grant://acme/system-alpha/genesis"]),
            ),
            (
                "proposed genesis carried conformance residue",
                "/instantiation/conformance_receipt_refs",
                serde_json::json!(["receipt://acme/system-alpha/conformance"]),
            ),
            (
                "proposed genesis carried lifecycle residue",
                "/lifecycle_transition_refs",
                serde_json::json!(["lifecycle-transition://acme/system-alpha/activate"]),
            ),
            (
                "proposed genesis carried status residue",
                "/status_source_receipt_refs",
                serde_json::json!(["receipt://acme/system-alpha/status"]),
            ),
        ] {
            let mut residue = proposed_genesis.clone();
            set_json_pointer(&mut residue, pointer, replacement);
            assert_rejected(genesis_contract, &residue, label);
        }

        let constitution_contract =
            "schema://ioi/foundations/autonomous-system-constitution/v1";
        let mut constitution = fixture_value(
            "docs/architecture/_meta/schemas/fixtures/autonomous-system-constitution-v1/positive-draft.json",
        );
        constitution["status"] = Value::String("active".to_owned());
        constitution["activation_receipt_ref"] =
            Value::String("receipt://acme/system-alpha/constitution-activation".to_owned());
        validate_architecture_contract(constitution_contract, &constitution)
            .expect("active constitution carries its activation receipt");
        let mut missing_constitution_activation = constitution;
        missing_constitution_activation["activation_receipt_ref"] = Value::Null;
        assert_rejected(
            constitution_contract,
            &missing_constitution_activation,
            "active constitution omitted activation receipt",
        );
        let draft_constitution = fixture_value(
            "docs/architecture/_meta/schemas/fixtures/autonomous-system-constitution-v1/positive-draft.json",
        );
        for (field, residue) in [
            (
                "activation_receipt_ref",
                Value::String("receipt://acme/system-alpha/constitution-activation".to_owned()),
            ),
            (
                "public_commitment_ref",
                Value::String("commitment://acme/system-alpha/constitution".to_owned()),
            ),
        ] {
            let mut draft_with_residue = draft_constitution.clone();
            draft_with_residue[field] = residue;
            assert_rejected(
                constitution_contract,
                &draft_with_residue,
                "draft constitution carried terminal proof residue",
            );
        }

        let amendment_contract =
            "schema://ioi/foundations/autonomous-system-constitution-amendment/v1";
        let mut proposed_amendment = fixture_value(
            "docs/architecture/_meta/schemas/fixtures/autonomous-system-constitution-amendment-v1/positive-proposed.json",
        );
        proposed_amendment["decision_ref"] =
            Value::String("decision://acme/system-alpha/amendment".to_owned());
        assert_rejected(
            amendment_contract,
            &proposed_amendment,
            "proposed constitution amendment carried terminal decision residue",
        );

        let ordering_contract =
            "schema://ioi/foundations/ordering-admission-finality-profile/v1";
        let mut ordering = fixture_value(
            "docs/architecture/_meta/schemas/fixtures/ordering-admission-finality-profile-v1/positive-single-authority.json",
        );
        ordering["status"] = Value::String("active".to_owned());
        ordering["conformance_receipt_refs"] =
            serde_json::json!(["receipt://acme/system-alpha/ordering-conformance"]);
        validate_architecture_contract(ordering_contract, &ordering)
            .expect("active ordering profile carries conformance evidence");
        let mut missing_ordering_evidence = ordering;
        missing_ordering_evidence["conformance_receipt_refs"] = serde_json::json!([]);
        assert_rejected(
            ordering_contract,
            &missing_ordering_evidence,
            "active ordering profile omitted conformance evidence",
        );
        let mut draft_ordering_residue = fixture_value(
            "docs/architecture/_meta/schemas/fixtures/ordering-admission-finality-profile-v1/positive-single-authority.json",
        );
        draft_ordering_residue["conformance_receipt_refs"] =
            serde_json::json!(["receipt://acme/system-alpha/ordering-conformance"]);
        assert_rejected(
            ordering_contract,
            &draft_ordering_residue,
            "draft ordering profile carried conformance residue",
        );

        let lifecycle_contract =
            "schema://ioi/foundations/lifecycle-transition/v1";
        let mut transition = fixture_value(
            "docs/architecture/_meta/schemas/fixtures/lifecycle-transition-v1/positive-initialize-proposal.json",
        );
        transition["decision_ref"] =
            Value::String("decision://acme/system-alpha/initialize".to_owned());
        transition["authority_grant_refs"] =
            serde_json::json!(["grant://acme/system-alpha/initialize"]);
        transition["resulting_state_root"] =
            Value::String(format!("sha256:{}", "e".repeat(64)));
        transition["operation_commitment"] =
            Value::String(format!("sha256:{}", "d".repeat(64)));
        transition["receipt_refs"] =
            serde_json::json!(["receipt://acme/system-alpha/initialize"]);
        transition["status"] = Value::String("committed".to_owned());
        validate_architecture_contract(lifecycle_contract, &transition)
            .expect("committed lifecycle transition carries its terminal proof set");
        for (field, replacement) in [
            ("decision_ref", Value::Null),
            ("authority_grant_refs", serde_json::json!([])),
            ("resulting_state_root", Value::Null),
            ("operation_commitment", Value::Null),
            ("receipt_refs", serde_json::json!([])),
        ] {
            let mut missing = transition.clone();
            missing[field] = replacement;
            assert_rejected(
                lifecycle_contract,
                &missing,
                "committed lifecycle transition omitted required proof",
            );
        }
        let proposed_transition = fixture_value(
            "docs/architecture/_meta/schemas/fixtures/lifecycle-transition-v1/positive-initialize-proposal.json",
        );
        for (field, residue) in [
            (
                "decision_ref",
                Value::String("decision://acme/system-alpha/initialize".to_owned()),
            ),
            (
                "authority_grant_refs",
                serde_json::json!(["grant://acme/system-alpha/initialize"]),
            ),
            (
                "resulting_state_root",
                Value::String(format!("sha256:{}", "e".repeat(64))),
            ),
            (
                "operation_commitment",
                Value::String(format!("sha256:{}", "d".repeat(64))),
            ),
            (
                "state_transition_commitment_ref",
                Value::String("transition://acme/system-alpha/initialize".to_owned()),
            ),
            (
                "disposition_receipt_refs",
                serde_json::json!(["receipt://acme/system-alpha/disposition"]),
            ),
            (
                "receipt_refs",
                serde_json::json!(["receipt://acme/system-alpha/initialize"]),
            ),
            (
                "public_commitment_ref",
                Value::String("commitment://acme/system-alpha/initialize".to_owned()),
            ),
        ] {
            let mut proposed_with_residue = proposed_transition.clone();
            proposed_with_residue[field] = residue;
            assert_rejected(
                lifecycle_contract,
                &proposed_with_residue,
                "proposed lifecycle transition carried terminal proof residue",
            );
        }

        let enrollment_contract =
            "schema://ioi/foundations/ioi-network-enrollment/v1";
        let mut connected = fixture_value(
            "docs/architecture/_meta/schemas/fixtures/ioi-network-enrollment-v1/negative-compatible-selected-service.json",
        );
        connected["profile"] = Value::String("ioi_connected".to_owned());
        connected["status"] = Value::String("active".to_owned());
        connected["assurance_claim"] =
            Value::String("connected_services_only".to_owned());
        connected["connection"]["network_ref"] =
            Value::String("network://ioi-l1".to_owned());
        connected["authority_grant_refs"] =
            serde_json::json!(["grant://acme/system-alpha/network-enrollment"]);
        connected["transition_receipt_refs"] =
            serde_json::json!(["receipt://acme/system-alpha/network-activation"]);
        validate_architecture_contract(enrollment_contract, &connected)
            .expect("connected active enrollment carries authority and transition receipts");
        let mut missing_authority = connected.clone();
        missing_authority["authority_grant_refs"] = serde_json::json!([]);
        assert_rejected(
            enrollment_contract,
            &missing_authority,
            "connected active enrollment omitted authority evidence",
        );
        let mut missing_transition_receipt = connected.clone();
        missing_transition_receipt["transition_receipt_refs"] = serde_json::json!([]);
        assert_rejected(
            enrollment_contract,
            &missing_transition_receipt,
            "connected active enrollment omitted transition receipt",
        );

        let mut secured = connected;
        secured["profile"] = Value::String("ioi_secured".to_owned());
        secured["assurance_claim"] = Value::String("secured_profile".to_owned());
        secured["standard_das_conformance_profile_ref"] =
            Value::String("conformance-profile://acme/standard-das".to_owned());
        secured["conformance"]["conformance_receipt_refs"] =
            serde_json::json!(["receipt://acme/system-alpha/standard-das-conformance"]);
        validate_architecture_contract(enrollment_contract, &secured)
            .expect("secured active enrollment carries conformance evidence");
        secured["conformance"]["conformance_receipt_refs"] = serde_json::json!([]);
        assert_rejected(
            enrollment_contract,
            &secured,
            "secured active enrollment omitted conformance evidence",
        );
    }

    #[test]
    fn invariant_runtime_rejects_absent_operands_and_uses_portable_scalar_equality() {
        let missing_rules = serde_json::json!([{
            "rule_id": "generated.fields-equal-missing",
            "expression": {
                "operator": "fields_equal",
                "paths": ["$.left", "$.right"],
            },
        }]);
        assert!(
            validate_invariants("generated-regression", &missing_rules, &serde_json::json!({}))
                .is_err(),
            "missing fields_equal operands must not compare equal",
        );

        let scalar_rules = serde_json::json!([{
            "rule_id": "generated.scalar-condition-equality",
            "expression": {
                "operator": "non_empty_when_in",
                "path": "$.evidence",
                "when_path": "$.mode",
                "values": [-0.0],
            },
        }]);
        assert!(
            validate_invariants(
                "generated-regression",
                &scalar_rules,
                &serde_json::json!({"mode": 0, "evidence": []}),
            )
            .is_err(),
            "portable JSON number equality must treat negative zero and zero as equal",
        );
    }

    #[test]
    fn indexed_invariant_paths_are_strict_and_fields_equal_reads_exact_slots() {
        let value = serde_json::json!({
            "entries": ["first", "second"],
            "not_an_array": {"0": "first"},
        });
        assert_eq!(
            value_at_path(&value, "$.entries[0]"),
            Some(&Value::String("first".to_owned())),
        );
        assert_eq!(
            value_at_path(&value, "$.entries[1]"),
            Some(&Value::String("second".to_owned())),
        );
        for refused in [
            "$.entries[2]",
            "$.entries[01]",
            "$.entries[x]",
            "$.entries[0][1]",
            "$.not_an_array[0]",
        ] {
            assert_eq!(value_at_path(&value, refused), None, "{refused}");
        }

        let rules = serde_json::json!([
            {
                "rule_id": "indexed.first",
                "expression": {
                    "operator": "fields_equal",
                    "paths": ["$.sequence_one.transition_ref", "$.transition_refs[0]"]
                }
            },
            {
                "rule_id": "indexed.second",
                "expression": {
                    "operator": "fields_equal",
                    "paths": ["$.sequence_two.transition_ref", "$.transition_refs[1]"]
                }
            }
        ]);
        let valid = serde_json::json!({
            "sequence_one": {"transition_ref": "transition://one"},
            "sequence_two": {"transition_ref": "transition://two"},
            "transition_refs": ["transition://one", "transition://two"],
        });
        validate_invariants("indexed-regression", &rules, &valid)
            .expect("indexed fields_equal accepts exact slots");
        for (index, expected_rule) in [(0, "indexed.first"), (1, "indexed.second")] {
            let mut mutated = valid.clone();
            mutated["transition_refs"][index] = Value::String("transition://forged".to_owned());
            let error = validate_invariants("indexed-regression", &rules, &mutated)
                .expect_err("indexed slot mutation refuses");
            assert!(error.contains(expected_rule), "{error}");
        }
    }

    #[test]
    fn boolean_const_projection_uses_a_literal_type() {
        let literal =
            AutonomousSystemConstitutionV1GovernanceAgentMayCommitAmendment::False;
        assert_eq!(
            serde_json::to_value(literal).expect("literal false serializes"),
            Value::Bool(false),
        );
        assert!(
            serde_json::from_value::<
                AutonomousSystemConstitutionV1GovernanceAgentMayCommitAmendment,
            >(Value::Bool(true))
            .is_err(),
            "literal-false projection accepted true",
        );
        serde_json::from_value::<
            AutonomousSystemConstitutionV1GovernanceAgentMayCommitAmendment,
        >(Value::Bool(false))
        .expect("literal-false projection accepts false");
    }

    #[test]
    fn dynamic_raw_string_delimiter_survives_schema_controlled_hashes() {
        let schema: Value = serde_json::from_str(RAW_STRING_DELIMITER_REGRESSION_SCHEMA)
            .expect("dynamic raw literal contains JSON");
        assert_eq!(
            schema["const"],
            Value::String("schema-controlled\\\"###literal".to_owned()),
        );
    }
}
`;
}

function formatRust(source) {
  const toolchain = pinnedRustToolchain();
  verifyPinnedRustfmt(toolchain);
  const temporaryDirectory = fs.mkdtempSync(
    path.join(os.tmpdir(), "ioi-architecture-contracts-"),
  );
  const temporaryPath = path.join(
    temporaryDirectory,
    "architecture_contracts.rs",
  );
  try {
    fs.writeFileSync(temporaryPath, source);
    const result = spawnSync(
      "rustup",
      ["run", toolchain, "rustfmt", "--edition", "2021", temporaryPath],
      {
        cwd: root,
        encoding: "utf8",
      },
    );
    if (result.status !== 0) {
      throw new Error(
        `rustfmt failed for generated architecture contracts: ${result.stderr}`,
      );
    }
    return fs.readFileSync(temporaryPath, "utf8");
  } finally {
    fs.rmSync(temporaryDirectory, { force: true, recursive: true });
  }
}

function pinnedRustToolchain() {
  const toolchainPath = path.join(root, "rust-toolchain.toml");
  const source = fs.readFileSync(toolchainPath, "utf8");
  const match = /^\s*channel\s*=\s*"([^"]+)"\s*$/mu.exec(source);
  if (!match || !/^[0-9]+\.[0-9]+\.[0-9]+$/u.test(match[1])) {
    throw new Error(
      "rust-toolchain.toml must pin an exact semantic Rust toolchain version",
    );
  }
  return match[1];
}

function verifyPinnedRustfmt(toolchain) {
  const rustc = spawnSync("rustup", ["run", toolchain, "rustc", "--version"], {
    cwd: root,
    encoding: "utf8",
  });
  const rustfmt = spawnSync(
    "rustup",
    ["run", toolchain, "rustfmt", "--version"],
    {
      cwd: root,
      encoding: "utf8",
    },
  );
  if (
    rustc.status !== 0 ||
    !rustc.stdout.startsWith(`rustc ${toolchain} `) ||
    rustfmt.status !== 0 ||
    !/^rustfmt [0-9.]+/u.test(rustfmt.stdout)
  ) {
    throw new Error(
      `Pinned Rust formatter toolchain ${toolchain} is unavailable or mismatched: ` +
        `${(rustc.stderr || rustc.stdout).trim()} ${(rustfmt.stderr || rustfmt.stdout).trim()}`,
    );
  }
}

function runGeneratorCapabilityRegressions() {
  const missingOperandErrors = generatorInvariantErrors(
    {
      schema: { type: "object" },
      invariants: [{
        rules: [{
          rule_id: "generator-regression.fields-equal-missing",
          expression: {
            operator: "fields_equal",
            paths: ["$.left", "$.right"],
          },
        }],
      }],
    },
    {},
  );
  if (
    canonicalJson(missingOperandErrors) !==
      canonicalJson(["generator-regression.fields-equal-missing"])
  ) {
    throw new Error(
      "Generator regression: absent fields_equal operands did not fail closed",
    );
  }

  const scalarConditionErrors = generatorInvariantErrors(
    {
      schema: { type: "object" },
      invariants: [{
        rules: [{
          rule_id: "generator-regression.scalar-condition-equality",
          expression: {
            operator: "non_empty_when_in",
            path: "$.evidence",
            when_path: "$.mode",
            values: [-0],
          },
        }],
      }],
    },
    { mode: 0, evidence: [] },
  );
  if (
    canonicalJson(scalarConditionErrors) !==
      canonicalJson(["generator-regression.scalar-condition-equality"])
  ) {
    throw new Error(
      "Generator regression: portable scalar equality drifted for negative zero",
    );
  }

  const prototypeMaterialExpression = JSON.parse(
    '{"material_fields":{"__proto__":{"value":"retained"}}}',
  );
  const prototypeMaterial = generatorInvariantMaterial(
    {},
    prototypeMaterialExpression,
  );
  if (
    !isPlainObject(prototypeMaterial) ||
    Object.getPrototypeOf(prototypeMaterial) !== null ||
    !Object.hasOwn(prototypeMaterial, "__proto__") ||
    prototypeMaterial.__proto__ !== "retained"
  ) {
    throw new Error(
      "Generator regression: invariant hash material is prototype-sensitive",
    );
  }

  let rejectedUnsupportedAssertion = false;
  try {
    inventorySchemaKeywords(
      { type: "string", minProperties: 1 },
      "generator-regression.unsupported",
    );
  } catch (error) {
    rejectedUnsupportedAssertion =
      error instanceof Error &&
      error.message.includes("unsupported JSON Schema keyword");
  }
  if (!rejectedUnsupportedAssertion) {
    throw new Error(
      "Generator regression: unsupported assertion keyword did not fail closed",
    );
  }

  for (const [id, schema] of [
    ["unbounded", { type: "integer", minimum: 0 }],
    [
      "over-domain",
      {
        type: "integer",
        minimum: 0,
        maximum: PORTABLE_INTEGER_MAXIMUM + 1,
      },
    ],
    [
      "below-domain",
      {
        type: "integer",
        minimum: PORTABLE_SIGNED_INTEGER_MINIMUM - 1,
        maximum: 0,
      },
    ],
  ]) {
    let rejected = false;
    try {
      inventorySchemaKeywords(schema, `generator-regression.integer.${id}`);
    } catch (error) {
      rejected =
        error instanceof Error &&
        error.message.includes("portable JS-safe domain");
    }
    if (!rejected) {
      throw new Error(
        `Generator regression: ${id} integer schema did not fail closed`,
      );
    }
  }

  inventorySchemaKeywords(
    { type: "integer", minimum: -8, maximum: -8 },
    "generator-regression.integer.signed",
  );

  let rejectedNonCanonicalDateTime = false;
  try {
    inventorySchemaKeywords(
      { type: "string", format: "date-time" },
      "generator-regression.date-time",
    );
  } catch (error) {
    rejectedNonCanonicalDateTime =
      error instanceof Error &&
      error.message.includes("portable canonical RFC3339 pattern");
  }
  if (!rejectedNonCanonicalDateTime) {
    throw new Error(
      "Generator regression: date-time schema without the canonical portable pattern did not fail closed",
    );
  }

  let rejectedUnsupportedPattern = false;
  try {
    inventorySchemaKeywords(
      { type: "string", pattern: "^.$" },
      "generator-regression.unsupported-pattern",
    );
  } catch (error) {
    rejectedUnsupportedPattern =
      error instanceof Error &&
      error.message.includes("wildcard semantics are unsupported");
  }
  if (!rejectedUnsupportedPattern) {
    throw new Error(
      "Generator regression: unsupported ECMA-262 pattern did not fail closed",
    );
  }
  const whitespaceTranslation = rustEcmaPattern(
    "^schema://[^\\s]+$",
    "generator-regression.ecma-whitespace",
  );
  if (
    !whitespaceTranslation.includes("\\u{FEFF}") ||
    whitespaceTranslation.includes("\\u{0085}")
  ) {
    throw new Error(
      "Generator regression: ECMA-262 whitespace translation drifted",
    );
  }
  const immutableRefTranslation = rustEcmaPattern(
    "^schema://[^\\s?#\\\\]+$",
    "generator-regression.immutable-ref-separators",
  );
  if (
    !immutableRefTranslation.includes("\\u{FEFF}") ||
    !immutableRefTranslation.includes("?#\\\\")
  ) {
    throw new Error(
      "Generator regression: immutable-ref separator class translation drifted",
    );
  }

  const rawLiteral = rustRaw({
    const: 'schema-controlled"###literal',
  });
  if (!rawLiteral.startsWith('r####"') || !rawLiteral.endsWith('"####')) {
    throw new Error(
      "Generator regression: Rust raw-string delimiter was not expanded dynamically",
    );
  }

  const ordered = ["\u{10000}", "\uE000", "A"].sort(codePointCompare);
  if (ordered.join("") !== `A\uE000\u{10000}`) {
    throw new Error(
      "Generator regression: schema-controlled ordering is not Unicode code-point stable",
    );
  }
  verifyPinnedRustfmt(pinnedRustToolchain());
}

runGeneratorCapabilityRegressions();
if (cliMode === "self-test") {
  console.log(
    `Architecture contract generator self-test passed (${usedSchemaKeywords.size} semantic keywords).`,
  );
  process.exit(0);
}

const renderedTargets = new Map([
  ["typescript_projection", renderTypescript()],
  ["rust_projection", formatRust(renderRust())],
]);
const outputsByPath = new Map();
for (const target of declaredTargets) {
  const content = renderedTargets.get(target.kind);
  if (content === undefined) {
    throw new Error(
      `No renderer exists for generated target kind ${target.kind}`,
    );
  }
  if (!content.includes(target.symbol)) {
    throw new Error(
      `${target.contractId}: rendered ${target.kind} target lacks ${target.symbol}`,
    );
  }
  const existing = outputsByPath.get(target.path);
  if (existing !== undefined && existing !== content) {
    throw new Error(
      `Generated target path ${target.path} is assigned incompatible target kinds`,
    );
  }
  outputsByPath.set(target.path, content);
}
const outputs = [...outputsByPath.entries()].sort(([left], [right]) =>
  codePointCompare(left, right),
);
const check = cliMode === "check";
const mismatches = [];
for (const [targetPath, content] of outputs) {
  const filePath = safeGeneratedTargetPath(
    targetPath,
    `generated target ${targetPath}`,
  );
  if (check) {
    if (!fs.existsSync(filePath)) {
      mismatches.push(targetPath);
      continue;
    }
    const checkedPath = safeGeneratedTargetPath(
      targetPath,
      `generated target read ${targetPath}`,
      true,
    );
    if (fs.readFileSync(checkedPath, "utf8") !== content) {
      mismatches.push(targetPath);
    }
  } else {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(
      safeGeneratedTargetPath(
        targetPath,
        `generated target write ${targetPath}`,
      ),
      content,
    );
  }
}

if (mismatches.length > 0) {
  console.error("Architecture contract projections are out of date:");
  for (const mismatch of mismatches) console.error(`- ${mismatch}`);
  console.error("Run npm run generate:architecture-contracts.");
  process.exit(1);
}

console.log(
  check
    ? "Architecture contract projections are up to date."
    : "Generated architecture contract projections.",
);
