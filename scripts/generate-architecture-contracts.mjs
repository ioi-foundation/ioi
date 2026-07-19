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
const {
  ARCHITECTURE_CONTRACT_CONSUMER_TARGETS,
} = await import("./lib/architecture-contract-consumer-targets.mjs");
const { architectureContractConsumerBindingFailures } = await import(
  "./lib/architecture-contract-consumer-bindings.mjs"
);
const { safeRepositoryPath } = await import(
  "./lib/repository-path-boundary.mjs"
);
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
    .sort(codePointCompare)
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
    .join(",")}}`;
}

function schemaHash(schema) {
  return `sha256:${createHash("sha256").update(canonicalJson(schema)).digest("hex")}`;
}

function contractVersion(entry) {
  const match = entry.contract_id.match(/\/v([1-9][0-9]*)$/u);
  if (!match) throw new Error(`Contract id has no terminal version: ${entry.contract_id}`);
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
        throw new Error(`${targetAt}: unknown generated target kind ${JSON.stringify(target.kind)}`);
      }
      const consumerTarget =
        PINNED_CONSUMER_TARGET_BY_KIND.get(target.kind);
      if (target.path !== consumerTarget.path) {
        throw new Error(
          `${targetAt}: generated target path must match canonical ${target.kind} consumer ${consumerTarget.path}`,
        );
      }
      if (seenKinds.has(target.kind)) {
        throw new Error(`${at}: duplicate generated target kind ${target.kind}`);
      }
      seenKinds.add(target.kind);
      if (target.symbol !== expectedSymbol) {
        throw new Error(`${targetAt}: generated target symbol must be ${expectedSymbol}`);
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
        throw new Error(`${at}: missing required generated target kind ${kind}`);
      }
    }
  }
  return targets;
}

function resolveLocalRef(rootSchema, ref) {
  if (!ref.startsWith("#/")) {
    throw new Error(`Only local JSON Schema refs are supported by the pilot: ${ref}`);
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

  const grammarProbe = pattern
    .replaceAll("[^\\s]", "X")
    .replaceAll("\\S", "X");
  if (grammarProbe.includes("\\")) {
    throw new Error(
      `${at}: unsupported ECMA-262 escape; only out-of-class \\S and [^\\s] are supported`,
    );
  }
  let inClass = false;
  let groupDepth = 0;
  for (let index = 1; index < grammarProbe.length - 1; index += 1) {
    const character = grammarProbe[index];
    if (character === "[") {
      if (inClass) throw new Error(`${at}: nested character classes are unsupported`);
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

  return pattern
    .replaceAll("[^\\s]", `[^${RUST_ECMA_WHITESPACE_CLASS}]`)
    .replaceAll("\\S", `[^${RUST_ECMA_WHITESPACE_CLASS}]`);
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
        !["null", "string", "integer", "number", "boolean", "array", "object"].includes(
          value,
        )
      ) {
        throw new Error(`${at}.type: unsupported type declaration`);
      }
    } else if (keyword === "format" && value !== "date-time") {
      throw new Error(`${at}.format: unsupported format ${JSON.stringify(value)}`);
    } else if (
      ["minimum", "maximum", "minLength", "minItems", "maxItems"].includes(
        keyword,
      ) &&
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
    } else if (
      keyword === "required" &&
      !Array.isArray(value)
    ) {
      throw new Error(`${at}.${keyword}: expected an array`);
    } else if (
      keyword === "enum" &&
      (!Array.isArray(value) ||
        value.length === 0 ||
        !value.every((candidate) => typeof candidate === "string"))
    ) {
      throw new Error(
        `${at}.enum: architecture projections currently require a non-empty string enum`,
      );
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
    if (
      !Number.isSafeInteger(schema.minimum) ||
      !Number.isSafeInteger(schema.maximum) ||
      schema.minimum < PORTABLE_INTEGER_MINIMUM ||
      schema.maximum > PORTABLE_INTEGER_MAXIMUM ||
      schema.minimum > schema.maximum
    ) {
      throw new Error(
        `${at}: integer schemas must declare a semantic minimum/maximum within the portable unsigned JS-safe domain ` +
          `${PORTABLE_INTEGER_MINIMUM}..${PORTABLE_INTEGER_MAXIMUM}`,
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
    return closedStringValues(resolveLocalRef(rootSchema, schema.$ref), rootSchema);
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
  throw new Error(`Unsupported JSON literal in TypeScript projection: ${value}`);
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

const mutationDefinitions = [
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
    contractId:
      "schema://ioi/foundations/physical-action-execution-receipt/v1",
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
      value: [
        "dispute_resolution",
        "dispute_remedy_execution",
      ],
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
    contractId:
      "schema://ioi/foundations/autonomous-system-constitution/v1",
    fixture:
      "fixtures/autonomous-system-constitution-v1/positive-draft.json",
    keywords: ["const"],
    directProjectionRejection: true,
    patch: {
      operation: "set",
      pointer: "/governance/agent_may_commit_amendment",
      value: true,
    },
  },
];

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
  if (typeof pointer !== "string" || !pointer.startsWith("$.")) return undefined;
  return pointer
    .slice(2)
    .split(".")
    .reduce(
      (current, part) => (isPlainObject(current) ? current[part] : undefined),
      value,
    );
}

function generatorNonEmpty(value) {
  return (
    (Array.isArray(value) && value.length > 0) ||
    (typeof value === "string" && value.length > 0)
  );
}

function generatorInvariantErrors(contract, value) {
  const expectedSchemaHash = schemaHash(contract.schema);
  return contract.invariants.flatMap((profile) =>
    (profile.rules ?? []).flatMap((rule) => {
      const expression = rule.expression ?? {};
      let valid = false;
      if (expression.operator === "non_empty") {
        valid = generatorNonEmpty(
          generatorValueAtPath(value, expression.path),
        );
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
          !expression.values.some((expected) => Object.is(actual, expected)) ||
          generatorNonEmpty(generatorValueAtPath(value, expression.path));
      } else if (
        expression.operator === "fields_equal" &&
        Array.isArray(expression.paths) &&
        expression.paths.length === 2
      ) {
        valid =
          canonicalJson(generatorValueAtPath(value, expression.paths[0])) ===
          canonicalJson(generatorValueAtPath(value, expression.paths[1]));
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
          (expression.operator === "numbers_lte" ? left <= right : left < right);
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
    return {
      id: definition.id,
      contract_id: definition.contractId,
      source_fixture_path: `docs/architecture/_meta/schemas/${definition.fixture}`,
      covered_keywords: definition.keywords,
      ajv_expected_accept: Boolean(validate(value)),
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

  const contractsById = new Map(
    contracts.map((contract) => [contract.entry.contract_id, contract]),
  );
  return cases.map((candidate) => {
    const contract = contractsById.get(candidate.contract_id);
    const validate = generatorAjvValidators.get(candidate.contract_id);
    if (!contract || !validate) {
      throw new Error(`Differential case ${candidate.id} names an unknown contract`);
    }
    const value =
      candidate.value ??
      JSON.parse(candidate.value_json);
    const ajvSchemaAccept = Boolean(validate(value));
    const { value: _value, ...serializable } = candidate;
    return {
      ...serializable,
      ajv_schema_accept: ajvSchemaAccept,
      oracle_contract_accept:
        ajvSchemaAccept && generatorInvariantErrors(contract, value).length === 0,
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
    contracts.map(({ entry, schema }) => [entry.contract_id, schemaHash(schema)]),
  );
  const mutations = mutationCorpus();
  const differentialCases = differentialCorpus().map((candidate) => ({
    id: candidate.id,
    contract_id: candidate.contract_id,
    source_fixture_path: candidate.source_fixture_path,
    mutation_id: candidate.mutation_id,
    value_json: candidate.value_json,
  }));
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
export const ARCHITECTURE_CONTRACT_PORTABLE_DATE_TIME_PATTERN = ${JSON.stringify(PORTABLE_CANONICAL_DATE_TIME_PATTERN)} as const;
export const ARCHITECTURE_CONTRACT_ORACLE_PROFILE = "ajv-2020-12-plus-portable-invariants-and-canonical-rfc3339" as const;

export const ARCHITECTURE_CONTRACT_FIXTURES = ${JSON.stringify(fixtureMetadata(), null, 2)} as const;

export type ArchitectureContractMutation = {
  id: string;
  contract_id: string;
  source_fixture_path: string;
  covered_keywords: string[];
  ajv_expected_accept: boolean;
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
  return path.slice(2).split(".").reduce<unknown>(
    (current, key) => (isObject(current) ? current[key] : undefined),
    value,
  );
}

function invariantErrors(contractId: string, rules: Array<JsonObject>, value: unknown): string[] {
  return rules.flatMap((rule) => {
    const expression = isObject(rule.expression) ? rule.expression : {};
    const operator = expression.operator;
    let valid = false;
    if (operator === "non_empty") {
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
        Object.is(valueAtPath(value, expression.when_path), expected),
      );
      const candidate = valueAtPath(value, expression.path);
      valid =
        !applies ||
        (Array.isArray(candidate)
          ? candidate.length > 0
          : typeof candidate === "string" && candidate.length > 0);
    } else if (operator === "fields_equal" && Array.isArray(expression.paths) && expression.paths.length === 2) {
      valid = jsonSchemaEqual(
        valueAtPath(value, expression.paths[0]),
        valueAtPath(value, expression.paths[1]),
      );
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
  function rustType(node, rootSchema, nameHint) {
    if (node.$ref) return rustType(resolveLocalRef(rootSchema, node.$ref), rootSchema, nameHint);
    const nullable = nullableBranch(node, rootSchema);
    if (nullable) return `Option<${rustType(nullable, rootSchema, nameHint)}>`;
    const closedStrings = closedStringValues(node, rootSchema);
    if (closedStrings !== null) {
      return rustClosedStringEnum(nameHint, closedStrings);
    }
    if (node.oneOf || node.anyOf) {
      throw new Error(
        `${entry.contract_id}:${nameHint}: Rust projection cannot represent this union exactly`,
      );
    }
    switch (node.type) {
      case "string":
        return "String";
      case "integer":
        return "ArchitectureContractInteger";
      case "number":
        return "f64";
      case "boolean":
        return "bool";
      case "array":
        return `Vec<${rustType(node.items ?? {}, rootSchema, `${nameHint}Item`)}>`;
      case "object": {
        if (!node.properties) return "serde_json::Value";
        if (!definitions.has(nameHint)) {
          definitions.set(nameHint, null);
          const required = new Set(node.required ?? []);
          const fields = Object.entries(node.properties).map(([name, property]) => {
            let fieldType = rustType(property, rootSchema, `${nameHint}${name
              .split("_")
              .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
              .join("")}`);
            if (!required.has(name) && !fieldType.startsWith("Option<")) {
              fieldType = `Option<${fieldType}>`;
            }
            return {
              fieldType,
              jsonName: name,
              required: required.has(name),
              rustName: rustFieldName(name),
            };
          });
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
    .map(({ entry, schema }) => `    (${JSON.stringify(entry.contract_id)}, ${rustRaw(schema)}),`)
    .join("\n");
  const invariantEntries = contracts
    .map(({ entry, invariants }) =>
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

use regex::Regex;
use serde_json::Value;
use std::cmp::Ordering;

pub const ARCHITECTURE_CONTRACT_REGISTRY_VERSION: &str = ${JSON.stringify(registry.registry_version)};
pub const ARCHITECTURE_CONTRACT_PORTABLE_INTEGER_MINIMUM: u64 = ${PORTABLE_INTEGER_MINIMUM};
pub const ARCHITECTURE_CONTRACT_PORTABLE_INTEGER_MAXIMUM: u64 = ${PORTABLE_INTEGER_MAXIMUM};
pub const ARCHITECTURE_CONTRACT_PORTABLE_DATE_TIME_PATTERN: &str = ${rustString(PORTABLE_CANONICAL_DATE_TIME_PATTERN)};
pub const ARCHITECTURE_CONTRACT_ORACLE_PROFILE: &str =
    "ajv-2020-12-plus-portable-invariants-and-canonical-rfc3339";

pub const ARCHITECTURE_CONTRACT_ASSERTION_KEYWORDS: &[&str] = &[
${[...usedSchemaKeywords].sort(codePointCompare).map((keyword) => `    ${rustString(keyword)},`).join("\n")}
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
    path.strip_prefix("$.")?
        .split('.')
        .try_fold(value, |current, key| current.get(key))
}

fn non_empty(value: Option<&Value>) -> bool {
    value.is_some_and(|candidate| match candidate {
        Value::Array(items) => !items.is_empty(),
        Value::String(text) => !text.is_empty(),
        _ => false,
    })
}

fn validate_invariants(contract_id: &str, rules: &Value, value: &Value) -> Result<(), String> {
    for rule in rules.as_array().into_iter().flatten() {
        let expression = &rule["expression"];
        let valid = match expression.get("operator").and_then(Value::as_str) {
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
                    .is_some_and(|(actual, expected)| expected.contains(actual));
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
            return Err(format!("invariant:{rule_id}"));
        }
    }
    Ok(())
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
            66,
            "the registered golden corpus must remain the explicit 66-fixture bar",
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
                mutation.ajv_expected_accept,
                "mutation {} contract result={contract_result:?}",
                mutation.id,
            );
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
  let rejectedUnsupportedAssertion = false;
  try {
    inventorySchemaKeywords(
      { type: "string", maxLength: 1 },
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
    ["negative-domain", { type: "integer", minimum: -1, maximum: 1 }],
  ]) {
    let rejected = false;
    try {
      inventorySchemaKeywords(schema, `generator-regression.integer.${id}`);
    } catch (error) {
      rejected =
        error instanceof Error &&
        error.message.includes("portable unsigned JS-safe domain");
    }
    if (!rejected) {
      throw new Error(
        `Generator regression: ${id} integer schema did not fail closed`,
      );
    }
  }

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
    throw new Error(`No renderer exists for generated target kind ${target.kind}`);
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
