#!/usr/bin/env node
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const schemaRoot = path.join(root, "docs", "architecture", "_meta", "schemas");
const registryPath = path.join(
  schemaRoot,
  "architecture-contract-registry.v1.json",
);
const registry = readJson(registryPath);
const contracts = registry.contracts.map((entry) => ({
  entry,
  schema: readJson(path.join(schemaRoot, entry.schema_ref)),
  invariants: entry.cross_field_invariant_refs.map((ref) =>
    readJson(path.join(schemaRoot, ref.path)),
  ),
}));

const tsPath = path.join(
  root,
  "packages",
  "hypervisor-workbench",
  "src",
  "runtime",
  "generated",
  "architecture-contracts.ts",
);
const rustPath = path.join(
  root,
  "crates",
  "types",
  "src",
  "app",
  "generated",
  "architecture_contracts.rs",
);

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value)
    .sort()
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

function indent(text, spaces) {
  const prefix = " ".repeat(spaces);
  return text
    .split("\n")
    .map((line) => `${prefix}${line}`)
    .join("\n");
}

function tsType(schema, rootSchema, depth = 0) {
  if (schema.$ref) {
    return tsType(resolveLocalRef(rootSchema, schema.$ref), rootSchema, depth);
  }
  const union = schema.oneOf ?? schema.anyOf;
  if (union) {
    return union.map((branch) => tsType(branch, rootSchema, depth)).join(" | ");
  }
  if (schema.enum) {
    return schema.enum.map((value) => JSON.stringify(value)).join(" | ");
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
      expected_failure: null,
      expected_rule_id: null,
    })),
    ...entry.negative_fixture_refs.map((fixture) => ({
      contract_id: entry.contract_id,
      path: `docs/architecture/_meta/schemas/${fixture.path}`,
      expected: "reject",
      expected_failure: fixture.expected_failure,
      expected_rule_id: fixture.expected_rule_id ?? null,
    })),
  ]);
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

export const ARCHITECTURE_CONTRACT_FIXTURES = ${JSON.stringify(fixtureMetadata(), null, 2)} as const;

export const ARCHITECTURE_CONTRACT_SCHEMA_HASHES = ${JSON.stringify(schemaHashes, null, 2)} as const;

type JsonObject = Record<string, unknown>;
type ValidationResult = { ok: boolean; errors: string[] };

const CONTRACT_SCHEMAS: Record<string, JsonObject> = ${JSON.stringify(schemas, null, 2)};
const CONTRACT_INVARIANTS: Record<string, Array<JsonObject>> = ${JSON.stringify(invariants, null, 2)};

export function architectureContractSchemaHash(contractId: string): string | null {
  return (ARCHITECTURE_CONTRACT_SCHEMA_HASHES as Record<string, string>)[contractId] ?? null;
}

function isObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
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
    return resolved ? schemaMatches(root, resolved, value, at) : [at + ": unresolved $ref"];
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
      break;
    }
  }
  if (Array.isArray(schema.enum) && !schema.enum.some((candidate) => Object.is(candidate, value))) {
    return [at + ": value is outside enum"];
  }
  if ("const" in schema && !Object.is(schema.const, value)) {
    return [at + ": value does not match const"];
  }
  const type = schema.type;
  if (type === "null" && value !== null) return [at + ": expected null"];
  if (type === "string") {
    if (typeof value !== "string") return [at + ": expected string"];
    if (typeof schema.minLength === "number" && value.length < schema.minLength) {
      return [at + ": string shorter than minLength"];
    }
    if (typeof schema.pattern === "string" && !new RegExp(schema.pattern, "u").test(value)) {
      return [at + ": string failed pattern"];
    }
    if (schema.format === "date-time") {
      const zoned = /(?:Z|[+-]\\d{2}:\\d{2})$/.test(value);
      if (!value.includes("T") || !zoned || Number.isNaN(Date.parse(value))) {
        return [at + ": invalid date-time"];
      }
    }
  }
  if (type === "number" || type === "integer") {
    if (typeof value !== "number" || !Number.isFinite(value)) return [at + ": expected number"];
    if (type === "integer" && !Number.isInteger(value)) return [at + ": expected integer"];
    if (typeof schema.minimum === "number" && value < schema.minimum) {
      return [at + ": number below minimum"];
    }
  }
  if (type === "boolean" && typeof value !== "boolean") return [at + ": expected boolean"];
  if (type === "array") {
    if (!Array.isArray(value)) return [at + ": expected array"];
    if (typeof schema.minItems === "number" && value.length < schema.minItems) {
      return [at + ": array shorter than minItems"];
    }
    if (typeof schema.maxItems === "number" && value.length > schema.maxItems) {
      return [at + ": array longer than maxItems"];
    }
    if (schema.uniqueItems === true && new Set(value.map((item) => JSON.stringify(item))).size !== value.length) {
      return [at + ": array items are not unique"];
    }
    if (isObject(schema.items)) {
      const errors = value.flatMap((item, index) => schemaMatches(root, schema.items as JsonObject, item, at + "[" + index + "]"));
      if (errors.length > 0) return errors;
    }
  }
  if (type === "object") {
    if (!isObject(value)) return [at + ": expected object"];
    const properties = isObject(schema.properties) ? schema.properties : {};
    const required = Array.isArray(schema.required) ? schema.required : [];
    const missing = required.filter((name) => typeof name === "string" && !(name in value));
    if (missing.length > 0) return [at + ": missing " + missing.join(", ")];
    if (schema.additionalProperties === false) {
      const unknown = Object.keys(value).filter((name) => !(name in properties));
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
      valid = Object.is(
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

export function validateArchitectureContract(contractId: string, value: unknown): ValidationResult {
  const schema = CONTRACT_SCHEMAS[contractId];
  if (!schema) return { ok: false, errors: ["unknown contract: " + contractId] };
  const errors = schemaMatches(schema, schema, value, "$");
  if (errors.length === 0) errors.push(...invariantErrors(contractId, CONTRACT_INVARIANTS[contractId] ?? [], value));
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
  function rustFieldName(name) {
    return name === "ref" ? "r#ref" : name;
  }
  function rustType(node, rootSchema, nameHint) {
    if (node.$ref) return rustType(resolveLocalRef(rootSchema, node.$ref), rootSchema, nameHint);
    const nullable = nullableBranch(node, rootSchema);
    if (nullable) return `Option<${rustType(nullable, rootSchema, nameHint)}>`;
    if (node.oneOf || node.anyOf) return "serde_json::Value";
    if (node.enum) return "String";
    switch (node.type) {
      case "string":
        return "String";
      case "integer":
        return "u64";
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
            return `    pub ${rustFieldName(name)}: ${fieldType},`;
          });
          definitions.set(
            nameHint,
            `#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]\n#[serde(deny_unknown_fields)]\npub struct ${nameHint} {\n${fields.join("\n")}\n}`,
          );
        }
        return nameHint;
      }
      default:
        return "serde_json::Value";
    }
  }
  const topName = projectionSymbol(entry);
  rustType(schema, schema, topName);
  return [...definitions.values()].join("\n\n");
}

function rustRaw(value) {
  return `r###"${JSON.stringify(value)}"###`;
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
  const parseArms = contracts
    .map(
      ({ entry }) => `        ${JSON.stringify(entry.contract_id)} => {
            serde_json::from_value::<${projectionSymbol(entry)}>(value.clone())
                .map(|_| ())
                .map_err(|error| error.to_string())
        }`,
    )
    .join(",\n");

  return `//! Generated by scripts/generate-architecture-contracts.mjs. Do not edit.
#![allow(missing_docs)]

use regex::Regex;
use serde_json::Value;
use std::collections::HashSet;

pub const ARCHITECTURE_CONTRACT_REGISTRY_VERSION: &str = ${JSON.stringify(registry.registry_version)};

pub const ARCHITECTURE_CONTRACT_SCHEMA_HASHES: &[(&str, &str)] = &[
${schemaHashEntries}
];

pub fn architecture_contract_schema_hash(contract_id: &str) -> Option<&'static str> {
    ARCHITECTURE_CONTRACT_SCHEMA_HASHES
        .iter()
        .find_map(|(id, hash)| (*id == contract_id).then_some(*hash))
}

${structs}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GoldenFixture {
    pub contract_id: &'static str,
    pub path: &'static str,
    pub expected_accept: bool,
    pub expected_failure: Option<&'static str>,
    pub expected_rule_id: Option<&'static str>,
}

pub const ARCHITECTURE_CONTRACT_FIXTURES: &[GoldenFixture] = &[
${fixtureEntries}
];

const CONTRACT_SCHEMAS: &[(&str, &str)] = &[
${schemaEntries}
];

const CONTRACT_INVARIANTS: &[(&str, &str)] = &[
${invariantEntries}
];

fn resolve_ref<'a>(root: &'a Value, reference: &str) -> Option<&'a Value> {
    let pointer = reference.strip_prefix('#')?;
    root.pointer(pointer)
}

fn type_matches(expected: &str, value: &Value) -> bool {
    match expected {
        "null" => value.is_null(),
        "string" => value.is_string(),
        "integer" => value.as_u64().is_some(),
        "number" => value.is_number(),
        "boolean" => value.is_boolean(),
        "array" => value.is_array(),
        "object" => value.is_object(),
        _ => false,
    }
}

fn validate_node(root: &Value, schema: &Value, value: &Value, at: &str) -> Result<(), String> {
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        let resolved = resolve_ref(root, reference)
            .ok_or_else(|| format!("{at}: unresolved $ref {reference}"))?;
        return validate_node(root, resolved, value, at);
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
            break;
        }
    }
    if let Some(values) = schema.get("enum").and_then(Value::as_array) {
        if !values.contains(value) {
            return Err(format!("{at}: value is outside enum"));
        }
    }
    if let Some(expected) = schema.get("const") {
        if expected != value {
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
            let regex = Regex::new(pattern).map_err(|error| format!("invalid schema regex: {error}"))?;
            if !regex.is_match(text) {
                return Err(format!("{at}: string failed pattern"));
            }
        }
        if schema.get("format").and_then(Value::as_str) == Some("date-time") {
            let zoned = text.ends_with('Z')
                || text
                    .rsplit_once(['+', '-'])
                    .is_some_and(|(_, zone)| zone.len() == 5 && zone.as_bytes().get(2) == Some(&b':'));
            if !text.contains('T') || !zoned {
                return Err(format!("{at}: invalid date-time"));
            }
        }
    }
    if let Some(minimum) = schema.get("minimum").and_then(Value::as_f64) {
        if value.as_f64().is_some_and(|number| number < minimum) {
            return Err(format!("{at}: number below minimum"));
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
            let unique: HashSet<String> = items.iter().map(Value::to_string).collect();
            if unique.len() != items.len() {
                return Err(format!("{at}: array items are not unique"));
            }
        }
        if let Some(item_schema) = schema.get("items") {
            for (index, item) in items.iter().enumerate() {
                validate_node(root, item_schema, item, &format!("{at}[{index}]"))?;
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
                .is_some_and(|(left, right)| left == right),
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
                        value_at_path(value, paths.first()?.as_str()?)?.as_u64()?,
                        value_at_path(value, paths.get(1)?.as_str()?)?.as_u64()?,
                    ))
                })
                .is_some_and(|(left, right)| {
                    if operator == "numbers_lte" {
                        left <= right
                    } else {
                        left < right
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

pub fn validate_architecture_contract(contract_id: &str, value: &Value) -> Result<(), String> {
    let schema_text = CONTRACT_SCHEMAS
        .iter()
        .find_map(|(id, schema)| (*id == contract_id).then_some(*schema))
        .ok_or_else(|| format!("unknown contract: {contract_id}"))?;
    let invariant_text = CONTRACT_INVARIANTS
        .iter()
        .find_map(|(id, rules)| (*id == contract_id).then_some(*rules))
        .unwrap_or("[]");
    let schema: Value = serde_json::from_str(schema_text).map_err(|error| error.to_string())?;
    let invariants: Value = serde_json::from_str(invariant_text).map_err(|error| error.to_string())?;
    validate_node(&schema, &schema, value, "$")?;
    validate_invariants(contract_id, &invariants, value)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE_BODIES: &[(&str, &str)] = &[
${fixtureBodies}
    ];

    fn parse_projection(contract_id: &str, value: &Value) -> Result<(), String> {
        match contract_id {
${parseArms},
            _ => Err(format!("unknown projection: {contract_id}")),
        }
    }

    #[test]
    fn golden_fixtures_match_generated_rust_contracts() {
        for fixture in ARCHITECTURE_CONTRACT_FIXTURES {
            let body = FIXTURE_BODIES
                .iter()
                .find_map(|(path, body)| (*path == fixture.path).then_some(*body))
                .expect("fixture body is generated");
            let value: Value = serde_json::from_str(body).expect("fixture contains JSON");
            let result = validate_architecture_contract(fixture.contract_id, &value)
                .and_then(|_| parse_projection(fixture.contract_id, &value));
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
}
`;
}

function formatRust(source) {
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
      "rustfmt",
      ["--edition", "2021", temporaryPath],
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

const outputs = [
  [tsPath, renderTypescript()],
  [rustPath, formatRust(renderRust())],
];
const check = process.argv.includes("--check");
const mismatches = [];
for (const [filePath, content] of outputs) {
  if (check) {
    if (!fs.existsSync(filePath) || fs.readFileSync(filePath, "utf8") !== content) {
      mismatches.push(path.relative(root, filePath));
    }
  } else {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, content);
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
