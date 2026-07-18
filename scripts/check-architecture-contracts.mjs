#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const schemaRoot = path.join(root, "docs", "architecture", "_meta", "schemas");
const registryPath = path.join(
  schemaRoot,
  "architecture-contract-registry.v1.json",
);
const failures = [];
const fixturePaths = new Set();
const generatedTargetPaths = new Map();
const supportedGeneratedTargetKinds = new Set([
  "typescript_projection",
  "rust_projection",
]);

function fail(message) {
  failures.push(message);
}

function readJson(filePath) {
  try {
    return JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch (error) {
    fail(`${path.relative(root, filePath)}: ${error.message}`);
    return null;
  }
}

function isObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
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

function safeGeneratedTargetPath(targetPath, at) {
  if (
    typeof targetPath !== "string" ||
    targetPath.length === 0 ||
    targetPath.includes("\\") ||
    path.isAbsolute(targetPath) ||
    path.win32.isAbsolute(targetPath)
  ) {
    fail(`${at}: generated target path must be a repository-relative POSIX path`);
    return null;
  }
  const normalized = path.posix.normalize(targetPath);
  if (
    normalized !== targetPath ||
    normalized === "." ||
    normalized === ".." ||
    normalized.startsWith("../")
  ) {
    fail(`${at}: generated target path escapes or is not normalized: ${targetPath}`);
    return null;
  }
  const absolute = path.resolve(root, targetPath);
  const relative = path.relative(root, absolute);
  if (
    relative.length === 0 ||
    relative === ".." ||
    relative.startsWith(`..${path.sep}`) ||
    path.isAbsolute(relative)
  ) {
    fail(`${at}: generated target path escapes the repository: ${targetPath}`);
    return null;
  }
  return absolute;
}

function schemaHash(schema) {
  return `sha256:${createHash("sha256").update(canonicalJson(schema)).digest("hex")}`;
}

function contractVersion(contractId) {
  const match = contractId.match(/\/v([1-9][0-9]*)$/u);
  return match ? Number.parseInt(match[1], 10) : null;
}

function preflightGeneratedTargets(registryDocument) {
  if (!Array.isArray(registryDocument?.contracts)) {
    fail("registry: contract pilot must contain a contracts array");
    return;
  }
  for (const contract of registryDocument.contracts) {
    const contractId = contract?.contract_id ?? "unknown";
    const at = `${contractId}: generated_targets`;
    if (!Array.isArray(contract?.generated_targets)) {
      fail(`${at} must be an array`);
      continue;
    }
    const version =
      typeof contract.contract_id === "string"
        ? contractVersion(contract.contract_id)
        : null;
    const expectedSymbol =
      typeof contract.canonical_name === "string" && version !== null
        ? `${contract.canonical_name}V${version}`
        : null;
    const seenKinds = new Set();
    const seenDefinitions = new Set();
    for (const [index, target] of contract.generated_targets.entries()) {
      const targetAt = `${at}[${index}]`;
      if (!isObject(target)) {
        fail(`${targetAt} must be an object`);
        continue;
      }
      if (!supportedGeneratedTargetKinds.has(target.kind)) {
        fail(`${targetAt}: unknown generated target kind ${target.kind}`);
        continue;
      }
      if (seenKinds.has(target.kind)) {
        fail(`${at}: duplicate generated target kind ${target.kind}`);
      }
      seenKinds.add(target.kind);
      if (expectedSymbol === null || target.symbol !== expectedSymbol) {
        fail(`${targetAt}: generated target symbol must be ${expectedSymbol ?? "derivable"}`);
      }
      const definition = `${target.kind}\u0000${target.path}\u0000${target.symbol}`;
      if (seenDefinitions.has(definition)) {
        fail(`${at}: duplicate generated target definition`);
      }
      seenDefinitions.add(definition);
      const absolute = safeGeneratedTargetPath(target.path, targetAt);
      if (absolute) generatedTargetPaths.set(target, absolute);
    }
    for (const kind of supportedGeneratedTargetKinds) {
      if (!seenKinds.has(kind)) {
        fail(`${at}: missing required generated target kind ${kind}`);
      }
    }
  }
}

function collectRefs(value, at = "$") {
  if (Array.isArray(value)) {
    return value.flatMap((item, index) => collectRefs(item, `${at}[${index}]`));
  }
  if (!isObject(value)) return [];
  return [
    ...(typeof value.$ref === "string" ? [{ ref: value.$ref, at }] : []),
    ...Object.entries(value).flatMap(([key, item]) =>
      collectRefs(item, `${at}.${key}`),
    ),
  ];
}

function resolvePointer(value, ref) {
  if (!ref.startsWith("#/")) return null;
  return ref
    .slice(2)
    .split("/")
    .map((part) => part.replaceAll("~1", "/").replaceAll("~0", "~"))
    .reduce((current, part) => current?.[part], value);
}

function valueAtPath(value, pointer) {
  if (typeof pointer !== "string" || !pointer.startsWith("$.")) return undefined;
  return pointer
    .slice(2)
    .split(".")
    .reduce((current, part) => (isObject(current) ? current[part] : undefined), value);
}

function evaluateInvariants(profiles, value, expectedSchemaHash) {
  const errors = [];
  for (const profile of profiles) {
    for (const rule of profile.rules ?? []) {
      const expression = rule.expression ?? {};
      let valid = false;
      if (expression.operator === "non_empty") {
        const candidate = valueAtPath(value, expression.path);
        valid = Array.isArray(candidate)
          ? candidate.length > 0
          : typeof candidate === "string" && candidate.length > 0;
      } else if (
        expression.operator === "any_non_empty" &&
        Array.isArray(expression.paths)
      ) {
        valid = expression.paths.some((pointer) => {
          const candidate = valueAtPath(value, pointer);
          return Array.isArray(candidate)
            ? candidate.length > 0
            : typeof candidate === "string" && candidate.length > 0;
        });
      } else if (
        expression.operator === "non_empty_when_in" &&
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
      } else if (
        expression.operator === "fields_equal" &&
        Array.isArray(expression.paths) &&
        expression.paths.length === 2
      ) {
        valid = Object.is(
          valueAtPath(value, expression.paths[0]),
          valueAtPath(value, expression.paths[1]),
        );
      } else if (expression.operator === "matches_contract_schema_hash") {
        valid = valueAtPath(value, expression.path) === expectedSchemaHash;
      } else if (
        ["numbers_lte", "numbers_lt"].includes(expression.operator) &&
        Array.isArray(expression.paths) &&
        expression.paths.length === 2
      ) {
        const left = valueAtPath(value, expression.paths[0]);
        const right = valueAtPath(value, expression.paths[1]);
        valid =
          typeof left === "number" &&
          typeof right === "number" &&
          (expression.operator === "numbers_lte" ? left <= right : left < right);
      } else {
        fail(`${profile.$id}: unsupported invariant operator ${expression.operator}`);
      }
      if (!valid) errors.push(rule.rule_id);
    }
  }
  return errors;
}

function markdownAnchorExists(filePath, anchor) {
  if (!anchor) return true;
  const headings = fs
    .readFileSync(filePath, "utf8")
    .split(/\r?\n/u)
    .filter((line) => /^#{1,6}\s+/u.test(line))
    .map((line) =>
      line
        .replace(/^#{1,6}\s+/u, "")
        .trim()
        .toLowerCase()
        .replace(/[`*_]/gu, "")
        .replace(/[^a-z0-9 -]/gu, "")
        .replace(/\s+/gu, "-"),
    );
  return headings.includes(anchor);
}

function checkRegistryMetadata(registry) {
  if (registry.$schema !== "https://json-schema.org/draft/2020-12/schema") {
    fail("registry: $schema must identify JSON Schema 2020-12");
  }
  if (registry.$id !== "schema://ioi/architecture-contract-registry/v1") {
    fail("registry: unexpected $id");
  }
  if (registry.registry_version !== "ioi.architecture-contract-registry.v1") {
    fail("registry: unexpected registry_version");
  }
  if (!Array.isArray(registry.contracts) || registry.contracts.length < 2) {
    fail("registry: contract pilot must contain at least two contracts");
    return;
  }
  const required = [
    "contract_id",
    "canonical_name",
    "canonical_owner_ref",
    "schema_version",
    "maturity",
    "stability",
    "wire_format",
    "canonical_encoding_profile_ref",
    "evolution",
    "schema_ref",
    "cross_field_invariant_refs",
    "compatibility_aliases",
    "generated_targets",
    "positive_fixture_refs",
    "negative_fixture_refs",
  ];
  const ids = new Set();
  for (const contract of registry.contracts) {
    for (const field of required) {
      if (!Object.hasOwn(contract, field)) fail(`${contract.contract_id ?? "contract"}: missing ${field}`);
    }
    if (ids.has(contract.contract_id)) fail(`registry: duplicate ${contract.contract_id}`);
    ids.add(contract.contract_id);
    if (!/^schema:\/\/ioi\/[a-z0-9/-]+\/v[1-9][0-9]*$/u.test(contract.contract_id)) {
      fail(`${contract.contract_id}: invalid contract id`);
    }
    if (!/^[A-Z][A-Za-z0-9]+$/u.test(contract.canonical_name)) {
      fail(`${contract.contract_id}: invalid canonical_name`);
    }
    if (!["implemented", "partial", "target", "research", "reserved"].includes(contract.maturity)) {
      fail(`${contract.contract_id}: invalid maturity`);
    }
    if (!["experimental", "provisional", "stable", "deprecated"].includes(contract.stability)) {
      fail(`${contract.contract_id}: invalid stability`);
    }
    if (contract.wire_format !== "json") fail(`${contract.contract_id}: pilot wire format must be json`);
    if (
      contract.canonical_encoding_profile_ref !== null &&
      !/^encoding-profile:\/\/ioi\/[a-z0-9/-]+\/v[1-9][0-9]*$/u.test(
        contract.canonical_encoding_profile_ref,
      )
    ) {
      fail(`${contract.contract_id}: invalid canonical encoding profile ref`);
    }
    if (
      !isObject(contract.evolution) ||
      !Object.hasOwn(contract.evolution, "successor_of") ||
      !Object.hasOwn(contract.evolution, "successor_contract_id") ||
      !Object.hasOwn(contract.evolution, "compatibility") ||
      !Object.hasOwn(contract.evolution, "migration_policy") ||
      !Object.hasOwn(contract.evolution, "predecessor_remains_valid") ||
      !Object.hasOwn(contract.evolution, "wire_mutation_policy") ||
      !Object.hasOwn(contract.evolution, "hash_impact")
    ) {
      fail(`${contract.contract_id}: incomplete evolution metadata`);
    } else {
      if (!['initial', 'backward_compatible', 'breaking'].includes(contract.evolution.compatibility)) {
        fail(`${contract.contract_id}: invalid evolution compatibility`);
      }
      if (!['none', 'explicit_adapter_required'].includes(contract.evolution.migration_policy)) {
        fail(`${contract.contract_id}: invalid migration policy`);
      }
      if (typeof contract.evolution.predecessor_remains_valid !== 'boolean') {
        fail(`${contract.contract_id}: predecessor_remains_valid must be boolean`);
      }
      if (contract.evolution.wire_mutation_policy !== 'forbidden') {
        fail(`${contract.contract_id}: durable wire mutation must remain forbidden`);
      }
      if (!['none', 'canonical_body_changed', 'signature_preimage_changed'].includes(contract.evolution.hash_impact)) {
        fail(`${contract.contract_id}: invalid hash impact`);
      }
    }
    if (!contract.canonical_owner_ref.startsWith("canon://")) {
      fail(`${contract.contract_id}: canonical owner must use canon://`);
    } else {
      const owner = contract.canonical_owner_ref.slice("canon://".length);
      const [ownerFile, anchor] = owner.split("#", 2);
      const ownerPath = path.join(root, ownerFile);
      if (!fs.existsSync(ownerPath)) {
        fail(`${contract.contract_id}: missing canonical owner ${ownerFile}`);
      } else if (!markdownAnchorExists(ownerPath, anchor)) {
        fail(`${contract.contract_id}: missing canonical owner anchor #${anchor}`);
      }
    }
  }
  const contractsById = new Map(registry.contracts.map((contract) => [contract.contract_id, contract]));
  for (const contract of registry.contracts) {
    const evolution = contract.evolution;
    if (!isObject(evolution)) continue;
    if (evolution.successor_of !== null) {
      const predecessor = contractsById.get(evolution.successor_of);
      if (!predecessor) {
        fail(`${contract.contract_id}: missing predecessor ${evolution.successor_of}`);
      } else {
        if (predecessor.evolution?.successor_contract_id !== contract.contract_id) {
          fail(`${contract.contract_id}: predecessor does not point to successor`);
        }
        if (predecessor.canonical_name !== contract.canonical_name) {
          fail(`${contract.contract_id}: successor changed canonical name`);
        }
        if ((contractVersion(predecessor.contract_id) ?? 0) >= (contractVersion(contract.contract_id) ?? 0)) {
          fail(`${contract.contract_id}: successor version must increase`);
        }
      }
      if (evolution.compatibility === 'initial' || evolution.migration_policy === 'none') {
        fail(`${contract.contract_id}: successor lacks compatibility or migration disposition`);
      }
    } else if (evolution.compatibility !== 'initial') {
      fail(`${contract.contract_id}: initial contract must use initial compatibility`);
    }
    if (evolution.successor_contract_id !== null && !contractsById.has(evolution.successor_contract_id)) {
      fail(`${contract.contract_id}: missing successor ${evolution.successor_contract_id}`);
    }
  }
}

const registry = readJson(registryPath);
if (!registry) process.exit(1);
preflightGeneratedTargets(registry);
if (failures.length > 0) {
  console.error(failures.join("\n"));
  process.exit(1);
}
checkRegistryMetadata(registry);

const ajv = new Ajv2020({ allErrors: true, strict: true, validateFormats: true });
ajv.addKeyword({ keyword: "x-ioi-schema-version", schemaType: "string" });
addFormats(ajv);

for (const contract of registry.contracts ?? []) {
  const schemaPath = path.join(schemaRoot, contract.schema_ref);
  const schema = readJson(schemaPath);
  if (!schema) continue;
  if (schema.$schema !== "https://json-schema.org/draft/2020-12/schema") {
    fail(`${contract.contract_id}: schema is not 2020-12`);
  }
  if (schema.$id !== contract.contract_id) fail(`${contract.contract_id}: schema $id mismatch`);
  if (schema.title !== contract.canonical_name) fail(`${contract.contract_id}: schema title mismatch`);
  if (schema["x-ioi-schema-version"] !== contract.schema_version) {
    fail(`${contract.contract_id}: schema version mismatch`);
  }
  if (schema.type !== "object" || schema.additionalProperties !== false) {
    fail(`${contract.contract_id}: top-level schema must be a closed object`);
  }
  for (const { ref, at } of collectRefs(schema)) {
    if (ref.startsWith("#/") && resolvePointer(schema, ref) === undefined) {
      fail(`${contract.contract_id}: unresolved local ref ${ref} at ${at}`);
    } else if (!ref.startsWith("#/")) {
      fail(`${contract.contract_id}: pilot schema uses non-local $ref ${ref} at ${at}`);
    }
  }

  let validate;
  try {
    validate = ajv.compile(schema);
  } catch (error) {
    fail(`${contract.contract_id}: Ajv compile failed: ${error.message}`);
    continue;
  }
  const expectedSchemaHash = schemaHash(schema);

  const invariantProfiles = [];
  for (const invariantRef of contract.cross_field_invariant_refs) {
    const invariantPath = path.join(schemaRoot, invariantRef.path);
    const profile = readJson(invariantPath);
    if (!profile) continue;
    invariantProfiles.push(profile);
    if (profile.$id !== invariantRef.invariant_id) {
      fail(`${contract.contract_id}: invariant id mismatch at ${invariantRef.path}`);
    }
    if (profile.contract_id !== contract.contract_id) {
      fail(`${contract.contract_id}: invariant contract mismatch at ${invariantRef.path}`);
    }
    if (profile.language !== "ioi.portable-invariants.v1") {
      fail(`${contract.contract_id}: unsupported invariant language`);
    }
    const ruleIds = new Set();
    for (const rule of profile.rules ?? []) {
      if (ruleIds.has(rule.rule_id)) fail(`${profile.$id}: duplicate rule ${rule.rule_id}`);
      ruleIds.add(rule.rule_id);
      const pointers = [
        ...(rule.expression?.paths ?? [rule.expression?.path]),
        rule.expression?.when_path,
      ];
      for (const pointer of pointers.filter(Boolean)) {
        const property = pointer.startsWith("$.") ? pointer.slice(2).split(".")[0] : null;
        if (!property || !Object.hasOwn(schema.properties ?? {}, property)) {
          fail(`${profile.$id}: invariant path is outside schema: ${pointer}`);
        }
      }
    }
  }

  const positivePaths = contract.positive_fixture_refs.map((fixturePath) => ({
    path: fixturePath,
    expected: "accept",
  }));
  const negativePaths = contract.negative_fixture_refs.map((fixture) => ({
    ...fixture,
    expected: "reject",
  }));
  for (const fixture of [...positivePaths, ...negativePaths]) {
    const fixturePath = path.join(schemaRoot, fixture.path);
    if (fixturePaths.has(fixture.path)) fail(`registry: duplicate fixture ${fixture.path}`);
    fixturePaths.add(fixture.path);
    const value = readJson(fixturePath);
    if (!value) continue;
    const schemaValid = validate(value);
    const invariantErrors = schemaValid
      ? evaluateInvariants(
          invariantProfiles,
          value,
          expectedSchemaHash,
        )
      : [];
    const accepted = schemaValid && invariantErrors.length === 0;
    if (fixture.expected === "accept" && !accepted) {
      fail(
        `${fixture.path}: positive fixture rejected: ${schemaValid ? invariantErrors.join(", ") : ajv.errorsText(validate.errors)}`,
      );
    }
    if (fixture.expected === "reject" && accepted) {
      fail(`${fixture.path}: negative fixture was accepted`);
    }
    if (fixture.expected_failure === "schema" && schemaValid) {
      fail(`${fixture.path}: expected schema rejection but reached invariants`);
    }
    if (fixture.expected_failure === "invariant") {
      if (!schemaValid) fail(`${fixture.path}: expected invariant rejection but schema rejected`);
      if (!invariantErrors.includes(fixture.expected_rule_id)) {
        fail(`${fixture.path}: missing expected invariant ${fixture.expected_rule_id}`);
      }
    }
  }

  const aliases = new Set();
  for (const alias of contract.compatibility_aliases) {
    if (aliases.has(alias.alias)) fail(`${contract.contract_id}: duplicate alias ${alias.alias}`);
    aliases.add(alias.alias);
    if (alias.kind !== "field") fail(`${contract.contract_id}: unsupported alias kind ${alias.kind}`);
    if (!Object.hasOwn(schema.properties ?? {}, alias.canonical)) {
      fail(`${contract.contract_id}: alias target ${alias.canonical} is not canonical`);
    }
    if (Object.hasOwn(schema.properties ?? {}, alias.alias)) {
      fail(`${contract.contract_id}: compatibility alias ${alias.alias} is writeable`);
    }
    if (alias.read_policy !== "compatibility_adapter_only" || alias.write_policy !== "forbidden") {
      fail(`${contract.contract_id}: alias ${alias.alias} is not read-only`);
    }
    const aliasFixture = contract.negative_fixture_refs.some((fixture) => {
      const value = readJson(path.join(schemaRoot, fixture.path));
      return isObject(value) && Object.hasOwn(value, alias.alias);
    });
    if (!aliasFixture) fail(`${contract.contract_id}: alias ${alias.alias} has no write-rejection fixture`);
  }

  for (const target of Array.isArray(contract.generated_targets)
    ? contract.generated_targets
    : []) {
    const targetPath = generatedTargetPaths.get(target);
    if (!targetPath) continue;
    if (!fs.existsSync(targetPath)) {
      fail(`${contract.contract_id}: missing generated target ${target.path}`);
    } else if (!fs.readFileSync(targetPath, "utf8").includes(target.symbol)) {
      fail(`${contract.contract_id}: generated target lacks symbol ${target.symbol}`);
    }
  }
}

const generated = spawnSync(
  process.execPath,
  ["scripts/generate-architecture-contracts.mjs", "--check"],
  { cwd: root, encoding: "utf8" },
);
if (generated.status !== 0) {
  fail(
    `generated parity failed: ${(generated.stderr || generated.stdout || "unknown failure").trim()}`,
  );
}

if (failures.length > 0) {
  console.error("Architecture contract checks failed:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log(
  JSON.stringify(
    {
      ok: true,
      registry_version: registry.registry_version,
      contracts: registry.contracts.length,
      fixtures: fixturePaths.size,
      validator: "ajv-2020-12",
    },
    null,
    2,
  ),
);
