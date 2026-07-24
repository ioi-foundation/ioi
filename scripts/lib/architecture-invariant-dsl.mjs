function isObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function resolveLocalRef(schema, ref) {
  if (typeof ref !== "string" || !ref.startsWith("#/")) return undefined;
  return ref
    .slice(2)
    .split("/")
    .map((part) => part.replaceAll("~1", "/").replaceAll("~0", "~"))
    .reduce((current, part) => current?.[part], schema);
}

function expandedSchemaNodes(rootSchema, initialNodes) {
  const queue = [...initialNodes];
  const expanded = [];
  const seen = new Set();
  while (queue.length > 0) {
    const node = queue.shift();
    if (!isObject(node) || seen.has(node)) continue;
    seen.add(node);
    expanded.push(node);
    if (typeof node.$ref === "string") {
      queue.push(resolveLocalRef(rootSchema, node.$ref));
    }
    for (const keyword of ["allOf", "anyOf", "oneOf"]) {
      if (Array.isArray(node[keyword])) queue.push(...node[keyword]);
    }
    for (const keyword of ["if", "then", "else"]) {
      if (isObject(node[keyword])) queue.push(node[keyword]);
    }
  }
  return expanded;
}

function pathParts(pointer) {
  if (typeof pointer !== "string" || !pointer.startsWith("$.")) {
    return null;
  }
  const parts = [];
  for (const segment of pointer.slice(2).split(".")) {
    const match = /^([a-z][a-z0-9_]*)(?:\[(0|[1-9][0-9]*)\])?$/u.exec(segment);
    if (match === null) return null;
    parts.push(match[1]);
    if (match[2] !== undefined) parts.push(Number(match[2]));
  }
  return parts.length > 0 ? parts : null;
}

function schemaNodeAtArrayIndex(node, index) {
  if (!Number.isSafeInteger(index) || index < 0) return undefined;
  if (
    Number.isInteger(node.maxItems) &&
    node.maxItems >= 0 &&
    index >= node.maxItems
  ) {
    return undefined;
  }
  if (Array.isArray(node.prefixItems) && index < node.prefixItems.length) {
    return node.prefixItems[index];
  }
  return isObject(node.items) ? node.items : undefined;
}

function pathResolvesAcrossAlternatives(
  rootSchema,
  node,
  parts,
  visiting = new WeakMap(),
) {
  if (!isObject(node)) return false;
  if (parts.length === 0) return true;

  let activePaths = visiting.get(node);
  if (activePaths === undefined) {
    activePaths = new Set();
    visiting.set(node, activePaths);
  }
  const pathKey = parts.map(String).join(".");
  if (activePaths.has(pathKey)) return false;
  activePaths.add(pathKey);

  try {
    const [part, ...remaining] = parts;
    if (typeof part === "number") {
      const candidate = schemaNodeAtArrayIndex(node, part);
      if (
        candidate !== undefined &&
        pathResolvesAcrossAlternatives(rootSchema, candidate, remaining, visiting)
      ) {
        return true;
      }
    }
    if (
      typeof part === "string" &&
      isObject(node.properties) &&
      Object.hasOwn(node.properties, part) &&
      pathResolvesAcrossAlternatives(
        rootSchema,
        node.properties[part],
        remaining,
        visiting,
      )
    ) {
      return true;
    }
    if (
      typeof node.$ref === "string" &&
      pathResolvesAcrossAlternatives(
        rootSchema,
        resolveLocalRef(rootSchema, node.$ref),
        parts,
        visiting,
      )
    ) {
      return true;
    }
    if (
      Array.isArray(node.allOf) &&
      node.allOf.some((branch) =>
        pathResolvesAcrossAlternatives(rootSchema, branch, parts, visiting)
      )
    ) {
      return true;
    }
    for (const keyword of ["anyOf", "oneOf"]) {
      if (
        Array.isArray(node[keyword]) &&
        node[keyword].length > 0 &&
        node[keyword].every((branch) =>
          pathResolvesAcrossAlternatives(rootSchema, branch, parts, visiting)
        )
      ) {
        return true;
      }
    }
    if (
      isObject(node.if) &&
      isObject(node.then) &&
      isObject(node.else) &&
      pathResolvesAcrossAlternatives(rootSchema, node.then, parts, visiting) &&
      pathResolvesAcrossAlternatives(rootSchema, node.else, parts, visiting)
    ) {
      return true;
    }
    return false;
  } finally {
    activePaths.delete(pathKey);
  }
}

export function invariantPathResolvesPortably(rootSchema, pointer) {
  const parts = pathParts(pointer);
  return parts !== null &&
    pathResolvesAcrossAlternatives(rootSchema, rootSchema, parts);
}

function schemaNodesAtPath(rootSchema, pointer) {
  const parts = pathParts(pointer);
  if (parts === null) return [];
  let nodes = [rootSchema];
  for (const part of parts) {
    const next = [];
    for (const node of expandedSchemaNodes(rootSchema, nodes)) {
      if (typeof part === "number") {
        const candidate = schemaNodeAtArrayIndex(node, part);
        if (candidate !== undefined) next.push(candidate);
      } else if (typeof part === "string" && isObject(node.properties) && Object.hasOwn(node.properties, part)) {
        next.push(node.properties[part]);
      }
    }
    if (next.length === 0) return [];
    nodes = next;
  }
  return expandedSchemaNodes(rootSchema, nodes);
}

function directSchemaNodeAtPath(rootSchema, pointer) {
  const parts = pathParts(pointer);
  if (parts === null) return null;
  let node = rootSchema;
  const seenRefs = new Set();
  const dereference = () => {
    while (isObject(node) && typeof node.$ref === "string") {
      if (seenRefs.has(node.$ref)) return false;
      seenRefs.add(node.$ref);
      node = resolveLocalRef(rootSchema, node.$ref);
    }
    return isObject(node);
  };
  for (const part of parts) {
    if (!dereference()) {
      return null;
    }
    if (typeof part === "number") {
      node = schemaNodeAtArrayIndex(node, part);
      if (!isObject(node)) return null;
    } else {
      if (!isObject(node.properties) || !Object.hasOwn(node.properties, part)) return null;
      node = node.properties[part];
    }
  }
  return dereference() ? node : null;
}

export function invariantPathFiniteDomain(
  rootSchema,
  pointer,
  { arrayItems = false } = {},
) {
  let node = directSchemaNodeAtPath(rootSchema, pointer);
  if (node === null) return null;
  if (arrayItems) {
    if (!isObject(node.items)) return null;
    node = node.items;
    const seenRefs = new Set();
    while (isObject(node) && typeof node.$ref === "string") {
      if (seenRefs.has(node.$ref)) return null;
      seenRefs.add(node.$ref);
      node = resolveLocalRef(rootSchema, node.$ref);
    }
    if (!isObject(node)) return null;
  }
  const values = Object.hasOwn(node, "const")
    ? [node.const]
    : Array.isArray(node.enum)
    ? node.enum
    : null;
  if (
    values === null ||
    values.some(
      (value) =>
        !["string", "number", "boolean"].includes(typeof value) &&
        value !== null,
    )
  ) {
    return null;
  }
  return [...values];
}

function fieldExistsAtPath(rootSchema, pointer, field, arrayItems) {
  let nodes = schemaNodesAtPath(rootSchema, pointer);
  if (arrayItems) {
    nodes = expandedSchemaNodes(
      rootSchema,
      nodes.flatMap((node) => {
        if (Array.isArray(node.items)) return node.items;
        return isObject(node.items) ? [node.items] : [];
      }),
    );
  }
  return nodes.some(
    (node) =>
      isObject(node.properties) && Object.hasOwn(node.properties, field),
  );
}

function nonEmptyString(value) {
  return typeof value === "string" && value.length > 0;
}

function isPortableJsonScalar(value) {
  return value === null ||
    typeof value === "string" ||
    typeof value === "boolean" ||
    (typeof value === "number" && Number.isFinite(value));
}

const PROTOTYPE_SENSITIVE_MATERIAL_FIELDS = new Set([
  "__proto__",
  "constructor",
  "prototype",
]);

function pathList(value, length = null) {
  return (
    Array.isArray(value) &&
    value.length > 0 &&
    (length === null || value.length === length) &&
    value.every((entry) => pathParts(entry) !== null)
  );
}

const SUPPORTED_OPERATORS = new Set([
  "any_non_empty",
  "any_of",
  "array_contains_value",
  "array_exact_ref_coverage",
  "array_field_equals",
  "array_length_equals",
  "array_unique_by_fields",
  "field_ends_with",
  "field_starts_with_path",
  "field_suffix_equals_prefixed_field",
  "fields_equal",
  "fields_not_equal",
  "jcs_sha256_equals",
  "matches_contract_schema_hash",
  "non_empty",
  "non_empty_when_in",
  "numbers_lt",
  "numbers_lte",
  "object_fields_equal",
  "optional_field_equals",
  "prefixed_field_equals",
  "scope_pattern_matches",
  "sha256_parts_equals",
]);

function expressionPointers(value) {
  if (typeof value === "string") return value.startsWith("$.") ? [value] : [];
  if (Array.isArray(value)) return value.flatMap(expressionPointers);
  if (!isObject(value)) return [];
  return Object.values(value).flatMap(expressionPointers);
}

function validateHashExpression(expression, at, errors) {
  if (
    !["bytes32", "sha256_string", "prefixed_ref"].includes(
      expression.expected_encoding,
    )
  ) {
    errors.push(`${at}: expected_encoding is unsupported`);
  }
  if (
    expression.expected_encoding === "prefixed_ref" &&
    !nonEmptyString(expression.prefix)
  ) {
    errors.push(`${at}: prefixed_ref requires a nonempty prefix`);
  }
  if (pathParts(expression.expected_path) === null) {
    errors.push(`${at}: expected_path is malformed`);
  }
}

function validateExpression(rootSchema, expression, at, errors) {
  if (!isObject(expression)) {
    errors.push(`${at}: expression must be an object`);
    return;
  }
  if (!SUPPORTED_OPERATORS.has(expression.operator)) {
    errors.push(`${at}: unsupported invariant operator ${expression.operator}`);
    return;
  }
  if (expression.operator === "any_of") {
    if (
      !Array.isArray(expression.expressions) ||
      expression.expressions.length === 0
    ) {
      errors.push(`${at}: any_of requires a nonempty expressions array`);
      return;
    }
    expression.expressions.forEach((candidate, index) =>
      validateExpression(
        rootSchema,
        candidate,
        `${at}.expressions[${index}]`,
        errors,
      )
    );
    return;
  }

  for (const pointer of expressionPointers(expression)) {
    if (!invariantPathResolvesPortably(rootSchema, pointer)) {
      errors.push(
        `${at}: invariant path does not resolve through every reachable schema alternative: ${pointer}`,
      );
    }
  }

  const requirePath = (name) => {
    if (pathParts(expression[name]) === null) {
      errors.push(`${at}: ${name} must be a canonical invariant path`);
    }
  };
  const requireString = (name) => {
    if (!nonEmptyString(expression[name])) {
      errors.push(`${at}: ${name} must be a nonempty string`);
    }
  };
  const requirePaths = (name, length = null) => {
    if (!pathList(expression[name], length)) {
      errors.push(
        `${at}: ${name} must be a nonempty canonical path array${length === null ? "" : ` of length ${length}`}`,
      );
    }
  };

  switch (expression.operator) {
    case "non_empty":
    case "matches_contract_schema_hash":
      requirePath("path");
      break;
    case "any_non_empty":
      requirePaths("paths");
      break;
    case "non_empty_when_in":
      requirePath("path");
      requirePath("when_path");
      if (!Array.isArray(expression.values) || expression.values.length === 0) {
        errors.push(`${at}: values must be a nonempty array`);
      } else if (!expression.values.every(isPortableJsonScalar)) {
        errors.push(`${at}: values must contain only portable JSON scalars`);
      }
      break;
    case "fields_equal":
    case "fields_not_equal":
    case "numbers_lte":
    case "numbers_lt":
      requirePaths("paths", 2);
      break;
    case "array_field_equals":
      requirePath("array_path");
      requirePath("expected_path");
      requireString("field");
      if (
        nonEmptyString(expression.field) &&
        !fieldExistsAtPath(
          rootSchema,
          expression.array_path,
          expression.field,
          true,
        )
      ) {
        errors.push(`${at}: array item field does not resolve: ${expression.field}`);
      }
      break;
    case "optional_field_equals":
      requirePath("optional_object_path");
      requirePath("expected_path");
      requireString("field");
      if (
        nonEmptyString(expression.field) &&
        !fieldExistsAtPath(
          rootSchema,
          expression.optional_object_path,
          expression.field,
          false,
        )
      ) {
        errors.push(`${at}: optional object field does not resolve: ${expression.field}`);
      }
      break;
    case "prefixed_field_equals":
      requirePath("path");
      requirePath("expected_path");
      requireString("prefix");
      break;
    case "field_ends_with":
      requirePath("path");
      requirePath("expected_path");
      break;
    case "array_length_equals":
      requirePath("array_path");
      requirePath("count_path");
      break;
    case "array_unique_by_fields": {
      requirePath("array_path");
      const fields = expression.fields;
      if (
        !Array.isArray(fields) ||
        fields.length === 0 ||
        fields.length > 8 ||
        new Set(fields).size !== fields.length ||
        fields.some((field) => !/^[a-z][a-z0-9_]*$/u.test(field))
      ) {
        errors.push(`${at}: fields must contain 1..=8 unique canonical names`);
      } else {
        for (const field of fields) {
          if (!fieldExistsAtPath(rootSchema, expression.array_path, field, true)) {
            errors.push(`${at}: array item field does not resolve: ${field}`);
          }
        }
      }
      break;
    }
    case "object_fields_equal": {
      requirePaths("object_paths", 2);
      const fields = expression.fields;
      if (
        !Array.isArray(fields) ||
        fields.length === 0 ||
        fields.some((field) => !nonEmptyString(field))
      ) {
        errors.push(`${at}: fields must be a nonempty string array`);
      } else if (pathList(expression.object_paths, 2)) {
        for (const pointer of expression.object_paths) {
          for (const field of fields) {
            if (!fieldExistsAtPath(rootSchema, pointer, field, false)) {
              errors.push(`${at}: object field does not resolve at ${pointer}: ${field}`);
            }
          }
        }
      }
      break;
    }
    case "jcs_sha256_equals": {
      validateHashExpression(expression, at, errors);
      if (
        !["jcs_sha256", "jcs_sha256_then_utf8_sha256"].includes(
          expression.algorithm,
        )
      ) {
        errors.push(`${at}: algorithm is unsupported`);
      }
      if (
        expression.algorithm === "jcs_sha256_then_utf8_sha256" &&
        !nonEmptyString(expression.intermediate_prefix)
      ) {
        errors.push(`${at}: chained hashing requires intermediate_prefix`);
      }
      const hasPath = Object.hasOwn(expression, "material_path");
      const hasFields = Object.hasOwn(expression, "material_fields");
      if (hasPath === hasFields) {
        errors.push(`${at}: exactly one material source is required`);
      } else if (hasPath) {
        requirePath("material_path");
      } else if (
        !isObject(expression.material_fields) ||
        Object.keys(expression.material_fields).length === 0
      ) {
        errors.push(`${at}: material_fields must be a nonempty object`);
      } else {
        for (const [field, descriptor] of Object.entries(
          expression.material_fields,
        )) {
          if (PROTOTYPE_SENSITIVE_MATERIAL_FIELDS.has(field)) {
            errors.push(`${at}: material field ${field} is prototype-sensitive`);
          } else if (!isObject(descriptor)) {
            errors.push(`${at}: material field ${field} must be an object`);
          } else {
            const hasDescriptorPath = Object.hasOwn(descriptor, "path");
            const hasValue = Object.hasOwn(descriptor, "value");
            if (hasDescriptorPath === hasValue) {
              errors.push(`${at}: material field ${field} needs exactly one source`);
            } else if (hasDescriptorPath && pathParts(descriptor.path) === null) {
              errors.push(`${at}: material field ${field} path is malformed`);
            }
          }
        }
      }
      break;
    }
    case "sha256_parts_equals":
      validateHashExpression(expression, at, errors);
      if (!Array.isArray(expression.parts) || expression.parts.length === 0) {
        errors.push(`${at}: parts must be a nonempty array`);
      } else {
        expression.parts.forEach((part, index) => {
          if (!isObject(part)) {
            errors.push(`${at}: part ${index} must be an object`);
            return;
          }
          const sources = ["utf8", "signed_i32_be_path", "bytes_path"]
            .filter((name) => Object.hasOwn(part, name));
          if (sources.length !== 1) {
            errors.push(`${at}: part ${index} needs exactly one source`);
          } else if (
            sources[0] !== "utf8" &&
            pathParts(part[sources[0]]) === null
          ) {
            errors.push(`${at}: part ${index} path is malformed`);
          } else if (sources[0] === "utf8" && typeof part.utf8 !== "string") {
            errors.push(`${at}: part ${index} utf8 value must be a string`);
          }
        });
      }
      break;
    case "array_contains_value":
      requirePath("array_path");
      requirePath("expected_path");
      break;
    case "array_exact_ref_coverage":
      requirePath("array_path");
      for (const name of ["required_paths", "required_array_paths"]) {
        if (
          !Array.isArray(expression[name]) ||
          expression[name].some((pointer) => pathParts(pointer) === null)
        ) {
          errors.push(`${at}: ${name} must be a canonical path array`);
        }
      }
      if (
        expression.required_derived_refs !== undefined &&
        (!Array.isArray(expression.required_derived_refs) ||
          expression.required_derived_refs.some(
            (entry) =>
              !isObject(entry) ||
              pathParts(entry.path) === null ||
              !nonEmptyString(entry.prefix) ||
              (entry.strip_prefix !== undefined &&
                typeof entry.strip_prefix !== "string"),
          ))
      ) {
        errors.push(`${at}: required_derived_refs is malformed`);
      }
      break;
    case "scope_pattern_matches":
      requirePath("pattern_path");
      requirePath("value_path");
      break;
    case "field_starts_with_path":
      requirePath("path");
      requirePath("expected_path");
      requireString("prefix");
      if (
        expression.strip_prefix !== undefined &&
        typeof expression.strip_prefix !== "string"
      ) {
        errors.push(`${at}: strip_prefix must be a string`);
      }
      if (expression.suffix !== undefined && typeof expression.suffix !== "string") {
        errors.push(`${at}: suffix must be a string`);
      }
      break;
    case "field_suffix_equals_prefixed_field":
      requirePath("source_path");
      requirePath("target_path");
      requireString("delimiter");
      requireString("target_prefix");
      break;
    default:
      break;
  }
}

export function validateInvariantProfile(rootSchema, profile) {
  const errors = [];
  if (!Array.isArray(profile?.rules)) {
    return ["profile rules must be an array"];
  }
  profile.rules.forEach((rule, index) => {
    const at = `rule[${index}]${nonEmptyString(rule?.rule_id) ? ` ${rule.rule_id}` : ""}`;
    if (!isObject(rule) || !nonEmptyString(rule.rule_id)) {
      errors.push(`${at}: rule_id must be a nonempty string`);
      return;
    }
    validateExpression(rootSchema, rule.expression, at, errors);
  });
  return errors;
}
