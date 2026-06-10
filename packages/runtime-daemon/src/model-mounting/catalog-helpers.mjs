import fs from "node:fs";
import path from "node:path";

import {
  runtimeError,
} from "./io.mjs";

const RETIRED_DESTRUCTIVE_CONFIRMATION_REQUEST_ALIASES = [
  "confirmDestructive",
  "destructiveConfirmed",
  "destructive_confirmed",
];

const CANONICAL_DESTRUCTIVE_CONFIRMATION_REQUEST_FIELDS = [
  "confirm_destructive",
];

export function modelFileScore(filePath) {
  const name = path.basename(filePath).toLowerCase();
  if (name.endsWith(".gguf")) return 3;
  if (name.endsWith(".safetensors")) return 2;
  if (name.endsWith(".onnx") || name.endsWith(".bin")) return 1;
  return 0;
}

export function destructiveConfirmationState(body = {}, { required = true, action = "destructive_action" } = {}) {
  assertCanonicalDestructiveConfirmationRequestBody(body);
  const confirmed = Boolean(body.confirm_destructive ?? false);
  return {
    required,
    confirmed: required ? confirmed : true,
    action,
    source: confirmed ? "operator_confirmation" : required ? "not_provided" : "not_required",
  };
}

function assertCanonicalDestructiveConfirmationRequestBody(body = {}) {
  const retiredAliases = RETIRED_DESTRUCTIVE_CONFIRMATION_REQUEST_ALIASES.filter((field) =>
    Object.hasOwn(body, field),
  );
  if (retiredAliases.length === 0) return;
  throw runtimeError({
    status: 400,
    code: "destructive_confirmation_request_aliases_retired",
    message: "Destructive confirmation request aliases are retired; use canonical snake_case request fields.",
    details: {
      retired_aliases: retiredAliases,
      canonical_fields: CANONICAL_DESTRUCTIVE_CONFIRMATION_REQUEST_FIELDS,
    },
  });
}

export function parseModelQuantization(value) {
  return String(value ?? "").match(/\b(Q[0-9]_[A-Za-z0-9_]+|Q[0-9]+|F16|BF16|IQ[0-9]_[A-Za-z0-9_]+)\b/i)?.[1] ?? null;
}

export function listModelFiles(root) {
  if (!fs.existsSync(root)) return [];
  const results = [];
  for (const entry of fs.readdirSync(root, { withFileTypes: true })) {
    const entryPath = path.join(root, entry.name);
    if (entry.isDirectory()) {
      results.push(...listModelFiles(entryPath));
    } else if (entry.isFile() && modelFileScore(entryPath) > 0) {
      results.push(entryPath);
    }
  }
  return results.sort();
}
