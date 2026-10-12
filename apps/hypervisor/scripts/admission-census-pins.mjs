// The census's pinned values (admission-census-pins.json) and their one reader: the census verifier
// and the admission-census entailment check both read the pins through `readCensusPins`.
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const PINS_FILE = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "admission-census-pins.json",
);

/// The pinned structure: every key is required and every leaf is a non-negative integer. A new
/// pinned leaf (a new unadjudicable bucket included) is added here, in the sidecar and in the
/// verifier's PINNED together.
export const PIN_SHAPE = {
  modules: 0,
  familyMentions: 0,
  tokenMentions: 0,
  judgedTokenPositions: 0,
  productionWriterCalls: { family: 0, nonFamilyLiteral: 0, runtimeParameter: 0 },
  productionFsCalls: 0,
  unadjudicable: {
    "foreign-qualified": 0,
    "opaque-initialiser": 0,
    "bare-undeclared": 0,
    "ambiguous-module": 0,
    "not-a-visible-const": 0,
    "resolution-cycle": 0,
  },
  includes: { splicedCode: 0, dataStr: 0, dataBytes: 0, dataOpaqueArg: 0 },
  compileAssembly: { production: 0, test: 0 },
};

/// The one key beside the pins: `history`, at the top level only, a list of notes.
export const HISTORY_KEY = "history";

const isRecord = (value) => value !== null && typeof value === "object" && !Array.isArray(value);

/// The structure errors of a pin document, each naming its path: a PINNED leaf that is missing or
/// is not a non-negative integer, a group that is not an object, a key that is not pinned, and
/// history anywhere but its declared key or not a list of notes.
export function censusPinErrors(pins) {
  const errors = [];
  const walk = (shape, value, at) => {
    if (!isRecord(value)) {
      errors.push(`${at || "the pin document"}: not an object`);
      return;
    }
    for (const key of Object.keys(shape)) {
      const where = at ? `${at}.${key}` : key;
      if (!Object.hasOwn(value, key)) {
        errors.push(`${where}: missing`);
      } else if (isRecord(shape[key])) {
        walk(shape[key], value[key], where);
      } else if (!Number.isSafeInteger(value[key]) || value[key] < 0) {
        errors.push(`${where}: ${JSON.stringify(value[key])} is not a non-negative integer`);
      }
    }
    for (const key of Object.keys(value)) {
      if (Object.hasOwn(shape, key)) continue;
      const where = at ? `${at}.${key}` : key;
      if (!at && key === HISTORY_KEY) {
        const notes = value[key];
        if (!Array.isArray(notes) || !notes.every((note) => typeof note === "string")) {
          errors.push(`${where}: not a list of notes`);
        }
      } else if (key === HISTORY_KEY) {
        errors.push(`${where}: history belongs only under the top-level "${HISTORY_KEY}" key`);
      } else {
        errors.push(`${where}: not a pinned key`);
      }
    }
  };
  walk(PIN_SHAPE, pins, "");
  return errors;
}

/// The PINNED leaves of a checked pin document: everything but its history.
export function pinnedLeaves(pins) {
  const { [HISTORY_KEY]: _history, ...leaves } = pins;
  return leaves;
}

/// Read a pin document and refuse a malformed one.
export function readCensusPins(file = PINS_FILE) {
  const pins = JSON.parse(readFileSync(file, "utf8"));
  const errors = censusPinErrors(pins);
  if (errors.length) {
    throw new Error(`the census pins in ${file} are malformed: ${errors.join("; ")}`);
  }
  return pins;
}
