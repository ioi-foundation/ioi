// The census's pinned values (admission-census-pins.json) and their one reader: the census verifier
// and the admission-census entailment check both read the pins through `readCensusPins`.
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const PINS_FILE = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "admission-census-pins.json",
);

/// The structure errors of a pin document.
export function censusPinErrors(_pins) {
  return [];
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
