import { mkdirSync } from "node:fs";

export function ensureDir(path) {
  mkdirSync(path, { recursive: true });
}
