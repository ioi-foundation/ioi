import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export function writeBundle(outputRoot, bundle) {
  mkdirSync(outputRoot, { recursive: true });
  const path = join(outputRoot, "result.json");
  writeFileSync(path, `${JSON.stringify(bundle, null, 2)}\n`, "utf8");
  return path;
}


export { collectRuntimeArtifacts } from "./core.mjs";
