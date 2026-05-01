import { build } from "esbuild";
import fs from "node:fs/promises";
import path from "node:path";

const root = path.resolve(new URL("..", import.meta.url).pathname);
const dist = path.join(root, "dist");

const packageEntryPoints = [
  "src/index.ts",
  "src/agent.ts",
  "src/run.ts",
  "src/messages.ts",
  "src/options.ts",
  "src/errors.ts",
  "src/substrate-client.ts",
  "src/testing.ts",
].map((entry) => path.join(root, entry));
const exampleEntryPoints = ["examples/quickstart-local.ts"].map((entry) => path.join(root, entry));

await fs.mkdir(dist, { recursive: true });

await build({
  entryPoints: packageEntryPoints,
  outbase: root,
  outdir: dist,
  bundle: false,
  platform: "node",
  format: "esm",
  target: "node18",
  sourcemap: true,
  outExtension: { ".js": ".js" },
});

await build({
  entryPoints: exampleEntryPoints,
  outfile: path.join(dist, "quickstart-local.js"),
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node18",
  sourcemap: true,
});

await build({
  entryPoints: packageEntryPoints,
  outbase: root,
  outdir: dist,
  bundle: false,
  platform: "node",
  format: "cjs",
  target: "node18",
  sourcemap: true,
  outExtension: { ".js": ".cjs" },
});

for (const subdir of ["src", "examples"]) {
  const sourceDir = path.join(dist, subdir);
  try {
    const entries = await fs.readdir(sourceDir);
    for (const entry of entries) {
      await fs.rename(path.join(sourceDir, entry), path.join(dist, entry));
    }
    await fs.rm(sourceDir, { recursive: true, force: true });
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") {
      continue;
    }
    throw error;
  }
}
