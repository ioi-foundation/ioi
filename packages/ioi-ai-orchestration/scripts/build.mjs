import { build } from "esbuild";
import fs from "node:fs/promises";
import path from "node:path";

const root = path.resolve(new URL("..", import.meta.url).pathname);
const dist = path.join(root, "dist");

const packageEntryPoints = ["src/index.ts", "src/collaboration.ts", "src/bindings.ts", "src/work.ts", "src/orchestrations.ts"].map((entry) => path.join(root, entry));

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

const sourceDir = path.join(dist, "src");
try {
  for (const entry of await fs.readdir(sourceDir)) {
    await fs.rename(path.join(sourceDir, entry), path.join(dist, entry));
  }
  await fs.rm(sourceDir, { recursive: true, force: true });
} catch (error) {
  if (!(error && typeof error === "object" && "code" in error && error.code === "ENOENT")) throw error;
}
