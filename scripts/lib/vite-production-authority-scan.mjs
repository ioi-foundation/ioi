import { createHash } from "node:crypto";
import { access, readFile, readdir, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import ts from "typescript";

const SOURCE_EXTENSIONS = [
  "",
  ".js",
  ".jsx",
  ".mjs",
  ".cjs",
  ".ts",
  ".tsx",
  ".css",
  ".json",
  ".svg",
];
const TEXT_EXTENSIONS = new Set([
  ".css",
  ".html",
  ".js",
  ".json",
  ".map",
  ".mjs",
  ".svg",
  ".txt",
]);

const exists = async (file) => {
  try {
    await access(file);
    return true;
  } catch {
    return false;
  }
};

const inside = (parent, candidate) =>
  candidate === parent || candidate.startsWith(`${parent}${path.sep}`);
const relative = (root, file) =>
  path.relative(root, file).split(path.sep).join("/");
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

async function listFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const nested = await Promise.all(
    entries.map((entry) => {
      const resolved = path.join(directory, entry.name);
      return entry.isDirectory() ? listFiles(resolved) : [resolved];
    }),
  );
  return nested.flat().sort();
}

function htmlModuleSpecifiers(source) {
  const specifiers = [];
  for (const match of source.matchAll(/<script\b([^>]*)>/giu)) {
    const attributes = Object.fromEntries(
      [...match[1].matchAll(/([\w:-]+)\s*=\s*["']([^"']*)["']/gu)].map(
        (item) => [item[1].toLowerCase(), item[2]],
      ),
    );
    if (attributes.type === "module" && attributes.src)
      specifiers.push(attributes.src);
  }
  return specifiers;
}

function moduleSpecifiers(source, extension) {
  if (extension === ".html") return htmlModuleSpecifiers(source);
  const specifiers = [];
  if (extension === ".css") {
    for (const match of source.matchAll(
      /@import\s+(?:url\(\s*)?["']([^"']+)["']/gu,
    ))
      specifiers.push(match[1]);
    return specifiers;
  }
  const scriptKinds = {
    ".js": ts.ScriptKind.JS,
    ".jsx": ts.ScriptKind.JSX,
    ".mjs": ts.ScriptKind.JS,
    ".cjs": ts.ScriptKind.JS,
    ".ts": ts.ScriptKind.TS,
    ".tsx": ts.ScriptKind.TSX,
  };
  const sourceFile = ts.createSourceFile(
    `production-entry${extension}`,
    source,
    ts.ScriptTarget.Latest,
    false,
    scriptKinds[extension] || ts.ScriptKind.JS,
  );
  const visit = (node) => {
    if (
      (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) &&
      node.moduleSpecifier &&
      ts.isStringLiteralLike(node.moduleSpecifier)
    ) {
      specifiers.push(node.moduleSpecifier.text);
    } else if (
      ts.isCallExpression(node) &&
      node.arguments.length === 1 &&
      ts.isStringLiteralLike(node.arguments[0])
    ) {
      if (
        node.expression.kind === ts.SyntaxKind.ImportKeyword ||
        (ts.isIdentifier(node.expression) && node.expression.text === "require")
      ) {
        specifiers.push(node.arguments[0].text);
      }
    } else if (
      ts.isImportEqualsDeclaration(node) &&
      ts.isExternalModuleReference(node.moduleReference) &&
      node.moduleReference.expression &&
      ts.isStringLiteralLike(node.moduleReference.expression)
    ) {
      specifiers.push(node.moduleReference.expression.text);
    }
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
  return specifiers;
}

async function resolveSpecifier(
  root,
  importer,
  rawSpecifier,
  allowedSourceRoots = [root],
) {
  const specifier = rawSpecifier.split(/[?#]/u, 1)[0];
  if (
    !specifier ||
    specifier.startsWith("data:") ||
    specifier.startsWith("http:") ||
    specifier.startsWith("https:")
  )
    return null;
  if (!specifier.startsWith(".") && !specifier.startsWith("/"))
    return { package: specifier };
  const base = specifier.startsWith("/")
    ? path.join(root, specifier.slice(1))
    : path.resolve(path.dirname(importer), specifier);
  if (!allowedSourceRoots.some((allowedRoot) => inside(allowedRoot, base))) {
    throw new Error(
      `${relative(root, importer)} imports outside its admitted source roots: ${rawSpecifier}`,
    );
  }
  const candidates = SOURCE_EXTENSIONS.flatMap((extension) => [
    `${base}${extension}`,
    path.join(base, `index${extension}`),
  ]);
  for (const candidate of [...new Set(candidates)]) {
    if ((await exists(candidate)) && (await stat(candidate)).isFile())
      return { file: candidate };
  }
  const publicCandidate = path.join(
    root,
    "public",
    specifier.replace(/^\/+/, ""),
  );
  if (
    specifier.startsWith("/") &&
    (await exists(publicCandidate)) &&
    (await stat(publicCandidate)).isFile()
  )
    return { file: publicCandidate };
  throw new Error(
    `${relative(root, importer)} has an unresolved production import: ${rawSpecifier}`,
  );
}

async function sourceGraph(root, entries, allowedSourceRoots = [root]) {
  const pending = entries.map((entry) => path.resolve(root, entry));
  const visited = new Set();
  const packages = new Set();
  while (pending.length > 0) {
    const file = pending.pop();
    if (visited.has(file)) continue;
    if (
      !allowedSourceRoots.some((allowedRoot) => inside(allowedRoot, file)) ||
      !(await exists(file)) ||
      !(await stat(file)).isFile()
    ) {
      throw new Error(
        `missing or unadmitted production entry ${relative(root, file)}`,
      );
    }
    visited.add(file);
    const extension = path.extname(file).toLowerCase();
    if (
      !TEXT_EXTENSIONS.has(extension) &&
      extension !== ".jsx" &&
      extension !== ".tsx" &&
      extension !== ".ts"
    )
      continue;
    const source = await readFile(file, "utf8");
    for (const specifier of moduleSpecifiers(source, extension)) {
      const resolved = await resolveSpecifier(
        root,
        file,
        specifier,
        allowedSourceRoots,
      );
      if (resolved?.package) packages.add(resolved.package);
      if (resolved?.file) pending.push(resolved.file);
    }
  }
  return { files: [...visited].sort(), packages: [...packages].sort() };
}

export async function inspectProductionSourceGraph({
  root,
  entries = ["index.html"],
  fixtureRoots = [],
  allowedSourceRoots = [],
}) {
  const applicationRoot = path.resolve(root);
  const admittedRoots = [
    applicationRoot,
    ...allowedSourceRoots.map((allowedRoot) =>
      path.resolve(applicationRoot, allowedRoot),
    ),
  ];
  const graph = await sourceGraph(applicationRoot, entries, admittedRoots);
  const normalizedFixtures = fixtureRoots.map((fixture) =>
    fixture.replace(/\/$/u, ""),
  );
  const fixtureReport = [];
  for (const fixture of normalizedFixtures) {
    const fixtureRoot = path.resolve(applicationRoot, fixture);
    if (!(await exists(fixtureRoot)))
      throw new Error(`declared fixture root is missing: ${fixture}`);
    const leak = graph.files.find((file) => inside(fixtureRoot, file));
    if (leak)
      throw new Error(
        `quarantined fixture entered the production graph: ${relative(applicationRoot, leak)}`,
      );
    fixtureReport.push({ root: fixture, reachable: false });
  }
  return {
    files: graph.files.map((file) => relative(applicationRoot, file)),
    packages: graph.packages,
    quarantined_fixtures: fixtureReport,
  };
}

function assertForbidden(source, file, patterns, scope) {
  for (const item of patterns) {
    if (item.sourceOnly && scope !== "source") continue;
    item.pattern.lastIndex = 0;
    if (item.pattern.test(source))
      throw new Error(`${file} contains forbidden ${item.label} (${scope})`);
  }
}

async function inspectDist(distRoot, buildEntries, fixtureRoots, forbidden) {
  const manifestPath = path.join(distRoot, ".vite", "manifest.json");
  if (!(await exists(path.join(distRoot, "index.html"))))
    throw new Error(
      "production dist/index.html is missing; run Vite before the authority scan",
    );
  if (!(await exists(manifestPath)))
    throw new Error(
      "production Vite manifest is missing; build with --manifest",
    );
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  const entryKeys = Object.entries(manifest)
    .filter(([, value]) => value.isEntry)
    .map(([key]) => key);
  for (const entry of buildEntries) {
    const normalized = entry.replace(/^\.\//u, "");
    if (!entryKeys.includes(normalized))
      throw new Error(
        `Vite manifest does not identify ${normalized} as an entry`,
      );
  }
  const referenced = new Set(["index.html", ".vite/manifest.json"]);
  for (const [key, value] of Object.entries(manifest)) {
    if (
      fixtureRoots.some(
        (fixture) => key === fixture || key.startsWith(`${fixture}/`),
      )
    )
      throw new Error(`quarantined fixture entered the Vite manifest: ${key}`);
    for (const output of [
      value.file,
      ...(value.css || []),
      ...(value.assets || []),
    ].filter(Boolean))
      referenced.add(output);
  }
  for (const output of referenced) {
    const resolved = path.resolve(distRoot, output);
    if (
      !inside(distRoot, resolved) ||
      !(await exists(resolved)) ||
      !(await stat(resolved)).isFile()
    )
      throw new Error(
        `Vite manifest references missing or unsafe output: ${output}`,
      );
  }
  const files = (await listFiles(distRoot)).filter(
    (file) => relative(distRoot, file) !== "production-authority-scan.json",
  );
  const hashes = {};
  for (const file of files) {
    const bytes = await readFile(file);
    const name = relative(distRoot, file);
    hashes[name] = `sha256:${sha256(bytes)}`;
    if (TEXT_EXTENSIONS.has(path.extname(file).toLowerCase()))
      assertForbidden(
        bytes.toString("utf8"),
        `dist/${name}`,
        forbidden,
        "dist",
      );
  }
  return {
    entryKeys,
    files: files.map((file) => relative(distRoot, file)),
    hashes,
  };
}

export async function runProductionAuthorityScan({
  appName,
  root,
  entries = ["index.html"],
  fixtureRoots = ["fixtures/legacy-ui"],
  forbidden,
}) {
  const applicationRoot = path.resolve(root);
  const normalizedFixtures = fixtureRoots.map((fixture) =>
    fixture.replace(/\/$/u, ""),
  );
  const graph = await sourceGraph(applicationRoot, entries);
  const fixtureReport = [];
  for (const fixture of normalizedFixtures) {
    const fixtureRoot = path.resolve(applicationRoot, fixture);
    if (
      !(await exists(fixtureRoot)) ||
      !(await exists(path.join(fixtureRoot, "README.md")))
    )
      throw new Error(`quarantined fixture root requires ${fixture}/README.md`);
    const leak = graph.files.find((file) => inside(fixtureRoot, file));
    if (leak)
      throw new Error(
        `quarantined fixture entered the production graph: ${relative(applicationRoot, leak)}`,
      );
    fixtureReport.push({
      root: fixture,
      file_count: (await listFiles(fixtureRoot)).length,
      reachable: false,
    });
  }
  for (const file of graph.files) {
    const extension = path.extname(file).toLowerCase();
    if (
      TEXT_EXTENSIONS.has(extension) ||
      [".jsx", ".tsx", ".ts"].includes(extension)
    )
      assertForbidden(
        await readFile(file, "utf8"),
        relative(applicationRoot, file),
        forbidden,
        "source",
      );
  }
  const html = await readFile(path.join(applicationRoot, "index.html"), "utf8");
  const sourceEntries = htmlModuleSpecifiers(html).map((entry) =>
    entry.replace(/^\/+/, ""),
  );
  if (sourceEntries.length === 0)
    throw new Error("index.html declares no Vite module entry");
  const dist = await inspectDist(
    path.join(applicationRoot, "dist"),
    entries,
    normalizedFixtures,
    forbidden,
  );
  const report = {
    schema_version: "ioi.production-authority-scan.v1",
    app: appName,
    source_graph: {
      build_entries: entries,
      module_entries: sourceEntries,
      files: graph.files.map((file) => relative(applicationRoot, file)),
      packages: graph.packages,
    },
    quarantined_fixtures: fixtureReport,
    dist,
  };
  await writeFile(
    path.join(applicationRoot, "dist", "production-authority-scan.json"),
    `${JSON.stringify(report, null, 2)}\n`,
    "utf8",
  );
  console.log(
    `${appName} production authority scan passed: ${report.source_graph.files.length} graph files, ${dist.files.length} built files, ${fixtureReport.reduce((sum, fixture) => sum + fixture.file_count, 0)} quarantined fixture files unreachable`,
  );
}
