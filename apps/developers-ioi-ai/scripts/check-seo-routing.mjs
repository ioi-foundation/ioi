import fs from "node:fs";
import path from "node:path";

const appRoot = process.cwd();
const siteOrigin = "https://developers.ioi.ai";

const read = (relativePath) =>
  fs.readFileSync(path.join(appRoot, relativePath), "utf8");

const failures = [];

function assert(condition, message) {
  if (!condition) {
    failures.push(message);
  }
}

function routeUrl(routePath) {
  return `${siteOrigin}${routePath === "/" ? "/" : routePath}`;
}

const docs = read("src/content/docs.tsx");
const app = read("src/App.tsx");
const index = read("index.html");
const pkg = JSON.parse(read("package.json"));
const routes = [...docs.matchAll(/routePath: '([^']+)'/g)].map((match) => match[1]);

assert(routes.includes("/"), "Sitemap source routes must include the home route.");
assert(routes.length >= 18, `Expected all public doc routes, found ${routes.length}.`);
assert(new Set(routes).size === routes.length, "Duplicate routePath entries found.");

for (const routePath of routes) {
  assert(routePath.startsWith("/"), `Route path must be absolute: ${routePath}`);
  assert(!routePath.includes("#"), `Route path must not be hash-based: ${routePath}`);
}

const sitemap = read("public/sitemap.xml");
const robots = read("public/robots.txt");
const redirects = read("public/_redirects");
const htaccess = read("public/.htaccess");

for (const routePath of routes) {
  const url = routeUrl(routePath);
  assert(sitemap.includes(`<loc>${url}</loc>`), `Sitemap missing route: ${url}`);
}

assert(
  !sitemap.includes("#"),
  "Sitemap must not include legacy hash routes; canonical paths should be path-routed.",
);
assert(
  sitemap.includes("<lastmod>2026-05-16</lastmod>"),
  "Sitemap entries should carry the current verification date.",
);
assert(
  robots.includes(`Sitemap: ${siteOrigin}/sitemap.xml`),
  "robots.txt must point crawlers to the public sitemap.",
);

assert(
  redirects.trim() === "/* /index.html 200",
  "_redirects must include a static-host SPA fallback.",
);
assert(htaccess.includes("RewriteEngine On"), ".htaccess must enable rewrite rules.");
assert(
  htaccess.includes("RewriteCond %{REQUEST_FILENAME} -f") &&
    htaccess.includes("RewriteCond %{REQUEST_FILENAME} -d"),
  ".htaccess must preserve real static files and directories before the SPA fallback.",
);
assert(
  htaccess.includes("RewriteRule ^ index.html"),
  ".htaccess must route path requests to index.html.",
);

for (const needle of [
  '<meta name="robots" content="index,follow"',
  '<link rel="canonical" href="https://developers.ioi.ai/"',
  '<meta property="og:site_name" content="developers.ioi.ai"',
  '<meta property="og:type" content="website"',
  '<meta name="twitter:card" content="summary"',
  "<title>developers.ioi.ai | IOI Builder Docs</title>",
]) {
  assert(index.includes(needle), `index.html missing SEO baseline: ${needle}`);
}

for (const needle of [
  "const SITE_ORIGIN = 'https://developers.ioi.ai'",
  "function updateDocumentSeo(page: DocPage)",
  "document.title = title",
  "setMeta('name', 'description', page.summary)",
  "setMeta('property', 'og:url', url)",
  "canonical.href = url",
]) {
  assert(app.includes(needle), `App missing route-aware SEO update: ${needle}`);
}

assert(
  pkg.scripts?.["validate:seo"] === "node scripts/check-seo-routing.mjs",
  "package.json missing validate:seo script.",
);

if (failures.length > 0) {
  console.error("developers.ioi.ai SEO/routing check failed:");
  for (const failure of failures) {
    console.error(`- ${failure}`);
  }
  process.exit(1);
}

console.log("developers.ioi.ai SEO/routing check passed.");
