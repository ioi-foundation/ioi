import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { spawn } from "node:child_process";

const appRoot = process.cwd();
const repoRoot = path.resolve(appRoot, "../..");
const siteOrigin = "https://developers.ioi.ai";
const blockedCopy = [
  "Current / runnable",
  "runnable today",
  "framed surface",
  "mock quickstart",
  "Mock quickstart",
  "Explicit mock",
  "mock-only",
  "Source freshness",
  "Source Provenance",
  "Canonical Depth",
];
const routes = [
  ["/", "Start Here"],
  ["/quickstart", "Quickstart"],
  ["/api", "API Reference"],
  ["/sdks", "SDKs & Libraries"],
  ["/autopilot", "Autopilot"],
  ["/runtime", "Runtime Daemon"],
  ["/model-mounting", "Model Mounting"],
  ["/mcp-tools", "MCP Tools"],
  ["/benchmarks", "Benchmarks"],
  ["/ship/sas", "sas.xyz"],
  ["/ship/aiagent", "aiagent.xyz"],
];

const port = await findOpenPort(4175);
const baseUrl = `http://127.0.0.1:${port}`;
const npmCommand = process.platform === "win32" ? "npm.cmd" : "npm";
const server = spawn(
  npmCommand,
  ["run", "preview", "--", "--host", "127.0.0.1", "--port", String(port), "--strictPort"],
  {
    cwd: appRoot,
    detached: process.platform !== "win32",
    env: process.env,
    stdio: ["ignore", "pipe", "pipe"],
  },
);

let output = "";
server.stdout.on("data", (chunk) => {
  output += chunk.toString();
});
server.stderr.on("data", (chunk) => {
  output += chunk.toString();
});

try {
  await waitForServer(`${baseUrl}/`);
  const chromium = await loadPlaywrightChromium();

  if (chromium) {
    await runPlaywrightSmoke(chromium, baseUrl);
  } else {
    await runHttpFallbackSmoke(baseUrl);
  }

  console.log("developers.ioi.ai route smoke passed.");
} catch (error) {
  console.error(output.trim());
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
} finally {
  await terminateServer(server);
}

async function runPlaywrightSmoke(chromium, baseUrl) {
  const artifactDir = path.join(
    repoRoot,
    ".tmp/developers-ioi-ai-visual-smoke",
    new Date().toISOString().replace(/[:.]/g, "-"),
  );
  fs.mkdirSync(artifactDir, { recursive: true });

  let browser;
  try {
    browser = await chromium.launch({ headless: true });
  } catch (error) {
    console.warn(
      `Playwright is installed but no browser could be launched; falling back to HTTP smoke. ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
    await runHttpFallbackSmoke(baseUrl);
    return;
  }

  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
    for (const [routePath, expectedText] of routes) {
      await page.goto(`${baseUrl}${routePath}`, { waitUntil: "networkidle" });
      const bodyText = (await page.locator("body").innerText()).replace(/\s+/g, " ");
      if (!bodyText.includes(expectedText)) {
        throw new Error(`Route ${routePath} did not render expected text: ${expectedText}`);
      }
      const expectedCanonical = `${siteOrigin}${routePath === "/" ? "/" : routePath}`;
      const canonical = await page.locator('link[rel="canonical"]').getAttribute("href");
      if (canonical !== expectedCanonical) {
        throw new Error(
          `Route ${routePath} rendered canonical ${canonical ?? "(missing)"}, expected ${expectedCanonical}`,
        );
      }
      const description = await page.locator('meta[name="description"]').getAttribute("content");
      if (!description || description.length < 50) {
        throw new Error(`Route ${routePath} rendered a weak or missing meta description.`);
      }
      for (const phrase of blockedCopy) {
        if (bodyText.toLowerCase().includes(phrase.toLowerCase())) {
          throw new Error(`Route ${routePath} still renders obtuse copy: ${phrase}`);
        }
      }
      if (routePath === "/quickstart") {
        const runtimeIndex = bodyText.indexOf("Connect To The Local Runtime");
        const fixtureIndex = bodyText.indexOf("Offline SDK Fixture For Tests");
        if (runtimeIndex === -1 || fixtureIndex === -1 || fixtureIndex < runtimeIndex) {
          throw new Error("Quickstart should lead with daemon-backed local runtime before the offline fixture.");
        }
      }
      const filename = routePath === "/" ? "root.png" : `${routePath.slice(1).replace(/\//g, "-")}.png`;
      await captureScreenshot(page, path.join(artifactDir, filename));
    }
    console.log(`Playwright screenshots written to ${path.relative(repoRoot, artifactDir)}`);
  } finally {
    await browser.close();
  }
}

async function captureScreenshot(page, screenshotPath) {
  try {
    await page.screenshot({
      path: screenshotPath,
      fullPage: true,
      animations: "disabled",
    });
  } catch (error) {
    console.warn(
      `Full-page screenshot failed; capturing viewport instead. ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
    await page.screenshot({
      path: screenshotPath,
      animations: "disabled",
    });
  }
}

async function runHttpFallbackSmoke(baseUrl) {
  console.warn("Playwright is not installed; running HTTP route fallback smoke without screenshots.");
  for (const [routePath] of routes) {
    const response = await fetch(`${baseUrl}${routePath}`);
    if (!response.ok) {
      throw new Error(`Route ${routePath} returned HTTP ${response.status}`);
    }
    const html = await response.text();
    if (!html.includes('<div id="root">')) {
      throw new Error(`Route ${routePath} did not return the Vite app shell.`);
    }
  }

  for (const assetPath of ["/robots.txt", "/sitemap.xml", "/_redirects"]) {
    const response = await fetch(`${baseUrl}${assetPath}`);
    if (!response.ok) {
      throw new Error(`Static SEO asset ${assetPath} returned HTTP ${response.status}`);
    }
  }
}

async function loadPlaywrightChromium() {
  try {
    const mod = await import("playwright");
    return mod.chromium;
  } catch {
    try {
      const mod = await import("@playwright/test");
      return mod.chromium;
    } catch {
      return null;
    }
  }
}

async function waitForServer(url) {
  const deadline = Date.now() + 20_000;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(url);
      if (response.ok) {
        return;
      }
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
  }
  throw new Error(`Timed out waiting for preview server at ${url}`);
}

function findOpenPort(startPort) {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.unref();
    server.on("error", (error) => {
      if (error.code === "EADDRINUSE") {
        resolve(findOpenPort(startPort + 1));
      } else {
        reject(error);
      }
    });
    server.listen(startPort, "127.0.0.1", () => {
      const address = server.address();
      server.close(() => resolve(address.port));
    });
  });
}

async function terminateServer(child) {
  if (child.exitCode !== null) {
    return;
  }

  killChild(child, "SIGTERM");
  const exited = await waitForExit(child, 2_000);
  if (!exited) {
    killChild(child, "SIGKILL");
    await waitForExit(child, 1_000);
  }
}

function killChild(child, signal) {
  try {
    if (process.platform !== "win32" && child.pid) {
      process.kill(-child.pid, signal);
    } else {
      child.kill(signal);
    }
  } catch (error) {
    if (error?.code !== "ESRCH") {
      throw error;
    }
  }
}

function waitForExit(child, timeoutMs) {
  return new Promise((resolve) => {
    if (child.exitCode !== null) {
      resolve(true);
      return;
    }

    const timeout = setTimeout(() => resolve(false), timeoutMs);
    timeout.unref();
    child.once("exit", () => {
      clearTimeout(timeout);
      resolve(true);
    });
  });
}
