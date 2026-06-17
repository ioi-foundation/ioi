import { createServer } from "node:http";
import { readFile, stat, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { extname, join, normalize, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { chromium } from "playwright";

const repoRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
const distRoot = resolve(repoRoot, "apps/hypervisor/dist");

const contentTypes = new Map([
  [".css", "text/css; charset=utf-8"],
  [".html", "text/html; charset=utf-8"],
  [".js", "text/javascript; charset=utf-8"],
  [".json", "application/json; charset=utf-8"],
  [".png", "image/png"],
  [".svg", "image/svg+xml"],
  [".ttf", "font/ttf"],
  [".woff", "font/woff"],
  [".woff2", "font/woff2"],
]);

const homeOnboardingCompletedState = {
  selectedStepId: "setup-theme",
  completedStepIds: [
    "setup-theme",
    "setup-ui-density",
    "setup-web-extensions",
    "setup-language-extensions",
    "setup-sync-settings",
    "setup-command-palette",
    "setup-open-code",
    "setup-quick-open",
    "setup-desktop-theme",
    "setup-video-tutorial",
    "fundamentals-settings",
    "fundamentals-extensions",
    "fundamentals-terminal",
    "fundamentals-debug",
    "fundamentals-git-clone",
    "fundamentals-git-init",
    "fundamentals-git",
    "fundamentals-install-git",
    "fundamentals-tasks",
    "fundamentals-shortcuts",
    "fundamentals-workspace-trust",
    "accessibility-help",
    "accessibility-view",
    "accessibility-verbosity",
    "accessibility-command-palette",
    "accessibility-keybindings",
    "accessibility-signals",
    "accessibility-hover",
    "accessibility-symbols",
    "accessibility-folding",
    "accessibility-intellisense",
    "accessibility-settings",
    "accessibility-dictation",
    "notebook-profile",
  ],
  completedAtMs: 1_780_000_000_000,
  skippedAtMs: 1_780_000_000_000,
  actionReceipts: [],
};

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function contentTypeFor(pathname) {
  return contentTypes.get(extname(pathname)) ?? "application/octet-stream";
}

function pathInside(root, candidate) {
  const rel = relative(root, candidate);
  return rel === "" || (!rel.startsWith("..") && !rel.includes("..\\"));
}

async function fileForRequest(url) {
  const requestPath = decodeURIComponent(url.pathname);
  const normalizedPath = normalize(requestPath).replace(/^(\.\.[/\\])+/, "");
  const candidate = resolve(distRoot, `.${normalizedPath}`);
  if (pathInside(distRoot, candidate)) {
    try {
      const info = await stat(candidate);
      if (info.isFile()) {
        return candidate;
      }
    } catch {
      // Fall through to the SPA entry.
    }
  }
  return join(distRoot, "index.html");
}

async function createStaticServer() {
  assert(
    existsSync(join(distRoot, "index.html")),
    "apps/hypervisor/dist/index.html is missing; run npm run build --workspace=@ioi/hypervisor-app first.",
  );
  const server = createServer(async (request, response) => {
    try {
      const filePath = await fileForRequest(
        new URL(request.url ?? "/", "http://127.0.0.1"),
      );
      response.setHeader("content-type", contentTypeFor(filePath));
      response.end(await readFile(filePath));
    } catch (error) {
      response.statusCode = 500;
      response.end(error instanceof Error ? error.message : String(error));
    }
  });
  await new Promise((resolveListen) => {
    server.listen(0, "127.0.0.1", resolveListen);
  });
  return {
    server,
    url: `http://127.0.0.1:${server.address().port}/`,
  };
}

async function main() {
  const evidencePath = process.argv.includes("--evidence")
    ? process.argv[process.argv.indexOf("--evidence") + 1]
    : null;
  const { server, url } = await createStaticServer();
  const browser = await chromium.launch({ headless: true });
  const consoleMessages = [];
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 960 } });
    page.setDefaultTimeout(90_000);
    await page.addInitScript((completedState) => {
      window.localStorage.setItem(
        "hypervisor.home.onboarding.v1",
        JSON.stringify(completedState),
      );
    }, homeOnboardingCompletedState);
    page.on("console", (message) => {
      if (["error", "warning"].includes(message.type())) {
        consoleMessages.push({
          type: message.type(),
          text: message.text(),
        });
      }
    });
    page.on("pageerror", (error) => {
      consoleMessages.push({
        type: "pageerror",
        text: error.message,
      });
    });

    await page.goto(url, { waitUntil: "domcontentloaded", timeout: 90_000 });
    const onboardingSkip = page.locator(".chat-home-walkthrough-skip");
    if (await onboardingSkip.count()) {
      await onboardingSkip.first().click({ force: true });
    }
    try {
      await page.waitForSelector('[data-home-dashboard-variant="hypervisor-zero-state"]');
    } catch (error) {
      const rootText = await page.locator("#root").innerText({ timeout: 1_000 }).catch(
        () => "",
      );
      throw new Error(
        [
          "Hypervisor Home cockpit did not become visible.",
          `root_text=${JSON.stringify(rootText.slice(0, 600))}`,
          `console=${JSON.stringify(consoleMessages.slice(-10))}`,
          error instanceof Error ? error.message : String(error),
        ].join("\n"),
      );
    }
    const bodyText = await page.locator("body").innerText();
    assert(bodyText.includes("Welcome back to Hypervisor"), "Home cockpit did not render Hypervisor copy.");
    assert(
      bodyText.includes("What do you want to get done today?"),
      "Home does not expose the IOI-reference intent composer.",
    );
    assert(!bodyText.includes("Autopilot Code"), "Legacy Autopilot Code copy is visible in the shell.");
    await page.waitForSelector('[data-home-intent-composer="ioi-reference-primary"]');
    await page.waitForSelector('[data-home-intent-submit="new-session"]');

    const seededIntent = "Automate env setup";
    await page
      .locator('[data-home-intent-recipe="automation.default"]')
      .click();
    await page.locator('[data-home-intent-submit="new-session"]').click();
    await page.waitForSelector(".hypervisor-new-session-modal");
    await page.waitForSelector('[data-new-session-launch-summary="ioi.hypervisor.new_session_launch_summary.v1"]');
    const recipeSelection = await page
      .locator('button:has-text("Automation")')
      .first()
      .getAttribute("class");
    assert(
      recipeSelection?.includes("is-selected"),
      "New Session did not receive the Home quickstart recipe destination.",
    );
    const modalSeedIntent = await page
      .locator('[data-new-session-field="seed-intent"]')
      .inputValue();
    assert(
      modalSeedIntent === seededIntent,
      "New Session did not receive the Home composer seed intent.",
    );
    const summarySeedIntent = await page
      .locator("[data-new-session-seed-intent]")
      .getAttribute("data-new-session-seed-intent");
    assert(
      summarySeedIntent === seededIntent,
      "New Session launch summary did not bind the seed intent.",
    );
    const defaultPrivacy = await page
      .locator('[data-new-session-field="privacy"]')
      .inputValue();
    assert(
      defaultPrivacy === "privacy:ctee-private-workspace",
      "New Session should default to cTEE private workspace posture.",
    );
    await page.selectOption('[data-new-session-field="harness"]', "agent-harness-adapter:codex_cli");
    await page.waitForFunction(() => {
      const summary = document.querySelector("[data-new-session-harness-verdict]");
      return summary?.getAttribute("data-new-session-harness-verdict") === "blocked";
    });
    const blockedLaunchDisabled = await page
      .locator('[data-new-session-action="launch"]')
      .isDisabled();
    assert(blockedLaunchDisabled, "External harness with cTEE private workspace should disable launch.");

    await page.selectOption('[data-new-session-field="privacy"]', "privacy:redacted-projection");
    await page.waitForFunction(() => {
      const summary = document.querySelector("[data-new-session-harness-verdict]");
      return [
        "adapter_native_only",
        "compatible",
        "provider_trust",
      ].includes(summary?.getAttribute("data-new-session-harness-verdict") ?? "");
    });
    const compatibleLaunchDisabled = await page
      .locator('[data-new-session-action="launch"]')
      .isDisabled();
    assert(!compatibleLaunchDisabled, "Compatible redacted external harness launch should be available.");
    await page.locator('button[aria-label="Close New Session"]').click();

    await page.locator('[data-window-surface="providers"]').click();
    await page.waitForSelector("[data-hypervisor-provider-placement]");
    await page
      .locator('[data-provider-operation-kind="archive"]')
      .first()
      .click();
    await page.waitForSelector("[data-provider-operation-proposal]");
    const proposalAdmission = await page
      .locator("[data-provider-operation-proposal]")
      .getAttribute("data-provider-operation-admission");
    assert(
      proposalAdmission === "ready_for_daemon_admission",
      "Provider operation proposal did not surface daemon admission posture.",
    );

    const result = {
      schema_version: "ioi.hypervisor.app_shell_contract.v1",
      ok: true,
      url,
      checks: [
        "home_intent_composer_rendered",
        "home_seed_intent_reaches_new_session",
        "home_quickstart_recipe_reaches_new_session",
        "home_cockpit_rendered",
        "new_session_launch_summary_rendered",
        "external_harness_ctee_blocked",
        "external_harness_redacted_projection_allowed",
        "provider_operation_proposal_rendered",
      ],
      consoleMessages,
    };
    if (evidencePath) {
      await writeFile(evidencePath, `${JSON.stringify(result, null, 2)}\n`);
    }
    console.log(JSON.stringify(result, null, 2));
  } finally {
    await browser.close().catch(() => undefined);
    await new Promise((resolveClose) => server.close(resolveClose));
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.stack : error);
  process.exitCode = 1;
});
