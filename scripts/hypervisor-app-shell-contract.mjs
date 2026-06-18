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
      await page.waitForSelector('[data-home-dashboard-variant="ioi-reference-home"]');
    } catch (error) {
      const rootText = await page.locator("#root").innerText({ timeout: 1_000 }).catch(
        () => "",
      );
      throw new Error(
        [
          "Hypervisor Home reference prompt shell did not become visible.",
          `root_text=${JSON.stringify(rootText.slice(0, 600))}`,
          `console=${JSON.stringify(consoleMessages.slice(-10))}`,
          error instanceof Error ? error.message : String(error),
        ].join("\n"),
      );
    }
    const bodyText = await page.locator("body").innerText();
    assert(
      bodyText.includes("What do you want to get done today?"),
      "Home does not expose the IOI-reference intent composer.",
    );
    const homePromptPlaceholder = await page
      .locator('textarea[aria-label="Session intent"]')
      .getAttribute("placeholder");
    assert(
      homePromptPlaceholder === "Describe your task or type / for commands",
      "Home does not expose the IOI-reference prompt input.",
    );
    assert(!bodyText.includes("Autopilot Code"), "Legacy Autopilot Code copy is visible in the shell.");

    const seededIntent =
      "Open a governed Workbench session to find, reproduce, and fix a bug in this project.";
    await page.locator('button:has-text("Fix a bug")').click();
    await page.waitForSelector(".hypervisor-new-session-modal");
    await page.waitForSelector('[data-new-session-launch-summary="ioi.hypervisor.new_session_launch_summary.v1"]');
    const summarySeedIntent = await page
      .locator("[data-new-session-seed-intent]")
      .getAttribute("data-new-session-seed-intent");
    assert(
      summarySeedIntent === seededIntent,
      "New Session launch summary did not bind the seed intent.",
    );
    const defaultPrivacy = await page
      .locator('label:has-text("Privacy") select')
      .inputValue();
    assert(
      defaultPrivacy === "privacy:ctee-private-workspace",
      "New Session should default to cTEE private workspace posture.",
    );
    await page.selectOption('label:has-text("Harness") select', "agent-harness-adapter:codex_cli");
    await page.waitForFunction(() => {
      const summary = document.querySelector("[data-new-session-harness-verdict]");
      return summary?.getAttribute("data-new-session-harness-verdict") === "blocked";
    });
    const blockedLaunchDisabled = await page
      .locator(".hypervisor-new-session-modal__compact-choice")
      .first()
      .isDisabled();
    assert(blockedLaunchDisabled, "External harness with cTEE private workspace should disable launch.");

    await page.selectOption('label:has-text("Privacy") select', "privacy:redacted-projection");
    await page.waitForFunction(() => {
      const summary = document.querySelector("[data-new-session-harness-verdict]");
      return [
        "adapter_native_only",
        "compatible",
        "provider_trust",
      ].includes(summary?.getAttribute("data-new-session-harness-verdict") ?? "");
    });
    const compatibleLaunchDisabled = await page
      .locator(".hypervisor-new-session-modal__compact-choice")
      .first()
      .isDisabled();
    assert(!compatibleLaunchDisabled, "Compatible redacted external harness launch should be available.");
    await page.locator('button[aria-label="Close New Session"]').click();

    await page.locator('[data-window-surface="projects"]').click();
    await page.waitForSelector("[data-hypervisor-project-state]");
    const projectsText = await page.locator("body").innerText();
    assert(projectsText.includes("No projects"), "Projects page did not render the IOI-reference empty state.");
    assert(projectsText.includes("New project"), "Projects page did not expose the New project action.");
    assert(
      !(projectsText.match(/Code repositories|Pull requests|No pull requests created by you|Object Head|State Root|Agentgres op|restore posture and state roots/i)),
      "Projects page leaked repository-console or runtime-truth copy into the visible surface.",
    );
    const projectsSearchPlaceholder = await page
      .locator(".hypervisor-project-state__search input")
      .getAttribute("placeholder");
    assert(
      projectsSearchPlaceholder === "Search projects",
      "Projects page did not expose the reference search control.",
    );

    await page.locator('[data-window-surface="workbench"]').click();
    await page.waitForSelector('[data-workbench-adapter-hub="true"]');
    const workbenchText = await page.locator("body").innerText();
    assert(workbenchText.includes("Choose a governed adapter target"), "Workbench adapter hub did not render.");
    assert(workbenchText.includes("Adapter targets"), "Workbench did not expose adapter targets.");
    assert(
      !(workbenchText.match(/Code repositories|Pull requests|No pull requests created by you|daemon gates|Agentgres/i)),
      "Workbench leaked repository-console or implementation-truth copy into the visible surface.",
    );
    const adapterTargetCount = await page
      .locator("[data-workbench-adapter-target]")
      .count();
    assert(adapterTargetCount >= 8, "Workbench did not render enough adapter target choices.");
    await page.locator('[data-workbench-adapter-target="cursor"]').click();
    const cursorPressed = await page
      .locator('[data-workbench-adapter-target="cursor"]')
      .getAttribute("aria-pressed");
    assert(cursorPressed === "true", "Workbench adapter target selection is not live.");

    await page.locator('[data-window-surface="agents"]').click();
    await page.waitForSelector("[data-hypervisor-agents]");
    const agentsText = await page.locator("body").innerText();
    assert(agentsText.includes("Agents"), "Agents surface did not render.");
    const agentsSearchPlaceholder = await page
      .locator(".hypervisor-agents__search input")
      .getAttribute("placeholder");
    assert(
      agentsSearchPlaceholder === "Search agents...",
      "Agents surface did not expose the reference search control.",
    );
    assert(agentsText.includes("Selected agent"), "Agents surface did not expose a selected agent detail pane.");
    assert(agentsText.includes("Interface"), "Agents surface did not expose the product-facing interface column.");
    assert(agentsText.includes("Access"), "Agents surface did not expose the product-facing access controls.");
    assert(
      !(
        agentsText.match(
          /Configured workers|Review leases|Daemon Owned|Proposal Source Only|Default Harness Profile|Hypervisor Daemon|Agentgres|wallet\.network/i,
        )
      ),
      "Agents surface leaked implementation-truth copy into the visible product surface.",
    );

    const result = {
      schema_version: "ioi.hypervisor.app_shell_contract.v1",
      ok: true,
      url,
      checks: [
        "home_reference_prompt_shell_rendered",
        "home_seed_intent_reaches_new_session",
        "home_reference_prompt_reaches_new_session",
        "new_session_launch_summary_rendered",
        "external_harness_ctee_blocked",
        "external_harness_redacted_projection_allowed",
        "projects_reference_empty_state_rendered",
        "workbench_adapter_hub_rendered",
        "workbench_adapter_selection_live",
        "agents_reference_product_surface_rendered",
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
