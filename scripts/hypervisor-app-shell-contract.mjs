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
    const page = await browser.newPage({
      viewport: { width: 1440, height: 960 },
    });
    page.setDefaultTimeout(90_000);
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
      await page.waitForSelector(
        '[data-home-dashboard-variant="ioi-reference-home"]',
      );
    } catch (error) {
      const rootText = await page
        .locator("#root")
        .innerText({ timeout: 1_000 })
        .catch(() => "");
      throw new Error(
        [
          "Hypervisor Home reference session workplane did not become visible.",
          `root_text=${JSON.stringify(rootText.slice(0, 600))}`,
          `console=${JSON.stringify(consoleMessages.slice(-10))}`,
          error instanceof Error ? error.message : String(error),
        ].join("\n"),
      );
    }
    const bodyText = await page.locator("body").innerText();
    const promptPlaceholder = await page
      .locator(".chat-home-zero-composer textarea")
      .getAttribute("placeholder");
    assert(
      bodyText.includes("What do you want to get done today?"),
      "Home does not expose the IOI-reference prompt surface.",
    );
    assert(
      promptPlaceholder === "Describe your task or type / for commands",
      "Home does not expose the reference prompt composer.",
    );
    assert(
      bodyText.includes("Recent Sessions"),
      "Home does not expose the IOI-reference recent session list.",
    );
    assert(
      (await page.locator('[data-home-recent-sessions="ioi-reference"]').count()) ===
        1,
      "Home recent sessions list is not bound to the IOI-reference marker.",
    );
    const seededIntent =
      "Open a governed Hypervisor session for this workspace.";
    await page.locator('[data-home-start-session="true"]').click();
    await page.waitForSelector(".hypervisor-new-session-modal");
    await page.waitForSelector(
      '[data-new-session-launch-summary="ioi.hypervisor.new_session_launch_summary.v1"]',
    );
    await page.waitForSelector(
      '[data-new-session-target-binding="ioi.hypervisor.new_session_target_binding.v1"]',
    );
    const summarySeedIntent = await page
      .locator("[data-new-session-seed-intent]")
      .getAttribute("data-new-session-seed-intent");
    assert(
      summarySeedIntent === seededIntent,
      "New Session launch summary did not bind the seed intent.",
    );
    const targetBindingRef = await page
      .locator("[data-new-session-target-binding-ref]")
      .getAttribute("data-new-session-target-binding-ref");
    const targetKind = await page
      .locator("[data-new-session-target-kind]")
      .getAttribute("data-new-session-target-kind");
    const targetSessionRoute = await page
      .locator("[data-new-session-target-session-route]")
      .getAttribute("data-new-session-target-session-route");
    assert(
      targetBindingRef?.startsWith("target-binding:new-session/"),
      "New Session launch summary did not bind a durable target binding ref.",
    );
    assert(
      targetKind === "mission",
      "New Session launch summary did not expose the selected target kind.",
    );
    assert(
      targetSessionRoute?.startsWith("session-route:sessions/"),
      "New Session launch summary did not expose the selected session route.",
    );
    const defaultPrivacy = await page
      .locator('label:has-text("Privacy") select')
      .inputValue();
    assert(
      defaultPrivacy === "privacy:ctee-private-workspace",
      "New Session should default to cTEE private workspace posture.",
    );
    await page.selectOption(
      'label:has-text("Harness") select',
      "agent-harness-adapter:codex_cli",
    );
    await page.waitForFunction(() => {
      const summary = document.querySelector(
        "[data-new-session-harness-verdict]",
      );
      return (
        summary?.getAttribute("data-new-session-harness-verdict") === "blocked"
      );
    });
    const blockedLaunchDisabled = await page
      .locator(".hypervisor-new-session-modal__compact-choice")
      .first()
      .isDisabled();
    assert(
      blockedLaunchDisabled,
      "External harness with cTEE private workspace should disable launch.",
    );

    await page.selectOption(
      'label:has-text("Privacy") select',
      "privacy:redacted-projection",
    );
    await page.waitForFunction(() => {
      const summary = document.querySelector(
        "[data-new-session-harness-verdict]",
      );
      return ["adapter_native_only", "compatible", "provider_trust"].includes(
        summary?.getAttribute("data-new-session-harness-verdict") ?? "",
      );
    });
    const compatibleLaunchDisabled = await page
      .locator(".hypervisor-new-session-modal__compact-choice")
      .first()
      .isDisabled();
    assert(
      !compatibleLaunchDisabled,
      "Compatible redacted external harness launch should be available.",
    );
    await page.locator('button[aria-label="Close New Session"]').click();

    await page.goto(new URL("?view=sessions", url).toString(), {
      waitUntil: "domcontentloaded",
      timeout: 90_000,
    });
    await page.waitForSelector('[data-session-reference-page="environment-detail"]');
    const sessionsText = await page.locator("body").innerText();
    assert(
      sessionsText.includes("Started remote environment") &&
        sessionsText.includes("Initialized repository") &&
        sessionsText.includes("Loaded secrets") &&
        sessionsText.includes("Loaded automations") &&
        sessionsText.includes("Started dev container"),
      "Sessions did not render the IOI-reference environment lifecycle.",
    );
    assert(
      sessionsText.includes("No open ports"),
      "Sessions did not render the reference empty ports state.",
    );
    assert(
      sessionsText.includes(".devcontainer/") &&
        sessionsText.includes("devcontainer.json") &&
        sessionsText.includes("Dockerfile") &&
        sessionsText.includes("parent-harness-evidence-boundary.md"),
      "Sessions did not render the reference changed-file tree.",
    );
    assert(
      (await page.locator(".hypervisor-session-operations__activity-grid").count()) ===
        0,
      "Sessions reintroduced the non-reference center activity card grid.",
    );
    assert(
      (await page.locator("[data-session-port-service]").count()) === 0,
      "Sessions should render empty ports until daemon reports an opened service.",
    );

    await page.locator('[data-window-surface="projects"]').click();
    await page.waitForSelector("[data-hypervisor-project-state]");
    const projectsText = await page.locator("body").innerText();
    assert(
      projectsText.includes("No projects"),
      "Projects page did not render the IOI-reference empty state.",
    );
    assert(
      projectsText.includes("New project"),
      "Projects page did not expose the New project action.",
    );
    const projectsSearchPlaceholder = await page
      .locator(".hypervisor-project-state__search input")
      .getAttribute("placeholder");
    assert(
      projectsSearchPlaceholder === "Search projects",
      "Projects page did not expose the reference search control.",
    );

    await page.goto(new URL("?view=workbench", url).toString(), {
      waitUntil: "domcontentloaded",
      timeout: 90_000,
    });
    await page.waitForSelector(".chat-workspace-oss-shell__workbench-surface");
    const workbenchSurfaceCount = await page
      .locator(".chat-workspace-oss-shell__workbench-surface")
      .count();
    assert(
      workbenchSurfaceCount === 1,
      "Workbench did not render the code-editor workspace session surface.",
    );

    await page.goto(new URL("?view=agents", url).toString(), {
      waitUntil: "domcontentloaded",
      timeout: 90_000,
    });
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
    assert(
      agentsText.includes("Selected agent"),
      "Agents surface did not expose a selected agent detail pane.",
    );
    assert(
      agentsText.includes("Interface"),
      "Agents surface did not expose the product-facing interface column.",
    );
    assert(
      agentsText.includes("Access"),
      "Agents surface did not expose the product-facing access controls.",
    );
    assert(
      !agentsText.includes("Build with Agent"),
      "Agents surface should not expose a right-side agent chat pane.",
    );
    assert(
      !agentsText.match(
        /Configured workers|Review leases|Daemon Owned|Proposal Source Only|Default Harness Profile|Hypervisor Daemon|Agentgres|wallet\.network|Total Agents|Personal Source Only|Provider Source Only/i,
      ),
      "Agents surface leaked implementation-truth copy into the visible product surface.",
    );

    await page.goto(new URL("?view=receipts", url).toString(), {
      waitUntil: "domcontentloaded",
      timeout: 90_000,
    });
    await page.waitForSelector(
      '[data-receipt-evidence-filter-controls="true"]',
    );
    const initialReceiptCount = Number(
      await page
        .locator("[data-receipt-evidence-filtered-count]")
        .getAttribute("data-receipt-evidence-filtered-count"),
    );
    assert(
      initialReceiptCount > 1,
      "Receipts surface did not render evidence records.",
    );
    await page.selectOption('label:has-text("Status") select', "draft");
    await page.waitForFunction(() => {
      const root = document.querySelector(
        "[data-receipt-evidence-filtered-count]",
      );
      const cards = Array.from(
        document.querySelectorAll("[data-receipt-evidence-status]"),
      );
      return (
        Number(
          root?.getAttribute("data-receipt-evidence-filtered-count") ?? "0",
        ) > 0 &&
        cards.every(
          (card) =>
            card.getAttribute("data-receipt-evidence-status") === "draft",
        )
      );
    });
    await page.locator("[data-receipt-evidence-review]").first().click();
    const receiptDetailRef = await page
      .locator("[data-receipt-evidence-detail]")
      .getAttribute("data-receipt-evidence-detail");
    const receiptReplayRef = await page
      .locator("[data-receipt-evidence-detail]")
      .getAttribute("data-receipt-evidence-replay-ref");
    assert(
      receiptDetailRef?.startsWith("receipt:"),
      "Receipts surface did not expose selected receipt detail.",
    );
    assert(
      receiptReplayRef?.startsWith("agentgres://replay/"),
      "Receipts surface did not expose selected replay ref.",
    );

    await page.goto(new URL("?view=settings", url).toString(), {
      waitUntil: "domcontentloaded",
      timeout: 90_000,
    });
    await page.waitForSelector(
      '[data-settings-reference-shell="ioi-settings"]',
    );
    const settingsText = await page.locator("body").innerText();
    assert(
      settingsText.includes("User settings"),
      "Settings reference shell did not render.",
    );
    assert(
      settingsText.includes("Account"),
      "Settings did not expose Account navigation.",
    );
    assert(
      settingsText.includes("Secrets"),
      "Settings did not expose Secrets navigation.",
    );
    assert(
      settingsText.includes("Git authentications"),
      "Settings did not expose Git authentication navigation.",
    );
    assert(
      settingsText.includes("Personal access tokens"),
      "Settings did not expose personal access token navigation.",
    );
    assert(
      settingsText.includes("Integrations"),
      "Settings did not expose Integrations navigation.",
    );
    assert(
      settingsText.includes("Default code editor target"),
      "Settings did not expose default code editor target preference.",
    );
    assert(
      settingsText.includes("Embedded code editor"),
      "Settings did not expose the embedded code editor preference.",
    );
    assert(
      !settingsText.match(
        /Default Editor|default selected editor|Code tab|Show the embedded VS Code editor|adapter_preference_ref/i,
      ),
      "Settings leaked old Code tab or raw adapter-preference copy.",
    );
    const settingsShell = page.locator(
      '[data-settings-reference-shell="ioi-settings"]',
    );
    const settingsAdvancedSummary = settingsShell
      .locator("summary:has-text('Advanced')")
      .first();
    if (await settingsAdvancedSummary.isVisible()) {
      await settingsAdvancedSummary.click();
    }
    const codeEditorAdapterSettingsNav = settingsShell
      .locator(
        '.chat-settings-reference-advanced button:has-text("Code editor adapter")',
      )
      .first();
    await codeEditorAdapterSettingsNav.scrollIntoViewIfNeeded();
    await codeEditorAdapterSettingsNav.click();
    const settingsMain = settingsShell.locator(".chat-settings-reference-main");
    await settingsMain
      .locator("[data-code-editor-adapter-executor-lane]")
      .first()
      .waitFor({ state: "visible", timeout: 30_000 });
    const settingsAdapterRows = await settingsMain
      .locator("[data-code-editor-adapter-executor-lane]")
      .count();
    assert(
      settingsAdapterRows >= 8,
      "Settings did not expose governed adapter target metadata.",
    );
    const settingsControlRows = await settingsMain
      .locator("[data-code-editor-adapter-control-action]")
      .count();
    assert(
      settingsControlRows === settingsAdapterRows,
      "Settings adapter rows did not carry control action metadata.",
    );
    const settingsAdapterText = await page.locator("body").innerText();
    assert(
      settingsAdapterText.includes("Open embedded") &&
        settingsAdapterText.includes("Open desktop") &&
        settingsAdapterText.includes("Local workspace"),
      "Settings adapter section did not render product-facing adapter control labels.",
    );

    const result = {
      schema_version: "ioi.hypervisor.app_shell_contract.v1",
      ok: true,
      url,
      checks: [
        "home_reference_prompt_surface_rendered",
        "home_seed_intent_reaches_new_session",
        "home_reference_prompt_action_reaches_new_session",
        "new_session_launch_summary_rendered",
        "external_harness_ctee_blocked",
        "external_harness_redacted_projection_allowed",
        "sessions_reference_environment_lifecycle_rendered",
        "projects_reference_empty_state_rendered",
        "workbench_workspace_session_surface_rendered",
        "agents_reference_product_surface_rendered",
        "receipts_filter_and_drill_in_rendered",
        "settings_reference_surface_rendered",
        "settings_reference_authority_sections_rendered",
        "settings_adapter_controls_rendered",
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
