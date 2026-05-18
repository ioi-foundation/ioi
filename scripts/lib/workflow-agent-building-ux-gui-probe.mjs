#!/usr/bin/env node
import { writeFileSync } from "node:fs";

const outputPath = process.argv[2];
if (!outputPath) {
  throw new Error("usage: workflow-agent-building-ux-gui-probe.mjs <output-path>");
}

const appUrl = process.env.AUTOPILOT_GUI_URL ?? "http://127.0.0.1:1428/chat";

async function playwright() {
  try {
    return await import("playwright");
  } catch (error) {
    throw new Error(`Playwright is required for this live GUI probe: ${error.message}`);
  }
}

async function clickFirstExisting(page, selectors) {
  for (const selector of selectors) {
    const locator = page.locator(selector).first();
    if ((await locator.count()) > 0) {
      await locator.click({ timeout: 5_000 });
      return selector;
    }
  }
  throw new Error(`Missing expected selector: ${selectors.join(" | ")}`);
}

async function openWorkflows(page) {
  await page.goto(appUrl, { waitUntil: "domcontentloaded" });
  await page.getByRole("button", { name: /workflows/i }).click({ timeout: 15_000 });
}

async function createBlankWorkflow(page, name) {
  await page.getByTestId("workflow-create-button").click();
  await page.getByTestId("workflow-create-modal").waitFor({ timeout: 10_000 });
  await page.getByTestId("workflow-create-name").fill(name);
  await page.getByTestId("workflow-create-submit").click();
  await page.getByTestId("workflow-empty-start-overlay").waitFor({ timeout: 10_000 });
}

async function addManualInput(page) {
  await page
    .locator('[data-testid="workflow-empty-start-source.manual"]')
    .evaluate((element) => {
      if (element instanceof HTMLElement) element.click();
    });
  if ((await page.getByTestId("workflow-node-config-modal").count()) > 0) {
    await page.keyboard.press("Escape");
    await page
      .getByTestId("workflow-node-config-modal")
      .waitFor({ state: "detached", timeout: 10_000 });
  }
  await page.getByTestId("workflow-guided-next").waitFor({ timeout: 10_000 });
}

async function addAgentStepFromGuidedNext(page) {
  await page.getByTestId("workflow-guided-next-action-add_agent_step").click();
  await clickFirstExisting(page, [
    '[data-testid="workflow-add-compatible-model_call"]',
    '[data-testid="workflow-component-model_call"]',
  ]);
  await page.getByTestId("workflow-guided-next").waitFor({ timeout: 10_000 });
}

async function addOutputFromGuidedNext(page) {
  await page.getByTestId("workflow-guided-next-action-add_output").click();
  await clickFirstExisting(page, [
    '[data-testid="workflow-add-compatible-output.inline"]',
    '[data-testid="workflow-component-output.inline"]',
    '[data-testid="workflow-component-output"]',
  ]);
  await page.getByTestId("workflow-guided-next").waitFor({ timeout: 10_000 });
}

async function addBrowserToolToSelectedAgent(page) {
  await page.getByTestId("workflow-guided-next-action-add_tool").click();
  await page.getByTestId("workflow-node-library-search").fill("browser");
  await clickFirstExisting(page, [
    '[data-testid="workflow-add-compatible-plugin_tool.browser_use"]',
    '[data-testid="workflow-component-plugin_tool.browser_use"]',
    '[data-testid="workflow-component-plugin_tool.browser"]',
  ]);
  await page.getByTestId("workflow-selection-preview").waitFor({ timeout: 10_000 });
}

async function probePromptAgent(page) {
  await createBlankWorkflow(page, "Probe prompt agent");
  await addManualInput(page);
  const inputGuidance = await page.getByTestId("workflow-guided-next").innerText();
  await addAgentStepFromGuidedNext(page);
  const agentGuidance = await page.getByTestId("workflow-guided-next").innerText();
  await addOutputFromGuidedNext(page);
  const outputGuidance = await page.getByTestId("workflow-guided-next").innerText();
  await page.getByTestId("workflow-validate-button").click();
  await page.getByTestId("workflow-run-button").click();
  const body = await page.locator("body").innerText();
  return {
    inputGuidance,
    agentGuidance,
    outputGuidance,
    noRawInvokeError: !/Cannot read properties of undefined \(reading 'invoke'\)/.test(body),
    hasAgentStep: /Agent Step|Model/.test(body),
    hasInlineOutput: /Inline output|Output/.test(body),
  };
}

async function probeToolAgent(page) {
  await createBlankWorkflow(page, "Probe browser tool agent");
  await addManualInput(page);
  await addAgentStepFromGuidedNext(page);
  await addBrowserToolToSelectedAgent(page);
  const bodyAfterTool = await page.locator("body").innerText();
  await page.getByTestId("workflow-repair-action-bind_tool_capability").click();
  await page.getByTestId("workflow-connector-binding-modal").waitFor({ timeout: 10_000 });
  const connectorText = await page.getByTestId("workflow-connector-binding-modal").innerText();
  await page.keyboard.press("Escape");
  await page.getByTestId("workflow-connector-binding-modal").waitFor({ state: "detached", timeout: 10_000 });
  return {
    browserToolVisible: /Browser tool|Browser Use/i.test(bodyAfterTool),
    connectorModalVisible: /Connectors and plugins/i.test(connectorText),
    connectorFallbackIsUserFacing: !/Cannot read properties of undefined \(reading 'invoke'\)/.test(connectorText),
  };
}

async function probeRepoRecovery(page) {
  await createBlankWorkflow(page, "Probe repo recovery");
  await addManualInput(page);
  await page.getByTestId("workflow-show-compatible-nodes").click();
  await page.getByTestId("workflow-node-library-search").fill("repo");
  await page.waitForTimeout(250);
  const repoSearchText = await page.locator("body").innerText();
  await page.getByTestId("workflow-node-library-search").fill("github");
  await page.getByTestId("workflow-compatible-search-recovery").waitFor({ timeout: 10_000 });
  const recoveryText = await page.getByTestId("workflow-compatible-search-recovery").innerText();
  await page.getByTestId("workflow-compatible-search-show-all").click();
  await clickFirstExisting(page, [
    '[data-testid="workflow-component-github_context"]',
    '[data-testid="workflow-component-repository_context"]',
  ]);
  const configModalCount = await page.getByTestId("workflow-node-config-modal").count();
  const selectedText = await page.getByTestId("workflow-selection-preview").innerText();
  return {
    repoSearchText,
    recoveryText,
    repositoryAddedTopologyFirst:
      configModalCount === 0 && /GitHub Context|Repository Context/i.test(selectedText),
  };
}

async function probeModalKeyboard(page) {
  await page.getByTestId("workflow-model-bindings-button").click();
  await page.getByTestId("workflow-model-binding-modal").waitFor({ timeout: 10_000 });
  await page.keyboard.press("Escape");
  await page.getByTestId("workflow-model-binding-modal").waitFor({ state: "detached", timeout: 10_000 });
  const modelFocus = await page.evaluate(() => document.activeElement?.getAttribute("data-testid"));

  await page.getByTestId("workflow-connector-bindings-button").click();
  await page.getByTestId("workflow-connector-binding-modal").waitFor({ timeout: 10_000 });
  await page.keyboard.press("Escape");
  await page.getByTestId("workflow-connector-binding-modal").waitFor({ state: "detached", timeout: 10_000 });
  const connectorFocus = await page.evaluate(() => document.activeElement?.getAttribute("data-testid"));

  await page.getByTestId("workflow-configure-node").click();
  await page.getByTestId("workflow-node-config-modal").waitFor({ timeout: 10_000 });
  await page.keyboard.press("Escape");
  await page.getByTestId("workflow-node-config-modal").waitFor({ state: "detached", timeout: 10_000 });
  await page.getByTestId("workflow-show-compatible-nodes").click();
  return {
    modelFocus,
    connectorFocus,
    addNextStillClickable: (await page.getByTestId("workflow-node-library-search").count()) > 0,
  };
}

async function probeSearchAndAdvancedLabels(page) {
  await createBlankWorkflow(page, "Probe search labels");
  await page.getByTestId("workflow-empty-browse-primitives").click();
  await page.getByTestId("workflow-node-library-search").fill("browser");
  const defaultSearchText = await page.getByTestId("workflow-component-library").innerText();
  await page.getByTestId("workflow-node-palette-advanced").click();
  await page.getByTestId("workflow-node-library-search").fill("browser");
  const advancedSearchText = await page.getByTestId("workflow-component-library").innerText();
  await page.getByTestId("workflow-node-library-search").fill("repo");
  await page.getByTestId("workflow-node-palette-recommended").click();
  const repoSearchText = await page.getByTestId("workflow-component-library").innerText();
  return {
    defaultSearchText,
    advancedSearchText,
    repoSearchText,
  };
}

async function run() {
  const { chromium } = await playwright();
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 1600, height: 900 } });
  try {
    await openWorkflows(page);
    const promptAgent = await probePromptAgent(page);
    const toolAgent = await probeToolAgent(page);
    const repoRecovery = await probeRepoRecovery(page);
    const modalKeyboard = await probeModalKeyboard(page);
    const searchLabels = await probeSearchAndAdvancedLabels(page);
    const checks = {
      promptAgentGraph:
        /Add Agent Step/.test(promptAgent.inputGuidance) &&
        /Attach tool/.test(promptAgent.agentGuidance) &&
        /Validate/.test(promptAgent.outputGuidance) &&
        promptAgent.hasAgentStep &&
        promptAgent.hasInlineOutput,
      browserToolAttachment:
        toolAgent.browserToolVisible &&
        toolAgent.connectorModalVisible &&
        toolAgent.connectorFallbackIsUserFacing,
      repoCompatibleRecovery:
        /Repository tool|Coding tool pack|Repository Context/i.test(
          repoRecovery.repoSearchText,
        ) &&
        /No github primitives connect directly from Manual input/i.test(
          repoRecovery.recoveryText,
        ) && repoRecovery.repositoryAddedTopologyFirst,
      modalKeyboard:
        modalKeyboard.modelFocus === "workflow-model-bindings-button" &&
        modalKeyboard.connectorFocus === "workflow-connector-bindings-button" &&
        modalKeyboard.addNextStillClickable,
      validateRunNoRawRuntimeException: promptAgent.noRawInvokeError,
      searchRankingAndLabels:
        /Browser tool/i.test(searchLabels.defaultSearchText) &&
        /plugin_tool|runtime|contract|browser_use/i.test(searchLabels.advancedSearchText) &&
        /Repository Context|Coding tool pack|Repository tool/i.test(searchLabels.repoSearchText),
    };
    const passed = Object.values(checks).every(Boolean);
    const proof = {
      schemaVersion: "workflow.agent-building-ux-gui-probe.v1",
      appUrl,
      passed,
      checks,
      promptAgent,
      toolAgent,
      repoRecovery,
      modalKeyboard,
      searchLabels,
      generatedAt: new Date().toISOString(),
    };
    writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`);
    if (!passed) {
      throw new Error(JSON.stringify(checks, null, 2));
    }
  } finally {
    await browser.close();
  }
}

run().catch((error) => {
  writeFileSync(
    outputPath,
    `${JSON.stringify(
      {
        schemaVersion: "workflow.agent-building-ux-gui-probe.v1",
        appUrl,
        passed: false,
        error: error.message,
        generatedAt: new Date().toISOString(),
      },
      null,
      2,
    )}\n`,
  );
  console.error(error);
  process.exit(1);
});
