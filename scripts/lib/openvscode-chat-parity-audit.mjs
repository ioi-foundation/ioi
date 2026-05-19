#!/usr/bin/env node
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { chromium } from "playwright";

const openVsCodeUrl = process.env.OPENVSCODE_URL ?? "http://127.0.0.1:24777/";
const outDir =
  process.env.PARITY_OUT_DIR ?? "/tmp/autopilot-chat-parity";
const interactive = truthy(process.env.OPENVSCODE_CHAT_PARITY_INTERACTIVE);
const headless = interactive
  ? false
  : process.env.OPENVSCODE_CHAT_PARITY_HEADLESS !== "0";
const runTraces = interactive
  ? truthy(process.env.OPENVSCODE_CHAT_PARITY_TRACE)
  : process.env.OPENVSCODE_CHAT_PARITY_TRACE !== "0";

function truthy(value) {
  return /^(1|true|yes|on)$/i.test(value ?? "");
}

async function waitForInteractiveClose() {
  console.log(
    "Interactive legacy OpenVSCode chat is visible. Click around in the browser, then press Enter here to capture final evidence and close.",
  );
  if (!process.stdin.isTTY) {
    console.log("stdin is not a TTY; use Ctrl+C to end this interactive session.");
    await new Promise(() => undefined);
    return;
  }
  process.stdin.setEncoding("utf8");
  process.stdin.resume();
  await new Promise((resolve) => {
    process.stdin.once("data", resolve);
  });
  process.stdin.pause();
}

const revealLegacyChatCss = `
.monaco-workbench .part.auxiliarybar,
.monaco-workbench .part.auxiliarybar.right,
.monaco-workbench .auxiliarybar,
.monaco-workbench .auxiliarybar.right,
.monaco-workbench .part.auxiliarybar .composite.title,
.monaco-workbench .part.auxiliarybar .pane-composite-part,
.monaco-workbench .part.auxiliarybar .pane-header,
.monaco-workbench .part.auxiliarybar [aria-label="Chat"],
.monaco-workbench .part.auxiliarybar [id*="chat"],
.monaco-workbench .part.auxiliarybar [class*="chat"] {
  display: flex !important;
  visibility: visible !important;
  pointer-events: auto !important;
}
.monaco-workbench .part.auxiliarybar,
.monaco-workbench .part.auxiliarybar.right,
.monaco-workbench .auxiliarybar,
.monaco-workbench .auxiliarybar.right {
  width: 320px !important;
  min-width: 280px !important;
  max-width: 520px !important;
  flex-basis: 320px !important;
}
`;

const titleActionLabels = [
  "New Chat (Ctrl+N)",
  "New Chat",
  "Configure Chat",
  "Views and More Actions...",
  "Maximize Secondary Side Bar Size",
  "Hide Secondary Side Bar (Ctrl+Alt+B)",
];

async function collectChatDom(page) {
  return page.evaluate((labels) => {
    function rectFor(element) {
      const rect = element.getBoundingClientRect();
      return {
        x: Math.round(rect.x),
        y: Math.round(rect.y),
        width: Math.round(rect.width),
        height: Math.round(rect.height),
      };
    }

    const auxiliary = document.querySelector(".part.auxiliarybar");
    const titleButtons = Array.from(
      document.querySelectorAll(".part.auxiliarybar .composite.title .action-label, .part.auxiliarybar .title-actions .action-label, .part.auxiliarybar .monaco-action-bar .action-label"),
    ).map((element, index) => ({
      index,
      ariaLabel: element.getAttribute("aria-label"),
      title: element.getAttribute("title"),
      className: element.className,
      text: element.textContent?.trim() ?? "",
      rect: rectFor(element),
    }));

    const labelPresence = labels.map((label) => {
      const element =
        document.querySelector(`.part.auxiliarybar [aria-label="${label}"]`) ??
        document.querySelector(`.part.auxiliarybar [title="${label}"]`);
      return {
        label,
        present: Boolean(element),
        className: element?.className ?? null,
        rect: element ? rectFor(element) : null,
      };
    });

    const composerButtons = Array.from(
      document.querySelectorAll(
        ".part.auxiliarybar [aria-label*='Add Context'], .part.auxiliarybar [aria-label*='Send'], .part.auxiliarybar .interactive-session-input-toolbar .action-label, .part.auxiliarybar .chat-input-toolbar .action-label, .part.auxiliarybar textarea, .part.auxiliarybar input",
      ),
    ).map((element, index) => ({
      index,
      ariaLabel: element.getAttribute("aria-label"),
      title: element.getAttribute("title"),
      placeholder: element.getAttribute("placeholder"),
      className: element.className,
      text: element.textContent?.trim() ?? "",
      rect: rectFor(element),
    }));

    return {
      url: location.href,
      title: document.title,
      auxiliaryPresent: Boolean(auxiliary),
      auxiliaryRect: auxiliary ? rectFor(auxiliary) : null,
      titleButtons,
      labelPresence,
      composerButtons,
      visibleText: document.body.innerText,
    };
  }, titleActionLabels);
}

async function traceAction(page, label) {
  const locator = page.locator(`.part.auxiliarybar [aria-label="${label}"]`).first();
  const count = await locator.count();
  if (count === 0) {
    return { label, clicked: false, reason: "not found" };
  }

  await locator.click({ timeout: 1500 });
  await page.waitForTimeout(300);
  const menu = await page.evaluate(() => {
    const quickInput = document.querySelector(".quick-input-widget");
    const contextMenu = document.querySelector(".context-view .monaco-menu");
    const candidate = quickInput ?? contextMenu;
    if (!candidate) {
      return null;
    }
    return {
      className: candidate.className,
      text: candidate.textContent?.trim() ?? "",
    };
  });
  await page.keyboard.press("Escape").catch(() => undefined);
  await page.waitForTimeout(100);
  return { label, clicked: true, menu };
}

await mkdir(outDir, { recursive: true });

const browser = await chromium.launch({ headless });
try {
  const page = await browser.newPage({ viewport: { width: 1280, height: 920 } });
  await page.goto(openVsCodeUrl, { waitUntil: "domcontentloaded", timeout: 30_000 });
  await page.waitForTimeout(1500);
  await page.addStyleTag({ content: revealLegacyChatCss });
  await page.waitForTimeout(500);

  const screenshotPath = path.join(outDir, "legacy-openvscode-chat-visible.png");
  await page.screenshot({ path: screenshotPath, fullPage: true });

  const before = await collectChatDom(page);
  const traces = [];
  if (runTraces) {
    for (const label of [
      "New Chat",
      "Configure Chat",
      "Views and More Actions...",
      "Maximize Secondary Side Bar Size",
    ]) {
      traces.push(await traceAction(page, label));
    }
  }
  if (interactive) {
    await waitForInteractiveClose();
  }
  const after = await collectChatDom(page);
  const finalScreenshotPath = interactive
    ? path.join(outDir, "legacy-openvscode-chat-interactive-final.png")
    : null;
  if (finalScreenshotPath) {
    await page.screenshot({ path: finalScreenshotPath, fullPage: true });
  }

  const report = {
    generatedAt: new Date().toISOString(),
    openVsCodeUrl,
    mode: interactive ? "interactive" : "audit",
    headless,
    runTraces,
    screenshotPath,
    finalScreenshotPath,
    revealLegacyChatCss,
    titleActionLabels,
    before,
    traces,
    after,
  };
  const reportPath = path.join(outDir, "legacy-openvscode-chat-dom.json");
  await writeFile(reportPath, `${JSON.stringify(report, null, 2)}\n`);
  console.log(`legacy chat screenshot: ${screenshotPath}`);
  if (finalScreenshotPath) {
    console.log(`legacy chat final screenshot: ${finalScreenshotPath}`);
  }
  console.log(`legacy chat dom report: ${reportPath}`);
} finally {
  await browser.close();
}
