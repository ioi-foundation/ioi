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

async function restoreLegacyOpenVsCodeChrome(page) {
  return page.evaluate(() => {
    const removedRules = [];
    for (const sheet of Array.from(document.styleSheets)) {
      let rules;
      try {
        rules = sheet.cssRules;
      } catch {
        continue;
      }
      if (!rules) {
        continue;
      }

      for (let index = rules.length - 1; index >= 0; index -= 1) {
        const rule = rules[index];
        const text = rule.cssText ?? "";
        const targetsAutopilotSuppression =
          text.includes(".monaco-workbench .part.auxiliarybar") ||
          text.includes(".monaco-workbench .auxiliarybar") ||
          text.includes(".monaco-workbench .part.titlebar") ||
          text.includes(".monaco-workbench .part.titlebar .command-center");
        const suppressesNativeChrome =
          text.includes("display: none !important") ||
          text.includes("visibility: hidden !important") ||
          text.includes("width: 0px !important") ||
          text.includes("flex-basis: 0px !important") ||
          text.includes("grid-template-columns");
        if (!targetsAutopilotSuppression || !suppressesNativeChrome) {
          continue;
        }
        removedRules.push(text.slice(0, 500));
        sheet.deleteRule(index);
      }
    }
    return removedRules;
  });
}

async function legacyChatVisible(page) {
  return page.evaluate(() => {
    const auxiliary = document.querySelector(".part.auxiliarybar");
    const welcome = document.querySelector(".part.auxiliarybar .chat-welcome-view");
    if (!auxiliary || !welcome) {
      return false;
    }
    const auxiliaryRect = auxiliary.getBoundingClientRect();
    const welcomeRect = welcome.getBoundingClientRect();
    const auxiliaryStyle = getComputedStyle(auxiliary);
    const welcomeStyle = getComputedStyle(welcome);
    return (
      auxiliaryRect.width > 120 &&
      auxiliaryRect.height > 240 &&
      welcomeRect.width > 120 &&
      welcomeRect.height > 80 &&
      welcomeRect.y < window.innerHeight - 160 &&
      auxiliaryStyle.visibility !== "hidden" &&
      auxiliaryStyle.display !== "none" &&
      welcomeStyle.visibility !== "hidden" &&
      welcomeStyle.display !== "none"
    );
  });
}

async function activateLegacyChat(page) {
  if (await legacyChatVisible(page)) {
    return { activated: false, reason: "already-visible" };
  }
  await page.keyboard.press("Control+Alt+I").catch(() => undefined);
  await page.waitForTimeout(500);
  if (await legacyChatVisible(page)) {
    return { activated: true, method: "keyboard", chord: "Control+Alt+I" };
  }

  const chatTitle = page.locator('.part.auxiliarybar [aria-label="Chat (Ctrl+Alt+I)"]').first();
  if ((await chatTitle.count()) > 0) {
    await chatTitle.click({ timeout: 1500 }).catch(() => undefined);
    await page.waitForTimeout(500);
  }
  if (await legacyChatVisible(page)) {
    return { activated: true, method: "title-click" };
  }
  return { activated: false, reason: "chat-view-not-visible" };
}

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
  const removedSuppressionRules = await restoreLegacyOpenVsCodeChrome(page);
  await page.waitForTimeout(500);
  const activation = await activateLegacyChat(page);
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
    restoreStrategy: "cssom-remove-autopilot-openvscode-suppression-rules",
    removedSuppressionRules,
    activation,
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
