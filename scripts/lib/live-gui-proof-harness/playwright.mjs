import { existsSync } from "node:fs";
import { join } from "node:path";

export async function waitForCdp(port, waitForPredicate, timeoutMs = 45_000) {
  return waitForPredicate(async () => {
    try {
      const response = await fetch(`http://127.0.0.1:${port}/json/version`);
      return response.ok ? response.json() : null;
    } catch {
      return null;
    }
  }, timeoutMs, 500);
}

export async function findFrameWithTestId(page, testId, waitForPredicate, timeoutMs = 45_000) {
  const selector = `[data-testid="${testId}"]`;
  const frame = await waitForPredicate(async () => {
    for (const candidate of page.frames()) {
      try {
        if ((await candidate.locator(selector).count()) > 0) return candidate;
      } catch {
        // VS Code swaps webview frames during startup.
      }
    }
    return null;
  }, timeoutMs, 300);
  if (!frame) throw new Error(`Could not find frame with ${selector}`);
  return frame;
}

export async function screenshot(page, outputDir, file, screenshots) {
  const path = join(outputDir, file);
  await page.screenshot({ path, fullPage: true });
  screenshots.push({ file, path, exists: existsSync(path) });
  return path;
}

export async function clickWithDomFallback(frameOrPage, selector, { timeout = 1500, index = 0 } = {}) {
  const locator = frameOrPage.locator(selector).nth(index);
  await clickLocatorWithDomFallback(locator, { timeout });
}

export async function clickLocatorWithDomFallback(locator, { timeout = 1500 } = {}) {
  await locator.click({ timeout }).catch(async () => {
    await locator.evaluate((node) => node.click());
  });
}
