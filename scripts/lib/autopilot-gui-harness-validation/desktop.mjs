import { spawnSync } from "node:child_process";
import { unlinkSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

import { GUI_AUTOMATION_CLICK_POLICY } from "../autopilot-gui-harness-contract.mjs";

const repoRoot = resolve(new URL("../../..", import.meta.url).pathname);

export function commandExists(command) {
  const result = spawnSync("bash", ["-lc", `command -v ${command}`], {
    cwd: repoRoot,
    encoding: "utf8",
  });
  return result.status === 0;
}

export function runShell(command, options = {}) {
  return spawnSync("bash", ["-lc", command], {
    cwd: repoRoot,
    encoding: "utf8",
    ...options,
  });
}

export function assertGuiClickTargetSafe({ x, y, purpose }) {
  const { minWindowX, minWindowY } = GUI_AUTOMATION_CLICK_POLICY.safeZone;
  if (x < minWindowX || y < minWindowY) {
    throw new Error(
      `Refusing GUI click for ${purpose}: (${x}, ${y}) is outside the composer/content safe zone and may hit ${GUI_AUTOMATION_CLICK_POLICY.forbiddenZones.join(", ")}.`,
    );
  }
}

export function windowGeometry(windowId) {
  const result = runShell(`xdotool getwindowgeometry --shell ${windowId}`, {
    timeout: 4_000,
  });
  if (result.status !== 0) {
    return null;
  }
  const values = Object.fromEntries(
    result.stdout
      .split("\n")
      .map((line) => line.trim().split("="))
      .filter((parts) => parts.length === 2),
  );
  const x = Number(values.X);
  const y = Number(values.Y);
  const width = Number(values.WIDTH);
  const height = Number(values.HEIGHT);
  if (![x, y, width, height].every(Number.isFinite)) {
    return null;
  }
  return { x, y, width, height };
}

export function detectFocusedComposerClick(windowId) {
  const imagePath = join(
    process.env.TMPDIR || "/tmp",
    `autopilot-composer-detect-${process.pid}.png`,
  );
  const screenshot = runShell(
    `import -window ${windowId} ${JSON.stringify(imagePath)}`,
    {
      timeout: 20_000,
    },
  );
  if (screenshot.status !== 0) {
    return null;
  }

  try {
    const crop = { x: 300, y: 340, width: 980, height: 310 };
    const pixels = runShell(
      `convert ${JSON.stringify(imagePath)} -crop ${crop.width}x${crop.height}+${crop.x}+${crop.y} -depth 8 txt:-`,
      {
        timeout: 20_000,
        maxBuffer: 32 * 1024 * 1024,
      },
    );
    if (pixels.status !== 0) {
      return null;
    }

    let minX = Number.POSITIVE_INFINITY;
    let minY = Number.POSITIVE_INFINITY;
    let maxX = 0;
    let maxY = 0;
    let count = 0;
    const grayRows = new Map();
    for (const line of pixels.stdout.split("\n")) {
      const match = line.match(/^(\d+),(\d+): \((\d+),(\d+),(\d+)/);
      if (!match) continue;
      const localX = Number(match[1]);
      const localY = Number(match[2]);
      const red = Number(match[3]);
      const green = Number(match[4]);
      const blue = Number(match[5]);
      const isComposerBlue =
        red <= 80 && green >= 80 && green <= 190 && blue >= 170;
      const x = crop.x + localX;
      const y = crop.y + localY;
      if (x < GUI_AUTOMATION_CLICK_POLICY.safeZone.minWindowX) continue;
      if (isComposerBlue) {
        minX = Math.min(minX, x);
        minY = Math.min(minY, y);
        maxX = Math.max(maxX, x);
        maxY = Math.max(maxY, y);
        count += 1;
      }
      const isNeutralBorder =
        Math.abs(red - green) <= 3 &&
        Math.abs(green - blue) <= 3 &&
        red >= 185 &&
        red <= 235;
      if (isNeutralBorder && y >= 400) {
        const row = grayRows.get(y) ?? {
          count: 0,
          minX: Number.POSITIVE_INFINITY,
          maxX: 0,
        };
        row.count += 1;
        row.minX = Math.min(row.minX, x);
        row.maxX = Math.max(row.maxX, x);
        grayRows.set(y, row);
      }
    }

    if (
      Number.isFinite(minX) &&
      count >= 250 &&
      maxX - minX >= 120 &&
      maxY - minY >= 35
    ) {
      return {
        x: Math.round((minX + maxX) / 2),
        y: Math.min(Math.max(minY + 26, minY + 14), maxY - 12),
        bounds: { minX, minY, maxX, maxY, bluePixelCount: count },
      };
    }

    const wideRows = [...grayRows.entries()]
      .map(([y, row]) => ({ y, ...row, width: row.maxX - row.minX }))
      .filter((row) => row.count >= 250 && row.width >= 120)
      .sort((left, right) => right.width - left.width || left.y - right.y);
    const maxWidth = wideRows[0]?.width ?? 0;
    const topBorder = wideRows
      .filter((row) => row.width >= maxWidth - 16)
      .sort((left, right) => left.y - right.y)[0];
    if (!topBorder) {
      return null;
    }
    const fallbackX =
      topBorder.width >= 700
        ? Math.round((topBorder.minX + topBorder.maxX) / 2)
        : Math.round(crop.x + crop.width / 2);
    return {
      x: Math.max(GUI_AUTOMATION_CLICK_POLICY.safeZone.minWindowX, fallbackX),
      y: topBorder.y + 24,
      bounds: {
        minX: topBorder.minX,
        minY: topBorder.y,
        maxX: topBorder.maxX,
        maxY: topBorder.y,
        grayPixelCount: topBorder.count,
      },
    };
  } finally {
    try {
      unlinkSync(imagePath);
    } catch {
      // best-effort cleanup
    }
  }
}

export function windowIds(windowName) {
  const wmctrl = runShell(
    `wmctrl -l | grep -i ${JSON.stringify(windowName)} | awk '{print $1}'`,
    {
      timeout: 4_000,
    },
  );
  const ids = new Set(
    wmctrl.stdout
      .split(/\s+/)
      .map((item) => item.trim())
      .filter(Boolean),
  );
  const xdotool = runShell(
    `xdotool search --name ${JSON.stringify(windowName)}`,
    {
      timeout: 4_000,
    },
  );
  for (const line of xdotool.stdout.split(/\s+/)) {
    const trimmed = line.trim();
    if (trimmed) ids.add(trimmed);
  }
  return [...ids];
}

export function closeMatchingWindows(windowName) {
  for (const windowId of windowIds(windowName)) {
    runShell(`xdotool windowclose ${windowId}`, { timeout: 4_000 });
  }
}

async function sleep(ms) {
  await new Promise((resolveSleep) => setTimeout(resolveSleep, ms));
}

export async function waitForWindow(windowName, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const ids = windowIds(windowName);
    if (ids.length > 0) return ids.at(-1);
    await sleep(1_000);
  }
  return null;
}

export function typeQuery(windowId, query) {
  const inputPath = join(
    process.env.TMPDIR || "/tmp",
    `autopilot-gui-query-${process.pid}.txt`,
  );
  writeFileSync(inputPath, query, "utf8");
  runShell(`xdotool windowactivate ${windowId}`, { timeout: 4_000 });
  runShell("sleep 0.3", { timeout: 2_000 });
  runShell(`xdotool key --clearmodifiers Escape`, { timeout: 5_000 });
  runShell("sleep 0.3", { timeout: 2_000 });
  const composerClick = detectFocusedComposerClick(windowId) ?? {
    x: 420,
    y: 575,
  };
  assertGuiClickTargetSafe({
    x: composerClick.x,
    y: composerClick.y,
    purpose: "chat composer focus",
  });
  const origin = windowGeometry(windowId);
  const clickPoints = [
    {
      x: composerClick.x,
      y: Math.max(
        composerClick.y - 22,
        GUI_AUTOMATION_CLICK_POLICY.safeZone.minWindowY,
      ),
    },
    { x: composerClick.x, y: composerClick.y },
  ];
  for (const point of clickPoints) {
    assertGuiClickTargetSafe({
      x: point.x,
      y: point.y,
      purpose: "chat composer focus",
    });
    const clickCommand = origin
      ? `xdotool mousemove ${origin.x + point.x} ${origin.y + point.y} click 1`
      : `xdotool mousemove --window ${windowId} ${point.x} ${point.y} click 1`;
    runShell(clickCommand, { timeout: 5_000 });
    runShell("sleep 0.15", { timeout: 2_000 });
  }
  runShell("sleep 0.75", { timeout: 2_000 });
  runShell(`xdotool key --clearmodifiers ctrl+a BackSpace`, { timeout: 5_000 });
  runShell("sleep 0.35", { timeout: 2_000 });
  const typed = runShell(
    `xdotool type --clearmodifiers --delay 18 --file ${JSON.stringify(inputPath)}`,
    {
      timeout: 120_000,
    },
  );
  if (typed.status !== 0) {
    let pasted = false;
    if (commandExists("xclip")) {
      pasted =
        runShell(`xclip -selection clipboard < ${JSON.stringify(inputPath)}`, {
          timeout: 5_000,
        }).status === 0;
    } else if (commandExists("xsel")) {
      pasted =
        runShell(`xsel --clipboard --input < ${JSON.stringify(inputPath)}`, {
          timeout: 5_000,
        }).status === 0;
    }
    if (pasted) {
      runShell(`xdotool key --clearmodifiers ctrl+v`, { timeout: 5_000 });
    } else {
      throw new Error(
        `Failed to type retained GUI query into the composer: ${typed.stderr || typed.stdout}`,
      );
    }
  }
  runShell("sleep 0.3", { timeout: 2_000 });
  runShell(`xdotool key --clearmodifiers Return`, { timeout: 5_000 });
  if (composerClick.bounds?.maxX && composerClick.bounds?.maxY) {
    const sendPoint = {
      x: Math.max(
        GUI_AUTOMATION_CLICK_POLICY.safeZone.minWindowX,
        composerClick.bounds.maxX - 24,
      ),
      y: composerClick.bounds.maxY + 24,
    };
    const sendClickCommand = origin
      ? `xdotool mousemove ${origin.x + sendPoint.x} ${origin.y + sendPoint.y} click 1`
      : `xdotool mousemove --window ${windowId} ${sendPoint.x} ${sendPoint.y} click 1`;
    assertGuiClickTargetSafe({
      x: sendPoint.x,
      y: sendPoint.y,
      purpose: "chat composer send",
    });
    runShell("sleep 0.2", { timeout: 2_000 });
    runShell(sendClickCommand, { timeout: 5_000 });
  }
  try {
    unlinkSync(inputPath);
  } catch {
    // best-effort cleanup
  }
}

export function captureScreenshot(windowId, outputRoot, scenario) {
  const path = join(outputRoot, `${scenario}.png`);
  const result = runShell(
    `import -window ${windowId} ${JSON.stringify(path)}`,
    {
      timeout: 20_000,
    },
  );
  return {
    path,
    ok: result.status === 0,
    stderr: result.stderr.trim(),
  };
}
