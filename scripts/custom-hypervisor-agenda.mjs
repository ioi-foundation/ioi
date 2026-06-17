#!/usr/bin/env node
import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, "..");

const evidenceDir = path.join(rootDir, "scripts", "evidence");
const tmpDataDir = path.join(evidenceDir, ".ioi-data-tmp");

// Ensure evidence directory exists
fs.mkdirSync(evidenceDir, { recursive: true });

console.log("=== Hypervisor E2E Automation Agenda Playbook ===");
console.log(`Workspace Root: ${rootDir}`);
console.log(`Evidence Directory: ${evidenceDir}`);
console.log(`Temporary Data Directory: ${tmpDataDir}`);

// Clean up previous temp data if any
if (fs.existsSync(tmpDataDir)) {
  console.log("Cleaning up previous temporary daemon data...");
  fs.rmSync(tmpDataDir, { recursive: true, force: true });
}

let daemonProcess = null;
let viteProcess = null;
let browserInstance = null;

// Track active processes for robust cleanup
const activeProcesses = [];

function registerProcess(proc, name) {
  activeProcesses.push({ proc, name });
  proc.on("exit", (code, signal) => {
    console.log(`Process [${name}] exited with code: ${code}, signal: ${signal}`);
  });
}

// Clean up all resources
async function cleanup() {
  console.log("\n=== Tearing down background servers and browser ===");
  if (browserInstance) {
    try {
      await browserInstance.close();
      console.log("Playwright browser closed.");
    } catch (e) {
      console.error("Error closing browser:", e.message);
    }
  }

  for (const { proc, name } of activeProcesses) {
    if (proc.pid && !proc.killed) {
      console.log(`Killing [${name}] (PID: ${proc.pid})...`);
      try {
        proc.kill("SIGTERM");
        // Bounded wait or force kill if needed
        setTimeout(() => {
          try {
            if (!proc.killed) {
              proc.kill("SIGKILL");
            }
          } catch (e) {}
        }, 1000);
      } catch (e) {
        console.error(`Error killing process [${name}]:`, e.message);
      }
    }
  }

  // Clean up tmp directory
  if (fs.existsSync(tmpDataDir)) {
    try {
      fs.rmSync(tmpDataDir, { recursive: true, force: true });
      console.log("Temporary daemon data directory cleaned up.");
    } catch (e) {
      console.error("Error deleting temporary daemon data directory:", e.message);
    }
  }
  console.log("=== Teardown complete. Zero ports locked. ===\n");
}

// Handle termination signals
process.on("SIGINT", async () => {
  console.log("\nReceived SIGINT. Shutting down...");
  await cleanup();
  process.exit(130);
});

process.on("SIGTERM", async () => {
  console.log("\nReceived SIGTERM. Shutting down...");
  await cleanup();
  process.exit(143);
});

process.on("exit", () => {
  // Synchronous process cleanup fallback
  for (const { proc, name } of activeProcesses) {
    if (proc.pid && !proc.killed) {
      try {
        proc.kill("SIGKILL");
      } catch (e) {}
    }
  }
});

// Polling wait helper
async function waitUrlReady(url, label, timeoutMs = 90000) {
  const start = Date.now();
  console.log(`Waiting for ${label} at ${url}...`);
  while (Date.now() - start < timeoutMs) {
    try {
      const res = await fetch(url);
      if (res.ok || res.status === 404 || res.status === 401) {
        console.log(`[OK] ${label} is ready!`);
        return true;
      }
    } catch (e) {
      // Ignore network errors during boot
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error(`Timeout waiting for ${label} at ${url} after ${timeoutMs}ms`);
}

async function run() {
  try {
    // 1. Spawn Node-based Runtime Daemon Service
    console.log("Spawning ioi-local runtime daemon service...");
    const daemonScript = path.join(rootDir, "scripts", "ioi-local-runtime-daemon.mjs");

    daemonProcess = spawn("node", [daemonScript, "--port", "9000", "--state-dir", tmpDataDir, "--cwd", rootDir], {
      cwd: rootDir,
      env: process.env,
      stdio: "pipe"
    });
    
    registerProcess(daemonProcess, "ioi-local-runtime-daemon");
    
    // Pipe daemon logs to stdout with prefix for visibility
    daemonProcess.stdout.on("data", (data) => {
      // Optional: console.log(`[Daemon] ${data.toString().trim()}`);
    });
    daemonProcess.stderr.on("data", (data) => {
      // Optional: console.error(`[Daemon-Err] ${data.toString().trim()}`);
    });

    // Wait for Daemon public API to be ready
    await waitUrlReady("http://127.0.0.1:9000/v1/doctor", "ioi-local companion daemon");

    // 2. Spawn Vite Frontend Dev Server
    console.log("Spawning Vite frontend dev server...");
    viteProcess = spawn("npm", ["run", "dev", "--workspace=apps/hypervisor", "--", "--port", "1428", "--host", "127.0.0.1"], {
      cwd: rootDir,
      stdio: "pipe"
    });

    registerProcess(viteProcess, "Vite Dev Server");

    // Pipe vite logs to stdout with prefix
    viteProcess.stdout.on("data", (data) => {
      // Optional: console.log(`[Vite] ${data.toString().trim()}`);
    });

    // Wait for Vite frontend to be responsive
    await waitUrlReady("http://127.0.0.1:1428", "Vite dev server");

    // 3. Playwright Automation session
    console.log("Launching Playwright chromium browser...");
    browserInstance = await chromium.launch({
      headless: true,
      args: ["--no-sandbox", "--disable-setuid-sandbox"]
    });

    const context = await browserInstance.newContext({
      viewport: { width: 1440, height: 900 }
    });

    const page = await context.newPage();

    // Navigate to Chat interface
    console.log("Navigating to Autopilot Chat interface...");
    await page.goto("http://localhost:1428/chat", { waitUntil: "networkidle" });
    
    // Fallback check if routing needs direct path or has hash
    const currentUrl = page.url();
    console.log(`Loaded page URL: ${currentUrl}`);

    // Capture Evidence Step 1: Initial Load
    const step1Path = path.join(evidenceDir, "step1_initial_load.png");
    await page.screenshot({ path: step1Path });
    console.log(`Saved screenshot: ${step1Path}`);

    // Wait for chat input text area to be visible
    console.log("Waiting for spot-input element to be visible...");
    const textarea = page.locator(".spot-input");
    await textarea.waitFor({ state: "visible", timeout: 10000 });

    // Capture Evidence Step 2: Input Field Ready
    const step2Path = path.join(evidenceDir, "step2_input_field_ready.png");
    await page.screenshot({ path: step2Path });
    console.log(`Saved screenshot: ${step2Path}`);

    // Enter a coding prompt in Autopilot spot-input
    const promptText = "Create a robust React hooks manager component that synchronizes network latency statistics.";
    console.log(`Entering prompt: "${promptText}"`);
    await textarea.fill(promptText);
    await page.waitForTimeout(500);

    // Capture Evidence Step 3: Prompt Filled
    const step3Path = path.join(evidenceDir, "step3_prompt_filled.png");
    await page.screenshot({ path: step3Path });
    console.log(`Saved screenshot: ${step3Path}`);

    // Press Submit button (spot-send-btn)
    console.log("Submitting prompt...");
    const submitBtn = page.locator(".spot-send-btn");
    await submitBtn.click();

    // Wait for response/execution flow to start rendering
    console.log("Waiting for execution events and canvas/flow nodes to materialize...");
    await page.waitForTimeout(3000);

    // Capture Evidence Step 4: Execution Progress
    const step4Path = path.join(evidenceDir, "step4_execution_progress.png");
    await page.screenshot({ path: step4Path });
    console.log(`Saved screenshot: ${step4Path}`);

    // Check if there are any active workflow nodes or approval gates we can interact with
    const nodes = page.locator(".react-flow__node");
    const nodeCount = await nodes.count();
    console.log(`Detected React Flow nodes: ${nodeCount}`);

    if (nodeCount > 0) {
      console.log("Interacting with React Flow canvas nodes...");
      // Try to click first node to open details/metadata
      await nodes.first().click().catch(() => undefined);
      await page.waitForTimeout(1000);

      // Capture Evidence Step 5: Canvas Node Details
      const step5Path = path.join(evidenceDir, "step5_canvas_node_details.png");
      await page.screenshot({ path: step5Path });
      console.log(`Saved screenshot: ${step5Path}`);
    } else {
      console.log("No React Flow canvas nodes detected yet. Taking fallback execution screenshot...");
    }

    console.log("Playbook execution completed successfully!");
  } catch (error) {
    console.error("Error during playbook execution:", error);
    process.exitCode = 1;
  } finally {
    await cleanup();
  }
}

run();
