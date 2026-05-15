import assert from "node:assert/strict";
import test from "node:test";

import {
  COMPUTER_USE_BROWSER_DISCOVERY_SCHEMA_VERSION,
  browserDiscoveryReportFromProcessRows,
  parseBrowserProcessRow,
} from "./browser-discovery.mjs";

test("browser discovery parses top-level browser processes without leaking profile paths", () => {
  const rows = [
    "100 1 google-chrome google-chrome --remote-debugging-port=9222 --user-data-dir=/home/alice/.config/google-chrome-debug --profile-directory=Default",
    "101 100 chrome chrome --type=renderer --user-data-dir=/home/alice/.config/google-chrome-debug",
    "200 1 chromium-browser chromium-browser --remote-debugging-port=9333",
    "300 1 bash bash -lc echo chrome",
  ];

  const report = browserDiscoveryReportFromProcessRows(rows, {
    discoveredAt: "2026-05-14T00:00:00.000Z",
    platform: "linux",
  });

  assert.equal(report.schema_version, COMPUTER_USE_BROWSER_DISCOVERY_SCHEMA_VERSION);
  assert.equal(report.object, "ioi.computer_use.browser_discovery_report");
  assert.equal(report.process_count, 4);
  assert.equal(report.browser_process_count, 2);
  assert.equal(report.cdp_endpoint_count, 2);
  assert.deepEqual(
    report.browser_processes.map((process) => process.browser_family),
    ["chrome", "chromium"],
  );
  assert.equal(report.browser_processes[0]?.remote_debugging_port, 9222);
  assert.equal(report.browser_processes[0]?.user_data_dir_present, true);
  assert.match(report.browser_processes[0]?.user_data_dir_hash ?? "", /^[a-f0-9]{64}$/);
  assert.equal(report.browser_processes[1]?.default_profile_cdp_refusal_risk, true);
  assert.equal(report.default_profile_remote_debugging_blockers.length, 1);
  assert.equal(report.safety.read_only, true);
  assert.equal(report.safety.mutated_browser_state, false);
  assert.equal(report.safety.copied_credentials, false);
  assert.equal(report.safety.raw_profile_paths_redacted, true);
  assert.equal(JSON.stringify(report).includes("/home/alice"), false);
});

test("browser discovery marks browser child processes for exclusion", () => {
  const child = parseBrowserProcessRow(
    "101 100 chrome chrome --type=renderer --remote-debugging-port=9222",
    { platform: "linux" },
  );
  assert.equal(child?.is_browser_child_process, true);
  assert.equal(child?.browser_family, "chrome");
});
