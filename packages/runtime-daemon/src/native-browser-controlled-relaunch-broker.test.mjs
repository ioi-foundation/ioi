import assert from "node:assert/strict";
import test from "node:test";

import { launchControlledNativeBrowser } from "./native-browser-controlled-relaunch-broker.mjs";

test("controlled relaunch broker ignores retired camelCase launch aliases", async () => {
  const result = await launchControlledNativeBrowser({
    runId: "run_retired_controlled_relaunch_aliases",
    input: {
      controlledRelaunchApprovalRef: "approval_retired",
      hostBrowserLaunchApprovalRef: "host_approval_retired",
      browserLaunchApprovalRef: "browser_approval_retired",
      controlledRelaunchBrokerRef: "broker_retired_field",
      computerUseControlledRelaunchBroker: { brokerRef: "broker_retired_nested" },
      controlledRelaunchBroker: { brokerRef: "broker_retired_controlled" },
      controlledRelaunchExecutablePath: "/tmp/retired-browser",
      browserExecutablePath: "/tmp/retired-browser",
      controlledRelaunchExecutableArgs: ["--retired-executable-arg"],
      browserExecutableArgs: ["--retired-browser-arg"],
      controlledRelaunchExtraArgs: ["--retired-extra-arg"],
      browserLaunchArgs: ["--retired-launch-arg"],
      controlledRelaunchCdpPort: 9999,
      browserLaunchCdpPort: 9998,
      controlledRelaunchStartUrl: "https://retired.example.test",
      targetUrl: "https://retired-target.example.test",
      controlledRelaunchHeadless: true,
      browserLaunchHeadless: true,
    },
  });

  assert.equal(result.status, "unavailable");
  assert.equal(result.launchReceipt.status, "unavailable");
  assert.equal(result.launchReceipt.error_class, "ControlledRelaunchApprovalRequired");
  assert.equal(result.launchReceipt.approval_ref, null);
  assert.equal(result.launchReceipt.broker_ref.includes("broker_retired"), false);
  assert.equal(result.launchReceipt.start_url, null);
  assert.deepEqual(
    result.launchReceipt.evidence_refs.filter((ref) => ref.includes("retired")),
    [],
  );
});
