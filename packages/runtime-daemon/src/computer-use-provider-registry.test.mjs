import assert from "node:assert/strict";
import test from "node:test";

import {
  computerUseProviderForLane,
  computerUseProviderRegistryReport,
  computerUseThreadToolNameForProvider,
} from "./computer-use-provider-registry.mjs";

test("computer-use provider registry reports concrete fixture and planned container separately", () => {
  const report = computerUseProviderRegistryReport();
  assert.equal(report.object, "ioi.computer_use.provider_registry_report");
  const providerIds = report.providers.map((provider) => provider.provider_id);
  assert.ok(providerIds.includes("ioi.computer_use.sandboxed_hosted.local_fixture"));
  assert.ok(providerIds.includes("ioi.computer_use.sandboxed_hosted.local_container"));
  assert.ok(report.available_provider_ids.includes("ioi.computer_use.sandboxed_hosted.local_fixture"));
  assert.ok(report.unavailable_provider_ids.includes("ioi.computer_use.sandboxed_hosted.local_container"));

  const fixtureProvider = computerUseProviderForLane("sandboxed_hosted", { provider_id: "local_fixture" });
  assert.equal(fixtureProvider.provider_kind, "local_fixture");
  assert.equal(computerUseThreadToolNameForProvider(fixtureProvider), "ioi.computer_use.sandboxed_hosted");

  const containerProvider = computerUseProviderForLane("sandboxed_hosted", { provider_id: "local_container" });
  assert.equal(containerProvider.provider_kind, "local_container");
  assert.equal(containerProvider.status, "unavailable");
  assert.equal(computerUseThreadToolNameForProvider(containerProvider), null);
  assert.match(containerProvider.unavailable_reason, /no container runtime adapter is mounted/i);
});

test("computer-use provider selection ignores retired hint aliases", () => {
  const retiredProviderHint = computerUseProviderForLane("sandboxed_hosted", { providerHint: "local_container" });
  assert.equal(retiredProviderHint.provider_kind, "local_fixture");

  const retiredProviderKind = computerUseProviderForLane("sandboxed_hosted", { providerKind: "local_container" });
  assert.equal(retiredProviderKind.provider_kind, "local_fixture");

  const retiredSessionMode = computerUseProviderForLane("native_browser", { sessionMode: "unsupported_retired_mode" });
  assert.equal(retiredSessionMode.provider_kind, "task_scoped_browser_profile");
});
