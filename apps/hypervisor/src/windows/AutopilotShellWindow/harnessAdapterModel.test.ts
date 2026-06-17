import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  DEFAULT_HARNESS_PROFILE_OPTION,
  HYPERVISOR_AGENT_HARNESS_ADAPTER_PROFILES,
  HYPERVISOR_HARNESS_SELECTION_OPTIONS,
  buildHarnessAdapterReceiptDraft,
  buildHarnessCompatibilityVerdict,
  getHarnessSelectionRef,
  isAgentHarnessAdapterOption,
} from "./harnessAdapterModel.ts";

test("default harness profile is the IOI reference scaffold, not an external adapter", () => {
  assert.equal(DEFAULT_HARNESS_PROFILE_OPTION.selection_kind, "harness_profile");
  assert.equal(
    DEFAULT_HARNESS_PROFILE_OPTION.role,
    "reference_scaffold_fallback",
  );
  assert.equal(
    getHarnessSelectionRef(DEFAULT_HARNESS_PROFILE_OPTION),
    "harness-profile:default_harness_profile",
  );
  assert.equal(
    HYPERVISOR_HARNESS_SELECTION_OPTIONS[0],
    DEFAULT_HARNESS_PROFILE_OPTION,
  );
  assert.equal(
    isAgentHarnessAdapterOption(DEFAULT_HARNESS_PROFILE_OPTION),
    false,
  );
});

test("external coding tools are proposal-source AgentHarnessAdapters", () => {
  const adapterIds = HYPERVISOR_AGENT_HARNESS_ADAPTER_PROFILES.map(
    (profile) => profile.adapter_id,
  );

  assert.deepEqual(adapterIds, [
    "codex_cli",
    "codex_desktop_linux",
    "claude_code_cli",
    "deepseek_tui",
    "aider_cli",
    "openhands",
    "generic_cli",
  ]);

  for (const profile of HYPERVISOR_AGENT_HARNESS_ADAPTER_PROFILES) {
    assert.equal(profile.selection_kind, "agent_harness_adapter");
    assert.equal(profile.truth_boundary, "proposal_source_only");
    assert.equal(profile.runtimeTruthSource, "daemon-runtime");
    assert.ok(profile.required_authority_scopes.length > 0);
    assert.match(profile.receipt_policy_ref, /^receipt-policy:harness-adapter\//);
  }
});

test("compatibility verdicts expose provider trust and local-route gaps", () => {
  const claude = HYPERVISOR_AGENT_HARNESS_ADAPTER_PROFILES.find(
    (profile) => profile.adapter_id === "claude_code_cli",
  );
  const deepseek = HYPERVISOR_AGENT_HARNESS_ADAPTER_PROFILES.find(
    (profile) => profile.adapter_id === "deepseek_tui",
  );
  const codex = HYPERVISOR_AGENT_HARNESS_ADAPTER_PROFILES.find(
    (profile) => profile.adapter_id === "codex_cli",
  );
  assert.ok(claude);
  assert.ok(deepseek);
  assert.ok(codex);

  assert.deepEqual(
    buildHarnessCompatibilityVerdict(claude, true),
    {
      selection_ref: "agent-harness-adapter:claude_code_cli",
      state: "provider_trust",
      summary:
        "Adapter-native model execution is a provider-trust lane and must be disclosed before launch.",
      requiresDaemonGate: true,
      privacyWarning:
        "Do not route protected workspace state into this adapter without a redacted projection or explicit unsafe-mount approval.",
    },
  );
  assert.equal(
    buildHarnessCompatibilityVerdict(deepseek, false).state,
    "local_route_unavailable",
  );
  assert.equal(
    buildHarnessCompatibilityVerdict(codex, true).state,
    "adapter_native_only",
  );
});

test("receipt drafts bind adapter execution through daemon truth and workspace posture", () => {
  const deepseek = HYPERVISOR_AGENT_HARNESS_ADAPTER_PROFILES.find(
    (profile) => profile.adapter_id === "deepseek_tui",
  );
  assert.ok(deepseek);

  const adapterReceipt = buildHarnessAdapterReceiptDraft(deepseek);
  assert.equal(
    adapterReceipt.schema_version,
    "ioi.hypervisor.harness_adapter_receipt.v1",
  );
  assert.equal(
    adapterReceipt.selection_ref,
    "agent-harness-adapter:deepseek_tui",
  );
  assert.equal(adapterReceipt.execution_lane, "docker_container");
  assert.equal(adapterReceipt.runtimeTruthSource, "daemon-runtime");
  assert.deepEqual(adapterReceipt.agentgres_operation_refs, []);

  const defaultReceipt = buildHarnessAdapterReceiptDraft(
    DEFAULT_HARNESS_PROFILE_OPTION,
  );
  assert.equal(
    defaultReceipt.selection_ref,
    "harness-profile:default_harness_profile",
  );
  assert.equal(defaultReceipt.workspace_mount_policy, "ctee_private_workspace");
});

test("source text rejects legacy external-harness-as-runtime shortcuts", () => {
  const source = readFileSync(
    "apps/hypervisor/src/windows/AutopilotShellWindow/harnessAdapterModel.ts",
    "utf8",
  );

  assert.match(source, /truth_boundary: "proposal_source_only"/);
  assert.match(source, /runtimeTruthSource: "daemon-runtime"/);
  assert.doesNotMatch(source, /Codex = Default Harness/);
  assert.doesNotMatch(source, /Claude Code = Default Harness/);
  assert.doesNotMatch(source, /external harness.*runtime truth/i);
});
