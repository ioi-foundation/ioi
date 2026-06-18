export const HYPERVISOR_CORE_TAXONOMY_SCHEMA_VERSION =
  "ioi.runtime.hypervisor_core_taxonomy.v1";

export function buildHypervisorCoreTaxonomy({ nowIso } = {}) {
  const createdAt =
    typeof nowIso === "function" ? nowIso() : new Date().toISOString();

  return {
    schema_version: HYPERVISOR_CORE_TAXONOMY_SCHEMA_VERSION,
    taxonomy_ref: "hypervisor-core-taxonomy:canonical",
    generated_at: createdAt,
    core: {
      id: "hypervisor-core",
      execution_owner: "hypervisor-daemon",
      runtimeTruthSource: "daemon-runtime",
      doctrine:
        "Hypervisor Core is the shared substrate; clients and surfaces operate it, but the Hypervisor Daemon owns execution semantics.",
    },
    first_class_clients: [
      {
        id: "hypervisor-app",
        kind: "app",
        description: "Native desktop client over Hypervisor Core.",
      },
      {
        id: "hypervisor-web",
        kind: "web",
        description: "Browser/team/remote client over Hypervisor Core.",
      },
      {
        id: "hypervisor-cli-headless",
        kind: "cli_headless",
        description:
          "Terminal, scripting, CI, node-ops, and headless operator client over Hypervisor Core.",
      },
    ],
    optional_presentations: [
      {
        id: "hypervisor-tui",
        kind: "tui_presentation",
        parent_client: "hypervisor-cli-headless",
        description:
          "Optional terminal presentation over CLI/headless contracts; not a separate runtime lane.",
      },
    ],
    application_surfaces: [
      "home",
      "sessions",
      "projects",
      "workbench",
      "automations",
      "agents",
      "models",
      "privacy_ctee",
      "authority",
      "receipts",
      "insights",
      "foundry",
      "providers",
      "environments",
      "settings",
    ].map((id) => ({
      id,
      surface_ref: `hypervisor-surface:${id}`,
      truth_owner: "hypervisor-daemon",
      boundary:
        "Application surfaces are governed projections and controls over Hypervisor Core, not runtime owners.",
    })),
    retired_surface_aliases: [
      {
        alias: "fleet",
        replacement: "sessions/providers/environments",
        reason:
          "Fleet posture is folded into Hypervisor session, provider, and environment management instead of a separate app surface.",
      },
    ],
    adapter_target_families: [
      {
        id: "code_editor",
        examples: ["embedded-workbench", "vscode", "cursor", "windsurf", "jetbrains", "browser-ide"],
        allowed_surface_refs: ["hypervisor-surface:workbench"],
        runtimeTruthSource: "daemon-runtime",
      },
      {
        id: "terminal",
        examples: ["shell", "tmux", "remote-shell"],
        allowed_surface_refs: ["hypervisor-surface:sessions", "hypervisor-surface:environments"],
        runtimeTruthSource: "daemon-runtime",
      },
      {
        id: "browser",
        examples: ["browser-automation", "browser-sandbox"],
        allowed_surface_refs: ["hypervisor-surface:sessions", "hypervisor-surface:automations"],
        runtimeTruthSource: "daemon-runtime",
      },
      {
        id: "vm_or_container",
        examples: ["local-container", "cloud-vm", "microvm"],
        allowed_surface_refs: ["hypervisor-surface:sessions", "hypervisor-surface:providers"],
        runtimeTruthSource: "daemon-runtime",
      },
      {
        id: "provider",
        examples: ["aws", "gcp", "azure", "akash", "filecoin", "runpod", "local-machine"],
        allowed_surface_refs: ["hypervisor-surface:providers", "hypervisor-surface:environments"],
        runtimeTruthSource: "daemon-runtime",
      },
      {
        id: "hypervisoros_node",
        examples: ["persistent-node", "bare-metal-node"],
        allowed_surface_refs: ["hypervisor-surface:sessions", "hypervisor-surface:environments"],
        runtimeTruthSource: "daemon-runtime",
      },
    ],
    agent_harness_adapters: [
      "codex_style",
      "claude_style",
      "deepseek_style",
      "aider_style",
      "openhands_style",
      "generic_cli",
    ].map((id) => ({
      id,
      adapter_ref: `agent-harness-adapter:${id}`,
      authority: "proposal_source_only",
      runtimeTruthSource: "daemon-runtime",
      boundary:
        "External harnesses may propose work through daemon gates; they are not Hypervisor clients and do not own runtime truth.",
    })),
    truth_boundaries: [
      {
        owner: "wallet.network",
        owns: ["authority", "secrets", "approvals", "leases", "declassification", "spend", "revocation"],
      },
      {
        owner: "Agentgres",
        owns: ["admitted operational truth", "state roots", "artifact refs", "archive refs", "receipt linkage", "restore validity"],
      },
      {
        owner: "storage backends",
        owns: ["payload bytes"],
      },
      {
        owner: "route engines",
        owns: ["candidate proposals", "venue metadata", "route evidence"],
      },
      {
        owner: "IOI L1",
        owns: ["triggered public/economic/cross-domain commitments"],
      },
    ],
    anti_patterns: [
      "Treating Hypervisor App, Hypervisor Web, CLI/headless, Workbench, Foundry, or editor hosts as runtime truth.",
      "Treating external coding harnesses as Hypervisor clients instead of AgentHarnessAdapters.",
      "Reintroducing Fleet as a separate product surface instead of session/provider/environment management.",
      "Putting terminal, VM, provider, or HypervisorOS node launch posture back into the Workbench code-editor adapter surface.",
      "Letting storage backends, route engines, Wallet UI, or L1 bypass daemon admission and Agentgres truth.",
    ],
  };
}
