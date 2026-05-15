import type { LocalEngineEnvironmentBinding } from "../../types";

export type SettingsAuthorityPostureTone = "ready" | "warning" | "idle";

export interface SettingsAuthorityPostureSummary {
  totalBindings: number;
  secretBindings: number;
  vaultBackedBindings: number;
  rawSecretBindings: number;
  publicBindings: number;
  tone: SettingsAuthorityPostureTone;
  label: string;
  detail: string;
  checklist: string[];
}

function isVaultRef(value: string): boolean {
  const normalized = value.trim().toLowerCase();
  return (
    normalized.startsWith("vault://") ||
    normalized.startsWith("wallet://") ||
    normalized.startsWith("ioi-vault://") ||
    normalized.startsWith("secret://")
  );
}

export function summarizeSettingsAuthorityPosture(
  bindings: readonly LocalEngineEnvironmentBinding[],
): SettingsAuthorityPostureSummary {
  const totalBindings = bindings.length;
  const secretBindings = bindings.filter((binding) => binding.secret).length;
  const vaultBackedBindings = bindings.filter((binding) =>
    isVaultRef(binding.value),
  ).length;
  const rawSecretBindings = bindings.filter(
    (binding) => binding.secret && !isVaultRef(binding.value),
  ).length;
  const publicBindings = Math.max(totalBindings - secretBindings, 0);
  const tone: SettingsAuthorityPostureTone =
    totalBindings === 0 ? "idle" : rawSecretBindings > 0 ? "warning" : "ready";
  const label =
    tone === "idle"
      ? "No bindings"
      : tone === "warning"
        ? "Vault migration needed"
        : "Vault-aligned";
  const detail =
    tone === "warning"
      ? `${rawSecretBindings} secret binding${rawSecretBindings === 1 ? "" : "s"} still use raw values.`
      : tone === "ready"
        ? `${vaultBackedBindings} vault-backed binding${vaultBackedBindings === 1 ? "" : "s"} are ready for authority projection.`
        : "Environment bindings are empty; live capabilities still require credential readiness metadata.";
  const checklist = [
    `${secretBindings} secret binding${secretBindings === 1 ? "" : "s"}`,
    `${vaultBackedBindings} vault ref${vaultBackedBindings === 1 ? "" : "s"}`,
    `${rawSecretBindings} raw secret${rawSecretBindings === 1 ? "" : "s"}`,
    `${publicBindings} public binding${publicBindings === 1 ? "" : "s"}`,
  ];
  return {
    totalBindings,
    secretBindings,
    vaultBackedBindings,
    rawSecretBindings,
    publicBindings,
    tone,
    label,
    detail,
    checklist,
  };
}
