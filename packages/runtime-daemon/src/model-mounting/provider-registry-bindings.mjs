import {
  hostedProvider as hostedProviderFromRegistry,
  optionalString as optionalStringFromRegistry,
  publicProvider as publicProviderFromRegistry,
  requiredString as requiredStringFromRegistry,
} from "./provider-registry.mjs";

export function createProviderRegistryBindings(deps = {}) {
  const {
    providerHasVaultRef,
    providerRequiresVaultSecret,
    runtimeError,
    stableHash,
  } = deps;

  return {
    hostedProvider(id, label, apiFormat, secret) {
      return hostedProviderFromRegistry(id, label, apiFormat, secret);
    },
    publicProvider(provider, vaultMetadata = null) {
      return publicProviderFromRegistry(provider, vaultMetadata, {
        providerHasVaultRef,
        providerRequiresVaultSecret,
        stableHash,
      });
    },
    requiredString(value, field) {
      return requiredStringFromRegistry(value, field, { runtimeError });
    },
    optionalString(value) {
      return optionalStringFromRegistry(value);
    },
  };
}
