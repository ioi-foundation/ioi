import { driverNameForProvider } from "./provider-driver-helpers.mjs";
import {
  FixtureModelProviderDriver,
  NativeLocalModelProviderDriver,
} from "./provider-local-drivers.mjs";
import { OpenAICompatibleModelProviderDriver } from "./provider-openai-compatible-driver.mjs";
import { OllamaModelProviderDriver } from "./provider-ollama-driver.mjs";
import {
  LlamaCppModelProviderDriver,
  VllmModelProviderDriver,
} from "./provider-openai-backend-drivers.mjs";
import { LmStudioModelProviderDriver } from "./provider-lm-studio-driver.mjs";

export function driverForProvider(state, provider) {
  const driver = driverNameForProvider(provider);
  if (driver === "native_local") return new NativeLocalModelProviderDriver();
  if (driver === "lm_studio") return new LmStudioModelProviderDriver({ state });
  if (driver === "llama_cpp") return new LlamaCppModelProviderDriver({ state });
  if (driver === "ollama") return new OllamaModelProviderDriver();
  if (driver === "vllm") return new VllmModelProviderDriver({ state });
  if (driver === "openai_compatible") {
    return new OpenAICompatibleModelProviderDriver({ label: provider.kind });
  }
  return new FixtureModelProviderDriver();
}
