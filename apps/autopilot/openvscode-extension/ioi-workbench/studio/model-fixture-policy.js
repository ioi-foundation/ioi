"use strict";

function createStudioModelFixturePolicy({
  getEnv = () => "",
  stringValue = (value, fallback = "") => {
    if (value === undefined || value === null) {
      return fallback;
    }
    const normalized = String(value).trim();
    return normalized || fallback;
  },
} = {}) {
  function studioFixtureModelUsageAllowed() {
    return /^(1|true|yes|on)$/i.test(String(getEnv("IOI_STUDIO_ALLOW_FIXTURE_MODELS") || getEnv("IOI_STUDIO_FIXTURE_MODE") || ""));
  }

  function studioDenyFixtureModelPolicy() {
    return studioFixtureModelUsageAllowed()
      ? {}
      : {
          deny_fixture_models: true,
          denyFixtureModels: true,
        };
  }

  function studioTextContainsProductFixtureMarker(text = "") {
    const haystack = stringValue(text).toLowerCase();
    return (
      haystack.includes("ioi model router fixture response") ||
      haystack.includes("input_hash=") ||
      haystack.includes("autopilot:native-fixture") ||
      haystack.includes("local:auto") ||
      haystack.includes("stories260k") ||
      haystack.includes("deterministic native-local model fixture") ||
      haystack.includes("native_local.fixture") ||
      haystack.includes("backend.fixture")
    );
  }

  return {
    studioDenyFixtureModelPolicy,
    studioFixtureModelUsageAllowed,
    studioTextContainsProductFixtureMarker,
  };
}

module.exports = {
  createStudioModelFixturePolicy,
};
