import assert from "node:assert/strict";
import test from "node:test";

import { exposeInternalFixtureModels, internalFixtureModelsEnabled } from "./environment.mjs";

test("internal fixture model exposure uses canonical env toggle", () => {
  assert.equal(
    exposeInternalFixtureModels({ IOI_EXPOSE_INTERNAL_FIXTURE_MODELS: "1" }),
    true,
  );
  assert.equal(
    internalFixtureModelsEnabled({ IOI_EXPOSE_INTERNAL_FIXTURE_MODELS: "1" }),
    true,
  );
});

test("internal fixture model exposure ignores retired enable env alias", () => {
  assert.equal(
    internalFixtureModelsEnabled({ IOI_ENABLE_INTERNAL_FIXTURE_MODELS: "1" }),
    false,
  );
  assert.equal(
    internalFixtureModelsEnabled({
      IOI_ENABLE_INTERNAL_FIXTURE_MODELS: "1",
      IOI_EXPOSE_INTERNAL_FIXTURE_MODELS: "0",
    }),
    false,
  );
});
