import assert from "node:assert/strict";
import test from "node:test";

import { normalizeImportMode } from "./catalog-helpers.mjs";

test("catalog import mode errors use canonical details", () => {
  assert.throws(
    () => normalizeImportMode("side-load"),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "bad_request");
      assert.equal(error.details.import_mode, "side_load");
      assert.equal(Object.hasOwn(error.details, "importMode"), false);
      return true;
    },
  );
});
