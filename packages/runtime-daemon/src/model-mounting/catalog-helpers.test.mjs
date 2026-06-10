import assert from "node:assert/strict";
import test from "node:test";

import {
  destructiveConfirmationState,
  normalizeImportMode,
} from "./catalog-helpers.mjs";

test("destructive confirmation accepts canonical request fields", () => {
  assert.deepEqual(
    destructiveConfirmationState(
      { confirm_destructive: true },
      { required: true, action: "model_storage_cleanup" },
    ),
    {
      required: true,
      confirmed: true,
      action: "model_storage_cleanup",
      source: "operator_confirmation",
    },
  );
  assert.equal(
    destructiveConfirmationState(
      { confirm_destructive: true },
      { required: true, action: "model_storage_cleanup" },
    ).confirmed,
    true,
  );
});

test("destructive confirmation rejects retired request aliases", () => {
  assert.throws(
    () =>
      destructiveConfirmationState(
        {
          confirmDestructive: true,
          destructiveConfirmed: true,
          destructive_confirmed: true,
        },
        { required: true, action: "model_storage_cleanup" },
      ),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "destructive_confirmation_request_aliases_retired");
      assert.deepEqual(error.details.retired_aliases, [
        "confirmDestructive",
        "destructiveConfirmed",
        "destructive_confirmed",
      ]);
      assert.deepEqual(error.details.canonical_fields, [
        "confirm_destructive",
      ]);
      return true;
    },
  );
});

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
