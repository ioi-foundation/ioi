import assert from "node:assert/strict";
import test from "node:test";
import { projectDomainAppRuntimeModel } from "./domain-app-runtime-model.mjs";

test("canonical ontology object and action types project into the generated runtime", () => {
  const model = projectDomainAppRuntimeModel({
    canonical_object_model: {
      value_types: [{ id: "money", name: "Money" }],
      object_types: [
        { id: "loan", name: "Loan" },
        { id: "borrower", name: "Borrower" },
      ],
      link_types: [{ id: "held_by", name: "Held by" }],
      action_types: [
        {
          id: "approve",
          name: "Approve",
          kind: "modify_object",
          applies_to: "loan",
        },
        { id: "health", name: "Health", kind: "function" },
      ],
    },
  });

  assert.deepEqual(model.valueTypes, ["Money"]);
  assert.deepEqual(model.linkTypes, ["Held by"]);
  assert.deepEqual(
    model.objects.map(({ id, name, actions }) => ({
      id,
      name,
      actions: actions.map((action) => action.name),
    })),
    [
      { id: "loan", name: "Loan", actions: ["Approve", "Health"] },
      { id: "borrower", name: "Borrower", actions: ["Health"] },
    ],
  );
});

test("legacy string arrays remain a read-only compatibility projection", () => {
  const model = projectDomainAppRuntimeModel({
    canonical_object_model: {
      objects: ["Loan"],
      actions: ["Inspect"],
      states: ["draft"],
    },
  });

  assert.equal(model.objects[0].name, "Loan");
  assert.equal(model.objects[0].actions[0].name, "Inspect");
  assert.deepEqual(model.states, ["draft"]);
});
