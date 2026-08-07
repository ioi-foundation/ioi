function records(value) {
  return Array.isArray(value) ? value : [];
}

function identity(record, fallback) {
  if (typeof record === "string") return record;
  if (!record || typeof record !== "object") return fallback;
  return String(record.id || record.name || fallback);
}

function label(record, fallback) {
  if (typeof record === "string") return record;
  if (!record || typeof record !== "object") return fallback;
  return String(record.name || record.id || fallback);
}

export function projectDomainAppRuntimeModel(ontology) {
  const canonical = ontology?.canonical_object_model || {};
  const canonicalObjects = records(canonical.object_types);
  const legacyObjects =
    canonicalObjects.length === 0 ? records(canonical.objects) : [];
  const canonicalActions = records(canonical.action_types);
  const legacyActions =
    canonicalActions.length === 0 ? records(canonical.actions) : [];
  const actions = [...canonicalActions, ...legacyActions].map(
    (action, index) => ({
      id: identity(action, `action_${index + 1}`),
      name: label(action, `Action ${index + 1}`),
      kind:
        typeof action === "object" && action ? String(action.kind || "") : "",
      appliesTo:
        typeof action === "object" && action
          ? String(action.applies_to || "")
          : "",
    }),
  );
  const objects = [...canonicalObjects, ...legacyObjects].map(
    (object, index) => {
      const id = identity(object, `object_${index + 1}`);
      const name = label(object, `Object ${index + 1}`);
      return {
        id,
        name,
        actions: actions.filter(
          (action) =>
            action.appliesTo.length === 0 ||
            action.appliesTo === id ||
            action.appliesTo === name,
        ),
      };
    },
  );
  return {
    objects,
    valueTypes: records(canonical.value_types).map((record, index) =>
      label(record, `Value type ${index + 1}`),
    ),
    linkTypes: records(canonical.link_types).map((record, index) =>
      label(record, `Relation ${index + 1}`),
    ),
    states: records(canonical.states).map((record, index) =>
      label(record, `State ${index + 1}`),
    ),
    events: records(canonical.events).map((record, index) =>
      label(record, `Event ${index + 1}`),
    ),
    roles: records(canonical.roles).map((record, index) =>
      label(record, `Role ${index + 1}`),
    ),
  };
}
