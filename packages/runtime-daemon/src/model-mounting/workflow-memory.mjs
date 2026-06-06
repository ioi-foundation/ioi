const MEMORY_OPTION_KEYS = [
  "memory_key",
  "scope",
  "injection_enabled",
  "disabled",
  "read_only",
  "write_requires_approval",
  "write_approved",
  "subagent_inheritance",
  "retention",
  "redaction",
  "remember",
];

export function workflowMemoryOptionsFromBody(body = {}) {
  const memory = objectOrEmpty(body.memory);
  const logic = objectOrEmpty(body.logic);
  const sources = [memory, logic, body];
  const hasMemoryConfig = sources.some((source) =>
    MEMORY_OPTION_KEYS.some((key) => Object.prototype.hasOwnProperty.call(source, key)),
  );
  if (!hasMemoryConfig) return null;
  const pick = (...keys) => {
    for (const source of sources) {
      for (const key of keys) {
        if (Object.prototype.hasOwnProperty.call(source, key)) return source[key];
      }
    }
    return undefined;
  };
  const injectionEnabled = optionalBoolean(pick("injection_enabled"));
  const disabledValue = optionalBoolean(pick("disabled"));
  const options = {
    memory_key: optionalString(pick("memory_key")),
    scope: optionalString(pick("scope")) ?? "thread",
    injection_enabled: injectionEnabled ?? true,
    disabled: disabledValue ?? injectionEnabled === false,
    read_only: optionalBoolean(pick("read_only")) ?? false,
    write_requires_approval: optionalBoolean(pick("write_requires_approval")) ?? false,
    write_approved: optionalBoolean(pick("write_approved")) ?? false,
    subagent_inheritance: optionalString(pick("subagent_inheritance")) ?? "explicit",
    retention: optionalString(pick("retention")),
    redaction: optionalString(pick("redaction")) ?? "none",
    remember: optionalString(pick("remember")),
  };
  return Object.fromEntries(Object.entries(options).filter(([, value]) => value !== undefined && value !== null && value !== ""));
}

export function workflowMemoryWriteBlockReason(memory) {
  if (!memory?.remember) return null;
  if (memory.disabled) return "memory_disabled";
  if (memory.read_only) return "memory_read_only";
  if (memory.write_requires_approval && !memory.write_approved) return "memory_write_requires_approval";
  return null;
}

function objectOrEmpty(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : {};
}

function optionalString(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed ? trimmed : null;
}

function optionalBoolean(value) {
  if (value === undefined || value === null) return undefined;
  return value === true || value === "true" || value === 1 || value === "1";
}
