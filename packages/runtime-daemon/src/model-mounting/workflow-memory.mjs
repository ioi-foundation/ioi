const MEMORY_OPTION_KEYS = [
  "memoryKey",
  "memory_key",
  "scope",
  "memoryScope",
  "memory_scope",
  "injectionEnabled",
  "memoryInjectionEnabled",
  "injection_enabled",
  "memory_injection_enabled",
  "disabled",
  "memoryDisabled",
  "memory_disabled",
  "readOnly",
  "memoryReadOnly",
  "read_only",
  "memory_read_only",
  "writeRequiresApproval",
  "memoryWriteRequiresApproval",
  "write_requires_approval",
  "memory_write_requires_approval",
  "writeApproved",
  "memoryWriteApproved",
  "write_approved",
  "memory_write_approved",
  "subagentInheritance",
  "memorySubagentInheritance",
  "subagent_inheritance",
  "memory_subagent_inheritance",
  "retention",
  "memoryRetention",
  "memory_retention",
  "redaction",
  "memoryRedaction",
  "memory_redaction",
  "remember",
  "memoryRemember",
  "memory_remember",
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
  const injectionEnabled = optionalBoolean(
    pick("injectionEnabled", "memoryInjectionEnabled", "injection_enabled", "memory_injection_enabled"),
  );
  const disabledValue = optionalBoolean(pick("disabled", "memoryDisabled", "memory_disabled"));
  const options = {
    memoryKey: optionalString(pick("memoryKey", "memory_key")),
    scope: optionalString(pick("scope", "memoryScope", "memory_scope")) ?? "thread",
    injectionEnabled: injectionEnabled ?? true,
    disabled: disabledValue ?? injectionEnabled === false,
    readOnly: optionalBoolean(pick("readOnly", "memoryReadOnly", "read_only", "memory_read_only")) ?? false,
    writeRequiresApproval:
      optionalBoolean(
        pick(
          "writeRequiresApproval",
          "memoryWriteRequiresApproval",
          "write_requires_approval",
          "memory_write_requires_approval",
        ),
      ) ?? false,
    writeApproved:
      optionalBoolean(pick("writeApproved", "memoryWriteApproved", "write_approved", "memory_write_approved")) ?? false,
    subagentInheritance:
      optionalString(
        pick("subagentInheritance", "memorySubagentInheritance", "subagent_inheritance", "memory_subagent_inheritance"),
      ) ?? "explicit",
    retention: optionalString(pick("retention", "memoryRetention", "memory_retention")),
    redaction: optionalString(pick("redaction", "memoryRedaction", "memory_redaction")) ?? "none",
    remember: optionalString(pick("remember", "memoryRemember", "memory_remember")),
  };
  return Object.fromEntries(Object.entries(options).filter(([, value]) => value !== undefined && value !== null && value !== ""));
}

export function workflowMemoryWriteBlockReason(memory) {
  if (!memory?.remember) return null;
  if (memory.disabled) return "memory_disabled";
  if (memory.readOnly) return "memory_read_only";
  if (memory.writeRequiresApproval && !memory.writeApproved) return "memory_write_requires_approval";
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
