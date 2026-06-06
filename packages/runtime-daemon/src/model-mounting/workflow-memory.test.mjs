import assert from "node:assert/strict";
import test from "node:test";

import { workflowMemoryOptionsFromBody, workflowMemoryWriteBlockReason } from "./workflow-memory.mjs";

test("workflowMemoryOptionsFromBody emits canonical memory options from canonical request fields", () => {
  const options = workflowMemoryOptionsFromBody({
    memory: {
      memory_key: "project",
      scope: "workspace",
      injection_enabled: "false",
      read_only: "true",
      write_requires_approval: true,
      write_approved: "1",
      subagent_inheritance: "read_only",
      retention: "session",
      redaction: "summary",
      remember: "ship the Rust substrate",
    },
  });

  assert.deepEqual(options, {
    memory_key: "project",
    scope: "workspace",
    injection_enabled: false,
    disabled: true,
    read_only: true,
    write_requires_approval: true,
    write_approved: true,
    subagent_inheritance: "read_only",
    retention: "session",
    redaction: "summary",
    remember: "ship the Rust substrate",
  });
});

test("workflowMemoryOptionsFromBody ignores retired camelCase and memory-prefixed aliases", () => {
  const options = workflowMemoryOptionsFromBody({
    memory: {
      memoryKey: "retired.project",
      memoryScope: "workspace",
      memoryInjectionEnabled: false,
      memoryDisabled: true,
      memoryReadOnly: true,
      memoryWriteRequiresApproval: true,
      memoryWriteApproved: true,
      memorySubagentInheritance: "full",
      memoryRetention: "forever",
      memoryRedaction: "full",
      memoryRemember: "do not remember this alias",
      injectionEnabled: false,
      readOnly: true,
      writeRequiresApproval: true,
      writeApproved: true,
      subagentInheritance: "read_only",
    },
  });

  assert.equal(options, null);
});

test("workflowMemoryOptionsFromBody canonical request fields win over retired aliases", () => {
  const options = workflowMemoryOptionsFromBody({
    logic: {
      memoryKey: "retired.logic",
      memory_key: "canonical.logic",
      writeApproved: true,
      write_approved: false,
    },
  });

  assert.equal(options.memory_key, "canonical.logic");
  assert.equal(options.write_approved, false);
  assert.equal(Object.hasOwn(options, "memoryKey"), false);
  assert.equal(Object.hasOwn(options, "writeApproved"), false);
});

test("workflowMemoryWriteBlockReason uses canonical write-gating fields only", () => {
  assert.equal(
    workflowMemoryWriteBlockReason({
      remember: "requires approval",
      write_requires_approval: true,
      write_approved: false,
    }),
    "memory_write_requires_approval",
  );
  assert.equal(
    workflowMemoryWriteBlockReason({
      remember: "approved",
      write_requires_approval: true,
      write_approved: true,
    }),
    null,
  );
  assert.equal(
    workflowMemoryWriteBlockReason({
      remember: "retired aliases ignored",
      writeRequiresApproval: true,
      writeApproved: false,
    }),
    null,
  );
});
