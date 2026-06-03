export function createRuntimeRunHelpers({
  normalizeArray,
} = {}) {
  function resultForMode(mode, agent, prompt, source, memory = {}) {
    if (memory.command === "disable") {
      return "Memory is disabled for this thread.";
    }
    if (memory.command === "enable") {
      return "Memory is enabled for this thread.";
    }
    if (memory.command === "path") {
      return `Memory records path: ${memory.paths?.recordsPath ?? "unknown"}\nMemory policy path: ${memory.paths?.policiesPath ?? "unknown"}`;
    }
    if (memory.policyBlockReason) {
      return `Memory write blocked by policy: ${memory.policyBlockReason}.`;
    }
    if (memory.command === "edit") {
      const edited = normalizeArray(memory.mutations).find((mutation) => mutation.operation === "edit")?.record;
      return edited ? `Edited memory: ${edited.id}` : "No memory was edited.";
    }
    if (memory.command === "delete") {
      const deleted = normalizeArray(memory.mutations).find((mutation) => mutation.operation === "delete")?.record;
      return deleted ? `Deleted memory: ${deleted.id}` : "No memory was deleted.";
    }
    if (memory.disabled && (memory.command === "remember" || memory.command === "show")) {
      return "Memory is disabled for this run.";
    }
    if (memory.command === "remember") {
      const remembered = normalizeArray(memory.writes).map((write) => write.record?.fact).filter(Boolean);
      return remembered.length > 0
        ? `Remembered: ${remembered.join("; ")}`
        : "No memory was written because the remember request was empty.";
    }
    if (memory.command === "show") {
      const records = normalizeArray(memory.records);
      return records.length > 0
        ? `Memory:\n${records.map((record) => `- ${record.fact}`).join("\n")}`
        : "Memory is empty for this thread.";
    }
    switch (mode) {
      case "plan":
        return `Plan-only daemon run recorded objective, constraints, postconditions, and stop reason for: ${prompt}`;
      case "dry_run":
        return "Dry run completed through the daemon. Side effects were previewed and no mutation was executed.";
      case "handoff":
        return "Daemon handoff bundle is complete: objective, state, blockers, evidence, and next action are preserved.";
      case "learn":
        return "Governed learning record created behind memory quality and bounded self-improvement gates.";
      case "send":
      default:
        return `IOI daemon run completed for ${agent.cwd}. Source=${source}. Trace, receipts, Agentgres canonical projection, task state, uncertainty, probe, postconditions, semantic impact, stop condition, and scorecard are available through public runtime APIs.`;
    }
  }

  function taskFamilyForMode(mode) {
    switch (mode) {
      case "plan":
        return "planning";
      case "dry_run":
        return "safety_preview";
      case "handoff":
        return "delegation";
      case "learn":
        return "learning";
      case "send":
      default:
        return "local_daemon_agentgres";
    }
  }

  function strategyForMode(mode) {
    switch (mode) {
      case "plan":
        return "daemon_plan_with_postconditions";
      case "dry_run":
        return "daemon_dry_run_before_effect";
      case "handoff":
        return "daemon_handoff_with_state_preservation";
      case "learn":
        return "daemon_bounded_learning_gate";
      case "send":
      default:
        return "local_daemon_agentgres_execution";
    }
  }

  function capabilitySequenceForMode(mode, agent) {
    const sequence = [
      "authority_check",
      "policy_check",
      "task_state_write",
      "agentgres_operation_log",
      "trace_export",
      "canonical_replay",
    ];
    if (agent.options.mcpServerNames.length > 0) sequence.push("mcp_containment");
    if (agent.options.skillNames.length > 0) sequence.push("skill_instruction_import");
    if (agent.options.hookNames.length > 0) sequence.push("runtime_event_hook");
    if (mode === "dry_run") sequence.push("side_effect_preview");
    if (mode === "handoff") sequence.push("handoff_quality");
    if (mode === "learn") sequence.push("memory_quality_gate");
    return sequence;
  }

  function makeEvent(runId, agentId, index, type, summary, data) {
    return {
      id: `${runId}:event:${String(index).padStart(3, "0")}:${type}`,
      runId,
      agentId,
      type,
      cursor: `${runId}:${index}`,
      createdAt: new Date().toISOString(),
      summary,
      data,
    };
  }

  return {
    capabilitySequenceForMode,
    makeEvent,
    resultForMode,
    strategyForMode,
    taskFamilyForMode,
  };
}
