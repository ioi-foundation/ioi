function defaultEscapeHtml(value = "") {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function createStudioCodeExecution(deps = {}) {
  const commandPayloadAttr = deps.commandPayloadAttr || (() => "");
  const escapeHtml = deps.escapeHtml || defaultEscapeHtml;

  function studioExecutableCodeBlocksFromText(content = "") {
    const blocks = [];
    const executableLanguages = new Set(["bash", "sh", "shell", "zsh", "python", "javascript", "typescript", "node"]);
    const fencePattern = /```([a-zA-Z0-9_-]+)\s*\n([\s\S]*?)```/g;
    let match = null;
    while ((match = fencePattern.exec(String(content || "")))) {
      const language = String(match[1] || "").trim().toLowerCase();
      const normalizedLanguage = language === "js" ? "javascript" : language === "ts" ? "typescript" : language;
      const source = String(match[2] || "").trim();
      if (source && executableLanguages.has(normalizedLanguage)) {
        blocks.push({ language: normalizedLanguage, source });
      }
    }
    return blocks;
  }

  function studioCodeExecutionPolicy(source = "") {
    if (/\b(curl|wget|ssh|scp|nc|ncat|telnet)\b|https?:\/\//i.test(source)) {
      return {
        status: "blocked",
        blockReason: "Network-shaped code block requires explicit approval before execution.",
        policyRefs: ["policy:code_execution.plan_only", "policy:code_execution.sandbox.network_deny", "policy:code_execution.block.network"],
      };
    }
    if (/\brm\s+-rf\b|>\s*\/|sudo\b/i.test(source)) {
      return {
        status: "blocked",
        blockReason: "Host-write or privileged command shape cannot be executed from chat.",
        policyRefs: ["policy:code_execution.plan_only", "policy:code_execution.sandbox.network_deny", "policy:code_execution.block.host_write"],
      };
    }
    return {
      status: "ready",
      blockReason: null,
      policyRefs: ["policy:code_execution.plan_only", "policy:code_execution.sandbox.network_deny"],
    };
  }

  function studioChatCodeExecutionRows(turn = {}, turnIndex = 0) {
    const blocks = studioExecutableCodeBlocksFromText(turn.content || turn.text || "");
    if (!blocks.length) {
      return "";
    }
    return blocks.map((block, blockIndex) => {
      const policy = studioCodeExecutionPolicy(block.source);
      const payload = {
        turnIndex,
        blockIndex,
        language: block.language,
        source: block.source,
        applyMode: "plan_only",
        sandbox: {
          network: "deny",
          writeScope: "workspace_only",
          timeoutMs: 10000,
          receiptRequired: true,
        },
        policyRefs: policy.policyRefs,
      };
      return `
      <article class="studio-chat-code-execution-card" data-testid="studio-chat-code-execution-card" data-language="${escapeHtml(block.language)}" data-execution-status="${escapeHtml(policy.status)}" data-network-policy="deny" data-apply-mode="plan_only">
        <header>
          <strong>Run code in sandbox</strong>
          <span>${escapeHtml(block.language)} &middot; plan only &middot; network denied</span>
        </header>
        ${policy.blockReason ? `<p data-testid="studio-chat-code-execution-block-reason">${escapeHtml(policy.blockReason)}</p>` : ""}
        <footer>
          <button type="button" data-testid="studio-chat-code-execute-plan" data-bridge-request="chat.executeCodeBlock.plan"${commandPayloadAttr(payload)} ${policy.status === "blocked" ? "disabled" : ""}>Prepare run</button>
          <span data-testid="studio-chat-code-execution-policy">${escapeHtml(policy.policyRefs.join(", "))}</span>
        </footer>
      </article>
    `;
    }).join("");
  }

  return {
    studioChatCodeExecutionRows,
    studioCodeExecutionPolicy,
    studioExecutableCodeBlocksFromText,
  };
}

module.exports = {
  createStudioCodeExecution,
};
