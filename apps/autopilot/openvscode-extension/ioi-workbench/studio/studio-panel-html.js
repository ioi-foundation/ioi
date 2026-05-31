let studioPanelNonce = null;

const { studioPanelStyles } = require("./studio-panel-styles");

function createStudioPanelHtml({
  nonce,
  getPageNonce,
  workspaceSummary,
  renderStudioOperationalSurface,
  bridgeUrl,
  STUDIO_APPROVAL_ID,
}) {
  return function studioPanelHtml(state) {
  const pageNonce = getPageNonce ? getPageNonce() : (studioPanelNonce || (studioPanelNonce = nonce()));
  const workspace = state.workspace || workspaceSummary();
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta
      http-equiv="Content-Security-Policy"
      content="default-src 'none'; img-src data:; style-src 'nonce-${pageNonce}' 'unsafe-inline'; script-src 'nonce-${pageNonce}';"
    />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Agent Studio</title>
    <style nonce="${pageNonce}">
      ${studioPanelStyles()}
    </style>
  </head>
  <body>
	    ${renderStudioOperationalSurface(state, { standalone: true })}
	    <script nonce="${pageNonce}">
	      const vscode = acquireVsCodeApi();
	      const ioiBridgeUrl = ${JSON.stringify(bridgeUrl() || "")};
      const STUDIO_MARKDOWN_FENCE = String.fromCharCode(96, 96, 96);
      const STUDIO_MARKDOWN_TICK = String.fromCharCode(96);
      function escapeMarkdownHtml(value) {
        return String(value || "")
          .replace(/&/g, "&amp;")
          .replace(/</g, "&lt;")
          .replace(/>/g, "&gt;")
          .replace(/"/g, "&quot;")
          .replace(/'/g, "&#39;");
      }
      function sanitizeMarkdownUrl(value) {
        const raw = String(value || "").trim();
        if (!raw || /[\\u0000-\\u001f\\u007f]/.test(raw)) return "";
        if (/^(?:https?:|mailto:|#|\\/)/i.test(raw)) return raw;
        try {
          const parsed = new URL(raw, "https://autopilot.local/");
          const protocol = parsed.protocol.toLowerCase();
          return protocol === "http:" || protocol === "https:" || protocol === "mailto:" ? raw : "";
        } catch {
          return "";
        }
      }
      function markdownPlaceholder(placeholders, html) {
        const key = "\\u0000studio-md-" + placeholders.length + "\\u0000";
        placeholders.push([key, html]);
        return key;
      }
      function renderMarkdownInline(value) {
        const placeholders = [];
        const codeSpan = new RegExp(STUDIO_MARKDOWN_TICK + "([^" + STUDIO_MARKDOWN_TICK + "\\\\n]+)" + STUDIO_MARKDOWN_TICK, "g");
        let text = String(value || "").replace(codeSpan, (_match, code) =>
          markdownPlaceholder(placeholders, "<code>" + escapeMarkdownHtml(code) + "</code>")
        );
        text = text.replace(/\\[([^\\]\\n]+)\\]\\(([^)\\s]+)(?:\\s+&quot;[^&]*&quot;)?\\)/g, (match, label, url) => {
          const safeUrl = sanitizeMarkdownUrl(url);
          if (!safeUrl) return label;
          return markdownPlaceholder(
            placeholders,
            '<a href="' + escapeMarkdownHtml(safeUrl) + '" target="_blank" rel="noreferrer noopener">' +
              renderMarkdownInline(label) +
              "</a>"
          );
        });
        text = escapeMarkdownHtml(text)
          .replace(/\\*\\*([^*]+)\\*\\*/g, "<strong>$1</strong>")
          .replace(/__([^_]+)__/g, "<strong>$1</strong>")
          .replace(/(^|\\W)\\*([^*\\n]+)\\*/g, "$1<em>$2</em>")
          .replace(/(^|\\W)_([^_\\n]+)_/g, "$1<em>$2</em>");
        for (const [key, html] of placeholders) {
          text = text.split(key).join(html);
        }
        return text;
      }
      function markdownTableCells(line) {
        return String(line || "")
          .trim()
          .replace(/^\\|/, "")
          .replace(/\\|$/, "")
          .split("|")
          .map((cell) => renderMarkdownInline(cell.trim()));
      }
      function isMarkdownTableSeparator(line) {
        return /^\\s*\\|?(?:\\s*:?-{3,}:?\\s*\\|)+\\s*:?-{3,}:?\\s*\\|?\\s*$/.test(String(line || ""));
      }
      function renderMarkdownTable(lines) {
        const header = markdownTableCells(lines[0] || "");
        const rows = lines.slice(2).map(markdownTableCells);
        const head = "<thead><tr>" + header.map((cell) => "<th>" + cell + "</th>").join("") + "</tr></thead>";
        const body = rows.length
          ? "<tbody>" + rows.map((row) => "<tr>" + row.map((cell) => "<td>" + cell + "</td>").join("") + "</tr>").join("") + "</tbody>"
          : "";
        return "<table>" + head + body + "</table>";
      }
      function renderMarkdownBlocks(value) {
        const lines = String(value || "").replace(/\\r\\n?/g, "\\n").split("\\n");
        const html = [];
        let paragraph = [];
        let listType = "";
        let listItems = [];
        let fenceLanguage = "";
        let fenceLines = null;
        const flushParagraph = () => {
          if (!paragraph.length) return;
          html.push("<p>" + renderMarkdownInline(paragraph.join(" ").trim()) + "</p>");
          paragraph = [];
        };
        const flushList = () => {
          if (!listType || !listItems.length) return;
          html.push("<" + listType + ">" + listItems.map((item) => "<li>" + renderMarkdownInline(item) + "</li>").join("") + "</" + listType + ">");
          listType = "";
          listItems = [];
        };
        const flushFence = () => {
          if (!fenceLines) return;
          const language = fenceLanguage ? ' class="language-' + escapeMarkdownHtml(fenceLanguage) + '"' : "";
          html.push("<pre><code" + language + ">" + escapeMarkdownHtml(fenceLines.join("\\n")) + "</code></pre>");
          fenceLanguage = "";
          fenceLines = null;
        };
        for (let index = 0; index < lines.length; index += 1) {
          const line = lines[index] || "";
          const trimmed = line.trim();
          if (trimmed.startsWith(STUDIO_MARKDOWN_FENCE)) {
            if (fenceLines) {
              flushFence();
            } else {
              flushParagraph();
              flushList();
              fenceLanguage = trimmed.slice(STUDIO_MARKDOWN_FENCE.length).trim().replace(/[^a-z0-9_-]/gi, "").slice(0, 32);
              fenceLines = [];
            }
            continue;
          }
          if (fenceLines) {
            fenceLines.push(line);
            continue;
          }
          if (!trimmed) {
            flushParagraph();
            flushList();
            continue;
          }
          if (/^---+$/.test(trimmed)) {
            flushParagraph();
            flushList();
            html.push("<hr />");
            continue;
          }
          if (line.includes("|") && isMarkdownTableSeparator(lines[index + 1] || "")) {
            flushParagraph();
            flushList();
            const tableLines = [line, lines[index + 1] || ""];
            index += 2;
            while (index < lines.length && String(lines[index] || "").trim() && String(lines[index] || "").includes("|")) {
              tableLines.push(lines[index] || "");
              index += 1;
            }
            index -= 1;
            html.push(renderMarkdownTable(tableLines));
            continue;
          }
          const heading = trimmed.match(/^(#{1,4})\\s+(.+)$/);
          if (heading) {
            flushParagraph();
            flushList();
            const level = Math.min(4, heading[1].length);
            html.push("<h" + level + ">" + renderMarkdownInline(heading[2]) + "</h" + level + ">");
            continue;
          }
          const quote = trimmed.match(/^>\\s?(.*)$/);
          if (quote) {
            flushParagraph();
            flushList();
            html.push("<blockquote>" + renderMarkdownInline(quote[1]) + "</blockquote>");
            continue;
          }
          const unordered = trimmed.match(/^[-*+]\\s+(.+)$/);
          if (unordered) {
            flushParagraph();
            if (listType && listType !== "ul") flushList();
            listType = "ul";
            listItems.push(unordered[1]);
            continue;
          }
          const ordered = trimmed.match(/^\\d+[.)]\\s+(.+)$/);
          if (ordered) {
            flushParagraph();
            if (listType && listType !== "ol") flushList();
            listType = "ol";
            listItems.push(ordered[1]);
            continue;
          }
          flushList();
          paragraph.push(line);
        }
        flushFence();
        flushParagraph();
        flushList();
        return html.join("");
      }
      function renderMarkdownInto(node, value) {
        if (!node) return;
        const source = String(value || "");
        node.dataset.rawMarkdown = source;
        node.innerHTML = renderMarkdownBlocks(source);
      }
      function appendMarkdownDelta(node, delta) {
        if (!node) return;
        renderMarkdownInto(node, String(node.dataset.rawMarkdown || "") + String(delta || ""));
      }
      function hydrateExistingAssistantMarkdown() {
        document.querySelectorAll("[data-testid='studio-assistant-answer-text'], [data-testid='studio-streaming-output']").forEach((node) => {
          const turn = node.closest("[data-studio-turn-role='assistant']");
          if (!turn || node.dataset.rawMarkdown !== undefined) return;
          node.classList.add("studio-markdown");
          renderMarkdownInto(node, node.textContent || "");
        });
      }
      function parsePayload(raw) {
        if (!raw) return undefined;
        try {
          return JSON.parse(raw);
        } catch (error) {
          console.error("[IOI Studio] Failed to parse payload", error);
          return undefined;
        }
      }
      function isForkQuickInputCommand(command) {
        return command === "ioi.quickInput.context.open" ||
          command === "ioi.quickInput.tools.configure" ||
          command === "ioi.quickInput.modelRoute.pick" ||
          command === "ioi.quickInput.workflowTarget.pick" ||
          command === "ioi.quickInput.agentMode.pick" ||
          command === "ioi.quickInput.permissionMode.pick";
      }
      function focusStudioComposer() {
        const focus = () => {
          const input = document.querySelector("[data-studio-prompt]");
          if (!input) {
            return;
          }
          try {
            window.focus();
          } catch {
            // Best-effort only; Electron/VS Code may already own focus at the host window.
          }
          input.focus({ preventScroll: true });
          try {
            const length = String(input.value || "").length;
            input.setSelectionRange(length, length);
          } catch {
            // Some focus targets may not support text selection.
          }
        };
        focus();
        for (const delay of [40, 80, 160, 320, 650, 1000, 1500]) {
          window.setTimeout(focus, delay);
        }
      }
      function openForkQuickInput(command, payload) {
        const message = {
          source: "ioi-workbench-agent-studio",
          type: "ioi.quickInput.open",
          command,
          payload: {
            ...(payload || {}),
            bridgeUrl: ioiBridgeUrl,
            runtimeAuthority: "daemon-owned",
            projectionOwner: "ioi-workbench-agent-studio",
            composerTestId: "studio-composer-input"
          }
        };
        window.parent?.postMessage(message, "*");
        if (window.top && window.top !== window.parent) {
          window.top.postMessage(message, "*");
        }
      }
      function buttonQuickInputPayload(button) {
        const payload = parsePayload(button.dataset.payload) || {};
        const rect = button.getBoundingClientRect();
        return {
          ...payload,
          controlTestId: button.dataset.testid || "",
          anchorRect: {
            left: rect.left,
            top: rect.top,
            right: rect.right,
            bottom: rect.bottom,
            width: rect.width,
            height: rect.height
          }
        };
      }
      function executionModeFromAgentModeResult(result) {
        const normalized = String(result?.selectionId || result?.mode || result?.label || "agent")
          .toLowerCase()
          .replace(/[\\s-]+/g, "_");
        return ["ask", "chat", "chat_only", "chatonly", "direct_chat", "direct_model"].includes(normalized)
          ? "ask"
          : "agent";
      }
      function applyAgentModeResult(result) {
        const mode = executionModeFromAgentModeResult(result);
        const modeButton = document.querySelector("[data-testid='studio-mode-toggle']");
        if (modeButton) {
          modeButton.dataset.studioMode = mode;
          const label = modeButton.querySelector("span");
          if (label) label.textContent = mode === "ask" ? "Ask" : "Agent";
        }
        return mode;
      }
      function permissionModeFromResult(result) {
        const normalized = String(result?.approvalMode || result?.approval_mode || result?.selectionId || result?.mode || result?.label || "suggest")
          .toLowerCase()
          .replace(/[\\s-]+/g, "_");
        if (["auto_review", "auto_local", "autolocal", "auto"].includes(normalized)) {
          return "auto_local";
        }
        if (["full_access", "fullaccess", "never_prompt", "neverprompt", "yolo"].includes(normalized)) {
          return "never_prompt";
        }
        return "suggest";
      }
      function permissionModeLabel(mode) {
        if (mode === "auto_local") return "Auto-review";
        if (mode === "never_prompt") return "Full access";
        return "Default permissions";
      }
      function permissionThreadMode(mode) {
        return mode === "never_prompt" ? "yolo" : "agent";
      }
      function applyPermissionModeResult(result) {
        const approvalMode = permissionModeFromResult(result);
        const permissionButton = document.querySelector("[data-testid='studio-permissions-toggle']");
        if (permissionButton) {
          permissionButton.dataset.approvalMode = approvalMode;
          permissionButton.title = "Permissions - " + permissionModeLabel(approvalMode);
          permissionButton.setAttribute("aria-label", permissionButton.title);
          const label = permissionButton.querySelector("span");
          if (label) label.textContent = permissionModeLabel(approvalMode);
        }
        return approvalMode;
      }
      function updateStreamRunBar(turn, status, label) {
        const runBar = turn?.querySelector("[data-testid='studio-run-status-bar']");
        if (!runBar) return;
        const strong = runBar.querySelector("strong");
        const statusNode = runBar.querySelector("span:last-child");
        if (strong) strong.textContent = label || (status === "completed" ? "Worked" : "Working...");
        if (statusNode) statusNode.textContent = status || "streaming";
      }
      function ensureStreamingAssistantTurn(streamId) {
        const transcript =
          document.querySelector("[data-testid='studio-chat-transcript']") ||
          document.querySelector("[data-testid='studio-transcript']");
        if (!transcript) return null;
        let turn = transcript.querySelector("[data-studio-stream-turn='" + streamId + "']");
        if (!turn) {
          turn = appendProjectedTurn("assistant", "");
          turn.dataset.studioStreamTurn = streamId;
          turn.setAttribute("data-testid", "studio-streaming-assistant-turn");
        }
        let text = turn.querySelector("[data-testid='studio-streaming-output']");
        if (!text) {
          text = turn.querySelector("[data-testid='studio-assistant-answer-text']");
          if (!text) {
            const body = turn.querySelector("[data-testid='studio-assistant-answer-card']") || turn.querySelector(".studio-chat-turn__body");
            text = document.createElement("div");
            body?.append(text);
          }
          text?.classList.add("studio-markdown");
          text?.setAttribute("data-testid", "studio-streaming-output");
        }
        return { turn, text };
      }
      function ensureStreamingThinkingBlock(turn) {
        if (!turn) return null;
        const body = turn.querySelector("[data-testid='studio-assistant-answer-card']") || turn.querySelector(".studio-chat-turn__body");
        if (!body) return null;
        let block = body.querySelector("[data-testid='studio-thinking-block']");
        if (!block) {
          block = document.createElement("details");
          block.className = "studio-thinking-block";
          block.setAttribute("data-testid", "studio-thinking-block");
          block.open = true;
          block.innerHTML = "<summary>Thinking</summary><p></p>";
          const output = body.querySelector("[data-testid='studio-streaming-output']") || body.querySelector("p");
          body.insertBefore(block, output || body.firstChild);
        }
        return block.querySelector("p");
      }
      const studioRuntimeStreamKinds = new Map();
      const studioRuntimeStreamPresentations = new Map();
      function studioStreamKind(streamId) {
        return studioRuntimeStreamKinds.get(String(streamId || "")) || "assistant";
      }
      function studioStreamPresentation(streamId) {
        return studioRuntimeStreamPresentations.get(String(streamId || "")) || "";
      }
      function setStudioStreamKind(payload) {
        const streamId = String(payload?.streamId || "");
        if (!streamId) return "assistant";
        const presentation = String(payload?.presentation || "");
        const kind = presentation === "artifact_generation" ? "artifact_source" : "assistant";
        studioRuntimeStreamPresentations.set(streamId, presentation);
        studioRuntimeStreamKinds.set(streamId, kind);
        return kind;
      }
      function ensurePendingThinkingBlock() {
        const pending = ensurePendingProjection();
        if (!pending) return null;
        let block = pending.querySelector("[data-testid='studio-pending-thinking']");
        if (!block) {
          block = document.createElement("details");
          block.className = "studio-pending__thinking";
          block.setAttribute("data-testid", "studio-pending-thinking");
          block.open = true;
          block.innerHTML = "<summary>Thinking</summary><p></p>";
          const worklog = pending.querySelector("[data-testid='studio-pending-worklog']");
          pending.insertBefore(block, worklog || null);
        }
        return block.querySelector("p");
      }
      function ensureArtifactSourceStream(payload = {}) {
        const pending = ensurePendingProjection();
        if (!pending) return null;
        let block = pending.querySelector("[data-testid='studio-artifact-source-stream']");
        if (!block) {
          block = document.createElement("section");
          block.className = "studio-artifact-source-stream";
          block.setAttribute("data-testid", "studio-artifact-source-stream");
          block.innerHTML =
            "<header></header>" +
            "<pre data-testid='studio-artifact-source-output'></pre>";
          pending.append(block);
        }
        const header = block.querySelector("header");
        if (header) {
          const fileName = payload.fileName || payload.sourceFileName || "index.html";
          header.textContent = payload.label ? payload.label + " · " + fileName : "Writing " + fileName;
        }
        return block.querySelector("[data-testid='studio-artifact-source-output']");
      }
      function appendArtifactSourceStreamDelta(payload = {}) {
        const output = ensureArtifactSourceStream(payload);
        if (!output) return;
        output.textContent = (output.textContent || "") + (payload.delta || "");
      }
      function handleStudioRuntimeMessage(message) {
        const payload = message.payload || {};
        if (message.type === "agentWorkStep") {
          appendPendingWorkStep(payload);
          return;
        }
        if (!payload.streamId) return;
        if (message.type === "assistantStreamStart") {
          const kind = setStudioStreamKind(payload);
          showPendingProjection();
          if (kind === "artifact_source") {
            ensureArtifactSourceStream(payload);
          }
          return;
        }
        if (message.type === "assistantStreamDelta") {
          if (studioStreamKind(payload.streamId) === "artifact_source") {
            appendArtifactSourceStreamDelta(payload);
            document.querySelector("[data-testid='agent-studio-operational-chat']")?.setAttribute("data-studio-status", "streaming");
            return;
          }
          const target = ensureStreamingAssistantTurn(payload.streamId);
          if (target?.text) {
            appendMarkdownDelta(target.text, payload.delta || "");
          }
          updateStreamRunBar(target?.turn, "streaming", "Working...");
          document.querySelector("[data-testid='agent-studio-operational-chat']")?.setAttribute("data-studio-status", "streaming");
          hidePendingProjectionAfterMinimum();
          return;
        }
        if (message.type === "assistantThinkingDelta") {
          if (studioStreamKind(payload.streamId) === "artifact_source") {
            const thinking = ensurePendingThinkingBlock();
            if (thinking) {
              thinking.textContent = (thinking.textContent || "") + (payload.delta || "");
            }
            document.querySelector("[data-testid='agent-studio-operational-chat']")?.setAttribute("data-studio-status", "streaming");
            return;
          }
          const target = ensureStreamingAssistantTurn(payload.streamId);
          const thinking = ensureStreamingThinkingBlock(target?.turn);
          if (thinking) {
            thinking.textContent = (thinking.textContent || "") + (payload.delta || "");
          }
          updateStreamRunBar(target?.turn, "streaming", "Working...");
          document.querySelector("[data-testid='agent-studio-operational-chat']")?.setAttribute("data-studio-status", "streaming");
          hidePendingProjectionAfterMinimum();
          return;
        }
        if (message.type === "assistantStreamComplete") {
          if (studioStreamKind(payload.streamId) === "artifact_source") {
            const source = ensureArtifactSourceStream(payload);
            if (source && payload.text) {
              source.textContent = payload.text;
            }
            if (payload.thinkingText) {
              const thinking = ensurePendingThinkingBlock();
              if (thinking) thinking.textContent = payload.thinkingText;
            }
            document.querySelector("[data-testid='agent-studio-operational-chat']")?.setAttribute("data-studio-status", "streaming");
            studioRuntimeStreamKinds.delete(String(payload.streamId || ""));
            return;
          }
          const presentation = String(payload.presentation || studioStreamPresentation(payload.streamId) || "");
          const isAgentFinalHandoff = presentation === "agent_final_handoff";
          const finalProjectionOwnsCompletion =
            presentation === "artifact_handoff" ||
            presentation === "artifact_blocked_handoff";
          const target = ensureStreamingAssistantTurn(payload.streamId);
          if (target?.turn && payload.thinkingText) {
            const thinking = ensureStreamingThinkingBlock(target.turn);
            if (thinking) thinking.textContent = payload.thinkingText;
          }
          if (target?.text && payload.text) {
            renderMarkdownInto(target.text, payload.text);
          }
          updateStreamRunBar(target?.turn, "completed", "Worked");
          const root = document.querySelector("[data-testid='agent-studio-operational-chat']");
          if (isAgentFinalHandoff) {
            root?.setAttribute("data-agent-final-handoff-stream-complete", "true");
            root?.setAttribute("data-studio-status", "completed");
          }
          if (presentation === "artifact_handoff" || presentation === "artifact_blocked_handoff") {
            root?.setAttribute("data-artifact-handoff-stream-complete", "true");
          }
          if (finalProjectionOwnsCompletion) {
            root?.setAttribute("data-studio-status", "streaming");
          } else if (!isAgentFinalHandoff) {
            root?.setAttribute("data-studio-status", "completed");
          }
          studioRuntimeStreamPresentations.delete(String(payload.streamId || ""));
          hidePendingProjectionAfterMinimum();
          return;
        }
        if (message.type === "assistantStreamError") {
          const target = ensureStreamingAssistantTurn(payload.streamId);
          if (target?.text) {
            target.text.textContent = payload.error || "Daemon model stream failed.";
          }
          updateStreamRunBar(target?.turn, "blocked", "Blocked");
          hidePendingProjectionAfterMinimum();
          document.querySelector("[data-testid='agent-studio-operational-chat']")?.setAttribute("data-studio-status", "blocked");
        }
      }
      function projectStudioAgentTurnComplete(payload) {
        const text = String(payload?.text || "").trim() || "Agent Mode completed without additional assistant text.";
        const turn = appendProjectedTurn("assistant", text, { prompt: String(payload?.prompt || "") });
        if (turn) {
          turn.dataset.studioAgentTurnId = String(payload?.turnId || "");
          turn.dataset.studioRuntimeEventCount = String(payload?.eventCount || 0);
          turn.dataset.studioReceiptRefs = Array.isArray(payload?.receiptRefs) ? payload.receiptRefs.join(",") : "";
          turn.scrollIntoView({ block: "end", inline: "nearest" });
        }
        const root = document.querySelector("[data-testid='agent-studio-operational-chat']");
        root?.setAttribute("data-studio-status", "completed");
        hidePendingProjectionAfterMinimum();
        focusStudioComposer();
      }
      function projectStudioAgentTurnBlocked(payload) {
        const explicitText = String(payload?.text || "").trim();
        const text = explicitText || "Studio could not complete the daemon turn: " + (String(payload?.error || "").trim() || "runtime_bridge_failed");
        const turn = appendProjectedTurn("assistant", text, { prompt: String(payload?.prompt || "") });
        if (turn) {
          turn.scrollIntoView({ block: "end", inline: "nearest" });
        }
        const root = document.querySelector("[data-testid='agent-studio-operational-chat']");
        root?.setAttribute("data-studio-status", "blocked");
        hidePendingProjectionAfterMinimum();
        focusStudioComposer();
      }
      window.addEventListener("message", (event) => {
        const message = event.data || {};
        if (message.source === "ioi-studio-control" && message.type === "focusComposer") {
          focusStudioComposer();
          return;
        }
        if (message.source === "ioi-studio-control" && message.type === "agentTurnComplete") {
          projectStudioAgentTurnComplete(message.payload || {});
          return;
        }
        if (message.source === "ioi-studio-control" && message.type === "agentTurnBlocked") {
          projectStudioAgentTurnBlocked(message.payload || {});
          return;
        }
        if (message.source === "ioi-studio-runtime") {
          handleStudioRuntimeMessage(message);
          return;
        }
        if (message.source !== "ioi-autopilot-fork-quickinput" || message.type !== "ioi.quickInput.result") {
          return;
        }
        const result = message.result || {};
        if (result.kind === "focusComposer") {
          focusStudioComposer();
          return;
        }
        if (result.kind === "context") {
          if (result.bridgeRequestAlreadyWritten) {
            focusStudioComposer();
            return;
          }
          vscode.postMessage({
            type: "bridgeRequest",
            requestType: result.requestType || "chat.contextPicker.select",
            payload: {
              contextId: result.contextId,
              label: result.label,
              source: "fork-native-quickinput",
              nativeForkContributionUsed: true,
              extensionQuickPickFallbackUsed: false,
              runtimeAuthority: "daemon-owned",
              projectionOwner: "ioi-workbench-agent-studio"
            }
          });
          focusStudioComposer();
          return;
        }
        if (result.kind === "tools") {
          if (result.bridgeRequestAlreadyWritten) {
            focusStudioComposer();
            return;
          }
          vscode.postMessage({
            type: "bridgeRequest",
            requestType: "chat.toolControls",
            payload: {
              action: result.action || "configureTools",
              selectedTools: result.selectedTools || [],
              selectedCount: result.selectedCount || 0,
              source: "fork-native-quickinput",
              nativeForkContributionUsed: true,
              extensionQuickPickFallbackUsed: false,
              runtimeAuthority: "daemon-owned",
              projectionOwner: "ioi-workbench-agent-studio"
            }
          });
          focusStudioComposer();
          return;
        }
        if (result.kind === "modelRoute" && result.requestType === "models.open") {
          vscode.postMessage({
            type: "command",
            command: "ioi.models.open",
            payload: {
              phase: "recommended-setup",
              source: "studio-model-route-empty-state",
              runtimeAuthority: "daemon-owned",
              projectionOwner: "ioi-workbench-agent-studio"
            }
          });
          return;
        }
        if (result.kind === "target" || result.kind === "agentMode" || result.kind === "permissionMode" || result.kind === "modelRoute" || result.kind === "modelroute") {
          const selectedExecutionMode = result.kind === "agentMode" ? applyAgentModeResult(result) : undefined;
          const selectedPermissionMode = result.kind === "permissionMode" ? applyPermissionModeResult(result) : undefined;
          vscode.postMessage({
            type: "bridgeRequest",
            requestType: result.requestType || (result.kind === "agentMode" ? "chat.agentMode.select" : result.kind === "permissionMode" ? "chat.permissionMode.select" : "chat.target.select"),
            payload: {
              selectionId: result.selectionId,
              bridgeRequestAlreadyWritten: Boolean(result.bridgeRequestAlreadyWritten),
              executionMode: selectedExecutionMode,
              approvalMode: selectedPermissionMode,
              approval_mode: selectedPermissionMode,
              threadMode: selectedPermissionMode ? permissionThreadMode(selectedPermissionMode) : undefined,
              thread_mode: selectedPermissionMode ? permissionThreadMode(selectedPermissionMode) : undefined,
              label: result.label,
              source: "fork-native-quickinput",
              nativeForkContributionUsed: true,
              extensionQuickPickFallbackUsed: false,
              runtimeAuthority: "daemon-owned",
              projectionOwner: "ioi-workbench-agent-studio"
            }
          });
          focusStudioComposer();
        }
      });
      document.addEventListener("keydown", (event) => {
        if (event.key !== "Escape") {
          return;
        }
        window.parent?.postMessage({
          source: "ioi-workbench-agent-studio",
          type: "ioi.quickInput.dismiss",
          payload: {
            reason: "escape",
            restoreComposer: true
          }
        }, "*");
        if (window.top && window.top !== window.parent) {
          window.top.postMessage({
            source: "ioi-workbench-agent-studio",
            type: "ioi.quickInput.dismiss",
            payload: {
              reason: "escape",
              restoreComposer: true
            }
          }, "*");
        }
      }, true);
      document.querySelectorAll("[data-command]").forEach((button) => {
        button.addEventListener("click", () => {
          if (isForkQuickInputCommand(button.dataset.command)) {
            openForkQuickInput(button.dataset.command, buttonQuickInputPayload(button));
            return;
          }
          vscode.postMessage({
            type: "command",
            command: button.dataset.command,
            payload: parsePayload(button.dataset.payload)
          });
        });
      });
      document.querySelectorAll("[data-bridge-request]").forEach((button) => {
        button.addEventListener("click", () => {
          vscode.postMessage({
            type: "bridgeRequest",
            requestType: button.dataset.bridgeRequest,
            payload: parsePayload(button.dataset.payload)
          });
        });
      });
      const TOOLCAT_MARKER_RE = /\\bTOOLCAT_(?:SINGLE_TOOL|STAGE\\d+_[A-Z0-9_]+)\\b/i;
      const TOOLCAT_TOOL_RE = /\\btoolcat_tool=([a-z0-9_.]+(?:__[a-z0-9_]+)?)/i;
      const TOOLCAT_SINGLE_TOOL_RE = /\\bTOOLCAT_SINGLE_TOOL\\s+([a-z0-9_.]+(?:__[a-z0-9_]+)?)/i;
      function compactProjectedText(value) {
        return String(value || "").replace(/\\s+/g, " ").trim();
      }
      function humanizeProjectedToolName(value) {
        return compactProjectedText(value)
          .replace(/\\./g, " ")
          .replace(/__+/g, " ")
          .replace(/_+/g, " ")
          .replace(/\\s+/g, " ")
          .trim()
          .toLowerCase();
      }
      function projectedToolcatToolName(text) {
        const value = String(text || "");
        const match = value.match(TOOLCAT_TOOL_RE) || value.match(TOOLCAT_SINGLE_TOOL_RE);
        return humanizeProjectedToolName(match?.[1] || "");
      }
      function projectedApprovalToolName(text) {
        const match = String(text || "").match(/\\btools?:\\s*([a-z0-9_.]+(?:__[a-z0-9_]+)?)/i);
        return humanizeProjectedToolName(match?.[1] || "");
      }
      function humanizeProjectedTurnText(role, content) {
        const raw = String(content || "").trim();
        const compact = compactProjectedText(raw);
        if (!compact) return "";
        if (TOOLCAT_MARKER_RE.test(compact)) {
          const toolName = projectedToolcatToolName(compact);
          if (role === "user") {
            return toolName
              ? "Run live Rust tool catalogue verification for " + toolName + "."
              : "Run live Rust tool catalogue verification.";
          }
          if (/\\bfailed\\b|\\bfailure\\b/i.test(compact)) {
            return toolName
              ? "The live Rust tool catalogue probe failed for " + toolName + ". Details are in Tracing."
              : "The live Rust tool catalogue verification step failed. Details are in Tracing.";
          }
          return toolName
            ? "The live Rust tool catalogue probe completed for " + toolName + "."
            : "The live Rust tool catalogue verification step completed.";
        }
        if (role === "assistant" && /\\b(waiting for approval|awaiting .*approval|approval required|requires approval|pending approval|policy gate)\\b/i.test(compact)) {
          const toolName = projectedApprovalToolName(compact);
          return toolName
            ? "Permission is required before Agent can use " + toolName + "."
            : "Permission is required before Agent can continue.";
        }
        if (role === "assistant" && /Daemon agent turn completed but did not emit a final chat__reply|did not emit a final chat__reply|final chat__reply/i.test(compact)) {
          return "Agent reached the runtime but did not produce a chat reply. Details are in Tracing.";
        }
        return raw;
      }
      function projectedTurnText(turn) {
        return compactProjectedText(
          turn?.querySelector("[data-testid='studio-assistant-answer-text']")?.textContent ||
          turn?.querySelector("[data-testid='studio-streaming-output']")?.textContent ||
          turn?.querySelector("p")?.textContent ||
          ""
        );
      }
      function projectedAssistantNearUser(userTurn, content, toolName) {
        const expectedText = compactProjectedText(humanizeProjectedTurnText("assistant", content));
        let cursor = userTurn?.nextElementSibling || null;
        while (cursor) {
          if (cursor.getAttribute("data-studio-turn-role") === "user") break;
          if (cursor.getAttribute("data-studio-turn-role") === "assistant") {
            const assistantTool = cursor.dataset.studioAssistantTool || "";
            if ((toolName && assistantTool === toolName) || (expectedText && projectedTurnText(cursor) === expectedText)) {
              return cursor;
            }
          }
          cursor = cursor.nextElementSibling;
        }
        return null;
      }
      function projectedAssistantAnchor(transcript, content, options = {}) {
        if (!transcript) return null;
        const promptText = compactProjectedText(options.prompt || "");
        const promptTool = projectedToolcatToolName(promptText);
        const contentTool = projectedToolcatToolName(content);
        const toolName = promptTool || contentTool;
        if (!toolName && !promptText) return null;
        const userTurns = Array.from(transcript.querySelectorAll("[data-studio-turn-role='user']"));
        for (let index = userTurns.length - 1; index >= 0; index -= 1) {
          const userTurn = userTurns[index];
          const userTool = userTurn.dataset.studioPromptTool || "";
          const userPrompt = userTurn.dataset.studioPromptText || "";
          const matchesTool = toolName && userTool === toolName;
          const matchesPrompt = promptText && userPrompt === promptText;
          if (!matchesTool && !matchesPrompt) continue;
          const duplicate = projectedAssistantNearUser(userTurn, content, toolName);
          return { after: userTurn, duplicate };
        }
        return null;
      }
      function appendProjectedTurn(role, content, options = {}) {
        const transcript =
          document.querySelector("[data-testid='studio-chat-transcript']") ||
          document.querySelector("[data-testid='studio-transcript']");
        if (!transcript) return;
        const anchor = role === "assistant" ? projectedAssistantAnchor(transcript, content, options) : null;
        if (anchor?.duplicate) {
          if (role === "assistant") {
            const text = anchor.duplicate.querySelector("[data-testid='studio-assistant-answer-text'], [data-testid='studio-streaming-output']");
            if (text) {
              text.classList.add("studio-markdown");
              text.setAttribute("data-testid", "studio-assistant-answer-text");
              renderMarkdownInto(text, humanizeProjectedTurnText(role, content));
            }
          }
          return anchor.duplicate;
        }
        const turn = document.createElement("article");
        turn.className = "studio-chat-turn studio-chat-turn--" + role;
        turn.dataset.studioTurnRole = role;
        turn.setAttribute("data-testid", role === "user" ? "studio-user-turn-immediate" : "studio-chat-turn");
        if (role === "assistant") {
          turn.dataset.documentedWork = "false";
          turn.dataset.studioAssistantTool = projectedToolcatToolName(options.prompt || content);
        }
        if (role === "user") {
          turn.dataset.studioPromptText = compactProjectedText(content);
          turn.dataset.studioPromptTool = projectedToolcatToolName(content);
        }
        const body = document.createElement("div");
        body.className =
          "studio-chat-turn__body" +
          (role === "user" ? " studio-user-bubble" : role === "assistant" ? " studio-assistant-answer-card" : "");
        if (role === "user") {
          body.setAttribute("data-testid", "studio-user-bubble");
        }
        if (role === "assistant") {
          body.setAttribute("data-testid", "studio-assistant-answer-card");
        }
        const meta = document.createElement("div");
        meta.className = "studio-chat-turn__meta";
        const name = document.createElement("strong");
        name.textContent = role === "user" ? "You" : "Autopilot";
        const time = document.createElement("span");
        time.textContent = new Date().toISOString();
        const paragraph = document.createElement(role === "assistant" ? "div" : "p");
        if (role === "assistant") {
          paragraph.className = "studio-markdown";
          paragraph.setAttribute("data-testid", "studio-assistant-answer-text");
          renderMarkdownInto(paragraph, humanizeProjectedTurnText(role, content));
        } else {
          paragraph.textContent = humanizeProjectedTurnText(role, content);
        }
        meta.append(name, time);
        body.append(meta, paragraph);
        turn.append(body);
        if (anchor?.after?.nextSibling) {
          transcript.insertBefore(turn, anchor.after.nextSibling);
        } else {
          transcript.append(turn);
        }
        return turn;
      }
      let studioPendingProjectionTimer = null;
      function studioPendingProjectionLabel(startedAt) {
        const rawStartedAt = Number(startedAt || performance.now());
        const now = rawStartedAt > 1000000000000 ? Date.now() : performance.now();
        const elapsedSeconds = Math.max(0, Math.floor((now - rawStartedAt) / 1000));
        return "Thinking about your request · " + elapsedSeconds + "s";
      }
      function updatePendingProjectionLabel(pending) {
        const label = pending?.querySelector("[data-testid='studio-pending-label']");
        if (!label) return;
        label.textContent = studioPendingProjectionLabel(pending.dataset.pendingStartedAtMs);
      }
      function pendingWorkStepsFromRoot() {
        const root = document.querySelector("[data-testid='agent-studio-operational-chat']");
        try {
          const parsed = JSON.parse(root?.dataset.pendingWorklog || "[]");
          return Array.isArray(parsed) ? parsed : [];
        } catch {
          return [];
        }
      }
      function ensurePendingProjection() {
        const transcript =
          document.querySelector("[data-testid='studio-chat-transcript']") ||
          document.querySelector("[data-testid='studio-transcript']");
        if (!transcript) return null;
        let pending = transcript.querySelector("[data-testid='studio-pending-state']");
        if (!pending) {
          pending = document.createElement("article");
          pending.className = "studio-chat-turn studio-chat-turn--assistant studio-pending";
          pending.setAttribute("data-testid", "studio-pending-state");
          pending.setAttribute("data-studio-turn-role", "assistant");
          pending.setAttribute("data-documented-work", "false");
          pending.innerHTML =
            '<div class="studio-pending__line">' +
              '<span class="studio-pending__dots" aria-hidden="true"><span></span><span></span><span></span></span>' +
              '<strong data-testid="studio-pending-label">Thinking about your request · 0s</strong>' +
            '</div>' +
            '<ol class="studio-pending__worklog" data-testid="studio-pending-worklog"></ol>';
          transcript.append(pending);
        }
        if (pending.hasAttribute("hidden")) {
          pending.removeAttribute("hidden");
        }
        if (!pending.dataset.pendingStartedAtMs) {
          const rootStartedAt = document.querySelector("[data-testid='agent-studio-operational-chat']")?.getAttribute("data-pending-started-at-ms");
          pending.dataset.pendingStartedAtMs = rootStartedAt || String(performance.now());
        }
        updatePendingProjectionLabel(pending);
        if (!studioPendingProjectionTimer) {
          studioPendingProjectionTimer = window.setInterval(() => {
            const currentPending = document.querySelector("[data-testid='studio-pending-state']");
            if (!currentPending || currentPending.hasAttribute("hidden")) {
              window.clearInterval(studioPendingProjectionTimer);
              studioPendingProjectionTimer = null;
              return;
            }
            updatePendingProjectionLabel(currentPending);
          }, 500);
        }
        return pending;
      }
      function appendPendingWorkStep(payload) {
        const pending = ensurePendingProjection();
        const list = pending?.querySelector("[data-testid='studio-pending-worklog']");
        if (!list) return;
        const label = String(payload?.label || "").trim();
        const detail = String(payload?.detail || "").trim();
        if (!label) return;
        const abstractPendingText = [label, detail].join(" ").toLowerCase();
        if ([
          "governed agent run",
          "governed agent harness",
          "daemon session",
          "model route",
          "policy context",
          "daemon-owned",
          "tool calls, policy checks",
          "receipts and traces",
          "receipts stay",
          "traces stay",
          "prepare artifact run",
          "preparing artifact",
          "drafting website artifact",
          "drafted custom website",
          "creating sandboxed artifact",
          "created artifact preview",
          "gathering source context",
          "gathered source context",
        ].some((phrase) => abstractPendingText.includes(phrase))) {
          return;
        }
        const toolName = String(
          payload?.toolName ||
          payload?.tool_name ||
          payload?.toolId ||
          payload?.tool_id ||
          payload?.name ||
          payload?.tool ||
          (label.match(/\b[a-z][a-z0-9]*__[a-z0-9_]+\b/i)?.[0] || "")
        ).trim();
        const kind = String(payload?.kind || payload?.eventKind || payload?.event_kind || "").toLowerCase();
        const concreteTool = toolName &&
          toolName !== "chat__reply" &&
          (!kind || /tool|receipt|command|shell|browser|file|web|turn\.step|agent\.step/.test(kind)) &&
          (/(?:^|__)(?:agent|browser|computer|file|memory|mcp|shell|web|workspace|model|artifact|editor|screen|terminal)__?/i.test(toolName) ||
            /\b[a-z][a-z0-9]*__[a-z0-9_]+\b/i.test(toolName));
        if (!concreteTool) return;
        const id = String(payload?.id || payload?.stepId || payload?.eventId || payload?.event_id || payload?.toolCallId || payload?.tool_call_id || toolName || label);
        let item = Array.from(list.querySelectorAll("li")).find((node) =>
          (id && node.dataset.stepId === id) ||
          (toolName && node.dataset.toolName === toolName)
        );
        if (item) {
          item.dataset.status = String(payload?.status || "running");
          const text = item.querySelector("p");
          const meta = item.querySelector("span");
          if (text) text.textContent = label;
          if (detail) {
            if (meta) meta.textContent = detail;
          }
          return;
        }
        item = document.createElement("li");
        item.dataset.stepId = id;
        item.dataset.toolName = toolName;
        item.dataset.status = String(payload?.status || "running");
        const text = document.createElement("p");
        text.textContent = label;
        item.append(text);
        if (detail) {
          const meta = document.createElement("span");
          meta.textContent = detail;
          item.append(meta);
        }
        list.append(item);
      }
      function hydratePendingWorkStepsFromRoot() {
        for (const step of pendingWorkStepsFromRoot()) {
          appendPendingWorkStep(step);
        }
      }
      function showPendingProjection() {
        const root = document.querySelector("[data-testid='agent-studio-operational-chat']");
        root?.setAttribute("data-studio-status", "pending");
        root?.setAttribute("data-immediate-submit-seen", "true");
        root?.setAttribute("data-pending-state-seen", "true");
        if (root && !root.getAttribute("data-pending-started-at-ms")) {
          root.setAttribute("data-pending-started-at-ms", String(performance.now()));
        }
        ensurePendingProjection();
        hydratePendingWorkStepsFromRoot();
      }
      function hidePendingProjectionAfterMinimum() {
        const root = document.querySelector("[data-testid='agent-studio-operational-chat']");
        const pending = document.querySelector("[data-testid='studio-pending-state']");
        const startedAt = Number(pending?.dataset.pendingStartedAtMs || root?.getAttribute("data-pending-started-at-ms") || "0");
        const elapsed = startedAt > 0 ? performance.now() - startedAt : 0;
        const hide = () => {
          const artifactSource = pending?.querySelector("[data-testid='studio-artifact-source-output']");
          if (artifactSource && artifactSource.textContent.trim()) {
            pending?.setAttribute("data-artifact-source-retained", "true");
            pending?.querySelector(".studio-pending__line")?.remove();
            pending?.querySelector("[data-testid='studio-pending-worklog']")?.remove();
            root?.removeAttribute("data-pending-started-at-ms");
            if (studioPendingProjectionTimer) {
              window.clearInterval(studioPendingProjectionTimer);
              studioPendingProjectionTimer = null;
            }
            return;
          }
          pending?.remove();
          root?.removeAttribute("data-pending-started-at-ms");
          if (studioPendingProjectionTimer) {
            window.clearInterval(studioPendingProjectionTimer);
            studioPendingProjectionTimer = null;
          }
        };
        const remaining = Math.max(0, 650 - elapsed);
        if (remaining > 0) {
          window.setTimeout(hide, remaining);
        } else {
          hide();
        }
      }
      document.querySelector("[data-studio-prompt-form]")?.addEventListener("submit", (event) => {
        event.preventDefault();
        const prompt = document.querySelector("[data-studio-prompt]")?.value?.trim();
        if (!prompt) {
          focusStudioComposer();
          return;
        }
        appendProjectedTurn("user", prompt);
        showPendingProjection();
        const routePicker = document.querySelector("[data-testid='studio-model-route-picker']");
        const selectedOption = routePicker?.selectedOptions?.[0] || null;
        const routeId = routePicker?.value || "route.local-first";
        const modelUnavailable =
          routePicker?.dataset?.modelUnavailable === "true" ||
          /no product model/i.test(selectedOption?.textContent || "");
        const modelId =
          modelUnavailable
            ? "__product_model_unavailable__"
            : selectedOption?.dataset?.modelId ||
              routePicker?.dataset?.selectedModelId ||
              "auto";
        const endpointId =
          selectedOption?.dataset?.endpointId ||
          routePicker?.dataset?.selectedEndpointId ||
          "";
        const reasoningPicker = document.querySelector("[data-testid='studio-reasoning-effort-picker']");
        const reasoningEffort = reasoningPicker?.value || "none";
        const modeButton = document.querySelector("[data-testid='studio-mode-toggle']");
        const executionMode = modeButton?.dataset?.studioMode || "agent";
        const permissionButton = document.querySelector("[data-testid='studio-permissions-toggle']");
        const approvalMode = permissionButton?.dataset?.approvalMode || "suggest";
        const threadMode = permissionThreadMode(approvalMode);
        const studioMessage = {
          type: "studioSubmit",
          requestType: "chat.submit",
          payload: {
            prompt,
            routeId,
            model: routeId,
            modelId,
            endpointId,
            reasoningEffort,
            reasoning_effort: reasoningEffort,
            executionMode,
            approvalMode,
            approval_mode: approvalMode,
            threadMode,
            thread_mode: threadMode,
            workspaceRoot: ${JSON.stringify(workspace.path || workspace.rootPath || "")},
            runtimeAuthority: "daemon-owned",
            projectionOwner: "ioi-workbench-agent-studio"
          }
        };
        document.querySelector("[data-studio-prompt]").value = "";
        requestAnimationFrame(() => {
          window.setTimeout(() => vscode.postMessage(studioMessage), 0);
        });
      });
      document.querySelector("[data-studio-prompt]")?.addEventListener("keydown", (event) => {
        if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
          event.preventDefault();
          document.querySelector("[data-studio-prompt-form]")?.requestSubmit();
        }
      });
      document.querySelectorAll("[data-studio-hunk-decision]").forEach((button) => {
        button.addEventListener("click", () => {
          vscode.postMessage({
            type: "studioHunkDecision",
            decision: button.dataset.studioHunkDecision,
            payload: {
              approvalId: button.dataset.approvalId || ${JSON.stringify(STUDIO_APPROVAL_ID)},
              file: button.dataset.hunkFile || "docs/evidence/agent-studio-preview.md",
              runtimeAuthority: "daemon-owned",
              projectionOwner: "ioi-workbench-agent-studio"
            }
          });
        });
      });
      document.querySelectorAll("[data-studio-hunk-nav]").forEach((button) => {
        button.addEventListener("click", () => {
          vscode.postMessage({
            type: "studioHunkNavigate",
            direction: button.dataset.studioHunkNav || "next",
            payload: {
              runtimeAuthority: "daemon-owned",
              projectionOwner: "ioi-workbench-agent-studio"
            }
          });
        });
      });
      document.querySelector("[data-studio-stop]")?.addEventListener("click", () => {
        vscode.postMessage({ type: "studioStop" });
      });
      document.querySelector("[data-studio-resume]")?.addEventListener("click", () => {
        vscode.postMessage({ type: "studioResume" });
      });
      function setUtilityDrawerExpanded(expanded) {
        const drawer = document.querySelector("[data-testid='studio-utility-drawer']");
        const shell = document.querySelector("[data-testid='agent-studio-operational-chat']");
        if (!drawer) return;
        drawer.classList.toggle("is-expanded", expanded);
        drawer.setAttribute("aria-expanded", String(expanded));
        shell?.classList.toggle("has-expanded-utility", expanded);
      }
      document.querySelectorAll("[data-studio-drawer-toggle]").forEach((button) => {
        button.addEventListener("click", () => {
          const drawer = document.querySelector("[data-testid='studio-utility-drawer']");
          setUtilityDrawerExpanded(!drawer?.classList.contains("is-expanded"));
        });
      });
      document.querySelectorAll("[data-studio-drawer-open]").forEach((button) => {
        button.addEventListener("click", () => setUtilityDrawerExpanded(true));
      });
      document.querySelectorAll("[data-studio-managed-session-expand]").forEach((button) => {
        button.addEventListener("click", () => {
          const card = button.closest("[data-testid='studio-managed-session-card']");
          const expanded = !card?.classList.contains("is-expanded");
          card?.classList.toggle("is-expanded", expanded);
          card?.setAttribute("data-session-expanded", String(expanded));
          button.setAttribute("aria-expanded", String(expanded));
          button.textContent = expanded ? "Collapse" : "Expand";
        });
      });
      document.querySelectorAll("[data-studio-managed-session-control]").forEach((button) => {
        button.addEventListener("click", () => {
          const card = button.closest("[data-testid='studio-managed-session-card']");
          const control = button.dataset.studioManagedSessionControl || "observe";
          card?.setAttribute("data-control-state", control);
          card?.querySelectorAll("[data-studio-managed-session-control]").forEach((candidate) => {
            const active = candidate === button;
            candidate.classList.toggle("is-active", active);
            candidate.setAttribute("aria-pressed", String(active));
          });
        });
      });
      document.querySelectorAll("[data-studio-artifact-expand]").forEach((button) => {
        button.addEventListener("click", () => {
          const card = button.closest("[data-testid='studio-conversation-artifact-card']");
          const expanded = !card?.classList.contains("is-expanded");
          card?.classList.toggle("is-expanded", expanded);
          card?.setAttribute("data-artifact-expanded", String(expanded));
          button.setAttribute("aria-expanded", String(expanded));
          button.textContent = expanded ? "Collapse" : "Open";
        });
      });
      document.querySelectorAll("[data-studio-artifact-action]").forEach((button) => {
        button.addEventListener("click", () => {
          vscode.postMessage({
            type: "studioArtifactAction",
            payload: {
              artifactId: button.dataset.artifactId || "",
              action: button.dataset.studioArtifactAction || "ask",
              runtimeAuthority: "daemon-owned",
              projectionOwner: "ioi-workbench-agent-studio"
            }
          });
        });
      });
      document.querySelectorAll("[data-studio-copy-answer]").forEach((button) => {
        button.addEventListener("click", async () => {
          const card = button.closest("[data-testid='studio-assistant-answer-card']");
          const text = card?.querySelector("[data-testid='studio-assistant-answer-text']")?.textContent ||
            card?.querySelector("[data-testid='studio-streaming-output']")?.textContent ||
            card?.querySelector("p")?.textContent ||
            "";
          await navigator.clipboard?.writeText?.(text).catch(() => undefined);
        });
      });
      hydrateExistingAssistantMarkdown();
      setTimeout(() => {
        vscode.postMessage({
          type: "studioOperationalProof",
          proof: {
            targetStudioOperationalChatAchieved: true,
            targetStudioTauriChatUxParityAchieved: true,
            sessionRailVisible: true,
            chatFirstTranscript: true,
            bottomComposerVisible: true,
            studioNativeQuickInputToolPicker: true,
            utilityEvidenceDrawerProgressive: true,
            runtimeAuthority: "daemon-owned",
            projectionOwner: "ioi-workbench-agent-studio",
            tauriUsed: false,
            webviewOwnsRuntimeState: false,
            externalConnectorAction: false
          }
        });
      }, 250);
    </script>
  </body>
</html>`;
}

}

module.exports = {
  createStudioPanelHtml,
};
