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
      content="default-src 'none'; img-src data: https:; style-src 'nonce-${pageNonce}' 'unsafe-inline'; script-src 'nonce-${pageNonce}';"
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
      const studioWorkspaceRoot = ${JSON.stringify(workspace.path || workspace.rootPath || "")};
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
      function compactPublicText(value) {
        return String(value || "").replace(/\\s+/g, " ").trim();
      }
      function sanitizePublicToolText(value) {
        return compactPublicText(value)
          .replace(/\\bshell__start:[a-f0-9]{12,}\\b/gi, "<command>")
          .replace(/\\b(?:receipt|trace|request|turn|thread)_[a-z0-9:_-]{8,}\\b/gi, "<ref>")
          .replace(/ioi-session-stdin-[^\\s"']+/gi, "<stdin-bridge>")
          .replace(/\\/tmp\\/[^\\s"']+/gi, "<tmp>")
          .replace(/"command_id"\\s*:\\s*"[^"]+"/gi, "")
          .replace(/\\s+/g, " ")
          .trim();
      }
      function sanitizePublicOutputBlock(value, max) {
        return String(value || "")
          .replace(/\\bThe tool returned an? ["']?Invalid transaction["']? error with the specific policy reason:\\s*/gi, "The policy reason was: ")
          .replace(/\\ban? ["']?Invalid transaction["']? error\\b/gi, "a policy block")
          .replace(/\\ban policy block\\b/gi, "a policy block")
          .replace(/\\bInvalid transaction:\\s*/gi, "")
          .replace(/\\bBlocked by Policy:\\s*/gi, "Blocked by policy: ")
          .replace(/\\bshell__start:[a-f0-9]{12,}\\b/gi, "<command>")
          .replace(/\\b(?:receipt|trace|request|turn|thread)_[a-z0-9:_-]{8,}\\b/gi, "<ref>")
          .replace(/ioi-session-stdin-[^\\s"']+/gi, "<stdin-bridge>")
          .replace(/\\/tmp\\/[^\\s"']+/gi, "<tmp>")
          .replace(/\\/home\\/[^\\s"']+/gi, "<path>")
          .replace(/"command_id"\\s*:\\s*"[^"]+"/gi, "")
          .slice(0, Number(max) || 6000)
          .trim();
      }
      function sanitizePublicAssistantText(value) {
        return String(value || "")
          .replace(/\\bwas blocked by the governed file tool\\.\\s*The tool returned (?:the following )?(?:the )?error:\\s*/gi, "was blocked. The policy reason was: ")
          .replace(/\\bThe governed file (?:tool|write) returned (?:the following )?(?:the )?error:\\s*Blocked by policy:\\s*/gi, "The policy reason was: ")
          .replace(/\\bThe tool returned (?:the following )?(?:the )?error:\\s*\\x60*\\s*Blocked by policy:\\s*/gi, "The policy reason was: ")
          .replace(/\\x60+\\s*Blocked by policy:\\s*/gi, "Blocked by policy: ")
          .replace(/\\bThe policy reason was:\\s*Blocked by policy:\\s*/gi, "The policy reason was: ")
          .replace(/\\s*\\x60+(?=\\s|$)/g, "")
          .replace(/\\bThe tool returned an? ["']?Invalid transaction["']? error with the specific policy reason:\\s*/gi, "The policy reason was: ")
          .replace(/\\ban? ["']?Invalid transaction["']? error\\b/gi, "a policy block")
          .replace(/\\ban policy block\\b/gi, "a policy block")
          .replace(/\\bInvalid transaction:\\s*/gi, "")
          .replace(/\\bBlocked by Policy:\\s*/gi, "Blocked by policy: ")
          .replace(/\\bERROR_CLASS=[a-z0-9_:-]+\\b/gi, "policy block")
          .replace(/\\x60?\\bfile__write\\b\\x60?/gi, "the governed file write")
          .replace(/\\x60?\\bfile__read\\b\\x60?/gi, "the governed file read")
          .replace(/\\x60?\\bshell__run\\b\\x60?/gi, "the governed command runner")
          .replace(/\\x60?\\/tmp\\/(?:autopilot-agent-studio-|autopilot-|ioi-)[^\\s"'<>)\\]}]+\\x60?/gi, "the requested workspace path")
          .replace(/\\bshell__start:[a-f0-9]{12,}\\b/gi, "command")
          .replace(/"command_id"\\s*:\\s*"[^"]+"\\s*,?/gi, "")
          .replace(/"commandId"\\s*:\\s*"[^"]+"\\s*,?/gi, "")
          .replace(/\\b(?:receipt|trace|request|turn|thread)_[a-z0-9:_-]{8,}\\b/gi, "Tracing")
          .replace(/\\b(?:receipt|trace):\\/\\/[^\\s)\\]}]+/gi, "Tracing")
          .replace(/\\bworkspace_change:[^\\s)\\]}]+/gi, "workspace change")
          .replace(/[ \\t]+\\n/g, "\\n")
          .trim();
      }
      function publicWorkspacePath(value) {
        const raw = String(value || "").replace(/\\\\/g, "/").trim();
        const root = String(studioWorkspaceRoot || "").replace(/\\\\/g, "/").trim();
        if (!raw) return "workspace";
        if (root && raw.startsWith(root + "/")) {
          return raw.slice(root.length + 1) || "workspace";
        }
        if (/^\\/tmp\\//.test(raw)) {
          return "workspace file";
        }
        return sanitizePublicToolText(raw).replace(/^\\.\\//, "") || "workspace";
      }
      function firstProjectedArray(value) {
        return Array.isArray(value) ? value : [];
      }
      function projectedRecordValue(value) {
        return value && typeof value === "object" ? value : {};
      }
      function sourceDomainFromUrl(url) {
        try {
          return new URL(String(url || "")).hostname.replace(/^www\\./i, "");
        } catch {
          return "";
        }
      }
      function normalizeSourceChips(value) {
        const entries = Array.isArray(value) ? value : [];
        const seen = new Set();
        const chips = [];
        for (const raw of entries) {
          if (!raw || typeof raw !== "object") continue;
          const url = compactPublicText(raw.url || raw.href || raw.link);
          const domain = compactPublicText(raw.domain || raw.hostname || sourceDomainFromUrl(url)).replace(/^www\\./i, "");
          const title = compactPublicText(raw.title || raw.name || raw.label || domain || url).slice(0, 96);
          const excerpt = compactPublicText(raw.excerpt || raw.snippet || raw.summary || "").slice(0, 220);
          const state = compactPublicText(raw.state || raw.status || raw.sourceState || "used").slice(0, 32);
          if (!title && !domain && !url) continue;
          const key = (url || domain || title).toLowerCase();
          if (seen.has(key)) continue;
          seen.add(key);
          chips.push({ url, domain, title, excerpt, state });
          if (chips.length >= 6) break;
        }
        return chips;
      }
      function studioSourceChipIconDataUri(source) {
        const domain = compactPublicText(source?.domain || "");
        const title = compactPublicText(source?.title || domain || "source");
        const seed = domain || title || "source";
        const glyph = escapeMarkdownHtml(seed.replace(/^www\\./i, "").slice(0, 1).toUpperCase() || "S");
        const hue = Array.from(seed).reduce((sum, char) => sum + char.charCodeAt(0), 0) % 360;
        const svg =
          '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 16 16">' +
          '<rect width="16" height="16" rx="4" fill="hsl(' + hue + ' 45% 30%)"/>' +
          '<text x="8" y="11" text-anchor="middle" font-family="system-ui, sans-serif" font-size="9" font-weight="700" fill="white">' +
          glyph +
          "</text></svg>";
        return "data:image/svg+xml;utf8," + encodeURIComponent(svg);
      }
      function studioSourceChipFaviconUrl(source) {
        const explicit = sanitizeMarkdownUrl(source?.faviconUrl || source?.favicon_url || source?.iconUrl || source?.icon_url || "");
        if (/^(?:https?:\\/\\/|data:image\\/)/i.test(explicit)) return explicit;
        const rawUrl = sanitizeMarkdownUrl(source?.url || source?.href || source?.link || "");
        let domain = compactPublicText(source?.domain || source?.hostname || "").replace(/^www\\./i, "");
        if (!domain && rawUrl) {
          try {
            domain = new URL(rawUrl).hostname.replace(/^www\\./i, "");
          } catch {
            domain = "";
          }
        }
        if (!domain && !rawUrl) return "";
        const domainUrl = rawUrl || "https://" + domain;
        return "https://www.google.com/s2/favicons?sz=32&domain_url=" + encodeURIComponent(domainUrl);
      }
      function studioProjectedSourceChipRows(sourceRefs, limit = 6) {
        return normalizeSourceChips(sourceRefs).slice(0, limit).map((source) => {
          const url = sanitizeMarkdownUrl(source.url);
          const label = source.title || source.domain || source.url;
          const title = [label, source.domain, source.excerpt].filter(Boolean).join(" - ");
          const iconUrl = studioSourceChipFaviconUrl(source) || studioSourceChipIconDataUri(source);
          const body =
            '<img src="' + escapeMarkdownHtml(iconUrl) + '" alt="" aria-hidden="true">' +
            '<span>' + escapeMarkdownHtml(String(label || "").slice(0, 96)) + "</span>" +
            (source.domain && source.domain !== label ? "<small>" + escapeMarkdownHtml(source.domain) + "</small>" : "") +
            (source.state ? "<em>" + escapeMarkdownHtml(source.state) + "</em>" : "");
          if (url && /^https?:\\/\\//i.test(url)) {
            return '<a class="studio-source-chip" href="' + escapeMarkdownHtml(url) + '" target="_blank" rel="noreferrer noopener" title="' + escapeMarkdownHtml(title) + '">' + body + "</a>";
          }
          return '<span class="studio-source-chip" title="' + escapeMarkdownHtml(title) + '">' + body + "</span>";
        }).join("");
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
        node.dataset.markdownHydrated = "true";
        node.innerHTML = renderMarkdownBlocks(source);
      }
      function studioProjectedSourceRows(sourceRefs) {
        const refs = normalizeSourceChips(sourceRefs);
        if (!refs.length) return "";
        return '<div class="studio-answer-sources" data-testid="studio-answer-sources" aria-label="Sources">' +
          '<span>Sources</span>' +
          '<div class="studio-source-chip-list">' + studioProjectedSourceChipRows(refs) + "</div>" +
          '</div>';
      }
      function syncProjectedSourceRows(turn, sourceRefs) {
        const body = turn?.querySelector?.("[data-testid='studio-assistant-answer-card']") || turn?.querySelector?.(".studio-chat-turn__body");
        if (!body) return;
        const existing = body.querySelector("[data-testid='studio-answer-sources']");
        const sourceRows = studioProjectedSourceRows(sourceRefs);
        if (sourceRows) {
          if (existing) {
            existing.outerHTML = sourceRows;
          } else {
            body.insertAdjacentHTML("beforeend", sourceRows);
          }
        } else if (existing) {
          existing.remove();
        }
      }
      function appendMarkdownDelta(node, delta) {
        if (!node) return;
        const nextRaw = String(node.dataset.rawMarkdownRaw || node.dataset.rawMarkdown || "") + String(delta || "");
        node.dataset.rawMarkdownRaw = nextRaw;
        renderMarkdownInto(node, sanitizePublicAssistantText(nextRaw));
      }
      function hydrateExistingAssistantMarkdown() {
        document.querySelectorAll("[data-testid='studio-assistant-answer-text'], [data-testid='studio-streaming-output']").forEach((node) => {
          const turn = node.closest("[data-studio-turn-role='assistant']");
          if (!turn || node.dataset.rawMarkdown !== undefined) return;
          node.classList.add("studio-markdown");
          renderMarkdownInto(node, sanitizePublicAssistantText(node.textContent || ""));
        });
      }
      function studioTranscriptNode() {
        return document.querySelector("[data-testid='studio-transcript']");
      }
      function shouldAutoScrollStudioTranscript(transcript) {
        if (!transcript) return false;
        const distanceFromBottom = transcript.scrollHeight - transcript.scrollTop - transcript.clientHeight;
        return distanceFromBottom < 180;
      }
      function scrollStudioTranscriptToLatest(target) {
        const transcript = studioTranscriptNode();
        if (!transcript || !shouldAutoScrollStudioTranscript(transcript)) return;
        window.requestAnimationFrame(() => {
          const node = target && typeof target.scrollIntoView === "function" ? target : null;
          if (node) {
            node.scrollIntoView({ block: "end", inline: "nearest" });
            return;
          }
          transcript.scrollTop = transcript.scrollHeight;
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
        const statusNode = runBar.querySelector("[data-studio-run-status-label]");
        if (strong) {
          const current = String(strong.textContent || "");
          if (!(label === "Worked" && current.startsWith("Worked for "))) {
            strong.textContent = label || (status === "completed" ? "Worked" : "Working...");
          }
        }
        if (statusNode) statusNode.textContent = status || "streaming";
      }
      function formatProjectedWorkDuration(durationMs) {
        const seconds = Math.max(0, Math.round(Number(durationMs || 0) / 1000));
        if (seconds <= 0) return "<1s";
        if (seconds < 60) return String(seconds) + "s";
        const minutes = Math.floor(seconds / 60);
        const remaining = seconds % 60;
        return remaining ? String(minutes) + "m " + String(remaining) + "s" : String(minutes) + "m";
      }
      function normalizeProjectedWorkRows(workRecord) {
        const record = workRecord && typeof workRecord === "object" ? workRecord : {};
        const hasRicherWorkRows = (
          (Array.isArray(record.commandOutputs) && record.commandOutputs.length) ||
          (Array.isArray(record.diffHunks) && record.diffHunks.length) ||
          (Array.isArray(record.sessionCards) && record.sessionCards.length) ||
          (Array.isArray(record.artifactCards) && record.artifactCards.length)
        );
        const rows = Array.isArray(record.workRows) && record.workRows.length
          ? record.workRows
          : (!hasRicherWorkRows && Array.isArray(record.lines) ? record.lines.map((line) => ({ headline: line, status: "completed" })) : []);
        return rows.map((row) => {
          const source = row && typeof row === "object" ? row : { headline: row };
          const headline = compactPublicText(source.headline || source.label || "");
          if (!headline) return null;
          return {
            kind: compactPublicText(source.kind || "tool").slice(0, 48),
            status: compactPublicText(source.status || "completed").slice(0, 32),
            headline: headline.slice(0, 160),
            summary: compactPublicText(source.summary || source.detail || "").slice(0, 220),
            excerptPreview: compactPublicText(source.excerptPreview || source.excerpt_preview || "").slice(0, 280),
            sourceChips: Array.isArray(source.sourceChips || source.source_chips) ? (source.sourceChips || source.source_chips) : [],
          };
        }).filter(Boolean).slice(0, 12);
      }
      function publicWorkRowText(value) {
        return compactPublicText(value || "")
          .replace(/\\b(Patched|Edited|Read)\\s+<tmp>(?=$|\\s|[.,;:])/gi, "$1 workspace file")
          .replace(/<tmp>/g, "workspace file")
          .trim();
      }
      function projectedWorkRowsHtml(workRecord) {
        return normalizeProjectedWorkRows(workRecord).map((row) =>
          '<li class="studio-work-row" data-status="' + escapeMarkdownHtml(row.status) + '" data-kind="' + escapeMarkdownHtml(row.kind) + '">' +
            '<div class="studio-work-row__main">' +
              '<strong>' + escapeMarkdownHtml(publicWorkRowText(row.headline)) + "</strong>" +
              (row.summary ? "<span>" + escapeMarkdownHtml(publicWorkRowText(row.summary)) + "</span>" : "") +
            "</div>" +
            (normalizeSourceChips(row.sourceChips).length
              ? '<div class="studio-source-chip-list">' + studioProjectedSourceChipRows(row.sourceChips, 6) + "</div>"
              : "") +
            (row.excerptPreview ? '<p class="studio-work-row__excerpt">' + escapeMarkdownHtml(publicWorkRowText(row.excerptPreview)) + "</p>" : "") +
          "</li>"
        ).join("");
      }
      function publicCommandLabel(source) {
        const toolId = compactPublicText(source.toolId || source.tool_id || "");
        const rawLabel = compactPublicText(source.label || source.command || toolId || "Command");
        const commandKind = publicCommandKindLabel(source.command || source.commandLabel || source.command_label || "");
        const commandVerb = publicCommandVerb(source, toolId);
        if (/^(?:shell|command)$/i.test(rawLabel)) {
          return commandKind
            ? commandVerb + " " + commandKind + " command"
            : (/running|started/i.test(String(source.status || "")) ? "Running command" : "Ran command");
        }
        if (/^[a-z][a-z0-9_]*__[a-z0-9_]+$/i.test(rawLabel) || rawLabel === toolId) {
          if (toolId === "shell__start") return commandKind ? commandVerb + " " + commandKind + " command" : (/running/i.test(String(source.status || "")) ? "Running command" : "Started command");
          if (toolId === "shell__run" || toolId === "terminal__run") return commandKind ? commandVerb + " " + commandKind + " command" : (/running|started/i.test(String(source.status || "")) ? "Running command" : "Ran command");
          if (toolId === "shell__status") return "Checked command status";
          if (toolId === "shell__input") return "Sent input to retained command";
          if (toolId === "shell__terminate") return "Terminated retained command";
          if (toolId === "shell__reset") return "Reset retained shell state";
          if (/^shell__|^terminal__/.test(toolId)) return "Ran command";
          return rawLabel.replace(/^browser__/, "browser ").replace(/^file__/, "file ").replace(/^agent__/, "agent ").replace(/__+/g, " ").replace(/[_./-]+/g, " ").replace(/\\s+/g, " ").trim();
        }
        return rawLabel;
      }
      function publicCommandVerb(source, toolId = "") {
        const status = String(source.status || "").toLowerCase();
        if (/failed|error/.test(status)) return "Failed";
        if (/running|started|pending/.test(status)) return "Running";
        if (toolId === "shell__start") return "Started";
        return "Ran";
      }
      function publicCommandKindLabel(value) {
        const text = compactPublicText(value);
        if (!text || /^(?:shell|command|running command|ran command|started command)$/i.test(text)) return "";
        const head = text.split(/\s+/)[0].split(/[\\/]/).pop().toLowerCase();
        if (!head) return "";
        if (head === "node" || head === "nodejs") return "Node.js";
        if (head === "python" || head === "python3") return "Python";
        if (["npm", "pnpm", "yarn", "bun", "cargo", "deno", "go", "rustc", "make"].includes(head)) return head;
        if (head === "bash" || head === "sh" || head === "zsh") return "shell";
        return "";
      }
      function publicCommandSurfaceLabel(source) {
        const toolId = compactPublicText(source.toolId || source.tool_id || "");
        const rawLabel = compactPublicText(source.label || source.command || "");
        if (/^shell__|^terminal__/.test(toolId) || /^(?:shell|command)$/i.test(rawLabel)) return "Shell";
        if (/^browser__/.test(toolId)) return "Browser";
        if (/^file__/.test(toolId)) return "File";
        return "";
      }
      function normalizeProjectedCommandOutputs(workRecord) {
        const commands = Array.isArray(workRecord?.commandOutputs) ? workRecord.commandOutputs : [];
        const recordSettled = /^(?:completed|blocked|failed|cancelled|canceled)$/i.test(compactPublicText(workRecord?.status || ""));
        const hasCommandOutput = commands.some((command) => {
          const source = command && typeof command === "object" ? command : {};
          return Boolean(compactPublicText(source.stdout || source.output || source.chunk || source.text || source.excerptPreview || source.excerpt_preview || source.stderr || ""));
        });
        const hasWorkRowOutput = Array.isArray(workRecord?.workRows) && workRecord.workRows.some((row) => {
          const source = row && typeof row === "object" ? row : {};
          return Boolean(compactPublicText(source.excerptPreview || source.excerpt_preview || ""));
        });
        return commands.map((command, index) => {
          const source = command && typeof command === "object" ? command : {};
          const rawStatus = compactPublicText(source.status || "completed").slice(0, 32);
          const hasOutput = Boolean(compactPublicText(source.stdout || source.output || source.chunk || source.text || source.excerptPreview || source.excerpt_preview || source.stderr || ""));
          const effectiveSource = {
            ...source,
            status: recordSettled && hasOutput && /^(?:running|started|pending)$/i.test(rawStatus)
              ? "completed"
              : rawStatus,
          };
          const label = publicCommandLabel(effectiveSource).slice(0, 160);
          if (!label) return null;
          return {
            id: compactPublicText(effectiveSource.id || effectiveSource.commandId || effectiveSource.command_id || "command." + index).slice(0, 96),
            toolId: compactPublicText(effectiveSource.toolId || effectiveSource.tool_id || "shell").slice(0, 96),
            label,
            surface: publicCommandSurfaceLabel(effectiveSource).slice(0, 48),
            status: effectiveSource.status,
            stdout: sanitizePublicOutputBlock(effectiveSource.stdout || effectiveSource.output || effectiveSource.chunk || effectiveSource.text || effectiveSource.excerptPreview || effectiveSource.excerpt_preview || ""),
            stderr: sanitizePublicOutputBlock(effectiveSource.stderr || ""),
            excerptPreview: sanitizePublicOutputBlock(effectiveSource.excerptPreview || effectiveSource.excerpt_preview || ""),
            exitCode: effectiveSource.exitCode ?? effectiveSource.exit_code,
            durationMs: effectiveSource.durationMs ?? effectiveSource.duration_ms,
          };
        }).filter(Boolean).filter((command) => {
          const status = compactPublicText(command.status || "");
          const emptyOutput = !compactPublicText(
            command.stdout ||
            command.output ||
            command.chunk ||
            command.text ||
            command.excerptPreview ||
            command.excerpt_preview ||
            ""
          ) && !compactPublicText(command.stderr || "");
          if (recordSettled && emptyOutput && /^(?:running|started|pending)$/i.test(status)) return false;
          if (recordSettled && (hasCommandOutput || hasWorkRowOutput) && emptyOutput && /^(?:completed|succeeded|success)$/i.test(status)) return false;
          return true;
        }).slice(-4);
      }
      function projectedCommandOutputRowsHtml(workRecord) {
        return normalizeProjectedCommandOutputs(workRecord).map((command, index) => {
          const durationMs = Number(command.durationMs);
          const duration = Number.isFinite(durationMs) ? formatProjectedWorkDuration(durationMs) : "";
          const meta = [command.status, command.exitCode !== undefined && command.exitCode !== null ? "exit " + command.exitCode : "", duration].filter(Boolean).join(" · ");
          return '<details class="studio-command-work-row" data-testid="studio-command-output-row"' + (index === 0 ? " open" : "") + ">" +
            "<summary><strong>" + escapeMarkdownHtml(command.label || "Ran command") + "</strong>" +
              (command.surface ? "<span>" + escapeMarkdownHtml(command.surface) + "</span>" : "") +
              (meta ? "<em>" + escapeMarkdownHtml(meta) + "</em>" : "") +
            "</summary>" +
            '<pre data-testid="studio-command-stdout">' + escapeMarkdownHtml(command.stdout || "No output") + "</pre>" +
            (command.stderr ? '<pre class="studio-command-stderr" data-testid="studio-command-stderr">' + escapeMarkdownHtml(command.stderr) + "</pre>" : "") +
          "</details>";
        }).join("");
      }
      function normalizeProjectedDiffHunks(workRecord) {
        const hunks = Array.isArray(workRecord?.diffHunks) ? workRecord.diffHunks : [];
        return hunks.map((hunk, index) => {
          const source = hunk && typeof hunk === "object" ? hunk : {};
          return {
            title: compactPublicText(source.title || "Hunk " + (index + 1)).slice(0, 120),
            file: publicWorkspacePath(source.file || source.path || "workspace").slice(0, 180),
            status: compactPublicText(source.status || "pending").slice(0, 32),
            before: sanitizePublicOutputBlock(source.before || source.search || "", 4000),
            after: sanitizePublicOutputBlock(source.after || source.replace || "", 4000),
            stale: Boolean(source.stale),
            staleReason: compactPublicText(source.staleReason || source.stale_reason || "").slice(0, 160),
            acceptAvailable: source.acceptAvailable ?? source.accept_available ?? true,
            rejectAvailable: source.rejectAvailable ?? source.reject_available ?? true,
            rollbackAvailable: source.rollbackAvailable ?? source.rollback_available ?? false,
            approvalId: compactPublicText(source.approvalId || source.approval_id || "").slice(0, 160),
            changeId: compactPublicText(source.changeId || source.change_id || "").slice(0, 160),
            hunkIndex: Number.isFinite(Number(source.hunkIndex ?? source.hunk_index)) ? Number(source.hunkIndex ?? source.hunk_index) : index,
          };
        }).filter(Boolean).slice(-6);
      }
      function projectedDiffHunksHtml(workRecord) {
        return normalizeProjectedDiffHunks(workRecord).map((hunk) =>
          '<article class="studio-diff-hunk" data-testid="studio-inline-diff-hunks" data-native-diff-hunk="true">' +
            "<header><strong>" + escapeMarkdownHtml(hunk.title) + "</strong><code>" + escapeMarkdownHtml(hunk.file || "workspace") + "</code><mark>" + escapeMarkdownHtml(hunk.status) + "</mark></header>" +
            (hunk.stale && hunk.staleReason ? '<p class="studio-diff-hunk__stale">Stale: ' + escapeMarkdownHtml(hunk.staleReason) + "</p>" : "") +
            '<pre data-testid="studio-native-diff-hunk"><span class="studio-diff-remove">' + escapeMarkdownHtml(hunk.before || "") + '</span>\\n<span class="studio-diff-add">' + escapeMarkdownHtml(hunk.after || "") + "</span></pre>" +
            '<footer data-testid="studio-hunk-accept-reject">' +
              '<button type="button" data-testid="studio-hunk-prev" data-studio-hunk-nav="previous">Previous</button>' +
              '<button type="button" data-testid="studio-hunk-next" data-studio-hunk-nav="next">Next</button>' +
              (hunk.acceptAvailable ? '<button type="button" data-testid="studio-hunk-accept" data-studio-hunk-decision="approve" data-approval-id="' + escapeMarkdownHtml(hunk.approvalId || "") + '" data-hunk-file="' + escapeMarkdownHtml(hunk.file || "workspace") + '" data-change-id="' + escapeMarkdownHtml(hunk.changeId || "") + '" data-hunk-index="' + escapeMarkdownHtml(String(hunk.hunkIndex)) + '">Accept hunk</button>' : "") +
              (hunk.rejectAvailable ? '<button type="button" data-testid="studio-hunk-reject" data-studio-hunk-decision="reject" data-approval-id="' + escapeMarkdownHtml(hunk.approvalId || "") + '" data-hunk-file="' + escapeMarkdownHtml(hunk.file || "workspace") + '" data-change-id="' + escapeMarkdownHtml(hunk.changeId || "") + '" data-hunk-index="' + escapeMarkdownHtml(String(hunk.hunkIndex)) + '">Reject hunk</button>' : "") +
              (hunk.rollbackAvailable ? '<button type="button" data-testid="studio-hunk-rollback" data-studio-hunk-decision="rollback" data-approval-id="' + escapeMarkdownHtml(hunk.approvalId || "") + '" data-hunk-file="' + escapeMarkdownHtml(hunk.file || "workspace") + '" data-change-id="' + escapeMarkdownHtml(hunk.changeId || "") + '" data-hunk-index="' + escapeMarkdownHtml(String(hunk.hunkIndex)) + '">Roll back hunk</button>' : "") +
            "</footer>" +
          "</article>"
        ).join("");
      }
      function postStudioHunkDecision(button) {
        if (!button) return;
        document.body.dataset.studioHunkDecisionObserved = "true";
        document.body.dataset.studioHunkDecisionLast = button.dataset.studioHunkDecision || "";
        vscode.postMessage({
          type: "studioHunkDecision",
          decision: button.dataset.studioHunkDecision,
          payload: {
            approvalId: button.dataset.approvalId || ${JSON.stringify(STUDIO_APPROVAL_ID)},
            file: button.dataset.hunkFile || "workspace",
            changeId: button.dataset.changeId || "",
            hunkIndex: button.dataset.hunkIndex || "",
            runtimeAuthority: "daemon-owned",
            projectionOwner: "ioi-workbench-agent-studio"
          }
        });
      }
      function bindStudioHunkControls(root) {
        const scope = root || document;
        let boundCount = 0;
        scope.querySelectorAll("[data-studio-hunk-decision]").forEach((button) => {
          if (button.dataset.studioHunkDecisionBound !== "true") {
            button.dataset.studioHunkDecisionBound = "true";
            button.addEventListener("click", (event) => {
              event.preventDefault();
              postStudioHunkDecision(button);
            });
          }
          boundCount += 1;
        });
        document.body.dataset.studioHunkDecisionBoundCount = String(boundCount);
      }
      function normalizeProjectedSessionCards(workRecord) {
        const cards = Array.isArray(workRecord?.sessionCards) ? workRecord.sessionCards : [];
        return cards.map((session) => {
          const source = session && typeof session === "object" ? session : {};
          const surfaceLabel = compactPublicText(source.surfaceLabel || source.surface_label || "Sandbox browser").slice(0, 80);
          const statusLabel = compactPublicText(source.statusLabel || source.status_label || "Complete").slice(0, 80);
          const title = compactPublicText(source.title || "Browser session").slice(0, 120);
          const detail = compactPublicText(source.detail || source.summary || "Managed browser session").slice(0, 240);
          const status = compactPublicText(source.status || "complete").slice(0, 48);
          const controlState = compactPublicText(source.controlState || source.control_state || "observe").slice(0, 48);
          return {
            id: compactPublicText(source.id || source.sessionId || source.session_id || source.managedSessionId || source.managed_session_id || title || "managed-session").slice(0, 120),
            kind: compactPublicText(source.kind || "sandbox_browser").slice(0, 48),
            surfaceLabel,
            status,
            statusLabel,
            controlState,
            title,
            detail,
            pageTitle: compactPublicText(source.pageTitle || source.page_title || "").slice(0, 120),
            target: compactPublicText(source.target || source.url || "").slice(0, 160),
            lastTool: compactPublicText(source.lastTool || source.last_tool || "browser").slice(0, 80),
            waitingForUser: Boolean(source.waitingForUser || source.waiting_for_user),
            waitingReason: compactPublicText(source.waitingReason || source.waiting_reason || "").slice(0, 80),
            replayReady: Boolean(source.replayReady || source.replay_ready),
          };
        }).filter((session) => session.id || session.title || session.detail).slice(-3);
      }
      function projectedManagedSessionRowsHtml(workRecord) {
        const sessions = normalizeProjectedSessionCards(workRecord);
        if (!sessions.length) return "";
        return '<section class="studio-managed-sessions" data-testid="studio-managed-sessions" aria-label="Browser and computer sessions">' +
          sessions.map((session) => {
            const labels = [
              ["sandbox_browser", "Sandbox browser"],
              ["local_browser", "Local browser"],
              ["desktop", "Desktop"]
            ].map(([kind, label]) =>
              '<span data-testid="studio-managed-session-mode-label" data-session-mode-label="' + escapeMarkdownHtml(kind) + '" class="' + (kind === session.kind ? "is-active" : "") + '">' + escapeMarkdownHtml(label) + "</span>"
            ).join("");
            return '<section class="studio-managed-session-card studio-managed-session-card--' + escapeMarkdownHtml(session.kind) + '" data-testid="studio-managed-session-card" data-session-id="' + escapeMarkdownHtml(session.id) + '" data-session-kind="' + escapeMarkdownHtml(session.kind) + '" data-session-label="' + escapeMarkdownHtml(session.surfaceLabel) + '" data-session-status="' + escapeMarkdownHtml(session.statusLabel) + '" data-control-state="' + escapeMarkdownHtml(session.controlState) + '">' +
              '<header class="studio-managed-session-card__header">' +
                "<div><strong>" + escapeMarkdownHtml(session.surfaceLabel) + "</strong><span>" + escapeMarkdownHtml(session.statusLabel) + "</span></div>" +
                '<button type="button" data-testid="studio-managed-session-expand" data-studio-managed-session-expand aria-expanded="false">Expand</button>' +
              "</header>" +
              '<div class="studio-managed-session-preview" data-testid="studio-managed-session-compact-preview">' +
                '<div class="studio-managed-session-preview__chrome" aria-hidden="true"><span></span><span></span><span></span></div>' +
                '<div class="studio-managed-session-preview__body">' +
                  "<strong>" + escapeMarkdownHtml(session.pageTitle || session.title) + "</strong>" +
                  "<span>" + escapeMarkdownHtml(session.detail || session.target || "Managed browser session") + "</span>" +
                  (session.waitingForUser ? '<mark data-testid="studio-managed-session-waiting">Waiting for user' + (session.waitingReason ? ": " + escapeMarkdownHtml(session.waitingReason) : "") + "</mark>" : "") +
                "</div>" +
              "</div>" +
              '<div class="studio-managed-session-expanded" data-testid="studio-managed-session-expanded-view">' +
                '<div class="studio-managed-session-mode-labels" data-testid="studio-managed-session-mode-labels">' + labels + "</div>" +
                "<p>" + escapeMarkdownHtml(session.detail || "Agent-controlled sandbox session ready for observation.") + "</p>" +
                '<div class="studio-managed-session-controls" data-testid="studio-managed-session-controls">' +
                  '<button type="button" data-testid="studio-managed-session-observe" data-studio-managed-session-control="observe" aria-pressed="' + String(session.controlState === "observe") + '" class="' + (session.controlState === "observe" ? "is-active" : "") + '">Observe</button>' +
                  '<button type="button" data-testid="studio-managed-session-take-over" data-studio-managed-session-control="take_over" aria-pressed="' + String(session.controlState === "take_over") + '" class="' + (session.controlState === "take_over" ? "is-active" : "") + '">Take over</button>' +
                  '<button type="button" data-testid="studio-managed-session-return" data-studio-managed-session-control="return_agent" aria-pressed="' + String(session.controlState === "return_agent") + '" class="' + (session.controlState === "return_agent" ? "is-active" : "") + '">Return control to Agent</button>' +
                "</div>" +
              "</div>" +
            "</section>";
          }).join("") +
        "</section>";
      }
      function projectedArtifactClassLabel(artifact = {}) {
        const value = compactPublicText(artifact.artifactClass || artifact.artifact_class || artifact.class || "artifact");
        if (value === "static_html_js") return /website|web\\s*site|webpage|landing\\s+page/i.test(
          String(artifact.outputModality || artifact.output_modality || artifact.title || artifact.summary || "")
        ) ? "Website" : "HTML report";
        if (value === "react_vite_app") return "App preview";
        if (value === "imported_document") return "Document";
        if (value === "pdf_preview") return "PDF";
        if (value === "diff_patch") return "Patch";
        if (value === "dataset_chart") return "Dataset";
        if (value === "browser_observation") return "Browser capture";
        return value.replace(/[_-]+/g, " ").replace(/\\s+/g, " ").trim().replace(/\\b[a-z]/g, (char) => char.toUpperCase());
      }
      function projectedArtifactPreviewLabel(artifact = {}) {
        const previewRefs = firstProjectedArray(artifact.previewRefs || artifact.preview_refs);
        if (!previewRefs.length) return "Preview pending";
        const mediaType = compactPublicText(previewRefs[0]?.mediaType || previewRefs[0]?.media_type || "preview");
        if (/html/i.test(mediaType)) return /website|web\\s*site|webpage|landing\\s+page/i.test(String(artifact.title || artifact.summary || "")) ? "Website preview" : "HTML preview";
        if (/pdf/i.test(mediaType)) return "PDF preview";
        if (/csv|json/i.test(mediaType)) return "Data preview";
        return "Preview ready";
      }
      function projectedArtifactInlinePreviewHtml(artifact = {}) {
        const inline = projectedRecordValue(artifact.previewInline || artifact.preview_inline);
        const text = String(inline.text || "");
        if (!text) return "";
        const mediaType = compactPublicText(inline.mediaType || inline.media_type || "");
        if (/html/i.test(mediaType)) {
          return '<iframe class="studio-conversation-artifact-frame" data-testid="studio-conversation-artifact-preview-frame" sandbox="allow-scripts" title="' +
            escapeMarkdownHtml(artifact.title || "Artifact preview") + '" srcdoc="' + escapeMarkdownHtml(text) + '"></iframe>';
        }
        return '<pre class="studio-conversation-artifact-source-preview" data-testid="studio-conversation-artifact-source-preview">' +
          escapeMarkdownHtml(text.slice(0, 6000)) + "</pre>";
      }
      function projectedArtifactPreviewShell(artifact = {}, expanded = false) {
        const inlinePreview = projectedArtifactInlinePreviewHtml(artifact);
        if (inlinePreview) {
          return '<div class="studio-conversation-artifact-preview studio-conversation-artifact-preview--' + (expanded ? "expanded" : "compact") + '" data-testid="studio-conversation-artifact-preview">' +
            inlinePreview +
          "</div>";
        }
        const stateLabel = compactPublicText(artifact.stateLabel || artifact.state_label || artifact.status || "Preview ready");
        return '<div class="studio-conversation-artifact-preview studio-conversation-artifact-preview--placeholder" data-testid="studio-conversation-artifact-preview">' +
          "<strong>" + escapeMarkdownHtml(projectedArtifactPreviewLabel(artifact)) + "</strong>" +
          "<span>" + escapeMarkdownHtml(stateLabel) + "</span>" +
        "</div>";
      }
      function normalizeProjectedArtifactCards(workRecord, extraArtifacts) {
        const cards = [
          ...firstProjectedArray(workRecord?.artifactCards),
          ...firstProjectedArray(extraArtifacts),
        ];
        const seen = new Set();
        return cards.map((artifact) => artifact && typeof artifact === "object" ? artifact : null)
          .filter(Boolean)
          .filter((artifact) => {
            const id = compactPublicText(artifact.id || artifact.artifactId || artifact.artifact_id || artifact.title || "");
            const key = id || JSON.stringify({ title: artifact.title, class: artifact.artifactClass || artifact.artifact_class }).slice(0, 120);
            if (seen.has(key)) return false;
            seen.add(key);
            return true;
          })
          .slice(-6);
      }
      function projectedConversationArtifactRowsHtml(workRecord, extraArtifacts) {
        const artifacts = normalizeProjectedArtifactCards(workRecord, extraArtifacts);
        if (!artifacts.length) return "";
        return '<section class="studio-conversation-artifacts" data-testid="studio-conversation-artifacts" aria-label="Conversation artifacts">' +
          artifacts.map((artifact) => {
            const artifactId = compactPublicText(artifact.id || artifact.artifactId || artifact.artifact_id || "artifact").slice(0, 160);
            const stateLabel = compactPublicText(artifact.stateLabel || artifact.state_label || artifact.status || "Preview ready");
            const actions = firstProjectedArray(artifact.actions).slice(0, 6);
            const revisionCount = firstProjectedArray(artifact.revisions).length || 1;
            const artifactClass = compactPublicText(artifact.artifactClass || artifact.artifact_class || "");
            return '<article class="studio-conversation-artifact-card" data-testid="studio-conversation-artifact-card" data-artifact-id="' + escapeMarkdownHtml(artifactId) + '" data-artifact-class="' + escapeMarkdownHtml(artifactClass) + '" data-artifact-status="' + escapeMarkdownHtml(artifact.status || "") + '" data-artifact-expanded="false">' +
              '<header class="studio-conversation-artifact-card__header">' +
                '<div><span data-testid="studio-conversation-artifact-type">' + escapeMarkdownHtml(projectedArtifactClassLabel(artifact)) + '</span>' +
                '<strong data-testid="studio-conversation-artifact-title">' + escapeMarkdownHtml(artifact.title || "Conversation artifact") + "</strong></div>" +
                '<button type="button" data-testid="studio-conversation-artifact-expand" data-studio-artifact-expand aria-expanded="false">Open</button>' +
              "</header>" +
              '<div class="studio-conversation-artifact-compact" data-testid="studio-conversation-artifact-compact">' +
                '<div class="studio-conversation-artifact-compact__status"><strong>' + escapeMarkdownHtml(stateLabel) + '</strong><span>' +
                  escapeMarkdownHtml(projectedArtifactPreviewLabel(artifact)) + " · " + escapeMarkdownHtml(String(revisionCount)) + " revision" + (revisionCount === 1 ? "" : "s") +
                "</span></div>" +
                projectedArtifactPreviewShell(artifact, false) +
              "</div>" +
              '<div class="studio-conversation-artifact-expanded" data-testid="studio-conversation-artifact-expanded-view">' +
                '<div class="studio-conversation-artifact-meta studio-visually-hidden" data-testid="studio-conversation-artifact-renderer-meta">' +
                  '<span>Renderer: ' + escapeMarkdownHtml(artifact.renderer?.label || artifact.renderer?.kind || "sandboxed preview") + '</span>' +
                  '<span>Sandbox: network denied · no ambient filesystem</span>' +
                "</div>" +
                projectedArtifactPreviewShell(artifact, true) +
                (/compare|document|diff|patch/i.test(String((artifact.status || "") + " " + artifactClass)) ?
                  '<div class="studio-conversation-artifact-compare" data-testid="studio-conversation-artifact-compare-state"><strong>Compare ready</strong><span>Original, projection, and latest revision are preserved by the daemon.</span></div>' :
                  "") +
                '<div class="studio-conversation-artifact-actions" data-testid="studio-conversation-artifact-actions">' +
                  actions.map((action) => '<button type="button" data-testid="studio-conversation-artifact-action" data-studio-artifact-action="' + escapeMarkdownHtml(action) + '" data-artifact-id="' + escapeMarkdownHtml(artifactId) + '">' + escapeMarkdownHtml(String(action).replace(/[_-]+/g, " ")) + "</button>").join("") +
                "</div>" +
              "</div>" +
            "</article>";
          }).join("") +
        "</section>";
      }
      function bindConversationArtifactControls(root) {
        const scope = root || document;
        scope.querySelectorAll("[data-studio-artifact-expand]").forEach((button) => {
          if (button.dataset.studioArtifactExpandBound === "true") return;
          button.dataset.studioArtifactExpandBound = "true";
          button.addEventListener("click", () => {
            const card = button.closest("[data-testid='studio-conversation-artifact-card']");
            const expanded = !card?.classList.contains("is-expanded");
            card?.classList.toggle("is-expanded", expanded);
            card?.setAttribute("data-artifact-expanded", String(expanded));
            button.setAttribute("aria-expanded", String(expanded));
            button.textContent = expanded ? "Collapse" : "Open";
          });
        });
        scope.querySelectorAll("[data-studio-artifact-action]").forEach((button) => {
          if (button.dataset.studioArtifactActionBound === "true") return;
          button.dataset.studioArtifactActionBound = "true";
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
      }
      function ensureProjectedConversationArtifacts(turn, workRecord, artifacts) {
        if (!turn) return;
        const artifactRowsHtml = projectedConversationArtifactRowsHtml(workRecord, artifacts);
        turn.querySelectorAll("[data-testid='studio-conversation-artifacts']").forEach((node) => node.remove());
        if (!artifactRowsHtml) return;
        const anchor =
          Array.from(turn.querySelectorAll("[data-testid='studio-managed-sessions']")).pop() ||
          turn.querySelector("[data-testid='studio-run-status-bar']") ||
          turn.querySelector("[data-testid='studio-assistant-answer-card']") ||
          turn;
        anchor.insertAdjacentHTML("afterend", artifactRowsHtml);
        bindConversationArtifactControls(turn);
        const root = document.querySelector("[data-testid='agent-studio-operational-chat']");
        root?.setAttribute("data-conversation-artifact-observed", "true");
      }
      function bindManagedSessionControls(root) {
        const scope = root || document;
        scope.querySelectorAll("[data-studio-managed-session-expand]").forEach((button) => {
          if (button.dataset.studioManagedSessionBound === "true") return;
          button.dataset.studioManagedSessionBound = "true";
          button.addEventListener("click", () => {
            const card = button.closest("[data-testid='studio-managed-session-card']");
            const expanded = !card?.classList.contains("is-expanded");
            card?.classList.toggle("is-expanded", expanded);
            card?.setAttribute("data-session-expanded", String(expanded));
            button.setAttribute("aria-expanded", String(expanded));
            button.textContent = expanded ? "Collapse" : "Expand";
          });
        });
        if (window.__ioiManagedSessionControlDelegateBound !== true) {
          window.__ioiManagedSessionControlDelegateBound = true;
          document.addEventListener("click", (event) => {
            const button = event.target?.closest?.("[data-studio-managed-session-control]");
            if (!button) return;
            const card = button.closest("[data-testid='studio-managed-session-card']");
            const control = button.dataset.studioManagedSessionControl || "observe";
            card?.setAttribute("data-control-state", control);
            card?.querySelectorAll("[data-studio-managed-session-control]").forEach((candidate) => {
              const active = candidate === button;
              candidate.classList.toggle("is-active", active);
              candidate.setAttribute("aria-pressed", String(active));
            });
            vscode.postMessage({
              source: "ioi-studio-managed-session",
              type: "studioManagedSessionControl",
              payload: {
                managedSessionId: card?.dataset.sessionId || "",
                control,
                sessionKind: card?.dataset.sessionKind || "",
                reason: control === "take_over"
                  ? "operator requested manual control"
                  : control === "return_agent"
                    ? "operator returned control to Agent"
                    : "operator observing session",
              },
            });
          });
        }
      }
      function ensureProjectedWorkRunBar(turn, workRecord, status) {
        const rowsHtml = projectedWorkRowsHtml(workRecord);
        const commandsHtml = projectedCommandOutputRowsHtml(workRecord);
        const diffHunksHtml = projectedDiffHunksHtml(workRecord);
        const sessionCards = normalizeProjectedSessionCards(workRecord);
        const sessionsHtml = projectedManagedSessionRowsHtml(workRecord);
        if (!turn || (!rowsHtml && !commandsHtml && !diffHunksHtml && !sessionsHtml)) return;
        turn.dataset.documentedWork = "true";
        turn.setAttribute("data-documented-work", "true");
        const headline = status === "blocked"
          ? "Stopped by operator"
          : "Worked for " + formatProjectedWorkDuration(workRecord?.durationMs);
        const runBarHtml =
          '<details class="studio-run-status-bar" data-testid="studio-run-status-bar">' +
            "<summary>" +
              '<span class="studio-run-status-bar__check" aria-hidden="true">✓</span>' +
              "<strong>" + escapeMarkdownHtml(headline) + "</strong>" +
            "</summary>" +
            '<ul class="studio-run-status-bar__details studio-work-record" data-testid="studio-work-summary-lines">' +
              rowsHtml +
            "</ul>" +
            commandsHtml +
            diffHunksHtml +
          "</details>";
        const existing = turn.querySelector("[data-testid='studio-run-status-bar']");
        if (existing) {
          existing.outerHTML = runBarHtml;
        } else {
          turn.insertAdjacentHTML("afterbegin", runBarHtml);
        }
        turn.querySelectorAll("[data-testid='studio-managed-sessions']").forEach((node) => node.remove());
        if (sessionsHtml) {
          const runBar = turn.querySelector("[data-testid='studio-run-status-bar']");
          runBar?.insertAdjacentHTML("afterend", sessionsHtml);
          const root = document.querySelector("[data-testid='agent-studio-operational-chat']");
          root?.setAttribute("data-managed-live-viewport-observed", "true");
          root?.setAttribute("data-managed-session-labels-observed", "true");
          root?.setAttribute("data-managed-session-count", String(Math.max(sessionCards.length, Number(root?.getAttribute("data-managed-session-count") || 0) || 0)));
          bindManagedSessionControls(turn);
        }
        bindStudioHunkControls(turn);
        ensureProjectedConversationArtifacts(turn, workRecord, []);
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
      const studioRuntimeCompletedStreams = new Set();
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
        scrollStudioTranscriptToLatest(output.closest("[data-studio-turn-role='assistant']") || output);
      }
      function handleStudioRuntimeMessage(message) {
        const payload = message.payload || {};
        if (message.type === "agentWorkStep") {
          const rootStatus = document.querySelector("[data-testid='agent-studio-operational-chat']")?.getAttribute("data-studio-status") || "";
          if (["completed", "blocked"].includes(rootStatus)) {
            hidePendingProjectionAfterMinimum();
            return;
          }
          appendPendingWorkStep(payload);
          return;
        }
        if (message.type === "agentWorklogSnapshot") {
          const rootStatus = document.querySelector("[data-testid='agent-studio-operational-chat']")?.getAttribute("data-studio-status") || "";
          if (["completed", "blocked"].includes(rootStatus)) {
            hidePendingProjectionAfterMinimum();
            return;
          }
          const steps = Array.isArray(payload.steps) ? payload.steps : [];
          if (!steps.length) return;
          const pending = ensurePendingProjection();
          const list = pending?.querySelector("[data-testid='studio-pending-worklog']");
          if (list) {
            list.innerHTML = "";
          }
          for (const step of steps) {
            appendPendingWorkStep(step);
          }
          return;
        }
        if (!payload.streamId) return;
        if (message.type === "assistantStreamStart") {
          const kind = setStudioStreamKind(payload);
          studioRuntimeCompletedStreams.delete(String(payload.streamId || ""));
          showPendingProjection();
          if (kind === "artifact_source") {
            ensureArtifactSourceStream(payload);
          }
          return;
        }
        if (message.type === "assistantStreamDelta") {
          if (studioRuntimeCompletedStreams.has(String(payload.streamId || ""))) {
            return;
          }
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
          scrollStudioTranscriptToLatest(target?.turn);
          document.querySelector("[data-testid='agent-studio-operational-chat']")?.setAttribute("data-studio-status", "streaming");
          hidePendingProjectionAfterMinimum();
          return;
        }
        if (message.type === "assistantThinkingDelta") {
          if (studioRuntimeCompletedStreams.has(String(payload.streamId || ""))) {
            return;
          }
          if (studioStreamKind(payload.streamId) === "artifact_source") {
            const thinking = ensurePendingThinkingBlock();
            if (thinking) {
              thinking.textContent = (thinking.textContent || "") + (payload.delta || "");
            }
            scrollStudioTranscriptToLatest(thinking?.closest("[data-studio-turn-role='assistant']") || thinking);
            document.querySelector("[data-testid='agent-studio-operational-chat']")?.setAttribute("data-studio-status", "streaming");
            return;
          }
          const target = ensureStreamingAssistantTurn(payload.streamId);
          const thinking = ensureStreamingThinkingBlock(target?.turn);
          if (thinking) {
            thinking.textContent = (thinking.textContent || "") + (payload.delta || "");
          }
          updateStreamRunBar(target?.turn, "streaming", "Working...");
          scrollStudioTranscriptToLatest(target?.turn);
          document.querySelector("[data-testid='agent-studio-operational-chat']")?.setAttribute("data-studio-status", "streaming");
          hidePendingProjectionAfterMinimum();
          return;
        }
        if (message.type === "assistantStreamComplete") {
          studioRuntimeCompletedStreams.add(String(payload.streamId || ""));
          if (studioStreamKind(payload.streamId) === "artifact_source") {
            const source = ensureArtifactSourceStream(payload);
            if (source && payload.text) {
              source.textContent = payload.text;
            }
            if (payload.thinkingText) {
              const thinking = ensurePendingThinkingBlock();
              if (thinking) thinking.textContent = payload.thinkingText;
            }
            scrollStudioTranscriptToLatest(source?.closest("[data-studio-turn-role='assistant']") || source);
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
            renderMarkdownInto(target.text, sanitizePublicAssistantText(payload.text));
          }
          if (target?.turn && Array.isArray(payload.sourceRefs)) {
            syncProjectedSourceRows(target.turn, payload.sourceRefs);
          }
          if (target?.turn && payload.workRecord) {
            ensureProjectedWorkRunBar(target.turn, payload.workRecord, "completed");
          }
          if (target?.turn && (payload.workRecord || Array.isArray(payload.artifacts))) {
            ensureProjectedConversationArtifacts(target.turn, payload.workRecord, payload.artifacts);
          }
          updateStreamRunBar(target?.turn, "completed", "Worked");
          scrollStudioTranscriptToLatest(target?.turn);
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
        const status = String(payload?.status || "completed").trim() || "completed";
        const turn = appendProjectedTurn("assistant", text, {
          prompt: String(payload?.prompt || ""),
          sourceRefs: Array.isArray(payload?.sourceRefs) ? payload.sourceRefs : [],
        });
        if (turn) {
          ensureProjectedWorkRunBar(turn, payload?.workRecord, status);
          ensureProjectedConversationArtifacts(turn, payload?.workRecord, payload?.artifacts);
          updateStreamRunBar(turn, status === "blocked" ? "blocked" : "completed", status === "blocked" ? "Blocked" : "Worked");
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
        if (message.source !== "ioi-hypervisor-workbench-quickinput" || message.type !== "ioi.quickInput.result") {
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
        return role === "assistant" ? sanitizePublicAssistantText(raw) : raw;
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
            syncProjectedSourceRows(anchor.duplicate, options.sourceRefs);
          }
          scrollStudioTranscriptToLatest(anchor.duplicate);
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
        if (role === "assistant") {
          syncProjectedSourceRows(turn, options.sourceRefs);
        }
        if (anchor?.after?.nextSibling) {
          transcript.insertBefore(turn, anchor.after.nextSibling);
        } else {
          transcript.append(turn);
        }
        scrollStudioTranscriptToLatest(turn);
        return turn;
      }
      let studioPendingProjectionTimer = null;
      function studioPendingProjectionLabel(startedAt) {
        const rawStartedAt = Number(startedAt || performance.now());
        const now = rawStartedAt > 1000000000000 ? Date.now() : performance.now();
        const elapsedSeconds = Math.max(0, Math.floor((now - rawStartedAt) / 1000));
        return "Thinking about your request · " + elapsedSeconds + "s";
      }
      function studioFormatElapsedLabel(totalSeconds) {
        const seconds = Math.max(0, Math.floor(Number(totalSeconds) || 0));
        const minutes = Math.floor(seconds / 60);
        const remainder = seconds % 60;
        if (minutes > 0) return minutes + "m " + remainder + "s";
        return seconds + "s";
      }
      function studioPendingWorkStepStartedAtMs(payload, fallback = performance.now()) {
        const raw = payload?.at || payload?.startedAt || payload?.started_at || "";
        const parsed = Date.parse(String(raw || ""));
        if (Number.isFinite(parsed)) return parsed;
        const numeric = Number(raw);
        if (Number.isFinite(numeric) && numeric > 0) return numeric;
        return fallback;
      }
      function studioPendingStepVisibleDetail(detail) {
        const text = sanitizePublicToolText(detail);
        if (/^(?:running|started|completed|pending|status:\s*(?:running|started|completed|pending))$/i.test(text)) {
          return "";
        }
        return text;
      }
      function studioPendingCommandOutputExcerpt(payload = {}, fallbackExcerpt = "") {
        const text = sanitizePublicOutputBlock(
          payload.excerptPreview ||
            payload.excerpt_preview ||
            payload.stdout ||
            payload.output ||
            payload.chunk ||
            payload.text ||
            fallbackExcerpt ||
            "",
          1200
        );
        if (!text) return "";
        const commandLabel = compactPublicText(payload.command || payload.commandLabel || payload.command_label || payload.detail || "");
        const rowLabel = compactPublicText(payload.label || "");
        if (commandLabel && text === commandLabel) return "";
        if (rowLabel && text === rowLabel) return "";
        if (/^[a-z0-9_.-]+\s+-lc\s+<arg>$/i.test(text)) return "";
        if (/^[a-z0-9_.-]+\s+-e\s+<inline script>$/i.test(text)) return "";
        return text;
      }
      function studioPendingStepLabelForDisplay(item, baseLabel) {
        const label = sanitizePublicToolText(baseLabel || item?.dataset.baseLabel || "");
        const status = String(item?.dataset.status || "").toLowerCase();
        if (label === "Running command" && /running|started/.test(status)) {
          const rawStartedAt = Number(item?.dataset.startedAtMs || performance.now());
          const now = rawStartedAt > 1000000000000 ? Date.now() : performance.now();
          const elapsedSeconds = Math.max(0, Math.floor((now - rawStartedAt) / 1000));
          return label + " for " + studioFormatElapsedLabel(elapsedSeconds);
        }
        return label;
      }
      function updatePendingWorkStepLabels(pending) {
        const rows = pending?.querySelectorAll?.("[data-testid='studio-pending-worklog'] li") || [];
        rows.forEach((item) => {
          const headline = item.querySelector(".studio-pending-step__headline");
          if (!headline) return;
          headline.textContent = studioPendingStepLabelForDisplay(item, item.dataset.baseLabel || headline.textContent);
        });
      }
      function updatePendingProjectionLabel(pending) {
        const label = pending?.querySelector("[data-testid='studio-pending-label']");
        if (!label) return;
        label.textContent = studioPendingProjectionLabel(pending.dataset.pendingStartedAtMs);
        updatePendingWorkStepLabels(pending);
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
        if (pending?.getAttribute("data-artifact-source-retained") === "true") {
          pending.remove();
          pending = null;
        }
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
        scrollStudioTranscriptToLatest(pending);
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
        const rawLabel = String(payload?.label || "");
        const toolName = String(
          payload?.toolName ||
          payload?.tool_name ||
          payload?.toolId ||
          payload?.tool_id ||
          payload?.name ||
          payload?.tool ||
          (rawLabel.match(/\b[a-z][a-z0-9]*__[a-z0-9_]+\b/i)?.[0] || "")
        ).trim();
        let label = sanitizePublicToolText(rawLabel);
        const detail = studioPendingStepVisibleDetail(payload?.detail || "");
        if (!label) return;
        const normalizedTool = toolName.toLowerCase();
        if (normalizedTool === "shell__start") {
          const shellStateText = [detail, payload?.status].join(" ");
          label = /failed|error/i.test(shellStateText)
            ? "Command failed"
            : /running/i.test(shellStateText)
              ? "Running command"
              : "Started command";
        } else if (normalizedTool === "shell__run" || normalizedTool === "terminal__run") {
          const shellRunStateText = [detail, payload?.status].join(" ");
          label = /failed|error/i.test(shellRunStateText)
            ? "Command failed"
            : /running|started/i.test(shellRunStateText)
              ? "Running command"
              : "Ran command";
        } else if (normalizedTool === "shell__status") {
          label = "Checked command status";
        } else if (normalizedTool === "shell__input") {
          const inputState = [detail, payload?.status].join(" ");
          label = /already stopped|already terminated|obsolete/i.test(inputState)
            ? "Skipped obsolete input"
            : /failed|skipped|already sent/i.test(inputState)
            ? "Skipped duplicate input"
            : "Sent input to retained command";
        } else if (normalizedTool === "shell__terminate") {
          label = "Terminated retained command";
        } else if (normalizedTool === "shell__reset") {
          label = "Reset retained shell state";
        }
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
          item.dataset.baseLabel = label;
          if (!item.dataset.startedAtMs) {
            item.dataset.startedAtMs = String(studioPendingWorkStepStartedAtMs(payload));
          }
          const text = item.querySelector(".studio-pending-step__headline");
          let meta = item.querySelector(".studio-pending-step__summary");
          if (text) text.textContent = studioPendingStepLabelForDisplay(item, label);
          if (detail) {
            if (!meta) {
              meta = document.createElement("span");
              meta.className = "studio-pending-step__summary";
              item.append(meta);
            }
            meta.textContent = detail;
          } else if (meta) {
            meta.remove();
          }
          renderPendingWorkStepDecorations(item, payload);
          return;
        }
        item = document.createElement("li");
        item.dataset.stepId = id;
        item.dataset.toolName = toolName;
        item.dataset.status = String(payload?.status || "running");
        item.dataset.baseLabel = label;
        item.dataset.startedAtMs = String(studioPendingWorkStepStartedAtMs(payload));
        const text = document.createElement("p");
        text.className = "studio-pending-step__headline";
        text.textContent = studioPendingStepLabelForDisplay(item, label);
        item.append(text);
        if (detail) {
          const meta = document.createElement("span");
          meta.className = "studio-pending-step__summary";
          meta.textContent = detail;
          item.append(meta);
        }
        renderPendingWorkStepDecorations(item, payload);
        list.append(item);
        scrollStudioTranscriptToLatest(item);
      }
      function isPendingCommandStep(item, payload = {}) {
        const haystack = [
          item?.dataset?.toolName,
          item?.dataset?.baseLabel,
          payload?.toolName,
          payload?.tool_name,
          payload?.toolId,
          payload?.tool_id,
          payload?.label,
          payload?.kind,
        ].map((value) => String(value || "").toLowerCase()).join(" ");
        return /shell|terminal|command/.test(haystack);
      }
      function renderPendingWorkStepDecorations(item, payload = {}) {
        if (!item) return;
        const sourceChips = normalizeSourceChips(payload.sourceChips || payload.source_chips || payload.sources);
        let chipsNode = item.querySelector(".studio-source-chip-list");
        if (sourceChips.length) {
          if (!chipsNode) {
            chipsNode = document.createElement("div");
            chipsNode.className = "studio-source-chip-list";
            item.append(chipsNode);
          }
          chipsNode.innerHTML = studioProjectedSourceChipRows(sourceChips);
        } else if (chipsNode) {
          chipsNode.remove();
        }
        const commandStep = isPendingCommandStep(item, payload);
        const excerpt = commandStep
          ? studioPendingCommandOutputExcerpt(payload, sourceChips[0]?.excerpt || "")
          : sanitizePublicOutputBlock(payload.excerptPreview || payload.excerpt_preview || sourceChips[0]?.excerpt || "", 1200);
        let excerptNode = item.querySelector(".studio-pending-step__excerpt");
        const genericCommandExcerpt = commandStep && /^(?:ran command|running command|started command|command completed)$/i.test(excerpt);
        if (genericCommandExcerpt && excerptNode && excerptNode.textContent.trim()) {
          return;
        }
        if (excerpt) {
          const expectedTag = commandStep ? "PRE" : "P";
          if (excerptNode && excerptNode.tagName !== expectedTag) {
            excerptNode.remove();
            excerptNode = null;
          }
          if (!excerptNode) {
            excerptNode = document.createElement(commandStep ? "pre" : "p");
            excerptNode.className = commandStep
              ? "studio-pending-step__excerpt studio-pending-step__command-output"
              : "studio-pending-step__excerpt";
            if (commandStep) {
              excerptNode.setAttribute("data-testid", "studio-pending-command-output");
            }
            item.append(excerptNode);
          }
          excerptNode.textContent = excerpt;
        } else if (excerptNode && !commandStep) {
          excerptNode.remove();
        }
      }
      function hydratePendingWorkStepsFromRoot() {
        for (const step of pendingWorkStepsFromRoot()) {
          appendPendingWorkStep(step);
        }
      }
      function showPendingProjection() {
        const root = document.querySelector("[data-testid='agent-studio-operational-chat']");
        root?.setAttribute("data-studio-status", "pending");
        root?.removeAttribute("data-agent-final-handoff-stream-complete");
        root?.removeAttribute("data-artifact-handoff-stream-complete");
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
          const rootStatus = root?.getAttribute("data-studio-status") || "";
          if (artifactSource && artifactSource.textContent.trim() && !["completed", "blocked"].includes(rootStatus)) {
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
      document.addEventListener("click", (event) => {
        let button = event.target;
        while (button && button !== document && !button.dataset?.studioHunkDecision) {
          button = button.parentElement;
        }
        if (!button) return;
        event.preventDefault();
        document.body.dataset.studioHunkDecisionObserved = "true";
        document.body.dataset.studioHunkDecisionLast = button.dataset.studioHunkDecision || "";
        vscode.postMessage({
          type: "studioHunkDecision",
          decision: button.dataset.studioHunkDecision,
          payload: {
            approvalId: button.dataset.approvalId || ${JSON.stringify(STUDIO_APPROVAL_ID)},
            file: button.dataset.hunkFile || "docs/evidence/agent-studio-preview.md",
            changeId: button.dataset.changeId || "",
            hunkIndex: button.dataset.hunkIndex || "",
            runtimeAuthority: "daemon-owned",
            projectionOwner: "ioi-workbench-agent-studio"
          }
        });
      }, true);
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
      bindManagedSessionControls(document);
      bindConversationArtifactControls(document);
      bindStudioHunkControls(document);
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
