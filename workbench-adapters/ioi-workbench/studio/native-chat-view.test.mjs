import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);
const { createNativeChatViewRenderer } = require("./native-chat-view.js");

function escapeHtml(value = "") {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function createRenderer() {
  return createNativeChatViewRenderer({
    escapeHtml,
    workspaceSummary: () => ({
      name: "workspace",
      path: "/workspace",
    }),
  });
}

test("empty native chat view keeps product pane, composer, and default actions", () => {
  const renderer = createRenderer();
  const html = renderer.renderChatView({ chat: {}, workspace: {} });

  assert.match(html, /data-operator-chat-pane="native-openvscode"/);
  assert.match(html, /data-inspection-target="native-ioi-chat-pane"/);
  assert.match(html, /data-inspection-target="native-ioi-chat-composer"/);
  assert.match(html, /data-inspection-target="native-ioi-chat-empty-state"/);
  assert.match(html, /data-bridge-request="workflow\.codeGenerationRequest"/);
  assert.match(html, /&quot;targetWorkspace&quot;:&quot;\/workspace&quot;/);
  assert.match(html, /data-bridge-request="chat\.showConfig"/);
});

test("native chat conversation normalizes turns and escapes role/text/status", () => {
  const renderer = createRenderer();
  const turns = renderer.normalizedNativeChatTurns({
    chat: {
      turns: [
        { id: "u1", role: "user", text: "  build <site>  ", timestamp: 12 },
        { role: "assistant", text: "\nDone & ready\n" },
        { role: "assistant", text: "   " },
      ],
    },
  });

  assert.deepEqual(turns, [
    { id: "u1", role: "user", text: "build <site>", timestamp: 12 },
    {
      id: "native-chat-turn:1",
      role: "assistant",
      text: "Done & ready",
      timestamp: null,
    },
  ]);

  const html = renderer.renderNativeChatConversation({
    chat: {
      phase: "<Working>",
      currentStep: "Read & patch",
      turns,
    },
  });

  assert.match(html, /data-inspection-target="native-ioi-chat-thread"/);
  assert.match(html, /data-chat-turn-role="user"/);
  assert.match(html, /build &lt;site&gt;/);
  assert.match(html, /Done &amp; ready/);
  assert.match(html, /data-inspection-target="native-ioi-chat-status"/);
  assert.match(html, /&lt;Working&gt;/);
  assert.match(html, /Read &amp; patch/);
});

test("native chat view renders configured labels, actions, and icon fallbacks", () => {
  const renderer = createRenderer();
  const html = renderer.renderChatView({
    workspace: { path: "/repo" },
    chat: {
      contextLabel: "Context <one>",
      modelLabel: "Model & route",
      modeLabel: "Agent",
      suggestedActions: [
        {
          label: "Run <proof>",
          requestType: "ioi.proof",
          payload: { path: "/repo" },
        },
      ],
    },
  });

  assert.match(html, /Context &lt;one&gt;/);
  assert.match(html, /Choose model or command - Model &amp; route/);
  assert.match(html, /data-chat-mode="Agent"/);
  assert.match(html, /Run &lt;proof&gt;/);
  assert.match(html, /data-bridge-request="ioi\.proof"/);
  assert.match(html, /data-tauri-icon="paperclip"/);
  assert.match(html, /data-tauri-codicon="send"/);
  assert.equal(renderer.renderNativeChatIcon("missing"), "");
});
