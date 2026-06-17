"use strict";

function createNativeChatViewRenderer({ escapeHtml, workspaceSummary }) {
  function renderNativeChatIcon(name) {
    const lucideCommon =
      'class="studio-source-icon studio-source-icon--lucide" viewBox="0 0 24 24" fill="none" stroke="currentColor" focusable="false" aria-hidden="true"';
    const codiconCommon =
      'class="studio-source-icon studio-source-icon--codicon" viewBox="0 0 16 16" fill="currentColor" focusable="false" aria-hidden="true"';
    switch (name) {
      case "paperclip":
        return `<svg ${lucideCommon} data-tauri-icon="paperclip" width="14" height="14" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="m21.44 11.05-9.19 9.19a6 6 0 0 1-8.49-8.49l8.57-8.57A4 4 0 1 1 18 8.84l-8.59 8.57a2 2 0 0 1-2.83-2.83l8.49-8.48" /></svg>`;
      case "device-desktop":
        return `<svg ${codiconCommon} data-tauri-codicon="device-desktop"><path d="M13.013 1.013L2.987 1.013L2.987 1.013Q2.187 1.013 1.600 1.600L1.600 1.600L1.600 1.600Q1.013 2.187 1.013 2.987L1.013 2.987L1.013 9.973L1.013 9.973Q1.013 10.827 1.600 11.413L1.600 11.413L1.600 11.413Q2.187 12 2.987 12L2.987 12L5.013 12L5.013 13.973L3.520 13.973L3.520 13.973Q3.307 13.973 3.147 14.133L3.147 14.133L3.147 14.133Q2.987 14.293 2.987 14.507L2.987 14.507L2.987 14.507Q2.987 14.720 3.147 14.853L3.147 14.853L3.147 14.853Q3.307 14.987 3.520 14.987L3.520 14.987L12.480 14.987L12.480 14.987Q12.693 14.987 12.853 14.853L12.853 14.853L12.853 14.853Q13.013 14.720 13.013 14.507L13.013 14.507L13.013 14.507Q13.013 14.293 12.853 14.133L12.853 14.133L12.853 14.133Q12.693 13.973 12.480 13.973L12.480 13.973L10.987 13.973L10.987 12L13.013 12L13.013 12Q13.813 12 14.400 11.413L14.400 11.413L14.400 11.413Q14.987 10.827 14.987 9.973L14.987 9.973L14.987 2.987L14.987 2.987Q14.987 2.187 14.400 1.600L14.400 1.600L14.400 1.600Q13.813 1.013 13.013 1.013L13.013 1.013ZM6.027 12L10.027 12L10.027 13.973L6.027 13.973L6.027 12ZM2.027 9.973L2.027 2.987L2.027 2.987Q2.027 2.560 2.293 2.267L2.293 2.267L2.293 2.267Q2.560 1.973 2.987 1.973L2.987 1.973L13.013 1.973L13.013 1.973Q13.440 2.027 13.733 2.293L13.733 2.293L13.733 2.293Q14.027 2.560 14.027 2.987L14.027 2.987L14.027 9.973L14.027 9.973Q13.973 10.400 13.707 10.693L13.707 10.693L13.707 10.693Q13.440 10.987 13.013 10.987L13.013 10.987L2.987 10.987L2.987 10.987Q2.560 10.987 2.293 10.693L2.293 10.693L2.293 10.693Q2.027 10.400 2.027 9.973L2.027 9.973Z" /></svg>`;
      case "cube":
        return `<svg ${lucideCommon} data-tauri-icon="cube" width="14" height="14" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="m21 16-9 5-9-5V8l9-5 9 5v8Z" /><path d="m3.3 7.3 8.7 5 8.7-5" /><path d="M12 22V12" /></svg>`;
      case "chevron-down":
        return `<svg ${codiconCommon} data-tauri-codicon="chevron-down"><path d="M3.147 5.867L3.147 5.867L7.627 10.347L7.627 10.347Q7.787 10.507 8 10.507L8 10.507L8 10.507Q8.213 10.507 8.373 10.347L8.373 10.347L12.853 5.867L12.853 5.867Q13.013 5.707 13.013 5.493L13.013 5.493L13.013 5.493Q13.013 5.280 12.853 5.147L12.853 5.147L12.853 5.147Q12.693 5.013 12.480 5.013L12.480 5.013L12.480 5.013Q12.267 5.013 12.160 5.173L12.160 5.173L8 9.280L3.840 5.173L3.840 5.173Q3.733 5.013 3.520 5.013L3.520 5.013L3.520 5.013Q3.307 5.013 3.147 5.147L3.147 5.147L3.147 5.147Q2.987 5.280 2.987 5.493L2.987 5.493L2.987 5.493Q2.987 5.707 3.147 5.867Z" /></svg>`;
      case "tools":
        return `<svg ${codiconCommon} data-tauri-codicon="tools"><path d="M5.66901 0.999997C5.52101 0.945997 5.34701 0.968997 5.21401 1.062C5.08101 1.155 5.00201 1.308 5.00201 1.47V3.286C5.00201 3.561 4.77701 3.786 4.50201 3.786C4.22701 3.786 4.00201 3.561 4.00201 3.286V1.47C4.00201 1.308 3.92301 1.156 3.79001 1.062C3.65801 0.967997 3.48501 0.945997 3.33501 0.999997C1.93901 1.495 1.00201 2.816 1.00201 4.287C1.00201 5.646 1.79201 6.876 3.00201 7.449V13.5C3.00201 14.327 3.67501 15 4.50201 15C5.32901 15 6.00201 14.327 6.00201 13.5V7.449C7.21201 6.876 8.00201 5.646 8.00201 4.287C8.00201 2.816 7.06401 1.495 5.66901 0.999997ZM5.33601 6.644C5.13601 6.714 5.00201 6.904 5.00201 7.116V13.501C5.00201 13.776 4.77701 14.001 4.50201 14.001C4.22701 14.001 4.00201 13.776 4.00201 13.501V7.116C4.00201 6.904 3.86801 6.715 3.66801 6.644C2.67201 6.292 2.00201 5.345 2.00201 4.288C2.00201 3.496 2.38501 2.765 3.00201 2.301V3.288C3.00201 4.115 3.67501 4.788 4.50201 4.788C5.32901 4.788 6.00201 4.115 6.00201 3.288V2.301C6.61901 2.765 7.00201 3.496 7.00201 4.288C7.00201 5.346 6.33201 6.293 5.33601 6.644ZM13.5 8H13.002V4.118L13.449 3.223C13.509 3.105 13.518 2.967 13.476 2.841L12.976 1.341C12.908 1.137 12.716 0.998997 12.501 0.998997H10.501C10.286 0.998997 10.095 1.137 10.026 1.341L9.52601 2.841C9.48401 2.967 9.49401 3.105 9.55301 3.223L10 4.118V8H9.50001C9.22401 8 9.00001 8.224 9.00001 8.5V12.5C9.00001 13.879 10.121 15 11.5 15C12.879 15 14 13.879 14 12.5V8.5C14 8.224 13.776 8 13.5 8ZM10.862 2.001H12.141L12.461 2.963L12.054 3.777C12.02 3.846 12.001 3.923 12.001 4.001V8.001H11.001V4.001C11.001 3.924 10.983 3.847 10.949 3.777L10.542 2.963L10.862 2.001ZM13.002 12.5C13.002 13.327 12.329 14 11.502 14C10.675 14 10.002 13.327 10.002 12.5V9H13.002V12.5Z" /></svg>`;
      case "send":
        return `<svg ${codiconCommon} data-tauri-codicon="send"><path d="M1.173 1.120L1.173 1.120L1.173 1.120Q1.440 0.907 1.707 1.067L1.707 1.067L14.720 7.573L14.720 7.573Q14.987 7.680 14.987 8L14.987 8L14.987 8Q14.987 8.320 14.720 8.427L14.720 8.427L1.707 14.933L1.707 14.933Q1.440 15.093 1.173 14.880L1.173 14.880L1.173 14.880Q0.907 14.667 1.013 14.347L1.013 14.347L2.987 8L1.013 1.653L1.013 1.653Q0.907 1.333 1.173 1.120ZM9.493 8.480L3.893 8.480L2.347 13.547L13.387 8L2.347 2.453L3.893 7.520L9.493 7.520L9.493 7.520Q9.707 7.520 9.867 7.653L9.867 7.653L9.867 7.653Q10.027 7.787 10.027 8L10.027 8L10.027 8Q10.027 8.213 9.867 8.347L9.867 8.347L9.867 8.347Q9.707 8.480 9.493 8.480L9.493 8.480Z" /></svg>`;
      case "stop":
        return `<svg ${lucideCommon} data-tauri-icon="stop" width="12" height="12" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="6" y="6" width="12" height="12" rx="2" /></svg>`;
      default:
        return "";
    }
  }

  function normalizedNativeChatTurns(state) {
    const turns = Array.isArray(state.chat?.turns) ? state.chat.turns : [];
    return turns
      .filter((turn) => turn && typeof turn.text === "string" && turn.text.trim())
      .map((turn, index) => ({
        id: typeof turn.id === "string" ? turn.id : `native-chat-turn:${index}`,
        role: typeof turn.role === "string" ? turn.role : "assistant",
        text: turn.text.trim(),
        timestamp: typeof turn.timestamp === "number" ? turn.timestamp : null,
      }));
  }

  function renderNativeChatConversation(state) {
    const turns = normalizedNativeChatTurns(state);
    const phase = typeof state.chat?.phase === "string" ? state.chat.phase : null;
    const currentStep =
      typeof state.chat?.currentStep === "string" ? state.chat.currentStep.trim() : "";
    if (turns.length === 0) {
      return "";
    }

    const status =
      phase && phase !== "Complete"
        ? `
          <div class="operator-chat-thread__status" data-inspection-target="native-ioi-chat-status">
            <span>${escapeHtml(phase)}</span>
            <strong>${escapeHtml(currentStep || "Working through the runtime...")}</strong>
          </div>
        `
        : "";

    return `
      <div class="operator-chat-thread" data-inspection-target="native-ioi-chat-thread">
        ${turns
          .map(
            (turn) => `
              <article
                class="operator-chat-message operator-chat-message--${escapeHtml(turn.role)}"
                data-chat-turn-role="${escapeHtml(turn.role)}"
              >
                <span>${escapeHtml(turn.role === "user" ? "You" : "Autopilot")}</span>
                <p>${escapeHtml(turn.text)}</p>
              </article>
            `,
          )
          .join("")}
        ${status}
      </div>
    `;
  }

  function renderChatView(state) {
    const modelLabel =
      state.chat?.modelLabel ||
      state.chat?.model ||
      state.chat?.selectedModelLabel ||
      "Local: qwen3.5:9b";
    const contextLabel = state.chat?.contextLabel || "Add Context...";
    const modeLabel = state.chat?.modeLabel || "Auto";
    const targetWorkspace = state.workspace?.path || workspaceSummary().path;
    const suggestedActions = Array.isArray(state.chat?.suggestedActions)
      ? state.chat.suggestedActions
      : [
          {
            label: "Build Workspace",
            requestType: "workflow.codeGenerationRequest",
            payload: {
              workflowRef: "workflow:active",
              packageRef: "package:active",
              goal: "Generate a proposal-first code change from the active workspace prompt.",
              boundModelCapabilityRef: "model-capability:unbound",
              boundToolCapabilityRefs: ["tool-capability:workspace.fs.proposal"],
              targetWorkspace,
              authorityScope: "workspace.fs.proposal",
              proposalOnly: true,
            },
          },
          {
            label: "Show Config",
            requestType: "chat.showConfig",
          },
        ];
    const conversation = renderNativeChatConversation(state);
    return `
      <section
        class="operator-chat-pane"
        data-operator-chat-pane="native-openvscode"
        data-inspection-target="native-ioi-chat-pane"
        aria-label="Autopilot Chat"
      >
        ${
          conversation ||
          `
            <div class="operator-chat-empty" data-inspection-target="native-ioi-chat-empty-state">
              <div class="operator-chat-empty__icon" aria-hidden="true">
                <svg viewBox="0 0 32 32" focusable="false">
                  <path d="M7.5 8.5h13a4 4 0 0 1 4 4v4a4 4 0 0 1-4 4H15l-5.5 4v-4h-2a4 4 0 0 1-4-4v-4a4 4 0 0 1 4-4Z" />
                  <path d="M24 5.5v5M21.5 8h5M27 13.5v3M25.5 15h3" />
                </svg>
              </div>
              <h2>Build with Agent</h2>
              <p>
                AI responses may be inaccurate.
                <a href="#" data-bridge-request="chat.generateAgentInstructions">Generate Agent Instructions</a>
                to onboard AI onto your codebase.
              </p>
            </div>
          `
        }
        <div class="operator-chat-bottom">
          <div
            class="operator-chat-notice"
            data-native-chat-notice
            data-inspection-target="native-ioi-chat-notice"
            hidden
          ></div>
          <div class="operator-chat-suggestions" aria-label="Suggested actions">
            <span>SUGGESTED ACTIONS</span>
            <div>
              ${suggestedActions
                .map(
                  (action) => `
                    <button
                      class="operator-chat-suggestion"
                      data-bridge-request="${escapeHtml(action.requestType || "chat.suggestedAction")}"
                      data-payload="${escapeHtml(
                        JSON.stringify(action.payload || { label: action.label }),
                      )}"
                    >${escapeHtml(action.label)}</button>
                  `,
                )
                .join("")}
            </div>
          </div>
          <form
            class="operator-chat-composer"
            data-chat-composer-form
            data-inspection-target="native-ioi-chat-composer"
            aria-label="Chat composer"
          >
            <div class="operator-chat-composer__context-row">
              <button
                type="button"
                class="operator-chat-context-button"
                data-bridge-request="chat.addContext"
              >
                <span class="operator-chat-button-icon">${renderNativeChatIcon("paperclip")}</span>
                <span>${escapeHtml(contextLabel)}</span>
              </button>
            </div>
            <textarea
              data-chat-composer-input
              rows="2"
              placeholder="Describe what to build next"
              aria-label="Describe what to build next"
              autocomplete="off"
              autocapitalize="off"
              spellcheck="false"
            ></textarea>
            <div class="operator-chat-composer__controls">
              <button
                type="button"
                class="operator-chat-icon-select"
                aria-label="Set Session Target"
                title="Set Session Target"
                data-bridge-request="chat.attachEditorContext"
              >
                <span class="operator-chat-button-icon">${renderNativeChatIcon("device-desktop")}</span>
                <span class="operator-chat-button-chevron">${renderNativeChatIcon("chevron-down")}</span>
              </button>
              <button
                type="button"
                class="operator-chat-icon-select"
                aria-label="Choose model or command - ${escapeHtml(modelLabel)}"
                title="Choose model or command - ${escapeHtml(modelLabel)}"
                data-bridge-request="chat.contextOptions"
                data-chat-model="${escapeHtml(modelLabel)}"
              >
                <span class="operator-chat-button-icon">${renderNativeChatIcon("cube")}</span>
                <span class="operator-chat-button-chevron">${renderNativeChatIcon("chevron-down")}</span>
              </button>
              <button
                type="button"
                class="operator-chat-mode-select"
                aria-label="Mode - ${escapeHtml(modeLabel)}"
                title="Mode - ${escapeHtml(modeLabel)}"
                data-bridge-request="chat.modeOptions"
                data-chat-mode="${escapeHtml(modeLabel)}"
              >
                <span>${escapeHtml(modeLabel)}</span>
                <span class="operator-chat-button-chevron">${renderNativeChatIcon("chevron-down")}</span>
              </button>
              <button
                type="button"
                class="operator-chat-tool-toggle"
                aria-label="Select tools"
                data-bridge-request="commandCenter.open"
                data-payload='{"mode":"tools"}'
              >
                <span class="operator-chat-button-icon">${renderNativeChatIcon("tools")}</span>
              </button>
              <button class="operator-chat-send" type="submit" aria-label="Send chat request">
                <span class="operator-chat-button-icon">${renderNativeChatIcon("send")}</span>
              </button>
            </div>
          </form>
        </div>
      </section>
    `;
  }

  return {
    normalizedNativeChatTurns,
    renderChatView,
    renderNativeChatConversation,
    renderNativeChatIcon,
  };
}

module.exports = {
  createNativeChatViewRenderer,
};
