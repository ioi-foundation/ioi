function studioPanelStyles() {
  return String.raw`
      :root {
        color-scheme: dark;
        --studio-bg: #171717;
        --studio-panel: #202020;
        --studio-panel-strong: #272727;
        --studio-border: rgba(255, 255, 255, 0.12);
        --studio-border-strong: rgba(255, 255, 255, 0.2);
        --studio-text: #e8e8e8;
        --studio-muted: #aaaeb5;
        --studio-dim: #7c828b;
        --studio-accent: #7aa2ff;
        --studio-good: #7fd1a5;
        --studio-warn: #e7bf62;
        --studio-danger: #ff7b8a;
      }
      * {
        box-sizing: border-box;
      }
      body {
        margin: 0;
        min-height: 100vh;
        overflow: hidden;
        font-family: var(--vscode-font-family, ui-sans-serif, system-ui, sans-serif);
        color: var(--studio-text);
        background: var(--studio-bg);
      }
      button,
      select,
      textarea {
        font: inherit;
      }
      button,
      select {
        border: 1px solid var(--studio-border);
        border-radius: 4px;
        background: #2d2d2d;
        color: var(--studio-text);
      }
      button {
        min-height: 30px;
        padding: 5px 10px;
        cursor: pointer;
      }
      button:hover,
      select:hover {
        border-color: var(--studio-border-strong);
        background: #353535;
      }
      .studio-operational-shell {
        height: 100vh;
        display: grid;
        grid-template-columns: minmax(230px, 280px) minmax(420px, 1fr) minmax(320px, 380px);
        grid-template-rows: minmax(0, 1fr);
        overflow: hidden;
      }
      .studio-operational-rail,
      .studio-chat-main,
      .studio-operator-context {
        min-width: 0;
        min-height: 0;
      }
      .studio-operational-rail,
      .studio-operator-context {
        border-right: 1px solid var(--studio-border);
        background: #181818;
        padding: 18px;
        overflow: auto;
      }
      .studio-operator-context {
        border-right: 0;
        border-left: 1px solid var(--studio-border);
      }
      .studio-eyebrow,
      .studio-control-group h3,
      .studio-operator-context h3 {
        margin: 0 0 9px;
        color: var(--studio-muted);
        font-size: 11px;
        font-weight: 700;
        letter-spacing: .08em;
        text-transform: uppercase;
      }
      h1,
      h2 {
        margin: 3px 0 4px;
        letter-spacing: 0;
      }
      h1 {
        font-size: 22px;
      }
      h2 {
        font-size: 18px;
      }
      p {
        margin: 0;
        color: var(--studio-muted);
        line-height: 1.45;
      }
      .studio-control-group,
      .studio-operator-context section,
      .studio-approval,
      .studio-diff-hunk {
        border: 1px solid var(--studio-border);
        border-radius: 6px;
        background: var(--studio-panel);
        padding: 12px;
      }
      .studio-control-group,
      .studio-operator-context section,
      .studio-approval {
        margin-top: 14px;
      }
      .studio-control-group button,
      .studio-history-item {
        width: 100%;
        margin-top: 7px;
        text-align: left;
      }
      .studio-history-item {
        display: grid;
        gap: 2px;
      }
      .studio-history-item span,
      .studio-operator-context li span,
      .studio-approval span {
        color: var(--studio-muted);
        font-size: 12px;
      }
      .studio-chat-main {
        display: grid;
        grid-template-rows: auto minmax(0, 1fr) auto;
        overflow: hidden;
        background: #1c1c1c;
      }
      .studio-chat-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 16px;
        padding: 16px 18px;
        border-bottom: 1px solid var(--studio-border);
        background: #191919;
      }
      .studio-route-controls {
        display: flex;
        align-items: center;
        gap: 8px;
        flex-wrap: wrap;
      }
      .studio-route-controls select {
        max-width: 230px;
        min-height: 30px;
        padding: 0 8px;
      }
      .studio-transcript {
        min-height: 0;
        padding: 18px;
        overflow: auto;
        display: grid;
        align-content: start;
        gap: 12px;
      }
      .studio-chat-turn {
        display: grid;
        grid-template-columns: 34px minmax(0, 1fr);
        gap: 10px;
      }
      .studio-chat-turn__avatar {
        width: 30px;
        height: 30px;
        border-radius: 50%;
        display: grid;
        place-items: center;
        background: #303030;
        color: #fff;
        font-weight: 700;
      }
      .studio-chat-turn--user .studio-chat-turn__avatar {
        background: #125ea8;
      }
      .studio-chat-turn__body {
        border: 1px solid var(--studio-border);
        border-radius: 7px;
        padding: 10px 12px;
        background: var(--studio-panel);
      }
      .studio-chat-turn__meta {
        display: flex;
        justify-content: space-between;
        gap: 12px;
        margin-bottom: 6px;
        color: var(--studio-muted);
        font-size: 12px;
      }
      .studio-chat-turn__body p {
        color: var(--studio-text);
        white-space: pre-wrap;
      }
      .studio-thinking-block {
        margin: 0 0 10px;
        border-left: 1px solid #303742;
        padding-left: 12px;
        color: var(--studio-muted);
      }
      .studio-thinking-block summary {
        cursor: pointer;
        color: var(--studio-muted);
      }
      .studio-thinking-block p {
        margin: 8px 0 0;
        max-height: 220px;
        overflow: auto;
        color: var(--studio-muted);
      }
      .studio-response-metrics {
        display: flex;
        flex-wrap: wrap;
        gap: 6px;
        margin-top: 12px;
        color: var(--studio-muted);
        font-size: 11px;
      }
      .studio-response-metrics span {
        display: inline-flex;
        gap: 4px;
        min-height: 22px;
        align-items: center;
        border: 1px solid #343434;
        border-radius: 999px;
        padding: 2px 8px;
        background: #101010;
      }
      .studio-response-metrics strong {
        color: var(--studio-text);
        font-weight: 600;
      }
      .studio-answer-sources {
        display: flex;
        flex-wrap: wrap;
        align-items: center;
        gap: 6px;
        margin-top: 12px;
        color: var(--studio-muted);
        font-size: 12px;
      }
      .studio-answer-sources span {
        color: var(--studio-muted);
      }
      .studio-answer-sources a {
        max-width: 260px;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
        border: 1px solid #343434;
        border-radius: 999px;
        padding: 2px 8px;
        background: #101010;
        color: var(--studio-accent);
        text-decoration: none;
      }
      .studio-answer-sources a:hover {
        border-color: var(--studio-border-strong);
        text-decoration: underline;
      }
      .studio-chat-output-renderer {
        display: grid;
        gap: 10px;
        margin: 12px 0 0;
        border: 1px solid #4d4d4d;
        border-radius: 7px;
        padding: 12px;
        background: #101010;
      }
      .studio-chat-output-renderer figcaption,
      .studio-chat-renderer-toolbar {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 8px;
        flex-wrap: wrap;
      }
      .studio-chat-output-renderer figcaption span,
      .studio-mermaid-source summary {
        color: var(--studio-muted);
        font-size: 12px;
      }
      .studio-chat-renderer-toolbar button {
        min-height: 26px;
        border-radius: 999px;
        padding: 2px 9px;
      }
      .studio-mermaid-diagram {
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
        align-items: center;
        padding: 10px;
        border: 1px dashed #4a4a4a;
        border-radius: 6px;
      }
      .studio-mermaid-node {
        border: 1px solid #6a6a6a;
        border-radius: 999px;
        background: #1f1f1f;
        color: var(--studio-text);
        padding: 4px 10px;
      }
      .studio-mermaid-source pre {
        max-height: 180px;
        overflow: auto;
        margin: 8px 0 0;
        white-space: pre-wrap;
      }
      .studio-chat-code-execution-card {
        display: grid;
        gap: 10px;
        margin: 12px 0 0;
        border: 1px solid #4d4d4d;
        border-radius: 7px;
        padding: 12px;
        background: #0d0d0d;
      }
      .studio-chat-code-execution-card header,
      .studio-chat-code-execution-card footer {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 8px;
        flex-wrap: wrap;
      }
      .studio-chat-code-execution-card header span,
      .studio-chat-code-execution-card footer span {
        color: var(--studio-muted);
        font-size: 12px;
      }
      .studio-chat-code-execution-card pre {
        max-height: 180px;
        overflow: auto;
        margin: 0;
        white-space: pre-wrap;
      }
      .studio-chat-code-execution-card[data-execution-status="blocked"] {
        border-color: #8a5b38;
      }
      .studio-chat-code-execution-card button {
        min-height: 28px;
        border-radius: 999px;
        padding: 3px 10px;
      }
      .studio-pending {
        display: grid;
        gap: 10px;
        width: min(100%, 520px);
        color: var(--studio-muted);
        font-size: 14px;
        line-height: 1.55;
        padding: 2px 0;
      }
      .studio-pending[hidden] {
        display: none;
      }
      .studio-pending__dots {
        display: inline-flex;
        align-items: center;
        gap: 4px;
        color: var(--studio-muted);
      }
      .studio-pending__line {
        display: inline-flex;
        align-items: center;
        gap: 10px;
      }
      .studio-pending__worklog {
        display: grid;
        gap: 12px;
        margin: 4px 0 0;
        padding: 0;
        list-style: none;
      }
      .studio-pending__worklog li {
        display: grid;
        gap: 4px;
        border-left: 1px solid #303742;
        padding-left: 12px;
      }
      .studio-pending__worklog p {
        margin: 0;
        color: var(--studio-text);
      }
      .studio-pending__worklog span {
        color: var(--studio-muted);
        font-size: 12px;
      }
      .studio-pending__thinking,
      .studio-artifact-source-stream {
        display: grid;
        gap: 8px;
        border-left: 1px solid #303742;
        padding-left: 12px;
      }
      .studio-pending__thinking summary,
      .studio-artifact-source-stream header {
        color: var(--studio-muted);
        font-size: 12px;
      }
      .studio-pending__thinking p {
        margin: 0;
        max-height: 180px;
        overflow: auto;
        white-space: pre-wrap;
        color: var(--studio-muted);
      }
      .studio-artifact-source-stream {
        width: min(100%, 760px);
        border: 1px solid #303742;
        border-radius: 7px;
        padding: 10px 12px;
        background: #0d1114;
      }
      .studio-artifact-source-stream pre {
        max-height: 300px;
        overflow: auto;
        margin: 0;
        white-space: pre-wrap;
        color: var(--studio-text);
        font-size: 12px;
        line-height: 1.45;
      }
      .studio-pending__dots span {
        width: 7px;
        height: 7px;
        border-radius: 50%;
        background: currentColor;
        animation: studioPulse 1s infinite ease-in-out;
      }
      .studio-pending__dots span:nth-child(2) {
        animation-delay: .12s;
      }
      .studio-pending__dots span:nth-child(3) {
        animation-delay: .24s;
      }
      .studio-pending strong {
        font: inherit;
        font-weight: 400;
        color: inherit;
      }
      @keyframes studioPulse {
        0%, 80%, 100% { opacity: .35; transform: translateY(0); }
        40% { opacity: 1; transform: translateY(-2px); }
      }
      .studio-composer {
        border-top: 0;
        background: #191919;
        padding: 12px 14px;
      }
      .studio-composer textarea {
        width: 100%;
        min-height: 76px;
        resize: vertical;
        border: 1px solid var(--studio-border);
        border-radius: 7px;
        outline: 0;
        background: #121212;
        color: var(--studio-text);
        line-height: 1.5;
        padding: 10px 12px;
      }
      .studio-composer textarea::placeholder {
        color: var(--studio-muted);
      }
      .studio-composer-toolbar {
        display: flex;
        align-items: center;
        justify-content: flex-end;
        gap: 8px;
        margin-top: 8px;
      }
      .studio-composer-toolbar button[type="submit"] {
        margin-left: auto;
        background: #0e639c;
        border-color: #0e639c;
      }
      .studio-tauri-chat-shell {
        grid-template-columns: minmax(240px, 300px) minmax(520px, 1fr) 52px;
        background: #050505;
      }
      .studio-tauri-chat-shell:has(.studio-utility-drawer.is-expanded),
      .studio-tauri-chat-shell.has-expanded-utility {
        grid-template-columns: minmax(240px, 300px) minmax(520px, 1fr) minmax(340px, 390px);
      }
      .studio-session-rail {
        background: #141414;
        border-right-color: #303030;
        padding: 16px 12px;
      }
      .studio-session-rail__header {
        display: grid;
        grid-template-columns: minmax(0, 1fr) 32px;
        align-items: center;
        gap: 10px;
      }
      .studio-session-rail__header h2 {
        grid-column: 1 / 2;
        margin-top: 0;
        color: var(--studio-muted);
        font-size: 13px;
        font-weight: 500;
      }
      .studio-session-rail__header button {
        grid-column: 2 / 3;
        grid-row: 1 / 3;
        width: 30px;
        min-height: 30px;
        padding: 0;
        font-size: 18px;
      }
      .studio-session-search {
        position: relative;
        display: block;
        margin: 14px 0 10px;
      }
      .studio-session-search input {
        width: 100%;
        height: 30px;
        border: 1px solid var(--studio-border-strong);
        border-radius: 6px;
        background: #050505;
        color: var(--studio-text);
        padding: 0 10px 0 30px;
      }
      .studio-search-icon {
        position: absolute;
        left: 10px;
        top: 6px;
        color: var(--studio-muted);
      }
      .studio-session-actions {
        display: grid;
        gap: 6px;
        margin-bottom: 18px;
      }
      .studio-session-actions button,
      .studio-rail-secondary button {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 10px;
      }
      .studio-history-group {
        border: 0;
        background: transparent;
        padding: 0;
      }
      .studio-history-date {
        display: block;
        margin: 4px 0 8px;
        color: var(--studio-muted);
        font-size: 11px;
        font-weight: 700;
        text-transform: uppercase;
      }
      .studio-history-item--current {
        background: #050505;
        border-color: #050505;
      }
      .studio-chat-main {
        position: relative;
        background: #050505;
      }
      .studio-chat-header {
        min-height: 48px;
        padding: 0 16px;
        background: #070707;
      }
      .studio-chat-tab {
        min-height: 48px;
        border: 0;
        border-radius: 0;
        border-bottom: 2px solid var(--studio-accent);
        background: transparent;
        font-size: 12px;
        font-weight: 700;
        text-transform: uppercase;
      }
      .studio-transcript {
        padding: 42px 54px 26px;
        gap: 20px;
      }
      .studio-chat-transcript {
        display: grid;
        gap: 22px;
      }
      .studio-chat-turn {
        grid-template-columns: minmax(0, 1fr);
        max-width: 1040px;
      }
      .studio-chat-turn__avatar {
        display: none;
      }
      .studio-chat-turn--user {
        justify-self: end;
        max-width: min(560px, 80%);
      }
      .studio-chat-turn--assistant,
      .studio-chat-turn--system {
        max-width: min(1040px, 100%);
      }
      .studio-user-bubble {
        border-color: #5a5a5a;
        border-radius: 999px;
        background: #3b3b3b;
        padding: 13px 18px;
      }
      .studio-user-bubble .studio-chat-turn__meta {
        display: none;
      }
      .studio-assistant-answer-card {
        border: 0;
        background: transparent;
        padding: 8px 0 0;
      }
      .studio-assistant-answer-card .studio-chat-turn__meta {
        display: none;
      }
      .studio-markdown {
        color: var(--studio-text);
        line-height: 1.58;
      }
      .studio-markdown > *:first-child {
        margin-top: 0;
      }
      .studio-markdown > *:last-child {
        margin-bottom: 0;
      }
      .studio-markdown p,
      .studio-markdown ul,
      .studio-markdown ol,
      .studio-markdown blockquote,
      .studio-markdown pre,
      .studio-markdown table {
        margin: 0 0 12px;
      }
      .studio-markdown p {
        color: var(--studio-text);
      }
      .studio-markdown h1,
      .studio-markdown h2,
      .studio-markdown h3,
      .studio-markdown h4 {
        margin: 18px 0 8px;
        color: var(--studio-text);
        font-weight: 700;
        letter-spacing: 0;
      }
      .studio-markdown h1 {
        font-size: 24px;
      }
      .studio-markdown h2 {
        font-size: 20px;
      }
      .studio-markdown h3 {
        font-size: 17px;
      }
      .studio-markdown h4 {
        font-size: 15px;
      }
      .studio-markdown ul,
      .studio-markdown ol {
        padding-left: 22px;
      }
      .studio-markdown li {
        margin: 5px 0;
      }
      .studio-markdown li > p {
        margin: 0;
      }
      .studio-markdown code {
        border-radius: 4px;
        background: #383838;
        padding: 1px 5px;
        color: #e8e8e8;
        font-family: var(--vscode-editor-font-family, ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace);
        font-size: .92em;
      }
      .studio-markdown pre {
        max-width: 100%;
        overflow: auto;
        border: 1px solid var(--studio-border);
        border-radius: 7px;
        background: #101010;
        padding: 12px;
      }
      .studio-markdown pre code {
        display: block;
        min-width: max-content;
        border-radius: 0;
        background: transparent;
        padding: 0;
        white-space: pre;
      }
      .studio-markdown a {
        color: var(--studio-accent);
        text-decoration: none;
      }
      .studio-markdown a:hover {
        text-decoration: underline;
      }
      .studio-markdown blockquote {
        border-left: 2px solid var(--studio-border-strong);
        padding-left: 12px;
        color: var(--studio-muted);
      }
      .studio-markdown table {
        width: 100%;
        border-collapse: collapse;
        font-size: 13px;
      }
      .studio-markdown th,
      .studio-markdown td {
        border: 1px solid var(--studio-border);
        padding: 6px 8px;
        text-align: left;
        vertical-align: top;
      }
      .studio-markdown th {
        background: #242424;
        color: var(--studio-text);
      }
      .studio-markdown hr {
        border: 0;
        border-top: 1px solid var(--studio-border);
        margin: 16px 0;
      }
      .studio-run-status-bar {
        width: 100%;
        min-height: 38px;
        border: 1px solid #7b7b7b;
        border-radius: 7px;
        background: #080808;
        padding: 0;
        color: var(--studio-text);
      }
      .studio-run-status-bar summary {
        display: flex;
        align-items: center;
        gap: 10px;
        min-height: 38px;
        padding: 0 12px;
        cursor: pointer;
        list-style: none;
      }
      .studio-run-status-bar summary::-webkit-details-marker {
        display: none;
      }
      .studio-run-status-bar summary::after {
        content: "›";
        margin-left: auto;
        color: var(--studio-muted);
      }
      .studio-run-status-bar[open] summary::after {
        transform: rotate(90deg);
      }
      .studio-run-status-bar__check {
        color: #4fa3ff;
      }
      .studio-run-status-bar__details {
        display: grid;
        gap: 7px;
        margin: 0;
        border-top: 1px solid #242424;
        padding: 8px 14px 12px 34px;
        color: var(--studio-muted);
        line-height: 1.5;
      }
      .studio-run-status-bar button {
        margin-left: auto;
        border: 0;
        background: transparent;
        color: var(--studio-muted);
      }
      .studio-run-status-bar .studio-verified-badge {
        margin-left: auto;
      }
      .studio-run-status-bar .studio-verified-badge + button {
        margin-left: 0;
      }
      .studio-managed-sessions {
        display: grid;
        gap: 10px;
        margin-top: 10px;
      }
      .studio-managed-session-card {
        display: grid;
        gap: 10px;
        width: min(100%, 620px);
        border: 1px solid #3e5f7e;
        border-radius: 7px;
        background: #050607;
        padding: 10px;
        color: var(--studio-text);
      }
      .studio-managed-session-card__header {
        display: grid;
        grid-template-columns: auto minmax(0, 1fr) auto;
        align-items: center;
        gap: 10px;
      }
      .studio-managed-session-card__header div {
        display: grid;
        gap: 2px;
        min-width: 0;
      }
      .studio-managed-session-card__header strong,
      .studio-managed-session-preview__body strong {
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
      }
      .studio-managed-session-card__header span,
      .studio-managed-session-preview__body span {
        overflow: hidden;
        color: var(--studio-muted);
        text-overflow: ellipsis;
        white-space: nowrap;
      }
      .studio-managed-session-card__header button,
      .studio-managed-session-controls button {
        min-height: 28px;
        border: 1px solid #4e4e4e;
        border-radius: 6px;
        background: #151515;
        color: var(--studio-text);
      }
      .studio-managed-session-preview {
        display: grid;
        overflow: hidden;
        min-height: 118px;
        border: 1px solid #2a2a2a;
        border-radius: 6px;
        background: #101417;
      }
      .studio-managed-session-preview__chrome {
        display: flex;
        gap: 5px;
        align-items: center;
        height: 24px;
        border-bottom: 1px solid #2d353c;
        background: #171d22;
        padding: 0 9px;
      }
      .studio-managed-session-preview__chrome span {
        width: 7px;
        height: 7px;
        border-radius: 50%;
        background: #66727c;
      }
      .studio-managed-session-preview__body {
        display: grid;
        align-content: center;
        gap: 8px;
        min-width: 0;
        min-height: 90px;
        padding: 12px 14px;
        background:
          linear-gradient(90deg, rgba(79, 163, 255, 0.12) 1px, transparent 1px),
          linear-gradient(rgba(79, 163, 255, 0.08) 1px, transparent 1px),
          #080b0e;
        background-size: 18px 18px;
      }
      .studio-managed-session-preview__body mark {
        width: fit-content;
        border: 1px solid #a47620;
        border-radius: 999px;
        background: rgba(164, 118, 32, 0.16);
        color: #ffcf77;
        padding: 2px 8px;
      }
      .studio-managed-session-expanded {
        display: none;
        gap: 10px;
      }
      .studio-managed-session-card.is-expanded .studio-managed-session-expanded {
        display: grid;
      }
      .studio-managed-session-expanded p {
        margin: 0;
        color: var(--studio-muted);
      }
      .studio-managed-session-mode-labels,
      .studio-managed-session-controls {
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
        align-items: center;
      }
      .studio-managed-session-mode-labels span {
        border: 1px solid #3e3e3e;
        border-radius: 999px;
        color: var(--studio-muted);
        padding: 3px 9px;
      }
      .studio-managed-session-mode-labels span.is-active,
      .studio-managed-session-controls button.is-active {
        border-color: #4fa3ff;
        color: #ffffff;
      }
      .studio-conversation-artifacts {
        display: grid;
        gap: 10px;
        margin-top: 14px;
      }
      .studio-visually-hidden {
        position: absolute;
        width: 1px;
        height: 1px;
        overflow: hidden;
        clip: rect(0 0 0 0);
        white-space: nowrap;
      }
      .studio-conversation-artifact-card {
        display: grid;
        gap: 10px;
        width: min(100%, 680px);
        border: 1px solid #2f4358;
        border-radius: 7px;
        background: #080b0e;
        padding: 12px;
        color: var(--studio-text);
      }
      .studio-conversation-artifact-card__header {
        display: grid;
        grid-template-columns: minmax(0, 1fr) auto;
        gap: 10px;
        align-items: center;
      }
      .studio-conversation-artifact-card__header div {
        display: grid;
        gap: 3px;
        min-width: 0;
      }
      .studio-conversation-artifact-card__header span,
      .studio-conversation-artifact-compact span,
      .studio-conversation-artifact-meta span,
      .studio-conversation-artifact-preview span,
      .studio-conversation-artifact-compare span {
        overflow: hidden;
        color: var(--studio-muted);
        text-overflow: ellipsis;
        white-space: nowrap;
      }
      .studio-conversation-artifact-card__header strong,
      .studio-conversation-artifact-compact strong {
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
      }
      .studio-conversation-artifact-card button {
        min-height: 28px;
        border: 1px solid #4e4e4e;
        border-radius: 6px;
        background: #151515;
        color: var(--studio-text);
      }
      .studio-conversation-artifact-preview,
      .studio-conversation-artifact-compare,
      .studio-conversation-artifact-fidelity {
        display: grid;
        gap: 5px;
        border: 1px solid #2d3642;
        border-radius: 6px;
        background: #101417;
        padding: 12px;
      }
      .studio-conversation-artifact-compact {
        display: grid;
        gap: 10px;
      }
      .studio-conversation-artifact-compact__status {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 10px;
        min-width: 0;
      }
      .studio-conversation-artifact-preview {
        overflow: hidden;
        padding: 0;
        background: #f5f7fb;
      }
      .studio-conversation-artifact-preview--compact {
        height: 220px;
      }
      .studio-conversation-artifact-preview--expanded {
        height: min(58vh, 520px);
      }
      .studio-conversation-artifact-preview--placeholder {
        height: auto;
        padding: 12px;
        background: #101417;
      }
      .studio-conversation-artifact-frame {
        display: block;
        width: 100%;
        height: 100%;
        border: 0;
        background: #ffffff;
      }
      .studio-conversation-artifact-source-preview {
        width: 100%;
        max-height: 420px;
        margin: 0;
        overflow: auto;
        padding: 14px;
        color: #dce7f2;
        background: #0c1014;
        white-space: pre-wrap;
      }
      .studio-conversation-artifact-expanded {
        display: none;
        gap: 10px;
      }
      .studio-conversation-artifact-card.is-expanded .studio-conversation-artifact-expanded {
        display: grid;
      }
      .studio-conversation-artifact-expanded p {
        margin: 0;
        color: var(--studio-muted);
      }
      .studio-conversation-artifact-meta,
      .studio-conversation-artifact-actions {
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
        align-items: center;
      }
      .studio-conversation-artifact-meta span {
        border: 1px solid #3e3e3e;
        border-radius: 999px;
        padding: 3px 9px;
      }
      .studio-answer-actions {
        display: flex;
        align-items: center;
        flex-wrap: wrap;
        gap: 8px;
        margin-top: 12px;
      }
      .studio-answer-actions button {
        min-height: 28px;
        border-radius: 999px;
        padding: 3px 10px;
      }
      .studio-work-record {
        display: grid;
        gap: 8px;
        margin: 12px 0 0;
        padding: 0;
        list-style: none;
        color: var(--studio-muted);
      }
      .studio-work-record li {
        position: relative;
        padding-left: 18px;
      }
      .studio-work-record li::before {
        content: "";
        position: absolute;
        left: 2px;
        top: .65em;
        width: 5px;
        height: 5px;
        border-radius: 999px;
        background: #6ea8fe;
      }
      .studio-view-trace-link {
        color: #9dc6ff;
      }
      .studio-verified-badge {
        display: inline-flex;
        align-items: center;
        min-height: 22px;
        border-radius: 999px;
        padding: 0 8px;
        background: rgba(127, 209, 165, .12);
        color: var(--studio-good);
        font-size: 12px;
        font-weight: 600;
        white-space: nowrap;
      }
      .studio-verified-badge--unverified {
        background: rgba(231, 191, 98, .12);
        color: var(--studio-warn);
      }
      .studio-compact-runtime-list {
        display: grid;
        gap: 8px;
        max-width: min(1040px, 100%);
      }
      .studio-compact-runtime-card {
        display: grid;
        grid-template-columns: minmax(0, 1fr) auto auto;
        align-items: center;
        gap: 10px;
        border: 1px solid rgba(255, 255, 255, .18);
        border-radius: 7px;
        background: rgba(255, 255, 255, .035);
        padding: 8px 10px;
      }
      .studio-compact-runtime-card--blocking {
        border-color: rgba(231, 191, 98, .45);
      }
      .studio-compact-runtime-card > div {
        display: flex;
        align-items: center;
        gap: 8px;
        min-width: 0;
      }
      .studio-compact-runtime-card strong,
      .studio-compact-runtime-card span:not(.studio-status-dot):not(.studio-verified-badge) {
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
      }
      .studio-compact-runtime-card span:not(.studio-status-dot):not(.studio-verified-badge) {
        color: var(--studio-muted);
      }
      .studio-compact-runtime-card button {
        min-height: 26px;
        padding: 2px 9px;
      }
      .studio-composer {
        border-top: 0;
        background: #050505;
        padding: 10px 24px 14px;
      }
      .studio-tauri-composer {
        width: min(760px, 100%);
        margin: 0 auto;
        border: 1px solid #6a6a6a;
        border-radius: 4px;
        background: #121212;
        padding: 8px 10px 10px;
      }
      .studio-composer-context-row {
        display: flex;
        align-items: center;
        justify-content: flex-start;
        min-height: 24px;
        margin-bottom: 6px;
      }
      .studio-tauri-composer textarea {
        min-height: 48px;
        max-height: 170px;
        border: 0;
        border-radius: 0;
        background: transparent;
        padding: 0;
      }
      .studio-composer-toolbar {
        display: flex;
        align-items: center;
        gap: 2px;
        justify-content: flex-start;
        margin-top: 8px;
      }
      .studio-icon-toggle,
      .studio-mode-toggle,
      .studio-send-icon,
      .studio-stop-icon-button {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        gap: 5px;
        min-height: 24px;
        border-radius: 3px;
        line-height: 1;
      }
      .studio-context-btn {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        gap: 5px;
        min-height: 24px;
        padding: 0 8px;
        border-radius: 3px;
        line-height: 1;
      }
      .studio-composer-context-row .studio-context-btn {
        min-height: 18px;
        padding: 0 2px;
        border-color: var(--studio-border);
        background: transparent;
        color: var(--studio-muted);
      }
      .studio-composer-context-row .studio-context-btn:hover {
        border-color: var(--studio-border-strong);
        background: transparent;
        color: var(--studio-text);
      }
      .studio-composer-toolbar .studio-icon-toggle,
      .studio-composer-toolbar .studio-mode-toggle {
        border-color: transparent;
        background: transparent;
        color: var(--studio-muted);
      }
      .studio-composer-toolbar .studio-icon-toggle:hover,
      .studio-composer-toolbar .studio-mode-toggle:hover,
      .studio-composer-toolbar .studio-icon-toggle:focus-visible,
      .studio-composer-toolbar .studio-mode-toggle:focus-visible {
        border-color: transparent;
        background: rgba(255, 255, 255, 0.08);
        color: var(--studio-text);
        outline: none;
      }
      .studio-context-btn__icon,
      .studio-icon-toggle__glyph {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        width: 13px;
        height: 13px;
        flex: 0 0 auto;
      }
      .studio-icon-toggle__chevron {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        width: 9px;
        height: 9px;
        flex: 0 0 auto;
        color: var(--studio-muted);
      }
      .studio-source-icon {
        display: block;
        width: 13px;
        height: 13px;
      }
      .studio-source-icon--lucide {
        width: 13px;
        height: 13px;
      }
      .studio-source-icon[data-tauri-codicon="chevron-down"] {
        width: 9px;
        height: 9px;
      }
      .studio-icon-toggle {
        width: 28px;
        min-width: 28px;
        height: 22px;
        min-height: 22px;
        padding: 0 4px;
      }
      .studio-mode-toggle {
        min-width: 48px;
        height: 22px;
        min-height: 22px;
        padding: 0 5px;
      }
      .studio-permissions-toggle {
        min-width: 136px;
        max-width: 180px;
      }
      .studio-permissions-toggle > span:first-child {
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
      }
      .studio-send-icon {
        width: 28px;
        min-width: 28px;
        height: 28px;
        padding: 0;
        border-color: #1f6feb;
        background: #0e639c;
      }
      .studio-stop-icon-button {
        width: 30px;
        min-width: 30px;
        height: 30px;
        padding: 0;
      }
      .studio-utility-drawer {
        position: relative;
        overflow: hidden;
        padding: 0;
        background: #151515;
      }
      .studio-utility-toggle {
        width: 100%;
        height: 100%;
        min-height: 100vh;
        border: 0;
        border-radius: 0;
        writing-mode: vertical-rl;
        text-orientation: mixed;
        background: #111;
        color: var(--studio-muted);
      }
      .studio-utility-drawer__content {
        display: none;
        height: 100%;
        overflow: auto;
        padding: 16px;
      }
      .studio-utility-drawer.is-expanded {
        overflow: auto;
      }
      .studio-utility-drawer.is-expanded .studio-utility-toggle {
        position: sticky;
        top: 0;
        z-index: 2;
        width: 100%;
        height: 34px;
        min-height: 34px;
        writing-mode: horizontal-tb;
        text-align: left;
      }
      .studio-utility-drawer.is-expanded .studio-utility-drawer__content {
        display: grid;
        gap: 14px;
      }
      .studio-utility-drawer section,
      .studio-utility-drawer .studio-approval,
      .studio-utility-drawer .studio-diff-hunk {
        margin-top: 0;
      }
      .studio-operator-context ol,
      .studio-operator-context ul {
        margin: 0;
        padding: 0;
        list-style: none;
        display: grid;
        gap: 9px;
      }
      .studio-operator-context li {
        display: grid;
        gap: 3px;
      }
      .studio-status-dot {
        width: 8px;
        height: 8px;
        border-radius: 50%;
        display: inline-block;
        margin-right: 7px;
        background: var(--studio-accent);
      }
      .studio-status-dot--pending {
        background: var(--studio-warn);
      }
      .studio-status-dot--blocked,
      .studio-status-dot--failed {
        background: var(--studio-danger);
      }
      .studio-status-dot--completed,
      .studio-status-dot--ready {
        background: var(--studio-good);
      }
      .studio-approval {
        display: flex;
        justify-content: space-between;
        gap: 10px;
      }
      mark {
        border-radius: 999px;
        padding: 2px 7px;
        background: rgba(127, 209, 165, .12);
        color: var(--studio-good);
      }
      code {
        color: #b7d4ff;
        word-break: break-all;
      }
      .studio-diff-hunk {
        margin-top: 10px;
      }
      .studio-diff-hunk header,
      .studio-diff-hunk footer {
        display: flex;
        gap: 8px;
        align-items: center;
        flex-wrap: wrap;
      }
      .studio-diff-hunk pre {
        margin: 10px 0;
        overflow: auto;
        padding: 10px;
        border-radius: 5px;
        background: #111;
        white-space: pre-wrap;
      }
      .studio-diff-remove {
        display: block;
        color: #ffb1b9;
      }
      .studio-diff-add {
        display: block;
        color: #a3e6bd;
      }
      .studio-cockpit-card {
        display: grid;
        gap: 8px;
        border: 1px solid var(--studio-border);
        border-radius: 6px;
        background: #202020;
        padding: 10px;
      }
      .studio-cockpit-card + .studio-cockpit-card {
        margin-top: 8px;
      }
      .studio-cockpit-card header,
      .studio-cockpit-card footer {
        display: flex;
        align-items: center;
        gap: 8px;
        min-width: 0;
      }
      .studio-cockpit-card header mark {
        margin-left: auto;
      }
      .studio-cockpit-card dl {
        display: grid;
        grid-template-columns: max-content minmax(0, 1fr);
        gap: 5px 10px;
        margin: 0;
      }
      .studio-cockpit-card dt {
        color: var(--studio-muted);
        font-size: 12px;
      }
      .studio-cockpit-card dd {
        margin: 0;
        min-width: 0;
      }
      .studio-command-output-card pre {
        max-height: 180px;
        margin: 0;
        overflow: auto;
        border-radius: 5px;
        background: #0c0c0c;
        padding: 9px;
        color: #d6e4ff;
        white-space: pre-wrap;
      }
      .studio-command-output-card .studio-command-stderr {
        color: #ffb1b9;
      }
      .studio-replay-steps {
        margin-top: 12px;
        padding-top: 12px;
        border-top: 1px solid var(--studio-border);
      }
      @media (max-width: 980px) {
        .studio-operational-shell {
          grid-template-columns: minmax(0, 1fr);
          overflow: auto;
        }
        .studio-operational-rail,
        .studio-operator-context,
        .studio-chat-main {
          min-height: auto;
          overflow: visible;
        }
      }
`;
}

module.exports = { studioPanelStyles };
