# IOI Runtime

A native desktop agent runtime built with Tauri. Provides a non-blocking UX for autonomous agent execution with policy gates and cryptographic receipts.

## Architecture

```
IOI Runtime (Tauri)
│
├── System Tray
│   └── Menu: Open Chat Session, Open Chat, Quit
│
├── Windows (Multi-window architecture)
│   │
│   ├── Chat Session Window (⌘+Space)
│   │   ├── Transparent overlay
│   │   ├── Intent input
│   │   └── Quick suggestions
│   │
│   ├── Pill Window (floating)
│   │   ├── Task progress indicator
│   │   ├── Non-blocking (user continues working)
│   │   ├── Expandable for details
│   │   └── Positioned bottom-right
│   │
│   ├── Gate Window (modal)
│   │   ├── Policy gate approval
│   │   ├── Risk level indicator
│   │   ├── Approve/Deny actions
│   │   └── Blocks until resolved
│   │
│   └── Chat Window (full IDE)
│       ├── Agent Builder (intent → workflow)
│       ├── Compose (manual canvas)
│       ├── My Agents / Templates
│       └── Observability (tracing)
│
└── State Management
    ├── Zustand store (React)
    ├── Tauri events (cross-window sync)
    └── Rust backend state
```

## User Flow

1. **Idle State**
   - IOI icon in system tray
   - Press `⌘+Space` (or click tray) to invoke

2. **Chat Session**
   - Type intent: "Book a flight to NYC under $400"
   - Press Enter to start agent

3. **Execution**
   - Chat Session closes
   - Floating pill appears in corner
   - User continues normal work
   - Pill shows: agent name, current step, progress

4. **Policy Gate** (when triggered)
   - Modal appears, demands attention
   - Shows: action description, risk level
   - User must Approve or Deny
   - If denied, task cancelled

5. **Completion**
   - Pill shows checkmark
   - Click to expand receipt details
   - System notification sent
   - Dismiss to clear

## Development

### Prerequisites

- [Rust](https://rustup.rs/)
- [Node.js](https://nodejs.org/) (v20+ LTS recommended)
- [Tauri CLI](https://tauri.app/v1/guides/getting-started/prerequisites)

On Ubuntu/Pop!_OS, install the desktop build dependencies required by Tauri:

```bash
sudo apt update
sudo apt install -y \
  build-essential \
  pkg-config \
  libssl-dev \
  libgtk-3-dev \
  libayatana-appindicator3-dev \
  librsvg2-dev \
  libsoup-3.0-dev \
  libwebkit2gtk-4.1-dev
```

### Setup

```bash
# Install dependencies
npm install

# Run the Electron/VS Code fork in development.
# This also starts a supervised IOI daemon sidecar and projects discovered
# local LM Studio/Ollama model artifacts into Autopilot Models.
npm run dev:desktop

# Validate the direct Workspace shell and retain a GUI receipt bundle
npm run probe:desktop:workspace
```

`npm run dev:desktop` launches the canonical Electron/VS Code fork through
`scripts/launch-autopilot-ide-fork.mjs`. If `IOI_DAEMON_ENDPOINT` is not already
set, the launcher syncs the current `ioi-workbench` extension into the packaged
fork, starts an IOI daemon sidecar, grants the workbench a scoped daemon token,
asks the daemon to discover local model providers, mounts discovered local
models as daemon endpoints, and passes the daemon endpoint/token to
`ioi-workbench`. Set `AUTOPILOT_SKIP_EXTENSION_SYNC=1` to skip extension sync,
`AUTOPILOT_SKIP_DAEMON=1` to opt out of daemon startup, or
`AUTOPILOT_SKIP_MODEL_AUTODISCOVERY=1` to start the daemon without local model
discovery. The `ide/vscode` source checkout is optional for this launch path;
the required runtime artifact is the packaged Electron app at
`ide/builds/VSCode-linux-x64` or `AUTOPILOT_VSCODE_PACKAGED_ROOT`.

### Project Structure

```
ioi-runtime/
├── src/                    # React frontend
│   ├── main.tsx           # Entry point with routing
│   ├── store/             # Zustand state management
│   │   └── agentStore.ts  # Agent task state
│   ├── styles/            # Global styles
│   │   └── global.css
│   └── windows/           # Window components
│       ├── ChatShellWindow/index.tsx
│       ├── PillWindow.tsx
│       ├── GateWindow.tsx
│       └── ChatWindow.tsx
│
├── src-tauri/             # Rust backend
│   ├── Cargo.toml         # Rust dependencies
│   ├── tauri.conf.json    # Tauri configuration
│   ├── icons/             # App icons
│   └── src/
│       └── main.rs        # Window management, tray, shortcuts
│
├── package.json
├── vite.config.ts
└── tsconfig.json
```

## Key Features

### Multi-Window Architecture
Each UI surface is a separate Tauri window:
- **Transparent**: Chat Session, Pill, Gate windows have transparent backgrounds
- **Always on Top**: Overlay windows stay above other apps
- **Frameless**: No window decorations for overlay windows
- **Skip Taskbar**: Overlay windows don't appear in taskbar

### Global Shortcut
- `⌘+Space` (macOS) / `Ctrl+Space` (Windows/Linux) toggles Chat Session
- Registered at OS level, works from any app

### Cross-Window Communication
- Tauri events broadcast state changes to all windows
- Zustand store syncs state within each window
- Rust backend maintains authoritative state

### Policy Gates
- IOI's core safety primitive
- Agent pauses at defined checkpoints
- User must approve before high-risk actions
- Risk levels: LOW (green), MEDIUM (amber), HIGH (red)

### Receipts
- Cryptographic proof of execution
- Records: duration, action count, cost
- Audit trail for all agent actions

## License

MIT
