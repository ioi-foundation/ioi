# IOI Runtime

A native desktop agent runtime built with Tauri. Provides a non-blocking UX for autonomous agent execution with policy gates and cryptographic receipts.

## Architecture

```
IOI Runtime (Tauri)
│
├── System Tray
│   └── Menu: Open Spotlight, Open Studio, Quit
│
├── Windows (Multi-window architecture)
│   │
│   ├── Spotlight Window (⌘+Space)
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
│   └── Studio Window (full IDE)
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

2. **Spotlight**
   - Type intent: "Book a flight to NYC under $400"
   - Press Enter to start agent

3. **Execution**
   - Spotlight closes
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
- [Node.js](https://nodejs.org/) (v18+)
- [Tauri CLI](https://tauri.app/v1/guides/getting-started/prerequisites)

### Setup

```bash
# Install dependencies
npm install

# Run in development
npm run tauri dev

# Build for production
npm run tauri build
```

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
│       ├── SpotlightWindow.tsx
│       ├── PillWindow.tsx
│       ├── GateWindow.tsx
│       └── StudioWindow.tsx
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
- **Transparent**: Spotlight, Pill, Gate windows have transparent backgrounds
- **Always on Top**: Overlay windows stay above other apps
- **Frameless**: No window decorations for overlay windows
- **Skip Taskbar**: Overlay windows don't appear in taskbar

### Global Shortcut
- `⌘+Space` (macOS) / `Ctrl+Space` (Windows/Linux) toggles Spotlight
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
