# Architectural Improvements Broad Checklist

Status: passed
Complete: 21/21

| ID | Lane | Status | Evidence |
| --- | --- | --- | --- |
| A1 | capability-tier contract | Complete | crates/types/src/app/runtime_contracts.rs<br>crates/services/src/agentic/runtime/tools/contracts.rs |
| A2 | retired capability aliases | Complete | crates/types/src/app/runtime_contracts.rs |
| B1 | daemon SDK route coverage | Complete | packages/agent-sdk/src/substrate-client.ts |
| B2 | event streaming and reconnect transport | Complete | packages/agent-sdk/src/substrate-client.ts<br>packages/runtime-daemon/src/index.mjs |
| B3 | live local daemon service | Complete | packages/runtime-daemon/src/index.mjs |
| C1 | SDK live bridge default | Complete | packages/agent-sdk/src/substrate-client.ts |
| C2 | SDK public live surface | Complete | packages/agent-sdk/src/agent.ts<br>packages/agent-sdk/src/substrate-client.ts<br>packages/agent-sdk/src/messages.ts |
| C3 | SDK mock boundary | Complete | packages/agent-sdk/src/index.ts<br>packages/agent-sdk/src/testing.ts |
| D1 | event golden behavior | Complete | packages/agent-sdk/test/sdk.test.mjs |
| E1 | tool catalog contract | Complete | packages/agent-sdk/src/substrate-client.ts<br>packages/agent-sdk/src/messages.ts |
| F1 | MCP skills hooks provenance | Complete | packages/agent-sdk/src/substrate-client.ts |
| G1 | subagent execution surface | Complete | packages/agent-sdk/src/agent.ts<br>packages/agent-sdk/test/sdk.test.mjs |
| H1 | runtime catalogs | Complete | packages/agent-sdk/src/substrate-client.ts<br>packages/agent-sdk/test/sdk.test.mjs |
| I1 | canonical persistence boundary | Complete | docs/plans/architectural-improvements-broad-master-guide.md<br>packages/agent-sdk/src/substrate-client.ts<br>packages/runtime-daemon/src/index.mjs |
| I2 | Agentgres canonical live proof | Complete | packages/runtime-daemon/src/index.mjs<br>scripts/evidence/runtime-complete-plus.mjs |
| J1 | CLI remains client | Complete | crates/cli/src/commands/agent.rs |
| K1 | hosted/self-hosted provider shape | Complete | packages/agent-sdk/src/options.ts |
| L1 | GUI and workflow substrate guardrails | Complete | packages/agent-ide/src/WorkflowComposer/controller.tsx |
| M1 | smarter-agent behavioral projections | Complete | packages/agent-sdk/src/messages.ts |
| Z1 | public vocabulary and retired product names | Complete | apps/developers-ioi-ai/src/content/docs.tsx<br>crates/types/src/app/chat.rs |
| Z2 | repeatable validation commands | Complete | package.json |
