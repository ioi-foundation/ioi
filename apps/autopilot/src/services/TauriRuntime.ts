// apps/autopilot/src/services/TauriRuntime.ts
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { 
  AgentRuntime, GraphPayload, GraphEvent, ProjectFile, AgentSummary, 
  FleetState, Zone, Container, MarketplaceAgent, ConnectorSummary
} from "@ioi/agent-ide";

// Mock Data
const MOCK_AGENTS: AgentSummary[] = [
  { id: 'a1', name: 'Invoice Analyst', description: 'Parses PDF invoices', icon: '📄', model: 'GPT-4o' },
  { id: 'a2', name: 'Support Triager', description: 'Routes incoming tickets', icon: '📞', model: 'Claude 3.5' },
];

const INITIAL_ZONES: Zone[] = [
  { id: "local", name: "Local (Mac Studio)", type: "local", capacity: { used: 14, total: 64, unit: "GB" }, costPerHour: 0.00 },
  { id: "akash", name: "Akash Network (gpu-1)", type: "cloud", capacity: { used: 22, total: 48, unit: "VRAM" }, costPerHour: 0.45 },
];

const INITIAL_CONTAINERS: Container[] = [
  { id: "c1", name: "research-worker-a", image: "ioi/researcher:v1.2", zoneId: "local", status: "running", metrics: { cpu: 12, ram: 24 }, uptime: "2h 14m" },
  { id: "c3", name: "video-gen-worker", image: "ioi/creative:v0.9", zoneId: "akash", status: "running", metrics: { cpu: 88, ram: 60, vram: 92 }, uptime: "15m" },
];

const MARKET_AGENTS: MarketplaceAgent[] = [
  { id: "a1", name: "DeFi Sentinel", developer: "QuantLabs", price: "$0.05/run", description: "Monitors chain events", requirements: "24GB VRAM" },
  { id: "a2", name: "Legal Reviewer", developer: "LawAI", price: "$29/mo", description: "Contract analysis", requirements: "8GB VRAM" },
  { id: "a3", name: "Research Swarm", developer: "OpenSci", price: "Free", description: "Deep research", requirements: "48GB VRAM" },
  { id: "a4", name: "Video Gen", developer: "CreativeX", price: "$0.10/min", description: "AI Video", requirements: "H100 GPU" },
];

const CONNECTORS: ConnectorSummary[] = [
  {
    id: "mail.primary",
    name: "Mail",
    provider: "wallet.network",
    category: "communication",
    description:
      "Planned first wallet_network integration. Enables inbox listing and latest-email read under delegated wallet session policy.",
    status: "needs_auth",
    authMode: "wallet_network_session",
    scopes: ["mail.read.latest", "mail.read.thread"],
    notes:
      "E2E target: request session channel, approve bounded read lease, perform check-inbox and read-latest-email ops.",
  },
  {
    id: "calendar.primary",
    name: "Calendar",
    provider: "wallet.network",
    category: "productivity",
    description: "Scaffold for calendar operations with the same approval and lease model.",
    status: "disabled",
    authMode: "wallet_network_session",
    scopes: ["calendar.read.events"],
  },
];

export class TauriRuntime implements AgentRuntime {
    async runGraph(payload: GraphPayload): Promise<void> {
        await invoke("run_studio_graph", { payload });
    }

    async stopExecution(): Promise<void> {
        await invoke("cancel_task");
    }

    async checkNodeCache(nodeId: string, config: any, input: string): Promise<any> {
        return invoke("check_node_cache", { nodeId, config, input });
    }

    async getAvailableTools(): Promise<any[]> {
        return invoke("get_available_tools");
    }

    async runNode(nodeType: string, config: any, input: string): Promise<any> {
        return invoke("test_node_execution", { 
            nodeType, 
            config, 
            input, 
            nodeId: null, 
            sessionId: null 
        });
    }

    async loadProject(path?: string): Promise<ProjectFile | null> {
        if (!path) return null;
        // @ts-ignore
        return invoke("load_project", { path });
    }

    async saveProject(path: string, project: ProjectFile): Promise<void> {
        await invoke("save_project", { path, project });
    }

    async getAgents(): Promise<AgentSummary[]> {
        return MOCK_AGENTS;
    }

    async getFleetState(): Promise<FleetState> {
        return {
            zones: INITIAL_ZONES,
            containers: INITIAL_CONTAINERS.map(c => ({
                ...c,
                metrics: {
                    cpu: Math.min(100, Math.max(0, c.metrics.cpu + (Math.random() * 10 - 5))),
                    ram: Math.min(100, Math.max(0, c.metrics.ram + (Math.random() * 4 - 2))),
                    vram: c.metrics.vram ? Math.min(100, Math.max(0, c.metrics.vram + (Math.random() * 6 - 3))) : undefined
                }
            }))
        };
    }

    async getMarketplaceAgents(): Promise<MarketplaceAgent[]> {
        return MARKET_AGENTS;
    }

    async installAgent(agentId: string): Promise<void> {
        console.log("Installing agent:", agentId);
        // TODO: Implement backend install logic
    }

    async getConnectors(): Promise<ConnectorSummary[]> {
        return CONNECTORS;
    }

    onEvent(callback: (event: GraphEvent) => void): () => void {
        const unlisten = listen<any>("graph-event", (e) => {
            callback({
                node_id: e.payload.node_id,
                status: e.payload.status,
                result: e.payload.result,
                fitness_score: e.payload.fitness_score,
                generation: e.payload.generation
            });
        });
        
        return () => { unlisten.then(f => f()); };
    }
}
