// apps/agent-studio/src/services/WebMockRuntime.ts

// Use 'import type' to ensure these are erased at compile time
import type { 
  AgentRuntime, 
  GraphPayload, 
  GraphEvent, 
  ProjectFile, 
  AgentSummary, 
  CacheResult,
  FleetState,
  MarketplaceAgent,
  ConnectorSummary
} from "@ioi/agent-ide";

const MOCK_AGENTS: AgentSummary[] = [
  { id: 'web-1', name: 'Web Scraper', description: 'Extracts data from URLs', icon: '🕷️', model: 'GPT-3.5' },
  { id: 'web-2', name: 'JSON Formatter', description: 'Cleans up messy JSON', icon: '🧹', model: 'Local' },
];

const MOCK_FLEET: FleetState = {
    zones: [
        { id: "akash", name: "Akash Network", type: "cloud", capacity: { used: 12, total: 200, unit: "GPU" }, costPerHour: 0.45 },
    ],
    containers: [
        { id: "c1", name: "remote-worker-1", image: "ioi/worker:latest", zoneId: "akash", status: "running", metrics: { cpu: 45, ram: 30 }, uptime: "4d 2h" }
    ]
};

const MARKET_AGENTS: MarketplaceAgent[] = [
  { id: "a1", name: "DeFi Sentinel", developer: "QuantLabs", price: "$0.05/run", description: "Monitors chain events", requirements: "24GB VRAM" },
  { id: "a2", name: "Legal Reviewer", developer: "LawAI", price: "$29/mo", description: "Contract analysis", requirements: "8GB VRAM" },
  { id: "a3", name: "Research Swarm", developer: "OpenSci", price: "Free", description: "Deep research", requirements: "48GB VRAM" },
  { id: "a4", name: "Video Gen", developer: "CreativeX", price: "$0.10/min", description: "AI Video", requirements: "H100 GPU" },
];

const MOCK_CONNECTORS: ConnectorSummary[] = [
  {
    id: "mail.primary",
    name: "Mail",
    provider: "wallet.network",
    category: "communication",
    description:
      "Mail connector scaffold for delegated agent inbox workflows with bounded wallet session authority.",
    status: "needs_auth",
    authMode: "wallet_network_session",
    scopes: ["mail.read.latest", "mail.read.thread"],
    notes: "Web demo data: auth flow not active in this runtime.",
  },
];

export class WebMockRuntime implements AgentRuntime {
    private eventCallback: ((event: GraphEvent) => void) | null = null;

    async runGraph(payload: GraphPayload): Promise<void> {
        console.log("[WebRuntime] Running graph", payload);
        
        // Simulate execution sequence
        payload.nodes.forEach((node, index) => {
            setTimeout(() => {
                this.emit({
                    node_id: node.id,
                    status: 'running',
                    result: undefined
                });

                setTimeout(() => {
                    this.emit({
                        node_id: node.id,
                        status: 'success',
                        result: {
                            output: `Simulated output for ${node.id}`,
                            metrics: { latency_ms: Math.random() * 500 },
                            input_snapshot: { simulated: true }
                        }
                    });
                }, 1000 + index * 500);
            }, index * 200);
        });
    }

    async stopExecution(): Promise<void> {
        console.log("[WebRuntime] Stop execution");
    }

    async checkNodeCache(_nodeId: string, _config: any, _input: string): Promise<CacheResult | null> {
        return null; // No cache in web demo
    }

    async getAvailableTools(): Promise<any[]> {
        return [
            { name: "web_search", description: "Search Google", parameters: "{}" },
            { name: "calculator", description: "Math ops", parameters: "{}" }
        ];
    }

    async runNode(nodeType: string, config: any, input: string): Promise<any> {
        console.log(`[WebRuntime] Running node ${nodeType}`, { config, input });
        await new Promise(r => setTimeout(r, 800));
        return {
            status: "success",
            output: `Simulated result for ${nodeType}`,
            metrics: { latency_ms: 120 }
        };
    }

    async loadProject(_path?: string): Promise<ProjectFile | null> {
        const saved = localStorage.getItem("last_project");
        return saved ? JSON.parse(saved) : null;
    }

    async saveProject(_path: string, project: ProjectFile): Promise<void> {
        console.log("[WebRuntime] Saving project", project);
        localStorage.setItem("last_project", JSON.stringify(project));
    }

    async getAgents(): Promise<AgentSummary[]> {
        return MOCK_AGENTS;
    }
    
    async getFleetState(): Promise<FleetState> {
        return MOCK_FLEET;
    }

    async getMarketplaceAgents(): Promise<MarketplaceAgent[]> {
        return MARKET_AGENTS;
    }

    async installAgent(agentId: string): Promise<void> {
        console.log("[WebRuntime] Installing agent", agentId);
        // Simulate install delay
        await new Promise(r => setTimeout(r, 1000));
    }

    async getConnectors(): Promise<ConnectorSummary[]> {
        return MOCK_CONNECTORS;
    }

    onEvent(callback: (event: GraphEvent) => void): () => void {
        this.eventCallback = callback;
        return () => { this.eventCallback = null; };
    }

    private emit(event: GraphEvent) {
        if (this.eventCallback) this.eventCallback(event);
    }
}
