import { useEffect, useMemo, useRef } from "react";
import ForceGraph3DFactory from "3d-force-graph";
import type { AtlasNeighborhood } from "../types";

interface ForceNode {
  id: string;
  label: string;
  summary: string;
  color: string;
  val: number;
  x?: number;
  y?: number;
  z?: number;
}

interface ForceLink {
  source: string;
  target: string;
  label: string;
  color: string;
  width: number;
}

interface ForceGraphData {
  nodes: ForceNode[];
  links: ForceLink[];
}

interface ContextAtlasGraph3DProps {
  neighborhood: AtlasNeighborhood;
  onSelectNode?: (nodeId: string) => void;
  maxNodes?: number;
  title?: string;
  badge?: string;
  className?: string;
}

const NODE_COLORS: Record<string, string> = {
  session: "#7dd3fc",
  skill: "#fbbf24",
  tool: "#34d399",
  evidence: "#fb7185",
  published_doc: "#f97316",
  constraint: "#c4b5fd",
  query: "#67e8f9",
  index_root: "#93c5fd",
  proof: "#c084fc",
};

function colorForNode(kind: string): string {
  return NODE_COLORS[kind] || "#94a3b8";
}

function buildGraphData(neighborhood: AtlasNeighborhood, maxNodes: number): ForceGraphData {
  const focusId = neighborhood.focus_id ?? null;
  const rankedNodes = neighborhood.nodes
    .slice()
    .sort((left, right) => {
      if (left.id === focusId) return -1;
      if (right.id === focusId) return 1;
      return (right.emphasis ?? 0) - (left.emphasis ?? 0);
    })
    .slice(0, Math.max(1, maxNodes));

  const allowedIds = new Set(rankedNodes.map((node) => node.id));
  const nodes = rankedNodes.map((node, index) => ({
    id: node.id,
    label: node.label,
    summary: node.summary,
    color: colorForNode(node.kind),
    val: Math.max(1.6, Math.min(9.5, 2 + (node.emphasis ?? 0.4) * 7)),
    x: index % 2 === 0 ? -26 * (index + 1) : 26 * (index + 1),
    y: node.id === focusId ? 0 : (index % 3 === 0 ? -20 : 20),
    z: (index - Math.floor(rankedNodes.length / 2)) * 14,
  }));
  const links = neighborhood.edges
    .filter((edge) => allowedIds.has(edge.source_id) && allowedIds.has(edge.target_id))
    .map((edge) => ({
      source: edge.source_id,
      target: edge.target_id,
      label: edge.summary || edge.relation,
      color: edge.relation === "similar_to" ? "#facc15" : "#94a3b8",
      width: Math.max(0.6, Math.min(2.6, edge.weight || 1)),
    }));

  return { nodes, links };
}

export function ContextAtlasGraph3D({
  neighborhood,
  onSelectNode,
  maxNodes = 48,
  title,
  badge,
  className,
}: ContextAtlasGraph3DProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const graphRef = useRef<any>(null);
  const graphData = useMemo(
    () => buildGraphData(neighborhood, maxNodes),
    [maxNodes, neighborhood],
  );

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    if (!graphRef.current) {
      graphRef.current = ForceGraph3DFactory()(container)
        .backgroundColor("rgba(0,0,0,0)")
        .nodeLabel((node: ForceNode) => `${node.label}\n${node.summary}`)
        .nodeColor((node: ForceNode) => node.color)
        .nodeVal((node: ForceNode) => node.val)
        .nodeOpacity(0.94)
        .linkColor((link: ForceLink) => link.color)
        .linkWidth((link: ForceLink) => link.width)
        .linkOpacity(0.28)
        .linkLabel((link: ForceLink) => link.label)
        .linkDirectionalParticles(1)
        .linkDirectionalParticleWidth(1.2)
        .linkDirectionalParticleSpeed(0.0032)
        .showNavInfo(false)
        .cooldownTicks(80)
        .onNodeClick((node: { id: string; x?: number; y?: number; z?: number }) => {
          if (onSelectNode) {
            onSelectNode(node.id);
          }
          if (!graphRef.current) return;
          const x = typeof node.x === "number" ? node.x : 0;
          const y = typeof node.y === "number" ? node.y : 0;
          const z = typeof node.z === "number" ? node.z : 0;
          graphRef.current.centerAt(x, y, 650);
          graphRef.current.cameraPosition({ x, y, z: z + 95 }, { x, y, z }, 900);
        });
    }

    const setSize = () => {
      if (!graphRef.current || !container) return;
      const width = Math.max(280, Math.floor(container.clientWidth || 0));
      const height = Math.max(220, Math.floor(container.clientHeight || 0));
      graphRef.current.width(width);
      graphRef.current.height(height);
    };

    setSize();
    const observer = new ResizeObserver(() => setSize());
    observer.observe(container);
    return () => observer.disconnect();
  }, [onSelectNode]);

  useEffect(() => {
    if (!graphRef.current) return;
    graphRef.current.graphData(graphData);
    graphRef.current.d3AlphaDecay(0.034);
    graphRef.current.d3VelocityDecay(0.26);
    if (graphData.nodes.length > 0) {
      graphRef.current.zoomToFit(700, 56);
    }
  }, [graphData]);

  const resolvedTitle = title || neighborhood.title || "Context Atlas";
  const resolvedBadge =
    badge || `${graphData.nodes.length} nodes · ${graphData.links.length} edges`;

  return (
    <div className={["context-atlas-graph-card", className].filter(Boolean).join(" ")}>
      <div className="context-atlas-graph-head">
        <span className="context-atlas-graph-title">{resolvedTitle}</span>
        <span className="context-atlas-graph-badge">{resolvedBadge}</span>
      </div>
      {graphData.nodes.length === 0 ? (
        <div className="context-atlas-graph-empty">No graph context available for this scope.</div>
      ) : (
        <div className="context-atlas-graph-canvas" ref={containerRef} />
      )}
    </div>
  );
}
