import { useEffect, useMemo, useRef } from "react";
import ForceGraph3DFactory from "3d-force-graph";
import type { SubstrateReceiptRow } from "./ArtifactHubViews";

type GraphNodeKind =
  | "query"
  | "index"
  | "candidates"
  | "rerank"
  | "topk"
  | "proof"
  | "certificate";

interface GraphNode {
  id: string;
  kind: GraphNodeKind;
  label: string;
  val: number;
  color: string;
  z: number;
  x?: number;
  y?: number;
}

interface GraphLink {
  source: string;
  target: string;
  label: string;
  color: string;
}

interface GraphData {
  nodes: GraphNode[];
  links: GraphLink[];
}

const NODE_COLORS: Record<GraphNodeKind, string> = {
  query: "#8be9fd",
  index: "#6272a4",
  candidates: "#ffb86c",
  rerank: "#69f0ae",
  topk: "#ff79c6",
  proof: "#bd93f9",
  certificate: "#ffb86c",
};

function safeParseMs(value: string): number {
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? 0 : parsed;
}

function metricShortLabel(metric: string): string {
  const normalized = metric.trim().toLowerCase();
  if (normalized === "cosine_distance") return "cos";
  if (normalized === "euclidean" || normalized === "l2") return "l2";
  if (!normalized) return "metric";
  return normalized;
}

function boundedVal(raw: number, min = 1.5, max = 12): number {
  if (!Number.isFinite(raw)) return min;
  return Math.max(min, Math.min(max, raw));
}

function buildGraphData(
  receipts: SubstrateReceiptRow[],
  maxReceipts: number,
): GraphData {
  const sorted = receipts
    .slice()
    .sort((a, b) => safeParseMs(a.timestamp) - safeParseMs(b.timestamp))
    .slice(-Math.max(1, maxReceipts));

  const nodes = new Map<string, GraphNode>();
  const links: GraphLink[] = [];
  let previousTopNode: string | null = null;

  const addNode = (node: GraphNode) => {
    if (!nodes.has(node.id)) {
      nodes.set(node.id, node);
    }
  };

  const addLink = (
    source: string,
    target: string,
    label: string,
    color: string,
  ) => {
    links.push({ source, target, label, color });
  };

  sorted.forEach((receipt, idx) => {
    const z = idx * 18;
    const lateral = idx % 2 === 0 ? -40 : 40;
    const qNodeId = `query:${receipt.eventId}`;
    const idxNodeId = `index:${receipt.eventId}`;
    const candNodeId = `candidates:${receipt.eventId}`;
    const rerankNodeId = `rerank:${receipt.eventId}`;
    const topNodeId = `topk:${receipt.eventId}`;

    addNode({
      id: qNodeId,
      kind: "query",
      label: `query ${receipt.stepIndex} · ${receipt.k}`,
      val: 3,
      color: NODE_COLORS.query,
      x: lateral,
      y: -20,
      z,
    });
    addNode({
      id: idxNodeId,
      kind: "index",
      label: `index ${receipt.indexRoot.slice(0, 10)}…`,
      val: 3.4,
      color: NODE_COLORS.index,
      x: lateral + 10,
      y: 20,
      z,
    });
    addNode({
      id: candNodeId,
      kind: "candidates",
      label: `C=${receipt.candidateTotal}/${receipt.candidateLimit}`,
      val: boundedVal(2 + receipt.candidateTotal / 12),
      color: NODE_COLORS.candidates,
      x: lateral + 48,
      y: -8,
      z: z + 4,
    });
    addNode({
      id: rerankNodeId,
      kind: "rerank",
      label: `rerank=${receipt.candidateReranked}`,
      val: boundedVal(2 + receipt.candidateReranked / 10),
      color: NODE_COLORS.rerank,
      x: lateral + 78,
      y: 18,
      z: z + 6,
    });
    addNode({
      id: topNodeId,
      kind: "topk",
      label: `top-k=${receipt.k} · ${metricShortLabel(receipt.distanceMetric)}`,
      val: boundedVal(2 + receipt.k / 2, 1.8, 9),
      color: NODE_COLORS.topk,
      x: lateral + 106,
      y: -12,
      z: z + 8,
    });

    addLink(qNodeId, idxNodeId, "lookup", "#6272a4");
    addLink(idxNodeId, candNodeId, "candidate gen", "#ffb86c");
    addLink(candNodeId, rerankNodeId, "exact rerank", "#69f0ae");
    addLink(rerankNodeId, topNodeId, "select top-k", "#ff79c6");

    if (receipt.proofHash || receipt.proofRef) {
      const proofNodeId = `proof:${receipt.eventId}`;
      addNode({
        id: proofNodeId,
        kind: "proof",
        label: `proof ${receipt.proofHash?.slice(0, 10) || "ref"}…`,
        val: 2.3,
        color: NODE_COLORS.proof,
        x: lateral + 128,
        y: 18,
        z: z + 10,
      });
      addLink(topNodeId, proofNodeId, "trace proof", "#bd93f9");
    }

    if (receipt.certificateMode && receipt.certificateMode !== "none") {
      const certNodeId = `cert:${receipt.eventId}`;
      addNode({
        id: certNodeId,
        kind: "certificate",
        label: `cert=${receipt.certificateMode}`,
        val: 2.2,
        color: NODE_COLORS.certificate,
        x: lateral + 148,
        y: -18,
        z: z + 12,
      });
      addLink(topNodeId, certNodeId, "lb cert", "#ffb86c");
    }

    if (previousTopNode) {
      addLink(previousTopNode, qNodeId, "next introspection", "#6c7896");
    }
    previousTopNode = topNodeId;
  });

  return {
    nodes: Array.from(nodes.values()),
    links,
  };
}

interface SubstrateGlassBoxProps {
  receipts: SubstrateReceiptRow[];
  maxReceipts?: number;
}

export function SubstrateGlassBox({
  receipts,
  maxReceipts = 24,
}: SubstrateGlassBoxProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const graphRef = useRef<any>(null);
  const graphData = useMemo(
    () => buildGraphData(receipts, maxReceipts),
    [maxReceipts, receipts],
  );

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    if (!graphRef.current) {
      const graph = ForceGraph3DFactory()(container)
        .backgroundColor("rgba(0,0,0,0)")
        .nodeLabel((node: GraphNode) => node.label)
        .nodeColor((node: GraphNode) => node.color)
        .nodeVal((node: GraphNode) => node.val)
        .nodeOpacity(0.94)
        .linkColor((link: GraphLink) => link.color)
        .linkLabel((link: GraphLink) => link.label)
        .linkOpacity(0.42)
        .linkDirectionalParticles(1)
        .linkDirectionalParticleSpeed(0.0038)
        .showNavInfo(false)
        .cooldownTicks(90)
        .onNodeClick((node: { x?: number; y?: number; z?: number }) => {
          if (!graphRef.current) return;
          const x = typeof node.x === "number" ? node.x : 0;
          const y = typeof node.y === "number" ? node.y : 0;
          const z = typeof node.z === "number" ? node.z : 0;
          graphRef.current.centerAt(x, y, 700);
          graphRef.current.cameraPosition(
            { x, y, z: z + 110 },
            { x, y, z },
            900,
          );
        });
      graphRef.current = graph;
    }

    const setSize = () => {
      if (!graphRef.current || !container) return;
      const width = Math.max(260, Math.floor(container.clientWidth || 0));
      const height = Math.max(220, Math.floor(container.clientHeight || 0));
      graphRef.current.width(width);
      graphRef.current.height(height);
    };
    setSize();

    const observer = new ResizeObserver(() => setSize());
    observer.observe(container);

    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    if (!graphRef.current) return;
    graphRef.current.graphData(graphData);
    graphRef.current.d3AlphaDecay(0.035);
    graphRef.current.d3VelocityDecay(0.28);
    graphRef.current.zoomToFit(650, 50);
  }, [graphData]);

  return (
    <div className="artifact-hub-substrate-card">
      <div className="artifact-hub-substrate-head">
        <span className="artifact-hub-substrate-title">Runtime graph</span>
        <span className="artifact-hub-substrate-badge">
          {graphData.nodes.length} nodes · {graphData.links.length} edges
        </span>
      </div>
      <div className="artifact-hub-substrate-canvas" ref={containerRef} />
      <div className="artifact-hub-substrate-legend">
        <span>query</span>
        <span>index</span>
        <span>candidates</span>
        <span>rerank</span>
        <span>top-k</span>
        <span>proof/cert</span>
      </div>
    </div>
  );
}
