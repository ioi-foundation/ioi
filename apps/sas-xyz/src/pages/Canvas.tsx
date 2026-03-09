import React, { useState, useCallback, useRef, useEffect } from 'react';
import {
  ReactFlow,
  MiniMap,
  Controls,
  Background,
  useNodesState,
  useEdgesState,
  addEdge,
  Panel,
  Handle,
  Position,
  useReactFlow,
  ReactFlowProvider,
  MarkerType
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { 
  Brain, Database, MessageSquare, ShieldAlert, Play, Save, 
  Zap, Globe, Mail, Settings2, Trash2, Plus, X, Activity,
  Terminal, CheckCircle2, AlertCircle, Loader2
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';

// --- Custom Nodes ---

const NodeHeader = ({ icon: Icon, title, colorClass, onSettings, onDelete, isActive }: any) => (
  <div className="flex items-center justify-between mb-3 border-b border-white/5 pb-2">
    <div className="flex items-center space-x-2">
      <div className={`p-1.5 rounded-md bg-surface border border-white/10 ${colorClass} relative`}>
        <Icon className="w-4 h-4" />
        {isActive && (
          <span className="absolute -top-1 -right-1 w-2 h-2 rounded-full bg-current animate-ping" />
        )}
      </div>
      <span className="font-bold text-sm text-white">{title}</span>
    </div>
    <div className="flex space-x-1 opacity-0 group-hover:opacity-100 transition-opacity">
      <button onClick={onSettings} className="p-1 text-gray-400 hover:text-white rounded hover:bg-white/10">
        <Settings2 className="w-3 h-3" />
      </button>
      <button onClick={onDelete} className="p-1 text-gray-400 hover:text-red-400 rounded hover:bg-white/10">
        <Trash2 className="w-3 h-3" />
      </button>
    </div>
  </div>
);

const TriggerNode = ({ data, selected }: any) => (
  <div className={`bg-[#1A1D24] border-2 rounded-xl p-4 w-64 shadow-xl transition-all duration-300 group ${selected ? 'border-emerald-accent shadow-[0_0_15px_rgba(0,255,102,0.15)]' : 'border-white/10 hover:border-white/20'} ${data.isActive ? 'ring-2 ring-emerald-accent ring-offset-2 ring-offset-[#0B0D11] scale-105' : ''}`}>
    <NodeHeader icon={Zap} title="Trigger" colorClass="text-emerald-accent" isActive={data.isActive} />
    <div className="text-sm text-gray-300 mb-1">{data.label}</div>
    <div className="text-xs text-gray-500 font-mono">{data.config || 'No config'}</div>
    <Handle type="source" position={Position.Right} className="w-3 h-3 bg-emerald-accent border-2 border-[#1A1D24]" />
  </div>
);

const CognitionNode = ({ data, selected }: any) => (
  <div className={`bg-[#1A1D24] border-2 rounded-xl p-4 w-64 shadow-xl transition-all duration-300 group ${selected ? 'border-cyan-accent shadow-[0_0_15px_rgba(0,240,255,0.15)]' : 'border-white/10 hover:border-white/20'} ${data.isActive ? 'ring-2 ring-cyan-accent ring-offset-2 ring-offset-[#0B0D11] scale-105' : ''}`}>
    <Handle type="target" position={Position.Left} className="w-3 h-3 bg-cyan-accent border-2 border-[#1A1D24]" />
    <NodeHeader icon={Brain} title="Cognition" colorClass="text-cyan-accent" isActive={data.isActive} />
    <div className="text-sm text-gray-300 mb-1">{data.label}</div>
    <div className="text-xs text-gray-500 font-mono flex justify-between">
      <span>{data.provider || 'Unknown'}</span>
      <span className="text-cyan-accent/70">{data.model || 'Auto'}</span>
    </div>
    <Handle type="source" position={Position.Right} className="w-3 h-3 bg-cyan-accent border-2 border-[#1A1D24]" />
  </div>
);

const ToolNode = ({ data, selected }: any) => {
  const Icon = data.type === 'db' ? Database : Globe;
  return (
    <div className={`bg-[#1A1D24] border-2 rounded-xl p-4 w-64 shadow-xl transition-all duration-300 group ${selected ? 'border-amber-accent shadow-[0_0_15px_rgba(255,176,0,0.15)]' : 'border-white/10 hover:border-white/20'} ${data.isActive ? 'ring-2 ring-amber-accent ring-offset-2 ring-offset-[#0B0D11] scale-105' : ''}`}>
      <Handle type="target" position={Position.Left} className="w-3 h-3 bg-amber-accent border-2 border-[#1A1D24]" />
      <NodeHeader icon={Icon} title="Tool / MCP" colorClass="text-amber-accent" isActive={data.isActive} />
      <div className="text-sm text-gray-300 mb-1">{data.label}</div>
      <div className="text-xs text-amber-accent/80 font-mono bg-amber-accent/10 p-1.5 rounded mt-2 border border-amber-accent/20">
        {data.action || 'No action defined'}
      </div>
      <Handle type="source" position={Position.Right} className="w-3 h-3 bg-amber-accent border-2 border-[#1A1D24]" />
    </div>
  );
};

const OutputNode = ({ data, selected }: any) => {
  const Icon = data.type === 'slack' ? MessageSquare : Mail;
  return (
    <div className={`bg-[#1A1D24] border-2 rounded-xl p-4 w-64 shadow-xl transition-all duration-300 group ${selected ? 'border-purple-500 shadow-[0_0_15px_rgba(168,85,247,0.15)]' : 'border-white/10 hover:border-white/20'} ${data.isActive ? 'ring-2 ring-purple-500 ring-offset-2 ring-offset-[#0B0D11] scale-105' : ''}`}>
      <Handle type="target" position={Position.Left} className="w-3 h-3 bg-purple-500 border-2 border-[#1A1D24]" />
      <NodeHeader icon={Icon} title="Output" colorClass="text-purple-500" isActive={data.isActive} />
      <div className="text-sm text-gray-300 mb-1">{data.label}</div>
      <div className="text-xs text-gray-500 font-mono">{data.target || 'No target'}</div>
    </div>
  );
};

const nodeTypes = {
  trigger: TriggerNode,
  cognition: CognitionNode,
  tool: ToolNode,
  output: OutputNode,
};

// --- Initial Data ---

const initialNodes = [
  {
    id: 'trigger-1',
    type: 'trigger',
    position: { x: 50, y: 200 },
    data: { label: 'Webhook Event', config: 'POST /api/v1/ingest', isActive: false },
  },
  {
    id: 'cog-1',
    type: 'cognition',
    position: { x: 400, y: 200 },
    data: { label: 'Triage Agent', provider: 'Meta', model: 'Llama-3-70b', isActive: false },
  },
  {
    id: 'tool-1',
    type: 'tool',
    position: { x: 400, y: 400 },
    data: { type: 'db', label: 'Customer DB', action: 'SELECT * FROM users', isActive: false },
  },
  {
    id: 'out-1',
    type: 'output',
    position: { x: 800, y: 200 },
    data: { type: 'slack', label: 'Slack Alert', target: '#support-alerts', isActive: false },
  },
];

const initialEdges = [
  { 
    id: 'e-t1-c1', 
    source: 'trigger-1', 
    target: 'cog-1', 
    animated: true, 
    style: { stroke: '#00FF66', strokeWidth: 2 },
    markerEnd: { type: MarkerType.ArrowClosed, color: '#00FF66' }
  },
  { 
    id: 'e-c1-t1', 
    source: 'cog-1', 
    target: 'tool-1', 
    animated: true, 
    style: { stroke: '#FFB000', strokeWidth: 2, strokeDasharray: '5 5' },
    markerEnd: { type: MarkerType.ArrowClosed, color: '#FFB000' }
  },
  { 
    id: 'e-t1-c1-back', 
    source: 'tool-1', 
    target: 'cog-1', 
    animated: true, 
    style: { stroke: '#FFB000', strokeWidth: 2, strokeDasharray: '5 5' },
    markerEnd: { type: MarkerType.ArrowClosed, color: '#FFB000' }
  },
  { 
    id: 'e-c1-o1', 
    source: 'cog-1', 
    target: 'out-1', 
    animated: true, 
    style: { stroke: '#00F0FF', strokeWidth: 2 },
    markerEnd: { type: MarkerType.ArrowClosed, color: '#00F0FF' }
  },
];

// --- Main Component ---

function Flow() {
  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);
  const [isSimulating, setIsSimulating] = useState(false);
  const [isLogsOpen, setIsLogsOpen] = useState(false);
  const [selectedNode, setSelectedNode] = useState<any>(null);
  const [logs, setLogs] = useState<{time: string, msg: string, type: string}[]>([]);
  const [isDeployModalOpen, setIsDeployModalOpen] = useState(false);
  const [isGhostMode, setIsGhostMode] = useState(false);
  const { screenToFlowPosition } = useReactFlow();
  const logsEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (logsEndRef.current) {
      logsEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs]);

  const onConnect = useCallback(
    (params: any) => setEdges((eds) => addEdge({ 
      ...params, 
      animated: true, 
      style: { stroke: '#fff', strokeWidth: 2 },
      markerEnd: { type: MarkerType.ArrowClosed, color: '#fff' }
    }, eds)),
    [setEdges],
  );

  const onDragOver = useCallback((event: any) => {
    event.preventDefault();
    event.dataTransfer.dropEffect = 'move';
  }, []);

  const onDrop = useCallback(
    (event: any) => {
      event.preventDefault();

      const type = event.dataTransfer.getData('application/reactflow');
      if (typeof type === 'undefined' || !type) return;

      const position = screenToFlowPosition({
        x: event.clientX,
        y: event.clientY,
      });

      const newNode = {
        id: `${type}-${Date.now()}`,
        type,
        position,
        data: { label: `New ${type} node`, isActive: false },
      };

      setNodes((nds) => nds.concat(newNode));
    },
    [screenToFlowPosition, setNodes],
  );

  const onNodeClick = useCallback((_, node) => {
    setSelectedNode(node);
  }, []);

  const onPaneClick = useCallback(() => {
    setSelectedNode(null);
  }, []);

  const updateNodeData = (id: string, newData: any) => {
    setNodes((nds) =>
      nds.map((node) => {
        if (node.id === id) {
          return { ...node, data: { ...node.data, ...newData } };
        }
        return node;
      })
    );
    if (selectedNode && selectedNode.id === id) {
      setSelectedNode((prev: any) => ({ ...prev, data: { ...prev.data, ...newData } }));
    }
  };

  const deleteNode = () => {
    if (selectedNode) {
      setNodes((nds) => nds.filter((n) => n.id !== selectedNode.id));
      setEdges((eds) => eds.filter((e) => e.source !== selectedNode.id && e.target !== selectedNode.id));
      setSelectedNode(null);
    }
  };

  const addLog = (msg: string, type: 'info' | 'success' | 'warning' = 'info') => {
    const time = new Date().toLocaleTimeString([], { hour12: false, hour: '2-digit', minute:'2-digit', second:'2-digit' });
    setLogs(prev => [...prev, { time, msg, type }]);
  };

  const runSimulation = () => {
    if (isSimulating) return;
    setIsSimulating(true);
    setIsLogsOpen(true);
    setLogs([]);
    addLog('Initializing Sandbox Environment...', 'info');
    
    const setNodeActive = (id: string | null) => {
      setNodes(nds => nds.map(n => ({
        ...n,
        data: { ...n.data, isActive: n.id === id }
      })));
    };

    setTimeout(() => {
      addLog('[TRIGGER] Webhook Event received from external source.', 'success');
      setNodeActive('trigger-1');
    }, 1000);
    
    setTimeout(() => {
      addLog('[COGNITION] Triage Agent analyzing payload...', 'info');
      setNodeActive('cog-1');
    }, 2500);
    
    setTimeout(() => {
      addLog('[TOOL] Querying Customer DB for user context...', 'warning');
      setNodeActive('tool-1');
    }, 4000);

    setTimeout(() => {
      addLog('[COGNITION] Context retrieved. Formulating response...', 'info');
      setNodeActive('cog-1');
    }, 5500);
    
    setTimeout(() => {
      addLog('[OUTPUT] Sending Slack Alert to #support-alerts...', 'success');
      setNodeActive('out-1');
    }, 7000);
    
    setTimeout(() => {
      addLog('Simulation complete. All nodes executed successfully.', 'info');
      setNodeActive(null);
      setIsSimulating(false);
    }, 8500);
  };

  return (
    <div className="flex h-[calc(100vh-8rem)] w-full border border-border rounded-xl overflow-hidden relative bg-[#0B0D11]">
      
      {/* Sidebar Palette */}
      <div className="w-64 bg-surface border-r border-border flex flex-col z-10">
        <div className="p-4 border-b border-border">
          <h3 className="font-bold text-white flex items-center">
            <Plus className="w-4 h-4 mr-2 text-cyan-accent" />
            Add Nodes
          </h3>
          <p className="text-xs text-gray-400 mt-1">Drag and drop to canvas</p>
        </div>
        <div className="p-4 flex flex-col space-y-3 overflow-y-auto">
          
          <div 
            className="p-3 border border-white/10 rounded-lg bg-[#1A1D24] cursor-grab hover:border-emerald-accent/50 transition-colors"
            onDragStart={(e) => e.dataTransfer.setData('application/reactflow', 'trigger')}
            draggable
          >
            <div className="flex items-center space-x-2 mb-1">
              <Zap className="w-4 h-4 text-emerald-accent" />
              <span className="text-sm font-bold text-white">Trigger</span>
            </div>
            <p className="text-xs text-gray-500">Start the workflow</p>
          </div>

          <div 
            className="p-3 border border-white/10 rounded-lg bg-[#1A1D24] cursor-grab hover:border-cyan-accent/50 transition-colors"
            onDragStart={(e) => e.dataTransfer.setData('application/reactflow', 'cognition')}
            draggable
          >
            <div className="flex items-center space-x-2 mb-1">
              <Brain className="w-4 h-4 text-cyan-accent" />
              <span className="text-sm font-bold text-white">Cognition</span>
            </div>
            <p className="text-xs text-gray-500">LLM processing node</p>
          </div>

          <div 
            className="p-3 border border-white/10 rounded-lg bg-[#1A1D24] cursor-grab hover:border-amber-accent/50 transition-colors"
            onDragStart={(e) => e.dataTransfer.setData('application/reactflow', 'tool')}
            draggable
          >
            <div className="flex items-center space-x-2 mb-1">
              <Database className="w-4 h-4 text-amber-accent" />
              <span className="text-sm font-bold text-white">Tool / MCP</span>
            </div>
            <p className="text-xs text-gray-500">External API or DB</p>
          </div>

          <div 
            className="p-3 border border-white/10 rounded-lg bg-[#1A1D24] cursor-grab hover:border-purple-500/50 transition-colors"
            onDragStart={(e) => e.dataTransfer.setData('application/reactflow', 'output')}
            draggable
          >
            <div className="flex items-center space-x-2 mb-1">
              <MessageSquare className="w-4 h-4 text-purple-500" />
              <span className="text-sm font-bold text-white">Output</span>
            </div>
            <p className="text-xs text-gray-500">Send response</p>
          </div>

        </div>
      </div>

      {/* Main Canvas */}
      <div className="flex-1 relative overflow-hidden">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onConnect={onConnect}
          onDrop={onDrop}
          onDragOver={onDragOver}
          onNodeClick={onNodeClick}
          onPaneClick={onPaneClick}
          nodeTypes={nodeTypes}
          fitView
          className="bg-[#0B0D11]"
          defaultEdgeOptions={{
            style: { strokeWidth: 2 },
            type: 'smoothstep',
          }}
        >
          <Background color="#232730" gap={16} size={2} />
          <Controls className="bg-surface border-border fill-white" />
          <MiniMap 
            nodeColor={(node) => {
              switch (node.type) {
                case 'trigger': return '#00FF66';
                case 'cognition': return '#00F0FF';
                case 'tool': return '#FFB000';
                case 'output': return '#A855F7';
                default: return '#eee';
              }
            }}
            maskColor="rgba(11, 13, 17, 0.8)"
            className="bg-surface border-border rounded-lg overflow-hidden"
          />
          
          <Panel position="top-right" className="flex space-x-2">
            <button 
              className="flex items-center space-x-2 bg-surface border border-border px-4 py-2 rounded-lg text-sm font-medium hover:bg-surface-hover transition-colors shadow-lg"
              onClick={runSimulation}
              disabled={isSimulating}
            >
              {isSimulating ? (
                <Loader2 className="w-4 h-4 text-emerald-accent animate-spin" />
              ) : (
                <Play className="w-4 h-4 text-emerald-accent" />
              )}
              <span>{isSimulating ? 'Simulating...' : 'Run Sandbox'}</span>
            </button>
            <button 
              onClick={() => setIsDeployModalOpen(true)}
              className="flex items-center space-x-2 bg-cyan-accent text-bg px-4 py-2 rounded-lg text-sm font-bold hover:bg-cyan-accent/90 transition-colors shadow-lg shadow-cyan-accent/20"
            >
              <Save className="w-4 h-4" />
              <span>Deploy</span>
            </button>
          </Panel>

          <Panel position="top-left" className="bg-surface/80 backdrop-blur-md border border-border p-4 rounded-xl w-64 shadow-xl">
            <div className="flex items-center space-x-2 mb-3 text-amber-accent">
              <ShieldAlert className="w-4 h-4" />
              <span className="font-bold text-sm uppercase tracking-wider">Firewall Policy</span>
            </div>
            <div className="space-y-2 font-mono text-xs">
              <div className="flex justify-between items-center text-gray-400 bg-bg p-2 rounded border border-white/5">
                <span>Egress:</span>
                <span className="text-emerald-accent">api.slack.com</span>
              </div>
              <div className="flex justify-between items-center text-gray-400 bg-bg p-2 rounded border border-white/5">
                <span>Ingress:</span>
                <span className="text-cyan-accent">Postgres (Read)</span>
              </div>
              <div className="mt-4 pt-4 border-t border-border">
                <button 
                  onClick={() => setIsGhostMode(!isGhostMode)}
                  className={`w-full py-2 border rounded-lg transition-colors flex items-center justify-center ${isGhostMode ? 'bg-purple-500/10 border-purple-500/50 text-purple-400' : 'border-border text-gray-400 hover:text-white hover:border-gray-500'}`}
                >
                  <Activity className={`w-3 h-3 mr-2 ${isGhostMode ? 'animate-pulse' : ''}`} />
                  {isGhostMode ? 'Ghost Mode (Active)' : 'Ghost Mode (Record)'}
                </button>
              </div>
            </div>
          </Panel>
        </ReactFlow>

        {/* Logs Panel (Bottom) */}
        <AnimatePresence>
          {isLogsOpen && (
            <motion.div 
              initial={{ y: '100%' }}
              animate={{ y: 0 }}
              exit={{ y: '100%' }}
              transition={{ type: 'spring', damping: 25, stiffness: 200 }}
              className="absolute bottom-0 left-0 right-0 h-48 border-t border-border bg-[#050505]/95 backdrop-blur-md flex flex-col z-10 shadow-[0_-10px_40px_rgba(0,0,0,0.5)]"
            >
              <div className="flex items-center justify-between px-4 py-2 border-b border-border bg-surface/80">
                <div className="flex items-center space-x-2 text-xs font-mono text-gray-400">
                  <Terminal className="w-4 h-4 text-cyan-accent" />
                  <span>Sandbox Execution Logs</span>
                </div>
                <button 
                  onClick={() => setIsLogsOpen(false)} 
                  className="text-gray-500 hover:text-white p-1 rounded hover:bg-white/10 transition-colors"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
              <div className="flex-1 overflow-y-auto p-4 font-mono text-xs space-y-2">
                {logs.map((log, i) => (
                  <div key={i} className="flex items-start space-x-3">
                    <span className="text-gray-600 shrink-0">[{log.time}]</span>
                    {log.type === 'success' && <CheckCircle2 className="w-4 h-4 text-emerald-accent shrink-0" />}
                    {log.type === 'warning' && <AlertCircle className="w-4 h-4 text-amber-accent shrink-0" />}
                    {log.type === 'info' && <Activity className="w-4 h-4 text-cyan-accent shrink-0" />}
                    <span className={`
                      ${log.type === 'success' ? 'text-emerald-accent' : ''}
                      ${log.type === 'warning' ? 'text-amber-accent' : ''}
                      ${log.type === 'info' ? 'text-gray-300' : ''}
                    `}>
                      {log.msg}
                    </span>
                  </div>
                ))}
                <div ref={logsEndRef} />
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* Properties Panel (Right Sidebar) */}
      <AnimatePresence>
        {selectedNode && (
          <motion.div 
            initial={{ x: 300, opacity: 0 }}
            animate={{ x: 0, opacity: 1 }}
            exit={{ x: 300, opacity: 0 }}
            transition={{ type: 'spring', damping: 25, stiffness: 200 }}
            className="absolute top-0 right-0 h-full w-80 bg-surface border-l border-border z-20 shadow-2xl flex flex-col"
          >
            <div className="p-4 border-b border-border flex justify-between items-center bg-surface-hover">
              <h3 className="font-bold text-white flex items-center">
                <Settings2 className="w-4 h-4 mr-2 text-cyan-accent" />
                Node Properties
              </h3>
              <button onClick={() => setSelectedNode(null)} className="text-gray-400 hover:text-white">
                <X className="w-4 h-4" />
              </button>
            </div>
            
            <div className="p-6 flex-1 overflow-y-auto space-y-6">
              <div>
                <label className="block text-xs text-gray-500 uppercase tracking-wider mb-2">Node ID</label>
                <div className="font-mono text-xs text-gray-300 bg-bg p-2 rounded border border-white/5">
                  {selectedNode.id}
                </div>
              </div>

              <div>
                <label className="block text-xs text-gray-500 uppercase tracking-wider mb-2">Label</label>
                <input 
                  type="text" 
                  value={selectedNode.data.label || ''}
                  onChange={(e) => updateNodeData(selectedNode.id, { label: e.target.value })}
                  className="w-full bg-bg border border-border rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-accent"
                />
              </div>

              {selectedNode.type === 'cognition' && (
                <>
                  <div>
                    <label className="block text-xs text-gray-500 uppercase tracking-wider mb-2">Model Provider</label>
                    <select 
                      value={selectedNode.data.provider || 'Meta'}
                      onChange={(e) => updateNodeData(selectedNode.id, { provider: e.target.value })}
                      className="w-full bg-bg border border-border rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-accent"
                    >
                      <option>Meta</option>
                      <option>OpenAI</option>
                      <option>Anthropic</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-xs text-gray-500 uppercase tracking-wider mb-2">System Prompt</label>
                    <textarea 
                      rows={4}
                      className="w-full bg-bg border border-border rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-accent font-mono text-xs"
                      defaultValue="You are a helpful assistant."
                    />
                  </div>
                </>
              )}

              {selectedNode.type === 'tool' && (
                <div>
                  <label className="block text-xs text-gray-500 uppercase tracking-wider mb-2">Action / Query</label>
                  <textarea 
                    rows={3}
                    value={selectedNode.data.action || ''}
                    onChange={(e) => updateNodeData(selectedNode.id, { action: e.target.value })}
                    className="w-full bg-bg border border-border rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-accent font-mono text-xs text-amber-accent"
                  />
                </div>
              )}

              {selectedNode.type === 'trigger' && (
                <div>
                  <label className="block text-xs text-gray-500 uppercase tracking-wider mb-2">Webhook Config</label>
                  <input 
                    type="text" 
                    value={selectedNode.data.config || ''}
                    onChange={(e) => updateNodeData(selectedNode.id, { config: e.target.value })}
                    className="w-full bg-bg border border-border rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-accent font-mono text-xs text-emerald-accent"
                  />
                </div>
              )}

              <div className="pt-6 border-t border-border">
                <button 
                  onClick={deleteNode}
                  className="w-full py-2 bg-red-500/10 text-red-500 border border-red-500/20 rounded-lg hover:bg-red-500/20 transition-colors text-sm font-medium flex items-center justify-center"
                >
                  <Trash2 className="w-4 h-4 mr-2" />
                  Delete Node
                </button>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Deploy Modal */}
      <AnimatePresence>
        {isDeployModalOpen && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-sm">
            <motion.div 
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.95, opacity: 0 }}
              className="bg-surface border border-border rounded-xl shadow-2xl w-full max-w-md overflow-hidden"
            >
              <div className="p-4 border-b border-border flex justify-between items-center">
                <h3 className="font-bold text-white flex items-center">
                  <Save className="w-4 h-4 mr-2 text-cyan-accent" />
                  Deploy Agent
                </h3>
                <button onClick={() => setIsDeployModalOpen(false)} className="text-gray-400 hover:text-white">
                  <X className="w-4 h-4" />
                </button>
              </div>
              <div className="p-6 space-y-4">
                <div>
                  <label className="block text-xs text-gray-500 uppercase tracking-wider mb-2">Environment</label>
                  <select className="w-full bg-bg border border-border rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-accent">
                    <option>Production (Mainnet)</option>
                    <option>Staging (Testnet)</option>
                  </select>
                </div>
                <div>
                  <label className="block text-xs text-gray-500 uppercase tracking-wider mb-2">Version Tag</label>
                  <input 
                    type="text" 
                    defaultValue="v1.0.0"
                    className="w-full bg-bg border border-border rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-accent font-mono"
                  />
                </div>
                <div className="bg-amber-accent/10 border border-amber-accent/20 rounded-lg p-3 flex items-start space-x-3">
                  <ShieldAlert className="w-5 h-5 text-amber-accent shrink-0 mt-0.5" />
                  <div className="text-xs text-amber-accent/80">
                    Deploying to Mainnet will consume IOI credits based on the selected model provider and tool usage.
                  </div>
                </div>
              </div>
              <div className="p-4 border-t border-border bg-surface-hover flex justify-end space-x-3">
                <button 
                  onClick={() => setIsDeployModalOpen(false)}
                  className="px-4 py-2 rounded-lg text-sm font-medium text-gray-400 hover:text-white transition-colors"
                >
                  Cancel
                </button>
                <button 
                  onClick={() => {
                    setIsDeployModalOpen(false);
                    addLog('Deployment initiated to Production (Mainnet)', 'info');
                    setIsLogsOpen(true);
                  }}
                  className="px-4 py-2 rounded-lg text-sm font-bold bg-cyan-accent text-bg hover:bg-cyan-accent/90 transition-colors shadow-lg shadow-cyan-accent/20"
                >
                  Confirm Deployment
                </button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

    </div>
  );
}

export default function Canvas() {
  return (
    <ReactFlowProvider>
      <Flow />
    </ReactFlowProvider>
  );
}
